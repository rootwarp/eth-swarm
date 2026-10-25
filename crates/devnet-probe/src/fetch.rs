//! `fetch-epoch`: one full finalized epoch fetched by BlocksByRange v2 from the reference CLs,
//! every slot's root compared with the reference beacon API's.
//!
//! 1. Our Status from probe mode's provider ([`OurStatus`]); the reference API's finalized
//!    epoch F. The epoch fetched is F − 1 (every slot of it is finalized), or the one asked for,
//!    which must be before F; never epoch 0, whose first slot is the genesis block.
//! 2. Every reference CL dialed; each must become Status-valid (its Status relevant to ours)
//!    within the status deadline. One line each. The swarm carries `status`'s ignore-all
//!    gossipsub on `beacon_block` at our fork digest, publishing nothing: a CL drops a peer
//!    that does not speak gossipsub.
//! 3. The epoch through cl-p2p's [`fetch_epoch`] over its [`RangeRequester`]: BlocksByRange v2,
//!    `step` 1, `count` at most `MAX_REQUEST_BLOCKS_DENEB`, starting at or after the peer's
//!    `earliest_available_slot`, every response checked (slots, context digest of the block's
//!    epoch, parent links). An empty stretch counts only once two peers agree, or a parent link
//!    proves it; anything resting on one peer's word is `unconfirmed`, and fails.
//! 4. Every slot of the epoch: the fetched block's root must equal
//!    `/eth/v1/beacon/blocks/{slot}/root`, and a slot without a fetched block must be a 404
//!    there. One line per slot, then one for the requests, one for `unconfirmed`, and one for
//!    peer faults (a response that broke a rule fails the check even if another peer covered
//!    for it).

use super::api::{hex0x, ProbeApi};
use super::devnet::Devnet;
use super::ours::{Clock, OurStatus};
use super::report::{Check, Line};
use super::swarm::{error_chain, probe_swarm, SwarmPlan};
use cl_p2p::behaviour::SpecBehaviour;
use cl_p2p::m2a_session::PinnedPeer;
use cl_p2p::rpc::inbound::StatusSource;
use cl_p2p::rpc::outbound::{
    fetch_epoch as fetch_range_epoch, FetchError, Linked, RangeFetch, RangeRequester,
};
use cl_p2p::transport::DialFailure;
use consensus_types::primitives::{Root, Slot};
use consensus_types::{forked, EthSpec};
use futures::StreamExt;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::SwarmEvent;
use libp2p::{PeerId, Swarm};
use network_config::Epoch;
use p2p_wire::rpc::messages::{ForkDigest, StatusV2};
use p2p_wire::rpc::protocols::MAX_REQUEST_BLOCKS_DENEB;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

/// The check's name.
pub const NAME: &str = "fetch-epoch";
/// How long the whole range fetch may take by default \[est\].
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// How long, from the start, the peers have to become Status-valid by default \[est\].
pub const DEFAULT_STATUS_DEADLINE: Duration = Duration::from_secs(30);
/// The swarm's idle-connection timeout: past every wait of the check.
const IDLE: Duration = Duration::from_secs(120);

/// What `fetch-epoch` runs.
#[derive(Debug, Clone)]
pub struct FetchPlan {
    /// The reference CLs, each at its TCP address.
    pub peers: Vec<PinnedPeer>,
    /// The epoch to fetch; the finalized epoch − 1 when `None`.
    pub epoch: Option<Epoch>,
    /// How long, from the start, the peers have to become Status-valid.
    pub status_deadline: Duration,
    /// How long the range fetch may take.
    pub fetch_timeout: Duration,
}

/// The epoch to fetch, given the finalized epoch.
fn pick_epoch(finalized: Epoch, asked: Option<Epoch>) -> Result<Epoch, String> {
    let epoch = match asked {
        Some(e) if e >= finalized => {
            return Err(format!(
                "epoch {e} is not before the finalized epoch {finalized}: not every slot of it is \
                 finalized"
            ))
        }
        Some(e) => e,
        None if finalized < 2 => {
            return Err(format!(
                "the reference API's finalized epoch {finalized} leaves no finalized epoch past \
                 genesis to fetch (it must be at least 2)"
            ))
        }
        None => finalized - 1,
    };
    if epoch == 0 {
        return Err(
            "epoch 0 starts with the genesis block, which a CL need not serve over \
                    BlocksByRange: ask for a later epoch"
                .into(),
        );
    }
    Ok(epoch)
}

/// Runs the check (see the module docs).
pub async fn fetch_epoch<E: EthSpec>(
    devnet: &Devnet,
    api: ProbeApi,
    clock: Clock,
    plan: &FetchPlan,
) -> Check {
    let (ours, first) = match OurStatus::start(
        devnet,
        api.clone(),
        clock,
        super::ours::DEFAULT_REFRESH_INTERVAL,
    )
    .await
    {
        Ok(started) => started,
        Err(e) => return Check::failed(NAME, e),
    };
    let finalized = match api.finalized().await {
        Ok(checkpoint) => checkpoint.epoch,
        Err(e) => return Check::failed(NAME, format!("the reference API's finality: {e}")),
    };
    let epoch = match pick_epoch(finalized, plan.epoch) {
        Ok(epoch) => epoch,
        Err(e) => return Check::failed(NAME, e),
    };
    let mut swarm = match fetch_swarm::<E>(devnet, ours.source(), plan, first.fork_digest) {
        Ok(swarm) => swarm,
        Err(e) => return Check::failed(NAME, format!("probe swarm: {e}")),
    };
    let mut check = Check::new(NAME);
    let valid = ready(&mut swarm, plan, &mut check).await;
    if valid.is_empty() {
        check.fail("no Status-valid peer to fetch from");
        return check;
    }
    let slots_per_epoch = devnet.slots_per_epoch();
    let first = epoch * slots_per_epoch;
    let last = first + slots_per_epoch - 1;
    let digest_at = |e: Epoch| devnet.digest_at(e);
    let fetched = {
        let mut requester = RangeRequester::<E, _>::new(&mut swarm, &digest_at);
        tokio::time::timeout(
            plan.fetch_timeout,
            fetch_range_epoch(&mut requester, epoch, slots_per_epoch),
        )
        .await
    };
    let fetch = match fetched {
        Ok(Ok(fetch)) => fetch,
        Ok(Err(e)) => {
            let failures = match &e {
                FetchError::NoPeer { failures, .. } => failures
                    .iter()
                    .map(|(peer, e)| format!("; {peer}: {e}"))
                    .collect::<String>(),
                FetchError::InvalidRange { .. } => String::new(),
            };
            check.fail(format!(
                "epoch {epoch} (slots {first}..={last}): {e}{failures}"
            ));
            return check;
        }
        Err(_) => {
            check.fail(format!(
                "epoch {epoch} (slots {first}..={last}): not fetched within {:?}",
                plan.fetch_timeout
            ));
            return check;
        }
    };
    check.pass(format!(
        "epoch {epoch} (slots {first}..={last}) of finalized epoch {finalized}: {} blocks fetched \
         in {} requests",
        fetch.blocks.len(),
        fetch.requests.len()
    ));
    compare(&api, first..=last, &fetch, &mut check).await;
    judge_fetch(&fetch, &valid, &mut check);
    check
}

/// The swarm `fetch-epoch` dials from: our Status from `status`, no listener, every peer of
/// `plan` exempt from the connection caps, and `status`'s ignore-all gossipsub on
/// `beacon_block` at our fork digest `digest` (a CL drops a peer that does not speak
/// gossipsub).
fn fetch_swarm<E: EthSpec>(
    devnet: &Devnet,
    status: Arc<dyn StatusSource>,
    plan: &FetchPlan,
    digest: ForkDigest,
) -> Result<Swarm<SpecBehaviour<E>>, String> {
    let swarm_plan = SwarmPlan {
        listen: Vec::new(),
        idle: IDLE,
        bypass: plan.peers.iter().map(|p| p.peer_id).collect(),
        muxer_observer: None,
        ping_interval: cl_p2p::rpc::inbound::PING_INTERVAL,
        gossip: Some(digest),
        limits: cl_p2p::rpc::limits::RpcLimits::default(),
    };
    probe_swarm::<E>(devnet, status, swarm_plan)
}

/// Dials every peer and drives the swarm until each is Status-valid or failed, or the
/// deadline passed; one line per peer. Returns the Status-valid peers' Status.
async fn ready<E: EthSpec>(
    swarm: &mut Swarm<SpecBehaviour<E>>,
    plan: &FetchPlan,
    check: &mut Check,
) -> HashMap<PeerId, StatusV2> {
    let mut failed: HashMap<PeerId, String> = HashMap::new();
    for peer in &plan.peers {
        let opts = DialOpts::peer_id(peer.peer_id)
            .addresses(vec![peer.addr.clone()])
            .build();
        if let Err(e) = swarm.dial(opts) {
            failed.insert(peer.peer_id, dial_failure(&e));
        }
    }
    let valid = |swarm: &Swarm<SpecBehaviour<E>>| -> HashMap<PeerId, StatusV2> {
        swarm
            .behaviour()
            .req_resp
            .status_valid_peers()
            .into_iter()
            .collect()
    };
    let settled = |swarm: &Swarm<SpecBehaviour<E>>, failed: &HashMap<PeerId, String>| {
        let valid = valid(swarm);
        plan.peers
            .iter()
            .all(|p| valid.contains_key(&p.peer_id) || failed.contains_key(&p.peer_id))
    };
    let wait = async {
        while !settled(swarm, &failed) {
            if let SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                error,
                ..
            } = swarm.select_next_some().await
            {
                failed.entry(peer).or_insert_with(|| dial_failure(&error));
            }
        }
    };
    let _ = tokio::time::timeout(plan.status_deadline, wait).await;
    let valid = valid(swarm);
    for peer in &plan.peers {
        let at = format!("peer {} at {}", peer.peer_id, peer.addr);
        match (valid.get(&peer.peer_id), failed.get(&peer.peer_id)) {
            (Some(status), _) => check.pass(format!(
                "{at}: Status-valid (head slot {}, earliest_available_slot {})",
                status.head_slot, status.earliest_available_slot
            )),
            (None, Some(why)) => check.fail(format!("{at}: {why}")),
            (None, None) => check.fail(format!(
                "{at}: not Status-valid within {:?}",
                plan.status_deadline
            )),
        }
    }
    valid
}

/// One line per slot of `slots`: the fetched block's root against the API's, or an empty slot
/// against its 404.
async fn compare<E: EthSpec>(
    api: &ProbeApi,
    slots: std::ops::RangeInclusive<Slot>,
    fetch: &RangeFetch<forked::SignedBeaconBlock<E>>,
    check: &mut Check,
) {
    let fetched: BTreeMap<Slot, Root> = fetch.blocks.iter().map(|b| (b.slot(), b.root())).collect();
    for slot in slots {
        let api_root = match api.block_root(slot).await {
            Ok(root) => root,
            Err(e) => {
                check.fail(format!("slot {slot}: the reference API's root: {e}"));
                continue;
            }
        };
        let line = match (fetched.get(&slot), api_root) {
            (Some(ours), Some(theirs)) if *ours == theirs => Line {
                pass: true,
                detail: format!(
                    "slot {slot}: block {} equals the API root",
                    hex0x(ours.as_slice())
                ),
            },
            (Some(ours), Some(theirs)) => Line {
                pass: false,
                detail: format!(
                    "slot {slot}: fetched block {}, the API root {}",
                    hex0x(ours.as_slice()),
                    hex0x(theirs.as_slice())
                ),
            },
            (Some(ours), None) => Line {
                pass: false,
                detail: format!(
                    "slot {slot}: fetched block {}, the API has none (404)",
                    hex0x(ours.as_slice())
                ),
            },
            (None, Some(theirs)) => Line {
                pass: false,
                detail: format!(
                    "slot {slot}: no block fetched, the API root {}",
                    hex0x(theirs.as_slice())
                ),
            },
            (None, None) => Line {
                pass: true,
                detail: format!("slot {slot}: empty, the API answers 404"),
            },
        };
        check.record(line.pass, line.detail);
    }
}

/// The lines on how the fetch went: its requests, `unconfirmed` and peer faults.
fn judge_fetch<B>(fetch: &RangeFetch<B>, valid: &HashMap<PeerId, StatusV2>, check: &mut Check) {
    let requests: Vec<String> = fetch
        .requests
        .iter()
        .map(|(peer, r)| format!("{peer} start {} count {}", r.start_slot, r.count))
        .collect();
    let in_rules = fetch.requests.iter().all(|(peer, r)| {
        let eas = valid.get(peer).map_or(0, |s| s.earliest_available_slot);
        r.step == 1 && (1..=MAX_REQUEST_BLOCKS_DENEB).contains(&r.count) && r.start_slot >= eas
    });
    check.record(
        in_rules,
        format!(
            "requests: BlocksByRange v2, step 1, count 1..={MAX_REQUEST_BLOCKS_DENEB}, start at or \
             after the peer's earliest_available_slot: {}",
            requests.join("; ")
        ),
    );
    if fetch.unconfirmed.is_empty() {
        check.pass("unconfirmed: none (every empty slot settled by two peers or a parent link)");
    } else {
        let gaps: Vec<String> = fetch
            .unconfirmed
            .iter()
            .map(|(from, to)| format!("slots {from}..{to}"))
            .collect();
        check.fail(format!(
            "unconfirmed: {} rest on one peer's word (no second peer agreed)",
            gaps.join(", ")
        ));
    }
    let faults: Vec<String> = fetch
        .failures
        .iter()
        .filter(|(_, e)| e.is_peer_fault())
        .map(|(peer, e)| format!("{peer}: {e}"))
        .collect();
    if faults.is_empty() {
        check.pass(format!(
            "peer faults: none ({} requests failed without one)",
            fetch.failures.len()
        ));
    } else {
        check.fail(format!("peer faults: {}", faults.join("; ")));
    }
}

fn dial_failure(error: &libp2p::swarm::DialError) -> String {
    format!(
        "dial failed (reason={}): {}",
        DialFailure::of(error).as_str(),
        error_chain(error)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{closed_port_peer, devnet, now_ms, FixtureChain};
    use cl_p2p::rpc::outbound::block_root;
    use cl_p2p::testkit::{BlocksReply, StatusPeer, StatusReply};
    use consensus_types::{forked, Minimal};
    use ssz::Encode;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    type P = Minimal;

    /// The fixture chain: a block at every slot of 16..40 except `empty`, each the child of the
    /// one before.
    fn chain(empty: &[Slot]) -> BTreeMap<Slot, forked::SignedBeaconBlock<P>> {
        let mut parent = Root::repeat_byte(0x77);
        let mut out = BTreeMap::new();
        for slot in (16..40).filter(|s| !empty.contains(s)) {
            let mut b = p2p_wire::testkit::gloas_block::<P>(slot);
            b.message.parent_root = parent;
            let block = forked::SignedBeaconBlock::Gloas(b);
            parent = block_root(&block);
            out.insert(slot, block);
        }
        out
    }

    /// A reference CL serving `blocks`, Status-valid against ours (it echoes our Status, its
    /// head at slot 40).
    async fn peer(
        devnet: &Devnet,
        blocks: BTreeMap<Slot, forked::SignedBeaconBlock<P>>,
    ) -> StatusPeer {
        let digests: BTreeMap<Slot, [u8; 4]> = blocks
            .keys()
            .map(|slot| (*slot, devnet.digest_at(slot / 8).unwrap()))
            .collect();
        StatusPeer::spawn_with_blocks(
            Box::new(|req, _| {
                StatusReply::Status(StatusV2 {
                    head_slot: 40,
                    earliest_available_slot: 0,
                    ..req.clone()
                })
            }),
            None,
            None,
            Some(Box::new(move |req, _| {
                let end = req.start_slot + req.count;
                BlocksReply::Blocks(
                    blocks
                        .range(req.start_slot..end)
                        .map(|(slot, b)| (digests[slot], b.as_ssz_bytes()))
                        .collect(),
                )
            })),
            None,
        )
        .await
    }

    /// The fixture API: finalized at `finalized` (its block at the epoch's first slot), the
    /// roots of `blocks`.
    async fn api_for(
        finalized: Epoch,
        blocks: &BTreeMap<Slot, forked::SignedBeaconBlock<P>>,
    ) -> (FixtureChain, testkit::collector::testing::FixtureServer) {
        let chain = FixtureChain::default();
        let finalized_root = Root::repeat_byte(0xf0);
        chain.finalize(finalized, finalized_root, finalized * 8);
        chain.with(|s| {
            for (slot, b) in blocks {
                s.roots.insert(*slot, block_root(b));
            }
        });
        let server = chain.serve().await;
        (chain, server)
    }

    fn plan(peers: Vec<PinnedPeer>, epoch: Option<Epoch>) -> FetchPlan {
        FetchPlan {
            peers,
            epoch,
            status_deadline: Duration::from_secs(5),
            fetch_timeout: Duration::from_secs(20),
        }
    }

    fn clock() -> Clock {
        Arc::new(now_ms)
    }

    fn pinned(p: &StatusPeer) -> PinnedPeer {
        p.pinned()
    }

    fn details(check: &Check) -> Vec<String> {
        check.lines().iter().map(|l| l.detail.clone()).collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_root_and_every_empty_slot_matches() {
        let devnet = devnet();
        // Epoch 3 is slots 24..32: 26 is empty between blocks, 31 empty at its end.
        let blocks = chain(&[26, 31]);
        let (_chain, server) = api_for(4, &blocks).await;
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let a = peer(&devnet, blocks.clone()).await;
        let b = peer(&devnet, blocks.clone()).await;
        let check = fetch_epoch::<P>(
            &devnet,
            api,
            clock(),
            &plan(vec![pinned(&a), pinned(&b)], None),
        )
        .await;
        let lines = details(&check);
        assert!(check.passed(), "{lines:#?}");
        assert!(
            lines.iter().any(|l| l.contains("epoch 3 (slots 24..=31)")),
            "{lines:#?}"
        );
        let root25 = hex0x(block_root(&blocks[&25]).as_slice());
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("slot 25: block") && l.contains(&root25)),
            "{lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("slot 26: empty")),
            "{lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("slot 31: empty")),
            "{lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("unconfirmed: none")),
            "{lines:#?}"
        );
        // Every request asked at most 128 slots, step 1.
        let asked: Vec<_> = a
            .blocks_requests()
            .into_iter()
            .chain(b.blocks_requests())
            .collect();
        assert!(!asked.is_empty());
        assert!(asked
            .iter()
            .all(|r| r.count <= 128 && r.step == 1 && r.start_slot >= 24));
    }

    /// The remote of [`identify_listener`]: identify, and a gossipsub that subscribes to
    /// nothing, as a CL speaks it.
    #[derive(libp2p::swarm::NetworkBehaviour)]
    struct IdentifyListener {
        identify: libp2p::identify::Behaviour,
        gossipsub: libp2p::gossipsub::Behaviour,
    }

    /// A remote that hears identify from whoever dials it, at its address.
    ///
    /// It speaks gossipsub too. The gossipsub of the dialer opens its stream at once, and on a
    /// remote without gossipsub that stream fails: the dialer then takes `/meshsub/1.*` off the
    /// protocols of the connection. If that failure comes before the identify answer, the
    /// answer lists no `/meshsub/1.*`, so the remote must accept the stream.
    async fn identify_listener() -> (
        PinnedPeer,
        futures::channel::oneshot::Receiver<libp2p::identify::Info>,
    ) {
        use libp2p::swarm::SwarmEvent;
        use libp2p::{gossipsub, identify, noise, tcp, yamux, SwarmBuilder};
        let key = libp2p::identity::Keypair::generate_secp256k1();
        let mut swarm = SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|key| {
                let config = gossipsub::ConfigBuilder::default()
                    .validation_mode(gossipsub::ValidationMode::Anonymous)
                    .build()
                    .unwrap();
                IdentifyListener {
                    identify: identify::Behaviour::new(identify::Config::new(
                        cl_p2p::behaviour::IDENTIFY_PROTOCOL_VERSION.to_owned(),
                        key.public(),
                    )),
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Anonymous,
                        config,
                    )
                    .unwrap(),
                }
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        let peer_id = *swarm.local_peer_id();
        let (tx, rx) = futures::channel::oneshot::channel();
        tokio::spawn(async move {
            let mut tx = Some(tx);
            loop {
                if let SwarmEvent::Behaviour(IdentifyListenerEvent::Identify(
                    identify::Event::Received { info, .. },
                )) = swarm.select_next_some().await
                {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(info);
                    }
                }
            }
        });
        (PinnedPeer { peer_id, addr }, rx)
    }

    /// A CL drops a peer that does not speak gossipsub, so the fetch swarm announces it, as
    /// `status`'s does: the ignore-all gossipsub on `beacon_block` at our fork digest.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_fetch_swarm_speaks_gossipsub() {
        let devnet = devnet();
        let (remote, heard) = identify_listener().await;
        let digest = devnet.digest_at(3).unwrap();
        let mut swarm = fetch_swarm::<P>(
            &devnet,
            Arc::new(cl_p2p::rpc::inbound::SharedStatus::new(None)),
            &plan(vec![remote.clone()], None),
            digest,
        )
        .unwrap();
        let topics: Option<Vec<String>> = swarm.behaviour().gossipsub.as_ref().map(|g| {
            g.gossipsub()
                .topics()
                .map(|t| t.as_str().to_owned())
                .collect()
        });
        swarm
            .dial(
                DialOpts::peer_id(remote.peer_id)
                    .addresses(vec![remote.addr.clone()])
                    .build(),
            )
            .unwrap();
        let driven = tokio::spawn(async move {
            loop {
                swarm.select_next_some().await;
            }
        });
        let info = tokio::time::timeout(Duration::from_secs(10), heard)
            .await
            .expect("identify within 10 s")
            .expect("identify");
        driven.abort();
        let protocols: Vec<String> = info.protocols.iter().map(ToString::to_string).collect();
        assert!(
            protocols
                .iter()
                .any(|p| p.starts_with("/eth2/beacon_chain/req/status/")),
            "{protocols:?}"
        );
        assert!(
            protocols.iter().any(|p| p.starts_with("/meshsub/1.")),
            "{protocols:?}"
        );
        let topic =
            p2p_wire::gossip::GossipTopic::new(digest, p2p_wire::gossip::GossipKind::BeaconBlock);
        assert_eq!(topics, Some(vec![topic.to_string()]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_the_api_does_not_have_fails_its_slot() {
        let devnet = devnet();
        let blocks = chain(&[]);
        let (chain_api, server) = api_for(4, &blocks).await;
        // The API has another root at 28, and no block at 29.
        chain_api.with(|s| {
            s.roots.insert(28, Root::repeat_byte(0x28));
            s.roots.remove(&29);
        });
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let a = peer(&devnet, blocks.clone()).await;
        let b = peer(&devnet, blocks.clone()).await;
        let check = fetch_epoch::<P>(
            &devnet,
            api,
            clock(),
            &plan(vec![pinned(&a), pinned(&b)], Some(3)),
        )
        .await;
        assert!(!check.passed());
        let failed: Vec<&Line> = check.lines().iter().filter(|l| !l.pass).collect();
        assert_eq!(failed.len(), 2, "{failed:#?}");
        assert!(
            failed[0].detail.starts_with("slot 28: fetched block"),
            "{failed:#?}"
        );
        assert!(
            failed[1].detail.starts_with("slot 29: fetched block"),
            "{failed:#?}"
        );
        assert!(failed[1].detail.contains("the API has none"), "{failed:#?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_peers_word_on_trailing_empty_slots_is_unconfirmed() {
        let devnet = devnet();
        let blocks = chain(&[30, 31]);
        let (_chain, server) = api_for(4, &blocks).await;
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let a = peer(&devnet, blocks).await;
        let check = fetch_epoch::<P>(&devnet, api, clock(), &plan(vec![pinned(&a)], None)).await;
        assert!(!check.passed());
        let lines = details(&check);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("unconfirmed: slots 30..32")),
            "{lines:#?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_epoch_must_be_finalized_and_past_genesis() {
        let devnet = devnet();
        let blocks = chain(&[]);
        let a = peer(&devnet, blocks.clone()).await;
        for (finalized, epoch, want) in [
            (1, None, "finalized epoch 1"),
            (4, Some(4), "epoch 4 is not before the finalized epoch 4"),
            (4, Some(0), "epoch 0"),
        ] {
            let (_chain, server) = api_for(finalized, &blocks).await;
            let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
            let check =
                fetch_epoch::<P>(&devnet, api, clock(), &plan(vec![pinned(&a)], epoch)).await;
            assert!(!check.passed());
            let lines = details(&check);
            assert!(lines.iter().any(|l| l.contains(want)), "{want}: {lines:#?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_status_valid_peer_fails() {
        let devnet = devnet();
        let blocks = chain(&[]);
        let (_chain, server) = api_for(4, &blocks).await;
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let mut plan = plan(vec![closed_port_peer()], None);
        plan.status_deadline = Duration::from_secs(1);
        let check = fetch_epoch::<P>(&devnet, api.clone(), clock(), &plan).await;
        assert!(!check.passed());
        let lines = details(&check);
        assert!(
            lines.iter().any(|l| l.contains("dial failed")),
            "{lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("no Status-valid peer")),
            "{lines:#?}"
        );
        // No API at all: no Status of ours.
        let down = FixtureChain::default();
        down.with(|s| s.down = true);
        let server = down.serve().await;
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let check = fetch_epoch::<P>(&devnet, api, clock(), &plan).await;
        assert!(details(&check)[0].contains("no Status of ours"));
    }
}
