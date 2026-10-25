//! End to end, in process: cl-chain (probe mode's column store, its column server and our
//! Status on `ethswarm.chain.v1.ReqRespService`, behind its method ACL on a Unix socket in a
//! temp dir) and cl-p2p (the probe swarm, whose column responders and Status ask cl-chain over
//! that socket), as `devnet_probe::serve` wires them.
//!
//! Columns come in through the real ingest path: each sidecar as cl-p2p's gossipsub captures
//! it (`Captured` on the swarm's capture tap: the topic and the decompressed SSZ) is decoded by
//! the fork of its slot and handed to `ColumnIngest::on_column`, where the reference node (a
//! fixture beacon API over HTTP) vouches for its block root, the cells are checked by KZG (a
//! verifier that passes every cell: cl-verify is not under test here, `cl-chain`'s
//! `tests/v2_serving.rs` runs the real one), and only custody columns are stored. A libp2p
//! requester then asks the probe as a peer would, and every answer is held to the store, byte
//! for byte, and to the serving rules (`cl_chain::reqresp`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cl_chain::probe::{BeaconApi, DEFAULT_API_TIMEOUT};
use cl_chain::verify::client::{KzgOutcome, KzgVerifier};
use cl_p2p::gossip::{capture_tap, CaptureTap, Captured};
use cl_p2p::rpc::answer_bucket::AnswerPrefixes;
use consensus_types::das::{compute_subnet_for_data_column_sidecar, custody_columns};
use consensus_types::primitives::Root;
use consensus_types::{gloas, Minimal};
use devnet_probe::answers::{self, AnswersPlan};
use devnet_probe::devnet::Devnet;
use devnet_probe::fixtures::FixtureChain;
use devnet_probe::serve::{
    self, chain_link, node_id, p2p_swarm, ChainPlan, ChainSide, ColumnAnswer, ColumnRequester,
    ServePlan,
};
use devnet_probe::swarm::SwarmPlan;
use ethswarm_proto::chain as pb;
use ethswarm_proto::verify::KzgCellProof;
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use network_config::Genesis;
use p2p_wire::gossip::{GossipKind, GossipTopic};
use p2p_wire::rpc::messages::ForkDigest;
use p2p_wire::rpc::protocols::ResultCode;
use pb::req_resp_service_client::ReqRespServiceClient;
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use testkit::collector::testing::FixtureServer;
use tree_hash::TreeHash;

type E = Minimal;

/// The slot the wall clock is at when a test starts: the first slot of epoch 12 (Gloas).
const NOW_SLOT: u64 = 96;
/// The blocks stored: five, from [`NOW_SLOT`], each the child of the one before.
const SLOTS: std::ops::Range<u64> = NOW_SLOT..NOW_SLOT + 5;
/// The reference's chain goes on past [`SLOTS`] to here (exclusive).
const CHAIN_END: u64 = NOW_SLOT + 7;
/// A block the reference vouches for whose parent it does not know: a gap before it.
const GAP_SLOT: u64 = NOW_SLOT + 7;
/// How long the store may take to settle.
const SETTLE: Duration = Duration::from_secs(30);

/// Passes every cell.
struct Valid;

impl KzgVerifier for Valid {
    async fn verify_cells(&self, _: Vec<KzgCellProof>, _: Duration) -> KzgOutcome {
        KzgOutcome::Valid
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

/// The fixture devnet (minimal, Fulu at 0, a blob change at 1, Gloas at 2, 6 s slots), its
/// genesis [`NOW_SLOT`] slots ago, with the serve range's config value.
fn devnet() -> Devnet {
    devnet_at(NOW_SLOT, "")
}

/// The fixture devnet, its genesis `now_slot` slots ago, its config with `more` appended
/// before the serve range's value.
fn devnet_at(now_slot: u64, more: &str) -> Devnet {
    let config = format!(
        "{}{more}MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS: 4096\n",
        testkit::export_blocks::fixtures::CONFIG
    );
    let now_s = u64::try_from(now_ms() / 1000).unwrap();
    let genesis = Genesis {
        genesis_time: now_s - now_slot * 6,
        genesis_validators_root: [0x42; 32],
    };
    Devnet::new(config.as_bytes(), genesis).unwrap()
}

/// A Gloas block at `slot` on `parent` whose bid commits to one blob: its root and SSZ.
fn block(slot: u64, parent: [u8; 32]) -> ([u8; 32], Vec<u8>) {
    let mut block = p2p_wire::testkit::gloas_block::<E>(slot);
    block.message.parent_root = parent.into();
    block
        .message
        .body
        .signed_execution_payload_bid
        .message
        .blob_kzg_commitments = vec![[0xc0; 48]].try_into().unwrap();
    (block.message.tree_hash_root().0, block.as_ssz_bytes())
}

/// The test chain: an anchor before [`SLOTS`] (its parent unknown) and a block at each of
/// them, each on the one before; `(slot, root)` of each, anchor first. It is the reference's
/// canonical chain, to its head in the slot before [`CHAIN_END`].
#[derive(Clone)]
struct Chain {
    blocks: Vec<(u64, [u8; 32])>,
    /// The root of the block at [`GAP_SLOT`].
    gap: [u8; 32],
}

impl Chain {
    /// The chain to [`CHAIN_END`], served by `reference` (headers and blocks), finalized at
    /// the anchor; and the block at [`GAP_SLOT`] whose parent nobody knows.
    fn new(reference: &FixtureChain) -> Self {
        let mut blocks = Vec::new();
        let mut parent = [0x99; 32];
        let serve = |slot: u64, root: [u8; 32], ssz: Vec<u8>| {
            reference.with(|s| {
                s.headers.insert(Root::from(root), slot);
                s.blocks.insert(Root::from(root), ssz);
            });
        };
        for slot in (NOW_SLOT - 1)..CHAIN_END {
            let (root, ssz) = block(slot, parent);
            serve(slot, root, ssz);
            blocks.push((slot, root));
            parent = root;
        }
        let (gap, ssz) = block(GAP_SLOT, [0x77; 32]);
        serve(GAP_SLOT, gap, ssz);
        reference.finalize(11, Root::from(blocks[0].1), NOW_SLOT - 1);
        // Its head, whose chain the probe's range answers follow, is the chain's last block.
        let (slot, head) = blocks[blocks.len() - 1];
        reference.with(|s| s.head = Some((slot, Root::from(head))));
        Self { blocks, gap }
    }

    /// The root of the chain's block at `slot`.
    fn root(&self, slot: u64) -> [u8; 32] {
        self.blocks.iter().find(|(s, _)| *s == slot).unwrap().1
    }
}

/// Column `index` of the chain's block at `slot`, as gossiped: one cell, distinct per column.
fn sidecar(chain: &Chain, slot: u64, index: u64) -> gloas::DataColumnSidecar<E> {
    sidecar_of(chain.root(slot), slot, index)
}

/// Column `index` of the block `root` at `slot`.
fn sidecar_of(root: [u8; 32], slot: u64, index: u64) -> gloas::DataColumnSidecar<E> {
    gloas::DataColumnSidecar {
        index,
        column: vec![vec![index as u8 ^ slot as u8; 2048].try_into().unwrap()]
            .try_into()
            .unwrap(),
        kzg_proofs: vec![[0x0b; 48]].try_into().unwrap(),
        slot,
        beacon_block_root: root.into(),
    }
}

/// `sidecar` as the swarm's capture tap hands it over from its subnet's topic.
fn captured(devnet: &Devnet, sidecar: &gloas::DataColumnSidecar<E>) -> Captured {
    let digest = devnet.digest_at(sidecar.slot / 8).unwrap();
    let subnet_id = compute_subnet_for_data_column_sidecar(sidecar.index);
    Captured {
        recv_mono: std::time::Instant::now(),
        recv_wall: SystemTime::now(),
        topic: GossipTopic::new(digest, GossipKind::DataColumnSidecar { subnet_id }).to_string(),
        message_id: vec![0; 20],
        source: PeerId::random(),
        data: sidecar.as_ssz_bytes(),
    }
}

/// Gossips `indices` of every block of [`SLOTS`] into `tap`.
fn gossip(devnet: &Devnet, chain: &Chain, tap: &CaptureTap, indices: &[u64]) {
    for slot in SLOTS {
        for &index in indices {
            assert!(tap.offer(captured(devnet, &sidecar(chain, slot, index))));
        }
    }
}

/// A socket root the bind accepts, or a column store's parent `serve` accepts: a fresh
/// directory named without symlinks (macOS's `/var` is one), short enough for a socket path.
fn socket_root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new().prefix("sv-").tempdir().unwrap();
    let path = std::fs::canonicalize(dir.path()).unwrap();
    (dir, path)
}

fn reference_api(server: &FixtureServer) -> BeaconApi {
    BeaconApi::new(&format!("http://{}", server.addr), DEFAULT_API_TIMEOUT).unwrap()
}

fn listen() -> Vec<Multiaddr> {
    vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()]
}

/// Waits until `done` holds; fails after [`SETTLE`].
async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + SETTLE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Our Status as the probe `peer` answers `requester`, read fresh each time: never below the
/// slot `probe` serves from.
async fn advertised(
    requester: &mut ColumnRequester<E>,
    peer: PeerId,
    digest: ForkDigest,
    probe: &ChainSide<E, Valid>,
) -> p2p_wire::rpc::messages::StatusV2 {
    let ours = requester.status(peer, digest).await.unwrap();
    let floor = probe.status_floor().unwrap();
    assert!(
        ours.earliest_available_slot >= floor,
        "advertised {} below {floor}",
        ours.earliest_available_slot
    );
    if let Some(served) = probe.earliest_available_slot() {
        assert!(ours.earliest_available_slot >= served);
    }
    ours
}

/// A serve plan of `serve_for` into `columns_dir`, the socket under `socket_root`.
fn serve_plan(serve_for: Duration, columns_dir: PathBuf, socket_root: PathBuf) -> ServePlan {
    ServePlan {
        listen: listen(),
        peers: Vec::new(),
        serve_for,
        columns_dir,
        socket_root,
        verify_timeout: Duration::from_secs(5),
        answer_prefixes: AnswerPrefixes::default(),
    }
}

/// The wire form of the stored sidecars of `slots` for `indices`, as the requester reads them.
fn wire(
    devnet: &Devnet,
    chain: &Chain,
    slots: impl IntoIterator<Item = u64>,
    indices: &[u64],
) -> Vec<(ForkDigest, Vec<u8>)> {
    slots
        .into_iter()
        .flat_map(|slot| {
            indices.iter().map(move |&i| {
                let digest = devnet.digest_at(slot / 8).unwrap();
                (digest, sidecar(chain, slot, i).as_ssz_bytes())
            })
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custody_columns_from_gossip_are_served_byte_for_byte() {
    let devnet = devnet();
    let reference = FixtureChain::default();
    let chain = Chain::new(&reference);
    let server = reference.serve().await;

    let key = Keypair::generate_secp256k1();
    let id = node_id(&key).unwrap();
    let custody = custody_columns(id, 4).unwrap();
    let other: Vec<u64> = (0..128).filter(|c| !custody.contains(c)).take(2).collect();
    let link = chain_link::<E>(&devnet, now_ms()).unwrap();
    let columns_dir = tempfile::tempdir().unwrap();
    let (_root_dir, root) = socket_root();
    let uid = ipc::uds::Ownership::current().uid;
    let probe = ChainSide::<E, Valid>::start(
        &devnet,
        ChainPlan {
            link: link.clone(),
            node_id: id,
            columns_dir: columns_dir.path().join("columns"),
            socket_root: root.clone(),
            caller_uid: uid,
            reference: reference_api(&server),
            kzg: Valid,
            verify_timeout: Duration::from_secs(5),
            cgc_set_slot: NOW_SLOT,
        },
        &mut Registry::default(),
    )
    .unwrap();
    // A Status never waits on the reference API: the first needs a sample.
    probe.sample_reference().await.unwrap();
    assert_eq!(probe.custody_columns(), custody);
    assert_eq!(probe.custody_group_count(), 4);
    assert_eq!(
        probe.socket(),
        root.join("cl-chain/cl-chain.sock"),
        "cl-chain's socket under the root"
    );
    let (tap, tapped) = capture_tap(2048);
    let digest = devnet.digest_at(NOW_SLOT / 8).unwrap();
    let plan = SwarmPlan {
        listen: listen(),
        idle: Duration::from_secs(60),
        bypass: Vec::new(),
        muxer_observer: None,
        ping_interval: cl_p2p::rpc::inbound::PING_INTERVAL,
        gossip: None,
        limits: cl_p2p::rpc::limits::RpcLimits::default(),
    };
    let p2p = p2p_swarm::<E>(
        &devnet,
        link,
        probe.socket(),
        uid,
        key,
        plan,
        &custody,
        4,
        digest,
        tap.clone(),
    )
    .await
    .unwrap();
    let (mut swarm, our_status, refresh) = (p2p.swarm, p2p.status, p2p.refresh);
    // The ignore-all gossipsub is on our custody subnets (and beacon_block).
    let topics: Vec<String> = swarm
        .behaviour()
        .gossipsub
        .as_ref()
        .unwrap()
        .gossipsub()
        .topics()
        .map(|t| t.as_str().to_owned())
        .collect();
    for &c in &custody {
        let subnet = GossipKind::DataColumnSidecar {
            subnet_id: compute_subnet_for_data_column_sidecar(c),
        };
        assert!(topics.contains(&GossipTopic::new(digest, subnet).to_string()));
    }
    let addr = tokio::time::timeout(SETTLE, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    })
    .await
    .expect("the probe swarm listens");
    let peer = *swarm.local_peer_id();
    let probe = Arc::new(probe);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let pumping = Arc::new(AtomicBool::new(true));
    let driver = tokio::spawn(serve::drive(
        swarm,
        Arc::clone(&probe),
        tapped,
        pumping,
        stopped,
    ));
    let mut requester = ColumnRequester::<E>::new(&devnet).unwrap();
    requester.connect(peer, addr.clone()).await.unwrap();
    // Nothing stored yet: the slot it serves from at the earliest, cgc_set_slot, not the head.
    let empty = advertised(&mut requester, peer, digest, &probe).await;
    assert_eq!(
        (empty.head_slot, empty.earliest_available_slot),
        (NOW_SLOT - 1, NOW_SLOT)
    );

    // Every custody column of five blocks, and two columns we do not custody, from gossip.
    let mut gossiped = custody.clone();
    gossiped.extend(&other);
    gossip(&devnet, &chain, &tap, &gossiped);
    wait_for("the store to settle", || {
        probe.reader().column_count().unwrap() >= (5 * custody.len()) as u64 && probe.pending() == 0
    })
    .await;
    assert_eq!(
        probe.reader().column_count().unwrap(),
        (5 * custody.len()) as u64,
        "custody columns only"
    );
    assert_eq!(probe.earliest_available_slot(), Some(NOW_SLOT));
    assert_eq!(
        advertised(&mut requester, peer, digest, &probe)
            .await
            .earliest_available_slot,
        NOW_SLOT
    );
    // The outside check of the systemd units: a peer of its own asks, and every answer is
    // judged against the store, by range from the Status's earliest slot to the last block.
    let outside = AnswersPlan {
        probe: addr.clone(),
        columns_dir: columns_dir.path().join("columns"),
        node_id: id,
        behind_slots: Some(0),
    };
    let at_the_last_block = now_ms() + 4 * 6_000;
    let judged =
        answers::answers_with::<E>(&devnet, &outside, probe.reader(), at_the_last_block).await;
    assert!(judged.passed(), "{:?}", judged.render());
    assert_eq!(judged.lines().len(), 4, "{:?}", judged.render());
    // A range that ends before the slot it is served from has nothing to ask.
    let early =
        answers::answers_with::<E>(&devnet, &outside, probe.reader(), now_ms() - 6_000).await;
    assert!(!early.passed(), "{:?}", early.render());
    // By range: every block of the range, every requested custody column, byte for byte, in
    // (slot, column_index) order, each with the digest of its slot's epoch.
    let got = requester
        .by_range(peer, NOW_SLOT, 5, &custody)
        .await
        .unwrap();
    assert!(
        got == ColumnAnswer::Sidecars(wire(&devnet, &chain, SLOTS, &custody)),
        "by range: not the stored bytes"
    );
    // Part of the custody, part of the range.
    let some = [custody[2], custody[0]];
    let got = requester
        .by_range(peer, NOW_SLOT + 1, 2, &some)
        .await
        .unwrap();
    let mut sorted = some.to_vec();
    sorted.sort_unstable();
    assert!(
        got == ColumnAnswer::Sidecars(wire(&devnet, &chain, NOW_SLOT + 1..NOW_SLOT + 3, &sorted))
    );
    // By root: the stored identifiers, in request order; an unknown root left out.
    let got = requester
        .by_root(
            peer,
            &[
                (chain.root(NOW_SLOT + 3), custody.clone()),
                ([0x5a; 32], custody.clone()),
                (chain.root(NOW_SLOT), vec![custody[1]]),
            ],
        )
        .await
        .unwrap();
    let mut want = wire(&devnet, &chain, [NOW_SLOT + 3], &custody);
    want.extend(wire(&devnet, &chain, [NOW_SLOT], &[custody[1]]));
    assert!(
        got == ColumnAnswer::Sidecars(want),
        "by root: not the stored bytes"
    );
    // A column we do not custody (and never stored, though it was gossiped).
    assert_eq!(
        requester.by_range(peer, NOW_SLOT, 5, &other[..1]).await,
        Ok(ColumnAnswer::Refused(ResultCode::ResourceUnavailable))
    );
    assert_eq!(
        requester
            .by_root(peer, &[(chain.root(NOW_SLOT), other.clone())])
            .await,
        Ok(ColumnAnswer::Sidecars(Vec::new()))
    );
    // Below earliest_available_slot: unavailable, never an empty success.
    assert_eq!(
        requester.by_range(peer, NOW_SLOT - 8, 4, &custody).await,
        Ok(ColumnAnswer::Refused(ResultCode::ResourceUnavailable))
    );
    // After the current epoch: nothing exists there yet, an empty success.
    assert_eq!(
        requester.by_range(peer, NOW_SLOT + 64, 4, &custody).await,
        Ok(ColumnAnswer::Sidecars(Vec::new()))
    );
    // Out of bounds: an index past NUMBER_OF_COLUMNS.
    assert_eq!(
        requester.by_range(peer, NOW_SLOT, 1, &[128]).await,
        Ok(ColumnAnswer::Refused(ResultCode::InvalidRequest))
    );

    // A sidecar on a topic of another fork digest than its slot's is dropped undecoded, and
    // never stored.
    let mut elsewhere = captured(&devnet, &sidecar(&chain, NOW_SLOT + 5, custody[0]));
    let fulu = devnet.digest_at(0).unwrap();
    elsewhere.topic = GossipTopic::new(
        fulu,
        GossipKind::DataColumnSidecar {
            subnet_id: compute_subnet_for_data_column_sidecar(custody[0]),
        },
    )
    .to_string();
    let before = probe.reader().column_count().unwrap();
    assert!(!probe.hand_over(&elsewhere));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(probe.reader().column_count().unwrap(), before);

    // Only column sidecars that decode are handed over.
    let mut block = captured(&devnet, &sidecar(&chain, NOW_SLOT, custody[0]));
    block.topic = GossipTopic::new(digest, GossipKind::BeaconBlock).to_string();
    assert!(!probe.hand_over(&block));
    let mut garbage = captured(&devnet, &sidecar(&chain, NOW_SLOT, custody[0]));
    garbage.data.truncate(7);
    assert!(!probe.hand_over(&garbage));

    // cl-chain's GetStatus, as cl-p2p reads it: its earliest_available_slot is the column
    // server's. The ACL lets cl-p2p call the serving methods and nothing else.
    let channel = ipc::uds::connect_path(probe.socket(), uid).await.unwrap();
    let mut client = ReqRespServiceClient::new(channel);
    let status = client
        .get_status(pb::GetStatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(status.earliest_available_slot, NOW_SLOT);
    assert_eq!(status.head_slot, NOW_SLOT - 1);
    let denied = client
        .get_metadata(pb::GetMetadataRequest {})
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    // A block the reference vouches for but whose parent it does not know: a gap before it,
    // which raises the slot served from. Our Status follows at once, not a refresh later.
    for &index in &custody {
        assert!(tap.offer(captured(&devnet, &sidecar_of(chain.gap, GAP_SLOT, index))));
    }
    wait_for("the gap to raise the floor", || {
        probe.earliest_available_slot() > Some(NOW_SLOT) && probe.pending() == 0
    })
    .await;
    let raised = advertised(&mut requester, peer, digest, &probe).await;
    assert_eq!(
        Some(raised.earliest_available_slot),
        probe.earliest_available_slot()
    );
    // The last good Status for judging was refreshed by those reads too.
    let cached = cl_p2p::rpc::inbound::StatusSource::status(&our_status).unwrap();
    assert_eq!(
        cached.earliest_available_slot,
        raised.earliest_available_slot
    );

    let _ = stop.send(());
    driver.await.unwrap();
    drop(refresh);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_stores_and_answers_on_a_devnet_of_one() {
    let devnet = devnet();
    let reference = FixtureChain::default();
    let chain = Chain::new(&reference);
    let server = reference.serve().await;
    let (_columns_dir, columns_dir) = socket_root();
    let (_root_dir, root) = socket_root();
    let plan = serve_plan(Duration::from_secs(4), columns_dir.join("columns"), root);
    // The probe's node key, and so its custody, is its own: every column is gossiped, a
    // block's 128 at a time, below the store's pending queue (512). Gossip goes on while it
    // checks its answers, which hold all the same: nothing enters the store meanwhile.
    let (tap, tapped) = capture_tap(1024);
    let all: Vec<u64> = (0..128).collect();
    let feed = {
        let (devnet, chain, tap) = (devnet.clone(), chain.clone(), tap.clone());
        tokio::spawn(async move {
            for slot in SLOTS {
                for &index in &all {
                    assert!(tap.offer(captured(&devnet, &sidecar(&chain, slot, index))));
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            for slot in SLOTS.end..CHAIN_END {
                tokio::time::sleep(Duration::from_millis(1200)).await;
                for &index in &all {
                    // Past the tap's room while the hand-off is stopped: dropped, counted.
                    let _ = tap.offer(captured(&devnet, &sidecar(&chain, slot, index)));
                }
            }
        })
    };
    let check = serve::serve::<E, Valid>(
        &devnet,
        reference_api(&server),
        Valid,
        &plan,
        (tap, tapped),
        now_ms(),
    )
    .await;
    feed.await.unwrap();
    let lines: Vec<_> = check
        .lines()
        .iter()
        .map(|l| (l.pass, l.detail.clone()))
        .collect();
    assert!(check.passed(), "{lines:#?}");
    assert_eq!(lines.len(), 7, "{lines:#?}");
    assert!(lines[1].1.contains("head slot 95"), "{lines:#?}");
    assert!(lines[2].1.contains("custody columns stored"), "{lines:#?}");
    assert!(lines[2].1.contains("dropped: not_custody="), "{lines:#?}");
    assert!(
        lines[3]
            .1
            .contains("our Status advertises earliest_available_slot 96, served from 96"),
        "{lines:#?}"
    );
    assert!(
        lines[4].1.contains("each as stored, in order"),
        "{lines:#?}"
    );
}

/// With nothing gossiped (and a reference CL that refuses the dial) nothing is stored, and
/// the check says so instead of judging empty answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_with_nothing_stored_fails() {
    let devnet = devnet();
    let reference = FixtureChain::default();
    reference.finalize(11, Root::from([7; 32]), 88);
    let server = reference.serve().await;
    let (_columns_dir, columns_dir) = socket_root();
    let (_root_dir, root) = socket_root();
    let closed = cl_p2p::testkit::refused_tcp_addr(std::net::Ipv4Addr::LOCALHOST.into());
    let peer = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}",
        closed.port(),
        PeerId::random()
    );
    let plan = ServePlan {
        peers: vec![devnet_probe::devnet::parse_peer(&peer).unwrap()],
        ..serve_plan(Duration::from_secs(1), columns_dir.join("columns"), root)
    };
    let check = serve::serve::<E, Valid>(
        &devnet,
        reference_api(&server),
        Valid,
        &plan,
        capture_tap(1),
        now_ms(),
    )
    .await;
    let lines: Vec<_> = check
        .lines()
        .iter()
        .map(|l| (l.pass, l.detail.clone()))
        .collect();
    assert!(!check.passed(), "{lines:#?}");
    assert!(
        lines[1].0 && lines[1].1.contains("head slot 88"),
        "{lines:#?}"
    );
    assert!(
        lines[2].1.contains("0 custody columns stored"),
        "{lines:#?}"
    );
    assert!(lines[3].0, "{lines:#?}");
    assert!(lines[4].1.contains("nothing to serve"), "{lines:#?}");
}

#[tokio::test]
async fn serve_needs_a_new_store_it_can_open() {
    let devnet = devnet();
    let reference = FixtureChain::default();
    let server = reference.serve().await;
    let (_root_dir, root) = socket_root();
    let file = tempfile::NamedTempFile::new_in(&root).unwrap();
    let run = |columns_dir: PathBuf, socket_root: PathBuf| {
        let plan = serve_plan(Duration::from_secs(1), columns_dir, socket_root);
        let api = reference_api(&server);
        let devnet = devnet.clone();
        async move {
            serve::serve::<E, Valid>(&devnet, api, Valid, &plan, capture_tap(1), now_ms()).await
        }
    };
    // A store of another run (another node key): refused before anything is opened.
    let old = run(file.path().to_owned(), root.clone()).await;
    assert!(!old.passed());
    assert!(
        old.lines()[0].detail.contains("must be new"),
        "{:?}",
        old.lines()
    );
    // A store that cannot be created.
    let check = run(file.path().join("columns"), root.clone()).await;
    assert!(!check.passed());
    assert!(
        check.lines()[0].detail.contains("column store"),
        "{:?}",
        check.lines()
    );
    // A start that fails after the store was created (no socket under a file) leaves no store
    // behind, so the next run is not refused for it.
    let (_dir, dir) = socket_root();
    let columns = dir.join("columns");
    let check = run(columns.clone(), file.path().to_owned()).await;
    assert!(!check.passed());
    assert!(
        check.lines()[0].detail.contains("socket"),
        "{:?}",
        check.lines()
    );
    assert!(!columns.exists(), "the new store was removed");
    // A symlink in its place is refused, not followed.
    std::os::unix::fs::symlink(&dir, &columns).unwrap();
    let check = run(columns.clone(), root.clone()).await;
    assert!(
        check.lines()[0].detail.contains("must be new"),
        "{:?}",
        check.lines()
    );
}

/// A run that would cross the next fork digest is cut short before it, and one too close to
/// it is refused: the probe subscribes to one digest's column subnets.
#[tokio::test]
async fn serve_does_not_cross_a_fork_digest() {
    // A blob change at epoch 13: one slot after the clock's.
    let more = "  - EPOCH: 13\n    MAX_BLOBS_PER_BLOCK: 15\n";
    let devnet = devnet_at(103, more);
    let reference = FixtureChain::default();
    let server = reference.serve().await;
    let (_dir, dir) = socket_root();
    let (_root_dir, root) = socket_root();
    let plan = serve_plan(Duration::from_secs(60), dir.join("columns"), root);
    let check = serve::serve::<E, Valid>(
        &devnet,
        reference_api(&server),
        Valid,
        &plan,
        capture_tap(1),
        now_ms(),
    )
    .await;
    assert!(!check.passed());
    assert!(
        check.lines()[0].detail.contains("changes at epoch 13"),
        "{:?}",
        check.lines()
    );
    assert!(!dir.join("columns").exists(), "refused before the store");
}

/// A start that took so long that the clip after it fails ends the run as a failed start
/// does: the new store is removed, so a rerun with the same arguments is not refused for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clip_that_fails_after_the_start_removes_the_new_store() {
    // A blob change at epoch 14 (slot 112), 6 slots after the clock's: the run starts one
    // slot and the check's time before it, so the start's own time leaves less than a slot to
    // serve.
    let more = "  - EPOCH: 14\n    MAX_BLOBS_PER_BLOCK: 15\n";
    let devnet = devnet_at(106, more);
    let (epoch, change) = serve::next_digest_change(&devnet, now_ms()).unwrap();
    assert_eq!(epoch, 14);
    let started = change - (serve::AFTER_SERVING + Duration::from_secs(6)).as_millis();
    let reference = FixtureChain::default();
    reference.finalize(12, Root::from([7; 32]), 96);
    let server = reference.serve().await;
    let (_dir, dir) = socket_root();
    let (_root_dir, root) = socket_root();
    let columns = dir.join("columns");
    let plan = serve_plan(Duration::from_secs(60), columns.clone(), root);
    let check = serve::serve::<E, Valid>(
        &devnet,
        reference_api(&server),
        Valid,
        &plan,
        capture_tap(1),
        started,
    )
    .await;
    let lines: Vec<_> = check
        .lines()
        .iter()
        .map(|l| (l.pass, l.detail.clone()))
        .collect();
    assert!(!check.passed(), "{lines:#?}");
    assert!(
        lines
            .iter()
            .any(|(pass, detail)| !pass && detail.contains("after a start of")),
        "{lines:#?}"
    );
    assert!(!columns.exists(), "the new store was removed");
}
