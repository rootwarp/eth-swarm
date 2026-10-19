//! `status`: the Status v2 exchange with each reference CL in both directions, then each
//! connection held, with our Ping cadence and no Goodbye from either side.
//!
//! Per reference CL, on one probe swarm:
//!
//! 1. **Ours answered**: we dial it and our Status v2 goes out first (the dialer's duty); its
//!    response must be a Status that is relevant to ours (same fork digest, no conflicting
//!    finalized checkpoint), within the status deadline from the start.
//! 2. **Theirs answered**: it sends us its Status as a request, relevant to ours, and our
//!    answer with our Status is sent (written to its stream, not only queued). A CL
//!    sends that on its periodic re-Status (every few minutes), so it must arrive by the end
//!    of the hold, on the same connection.
//! 3. **Held**: from our answered Status, the connection stays up for the hold, while we Ping
//!    it every ping interval, and neither side says Goodbye. A Goodbye is reported with its
//!    reason; a Status that is not relevant gets our Goodbye 2 and fails.
//!
//! Our Status comes from probe mode's provider ([`OurStatus`]). The swarm carries the probe's
//! ignore-all gossipsub on `beacon_block` at our fork digest, as the production probe does.

use super::api::ProbeApi;
use super::devnet::Devnet;
pub use super::ours::Clock;
use super::ours::OurStatus;
use super::report::Check;
use super::swarm::{error_chain, probe_swarm, SwarmPlan};
use cl_p2p::behaviour::{SpecBehaviour, SpecBehaviourEvent};
use cl_p2p::m2a_session::PinnedPeer;
use cl_p2p::rpc::inbound::{
    ControlEvent, Relevance, StatusVia, GOODBYE_CLIENT_SHUTDOWN, GOODBYE_FAULT,
    GOODBYE_IRRELEVANT_NETWORK,
};
use cl_p2p::transport::DialFailure;
use consensus_types::EthSpec;
use futures::StreamExt;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{ConnectionId, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm};
use p2p_wire::rpc::messages::StatusV2;
use std::time::Duration;
use tokio::time::Instant;

/// The check's name.
pub const NAME: &str = "status";
/// The hold the criterion asks for, 10 minutes: a shorter one is diagnostic only.
pub const ACCEPTANCE_HOLD: Duration = Duration::from_secs(600);
/// How long each connection must hold by default: [`ACCEPTANCE_HOLD`].
pub const DEFAULT_HOLD: Duration = ACCEPTANCE_HOLD;
/// Our Ping cadence by default: cl-p2p's (`PING_INTERVAL`, 15 s).
pub const DEFAULT_PING_INTERVAL: Duration = cl_p2p::rpc::inbound::PING_INTERVAL;
/// How long, from the start, each peer has to answer our Status by default \[est\].
pub const DEFAULT_STATUS_DEADLINE: Duration = Duration::from_secs(30);
/// The least idle-connection timeout of the swarm: well past our Ping cadence, so a quiet
/// moment between Pings never closes a held connection on our side.
const MIN_IDLE: Duration = Duration::from_secs(60);
/// How often the deadlines are looked at.
const TICK: Duration = Duration::from_millis(100);

/// What `status` runs.
#[derive(Debug, Clone)]
pub struct StatusPlan {
    /// The reference CLs, each at its TCP address.
    pub peers: Vec<PinnedPeer>,
    /// How long each connection must hold after our Status was answered.
    pub hold: Duration,
    /// How often cl-p2p's req/resp behaviour Pings each peer (its Ping cadence).
    pub ping_interval: Duration,
    /// How long, from the start, each peer has to answer our Status.
    pub status_deadline: Duration,
    /// How often our Status is sampled again.
    pub refresh_interval: Duration,
    /// Where the probe swarm listens; none by default (every exchange runs on our dial).
    pub listen: Vec<Multiaddr>,
}

/// The reason name of a Goodbye (`phase0/p2p-interface.md` Goodbye).
#[must_use]
pub fn goodbye_name(reason: u64) -> &'static str {
    match reason {
        GOODBYE_CLIENT_SHUTDOWN => "client shutdown",
        GOODBYE_IRRELEVANT_NETWORK => "irrelevant network",
        GOODBYE_FAULT => "fault/error",
        _ => "unknown reason",
    }
}

/// What is known of one peer.
struct Watch {
    peer: PinnedPeer,
    connection: Option<ConnectionId>,
    /// When its response to our Status was judged relevant, and that Status.
    ours_answered: Option<(Instant, StatusV2)>,
    /// Whether its own Status (a request) was judged relevant.
    theirs_relevant: bool,
    /// When our answer to that request was sent ([`ControlEvent::StatusAnswered`]).
    theirs_answered: Option<Instant>,
    pongs: u32,
    /// The verdict, once there is one.
    done: Option<Result<String, String>>,
}

impl Watch {
    fn fail(&mut self, why: String) {
        if self.done.is_none() {
            tracing::warn!(peer = %self.peer.peer_id, %why, "status check failed");
            self.done = Some(Err(why));
        }
    }
}

/// Runs the check on every peer of `plan`: one line per peer.
pub async fn status<E: EthSpec>(
    devnet: &Devnet,
    api: ProbeApi,
    clock: Clock,
    plan: &StatusPlan,
) -> Check {
    let (ours, first) = match OurStatus::start(devnet, api, clock, plan.refresh_interval).await {
        Ok(started) => started,
        Err(e) => return Check::failed(NAME, e),
    };
    tracing::info!(
        fork_digest = ?first.fork_digest,
        finalized_epoch = first.finalized_epoch,
        head_slot = first.head_slot,
        "our Status"
    );
    let swarm_plan = SwarmPlan {
        listen: plan.listen.clone(),
        idle: plan.ping_interval.saturating_mul(4).max(MIN_IDLE),
        bypass: plan.peers.iter().map(|p| p.peer_id).collect(),
        muxer_observer: None,
        // The production probe's gossipsub, so a CL holds the connection to the swarm the
        // probe really runs: subscribed to beacon_block, every message IGNOREd.
        // cl-p2p's own Ping cadence, at the plan's interval.
        ping_interval: plan.ping_interval,
        gossip: Some(first.fork_digest),
        limits: cl_p2p::rpc::limits::RpcLimits::default(),
    };
    let mut swarm = match probe_swarm::<E>(devnet, ours.source(), swarm_plan) {
        Ok(swarm) => swarm,
        Err(e) => return Check::failed(NAME, format!("probe swarm: {e}")),
    };
    let mut watches: Vec<Watch> = plan
        .peers
        .iter()
        .map(|peer| Watch {
            peer: peer.clone(),
            connection: None,
            ours_answered: None,
            theirs_relevant: false,
            theirs_answered: None,
            pongs: 0,
            done: None,
        })
        .collect();
    for w in &mut watches {
        let opts = DialOpts::peer_id(w.peer.peer_id)
            .addresses(vec![w.peer.addr.clone()])
            .build();
        if let Err(e) = swarm.dial(opts) {
            w.fail(dial_failure(&e));
        }
    }
    run(&mut swarm, &mut watches, plan).await;
    drop(ours);
    let mut check = Check::new(NAME);
    for w in watches {
        let at = format!("peer {} at {}", w.peer.peer_id, w.peer.addr);
        match w.done {
            Some(Ok(detail)) => check.pass(format!("{at}: {detail}")),
            Some(Err(why)) => check.fail(format!("{at}: {why}")),
            None => check.fail(format!("{at}: no verdict")),
        }
    }
    check
}

/// Drives the swarm until every peer has a verdict.
async fn run<E: EthSpec>(
    swarm: &mut Swarm<SpecBehaviour<E>>,
    watches: &mut [Watch],
    plan: &StatusPlan,
) {
    let start = Instant::now();
    let mut tick = tokio::time::interval(TICK);
    while watches.iter().any(|w| w.done.is_none()) {
        tokio::select! {
            event = swarm.select_next_some() => on_event(event, watches),
            _ = tick.tick() => {}
        }
        let now = Instant::now();
        for w in watches.iter_mut().filter(|w| w.done.is_none()) {
            judge_time(w, now, start, plan);
        }
    }
}

/// Whether `now` is `after` past `from`; never, for a time past what the clock can hold.
fn reached(now: Instant, from: Instant, after: Duration) -> bool {
    from.checked_add(after).is_some_and(|at| now >= at)
}

/// The verdicts time gives: no answer to our Status in time, or the hold is over.
fn judge_time(w: &mut Watch, now: Instant, start: Instant, plan: &StatusPlan) {
    match &w.ours_answered {
        None if reached(now, start, plan.status_deadline) => w.fail(format!(
            "no valid Status response to ours within {:?}",
            plan.status_deadline
        )),
        Some((at, theirs)) if reached(now, *at, plan.hold) => {
            let verdict = match w.theirs_answered {
                Some(asked) => Ok(format!(
                    "our Status v2 answered (its finalized epoch {}, head slot {}), its Status \
                     answered {:.1} s in, held {:.1} s on one connection, {} of our Pings answered, no \
                     Goodbye",
                    theirs.finalized_epoch,
                    theirs.head_slot,
                    (asked - *at).as_secs_f64().max(0.0),
                    plan.hold.as_secs_f64(),
                    w.pongs
                )),
                None => Err(format!(
                    "our Status v2 answered and the connection held {:.1} s, but the peer never \
                     sent us a Status to answer",
                    plan.hold.as_secs_f64()
                )),
            };
            match verdict {
                Ok(detail) => {
                    tracing::info!(peer = %w.peer.peer_id, %detail, "status check passed");
                    w.done = Some(Ok(detail));
                }
                Err(why) => w.fail(why),
            }
        }
        _ => {}
    }
}

fn on_event<E: EthSpec>(event: SwarmEvent<SpecBehaviourEvent<E>>, watches: &mut [Watch]) {
    let watch = |watches: &mut [Watch], peer: PeerId| -> Option<usize> {
        watches
            .iter()
            .position(|w| w.peer.peer_id == peer && w.done.is_none())
    };
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            ..
        } => {
            if let Some(i) = watch(watches, peer_id) {
                watches[i].connection.get_or_insert(connection_id);
            }
        }
        SwarmEvent::OutgoingConnectionError {
            peer_id: Some(peer_id),
            error,
            ..
        } => {
            if let Some(i) = watch(watches, peer_id) {
                watches[i].fail(dial_failure(&error));
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            cause,
            ..
        } => {
            if let Some(i) = watch(watches, peer_id) {
                if watches[i].connection == Some(connection_id) {
                    let cause = cause.map_or("closed by our side".to_owned(), |e| error_chain(&e));
                    watches[i].fail(format!("the connection closed ({cause})"));
                }
            }
        }
        SwarmEvent::Behaviour(SpecBehaviourEvent::ReqResp(event)) => on_control(event, watches),
        _ => {}
    }
}

fn on_control(event: ControlEvent, watches: &mut [Watch]) {
    let Some(w) = (match &event {
        ControlEvent::Status { peer, .. }
        | ControlEvent::StatusAnswered { peer }
        | ControlEvent::Pong { peer, .. }
        | ControlEvent::GoodbyeReceived { peer, .. } => watches
            .iter_mut()
            .find(|w| w.peer.peer_id == *peer && w.done.is_none()),
        _ => None,
    }) else {
        return;
    };
    match event {
        ControlEvent::Status {
            status,
            relevance: Relevance::Relevant,
            via,
            ..
        } => match via {
            StatusVia::Response => {
                w.ours_answered.get_or_insert((Instant::now(), status));
            }
            StatusVia::Request => w.theirs_relevant = true,
        },
        // Our answer to its Status left: only now does its side of the handshake count.
        ControlEvent::StatusAnswered { .. } if w.theirs_relevant => {
            w.theirs_answered.get_or_insert(Instant::now());
        }
        ControlEvent::Status {
            status, relevance, ..
        } => w.fail(format!(
            "its Status is not relevant ({relevance:?}: fork digest {}, finalized epoch {}); we \
             said Goodbye {GOODBYE_IRRELEVANT_NETWORK}",
            super::api::hex0x(&status.fork_digest),
            status.finalized_epoch
        )),
        ControlEvent::Pong { .. } => w.pongs += 1,
        ControlEvent::GoodbyeReceived { reason, .. } => w.fail(format!(
            "the peer said Goodbye {reason} ({})",
            goodbye_name(reason)
        )),
        _ => {}
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
    use crate::fixtures::{closed_port_peer, devnet, now_ms, FixtureChain, Script, StandIn};
    use consensus_types::primitives::Root;
    use consensus_types::Minimal;
    use std::sync::Arc;

    const FINALIZED_EPOCH: u64 = 4;

    fn finalized_root() -> Root {
        Root::repeat_byte(0xf4)
    }

    /// A CL's Status that matches ours: our digest now, the fixture API's finality.
    fn matching(devnet: &Devnet) -> StatusV2 {
        StatusV2 {
            fork_digest: devnet.fork_digest(now_ms()).unwrap(),
            finalized_root: finalized_root(),
            finalized_epoch: FINALIZED_EPOCH,
            head_root: Root::repeat_byte(0x99),
            head_slot: FINALIZED_EPOCH * 8 + 5,
            earliest_available_slot: 0,
        }
    }

    async fn reference_api() -> (FixtureChain, testkit::collector::testing::FixtureServer) {
        let chain = FixtureChain::default();
        chain.finalize(FINALIZED_EPOCH, finalized_root(), FINALIZED_EPOCH * 8);
        let server = chain.serve().await;
        (chain, server)
    }

    fn plan(peers: Vec<PinnedPeer>, hold: Duration) -> StatusPlan {
        StatusPlan {
            peers,
            hold,
            ping_interval: Duration::from_millis(200),
            status_deadline: Duration::from_secs(5),
            refresh_interval: Duration::from_millis(300),
            listen: Vec::new(),
        }
    }

    fn clock() -> Clock {
        Arc::new(now_ms)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn both_directions_then_a_held_connection_pass() {
        let devnet = devnet();
        let (_chain, server) = reference_api().await;
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let script = Script {
            restatus_after: Some(Duration::from_millis(300)),
            ..Script::default()
        };
        let cl = StandIn::scripted::<Minimal>(&devnet, Some(matching(&devnet)), script).await;
        let hold = Duration::from_millis(1500);
        let check = status::<Minimal>(&devnet, api, clock(), &plan(vec![cl.pinned()], hold)).await;
        assert!(check.passed(), "{check:?}");
        let line = &check.lines()[0].detail;
        assert!(line.contains(&cl.id.to_string()), "{line}");
        assert!(line.contains("its Status answered"), "{line}");
        assert!(line.contains("held 1.5"), "{line}");
        assert!(line.contains("no Goodbye"), "{line}");
        assert!(!line.contains(" 0 of our Pings answered"), "{line}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_broken_rule_fails_its_peer() {
        let devnet = devnet();
        let (_chain, server) = reference_api().await;
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let ok = matching(&devnet);
        let restatus = Some(Duration::from_millis(200));
        let silent = StandIn::spawn::<Minimal>(&devnet, Some(ok.clone())).await;
        let goodbye = StandIn::scripted::<Minimal>(
            &devnet,
            Some(ok.clone()),
            Script {
                restatus_after: restatus,
                goodbye_after: Some((Duration::from_millis(500), 3)),
                ..Script::default()
            },
        )
        .await;
        let dropped = StandIn::scripted::<Minimal>(
            &devnet,
            Some(ok.clone()),
            Script {
                restatus_after: restatus,
                disconnect_after: Some(Duration::from_millis(500)),
                ..Script::default()
            },
        )
        .await;
        let other_digest = StatusV2 {
            fork_digest: [0xde, 0xad, 0xbe, 0xef],
            ..ok.clone()
        };
        let irrelevant = StandIn::spawn::<Minimal>(&devnet, Some(other_digest)).await;
        let no_status = StandIn::spawn::<Minimal>(&devnet, None).await;
        let peers = vec![
            silent.pinned(),
            goodbye.pinned(),
            dropped.pinned(),
            irrelevant.pinned(),
            no_status.pinned(),
            closed_port_peer(),
        ];
        let mut plan = plan(peers, Duration::from_millis(1500));
        plan.status_deadline = Duration::from_secs(2);
        let check = status::<Minimal>(&devnet, api, clock(), &plan).await;
        let lines = check.lines();
        assert_eq!(lines.len(), 6, "{lines:?}");
        assert!(lines.iter().all(|l| !l.pass), "{lines:?}");
        let want = [
            "never sent us a Status",
            "Goodbye 3 (fault/error)",
            "connection closed",
            "WrongForkDigest",
            "no valid Status",
            "dial failed",
        ];
        for (line, want) in lines.iter().zip(want) {
            assert!(line.detail.contains(want), "{want}: {}", line.detail);
        }
    }

    #[tokio::test]
    async fn no_status_of_ours_fails_before_dialing() {
        let devnet = devnet();
        let chain = FixtureChain::default();
        let server = chain.serve().await;
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let check = status::<Minimal>(
            &devnet,
            api,
            clock(),
            &plan(vec![closed_port_peer()], Duration::from_secs(1)),
        )
        .await;
        assert!(!check.passed());
        assert_eq!(check.lines().len(), 1);
        assert!(
            check.lines()[0].detail.contains("no Status of ours"),
            "{check:?}"
        );
    }

    /// Hold, Ping and deadline durations past what the clock can hold fail no peer by a panic:
    /// the peer here fails its dial, and the run ends.
    #[tokio::test]
    async fn durations_past_the_clock_do_not_panic() {
        let devnet = devnet();
        let (_chain, server) = reference_api().await;
        let api = ProbeApi::new(server.url(""), Duration::from_secs(5));
        let mut plan = plan(vec![closed_port_peer()], Duration::MAX);
        plan.ping_interval = Duration::MAX;
        plan.status_deadline = Duration::MAX;
        let check = status::<Minimal>(&devnet, api, clock(), &plan).await;
        assert!(!check.passed());
        assert!(
            check.lines()[0].detail.contains("dial failed"),
            "{check:#?}"
        );
    }

    fn watch() -> Watch {
        Watch {
            peer: closed_port_peer(),
            connection: None,
            ours_answered: None,
            theirs_relevant: false,
            theirs_answered: None,
            pongs: 0,
            done: None,
        }
    }

    /// The peer's own Status counts as answered once our answer was sent, not when it was
    /// judged (our answer only queued then), and only if that Status was relevant.
    #[test]
    fn theirs_counts_as_answered_once_our_answer_is_sent() {
        let devnet = devnet();
        let mut watches = [watch()];
        let peer = watches[0].peer.peer_id;
        let judged = ControlEvent::Status {
            peer,
            status: matching(&devnet),
            relevance: Relevance::Relevant,
            via: StatusVia::Request,
        };
        on_control(judged, &mut watches);
        assert!(watches[0].theirs_answered.is_none(), "judged, not yet sent");
        on_control(ControlEvent::StatusAnswered { peer }, &mut watches);
        assert!(watches[0].theirs_answered.is_some());

        // An answer sent with no relevant Status of theirs judged first counts for nothing.
        let mut watches = [watch()];
        let peer = watches[0].peer.peer_id;
        on_control(ControlEvent::StatusAnswered { peer }, &mut watches);
        assert!(watches[0].theirs_answered.is_none());
    }

    #[test]
    fn goodbye_reasons_are_named() {
        assert_eq!(goodbye_name(1), "client shutdown");
        assert_eq!(goodbye_name(2), "irrelevant network");
        assert_eq!(goodbye_name(3), "fault/error");
        assert_eq!(goodbye_name(128), "unknown reason");
    }
}
