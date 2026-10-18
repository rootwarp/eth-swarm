//! The req/resp limits ([`crate::rpc::limits`]): the outbound semaphore as a model, and the
//! rate limit, the outbound cap, the inbound stream cap and the IGNORE queue on local swarms.

use crate::rpc::limits::{outbound_queue_name, Admit, OutboundSemaphore, QueueMetrics};
use crate::rpc::MAX_CONCURRENT_REQUESTS;
use p2p_wire::rpc::protocols::Protocol;
use prometheus_client::registry::Registry;
use proptest::prelude::*;
use std::collections::{HashMap, VecDeque};

/// One step: a request on `Protocol::ALL[protocol]`, then, if `finish`, the completion of the
/// `pick`-th request in flight (of any protocol).
#[derive(Debug, Clone)]
struct Step {
    protocol: usize,
    finish: bool,
    pick: usize,
}

fn step() -> impl Strategy<Value = Step> {
    (0..Protocol::ALL.len(), any::<bool>(), any::<usize>()).prop_map(|(protocol, finish, pick)| {
        Step {
            protocol,
            finish,
            pick,
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// 100 requests over random protocols, finishing in random order: in flight per protocol
    /// never exceeds 2, the waiting ones start oldest first, and every request either starts or
    /// is IGNOREd by a full queue.
    #[test]
    fn outbound_semaphore_proptest(
        steps in prop::collection::vec(step(), 100),
        queue_len in 0usize..6,
    ) {
        let metrics = QueueMetrics::register(&mut Registry::default());
        let mut sem = OutboundSemaphore::new(queue_len, metrics.clone());
        let mut in_flight: Vec<(Protocol, u32)> = Vec::new();
        let mut waiting: HashMap<Protocol, VecDeque<u32>> = HashMap::new();
        let (mut started, mut ignored) = (0u32, 0u32);
        let start = |in_flight: &mut Vec<(Protocol, u32)>, p, id, started: &mut u32| {
            in_flight.push((p, id));
            *started += 1;
        };
        for (id, s) in (0u32..).zip(&steps) {
            let p = Protocol::ALL[s.protocol];
            match sem.submit(p, id) {
                Admit::Start(got) => {
                    prop_assert_eq!(got, id);
                    start(&mut in_flight, p, id, &mut started);
                }
                Admit::Queued => waiting.entry(p).or_default().push_back(id),
                Admit::Ignored(got) => {
                    prop_assert_eq!(got, id);
                    prop_assert_eq!(waiting.get(&p).map_or(0, VecDeque::len), queue_len.max(1));
                    ignored += 1;
                }
            }
            if s.finish && !in_flight.is_empty() {
                let (done, _) = in_flight.remove(s.pick % in_flight.len());
                let next = sem.release(done);
                let want = waiting.get_mut(&done).and_then(VecDeque::pop_front);
                prop_assert_eq!(next, want);
                if let Some(next) = next {
                    start(&mut in_flight, done, next, &mut started);
                }
            }
            for p in Protocol::ALL {
                let open = in_flight.iter().filter(|(q, _)| *q == p).count();
                prop_assert!(sem.in_flight(p) <= MAX_CONCURRENT_REQUESTS);
                prop_assert_eq!(sem.in_flight(p), open);
            }
        }
        // Finish everything: every waiting request gets its turn.
        while let Some((done, _)) = in_flight.pop() {
            if let Some(next) = sem.release(done) {
                prop_assert_eq!(Some(next), waiting.get_mut(&done).and_then(VecDeque::pop_front));
                start(&mut in_flight, done, next, &mut started);
            }
        }
        prop_assert!(waiting.values().all(VecDeque::is_empty));
        prop_assert_eq!(started + ignored, steps.len() as u32);
        let dropped: u64 = Protocol::ALL
            .iter()
            .map(|p| metrics.dropped(outbound_queue_name(*p)))
            .sum();
        prop_assert_eq!(dropped, u64::from(ignored));
    }
}

// ---------------------------------------------------------------------------------------------
// On local swarms

use super::{
    config, result_code, status_with, tcp_swarm, until, BytesCodec, Cmd, Node, RawPeer, Seen,
    DIGEST, E, SETTLE, WAIT,
};
use crate::rpc::codec::{Deadlines, ReceivedChunk, RpcCodec, RpcRequest};
use crate::rpc::limits::Quota;
use futures::StreamExt;
use libp2p::request_response::{self, ProtocolSupport, ResponseChannel};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm};
use p2p_wire::rpc::codec::encode_request;
use p2p_wire::rpc::messages::{Ping, StatusV2};
use p2p_wire::rpc::protocols::{Request, Response, ResponseChunk, ResultCode};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test]
async fn rate_limited_withholds() {
    // One Ping chunk a second, no burst.
    let mut cfg = config(status_with(DIGEST), 5, 4);
    cfg.limits.rate.ping = Quota::new(1, Duration::from_secs(1));
    let mut ours = Node::spawn(cfg).await;
    let mut raw = RawPeer::new(5);
    raw.connect(ours.addr.clone()).await;

    // Two Pings at once, the most a requester may have open: the first is answered at once,
    // the second withheld until its token is back, both whole success chunks.
    let start = Instant::now();
    let first = raw.send(ours.peer, Request::Ping(Ping(5)));
    let second = raw.send(ours.peer, Request::Ping(Ping(5)));
    let mut done = HashMap::new();
    tokio::time::timeout(WAIT, async {
        while done.len() < 2 {
            let event = raw.swarm.select_next_some().await;
            if let Some((id, outcome)) = raw.handle(event) {
                done.insert(id, (outcome, start.elapsed()));
            }
        }
    })
    .await
    .expect("both Pings answered");
    let pong = ResponseChunk::Success(Response::Ping(Ping(5)));
    let (answer, at) = done.remove(&first).unwrap();
    assert_eq!(super::single(answer.unwrap()), pong);
    assert!(
        at < Duration::from_millis(900),
        "the first came after {at:?}"
    );
    let (answer, at) = done.remove(&second).unwrap();
    assert_eq!(super::single(answer.unwrap()), pong, "no error chunk");
    assert!(
        at >= Duration::from_millis(1000) && at < Duration::from_secs(4),
        "the second came after {at:?}"
    );
    assert_eq!(ours.metrics.rate_limited_count(Protocol::PingV1), 1);

    // The next one waits for the token after that: about 2 s from the start.
    let third = raw.send(ours.peer, Request::Ping(Ping(5)));
    let answer = raw.outcome(third).await.unwrap();
    assert_eq!(super::single(answer), pong);
    let at = start.elapsed();
    assert!(
        at >= Duration::from_millis(2000),
        "the third came after {at:?}"
    );
    assert_eq!(ours.metrics.rate_limited_count(Protocol::PingV1), 2);

    // Withholding never closed the stream or the connection.
    let peer = raw.id();
    let seen = tokio::select! {
        () = raw.run() => unreachable!(),
        seen = ours.drain(SETTLE) => seen,
    };
    assert!(
        !seen
            .iter()
            .any(|s| matches!(s, Seen::Closed(p) if *p == peer)),
        "{seen:?}"
    );
    // Other protocols kept their own quota: a Status is answered at once.
    let start = Instant::now();
    let id = raw.send(ours.peer, Request::Status(status_with(DIGEST)));
    assert!(raw.outcome(id).await.is_ok());
    assert!(start.elapsed() < Duration::from_millis(900));
    assert_eq!(ours.metrics.rate_limited_count(Protocol::StatusV2), 0);
}

/// Sends `n` Pings at once and returns, for each, its answer and when it came (from `start`).
async fn pings(
    raw: &mut RawPeer,
    to: PeerId,
    n: usize,
    start: Instant,
) -> Vec<(ResponseChunk<E>, Duration)> {
    let ids: Vec<_> = (0..n)
        .map(|_| raw.send(to, Request::Ping(Ping(5))))
        .collect();
    let mut done = HashMap::new();
    tokio::time::timeout(WAIT, async {
        while done.len() < n {
            let event = raw.swarm.select_next_some().await;
            if let Some((id, outcome)) = raw.handle(event) {
                done.insert(id, (outcome, start.elapsed()));
            }
        }
    })
    .await
    .expect("every Ping answered");
    ids.iter()
        .map(|id| {
            let (outcome, at) = done.remove(id).unwrap();
            (super::single(outcome.expect("answered")), at)
        })
        .collect()
}

/// Closes `raw`'s connection to the node and waits until the node saw it close.
async fn leave(ours: &mut Node, raw: RawPeer) {
    let peer = raw.id();
    drop(raw);
    ours.closed(peer).await;
}

#[tokio::test]
async fn withheld_answers_dropped_on_disconnect_are_refunded() {
    // The default Ping quota: 2 at once, then one per 2 s.
    let mut ours = Node::spawn(config(status_with(DIGEST), 5, 4)).await;
    let key = libp2p::identity::Keypair::generate_secp256k1();
    let mut raw = RawPeer::with_key(key.clone(), 5);
    raw.connect(ours.addr.clone()).await;
    // Spend the burst, then leave two answers withheld (due at about 2 s and 4 s).
    pings(&mut raw, ours.peer, 2, Instant::now()).await;
    raw.send(ours.peer, Request::Ping(Ping(5)));
    raw.send(ours.peer, Request::Ping(Ping(5)));
    raw.run_for(SETTLE).await;
    assert_eq!(ours.metrics.rate_limited_count(Protocol::PingV1), 2);
    leave(&mut ours, raw).await;

    // Back as the same peer: the two dropped answers were never sent, so they are not
    // charged, and the next two arrive whole within the 5 s first-byte deadline.
    let mut raw = RawPeer::with_key(key, 5);
    raw.connect(ours.addr.clone()).await;
    let start = Instant::now();
    let pong = ResponseChunk::Success(Response::Ping(Ping(5)));
    for (answer, at) in pings(&mut raw, ours.peer, 2, start).await {
        assert_eq!(answer, pong);
        assert!(at < Duration::from_secs(5), "answered after {at:?}");
    }
}

#[tokio::test]
async fn a_reconnect_after_sent_chunks_keeps_the_bucket() {
    // One Ping chunk per 3 s, no burst.
    let mut cfg = config(status_with(DIGEST), 5, 4);
    cfg.limits.rate.ping = Quota::new(1, Duration::from_secs(3));
    let mut ours = Node::spawn(cfg).await;
    let key = libp2p::identity::Keypair::generate_secp256k1();
    let mut raw = RawPeer::with_key(key.clone(), 5);
    raw.connect(ours.addr.clone()).await;
    let start = Instant::now();
    let (_, first) = pings(&mut raw, ours.peer, 1, start).await.remove(0);
    assert!(first < Duration::from_millis(900), "{first:?}");
    leave(&mut ours, raw).await;
    // The sent chunk stays charged: reconnecting does not buy a fresh token.
    let mut raw = RawPeer::with_key(key, 5);
    raw.connect(ours.addr.clone()).await;
    let (answer, at) = pings(&mut raw, ours.peer, 1, start).await.remove(0);
    assert_eq!(answer, ResponseChunk::Success(Response::Ping(Ping(5))));
    assert!(at >= Duration::from_secs(3), "answered after {at:?}");
}

/// A peer that serves Status inbound on up to 8 streams per connection and holds every request
/// unanswered until the test releases it.
struct HoldingPeer {
    swarm: Swarm<request_response::Behaviour<RpcCodec<E>>>,
    held: Vec<ResponseChannel<Vec<ReceivedChunk<E>>>>,
    received: usize,
}

fn holding_behaviour() -> request_response::Behaviour<RpcCodec<E>> {
    request_response::Behaviour::with_codec(
        RpcCodec::new(
            Arc::new(p2p_wire::testkit::context_table()),
            Deadlines::default(),
        ),
        [(Protocol::StatusV2, ProtocolSupport::Inbound)],
        request_response::Config::default()
            .with_request_timeout(WAIT)
            .with_max_concurrent_streams(8),
    )
}

/// The Status a holding peer answers with: the node's own, so the node judges it relevant.
fn answer(status: StatusV2) -> Vec<ReceivedChunk<E>> {
    vec![ReceivedChunk {
        context: None,
        chunk: ResponseChunk::Success(Response::Status(status)),
    }]
}

impl HoldingPeer {
    async fn listen() -> (Self, Multiaddr) {
        let mut swarm = tcp_swarm(holding_behaviour());
        swarm.listen_on(super::loopback()).unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        let peer = Self {
            swarm,
            held: Vec::new(),
            received: 0,
        };
        (peer, addr)
    }

    fn id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    fn on(
        &mut self,
        event: SwarmEvent<request_response::Event<RpcRequest, Vec<ReceivedChunk<E>>>>,
    ) {
        if let SwarmEvent::Behaviour(request_response::Event::Message {
            message: request_response::Message::Request { channel, .. },
            ..
        }) = event
        {
            self.received += 1;
            self.held.push(channel);
        }
    }

    /// Runs until `check` holds, within [`WAIT`].
    async fn run_until(&mut self, what: &str, check: impl Fn(&Self) -> bool) {
        tokio::time::timeout(WAIT, async {
            while !check(self) {
                let event = self.swarm.select_next_some().await;
                self.on(event);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    async fn run_for(&mut self, for_: Duration) {
        let _ = tokio::time::timeout(for_, async {
            loop {
                let event = self.swarm.select_next_some().await;
                self.on(event);
            }
        })
        .await;
    }

    /// Answers the oldest held request.
    fn release_one(&mut self) {
        let channel = self.held.remove(0);
        let _ = self
            .swarm
            .behaviour_mut()
            .send_response(channel, answer(status_with(DIGEST)));
    }
}

/// A node that dialed `peer` and was asked for `statuses` Status requests in all: the one it
/// sends on connecting and `statuses - 1` more.
async fn node_sending_statuses(
    queue_len: usize,
    peer: &mut HoldingPeer,
    addr: Multiaddr,
    statuses: usize,
) -> Node {
    let mut cfg = config(status_with(DIGEST), 1, 4);
    cfg.limits.outbound_queue_len = queue_len;
    let mut ours = Node::spawn(cfg).await;
    ours.send(Cmd::Dial(addr));
    let theirs = peer.id();
    tokio::select! {
        () = peer.run_for(WAIT) => panic!("no connection"),
        () = ours.next("the connection", |s| matches!(s, Seen::Established(p) if *p == theirs).then_some(())) => {}
    }
    for _ in 1..statuses {
        ours.send(Cmd::Status(theirs));
    }
    ours
}

#[tokio::test]
async fn outbound_requests_stay_within_two_per_protocol() {
    let (mut peer, addr) = HoldingPeer::listen().await;
    let ours = node_sending_statuses(8, &mut peer, addr, 5).await;
    // Five Status requests, the peer could take eight: only two are ever open.
    peer.run_until("two Status requests", |p| p.received == 2)
        .await;
    peer.run_for(SETTLE).await;
    assert_eq!(peer.received, 2, "a third went out with two open");
    assert_eq!(ours.metrics.outbound_inflight(Protocol::StatusV2), 2);
    let mut max_open = 0;
    while peer.received < 5 {
        peer.release_one();
        let want = peer.received + 1;
        peer.run_until("the next waiting Status", |p| p.received == want)
            .await;
        max_open = max_open.max(peer.held.len());
    }
    assert_eq!(max_open, MAX_CONCURRENT_REQUESTS);
    peer.run_for(SETTLE).await;
    assert_eq!(peer.received, 5, "every waiting request went out once");
    while !peer.held.is_empty() {
        peer.release_one();
    }
    let metrics = ours.metrics.clone();
    until("the slots to free", peer.run_for(WAIT), || {
        metrics.outbound_inflight(Protocol::StatusV2) == 0
    })
    .await;
    assert_eq!(
        ours.metrics
            .queues()
            .dropped(outbound_queue_name(Protocol::StatusV2)),
        0
    );
}

#[tokio::test]
async fn a_full_outbound_queue_ignores_the_request() {
    let (mut peer, addr) = HoldingPeer::listen().await;
    // Two open, one waiting, the fourth IGNOREd.
    let ours = node_sending_statuses(1, &mut peer, addr, 4).await;
    let metrics = ours.metrics.clone();
    let queue = outbound_queue_name(Protocol::StatusV2);
    until("the fourth to be ignored", peer.run_for(WAIT), || {
        metrics.queues().dropped(queue) == 1
    })
    .await;
    assert_eq!(peer.received, 2);
    peer.release_one();
    peer.release_one();
    peer.run_until("the waiting one", |p| p.received == 3).await;
    peer.run_for(SETTLE).await;
    assert_eq!(peer.received, 3, "the ignored request never went out");
    assert_eq!(ours.metrics.queues().dropped(queue), 1);
}

/// A peer that holds our Status requests and sends its own raw Status bytes.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct HoldAndSend {
    hold: request_response::Behaviour<RpcCodec<E>>,
    send: request_response::Behaviour<BytesCodec>,
}

/// [`HoldAndSend`] on a swarm: the Status requests it holds, the answers to its own.
struct Prober {
    swarm: Swarm<HoldAndSend>,
    held: Vec<ResponseChannel<Vec<ReceivedChunk<E>>>>,
    answers: HashMap<request_response::OutboundRequestId, Result<Vec<u8>, String>>,
}

impl Prober {
    fn on(&mut self, event: SwarmEvent<HoldAndSendEvent>) {
        use request_response::{Event, Message};
        let SwarmEvent::Behaviour(event) = event else {
            return;
        };
        match event {
            HoldAndSendEvent::Hold(Event::Message {
                message: Message::Request { channel, .. },
                ..
            }) => self.held.push(channel),
            HoldAndSendEvent::Send(Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            }) => {
                self.answers.insert(request_id, Ok(response));
            }
            HoldAndSendEvent::Send(Event::OutboundFailure {
                request_id, error, ..
            }) => {
                self.answers.insert(request_id, Err(error.to_string()));
            }
            _ => {}
        }
    }

    async fn run_until(&mut self, what: &str, check: impl Fn(&Self) -> bool) {
        tokio::time::timeout(WAIT, async {
            while !check(self) {
                let event = self.swarm.select_next_some().await;
                self.on(event);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    async fn run_for(&mut self, for_: Duration) {
        let _ = tokio::time::timeout(for_, async {
            loop {
                let event = self.swarm.select_next_some().await;
                self.on(event);
            }
        })
        .await;
    }

    /// Sends `bytes` (or nothing, holding the stream silent) as a Status request.
    fn send(&mut self, to: PeerId, bytes: Option<Vec<u8>>) -> request_response::OutboundRequestId {
        self.swarm.behaviour_mut().send.send_request(&to, bytes)
    }

    async fn answer(&mut self, id: request_response::OutboundRequestId) -> Result<Vec<u8>, String> {
        self.run_until("the answer", |p| p.answers.contains_key(&id))
            .await;
        self.answers.remove(&id).expect("just seen")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_stream_cap_is_per_peer_and_apart_from_ours() {
    let mut swarm = tcp_swarm(HoldAndSend {
        hold: holding_behaviour(),
        send: request_response::Behaviour::with_codec(
            BytesCodec,
            [(
                StreamProtocol::new(Protocol::StatusV2.id()),
                ProtocolSupport::Outbound,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(8),
        ),
    });
    swarm.listen_on(super::loopback()).unwrap();
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            break address;
        }
    };
    let theirs = *swarm.local_peer_id();
    let mut peer = Prober {
        swarm,
        held: Vec::new(),
        answers: HashMap::new(),
    };
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    ours.send(Cmd::Dial(addr));
    tokio::select! {
        () = peer.run_for(WAIT) => panic!("no connection"),
        () = ours.next("the connection", |s| matches!(s, Seen::Established(p) if *p == theirs).then_some(())) => {}
    }
    ours.send(Cmd::Status(theirs));
    // The peer holds our two Status requests: both of our outbound slots on the connection.
    peer.run_until("our two Status requests", |p| p.held.len() == 2)
        .await;
    let status = encode_request(&Request::Status(status_with(DIGEST))).unwrap();

    // Our two open requests take none of the peer's slots: its Status is answered.
    let id = peer.send(ours.peer, Some(status.clone()));
    let wire = peer.answer(id).await.expect("served");
    assert_eq!(result_code(Protocol::StatusV2, &wire), ResultCode::Success);

    // Two silent streams take the peer's two slots; its third concurrent stream is not served.
    for _ in 0..2 {
        peer.send(ours.peer, None);
    }
    peer.run_for(SETTLE).await;
    let id = peer.send(ours.peer, Some(status));
    if let Ok(wire) = peer.answer(id).await {
        assert!(wire.is_empty(), "served past the cap: {wire:?}");
    }
    assert_eq!(peer.held.len(), 2, "we sent no third Status");
}
