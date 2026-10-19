//! The control protocols on local swarms (127.0.0.1, TCP + Noise + yamux), never a public peer.
//!
//! [`Node`] is the production probe swarm ([`build_swarm`] with
//! [`Control`](super::inbound::Control)) on its own task.
//! The scripted peers are bare `request_response` swarms: [`RawPeer`] speaks the protocols
//! through the production codec and answers what the test tells it to (or nothing), and
//! [`bytes_peer`] writes whatever bytes a test gives it, or holds its stream open and silent.

mod columns;
mod limits;

use super::codec::{Answer, Deadline, Deadlines, ReceivedChunk, RpcRequest};
use super::inbound::{
    ControlConfig, ControlEvent, DuplexEvent, Protocols, ProtocolsEvent, Relevance, SharedStatus,
    StatusVia,
};
use super::metrics::{RpcMetrics, StatusValidity};
use super::unsupported::Unsupported;
use crate::behaviour::{BehaviourEvent, ProbeSpec, SpecBehaviour};
use crate::testkit;
use crate::transport::{
    build_swarm, muxer_upgrades, with_negotiating_inbound_streams, Direction, MuxerBudget,
    SwarmConfig, TransportMetrics, MAX_NEGOTIATING_INBOUND_STREAMS,
};
use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::upgrade::{SelectUpgrade, Version};
use libp2p::identity::Keypair;
use libp2p::request_response::{self, OutboundFailure, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::{ConnectionId, SwarmEvent};
use libp2p::{
    noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, Transport as _,
};
use p2p_wire::enr::{decode_cgc, encode_cgc};
use p2p_wire::rpc::codec::{decode_response_chunk, encode_chunk, encode_request};
use p2p_wire::rpc::messages::{
    BlocksByRangeV2Request, ForkDigest, Goodbye, MetaDataV3, Ping, StatusV2,
};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tracing_subscriber::layer::SubscriberExt as _;

type E = ProbeSpec;

/// How long a test waits for anything that should happen at once.
const WAIT: Duration = Duration::from_secs(20);
/// How long a test lets the swarms run to see that something does not happen.
const SETTLE: Duration = Duration::from_millis(500);

const DIGEST: ForkDigest = [0x0a, 0x0b, 0x0c, 0x0d];
const OTHER_DIGEST: ForkDigest = [0x01, 0x02, 0x03, 0x04];

fn status_with(fork_digest: ForkDigest) -> StatusV2 {
    StatusV2 {
        fork_digest,
        ..p2p_wire::testkit::status()
    }
}

fn config(status: StatusV2, seq_number: u64, cgc: u64) -> ControlConfig {
    ControlConfig {
        status: Arc::new(SharedStatus::new(Some(status))),
        metadata: Arc::new(super::inbound::SharedMetaData::new(
            testkit::local_metadata(seq_number, cgc),
        )),
        ..testkit::control_config(None)
    }
}

fn loopback() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

/// What a test asks a running node to do.
enum Cmd {
    Dial(Multiaddr),
    Status(PeerId),
    Ping(PeerId),
    Goodbye(PeerId, u64),
}

/// A node event a test waits for.
#[derive(Debug)]
enum Seen {
    Control(ControlEvent),
    Established(PeerId),
    Closed(PeerId),
}

/// A probe swarm on its own task.
struct Node {
    peer: PeerId,
    addr: Multiaddr,
    cmds: UnboundedSender<Cmd>,
    events: UnboundedReceiver<Seen>,
    metrics: RpcMetrics,
}

impl Node {
    async fn spawn(cfg: ControlConfig) -> Self {
        Self::spawn_idle(cfg, WAIT).await
    }

    /// A node whose connections close after `idle` without an open stream.
    async fn spawn_idle(cfg: ControlConfig, idle: Duration) -> Self {
        let mut registry = Registry::default();
        let transport = TransportMetrics::register(&mut registry);
        let mut swarm_cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
        swarm_cfg.listen_addrs = vec![loopback()];
        swarm_cfg.idle_connection_timeout = idle;
        let (req_resp, metrics) = testkit::control(&mut registry, cfg);
        let swarm =
            build_swarm(Keypair::generate_secp256k1(), &swarm_cfg, req_resp).expect("swarm");
        Self::start(swarm, metrics).await
    }

    /// A node whose socket writes stall once `stalled` is set ([`Stalling`]), over the
    /// production muxer stack and behaviour.
    async fn spawn_stalling(cfg: ControlConfig, stalled: Arc<AtomicBool>) -> Self {
        let mut registry = Registry::default();
        let transport = TransportMetrics::register(&mut registry);
        let swarm_cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
        let (req_resp, metrics) = testkit::control(&mut registry, cfg);
        let (yamux, mplex) = muxer_upgrades(&swarm_cfg);
        let mut swarm = SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
            .with_tokio()
            .with_other_transport(|key| {
                let stack = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
                    .map(move |socket, _| Stalling {
                        inner: socket,
                        stalled,
                    })
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise::Config::new(key)?)
                    .multiplex(SelectUpgrade::new(yamux(), mplex()))
                    .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
                    .boxed();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(stack)
            })
            .expect("transport")
            .with_behaviour(|key| {
                SpecBehaviour::with_caps(
                    key.public(),
                    swarm_cfg.agent_version.clone(),
                    swarm_cfg.caps,
                    req_resp,
                )
            })
            .expect("behaviour")
            .with_swarm_config(|c| {
                with_negotiating_inbound_streams(
                    c.with_idle_connection_timeout(WAIT),
                    MAX_NEGOTIATING_INBOUND_STREAMS,
                )
            })
            .build();
        swarm.listen_on(loopback()).expect("listen");
        Self::start(swarm, metrics).await
    }

    /// Runs `swarm` on its own task once it listens.
    async fn start(mut swarm: Swarm<SpecBehaviour<E>>, metrics: RpcMetrics) -> Self {
        let peer = *swarm.local_peer_id();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        let (cmds, mut cmd_rx) = mpsc::unbounded::<Cmd>();
        let (tx, events) = mpsc::unbounded();
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    cmd = cmd_rx.next() => {
                        let control = &mut swarm.behaviour_mut().req_resp;
                        match cmd {
                            Some(Cmd::Dial(addr)) => swarm.dial(addr).expect("dial"),
                            Some(Cmd::Status(peer)) => {
                                control.send_status(peer);
                            }
                            Some(Cmd::Ping(peer)) => control.ping(peer),
                            Some(Cmd::Goodbye(peer, reason)) => control.goodbye(peer, reason),
                            None => return,
                        }
                        continue;
                    }
                    event = swarm.select_next_some() => event,
                };
                let seen = match event {
                    SwarmEvent::Behaviour(BehaviourEvent::ReqResp(e)) => Seen::Control(e),
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => Seen::Established(peer_id),
                    SwarmEvent::ConnectionClosed { peer_id, .. } => Seen::Closed(peer_id),
                    _ => continue,
                };
                if tx.unbounded_send(seen).is_err() {
                    return;
                }
            }
        });
        Self {
            peer,
            addr,
            cmds,
            events,
            metrics,
        }
    }

    fn send(&self, cmd: Cmd) {
        self.cmds.unbounded_send(cmd).expect("node running");
    }

    /// The next event `pick` maps to `Some`, within [`WAIT`].
    async fn next<T>(&mut self, what: &str, mut pick: impl FnMut(&Seen) -> Option<T>) -> T {
        let found = tokio::time::timeout(WAIT, async {
            while let Some(seen) = self.events.next().await {
                if let Some(found) = pick(&seen) {
                    return found;
                }
            }
            panic!("{what}: the node stopped");
        });
        found
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
    }

    /// Every event within `for_`.
    async fn drain(&mut self, for_: Duration) -> Vec<Seen> {
        let mut seen = Vec::new();
        let _ = tokio::time::timeout(for_, async {
            while let Some(s) = self.events.next().await {
                seen.push(s);
            }
        })
        .await;
        seen
    }

    async fn verdict_on(&mut self, peer: PeerId) -> Relevance {
        self.next("a Status verdict", |seen| match seen {
            Seen::Control(ControlEvent::Status {
                peer: p, relevance, ..
            }) if *p == peer => Some(*relevance),
            _ => None,
        })
        .await
    }

    async fn closed(&mut self, peer: PeerId) {
        self.next("the connection to close", |seen| match seen {
            Seen::Closed(p) if *p == peer => Some(()),
            _ => None,
        })
        .await;
    }
}

/// A socket whose writes, flushes and closes are pending for good once `stalled` is set: our
/// side of a connection whose peer stopped reading, with the send buffer full.
struct Stalling<S> {
    inner: S,
    stalled: Arc<AtomicBool>,
}

impl<S> Stalling<S> {
    fn stalled(&self) -> bool {
        self.stalled.load(Ordering::SeqCst)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Stalling<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stalling<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.stalled() {
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.stalled() {
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.stalled() {
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_close(cx)
    }
}

/// Polls `check` every 20 ms while `drive` runs, until it holds or [`WAIT`] passes.
async fn until<F: std::future::Future<Output = ()>>(
    what: &str,
    drive: F,
    mut check: impl FnMut() -> bool,
) {
    tokio::pin!(drive);
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        tokio::select! {
            () = &mut drive => panic!("{what}: the driver stopped"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The scripted request_response peer, over the production codec.

/// How one of [`RawPeer`]'s requests ended: the response, or the failure.
type Outcome = Result<Vec<ReceivedChunk<E>>, String>;

/// A bare swarm of the five protocols; the test decides what it sends and answers.
struct RawPeer {
    swarm: Swarm<Protocols<E>>,
    /// What it answers a MetaData request with.
    metadata: MetaDataV3,
    /// MetaData requests it received.
    metadata_requests: usize,
    /// Whether it answers Status requests (else it holds them, silent).
    answer_status: bool,
    held: Vec<request_response::ResponseChannel<Answer<E>>>,
    /// Outcomes of our requests that completed while another was awaited.
    done: HashMap<OutboundRequestId, Outcome>,
}

fn tcp_swarm<B: libp2p::swarm::NetworkBehaviour>(behaviour: B) -> Swarm<B> {
    tcp_swarm_as(Keypair::generate_secp256k1(), behaviour)
}

/// [`tcp_swarm`] with the node key `key`, so a test can reconnect as the same peer.
fn tcp_swarm_as<B: libp2p::swarm::NetworkBehaviour>(key: Keypair, behaviour: B) -> Swarm<B> {
    SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("tcp")
        .with_behaviour(|_| behaviour)
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
        .build()
}

impl RawPeer {
    fn new(seq_number: u64) -> Self {
        Self::with_key(Keypair::generate_secp256k1(), seq_number)
    }

    /// A peer with the node key `key`.
    fn with_key(key: Keypair, seq_number: u64) -> Self {
        let protocols = Protocols::new(
            Arc::new(p2p_wire::testkit::column_context_table()),
            Deadlines::default(),
            None,
        );
        Self {
            swarm: tcp_swarm_as(key, protocols),
            metadata: MetaDataV3 {
                seq_number,
                ..p2p_wire::testkit::metadata()
            },
            metadata_requests: 0,
            answer_status: true,
            held: Vec::new(),
            done: HashMap::new(),
        }
    }

    fn id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    async fn listen(&mut self) -> Multiaddr {
        self.swarm.listen_on(loopback()).unwrap();
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = self.swarm.select_next_some().await {
                return address;
            }
        }
    }

    async fn connect(&mut self, addr: Multiaddr) {
        self.swarm.dial(addr).unwrap();
        tokio::time::timeout(WAIT, async {
            loop {
                if let SwarmEvent::ConnectionEstablished { .. } =
                    self.swarm.select_next_some().await
                {
                    return;
                }
            }
        })
        .await
        .expect("connected");
    }

    fn send(&mut self, peer: PeerId, request: Request) -> OutboundRequestId {
        self.swarm
            .behaviour_mut()
            .of(request.protocol())
            .send_request(&peer, request.into())
    }

    /// Handles one swarm event; the outcome of an outbound request, if it was one.
    fn handle(
        &mut self,
        event: SwarmEvent<ProtocolsEvent<E>>,
    ) -> Option<(OutboundRequestId, Outcome)> {
        use request_response::{Event, Message};
        let SwarmEvent::Behaviour(event) = event else {
            return None;
        };
        let event = match event {
            ProtocolsEvent::Status(e)
            | ProtocolsEvent::Metadata(e)
            | ProtocolsEvent::Ping(e)
            | ProtocolsEvent::Goodbye(e)
            | ProtocolsEvent::BlocksByRange(e)
            | ProtocolsEvent::DataColumnsByRange(e)
            | ProtocolsEvent::DataColumnsByRoot(e) => e,
        };
        match event {
            DuplexEvent::Inbound(Event::Message {
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            }) => {
                let reply = |r: Response<E>| {
                    vec![ReceivedChunk {
                        context: None,
                        chunk: ResponseChunk::Success(r),
                    }]
                };
                let behaviour = self.swarm.behaviour_mut();
                match request {
                    RpcRequest::Valid(Request::MetaData) => {
                        self.metadata_requests += 1;
                        let answer = reply(Response::MetaData(self.metadata.clone()));
                        let _ = behaviour.metadata.send_response(channel, answer);
                    }
                    RpcRequest::Valid(Request::Ping(_)) => {
                        let answer = reply(Response::Ping(Ping(self.metadata.seq_number)));
                        let _ = behaviour.ping.send_response(channel, answer);
                    }
                    RpcRequest::Valid(Request::Status(theirs)) if self.answer_status => {
                        let _ = behaviour
                            .status
                            .send_response(channel, reply(Response::Status(theirs)));
                    }
                    _ => self.held.push(channel),
                }
                None
            }
            DuplexEvent::Outbound(Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            }) => Some((request_id, Ok(response))),
            DuplexEvent::Outbound(Event::OutboundFailure {
                request_id, error, ..
            }) => Some((request_id, Err(error.to_string()))),
            _ => None,
        }
    }

    /// Runs until request `id` completes.
    async fn outcome(&mut self, id: OutboundRequestId) -> Outcome {
        tokio::time::timeout(WAIT, async {
            loop {
                if let Some(outcome) = self.done.remove(&id) {
                    return outcome;
                }
                let event = self.swarm.select_next_some().await;
                if let Some((done, outcome)) = self.handle(event) {
                    self.done.insert(done, outcome);
                }
            }
        })
        .await
        .expect("the request completed")
    }

    /// Runs, answering, for `for_`.
    async fn run_for(&mut self, for_: Duration) {
        let _ = tokio::time::timeout(for_, self.run()).await;
    }

    /// Runs, answering, forever.
    async fn run(&mut self) {
        loop {
            let event = self.swarm.select_next_some().await;
            self.handle(event);
        }
    }
}

fn single(chunks: Vec<ReceivedChunk<E>>) -> ResponseChunk<E> {
    let mut chunks = chunks.into_iter();
    let first = chunks.next().expect("one chunk");
    assert!(chunks.next().is_none(), "more than one chunk");
    first.chunk
}

// ---------------------------------------------------------------------------------------------
// Status

#[tokio::test]
async fn status_wrong_digest_goodbye_2() {
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;

    // A peer on another fork digest dials us and sends its Status first.
    let mut other = Node::spawn(config(status_with(OTHER_DIGEST), 1, 4)).await;
    other.send(Cmd::Dial(ours.addr.clone()));
    assert_eq!(
        ours.verdict_on(other.peer).await,
        Relevance::WrongForkDigest
    );
    let reason = other
        .next("our Goodbye", |seen| match seen {
            Seen::Control(ControlEvent::GoodbyeReceived { peer, reason, .. })
                if *peer == ours.peer =>
            {
                Some(*reason)
            }
            _ => None,
        })
        .await;
    assert_eq!(reason, 2);
    ours.closed(other.peer).await;
    assert_eq!(
        ours.metrics.goodbye_sent_count(2, StatusValidity::Invalid),
        1
    );
    assert_eq!(ours.metrics.status_valid_peers(), 0);

    // A peer on our digest: valid both ways, no Goodbye 2 or 3, the connection stays.
    let mut same = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    same.send(Cmd::Dial(ours.addr.clone()));
    assert_eq!(ours.verdict_on(same.peer).await, Relevance::Relevant);
    // The peer accepted our Status (its response path).
    assert_eq!(same.verdict_on(ours.peer).await, Relevance::Relevant);
    assert_eq!(ours.metrics.status_valid_peers(), 1);
    let later = same.drain(SETTLE).await;
    assert!(
        !later.iter().any(|s| matches!(
            s,
            Seen::Closed(_) | Seen::Control(ControlEvent::GoodbyeReceived { .. })
        )),
        "{later:?}"
    );
    for reason in [2, 3] {
        for validity in StatusValidity::ALL {
            assert_eq!(same.metrics.goodbye_received_count(reason, validity), 0);
        }
        assert_eq!(
            ours.metrics
                .goodbye_sent_count(reason, StatusValidity::Valid),
            0
        );
    }
}

/// Each Status verdict says who asked: the dialer judges the listener's response to its Status,
/// the listener judges the dialer's request; a Status the listener sends later is a request on
/// the dialer's side.
#[tokio::test]
async fn status_event_names_who_asked() {
    let mut listener = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut dialer = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    dialer.send(Cmd::Dial(listener.addr.clone()));
    let via_of = |peer: PeerId| {
        move |seen: &Seen| match seen {
            Seen::Control(ControlEvent::Status { peer: p, via, .. }) if *p == peer => Some(*via),
            _ => None,
        }
    };
    assert_eq!(
        listener
            .next("the dialer's Status", via_of(dialer.peer))
            .await,
        StatusVia::Request
    );
    assert_eq!(
        dialer
            .next("the listener's answer", via_of(listener.peer))
            .await,
        StatusVia::Response
    );
    listener.send(Cmd::Status(dialer.peer));
    assert_eq!(
        dialer
            .next("the listener's Status", via_of(listener.peer))
            .await,
        StatusVia::Request
    );
    assert_eq!(
        listener
            .next("the dialer's answer", via_of(dialer.peer))
            .await,
        StatusVia::Response
    );
}

/// A peer's Status request counts as answered once our Status was written to its stream
/// (`StatusAnswered`), and not when we had none to answer with (`2: ServerError`).
#[tokio::test]
async fn status_answered_once_our_status_is_sent() {
    let mut listener = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let dialer = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    dialer.send(Cmd::Dial(listener.addr.clone()));
    listener
        .next("our Status sent to the dialer", |seen| match seen {
            Seen::Control(ControlEvent::StatusAnswered { peer }) if *peer == dialer.peer => {
                Some(())
            }
            _ => None,
        })
        .await;

    let mut silent = Node::spawn(testkit::control_config(None)).await;
    let mut asker = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    asker.send(Cmd::Dial(silent.addr.clone()));
    asker
        .next("the connection", |seen| match seen {
            Seen::Established(p) if *p == silent.peer => Some(()),
            _ => None,
        })
        .await;
    let seen = silent.drain(SETTLE).await;
    assert!(
        !seen
            .iter()
            .any(|s| matches!(s, Seen::Control(ControlEvent::StatusAnswered { .. }))),
        "{seen:?}"
    );
}

#[tokio::test]
async fn our_status_goes_out_on_every_dial_and_conflicts_are_irrelevant() {
    // We dial: our Status goes first, the peer answers with a finalized root other than ours
    // at our finalized epoch.
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut raw = RawPeer::new(1);
    let addr = raw.listen().await;
    ours.send(Cmd::Dial(addr));
    // The raw peer echoes our Status back, so swap in a conflicting one by holding it and
    // answering by hand.
    raw.answer_status = false;
    let channel = tokio::time::timeout(WAIT, async {
        loop {
            let event = raw.swarm.select_next_some().await;
            raw.handle(event);
            if let Some(channel) = raw.held.pop() {
                return channel;
            }
        }
    })
    .await
    .expect("our Status arrived");
    let conflict = StatusV2 {
        finalized_root: [0xee; 32].into(),
        ..status_with(DIGEST)
    };
    let answer = vec![ReceivedChunk {
        context: None,
        chunk: ResponseChunk::Success(Response::Status(conflict)),
    }];
    raw.swarm
        .behaviour_mut()
        .status
        .send_response(channel, answer)
        .unwrap();
    let peer = raw.id();
    tokio::select! {
        () = raw.run() => unreachable!(),
        verdict = ours.verdict_on(peer) => assert_eq!(verdict, Relevance::FinalizedConflict),
    }
    tokio::select! {
        () = raw.run() => unreachable!(),
        () = ours.closed(peer) => {}
    }
    assert_eq!(
        ours.metrics.goodbye_sent_count(2, StatusValidity::Invalid),
        1
    );
}

#[tokio::test]
async fn without_a_status_of_ours_nothing_is_judged() {
    // The source has no Status yet (cl-chain unreachable): an inbound Status is answered
    // `2: ServerError` (Status specifies no `3`), the peer is not judged, and a dial sends none.
    let cfg = ControlConfig {
        status: Arc::new(SharedStatus::new(None)),
        ..config(status_with(DIGEST), 1, 4)
    };
    let mut ours = Node::spawn(cfg).await;
    let mut raw = RawPeer::new(1);
    raw.connect(ours.addr.clone()).await;
    let id = raw.send(ours.peer, Request::Status(status_with(OTHER_DIGEST)));
    match single(raw.outcome(id).await.unwrap()) {
        ResponseChunk::Error { code, .. } => assert_eq!(code, ResultCode::ServerError),
        other => panic!("{other:?}"),
    }
    let mut dialed = RawPeer::new(1);
    dialed.answer_status = false;
    let addr = dialed.listen().await;
    ours.send(Cmd::Dial(addr));
    tokio::select! {
        () = raw.run() => unreachable!(),
        () = dialed.run_for(SETTLE * 2) => {}
    }
    assert!(dialed.held.is_empty(), "a Status was sent");
    let seen = ours.drain(SETTLE).await;
    let dialed_id = dialed.id();
    assert!(
        seen.iter()
            .any(|s| matches!(s, Seen::Established(p) if *p == dialed_id)),
        "{seen:?}"
    );
    assert!(
        !seen.iter().any(|s| matches!(
            s,
            Seen::Closed(_) | Seen::Control(ControlEvent::Status { .. })
        )),
        "{seen:?}"
    );
    for validity in StatusValidity::ALL {
        assert_eq!(ours.metrics.goodbye_sent_count(2, validity), 0);
    }
}

// ---------------------------------------------------------------------------------------------
// Ping and MetaData

#[tokio::test]
async fn ping_and_metadata_seq() {
    let cgc = decode_cgc(&encode_cgc(4)).unwrap();
    let mut ours = Node::spawn(config(status_with(DIGEST), 5, cgc)).await;
    let mut raw = RawPeer::new(9);
    raw.connect(ours.addr.clone()).await;

    // Ping returns our seq_number, at once.
    let start = Instant::now();
    let id = raw.send(ours.peer, Request::Ping(Ping(9)));
    let pong = single(raw.outcome(id).await.unwrap());
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(pong, ResponseChunk::Success(Response::Ping(Ping(5))));
    // We held no MetaData of the peer: exactly one GetMetaData.
    raw.run_for(SETTLE).await;
    assert_eq!(raw.metadata_requests, 1);
    let metadata = ours
        .next("the peer's MetaData", |seen| match seen {
            Seen::Control(ControlEvent::MetaData { metadata, .. }) => Some(metadata.clone()),
            _ => None,
        })
        .await;
    assert_eq!(metadata.seq_number, 9);

    // The same seq_number again: nothing new to fetch.
    let id = raw.send(ours.peer, Request::Ping(Ping(9)));
    raw.outcome(id).await.unwrap();
    raw.run_for(SETTLE).await;
    assert_eq!(raw.metadata_requests, 1);

    // A higher one, twice at once: exactly one more GetMetaData.
    raw.metadata.seq_number = 10;
    let first = raw.send(ours.peer, Request::Ping(Ping(10)));
    let second = raw.send(ours.peer, Request::Ping(Ping(10)));
    raw.outcome(first).await.unwrap();
    raw.outcome(second).await.unwrap();
    raw.run_for(SETTLE).await;
    assert_eq!(raw.metadata_requests, 2);

    // Our MetaData: our seq_number, the ENR cgc, no subnets.
    let id = raw.send(ours.peer, Request::MetaData);
    match single(raw.outcome(id).await.unwrap()) {
        ResponseChunk::Success(Response::MetaData(m)) => {
            assert_eq!(m.seq_number, 5);
            assert_eq!(m.custody_group_count, cgc);
            assert_eq!(m.attnets.num_set_bits() + m.syncnets.num_set_bits(), 0);
        }
        other => panic!("{other:?}"),
    }

    // Our Ping: the peer's answer is its seq_number, which we already hold.
    ours.send(Cmd::Ping(raw.id()));
    let peer = raw.id();
    let seq = tokio::select! {
        () = raw.run() => unreachable!(),
        seq = ours.next("the Pong", |seen| match seen {
            Seen::Control(ControlEvent::Pong { peer: p, seq_number }) if *p == peer => {
                Some(*seq_number)
            }
            _ => None,
        }) => seq,
    };
    assert_eq!(seq, 10);
    raw.run_for(SETTLE).await;
    assert_eq!(raw.metadata_requests, 2);
}

// ---------------------------------------------------------------------------------------------
// Deadlines

#[tokio::test]
async fn ttfb_timeout_metric() {
    // We dial a peer that takes our Status and never answers.
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut raw = RawPeer::new(1);
    raw.answer_status = false;
    let addr = raw.listen().await;
    ours.send(Cmd::Dial(addr));
    let peer = raw.id();
    tokio::select! {
        () = raw.run() => unreachable!(),
        () = ours.next("the connection", |seen| {
            matches!(seen, Seen::Established(p) if *p == peer).then_some(())
        }) => {}
    }
    let start = Instant::now();
    let metrics = ours.metrics.clone();
    until("the first-byte deadline", raw.run(), || {
        metrics.timeouts(Deadline::Ttfb) == 1
    })
    .await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(4900) && elapsed < Duration::from_secs(7),
        "{elapsed:?}"
    );
    assert_eq!(ours.metrics.invalid_data_count(Direction::Outbound), 0);
    assert_eq!(ours.metrics.timeouts(Deadline::Total), 0);
    // A timeout says nothing about the peer's chain: no verdict, no Goodbye, still connected.
    assert_eq!(ours.metrics.status_valid_peers(), 0);
    for validity in StatusValidity::ALL {
        assert_eq!(ours.metrics.goodbye_sent_count(2, validity), 0);
    }
    let later = tokio::select! {
        () = raw.run() => unreachable!(),
        later = ours.drain(SETTLE) => later,
    };
    assert!(
        !later.iter().any(|s| matches!(
            s,
            Seen::Closed(_) | Seen::Control(ControlEvent::Status { .. })
        )),
        "{later:?}"
    );
}

#[tokio::test]
async fn malformed_response_counts_invalid_data_not_a_timeout() {
    // The peer answers our Ping with a 7-byte payload: a refused response, at once.
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let peer = testkit::StatusPeer::spawn_with_ping(
        Box::new(|req, _| testkit::StatusReply::Status(req.clone())),
        None,
        Some(Box::new(|_, _| testkit::PingReply::Ssz(vec![0; 7]))),
        None,
    )
    .await;
    ours.send(Cmd::Dial(peer.addr.clone()));
    assert_eq!(ours.verdict_on(peer.id).await, Relevance::Relevant);
    ours.send(Cmd::Ping(peer.id));
    let metrics = ours.metrics.clone();
    until(
        "the refused Pong",
        async { std::future::pending().await },
        || metrics.invalid_data_count(Direction::Outbound) == 1,
    )
    .await;
    for kind in Deadline::ALL {
        assert_eq!(ours.metrics.timeouts(kind), 0, "{kind:?}");
    }
    assert_eq!(peer.pings(), vec![1]);
}

/// Writes the bytes it is given as the request (or nothing, holding the stream open), and
/// reads the whole response.
#[derive(Clone, Default)]
struct BytesCodec;

/// The most response bytes [`BytesCodec`] reads.
const MAX_BYTES_RESPONSE: u64 = 64 << 10;

impl request_response::Codec for BytesCodec {
    type Protocol = StreamProtocol;
    type Request = Option<Vec<u8>>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(MAX_BYTES_RESPONSE).read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match request {
            Some(bytes) => {
                io.write_all(&bytes).await?;
                io.flush().await
            }
            None => futures::future::pending().await,
        }
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        _: &mut T,
        _: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// An outbound-only behaviour requesting on `protocol` with [`BytesCodec`].
fn bytes_behaviour(protocol: &'static str) -> request_response::Behaviour<BytesCodec> {
    request_response::Behaviour::with_codec(
        BytesCodec,
        [(StreamProtocol::new(protocol), ProtocolSupport::Outbound)],
        request_response::Config::default()
            .with_request_timeout(Duration::from_secs(30))
            .with_max_concurrent_streams(8),
    )
}

/// A bare swarm requesting on `protocol` with [`BytesCodec`].
fn bytes_peer(protocol: &'static str) -> Swarm<request_response::Behaviour<BytesCodec>> {
    tcp_swarm(bytes_behaviour(protocol))
}

async fn bytes_connect(
    swarm: &mut Swarm<request_response::Behaviour<BytesCodec>>,
    addr: Multiaddr,
) {
    swarm.dial(addr).unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            if let SwarmEvent::ConnectionEstablished { .. } = swarm.select_next_some().await {
                return;
            }
        }
    })
    .await
    .expect("connected");
}

/// Runs `swarm` until request `id` completes.
async fn bytes_outcome(
    swarm: &mut Swarm<request_response::Behaviour<BytesCodec>>,
    id: OutboundRequestId,
) -> Result<Vec<u8>, OutboundFailure> {
    tokio::time::timeout(WAIT, async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                }) if request_id == id => return Ok(response),
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure {
                    request_id,
                    error,
                    ..
                }) if request_id == id => return Err(error),
                _ => {}
            }
        }
    })
    .await
    .expect("the request completed")
}

/// Sends `bytes` on `protocol` to `node` from a fresh peer; the response or the failure.
async fn send_bytes(
    node: &Node,
    protocol: Protocol,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, OutboundFailure> {
    let mut peer = bytes_peer(protocol.id());
    bytes_connect(&mut peer, node.addr.clone()).await;
    let id = peer.behaviour_mut().send_request(&node.peer, Some(bytes));
    bytes_outcome(&mut peer, id).await
}

fn result_code(protocol: Protocol, wire: &[u8]) -> ResultCode {
    let contexts = p2p_wire::testkit::context_table();
    match decode_response_chunk::<E>(wire, protocol, &contexts).expect("one chunk") {
        ResponseChunk::Error { code, .. } => code,
        ResponseChunk::Success(_) => ResultCode::Success,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_inbound_streams_hold_slots_until_the_first_byte_deadline() {
    let ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut peer = bytes_peer(Protocol::StatusV2.id());
    bytes_connect(&mut peer, ours.addr.clone()).await;
    let status = encode_request(&Request::Status(status_with(DIGEST))).unwrap();

    // Two streams that never send a byte take both of the protocol's slots.
    let start = Instant::now();
    for _ in 0..2 {
        peer.behaviour_mut().send_request(&ours.peer, None);
    }
    let _ = tokio::time::timeout(SETTLE, async {
        loop {
            peer.select_next_some().await;
        }
    })
    .await;
    // While they hold them, a third stream is not served.
    let id = peer
        .behaviour_mut()
        .send_request(&ours.peer, Some(status.clone()));
    if let Ok(wire) = bytes_outcome(&mut peer, id).await {
        assert!(
            wire.is_empty(),
            "served while the slots were full: {wire:?}"
        );
    }
    assert_eq!(ours.metrics.timeouts(Deadline::Ttfb), 0);

    // At 5 s both are closed, each counted as a first-byte timeout.
    let metrics = ours.metrics.clone();
    let drive = async {
        loop {
            peer.select_next_some().await;
        }
    };
    until("the silent streams to time out", drive, || {
        metrics.timeouts(Deadline::Ttfb) == 2
    })
    .await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(4900) && elapsed < Duration::from_secs(7),
        "{elapsed:?}"
    );
    assert_eq!(ours.metrics.invalid_data_count(Direction::Inbound), 0);

    // The slots are free again: a Status is answered at once.
    let start = Instant::now();
    let id = peer.behaviour_mut().send_request(&ours.peer, Some(status));
    let wire = bytes_outcome(&mut peer, id).await.unwrap();
    assert_eq!(result_code(Protocol::StatusV2, &wire), ResultCode::Success);
    assert!(start.elapsed() < Duration::from_secs(5));
}

// ---------------------------------------------------------------------------------------------
// Clean rejects

#[tokio::test]
async fn malformed_requests_get_invalid_request() {
    let ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let ping_too_long = encode_chunk(&[0u8; 16]).unwrap();
    let status_too_short = encode_chunk(&[0u8; 8]).unwrap();
    let mut ping_and_more = encode_request(&Request::Ping(Ping(1))).unwrap();
    ping_and_more.push(0);
    let cases = [
        (Protocol::PingV1, ping_too_long),
        (Protocol::StatusV2, status_too_short),
        (Protocol::PingV1, ping_and_more),
        (Protocol::MetaDataV3, vec![0]),
    ];
    for (protocol, bytes) in cases {
        let wire = send_bytes(&ours, protocol, bytes).await.unwrap();
        assert_eq!(
            result_code(protocol, &wire),
            ResultCode::InvalidRequest,
            "{protocol}"
        );
    }
    assert_eq!(ours.metrics.invalid_data_count(Direction::Inbound), 4);
    // Goodbye has a response too, so a malformed one gets the error chunk as well.
    let wire = send_bytes(&ours, Protocol::GoodbyeV1, vec![0])
        .await
        .unwrap();
    assert_eq!(
        result_code(Protocol::GoodbyeV1, &wire),
        ResultCode::InvalidRequest
    );
    assert_eq!(ours.metrics.invalid_data_count(Direction::Inbound), 5);
}

#[tokio::test]
async fn unservable_blocks_by_range_gets_resource_unavailable() {
    let ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let request = Request::BlocksByRange(BlocksByRangeV2Request {
        start_slot: 64,
        count: 32,
        step: 1,
    });
    let wire = send_bytes(
        &ours,
        Protocol::BlocksByRangeV2,
        encode_request(&request).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        result_code(Protocol::BlocksByRangeV2, &wire),
        ResultCode::ResourceUnavailable
    );
    // The error chunk carries no context bytes: the payload follows the result byte.
    assert_eq!(wire[1..], encode_chunk(b"no blocks stored").unwrap()[..]);
}

#[tokio::test]
async fn unadvertised_protocols_fail_negotiation() {
    let ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    for protocol in [
        "/eth2/beacon_chain/req/status/1/ssz_snappy",
        "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
        "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
        "/eth2/beacon_chain/req/data_column_sidecars_by_range/2/ssz_snappy",
        "/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy",
    ] {
        let mut peer = bytes_peer(protocol);
        bytes_connect(&mut peer, ours.addr.clone()).await;
        let id = peer
            .behaviour_mut()
            .send_request(&ours.peer, Some(Vec::new()));
        match bytes_outcome(&mut peer, id).await {
            Err(OutboundFailure::UnsupportedProtocols) => {}
            other => panic!("{protocol}: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Unsupported protocols: written probe deviations

/// The guard: the protocols the spec makes MUST-support that the probe leaves unregistered.
/// Registering one (closing [6.42] or [6.19b]) means taking it off this list, off
/// [`Unsupported`] and out of the README's §Deviations, together.
#[test]
fn unsupported_ids_stay_unregistered() {
    assert_eq!(
        Unsupported::ALL.map(Unsupported::id),
        [
            "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy",
            "/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy",
            "/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy",
        ]
    );
    for protocol in Protocol::ALL {
        assert_eq!(Unsupported::from_id(protocol.id()), None, "{protocol}");
    }
    let readme = include_str!("../../README.md");
    let deviations = readme
        .split_once("\n## Deviations\n")
        .map(|(_, rest)| {
            rest.split_once("\n## ")
                .map_or(rest, |(section, _)| section)
        })
        .expect("the README has a §Deviations section");
    for unsupported in Unsupported::ALL {
        assert!(
            deviations.contains(unsupported.id()),
            "README §Deviations does not name {}",
            unsupported.id()
        );
        assert_eq!(Unsupported::from_id(unsupported.id()), Some(unsupported));
    }
    for closing in ["[6.42]", "[6.19b]"] {
        assert!(
            deviations.contains(closing),
            "README §Deviations: {closing}"
        );
    }
}

/// A peer requesting the [`Unsupported`] protocols, one behaviour each (a behaviour offers all
/// its protocols on every stream, so one each makes every stream propose one id), and Status.
#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct UnsupportedRequests {
    blocks_by_head: request_response::Behaviour<BytesCodec>,
    envelopes_by_range: request_response::Behaviour<BytesCodec>,
    envelopes_by_root: request_response::Behaviour<BytesCodec>,
    status: request_response::Behaviour<BytesCodec>,
}

/// An [`UnsupportedRequests`] swarm on one connection to a [`Node`].
struct Requester {
    swarm: Swarm<UnsupportedRequests>,
    node: PeerId,
    connection: ConnectionId,
}

/// Which behaviour of [`UnsupportedRequests`]: an [`Unsupported`] protocol, or Status.
type Which = Option<Unsupported>;

impl Requester {
    async fn connect(node: &Node) -> Self {
        let mut swarm = tcp_swarm(UnsupportedRequests {
            blocks_by_head: bytes_behaviour(Unsupported::BlocksByHeadV1.id()),
            envelopes_by_range: bytes_behaviour(Unsupported::EnvelopesByRangeV1.id()),
            envelopes_by_root: bytes_behaviour(Unsupported::EnvelopesByRootV1.id()),
            status: bytes_behaviour(Protocol::StatusV2.id()),
        });
        swarm.dial(node.addr.clone()).unwrap();
        let connection = tokio::time::timeout(WAIT, async {
            loop {
                if let SwarmEvent::ConnectionEstablished { connection_id, .. } =
                    swarm.select_next_some().await
                {
                    return connection_id;
                }
            }
        })
        .await
        .expect("connected");
        Self {
            swarm,
            node: node.peer,
            connection,
        }
    }

    fn behaviour(&mut self, which: Which) -> &mut request_response::Behaviour<BytesCodec> {
        let requests = self.swarm.behaviour_mut();
        match which {
            Some(Unsupported::BlocksByHeadV1) => &mut requests.blocks_by_head,
            Some(Unsupported::EnvelopesByRangeV1) => &mut requests.envelopes_by_range,
            Some(Unsupported::EnvelopesByRootV1) => &mut requests.envelopes_by_root,
            None => &mut requests.status,
        }
    }

    /// Sends `bytes` on `which` and runs until the request ends: the response or the failure.
    /// Panics if the connection closes or a second one opens on the way.
    async fn request(&mut self, which: Which, bytes: Vec<u8>) -> Result<Vec<u8>, OutboundFailure> {
        use request_response::{Event, Message};
        let node = self.node;
        let id = self.behaviour(which).send_request(&node, Some(bytes));
        let connection = self.connection;
        tokio::time::timeout(WAIT, async {
            loop {
                let (from, event) = match self.swarm.select_next_some().await {
                    SwarmEvent::Behaviour(UnsupportedRequestsEvent::BlocksByHead(e)) => {
                        (Some(Unsupported::BlocksByHeadV1), e)
                    }
                    SwarmEvent::Behaviour(UnsupportedRequestsEvent::EnvelopesByRange(e)) => {
                        (Some(Unsupported::EnvelopesByRangeV1), e)
                    }
                    SwarmEvent::Behaviour(UnsupportedRequestsEvent::EnvelopesByRoot(e)) => {
                        (Some(Unsupported::EnvelopesByRootV1), e)
                    }
                    SwarmEvent::Behaviour(UnsupportedRequestsEvent::Status(e)) => (None, e),
                    SwarmEvent::ConnectionClosed { cause, .. } => {
                        panic!("the connection closed: {cause:?}")
                    }
                    SwarmEvent::ConnectionEstablished { .. } => panic!("a second connection"),
                    _ => continue,
                };
                if from != which {
                    continue;
                }
                match event {
                    Event::Message {
                        connection_id,
                        message:
                            Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    } if request_id == id => {
                        assert_eq!(connection_id, connection, "answered on another connection");
                        return Ok(response);
                    }
                    Event::OutboundFailure {
                        request_id, error, ..
                    } if request_id == id => return Err(error),
                    _ => {}
                }
            }
        })
        .await
        .expect("the request ended")
    }

    /// Requests `protocol`: the negotiation must fail.
    async fn refused(&mut self, protocol: Unsupported) {
        match self
            .request(Some(protocol), unsupported_request(protocol))
            .await
        {
            Err(OutboundFailure::UnsupportedProtocols) => {}
            other => panic!("{}: {other:?}", protocol.id()),
        }
    }

    /// A Status on the same connection is answered: it stayed up.
    async fn still_served(&mut self) {
        let status = encode_request(&Request::Status(status_with(DIGEST))).unwrap();
        let wire = self.request(None, status).await.expect("Status answered");
        assert_eq!(result_code(Protocol::StatusV2, &wire), ResultCode::Success);
    }
}

/// A well-formed request of `protocol`, as a peer would send it.
fn unsupported_request(protocol: Unsupported) -> Vec<u8> {
    let ssz = match protocol {
        // (beacon_root: Root, count: uint64)
        Unsupported::BlocksByHeadV1 => [&[0x11; 32][..], &64u64.to_le_bytes()].concat(),
        // (start_slot: Slot, count: uint64)
        Unsupported::EnvelopesByRangeV1 => [64u64.to_le_bytes(), 32u64.to_le_bytes()].concat(),
        // List[Root, MAX_REQUEST_PAYLOADS]: two roots.
        Unsupported::EnvelopesByRootV1 => [[0x22; 32], [0x33; 32]].concat(),
    };
    encode_chunk(&ssz).unwrap()
}

/// The peer's request fails negotiation, the probe's inbound side never sees a stream (no
/// handler reads a byte, so nothing is counted invalid or timed out), and the connection
/// stays up: a Status on it is answered, and neither side saw it close.
async fn assert_refused_cleanly(protocols: &[Unsupported]) {
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut peer = Requester::connect(&ours).await;
    for &protocol in protocols {
        peer.refused(protocol).await;
    }
    peer.still_served().await;
    assert_eq!(ours.metrics.invalid_data_count(Direction::Inbound), 0);
    for kind in Deadline::ALL {
        assert_eq!(ours.metrics.timeouts(kind), 0, "{kind:?}");
    }
    let requester = *peer.swarm.local_peer_id();
    let seen = ours.drain(SETTLE).await;
    assert!(
        !seen
            .iter()
            .any(|s| matches!(s, Seen::Closed(p) if *p == requester)),
        "{seen:?}"
    );
}

#[tokio::test]
async fn blocks_by_head_rejected() {
    assert_refused_cleanly(&[Unsupported::BlocksByHeadV1]).await;
}

#[tokio::test]
async fn envelopes_rejected() {
    assert_refused_cleanly(&[
        Unsupported::EnvelopesByRangeV1,
        Unsupported::EnvelopesByRootV1,
    ])
    .await;
}

#[tokio::test]
async fn unsupported_counted() {
    let ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    // This runtime polls the node's swarm on this thread, so a thread-scoped subscriber sees
    // its listener's events.
    let subscriber =
        tracing_subscriber::registry().with(super::unsupported::layer(ours.metrics.clone()));
    let _scoped = tracing::subscriber::set_default(subscriber);
    let counts = || Unsupported::ALL.map(|p| ours.metrics.inbound_unsupported_count(p));

    // `tracing` caches a callsite's interest process-wide, and another test may register the
    // listener's callsite while this one sets its subscriber. A refused proposal the count
    // ignores registers it first, then the cache is rebuilt with this subscriber in it.
    let mut warm_up = bytes_peer("/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy");
    bytes_connect(&mut warm_up, ours.addr.clone()).await;
    let id = warm_up
        .behaviour_mut()
        .send_request(&ours.peer, Some(Vec::new()));
    assert!(matches!(
        bytes_outcome(&mut warm_up, id).await,
        Err(OutboundFailure::UnsupportedProtocols)
    ));
    tracing::callsite::rebuild_interest_cache();
    assert_eq!(counts(), [0, 0, 0]);

    let mut peer = Requester::connect(&ours).await;
    for (n, protocol) in Unsupported::ALL.into_iter().enumerate() {
        for _ in 0..=n {
            peer.refused(protocol).await;
        }
    }
    assert_eq!(counts(), [1, 2, 3]);
    // A served protocol is not counted.
    peer.still_served().await;
    assert_eq!(counts(), [1, 2, 3]);
}

// ---------------------------------------------------------------------------------------------
// Goodbye

#[tokio::test]
async fn goodbye_metrics() {
    // The `goodbye_received` log line is checked in tests/goodbye_log.rs, its own process.
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut theirs = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    theirs.send(Cmd::Dial(ours.addr.clone()));
    assert_eq!(ours.verdict_on(theirs.peer).await, Relevance::Relevant);
    assert_eq!(theirs.verdict_on(ours.peer).await, Relevance::Relevant);

    // We send Goodbye 1 to a Status-valid peer.
    ours.send(Cmd::Goodbye(theirs.peer, 1));
    let (reason, validity, direction) = theirs
        .next("our Goodbye", |seen| match seen {
            Seen::Control(ControlEvent::GoodbyeReceived {
                peer,
                reason,
                status_valid,
                direction,
                ..
            }) if *peer == ours.peer => Some((*reason, *status_valid, *direction)),
            _ => None,
        })
        .await;
    assert_eq!(
        (reason, validity, direction),
        (1, StatusValidity::Valid, Direction::Outbound)
    );
    ours.closed(theirs.peer).await;
    assert_eq!(ours.metrics.goodbye_sent_count(1, StatusValidity::Valid), 1);
    assert_eq!(
        theirs
            .metrics
            .goodbye_received_count(1, StatusValidity::Valid),
        1
    );
    assert_eq!(
        ours.metrics
            .goodbye_received_count(1, StatusValidity::Valid),
        0
    );
    // Exactly one event per received Goodbye.
    let more = theirs.drain(SETTLE).await;
    assert!(
        !more
            .iter()
            .any(|s| matches!(s, Seen::Control(ControlEvent::GoodbyeReceived { .. }))),
        "{more:?}"
    );

    // A peer that says Goodbye 3 before any Status: counted under `unknown`, inbound.
    let mut raw = RawPeer::new(1);
    raw.connect(ours.addr.clone()).await;
    let id = raw.send(ours.peer, Request::Goodbye(Goodbye(3)));
    // One response chunk, then the stream (and the connection) closes.
    let _ = raw.outcome(id).await;
    let (validity, direction) = ours
        .next("the peer's Goodbye", |seen| match seen {
            Seen::Control(ControlEvent::GoodbyeReceived {
                reason: 3,
                status_valid,
                direction,
                ..
            }) => Some((*status_valid, *direction)),
            _ => None,
        })
        .await;
    assert_eq!(
        (validity, direction),
        (StatusValidity::Unknown, Direction::Inbound)
    );
    assert_eq!(
        ours.metrics
            .goodbye_received_count(3, StatusValidity::Unknown),
        1
    );
    let more = ours.drain(SETTLE).await;
    let received = more
        .iter()
        .filter(|s| matches!(s, Seen::Control(ControlEvent::GoodbyeReceived { .. })))
        .count();
    assert_eq!(received, 0, "{more:?}");
}

// ---------------------------------------------------------------------------------------------
// BlocksByRange bounds, the Goodbye response, MetaData snapshots and the Ping cadence

#[tokio::test]
async fn blocks_by_range_out_of_bounds_gets_invalid_request() {
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut peer = bytes_peer(Protocol::BlocksByRangeV2.id());
    bytes_connect(&mut peer, ours.addr.clone()).await;
    let range = |count, step| {
        encode_request(&Request::BlocksByRange(BlocksByRangeV2Request {
            start_slot: 64,
            count,
            step,
        }))
        .unwrap()
    };
    // `step` 0 and `count` above MAX_REQUEST_BLOCKS_DENEB are invalid requests; the largest
    // valid count, and a deprecated `step` above 1, are merely unservable here.
    for (count, step, want) in [
        (32, 0, ResultCode::InvalidRequest),
        (129, 1, ResultCode::InvalidRequest),
        (u64::MAX, 1, ResultCode::InvalidRequest),
        (128, 1, ResultCode::ResourceUnavailable),
        (32, 2, ResultCode::ResourceUnavailable),
    ] {
        let id = peer
            .behaviour_mut()
            .send_request(&ours.peer, Some(range(count, step)));
        let wire = bytes_outcome(&mut peer, id).await.unwrap();
        assert_eq!(
            result_code(Protocol::BlocksByRangeV2, &wire),
            want,
            "count {count}, step {step}"
        );
    }
    // A clean reject: well-formed, so no invalid data, and the connection stays.
    assert_eq!(ours.metrics.invalid_data_count(Direction::Inbound), 0);
    let later = ours.drain(SETTLE).await;
    assert!(
        !later.iter().any(|s| matches!(s, Seen::Closed(_))),
        "{later:?}"
    );
}

/// Reads a whole request and answers it with the bytes it is given.
#[derive(Clone, Default)]
struct ReplyCodec;

impl request_response::Codec for ReplyCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(MAX_BYTES_RESPONSE).read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        _: &mut T,
        _: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        bytes: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&bytes).await?;
        io.flush().await
    }
}

/// Answers every request `peer` receives with `reply`, keeping the last request in `got`.
async fn reply_to_each(
    peer: &mut Swarm<request_response::Behaviour<ReplyCodec>>,
    reply: &[u8],
    got: &mut Option<Vec<u8>>,
) {
    loop {
        if let SwarmEvent::Behaviour(request_response::Event::Message {
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        }) = peer.select_next_some().await
        {
            *got = Some(request);
            let _ = peer.behaviour_mut().send_response(channel, reply.to_vec());
        }
    }
}

#[tokio::test]
async fn a_goodbye_answered_with_one_chunk_is_no_fault() {
    use ssz::Encode;
    // Some clients answer a Goodbye with the single chunk `phase0` specifies (L1461, L1483).
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut peer = tcp_swarm(request_response::Behaviour::with_codec(
        ReplyCodec,
        [(
            StreamProtocol::new(Protocol::GoodbyeV1.id()),
            ProtocolSupport::Inbound,
        )],
        request_response::Config::default(),
    ));
    peer.listen_on(loopback()).unwrap();
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = peer.select_next_some().await {
            break address;
        }
    };
    let id = *peer.local_peer_id();
    ours.send(Cmd::Dial(addr));
    let reply =
        p2p_wire::rpc::codec::encode_success_chunk(None, &Goodbye(1).as_ssz_bytes()).unwrap();
    let mut got = None;
    tokio::select! {
        () = reply_to_each(&mut peer, &reply, &mut got) => unreachable!(),
        () = ours.next("the connection", |seen| {
            matches!(seen, Seen::Established(p) if *p == id).then_some(())
        }) => {}
    }
    ours.send(Cmd::Goodbye(id, 1));
    tokio::select! {
        () = reply_to_each(&mut peer, &reply, &mut got) => unreachable!(),
        () = ours.closed(id) => {}
    }
    assert_eq!(
        got,
        Some(encode_request(&Request::Goodbye(Goodbye(1))).unwrap())
    );
    assert_eq!(
        ours.metrics.goodbye_sent_count(1, StatusValidity::Unknown),
        1
    );
    // The reply is ignored quietly: no invalid data, no fault.
    assert_eq!(ours.metrics.invalid_data_count(Direction::Outbound), 0);
}

/// A MetaData source that changes on every read: `seq_number` and `custody_group_count` both `n`
/// on the `n`th.
struct Ticking(AtomicU64);

impl super::inbound::MetaDataSource for Ticking {
    fn metadata(&self) -> MetaDataV3 {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        testkit::local_metadata(n, n)
    }
}

#[tokio::test]
async fn every_metadata_answer_is_one_snapshot() {
    // Our MetaData changes under every read, and the peer asks more often than its quota (2 at
    // once, then one per 2 s), so later answers wait for their token: each still carries the
    // seq_number of the very fields it holds.
    let cfg = ControlConfig {
        metadata: Arc::new(Ticking(AtomicU64::new(0))),
        ..config(status_with(DIGEST), 1, 4)
    };
    let ours = Node::spawn(cfg).await;
    let mut raw = RawPeer::new(1);
    raw.connect(ours.addr.clone()).await;
    let mut seen = Vec::new();
    // Two at once (its two streams), then a third over the quota.
    for batch in [2, 1] {
        let ids: Vec<_> = (0..batch)
            .map(|_| raw.send(ours.peer, Request::MetaData))
            .collect();
        for id in ids {
            match single(raw.outcome(id).await.unwrap()) {
                ResponseChunk::Success(Response::MetaData(m)) => {
                    assert_eq!(m.seq_number, m.custody_group_count, "{m:?}");
                    seen.push(m.seq_number);
                }
                other => panic!("{other:?}"),
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 3, "a fresh snapshot per answer: {seen:?}");
}

#[tokio::test]
async fn our_pings_keep_an_idle_connection_up() {
    let idle = Duration::from_secs(1);
    // Without a Ping inside the idle timeout, a connection with no stream closes.
    let cfg = ControlConfig {
        ping_interval: Duration::from_secs(3600),
        ..config(status_with(DIGEST), 1, 4)
    };
    let mut quiet = Node::spawn_idle(cfg, idle).await;
    let mut raw = RawPeer::new(1);
    raw.connect(quiet.addr.clone()).await;
    let start = Instant::now();
    let peer = raw.id();
    tokio::select! {
        () = raw.run() => unreachable!(),
        () = quiet.closed(peer) => {}
    }
    assert!(start.elapsed() < idle * 3, "{:?}", start.elapsed());

    // Pinging every 250 ms, four times inside it: the connection stays, each Ping answered.
    let cfg = ControlConfig {
        ping_interval: idle / 4,
        ..config(status_with(DIGEST), 1, 4)
    };
    let mut ours = Node::spawn_idle(cfg, idle).await;
    let mut raw = RawPeer::new(1);
    raw.connect(ours.addr.clone()).await;
    let peer = raw.id();
    let seen = tokio::select! {
        () = raw.run() => unreachable!(),
        seen = ours.drain(idle * 4) => seen,
    };
    assert!(
        !seen.iter().any(|s| matches!(s, Seen::Closed(_))),
        "{seen:?}"
    );
    let pongs = seen
        .iter()
        .filter(|s| matches!(s, Seen::Control(ControlEvent::Pong { peer: p, .. }) if *p == peer))
        .count();
    assert!((8..=20).contains(&pongs), "{pongs} Pongs in 4 s");
}

#[tokio::test]
async fn an_inbound_goodbye_gets_one_chunk_then_the_connection_closes() {
    // "The response MUST consist of a single `response_chunk`" (`phase0` L1483), with the
    // `uint64` content of L1461: we echo the peer's reason.
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut peer = bytes_peer(Protocol::GoodbyeV1.id());
    bytes_connect(&mut peer, ours.addr.clone()).await;
    let theirs = *peer.local_peer_id();
    let request = encode_request(&Request::Goodbye(Goodbye(129))).unwrap();
    let id = peer.behaviour_mut().send_request(&ours.peer, Some(request));
    let wire = bytes_outcome(&mut peer, id).await.unwrap();
    let want = p2p_wire::rpc::codec::encode_success_chunk(None, &129u64.to_le_bytes()).unwrap();
    assert_eq!(wire, want, "exactly one Goodbye chunk, nothing after it");
    let contexts = p2p_wire::testkit::context_table();
    assert_eq!(
        decode_response_chunk::<E>(&wire, Protocol::GoodbyeV1, &contexts),
        Ok(ResponseChunk::Success(Response::Goodbye(Goodbye(129))))
    );
    tokio::select! {
        () = async { loop { peer.select_next_some().await; } } => unreachable!(),
        () = ours.closed(theirs) => {}
    }
    assert_eq!(
        ours.metrics
            .goodbye_received_count(129, StatusValidity::Unknown),
        1
    );
}

#[tokio::test]
async fn a_peer_that_stops_reading_after_our_goodbye_answer_is_dropped_at_the_close_deadline() {
    // Once our answer is out the peer reads nothing more and our send buffer stays full, so the
    // graceful close at the end of the linger cannot write its close frames. The connection is
    // dropped at its close deadline instead of holding its slot for good.
    let stalled = Arc::new(AtomicBool::new(false));
    let mut ours =
        Node::spawn_stalling(config(status_with(DIGEST), 1, 4), Arc::clone(&stalled)).await;
    let mut peer = bytes_peer(Protocol::GoodbyeV1.id());
    bytes_connect(&mut peer, ours.addr.clone()).await;
    let theirs = *peer.local_peer_id();
    let request = encode_request(&Request::Goodbye(Goodbye(1))).unwrap();
    let id = peer.behaviour_mut().send_request(&ours.peer, Some(request));
    bytes_outcome(&mut peer, id)
        .await
        .expect("our Goodbye answer");
    stalled.store(true, Ordering::SeqCst);
    let answered = Instant::now();
    let bound = super::inbound::GOODBYE_LINGER + super::inbound::CLOSE_DEADLINE;
    let closed = tokio::time::timeout(bound + Duration::from_secs(2), async {
        tokio::select! {
            () = async { loop { peer.select_next_some().await; } } => unreachable!(),
            () = ours.closed(theirs) => {}
        }
    })
    .await;
    let took = answered.elapsed();
    assert!(
        closed.is_ok(),
        "still connected {took:?} after our Goodbye answer"
    );
    // The close did stall: it ended at its deadline, not at the end of the linger.
    assert!(took + Duration::from_millis(500) >= bound, "{took:?}");
}

/// Sends `bytes` as a Goodbye request on `peer` every `every` until `node` closes the
/// connection; how many were sent, and how long from the first until the close.
async fn goodbyes_until_closed(
    node: &mut Node,
    peer: &mut Swarm<request_response::Behaviour<BytesCodec>>,
    bytes: &[u8],
    every: Duration,
) -> (usize, Duration) {
    let theirs = *peer.local_peer_id();
    let ours = node.peer;
    let start = Instant::now();
    let mut sent = 0;
    let mut tick = tokio::time::interval(every);
    let closed = node.closed(theirs);
    tokio::pin!(closed);
    loop {
        tokio::select! {
            () = &mut closed => return (sent, start.elapsed()),
            _ = tick.tick() => {
                peer.behaviour_mut().send_request(&ours, Some(bytes.to_vec()));
                sent += 1;
            }
            _ = peer.select_next_some() => {}
        }
    }
}

#[tokio::test]
async fn goodbyes_during_the_linger_neither_extend_it_nor_count_again() {
    // A Goodbye every 300 ms: each is answered, but the connection still closes one linger
    // after the first answer, and only the first is counted, logged and reported.
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut peer = bytes_peer(Protocol::GoodbyeV1.id());
    bytes_connect(&mut peer, ours.addr.clone()).await;
    let bye = encode_request(&Request::Goodbye(Goodbye(1))).unwrap();
    let every = Duration::from_millis(300);
    let (sent, took) = goodbyes_until_closed(&mut ours, &mut peer, &bye, every).await;
    assert!(sent >= 3, "{sent} Goodbyes in {took:?}");
    assert!(
        took < super::inbound::GOODBYE_LINGER + Duration::from_secs(2),
        "{took:?}"
    );
    assert_eq!(
        ours.metrics
            .goodbye_received_count(1, StatusValidity::Unknown),
        1
    );
    let later = ours.drain(SETTLE).await;
    assert!(
        !later
            .iter()
            .any(|s| matches!(s, Seen::Control(ControlEvent::GoodbyeReceived { .. }))),
        "{later:?}"
    );
}

#[tokio::test]
async fn a_malformed_goodbye_is_answered_then_the_connection_closes() {
    // A Goodbye that breaks the wire format gets `1: InvalidRequest`, unpaced like any Goodbye
    // answer; then the connection closes a linger on, so a peer cannot loop on it.
    let mut ours = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut peer = bytes_peer(Protocol::GoodbyeV1.id());
    bytes_connect(&mut peer, ours.addr.clone()).await;
    let id = peer.behaviour_mut().send_request(&ours.peer, Some(vec![0]));
    let wire = bytes_outcome(&mut peer, id).await.unwrap();
    assert_eq!(
        result_code(Protocol::GoodbyeV1, &wire),
        ResultCode::InvalidRequest
    );
    let every = Duration::from_millis(300);
    let (_, took) = goodbyes_until_closed(&mut ours, &mut peer, &[0], every).await;
    assert!(
        took < super::inbound::GOODBYE_LINGER + Duration::from_secs(2),
        "{took:?}"
    );
    // A malformed Goodbye is no Goodbye: nothing counted as received.
    for validity in StatusValidity::ALL {
        assert_eq!(ours.metrics.goodbye_received_count(1, validity), 0);
    }
}
