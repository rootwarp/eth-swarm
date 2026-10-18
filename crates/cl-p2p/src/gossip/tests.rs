//! The local topology the gossip tests run: the probe (or, as a control, a plain forwarding
//! gossipsub node) in the centre, forwarding gossipsub neighbours whose transports tap every
//! byte they read, and a scripted meshsub peer that writes raw RPCs (IWANT, duplicates) and
//! reads the centre's stream itself.
//!
//! What a tap read is parsed back into gossipsub RPCs ([`Traffic`]): multistream-select
//! headers are skipped, each length-prefixed `RPC` is walked, and its `publish` entries (the
//! data messages) are counted apart from subscriptions and control.

use super::config::{max_message_size, message_id, GossipConfig, MCACHE_LEN};
use super::{capture_tap, CaptureReader, IgnoreAll, IgnoreAllEvent, WireTransform};
use crate::behaviour::BehaviourEvent;
use crate::transport::{build_swarm_with_gossip, MuxerBudget, SwarmConfig, TransportMetrics};
use consensus_types::caps::NetworkCaps;
use consensus_types::Mainnet;
use futures::channel::{mpsc, oneshot};
use futures::{
    ready, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, StreamExt as _,
};
use libp2p::core::muxing::{StreamMuxer, StreamMuxerBox, StreamMuxerEvent, StreamMuxerExt as _};
use libp2p::core::transport::{Boxed, PortUse};
use libp2p::core::upgrade::{ReadyUpgrade, Version};
use libp2p::core::Endpoint;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId};
use libp2p::identity::Keypair;
use libp2p::swarm::handler::{ConnectionEvent, FullyNegotiatedInbound, FullyNegotiatedOutbound};
use libp2p::swarm::{
    ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm,
    NetworkBehaviour, Stream, StreamProtocol, SubstreamProtocol, SwarmEvent, THandler,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder, Transport as _};
use p2p_wire::gossip::{GossipKind, GossipTopic, SnappyTransform, TopicCaps};
use p2p_wire::rpc::codec::encode_varint;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

/// Heartbeat of every node in these tests, so meshes form and caches shift quickly.
const HEARTBEAT: Duration = Duration::from_millis(100);
/// How long any one wait may take.
const WAIT: Duration = Duration::from_secs(20);
/// The protocol the scripted peer speaks.
const MESHSUB: StreamProtocol = StreamProtocol::new("/meshsub/1.1.0");

/// The topic every node subscribes.
pub(super) fn topic() -> GossipTopic {
    GossipTopic::new([0xab, 0xcd, 0x00, 0x12], GossipKind::BeaconBlock)
}

fn ident_topic() -> IdentTopic {
    IdentTopic::new(topic().to_string())
}

fn caps() -> TopicCaps {
    TopicCaps::gloas::<Mainnet>(&NetworkCaps::from_blob_schedule(21, &[]))
}

/// A distinct `len`-byte SSZ payload.
pub(super) fn payload(tag: &str, i: usize, len: usize) -> Vec<u8> {
    let mut out = format!("{tag}-{i}-").into_bytes();
    let seed = out.len();
    out.extend((0..len.saturating_sub(seed)).map(|j| (j * 31 + i) as u8));
    out.truncate(len);
    out
}

pub(super) fn compressed(ssz: &[u8]) -> Vec<u8> {
    SnappyTransform::new(caps())
        .outbound(&topic().to_string(), ssz)
        .unwrap()
}

pub(super) fn id_of(ssz: &[u8]) -> MessageId {
    MessageId::new(&p2p_wire::gossip::message_id_of_decompressed(
        &topic().to_string(),
        ssz,
    ))
}

fn loopback() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

/// Polls `check` until it returns `Some`, for at most [`WAIT`].
async fn eventually<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// The centre.

/// A message the centre delivered to its application.
#[derive(Clone, Debug)]
pub(super) struct Delivered {
    pub id: MessageId,
    pub source: PeerId,
    /// The probe's `in_cache`; `None` from the forwarding control.
    pub in_cache: Option<bool>,
}

/// The node in the middle: its address, and what it delivered (each message once).
pub(super) struct Center {
    pub peer: PeerId,
    pub addr: Multiaddr,
    delivered: Arc<Mutex<Vec<Delivered>>>,
    topics: mpsc::UnboundedSender<oneshot::Sender<PeerTopics>>,
}

/// Each peer gossipsub knows, with the topics it holds for it.
type PeerTopics = Vec<(PeerId, Vec<String>)>;

/// What gossipsub holds about each peer's subscriptions.
fn peer_topics<D, F>(gossipsub: &gossipsub::Behaviour<D, F>) -> PeerTopics
where
    D: gossipsub::DataTransform + Send + 'static,
    F: gossipsub::TopicSubscriptionFilter + Send + 'static,
{
    gossipsub
        .all_peers()
        .map(|(peer, topics)| (*peer, topics.iter().map(|t| t.to_string()).collect()))
        .collect()
}

impl Center {
    pub(super) fn delivered(&self) -> Vec<Delivered> {
        self.delivered.lock().unwrap().clone()
    }

    /// The topics the centre holds for `peer` (empty if it holds none, or no such peer).
    pub(super) async fn topics_of(&self, peer: PeerId) -> Vec<String> {
        let (tx, rx) = oneshot::channel();
        self.topics.unbounded_send(tx).unwrap();
        let all = rx.await.unwrap();
        all.into_iter()
            .find(|(p, _)| *p == peer)
            .map(|(_, t)| t)
            .unwrap_or_default()
    }

    pub(super) fn has(&self, id: &MessageId) -> bool {
        self.delivered.lock().unwrap().iter().any(|d| &d.id == id)
    }

    /// Waits until at least `n` messages were delivered, and returns them.
    pub(super) async fn wait_for_deliveries(&self, n: usize) -> Vec<Delivered> {
        eventually(&format!("{n} deliveries"), || {
            let d = self.delivered();
            (d.len() >= n).then_some(d)
        })
        .await
    }
}

/// The probe, built by the production [`build_swarm_with_gossip`], on 127.0.0.1.
pub(super) struct Probe {
    pub center: Center,
    pub capture: CaptureReader,
    registry: Registry,
}

impl Probe {
    /// The probe with a capture queue of `capture` messages, running on its own task.
    pub(super) async fn spawn(capture: usize) -> Self {
        let mut registry = Registry::default();
        let transport = TransportMetrics::register(&mut registry);
        let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
        cfg.listen_addrs = vec![loopback()];
        cfg.idle_connection_timeout = WAIT;
        let mut gossip_cfg = GossipConfig::new(vec![topic()], caps(), Duration::from_secs(60));
        gossip_cfg.heartbeat_interval = HEARTBEAT;
        gossip_cfg.heartbeat_initial_delay = HEARTBEAT;
        let (tap, reader) = capture_tap(capture);
        let gossip = IgnoreAll::new(&gossip_cfg, &mut registry)
            .unwrap()
            .with_tap(tap);
        let (req_resp, _) = crate::testkit::control(
            &mut registry,
            crate::testkit::control_config(Some(p2p_wire::testkit::status())),
        );
        let swarm =
            build_swarm_with_gossip(Keypair::generate_secp256k1(), &cfg, req_resp, gossip).unwrap();
        let topics = |swarm: &Swarm<crate::behaviour::Behaviour>| {
            swarm
                .behaviour()
                .gossipsub
                .as_ref()
                .map(|g| peer_topics(g.gossipsub()))
                .unwrap_or_default()
        };
        let center = spawn_center(swarm, topics, |event| match event {
            BehaviourEvent::Gossipsub(IgnoreAllEvent::Ignored {
                source,
                message_id,
                in_cache,
                ..
            }) => Some(Delivered {
                id: message_id,
                source,
                in_cache: Some(in_cache),
            }),
            _ => None,
        })
        .await;
        Self {
            center,
            capture: reader,
            registry,
        }
    }

    /// The probe's metrics as scraped now.
    pub(super) fn metrics(&self) -> Metrics {
        Metrics::scrape(&self.registry)
    }
}

/// A plain forwarding gossipsub node in the centre, and its metrics: the control that shows
/// the taps see a node that does forward.
async fn spawn_forwarder() -> (Center, Registry) {
    let mut registry = Registry::default();
    let mut swarm = gossip_swarm(None, &mut registry);
    swarm.listen_on(loopback()).unwrap();
    let topics =
        |swarm: &Swarm<gossipsub::Behaviour<WireTransform>>| peer_topics(swarm.behaviour());
    let center = spawn_center(swarm, topics, |event| match event {
        gossipsub::Event::Message {
            propagation_source,
            message_id,
            ..
        } => Some(Delivered {
            id: message_id,
            source: propagation_source,
            in_cache: None,
        }),
        _ => None,
    })
    .await;
    (center, registry)
}

/// Waits for the listening `swarm`'s address, then runs it on its own task, keeping what
/// `delivered` maps.
async fn spawn_center<B>(
    mut swarm: Swarm<B>,
    topics: fn(&Swarm<B>) -> PeerTopics,
    delivered: fn(B::ToSwarm) -> Option<Delivered>,
) -> Center
where
    B: NetworkBehaviour + Send + 'static,
{
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            break address;
        }
    };
    let peer = *swarm.local_peer_id();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    let (topics_tx, mut queries) = mpsc::unbounded::<oneshot::Sender<PeerTopics>>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                query = queries.next() => match query {
                    Some(reply) => {
                        let _ = reply.send(topics(&swarm));
                    }
                    None => return,
                },
                event = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(event) = event {
                        if let Some(d) = delivered(event) {
                            sink.lock().unwrap().push(d);
                        }
                    }
                }
            }
        }
    });
    Center {
        peer,
        addr,
        delivered: log,
        topics: topics_tx,
    }
}

#[derive(Debug)]
/// A scrape of a registry in the text format. prometheus-client writes a labelled family only
/// once it has a series, so a counter that never moved is absent and reads 0 here.
pub(super) struct Metrics(String);

impl Metrics {
    fn scrape(registry: &Registry) -> Self {
        let mut text = String::new();
        encode(&mut text, registry).unwrap();
        Self(text)
    }

    /// Whether any line of the scrape contains `needle`.
    pub(super) fn contains(&self, needle: &str) -> bool {
        self.0.contains(needle)
    }

    /// The sum of every sample of `name` (counter or gauge); 0 if it has none.
    pub(super) fn sum(&self, name: &str) -> u64 {
        self.sum_matching(name, "")
    }

    /// The sum of the samples of `name` whose line contains `needle`.
    pub(super) fn sum_matching(&self, name: &str, needle: &str) -> u64 {
        self.0
            .lines()
            .filter(|l| !l.starts_with('#') && l.contains(needle))
            .filter_map(|l| {
                let (series, value) = l.rsplit_once(' ')?;
                let metric = series.split('{').next()?;
                (metric == name || metric == format!("{name}_total"))
                    .then(|| value.parse::<f64>().ok())
                    .flatten()
            })
            .map(|v| v as u64)
            .sum()
    }
}

// ---------------------------------------------------------------------------------------------
// Forwarding gossipsub neighbours with tapped transports.

/// The bytes read so far from one stream.
type StreamBytes = Arc<Mutex<Vec<u8>>>;

/// The bytes read from each stream of each connection, by the remote peer.
type Taps = Arc<Mutex<Vec<(PeerId, StreamBytes)>>>;

/// A protobuf field: its number, and its value if it is length-delimited.
type Field<'a> = (u64, Option<&'a [u8]>);

/// A muxer whose streams record every byte read from them.
struct TapMuxer<M> {
    inner: M,
    peer: PeerId,
    taps: Taps,
}

impl<M> TapMuxer<M> {
    fn tap<S>(&self, inner: S) -> TapStream<S> {
        let read = Arc::new(Mutex::new(Vec::new()));
        self.taps.lock().unwrap().push((self.peer, read.clone()));
        TapStream { inner, read }
    }
}

impl<M> StreamMuxer for TapMuxer<M>
where
    M: StreamMuxer + Unpin,
    M::Substream: Unpin,
{
    type Substream = TapStream<M::Substream>;
    type Error = M::Error;

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let stream = ready!(this.inner.poll_inbound_unpin(cx))?;
        Poll::Ready(Ok(this.tap(stream)))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let stream = ready!(this.inner.poll_outbound_unpin(cx))?;
        Poll::Ready(Ok(this.tap(stream)))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.poll_close_unpin(cx)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        self.get_mut().inner.poll_unpin(cx)
    }
}

struct TapStream<S> {
    inner: S,
    read: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for TapStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        this.read.lock().unwrap().extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TapStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

type PeerTransport =
    Result<Boxed<(PeerId, StreamMuxerBox)>, Box<dyn std::error::Error + Send + Sync>>;

/// TCP + Noise + yamux, every stream tapped into `taps`.
fn tapped_transport(key: &Keypair, taps: Taps) -> PeerTransport {
    Ok(
        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(key)?)
            .multiplex(yamux::Config::default())
            .map(move |(peer, inner), _| {
                let muxer = TapMuxer {
                    inner,
                    peer,
                    taps: taps.clone(),
                };
                (peer, StreamMuxerBox::new(muxer))
            })
            .boxed(),
    )
}

/// A default (forwarding) gossipsub node on the test topic: StrictNoSign and the Altair
/// message-id like the probe, so ids agree, but no manual validation. Tapped if `taps` is set.
fn gossip_swarm(
    taps: Option<Taps>,
    registry: &mut Registry,
) -> Swarm<gossipsub::Behaviour<WireTransform>> {
    let config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Anonymous)
        .message_id_fn(message_id)
        .max_transmit_size(max_message_size())
        .heartbeat_interval(HEARTBEAT)
        .heartbeat_initial_delay(HEARTBEAT)
        .build()
        .unwrap();
    let mut behaviour = gossipsub::Behaviour::new_with_transform(
        MessageAuthenticity::Anonymous,
        config,
        WireTransform::new(
            SnappyTransform::new(caps()),
            [ident_topic().hash()].into_iter().collect(),
        ),
    )
    .unwrap()
    .with_metrics(registry, gossipsub::MetricsConfig::default());
    behaviour.subscribe(&ident_topic()).unwrap();
    let builder = SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1()).with_tokio();
    match taps {
        Some(taps) => builder
            .with_other_transport(move |key| tapped_transport(key, taps))
            .unwrap()
            .with_behaviour(|_| behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
            .build(),
        None => builder
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
            .build(),
    }
}

enum Cmd {
    Dial(Multiaddr),
    Publish(Vec<u8>, oneshot::Sender<Result<MessageId, String>>),
    Mesh(oneshot::Sender<Vec<PeerId>>),
}

/// A forwarding gossipsub neighbour on its own task, its transport tapped.
pub(super) struct Neighbour {
    pub peer: PeerId,
    addr: Multiaddr,
    cmds: mpsc::UnboundedSender<Cmd>,
    taps: Taps,
    registry: Registry,
}

impl Neighbour {
    pub(super) async fn spawn() -> Self {
        let taps: Taps = Arc::default();
        let mut registry = Registry::default();
        let mut swarm = gossip_swarm(Some(taps.clone()), &mut registry);
        swarm.listen_on(loopback()).unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        let peer = *swarm.local_peer_id();
        let (cmds, mut rx) = mpsc::unbounded::<Cmd>();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = rx.next() => match cmd {
                        Some(Cmd::Dial(addr)) => swarm.dial(addr).unwrap(),
                        Some(Cmd::Publish(ssz, reply)) => {
                            let result = swarm
                                .behaviour_mut()
                                .publish(ident_topic(), ssz)
                                .map_err(|e| e.to_string());
                            let _ = reply.send(result);
                        }
                        Some(Cmd::Mesh(reply)) => {
                            let hash = ident_topic().hash();
                            let _ = reply.send(swarm.behaviour().mesh_peers(&hash).copied().collect());
                        }
                        None => return,
                    },
                    _ = swarm.select_next_some() => {}
                }
            }
        });
        Self {
            peer,
            addr,
            cmds,
            taps,
            registry,
        }
    }

    /// The neighbour's gossipsub metrics, registered exactly as the probe's are.
    pub(super) fn metrics(&self) -> Metrics {
        Metrics::scrape(&self.registry)
    }

    pub(super) fn dial(&self, addr: Multiaddr) {
        self.cmds.unbounded_send(Cmd::Dial(addr)).unwrap();
    }

    /// Publishes `ssz` and returns its id.
    pub(super) async fn publish(&self, ssz: Vec<u8>) -> MessageId {
        let (tx, rx) = oneshot::channel();
        self.cmds.unbounded_send(Cmd::Publish(ssz, tx)).unwrap();
        rx.await.unwrap().expect("publish")
    }

    async fn mesh(&self) -> Vec<PeerId> {
        let (tx, rx) = oneshot::channel();
        self.cmds.unbounded_send(Cmd::Mesh(tx)).unwrap();
        rx.await.unwrap()
    }

    /// Waits until `peer` is in this neighbour's mesh for the topic.
    pub(super) async fn wait_for_mesh_with(&self, peer: PeerId) {
        let deadline = tokio::time::Instant::now() + WAIT;
        while !self.mesh().await.contains(&peer) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "no mesh with {peer}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The traffic this neighbour read from `peer`'s streams, and from everyone else's.
    fn traffic(&self, peer: PeerId) -> Result<NeighbourTraffic, Unparsed> {
        let mut t = NeighbourTraffic {
            from_center: Traffic::default(),
            from_neighbours: Traffic::default(),
        };
        for (remote, bytes) in self.taps.lock().unwrap().iter() {
            let stream = Traffic::of_stream(&bytes.lock().unwrap())?;
            if *remote == peer {
                t.from_center.add(&stream);
            } else {
                t.from_neighbours.add(&stream);
            }
        }
        Ok(t)
    }
}

// ---------------------------------------------------------------------------------------------
// The scripted meshsub peer.

#[derive(Debug)]
enum RawEvent {
    Outbound(Stream),
    Inbound(Stream),
}

/// Opens one meshsub stream per connection and hands every meshsub stream to the test.
#[derive(Default)]
struct Raw {
    events: VecDeque<RawEvent>,
}

impl NetworkBehaviour for Raw {
    type ConnectionHandler = RawHandler;
    type ToSwarm = RawEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(RawHandler::default())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(RawHandler::default())
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.events.push_back(event);
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<RawEvent, Infallible>> {
        self.events
            .pop_front()
            .map_or(Poll::Pending, |e| Poll::Ready(ToSwarm::GenerateEvent(e)))
    }
}

#[derive(Default)]
struct RawHandler {
    requested: bool,
    events: VecDeque<RawEvent>,
}

impl ConnectionHandler for RawHandler {
    type FromBehaviour = Infallible;
    type ToBehaviour = RawEvent;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(MESHSUB), ())
    }

    fn connection_keep_alive(&self) -> bool {
        true
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), RawEvent>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }
        if !self.requested {
            self.requested = true;
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(MESHSUB), ()),
            });
        }
        Poll::Pending
    }

    fn on_behaviour_event(&mut self, event: Infallible) {
        match event {}
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: stream,
                ..
            }) => self.events.push_back(RawEvent::Inbound(stream)),
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                ..
            }) => self.events.push_back(RawEvent::Outbound(stream)),
            _ => {}
        }
    }
}

/// A peer that speaks meshsub by hand: it writes RPCs on its stream to the centre, and keeps
/// every byte the centre writes on its streams to it.
pub(super) struct Scripted {
    peer: PeerId,
    out: Stream,
    read: Arc<Mutex<Vec<StreamBytes>>>,
}

impl Scripted {
    pub(super) async fn connect(center: &Multiaddr) -> Self {
        let mut swarm = SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| Raw::default())
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
            .build();
        swarm.dial(center.clone()).unwrap();
        let peer = *swarm.local_peer_id();
        let read: Arc<Mutex<Vec<StreamBytes>>> = Arc::default();
        let (out_tx, out_rx) = oneshot::channel();
        let streams = read.clone();
        tokio::spawn(async move {
            let mut out_tx = Some(out_tx);
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::Behaviour(RawEvent::Outbound(stream)) => {
                        if let Some(tx) = out_tx.take() {
                            let _ = tx.send(stream);
                        }
                    }
                    SwarmEvent::Behaviour(RawEvent::Inbound(mut stream)) => {
                        let buf = Arc::new(Mutex::new(Vec::new()));
                        streams.lock().unwrap().push(buf.clone());
                        tokio::spawn(async move {
                            let mut chunk = vec![0u8; 64 * 1024];
                            while let Ok(n @ 1..) = stream.read(&mut chunk).await {
                                buf.lock().unwrap().extend_from_slice(&chunk[..n]);
                            }
                        });
                    }
                    _ => {}
                }
            }
        });
        let out = tokio::time::timeout(WAIT, out_rx)
            .await
            .expect("a meshsub stream to the centre")
            .unwrap();
        Self { peer, out, read }
    }

    /// Writes `rpc` as one length-prefixed frame.
    pub(super) async fn send(&mut self, rpc: &[u8]) {
        let mut frame = Vec::with_capacity(rpc.len() + 10);
        encode_varint(rpc.len() as u64, &mut frame);
        frame.extend_from_slice(rpc);
        self.out.write_all(&frame).await.unwrap();
        self.out.flush().await.unwrap();
    }

    /// What the centre wrote to this peer.
    fn traffic(&self) -> Result<Traffic, Unparsed> {
        let mut total = Traffic::default();
        for stream in self.read.lock().unwrap().iter() {
            total.add(&Traffic::of_rpcs(&stream.lock().unwrap())?);
        }
        Ok(total)
    }
}

/// gossipsub `RPC` encoders (`rpc.proto`): just the fields the scripted peer sends.
pub(super) mod rpc {
    use super::encode_varint;

    fn bytes(field: u64, value: &[u8], out: &mut Vec<u8>) {
        encode_varint(field << 3 | 2, out);
        encode_varint(value.len() as u64, out);
        out.extend_from_slice(value);
    }

    /// `subscriptions { subscribe: true, topic_id }`.
    pub fn subscribe(topic: &str) -> Vec<u8> {
        subscribe_all([topic])
    }

    /// One `subscriptions` entry per topic, in one RPC.
    pub fn subscribe_all<'a>(topics: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
        let mut out = Vec::new();
        for topic in topics {
            let mut opts = vec![0x08, 0x01];
            bytes(2, topic.as_bytes(), &mut opts);
            bytes(1, &opts, &mut out);
        }
        out
    }

    /// `publish` entries: `Message { data, topic }`, no `from`, `seqno`, `signature`, `key`.
    pub fn publish<'a>(topic: &str, data: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        for d in data {
            let mut message = Vec::new();
            bytes(2, d, &mut message);
            bytes(4, topic.as_bytes(), &mut message);
            bytes(2, &message, &mut out);
        }
        out
    }

    /// One `publish` entry, `Message { data, topic }`, with each `(field, value)` of `extra`
    /// appended as a bytes field.
    pub fn publish_with(topic: &str, data: &[u8], extra: &[(u64, &[u8])]) -> Vec<u8> {
        let mut message = Vec::new();
        bytes(2, data, &mut message);
        bytes(4, topic.as_bytes(), &mut message);
        for (field, value) in extra {
            bytes(*field, value, &mut message);
        }
        let mut out = Vec::new();
        bytes(2, &message, &mut out);
        out
    }

    /// `control { graft { topic_id } }`.
    pub fn graft(topic: &str) -> Vec<u8> {
        let mut graft = Vec::new();
        bytes(1, topic.as_bytes(), &mut graft);
        let mut control = Vec::new();
        bytes(3, &graft, &mut control);
        let mut out = Vec::new();
        bytes(3, &control, &mut out);
        out
    }

    /// `control { ihave { topic_id, message_ids } }`.
    pub fn ihave<'a>(topic: &str, ids: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
        let mut ihave = Vec::new();
        bytes(1, topic.as_bytes(), &mut ihave);
        for id in ids {
            bytes(2, id, &mut ihave);
        }
        let mut control = Vec::new();
        bytes(1, &ihave, &mut control);
        let mut out = Vec::new();
        bytes(3, &control, &mut out);
        out
    }

    /// `control { iwant { message_ids } }`.
    pub fn iwant<'a>(ids: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
        let mut iwant = Vec::new();
        for id in ids {
            bytes(1, id, &mut iwant);
        }
        let mut control = Vec::new();
        bytes(2, &iwant, &mut control);
        let mut out = Vec::new();
        bytes(3, &control, &mut out);
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing what a tap read.

/// The gossipsub traffic in some bytes read from a peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Traffic {
    /// `RPC` frames.
    pub frames: usize,
    /// `RPC.publish` entries: data messages.
    pub publish_msgs: usize,
    /// Their encoded bytes.
    pub publish_bytes: usize,
    /// Message ids announced in `IHAVE`.
    pub ihave_ids: usize,
    /// Message ids requested in `IWANT`.
    pub iwant_ids: usize,
}

impl Traffic {
    fn add(&mut self, other: &Traffic) {
        self.frames += other.frames;
        self.publish_msgs += other.publish_msgs;
        self.publish_bytes += other.publish_bytes;
        self.ihave_ids += other.ihave_ids;
        self.iwant_ids += other.iwant_ids;
    }

    /// One stream as a muxer delivered it: multistream-select headers, then (on a meshsub
    /// stream) `RPC` frames. Any other protocol must carry nothing after its headers here.
    fn of_stream(bytes: &[u8]) -> Result<Traffic, Unparsed> {
        let mut pos = 0;
        let mut meshsub = false;
        while let Some((len, n)) = varint(&bytes[pos..]) {
            let Some(msg) = bytes.get(pos + n..pos + n + len as usize) else {
                break;
            };
            let header = msg.ends_with(b"\n") && (msg.starts_with(b"/") || msg == b"na\n");
            if !header {
                break;
            }
            meshsub |= msg.starts_with(b"/meshsub/");
            pos += n + len as usize;
        }
        let rest = &bytes[pos..];
        if !meshsub {
            assert!(rest.is_empty(), "unexpected bytes on a non-gossip stream");
            return Ok(Traffic::default());
        }
        Traffic::of_rpcs(rest)
    }

    /// Length-prefixed `RPC` frames. A last frame still arriving is [`Unparsed::Partial`];
    /// anything malformed panics.
    fn of_rpcs(mut bytes: &[u8]) -> Result<Traffic, Unparsed> {
        let mut t = Traffic::default();
        while !bytes.is_empty() {
            let frame =
                varint(bytes).and_then(|(len, n)| Some((bytes.get(n..n + len as usize)?, n)));
            let Some((frame, n)) = frame else {
                return Err(Unparsed::Partial);
            };
            let len = frame.len();
            t.frames += 1;
            let frame = fields(frame).unwrap_or_else(|e| panic!("malformed RPC: {e}"));
            for (field, value) in frame {
                match (field, value) {
                    (2, Some(message)) => {
                        t.publish_msgs += 1;
                        t.publish_bytes += message.len();
                    }
                    (3, Some(control)) => {
                        let control = fields(control).unwrap_or_else(|e| panic!("control: {e}"));
                        for (f, entry) in control {
                            let ids = |entry, id_field| {
                                let entry = fields(entry).unwrap_or_else(|e| panic!("{e}"));
                                entry.iter().filter(|(f, _)| *f == id_field).count()
                            };
                            match (f, entry) {
                                (1, Some(ihave)) => t.ihave_ids += ids(ihave, 2),
                                (2, Some(iwant)) => t.iwant_ids += ids(iwant, 1),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            bytes = &bytes[n + len..];
        }
        Ok(t)
    }
}

/// A tap read that ends inside a frame: read it again once the frame has arrived.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Unparsed {
    Partial,
}

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, b) in bytes.iter().take(10).enumerate() {
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// The top-level fields of a protobuf message: number, and the value of length-delimited ones.
fn fields(mut bytes: &[u8]) -> Result<Vec<Field<'_>>, String> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (tag, n) = varint(bytes).ok_or("tag")?;
        bytes = &bytes[n..];
        let skip = match tag & 7 {
            0 => varint(bytes).ok_or("varint")?.1,
            1 => 8,
            5 => 4,
            2 => {
                let (len, n) = varint(bytes).ok_or("length")?;
                let value = bytes.get(n..n + len as usize).ok_or("truncated field")?;
                out.push((tag >> 3, Some(value)));
                bytes = &bytes[n + len as usize..];
                continue;
            }
            wire => return Err(format!("wire type {wire}")),
        };
        out.push((tag >> 3, None));
        bytes = bytes.get(skip..).ok_or("truncated scalar")?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// The scenarios.

/// What one neighbour's tap saw.
#[derive(Debug, Default)]
pub(super) struct NeighbourTraffic {
    pub from_center: Traffic,
    pub from_neighbours: Traffic,
}

/// What the scenarios observed.
#[derive(Debug)]
pub(super) struct Observed {
    pub neighbours: Vec<NeighbourTraffic>,
    /// Each neighbour's gossipsub metrics at the end.
    pub neighbour_metrics: Vec<Metrics>,
    /// What the centre wrote to the scripted peer.
    pub scripted: Traffic,
    /// Distinct messages the centre delivered.
    pub delivered: usize,
    /// Messages the centre must have delivered.
    pub expected_at_least: usize,
}

/// Messages each neighbour floods.
const FLOOD: usize = 10;
/// Copies of an already seen message the scripted peer sends.
const DUPLICATES: usize = 20;
/// Messages in the scripted peer's overload burst, sent 50 to an RPC.
const BURST: usize = 1000;
/// Messages in each neighbour's overload burst.
const NEIGHBOUR_BURST: usize = 100;

/// Three tapped neighbours (all connected to each other and to the centre) and the scripted
/// peer around `center`, then: a flood (each message reaches the centre through every
/// neighbour, so duplicates too), duplicates from the scripted peer, IWANT for every id the
/// centre has seen, IWANT again after `mcache_len` heartbeats, and an overload burst.
/// `heartbeats` reads the centre's heartbeat count.
pub(super) async fn run_scenarios(center: &Center, heartbeats: impl Fn() -> u64) -> Observed {
    let topic = topic().to_string();
    let mut neighbours = Vec::new();
    for _ in 0..3 {
        neighbours.push(Neighbour::spawn().await);
    }
    for (i, n) in neighbours.iter().enumerate() {
        n.dial(center.addr.clone());
        for other in &neighbours[i + 1..] {
            n.dial(other.addr.clone());
        }
    }
    let mut scripted = Scripted::connect(&center.addr).await;
    scripted.send(&rpc::subscribe(&topic)).await;
    scripted.send(&rpc::graft(&topic)).await;
    for n in &neighbours {
        n.wait_for_mesh_with(center.peer).await;
        for other in &neighbours {
            if other.peer != n.peer {
                n.wait_for_mesh_with(other.peer).await;
            }
        }
    }

    // Flood: every neighbour publishes; each message reaches the centre from up to three peers.
    let mut ids = Vec::new();
    for (i, n) in neighbours.iter().enumerate() {
        for j in 0..FLOOD {
            ids.push(n.publish(payload(&format!("flood{i}"), j, 1500)).await);
        }
    }
    center.wait_for_deliveries(ids.len()).await;

    // The scripted peer's own message, then duplicates of it and of a neighbour's message.
    let own = payload("scripted", 0, 600);
    let own_data = compressed(&own);
    scripted.send(&rpc::publish(&topic, [&own_data[..]])).await;
    let own_id = id_of(&own);
    eventually("the scripted message", || center.has(&own_id).then_some(())).await;
    ids.push(own_id);
    let seen = compressed(&payload("flood0", 0, 1500));
    let copies: Vec<&[u8]> = (0..DUPLICATES)
        .map(|_| &own_data[..])
        .chain([&seen[..]; 5])
        .collect();
    scripted.send(&rpc::publish(&topic, copies)).await;

    // IWANT every seen id now, and again once the cache has shifted past mcache_len windows.
    // gossipsub runs a heartbeat only when its task is woken, so keep it busy with
    // subscription refreshes until enough heartbeats have run.
    let wanted: Vec<&[u8]> = ids.iter().map(|id| &id.0[..]).collect();
    scripted.send(&rpc::iwant(wanted.clone())).await;
    let start = heartbeats();
    let deadline = tokio::time::Instant::now() + WAIT;
    while heartbeats() <= start + MCACHE_LEN as u64 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the centre's heartbeat stalled"
        );
        scripted.send(&rpc::subscribe(&topic)).await;
        tokio::time::sleep(HEARTBEAT / 4).await;
    }
    scripted.send(&rpc::iwant(wanted)).await;

    // Overload: a burst from the scripted peer in 50-message RPCs, and from every neighbour.
    let burst: Vec<Vec<u8>> = (0..BURST)
        .map(|i| compressed(&payload("burst", i, 300)))
        .collect();
    for chunk in burst.chunks(50) {
        scripted
            .send(&rpc::publish(&topic, chunk.iter().map(Vec::as_slice)))
            .await;
    }
    for (i, n) in neighbours.iter().enumerate() {
        for j in 0..NEIGHBOUR_BURST {
            n.publish(payload(&format!("nburst{i}"), j, 300)).await;
        }
    }
    // Every scripted message reaches the centre directly; neighbour bursts may be shed.
    let expected_at_least = ids.len() + BURST;
    center.wait_for_deliveries(expected_at_least).await;

    // Let late gossip (heartbeats, IHAVE, IWANT answers) arrive, then read the taps.
    tokio::time::sleep(HEARTBEAT * 5).await;
    let delivered = center.delivered().len();
    let neighbour_metrics = neighbours.iter().map(Neighbour::metrics).collect();
    let (neighbours, scripted) = eventually("every tap to end on a frame boundary", || {
        let n: Result<Vec<_>, _> = neighbours.iter().map(|n| n.traffic(center.peer)).collect();
        Some((n.ok()?, scripted.traffic().ok()?))
    })
    .await;
    Observed {
        neighbours,
        neighbour_metrics,
        scripted,
        delivered,
        expected_at_least,
    }
}

/// The control: the same topology around a forwarding node. The taps that read nothing from the
/// probe read its data messages here, so a zero above is the probe's doing, not a blind tap.
#[tokio::test]
async fn the_taps_see_a_forwarding_peer() {
    let (center, registry) = spawn_forwarder().await;
    let observed = run_scenarios(&center, || {
        Metrics::scrape(&registry).sum("heartbeat_duration_count")
    })
    .await;
    // The counters that read 0 on the probe count here.
    assert!(Metrics::scrape(&registry).sum("topic_msg_sent_counts") > 0);
    for (i, n) in observed.neighbours.iter().enumerate() {
        assert!(
            n.from_center.publish_msgs > 0 && n.from_center.publish_bytes > 0,
            "neighbour {i} saw no data from a forwarding centre: {n:?}"
        );
    }
    assert!(
        observed.scripted.publish_msgs > 0,
        "the scripted peer got no data from a forwarding centre: {:?}",
        observed.scripted
    );
}

#[test]
fn the_parser_counts_publish_apart_from_control() {
    let topic = topic().to_string();
    let mut rpcs = Vec::new();
    for rpc in [
        rpc::subscribe(&topic),
        rpc::publish(&topic, [&b"abc"[..], &b"de"[..]]),
        rpc::graft(&topic),
        rpc::iwant([&b"id"[..]]),
    ] {
        encode_varint(rpc.len() as u64, &mut rpcs);
        rpcs.extend_from_slice(&rpc);
    }
    let t = Traffic::of_rpcs(&rpcs).unwrap();
    assert_eq!(t.iwant_ids, 1);
    assert_eq!(
        Traffic::of_rpcs(&rpcs[..rpcs.len() - 1]),
        Err(Unparsed::Partial)
    );
    assert_eq!((t.frames, t.publish_msgs, t.ihave_ids), (4, 2, 0));
    // Each Message: data (2 + len) and topic (2 + topic len).
    assert_eq!(t.publish_bytes, (2 + 3) + (2 + 2) + 2 * (2 + topic.len()));

    // An IHAVE with two ids: control { ihave { message_ids, message_ids } }.
    let ihave = [
        0x1a, 0x0a, 0x0a, 0x08, 0x12, 0x02, b'a', b'b', 0x12, 0x02, b'c', b'd',
    ];
    let mut frame = vec![ihave.len() as u8];
    frame.extend_from_slice(&ihave);
    assert_eq!(Traffic::of_rpcs(&frame).unwrap().ihave_ids, 2);

    // A stream: multistream-select headers first.
    let mut stream = Vec::new();
    for header in [&b"/multistream/1.0.0\n"[..], b"/meshsub/1.3.0\n"] {
        encode_varint(header.len() as u64, &mut stream);
        stream.extend_from_slice(header);
    }
    stream.extend_from_slice(&rpcs);
    assert_eq!(Traffic::of_stream(&stream), Ok(t));
    // A refused protocol carries nothing.
    let mut refused = Vec::new();
    for header in [&b"/multistream/1.0.0\n"[..], b"na\n"] {
        encode_varint(header.len() as u64, &mut refused);
        refused.extend_from_slice(header);
    }
    assert_eq!(Traffic::of_stream(&refused), Ok(Traffic::default()));
    assert_eq!(Traffic::of_rpcs(&[0x05, 0x0a]), Err(Unparsed::Partial));
    assert!(fields(&[0x0b]).is_err(), "wire type 3");
}

/// Sends a fresh message from `scripted` and waits until the centre delivered it: every RPC
/// sent before it has been handled.
pub(super) async fn handled(center: &Center, scripted: &mut Scripted, tag: &str) {
    let marker = payload(tag, 0, 100);
    scripted
        .send(&rpc::publish(
            &topic().to_string(),
            [&compressed(&marker)[..]],
        ))
        .await;
    let id = id_of(&marker);
    eventually(&format!("marker {tag}"), || center.has(&id).then_some(())).await;
}

/// A peer subscribing to many topics the probe does not handle: the probe holds, for it, only
/// the topics it subscribes itself.
#[tokio::test]
async fn off_list_subscriptions_are_not_kept() {
    let probe = Probe::spawn(1).await;
    let center = &probe.center;
    let mut scripted = Scripted::connect(&center.addr).await;
    let topic = topic().to_string();
    scripted.send(&rpc::subscribe(&topic)).await;
    // Each RPC under the per-request cap, so only the topic filter can refuse them.
    for batch in 0..360 {
        let junk: Vec<String> = (0..50).map(|i| format!("/junk/{batch}/{i}")).collect();
        scripted
            .send(&rpc::subscribe_all(junk.iter().map(String::as_str)))
            .await;
    }
    let other_fork = topic.replace("abcd0012", "abcd0013");
    scripted.send(&rpc::subscribe(&other_fork)).await;
    handled(center, &mut scripted, "after-junk").await;
    assert_eq!(center.topics_of(scripted.peer).await, vec![topic]);
}

/// One RPC with more subscriptions than the per-request cap is ignored whole; one at the cap
/// is taken (its listed topic kept, the rest dropped).
#[tokio::test]
async fn an_rpc_over_the_subscription_cap_is_ignored() {
    use super::config::MAX_SUBSCRIPTIONS_PER_REQUEST;
    let probe = Probe::spawn(1).await;
    let center = &probe.center;
    let mut scripted = Scripted::connect(&center.addr).await;
    let topic = topic().to_string();
    let rpc_of = |n: usize| {
        let junk: Vec<String> = (1..n).map(|i| format!("/j{i}")).collect();
        rpc::subscribe_all(std::iter::once(topic.as_str()).chain(junk.iter().map(String::as_str)))
    };

    scripted
        .send(&rpc_of(MAX_SUBSCRIPTIONS_PER_REQUEST + 1))
        .await;
    handled(center, &mut scripted, "over").await;
    assert!(center.topics_of(scripted.peer).await.is_empty());

    scripted.send(&rpc_of(MAX_SUBSCRIPTIONS_PER_REQUEST)).await;
    handled(center, &mut scripted, "at").await;
    assert_eq!(center.topics_of(scripted.peer).await, vec![topic]);
}

/// Messages on topics the probe does not handle: only our topics get metric labels, and our
/// topic's metrics count only our messages.
#[tokio::test]
async fn off_list_topics_get_no_metric_labels() {
    let probe = Probe::spawn(1).await;
    let center = &probe.center;
    let mut scripted = Scripted::connect(&center.addr).await;
    for name in [
        "voluntary_exit",
        "proposer_slashing",
        "beacon_aggregate_and_proof",
    ] {
        let other = format!("/eth2/abcd0012/{name}/ssz_snappy");
        scripted
            .send(&rpc::publish(&other, [&compressed(b"ssz")[..]]))
            .await;
    }
    handled(center, &mut scripted, "after-other-topics").await;
    let metrics = probe.metrics();
    for name in [
        "voluntary_exit",
        "proposer_slashing",
        "beacon_aggregate_and_proof",
    ] {
        assert!(!metrics.contains(name), "{name} labels a metric");
    }
    assert_eq!(metrics.sum("topic_msg_recv_counts_unfiltered"), 1);
    assert_eq!(
        metrics.sum_matching("topic_msg_recv_counts", &topic().to_string()),
        1
    );
    assert_eq!(metrics.sum("ignored_messages_per_topic"), 1);
    assert_eq!(metrics.sum("invalid_messages_per_topic"), 0);
    // Only the marker on our topic reached IgnoreAll.
    assert_eq!(center.delivered().len(), 1);
}

/// Every topic of two fork digests, by their real names, in one RPC (a supernode connecting
/// ahead of a fork): the codec takes the RPC whole and our subscription is kept.
#[tokio::test]
async fn a_full_two_fork_announcement_is_taken() {
    use super::config::MAX_SUBSCRIPTIONS_PER_REQUEST;
    let probe = Probe::spawn(1).await;
    let center = &probe.center;
    let mut scripted = Scripted::connect(&center.addr).await;
    let names: Vec<String> = [
        "beacon_block",
        "beacon_aggregate_and_proof",
        "voluntary_exit",
        "proposer_slashing",
        "attester_slashing",
        "sync_committee_contribution_and_proof",
        "bls_to_execution_change",
        "light_client_finality_update",
        "light_client_optimistic_update",
        "execution_payload_bid",
        "execution_payload",
        "payload_attestation_message",
        "proposer_preferences",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain((0..64).map(|i| format!("beacon_attestation_{i}")))
    .chain((0..4).map(|i| format!("sync_committee_{i}")))
    .chain((0..128).map(|i| format!("data_column_sidecar_{i}")))
    .collect();
    let topics: Vec<String> = ["abcd0012", "abcd0013"]
        .iter()
        .flat_map(|d| {
            names
                .iter()
                .map(move |n| format!("/eth2/{d}/{n}/ssz_snappy"))
        })
        .collect();
    assert_eq!(topics.len(), MAX_SUBSCRIPTIONS_PER_REQUEST);
    let announcement = rpc::subscribe_all(topics.iter().map(String::as_str));
    assert!(
        announcement.len() > 16 * 1024,
        "{} bytes",
        announcement.len()
    );
    scripted.send(&announcement).await;
    handled(center, &mut scripted, "announced").await;
    assert_eq!(
        center.topics_of(scripted.peer).await,
        vec![topic().to_string()]
    );
}

/// The probe uses mesh push only: it answers no IHAVE with an IWANT, and still counts what its
/// mesh pushes to it.
#[tokio::test]
async fn ihave_gets_no_iwant() {
    let probe = Probe::spawn(1).await;
    let center = &probe.center;
    let mut scripted = Scripted::connect(&center.addr).await;
    let topic = topic().to_string();
    scripted.send(&rpc::subscribe(&topic)).await;
    scripted.send(&rpc::graft(&topic)).await;
    let ids: Vec<[u8; 20]> = (0..200u32)
        .map(|i| {
            let mut id = [0u8; 20];
            id[..4].copy_from_slice(&i.to_le_bytes());
            id
        })
        .collect();
    for chunk in ids.chunks(20) {
        scripted
            .send(&rpc::ihave(&topic, chunk.iter().map(|id| &id[..])))
            .await;
    }
    handled(center, &mut scripted, "after-ihave").await;
    tokio::time::sleep(HEARTBEAT * 3).await;
    let t = eventually("the probe's stream on a frame boundary", || {
        scripted.traffic().ok()
    })
    .await;
    assert!(
        t.frames > 0,
        "the scripted peer read nothing from the probe"
    );
    assert_eq!(t.iwant_ids, 0, "{t:?}");
    let metrics = probe.metrics();
    assert_eq!(
        metrics.sum_matching("topic_msg_recv_counts", &topic),
        1,
        "the pushed marker is counted"
    );
}
