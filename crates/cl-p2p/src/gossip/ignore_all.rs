//! [`IgnoreAll`]: gossipsub that reports IGNORE for every message and so forwards none.
//!
//! The probe has no state transition, so it cannot validate a block, and unverified blocks are
//! never relayed (`phase0/p2p-interface.md`). With manual validation gossipsub forwards a
//! message only after the application reports `Accept`; IGNORE drops it from the message
//! cache with no P4 penalty, and the cache never gossips (IHAVE) or serves (IWANT) a message
//! that has not been validated. So once every message is reported IGNORE, no data message
//! leaves this node: not as a forward, not as an IWANT answer, not from a duplicate.
//!
//! [`IgnoreAll`] wraps the gossipsub behaviour and keeps it private. It reports each message
//! inside its own `poll`, the moment gossipsub hands it over and before the swarm's owner sees
//! anything, and it exposes no `publish`: no code path can send a data message. The owner gets
//! [`IgnoreAllEvent::Ignored`] for each message, and every other gossipsub event as is.
//!
//! Each message also goes to an optional [`CaptureTap`] with its receive time: a bounded queue
//! that drops (and counts) when the reader is behind, so capture never slows the swarm.

use super::{GossipConfig, GossipError};
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::gossipsub::{
    self, DataTransform, MessageAcceptance, MessageAuthenticity, MessageId, TopicHash,
    TopicSubscriptionFilter,
};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use prometheus_client::registry::Registry;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

/// The probe's gossipsub: the bounded snappy transform, and peers' subscriptions held only for
/// our own topics.
pub type ProbeGossipsub =
    gossipsub::Behaviour<super::WireTransform, super::config::ProbeSubscriptionFilter>;

/// What [`IgnoreAll`] needs from gossipsub: the validation report, and nothing that publishes.
pub trait ValidationSink {
    /// Reports `acceptance` for message `id` received from `source`; `false` if the message
    /// was no longer in the cache.
    fn report_validation(
        &mut self,
        id: &MessageId,
        source: &PeerId,
        acceptance: MessageAcceptance,
    ) -> bool;
}

impl<D, F> ValidationSink for gossipsub::Behaviour<D, F>
where
    D: DataTransform + Send + 'static,
    F: TopicSubscriptionFilter + Send + 'static,
{
    fn report_validation(
        &mut self,
        id: &MessageId,
        source: &PeerId,
        acceptance: MessageAcceptance,
    ) -> bool {
        self.report_message_validation_result(id, source, acceptance)
    }
}

/// One received message, as [`IgnoreAll`] hands it to the capture tap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Captured {
    /// When gossipsub delivered it, monotonic.
    pub recv_mono: Instant,
    /// When gossipsub delivered it, wall clock.
    pub recv_wall: SystemTime,
    /// The full topic string.
    pub topic: String,
    /// The message-id.
    pub message_id: Vec<u8>,
    /// The peer it came from.
    pub source: PeerId,
    /// The decompressed SSZ bytes (the data transform has already run).
    pub data: Vec<u8>,
}

/// The sending side of a bounded capture queue: [`CaptureTap::offer`] never waits.
#[derive(Clone, Debug)]
pub struct CaptureTap {
    tx: SyncSender<Captured>,
    dropped: Arc<AtomicU64>,
}

/// The reading side of a capture queue.
#[derive(Debug)]
pub struct CaptureReader {
    rx: Receiver<Captured>,
    dropped: Arc<AtomicU64>,
}

/// A capture queue holding at most `capacity` messages (at least one).
pub fn capture_tap(capacity: usize) -> (CaptureTap, CaptureReader) {
    let (tx, rx) = mpsc::sync_channel(capacity.max(1));
    let dropped = Arc::new(AtomicU64::new(0));
    (
        CaptureTap {
            tx,
            dropped: dropped.clone(),
        },
        CaptureReader { rx, dropped },
    )
}

impl CaptureTap {
    /// Queues `captured`, or drops and counts it if the queue is full or its reader is gone.
    pub fn offer(&self, captured: Captured) -> bool {
        match self.tx.try_send(captured) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Messages dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl CaptureReader {
    /// The next queued message, if any, without waiting.
    pub fn try_next(&self) -> Option<Captured> {
        self.rx.try_recv().ok()
    }

    /// Messages the tap dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// What [`IgnoreAll`] tells the swarm's owner.
#[derive(Debug)]
pub enum IgnoreAllEvent {
    /// A message arrived and was reported IGNORE.
    Ignored {
        /// The peer it came from.
        source: PeerId,
        /// Its message-id.
        message_id: MessageId,
        /// Its topic.
        topic: TopicHash,
        /// Whether gossipsub still had it cached when the report arrived (it always has: the
        /// report is made in the same poll).
        in_cache: bool,
    },
    /// Any other gossipsub event: subscriptions, slow peers, peers without gossipsub.
    Gossipsub(gossipsub::Event),
}

/// Gossipsub that reports IGNORE for every message; see the module docs.
///
/// [`IgnoreAll::new`] is the only way to build one outside this module, so the gossipsub
/// inside always has manual validation, StrictNoSign and the subscription filter: one built
/// without manual validation would forward each message before it is reported.
///
/// ```compile_fail,E0624
/// fn wrap(gossipsub: cl_p2p::gossip::ProbeGossipsub) -> cl_p2p::gossip::IgnoreAll {
///     cl_p2p::gossip::IgnoreAll::with_inner(gossipsub)
/// }
/// ```
pub struct IgnoreAll<G = ProbeGossipsub> {
    inner: G,
    tap: Option<CaptureTap>,
    ignored: u64,
}

impl IgnoreAll<ProbeGossipsub> {
    /// The probe's gossipsub per `cfg`, its metrics registered on `registry`, with every
    /// `cfg.topics` topic subscribed.
    ///
    /// The metrics are gossipsub's own: among them `topic_msg_sent_counts` and
    /// `topic_msg_published`, which stay at zero for every topic, `mesh_peer_counts` (the
    /// mesh degree per topic), and `ignored_messages_per_topic`, labelled only with our own
    /// topics ([`super::config::metrics_config`]). prometheus-client writes a
    /// labelled family only once it has a series, so the two zero counters are absent from a
    /// scrape of the probe: absent reads 0.
    ///
    /// # Errors
    ///
    /// [`GossipError`] if the configuration is refused or a topic cannot be subscribed.
    pub fn new(cfg: &GossipConfig, registry: &mut Registry) -> Result<Self, GossipError> {
        let mut gossipsub = gossipsub::Behaviour::new_with_subscription_filter_and_transform(
            MessageAuthenticity::Anonymous,
            cfg.gossipsub()?,
            cfg.subscription_filter(),
            cfg.transform(),
        )
        .map_err(GossipError::Behaviour)?
        .with_metrics(registry, super::config::metrics_config());
        for topic in &cfg.topics {
            gossipsub.subscribe(&gossipsub::IdentTopic::new(topic.to_string()))?;
        }
        Ok(Self::with_inner(gossipsub))
    }
}

impl<G> IgnoreAll<G> {
    /// Ignore-all over `inner`. Private: only [`IgnoreAll::new`] builds the gossipsub it
    /// wraps, so manual validation cannot be left out.
    fn with_inner(inner: G) -> Self {
        Self {
            inner,
            tap: None,
            ignored: 0,
        }
    }

    /// Sends every received message to `tap` too.
    #[must_use]
    pub fn with_tap(mut self, tap: CaptureTap) -> Self {
        self.tap = Some(tap);
        self
    }

    /// Messages reported IGNORE so far.
    pub fn ignored(&self) -> u64 {
        self.ignored
    }

    /// The gossipsub behaviour, read-only (mesh and peer state).
    pub fn gossipsub(&self) -> &G {
        &self.inner
    }
}

impl<G: ValidationSink> IgnoreAll<G> {
    fn ignore(
        &mut self,
        source: PeerId,
        message_id: MessageId,
        message: gossipsub::Message,
    ) -> IgnoreAllEvent {
        let recv_mono = Instant::now();
        let recv_wall = SystemTime::now();
        let in_cache =
            self.inner
                .report_validation(&message_id, &source, MessageAcceptance::Ignore);
        self.ignored += 1;
        if !in_cache {
            tracing::warn!(%message_id, peer = %source, "ignored message was not in the cache");
        }
        if let Some(tap) = &self.tap {
            tap.offer(Captured {
                recv_mono,
                recv_wall,
                topic: message.topic.to_string(),
                message_id: message_id.0.clone(),
                source,
                data: message.data,
            });
        }
        IgnoreAllEvent::Ignored {
            source,
            message_id,
            topic: message.topic,
            in_cache,
        }
    }
}

impl<G> NetworkBehaviour for IgnoreAll<G>
where
    G: NetworkBehaviour<ToSwarm = gossipsub::Event> + ValidationSink,
{
    type ConnectionHandler = G::ConnectionHandler;
    type ToSwarm = IgnoreAllEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        match self.inner.poll(cx) {
            Poll::Ready(ToSwarm::GenerateEvent(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            })) => Poll::Ready(ToSwarm::GenerateEvent(self.ignore(
                propagation_source,
                message_id,
                message,
            ))),
            Poll::Ready(other) => Poll::Ready(other.map_out(IgnoreAllEvent::Gossipsub)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::swarm::dummy;
    use std::collections::VecDeque;
    use std::convert::Infallible;

    /// A gossipsub stand-in: emits scripted events and records every report.
    #[derive(Default)]
    struct Scripted {
        events: VecDeque<gossipsub::Event>,
        reports: Vec<(MessageId, PeerId, MessageAcceptance)>,
        /// What `report_validation` answers.
        cached: bool,
        swarm_events: usize,
    }

    impl ValidationSink for Scripted {
        fn report_validation(
            &mut self,
            id: &MessageId,
            source: &PeerId,
            acceptance: MessageAcceptance,
        ) -> bool {
            self.reports.push((id.clone(), *source, acceptance));
            self.cached
        }
    }

    impl NetworkBehaviour for Scripted {
        type ConnectionHandler = dummy::ConnectionHandler;
        type ToSwarm = gossipsub::Event;

        fn handle_established_inbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: &Multiaddr,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn handle_established_outbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: Endpoint,
            _: PortUse,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn on_swarm_event(&mut self, _: FromSwarm) {
            self.swarm_events += 1;
        }

        fn on_connection_handler_event(
            &mut self,
            _: PeerId,
            _: ConnectionId,
            event: THandlerOutEvent<Self>,
        ) {
            match event {}
        }

        fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<gossipsub::Event, Infallible>> {
            self.events
                .pop_front()
                .map_or(Poll::Pending, |e| Poll::Ready(ToSwarm::GenerateEvent(e)))
        }
    }

    const TOPIC: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    fn message(i: u8, source: PeerId) -> gossipsub::Event {
        gossipsub::Event::Message {
            propagation_source: source,
            message_id: MessageId::new(&[i]),
            message: gossipsub::Message {
                source: None,
                data: vec![i; 3],
                sequence_number: None,
                topic: TopicHash::from_raw(TOPIC),
            },
        }
    }

    fn drain<G>(behaviour: &mut IgnoreAll<G>) -> Vec<IgnoreAllEvent>
    where
        G: NetworkBehaviour<ToSwarm = gossipsub::Event> + ValidationSink,
    {
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let mut out = Vec::new();
        while let Poll::Ready(event) = behaviour.poll(&mut cx) {
            match event {
                ToSwarm::GenerateEvent(e) => out.push(e),
                other => panic!("unexpected {other:?}"),
            }
        }
        out
    }

    #[test]
    fn every_message_is_reported_ignore_in_the_poll_that_delivers_it() {
        let peer = PeerId::random();
        let mut inner = Scripted {
            cached: true,
            ..Default::default()
        };
        for i in 0..5 {
            inner.events.push_back(message(i, peer));
        }
        let mut behaviour = IgnoreAll::with_inner(inner);
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        for i in 0..5u8 {
            let Poll::Ready(ToSwarm::GenerateEvent(IgnoreAllEvent::Ignored {
                source,
                message_id,
                topic,
                in_cache,
            })) = behaviour.poll(&mut cx)
            else {
                panic!("message {i} not ignored");
            };
            // Reported before the event reached us.
            assert_eq!(behaviour.gossipsub().reports.len(), usize::from(i) + 1);
            assert_eq!(
                behaviour.gossipsub().reports[usize::from(i)],
                (message_id.clone(), peer, MessageAcceptance::Ignore)
            );
            assert_eq!((source, message_id), (peer, MessageId::new(&[i])));
            assert_eq!(topic.as_str(), TOPIC);
            assert!(in_cache);
        }
        assert!(behaviour.poll(&mut cx).is_pending());
        assert_eq!(behaviour.ignored(), 5);
    }

    #[test]
    fn other_events_pass_through_unreported() {
        let peer = PeerId::random();
        let mut inner = Scripted::default();
        inner.events.push_back(gossipsub::Event::Subscribed {
            peer_id: peer,
            topic: TopicHash::from_raw(TOPIC),
        });
        inner
            .events
            .push_back(gossipsub::Event::GossipsubNotSupported { peer_id: peer });
        let mut behaviour = IgnoreAll::with_inner(inner);
        let events = drain(&mut behaviour);
        assert!(matches!(
            events[..],
            [
                IgnoreAllEvent::Gossipsub(gossipsub::Event::Subscribed { .. }),
                IgnoreAllEvent::Gossipsub(gossipsub::Event::GossipsubNotSupported { .. })
            ]
        ));
        assert!(behaviour.gossipsub().reports.is_empty());
        assert_eq!(behaviour.ignored(), 0);
    }

    #[test]
    fn a_message_gone_from_the_cache_is_still_counted_and_flagged() {
        let peer = PeerId::random();
        let mut inner = Scripted::default();
        inner.events.push_back(message(7, peer));
        let mut behaviour = IgnoreAll::with_inner(inner);
        let events = drain(&mut behaviour);
        assert!(matches!(
            events[..],
            [IgnoreAllEvent::Ignored {
                in_cache: false,
                ..
            }]
        ));
        assert_eq!(behaviour.ignored(), 1);
    }

    #[test]
    fn the_tap_gets_each_message_and_drops_when_full() {
        let peer = PeerId::random();
        let mut inner = Scripted {
            cached: true,
            ..Default::default()
        };
        for i in 0..4 {
            inner.events.push_back(message(i, peer));
        }
        let (tap, reader) = capture_tap(2);
        let before = SystemTime::now();
        let mut behaviour = IgnoreAll::with_inner(inner).with_tap(tap.clone());
        assert_eq!(drain(&mut behaviour).len(), 4);
        let first = reader.try_next().unwrap();
        assert_eq!(first.topic, TOPIC);
        assert_eq!(first.message_id, vec![0]);
        assert_eq!(first.source, peer);
        assert_eq!(first.data, vec![0; 3]);
        assert!(first.recv_wall >= before);
        assert_eq!(reader.try_next().unwrap().message_id, vec![1]);
        assert!(reader.try_next().is_none());
        assert_eq!((reader.dropped(), tap.dropped()), (2, 2));
        // Every message was reported, captured or not.
        assert_eq!(behaviour.gossipsub().reports.len(), 4);
        // A reader that is gone counts as full.
        drop(reader);
        assert!(!tap.offer(first));
        assert_eq!(tap.dropped(), 3);
    }

    #[test]
    fn swarm_events_reach_the_inner_behaviour() {
        let mut behaviour = IgnoreAll::with_inner(Scripted::default());
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        let id = ConnectionId::new_unchecked(1);
        assert!(behaviour
            .handle_pending_inbound_connection(id, &addr, &addr)
            .is_ok());
        assert!(behaviour
            .handle_pending_outbound_connection(id, None, &[], Endpoint::Dialer)
            .unwrap()
            .is_empty());
        assert!(behaviour
            .handle_established_inbound_connection(id, PeerId::random(), &addr, &addr)
            .is_ok());
        assert!(behaviour
            .handle_established_outbound_connection(
                id,
                PeerId::random(),
                &addr,
                Endpoint::Dialer,
                PortUse::New
            )
            .is_ok());
        behaviour.on_swarm_event(FromSwarm::NewListenAddr(libp2p::swarm::NewListenAddr {
            listener_id: libp2p::core::transport::ListenerId::next(),
            addr: &addr,
        }));
        assert_eq!(behaviour.gossipsub().swarm_events, 1);
    }
}
