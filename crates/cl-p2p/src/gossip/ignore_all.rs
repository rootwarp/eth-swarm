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
//! that drops (and counts) when the reader is behind, so capture never slows the swarm. A tap
//! can keep only some topics ([`CaptureTap::keeping`]): the others never enter its queue, so
//! the queue holds at most its capacity of messages of those topics. A topic that is not in the
//! subscribed set, as after its fork digest retired ([`IgnoreAll::retire_digest`]), never
//! reaches the tap either.

use super::config::{digest_of, topic_hash};
use super::{GossipConfig, GossipError, TopicSet};
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
use p2p_wire::gossip::GossipTopic;
use p2p_wire::rpc::messages::ForkDigest;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

/// The probe's gossipsub: the bounded snappy transform, and peers' subscriptions held only for
/// the whitelist (our topics and the column subnets of their fork digests).
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
    dropped: Counter,
    /// The topics the tap keeps; `None` keeps every topic.
    keep: Option<fn(&str) -> bool>,
}

/// The reading side of a capture queue.
#[derive(Debug)]
pub struct CaptureReader {
    rx: Receiver<Captured>,
    dropped: Counter,
}

/// A capture queue holding at most `capacity` messages (at least one).
pub fn capture_tap(capacity: usize) -> (CaptureTap, CaptureReader) {
    capture_tap_counted(capacity, Counter::default())
}

/// [`capture_tap`], its drops counted on `dropped` (a metric's counter, which it shares).
pub fn capture_tap_counted(capacity: usize, dropped: Counter) -> (CaptureTap, CaptureReader) {
    let (tx, rx) = mpsc::sync_channel(capacity.max(1));
    (
        CaptureTap {
            tx,
            dropped: dropped.clone(),
            keep: None,
        },
        CaptureReader { rx, dropped },
    )
}

impl CaptureTap {
    /// The same tap, keeping only the messages whose full topic string `keep` accepts. The
    /// others never enter the queue, and they are no drop.
    #[must_use]
    pub fn keeping(mut self, keep: fn(&str) -> bool) -> Self {
        self.keep = Some(keep);
        self
    }

    /// Whether the tap keeps messages of `topic`.
    #[must_use]
    pub fn wants(&self, topic: &str) -> bool {
        self.keep.is_none_or(|keep| keep(topic))
    }

    /// Queues `captured`, or drops and counts it if the queue is full or its reader is gone.
    pub fn offer(&self, captured: Captured) -> bool {
        match self.tx.try_send(captured) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.inc();
                false
            }
        }
    }

    /// Messages dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.get()
    }
}

impl CaptureReader {
    /// The next queued message, if any, without waiting.
    pub fn try_next(&self) -> Option<Captured> {
        self.rx.try_recv().ok()
    }

    /// The next message: waits for one, and blocks the thread while it waits. `None` once the
    /// queue is empty and every [`CaptureTap`] of it is gone (the swarm was dropped).
    pub fn recv(&self) -> Option<Captured> {
        self.rx.recv().ok()
    }

    /// Messages the tap dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.get()
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
    /// Our subscribed topics: the set gossipsub's transform reads.
    topics: TopicSet,
    /// The whitelist gossipsub's subscription filter reads: a superset of `topics`.
    whitelist: TopicSet,
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
        let topics = cfg.topic_set()?;
        let whitelist = cfg.whitelist()?;
        let mut gossipsub = gossipsub::Behaviour::new_with_subscription_filter_and_transform(
            MessageAuthenticity::Anonymous,
            cfg.gossipsub()?,
            cfg.subscription_filter(&whitelist),
            cfg.transform(&topics),
        )
        .map_err(GossipError::Behaviour)?
        .with_metrics(registry, super::config::metrics_config());
        for topic in &cfg.topics {
            gossipsub.subscribe(&gossipsub::IdentTopic::new(topic.to_string()))?;
        }
        let mut ignore_all = Self::with_inner(gossipsub);
        ignore_all.topics = topics;
        ignore_all.whitelist = whitelist;
        Ok(ignore_all)
    }

    /// Subscribes `topics` on top of the ones subscribed so far (the custody column subnets
    /// cl-chain asks for, [`crate::custody`]); returns how many were not subscribed yet.
    ///
    /// They join the whitelist and then the subscribed [`TopicSet`] first, so the transform
    /// decodes their messages from the moment gossipsub announces them; IGNORE-all applies to
    /// them like to every topic. gossipsub keeps a peer's subscription only to a whitelisted
    /// topic, and meshes (by our GRAFT or the peer's) only with a peer it holds subscribed. The
    /// whitelist holds every column subnet of the configured fork digests from the start
    /// ([`GossipConfig::whitelist`]), so peers that announced one before we subscribe it join
    /// its mesh on the same connection. A topic outside the whitelist until now (a column
    /// subnet under another fork digest) has its peers' subscriptions kept only from here on:
    /// a peer that announced it earlier joins the mesh only once it reconnects.
    ///
    /// # Errors
    ///
    /// [`GossipError::TooManyTopics`] if the whitelist would pass
    /// [`super::config::MAX_TOPICS`]; nothing is subscribed then. [`GossipError::Subscribe`]
    /// from gossipsub.
    pub fn subscribe(&mut self, topics: &[GossipTopic]) -> Result<usize, GossipError> {
        let hashes: Vec<TopicHash> = topics.iter().map(topic_hash).collect();
        // The subscribed set stays within the whitelist, so it cannot pass the bound once the
        // whitelist has taken the topics.
        self.whitelist.extend(&hashes)?;
        self.topics.extend(&hashes)?;
        let mut subscribed = 0;
        for topic in topics {
            if self
                .inner
                .subscribe(&gossipsub::IdentTopic::new(topic.to_string()))?
            {
                subscribed += 1;
            }
        }
        Ok(subscribed)
    }

    /// Retires the fork digest `digest`: unsubscribes every topic under it, and removes them
    /// from the subscribed set and from the whitelist (its whitelisted column subnets too), so
    /// the room takes the topics of later digests. Returns how many topics were unsubscribed.
    /// gossipsub tells our peers and leaves the meshes; the transform refuses the topics' late
    /// messages before decompression, as for any topic we do not subscribe.
    pub fn retire_digest(&mut self, digest: ForkDigest) -> usize {
        let ours: Vec<TopicHash> = self
            .inner
            .topics()
            .filter(|t| digest_of(t) == Some(digest))
            .cloned()
            .collect();
        let mut unsubscribed = 0;
        for topic in &ours {
            if self
                .inner
                .unsubscribe(&gossipsub::IdentTopic::new(topic.as_str()))
            {
                unsubscribed += 1;
            }
        }
        self.topics.remove_digest(digest);
        self.whitelist.remove_digest(digest);
        unsubscribed
    }
}

impl<G> IgnoreAll<G> {
    /// Ignore-all over `inner`. Private: only [`IgnoreAll::new`] builds the gossipsub it
    /// wraps, so manual validation cannot be left out.
    fn with_inner(inner: G) -> Self {
        Self {
            inner,
            topics: TopicSet::default(),
            whitelist: TopicSet::default(),
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

    /// The topics in the whitelist: at most [`super::config::MAX_TOPICS`].
    pub fn whitelist_len(&self) -> usize {
        self.whitelist.len()
    }

    /// The topics in the subscribed set, which the transform decodes.
    pub fn subscribed_len(&self) -> usize {
        self.topics.len()
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
        // Only a topic still subscribed (its digest live, not retired) reaches the tap.
        if let Some(tap) = self
            .tap
            .as_ref()
            .filter(|_| self.topics.contains(&message.topic))
        {
            let topic = message.topic.to_string();
            if tap.wants(&topic) {
                tap.offer(Captured {
                    recv_mono,
                    recv_wall,
                    topic,
                    message_id: message_id.0.clone(),
                    source,
                    data: message.data,
                });
            }
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
        let mut behaviour = live(IgnoreAll::with_inner(inner).with_tap(tap.clone()));
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

    /// `behaviour` with [`TOPIC`] in its subscribed set, as `IgnoreAll::new` subscribes a topic.
    fn live(behaviour: IgnoreAll<Scripted>) -> IgnoreAll<Scripted> {
        behaviour
            .topics
            .extend(&[TopicHash::from_raw(TOPIC)])
            .unwrap();
        behaviour
    }

    /// The tap follows the live digests: a message of a topic that is not (or no longer) in the
    /// subscribed set, as after its digest retired, is reported IGNORE and never tapped.
    #[test]
    fn the_tap_keeps_only_the_live_topics() {
        let peer = PeerId::random();
        let mut inner = Scripted {
            cached: true,
            ..Default::default()
        };
        inner.events.push_back(message(0, peer));
        let (tap, reader) = capture_tap(4);
        let mut behaviour = live(IgnoreAll::with_inner(inner).with_tap(tap));
        drain(&mut behaviour);
        assert_eq!(reader.try_next().unwrap().message_id, vec![0]);
        // The digest of TOPIC retires; a late message of it is not tapped.
        assert_eq!(behaviour.topics.remove_digest([0; 4]), 1);
        let mut inner = Scripted {
            cached: true,
            ..Default::default()
        };
        inner.events.push_back(message(1, peer));
        let mut late = IgnoreAll::with_inner(inner).with_tap(behaviour.tap.take().unwrap());
        late.topics = behaviour.topics.clone();
        assert_eq!(drain(&mut late).len(), 1, "still reported IGNORE");
        assert_eq!(late.gossipsub().reports.len(), 1);
        assert!(
            reader.try_next().is_none(),
            "a retired digest's message is not tapped"
        );
    }

    /// A tap that keeps only some topics gets nothing of the others, and its drops count on
    /// the counter it was given.
    #[test]
    fn a_filtered_tap_keeps_only_its_topics_and_counts_its_drops() {
        let peer = PeerId::random();
        let mut inner = Scripted {
            cached: true,
            ..Default::default()
        };
        for i in 0..3 {
            inner.events.push_back(message(i, peer));
        }
        let none = |_: &str| false;
        let (tap, reader) = capture_tap(4);
        let mut behaviour = live(IgnoreAll::with_inner(inner).with_tap(tap.keeping(none)));
        assert_eq!(
            drain(&mut behaviour).len(),
            3,
            "every message is still reported"
        );
        assert!(reader.try_next().is_none(), "no topic kept");
        assert_eq!(reader.dropped(), 0, "a topic not kept is no drop");
        let counter = Counter::default();
        let (tap, reader) = capture_tap_counted(1, counter.clone());
        let kept = tap.keeping(|topic| topic == TOPIC);
        assert!(kept.wants(TOPIC) && !kept.wants("/eth2/00000000/execution_payload/ssz_snappy"));
        let mut inner = Scripted {
            cached: true,
            ..Default::default()
        };
        inner.events.push_back(message(0, peer));
        inner.events.push_back(message(1, peer));
        let mut behaviour = live(IgnoreAll::with_inner(inner).with_tap(kept));
        drain(&mut behaviour);
        assert_eq!(reader.try_next().unwrap().message_id, vec![0]);
        assert_eq!((counter.get(), reader.dropped()), (1, 1));
    }

    /// `recv` waits for the next message, and ends once every tap is gone.
    #[test]
    fn recv_waits_for_a_message_and_ends_with_the_taps() {
        let (tap, reader) = capture_tap(2);
        let sender = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let captured = Captured {
                recv_mono: Instant::now(),
                recv_wall: SystemTime::now(),
                topic: TOPIC.into(),
                message_id: vec![7],
                source: PeerId::random(),
                data: vec![1],
            };
            assert!(tap.offer(captured));
        });
        assert_eq!(reader.recv().unwrap().message_id, vec![7]);
        sender.join().unwrap();
        assert!(reader.recv().is_none(), "the tap is gone");
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
