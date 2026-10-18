//! Req/resp limits beyond the wire format: how fast a peer is answered, how many requests we
//! have open, and what happens to work that does not fit.
//!
//! - [`RateLimiter`]: one token bucket per (peer, protocol), counted in response chunks. A peer
//!   over its [`Quota`] is not answered with an error and its stream is not closed: each chunk
//!   is withheld until its own token is free and then sent whole (`phase0/p2p-interface.md`
//!   L1269–1274, "The responder MAY rate-limit chunks by withholding each chunk until capacity
//!   is available. The responder MUST NOT respond with an error or close the stream when rate
//!   limiting."). The bucket is GCRA, so the limiter only answers *when* a chunk may go.
//! - [`ChunkPacer`]: the inbound codec's handle on one peer's bucket of one protocol. Each chunk
//!   reserves its token when it is next to be written ([`ChunkPacer::reserve`]), so a chunk
//!   waits for the chunks before it, never for the ones after it, and concurrent answers share
//!   the bucket chunk by chunk. A reservation dropped before its chunk was sent (the stream or
//!   the connection went away) gives its period back ([`RateLimiter::refund`]); a sent chunk
//!   stays charged, so reconnecting does not refill a bucket.
//! - [`OutboundSemaphore`]: at most [`MAX_CONCURRENT_REQUESTS`] outbound requests per protocol
//!   ID across the probe (`phase0` L309, L1228: "The requester MUST NOT make more than
//!   `MAX_CONCURRENT_REQUESTS` concurrent requests with the same protocol ID"). A request over
//!   it waits in that protocol's bounded queue; a full queue IGNOREs it.
//! - [`ignore_queue`]: a bounded `tokio::sync::mpsc` queue fed with `try_send`. Overload never
//!   blocks the swarm and never ACCEPTs: an item that does not fit is IGNOREd (dropped) and
//!   counted in `queue_dropped_total{queue}`.
//!
//! The inbound concurrent-stream cap is `request_response`'s own: each protocol's inbound
//! behaviour serves at most [`MAX_CONCURRENT_REQUESTS`] streams per connection and resets the
//! next one ([`super::inbound::Duplex`]), and a peer holds one connection.

use super::metrics::RpcMetrics;
use super::MAX_CONCURRENT_REQUESTS;
use libp2p::PeerId;
use p2p_wire::rpc::protocols::Protocol;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// A token bucket: `burst` chunks at once, then one every `period`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Chunks that may go out back to back: at least 1.
    pub burst: u32,
    /// How long one token takes to come back.
    pub period: Duration,
}

impl Quota {
    /// `burst` chunks at once (0 counts as 1), then one per `period`.
    #[must_use]
    pub const fn new(burst: u32, period: Duration) -> Self {
        Self {
            burst: if burst == 0 { 1 } else { burst },
            period,
        }
    }

    /// How far ahead of its bucket a peer may run: `burst - 1` periods.
    fn tolerance(self) -> Duration {
        self.period.saturating_mul(self.burst.saturating_sub(1))
    }
}

/// The response-chunk quota of each protocol, per peer \[est\].
///
/// Every period is at most 2 s, and a chunk reserves its token only when it is next to be
/// written, so with [`MAX_CONCURRENT_REQUESTS`] answers open no chunk waits more than two
/// periods: under 5 s, the requester's first-byte and per-chunk deadline (ours, and the common
/// client default). A peer within the request limit is slowed down, never timed out. Two full
/// `BeaconBlocksByRange` answers from an empty bucket take 256 periods, about 5 s, inside the
/// 10 s an exchange may take. `Goodbye` has no response chunk and no quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// `Status`: 5 at once, then one per 2 s.
    pub status: Quota,
    /// `MetaData`: 2 at once, then one per 2 s.
    pub metadata: Quota,
    /// `Ping`: 2 at once, then one per 2 s.
    pub ping: Quota,
    /// `BeaconBlocksByRange`, in blocks: 128 at once, then one per 20 ms (50 a second).
    pub blocks_by_range: Quota,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            status: Quota::new(5, Duration::from_secs(2)),
            metadata: Quota::new(2, Duration::from_secs(2)),
            ping: Quota::new(2, Duration::from_secs(2)),
            blocks_by_range: Quota::new(128, Duration::from_millis(20)),
        }
    }
}

impl RateLimits {
    /// The quota of `protocol`; `None` for one without response chunks (`Goodbye`).
    #[must_use]
    pub fn quota(&self, protocol: Protocol) -> Option<Quota> {
        match protocol {
            Protocol::StatusV2 => Some(self.status),
            Protocol::MetaDataV3 => Some(self.metadata),
            Protocol::PingV1 => Some(self.ping),
            Protocol::BlocksByRangeV2 => Some(self.blocks_by_range),
            Protocol::GoodbyeV1 => None,
        }
    }
}

/// The wait queue each protocol's outbound requests get by default \[est\]: room for a Status
/// to every peer of a full swarm (160 connections) with headroom.
pub const DEFAULT_OUTBOUND_QUEUE_LEN: usize = 256;

/// The req/resp limits [`super::inbound::Control`] runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcLimits {
    /// The response-chunk quota per (peer, protocol).
    pub rate: RateLimits,
    /// Outbound requests of one protocol that wait for a free slot; more are IGNOREd.
    pub outbound_queue_len: usize,
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            rate: RateLimits::default(),
            outbound_queue_len: DEFAULT_OUTBOUND_QUEUE_LEN,
        }
    }
}

/// Every peer's token buckets, one per protocol (see the module docs).
///
/// Each bucket is the theoretical arrival time of its next chunk (GCRA): a chunk may go once
/// `now` is no more than `burst - 1` periods before it, and every chunk moves it one period on.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    limits: RateLimits,
    next: HashMap<(PeerId, Protocol), Instant>,
}

impl RateLimiter {
    /// Buckets under `limits`, all full.
    #[must_use]
    pub fn new(limits: RateLimits) -> Self {
        Self {
            limits,
            next: HashMap::new(),
        }
    }

    /// When the next response chunk of `protocol` to `peer` may be sent: `now` while the peer
    /// is within its quota, else the instant its token comes back. The chunk is charged either
    /// way, so chunks are scheduled one period apart in the order they were asked for.
    pub fn schedule(&mut self, peer: PeerId, protocol: Protocol, now: Instant) -> Instant {
        let Some(quota) = self.limits.quota(protocol) else {
            return now;
        };
        let next = self.next.entry((peer, protocol)).or_insert(now);
        let due = (*next).max(now);
        *next = due + quota.period;
        due.checked_sub(quota.tolerance())
            .map_or(now, |at| at.max(now))
    }

    /// Gives back the period of one chunk of `protocol` to `peer` that was scheduled but never
    /// sent. The bucket never moves before `now`, so refunds cannot build a burst.
    pub fn refund(&mut self, peer: PeerId, protocol: Protocol, now: Instant) {
        let Some(quota) = self.limits.quota(protocol) else {
            return;
        };
        if let Some(next) = self.next.get_mut(&(peer, protocol)) {
            *next = next
                .checked_sub(quota.period)
                .map_or(now, |back| back.max(now));
        }
    }

    /// Forgets the buckets of every peer `connected` rejects that are full again, so a peer
    /// that leaves stops taking memory but cannot reconnect out of a bucket still in debt.
    pub fn prune(&mut self, now: Instant, connected: impl Fn(&PeerId) -> bool) {
        self.next
            .retain(|(peer, _), next| connected(peer) || *next > now);
    }

    /// How many buckets are held.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.next.len()
    }
}

/// A [`RateLimiter`] shared by the behaviour and the inbound streams' writers.
pub type SharedLimiter = Arc<Mutex<RateLimiter>>;

/// A [`SharedLimiter`] under `limits`.
#[must_use]
pub fn shared_limiter(limits: RateLimits) -> SharedLimiter {
    Arc::new(Mutex::new(RateLimiter::new(limits)))
}

fn lock(limiter: &SharedLimiter) -> std::sync::MutexGuard<'_, RateLimiter> {
    limiter.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One peer's bucket of one protocol, for the writer of an answer (see the module docs).
/// Cheap to clone: every clone is the same bucket.
#[derive(Clone)]
pub struct ChunkPacer(Arc<Pacer>);

struct Pacer {
    limiter: SharedLimiter,
    peer: PeerId,
    protocol: Protocol,
    metrics: Option<RpcMetrics>,
}

impl fmt::Debug for ChunkPacer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkPacer")
            .field("peer", &self.0.peer)
            .field("protocol", &self.0.protocol)
            .finish_non_exhaustive()
    }
}

impl ChunkPacer {
    /// The pacer of `peer`'s `protocol` bucket in `limiter`, counting every withheld chunk in
    /// `rpc_rate_limited_total{protocol}` if `metrics` is given.
    #[must_use]
    pub fn new(
        limiter: SharedLimiter,
        peer: PeerId,
        protocol: Protocol,
        metrics: Option<RpcMetrics>,
    ) -> Self {
        Self(Arc::new(Pacer {
            limiter,
            peer,
            protocol,
            metrics,
        }))
    }

    /// Charges the token of the next chunk: the chunk may be written at [`Reservation::due`].
    /// Call [`Reservation::sent`] once it was; a reservation dropped before is refunded.
    #[must_use]
    pub fn reserve(&self) -> Reservation {
        let p = &self.0;
        let now = Instant::now();
        let due = lock(&p.limiter).schedule(p.peer, p.protocol, now);
        if due > now {
            if let Some(metrics) = &p.metrics {
                metrics.rate_limited(p.protocol);
            }
            tracing::debug!(
                peer = %p.peer,
                protocol = %p.protocol,
                wait_ms = (due - now).as_millis() as u64,
                "over quota: chunk withheld"
            );
        }
        Reservation {
            pacer: self.clone(),
            due,
            sent: false,
        }
    }
}

/// The token of one chunk ([`ChunkPacer::reserve`]): refunded on drop unless the chunk was sent.
#[derive(Debug)]
pub struct Reservation {
    pacer: ChunkPacer,
    due: Instant,
    sent: bool,
}

impl Reservation {
    /// When the chunk may be written.
    #[must_use]
    pub fn due(&self) -> Instant {
        self.due
    }

    /// The chunk was written: its token stays spent.
    pub fn sent(mut self) {
        self.sent = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.sent {
            let p = &self.pacer.0;
            lock(&p.limiter).refund(p.peer, p.protocol, Instant::now());
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct QueueLabel {
    queue: &'static str,
}

/// `queue_dropped_total{queue}`: items a bounded queue IGNOREd because it was full or its
/// consumer was gone. Registered once and shared by every queue.
#[derive(Clone, Debug)]
pub struct QueueMetrics {
    dropped: Family<QueueLabel, Counter>,
}

impl QueueMetrics {
    /// Creates `queue_dropped_total` and registers it in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self {
            dropped: Family::default(),
        };
        registry.register(
            "queue_dropped",
            "Items a bounded queue ignored because it was full or its consumer was gone",
            metrics.dropped.clone(),
        );
        metrics
    }

    /// Creates the `queue` label at 0, so the series exists before the first drop.
    pub fn declare(&self, queue: &'static str) {
        drop(self.dropped.get_or_create(&QueueLabel { queue }));
    }

    fn count(&self, queue: &'static str) {
        self.dropped.get_or_create(&QueueLabel { queue }).inc();
    }

    /// The current `queue_dropped_total{queue}`.
    #[must_use]
    pub fn dropped(&self, queue: &'static str) -> u64 {
        self.dropped.get_or_create(&QueueLabel { queue }).get()
    }
}

/// Why an item was IGNOREd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    /// The queue was at its capacity.
    Full,
    /// The consumer is gone.
    Closed,
}

/// An item a queue did not take, handed back to the producer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignored<T> {
    /// The item.
    pub item: T,
    /// Why.
    pub reason: IgnoreReason,
}

/// The producer half of a bounded IGNORE queue ([`ignore_queue`]).
#[derive(Debug)]
pub struct IgnoreQueue<T> {
    name: &'static str,
    tx: mpsc::Sender<T>,
    metrics: QueueMetrics,
}

/// A bounded queue named `name` holding at most `capacity` items (0 counts as 1), whose
/// producer never waits: what does not fit is IGNOREd and counted in
/// `queue_dropped_total{queue = name}`.
pub fn ignore_queue<T>(
    name: &'static str,
    capacity: usize,
    metrics: QueueMetrics,
) -> (IgnoreQueue<T>, mpsc::Receiver<T>) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    metrics.declare(name);
    (IgnoreQueue { name, tx, metrics }, rx)
}

impl<T> IgnoreQueue<T> {
    /// Queues `item` if there is room (`try_send`); else IGNOREs it, counts it and hands it
    /// back.
    ///
    /// # Errors
    ///
    /// [`Ignored`] with the item if the queue is full or its consumer is gone.
    pub fn offer(&self, item: T) -> Result<(), Ignored<T>> {
        let ignored = match self.tx.try_send(item) {
            Ok(()) => return Ok(()),
            Err(mpsc::error::TrySendError::Full(item)) => Ignored {
                item,
                reason: IgnoreReason::Full,
            },
            Err(mpsc::error::TrySendError::Closed(item)) => Ignored {
                item,
                reason: IgnoreReason::Closed,
            },
        };
        self.metrics.count(self.name);
        tracing::debug!(queue = self.name, reason = ?ignored.reason, "queue full: ignored");
        Err(ignored)
    }

    /// The queue's `queue` label.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

/// The `queue` label of `protocol`'s outbound wait queue.
#[must_use]
pub fn outbound_queue_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::StatusV2 => "rpc_outbound_status",
        Protocol::MetaDataV3 => "rpc_outbound_metadata",
        Protocol::PingV1 => "rpc_outbound_ping",
        Protocol::BlocksByRangeV2 => "rpc_outbound_blocks_by_range",
        Protocol::GoodbyeV1 => "rpc_outbound_goodbye",
    }
}

/// What [`OutboundSemaphore::submit`] did with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admit<T> {
    /// A slot was free and is now the request's: send it.
    Start(T),
    /// Every slot is taken: the request waits in its protocol's queue.
    Queued,
    /// The protocol's queue is full: the request is IGNOREd, handed back.
    Ignored(T),
}

/// One protocol's slots and wait queue.
#[derive(Debug)]
struct Lane<T> {
    in_flight: usize,
    queue: IgnoreQueue<T>,
    waiting: mpsc::Receiver<T>,
}

/// At most [`MAX_CONCURRENT_REQUESTS`] requests in flight per protocol, the rest waiting in a
/// bounded queue per protocol (see the module docs). Sans-IO: the owner sends what it is handed
/// and reports each request that finished ([`OutboundSemaphore::release`]).
#[derive(Debug)]
pub struct OutboundSemaphore<T> {
    queue_len: usize,
    metrics: QueueMetrics,
    lanes: HashMap<Protocol, Lane<T>>,
}

impl<T> OutboundSemaphore<T> {
    /// Slots for every protocol, each with a wait queue of `queue_len` requests.
    #[must_use]
    pub fn new(queue_len: usize, metrics: QueueMetrics) -> Self {
        Self {
            queue_len,
            metrics,
            lanes: HashMap::new(),
        }
    }

    fn lane(&mut self, protocol: Protocol) -> &mut Lane<T> {
        self.lanes.entry(protocol).or_insert_with(|| {
            let (queue, waiting) = ignore_queue(
                outbound_queue_name(protocol),
                self.queue_len,
                self.metrics.clone(),
            );
            Lane {
                in_flight: 0,
                queue,
                waiting,
            }
        })
    }

    /// Takes a slot of `protocol` for `request`, or queues it, or IGNOREs it.
    pub fn submit(&mut self, protocol: Protocol, request: T) -> Admit<T> {
        let lane = self.lane(protocol);
        if lane.in_flight < MAX_CONCURRENT_REQUESTS {
            lane.in_flight += 1;
            return Admit::Start(request);
        }
        match lane.queue.offer(request) {
            Ok(()) => Admit::Queued,
            Err(Ignored { item, .. }) => Admit::Ignored(item),
        }
    }

    /// A request of `protocol` finished: its slot goes to the oldest waiting request, which is
    /// returned to be sent, or is freed.
    pub fn release(&mut self, protocol: Protocol) -> Option<T> {
        let lane = self.lanes.get_mut(&protocol)?;
        if lane.in_flight == 0 {
            return None;
        }
        match lane.waiting.try_recv() {
            Ok(next) => Some(next),
            Err(_) => {
                lane.in_flight -= 1;
                None
            }
        }
    }

    /// Requests of `protocol` in flight.
    #[must_use]
    pub fn in_flight(&self, protocol: Protocol) -> usize {
        self.lanes.get(&protocol).map_or(0, |lane| lane.in_flight)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::registry::Registry;

    fn at(start: Instant, ms: u64) -> Instant {
        start + Duration::from_millis(ms)
    }

    #[test]
    fn a_burst_goes_out_at_once_then_one_chunk_per_period() {
        let start = Instant::now();
        let quota = Quota::new(2, Duration::from_secs(1));
        let mut limiter = RateLimiter::new(RateLimits {
            ping: quota,
            ..RateLimits::default()
        });
        let peer = PeerId::random();
        let ping = Protocol::PingV1;
        // Two tokens: both chunks now.
        assert_eq!(limiter.schedule(peer, ping, start), start);
        assert_eq!(limiter.schedule(peer, ping, start), start);
        // The third waits for the first token to come back, the fourth for the second.
        assert_eq!(limiter.schedule(peer, ping, start), at(start, 1000));
        assert_eq!(limiter.schedule(peer, ping, start), at(start, 2000));
        // Another peer and another protocol have their own buckets.
        assert_eq!(limiter.schedule(PeerId::random(), ping, start), start);
        assert_eq!(limiter.schedule(peer, Protocol::StatusV2, start), start);
        // Once idle long enough the bucket is full again.
        let later = at(start, 10_000);
        assert_eq!(limiter.schedule(peer, ping, later), later);
        assert_eq!(limiter.schedule(peer, ping, later), later);
        assert_eq!(limiter.schedule(peer, ping, later), at(later, 1000));
    }

    #[test]
    fn a_refund_gives_one_period_back_never_before_now() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(RateLimits {
            ping: Quota::new(1, Duration::from_secs(1)),
            ..RateLimits::default()
        });
        let peer = PeerId::random();
        let ping = Protocol::PingV1;
        assert_eq!(limiter.schedule(peer, ping, start), start);
        assert_eq!(limiter.schedule(peer, ping, start), at(start, 1000));
        // The second chunk was never sent: its period comes back.
        limiter.refund(peer, ping, start);
        assert_eq!(limiter.schedule(peer, ping, start), at(start, 1000));
        // Refunds never move a bucket before now, so they cannot buy a burst.
        for _ in 0..5 {
            limiter.refund(peer, ping, at(start, 500));
        }
        assert_eq!(limiter.schedule(peer, ping, at(start, 500)), at(start, 500));
        assert_eq!(
            limiter.schedule(peer, ping, at(start, 500)),
            at(start, 1500)
        );
        // Nothing to refund: no bucket, or no quota.
        limiter.refund(PeerId::random(), ping, start);
        limiter.refund(peer, Protocol::GoodbyeV1, start);
        assert_eq!(limiter.tracked(), 1);
    }

    #[test]
    fn goodbye_has_no_chunk_to_withhold() {
        let mut limiter = RateLimiter::new(RateLimits::default());
        let now = Instant::now();
        let peer = PeerId::random();
        for _ in 0..100 {
            assert_eq!(limiter.schedule(peer, Protocol::GoodbyeV1, now), now);
        }
        assert_eq!(limiter.tracked(), 0);
        assert_eq!(RateLimits::default().quota(Protocol::GoodbyeV1), None);
    }

    #[test]
    fn a_zero_burst_still_lets_one_chunk_through() {
        let quota = Quota::new(0, Duration::from_secs(1));
        assert_eq!(quota.burst, 1);
        let mut limiter = RateLimiter::new(RateLimits {
            status: quota,
            ..RateLimits::default()
        });
        let now = Instant::now();
        let peer = PeerId::random();
        assert_eq!(limiter.schedule(peer, Protocol::StatusV2, now), now);
        assert_eq!(
            limiter.schedule(peer, Protocol::StatusV2, now),
            at(now, 1000)
        );
    }

    #[test]
    fn prune_keeps_connected_peers_and_peers_still_in_debt() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(RateLimits {
            ping: Quota::new(1, Duration::from_secs(1)),
            ..RateLimits::default()
        });
        let (connected, gone, in_debt) = (PeerId::random(), PeerId::random(), PeerId::random());
        for peer in [connected, gone, in_debt] {
            limiter.schedule(peer, Protocol::PingV1, start);
        }
        limiter.schedule(in_debt, Protocol::PingV1, at(start, 1500));
        limiter.prune(at(start, 1500), |p| *p == connected);
        assert_eq!(
            limiter.tracked(),
            2,
            "the gone peer's full bucket is dropped"
        );
        // A reconnect does not reset a bucket still in debt.
        assert_eq!(
            limiter.schedule(in_debt, Protocol::PingV1, at(start, 1500)),
            at(start, 2500)
        );
    }

    #[test]
    fn default_quotas_withhold_no_chunk_past_the_requesters_first_byte_deadline() {
        // At most MAX_CONCURRENT_REQUESTS requests of a protocol are open per peer, so a chunk
        // waits at most that many periods: always under the 5 s first-byte deadline.
        let ttfb = crate::rpc::codec::Deadlines::default().ttfb;
        let limits = RateLimits::default();
        for protocol in Protocol::ALL {
            if let Some(q) = limits.quota(protocol) {
                assert!(q.burst >= 1, "{protocol}");
                let wait = q.period * MAX_CONCURRENT_REQUESTS as u32;
                assert!(wait < ttfb, "{protocol}: {wait:?}");
                assert!(wait < crate::rpc::REQUEST_TIMEOUT, "{protocol}");
            }
        }
        assert!(limits.status.burst >= 2);
        // Two full block answers from an empty bucket fit well inside one exchange.
        let blocks = limits.blocks_by_range.period
            * (MAX_CONCURRENT_REQUESTS as u32
                * p2p_wire::rpc::protocols::MAX_REQUEST_BLOCKS_DENEB as u32);
        assert!(blocks < crate::rpc::REQUEST_TIMEOUT, "{blocks:?}");
    }

    #[test]
    fn a_full_queue_ignores_and_counts() {
        let mut registry = Registry::default();
        let metrics = QueueMetrics::register(&mut registry);
        let (queue, mut rx) = ignore_queue::<u32>("test", 2, metrics.clone());
        assert_eq!(queue.offer(1), Ok(()));
        assert_eq!(queue.offer(2), Ok(()));
        assert_eq!(
            queue.offer(3),
            Err(Ignored {
                item: 3,
                reason: IgnoreReason::Full
            })
        );
        assert_eq!(metrics.dropped("test"), 1);
        assert_eq!(rx.try_recv(), Ok(1));
        assert_eq!(queue.offer(4), Ok(()));
        assert_eq!(queue.name(), "test");
        // A consumer that went away: everything is ignored, never queued.
        drop(rx);
        assert_eq!(
            queue.offer(5),
            Err(Ignored {
                item: 5,
                reason: IgnoreReason::Closed
            })
        );
        assert_eq!(metrics.dropped("test"), 2);
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
        assert!(
            text.contains("queue_dropped_total{queue=\"test\"} 2"),
            "{text}"
        );
        // A zero capacity is one: tokio refuses an empty channel.
        let (one, _rx) = ignore_queue::<u8>("one", 0, metrics);
        assert_eq!(one.offer(1), Ok(()));
        assert!(one.offer(2).is_err());
    }

    fn semaphore(queue_len: usize) -> (OutboundSemaphore<u32>, QueueMetrics) {
        let metrics = QueueMetrics::register(&mut Registry::default());
        (OutboundSemaphore::new(queue_len, metrics.clone()), metrics)
    }

    #[test]
    fn a_third_request_waits_for_a_free_slot() {
        let (mut sem, _) = semaphore(8);
        let p = Protocol::StatusV2;
        assert_eq!(sem.submit(p, 1), Admit::Start(1));
        assert_eq!(sem.submit(p, 2), Admit::Start(2));
        assert_eq!(sem.submit(p, 3), Admit::Queued);
        assert_eq!(sem.submit(p, 4), Admit::Queued);
        // Another protocol has its own two slots.
        assert_eq!(sem.submit(Protocol::PingV1, 9), Admit::Start(9));
        assert_eq!(sem.in_flight(p), 2);
        // A finished request hands its slot to the oldest waiting one.
        assert_eq!(sem.release(p), Some(3));
        assert_eq!(sem.in_flight(p), 2);
        assert_eq!(sem.release(p), Some(4));
        assert_eq!(sem.release(p), None);
        assert_eq!(sem.in_flight(p), 1);
        assert_eq!(sem.release(p), None);
        assert_eq!(sem.in_flight(p), 0);
        // A release with nothing in flight is a no-op.
        assert_eq!(sem.release(p), None);
        assert_eq!(sem.in_flight(p), 0);
    }

    #[test]
    fn a_full_wait_queue_ignores_the_request() {
        let (mut sem, metrics) = semaphore(1);
        let p = Protocol::MetaDataV3;
        assert_eq!(sem.submit(p, 1), Admit::Start(1));
        assert_eq!(sem.submit(p, 2), Admit::Start(2));
        assert_eq!(sem.submit(p, 3), Admit::Queued);
        assert_eq!(sem.submit(p, 4), Admit::Ignored(4));
        assert_eq!(metrics.dropped(outbound_queue_name(p)), 1);
        assert_eq!(outbound_queue_name(p), "rpc_outbound_metadata");
        assert_eq!(sem.in_flight(p), 2);
    }
}
