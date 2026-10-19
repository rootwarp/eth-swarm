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
//!   the bucket chunk by chunk. A reservation dropped before its chunk was written whole (the
//!   stream or the connection went away) gives back the part of its period still ahead
//!   ([`RateLimiter::refund`]), nothing once that period ran out; a chunk written whole stays
//!   charged, even if its flush failed, so reconnecting does not refill a bucket.
//! - [`OutboundSemaphore`]: at most [`MAX_CONCURRENT_REQUESTS`] outbound requests per protocol
//!   ID across the probe (`phase0` L309, L1228: "The requester MUST NOT make more than
//!   `MAX_CONCURRENT_REQUESTS` concurrent requests with the same protocol ID"). A request over
//!   it waits in that protocol's bounded queue; a full queue IGNOREs it.
//! - [`BookedChunks`]: a column answer's tokens, booked in one go when its request is admitted
//!   ([`RateLimiter::charge_block`]), so a peer pays for its request before any lookup runs and
//!   cannot reset its way out of the bill: once the answer's size is known the tokens it does not
//!   use are given back ([`BookedChunks::settle`]), never more, and a reset refunds nothing.
//! - [`ColumnPlaces`]: the column answers held at once, from the lookup until the stream's
//!   writer returns, at most one per peer ([`AnswerPermit`]).
//! - [`ignore_queue`]: a bounded `tokio::sync::mpsc` queue fed with `try_send`. Overload never
//!   blocks the swarm and never ACCEPTs: an item that does not fit is IGNOREd (dropped) and
//!   counted in `queue_dropped_total{queue}`.
//!
//! The inbound concurrent-stream cap is `request_response`'s own: each protocol's inbound
//! behaviour serves at most [`MAX_CONCURRENT_REQUESTS`] streams per connection and resets the
//! next one ([`super::inbound::Duplex`]), and a peer holds one connection.

use super::metrics::RpcMetrics;
use super::MAX_CONCURRENT_REQUESTS;
use crate::peer_caps::IpBucket;
use futures::task::AtomicWaker;
use libp2p::PeerId;
use p2p_wire::rpc::protocols::{Protocol, MAX_REQUEST_DATA_COLUMN_SIDECARS};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::collections::HashSet;
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
/// 10 s an exchange may take. The column protocols count sidecars, and an answer holds no more
/// than its quota delivers in [`COLUMN_ANSWER_WINDOW`] ([`RpcLimits::column_answer_sidecars`]:
/// 512 + 5 s / 5 ms = 1,512 by default), so a paced answer is never cut by the requester's
/// deadline. `Goodbye` has no quota: its one response chunk ends the connection.
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
    /// `DataColumnSidecarsByRange`, in sidecars: 512 at once, then one per 5 ms (200 a second).
    pub data_columns_by_range: Quota,
    /// `DataColumnSidecarsByRoot`, in sidecars: as by range.
    pub data_columns_by_root: Quota,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            status: Quota::new(5, Duration::from_secs(2)),
            metadata: Quota::new(2, Duration::from_secs(2)),
            ping: Quota::new(2, Duration::from_secs(2)),
            blocks_by_range: Quota::new(128, Duration::from_millis(20)),
            data_columns_by_range: Quota::new(512, Duration::from_millis(5)),
            data_columns_by_root: Quota::new(512, Duration::from_millis(5)),
        }
    }
}

impl RateLimits {
    /// The quota of `protocol`; `None` for `Goodbye`, whose one chunk ends the connection.
    #[must_use]
    pub fn quota(&self, protocol: Protocol) -> Option<Quota> {
        match protocol {
            Protocol::StatusV2 => Some(self.status),
            Protocol::MetaDataV3 => Some(self.metadata),
            Protocol::PingV1 => Some(self.ping),
            Protocol::BlocksByRangeV2 => Some(self.blocks_by_range),
            Protocol::GoodbyeV1 => None,
            Protocol::DataColumnsByRangeV1 => Some(self.data_columns_by_range),
            Protocol::DataColumnsByRootV1 => Some(self.data_columns_by_root),
        }
    }
}

/// The wait queue each protocol's outbound requests get by default \[est\]: room for a Status
/// to every peer of a full swarm (160 connections) with headroom.
pub const DEFAULT_OUTBOUND_QUEUE_LEN: usize = 256;

/// The SSZ bytes one column answer may hold: 8 MiB \[est\]. An answer is cut at the last whole
/// block that fits (the first block always goes, "Clients MAY limit the number of data column
/// sidecars in the response", `fulu/p2p-interface.md` L682), so one epoch of 4 custody columns
/// of 21-blob Gloas blocks (32 × 4 × 44,072 bytes, 5.4 MiB) fits whole.
pub const MAX_COLUMN_RESPONSE_BYTES: usize = 8 << 20;

/// How long a column answer's chunks may take to go out at the peer's quota \[est\]: 5 s, the
/// requester's 10 s total less the queue wait and the lookup (2 s each) and a second to spare.
pub const COLUMN_ANSWER_WINDOW: Duration = Duration::from_secs(5);

/// Column answers held at once, over every peer, from the lookup until the stream's writer
/// returns \[est\]. cl-chain runs as many reads at once (`cl_chain::reqresp::DEFAULT_MAX_READS`),
/// so no lookup is refused there as overloaded.
///
/// Memory, an estimate and not a bound (allocator overhead and freed-but-kept heap aside), per
/// held answer of at most [`MAX_COLUMN_RESPONSE_BYTES`] (8 MiB) of SSZ, with the network's caps
/// (a 21-blob Gloas sidecar is 44 KB):
///
/// - the chain.v1 client's copy of the answer's SSZ, then its decoded sidecars, which replace
///   it one sidecar at a time: about 8 MiB (the decoded form adds well under 1 % in headers),
///   plus tonic's receive buffer of the message being decoded (one sidecar) and the HTTP/2
///   window (64 KiB);
/// - the chunk being written: its re-encoded SSZ, its snappy frames and the chunk buffer,
///   three sidecars (about 130 KB);
/// - the stream's muxer send buffer, up to its window (yamux: 256 KiB).
///
/// About 8.5 MiB per answer, so 8 × 8.5 MiB ≈ 68 MiB in cl-p2p, and cl-chain holds up to
/// 8 reads × 8 MiB ≈ 64 MiB more while its answers are sent. With the preset's caps (no network
/// config) one sidecar may be up to 8.5 MB, and the per-chunk copies alone could reach
/// ≈ 25 MB per answer.
pub const DEFAULT_MAX_COLUMN_ANSWERS: usize = 8;

/// Column answers held at once by the peers of one IP (an IPv6 /58) \[est\]: 2, so one IP
/// with its 8 inbound connections (`ConnectionCaps::max_established_incoming_per_ip`) cannot
/// take all [`DEFAULT_MAX_COLUMN_ANSWERS`] places.
pub const DEFAULT_MAX_COLUMN_ANSWERS_PER_IP: usize = 2;

/// How long a due column chunk may take to be written \[est\]: 1 s. A requester that stopped
/// reading fills its stream's window and then holds the next chunk; past this its stream is
/// reset and the answer's place given back, so it cannot hold a place for the 10 s exchange
/// timeout. Counted in `rpc_timeouts_total{kind="per_chunk"}`.
pub const COLUMN_WRITE_DEADLINE: Duration = Duration::from_secs(1);

/// Column requests waiting for their tokens or a place, over every peer \[est\]: at most 64 × a
/// by-root request (136 KiB) held. Past it a request gets `2: ServerError`.
pub const DEFAULT_COLUMN_QUEUE_LEN: usize = 64;

/// How long an admitted column request waits for a place once its tokens are due \[est\]: 2 s,
/// so that with a 2 s lookup its first byte goes out before the requester's 5 s deadline. Past
/// it the request gets `2: ServerError`, counted.
pub const COLUMN_QUEUE_WAIT: Duration = Duration::from_secs(2);

/// The req/resp limits [`super::inbound::Control`] runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcLimits {
    /// The response-chunk quota per (peer, protocol).
    pub rate: RateLimits,
    /// Outbound requests of one protocol that wait for a free slot; more are IGNOREd.
    pub outbound_queue_len: usize,
    /// Column answers held at once, one per peer at most ([`ColumnPlaces`]).
    pub max_column_answers: usize,
    /// Column requests waiting at once; past it a request gets `2: ServerError` and counts in
    /// `queue_dropped_total{queue="rpc_column_queue"}`.
    pub column_queue_len: usize,
    /// How long a request whose tokens are due waits for a place before `2: ServerError`.
    pub column_queue_wait: Duration,
    /// How long an answer's chunks may take at the quota ([`Self::column_answer_sidecars`]).
    pub column_answer_window: Duration,
    /// The SSZ bytes one column answer may hold.
    pub max_column_response_bytes: usize,
    /// Column answers held at once by the peers of one IP (an IPv6 /58).
    pub max_column_answers_per_ip: usize,
    /// How long a due column chunk may take to be written before its stream is reset and its
    /// place given back.
    pub column_write_deadline: Duration,
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            rate: RateLimits::default(),
            outbound_queue_len: DEFAULT_OUTBOUND_QUEUE_LEN,
            max_column_answers: DEFAULT_MAX_COLUMN_ANSWERS,
            column_queue_len: DEFAULT_COLUMN_QUEUE_LEN,
            column_queue_wait: COLUMN_QUEUE_WAIT,
            column_answer_window: COLUMN_ANSWER_WINDOW,
            max_column_response_bytes: MAX_COLUMN_RESPONSE_BYTES,
            max_column_answers_per_ip: DEFAULT_MAX_COLUMN_ANSWERS_PER_IP,
            column_write_deadline: COLUMN_WRITE_DEADLINE,
        }
    }
}

impl RpcLimits {
    /// The most sidecars one answer of `protocol` holds: its share of what the quota delivers
    /// from a full bucket within [`Self::column_answer_window`], `burst + window / period`,
    /// split between the [`MAX_CONCURRENT_REQUESTS`] streams a peer may hold open, so two
    /// answers at once both go out within the window; at most
    /// `MAX_REQUEST_DATA_COLUMN_SIDECARS`. A booking also never takes more than the bucket
    /// still delivers in the window ([`RateLimiter::deliverable`]).
    #[must_use]
    pub fn column_answer_sidecars(&self, protocol: Protocol) -> u64 {
        let Some(quota) = self.rate.quota(protocol) else {
            return MAX_REQUEST_DATA_COLUMN_SIDECARS;
        };
        let paced = match quota.period.as_nanos() {
            0 => return MAX_REQUEST_DATA_COLUMN_SIDECARS,
            period => self.column_answer_window.as_nanos() / period,
        };
        let full = u64::from(quota.burst).saturating_add(u64::try_from(paced).unwrap_or(u64::MAX));
        (full / MAX_CONCURRENT_REQUESTS as u64).min(MAX_REQUEST_DATA_COLUMN_SIDECARS)
    }
}

/// Every peer's token buckets, one per protocol (see the module docs).
///
/// Each bucket is the theoretical arrival time of its next chunk (GCRA): a chunk may go once
/// `now` is no more than `burst - 1` periods before it, and every chunk moves it one period on.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    limits: RateLimits,
    buckets: HashMap<(PeerId, Protocol), Bucket>,
    created: u64,
}

/// One (peer, protocol) bucket.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// The theoretical arrival time of the next chunk.
    next: Instant,
    /// How far refunds have moved `next` back in all: no charge still held moved further.
    refunded: Duration,
    /// Which bucket this is, so a charge on a pruned bucket refunds nothing to its successor.
    id: u64,
}

/// `n` chunks' tokens booked at once ([`RateLimiter::charge_block`]): chunk `i` may go at
/// [`BlockCharge::due`] of `i`.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct BlockCharge {
    /// When the first token's period starts, and the earliest any chunk goes.
    start: Instant,
    /// The earliest any chunk goes: when the block was booked.
    booked_at: Instant,
    period: Duration,
    tolerance: Duration,
    /// Tokens still booked.
    n: u64,
    booked: Option<Booking>,
}

impl BlockCharge {
    /// When chunk `i` (0-based) may be sent, as booked.
    #[must_use]
    pub fn due(&self, i: u64) -> Instant {
        self.due_after(i, Duration::ZERO)
    }

    /// When chunk `i` may be sent once the bucket moved back `shift` since the booking (a
    /// refund of a booking before it): the whole booking moves up by that much, never to before
    /// it was booked.
    fn due_after(&self, i: u64, shift: Duration) -> Instant {
        let start = self
            .start
            .checked_sub(shift)
            .map_or(self.booked_at, |s| s.max(self.booked_at));
        let at = start
            + self
                .period
                .saturating_mul(u32::try_from(i).unwrap_or(u32::MAX));
        at.checked_sub(self.tolerance)
            .map_or(self.booked_at, |at| at.max(self.booked_at))
    }

    /// The tokens booked.
    #[must_use]
    pub fn tokens(&self) -> u64 {
        self.n
    }
}

/// One chunk's token, as [`RateLimiter::charge`] booked it: when the chunk may go and, for
/// [`RateLimiter::refund`], where its period sits in the bucket.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct Charge {
    due: Instant,
    booked: Option<Booking>,
}

/// Where a charged period sits: its bucket, the bucket's `next` right after the charge (the
/// end of the period) and the bucket's `refunded` then.
#[derive(Debug, PartialEq, Eq)]
struct Booking {
    bucket: u64,
    until: Instant,
    refunded: Duration,
}

impl Charge {
    /// When the chunk may be sent.
    #[must_use]
    pub fn due(&self) -> Instant {
        self.due
    }
}

impl RateLimiter {
    /// Buckets under `limits`, all full.
    #[must_use]
    pub fn new(limits: RateLimits) -> Self {
        Self {
            limits,
            buckets: HashMap::new(),
            created: 0,
        }
    }

    /// Charges the next response chunk of `protocol` to `peer`: it may be sent at
    /// [`Charge::due`], `now` while the peer is within its quota, else the instant its token
    /// comes back. The chunk is charged either way, so chunks are scheduled one period apart in
    /// the order they were asked for.
    pub fn charge(&mut self, peer: PeerId, protocol: Protocol, now: Instant) -> Charge {
        let Some(quota) = self.limits.quota(protocol) else {
            return Charge {
                due: now,
                booked: None,
            };
        };
        let created = &mut self.created;
        let bucket = self.buckets.entry((peer, protocol)).or_insert_with(|| {
            *created += 1;
            Bucket {
                next: now,
                refunded: Duration::ZERO,
                id: *created,
            }
        });
        let start = bucket.next.max(now);
        bucket.next = start + quota.period;
        Charge {
            due: start
                .checked_sub(quota.tolerance())
                .map_or(now, |at| at.max(now)),
            booked: Some(Booking {
                bucket: bucket.id,
                until: bucket.next,
                refunded: bucket.refunded,
            }),
        }
    }

    /// Charges `n` response chunks of `protocol` to `peer` at once, one period after the other
    /// from the bucket's next free period: what [`Self::charge`] `n` times does, in one step.
    pub fn charge_block(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        n: u64,
        now: Instant,
    ) -> BlockCharge {
        let Some(quota) = self.limits.quota(protocol) else {
            return BlockCharge {
                start: now,
                booked_at: now,
                period: Duration::ZERO,
                tolerance: Duration::ZERO,
                n,
                booked: None,
            };
        };
        let created = &mut self.created;
        let bucket = self.buckets.entry((peer, protocol)).or_insert_with(|| {
            *created += 1;
            Bucket {
                next: now,
                refunded: Duration::ZERO,
                id: *created,
            }
        });
        let start = bucket.next.max(now);
        let span = quota
            .period
            .saturating_mul(u32::try_from(n).unwrap_or(u32::MAX));
        bucket.next = start + span;
        BlockCharge {
            start,
            booked_at: now,
            period: quota.period,
            tolerance: quota.tolerance(),
            n,
            booked: Some(Booking {
                bucket: bucket.id,
                until: bucket.next,
                refunded: bucket.refunded,
            }),
        }
    }

    /// How many chunks of `protocol` the bucket of `peer` can still deliver from `now` within
    /// `window`: the chunks a booking now would have due by `now + window`.
    #[must_use]
    pub fn deliverable(
        &self,
        peer: PeerId,
        protocol: Protocol,
        window: Duration,
        now: Instant,
    ) -> u64 {
        let Some(quota) = self.limits.quota(protocol) else {
            return u64::MAX;
        };
        let start = self
            .buckets
            .get(&(peer, protocol))
            .map_or(now, |b| b.next.max(now));
        let horizon = now + window + quota.tolerance();
        let Some(span) = horizon.checked_duration_since(start) else {
            return 0;
        };
        match quota.period.as_nanos() {
            0 => u64::MAX,
            period => u64::try_from(span.as_nanos() / period)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        }
    }

    /// When chunk `i` of `charge` may be sent now: as booked, moved up by every refund of
    /// `peer`'s `protocol` bucket since the booking.
    #[must_use]
    pub fn due_of(
        &self,
        peer: PeerId,
        protocol: Protocol,
        charge: &BlockCharge,
        i: u64,
    ) -> Instant {
        let shift = charge
            .booked
            .as_ref()
            .and_then(|booked| {
                self.buckets
                    .get(&(peer, protocol))
                    .filter(|b| b.id == booked.bucket)
                    .map(|b| b.refunded.saturating_sub(booked.refunded))
            })
            .unwrap_or_default();
        charge.due_after(i, shift)
    }

    /// Gives back the last `unused` tokens of `charge`, as far as they are still ahead of
    /// `now` (see [`Self::refund`]); `charge` keeps the rest.
    pub fn refund_tail(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        charge: &mut BlockCharge,
        unused: u64,
        now: Instant,
    ) {
        let unused = unused.min(charge.n);
        if unused == 0 {
            return;
        }
        charge.n -= unused;
        let Some(booked) = &charge.booked else {
            return;
        };
        let back = charge
            .period
            .saturating_mul(u32::try_from(unused).unwrap_or(u32::MAX));
        self.give_back(peer, protocol, booked, back, now);
    }

    /// [`Self::charge`], for a chunk that is never refunded: when it may be sent.
    pub fn schedule(&mut self, peer: PeerId, protocol: Protocol, now: Instant) -> Instant {
        self.charge(peer, protocol, now).due
    }

    /// Gives back what is still ahead of `now` of the period `charge` booked for a chunk of
    /// `protocol` to `peer` that was never sent: at most one period, and nothing once the
    /// period ran out, since time since spent it and later chunks may hold the bucket now.
    ///
    /// A refund moves the bucket back, and with it at most that far every charge after the
    /// refunded one, so `until` less what was refunded since is never later than where the
    /// period really ends: a refund never gives back more than the live part of its charge.
    /// The bucket never moves before `now`, so refunds cannot build a burst.
    pub fn refund(&mut self, peer: PeerId, protocol: Protocol, charge: Charge, now: Instant) {
        let (Some(quota), Some(booked)) = (self.limits.quota(protocol), charge.booked) else {
            return;
        };
        self.give_back(peer, protocol, &booked, quota.period, now);
    }

    /// Moves `peer`'s `protocol` bucket back by what is still ahead of `now` of the last `most`
    /// of the span `booked` ends, at most `most`.
    fn give_back(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        booked: &Booking,
        most: Duration,
        now: Instant,
    ) {
        let Some(bucket) = self
            .buckets
            .get_mut(&(peer, protocol))
            .filter(|bucket| bucket.id == booked.bucket)
        else {
            return;
        };
        let moved_since = bucket.refunded.saturating_sub(booked.refunded);
        let live = booked
            .until
            .checked_sub(moved_since)
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
            .min(most);
        let back = bucket
            .next
            .checked_sub(live)
            .map_or(now, |back| back.max(now));
        if back < bucket.next {
            bucket.refunded = bucket.refunded.saturating_add(bucket.next - back);
            bucket.next = back;
        }
    }

    /// Forgets the buckets of every peer `connected` rejects that are full again, so a peer
    /// that leaves stops taking memory but cannot reconnect out of a bucket still in debt.
    pub fn prune(&mut self, now: Instant, connected: impl Fn(&PeerId) -> bool) {
        self.buckets
            .retain(|(peer, _), bucket| connected(peer) || bucket.next > now);
    }

    /// How many buckets are held.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
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
    /// Call [`Reservation::sent`] once it was written whole; a reservation dropped before gets
    /// back the part of its charge still ahead.
    #[must_use]
    pub fn reserve(&self) -> Reservation {
        let p = &self.0;
        let now = Instant::now();
        let charge = lock(&p.limiter).charge(p.peer, p.protocol, now);
        let due = charge.due();
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
            charge: Some(charge),
        }
    }
}

/// The token of one chunk ([`ChunkPacer::reserve`]): on drop, unless the chunk was sent, the
/// part of its charge still ahead is refunded ([`RateLimiter::refund`]).
#[derive(Debug)]
pub struct Reservation {
    pacer: ChunkPacer,
    due: Instant,
    /// `None` once the chunk was sent.
    charge: Option<Charge>,
}

impl Reservation {
    /// When the chunk may be written.
    #[must_use]
    pub fn due(&self) -> Instant {
        self.due
    }

    /// The chunk was written: its token stays spent.
    pub fn sent(mut self) {
        self.charge = None;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(charge) = self.charge.take() {
            let p = &self.pacer.0;
            lock(&p.limiter).refund(p.peer, p.protocol, charge, Instant::now());
        }
    }
}

/// One column answer's tokens, booked when its request was admitted (see the module docs).
/// Dropping it refunds nothing.
pub struct BookedChunks {
    limiter: SharedLimiter,
    peer: PeerId,
    protocol: Protocol,
    charge: BlockCharge,
    metrics: Option<RpcMetrics>,
    write_deadline: Duration,
}

impl fmt::Debug for BookedChunks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BookedChunks")
            .field("peer", &self.peer)
            .field("protocol", &self.protocol)
            .field("charge", &self.charge)
            .finish_non_exhaustive()
    }
}

impl BookedChunks {
    /// Books `n` chunks of `protocol` to `peer` in `limiter`, each to be written within
    /// `write_deadline` once due, counting every withheld chunk in
    /// `rpc_rate_limited_total{protocol}` if `metrics` is given.
    #[must_use]
    pub fn book(
        limiter: &SharedLimiter,
        peer: PeerId,
        protocol: Protocol,
        n: u64,
        metrics: Option<RpcMetrics>,
        write_deadline: Duration,
    ) -> Self {
        let charge = lock(limiter).charge_block(peer, protocol, n, Instant::now());
        Self {
            limiter: Arc::clone(limiter),
            peer,
            protocol,
            charge,
            metrics,
            write_deadline,
        }
    }

    /// When the first chunk may go: the lookup waits for it.
    #[must_use]
    pub fn ready_at(&self) -> Instant {
        lock(&self.limiter).due_of(self.peer, self.protocol, &self.charge, 0)
    }

    /// How long a due chunk may take to be written.
    #[must_use]
    pub fn write_deadline(&self) -> Duration {
        self.write_deadline
    }

    /// The tokens still booked.
    #[must_use]
    pub fn tokens(&self) -> u64 {
        self.charge.tokens()
    }

    /// The answer holds `used` chunks: the tokens past them go back, as far as still ahead.
    pub fn settle(&mut self, used: u64) {
        let unused = self.charge.tokens().saturating_sub(used);
        lock(&self.limiter).refund_tail(
            self.peer,
            self.protocol,
            &mut self.charge,
            unused,
            Instant::now(),
        );
    }

    /// When chunk `i` may be written; counts it as withheld if that is still ahead.
    #[must_use]
    pub fn due(&self, i: u64) -> Instant {
        let due = lock(&self.limiter).due_of(self.peer, self.protocol, &self.charge, i);
        if due > Instant::now() {
            if let Some(metrics) = &self.metrics {
                metrics.rate_limited(self.protocol);
            }
            tracing::debug!(
                peer = %self.peer,
                protocol = %self.protocol,
                chunk = i,
                "over quota: column chunk withheld"
            );
        }
        due
    }
}

/// The column answers held at once (see the module docs). Cheap to clone: every clone is the
/// same set of places.
#[derive(Clone)]
pub struct ColumnPlaces(Arc<Places>);

struct Places {
    max: usize,
    max_per_ip: usize,
    state: Mutex<PlacesState>,
    waker: AtomicWaker,
    metrics: Option<RpcMetrics>,
}

#[derive(Default)]
struct PlacesState {
    peers: HashSet<PeerId>,
    per_ip: HashMap<IpBucket, usize>,
    bytes: usize,
}

impl fmt::Debug for ColumnPlaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ColumnPlaces")
            .field("max", &self.0.max)
            .field("held", &self.held())
            .finish_non_exhaustive()
    }
}

impl ColumnPlaces {
    /// `max` places, at most `max_per_ip` to the peers of one IP, reported in
    /// `rpc_column_answers` and `rpc_column_answer_bytes` if `metrics` is given.
    #[must_use]
    pub fn new(max: usize, max_per_ip: usize, metrics: Option<RpcMetrics>) -> Self {
        Self(Arc::new(Places {
            max,
            max_per_ip,
            state: Mutex::default(),
            waker: AtomicWaker::new(),
            metrics,
        }))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PlacesState> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A place for `peer` at `ip` (its IP's bucket, `None` without one), unless every place
    /// is held, `peer` holds one, or the peers of `ip` hold their most.
    #[must_use]
    pub(crate) fn try_take(&self, peer: PeerId, ip: Option<IpBucket>) -> Option<AnswerPermit> {
        let mut state = self.state();
        let ip_full =
            ip.is_some_and(|ip| state.per_ip.get(&ip).copied().unwrap_or(0) >= self.0.max_per_ip);
        if state.peers.len() >= self.0.max || ip_full || !state.peers.insert(peer) {
            return None;
        }
        if let Some(ip) = ip {
            *state.per_ip.entry(ip).or_default() += 1;
        }
        self.report(&state);
        Some(AnswerPermit {
            places: self.clone(),
            peer,
            ip,
            bytes: 0,
        })
    }

    /// Places held now.
    #[must_use]
    pub fn held(&self) -> usize {
        self.state().peers.len()
    }

    /// Whether `peer` holds a place.
    #[must_use]
    pub fn holds(&self, peer: &PeerId) -> bool {
        self.state().peers.contains(peer)
    }

    /// Wakes `waker` once a place is given back.
    pub fn register(&self, waker: &std::task::Waker) {
        self.0.waker.register(waker);
    }

    fn report(&self, state: &PlacesState) {
        if let Some(metrics) = &self.0.metrics {
            metrics.set_column_answers(state.peers.len(), state.bytes);
        }
    }
}

/// One held column answer's place ([`ColumnPlaces::try_take`]), given back on drop: when the
/// stream's writer returns, or when the answer never got there.
pub struct AnswerPermit {
    places: ColumnPlaces,
    peer: PeerId,
    ip: Option<IpBucket>,
    bytes: usize,
}

impl fmt::Debug for AnswerPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnswerPermit")
            .field("peer", &self.peer)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl AnswerPermit {
    /// The answer holds `bytes` of SSZ from now on.
    pub fn hold_bytes(&mut self, bytes: usize) {
        let mut state = self.places.state();
        state.bytes = state.bytes.saturating_sub(self.bytes).saturating_add(bytes);
        self.bytes = bytes;
        self.places.report(&state);
    }
}

impl Drop for AnswerPermit {
    fn drop(&mut self) {
        {
            let mut state = self.places.state();
            state.peers.remove(&self.peer);
            if let Some(ip) = self.ip {
                if let Some(n) = state.per_ip.get_mut(&ip) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        state.per_ip.remove(&ip);
                    }
                }
            }
            state.bytes = state.bytes.saturating_sub(self.bytes);
            self.places.report(&state);
        }
        self.places.0.waker.wake();
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

    pub(crate) fn count(&self, queue: &'static str) {
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
        Protocol::DataColumnsByRangeV1 => "rpc_outbound_data_columns_by_range",
        Protocol::DataColumnsByRootV1 => "rpc_outbound_data_columns_by_root",
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
    fn a_block_charge_books_its_tokens_and_gives_back_only_the_unused_tail() {
        let quota = Quota::new(2, Duration::from_secs(1));
        let mut limiter = RateLimiter::new(RateLimits {
            data_columns_by_range: quota,
            ..RateLimits::default()
        });
        let peer = PeerId::random();
        let p = Protocol::DataColumnsByRangeV1;
        let now = Instant::now();
        let mut block = limiter.charge_block(peer, p, 5, now);
        assert_eq!(block.tokens(), 5);
        // Two at once (the burst), then one a second.
        assert_eq!(block.due(0), now);
        assert_eq!(block.due(1), now);
        assert_eq!(block.due(2), now + Duration::from_secs(1));
        assert_eq!(block.due(4), now + Duration::from_secs(3));
        // The answer used two: three periods go back; the bucket is where two chunks leave it.
        limiter.refund_tail(peer, p, &mut block, 3, now);
        assert_eq!(block.tokens(), 2);
        assert_eq!(limiter.schedule(peer, p, now), now + Duration::from_secs(1));
        // Nothing past what was booked goes back.
        limiter.refund_tail(peer, p, &mut block, 10, now);
        assert_eq!(block.tokens(), 0);
        let goodbye = limiter.charge_block(peer, Protocol::GoodbyeV1, 3, now);
        assert_eq!(goodbye.due(2), now);
    }

    #[test]
    fn column_answers_hold_what_their_quota_delivers_in_the_window() {
        let limits = RpcLimits::default();
        assert_eq!(
            limits.column_answer_sidecars(Protocol::DataColumnsByRangeV1),
            756
        );
        assert_eq!(
            limits.column_answer_sidecars(Protocol::DataColumnsByRootV1),
            756
        );
        assert_eq!(
            limits.column_answer_sidecars(Protocol::GoodbyeV1),
            MAX_REQUEST_DATA_COLUMN_SIDECARS
        );
        let fast = RpcLimits {
            rate: RateLimits {
                data_columns_by_range: Quota::new(1, Duration::ZERO),
                ..RateLimits::default()
            },
            ..limits
        };
        assert_eq!(
            fast.column_answer_sidecars(Protocol::DataColumnsByRangeV1),
            MAX_REQUEST_DATA_COLUMN_SIDECARS
        );
    }

    /// BUG-002: a booking takes what the bucket can still deliver within the window, and a
    /// tail refund brings the bookings behind it forward.
    #[test]
    fn bookings_fit_the_window_and_follow_a_refund() {
        let quota = Quota::new(2, Duration::from_secs(1));
        let mut limiter = RateLimiter::new(RateLimits {
            data_columns_by_range: quota,
            ..RateLimits::default()
        });
        let peer = PeerId::random();
        let p = Protocol::DataColumnsByRangeV1;
        let now = Instant::now();
        let window = Duration::from_secs(4);
        // A full bucket: two at once, then one a second for four seconds.
        assert_eq!(limiter.deliverable(peer, p, window, now), 6);
        let mut first = limiter.charge_block(peer, p, 4, now);
        assert_eq!(limiter.deliverable(peer, p, window, now), 2);
        let second = limiter.charge_block(peer, p, 2, now);
        assert_eq!(limiter.deliverable(peer, p, window, now), 0);
        assert_eq!(
            limiter.due_of(peer, p, &second, 0),
            now + Duration::from_secs(3)
        );
        // The first answer used one: its three unused periods go back, and the second moves up
        // behind the one that was used.
        limiter.refund_tail(peer, p, &mut first, 3, now);
        assert_eq!(limiter.due_of(peer, p, &second, 0), now);
        assert_eq!(
            limiter.due_of(peer, p, &second, 1),
            now + Duration::from_secs(1)
        );
    }

    #[test]
    fn column_places_hold_one_answer_per_peer_up_to_the_most() {
        let metrics = RpcMetrics::register(&mut Registry::default());
        let places = ColumnPlaces::new(2, 2, Some(metrics.clone()));
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut first = places.try_take(a, None).unwrap();
        assert!(places.try_take(a, None).is_none(), "one per peer");
        let second = places.try_take(b, None).unwrap();
        assert!(places.try_take(c, None).is_none(), "every place held");
        first.hold_bytes(10);
        assert!(places.holds(&a));
        assert_eq!((places.held(), metrics.column_answers_held()), (2, 2));
        assert_eq!(metrics.column_answer_bytes_held(), 10);
        drop(first);
        assert_eq!(places.held(), 1);
        assert_eq!(metrics.column_answer_bytes_held(), 0);
        assert!(places.try_take(c, None).is_some());
        drop(second);
        // At most two places per IP, whatever the peers.
        let places = ColumnPlaces::new(8, 2, None);
        let one = Some(crate::peer_caps::IpBucket::V4(
            std::net::Ipv4Addr::LOCALHOST,
        ));
        let other = Some(crate::peer_caps::IpBucket::V4(std::net::Ipv4Addr::new(
            10, 0, 0, 1,
        )));
        let held: Vec<_> = (0..2)
            .map(|_| places.try_take(PeerId::random(), one).unwrap())
            .collect();
        assert!(
            places.try_take(PeerId::random(), one).is_none(),
            "the IP's two are held"
        );
        assert!(places.try_take(PeerId::random(), other).is_some());
        drop(held);
        assert!(places.try_take(PeerId::random(), one).is_some());
        assert!(format!("{places:?}").contains("max: 8"));
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
        let second = limiter.charge(peer, ping, start);
        assert_eq!(second.due(), at(start, 1000));
        // The second chunk was never sent: its period comes back.
        limiter.refund(peer, ping, second, start);
        assert_eq!(limiter.schedule(peer, ping, start), at(start, 1000));
        // Five chunks queued behind it (2 s to 7 s) are refunded a period each; the one sent
        // stays charged until 2 s.
        let queued: Vec<Charge> = (0..5).map(|_| limiter.charge(peer, ping, start)).collect();
        for charge in queued {
            limiter.refund(peer, ping, charge, at(start, 1500));
        }
        assert_eq!(
            limiter.schedule(peer, ping, at(start, 1500)),
            at(start, 2000)
        );
        // Refunded later than every charge ran out, a queue never moves the bucket before now,
        // so refunds cannot buy a burst.
        let queued: Vec<Charge> = (0..5).map(|_| limiter.charge(peer, ping, start)).collect();
        for charge in queued.into_iter().rev() {
            limiter.refund(peer, ping, charge, at(start, 9000));
        }
        assert_eq!(
            limiter.schedule(peer, ping, at(start, 9000)),
            at(start, 9000)
        );
        assert_eq!(
            limiter.schedule(peer, ping, at(start, 9000)),
            at(start, 10_000)
        );
        // Nothing to refund: no quota, no bucket, or a bucket pruned and made anew since.
        let goodbye = limiter.charge(peer, Protocol::GoodbyeV1, start);
        assert_eq!(goodbye.due(), start);
        limiter.refund(peer, Protocol::GoodbyeV1, goodbye, start);
        let gone = PeerId::random();
        let stale = limiter.charge(gone, ping, start);
        let other = PeerId::random();
        let missing = limiter.charge(other, ping, start);
        limiter.prune(at(start, 1000), |p| *p == peer);
        limiter.refund(other, ping, missing, at(start, 1000));
        assert_eq!(limiter.tracked(), 1);
        let later = at(start, 5000);
        assert_eq!(limiter.schedule(gone, ping, later), later);
        limiter.refund(gone, ping, stale, later);
        assert_eq!(limiter.schedule(gone, ping, later), at(later, 1000));
    }

    /// The default Ping quota on one peer's bucket, and the pacer of it.
    fn ping_pacer() -> (SharedLimiter, PeerId, ChunkPacer) {
        let limiter = shared_limiter(RateLimits::default());
        let peer = PeerId::random();
        let pacer = ChunkPacer::new(limiter.clone(), peer, Protocol::PingV1, None);
        (limiter, peer, pacer)
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_chunk_whose_charge_expired_refunds_nothing() {
        // The default Ping quota: 2 at once, then one per 2 s.
        let (limiter, peer, pacer) = ping_pacer();
        let start = Instant::now();
        // A's write stalls; its charge runs out at 2 s.
        let a = pacer.reserve();
        tokio::time::advance(Duration::from_secs(3)).await;
        // B is charged from 3 s to 5 s and sent.
        pacer.reserve().sent();
        tokio::time::advance(Duration::from_millis(100)).await;
        // A's stream is reset: its charge already expired, so B's must survive.
        drop(a);
        let now = Instant::now();
        let mut limiter = lock(&limiter);
        assert_eq!(limiter.schedule(peer, Protocol::PingV1, now), now);
        assert_eq!(
            limiter.schedule(peer, Protocol::PingV1, now),
            at(start, 5000),
            "B's charge was erased"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stalling_and_resetting_gains_no_token() {
        // A peer that keeps one write stalled past most of its charge and resets it after the
        // next chunk went out. Every cycle its bucket ends no better than a peer's that never
        // asked for the stalled chunks, and no worse than one's that was sent them all.
        let (limiter, peer, pacer) = ping_pacer();
        let mut never_asked = RateLimiter::new(RateLimits::default());
        let mut all_sent = RateLimiter::new(RateLimits::default());
        let ping = Protocol::PingV1;
        for _ in 0..20 {
            let stalled = pacer.reserve();
            all_sent.schedule(peer, ping, Instant::now());
            tokio::time::advance(Duration::from_secs(3)).await;
            pacer.reserve().sent();
            all_sent.schedule(peer, ping, Instant::now());
            never_asked.schedule(peer, ping, Instant::now());
            tokio::time::advance(Duration::from_millis(100)).await;
            drop(stalled);
            // Past the burst, where the bucket shows.
            let now = Instant::now();
            let ours = past_burst(&lock(&limiter), peer, now);
            assert!(
                ours >= past_burst(&never_asked, peer, now),
                "a token was gained"
            );
            assert!(ours <= past_burst(&all_sent, peer, now));
        }
    }

    /// When `peer`'s Ping chunk after a full default burst would go at `now`, without
    /// charging it.
    fn past_burst(limiter: &RateLimiter, peer: PeerId, now: Instant) -> Instant {
        let mut probe = limiter.clone();
        (0..RateLimits::default().ping.burst)
            .fold(now, |_, _| probe.schedule(peer, Protocol::PingV1, now))
    }

    /// When `peer`'s next Ping chunk would go at `now`, without charging it.
    fn next_ping(limiter: &SharedLimiter, peer: PeerId, now: Instant) -> Instant {
        lock(limiter).clone().schedule(peer, Protocol::PingV1, now)
    }

    #[tokio::test(start_paused = true)]
    async fn an_unsent_chunk_refunds_only_the_part_of_its_charge_still_ahead() {
        // One Ping chunk per 2 s, no burst.
        let limiter = shared_limiter(RateLimits {
            ping: Quota::new(1, Duration::from_secs(2)),
            ..RateLimits::default()
        });
        let peer = PeerId::random();
        let pacer = ChunkPacer::new(limiter.clone(), peer, Protocol::PingV1, None);
        let start = Instant::now();
        // A chunk dropped at once is refunded in full.
        drop(pacer.reserve());
        assert_eq!(next_ping(&limiter, peer, start), start);
        // A is charged from 0 s to 2 s, B from 2 s to 4 s and sent.
        let a = pacer.reserve();
        pacer.reserve().sent();
        // A is dropped at 0.5 s: the 1.5 s of its charge still ahead comes back, not 2 s.
        tokio::time::advance(Duration::from_millis(500)).await;
        drop(a);
        assert_eq!(next_ping(&limiter, peer, Instant::now()), at(start, 2500));
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
