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
//!   cannot reset its way out of the bill: once the answer's first chunk was written whole the
//!   tokens it does not use, past its lookup's cost, are given back
//!   ([`BookedChunks::settle_answer`]), once and never more, and a reset before that (or a close
//!   during the lookup) refunds nothing.
//! - [`ColumnPlaces`]: the column answers held at once, from the lookup until the stream's
//!   writer returns, at most one per peer ([`AnswerPermit`]), each written to its booked
//!   schedule and held no longer than the answer window and the write deadline
//!   ([`WriteSchedule`]).
//! - [`ignore_queue`]: a bounded `tokio::sync::mpsc` queue fed with `try_send`. Overload never
//!   blocks the swarm and never ACCEPTs: an item that does not fit is IGNOREd (dropped) and
//!   counted in `queue_dropped_total{queue}`.
//!
//! The inbound concurrent-stream cap is `request_response`'s own: each protocol's inbound
//! behaviour serves at most [`MAX_CONCURRENT_REQUESTS`] streams per connection and resets the
//! next one ([`super::inbound::Duplex`]), and a peer holds one connection.

use super::answer_bucket::{AnswerBucket, AnswerPrefixes};
use super::metrics::RpcMetrics;
use super::MAX_CONCURRENT_REQUESTS;
use futures::task::AtomicWaker;
use libp2p::PeerId;
use p2p_wire::rpc::protocols::{Protocol, MAX_REQUEST_DATA_COLUMN_SIDECARS};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
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

/// The SSZ bytes one column answer may hold: 8 MiB \[est\], read in [`COLUMN_ANSWER_WINDOW`].
/// An answer is cut at the last whole block that fits (the first block always goes if it reaches
/// the requester before the answer's place goes back, else the answer is `3: ResourceUnavailable`;
/// "Clients MAY limit the number of data column sidecars in the response",
/// `fulu/p2p-interface.md` L682), so one epoch of 4 custody columns of 21-blob Gloas blocks
/// (32 × 4 × 44,072 bytes, 5.4 MiB) fits whole. The answer holds no more than a requester
/// reading these bytes per window reads from the lookup's end, and again from when writing
/// starts, to the window's end, given when each chunk's token is due ([`PacedReader`]): after
/// the longest lookup (2 s), 3 s of the 5 s, about 4.8 MiB with the tokens due by then, and less
/// when they are due later or writing starts later.
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

/// Column answers held at once by the peers of one address block (an IPv4 /24 or an IPv6 /48,
/// [`RpcLimits::column_answer_prefixes`]) \[est\]: 2, so one host with its 8 inbound
/// connections (`ConnectionCaps::max_established_incoming_per_ip`), or with a block of
/// neighbouring addresses, cannot take all [`DEFAULT_MAX_COLUMN_ANSWERS`] places.
pub const DEFAULT_MAX_COLUMN_ANSWERS_PER_IP: usize = 2;

/// How far a column chunk may fall behind its answer's schedule before its stream is reset
/// \[est\]: 1 s. A chunk is due at its token, no earlier than the share of the answer window
/// ([`COLUMN_ANSWER_WINDOW`], from when the answer took its place) that the answer's SSZ bytes
/// before it are of all of them, so a burst never asks for the whole answer at once, and no
/// earlier than a requester reading at the answer's pace has it ([`PacedReader`]); it must be
/// written and flushed within this of that, and within this and its own bytes' time at that
/// pace of its write's start, and the place goes back within the window and this of being
/// taken ([`WriteSchedule`]). The deadline is not a new one per write: a requester that
/// reads a chunk just inside it each time still falls behind its schedule and is reset, so it
/// holds a place for about a second (and a chunk's bytes' time) past the pace it keeps, not the
/// 10 s exchange timeout. One that reads at the answer's pace (8 MiB in 5 s, about 1.7 MB/s)
/// whenever a chunk is there to read is never cut, however the bytes are spread over the chunks,
/// however large one chunk is and however long they wait for their tokens: the answer holds no
/// more than the whole blocks that pace reads by the end of the window from when its writer
/// started ([`BookedChunks::cut`]). Counted in `rpc_timeouts_total{kind="per_chunk"}`.
pub const COLUMN_WRITE_DEADLINE: Duration = Duration::from_secs(1);

/// The deadlines a column answer is written under ([`RpcLimits::column_deadlines`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnDeadlines {
    /// How long the answer's chunks may take, from when it took its place.
    pub answer_window: Duration,
    /// How far a chunk may fall behind the answer's schedule ([`COLUMN_WRITE_DEADLINE`]).
    pub write: Duration,
    /// The SSZ bytes a requester reads in `answer_window`: the pace each chunk's deadline
    /// leaves its bytes, and an answer is cut to ([`PacedReader`]).
    pub answer_bytes: usize,
}

impl Default for ColumnDeadlines {
    /// [`COLUMN_ANSWER_WINDOW`], [`COLUMN_WRITE_DEADLINE`] and [`MAX_COLUMN_RESPONSE_BYTES`].
    fn default() -> Self {
        Self {
            answer_window: COLUMN_ANSWER_WINDOW,
            write: COLUMN_WRITE_DEADLINE,
            answer_bytes: MAX_COLUMN_RESPONSE_BYTES,
        }
    }
}

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
    /// Column answers held at once by the peers of one address block
    /// ([`Self::column_answer_prefixes`]).
    pub max_column_answers_per_ip: usize,
    /// How wide that block is: an IPv4 /24 and an IPv6 /48 by default, an IPv4-mapped IPv6
    /// address counted as its IPv4 address ([`super::answer_bucket`]).
    pub column_answer_prefixes: AnswerPrefixes,
    /// How far a column chunk may fall behind its answer's schedule before its stream is reset
    /// and its place given back ([`COLUMN_WRITE_DEADLINE`]).
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
            column_answer_prefixes: AnswerPrefixes::default(),
            column_write_deadline: COLUMN_WRITE_DEADLINE,
        }
    }
}

impl RpcLimits {
    /// The deadlines a column answer is written under.
    #[must_use]
    pub fn column_deadlines(&self) -> ColumnDeadlines {
        ColumnDeadlines {
            answer_window: self.column_answer_window,
            write: self.column_write_deadline,
            answer_bytes: self.max_column_response_bytes,
        }
    }

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

/// How many of its latest refunds a bucket remembers, by the charge each gave back from \[est\]:
/// a peer has at most [`MAX_CONCURRENT_REQUESTS`] answers of a protocol open, and each column
/// answer refunds once. Past it a booking errs on the side of the bucket
/// ([`Bucket::moved_before`]).
pub(crate) const REFUND_LOG_LEN: usize = 16;

/// One (peer, protocol) bucket.
#[derive(Debug, Clone)]
struct Bucket {
    /// The theoretical arrival time of the next chunk.
    next: Instant,
    /// How far refunds have moved `next` back in all: no charge still held moved further.
    refunded: Duration,
    /// Which bucket this is, so a charge on a pruned bucket refunds nothing to its successor.
    id: u64,
    /// Charges made on this bucket so far: the number of the next one.
    charges: u64,
    /// The latest refunds, oldest first: the number of the charge each gave back from, and how
    /// far it moved `next` back.
    refunds: VecDeque<(u64, Duration)>,
    /// Refunds ever made: one past the last of `refunds`.
    logged: u64,
}

impl Bucket {
    fn new(now: Instant, id: u64) -> Self {
        Self {
            next: now,
            refunded: Duration::ZERO,
            id,
            charges: 0,
            refunds: VecDeque::new(),
            logged: 0,
        }
    }

    /// Where a charge that moves `next` to `until` sits, as its [`Booking`].
    fn book(&mut self, until: Instant) -> Booking {
        self.next = until;
        let booking = Booking {
            bucket: self.id,
            seq: self.charges,
            until,
            refunded: self.refunded,
            logged: self.logged,
        };
        self.charges += 1;
        booking
    }

    /// How far the refunds of the charges before `booked` moved `next` back since it was
    /// booked: what moved `booked` itself. `Err` with the part still logged if some of them
    /// were forgotten ([`REFUND_LOG_LEN`]), a lower bound.
    fn moved_before(&self, booked: &Booking) -> Result<Duration, Duration> {
        let first_kept = self.logged - self.refunds.len() as u64;
        let skip = usize::try_from(booked.logged.saturating_sub(first_kept)).unwrap_or(usize::MAX);
        let moved = self
            .refunds
            .iter()
            .skip(skip)
            .filter(|(seq, _)| *seq < booked.seq)
            .fold(Duration::ZERO, |sum, (_, d)| sum.saturating_add(*d));
        if booked.logged < first_kept {
            Err(moved)
        } else {
            Ok(moved)
        }
    }

    /// Logs a refund of the charge numbered `seq` that moved `next` back by `moved`.
    fn log_refund(&mut self, seq: u64, moved: Duration) {
        if self.refunds.len() >= REFUND_LOG_LEN {
            self.refunds.pop_front();
        }
        self.refunds.push_back((seq, moved));
        self.logged += 1;
        self.refunded = self.refunded.saturating_add(moved);
    }
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

/// Where a charged span sits: its bucket, its number there, its end (the bucket's `next` right
/// after the charge, less what it gave back since), and the bucket's `refunded` and refunds
/// logged then.
#[derive(Debug, PartialEq, Eq)]
struct Booking {
    bucket: u64,
    seq: u64,
    until: Instant,
    refunded: Duration,
    logged: u64,
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
        let bucket = self.bucket(peer, protocol, now);
        let start = bucket.next.max(now);
        let booked = bucket.book(start + quota.period);
        Charge {
            due: start
                .checked_sub(quota.tolerance())
                .map_or(now, |at| at.max(now)),
            booked: Some(booked),
        }
    }

    /// `peer`'s `protocol` bucket, a full one made at `now` if there is none.
    fn bucket(&mut self, peer: PeerId, protocol: Protocol, now: Instant) -> &mut Bucket {
        let created = &mut self.created;
        self.buckets.entry((peer, protocol)).or_insert_with(|| {
            *created += 1;
            Bucket::new(now, *created)
        })
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
        let bucket = self.bucket(peer, protocol, now);
        let start = bucket.next.max(now);
        let span = quota
            .period
            .saturating_mul(u32::try_from(n).unwrap_or(u32::MAX));
        let booked = bucket.book(start + span);
        BlockCharge {
            start,
            booked_at: now,
            period: quota.period,
            tolerance: quota.tolerance(),
            n,
            booked: Some(booked),
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

    /// When chunk `i` of `charge` may be sent now: as booked, moved up by the refunds of the
    /// charges booked before it on `peer`'s `protocol` bucket, made since. Its own refunds and
    /// those of later charges move only the charges after them. If the bucket forgot some of
    /// those refunds, it moves up by the ones it still knows: later than it could, never
    /// earlier.
    #[must_use]
    pub fn due_of(
        &self,
        peer: PeerId,
        protocol: Protocol,
        charge: &BlockCharge,
        i: u64,
    ) -> Instant {
        charge.due_after(i, self.shift_of(peer, protocol, charge))
    }

    /// How far the refunds of the charges booked before `charge` moved it up ([`Self::due_of`]).
    fn shift_of(&self, peer: PeerId, protocol: Protocol, charge: &BlockCharge) -> Duration {
        charge
            .booked
            .as_ref()
            .and_then(|booked| {
                self.buckets
                    .get(&(peer, protocol))
                    .filter(|b| b.id == booked.bucket)
                    .map(|b| b.moved_before(booked).unwrap_or_else(|known| known))
            })
            .unwrap_or_default()
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
        let Some(booked) = &mut charge.booked else {
            return;
        };
        let back = charge
            .period
            .saturating_mul(u32::try_from(unused).unwrap_or(u32::MAX));
        let moved = self.give_back(peer, protocol, booked, back, now);
        // Its span now ends that much earlier.
        booked.until = booked.until.checked_sub(moved).unwrap_or(booked.until);
    }

    /// [`Self::charge`], for a chunk that is never refunded: when it may be sent.
    pub fn schedule(&mut self, peer: PeerId, protocol: Protocol, now: Instant) -> Instant {
        self.charge(peer, protocol, now).due
    }

    /// Gives back what is still ahead of `now` of the period `charge` booked for a chunk of
    /// `protocol` to `peer` that was never sent: at most one period, and nothing once the
    /// period ran out, since time since spent it and later chunks may hold the bucket now.
    ///
    /// A refund moves the bucket back, and with it every charge after the refunded one, so a
    /// charge's period ends where it was booked less the refunds of the charges before it made
    /// since (`Bucket::moved_before`; every refund since, if the bucket forgot some, which is
    /// never less): a refund never gives back more than the live part of its charge. The
    /// bucket never moves before `now`, so refunds cannot build a burst.
    pub fn refund(&mut self, peer: PeerId, protocol: Protocol, charge: Charge, now: Instant) {
        let (Some(quota), Some(booked)) = (self.limits.quota(protocol), charge.booked) else {
            return;
        };
        self.give_back(peer, protocol, &booked, quota.period, now);
    }

    /// Moves `peer`'s `protocol` bucket back by what is still ahead of `now` of the last `most`
    /// of the span `booked` ends, at most `most`, and logs it as a refund of `booked`. Returns
    /// how far it moved.
    fn give_back(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        booked: &Booking,
        most: Duration,
        now: Instant,
    ) -> Duration {
        let Some(bucket) = self
            .buckets
            .get_mut(&(peer, protocol))
            .filter(|bucket| bucket.id == booked.bucket)
        else {
            return Duration::ZERO;
        };
        let moved_since = bucket
            .moved_before(booked)
            .unwrap_or_else(|_| bucket.refunded.saturating_sub(booked.refunded));
        let live = booked
            .until
            .checked_sub(moved_since)
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
            .min(most);
        let back = bucket
            .next
            .checked_sub(live)
            .map_or(now, |back| back.max(now));
        if back >= bucket.next {
            return Duration::ZERO;
        }
        let moved = bucket.next - back;
        bucket.next = back;
        bucket.log_refund(booked.seq, moved);
        moved
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
/// Dropping it unsettled refunds nothing.
pub struct BookedChunks {
    limiter: SharedLimiter,
    peer: PeerId,
    protocol: Protocol,
    charge: BlockCharge,
    metrics: Option<RpcMetrics>,
    deadlines: ColumnDeadlines,
    /// The tokens that stay charged however short the answer ([`Self::with_lookup_cost`]).
    lookup_cost: u64,
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
    /// Books `n` chunks of `protocol` to `peer` in `limiter`, to be written under `deadlines`
    /// ([`Self::write_schedule`]), counting every withheld chunk in
    /// `rpc_rate_limited_total{protocol}` if `metrics` is given.
    #[must_use]
    pub fn book(
        limiter: &SharedLimiter,
        peer: PeerId,
        protocol: Protocol,
        n: u64,
        metrics: Option<RpcMetrics>,
        deadlines: ColumnDeadlines,
    ) -> Self {
        let charge = lock(limiter).charge_block(peer, protocol, n, Instant::now());
        Self {
            limiter: Arc::clone(limiter),
            peer,
            protocol,
            charge,
            metrics,
            deadlines,
            lookup_cost: 0,
        }
    }

    /// The same booking, of which `tokens` (at most those booked) stay charged once its lookup
    /// ran, however short the answer ([`Self::settle_answer`]).
    #[must_use]
    pub fn with_lookup_cost(mut self, tokens: u64) -> Self {
        self.lookup_cost = tokens.min(self.charge.tokens());
        self
    }

    /// When the first chunk may go: the lookup waits for it.
    #[must_use]
    pub fn ready_at(&self) -> Instant {
        lock(&self.limiter).due_of(self.peer, self.protocol, &self.charge, 0)
    }

    /// The requester an answer of these tokens that took its place at `held_since` is written
    /// to from `now`, reading at the answer's pace ([`PacedReader`]).
    #[must_use]
    pub fn reader(&self, held_since: Instant, now: Instant) -> PacedReader<'_> {
        let shift = lock(&self.limiter).shift_of(self.peer, self.protocol, &self.charge);
        PacedReader {
            charge: &self.charge,
            shift,
            start: now,
            end: held_since + self.deadlines.answer_window,
            hold_until: held_since + self.deadlines.answer_window + self.deadlines.write,
            bytes: self.deadlines.answer_bytes as u64,
            window: self.deadlines.answer_window,
        }
    }

    /// The schedule chunks of `sizes` SSZ bytes each are written to from `now`, by an answer
    /// that took its place at `held_since`: chunk `i` is due at the latest of its token
    /// ([`Self::due`]), its share of the window (as far from `now` to `held_since` + the answer
    /// window as the bytes before it are of the answer's) and when a requester reading at the
    /// answer's pace from `now` has it ([`Self::reader`]), and must be written within the write
    /// deadline of that, and of its write's start ([`WriteSchedule::written_by`]). The place is
    /// held no longer than the window and the write deadline from `held_since`.
    #[must_use]
    pub fn write_schedule(
        &self,
        sizes: impl IntoIterator<Item = usize>,
        held_since: Instant,
        now: Instant,
    ) -> WriteSchedule {
        let end = (held_since + self.deadlines.answer_window).max(now);
        let reader = self.reader(held_since, now);
        let mut total = 0u64;
        let mut read = now;
        let (mut before, mut read_by, mut transfer) = (Vec::new(), Vec::new(), Vec::new());
        for (size, i) in sizes.into_iter().zip(0u64..) {
            before.push(total);
            total = total.saturating_add(size as u64);
            read = reader.read(i, size, read);
            read_by.push(read);
            transfer.push(reader.transfer(size).unwrap_or(Duration::MAX));
        }
        WriteSchedule {
            start: now,
            span: end - now,
            before,
            total,
            read_by,
            transfer,
            write: self.deadlines.write,
            hold_until: held_since + self.deadlines.answer_window + self.deadlines.write,
        }
    }

    /// The tokens still booked.
    #[must_use]
    pub fn tokens(&self) -> u64 {
        self.charge.tokens()
    }

    /// How many chunks, and how many of their SSZ bytes, of an answer of chunks of `sizes` SSZ
    /// bytes in whole blocks of `blocks` chunks each, whose writer starts at `now`, its place
    /// taken at `held_since`, goes out: the whole blocks a requester reading at the answer's pace
    /// from `now` has by the end of the window, within these tokens
    /// ([`PacedReader::whole_blocks`]).
    #[must_use]
    pub fn cut(
        &self,
        sizes: &[usize],
        blocks: &[usize],
        held_since: Instant,
        now: Instant,
    ) -> (usize, usize) {
        self.reader(held_since, now)
            .whole_blocks(sizes, blocks, self.tokens(), usize::MAX)
    }

    /// The answer goes out with `kept` chunks: the tokens past them, and past the lookup's cost,
    /// go back, as far as still ahead. Its writer calls this once, when the first chunk was
    /// written whole (the stream was still there), or at once for an answer of no chunks.
    pub fn settle_answer(&mut self, kept: u64) {
        self.settle(kept.max(self.lookup_cost));
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

/// When each chunk of a column answer must be written by ([`BookedChunks::write_schedule`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteSchedule {
    start: Instant,
    /// From `start` to the end of the answer window.
    span: Duration,
    /// The SSZ bytes of the chunks before each chunk.
    before: Vec<u64>,
    /// The SSZ bytes of every chunk.
    total: u64,
    /// When a requester reading at the answer's pace has each chunk ([`PacedReader::read`]).
    read_by: Vec<Instant>,
    /// How long each chunk's own bytes take at the answer's pace ([`PacedReader::transfer`]).
    transfer: Vec<Duration>,
    write: Duration,
    hold_until: Instant,
}

impl WriteSchedule {
    /// When chunk `i`, due at `due`, must be written and flushed by if its write starts at
    /// `now`: the write deadline after the latest of `due`, its share of the window (the share
    /// the bytes before it have of the answer's, so a requester that reads the answer evenly
    /// over the window keeps up however its bytes are spread over its chunks) and when a
    /// requester reading at the answer's pace has it (so the time the chunks before it waited
    /// for their tokens is not counted as reading time it had), never past the place's hold,
    /// and never more than the chunk's own bytes' time at the answer's pace and the write
    /// deadline after the later of `due` and `now` (a requester that stopped reading is cut as
    /// soon as it holds a chunk that long; one reading at the pace has a chunk of any size by
    /// then).
    #[must_use]
    pub fn written_by(&self, i: u64, due: Instant, now: Instant) -> Instant {
        let at = usize::try_from(i).ok();
        let before = at
            .and_then(|i| self.before.get(i))
            .map_or(self.total, |&before| before);
        let read = at
            .and_then(|i| self.read_by.get(i))
            .map_or(due, |&read| read);
        let transfer = at
            .and_then(|i| self.transfer.get(i))
            .map_or(Duration::ZERO, |&transfer| transfer);
        let share = match self.total {
            0 => 0,
            total => self.span.as_nanos() * u128::from(before) / u128::from(total),
        };
        let share = Duration::from_nanos(u64::try_from(share).unwrap_or(u64::MAX));
        let started = due.max(now);
        let held = started
            .checked_add(transfer.saturating_add(self.write))
            .unwrap_or(self.hold_until);
        (due.max(self.start + share).max(read) + self.write)
            .min(held)
            .min(self.hold_until)
    }
}

/// A requester reading a column answer at the answer's pace ([`ColumnDeadlines::answer_bytes`]
/// per answer window) whenever there is a chunk to read ([`BookedChunks::reader`]): it reads
/// chunk `i` once its token is due and the chunk before it is read, so it banks no reading time
/// while a chunk waits for its token. An answer is cut at the last whole block it has read by
/// the end of the window ([`Self::end`]), and each chunk's deadline leaves it the time it needs
/// ([`WriteSchedule::written_by`]).
#[derive(Debug)]
pub struct PacedReader<'a> {
    charge: &'a BlockCharge,
    /// How far the refunds of earlier charges moved `charge` up, when the reader was made.
    shift: Duration,
    /// When the first byte can go out.
    start: Instant,
    /// The end of the answer window.
    end: Instant,
    /// When the answer's place goes back: the end of the window and the write deadline.
    hold_until: Instant,
    /// The bytes it reads per `window`.
    bytes: u64,
    window: Duration,
}

impl PacedReader<'_> {
    /// When the first byte can go out: the reader has read nothing before.
    #[must_use]
    pub fn start(&self) -> Instant {
        self.start
    }

    /// The end of the answer window: an answer holds no more than the whole blocks read by then.
    #[must_use]
    pub fn end(&self) -> Instant {
        self.end
    }

    /// When it has read chunk `i`, of `size` SSZ bytes, if it had read the chunk before it by
    /// `prev`: the chunk's bytes' time at the answer's pace after the later of `prev` and the
    /// chunk's token (a pace of 0 bytes reads 1 byte per window).
    #[must_use]
    pub fn read(&self, i: u64, size: usize, prev: Instant) -> Instant {
        let from = self.charge.due_after(i, self.shift).max(prev);
        self.transfer(size)
            .and_then(|transfer| from.checked_add(transfer))
            .unwrap_or_else(|| from.max(self.end) + self.window)
    }

    /// How many chunks, and how many of their SSZ bytes, an answer of chunks of `sizes` SSZ
    /// bytes in whole blocks of `blocks` chunks each (in order; chunks past them are no block)
    /// holds: the first block whole if it is within `most_chunks` and this reader has read it
    /// before the place goes back (the end of the window and the write deadline), else nothing,
    /// so it is never sent in part and then reset; then each next whole block while the answer
    /// stays within `most_chunks` and `most_bytes` and this reader has read it by the end of the
    /// window ([`Self::end`]).
    #[must_use]
    pub fn whole_blocks(
        &self,
        sizes: &[usize],
        blocks: &[usize],
        most_chunks: u64,
        most_bytes: usize,
    ) -> (usize, usize) {
        let (mut chunks, mut bytes) = (0usize, 0usize);
        let mut read = self.start;
        for &len in blocks {
            let Some(block) = sizes.get(chunks..chunks.saturating_add(len)) else {
                break;
            };
            let read_by = block
                .iter()
                .zip(chunks as u64..)
                .fold(read, |prev, (&size, i)| self.read(i, size, prev));
            let size = block.iter().fold(0usize, |n, &s| n.saturating_add(s));
            let within_tokens = (chunks + len) as u64 <= most_chunks;
            let fits = bytes.saturating_add(size) <= most_bytes && read_by <= self.end;
            let held = read_by <= self.hold_until;
            if !within_tokens || !held || (chunks > 0 && !fits) {
                break;
            }
            read = read_by;
            chunks += len;
            bytes = bytes.saturating_add(size);
        }
        (chunks, bytes)
    }

    /// How long `size` SSZ bytes take at the answer's pace (a pace of 0 bytes reads 1 byte per
    /// window); `None` if too long to tell.
    #[must_use]
    pub fn transfer(&self, size: usize) -> Option<Duration> {
        let nanos = self.window.as_nanos() * size as u128 / u128::from(self.bytes.max(1));
        u64::try_from(nanos).ok().map(Duration::from_nanos)
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
    per_ip: HashMap<AnswerBucket, usize>,
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
    /// `max` places, at most `max_per_ip` to the peers of one address block, reported in
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

    /// A place for `peer` at `ip` (its address block, `None` without one), unless every place
    /// is held, `peer` holds one, or the peers of `ip` hold their most.
    #[must_use]
    pub(crate) fn try_take(&self, peer: PeerId, ip: Option<AnswerBucket>) -> Option<AnswerPermit> {
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
            since: Instant::now(),
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
    ip: Option<AnswerBucket>,
    bytes: usize,
    /// When it was taken.
    since: Instant,
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
    /// When the place was taken: its answer's window starts then ([`WriteSchedule`]).
    #[must_use]
    pub fn held_since(&self) -> Instant {
        self.since
    }

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

    /// CR-002: a booking moves up only for the refunds of bookings before it. Its own unused
    /// tail and the refunds of bookings after it leave its due times as booked, so no more than
    /// the burst is ever due at once.
    #[test]
    fn a_booking_moves_up_only_for_refunds_of_bookings_before_it() {
        let limits = RateLimits::default();
        let quota = limits.data_columns_by_range;
        let period = quota.period;
        let p = Protocol::DataColumnsByRangeV1;
        let peer = PeerId::random();
        let now = Instant::now();
        let mut limiter = RateLimiter::new(limits);
        let first = limiter.charge_block(peer, p, 756, now);
        let mut second = limiter.charge_block(peer, p, 756, now);
        let booked: Vec<Instant> = (0..756)
            .map(|i| limiter.due_of(peer, p, &second, i))
            .collect();
        assert_eq!(booked[0], now + period * (756 - 511));
        // The second answer holds 376: its own tail goes back, its due times stay.
        limiter.refund_tail(peer, p, &mut second, 380, now);
        assert_eq!(second.tokens(), 376);
        for (i, &at) in (0..376).zip(&booked) {
            assert_eq!(limiter.due_of(peer, p, &second, i), at, "chunk {i}");
        }
        let due_at = |limiter: &RateLimiter, at: Instant| {
            (0..first.tokens())
                .filter(|&i| limiter.due_of(peer, p, &first, i) <= at)
                .count()
                + (0..second.tokens())
                    .filter(|&i| limiter.due_of(peer, p, &second, i) <= at)
                    .count()
        };
        assert_eq!(due_at(&limiter, now), quota.burst as usize, "the burst");
        // What went back is free: a third booking goes right after the second's kept tokens.
        let third = limiter.charge_block(peer, p, 1, now);
        assert_eq!(
            limiter.due_of(peer, p, &third, 0),
            now + period * (756 + 376 - 511)
        );
        // A refund of a later booking leaves an earlier one as booked.
        let mut limiter = RateLimiter::new(limits);
        let first = limiter.charge_block(peer, p, 756, now);
        let mut second = limiter.charge_block(peer, p, 756, now);
        let booked: Vec<Instant> = (0..756)
            .map(|i| limiter.due_of(peer, p, &first, i))
            .collect();
        limiter.refund_tail(peer, p, &mut second, 756, now);
        for (i, &at) in (0..756).zip(&booked) {
            assert_eq!(limiter.due_of(peer, p, &first, i), at, "chunk {i}");
        }
    }

    /// BUG-001: a requester reading at the answer's pace reads each chunk from the later of its
    /// token and the chunk before it: waiting for a token banks it no reading time.
    #[tokio::test(start_paused = true)]
    async fn a_paced_reader_reads_each_chunk_after_its_token_and_the_one_before() {
        let limiter = shared_limiter(RateLimits {
            data_columns_by_range: Quota::new(1, Duration::from_secs(1)),
            ..RateLimits::default()
        });
        let peer = PeerId::random();
        let p = Protocol::DataColumnsByRangeV1;
        // 1,000 bytes a second.
        let deadlines = ColumnDeadlines {
            answer_bytes: 5_000,
            ..ColumnDeadlines::default()
        };
        let now = Instant::now();
        let booked = BookedChunks::book(&limiter, peer, p, 3, None, deadlines);
        let reader = booked.reader(now, at(now, 200));
        assert_eq!(reader.start(), at(now, 200));
        assert_eq!(reader.end(), now + COLUMN_ANSWER_WINDOW);
        // Due at once: read half a second after the one before.
        assert_eq!(reader.read(0, 500, reader.start()), at(now, 700));
        // Due a second on: half a second after its token, nothing read ahead while it waited.
        assert_eq!(reader.read(1, 500, at(now, 700)), at(now, 1_500));
        // Due two seconds on, but the one before is read later: half a second after that.
        assert_eq!(reader.read(2, 500, at(now, 2_700)), at(now, 3_200));
        // A pace of 0 bytes reads one byte per window; its token is due when the three are.
        let slow = BookedChunks::book(
            &limiter,
            peer,
            p,
            1,
            None,
            ColumnDeadlines {
                answer_bytes: 0,
                ..deadlines
            },
        );
        let reader = slow.reader(now, now);
        assert_eq!(
            reader.read(0, 2, now),
            at(now, 3_000) + COLUMN_ANSWER_WINDOW * 2
        );
        // A read too long to tell lands past the window all the same.
        let huge = ColumnDeadlines {
            answer_window: Duration::from_secs(1 << 30),
            answer_bytes: 1,
            ..deadlines
        };
        let endless = BookedChunks::book(&limiter, peer, p, 1, None, huge);
        let reader = endless.reader(now, now);
        assert!(reader.read(0, usize::MAX, now) > reader.end());
    }

    /// CR-002: past the refunds a bucket remembers, a booking's due times never move up and a
    /// refund never gives back more than the live part of its charge.
    #[test]
    fn forgotten_refunds_err_on_the_side_of_the_bucket() {
        let quota = Quota::new(1, Duration::from_secs(1));
        let mut limiter = RateLimiter::new(RateLimits {
            data_columns_by_range: quota,
            ..RateLimits::default()
        });
        let p = Protocol::DataColumnsByRangeV1;
        let peer = PeerId::random();
        let now = Instant::now();
        let early: Vec<BlockCharge> = (0..=REFUND_LOG_LEN)
            .map(|_| limiter.charge_block(peer, p, 1, now))
            .collect();
        let mut last = limiter.charge_block(peer, p, 2, now);
        let booked = limiter.due_of(peer, p, &last, 0);
        // More refunds of earlier bookings than the bucket remembers.
        for mut charge in early {
            limiter.refund_tail(peer, p, &mut charge, 1, now);
        }
        let moved = limiter.due_of(peer, p, &last, 0);
        assert!(moved <= booked && moved > now, "{moved:?}");
        // Its own tail is still given back, no more than it booked.
        let next = limiter.clone().schedule(peer, p, now);
        limiter.refund_tail(peer, p, &mut last, 1, now);
        let after = limiter.clone().schedule(peer, p, now);
        assert!(
            after < next && next - after <= quota.period,
            "{next:?} {after:?}"
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
        // At most two places per address block, whatever the peers and addresses in it.
        let places = ColumnPlaces::new(8, 2, None);
        let prefixes = AnswerPrefixes::default();
        let at = |ip: &str| Some(prefixes.bucket(ip.parse().unwrap()));
        let one = at("10.0.0.1");
        let other = at("10.0.1.1");
        let held: Vec<_> = ["10.0.0.1", "10.0.0.2"]
            .iter()
            .map(|&ip| places.try_take(PeerId::random(), at(ip)).unwrap())
            .collect();
        for neighbour in ["10.0.0.3", "::ffff:10.0.0.4"] {
            assert!(
                places.try_take(PeerId::random(), at(neighbour)).is_none(),
                "the /24's two are held: {neighbour}"
            );
        }
        let v6: Vec<_> = ["2001:db8:1::1", "2001:db8:1:2::1"]
            .iter()
            .map(|&ip| places.try_take(PeerId::random(), at(ip)).unwrap())
            .collect();
        assert!(
            places
                .try_take(PeerId::random(), at("2001:db8:1:3::1"))
                .is_none(),
            "the /48's two are held"
        );
        assert!(places
            .try_take(PeerId::random(), at("2001:db8:2::1"))
            .is_some());
        drop(v6);
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
