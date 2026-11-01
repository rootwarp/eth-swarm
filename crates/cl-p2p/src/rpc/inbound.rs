//! The control protocols, both ways: Status v2, MetaData v3, Ping v1 and Goodbye v1, plus
//! `BeaconBlocksByRange` v2, served by a [`Responder`] if one is given
//! ([`Control::with_blocks_responder`]) and else answered `3: ResourceUnavailable` (the probe
//! stores no blocks), and the custody columns served by `DataColumnSidecarsByRange` v1 and
//! `DataColumnSidecarsByRoot` v1.
//!
//! [`Control`] is the probe swarm's req/resp behaviour. It holds one [`Duplex`] per protocol
//! ([`Protocols`], see [`crate::rpc`] for why one each): an inbound-only and an outbound-only
//! `request_response` behaviour, so these seven are what multistream-select offers and any other
//! protocol fails negotiation (`phase0/p2p-interface.md` L187–190), among them the MUST-support
//! ones the probe leaves out ([`super::unsupported`]). It answers every inbound
//! request itself and reports what it learned as [`ControlEvent`]s.
//!
//! # Answers
//!
//! - **Status** (`fulu/p2p-interface.md` L538–571): our Status from the [`StatusSource`]. A
//!   source that reads a fresh Status ([`StatusSource::fresh`], the service's from cl-chain) is
//!   read once for every Status we send or answer, so its `earliest_available_slot` never lags
//!   the column store: an answer's read starts once its token is due (see Limits), so a floor
//!   that rises while it waits for its token is what it carries, and ours on a dial when its
//!   request gets its outbound slot (see [Status](#status)). The answer is `2: ServerError`
//!   (Status does not specify `3`) when there is no Status of ours:
//!   - none known yet, from a source that reads none fresh;
//!   - the fresh read failed or passed its deadline: cl-chain is down or refused it, has no
//!     reference sample yet (`UNAVAILABLE` before its first), or its column store cannot say
//!     what it serves from;
//!   - the read would end past the requester's first-byte deadline less
//!     [`STATUS_ANSWER_SLACK`] (it is cut there), or its token is due past it (refused on
//!     arrival, unread, its token given back);
//!   - cl-chain's answer breaks the contract: a field of the wrong length, or no finalized
//!     checkpoint ([`status_from_chain`]).
//!
//!   The peer's Status is then judged ([`relevance`], against the last known Status), and
//!   [`ControlEvent::StatusAnswered`] follows once our Status was written to its stream.
//! - **MetaData**: one snapshot of the [`MetaDataSource`] (cl-chain): its `seq_number` and the
//!   fields it numbers, read together, so a `seq_number` bumped while an answer waits for its
//!   token never pairs with fields of another one. The probe subscribes to no attestation or
//!   sync subnets, and `custody_group_count` is the ENR `cgc`.
//! - **Ping** (`phase0` L1628–1682): our `seq_number`. A peer `seq_number` above the one of its
//!   MetaData we hold, or any while we hold none, triggers one GetMetaData; no second one goes
//!   out while one is open. One announced while it is open is kept: if the answer is older, it
//!   is asked for once more right away, not left until the next Ping.
//! - **Goodbye** (`phase0` L1457–1483): one response chunk, as the spec has it ("Request,
//!   Response Content: (Uint64)", L1461; "The response MUST consist of a single
//!   `response_chunk`", L1483), whose reason is the peer's own (the spec does not say which).
//!   The connection closes [`GOODBYE_LINGER`] after it went out, if the peer did not close it
//!   first, and is dropped if that close has not finished [`CLOSE_DEADLINE`] later. Counted
//!   and logged as one `goodbye_received` event. Our own Goodbye accepts an answer of one chunk
//!   or none (Lighthouse sends none).
//! - **BeaconBlocksByRange**: `3: ResourceUnavailable`, which that protocol specifies for blocks
//!   the responder does not have (`phase0` L1540). A request with `step` 0 or a `count` above
//!   `MAX_REQUEST_BLOCKS_DENEB` (128) is semantically invalid and gets `1: InvalidRequest`
//!   (`phase0` L1286–1288, L1514; `deneb` L876); the connection stays.
//!   With a [`Responder`] the answer is streamed ([`super::responder`]): the request is checked
//!   first, as above, before the responder runs or anything is read or booked (never clamped);
//!   one asking for no block is an empty answer; else the responder produces its chunks on its
//!   own task as the stream's writer sends them. The writer sends `2: ServerError` if no chunk
//!   was produced by the first-byte deadline less [`STATUS_ANSWER_SLACK`] (4.5 s), and ends the
//!   answer cleanly at its last whole chunk at the total deadline less the same slack (9.5 s),
//!   ahead of the requester's deadlines and of `request_response`'s own [`REQUEST_TIMEOUT`],
//!   which started before the request was read. A responder that returns ends the answer (with
//!   no chunk: `2: ServerError` on a single-response protocol); one that panics, or whose chunk
//!   the sink refused, ends it with `2: ServerError` if nothing went out, else at the last
//!   whole chunk. The column protocols keep their own path below (#148 moves them onto a
//!   responder).
//! - **DataColumnSidecarsByRange / ByRoot** (`fulu/p2p-interface.md` L605–775): the custody
//!   columns cl-chain stores, from the [`ColumnSource`] ([`ControlConfig::columns`]; cl-p2p
//!   opens no database, see [`super::columns`]). A request naming an index at or past
//!   `NUMBER_OF_COLUMNS` or more than `MAX_REQUEST_DATA_COLUMN_SIDECARS` (16,384) sidecars gets
//!   `1: InvalidRequest` (L746–747), and one naming none an empty answer. The source's answer
//!   is held to the request and cut at a whole block ([`super::columns`]): each chunk carries
//!   the fork digest of its sidecar's slot's epoch as context bytes (L700–702, L766–768). Its
//!   refusals go out with the fixed message of their code, never as an empty success:
//!   - `3: ResourceUnavailable`: below `earliest_available_slot` or before
//!     `data_column_serve_range` (cl-chain's answer, L652–656); a range naming a column we do
//!     not custody (cl-chain's answer, `cl_chain::reqresp`); no [`ColumnSource`]; and an
//!     answer whose first block would not reach a requester reading at the answer's pace
//!     before its place goes back (its hold: the window and the write deadline, checked at
//!     the lookup's cut and again by the stream's writer, [`BookedChunks::cut`]), refused whole
//!     rather than sent in part and reset;
//!   - `2: ServerError`: a lookup past [`COLUMN_LOOKUP_TIMEOUT`], or one cl-chain failed (its
//!     store), refused as overloaded, or answered with any error code but those of `1` and `3`
//!     (cl-chain unreachable too); a source answer that breaks the contract (a sidecar that
//!     does not decode, or whose context, slot or column is not what it is served as, see
//!     [`super::columns`]); a full column queue, or no place within the queue wait (see
//!     Limits); no
//!     runtime to run the lookup on.
//! - A request that broke the wire format: `1: InvalidRequest` (`phase0` L1383–1386), a
//!   Goodbye's included; a column request whose list is past its SSZ limit too
//!   (`MAX_REQUEST_BLOCKS_DENEB` identifiers, `NUMBER_OF_COLUMNS` indices).
//!
//! Error chunks carry no context bytes and `3` only where the protocol specifies it: the codec
//! refuses anything else ([`super::codec::encode_response`]).
//!
//! # Limits
//!
//! [`ControlConfig::limits`] ([`super::limits`]):
//!
//! - **Rate**: every answer goes to its stream with the pacer of the peer's bucket of its
//!   protocol ([`super::codec::Answer`]). The stream's writer charges each chunk when it is next
//!   to go and, over the quota, withholds it until its token is free, then sends it whole: never
//!   an error chunk, never a closed stream (`phase0` L1269–1274), counted in
//!   `rpc_rate_limited_total{protocol}`. A chunk that never went out (the peer left) is
//!   refunded; a sent one stays charged after a reconnect. Our Status answered from a fresh
//!   read takes its token when the request arrives and is read once the token is due, then
//!   goes out at that token ([`super::codec::Answer::token`]). Until then the request waits
//!   with its peer's session: a failed request or a closed connection drops it, its token
//!   gives back what is still ahead of it and a read it started is cancelled, so a peer that
//!   reconnects and asks again holds no more waiting answers, reads or debt than one that
//!   stayed. A request whose connection closed before its token is not read for. A stream the
//!   peer reset on a connection that stays still looks open, so it is read for and waits
//!   until its request fails, at the handler's [`REQUEST_TIMEOUT`] at the latest; no more than
//!   [`MAX_CONCURRENT_REQUESTS`] such streams per connection wait at once.
//! - **Inbound streams**: each [`Duplex`] serves at most [`MAX_CONCURRENT_REQUESTS`] inbound
//!   streams per connection, apart from ours, and resets the next one; a withheld chunk keeps
//!   its stream, so a peer over its quota cannot open more. A column stream holds its slot
//!   while its lookup runs, too.
//! - **Streamed answers**: at most [`RpcLimits::max_inbound_streams`] (256) at once over all
//!   peers; one past them is dropped without a chunk (a reset, as the per-connection cap does)
//!   and counted in `rpc_inbound_streams_refused_total`. A request books its
//!   [`Responder::cost`] (by default the items it asks for) on its peer's bucket when it is
//!   admitted, so a peer over its quota is held back from its first request on: its chunks go
//!   out at those tokens (then the pacer's), withheld whole, never an error or a close. What
//!   the answer did not use goes back once it ended, past one token for its read; a reset
//!   gives nothing back. Its chunks wait in a queue of [`super::responder::STREAM_QUEUE_LEN`]
//!   and within the peer's [`RpcLimits::max_queued_bytes_per_peer`], so a slow reader holds
//!   the responder back. The slot, the bytes and the responder's task are freed when the
//!   stream's writer returns or is dropped (written, reset, timed out, the connection
//!   closed), whether or not the responder finished.
//! - **Columns**: a column request books its tokens when it is admitted
//!   ([`super::limits::BookedChunks`], `column_tokens`): as many sidecars as it names, at most
//!   an answer's share of what the quota delivers in [`RpcLimits::column_answer_window`] and at
//!   most what the bucket can still deliver in that window, at least its largest block (for
//!   roots, every column named for one root over all its identifiers, each once: the first
//!   block always goes out, so every chunk sent is paid for) and at least its lookup's cost.
//!   Its lookup waits until the first token is due, so a peer over its quota costs no lookup,
//!   and its chunks go out at the booked tokens; a booking behind another moves up as that
//!   one's unused tokens go back. Those go back once, when the answer's first chunk was written
//!   whole (an empty answer: when its writer starts), past the chunks it holds and its lookup's
//!   cost, which stays charged however little the lookup found: one token per identifier
//!   naming a column (the store looks its root up), one per range (`lookup_cost`). At the
//!   default quota (512 at once, then 200 a second) a peer naming 128 unknown roots a time
//!   keeps 128 tokens (640 ms) per lookup, so past its burst its empty lookups run at no more
//!   than 200 roots a second. The cost never exceeds the sidecars a request names (each such
//!   identifier names one at least), so no peer pays more for an empty answer than for the
//!   same request answered in full, and a pattern its quota serves in time with full answers
//!   is served in time with empty ones.
//!   A reset before that first chunk, or a close during the lookup (its answer dropped), gives
//!   back nothing, so a peer cannot request and reset its way past its quota: the
//!   request-response handler waits on its response channel, not the stream, so a reset
//!   during the lookup shows only when the answer's first write fails. A requester that goes
//!   away later pays for the whole answer as cut, as one that read it does.
//!   Answers hold a place from the lookup until the stream's writer returns
//!   ([`super::limits::ColumnPlaces`]): at most [`RpcLimits::max_column_answers`] (8) at once,
//!   one per peer and [`RpcLimits::max_column_answers_per_ip`] (2) per address block (an IPv4
//!   /24 or IPv6 /48, [`RpcLimits::column_answer_prefixes`]), each at most
//!   [`RpcLimits::max_column_response_bytes`] (8 MiB) of SSZ, encoded one chunk at a time (an
//!   estimated 68 MiB for all, see [`super::limits::DEFAULT_MAX_COLUMN_ANSWERS`]), and no more
//!   than the whole blocks a requester reading those bytes per
//!   [`RpcLimits::column_answer_window`] reads from the lookup's end to the end of the window,
//!   given when each chunk's token is due ([`answer_columns`], [`super::limits::PacedReader`]);
//!   the stream's writer cuts it again, at a whole block, to what that requester reads from
//!   when writing starts ([`super::limits::BookedChunks::cut`]): a slow lookup, a delay before
//!   writing or tokens due late shorten the answer instead of leaving the requester less time
//!   for the same bytes. Each answer is written to a
//!   schedule ([`super::limits::WriteSchedule`]): a chunk is due at its booked token, no
//!   earlier than the share of the window from when the answer took its place that the
//!   answer's bytes before it are of all of them, and no earlier than such a requester has it,
//!   and a chunk not written within
//!   [`RpcLimits::column_write_deadline`] (1 s) of that, or within its own bytes' time at the
//!   answer's pace and the write deadline of its write's start, resets its stream and frees
//!   the place. A requester that stops reading holds it for about a second and its chunk's
//!   bytes' time, and one that reads a chunk just inside the deadline each time falls behind
//!   its schedule and is cut too; no place is held past the window and the write deadline, so
//!   slow readers spread over many IPs cannot keep every place for the 10 s exchange timeout.
//!   A request whose tokens are due waits for a place up to
//!   [`RpcLimits::column_queue_wait`] (2 s), then gets `2: ServerError`; at most
//!   [`RpcLimits::column_queue_len`] (64) wait, and one past them gets `2` at once (both counted
//!   in `queue_dropped_total{queue="rpc_column_queue"}`). A request waiting for its tokens is
//!   never refused (L1269–1274): it waits until its stream closes.
//! - **Outbound requests**: at most [`MAX_CONCURRENT_REQUESTS`] in flight per protocol across
//!   every peer (`rpc_outbound_inflight{protocol}`), the rest waiting in the protocol's bounded
//!   queue. A full queue IGNOREs the request (`queue_dropped_total{queue}`); an IGNOREd Goodbye
//!   closes the connection at once, since it was going to close anyway. A waiting request whose
//!   peer has left, or to a peer either side said Goodbye to (but our Goodbye), is dropped when
//!   its turn comes. Our Status from a source read fresh waits there as the intent to send,
//!   not a value: it is read when its turn comes, and the read holds the slot until the Status
//!   goes out, or gives it back if the read fails or the peer left meanwhile. An intent whose
//!   dial's [`STATUS_HANDSHAKE_DEADLINE`] passed while it waited, or whose connection is gone,
//!   is dropped when its turn comes, starting no read, and the slot goes to the next. Pings
//!   take no slot here: at most one per peer, sent at once ([`Control::ping`]).
//!
//! # Our BlocksByRange requests
//!
//! [`Control::request_blocks`] sends a BeaconBlocksByRange request under the same outbound
//! limit and hands back a [`BlocksTicket`]. When the request ends (the response, a failure, or
//! its peer left while it waited) its outcome is kept for [`Control::take_blocks`] and
//! [`ControlEvent::BlocksByRange`] says so; [`Control::cancel_blocks`] forgets it.
//! [`super::outbound::RangeRequester`] drives this. [`Control::status_valid_peers`] lists the
//! peers whose last Status was valid, with that Status, to pick from.
//!
//! # Status
//!
//! On every connection we dial, our Status goes out first ("the dialing client MUST send a
//! Status request upon connection", `phase0` L1437), and a reference CL drops a dialer that
//! sends none, so a fresh read that fails is retried while the connection lasts and neither
//! side said Goodbye: after [`STATUS_RETRY_BACKOFF`] (500 ms), doubled before each next retry,
//! at most [`STATUS_SEND_ATTEMPTS`] (4) reads, none starting later than
//! [`STATUS_HANDSHAKE_DEADLINE`] (10 s) after the dial, a read still waiting for its outbound
//! slot then included. Each read bounds its own time, so the Status goes out at most the
//! deadline and one read after the dial, or not at all (logged): a read started before the
//! deadline can end after it. Its reads and retries are of the peer's session (from the
//! connection that began it, while any connection to it lasts): one that outlives its session
//! is neither sent on the peer's next connection nor retried there, so each session's dial
//! gets its own bound. A Status with another fork digest, or a
//! finalized checkpoint that conflicts with ours, gets `Goodbye(2)` and the connection is closed
//! once the Goodbye completed (`phase0` L1441–1449); any other is valid
//! (`p2p_status_valid_peers`). A Status exchange that failed (a timeout, an error chunk) says
//! nothing about the peer's chain: it is ignored, never taken as valid or invalid.
//!
//! # Ping cadence
//!
//! Every connected peer is pinged [`ControlConfig::ping_interval`] ([`PING_INTERVAL`], 15 s)
//! after it connected, then an interval after its last Ping ended, until either side said
//! Goodbye. A peer has at most one Ping in flight, and it goes out at once, outside the shared
//! outbound lane, so neither slow nor silent peers can hold back anyone's Ping. That traffic is
//! what keeps a quiet connection up: the swarm's idle timeout
//! ([`crate::transport::DEFAULT_IDLE_CONNECTION_TIMEOUT`], 30 s) is twice the interval, and two
//! Pings to a peer are always at least an interval apart (Lighthouse allows 2 per 10 s).
//!
//! # Deadlines
//!
//! Inside the codec ([`super::codec`]): 5 s to the first byte and per chunk, 10 s in total, for
//! requests we read and responses we read. A silent inbound stream fails at 5 s and is dropped;
//! until then it holds one of the protocol's [`MAX_CONCURRENT_REQUESTS`] stream slots on its
//! connection. Every passed deadline counts in `rpc_timeouts_total{kind}`.

use super::codec::{
    Answer, Deadline, Deadlines, InboundCodec, ReadError, ReceivedChunk, RpcCodec, RpcRequest,
};
use super::columns::{
    column_chunks, error_answer, lookup_cost, AnswerBudget, ColumnLookup, ColumnReply,
    ColumnSource, Requested,
};
use super::limits::{
    shared_limiter, Admit, AnswerPermit, BookedChunks, ChunkPacer, ColumnPlaces, OutboundSemaphore,
    Reservation, RpcLimits, SharedLimiter,
};
use super::metrics::{RpcMetrics, StatusValidity};
use super::outbound::{check_request, outbound_failure, OutboundError, RangeError};
use super::responder::{PeerBytes, Responder, StreamedAnswer};
use super::{MAX_CONCURRENT_REQUESTS, REQUEST_TIMEOUT};
use crate::transport::Direction;
use consensus_types::EthSpec;
use ethswarm_proto::chain as pb;
use futures::future::{abortable, AbortHandle};
use futures::stream::{FuturesUnordered, StreamExt as _};
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::request_response::{
    self, InboundFailure, InboundRequestId, OutboundFailure, OutboundRequestId, ProtocolSupport,
    ResponseChannel,
};
use libp2p::swarm::{
    CloseConnection, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use p2p_wire::rpc::codec::ContextTable;
use p2p_wire::rpc::messages::{
    BlocksByRangeV2Request, ErrorMessage, Goodbye, MetaDataV3, Ping, StatusV2,
};
use p2p_wire::rpc::protocols::{
    column_request_error, Protocol, Request, Response, ResponseChunk, ResultCode,
    MAX_REQUEST_BLOCKS_DENEB,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep};

/// How long after a peer's last Ping ended (or it connected) the next one goes out \[est\]:
/// 15 s, as Lighthouse pings the peers it dialed, so two Pings to a peer are at least 15 s
/// apart, inside every client's Ping quota (Lighthouse allows 2 per 10 s).
///
/// It is also what keeps a quiet connection up: the swarm closes one with no open stream after
/// [`crate::transport::DEFAULT_IDLE_CONNECTION_TIMEOUT`] (30 s), twice this interval. A Ping
/// goes out when due, never waiting for a shared slot ([`Control::ping`]), so a connection is
/// never quiet for longer than the interval.
pub const PING_INTERVAL: Duration = Duration::from_secs(15);

/// How long a connection stays up after our answer to the peer's Goodbye went out \[est\]: the
/// peer, which said it is leaving, normally closes it at once; this bounds a peer that does not.
/// The graceful close that follows is bounded by [`CLOSE_DEADLINE`].
pub const GOODBYE_LINGER: Duration = Duration::from_secs(1);

/// How long a graceful close may take once it began before the connection is dropped
/// \[est\]: 5 s, the codec's deadline for one chunk.
///
/// A close writes what the muxer still holds, then the close frames, and the swarm waits for
/// it with no deadline of its own; a peer that stopped reading with our send buffer full would
/// hold it up for good, and the connection its slot. The probe swarm's muxers fail a close
/// still unfinished at this deadline ([`crate::transport::CloseDeadline`]), and the swarm then
/// drops the connection. It bounds every close the swarm begins: after the Goodbye linger, so
/// a connection is gone at most `GOODBYE_LINGER + CLOSE_DEADLINE` (6 s) after our answer to the
/// peer's Goodbye went out, and after our own Goodbye completed.
pub const CLOSE_DEADLINE: Duration = Duration::from_secs(5);

/// How long one column lookup may take before its request gets `2: ServerError` \[est\]: 2 s,
/// cl-chain's read deadline, so with [`RpcLimits::column_queue_wait`] before it the error chunk
/// still beats the requester's 5 s first-byte deadline.
pub const COLUMN_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// How many fresh reads our Status on a dial gets at most \[est\]: the first and 3 retries
/// ([`StatusSource::fresh`]; a reference CL drops a dialer that sends no Status).
pub const STATUS_SEND_ATTEMPTS: u32 = 4;

/// The wait before the first retry of a failed fresh Status read on a dial, doubled before
/// each next one \[est\]: 500 ms, 1 s, 2 s.
pub const STATUS_RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// How long after a dial a retry of its Status read may start \[est\]: 10 s, a few failed
/// reads of cl-chain's 2 s deadline and their backoff. With the reads' own deadline, the last
/// Status of a dial goes out at most this plus one read after it.
pub const STATUS_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// What our Status answer to a peer leaves of the requester's first-byte deadline
/// ([`ControlConfig::deadlines`]) for its write \[est\]: its fresh read ends that long before
/// the deadline, or the answer is `2: ServerError`. With the default quota and 2 Status streams
/// a token is due at most 4 s after the request, so the read keeps at least 500 ms.
pub const STATUS_ANSWER_SLACK: Duration = Duration::from_millis(500);

/// The `queue` label of column requests refused because the queue was full or no place freed
/// in time.
pub const COLUMN_QUEUE: &str = "rpc_column_queue";

/// Goodbye reason 1: client shut down.
pub const GOODBYE_CLIENT_SHUTDOWN: u64 = 1;
/// Goodbye reason 2: irrelevant network.
pub const GOODBYE_IRRELEVANT_NETWORK: u64 = 2;
/// Goodbye reason 3: fault/error.
pub const GOODBYE_FAULT: u64 = 3;

/// The Status we send and answer with.
///
/// `fork_digest` is `compute_fork_digest` at the wall-clock epoch; the finalized checkpoint and
/// head are what cl-chain reports (`ethswarm.chain.v1.ReqRespService/GetStatus`, see
/// [`status_from_chain`]). `None` while no good value is known: nothing is sent, and an
/// inbound Status is answered `2: ServerError`.
pub trait StatusSource: Send + Sync + 'static {
    /// Our Status now, as last known: what a peer's Status is judged against.
    fn status(&self) -> Option<StatusV2>;

    /// A fresh read of our Status for one Status that goes out (sent on a dial, or answered),
    /// if this source reads one: its `earliest_available_slot` is then what the column store
    /// serves from at that moment, never a cached value the store has since passed. The read
    /// bounds its own time; `None` from it means no Status: the request is answered
    /// `2: ServerError` and nothing is sent. Without one (the default), [`Self::status`] goes
    /// out at once.
    fn fresh(&self) -> Option<StatusLookup> {
        None
    }
}

/// A fresh read of our Status ([`StatusSource::fresh`]). It reads when first polled, not when
/// made: a Status on a dial is asked for at once and read once it has its outbound slot.
pub type StatusLookup = Pin<Box<dyn Future<Output = Option<StatusV2>> + Send>>;

/// Where one Status on a dial is in its fresh reads.
#[derive(Debug, Clone, Copy)]
struct StatusAttempt {
    /// The session with the peer it is for ([`PeerState::session`]): nothing of it reaches a
    /// later one.
    session: ConnectionId,
    /// The reads that failed so far.
    failed: u32,
    /// No read starts after this: [`STATUS_HANDSHAKE_DEADLINE`] after the dial.
    deadline: Instant,
}

impl StatusAttempt {
    /// The first read of a dial now, in `session`.
    fn first(session: ConnectionId) -> Self {
        Self {
            session,
            failed: 0,
            deadline: Instant::now() + STATUS_HANDSHAKE_DEADLINE,
        }
    }

    /// When the retry after this attempt's failed read is due, if one is within the bound:
    /// [`STATUS_SEND_ATTEMPTS`] reads, none starting past the deadline.
    fn retry(self, now: Instant) -> Option<(Instant, Self)> {
        let failed = self.failed + 1;
        if failed >= STATUS_SEND_ATTEMPTS {
            return None;
        }
        let due = now + STATUS_RETRY_BACKOFF * 2u32.pow(failed - 1);
        (due <= self.deadline).then_some((due, Self { failed, ..self }))
    }
}

/// What our Status answers hold at one moment, for tests ([`Control::status_backlog`]).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StatusBacklog {
    /// Peers' Status requests waiting for their token or their read.
    pub waiting: usize,
    /// Fresh Status reads running.
    pub reading: usize,
    /// Status answers handed to their streams and not yet sent or failed.
    pub answering: usize,
    /// How long until the peer's next Status token is due.
    pub token_in: Duration,
}

/// What a fresh Status read is for.
enum StatusUse {
    /// Our Status to `peer`, on a dial: the read holds the Status lane's slot.
    Send {
        peer: PeerId,
        attempt: StatusAttempt,
    },
    /// The answer to `peer`'s Status request `request_id`, waiting in its session's
    /// [`PeerState::status_waits`]: nothing if that request is gone by then.
    Answer {
        peer: PeerId,
        request_id: InboundRequestId,
    },
}

/// A peer's Status request we answer from a fresh read, from when it arrived until the
/// answer goes to its stream. It lives in its session's [`PeerState::status_waits`], so a
/// failed request or a closed connection drops it at once, and with it its token, which gives
/// back what is still ahead of it, and its read, which is cancelled if it started.
struct StatusWait<E: EthSpec> {
    protocol: Protocol,
    channel: ResponseChannel<Answer<E>>,
    theirs: StatusV2,
    /// The answer's token, taken on arrival: the read starts once it is due, and the answer
    /// goes out at it ([`super::codec::Answer::token`]).
    token: Reservation,
    /// The read, until it starts.
    read: Option<StatusLookup>,
    /// Cancels the read once it started, when the wait is dropped.
    reading: Option<CancelOnDrop>,
    /// The requester's first-byte deadline less [`STATUS_ANSWER_SLACK`]: the read ends by then,
    /// or the answer is `2: ServerError`.
    answer_by: Instant,
}

/// Cancels a started Status read when dropped: whatever removes its [`StatusWait`] ends the
/// read, so no read runs for a request that is gone.
struct CancelOnDrop(AbortHandle);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<E: EthSpec> std::fmt::Debug for StatusWait<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusWait")
            .field("protocol", &self.protocol)
            .field("due", &self.token.due())
            .field("reading", &self.read.is_none())
            .finish_non_exhaustive()
    }
}

/// A fresh Status read in flight, and what it is for.
type StatusRead = Pin<Box<dyn Future<Output = (StatusUse, Option<StatusV2>)> + Send>>;

/// Our MetaData, whose `seq_number` cl-chain owns (`ethswarm.chain.v1.ReqRespService/
/// GetMetadata`).
///
/// One call is one snapshot: the `seq_number` and the fields it numbers come from the same
/// state, so an answer never pairs a new `seq_number` with old fields, or the reverse. The
/// owner changes them together ([`SharedMetaData::set`]); `custody_group_count` is the `cgc`
/// our ENR advertises (cl-discv5 builds the record; cl-p2p does not link it).
pub trait MetaDataSource: Send + Sync + 'static {
    /// Our MetaData now.
    fn metadata(&self) -> MetaDataV3;
}

/// A [`StatusSource`] the owner keeps current: the last good Status it was given.
#[derive(Debug, Default)]
pub struct SharedStatus(RwLock<Option<StatusV2>>);

impl SharedStatus {
    /// A source holding `status`.
    #[must_use]
    pub fn new(status: Option<StatusV2>) -> Self {
        Self(RwLock::new(status))
    }

    /// Replaces the Status.
    pub fn set(&self, status: StatusV2) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(status);
    }
}

impl StatusSource for SharedStatus {
    fn status(&self) -> Option<StatusV2> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// A [`MetaDataSource`] the owner keeps current: the last MetaData it was given, every field
/// replaced at once.
#[derive(Debug)]
pub struct SharedMetaData(RwLock<MetaDataV3>);

impl SharedMetaData {
    /// A source holding `metadata`.
    #[must_use]
    pub fn new(metadata: MetaDataV3) -> Self {
        Self(RwLock::new(metadata))
    }

    /// Replaces the MetaData, `seq_number` and fields together.
    pub fn set(&self, metadata: MetaDataV3) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = metadata;
    }
}

impl MetaDataSource for SharedMetaData {
    fn metadata(&self) -> MetaDataV3 {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Why a chain.v1 `GetStatusResponse` is not a Status.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainStatusError {
    /// A bytes field has the wrong length.
    #[error("{field} is {len} bytes, want {want}")]
    Length {
        field: &'static str,
        len: usize,
        want: usize,
    },
    /// `finalized` is missing.
    #[error("no finalized checkpoint")]
    NoFinalized,
}

fn fixed<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N], ChainStatusError> {
    bytes.try_into().map_err(|_| ChainStatusError::Length {
        field,
        len: bytes.len(),
        want: N,
    })
}

/// Our Status from cl-chain's `GetStatusResponse` (`proto/ethswarm/chain/v1/reqresp.proto`).
///
/// # Errors
///
/// A missing checkpoint or a field of the wrong length: the response breaks the contract.
pub fn status_from_chain(response: &pb::GetStatusResponse) -> Result<StatusV2, ChainStatusError> {
    let finalized = response
        .finalized
        .as_ref()
        .ok_or(ChainStatusError::NoFinalized)?;
    Ok(StatusV2 {
        fork_digest: fixed("fork_digest", &response.fork_digest)?,
        finalized_root: fixed::<32>("finalized.root", &finalized.root)?.into(),
        finalized_epoch: finalized.epoch,
        head_root: fixed::<32>("head_root", &response.head_root)?.into(),
        head_slot: response.head_slot,
        earliest_available_slot: response.earliest_available_slot,
    })
}

/// The verdict on a peer's Status (`phase0/p2p-interface.md` L1437–1449).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relevance {
    /// Same fork digest, no conflicting finalized checkpoint.
    Relevant,
    /// Another fork digest: another network or fork.
    WrongForkDigest,
    /// The peer finalized another root at our finalized epoch: the chains are disjoint.
    FinalizedConflict,
}

impl Relevance {
    /// Whether the peer is Status-valid.
    #[must_use]
    pub fn is_relevant(self) -> bool {
        self == Self::Relevant
    }
}

/// Judges `theirs` against `ours`.
///
/// The only finalized root we know is our own, so a conflict is provable only at our finalized
/// epoch; a peer finalized before or past it is not judged on its root.
#[must_use]
pub fn relevance(ours: &StatusV2, theirs: &StatusV2) -> Relevance {
    if theirs.fork_digest != ours.fork_digest {
        Relevance::WrongForkDigest
    } else if theirs.finalized_epoch == ours.finalized_epoch
        && theirs.finalized_root != ours.finalized_root
    {
        Relevance::FinalizedConflict
    } else {
        Relevance::Relevant
    }
}

/// What [`Control`] answers with.
#[derive(Clone)]
pub struct ControlConfig {
    /// Our Status.
    pub status: Arc<dyn StatusSource>,
    /// Our MetaData, `custody_group_count` the `cgc` our ENR advertises.
    pub metadata: Arc<dyn MetaDataSource>,
    /// Fork digest → fork, for the context bytes of block responses.
    pub contexts: Arc<ContextTable>,
    /// The codec's deadlines.
    pub deadlines: Deadlines,
    /// The rate limits and the outbound queue (see the module docs).
    pub limits: RpcLimits,
    /// How often each connected peer is pinged: [`PING_INTERVAL`]; zero pings none.
    pub ping_interval: Duration,
    /// Where the column answers come from (cl-chain); `None` answers every column request
    /// `3: ResourceUnavailable`.
    pub columns: Option<Arc<dyn ColumnSource>>,
}

impl std::fmt::Debug for ControlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlConfig")
            .field("status", &self.status.status())
            .field("metadata", &self.metadata.metadata())
            .field("deadlines", &self.deadlines)
            .field("limits", &self.limits)
            .field("ping_interval", &self.ping_interval)
            .field("columns", &self.columns.is_some())
            .finish_non_exhaustive()
    }
}

/// One protocol both ways: an inbound-only and an outbound-only `request_response` behaviour.
///
/// `request_response` caps the streams of a connection per behaviour, inbound and outbound
/// together. Apart, each direction has its own [`MAX_CONCURRENT_REQUESTS`]: our open requests
/// never take a slot of the peer's (or make ours fail while the peer has two open), and a
/// peer's third concurrent stream is reset, whatever we have open.
///
/// The inbound side writes [`Answer`]s through [`InboundCodec`], chunk by chunk under the
/// requester's quota; the outbound side reads responses as `Vec<ReceivedChunk>`.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
pub struct Duplex<E: EthSpec> {
    /// Serves the peer's requests.
    pub inbound: request_response::Behaviour<InboundCodec<E>>,
    /// Sends ours.
    pub outbound: request_response::Behaviour<RpcCodec<E>>,
}

impl<E: EthSpec> Duplex<E> {
    /// `protocol` both ways, each direction on its own clone of `codec`.
    fn new(protocol: Protocol, codec: &RpcCodec<E>) -> Self {
        let config = || {
            request_response::Config::default()
                .with_request_timeout(REQUEST_TIMEOUT)
                .with_max_concurrent_streams(MAX_CONCURRENT_REQUESTS)
        };
        Self {
            inbound: request_response::Behaviour::with_codec(
                InboundCodec::new(codec.clone()),
                [(protocol, ProtocolSupport::Inbound)],
                config(),
            ),
            outbound: request_response::Behaviour::with_codec(
                codec.clone(),
                [(protocol, ProtocolSupport::Outbound)],
                config(),
            ),
        }
    }

    /// Sends `request` to `peer`, dialing it if need be.
    pub fn send_request(&mut self, peer: &PeerId, request: RpcRequest) -> OutboundRequestId {
        self.outbound.send_request(peer, request)
    }

    /// Answers the request of `channel` (unpaced, from plain chunks).
    ///
    /// # Errors
    ///
    /// The answer back if the stream is gone.
    pub fn send_response(
        &mut self,
        channel: ResponseChannel<Answer<E>>,
        answer: impl Into<Answer<E>>,
    ) -> Result<(), Answer<E>> {
        self.inbound.send_response(channel, answer.into())
    }
}

/// One [`Duplex`] per protocol.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
pub struct Protocols<E: EthSpec> {
    pub status: Duplex<E>,
    pub metadata: Duplex<E>,
    pub ping: Duplex<E>,
    pub goodbye: Duplex<E>,
    pub blocks_by_range: Duplex<E>,
    pub data_columns_by_range: Duplex<E>,
    pub data_columns_by_root: Duplex<E>,
}

impl<E: EthSpec> Protocols<E> {
    /// Every protocol, its codec looking context bytes up in `contexts`, under `deadlines`,
    /// counting passed deadlines in `metrics` if given.
    #[must_use]
    pub fn new(
        contexts: Arc<ContextTable>,
        deadlines: Deadlines,
        metrics: Option<RpcMetrics>,
    ) -> Self {
        let codec = RpcCodec::new(contexts, deadlines);
        let codec = match metrics {
            Some(m) => codec.with_metrics(m),
            None => codec,
        };
        Self {
            status: Duplex::new(Protocol::StatusV2, &codec),
            metadata: Duplex::new(Protocol::MetaDataV3, &codec),
            ping: Duplex::new(Protocol::PingV1, &codec),
            goodbye: Duplex::new(Protocol::GoodbyeV1, &codec),
            blocks_by_range: Duplex::new(Protocol::BlocksByRangeV2, &codec),
            data_columns_by_range: Duplex::new(Protocol::DataColumnsByRangeV1, &codec),
            data_columns_by_root: Duplex::new(Protocol::DataColumnsByRootV1, &codec),
        }
    }

    /// The behaviour of `protocol`.
    pub fn of(&mut self, protocol: Protocol) -> &mut Duplex<E> {
        match protocol {
            Protocol::StatusV2 => &mut self.status,
            Protocol::MetaDataV3 => &mut self.metadata,
            Protocol::PingV1 => &mut self.ping,
            Protocol::GoodbyeV1 => &mut self.goodbye,
            Protocol::BlocksByRangeV2 => &mut self.blocks_by_range,
            Protocol::DataColumnsByRangeV1 => &mut self.data_columns_by_range,
            Protocol::DataColumnsByRootV1 => &mut self.data_columns_by_root,
        }
    }
}

/// Which exchange carried a peer's Status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusVia {
    /// The peer's request: it sent its Status, and we answered with ours.
    Request,
    /// The peer's response to our Status request.
    Response,
}

/// What [`Control`] reports.
#[derive(Debug, Clone)]
pub enum ControlEvent {
    /// A peer's Status (its request, or its response to ours: `via`) was judged.
    Status {
        peer: PeerId,
        status: StatusV2,
        relevance: Relevance,
        via: StatusVia,
    },
    /// A peer answered our Ping with its `seq_number`.
    Pong { peer: PeerId, seq_number: u64 },
    /// A peer's MetaData arrived. Boxed: its inline bitvectors are larger than any other
    /// variant.
    MetaData {
        peer: PeerId,
        metadata: Box<MetaDataV3>,
    },
    /// A peer said Goodbye. Logged as the `goodbye_received` event too.
    GoodbyeReceived {
        peer: PeerId,
        reason: u64,
        status_valid: StatusValidity,
        direction: Direction,
        at: SystemTime,
    },
    /// Our Status, the answer to the peer's Status request, was written to its stream: the
    /// peer's side of the handshake is done (a `2: ServerError` answer is not this).
    StatusAnswered { peer: PeerId },
    /// One of our BlocksByRange requests ended: its outcome waits in [`Control::take_blocks`].
    BlocksByRange { peer: PeerId, ticket: BlocksTicket },
}

/// Names one of our BlocksByRange requests ([`Control::request_blocks`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlocksTicket(u64);

/// How one of our BlocksByRange requests ended: the response's chunks, or why there are none.
pub type BlocksOutcome<E> = Result<Vec<ReceivedChunk<E>>, OutboundError>;

/// One of our requests, waiting for a slot of its protocol or holding one.
struct Outgoing {
    peer: PeerId,
    request: Pending,
    /// The ticket of a BlocksByRange request, for its outcome.
    ticket: Option<BlocksTicket>,
}

/// What one of our requests sends once it has its slot.
enum Pending {
    /// This request.
    Request(Request),
    /// Our Status, from this read, made once the request has its slot: what the store serves
    /// from when it goes out, not when it was queued.
    FreshStatus {
        read: StatusLookup,
        attempt: StatusAttempt,
    },
}

impl Pending {
    fn protocol(&self) -> Protocol {
        match self {
            Self::Request(request) => request.protocol(),
            Self::FreshStatus { .. } => Protocol::StatusV2,
        }
    }

    fn is_goodbye(&self) -> bool {
        matches!(self, Self::Request(Request::Goodbye(_)))
    }
}

/// What we know of one connected peer.
#[derive(Debug)]
struct PeerState<E: EthSpec> {
    /// The connection that began this session with the peer, which lasts while any connection
    /// to it does: a number no later session has. Our Status reads and retries carry it, so
    /// one that outlives its session never reaches the next.
    session: ConnectionId,
    direction: Direction,
    /// The address block of its remote IP, for the per-IP column answer places.
    ip: Option<super::answer_bucket::AnswerBucket>,
    /// The verdict on its last judged Status.
    status_valid: Option<bool>,
    /// Its last judged Status.
    status: Option<StatusV2>,
    /// The `seq_number` of its last MetaData.
    metadata_seq: Option<u64>,
    /// Whether our GetMetaData request is open (in flight or waiting for a slot).
    metadata_open: bool,
    /// The highest `seq_number` the peer announced while our request was open, if above the
    /// one known: asked for once more when the open request ends with an older MetaData.
    metadata_announced: Option<u64>,
    /// Whether we sent it a Goodbye.
    goodbye_sent: bool,
    /// Whether it sent us one.
    goodbye_received: bool,
    /// When its connection closes: a linger after our answer to its Goodbye went out.
    close_at: Option<Instant>,
    /// Our Ping to it in flight, if one is: never more than one.
    ping: Option<OutboundRequestId>,
    /// When our next Ping to it is due: an interval after the last one ended.
    next_ping: Instant,
    /// The retry of our Status after a failed fresh read on a dial, and when it is due.
    status_retry: Option<(Instant, StatusAttempt)>,
    /// Its Status requests we answer from a fresh read, until each answer goes to its stream.
    status_waits: HashMap<InboundRequestId, StatusWait<E>>,
    /// The bytes its streamed answers may hold queued ([`RpcLimits::max_queued_bytes_per_peer`]).
    queued_bytes: PeerBytes,
}

impl<E: EthSpec> PeerState<E> {
    /// Whether either side said Goodbye: nothing more goes out but our own Goodbye.
    fn leaving(&self) -> bool {
        self.goodbye_sent || self.goodbye_received
    }
}

/// A column answer ready to go out: its request's stream, chunks, tokens (settled by the
/// stream's writer) and place.
struct ColumnAnswer<E: EthSpec> {
    protocol: Protocol,
    channel: ResponseChannel<Answer<E>>,
    chunks: Vec<ReceivedChunk<E>>,
    booked: BookedChunks,
    permit: AnswerPermit,
}

/// The chunks a column lookup's answer goes out as, and their SSZ bytes: its reply
/// (`2: ServerError` past [`COLUMN_LOOKUP_TIMEOUT`]) held to `requested` and cut to `budget`
/// and to the whole blocks a requester reading at the answer's pace from the lookup's end has
/// by the end of the window of `permit`'s place, given when each of `booked`'s tokens is due
/// ([`column_chunks`], [`BookedChunks::reader`]). The stream's writer cuts it again from when
/// it starts, and settles `booked` then ([`super::codec::Answer`]).
pub(crate) async fn answer_columns<E: EthSpec>(
    lookup: ColumnLookup,
    requested: &Requested,
    contexts: &ContextTable,
    budget: AnswerBudget,
    metrics: &RpcMetrics,
    permit: &AnswerPermit,
    booked: &BookedChunks,
) -> (Vec<ReceivedChunk<E>>, usize) {
    let reply = tokio::time::timeout(COLUMN_LOOKUP_TIMEOUT, lookup)
        .await
        .unwrap_or_else(|_| ColumnReply::server_error("column lookup timed out"));
    let reader = booked.reader(permit.held_since(), Instant::now());
    column_chunks(reply, requested, contexts, budget, &reader, metrics)
}

/// The tokens column `request`, naming `requested`, books when it is admitted: as many
/// sidecars as it names, at most an answer's `share` of the window and the `deliverable` tokens
/// its bucket still delivers in it, and at least its largest block
/// ([`Requested::largest_block`]), which always goes out, so every chunk sent is paid for, and
/// its lookup's cost ([`lookup_cost`]), which stays charged.
pub(crate) fn column_tokens(
    request: &Request,
    requested: &Requested,
    share: u64,
    deliverable: u64,
) -> u64 {
    let max_chunks = request.max_response_chunks();
    max_chunks
        .min(share)
        .min(deliverable)
        .max(requested.largest_block().min(max_chunks))
        .max(lookup_cost(request).min(max_chunks))
}

/// A column request admitted and waiting for its tokens or a place.
struct QueuedColumn<E: EthSpec> {
    peer: PeerId,
    protocol: Protocol,
    channel: ResponseChannel<Answer<E>>,
    request: Request,
    booked: BookedChunks,
    /// When it was admitted.
    since: Instant,
}

impl<E: EthSpec> QueuedColumn<E> {
    /// When it may start waiting for a place: its first token due, and admitted.
    fn ready_at(&self) -> Instant {
        self.booked.ready_at().max(self.since)
    }
}

/// The probe's req/resp behaviour (see the module docs).
pub struct Control<E: EthSpec> {
    inner: Protocols<E>,
    cfg: ControlConfig,
    metrics: RpcMetrics,
    peers: HashMap<PeerId, PeerState<E>>,
    /// Our Goodbye requests still open; the connection closes when each completes.
    goodbyes: HashMap<OutboundRequestId, PeerId>,
    /// Our answers to peers' Goodbyes still being written; the connection closes when each is
    /// sent or fails.
    goodbye_answers: HashMap<InboundRequestId, PeerId>,
    /// Our requests in flight, each holding a slot of its protocol. Keyed by protocol too:
    /// every protocol's behaviour numbers its requests on its own, so IDs repeat across them.
    in_flight: HashSet<(Protocol, OutboundRequestId)>,
    /// The outbound slots and wait queues.
    outbound: OutboundSemaphore<Outgoing>,
    /// The ticket of each of our BlocksByRange requests in flight, by the BlocksByRange
    /// behaviour's request ID (each behaviour numbers its own).
    blocks_in_flight: HashMap<OutboundRequestId, BlocksTicket>,
    /// Every ticket neither taken nor cancelled: `None` while its request is open.
    blocks: HashMap<BlocksTicket, Option<BlocksOutcome<E>>>,
    next_ticket: u64,
    /// Every peer's response quota, shared with the inbound streams' writers.
    limiter: SharedLimiter,
    /// Wakes the behaviour when the next Ping or Goodbye close is due; `None` with neither.
    timer: Option<Pin<Box<Sleep>>>,
    pending: VecDeque<ToSwarm<ControlEvent, THandlerInEvent<Protocols<E>>>>,
    /// The peers' Status requests we are answering with our Status, until the answer is sent
    /// ([`ControlEvent::StatusAnswered`]) or fails.
    status_answers: HashSet<InboundRequestId>,
    /// Fresh Status reads in flight ([`StatusSource::fresh`]).
    status_reads: FuturesUnordered<StatusRead>,
    /// Column lookups open, each on its own task, each holding a place: `None` from one whose
    /// stream closed during it.
    lookups: FuturesUnordered<JoinHandle<Option<ColumnAnswer<E>>>>,
    /// The column answers' places, shared with the streams' writers.
    places: ColumnPlaces,
    /// Column requests waiting for their tokens or a place, in arrival order.
    column_queue: VecDeque<QueuedColumn<E>>,
    /// Wakes the behaviour when the next queued column request is due or times out.
    queue_timer: Option<Pin<Box<Sleep>>>,
    /// Serves BlocksByRange with streamed answers; `None` answers `3: ResourceUnavailable`.
    blocks_responder: Option<Arc<dyn Responder<E>>>,
    /// The streamed answers' slots ([`RpcLimits::max_inbound_streams`]), over every peer.
    streams: Arc<Semaphore>,
}

/// The `ErrorMessage` of `text`, cut at 256 bytes.
fn error_message(text: &str) -> ErrorMessage {
    let bytes = text.as_bytes();
    let cut = &bytes[..bytes
        .len()
        .min(p2p_wire::rpc::messages::MAX_ERROR_MESSAGE_LEN)];
    ErrorMessage::new(cut.to_vec()).unwrap_or_default()
}

fn error_chunk<E: EthSpec>(code: ResultCode, text: &str) -> Vec<ReceivedChunk<E>> {
    vec![ReceivedChunk {
        context: None,
        chunk: ResponseChunk::Error {
            code,
            message: error_message(text),
        },
    }]
}

fn success_chunk<E: EthSpec>(response: Response<E>) -> Vec<ReceivedChunk<E>> {
    vec![ReceivedChunk {
        context: None,
        chunk: ResponseChunk::Success(response),
    }]
}

/// The one success response of `chunks`, if that is what they are.
fn single_success<E: EthSpec>(chunks: Vec<ReceivedChunk<E>>) -> Option<Response<E>> {
    let mut chunks = chunks.into_iter();
    match (chunks.next(), chunks.next()) {
        (
            Some(ReceivedChunk {
                chunk: ResponseChunk::Success(response),
                ..
            }),
            None,
        ) => Some(response),
        _ => None,
    }
}

/// Why a peer's BeaconBlocksByRange request is semantically invalid, if it is: `step` 0 ("must
/// be set to 1", `phase0/p2p-interface.md` L1514), or a `count` above
/// [`MAX_REQUEST_BLOCKS_DENEB`] ("No more than `MAX_REQUEST_BLOCKS_DENEB` may be requested at a
/// time", `deneb/p2p-interface.md` L876). A `step` above 1 is not refused: a responder may
/// answer it with a single block during the deprecation (`phase0` L1514–1515).
fn out_of_bounds(range: &BlocksByRangeV2Request) -> Option<String> {
    if range.step == 0 {
        Some("step 0, must be 1".to_owned())
    } else if range.count > MAX_REQUEST_BLOCKS_DENEB {
        Some(format!(
            "count {} above MAX_REQUEST_BLOCKS_DENEB {MAX_REQUEST_BLOCKS_DENEB}",
            range.count
        ))
    } else {
        None
    }
}

fn unix_ms(at: SystemTime) -> u128 {
    at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis())
}

impl<E: EthSpec> Control<E> {
    /// The behaviour answering with `cfg`, counting in `metrics`.
    #[must_use]
    pub fn new(cfg: ControlConfig, metrics: RpcMetrics) -> Self {
        metrics.queues().declare(COLUMN_QUEUE);
        let places = ColumnPlaces::new(
            cfg.limits.max_column_answers,
            cfg.limits.max_column_answers_per_ip,
            Some(metrics.clone()),
        );
        let streams = cfg.limits.max_inbound_streams.min(Semaphore::MAX_PERMITS);
        let streams = Arc::new(Semaphore::new(streams));
        Self {
            inner: Protocols::new(
                Arc::clone(&cfg.contexts),
                cfg.deadlines,
                Some(metrics.clone()),
            ),
            outbound: OutboundSemaphore::new(
                cfg.limits.outbound_queue_len,
                metrics.queues().clone(),
            ),
            limiter: shared_limiter(cfg.limits.rate),
            cfg,
            metrics,
            peers: HashMap::new(),
            goodbyes: HashMap::new(),
            goodbye_answers: HashMap::new(),
            in_flight: HashSet::new(),
            blocks_in_flight: HashMap::new(),
            blocks: HashMap::new(),
            next_ticket: 0,
            timer: None,
            pending: VecDeque::new(),
            status_answers: HashSet::new(),
            status_reads: FuturesUnordered::new(),
            lookups: FuturesUnordered::new(),
            places,
            column_queue: VecDeque::new(),
            queue_timer: None,
            blocks_responder: None,
            streams,
        }
    }

    /// The same behaviour, serving BlocksByRange with `responder`'s streamed answers (see the
    /// module docs) instead of `3: ResourceUnavailable`.
    #[must_use]
    pub fn with_blocks_responder(mut self, responder: Arc<dyn Responder<E>>) -> Self {
        self.blocks_responder = Some(responder);
        self
    }

    /// What our Status answers hold now ([`StatusBacklog`]).
    #[cfg(test)]
    pub(super) fn status_backlog(&self, peer: PeerId) -> StatusBacklog {
        let now = Instant::now();
        let mut limiter = self
            .limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A look at the bucket: charged and given straight back.
        let charge = limiter.charge(peer, Protocol::StatusV2, now);
        let due = charge.due();
        limiter.refund(peer, Protocol::StatusV2, charge, now);
        StatusBacklog {
            waiting: self.peers.values().map(|s| s.status_waits.len()).sum(),
            reading: self.status_reads.len(),
            answering: self.status_answers.len(),
            token_in: due.saturating_duration_since(now),
        }
    }

    /// Our MetaData now: one snapshot of the [`MetaDataSource`].
    #[must_use]
    pub fn local_metadata(&self) -> MetaDataV3 {
        self.cfg.metadata.metadata()
    }

    /// Sends `request` to `peer` in a free slot of its protocol, or queues it; `false` if the
    /// queue IGNOREd it.
    fn submit(&mut self, peer: PeerId, request: Request) -> bool {
        self.submit_outgoing(Outgoing {
            peer,
            request: Pending::Request(request),
            ticket: None,
        })
    }

    fn submit_outgoing(&mut self, outgoing: Outgoing) -> bool {
        let protocol = outgoing.request.protocol();
        if self.leaving(outgoing.peer) && !outgoing.request.is_goodbye() {
            tracing::debug!(peer = %outgoing.peer, %protocol, "after a Goodbye: request not sent");
            return false;
        }
        let taken = match self.outbound.submit(protocol, outgoing) {
            Admit::Start(outgoing) => {
                self.dispatch(outgoing);
                true
            }
            Admit::Queued => true,
            Admit::Ignored(Outgoing { peer, request, .. }) => {
                tracing::debug!(%peer, %protocol, "outbound queue full: request ignored");
                if request.is_goodbye() {
                    self.close(peer);
                }
                false
            }
        };
        self.metrics
            .set_outbound_inflight(protocol, self.outbound.in_flight(protocol));
        taken
    }

    /// Sends `outgoing`, which holds a slot of its protocol; a Status read fresh starts its
    /// read now, holding the slot until it is sent ([`Self::poll_status_reads`]).
    fn dispatch(&mut self, outgoing: Outgoing) {
        let Outgoing {
            peer,
            request,
            ticket,
        } = outgoing;
        let request = match request {
            Pending::Request(request) => request,
            Pending::FreshStatus { read, attempt } => {
                let to = StatusUse::Send { peer, attempt };
                self.status_reads
                    .push(Box::pin(async move { (to, read.await) }));
                return;
            }
        };
        self.send_now(peer, request, ticket);
    }

    /// Sends `request` to `peer` in the slot of its protocol it holds.
    fn send_now(&mut self, peer: PeerId, request: Request, ticket: Option<BlocksTicket>) {
        let protocol = request.protocol();
        let goodbye = matches!(request, Request::Goodbye(_));
        let id = self.inner.of(protocol).send_request(&peer, request.into());
        self.in_flight.insert((protocol, id));
        if goodbye {
            self.goodbyes.insert(id, peer);
        }
        if let Some(ticket) = ticket {
            self.blocks_in_flight.insert(id, ticket);
        }
    }

    /// Request `id` of `protocol` finished: its slot goes to the next waiting request of a
    /// connected peer.
    fn finished(&mut self, protocol: Protocol, id: OutboundRequestId) {
        if !self.in_flight.remove(&(protocol, id)) {
            return;
        }
        if protocol == Protocol::PingV1 {
            // Pings hold no shared slot ([`Control::ping`]).
            self.metrics
                .set_outbound_inflight(protocol, self.pings_in_flight());
            return;
        }
        self.release(protocol);
    }

    /// A slot of `protocol` is free again: it goes to the next waiting request of a connected
    /// peer.
    fn release(&mut self, protocol: Protocol) {
        while let Some(next) = self.outbound.release(protocol) {
            let peer = next.peer;
            let refusal = match self.peers.get(&peer) {
                // Nothing but our Goodbye goes out once either side said Goodbye.
                Some(state) if state.leaving() && !next.request.is_goodbye() => {
                    tracing::debug!(%peer, %protocol, "after our Goodbye: the waiting request is dropped");
                    Some(OutboundError::Disconnected)
                }
                // The peer's Status may have changed while the request waited.
                Some(_) => match &next.request {
                    Pending::Request(Request::BlocksByRange(range)) => {
                        self.servable(peer, range).err()
                    }
                    // A Status read of an earlier session, or one past its dial's deadline.
                    Pending::FreshStatus { attempt, .. } => self
                        .status_lapsed(peer, attempt)
                        .then_some(OutboundError::Disconnected),
                    Pending::Request(_) => None,
                },
                None => {
                    tracing::debug!(%peer, %protocol, "the peer left: its waiting request is dropped");
                    Some(OutboundError::Disconnected)
                }
            };
            let Some(error) = refusal else {
                self.dispatch(next);
                break;
            };
            if let Some(ticket) = next.ticket {
                self.blocks_done(peer, ticket, Err(error));
            }
        }
        self.metrics
            .set_outbound_inflight(protocol, self.outbound.in_flight(protocol));
    }

    /// Requests the blocks of `request` from `peer` in a free slot of the protocol, or queues
    /// the request; its outcome is kept for [`Control::take_blocks`] under the returned ticket.
    ///
    /// The request must start at or after the peer's `earliest_available_slot`, by its last
    /// Status, which must be valid (`fulu/p2p-interface.md` L552–561); that is checked again
    /// when a waiting request's turn comes, and a request that fails it then ends with the
    /// refusal.
    ///
    /// # Errors
    ///
    /// [`RangeError::Outbound`] with [`OutboundError::InvalidRequest`] for a request outside the
    /// protocol's limits or the peer's range, or to a peer without a valid Status; with
    /// [`OutboundError::Disconnected`] once either side said Goodbye; [`RangeError::Ignored`] if
    /// the wait queue is full. None is sent.
    pub fn request_blocks(
        &mut self,
        peer: PeerId,
        request: BlocksByRangeV2Request,
    ) -> Result<BlocksTicket, RangeError> {
        check_request(&request)?;
        self.servable(peer, &request)?;
        if self.leaving(peer) {
            return Err(OutboundError::Disconnected.into());
        }
        let ticket = BlocksTicket(self.next_ticket);
        self.next_ticket += 1;
        self.blocks.insert(ticket, None);
        let outgoing = Outgoing {
            peer,
            request: Pending::Request(Request::BlocksByRange(request)),
            ticket: Some(ticket),
        };
        if self.submit_outgoing(outgoing) {
            Ok(ticket)
        } else {
            self.blocks.remove(&ticket);
            Err(RangeError::Ignored)
        }
    }

    /// Whether either side said Goodbye to `peer`: nothing but our Goodbye goes out to it.
    fn leaving(&self, peer: PeerId) -> bool {
        self.peers.get(&peer).is_some_and(PeerState::leaving)
    }

    /// Whether `peer` can serve `request` by its last Status: valid, with
    /// `earliest_available_slot` at or before `start_slot`.
    fn servable(
        &self,
        peer: PeerId,
        request: &BlocksByRangeV2Request,
    ) -> Result<(), OutboundError> {
        let status = self
            .peers
            .get(&peer)
            .filter(|state| state.status_valid == Some(true))
            .and_then(|state| state.status.as_ref());
        match status {
            None => Err(OutboundError::InvalidRequest(format!(
                "peer {peer} has no valid Status"
            ))),
            Some(s) if request.start_slot < s.earliest_available_slot => {
                Err(OutboundError::InvalidRequest(format!(
                    "start_slot {} is before the peer's earliest_available_slot {}",
                    request.start_slot, s.earliest_available_slot
                )))
            }
            Some(_) => Ok(()),
        }
    }

    /// The outcome of `ticket`'s request once it ended, taken out; `None` while it is open (or
    /// for a ticket taken or cancelled before).
    pub fn take_blocks(&mut self, ticket: BlocksTicket) -> Option<BlocksOutcome<E>> {
        match self.blocks.get(&ticket) {
            Some(Some(_)) => self.blocks.remove(&ticket).flatten(),
            _ => None,
        }
    }

    /// Forgets `ticket`: an outcome kept or still to come is dropped.
    pub fn cancel_blocks(&mut self, ticket: BlocksTicket) {
        self.blocks.remove(&ticket);
    }

    /// The outcome of `ticket`'s request, kept unless the ticket was cancelled.
    fn blocks_done(&mut self, peer: PeerId, ticket: BlocksTicket, outcome: BlocksOutcome<E>) {
        match self.blocks.get_mut(&ticket) {
            Some(slot) => {
                *slot = Some(outcome);
                self.emit(ControlEvent::BlocksByRange { peer, ticket });
            }
            None => tracing::debug!(%peer, "a cancelled BlocksByRange request ended: dropped"),
        }
    }

    /// Every peer whose last Status was valid, with that Status, by peer ID.
    #[must_use]
    pub fn status_valid_peers(&self) -> Vec<(PeerId, StatusV2)> {
        let mut peers: Vec<(PeerId, StatusV2)> = self
            .peers
            .iter()
            .filter(|(_, state)| state.status_valid == Some(true))
            .filter_map(|(peer, state)| state.status.clone().map(|s| (*peer, s)))
            .collect();
        peers.sort_unstable_by_key(|(peer, _)| *peer);
        peers
    }

    /// Sends our Status to `peer`; `false` (and nothing sent) while we have none, or if the
    /// outbound queue IGNOREd it. A source that reads a fresh Status ([`StatusSource::fresh`])
    /// is read once the request has its slot, and sent once the read ends: `true` means it was
    /// asked for. A read that fails is retried within the bound of
    /// [`STATUS_SEND_ATTEMPTS`] and [`STATUS_HANDSHAKE_DEADLINE`] while the peer stays.
    pub fn send_status(&mut self, peer: PeerId) -> bool {
        let Some(session) = self.peers.get(&peer).map(|state| state.session) else {
            tracing::debug!(%peer, "not connected: no Status sent");
            return false;
        };
        self.send_status_attempt(peer, StatusAttempt::first(session))
    }

    /// Whether `attempt`, a fresh Status read for `peer`, may no longer start: its session
    /// ended (a later connection has its own), or it would start past its dial's
    /// [`STATUS_HANDSHAKE_DEADLINE`]. Logged when it may not.
    fn status_lapsed(&self, peer: PeerId, attempt: &StatusAttempt) -> bool {
        if self
            .peers
            .get(&peer)
            .is_none_or(|state| state.session != attempt.session)
        {
            tracing::debug!(%peer, "our Status read is of a connection gone: none sent");
            return true;
        }
        if Instant::now() > attempt.deadline {
            tracing::warn!(
                %peer,
                reads = attempt.failed,
                "no fresh Status of ours within the handshake bound: none sent"
            );
            return true;
        }
        false
    }

    fn send_status_attempt(&mut self, peer: PeerId, attempt: StatusAttempt) -> bool {
        if let Some(read) = self.cfg.status.fresh() {
            if self.status_lapsed(peer, &attempt) {
                return false;
            }
            return self.submit_outgoing(Outgoing {
                peer,
                request: Pending::FreshStatus { read, attempt },
                ticket: None,
            });
        }
        let Some(ours) = self.cfg.status.status() else {
            tracing::debug!(%peer, "no Status of ours yet: none sent");
            return false;
        };
        self.submit(peer, Request::Status(ours))
    }

    /// Pings `peer` with our `seq_number`, unless a Ping to it is in flight or either side said
    /// Goodbye.
    ///
    /// A Ping takes no slot of the shared outbound lane: it goes out at once, at most one per
    /// peer. The lane's 2 slots are shared by every peer, and a Ping waiting there opens no
    /// stream, so the connection's idle timer would run on; at 160 peers the 10.7 Pings/s would
    /// not fit it once Pings take over ~190 ms, and a few peers that never answer would hold
    /// it. One Ping per peer stays within `MAX_CONCURRENT_REQUESTS` ("The requester MUST NOT
    /// make more than `MAX_CONCURRENT_REQUESTS` concurrent requests with the same protocol
    /// ID", `phase0/p2p-interface.md` L1228–1229). That limit is per peer: it is what each
    /// responder counts ("peers that concurrently open more than `MAX_CONCURRENT_REQUESTS`
    /// streams for the same request type", L1310–1312).
    pub fn ping(&mut self, peer: PeerId) {
        let Some(state) = self.peers.get(&peer) else {
            return;
        };
        if state.leaving() || state.ping.is_some() {
            return;
        }
        let ours = self.local_metadata().seq_number;
        let request = Request::Ping(Ping(ours));
        let id = self
            .inner
            .of(Protocol::PingV1)
            .send_request(&peer, request.into());
        self.in_flight.insert((Protocol::PingV1, id));
        if let Some(state) = self.peers.get_mut(&peer) {
            state.ping = Some(id);
        }
        self.metrics
            .set_outbound_inflight(Protocol::PingV1, self.pings_in_flight());
    }

    /// Our Pings in flight, at most one per peer.
    fn pings_in_flight(&self) -> usize {
        self.in_flight
            .iter()
            .filter(|(protocol, _)| *protocol == Protocol::PingV1)
            .count()
    }

    /// Our Ping `id` to `peer` ended: the next is due an interval from now.
    fn ping_done(&mut self, peer: PeerId, id: OutboundRequestId) {
        if let Some(state) = self.peers.get_mut(&peer) {
            if state.ping == Some(id) {
                state.ping = None;
                state.next_ping = Instant::now() + self.cfg.ping_interval;
            }
        }
    }

    /// Requests `peer`'s MetaData, unless a request is already open.
    pub fn request_metadata(&mut self, peer: PeerId) {
        if self
            .peers
            .get(&peer)
            .is_none_or(|state| state.metadata_open)
        {
            return;
        }
        let open = self.submit(peer, Request::MetaData);
        if let Some(state) = self.peers.get_mut(&peer) {
            state.metadata_open = open;
        }
    }

    /// Sends `peer` a Goodbye with `reason`; the connection closes once it completed.
    pub fn goodbye(&mut self, peer: PeerId, reason: u64) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        if state.goodbye_sent {
            return;
        }
        state.goodbye_sent = true;
        let status_valid = StatusValidity::from(state.status_valid);
        self.metrics.goodbye_sent(reason, status_valid);
        tracing::info!(
            %peer,
            reason,
            status_valid = status_valid.as_str(),
            "goodbye_sent"
        );
        self.submit(peer, Request::Goodbye(Goodbye(reason)));
    }

    /// Closes every connection whose Goodbye linger ended, pings every peer whose Ping is due
    /// (none once either side said Goodbye, none while one is in flight), and sets the timer
    /// for the next of these; `cx` is woken then.
    fn poll_timers(&mut self, cx: &mut Context<'_>) {
        let pinging = !self.cfg.ping_interval.is_zero();
        let waiting = |state: &PeerState<E>| pinging && !state.leaving() && state.ping.is_none();
        loop {
            let now = Instant::now();
            let mut closes = Vec::new();
            let mut pings = Vec::new();
            let mut statuses = Vec::new();
            let mut answers = Vec::new();
            for (peer, state) in &mut self.peers {
                for (id, wait) in &state.status_waits {
                    if wait.read.is_some() && wait.token.due() <= now {
                        answers.push((*peer, *id));
                    }
                }
                if state.close_at.is_some_and(|at| at <= now) {
                    state.close_at = None;
                    closes.push(*peer);
                }
                if waiting(state) && state.next_ping <= now {
                    pings.push(*peer);
                }
                if let Some((_, attempt)) = state.status_retry.take_if(|(due, _)| *due <= now) {
                    statuses.push((*peer, attempt));
                }
            }
            for peer in closes {
                self.close(peer);
            }
            for peer in pings {
                self.ping(peer);
            }
            for (peer, attempt) in statuses {
                self.send_status_attempt(peer, attempt);
            }
            for (peer, request_id) in answers {
                self.read_status_answer(peer, request_id);
            }
            let next = self
                .peers
                .values()
                .flat_map(|state| {
                    [
                        state.close_at,
                        waiting(state).then_some(state.next_ping),
                        state.status_retry.map(|(due, _)| due),
                    ]
                    .into_iter()
                    .chain(
                        state
                            .status_waits
                            .values()
                            .filter(|wait| wait.read.is_some())
                            .map(|wait| Some(wait.token.due())),
                    )
                })
                .flatten()
                .min();
            let Some(next) = next else {
                self.timer = None;
                return;
            };
            let timer = self
                .timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(next)));
            if timer.deadline() != next {
                timer.as_mut().reset(next);
            }
            if timer.as_mut().poll(cx).is_pending() {
                return;
            }
        }
    }

    /// Asks the swarm to close every connection to `peer`. The close is graceful, and the
    /// probe swarm's muxers drop a connection whose close outlasts [`CLOSE_DEADLINE`].
    fn close(&mut self, peer: PeerId) {
        self.pending.push_back(ToSwarm::CloseConnection {
            peer_id: peer,
            connection: CloseConnection::All,
        });
    }

    fn emit(&mut self, event: ControlEvent) {
        self.pending.push_back(ToSwarm::GenerateEvent(event));
    }

    /// Records the verdict on `theirs`, which came `via` the peer's request or its response; an
    /// irrelevant peer gets `Goodbye(2)`.
    fn judge(&mut self, peer: PeerId, theirs: StatusV2, via: StatusVia) {
        let Some(ours) = self.cfg.status.status() else {
            tracing::debug!(%peer, "no Status of ours yet: the peer's is not judged");
            return;
        };
        let verdict = relevance(&ours, &theirs);
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        let valid = verdict.is_relevant();
        let was_valid = state.status_valid == Some(true);
        state.status_valid = Some(valid);
        state.status = Some(theirs.clone());
        if valid != was_valid {
            self.metrics.status_valid_peer(valid);
        }
        tracing::info!(
            %peer,
            ?verdict,
            fork_digest = ?theirs.fork_digest,
            finalized_epoch = theirs.finalized_epoch,
            head_slot = theirs.head_slot,
            "peer status judged"
        );
        self.emit(ControlEvent::Status {
            peer,
            status: theirs,
            relevance: verdict,
            via,
        });
        if !valid {
            self.goodbye(peer, GOODBYE_IRRELEVANT_NETWORK);
        }
    }

    /// A `seq_number` the peer announced: fetch its MetaData if it is newer than ours of it. While
    /// our request is open, the announcement is kept for when it ends ([`Self::metadata_done`]).
    fn on_peer_seq(&mut self, peer: PeerId, seq_number: u64) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        if state.metadata_seq.is_some_and(|known| seq_number <= known) {
            return;
        }
        if state.metadata_open {
            state.metadata_announced = state.metadata_announced.max(Some(seq_number));
        } else {
            self.request_metadata(peer);
        }
    }

    /// Hands `chunks` to the stream with the pacer of `peer`'s `protocol` bucket: the stream
    /// writes each chunk once its token is free.
    fn respond(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        channel: ResponseChannel<Answer<E>>,
        chunks: Vec<ReceivedChunk<E>>,
    ) -> bool {
        let answer = self.paced(peer, protocol, chunks);
        self.send_answer(protocol, channel, answer)
    }

    /// `chunks` as an answer paced by `peer`'s `protocol` bucket.
    fn paced(&self, peer: PeerId, protocol: Protocol, chunks: Vec<ReceivedChunk<E>>) -> Answer<E> {
        Answer {
            pacer: Some(self.pacer(peer, protocol)),
            ..Answer::from(chunks)
        }
    }

    /// Our answer to `peer`'s `request` from `responder` (see the module docs): checked first,
    /// so one out of bounds is `1: InvalidRequest` before anything is read or booked, and one
    /// naming nothing an empty answer; else the responder's streamed answer, its
    /// [`Responder::cost`] booked. `None` drops the stream without a chunk: past the global
    /// stream cap (counted), or for a peer no longer connected.
    fn answer_streamed(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        request: Request,
        responder: &dyn Responder<E>,
    ) -> Option<Answer<E>> {
        let invalid = match &request {
            Request::BlocksByRange(range) => out_of_bounds(range),
            other => column_request_error(other),
        };
        if let Some(why) = invalid {
            tracing::debug!(%peer, %protocol, %why, "request out of bounds");
            let chunks = error_chunk(ResultCode::InvalidRequest, &why);
            return Some(self.paced(peer, protocol, chunks));
        }
        if request.max_response_chunks() == 0 {
            return Some(self.paced(peer, protocol, Vec::new()));
        }
        let budget = self.peers.get(&peer)?.queued_bytes.clone();
        let Ok(slot) = Arc::clone(&self.streams).try_acquire_owned() else {
            self.metrics.inbound_stream_refused();
            tracing::debug!(%peer, %protocol, "inbound stream cap reached: stream dropped");
            return None;
        };
        let booked = BookedChunks::book(
            &self.limiter,
            peer,
            protocol,
            responder.cost(&request),
            Some(self.metrics.clone()),
            self.cfg.limits.column_deadlines(),
        )
        .with_lookup_cost(1);
        let contexts = Arc::clone(&self.cfg.contexts);
        let Some(stream) = StreamedAnswer::start(responder, peer, request, contexts, budget, slot)
        else {
            let chunks = error_chunk(ResultCode::ServerError, "no runtime");
            return Some(self.paced(peer, protocol, chunks));
        };
        let pacer = self.pacer(peer, protocol);
        Some(Answer::streamed(stream, Some(pacer), Some(booked)))
    }

    /// The pacer of `peer`'s `protocol` bucket.
    fn pacer(&self, peer: PeerId, protocol: Protocol) -> ChunkPacer {
        ChunkPacer::new(
            Arc::clone(&self.limiter),
            peer,
            protocol,
            Some(self.metrics.clone()),
        )
    }

    /// Hands `answer` to its stream.
    fn send_answer(
        &mut self,
        protocol: Protocol,
        channel: ResponseChannel<Answer<E>>,
        answer: Answer<E>,
    ) -> bool {
        let sent = self
            .inner
            .of(protocol)
            .send_response(channel, answer)
            .is_ok();
        if !sent {
            tracing::debug!(%protocol, "the stream closed before our response");
        }
        sent
    }

    fn on_request(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        request_id: InboundRequestId,
        request: RpcRequest,
        channel: ResponseChannel<Answer<E>>,
    ) {
        let request = match request {
            RpcRequest::Valid(request) => request,
            RpcRequest::Malformed(error) => {
                self.metrics.invalid_data(Direction::Inbound);
                tracing::debug!(%peer, %protocol, %error, "malformed request");
                let answer = error_chunk(ResultCode::InvalidRequest, &error.to_string());
                let answered = self.respond(peer, protocol, channel, answer);
                // A Goodbye answer has no quota: a malformed one ends the connection like a
                // valid one, so a peer cannot loop on decode, error and write.
                if protocol == Protocol::GoodbyeV1 {
                    self.linger_after(peer, request_id, answered);
                }
                return;
            }
        };
        match request {
            Request::Status(theirs) => {
                if let Some(read) = self.cfg.status.fresh() {
                    self.wait_status(peer, protocol, request_id, channel, theirs, read);
                    return;
                }
                let ours = self.cfg.status.status();
                let answered = ours.is_some();
                let answer = match ours {
                    Some(ours) => success_chunk(Response::Status(ours)),
                    None => error_chunk(ResultCode::ServerError, "status unavailable"),
                };
                if self.respond(peer, protocol, channel, answer) && answered {
                    self.status_answers.insert(request_id);
                }
                self.judge(peer, theirs, StatusVia::Request);
            }
            Request::MetaData => {
                let answer = success_chunk(Response::MetaData(self.local_metadata()));
                self.respond(peer, protocol, channel, answer);
            }
            Request::Ping(Ping(seq_number)) => {
                let ours = self.local_metadata().seq_number;
                let answer = success_chunk(Response::Ping(Ping(ours)));
                self.respond(peer, protocol, channel, answer);
                self.on_peer_seq(peer, seq_number);
            }
            Request::Goodbye(Goodbye(reason)) => {
                // One chunk, its reason the peer's own: the spec says the response is a single
                // chunk of the same `uint64` content (`phase0` L1461, L1483), not which value.
                // The connection closes once it went out (or failed), not before.
                // Only the first Goodbye is counted, logged and reported; a later one is still
                // answered, and moves no close already set.
                let answer = success_chunk(Response::Goodbye(Goodbye(reason)));
                let answered = self.respond(peer, protocol, channel, answer);
                self.linger_after(peer, request_id, answered);
                if self.peers.get(&peer).is_some_and(|s| !s.goodbye_received) {
                    self.on_goodbye(peer, reason);
                }
            }
            Request::BlocksByRange(range) if self.blocks_responder.is_some() => {
                let responder = self.blocks_responder.clone();
                let request = Request::BlocksByRange(range);
                let answer =
                    responder.and_then(|r| self.answer_streamed(peer, protocol, request, &*r));
                if let Some(answer) = answer {
                    self.send_answer(protocol, channel, answer);
                }
            }
            Request::BlocksByRange(range) => {
                let answer = match out_of_bounds(&range) {
                    Some(why) => {
                        tracing::debug!(%peer, %why, "BlocksByRange request out of bounds");
                        error_chunk(ResultCode::InvalidRequest, &why)
                    }
                    None => error_chunk(ResultCode::ResourceUnavailable, "no blocks stored"),
                };
                self.respond(peer, protocol, channel, answer);
            }
            request @ (Request::DataColumnsByRange(_) | Request::DataColumnsByRoot(_)) => {
                self.serve_columns(peer, protocol, channel, request);
            }
        }
    }

    /// Admits a peer's column request (see the module docs): answers it at once if it is out of
    /// bounds, names nothing or finds no store or no room, else books its tokens and queues it.
    fn serve_columns(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        channel: ResponseChannel<Answer<E>>,
        request: Request,
    ) {
        if let Some(why) = column_request_error(&request) {
            tracing::debug!(%peer, %protocol, %why, "column request out of bounds");
            self.respond(
                peer,
                protocol,
                channel,
                error_answer(ResultCode::InvalidRequest),
            );
            return;
        }
        let max_chunks = request.max_response_chunks();
        if max_chunks == 0 {
            self.respond(peer, protocol, channel, Vec::new());
            return;
        }
        if self.cfg.columns.is_none() {
            let answer = error_answer(ResultCode::ResourceUnavailable);
            self.respond(peer, protocol, channel, answer);
            return;
        }
        if self.column_queue.len() >= self.cfg.limits.column_queue_len {
            self.metrics.queues().count(COLUMN_QUEUE);
            tracing::debug!(%peer, %protocol, "the column queue is full");
            self.respond(
                peer,
                protocol,
                channel,
                error_answer(ResultCode::ServerError),
            );
            return;
        }
        // What the bucket can still deliver within the window, at most an answer's share, and
        // at least one whole block: a peer over its quota still gets its first block, late.
        let limits = &self.cfg.limits;
        let deliverable = self
            .limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .deliverable(peer, protocol, limits.column_answer_window, Instant::now());
        let Some(requested) = Requested::of(&request) else {
            unreachable!("{request:?} is not a column request")
        };
        let tokens = column_tokens(
            &request,
            &requested,
            limits.column_answer_sidecars(protocol),
            deliverable,
        );
        let booked = BookedChunks::book(
            &self.limiter,
            peer,
            protocol,
            tokens,
            Some(self.metrics.clone()),
            limits.column_deadlines(),
        )
        .with_lookup_cost(lookup_cost(&request));
        drop(requested);
        self.column_queue.push_back(QueuedColumn {
            peer,
            protocol,
            channel,
            request,
            booked,
            since: Instant::now(),
        });
    }

    /// Goes through the queued column requests in order: drops those whose stream closed
    /// (their tokens stay spent), starts those whose tokens are due and whose peer gets a
    /// place, and refuses those that waited for a place past the queue wait. Then sets the
    /// queue timer for the next of these; `cx` is woken then, or when a place is given back.
    fn pump_columns(&mut self, cx: &mut Context<'_>) {
        self.places.register(cx.waker());
        let wait = self.cfg.limits.column_queue_wait;
        loop {
            let now = Instant::now();
            let mut next: Option<Instant> = None;
            let mut i = 0;
            while i < self.column_queue.len() {
                let queued = &self.column_queue[i];
                if !queued.channel.is_open() {
                    tracing::debug!(peer = %queued.peer, "a queued column request's stream closed");
                    self.column_queue.remove(i);
                    continue;
                }
                let ready = queued.ready_at();
                if ready > now {
                    next = Some(next.map_or(ready, |n| n.min(ready)));
                    i += 1;
                    continue;
                }
                let ip = self.peers.get(&queued.peer).and_then(|p| p.ip);
                if let Some(permit) = self.places.try_take(queued.peer, ip) {
                    let queued = self.column_queue.remove(i).expect("at i");
                    self.start_lookup(queued, permit);
                    continue;
                }
                if now >= ready + wait {
                    let mut queued = self.column_queue.remove(i).expect("at i");
                    self.metrics.queues().count(COLUMN_QUEUE);
                    tracing::debug!(peer = %queued.peer, "no column answer place in time");
                    // Not served: every booked token goes back; the error chunk pays its own.
                    queued.booked.settle(0);
                    let answer = error_answer(ResultCode::ServerError);
                    self.respond(queued.peer, queued.protocol, queued.channel, answer);
                    continue;
                }
                let at = ready + wait;
                next = Some(next.map_or(at, |n| n.min(at)));
                i += 1;
            }
            let Some(next) = next else {
                self.queue_timer = None;
                return;
            };
            let timer = self
                .queue_timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(next)));
            if timer.deadline() != next {
                timer.as_mut().reset(next);
            }
            if timer.as_mut().poll(cx).is_pending() {
                return;
            }
        }
    }

    /// Runs the lookup of `queued` on its own task, holding `permit`.
    fn start_lookup(&mut self, queued: QueuedColumn<E>, mut permit: AnswerPermit) {
        let QueuedColumn {
            peer,
            protocol,
            channel,
            request,
            booked,
            ..
        } = queued;
        let (Some(source), Some(requested), Ok(runtime)) = (
            self.cfg.columns.clone(),
            Requested::of(&request),
            tokio::runtime::Handle::try_current(),
        ) else {
            self.respond(
                peer,
                protocol,
                channel,
                error_answer(ResultCode::ServerError),
            );
            return;
        };
        let lookup = match &request {
            Request::DataColumnsByRange(range) => source.by_range(range),
            Request::DataColumnsByRoot(roots) => source.by_root(roots),
            other => unreachable!("{other:?} is not a column request"),
        };
        drop(request);
        let contexts = Arc::clone(&self.cfg.contexts);
        let metrics = self.metrics.clone();
        let budget = AnswerBudget {
            max_sidecars: booked.tokens(),
            max_bytes: self.cfg.limits.max_column_response_bytes,
        };
        self.lookups.push(runtime.spawn(async move {
            let (chunks, bytes) = answer_columns(
                lookup, &requested, &contexts, budget, &metrics, &permit, &booked,
            )
            .await;
            if !channel.is_open() {
                // Gone during the lookup: its tokens stay spent, as on a reset. (A reset of the
                // stream alone leaves the channel open; the writer sees it.)
                tracing::debug!(%peer, "a column request's stream closed during its lookup");
                return None;
            }
            permit.hold_bytes(bytes);
            Some(ColumnAnswer {
                protocol,
                channel,
                chunks,
                booked,
                permit,
            })
        }));
    }

    /// Takes `peer`'s Status request `request_id` to answer from a fresh `read`: its token is
    /// taken now, and the read starts once it is due ([`Self::read_status_answer`]), so the
    /// answer carries the floor of when it goes out, not of when it arrived. A token due at or
    /// past the requester's first-byte deadline less [`STATUS_ANSWER_SLACK`] is given back and
    /// the request answered `2: ServerError` at once, unread.
    fn wait_status(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        request_id: InboundRequestId,
        channel: ResponseChannel<Answer<E>>,
        theirs: StatusV2,
        read: StatusLookup,
    ) {
        let token = self.pacer(peer, protocol).reserve();
        let answer_by =
            Instant::now() + self.cfg.deadlines.ttfb.saturating_sub(STATUS_ANSWER_SLACK);
        if !self.peers.contains_key(&peer) {
            // Not connected: the stream goes, and the token back.
            return;
        }
        if token.due() >= answer_by {
            // A token due that late leaves no time to read and answer before the requester's
            // first-byte deadline: refused now, and the token goes back unspent.
            tracing::debug!(%peer, "a Status token due past the first-byte deadline: refused");
            drop(token);
            let answer = error_chunk(ResultCode::ServerError, "status unavailable");
            self.send_answer(protocol, channel, Answer::from(answer));
            self.judge(peer, theirs, StatusVia::Request);
            return;
        }
        if let Some(state) = self.peers.get_mut(&peer) {
            state.status_waits.insert(
                request_id,
                StatusWait {
                    protocol,
                    channel,
                    theirs,
                    token,
                    read: Some(read),
                    reading: None,
                    answer_by,
                },
            );
        }
    }

    /// Starts the read of `peer`'s Status request `request_id`, whose token is due, bounded by
    /// the requester's first-byte deadline less [`STATUS_ANSWER_SLACK`]; none if its stream has
    /// closed meanwhile, which drops the request, and none past that bound, which answers
    /// `2: ServerError` at once.
    fn read_status_answer(&mut self, peer: PeerId, request_id: InboundRequestId) {
        let Some(waits) = self.peers.get_mut(&peer).map(|s| &mut s.status_waits) else {
            return;
        };
        let Some(wait) = waits.get_mut(&request_id) else {
            return;
        };
        if !wait.channel.is_open() {
            tracing::debug!(%peer, "the Status stream closed before its token: not read");
            waits.remove(&request_id);
            return;
        }
        let Some(read) = wait.read.take() else {
            return;
        };
        let by = wait.answer_by;
        if Instant::now() >= by {
            tracing::debug!(%peer, "a Status token due past the first-byte deadline: not read");
            self.answer_status(peer, request_id, None);
            return;
        }
        let (read, cancel) = abortable(tokio::time::timeout_at(by, read));
        wait.reading = Some(CancelOnDrop(cancel));
        let to = StatusUse::Answer { peer, request_id };
        self.status_reads.push(Box::pin(async move {
            // A cancelled read answers nothing: its request is gone.
            let ours = match read.await {
                Ok(Ok(ours)) => ours,
                Ok(Err(_)) => {
                    tracing::debug!(%peer, "our Status read ran past the first-byte deadline");
                    None
                }
                Err(_) => None,
            };
            (to, ours)
        }));
    }

    /// Answers `peer`'s Status request `request_id` with `ours` (`2: ServerError` if none),
    /// at the token it was read at, and judges the peer's Status; nothing if the request is
    /// gone (it failed, or its connection closed).
    fn answer_status(
        &mut self,
        peer: PeerId,
        request_id: InboundRequestId,
        ours: Option<StatusV2>,
    ) {
        let Some(wait) = self
            .peers
            .get_mut(&peer)
            .and_then(|s| s.status_waits.remove(&request_id))
        else {
            return;
        };
        let answered = ours.is_some();
        let chunks = match ours {
            Some(ours) => success_chunk(Response::Status(ours)),
            None => error_chunk(ResultCode::ServerError, "status unavailable"),
        };
        let answer = Answer {
            chunks,
            pacer: None,
            token: Some(Box::new(wait.token)),
            booked: None,
            permit: None,
            stream: None,
        };
        if self.send_answer(wait.protocol, wait.channel, answer) && answered {
            self.status_answers.insert(request_id);
        }
        self.judge(peer, wait.theirs, StatusVia::Request);
    }

    /// Schedules the retry of our Status to `peer` after `attempt`'s read failed, within the
    /// bound ([`StatusAttempt::retry`]), while the peer stays and neither side said Goodbye;
    /// `true` if it did.
    fn retry_status(&mut self, peer: PeerId, attempt: StatusAttempt) -> bool {
        let Some(state) = self
            .peers
            .get_mut(&peer)
            .filter(|s| s.session == attempt.session && !s.leaving())
        else {
            tracing::debug!(%peer, "no fresh Status of ours, and its connection is gone: none sent");
            return false;
        };
        match attempt.retry(Instant::now()) {
            Some(retry) => {
                tracing::debug!(%peer, failed = retry.1.failed, "no fresh Status of ours: retrying");
                state.status_retry = Some(retry);
                true
            }
            None => {
                tracing::warn!(
                    %peer,
                    reads = attempt.failed + 1,
                    "no fresh Status of ours within the handshake bound: none sent"
                );
                false
            }
        }
    }

    /// Sends or answers with every fresh Status read that ended; `true` if a retry was
    /// scheduled, whose timer is still to be set ([`Self::poll_timers`]).
    fn poll_status_reads(&mut self, cx: &mut Context<'_>) -> bool {
        let mut retrying = false;
        while let Poll::Ready(Some((to, ours))) = self.status_reads.poll_next_unpin(cx) {
            match to {
                // The read held the Status lane's slot: the Status goes out in it, or it is
                // given back.
                // A read of an earlier session never goes out on a later one.
                StatusUse::Send { peer, attempt } => match ours {
                    Some(ours)
                        if self
                            .peers
                            .get(&peer)
                            .is_some_and(|s| s.session == attempt.session && !s.leaving()) =>
                    {
                        self.send_now(peer, Request::Status(ours), None);
                    }
                    Some(_) => {
                        tracing::debug!(%peer, "gone or leaving during our Status read: none sent");
                        self.release(Protocol::StatusV2);
                    }
                    None => {
                        self.release(Protocol::StatusV2);
                        retrying |= self.retry_status(peer, attempt);
                    }
                },
                StatusUse::Answer { peer, request_id } => {
                    self.answer_status(peer, request_id, ours);
                }
            }
        }
        retrying
    }

    /// Sends every column answer whose lookup ended, at its booked tokens, holding its place.
    fn poll_lookups(&mut self, cx: &mut Context<'_>) {
        while let Poll::Ready(Some(done)) = self.lookups.poll_next_unpin(cx) {
            match done {
                Ok(None) => {}
                Ok(Some(done)) => {
                    let sidecars = done
                        .chunks
                        .iter()
                        .filter(|c| matches!(c.chunk, ResponseChunk::Success(_)))
                        .count();
                    let answer = Answer {
                        chunks: done.chunks,
                        pacer: None,
                        token: None,
                        booked: Some(Box::new(done.booked)),
                        permit: Some(Box::new(done.permit)),
                        stream: None,
                    };
                    let protocol = done.protocol;
                    if self
                        .inner
                        .of(protocol)
                        .send_response(done.channel, answer)
                        .is_ok()
                    {
                        self.metrics.column_sidecars_answered(protocol, sidecars);
                    } else {
                        tracing::debug!(%protocol, "the stream closed before our column answer");
                    }
                }
                // The stream drops unanswered with the task's channel, and the place with it.
                Err(e) => tracing::error!(error = %e, "a column lookup task ended abnormally"),
            }
        }
    }

    fn on_goodbye(&mut self, peer: PeerId, reason: u64) {
        let Some(state) = self.peers.get(&peer) else {
            return;
        };
        let status_valid = StatusValidity::from(state.status_valid);
        let direction = state.direction;
        let at = SystemTime::now();
        if let Some(state) = self.peers.get_mut(&peer) {
            state.goodbye_received = true;
        }
        self.metrics.goodbye_received(reason, status_valid);
        tracing::info!(
            %peer,
            reason,
            status_valid = status_valid.as_str(),
            direction = direction.as_str(),
            unix_ms = unix_ms(at) as u64,
            "goodbye_received"
        );
        self.emit(ControlEvent::GoodbyeReceived {
            peer,
            reason,
            status_valid,
            direction,
            at,
        });
    }

    /// Our answer to `peer`'s Goodbye `id` was handed to its stream (`answered`), or the
    /// stream was gone: the connection closes once the answer went out, or now.
    fn linger_after(&mut self, peer: PeerId, id: InboundRequestId, answered: bool) {
        if answered {
            self.goodbye_answers.insert(id, peer);
        } else {
            self.close(peer);
        }
    }

    /// Our answer to a peer's Goodbye (`id`) went out or failed: the connection closes a
    /// [`GOODBYE_LINGER`] on, unless the peer closes it first, so the peer can read the answer
    /// before the connection goes. A close already set stays: later Goodbyes never move it.
    fn goodbye_answered(&mut self, id: InboundRequestId) {
        if let Some(peer) = self.goodbye_answers.remove(&id) {
            if let Some(state) = self.peers.get_mut(&peer) {
                state
                    .close_at
                    .get_or_insert_with(|| Instant::now() + GOODBYE_LINGER);
            }
        }
    }

    fn on_response(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        id: OutboundRequestId,
        chunks: Vec<ReceivedChunk<E>>,
    ) {
        self.finished(protocol, id);
        if protocol == Protocol::PingV1 {
            self.ping_done(peer, id);
        }
        match protocol {
            Protocol::GoodbyeV1 => self.on_goodbye_done(id),
            Protocol::MetaDataV3 => match single_success(chunks) {
                Some(Response::MetaData(metadata)) => {
                    let seq_number = metadata.seq_number;
                    if let Some(state) = self.peers.get_mut(&peer) {
                        state.metadata_seq = Some(seq_number);
                    }
                    self.emit(ControlEvent::MetaData {
                        peer,
                        metadata: Box::new(metadata),
                    });
                    self.metadata_done(peer, Some(seq_number));
                }
                other => {
                    tracing::debug!(%peer, ?other, "no MetaData in the response");
                    self.metadata_done(peer, None);
                }
            },
            Protocol::StatusV2 => match single_success(chunks) {
                Some(Response::Status(theirs)) => self.judge(peer, theirs, StatusVia::Response),
                other => tracing::debug!(%peer, ?other, "no Status in the response: ignored"),
            },
            Protocol::PingV1 => match single_success(chunks) {
                Some(Response::Ping(Ping(seq_number))) => {
                    self.emit(ControlEvent::Pong { peer, seq_number });
                    self.on_peer_seq(peer, seq_number);
                }
                other => tracing::debug!(%peer, ?other, "no Ping in the response"),
            },
            Protocol::BlocksByRangeV2 => match self.blocks_in_flight.remove(&id) {
                Some(ticket) => self.blocks_done(peer, ticket, Ok(chunks)),
                None => tracing::debug!(%peer, chunks = chunks.len(), "a BlocksByRange response"),
            },
            // We send no column request yet.
            Protocol::DataColumnsByRangeV1 | Protocol::DataColumnsByRootV1 => {
                tracing::debug!(%peer, %protocol, chunks = chunks.len(), "a column response");
            }
        }
    }

    /// Our one MetaData request to `peer` finished, with a MetaData of `got` if it brought one.
    /// A `seq_number` announced meanwhile and above `got` is asked for once more now; a failed
    /// request drops it, and the next announcement asks again.
    fn metadata_done(&mut self, peer: PeerId, got: Option<u64>) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        state.metadata_open = false;
        let announced = state.metadata_announced.take();
        if got.is_some_and(|got| announced.is_some_and(|a| a > got)) {
            self.request_metadata(peer);
        }
    }

    fn on_goodbye_done(&mut self, id: OutboundRequestId) {
        if let Some(peer) = self.goodbyes.remove(&id) {
            self.close(peer);
        }
    }

    fn on_outbound_failure(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        id: OutboundRequestId,
        error: OutboundFailure,
    ) {
        self.finished(protocol, id);
        if protocol == Protocol::PingV1 {
            self.ping_done(peer, id);
        }
        // The codec counts its own deadlines; `request_response`'s is the whole exchange.
        match &error {
            OutboundFailure::Timeout => self.metrics.timed_out(Deadline::Total),
            OutboundFailure::Io(e) => match codec_error(e) {
                Some(ReadError::Deadline(_) | ReadError::Io(_)) | None => {}
                Some(_) => self.metrics.invalid_data(Direction::Outbound),
            },
            _ => {}
        }
        tracing::debug!(%peer, %protocol, %error, "outbound request failed");
        match protocol {
            // A peer may close without answering our Goodbye: a failure after it is expected.
            Protocol::GoodbyeV1 => self.on_goodbye_done(id),
            Protocol::MetaDataV3 => self.metadata_done(peer, None),
            _ => {}
        }
        // Request IDs are numbered per behaviour: only a BlocksByRange ID names a ticket.
        if protocol != Protocol::BlocksByRangeV2 {
            return;
        }
        if let Some(ticket) = self.blocks_in_flight.remove(&id) {
            self.blocks_done(peer, ticket, Err(outbound_failure(error)));
        }
    }

    fn on_inbound_failure(&mut self, peer: PeerId, protocol: Protocol, error: InboundFailure) {
        // A failed `read_request` is never reported here (the codec counts its deadlines);
        // this is a response we did not write in time.
        if let InboundFailure::Timeout = error {
            self.metrics.timed_out(Deadline::Total);
        }
        tracing::debug!(%peer, %protocol, %error, "inbound request failed");
    }

    fn on_protocol_event(&mut self, event: ProtocolsEvent<E>) {
        use request_response::{Event, Message};
        let (protocol, event) = match event {
            ProtocolsEvent::Status(e) => (Protocol::StatusV2, e),
            ProtocolsEvent::Metadata(e) => (Protocol::MetaDataV3, e),
            ProtocolsEvent::Ping(e) => (Protocol::PingV1, e),
            ProtocolsEvent::Goodbye(e) => (Protocol::GoodbyeV1, e),
            ProtocolsEvent::BlocksByRange(e) => (Protocol::BlocksByRangeV2, e),
            ProtocolsEvent::DataColumnsByRange(e) => (Protocol::DataColumnsByRangeV1, e),
            ProtocolsEvent::DataColumnsByRoot(e) => (Protocol::DataColumnsByRootV1, e),
        };
        match event {
            DuplexEvent::Inbound(Event::Message {
                peer,
                message:
                    Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            }) => self.on_request(peer, protocol, request_id, request, channel),
            DuplexEvent::Inbound(Event::InboundFailure {
                peer,
                request_id,
                error,
                ..
            }) => {
                if protocol == Protocol::GoodbyeV1 {
                    self.goodbye_answered(request_id);
                }
                if protocol == Protocol::StatusV2 {
                    self.status_answers.remove(&request_id);
                    // A request still waiting for its token or read goes, giving its token
                    // back.
                    if let Some(state) = self.peers.get_mut(&peer) {
                        state.status_waits.remove(&request_id);
                    }
                }
                self.on_inbound_failure(peer, protocol, error);
            }
            DuplexEvent::Inbound(Event::ResponseSent { request_id, .. })
                if protocol == Protocol::GoodbyeV1 =>
            {
                self.goodbye_answered(request_id);
            }
            // Request IDs are numbered per behaviour: only a Status one names our answer.
            DuplexEvent::Inbound(Event::ResponseSent {
                peer, request_id, ..
            }) if protocol == Protocol::StatusV2 => {
                if self.status_answers.remove(&request_id) {
                    self.emit(ControlEvent::StatusAnswered { peer });
                }
            }
            DuplexEvent::Outbound(Event::Message {
                peer,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            }) => self.on_response(peer, protocol, request_id, response),
            DuplexEvent::Outbound(Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            }) => self.on_outbound_failure(peer, protocol, request_id, error),
            // What each one-way behaviour never reports (a response on the inbound side, a
            // request on the outbound side).
            DuplexEvent::Inbound(_) | DuplexEvent::Outbound(_) => {}
        }
    }
}

/// The codec's [`ReadError`] inside `e`, if it is one.
fn codec_error(e: &std::io::Error) -> Option<&ReadError> {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<ReadError>())
}

impl<E: EthSpec> NetworkBehaviour for Control<E> {
    type ConnectionHandler = THandler<Protocols<E>>;
    type ToSwarm = ControlEvent;

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
        match event {
            FromSwarm::ConnectionEstablished(c) if c.other_established == 0 => {
                let direction = Direction::of(c.endpoint.is_dialer());
                self.peers.insert(
                    c.peer_id,
                    PeerState {
                        session: c.connection_id,
                        direction,
                        ip: self
                            .cfg
                            .limits
                            .column_answer_prefixes
                            .of(c.endpoint.get_remote_address()),
                        status_valid: None,
                        status: None,
                        metadata_seq: None,
                        metadata_open: false,
                        metadata_announced: None,
                        goodbye_sent: false,
                        goodbye_received: false,
                        close_at: None,
                        ping: None,
                        next_ping: Instant::now() + self.cfg.ping_interval,
                        status_retry: None,
                        status_waits: HashMap::new(),
                        queued_bytes: PeerBytes::new(self.cfg.limits.max_queued_bytes_per_peer),
                    },
                );
                if direction == Direction::Outbound {
                    self.send_status(c.peer_id);
                }
            }
            FromSwarm::ConnectionClosed(c) if c.remaining_established == 0 => {
                if let Some(state) = self.peers.remove(&c.peer_id) {
                    if state.status_valid == Some(true) {
                        self.metrics.status_valid_peer(false);
                    }
                }
                self.goodbyes.retain(|_, peer| *peer != c.peer_id);
                self.goodbye_answers.retain(|_, peer| *peer != c.peer_id);
                // Its Pings in flight end with the connection; their IDs go too.
                self.metrics
                    .set_outbound_inflight(Protocol::PingV1, self.pings_in_flight());
                // Its streams' unsent chunks refund themselves as the streams drop.
                let peers = &self.peers;
                self.limiter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .prune(Instant::now(), |peer| peers.contains_key(peer));
            }
            _ => {}
        }
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
        loop {
            // Each event may have ended a Ping, whose peer is due again an interval on, or a
            // Goodbye answer, whose connection closes a linger on; or started a column lookup.
            self.poll_timers(cx);
            // Lookups the pump starts are polled right after, so their tasks can wake us.
            self.pump_columns(cx);
            self.poll_lookups(cx);
            if self.poll_status_reads(cx) {
                // A retry is due later: its timer is set on the next turn.
                continue;
            }
            if let Some(next) = self.pending.pop_front() {
                return Poll::Ready(next);
            }
            match self.inner.poll(cx) {
                Poll::Ready(ToSwarm::GenerateEvent(event)) => self.on_protocol_event(event),
                Poll::Ready(other) => {
                    return Poll::Ready(other.map_out(|_| unreachable!("handled above")));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethswarm_proto::common;
    use p2p_wire::testkit;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn by_root(ids: &[([u8; 32], &[u64])]) -> Request {
        use p2p_wire::rpc::messages::{DataColumnsByRootIdentifier, DataColumnsByRootV1Request};
        let ids: Vec<_> = ids
            .iter()
            .map(|(root, columns)| DataColumnsByRootIdentifier {
                block_root: (*root).into(),
                columns: columns.to_vec().try_into().unwrap(),
            })
            .collect();
        Request::DataColumnsByRoot(DataColumnsByRootV1Request(ids.try_into().unwrap()))
    }

    /// SEC-002: the first block of an answer always goes out, so a request books at least the
    /// most sidecars one block can hold: for roots, every column named for a root over all its
    /// identifiers, each once, however the identifiers split them.
    #[test]
    fn a_request_books_its_largest_block_however_its_identifiers_split_it() {
        let (r, s) = ([1; 32], [2; 32]);
        let request = by_root(&[(r, &[0, 1]), (s, &[0]), (r, &[2, 1]), (r, &[3])]);
        assert_eq!(request.max_response_chunks(), 6);
        let split = Requested::of(&request).unwrap();
        // A spent bucket: the four columns of `r` all the same.
        assert_eq!(column_tokens(&request, &split, 756, 0), 4);
        // As many as it names when the bucket and the share have them.
        assert_eq!(column_tokens(&request, &split, 756, 1_000), 6);
        // A range: its columns, each once.
        let range =
            Request::DataColumnsByRange(p2p_wire::rpc::messages::DataColumnsByRangeV1Request {
                start_slot: 0,
                count: 32,
                columns: vec![1, 47, 47].try_into().unwrap(),
            });
        let ranged = Requested::of(&range).unwrap();
        assert_eq!(column_tokens(&range, &ranged, 756, 0), 2);
        // SEC-001: and at least the lookup's cost, one token per identifier naming a column
        // (the store looks each up), one per range.
        assert_eq!(lookup_cost(&request), 4);
        assert_eq!(lookup_cost(&by_root(&[(r, &[]), (s, &[4])])), 1);
        assert_eq!(lookup_cost(&range), 1);
        let ids: Vec<([u8; 32], &[u64])> = (0..8u8).map(|i| ([i; 32], &[5u64][..])).collect();
        let roots = by_root(&ids);
        assert_eq!(
            column_tokens(&roots, &Requested::of(&roots).unwrap(), 756, 0),
            8
        );
    }

    #[test]
    fn relevance_checks_digest_then_finalized() {
        let ours = testkit::status();
        assert_eq!(relevance(&ours, &ours), Relevance::Relevant);
        let other_digest = StatusV2 {
            fork_digest: [9; 4],
            ..ours.clone()
        };
        assert_eq!(relevance(&ours, &other_digest), Relevance::WrongForkDigest);
        // Another root at our finalized epoch: disjoint chains.
        let conflict = StatusV2 {
            finalized_root: [7; 32].into(),
            ..ours.clone()
        };
        assert_eq!(relevance(&ours, &conflict), Relevance::FinalizedConflict);
        assert!(!Relevance::FinalizedConflict.is_relevant());
        // Another root at another epoch is not provably a conflict.
        let later = StatusV2 {
            finalized_root: [7; 32].into(),
            finalized_epoch: ours.finalized_epoch + 1,
            ..ours.clone()
        };
        assert_eq!(relevance(&ours, &later), Relevance::Relevant);
        // The digest decides first.
        let both = StatusV2 {
            fork_digest: [9; 4],
            ..conflict
        };
        assert_eq!(relevance(&ours, &both), Relevance::WrongForkDigest);
    }

    fn chain_status() -> pb::GetStatusResponse {
        pb::GetStatusResponse {
            fork_digest: vec![1, 2, 3, 4],
            finalized: Some(common::Checkpoint {
                epoch: 7,
                root: vec![5; 32],
            }),
            head_root: vec![6; 32],
            head_slot: 230,
            earliest_available_slot: 224,
        }
    }

    #[test]
    fn status_from_the_chain_contract() {
        let status = status_from_chain(&chain_status()).unwrap();
        assert_eq!(
            status,
            StatusV2 {
                fork_digest: [1, 2, 3, 4],
                finalized_root: [5; 32].into(),
                finalized_epoch: 7,
                head_root: [6; 32].into(),
                head_slot: 230,
                earliest_available_slot: 224,
            }
        );
        let mut short = chain_status();
        short.fork_digest.pop();
        assert_eq!(
            status_from_chain(&short),
            Err(ChainStatusError::Length {
                field: "fork_digest",
                len: 3,
                want: 4
            })
        );
        let mut long = chain_status();
        long.head_root.push(0);
        assert!(matches!(
            status_from_chain(&long),
            Err(ChainStatusError::Length {
                field: "head_root",
                ..
            })
        ));
        let mut none = chain_status();
        none.finalized = None;
        assert_eq!(status_from_chain(&none), Err(ChainStatusError::NoFinalized));
    }

    #[test]
    fn shared_sources_hand_out_the_current_value() {
        let shared = SharedStatus::new(None);
        assert_eq!(shared.status(), None);
        shared.set(testkit::status());
        assert_eq!(shared.status(), Some(testkit::status()));
    }

    #[test]
    fn error_messages_fit_the_list_bound() {
        let long = "x".repeat(300);
        assert_eq!(error_message(&long).len(), 256);
        assert_eq!(&error_message("pruned")[..], b"pruned");
    }

    /// Tells `control` an inbound connection from `peer` is up (`up`) or gone.
    fn connection(
        control: &mut Control<consensus_types::Minimal>,
        peer: PeerId,
        n: usize,
        up: bool,
    ) {
        use libp2p::core::ConnectedPoint;
        use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished};
        let endpoint = ConnectedPoint::Listener {
            local_addr: "/ip4/127.0.0.1/tcp/9000".parse().unwrap(),
            send_back_addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
        };
        let connection_id = ConnectionId::new_unchecked(n);
        if up {
            let ConnectedPoint::Listener {
                local_addr,
                send_back_addr,
            } = &endpoint
            else {
                unreachable!()
            };
            assert!(control
                .handle_established_inbound_connection(
                    connection_id,
                    peer,
                    local_addr,
                    send_back_addr
                )
                .is_ok());
        }
        control.on_swarm_event(if up {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: peer,
                connection_id,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            })
        } else {
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id: peer,
                connection_id,
                endpoint: &endpoint,
                cause: None,
                remaining_established: 0,
            })
        });
    }

    #[test]
    fn an_ignored_goodbye_closes_at_once_and_a_left_peer_loses_its_turn() {
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = RpcMetrics::register(&mut registry);
        let mut cfg = crate::testkit::control_config(Some(testkit::status()));
        cfg.limits.outbound_queue_len = 1;
        let mut control = Control::<consensus_types::Minimal>::new(cfg, metrics.clone());
        let peers: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
        for (n, peer) in peers.iter().enumerate() {
            connection(&mut control, *peer, n, true);
            control.goodbye(*peer, GOODBYE_CLIENT_SHUTDOWN);
        }
        // Two in flight, one waiting, the fourth IGNOREd: its connection closes now.
        assert_eq!(control.outbound.in_flight(Protocol::GoodbyeV1), 2);
        assert_eq!(metrics.outbound_inflight(Protocol::GoodbyeV1), 2);
        let queue = super::super::limits::outbound_queue_name(Protocol::GoodbyeV1);
        assert_eq!(metrics.queues().dropped(queue), 1);
        let closes: Vec<PeerId> = control
            .pending
            .iter()
            .filter_map(|e| match e {
                ToSwarm::CloseConnection { peer_id, .. } => Some(*peer_id),
                _ => None,
            })
            .collect();
        assert_eq!(closes, [peers[3]]);
        // The waiting peer leaves: when a slot frees, its Goodbye is dropped, not sent.
        connection(&mut control, peers[2], 2, false);
        let first = *control.goodbyes.keys().next().unwrap();
        control.finished(Protocol::GoodbyeV1, first);
        assert_eq!(control.outbound.in_flight(Protocol::GoodbyeV1), 1);
        assert!(
            !control.goodbyes.values().any(|p| *p == peers[2]),
            "no Goodbye went to the peer that left"
        );
        assert_eq!(control.goodbyes.len(), 2);
        // A finished request we do not know changes nothing, nor one of another protocol.
        control.finished(Protocol::GoodbyeV1, first);
        let second = *control.goodbyes.keys().find(|id| **id != first).unwrap();
        control.finished(Protocol::StatusV2, second);
        assert_eq!(control.outbound.in_flight(Protocol::GoodbyeV1), 1);
    }

    /// A Control under the fixture config with `n` inbound peers connected.
    fn control_with_peers(
        n: usize,
        queue_len: usize,
    ) -> (Control<consensus_types::Minimal>, RpcMetrics, Vec<PeerId>) {
        let mut cfg = crate::testkit::control_config(Some(testkit::status()));
        cfg.limits.outbound_queue_len = queue_len;
        control_with(cfg, n)
    }

    /// A Control under `cfg` with `n` inbound peers connected.
    fn control_with(
        cfg: ControlConfig,
        n: usize,
    ) -> (Control<consensus_types::Minimal>, RpcMetrics, Vec<PeerId>) {
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let mut control = Control::new(cfg, metrics.clone());
        let peers: Vec<PeerId> = (0..n).map(|_| PeerId::random()).collect();
        for (i, peer) in peers.iter().enumerate() {
            connection(&mut control, *peer, i, true);
        }
        (control, metrics, peers)
    }

    #[test]
    fn overlapping_request_ids_free_their_own_protocols_slot() {
        let (mut control, metrics, peers) = control_with_peers(3, 8);
        for peer in &peers[..2] {
            assert!(control.send_status(*peer));
        }
        for peer in &peers {
            control.request_metadata(*peer);
        }
        // Each protocol's behaviour numbers its requests from 1: Status and MetaData share IDs.
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 2);
        assert_eq!(control.outbound.in_flight(Protocol::MetaDataV3), 2);
        let open: Vec<(Protocol, OutboundRequestId)> = control.in_flight.iter().copied().collect();
        assert_eq!(open.len(), 4, "{open:?}");
        let ids = |p| {
            let mut ids: Vec<_> = open
                .iter()
                .filter(|(q, _)| *q == p)
                .map(|(_, id)| *id)
                .collect();
            ids.sort_unstable();
            ids
        };
        assert_eq!(ids(Protocol::StatusV2), ids(Protocol::MetaDataV3));
        // Status finishes: MetaData keeps both its slots and its third request keeps waiting.
        for id in ids(Protocol::StatusV2) {
            control.on_outbound_failure(peers[0], Protocol::StatusV2, id, OutboundFailure::Timeout);
        }
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 0);
        assert_eq!(control.outbound.in_flight(Protocol::MetaDataV3), 2);
        assert_eq!(metrics.outbound_inflight(Protocol::StatusV2), 0);
        assert_eq!(metrics.outbound_inflight(Protocol::MetaDataV3), 2);
        // MetaData finishes, the waiting one included: every slot is free.
        while let Some(&(p, id)) = control.in_flight.iter().next() {
            control.on_outbound_failure(peers[0], p, id, OutboundFailure::ConnectionClosed);
        }
        for p in Protocol::ALL {
            assert_eq!(control.outbound.in_flight(p), 0, "{p}");
            assert_eq!(metrics.outbound_inflight(p), 0, "{p}");
        }
    }

    /// The peer whose Ping `id` is, if `protocol` is Ping.
    fn pinged(
        control: &Control<consensus_types::Minimal>,
        id: OutboundRequestId,
        protocol: Protocol,
    ) -> Option<PeerId> {
        (protocol == Protocol::PingV1)
            .then(|| {
                control
                    .peers
                    .iter()
                    .find(|(_, state)| state.ping == Some(id))
                    .map(|(peer, _)| *peer)
            })
            .flatten()
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Requests on three protocols to eight peers, finishing in random order: the slots a
        /// protocol holds are always its own requests in flight, never above 2, and all come
        /// back once everything finished. Pings take no slot: at most one per peer.
        #[test]
        fn mixed_protocols_free_only_their_own_slots(
            steps in proptest::collection::vec(
                (0..3usize, 0..8usize, proptest::prelude::any::<bool>(), proptest::prelude::any::<usize>()),
                100,
            ),
        ) {
            let (mut control, metrics, peers) = control_with_peers(8, 4);
            let protocols = [Protocol::StatusV2, Protocol::PingV1, Protocol::MetaDataV3];
            for (p, k, finish, pick) in steps {
                match protocols[p] {
                    Protocol::StatusV2 => {
                        control.send_status(peers[k]);
                    }
                    Protocol::PingV1 => control.ping(peers[k]),
                    _ => control.request_metadata(peers[k]),
                }
                if finish && !control.in_flight.is_empty() {
                    let mut open: Vec<_> = control.in_flight.iter().copied().collect();
                    open.sort_unstable_by_key(|(p, id)| (format!("{p}"), *id));
                    let (q, id) = open[pick % open.len()];
                    let peer = pinged(&control, id, q).unwrap_or(peers[k]);
                    control.on_outbound_failure(peer, q, id, OutboundFailure::Timeout);
                }
                for q in protocols {
                    let open = control.in_flight.iter().filter(|(p, _)| *p == q).count();
                    if q == Protocol::PingV1 {
                        let pinged = control.peers.values().filter(|s| s.ping.is_some()).count();
                        proptest::prop_assert_eq!(open, pinged);
                        proptest::prop_assert_eq!(control.outbound.in_flight(q), 0);
                    } else {
                        proptest::prop_assert_eq!(open, control.outbound.in_flight(q));
                        proptest::prop_assert!(open <= MAX_CONCURRENT_REQUESTS);
                    }
                }
            }
            while let Some(&(q, id)) = control.in_flight.iter().next() {
                let peer = pinged(&control, id, q).unwrap_or(peers[0]);
                control.on_outbound_failure(peer, q, id, OutboundFailure::Timeout);
            }
            for q in protocols {
                proptest::prop_assert_eq!(control.outbound.in_flight(q), 0);
                proptest::prop_assert_eq!(metrics.outbound_inflight(q), 0);
            }
        }
    }

    #[test]
    fn blocks_requests_take_outbound_slots_and_keep_their_outcome() {
        use super::super::limits::outbound_queue_name;
        use p2p_wire::rpc::messages::BlocksByRangeV2Request;
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = RpcMetrics::register(&mut registry);
        let mut cfg = crate::testkit::control_config(Some(testkit::status()));
        cfg.limits.outbound_queue_len = 1;
        let mut control = Control::<consensus_types::Minimal>::new(cfg, metrics.clone());
        let peers: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
        for (n, peer) in peers.iter().enumerate() {
            connection(&mut control, *peer, n, true);
            // Status-valid, blocks from slot 5.
            control.judge(*peer, testkit::status(), StatusVia::Response);
        }
        let range = BlocksByRangeV2Request {
            start_slot: 8,
            count: 8,
            step: 1,
        };
        let p = Protocol::BlocksByRangeV2;
        let tickets: Vec<_> = peers[..3]
            .iter()
            .map(|peer| control.request_blocks(*peer, range).unwrap())
            .collect();
        // Two in flight, the third waits; a fourth finds the queue full and is IGNOREd.
        assert_eq!(control.outbound.in_flight(p), 2);
        assert_eq!(metrics.outbound_inflight(p), 2);
        assert_eq!(control.blocks_in_flight.len(), 2);
        assert!(matches!(
            control.request_blocks(peers[3], range),
            Err(RangeError::Ignored)
        ));
        assert_eq!(metrics.queues().dropped(outbound_queue_name(p)), 1);
        // A request outside the protocol's limits never takes a slot.
        let too_many = BlocksByRangeV2Request {
            count: 129,
            ..range
        };
        assert!(matches!(
            control.request_blocks(peers[3], too_many),
            Err(RangeError::Outbound(OutboundError::InvalidRequest(_)))
        ));
        assert!(tickets.iter().all(|t| control.take_blocks(*t).is_none()));

        // The first response arrives: its outcome is kept, and the waiting request goes out.
        let (first, _) = control
            .blocks_in_flight
            .iter()
            .find(|(_, t)| **t == tickets[0])
            .map(|(id, t)| (*id, *t))
            .unwrap();
        control.on_response(peers[0], p, first, Vec::new());
        assert_eq!(control.outbound.in_flight(p), 2);
        assert!(control.blocks_in_flight.values().any(|t| *t == tickets[2]));
        assert!(control.pending.iter().any(|e| matches!(
            e,
            ToSwarm::GenerateEvent(ControlEvent::BlocksByRange { ticket, .. }) if *ticket == tickets[0]
        )));
        assert!(matches!(control.take_blocks(tickets[0]), Some(Ok(chunks)) if chunks.is_empty()));
        assert!(control.take_blocks(tickets[0]).is_none(), "taken once");

        // Every behaviour numbers its own request IDs: another protocol's failure under the
        // same ID leaves the ticket open.
        let second_id = control
            .blocks_in_flight
            .iter()
            .find(|(_, t)| **t == tickets[1])
            .map(|(id, _)| *id)
            .unwrap();
        control.on_outbound_failure(
            peers[1],
            Protocol::StatusV2,
            second_id,
            OutboundFailure::Timeout,
        );
        assert!(control.blocks_in_flight.contains_key(&second_id));
        assert!(control.take_blocks(tickets[1]).is_none());
        assert_eq!(control.outbound.in_flight(p), 2, "nor frees its slot");

        // A cancelled ticket's outcome is dropped when it comes.
        control.cancel_blocks(tickets[1]);
        let second = control
            .blocks_in_flight
            .iter()
            .find(|(_, t)| **t == tickets[1])
            .map(|(id, _)| *id)
            .unwrap();
        control.on_outbound_failure(peers[1], p, second, OutboundFailure::Timeout);
        assert!(control.take_blocks(tickets[1]).is_none());
        assert_eq!(control.outbound.in_flight(p), 1);

        // A waiting request whose peer left ends as Disconnected when its turn comes.
        let sent = control.request_blocks(peers[3], range).unwrap();
        let blocked = control.request_blocks(peers[3], range).unwrap();
        assert_eq!(control.outbound.in_flight(p), 2);
        connection(&mut control, peers[3], 3, false);
        let third = control
            .blocks_in_flight
            .iter()
            .find(|(_, t)| **t == tickets[2])
            .map(|(id, _)| *id)
            .unwrap();
        control.on_outbound_failure(peers[2], p, third, OutboundFailure::ConnectionClosed);
        assert!(matches!(
            control.take_blocks(tickets[2]),
            Some(Err(OutboundError::Disconnected))
        ));
        assert!(matches!(
            control.take_blocks(blocked),
            Some(Err(OutboundError::Disconnected))
        ));
        assert!(control.take_blocks(sent).is_none(), "still in flight");
    }

    #[test]
    fn blocks_requests_start_at_the_peers_earliest_available_slot() {
        use p2p_wire::rpc::messages::BlocksByRangeV2Request;
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = RpcMetrics::register(&mut registry);
        let mut control = Control::<consensus_types::Minimal>::new(
            crate::testkit::control_config(Some(testkit::status())),
            metrics.clone(),
        );
        let (served, unjudged, invalid) = (PeerId::random(), PeerId::random(), PeerId::random());
        for (n, peer) in [served, unjudged, invalid].into_iter().enumerate() {
            connection(&mut control, peer, n, true);
        }
        let from = |earliest_available_slot| StatusV2 {
            earliest_available_slot,
            ..testkit::status()
        };
        control.judge(served, from(64), StatusVia::Response);
        control.judge(
            invalid,
            StatusV2 {
                fork_digest: [9; 4],
                ..from(0)
            },
            StatusVia::Response,
        );
        let at = |start_slot| BlocksByRangeV2Request {
            start_slot,
            count: 8,
            step: 1,
        };
        let refused = |control: &mut Control<consensus_types::Minimal>, peer, start| match control
            .request_blocks(peer, at(start))
        {
            Err(RangeError::Outbound(OutboundError::InvalidRequest(why))) => why,
            other => panic!("{other:?}"),
        };
        let p = Protocol::BlocksByRangeV2;
        // Below the peer's earliest_available_slot, or to a peer without a valid Status: refused
        // before it takes a slot.
        let why = refused(&mut control, served, 56);
        assert!(why.contains("start_slot 56") && why.contains("64"), "{why}");
        assert!(refused(&mut control, unjudged, 64).contains("no valid Status"));
        assert!(refused(&mut control, invalid, 64).contains("no valid Status"));
        assert_eq!(control.outbound.in_flight(p), 0);

        // Two in flight, two waiting; while they wait the peer's Status moves its
        // earliest_available_slot past the first waiting one's start.
        let tickets: Vec<_> = [64, 64, 64, 128]
            .into_iter()
            .map(|start| control.request_blocks(served, at(start)).unwrap())
            .collect();
        assert_eq!(control.outbound.in_flight(p), 2);
        control.judge(served, from(100), StatusVia::Response);
        let first = control
            .blocks_in_flight
            .iter()
            .find(|(_, t)| **t == tickets[0])
            .map(|(id, _)| *id)
            .unwrap();
        control.on_response(served, p, first, Vec::new());
        // The waiting request from 64 ends with the refusal; the one from 128 takes the slot.
        match control.take_blocks(tickets[2]) {
            Some(Err(OutboundError::InvalidRequest(why))) => {
                assert!(why.contains("earliest_available_slot 100"), "{why}");
            }
            other => panic!("{other:?}"),
        }
        assert!(control.blocks_in_flight.values().any(|t| *t == tickets[3]));
        assert_eq!(control.outbound.in_flight(p), 2);
        assert_eq!(metrics.outbound_inflight(p), 2);
        // Both finish: the slots are free again.
        for ticket in [tickets[1], tickets[3]] {
            let id = control
                .blocks_in_flight
                .iter()
                .find(|(_, t)| **t == ticket)
                .map(|(id, _)| *id)
                .unwrap();
            control.on_outbound_failure(served, p, id, OutboundFailure::Timeout);
        }
        assert_eq!(control.outbound.in_flight(p), 0);
        assert_eq!(metrics.outbound_inflight(p), 0);

        // A waiting request whose peer's Status turns invalid is dropped: that peer got our
        // Goodbye, and nothing else goes out after it.
        control.judge(served, from(0), StatusVia::Response);
        let tickets: Vec<_> = (0..3)
            .map(|_| control.request_blocks(served, at(64)).unwrap())
            .collect();
        control.judge(
            served,
            StatusV2 {
                fork_digest: [9; 4],
                ..from(0)
            },
            StatusVia::Response,
        );
        let id = control
            .blocks_in_flight
            .iter()
            .find(|(_, t)| **t == tickets[0])
            .map(|(id, _)| *id)
            .unwrap();
        control.on_response(served, p, id, Vec::new());
        assert!(matches!(
            control.take_blocks(tickets[2]),
            Some(Err(OutboundError::Disconnected))
        ));
        assert_eq!(control.outbound.in_flight(p), 1);
    }

    #[test]
    fn status_valid_peers_carry_their_last_status() {
        let mut control = Control::<consensus_types::Minimal>::new(
            crate::testkit::control_config(Some(testkit::status())),
            RpcMetrics::register(&mut prometheus_client::registry::Registry::default()),
        );
        let (valid, invalid, unjudged) = (PeerId::random(), PeerId::random(), PeerId::random());
        for (n, peer) in [valid, invalid, unjudged].into_iter().enumerate() {
            connection(&mut control, peer, n, true);
        }
        let theirs = StatusV2 {
            head_slot: 99,
            earliest_available_slot: 64,
            ..testkit::status()
        };
        control.judge(valid, theirs.clone(), StatusVia::Response);
        control.judge(
            invalid,
            StatusV2 {
                fork_digest: [9; 4],
                ..testkit::status()
            },
            StatusVia::Response,
        );
        assert_eq!(control.status_valid_peers(), [(valid, theirs)]);
        connection(&mut control, valid, 0, false);
        assert!(control.status_valid_peers().is_empty());
    }

    /// A source whose MetaData changes on every read: `seq_number` and `custody_group_count`
    /// both `n` on the `n`th.
    #[derive(Default)]
    struct Ticking(AtomicU64);

    impl MetaDataSource for Ticking {
        fn metadata(&self) -> MetaDataV3 {
            let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
            MetaDataV3 {
                seq_number: n,
                attnets: Default::default(),
                syncnets: Default::default(),
                custody_group_count: n,
            }
        }
    }

    #[test]
    fn local_metadata_is_one_snapshot() {
        let cfg = ControlConfig {
            metadata: Arc::new(Ticking::default()),
            ..crate::testkit::control_config(None)
        };
        let control = Control::<consensus_types::Minimal>::new(
            cfg,
            RpcMetrics::register(&mut prometheus_client::registry::Registry::default()),
        );
        // Each read is one snapshot: the seq_number numbers the fields it came with.
        for _ in 0..3 {
            let metadata = control.local_metadata();
            assert_eq!(metadata.seq_number, metadata.custody_group_count);
        }
    }

    #[test]
    fn shared_metadata_replaces_every_field_at_once() {
        let metadata = |seq_number, custody_group_count| MetaDataV3 {
            seq_number,
            attnets: Default::default(),
            syncnets: Default::default(),
            custody_group_count,
        };
        let shared = SharedMetaData::new(metadata(1, 4));
        assert_eq!(shared.metadata(), metadata(1, 4));
        shared.set(metadata(2, 8));
        assert_eq!(MetaDataSource::metadata(&shared), metadata(2, 8));
    }

    #[test]
    fn a_seq_announced_while_our_request_is_open_is_fetched_next() {
        let (mut control, _, peers) = control_with_peers(1, 8);
        let peer = peers[0];
        let open = |control: &Control<consensus_types::Minimal>| -> Vec<OutboundRequestId> {
            control
                .in_flight
                .iter()
                .filter(|(p, _)| *p == Protocol::MetaDataV3)
                .map(|(_, id)| *id)
                .collect()
        };
        let answer = |seq_number| {
            success_chunk::<consensus_types::Minimal>(Response::MetaData(MetaDataV3 {
                seq_number,
                ..testkit::metadata()
            }))
        };
        // The peer announces 9: one request. It announces 10 while that one is open.
        control.on_peer_seq(peer, 9);
        let [first] = open(&control)[..] else {
            panic!("one request")
        };
        control.on_peer_seq(peer, 10);
        control.on_peer_seq(peer, 10);
        assert_eq!(
            open(&control),
            [first],
            "no second request while one is open"
        );
        // The answer is the old MetaData: 10 is asked for once more, right away.
        control.on_response(peer, Protocol::MetaDataV3, first, answer(9));
        let [second] = open(&control)[..] else {
            panic!("one more request")
        };
        assert_ne!(second, first);
        // That answer still says 9 (the peer lags its own Ping): no third request until the
        // next announcement.
        control.on_response(peer, Protocol::MetaDataV3, second, answer(9));
        assert!(open(&control).is_empty());
        assert_eq!(control.peers[&peer].metadata_seq, Some(9));
        control.on_peer_seq(peer, 10);
        let [third] = open(&control)[..] else {
            panic!("a request for the next announcement")
        };
        // An answer that catches up with the announcement asks for nothing more, nor does a
        // failed request leave one pending.
        control.on_response(peer, Protocol::MetaDataV3, third, answer(10));
        assert!(open(&control).is_empty());
        control.on_peer_seq(peer, 11);
        let [fourth] = open(&control)[..] else {
            panic!("a request for 11")
        };
        control.on_peer_seq(peer, 12);
        control.on_outbound_failure(peer, Protocol::MetaDataV3, fourth, OutboundFailure::Timeout);
        assert!(open(&control).is_empty());
        assert_eq!(control.peers[&peer].metadata_seq, Some(10));
    }

    /// Polls `control` once, as the swarm would.
    fn poll_once(control: &mut Control<consensus_types::Minimal>) {
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        while control.poll(&mut cx).is_ready() {}
    }

    #[tokio::test(start_paused = true)]
    async fn every_peer_is_pinged_each_interval_until_our_goodbye() {
        let interval = Duration::from_secs(1);
        let cfg = ControlConfig {
            ping_interval: interval,
            ..crate::testkit::control_config(Some(testkit::status()))
        };
        let (mut control, _, peers) = control_with(cfg, 2);
        let pings = |control: &mut Control<consensus_types::Minimal>| {
            let open: Vec<_> = control
                .peers
                .iter()
                .filter_map(|(peer, state)| state.ping.map(|id| (*peer, id)))
                .collect();
            for &(peer, id) in &open {
                control.on_outbound_failure(peer, Protocol::PingV1, id, OutboundFailure::Timeout);
            }
            open.len()
        };
        // Connected now: the first Ping is one interval away, then one each interval.
        poll_once(&mut control);
        assert_eq!(pings(&mut control), 0);
        for _ in 0..2 {
            tokio::time::advance(interval).await;
            poll_once(&mut control);
            assert_eq!(pings(&mut control), 2, "one each");
        }
        poll_once(&mut control);
        let next = control.timer.as_ref().unwrap().deadline();
        assert_eq!(next, control.peers[&peers[0]].next_ping);
        // After our Goodbye a peer is pinged no more; with none left, no timer.
        for peer in &peers {
            control.goodbye(*peer, GOODBYE_CLIENT_SHUTDOWN);
        }
        tokio::time::advance(interval).await;
        poll_once(&mut control);
        assert_eq!(pings(&mut control), 0);
        assert!(control.timer.is_none());
    }

    /// Answers or fails every Ping of `control` that is due by `answers` (Ping ID → when, and
    /// whether it is answered); notes each new one, at `now`, in `sent` (peer → send times).
    fn run_pings(
        control: &mut Control<consensus_types::Minimal>,
        now: Instant,
        answers: &mut HashMap<OutboundRequestId, (PeerId, Instant, bool)>,
        sent: &mut HashMap<PeerId, Vec<Instant>>,
        delay: impl Fn(PeerId, usize) -> Option<Duration>,
    ) {
        let due: Vec<_> = answers
            .iter()
            .filter(|(_, (_, at, _))| *at <= now)
            .map(|(id, (peer, _, answered))| (*id, *peer, *answered))
            .collect();
        for (id, peer, answered) in due {
            answers.remove(&id);
            if answered {
                let pong = success_chunk(Response::Ping(Ping(1)));
                control.on_response(peer, Protocol::PingV1, id, pong);
            } else {
                control.on_outbound_failure(peer, Protocol::PingV1, id, OutboundFailure::Timeout);
            }
        }
        poll_once(control);
        let open: Vec<_> = control
            .peers
            .iter()
            .filter_map(|(peer, state)| state.ping.map(|id| (*peer, id)))
            .collect();
        for (peer, id) in open {
            if let std::collections::hash_map::Entry::Vacant(slot) = answers.entry(id) {
                let times = sent.entry(peer).or_default();
                times.push(now);
                // `None`: never answered; the first-byte deadline fails it at 5 s.
                let (after, answered) = delay(peer, times.len() - 1)
                    .map_or((Duration::from_secs(5), false), |d| (d, true));
                slot.insert((peer, now + after, answered));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pings_to_160_peers_keep_every_healthy_connection_up() {
        // A full swarm: 6 peers never answer (each Ping holds its stream for the 5 s first-byte
        // deadline), the other 154 answer in 300 ms. Through one shared 2-slot lane that is
        // 10.7 Pings/s needing over 3 slots: the queue would grow without end and healthy
        // connections would sit idle past the 30 s timeout. Each peer's own Ping lane keeps
        // every connection's quiet gaps under it.
        let idle = crate::transport::DEFAULT_IDLE_CONNECTION_TIMEOUT;
        let (mut control, metrics, peers) = control_with_peers(160, 256);
        let silent: HashSet<PeerId> = peers[..6].iter().copied().collect();
        let start = Instant::now();
        let mut answers = HashMap::new();
        let mut sent: HashMap<PeerId, Vec<Instant>> = HashMap::new();
        let step = Duration::from_millis(100);
        let mut most_open = 0;
        while start.elapsed() < Duration::from_secs(600) {
            tokio::time::advance(step).await;
            let now = Instant::now();
            run_pings(&mut control, now, &mut answers, &mut sent, |peer, _| {
                (!silent.contains(&peer)).then_some(Duration::from_millis(300))
            });
            most_open = most_open.max(metrics.outbound_inflight(Protocol::PingV1));
        }
        for peer in peers.iter().filter(|p| !silent.contains(p)) {
            let times = &sent[peer];
            // Quiet from connecting until the first Ping, then between two Pings: each Ping
            // stream lasts 300 ms, so the gap is the time between sends less that.
            let mut quiet_from = start;
            for at in times {
                assert!(
                    *at - quiet_from < idle,
                    "{peer}: quiet {:?}",
                    *at - quiet_from
                );
                quiet_from = *at + Duration::from_millis(300);
            }
            assert!(times.len() >= 600 / 16, "{peer}: {} Pings", times.len());
        }
        // More Pings than the shared lane's 2 slots were open at once.
        assert!(most_open > MAX_CONCURRENT_REQUESTS as i64, "{most_open}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_ping_is_never_followed_by_a_burst() {
        // The peer holds our first Ping 40 s. No second Ping goes out while it is open, and the
        // next one comes an interval after it ended: never 3 (Lighthouse's limit is 2) in 10 s.
        let (mut control, _, peers) = control_with_peers(1, 8);
        let start = Instant::now();
        let mut answers = HashMap::new();
        let mut sent: HashMap<PeerId, Vec<Instant>> = HashMap::new();
        while start.elapsed() < Duration::from_secs(120) {
            tokio::time::advance(Duration::from_millis(100)).await;
            run_pings(
                &mut control,
                Instant::now(),
                &mut answers,
                &mut sent,
                |_, n| Some(Duration::from_millis(if n == 0 { 40_000 } else { 50 })),
            );
        }
        let times = &sent[&peers[0]];
        let offsets: Vec<u64> = times.iter().map(|t| (*t - start).as_secs()).collect();
        assert_eq!(offsets[..2], [15, 70], "{offsets:?}");
        for pair in times.windows(2) {
            assert!(pair[1] - pair[0] >= PING_INTERVAL, "{offsets:?}");
        }
    }

    #[test]
    fn nothing_but_the_goodbye_goes_out_after_it() {
        let (mut control, _, peers) = control_with_peers(3, 8);
        // Two Status requests hold the lane's slots; a third, to the peer we then say
        // Goodbye to, waits.
        for peer in &peers {
            assert!(control.send_status(*peer));
        }
        let bye = peers[2];
        control.goodbye(bye, GOODBYE_CLIENT_SHUTDOWN);
        // No Ping to it from now on, by hand or by the cadence.
        control.ping(bye);
        assert!(control.peers[&bye].ping.is_none());
        // The waiting Status is dropped when its turn comes, not sent after the Goodbye.
        let first = *control
            .in_flight
            .iter()
            .find(|(p, _)| *p == Protocol::StatusV2)
            .unwrap();
        control.on_outbound_failure(peers[0], first.0, first.1, OutboundFailure::Timeout);
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 1);
        // The other peers are still pinged.
        control.ping(peers[0]);
        assert!(control.peers[&peers[0]].ping.is_some());
    }

    #[test]
    fn late_answers_send_nothing_after_our_goodbye() {
        let (mut control, _, peers) = control_with_peers(2, 8);
        let (late_pong, refetch) = (peers[0], peers[1]);
        let metadata_requests = |control: &Control<consensus_types::Minimal>| {
            control
                .in_flight
                .iter()
                .filter(|(p, _)| *p == Protocol::MetaDataV3)
                .count()
        };
        let metadata = |seq_number| {
            success_chunk::<consensus_types::Minimal>(Response::MetaData(MetaDataV3 {
                seq_number,
                ..testkit::metadata()
            }))
        };
        let open_metadata = |control: &Control<consensus_types::Minimal>, n: usize| {
            let mut ids: Vec<_> = control
                .in_flight
                .iter()
                .filter(|(p, _)| *p == Protocol::MetaDataV3)
                .map(|(_, id)| *id)
                .collect();
            ids.sort_unstable();
            ids[n]
        };
        // Both Status-valid. A Ping to one peer and a MetaData request to the other are open,
        // the second with a newer seq_number announced meanwhile; then both get our Goodbye.
        for peer in &peers {
            control.judge(*peer, testkit::status(), StatusVia::Response);
        }
        control.ping(late_pong);
        let pong_id = control.peers[&late_pong].ping.unwrap();
        control.on_peer_seq(refetch, 3);
        let refetch_id = open_metadata(&control, 0);
        control.on_peer_seq(refetch, 9);
        control.goodbye(late_pong, GOODBYE_CLIENT_SHUTDOWN);
        control.goodbye(refetch, GOODBYE_CLIENT_SHUTDOWN);
        // The late Pong announces a seq_number we never fetched: no GetMetaData.
        let pong = success_chunk(Response::Ping(Ping(7)));
        control.on_response(late_pong, Protocol::PingV1, pong_id, pong);
        assert_eq!(metadata_requests(&control), 1, "only the open one");
        // The open request ends below the announced 9: no refetch.
        control.on_response(refetch, Protocol::MetaDataV3, refetch_id, metadata(3));
        assert_eq!(metadata_requests(&control), 0);
        // Nor anything asked for by hand, but the Goodbye already sent.
        control.request_metadata(late_pong);
        assert!(!control.send_status(refetch));
        assert_eq!(metadata_requests(&control), 0);
        assert!(matches!(
            control.request_blocks(
                refetch,
                BlocksByRangeV2Request {
                    start_slot: 8,
                    count: 8,
                    step: 1
                }
            ),
            Err(RangeError::Outbound(OutboundError::Disconnected))
        ));
    }

    /// A Status source read fresh, as the service's from cl-chain: each read runs when first
    /// polled, takes `delay`, and reads the floor then; the next `failing` reads fail.
    #[derive(Default)]
    struct LiveFloor {
        floor: AtomicU64,
        failing: AtomicU64,
        delay_ms: AtomicU64,
        /// The floor each good read returned, in order; a failed read is `None`.
        reads: std::sync::Mutex<Vec<Option<u64>>>,
    }

    struct LiveReads(Arc<LiveFloor>);

    impl StatusSource for LiveReads {
        fn status(&self) -> Option<StatusV2> {
            Some(testkit::status())
        }

        fn fresh(&self) -> Option<StatusLookup> {
            let live = Arc::clone(&self.0);
            Some(Box::pin(async move {
                let delay = live.delay_ms.load(Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(delay)).await;
                // One task polls the reads at a time: a load and a store suffice.
                let failing = live.failing.load(Ordering::SeqCst);
                let failed = failing > 0;
                if failed {
                    live.failing.store(failing - 1, Ordering::SeqCst);
                }
                let read = (!failed).then(|| live.floor.load(Ordering::SeqCst));
                live.reads.lock().unwrap().push(read);
                read.map(|earliest_available_slot| StatusV2 {
                    earliest_available_slot,
                    ..testkit::status()
                })
            }))
        }
    }

    impl LiveFloor {
        fn reads(&self) -> Vec<Option<u64>> {
            self.reads.lock().unwrap().clone()
        }
    }

    /// A Control reading its Status fresh from `live`, with `n` peers connected.
    fn control_reading(
        live: &Arc<LiveFloor>,
        n: usize,
    ) -> (Control<consensus_types::Minimal>, RpcMetrics, Vec<PeerId>) {
        let cfg = ControlConfig {
            status: Arc::new(LiveReads(Arc::clone(live))),
            ..crate::testkit::control_config(None)
        };
        control_with(cfg, n)
    }

    fn statuses_in_flight(control: &Control<consensus_types::Minimal>) -> Vec<OutboundRequestId> {
        control
            .in_flight
            .iter()
            .filter(|(p, _)| *p == Protocol::StatusV2)
            .map(|(_, id)| *id)
            .collect()
    }

    /// A Status waiting for its slot is read when it gets the slot, not when it was asked
    /// for: a floor that rose meanwhile is what it carries.
    #[tokio::test(start_paused = true)]
    async fn a_queued_status_is_read_when_it_gets_its_slot() {
        let live = Arc::new(LiveFloor::default());
        live.floor.store(100, Ordering::SeqCst);
        let (mut control, metrics, peers) = control_reading(&live, 3);
        for peer in &peers {
            assert!(control.send_status(*peer));
        }
        poll_once(&mut control);
        assert_eq!(
            live.reads(),
            [Some(100), Some(100)],
            "the third waits, unread"
        );
        assert_eq!(statuses_in_flight(&control).len(), 2);
        assert_eq!(metrics.outbound_inflight(Protocol::StatusV2), 2);
        live.floor.store(140, Ordering::SeqCst);
        let first = statuses_in_flight(&control)[0];
        control.on_outbound_failure(
            peers[0],
            Protocol::StatusV2,
            first,
            OutboundFailure::Timeout,
        );
        poll_once(&mut control);
        assert_eq!(live.reads(), [Some(100), Some(100), Some(140)]);
        assert_eq!(statuses_in_flight(&control).len(), 2);
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 2);
        // While a read runs it holds the slot; a peer gone by its end gives it back.
        live.delay_ms.store(100, Ordering::SeqCst);
        for id in statuses_in_flight(&control) {
            control.on_outbound_failure(peers[1], Protocol::StatusV2, id, OutboundFailure::Timeout);
        }
        assert!(control.send_status(peers[1]));
        poll_once(&mut control);
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 1);
        connection(&mut control, peers[1], 1, false);
        tokio::time::advance(Duration::from_millis(100)).await;
        poll_once(&mut control);
        assert_eq!(live.reads().len(), 4);
        assert!(
            statuses_in_flight(&control).is_empty(),
            "none sent to a peer gone"
        );
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 0);
        assert_eq!(metrics.outbound_inflight(Protocol::StatusV2), 0);
    }

    /// A failed fresh read on a dial is retried after a backoff, the slot free meanwhile, and
    /// the Status goes out once a read succeeds.
    #[tokio::test(start_paused = true)]
    async fn a_failed_status_read_on_a_dial_is_retried() {
        let live = Arc::new(LiveFloor::default());
        live.floor.store(100, Ordering::SeqCst);
        live.failing.store(1, Ordering::SeqCst);
        let (mut control, _, peers) = control_reading(&live, 1);
        assert!(control.send_status(peers[0]));
        poll_once(&mut control);
        assert_eq!(live.reads(), [None]);
        assert!(statuses_in_flight(&control).is_empty());
        assert_eq!(
            control.outbound.in_flight(Protocol::StatusV2),
            0,
            "free meanwhile"
        );
        tokio::time::advance(STATUS_RETRY_BACKOFF - Duration::from_millis(1)).await;
        poll_once(&mut control);
        assert_eq!(live.reads(), [None], "not before the backoff");
        tokio::time::advance(Duration::from_millis(1)).await;
        poll_once(&mut control);
        assert_eq!(live.reads(), [None, Some(100)]);
        assert_eq!(statuses_in_flight(&control).len(), 1, "sent");
        assert!(control.peers[&peers[0]].status_retry.is_none());
    }

    /// Reads that keep failing give up after [`STATUS_SEND_ATTEMPTS`], or when the next
    /// would start past [`STATUS_HANDSHAKE_DEADLINE`] after the dial; a peer that leaves or
    /// gets our Goodbye stops them.
    #[tokio::test(start_paused = true)]
    async fn repeated_failed_status_reads_give_up_after_the_bound() {
        // Instant reads: the attempt bound, at 0, 0.5, 1.5 and 3.5 s.
        let live = Arc::new(LiveFloor::default());
        live.failing.store(u64::MAX, Ordering::SeqCst);
        let (mut control, _, peers) = control_reading(&live, 3);
        assert!(control.send_status(peers[0]));
        let start = Instant::now();
        let mut at = Vec::new();
        for _ in 0..300 {
            poll_once(&mut control);
            if live.reads().len() > at.len() {
                at.push((Instant::now() - start).as_millis());
            }
            tokio::time::advance(Duration::from_millis(50)).await;
        }
        assert_eq!(at, [0, 500, 1_500, 3_500]);
        assert_eq!(STATUS_SEND_ATTEMPTS, 4);
        assert!(statuses_in_flight(&control).is_empty());
        assert!(control.peers[&peers[0]].status_retry.is_none());
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 0);

        // Slow reads (4 s each): the deadline bounds them first. The third read starts at
        // 9.5 s; the next would start at 15.5 s, past 10 s.
        let slow = Arc::new(LiveFloor::default());
        slow.failing.store(u64::MAX, Ordering::SeqCst);
        slow.delay_ms.store(4_000, Ordering::SeqCst);
        let (mut control, _, peers) = control_reading(&slow, 1);
        assert!(control.send_status(peers[0]));
        for _ in 0..600 {
            poll_once(&mut control);
            tokio::time::advance(Duration::from_millis(50)).await;
        }
        assert_eq!(slow.reads().len(), 3);
        assert!(control.peers[&peers[0]].status_retry.is_none());

        // A peer that leaves, or that we say Goodbye to, during the backoff: no more reads.
        let gone = Arc::new(LiveFloor::default());
        gone.failing.store(u64::MAX, Ordering::SeqCst);
        let (mut control, _, peers) = control_reading(&gone, 2);
        assert!(control.send_status(peers[0]));
        assert!(control.send_status(peers[1]));
        poll_once(&mut control);
        assert_eq!(gone.reads().len(), 2);
        connection(&mut control, peers[0], 0, false);
        control.goodbye(peers[1], GOODBYE_CLIENT_SHUTDOWN);
        for _ in 0..100 {
            tokio::time::advance(Duration::from_millis(100)).await;
            poll_once(&mut control);
        }
        assert_eq!(gone.reads().len(), 2);
        assert!(!control.send_status(peers[1]), "after our Goodbye");
    }

    /// A read that outlives its connection is not sent on the peer's next connection: the
    /// slot it held goes back, and the new connection's own read is what goes out there.
    #[tokio::test(start_paused = true)]
    async fn a_read_of_a_closed_connection_is_not_sent_on_the_next() {
        let live = Arc::new(LiveFloor::default());
        live.floor.store(100, Ordering::SeqCst);
        live.delay_ms.store(1_000, Ordering::SeqCst);
        let (mut control, _, peers) = control_reading(&live, 1);
        assert!(control.send_status(peers[0]));
        poll_once(&mut control);
        // Half way through the read the connection closes; the peer is back at once, and our
        // Status on the new connection is read in the other slot.
        tokio::time::advance(Duration::from_millis(500)).await;
        connection(&mut control, peers[0], 0, false);
        connection(&mut control, peers[0], 1, true);
        assert!(control.send_status(peers[0]));
        poll_once(&mut control);
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 2);
        // The old read ends.
        tokio::time::advance(Duration::from_millis(500)).await;
        poll_once(&mut control);
        assert_eq!(live.reads(), [Some(100)]);
        assert!(
            statuses_in_flight(&control).is_empty(),
            "the old connection's read is not sent on the new one"
        );
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 1);
        // The new one's read ends, and goes out.
        tokio::time::advance(Duration::from_millis(500)).await;
        poll_once(&mut control);
        assert_eq!(live.reads(), [Some(100), Some(100)]);
        assert_eq!(statuses_in_flight(&control).len(), 1);
    }

    /// A failed read that outlives its connection schedules no retry on the peer's next one:
    /// the new connection's dial gets its own [`STATUS_SEND_ATTEMPTS`] reads, no more.
    #[tokio::test(start_paused = true)]
    async fn a_failed_read_of_a_closed_connection_retries_nothing_on_the_next() {
        let live = Arc::new(LiveFloor::default());
        live.failing.store(u64::MAX, Ordering::SeqCst);
        live.delay_ms.store(1_000, Ordering::SeqCst);
        let (mut control, _, peers) = control_reading(&live, 1);
        assert!(control.send_status(peers[0]));
        poll_once(&mut control);
        tokio::time::advance(Duration::from_millis(500)).await;
        connection(&mut control, peers[0], 0, false);
        connection(&mut control, peers[0], 1, true);
        assert!(control.send_status(peers[0]));
        for _ in 0..400 {
            poll_once(&mut control);
            tokio::time::advance(Duration::from_millis(50)).await;
        }
        // The old connection's one read, then the new one's four (from 0.5 s: at 0.5, 2, 4
        // and 7 s, each failing a second later).
        assert_eq!(live.reads().len(), 1 + STATUS_SEND_ATTEMPTS as usize);
        assert!(control.peers[&peers[0]].status_retry.is_none());
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 0);
    }

    /// A retry queued behind two held Status slots past its dial's
    /// [`STATUS_HANDSHAKE_DEADLINE`] never starts a read: it is dropped when its turn comes, and
    /// its slot goes to the next one waiting.
    #[tokio::test(start_paused = true)]
    async fn a_retry_queued_past_its_deadline_starts_no_read() {
        let live = Arc::new(LiveFloor::default());
        live.floor.store(100, Ordering::SeqCst);
        live.failing.store(1, Ordering::SeqCst);
        let (mut control, _, peers) = control_reading(&live, 4);
        let (late, held, other, next) = (peers[0], peers[1], peers[2], peers[3]);
        // `late`'s read fails; its retry is due in 500 ms.
        assert!(control.send_status(late));
        poll_once(&mut control);
        assert_eq!(live.reads(), [None]);
        // Two Statuses go out meanwhile and are never answered: both slots stay taken.
        assert!(control.send_status(held));
        assert!(control.send_status(other));
        poll_once(&mut control);
        assert_eq!(statuses_in_flight(&control).len(), 2);
        // The retry waits for a slot; so does another dial's Status, 5 s on.
        tokio::time::advance(STATUS_RETRY_BACKOFF).await;
        poll_once(&mut control);
        tokio::time::advance(Duration::from_millis(4_500)).await;
        assert!(control.send_status(next));
        poll_once(&mut control);
        assert_eq!(live.reads().len(), 3, "both wait, unread");
        // A slot frees past `late`'s deadline: its retry is dropped, and the slot is `next`'s.
        tokio::time::advance(Duration::from_millis(5_500)).await;
        let freed = statuses_in_flight(&control)[0];
        control.on_outbound_failure(held, Protocol::StatusV2, freed, OutboundFailure::Timeout);
        poll_once(&mut control);
        assert_eq!(
            live.reads(),
            [None, Some(100), Some(100), Some(100)],
            "one read, `next`'s"
        );
        assert_eq!(statuses_in_flight(&control).len(), 2);
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 2);
        assert!(control.peers[&late].status_retry.is_none());
        // Nothing else waited: the next free slot starts no read.
        let freed = statuses_in_flight(&control)[0];
        control.on_outbound_failure(other, Protocol::StatusV2, freed, OutboundFailure::Timeout);
        poll_once(&mut control);
        assert_eq!(live.reads().len(), 4, "`late`'s retry never read");
        assert_eq!(control.outbound.in_flight(Protocol::StatusV2), 1);
    }

    /// With the default Status quota and both Status streams a peer may open, an answer's token
    /// is due at most two periods after its request, and its read still has time before the
    /// requester's first-byte deadline less the slack: the answer goes out in time, as one
    /// paced by the stream's writer does.
    #[test]
    fn a_status_answer_keeps_time_for_its_read_under_the_default_quota() {
        let ttfb = Deadlines::default().ttfb;
        let status = RpcLimits::default().rate.status;
        let due = status.period * MAX_CONCURRENT_REQUESTS as u32;
        let read = ttfb
            .checked_sub(STATUS_ANSWER_SLACK + due)
            .expect("a token due before the deadline");
        assert!(read >= Duration::from_millis(500), "{read:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_interval_pings_none() {
        let cfg = ControlConfig {
            ping_interval: Duration::ZERO,
            ..crate::testkit::control_config(Some(testkit::status()))
        };
        let (mut control, _, _) = control_with(cfg, 1);
        poll_once(&mut control);
        tokio::time::advance(PING_INTERVAL).await;
        poll_once(&mut control);
        assert!(control.peers.values().all(|state| state.ping.is_none()));
        assert!(control.timer.is_none());
    }

    #[test]
    fn local_metadata_carries_the_enr_cgc() {
        let cfg = ControlConfig {
            status: Arc::new(SharedStatus::new(None)),
            metadata: Arc::new(SharedMetaData::new(MetaDataV3 {
                seq_number: 11,
                attnets: Default::default(),
                syncnets: Default::default(),
                custody_group_count: 4,
            })),
            contexts: Arc::new(testkit::context_table()),
            deadlines: Deadlines::default(),
            limits: RpcLimits::default(),
            ping_interval: PING_INTERVAL,
            columns: None,
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("custody_group_count: 4"), "{debug}");
        let control = Control::<consensus_types::Minimal>::new(
            cfg,
            RpcMetrics::register(&mut prometheus_client::registry::Registry::default()),
        );
        let metadata = control.local_metadata();
        assert_eq!(metadata.seq_number, 11);
        assert_eq!(metadata.custody_group_count, 4);
        assert_eq!(metadata.attnets.num_set_bits(), 0);
        assert_eq!(metadata.syncnets.num_set_bits(), 0);
    }

    // --- streamed answers (#234) ---

    use super::super::codec::read_response_chunks;
    use super::super::limits::Quota;
    use super::super::responder::testing::{self, Lives};
    use super::super::responder::{Responder, STREAM_QUEUE_LEN};
    use consensus_types::caps::NetworkCaps;
    use futures::AsyncWrite;
    use libp2p::request_response::Codec as _;
    use std::sync::atomic::AtomicUsize;

    type Spec = consensus_types::Minimal;
    const BLOCKS: Protocol = Protocol::BlocksByRangeV2;

    fn blocks(count: u64) -> Request {
        Request::BlocksByRange(BlocksByRangeV2Request {
            start_slot: 1,
            count,
            step: 1,
        })
    }

    /// A Control serving from [`testing::serving_table`] under `limits`, with `n` peers.
    fn serving(
        n: usize,
        limits: impl FnOnce(&mut RpcLimits),
    ) -> (Control<Spec>, RpcMetrics, Vec<PeerId>) {
        let mut cfg = crate::testkit::control_config(Some(testkit::status()));
        cfg.contexts = testing::serving_table(NetworkCaps::PRESET_BOUND);
        limits(&mut cfg.limits);
        control_with(cfg, n)
    }

    /// The writer of `control`'s streams.
    fn writer(control: &Control<Spec>) -> InboundCodec<Spec> {
        let contexts = Arc::clone(&control.cfg.contexts);
        InboundCodec::new(RpcCodec::new(contexts, control.cfg.deadlines))
    }

    /// `peer`'s bytes not held by a queued chunk.
    fn free_bytes(control: &Control<Spec>, peer: PeerId) -> usize {
        control.peers[&peer].queued_bytes.available()
    }

    /// When a chunk of `peer`'s BlocksByRange bucket charged now would be due (charged and
    /// given back: a look).
    fn next_due(control: &Control<Spec>, peer: PeerId) -> Instant {
        let mut limiter = control.limiter.lock().unwrap();
        let now = Instant::now();
        let charge = limiter.charge(peer, BLOCKS, now);
        let due = charge.due();
        limiter.refund(peer, BLOCKS, charge, now);
        due
    }

    /// What a requester reads from `wire`, to its end.
    async fn read_back(wire: &[u8]) -> Vec<ResponseChunk<Spec>> {
        let contexts = testkit::context_table();
        read_response_chunks::<Spec, _>(&mut &wire[..], BLOCKS, 128, &contexts)
            .await
            .unwrap()
    }

    fn code_of(read: &[ResponseChunk<Spec>]) -> Option<ResultCode> {
        match read {
            [.., ResponseChunk::Error { code, .. }] => Some(*code),
            _ => None,
        }
    }

    /// A requester: takes a write whole once `every` passed since the last, counting them in
    /// `written`; after `accept` writes it takes none (stops reading) and, if `reset`, fails
    /// each (the peer reset the stream).
    struct Reader {
        every: Duration,
        next: Pin<Box<Sleep>>,
        bytes: Vec<u8>,
        written: Arc<AtomicUsize>,
        accept: usize,
        reset: bool,
    }

    impl Reader {
        fn new(every: Duration) -> Self {
            Self {
                every,
                next: Box::pin(tokio::time::sleep(Duration::ZERO)),
                bytes: Vec::new(),
                written: Arc::default(),
                accept: usize::MAX,
                reset: false,
            }
        }

        fn stopping_after(mut self, accept: usize, reset: bool) -> Self {
            self.accept = accept;
            self.reset = reset;
            self
        }
    }

    impl AsyncWrite for Reader {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.written.load(Ordering::SeqCst) >= self.accept {
                return match self.reset {
                    true => Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into())),
                    false => Poll::Pending,
                };
            }
            std::task::ready!(self.next.as_mut().poll(cx));
            let at = Instant::now() + self.every;
            self.next.as_mut().reset(at);
            self.bytes.extend_from_slice(buf);
            self.written.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Sends the blocks of `1..=n`, each counted in `reads` before it is read from the store,
    /// until the sink fails; holds a [`Lives`] entry.
    fn reading(n: u64, reads: &Arc<AtomicUsize>, lives: &Lives) -> Arc<dyn Responder<Spec>> {
        let (reads, lives) = (Arc::clone(reads), lives.clone());
        testing::script(move |_, mut sink| {
            let (reads, live) = (Arc::clone(&reads), lives.enter());
            async move {
                let _live = live;
                for slot in 1..=n {
                    reads.fetch_add(1, Ordering::SeqCst);
                    if sink.send(testing::block(slot)).await.is_err() {
                        return;
                    }
                }
            }
        })
    }

    /// Sends `before` blocks, then waits for good.
    fn stalls_after(before: u64, lives: &Lives) -> Arc<dyn Responder<Spec>> {
        let lives = lives.clone();
        testing::script(move |_, mut sink| {
            let live = lives.enter();
            async move {
                let _live = live;
                for slot in 1..=before {
                    sink.send(testing::block(slot)).await.unwrap();
                }
                futures::future::pending::<()>().await;
            }
        })
    }

    /// #1 (acceptance): a 128-block answer streams to a requester slower than its responder
    /// with at most what the byte budget holds queued (never more than the queue), every
    /// block whole and in order; and both deadlines fire: nothing produced by 4.5 s is
    /// `2: ServerError`, a stall after a chunk ends the answer cleanly at 9.5 s.
    #[tokio::test(start_paused = true)]
    async fn multi_chunk_bounded() {
        let sizes: Vec<usize> = (1..=128u64)
            .map(|slot| {
                let ssz = testing::block::<Spec>(slot).ssz_bytes();
                let chunk = p2p_wire::rpc::codec::encode_success_chunk(Some([0; 4]), &ssz);
                chunk.unwrap().len()
            })
            .collect();
        let smallest = *sizes.iter().min().unwrap();
        let budget = 3 * smallest;
        let (mut control, _, peers) = serving(1, |l| l.max_queued_bytes_per_peer = budget);
        let peer = peers[0];
        let reader = Reader::new(Duration::from_millis(10));
        let (written, peak) = (Arc::clone(&reader.written), Arc::new(AtomicUsize::new(0)));
        let all = {
            let (written, peak) = (Arc::clone(&written), Arc::clone(&peak));
            testing::script(move |_, mut sink| {
                let (written, peak) = (Arc::clone(&written), Arc::clone(&peak));
                async move {
                    for slot in 1..=128u64 {
                        sink.send(testing::block(slot)).await.unwrap();
                        let queued = slot as usize - written.load(Ordering::SeqCst);
                        peak.fetch_max(queued, Ordering::SeqCst);
                    }
                }
            })
        };
        let answer = control.answer_streamed(peer, BLOCKS, blocks(128), &*all);
        let mut reader = reader;
        let start = Instant::now();
        writer(&control)
            .write_response(&BLOCKS, &mut reader, answer.unwrap())
            .await
            .unwrap();
        assert!(Instant::now() - start < Duration::from_secs(2));
        let read = read_back(&reader.bytes).await;
        let slots: Vec<u64> = read
            .iter()
            .map(|c| match c {
                ResponseChunk::Success(Response::Block(b)) => b.slot(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(slots, (1..=128).collect::<Vec<_>>());
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak >= 2, "the responder ran ahead of the reader: {peak}");
        assert!(
            peak <= budget / smallest,
            "{peak} chunks queued past the byte budget"
        );
        assert!(peak <= STREAM_QUEUE_LEN + 1);
        assert_eq!(free_bytes(&control, peer), budget);
        // The deadlines, from when each answer started.
        let lives = Lives::default();
        for (before, after, read) in [(0, 4_500, 0), (1, 9_500, 1)] {
            let answer =
                control.answer_streamed(peer, BLOCKS, blocks(2), &*stalls_after(before, &lives));
            let mut reader = Reader::new(Duration::ZERO);
            let start = Instant::now();
            writer(&control)
                .write_response(&BLOCKS, &mut reader, answer.unwrap())
                .await
                .unwrap();
            assert_eq!((Instant::now() - start).as_millis(), after);
            let got = read_back(&reader.bytes).await;
            match read {
                0 => assert_eq!(code_of(&got), Some(ResultCode::ServerError)),
                _ => assert!(matches!(got[..], [ResponseChunk::Success(_)])),
            }
        }
        lives.gone().await;
    }

    /// #2 (acceptance): the peer resets the stream mid-answer. The write fails, and the
    /// answer's global slot, its peer's bytes and its responder's task are all freed at once;
    /// the tokens it booked stay spent (a reset refunds nothing, so a peer cannot request and
    /// reset its way past its quota). The freed slot serves the next stream.
    #[tokio::test(start_paused = true)]
    async fn reset_mid_response() {
        let (mut control, _, peers) = serving(1, |l| {
            l.max_inbound_streams = 1;
            l.rate.blocks_by_range = Quota::new(1, Duration::from_millis(10));
        });
        let peer = peers[0];
        let budget = control.cfg.limits.max_queued_bytes_per_peer;
        let (reads, lives) = (Arc::new(AtomicUsize::new(0)), Lives::default());
        let endless = reading(u64::MAX, &reads, &lives);
        let start = Instant::now();
        let answer = control.answer_streamed(peer, BLOCKS, blocks(128), &*endless);
        assert_eq!(
            control.streams.available_permits(),
            0,
            "the one slot is held"
        );
        assert!(control
            .answer_streamed(peer, BLOCKS, blocks(1), &*endless)
            .is_none());
        let mut reader = Reader::new(Duration::from_millis(10)).stopping_after(3, true);
        let err = writer(&control)
            .write_response(&BLOCKS, &mut reader, answer.unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        lives.gone().await;
        assert_eq!(control.streams.available_permits(), 1);
        assert_eq!(free_bytes(&control, peer), budget);
        let spent = next_due(&control, peer) - start;
        assert_eq!(
            spent,
            Duration::from_millis(1_280),
            "the 128 tokens stay spent"
        );
        let next = control.answer_streamed(peer, BLOCKS, blocks(1), &*endless);
        assert!(
            next.is_some_and(|a| a.stream.is_some()),
            "the slot serves again"
        );
    }

    /// #17 (Vera 1), #12: a request out of bounds (a `count` above MAX_REQUEST_BLOCKS_DENEB,
    /// `step` 0) is `1: InvalidRequest` before the responder runs, before any store read and
    /// before anything is booked: never clamped; one asking for nothing is an empty answer,
    /// unserved too.
    #[tokio::test(start_paused = true)]
    async fn count_over_cap_invalid_request_before_store() {
        let (mut control, _, peers) = serving(1, |_| {});
        let peer = peers[0];
        let (reads, lives) = (Arc::new(AtomicUsize::new(0)), Lives::default());
        let counting = reading(128, &reads, &lives);
        let step_0 = Request::BlocksByRange(BlocksByRangeV2Request {
            start_slot: 1,
            count: 2,
            step: 0,
        });
        for (request, code) in [
            (blocks(129), Some(ResultCode::InvalidRequest)),
            (blocks(u64::MAX), Some(ResultCode::InvalidRequest)),
            (step_0, Some(ResultCode::InvalidRequest)),
            (blocks(0), None),
        ] {
            let due = next_due(&control, peer);
            let answer = control.answer_streamed(peer, BLOCKS, request, &*counting);
            let answer = answer.unwrap();
            assert!(answer.stream.is_none(), "not served");
            assert_eq!(next_due(&control, peer), due, "nothing booked");
            let mut reader = Reader::new(Duration::ZERO);
            writer(&control)
                .write_response(&BLOCKS, &mut reader, answer)
                .await
                .unwrap();
            assert_eq!(code_of(&read_back(&reader.bytes).await), code);
        }
        assert_eq!(lives.count(), 0, "serve was never called");
        assert_eq!(reads.load(Ordering::SeqCst), 0, "no store read");
        assert_eq!(control.streams.available_permits(), 256, "no slot taken");
    }

    /// #18 (Vera 2): at most `max_inbound_streams` (256 by default) streamed answers at once
    /// across all peers: the next stream is dropped without a chunk (reset, like
    /// `request_response`'s own per-connection cap) and counted; a slot frees when an
    /// answer's writer is gone.
    #[tokio::test(start_paused = true)]
    async fn global_inbound_stream_cap() {
        assert_eq!(RpcLimits::default().max_inbound_streams, 256);
        let (mut control, metrics, peers) = serving(3, |l| l.max_inbound_streams = 2);
        let held = stalls_after(0, &Lives::default());
        let first = control.answer_streamed(peers[0], BLOCKS, blocks(1), &*held);
        let second = control.answer_streamed(peers[1], BLOCKS, blocks(1), &*held);
        assert!(first.is_some() && second.is_some());
        assert!(control
            .answer_streamed(peers[2], BLOCKS, blocks(1), &*held)
            .is_none());
        assert_eq!(metrics.inbound_streams_refused(), 1);
        drop(first);
        assert!(control
            .answer_streamed(peers[2], BLOCKS, blocks(1), &*held)
            .is_some());
        assert_eq!(metrics.inbound_streams_refused(), 1);
    }

    /// #19 (Vera 3): a responder reads its store only as fast as its stream drains: with a
    /// requester that reads nothing it stops once the queue is full, and each chunk the
    /// requester takes lets one more read through; the peer's queued bytes stay within its
    /// budget.
    #[tokio::test(start_paused = true)]
    async fn store_reads_bounded_by_queue() {
        let (mut control, _, peers) = serving(1, |_| {});
        let peer = peers[0];
        let budget = control.cfg.limits.max_queued_bytes_per_peer;
        let (reads, lives) = (Arc::new(AtomicUsize::new(0)), Lives::default());
        let responder = reading(128, &reads, &lives);
        let answer = control.answer_streamed(peer, BLOCKS, blocks(128), &*responder);
        tokio::time::sleep(Duration::from_secs(3)).await;
        // The queue's chunks and the one waiting for room.
        assert_eq!(reads.load(Ordering::SeqCst), STREAM_QUEUE_LEN + 1);
        let held = budget - free_bytes(&control, peer);
        assert!(held > 0 && held <= budget);
        // A requester that reads two chunks, then stops.
        let mut reader = Reader::new(Duration::from_millis(10)).stopping_after(2, false);
        let mut codec = writer(&control);
        let write = codec.write_response(&BLOCKS, &mut reader, answer.unwrap());
        assert!(tokio::time::timeout(Duration::from_secs(3), write)
            .await
            .is_err());
        // Written, in hand, queued, waiting: never more.
        assert_eq!(reads.load(Ordering::SeqCst), 2 + 1 + STREAM_QUEUE_LEN + 1);
        lives.gone().await;
        assert_eq!(free_bytes(&control, peer), budget);
    }

    /// #20: however a streamed answer ends without being written in full (its writer dropped:
    /// `request_response`'s backstop or a closed connection; the answer dropped before its
    /// writer started; a deadline), its global slot, its peer's bytes and its responder's task
    /// are freed.
    #[tokio::test(start_paused = true)]
    async fn drop_and_timeout_free_slot_and_task() {
        let (mut control, _, peers) = serving(1, |_| {});
        let peer = peers[0];
        let budget = control.cfg.limits.max_queued_bytes_per_peer;
        let (reads, lives) = (Arc::new(AtomicUsize::new(0)), Lives::default());
        let endless = reading(u64::MAX, &reads, &lives);
        let freed = |control: &Control<Spec>| {
            assert_eq!(control.streams.available_permits(), 256);
            assert_eq!(free_bytes(control, peer), budget);
        };
        // The writer dropped mid-answer.
        let answer = control.answer_streamed(peer, BLOCKS, blocks(128), &*endless);
        let mut reader = Reader::new(Duration::from_millis(100));
        let mut codec = writer(&control);
        let write = codec.write_response(&BLOCKS, &mut reader, answer.unwrap());
        assert!(tokio::time::timeout(Duration::from_secs(1), write)
            .await
            .is_err());
        lives.gone().await;
        freed(&control);
        // Dropped before its writer started (the stream closed first).
        let answer = control.answer_streamed(peer, BLOCKS, blocks(128), &*endless);
        tokio::task::yield_now().await;
        drop(answer);
        lives.gone().await;
        freed(&control);
        // A deadline: nothing produced in time.
        let answer = control.answer_streamed(peer, BLOCKS, blocks(1), &*stalls_after(0, &lives));
        let mut reader = Reader::new(Duration::ZERO);
        writer(&control)
            .write_response(&BLOCKS, &mut reader, answer.unwrap())
            .await
            .unwrap();
        lives.gone().await;
        freed(&control);
    }

    /// #21 (the #284 lesson): a responder that panics frees its slot and its bytes without
    /// finishing: `2: ServerError` if it sent nothing, else a clean end at its last whole
    /// chunk.
    #[tokio::test(start_paused = true)]
    async fn panicking_responder_frees_slot() {
        let (mut control, _, peers) = serving(1, |l| l.max_inbound_streams = 1);
        let peer = peers[0];
        let budget = control.cfg.limits.max_queued_bytes_per_peer;
        for before in [0u64, 2] {
            let buggy = testing::script(move |_, mut sink| async move {
                for slot in 1..=before {
                    sink.send(testing::block(slot)).await.unwrap();
                }
                panic!("a responder bug");
            });
            let answer = control.answer_streamed(peer, BLOCKS, blocks(4), &*buggy);
            let mut reader = Reader::new(Duration::ZERO);
            writer(&control)
                .write_response(&BLOCKS, &mut reader, answer.unwrap())
                .await
                .unwrap();
            let read = read_back(&reader.bytes).await;
            match before {
                0 => assert_eq!(code_of(&read), Some(ResultCode::ServerError)),
                _ => assert!(matches!(
                    read[..],
                    [ResponseChunk::Success(_), ResponseChunk::Success(_)]
                )),
            }
            assert_eq!(control.streams.available_permits(), 1, "the slot is back");
            assert_eq!(free_bytes(&control, peer), budget);
        }
    }

    /// Ruling 2 (Vera 2): a streamed request books [`Responder::cost`] of its peer's (peer,
    /// protocol) bucket when it is admitted (by default the items it asks for), so a peer over
    /// its quota is held back from its first request on: its chunks go out at the booked
    /// tokens, withheld whole, never an error. What the answer did not use goes back once it
    /// ended, the store read's one token aside; a custom cost books its own.
    #[tokio::test(start_paused = true)]
    async fn cost_booked_at_admission_and_given_back_once() {
        let (mut control, _, peers) = serving(1, |l| {
            l.rate.blocks_by_range = Quota::new(1, Duration::from_secs(1));
        });
        let peer = peers[0];
        let start = Instant::now();
        let two = testing::script(|_, mut sink| async move {
            for slot in 1..=2 {
                sink.send(testing::block(slot)).await.unwrap();
            }
        });
        let answer = control.answer_streamed(peer, BLOCKS, blocks(10), &*two);
        assert_eq!(
            next_due(&control, peer) - start,
            Duration::from_secs(10),
            "10 booked"
        );
        let mut reader = Reader::new(Duration::ZERO);
        writer(&control)
            .write_response(&BLOCKS, &mut reader, answer.unwrap())
            .await
            .unwrap();
        assert_eq!(read_back(&reader.bytes).await.len(), 2);
        assert_eq!(
            Instant::now() - start,
            Duration::from_secs(1),
            "the second withheld 1 s"
        );
        assert_eq!(
            next_due(&control, peer) - start,
            Duration::from_secs(2),
            "8 went back"
        );
        let nothing = testing::script(|_, _| async {});
        let answer = control.answer_streamed(peer, BLOCKS, blocks(10), &*nothing);
        let mut reader = Reader::new(Duration::ZERO);
        writer(&control)
            .write_response(&BLOCKS, &mut reader, answer.unwrap())
            .await
            .unwrap();
        assert_eq!(
            next_due(&control, peer) - start,
            Duration::from_secs(3),
            "the read's token stays"
        );
        struct Flat(Arc<dyn Responder<Spec>>);
        impl Responder<Spec> for Flat {
            fn cost(&self, _: &Request) -> u64 {
                5
            }
            fn serve(
                &self,
                peer: PeerId,
                request: Request,
                sink: super::super::responder::ChunkSink<Spec>,
            ) -> super::super::responder::Serving {
                self.0.serve(peer, request, sink)
            }
        }
        let flat = Flat(testing::script(|_, _| futures::future::pending()));
        let _held = control.answer_streamed(peer, BLOCKS, blocks(128), &flat);
        assert_eq!(
            next_due(&control, peer) - start,
            Duration::from_secs(8),
            "5 booked"
        );
    }

    // --- streamed answers on local swarms (TCP, noise, yamux; real time) ---

    use libp2p::swarm::SwarmEvent;
    use libp2p::{noise, tcp, yamux, Swarm, SwarmBuilder};
    use p2p_wire::rpc::codec::{encode_chunk, encode_request};
    use p2p_wire::rpc::messages::DataColumnsByRangeV1Request;

    /// Writes raw request bytes, reads the raw response to its end.
    #[derive(Clone, Default)]
    struct Raw;

    impl request_response::Codec for Raw {
        type Protocol = Protocol;
        type Request = Vec<u8>;
        type Response = Vec<u8>;

        async fn read_request<T>(&mut self, _: &Protocol, _: &mut T) -> std::io::Result<Vec<u8>>
        where
            T: futures::AsyncRead + Unpin + Send,
        {
            Err(std::io::ErrorKind::Unsupported.into())
        }

        async fn read_response<T>(&mut self, _: &Protocol, io: &mut T) -> std::io::Result<Vec<u8>>
        where
            T: futures::AsyncRead + Unpin + Send,
        {
            use futures::AsyncReadExt as _;
            let mut buf = Vec::new();
            io.take(4 << 20).read_to_end(&mut buf).await?;
            Ok(buf)
        }

        async fn write_request<T>(
            &mut self,
            _: &Protocol,
            io: &mut T,
            bytes: Vec<u8>,
        ) -> std::io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            use futures::AsyncWriteExt as _;
            io.write_all(&bytes).await?;
            io.flush().await
        }

        async fn write_response<T>(
            &mut self,
            _: &Protocol,
            _: &mut T,
            _: Vec<u8>,
        ) -> std::io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    type RawSwarm = Swarm<request_response::Behaviour<Raw>>;
    type Outcomes = HashMap<OutboundRequestId, Result<Vec<u8>, String>>;
    const E2E_WAIT: Duration = Duration::from_secs(20);

    /// A requester of `protocol` connected to `addr`, up to 8 streams at once.
    async fn raw_peer(protocol: Protocol, addr: &Multiaddr) -> RawSwarm {
        let behaviour = request_response::Behaviour::with_codec(
            Raw,
            [(protocol, ProtocolSupport::Outbound)],
            request_response::Config::default()
                .with_request_timeout(REQUEST_TIMEOUT)
                .with_max_concurrent_streams(8),
        );
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(E2E_WAIT))
            .build();
        swarm.dial(addr.clone()).unwrap();
        tokio::time::timeout(E2E_WAIT, async {
            while !matches!(
                swarm.select_next_some().await,
                SwarmEvent::ConnectionEstablished { .. }
            ) {}
        })
        .await
        .expect("connected");
        swarm
    }

    /// Runs `swarm` until `done` holds `n` outcomes.
    async fn run_until(swarm: &mut RawSwarm, done: &mut Outcomes, n: usize) {
        use request_response::{Event, Message};
        tokio::time::timeout(E2E_WAIT, async {
            while done.len() < n {
                match swarm.select_next_some().await {
                    SwarmEvent::Behaviour(Event::Message {
                        message:
                            Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    }) => drop(done.insert(request_id, Ok(response))),
                    SwarmEvent::Behaviour(Event::OutboundFailure {
                        request_id, error, ..
                    }) => {
                        drop(done.insert(request_id, Err(error.to_string())));
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("the outcomes");
    }

    /// Sends `bytes` to `node` and waits for the answer's raw bytes.
    async fn exchange(swarm: &mut RawSwarm, node: PeerId, bytes: Vec<u8>) -> Vec<u8> {
        let id = swarm.behaviour_mut().send_request(&node, bytes);
        let mut done = Outcomes::new();
        run_until(swarm, &mut done, 1).await;
        done.remove(&id).expect("its outcome").expect("answered")
    }

    async fn read_wire(protocol: Protocol, wire: &[u8]) -> Vec<ResponseChunk<Spec>> {
        let contexts = testkit::column_context_table();
        read_response_chunks::<Spec, _>(&mut &wire[..], protocol, 128, &contexts)
            .await
            .unwrap()
    }

    /// Counts the lookups it is asked for; finds nothing.
    struct CountingColumns(Arc<AtomicUsize>);

    impl ColumnSource for CountingColumns {
        fn by_range(&self, _: &DataColumnsByRangeV1Request) -> ColumnLookup {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { ColumnReply::Sidecars(Vec::new()) })
        }

        fn by_root(&self, _: &p2p_wire::rpc::messages::DataColumnsByRootV1Request) -> ColumnLookup {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { ColumnReply::Sidecars(Vec::new()) })
        }
    }

    /// Waits (polling, bounded) until `lives` holds `n` responder futures.
    async fn lives_at(lives: &Lives, n: usize) {
        let deadline = Instant::now() + E2E_WAIT;
        while lives.count() != n {
            assert!(
                Instant::now() < deadline,
                "{} responder futures, not {n}",
                lives.count()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The streamed BlocksByRange answer through the whole stack: 128 blocks, every one whole,
    /// then the end of the stream (the write side closed after the last chunk, #10, #1). With a
    /// responder configured, a request that breaks the wire format (#8: a varint over 10 bytes,
    /// a length over the request's bound refused before any frame, snappy frames past the
    /// declared length; #11: bytes after the one request chunk) or a count over the cap (#17)
    /// is `1: InvalidRequest` and never reaches it (#12); column requests over their caps never
    /// reach the store (#17). A peer's third concurrent stream is reset (#14); a stream past
    /// the global cap is dropped without a chunk (#18); a peer that goes away mid-answer frees
    /// its task and its slot (#2, #20).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn streamed_blocks_over_a_swarm() {
        let (lives, calls, lookups) = (
            Lives::default(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        let gate = Arc::new(Semaphore::new(0));
        let responder = {
            let (lives, calls, gate) = (lives.clone(), Arc::clone(&calls), Arc::clone(&gate));
            testing::script(move |request, mut sink| {
                calls.fetch_add(1, Ordering::SeqCst);
                let (live, gate) = (lives.enter(), Arc::clone(&gate));
                async move {
                    let _live = live;
                    let Request::BlocksByRange(range) = request else {
                        return;
                    };
                    match range.count {
                        2 => drop(gate.acquire().await),
                        3 => futures::future::pending().await,
                        _ => {}
                    }
                    for slot in 1..=range.count.min(128) {
                        if sink.send(testing::block(slot)).await.is_err() {
                            return;
                        }
                    }
                }
            })
        };
        let mut cfg = crate::testkit::control_config(Some(testkit::status()));
        cfg.contexts = testing::serving_table(NetworkCaps::PRESET_BOUND);
        cfg.limits.max_inbound_streams = 2;
        cfg.columns = Some(Arc::new(CountingColumns(Arc::clone(&lookups))));
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = RpcMetrics::register(&mut registry);
        let control = Control::<Spec>::new(cfg, metrics.clone()).with_blocks_responder(responder);
        let transport = crate::transport::TransportMetrics::register(&mut registry);
        let budget = crate::transport::MuxerBudget::with_defaults(&transport);
        let mut swarm_cfg = crate::transport::SwarmConfig::new(budget);
        swarm_cfg.listen_addrs = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
        let key = libp2p::identity::Keypair::generate_secp256k1();
        let mut node = crate::transport::build_swarm(key, &swarm_cfg, control).unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
                break address;
            }
        };
        let ours = *node.local_peer_id();
        tokio::spawn(async move {
            loop {
                node.select_next_some().await;
            }
        });

        // 128 blocks, then the end of the stream.
        let mut a = raw_peer(BLOCKS, &addr).await;
        let wire = exchange(&mut a, ours, encode_request(&blocks(128)).unwrap()).await;
        let read = read_wire(BLOCKS, &wire).await;
        assert_eq!(read.len(), 128);
        assert!(read.iter().all(|c| matches!(c, ResponseChunk::Success(_))));

        // Malformed and out-of-bounds requests: `1`, never served.
        let mut over_declared = vec![24u8];
        over_declared.extend_from_slice(&encode_chunk(&[0u8; 48]).unwrap()[1..]);
        let mut trailing = encode_request(&blocks(1)).unwrap();
        trailing.push(0);
        for (case, bytes) in [
            (
                "#8 a varint over 10 bytes",
                [vec![0x80; 10], vec![0x01]].concat(),
            ),
            (
                "#8 a length over the bound",
                [vec![0xe8, 0x07], vec![0xff; 8]].concat(),
            ),
            ("#8 frames past the declared length", over_declared),
            ("#11 bytes after the request chunk", trailing),
            (
                "#17 count over MAX_REQUEST_BLOCKS_DENEB",
                encode_request(&blocks(129)).unwrap(),
            ),
        ] {
            let read = read_wire(BLOCKS, &exchange(&mut a, ours, bytes).await).await;
            assert_eq!(code_of(&read), Some(ResultCode::InvalidRequest), "{case}");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "#12: none reached the responder"
        );
        let columns = Protocol::DataColumnsByRangeV1;
        let mut c = raw_peer(columns, &addr).await;
        for request in [
            DataColumnsByRangeV1Request {
                start_slot: 0,
                count: 129,
                columns: (0..128).collect::<Vec<u64>>().try_into().unwrap(),
            },
            DataColumnsByRangeV1Request {
                start_slot: 0,
                count: 1,
                columns: vec![128].try_into().unwrap(),
            },
        ] {
            let bytes = encode_request(&Request::DataColumnsByRange(request)).unwrap();
            let read = read_wire(columns, &exchange(&mut c, ours, bytes).await).await;
            assert_eq!(code_of(&read), Some(ResultCode::InvalidRequest));
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 0, "#17: no store read");

        // Three held streams on one connection: the third is reset.
        let held: Vec<OutboundRequestId> = (0..3)
            .map(|_| {
                a.behaviour_mut()
                    .send_request(&ours, encode_request(&blocks(2)).unwrap())
            })
            .collect();
        let mut done = Outcomes::new();
        run_until(&mut a, &mut done, 1).await;
        let refused = done.values().next().unwrap();
        assert!(
            refused.as_ref().map_or(true, Vec::is_empty),
            "#14: {refused:?}"
        );
        // Both global slots are held: another peer's stream is dropped without a chunk.
        lives_at(&lives, 2).await;
        let mut b = raw_peer(BLOCKS, &addr).await;
        let id = b
            .behaviour_mut()
            .send_request(&ours, encode_request(&blocks(2)).unwrap());
        let mut dropped = Outcomes::new();
        run_until(&mut b, &mut dropped, 1).await;
        assert!(dropped[&id].as_ref().map_or(true, Vec::is_empty), "#18");
        assert_eq!(metrics.inbound_streams_refused(), 1);
        gate.add_permits(1);
        run_until(&mut a, &mut done, 3).await;
        let served = held
            .iter()
            .filter(|id| done[id].as_ref().is_ok_and(|w| !w.is_empty()))
            .count();
        assert_eq!(served, 2);

        // A peer that goes away mid-answer frees its task and its slot.
        lives_at(&lives, 0).await;
        let _ = b
            .behaviour_mut()
            .send_request(&ours, encode_request(&blocks(3)).unwrap());
        let reached = async {
            loop {
                tokio::select! {
                    _ = b.select_next_some() => {}
                    () = lives_at(&lives, 1) => return,
                }
            }
        };
        reached.await;
        drop(b);
        lives_at(&lives, 0).await;
        // Both slots serve again.
        let ids: Vec<OutboundRequestId> = (0..2)
            .map(|_| {
                a.behaviour_mut()
                    .send_request(&ours, encode_request(&blocks(128)).unwrap())
            })
            .collect();
        let mut done = Outcomes::new();
        run_until(&mut a, &mut done, 2).await;
        for id in ids {
            let wire = done[&id].as_ref().expect("served");
            assert_eq!(read_wire(BLOCKS, wire).await.len(), 128);
        }
        assert_eq!(metrics.inbound_streams_refused(), 1);
    }
}
