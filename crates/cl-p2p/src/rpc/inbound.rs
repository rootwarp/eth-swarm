//! The control protocols, both ways: Status v2, MetaData v3, Ping v1 and Goodbye v1, plus
//! `BeaconBlocksByRange` v2 answered `3: ResourceUnavailable` (the probe stores no blocks).
//!
//! [`Control`] is the probe swarm's req/resp behaviour. It holds one [`Duplex`] per protocol
//! ([`Protocols`], see [`crate::rpc`] for why one each): an inbound-only and an outbound-only
//! `request_response` behaviour, so these five are what multistream-select offers and any other
//! protocol fails negotiation (`phase0/p2p-interface.md` L187–190), among them the MUST-support
//! ones the probe leaves out ([`super::unsupported`]). It answers every inbound
//! request itself and reports what it learned as [`ControlEvent`]s.
//!
//! # Answers
//!
//! - **Status** (`fulu/p2p-interface.md` L538–571): our Status from the [`StatusSource`]; with
//!   none known yet `2: ServerError` (Status does not specify `3`). The peer's Status is then
//!   judged ([`relevance`]).
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
//!   first. Counted and logged as one `goodbye_received` event. Our own Goodbye accepts an
//!   answer of one chunk or none (Lighthouse sends none).
//! - **BeaconBlocksByRange**: `3: ResourceUnavailable`, which that protocol specifies for blocks
//!   the responder does not have (`phase0` L1540). A request with `step` 0 or a `count` above
//!   `MAX_REQUEST_BLOCKS_DENEB` (128) is semantically invalid and gets `1: InvalidRequest`
//!   (`phase0` L1286–1288, L1514; `deneb` L876); the connection stays.
//! - A request that broke the wire format: `1: InvalidRequest` (`phase0` L1383–1386), a
//!   Goodbye's included.
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
//!   refunded; a sent one stays charged after a reconnect.
//! - **Inbound streams**: each [`Duplex`] serves at most [`MAX_CONCURRENT_REQUESTS`] inbound
//!   streams per connection, apart from ours, and resets the next one; a withheld chunk keeps
//!   its stream, so a peer over its quota cannot open more.
//! - **Outbound requests**: at most [`MAX_CONCURRENT_REQUESTS`] in flight per protocol across
//!   every peer (`rpc_outbound_inflight{protocol}`), the rest waiting in the protocol's bounded
//!   queue. A full queue IGNOREs the request (`queue_dropped_total{queue}`); an IGNOREd Goodbye
//!   closes the connection at once, since it was going to close anyway. A waiting request whose
//!   peer has left, or to a peer either side said Goodbye to (but our Goodbye), is dropped when
//!   its turn comes. Pings take no slot here: at most one per peer, sent at once
//!   ([`Control::ping`]).
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
//! Status request upon connection", `phase0` L1437). A Status with another fork digest, or a
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
use super::limits::{
    shared_limiter, Admit, ChunkPacer, OutboundSemaphore, RpcLimits, SharedLimiter,
};
use super::metrics::{RpcMetrics, StatusValidity};
use super::outbound::{check_request, outbound_failure, OutboundError, RangeError};
use super::{MAX_CONCURRENT_REQUESTS, REQUEST_TIMEOUT};
use crate::transport::Direction;
use consensus_types::EthSpec;
use ethswarm_proto::chain as pb;
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
    Protocol, Request, Response, ResponseChunk, ResultCode, MAX_REQUEST_BLOCKS_DENEB,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
pub const GOODBYE_LINGER: Duration = Duration::from_secs(1);

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
    /// Our Status now.
    fn status(&self) -> Option<StatusV2>;
}

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
}

impl std::fmt::Debug for ControlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlConfig")
            .field("status", &self.status.status())
            .field("metadata", &self.metadata.metadata())
            .field("deadlines", &self.deadlines)
            .field("limits", &self.limits)
            .field("ping_interval", &self.ping_interval)
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
        }
    }
}

/// What [`Control`] reports.
#[derive(Debug, Clone)]
pub enum ControlEvent {
    /// A peer's Status (its request, or its response to ours) was judged.
    Status {
        peer: PeerId,
        status: StatusV2,
        relevance: Relevance,
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
    /// One of our BlocksByRange requests ended: its outcome waits in [`Control::take_blocks`].
    BlocksByRange { peer: PeerId, ticket: BlocksTicket },
}

/// Names one of our BlocksByRange requests ([`Control::request_blocks`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlocksTicket(u64);

/// How one of our BlocksByRange requests ended: the response's chunks, or why there are none.
pub type BlocksOutcome<E> = Result<Vec<ReceivedChunk<E>>, OutboundError>;

/// One of our requests, waiting for a slot of its protocol or holding one.
#[derive(Debug)]
struct Outgoing {
    peer: PeerId,
    request: Request,
    /// The ticket of a BlocksByRange request, for its outcome.
    ticket: Option<BlocksTicket>,
}

/// What we know of one connected peer.
#[derive(Debug, Clone)]
struct PeerState {
    direction: Direction,
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
}

impl PeerState {
    /// Whether either side said Goodbye: nothing more goes out but our own Goodbye.
    fn leaving(&self) -> bool {
        self.goodbye_sent || self.goodbye_received
    }
}

/// The probe's req/resp behaviour (see the module docs).
pub struct Control<E: EthSpec> {
    inner: Protocols<E>,
    cfg: ControlConfig,
    metrics: RpcMetrics,
    peers: HashMap<PeerId, PeerState>,
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
            request,
            ticket: None,
        })
    }

    fn submit_outgoing(&mut self, outgoing: Outgoing) -> bool {
        let protocol = outgoing.request.protocol();
        if self.leaving(outgoing.peer) && !matches!(outgoing.request, Request::Goodbye(_)) {
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
                if let Request::Goodbye(_) = request {
                    self.close(peer);
                }
                false
            }
        };
        self.metrics
            .set_outbound_inflight(protocol, self.outbound.in_flight(protocol));
        taken
    }

    /// Sends `outgoing`, which holds a slot of its protocol.
    fn dispatch(&mut self, outgoing: Outgoing) {
        let Outgoing {
            peer,
            request,
            ticket,
        } = outgoing;
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
        while let Some(next) = self.outbound.release(protocol) {
            let peer = next.peer;
            let refusal = match self.peers.get(&peer) {
                // Nothing but our Goodbye goes out once either side said Goodbye.
                Some(state) if state.leaving() && !matches!(next.request, Request::Goodbye(_)) => {
                    tracing::debug!(%peer, %protocol, "after our Goodbye: the waiting request is dropped");
                    Some(OutboundError::Disconnected)
                }
                // The peer's Status may have changed while the request waited.
                Some(_) => match &next.request {
                    Request::BlocksByRange(range) => self.servable(peer, range).err(),
                    _ => None,
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
            request: Request::BlocksByRange(request),
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
    /// outbound queue IGNOREd it.
    pub fn send_status(&mut self, peer: PeerId) -> bool {
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
        let waiting = |state: &PeerState| pinging && !state.leaving() && state.ping.is_none();
        loop {
            let now = Instant::now();
            let mut closes = Vec::new();
            let mut pings = Vec::new();
            for (peer, state) in &mut self.peers {
                if state.close_at.is_some_and(|at| at <= now) {
                    state.close_at = None;
                    closes.push(*peer);
                }
                if waiting(state) && state.next_ping <= now {
                    pings.push(*peer);
                }
            }
            for peer in closes {
                self.close(peer);
            }
            for peer in pings {
                self.ping(peer);
            }
            let next = self
                .peers
                .values()
                .flat_map(|state| [state.close_at, waiting(state).then_some(state.next_ping)])
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

    fn close(&mut self, peer: PeerId) {
        self.pending.push_back(ToSwarm::CloseConnection {
            peer_id: peer,
            connection: CloseConnection::All,
        });
    }

    fn emit(&mut self, event: ControlEvent) {
        self.pending.push_back(ToSwarm::GenerateEvent(event));
    }

    /// Records the verdict on `theirs`; an irrelevant peer gets `Goodbye(2)`.
    fn judge(&mut self, peer: PeerId, theirs: StatusV2) {
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
        let pacer = ChunkPacer::new(
            Arc::clone(&self.limiter),
            peer,
            protocol,
            Some(self.metrics.clone()),
        );
        let answer = Answer {
            chunks,
            pacer: Some(pacer),
        };
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
                let answer = match self.cfg.status.status() {
                    Some(ours) => success_chunk(Response::Status(ours)),
                    None => error_chunk(ResultCode::ServerError, "status unavailable"),
                };
                self.respond(peer, protocol, channel, answer);
                self.judge(peer, theirs);
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
                Some(Response::Status(theirs)) => self.judge(peer, theirs),
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
                self.on_inbound_failure(peer, protocol, error);
            }
            DuplexEvent::Inbound(Event::ResponseSent { request_id, .. })
                if protocol == Protocol::GoodbyeV1 =>
            {
                self.goodbye_answered(request_id);
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
            // Sent answers; and what each one-way behaviour never reports (a response on the
            // inbound side, a request on the outbound side).
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
                        direction,
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
            // Goodbye answer, whose connection closes a linger on.
            self.poll_timers(cx);
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
            control.judge(*peer, testkit::status());
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
        control.judge(served, from(64));
        control.judge(
            invalid,
            StatusV2 {
                fork_digest: [9; 4],
                ..from(0)
            },
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
        control.judge(served, from(100));
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
        control.judge(served, from(0));
        let tickets: Vec<_> = (0..3)
            .map(|_| control.request_blocks(served, at(64)).unwrap())
            .collect();
        control.judge(
            served,
            StatusV2 {
                fork_digest: [9; 4],
                ..from(0)
            },
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
        control.judge(valid, theirs.clone());
        control.judge(
            invalid,
            StatusV2 {
                fork_digest: [9; 4],
                ..testkit::status()
            },
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
            control.judge(*peer, testkit::status());
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
}
