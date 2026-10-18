//! The control protocols, both ways: Status v2, MetaData v3, Ping v1 and Goodbye v1, plus
//! `BeaconBlocksByRange` v2 answered `3: ResourceUnavailable` (the probe stores no blocks).
//!
//! [`Control`] is the probe swarm's req/resp behaviour. It holds one [`Duplex`] per protocol
//! ([`Protocols`], see [`crate::rpc`] for why one each): an inbound-only and an outbound-only
//! `request_response` behaviour, so these five are what multistream-select offers and any other
//! protocol fails negotiation (`phase0/p2p-interface.md` L187–190). It answers every inbound
//! request itself and reports what it learned as [`ControlEvent`]s.
//!
//! # Answers
//!
//! - **Status** (`fulu/p2p-interface.md` L538–571): our Status from the [`StatusSource`]; with
//!   none known yet `2: ServerError` (Status does not specify `3`). The peer's Status is then
//!   judged ([`relevance`]).
//! - **MetaData**: `seq_number` from the [`MetaDataSource`] (cl-chain), no attestation or sync
//!   subnets (the probe subscribes to none), `custody_group_count` the ENR `cgc`
//!   ([`ControlConfig::custody_group_count`]).
//! - **Ping** (`phase0` L1628–1682): our `seq_number`. A peer `seq_number` above the one of its
//!   MetaData we hold, or any while we hold none, triggers one GetMetaData; no second one goes
//!   out while one is open.
//! - **Goodbye** (`phase0` L1457–1483): no response chunk; the stream closes and so does the
//!   connection. Counted and logged as one `goodbye_received` event.
//! - **BeaconBlocksByRange**: `3: ResourceUnavailable`, which that protocol specifies for blocks
//!   the responder does not have (`phase0` L1540).
//! - A request that broke the wire format: `1: InvalidRequest` (`phase0` L1383–1386), except a
//!   Goodbye, which has no response.
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
//!   peer has left is dropped when its turn comes.
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
use super::{MAX_CONCURRENT_REQUESTS, REQUEST_TIMEOUT};
use crate::transport::Direction;
use consensus_types::EthSpec;
use ethswarm_proto::chain as pb;
use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::request_response::{
    self, InboundFailure, OutboundFailure, OutboundRequestId, ProtocolSupport, ResponseChannel,
};
use libp2p::swarm::{
    CloseConnection, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use p2p_wire::rpc::codec::ContextTable;
use p2p_wire::rpc::messages::{ErrorMessage, Goodbye, MetaDataV3, Ping, StatusV2};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

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

/// Our MetaData `seq_number`, which cl-chain owns (`ethswarm.chain.v1.ReqRespService/
/// GetMetadata`).
pub trait MetaDataSource: Send + Sync + 'static {
    /// Our `seq_number` now.
    fn seq_number(&self) -> u64;
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

impl MetaDataSource for AtomicU64 {
    fn seq_number(&self) -> u64 {
        self.load(Ordering::Acquire)
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
    /// Our MetaData `seq_number`.
    pub metadata: Arc<dyn MetaDataSource>,
    /// Our custody group count: the `cgc` our ENR advertises (cl-discv5 builds the record; the
    /// value is passed in, since cl-p2p does not link cl-discv5).
    pub custody_group_count: u64,
    /// Fork digest → fork, for the context bytes of block responses.
    pub contexts: Arc<ContextTable>,
    /// The codec's deadlines.
    pub deadlines: Deadlines,
    /// The rate limits and the outbound queue (see the module docs).
    pub limits: RpcLimits,
}

impl std::fmt::Debug for ControlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlConfig")
            .field("status", &self.status.status())
            .field("seq_number", &self.metadata.seq_number())
            .field("custody_group_count", &self.custody_group_count)
            .field("deadlines", &self.deadlines)
            .field("limits", &self.limits)
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
}

/// What we know of one connected peer.
#[derive(Debug, Clone)]
struct PeerState {
    direction: Direction,
    /// The verdict on its last judged Status.
    status_valid: Option<bool>,
    /// The `seq_number` of its last MetaData.
    metadata_seq: Option<u64>,
    /// Whether our GetMetaData request is open (in flight or waiting for a slot).
    metadata_open: bool,
    /// Whether we sent it a Goodbye.
    goodbye_sent: bool,
}

/// The probe's req/resp behaviour (see the module docs).
pub struct Control<E: EthSpec> {
    inner: Protocols<E>,
    cfg: ControlConfig,
    metrics: RpcMetrics,
    peers: HashMap<PeerId, PeerState>,
    /// Our Goodbye requests still open; the connection closes when each completes.
    goodbyes: HashMap<OutboundRequestId, PeerId>,
    /// Our requests in flight, each holding a slot of its protocol. Keyed by protocol too:
    /// every protocol's behaviour numbers its requests on its own, so IDs repeat across them.
    in_flight: HashSet<(Protocol, OutboundRequestId)>,
    /// The outbound slots and wait queues.
    outbound: OutboundSemaphore<(PeerId, Request)>,
    /// Every peer's response quota, shared with the inbound streams' writers.
    limiter: SharedLimiter,
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
            in_flight: HashSet::new(),
            pending: VecDeque::new(),
        }
    }

    /// Our MetaData now.
    #[must_use]
    pub fn local_metadata(&self) -> MetaDataV3 {
        MetaDataV3 {
            seq_number: self.cfg.metadata.seq_number(),
            attnets: Default::default(),
            syncnets: Default::default(),
            custody_group_count: self.cfg.custody_group_count,
        }
    }

    /// Sends `request` to `peer` in a free slot of its protocol, or queues it; `false` if the
    /// queue IGNOREd it.
    fn submit(&mut self, peer: PeerId, request: Request) -> bool {
        let protocol = request.protocol();
        let taken = match self.outbound.submit(protocol, (peer, request)) {
            Admit::Start((peer, request)) => {
                self.dispatch(peer, request);
                true
            }
            Admit::Queued => true,
            Admit::Ignored((peer, request)) => {
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

    /// Sends `request`, which holds a slot of its protocol.
    fn dispatch(&mut self, peer: PeerId, request: Request) {
        let protocol = request.protocol();
        let goodbye = matches!(request, Request::Goodbye(_));
        let id = self.inner.of(protocol).send_request(&peer, request.into());
        self.in_flight.insert((protocol, id));
        if goodbye {
            self.goodbyes.insert(id, peer);
        }
    }

    /// Request `id` of `protocol` finished: its slot goes to the next waiting request of a
    /// connected peer.
    fn finished(&mut self, protocol: Protocol, id: OutboundRequestId) {
        if !self.in_flight.remove(&(protocol, id)) {
            return;
        }
        while let Some((peer, request)) = self.outbound.release(protocol) {
            if self.peers.contains_key(&peer) {
                self.dispatch(peer, request);
                break;
            }
            tracing::debug!(%peer, %protocol, "the peer left: its waiting request is dropped");
        }
        self.metrics
            .set_outbound_inflight(protocol, self.outbound.in_flight(protocol));
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

    /// Pings `peer` with our `seq_number`.
    pub fn ping(&mut self, peer: PeerId) {
        let ours = self.cfg.metadata.seq_number();
        self.submit(peer, Request::Ping(Ping(ours)));
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

    /// A `seq_number` the peer announced: fetch its MetaData if it is newer than ours of it.
    fn on_peer_seq(&mut self, peer: PeerId, seq_number: u64) {
        let Some(state) = self.peers.get(&peer) else {
            return;
        };
        if state.metadata_seq.is_none_or(|known| seq_number > known) {
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
    ) {
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
        if self
            .inner
            .of(protocol)
            .send_response(channel, answer)
            .is_err()
        {
            tracing::debug!(%protocol, "the stream closed before our response");
        }
    }

    fn on_request(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        request: RpcRequest,
        channel: ResponseChannel<Answer<E>>,
    ) {
        let request = match request {
            RpcRequest::Valid(request) => request,
            RpcRequest::Malformed(error) => {
                self.metrics.invalid_data(Direction::Inbound);
                tracing::debug!(%peer, %protocol, %error, "malformed request");
                if protocol != Protocol::GoodbyeV1 {
                    let answer = error_chunk(ResultCode::InvalidRequest, &error.to_string());
                    self.respond(peer, protocol, channel, answer);
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
                let ours = self.cfg.metadata.seq_number();
                let answer = success_chunk(Response::Ping(Ping(ours)));
                self.respond(peer, protocol, channel, answer);
                self.on_peer_seq(peer, seq_number);
            }
            Request::Goodbye(Goodbye(reason)) => {
                // No response chunk: dropping the channel closes the stream.
                drop(channel);
                self.on_goodbye(peer, reason);
            }
            Request::BlocksByRange(_) => {
                let answer = error_chunk(ResultCode::ResourceUnavailable, "no blocks stored");
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
        self.close(peer);
    }

    fn on_response(
        &mut self,
        peer: PeerId,
        protocol: Protocol,
        id: OutboundRequestId,
        chunks: Vec<ReceivedChunk<E>>,
    ) {
        self.finished(protocol, id);
        match protocol {
            Protocol::GoodbyeV1 => self.on_goodbye_done(id),
            Protocol::MetaDataV3 => {
                self.metadata_done(peer);
                match single_success(chunks) {
                    Some(Response::MetaData(metadata)) => {
                        if let Some(state) = self.peers.get_mut(&peer) {
                            state.metadata_seq = Some(metadata.seq_number);
                        }
                        self.emit(ControlEvent::MetaData {
                            peer,
                            metadata: Box::new(metadata),
                        });
                    }
                    other => tracing::debug!(%peer, ?other, "no MetaData in the response"),
                }
            }
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
            Protocol::BlocksByRangeV2 => {
                tracing::debug!(%peer, chunks = chunks.len(), "a BlocksByRange response");
            }
        }
    }

    /// Our one MetaData request to `peer` finished.
    fn metadata_done(&mut self, peer: PeerId) {
        if let Some(state) = self.peers.get_mut(&peer) {
            state.metadata_open = false;
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
            // A Goodbye has no response: a failure after sending is expected.
            Protocol::GoodbyeV1 => self.on_goodbye_done(id),
            Protocol::MetaDataV3 => self.metadata_done(peer),
            _ => {}
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
                        request, channel, ..
                    },
                ..
            }) => self.on_request(peer, protocol, request, channel),
            DuplexEvent::Inbound(Event::InboundFailure { peer, error, .. }) => {
                self.on_inbound_failure(peer, protocol, error);
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
                        metadata_seq: None,
                        metadata_open: false,
                        goodbye_sent: false,
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
        let seq = AtomicU64::new(3);
        assert_eq!(seq.seq_number(), 3);
        seq.store(4, Ordering::Release);
        assert_eq!(MetaDataSource::seq_number(&seq), 4);
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
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let mut cfg = crate::testkit::control_config(Some(testkit::status()));
        cfg.limits.outbound_queue_len = queue_len;
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

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Requests on three protocols to eight peers, finishing in random order: the slots a
        /// protocol holds are always its own requests in flight, never above 2, and all come
        /// back once everything finished.
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
                    control.on_outbound_failure(peers[k], q, id, OutboundFailure::Timeout);
                }
                for q in protocols {
                    let open = control.in_flight.iter().filter(|(p, _)| *p == q).count();
                    proptest::prop_assert_eq!(open, control.outbound.in_flight(q));
                    proptest::prop_assert!(open <= MAX_CONCURRENT_REQUESTS);
                }
            }
            while let Some(&(q, id)) = control.in_flight.iter().next() {
                control.on_outbound_failure(peers[0], q, id, OutboundFailure::Timeout);
            }
            for q in protocols {
                proptest::prop_assert_eq!(control.outbound.in_flight(q), 0);
                proptest::prop_assert_eq!(metrics.outbound_inflight(q), 0);
            }
        }
    }

    #[test]
    fn local_metadata_carries_the_enr_cgc() {
        let cfg = ControlConfig {
            status: Arc::new(SharedStatus::new(None)),
            metadata: Arc::new(AtomicU64::new(11)),
            custody_group_count: 4,
            contexts: Arc::new(testkit::context_table()),
            deadlines: Deadlines::default(),
            limits: RpcLimits::default(),
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
