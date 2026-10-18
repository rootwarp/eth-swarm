//! The control protocols, both ways: Status v2, MetaData v3, Ping v1 and Goodbye v1, plus
//! `BeaconBlocksByRange` v2 answered `3: ResourceUnavailable` (the probe stores no blocks).
//!
//! [`Control`] is the probe swarm's req/resp behaviour. It holds one `request_response`
//! behaviour per protocol ([`Protocols`], see [`crate::rpc`] for why one each), every one with
//! `ProtocolSupport::Full`, so these five are what multistream-select offers and any other
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

use super::codec::{Deadline, Deadlines, ReadError, ReceivedChunk, RpcCodec, RpcRequest};
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
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

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
}

impl std::fmt::Debug for ControlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlConfig")
            .field("status", &self.status.status())
            .field("seq_number", &self.metadata.seq_number())
            .field("custody_group_count", &self.custody_group_count)
            .field("deadlines", &self.deadlines)
            .finish_non_exhaustive()
    }
}

/// One `request_response` behaviour per protocol, each `ProtocolSupport::Full`.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
pub struct Protocols<E: EthSpec> {
    pub status: request_response::Behaviour<RpcCodec<E>>,
    pub metadata: request_response::Behaviour<RpcCodec<E>>,
    pub ping: request_response::Behaviour<RpcCodec<E>>,
    pub goodbye: request_response::Behaviour<RpcCodec<E>>,
    pub blocks_by_range: request_response::Behaviour<RpcCodec<E>>,
}

/// A behaviour serving and requesting `protocol`.
fn full_behaviour<E: EthSpec>(
    protocol: Protocol,
    codec: RpcCodec<E>,
) -> request_response::Behaviour<RpcCodec<E>> {
    request_response::Behaviour::with_codec(
        codec,
        [(protocol, ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(MAX_CONCURRENT_REQUESTS),
    )
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
        let codec = || {
            let codec = RpcCodec::new(Arc::clone(&contexts), deadlines);
            match &metrics {
                Some(m) => codec.with_metrics(m.clone()),
                None => codec,
            }
        };
        Self {
            status: full_behaviour(Protocol::StatusV2, codec()),
            metadata: full_behaviour(Protocol::MetaDataV3, codec()),
            ping: full_behaviour(Protocol::PingV1, codec()),
            goodbye: full_behaviour(Protocol::GoodbyeV1, codec()),
            blocks_by_range: full_behaviour(Protocol::BlocksByRangeV2, codec()),
        }
    }

    /// The behaviour of `protocol`.
    pub fn of(&mut self, protocol: Protocol) -> &mut request_response::Behaviour<RpcCodec<E>> {
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
    /// Our open GetMetaData request.
    metadata_request: Option<OutboundRequestId>,
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
            cfg,
            metrics,
            peers: HashMap::new(),
            goodbyes: HashMap::new(),
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

    /// Sends our Status to `peer`; `false` (and nothing sent) while we have none.
    pub fn send_status(&mut self, peer: PeerId) -> bool {
        let Some(ours) = self.cfg.status.status() else {
            tracing::debug!(%peer, "no Status of ours yet: none sent");
            return false;
        };
        self.inner
            .status
            .send_request(&peer, Request::Status(ours).into());
        true
    }

    /// Pings `peer` with our `seq_number`.
    pub fn ping(&mut self, peer: PeerId) {
        let ours = self.cfg.metadata.seq_number();
        self.inner
            .ping
            .send_request(&peer, Request::Ping(Ping(ours)).into());
    }

    /// Requests `peer`'s MetaData, unless a request is already open.
    pub fn request_metadata(&mut self, peer: PeerId) {
        let Some(state) = self.peers.get_mut(&peer) else {
            return;
        };
        if state.metadata_request.is_some() {
            return;
        }
        let id = self
            .inner
            .metadata
            .send_request(&peer, Request::MetaData.into());
        state.metadata_request = Some(id);
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
        let id = self
            .inner
            .goodbye
            .send_request(&peer, Request::Goodbye(Goodbye(reason)).into());
        self.goodbyes.insert(id, peer);
        self.metrics.goodbye_sent(reason, status_valid);
        tracing::info!(
            %peer,
            reason,
            status_valid = status_valid.as_str(),
            "goodbye_sent"
        );
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

    fn respond(
        &mut self,
        protocol: Protocol,
        channel: ResponseChannel<Vec<ReceivedChunk<E>>>,
        chunks: Vec<ReceivedChunk<E>>,
    ) {
        if self
            .inner
            .of(protocol)
            .send_response(channel, chunks)
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
        channel: ResponseChannel<Vec<ReceivedChunk<E>>>,
    ) {
        let request = match request {
            RpcRequest::Valid(request) => request,
            RpcRequest::Malformed(error) => {
                self.metrics.invalid_data(Direction::Inbound);
                tracing::debug!(%peer, %protocol, %error, "malformed request");
                if protocol != Protocol::GoodbyeV1 {
                    let answer = error_chunk(ResultCode::InvalidRequest, &error.to_string());
                    self.respond(protocol, channel, answer);
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
                self.respond(protocol, channel, answer);
                self.judge(peer, theirs);
            }
            Request::MetaData => {
                let answer = success_chunk(Response::MetaData(self.local_metadata()));
                self.respond(protocol, channel, answer);
            }
            Request::Ping(Ping(seq_number)) => {
                let ours = self.cfg.metadata.seq_number();
                self.respond(protocol, channel, success_chunk(Response::Ping(Ping(ours))));
                self.on_peer_seq(peer, seq_number);
            }
            Request::Goodbye(Goodbye(reason)) => {
                // No response chunk: dropping the channel closes the stream.
                drop(channel);
                self.on_goodbye(peer, reason);
            }
            Request::BlocksByRange(_) => {
                let answer = error_chunk(ResultCode::ResourceUnavailable, "no blocks stored");
                self.respond(protocol, channel, answer);
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
        match protocol {
            Protocol::GoodbyeV1 => self.on_goodbye_done(id),
            Protocol::MetaDataV3 => {
                self.metadata_done(peer, id);
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

    fn metadata_done(&mut self, peer: PeerId, id: OutboundRequestId) {
        if let Some(state) = self.peers.get_mut(&peer) {
            if state.metadata_request == Some(id) {
                state.metadata_request = None;
            }
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
            Protocol::MetaDataV3 => self.metadata_done(peer, id),
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
            Event::Message {
                peer,
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            } => self.on_request(peer, protocol, request, channel),
            Event::Message {
                peer,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => self.on_response(peer, protocol, request_id, response),
            Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => self.on_outbound_failure(peer, protocol, request_id, error),
            Event::InboundFailure { peer, error, .. } => {
                self.on_inbound_failure(peer, protocol, error);
            }
            Event::ResponseSent { .. } => {}
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
                        metadata_request: None,
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

    #[test]
    fn local_metadata_carries_the_enr_cgc() {
        let cfg = ControlConfig {
            status: Arc::new(SharedStatus::new(None)),
            metadata: Arc::new(AtomicU64::new(11)),
            custody_group_count: 4,
            contexts: Arc::new(testkit::context_table()),
            deadlines: Deadlines::default(),
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
