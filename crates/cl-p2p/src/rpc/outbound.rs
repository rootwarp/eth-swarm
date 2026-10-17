//! Outbound requests on a running swarm: the dialer's side of each exchange.
//!
//! [`status`] sends our Status v2 on `/eth2/beacon_chain/req/status/2/ssz_snappy` and returns
//! the peer's, once it passed the handshake check of `phase0/p2p-interface.md` "Status"
//! (L1414–1455): a peer whose `fork_digest` differs from ours is on another network or fork,
//! and the exchange fails ([`OutboundError::ForkDigestMismatch`], which carries the peer's
//! Status for the log). `fulu/p2p-interface.md` L538–571 defines Status v2 (the added
//! `earliest_available_slot`); judging the other fields is the caller's business.
//!
//! [`metadata`] requests the peer's MetaData v3 on `/eth2/beacon_chain/req/metadata/3/ssz_snappy`
//! (`fulu/p2p-interface.md` "GetMetaData v3", L778–794, type L269–288): the request is empty
//! (the codec writes nothing and `request_response` closes the write half), and the response is
//! exactly one success chunk. The codec already refuses a second chunk; [`single_metadata`]
//! checks the count again on what it decoded.
//!
//! [`ping`] sends our MetaData `seq_number` on `/eth2/beacon_chain/req/ping/1/ssz_snappy` and
//! returns the peer's (`phase0/p2p-interface.md` "Ping", L1628–1682): the request is
//! `Ping(uint64)` and the response one 8-byte success chunk. Judging the answer against the
//! peer's MetaData is the caller's business.
//!
//! [`blocks_by_range`] sends one `BeaconBlocksByRange` v2 request on
//! `/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy` (`phase0/p2p-interface.md`
//! L1485–1575) and returns the blocks once every one of them passed the request's rules:
//! `count` is 1 to `MAX_REQUEST_BLOCKS_DENEB` (128, `deneb/p2p-interface.md` L68) and `step`
//! is 1, checked before anything is sent; the codec reads at most `count` chunks and decodes
//! each in the fork its context bytes name (Gloas, or Fulu codec-only); then each block's slot
//! must be inside `[start_slot, start_slot + count)` and above the previous block's, and its
//! context bytes must be `compute_fork_digest` of the block's own epoch (`gloas/p2p-interface.md`
//! L1356–1374), which the caller supplies. Any failure drops every block of the response
//! ([`OutboundError::InvalidBlocks`]).
//!
//! A response the codec refused (a wrong SSZ length, a chunk too many, …) fails as
//! [`OutboundError::InvalidResponse`] with the codec's typed [`ReadError`].

use crate::rpc::codec::{ReadError, ReceivedChunk, RpcCodec};
use consensus_types::primitives::{Epoch, Slot};
use consensus_types::{forked, EthSpec};
use futures::StreamExt;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{PeerId, Swarm};
use p2p_wire::rpc::messages::{BlocksByRangeV2Request, ForkDigest, MetaDataV3, Ping, StatusV2};
use p2p_wire::rpc::protocols::{
    Request, Response, ResponseChunk, ResultCode, MAX_REQUEST_BLOCKS_DENEB,
};

/// One event of an outbound `request_response` behaviour.
pub type RpcEvent<E> = request_response::Event<Request, Vec<ReceivedChunk<E>>>;

/// A behaviour with a Status v2 `request_response` behaviour inside.
pub trait StatusRpc<E: EthSpec>: NetworkBehaviour {
    /// The Status v2 behaviour.
    fn status_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>>;

    /// The Status behaviour's event inside `event`, or `None` for another behaviour's.
    fn status_event(event: Self::ToSwarm) -> Option<RpcEvent<E>>;
}

/// A behaviour with a MetaData v3 `request_response` behaviour inside.
pub trait MetaDataRpc<E: EthSpec>: NetworkBehaviour {
    /// The MetaData v3 behaviour.
    fn metadata_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>>;

    /// The MetaData behaviour's event inside `event`, or `None` for another behaviour's.
    fn metadata_event(event: Self::ToSwarm) -> Option<RpcEvent<E>>;
}

/// A behaviour with a Ping v1 `request_response` behaviour inside.
pub trait PingRpc<E: EthSpec>: NetworkBehaviour {
    /// The Ping v1 behaviour.
    fn ping_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>>;

    /// The Ping behaviour's event inside `event`, or `None` for another behaviour's.
    fn ping_event(event: Self::ToSwarm) -> Option<RpcEvent<E>>;
}

/// A behaviour with a BeaconBlocksByRange v2 `request_response` behaviour inside.
pub trait BlocksByRangeRpc<E: EthSpec>: NetworkBehaviour {
    /// The BlocksByRange v2 behaviour.
    fn blocks_by_range_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>>;

    /// The BlocksByRange behaviour's event inside `event`, or `None` for another behaviour's.
    fn blocks_by_range_event(event: Self::ToSwarm) -> Option<RpcEvent<E>>;
}

/// The fork digest of an epoch (`compute_fork_digest`), `None` where it has none.
pub type DigestAt<'a> = dyn Fn(Epoch) -> Option<ForkDigest> + Sync + 'a;

/// How a BlocksByRange response broke its request's rules.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlocksError {
    /// A block outside `[start, end)`.
    #[error("a block at slot {slot}, outside the requested [{start}, {end})")]
    SlotOutOfRange {
        /// The block's slot.
        slot: Slot,
        /// `start_slot`.
        start: Slot,
        /// `start_slot + count`.
        end: Slot,
    },
    /// A block at or below the slot of the block before it.
    #[error("a block at slot {slot} after one at slot {previous}: slots must strictly increase")]
    NonIncreasingSlot {
        /// The block's slot.
        slot: Slot,
        /// The previous block's slot.
        previous: Slot,
    },
    /// Context bytes other than the fork digest of the block's epoch.
    #[error(
        "a block at slot {slot} (epoch {epoch}) with context {}, the epoch's digest is {}",
        digest_text(.got),
        digest_text(.want)
    )]
    WrongContextDigest {
        /// The block's slot.
        slot: Slot,
        /// Its epoch.
        epoch: Epoch,
        /// The context bytes it came with.
        got: Option<ForkDigest>,
        /// `compute_fork_digest` of its epoch.
        want: Option<ForkDigest>,
    },
}

fn digest_text(digest: &Option<ForkDigest>) -> String {
    digest.map_or_else(|| "none".to_owned(), |d| format!("0x{}", hex(&d)))
}

/// Why an outbound exchange failed.
#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    /// The peer's Status names another fork digest: the handshake fails.
    #[error(
        "fork digest mismatch: ours 0x{}, the peer's 0x{}",
        hex(.ours),
        hex(&.peer.fork_digest)
    )]
    ForkDigestMismatch {
        /// Our digest.
        ours: ForkDigest,
        /// The peer's whole Status.
        peer: Box<StatusV2>,
    },
    /// The peer answered with an error chunk.
    #[error("error response {code:?}: {message}")]
    ErrorResponse {
        /// The result code.
        code: ResultCode,
        /// The peer's message, lossily UTF-8.
        message: String,
    },
    /// The response was not one chunk of the requested message.
    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),
    /// The request breaks the protocol's limits; it was not sent.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The blocks broke the request's range or context rule; every block is dropped.
    #[error("invalid blocks: {0}")]
    InvalidBlocks(BlocksError),
    /// The codec refused the response: it broke the wire format (a wrong SSZ length, …) or
    /// the request's limits (a chunk too many, …).
    #[error("invalid response: {0}")]
    InvalidResponse(ReadError),
    /// `request_response` reported the request failed (dial, timeout, stream, codec).
    #[error("request failed: {0}")]
    Failure(String),
    /// The last connection to the peer closed before a response.
    #[error("the peer disconnected before responding")]
    Disconnected,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `error` and every `source()` under it, `: `-separated.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut next = error.source();
    while let Some(e) = next {
        out.push_str(": ");
        out.push_str(&e.to_string());
        next = e.source();
    }
    out
}

/// Sends `ours` to `peer` and drives `swarm` until the peer's Status arrives or the exchange
/// fails. The peer's Status is returned only if its `fork_digest` equals ours.
///
/// Events of other behaviours that arrive meanwhile are dropped (logged at debug).
pub async fn status<E, B>(
    swarm: &mut Swarm<B>,
    peer: PeerId,
    ours: &StatusV2,
) -> Result<StatusV2, OutboundError>
where
    E: EthSpec,
    B: StatusRpc<E>,
{
    let id = swarm
        .behaviour_mut()
        .status_rpc()
        .send_request(&peer, Request::Status(ours.clone()));
    let chunks = wait_for_response(swarm, id, B::status_event).await?;
    let theirs = single_status(without_context(chunks))?;
    if theirs.fork_digest != ours.fork_digest {
        return Err(OutboundError::ForkDigestMismatch {
            ours: ours.fork_digest,
            peer: Box::new(theirs),
        });
    }
    Ok(theirs)
}

/// Requests `peer`'s MetaData v3 and drives `swarm` until it arrives or the exchange fails.
///
/// Events of other behaviours that arrive meanwhile are dropped (logged at debug).
pub async fn metadata<E, B>(swarm: &mut Swarm<B>, peer: PeerId) -> Result<MetaDataV3, OutboundError>
where
    E: EthSpec,
    B: MetaDataRpc<E>,
{
    let id = swarm
        .behaviour_mut()
        .metadata_rpc()
        .send_request(&peer, Request::MetaData);
    let chunks = wait_for_response(swarm, id, B::metadata_event).await?;
    single_metadata(without_context(chunks))
}

/// Sends our `seq_number` to `peer` and drives `swarm` until the peer's arrives or the exchange
/// fails.
///
/// Events of other behaviours that arrive meanwhile are dropped (logged at debug).
pub async fn ping<E, B>(swarm: &mut Swarm<B>, peer: PeerId, ours: u64) -> Result<u64, OutboundError>
where
    E: EthSpec,
    B: PingRpc<E>,
{
    let id = swarm
        .behaviour_mut()
        .ping_rpc()
        .send_request(&peer, Request::Ping(Ping(ours)));
    let chunks = wait_for_response(swarm, id, B::ping_event).await?;
    single_ping(without_context(chunks))
}

/// Sends `request` to `peer`, drives `swarm` until the response is complete or the exchange
/// fails, and returns the blocks once each passed the request's rules (see the module docs).
/// `digest_at` is `compute_fork_digest` of the session's chain.
///
/// Events of other behaviours that arrive meanwhile are dropped (logged at debug).
pub async fn blocks_by_range<E, B>(
    swarm: &mut Swarm<B>,
    peer: PeerId,
    request: BlocksByRangeV2Request,
    digest_at: &DigestAt<'_>,
) -> Result<Vec<forked::SignedBeaconBlock<E>>, OutboundError>
where
    E: EthSpec,
    B: BlocksByRangeRpc<E>,
{
    check_request(&request)?;
    let id = swarm
        .behaviour_mut()
        .blocks_by_range_rpc()
        .send_request(&peer, Request::BlocksByRange(request));
    let chunks = wait_for_response(swarm, id, B::blocks_by_range_event).await?;
    check_blocks(&request, chunks, digest_at)
}

/// `count` in `1..=MAX_REQUEST_BLOCKS_DENEB`, `step` 1, and the range inside `u64` slots.
fn check_request(request: &BlocksByRangeV2Request) -> Result<(), OutboundError> {
    let invalid = |why: String| Err(OutboundError::InvalidRequest(why));
    if !(1..=MAX_REQUEST_BLOCKS_DENEB).contains(&request.count) {
        return invalid(format!(
            "count {} is not in 1..={MAX_REQUEST_BLOCKS_DENEB}",
            request.count
        ));
    }
    if request.step != 1 {
        return invalid(format!("step {}, not 1", request.step));
    }
    if request.start_slot.checked_add(request.count).is_none() {
        return invalid(format!(
            "start_slot {} + count {} overflows",
            request.start_slot, request.count
        ));
    }
    Ok(())
}

/// The blocks of a BlocksByRange response, once every chunk is a block of `request`'s range,
/// above the one before it and under its own epoch's digest. An error chunk fails the whole
/// response.
fn check_blocks<E: EthSpec>(
    request: &BlocksByRangeV2Request,
    chunks: Vec<ReceivedChunk<E>>,
    digest_at: &DigestAt<'_>,
) -> Result<Vec<forked::SignedBeaconBlock<E>>, OutboundError> {
    let start = request.start_slot;
    let end = start.saturating_add(request.count);
    let mut blocks: Vec<forked::SignedBeaconBlock<E>> = Vec::with_capacity(chunks.len());
    for ReceivedChunk { context, chunk } in chunks {
        let block = match chunk {
            ResponseChunk::Success(Response::Block(block)) => *block,
            ResponseChunk::Success(other) => {
                return Err(OutboundError::UnexpectedResponse(format!("{other:?}")))
            }
            ResponseChunk::Error { code, message } => {
                return Err(OutboundError::ErrorResponse {
                    code,
                    message: String::from_utf8_lossy(&message).into_owned(),
                })
            }
        };
        let slot = block.slot();
        let invalid = |e| Err(OutboundError::InvalidBlocks(e));
        if !(start..end).contains(&slot) {
            return invalid(BlocksError::SlotOutOfRange { slot, start, end });
        }
        if let Some(previous) = blocks.last().map(forked::SignedBeaconBlock::slot) {
            if slot <= previous {
                return invalid(BlocksError::NonIncreasingSlot { slot, previous });
            }
        }
        let epoch = slot / E::slots_per_epoch();
        let want = digest_at(epoch);
        if want.is_none() || context != want {
            return invalid(BlocksError::WrongContextDigest {
                slot,
                epoch,
                got: context,
                want,
            });
        }
        blocks.push(block);
    }
    Ok(blocks)
}

/// Drives `swarm` until request `id` has a response or fails; `event_of` picks the requesting
/// behaviour's events. A closed connection is not judged here: `request_response` fails every
/// request still pending on it (`OutboundFailure::ConnectionClosed`), and a response that
/// arrived first is delivered first.
async fn wait_for_response<E, B>(
    swarm: &mut Swarm<B>,
    id: OutboundRequestId,
    event_of: fn(B::ToSwarm) -> Option<RpcEvent<E>>,
) -> Result<Vec<ReceivedChunk<E>>, OutboundError>
where
    E: EthSpec,
    B: NetworkBehaviour,
{
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(event) => match event_of(event) {
                Some(request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                }) if request_id == id => return Ok(response),
                Some(request_response::Event::OutboundFailure {
                    request_id, error, ..
                }) if request_id == id => return Err(outbound_failure(error)),
                Some(other) => tracing::debug!(event = ?other, "req/resp behaviour event"),
                None => tracing::debug!("another behaviour's event"),
            },
            _ => tracing::trace!("swarm event while waiting for a response"),
        }
    }
}

/// The error of a failed request. A codec refusal reaches `request_response` as an
/// [`std::io::Error`] around the [`ReadError`]; that one keeps its type, unless it is a passed
/// deadline or a stream failure, which say nothing about the peer's bytes.
fn outbound_failure(error: request_response::OutboundFailure) -> OutboundError {
    use request_response::OutboundFailure;
    match error {
        OutboundFailure::ConnectionClosed => OutboundError::Disconnected,
        OutboundFailure::Io(e) => match refused_response(e) {
            Ok(read) => OutboundError::InvalidResponse(read),
            Err(e) => OutboundError::Failure(error_chain(&OutboundFailure::Io(e))),
        },
        error => OutboundError::Failure(error_chain(&error)),
    }
}

/// The [`ReadError`] inside `e` if it is about the response's bytes, else `e` unchanged.
fn refused_response(e: std::io::Error) -> Result<ReadError, std::io::Error> {
    let refused = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ReadError>())
        .is_some_and(|read| !matches!(read, ReadError::Deadline(_) | ReadError::Io(_)));
    if !refused {
        return Err(e);
    }
    let kind = e.kind();
    match e.into_inner() {
        Some(inner) => inner
            .downcast::<ReadError>()
            .map(|read| *read)
            .map_err(|inner| std::io::Error::new(kind, inner)),
        None => Err(kind.into()),
    }
}

/// The chunks of a protocol without context bytes.
fn without_context<E: EthSpec>(chunks: Vec<ReceivedChunk<E>>) -> Vec<ResponseChunk<E>> {
    chunks.into_iter().map(|c| c.chunk).collect()
}

/// The one success payload of a single-chunk response.
fn single_chunk<E: EthSpec>(
    mut chunks: Vec<ResponseChunk<E>>,
) -> Result<Response<E>, OutboundError> {
    if chunks.len() != 1 {
        return Err(OutboundError::UnexpectedResponse(format!(
            "{} chunks",
            chunks.len()
        )));
    }
    match chunks.remove(0) {
        ResponseChunk::Success(response) => Ok(response),
        ResponseChunk::Error { code, message } => Err(OutboundError::ErrorResponse {
            code,
            message: String::from_utf8_lossy(&message).into_owned(),
        }),
    }
}

/// The one Status chunk of a Status response.
fn single_status<E: EthSpec>(chunks: Vec<ResponseChunk<E>>) -> Result<StatusV2, OutboundError> {
    match single_chunk(chunks)? {
        Response::Status(s) => Ok(s),
        other => Err(OutboundError::UnexpectedResponse(format!("{other:?}"))),
    }
}

/// The one MetaData chunk of a MetaData response.
fn single_metadata<E: EthSpec>(chunks: Vec<ResponseChunk<E>>) -> Result<MetaDataV3, OutboundError> {
    match single_chunk(chunks)? {
        Response::MetaData(m) => Ok(m),
        other => Err(OutboundError::UnexpectedResponse(format!("{other:?}"))),
    }
}

/// The `seq_number` of the one Ping chunk of a Ping response.
fn single_ping<E: EthSpec>(chunks: Vec<ResponseChunk<E>>) -> Result<u64, OutboundError> {
    match single_chunk(chunks)? {
        Response::Ping(Ping(seq_number)) => Ok(seq_number),
        other => Err(OutboundError::UnexpectedResponse(format!("{other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m2a_session::{NodeKey, Session, SessionBehaviour, Transport};
    use crate::rpc::codec::Deadlines;
    use crate::rpc::codec::ReadError;
    use crate::testkit::{BlocksReply, MetaDataReply, PingReply, StatusPeer, StatusReply};
    use consensus_types::primitives::{Slot, B256};
    use consensus_types::{ForkName, Minimal};
    use p2p_wire::rpc::codec::CodecError;
    use p2p_wire::rpc::protocols::MAX_REQUEST_BLOCKS_DENEB;
    use p2p_wire::testkit;
    use ssz::Encode;
    use std::sync::Arc;

    type E = Minimal;

    const OURS: ForkDigest = [0x66, 0x9e, 0x6c, 0x11];

    fn ours() -> StatusV2 {
        StatusV2 {
            fork_digest: OURS,
            finalized_root: B256::repeat_byte(1),
            finalized_epoch: 10,
            head_root: B256::repeat_byte(2),
            head_slot: 320,
            earliest_available_slot: 320,
        }
    }

    async fn connected(peer: &StatusPeer) -> Session<E> {
        let mut session = Session::<E>::start(
            NodeKey::ephemeral(),
            peer.pinned(),
            Arc::new(testkit::context_table()),
            Deadlines::default(),
            Transport::Tcp,
        )
        .unwrap();
        session.connect().await.unwrap();
        session
    }

    #[tokio::test]
    async fn status_digest_match_returns_the_peers_status() {
        let theirs = StatusV2 {
            head_slot: 999,
            earliest_available_slot: 7,
            ..ours()
        };
        let peer = StatusPeer::echoing(theirs.clone()).await;
        let mut session = connected(&peer).await;
        let got = status(session.swarm(), peer.id, &ours()).await.unwrap();
        assert_eq!(got, theirs);
        assert_eq!(
            peer.requests(),
            vec![ours()],
            "the peer received our Status"
        );
    }

    #[tokio::test]
    async fn status_digest_mismatch_fails() {
        let foreign = StatusV2 {
            fork_digest: [0xde, 0xad, 0xbe, 0xef],
            ..ours()
        };
        let reply = foreign.clone();
        let peer = StatusPeer::spawn(
            Box::new(move |_, _| StatusReply::Status(reply.clone())),
            None,
        )
        .await;
        let mut session = connected(&peer).await;
        let err = status(session.swarm(), peer.id, &ours()).await.unwrap_err();
        match &err {
            OutboundError::ForkDigestMismatch { ours: o, peer: p } => {
                assert_eq!(*o, OURS);
                assert_eq!(**p, foreign);
            }
            other => panic!("{other}"),
        }
        assert!(err.to_string().contains("deadbeef"), "{err}");
        assert!(err.to_string().contains("669e6c11"), "{err}");
    }

    #[tokio::test]
    async fn error_chunk_fails() {
        let peer = StatusPeer::spawn(
            Box::new(|_, _| StatusReply::Error(ResultCode::ServerError, b"busy".to_vec())),
            None,
        )
        .await;
        let mut session = connected(&peer).await;
        let err = status(session.swarm(), peer.id, &ours()).await.unwrap_err();
        assert!(
            matches!(&err, OutboundError::ErrorResponse { code: ResultCode::ServerError, message } if message == "busy"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_peer_without_status_fails_the_request() {
        // Not connected at all: request_response dials, and the allow list has no address.
        let peer = StatusPeer::echoing(ours()).await;
        let mut session = connected(&peer).await;
        let stranger = PeerId::random();
        let err = status(session.swarm(), stranger, &ours())
            .await
            .unwrap_err();
        assert!(matches!(err, OutboundError::Failure(_)), "{err}");
    }

    #[tokio::test]
    async fn a_connection_closed_under_the_request_is_disconnected() {
        let peer = StatusPeer::echoing(ours()).await;
        let mut session = connected(&peer).await;
        let id = session
            .swarm()
            .behaviour_mut()
            .status
            .send_request(&peer.id, Request::Status(ours()));
        session.swarm().disconnect_peer_id(peer.id).unwrap();
        let err = wait_for_response(session.swarm(), id, SessionBehaviour::<E>::status_event)
            .await
            .unwrap_err();
        assert!(matches!(err, OutboundError::Disconnected), "{err}");
    }

    /// A peer serving Status and, with `reply`, MetaData.
    async fn metadata_peer(reply: MetaDataReply) -> StatusPeer {
        StatusPeer::spawn_with_metadata(
            Box::new(|req, _| StatusReply::Status(req.clone())),
            Some(Box::new(move |_| reply.clone())),
            None,
        )
        .await
    }

    #[tokio::test]
    async fn metadata_roundtrip() {
        let canned = p2p_wire::testkit::metadata();
        let peer = metadata_peer(MetaDataReply::MetaData(canned.clone())).await;
        let mut session = connected(&peer).await;
        let got = metadata(session.swarm(), peer.id).await.unwrap();
        assert_eq!(got.seq_number, 7);
        let attnets: Vec<usize> = (0..64).filter(|&i| got.attnets.get(i).unwrap()).collect();
        assert_eq!(attnets, [0, 63]);
        let syncnets: Vec<usize> = (0..4).filter(|&i| got.syncnets.get(i).unwrap()).collect();
        assert_eq!(syncnets, [2]);
        assert_eq!(got.custody_group_count, 4);
        assert_eq!(got, canned);
        // The request was empty (the peer refuses any byte), and the same connection serves
        // a Status afterwards.
        assert_eq!(peer.metadata_requests(), 1);
        status(session.swarm(), peer.id, &ours()).await.unwrap();
        assert_eq!(peer.connections(), 1);

        // Two chunks on a single-response protocol: refused, nothing decoded is returned.
        let peer = metadata_peer(MetaDataReply::Chunks(vec![canned.clone(), canned])).await;
        let mut session = connected(&peer).await;
        let err = metadata(session.swarm(), peer.id).await.unwrap_err();
        assert!(
            matches!(
                err,
                OutboundError::InvalidResponse(ReadError::TooManyChunks { max: 1 })
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("chunks"), "{err}");
    }

    #[tokio::test]
    async fn metadata_error_chunk_fails() {
        let reply = MetaDataReply::Error(ResultCode::ResourceUnavailable, b"no".to_vec());
        let peer = metadata_peer(reply).await;
        let mut session = connected(&peer).await;
        let err = metadata(session.swarm(), peer.id).await.unwrap_err();
        assert!(
            matches!(&err, OutboundError::ErrorResponse { code: ResultCode::ResourceUnavailable, message } if message == "no"),
            "{err}"
        );
    }

    /// A peer serving Status, MetaData (the fixture's, `seq_number` 7) and, with `reply`, Ping.
    async fn ping_peer(reply: PingReply) -> StatusPeer {
        StatusPeer::spawn_with_ping(
            Box::new(|req, _| StatusReply::Status(req.clone())),
            Some(Box::new(|_| {
                MetaDataReply::MetaData(p2p_wire::testkit::metadata())
            })),
            Some(Box::new(move |_, _| reply.clone())),
            None,
        )
        .await
    }

    #[tokio::test]
    async fn ping_roundtrip() {
        let peer = ping_peer(PingReply::Ping(7)).await;
        let mut session = connected(&peer).await;
        assert_eq!(ping(session.swarm(), peer.id, 0).await.unwrap(), 7);
        assert_eq!(peer.pings(), vec![0], "the peer received our seq_number");
        // The answer is the seq_number of the MetaData the same connection serves.
        let m = metadata(session.swarm(), peer.id).await.unwrap();
        assert_eq!(m.seq_number, 7);
        assert_eq!(peer.connections(), 1);

        // 9 bytes: the declared length is above Ping's 8, refused before decoding.
        let peer = ping_peer(PingReply::Ssz(vec![7, 0, 0, 0, 0, 0, 0, 0, 0])).await;
        let mut session = connected(&peer).await;
        let err = ping(session.swarm(), peer.id, 0).await.unwrap_err();
        assert!(
            matches!(
                err,
                OutboundError::InvalidResponse(ReadError::Codec(CodecError::PayloadTooLarge {
                    len: 9,
                    max: 8
                }))
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("exceeds the bound 8"), "{err}");

        // Two chunks on a single-response protocol: refused, nothing decoded is returned.
        let peer = ping_peer(PingReply::Chunks(vec![7, 7])).await;
        let mut session = connected(&peer).await;
        let err = ping(session.swarm(), peer.id, 0).await.unwrap_err();
        assert!(
            matches!(
                err,
                OutboundError::InvalidResponse(ReadError::TooManyChunks { max: 1 })
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn ping_error_chunk_fails() {
        let reply = PingReply::Error(ResultCode::InvalidRequest, b"no".to_vec());
        let peer = ping_peer(reply).await;
        let mut session = connected(&peer).await;
        let err = ping(session.swarm(), peer.id, 3).await.unwrap_err();
        assert!(
            matches!(&err, OutboundError::ErrorResponse { code: ResultCode::InvalidRequest, message } if message == "no"),
            "{err}"
        );
        assert_eq!(peer.pings(), vec![3]);
    }

    // BeaconBlocksByRange v2 on the fixture peer (minimal preset: 8 slots per epoch).

    /// The fixture schedule: Fulu before epoch 2, Gloas from it.
    fn fixture_digest(epoch: Epoch) -> Option<ForkDigest> {
        Some(if epoch < 2 {
            testkit::FULU_DIGEST
        } else {
            testkit::GLOAS_DIGEST
        })
    }

    /// Slots 12..20: epoch 1 (Fulu) up to slot 15, epoch 2 (Gloas) from slot 16.
    fn range() -> BlocksByRangeV2Request {
        BlocksByRangeV2Request {
            start_slot: 12,
            count: 8,
            step: 1,
        }
    }

    /// The fixture block at `slot` in the shape of `fork`, on the wire with `digest`.
    fn wire_block(slot: Slot, fork: ForkName, digest: ForkDigest) -> (ForkDigest, Vec<u8>) {
        let ssz = match fork {
            ForkName::Fulu => testkit::fulu_block::<E>(slot).as_ssz_bytes(),
            ForkName::Gloas => testkit::gloas_block::<E>(slot).as_ssz_bytes(),
        };
        (digest, ssz)
    }

    /// The fixture block at `slot`, in its epoch's fork and digest.
    fn canonical(slot: Slot) -> (ForkDigest, Vec<u8>) {
        if slot < 16 {
            wire_block(slot, ForkName::Fulu, testkit::FULU_DIGEST)
        } else {
            wire_block(slot, ForkName::Gloas, testkit::GLOAS_DIGEST)
        }
    }

    /// A peer serving Status and, with `reply`, BlocksByRange.
    async fn blocks_peer(reply: BlocksReply) -> StatusPeer {
        StatusPeer::spawn_with_blocks(
            Box::new(|req, _| StatusReply::Status(req.clone())),
            None,
            None,
            Some(Box::new(move |_, _| reply.clone())),
            None,
        )
        .await
    }

    /// Requests [`range`] from a fixture peer answering `reply`.
    async fn fetch(
        reply: BlocksReply,
    ) -> (
        StatusPeer,
        Result<Vec<forked::SignedBeaconBlock<E>>, OutboundError>,
    ) {
        let peer = blocks_peer(reply).await;
        let mut session = connected(&peer).await;
        let got = blocks_by_range(session.swarm(), peer.id, range(), &fixture_digest).await;
        (peer, got)
    }

    fn invalid_blocks(
        got: Result<Vec<forked::SignedBeaconBlock<E>>, OutboundError>,
    ) -> BlocksError {
        match got {
            Err(OutboundError::InvalidBlocks(e)) => e,
            Err(other) => panic!("{other}"),
            Ok(blocks) => panic!("accepted {} blocks", blocks.len()),
        }
    }

    #[tokio::test]
    async fn blocks_by_range_roundtrip() {
        // Empty slots 14, 17, 18; the range crosses the Fulu/Gloas boundary at slot 16, and
        // each chunk is decoded in the fork its context bytes name.
        let slots = [12, 13, 15, 16, 19];
        let reply = BlocksReply::Blocks(slots.map(canonical).into());
        let (peer, got) = fetch(reply).await;
        let blocks = got.unwrap();
        let got: Vec<(Slot, ForkName)> = blocks.iter().map(|b| (b.slot(), b.fork_name())).collect();
        use ForkName::{Fulu, Gloas};
        assert_eq!(
            got,
            [(12, Fulu), (13, Fulu), (15, Fulu), (16, Gloas), (19, Gloas)]
        );
        assert_eq!(
            blocks[3],
            forked::SignedBeaconBlock::Gloas(testkit::gloas_block(16))
        );
        assert_eq!(peer.blocks_requests(), vec![range()]);
        assert_eq!(peer.connections(), 1);

        // No block at all is a valid answer: every slot of the range is empty.
        let (_, got) = fetch(BlocksReply::Blocks(Vec::new())).await;
        assert!(got.unwrap().is_empty());
    }

    #[tokio::test]
    async fn slot_out_of_range_rejected() {
        for (slots, bad) in [([12, 20], 20), ([11, 12], 11)] {
            let reply = BlocksReply::Blocks(slots.map(canonical).into());
            let (_, got) = fetch(reply).await;
            let err = invalid_blocks(got);
            assert_eq!(
                err,
                BlocksError::SlotOutOfRange {
                    slot: bad,
                    start: 12,
                    end: 20
                },
                "{slots:?}"
            );
            assert!(err.to_string().contains("[12, 20)"), "{err}");
        }
    }

    #[tokio::test]
    async fn non_increasing_slots_rejected() {
        for (slots, slot, previous) in [([13, 13], 13, 13), ([14, 13], 13, 14)] {
            let reply = BlocksReply::Blocks(slots.map(canonical).into());
            let (_, got) = fetch(reply).await;
            assert_eq!(
                invalid_blocks(got),
                BlocksError::NonIncreasingSlot { slot, previous },
                "{slots:?}"
            );
        }
    }

    #[tokio::test]
    async fn wrong_context_digest_rejected() {
        // A Fulu block of epoch 1 under the second Fulu digest: it decodes (the digest names
        // Fulu), but it is not the digest of the block's epoch.
        let reply = BlocksReply::Blocks(vec![
            canonical(12),
            wire_block(13, ForkName::Fulu, testkit::FULU_BPO_DIGEST),
        ]);
        let (_, got) = fetch(reply).await;
        let err = invalid_blocks(got);
        assert_eq!(
            err,
            BlocksError::WrongContextDigest {
                slot: 13,
                epoch: 1,
                got: Some(testkit::FULU_BPO_DIGEST),
                want: Some(testkit::FULU_DIGEST),
            }
        );
        assert!(err.to_string().contains("0xf0010002"), "{err}");
        // A Gloas-epoch slot under the Fulu digest, in the Fulu shape.
        let reply = BlocksReply::Blocks(vec![wire_block(16, ForkName::Fulu, testkit::FULU_DIGEST)]);
        let (_, got) = fetch(reply).await;
        assert!(matches!(
            invalid_blocks(got),
            BlocksError::WrongContextDigest {
                slot: 16,
                epoch: 2,
                ..
            }
        ));
        // A digest the table does not know is refused by the codec, before the payload.
        let reply = BlocksReply::Blocks(vec![wire_block(
            12,
            ForkName::Fulu,
            testkit::UNKNOWN_DIGEST,
        )]);
        let (_, got) = fetch(reply).await;
        assert!(
            matches!(
                got,
                Err(OutboundError::InvalidResponse(ReadError::Codec(
                    CodecError::UnknownContext(_)
                )))
            ),
            "{got:?}"
        );
    }

    #[tokio::test]
    async fn blocks_by_range_limits() {
        // More chunks than `count`: the codec refuses the response.
        let peer = blocks_peer(BlocksReply::Blocks([12, 13, 14].map(canonical).into())).await;
        let mut session = connected(&peer).await;
        let two = BlocksByRangeV2Request {
            count: 2,
            ..range()
        };
        let err = blocks_by_range(session.swarm(), peer.id, two, &fixture_digest)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                OutboundError::InvalidResponse(ReadError::TooManyChunks { max: 2 })
            ),
            "{err:?}"
        );
        // A request outside 1..=MAX_REQUEST_BLOCKS_DENEB, a step other than 1 or a range past
        // the last slot is never sent.
        let bad = [
            BlocksByRangeV2Request {
                count: 0,
                ..range()
            },
            BlocksByRangeV2Request {
                count: 129,
                ..range()
            },
            BlocksByRangeV2Request { step: 2, ..range() },
            BlocksByRangeV2Request {
                start_slot: u64::MAX,
                ..range()
            },
        ];
        for request in bad {
            let err = blocks_by_range(session.swarm(), peer.id, request, &fixture_digest)
                .await
                .unwrap_err();
            assert!(
                matches!(err, OutboundError::InvalidRequest(_)),
                "{request:?}: {err}"
            );
        }
        assert_eq!(
            peer.blocks_requests(),
            vec![two],
            "only the valid request went out"
        );
        let full = BlocksByRangeV2Request {
            count: MAX_REQUEST_BLOCKS_DENEB,
            ..range()
        };
        assert!(check_request(&full).is_ok());
    }

    #[tokio::test]
    async fn blocks_error_chunk_fails() {
        let reply = BlocksReply::Error(ResultCode::ResourceUnavailable, b"pruned".to_vec());
        let (_, got) = fetch(reply).await;
        assert!(
            matches!(&got, Err(OutboundError::ErrorResponse { code: ResultCode::ResourceUnavailable, message }) if message == "pruned"),
            "{got:?}"
        );
    }

    #[test]
    fn blocks_need_a_block_with_context_bytes() {
        let block = |context| ReceivedChunk::<E> {
            context,
            chunk: ResponseChunk::Success(Response::Block(Box::new(
                forked::SignedBeaconBlock::Fulu(testkit::fulu_block(12)),
            ))),
        };
        assert_eq!(
            check_blocks(
                &range(),
                vec![block(Some(testkit::FULU_DIGEST))],
                &fixture_digest
            )
            .unwrap()
            .len(),
            1
        );
        // No context bytes: the codec never yields that for a block, and it is refused.
        let err = check_blocks(&range(), vec![block(None)], &fixture_digest).unwrap_err();
        assert!(
            matches!(
                err,
                OutboundError::InvalidBlocks(BlocksError::WrongContextDigest { got: None, .. })
            ),
            "{err}"
        );
        // An epoch the schedule has no digest for (before Fulu).
        let none = |_: Epoch| None;
        let err =
            check_blocks(&range(), vec![block(Some(testkit::FULU_DIGEST))], &none).unwrap_err();
        assert!(
            matches!(
                err,
                OutboundError::InvalidBlocks(BlocksError::WrongContextDigest { want: None, .. })
            ),
            "{err}"
        );
        let ping = ReceivedChunk::<E> {
            context: None,
            chunk: ResponseChunk::Success(Response::Ping(Ping(1))),
        };
        let err = check_blocks(&range(), vec![ping], &fixture_digest).unwrap_err();
        assert!(matches!(err, OutboundError::UnexpectedResponse(_)), "{err}");
    }

    #[test]
    fn single_ping_refuses_other_shapes() {
        let one = vec![ResponseChunk::<E>::Success(Response::Ping(Ping(9)))];
        assert_eq!(single_ping(one).unwrap(), 9);
        let status = vec![ResponseChunk::<E>::Success(Response::Status(ours()))];
        assert!(matches!(
            single_ping(status),
            Err(OutboundError::UnexpectedResponse(_))
        ));
        let two = vec![
            ResponseChunk::<E>::Success(Response::Ping(Ping(9))),
            ResponseChunk::<E>::Success(Response::Ping(Ping(9))),
        ];
        assert!(matches!(
            single_ping(two),
            Err(OutboundError::UnexpectedResponse(_))
        ));
    }

    #[test]
    fn single_metadata_refuses_other_shapes() {
        let m = p2p_wire::testkit::metadata();
        let one = vec![ResponseChunk::<E>::Success(Response::MetaData(m.clone()))];
        assert_eq!(single_metadata(one).unwrap(), m);
        let status = vec![ResponseChunk::<E>::Success(Response::Status(ours()))];
        assert!(matches!(
            single_metadata(status),
            Err(OutboundError::UnexpectedResponse(_))
        ));
        let two = vec![
            ResponseChunk::<E>::Success(Response::MetaData(m.clone())),
            ResponseChunk::<E>::Success(Response::MetaData(m)),
        ];
        assert!(matches!(
            single_metadata(two),
            Err(OutboundError::UnexpectedResponse(_))
        ));
    }

    #[test]
    fn single_status_refuses_other_shapes() {
        let none: Vec<ResponseChunk<E>> = vec![];
        assert!(matches!(
            single_status(none),
            Err(OutboundError::UnexpectedResponse(_))
        ));
        let ping = vec![ResponseChunk::<E>::Success(Response::Ping(Ping(1)))];
        assert!(matches!(
            single_status(ping),
            Err(OutboundError::UnexpectedResponse(_))
        ));
        let two = vec![
            ResponseChunk::<E>::Success(Response::Status(ours())),
            ResponseChunk::<E>::Success(Response::Status(ours())),
        ];
        assert!(matches!(
            single_status(two),
            Err(OutboundError::UnexpectedResponse(_))
        ));
    }

    #[test]
    fn outbound_failure_keeps_the_codecs_refusal_typed() {
        use crate::rpc::codec::Deadline;
        use request_response::OutboundFailure;
        let io = |e: ReadError| OutboundFailure::Io(e.into());
        assert!(matches!(
            outbound_failure(io(ReadError::NoResponse)),
            OutboundError::InvalidResponse(ReadError::NoResponse)
        ));
        // A passed deadline or a failed stream is not about the peer's bytes.
        let late = outbound_failure(io(ReadError::Deadline(Deadline::Ttfb)));
        assert!(
            matches!(&late, OutboundError::Failure(m) if m.contains("Ttfb deadline passed")),
            "{late}"
        );
        let reset = io(ReadError::Io(std::io::ErrorKind::ConnectionReset.into()));
        assert!(matches!(outbound_failure(reset), OutboundError::Failure(_)));
        let other = OutboundFailure::Io(std::io::Error::other("stream"));
        assert!(
            matches!(outbound_failure(other), OutboundError::Failure(m) if m.contains("stream"))
        );
        assert!(matches!(
            outbound_failure(OutboundFailure::ConnectionClosed),
            OutboundError::Disconnected
        ));
        assert!(matches!(
            outbound_failure(OutboundFailure::Timeout),
            OutboundError::Failure(_)
        ));
    }

    #[test]
    fn error_chain_joins_sources() {
        #[derive(Debug, thiserror::Error)]
        #[error("outer")]
        struct Outer(#[source] std::io::Error);
        assert_eq!(
            error_chain(&Outer(std::io::Error::other("cause"))),
            "outer: cause"
        );
    }
}
