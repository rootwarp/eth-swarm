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
//!
//! # The probe's range requester
//!
//! [`RangeRequester::blocks_by_range`] is the same exchange on the probe swarm: the request goes
//! through [`Control`], so it waits for one of the
//! [`MAX_CONCURRENT_REQUESTS`](super::MAX_CONCURRENT_REQUESTS) outbound slots of the protocol
//! (a full wait queue IGNOREs it, [`RangeError::Ignored`]) and is read by the codec under its
//! deadlines. The context bytes are looked up in the codec's table before the payload is decoded
//! (an unknown digest is refused there), and each block's context must then be the digest of the
//! block's own epoch on the BPO-aware schedule ([`ScheduleDigests`] over
//! `network_config::digest::digest_schedule`): a block decoded in another fork's shape than its
//! slot's fails the response. On top of [`blocks_by_range`]'s rules, each block's `parent_root`
//! must be the root of the block before it (`phase0/p2p-interface.md` L1563–1567); skipped
//! slots are fine.
//!
//! [`fetch_epoch`] (and [`fetch_range`]) fetch a range over any [`RangeSource`], one request of
//! at most `MAX_REQUEST_BLOCKS_DENEB` after the other. [`Control::request_blocks`] refuses a
//! request below the peer's `earliest_available_slot` by its last valid Status, and checks again
//! when a waiting request's turn comes, so no caller can send one.
//!
//! - **Peers**: one snapshot of the Status-valid peers per piece of at most 128 slots, those
//!   whose `earliest_available_slot` is at or before the first slot requested
//!   (`fulu/p2p-interface.md` L552–561); peers whose `head_slot` reaches the end of the slots
//!   asked for first, peers behind the first slot last, and within those the peers asked fewer
//!   times in the piece first (so peers take turns), then the highest `head_slot`. A peer whose
//!   answer broke the rules is not asked again. One whose request failed without a fault (a
//!   timeout, an error chunk, a full queue) and whose head reaches the slots asked for is asked
//!   once more when no other peer is left, once per position of the piece's first open slot.
//!   A piece takes at most [`MAX_ATTEMPTS_PER_PIECE`] requests.
//! - **What settles a slot**: a block kept; a link (a block whose parent is the last block kept
//!   proves the slots between them empty); or two different peers whose answers have no block
//!   there and whose `head_slot` reaches the last of those slots (a peer behind them, syncing
//!   say, truthfully has none, so its empty answer counts for nothing). One peer's word is never
//!   enough: an empty answer, or an answer whose first block
//!   is after the requested start while no earlier block is known, is held until a second peer
//!   agrees (the same peer asked again counts only once). The slots no second peer settles are
//!   kept as [`RangeFetch::unconfirmed`], never silently empty.
//! - **Short answers**: a peer may stop after its first block (`phase0` L1575), so an answer
//!   that ends before the piece does is kept and the rest is asked again, of the peer asked
//!   fewest times in the piece first. That is not a fault.
//! - **Links**: the first block of each answer must name the last block kept so far as its
//!   parent, or the answer is dropped ([`RangeError::Disjoint`], not a fault: either peer may be
//!   on another branch) and the rest is asked of another peer. After an unconfirmed gap the next
//!   block's parent may be in the gap, so the next answer is held to the start rules instead.
//!
//! The trust this rests on, and what checks the rest:
//!
//! - **Omissions**: two peers. Two colluding peers that both claim a head past the range and
//!   both answer a gap with no block settle it in two requests, and a peer that has the blocks
//!   is not asked; `unconfirmed` does not show that gap. The fetcher trusts any two peers to
//!   not lie together.
//! - **Forgeries**: none. A peer can hand back a linked chain that is not the canonical one,
//!   and a claimed `head_slot` is not checked.
//!
//! Both are caught by the probe's comparison of every slot's root with the reference node's
//! (a block the result lacks is a slot the reference has a root for), not here.

use crate::rpc::codec::{ReadError, ReceivedChunk, RpcCodec, RpcRequest};
use crate::rpc::inbound::{BlocksOutcome, BlocksTicket, Control, ControlEvent};
use consensus_types::primitives::{Epoch, Root, Slot};
use consensus_types::{forked, EthSpec};
use futures::StreamExt;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{PeerId, Swarm};
use network_config::digest::DigestInputs;
use p2p_wire::rpc::messages::{BlocksByRangeV2Request, ForkDigest, MetaDataV3, Ping, StatusV2};
use p2p_wire::rpc::protocols::{
    Request, Response, ResponseChunk, ResultCode, MAX_REQUEST_BLOCKS_DENEB,
};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::marker::PhantomData;
use tree_hash::TreeHash;

/// One event of an outbound `request_response` behaviour.
pub type RpcEvent<E> = request_response::Event<RpcRequest, Vec<ReceivedChunk<E>>>;

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
    /// A block whose `parent_root` is not the root of the block before it.
    #[error(
        "the block at slot {slot} has parent {parent_root}, not {previous_root}, the root of the \
         block at slot {previous_slot} before it"
    )]
    BrokenParentLink {
        /// The block's slot.
        slot: Slot,
        /// Its `parent_root`.
        parent_root: Root,
        /// The previous block's slot.
        previous_slot: Slot,
        /// The previous block's root.
        previous_root: Root,
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
        .send_request(&peer, Request::Status(ours.clone()).into());
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
        .send_request(&peer, Request::MetaData.into());
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
        .send_request(&peer, Request::Ping(Ping(ours)).into());
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
        .send_request(&peer, Request::BlocksByRange(request).into());
    let chunks = wait_for_response(swarm, id, B::blocks_by_range_event).await?;
    check_blocks(&request, chunks, digest_at)
}

/// `count` in `1..=MAX_REQUEST_BLOCKS_DENEB`, `step` 1, and the range inside `u64` slots.
pub(crate) fn check_request(request: &BlocksByRangeV2Request) -> Result<(), OutboundError> {
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
        let previous = blocks.last().map(forked::SignedBeaconBlock::slot);
        check_slot(slot, previous, start, end).map_err(OutboundError::InvalidBlocks)?;
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

/// A block's `slot` inside `[start, end)` and above the `previous` block's.
fn check_slot(
    slot: Slot,
    previous: Option<Slot>,
    start: Slot,
    end: Slot,
) -> Result<(), BlocksError> {
    if !(start..end).contains(&slot) {
        return Err(BlocksError::SlotOutOfRange { slot, start, end });
    }
    match previous {
        Some(previous) if slot <= previous => {
            Err(BlocksError::NonIncreasingSlot { slot, previous })
        }
        _ => Ok(()),
    }
}

/// What the range checks read of a block.
pub trait Linked {
    /// `slot`.
    fn slot(&self) -> Slot;
    /// `hash_tree_root(block.message)`.
    fn root(&self) -> Root;
    /// `message.parent_root`.
    fn parent_root(&self) -> Root;
}

/// `hash_tree_root(block.message)`: the block root the beacon API reports.
pub fn block_root<E: EthSpec>(block: &forked::SignedBeaconBlock<E>) -> Root {
    match block {
        forked::SignedBeaconBlock::Fulu(b) => b.message.tree_hash_root(),
        forked::SignedBeaconBlock::Gloas(b) => b.message.tree_hash_root(),
    }
}

impl<E: EthSpec> Linked for forked::SignedBeaconBlock<E> {
    fn slot(&self) -> Slot {
        forked::SignedBeaconBlock::slot(self)
    }

    fn root(&self) -> Root {
        block_root(self)
    }

    fn parent_root(&self) -> Root {
        match self {
            Self::Fulu(b) => b.message.parent_root,
            Self::Gloas(b) => b.message.parent_root,
        }
    }
}

/// Every block's `parent_root` is the root of the block before it.
fn check_parent_links<B: Linked>(blocks: &[B]) -> Result<(), BlocksError> {
    for pair in blocks.windows(2) {
        let [previous, block] = pair else { continue };
        let previous_root = previous.root();
        if block.parent_root() != previous_root {
            return Err(BlocksError::BrokenParentLink {
                slot: block.slot(),
                parent_root: block.parent_root(),
                previous_slot: previous.slot(),
                previous_root,
            });
        }
    }
    Ok(())
}

/// The fork digest of every epoch from Fulu on: the BPO-aware schedule
/// (`network_config::digest::digest_schedule`), where the digest of an epoch is the one of the
/// last entry at or before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleDigests(Vec<(Epoch, ForkDigest)>);

impl ScheduleDigests {
    /// The digests of `schedule`'s entries.
    #[must_use]
    pub fn new(schedule: &[DigestInputs]) -> Self {
        let mut entries: Vec<(Epoch, ForkDigest)> =
            schedule.iter().map(|i| (i.epoch, i.fork_digest)).collect();
        entries.sort_unstable_by_key(|(epoch, _)| *epoch);
        Self(entries)
    }

    /// `compute_fork_digest` of `epoch`; `None` before the first entry (before Fulu).
    #[must_use]
    pub fn digest_at(&self, epoch: Epoch) -> Option<ForkDigest> {
        self.0
            .iter()
            .rev()
            .find(|(from, _)| *from <= epoch)
            .map(|(_, digest)| *digest)
    }
}

/// Why one range request of the probe gave no blocks.
#[derive(Debug, thiserror::Error)]
pub enum RangeError {
    /// The exchange failed or its response broke the request's rules (see [`OutboundError`]).
    #[error(transparent)]
    Outbound(#[from] OutboundError),
    /// The protocol's outbound wait queue was full: the request was IGNOREd, never sent.
    #[error("the outbound BeaconBlocksByRange queue is full: the request was ignored")]
    Ignored,
    /// The answer's first block does not name the last block fetched before it as its parent.
    #[error(
        "the block at slot {slot} has parent {parent_root}, not {anchor}, the last block \
         fetched before it"
    )]
    Disjoint {
        /// The first block's slot.
        slot: Slot,
        /// Its `parent_root`.
        parent_root: Root,
        /// The root of the last block fetched before it.
        anchor: Root,
    },
}

impl RangeError {
    /// Whether the peer broke a rule of the protocol: its response was malformed, more than
    /// the request allows, or blocks outside the request's rules. A failed exchange (a
    /// deadline, a closed stream, an error chunk), an IGNOREd request or an answer of another
    /// branch is not.
    #[must_use]
    pub fn is_peer_fault(&self) -> bool {
        matches!(
            self,
            Self::Outbound(
                OutboundError::InvalidBlocks(_)
                    | OutboundError::InvalidResponse(_)
                    | OutboundError::UnexpectedResponse(_)
            )
        )
    }

    /// Whether the same request may succeed if sent again: a failed exchange or an IGNOREd
    /// request, not a fault and not an answer of another branch.
    #[must_use]
    pub fn may_pass(&self) -> bool {
        !self.is_peer_fault() && !matches!(self, Self::Disjoint { .. })
    }
}

/// A behaviour with the probe's [`Control`] inside.
pub trait ControlRpc<E: EthSpec>: NetworkBehaviour {
    /// The req/resp behaviour.
    fn control(&self) -> &Control<E>;

    /// The req/resp behaviour, mutably.
    fn control_mut(&mut self) -> &mut Control<E>;

    /// The req/resp behaviour's event inside `event`, or `None` for another behaviour's.
    fn control_event(event: Self::ToSwarm) -> Option<ControlEvent>;
}

/// The probe's BeaconBlocksByRange v2 requester: drives `swarm` through each exchange.
///
/// Events of other behaviours, and the req/resp behaviour's other events, that arrive meanwhile
/// are dropped (logged at debug); [`Control`] has already acted on its own.
pub struct RangeRequester<'a, E: EthSpec, B: ControlRpc<E>> {
    swarm: &'a mut Swarm<B>,
    digest_at: &'a DigestAt<'a>,
    _spec: PhantomData<E>,
}

impl<'a, E: EthSpec, B: ControlRpc<E>> RangeRequester<'a, E, B> {
    /// A requester on `swarm`, judging context bytes by `digest_at` (the BPO-aware schedule:
    /// [`ScheduleDigests::digest_at`]).
    pub fn new(swarm: &'a mut Swarm<B>, digest_at: &'a DigestAt<'a>) -> Self {
        Self {
            swarm,
            digest_at,
            _spec: PhantomData,
        }
    }

    /// Requests the blocks of `[start_slot, start_slot + count)` from `peer` (`step` 1) and
    /// returns them once every one passed the request's rules (see the module docs).
    ///
    /// # Errors
    ///
    /// [`RangeError`]: a request outside the protocol's limits (never sent), a full outbound
    /// queue, a failed exchange, or a response that broke a rule (every block is dropped).
    pub async fn blocks_by_range(
        &mut self,
        peer: PeerId,
        start_slot: Slot,
        count: u64,
    ) -> Result<Vec<forked::SignedBeaconBlock<E>>, RangeError> {
        self.send(
            peer,
            BlocksByRangeV2Request {
                start_slot,
                count,
                step: 1,
            },
        )
        .await
    }

    async fn send(
        &mut self,
        peer: PeerId,
        request: BlocksByRangeV2Request,
    ) -> Result<Vec<forked::SignedBeaconBlock<E>>, RangeError> {
        let ticket = self
            .swarm
            .behaviour_mut()
            .control_mut()
            .request_blocks(peer, request)?;
        let chunks = Pending {
            swarm: &mut *self.swarm,
            ticket,
            _spec: PhantomData,
        }
        .outcome()
        .await?;
        let blocks = check_blocks(&request, chunks, self.digest_at)?;
        check_parent_links(&blocks).map_err(OutboundError::InvalidBlocks)?;
        Ok(blocks)
    }
}

/// One open request of a [`RangeRequester`]; dropped before its outcome (the future was
/// cancelled), it tells [`Control`] to forget the outcome.
struct Pending<'s, E: EthSpec, B: ControlRpc<E>> {
    swarm: &'s mut Swarm<B>,
    ticket: BlocksTicket,
    _spec: PhantomData<E>,
}

impl<E: EthSpec, B: ControlRpc<E>> Pending<'_, E, B> {
    async fn outcome(&mut self) -> BlocksOutcome<E> {
        loop {
            let control = self.swarm.behaviour_mut().control_mut();
            if let Some(outcome) = control.take_blocks(self.ticket) {
                return outcome;
            }
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(event) => match B::control_event(event) {
                    Some(ControlEvent::BlocksByRange { ticket, .. }) if ticket == self.ticket => {}
                    Some(other) => tracing::debug!(event = ?other, "req/resp event"),
                    None => tracing::debug!("another behaviour's event"),
                },
                _ => tracing::trace!("swarm event while waiting for blocks"),
            }
        }
    }
}

impl<E: EthSpec, B: ControlRpc<E>> Drop for Pending<'_, E, B> {
    fn drop(&mut self) {
        self.swarm
            .behaviour_mut()
            .control_mut()
            .cancel_blocks(self.ticket);
    }
}

/// Where [`fetch_range`] gets its peers and blocks from.
pub trait RangeSource {
    /// The block type.
    type Block: Linked;

    /// The Status-valid peers and their last Status.
    fn range_peers(&self) -> Vec<(PeerId, StatusV2)>;

    /// Sends `request` to `peer`; the blocks once they passed the request's rules.
    fn request_range(
        &mut self,
        peer: PeerId,
        request: BlocksByRangeV2Request,
    ) -> impl Future<Output = Result<Vec<Self::Block>, RangeError>>;
}

impl<E: EthSpec, B: ControlRpc<E>> RangeSource for RangeRequester<'_, E, B> {
    type Block = forked::SignedBeaconBlock<E>;

    fn range_peers(&self) -> Vec<(PeerId, StatusV2)> {
        self.swarm.behaviour().control().status_valid_peers()
    }

    fn request_range(
        &mut self,
        peer: PeerId,
        request: BlocksByRangeV2Request,
    ) -> impl Future<Output = Result<Vec<Self::Block>, RangeError>> {
        self.send(peer, request)
    }
}

/// Requests one piece of a range (at most `MAX_REQUEST_BLOCKS_DENEB` slots) may take before
/// what is still open in it is given up \[est\]: room for peers that answer a few blocks at a
/// time, and a bound on what a stream of faulty peers can cost.
pub const MAX_ATTEMPTS_PER_PIECE: usize = 64;

/// What [`fetch_range`] got.
#[derive(Debug)]
pub struct RangeFetch<B> {
    /// Every block of the range, in slot order, each the child of the one before, except
    /// across an [`unconfirmed`](Self::unconfirmed) gap: the first block after one may name a
    /// block inside it as its parent.
    pub blocks: Vec<B>,
    /// Every request sent, in order, with its peer.
    pub requests: Vec<(PeerId, BlocksByRangeV2Request)>,
    /// Every request that gave no blocks, with its peer; [`RangeError::is_peer_fault`] tells
    /// which broke a rule.
    pub failures: Vec<(PeerId, RangeError)>,
    /// `[start, end)` ranges kept as empty on one peer's word (or on none, once the piece ran out
    /// of peers or attempts): no second peer confirmed them.
    pub unconfirmed: Vec<(Slot, Slot)>,
}

impl<B: Linked> RangeFetch<B> {
    /// The block the next answer must link to: the last block kept, unless an unconfirmed gap
    /// follows it (the next block's parent may be in the gap).
    fn anchor(&self) -> Option<&B> {
        let last = self.blocks.last()?;
        match self.unconfirmed.last() {
            Some((from, _)) if *from > last.slot() => None,
            _ => Some(last),
        }
    }
}

/// Why [`fetch_range`] could not complete.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The range is empty or ends past the last slot.
    #[error("no range of slots: start {start_slot}, count {count}")]
    InvalidRange {
        /// The first slot.
        start_slot: Slot,
        /// The slot count.
        count: u64,
    },
    /// No Status-valid peer with `earliest_available_slot` at or before `slot` was left to ask.
    #[error(
        "no peer left to ask for the blocks from slot {slot} ({} failed requests)",
        failures.len()
    )]
    NoPeer {
        /// The first slot no answer covered.
        slot: Slot,
        /// Every failed request, with its peer.
        failures: Vec<(PeerId, RangeError)>,
    },
}

/// Fetches every block of `epoch` (of `slots_per_epoch` slots) over `source`; see
/// [`fetch_range`].
///
/// # Errors
///
/// [`FetchError`], as [`fetch_range`].
pub async fn fetch_epoch<S: RangeSource>(
    source: &mut S,
    epoch: Epoch,
    slots_per_epoch: u64,
) -> Result<RangeFetch<S::Block>, FetchError> {
    let Some(start_slot) = epoch.checked_mul(slots_per_epoch) else {
        return Err(FetchError::InvalidRange {
            start_slot: Slot::MAX,
            count: slots_per_epoch,
        });
    };
    fetch_range(source, start_slot, slots_per_epoch).await
}

/// Fetches every block of `[start_slot, start_slot + count)` over `source`, one request of at
/// most `MAX_REQUEST_BLOCKS_DENEB` (`step` 1) at a time, from peers whose
/// `earliest_available_slot` is at or before the request's first slot (see the module docs).
///
/// # Errors
///
/// [`FetchError::InvalidRange`] for an empty range or one past the last slot;
/// [`FetchError::NoPeer`] when no peer is left for a piece no answer covered.
pub async fn fetch_range<S: RangeSource>(
    source: &mut S,
    start_slot: Slot,
    count: u64,
) -> Result<RangeFetch<S::Block>, FetchError> {
    let end = match start_slot.checked_add(count) {
        Some(end) if count > 0 => end,
        _ => return Err(FetchError::InvalidRange { start_slot, count }),
    };
    let mut fetch = RangeFetch {
        blocks: Vec::new(),
        requests: Vec::new(),
        failures: Vec::new(),
        unconfirmed: Vec::new(),
    };
    let mut faulty: HashSet<PeerId> = HashSet::new();
    let mut from = start_slot;
    while from < end {
        let to = end.min(from.saturating_add(MAX_REQUEST_BLOCKS_DENEB));
        fetch_piece(source, from, to, &mut fetch, &mut faulty).await?;
        from = to;
    }
    Ok(fetch)
}

/// What is known of one piece `[.., end)` of a range: every slot before `cursor` is settled.
struct Piece<B> {
    cursor: Slot,
    end: Slot,
    /// Peers asked since `cursor` last moved.
    asked: HashSet<PeerId>,
    /// Peers whose head reaches the slots asked for and whose request failed in a way that
    /// may pass ([`RangeError::may_pass`]): asked once more when nobody else is left.
    retry: HashSet<PeerId>,
    /// Peers asked that once more since `cursor` last moved.
    retried: HashSet<PeerId>,
    /// How many times each peer was asked in the piece: the fewer, the sooner it is asked.
    asks: HashMap<PeerId, usize>,
    /// Peers whose answer says `[cursor, target)` holds no block.
    empty: HashSet<PeerId>,
    /// An answer whose first block is after `cursor` while no block before it is known: the
    /// slots before it rest on its peer's word alone until a second peer agrees.
    held: Option<(PeerId, Vec<B>)>,
}

impl<B: Linked> Piece<B> {
    /// The end of the slots asked for next: the held answer's first block, or the piece's end.
    fn target(&self) -> Slot {
        self.held
            .as_ref()
            .and_then(|(_, blocks)| blocks.first())
            .map_or(self.end, Linked::slot)
    }

    /// Keeps `blocks` (already checked against `fetch`'s last block) and moves past them.
    fn take(&mut self, fetch: &mut RangeFetch<B>, blocks: Vec<B>) {
        if let Some(last) = blocks.last() {
            self.cursor = last.slot() + 1;
        }
        fetch.blocks.extend(blocks);
        self.asked.clear();
        self.retry.clear();
        self.retried.clear();
        self.empty.clear();
    }

    /// Notes that `peer`'s request failed with `error`: a covering peer whose failure may pass
    /// is kept to be asked once more.
    fn failed(&mut self, peer: PeerId, error: &RangeError, covering: bool) {
        if covering && error.may_pass() && !self.retried.contains(&peer) {
            self.retry.insert(peer);
        }
    }

    /// Makes the peers kept by [`Piece::failed`] askable again; `false` if there are none.
    fn ask_failed_again(&mut self) -> bool {
        if self.retry.is_empty() {
            return false;
        }
        for peer in self.retry.drain() {
            self.asked.remove(&peer);
            self.retried.insert(peer);
        }
        true
    }

    /// Keeps the held answer if it is the child of the last block kept; drops it, as another
    /// branch's, if not.
    fn settle_held(&mut self, fetch: &mut RangeFetch<B>) {
        let Some((peer, blocks)) = self.held.take() else {
            return;
        };
        match fits(fetch.anchor(), self.cursor, self.end, blocks) {
            Ok(blocks) => self.take(fetch, blocks),
            Err(e) => {
                tracing::debug!(%peer, error = %e, "a held answer does not fit: dropped");
                fetch.failures.push((peer, e));
            }
        }
    }
}

/// Fetches the piece `[start, end)` (at most `MAX_REQUEST_BLOCKS_DENEB` slots) into `fetch`,
/// from one snapshot of the peers and in at most [`MAX_ATTEMPTS_PER_PIECE`] requests.
///
/// A slot is settled by a block kept, by a link (a block whose parent is the last block kept
/// proves the slots between them empty), or by two different peers whose answers have no block
/// there. Short answers are kept and the rest is asked again; what no second peer settles is
/// [`RangeFetch::unconfirmed`].
async fn fetch_piece<S: RangeSource>(
    source: &mut S,
    start: Slot,
    end: Slot,
    fetch: &mut RangeFetch<S::Block>,
    faulty: &mut HashSet<PeerId>,
) -> Result<(), FetchError> {
    let peers = source.range_peers();
    let mut piece = Piece {
        cursor: start,
        end,
        asked: HashSet::new(),
        retry: HashSet::new(),
        retried: HashSet::new(),
        asks: HashMap::new(),
        empty: HashSet::new(),
        held: None,
    };
    let mut attempts = 0;
    while piece.cursor < end {
        let next = (attempts < MAX_ATTEMPTS_PER_PIECE)
            .then(|| loop {
                let skip = |p: &PeerId| piece.asked.contains(p) || faulty.contains(p);
                let (cursor, target) = (piece.cursor, piece.target());
                let picked = pick_peer(&peers, cursor, target, skip, &piece.asks);
                if picked.is_some() || !piece.ask_failed_again() {
                    break picked;
                }
            })
            .flatten();
        let Some(peer) = next else {
            give_up(&mut piece, fetch, start)?;
            continue;
        };
        attempts += 1;
        piece.asked.insert(peer);
        *piece.asks.entry(peer).or_default() += 1;
        let (cursor, target) = (piece.cursor, piece.target());
        let request = BlocksByRangeV2Request {
            start_slot: cursor,
            count: target - cursor,
            step: 1,
        };
        fetch.requests.push((peer, request));
        let answer = source
            .request_range(peer, request)
            .await
            .and_then(|blocks| fits(fetch.anchor(), cursor, target, blocks));
        let blocks = match answer {
            Ok(blocks) => blocks,
            Err(e) => {
                tracing::debug!(%peer, start_slot = cursor, error = %e, "range request failed");
                if e.is_peer_fault() {
                    faulty.insert(peer);
                }
                piece.failed(peer, &e, covers(&peers, peer, target));
                fetch.failures.push((peer, e));
                continue;
            }
        };
        let Some(first) = blocks.first().map(Linked::slot) else {
            // Only a peer whose head reaches the gap's last slot says anything by having no
            // block in it: one behind (syncing, say) truthfully has none.
            if covers(&peers, peer, target) {
                piece.empty.insert(peer);
            }
            if piece.empty.len() >= 2 {
                if piece.held.is_some() {
                    piece.settle_held(fetch);
                } else {
                    piece.cursor = end;
                }
            }
            continue;
        };
        // The slots before `first` are settled by a link to the last block kept, by starting
        // at the cursor, or by another peer's answer without a block there.
        let settled =
            fetch.anchor().is_some() || first == cursor || piece.empty.iter().any(|p| *p != peer);
        if settled {
            piece.take(fetch, blocks);
            piece.settle_held(fetch);
        } else {
            if covers(&peers, peer, first) {
                piece.empty.insert(peer);
            }
            piece.held = Some((peer, blocks));
        }
    }
    Ok(())
}

/// No peer (or no attempt) is left for the piece's open slots: a held answer is kept with the
/// slots before it unconfirmed; else the rest of the piece is unconfirmed if anything was heard
/// of it, and the fetch fails if nothing was.
fn give_up<B: Linked>(
    piece: &mut Piece<B>,
    fetch: &mut RangeFetch<B>,
    start: Slot,
) -> Result<(), FetchError> {
    if let Some((_, blocks)) = piece.held.take() {
        let first = blocks.first().map_or(piece.end, Linked::slot);
        fetch.unconfirmed.push((piece.cursor, first));
        piece.take(fetch, blocks);
    } else if piece.cursor > start || !piece.empty.is_empty() {
        fetch.unconfirmed.push((piece.cursor, piece.end));
        piece.cursor = piece.end;
    } else {
        return Err(FetchError::NoPeer {
            slot: piece.cursor,
            failures: std::mem::take(&mut fetch.failures),
        });
    }
    Ok(())
}

/// Whether `peer`'s head, by its Status in `peers`, reaches the last slot before `target`: only
/// then does an answer without a block in `[.., target)` say the slots are empty.
fn covers(peers: &[(PeerId, StatusV2)], peer: PeerId, target: Slot) -> bool {
    peers
        .iter()
        .find(|(p, _)| *p == peer)
        .is_some_and(|(_, status)| status.head_slot >= target.saturating_sub(1))
}

/// The peer to ask for the blocks of `[slot, target)`: of the peers `skip` passes, those whose
/// `earliest_available_slot` is at or before `slot`. First those whose head reaches
/// `target - 1`, then those whose head reaches `slot` (a peer behind it is asked last); within
/// each, those asked fewer times in the piece (`asks`) first, then the highest `head_slot`, then
/// the lowest peer ID, so the choice is deterministic.
fn pick_peer(
    peers: &[(PeerId, StatusV2)],
    slot: Slot,
    target: Slot,
    skip: impl Fn(&PeerId) -> bool,
    asks: &HashMap<PeerId, usize>,
) -> Option<PeerId> {
    peers
        .iter()
        .filter(|(peer, status)| !skip(peer) && status.earliest_available_slot <= slot)
        .max_by_key(|(peer, status)| {
            (
                status.head_slot >= target.saturating_sub(1),
                status.head_slot >= slot,
                Reverse(asks.get(peer).copied().unwrap_or(0)),
                status.head_slot,
                Reverse(*peer),
            )
        })
        .map(|(peer, _)| *peer)
}

/// `blocks`, an answer for `[start, end)`, if their slots are inside it and strictly increase,
/// each is the child of the one before, and the first one is the child of `anchor`, the last
/// block fetched before.
fn fits<B: Linked>(
    anchor: Option<&B>,
    start: Slot,
    end: Slot,
    blocks: Vec<B>,
) -> Result<Vec<B>, RangeError> {
    let mut previous = None;
    for block in &blocks {
        check_slot(block.slot(), previous, start, end).map_err(OutboundError::InvalidBlocks)?;
        previous = Some(block.slot());
    }
    check_parent_links(&blocks).map_err(OutboundError::InvalidBlocks)?;
    if let (Some(anchor), Some(first)) = (anchor, blocks.first()) {
        let anchor = anchor.root();
        if first.parent_root() != anchor {
            return Err(RangeError::Disjoint {
                slot: first.slot(),
                parent_root: first.parent_root(),
                anchor,
            });
        }
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
pub(crate) fn outbound_failure(error: request_response::OutboundFailure) -> OutboundError {
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
    use proptest::strategy::Strategy as _;
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
            .send_request(&peer.id, Request::Status(ours()).into());
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

    // The probe's range requester: the production probe swarm (Control behind the outbound
    // semaphore) against scripted loopback peers. Mainnet preset: 32 slots per epoch, so
    // epoch 2 (slots 64..96) is Gloas on the fixture schedule and epoch 1 is Fulu.

    mod probe {
        use super::*;
        use crate::behaviour::{Behaviour, ProbeSpec};
        use crate::rpc::inbound::Control;
        use crate::testkit::{BlocksResponder, StatusPeer, StatusReply};
        use crate::transport::{build_swarm, MuxerBudget, SwarmConfig, TransportMetrics};
        use libp2p::identity::Keypair;
        use prometheus_client::registry::Registry;
        use std::time::Duration;

        pub type P = ProbeSpec;

        pub const WAIT: Duration = Duration::from_secs(20);

        /// Our Status: the fixture digest, finalized at epoch 1.
        pub fn status() -> StatusV2 {
            StatusV2 {
                fork_digest: OURS,
                finalized_root: B256::repeat_byte(1),
                finalized_epoch: 1,
                head_root: B256::repeat_byte(2),
                head_slot: 100,
                earliest_available_slot: 0,
            }
        }

        /// The block of the fixture chain at `slot`, its parent `parent`: Fulu before slot 64,
        /// Gloas from it.
        pub fn block(slot: Slot, parent: Root) -> forked::SignedBeaconBlock<P> {
            if slot < 64 {
                let mut b = testkit::fulu_block::<P>(slot);
                b.message.parent_root = parent;
                forked::SignedBeaconBlock::Fulu(b)
            } else {
                let mut b = testkit::gloas_block::<P>(slot);
                b.message.parent_root = parent;
                forked::SignedBeaconBlock::Gloas(b)
            }
        }

        /// One block per slot of `slots`, each the child of the one before.
        pub fn chain(slots: impl IntoIterator<Item = Slot>) -> Vec<forked::SignedBeaconBlock<P>> {
            let mut parent = B256::repeat_byte(0x77);
            slots
                .into_iter()
                .map(|slot| {
                    let b = block(slot, parent);
                    parent = block_root(&b);
                    b
                })
                .collect()
        }

        /// `block` on the wire under its epoch's fixture digest.
        pub fn wire(block: &forked::SignedBeaconBlock<P>) -> (ForkDigest, Vec<u8>) {
            let digest = fixture_digest(block.slot() / 32).unwrap();
            (digest, block.as_ssz_bytes())
        }

        /// A peer whose Status (ours, with `head_slot` and `earliest_available_slot` its own)
        /// is valid, answering BlocksByRange with `blocks`.
        pub async fn peer(head_slot: Slot, eas: Slot, blocks: BlocksResponder) -> StatusPeer {
            StatusPeer::spawn_with_blocks(
                Box::new(move |req, _| {
                    StatusReply::Status(StatusV2 {
                        head_slot,
                        earliest_available_slot: eas,
                        ..req.clone()
                    })
                }),
                None,
                None,
                Some(blocks),
                None,
            )
            .await
        }

        /// The probe swarm, connected to every peer of `peers`, each Status-valid.
        pub async fn probe(peers: &[&StatusPeer]) -> Swarm<Behaviour> {
            let mut registry = Registry::default();
            let transport = TransportMetrics::register(&mut registry);
            let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
            cfg.listen_addrs = Vec::new();
            cfg.idle_connection_timeout = WAIT;
            let (req_resp, _) = crate::testkit::control(
                &mut registry,
                crate::testkit::control_config(Some(status())),
            );
            let mut swarm = build_swarm(Keypair::generate_secp256k1(), &cfg, req_resp).unwrap();
            for p in peers {
                swarm.dial(p.addr.clone()).unwrap();
            }
            tokio::time::timeout(WAIT, async {
                while swarm.behaviour().req_resp.status_valid_peers().len() < peers.len() {
                    swarm.select_next_some().await;
                }
            })
            .await
            .expect("every peer Status-valid");
            swarm
        }

        pub fn control(swarm: &mut Swarm<Behaviour>) -> &mut Control<P> {
            &mut swarm.behaviour_mut().req_resp
        }
    }

    /// Each broken rule fails the whole response: no block of it is returned.
    #[tokio::test]
    async fn response_validation() {
        use probe::{chain, P};
        let good = chain(64..72);
        let wire_all = |blocks: &[forked::SignedBeaconBlock<P>]| -> BlocksReply {
            BlocksReply::Blocks(blocks.iter().map(probe::wire).collect())
        };
        // A slot outside [64, 72): a block of slot 72 after the chain.
        let out_of_range = {
            let mut blocks = chain(64..66);
            blocks.push(probe::block(72, block_root(&blocks[1])));
            wire_all(&blocks)
        };
        // The same slot twice.
        let non_increasing = {
            let first = probe::block(65, B256::repeat_byte(0x77));
            let again = probe::block(65, block_root(&first));
            wire_all(&[first, again])
        };
        // Three blocks for a request of two.
        let too_many = wire_all(&good[..3]);
        // A Gloas-epoch slot under the Fulu digest, in the Fulu shape: it decodes, but the
        // digest is not the one of the block's epoch.
        let wrong_digest = {
            let mut fulu = testkit::fulu_block::<P>(64);
            fulu.message.parent_root = B256::repeat_byte(0x77);
            BlocksReply::Blocks(vec![(testkit::FULU_DIGEST, fulu.as_ssz_bytes())])
        };
        // Slot 66 does not name slot 65's root as its parent.
        let broken_link = {
            let mut blocks = chain(64..66);
            blocks.push(probe::block(66, B256::repeat_byte(0x55)));
            wire_all(&blocks)
        };
        let valid = wire_all(&good);
        let replies = [
            out_of_range,
            non_increasing,
            too_many,
            wrong_digest,
            broken_link,
            valid,
        ];
        let peer = probe::peer(
            100,
            0,
            Box::new(move |_, n| replies[n.min(replies.len() - 1)].clone()),
        )
        .await;
        let mut swarm = probe::probe(&[&peer]).await;
        let mut ranges = RangeRequester::<P, _>::new(&mut swarm, &fixture_digest);

        let mut faults = Vec::new();
        let got = ranges.blocks_by_range(peer.id, 64, 8).await;
        assert!(
            matches!(
                got,
                Err(RangeError::Outbound(OutboundError::InvalidBlocks(
                    BlocksError::SlotOutOfRange {
                        slot: 72,
                        start: 64,
                        end: 72
                    }
                )))
            ),
            "{got:?}"
        );
        faults.push(got.unwrap_err());
        let got = ranges.blocks_by_range(peer.id, 64, 8).await;
        assert!(
            matches!(
                got,
                Err(RangeError::Outbound(OutboundError::InvalidBlocks(
                    BlocksError::NonIncreasingSlot {
                        slot: 65,
                        previous: 65
                    }
                )))
            ),
            "{got:?}"
        );
        faults.push(got.unwrap_err());
        let got = ranges.blocks_by_range(peer.id, 64, 2).await;
        assert!(
            matches!(
                got,
                Err(RangeError::Outbound(OutboundError::InvalidResponse(
                    ReadError::TooManyChunks { max: 2 }
                )))
            ),
            "{got:?}"
        );
        faults.push(got.unwrap_err());
        let got = ranges.blocks_by_range(peer.id, 64, 8).await;
        assert!(
            matches!(
                got,
                Err(RangeError::Outbound(OutboundError::InvalidBlocks(
                    BlocksError::WrongContextDigest {
                        slot: 64,
                        epoch: 2,
                        got: Some(testkit::FULU_DIGEST),
                        want: Some(testkit::GLOAS_DIGEST),
                    }
                )))
            ),
            "{got:?}"
        );
        faults.push(got.unwrap_err());
        let got = ranges.blocks_by_range(peer.id, 64, 8).await;
        match &got {
            Err(RangeError::Outbound(OutboundError::InvalidBlocks(
                e @ BlocksError::BrokenParentLink {
                    slot: 66,
                    previous_slot: 65,
                    ..
                },
            ))) => assert!(e.to_string().contains("slot 66"), "{e}"),
            other => panic!("{other:?}"),
        }
        faults.push(got.unwrap_err());
        // Every one of them is the peer's fault; the valid response then passes whole.
        assert_eq!(faults.len(), 5);
        assert!(faults.iter().all(RangeError::is_peer_fault), "{faults:?}");
        let blocks = ranges.blocks_by_range(peer.id, 64, 8).await.unwrap();
        assert_eq!(blocks, good);
        let sent: Vec<(Slot, u64, u64)> = peer
            .blocks_requests()
            .iter()
            .map(|r| (r.start_slot, r.count, r.step))
            .collect();
        assert_eq!(
            sent,
            [
                (64, 8, 1),
                (64, 8, 1),
                (64, 2, 1),
                (64, 8, 1),
                (64, 8, 1),
                (64, 8, 1)
            ]
        );
        // A request the protocol forbids is refused before it reaches the semaphore.
        let err = ranges.blocks_by_range(peer.id, 64, 129).await.unwrap_err();
        assert!(
            matches!(err, RangeError::Outbound(OutboundError::InvalidRequest(_))),
            "{err}"
        );
        assert!(!err.is_peer_fault());
        assert_eq!(peer.blocks_requests().len(), 6);
        // The peer stays connected and Status-valid: a broken response is not answered with a
        // disconnect here (scoring is the caller's).
        assert_eq!(ranges.range_peers().len(), 1);
        assert_eq!(probe::control(&mut swarm).status_valid_peers().len(), 1);
    }

    /// A peer that stops after 10 of the epoch's 32 blocks: the 10 are kept, the suffix comes
    /// from the second peer, and the epoch completes with no fault on either.
    #[tokio::test]
    async fn partial_then_retry() {
        use probe::{chain, wire, P};
        let epoch: Vec<_> = chain(64..96);
        let wire_epoch: Vec<(ForkDigest, Vec<u8>)> = epoch.iter().map(wire).collect();
        let serve = |stop_after: usize| -> crate::testkit::BlocksResponder {
            let all = wire_epoch.clone();
            Box::new(move |req, _| {
                let blocks = all
                    .iter()
                    .zip(64u64..)
                    .filter(|(_, slot)| (req.start_slot..req.start_slot + req.count).contains(slot))
                    .map(|(w, _)| w.clone())
                    .take(stop_after)
                    .collect();
                BlocksReply::Blocks(blocks)
            })
        };
        // The short peer has the higher head, so it is asked first.
        let short = probe::peer(200, 0, serve(10)).await;
        let full = probe::peer(100, 64, serve(usize::MAX)).await;
        // Its earliest_available_slot is after the epoch: never asked.
        let pruned = probe::peer(300, 96, serve(usize::MAX)).await;
        let mut swarm = probe::probe(&[&short, &full, &pruned]).await;
        let mut ranges = RangeRequester::<P, _>::new(&mut swarm, &fixture_digest);
        let fetched = fetch_epoch(&mut ranges, 2, 32).await.unwrap();

        assert_eq!(fetched.blocks.len(), 32);
        assert_eq!(fetched.blocks, epoch, "every slot, in order, linked");
        let first = |p: &StatusPeer| -> Vec<BlocksByRangeV2Request> { p.blocks_requests() };
        assert_eq!(
            first(&short),
            [BlocksByRangeV2Request {
                start_slot: 64,
                count: 32,
                step: 1
            }]
        );
        assert_eq!(
            first(&full),
            [BlocksByRangeV2Request {
                start_slot: 74,
                count: 22,
                step: 1
            }],
            "only the missing suffix"
        );
        assert!(first(&pruned).is_empty());
        // Asked directly, a range below its earliest_available_slot is refused, never sent.
        let err = ranges.blocks_by_range(pruned.id, 64, 32).await.unwrap_err();
        assert!(
            matches!(&err, RangeError::Outbound(OutboundError::InvalidRequest(m)) if m.contains("earliest_available_slot 96")),
            "{err}"
        );
        assert!(first(&pruned).is_empty());
        assert!(fetched.failures.is_empty(), "{:?}", fetched.failures);
        assert!(fetched.unconfirmed.is_empty());
        assert_eq!(
            fetched.requests,
            [
                (
                    short.id,
                    BlocksByRangeV2Request {
                        start_slot: 64,
                        count: 32,
                        step: 1
                    }
                ),
                (
                    full.id,
                    BlocksByRangeV2Request {
                        start_slot: 74,
                        count: 22,
                        step: 1
                    }
                ),
            ]
        );
    }

    // The epoch fetcher over a scripted source: no swarm, so every case is cheap enough for
    // a property test.

    mod scripted {
        use super::*;

        /// A block reduced to what the fetcher reads.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct Fake {
            pub slot: Slot,
            pub parent: Root,
        }

        pub fn root_of(slot: Slot) -> Root {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&slot.to_le_bytes());
            bytes[31] = 1;
            Root::from(bytes)
        }

        impl Linked for Fake {
            fn slot(&self) -> Slot {
                self.slot
            }
            fn root(&self) -> Root {
                root_of(self.slot)
            }
            fn parent_root(&self) -> Root {
                self.parent
            }
        }

        /// A chain with a block at every slot of `present`, each the child of the one before.
        pub fn chain(present: impl IntoIterator<Item = Slot>) -> Vec<Fake> {
            let mut parent = B256::repeat_byte(0x77);
            present
                .into_iter()
                .map(|slot| {
                    let b = Fake { slot, parent };
                    parent = b.root();
                    b
                })
                .collect()
        }

        /// How a scripted peer answers.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Answer {
            /// Every block of the range.
            Full,
            /// The first `n` (at least 1, as the spec requires) blocks of the range.
            StopAfter(usize),
            /// The request fails (a timeout, say): not the peer's fault.
            Fail,
            /// The first request fails, then every one is answered in full.
            FailOnce,
            /// A block outside the range: the peer's fault.
            Invalid,
            /// Blocks of another branch: the first is not linked to the ones before.
            OtherChain,
            /// Lies: no block at all.
            Empty,
            /// Lies: only the last block of the range, a real one.
            LastOnly,
            /// Only the last block of the range, on another branch.
            ForkLast,
        }

        pub struct Peer {
            pub id: PeerId,
            pub status: StatusV2,
            pub answer: Answer,
        }

        pub fn peer(head_slot: Slot, earliest_available_slot: Slot, answer: Answer) -> Peer {
            Peer {
                id: PeerId::random(),
                status: StatusV2 {
                    head_slot,
                    earliest_available_slot,
                    ..ours()
                },
                answer,
            }
        }

        pub struct Source {
            pub chain: Vec<Fake>,
            pub peers: Vec<Peer>,
            pub sent: Vec<(PeerId, BlocksByRangeV2Request)>,
        }

        impl RangeSource for Source {
            type Block = Fake;

            fn range_peers(&self) -> Vec<(PeerId, StatusV2)> {
                self.peers
                    .iter()
                    .map(|p| (p.id, p.status.clone()))
                    .collect()
            }

            fn request_range(
                &mut self,
                peer: PeerId,
                request: BlocksByRangeV2Request,
            ) -> impl std::future::Future<Output = Result<Vec<Fake>, RangeError>> {
                self.sent.push((peer, request));
                let (answer, head) = self
                    .peers
                    .iter()
                    .find(|p| p.id == peer)
                    .map_or((Answer::Fail, 0), |p| (p.answer, p.status.head_slot));
                let end = request.start_slot + request.count;
                // Each peer has the chain up to its own head.
                let in_range = self
                    .chain
                    .iter()
                    .filter(|b| (request.start_slot..end).contains(&b.slot) && b.slot <= head)
                    .copied();
                let asked_before = self.sent.iter().filter(|(p, _)| *p == peer).count() > 1;
                let result = match answer {
                    Answer::Full => Ok(in_range.collect()),
                    Answer::FailOnce if asked_before => Ok(in_range.collect()),
                    Answer::FailOnce => Err(OutboundError::Failure("timeout".into()).into()),
                    Answer::StopAfter(n) => Ok(in_range.take(n.max(1)).collect()),
                    Answer::Fail => Err(OutboundError::Failure("timeout".into()).into()),
                    Answer::Invalid => {
                        Err(OutboundError::InvalidBlocks(BlocksError::SlotOutOfRange {
                            slot: end,
                            start: request.start_slot,
                            end,
                        })
                        .into())
                    }
                    Answer::OtherChain => Ok(in_range
                        .enumerate()
                        .map(|(i, b)| match i {
                            0 => Fake {
                                parent: B256::repeat_byte(0x99),
                                ..b
                            },
                            _ => b,
                        })
                        .collect()),
                    Answer::Empty => Ok(Vec::new()),
                    Answer::LastOnly => Ok(in_range.last().into_iter().collect()),
                    Answer::ForkLast => Ok(in_range
                        .last()
                        .map(|b| Fake {
                            parent: B256::repeat_byte(0x99),
                            ..b
                        })
                        .into_iter()
                        .collect()),
                };
                std::future::ready(result)
            }
        }

        pub fn run(
            source: &mut Source,
            start: Slot,
            count: u64,
        ) -> Result<RangeFetch<Fake>, FetchError> {
            futures::executor::block_on(fetch_range(source, start, count))
        }
    }

    #[test]
    fn a_short_answer_is_confirmed_by_a_second_peer() {
        use scripted::{chain, peer, run, Answer, Source};
        // Slots 30 and 31 are empty: the first answer ends at 29, and the suffix [30, 32) is
        // empty once two different peers answered it with no block: the second peer, then the
        // first asked again.
        let mut source = Source {
            chain: chain(0..30),
            peers: vec![peer(50, 0, Answer::Full), peer(40, 0, Answer::Full)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 0, 32).unwrap();
        assert_eq!(fetched.blocks, chain(0..30));
        let sent: Vec<(PeerId, Slot, u64)> = source
            .sent
            .iter()
            .map(|(p, r)| (*p, r.start_slot, r.count))
            .collect();
        let (first, second) = (source.peers[0].id, source.peers[1].id);
        assert_eq!(sent, [(first, 0, 32), (second, 30, 2), (first, 30, 2)]);
        assert!(fetched.unconfirmed.is_empty() && fetched.failures.is_empty());

        // With one peer only, its empty answer is not enough: the suffix is kept as
        // unconfirmed, not failed.
        let mut source = Source {
            chain: chain(0..30),
            peers: vec![peer(50, 0, Answer::Full)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 0, 32).unwrap();
        assert_eq!(fetched.blocks.len(), 30);
        assert_eq!(fetched.unconfirmed, [(30, 32)]);
        // An empty epoch needs two empty answers too.
        let mut source = Source {
            chain: Vec::new(),
            peers: vec![peer(50, 0, Answer::Full), peer(40, 0, Answer::Full)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 0, 32).unwrap();
        assert!(fetched.blocks.is_empty() && fetched.unconfirmed.is_empty());
        assert_eq!(source.sent.len(), 2);
    }

    #[test]
    fn one_empty_answer_does_not_confirm_a_gap() {
        use scripted::{chain, peer, run, Answer, Source};
        // An honest peer stops after 10 of 32 blocks; a lying one answers the suffix with
        // nothing. The suffix is asked again, of the honest peer, until it is covered.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![
                peer(200, 0, Answer::StopAfter(10)),
                peer(100, 0, Answer::Empty),
            ],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(fetched.blocks, source.chain, "all 32 blocks");
        assert!(fetched.unconfirmed.is_empty());
        let (honest, liar) = (source.peers[0].id, source.peers[1].id);
        assert_eq!(
            source.sent[1],
            (
                liar,
                BlocksByRangeV2Request {
                    start_slot: 74,
                    count: 22,
                    step: 1
                }
            )
        );
        assert_eq!(
            source.sent[2],
            (
                honest,
                BlocksByRangeV2Request {
                    start_slot: 74,
                    count: 22,
                    step: 1
                }
            )
        );

        // A liar alone: its empty answer is one voice, so the range stays unconfirmed, never
        // silently empty.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![peer(100, 0, Answer::Empty)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert!(fetched.blocks.is_empty());
        assert_eq!(fetched.unconfirmed, [(64, 96)]);
    }

    #[test]
    fn a_behind_peers_empty_answer_settles_nothing() {
        use scripted::{chain, peer, run, Answer, Source};
        let range = |start_slot, count| BlocksByRangeV2Request {
            start_slot,
            count,
            step: 1,
        };
        // H stops after 10 blocks; two honest peers whose heads (50, 40) are before the range
        // truthfully have nothing in it. Their empty answers settle nothing: H is asked again.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![
                peer(200, 0, Answer::StopAfter(10)),
                peer(50, 0, Answer::Full),
                peer(40, 0, Answer::Full),
            ],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(fetched.blocks, source.chain, "all 32 blocks");
        assert!(fetched.unconfirmed.is_empty());
        let h = source.peers[0].id;
        assert_eq!(
            source.sent,
            [
                (h, range(64, 32)),
                (h, range(74, 22)),
                (h, range(84, 12)),
                (h, range(94, 2))
            ],
            "the peers behind the range are asked last, so never"
        );

        // A liar claiming head 300 answers empty, an honest peer at head 40 truthfully too:
        // only the liar's answer counts, and one is not enough.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![
                peer(300, 0, Answer::Empty),
                peer(200, 0, Answer::StopAfter(10)),
                peer(40, 0, Answer::Full),
            ],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(fetched.blocks, source.chain, "all 32 blocks");
        assert!(fetched.unconfirmed.is_empty());

        // A peer whose head is inside the gap covers only part of it: its empty answer to
        // [74, 96) does not count either, so with H alone the rest stays unconfirmed.
        let mut source = Source {
            chain: chain(64..74),
            peers: vec![peer(200, 0, Answer::Full), peer(80, 0, Answer::Full)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(fetched.blocks, source.chain);
        assert_eq!(fetched.unconfirmed, [(74, 96)]);

        // Peers that are all behind the range: nothing covers it.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![peer(50, 0, Answer::Full), peer(40, 0, Answer::Full)],
            sent: Vec::new(),
        };
        assert!(matches!(
            run(&mut source, 64, 32),
            Err(FetchError::NoPeer { slot: 64, .. })
        ));
    }

    #[test]
    fn peers_take_turns_and_an_unconfirmed_gap_breaks_no_later_link() {
        use scripted::{chain, peer, run, Answer, Source};
        // The highest head answers one block at a time. Its first block (5) is held, the
        // other peer confirms [0, 5) empty, and from then on both have been asked: the one
        // asked fewer times goes first, so the one-block peer does not use up the piece's
        // attempts while the other has the rest.
        let mut source = Source {
            chain: chain(5..128),
            peers: vec![
                peer(300, 0, Answer::StopAfter(1)),
                peer(200, 0, Answer::Full),
            ],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 0, 128).unwrap();
        assert_eq!(fetched.blocks, source.chain);
        assert!(fetched.unconfirmed.is_empty());
        assert_eq!(source.sent.len(), 4, "{:?}", source.sent);

        // [0, 128) ends with a gap only one peer answered (slots 100..128 empty to the one
        // covering peer, whose head is 140). The next piece is not held to link to block 99:
        // its blocks start at 130 after an unconfirmed gap, and they are kept.
        let mut slots: Vec<Slot> = (0..100).collect();
        slots.extend(130..140);
        let mut source = Source {
            chain: chain(slots),
            peers: vec![peer(140, 0, Answer::Full)],
            sent: Vec::new(),
        };
        // The chain's block 130 names 99 as its parent: make it name a block the peer
        // never served, as after a real gap.
        source.chain[100].parent = B256::repeat_byte(0x42);
        let fetched = run(&mut source, 0, 140).unwrap();
        assert_eq!(fetched.blocks, source.chain);
        assert_eq!(fetched.unconfirmed, [(100, 128), (128, 130)]);
        assert!(fetched.failures.is_empty(), "{:?}", fetched.failures);
    }

    #[test]
    fn a_peer_that_skips_the_start_is_not_trusted_alone() {
        use scripted::{chain, peer, run, Answer, Source};
        // The peer with the highest head answers [64, 96) with only the real block 95: the
        // slots before it are asked of the honest peer, and its blocks link up to 95.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![peer(200, 0, Answer::LastOnly), peer(100, 0, Answer::Full)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(fetched.blocks, source.chain, "all 32 blocks");
        assert!(fetched.unconfirmed.is_empty() && fetched.failures.is_empty());
        let (liar, honest) = (source.peers[0].id, source.peers[1].id);
        assert_eq!(
            source.sent,
            [
                (
                    liar,
                    BlocksByRangeV2Request {
                        start_slot: 64,
                        count: 32,
                        step: 1
                    }
                ),
                (
                    honest,
                    BlocksByRangeV2Request {
                        start_slot: 64,
                        count: 31,
                        step: 1
                    }
                ),
            ]
        );

        // Alone, its block is kept and the slots before it are unconfirmed.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![peer(200, 0, Answer::LastOnly)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(fetched.blocks, source.chain[31..]);
        assert_eq!(fetched.unconfirmed, [(64, 95)]);

        // A second peer that has no block before 95 either confirms the gap.
        let mut source = Source {
            chain: chain([80, 95]),
            peers: vec![
                peer(200, 0, Answer::LastOnly),
                peer(100, 81, Answer::Full),
                peer(90, 0, Answer::Empty),
            ],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 81, 15).unwrap();
        assert_eq!(fetched.blocks, source.chain[1..]);
        assert!(fetched.unconfirmed.is_empty());
        // A second answer whose blocks do not lead to the held one drops it, as another
        // branch's; the honest peer then serves the rest.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![
                peer(200, 0, Answer::ForkLast),
                peer(150, 0, Answer::StopAfter(3)),
                peer(100, 0, Answer::Full),
            ],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(fetched.blocks, source.chain);
        assert!(fetched.unconfirmed.is_empty());
        assert!(
            matches!(
                fetched.failures[..],
                [(p, RangeError::Disjoint { slot: 95, .. })] if p == source.peers[0].id
            ),
            "{:?}",
            fetched.failures
        );
    }

    #[test]
    fn an_endless_supply_of_faulty_peers_ends_the_fetch() {
        use scripted::{Answer, Fake};
        /// Fresh Status-valid peers on every look, each answering out of range.
        struct Endless {
            sent: usize,
        }
        impl RangeSource for Endless {
            type Block = Fake;
            fn range_peers(&self) -> Vec<(PeerId, StatusV2)> {
                (0..1000)
                    .map(|_| scripted::peer(100, 0, Answer::Invalid))
                    .map(|p| (p.id, p.status))
                    .collect()
            }
            fn request_range(
                &mut self,
                _: PeerId,
                request: BlocksByRangeV2Request,
            ) -> impl std::future::Future<Output = Result<Vec<Fake>, RangeError>> {
                self.sent += 1;
                let end = request.start_slot + request.count;
                std::future::ready(Ok(vec![Fake {
                    slot: end,
                    parent: B256::ZERO,
                }]))
            }
        }
        let mut source = Endless { sent: 0 };
        let err = futures::executor::block_on(fetch_range(&mut source, 0, 32)).unwrap_err();
        match err {
            FetchError::NoPeer { slot: 0, failures } => {
                assert_eq!(failures.len(), MAX_ATTEMPTS_PER_PIECE);
                assert!(failures.iter().all(|(_, e)| e.is_peer_fault()));
            }
            other => panic!("{other}"),
        }
        assert_eq!(source.sent, MAX_ATTEMPTS_PER_PIECE);
    }

    #[test]
    fn failed_and_faulty_peers_are_passed_over() {
        use scripted::{chain, peer, run, Answer, Source};
        let mut source = Source {
            chain: chain(0..32),
            peers: vec![
                peer(90, 0, Answer::Invalid),
                peer(80, 0, Answer::Fail),
                peer(75, 0, Answer::StopAfter(5)),
                peer(70, 0, Answer::OtherChain),
                peer(60, 0, Answer::Full),
            ],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 0, 32).unwrap();
        assert_eq!(fetched.blocks, chain(0..32));
        let ids: Vec<PeerId> = source.peers.iter().map(|p| p.id).collect();
        let failed: Vec<(PeerId, bool)> = fetched
            .failures
            .iter()
            .map(|(p, e)| (*p, e.is_peer_fault()))
            .collect();
        // The out-of-range answer is a fault, the timeout and the unlinked chain are not.
        assert_eq!(failed, [(ids[0], true), (ids[1], false), (ids[3], false)]);
        let disjoint = &fetched.failures[2].1;
        assert!(
            matches!(disjoint, RangeError::Disjoint { slot: 5, .. }),
            "{disjoint}"
        );
        assert!(disjoint.to_string().contains("slot 5"), "{disjoint}");
        assert_eq!(source.sent.len(), 5);

        // Nobody left to ask for a range no answer covered: the fetch fails with every failure,
        // the timed-out peer's second one included.
        let mut source = Source {
            chain: chain(0..32),
            peers: vec![peer(90, 0, Answer::Fail), peer(80, 40, Answer::Full)],
            sent: Vec::new(),
        };
        match run(&mut source, 0, 32) {
            Err(e @ FetchError::NoPeer { slot: 0, .. }) => {
                assert!(e.to_string().contains("slot 0"), "{e}");
                let FetchError::NoPeer { failures, .. } = e else {
                    unreachable!()
                };
                assert_eq!(failures.len(), 2);
            }
            other => panic!("{other:?}"),
        }
        let pruned = source.peers[1].id;
        assert!(
            source.sent.iter().all(|(p, _)| *p != pruned),
            "the pruned peer is never asked"
        );
    }

    #[test]
    fn a_covering_peer_that_timed_out_is_asked_again_after_the_others() {
        use scripted::{chain, peer, run, Answer, Source};
        let range = BlocksByRangeV2Request {
            start_slot: 64,
            count: 32,
            step: 1,
        };
        // The only peer with the blocks times out once; the other is behind the range. Once
        // the behind one was tried, the covering one is asked again, and answers.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![peer(200, 0, Answer::FailOnce), peer(40, 0, Answer::Full)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(fetched.blocks, source.chain);
        assert!(fetched.unconfirmed.is_empty());
        let (covering, behind) = (source.peers[0].id, source.peers[1].id);
        assert_eq!(
            source.sent,
            [(covering, range), (behind, range), (covering, range)]
        );
        assert!(matches!(
            fetched.failures[..],
            [(p, ref e)] if p == covering && !e.is_peer_fault()
        ));

        // Once only: a peer that keeps failing is not asked a third time for the same slots.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![peer(200, 0, Answer::Fail), peer(40, 0, Answer::Full)],
            sent: Vec::new(),
        };
        assert!(matches!(
            run(&mut source, 64, 32),
            Err(FetchError::NoPeer { slot: 64, ref failures }) if failures.len() == 2
        ));
        assert_eq!(source.sent.len(), 3);

        // A failed peer whose head is short of the slots asked for is not asked again.
        let mut source = Source {
            chain: chain(64..96),
            peers: vec![peer(80, 0, Answer::Fail), peer(200, 0, Answer::Empty)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 64, 32).unwrap();
        assert_eq!(source.sent.len(), 2, "{:?}", source.sent);
        assert_eq!(fetched.unconfirmed, [(64, 96)]);

        // Only a failure that may pass is worth a second request: not a fault, nor an answer
        // of another branch.
        let timeout = RangeError::from(OutboundError::Failure("timeout".into()));
        assert!(timeout.may_pass());
        assert!(RangeError::Ignored.may_pass());
        assert!(!RangeError::Disjoint {
            slot: 5,
            parent_root: B256::ZERO,
            anchor: B256::ZERO,
        }
        .may_pass());
        let fault = OutboundError::InvalidBlocks(BlocksError::NonIncreasingSlot {
            slot: 1,
            previous: 1,
        });
        assert!(!RangeError::from(fault).may_pass());
    }

    #[test]
    fn ranges_are_split_at_the_request_cap() {
        use scripted::{chain, peer, run, Answer, Source};
        let mut source = Source {
            chain: chain(100..400),
            peers: vec![peer(500, 0, Answer::Full)],
            sent: Vec::new(),
        };
        let fetched = run(&mut source, 100, 300).unwrap();
        assert_eq!(fetched.blocks, chain(100..400));
        let sent: Vec<(Slot, u64)> = source
            .sent
            .iter()
            .map(|(_, r)| (r.start_slot, r.count))
            .collect();
        assert_eq!(sent, [(100, 128), (228, 128), (356, 44)]);
        // A later piece's first block must name the earlier piece's last as its parent.
        assert_eq!(fetched.blocks[128].parent, fetched.blocks[127].root());

        for (start, count) in [(0, 0), (u64::MAX, 2)] {
            let err = run(&mut source, start, count).unwrap_err();
            assert!(matches!(err, FetchError::InvalidRange { .. }), "{err}");
        }
        let err = futures::executor::block_on(fetch_epoch(&mut source, u64::MAX, 32)).unwrap_err();
        assert!(matches!(err, FetchError::InvalidRange { .. }), "{err}");
        let fetched = futures::executor::block_on(fetch_epoch(&mut source, 4, 32)).unwrap();
        assert_eq!(fetched.blocks, source.chain[28..60], "slots 128..160");
    }

    /// One generated fetch: the range, which slots hold a block, and the peers.
    #[derive(Debug, Clone)]
    struct FetchCase {
        start: Slot,
        count: u64,
        present: Vec<bool>,
        /// `(earliest_available_slot, head_slot, answer)` of peers that have the chain up to
        /// their head and never lie.
        others: Vec<(Slot, Slot, scripted::Answer)>,
        /// How far past the range's last slot the honest peer's head is.
        honest_ahead: u64,
        honest_eas: u64,
        /// [`scripted::Answer::Full`], or [`scripted::Answer::Fail`] for a peer that times out.
        honest: scripted::Answer,
        /// A peer that lies by omission, if any.
        liar: Option<(Slot, Slot, scripted::Answer)>,
    }

    /// The properties of [`count_cap_proptest`] for one case.
    fn check_fetch(case: &FetchCase) -> Result<(), proptest::test_runner::TestCaseError> {
        use proptest::prelude::*;
        use scripted::{chain, peer, Answer, Source};
        let (start, count) = (case.start, case.count);
        let slots = (0u64..)
            .zip(&case.present)
            .filter(|(_, p)| **p)
            .map(|(s, _)| s);
        let mut peers: Vec<_> = case
            .others
            .iter()
            .map(|&(eas, head, answer)| peer(head, eas, answer))
            .collect();
        // The honest peer's head is at or past the range's last slot; the others' heads are
        // anywhere, so some are behind it and have only part of the range.
        let honest_head = start + count - 1 + case.honest_ahead;
        peers.push(peer(
            honest_head,
            case.honest_eas % (start + 1),
            case.honest,
        ));
        peers.extend(case.liar.map(|(eas, head, answer)| peer(head, eas, answer)));
        let mut source = Source {
            chain: chain(slots),
            peers,
            sent: Vec::new(),
        };
        let fetched = scripted::run(&mut source, start, count);
        let end = start + count;
        for (peer, request) in &source.sent {
            prop_assert!(
                (1..=MAX_REQUEST_BLOCKS_DENEB).contains(&request.count),
                "{request:?}"
            );
            prop_assert_eq!(request.step, 1);
            prop_assert!(request.start_slot >= start && request.start_slot + request.count <= end);
            let eas = source
                .peers
                .iter()
                .find(|p| p.id == *peer)
                .unwrap()
                .status
                .earliest_available_slot;
            prop_assert!(
                request.start_slot >= eas,
                "{request:?} to a peer from {eas}"
            );
        }
        let honest = case.honest == Answer::Full;
        let fetched = match fetched {
            Ok(fetched) => fetched,
            // With the honest peer timing out, there may be nobody to ask.
            Err(FetchError::NoPeer { .. }) if !honest => return Ok(()),
            Err(e) => return Err(TestCaseError::fail(format!("{e}"))),
        };
        let want: Vec<_> = source
            .chain
            .iter()
            .filter(|b| (start..end).contains(&b.slot))
            .copied()
            .collect();
        for b in want.iter().filter(|b| !fetched.blocks.contains(b)) {
            prop_assert!(
                fetched
                    .unconfirmed
                    .iter()
                    .any(|&(from, to)| (from..to).contains(&b.slot)),
                "slot {} missing outside {:?}",
                b.slot,
                fetched.unconfirmed
            );
        }
        prop_assert!(fetched.blocks.iter().all(|b| want.contains(b)));
        if case.liar.is_none() {
            prop_assert!(fetched.failures.iter().all(|(_, e)| !e.is_peer_fault()));
            if honest {
                prop_assert_eq!(fetched.blocks, want);
            }
        }
        Ok(())
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Any range, any chain, peers that stop early, fail, are pruned or are behind (they
        /// have the chain up to their head only), an honest peer that has the whole range but
        /// may time out, and at most one peer that lies by omission: every request the fetcher
        /// sends has `count` 1 to 128 and `step` 1, lies inside the range and starts at or after
        /// its peer's `earliest_available_slot`. Every block of the chain the result lacks is
        /// inside an `unconfirmed` range; with the honest peer answering and no liar, the blocks
        /// are exactly the chain's.
        ///
        /// The timing-out honest peer is what lets a liar and a peer behind the range be the
        /// only two answers for a gap, so the head rule (`covers`) is tested here too
        /// ([`a_liar_and_a_behind_peer_settle_nothing`] is that case on its own).
        #[test]
        fn count_cap_proptest(
            start in 0u64..400,
            count in 1u64..400,
            present in proptest::collection::vec(proptest::bool::weighted(0.8), 800),
            others in proptest::collection::vec(
                (0u64..900, 0u64..1000, proptest::prop_oneof![
                    proptest::strategy::Just(scripted::Answer::Full),
                    proptest::strategy::Just(scripted::Answer::Fail),
                    (1usize..12).prop_map(scripted::Answer::StopAfter),
                ]),
                0..4,
            ),
            honest_ahead in 0u64..200,
            honest_eas in proptest::num::u64::ANY,
            honest in proptest::prop_oneof![
                3 => proptest::strategy::Just(scripted::Answer::Full),
                1 => proptest::strategy::Just(scripted::Answer::Fail),
            ],
            liar in proptest::option::of((0u64..900, 0u64..1000, proptest::prop_oneof![
                proptest::strategy::Just(scripted::Answer::Empty),
                proptest::strategy::Just(scripted::Answer::LastOnly),
            ])),
        ) {
            check_fetch(&FetchCase {
                start,
                count,
                present,
                others,
                honest_ahead,
                honest_eas,
                honest,
                liar,
            })?;
        }
    }

    /// The head rule on its own: the honest peer times out, a liar claiming a head past the
    /// range answers it empty, and so does a peer whose head is behind it. Only the liar's
    /// empty answer counts, and one is not enough: the range stays unconfirmed. With `covers`
    /// always `true`, the two would settle it as empty.
    #[test]
    fn a_liar_and_a_behind_peer_settle_nothing() {
        use scripted::Answer;
        let case = FetchCase {
            start: 64,
            count: 32,
            present: vec![true; 128],
            others: vec![(0, 40, Answer::Full)],
            honest_ahead: 100,
            honest_eas: 0,
            honest: Answer::Fail,
            liar: Some((0, 900, Answer::Empty)),
        };
        if let Err(e) = check_fetch(&case) {
            panic!("{e}");
        }
    }

    #[test]
    fn schedule_digests_follow_the_bpo_schedule() {
        use network_config::digest::{compute_fork_digest, digest_schedule};
        use network_config::{ChainConfig, Network};
        for network in [Network::Sepolia, Network::Hoodi] {
            let config = ChainConfig::load(network).unwrap();
            // Hoodi has no pinned genesis here: any root gives the schedule's shape.
            let gvr = network
                .genesis()
                .map_or([0x42; 32], |g| g.genesis_validators_root);
            let schedule = digest_schedule(&config, &gvr);
            assert!(
                schedule.len() > 1,
                "{network:?}: Fulu and a BPO epoch at least"
            );
            let digests = ScheduleDigests::new(&schedule);
            for entry in &schedule {
                for epoch in [entry.epoch.saturating_sub(1), entry.epoch, entry.epoch + 1] {
                    assert_eq!(
                        digests.digest_at(epoch),
                        compute_fork_digest(&config, &gvr, epoch).ok(),
                        "{network:?} epoch {epoch}"
                    );
                }
            }
            assert_eq!(
                digests.digest_at(schedule[0].epoch - 1),
                None,
                "before Fulu"
            );
            let last = schedule.last().unwrap();
            assert_eq!(digests.digest_at(u64::MAX), Some(last.fork_digest));
            // Entries in any order give the same answers.
            let mut reversed = schedule.clone();
            reversed.reverse();
            assert_eq!(ScheduleDigests::new(&reversed), digests);
        }
    }

    #[test]
    fn parent_links_and_slots_are_checked_on_any_source() {
        use scripted::{chain, Fake};
        let blocks = chain([3, 5, 6]);
        assert!(check_parent_links(&blocks).is_ok());
        assert!(check_parent_links::<Fake>(&[]).is_ok());
        let mut broken = blocks.clone();
        broken[2].parent = B256::repeat_byte(9);
        assert!(matches!(
            check_parent_links(&broken),
            Err(BlocksError::BrokenParentLink {
                slot: 6,
                previous_slot: 5,
                ..
            })
        ));
        // A source handing back blocks outside its request, or out of order, is refused by the
        // fetcher too: a fault.
        for (bad, start, end) in [(chain([3, 9]), 3, 9), (vec![blocks[1], blocks[0]], 3, 9)] {
            let err = fits(None, start, end, bad).unwrap_err();
            assert!(err.is_peer_fault(), "{err}");
        }
        assert!(fits(Some(&blocks[0]), 4, 9, blocks[1..].to_vec()).is_ok());
        assert!(matches!(
            fits(Some(&blocks[1]), 4, 9, blocks[1..].to_vec()),
            Err(RangeError::Disjoint { slot: 5, .. })
        ));
        assert!(RangeError::Ignored.to_string().contains("ignored"));
        assert!(!RangeError::Ignored.is_peer_fault());
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
