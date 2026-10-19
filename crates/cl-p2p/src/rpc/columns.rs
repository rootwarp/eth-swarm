//! Where the probe's column answers come from: cl-chain, which owns the column store.
//!
//! cl-p2p opens no database. A peer's `DataColumnSidecarsByRange` or `DataColumnSidecarsByRoot`
//! request (`fulu/p2p-interface.md` L605–775) goes to a [`ColumnSource`]; in the service that is
//! [`ChainColumns`], the `ethswarm.chain.v1.ReqRespService` client (`DataColumnsByRange`,
//! `DataColumnsByRoot`), whose server reads `cl-chain-columns`
//! (`cl_chain::reqresp::{columns_by_range, columns_by_root}`). The source answers with the stored
//! sidecars in the order they go out ([`ColumnReply::Sidecars`]), each with the fork digest of
//! its slot's epoch, or with the error chunk the request gets ([`ColumnReply::Refused`]).
//! [`super::inbound::Control`] decodes each sidecar by that fork before it goes out.
//!
//! # The chain.v1 stream
//!
//! [`ChainColumns`] sends the request with our hello in-line and reads the response through the
//! `ipc` contract layer ([`Link::open`] on [`Inbound::from_server`]): the server's hello first,
//! then one chunk per body, every envelope's `seq` strictly from 1 and its fork digest checked
//! against the fork of its slot ([`Link::check_envelope`]). A contract error, or an envelope
//! dropped by those checks (an unknown type, a digest mismatch: never decoded), fails the whole
//! answer as `2: ServerError`: a column the probe cannot vouch for would leave a block
//! incomplete, which the protocol forbids (L672–673). Past the first block, the client stops
//! reading once the sidecars would pass `max_bytes`, and the answer is then cut at a whole block
//! ([`column_chunks`]), the rule cl-chain cuts by too. An error chunk is
//! mapped by its code: `ERROR_CODE_RESOURCE_UNAVAILABLE` to `3: ResourceUnavailable`,
//! `ERROR_CODE_INVALID` to `1: InvalidRequest`, anything else to `2: ServerError`. A cl-chain
//! that cannot be reached is `2: ServerError` too, never an empty success.
//!
//! # The answer ([`column_chunks`])
//!
//! Whatever the source hands over is held to the request before it goes out: each sidecar is
//! decoded by the fork its context digest names (the fork of its slot) and must be at its slot
//! and of its root (Gloas: `beacon_block_root`; Fulu: the root of its block header), else the
//! whole answer is `2: ServerError`. A sidecar the
//! request did not name, or named once and got twice, is dropped and counted
//! (`rpc_column_unrequested_total`). The answer is then cut at the last whole block within the
//! sidecars the requester's quota delivers in the answer window, within the byte budget, and
//! read by the end of the window by a requester reading at the answer's pace from when the
//! lookup ended, given when each chunk's token is due ([`PacedReader`]), the first block always
//! in, and cut again the same way from when its writer starts (`block_lengths`); a range
//! answer whose first block lacks a requested column is `2: ServerError` (cl-chain never sends
//! one), and so is one whose first block holds more sidecars than were booked (the booking
//! holds the largest block a request names, `Requested::largest_block`), so no chunk goes out
//! unpaid. Error chunks carry a fixed message per code ([`fixed_message`]); the source's detail
//! goes to the log only.

use super::codec::ReceivedChunk;
use super::limits::PacedReader;
use super::metrics::RpcMetrics;
use consensus_types::{forked, EthSpec};
use ethswarm_proto::chain as pb;
use ethswarm_proto::common::{ErrorCode, PayloadType};
use futures::Stream;
use ipc::envelope::Envelopes;
use ipc::frame::{InFrame, Inbound};
use ipc::Link;
use network_config::ForkName;
use p2p_wire::rpc::codec::ContextTable;
use p2p_wire::rpc::messages::ErrorMessage;
use p2p_wire::rpc::messages::{
    DataColumnsByRangeV1Request, DataColumnsByRootV1Request, ForkDigest,
};
use p2p_wire::rpc::protocols::{Request, Response, ResponseChunk, ResultCode};
use pb::req_resp_service_client::ReqRespServiceClient;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use tonic::transport::Channel;
use tonic::Status;
use tree_hash::TreeHash;

/// One stored sidecar as the source hands it over: its SSZ, the fork of its slot and the
/// digest of its slot's epoch, which go out as the chunk's context bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedColumn {
    /// The fork digest of the epoch of the sidecar's slot.
    pub context: ForkDigest,
    /// The fork of the sidecar's slot: the shape it is decoded with.
    pub fork: ForkName,
    /// The sidecar's slot.
    pub slot: u64,
    /// The sidecar's block root.
    pub block_root: [u8; 32],
    /// The sidecar's SSZ, as stored.
    pub ssz: Vec<u8>,
}

/// A source's answer to one column request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnReply {
    /// The sidecars, in the order they go out; none is an empty success.
    Sidecars(Vec<ServedColumn>),
    /// The request gets this error chunk (never [`ResultCode::Success`]).
    Refused(ResultCode, String),
}

impl ColumnReply {
    /// `2: ServerError` with `why`.
    #[must_use]
    pub fn server_error(why: impl Into<String>) -> Self {
        Self::Refused(ResultCode::ServerError, why.into())
    }
}

/// One column lookup in flight.
pub type ColumnLookup = Pin<Box<dyn Future<Output = ColumnReply> + Send>>;

/// Answers the column requests of peers (see the module docs). Each call starts one lookup;
/// [`super::inbound::Control`] bounds how many are open and how long each may take.
pub trait ColumnSource: Send + Sync + 'static {
    /// The stored sidecars of `request`, in `(slot, column_index)` order.
    fn by_range(&self, request: &DataColumnsByRangeV1Request) -> ColumnLookup;

    /// The stored sidecars of `request`'s identifiers.
    fn by_root(&self, request: &DataColumnsByRootV1Request) -> ColumnLookup;
}

/// The `ethswarm.chain.v1.ReqRespService` client: our [`ColumnSource`] in the service.
#[derive(Clone, Debug)]
pub struct ChainColumns {
    client: ReqRespServiceClient<Channel>,
    link: Link,
    max_bytes: usize,
}

impl ChainColumns {
    /// A source asking cl-chain over `channel`, holding its streams to `link` (our hello, the
    /// fork schedule and digests), and at most `max_bytes` of sidecar SSZ per answer
    /// ([`super::limits::MAX_COLUMN_RESPONSE_BYTES`]).
    #[must_use]
    pub fn new(channel: Channel, link: Link, max_bytes: usize) -> Self {
        Self {
            client: ReqRespServiceClient::new(channel),
            link,
            max_bytes,
        }
    }
}

impl ColumnSource for ChainColumns {
    fn by_range(&self, request: &DataColumnsByRangeV1Request) -> ColumnLookup {
        let mut client = self.client.clone();
        let (link, max_bytes) = (self.link.clone(), self.max_bytes);
        let request = pb::DataColumnsByRangeRequest {
            start_slot: request.start_slot,
            count: request.count,
            columns: request.columns.to_vec(),
            hello: Some(link.local().clone()),
        };
        Box::pin(async move {
            match client.data_columns_by_range(request).await {
                Ok(stream) => read_answer(&link, stream.into_inner(), max_bytes).await,
                Err(status) => unreachable_chain(&status),
            }
        })
    }

    fn by_root(&self, request: &DataColumnsByRootV1Request) -> ColumnLookup {
        let mut client = self.client.clone();
        let (link, max_bytes) = (self.link.clone(), self.max_bytes);
        let request = pb::DataColumnsByRootRequest {
            ids: request
                .0
                .iter()
                .map(|id| pb::DataColumnsByRootIdentifier {
                    block_root: id.block_root.to_vec(),
                    columns: id.columns.to_vec(),
                })
                .collect(),
            hello: Some(link.local().clone()),
        };
        Box::pin(async move {
            match client.data_columns_by_root(request).await {
                Ok(stream) => read_answer(&link, stream.into_inner(), max_bytes).await,
                Err(status) => unreachable_chain(&status),
            }
        })
    }
}

/// The call failed before its stream opened: cl-chain is down, refused the call, or failed it.
fn unreachable_chain(status: &Status) -> ColumnReply {
    tracing::debug!(code = ?status.code(), message = status.message(), "column lookup failed");
    ColumnReply::server_error("column store unavailable")
}

/// The one chunk a column response body carries.
trait ChunkBody {
    fn into_item(self) -> Option<pb::ResponseChunk>;
}

impl ChunkBody for pb::DataColumnsByRangeResponseBody {
    fn into_item(self) -> Option<pb::ResponseChunk> {
        self.item
    }
}

impl ChunkBody for pb::DataColumnsByRootResponseBody {
    fn into_item(self) -> Option<pb::ResponseChunk> {
        self.item
    }
}

/// The wire result code of cl-chain's error chunk.
fn result_code(code: i32) -> ResultCode {
    match ErrorCode::try_from(code) {
        Ok(ErrorCode::ResourceUnavailable) => ResultCode::ResourceUnavailable,
        Ok(ErrorCode::Invalid) => ResultCode::InvalidRequest,
        _ => ResultCode::ServerError,
    }
}

/// Reads cl-chain's column response stream (see the module docs).
async fn read_answer<S, T>(link: &Link, stream: S, max_bytes: usize) -> ColumnReply
where
    S: Stream<Item = Result<T, Status>> + Unpin,
    T: InFrame,
    T::Body: Envelopes + ChunkBody,
{
    let mut guarded = match link.open(Inbound::from_server(stream)).await {
        Ok(guarded) => guarded,
        Err(e) => return ColumnReply::server_error(format!("column stream: {}", e.detail())),
    };
    let mut sidecars: Vec<ServedColumn> = Vec::new();
    let mut bytes = 0usize;
    loop {
        let accepted = match guarded.body().await {
            Ok(Some(accepted)) => accepted,
            Ok(None) => return ColumnReply::Sidecars(sidecars),
            Err(e) => return ColumnReply::server_error(format!("column stream: {}", e.detail())),
        };
        if let Some((_, reason)) = accepted.dropped.first() {
            return ColumnReply::server_error(format!("column dropped: {reason}"));
        }
        let envelope = match accepted.body.into_item().and_then(|item| item.result) {
            Some(pb::response_chunk::Result::Chunk(envelope)) => envelope,
            Some(pb::response_chunk::Result::Error(e)) => {
                return ColumnReply::Refused(result_code(e.code), e.detail);
            }
            // `Envelopes::check_shape` refuses a chunk with neither.
            None => return ColumnReply::server_error("an empty column chunk"),
        };
        if envelope.payload_type != PayloadType::DataColumnSidecar as i32 {
            return ColumnReply::server_error(format!(
                "payload_type {} in a column answer",
                envelope.payload_type
            ));
        }
        // Passed above; read again for the fork of its slot.
        let fork = match link.check_envelope(&envelope) {
            Ok(checked) => checked.fork,
            Err(e) => return ColumnReply::server_error(format!("column envelope: {e}")),
        };
        let Ok(context) = ForkDigest::try_from(envelope.fork_digest.as_slice()) else {
            return ColumnReply::server_error("a column envelope without a 4-byte digest");
        };
        let Ok(block_root) = <[u8; 32]>::try_from(envelope.root.as_slice()) else {
            return ColumnReply::server_error("a column envelope without a 32-byte root");
        };
        let first_block = sidecars
            .first()
            .is_none_or(|first| (first.slot, first.block_root) == (envelope.slot, block_root));
        bytes = bytes.saturating_add(envelope.ssz.len());
        if bytes > max_bytes && !first_block {
            // Hold no more: the answer is cut at a whole block before this one.
            return ColumnReply::Sidecars(sidecars);
        }
        sidecars.push(ServedColumn {
            context,
            fork,
            slot: envelope.slot,
            block_root,
            ssz: envelope.ssz,
        });
    }
}

/// The message an error chunk of `code` goes out with: fixed, so no store, contract or peer
/// detail leaves the probe.
#[must_use]
pub fn fixed_message(code: ResultCode) -> &'static str {
    match code {
        ResultCode::InvalidRequest => "invalid request",
        ResultCode::ResourceUnavailable => "resource unavailable",
        ResultCode::ServerError | ResultCode::Success => "server error",
    }
}

/// The one error chunk of `code`, with its fixed message.
pub(crate) fn error_answer<E: EthSpec>(code: ResultCode) -> Vec<ReceivedChunk<E>> {
    let code = match code {
        ResultCode::Success => ResultCode::ServerError,
        other => other,
    };
    let message = ErrorMessage::new(fixed_message(code).as_bytes().to_vec()).unwrap_or_default();
    vec![ReceivedChunk {
        context: None,
        chunk: ResponseChunk::Error { code, message },
    }]
}

/// What a column request named: the sidecars an answer may hold.
pub(crate) enum Requested {
    /// `[start, end)` and the columns of each slot.
    Range {
        start: u64,
        end: u64,
        columns: BTreeSet<u64>,
    },
    /// The `(root, index)` pairs.
    Root(HashSet<([u8; 32], u64)>),
}

impl Requested {
    /// What `request` names; `None` for a request that is not a column request.
    pub(crate) fn of(request: &Request) -> Option<Self> {
        Some(match request {
            Request::DataColumnsByRange(r) => Requested::Range {
                start: r.start_slot,
                end: r.start_slot.saturating_add(r.count),
                columns: r.columns.iter().copied().collect(),
            },
            Request::DataColumnsByRoot(r) => Requested::Root(
                r.0.iter()
                    .flat_map(|id| id.columns.iter().map(move |&i| (id.block_root.0, i)))
                    .collect(),
            ),
            _ => return None,
        })
    }

    fn names(&self, slot: u64, root: &[u8; 32], index: u64) -> bool {
        match self {
            Requested::Range {
                start,
                end,
                columns,
            } => (*start..*end).contains(&slot) && columns.contains(&index),
            Requested::Root(pairs) => pairs.contains(&(*root, index)),
        }
    }

    /// The most sidecars one block of the answer can hold: the requested columns of a range;
    /// for roots, the columns named for one root over every identifier naming it, each once.
    pub(crate) fn largest_block(&self) -> u64 {
        match self {
            Requested::Range { columns, .. } => columns.len() as u64,
            Requested::Root(pairs) => {
                let mut per_root: HashMap<&[u8; 32], u64> = HashMap::new();
                for (root, _) in pairs {
                    *per_root.entry(root).or_default() += 1;
                }
                per_root.into_values().max().unwrap_or(0)
            }
        }
    }

    /// The sidecars every block of the answer must hold: the requested columns of a range.
    fn per_block(&self) -> Option<usize> {
        match self {
            Requested::Range { columns, .. } => Some(columns.len()),
            Requested::Root(_) => None,
        }
    }
}

/// What a lookup of column `request` costs its peer however little it finds, in tokens: one per
/// identifier that names a column (the store looks its root up), one for a range (one read of
/// it). Never more than the sidecars the request names.
pub(crate) fn lookup_cost(request: &Request) -> u64 {
    match request {
        Request::DataColumnsByRoot(r) => {
            r.0.iter().filter(|id| !id.columns.is_empty()).count() as u64
        }
        _ => 1,
    }
}

/// How much one column answer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AnswerBudget {
    /// Sidecars: what the requester's quota delivers in the answer window, and no more than
    /// requested.
    pub(crate) max_sidecars: u64,
    /// SSZ bytes.
    pub(crate) max_bytes: usize,
}

/// A decoded sidecar on its way out, with its block.
struct Outgoing<E: EthSpec> {
    block: (u64, [u8; 32]),
    bytes: usize,
    chunk: ReceivedChunk<E>,
}

/// The chunks of a source's answer to `requested` and their SSZ bytes (see the module docs).
pub(crate) fn column_chunks<E: EthSpec>(
    reply: ColumnReply,
    requested: &Requested,
    contexts: &ContextTable,
    budget: AnswerBudget,
    reader: &PacedReader<'_>,
    metrics: &RpcMetrics,
) -> (Vec<ReceivedChunk<E>>, usize) {
    let refuse = |why: String| {
        tracing::warn!(%why, "column answer refused");
        (error_answer(ResultCode::ServerError), 0)
    };
    let sidecars = match reply {
        ColumnReply::Sidecars(sidecars) => sidecars,
        ColumnReply::Refused(code, why) => {
            tracing::debug!(?code, %why, "column request refused");
            return (error_answer(code), 0);
        }
    };
    let Some(network) = contexts.network_caps() else {
        return refuse("no network caps to read column sidecars with".into());
    };
    let mut seen = HashSet::new();
    let mut unrequested = 0u64;
    let mut outgoing: Vec<Outgoing<E>> = Vec::with_capacity(sidecars.len());
    for served in sidecars {
        if contexts.fork(&served.context) != Some(served.fork) {
            return refuse(format!(
                "context {:02x?} does not name {:?}",
                served.context, served.fork
            ));
        }
        let decoded = match forked::DataColumnSidecar::<E>::from_ssz_bytes_for_fork_with(
            &served.ssz,
            served.fork,
            network,
        ) {
            Ok(decoded) => decoded,
            Err(e) => return refuse(format!("a stored sidecar does not decode: {e}")),
        };
        if decoded.slot() != served.slot {
            return refuse(format!(
                "a sidecar of slot {} served as slot {}",
                decoded.slot(),
                served.slot
            ));
        }
        let index = match &decoded {
            forked::DataColumnSidecar::Fulu(s) => {
                if s.signed_block_header.message.tree_hash_root().0 != served.block_root {
                    return refuse("a sidecar served under another block root".into());
                }
                s.index
            }
            forked::DataColumnSidecar::Gloas(s) => {
                if s.beacon_block_root.0 != served.block_root {
                    return refuse("a sidecar served under another block root".into());
                }
                s.index
            }
        };
        if !requested.names(served.slot, &served.block_root, index)
            || !seen.insert((served.block_root, index))
        {
            unrequested += 1;
            continue;
        }
        outgoing.push(Outgoing {
            block: (served.slot, served.block_root),
            bytes: served.ssz.len(),
            chunk: ReceivedChunk {
                context: Some(served.context),
                chunk: ResponseChunk::Success(Response::DataColumn(Box::new(decoded))),
            },
        });
    }
    if unrequested > 0 {
        metrics.unrequested(unrequested);
        tracing::warn!(unrequested, "unrequested column sidecars dropped");
    }
    // Whole blocks, up to the first one that lacks a requested column.
    let mut blocks = Vec::new();
    let mut at = 0usize;
    while at < outgoing.len() {
        let block = outgoing[at].block;
        let len = outgoing[at..]
            .iter()
            .position(|o| o.block != block)
            .unwrap_or(outgoing.len() - at);
        if requested.per_block().is_some_and(|n| n != len) {
            if blocks.is_empty() {
                return refuse(format!(
                    "the first block, at slot {}, lacks requested columns",
                    block.0
                ));
            }
            break;
        }
        blocks.push(len);
        at += len;
    }
    // The first block always goes, so it must be paid for: the booking holds the most sidecars
    // one block of the request can have ([`Requested::largest_block`]).
    if let Some(&first) = blocks.first() {
        if first as u64 > budget.max_sidecars {
            return refuse(format!(
                "the first block holds {first} sidecars, {} booked",
                budget.max_sidecars
            ));
        }
    }
    // The first block, then while within the budget and read in the window.
    let sizes: Vec<usize> = outgoing.iter().map(|o| o.bytes).collect();
    let (keep, bytes) = reader.whole_blocks(&sizes, &blocks, budget.max_sidecars, budget.max_bytes);
    outgoing.truncate(keep);
    (outgoing.into_iter().map(|o| o.chunk).collect(), bytes)
}

/// The block a column answer's chunk carries a sidecar of: its slot and block root (Gloas:
/// `beacon_block_root`; Fulu: the root of its block header), `None` for any other chunk.
fn block_of<E: EthSpec>(chunk: &ReceivedChunk<E>) -> Option<(u64, [u8; 32])> {
    let ResponseChunk::Success(Response::DataColumn(sidecar)) = &chunk.chunk else {
        return None;
    };
    Some(match &**sidecar {
        forked::DataColumnSidecar::Fulu(s) => (
            s.signed_block_header.message.slot,
            s.signed_block_header.message.tree_hash_root().0,
        ),
        forked::DataColumnSidecar::Gloas(s) => (s.slot, s.beacon_block_root.0),
    })
}

/// The whole blocks of an answer of `chunks`, in order: how many chunks each holds, a run of
/// sidecars of one block (any other chunk is a block of its own). [`column_chunks`] made the
/// answer of whole blocks, so its writer cuts it again at one ([`super::codec::Answer`]).
pub(crate) fn block_lengths<E: EthSpec>(chunks: &[ReceivedChunk<E>]) -> Vec<usize> {
    let mut blocks: Vec<usize> = Vec::new();
    let mut last = None;
    for chunk in chunks {
        let block = block_of(chunk);
        match blocks.last_mut() {
            Some(len) if block.is_some() && block == last => *len += 1,
            _ => blocks.push(1),
        }
        last = block;
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethswarm_proto::common::{Envelope, Error, Hello};
    use ipc::envelope::DigestTable;
    use ipc::frame::OutFrame;
    use network_config::{ForkSchedule, ScheduledFork};

    const GLOAS: ForkDigest = [0x61, 0x0a, 0x50, 0x01];

    fn link() -> Link {
        let at = |epoch| ScheduledFork {
            version: [0; 4],
            epoch,
        };
        let digests = DigestTable::new(vec![(0, ForkName::Gloas, GLOAS)]).unwrap();
        let hello = Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 1,
            ..Default::default()
        };
        Link::new::<consensus_types::Mainnet>(
            hello,
            1,
            ForkSchedule::new(at(0), at(0)).unwrap(),
            digests,
        )
    }

    fn server_hello(link: &Link) -> Hello {
        Hello {
            generation: 7,
            ..link.local().clone()
        }
    }

    fn chunk(
        seq: u64,
        slot: u64,
        digest: ForkDigest,
        ssz: Vec<u8>,
    ) -> pb::DataColumnsByRangeResponse {
        pb::DataColumnsByRangeResponse::body(pb::DataColumnsByRangeResponseBody {
            item: Some(pb::ResponseChunk {
                result: Some(pb::response_chunk::Result::Chunk(Envelope {
                    fork_digest: digest.to_vec(),
                    slot,
                    root: vec![1; 32],
                    ssz,
                    payload_type: PayloadType::DataColumnSidecar as i32,
                    trace_id: Vec::new(),
                    seq,
                })),
            }),
        })
    }

    fn error(code: ErrorCode) -> pb::DataColumnsByRangeResponse {
        pb::DataColumnsByRangeResponse::body(pb::DataColumnsByRangeResponseBody {
            item: Some(pb::ResponseChunk {
                result: Some(pb::response_chunk::Result::Error(Error {
                    code: code as i32,
                    detail: "below earliest".into(),
                })),
            }),
        })
    }

    async fn read(frames: Vec<pb::DataColumnsByRangeResponse>, max: usize) -> ColumnReply {
        let link = link();
        let stream = futures::stream::iter(frames.into_iter().map(Ok));
        read_answer(&link, stream, max).await
    }

    #[tokio::test]
    async fn chunks_in_order_then_the_end() {
        let link = link();
        let frames = vec![
            pb::DataColumnsByRangeResponse::hello(server_hello(&link)),
            chunk(1, 9, GLOAS, vec![1; 10]),
            chunk(2, 10, GLOAS, vec![2; 10]),
        ];
        let ColumnReply::Sidecars(sidecars) = read(frames, 20).await else {
            panic!("refused")
        };
        let slots: Vec<_> = sidecars
            .iter()
            .map(|s| (s.slot, s.fork, s.context))
            .collect();
        assert_eq!(
            slots,
            [(9, ForkName::Gloas, GLOAS), (10, ForkName::Gloas, GLOAS)]
        );
        assert_eq!(sidecars[1].ssz, vec![2; 10]);
    }

    /// The client holds at most `max_bytes` past the first block: it stops reading there, and
    /// the answer is cut at a whole block later ([`super::super::inbound`]).
    #[tokio::test]
    async fn the_client_stops_reading_past_its_budget_but_keeps_the_first_block() {
        let link = link();
        let frames = vec![
            pb::DataColumnsByRangeResponse::hello(server_hello(&link)),
            chunk(1, 9, GLOAS, vec![1; 10]),
            chunk(2, 9, GLOAS, vec![2; 11]),
            chunk(3, 10, GLOAS, vec![3; 1]),
            chunk(4, 11, GLOAS, vec![4; 9]),
        ];
        let ColumnReply::Sidecars(sidecars) = read(frames, 15).await else {
            panic!("refused")
        };
        let slots: Vec<_> = sidecars.iter().map(|s| (s.slot, s.ssz.len())).collect();
        assert_eq!(
            slots,
            [(9, 10), (9, 11)],
            "the first block whole, then nothing"
        );
        assert!(sidecars.iter().all(|s| s.block_root == [1; 32]));
    }

    #[tokio::test]
    async fn error_chunks_map_to_their_result_codes() {
        let link = link();
        for (code, want) in [
            (
                ErrorCode::ResourceUnavailable,
                ResultCode::ResourceUnavailable,
            ),
            (ErrorCode::Invalid, ResultCode::InvalidRequest),
            (ErrorCode::Overloaded, ResultCode::ServerError),
        ] {
            let frames = vec![
                pb::DataColumnsByRangeResponse::hello(server_hello(&link)),
                error(code),
            ];
            assert_eq!(
                read(frames, 20).await,
                ColumnReply::Refused(want, "below earliest".into())
            );
        }
    }

    #[tokio::test]
    async fn a_contract_break_fails_the_whole_answer() {
        let link = link();
        let refused = |reply: ColumnReply| match reply {
            ColumnReply::Refused(ResultCode::ServerError, why) => why,
            other => panic!("{other:?}"),
        };
        // A digest that is not the slot's: dropped undecoded, and the answer with it.
        let frames = vec![
            pb::DataColumnsByRangeResponse::hello(server_hello(&link)),
            chunk(1, 9, GLOAS, vec![1; 10]),
            chunk(2, 10, [9; 4], vec![2; 10]),
        ];
        assert!(refused(read(frames, 20).await).contains("dropped"));
        // A seq gap.
        let frames = vec![
            pb::DataColumnsByRangeResponse::hello(server_hello(&link)),
            chunk(2, 9, GLOAS, vec![1; 10]),
        ];
        assert!(refused(read(frames, 20).await).contains("seq"));
        // No hello first.
        let frames = vec![chunk(1, 9, GLOAS, vec![1; 10])];
        refused(read(frames, 20).await);
        // A root that is not 32 bytes.
        let mut short = chunk(1, 9, GLOAS, vec![1; 10]);
        if let Some(pb::data_columns_by_range_response::Frame::Body(body)) = &mut short.frame {
            if let Some(pb::response_chunk::Result::Chunk(e)) =
                body.item.as_mut().and_then(|i| i.result.as_mut())
            {
                e.root.pop();
            }
        }
        let frames = vec![
            pb::DataColumnsByRangeResponse::hello(server_hello(&link)),
            short,
        ];
        assert!(refused(read(frames, 20).await).contains("root"));
        // Another payload type.
        let mut block = chunk(1, 9, GLOAS, vec![1; 10]);
        if let Some(pb::data_columns_by_range_response::Frame::Body(body)) = &mut block.frame {
            if let Some(pb::response_chunk::Result::Chunk(e)) =
                body.item.as_mut().and_then(|i| i.result.as_mut())
            {
                e.payload_type = PayloadType::SignedBeaconBlock as i32;
            }
        }
        let frames = vec![
            pb::DataColumnsByRangeResponse::hello(server_hello(&link)),
            block,
        ];
        assert!(refused(read(frames, 20).await).contains("payload_type"));
        // A transport failure mid-stream.
        let stream = futures::stream::iter(vec![
            Ok(pb::DataColumnsByRangeResponse::hello(server_hello(&link))),
            Err(Status::unavailable("gone")),
        ]);
        refused(read_answer(&link, stream, 20).await);
        assert_eq!(
            unreachable_chain(&Status::unavailable("down")),
            ColumnReply::server_error("column store unavailable")
        );
    }
}
