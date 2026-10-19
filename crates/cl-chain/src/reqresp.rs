//! cl-chain's side of the column req/resp protocols: `ethswarm.chain.v1.ReqRespService`
//! `DataColumnsByRange` and `DataColumnsByRoot`, which cl-p2p calls for a peer's
//! `DataColumnSidecarsByRange` v1 or `DataColumnSidecarsByRoot` v1 request
//! (`fulu/p2p-interface.md` L605–775). cl-p2p opens no database: the answer is read here, from
//! the `cl-chain-columns` store the probe fills from gossip ([`crate::probe::ColumnIngest`]).
//! Given a [`ChainStatus`] ([`ReqRespServer::serving_status`]: in probe mode the
//! [`StatusProvider`], whose `earliest_available_slot` is [`ColumnServer`]'s), it also serves
//! `GetStatus`, a unary call with no hello, `UNAVAILABLE` while there is no Status yet. The other
//! RPCs of the service are still stubs. [`crate::ChainStub::serving`] mounts it.
//!
//! # What is served
//!
//! - **The custody columns only.** The store holds the node's custody columns (4 groups), and
//!   nothing else is ever stored. A range request that names another column gets
//!   `3: ResourceUnavailable`: every block it would include lacks that column, and "Clients
//!   MUST include all data column sidecars of each block from which they include data column
//!   sidecars" (L672–673), so the answer below would be empty. A by-root request just gets no such sidecar ("It may be less in the
//!   case that the responding peer is missing blocks or sidecars", L728–733).
//! - **From `earliest_available_slot`.** That is [`ColumnServer::earliest_available_slot`]:
//!   [`earliest_servable_slot`] of the store's first stored slot, its finalized-slot watermark,
//!   `cgc_set_slot` and its contiguous-from slot. The first stored slot alone is a historical
//!   minimum, not proof that anything from there is held: pruning on finality removes the
//!   columns at and below the watermark and leaves it in place, columns stored before
//!   `cgc_set_slot` are of a smaller custody, and a blob-carrying block that was never stored
//!   (downtime, or every one of its columns missed gossip) leaves a gap the store detects
//!   through the chain links of the blocks after it ([`cl_chain_columns::BlockLink::Gap`]).
//!   With all four, the value is the lowest slot from which the store holds every blob-carrying
//!   block it knows of. For a node that stores forward from the slot `cgc` was set at, without
//!   a gap, it is that slot (`fulu/validator.md` L173–175: "the `earliest_available_slot` field
//!   … SHOULD reflect the slot at which the `custody_group_count` was updated"), and the Status
//!   says so ([`crate::probe::StatusProvider::serving_columns`], [`ColumnServer::status_floor`]:
//!   with nothing stored yet, the higher of `cgc_set_slot` and the slot after the watermark).
//! - **Within `data_column_serve_range`**: `[max(current_epoch -
//!   MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS, FULU_FORK_EPOCH), current_epoch]` by the wall
//!   clock (L647–651, [`ServeClock`]).
//!
//! A range request starting below `earliest_available_slot` or before
//! `data_column_serve_range`, or any request while nothing is stored, gets
//! `3: ResourceUnavailable` (L652–656), never an empty success: an empty answer would claim the
//! range holds no blobs. A range starting after the current epoch is an empty success: no
//! column exists there yet, and "Slots that do not contain known data columns MUST be skipped"
//! (L678–680). A by-root request answers what it can (L758–759): a root the store does not
//! know, or whose block is below `earliest_available_slot` or outside the range (L752–756,
//! "MAY … not include the data column sidecar"), is left out, and so is a `(root, index)` pair
//! named twice.
//!
//! # One chain ([`columns_by_range`])
//!
//! The probe runs no fork choice. Each stored block carries its link to the stored block before
//! it on its chain, and a range answer is one chain of linked blocks (L691–695): of the blocks
//! in the range (every stored one, whether or not it holds a requested column), the longest
//! chain of links (ties to the one with the higher tip, and if still tied, only the blocks the
//! tied chains share). Blocks off it on another branch are left out. Blocks in the range but
//! no chain left to serve (a tie with nothing shared) get `3: ResourceUnavailable`. A block
//! past the chain whose link was never followed (a gap, or a block still pending its ancestor)
//! may be on the chain, so it is never silently skipped: the answer ends before it.
//!
//! A block stored [`BlockLink::Pending`] names the slot of the ancestor it waits for: a
//! blob-carrying block the store knows it lacks, whether or not any block of the range is
//! stored. The range is read only up to the first such slot in it
//! ([`Snapshot::first_pending_target`]), and a range with nothing stored before that slot is
//! `3: ResourceUnavailable`, never an empty success, even while settlement has not run (a quiet
//! store). A chain whose first block waits for an ancestor before the range starts there, as one
//! whose parent is before the range. A pending link of a store no writer has migrated yet names
//! no slot, so any slot below its block may be the missing one: a range starting below that
//! block is `3: ResourceUnavailable`.
//!
//! # Order and completeness
//!
//! The answer is in `(slot, column_index)` order (L675–676) and includes a block only with
//! every requested column (L672–673): it is the longest prefix of the chain whose blocks each
//! hold every requested column, ending before the first block that lacks one (some of its
//! columns never arrived, or it holds none of them) and before any slot it may lack (above).
//! "Clients MAY limit the number of data column sidecars in the response" (L682), so a column
//! missed on gossip shortens an answer instead of refusing it; partial blocks are never sent.
//! When that prefix is empty the request is `3: ResourceUnavailable`: "Clients MUST respond with
//! at least the data column sidecars of the first blob-carrying block that exists in the range,
//! if they have it" (L668–670), and an empty answer would claim the range carries no blobs
//! (L678–680, "Slots that do not contain known data columns MUST be skipped" only for slots
//! without known columns). So does a blob-carrying block before the chain's first in the range,
//! held without the requested columns. The budget ([`ServeBudget`]: bytes and sidecars) ends an
//! answer the same way, before the block that would pass it (the block the read was cut at,
//! [`cl_chain_columns::RangeRead::cut`], and only that one is spared the completeness check); the
//! first block always goes whole, past the budget if it must. A by-root answer ends before the
//! identifier that would take it past the budget, its first identifier's sidecars always in.
//! cl-p2p cuts any answer at a whole block too, within the same budget and also to what the
//! requester's quota and reading pace deliver in what is left of its answer window, so what goes
//! out is this answer or a shorter prefix of it, never more.
//!
//! The view (custody, `earliest_available_slot`) and the read come from one read transaction
//! ([`Snapshot`]), so a finality prune between them cannot make a pruned slot look empty.
//!
//! # Bounds
//!
//! `1: InvalidRequest` (`ERROR_CODE_INVALID` on chain.v1) for an index at or past
//! `NUMBER_OF_COLUMNS`, more than `MAX_REQUEST_DATA_COLUMN_SIDECARS` (16,384) sidecars, more than
//! `MAX_REQUEST_BLOCKS_DENEB` (128) identifiers or a root that is not 32 bytes. At most
//! [`DEFAULT_MAX_READS`] (8, cl-p2p's answer places) reads run at once: past them a request gets
//! `ERROR_CODE_OVERLOADED`,
//! which cl-p2p answers `2: ServerError` (overload is IGNORE, never ACCEPT, `proto/README.md`
//! rule 4). Each read stops at [`READ_DEADLINE`], so a read whose caller gave up does not run
//! on. Error details stay in the log: the stream carries a fixed message per code.

use crate::probe::{
    earliest_servable_slot, ProbeChain, ProbeError, ReferenceApi, Root, StatusProvider,
};
use cl_chain_columns::{BlockLink, ColumnReader, ColumnWriter, RangeBudget, Snapshot};
use consensus_types::das;
use consensus_types::primitives::{Slot, U256};
use ethswarm_proto::chain as pb;
use ethswarm_proto::common::{self, Envelope, ErrorCode, PayloadType};
use ipc::frame::OutFrame;
use ipc::hello::stream_hello;
use ipc::stub::StubStream;
use ipc::Link;
use network_config::digest::{compute_fork_digest, current_epoch};
use network_config::{Epoch, ForkName};
use pb::req_resp_service_server::{ReqRespService, ReqRespServiceServer};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

/// `NUMBER_OF_COLUMNS` (`fulu/das-core.md`).
pub const NUMBER_OF_COLUMNS: u64 = das::NUMBER_OF_COLUMNS;

/// `MAX_REQUEST_DATA_COLUMN_SIDECARS` (`fulu/p2p-interface.md` L170–175).
pub const MAX_REQUEST_DATA_COLUMN_SIDECARS: u64 = 16_384;

/// `MAX_REQUEST_BLOCKS_DENEB`: the most identifiers of one by-root request (L85–94).
pub const MAX_REQUEST_BLOCKS_DENEB: usize = 128;

/// The SSZ bytes one answer holds at most by default: 8 MiB, cl-p2p's
/// `MAX_COLUMN_RESPONSE_BYTES`.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 << 20;

/// The sidecars one answer holds at most by default: 756, cl-p2p's per-answer share of what
/// its default column quota (512 at once, then one per 5 ms) delivers in its 5 s answer window,
/// split between the two streams a peer may hold open
/// (`cl_p2p::rpc::limits::RpcLimits::column_answer_sidecars`).
pub const DEFAULT_MAX_RESPONSE_SIDECARS: usize = 756;

/// Reads that run at once by default \[est\]: each holds at most one answer's budget, so at
/// most 8 × 8 MiB of SSZ is read at once. cl-p2p holds at most as many answers
/// (`cl_p2p::rpc::limits::DEFAULT_MAX_COLUMN_ANSWERS`), so its lookups are never refused as
/// overloaded here.
pub const DEFAULT_MAX_READS: usize = 8;

/// How long one read may run \[est\]: 2 s, cl-p2p's `COLUMN_LOOKUP_TIMEOUT`, after which the
/// caller has given up.
pub const READ_DEADLINE: Duration = Duration::from_secs(2);

/// One stored sidecar of an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    /// The slot of its block.
    pub slot: Slot,
    /// Its block root.
    pub block_root: Root,
    /// Its column index.
    pub index: u64,
    /// Its SSZ, as stored.
    pub ssz: Vec<u8>,
}

/// Why a request is not answered with sidecars.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// `1: InvalidRequest`.
    #[error("invalid request: {0}")]
    Invalid(String),
    /// `3: ResourceUnavailable`.
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// Too many reads at once: `ERROR_CODE_OVERLOADED`.
    #[error("overloaded")]
    Overloaded,
    /// The store failed, or the read ran past its deadline: `2: ServerError`.
    #[error("column store: {0}")]
    Store(String),
}

impl From<cl_chain_columns::Error> for Refusal {
    fn from(e: cl_chain_columns::Error) -> Self {
        Self::Store(e.to_string())
    }
}

/// How much one answer holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeBudget {
    /// SSZ bytes of sidecars.
    pub max_bytes: usize,
    /// Sidecars.
    pub max_sidecars: usize,
}

impl Default for ServeBudget {
    /// [`DEFAULT_MAX_RESPONSE_BYTES`] and [`DEFAULT_MAX_RESPONSE_SIDECARS`].
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_sidecars: DEFAULT_MAX_RESPONSE_SIDECARS,
        }
    }
}

/// What a request is answered against, read from the store and the clock together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeView {
    /// The custody columns, sorted.
    pub custody: Vec<u64>,
    /// `earliest_available_slot`; `None` while nothing can be served.
    pub earliest: Option<Slot>,
    /// `data_column_serve_range` as inclusive slots; `None` before Fulu by the wall clock.
    pub serve_range: Option<(Slot, Slot)>,
    /// What one answer holds.
    pub budget: ServeBudget,
    /// The read stops with [`Refusal::Store`] once this passes.
    pub deadline: Option<Instant>,
}

/// Whether a block at `slot` is servable: at or above `earliest_available_slot` and within the
/// serve range.
enum Servable {
    Yes,
    /// Below `earliest_available_slot`, before the range, or nothing stored.
    No(String),
    /// After the range: the future, where nothing exists yet.
    Future,
}

impl ServeView {
    fn servable(&self, slot: Slot, what: &str) -> Servable {
        let Some(earliest) = self.earliest else {
            return Servable::No("no columns stored".into());
        };
        let Some((first, last)) = self.serve_range else {
            return Servable::No("data_column_serve_range is empty before Fulu".into());
        };
        if slot > last {
            Servable::Future
        } else if slot < earliest {
            Servable::No(format!(
                "{what} {slot} is below earliest_available_slot {earliest}"
            ))
        } else if slot < first {
            Servable::No(format!(
                "{what} {slot} is before data_column_serve_range [{first}, {last}]"
            ))
        } else {
            Servable::Yes
        }
    }

    fn past_deadline(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    fn range_budget(&self) -> RangeBudget {
        RangeBudget {
            max_bytes: self.budget.max_bytes,
            max_columns: self.budget.max_sidecars,
            deadline: self.deadline,
        }
    }
}

/// An index at or past `NUMBER_OF_COLUMNS` is invalid.
fn check_indices(columns: &[u64]) -> Result<(), Refusal> {
    match columns.iter().find(|&&i| i >= NUMBER_OF_COLUMNS) {
        Some(i) => Err(Refusal::Invalid(format!(
            "column index {i} is not below NUMBER_OF_COLUMNS {NUMBER_OF_COLUMNS}"
        ))),
        None => Ok(()),
    }
}

/// More than `MAX_REQUEST_DATA_COLUMN_SIDECARS` sidecars is invalid.
fn check_sidecars(sidecars: u64) -> Result<u64, Refusal> {
    if sidecars > MAX_REQUEST_DATA_COLUMN_SIDECARS {
        return Err(Refusal::Invalid(format!(
            "{sidecars} sidecars requested, above MAX_REQUEST_DATA_COLUMN_SIDECARS \
             {MAX_REQUEST_DATA_COLUMN_SIDECARS}"
        )));
    }
    Ok(sidecars)
}

/// The bounds of a `DataColumnSidecarsByRange` request (see the module docs, `# Bounds`), which
/// need no store: every index below `NUMBER_OF_COLUMNS`, and at most
/// `MAX_REQUEST_DATA_COLUMN_SIDECARS` sidecars, `count × len(columns)` with a column named twice
/// counted twice. [`columns_by_range`] holds every request to them before it reads; the fuzz
/// targets hold them to the spec rule and to cl-p2p's admission check.
///
/// # Errors
///
/// [`Refusal::Invalid`]: a bound does not hold. Else the number of sidecars the request names.
pub fn range_request_bounds(count: u64, columns: &[u64]) -> Result<u64, Refusal> {
    check_indices(columns)?;
    check_sidecars(count.saturating_mul(columns.len() as u64))
}

/// The bounds of a `DataColumnSidecarsByRoot` request, as [`range_request_bounds`]: at most
/// `MAX_REQUEST_BLOCKS_DENEB` identifiers, at most `MAX_REQUEST_DATA_COLUMN_SIDECARS` sidecars
/// (every identifier's columns, a pair named twice counted twice) and every index below
/// `NUMBER_OF_COLUMNS`. [`columns_by_root`] holds every request to them before it reads.
///
/// # Errors
///
/// [`Refusal::Invalid`]: a bound does not hold. Else the number of sidecars the request names.
pub fn root_request_bounds(ids: &[(Root, Vec<u64>)]) -> Result<u64, Refusal> {
    if ids.len() > MAX_REQUEST_BLOCKS_DENEB {
        return Err(Refusal::Invalid(format!(
            "{} identifiers, above MAX_REQUEST_BLOCKS_DENEB {MAX_REQUEST_BLOCKS_DENEB}",
            ids.len()
        )));
    }
    let sidecars = check_sidecars(ids.iter().map(|(_, c)| c.len() as u64).sum())?;
    for (_, columns) in ids {
        check_indices(columns)?;
    }
    Ok(sidecars)
}

/// One block of a range read.
struct ReadBlock {
    slot: Slot,
    root: Root,
    link: BlockLink,
    columns: Vec<cl_chain_columns::RangeColumn>,
}

/// The blocks of `blocks` (in slot order) on the one chain the answer follows (see the module
/// docs), as indices in slot order.
fn one_chain(blocks: &[ReadBlock]) -> Vec<usize> {
    let at: HashMap<Root, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.root, i))
        .collect();
    let parent = |i: usize| match blocks[i].link {
        BlockLink::Parent(root) => at.get(&root).copied().filter(|&p| p < i),
        BlockLink::Start | BlockLink::Gap | BlockLink::Pending(..) => None,
    };
    // Parents come before their children in slot order.
    let mut depth = vec![0usize; blocks.len()];
    for i in 0..blocks.len() {
        depth[i] = 1 + parent(i).map_or(0, |p| depth[p]);
    }
    let walk = |tip: usize| {
        let mut chain = vec![tip];
        while let Some(p) = parent(*chain.last().expect("one")) {
            chain.push(p);
        }
        chain.reverse();
        chain
    };
    let Some(best) = (0..blocks.len()).max_by_key(|&i| (depth[i], blocks[i].slot)) else {
        return Vec::new();
    };
    let key = (depth[best], blocks[best].slot);
    let tied: Vec<usize> = (0..blocks.len())
        .filter(|&i| (depth[i], blocks[i].slot) == key)
        .collect();
    let mut chain = walk(best);
    for &other in &tied[..] {
        let theirs: HashSet<usize> = walk(other).into_iter().collect();
        chain.retain(|i| theirs.contains(i));
    }
    chain
}

/// `DataColumnSidecarsByRange` v1 from `reader` (see the module docs).
///
/// # Errors
///
/// [`Refusal`]: the error chunk the request gets.
pub fn columns_by_range(
    snapshot: &Snapshot<'_>,
    start_slot: Slot,
    count: u64,
    columns: &[u64],
    view: &ServeView,
) -> Result<Vec<Served>, Refusal> {
    range_request_bounds(count, columns)?;
    let wanted: BTreeSet<u64> = columns.iter().copied().collect();
    if wanted.is_empty() || count == 0 {
        return Ok(Vec::new());
    }
    let last = match view.servable(start_slot, "start_slot") {
        Servable::Yes => view.serve_range.map_or(start_slot, |(_, last)| last),
        Servable::Future => return Ok(Vec::new()),
        Servable::No(why) => return Err(Refusal::Unavailable(why)),
    };
    if let Some(other) = wanted
        .iter()
        .find(|i| view.custody.binary_search(i).is_err())
    {
        return Err(Refusal::Unavailable(format!(
            "column {other} is not a custody column"
        )));
    }
    let end = start_slot.saturating_add(count).min(last.saturating_add(1));
    // A blob-carrying block the store lacks though a stored block waits for it: the answer
    // ends before it, and with nothing before it the range is unavailable.
    let missing = snapshot.first_pending_target(start_slot, end, view.deadline)?;
    let read = snapshot.columns_in_range(
        start_slot,
        missing.unwrap_or(end),
        |i| wanted.contains(&i),
        view.range_budget(),
    )?;
    let mut blocks: Vec<ReadBlock> = read
        .blocks
        .iter()
        .map(|b| ReadBlock {
            slot: b.slot,
            root: b.block_root,
            link: b.link,
            columns: Vec::new(),
        })
        .collect();
    for column in read.columns {
        if let Some(b) = blocks
            .iter_mut()
            .find(|b| (b.slot, b.root) == (column.slot, column.block_root))
        {
            b.columns.push(column);
        }
    }
    let chain = one_chain(&blocks);
    let Some(&first) = chain.first() else {
        return match (blocks.is_empty(), missing) {
            (true, None) => Ok(Vec::new()),
            (true, Some(slot)) => Err(Refusal::Unavailable(format!(
                "the block at slot {slot} is not held"
            ))),
            (false, _) => Err(Refusal::Unavailable(
                "the blocks of the range share no chain".into(),
            )),
        };
    };
    // The chain's first block must be the range's first blob-carrying block on it.
    let unservable_start = match blocks[first].link {
        BlockLink::Parent(parent) => snapshot.slot_of(&parent)?.is_some_and(|s| s >= start_slot),
        BlockLink::Pending(_, target) => target >= start_slot,
        BlockLink::Gap => blocks[first].slot > start_slot,
        BlockLink::Start => false,
    };
    if unservable_start {
        return Err(Refusal::Unavailable(format!(
            "a block before slot {} in the range lacks requested columns",
            blocks[first].slot
        )));
    }
    // A block past the chain whose link was not followed may be on it: the answer ends before
    // it, never skips it.
    let tip = *chain.last().expect("not empty");
    let unlinked = blocks[tip + 1..]
        .iter()
        .find(|b| matches!(b.link, BlockLink::Gap | BlockLink::Pending(..)))
        .map(|b| b.slot);
    let mut served = Vec::new();
    let mut ended = None;
    for &i in &chain {
        let block = &mut blocks[i];
        if let Some(slot) = unlinked.filter(|&slot| block.slot >= slot) {
            ended = Some(format!(
                "the block at slot {slot} does not link to the chain"
            ));
            break;
        }
        // The budget cut this block: the answer ends before it.
        if read.cut == Some((block.slot, block.root)) {
            break;
        }
        if block.columns.len() != wanted.len() {
            ended = Some(format!(
                "the block at slot {} lacks requested columns",
                block.slot
            ));
            break;
        }
        served.extend(block.columns.drain(..).map(|r| Served {
            slot: r.slot,
            block_root: r.block_root,
            index: r.index,
            ssz: r.ssz,
        }));
    }
    // The chain holds a blob-carrying block: an empty answer would claim it holds none.
    if served.is_empty() {
        return Err(Refusal::Unavailable(ended.unwrap_or_else(|| {
            format!(
                "the budget cut the first block, at slot {}",
                blocks[first].slot
            )
        })));
    }
    Ok(served)
}

/// `DataColumnSidecarsByRoot` v1 from `reader`: per identifier in request order, its stored
/// requested columns in index order, each `(root, index)` once (see the module docs).
///
/// # Errors
///
/// [`Refusal`]: the error chunk the request gets.
pub fn columns_by_root(
    snapshot: &Snapshot<'_>,
    ids: &[(Root, Vec<u64>)],
    view: &ServeView,
) -> Result<Vec<Served>, Refusal> {
    root_request_bounds(ids)?;
    let wanted = ids
        .iter()
        .map(|(root, columns)| (root, columns.iter().copied().collect::<BTreeSet<u64>>()));
    let mut seen: HashSet<(Root, u64)> = HashSet::new();
    let mut served = Vec::new();
    let mut bytes = 0usize;
    for (root, columns) in wanted {
        if view.past_deadline() {
            return Err(Refusal::Store("the read ran past its deadline".into()));
        }
        let columns: Vec<u64> = columns
            .into_iter()
            .filter(|&i| seen.insert((*root, i)))
            .collect();
        if columns.is_empty() {
            continue;
        }
        let Some(slot) = snapshot.slot_of(root)? else {
            continue;
        };
        if !matches!(view.servable(slot, "block"), Servable::Yes) {
            continue;
        }
        let mut block = Vec::new();
        for index in columns {
            if let Some(ssz) = snapshot.get(root, index)? {
                block.push(Served {
                    slot,
                    block_root: *root,
                    index,
                    ssz,
                });
            }
        }
        let size = block
            .iter()
            .fold(0usize, |n, s| n.saturating_add(s.ssz.len()));
        let over = bytes.saturating_add(size) > view.budget.max_bytes
            || served.len() + block.len() > view.budget.max_sidecars;
        if !served.is_empty() && over {
            break;
        }
        bytes = bytes.saturating_add(size);
        served.extend(block);
    }
    Ok(served)
}

/// The wall clock's view of the chain, for the serve range and the context digests.
pub trait ServeClock: Send + Sync + 'static {
    /// `data_column_serve_range` now, as inclusive slots; `None` before Fulu or genesis.
    fn serve_range(&self) -> Option<(Slot, Slot)>;

    /// The fork digest of the epoch of `slot`, which its sidecar's envelope (and chunk) carries.
    fn fork_digest(&self, slot: Slot) -> Option<[u8; 4]>;
}

/// [`ServeClock`] from the system clock and the pinned network.
#[derive(Debug, Clone)]
pub struct WallClock {
    chain: ProbeChain,
    min_epochs: Epoch,
}

impl WallClock {
    /// The clock of `chain`, `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` from its config.
    ///
    /// # Errors
    ///
    /// The config has no such value, or not a number.
    pub fn new(chain: ProbeChain) -> Result<Self, String> {
        let key = "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS";
        let min_epochs = chain
            .config
            .get(key)
            .ok_or_else(|| format!("the config has no {key}"))?
            .parse()
            .map_err(|e| format!("{key}: {e}"))?;
        Ok(Self { chain, min_epochs })
    }

    /// `data_column_serve_range` at `now_ms` (Unix milliseconds), as inclusive slots.
    #[must_use]
    pub fn serve_range_at(&self, now_ms: u128) -> Option<(Slot, Slot)> {
        let chain = &self.chain;
        let spe = chain.slots_per_epoch;
        let now = current_epoch(
            chain.genesis.genesis_time,
            chain.config.slot_duration_ms(),
            spe,
            now_ms,
        )
        .ok()?;
        let fulu = chain.config.fork_schedule().fork_epoch(ForkName::Fulu)?;
        if now < fulu {
            return None;
        }
        let first = now.saturating_sub(self.min_epochs).max(fulu);
        let last = now.saturating_add(1).saturating_mul(spe).saturating_sub(1);
        Some((first.saturating_mul(spe), last))
    }
}

/// Unix milliseconds now.
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

impl ServeClock for WallClock {
    fn serve_range(&self) -> Option<(Slot, Slot)> {
        self.serve_range_at(now_ms())
    }

    fn fork_digest(&self, slot: Slot) -> Option<[u8; 4]> {
        let chain = &self.chain;
        let epoch = slot / chain.slots_per_epoch.max(1);
        compute_fork_digest(&chain.config, &chain.genesis.genesis_validators_root, epoch).ok()
    }
}

/// The column store as the req/resp server reads it.
pub trait ColumnStore: Send + Sync + 'static {
    /// The store's reader.
    fn reader(&self) -> &ColumnReader;
}

impl ColumnStore for ColumnWriter {
    fn reader(&self) -> &ColumnReader {
        ColumnWriter::reader(self)
    }
}

impl ColumnStore for ColumnReader {
    fn reader(&self) -> &ColumnReader {
        self
    }
}

/// The custody columns served from one store (see the module docs).
pub struct ColumnServer {
    store: Arc<dyn ColumnStore>,
    node_id: U256,
    clock: Arc<dyn ServeClock>,
    budget: ServeBudget,
}

impl std::fmt::Debug for ColumnServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColumnServer")
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl ColumnServer {
    /// Serves the custody columns of `node_id` from `store`, under `clock`, at most `budget`
    /// per answer ([`ServeBudget::default`]: cl-p2p's defaults).
    pub fn new(
        store: Arc<dyn ColumnStore>,
        node_id: U256,
        clock: Arc<dyn ServeClock>,
        budget: ServeBudget,
    ) -> Self {
        Self {
            store,
            node_id,
            clock,
            budget,
        }
    }

    /// The custody, `earliest_available_slot` and serve range now, no deadline.
    ///
    /// # Errors
    ///
    /// The store's.
    pub fn view(&self) -> Result<ServeView, Refusal> {
        self.view_in(&self.store.reader().snapshot()?)
    }

    /// [`Self::view`] as of `snapshot`, so a read through the same snapshot sees the store the
    /// view was taken of (no prune lands between the two).
    fn view_in(&self, reader: &Snapshot<'_>) -> Result<ServeView, Refusal> {
        let (custody, earliest) = match reader.custody()? {
            Some(record) => {
                let custody = das::custody_columns(self.node_id, record.cgc)
                    .map_err(|e| Refusal::Store(format!("custody: {e:?}")))?;
                let earliest = earliest_servable_slot(
                    reader.first_stored_slot()?,
                    reader.finalized_slot()?,
                    record.cgc_set_slot,
                    reader.contiguous_from()?,
                );
                (custody, earliest)
            }
            None => (Vec::new(), None),
        };
        Ok(ServeView {
            custody,
            earliest,
            serve_range: self.clock.serve_range(),
            budget: self.budget,
            deadline: None,
        })
    }

    /// The Status `earliest_available_slot`: [`Self::earliest_available_slot`] once a column
    /// is stored; before that the slot the store serves from at the earliest, the higher of
    /// `cgc_set_slot` and the slot after the finality watermark. Never below what
    /// [`columns_by_range`] serves from, so a peer asking from there is never refused for it.
    ///
    /// # Errors
    ///
    /// The store cannot be read, or holds no custody record.
    pub fn status_floor(&self) -> Result<Slot, String> {
        let snapshot = self.store.reader().snapshot().map_err(|e| e.to_string())?;
        let view = self.view_in(&snapshot).map_err(|e| e.to_string())?;
        if let Some(earliest) = view.earliest {
            return Ok(earliest);
        }
        let record = snapshot
            .custody()
            .map_err(|e| e.to_string())?
            .ok_or("no custody record")?;
        let after_finality = snapshot
            .finalized_slot()
            .map_err(|e| e.to_string())?
            .map_or(0, |f| f.saturating_add(1));
        Ok(record.cgc_set_slot.max(after_finality))
    }

    /// The slot columns are served from while they are: `None` while nothing is (or the
    /// store cannot be read).
    #[must_use]
    pub fn earliest_available_slot(&self) -> Option<Slot> {
        match self.view() {
            Ok(view) => view.earliest,
            Err(e) => {
                tracing::warn!(error = %e, "no earliest_available_slot: the column store failed");
                None
            }
        }
    }

    /// [`columns_by_range`] now, stopping at `deadline`.
    ///
    /// # Errors
    ///
    /// [`Refusal`].
    pub fn by_range(
        &self,
        start_slot: Slot,
        count: u64,
        columns: &[u64],
        deadline: Option<Instant>,
    ) -> Result<Vec<Served>, Refusal> {
        let snapshot = self.store.reader().snapshot()?;
        let view = ServeView {
            deadline,
            ..self.view_in(&snapshot)?
        };
        columns_by_range(&snapshot, start_slot, count, columns, &view)
    }

    /// [`columns_by_root`] now, stopping at `deadline`.
    ///
    /// # Errors
    ///
    /// [`Refusal`].
    pub fn by_root(
        &self,
        ids: &[(Root, Vec<u64>)],
        deadline: Option<Instant>,
    ) -> Result<Vec<Served>, Refusal> {
        let snapshot = self.store.reader().snapshot()?;
        let view = ServeView {
            deadline,
            ..self.view_in(&snapshot)?
        };
        columns_by_root(&snapshot, ids, &view)
    }

    /// `served` as the envelopes of a chain.v1 response, `seq` from 1: each stamped with the
    /// digest of its slot's epoch.
    fn envelopes(&self, served: Vec<Served>) -> Result<Vec<Envelope>, Refusal> {
        (1u64..)
            .zip(served)
            .map(|(seq, s)| {
                let digest = self.clock.fork_digest(s.slot).ok_or_else(|| {
                    Refusal::Store(format!("no fork digest for a stored slot {}", s.slot))
                })?;
                Ok(Envelope {
                    fork_digest: digest.to_vec(),
                    slot: s.slot,
                    root: s.block_root.to_vec(),
                    ssz: s.ssz,
                    payload_type: PayloadType::DataColumnSidecar as i32,
                    trace_id: Vec::new(),
                    seq,
                })
            })
            .collect()
    }
}

impl crate::probe::ServedColumns for ColumnServer {
    fn status_floor(&self) -> Result<Slot, String> {
        ColumnServer::status_floor(self)
    }
}

/// One Status lookup in flight.
pub type StatusLookup<'a> =
    Pin<Box<dyn Future<Output = Result<pb::GetStatusResponse, ProbeError>> + Send + 'a>>;

/// The Status `ReqRespService/GetStatus` serves: in probe mode the [`StatusProvider`], whose
/// `earliest_available_slot` is the column server's ([`StatusProvider::serving_columns`]).
pub trait ChainStatus: Send + Sync + 'static {
    /// The Status now; [`ProbeError`] while there is none, which the call answers
    /// `UNAVAILABLE` (cl-p2p then sends and judges no Status).
    fn status(&self) -> StatusLookup<'_>;
}

impl<A: ReferenceApi + 'static> ChainStatus for StatusProvider<A> {
    /// At once: the provider never waits on the reference API (see [`crate::probe`]).
    fn status(&self) -> StatusLookup<'_> {
        Box::pin(std::future::ready(StatusProvider::status(self, now_ms())))
    }
}

/// The message each refusal goes out with: fixed per code, so no store or contract detail
/// leaves cl-chain.
const INVALID_MESSAGE: &str = "invalid request";
const UNAVAILABLE_MESSAGE: &str = "resource unavailable";
const OVERLOADED_MESSAGE: &str = "overloaded";
const STORE_MESSAGE: &str = "column store failed";

/// The early end of an answer as the chunk that ends it; a store failure fails the stream.
fn refusal_chunk(refusal: &Refusal) -> Result<pb::ResponseChunk, Status> {
    let (code, detail) = match refusal {
        Refusal::Invalid(_) => (ErrorCode::Invalid, INVALID_MESSAGE),
        Refusal::Unavailable(_) => (ErrorCode::ResourceUnavailable, UNAVAILABLE_MESSAGE),
        Refusal::Overloaded => (ErrorCode::Overloaded, OVERLOADED_MESSAGE),
        // The stream fails: cl-p2p answers `2: ServerError`.
        Refusal::Store(_) => return Err(Status::internal(STORE_MESSAGE)),
    };
    Ok(pb::ResponseChunk {
        result: Some(pb::response_chunk::Result::Error(common::Error {
            code: code as i32,
            detail: detail.into(),
        })),
    })
}

/// `ethswarm.chain.v1.ReqRespService` with the column RPCs served from a [`ColumnServer`],
/// `GetStatus` from a [`ChainStatus`] once it is given one ([`Self::serving_status`]), and the
/// rest still stubs (contract checks, then `UNIMPLEMENTED`).
#[derive(Clone)]
pub struct ReqRespServer {
    link: Link,
    columns: Arc<ColumnServer>,
    reads: Arc<Semaphore>,
    status: Option<Arc<dyn ChainStatus>>,
}

impl std::fmt::Debug for ReqRespServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqRespServer")
            .field("link", &self.link)
            .field("columns", &self.columns)
            .field("serves_status", &self.status.is_some())
            .finish_non_exhaustive()
    }
}

impl ReqRespServer {
    /// Serves `columns`, holding every stream to `link`, at most [`DEFAULT_MAX_READS`] reads at
    /// once.
    #[must_use]
    pub fn new(link: Link, columns: Arc<ColumnServer>) -> Self {
        Self::with_max_reads(link, columns, DEFAULT_MAX_READS)
    }

    /// [`Self::new`] with at most `max_reads` reads at once.
    #[must_use]
    pub fn with_max_reads(link: Link, columns: Arc<ColumnServer>, max_reads: usize) -> Self {
        Self {
            link,
            columns,
            reads: Arc::new(Semaphore::new(max_reads)),
            status: None,
        }
    }

    /// The same server, answering `GetStatus` from `status`.
    #[must_use]
    pub fn serving_status(mut self, status: Arc<dyn ChainStatus>) -> Self {
        self.status = Some(status);
        self
    }

    /// The tonic service.
    #[must_use]
    pub fn into_service(self) -> ReqRespServiceServer<Self> {
        ReqRespServiceServer::new(self)
    }

    /// Checks the in-line hello, reads the answer off the async runtime under a read place and
    /// [`READ_DEADLINE`], and streams our hello, then one chunk per sidecar, then the refusal
    /// if there is one.
    async fn stream<R, B>(
        &self,
        hello: Option<&common::Hello>,
        read: impl FnOnce(&ColumnServer, Instant) -> Result<Vec<Served>, Refusal> + Send + 'static,
        body: fn(pb::ResponseChunk) -> B,
    ) -> Result<Response<StubStream<R>>, Status>
    where
        R: OutFrame<Body = B> + Send + 'static,
        B: Send + 'static,
    {
        self.link
            .accept_hello_field(hello)
            .map_err(|e| e.to_status())?;
        let (_, ours) = stream_hello(self.link.local()).map_err(|e| e.to_status())?;
        let answer = match Arc::clone(&self.reads).try_acquire_owned() {
            Ok(permit) => {
                let columns = Arc::clone(&self.columns);
                let deadline = Instant::now() + READ_DEADLINE;
                tokio::task::spawn_blocking(move || {
                    // Held until the read ends, even if the caller is gone.
                    let _permit = permit;
                    read(&columns, deadline).and_then(|served| columns.envelopes(served))
                })
                .await
                .unwrap_or_else(|e| Err(Refusal::Store(format!("column read: {e}"))))
            }
            Err(_) => Err(Refusal::Overloaded),
        };
        let (envelopes, refusal) = match answer {
            Ok(envelopes) => (envelopes, None),
            Err(refusal) => (Vec::new(), Some(refusal)),
        };
        let mut frames = vec![Ok(R::hello(ours))];
        frames.extend(envelopes.into_iter().map(|e| {
            Ok(R::body(body(pb::ResponseChunk {
                result: Some(pb::response_chunk::Result::Chunk(e)),
            })))
        }));
        if let Some(refusal) = refusal {
            tracing::debug!(%refusal, "column request refused");
            frames.push(refusal_chunk(&refusal).map(|chunk| R::body(body(chunk))));
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(frames))))
    }
}

/// The identifiers of a chain.v1 by-root request; a root that is not 32 bytes is invalid.
fn identifiers(request: &pb::DataColumnsByRootRequest) -> Result<Vec<(Root, Vec<u64>)>, Refusal> {
    request
        .ids
        .iter()
        .map(|id| {
            let root = Root::try_from(id.block_root.as_slice()).map_err(|_| {
                Refusal::Invalid(format!("a block root of {} bytes", id.block_root.len()))
            })?;
            Ok((root, id.columns.clone()))
        })
        .collect()
}

#[tonic::async_trait]
impl ReqRespService for ReqRespServer {
    async fn get_status(
        &self,
        _: Request<pb::GetStatusRequest>,
    ) -> Result<Response<pb::GetStatusResponse>, Status> {
        let Some(status) = &self.status else {
            return ipc::stub::unary(&self.link, "get_status", &[]);
        };
        // A unary call: no hello, no envelope.
        self.link.check_unary(&[]).map_err(|e| e.to_status())?;
        status
            .status()
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    async fn get_metadata(
        &self,
        _: Request<pb::GetMetadataRequest>,
    ) -> Result<Response<pb::GetMetadataResponse>, Status> {
        ipc::stub::unary(&self.link, "get_metadata", &[])
    }

    type BlocksByRangeStream = StubStream<pb::BlocksByRangeResponse>;

    async fn blocks_by_range(
        &self,
        request: Request<pb::BlocksByRangeRequest>,
    ) -> Result<Response<Self::BlocksByRangeStream>, Status> {
        ipc::stub::server_stream(&self.link, "blocks_by_range", request.get_ref())
    }

    type BlocksByRootStream = StubStream<pb::BlocksByRootResponse>;

    async fn blocks_by_root(
        &self,
        request: Request<pb::BlocksByRootRequest>,
    ) -> Result<Response<Self::BlocksByRootStream>, Status> {
        ipc::stub::server_stream(&self.link, "blocks_by_root", request.get_ref())
    }

    type PayloadEnvelopesByRangeStream = StubStream<pb::PayloadEnvelopesByRangeResponse>;

    async fn payload_envelopes_by_range(
        &self,
        request: Request<pb::PayloadEnvelopesByRangeRequest>,
    ) -> Result<Response<Self::PayloadEnvelopesByRangeStream>, Status> {
        ipc::stub::server_stream(&self.link, "payload_envelopes_by_range", request.get_ref())
    }

    type PayloadEnvelopesByRootStream = StubStream<pb::PayloadEnvelopesByRootResponse>;

    async fn payload_envelopes_by_root(
        &self,
        request: Request<pb::PayloadEnvelopesByRootRequest>,
    ) -> Result<Response<Self::PayloadEnvelopesByRootStream>, Status> {
        ipc::stub::server_stream(&self.link, "payload_envelopes_by_root", request.get_ref())
    }

    type DataColumnsByRangeStream = StubStream<pb::DataColumnsByRangeResponse>;

    async fn data_columns_by_range(
        &self,
        request: Request<pb::DataColumnsByRangeRequest>,
    ) -> Result<Response<Self::DataColumnsByRangeStream>, Status> {
        let request = request.into_inner();
        let (start, count, columns) = (request.start_slot, request.count, request.columns);
        self.stream(
            request.hello.as_ref(),
            move |server, deadline| server.by_range(start, count, &columns, Some(deadline)),
            |item| pb::DataColumnsByRangeResponseBody { item: Some(item) },
        )
        .await
    }

    type DataColumnsByRootStream = StubStream<pb::DataColumnsByRootResponse>;

    async fn data_columns_by_root(
        &self,
        request: Request<pb::DataColumnsByRootRequest>,
    ) -> Result<Response<Self::DataColumnsByRootStream>, Status> {
        let request = request.into_inner();
        let ids = identifiers(&request);
        self.stream(
            request.hello.as_ref(),
            move |server, deadline| server.by_root(&ids?, Some(deadline)),
            |item| pb::DataColumnsByRootResponseBody { item: Some(item) },
        )
        .await
    }
}

#[cfg(test)]
mod tests;
