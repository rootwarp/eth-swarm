//! [`ColumnIngest`]: the forward-only store of custody column sidecars from gossip.
//!
//! cl-p2p's ignore-all gossipsub reports IGNORE for every `data_column_sidecar_{subnet_id}`
//! message and hands the decoded sidecar to cl-chain; [`ColumnIngest::on_column`] takes it from
//! there and answers [`Verdict::Ignore`] for every column, stored or not. So no column this node
//! stores is ever re-broadcast. That is a recorded deviation from `gloas/p2p-interface.md`
//! L1292–1294 ("If validation succeeds, the client MUST re-broadcast the sidecar"): the probe
//! imports no block, so it vouches for no column to its peers.
//!
//! Each column goes through, in order:
//!
//! 1. **The pending queue** ([`IngestLimits::max_items`], [`IngestLimits::max_bytes`]). A column
//!    holds a place, sized by its SSZ, from its arrival until it is stored or dropped. One that
//!    would pass either cap is dropped at once and counted in
//!    `probe_column_queue_dropped_total`.
//! 2. **The local checks** of the storage contract: structure, subnet, custody, and forward only
//!    ([`super::column`]). A column before `cgc_set_slot` is dropped as `before_cgc_set_slot`:
//!    nothing is backfilled.
//! 3. **The root** (`probe::root_wait`). A column whose block root the reference view has
//!    cached goes on at once. A column of a root the reference announced on its `block` event
//!    stream ([`ColumnIngest::follow_head`], `probe::head`) shares that root's lookup in places
//!    of its own, with no turn in the first-ask budget and no place in the root wait, at most
//!    [`IngestLimits::max_announced_columns`] such columns at once, asking again while the
//!    announcement lives. Any other column, or one past those bounds, joins its root's entry:
//!    the first column of the root asks the reference once, at its turn of the first-ask
//!    budget ([`IngestLimits::first_asks_per_sec`]), and the others share the answer. A root
//!    the reference knows needs nothing more, and its block goes to the storage contract,
//!    which so never looks it up again. A root not known yet is seated in the
//!    wait (`gloas/p2p-interface.md` L1322–1324: "MAY be queued until block is retrieved"): one
//!    retry per [`IngestLimits::root_retry`] for all its columns, from a budget of its own
//!    ([`IngestLimits::retries_per_sec`]), for at most [`IngestLimits::root_wait`] from the
//!    first one's arrival, then dropped as `root_timeout`. A root refused, or whose wait ran out,
//!    is remembered for [`IngestLimits::unknown_root_ttl`], one not known yet that found no seat
//!    for a retry (at most [`MAX_UNKNOWN_ROOTS`](super::MAX_UNKNOWN_ROOTS) roots). At most
//!    [`IngestLimits::max_asking_columns`] columns wait for first asks,
//!    [`IngestLimits::max_waiting_columns`] for [`IngestLimits::max_waiting_roots`] seated
//!    roots, and [`MAX_CANDIDATES_PER_INDEX`](super::MAX_CANDIDATES_PER_INDEX) per index of a
//!    root; a column past a cap is dropped as `root_wait_full`, so columns of made-up roots never
//!    fill the queue ([`IngestLimits::validate`]). A flood of fresh made-up roots still dilutes
//!    the first-ask budget for the roots not announced: see the residual risk in
//!    `probe::root_wait`.
//! 4. **The copy budget** ([`IngestLimits::max_copy_bytes`]). Before the storage contract, the
//!    column charges the copies it is about to make: its cells for cl-verify and their
//!    encoding, and its SSZ for the write. The SSZ copy stays charged until the column is
//!    stored or dropped; the cells' until their request has left cl-verify's client queue, even
//!    past a verify timeout. A column whose copies do not fit is dropped as queue-full, so a
//!    stalled cl-verify cannot make the queue hold more than both budgets.
//! 5. **The storage contract** ([`super::storage_contract`]): root, commitments, KZG through
//!    cl-verify.
//! 6. **The link** ([`BlockLink`]): how the block ties to the stored block before it on its
//!    chain, from the parent roots of the blocks the reference vouches for. The column's task
//!    finds the nearest ancestor that is stored or carries blobs, passing through ancestors
//!    without blobs (they have no columns), at most [`MAX_LINK_WALK`] blocks back, and hands it
//!    to the writer as [`BlockLink::Pending`] with the ancestor's slot. An ancestor before
//!    `cgc_set_slot` or at or below the finalized watermark is [`BlockLink::Start`]; one the
//!    reference cannot vouch for, or a walk past its bound, is [`BlockLink::Gap`]. The writer
//!    decides at write time, after every earlier batch committed: an ancestor stored by then is
//!    the block's [`BlockLink::Parent`], and one finality covers by then (pruned, or refused) a
//!    [`BlockLink::Start`]; one not stored yet leaves the block pending, and it links as soon
//!    as the ancestor's columns are written, so a parent and child released together link
//!    whatever order they are written in. A gap from a later walk that failed does not replace
//!    a pending link. A block still pending once the store is [`PENDING_LINK_SLOTS`] past it is
//!    settled: a start if finality covers the ancestor's slot by then, else a
//!    [`BlockLink::Gap`] ([`ColumnWriter::settle_pending`]), and the store's contiguous-from
//!    slot rises to it ([`ColumnReader::contiguous_from`]): the Status never claims the slots
//!    before a gap. Until then a range answer never passes the ancestor's slot
//!    ([`crate::reqresp`]).
//! 7. **The write**, on the [`WRITER_THREAD`] thread: the columns of one block that the writer
//!    takes off its queue together, in one [`ColumnWriter::write_columns`] call, which commits
//!    them in transactions of at most
//!    [`MAX_COLUMNS_PER_TXN`](cl_chain_columns::MAX_COLUMNS_PER_TXN) (16) at the column env's
//!    background priority, so block import goes first, while it holds off reorg pruning. A root
//!    pruned as an orphan is refused from then on, so a later batch cannot bring it back. A
//!    refused write is dropped as `store_failed`. A column gives its queue place back once
//!    written, and the writer settles the pending links after each batch, so
//!    [`ColumnIngest::settled`] is what shows the store stopped changing: a barrier on the
//!    writer's queue, confirmed once everything before it is written and settled.
//!
//! `probe_column_buffer_bytes` is what the queued columns hold now, their SSZ and their copies
//! together, and `probe_column_buffer_alert` is 1 while that is at or above
//! [`IngestLimits::alert_bytes`] ([`COLUMN_BUFFER_ALERT_BYTES`], 48 MiB).
//!
//! The first stored slot ([`first_stored_column_slot`]) is written in the transaction that
//! stores the column, so it survives a crash together with the columns. It is a historical
//! minimum, not proof that the data is held; [`earliest_servable_slot`] is the slot the store
//! may claim to serve from. Pruning on finality and reorg stays with the column env
//! ([`ColumnWriter::prune_finalized`], [`ColumnWriter::prune_orphaned`]).

use super::column::{local_check, vouched_contract, ColumnContract, ColumnMetrics, Drop};
use super::head::{follow_head, HeadFollow, HeadSource};
use super::root_wait::{Answer, RootWaits};
use super::{BlockApi, GossipColumn, RefBlock, RefError, RefLimits, RefView, ReferenceApi, Root};
use crate::da::custody::Custody;
use crate::verify::client::{Held, KzgVerifier};
use cl_chain_columns::{BlockLink, Column, ColumnReader, ColumnWriter, WriteFailed, WriteReport};
use consensus_types::primitives::Slot;
use consensus_types::{gloas, EthSpec};
use ethswarm_proto::common::Verdict;
use ethswarm_proto::verify::KzgCellProof;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Queued column bytes at which `probe_column_buffer_alert` turns on: 48 MiB.
pub const COLUMN_BUFFER_ALERT_BYTES: usize = 48 << 20;

/// How long a column waits for the reference to learn its block root \[est\]. Provisional: no
/// deadline for this wait is pinned yet, so this is a third of a 12 s slot, long enough for the
/// reference to import a block whose columns arrived first.
pub const DEFAULT_ROOT_WAIT: Duration = Duration::from_secs(4);

/// How often a seated root is asked again \[est\]: eight times in a [`DEFAULT_ROOT_WAIT`].
pub const DEFAULT_ROOT_RETRY: Duration = Duration::from_millis(500);

/// Roots seated in the wait at once \[est\]: a slot's block arrives about every 12 s, and is
/// usually known by the time its columns arrive, so real waits need a few; the rest bounds
/// made-up roots.
pub const DEFAULT_MAX_WAITING_ROOTS: usize = 16;

/// Columns waiting for seated roots at once \[est\]: a block and a half at full custody.
pub const DEFAULT_MAX_WAITING_COLUMNS: usize = 192;

/// Columns waiting for first asks at once \[est\]. With [`DEFAULT_MAX_WAITING_COLUMNS`] it
/// leaves a full block's places in the default queue for columns whose roots are known.
pub const DEFAULT_MAX_ASKING_COLUMNS: usize = 192;

/// First asks of column roots a second \[est\]. Each is a header request, plus a block request
/// for a root it finds.
pub const DEFAULT_FIRST_ASKS_PER_SEC: u32 = 32;

/// First asks that may go out at once after a quiet spell \[est\]: a slot's root and a few late
/// ones.
pub const DEFAULT_FIRST_ASK_BURST: u32 = 16;

/// Retries of seated roots a second \[est\]: exactly a retry of every seat every
/// [`DEFAULT_ROOT_RETRY`] (16 / 0.5 s), the least [`IngestLimits::validate`] allows.
///
/// What the root wait asks of the reference with the defaults, in three separate bounds:
/// - **Sustained rate:** 32 first asks and 32 retries a second, 64 lookups, so at most 128
///   requests a second (a header, and the block for a root it finds).
/// - **Burst:** after a quiet spell, up to [`DEFAULT_FIRST_ASK_BURST`] first asks go out at
///   once on top of that rate. Retries do not burst: a seat asks again once per root retry.
/// - **Concurrency:** at most 96 lookups in flight at once, the seats' 16 retries and 80 first
///   asks within the 2 s lookup timeout ([`IngestLimits::validate_for`]), within the reference
///   view's `max_in_flight`.
///
/// The head seed adds a lookup per block the reference announces, in places of its own.
pub const DEFAULT_RETRIES_PER_SEC: u32 = 32;

/// Columns waiting on the lookups of announced roots at once \[est\]: a quarter of a block at
/// full custody. A root is usually cached before its columns arrive, so few ever wait; the cap
/// keeps forged columns of an announced root out of the places of known roots, and with the
/// root wait's caps it leaves 96 of the default queue's places to them.
pub const DEFAULT_MAX_ANNOUNCED_COLUMNS: usize = 32;

/// How long a root whose wait ran out, or that the reference refused, is remembered \[est\]:
/// one [`DEFAULT_ROOT_WAIT`], so a peer resending columns of a made-up root costs no request
/// for that long.
pub const DEFAULT_UNKNOWN_ROOT_TTL: Duration = DEFAULT_ROOT_WAIT;

/// How many blocks without blobs a column's chain link passes through at most \[est\]: two
/// epochs. Past it the block is a gap.
pub const MAX_LINK_WALK: usize = 64;

/// How many slots past a pending block the store writes before the block is settled as a gap
/// \[est\]: four slots (48 s), far past the root wait (4 s) a late parent's columns can take.
pub const PENDING_LINK_SLOTS: u64 = 4;

/// The name of the thread that writes the column env.
pub const WRITER_THREAD: &str = "columns-writer";

/// Columns the writer takes off its queue for one batch \[est\]: one full block.
const MAX_BATCH: usize = 128;

/// The bounds of a [`ColumnIngest`] (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestLimits {
    /// Columns queued at once, from arrival until stored or dropped.
    pub max_items: usize,
    /// Their SSZ bytes.
    pub max_bytes: usize,
    /// The bytes of the copies the queued columns hold past their sidecars: their cells for the
    /// KZG check, as `KzgCellProof`s and encoded, and the SSZ for the write. A column charges
    /// them before the storage contract and holds them until it is stored or dropped; one whose
    /// copies do not fit is dropped as queue-full.
    pub max_copy_bytes: usize,
    /// Bytes, queued and copies together, at which `probe_column_buffer_alert` turns on.
    pub alert_bytes: usize,
    /// How long a column waits for its block root, from the arrival of the first column of
    /// that root.
    pub root_wait: Duration,
    /// How often a seated root is asked again.
    pub root_retry: Duration,
    /// Roots seated in the wait at once.
    pub max_waiting_roots: usize,
    /// Columns waiting for seated roots at once, over every root.
    pub max_waiting_columns: usize,
    /// Columns waiting for first asks at once, over every root. With `max_waiting_columns`
    /// below `max_items`, so columns of made-up roots can never fill the queue.
    pub max_asking_columns: usize,
    /// How long a root whose wait ran out, or that the reference refused, is remembered, its
    /// columns dropped without a request.
    pub unknown_root_ttl: Duration,
    /// First asks of column roots a second.
    pub first_asks_per_sec: u32,
    /// First asks saved up for a burst, at most.
    pub first_ask_burst: u32,
    /// Retries of seated roots a second: at least a retry of every seat every `root_retry`.
    pub retries_per_sec: u32,
    /// Columns waiting on the lookups of announced roots at once, over every root. A column
    /// past it takes the root wait, with its caps.
    pub max_announced_columns: usize,
}

impl Default for IngestLimits {
    /// 512 columns (four blocks at full custody), 64 MiB queued and 64 MiB of copies \[est\],
    /// the alert at [`COLUMN_BUFFER_ALERT_BYTES`], and the root wait's `DEFAULT_*` constants.
    fn default() -> Self {
        Self {
            max_items: 512,
            max_bytes: 64 << 20,
            max_copy_bytes: 64 << 20,
            alert_bytes: COLUMN_BUFFER_ALERT_BYTES,
            root_wait: DEFAULT_ROOT_WAIT,
            root_retry: DEFAULT_ROOT_RETRY,
            max_waiting_roots: DEFAULT_MAX_WAITING_ROOTS,
            max_waiting_columns: DEFAULT_MAX_WAITING_COLUMNS,
            max_asking_columns: DEFAULT_MAX_ASKING_COLUMNS,
            unknown_root_ttl: DEFAULT_UNKNOWN_ROOT_TTL,
            first_asks_per_sec: DEFAULT_FIRST_ASKS_PER_SEC,
            first_ask_burst: DEFAULT_FIRST_ASK_BURST,
            retries_per_sec: DEFAULT_RETRIES_PER_SEC,
            max_announced_columns: DEFAULT_MAX_ANNOUNCED_COLUMNS,
        }
    }
}

/// Why [`IngestLimits`] cannot bound a store ([`IngestLimits::validate`]).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum LimitsError {
    /// A limit that must be above zero is zero: no column would ever be queued, asked about or
    /// waited for, or retries would spin.
    #[error("{0} must be above zero")]
    Zero(&'static str),
    /// The retry budget cannot retry every seat every `root_retry`, so seated roots would take
    /// turns and starve.
    #[error(
        "retries_per_sec {retries_per_sec} cannot retry {max_waiting_roots} seats every \
         {root_retry:?}"
    )]
    RetryShare {
        retries_per_sec: u32,
        max_waiting_roots: usize,
        root_retry: Duration,
    },
    /// The reference view has fewer lookup places than the lookups the root wait can hold in
    /// flight at once: a retry of every seat and every first ask still waiting on a slow
    /// reference ([`IngestLimits::first_asks_in_flight`]). A first ask for a known root could
    /// then find every place taken.
    #[error(
        "the reference view's max_in_flight {max_in_flight} must be at least max_waiting_roots \
         {max_waiting_roots} + first asks in flight {first_asks_in_flight}"
    )]
    LookupPlacesShort {
        max_in_flight: usize,
        max_waiting_roots: usize,
        first_asks_in_flight: usize,
    },
    /// The root wait and the announced lookups could hold every queue place, leaving none for
    /// columns of known roots.
    #[error(
        "max_waiting_columns {waiting} + max_asking_columns {asking} + max_announced_columns \
         {announced} must stay below max_items {max_items}"
    )]
    WaitsFillTheQueue {
        waiting: usize,
        asking: usize,
        announced: usize,
        max_items: usize,
    },
}

impl IngestLimits {
    /// Checks that these limits bound a store: every rate, burst and duration above zero, the
    /// retry budget covering a retry of every seat each `root_retry`, and the root wait's
    /// columns below the queue's places.
    ///
    /// # Errors
    ///
    /// [`LimitsError`]: the first limit that does not hold.
    pub fn validate(&self) -> Result<(), LimitsError> {
        let zero = [
            ("max_items", self.max_items == 0),
            ("root_wait", self.root_wait.is_zero()),
            ("root_retry", self.root_retry.is_zero()),
            ("first_asks_per_sec", self.first_asks_per_sec == 0),
            ("first_ask_burst", self.first_ask_burst == 0),
            ("retries_per_sec", self.retries_per_sec == 0),
        ];
        if let Some((name, _)) = zero.into_iter().find(|(_, zero)| *zero) {
            return Err(LimitsError::Zero(name));
        }
        // Integer math: retries_per_sec × root_retry ≥ max_waiting_roots, in nanoseconds.
        let retries = u128::from(self.retries_per_sec) * self.root_retry.as_nanos();
        if retries < self.max_waiting_roots as u128 * 1_000_000_000 {
            return Err(LimitsError::RetryShare {
                retries_per_sec: self.retries_per_sec,
                max_waiting_roots: self.max_waiting_roots,
                root_retry: self.root_retry,
            });
        }
        let waits = self
            .max_waiting_columns
            .saturating_add(self.max_asking_columns)
            .saturating_add(self.max_announced_columns);
        if waits >= self.max_items {
            return Err(LimitsError::WaitsFillTheQueue {
                waiting: self.max_waiting_columns,
                asking: self.max_asking_columns,
                announced: self.max_announced_columns,
                max_items: self.max_items,
            });
        }
        Ok(())
    }

    /// First asks that can be in flight at once against a reference view whose lookups end
    /// within `timeout`: `first_ask_burst`, and one turn per first-ask interval through the
    /// whole timeout, rounded up. The first-ask budget books turns by the generic cell rate
    /// algorithm, so any `timeout` of time holds at most that many turns, and a first ask that
    /// found no place asked nothing and holds none.
    #[must_use]
    pub fn first_asks_in_flight(&self, timeout: Duration) -> usize {
        // Integer math: ceil(first_asks_per_sec × timeout), in nanoseconds.
        let turns =
            (u128::from(self.first_asks_per_sec) * timeout.as_nanos()).div_ceil(1_000_000_000);
        let burst = usize::try_from(self.first_ask_burst).unwrap_or(usize::MAX);
        usize::try_from(turns)
            .unwrap_or(usize::MAX)
            .saturating_add(burst)
    }

    /// [`Self::validate`], and that the reference view's lookup places (`refs`) cover every
    /// lookup the root wait can hold in flight at once: a retry of each seat (one at a time per
    /// seat) and [`Self::first_asks_in_flight`] for the view's timeout. So retries and first
    /// asks that all hang on a slow reference never take the place of a first ask.
    ///
    /// # Errors
    ///
    /// [`LimitsError`]: the first limit that does not hold.
    pub fn validate_for(&self, refs: &RefLimits) -> Result<(), LimitsError> {
        self.validate()?;
        let first_asks_in_flight = self.first_asks_in_flight(refs.timeout);
        if refs.max_in_flight < self.max_waiting_roots.saturating_add(first_asks_in_flight) {
            return Err(LimitsError::LookupPlacesShort {
                max_in_flight: refs.max_in_flight,
                max_waiting_roots: self.max_waiting_roots,
                first_asks_in_flight,
            });
        }
        Ok(())
    }
}

/// The column store's queue and write metrics.
#[derive(Debug, Clone, Default)]
pub struct QueueMetrics {
    queue_dropped: Counter,
    stored: Counter,
    buffer_bytes: Gauge,
    buffer_alert: Gauge,
}

impl QueueMetrics {
    /// Registers `probe_column_queue_dropped_total`, `probe_column_stored_total`,
    /// `probe_column_buffer_bytes` and `probe_column_buffer_alert` in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self::default();
        registry.register(
            "probe_column_queue_dropped",
            "Gossip column sidecars dropped because the pending queue was full (items or bytes)",
            metrics.queue_dropped.clone(),
        );
        registry.register(
            "probe_column_stored",
            "Gossip column sidecars written to the column env",
            metrics.stored.clone(),
        );
        registry.register(
            "probe_column_buffer_bytes",
            "Bytes the queued gossip column sidecars hold, from arrival until stored or dropped: \
             their SSZ and the copies for the KZG check and the write",
            metrics.buffer_bytes.clone(),
        );
        registry.register(
            "probe_column_buffer_alert",
            "1 while probe_column_buffer_bytes is at or above the alert level, else 0",
            metrics.buffer_alert.clone(),
        );
        metrics
    }

    /// Columns dropped because the queue was full, so far.
    #[must_use]
    pub fn queue_dropped(&self) -> u64 {
        self.queue_dropped.get()
    }

    /// Columns written to the column env, so far.
    #[must_use]
    pub fn stored(&self) -> u64 {
        self.stored.get()
    }
}

/// The lowest slot a column was ever stored at, as persisted with the columns; `None` before
/// the first one.
///
/// A historical minimum, not proof that anything from there on is held: one column lowers it
/// even if the block's other custody columns never arrive, pruning (finality or reorg) leaves
/// it below the data that remains, and raising custody does not move it. So it is never the
/// Status `earliest_available_slot` on its own: that is [`earliest_servable_slot`], which also
/// takes the finalized-slot watermark and `cgc_set_slot`.
///
/// # Errors
///
/// The column env's.
pub fn first_stored_column_slot(
    reader: &ColumnReader,
) -> Result<Option<Slot>, cl_chain_columns::Error> {
    reader.first_stored_slot()
}

/// The lowest slot the column store may claim to serve: the highest of `first_stored_slot`
/// ([`first_stored_column_slot`]), the slot after the finalized-slot watermark
/// (`finalized_slot`, [`ColumnReader::finalized_slot`]: everything at or below it is pruned),
/// `cgc_set_slot` (columns before it are of a smaller custody) and `contiguous_from`
/// ([`ColumnReader::contiguous_from`]: a blob-carrying block before it is not held, after
/// downtime or a block whose columns all missed gossip). `None` while nothing was stored, or if
/// the watermark is the last slot. The Status `earliest_available_slot`, once the probe serves
/// columns, is this value.
///
/// Still not proof that every custody column from there on is held: a block whose columns
/// partly arrived is stored, and a range answer ends before it (`crate::reqresp`).
#[must_use]
pub fn earliest_servable_slot(
    first_stored_slot: Option<Slot>,
    finalized_slot: Option<Slot>,
    cgc_set_slot: Slot,
    contiguous_from: Option<Slot>,
) -> Option<Slot> {
    let after_finalized = match finalized_slot {
        Some(slot) => slot.checked_add(1)?,
        None => 0,
    };
    Some(
        first_stored_slot?
            .max(after_finalized)
            .max(cgc_set_slot)
            .max(contiguous_from.unwrap_or(0)),
    )
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Pending {
    items: usize,
    /// The queued sidecars' SSZ bytes.
    bytes: usize,
    /// The bytes of their copies ([`copy_bytes`]).
    copies: usize,
}

impl Pending {
    /// Everything the queue holds: the sidecars and their copies.
    fn total(self) -> usize {
        self.bytes.saturating_add(self.copies)
    }
}

/// `KZGCommitment` and `KZGProof` are both 48-byte compressed G1 points.
const KZG_POINT_BYTES: usize = 48;

/// The bytes of the copies a column's KZG check makes: its cells as [`KzgCellProof`]s for
/// cl-verify (`storage_contract`), and the request's protobuf encoding of them (no larger: each
/// field's tag and length cost less than the struct they are encoded from). Held until the
/// request leaves the verify client's outbound queue ([`KzgVerifier::verify_cells_holding`]).
fn kzg_copy_bytes<E: EthSpec>(sidecar: &gloas::DataColumnSidecar<E>) -> usize {
    let cells: usize = sidecar
        .column
        .iter()
        .map(|cell| std::mem::size_of::<KzgCellProof>() + 2 * KZG_POINT_BYTES + cell.len())
        .sum();
    cells.saturating_mul(2)
}

/// The pending queue's accounting.
struct Queue {
    limits: IngestLimits,
    pending: Mutex<Pending>,
    metrics: QueueMetrics,
}

impl Queue {
    /// A place for a column of `bytes`, or `None` if it would pass a cap.
    fn admit(self: &Arc<Self>, bytes: usize) -> Option<Place> {
        let mut pending = self.lock();
        let items = pending.items + 1;
        let total = pending.bytes.checked_add(bytes)?;
        if items > self.limits.max_items || total > self.limits.max_bytes {
            return None;
        }
        pending.items = items;
        pending.bytes = total;
        self.publish(*pending);
        Some(Place {
            queue: Arc::clone(self),
            bytes,
            copies: 0,
        })
    }

    /// Charges `bytes` of copies to the copy budget; `false`, charging nothing, if they would
    /// pass [`IngestLimits::max_copy_bytes`].
    fn charge_copies(&self, bytes: usize) -> bool {
        let mut pending = self.lock();
        match pending.copies.checked_add(bytes) {
            Some(copies) if copies <= self.limits.max_copy_bytes => {
                pending.copies = copies;
                self.publish(*pending);
                true
            }
            _ => false,
        }
    }

    fn release(&self, bytes: usize, copies: usize) {
        let mut pending = self.lock();
        pending.items -= 1;
        pending.bytes -= bytes;
        pending.copies -= copies;
        self.publish(*pending);
    }

    fn release_copies(&self, copies: usize) {
        let mut pending = self.lock();
        pending.copies -= copies;
        self.publish(*pending);
    }

    /// Counts a column dropped because the queue was full, and logs it.
    fn drop_full<E: EthSpec>(&self, column: &GossipColumn<E>, bytes: usize) {
        self.metrics.queue_dropped.inc();
        tracing::debug!(
            index = column.sidecar.index,
            slot = column.sidecar.slot,
            subnet = column.subnet_id,
            bytes,
            "column queue full: column sidecar dropped"
        );
    }

    /// Sets the gauges; called under the lock, so they move in the queue's order.
    fn publish(&self, pending: Pending) {
        let metrics = &self.metrics;
        let total = pending.total();
        metrics
            .buffer_bytes
            .set(i64::try_from(total).unwrap_or(i64::MAX));
        let alert = total >= self.limits.alert_bytes;
        if alert != (metrics.buffer_alert.get() == 1) {
            if alert {
                tracing::warn!(bytes = total, "column buffer above its alert level");
            } else {
                tracing::info!(bytes = total, "column buffer back below its alert level");
            }
            metrics.buffer_alert.set(i64::from(alert));
        }
    }

    /// The counts are updated together under the lock, so a panic cannot leave them half-set.
    fn lock(&self) -> MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One column's place in the pending queue, and the copies it charged, given back when dropped.
struct Place {
    queue: Arc<Queue>,
    bytes: usize,
    copies: usize,
}

impl Place {
    /// Charges the copies of the column's KZG check (`kzg`) and of its SSZ for the write
    /// (`ssz`) together ([`Queue::charge_copies`]). The SSZ copy stays charged to this place,
    /// which the write holds; the KZG copies go to the returned [`Charge`], which the check
    /// hands to cl-verify's client. `None`, charging nothing, if they do not fit.
    fn charge_copies(&mut self, kzg: usize, ssz: usize) -> Option<Charge> {
        if !self.queue.charge_copies(kzg.checked_add(ssz)?) {
            return None;
        }
        self.copies += ssz;
        Some(Charge {
            queue: Arc::clone(&self.queue),
            bytes: kzg,
        })
    }
}

/// Copies charged apart from a place, given back when dropped.
struct Charge {
    queue: Arc<Queue>,
    bytes: usize,
}

impl std::ops::Drop for Charge {
    fn drop(&mut self) {
        self.queue.release_copies(self.bytes);
    }
}

impl std::ops::Drop for Place {
    fn drop(&mut self) {
        self.queue.release(self.bytes, self.copies);
    }
}

/// One verified column for the writer thread, holding its queue place until written.
struct Write {
    slot: Slot,
    root: Root,
    index: u64,
    ssz: Vec<u8>,
    /// The block's link to the stored block before it on its chain.
    link: BlockLink,
    _place: Place,
}

/// What the writer thread takes off its queue.
enum Job {
    /// A column to store.
    Write(Write),
    /// Confirmed once every job before it is done, the settle of pending links after them
    /// included ([`ColumnIngest::settled`]).
    Barrier {
        ack: tokio::sync::oneshot::Sender<()>,
        /// The one barrier's turn on the queue, held until the writer took it: a wait given up
        /// meanwhile leaves the barrier queued, and no second one joins it.
        one: tokio::sync::OwnedMutexGuard<()>,
    },
}

/// What a column's task works with.
struct Shared<A, E, V, S, C> {
    refs: Arc<RefView<A, E>>,
    custody: Custody<S, C>,
    contract: ColumnContract<V>,
    waits: RootWaits,
    /// The column env, for the chain links.
    store: Arc<ColumnWriter>,
}

/// The forward-only custody column store (see the module docs).
///
/// [`ColumnIngest::on_column`] runs each column on its own task of the current tokio runtime,
/// at most [`IngestLimits::max_items`] at a time. Dropping the store aborts those tasks, lets the
/// writer thread finish the columns already handed to it and joins it.
pub struct ColumnIngest<A, E, V, S, C> {
    shared: Arc<Shared<A, E, V, S, C>>,
    queue: Arc<Queue>,
    tasks: Mutex<JoinSet<()>>,
    /// The only strong sender: the writer thread ends once it is dropped and its queue drained.
    writes: Option<mpsc::Sender<Job>>,
    /// Held by the one barrier on the writer's queue, so the queue keeps room for every place.
    barrier: Arc<tokio::sync::Mutex<()>>,
    writer_thread: Option<JoinHandle<()>>,
    writer: Arc<ColumnWriter>,
}

impl<A, E, V, S, C> ColumnIngest<A, E, V, S, C>
where
    A: ReferenceApi + BlockApi + 'static,
    E: EthSpec,
    V: KzgVerifier + 'static,
    S: Send + Sync + 'static,
    C: Send + Sync + 'static,
{
    /// A store checking columns against `refs`, `custody` and `contract`, writing them through
    /// `writer` on a new [`WRITER_THREAD`] thread, with its queue metrics in `metrics`.
    ///
    /// # Errors
    ///
    /// `InvalidInput` if `limits` do not bound a store with `refs`
    /// ([`IngestLimits::validate_for`]); the thread could not be spawned.
    pub fn start(
        refs: RefView<A, E>,
        custody: Custody<S, C>,
        contract: ColumnContract<V>,
        writer: Arc<ColumnWriter>,
        limits: IngestLimits,
        metrics: QueueMetrics,
    ) -> std::io::Result<Self> {
        limits
            .validate_for(&refs.limits())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // Every write holds a queue place, and one barrier at most is queued ([`Self::settled`]),
        // so the channel never holds more than `max_items` writes and that barrier.
        let (writes, jobs) = mpsc::channel(limits.max_items.max(1) + 1);
        let writer_thread = std::thread::Builder::new()
            .name(WRITER_THREAD.into())
            .spawn({
                let writer = Arc::clone(&writer);
                let dropped = contract.metrics.clone();
                let metrics = metrics.clone();
                move || run_writer(writer.as_ref(), jobs, &dropped, &metrics)
            })?;
        Ok(Self {
            shared: Arc::new(Shared {
                refs: Arc::new(refs),
                custody,
                contract,
                waits: RootWaits::new(limits),
                store: Arc::clone(&writer),
            }),
            queue: Arc::new(Queue {
                limits,
                pending: Mutex::default(),
                metrics,
            }),
            tasks: Mutex::default(),
            writes: Some(writes),
            barrier: Arc::default(),
            writer_thread: Some(writer_thread),
            writer,
        })
    }

    /// Roots the reference view is looking up now.
    #[cfg(test)]
    pub(crate) fn refs_in_flight(&self) -> usize {
        self.shared.refs.in_flight()
    }

    /// Whether the reference view has cached `root`.
    #[cfg(test)]
    pub(crate) fn refs_cached(&self, root: &Root) -> bool {
        self.shared.refs.cached_block(root).is_some()
    }

    /// Follows the reference's head from `source` ([`follow_head`]) on a task of this store,
    /// until the store is dropped: each root the reference announces is looked up ahead of its
    /// columns, in places of its own. Must be called within a tokio runtime.
    pub fn follow_head<H>(&self, source: H, config: HeadFollow)
    where
        H: HeadSource + 'static,
    {
        let refs = Arc::clone(&self.shared.refs);
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        tasks.spawn(follow_head(source, refs, config));
    }

    /// Takes a column sidecar from gossip; see the module docs. The verdict is always
    /// [`Verdict::Ignore`]: nothing is re-broadcast. Must be called within a tokio runtime.
    pub fn on_column(&self, column: GossipColumn<E>) -> Verdict {
        let bytes = column.sidecar.ssz_bytes_len();
        let Some(place) = self.queue.admit(bytes) else {
            self.queue.drop_full(&column, bytes);
            return Verdict::Ignore;
        };
        let Some(writes) = self.writes.as_ref().map(mpsc::Sender::downgrade) else {
            return Verdict::Ignore;
        };
        let arrived = Instant::now();
        let shared = Arc::clone(&self.shared);
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(finished) = tasks.try_join_next() {
            if let Err(e) = finished {
                tracing::error!(error = %e, "a column task ended abnormally");
            }
        }
        tasks.spawn(async move { shared.process(column, place, &writes, arrived).await });
        Verdict::Ignore
    }
}

impl<A, E, V, S, C> ColumnIngest<A, E, V, S, C> {
    /// Waits until the writer has done everything handed to it so far: the writes, and the
    /// settle of pending links after them ([`ColumnWriter::settle_pending`]). A column gives its
    /// queue place back once written, before that settle, so [`Self::pending`] at 0 alone does
    /// not show that the store stopped changing; 0 again after this does. `false` if the writer
    /// is gone.
    pub async fn settled(&self) -> bool {
        match self.writes.as_ref() {
            Some(writes) => barrier(writes, &self.barrier).await,
            None => false,
        }
    }

    /// Columns queued now: arrived, neither stored nor dropped yet.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue.lock().items
    }

    /// Their SSZ bytes.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.queue.lock().bytes
    }

    /// The bytes of their copies charged now ([`IngestLimits::max_copy_bytes`]).
    #[must_use]
    pub fn copy_bytes(&self) -> usize {
        self.queue.lock().copies
    }

    /// Roots columns wait for now.
    #[cfg(test)]
    pub(crate) fn waiting_roots(&self) -> usize {
        self.shared.waits.roots()
    }

    /// The custody the columns are checked against.
    #[must_use]
    pub fn custody(&self) -> &Custody<S, C> {
        &self.shared.custody
    }

    /// The storage contract, with its drop counts.
    #[must_use]
    pub fn contract(&self) -> &ColumnContract<V> {
        &self.shared.contract
    }

    /// [`first_stored_column_slot`] of this store's env.
    ///
    /// # Errors
    ///
    /// The column env's.
    pub fn first_stored_column_slot(&self) -> Result<Option<Slot>, cl_chain_columns::Error> {
        first_stored_column_slot(self.writer.reader())
    }
}

impl<A, E, V, S, C> std::ops::Drop for ColumnIngest<A, E, V, S, C> {
    fn drop(&mut self) {
        self.tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .abort_all();
        drop(self.writes.take());
        if let Some(thread) = self.writer_thread.take() {
            if thread.join().is_err() {
                tracing::error!("the {WRITER_THREAD} thread panicked");
            }
        }
    }
}

impl<A, E, V, S, C> Shared<A, E, V, S, C>
where
    A: ReferenceApi + BlockApi,
    E: EthSpec,
    V: KzgVerifier,
{
    /// Steps 2 to 5 of the module docs, then hands the column to the writer thread.
    async fn process(
        &self,
        column: GossipColumn<E>,
        mut place: Place,
        writes: &mpsc::WeakSender<Job>,
        arrived: Instant,
    ) {
        let metrics = &self.contract.metrics;
        if let Err(reason) = local_check(&column, &self.custody) {
            metrics.drop_column(&column, reason);
            return;
        }
        let root = column.sidecar.beacon_block_root.0;
        let index = column.sidecar.index;
        let block = match vouched_block(&self.refs, &self.waits, root, index, arrived).await {
            Ok(block) => block,
            Err(reason) => {
                metrics.drop_column(&column, reason);
                return;
            }
        };
        // Charged before the copies exist: the contract copies the cells for cl-verify, and
        // the write copies the SSZ.
        let (kzg, ssz) = (
            kzg_copy_bytes(&column.sidecar),
            column.sidecar.ssz_bytes_len(),
        );
        let Some(charge) = place.charge_copies(kzg, ssz) else {
            place.queue.drop_full(&column, kzg.saturating_add(ssz));
            return;
        };
        let held: Held = Box::new(charge);
        let checked = vouched_contract(&column, &block, &self.custody, &self.contract, held);
        let Ok(verified) = checked.await else {
            return;
        };
        let link = self.link(&block).await;
        let sidecar = verified.sidecar();
        let write = Write {
            slot: sidecar.slot,
            root,
            index: sidecar.index,
            ssz: sidecar.as_ssz_bytes(),
            link,
            _place: place,
        };
        // Never blocks: the channel has room for every queue place. A store being dropped has
        // no writer any more.
        let sent = writes
            .upgrade()
            .map(|tx| tx.try_send(Job::Write(write)).is_ok());
        if sent != Some(true) {
            metrics.drop_column(&column, Drop::StoreFailed);
        }
    }
}

/// Step 3 of the module docs: the block the reference vouches for as `root`, for the column
/// `index` that arrived at `arrived`.
/// - A root the reference view has cached needs no wait and no place in one, and its block goes
///   to the contract, so it is never looked up twice.
/// - A root with a live announcement shares its lookup in the announced places, with no
///   first-ask turn and no place in the root wait, if fewer than
///   [`IngestLimits::max_announced_columns`] columns wait so. A round without an answer is
///   asked again once per [`IngestLimits::root_retry`], or at once when the root is cached,
///   while the announcement lives and the wait lasts.
/// - Any other root, or an announced one past those bounds, waits in `waits`.
async fn vouched_block<A, E>(
    refs: &RefView<A, E>,
    waits: &RootWaits,
    root: Root,
    index: u64,
    arrived: Instant,
) -> Result<Arc<RefBlock>, Drop>
where
    A: ReferenceApi + BlockApi,
    E: EthSpec,
{
    if let Some(block) = refs.cached_block(&root) {
        return Ok(block);
    }
    // A place among the columns waiting on announced lookups, taken only for a root with a
    // live announcement, and held while the column asks.
    let limits = waits.limits();
    let deadline = arrived + limits.root_wait;
    if refs.is_announced(&root) {
        if let Some(_place) = waits.hold_announced() {
            // `None` once the announcement is spent or past its life: the root wait.
            loop {
                let ask = tokio::time::timeout_at(deadline, refs.lookup_announced(root));
                let e = match ask.await {
                    Err(_) => return Err(Drop::RootTimeout),
                    Ok(None) => break,
                    Ok(Some(Ok(block))) => return Ok(block),
                    Ok(Some(Err(e))) => e,
                };
                tracing::debug!(error = %e, "announced root not looked up yet");
                let next = Instant::now() + limits.root_retry;
                if next >= deadline {
                    break;
                }
                tokio::select! {
                    () = tokio::time::sleep_until(next) => {}
                    () = refs.until_cached(root) => {}
                }
            }
        }
    }
    let lookup = || async {
        match refs.lookup(root).await {
            Ok(block) => Answer::Known(block),
            // The reference names the root but its block does not establish it.
            Err(RefError::Block(_)) => Answer::Refused,
            // Not asked: every lookup place is taken.
            Err(RefError::Busy(_)) => Answer::Busy,
            // Not known yet, or the reference is slow or busy: ask again.
            Err(e) => {
                tracing::trace!(error = %e, "column root not known yet");
                Answer::Retry
            }
        }
    };
    let cached = refs.until_cached(root);
    waits
        .wait_or_cached(root, index, arrived, cached, lookup)
        .await
}

impl<A, E, V, S, C> Shared<A, E, V, S, C>
where
    A: ReferenceApi + BlockApi,
    E: EthSpec,
{
    /// What the writer links `block` by (step 6 of the module docs): [`BlockLink::Pending`] of
    /// the nearest ancestor that is stored or carries blobs, [`BlockLink::Start`] or
    /// [`BlockLink::Gap`].
    async fn link(&self, block: &RefBlock) -> BlockLink {
        let reader = self.store.reader();
        let cgc_set_slot = self.custody.cgc_set_slot();
        let Ok(finalized) = reader.finalized_slot() else {
            return BlockLink::Gap;
        };
        let held_before = |slot: Slot| slot < cgc_set_slot || finalized.is_some_and(|f| slot <= f);
        let mut parent = block.parent_root;
        for _ in 0..=MAX_LINK_WALK {
            match reader.slot_of(&parent) {
                // Stored now; the writer links it, or starts the chain there if finality pruned
                // it before the write.
                Ok(Some(slot)) => return BlockLink::Pending(parent, slot),
                Ok(None) => {}
                Err(_) => return BlockLink::Gap,
            }
            let Ok(ancestor) = self.refs.lookup(parent).await else {
                return BlockLink::Gap;
            };
            if held_before(ancestor.slot) {
                return BlockLink::Start;
            }
            if !ancestor.commitments.is_empty() {
                // Not stored yet: the writer decides once the batches before this one are in.
                return BlockLink::Pending(ancestor.root, ancestor.slot);
            }
            parent = ancestor.parent_root;
        }
        BlockLink::Gap
    }
}

/// Where the writer thread stores columns: the column env.
trait ColumnSink {
    /// [`ColumnWriter::write_block_columns_partial`]: on a failure, what was committed first.
    fn write_block_columns(
        &self,
        slot: Slot,
        root: &Root,
        link: BlockLink,
        columns: &[Column<'_>],
    ) -> Result<WriteReport, WriteFailed>;

    /// [`ColumnWriter::settle_pending`].
    fn settle_pending(&self, before_slot: Slot) -> cl_chain_columns::Result<usize>;
}

impl ColumnSink for ColumnWriter {
    fn write_block_columns(
        &self,
        slot: Slot,
        root: &Root,
        link: BlockLink,
        columns: &[Column<'_>],
    ) -> Result<WriteReport, WriteFailed> {
        ColumnWriter::write_block_columns_partial(self, slot, root, link, columns)
    }

    fn settle_pending(&self, before_slot: Slot) -> cl_chain_columns::Result<usize> {
        ColumnWriter::settle_pending(self, before_slot)
    }
}

/// Queues a barrier on the writer's queue `writes` and waits until the writer confirms it
/// ([`ColumnIngest::settled`]); `false` if the writer is gone. `one` keeps one barrier at most
/// on the queue, so it keeps room for every place's write: its guard goes with the barrier and
/// is released by the writer, so a wait given up after queueing it still holds the turn.
async fn barrier(writes: &mpsc::Sender<Job>, one: &Arc<tokio::sync::Mutex<()>>) -> bool {
    let one = Arc::clone(one).lock_owned().await;
    let (ack, acked) = tokio::sync::oneshot::channel();
    if writes.send(Job::Barrier { ack, one }).await.is_err() {
        return false;
    }
    acked.await.is_ok()
}

/// The writer thread: takes what is queued, up to [`MAX_BATCH`] columns or a barrier, writes
/// it, settles the pending links, and then confirms the barrier, until every sender is gone.
fn run_writer(
    writer: &impl ColumnSink,
    mut jobs: mpsc::Receiver<Job>,
    dropped: &ColumnMetrics,
    metrics: &QueueMetrics,
) {
    while let Some(first) = jobs.blocking_recv() {
        let mut batch = Vec::new();
        let mut barrier = None;
        let mut next = Some(first);
        while let Some(job) = next.take() {
            match job {
                Job::Write(write) => batch.push(write),
                // What comes after it waits for the next turn.
                Job::Barrier { ack, one } => {
                    barrier = Some((ack, one));
                    break;
                }
            }
            if batch.len() < MAX_BATCH {
                next = jobs.try_recv().ok();
            }
        }
        let highest = write_batch(writer, batch, dropped, metrics);
        // Blocks still waiting for an ancestor that never came, once the store is past them.
        if let Some(highest) = highest {
            if let Err(e) = writer.settle_pending(highest.saturating_sub(PENDING_LINK_SLOTS)) {
                tracing::warn!(error = %e, "pending column links not settled");
            }
        }
        if let Some((ack, one)) = barrier {
            // Nobody waits for it any more if the receiver is gone.
            let _ = ack.send(());
            drop(one);
        }
    }
}

/// Writes `batch` block by block, in slot order, each block of the batch in one
/// [`ColumnWriter::write_columns`] call. That call commits in transactions of at most
/// [`MAX_COLUMNS_PER_TXN`](cl_chain_columns::MAX_COLUMNS_PER_TXN) columns while it holds off
/// pruning, so a reorg prune lands before or after the batch's columns of a block, never
/// between two of its transactions. Columns of a block that verify later come in a later batch;
/// once the block was pruned as an orphan, the column env refuses them
/// ([`cl_chain_columns::Error::RootOrphaned`], counted as `store_failed`), so no batch brings an
/// orphan back with some of its columns. A call that fails partway leaves the transactions
/// before the failed one committed: those columns count as stored, the rest as `store_failed`.
/// A column that arrived twice is written once. Each column gives its queue place back once
/// written or dropped.
fn write_batch(
    writer: &impl ColumnSink,
    batch: Vec<Write>,
    dropped: &ColumnMetrics,
    metrics: &QueueMetrics,
) -> Option<Slot> {
    let mut highest = None;
    let mut blocks: BTreeMap<(Slot, Root), BTreeMap<u64, Write>> = BTreeMap::new();
    for write in batch {
        blocks
            .entry((write.slot, write.root))
            .or_default()
            .insert(write.index, write);
    }
    for ((slot, root), columns) in blocks {
        let ssz: Vec<Column<'_>> = columns
            .values()
            .map(|w| Column {
                index: w.index,
                ssz: &w.ssz,
            })
            .collect();
        // The columns of one block agree on its link but for a walk that failed: any link
        // beats a gap.
        let link = columns
            .values()
            .map(|w| w.link)
            .find(|link| *link != BlockLink::Gap)
            .unwrap_or(BlockLink::Gap);
        highest = highest.max(Some(slot));
        match writer.write_block_columns(slot, &root, link, &ssz) {
            Ok(report) => {
                metrics.stored.inc_by(report.columns as u64);
            }
            Err(failed) => {
                // The transactions before the failed one stay committed: their columns are
                // stored, and only the rest is dropped.
                let committed = failed.committed.columns.min(ssz.len());
                metrics.stored.inc_by(committed as u64);
                tracing::warn!(
                    error = %failed.error,
                    slot,
                    root = %hex::encode(root),
                    committed,
                    dropped = ssz.len() - committed,
                    "column write failed: column sidecars dropped"
                );
                for _ in committed..ssz.len() {
                    dropped.count(Drop::StoreFailed);
                }
            }
        }
    }
    highest
}

#[cfg(test)]
mod tests {
    use super::super::fake::Silent;
    use super::super::DEFAULT_API_TIMEOUT;
    use super::*;
    use cl_chain_columns::MAX_COLUMNS_PER_TXN;

    fn metrics() -> (ColumnMetrics, QueueMetrics) {
        (ColumnMetrics::default(), QueueMetrics::default())
    }

    fn queue(limits: IngestLimits) -> Arc<Queue> {
        Arc::new(Queue {
            limits,
            pending: Mutex::default(),
            metrics: QueueMetrics::default(),
        })
    }

    fn write(queue: &Arc<Queue>, slot: Slot, root: Root, index: u64) -> Write {
        let ssz = format!("sidecar {slot}/{index}").into_bytes();
        Write {
            slot,
            root,
            index,
            _place: queue.admit(ssz.len()).unwrap(),
            ssz,
            link: BlockLink::Gap,
        }
    }

    #[test]
    fn a_block_is_written_in_chunks_of_at_most_sixteen() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let queue = queue(IngestLimits::default());
        let (dropped, metrics) = metrics();
        let mut batch: Vec<_> = (0..20).map(|i| write(&queue, 9, [1; 32], i)).collect();
        // A copy of a column already in the batch, and another block's column.
        batch.push(write(&queue, 9, [1; 32], 3));
        batch.push(write(&queue, 10, [2; 32], 0));
        let before = writer.rw_txns_committed();
        write_batch(&writer, batch, &dropped, &metrics);
        assert_eq!(writer.rw_txns_committed(), before + 3, "16 + 4, then 1");
        assert_eq!(
            writer.reader().columns_for_root(&[1; 32]).unwrap().len(),
            20
        );
        assert_eq!(metrics.stored(), 21);
        assert_eq!(queue.lock().items, 0, "every place is given back");
    }

    /// A column env where a reorg prune of `orphan` lands after every `write_columns` call,
    /// counting the calls.
    struct PrunesBetweenCalls<'a> {
        writer: &'a ColumnWriter,
        orphan: Root,
        calls: std::cell::Cell<usize>,
    }

    impl ColumnSink for PrunesBetweenCalls<'_> {
        fn write_block_columns(
            &self,
            slot: Slot,
            root: &Root,
            link: BlockLink,
            columns: &[Column<'_>],
        ) -> Result<WriteReport, WriteFailed> {
            let written = self
                .writer
                .write_block_columns_partial(slot, root, link, columns);
            self.calls.set(self.calls.get() + 1);
            self.writer.prune_orphaned(&[self.orphan]).unwrap();
            written
        }

        fn settle_pending(&self, before_slot: Slot) -> cl_chain_columns::Result<usize> {
            self.writer.settle_pending(before_slot)
        }
    }

    /// A barrier job confirmed to `ack`, holding a turn of its own.
    fn barrier_job(ack: tokio::sync::oneshot::Sender<()>) -> Job {
        let one = Arc::new(tokio::sync::Mutex::new(()))
            .try_lock_owned()
            .unwrap();
        Job::Barrier { ack, one }
    }

    /// A column env whose pending-link settle begins, says so, and waits for `go`.
    struct SlowSettle<'a> {
        writer: &'a ColumnWriter,
        began: std::sync::mpsc::Sender<()>,
        go: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl ColumnSink for SlowSettle<'_> {
        fn write_block_columns(
            &self,
            slot: Slot,
            root: &Root,
            link: BlockLink,
            columns: &[Column<'_>],
        ) -> Result<WriteReport, WriteFailed> {
            self.writer
                .write_block_columns_partial(slot, root, link, columns)
        }

        fn settle_pending(&self, before_slot: Slot) -> cl_chain_columns::Result<usize> {
            self.began.send(()).unwrap();
            self.go.lock().unwrap().recv().unwrap();
            self.writer.settle_pending(before_slot)
        }
    }

    /// The queue empties once the batch is written, before its pending links are settled: the
    /// barrier is confirmed only after that settle, so the store has stopped changing then.
    #[test]
    fn the_barrier_is_confirmed_after_the_settle_of_the_batch_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let queue = queue(IngestLimits::default());
        let (dropped, metrics) = metrics();
        let (began, settling) = std::sync::mpsc::channel();
        let (go, wait) = std::sync::mpsc::channel();
        let sink = SlowSettle {
            writer: &writer,
            began,
            go: Mutex::new(wait),
        };
        let (jobs, received) = mpsc::channel(8);
        std::thread::scope(|scope| {
            scope.spawn(|| run_writer(&sink, received, &dropped, &metrics));
            jobs.blocking_send(Job::Write(write(&queue, 9, [1; 32], 0)))
                .unwrap();
            settling.recv().unwrap();
            assert_eq!(queue.lock().items, 0, "the place is back while it settles");
            let (ack, mut acked) = tokio::sync::oneshot::channel();
            jobs.blocking_send(barrier_job(ack)).unwrap();
            assert!(acked.try_recv().is_err(), "not confirmed while settling");
            go.send(()).unwrap();
            acked.blocking_recv().unwrap();
            assert_eq!(writer.reader().column_count().unwrap(), 1);
            // A barrier with nothing before it is confirmed at once, and writes after it wait
            // for the next turn.
            let (ack, acked) = tokio::sync::oneshot::channel();
            jobs.blocking_send(barrier_job(ack)).unwrap();
            acked.blocking_recv().unwrap();
            drop(jobs);
        });
    }

    /// A wait for the barrier that is given up leaves its barrier queued, and the next wait
    /// queues none until the writer took it: the queue keeps its room for every place's write.
    #[tokio::test]
    async fn a_given_up_barrier_wait_queues_no_second_barrier() {
        // The queue of a store of one place: its write, and one barrier.
        let (writes, mut jobs) = mpsc::channel(2);
        let one: Arc<tokio::sync::Mutex<()>> = Arc::default();
        // Queued, then given up while it waits for the writer.
        assert!(
            tokio::time::timeout(Duration::ZERO, barrier(&writes, &one))
                .await
                .is_err(),
            "it waits for the writer"
        );
        assert_eq!(jobs.len(), 1);
        // A second wait: its barrier waits for the first to be taken.
        let second = tokio::spawn({
            let (writes, one) = (writes.clone(), Arc::clone(&one));
            async move { barrier(&writes, &one).await }
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(jobs.len(), 1, "one barrier queued");
        let queue = queue(IngestLimits::default());
        assert!(
            writes
                .try_send(Job::Write(write(&queue, 9, [1; 32], 0)))
                .is_ok(),
            "the place's write has its room"
        );
        // The writer takes the first barrier: the second is queued, and confirmed.
        let Some(Job::Barrier { ack: first, .. }) = jobs.recv().await else {
            panic!("the first barrier");
        };
        drop(first);
        assert!(matches!(jobs.recv().await, Some(Job::Write(_))));
        let Some(Job::Barrier { ack, .. }) = jobs.recv().await else {
            panic!("the second barrier");
        };
        ack.send(()).unwrap();
        assert!(second.await.unwrap());
    }

    #[test]
    fn a_prune_between_writes_leaves_no_partial_root() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let queue = queue(IngestLimits::default());
        let (dropped, metrics) = metrics();
        let sink = PrunesBetweenCalls {
            writer: &writer,
            orphan: [1; 32],
            calls: std::cell::Cell::new(0),
        };
        // More columns than one transaction carries, of a block a reorg orphans meanwhile.
        let batch: Vec<_> = (0..20).map(|i| write(&queue, 9, [1; 32], i)).collect();
        write_batch(&sink, batch, &dropped, &metrics);
        assert_eq!(sink.calls.get(), 1, "the whole block in one call");
        let stored = writer.reader().columns_for_root(&[1; 32]).unwrap();
        assert!(stored.is_empty(), "{} columns of the orphan", stored.len());
        assert_eq!(queue.lock().items, 0);
    }

    #[test]
    fn a_refused_write_is_counted_and_gives_its_places_back() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer.prune_finalized(20).unwrap();
        let queue = queue(IngestLimits::default());
        let (dropped, metrics) = metrics();
        let batch = vec![write(&queue, 9, [1; 32], 0), write(&queue, 9, [1; 32], 1)];
        write_batch(&writer, batch, &dropped, &metrics);
        assert_eq!(dropped.dropped(Drop::StoreFailed), 2);
        assert_eq!(metrics.stored(), 0);
        assert_eq!(queue.lock().items, 0);
    }

    /// A column env that commits the first transaction of a block's columns, then fails.
    struct FailsAfterOneTxn<'a>(&'a ColumnWriter);

    impl ColumnSink for FailsAfterOneTxn<'_> {
        fn write_block_columns(
            &self,
            slot: Slot,
            root: &Root,
            link: BlockLink,
            columns: &[Column<'_>],
        ) -> Result<WriteReport, WriteFailed> {
            let first = &columns[..columns.len().min(MAX_COLUMNS_PER_TXN)];
            let committed = self
                .0
                .write_block_columns_partial(slot, root, link, first)?;
            if committed.columns == columns.len() {
                return Ok(committed);
            }
            Err(WriteFailed {
                committed,
                error: cl_chain_columns::Error::MapFull,
            })
        }

        fn settle_pending(&self, before_slot: Slot) -> cl_chain_columns::Result<usize> {
            self.0.settle_pending(before_slot)
        }
    }

    #[test]
    fn a_write_that_fails_partway_counts_what_it_committed_as_stored() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let queue = queue(IngestLimits::default());
        let (dropped, metrics) = metrics();
        let batch: Vec<_> = (0..20).map(|i| write(&queue, 9, [1; 32], i)).collect();
        write_batch(&FailsAfterOneTxn(&writer), batch, &dropped, &metrics);
        let stored = writer.reader().columns_for_root(&[1; 32]).unwrap().len();
        assert_eq!(stored, MAX_COLUMNS_PER_TXN);
        assert_eq!(metrics.stored(), 16, "the first transaction's columns");
        assert_eq!(dropped.dropped(Drop::StoreFailed), 4, "the rest only");
        assert_eq!(queue.lock().items, 0);
    }

    #[test]
    fn a_later_batch_cannot_bring_back_a_pruned_root() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let queue = queue(IngestLimits::default());
        let (dropped, metrics) = metrics();
        let first: Vec<_> = (0..4).map(|i| write(&queue, 9, [1; 32], i)).collect();
        write_batch(&writer, first, &dropped, &metrics);
        // A reorg orphans the block between two batches of its columns.
        writer.prune_orphaned(&[[1; 32]]).unwrap();
        let second: Vec<_> = (4..8).map(|i| write(&queue, 9, [1; 32], i)).collect();
        write_batch(&writer, second, &dropped, &metrics);
        assert_eq!(writer.reader().slot_of(&[1; 32]).unwrap(), None);
        assert_eq!(writer.reader().column_count().unwrap(), 0);
        assert_eq!(metrics.stored(), 4);
        assert_eq!(dropped.dropped(Drop::StoreFailed), 4);
        assert_eq!(queue.lock().items, 0);
    }

    #[test]
    fn limits_are_validated() {
        let defaults = IngestLimits::default();
        assert_eq!(defaults.validate(), Ok(()));
        let with = |f: fn(&mut IngestLimits)| {
            let mut limits = defaults;
            f(&mut limits);
            limits.validate()
        };
        assert_eq!(
            with(|l| l.max_items = 0),
            Err(LimitsError::Zero("max_items"))
        );
        assert_eq!(
            with(|l| l.root_wait = Duration::ZERO),
            Err(LimitsError::Zero("root_wait"))
        );
        assert_eq!(
            with(|l| l.root_retry = Duration::ZERO),
            Err(LimitsError::Zero("root_retry"))
        );
        assert_eq!(
            with(|l| l.first_asks_per_sec = 0),
            Err(LimitsError::Zero("first_asks_per_sec"))
        );
        assert_eq!(
            with(|l| l.first_ask_burst = 0),
            Err(LimitsError::Zero("first_ask_burst"))
        );
        assert_eq!(
            with(|l| l.retries_per_sec = 0),
            Err(LimitsError::Zero("retries_per_sec"))
        );
        // The default retry share is exactly a retry of every seat each root_retry.
        let short = with(|l| l.retries_per_sec = DEFAULT_RETRIES_PER_SEC - 1);
        assert!(
            matches!(short, Err(LimitsError::RetryShare { .. })),
            "{short:?}"
        );
        assert!(with(|l| l.max_waiting_roots += 1).is_err());
        assert_eq!(with(|l| l.root_retry = Duration::from_secs(1)), Ok(()));
        // The reference view must have a place for every seat's retry and every first ask that
        // can be in flight at once: the burst, and a turn per interval through the timeout.
        let refs = RefLimits::default();
        assert_eq!(defaults.first_asks_in_flight(refs.timeout), 16 + 32 * 2);
        assert_eq!(defaults.validate_for(&refs), Ok(()));
        let needed = defaults.max_waiting_roots + defaults.first_asks_in_flight(refs.timeout);
        let exact = RefLimits {
            max_in_flight: needed,
            ..refs
        };
        assert_eq!(defaults.validate_for(&exact), Ok(()));
        let tight = RefLimits {
            max_in_flight: needed - 1,
            ..refs
        };
        let err = defaults.validate_for(&tight).unwrap_err();
        assert_eq!(
            err,
            LimitsError::LookupPlacesShort {
                max_in_flight: needed - 1,
                max_waiting_roots: 16,
                first_asks_in_flight: 80,
            }
        );
        // A slower reference holds each first ask longer: more places.
        let slow = RefLimits {
            timeout: Duration::from_millis(2500),
            ..refs
        };
        assert_eq!(defaults.first_asks_in_flight(slow.timeout), 16 + 80);
        assert!(defaults.validate_for(&slow).is_err());
        // A rate that does not divide the timeout is rounded up.
        let odd = IngestLimits {
            first_asks_per_sec: 3,
            ..defaults
        };
        assert_eq!(odd.first_asks_in_flight(Duration::from_millis(500)), 16 + 2);
        assert!(with(|l| l.root_wait = Duration::ZERO).is_err());
        // The columns waiting on announced lookups count against the queue too.
        let announced = with(|l| l.max_announced_columns = 128);
        assert!(
            matches!(announced, Err(LimitsError::WaitsFillTheQueue { .. })),
            "{announced:?}"
        );
        let full = with(|l| l.max_asking_columns = 320);
        assert!(
            matches!(full, Err(LimitsError::WaitsFillTheQueue { .. })),
            "{full:?}"
        );
        assert!(full.unwrap_err().to_string().contains("below max_items"));
    }

    type SilentView = RefView<Arc<Silent>, crate::testing::Spec>;

    /// A made-up block root: `i` in its first bytes.
    fn fake_root(i: u32) -> Root {
        let mut root = [0xf0; 32];
        root[..4].copy_from_slice(&i.to_be_bytes());
        root
    }

    /// The root step of a column of `root` arriving now, on a task of its own.
    fn column_of(
        refs: &Arc<SilentView>,
        waits: &Arc<RootWaits>,
        root: Root,
    ) -> tokio::task::JoinHandle<Result<Root, Drop>> {
        let (refs, waits) = (Arc::clone(refs), Arc::clone(waits));
        tokio::spawn(async move {
            let block = vouched_block(&refs, &waits, root, 1, Instant::now()).await?;
            Ok(block.root)
        })
    }

    /// The lookup places under the heaviest mix of the root wait: every seat retrying, and a
    /// first-ask burst after a quiet spell, then the full first-ask rate, all hanging on a
    /// silent reference. A known root's first ask comes at the turn that makes the most
    /// lookups in flight. Returns the lookups in flight just before that turn, the busy
    /// refusals, and how the known root's column ended.
    async fn heaviest_mix(max_in_flight: usize) -> (usize, u64, Result<Root, Drop>) {
        // Retries one after another, a lookup timeout that is no whole number of first-ask
        // intervals (so no turn starts as a lookup ends), and a wait that outlasts the test.
        let limits = IngestLimits {
            root_wait: Duration::from_secs(20),
            root_retry: Duration::from_millis(10),
            retries_per_sec: 1600,
            ..IngestLimits::default()
        };
        let ref_limits = RefLimits {
            timeout: Duration::from_millis(2010),
            max_in_flight,
            ..RefLimits::default()
        };
        let reference = Arc::new(Silent::default());
        let refs = Arc::new(SilentView::new(
            Arc::clone(&reference),
            crate::testing::schedule(),
            ref_limits,
        ));
        let waits = Arc::new(RootWaits::new(limits));
        let start = Instant::now();
        // A burst of made-up roots: their first asks time out at 2.01 s, and they take every
        // seat, retrying from 2.02 s with no pause but the 10 ms between retries.
        let mut fakes: Vec<_> = (0..16)
            .map(|i| column_of(&refs, &waits, fake_root(i)))
            .collect();
        // Quiet until then: the first-ask burst is whole again. Then a burst, and a turn every
        // 31.25 ms: 16 at 2.02 s, the 64th turn after them at 4.02 s, before any of them ends.
        tokio::time::sleep_until(start + Duration::from_millis(2020)).await;
        fakes.extend((16..96).map(|i| column_of(&refs, &waits, fake_root(i))));
        let root = reference.serve(9);
        let known = column_of(&refs, &waits, root);
        tokio::time::sleep_until(start + Duration::from_millis(4019)).await;
        assert_eq!(
            waits.roots(),
            limits.max_waiting_roots,
            "every seat retries"
        );
        let in_flight = refs.in_flight();
        let known = known.await.unwrap();
        for fake in fakes {
            fake.abort();
        }
        (in_flight, refs.busy(), known)
    }

    /// The Medium finding of the lookup places: the places that `validate_for` requires hold
    /// the heaviest mix, and one place fewer than that mix needs starves a known root's first
    /// ask into `Busy`.
    #[tokio::test(start_paused = true)]
    async fn a_known_roots_first_ask_finds_a_place_while_retries_and_first_asks_hang() {
        // 16 seats, and the burst of 16 with 32 a second over 2.01 s, rounded up: 65.
        let limits = IngestLimits::default();
        let needed =
            limits.max_waiting_roots + limits.first_asks_in_flight(Duration::from_millis(2010));
        assert_eq!(needed, 16 + 16 + 65);
        let (in_flight, busy, known) = heaviest_mix(needed).await;
        assert_eq!(in_flight, 95, "16 retries, 16 + 63 first asks");
        assert_eq!(known.map(|_| ()), Ok(()));
        assert_eq!(busy, 0, "the 96th lookup found a place");
        // 96 places hold that mix too; 95 do not.
        assert_eq!(heaviest_mix(96).await.1, 0);
        let (_, busy, known) = heaviest_mix(95).await;
        assert!(
            busy > 0,
            "the known root's first ask found every place taken"
        );
        assert!(known.is_ok(), "it asks again at a later turn");
    }

    /// The acceptance of the head seed: a flood of fresh made-up roots far above the first-ask
    /// rate delays, and then refuses, a real root the reference has not announced, but never
    /// one it has: that root needs no first-ask turn and no asking place.
    #[tokio::test(start_paused = true)]
    async fn a_flood_above_the_first_ask_rate_cannot_delay_an_announced_root() {
        let limits = IngestLimits::default();
        let reference = Arc::new(Silent::default());
        let refs = Arc::new(SilentView::new(
            Arc::clone(&reference),
            crate::testing::schedule(),
            RefLimits::default(),
        ));
        let waits = Arc::new(RootWaits::new(limits));
        // 400 made-up roots at once, more than twelve times the first-ask rate: the burst goes
        // out, the next turns are booked through the wait, and the rest are refused.
        let flood = 400;
        let fakes: Vec<_> = (0..flood)
            .map(|i| column_of(&refs, &waits, fake_root(i)))
            .collect();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let (asking, _) = waits.columns();
        assert!(asking > 100, "{asking} made-up roots wait for a turn");
        let start = Instant::now();
        // A root the reference knows but has not announced takes its turn behind the flood.
        let unannounced = reference.serve(9);
        let behind = column_of(&refs, &waits, unannounced);
        // The reference announces a root: its columns are answered at once, the flood's turns
        // and caps notwithstanding.
        let announced = reference.serve(10);
        refs.announce(announced);
        for _ in 0..4 {
            let column = column_of(&refs, &waits, announced);
            assert_eq!(column.await.unwrap(), Ok(announced));
            assert_eq!(start.elapsed(), Duration::ZERO, "not delayed");
        }
        assert_eq!(reference.asked(announced), 1, "one lookup for its columns");
        assert_eq!(refs.busy(), 0);
        // The root not announced is delayed by the flood, or refused.
        match behind.await.unwrap() {
            Ok(root) => {
                assert_eq!(root, unannounced);
                assert!(start.elapsed() > Duration::from_secs(1), "delayed");
            }
            Err(reason) => assert_eq!(reason, Drop::RootWaitFull),
        }
        for fake in fakes {
            assert!(fake.await.unwrap().is_err());
        }
    }

    /// An announced root whose first lookup timed out on a slow reference keeps its hint: a
    /// column of it under a flood still shares a lookup in the announced places, with no
    /// first-ask turn.
    #[tokio::test(start_paused = true)]
    async fn an_announced_root_whose_first_lookup_timed_out_still_skips_the_flood() {
        let reference = Arc::new(Silent::default());
        let refs = Arc::new(SilentView::new(
            Arc::clone(&reference),
            crate::testing::schedule(),
            RefLimits::default(),
        ));
        let waits = Arc::new(RootWaits::new(IngestLimits::default()));
        // Announced before the reference serves it: the follower's lookup times out.
        let (_, ssz, root) = crate::testing::gloas_block(10, &[[1; 48]]);
        refs.announce(root);
        let first = refs.lookup_as_announced(root).await;
        assert_eq!(first, Err(RefError::Timeout(DEFAULT_API_TIMEOUT)));
        reference.blocks.lock().unwrap().insert(root, (10, ssz));
        let fakes: Vec<_> = (0..400)
            .map(|i| column_of(&refs, &waits, fake_root(i)))
            .collect();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let start = Instant::now();
        assert_eq!(column_of(&refs, &waits, root).await.unwrap(), Ok(root));
        assert_eq!(start.elapsed(), Duration::ZERO, "not delayed");
        assert_eq!(reference.asked(root), 2);
        for fake in fakes {
            fake.abort();
        }
    }

    /// A column that booked a first-ask turn behind a flood before its root was announced does
    /// not sleep to that turn once the announced lookup caches the root: it, and the columns
    /// following it, go on at once, and its turn asks nothing.
    #[tokio::test(start_paused = true)]
    async fn a_column_waiting_for_its_turn_goes_on_once_its_root_is_cached() {
        let reference = Arc::new(Silent::default());
        let refs = Arc::new(SilentView::new(
            Arc::clone(&reference),
            crate::testing::schedule(),
            RefLimits::default(),
        ));
        let waits = Arc::new(RootWaits::new(IngestLimits::default()));
        // The burst and three seconds of turns go to made-up roots.
        let fakes: Vec<_> = (0..112)
            .map(|i| column_of(&refs, &waits, fake_root(i)))
            .collect();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let root = reference.serve(9);
        let start = Instant::now();
        let first = column_of(&refs, &waits, root);
        tokio::time::sleep(Duration::from_millis(1)).await;
        let follower = column_of(&refs, &waits, root);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(reference.asked(root), 0, "its turn is seconds away");
        // The reference announces the root, and the follower of its stream caches it.
        refs.announce(root);
        assert_eq!(refs.lookup_as_announced(root).await.unwrap().root, root);
        assert_eq!(first.await.unwrap(), Ok(root));
        assert_eq!(follower.await.unwrap(), Ok(root));
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(reference.asked(root), 1, "the turn asked nothing");
        for fake in fakes {
            fake.abort();
        }
    }

    /// Columns of an announced root that wait for its lookup are capped: forged columns of the
    /// root cannot take the queue places of known roots. Past the cap, a column takes the root
    /// wait, with its caps, and still shares the lookup in flight.
    #[tokio::test(start_paused = true)]
    async fn columns_waiting_on_an_announced_lookup_are_capped() {
        let limits = IngestLimits {
            max_announced_columns: 2,
            ..IngestLimits::default()
        };
        let reference = Arc::new(Silent::default());
        let refs = Arc::new(SilentView::new(
            Arc::clone(&reference),
            crate::testing::schedule(),
            RefLimits::default(),
        ));
        let waits = Arc::new(RootWaits::new(limits));
        // Announced, and the reference does not answer: every column of it waits.
        let root = [0x99; 32];
        refs.announce(root);
        let columns: Vec<_> = (0..3).map(|_| column_of(&refs, &waits, root)).collect();
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(waits.announced_columns(), 2);
        assert_eq!(waits.columns(), (1, 0), "the third waits in the root wait");
        assert_eq!(reference.asked(root), 1, "one lookup for all three");
        for column in columns {
            column.abort();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(waits.announced_columns(), 0, "places given back");
    }

    /// The columns of an announced root that arrive during its first lookup, which gets no
    /// answer, keep asking in the announced places while the hint lives: under a flood that
    /// leaves the root wait no turn, they still get the block once the reference serves it.
    #[tokio::test(start_paused = true)]
    async fn columns_waiting_on_an_announced_lookup_that_times_out_ask_again() {
        let reference = Arc::new(Silent::default());
        let refs = Arc::new(SilentView::new(
            Arc::clone(&reference),
            crate::testing::schedule(),
            RefLimits::default(),
        ));
        let waits = Arc::new(RootWaits::new(IngestLimits::default()));
        let start = Instant::now();
        let fakes: Vec<_> = (0..400)
            .map(|i| column_of(&refs, &waits, fake_root(i)))
            .collect();
        tokio::time::sleep(Duration::from_millis(1)).await;
        // Announced before the reference serves it: the follower's lookup will time out, and
        // the root's columns arrive while it hangs.
        let (_, ssz, root) = crate::testing::gloas_block(10, &[[1; 48]]);
        refs.announce(root);
        let follower = {
            let refs = Arc::clone(&refs);
            tokio::spawn(async move { refs.lookup_as_announced(root).await })
        };
        // At the same instant: every waiter on the lookup times out together.
        let columns: Vec<_> = (0..3).map(|_| column_of(&refs, &waits, root)).collect();
        tokio::time::sleep(Duration::from_secs(1)).await;
        reference.blocks.lock().unwrap().insert(root, (10, ssz));
        assert!(
            follower.await.unwrap().is_err(),
            "the first lookup timed out"
        );
        for column in columns {
            assert_eq!(column.await.unwrap(), Ok(root));
        }
        // Asked again one root retry after the timeout, not at a turn behind the flood.
        let asked_again = DEFAULT_API_TIMEOUT + DEFAULT_ROOT_RETRY;
        assert!(
            start.elapsed() <= asked_again + Duration::from_millis(5),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(reference.asked(root), 2);
        for fake in fakes {
            fake.abort();
        }
    }

    /// A root whose announcement is spent, or never came (the stream is down), takes the root
    /// wait's path as before: a first ask at its turn.
    #[tokio::test(start_paused = true)]
    async fn a_root_not_announced_takes_the_root_wait() {
        let reference = Arc::new(Silent::default());
        let refs = Arc::new(SilentView::new(
            Arc::clone(&reference),
            crate::testing::schedule(),
            RefLimits::default(),
        ));
        let waits = Arc::new(RootWaits::new(IngestLimits::default()));
        let known = reference.serve(9);
        assert_eq!(column_of(&refs, &waits, known).await.unwrap(), Ok(known));
        assert_eq!(reference.asked(known), 1);
        assert_eq!(refs.announced(), 0);
        // An announced root whose block does not establish it: the refusal spends the hint,
        // and the column falls back to the root wait, whose first ask is refused too.
        let (_, _, refused) = crate::testing::gloas_block(10, &[[1; 48]]);
        let (_, other, _) = crate::testing::gloas_block(11, &[[1; 48]]);
        reference
            .blocks
            .lock()
            .unwrap()
            .insert(refused, (11, other));
        refs.announce(refused);
        let column = column_of(&refs, &waits, refused);
        assert_eq!(column.await.unwrap(), Err(Drop::UnknownRoot));
        assert_eq!(
            reference.asked(refused),
            2,
            "the announced round, then the first ask"
        );
        assert_eq!(refs.announced(), 0, "the hint is spent");
    }

    /// The asks of an announced root end with the column's wait.
    #[tokio::test(start_paused = true)]
    async fn the_asks_of_an_announced_root_end_with_the_wait() {
        let reference = Arc::new(Silent::default());
        let refs = Arc::new(SilentView::new(
            Arc::clone(&reference),
            crate::testing::schedule(),
            RefLimits::default(),
        ));
        let waits = Arc::new(RootWaits::new(IngestLimits::default()));
        let (_, _, never) = crate::testing::gloas_block(10, &[[1; 48]]);
        refs.announce(never);
        let start = Instant::now();
        let column = column_of(&refs, &waits, never);
        assert_eq!(column.await.unwrap(), Err(Drop::RootTimeout));
        assert_eq!(start.elapsed(), DEFAULT_ROOT_WAIT);
        assert_eq!(
            reference.asked(never),
            2,
            "at 0 s, then at 2.5 s, cut at 4 s"
        );
        assert_eq!(waits.announced_columns(), 0);
    }

    #[test]
    fn the_earliest_servable_slot_is_the_highest_bound() {
        // Nothing stored: nothing to serve, whatever the other bounds say.
        assert_eq!(earliest_servable_slot(None, Some(40), 16, None), None);
        // Each bound in turn the highest.
        assert_eq!(earliest_servable_slot(Some(17), None, 16, None), Some(17));
        assert_eq!(
            earliest_servable_slot(Some(17), Some(40), 16, None),
            Some(41)
        );
        assert_eq!(
            earliest_servable_slot(Some(17), Some(9), 30, None),
            Some(30)
        );
        // A gap: only from the block after it on.
        assert_eq!(
            earliest_servable_slot(Some(17), Some(9), 30, Some(50)),
            Some(50)
        );
        assert_eq!(
            earliest_servable_slot(Some(17), Some(60), 30, Some(50)),
            Some(61)
        );
        // A watermark at the last slot leaves nothing servable past it.
        assert_eq!(
            earliest_servable_slot(Some(1), Some(Slot::MAX), 0, None),
            None
        );
    }

    #[test]
    fn copies_are_charged_to_their_own_budget_and_the_gauges_report_both() {
        let queue = queue(IngestLimits {
            max_bytes: 100,
            max_copy_bytes: 100,
            alert_bytes: 120,
            ..IngestLimits::default()
        });
        let mut a = queue.admit(60).unwrap();
        let a_kzg = a.charge_copies(50, 20).unwrap();
        assert_eq!(queue.metrics.buffer_bytes.get(), 130);
        assert_eq!(queue.metrics.buffer_alert.get(), 1, "the copies count too");
        let mut b = queue.admit(40).unwrap();
        assert!(b.charge_copies(20, 11).is_none(), "past the copy cap");
        assert!(b.charge_copies(usize::MAX, 1).is_none(), "no overflow");
        let b_kzg = b.charge_copies(20, 10).unwrap();
        assert_eq!(
            *queue.lock(),
            Pending {
                items: 2,
                bytes: 100,
                copies: 100
            }
        );
        // A place and its KZG charge are given back apart, in either order.
        drop(a);
        assert_eq!(queue.metrics.buffer_bytes.get(), 120);
        drop(a_kzg);
        assert_eq!(queue.metrics.buffer_bytes.get(), 70);
        assert_eq!(queue.metrics.buffer_alert.get(), 0);
        drop(b_kzg);
        assert_eq!(queue.metrics.buffer_bytes.get(), 50);
        drop(b);
        assert_eq!(*queue.lock(), Pending::default());
        assert_eq!(queue.metrics.buffer_bytes.get(), 0);
    }

    #[test]
    fn the_kzg_copy_charge_covers_the_cells_twice() {
        let sidecar = gloas::DataColumnSidecar::<crate::testing::Spec> {
            index: 3,
            column: vec![vec![7; 2048].try_into().unwrap(); 2]
                .try_into()
                .unwrap(),
            kzg_proofs: vec![[1; 48]; 2].try_into().unwrap(),
            slot: 9,
            beacon_block_root: [2; 32].into(),
        };
        let per_cell = std::mem::size_of::<KzgCellProof>() + 48 + 2048 + 48;
        assert_eq!(kzg_copy_bytes(&sidecar), 2 * 2 * per_cell);
    }

    #[test]
    fn the_queue_holds_both_caps() {
        let queue = queue(IngestLimits {
            max_items: 2,
            max_bytes: 100,
            alert_bytes: 60,
            ..IngestLimits::default()
        });
        let a = queue.admit(50).unwrap();
        assert_eq!(queue.metrics.buffer_alert.get(), 0);
        assert!(queue.admit(51).is_none(), "past the byte cap");
        let b = queue.admit(50).unwrap();
        assert_eq!(queue.metrics.buffer_alert.get(), 1);
        assert!(queue.admit(0).is_none(), "past the item cap");
        assert!(queue.admit(usize::MAX).is_none(), "no overflow");
        drop((a, b));
        let pending = *queue.lock();
        assert_eq!((pending.items, pending.bytes), (0, 0));
        assert_eq!(queue.metrics.buffer_bytes.get(), 0);
        assert_eq!(queue.metrics.buffer_alert.get(), 0);
    }
}
