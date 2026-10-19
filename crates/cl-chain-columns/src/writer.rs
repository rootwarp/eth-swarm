use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard, PoisonError,
    },
    thread,
};

use libmdbx::{NoWriteMap, Transaction, WriteFlags, RW};

use crate::{
    env::{self, WriterOptions},
    error::{Error, Result},
    keys::{
        block_prefix, column_key, decode_column_key, BlockLink, BlockRoot, ADVERTISED_CGC_KEY,
        CGC_KEY, CGC_SET_SLOT_KEY, COLUMNS_TABLE, CONTIGUOUS_FROM_KEY, FINALIZED_SLOT_KEY,
        FIRST_STORED_SLOT_KEY, LINKS_TABLE, METADATA_SEQ_KEY, META_TABLE, ROOTS_TABLE,
    },
    reader::{meta_u64, scan_block, stored_link, stored_slot, ColumnReader, CustodyRecord},
    sched::{Priority, TxnScheduler},
    NUMBER_OF_COLUMNS, NUMBER_OF_CUSTODY_GROUPS,
};

/// Most columns one write transaction carries. MDBX runs one write txn at a time per env, so a
/// large txn stalls block import while it is open.
pub const MAX_COLUMNS_PER_TXN: usize = 16;

/// Most rows one finality-prune transaction deletes. Blocks are never split across
/// transactions, and one block holds at most [`NUMBER_OF_COLUMNS`] rows, so this is a hard cap.
pub const MAX_ROWS_PER_PRUNE_TXN: u64 = NUMBER_OF_COLUMNS;

/// Most orphan tombstones a writer keeps \[est\]: roots [`ColumnWriter::prune_orphaned`] pruned,
/// whose late columns [`ColumnWriter::write_columns`] refuses. A tombstone is forgotten once
/// finality covers its slot (the watermark refuses those writes from then on), or, oldest first,
/// once this many are kept. Reorgs orphan a block or two at a time, so this covers days of them.
pub const MAX_ORPHANED_ROOTS: usize = 1024;

/// Largest sidecar value accepted. A policy bound, not a type bound: the largest SSZ encoding of
/// a Fulu `DataColumnSidecar`, applied to both forks.
///
/// Fulu: `column`, `kzg_commitments` and `kzg_proofs` are lists capped at
/// `MAX_BLOB_COMMITMENTS_PER_BLOCK` (4096 in both presets). `index` 8 + three list offsets 12 +
/// `SignedBeaconBlockHeader` 208 + `kzg_commitments_inclusion_proof` 4 × 32 = 356 fixed bytes,
/// plus per blob one cell (`BYTES_PER_CELL` 2048), one commitment (48) and one proof (48):
/// 356 + 4096 × 2144 = 8,782,180 B. Exact for Fulu.
///
/// Gloas: `column` and `kzg_proofs` are `ProgressiveList`s with no type cap; the blob count is
/// bounded by `max_blobs_per_block` in `BLOB_SCHEDULE`. A Gloas sidecar is 56 fixed bytes
/// (`index`, two offsets, `slot`, `beacon_block_root`) + 2096 per blob, so this bound holds for
/// any schedule with `max_blobs_per_block` ≤ 4,189 (56 + 4189 × 2096 = 8,780,200 B), far above
/// any real schedule. Revisit if a `BLOB_SCHEDULE` entry or a later fork's sidecar layout could
/// exceed it: derive the cap from the schedule's maximum instead.
pub const MAX_SIDECAR_BYTES: usize = FULU_SIDECAR_FIXED_BYTES
    + MAX_BLOB_COMMITMENTS_PER_BLOCK * (BYTES_PER_CELL + 2 * BYTES_PER_KZG);

const FULU_SIDECAR_FIXED_BYTES: usize = 8 + 3 * 4 + 208 + 4 * 32;
const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;
const BYTES_PER_CELL: usize = 2048;
/// `KZGCommitment` and `KZGProof` are both 48-byte compressed G1 points.
const BYTES_PER_KZG: usize = 48;

/// One verified column sidecar to store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Column<'a> {
    pub index: u64,
    /// SSZ-encoded `DataColumnSidecar` of the block's fork; stored as is, never decoded here.
    pub ssz: &'a [u8],
}

/// What one [`ColumnWriter::write_columns`] call committed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    pub columns: usize,
    pub transactions: usize,
    pub max_columns_per_txn: usize,
}

/// What one prune call removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub columns: u64,
    pub blocks: u64,
}

/// Whether a write txn body wants its changes kept.
enum Commit<T> {
    Yes(T),
    /// Nothing changed: drop (abort) the txn and don't count it.
    No(T),
}

type RwTxn<'db> = Transaction<'db, RW, NoWriteMap>;

/// Orphan tombstones: roots pruned by [`ColumnWriter::prune_orphaned`], with their slot if any
/// column of them was stored, so no later write brings them back (see
/// [`MAX_ORPHANED_ROOTS`]). Kept in memory: a restart forgets them, and with them the columns
/// in flight that they guard against.
#[derive(Debug, Default)]
struct Orphans {
    slots: HashMap<BlockRoot, Option<u64>>,
    /// Insertion order of `slots`, oldest first.
    order: VecDeque<BlockRoot>,
    /// The blocks stored with [`BlockLink::Pending`], by the root they wait for, with their
    /// slots. Rebuilt from the links table at open.
    pending: HashMap<BlockRoot, Vec<(BlockRoot, u64)>>,
}

impl Orphans {
    fn contains(&self, block_root: &BlockRoot) -> bool {
        self.slots.contains_key(block_root)
    }

    /// Adds a tombstone for `block_root`, or fills in the slot of the one it has.
    fn insert(&mut self, block_root: BlockRoot, slot: Option<u64>) {
        if let Some(known) = self.slots.get_mut(&block_root) {
            if slot.is_some() {
                *known = slot;
            }
            return;
        }
        while self.slots.len() >= MAX_ORPHANED_ROOTS {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.slots.remove(&oldest);
        }
        self.order.push_back(block_root);
        self.slots.insert(block_root, slot);
    }

    /// Forgets the tombstone of `block_root`.
    fn remove(&mut self, block_root: &BlockRoot) {
        if self.slots.remove(block_root).is_some() {
            self.order.retain(|root| root != block_root);
        }
    }

    /// Forgets the tombstones at or below `finalized_slot`.
    fn forget_finalized(&mut self, finalized_slot: u64) {
        self.slots
            .retain(|_, slot| slot.is_none_or(|slot| slot > finalized_slot));
        let slots = &self.slots;
        self.order.retain(|root| slots.contains_key(root));
    }
}

/// A hook run in each column write transaction after its puts and before its commit, with the
/// block's slot ([`ColumnWriter::set_before_commit`]).
#[cfg(feature = "test-hooks")]
pub type BeforeCommit = Box<dyn Fn(u64) + Send + Sync>;

/// The test hooks of a [`ColumnWriter`]: none in a build without the `test-hooks` feature.
#[derive(Default)]
struct Hooks {
    #[cfg(feature = "test-hooks")]
    before_commit: std::sync::OnceLock<BeforeCommit>,
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks").finish_non_exhaustive()
    }
}

impl Hooks {
    /// Runs the before-commit hook, if one is set.
    fn before_commit(&self, _slot: u64) {
        #[cfg(feature = "test-hooks")]
        if let Some(hook) = self.before_commit.get() {
            hook(_slot);
        }
    }
}

/// The only handle that writes the column env. cl-chain owns it.
///
/// [`ColumnWriter::open`] takes the writer guard first, so a second writer for the same path, in
/// this process or any other, fails with [`Error::WriterAlreadyOpen`]. The type is neither
/// `Clone` nor constructible any other way, and readers ([`ColumnReader`]) have no write
/// methods. Methods take `&self`, so cl-chain shares one writer (e.g. in an `Arc`) between block
/// import and the low-priority column task.
///
/// Every write txn first takes a permit from one in-process scheduler. libmdbx 0.5.6 begins all
/// write txns on a single manager thread, and a begin that meets an open write txn gets
/// `MDBX_BUSY` and sleeps 250 ms before retrying, so letting two threads race for MDBX's own
/// lock costs import a quarter second per collision. The scheduler admits import-priority txns
/// ([`Self::set_cgc`]) ahead of queued background txns, so import waits at most for the one
/// chunk in flight, and admits one background txn after a bounded run of imports.
#[derive(Debug)]
pub struct ColumnWriter {
    // Field order is drop order: close the data env before releasing the guard.
    reader: ColumnReader,
    /// Serialises column writes and prunes, so a prune never lands between two chunks of one
    /// block's write and leaves the later chunks behind as orphans. Holds the orphan
    /// tombstones, checked by every write under the same lock.
    column_ops: Mutex<Orphans>,
    sched: TxnScheduler,
    rw_txns: AtomicU64,
    hooks: Hooks,
    _guard: env::Env,
}

impl ColumnWriter {
    /// Opens or creates the column env at `path` with default [`WriterOptions`] and creates
    /// every table on first open.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path, WriterOptions::default())
    }

    /// [`ColumnWriter::open`] with explicit options.
    pub fn open_with(path: impl AsRef<Path>, options: WriterOptions) -> Result<Self> {
        let path = path.as_ref();
        let guard = env::lock_writer(path)?;
        let db = env::open_rw(path, options)?;
        let pending = {
            let txn = db.begin_ro_txn()?;
            pending_links(&txn)?
        };
        Ok(Self {
            reader: ColumnReader::from_env(db),
            column_ops: Mutex::new(Orphans {
                pending,
                ..Orphans::default()
            }),
            sched: TxnScheduler::default(),
            rw_txns: AtomicU64::new(0),
            hooks: Hooks::default(),
            _guard: guard,
        })
    }

    /// Read access through the writer's own env.
    #[must_use]
    pub fn reader(&self) -> &ColumnReader {
        &self.reader
    }

    /// Sets the hook every column write transaction runs after its puts and before its commit,
    /// with the block's slot; only the first call sets it. A crash-test seam: a hook that blocks
    /// holds the transaction open, uncommitted, for as long as it blocks.
    #[cfg(feature = "test-hooks")]
    pub fn set_before_commit(&self, hook: BeforeCommit) {
        let _ = self.hooks.before_commit.set(hook);
    }

    /// Stores `child`'s link as a pending link on `target` in the layout stores wrote before
    /// pending links carried their target's slot (`3 ‖ root`), bypassing every rule. A seam for
    /// reading an env no writer has migrated yet: the next [`ColumnWriter::open`] migrates it.
    #[cfg(feature = "test-hooks")]
    pub fn put_legacy_pending_link(&self, child: &BlockRoot, target: &BlockRoot) -> Result<()> {
        let txn = self.reader.db.begin_rw_txn()?;
        let links = txn.open_table(Some(LINKS_TABLE))?;
        let mut value = vec![3];
        value.extend_from_slice(target);
        txn.put(&links, child, value, WriteFlags::UPSERT)?;
        txn.commit()?;
        Ok(())
    }

    /// Write transactions this handle has committed since [`ColumnWriter::open`] returned.
    #[must_use]
    pub fn rw_txns_committed(&self) -> u64 {
        self.rw_txns.load(Ordering::Relaxed)
    }

    /// Stores verified, unfinalized columns of one block, at most [`MAX_COLUMNS_PER_TXN`] per
    /// write transaction. Between transactions it yields the thread and lets any waiting import
    /// txn go first. Call it from a low-priority (blocking) task, never from import itself.
    ///
    /// The batch is validated before the first transaction: at most [`NUMBER_OF_COLUMNS`]
    /// columns, each index below it and unique, each value non-empty and at most
    /// [`MAX_SIDECAR_BYTES`], and the slot above the finalized-slot watermark
    /// ([`Error::SlotFinalized`]), and the root not pruned as an orphan ([`Error::RootOrphaned`],
    /// [`Self::prune_orphaned`]). A column already stored under the same key is replaced. Each
    /// transaction that stores a column below the first stored slot
    /// ([`ColumnReader::first_stored_slot`]) also lowers it to `slot`.
    ///
    /// The block is stored with [`BlockLink::Gap`]: nothing is known of its chain
    /// ([`Self::write_block_columns`]).
    pub fn write_columns(
        &self,
        slot: u64,
        block_root: &BlockRoot,
        columns: &[Column<'_>],
    ) -> Result<WriteReport> {
        self.write_block_columns(slot, block_root, BlockLink::Gap, columns)
    }

    /// [`Self::write_columns`], the block stored with `link`, in the first transaction.
    ///
    /// - [`BlockLink::Pending`] of a root that is stored is [`BlockLink::Parent`] of it, and one
    ///   of a slot at or below the finalized-slot watermark is [`BlockLink::Start`]: finality
    ///   pruned the target, or refuses it, and nothing before it is to be held.
    /// - A [`BlockLink::Gap`] or a pending link never replaces a [`BlockLink::Start`] or
    ///   [`BlockLink::Parent`] the block was stored with, a pending link never replaces a gap,
    ///   and a gap never replaces a pending link (a walk that failed once says nothing of the
    ///   target: [`Self::settle_pending`] decides); any other link replaces the stored one.
    /// - A gap that is kept raises the contiguous-from slot ([`ColumnReader::contiguous_from`])
    ///   to `slot` in the same transaction; a pending link raises nothing.
    /// - Every stored block pending on this block's root links to it, in the same transaction.
    pub fn write_block_columns(
        &self,
        slot: u64,
        block_root: &BlockRoot,
        link: BlockLink,
        columns: &[Column<'_>],
    ) -> Result<WriteReport> {
        validate_batch(columns)?;
        let mut orphans = lock(&self.column_ops);
        // Under `column_ops`, so no finality prune can move the watermark, and no reorg prune
        // can orphan the root, until this returns.
        let finalized_slot = self.reader.finalized_slot()?;
        let finalized = finalized_slot.filter(|&finalized_slot| slot <= finalized_slot);
        let orphaned = orphans.contains(block_root);
        if orphaned {
            // A tombstone laid before any column of the root was stored learns its slot from
            // the first late write, before any other check, so finality forgets it in its turn;
            // at once if finality already covers that slot.
            if finalized.is_some() {
                orphans.remove(block_root);
            } else {
                orphans.insert(*block_root, Some(slot));
            }
        }
        if let Some(finalized_slot) = finalized {
            return Err(Error::SlotFinalized {
                slot,
                finalized_slot,
            });
        }
        if orphaned {
            return Err(Error::RootOrphaned);
        }
        let mut report = WriteReport::default();
        for (i, chunk) in columns.chunks(MAX_COLUMNS_PER_TXN).enumerate() {
            if i > 0 {
                thread::yield_now();
            }
            let written = self.write_txn(Priority::Background, |txn| {
                write_chunk(txn, slot, block_root, chunk)?;
                if i == 0 {
                    write_link(txn, slot, block_root, link, &mut orphans.pending)?;
                }
                self.hooks.before_commit(slot);
                Ok(Commit::Yes(()))
            });
            if let Err(e) = written {
                // The pending index may have moved with a transaction that never committed.
                if let Ok(txn) = self.reader.db.begin_ro_txn() {
                    if let Ok(pending) = pending_links(&txn) {
                        orphans.pending = pending;
                    }
                }
                return Err(e);
            }
            report.columns += chunk.len();
            report.transactions += 1;
            report.max_columns_per_txn = report.max_columns_per_txn.max(chunk.len());
        }
        Ok(report)
    }

    /// Reorg pruning: removes every column of each orphaned block root, one write transaction
    /// per block (at most [`NUMBER_OF_COLUMNS`] rows), yielding between blocks, and leaves a
    /// tombstone for each root, stored or not: [`Self::write_columns`] refuses the root from
    /// then on ([`Error::RootOrphaned`]), so columns still in flight cannot bring it back. The
    /// tombstone is laid before the root's rows are removed, so it stands even if that fails.
    /// An orphaned root stays orphaned until finality covers its slot ([`MAX_ORPHANED_ROOTS`]):
    /// a reorg back to it does not re-admit its columns. Unknown roots have no rows to remove.
    pub fn prune_orphaned(&self, block_roots: &[BlockRoot]) -> Result<PruneReport> {
        let mut orphans = lock(&self.column_ops);
        let mut report = PruneReport::default();
        for (i, block_root) in block_roots.iter().enumerate() {
            if i > 0 {
                thread::yield_now();
            }
            orphans.insert(*block_root, None);
            let removed = self.write_txn(Priority::Background, |txn| {
                Ok(match prune_block(txn, block_root)? {
                    Some(removed) => Commit::Yes(Some(removed)),
                    None => Commit::No(None),
                })
            })?;
            if let Some((slot, columns)) = removed {
                orphans.insert(*block_root, Some(slot));
                report.columns += columns;
                report.blocks += 1;
            }
        }
        Ok(report)
    }

    /// Finality pruning: removes every column at or below `finalized_slot`, whole blocks at a
    /// time and at most [`MAX_ROWS_PER_PRUNE_TXN`] rows per write transaction, yielding between
    /// transactions. The first transaction also raises the finalized-slot watermark to
    /// `finalized_slot` (it never lowers), after which [`Self::write_columns`] refuses those
    /// slots. Also the backstop for orphans: any row left behind is removed once its slot
    /// finalizes.
    pub fn prune_finalized(&self, finalized_slot: u64) -> Result<PruneReport> {
        let mut orphans = lock(&self.column_ops);
        let mut report = PruneReport::default();
        loop {
            let (batch, more) = self.write_txn(Priority::Background, |txn| {
                let advanced = raise_watermark(txn, finalized_slot)?;
                let (batch, more) = prune_finalized_batch(txn, finalized_slot)?;
                Ok(if advanced || batch.blocks > 0 {
                    Commit::Yes((batch, more))
                } else {
                    Commit::No((batch, more))
                })
            })?;
            report.columns += batch.columns;
            report.blocks += batch.blocks;
            if !more {
                // The watermark is raised by now, and refuses every write the tombstones at or
                // below it guard against.
                orphans.forget_finalized(finalized_slot);
                return Ok(report);
            }
            thread::yield_now();
        }
    }

    /// Settles every block stored [`BlockLink::Pending`] at a slot below `before_slot` whose
    /// root never came: a [`BlockLink::Start`] if finality covers the target's slot by now
    /// (nothing before it is to be held), else a [`BlockLink::Gap`], raising the
    /// contiguous-from slot to the block's slot. Returns how many were settled.
    pub fn settle_pending(&self, before_slot: u64) -> Result<usize> {
        let mut orphans = lock(&self.column_ops);
        let due: Vec<(BlockRoot, BlockRoot, u64)> = orphans
            .pending
            .iter()
            .flat_map(|(target, children)| {
                children
                    .iter()
                    .filter(|(_, slot)| *slot < before_slot)
                    .map(move |(child, slot)| (*target, *child, *slot))
            })
            .collect();
        if due.is_empty() {
            return Ok(0);
        }
        let settled = self.write_txn(Priority::Background, |txn| {
            let finalized = meta_u64(txn, FINALIZED_SLOT_KEY)?;
            let mut settled = 0;
            for (target, child, slot) in &due {
                let Some(BlockLink::Pending(stored, target_slot)) = stored_link(txn, child)? else {
                    continue;
                };
                if stored != *target {
                    continue;
                }
                if finalized.is_some_and(|f| target_slot <= f) {
                    put_link(txn, child, BlockLink::Start)?;
                } else {
                    put_link(txn, child, BlockLink::Gap)?;
                    raise_contiguous(txn, *slot)?;
                }
                settled += 1;
            }
            Ok(Commit::Yes(settled))
        })?;
        for (target, child, _) in due {
            forget_pending(&mut orphans.pending, &target, &child);
        }
        Ok(settled)
    }

    /// Stores the node's custody group count. Runs at import priority. A count below the
    /// stored one is [`Error::CgcDecrease`] and writes nothing.
    pub fn set_cgc(&self, cgc: u64) -> Result<()> {
        check_cgc(cgc)?;
        self.write_txn(Priority::Import, |txn| {
            refuse_decrease(txn, cgc)?;
            let meta = txn.open_table(Some(META_TABLE))?;
            txn.put(&meta, CGC_KEY, cgc.to_be_bytes(), WriteFlags::UPSERT)?;
            Ok(Commit::Yes(()))
        })
    }

    /// Stores the whole custody record in one import-priority write transaction, so a crash
    /// leaves either the old record or the new one. The check against the stored count runs
    /// inside that transaction: a `cgc` below it is [`Error::CgcDecrease`] and writes nothing.
    /// `cgc` and `advertised_cgc` above [`NUMBER_OF_CUSTODY_GROUPS`] are
    /// [`Error::CgcOutOfRange`].
    pub fn set_custody(&self, record: &CustodyRecord) -> Result<()> {
        check_cgc(record.cgc)?;
        check_cgc(record.advertised_cgc)?;
        self.write_txn(Priority::Import, |txn| {
            refuse_decrease(txn, record.cgc)?;
            let meta = txn.open_table(Some(META_TABLE))?;
            for (key, value) in [
                (CGC_KEY, record.cgc),
                (CGC_SET_SLOT_KEY, record.cgc_set_slot),
                (METADATA_SEQ_KEY, record.metadata_seq),
                (ADVERTISED_CGC_KEY, record.advertised_cgc),
            ] {
                txn.put(&meta, key, value.to_be_bytes(), WriteFlags::UPSERT)?;
            }
            Ok(Commit::Yes(()))
        })
    }

    /// Runs `body` in one write txn under a scheduler permit and commits if it asks to.
    fn write_txn<T>(
        &self,
        priority: Priority,
        body: impl FnOnce(&RwTxn<'_>) -> Result<Commit<T>>,
    ) -> Result<T> {
        let _permit = self.sched.acquire(priority);
        let txn = self.reader.db.begin_rw_txn()?;
        match body(&txn)? {
            Commit::Yes(value) => {
                txn.commit()?;
                self.rw_txns.fetch_add(1, Ordering::Relaxed);
                Ok(value)
            }
            Commit::No(value) => Ok(value),
        }
    }
}

/// Every update of the guarded tombstones is one call that cannot panic halfway, so a panic
/// elsewhere cannot leave them inconsistent.
fn lock(mutex: &Mutex<Orphans>) -> MutexGuard<'_, Orphans> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn validate_batch(columns: &[Column<'_>]) -> Result<()> {
    if columns.len() > NUMBER_OF_COLUMNS as usize {
        return Err(Error::TooManyColumns { len: columns.len() });
    }
    let mut seen = [false; NUMBER_OF_COLUMNS as usize];
    for column in columns {
        let index = column.index;
        let slot = usize::try_from(index)
            .ok()
            .and_then(|i| seen.get_mut(i))
            .ok_or(Error::ColumnIndexOutOfRange { index })?;
        if std::mem::replace(slot, true) {
            return Err(Error::DuplicateColumn { index });
        }
        if column.ssz.is_empty() {
            return Err(Error::EmptySidecar { index });
        }
        if column.ssz.len() > MAX_SIDECAR_BYTES {
            return Err(Error::SidecarTooLarge {
                index,
                len: column.ssz.len(),
            });
        }
    }
    Ok(())
}

fn check_cgc(cgc: u64) -> Result<()> {
    if cgc > NUMBER_OF_CUSTODY_GROUPS {
        return Err(Error::CgcOutOfRange(cgc));
    }
    Ok(())
}

/// [`Error::CgcDecrease`] if `cgc` is below the stored count; the txn is then dropped.
fn refuse_decrease(txn: &RwTxn<'_>, cgc: u64) -> Result<()> {
    match meta_u64(txn, CGC_KEY)? {
        Some(stored) if cgc < stored => Err(Error::CgcDecrease {
            stored,
            requested: cgc,
        }),
        _ => Ok(()),
    }
}

/// Raises the finalized-slot watermark to `finalized_slot`; returns whether it moved.
fn raise_watermark(txn: &RwTxn<'_>, finalized_slot: u64) -> Result<bool> {
    if meta_u64(txn, FINALIZED_SLOT_KEY)?.is_some_and(|current| current >= finalized_slot) {
        return Ok(false);
    }
    let meta = txn.open_table(Some(META_TABLE))?;
    txn.put(
        &meta,
        FINALIZED_SLOT_KEY,
        finalized_slot.to_be_bytes(),
        WriteFlags::UPSERT,
    )?;
    Ok(true)
}

fn write_chunk(
    txn: &RwTxn<'_>,
    slot: u64,
    block_root: &BlockRoot,
    chunk: &[Column<'_>],
) -> Result<()> {
    match stored_slot(txn, block_root)? {
        Some(stored) if stored != slot => {
            return Err(Error::SlotMismatch {
                stored,
                given: slot,
            })
        }
        Some(_) => {}
        None => {
            let roots = txn.open_table(Some(ROOTS_TABLE))?;
            txn.put(&roots, block_root, slot.to_be_bytes(), WriteFlags::UPSERT)?;
        }
    }
    let columns = txn.open_table(Some(COLUMNS_TABLE))?;
    for column in chunk {
        let key = column_key(slot, block_root, column.index);
        txn.put(&columns, key, column.ssz, WriteFlags::UPSERT)?;
    }
    if !chunk.is_empty() && meta_u64(txn, FIRST_STORED_SLOT_KEY)?.is_none_or(|first| slot < first) {
        let meta = txn.open_table(Some(META_TABLE))?;
        txn.put(
            &meta,
            FIRST_STORED_SLOT_KEY,
            slot.to_be_bytes(),
            WriteFlags::UPSERT,
        )?;
    }
    Ok(())
}

/// Stores `link` for `block_root` at `slot`, and links the blocks pending on it (see
/// [`ColumnWriter::write_block_columns`]).
fn write_link(
    txn: &RwTxn<'_>,
    slot: u64,
    block_root: &BlockRoot,
    link: BlockLink,
    pending: &mut HashMap<BlockRoot, Vec<(BlockRoot, u64)>>,
) -> Result<()> {
    let finalized = meta_u64(txn, FINALIZED_SLOT_KEY)?;
    let link = match link {
        BlockLink::Pending(target, _) if stored_slot(txn, &target)?.is_some() => {
            BlockLink::Parent(target)
        }
        BlockLink::Pending(_, target_slot) if finalized.is_some_and(|f| target_slot <= f) => {
            BlockLink::Start
        }
        other => other,
    };
    let stored = stored_link(txn, block_root)?;
    let linked = |l: BlockLink| matches!(l, BlockLink::Start | BlockLink::Parent(_));
    let keep = match (stored, link) {
        (Some(s), BlockLink::Gap | BlockLink::Pending(..)) if linked(s) => true,
        (Some(BlockLink::Gap), BlockLink::Pending(..))
        | (Some(BlockLink::Pending(..)), BlockLink::Gap) => true,
        _ => false,
    };
    if !keep {
        put_link(txn, block_root, link)?;
        if link == BlockLink::Gap {
            raise_contiguous(txn, slot)?;
        }
        if let Some(BlockLink::Pending(old, _)) = stored {
            forget_pending(pending, &old, block_root);
        }
        if let BlockLink::Pending(target, _) = link {
            let children = pending.entry(target).or_default();
            if !children.iter().any(|(c, _)| c == block_root) {
                children.push((*block_root, slot));
            }
        }
    }
    for (child, _) in pending.remove(block_root).unwrap_or_default() {
        if matches!(stored_link(txn, &child)?, Some(BlockLink::Pending(t, _)) if t == *block_root) {
            put_link(txn, &child, BlockLink::Parent(*block_root))?;
        }
    }
    Ok(())
}

/// Takes `child` off the blocks pending on `target`, and `target` off the index once none is.
fn forget_pending(
    pending: &mut HashMap<BlockRoot, Vec<(BlockRoot, u64)>>,
    target: &BlockRoot,
    child: &BlockRoot,
) {
    if let Some(children) = pending.get_mut(target) {
        children.retain(|(c, _)| c != child);
        if children.is_empty() {
            pending.remove(target);
        }
    }
}

pub(crate) fn put_link(txn: &RwTxn<'_>, block_root: &BlockRoot, link: BlockLink) -> Result<()> {
    let links = txn.open_table(Some(LINKS_TABLE))?;
    txn.put(&links, block_root, link.encode(), WriteFlags::UPSERT)?;
    Ok(())
}

/// Raises the contiguous-from slot to `slot`; it never goes down.
pub(crate) fn raise_contiguous(txn: &RwTxn<'_>, slot: u64) -> Result<()> {
    if meta_u64(txn, CONTIGUOUS_FROM_KEY)?.is_none_or(|from| slot > from) {
        let meta = txn.open_table(Some(META_TABLE))?;
        txn.put(
            &meta,
            CONTIGUOUS_FROM_KEY,
            slot.to_be_bytes(),
            WriteFlags::UPSERT,
        )?;
    }
    Ok(())
}

/// Every stored block's pending link, by the root it waits for.
fn pending_links<K: libmdbx::TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
) -> Result<HashMap<BlockRoot, Vec<(BlockRoot, u64)>>> {
    let links = txn.open_table(Some(LINKS_TABLE))?;
    let mut cursor = txn.cursor(&links)?;
    let mut out: HashMap<BlockRoot, Vec<(BlockRoot, u64)>> = HashMap::new();
    let mut row = cursor.first::<Vec<u8>, Vec<u8>>()?;
    while let Some((key, value)) = row {
        if let Some(BlockLink::Pending(target, _)) = BlockLink::decode(&value) {
            let child: BlockRoot = key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Corrupt { table: LINKS_TABLE })?;
            if let Some(slot) = stored_slot(txn, &child)? {
                out.entry(target).or_default().push((child, slot));
            }
        }
        row = cursor.next::<Vec<u8>, Vec<u8>>()?;
    }
    Ok(out)
}

/// Rewrites every pending link stored without its target's slot, as stores wrote them before
/// ([`BlockLink::legacy_pending_target`]): [`BlockLink::Parent`] if the target is stored, else
/// [`BlockLink::Gap`], raising the contiguous-from slot to the block's slot, since the slot a
/// range answer must not pass is unknown. In the transaction `txn` the writer opens the env
/// with; a second run finds nothing to rewrite. Returns how many were rewritten.
pub(crate) fn migrate_legacy_pending(txn: &RwTxn<'_>) -> Result<usize> {
    let links = txn.open_table(Some(LINKS_TABLE))?;
    let mut legacy = Vec::new();
    {
        let mut cursor = txn.cursor(&links)?;
        let mut row = cursor.first::<Vec<u8>, Vec<u8>>()?;
        while let Some((key, value)) = row {
            if let Some(target) = BlockLink::legacy_pending_target(&value) {
                let child: BlockRoot = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Corrupt { table: LINKS_TABLE })?;
                legacy.push((child, target));
            }
            row = cursor.next::<Vec<u8>, Vec<u8>>()?;
        }
    }
    for (child, target) in &legacy {
        if stored_slot(txn, target)?.is_some() {
            put_link(txn, child, BlockLink::Parent(*target))?;
        } else {
            put_link(txn, child, BlockLink::Gap)?;
            if let Some(slot) = stored_slot(txn, child)? {
                raise_contiguous(txn, slot)?;
            }
        }
    }
    Ok(legacy.len())
}

/// Makes the env look as one written before the links table existed: drops the table and the
/// contiguous-from slot.
#[cfg(test)]
pub(crate) fn make_legacy_for_test(writer: &ColumnWriter) {
    let txn = writer.reader.db.begin_rw_txn().unwrap();
    let links = txn.open_table(Some(LINKS_TABLE)).unwrap();
    // SAFETY: no other handle of the table is open in this test.
    unsafe { txn.drop_table(links).unwrap() };
    let meta = txn.open_table(Some(META_TABLE)).unwrap();
    let _ = txn.del(&meta, CONTIGUOUS_FROM_KEY, None);
    txn.commit().unwrap();
}

/// Removes `block_root`'s link, if it has one.
fn del_link(txn: &RwTxn<'_>, block_root: &BlockRoot) -> Result<()> {
    let links = txn.open_table(Some(LINKS_TABLE))?;
    match txn.del(&links, block_root, None) {
        Ok(_) | Err(libmdbx::Error::NotFound) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Removes one block's columns and its root entry; returns its slot and the number of columns
/// removed, `None` if the block is not stored.
fn prune_block(txn: &RwTxn<'_>, block_root: &BlockRoot) -> Result<Option<(u64, u64)>> {
    let Some(slot) = stored_slot(txn, block_root)? else {
        return Ok(None);
    };
    let columns = txn.open_table(Some(COLUMNS_TABLE))?;
    let rows = scan_block::<_, ()>(txn, &columns, &block_prefix(slot, block_root))?;
    for (key, ()) in &rows {
        txn.del(&columns, key, None)?;
    }
    let roots = txn.open_table(Some(ROOTS_TABLE))?;
    txn.del(&roots, block_root, None)?;
    del_link(txn, block_root)?;
    Ok(Some((slot, rows.len() as u64)))
}

/// One finality-prune transaction. Rows are deleted from the start of the key space, so the
/// table's first row is always the next candidate. Returns whether finalized rows remain.
fn prune_finalized_batch(txn: &RwTxn<'_>, finalized_slot: u64) -> Result<(PruneReport, bool)> {
    let columns = txn.open_table(Some(COLUMNS_TABLE))?;
    let roots = txn.open_table(Some(ROOTS_TABLE))?;
    let mut report = PruneReport::default();
    loop {
        let Some((key, ())) = txn.cursor(&columns)?.first::<Vec<u8>, ()>()? else {
            return Ok((report, false));
        };
        let (slot, block_root, _) = decode_column_key(&key).ok_or(Error::Corrupt {
            table: COLUMNS_TABLE,
        })?;
        if slot > finalized_slot {
            return Ok((report, false));
        }
        let rows = scan_block::<_, ()>(txn, &columns, &block_prefix(slot, &block_root))?;
        let rows_len = rows.len() as u64;
        if report.columns > 0 && report.columns + rows_len > MAX_ROWS_PER_PRUNE_TXN {
            return Ok((report, true));
        }
        for (key, ()) in &rows {
            txn.del(&columns, key, None)?;
        }
        txn.del(&roots, block_root, None)?;
        del_link(txn, &block_root)?;
        report.columns += rows_len;
        report.blocks += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MIN_MAX_SIZE;
    use crate::sched::Priority;
    use crate::{keys::TABLES, Error, NUMBER_OF_COLUMNS, NUMBER_OF_CUSTODY_GROUPS};

    #[test]
    fn env_opens_with_max_tables() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let env = writer.reader.db.ptr().0;

        let mut flags = 0;
        assert_eq!(unsafe { mdbx_sys::mdbx_env_get_flags(env, &mut flags) }, 0);
        let no_sync =
            mdbx_sys::MDBX_NOMETASYNC | mdbx_sys::MDBX_SAFE_NOSYNC | mdbx_sys::MDBX_UTTERLY_NOSYNC;
        assert_eq!(flags & no_sync, 0, "env must be SyncMode::Durable");
        assert_eq!(flags & mdbx_sys::MDBX_RDONLY, 0);

        let mut max_tables = 0;
        let rc = unsafe {
            mdbx_sys::mdbx_env_get_option(env, mdbx_sys::MDBX_opt_max_db, &mut max_tables)
        };
        assert_eq!(rc, 0);
        assert_eq!(max_tables, crate::env::MAX_TABLES);

        let txn = writer.reader.db.begin_ro_txn().unwrap();
        for table in TABLES {
            txn.open_table(Some(table))
                .unwrap_or_else(|e| panic!("table {table} missing on first open: {e}"));
        }
    }

    const ROOT_A: BlockRoot = [0xaa; 32];
    const ROOT_B: BlockRoot = [0xbb; 32];

    fn sidecar(slot: u64, index: u64) -> Vec<u8> {
        format!("sidecar {slot}/{index}").into_bytes()
    }

    fn write_block(
        writer: &ColumnWriter,
        slot: u64,
        root: &BlockRoot,
        indices: &[u64],
    ) -> WriteReport {
        let bytes: Vec<Vec<u8>> = indices.iter().map(|&i| sidecar(slot, i)).collect();
        let columns: Vec<Column<'_>> = indices
            .iter()
            .zip(&bytes)
            .map(|(&index, ssz)| Column { index, ssz })
            .collect();
        writer.write_columns(slot, root, &columns).unwrap()
    }

    fn write_linked(writer: &ColumnWriter, slot: u64, root: &BlockRoot, link: BlockLink) {
        let ssz = sidecar(slot, 1);
        writer
            .write_block_columns(
                slot,
                root,
                link,
                &[Column {
                    index: 1,
                    ssz: &ssz,
                }],
            )
            .unwrap();
    }

    #[test]
    fn a_block_keeps_its_link_and_a_gap_raises_the_contiguous_slot() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let reader = writer.reader();
        assert_eq!(reader.contiguous_from().unwrap(), None);
        write_linked(&writer, 10, &ROOT_A, BlockLink::Start);
        assert_eq!(reader.link_of(&ROOT_A).unwrap(), Some(BlockLink::Start));
        assert_eq!(reader.contiguous_from().unwrap(), None, "a start is no gap");
        write_linked(&writer, 12, &ROOT_B, BlockLink::Parent(ROOT_A));
        assert_eq!(
            reader.link_of(&ROOT_B).unwrap(),
            Some(BlockLink::Parent(ROOT_A))
        );
        // A gap moves the contiguous slot up to the block's slot, never down.
        write_linked(&writer, 20, &[0xcc; 32], BlockLink::Gap);
        assert_eq!(reader.contiguous_from().unwrap(), Some(20));
        write_linked(&writer, 15, &[0xdd; 32], BlockLink::Gap);
        assert_eq!(reader.contiguous_from().unwrap(), Some(20));
        // A later write of a linked block never turns it into a gap; a gap block learns a link.
        write_linked(&writer, 12, &ROOT_B, BlockLink::Gap);
        assert_eq!(
            reader.link_of(&ROOT_B).unwrap(),
            Some(BlockLink::Parent(ROOT_A))
        );
        write_linked(&writer, 20, &[0xcc; 32], BlockLink::Parent(ROOT_B));
        assert_eq!(
            reader.link_of(&[0xcc; 32]).unwrap(),
            Some(BlockLink::Parent(ROOT_B))
        );
        assert_eq!(reader.contiguous_from().unwrap(), Some(20));
        // `write_columns` knows no link: a gap.
        write_block(&writer, 30, &[0xee; 32], &[1]);
        assert_eq!(reader.link_of(&[0xee; 32]).unwrap(), Some(BlockLink::Gap));
        assert_eq!(reader.contiguous_from().unwrap(), Some(30));
        assert_eq!(reader.link_of(&[0x11; 32]).unwrap(), None);
    }

    /// A child written before its parent waits for it without raising the contiguous slot, and
    /// links once the parent is written; one whose parent never comes is settled as a gap.
    #[test]
    fn a_pending_link_resolves_when_its_target_is_written_or_settles_as_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let reader = writer.reader();
        write_linked(&writer, 12, &ROOT_B, BlockLink::Pending(ROOT_A, 10));
        assert_eq!(
            reader.link_of(&ROOT_B).unwrap(),
            Some(BlockLink::Pending(ROOT_A, 10))
        );
        assert_eq!(reader.contiguous_from().unwrap(), None);
        write_linked(&writer, 10, &ROOT_A, BlockLink::Start);
        assert_eq!(
            reader.link_of(&ROOT_B).unwrap(),
            Some(BlockLink::Parent(ROOT_A))
        );
        // A target already stored: linked at once.
        write_linked(&writer, 14, &[0xcc; 32], BlockLink::Pending(ROOT_B, 12));
        assert_eq!(
            reader.link_of(&[0xcc; 32]).unwrap(),
            Some(BlockLink::Parent(ROOT_B))
        );
        // A target that never comes: pending until settled, then a gap at its slot.
        write_linked(&writer, 20, &[0xdd; 32], BlockLink::Pending([0x99; 32], 19));
        assert_eq!(writer.settle_pending(20).unwrap(), 0, "not before its slot");
        assert_eq!(reader.contiguous_from().unwrap(), None);
        // The pending index survives a reopen.
        drop(writer);
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(writer.settle_pending(21).unwrap(), 1);
        assert_eq!(
            writer.reader().link_of(&[0xdd; 32]).unwrap(),
            Some(BlockLink::Gap)
        );
        assert_eq!(writer.reader().contiguous_from().unwrap(), Some(20));
        // A gap block never goes back to pending; a pending one learns its link later.
        write_linked(&writer, 20, &[0xdd; 32], BlockLink::Pending([0x99; 32], 19));
        assert_eq!(
            writer.reader().link_of(&[0xdd; 32]).unwrap(),
            Some(BlockLink::Gap)
        );
    }

    /// BUG-008: a pending target that finality covers, pruned or refused, holds nothing the
    /// store must have: its child is a start, at write time or when settled, and raises nothing.
    #[test]
    fn a_pending_target_finality_covers_is_a_start_not_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let reader = writer.reader();
        // The target was stored when the link was found, and pruned before the write.
        writer.prune_finalized(10).unwrap();
        write_linked(&writer, 12, &ROOT_B, BlockLink::Pending(ROOT_A, 10));
        assert_eq!(reader.link_of(&ROOT_B).unwrap(), Some(BlockLink::Start));
        // Finality passes the target while the child waits for it.
        write_linked(&writer, 14, &[0xcc; 32], BlockLink::Pending([0x11; 32], 13));
        write_linked(&writer, 15, &[0xdd; 32], BlockLink::Pending([0x22; 32], 14));
        writer.prune_finalized(13).unwrap();
        assert_eq!(writer.settle_pending(100).unwrap(), 2);
        assert_eq!(reader.link_of(&[0xcc; 32]).unwrap(), Some(BlockLink::Start));
        // One whose target is still above finality is a gap.
        assert_eq!(reader.link_of(&[0xdd; 32]).unwrap(), Some(BlockLink::Gap));
        assert_eq!(reader.contiguous_from().unwrap(), Some(15));
        assert!(lock(&writer.column_ops).pending.is_empty());
    }

    /// BUG-009: a walk that failed once (a gap) does not overwrite a block waiting for its
    /// target, nor raise the contiguous slot; settlement decides.
    #[test]
    fn a_gap_never_replaces_a_pending_link() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let reader = writer.reader();
        write_linked(&writer, 12, &ROOT_B, BlockLink::Pending(ROOT_A, 11));
        write_linked(&writer, 12, &ROOT_B, BlockLink::Gap);
        write_block(&writer, 12, &ROOT_B, &[2]);
        assert_eq!(
            reader.link_of(&ROOT_B).unwrap(),
            Some(BlockLink::Pending(ROOT_A, 11))
        );
        assert_eq!(reader.contiguous_from().unwrap(), None);
        // The target still links it.
        write_linked(&writer, 11, &ROOT_A, BlockLink::Start);
        assert_eq!(
            reader.link_of(&ROOT_B).unwrap(),
            Some(BlockLink::Parent(ROOT_A))
        );
    }

    /// CR-006: a pending block that links elsewhere leaves no entry behind for its old target.
    #[test]
    fn relinking_a_pending_block_forgets_its_old_target() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        write_linked(&writer, 12, &ROOT_B, BlockLink::Pending(ROOT_A, 11));
        write_linked(&writer, 12, &ROOT_B, BlockLink::Pending([0x77; 32], 10));
        {
            let ops = lock(&writer.column_ops);
            assert!(!ops.pending.contains_key(&ROOT_A), "{:?}", ops.pending);
            assert_eq!(ops.pending[&[0x77; 32]], [(ROOT_B, 12)]);
        }
        write_linked(&writer, 12, &ROOT_B, BlockLink::Start);
        assert!(lock(&writer.column_ops).pending.is_empty());
        assert_eq!(writer.settle_pending(100).unwrap(), 0);
    }

    /// Stores `link` for `root` as it is, bypassing every rule: rows of an older schema.
    fn put_raw_link(writer: &ColumnWriter, root: &BlockRoot, value: &[u8]) {
        let txn = writer.reader.db.begin_rw_txn().unwrap();
        let links = txn.open_table(Some(LINKS_TABLE)).unwrap();
        txn.put(&links, root, value, WriteFlags::UPSERT).unwrap();
        txn.commit().unwrap();
    }

    /// The previous schema stored a pending link without its target's slot (`3 ‖ root`). A
    /// writer opening such an env migrates every one in its open transaction: a parent link if
    /// the target is stored, else a gap that raises the contiguous slot; a reader before that
    /// reads it as a gap, and a second open finds nothing left to migrate.
    #[test]
    fn pending_links_of_the_previous_schema_are_migrated_once() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = |target: &BlockRoot| {
            let mut value = vec![3];
            value.extend_from_slice(target);
            value
        };
        {
            let writer = ColumnWriter::open(dir.path()).unwrap();
            write_linked(&writer, 10, &ROOT_A, BlockLink::Start);
            write_linked(&writer, 12, &ROOT_B, BlockLink::Start);
            write_linked(&writer, 14, &[0xcc; 32], BlockLink::Start);
            put_raw_link(&writer, &ROOT_B, &legacy(&ROOT_A));
            put_raw_link(&writer, &[0xcc; 32], &legacy(&[0x99; 32]));
        }
        {
            let reader = ColumnReader::open(dir.path()).unwrap();
            assert_eq!(reader.link_of(&[0xcc; 32]).unwrap(), Some(BlockLink::Gap));
            assert_eq!(reader.contiguous_from().unwrap(), None, "not migrated yet");
        }
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let reader = writer.reader();
        assert_eq!(
            reader.link_of(&ROOT_B).unwrap(),
            Some(BlockLink::Parent(ROOT_A))
        );
        assert_eq!(reader.link_of(&[0xcc; 32]).unwrap(), Some(BlockLink::Gap));
        assert_eq!(reader.contiguous_from().unwrap(), Some(14));
        assert!(lock(&writer.column_ops).pending.is_empty());
        {
            let txn = writer.reader.db.begin_rw_txn().unwrap();
            assert_eq!(migrate_legacy_pending(&txn).unwrap(), 0, "nothing left");
        }
        drop(writer);
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(
            writer.reader().link_of(&ROOT_B).unwrap(),
            Some(BlockLink::Parent(ROOT_A))
        );
        assert_eq!(writer.reader().contiguous_from().unwrap(), Some(14));
        // A link of today's schema is never taken for an old one.
        write_linked(&writer, 16, &[0xdd; 32], BlockLink::Pending([0x98; 32], 15));
        drop(writer);
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(
            writer.reader().link_of(&[0xdd; 32]).unwrap(),
            Some(BlockLink::Pending([0x98; 32], 15))
        );
        assert_eq!(writer.settle_pending(100).unwrap(), 1, "still indexed");
    }

    #[test]
    fn pruning_removes_the_links_of_the_blocks_it_removes() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        write_linked(&writer, 10, &ROOT_A, BlockLink::Start);
        write_linked(&writer, 12, &ROOT_B, BlockLink::Parent(ROOT_A));
        writer.prune_orphaned(&[ROOT_B]).unwrap();
        assert_eq!(writer.reader().link_of(&ROOT_B).unwrap(), None);
        writer.prune_finalized(10).unwrap();
        assert_eq!(writer.reader().link_of(&ROOT_A).unwrap(), None);
    }

    #[test]
    fn written_columns_read_back_by_root() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        write_block(&writer, 5, &ROOT_A, &[9, 0, 127]);

        let reader = writer.reader();
        assert_eq!(reader.slot_of(&ROOT_A).unwrap(), Some(5));
        assert_eq!(reader.get(&ROOT_A, 9).unwrap(), Some(sidecar(5, 9)));
        assert_eq!(reader.get(&ROOT_A, 1).unwrap(), None);
        assert_eq!(reader.get(&ROOT_B, 9).unwrap(), None);
        assert_eq!(
            reader.columns_for_root(&ROOT_A).unwrap(),
            vec![
                (0, sidecar(5, 0)),
                (9, sidecar(5, 9)),
                (127, sidecar(5, 127))
            ]
        );
        assert_eq!(reader.columns_for_root(&ROOT_B).unwrap(), vec![]);
        assert_eq!(reader.column_count().unwrap(), 3);
        assert_eq!(reader.block_count().unwrap(), 1);
    }

    #[test]
    fn rewriting_a_column_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        write_block(&writer, 5, &ROOT_A, &[3]);
        writer
            .write_columns(
                5,
                &ROOT_A,
                &[Column {
                    index: 3,
                    ssz: b"new",
                }],
            )
            .unwrap();
        assert_eq!(
            writer.reader().get(&ROOT_A, 3).unwrap(),
            Some(b"new".to_vec())
        );
        assert_eq!(writer.reader().column_count().unwrap(), 1);
    }

    #[test]
    fn invalid_columns_are_rejected_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let mut columns: Vec<Column<'_>> =
            (0..20).map(|index| Column { index, ssz: b"x" }).collect();
        columns.push(Column {
            index: NUMBER_OF_COLUMNS,
            ssz: b"x",
        });
        assert!(matches!(
            writer.write_columns(1, &ROOT_A, &columns),
            Err(Error::ColumnIndexOutOfRange {
                index: NUMBER_OF_COLUMNS
            })
        ));
        assert!(matches!(
            writer.write_columns(1, &ROOT_A, &[Column { index: 4, ssz: b"" }]),
            Err(Error::EmptySidecar { index: 4 })
        ));
        assert_eq!(writer.rw_txns_committed(), 0);
        assert_eq!(writer.reader().column_count().unwrap(), 0);
        assert_eq!(writer.reader().block_count().unwrap(), 0);
    }

    #[test]
    fn a_block_root_cannot_move_to_another_slot() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        write_block(&writer, 5, &ROOT_A, &[0]);
        assert!(matches!(
            writer.write_columns(
                6,
                &ROOT_A,
                &[Column {
                    index: 1,
                    ssz: b"x"
                }]
            ),
            Err(Error::SlotMismatch {
                stored: 5,
                given: 6
            })
        ));
        assert_eq!(writer.reader().columns_for_root(&ROOT_A).unwrap().len(), 1);
    }

    #[test]
    fn empty_write_opens_no_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let report = writer.write_columns(1, &ROOT_A, &[]).unwrap();
        assert_eq!(report, WriteReport::default());
        assert_eq!(writer.rw_txns_committed(), 0);
        assert_eq!(writer.reader().slot_of(&ROOT_A).unwrap(), None);
    }

    #[test]
    fn chunks_le_16() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let all: Vec<u64> = (0..NUMBER_OF_COLUMNS).collect();

        let before = writer.rw_txns_committed();
        let report = write_block(&writer, 7, &ROOT_A, &all);
        assert_eq!(writer.rw_txns_committed() - before, 8);
        assert_eq!(report.transactions, 8);
        assert_eq!(report.columns, 128);
        assert!(report.max_columns_per_txn <= MAX_COLUMNS_PER_TXN);
        assert_eq!(MAX_COLUMNS_PER_TXN, 16);
        assert_eq!(
            writer.reader().columns_for_root(&ROOT_A).unwrap().len(),
            128
        );

        // A sibling at the same slot survives the reorg; the orphaned block leaves no row.
        write_block(&writer, 7, &ROOT_B, &[0, 1]);
        let pruned = writer.prune_orphaned(&[ROOT_A]).unwrap();
        assert_eq!(
            pruned,
            PruneReport {
                columns: 128,
                blocks: 1
            }
        );
        let reader = writer.reader();
        assert_eq!(reader.columns_for_root(&ROOT_A).unwrap(), vec![]);
        assert_eq!(reader.slot_of(&ROOT_A).unwrap(), None);
        assert_eq!(reader.column_count().unwrap(), 2);
        assert_eq!(reader.block_count().unwrap(), 1);
    }

    #[test]
    fn finality_prunes_every_column_at_or_below_the_finalized_slot() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let root_c: BlockRoot = [0xcc; 32];
        let root_d: BlockRoot = [0xdd; 32];
        write_block(&writer, 3, &ROOT_A, &[0, 1]);
        write_block(&writer, 4, &ROOT_B, &[5]);
        write_block(&writer, 4, &root_c, &[6, 7, 8]);
        write_block(&writer, 5, &root_d, &[0]);

        let pruned = writer.prune_finalized(4).unwrap();
        assert_eq!(
            pruned,
            PruneReport {
                columns: 6,
                blocks: 3
            }
        );
        let reader = writer.reader();
        for root in [ROOT_A, ROOT_B, root_c] {
            assert_eq!(reader.slot_of(&root).unwrap(), None);
            assert_eq!(reader.columns_for_root(&root).unwrap(), vec![]);
        }
        assert_eq!(
            reader.columns_for_root(&root_d).unwrap(),
            vec![(0, sidecar(5, 0))]
        );
        assert_eq!(reader.column_count().unwrap(), 1);
        assert_eq!(reader.block_count().unwrap(), 1);
    }

    #[test]
    fn the_first_stored_slot_is_the_lowest_slot_ever_written() {
        let dir = tempfile::tempdir().unwrap();
        {
            let writer = ColumnWriter::open(dir.path()).unwrap();
            assert_eq!(writer.reader().first_stored_slot().unwrap(), None);
            // An empty write stores nothing, so it sets nothing.
            writer.write_columns(30, &ROOT_A, &[]).unwrap();
            assert_eq!(writer.reader().first_stored_slot().unwrap(), None);
            write_block(&writer, 20, &ROOT_A, &[1]);
            assert_eq!(writer.reader().first_stored_slot().unwrap(), Some(20));
            // A later slot leaves it; a refused write (another slot for a stored root) too.
            write_block(&writer, 25, &ROOT_B, &[1, 2]);
            assert!(writer
                .write_columns(
                    3,
                    &ROOT_A,
                    &[Column {
                        index: 2,
                        ssz: b"x"
                    }]
                )
                .is_err());
            assert_eq!(writer.reader().first_stored_slot().unwrap(), Some(20));
            // A late column of an earlier slot lowers it, in the transaction that stores it.
            let before = writer.rw_txns_committed();
            write_block(&writer, 18, &[0xcc; 32], &[4]);
            assert_eq!(writer.rw_txns_committed(), before + 1);
            assert_eq!(writer.reader().first_stored_slot().unwrap(), Some(18));
            // Pruning removes columns, never the record of where storing began.
            writer.prune_finalized(20).unwrap();
            writer.prune_orphaned(&[ROOT_B]).unwrap();
            assert_eq!(writer.reader().column_count().unwrap(), 0);
            assert_eq!(writer.reader().first_stored_slot().unwrap(), Some(18));
        }
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(writer.reader().first_stored_slot().unwrap(), Some(18));
    }

    #[test]
    fn finality_prune_with_nothing_to_remove_only_advances_the_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        write_block(&writer, 10, &ROOT_A, &[0]);

        let before = writer.rw_txns_committed();
        assert_eq!(writer.prune_finalized(9).unwrap(), PruneReport::default());
        assert_eq!(writer.rw_txns_committed(), before + 1);
        assert_eq!(writer.reader().finalized_slot().unwrap(), Some(9));

        // Same or older finality: nothing to delete and nothing to advance.
        assert_eq!(writer.prune_finalized(9).unwrap(), PruneReport::default());
        assert_eq!(writer.prune_finalized(2).unwrap(), PruneReport::default());
        assert_eq!(writer.rw_txns_committed(), before + 1);
        assert_eq!(writer.reader().finalized_slot().unwrap(), Some(9));
        assert_eq!(writer.reader().column_count().unwrap(), 1);
    }

    #[test]
    fn a_late_write_cannot_undo_a_finality_prune() {
        let dir = tempfile::tempdir().unwrap();
        {
            let writer = ColumnWriter::open(dir.path()).unwrap();
            assert_eq!(writer.reader().finalized_slot().unwrap(), None);
            write_block(&writer, 5, &ROOT_A, &[0]);
            writer.prune_finalized(5).unwrap();
            let before = writer.rw_txns_committed();
            for slot in [5, 4, 0] {
                assert!(matches!(
                    writer.write_columns(slot, &ROOT_B, &[Column { index: 1, ssz: b"x" }]),
                    Err(Error::SlotFinalized { slot: s, finalized_slot: 5 }) if s == slot
                ));
            }
            assert!(matches!(
                writer.write_columns(5, &ROOT_B, &[]),
                Err(Error::SlotFinalized { .. })
            ));
            assert_eq!(writer.rw_txns_committed(), before);
            assert_eq!(writer.reader().column_count().unwrap(), 0);
        }
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(writer.reader().finalized_slot().unwrap(), Some(5));
        assert!(writer
            .write_columns(
                4,
                &ROOT_B,
                &[Column {
                    index: 1,
                    ssz: b"x"
                }]
            )
            .is_err());
        write_block(&writer, 6, &ROOT_B, &[1]);
        assert_eq!(writer.reader().column_count().unwrap(), 1);
    }

    #[test]
    fn batches_with_too_many_or_duplicate_columns_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let mut columns: Vec<Column<'_>> = (0..NUMBER_OF_COLUMNS)
            .map(|index| Column { index, ssz: b"x" })
            .collect();
        columns.push(Column {
            index: 0,
            ssz: b"x",
        });
        assert!(matches!(
            writer.write_columns(1, &ROOT_A, &columns),
            Err(Error::TooManyColumns { len: 129 })
        ));
        let duplicate = [3, 5, 3].map(|index| Column { index, ssz: b"x" });
        assert!(matches!(
            writer.write_columns(1, &ROOT_A, &duplicate),
            Err(Error::DuplicateColumn { index: 3 })
        ));
        assert_eq!(writer.rw_txns_committed(), 0);
        assert_eq!(writer.reader().column_count().unwrap(), 0);
    }

    #[test]
    fn sidecar_size_cap_is_the_largest_encodable_fulu_sidecar() {
        // 4096 cells of 2048 B, 4096 commitments and 4096 proofs of 48 B, plus index, three list
        // offsets, signed header and 4-deep inclusion proof.
        assert_eq!(MAX_SIDECAR_BYTES, 356 + 4096 * (2048 + 48 + 48));
        assert_eq!(MAX_SIDECAR_BYTES, 8_782_180);
        // Gloas sidecars (56 fixed + 2096 per blob) fit up to 4,189 blobs per block.
        let gloas = |blobs: usize| 56 + blobs * (2048 + 48);
        assert!(gloas(4189) <= MAX_SIDECAR_BYTES);
        assert!(gloas(4190) > MAX_SIDECAR_BYTES);

        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let largest = vec![1u8; MAX_SIDECAR_BYTES];
        let too_large = vec![1u8; MAX_SIDECAR_BYTES + 1];
        assert!(matches!(
            writer.write_columns(1, &ROOT_A, &[Column { index: 2, ssz: &too_large }]),
            Err(Error::SidecarTooLarge { index: 2, len }) if len == MAX_SIDECAR_BYTES + 1
        ));
        writer
            .write_columns(
                1,
                &ROOT_A,
                &[Column {
                    index: 2,
                    ssz: &largest,
                }],
            )
            .unwrap();
        assert_eq!(
            writer.reader().get(&ROOT_A, 2).unwrap().map(|v| v.len()),
            Some(MAX_SIDECAR_BYTES)
        );
    }

    #[test]
    fn a_full_map_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let options = WriterOptions {
            max_size: MIN_MAX_SIZE,
        };
        let writer = ColumnWriter::open_with(dir.path(), options).unwrap();
        // Two 16-column chunks of the largest sidecar need ~281 MB; the map holds 256 MiB.
        let ssz = vec![9u8; MAX_SIDECAR_BYTES];
        let columns: Vec<Column<'_>> = (0..32).map(|index| Column { index, ssz: &ssz }).collect();
        assert!(matches!(
            writer.write_columns(1, &ROOT_A, &columns),
            Err(Error::MapFull)
        ));
        assert_eq!(writer.reader().column_count().unwrap(), 16);
    }

    #[test]
    fn writer_options_default_and_validate_the_map_size() {
        assert_eq!(WriterOptions::default().max_size, 256 << 30);
        assert_eq!(MIN_MAX_SIZE, 256 << 20);
        let dir = tempfile::tempdir().unwrap();
        for max_size in [
            0,
            1 << 20,
            MIN_MAX_SIZE - (1 << 20),
            MIN_MAX_SIZE + 1,
            usize::MAX,
        ] {
            assert!(
                matches!(
                    ColumnWriter::open_with(dir.path(), WriterOptions { max_size }),
                    Err(Error::InvalidMaxSize { max_size: m }) if m == max_size
                ),
                "max_size {max_size} accepted"
            );
        }
        let writer = ColumnWriter::open_with(
            dir.path(),
            WriterOptions {
                max_size: MIN_MAX_SIZE,
            },
        )
        .unwrap();
        assert_eq!(writer.reader().db.info().unwrap().map_size(), MIN_MAX_SIZE);
    }

    #[test]
    fn reopening_alone_applies_a_new_map_size() {
        let dir = tempfile::tempdir().unwrap();
        let small = WriterOptions {
            max_size: MIN_MAX_SIZE,
        };
        let large = WriterOptions {
            max_size: 2 * MIN_MAX_SIZE,
        };
        drop(ColumnWriter::open_with(dir.path(), small).unwrap());
        let writer = ColumnWriter::open_with(dir.path(), large).unwrap();
        assert_eq!(
            writer.reader().db.info().unwrap().map_size(),
            2 * MIN_MAX_SIZE
        );
    }

    #[test]
    fn a_corrupt_cgc_value_is_reported_not_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer
            .write_txn(Priority::Import, |txn| {
                let meta = txn.open_table(Some(META_TABLE))?;
                txn.put(&meta, CGC_KEY, [1, 2, 3], WriteFlags::UPSERT)?;
                Ok(Commit::Yes(()))
            })
            .unwrap();
        assert!(matches!(
            writer.reader().cgc(),
            Err(Error::Corrupt { table: META_TABLE })
        ));
    }

    #[test]
    fn finality_prune_deletes_whole_blocks_in_bounded_transactions() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let all: Vec<u64> = (0..NUMBER_OF_COLUMNS).collect();
        for slot in 1..=3u64 {
            write_block(&writer, slot, &[slot as u8; 32], &all);
        }
        for slot in 4..=23u64 {
            write_block(&writer, slot, &[slot as u8; 32], &[0, 1, 2, 3, 4]);
        }

        let before = writer.rw_txns_committed();
        let pruned = writer.prune_finalized(23).unwrap();
        assert_eq!(
            pruned,
            PruneReport {
                columns: 3 * 128 + 100,
                blocks: 23
            }
        );
        // Three full blocks, one txn each; the twenty 5-column blocks fit in one more.
        assert_eq!(writer.rw_txns_committed() - before, 4);
        assert_eq!(writer.reader().column_count().unwrap(), 0);
        assert_eq!(writer.reader().block_count().unwrap(), 0);
    }

    #[test]
    fn a_write_cannot_bring_back_an_orphaned_root() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        write_block(&writer, 5, &ROOT_A, &[0, 1]);
        writer.prune_orphaned(&[ROOT_A]).unwrap();
        // Columns of the orphan that were still in flight when it was pruned.
        let late = [Column {
            index: 2,
            ssz: b"x",
        }];
        assert!(matches!(
            writer.write_columns(5, &ROOT_A, &late),
            Err(Error::RootOrphaned)
        ));
        // A root pruned before any column of it was stored is refused too.
        writer.prune_orphaned(&[ROOT_B]).unwrap();
        assert!(matches!(
            writer.write_columns(6, &ROOT_B, &late),
            Err(Error::RootOrphaned)
        ));
        let reader = writer.reader();
        assert_eq!(reader.slot_of(&ROOT_A).unwrap(), None);
        assert_eq!(reader.slot_of(&ROOT_B).unwrap(), None);
        assert_eq!(reader.column_count().unwrap(), 0);
        // Other roots, at the same slots, still store.
        write_block(&writer, 5, &[0xcc; 32], &[2]);
        assert_eq!(reader.column_count().unwrap(), 1);
    }

    #[test]
    fn a_slotless_tombstone_whose_late_write_is_finalized_is_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer.prune_orphaned(&[ROOT_B]).unwrap();
        writer.prune_finalized(10).unwrap();
        assert!(lock(&writer.column_ops).contains(&ROOT_B), "no slot: kept");
        // Its first late write lands after finality: refused by the watermark, which refuses
        // the root's slot from now on, so the tombstone is no longer needed.
        let late = [Column {
            index: 2,
            ssz: b"x",
        }];
        assert!(matches!(
            writer.write_columns(5, &ROOT_B, &late),
            Err(Error::SlotFinalized { slot: 5, .. })
        ));
        assert!(!lock(&writer.column_ops).contains(&ROOT_B));
        assert_eq!(lock(&writer.column_ops).order.len(), 0);
    }

    #[test]
    fn a_tombstone_learns_its_slot_from_a_refused_write() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        // Pruned before any column of it was stored: no slot yet.
        writer.prune_orphaned(&[ROOT_B]).unwrap();
        assert_eq!(lock(&writer.column_ops).slots.get(&ROOT_B), Some(&None));
        let late = [Column {
            index: 2,
            ssz: b"x",
        }];
        assert!(matches!(
            writer.write_columns(6, &ROOT_B, &late),
            Err(Error::RootOrphaned)
        ));
        assert_eq!(lock(&writer.column_ops).slots.get(&ROOT_B), Some(&Some(6)));
        // So finality at its slot forgets it.
        writer.prune_finalized(6).unwrap();
        assert!(!lock(&writer.column_ops).contains(&ROOT_B));
    }

    #[test]
    fn orphan_tombstones_are_bounded_and_forgotten_once_finalized() {
        let mut orphans = Orphans::default();
        let root = |i: usize| {
            let mut root = [0u8; 32];
            root[..8].copy_from_slice(&(i as u64).to_be_bytes());
            root
        };
        for i in 0..=MAX_ORPHANED_ROOTS {
            orphans.insert(root(i), Some(i as u64));
        }
        assert_eq!(orphans.slots.len(), MAX_ORPHANED_ROOTS);
        assert!(!orphans.contains(&root(0)), "the oldest is forgotten");
        assert!(orphans.contains(&root(1)));
        // A root pruned again keeps its place; its slot is filled in once known.
        orphans.insert(root(7), None);
        orphans.insert([0xee; 32], None);
        orphans.insert([0xee; 32], Some(3));
        // Finality forgets the tombstones it covers: the watermark refuses those slots anyway.
        orphans.forget_finalized(500);
        assert!(!orphans.contains(&root(500)) && !orphans.contains(&[0xee; 32]));
        assert!(
            !orphans.contains(&root(7)),
            "pruned again, it kept its known slot"
        );
        assert!(orphans.contains(&root(501)));
        assert_eq!(orphans.order.len(), orphans.slots.len());
        // A tombstone with no slot is kept until it is evicted.
        orphans.insert([0xdd; 32], None);
        orphans.forget_finalized(u64::MAX);
        assert!(orphans.contains(&[0xdd; 32]));
        assert_eq!(orphans.slots.len(), 1);
    }

    #[test]
    fn prune_orphaned_skips_unknown_roots() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        write_block(&writer, 1, &ROOT_A, &[0]);
        let before = writer.rw_txns_committed();
        assert_eq!(
            writer.prune_orphaned(&[ROOT_B]).unwrap(),
            PruneReport::default()
        );
        assert_eq!(writer.rw_txns_committed(), before);
        assert_eq!(writer.reader().column_count().unwrap(), 1);
    }

    #[test]
    fn cgc_round_trips_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let writer = ColumnWriter::open(dir.path()).unwrap();
            assert_eq!(writer.reader().cgc().unwrap(), None);
            writer.set_cgc(4).unwrap();
            writer.set_cgc(NUMBER_OF_CUSTODY_GROUPS).unwrap();
            assert!(matches!(
                writer.set_cgc(NUMBER_OF_CUSTODY_GROUPS + 1),
                Err(Error::CgcOutOfRange(129))
            ));
            write_block(&writer, 1, &ROOT_A, &[2]);
        }
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(
            writer.reader().cgc().unwrap(),
            Some(NUMBER_OF_CUSTODY_GROUPS)
        );
        assert_eq!(
            writer.reader().get(&ROOT_A, 2).unwrap(),
            Some(sidecar(1, 2))
        );
    }

    fn custody(cgc: u64, cgc_set_slot: u64, metadata_seq: u64) -> CustodyRecord {
        CustodyRecord {
            cgc,
            cgc_set_slot,
            metadata_seq,
            advertised_cgc: cgc,
        }
    }

    #[test]
    fn the_custody_record_round_trips_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let writer = ColumnWriter::open(dir.path()).unwrap();
            assert_eq!(writer.reader().custody().unwrap(), None);
            let before = writer.rw_txns_committed();
            writer.set_custody(&custody(4, 10, 1)).unwrap();
            writer.set_custody(&custody(8, 20, 2)).unwrap();
            // One write transaction each: the four values move together.
            assert_eq!(writer.rw_txns_committed() - before, 2);
            assert_eq!(writer.reader().custody().unwrap(), Some(custody(8, 20, 2)));
        }
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(writer.reader().custody().unwrap(), Some(custody(8, 20, 2)));
        assert_eq!(writer.reader().cgc().unwrap(), Some(8));
    }

    #[test]
    fn a_lower_cgc_is_refused_and_the_stored_record_stays() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer.set_custody(&custody(4, 10, 1)).unwrap();
        let before = writer.rw_txns_committed();
        assert!(matches!(
            writer.set_custody(&custody(2, 11, 2)),
            Err(Error::CgcDecrease {
                stored: 4,
                requested: 2
            })
        ));
        assert!(matches!(
            writer.set_cgc(3),
            Err(Error::CgcDecrease {
                stored: 4,
                requested: 3
            })
        ));
        assert_eq!(writer.rw_txns_committed(), before);
        assert_eq!(writer.reader().custody().unwrap(), Some(custody(4, 10, 1)));
        // The same count again is not a decrease: the other values may still move.
        writer.set_custody(&custody(4, 12, 2)).unwrap();
        assert_eq!(writer.reader().custody().unwrap(), Some(custody(4, 12, 2)));
    }

    #[test]
    fn custody_counts_past_the_group_count_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert!(matches!(
            writer.set_custody(&custody(NUMBER_OF_CUSTODY_GROUPS + 1, 0, 0)),
            Err(Error::CgcOutOfRange(129))
        ));
        let mut record = custody(4, 0, 0);
        record.advertised_cgc = NUMBER_OF_CUSTODY_GROUPS + 1;
        assert!(matches!(
            writer.set_custody(&record),
            Err(Error::CgcOutOfRange(129))
        ));
        assert_eq!(writer.reader().custody().unwrap(), None);
    }

    /// A count stored by `set_cgc` alone reads back with the other values at 0.
    #[test]
    fn a_cgc_without_the_rest_of_the_record_reads_as_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer.set_cgc(4).unwrap();
        assert_eq!(
            writer.reader().custody().unwrap(),
            Some(CustodyRecord {
                cgc: 4,
                cgc_set_slot: 0,
                metadata_seq: 0,
                advertised_cgc: 0,
            })
        );
    }

    #[test]
    fn import_goes_ahead_of_a_queued_column_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let writer = std::sync::Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let held = writer.sched.acquire(Priority::Background);

        let columns = {
            let writer = writer.clone();
            std::thread::spawn(move || {
                writer
                    .write_columns(
                        1,
                        &ROOT_A,
                        &[Column {
                            index: 0,
                            ssz: b"x",
                        }],
                    )
                    .unwrap()
            })
        };
        crate::sched::tests::wait_for_queue(&writer.sched, 0, 1);
        let import = {
            let writer = writer.clone();
            std::thread::spawn(move || writer.set_cgc(4).unwrap())
        };
        crate::sched::tests::wait_for_queue(&writer.sched, 1, 1);

        drop(held);
        import.join().unwrap();
        columns.join().unwrap();
        assert_eq!(
            writer.sched.grants(),
            vec![Priority::Background, Priority::Import, Priority::Background]
        );
        assert_eq!(writer.reader().cgc().unwrap(), Some(4));
        assert_eq!(writer.reader().column_count().unwrap(), 1);
    }

    /// Wall-clock check of the same property against real MDBX: without the scheduler, a
    /// collision costs libmdbx's 250 ms `MDBX_BUSY` retry. Timing-based, so not in the default
    /// run; `examples/write_bench.rs` measures the distribution.
    #[test]
    #[ignore = "wall-clock; run with --ignored"]
    fn priority_write_never_waits_out_a_busy_retry() {
        let dir = tempfile::tempdir().unwrap();
        let writer = std::sync::Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let background = {
            let (writer, done) = (writer.clone(), done.clone());
            std::thread::spawn(move || {
                let ssz = vec![7u8; 4096];
                let columns: Vec<Column<'_>> = (0..NUMBER_OF_COLUMNS)
                    .map(|index| Column { index, ssz: &ssz })
                    .collect();
                for slot in 0..48 {
                    writer
                        .write_columns(slot, &[slot as u8; 32], &columns)
                        .unwrap();
                }
                done.store(true, Ordering::Relaxed);
            })
        };
        let mut worst = std::time::Duration::ZERO;
        let mut writes = 0;
        while !done.load(Ordering::Relaxed) {
            let start = std::time::Instant::now();
            writer.set_cgc(4).unwrap();
            worst = worst.max(start.elapsed());
            writes += 1;
            // Import commits in bursts, not back to back; a busy loop would starve the writer.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        background.join().unwrap();
        assert!(
            writes > 10,
            "only {writes} priority writes overlapped the background writer"
        );
        assert!(
            worst < std::time::Duration::from_millis(200),
            "priority write waited {worst:?}"
        );
    }
}
