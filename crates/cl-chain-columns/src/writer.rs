use std::{
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
        block_prefix, column_key, decode_column_key, BlockRoot, ADVERTISED_CGC_KEY, CGC_KEY,
        CGC_SET_SLOT_KEY, COLUMNS_TABLE, FINALIZED_SLOT_KEY, METADATA_SEQ_KEY, META_TABLE,
        ROOTS_TABLE,
    },
    reader::{meta_u64, scan_block, stored_slot, ColumnReader, CustodyRecord},
    sched::{Priority, TxnScheduler},
    NUMBER_OF_COLUMNS, NUMBER_OF_CUSTODY_GROUPS,
};

/// Most columns one write transaction carries. MDBX runs one write txn at a time per env, so a
/// large txn stalls block import while it is open.
pub const MAX_COLUMNS_PER_TXN: usize = 16;

/// Most rows one finality-prune transaction deletes. Blocks are never split across
/// transactions, and one block holds at most [`NUMBER_OF_COLUMNS`] rows, so this is a hard cap.
pub const MAX_ROWS_PER_PRUNE_TXN: u64 = NUMBER_OF_COLUMNS;

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
    /// block's write and leaves the later chunks behind as orphans.
    column_ops: Mutex<()>,
    sched: TxnScheduler,
    rw_txns: AtomicU64,
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
        Ok(Self {
            reader: ColumnReader::from_env(db),
            column_ops: Mutex::new(()),
            sched: TxnScheduler::default(),
            rw_txns: AtomicU64::new(0),
            _guard: guard,
        })
    }

    /// Read access through the writer's own env.
    #[must_use]
    pub fn reader(&self) -> &ColumnReader {
        &self.reader
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
    /// ([`Error::SlotFinalized`]). A column already stored under the same key is replaced.
    pub fn write_columns(
        &self,
        slot: u64,
        block_root: &BlockRoot,
        columns: &[Column<'_>],
    ) -> Result<WriteReport> {
        validate_batch(columns)?;
        let _ops = lock(&self.column_ops);
        // Under `column_ops`, so no finality prune can move the watermark until this returns.
        if let Some(finalized_slot) = self.reader.finalized_slot()? {
            if slot <= finalized_slot {
                return Err(Error::SlotFinalized {
                    slot,
                    finalized_slot,
                });
            }
        }
        let mut report = WriteReport::default();
        for (i, chunk) in columns.chunks(MAX_COLUMNS_PER_TXN).enumerate() {
            if i > 0 {
                thread::yield_now();
            }
            self.write_txn(Priority::Background, |txn| {
                write_chunk(txn, slot, block_root, chunk).map(Commit::Yes)
            })?;
            report.columns += chunk.len();
            report.transactions += 1;
            report.max_columns_per_txn = report.max_columns_per_txn.max(chunk.len());
        }
        Ok(report)
    }

    /// Reorg pruning: removes every column of each orphaned block root, one write transaction
    /// per block (at most [`NUMBER_OF_COLUMNS`] rows), yielding between blocks. Unknown roots are
    /// skipped.
    pub fn prune_orphaned(&self, block_roots: &[BlockRoot]) -> Result<PruneReport> {
        let _ops = lock(&self.column_ops);
        let mut report = PruneReport::default();
        for (i, block_root) in block_roots.iter().enumerate() {
            if i > 0 {
                thread::yield_now();
            }
            let removed = self.write_txn(Priority::Background, |txn| {
                Ok(match prune_block(txn, block_root)? {
                    Some(columns) => Commit::Yes(Some(columns)),
                    None => Commit::No(None),
                })
            })?;
            if let Some(columns) = removed {
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
        let _ops = lock(&self.column_ops);
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
                return Ok(report);
            }
            thread::yield_now();
        }
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

/// The guarded state is `()`, so a panic elsewhere cannot leave it inconsistent.
fn lock(mutex: &Mutex<()>) -> MutexGuard<'_, ()> {
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
    Ok(())
}

/// Removes one block's columns and its root entry; returns the number of columns removed,
/// `None` if the block is not stored.
fn prune_block(txn: &RwTxn<'_>, block_root: &BlockRoot) -> Result<Option<u64>> {
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
    Ok(Some(rows.len() as u64))
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
