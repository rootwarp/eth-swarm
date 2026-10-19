use std::{borrow::Cow, path::Path};

use libmdbx::{Decodable, NoWriteMap, Table, Transaction, TransactionKind, RO};

use crate::{
    env,
    error::{Error, Result},
    keys::{
        block_prefix, column_key, decode_column_key, BlockLink, BlockRoot, ADVERTISED_CGC_KEY,
        BLOCK_PREFIX_LEN, CGC_KEY, CGC_SET_SLOT_KEY, COLUMNS_TABLE, CONTIGUOUS_FROM_KEY,
        FINALIZED_SLOT_KEY, FIRST_STORED_SLOT_KEY, LINKS_TABLE, METADATA_SEQ_KEY, META_TABLE,
        ROOTS_TABLE,
    },
};

/// The node's custody state, stored in one write transaction
/// ([`ColumnWriter::set_custody`](crate::ColumnWriter::set_custody)) so it survives a restart
/// whole.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CustodyRecord {
    /// The custody group count; it never decreases.
    pub cgc: u64,
    /// The slot at which `cgc` was last raised.
    pub cgc_set_slot: u64,
    /// The MetaData `seq_number`.
    pub metadata_seq: u64,
    /// The custody group count peers are told (ENR `cgc`, MetaData `custody_group_count`).
    pub advertised_cgc: u64,
}

/// One stored column read by [`ColumnReader::columns_in_range`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeColumn {
    /// The slot of its block.
    pub slot: u64,
    /// Its block.
    pub block_root: BlockRoot,
    /// Its column index.
    pub index: u64,
    /// Its SSZ, as stored.
    pub ssz: Vec<u8>,
}

/// One block of a range read, with its link ([`BlockLink::Gap`] for a block stored without
/// one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeBlock {
    /// Its slot.
    pub slot: u64,
    /// Its root.
    pub block_root: BlockRoot,
    /// How it ties to the stored block before it on its chain.
    pub link: BlockLink,
}

/// What [`ColumnReader::columns_in_range`] read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeRead {
    /// The columns, in key order: slot, then block root, then column index.
    pub columns: Vec<RangeColumn>,
    /// Every block of the range read, in key order, whether or not it holds a wanted column.
    pub blocks: Vec<RangeBlock>,
    /// The block `(slot, block_root)` the read stopped at for its budget, before the end of the
    /// range: the last block of [`Self::blocks`] if the budget cut it, with some of its stored
    /// columns not read, or the block after it, not read at all. `None` if the range was read
    /// to its end.
    pub cut: Option<(u64, BlockRoot)>,
}

/// How much one [`ColumnReader::columns_in_range`] may read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeBudget {
    /// The SSZ bytes of the columns read, at most.
    pub max_bytes: usize,
    /// The columns read, at most.
    pub max_columns: usize,
    /// The read stops with [`Error::Deadline`] once this passes.
    pub deadline: Option<std::time::Instant>,
}

impl RangeBudget {
    /// No bound at all.
    #[must_use]
    pub fn unbounded() -> Self {
        Self {
            max_bytes: usize::MAX,
            max_columns: usize::MAX,
            deadline: None,
        }
    }
}

/// How many rows a range read walks between two looks at its deadline.
const DEADLINE_EVERY: usize = 64;

/// Read-only view of the column store.
///
/// [`ColumnReader::open`] opens the env with `MDBX_RDONLY`, so a reader process cannot start a
/// write transaction at all, and this type has no write methods. Inside the writer process use
/// [`ColumnWriter::reader`](crate::ColumnWriter::reader): MDBX refuses a second open of one env
/// in the same process.
///
/// An env written before the links table existed (one no writer has opened since) reads every
/// block as [`BlockLink::Gap`] and as contiguous only from the slot after its highest stored
/// block, as the writer's migration makes it ([`ColumnWriter::open`](
/// crate::ColumnWriter::open)). Each [`Snapshot`] looks for the table again, so a reader opened
/// before a writer migrated the env reads links from then on. A pending link stored without its
/// target's slot reads as a gap, as the migration rewrites it unless its target is stored, and
/// no range below its block is read past its start ([`Snapshot::first_pending_target`]): the
/// slot its block waits for is unknown, and the migration's contiguous-from slot is not
/// written yet.
#[derive(Debug)]
pub struct ColumnReader {
    pub(crate) db: env::Env,
}

/// One read transaction over the store: every value read through it is of the same state
/// ([`ColumnReader::snapshot`]).
pub struct Snapshot<'r> {
    txn: Transaction<'r, RO, NoWriteMap>,
    legacy: bool,
}

impl std::fmt::Debug for Snapshot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("legacy", &self.legacy)
            .finish_non_exhaustive()
    }
}

impl ColumnReader {
    /// Opens an env the writer has already created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            db: env::open_ro(path.as_ref())?,
        })
    }

    pub(crate) fn from_env(db: env::Env) -> Self {
        Self { db }
    }

    /// One read transaction to read several values of one state through; whether the env has
    /// the links table yet is that state's too.
    pub fn snapshot(&self) -> Result<Snapshot<'_>> {
        let txn = self.db.begin_ro_txn()?;
        let legacy = match txn.open_table(Some(LINKS_TABLE)) {
            Ok(_) => false,
            Err(libmdbx::Error::NotFound) => true,
            Err(e) => return Err(e.into()),
        };
        Ok(Snapshot { txn, legacy })
    }

    /// Slot of a stored block, `None` if no column of it is stored.
    pub fn slot_of(&self, block_root: &BlockRoot) -> Result<Option<u64>> {
        self.snapshot()?.slot_of(block_root)
    }

    /// One column of a block.
    pub fn get(&self, block_root: &BlockRoot, column_index: u64) -> Result<Option<Vec<u8>>> {
        self.snapshot()?.get(block_root, column_index)
    }

    /// Every stored column of a block as `(column_index, ssz)`, in index order.
    pub fn columns_for_root(&self, block_root: &BlockRoot) -> Result<Vec<(u64, Vec<u8>)>> {
        let txn = self.db.begin_ro_txn()?;
        let Some(slot) = stored_slot(&txn, block_root)? else {
            return Ok(Vec::new());
        };
        let columns = txn.open_table(Some(COLUMNS_TABLE))?;
        scan_block::<_, Vec<u8>>(&txn, &columns, &block_prefix(slot, block_root))?
            .into_iter()
            .map(|(key, ssz)| {
                let (_, _, index) = decode_column_key(&key).ok_or(Error::Corrupt {
                    table: COLUMNS_TABLE,
                })?;
                Ok((index, ssz))
            })
            .collect()
    }

    /// [`Snapshot::columns_in_range`] in a transaction of its own.
    pub fn columns_in_range(
        &self,
        start_slot: u64,
        end_slot: u64,
        wanted: impl Fn(u64) -> bool,
        budget: RangeBudget,
    ) -> Result<RangeRead> {
        self.snapshot()?
            .columns_in_range(start_slot, end_slot, wanted, budget)
    }

    /// Stored custody group count, `None` before the first
    /// [`ColumnWriter::set_cgc`](crate::ColumnWriter::set_cgc).
    pub fn cgc(&self) -> Result<Option<u64>> {
        let txn = self.db.begin_ro_txn()?;
        meta_u64(&txn, CGC_KEY)
    }

    /// [`Snapshot::custody`] in a transaction of its own.
    pub fn custody(&self) -> Result<Option<CustodyRecord>> {
        self.snapshot()?.custody()
    }

    /// [`Snapshot::finalized_slot`] in a transaction of its own.
    pub fn finalized_slot(&self) -> Result<Option<u64>> {
        self.snapshot()?.finalized_slot()
    }

    /// [`Snapshot::first_stored_slot`] in a transaction of its own.
    pub fn first_stored_slot(&self) -> Result<Option<u64>> {
        self.snapshot()?.first_stored_slot()
    }

    /// [`Snapshot::link_of`] in a transaction of its own.
    pub fn link_of(&self, block_root: &BlockRoot) -> Result<Option<BlockLink>> {
        self.snapshot()?.link_of(block_root)
    }

    /// [`Snapshot::contiguous_from`] in a transaction of its own.
    pub fn contiguous_from(&self) -> Result<Option<u64>> {
        self.snapshot()?.contiguous_from()
    }

    /// Number of stored columns across all blocks.
    pub fn column_count(&self) -> Result<u64> {
        self.entries(COLUMNS_TABLE)
    }

    /// Number of blocks with at least one stored column.
    pub fn block_count(&self) -> Result<u64> {
        self.entries(ROOTS_TABLE)
    }

    fn entries(&self, table: &str) -> Result<u64> {
        let txn = self.db.begin_ro_txn()?;
        let table = txn.open_table(Some(table))?;
        Ok(txn.table_stat(&table)?.entries() as u64)
    }
}

impl Snapshot<'_> {
    /// Slot of a stored block, `None` if no column of it is stored.
    pub fn slot_of(&self, block_root: &BlockRoot) -> Result<Option<u64>> {
        stored_slot(&self.txn, block_root)
    }

    /// One column of a block.
    pub fn get(&self, block_root: &BlockRoot, column_index: u64) -> Result<Option<Vec<u8>>> {
        let Some(slot) = stored_slot(&self.txn, block_root)? else {
            return Ok(None);
        };
        let columns = self.txn.open_table(Some(COLUMNS_TABLE))?;
        Ok(self
            .txn
            .get(&columns, &column_key(slot, block_root, column_index))?)
    }

    /// The link `block_root` was stored with, `None` if the block is not stored.
    pub fn link_of(&self, block_root: &BlockRoot) -> Result<Option<BlockLink>> {
        if stored_slot(&self.txn, block_root)?.is_none() {
            return Ok(None);
        }
        self.link(block_root).map(Some)
    }

    /// The link of a stored block: [`BlockLink::Gap`] without one.
    fn link(&self, block_root: &BlockRoot) -> Result<BlockLink> {
        if self.legacy {
            return Ok(BlockLink::Gap);
        }
        Ok(stored_link(&self.txn, block_root)?.unwrap_or(BlockLink::Gap))
    }

    /// The stored custody record, `None` before the first
    /// [`ColumnWriter::set_custody`](crate::ColumnWriter::set_custody) or
    /// [`ColumnWriter::set_cgc`](crate::ColumnWriter::set_cgc). After `set_cgc` alone the other
    /// values read 0.
    pub fn custody(&self) -> Result<Option<CustodyRecord>> {
        let txn = &self.txn;
        let Some(cgc) = meta_u64(txn, CGC_KEY)? else {
            return Ok(None);
        };
        let value = |key| meta_u64(txn, key).map(Option::unwrap_or_default);
        Ok(Some(CustodyRecord {
            cgc,
            cgc_set_slot: value(CGC_SET_SLOT_KEY)?,
            metadata_seq: value(METADATA_SEQ_KEY)?,
            advertised_cgc: value(ADVERTISED_CGC_KEY)?,
        }))
    }

    /// Finalized-slot watermark: the highest slot passed to
    /// [`ColumnWriter::prune_finalized`](crate::ColumnWriter::prune_finalized), `None` before
    /// the first prune.
    pub fn finalized_slot(&self) -> Result<Option<u64>> {
        meta_u64(&self.txn, FINALIZED_SLOT_KEY)
    }

    /// The lowest slot any column was ever stored at, `None` before the first column. Written in
    /// the transaction that stores that column, so it survives any crash together with it; pruning
    /// never moves it. A historical minimum, not proof that anything from there on is held (see
    /// [`FIRST_STORED_SLOT_KEY`](crate::keys::FIRST_STORED_SLOT_KEY)).
    pub fn first_stored_slot(&self) -> Result<Option<u64>> {
        meta_u64(&self.txn, FIRST_STORED_SLOT_KEY)
    }

    /// The slot from which the stored blocks are contiguous
    /// ([`CONTIGUOUS_FROM_KEY`](crate::keys::CONTIGUOUS_FROM_KEY)): `None` before the first
    /// gap. An env without the links table: the slot after its highest stored block.
    pub fn contiguous_from(&self) -> Result<Option<u64>> {
        if self.legacy {
            return after_highest_block(&self.txn);
        }
        meta_u64(&self.txn, CONTIGUOUS_FROM_KEY)
    }

    /// The lowest slot in `start_slot..end_slot` of a block that a stored block is
    /// [`BlockLink::Pending`] on: a blob-carrying block known to be on that block's chain and not
    /// held. `None` if there is none (or the env has no links table). A pending link stored
    /// without its target's slot ([`BlockLink::legacy_pending_target`], not migrated yet) names
    /// no slot, so any slot below its block may be the one: `start_slot`, if its block is after
    /// it, and nothing below the block is served. Walks every stored link, and stops with
    /// [`Error::Deadline`] once `deadline` passed (looked at every 64 links).
    pub fn first_pending_target(
        &self,
        start_slot: u64,
        end_slot: u64,
        deadline: Option<std::time::Instant>,
    ) -> Result<Option<u64>> {
        if self.legacy || start_slot >= end_slot {
            return Ok(None);
        }
        let links = self.txn.open_table(Some(LINKS_TABLE))?;
        let mut cursor = self.txn.cursor(&links)?;
        let mut first = None;
        let mut walked = 0usize;
        let mut row = cursor.first::<Cow<'_, [u8]>, Cow<'_, [u8]>>()?;
        while let Some((key, value)) = row {
            if walked.is_multiple_of(DEADLINE_EVERY)
                && deadline.is_some_and(|d| std::time::Instant::now() >= d)
            {
                return Err(Error::Deadline);
            }
            walked += 1;
            let target = match BlockLink::decode(&value) {
                Some(BlockLink::Pending(_, slot)) => Some(slot),
                Some(_) => None,
                None if BlockLink::legacy_pending_target(&value).is_some() => {
                    let child: BlockRoot = key
                        .as_ref()
                        .try_into()
                        .map_err(|_| Error::Corrupt { table: LINKS_TABLE })?;
                    stored_slot(&self.txn, &child)?
                        .filter(|&slot| slot > start_slot)
                        .map(|_| start_slot)
                }
                None => None,
            };
            if let Some(slot) = target {
                if (start_slot..end_slot).contains(&slot) && first.is_none_or(|f| slot < f) {
                    first = Some(slot);
                }
            }
            row = cursor.next::<Cow<'_, [u8]>, Cow<'_, [u8]>>()?;
        }
        Ok(first)
    }

    /// The stored columns at slots `start_slot..end_slot` whose index `wanted` takes, in key
    /// order (slot, then block root, then column index), and every block of the range read,
    /// whether or not it holds a wanted column, with its link ([`RangeRead::blocks`]). The first
    /// block is read whole; it stops before the first column of a later block that would take it
    /// past `budget`'s bytes or columns ([`RangeRead::cut`]), and with [`Error::Deadline`]
    /// once its deadline passed (looked at every 64 rows). Only the columns taken are copied; a
    /// key past the range ends the walk before its value is read.
    pub fn columns_in_range(
        &self,
        start_slot: u64,
        end_slot: u64,
        wanted: impl Fn(u64) -> bool,
        budget: RangeBudget,
    ) -> Result<RangeRead> {
        let mut read = RangeRead::default();
        if start_slot >= end_slot {
            return Ok(read);
        }
        let txn = &self.txn;
        let table = txn.open_table(Some(COLUMNS_TABLE))?;
        let mut cursor = txn.cursor(&table)?;
        let corrupt = || Error::Corrupt {
            table: COLUMNS_TABLE,
        };
        let mut bytes = 0usize;
        let mut walked = 0usize;
        let mut row = cursor.set_range::<Cow<'_, [u8]>, ()>(&start_slot.to_be_bytes())?;
        while let Some((key, ())) = row {
            if walked.is_multiple_of(DEADLINE_EVERY)
                && budget
                    .deadline
                    .is_some_and(|d| std::time::Instant::now() >= d)
            {
                return Err(Error::Deadline);
            }
            walked += 1;
            let (slot, block_root, index) = decode_column_key(&key).ok_or_else(corrupt)?;
            if slot >= end_slot {
                break;
            }
            let new_block = read
                .blocks
                .last()
                .is_none_or(|b| (b.slot, b.block_root) != (slot, block_root));
            let first_block = read.blocks.is_empty() || (read.blocks.len() == 1 && !new_block);
            if wanted(index) {
                let ((), ssz) = cursor.get_current::<(), Vec<u8>>()?.ok_or_else(corrupt)?;
                let over = read.columns.len() >= budget.max_columns
                    || bytes.saturating_add(ssz.len()) > budget.max_bytes;
                if over && !first_block {
                    read.cut = Some((slot, block_root));
                    break;
                }
                bytes = bytes.saturating_add(ssz.len());
                if new_block {
                    read.blocks.push(RangeBlock {
                        slot,
                        block_root,
                        link: self.link(&block_root)?,
                    });
                }
                read.columns.push(RangeColumn {
                    slot,
                    block_root,
                    index,
                    ssz,
                });
            } else if new_block {
                read.blocks.push(RangeBlock {
                    slot,
                    block_root,
                    link: self.link(&block_root)?,
                });
            }
            row = cursor.next::<Cow<'_, [u8]>, ()>()?;
        }
        Ok(read)
    }
}

/// The slot after the highest stored column's, `None` with no column.
pub(crate) fn after_highest_block<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
) -> Result<Option<u64>> {
    let columns = txn.open_table(Some(COLUMNS_TABLE))?;
    let Some((key, ())) = txn.cursor(&columns)?.last::<Vec<u8>, ()>()? else {
        return Ok(None);
    };
    let (slot, _, _) = decode_column_key(&key).ok_or(Error::Corrupt {
        table: COLUMNS_TABLE,
    })?;
    Ok(Some(slot.saturating_add(1)))
}

/// Slot recorded for `block_root` in [`ROOTS_TABLE`].
pub(crate) fn stored_slot<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    block_root: &BlockRoot,
) -> Result<Option<u64>> {
    get_u64(txn, ROOTS_TABLE, block_root)
}

/// The link stored for `block_root`, `None` without one; other bytes are [`Error::Corrupt`].
pub(crate) fn stored_link<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    block_root: &BlockRoot,
) -> Result<Option<BlockLink>> {
    let links = txn.open_table(Some(LINKS_TABLE))?;
    match txn.get::<Vec<u8>>(&links, block_root)? {
        None => Ok(None),
        Some(bytes) => match BlockLink::decode(&bytes) {
            Some(link) => Ok(Some(link)),
            // Not migrated yet: what the writer's migration makes it, unless its target is
            // stored (then a gap claims less than the store holds, never more).
            None if BlockLink::legacy_pending_target(&bytes).is_some() => Ok(Some(BlockLink::Gap)),
            None => Err(Error::Corrupt { table: LINKS_TABLE }),
        },
    }
}

/// A `u64 BE` value from [`META_TABLE`].
pub(crate) fn meta_u64<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    key: &[u8],
) -> Result<Option<u64>> {
    get_u64(txn, META_TABLE, key)
}

/// Reads an 8-byte big-endian value; any other length is [`Error::Corrupt`] and is never copied.
fn get_u64<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    table: &'static str,
    key: &[u8],
) -> Result<Option<u64>> {
    let handle = txn.open_table(Some(table))?;
    match txn.get::<[u8; 8]>(&handle, key) {
        Ok(value) => Ok(value.map(u64::from_be_bytes)),
        Err(libmdbx::Error::DecodeError(_)) => Err(Error::Corrupt { table }),
        Err(e) => Err(e.into()),
    }
}

/// All `(key, value)` rows of [`COLUMNS_TABLE`] under one block prefix, in key order. Keys are
/// checked against the prefix before the value is decoded, so the first row past the block is
/// never copied.
pub(crate) fn scan_block<'txn, K, V>(
    txn: &'txn Transaction<'_, K, NoWriteMap>,
    columns: &Table<'txn>,
    prefix: &[u8; BLOCK_PREFIX_LEN],
) -> Result<Vec<(Vec<u8>, V)>>
where
    K: TransactionKind,
    V: Decodable<'txn> + 'txn,
{
    let mut cursor = txn.cursor(columns)?;
    let mut rows = Vec::new();
    let mut row = cursor.set_range::<Cow<'txn, [u8]>, ()>(prefix)?;
    while let Some((key, ())) = row {
        if !key.starts_with(prefix) {
            break;
        }
        let ((), value) = cursor.get_current::<(), V>()?.ok_or(Error::Corrupt {
            table: COLUMNS_TABLE,
        })?;
        rows.push((key.into_owned(), value));
        row = cursor.next::<Cow<'txn, [u8]>, ()>()?;
    }
    Ok(rows)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockLink, Column, ColumnWriter, RangeBudget};

    #[test]
    fn a_range_reads_the_wanted_columns_in_key_order_within_its_budget() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let col = |index| Column { index, ssz: b"xyz" };
        // Two blocks at slot 9 (two roots), one at 10, one at 11 without a wanted column, one
        // at 12; written out of order.
        writer.write_columns(12, &[3; 32], &[col(1)]).unwrap();
        writer
            .write_columns(9, &[2; 32], &[col(47), col(1), col(5)])
            .unwrap();
        writer.write_columns(9, &[1; 32], &[col(87)]).unwrap();
        writer
            .write_columns(10, &[4; 32], &[col(1), col(47)])
            .unwrap();
        writer.write_columns(11, &[5; 32], &[col(5)]).unwrap();
        let reader = writer.reader();
        let keys = |read: &RangeRead| -> Vec<(u64, u8, u64)> {
            read.columns
                .iter()
                .map(|c| (c.slot, c.block_root[0], c.index))
                .collect()
        };
        let blocks = |read: &RangeRead| -> Vec<(u64, u8)> {
            read.blocks
                .iter()
                .map(|b| (b.slot, b.block_root[0]))
                .collect()
        };
        let custody = |i: u64| [1, 47, 87].contains(&i);
        let all = RangeBudget::unbounded();
        let read = reader.columns_in_range(9, 12, custody, all).unwrap();
        assert_eq!(
            keys(&read),
            [(9, 1, 87), (9, 2, 1), (9, 2, 47), (10, 4, 1), (10, 4, 47)]
        );
        // Every block in the range, whether or not it holds a wanted column, with its link:
        // `write_columns` stores none, a gap.
        assert_eq!(blocks(&read), [(9, 1), (9, 2), (10, 4), (11, 5)]);
        assert!(read.blocks.iter().all(|b| b.link == BlockLink::Gap));
        assert_eq!(read.cut, None);
        assert!(read.columns.iter().all(|c| c.ssz == b"xyz"));
        // The end is exclusive, the start inclusive, and an empty range reads nothing.
        let read = reader.columns_in_range(10, 13, custody, all).unwrap();
        assert_eq!(keys(&read), [(10, 4, 1), (10, 4, 47), (12, 3, 1)]);
        assert_eq!(
            reader.columns_in_range(11, 11, custody, all).unwrap(),
            RangeRead::default()
        );
        // The byte budget stops before the block past it, and so does the column budget; the
        // first block is read whole whatever the budget.
        let bytes = RangeBudget {
            max_bytes: 7,
            ..all
        };
        let read = reader.columns_in_range(9, 12, custody, bytes).unwrap();
        assert_eq!(keys(&read), [(9, 1, 87), (9, 2, 1)]);
        // Cut inside a block: that block, read in part.
        assert_eq!(read.cut, Some((9, [2; 32])));
        let nothing = RangeBudget {
            max_bytes: 0,
            max_columns: 0,
            ..all
        };
        let read = reader.columns_in_range(9, 12, custody, nothing).unwrap();
        assert_eq!(keys(&read), [(9, 1, 87)]);
        assert_eq!(blocks(&read), [(9, 1)]);
        // Cut before a block: that block, not read at all.
        assert_eq!(read.cut, Some((9, [2; 32])));
        let columns = RangeBudget {
            max_columns: 3,
            ..all
        };
        let read = reader.columns_in_range(9, 12, custody, columns).unwrap();
        assert_eq!(keys(&read), [(9, 1, 87), (9, 2, 1), (9, 2, 47)]);
        assert_eq!(read.cut, Some((10, [4; 32])));
        assert_eq!(blocks(&read), [(9, 1), (9, 2)]);
        // A read past its deadline stops with an error.
        let late = RangeBudget {
            deadline: Some(std::time::Instant::now()),
            ..all
        };
        assert!(matches!(
            reader.columns_in_range(9, 12, custody, late),
            Err(Error::Deadline)
        ));
        // One snapshot reads the view and the range in one transaction.
        let snapshot = reader.snapshot().unwrap();
        assert_eq!(snapshot.first_stored_slot().unwrap(), Some(9));
        assert_eq!(snapshot.contiguous_from().unwrap(), Some(12));
        assert_eq!(
            keys(&snapshot.columns_in_range(12, 13, custody, all).unwrap()),
            [(12, 3, 1)]
        );
    }

    /// An env written before the links table existed: the writer adds the table and claims
    /// nothing before the slot after its highest stored block, in one transaction; a reader of
    /// it not yet opened by a writer behaves the same without writing.
    #[test]
    fn an_env_without_links_reads_as_contiguous_only_past_its_blocks() {
        let dir = tempfile::tempdir().unwrap();
        {
            let writer = ColumnWriter::open(dir.path()).unwrap();
            writer
                .write_block_columns(
                    7,
                    &[1; 32],
                    BlockLink::Start,
                    &[Column {
                        index: 1,
                        ssz: b"a",
                    }],
                )
                .unwrap();
            writer
                .write_block_columns(
                    9,
                    &[2; 32],
                    BlockLink::Parent([1; 32]),
                    &[Column {
                        index: 1,
                        ssz: b"b",
                    }],
                )
                .unwrap();
            crate::writer::make_legacy_for_test(&writer);
        }
        let reader = ColumnReader::open(dir.path()).unwrap();
        assert_eq!(reader.contiguous_from().unwrap(), Some(10));
        assert_eq!(reader.link_of(&[2; 32]).unwrap(), Some(BlockLink::Gap));
        let read = reader
            .columns_in_range(0, 100, |_| true, RangeBudget::unbounded())
            .unwrap();
        assert!(read.blocks.iter().all(|b| b.link == BlockLink::Gap));
        drop(reader);
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(writer.reader().contiguous_from().unwrap(), Some(10));
        assert_eq!(
            writer.reader().link_of(&[2; 32]).unwrap(),
            Some(BlockLink::Gap)
        );
        // New blocks link as usual; the old ones stay claimed past.
        writer
            .write_block_columns(
                11,
                &[3; 32],
                BlockLink::Parent([2; 32]),
                &[Column {
                    index: 1,
                    ssz: b"c",
                }],
            )
            .unwrap();
        assert_eq!(
            writer.reader().link_of(&[3; 32]).unwrap(),
            Some(BlockLink::Parent([2; 32]))
        );
        assert_eq!(writer.reader().contiguous_from().unwrap(), Some(10));
        // An empty old env claims nothing.
        let empty = tempfile::tempdir().unwrap();
        crate::writer::make_legacy_for_test(&ColumnWriter::open(empty.path()).unwrap());
        assert_eq!(
            ColumnWriter::open(empty.path())
                .unwrap()
                .reader()
                .contiguous_from()
                .unwrap(),
            None
        );
    }

    /// SEC-007: the slots of the blocks stored blocks wait for are known, so a range over one
    /// is never taken for a range without blobs.
    #[test]
    fn the_first_pending_target_of_a_range_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let write = |slot, root: [u8; 32], link| {
            writer
                .write_block_columns(
                    slot,
                    &root,
                    link,
                    &[Column {
                        index: 1,
                        ssz: b"a",
                    }],
                )
                .unwrap();
        };
        write(10, [1; 32], BlockLink::Start);
        write(14, [4; 32], BlockLink::Pending([3; 32], 12));
        write(15, [5; 32], BlockLink::Pending([2; 32], 11));
        let snapshot = writer.reader().snapshot().unwrap();
        let first = |start, end| snapshot.first_pending_target(start, end, None).unwrap();
        assert_eq!(first(0, 100), Some(11));
        assert_eq!(first(11, 12), Some(11));
        assert_eq!(first(12, 13), Some(12));
        assert_eq!(first(13, 100), None);
        assert_eq!(first(0, 11), None);
        assert_eq!(first(12, 12), None);
        assert!(matches!(
            snapshot.first_pending_target(0, 100, Some(std::time::Instant::now())),
            Err(Error::Deadline)
        ));
        drop(snapshot);
        // Once the target is written, its child links to it and nothing waits there.
        write(12, [3; 32], BlockLink::Parent([1; 32]));
        let snapshot = writer.reader().snapshot().unwrap();
        assert_eq!(snapshot.first_pending_target(12, 13, None).unwrap(), None);
        assert_eq!(
            snapshot.first_pending_target(0, 100, None).unwrap(),
            Some(11)
        );
    }

    /// CR-005: each snapshot looks for the links table itself, so a reader follows the env it
    /// reads whether a migration came before or after it was opened.
    #[test]
    fn each_snapshot_looks_for_the_links_table() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer
            .write_block_columns(
                7,
                &[1; 32],
                BlockLink::Start,
                &[Column {
                    index: 1,
                    ssz: b"a",
                }],
            )
            .unwrap();
        let reader = writer.reader();
        assert_eq!(reader.link_of(&[1; 32]).unwrap(), Some(BlockLink::Start));
        crate::writer::make_legacy_for_test(&writer);
        // Without the table: as the migration will make it.
        assert_eq!(reader.link_of(&[1; 32]).unwrap(), Some(BlockLink::Gap));
        assert_eq!(reader.contiguous_from().unwrap(), Some(8));
        let snapshot = reader.snapshot().unwrap();
        assert_eq!(snapshot.first_pending_target(0, 100, None).unwrap(), None);
        assert!(format!("{snapshot:?}").contains("legacy: true"));
    }

    #[test]
    fn reader_env_is_read_only() {
        let dir = tempfile::tempdir().unwrap();
        ColumnWriter::open(dir.path())
            .unwrap()
            .write_columns(
                1,
                &[1; 32],
                &[Column {
                    index: 0,
                    ssz: b"x",
                }],
            )
            .unwrap();

        let reader = ColumnReader::open(dir.path()).unwrap();
        let mut flags = 0;
        assert_eq!(
            unsafe { mdbx_sys::mdbx_env_get_flags(reader.db.ptr().0, &mut flags) },
            0
        );
        assert_ne!(flags & mdbx_sys::MDBX_RDONLY, 0);
        assert!(matches!(
            reader.db.begin_rw_txn(),
            Err(libmdbx::Error::Access)
        ));
        assert_eq!(reader.get(&[1; 32], 0).unwrap(), Some(b"x".to_vec()));
    }

    #[test]
    fn reader_does_not_create_a_missing_env() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        assert!(ColumnReader::open(&missing).is_err());
        assert!(!missing.exists());
    }
}
