use std::{borrow::Cow, path::Path};

use libmdbx::{Decodable, NoWriteMap, Table, Transaction, TransactionKind};

use crate::{
    env,
    error::{Error, Result},
    keys::{
        block_prefix, column_key, decode_column_key, BlockRoot, BLOCK_PREFIX_LEN, CGC_KEY,
        COLUMNS_TABLE, FINALIZED_SLOT_KEY, META_TABLE, ROOTS_TABLE,
    },
};

/// Read-only view of the column store.
///
/// [`ColumnReader::open`] opens the env with `MDBX_RDONLY`, so a reader process cannot start a
/// write transaction at all, and this type has no write methods. Inside the writer process use
/// [`ColumnWriter::reader`](crate::ColumnWriter::reader): MDBX refuses a second open of one env
/// in the same process.
#[derive(Debug)]
pub struct ColumnReader {
    pub(crate) db: env::Env,
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

    /// Slot of a stored block, `None` if no column of it is stored.
    pub fn slot_of(&self, block_root: &BlockRoot) -> Result<Option<u64>> {
        let txn = self.db.begin_ro_txn()?;
        stored_slot(&txn, block_root)
    }

    /// One column of a block.
    pub fn get(&self, block_root: &BlockRoot, column_index: u64) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_ro_txn()?;
        let Some(slot) = stored_slot(&txn, block_root)? else {
            return Ok(None);
        };
        let columns = txn.open_table(Some(COLUMNS_TABLE))?;
        Ok(txn.get(&columns, &column_key(slot, block_root, column_index))?)
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

    /// Stored custody group count, `None` before the first
    /// [`ColumnWriter::set_cgc`](crate::ColumnWriter::set_cgc).
    pub fn cgc(&self) -> Result<Option<u64>> {
        let txn = self.db.begin_ro_txn()?;
        meta_u64(&txn, CGC_KEY)
    }

    /// Finalized-slot watermark: the highest slot passed to
    /// [`ColumnWriter::prune_finalized`](crate::ColumnWriter::prune_finalized), `None` before
    /// the first prune.
    pub fn finalized_slot(&self) -> Result<Option<u64>> {
        let txn = self.db.begin_ro_txn()?;
        meta_u64(&txn, FINALIZED_SLOT_KEY)
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

/// Slot recorded for `block_root` in [`ROOTS_TABLE`].
pub(crate) fn stored_slot<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
    block_root: &BlockRoot,
) -> Result<Option<u64>> {
    get_u64(txn, ROOTS_TABLE, block_root)
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
    use crate::{Column, ColumnWriter};

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
