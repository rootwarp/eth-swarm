//! The schema version: a `u64 BE` row under [`SCHEMA_VERSION_KEY`] in `meta`, checked on every
//! open, writer and reader.
//!
//! - Equal to [`SCHEMA_VERSION`]: opens.
//! - Any other value, newer or unknown: [`Error::SchemaVersion`], nothing written.
//! - Not 8 bytes: [`Error::MalformedSchemaVersion`], nothing written.
//! - Absent: a fresh env, or one cl-chain-columns wrote before this crate (its four tables
//!   only). A reader opens it as it is; the writer upgrades it in place, creating the missing
//!   tables and writing the row in the same transaction.
//!
//! Only this row is read: any other `meta` row, such as [`crate::keys::STAMP_KEY`], is not a
//! version, so adding one needs no migration.

use libmdbx::{NoWriteMap, Transaction, TransactionKind, WriteFlags, RW};

use crate::{keys::SCHEMA_VERSION_KEY, tables::META, Error, Result};

/// The schema this build reads and writes.
pub const SCHEMA_VERSION: u64 = 1;

/// The stored version if it is [`SCHEMA_VERSION`], `None` if there is none (no row, or no
/// `meta` table yet); an error for anything else.
pub(crate) fn check<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
) -> Result<Option<u64>> {
    let meta = match txn.open_table(Some(META)) {
        Ok(meta) => meta,
        Err(libmdbx::Error::NotFound) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let Some(row) = txn.get::<Vec<u8>>(&meta, SCHEMA_VERSION_KEY)? else {
        return Ok(None);
    };
    let found = <[u8; 8]>::try_from(row.as_slice())
        .map(u64::from_be_bytes)
        .map_err(|_| Error::MalformedSchemaVersion { len: row.len() })?;
    if found != SCHEMA_VERSION {
        return Err(Error::SchemaVersion {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    Ok(Some(found))
}

/// Writes [`SCHEMA_VERSION`]; `meta` must exist.
pub(crate) fn write(txn: &Transaction<'_, RW, NoWriteMap>) -> Result<()> {
    let meta = txn.open_table(Some(META))?;
    txn.put(
        &meta,
        SCHEMA_VERSION_KEY,
        SCHEMA_VERSION.to_be_bytes(),
        WriteFlags::UPSERT,
    )?;
    Ok(())
}
