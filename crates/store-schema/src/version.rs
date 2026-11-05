//! The schema version: a `u64 BE` row under [`SCHEMA_VERSION_KEY`] in `meta`, checked on every
//! open, writer and reader.
//!
//! - [`SCHEMA_VERSION`] (3): opens.
//! - 2 (no `finalized_slots`): the writer upgrades it in place, creating the table empty and
//!   writing 3 in its open transaction, rewriting no other row; the index is backfilled after
//!   the open ([`crate::finalized::backfill`]). A reader refuses it ([`Error::NeedsUpgrade`])
//!   until then.
//! - 1, #291's layout (no `block_index`, `envelopes`, `fc_snapshot` either): the same, and
//!   `block_index` is filled from `blocks` in that transaction.
//! - Absent: a fresh env, or one cl-chain-columns wrote before this crate (its four tables
//!   only). A reader opens it as it is; the writer upgrades it in place, as for 1.
//! - Any other value, newer or unknown: [`Error::SchemaVersion`], nothing written. The writer
//!   never opens a newer env, so it never downgrades one.
//! - Not 8 bytes: [`Error::MalformedSchemaVersion`], nothing written.
//!
//! Only this row is read here: another `meta` row needs no migration.

use libmdbx::{NoWriteMap, Transaction, TransactionKind, WriteFlags, RW};

use crate::{keys::SCHEMA_VERSION_KEY, tables::META, Error, Result};

/// The schema this build reads and writes.
pub const SCHEMA_VERSION: u64 = 3;

/// The older versions the writer upgrades in place.
const UPGRADED_FROM: [u64; 2] = [1, 2];

/// The stored version, `None` if there is none (no row, or no `meta` table yet).
fn stored<K: TransactionKind>(txn: &Transaction<'_, K, NoWriteMap>) -> Result<Option<u64>> {
    let meta = match txn.open_table(Some(META)) {
        Ok(meta) => meta,
        Err(libmdbx::Error::NotFound) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let Some(row) = txn.get::<Vec<u8>>(&meta, SCHEMA_VERSION_KEY)? else {
        return Ok(None);
    };
    <[u8; 8]>::try_from(row.as_slice())
        .map(|found| Some(u64::from_be_bytes(found)))
        .map_err(|_| Error::MalformedSchemaVersion { len: row.len() })
}

fn newer_or_unknown(found: u64) -> Error {
    Error::SchemaVersion {
        found,
        supported: SCHEMA_VERSION,
    }
}

/// The writer's check: whether the env needs the upgrade to [`SCHEMA_VERSION`] (absent, 1 or
/// 2); an error for any other version.
pub(crate) fn check_writer(txn: &Transaction<'_, RW, NoWriteMap>) -> Result<bool> {
    match stored(txn)? {
        Some(SCHEMA_VERSION) => Ok(false),
        None => Ok(true),
        Some(found) if UPGRADED_FROM.contains(&found) => Ok(true),
        Some(found) => Err(newer_or_unknown(found)),
    }
}

/// The reader's check: [`SCHEMA_VERSION`] or absent opens; 1 and 2 wait for the writer.
pub(crate) fn check_reader<K: TransactionKind>(txn: &Transaction<'_, K, NoWriteMap>) -> Result<()> {
    match stored(txn)? {
        None | Some(SCHEMA_VERSION) => Ok(()),
        Some(found) if UPGRADED_FROM.contains(&found) => Err(Error::NeedsUpgrade { found }),
        Some(found) => Err(newer_or_unknown(found)),
    }
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
