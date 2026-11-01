//! The column store's side of the store-schema env ([`store_schema::env`]): every opener shares
//! its options (`SyncMode::Durable`, `max_tables`), writer guard and geometry checks. What stays
//! here is the column tables' own migration, run in the transaction that creates the tables.

use std::path::Path;

use libmdbx::WriteFlags;
use store_schema::env::{RwTxn, WriterGuard};
pub use store_schema::env::{
    WriterOptions, DEFAULT_MAX_SIZE, MAX_SIZE_ALIGN, MIN_MAX_SIZE, WRITER_LOCK_ATTEMPTS,
    WRITER_LOCK_RETRY_INTERVAL,
};

use crate::{
    error::Result,
    keys::{CONTIGUOUS_FROM_KEY, LINKS_TABLE, META_TABLE},
    reader::{after_highest_block, meta_u64},
};

pub(crate) type Env = store_schema::env::Env;

/// Opens the env as its one writer ([`store_schema::env::open_writer_with`]: guard, geometry,
/// schema version, every table) and migrates the column tables in the same transaction.
pub(crate) fn open_rw(path: &Path, opts: WriterOptions) -> Result<(Env, WriterGuard)> {
    Ok(store_schema::env::open_writer_with(path, opts, migrate)?.into_parts())
}

/// The column tables' migration. `created` names the tables this open created.
fn migrate(txn: &RwTxn<'_>, created: &[&'static str]) -> Result<()> {
    // An env written before the links table existed: its blocks have no links, so none of
    // them can be chained to; claim nothing up to and including its highest stored block.
    if created.contains(&LINKS_TABLE) {
        if let Some(after) = after_highest_block(txn)? {
            let meta = txn.open_table(Some(META_TABLE))?;
            let current = meta_u64(txn, CONTIGUOUS_FROM_KEY)?;
            let from = current.map_or(after, |c| c.max(after));
            txn.put(
                &meta,
                CONTIGUOUS_FROM_KEY,
                from.to_be_bytes(),
                WriteFlags::UPSERT,
            )?;
        }
    }
    // Pending links stored without their target's slot.
    crate::writer::migrate_legacy_pending(txn)?;
    Ok(())
}

/// Opens an existing env read-only ([`store_schema::env::open_reader`]): `MDBX_RDONLY`, no
/// write txn at all, and never the writer guard.
pub(crate) fn open_ro(path: &Path) -> Result<Env> {
    Ok(store_schema::env::open_reader(path)?)
}
