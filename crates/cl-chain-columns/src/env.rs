//! The column store's side of the store-schema env ([`store_schema::env`]): every opener shares
//! its options (`SyncMode::Durable`, `max_tables`), writer guard and geometry checks. What stays
//! here is the column tables' own migration, run in the transaction that creates the tables.

use std::path::Path;

use libmdbx::WriteFlags;
pub use store_schema::env::{
    WriterOptions, DEFAULT_MAX_SIZE, MAX_SIZE_ALIGN, MIN_MAX_SIZE, WRITER_LOCK_ATTEMPTS,
    WRITER_LOCK_RETRY_INTERVAL,
};
use store_schema::{env::WriterEnv, txn::RwTxn};

use crate::{
    error::Result,
    keys::{CONTIGUOUS_FROM_KEY, LINKS_TABLE, META_TABLE},
    reader::{after_highest_block, meta_u64},
};

pub(crate) type Env = store_schema::env::Env;

/// Opens the env as its one writer ([`store_schema::env::open_writer_with`]: guard, geometry,
/// schema version, every table) and migrates the column tables in the same transaction.
pub(crate) fn open_rw(path: &Path, opts: WriterOptions) -> Result<WriterEnv> {
    store_schema::env::open_writer_with(path, opts, migrate)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{column_key, BlockLink, COLUMNS_TABLE, ROOTS_TABLE};
    use store_schema::stamp;

    /// The probe store's one block, at [`SLOT`].
    const ROOT: [u8; 32] = [0xaa; 32];
    /// The block [`ROOT`]'s legacy pending link waits for, never stored.
    const TARGET: [u8; 32] = [0xbb; 32];
    const SLOT: u64 = 7;

    fn opts() -> WriterOptions {
        WriterOptions {
            max_size: MIN_MAX_SIZE,
        }
    }

    /// A probe store as one written before its first stamp, committed raw: no stamp, no block,
    /// a column of [`ROOT`] at [`SLOT`], its root row and custody's `cgc`. With `links`,
    /// [`ROOT`]'s link is a legacy pending link on [`TARGET`]; without, the store has no links
    /// table at all, as one written before it existed.
    fn unstamped_probe_store(path: &Path, links: bool) {
        let writer = open_rw(path, opts()).unwrap();
        let txn = writer.raw_env().begin_rw_txn().unwrap();
        let columns = txn.open_table(Some(COLUMNS_TABLE)).unwrap();
        txn.put(
            &columns,
            column_key(SLOT, &ROOT, 0),
            b"column",
            WriteFlags::UPSERT,
        )
        .unwrap();
        let roots = txn.open_table(Some(ROOTS_TABLE)).unwrap();
        txn.put(&roots, ROOT, SLOT.to_be_bytes(), WriteFlags::UPSERT)
            .unwrap();
        let meta = txn.open_table(Some(META_TABLE)).unwrap();
        txn.put(&meta, b"cgc", 8u64.to_be_bytes(), WriteFlags::UPSERT)
            .unwrap();
        let table = txn.open_table(Some(LINKS_TABLE)).unwrap();
        if links {
            let legacy = [&[3][..], &TARGET].concat();
            txn.put(&table, ROOT, legacy, WriteFlags::UPSERT).unwrap();
        } else {
            // SAFETY: no other handle of the table is open.
            unsafe { txn.drop_table(table).unwrap() };
        }
        txn.commit().unwrap();
    }

    /// An unstamped probe store (columns and custody, no block) still opens through the column
    /// tables' migration, which rewrites rows it holds and adds the one row the writer's open
    /// may add before the first stamp besides the version, [`CONTIGUOUS_FROM_KEY`]: a legacy
    /// pending link whose target is not stored becomes a gap at its block's slot, and a store
    /// written before the links table claims nothing up to its highest block. Still no stamp.
    #[test]
    fn an_unstamped_probe_store_migrates_and_opens() {
        for (links, from) in [(true, SLOT), (false, SLOT + 1)] {
            let dir = tempfile::tempdir().unwrap();
            unstamped_probe_store(dir.path(), links);
            let writer = open_rw(dir.path(), opts()).expect("the migration's rows are allowed");
            let txn = writer.begin_ro_txn().unwrap();
            assert_eq!(
                meta_u64(&txn, CONTIGUOUS_FROM_KEY).unwrap(),
                Some(from),
                "links {links}"
            );
            assert_eq!(meta_u64(&txn, b"cgc").unwrap(), Some(8), "links {links}");
            let table = txn.open_table(Some(LINKS_TABLE)).unwrap();
            let link = txn.get::<Vec<u8>>(&table, &ROOT).unwrap();
            assert_eq!(
                link,
                links.then(|| BlockLink::Gap.encode()),
                "links {links}"
            );
            assert_eq!(stamp::read(&txn).unwrap(), None, "links {links}");
            drop(txn);
            drop(writer);
            drop(open_rw(dir.path(), opts()).expect("opens again"));
        }
    }
}
