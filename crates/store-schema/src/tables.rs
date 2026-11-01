//! Table names of the env. A name is part of the on-disk format: never rename one, add a table.

use libmdbx::{NoWriteMap, Transaction, TransactionKind};

use crate::{Error, Result};

/// Column sidecars by `slot ‖ block_root ‖ column_index` (cl-chain-columns).
pub const COLUMNS: &str = "columns";
/// Block root → the slot that prefixes its column keys (cl-chain-columns).
pub const COLUMN_ROOTS: &str = "column_roots";
/// Block root → how the block ties to the stored block before it (cl-chain-columns).
pub const COLUMN_LINKS: &str = "column_links";
/// Small named rows: the schema version, the stamp ([`crate::stamp`]) and cl-chain-columns'
/// rows ([`crate::keys`]).
pub const META: &str = "meta";
/// Imported blocks by [`crate::keys::slot_root_key`].
pub const BLOCKS: &str = "blocks";
/// States by [`crate::keys::slot_root_key`] of the block they are the post-state of.
pub const STATES: &str = "states";
/// Block root → its slot (`u64 BE`), written with its `blocks` row ([`crate::blocks::put`]).
pub const BLOCK_INDEX: &str = "block_index";
/// Execution payload envelopes (Gloas). Created empty; its writer comes with [5.14a].
pub const ENVELOPES: &str = "envelopes";
/// The fork-choice snapshot. Created empty; its writer comes with #128.
pub const FC_SNAPSHOT: &str = "fc_snapshot";

/// Every table, in creation order: the four cl-chain-columns tables of before, then schema 1's,
/// then schema 2's. Any other named table in the env refuses every open
/// ([`Error::UnknownTable`]).
pub const TABLES: [&str; 9] = [
    COLUMNS,
    COLUMN_ROOTS,
    META,
    COLUMN_LINKS,
    BLOCKS,
    STATES,
    BLOCK_INDEX,
    ENVELOPES,
    FC_SNAPSHOT,
];

/// `max_tables` of every open, set before any table is created or opened (`None` makes every
/// named table `MDBX_DBS_FULL`). Leaves room for later tables without changing it.
pub const MAX_TABLES: u64 = 16;

const _: () = assert!(TABLES.len() as u64 + 4 <= MAX_TABLES);

/// Refuses any name in the main DB, the list of named tables, that is not in [`TABLES`].
pub(crate) fn check_known<K: TransactionKind>(txn: &Transaction<'_, K, NoWriteMap>) -> Result<()> {
    let main = txn.open_table(None)?;
    for row in txn.cursor(&main)?.iter::<Vec<u8>, ()>() {
        let (name, ()) = row?;
        if !TABLES.iter().any(|t| t.as_bytes() == name) {
            return Err(Error::UnknownTable {
                name: String::from_utf8_lossy(&name).into_owned(),
            });
        }
    }
    Ok(())
}
