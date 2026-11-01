//! Table names of the env. A name is part of the on-disk format: never rename one, add a table.

/// Column sidecars by `slot ‖ block_root ‖ column_index` (cl-chain-columns).
pub const COLUMNS: &str = "columns";
/// Block root → the slot that prefixes its column keys (cl-chain-columns).
pub const COLUMN_ROOTS: &str = "column_roots";
/// Block root → how the block ties to the stored block before it (cl-chain-columns).
pub const COLUMN_LINKS: &str = "column_links";
/// Small named rows: the schema version, #130's stamp and cl-chain-columns' rows
/// ([`crate::keys`]).
pub const META: &str = "meta";
/// Imported blocks by [`crate::keys::slot_root_key`].
pub const BLOCKS: &str = "blocks";
/// States by [`crate::keys::slot_root_key`] of the block they are the post-state of.
pub const STATES: &str = "states";

/// Every table, in creation order: the four cl-chain-columns tables of before, then the new.
pub const TABLES: [&str; 6] = [COLUMNS, COLUMN_ROOTS, META, COLUMN_LINKS, BLOCKS, STATES];

/// `max_tables` of every open, set before any table is created or opened (`None` makes every
/// named table `MDBX_DBS_FULL`). Room for #130's tables (`block_index`, `envelopes`,
/// `fc_snapshot`, `columns_finalized`) without changing it.
pub const MAX_TABLES: u64 = 16;

const _: () = assert!(TABLES.len() as u64 + 4 <= MAX_TABLES);
