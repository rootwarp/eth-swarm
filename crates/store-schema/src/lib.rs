//! The MDBX env cl-chain writes (ADR-008): its options, tables, keys and schema version, shared
//! by the one writer (cl-chain) and every reader (cl-store), so no two openers can disagree on
//! sync mode, `max_tables` or geometry (`MDBX_INCOMPATIBLE`).
//!
//! # Layout
//!
//! | table ([`tables`])  | key ([`keys`])                                  | value                       |
//! |---------------------|-------------------------------------------------|-----------------------------|
//! | `columns`           | `slot (u64 BE) ‖ block_root (32) ‖ column_index (u64 BE)` | SSZ `DataColumnSidecar` (cl-chain-columns) |
//! | `column_roots`      | `block_root (32)`                               | `slot (u64 BE)`             |
//! | `column_links`      | `block_root (32)`                               | cl-chain-columns' `BlockLink` |
//! | `meta`              | ASCII name                                      | per row, below              |
//! | `blocks`            | [`keys::slot_root_key`]: `slot (u64 BE) ‖ block_root (32)` | SSZ `SignedBeaconBlock` ([`blocks::put`]) |
//! | `block_index`       | `block_root (32)`                               | `slot (u64 BE)` ([`blocks::put`]) |
//! | `states`            | [`keys::slot_root_key`]: `slot (u64 BE) ‖ block_root (32)` | opaque (the importer's SSZ) |
//! | `envelopes`         | not written yet ([5.14a])                       |                             |
//! | `fc_snapshot`       | not written yet (#128)                          |                             |
//!
//! `meta` rows: [`keys::SCHEMA_VERSION_KEY`] (`u64 BE`, [`version`]); [`keys::STAMP_KEY`], the
//! head/finalized [`stamp`], 88 bytes, that every write transaction commits ([`txn::commit`]);
//! cl-chain-columns' custody and watermark rows (`cgc`, `finalized_slot`, ...). The version
//! check reads only its own row, so a new row never needs a migration.
//!
//! A block's root is `hash_tree_root(block.message)` and its slot the block's own, both from its
//! SSZ ([`blocks::put`]), and its `block_index` row is written in the same transaction. Every
//! write transaction commits through [`txn::commit`], which writes the stamp: a reader's snapshot
//! never holds a block newer than its stamp's head, nor a stamp whose blocks are missing.
//!
//! The column tables keep the names cl-chain-columns gave them (logically
//! `columns_unfinalized`): renaming them would rewrite every existing env. The C4 restart file
//! set (anchor, finalized pair, import log) is not in this env: it is cl-chain's
//! `persist::durable`.
//!
//! # Opening
//!
//! - [`env::open_writer`]: takes the writer guard (`writer.guard`, a tiny env opened
//!   `MDBX_EXCLUSIVE`; a live holder is [`Error::WriterHeld`]), opens the env read-write with
//!   `SyncMode::Durable` and `max_tables` = [`tables::MAX_TABLES`] set before any table is
//!   created, checks the requested geometry, then in one write transaction checks the schema
//!   version and the table names, creates every missing table (upgrading a version-1 env in
//!   place) and writes the version row.
//! - [`env::open_reader`]: `MDBX_RDONLY` with the same options; it never opens or creates the
//!   writer guard, and refuses a version or a table name it does not know, as the writer does,
//!   and a version-1 env the writer has not upgraded yet.

pub mod blocks;
pub mod env;
mod error;
pub mod keys;
pub mod stamp;
pub mod tables;
pub mod txn;
pub mod version;

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod testkit;

pub use error::{Error, Result};
