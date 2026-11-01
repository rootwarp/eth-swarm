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
//! | `blocks`            | [`keys::slot_root_key`]: `slot (u64 BE) ‖ block_root (32)` | opaque (the importer's SSZ) |
//! | `states`            | [`keys::slot_root_key`]: `slot (u64 BE) ‖ block_root (32)` | opaque (the importer's SSZ) |
//!
//! `meta` rows: [`keys::SCHEMA_VERSION_KEY`] (`u64 BE`, [`version`]); [`keys::STAMP_KEY`],
//! reserved for #130's head/finalized stamp (any length); cl-chain-columns' custody and
//! watermark rows (`cgc`, `finalized_slot`, ...). The version check reads only its own row, so a
//! new row never needs a migration.
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
//!   version, creates every missing table and writes the version row.
//! - [`env::open_reader`]: `MDBX_RDONLY` with the same options; it never opens or creates the
//!   writer guard, and refuses a version it does not know, as the writer does.

pub mod env;
mod error;
pub mod keys;
pub mod tables;
pub mod version;

pub use error::{Error, Result};
