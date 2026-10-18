//! MDBX store for verified, unfinalized data column sidecars, written only by cl-chain.
//!
//! - **Opaque values.** A column is stored as its SSZ bytes under `(slot, block_root,
//!   column_index)`; this crate never decodes it. Callers encode by the fork of the column's
//!   slot (Fulu sidecars carry header, commitments and inclusion proof; Gloas sidecars don't).
//!   The key layout is in [`keys`].
//! - **Chunked writes.** [`ColumnWriter::write_columns`] commits at most
//!   [`MAX_COLUMNS_PER_TXN`] (16) columns per write transaction and lets import go first between
//!   transactions, because MDBX allows one write transaction per env at a time.
//! - **Pruning.** [`ColumnWriter::prune_finalized`] removes every column at or below the
//!   finalized slot and records that slot as a watermark; later writes at or below it are
//!   refused. [`ColumnWriter::prune_orphaned`] removes every column of orphaned block roots
//!   after a reorg.
//! - **Custody.** The node's custody record lives in the same env for now
//!   ([`ColumnWriter::set_custody`], [`ColumnReader::custody`]): the custody group count, which
//!   never decreases ([`Error::CgcDecrease`]), the slot it was set at, the MetaData
//!   `seq_number` and the count advertised to peers, written in one transaction.
//! - **Single writer.** [`ColumnWriter::open`] holds an OS-level writer guard, so there is at
//!   most one writer per env across all processes. [`ColumnReader`] opens the env read-only and
//!   has no write methods:
//!
//! ```compile_fail
//! # fn f(reader: &cl_chain_columns::ColumnReader) {
//! reader.write_columns(1, &[0; 32], &[]);
//! # }
//! ```
//!
//! The env is always opened `SyncMode::Durable`; mixing it with `SafeNoSync`/`UtterlyNoSync` on
//! one env is `MDBX_INCOMPATIBLE`. These tables move into the shared store schema later without
//! an API change.

mod env;
mod error;
pub mod keys;
mod reader;
mod sched;
mod writer;

pub use env::{WriterOptions, DEFAULT_MAX_SIZE, MAX_SIZE_ALIGN, MIN_MAX_SIZE};
pub use error::{Error, Result};
pub use keys::BlockRoot;
pub use reader::{ColumnReader, CustodyRecord};
pub use writer::{
    Column, ColumnWriter, PruneReport, WriteReport, MAX_COLUMNS_PER_TXN, MAX_ROWS_PER_PRUNE_TXN,
    MAX_SIDECAR_BYTES,
};

/// `NUMBER_OF_COLUMNS` (Fulu `das-core.md`, unchanged in Gloas).
pub const NUMBER_OF_COLUMNS: u64 = 128;
/// `NUMBER_OF_CUSTODY_GROUPS` (Fulu `das-core.md`, unchanged in Gloas).
pub const NUMBER_OF_CUSTODY_GROUPS: u64 = 128;
