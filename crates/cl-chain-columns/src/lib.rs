//! MDBX store for verified, unfinalized data column sidecars, written only by cl-chain.
//!
//! - **Opaque values.** A column is stored as its SSZ bytes under `(slot, block_root,
//!   column_index)`; this crate never decodes it. Callers encode by the fork of the column's
//!   slot (Fulu sidecars carry header, commitments and inclusion proof; Gloas sidecars don't).
//!   The key layout is in [`keys`].
//! - **Chunked writes.** [`ColumnWriter::write_columns`] commits at most
//!   [`MAX_COLUMNS_PER_TXN`] (16) columns per write transaction and lets import go first between
//!   transactions, because MDBX allows one write transaction per env at a time.
//! - **Pruning.** Finality and retention are separate. [`ColumnWriter::finalize`] removes the
//!   blocks at or below the finalized slot that are off the finalized chain (the chain the
//!   stored links lead down from the blocks the caller names), keeps a block it cannot place
//!   below the contiguous-from slot, and raises the finalized-slot watermark: every block stored
//!   at or below it, from the contiguous-from slot on, is on that chain, and later writes at or
//!   below it are refused. [`ColumnWriter::prune_before`] removes every column
//!   below a slot (out of the retention window) and raises the retained-from slot
//!   ([`ColumnReader::retained_from`]), from which the store may claim to serve.
//!   [`ColumnWriter::prune_finalized`] does both at once: everything at or below the finalized
//!   slot. [`ColumnWriter::prune_orphaned`] removes every column of orphaned block roots and
//!   leaves a tombstone, so later writes of those roots are refused too.
//! - **Links.** Each stored block carries a [`BlockLink`] to the stored block before it on its
//!   chain ([`ColumnWriter::write_block_columns`]); a block waiting for an ancestor not stored
//!   yet links once that block is written, or is settled as a gap
//!   ([`ColumnWriter::settle_pending`]), and a gap raises the contiguous-from slot
//!   ([`ColumnReader::contiguous_from`]). A pending link names its target's slot, so a reader
//!   knows which slots hold a block the store lacks ([`Snapshot::first_pending_target`]). An env
//!   written before the links table existed is migrated when a writer opens it: contiguous only
//!   from the slot after its highest block; so are pending links stored without their target's
//!   slot (a parent link if the target is stored, else a gap), in the same transaction. Until
//!   then a reader serves nothing below the block of such a link.
//! - **Snapshots.** [`ColumnReader::snapshot`] reads several values of one state.
//! - **First stored slot.** [`ColumnReader::first_stored_slot`] is the lowest slot any column
//!   was ever stored at, written in the same transaction as that column; pruning leaves it. It
//!   is a historical minimum, not proof that the data from there on is held.
//! - **Custody.** The node's custody record lives in the same env for now
//!   ([`ColumnWriter::set_custody`], [`ColumnReader::custody`]): the custody group count, which
//!   never decreases ([`Error::CgcDecrease`]), the slot it was set at, the MetaData
//!   `seq_number` and the count advertised to peers, written in one transaction.
//! - **Single writer.** [`ColumnWriter::open`] holds an OS-level writer guard, so there is at
//!   most one writer per env across all processes. `EAGAIN`/`EWOULDBLOCK` from that lock is
//!   retried for about a second ([`WRITER_LOCK_ATTEMPTS`], [`WRITER_LOCK_RETRY_INTERVAL`]); a
//!   holder that outlasts the budget fails with [`Error::WriterAlreadyOpen`]. `MDBX_BUSY` is
//!   [`Error::EnvBusy`] and is not retried. [`ColumnReader`] opens the env read-only and
//!   has no write methods:
//!
//! ```compile_fail
//! # fn f(reader: &cl_chain_columns::ColumnReader) {
//! reader.write_columns(1, &[0; 32], &[]);
//! # }
//! ```
//!
//! The env is [`store_schema`]'s: always opened `SyncMode::Durable` (mixing it with
//! `SafeNoSync`/`UtterlyNoSync` on one env is `MDBX_INCOMPATIBLE`), with the same `max_tables`
//! for every opener, and a schema version this build does not read refuses the writer and
//! readers ([`Error::Schema`]). The first writer open of an env written before store-schema
//! adds its tables and version row in place.

mod env;
mod error;
pub mod keys;
mod reader;
mod sched;
mod writer;

pub use env::{
    WriterOptions, DEFAULT_MAX_SIZE, MAX_SIZE_ALIGN, MIN_MAX_SIZE, WRITER_LOCK_ATTEMPTS,
    WRITER_LOCK_RETRY_INTERVAL,
};
pub use error::{Error, Result};
pub use keys::{BlockLink, BlockRoot};
pub use reader::{
    ColumnReader, CustodyRecord, RangeBlock, RangeBudget, RangeColumn, RangeRead, Snapshot,
};
#[cfg(feature = "test-hooks")]
pub use writer::BeforeCommit;
pub use writer::{
    Column, ColumnWriter, PruneReport, WriteFailed, WriteReport, MAX_COLUMNS_PER_TXN,
    MAX_ORPHANED_ROOTS, MAX_ROWS_PER_PRUNE_TXN, MAX_SIDECAR_BYTES,
};

/// `NUMBER_OF_COLUMNS` (Fulu `das-core.md`, unchanged in Gloas).
pub const NUMBER_OF_COLUMNS: u64 = 128;
/// `NUMBER_OF_CUSTODY_GROUPS` (Fulu `das-core.md`, unchanged in Gloas).
pub const NUMBER_OF_CUSTODY_GROUPS: u64 = 128;
