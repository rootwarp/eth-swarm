use std::path::PathBuf;

use crate::{NUMBER_OF_COLUMNS, NUMBER_OF_CUSTODY_GROUPS};

/// Errors from the column store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mdbx: {0}")]
    Mdbx(libmdbx::Error),
    /// The env reached its map size ([`WriterOptions::max_size`](crate::WriterOptions)); the
    /// txn was aborted. Prune, or reopen with a larger map.
    #[error("column env map is full")]
    MapFull,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The exclusive writer lock stayed `EAGAIN`/`EWOULDBLOCK` through the retry budget.
    ///
    /// A live [`ColumnWriter`](crate::ColumnWriter) holds the lock that way for as long as it
    /// is open. The same errno also shows up for a moment after a writer is reaped: a `/proc`
    /// reader can keep the dead child's address space alive, and its mmaps pin the open-file
    /// description, so the OFD lock lingers with no fd holder. That case is retried; this
    /// error is what remains when the budget runs out.
    #[error("another column writer already holds {}", path.display())]
    WriterAlreadyOpen { path: PathBuf },
    /// `MDBX_BUSY` from the exclusive writer lock. Not the transient `EAGAIN` left after a
    /// writer is reaped, so it is not retried.
    #[error("column writer lock at {} returned MDBX_BUSY", path.display())]
    EnvBusy { path: PathBuf },
    /// [`WriterOptions::max_size`](crate::WriterOptions) is below
    /// [`MIN_MAX_SIZE`](crate::MIN_MAX_SIZE), not a multiple of
    /// [`MAX_SIZE_ALIGN`](crate::MAX_SIZE_ALIGN), or over `isize::MAX`.
    #[error(
        "map size {max_size} must be a multiple of 1 MiB, at least 256 MiB, at most isize::MAX"
    )]
    InvalidMaxSize { max_size: usize },
    /// MDBX kept a different map size than requested: another process has the env open, so the
    /// size stored in the env wins, or the request is below the space already used. Reopen with
    /// `effective`, or restart with readers detached to resize.
    #[error("requested map size {requested} B, env has {effective} B")]
    GeometryMismatch { requested: usize, effective: usize },
    #[error("column index {index} is not below NUMBER_OF_COLUMNS ({NUMBER_OF_COLUMNS})")]
    ColumnIndexOutOfRange { index: u64 },
    #[error("{len} columns in one write, more than NUMBER_OF_COLUMNS ({NUMBER_OF_COLUMNS})")]
    TooManyColumns { len: usize },
    #[error("column {index} appears twice in one write")]
    DuplicateColumn { index: u64 },
    #[error("column {index} has empty sidecar bytes")]
    EmptySidecar { index: u64 },
    /// Larger than any encodable sidecar ([`MAX_SIDECAR_BYTES`](crate::MAX_SIDECAR_BYTES)).
    #[error("column {index} sidecar is {len} bytes, over MAX_SIDECAR_BYTES")]
    SidecarTooLarge { index: u64, len: usize },
    /// The slot is at or below the finalized-slot watermark: its columns were already pruned
    /// and must not come back.
    #[error("slot {slot} is at or below the finalized slot {finalized_slot}")]
    SlotFinalized { slot: u64, finalized_slot: u64 },
    /// The block root was pruned as an orphan
    /// ([`ColumnWriter::prune_orphaned`](crate::ColumnWriter::prune_orphaned)); its columns must
    /// not come back.
    #[error("block root was pruned as an orphan")]
    RootOrphaned,
    /// A block root maps to exactly one slot; a write named a different one.
    #[error("block root is stored at slot {stored}, write named slot {given}")]
    SlotMismatch { stored: u64, given: u64 },
    #[error("cgc {0} exceeds NUMBER_OF_CUSTODY_GROUPS ({NUMBER_OF_CUSTODY_GROUPS})")]
    CgcOutOfRange(u64),
    /// The custody group count never decreases (`fulu/validator.md`); nothing was written.
    #[error("cgc {requested} is below the stored cgc {stored}")]
    CgcDecrease { stored: u64, requested: u64 },
    /// A read ran past its deadline and stopped.
    #[error("the read ran past its deadline")]
    Deadline,
    /// A stored row does not match the layout in [`keys`](crate::keys).
    #[error("corrupt row in table {table}")]
    Corrupt { table: &'static str },
    /// The env's schema refused the open: a schema version this build does not read
    /// ([`store_schema::Error::SchemaVersion`], [`store_schema::Error::MalformedSchemaVersion`]).
    /// Nothing was written.
    #[error("store schema: {0}")]
    Schema(store_schema::Error),
}

impl From<libmdbx::Error> for Error {
    fn from(e: libmdbx::Error) -> Self {
        match e {
            libmdbx::Error::MapFull => Error::MapFull,
            other => Error::Mdbx(other),
        }
    }
}

/// The env's errors in this crate's terms; a schema refusal is [`Error::Schema`].
impl From<store_schema::Error> for Error {
    fn from(e: store_schema::Error) -> Self {
        use store_schema::Error as S;
        match e {
            S::Mdbx(e) => e.into(),
            S::Io(e) => Error::Io(e),
            S::WriterHeld { path } => Error::WriterAlreadyOpen { path },
            S::EnvBusy { path } => Error::EnvBusy { path },
            S::InvalidMaxSize { max_size } => Error::InvalidMaxSize { max_size },
            S::GeometryMismatch {
                requested,
                effective,
            } => Error::GeometryMismatch {
                requested,
                effective,
            },
            other => Error::Schema(other),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
