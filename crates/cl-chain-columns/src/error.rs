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
    /// Another [`ColumnWriter`](crate::ColumnWriter), in this process or another, holds the env.
    #[error("another column writer already holds {}", path.display())]
    WriterAlreadyOpen { path: PathBuf },
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
    /// A block root maps to exactly one slot; a write named a different one.
    #[error("block root is stored at slot {stored}, write named slot {given}")]
    SlotMismatch { stored: u64, given: u64 },
    #[error("cgc {0} exceeds NUMBER_OF_CUSTODY_GROUPS ({NUMBER_OF_CUSTODY_GROUPS})")]
    CgcOutOfRange(u64),
    /// The custody group count never decreases (`fulu/validator.md`); nothing was written.
    #[error("cgc {requested} is below the stored cgc {stored}")]
    CgcDecrease { stored: u64, requested: u64 },
    /// A stored row does not match the layout in [`keys`](crate::keys).
    #[error("corrupt row in table {table}")]
    Corrupt { table: &'static str },
}

impl From<libmdbx::Error> for Error {
    fn from(e: libmdbx::Error) -> Self {
        match e {
            libmdbx::Error::MapFull => Error::MapFull,
            other => Error::Mdbx(other),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
