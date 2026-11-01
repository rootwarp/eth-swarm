use std::path::PathBuf;

/// Errors from opening the env.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An MDBX call failed.
    #[error("mdbx: {0}")]
    Mdbx(#[from] libmdbx::Error),
    /// Creating the env directory failed (or an upgrade hook's own I/O).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The writer guard stayed `EAGAIN`/`EWOULDBLOCK` through the retry budget: another writer
    /// holds the env, in this process or another.
    ///
    /// The same errno also shows up for a moment after a writer is reaped: a `/proc` reader can
    /// keep the dead child's address space alive, and its mmaps pin the open-file description,
    /// so the OFD lock lingers with no fd holder. That case is retried; this error is what
    /// remains when the budget runs out.
    #[error("another writer holds the env at {}", path.display())]
    WriterHeld {
        /// The env directory.
        path: PathBuf,
    },
    /// `MDBX_BUSY` from the writer guard. Not the transient `EAGAIN` left after a writer is
    /// reaped, so it is not retried.
    #[error("the writer guard at {} returned MDBX_BUSY", path.display())]
    EnvBusy {
        /// The env directory.
        path: PathBuf,
    },
    /// [`WriterOptions::max_size`](crate::env::WriterOptions) is below
    /// [`MIN_MAX_SIZE`](crate::env::MIN_MAX_SIZE), not a multiple of
    /// [`MAX_SIZE_ALIGN`](crate::env::MAX_SIZE_ALIGN), or over `isize::MAX`.
    #[error(
        "map size {max_size} must be a multiple of 1 MiB, at least 256 MiB, at most isize::MAX"
    )]
    InvalidMaxSize {
        /// The size asked for.
        max_size: usize,
    },
    /// MDBX kept a different map size than requested: another process has the env open, so the
    /// size stored in the env wins, or the request is below the space already used. Reopen with
    /// `effective`, or restart with readers detached to resize.
    #[error("requested map size {requested} B, env has {effective} B")]
    GeometryMismatch {
        /// The size asked for.
        requested: usize,
        /// The size MDBX applied.
        effective: usize,
    },
    /// The env's schema version is not [`SCHEMA_VERSION`](crate::version::SCHEMA_VERSION): a
    /// newer cl-chain wrote it, or it was never a version. Nothing was written.
    #[error("env schema version {found}, this build reads only {supported}")]
    SchemaVersion {
        /// The stored version.
        found: u64,
        /// [`SCHEMA_VERSION`](crate::version::SCHEMA_VERSION).
        supported: u64,
    },
    /// The schema version row is not 8 bytes. Nothing was written.
    #[error("env schema version row is {len} bytes, not a u64")]
    MalformedSchemaVersion {
        /// Its length.
        len: usize,
    },
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
