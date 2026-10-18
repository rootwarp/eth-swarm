//! [`ArchiveError`]: every way writing or opening an archive fails.

use super::manifest::ManifestError;
use super::names::NameError;
use super::payload::PayloadError;
use std::io;
use std::path::PathBuf;

/// Writing or opening an archive failed.
///
/// While capturing, a [`ArchiveError::Payload`] refuses one payload and the capture goes on;
/// every other error stops the capture ([`ArchiveError::stops_capture`]).
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// A file system operation failed (a full disk is `StorageFull`).
    #[error("{}: {source}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The capture configuration is refused.
    #[error("capture config: {0}")]
    Config(String),
    /// A network or topic name that cannot be a path component.
    #[error(transparent)]
    Name(#[from] NameError),
    /// One payload is refused; the capture goes on.
    #[error("payload refused: {0}")]
    Payload(#[from] PayloadError),
    /// Writing the payload would pass the capture's disk budget.
    #[error("disk budget of {budget} bytes exhausted: {written} written, {needed} more needed")]
    BudgetExhausted {
        /// The budget.
        budget: u64,
        /// Payload bytes written so far.
        written: u64,
        /// The refused payload's length.
        needed: u64,
    },
    /// An earlier error stopped the capture.
    #[error("the capture stopped after an earlier error: {0}")]
    Stopped(String),
    /// A sealed segment of the same slot range is already there; this one stays in its
    /// `.open-*` directory, manifest included.
    #[error("segment {} already exists; the sealed segment stays at {}", target.display(), open.display())]
    SegmentExists {
        /// The final directory that exists.
        target: PathBuf,
        /// Where the sealed segment is.
        open: PathBuf,
    },
    /// The manifest does not parse, does not hash to its digest or does not hold together.
    #[error("{}: {source}", path.display())]
    Manifest {
        /// The manifest file.
        path: PathBuf,
        /// The cause.
        source: ManifestError,
    },
    /// A file the manifest lists is not there.
    #[error("missing file {0}")]
    MissingFile(String),
    /// A file or directory the manifest does not list.
    #[error("file not in the manifest: {0}")]
    ExtraFile(String),
    /// A symlink or other non-regular entry where a file or directory belongs.
    #[error("{0}: not a regular file or directory")]
    NotRegular(String),
    /// A file's length differs from the manifest's.
    #[error("{path}: {actual} bytes, manifest says {expected}")]
    LengthMismatch {
        /// The file's path in the segment.
        path: String,
        /// The manifest's length.
        expected: u64,
        /// The file's length.
        actual: u64,
    },
    /// A file's sha256 differs from the manifest's.
    #[error("{path}: sha256 {actual}, manifest says {expected}")]
    Sha256Mismatch {
        /// The file's path in the segment.
        path: String,
        /// The manifest's sha256.
        expected: String,
        /// The file's sha256.
        actual: String,
    },
}

impl ArchiveError {
    /// Whether this error stops a capture: everything but a refused payload.
    pub fn stops_capture(&self) -> bool {
        !matches!(self, ArchiveError::Payload(_))
    }

    pub(crate) fn io(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Self {
        let path = path.into();
        move |source| ArchiveError::Io { path, source }
    }
}
