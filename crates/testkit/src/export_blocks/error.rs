//! [`ExportError`]: every way an export, or opening one, fails.

use super::manifest::ExportManifestError;
use crate::archive::ArchiveError;
use crate::collector::ApiError;
use consensus_types::codec::DecodeError;
use consensus_types::primitives::{Root, Slot};
use std::io;
use std::path::PathBuf;

/// `slot N: ` before a message about one slot.
fn at(slot: &Option<Slot>) -> String {
    slot.map(|s| format!("slot {s}: ")).unwrap_or_default()
}

/// An export failed, or an export directory was refused.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The export configuration is refused.
    #[error("export config: {0}")]
    Config(String),
    /// `<out>/<devnet>` exists already; an export never writes into an earlier one.
    #[error("{} exists already; export into a fresh directory", .0.display())]
    Exists(PathBuf),
    /// The export slot is past the source's finalized block, so its roots could still change.
    #[error("export slot {to} is after the finalized block's slot {finalized}")]
    NotFinalized {
        /// The export slot asked for.
        to: Slot,
        /// The source's finalized block slot.
        finalized: Slot,
    },
    /// A beacon API request failed or answered something the API does not specify.
    #[error("{}{source}", at(.slot))]
    Api {
        /// The slot asked about, if any.
        slot: Option<Slot>,
        /// The failure; it names the path template, never the base URL.
        source: ApiError,
    },
    /// A response body is over its bound; it was never read past it.
    #[error("{}{path}: body over {max} bytes", at(.slot))]
    TooLarge {
        /// The API path template.
        path: &'static str,
        /// The slot asked about, if any.
        slot: Option<Slot>,
        /// The bound.
        max: usize,
    },
    /// The SSZ does not decode with the shape of the fork of the object's own slot.
    #[error("{}{what}: ssz: {source}", at(.slot))]
    Decode {
        /// `block` or `genesis state`.
        what: &'static str,
        /// The slot asked for, for a block.
        slot: Option<Slot>,
        /// The cause.
        source: DecodeError,
    },
    /// The API served an object of another slot than the one asked for.
    #[error("asked for slot {requested}, the {what} is at slot {got}")]
    SlotMismatch {
        /// `block` or `genesis state`.
        what: &'static str,
        /// The slot asked for.
        requested: Slot,
        /// The object's slot.
        got: Slot,
    },
    /// Our `hash_tree_root` of the block differs from the API's root for its slot.
    #[error(
        "slot {slot}: the API's block root {api} is not the block's hash_tree_root {computed}"
    )]
    RootMismatch {
        /// The slot.
        slot: Slot,
        /// The API's root.
        api: Root,
        /// `hash_tree_root(message)`.
        computed: Root,
    },
    /// A block's parent is not the previous exported block: the chain is broken.
    #[error(
        "slot {slot}: parent_root {parent_root} is not the root {expected} of slot {expected_slot}"
    )]
    ParentMismatch {
        /// The block's slot.
        slot: Slot,
        /// Its `parent_root`.
        parent_root: Root,
        /// The previous exported block's slot.
        expected_slot: Slot,
        /// The previous exported block's root.
        expected: Root,
    },
    /// The genesis block is missing or does not commit to the genesis state.
    #[error("genesis: {0}")]
    Genesis(String),
    /// Writing or verifying the block archive failed.
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    /// A file system operation failed.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The export manifest does not parse, hash or hold together.
    #[error("{}: {source}", path.display())]
    Manifest {
        /// The manifest file.
        path: PathBuf,
        /// The cause.
        source: ExportManifestError,
    },
    /// The export directory does not match its manifest.
    #[error("{0}")]
    Mismatch(String),
}

impl ExportError {
    pub(crate) fn io(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Self {
        let path = path.into();
        move |source| ExportError::Io { path, source }
    }
}
