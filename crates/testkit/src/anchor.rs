//! The checked anchor of an `anchor-fetch` output directory.
//!
//! `anchor-fetch` writes `block.ssz` and `state.ssz`, and last `anchor.json`, the commit
//! marker: a directory without `anchor.json` holds no anchor, whatever else it holds.
//! [`load_anchor`] reads `anchor.json` and then checks everything it names:
//!
//! - each file record names its own file (`block.ssz`, `state.ssz`), and the file is a regular
//!   file with the recorded length and sha256;
//! - `fork` is `gloas`, and both files decode as the Gloas signed block and state;
//! - `hash_tree_root(block.message)` is `block_root` (the root of the message, never the root
//!   of the signed wrapper);
//! - `hash_tree_root(state)`, `block.message.state_root` and `state_root` are one root;
//! - the block and the state are at `slot`.
//!
//! Any mismatch is an error, and no anchor is returned. The JSON shape is the `anchor.json`
//! record that `anchor-fetch` writes. This crate never links cl-sync, so [`AnchorRecord`] is
//! its own copy of that shape.

#[cfg(feature = "test-support")]
pub mod fixtures;

use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{Root, Slot};
use consensus_types::{EthSpec, ForkName};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssz::Decode;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tree_hash::TreeHash;

/// The commit marker and record of an anchor directory.
pub const ANCHOR_FILE: &str = "anchor.json";
/// The SSZ of the signed anchor block.
pub const BLOCK_FILE: &str = "block.ssz";
/// The SSZ of the anchor state, the post-state of the block.
pub const STATE_FILE: &str = "state.ssz";
/// The largest `anchor.json` read.
const MAX_RECORD_BYTES: u64 = 64 << 10;
/// The largest `block.ssz` or `state.ssz` read: a mainnet-preset state with a few million
/// validators fits.
const MAX_BODY_BYTES: u64 = 2 << 30;

/// `anchor.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRecord {
    /// The anchor block root, `0x` hex.
    pub block_root: String,
    /// The slot of the block and of its post-state.
    pub slot: u64,
    /// `compute_epoch_at_slot(slot)`.
    pub epoch: u64,
    /// The finalized checkpoint epoch the root was taken from.
    pub finalized_epoch: u64,
    /// `block.message.state_root == hash_tree_root(state)`, `0x` hex.
    pub state_root: String,
    /// The fork of both bodies.
    pub fork: String,
    /// `block.ssz`.
    pub block: FileRecord,
    /// `state.ssz`.
    pub state: FileRecord,
    /// The providers the bodies came from.
    pub providers: Vec<ProviderRecord>,
    /// When the anchor was written, UTC RFC 3339.
    pub fetched_at: String,
}

/// A body file, as `anchor.json` records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    /// The file name in the directory.
    pub file: String,
    /// The sha256 of the file, lower-case hex.
    pub sha256: String,
    /// The length of the file.
    pub bytes: u64,
    /// The name of the provider it came from.
    pub provider: String,
}

/// A provider, as `anchor.json` records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRecord {
    /// `a` (block) or `b` (state).
    pub role: String,
    /// The provider name.
    pub name: String,
    /// The operator of the provider.
    pub operator: String,
    /// The provider URL, redacted.
    pub url: String,
}

/// Why [`load_anchor`] returned no anchor.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// No `anchor.json`: the directory holds no committed anchor.
    #[error("{}: no {ANCHOR_FILE}, so the directory holds no anchor", dir.display())]
    NotCommitted {
        /// The directory.
        dir: PathBuf,
    },
    /// A file cannot be read.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// `anchor.json` does not parse, or a field has a value this loader does not take.
    #[error("{ANCHOR_FILE}: {0}")]
    Record(String),
    /// A body file is not what its record says: another name, not a regular file, another
    /// length or another sha256.
    #[error("{file}: {detail}")]
    File {
        /// The file name.
        file: &'static str,
        /// Why.
        detail: String,
    },
    /// A body file does not decode as its Gloas type.
    #[error("{file}: {detail}")]
    Decode {
        /// The file name.
        file: &'static str,
        /// Why.
        detail: String,
    },
    /// `hash_tree_root(block.message)` is not `block_root`.
    #[error("block root {computed} is not the anchor block_root {anchor}")]
    BlockRoot {
        /// `block_root` of `anchor.json`.
        anchor: Root,
        /// `hash_tree_root(block.message)`.
        computed: Root,
    },
    /// `hash_tree_root(state)`, `block.message.state_root` and `state_root` are not one root.
    #[error("state root {computed}, block state_root {block}, anchor state_root {anchor}")]
    StateRoot {
        /// `state_root` of `anchor.json`.
        anchor: Root,
        /// `block.message.state_root`.
        block: Root,
        /// `hash_tree_root(state)`.
        computed: Root,
    },
}

/// An anchor that [`load_anchor`] checked. Only [`load_anchor`] makes one.
#[derive(Debug, Clone)]
pub struct LoadedAnchor<E: EthSpec> {
    state: BeaconState<E>,
    block: SignedBeaconBlock<E>,
    block_root: Root,
    state_root: Root,
}

impl<E: EthSpec> LoadedAnchor<E> {
    /// The anchor state: the post-state of [`Self::block`].
    pub fn state(&self) -> &BeaconState<E> {
        &self.state
    }

    /// The signed anchor block.
    pub fn block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }

    /// `hash_tree_root(block.message)`.
    pub fn block_root(&self) -> Root {
        self.block_root
    }

    /// `hash_tree_root(state)`, equal to `block.message.state_root`.
    pub fn state_root(&self) -> Root {
        self.state_root
    }

    /// The slot of the block and of the state.
    pub fn slot(&self) -> Slot {
        self.block.message.slot
    }

    /// The state and the signed block.
    pub fn into_parts(self) -> (BeaconState<E>, SignedBeaconBlock<E>) {
        (self.state, self.block)
    }
}

/// Opens the anchor directory `dir`. See the module docs for each check.
pub fn load_anchor<E: EthSpec>(dir: &Path) -> Result<LoadedAnchor<E>, AnchorError> {
    let record_path = dir.join(ANCHOR_FILE);
    let text = match read_regular(&record_path, ANCHOR_FILE, MAX_RECORD_BYTES) {
        Err(AnchorError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Err(AnchorError::NotCommitted {
                dir: dir.to_owned(),
            })
        }
        other => other?,
    };
    let record: AnchorRecord =
        serde_json::from_slice(&text).map_err(|e| AnchorError::Record(e.to_string()))?;
    if record.fork != ForkName::Gloas.as_str() {
        return Err(AnchorError::Record(format!(
            "fork {:?} is not gloas",
            record.fork
        )));
    }
    let anchor_block_root = parse_root("block_root", &record.block_root)?;
    let anchor_state_root = parse_root("state_root", &record.state_root)?;
    let block_bytes = read_body(dir, BLOCK_FILE, &record.block)?;
    let state_bytes = read_body(dir, STATE_FILE, &record.state)?;
    let block =
        SignedBeaconBlock::<E>::from_ssz_bytes(&block_bytes).map_err(|e| AnchorError::Decode {
            file: BLOCK_FILE,
            detail: format!("{e:?}"),
        })?;
    let mut state =
        BeaconState::<E>::from_ssz_bytes(&state_bytes).map_err(|e| AnchorError::Decode {
            file: STATE_FILE,
            detail: format!("{e:?}"),
        })?;
    let block_root = block.message.tree_hash_root();
    if block_root != anchor_block_root {
        return Err(AnchorError::BlockRoot {
            anchor: anchor_block_root,
            computed: block_root,
        });
    }
    state.apply_updates().map_err(|e| AnchorError::Decode {
        file: STATE_FILE,
        detail: format!("{e:?}"),
    })?;
    let state_root = state.tree_hash_root();
    if state_root != anchor_state_root || block.message.state_root != anchor_state_root {
        return Err(AnchorError::StateRoot {
            anchor: anchor_state_root,
            block: block.message.state_root,
            computed: state_root,
        });
    }
    // The roots bind the state to the block; the record must name their slot.
    if block.message.slot != record.slot || state.slot != record.slot {
        return Err(AnchorError::Record(format!(
            "slot {} is not the block slot {} and the state slot {}",
            record.slot, block.message.slot, state.slot
        )));
    }
    Ok(LoadedAnchor {
        state,
        block,
        block_root,
        state_root,
    })
}

/// `0x` and 64 hex digits.
fn parse_root(field: &str, text: &str) -> Result<Root, AnchorError> {
    text.strip_prefix("0x")
        .filter(|hex| hex.len() == 64)
        .and_then(|hex| hex.parse().ok())
        .ok_or_else(|| AnchorError::Record(format!("{field} {text:?} is not 0x and 64 hex digits")))
}

/// The bytes of the body file `name`, checked against `record`.
fn read_body(dir: &Path, name: &'static str, record: &FileRecord) -> Result<Vec<u8>, AnchorError> {
    let mismatch = |detail: String| AnchorError::File { file: name, detail };
    if record.file != name {
        return Err(mismatch(format!("the record names {:?}", record.file)));
    }
    if record.bytes > MAX_BODY_BYTES {
        return Err(mismatch(format!(
            "the record says {} bytes, over {MAX_BODY_BYTES}",
            record.bytes
        )));
    }
    let bytes = read_regular(&dir.join(name), name, record.bytes)?;
    if bytes.len() as u64 != record.bytes {
        return Err(mismatch(format!(
            "{} bytes, the record says {}",
            bytes.len(),
            record.bytes
        )));
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if sha256 != record.sha256 {
        return Err(mismatch(format!(
            "sha256 {sha256}, the record says {}",
            record.sha256
        )));
    }
    Ok(bytes)
}

/// The bytes of the regular file `path` (named `file`), refused past `max` bytes before it is
/// read.
fn read_regular(path: &Path, file: &'static str, max: u64) -> Result<Vec<u8>, AnchorError> {
    let io = |source| AnchorError::Io {
        path: path.to_owned(),
        source,
    };
    let meta = fs::symlink_metadata(path).map_err(io)?;
    let refused = |detail: String| AnchorError::File { file, detail };
    if !meta.file_type().is_file() {
        return Err(refused("not a regular file".into()));
    }
    if meta.len() > max {
        return Err(refused(format!("{} bytes, over {max}", meta.len())));
    }
    fs::read(path).map_err(io)
}
