//! `export.toml`: what a devnet export holds, and the digest of everything in it.
//!
//! The first line is `export_sha256 = "<hex>"`, the sha256 of every byte after that line (the
//! body), the same scheme as the archive's `manifest.toml`. The body is TOML:
//!
//! ```toml
//! export_sha256 = "…"
//! format_version = 2
//! devnet = "ethswarm-gloas"
//! source = "cl-1-lighthouse-geth"
//! preset = "minimal"
//! slot_start = 0
//! slot_end = 95
//! finalized_slot = 104
//! config_sha256 = "…"
//! genesis_time = 1760800000
//! genesis_validators_root = "0x…"
//! genesis_block_root = "0x…"
//! genesis_state_root = "0x…"
//! images = ["ethpandaops/lighthouse:unstable-c8ddac7@sha256:…"]
//! empty_slots = [7, 30]
//!
//! [genesis_state]
//! path = "genesis_state.ssz"
//! len = 123456
//! sha256 = "…"
//!
//! [[fork_schedule]]
//! fork = "fulu"
//! version = "0x…"
//! epoch = 0
//!
//! [[fork_digests]]
//! epoch = 0
//! digest = "0x…"
//!
//! [[segments]]
//! dir = "0-95"
//! archive_sha256 = "…"
//!
//! [[blocks]]
//! slot = 0
//! root = "0x…"
//! parent_root = "0x…"
//! ```
//!
//! Every block's root and every segment's archive digest (which covers every block file's
//! sha256) are in the body, so `export_sha256` pins the whole export.

use super::export::MAX_GENESIS_STATE_BYTES;
use crate::archive::{canonical_hex, segment_name, validate_network, Sha256Digest, PRESETS};
use consensus_types::primitives::{Epoch, ForkName, Root, Slot, Version};
use consensus_types::{EthSpec, Mainnet, Minimal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The export manifest's file name, in `<out>/<devnet>/`.
pub const EXPORT_FILE: &str = "export.toml";
/// The genesis state's file name, in `<out>/<devnet>/`: the SSZ as the beacon API served it.
pub const GENESIS_STATE_FILE: &str = "genesis_state.ssz";
/// The export format this crate writes and reads.
/// Version 2: the segments are of archive format 2, with a digest schedule.
pub const EXPORT_FORMAT_VERSION: u32 = 2;
/// The longest source label.
pub const MAX_SOURCE_LEN: usize = 64;
/// The longest image reference.
pub const MAX_IMAGE_LEN: usize = 256;
const HEADER_KEY: &str = "export_sha256 = \"";
const DIGEST_PREFIX: &str = "@sha256:";

/// The genesis state file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateFile {
    /// Its name in the export directory: always [`GENESIS_STATE_FILE`].
    pub path: String,
    /// Its length in bytes.
    pub len: u64,
    /// Its sha256.
    pub sha256: Sha256Digest,
}

/// One scheduled fork of the devnet's config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkEntry {
    /// The fork.
    pub fork: ForkName,
    /// `<FORK>_FORK_VERSION`.
    pub version: Version,
    /// `<FORK>_FORK_EPOCH`.
    pub epoch: Epoch,
}

/// A fork digest and the epoch it is in force from: the archive manifest's entry type.
pub use crate::archive::DigestEntry;

/// A sealed archive segment of the export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentEntry {
    /// `<slot_start>-<slot_end>`, the segment's directory in `<out>/<devnet>/`.
    pub dir: String,
    /// The segment's `archive_sha256`.
    pub archive_sha256: Sha256Digest,
}

/// One exported block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockEntry {
    /// `message.slot`.
    pub slot: Slot,
    /// `hash_tree_root(message)`, equal to the beacon API's root for the slot.
    pub root: Root,
    /// `message.parent_root`: the root of the previous exported block (zero for genesis).
    pub parent_root: Root,
}

/// A devnet export: blocks and roots from genesis to `slot_end`, the genesis state, and where
/// they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportManifest {
    /// The devnet name (the export directory's name, and the archive's network).
    pub devnet: String,
    /// The CL the export was read from (e.g. `cl-1-lighthouse-geth`).
    pub source: String,
    /// The preset the blocks were decoded with.
    pub preset: String,
    /// The first exported slot: genesis, 0.
    pub slot_start: Slot,
    /// The export slot, the last one exported.
    pub slot_end: Slot,
    /// The source's finalized block slot when the export started, at or after `slot_end`.
    pub finalized_slot: Slot,
    /// sha256 of the devnet `config.yaml` the fork schedule came from.
    pub config_sha256: Sha256Digest,
    /// `genesis_time` of the genesis state.
    pub genesis_time: u64,
    /// `genesis_validators_root` of the genesis state.
    pub genesis_validators_root: Root,
    /// The genesis block's root (`blocks[0].root`).
    pub genesis_block_root: Root,
    /// `hash_tree_root` of the genesis state, the genesis block's `state_root`.
    pub genesis_state_root: Root,
    /// The devnet's images, `repo:tag@sha256:<digest>`, sorted and unique.
    pub images: Vec<String>,
    /// The slots without a block (the beacon API answered 404), ascending.
    pub empty_slots: Vec<Slot>,
    /// The genesis state file.
    pub genesis_state: StateFile,
    /// The scheduled forks, oldest first.
    pub fork_schedule: Vec<ForkEntry>,
    /// The fork digests in force from genesis to `slot_end`, ascending by epoch.
    pub fork_digests: Vec<DigestEntry>,
    /// The archive segments holding the block files, in slot order.
    pub segments: Vec<SegmentEntry>,
    /// Every block from genesis to `slot_end`, ascending by slot.
    pub blocks: Vec<BlockEntry>,
}

/// An export manifest that cannot be read or does not hold together.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExportManifestError {
    /// The first line is not `export_sha256 = "<64 lowercase hex>"`.
    #[error("first line must be export_sha256 = \"<64 lowercase hex>\"")]
    Header,
    /// The body does not hash to `export_sha256`.
    #[error("export sha256 mismatch: manifest says {recorded}, body hashes to {computed}")]
    DigestMismatch {
        /// The header's digest.
        recorded: String,
        /// The body's digest.
        computed: String,
    },
    /// The body is not the export TOML.
    #[error("toml: {0}")]
    Toml(String),
    /// A version this crate does not read.
    #[error("format_version {0}, expected {EXPORT_FORMAT_VERSION}")]
    Version(u32),
    /// The fields contradict each other.
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(message: String) -> Result<T, ExportManifestError> {
    Err(ExportManifestError::Invalid(message))
}

impl ExportManifest {
    /// The block and empty-slot list, one entry per slot from `slot_start` to `slot_end`:
    /// `Some(root)` for a block, `None` for an empty slot. Only meaningful on a
    /// [validated](ExportManifest::validate) manifest.
    pub fn root_list(&self) -> Vec<Option<Root>> {
        let mut blocks = self.blocks.iter().peekable();
        (self.slot_start..=self.slot_end)
            .map(|slot| blocks.next_if(|b| b.slot == slot).map(|b| b.root))
            .collect()
    }

    /// Checks that the fields hold together: a valid devnet name, a source label, a known
    /// preset, genesis at slot 0 up to a `slot_end` at or before `finalized_slot`, sorted
    /// unique pinned images; every slot of the range either a block or empty, never both;
    /// a genesis block with a zero parent and the recorded root, and every later block's
    /// parent the previous block; the genesis state at [`GENESIS_STATE_FILE`] and at most
    /// [`MAX_GENESIS_STATE_BYTES`]; forks ascending, one from genesis, and digests ascending
    /// from genesis to `slot_end` with one from each fork in that range; and at least one
    /// segment, each named once.
    pub fn validate(&self) -> Result<(), ExportManifestError> {
        validate_network(&self.devnet).map_err(|e| ExportManifestError::Invalid(e.to_string()))?;
        validate_label("source", &self.source, MAX_SOURCE_LEN)?;
        if !PRESETS.contains(&self.preset.as_str()) {
            return invalid(format!("unknown preset {:?}", self.preset));
        }
        if self.slot_start != 0 {
            return invalid(format!("slot_start {} is not genesis (0)", self.slot_start));
        }
        if self.slot_end > self.finalized_slot {
            return invalid(format!(
                "slot_end {} is after the finalized slot {}",
                self.slot_end, self.finalized_slot
            ));
        }
        self.validate_images()?;
        self.validate_slots()?;
        self.validate_chain()?;
        if self.genesis_state.path != GENESIS_STATE_FILE {
            return invalid(format!(
                "the genesis state must be at {GENESIS_STATE_FILE}, not {:?}",
                self.genesis_state.path
            ));
        }
        if !strictly_ascending(self.fork_schedule.iter().map(|f| f.fork)) {
            return invalid("fork_schedule must be ascending by fork, each once".into());
        }
        if self
            .fork_schedule
            .windows(2)
            .any(|w| w[0].epoch > w[1].epoch)
        {
            return invalid("fork_schedule epochs must not decrease".into());
        }
        self.validate_digests()?;
        if self.genesis_state.len > MAX_GENESIS_STATE_BYTES {
            return invalid(format!(
                "the genesis state's {} bytes are over {MAX_GENESIS_STATE_BYTES}",
                self.genesis_state.len
            ));
        }
        if self.segments.is_empty() {
            return invalid("an export has at least one segment".into());
        }
        let mut dirs: Vec<&str> = self.segments.iter().map(|s| s.dir.as_str()).collect();
        dirs.sort_unstable();
        if dirs.windows(2).any(|w| w[0] == w[1]) {
            return invalid("each segment is listed once".into());
        }
        for dir in dirs {
            if !is_segment_name(dir) {
                return invalid(format!("segment {dir:?} is not <slot_start>-<slot_end>"));
            }
        }
        Ok(())
    }

    /// The forks and digests cover genesis to `slot_end`: a fork from epoch 0, digests from
    /// epoch 0 ascending strictly and none past `slot_end`'s epoch, and a digest from each
    /// fork's epoch in that range (a fork always changes the digest).
    ///
    /// The digest values are not recomputed: from Fulu, `compute_fork_digest` mixes the blob
    /// parameters of the epoch into every digest, fork epochs included, and the manifest does
    /// not carry the blob schedule. Opening checks their presence here and their match with
    /// the block files; the pinned `export_sha256` covers the values.
    fn validate_digests(&self) -> Result<(), ExportManifestError> {
        if self.fork_schedule.first().map(|f| f.epoch) != Some(0) {
            return invalid("fork_schedule must have a fork from genesis (epoch 0)".into());
        }
        if self.fork_digests.first().map(|d| d.epoch) != Some(0)
            || !strictly_ascending(self.fork_digests.iter().map(|d| d.epoch))
        {
            return invalid("fork_digests must start at epoch 0 and ascend strictly".into());
        }
        let end_epoch = self.slot_end / slots_per_epoch(&self.preset);
        if let Some(late) = self.fork_digests.iter().find(|d| d.epoch > end_epoch) {
            return invalid(format!(
                "fork digest of epoch {} is past slot_end's epoch {end_epoch}",
                late.epoch
            ));
        }
        for fork in self.fork_schedule.iter().filter(|f| f.epoch <= end_epoch) {
            if !self.fork_digests.iter().any(|d| d.epoch == fork.epoch) {
                return invalid(format!(
                    "no fork digest from {}'s epoch {}",
                    fork.fork, fork.epoch
                ));
            }
        }
        Ok(())
    }

    fn validate_images(&self) -> Result<(), ExportManifestError> {
        if self.images.is_empty() {
            return invalid("an export names the devnet's images".into());
        }
        if !strictly_ascending(self.images.iter()) {
            return invalid("images must be sorted and unique".into());
        }
        for image in &self.images {
            validate_image(image)?;
        }
        Ok(())
    }

    /// Every slot of `slot_start..=slot_end` is a block or empty, exactly once.
    fn validate_slots(&self) -> Result<(), ExportManifestError> {
        if !strictly_ascending(self.blocks.iter().map(|b| b.slot)) {
            return invalid("blocks must ascend strictly by slot".into());
        }
        if !strictly_ascending(self.empty_slots.iter()) {
            return invalid("empty_slots must ascend strictly".into());
        }
        let (mut blocks, mut empty) = (self.blocks.iter().peekable(), self.empty_slots.iter());
        let mut next_empty = empty.next();
        for slot in self.slot_start..=self.slot_end {
            let block = blocks.next_if(|b| b.slot == slot).is_some();
            let is_empty = next_empty == Some(&slot);
            if is_empty {
                next_empty = empty.next();
            }
            if block == is_empty {
                let what = if block {
                    "both a block and empty"
                } else {
                    "neither a block nor empty"
                };
                return invalid(format!("slot {slot} is {what}"));
            }
        }
        if blocks.next().is_some() || next_empty.is_some() {
            return invalid(format!("a slot past slot_end {} is listed", self.slot_end));
        }
        Ok(())
    }

    /// Genesis has a zero parent and the recorded root; each later block's parent is the
    /// block before it.
    fn validate_chain(&self) -> Result<(), ExportManifestError> {
        let Some(genesis) = self.blocks.first().filter(|b| b.slot == 0) else {
            return invalid("the export has no genesis block".into());
        };
        if genesis.parent_root != Root::ZERO {
            return invalid("the genesis block's parent_root is not zero".into());
        }
        if genesis.root != self.genesis_block_root {
            return invalid("genesis_block_root is not the slot 0 block's root".into());
        }
        for pair in self.blocks.windows(2) {
            if pair[1].parent_root != pair[0].root {
                return invalid(format!(
                    "slot {}: parent_root {} is not the root of slot {} ({})",
                    pair[1].slot, pair[1].parent_root, pair[0].slot, pair[0].root
                ));
            }
        }
        Ok(())
    }

    /// The manifest bytes and the export sha256 (the digest of the body), after
    /// [validating](ExportManifest::validate).
    pub fn render(&self) -> Result<(Vec<u8>, Sha256Digest), ExportManifestError> {
        self.validate()?;
        let body = toml::to_string(&RawExport::from(self))
            .map_err(|e| ExportManifestError::Toml(e.to_string()))?;
        let digest: Sha256Digest = Sha256::digest(body.as_bytes()).into();
        let mut out = format!("{HEADER_KEY}{}\"\n", hex::encode(digest)).into_bytes();
        out.extend_from_slice(body.as_bytes());
        Ok((out, digest))
    }

    /// Parses manifest bytes, checking the header digest first and then every field
    /// ([`ExportManifest::validate`]). Returns the manifest and its export sha256.
    pub fn parse(bytes: &[u8]) -> Result<(Self, Sha256Digest), ExportManifestError> {
        let (header, body) = bytes
            .iter()
            .position(|&b| b == b'\n')
            .map(|at| (&bytes[..at], &bytes[at + 1..]))
            .ok_or(ExportManifestError::Header)?;
        let recorded = std::str::from_utf8(header)
            .ok()
            .and_then(|h| h.strip_prefix(HEADER_KEY)?.strip_suffix('"'))
            .and_then(canonical_hex::<32>)
            .ok_or(ExportManifestError::Header)?;
        let computed: Sha256Digest = Sha256::digest(body).into();
        if computed != recorded {
            return Err(ExportManifestError::DigestMismatch {
                recorded: hex::encode(recorded),
                computed: hex::encode(computed),
            });
        }
        let toml_err = |e: String| ExportManifestError::Toml(e);
        let body = std::str::from_utf8(body).map_err(|e| toml_err(e.to_string()))?;
        let raw: RawExport = toml::from_str(body).map_err(|e| toml_err(e.to_string()))?;
        let manifest = ExportManifest::try_from(raw)?;
        manifest.validate()?;
        Ok((manifest, computed))
    }
}

/// `SLOTS_PER_EPOCH` of a known preset.
fn slots_per_epoch(preset: &str) -> u64 {
    if preset == Minimal::NAME {
        Minimal::slots_per_epoch()
    } else {
        Mainnet::slots_per_epoch()
    }
}

fn strictly_ascending<T: PartialOrd>(items: impl IntoIterator<Item = T>) -> bool {
    let mut it = items.into_iter().peekable();
    while let Some(a) = it.next() {
        if it.peek().is_some_and(|b| a >= *b) {
            return false;
        }
    }
    true
}

/// 1 to `max` printable ASCII characters without spaces or quotes.
pub(crate) fn validate_label(
    field: &str,
    value: &str,
    max: usize,
) -> Result<(), ExportManifestError> {
    let printable = value
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\');
    if value.is_empty() || value.len() > max || !printable {
        return invalid(format!(
            "{field} must be 1 to {max} printable characters without spaces or quotes"
        ));
    }
    Ok(())
}

/// `<repo>[:<tag>]@sha256:<64 lowercase hex>`: an image pinned by digest.
pub(crate) fn validate_image(image: &str) -> Result<(), ExportManifestError> {
    validate_label("an image", image, MAX_IMAGE_LEN)?;
    let pinned = image
        .split_once(DIGEST_PREFIX)
        .filter(|(name, _)| !name.is_empty())
        .and_then(|(_, digest)| canonical_hex::<32>(digest));
    if pinned.is_none() {
        return invalid(format!(
            "image {image:?} is not <repo:tag>@sha256:<64 lowercase hex>"
        ));
    }
    Ok(())
}

/// `<slot_start>-<slot_end>` as the archive names a segment.
fn is_segment_name(dir: &str) -> bool {
    let parse = |s: &str| s.parse::<Slot>().ok();
    dir.split_once('-')
        .and_then(|(a, b)| Some((parse(a)?, parse(b)?)))
        .is_some_and(|(a, b)| a <= b && segment_name(a, b) == dir)
}

fn prefixed_hex<const N: usize>(field: &str, text: &str) -> Result<[u8; N], ExportManifestError> {
    text.strip_prefix("0x")
        .and_then(canonical_hex::<N>)
        .ok_or_else(|| {
            ExportManifestError::Invalid(format!(
                "{field} {text:?} is not 0x and {} lowercase hex digits",
                2 * N
            ))
        })
}

fn plain_hex<const N: usize>(field: &str, text: &str) -> Result<[u8; N], ExportManifestError> {
    canonical_hex::<N>(text).ok_or_else(|| {
        ExportManifestError::Invalid(format!(
            "{field} {text:?} is not {} lowercase hex digits",
            2 * N
        ))
    })
}

fn root_hex(root: &Root) -> String {
    format!("0x{}", hex::encode(root))
}

fn parse_root(field: &str, text: &str) -> Result<Root, ExportManifestError> {
    prefixed_hex::<32>(field, text).map(Root::from)
}

/// The TOML shape of [`ExportManifest`]: digests and roots as hex strings. Values come
/// before tables, as TOML requires.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExport {
    format_version: u32,
    devnet: String,
    source: String,
    preset: String,
    slot_start: u64,
    slot_end: u64,
    finalized_slot: u64,
    config_sha256: String,
    genesis_time: u64,
    genesis_validators_root: String,
    genesis_block_root: String,
    genesis_state_root: String,
    images: Vec<String>,
    empty_slots: Vec<u64>,
    genesis_state: RawStateFile,
    fork_schedule: Vec<RawFork>,
    fork_digests: Vec<RawDigest>,
    segments: Vec<RawSegment>,
    blocks: Vec<RawBlock>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStateFile {
    path: String,
    len: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFork {
    fork: String,
    version: String,
    epoch: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDigest {
    epoch: u64,
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSegment {
    dir: String,
    archive_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBlock {
    slot: u64,
    root: String,
    parent_root: String,
}

impl From<&ExportManifest> for RawExport {
    fn from(m: &ExportManifest) -> Self {
        Self {
            format_version: EXPORT_FORMAT_VERSION,
            devnet: m.devnet.clone(),
            source: m.source.clone(),
            preset: m.preset.clone(),
            slot_start: m.slot_start,
            slot_end: m.slot_end,
            finalized_slot: m.finalized_slot,
            config_sha256: hex::encode(m.config_sha256),
            genesis_time: m.genesis_time,
            genesis_validators_root: root_hex(&m.genesis_validators_root),
            genesis_block_root: root_hex(&m.genesis_block_root),
            genesis_state_root: root_hex(&m.genesis_state_root),
            images: m.images.clone(),
            empty_slots: m.empty_slots.clone(),
            genesis_state: RawStateFile {
                path: m.genesis_state.path.clone(),
                len: m.genesis_state.len,
                sha256: hex::encode(m.genesis_state.sha256),
            },
            fork_schedule: m
                .fork_schedule
                .iter()
                .map(|f| RawFork {
                    fork: f.fork.as_str().to_owned(),
                    version: format!("0x{}", hex::encode(f.version)),
                    epoch: f.epoch,
                })
                .collect(),
            fork_digests: m
                .fork_digests
                .iter()
                .map(|d| RawDigest {
                    epoch: d.epoch,
                    digest: format!("0x{}", hex::encode(d.digest)),
                })
                .collect(),
            segments: m
                .segments
                .iter()
                .map(|s| RawSegment {
                    dir: s.dir.clone(),
                    archive_sha256: hex::encode(s.archive_sha256),
                })
                .collect(),
            blocks: m
                .blocks
                .iter()
                .map(|b| RawBlock {
                    slot: b.slot,
                    root: root_hex(&b.root),
                    parent_root: root_hex(&b.parent_root),
                })
                .collect(),
        }
    }
}

impl TryFrom<RawExport> for ExportManifest {
    type Error = ExportManifestError;

    fn try_from(raw: RawExport) -> Result<Self, ExportManifestError> {
        if raw.format_version != EXPORT_FORMAT_VERSION {
            return Err(ExportManifestError::Version(raw.format_version));
        }
        let fork_schedule = raw
            .fork_schedule
            .iter()
            .map(|f| {
                Ok(ForkEntry {
                    fork: f.fork.parse().map_err(|e: network_config::UnknownFork| {
                        ExportManifestError::Invalid(e.to_string())
                    })?,
                    version: prefixed_hex::<4>("fork version", &f.version)?,
                    epoch: f.epoch,
                })
            })
            .collect::<Result<_, ExportManifestError>>()?;
        let fork_digests = raw
            .fork_digests
            .iter()
            .map(|d| {
                Ok(DigestEntry {
                    epoch: d.epoch,
                    digest: prefixed_hex::<4>("fork digest", &d.digest)?,
                })
            })
            .collect::<Result<_, ExportManifestError>>()?;
        let segments = raw
            .segments
            .into_iter()
            .map(|s| {
                Ok(SegmentEntry {
                    archive_sha256: plain_hex::<32>("archive_sha256", &s.archive_sha256)?,
                    dir: s.dir,
                })
            })
            .collect::<Result<_, ExportManifestError>>()?;
        let blocks = raw
            .blocks
            .iter()
            .map(|b| {
                Ok(BlockEntry {
                    slot: b.slot,
                    root: parse_root("root", &b.root)?,
                    parent_root: parse_root("parent_root", &b.parent_root)?,
                })
            })
            .collect::<Result<_, ExportManifestError>>()?;
        Ok(Self {
            config_sha256: plain_hex::<32>("config_sha256", &raw.config_sha256)?,
            genesis_validators_root: parse_root(
                "genesis_validators_root",
                &raw.genesis_validators_root,
            )?,
            genesis_block_root: parse_root("genesis_block_root", &raw.genesis_block_root)?,
            genesis_state_root: parse_root("genesis_state_root", &raw.genesis_state_root)?,
            genesis_state: StateFile {
                sha256: plain_hex::<32>("genesis_state.sha256", &raw.genesis_state.sha256)?,
                path: raw.genesis_state.path,
                len: raw.genesis_state.len,
            },
            devnet: raw.devnet,
            source: raw.source,
            preset: raw.preset,
            slot_start: raw.slot_start,
            slot_end: raw.slot_end,
            finalized_slot: raw.finalized_slot,
            genesis_time: raw.genesis_time,
            images: raw.images,
            empty_slots: raw.empty_slots,
            fork_schedule,
            fork_digests,
            segments,
            blocks,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use consensus_types::primitives::B256;

    /// A valid manifest over slots 0..=5 with slot 3 empty.
    pub(crate) fn manifest() -> ExportManifest {
        let root = |b: u8| B256::repeat_byte(b);
        let blocks = vec![
            BlockEntry {
                slot: 0,
                root: root(0x10),
                parent_root: Root::ZERO,
            },
            BlockEntry {
                slot: 1,
                root: root(0x11),
                parent_root: root(0x10),
            },
            BlockEntry {
                slot: 2,
                root: root(0x12),
                parent_root: root(0x11),
            },
            BlockEntry {
                slot: 4,
                root: root(0x14),
                parent_root: root(0x12),
            },
            BlockEntry {
                slot: 5,
                root: root(0x15),
                parent_root: root(0x14),
            },
        ];
        ExportManifest {
            devnet: "ethswarm-gloas".into(),
            source: "cl-1-lighthouse-geth".into(),
            preset: "minimal".into(),
            slot_start: 0,
            slot_end: 5,
            finalized_slot: 8,
            config_sha256: [7; 32],
            genesis_time: 1_760_800_000,
            genesis_validators_root: root(0x42),
            genesis_block_root: root(0x10),
            genesis_state_root: root(0x43),
            images: vec![
                format!("ethereum/client-go:v1.17.8@sha256:{}", "ab".repeat(32)),
                format!("ethpandaops/lighthouse:unstable@sha256:{}", "cd".repeat(32)),
            ],
            empty_slots: vec![3],
            genesis_state: StateFile {
                path: GENESIS_STATE_FILE.into(),
                len: 1234,
                sha256: [9; 32],
            },
            fork_schedule: vec![
                ForkEntry {
                    fork: ForkName::Fulu,
                    version: [0x60, 0, 0, 1],
                    epoch: 0,
                },
                ForkEntry {
                    fork: ForkName::Gloas,
                    version: [0x70, 0, 0, 1],
                    epoch: 0,
                },
            ],
            fork_digests: vec![DigestEntry {
                epoch: 0,
                digest: [1, 2, 3, 4],
            }],
            segments: vec![SegmentEntry {
                dir: "0-5".into(),
                archive_sha256: [5; 32],
            }],
            blocks,
        }
    }

    fn with_digest(body: &str) -> Vec<u8> {
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        format!("export_sha256 = \"{digest}\"\n{body}").into_bytes()
    }

    fn body(m: &ExportManifest) -> String {
        let (bytes, _) = m.render().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        text.split_once('\n').unwrap().1.to_owned()
    }

    fn refused(m: ExportManifest, what: &str) {
        let err = m.validate().unwrap_err();
        assert!(
            matches!(err, ExportManifestError::Invalid(_)),
            "{what}: {err}"
        );
        assert_eq!(m.render().unwrap_err(), err, "{what}: render validates");
    }

    #[test]
    fn render_parse_round_trip() {
        let m = manifest();
        let (bytes, digest) = m.render().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let (header, body) = text.split_once('\n').unwrap();
        assert_eq!(
            header,
            format!("export_sha256 = \"{}\"", hex::encode(digest))
        );
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(body.as_bytes())));
        for field in [
            "devnet = \"ethswarm-gloas\"",
            "empty_slots = [3]",
            "fork = \"gloas\"",
            "[genesis_state]",
            "path = \"genesis_state.ssz\"",
        ] {
            assert!(body.contains(field), "{field} in\n{body}");
        }
        assert_eq!(ExportManifest::parse(&bytes).unwrap(), (m, digest));
    }

    #[test]
    fn the_root_list_has_one_entry_per_slot() {
        let list = manifest().root_list();
        let root = |b: u8| Some(B256::repeat_byte(b));
        assert_eq!(
            list,
            vec![
                root(0x10),
                root(0x11),
                root(0x12),
                None,
                root(0x14),
                root(0x15)
            ]
        );
    }

    #[test]
    fn every_flipped_byte_is_refused() {
        let (bytes, _) = manifest().render().unwrap();
        for at in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[at] ^= 0x01;
            assert!(
                ExportManifest::parse(&flipped).is_err(),
                "byte {at} accepted"
            );
        }
        assert!(ExportManifest::parse(&bytes[..bytes.len() - 1]).is_err());
        assert_eq!(ExportManifest::parse(b""), Err(ExportManifestError::Header));
        let upper = format!("export_sha256 = \"{}\"\n", "AB".repeat(32));
        assert_eq!(
            ExportManifest::parse(upper.as_bytes()),
            Err(ExportManifestError::Header)
        );
    }

    #[test]
    fn a_rehashed_body_must_still_parse_and_hold_together() {
        let good = body(&manifest());
        let unknown = format!("extra = 1\n{good}");
        assert!(matches!(
            ExportManifest::parse(&with_digest(&unknown)),
            Err(ExportManifestError::Toml(_))
        ));
        // Version 1 named segments of the archive format before the digest schedule.
        for (version, to) in [(1, "format_version = 1"), (3, "format_version = 3")] {
            let other = good.replace("format_version = 2", to);
            assert_ne!(other, good);
            assert_eq!(
                ExportManifest::parse(&with_digest(&other)),
                Err(ExportManifestError::Version(version))
            );
        }
        for (from, to) in [
            ("fork = \"gloas\"", "fork = \"heze\""),
            ("digest = \"0x01020304\"", "digest = \"0x010203\""),
            ("root = \"0x1111", "root = \"0xABAB"),
            ("config_sha256 = \"0707", "config_sha256 = \"0x07"),
            ("version = \"0x60000001\"", "version = \"60000001\""),
        ] {
            assert!(good.contains(from), "{from}");
            let edited = good.replacen(from, to, 1);
            assert!(
                matches!(
                    ExportManifest::parse(&with_digest(&edited)),
                    Err(ExportManifestError::Invalid(_))
                ),
                "{to}"
            );
        }
        let not_utf8 = [b"export_sha256 = \"".as_slice(), &[0xff; 3]].concat();
        assert_eq!(
            ExportManifest::parse(&not_utf8),
            Err(ExportManifestError::Header)
        );
    }

    #[test]
    fn a_broken_parent_chain_is_refused() {
        let mut m = manifest();
        m.blocks[3].parent_root = B256::repeat_byte(0x11);
        refused(m, "block 4's parent is not block 2");

        let mut m = manifest();
        m.blocks[0].parent_root = B256::repeat_byte(1);
        refused(m, "genesis with a parent");

        let mut m = manifest();
        m.genesis_block_root = B256::repeat_byte(1);
        refused(m, "genesis root is not block 0's");
    }

    #[test]
    fn every_slot_is_a_block_or_empty_exactly_once() {
        let mut m = manifest();
        m.empty_slots = vec![];
        refused(m, "slot 3 is neither");

        let mut m = manifest();
        m.empty_slots = vec![2, 3];
        refused(m, "slot 2 is both");

        let mut m = manifest();
        m.empty_slots = vec![3, 6];
        refused(m, "slot 6 is past the end");

        let mut m = manifest();
        m.empty_slots = vec![3, 3];
        refused(m, "slot 3 twice");

        let mut m = manifest();
        m.blocks.swap(1, 2);
        refused(m, "blocks out of order");

        let mut m = manifest();
        m.blocks.remove(0);
        refused(m, "no genesis block");

        let mut m = manifest();
        m.slot_start = 1;
        refused(m, "not from genesis");

        let mut m = manifest();
        m.slot_end = 9;
        refused(m, "past finality");
    }

    #[test]
    fn contradictions_are_refused() {
        let mut m = manifest();
        m.devnet = "../etc".into();
        assert!(m.validate().is_err(), "devnet name");

        let mut m = manifest();
        m.source.clear();
        refused(m, "no source");

        let mut m = manifest();
        m.source = "a\nb".into();
        refused(m, "control character in source");

        let mut m = manifest();
        m.preset = "gnosis".into();
        refused(m, "preset");

        let mut m = manifest();
        m.images.clear();
        refused(m, "no images");

        let mut m = manifest();
        m.images.reverse();
        refused(m, "unsorted images");

        for bad in [
            "ethereum/client-go:v1.17.8".to_owned(),
            format!("@sha256:{}", "ab".repeat(32)),
            format!("geth@sha256:{}", "AB".repeat(32)),
            format!("geth@sha256:{}", "ab".repeat(31)),
            format!("ge th@sha256:{}", "ab".repeat(32)),
        ] {
            let mut m = manifest();
            m.images = vec![bad.clone()];
            refused(m, &bad);
        }

        let mut m = manifest();
        m.genesis_state.path = "../state.ssz".into();
        refused(m, "genesis state path");

        let mut m = manifest();
        m.fork_schedule.swap(0, 1);
        refused(m, "forks out of order");

        let mut m = manifest();
        m.fork_digests.clear();
        refused(m, "no digest");

        let mut m = manifest();
        m.fork_digests[0].epoch = 1;
        refused(m, "no digest at genesis");

        let mut m = manifest();
        m.fork_digests.push(m.fork_digests[0]);
        refused(m, "digests not ascending");

        let mut m = manifest();
        m.fork_digests.push(DigestEntry {
            epoch: 1,
            digest: [5; 4],
        });
        refused(m, "a digest past slot_end's epoch");

        let mut m = manifest();
        m.fork_schedule[0].epoch = 1;
        m.fork_schedule[1].epoch = 1;
        refused(m, "no fork at genesis");

        let mut m = manifest();
        m.fork_schedule.clear();
        refused(m, "no fork");

        let mut m = manifest();
        m.genesis_state.len = MAX_GENESIS_STATE_BYTES + 1;
        refused(m, "a genesis state over the bound");

        let mut m = manifest();
        m.segments.clear();
        refused(m, "no segment");

        let mut m = manifest();
        m.segments.push(m.segments[0].clone());
        refused(m, "segment twice");

        let mut m = manifest();
        m.segments[0].dir = "../x".into();
        refused(m, "segment dir");
    }
}
