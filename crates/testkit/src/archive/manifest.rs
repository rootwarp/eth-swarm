//! `manifest.toml`: what a segment holds and the sha256 of every file in it.
//!
//! The first line is `archive_sha256 = "<hex>"`, the sha256 of every byte after that line (the
//! body). The body is TOML: the capture fields, then one `[[digest_schedule]]` table per fork
//! digest in force over the slot range, then one `[[files]]` table per file, sorted by path.
//! Every file's sha256 is in the body, so the archive digest covers every payload, and a
//! changed byte anywhere in the manifest fails either the header, the digest or the parse.
//!
//! ```toml
//! archive_sha256 = "…"
//! format_version = 2
//! network = "hoodi"
//! preset = "mainnet"
//! slot_start = 4235263
//! slot_end = 4235295
//! fork_digests = ["0x…", "0x…"]
//! topics = ["beacon_block", "data_column_sidecar_3"]
//! peer_count = 48
//! capture_host = "hoodi-ref-1"
//! clock_source = "chrony"
//! closed_by = "roll"
//! total_bytes = 123456
//!
//! [[digest_schedule]]
//! epoch = 54016
//! digest = "0x…"
//!
//! [[digest_schedule]]
//! epoch = 132352
//! digest = "0x…"
//!
//! [[files]]
//! path = "beacon_block/4235264_0x….ssz_snappy"
//! topic = "beacon_block"
//! slot = 4235264
//! root = "0x…"
//! fork_digest = "0x…"
//! len = 81234
//! sha256 = "…"
//! ```
//!
//! The digest schedule lets a reader find the fork digest of any slot of the segment without
//! outside config. Each entry is a digest and the epoch where it starts, blob-parameter-only
//! (BPO) changes included. The epoch of a slot comes from the preset's `SLOTS_PER_EPOCH`. The
//! schedule holds the entry in force at `slot_start` and each entry that starts by
//! `slot_end`, and nothing else, so it is the same for every reader. `fork_digests` is the
//! sorted set of its digests, and each file's `fork_digest` must be the one of its slot. The
//! schedule has at most [`MAX_DIGEST_SCHEDULE`] entries.
//!
//! A network with an embedded config (`sepolia`, `hoodi`) must have the preset of that config.
//!
//! The values are the network's as the capture computed them. They are not recomputed from
//! the fork versions and the genesis validators root: from Fulu every digest mixes in the
//! blob parameters of its epoch, which the manifest does not carry. The archive digest covers
//! the schedule, so a pinned `archive_sha256` pins the schedule too.
//!
//! Format version 1 had no digest schedule. This crate refuses a version 1 manifest
//! ([`ManifestError::Version`]): capture the archive again.

use super::names::{file_path, validate_network, validate_topic, NameError, TopicKind};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use consensus_types::primitives::{Epoch, Root, Slot};
use consensus_types::{EthSpec, Mainnet, Minimal};
use network_config::{ChainConfig, Network};
use p2p_wire::rpc::codec::max_compressed_len;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// The manifest's file name in a segment.
pub const MANIFEST_FILE: &str = "manifest.toml";
/// The manifest format this crate writes and reads.
pub const FORMAT_VERSION: u32 = 2;
/// The presets a manifest may name.
pub const PRESETS: [&str; 2] = ["mainnet", "minimal"];
/// The largest manifest: the reader refuses a larger one, and the writer rolls a segment
/// before its manifest would pass it. Far above the ~250 bytes per file of a real segment.
pub const MAX_MANIFEST_LEN: u64 = 64 << 20;
/// The most entries a manifest's digest schedule may have. A real network has a few: one per
/// fork and per blob-parameter change. The bound keeps the checks of a hostile manifest short.
pub const MAX_DIGEST_SCHEDULE: usize = 64;
/// The longest `error` a manifest records; the writer cuts a longer one at a char boundary.
pub const MAX_ERROR_LEN: usize = 1024;
const HEADER_KEY: &str = "archive_sha256 = \"";
/// The header line: the key, 64 hex digits, the closing quote and the newline.
const HEADER_LINE_LEN: u64 = (HEADER_KEY.len() + 64 + 2) as u64;
/// What a file adds besides its own keys: the blank line and `[[files]]` before its table.
const FILE_TABLE_OVERHEAD: u64 = "\n[[files]]\n".len() as u64;

/// A sha256 digest.
pub type Sha256Digest = [u8; 32];
/// A 4-byte fork digest.
pub type ForkDigest = [u8; 4];

/// Why a segment was sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClosedBy {
    /// The capture moved past the segment's slot window (`slot_end` is the window's end), or
    /// the manifest reached its size limit (`slot_end` is the last slot stored).
    Roll,
    /// The capture closed.
    Close,
    /// The capture stopped on an error (`error` says which); later payloads are not in it.
    Error,
}

/// A fork digest and the first epoch it is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestEntry {
    /// The first epoch of the digest.
    pub epoch: Epoch,
    /// `compute_fork_digest(genesis_validators_root, epoch)`.
    pub digest: ForkDigest,
}

/// One archived payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFile {
    /// `<topic>/<slot>_0x<root>.ssz_snappy`, relative to the segment.
    pub path: String,
    /// The gossip topic name, without fork digest and encoding.
    pub topic: String,
    /// The object's slot.
    pub slot: Slot,
    /// The block root: of the block, or of the sidecar's block.
    pub root: Root,
    /// The fork digest of the topic it arrived on.
    pub fork_digest: ForkDigest,
    /// The file length: the snappy-compressed payload as received.
    pub len: u64,
    /// sha256 of the file.
    pub sha256: Sha256Digest,
}

/// A segment's manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The network name (the archive's parent directory).
    pub network: String,
    /// The preset the payloads were decoded with.
    pub preset: String,
    /// The first slot the segment covers.
    pub slot_start: Slot,
    /// The last slot the segment covers.
    pub slot_end: Slot,
    /// Every fork digest in force over the slot range: the digests of `digest_schedule`,
    /// sorted and unique. Each file arrived on one of them.
    pub fork_digests: Vec<ForkDigest>,
    /// The network's fork digests over the slot range, ascending by epoch: the entry in force
    /// at `slot_start`, then each entry that starts by `slot_end`, BPO entries included.
    pub digest_schedule: Vec<DigestEntry>,
    /// The topics the capture subscribed to, sorted; subnets are in the topic names.
    pub topics: Vec<String>,
    /// The capture's peer count when the segment was sealed.
    pub peer_count: u32,
    /// The host that captured.
    pub capture_host: String,
    /// The clock the capture host kept time with (e.g. `chrony`).
    pub clock_source: String,
    /// Why the segment was sealed.
    pub closed_by: ClosedBy,
    /// The error that stopped the capture, with [`ClosedBy::Error`].
    pub error: Option<String>,
    /// The sum of every file's length.
    pub total_bytes: u64,
    /// The files, sorted by path.
    pub files: Vec<ArchiveFile>,
}

/// A manifest that cannot be read or does not hold together.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// The first line is not `archive_sha256 = "<64 lowercase hex>"`.
    #[error("first line must be archive_sha256 = \"<64 lowercase hex>\"")]
    Header,
    /// The body does not hash to `archive_sha256`.
    #[error("archive sha256 mismatch: manifest says {recorded}, body hashes to {computed}")]
    DigestMismatch {
        /// The header's digest.
        recorded: String,
        /// The body's digest.
        computed: String,
    },
    /// The body is not the manifest TOML.
    #[error("toml: {0}")]
    Toml(String),
    /// A version this crate does not read.
    #[error("format_version {0}, expected {FORMAT_VERSION}")]
    Version(u32),
    /// A file's fork digest is not the one `digest_schedule` gives for its slot.
    #[error(
        "{path}: fork digest 0x{} is not the schedule's for slot {slot} ({})",
        hex::encode(got),
        expected.map_or_else(|| "none".to_owned(), |d| format!("0x{}", hex::encode(d)))
    )]
    ForkDigest {
        /// The file's path in the segment.
        path: String,
        /// The file's slot.
        slot: Slot,
        /// The schedule's digest for the slot (`None` if the schedule has none).
        expected: Option<ForkDigest>,
        /// The file's digest.
        got: ForkDigest,
    },
    /// A network or topic name that cannot be a path component.
    #[error(transparent)]
    Name(#[from] NameError),
    /// The fields contradict each other.
    #[error("{0}")]
    Invalid(String),
}

impl Manifest {
    /// The epoch of `slot` by the preset's `SLOTS_PER_EPOCH` (`None` for an unknown preset).
    pub fn epoch_at(&self, slot: Slot) -> Option<Epoch> {
        slots_per_epoch(&self.preset).map(|n| slot / n)
    }

    /// The fork digest `digest_schedule` gives for `slot`: the one of the last entry that
    /// starts at or before the slot's epoch. `None` before the first entry or for an unknown
    /// preset. The schedule must ascend by epoch, as a validated one does.
    pub fn digest_at(&self, slot: Slot) -> Option<ForkDigest> {
        digest_in_force(&self.digest_schedule, self.epoch_at(slot)?)
    }

    /// Checks that the fields hold together: valid names, a known preset, `slot_start <=
    /// slot_end`, sorted unique topics the archive supports, at least one file, files sorted
    /// by path and unique, each at the path its topic, slot and root give, on a subscribed
    /// topic, inside the slot range, within the gossip size bound and on the fork digest of
    /// its slot; a digest schedule that covers the slot range exactly
    /// ([`Manifest::validate_schedule`]), `fork_digests` the sorted set of its digests,
    /// `total_bytes` the sum of the file lengths, and `error` set exactly when `closed_by` is
    /// `error`.
    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_network(&self.network)?;
        if !PRESETS.contains(&self.preset.as_str()) {
            return invalid(format!("unknown preset {:?}", self.preset));
        }
        check_network_preset(&self.network, &self.preset).map_err(ManifestError::Invalid)?;
        if self.slot_start > self.slot_end {
            return invalid(format!(
                "slot_start {} is after slot_end {}",
                self.slot_start, self.slot_end
            ));
        }
        if self.capture_host.is_empty() || self.clock_source.is_empty() {
            return invalid("capture_host and clock_source must not be empty".into());
        }
        if (self.closed_by == ClosedBy::Error) != self.error.is_some() {
            return invalid("error is set exactly when closed_by is \"error\"".into());
        }
        self.validate_schedule()?;
        for topic in &self.topics {
            validate_topic(topic)?;
            TopicKind::of(topic)?;
        }
        if !strictly_sorted(&self.topics) {
            return invalid("topics must be sorted and unique".into());
        }
        if self.files.is_empty() {
            return invalid("a segment holds at least one file".into());
        }
        if !strictly_sorted(self.files.iter().map(|f| &f.path)) {
            return invalid("files must be sorted by path and unique".into());
        }
        let max_len = max_compressed_len(MAX_PAYLOAD_SIZE) as u64;
        let mut total: u64 = 0;
        for f in &self.files {
            if self.topics.binary_search(&f.topic).is_err() {
                return invalid(format!("{}: topic {:?} is not subscribed", f.path, f.topic));
            }
            if f.path != file_path(&f.topic, f.slot, &f.root) {
                return invalid(format!(
                    "{}: path does not match topic, slot and root",
                    f.path
                ));
            }
            if !(self.slot_start..=self.slot_end).contains(&f.slot) {
                return invalid(format!("{}: slot outside the segment", f.path));
            }
            if f.len > max_len {
                return invalid(format!("{}: {} bytes, over {max_len}", f.path, f.len));
            }
            let expected = self.digest_at(f.slot);
            if expected != Some(f.fork_digest) {
                return Err(ManifestError::ForkDigest {
                    path: f.path.clone(),
                    slot: f.slot,
                    expected,
                    got: f.fork_digest,
                });
            }
            total = total.saturating_add(f.len);
        }
        if self.total_bytes != total {
            return invalid(format!(
                "total_bytes {} but the files hold {total}",
                self.total_bytes
            ));
        }
        Ok(())
    }

    /// Checks that `digest_schedule` covers the slot range exactly: at most
    /// [`MAX_DIGEST_SCHEDULE`] entries, not empty, strictly
    /// ascending by epoch, its first entry in force at `slot_start` (it starts at or before
    /// that epoch, and the next one starts after it), and no entry that starts after
    /// `slot_end`'s epoch. Also checks that `fork_digests` is the sorted set of its digests.
    /// Needs a known preset.
    fn validate_schedule(&self) -> Result<(), ManifestError> {
        let (Some(start), Some(end)) =
            (self.epoch_at(self.slot_start), self.epoch_at(self.slot_end))
        else {
            return invalid(format!("unknown preset {:?}", self.preset));
        };
        let schedule = &self.digest_schedule;
        if schedule.len() > MAX_DIGEST_SCHEDULE {
            return invalid(format!(
                "digest_schedule has {} entries, over {MAX_DIGEST_SCHEDULE} entries",
                schedule.len()
            ));
        }
        let Some(first) = schedule.first() else {
            return invalid("digest_schedule is empty".into());
        };
        if !strictly_sorted(schedule.iter().map(|d| &d.epoch)) {
            return invalid("digest_schedule must ascend strictly by epoch".into());
        }
        if first.epoch > start {
            return invalid(format!(
                "digest_schedule starts at epoch {}, after slot_start's epoch {start}",
                first.epoch
            ));
        }
        if let Some(next) = schedule.get(1).filter(|d| d.epoch <= start) {
            return invalid(format!(
                "digest_schedule entry of epoch {} is superseded at epoch {}, by slot_start's \
                 epoch {start}",
                first.epoch, next.epoch
            ));
        }
        if let Some(late) = schedule.iter().find(|d| d.epoch > end) {
            return invalid(format!(
                "digest_schedule entry of epoch {} starts after slot_end's epoch {end}",
                late.epoch
            ));
        }
        let digests: BTreeSet<ForkDigest> = schedule.iter().map(|d| d.digest).collect();
        if self.fork_digests != digests.into_iter().collect::<Vec<_>>() {
            return invalid("fork_digests must be the sorted digests of digest_schedule".into());
        }
        Ok(())
    }

    /// The manifest bytes and the archive sha256 (the digest of the body), after
    /// [validating](Manifest::validate).
    pub fn render(&self) -> Result<(Vec<u8>, Sha256Digest), ManifestError> {
        self.validate()?;
        let body = toml::to_string(&RawManifest::from(self))
            .map_err(|e| ManifestError::Toml(e.to_string()))?;
        let digest: Sha256Digest = Sha256::digest(body.as_bytes()).into();
        let mut out = format!("{HEADER_KEY}{}\"\n", hex::encode(digest)).into_bytes();
        out.extend_from_slice(body.as_bytes());
        Ok((out, digest))
    }

    /// Parses manifest bytes, checking the header digest first and then every field
    /// ([`Manifest::validate`]). Returns the manifest and its archive sha256.
    pub fn parse(bytes: &[u8]) -> Result<(Self, Sha256Digest), ManifestError> {
        let newline = bytes.iter().position(|&b| b == b'\n');
        let (header, body) = newline
            .map(|at| (&bytes[..at], &bytes[at + 1..]))
            .ok_or(ManifestError::Header)?;
        let recorded = std::str::from_utf8(header)
            .ok()
            .and_then(|h| h.strip_prefix(HEADER_KEY)?.strip_suffix('"'))
            .and_then(canonical_hex::<32>)
            .ok_or(ManifestError::Header)?;
        let computed: Sha256Digest = Sha256::digest(body).into();
        if computed != recorded {
            return Err(ManifestError::DigestMismatch {
                recorded: hex::encode(recorded),
                computed: hex::encode(computed),
            });
        }
        let body = std::str::from_utf8(body).map_err(|e| ManifestError::Toml(e.to_string()))?;
        // The version first: an older manifest has other fields, and must fail as a version.
        let version: RawVersion =
            toml::from_str(body).map_err(|e| ManifestError::Toml(e.to_string()))?;
        if version.format_version != FORMAT_VERSION {
            return Err(ManifestError::Version(version.format_version));
        }
        let raw: RawManifest =
            toml::from_str(body).map_err(|e| ManifestError::Toml(e.to_string()))?;
        let manifest = Manifest::try_from(raw)?;
        manifest.validate()?;
        Ok((manifest, computed))
    }
}

/// A `network` with an embedded config must have that config's `PRESET_BASE` as `preset`.
/// Any other network name can have any preset.
pub(crate) fn check_network_preset(network: &str, preset: &str) -> Result<(), String> {
    let Some(known) = Network::ALL.into_iter().find(|n| n.name() == network) else {
        return Ok(());
    };
    let config = ChainConfig::load(known).map_err(|e| format!("{network} config: {e}"))?;
    if config.preset_base() != preset {
        return Err(format!(
            "{network}'s preset is {}, not {preset:?}",
            config.preset_base()
        ));
    }
    Ok(())
}

/// `SLOTS_PER_EPOCH` of a preset in [`PRESETS`].
pub(crate) fn slots_per_epoch(preset: &str) -> Option<u64> {
    match preset {
        p if p == Mainnet::NAME => Some(Mainnet::slots_per_epoch()),
        p if p == Minimal::NAME => Some(Minimal::slots_per_epoch()),
        _ => None,
    }
}

/// One entry of a digest schedule: a fork digest and the epoch where it starts. The capture
/// config holds `(epoch, digest)` pairs, a manifest [`DigestEntry`] values.
pub(crate) trait ScheduleEntry {
    /// The first epoch of the digest.
    fn epoch(&self) -> Epoch;
    /// The digest.
    fn digest(&self) -> ForkDigest;
}

impl ScheduleEntry for DigestEntry {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
    fn digest(&self) -> ForkDigest {
        self.digest
    }
}

impl ScheduleEntry for (Epoch, ForkDigest) {
    fn epoch(&self) -> Epoch {
        self.0
    }
    fn digest(&self) -> ForkDigest {
        self.1
    }
}

/// The digest of `schedule` (ascending by epoch) in force at `epoch`, `None` before its first,
/// found by binary search.
pub(crate) fn digest_in_force<T: ScheduleEntry>(
    schedule: &[T],
    epoch: Epoch,
) -> Option<ForkDigest> {
    let after = schedule.partition_point(|d| d.epoch() <= epoch);
    after.checked_sub(1).map(|at| schedule[at].digest())
}

/// The entries of a network's digest schedule (ascending by epoch) that a manifest over the
/// epochs `start..=end` records: the entry in force at `start`, then each entry that starts by
/// `end`.
pub(crate) fn schedule_over<T: ScheduleEntry>(
    schedule: &[T],
    start: Epoch,
    end: Epoch,
) -> Vec<DigestEntry> {
    let first = schedule
        .partition_point(|d| d.epoch() <= start)
        .checked_sub(1);
    schedule
        .iter()
        .enumerate()
        .filter(|(at, d)| Some(*at) == first || (d.epoch() > start && d.epoch() <= end))
        .map(|(_, d)| DigestEntry {
            epoch: d.epoch(),
            digest: d.digest(),
        })
        .collect()
}

/// `error` cut to at most [`MAX_ERROR_LEN`] bytes, at a char boundary.
pub(crate) fn truncate_error(error: &str) -> String {
    let mut end = error.len().min(MAX_ERROR_LEN);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_owned()
}

/// An upper bound on the length of a manifest with these capture fields and no files: the
/// header line and the body with every other field at its longest (the largest slots, peer
/// count and total, the longer `closed_by`, an error of [`MAX_ERROR_LEN`] bytes that each
/// escape to six, every entry of the network's digest `schedule` at the largest epoch and
/// each of its digests in `fork_digests`). Add [`file_len_bound`] per file.
pub(crate) fn base_len_bound(
    network: &str,
    topics: &[String],
    capture_host: &str,
    clock_source: &str,
    schedule: &[(Epoch, ForkDigest)],
) -> u64 {
    let largest = i64::MAX as u64;
    let hex_digest = |d: &ForkDigest| format!("0x{}", hex::encode(d));
    let raw = RawManifest {
        format_version: FORMAT_VERSION,
        network: network.to_owned(),
        preset: PRESETS
            .iter()
            .max_by_key(|p| p.len())
            .copied()
            .unwrap_or_default()
            .to_owned(),
        slot_start: largest,
        slot_end: largest,
        fork_digests: schedule.iter().map(|(_, d)| hex_digest(d)).collect(),
        topics: topics.to_vec(),
        peer_count: u32::MAX,
        capture_host: capture_host.to_owned(),
        clock_source: clock_source.to_owned(),
        closed_by: ClosedBy::Error,
        error: Some("\u{7}".repeat(MAX_ERROR_LEN)),
        total_bytes: largest,
        digest_schedule: schedule
            .iter()
            .map(|(_, d)| RawDigest {
                epoch: largest,
                digest: hex_digest(d),
            })
            .collect(),
        files: Vec::new(),
    };
    toml::to_string(&raw).map_or(u64::MAX, |body| HEADER_LINE_LEN + body.len() as u64)
}

/// An upper bound on what `file` adds to a manifest: its `[[files]]` table and its digest.
pub(crate) fn file_len_bound(file: &ArchiveFile) -> u64 {
    toml::to_string(&RawFile::from(file))
        .map_or(u64::MAX, |table| table.len() as u64 + FILE_TABLE_OVERHEAD)
}

fn invalid<T>(message: String) -> Result<T, ManifestError> {
    Err(ManifestError::Invalid(message))
}

fn strictly_sorted<'a, T: Ord + 'a>(items: impl IntoIterator<Item = &'a T>) -> bool {
    let mut it = items.into_iter().peekable();
    while let Some(a) = it.next() {
        if it.peek().is_some_and(|b| a >= *b) {
            return false;
        }
    }
    true
}

/// `N` bytes from exactly `2 * N` lowercase hex digits.
pub(crate) fn canonical_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let lower = text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut out = [0u8; N];
    (lower && hex::decode_to_slice(text, &mut out).is_ok()).then_some(out)
}

/// `0x` and `2 * N` lowercase hex digits, as the Beacon API writes roots.
fn prefixed_hex<const N: usize>(field: &str, text: &str) -> Result<[u8; N], ManifestError> {
    text.strip_prefix("0x")
        .and_then(canonical_hex::<N>)
        .ok_or_else(|| {
            ManifestError::Invalid(format!(
                "{field} {text:?} is not 0x and {} lowercase hex digits",
                2 * N
            ))
        })
}

fn plain_hex<const N: usize>(field: &str, text: &str) -> Result<[u8; N], ManifestError> {
    canonical_hex::<N>(text).ok_or_else(|| {
        ManifestError::Invalid(format!(
            "{field} {text:?} is not {} lowercase hex digits",
            2 * N
        ))
    })
}

/// The TOML shape of [`Manifest`]: digests and roots as hex strings.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    format_version: u32,
    network: String,
    preset: String,
    slot_start: u64,
    slot_end: u64,
    fork_digests: Vec<String>,
    topics: Vec<String>,
    peer_count: u32,
    capture_host: String,
    clock_source: String,
    closed_by: ClosedBy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    total_bytes: u64,
    digest_schedule: Vec<RawDigest>,
    files: Vec<RawFile>,
}

/// The `format_version` of any manifest, read before the rest.
#[derive(Deserialize)]
struct RawVersion {
    format_version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDigest {
    epoch: u64,
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    path: String,
    topic: String,
    slot: u64,
    root: String,
    fork_digest: String,
    len: u64,
    sha256: String,
}

impl From<&Manifest> for RawManifest {
    fn from(m: &Manifest) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            network: m.network.clone(),
            preset: m.preset.clone(),
            slot_start: m.slot_start,
            slot_end: m.slot_end,
            fork_digests: m
                .fork_digests
                .iter()
                .map(|d| format!("0x{}", hex::encode(d)))
                .collect(),
            topics: m.topics.clone(),
            peer_count: m.peer_count,
            capture_host: m.capture_host.clone(),
            clock_source: m.clock_source.clone(),
            closed_by: m.closed_by,
            error: m.error.clone(),
            total_bytes: m.total_bytes,
            digest_schedule: m
                .digest_schedule
                .iter()
                .map(|d| RawDigest {
                    epoch: d.epoch,
                    digest: format!("0x{}", hex::encode(d.digest)),
                })
                .collect(),
            files: m.files.iter().map(RawFile::from).collect(),
        }
    }
}

impl From<&ArchiveFile> for RawFile {
    fn from(f: &ArchiveFile) -> Self {
        Self {
            path: f.path.clone(),
            topic: f.topic.clone(),
            slot: f.slot,
            root: format!("0x{}", hex::encode(f.root)),
            fork_digest: format!("0x{}", hex::encode(f.fork_digest)),
            len: f.len,
            sha256: hex::encode(f.sha256),
        }
    }
}

impl TryFrom<RawManifest> for Manifest {
    type Error = ManifestError;

    fn try_from(raw: RawManifest) -> Result<Self, ManifestError> {
        if raw.format_version != FORMAT_VERSION {
            return Err(ManifestError::Version(raw.format_version));
        }
        let fork_digests = raw
            .fork_digests
            .iter()
            .map(|d| prefixed_hex::<4>("fork digest", d))
            .collect::<Result<_, _>>()?;
        let digest_schedule = raw
            .digest_schedule
            .iter()
            .map(|d| {
                Ok(DigestEntry {
                    epoch: d.epoch,
                    digest: prefixed_hex::<4>("digest_schedule digest", &d.digest)?,
                })
            })
            .collect::<Result<_, ManifestError>>()?;
        let files = raw
            .files
            .into_iter()
            .map(|f| {
                Ok(ArchiveFile {
                    root: Root::from(prefixed_hex::<32>("root", &f.root)?),
                    fork_digest: prefixed_hex::<4>("fork_digest", &f.fork_digest)?,
                    sha256: plain_hex::<32>("sha256", &f.sha256)?,
                    path: f.path,
                    topic: f.topic,
                    slot: f.slot,
                    len: f.len,
                })
            })
            .collect::<Result<_, ManifestError>>()?;
        Ok(Self {
            network: raw.network,
            preset: raw.preset,
            slot_start: raw.slot_start,
            slot_end: raw.slot_end,
            fork_digests,
            digest_schedule,
            topics: raw.topics,
            peer_count: raw.peer_count,
            capture_host: raw.capture_host,
            clock_source: raw.clock_source,
            closed_by: raw.closed_by,
            error: raw.error,
            total_bytes: raw.total_bytes,
            files,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use consensus_types::primitives::B256;

    pub(crate) fn file(topic: &str, slot: Slot, root: u8, digest: ForkDigest) -> ArchiveFile {
        let root = B256::repeat_byte(root);
        ArchiveFile {
            path: file_path(topic, slot, &root),
            topic: topic.into(),
            slot,
            root,
            fork_digest: digest,
            len: 100 + slot,
            sha256: [slot as u8; 32],
        }
    }

    /// The digest from epoch 1 of [`manifest`].
    const PRE: ForkDigest = [1, 2, 3, 4];
    /// The digest from epoch 2 of [`manifest`].
    const POST: ForkDigest = [1, 2, 3, 5];

    /// A Minimal-preset segment over epochs 1 and 2 (slots 8 to 23), across a digest change
    /// at epoch 2 (slot 16).
    pub(crate) fn manifest() -> Manifest {
        let files = vec![
            file("beacon_block", 10, 1, PRE),
            file("beacon_block", 17, 2, POST),
            file("data_column_sidecar_3", 10, 1, PRE),
        ];
        Manifest {
            network: "devnet".into(),
            preset: "minimal".into(),
            slot_start: 8,
            slot_end: 23,
            fork_digests: vec![PRE, POST],
            digest_schedule: vec![
                DigestEntry {
                    epoch: 1,
                    digest: PRE,
                },
                DigestEntry {
                    epoch: 2,
                    digest: POST,
                },
            ],
            topics: vec!["beacon_block".into(), "data_column_sidecar_3".into()],
            peer_count: 48,
            capture_host: "hoodi-ref-1".into(),
            clock_source: "chrony".into(),
            closed_by: ClosedBy::Roll,
            error: None,
            total_bytes: files.iter().map(|f| f.len).sum(),
            files,
        }
    }

    fn with_digest(body: &str) -> Vec<u8> {
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        format!("archive_sha256 = \"{digest}\"\n{body}").into_bytes()
    }

    fn body(m: &Manifest) -> String {
        let (bytes, _) = m.render().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        text.split_once('\n').unwrap().1.to_owned()
    }

    fn invalid(m: Manifest) -> ManifestError {
        let err = m.validate().unwrap_err();
        assert_eq!(m.render().unwrap_err(), err, "render validates");
        err
    }

    #[test]
    fn render_parse_round_trip() {
        let m = manifest();
        let (bytes, digest) = m.render().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let (header, body) = text.split_once('\n').unwrap();
        assert_eq!(
            header,
            format!("archive_sha256 = \"{}\"", hex::encode(digest))
        );
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(body.as_bytes())));
        for field in [
            "network = \"devnet\"",
            "peer_count = 48",
            "clock_source = \"chrony\"",
        ] {
            assert!(body.contains(field), "{field} in\n{body}");
        }
        assert_eq!(Manifest::parse(&bytes).unwrap(), (m, digest));
    }

    fn bound(m: &Manifest) -> u64 {
        let schedule: Vec<_> = m
            .digest_schedule
            .iter()
            .map(|d| (d.epoch, d.digest))
            .collect();
        base_len_bound(
            &m.network,
            &m.topics,
            &m.capture_host,
            &m.clock_source,
            &schedule,
        ) + m.files.iter().map(file_len_bound).sum::<u64>()
    }

    #[test]
    fn the_length_bound_holds_at_the_extremes() {
        let mut m = manifest();
        assert!(m.render().unwrap().0.len() as u64 <= bound(&m));

        // Every field at its longest: a full error of control characters (each escaped to six
        // bytes), the largest slots, peer count and total, a digest per file, each in its own
        // epoch of the schedule.
        m.closed_by = ClosedBy::Error;
        m.error = Some(truncate_error(&"\u{7}".repeat(MAX_ERROR_LEN + 10)));
        m.peer_count = u32::MAX;
        m.capture_host = "\"".repeat(40);
        let top = i64::MAX as u64;
        let slot = |i: u8| top - 8 * u64::from(19 - i);
        m.files = (0..20u8)
            .map(|i| {
                let mut f = file("data_column_sidecar_127", slot(i), i, [i; 4]);
                f.len = max_compressed_len(MAX_PAYLOAD_SIZE) as u64;
                f
            })
            .collect();
        m.files.sort_by(|a, b| a.path.cmp(&b.path));
        m.topics = vec!["data_column_sidecar_127".into()];
        m.fork_digests = (0..20u8).map(|i| [i; 4]).collect();
        m.digest_schedule = (0..20u8)
            .map(|i| DigestEntry {
                epoch: slot(i) / 8,
                digest: [i; 4],
            })
            .collect();
        m.slot_start = slot(0);
        m.slot_end = top;
        m.total_bytes = m.files.iter().map(|f| f.len).sum();
        let rendered = m.render().unwrap().0.len() as u64;
        assert!(rendered <= bound(&m), "{rendered} > {}", bound(&m));
        assert!(bound(&m) - rendered < 1024, "the bound stays close");
    }

    #[test]
    fn a_long_error_is_cut_at_a_char_boundary() {
        assert_eq!(truncate_error("short"), "short");
        let long = "é".repeat(MAX_ERROR_LEN);
        let cut = truncate_error(&long);
        assert!(cut.len() <= MAX_ERROR_LEN && cut.len() > MAX_ERROR_LEN - 2);
        assert!(long.starts_with(&cut));
    }

    #[test]
    fn every_flipped_byte_is_refused() {
        let (bytes, _) = manifest().render().unwrap();
        for at in 0..bytes.len() {
            for bit in [0x01, 0x20, 0x80] {
                let mut flipped = bytes.clone();
                flipped[at] ^= bit;
                assert!(
                    Manifest::parse(&flipped).is_err(),
                    "byte {at} ^ {bit:#x} accepted"
                );
            }
        }
        assert!(
            Manifest::parse(&bytes[..bytes.len() - 1]).is_err(),
            "truncated"
        );
        let mut appended = bytes.clone();
        appended.extend_from_slice(b"\n");
        assert!(Manifest::parse(&appended).is_err(), "appended");
    }

    #[test]
    fn header_and_digest() {
        assert_eq!(Manifest::parse(b""), Err(ManifestError::Header));
        assert_eq!(
            Manifest::parse(b"network = \"x\"\n"),
            Err(ManifestError::Header)
        );
        let upper = format!("archive_sha256 = \"{}\"\n", "AB".repeat(32));
        assert_eq!(
            Manifest::parse(upper.as_bytes()),
            Err(ManifestError::Header)
        );
        let (mut bytes, _) = manifest().render().unwrap();
        bytes[HEADER_KEY.len()] = if bytes[HEADER_KEY.len()] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert!(matches!(
            Manifest::parse(&bytes),
            Err(ManifestError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn a_rehashed_body_must_still_parse_and_hold_together() {
        let good = body(&manifest());
        let unknown = format!("extra = 1\n{good}");
        assert!(matches!(
            Manifest::parse(&with_digest(&unknown)),
            Err(ManifestError::Toml(_))
        ));
        let v3 = good.replace("format_version = 2", "format_version = 3");
        assert_eq!(
            Manifest::parse(&with_digest(&v3)),
            Err(ManifestError::Version(3))
        );
        let upper_root = good.replacen("0x0101", "0xABAB", 1);
        assert!(matches!(
            Manifest::parse(&with_digest(&upper_root)),
            Err(ManifestError::Invalid(_))
        ));
        let short_digest = good.replacen("\"0x01020304\"", "\"0x010203\"", 1);
        assert!(matches!(
            Manifest::parse(&with_digest(&short_digest)),
            Err(ManifestError::Invalid(_))
        ));
        let negative = good.replace("slot_start = 8", "slot_start = -8");
        assert!(matches!(
            Manifest::parse(&with_digest(&negative)),
            Err(ManifestError::Toml(_))
        ));
        let not_utf8 = [b"archive_sha256 = \"".as_slice(), &[0xff; 3]].concat();
        assert_eq!(Manifest::parse(&not_utf8), Err(ManifestError::Header));
    }

    #[test]
    fn contradictions_are_refused() {
        let mut m = manifest();
        m.network = "../etc".into();
        assert!(matches!(invalid(m), ManifestError::Name(_)));

        let mut m = manifest();
        m.preset = "gnosis".into();
        assert!(matches!(invalid(m), ManifestError::Invalid(_)));

        let mut m = manifest();
        m.slot_start = 16;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "start after end"
        );

        let mut m = manifest();
        m.slot_end = 16;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(e) if e.contains("slot outside")),
            "file past the end"
        );

        let mut m = manifest();
        m.topics.reverse();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "unsorted topics"
        );

        let mut m = manifest();
        m.topics = vec!["beacon_block".into()];
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "unsubscribed file"
        );

        let mut m = manifest();
        m.topics.push("voluntary_exit".into());
        assert!(
            matches!(invalid(m), ManifestError::Name(_)),
            "unsupported topic"
        );

        let mut m = manifest();
        m.files.swap(0, 1);
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "unsorted files"
        );

        let mut m = manifest();
        m.files.push(m.files[0].clone());
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "duplicate file"
        );

        let mut m = manifest();
        m.files.clear();
        m.total_bytes = 0;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(e) if e.contains("at least one file")),
            "no files"
        );

        let mut m = manifest();
        m.files[0].path = "beacon_block/../../x".into();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "path not derived"
        );

        let mut m = manifest();
        m.files[0].len = max_compressed_len(MAX_PAYLOAD_SIZE) as u64 + 1;
        m.total_bytes = m.files.iter().map(|f| f.len).sum();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "oversized file"
        );

        let mut m = manifest();
        m.total_bytes += 1;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "total bytes"
        );

        let mut m = manifest();
        m.closed_by = ClosedBy::Error;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "error without reason"
        );

        let mut m = manifest();
        m.error = Some("disk full".into());
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "reason without error"
        );

        let mut m = manifest();
        m.capture_host.clear();
        assert!(matches!(invalid(m), ManifestError::Invalid(_)), "no host");

        let mut m = manifest();
        m.clock_source.clear();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "no clock source"
        );

        let mut m = manifest();
        m.closed_by = ClosedBy::Error;
        m.error = Some("disk full".into());
        assert_eq!(m.validate(), Ok(()));
        let (bytes, _) = m.render().unwrap();
        assert_eq!(Manifest::parse(&bytes).unwrap().0, m);
    }

    fn schedule_error(m: Manifest, says: &str) {
        let e = invalid(m);
        assert!(
            matches!(&e, ManifestError::Invalid(m) if m.contains(says)),
            "{says}: {e}"
        );
    }

    #[test]
    fn the_digest_schedule_must_cover_the_slot_range_exactly() {
        let mut m = manifest();
        m.digest_schedule.clear();
        schedule_error(m, "digest_schedule is empty");

        let mut m = manifest();
        m.digest_schedule.reverse();
        schedule_error(m, "ascend strictly");

        let mut m = manifest();
        m.digest_schedule[1].epoch = 1;
        schedule_error(m, "ascend strictly");

        // Starts after slot_start: slot 8 has no digest.
        let mut m = manifest();
        m.digest_schedule[0].epoch = 2;
        m.digest_schedule.pop();
        m.fork_digests = vec![PRE];
        schedule_error(m, "after slot_start's epoch 1");

        // An entry no slot of the range is in.
        let mut m = manifest();
        m.digest_schedule.insert(
            0,
            DigestEntry {
                epoch: 0,
                digest: [9; 4],
            },
        );
        m.fork_digests.insert(0, [9; 4]);
        schedule_error(m, "superseded");

        let mut m = manifest();
        m.digest_schedule.push(DigestEntry {
            epoch: 3,
            digest: [9; 4],
        });
        m.fork_digests.push([9; 4]);
        schedule_error(m, "after slot_end's epoch 2");

        // A preset whose epochs this crate does not know.
        let mut m = manifest();
        m.preset = "gnosis".into();
        assert!(
            matches!(m.validate_schedule(), Err(ManifestError::Invalid(e)) if e.contains("preset"))
        );
        assert_eq!((m.epoch_at(16), m.digest_at(16)), (None, None));
    }

    #[test]
    fn fork_digests_must_be_the_schedules() {
        for fork_digests in [vec![PRE], vec![POST, PRE], vec![PRE, POST, [9; 4]], vec![]] {
            let mut m = manifest();
            m.fork_digests = fork_digests;
            schedule_error(m, "sorted digests of digest_schedule");
        }
    }

    #[test]
    fn a_file_on_another_digest_than_its_slots_is_refused() {
        let m = manifest();
        assert_eq!(
            [7, 8, 15, 16, 23].map(|slot| m.digest_at(slot)),
            [None, Some(PRE), Some(PRE), Some(POST), Some(POST)],
            "none before the schedule's first epoch"
        );
        for (at, wrong, right) in [(0, POST, PRE), (1, PRE, POST), (2, [9; 4], PRE)] {
            let mut m = manifest();
            m.files[at].fork_digest = wrong;
            let (path, slot) = (m.files[at].path.clone(), m.files[at].slot);
            assert_eq!(
                invalid(m),
                ManifestError::ForkDigest {
                    path,
                    slot,
                    expected: Some(right),
                    got: wrong,
                }
            );
        }
        // Through parse, as open_verified reads it.
        let good = body(&manifest());
        let forged = good.replacen(
            "fork_digest = \"0x01020305\"",
            "fork_digest = \"0x01020304\"",
            1,
        );
        assert_ne!(forged, good);
        assert!(matches!(
            Manifest::parse(&with_digest(&forged)),
            Err(ManifestError::ForkDigest { slot: 17, .. })
        ));
        let e = ManifestError::ForkDigest {
            path: "p".into(),
            slot: 3,
            expected: None,
            got: [1, 2, 3, 4],
        };
        assert_eq!(
            e.to_string(),
            "p: fork digest 0x01020304 is not the schedule's for slot 3 (none)"
        );
    }

    #[test]
    fn a_version_1_manifest_is_refused_as_a_version() {
        // The format before the digest schedule.
        let v1 = r#"format_version = 1
network = "hoodi"
preset = "mainnet"
slot_start = 8
slot_end = 15
fork_digests = ["0x01020304"]
topics = ["beacon_block"]
peer_count = 48
capture_host = "hoodi-ref-1"
clock_source = "chrony"
closed_by = "roll"
total_bytes = 110

[[files]]
path = "beacon_block/10_0x0101010101010101010101010101010101010101010101010101010101010101.ssz_snappy"
topic = "beacon_block"
slot = 10
root = "0x0101010101010101010101010101010101010101010101010101010101010101"
fork_digest = "0x01020304"
len = 110
sha256 = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
"#;
        assert_eq!(
            Manifest::parse(&with_digest(v1)),
            Err(ManifestError::Version(1))
        );
        let no_version = v1.replacen("format_version = 1\n", "", 1);
        assert!(matches!(
            Manifest::parse(&with_digest(&no_version)),
            Err(ManifestError::Toml(_))
        ));
        // A schedule entry with a malformed digest.
        let good = body(&manifest());
        let short = good.replacen("digest = \"0x01020305\"", "digest = \"0x010203\"", 1);
        assert_ne!(short, good);
        assert!(matches!(
            Manifest::parse(&with_digest(&short)),
            Err(ManifestError::Invalid(e)) if e.contains("digest_schedule")
        ));
    }

    #[test]
    fn schedule_over_keeps_the_entry_in_force_and_those_that_start_by_the_end() {
        let net = [(10, [1; 4]), (20, [2; 4]), (30, [3; 4]), (40, [4; 4])];
        let epochs = |v: Vec<DigestEntry>| v.iter().map(|d| d.epoch).collect::<Vec<_>>();
        assert_eq!(epochs(schedule_over(&net, 25, 25)), [20]);
        assert_eq!(epochs(schedule_over(&net, 20, 30)), [20, 30]);
        assert_eq!(epochs(schedule_over(&net, 19, 41)), [10, 20, 30, 40]);
        assert_eq!(epochs(schedule_over(&net, 45, 50)), [40]);
        // Before the first entry: no entry in force, which validation refuses.
        assert_eq!(epochs(schedule_over(&net, 5, 20)), [10, 20]);
        assert_eq!(epochs(schedule_over(&net, 5, 9)), Vec::<u64>::new());
        assert_eq!(slots_per_epoch("mainnet"), Some(32));
        assert_eq!(slots_per_epoch("minimal"), Some(8));
        assert_eq!(slots_per_epoch("gnosis"), None);
    }

    /// [`manifest`] with a schedule of `n` entries, one from each epoch from 1 on.
    fn with_schedule_of(n: u64) -> Manifest {
        let mut m = manifest();
        let digest = |epoch: u64| match epoch {
            1 => PRE,
            2 => POST,
            e => [0xee, (e >> 8) as u8, e as u8, 0],
        };
        m.digest_schedule = (1..=n)
            .map(|epoch| DigestEntry {
                epoch,
                digest: digest(epoch),
            })
            .collect();
        m.fork_digests = m.digest_schedule.iter().map(|d| d.digest).collect();
        m.fork_digests.sort();
        m.slot_end = n * 8 + 7;
        m
    }

    #[test]
    fn a_schedule_over_the_entry_limit_is_refused() {
        let m = with_schedule_of(MAX_DIGEST_SCHEDULE as u64);
        assert_eq!(m.validate(), Ok(()));
        assert_eq!(m.digest_at(m.slot_end), Some(m.digest_schedule[63].digest));
        let (bytes, _) = m.render().unwrap();
        assert_eq!(Manifest::parse(&bytes).unwrap().0, m);
        schedule_error(
            with_schedule_of(MAX_DIGEST_SCHEDULE as u64 + 1),
            "over 64 entries",
        );
    }

    #[test]
    fn a_known_network_needs_its_preset() {
        let mut m = manifest();
        m.network = "hoodi".into();
        let e = invalid(m);
        assert!(
            matches!(&e, ManifestError::Invalid(s) if s.contains("hoodi's preset is mainnet")),
            "{e}"
        );
        let mut m = manifest();
        m.network = "sepolia".into();
        assert!(matches!(invalid(m), ManifestError::Invalid(s) if s.contains("sepolia")));
        // A network this crate has no config for: any known preset.
        let mut m = manifest();
        m.network = "hoodi-shadow".into();
        assert_eq!(m.validate(), Ok(()));
    }

    #[test]
    fn digest_in_force_reads_either_schedule_shape() {
        let tuples = [(10, [1; 4]), (20, [2; 4]), (30, [3; 4])];
        let entries = tuples.map(|(epoch, digest)| DigestEntry { epoch, digest });
        for (epoch, want) in [
            (0, None),
            (9, None),
            (10, Some([1; 4])),
            (19, Some([1; 4])),
            (20, Some([2; 4])),
            (30, Some([3; 4])),
            (u64::MAX, Some([3; 4])),
        ] {
            assert_eq!(digest_in_force(&tuples, epoch), want, "{epoch}");
            assert_eq!(digest_in_force(&entries, epoch), want, "{epoch}");
        }
        assert_eq!(digest_in_force::<DigestEntry>(&[], 5), None);
        assert_eq!(
            schedule_over(&entries, 25, 30),
            schedule_over(&tuples, 25, 30)
        );
    }
}
