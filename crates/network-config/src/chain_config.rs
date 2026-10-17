//! `ChainConfig`: a network's runtime config, read from a pinned eth-clients `config.yaml`.
//!
//! The YAML bytes are embedded at build time together with their sha256. [`ChainConfig::load`]
//! recomputes the digest before parsing, so a changed byte fails the load instead of silently
//! changing fork epochs or blob limits.

use crate::flat_yaml::{self, Record, Value};
use crate::fork_schedule::{Epoch, ForkSchedule, ScheduledFork, Version};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// `MAX_BLOB_COMMITMENTS_PER_BLOCK` (`presets/{mainnet,minimal}/deneb.yaml`, 4096 in both).
/// `fulu/beacon-chain.md` requires every blob-schedule entry to stay at or below it.
pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64 = 4096;

/// A network with an embedded config.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// Sepolia testnet.
    Sepolia,
    /// Hoodi testnet.
    Hoodi,
}

/// Where an embedded config came from and the digest it must hash to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedSource {
    /// GitHub repository, `owner/name`.
    pub repo: &'static str,
    /// Commit the file was taken from.
    pub commit: &'static str,
    /// Path inside the repository.
    pub path: &'static str,
    /// sha256 of the file bytes.
    pub sha256: [u8; 32],
}

impl Network {
    /// Every network with an embedded config.
    pub const ALL: [Network; 2] = [Network::Sepolia, Network::Hoodi];

    /// The `CONFIG_NAME` of the network.
    pub const fn name(self) -> &'static str {
        match self {
            Network::Sepolia => "sepolia",
            Network::Hoodi => "hoodi",
        }
    }

    /// The embedded `config.yaml` bytes.
    pub const fn embedded_config(self) -> &'static [u8] {
        match self {
            Network::Sepolia => include_bytes!("../networks/sepolia/config.yaml"),
            Network::Hoodi => include_bytes!("../networks/hoodi/config.yaml"),
        }
    }

    /// The pinned origin and digest of [`Self::embedded_config`].
    pub const fn pinned(self) -> PinnedSource {
        match self {
            Network::Sepolia => PinnedSource {
                repo: "eth-clients/sepolia",
                commit: "ddd2eb069df914017a3a40672dfb56e7e895e129",
                path: "metadata/config.yaml",
                sha256: hex32("53dbfc53e5039b6937851dbb53709a80532e0aa22450067d0d87bad544251458"),
            },
            Network::Hoodi => PinnedSource {
                repo: "eth-clients/hoodi",
                commit: "ef8998901c1350f41a0bcc0a2a8d4baad973abcf",
                path: "metadata/config.yaml",
                sha256: hex32("6bb49140d29d33489f6813cf95896a75d8cdd5f9f28ab5c1d9570966ced6bc8c"),
            },
        }
    }
}

/// A network's genesis: what `compute_fork_digest` and the slot clock need beyond the config.
///
/// Neither value is in `config.yaml`: `genesis_time` and `genesis_validators_root` are fields
/// of the genesis state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// `genesis_time`, Unix seconds.
    pub genesis_time: u64,
    /// `genesis_validators_root`.
    pub genesis_validators_root: [u8; 32],
}

impl Network {
    /// The pinned genesis, or `None` where none is pinned yet (Hoodi).
    ///
    /// **Unverified constants.** The Sepolia values are written from memory, not taken from a
    /// pinned file: `genesis_time` 1655733600 (2022-06-20 14:00:00 UTC, which is
    /// `MIN_GENESIS_TIME + GENESIS_DELAY` of the pinned config) and the genesis validators root
    /// below. `m2a-session` checks both against the reference node's `/eth/v1/beacon/genesis`
    /// before it sends a Status, and refuses to go on if either differs.
    pub const fn genesis(self) -> Option<Genesis> {
        match self {
            Network::Sepolia => Some(Genesis {
                genesis_time: 1_655_733_600,
                genesis_validators_root: hex32(
                    "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
                ),
            }),
            Network::Hoodi => None,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Network::ALL
            .into_iter()
            .find(|n| n.name() == s)
            .ok_or_else(|| format!("unknown network {s:?}"))
    }
}

/// Decodes 64 hex digits at compile time; a bad literal fails the build.
const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("sha256 literal must be lowercase hex"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "sha256 literal must be 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why a config failed to load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The bytes do not hash to the pinned digest.
    #[error("config sha256 mismatch: expected {}, got {}", hex(.expected), hex(.actual))]
    DigestMismatch {
        /// The pinned digest.
        expected: [u8; 32],
        /// The digest of the bytes given.
        actual: [u8; 32],
    },
    /// The text is not the flat YAML subset (line 0: not UTF-8).
    #[error("config line {line}: {reason}")]
    Parse {
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        reason: String,
    },
    /// A required key is absent.
    #[error("config is missing {0}")]
    Missing(&'static str),
    /// A key has a value of the wrong shape or out of range.
    #[error("config {key} = {value}: {reason}")]
    Invalid {
        /// The key.
        key: &'static str,
        /// The offending value as written.
        value: String,
        /// What is wrong.
        reason: String,
    },
}

/// `BlobParameters` (`fulu/beacon-chain.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobParameters {
    /// First epoch the entry applies to.
    pub epoch: Epoch,
    /// The maximum number of blobs per block from that epoch on.
    pub max_blobs_per_block: u64,
}

/// A parsed, digest-checked network config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainConfig {
    preset_base: String,
    config_name: String,
    genesis_fork_version: Version,
    slot_duration_ms: u64,
    max_payload_size: u64,
    electra_fork_epoch: Epoch,
    max_blobs_per_block_electra: u64,
    /// Sorted by epoch, ascending, without duplicates.
    blob_schedule: Vec<BlobParameters>,
    fork_schedule: ForkSchedule,
    scalars: BTreeMap<String, String>,
}

impl ChainConfig {
    /// Loads the embedded config of `network`, checking its pinned sha256.
    pub fn load(network: Network) -> Result<Self, ConfigError> {
        Self::load_from(network, network.embedded_config())
    }

    /// Parses `yaml` as `network`'s config; it must hash to the pinned digest.
    pub fn load_from(network: Network, yaml: &[u8]) -> Result<Self, ConfigError> {
        Self::from_yaml(yaml, &network.pinned().sha256)
    }

    /// Parses `yaml` after checking it hashes to `expected_sha256`.
    pub fn from_yaml(yaml: &[u8], expected_sha256: &[u8; 32]) -> Result<Self, ConfigError> {
        let actual: [u8; 32] = Sha256::digest(yaml).into();
        if actual != *expected_sha256 {
            return Err(ConfigError::DigestMismatch {
                expected: *expected_sha256,
                actual,
            });
        }
        let text = std::str::from_utf8(yaml).map_err(|e| ConfigError::Parse {
            line: 0,
            reason: format!("not UTF-8: {e}"),
        })?;
        Self::from_document(flat_yaml::parse(text)?)
    }

    fn from_document(doc: BTreeMap<String, Value>) -> Result<Self, ConfigError> {
        let r = Reader(&doc);
        let fulu = ScheduledFork {
            version: r.version("FULU_FORK_VERSION")?,
            epoch: r.uint("FULU_FORK_EPOCH")?,
        };
        let gloas = ScheduledFork {
            version: r.version("GLOAS_FORK_VERSION")?,
            epoch: r.uint("GLOAS_FORK_EPOCH")?,
        };
        let fork_schedule = ForkSchedule::new(fulu, gloas).map_err(|e| ConfigError::Invalid {
            key: "GLOAS_FORK_EPOCH",
            value: gloas.epoch.to_string(),
            reason: e.to_string(),
        })?;
        let blob_schedule = blob_schedule(r.records("BLOB_SCHEDULE")?, fulu.epoch)?;
        let scalars = doc
            .iter()
            .filter_map(|(k, v)| match v {
                Value::Scalar(s) => Some((k.clone(), s.clone())),
                Value::Records(_) => None,
            })
            .collect();
        Ok(Self {
            preset_base: r.scalar("PRESET_BASE")?.to_owned(),
            config_name: r.scalar("CONFIG_NAME")?.to_owned(),
            genesis_fork_version: r.version("GENESIS_FORK_VERSION")?,
            slot_duration_ms: r.uint("SLOT_DURATION_MS")?,
            max_payload_size: r.uint("MAX_PAYLOAD_SIZE")?,
            electra_fork_epoch: r.uint("ELECTRA_FORK_EPOCH")?,
            max_blobs_per_block_electra: r.uint("MAX_BLOBS_PER_BLOCK_ELECTRA")?,
            blob_schedule,
            fork_schedule,
            scalars,
        })
    }

    /// `PRESET_BASE`, e.g. `mainnet`.
    pub fn preset_base(&self) -> &str {
        &self.preset_base
    }

    /// `CONFIG_NAME`, e.g. `sepolia`.
    pub fn config_name(&self) -> &str {
        &self.config_name
    }

    /// `GENESIS_FORK_VERSION`.
    pub fn genesis_fork_version(&self) -> Version {
        self.genesis_fork_version
    }

    /// `SLOT_DURATION_MS`.
    pub fn slot_duration_ms(&self) -> u64 {
        self.slot_duration_ms
    }

    /// `MAX_PAYLOAD_SIZE` (`phase0/p2p-interface.md`): the largest uncompressed p2p payload.
    pub fn max_payload_size(&self) -> u64 {
        self.max_payload_size
    }

    /// The Fulu/Gloas fork schedule.
    pub fn fork_schedule(&self) -> &ForkSchedule {
        &self.fork_schedule
    }

    /// `MAX_BLOBS_PER_BLOCK_ELECTRA`: the blob limit before the first `BLOB_SCHEDULE` entry, and
    /// the starting value of `compute_max_data_column_sidecar_size` (`gloas/p2p-interface.md`).
    pub fn max_blobs_per_block_electra(&self) -> u64 {
        self.max_blobs_per_block_electra
    }

    /// `BLOB_SCHEDULE`, sorted by epoch.
    pub fn blob_schedule(&self) -> &[BlobParameters] {
        &self.blob_schedule
    }

    /// Any scalar value as written, for keys without a typed accessor.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.scalars.get(key).map(String::as_str)
    }

    /// `get_blob_parameters` (`fulu/beacon-chain.md`): the latest schedule entry at or before
    /// `epoch`, else `(ELECTRA_FORK_EPOCH, MAX_BLOBS_PER_BLOCK_ELECTRA)`.
    pub fn get_blob_parameters(&self, epoch: Epoch) -> BlobParameters {
        self.blob_schedule
            .iter()
            .rev()
            .find(|entry| epoch >= entry.epoch)
            .copied()
            .unwrap_or(BlobParameters {
                epoch: self.electra_fork_epoch,
                max_blobs_per_block: self.max_blobs_per_block_electra,
            })
    }
}

/// Typed access to the parsed document.
struct Reader<'a>(&'a BTreeMap<String, Value>);

impl Reader<'_> {
    fn scalar(&self, key: &'static str) -> Result<&str, ConfigError> {
        match self.0.get(key) {
            Some(Value::Scalar(s)) => Ok(s),
            Some(Value::Records(_)) => Err(invalid(key, "<list>", "expected a scalar")),
            None => Err(ConfigError::Missing(key)),
        }
    }

    fn uint(&self, key: &'static str) -> Result<u64, ConfigError> {
        let s = self.scalar(key)?;
        s.parse().map_err(|_| invalid(key, s, "expected a uint64"))
    }

    fn version(&self, key: &'static str) -> Result<Version, ConfigError> {
        let s = self.scalar(key)?;
        parse_version(s).ok_or_else(|| invalid(key, s, "expected 0x and 8 hex digits"))
    }

    /// An absent list is empty: `fulu/beacon-chain.md` allows an empty blob schedule.
    fn records(&self, key: &'static str) -> Result<&[Record], ConfigError> {
        match self.0.get(key) {
            Some(Value::Records(r)) => Ok(r),
            Some(Value::Scalar(s)) => Err(invalid(key, s, "expected a list")),
            None => Ok(&[]),
        }
    }
}

fn invalid(key: &'static str, value: &str, reason: &str) -> ConfigError {
    ConfigError::Invalid {
        key,
        value: value.to_owned(),
        reason: reason.to_owned(),
    }
}

fn parse_version(s: &str) -> Option<Version> {
    let digits = s.strip_prefix("0x")?;
    if digits.len() != 8 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok().map(u32::to_be_bytes)
}

/// Applies the `fulu/beacon-chain.md` blob-schedule rules: unique epochs, each at or after
/// `FULU_FORK_EPOCH`, each limit at or below `MAX_BLOB_COMMITMENTS_PER_BLOCK`.
fn blob_schedule(
    records: &[Record],
    fulu_epoch: Epoch,
) -> Result<Vec<BlobParameters>, ConfigError> {
    const KEY: &str = "BLOB_SCHEDULE";
    let mut out = Vec::with_capacity(records.len());
    let mut seen_epochs = BTreeSet::new();
    for record in records {
        let shown = record
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let bad = |reason: String| ConfigError::Invalid {
            key: KEY,
            value: format!("{{{shown}}}"),
            reason,
        };
        let field = |name: &str| -> Result<u64, ConfigError> {
            let (_, v) = record
                .iter()
                .find(|(k, _)| k == name)
                .ok_or_else(|| bad(format!("missing {name}")))?;
            v.parse()
                .map_err(|_| bad(format!("{name} is not a uint64")))
        };
        if let Some((extra, _)) = record
            .iter()
            .find(|(k, _)| k != "EPOCH" && k != "MAX_BLOBS_PER_BLOCK")
        {
            return Err(bad(format!("unknown field {extra}")));
        }
        let entry = BlobParameters {
            epoch: field("EPOCH")?,
            max_blobs_per_block: field("MAX_BLOBS_PER_BLOCK")?,
        };
        if entry.epoch < fulu_epoch {
            return Err(bad(format!(
                "epoch {} is before FULU_FORK_EPOCH {fulu_epoch}",
                entry.epoch
            )));
        }
        if entry.max_blobs_per_block > MAX_BLOB_COMMITMENTS_PER_BLOCK {
            return Err(bad(format!(
                "max blobs {} exceeds MAX_BLOB_COMMITMENTS_PER_BLOCK {MAX_BLOB_COMMITMENTS_PER_BLOCK}",
                entry.max_blobs_per_block
            )));
        }
        if !seen_epochs.insert(entry.epoch) {
            return Err(bad(format!("duplicate epoch {}", entry.epoch)));
        }
        out.push(entry);
    }
    out.sort_by_key(|e| e.epoch);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_digests_match_embedded_files() {
        for n in Network::ALL {
            let got: [u8; 32] = Sha256::digest(n.embedded_config()).into();
            assert_eq!(got, n.pinned().sha256, "{n}");
        }
    }

    #[test]
    fn sepolia_genesis_time_is_min_genesis_time_plus_delay() {
        // A consistency check of the unverified constant, not a proof: Sepolia started exactly
        // GENESIS_DELAY after MIN_GENESIS_TIME. The root is checked live (m2a-session).
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let field = |k| config.get(k).unwrap().parse::<u64>().unwrap();
        let genesis = Network::Sepolia.genesis().unwrap();
        assert_eq!(
            genesis.genesis_time,
            field("MIN_GENESIS_TIME") + field("GENESIS_DELAY")
        );
        assert_eq!(Network::Hoodi.genesis(), None);
    }

    #[test]
    fn versions_parse_big_endian() {
        assert_eq!(parse_version("0x90000075"), Some([0x90, 0, 0, 0x75]));
        assert_eq!(parse_version("0x9000007"), None);
        assert_eq!(parse_version("0x+0000075"), None);
    }

    #[test]
    fn digest_mismatch_shows_both_digests() {
        let err = ChainConfig::from_yaml(b"A: 1\n", &[0; 32]).unwrap_err();
        let text = err.to_string();
        assert!(text.contains(&"00".repeat(32)), "{text}");
    }
}
