//! [`TopicConfig`]: what a capture subscribes and samples, read as data from a TOML file
//! (`--topics-file`), never from the environment.
//!
//! ```toml
//! sse_events = ["block_gossip", "data_column_sidecar", "single_attestation"]
//! attestation_subnets = [0, 1]
//! ```
//!
//! - `sse_events`: the reference node's `/eth/v1/events` topics to subscribe, each a name of
//!   the beacon-APIs `01e99a6` eventstream ([`KNOWN_SSE_EVENTS`]), each once. The fallback,
//!   [`FALLBACK_SSE_EVENTS`] (`beacon_block` and the columns), must be among them: whatever else
//!   the node does not emit, a capture always has blocks and columns.
//! - `attestation_subnets`: the attestation subnets sampled, each below
//!   [`ATTESTATION_SUBNET_COUNT`], each once. An unaggregated attestation on any other subnet
//!   (or whose subnet is unknown) is counted, never recorded: a node subscribed to every subnet
//!   would otherwise write each attestation of the network. Required when `single_attestation`
//!   is subscribed.
//!
//! Both are copied into the capture's `capture.toml`, and `summary.toml` gives the count of
//! each. The file is not secret, so errors quote it; it must be a regular file no one but its
//! owner (root, or the collector's own user) may write.

use super::url::open_regular_file;
use p2p_wire::gossip::topic::ATTESTATION_SUBNET_COUNT;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Cap on a topics file: 16 KiB. A full config is a few hundred bytes.
pub const MAX_TOPICS_FILE_BYTES: usize = 16 << 10;

/// Every `topics` value of the beacon-APIs `01e99a6` eventstream (`apis/eventstream/index.yaml`).
pub const KNOWN_SSE_EVENTS: [&str; 24] = [
    "head",
    "head_v2",
    "block",
    "block_gossip",
    "attestation",
    "single_attestation",
    "voluntary_exit",
    "bls_to_execution_change",
    "proposer_slashing",
    "attester_slashing",
    "finalized_checkpoint",
    "chain_reorg",
    "contribution_and_proof",
    "light_client_finality_update",
    "light_client_optimistic_update",
    "payload_attributes",
    "data_column_sidecar",
    "execution_payload",
    "execution_payload_gossip",
    "execution_payload_available",
    "execution_payload_bid",
    "payload_attestation_message",
    "fast_confirmation",
    "proposer_preferences",
];

/// Subscribed in every capture: `beacon_block` and the columns.
pub const FALLBACK_SSE_EVENTS: [&str; 2] = ["block_gossip", "data_column_sidecar"];

/// The exit-14 topic set (`gloas/p2p-interface.md`), as the SSE event that reports a message
/// passing each topic's gossip validation, and the gossip topic it stands for. Lighthouse emits
/// `attestation` for an aggregate verified on `beacon_aggregate_and_proof` and
/// `single_attestation` for an unaggregated one on `beacon_attestation_{subnet_id}`.
pub const EXIT14_SSE_EVENTS: [(&str, &str); 7] = [
    ("block_gossip", "beacon_block"),
    ("execution_payload_gossip", "execution_payload"),
    ("execution_payload_bid", "execution_payload_bid"),
    ("payload_attestation_message", "payload_attestation_message"),
    ("attestation", "beacon_aggregate_and_proof"),
    ("single_attestation", "beacon_attestation_{subnet_id}"),
    ("data_column_sidecar", "data_column_sidecar_{subnet_id}"),
];

/// The SSE event of an unaggregated attestation: the one sampled by subnet.
pub const SINGLE_ATTESTATION: &str = "single_attestation";

/// A checked topics file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopicConfig {
    /// The SSE events to subscribe, in the file's order.
    pub sse_events: Vec<String>,
    /// The attestation subnets sampled, ascending.
    #[serde(default)]
    pub attestation_subnets: Vec<u64>,
}

/// Why a topics file was refused: the file's path and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {reason}")]
pub struct TopicsFileError {
    /// The file, as given.
    pub path: String,
    /// Why.
    pub reason: String,
}

impl TopicConfig {
    /// Parses and checks `text`; the error says why (see the module docs).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut config: Self = toml::from_str(text).map_err(|e| e.message().to_owned())?;
        for (i, event) in config.sse_events.iter().enumerate() {
            if !KNOWN_SSE_EVENTS.contains(&event.as_str()) {
                return Err(format!(
                    "sse_events: {event:?} is not a beacon-APIs eventstream topic"
                ));
            }
            if config.sse_events[..i].contains(event) {
                return Err(format!("sse_events: {event:?} is listed twice"));
            }
        }
        if let Some(missing) = FALLBACK_SSE_EVENTS
            .iter()
            .find(|f| !config.sse_events.iter().any(|e| e == *f))
        {
            return Err(format!(
                "sse_events: want {missing:?} (block_gossip and data_column_sidecar are always \
                 subscribed)"
            ));
        }
        let subnets = &mut config.attestation_subnets;
        if let Some(bad) = subnets.iter().find(|s| **s >= ATTESTATION_SUBNET_COUNT) {
            return Err(format!(
                "attestation_subnets: {bad} is not below {ATTESTATION_SUBNET_COUNT}"
            ));
        }
        subnets.sort_unstable();
        if let Some(twice) = subnets.windows(2).find(|w| w[0] == w[1]) {
            return Err(format!("attestation_subnets: {} is listed twice", twice[0]));
        }
        if config.sse_events.iter().any(|e| e == SINGLE_ATTESTATION) && subnets.is_empty() {
            return Err(format!(
                "attestation_subnets: {SINGLE_ATTESTATION} is subscribed, so name the subnets \
                 it samples"
            ));
        }
        Ok(config)
    }

    /// Reads and checks `path`: a regular file (refused from an lstat before it is opened
    /// otherwise), owned by root or `euid` and writable by its owner only, at most
    /// [`MAX_TOPICS_FILE_BYTES`] of UTF-8.
    pub fn read_file(path: &Path) -> Result<Self, TopicsFileError> {
        Self::read_file_as(path, rustix::process::geteuid().as_raw())
    }

    /// [`TopicConfig::read_file`] for a process whose effective UID is `euid`.
    fn read_file_as(path: &Path, euid: u32) -> Result<Self, TopicsFileError> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let bad = |reason: String| TopicsFileError {
            path: path.display().to_string(),
            reason,
        };
        let (file, meta) = open_regular_file(path).map_err(bad)?;
        if meta.uid() != 0 && meta.uid() != euid {
            return Err(bad(format!(
                "owned by uid {}, want root or {euid}",
                meta.uid()
            )));
        }
        if meta.permissions().mode() & 0o022 != 0 {
            return Err(bad(
                "group or others may write it (want mode 0644 or stricter)".into(),
            ));
        }
        let mut body = Vec::new();
        file.take(MAX_TOPICS_FILE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| bad(format!("read: {e}")))?;
        if body.len() > MAX_TOPICS_FILE_BYTES {
            return Err(bad(format!("over {MAX_TOPICS_FILE_BYTES} bytes")));
        }
        let text = String::from_utf8(body).map_err(|_| bad("not UTF-8".into()))?;
        Self::parse(&text).map_err(bad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOODI: &str =
        include_str!("../../../../ops/collector/collector-hoodi.topics.toml.example");
    const SEPOLIA: &str =
        include_str!("../../../../ops/collector/collector-sepolia.topics.toml.example");

    #[test]
    fn the_examples_subscribe_the_exit14_set_and_sample_subnets() {
        for (name, text) in [("hoodi", HOODI), ("sepolia", SEPOLIA)] {
            let config = TopicConfig::parse(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            let want: Vec<&str> = EXIT14_SSE_EVENTS.iter().map(|(e, _)| *e).collect();
            assert_eq!(config.sse_events, want, "{name}");
            assert!(!config.attestation_subnets.is_empty(), "{name}");
        }
        // Every exit-14 event is a known eventstream topic.
        assert!(EXIT14_SSE_EVENTS
            .iter()
            .all(|(e, _)| KNOWN_SSE_EVENTS.contains(e)));
    }

    #[test]
    fn a_config_is_checked() {
        let ok = TopicConfig::parse(
            "sse_events = [\"data_column_sidecar\", \"block_gossip\", \"single_attestation\"]\n\
             attestation_subnets = [9, 0]\n",
        )
        .unwrap();
        assert_eq!(
            ok.sse_events,
            ["data_column_sidecar", "block_gossip", "single_attestation"]
        );
        assert_eq!(ok.attestation_subnets, [0, 9]);
        // Without single_attestation, no subnet is needed.
        let blocks =
            TopicConfig::parse("sse_events = [\"block_gossip\", \"data_column_sidecar\"]").unwrap();
        assert!(blocks.attestation_subnets.is_empty());

        let base = "\"block_gossip\", \"data_column_sidecar\"";
        for (text, why) in [
            (
                format!("sse_events = [{base}, \"weather\"]"),
                "\"weather\" is not a beacon-APIs eventstream topic",
            ),
            (
                format!("sse_events = [{base}, \"head\", \"head\"]"),
                "\"head\" is listed twice",
            ),
            (
                "sse_events = [\"block_gossip\"]".to_owned(),
                "want \"data_column_sidecar\"",
            ),
            (
                format!("sse_events = [{base}, \"single_attestation\"]"),
                "name the subnets",
            ),
            (
                format!("sse_events = [{base}]\nattestation_subnets = [64]"),
                "64 is not below 64",
            ),
            (
                format!("sse_events = [{base}]\nattestation_subnets = [3, 1, 3]"),
                "3 is listed twice",
            ),
            (
                format!("sse_events = [{base}]\ncolumn_subnets = [1]"),
                "unknown field",
            ),
            ("attestation_subnets = [1]".to_owned(), "missing field"),
            (
                format!("sse_events = [{base}]\nattestation_subnets = [-1]"),
                "u64",
            ),
        ] {
            let err = TopicConfig::parse(&text).unwrap_err();
            assert!(err.contains(why), "{text}: {err} (want {why})");
        }
    }

    fn file(dir: &Path, name: &str, body: &str, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn a_topics_file_is_read_as_data() {
        let dir = tempfile::tempdir().unwrap();
        let good = file(dir.path(), "good", HOODI, 0o644);
        assert_eq!(
            TopicConfig::read_file(&good).unwrap(),
            TopicConfig::parse(HOODI).unwrap()
        );
        let long = format!("{HOODI}#{}\n", "x".repeat(MAX_TOPICS_FILE_BYTES));
        let euid = rustix::process::geteuid().as_raw();
        let cases = [
            (
                file(dir.path(), "group", HOODI, 0o664),
                "group or others may write",
            ),
            (
                file(dir.path(), "world", HOODI, 0o646),
                "group or others may write",
            ),
            (file(dir.path(), "long", &long, 0o644), "over 16384 bytes"),
            (
                file(dir.path(), "bad", "sse_events = 1", 0o644),
                "invalid type",
            ),
            (dir.path().join("missing"), "open"),
            (
                std::path::PathBuf::from("/dev/null"),
                "not a regular file (a character device), refused before opening",
            ),
        ];
        for (path, why) in &cases {
            let err = TopicConfig::read_file(path).unwrap_err().to_string();
            assert!(err.starts_with(&path.display().to_string()), "{err}");
            assert!(err.contains(why), "{err} (want {why})");
        }
        std::fs::write(dir.path().join("binary"), b"\xff").unwrap();
        let err = TopicConfig::read_file(&dir.path().join("binary")).unwrap_err();
        assert!(err.reason.contains("UTF-8"), "{err}");
        // Root's file or the collector's own; nobody else's (as root, every file is root's or
        // the collector's own).
        if euid != 0 {
            let other = euid.wrapping_add(1);
            let err = TopicConfig::read_file_as(&good, other).unwrap_err();
            assert_eq!(
                err.reason,
                format!("owned by uid {euid}, want root or {other}")
            );
        }
    }
}
