//! Names that become path components: networks (from the operator) and topics (from gossip).

use consensus_types::primitives::{Root, Slot};

/// The longest network or topic name.
pub const MAX_NAME_LEN: usize = 64;

/// A network or topic name that cannot be a path component of an archive.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// Empty or longer than 64 bytes.
    #[error("{kind} name {name:?} must have 1 to 64 characters")]
    Length {
        /// `network` or `topic`.
        kind: &'static str,
        /// The refused name.
        name: String,
    },
    /// A character outside the allowed set, or a leading `-`.
    #[error("{kind} name {name:?} may only use {allowed}")]
    Charset {
        /// `network` or `topic`.
        kind: &'static str,
        /// The refused name.
        name: String,
        /// The allowed characters.
        allowed: &'static str,
    },
    /// A topic this archiver cannot take a slot and root from.
    #[error("topic {0:?} is not archived (beacon_block and data_column_sidecar_<subnet> are)")]
    Unsupported(String),
}

/// What a topic carries, which decides how its slot and root are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicKind {
    /// `beacon_block`: a `SignedBeaconBlock`.
    BeaconBlock,
    /// `data_column_sidecar_<subnet>`: a `DataColumnSidecar`.
    DataColumnSidecar {
        /// The subnet in the topic name.
        subnet: u64,
    },
}

impl TopicKind {
    /// The kind of `topic`, or [`NameError::Unsupported`] for a topic the archive cannot file.
    pub fn of(topic: &str) -> Result<Self, NameError> {
        if topic == "beacon_block" {
            return Ok(Self::BeaconBlock);
        }
        topic
            .strip_prefix("data_column_sidecar_")
            .and_then(canonical_decimal)
            .map(|subnet| Self::DataColumnSidecar { subnet })
            .ok_or_else(|| NameError::Unsupported(topic.to_owned()))
    }
}

/// A decimal `u64` without a sign or a leading zero, so one subnet has one topic name.
fn canonical_decimal(digits: &str) -> Option<u64> {
    let canonical =
        digits.bytes().all(|b| b.is_ascii_digit()) && (digits == "0" || !digits.starts_with('0'));
    canonical.then(|| digits.parse().ok()).flatten()
}

/// `network` is 1 to 64 of `[a-z0-9_-]`, not starting with `-`: no `.`, `/` or `..`.
pub fn validate_network(network: &str) -> Result<(), NameError> {
    const ALLOWED: &str = "[a-z0-9_-], not starting with '-'";
    validate("network", network, ALLOWED, |b| b == b'-' || topic_byte(b))?;
    if network.starts_with('-') {
        return Err(charset("network", network, ALLOWED));
    }
    Ok(())
}

/// `topic` is 1 to 64 of `[a-z0-9_]`, as gossip topic names are.
pub fn validate_topic(topic: &str) -> Result<(), NameError> {
    validate("topic", topic, "[a-z0-9_]", topic_byte)
}

fn topic_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

fn charset(kind: &'static str, name: &str, allowed: &'static str) -> NameError {
    NameError::Charset {
        kind,
        name: name.to_owned(),
        allowed,
    }
}

fn validate(
    kind: &'static str,
    name: &str,
    allowed: &'static str,
    byte_ok: impl Fn(u8) -> bool,
) -> Result<(), NameError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(NameError::Length {
            kind,
            name: name.to_owned(),
        });
    }
    if !name.bytes().all(byte_ok) {
        return Err(charset(kind, name, allowed));
    }
    Ok(())
}

/// `<slot>_0x<root>.ssz_snappy`.
pub fn file_name(slot: Slot, root: &Root) -> String {
    format!("{slot}_0x{}.ssz_snappy", hex::encode(root))
}

/// `<topic>/<slot>_0x<root>.ssz_snappy`, the path of a file relative to its segment.
pub fn file_path(topic: &str, slot: Slot, root: &Root) -> String {
    format!("{topic}/{}", file_name(slot, root))
}

/// `<slot_start>-<slot_end>`, the segment directory name.
pub fn segment_name(slot_start: Slot, slot_end: Slot) -> String {
    format!("{slot_start}-{slot_end}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::primitives::B256;

    #[test]
    fn network_names() {
        for ok in ["sepolia", "hoodi", "kurtosis-gloas", "dev_1", "a"] {
            assert_eq!(validate_network(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "..",
            ".",
            "a/b",
            "../x",
            "Sepolia",
            "-x",
            "a.b",
            "a b",
            &"x".repeat(65),
        ] {
            assert!(validate_network(bad).is_err(), "{bad:?}");
        }
        assert!(matches!(
            validate_network(""),
            Err(NameError::Length { .. })
        ));
        assert!(matches!(
            validate_network(".."),
            Err(NameError::Charset { .. })
        ));
    }

    #[test]
    fn topic_names() {
        for ok in ["beacon_block", "data_column_sidecar_127", "x"] {
            assert_eq!(validate_topic(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "..",
            "beacon-block",
            "a/b",
            "Beacon",
            "x.y",
            &"x".repeat(65),
        ] {
            assert!(validate_topic(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn topic_kinds() {
        assert_eq!(TopicKind::of("beacon_block"), Ok(TopicKind::BeaconBlock));
        assert_eq!(
            TopicKind::of("data_column_sidecar_0"),
            Ok(TopicKind::DataColumnSidecar { subnet: 0 })
        );
        assert_eq!(
            TopicKind::of("data_column_sidecar_127"),
            Ok(TopicKind::DataColumnSidecar { subnet: 127 })
        );
        for bad in [
            "data_column_sidecar_",
            "data_column_sidecar_01",
            "data_column_sidecar_x",
            "data_column_sidecar_99999999999999999999",
            "beacon_aggregate_and_proof",
            "beacon_block_1",
        ] {
            assert_eq!(
                TopicKind::of(bad),
                Err(NameError::Unsupported(bad.into())),
                "{bad}"
            );
        }
    }

    #[test]
    fn paths() {
        let root = B256::repeat_byte(0xab);
        let hex = "ab".repeat(32);
        assert_eq!(file_name(7, &root), format!("7_0x{hex}.ssz_snappy"));
        assert_eq!(
            file_path("beacon_block", 7, &root),
            format!("beacon_block/7_0x{hex}.ssz_snappy")
        );
        assert_eq!(segment_name(64, 95), "64-95");
    }
}
