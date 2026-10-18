//! Gossip topics: `/eth2/<ForkDigestValue>/<Name>/<Encoding>` (`phase0/p2p-interface.md`
//! "Topics and messages").
//!
//! `ForkDigestValue` is the lowercase hex of the 4-byte fork digest with no `0x` prefix, and the
//! only encoding is `ssz_snappy`. [`GossipTopic::parse`] accepts exactly the strings
//! [`GossipTopic`]'s `Display` writes, so a topic has one spelling: upper-case hex, a subnet id
//! with a leading zero or a sign, and any name this node does not handle are refused (clients
//! MUST reject messages with an unknown topic).
//!
//! The names are every topic the probe may subscribe, with their Gloas message types
//! (`gloas/p2p-interface.md` "Topics and messages", `fulu/p2p-interface.md`
//! `data_column_sidecar_{subnet_id}`). Which of them are subscribed is configuration.

use crate::rpc::messages::ForkDigest;
use consensus_types::caps::ObjectKind;
use std::fmt;
use std::str::FromStr;

/// The topic prefix.
pub const TOPIC_PREFIX: &str = "eth2";
/// The only gossip encoding: SSZ, then snappy block compression.
pub const ENCODING_SSZ_SNAPPY: &str = "ssz_snappy";
/// `ATTESTATION_SUBNET_COUNT` (`phase0` config): the `beacon_attestation_{subnet_id}` subnets.
pub const ATTESTATION_SUBNET_COUNT: u64 = 64;
/// `DATA_COLUMN_SIDECAR_SUBNET_COUNT` (`fulu` config): the `data_column_sidecar_{subnet_id}`
/// subnets.
pub const DATA_COLUMN_SIDECAR_SUBNET_COUNT: u64 = 128;

const BEACON_BLOCK: &str = "beacon_block";
const BEACON_AGGREGATE_AND_PROOF: &str = "beacon_aggregate_and_proof";
const BEACON_ATTESTATION_PREFIX: &str = "beacon_attestation_";
const DATA_COLUMN_SIDECAR_PREFIX: &str = "data_column_sidecar_";
const EXECUTION_PAYLOAD_BID: &str = "execution_payload_bid";
const EXECUTION_PAYLOAD: &str = "execution_payload";
const PAYLOAD_ATTESTATION_MESSAGE: &str = "payload_attestation_message";

/// The `Name` part of a topic: what the topic carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GossipKind {
    /// `beacon_block`: `SignedBeaconBlock`.
    BeaconBlock,
    /// `beacon_aggregate_and_proof`: `SignedAggregateAndProof`.
    BeaconAggregateAndProof,
    /// `beacon_attestation_{subnet_id}`: `SingleAttestation`.
    BeaconAttestation {
        /// Below [`ATTESTATION_SUBNET_COUNT`].
        subnet_id: u64,
    },
    /// `data_column_sidecar_{subnet_id}`: `DataColumnSidecar`.
    DataColumnSidecar {
        /// Below [`DATA_COLUMN_SIDECAR_SUBNET_COUNT`].
        subnet_id: u64,
    },
    /// `execution_payload_bid`: `SignedExecutionPayloadBid`.
    ExecutionPayloadBid,
    /// `execution_payload`: `SignedExecutionPayloadEnvelope`.
    ExecutionPayload,
    /// `payload_attestation_message`: `PayloadAttestationMessage`.
    PayloadAttestationMessage,
}

impl GossipKind {
    /// The type of the topic's messages.
    pub fn object_kind(self) -> ObjectKind {
        match self {
            GossipKind::BeaconBlock => ObjectKind::SignedBeaconBlock,
            GossipKind::BeaconAggregateAndProof => ObjectKind::SignedAggregateAndProof,
            GossipKind::BeaconAttestation { .. } => ObjectKind::SingleAttestation,
            GossipKind::DataColumnSidecar { .. } => ObjectKind::DataColumnSidecar,
            GossipKind::ExecutionPayloadBid => ObjectKind::SignedExecutionPayloadBid,
            GossipKind::ExecutionPayload => ObjectKind::SignedExecutionPayloadEnvelope,
            GossipKind::PayloadAttestationMessage => ObjectKind::PayloadAttestationMessage,
        }
    }

    /// The kind named `name`.
    ///
    /// # Errors
    ///
    /// [`TopicError::UnknownName`] for a name this node does not handle,
    /// [`TopicError::Subnet`] for a subnet id that is not canonical or not below its count.
    pub fn from_name(name: &str) -> Result<Self, TopicError> {
        let kind = match name {
            BEACON_BLOCK => GossipKind::BeaconBlock,
            BEACON_AGGREGATE_AND_PROOF => GossipKind::BeaconAggregateAndProof,
            EXECUTION_PAYLOAD_BID => GossipKind::ExecutionPayloadBid,
            EXECUTION_PAYLOAD => GossipKind::ExecutionPayload,
            PAYLOAD_ATTESTATION_MESSAGE => GossipKind::PayloadAttestationMessage,
            _ => {
                if let Some(id) = name.strip_prefix(BEACON_ATTESTATION_PREFIX) {
                    GossipKind::BeaconAttestation {
                        subnet_id: subnet_id(name, id, ATTESTATION_SUBNET_COUNT)?,
                    }
                } else if let Some(id) = name.strip_prefix(DATA_COLUMN_SIDECAR_PREFIX) {
                    GossipKind::DataColumnSidecar {
                        subnet_id: subnet_id(name, id, DATA_COLUMN_SIDECAR_SUBNET_COUNT)?,
                    }
                } else {
                    return Err(TopicError::UnknownName(name.to_owned()));
                }
            }
        };
        Ok(kind)
    }
}

impl fmt::Display for GossipKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GossipKind::BeaconBlock => f.write_str(BEACON_BLOCK),
            GossipKind::BeaconAggregateAndProof => f.write_str(BEACON_AGGREGATE_AND_PROOF),
            GossipKind::BeaconAttestation { subnet_id } => {
                write!(f, "{BEACON_ATTESTATION_PREFIX}{subnet_id}")
            }
            GossipKind::DataColumnSidecar { subnet_id } => {
                write!(f, "{DATA_COLUMN_SIDECAR_PREFIX}{subnet_id}")
            }
            GossipKind::ExecutionPayloadBid => f.write_str(EXECUTION_PAYLOAD_BID),
            GossipKind::ExecutionPayload => f.write_str(EXECUTION_PAYLOAD),
            GossipKind::PayloadAttestationMessage => f.write_str(PAYLOAD_ATTESTATION_MESSAGE),
        }
    }
}

/// A canonical decimal subnet id below `count`: digits only, no leading zero.
fn subnet_id(name: &str, digits: &str, count: u64) -> Result<u64, TopicError> {
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    match digits.parse::<u64>() {
        Ok(id) if canonical && id < count => Ok(id),
        _ => Err(TopicError::Subnet(name.to_owned())),
    }
}

/// A gossip topic: the fork digest of the messages' epoch and what they carry, in
/// `ssz_snappy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GossipTopic {
    /// `compute_fork_digest(genesis_validators_root, epoch)` of the messages' epoch.
    pub fork_digest: ForkDigest,
    /// The topic name.
    pub kind: GossipKind,
}

impl GossipTopic {
    /// The `ssz_snappy` topic for `kind` under `fork_digest`.
    pub fn new(fork_digest: ForkDigest, kind: GossipKind) -> Self {
        Self { fork_digest, kind }
    }

    /// Parses the exact form `Display` writes.
    ///
    /// # Errors
    ///
    /// [`TopicError::Shape`] unless the string is `/eth2/<digest>/<name>/<encoding>`,
    /// [`TopicError::ForkDigest`] unless the digest is 8 lowercase hex digits,
    /// [`TopicError::UnknownName`] / [`TopicError::Subnet`] as [`GossipKind::from_name`], and
    /// [`TopicError::Encoding`] for an encoding other than `ssz_snappy`.
    pub fn parse(topic: &str) -> Result<Self, TopicError> {
        let shape = || TopicError::Shape(topic.to_owned());
        let rest = topic.strip_prefix('/').ok_or_else(shape)?;
        let mut parts = rest.split('/');
        let (Some(prefix), Some(digest), Some(name), Some(encoding), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(shape());
        };
        if prefix != TOPIC_PREFIX {
            return Err(shape());
        }
        let fork_digest = parse_digest(digest)?;
        let kind = GossipKind::from_name(name)?;
        if encoding != ENCODING_SSZ_SNAPPY {
            return Err(TopicError::Encoding(encoding.to_owned()));
        }
        Ok(Self { fork_digest, kind })
    }
}

/// Eight lowercase hex digits.
fn parse_digest(hex: &str) -> Result<ForkDigest, TopicError> {
    let refuse = || TopicError::ForkDigest(hex.to_owned());
    let bytes = hex.as_bytes();
    if bytes.len() != 8 {
        return Err(refuse());
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut digest = [0u8; 4];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (out, &[hi, lo]) in digest.iter_mut().zip(pairs) {
        let (Some(hi), Some(lo)) = (nibble(hi), nibble(lo)) else {
            return Err(refuse());
        };
        *out = hi << 4 | lo;
    }
    Ok(digest)
}

impl fmt::Display for GossipTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.fork_digest;
        write!(
            f,
            "/{TOPIC_PREFIX}/{a:02x}{b:02x}{c:02x}{d:02x}/{}/{ENCODING_SSZ_SNAPPY}",
            self.kind
        )
    }
}

impl FromStr for GossipTopic {
    type Err = TopicError;

    fn from_str(topic: &str) -> Result<Self, Self::Err> {
        Self::parse(topic)
    }
}

/// Why a topic string was refused. Each carries the offending part, so a log line names it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TopicError {
    /// Not `/eth2/<digest>/<name>/<encoding>`.
    #[error("not an eth2 topic: {0:?}")]
    Shape(String),
    /// The digest is not 8 lowercase hex digits.
    #[error("fork digest is not 8 lowercase hex digits: {0:?}")]
    ForkDigest(String),
    /// A topic name this node does not handle.
    #[error("unknown topic name: {0:?}")]
    UnknownName(String),
    /// A subnet id that is not canonical decimal below the subnet count.
    #[error("bad subnet id in topic name: {0:?}")]
    Subnet(String),
    /// An encoding other than `ssz_snappy`.
    #[error("unsupported encoding: {0:?}")]
    Encoding(String),
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One topic of every kind, with the first and last subnet of each subnet kind.
    pub(crate) fn every_kind() -> Vec<GossipKind> {
        vec![
            GossipKind::BeaconBlock,
            GossipKind::BeaconAggregateAndProof,
            GossipKind::BeaconAttestation { subnet_id: 0 },
            GossipKind::BeaconAttestation {
                subnet_id: ATTESTATION_SUBNET_COUNT - 1,
            },
            GossipKind::DataColumnSidecar { subnet_id: 0 },
            GossipKind::DataColumnSidecar {
                subnet_id: DATA_COLUMN_SIDECAR_SUBNET_COUNT - 1,
            },
            GossipKind::ExecutionPayloadBid,
            GossipKind::ExecutionPayload,
            GossipKind::PayloadAttestationMessage,
        ]
    }

    fn parse(topic: &str) -> Result<GossipTopic, TopicError> {
        GossipTopic::parse(topic)
    }

    #[test]
    fn every_digest_byte_is_two_lowercase_digits() {
        let topic = GossipTopic::new([0x00, 0x0a, 0xf0, 0xff], GossipKind::BeaconBlock);
        assert_eq!(topic.to_string(), "/eth2/000af0ff/beacon_block/ssz_snappy");
        assert_eq!(parse("/eth2/000af0ff/beacon_block/ssz_snappy"), Ok(topic));
    }

    #[test]
    fn a_digest_of_the_wrong_length_or_alphabet_is_refused() {
        for digest in [
            "abcdef1",
            "abcdef123",
            "",
            "0xabcdef",
            "abcdefgh",
            "abcd ef1",
            "+bcdef12",
        ] {
            let topic = format!("/eth2/{digest}/beacon_block/ssz_snappy");
            assert_eq!(
                parse(&topic),
                Err(TopicError::ForkDigest(digest.to_owned())),
                "{topic}"
            );
        }
    }

    #[test]
    fn subnet_ids_are_canonical_and_in_range() {
        for name in [
            "beacon_attestation_64",
            "beacon_attestation_01",
            "beacon_attestation_",
            "beacon_attestation_+1",
            "beacon_attestation_-1",
            "beacon_attestation_1a",
            "beacon_attestation_18446744073709551616",
            "data_column_sidecar_128",
            "data_column_sidecar_00",
        ] {
            let topic = format!("/eth2/00000000/{name}/ssz_snappy");
            assert_eq!(
                parse(&topic),
                Err(TopicError::Subnet(name.to_owned())),
                "{topic}"
            );
        }
        assert_eq!(
            GossipKind::from_name("data_column_sidecar_100"),
            Ok(GossipKind::DataColumnSidecar { subnet_id: 100 })
        );
    }

    #[test]
    fn the_shape_and_encoding_are_exact() {
        for topic in [
            "",
            "/",
            "eth2/00000000/beacon_block/ssz_snappy",
            "/eth1/00000000/beacon_block/ssz_snappy",
            "/eth2/00000000/beacon_block",
            "/eth2/00000000/beacon_block/ssz_snappy/",
            "/eth2/00000000/beacon_block/ssz_snappy/extra",
            "//eth2/00000000/beacon_block/ssz_snappy",
        ] {
            assert_eq!(
                parse(topic),
                Err(TopicError::Shape(topic.to_owned())),
                "{topic:?}"
            );
        }
        for encoding in ["ssz", "SSZ_SNAPPY", ""] {
            let topic = format!("/eth2/00000000/beacon_block/{encoding}");
            assert_eq!(
                parse(&topic),
                Err(TopicError::Encoding(encoding.to_owned())),
                "{topic}"
            );
        }
    }

    #[test]
    fn each_kind_maps_to_its_message_type() {
        let kinds: Vec<ObjectKind> = every_kind()
            .into_iter()
            .map(GossipKind::object_kind)
            .collect();
        assert_eq!(
            kinds,
            [
                ObjectKind::SignedBeaconBlock,
                ObjectKind::SignedAggregateAndProof,
                ObjectKind::SingleAttestation,
                ObjectKind::SingleAttestation,
                ObjectKind::DataColumnSidecar,
                ObjectKind::DataColumnSidecar,
                ObjectKind::SignedExecutionPayloadBid,
                ObjectKind::SignedExecutionPayloadEnvelope,
                ObjectKind::PayloadAttestationMessage,
            ]
        );
    }

    #[test]
    fn errors_name_the_offending_part() {
        let err = parse("/eth2/00000000/voluntary_exit/ssz_snappy").unwrap_err();
        assert_eq!(err.to_string(), "unknown topic name: \"voluntary_exit\"");
        assert!(parse("x")
            .unwrap_err()
            .to_string()
            .contains("not an eth2 topic"));
        assert!(parse("/eth2/0000000X/beacon_block/ssz_snappy")
            .unwrap_err()
            .to_string()
            .contains("0000000X"));
        assert!(parse("/eth2/00000000/beacon_attestation_99/ssz_snappy")
            .unwrap_err()
            .to_string()
            .contains("beacon_attestation_99"));
        assert!(parse("/eth2/00000000/beacon_block/ssz")
            .unwrap_err()
            .to_string()
            .contains("ssz"));
    }
}
