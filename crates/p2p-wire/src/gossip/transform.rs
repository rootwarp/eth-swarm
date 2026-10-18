//! The `ssz_snappy` gossip encoding: SSZ, then snappy *block* compression (not the framing
//! format req/resp uses) (`phase0/p2p-interface.md` "Encodings").
//!
//! [`SnappyTransform::inbound`] bounds a message before decompressing it:
//!
//! 1. the compressed `data` must be at most `max_compressed_len(MAX_PAYLOAD_SIZE)`, the bound
//!    the spec puts on `Message.data` for every topic, so a longer one is refused unread;
//! 2. the length the snappy header declares (`snap::raw::decompress_len`, a varint read with
//!    no allocation) must be at most the topic's cap;
//! 3. only then is the block decompressed, into exactly the declared length.
//!
//! The cap is the smaller of `MAX_PAYLOAD_SIZE` and the topic's Gloas SSZ bound
//! ([`TopicCaps`]), as the spec requires of the uncompressed payload. It bounds the
//! decompressed length only: a valid encoding that compresses badly (longer than
//! `max_compressed_len(cap)`) but decompresses within the cap is accepted. A decompression
//! bomb therefore costs at most the cap in memory, never the length it declares.

use super::topic::{GossipKind, GossipTopic, TopicError};
use crate::rpc::codec::max_compressed_len;
use consensus_types::caps::{max_size_for, NetworkCaps, ObjectKind, MAX_PAYLOAD_SIZE};
use consensus_types::{EthSpec, ForkName};

/// The uncompressed cap of every topic kind, for one preset and network, at Gloas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopicCaps {
    beacon_block: usize,
    aggregate_and_proof: usize,
    attestation: usize,
    data_column_sidecar: usize,
    execution_payload_bid: usize,
    execution_payload: usize,
    payload_attestation_message: usize,
}

impl TopicCaps {
    /// The Gloas caps of preset `E` on `network` (whose blob schedule bounds the column
    /// sidecar): `consensus_types::caps::max_size_for` of each topic's message type.
    pub fn gloas<E: EthSpec>(network: &NetworkCaps) -> Self {
        let cap = |kind| {
            // Every topic type exists at Gloas, so `None` cannot happen; the transport limit is
            // the fallback all caps are below anyway.
            max_size_for::<E>(kind, ForkName::Gloas, network).unwrap_or(MAX_PAYLOAD_SIZE)
        };
        Self {
            beacon_block: cap(ObjectKind::SignedBeaconBlock),
            aggregate_and_proof: cap(ObjectKind::SignedAggregateAndProof),
            attestation: cap(ObjectKind::SingleAttestation),
            data_column_sidecar: cap(ObjectKind::DataColumnSidecar),
            execution_payload_bid: cap(ObjectKind::SignedExecutionPayloadBid),
            execution_payload: cap(ObjectKind::SignedExecutionPayloadEnvelope),
            payload_attestation_message: cap(ObjectKind::PayloadAttestationMessage),
        }
    }

    /// The uncompressed cap of `kind`'s messages.
    pub fn cap(&self, kind: GossipKind) -> usize {
        match kind {
            GossipKind::BeaconBlock => self.beacon_block,
            GossipKind::BeaconAggregateAndProof => self.aggregate_and_proof,
            GossipKind::BeaconAttestation { .. } => self.attestation,
            GossipKind::DataColumnSidecar { .. } => self.data_column_sidecar,
            GossipKind::ExecutionPayloadBid => self.execution_payload_bid,
            GossipKind::ExecutionPayload => self.execution_payload,
            GossipKind::PayloadAttestationMessage => self.payload_attestation_message,
        }
    }
}

/// Why a message's `data` was refused. Gossipsub reports every one as `TransformFailed`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransformError {
    /// The topic is not one this node handles.
    #[error("topic: {0}")]
    Topic(#[from] TopicError),
    /// The compressed data is longer than snappy's worst case for `MAX_PAYLOAD_SIZE`.
    #[error("compressed data is {len} bytes, over the {max}-byte bound")]
    FrameTooLarge {
        /// The compressed length.
        len: usize,
        /// `max_compressed_len(MAX_PAYLOAD_SIZE)`.
        max: usize,
    },
    /// The snappy header declares more than the topic's cap. Found before decompressing.
    #[error("snappy header declares {declared} bytes, over the {cap}-byte topic cap")]
    DeclaredTooLarge {
        /// The declared uncompressed length.
        declared: usize,
        /// The topic's cap.
        cap: usize,
    },
    /// Not a valid snappy block.
    #[error("invalid snappy block: {0}")]
    Snappy(String),
}

/// Snappy block compression bounded by each topic's cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnappyTransform {
    caps: TopicCaps,
}

impl SnappyTransform {
    /// A transform holding messages to `caps`.
    pub fn new(caps: TopicCaps) -> Self {
        Self { caps }
    }

    /// The caps it enforces.
    pub fn caps(&self) -> &TopicCaps {
        &self.caps
    }

    /// Decompresses the `data` of a message received on `topic`, bounded as the module docs
    /// describe.
    ///
    /// # Errors
    ///
    /// [`TransformError::Topic`] for a topic this node does not handle, else
    /// [`TransformError::FrameTooLarge`], [`TransformError::DeclaredTooLarge`] or
    /// [`TransformError::Snappy`], in the order they are checked.
    pub fn inbound(&self, topic: &str, data: &[u8]) -> Result<Vec<u8>, TransformError> {
        let kind = GossipTopic::parse(topic)?.kind;
        decompress_bounded(data, self.caps.cap(kind))
    }

    /// Compresses `ssz` for `topic`.
    ///
    /// # Errors
    ///
    /// [`TransformError::Topic`] for a topic this node does not handle,
    /// [`TransformError::DeclaredTooLarge`] if `ssz` is over the topic's cap.
    pub fn outbound(&self, topic: &str, ssz: &[u8]) -> Result<Vec<u8>, TransformError> {
        let cap = self.caps.cap(GossipTopic::parse(topic)?.kind);
        if ssz.len() > cap {
            return Err(TransformError::DeclaredTooLarge {
                declared: ssz.len(),
                cap,
            });
        }
        snap::raw::Encoder::new()
            .compress_vec(ssz)
            .map_err(|e| TransformError::Snappy(e.to_string()))
    }
}

/// Decompresses one snappy block of at most `cap` bytes (clamped to `MAX_PAYLOAD_SIZE`): the
/// compressed data is held to `max_compressed_len(MAX_PAYLOAD_SIZE)`, and a block declaring
/// more than `cap` is refused from its header (see the module docs).
///
/// # Errors
///
/// [`TransformError::FrameTooLarge`], [`TransformError::DeclaredTooLarge`] or
/// [`TransformError::Snappy`].
pub fn decompress_bounded(data: &[u8], cap: usize) -> Result<Vec<u8>, TransformError> {
    let cap = cap.min(MAX_PAYLOAD_SIZE);
    let max = max_compressed_len(MAX_PAYLOAD_SIZE);
    if data.len() > max {
        return Err(TransformError::FrameTooLarge {
            len: data.len(),
            max,
        });
    }
    let declared =
        snap::raw::decompress_len(data).map_err(|e| TransformError::Snappy(e.to_string()))?;
    if declared > cap {
        return Err(TransformError::DeclaredTooLarge { declared, cap });
    }
    snap::raw::Decoder::new()
        .decompress_vec(data)
        .map_err(|e| TransformError::Snappy(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::Mainnet;

    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    fn transform() -> SnappyTransform {
        SnappyTransform::new(TopicCaps::gloas::<Mainnet>(
            &NetworkCaps::from_blob_schedule(21, &[]),
        ))
    }

    #[test]
    fn outbound_then_inbound_is_the_identity() {
        let t = transform();
        let ssz: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let data = t.outbound(BLOCK, &ssz).unwrap();
        assert_eq!(t.inbound(BLOCK, &data).unwrap(), ssz);
        assert_eq!(
            t.inbound(BLOCK, &t.outbound(BLOCK, &[]).unwrap()).unwrap(),
            b""
        );
    }

    #[test]
    fn an_unknown_topic_is_refused_before_the_data_is_read() {
        let t = transform();
        let topic = "/eth2/00000000/voluntary_exit/ssz_snappy";
        assert_eq!(
            t.inbound(topic, &[0xff; 4]),
            Err(TransformError::Topic(TopicError::UnknownName(
                "voluntary_exit".into()
            )))
        );
        assert!(matches!(
            t.outbound(topic, b"x"),
            Err(TransformError::Topic(_))
        ));
    }

    #[test]
    fn outbound_refuses_data_over_the_cap() {
        let t = transform();
        let topic = "/eth2/00000000/execution_payload_bid/ssz_snappy";
        let cap = t.caps().cap(GossipKind::ExecutionPayloadBid);
        assert_eq!(
            t.outbound(topic, &vec![0; cap + 1]),
            Err(TransformError::DeclaredTooLarge {
                declared: cap + 1,
                cap
            })
        );
    }

    /// A valid block that compresses badly: one 1-byte literal per byte, about twice the
    /// output. It is longer than `max_compressed_len(cap)` but decompresses within the cap, so
    /// it is accepted: only the decompressed length is held to the topic cap.
    #[test]
    fn an_inefficient_encoding_within_the_cap_is_accepted() {
        let t = transform();
        let topic = "/eth2/00000000/beacon_aggregate_and_proof/ssz_snappy";
        let cap = t.caps().cap(GossipKind::BeaconAggregateAndProof);
        let ssz: Vec<u8> = (0..cap).map(|i| (i % 251) as u8).collect();
        let mut data = Vec::new();
        crate::rpc::codec::encode_varint(cap as u64, &mut data);
        for &b in &ssz {
            // Literal tag: (length - 1) << 2 | 0b00.
            data.extend_from_slice(&[0x00, b]);
        }
        assert!(data.len() > max_compressed_len(cap));
        assert_eq!(t.inbound(topic, &data), Ok(ssz));
    }

    #[test]
    fn corrupt_blocks_are_refused() {
        let t = transform();
        // A header with no body; a truncated varint; a body shorter than declared.
        for data in [&[0x05][..], &[0x80][..], &[0x0a, 0x08, b'a', b'b'][..]] {
            assert!(
                matches!(t.inbound(BLOCK, data), Err(TransformError::Snappy(_))),
                "{data:?}"
            );
        }
        // The framing format (what req/resp uses) is not a raw block.
        let mut framed = Vec::new();
        {
            use std::io::Write as _;
            let mut w = snap::write::FrameEncoder::new(&mut framed);
            w.write_all(b"hello").unwrap();
        }
        assert!(t.inbound(BLOCK, &framed).is_err());
    }

    #[test]
    fn the_cap_never_exceeds_the_payload_limit() {
        let caps = transform().caps;
        assert!(caps.cap(GossipKind::BeaconBlock) <= MAX_PAYLOAD_SIZE);
        // A caller's cap over the limit is clamped to it.
        let mut bomb = Vec::new();
        crate::rpc::codec::encode_varint(MAX_PAYLOAD_SIZE as u64 + 1, &mut bomb);
        assert_eq!(
            decompress_bounded(&bomb, usize::MAX),
            Err(TransformError::DeclaredTooLarge {
                declared: MAX_PAYLOAD_SIZE + 1,
                cap: MAX_PAYLOAD_SIZE
            })
        );
    }

    #[test]
    fn errors_read_as_their_cause() {
        let e = TransformError::DeclaredTooLarge {
            declared: 9,
            cap: 8,
        };
        assert_eq!(
            e.to_string(),
            "snappy header declares 9 bytes, over the 8-byte topic cap"
        );
        let e = TransformError::FrameTooLarge { len: 9, max: 8 };
        assert_eq!(
            e.to_string(),
            "compressed data is 9 bytes, over the 8-byte bound"
        );
        assert!(TransformError::Topic(TopicError::Shape("x".into()))
            .to_string()
            .starts_with("topic: "));
    }
}
