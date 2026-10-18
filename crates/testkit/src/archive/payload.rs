//! Gossip payloads: snappy block-compressed SSZ (`phase0/p2p-interface.md`, gossip encoding),
//! bounded, decompressed and decoded by the fork of the object's own slot to read its slot and
//! block root.

use super::names::TopicKind;
use consensus_types::caps::{NetworkCaps, MAX_PAYLOAD_SIZE};
use consensus_types::codec::DecodeError;
use consensus_types::forked::{DataColumnSidecar, SignedBeaconBlock};
use consensus_types::primitives::{Root, Slot};
use consensus_types::{EthSpec, ForkSchedule};
use p2p_wire::rpc::codec::max_compressed_len;
use tree_hash::TreeHash;

/// What decoding a payload needs from the network: its fork schedule and column caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParams {
    /// Which fork's shape an object at a slot has.
    pub schedule: ForkSchedule,
    /// The column sidecar cap of the network's blob schedule.
    pub caps: NetworkCaps,
}

/// The slot and block root a payload is filed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// The object's slot: `message.slot` of a block, the block slot of a sidecar.
    pub slot: Slot,
    /// The block root: `hash_tree_root(message)` of a block, the root of the sidecar's block.
    pub root: Root,
}

/// A payload the archive refuses. The capture goes on.
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    /// More compressed bytes than `max_compressed_len(MAX_PAYLOAD_SIZE)`.
    #[error("{len} compressed bytes, over the gossip bound of {max}")]
    CompressedTooLarge {
        /// The payload length.
        len: usize,
        /// The bound.
        max: usize,
    },
    /// The snappy header announces more than `MAX_PAYLOAD_SIZE` bytes.
    #[error("{len} uncompressed bytes, over MAX_PAYLOAD_SIZE ({max})")]
    TooLarge {
        /// The announced length.
        len: usize,
        /// The bound.
        max: usize,
    },
    /// Not snappy block-compressed data.
    #[error("snappy: {0}")]
    Snappy(#[from] snap::Error),
    /// The SSZ does not decode with the shape of its slot's fork.
    #[error("ssz: {0}")]
    Decode(#[from] DecodeError),
    /// A slot TOML cannot hold (above `i64::MAX`).
    #[error("slot {0} is out of range")]
    SlotOutOfRange(Slot),
    /// The topic is not one the capture subscribed to.
    #[error("topic {0:?} is not subscribed by this capture")]
    Unsubscribed(String),
    /// The segment already holds a file of this topic, slot and root.
    #[error("{path} is already archived ({})", if *identical { "same bytes" } else { "different bytes" })]
    Duplicate {
        /// The file's path in the segment.
        path: String,
        /// Whether the bytes are the archived ones.
        identical: bool,
    },
}

/// Decompresses a gossip payload after checking both length bounds.
pub fn decompress(payload: &[u8]) -> Result<Vec<u8>, PayloadError> {
    let max = max_compressed_len(MAX_PAYLOAD_SIZE);
    if payload.len() > max {
        return Err(PayloadError::CompressedTooLarge {
            len: payload.len(),
            max,
        });
    }
    let len = snap::raw::decompress_len(payload)?;
    if len > MAX_PAYLOAD_SIZE {
        return Err(PayloadError::TooLarge {
            len,
            max: MAX_PAYLOAD_SIZE,
        });
    }
    Ok(snap::raw::Decoder::new().decompress_vec(payload)?)
}

/// The slot and block root of a `kind` payload, decoded by the fork of its own slot.
pub fn decode_payload<E: EthSpec>(
    kind: TopicKind,
    payload: &[u8],
    chain: &ChainParams,
) -> Result<Decoded, PayloadError> {
    let ssz = decompress(payload)?;
    let decoded = match kind {
        TopicKind::BeaconBlock => {
            let block = SignedBeaconBlock::<E>::from_ssz_bytes_by_slot(&ssz, &chain.schedule)?;
            let root = match &block {
                SignedBeaconBlock::Fulu(b) => b.message.tree_hash_root(),
                SignedBeaconBlock::Gloas(b) => b.message.tree_hash_root(),
            };
            Decoded {
                slot: block.slot(),
                root,
            }
        }
        TopicKind::DataColumnSidecar { .. } => {
            let sidecar =
                DataColumnSidecar::<E>::from_ssz_bytes_by_slot(&ssz, &chain.schedule, &chain.caps)?;
            let root = match &sidecar {
                DataColumnSidecar::Fulu(s) => s.signed_block_header.message.tree_hash_root(),
                DataColumnSidecar::Gloas(s) => s.beacon_block_root,
            };
            Decoded {
                slot: sidecar.slot(),
                root,
            }
        }
    };
    if i64::try_from(decoded.slot).is_err() {
        return Err(PayloadError::SlotOutOfRange(decoded.slot));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::fixtures::{self, Spec, GLOAS_SLOT};

    const BLOCK: TopicKind = TopicKind::BeaconBlock;
    const COLUMN: TopicKind = TopicKind::DataColumnSidecar { subnet: 3 };

    #[test]
    fn block_root_and_slot_in_both_forks() {
        for slot in [1, GLOAS_SLOT - 1, GLOAS_SLOT, GLOAS_SLOT + 5] {
            let (payload, root) = fixtures::block(slot, 9);
            let got = decode_payload::<Spec>(BLOCK, &payload, &fixtures::chain()).unwrap();
            assert_eq!(got, Decoded { slot, root }, "slot {slot}");
        }
    }

    #[test]
    fn column_block_root_in_both_forks() {
        // Gloas carries the block root; Fulu hashes the header it carries. Either way the
        // column is filed under its block's root.
        for slot in [2, GLOAS_SLOT - 1, GLOAS_SLOT, GLOAS_SLOT + 1] {
            let (_, block_root) = fixtures::block(slot, 7);
            let (payload, root) = fixtures::column(slot, 7, 3);
            assert_eq!(root, block_root, "slot {slot}");
            let got = decode_payload::<Spec>(COLUMN, &payload, &fixtures::chain()).unwrap();
            assert_eq!(got, Decoded { slot, root }, "slot {slot}");
        }
    }

    #[test]
    fn decodes_by_the_objects_slot_not_its_shape() {
        // A Fulu-shaped block at a Gloas slot is refused.
        let mut fulu = p2p_wire::testkit::fulu_block::<Spec>(GLOAS_SLOT);
        fulu.message.slot = GLOAS_SLOT;
        let payload = fixtures::snappy(&ssz::Encode::as_ssz_bytes(&fulu));
        let err = decode_payload::<Spec>(BLOCK, &payload, &fixtures::chain()).unwrap_err();
        assert!(matches!(err, PayloadError::Decode(_)), "{err}");
    }

    #[test]
    fn a_block_on_a_column_topic_is_refused() {
        let (payload, _) = fixtures::block(3, 0);
        let err = decode_payload::<Spec>(COLUMN, &payload, &fixtures::chain()).unwrap_err();
        assert!(matches!(err, PayloadError::Decode(_)), "{err}");
    }

    #[test]
    fn bounds_and_garbage() {
        let chain = fixtures::chain();
        let max = max_compressed_len(MAX_PAYLOAD_SIZE);
        let err = decode_payload::<Spec>(BLOCK, &vec![0; max + 1], &chain).unwrap_err();
        assert!(matches!(err, PayloadError::CompressedTooLarge { len, .. } if len == max + 1));

        // A snappy header announcing one byte over MAX_PAYLOAD_SIZE.
        let mut header = Vec::new();
        p2p_wire::rpc::codec::encode_varint(MAX_PAYLOAD_SIZE as u64 + 1, &mut header);
        let err = decompress(&header).unwrap_err();
        assert!(matches!(err, PayloadError::TooLarge { len, .. } if len == MAX_PAYLOAD_SIZE + 1));

        let err = decompress(&[0xff; 16]).unwrap_err();
        assert!(matches!(err, PayloadError::Snappy(_)), "{err}");

        let err = decode_payload::<Spec>(BLOCK, &fixtures::snappy(&[1, 2, 3]), &chain);
        assert!(matches!(err, Err(PayloadError::Decode(_))));
    }

    #[test]
    fn a_slot_toml_cannot_hold_is_refused() {
        let slot = i64::MAX as u64 + 1;
        let (payload, _) = fixtures::block(slot, 0);
        let err = decode_payload::<Spec>(BLOCK, &payload, &fixtures::chain()).unwrap_err();
        assert!(
            matches!(err, PayloadError::SlotOutOfRange(s) if s == slot),
            "{err}"
        );
    }
}
