//! The Altair gossip `message-id` (`altair/p2p-interface.md` "Topics and messages"; Gloas does
//! not change it):
//!
//! - if `data` has a valid snappy decompression,
//!   `SHA256(MESSAGE_DOMAIN_VALID_SNAPPY + uint_to_bytes(Uint64(len(topic))) + topic +
//!   snappy_decompress(data))[:20]`;
//! - otherwise `SHA256(MESSAGE_DOMAIN_INVALID_SNAPPY + uint_to_bytes(Uint64(len(topic))) +
//!   topic + data)[:20]`.
//!
//! The topic length is a little-endian `Uint64`. [`compute_message_id`] is the rule on a raw
//! message. Gossipsub computes the id after its data transform has decompressed the message, so
//! its hook is [`message_id_of_decompressed`], the valid-snappy branch over the decompressed
//! bytes (a message that does not decompress never gets an id: the transform refuses it).

use super::transform::decompress_bounded;
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use sha2::{Digest, Sha256};

/// `MESSAGE_DOMAIN_INVALID_SNAPPY` (`phase0` constants).
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
/// `MESSAGE_DOMAIN_VALID_SNAPPY` (`phase0` constants).
pub const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
/// A message-id is 20 bytes; clients MUST reject other sizes where relevant.
pub const MESSAGE_ID_LEN: usize = 20;

/// A gossip message-id.
pub type MessageId = [u8; MESSAGE_ID_LEN];

/// The message-id of a message with `data`, as received, on `topic`.
///
/// "A valid snappy decompression" is bounded by `MAX_PAYLOAD_SIZE`: no valid message is larger,
/// so data declaring more takes the invalid-snappy branch rather than being decompressed.
pub fn compute_message_id(topic: &str, data: &[u8]) -> MessageId {
    match decompress_bounded(data, MAX_PAYLOAD_SIZE) {
        Ok(decompressed) => message_id_of_decompressed(topic, &decompressed),
        Err(_) => id(MESSAGE_DOMAIN_INVALID_SNAPPY, topic, data),
    }
}

/// The message-id of a message on `topic` whose data decompressed to `decompressed`.
pub fn message_id_of_decompressed(topic: &str, decompressed: &[u8]) -> MessageId {
    id(MESSAGE_DOMAIN_VALID_SNAPPY, topic, decompressed)
}

fn id(domain: [u8; 4], topic: &str, data: &[u8]) -> MessageId {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update((topic.len() as u64).to_le_bytes())
        .chain_update(topic.as_bytes())
        .chain_update(data)
        .finalize();
    let mut out = [0u8; MESSAGE_ID_LEN];
    out.copy_from_slice(&digest[..MESSAGE_ID_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOPIC: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    fn hex(id: MessageId) -> String {
        id.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Vectors computed independently (Python hashlib) from the spec formula.
    #[test]
    fn valid_snappy_hashes_the_decompressed_data_under_its_domain() {
        let data = snap::raw::Encoder::new().compress_vec(b"hello").unwrap();
        let id = compute_message_id(TOPIC, &data);
        assert_eq!(hex(id), "be6c44734bb9094a08a18c221db77773fea4285b");
        assert_eq!(id, message_id_of_decompressed(TOPIC, b"hello"));
    }

    #[test]
    fn invalid_snappy_hashes_the_raw_data_under_its_domain() {
        let raw = [0xff, 0x00, 0x01];
        assert_eq!(
            hex(compute_message_id(TOPIC, &raw)),
            "63645138d5b65c7d91245232f3619eb775b23182"
        );
    }

    #[test]
    fn the_topic_is_part_of_the_id() {
        let data = snap::raw::Encoder::new().compress_vec(b"x").unwrap();
        let other = "/eth2/00000001/beacon_block/ssz_snappy";
        assert_ne!(
            compute_message_id(TOPIC, &data),
            compute_message_id(other, &data)
        );
    }

    #[test]
    fn data_declaring_more_than_the_payload_limit_takes_the_invalid_branch() {
        let mut bomb = Vec::new();
        crate::rpc::codec::encode_varint(MAX_PAYLOAD_SIZE as u64 + 1, &mut bomb);
        assert_eq!(
            compute_message_id(TOPIC, &bomb),
            id(MESSAGE_DOMAIN_INVALID_SNAPPY, TOPIC, &bomb)
        );
    }
}
