//! The gossip domain's wire format (consensus-specs v1.7.0-beta.4, `phase0/p2p-interface.md`
//! "The gossip domain: gossipsub", `altair/p2p-interface.md` "Topics and messages",
//! `gloas/p2p-interface.md` "The gossip domain: gossipsub"), with no libp2p dependency.
//!
//! - [`topic`]: [`GossipTopic`], `/eth2/<fork_digest>/<name>/ssz_snappy` with a lowercase hex
//!   digest, for every topic this node handles.
//! - [`transform`]: the snappy block decompression of a message's `data`, bounded by the topic's
//!   SSZ cap ([`TopicCaps`]) before anything is decompressed.
//! - [`message_id`]: the Altair `message-id`.
//!
//! `cl-p2p` adapts these to gossipsub (its `DataTransform` and `message_id_fn`).

pub mod message_id;
pub mod topic;
pub mod transform;

pub use message_id::{compute_message_id, message_id_of_decompressed, MessageId};
pub use topic::{GossipKind, GossipTopic, TopicError};
pub use transform::{SnappyTransform, TopicCaps, TransformError};

#[cfg(test)]
use consensus_types::caps::{max_size_for, NetworkCaps, ObjectKind};
#[cfg(test)]
use consensus_types::{ForkName, Mainnet, Minimal};

/// Every exit-14 topic parses and formats, and its transform cap is its Gloas SSZ bound: the
/// spec's size constants where `gloas/p2p-interface.md` defines one, else the consensus-types
/// bound.
#[test]
fn b9_topics() {
    let network = NetworkCaps::from_blob_schedule(9, &[]);
    let mainnet = TopicCaps::gloas::<Mainnet>(&network);
    let minimal = TopicCaps::gloas::<Minimal>(&network);
    let gloas = |kind| max_size_for::<Mainnet>(kind, ForkName::Gloas, &network).unwrap();
    let digest = [0x12, 0x34, 0xab, 0xcd];
    // (topic name, kind, Mainnet cap)
    let table = [
        (
            "beacon_block",
            GossipKind::BeaconBlock,
            gloas(ObjectKind::SignedBeaconBlock),
        ),
        // MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE (gloas/p2p-interface.md L78).
        (
            "execution_payload_bid",
            GossipKind::ExecutionPayloadBid,
            196_932,
        ),
        (
            "execution_payload",
            GossipKind::ExecutionPayload,
            gloas(ObjectKind::SignedExecutionPayloadEnvelope),
        ),
        (
            "payload_attestation_message",
            GossipKind::PayloadAttestationMessage,
            gloas(ObjectKind::PayloadAttestationMessage),
        ),
        // MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE (gloas/p2p-interface.md L76).
        (
            "beacon_aggregate_and_proof",
            GossipKind::BeaconAggregateAndProof,
            16_829,
        ),
        (
            "beacon_attestation_0",
            GossipKind::BeaconAttestation { subnet_id: 0 },
            gloas(ObjectKind::SingleAttestation),
        ),
        (
            "beacon_attestation_63",
            GossipKind::BeaconAttestation { subnet_id: 63 },
            gloas(ObjectKind::SingleAttestation),
        ),
        (
            "data_column_sidecar_0",
            GossipKind::DataColumnSidecar { subnet_id: 0 },
            consensus_types::caps::compute_max_data_column_sidecar_size::<Mainnet>(&network)
                as usize,
        ),
        (
            "data_column_sidecar_127",
            GossipKind::DataColumnSidecar { subnet_id: 127 },
            gloas(ObjectKind::DataColumnSidecar),
        ),
    ];
    for (name, kind, cap) in table {
        let text = format!("/eth2/1234abcd/{name}/ssz_snappy");
        let topic = GossipTopic::parse(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(topic, GossipTopic::new(digest, kind), "{text}");
        assert_eq!(topic.to_string(), text);
        assert_eq!(mainnet.cap(kind), cap, "{name}");
        assert!(cap <= consensus_types::caps::MAX_PAYLOAD_SIZE, "{name}");
        assert!(minimal.cap(kind) <= cap, "{name}: minimal above mainnet");
    }
    // The bid bound is the same in both presets.
    assert_eq!(minimal.cap(GossipKind::ExecutionPayloadBid), 196_932);
    // The column cap follows the network's blob schedule: 21 blobs at most on Sepolia and
    // Hoodi give 44,072 bytes.
    let sepolia = TopicCaps::gloas::<Mainnet>(&NetworkCaps::from_blob_schedule(21, &[]));
    assert_eq!(
        sepolia.cap(GossipKind::DataColumnSidecar { subnet_id: 5 }),
        44_072
    );
}

/// Parse and format round-trip for every kind; an upper-case digest or a name this node does
/// not handle is refused.
#[test]
fn topic_roundtrip() {
    let digest = [0xab, 0x01, 0x00, 0xff];
    for kind in topic::tests::every_kind() {
        let topic = GossipTopic::new(digest, kind);
        let text = topic.to_string();
        assert_eq!(GossipTopic::parse(&text), Ok(topic), "{text}");
        assert_eq!(text.parse::<GossipTopic>(), Ok(topic), "{text}");
    }
    assert_eq!(
        GossipTopic::new(digest, GossipKind::BeaconBlock).to_string(),
        "/eth2/ab0100ff/beacon_block/ssz_snappy"
    );
    for upper in [
        "/eth2/AB0100FF/beacon_block/ssz_snappy",
        "/eth2/Ab0100ff/beacon_block/ssz_snappy",
    ] {
        assert!(
            matches!(GossipTopic::parse(upper), Err(TopicError::ForkDigest(_))),
            "{upper}"
        );
    }
    for unknown in [
        "/eth2/ab0100ff/voluntary_exit/ssz_snappy",
        "/eth2/ab0100ff/beacon_blocks/ssz_snappy",
        "/eth2/ab0100ff/Beacon_block/ssz_snappy",
        "/eth2/ab0100ff//ssz_snappy",
    ] {
        assert!(
            matches!(GossipTopic::parse(unknown), Err(TopicError::UnknownName(_))),
            "{unknown}"
        );
    }
}

/// A snappy block whose declared length is over the topic cap is refused from its header,
/// before anything is decompressed or allocated for it.
#[test]
fn transform_bomb() {
    let network = NetworkCaps::from_blob_schedule(9, &[]);
    let transform = SnappyTransform::new(TopicCaps::gloas::<Mainnet>(&network));
    let topic = "/eth2/1234abcd/beacon_aggregate_and_proof/ssz_snappy";
    let cap = transform.caps().cap(GossipKind::BeaconAggregateAndProof);

    // At the cap: decompresses.
    let at_cap = snap::raw::Encoder::new()
        .compress_vec(&vec![0u8; cap])
        .unwrap();
    assert_eq!(transform.inbound(topic, &at_cap).unwrap().len(), cap);

    // One byte over: refused with the declared length, which only the header check reports.
    let over = snap::raw::Encoder::new()
        .compress_vec(&vec![0u8; cap + 1])
        .unwrap();
    assert_eq!(
        transform.inbound(topic, &over),
        Err(TransformError::DeclaredTooLarge {
            declared: cap + 1,
            cap
        })
    );

    // A bomb: a header declaring the snappy maximum (2^32 - 1) and a few bytes of body. A
    // decompressor would size its output from the header first; this is refused before.
    let mut bomb = Vec::new();
    crate::rpc::codec::encode_varint(u64::from(u32::MAX), &mut bomb);
    bomb.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        transform.inbound(topic, &bomb),
        Err(TransformError::DeclaredTooLarge {
            declared: u32::MAX as usize,
            cap
        })
    );

    // Compressed data longer than snappy's worst case for MAX_PAYLOAD_SIZE is refused unread:
    // the compressed bound is global, the topic cap bounds the decompressed length.
    let max = crate::rpc::codec::max_compressed_len(consensus_types::caps::MAX_PAYLOAD_SIZE);
    let long = vec![0u8; max + 1];
    assert_eq!(
        transform.inbound(topic, &long),
        Err(TransformError::FrameTooLarge {
            len: long.len(),
            max
        })
    );
}
