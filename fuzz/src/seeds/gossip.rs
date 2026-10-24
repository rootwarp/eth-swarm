//! The gossip seeds (`gossip_transform`, `message_id`): `[topic length][topic][data]`.
//!
//! Valid messages on every topic kind (the testkit blocks under each digest of the Sepolia
//! schedule and, for `gossip_transform`, the vector blocks on the Gloas `beacon_block`; a message
//! at its cap for the small caps, and the column sidecar at the cap of each Fulu digest's blob
//! limit), and the refusals:
//! a snappy header declaring one byte over the topic's cap, over `MAX_PAYLOAD_SIZE`, 4 GiB and
//! more than 4 GiB, an 11-byte header varint, a block cut short or with a byte after it, a
//! decompression bomb within the cap, the req/resp framing format instead of a raw block, a
//! digest off the schedule and a Gloas topic under a Fulu digest (no cap), an unknown topic name, an upper-case digest, an empty and a cut-short
//! topic, and data that is no snappy block at all (the invalid-snappy message-id).

use super::{Seed, VectorBlock, OVER_4GIB, VECTOR_PREFIX};
use crate::gossip::{gossip_digests, topic_caps};
use crate::{message_input, E};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use p2p_wire::gossip::{GossipKind, GossipTopic};
use p2p_wire::rpc::codec::encode_varint;
use p2p_wire::testkit;
use ssz::Encode;
use std::io::Write as _;

/// 1 MiB of zeros: within the block cap, about 48 KiB compressed.
const BOMB_LEN: usize = 1 << 20;

fn compress(ssz: &[u8]) -> Vec<u8> {
    snap::raw::Encoder::new()
        .compress_vec(ssz)
        .expect("a block within snappy's limit")
}

/// A snappy block header declaring `declared` bytes, then 16 zero bytes of body.
fn declaring(declared: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_varint(declared, &mut out);
    out.extend_from_slice(&[0; 16]);
    out
}

fn topic(digest: [u8; 4], kind: GossipKind) -> String {
    GossipTopic::new(digest, kind).to_string()
}

/// Every gossip seed: the shared ones for both targets, the vector blocks for
/// `gossip_transform` only.
pub fn all(seeds: &mut Vec<Seed>, vector_blocks: &[VectorBlock]) {
    let shared = messages();
    for target in ["gossip_transform", "message_id"] {
        for (name, bytes) in &shared {
            seeds.push(Seed {
                target,
                slow: false,
                name: name.clone(),
                bytes: bytes.clone(),
            });
        }
    }
    let block = topic(digest(3), GossipKind::BeaconBlock);
    for vector in vector_blocks {
        seeds.push(Seed {
            target: "gossip_transform",
            slow: false,
            name: format!("{VECTOR_PREFIX}{}", vector.case),
            bytes: message_input(&block, &compress(&vector.ssz)),
        });
    }
}

/// The `n`th digest of the Sepolia schedule: 0 Fulu, 1 and 2 its BPO digests, 3 Gloas.
fn digest(n: usize) -> [u8; 4] {
    gossip_digests()[n].0
}

/// `(name, input)` of the seeds both gossip targets share.
fn messages() -> Vec<(String, Vec<u8>)> {
    let caps = topic_caps();
    let gloas = topic(digest(3), GossipKind::BeaconBlock);
    let gloas_block = compress(&testkit::gloas_block::<E>(3).as_ssz_bytes());
    let fulu_block = compress(&testkit::fulu_block::<E>(1).as_ssz_bytes());
    let mut out = vec![
        (
            "block-gloas-valid".to_owned(),
            gloas.clone(),
            gloas_block.clone(),
        ),
        (
            "block-fulu-digest-valid".to_owned(),
            topic(digest(0), GossipKind::BeaconBlock),
            fulu_block.clone(),
        ),
        (
            "block-fulu-bpo1-digest-valid".to_owned(),
            topic(digest(1), GossipKind::BeaconBlock),
            fulu_block.clone(),
        ),
        (
            "block-fulu-bpo2-digest-valid".to_owned(),
            topic(digest(2), GossipKind::BeaconBlock),
            fulu_block,
        ),
        (
            "bid-on-fulu-digest".to_owned(),
            topic(digest(2), GossipKind::ExecutionPayloadBid),
            compress(b"x"),
        ),
        (
            "block-fulu-block-on-gloas-topic".to_owned(),
            gloas.clone(),
            compress(&testkit::fulu_block::<E>(2).as_ssz_bytes()),
        ),
        (
            "block-unsubscribed-digest".to_owned(),
            topic(testkit::UNKNOWN_DIGEST, GossipKind::BeaconBlock),
            gloas_block.clone(),
        ),
        (
            "block-declares-over-10mib".to_owned(),
            gloas.clone(),
            declaring(MAX_PAYLOAD_SIZE as u64 + 1),
        ),
        (
            "block-declares-4gib".to_owned(),
            gloas.clone(),
            declaring(u64::from(u32::MAX)),
        ),
        (
            "block-declares-over-4gib".to_owned(),
            gloas.clone(),
            declaring(OVER_4GIB as u64),
        ),
        (
            "block-declares-u64-max".to_owned(),
            gloas.clone(),
            declaring(u64::MAX),
        ),
        (
            "block-varint-11-bytes".to_owned(),
            gloas.clone(),
            [&[0x80; 10][..], &[0x01]].concat(),
        ),
        (
            "block-truncated".to_owned(),
            gloas.clone(),
            gloas_block[..gloas_block.len() - 1].to_vec(),
        ),
        (
            "block-trailing-byte".to_owned(),
            gloas.clone(),
            [&gloas_block[..], &[0]].concat(),
        ),
        (
            "block-snappy-bomb-1mib".to_owned(),
            gloas.clone(),
            compress(&vec![0; BOMB_LEN]),
        ),
        (
            "block-framing-format".to_owned(),
            gloas.clone(),
            framed(&testkit::gloas_block::<E>(3).as_ssz_bytes()),
        ),
        ("block-empty-data".to_owned(), gloas.clone(), Vec::new()),
        (
            "block-not-snappy".to_owned(),
            gloas.clone(),
            vec![0xff, 0x00, 0x01],
        ),
        (
            "topic-unknown-name".to_owned(),
            "/eth2/669e6c11/voluntary_exit/ssz_snappy".to_owned(),
            compress(b"x"),
        ),
        (
            "topic-upper-case-digest".to_owned(),
            "/eth2/669E6C11/beacon_block/ssz_snappy".to_owned(),
            gloas_block.clone(),
        ),
        ("topic-empty".to_owned(), String::new(), compress(b"x")),
    ];
    // Every other kind: an empty message, and a header one byte over its cap; the small caps
    // also a message of zeros at the cap.
    let kinds = [
        ("aggregate", GossipKind::BeaconAggregateAndProof),
        (
            "attestation-0",
            GossipKind::BeaconAttestation { subnet_id: 0 },
        ),
        (
            "attestation-63",
            GossipKind::BeaconAttestation { subnet_id: 63 },
        ),
        ("column-0", GossipKind::DataColumnSidecar { subnet_id: 0 }),
        (
            "column-127",
            GossipKind::DataColumnSidecar { subnet_id: 127 },
        ),
        ("bid", GossipKind::ExecutionPayloadBid),
        ("payload", GossipKind::ExecutionPayload),
        ("payload-attestation", GossipKind::PayloadAttestationMessage),
        ("block", GossipKind::BeaconBlock),
    ];
    for (name, kind) in kinds {
        let text = topic(digest(3), kind);
        let cap = caps.cap_at(digest(3), kind).expect("a Gloas topic");
        if kind != GossipKind::BeaconBlock {
            out.push((format!("{name}-empty"), text.clone(), compress(&[])));
        }
        out.push((
            format!("{name}-over-cap"),
            text.clone(),
            declaring(cap as u64 + 1),
        ));
        if cap <= SMALL_CAP {
            out.push((format!("{name}-at-cap"), text, compress(&vec![0; cap])));
        }
    }
    // The column sidecar under each Fulu digest, at and over the cap of its blob limit.
    for n in 0..3 {
        let column = GossipKind::DataColumnSidecar { subnet_id: 0 };
        let cap = caps.cap_at(digest(n), column).expect("a Fulu topic");
        let text = topic(digest(n), column);
        out.push((
            format!("column-0-fulu-{}-at-cap", n + 1),
            text.clone(),
            compress(&vec![0; cap]),
        ));
        out.push((
            format!("column-0-fulu-{}-over-cap", n + 1),
            text,
            declaring(cap as u64 + 1),
        ));
    }
    let mut inputs: Vec<(String, Vec<u8>)> = out
        .into_iter()
        .map(|(name, topic, data)| (name, message_input(&topic, &data)))
        .collect();
    // A topic length byte claiming more than the input holds.
    let whole = message_input(&gloas, &gloas_block);
    inputs.push(("topic-cut-short".to_owned(), whole[..20].to_vec()));
    inputs
}

/// A cap a message of zeros at it compresses well under the targets' `-max_len`.
const SMALL_CAP: usize = 1 << 18;

/// The req/resp framing format (stream identifier, frames) of `ssz`: not a raw snappy block.
fn framed(ssz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = snap::write::FrameEncoder::new(&mut out);
    w.write_all(ssz).expect("in memory");
    w.flush().expect("in memory");
    drop(w);
    out
}
