//! The `ssz_snappy` gossip encoding: SSZ, then snappy *block* compression (not the framing
//! format req/resp uses) (`phase0/p2p-interface.md` "Encodings").
//!
//! [`SnappyTransform::inbound`] bounds a message before decompressing it:
//!
//! 1. the topic's fork digest and kind must have a cap ([`TopicCaps::cap_at`]), else the
//!    message is refused unread ([`TransformError::NoCap`]);
//! 2. the compressed `data` must be at most `max_compressed_len(MAX_PAYLOAD_SIZE)`, the bound
//!    the spec puts on `Message.data` for every topic, so a longer one is refused unread;
//! 3. the length the snappy header declares (`snap::raw::decompress_len`, a varint read with
//!    no allocation) must be at most the topic's cap;
//! 4. only then is the block decompressed, into exactly the declared length.
//!
//! The cap is the smaller of `MAX_PAYLOAD_SIZE` and the SSZ bound of the topic's message type
//! at the fork its digest names, as the spec requires of the uncompressed payload. The digest
//! names a fork and, from Fulu, the blob parameters in force (`fulu/beacon-chain.md`
//! `compute_fork_digest`, which changes at each BPO epoch), so [`TopicCaps::from_schedule`]
//! caps each digest of the schedule on its own:
//!
//! - a Fulu digest: each type's Fulu bound, and for `data_column_sidecar_{subnet_id}` the
//!   sidecar of the largest blob limit in force at it or at a Fulu digest before it (a BPO entry
//!   can lower the limit, and a late sidecar keeps the limit of its own epoch)
//!   ([`consensus_types::caps::fulu_data_column_sidecar_size`]; `verify_data_column_sidecar`,
//!   `fulu/p2p-interface.md`, refuses more commitments than
//!   `get_blob_parameters(epoch).max_blobs_per_block`): 45,380 B at 21 blobs on Mainnet;
//! - a Gloas digest: each type's Gloas bound, and for the column sidecar
//!   `compute_max_data_column_sidecar_size()` (`gloas/p2p-interface.md` "Type-specific SSZ
//!   bounds"), which takes the largest blob count of the whole schedule: 44,072 B on Sepolia
//!   and Hoodi;
//! - any other digest, and a Gloas topic under a Fulu digest: no cap, because no message on it
//!   is valid.
//!
//! The Fulu sidecar carries its commitments, the signed header and the inclusion proof, so at
//! the same blob count it is larger than the Gloas one (2,144 B against 2,096 B per blob). One
//! Gloas cap for every digest would refuse every full-blob Fulu sidecar.
//!
//! The cap bounds the decompressed length only: a valid encoding that compresses badly (longer
//! than `max_compressed_len(cap)`) but decompresses within the cap is accepted. A
//! decompression bomb therefore costs at most the cap in memory, never the length it declares.

use super::topic::{GossipKind, GossipTopic, TopicError};
use crate::rpc::codec::max_compressed_len;
use crate::rpc::messages::ForkDigest;
use consensus_types::caps::{
    fulu_data_column_sidecar_size, max_size_for, NetworkCaps, ObjectKind, MAX_PAYLOAD_SIZE,
};
use consensus_types::{EthSpec, ForkName};
use network_config::digest::{digest_schedule, DigestInputs, Root};
use network_config::ChainConfig;

/// The uncompressed cap of each topic kind at one fork digest: `None` for a kind its fork does
/// not define.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DigestCaps {
    beacon_block: Option<usize>,
    aggregate_and_proof: Option<usize>,
    attestation: Option<usize>,
    data_column_sidecar: Option<usize>,
    execution_payload_bid: Option<usize>,
    execution_payload: Option<usize>,
    payload_attestation_message: Option<usize>,
}

impl DigestCaps {
    /// The caps of preset `E` at a digest of `fork` with `max_blobs_per_block` blobs in force,
    /// on the network of `network` (see the module docs).
    fn at<E: EthSpec>(fork: ForkName, max_blobs_per_block: u64, network: &NetworkCaps) -> Self {
        let cap = |kind| match (kind, fork) {
            (ObjectKind::DataColumnSidecar, ForkName::Fulu) => {
                let size = fulu_data_column_sidecar_size::<E>(max_blobs_per_block);
                Some(usize::try_from(size).map_or(MAX_PAYLOAD_SIZE, |s| s.min(MAX_PAYLOAD_SIZE)))
            }
            _ => max_size_for::<E>(kind, fork, network),
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

    fn cap(&self, kind: GossipKind) -> Option<usize> {
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

    /// The larger cap of each kind: a digest named twice refuses neither entry's messages.
    fn max(self, other: Self) -> Self {
        Self {
            beacon_block: self.beacon_block.max(other.beacon_block),
            aggregate_and_proof: self.aggregate_and_proof.max(other.aggregate_and_proof),
            attestation: self.attestation.max(other.attestation),
            data_column_sidecar: self.data_column_sidecar.max(other.data_column_sidecar),
            execution_payload_bid: self.execution_payload_bid.max(other.execution_payload_bid),
            execution_payload: self.execution_payload.max(other.execution_payload),
            payload_attestation_message: self
                .payload_attestation_message
                .max(other.payload_attestation_message),
        }
    }
}

/// The uncompressed cap of every topic kind under each fork digest, for one preset and
/// network (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopicCaps {
    /// The caps under every digest: [`TopicCaps::gloas`] only.
    every_digest: Option<DigestCaps>,
    /// The caps of each digest of the schedule, in schedule order, each digest once.
    by_digest: Vec<(ForkDigest, DigestCaps)>,
}

impl TopicCaps {
    /// The caps of preset `E` on `config`'s network, whose genesis validators root is
    /// `genesis_validators_root`: [`TopicCaps::from_schedule`] of its digest schedule
    /// (`network_config::digest::digest_schedule`, BPO digests included) and its
    /// [`NetworkCaps`]. What a node on a real network uses.
    pub fn from_config<E: EthSpec>(config: &ChainConfig, genesis_validators_root: &Root) -> Self {
        Self::from_schedule::<E>(
            &digest_schedule(config, genesis_validators_root),
            &NetworkCaps::from_config(config),
        )
    }

    /// The caps of preset `E` under each digest of `schedule`, from the fork and the blob
    /// parameters each entry was computed with; `network` (the whole blob schedule) bounds the
    /// Gloas column sidecar. A Fulu digest caps the column sidecar at the largest Fulu blob
    /// limit at or before it (by epoch), because `verify_data_column_sidecar` bounds a sidecar
    /// by its own slot's epoch, and a late sidecar of an earlier, larger limit can arrive under
    /// a digest that lowered it. A digest outside `schedule` has no cap. If two entries have one
    /// digest, each kind keeps the larger cap.
    pub fn from_schedule<E: EthSpec>(schedule: &[DigestInputs], network: &NetworkCaps) -> Self {
        let mut entries: Vec<&DigestInputs> = schedule.iter().collect();
        entries.sort_by_key(|entry| entry.epoch);
        let mut by_digest: Vec<(ForkDigest, DigestCaps)> = Vec::with_capacity(schedule.len());
        // The largest Fulu blob limit at or before each entry.
        let mut fulu_blobs = 0;
        for entry in entries {
            let blobs = entry.blob_parameters.max_blobs_per_block;
            if entry.fork == ForkName::Fulu {
                fulu_blobs = fulu_blobs.max(blobs);
            }
            let caps = DigestCaps::at::<E>(entry.fork, fulu_blobs.max(blobs), network);
            match by_digest.iter_mut().find(|(d, _)| *d == entry.fork_digest) {
                Some((_, held)) => *held = held.max(caps),
                None => by_digest.push((entry.fork_digest, caps)),
            }
        }
        Self {
            every_digest: None,
            by_digest,
        }
    }

    /// The Gloas caps of preset `E` on `network` (whose blob schedule bounds the column
    /// sidecar) under **every** fork digest: `consensus_types::caps::max_size_for` of each
    /// topic's message type at Gloas. For tests and tools without a digest schedule only: it
    /// refuses a full-blob Fulu column sidecar. A node uses [`TopicCaps::from_config`].
    pub fn gloas<E: EthSpec>(network: &NetworkCaps) -> Self {
        Self {
            every_digest: Some(DigestCaps::at::<E>(
                ForkName::Gloas,
                network.max_blobs_per_block(),
                network,
            )),
            by_digest: Vec::new(),
        }
    }

    /// The uncompressed cap of `kind`'s messages under `fork_digest`; `None` if no message of
    /// it is valid there (see the module docs).
    pub fn cap_at(&self, fork_digest: ForkDigest, kind: GossipKind) -> Option<usize> {
        let caps = match self.every_digest {
            Some(caps) => caps,
            None => self.by_digest.iter().find(|(d, _)| *d == fork_digest)?.1,
        };
        caps.cap(kind)
    }

    /// The largest cap of `kind` under any digest: what any message of it that the transform
    /// accepts may hold. 0 if no digest has a cap for it.
    pub fn cap(&self, kind: GossipKind) -> usize {
        self.every_digest
            .iter()
            .chain(self.by_digest.iter().map(|(_, caps)| caps))
            .filter_map(|caps| caps.cap(kind))
            .max()
            .unwrap_or(0)
    }

    /// The cap of `topic`'s messages, or [`TransformError::NoCap`].
    fn of(&self, topic: GossipTopic) -> Result<usize, TransformError> {
        self.cap_at(topic.fork_digest, topic.kind)
            .ok_or(TransformError::NoCap(topic))
    }
}

/// Why a message's `data` was refused. Gossipsub reports every one as `TransformFailed`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransformError {
    /// The topic is not one this node handles.
    #[error("topic: {0}")]
    Topic(#[from] TopicError),
    /// The topic has no cap: its fork digest is not one of the schedule's, or the fork it names
    /// does not define the topic (a Gloas topic under a Fulu digest). Found before the data is
    /// read.
    #[error(
        "no message is valid on {0}: its fork digest is not scheduled, or its fork has no such \
         topic"
    )]
    NoCap(GossipTopic),
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// [`TransformError::Topic`] for a topic this node does not handle,
    /// [`TransformError::NoCap`] for one with no cap at its digest, else
    /// [`TransformError::FrameTooLarge`], [`TransformError::DeclaredTooLarge`] or
    /// [`TransformError::Snappy`], in the order they are checked.
    pub fn inbound(&self, topic: &str, data: &[u8]) -> Result<Vec<u8>, TransformError> {
        let cap = self.caps.of(GossipTopic::parse(topic)?)?;
        decompress_bounded(data, cap)
    }

    /// Compresses `ssz` for `topic`.
    ///
    /// # Errors
    ///
    /// [`TransformError::Topic`] for a topic this node does not handle,
    /// [`TransformError::NoCap`] for one with no cap at its digest,
    /// [`TransformError::DeclaredTooLarge`] if `ssz` is over the topic's cap.
    pub fn outbound(&self, topic: &str, ssz: &[u8]) -> Result<Vec<u8>, TransformError> {
        let cap = self.caps.of(GossipTopic::parse(topic)?)?;
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

    /// The Sepolia digests, as `network_config::digest` pins them: Fulu (9 blobs), BPO1 (15),
    /// BPO2 (21) and Gloas.
    const SEPOLIA_FULU: ForkDigest = [0x7e, 0x0d, 0x34, 0x47];
    const SEPOLIA_BPO1: ForkDigest = [0xfd, 0x32, 0xb6, 0x22];
    const SEPOLIA_BPO2: ForkDigest = [0x74, 0xd0, 0x14, 0x59];
    const SEPOLIA_GLOAS: ForkDigest = [0x66, 0x9e, 0x6c, 0x11];

    fn sepolia() -> (ChainConfig, network_config::digest::Root) {
        let network = network_config::Network::Sepolia;
        let config = ChainConfig::load(network).unwrap();
        (config, network.genesis().unwrap().genesis_validators_root)
    }

    /// The transform of the Sepolia schedule, each digest held to its own fork's caps.
    fn sepolia_transform() -> SnappyTransform {
        let (config, gvr) = sepolia();
        SnappyTransform::new(TopicCaps::from_config::<Mainnet>(&config, &gvr))
    }

    fn column_topic(digest: ForkDigest) -> String {
        GossipTopic::new(digest, GossipKind::DataColumnSidecar { subnet_id: 0 }).to_string()
    }

    /// A Mainnet Fulu sidecar of `blobs` cells, commitments and proofs.
    fn fulu_sidecar(blobs: usize) -> Vec<u8> {
        use consensus_types::fulu;
        use consensus_types::primitives::Root;
        use ssz::Encode as _;
        fulu::DataColumnSidecar::<Mainnet> {
            index: 0,
            column: vec![Default::default(); blobs].try_into().unwrap(),
            kzg_commitments: vec![[0x11; 48]; blobs].try_into().unwrap(),
            kzg_proofs: vec![[0x22; 48]; blobs].try_into().unwrap(),
            signed_block_header: fulu::SignedBeaconBlockHeader {
                message: fulu::BeaconBlockHeader {
                    slot: 1,
                    proposer_index: 2,
                    parent_root: Root::ZERO,
                    state_root: Root::ZERO,
                    body_root: Root::ZERO,
                },
                signature: [0xaa; 96],
            },
            kzg_commitments_inclusion_proof: Default::default(),
        }
        .as_ssz_bytes()
    }

    /// A snappy block header declaring `len` bytes, and a few bytes of body.
    fn declaring(len: usize) -> Vec<u8> {
        let mut data = Vec::new();
        crate::rpc::codec::encode_varint(len as u64, &mut data);
        data.extend_from_slice(&[0; 8]);
        data
    }

    /// A Fulu sidecar of a full 21-blob block on the Sepolia BPO2 digest (Fulu, 21 blobs) is
    /// 45,380 bytes, over the Gloas bound of 44,072: the digest's own fork and blob limit
    /// cap it, so it passes, and one byte more is refused from the header.
    #[test]
    fn a_full_fulu_sidecar_on_a_fulu_digest_passes() {
        let t = sepolia_transform();
        let topic = column_topic(SEPOLIA_BPO2);
        let ssz = fulu_sidecar(21);
        assert_eq!(ssz.len(), 45_380);
        let data = snap::raw::Encoder::new().compress_vec(&ssz).unwrap();
        assert_eq!(t.inbound(&topic, &data), Ok(ssz.clone()));
        assert_eq!(t.outbound(&topic, &ssz).map(|d| d.len()), Ok(data.len()));
        assert_eq!(
            t.inbound(&topic, &declaring(45_381)),
            Err(TransformError::DeclaredTooLarge {
                declared: 45_381,
                cap: 45_380
            })
        );
    }

    /// The Sepolia Gloas digest keeps the Gloas bound,
    /// `compute_max_data_column_sidecar_size()` of the schedule: 44,072 bytes pass, one more
    /// does not, and neither does a Fulu-sized sidecar.
    #[test]
    fn a_gloas_digest_keeps_the_gloas_bound() {
        let t = sepolia_transform();
        let topic = column_topic(SEPOLIA_GLOAS);
        let at_cap = snap::raw::Encoder::new()
            .compress_vec(&[0; 44_072])
            .unwrap();
        assert_eq!(t.inbound(&topic, &at_cap).map(|s| s.len()), Ok(44_072));
        for declared in [44_073, 45_380] {
            assert_eq!(
                t.inbound(&topic, &declaring(declared)),
                Err(TransformError::DeclaredTooLarge {
                    declared,
                    cap: 44_072
                })
            );
        }
        // The same as the fork-agnostic Gloas caps.
        let (config, _) = sepolia();
        let gloas = TopicCaps::gloas::<Mainnet>(&NetworkCaps::from_config(&config));
        for kind in [
            GossipKind::BeaconBlock,
            GossipKind::BeaconAggregateAndProof,
            GossipKind::BeaconAttestation { subnet_id: 3 },
            GossipKind::DataColumnSidecar { subnet_id: 9 },
            GossipKind::ExecutionPayloadBid,
            GossipKind::ExecutionPayload,
            GossipKind::PayloadAttestationMessage,
        ] {
            assert_eq!(
                t.caps().cap_at(SEPOLIA_GLOAS, kind),
                Some(gloas.cap(kind)),
                "{kind}"
            );
        }
    }

    /// Each Fulu digest of Sepolia (9, 15 and 21 blobs: never lowered) caps a column sidecar at
    /// the largest Fulu blob limit at or before it, which here is the one in force, and its other
    /// topics at their Fulu bounds. The digests are the schedule's.
    #[test]
    fn each_fulu_digest_takes_the_blob_limit_in_force() {
        let (config, gvr) = sepolia();
        let schedule = network_config::digest::digest_schedule(&config, &gvr);
        let blobs: Vec<(ForkDigest, ForkName, u64)> = schedule
            .iter()
            .map(|i| (i.fork_digest, i.fork, i.blob_parameters.max_blobs_per_block))
            .collect();
        assert_eq!(
            blobs,
            [
                (SEPOLIA_FULU, ForkName::Fulu, 9),
                (SEPOLIA_BPO1, ForkName::Fulu, 15),
                (SEPOLIA_BPO2, ForkName::Fulu, 21),
                (SEPOLIA_GLOAS, ForkName::Gloas, 21),
            ]
        );
        let caps =
            TopicCaps::from_schedule::<Mainnet>(&schedule, &NetworkCaps::from_config(&config));
        assert_eq!(caps, TopicCaps::from_config::<Mainnet>(&config, &gvr));
        let column = GossipKind::DataColumnSidecar { subnet_id: 64 };
        // 356 + blobs * 2,144.
        for (digest, cap) in [
            (SEPOLIA_FULU, 19_652),
            (SEPOLIA_BPO1, 32_516),
            (SEPOLIA_BPO2, 45_380),
        ] {
            assert_eq!(caps.cap_at(digest, column), Some(cap));
            let fulu =
                |kind| max_size_for::<Mainnet>(kind, ForkName::Fulu, &NetworkCaps::PRESET_BOUND);
            assert_eq!(
                caps.cap_at(digest, GossipKind::BeaconBlock),
                fulu(ObjectKind::SignedBeaconBlock)
            );
            assert_eq!(
                caps.cap_at(digest, GossipKind::BeaconAggregateAndProof),
                fulu(ObjectKind::SignedAggregateAndProof)
            );
            assert_eq!(
                caps.cap_at(digest, GossipKind::BeaconAttestation { subnet_id: 0 }),
                fulu(ObjectKind::SingleAttestation)
            );
        }
    }

    /// No message is valid on a digest the schedule does not name, or on a Gloas topic under a
    /// Fulu digest: both are refused before the data is read, in both directions.
    #[test]
    fn a_topic_with_no_cap_at_its_digest_is_refused_unread() {
        let t = sepolia_transform();
        for (digest, kind) in [
            ([0; 4], GossipKind::BeaconBlock),
            ([0; 4], GossipKind::DataColumnSidecar { subnet_id: 0 }),
            (SEPOLIA_BPO2, GossipKind::ExecutionPayloadBid),
            (SEPOLIA_FULU, GossipKind::ExecutionPayload),
            (SEPOLIA_BPO1, GossipKind::PayloadAttestationMessage),
        ] {
            let topic = GossipTopic::new(digest, kind);
            let want = Err(TransformError::NoCap(topic));
            assert_eq!(t.caps().cap_at(digest, kind), None, "{topic}");
            assert_eq!(t.inbound(&topic.to_string(), &[0xff; 4]), want, "{topic}");
            assert_eq!(t.outbound(&topic.to_string(), b""), want, "{topic}");
        }
        assert_eq!(
            TransformError::NoCap(GossipTopic::new(
                [0xab, 0, 0, 0x01],
                GossipKind::BeaconBlock
            ))
            .to_string(),
            "no message is valid on /eth2/ab000001/beacon_block/ssz_snappy: its fork digest is \
             not scheduled, or its fork has no such topic"
        );
        // The Gloas topics pass under the Gloas digest.
        let bid = GossipTopic::new(SEPOLIA_GLOAS, GossipKind::ExecutionPayloadBid).to_string();
        let data = t.outbound(&bid, &[1; 100]).unwrap();
        assert_eq!(t.inbound(&bid, &data), Ok(vec![1; 100]));
    }

    /// Without a digest, a kind's cap is its largest over the schedule: what any accepted
    /// message of it may hold. The fork-agnostic Gloas caps hold under every digest.
    #[test]
    fn the_cap_of_a_kind_is_its_largest_at_any_digest() {
        let caps = sepolia_transform().caps().clone();
        assert_eq!(
            caps.cap(GossipKind::DataColumnSidecar { subnet_id: 1 }),
            45_380
        );
        assert_eq!(caps.cap(GossipKind::ExecutionPayloadBid), 196_932);
        for kind in [GossipKind::BeaconBlock, GossipKind::BeaconAggregateAndProof] {
            let largest = [SEPOLIA_FULU, SEPOLIA_BPO1, SEPOLIA_BPO2, SEPOLIA_GLOAS]
                .map(|d| caps.cap_at(d, kind).unwrap())
                .into_iter()
                .max();
            assert_eq!(Some(caps.cap(kind)), largest, "{kind}");
        }
        // An empty schedule (no Fulu) caps nothing.
        let none = TopicCaps::from_schedule::<Mainnet>(&[], &NetworkCaps::PRESET_BOUND);
        assert_eq!(none.cap(GossipKind::BeaconBlock), 0);
        assert_eq!(none.cap_at(SEPOLIA_FULU, GossipKind::BeaconBlock), None);
        // The Gloas caps: every digest, the same caps.
        let gloas = transform();
        for digest in [[0; 4], SEPOLIA_FULU, [0xff; 4]] {
            assert_eq!(
                gloas.caps().cap_at(digest, GossipKind::ExecutionPayloadBid),
                Some(196_932)
            );
            assert_eq!(
                gloas
                    .caps()
                    .cap_at(digest, GossipKind::DataColumnSidecar { subnet_id: 0 }),
                Some(44_072)
            );
        }
    }

    /// Two schedule entries with one digest (none on a real network) keep the larger cap of
    /// each kind, so neither entry's messages are refused.
    #[test]
    fn a_digest_named_twice_keeps_the_larger_caps() {
        let (config, gvr) = sepolia();
        let mut schedule = network_config::digest::digest_schedule(&config, &gvr);
        let mut fulu_again = schedule[2];
        fulu_again.fork_digest = SEPOLIA_GLOAS;
        schedule.push(fulu_again);
        let caps =
            TopicCaps::from_schedule::<Mainnet>(&schedule, &NetworkCaps::from_config(&config));
        let column = GossipKind::DataColumnSidecar { subnet_id: 0 };
        assert_eq!(caps.cap_at(SEPOLIA_GLOAS, column), Some(45_380));
        assert_eq!(
            caps.cap_at(SEPOLIA_GLOAS, GossipKind::ExecutionPayloadBid),
            Some(196_932)
        );
    }

    /// A BPO entry that lowers the blob limit (21, then 15): `verify_data_column_sidecar`
    /// bounds a sidecar by its own slot's epoch, so a late sidecar of the 21-blob epochs can
    /// arrive under the lowered digest. Each Fulu digest therefore caps at the largest Fulu
    /// limit at or before it; a Gloas digest keeps its own bound.
    #[test]
    fn a_lowered_blob_limit_keeps_the_larger_cap_of_the_digests_before_it() {
        let entry = |epoch, fork, max_blobs_per_block, digest: u8| DigestInputs {
            epoch,
            fork,
            fork_version: [0; 4],
            blob_parameters: network_config::BlobParameters {
                epoch,
                max_blobs_per_block,
            },
            genesis_validators_root: [0; 32],
            fork_digest: [digest; 4],
        };
        // Out of order on purpose: the schedule is read by epoch.
        let schedule = [
            entry(30, ForkName::Fulu, 15, 3),
            entry(10, ForkName::Fulu, 9, 1),
            entry(20, ForkName::Fulu, 21, 2),
            entry(40, ForkName::Fulu, 12, 4),
            entry(50, ForkName::Gloas, 6, 5),
        ];
        let caps = TopicCaps::from_schedule::<Mainnet>(
            &schedule,
            &NetworkCaps::from_blob_schedule(6, &[]),
        );
        let column = GossipKind::DataColumnSidecar { subnet_id: 0 };
        let fulu = |blobs| Some(fulu_data_column_sidecar_size::<Mainnet>(blobs) as usize);
        assert_eq!(caps.cap_at([1; 4], column), fulu(9));
        assert_eq!(caps.cap_at([2; 4], column), fulu(21));
        assert_eq!(caps.cap_at([3; 4], column), fulu(21), "lowered to 15");
        assert_eq!(caps.cap_at([4; 4], column), fulu(21), "lowered to 12");
        let gloas = consensus_types::caps::compute_max_data_column_sidecar_size::<Mainnet>(
            &NetworkCaps::from_blob_schedule(6, &[]),
        );
        assert_eq!(caps.cap_at([5; 4], column), Some(gloas as usize));
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
