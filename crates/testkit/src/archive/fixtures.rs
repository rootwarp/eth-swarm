//! Payload fixtures (feature `test-support`): a Minimal-preset fork schedule with Fulu from
//! genesis and Gloas from slot [`GLOAS_SLOT`], and small blocks and column sidecars of either
//! fork, snappy block-compressed as gossip carries them.

use super::payload::ChainParams;
use consensus_types::caps::NetworkCaps;
use consensus_types::primitives::{Root, Slot, B256};
use consensus_types::{fulu, gloas, EthSpec, ForkName, ForkSchedule, Minimal};
use network_config::ScheduledFork;
use ssz::Encode;
use ssz_types::FixedVector;
use tree_hash::TreeHash;

/// The preset of every fixture.
pub type Spec = Minimal;

/// `GLOAS_FORK_EPOCH` of [`schedule`].
pub const GLOAS_EPOCH: u64 = 2;
/// The first Gloas slot of [`schedule`] (Minimal: 8 slots per epoch).
pub const GLOAS_SLOT: Slot = GLOAS_EPOCH * 8;

/// Fulu from epoch 0, Gloas from [`GLOAS_EPOCH`].
pub fn schedule() -> ForkSchedule {
    ForkSchedule::new(
        ScheduledFork {
            version: [0x60, 0, 0, 1],
            epoch: 0,
        },
        ScheduledFork {
            version: [0x70, 0, 0, 1],
            epoch: GLOAS_EPOCH,
        },
    )
    .expect("ordered")
}

/// [`schedule`] with the preset bound on column sidecars.
pub fn chain() -> ChainParams {
    ChainParams {
        schedule: schedule(),
        caps: NetworkCaps::PRESET_BOUND,
    }
}

/// Snappy block compression, the gossip encoding.
pub fn snappy(ssz: &[u8]) -> Vec<u8> {
    snap::raw::Encoder::new()
        .compress_vec(ssz)
        .expect("compressible")
}

fn is_gloas<E: EthSpec>(schedule: &ForkSchedule, slot: Slot) -> bool {
    schedule.fork_at(E::epoch_at_slot(slot)) == Some(ForkName::Gloas)
}

/// [`block_on`] with [`Spec`] and [`schedule`].
pub fn block(slot: Slot, tag: u64) -> (Vec<u8>, Root) {
    block_on::<Spec>(&schedule(), slot, tag)
}

/// [`column_on`] with [`Spec`] and [`schedule`].
pub fn column(slot: Slot, tag: u64, index: u64) -> (Vec<u8>, Root) {
    column_on::<Spec>(&schedule(), slot, tag, index)
}

/// A `SignedBeaconBlock` at `slot` in the shape of its fork on `schedule`, `proposer_index`
/// set to `tag` so blocks of one slot differ, compressed; and its block root.
pub fn block_on<E: EthSpec>(schedule: &ForkSchedule, slot: Slot, tag: u64) -> (Vec<u8>, Root) {
    if is_gloas::<E>(schedule, slot) {
        let mut b = p2p_wire::testkit::gloas_block::<E>(slot);
        b.message.proposer_index = tag;
        (snappy(&b.as_ssz_bytes()), b.message.tree_hash_root())
    } else {
        let mut b = p2p_wire::testkit::fulu_block::<E>(slot);
        b.message.proposer_index = tag;
        (snappy(&b.as_ssz_bytes()), b.message.tree_hash_root())
    }
}

/// A one-blob `DataColumnSidecar` with column `index` of the block [`block_on`] makes for
/// `slot` and `tag`, in the shape of its fork on `schedule`, compressed; and that block's
/// root, which the Fulu sidecar's header and the Gloas sidecar's `beacon_block_root` both give.
pub fn column_on<E: EthSpec>(
    schedule: &ForkSchedule,
    slot: Slot,
    tag: u64,
    index: u64,
) -> (Vec<u8>, Root) {
    if is_gloas::<E>(schedule, slot) {
        let (_, block_root) = block_on::<E>(schedule, slot, tag);
        let sidecar = gloas::DataColumnSidecar::<E> {
            index,
            column: vec![FixedVector::default()].try_into().expect("one cell"),
            kzg_proofs: vec![[0x22; 48]].try_into().expect("one proof"),
            slot,
            beacon_block_root: block_root,
        };
        (snappy(&sidecar.as_ssz_bytes()), block_root)
    } else {
        let mut block = p2p_wire::testkit::fulu_block::<E>(slot);
        block.message.proposer_index = tag;
        let m = &block.message;
        let header = fulu::BeaconBlockHeader {
            slot,
            proposer_index: m.proposer_index,
            parent_root: m.parent_root,
            state_root: m.state_root,
            body_root: m.body.tree_hash_root(),
        };
        let root = header.tree_hash_root();
        let sidecar = fulu::DataColumnSidecar::<E> {
            index,
            column: vec![FixedVector::default()].try_into().expect("one cell"),
            kzg_commitments: vec![[0x11; 48]].try_into().expect("one commitment"),
            kzg_proofs: vec![[0x22; 48]].try_into().expect("one proof"),
            signed_block_header: fulu::SignedBeaconBlockHeader {
                message: header,
                signature: block.signature,
            },
            kzg_commitments_inclusion_proof: FixedVector::from_elem(B256::repeat_byte(4)),
        };
        (snappy(&sidecar.as_ssz_bytes()), root)
    }
}

/// Snappy block decompression, for checking stored payloads.
pub fn decompressed(payload: &[u8]) -> Vec<u8> {
    snap::raw::Decoder::new()
        .decompress_vec(payload)
        .expect("snappy")
}
