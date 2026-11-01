//! Fork dispatch by the object's slot.

mod common;

use common::{fulu_block, fulu_state, gloas_block, gloas_state};
use consensus_types::codec::DecodeError;
use consensus_types::forked::{BeaconState, SignedBeaconBlock};
use consensus_types::{EthSpec, ForkName, Mainnet, Minimal};
use network_config::{ChainConfig, ForkSchedule, Network};
use ssz::Encode;
use tree_hash::TreeHash;

const SEPOLIA_GLOAS_EPOCH: u64 = 353_024;

fn sepolia() -> ForkSchedule {
    *ChainConfig::load(Network::Sepolia).unwrap().fork_schedule()
}

#[test]
fn decode_by_slot_fork() {
    let schedule = sepolia();
    assert_eq!(
        schedule.fork_epoch(ForkName::Gloas),
        Some(SEPOLIA_GLOAS_EPOCH)
    );
    let first_gloas_slot = Mainnet::start_slot_at_epoch(SEPOLIA_GLOAS_EPOCH);
    let last_fulu_slot = first_gloas_slot - 1;

    let fulu = fulu_block::<Mainnet>(last_fulu_slot);
    let decoded =
        SignedBeaconBlock::<Mainnet>::from_ssz_bytes_by_slot(&fulu.as_ssz_bytes(), &schedule)
            .unwrap();
    assert_eq!(decoded.fork_name(), ForkName::Fulu);
    assert_eq!(decoded.slot(), last_fulu_slot);
    assert_eq!(decoded, SignedBeaconBlock::Fulu(fulu.clone()));

    let gloas = gloas_block::<Mainnet>(first_gloas_slot);
    let decoded =
        SignedBeaconBlock::<Mainnet>::from_ssz_bytes_by_slot(&gloas.as_ssz_bytes(), &schedule)
            .unwrap();
    assert_eq!(decoded.fork_name(), ForkName::Gloas);
    assert_eq!(decoded.slot(), first_gloas_slot);
    assert_eq!(decoded, SignedBeaconBlock::Gloas(gloas));

    // The slot picks the fork, not the shape: Fulu bytes at a Gloas slot are not read as Fulu.
    let misdated = fulu_block::<Mainnet>(first_gloas_slot).as_ssz_bytes();
    assert!(matches!(
        SignedBeaconBlock::<Mainnet>::from_ssz_bytes_by_slot(&misdated, &schedule),
        Err(DecodeError::Ssz(_))
    ));
}

#[test]
fn forked_block_encodes_and_hashes_like_its_variant() {
    let inner = gloas_block::<Minimal>(9);
    let forked = SignedBeaconBlock::Gloas(inner.clone());
    assert_eq!(forked.as_ssz_bytes(), inner.as_ssz_bytes());
    assert_eq!(forked.tree_hash_root(), inner.tree_hash_root());
    let fulu = SignedBeaconBlock::<Minimal>::Fulu(fulu_block(9));
    assert_eq!(fulu.fork_name(), ForkName::Fulu);
    assert_eq!(fulu.slot(), 9);
}

/// A block's root is `hash_tree_root(block.message)`, not the root of the signed container.
#[test]
fn message_root_is_the_root_of_the_message() {
    let fulu = fulu_block::<Minimal>(9);
    let forked = SignedBeaconBlock::Fulu(fulu.clone());
    assert_eq!(forked.message_root(), fulu.message.tree_hash_root());
    assert_ne!(forked.message_root(), forked.tree_hash_root());
    let gloas = gloas_block::<Minimal>(9);
    assert_eq!(
        SignedBeaconBlock::Gloas(gloas.clone()).message_root(),
        gloas.message.tree_hash_root()
    );
}

#[test]
fn pre_fulu_slots_are_refused() {
    let schedule = sepolia();
    let fulu_start = Mainnet::start_slot_at_epoch(schedule.fork_epoch(ForkName::Fulu).unwrap());
    let bytes = fulu_block::<Mainnet>(fulu_start - 1).as_ssz_bytes();
    assert_eq!(
        SignedBeaconBlock::<Mainnet>::from_ssz_bytes_by_slot(&bytes, &schedule),
        Err(DecodeError::PreFulu {
            slot: fulu_start - 1
        })
    );
}

#[test]
fn truncated_input_has_no_slot() {
    let schedule = sepolia();
    let bytes = fulu_block::<Mainnet>(0).as_ssz_bytes();
    assert!(matches!(
        SignedBeaconBlock::<Mainnet>::from_ssz_bytes_by_slot(&bytes[..107], &schedule),
        Err(DecodeError::Ssz(ssz::DecodeError::InvalidByteLength {
            len: 107,
            expected: 108
        }))
    ));
    assert!(matches!(
        BeaconState::<Mainnet>::from_ssz_bytes_by_slot(&[0; 47], &schedule),
        Err(DecodeError::Ssz(ssz::DecodeError::InvalidByteLength {
            len: 47,
            expected: 48
        }))
    ));
}

#[test]
fn state_decodes_by_slot_fork() {
    let schedule = sepolia();
    let first_gloas_slot = Mainnet::start_slot_at_epoch(SEPOLIA_GLOAS_EPOCH);

    let fulu = fulu_state::<Mainnet>(first_gloas_slot - 1);
    let decoded =
        BeaconState::<Mainnet>::from_ssz_bytes_by_slot(&fulu.as_ssz_bytes(), &schedule).unwrap();
    assert_eq!(decoded.fork_name(), ForkName::Fulu);
    assert_eq!(decoded.slot(), first_gloas_slot - 1);
    assert_eq!(decoded.tree_hash_root(), fulu.tree_hash_root());

    let gloas = gloas_state::<Mainnet>(first_gloas_slot);
    let decoded =
        BeaconState::<Mainnet>::from_ssz_bytes_by_slot(&gloas.as_ssz_bytes(), &schedule).unwrap();
    assert_eq!(decoded.fork_name(), ForkName::Gloas);
    assert_eq!(decoded.slot(), first_gloas_slot);
    assert_eq!(decoded.as_ssz_bytes(), gloas.as_ssz_bytes());
    assert_eq!(decoded.tree_hash_root(), gloas.tree_hash_root());
}

#[test]
fn explicit_fork_decode_checks_the_cap() {
    let bytes = gloas_block::<Minimal>(1).as_ssz_bytes();
    let block =
        SignedBeaconBlock::<Minimal>::from_ssz_bytes_for_fork(&bytes, ForkName::Gloas).unwrap();
    assert_eq!(block.fork_name(), ForkName::Gloas);
    let max = consensus_types::caps::max_size::<Minimal>(
        consensus_types::caps::ObjectKind::SignedBeaconBlock,
        ForkName::Gloas,
    )
    .unwrap();
    let oversized = vec![0u8; max + 1];
    assert!(matches!(
        SignedBeaconBlock::<Minimal>::from_ssz_bytes_for_fork(&oversized, ForkName::Gloas),
        Err(DecodeError::TooLarge { .. })
    ));
}
