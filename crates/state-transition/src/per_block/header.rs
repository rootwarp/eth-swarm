//! The block header, the RANDAO mix and the eth1 vote (P0 §Block processing, which Gloas
//! keeps).

use crate::accessors::{get_current_epoch, get_randao_mix, hash};
use crate::caches::get_beacon_proposer_index;
use crate::per_block::state_proposer_index;
use crate::{Preset, StfError};
use consensus_types::common::BeaconBlockHeader;
use consensus_types::gloas::{BeaconBlock, BeaconBlockBody, BeaconState};
use consensus_types::primitives::{Bytes32, Root};
use ssz_types::typenum::Unsigned;
use tree_hash::TreeHash;

/// `process_block_header` (P0 L2350-2370): checks the slot, the proposer and the parent of
/// the block ([`check_block_header`]), and caches the block as the latest block header.
///
/// As in the spec, the header is written before the slashed check. On `Err` the caller
/// drops the state.
pub fn process_block_header<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
) -> Result<(), StfError> {
    check_block_header(state, block)?;
    // Cache current block as the new latest block
    state.latest_block_header = BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        // Overwritten in the next process_slot call
        state_root: Root::ZERO,
        body_root: block.body.tree_hash_root(),
    };
    // Verify proposer is not slashed. `block.proposer_index` is the index of the lookahead
    // here, so an index outside the registry is a fault of our own state.
    let proposer = state.validators.get(block.proposer_index as usize).ok_or(
        StfError::ListIndexOutOfRange {
            list: "validators",
            index: block.proposer_index,
        },
    )?;
    if proposer.slashed {
        return Err(StfError::ProposerSlashed(block.proposer_index));
    }
    Ok(())
}

/// The four asserts of `process_block_header` (P0 L2352-2358) before it writes the header:
/// the slot, a newer slot than the latest block header, the proposer of the slot, and the
/// parent root. They read no registry list and change nothing.
///
/// [`crate::state_transition`] runs them before it builds the signature sets, so a block
/// that fails them costs no registry read and no backend call. The verdict is the one of
/// `process_block`: the only step before the header, the parent payload, changes none of
/// `state.slot`, `state.latest_block_header` and `state.proposer_lookahead`.
pub fn check_block_header<E: Preset>(
    state: &BeaconState<E>,
    block: &BeaconBlock<E>,
) -> Result<(), StfError> {
    // Verify that the slots match
    if block.slot != state.slot {
        return Err(StfError::BlockSlotMismatch {
            block: block.slot,
            state: state.slot,
        });
    }
    // Verify that the block is newer than latest block header
    if block.slot <= state.latest_block_header.slot {
        return Err(StfError::BlockNotNewer {
            block: block.slot,
            latest: state.latest_block_header.slot,
        });
    }
    // Verify that proposer index is the correct index
    let expected = get_beacon_proposer_index(state)?;
    if block.proposer_index != expected {
        return Err(StfError::WrongProposer {
            block: block.proposer_index,
            expected,
        });
    }
    // Verify that the parent matches
    let expected = state.latest_block_header.tree_hash_root();
    if block.parent_root != expected {
        return Err(StfError::ParentRootMismatch {
            block: block.parent_root,
            expected,
        });
    }
    Ok(())
}

/// `process_randao` (P0 L2376-2384): mixes the hash of the RANDAO reveal into the mix of
/// the current epoch.
///
/// The reveal check (`bls.Verify`, L2381) is not here: the caller gives
/// [`crate::signatures::randao_signature_set`] to the backend, in the one batch of
/// [`crate::signatures::block_signature_sets`].
pub fn process_randao<E: Preset>(
    state: &mut BeaconState<E>,
    body: &BeaconBlockBody<E>,
) -> Result<(), StfError> {
    let epoch = get_current_epoch(state);
    // `state.validators[get_beacon_proposer_index(state)]`: the proposer must exist.
    state_proposer_index(state)?;
    // Mix in RANDAO reveal
    let reveal_hash = hash(&[&body.randao_reveal]);
    let mut mix = get_randao_mix(state, epoch);
    for (byte, reveal_byte) in mix.iter_mut().zip(reveal_hash) {
        *byte ^= reveal_byte;
    }
    let index = (epoch % E::EpochsPerHistoricalVector::to_u64()) as usize;
    *state
        .randao_mixes
        .get_mut(index)
        .ok_or_else(|| StfError::Tree("randao_mixes is shorter than its length".into()))? =
        Bytes32::from(mix);
    Ok(())
}

/// `process_eth1_data` (P0 L2390-2396): records the eth1 vote of the block, and adopts it
/// when more than half of the slots of the voting period voted for it.
pub fn process_eth1_data<E: Preset>(
    state: &mut BeaconState<E>,
    body: &BeaconBlockBody<E>,
) -> Result<(), StfError> {
    state.eth1_data_votes.push(body.eth1_data.clone())?;
    let votes = state
        .eth1_data_votes
        .iter()
        .filter(|vote| **vote == body.eth1_data)
        .count() as u64;
    // `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH` is `SlotsPerEth1VotingPeriod`.
    if votes * 2 > E::SlotsPerEth1VotingPeriod::to_u64() {
        state.eth1_data = body.eth1_data.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{block_at_state_slot, genesis_state};
    use crate::{per_slot, state_root};
    use consensus_types::common::Eth1Data;
    use consensus_types::{EthSpec, Minimal};

    const ETH: u64 = 1_000_000_000;

    /// The error for a proposer index of the lookahead that is outside the registry.
    fn outside_registry(index: u64) -> StfError {
        StfError::ListIndexOutOfRange {
            list: "validators",
            index,
        }
    }

    /// A minimal state at slot 3 after a block at slot 2, and a valid block for slot 3.
    fn state_and_block() -> (BeaconState<Minimal>, BeaconBlock<Minimal>) {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        per_slot::process_slots(&mut state, 3).unwrap();
        state.latest_block_header.slot = 2;
        let block = block_at_state_slot(&state).message;
        (state, block)
    }

    #[test]
    fn header_caches_the_block() {
        let (mut state, block) = state_and_block();
        assert_eq!(process_block_header(&mut state, &block), Ok(()));
        assert_eq!(
            state.latest_block_header,
            BeaconBlockHeader {
                slot: 3,
                proposer_index: block.proposer_index,
                parent_root: block.parent_root,
                state_root: Root::ZERO,
                body_root: block.body.tree_hash_root(),
            }
        );
    }

    #[test]
    fn header_asserts() {
        let (state, block) = state_and_block();
        let run = |state: &BeaconState<Minimal>, block: &BeaconBlock<Minimal>| {
            process_block_header(&mut state.clone(), block)
        };
        let mut wrong = block.clone();
        wrong.slot = 4;
        assert_eq!(
            run(&state, &wrong),
            Err(StfError::BlockSlotMismatch { block: 4, state: 3 })
        );
        let mut old = state.clone();
        old.latest_block_header.slot = 3;
        assert_eq!(
            run(&old, &block),
            Err(StfError::BlockNotNewer {
                block: 3,
                latest: 3
            })
        );
        let mut stranger = block.clone();
        stranger.proposer_index = block.proposer_index + 1;
        assert_eq!(
            run(&state, &stranger),
            Err(StfError::WrongProposer {
                block: block.proposer_index + 1,
                expected: block.proposer_index
            })
        );
        let mut orphan = block.clone();
        orphan.parent_root = Root::repeat_byte(9);
        assert_eq!(
            run(&state, &orphan),
            Err(StfError::ParentRootMismatch {
                block: Root::repeat_byte(9),
                expected: block.parent_root
            })
        );
        let mut slashed = state.clone();
        let proposer = block.proposer_index as usize;
        slashed.validators.get_mut(proposer).unwrap().slashed = true;
        assert_eq!(
            run(&slashed, &block),
            Err(StfError::ProposerSlashed(block.proposer_index))
        );
        // A lookahead entry outside the registry has no validator to read. The index comes
        // from the state, so the error is not a proof that the block is invalid.
        let mut short = state.clone();
        *short.proposer_lookahead.get_mut(3).unwrap() = 64;
        let mut outside = block.clone();
        outside.proposer_index = 64;
        let err = run(&short, &outside).unwrap_err();
        assert_eq!(err, outside_registry(64));
        assert!(!err.proves_invalid());
    }

    #[test]
    fn randao_mixes_in_the_reveal_hash() {
        let (mut state, mut block) = state_and_block();
        block.body.randao_reveal = [0x33; 96];
        let before = get_randao_mix(&state, 0);
        let other_epoch = get_randao_mix(&state, 1);
        assert_eq!(process_randao(&mut state, &block.body), Ok(()));
        let reveal_hash = ethereum_hashing::hash_fixed(&[0x33; 96]);
        let want: Vec<u8> = before.iter().zip(reveal_hash).map(|(a, b)| a ^ b).collect();
        assert_eq!(get_randao_mix(&state, 0).as_slice(), &want[..]);
        assert_eq!(get_randao_mix(&state, 1), other_epoch);
        // Mixing the same reveal again gives back the old mix (xor).
        assert_eq!(process_randao(&mut state, &block.body), Ok(()));
        assert_eq!(get_randao_mix(&state, 0), before);
        state_root(&mut state).unwrap();

        let mut short = state.clone();
        *short.proposer_lookahead.get_mut(3).unwrap() = 64;
        assert_eq!(
            process_randao(&mut short, &block.body),
            Err(outside_registry(64))
        );
    }

    #[test]
    fn eth1_vote_needs_a_majority_of_the_period() {
        let (mut state, mut block) = state_and_block();
        let vote = Eth1Data {
            deposit_root: Root::repeat_byte(1),
            deposit_count: 7,
            block_hash: Root::repeat_byte(2),
        };
        block.body.eth1_data = vote.clone();
        let original = state.eth1_data.clone();
        // Minimal: 4 epochs of 8 slots, so 17 of 32 votes win.
        let period = <Minimal as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
        assert_eq!(period, 32);
        for _ in 0..period / 2 {
            process_eth1_data(&mut state, &block.body).unwrap();
        }
        assert_eq!(state.eth1_data, original);
        assert_eq!(state.eth1_data_votes.len() as u64, period / 2);
        process_eth1_data(&mut state, &block.body).unwrap();
        assert_eq!(state.eth1_data, vote);
        // Other votes do not count for it.
        let mut fresh = state_and_block().0;
        let mut other = block.body.clone();
        other.eth1_data.deposit_count = 8;
        for _ in 0..period / 2 {
            process_eth1_data(&mut fresh, &other).unwrap();
        }
        process_eth1_data(&mut fresh, &block.body).unwrap();
        assert_eq!(fresh.eth1_data, original);
        // A full list of votes cannot take one more.
        for _ in fresh.eth1_data_votes.len() as u64..period {
            process_eth1_data(&mut fresh, &other).unwrap();
        }
        assert!(matches!(
            process_eth1_data(&mut fresh, &other),
            Err(StfError::Tree(_))
        ));
    }
}
