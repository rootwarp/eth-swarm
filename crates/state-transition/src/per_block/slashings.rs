//! `process_proposer_slashing` (P0 L2422-2443) and `process_attester_slashing`
//! (P0 L2449-2462), which Gloas keeps, with `is_slashable_validator` (P0 L1129-1135) and
//! `is_slashable_attestation_data` (P0 L1141-1151).
//!
//! The BLS checks are not here: the caller gives
//! [`crate::signatures::proposer_slashing_signature_sets`] and
//! [`crate::signatures::attester_slashing_signature_sets`] to the backend, in the one batch
//! of [`crate::signatures::block_signature_sets`]. The checks of
//! `is_valid_indexed_attestation` that need no BLS run in every mode. Both functions call the
//! Gloas `slash_validator`, which also empties the pending builder payments of the blocks
//! that the slashed validator proposed.

use crate::accessors::get_current_epoch;
use crate::mutators::slash_validator;
use crate::per_block::attestation::check_indexed_attestation;
use crate::per_block::BlockContext;
use crate::{Preset, StfError};
use consensus_types::common::{AttestationData, ProposerSlashing, Validator};
use consensus_types::gloas::{AttesterSlashing, BeaconState};
use consensus_types::primitives::Epoch;

/// `is_slashable_validator` (P0 L1129-1135).
pub fn is_slashable_validator(validator: &Validator, epoch: Epoch) -> bool {
    !validator.slashed
        && validator.activation_epoch <= epoch
        && epoch < validator.withdrawable_epoch
}

/// `is_slashable_attestation_data` (P0 L1141-1151): a double vote or a surround vote.
pub fn is_slashable_attestation_data(data_1: &AttestationData, data_2: &AttestationData) -> bool {
    // Double vote
    (data_1 != data_2 && data_1.target.epoch == data_2.target.epoch)
        // Surround vote
        || (data_1.source.epoch < data_2.source.epoch
            && data_2.target.epoch < data_1.target.epoch)
}

/// `process_proposer_slashing` (P0 L2422-2443): slashes the proposer of two different
/// headers of one slot. The BLS checks of the two headers are not here: see the module
/// documentation. On `Err`, `state` is partly updated: the caller drops it.
pub fn process_proposer_slashing<E: Preset>(
    state: &mut BeaconState<E>,
    proposer_slashing: &ProposerSlashing,
) -> Result<(), StfError> {
    process_proposer_slashing_with(state, proposer_slashing, &mut BlockContext::default())
}

/// [`process_proposer_slashing`] with the total active balance of `ctx`.
pub fn process_proposer_slashing_with<E: Preset>(
    state: &mut BeaconState<E>,
    proposer_slashing: &ProposerSlashing,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    let header_1 = &proposer_slashing.signed_header_1.message;
    let header_2 = &proposer_slashing.signed_header_2.message;

    // Verify header slots match
    if header_1.slot != header_2.slot {
        return Err(StfError::ProposerSlashingSlots {
            slot_1: header_1.slot,
            slot_2: header_2.slot,
        });
    }
    // Verify header proposer indices match
    if header_1.proposer_index != header_2.proposer_index {
        return Err(StfError::ProposerSlashingProposers {
            proposer_1: header_1.proposer_index,
            proposer_2: header_2.proposer_index,
        });
    }
    // Verify the headers are different
    if header_1 == header_2 {
        return Err(StfError::ProposerSlashingSameHeaders);
    }
    // Verify the proposer is slashable
    let index = header_1.proposer_index;
    let proposer = state
        .validators
        .get(index as usize)
        .ok_or(StfError::UnknownValidator(index))?;
    if !is_slashable_validator(proposer, get_current_epoch(state)) {
        return Err(StfError::ValidatorNotSlashable(index));
    }
    // Verify signatures: in the batch of the block.

    slash_validator(state, index, None, ctx.total_active_balance())
}

/// `process_attester_slashing` (P0 L2449-2462): slashes each slashable validator that is in
/// both attestations of a double vote or a surround vote, in index order. The BLS checks of
/// the two attestations are not here: see the module documentation. On `Err`, `state` is
/// partly updated: the caller drops it.
pub fn process_attester_slashing<E: Preset>(
    state: &mut BeaconState<E>,
    attester_slashing: &AttesterSlashing<E>,
) -> Result<(), StfError> {
    process_attester_slashing_with(state, attester_slashing, &mut BlockContext::default())
}

/// [`process_attester_slashing`] with the total active balance of `ctx`.
pub fn process_attester_slashing_with<E: Preset>(
    state: &mut BeaconState<E>,
    attester_slashing: &AttesterSlashing<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;
    if !is_slashable_attestation_data(&attestation_1.data, &attestation_2.data) {
        return Err(StfError::NotSlashableAttestationData);
    }
    check_indexed_attestation(state, attestation_1)?;
    check_indexed_attestation(state, attestation_2)?;

    // The checks prove that both index lists are sorted and unique, so the indices of the
    // first list that are also in the second are `sorted(indices)`.
    let indices_2 = attestation_2.attesting_indices.as_slice();
    let mut slashed_any = false;
    for &index in attestation_1.attesting_indices.iter() {
        if indices_2.binary_search(&index).is_err() {
            continue;
        }
        let validator = state
            .validators
            .get(index as usize)
            .ok_or(StfError::UnknownValidator(index))?;
        if is_slashable_validator(validator, get_current_epoch(state)) {
            slash_validator(state, index, None, ctx.total_active_balance())?;
            slashed_any = true;
        }
    }
    if !slashed_any {
        return Err(StfError::NoValidatorSlashed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caches::get_beacon_proposer_index;
    use crate::state_root;
    use crate::testing::genesis_state;
    use consensus_types::common::{
        AttestationData, BeaconBlockHeader, Checkpoint, SignedBeaconBlockHeader,
    };
    use consensus_types::gloas::IndexedAttestation;
    use consensus_types::primitives::{Epoch, Gwei, Root, ValidatorIndex};
    use consensus_types::Minimal;

    const ETH: Gwei = 1_000_000_000;

    /// 8 validators of 32 ETH at slot 9 (epoch 1).
    fn state() -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        state.slot = 9;
        state
    }

    fn signed(slot: u64, proposer_index: u64, body: u8) -> SignedBeaconBlockHeader {
        SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot,
                proposer_index,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body_root: Root::repeat_byte(body),
            },
            signature: [body; 96],
        }
    }

    fn proposer_slashing(index: ValidatorIndex) -> ProposerSlashing {
        ProposerSlashing {
            signed_header_1: signed(5, index, 1),
            signed_header_2: signed(5, index, 2),
        }
    }

    fn data(source: Epoch, target: Epoch, root: u8) -> AttestationData {
        AttestationData {
            slot: 0,
            index: 0,
            beacon_block_root: Root::repeat_byte(root),
            source: Checkpoint {
                epoch: source,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: target,
                root: Root::ZERO,
            },
        }
    }

    fn indexed(indices: &[u64], data: AttestationData) -> IndexedAttestation<Minimal> {
        IndexedAttestation {
            attesting_indices: indices.to_vec().try_into().unwrap(),
            data,
            signature: [0x44; 96],
        }
    }

    /// A double vote of `indices_1` and `indices_2` in epoch 1.
    fn double_vote(indices_1: &[u64], indices_2: &[u64]) -> AttesterSlashing<Minimal> {
        AttesterSlashing {
            attestation_1: indexed(indices_1, data(0, 1, 1)),
            attestation_2: indexed(indices_2, data(0, 1, 2)),
        }
    }

    #[test]
    fn proposer_slashing_cases() {
        let mut state = state();
        assert_eq!(
            process_proposer_slashing(&mut state, &proposer_slashing(3)),
            Ok(())
        );
        assert!(state.validators.get(3).unwrap().slashed);
        assert!(*state.balances.get(3).unwrap() < 32 * ETH);

        let state = self::state();
        let refused = |slashing: &ProposerSlashing| {
            let mut copy = state.clone();
            let before = state_root(&mut copy).unwrap();
            let result = process_proposer_slashing(&mut copy, slashing);
            assert_eq!(state_root(&mut copy).unwrap(), before);
            result
        };
        let mut slots = proposer_slashing(3);
        slots.signed_header_2.message.slot = 6;
        assert_eq!(
            refused(&slots),
            Err(StfError::ProposerSlashingSlots {
                slot_1: 5,
                slot_2: 6
            })
        );
        let mut proposers = proposer_slashing(3);
        proposers.signed_header_2.message.proposer_index = 4;
        assert_eq!(
            refused(&proposers),
            Err(StfError::ProposerSlashingProposers {
                proposer_1: 3,
                proposer_2: 4
            })
        );
        // Two signatures of one header are not a slashing.
        let mut same = proposer_slashing(3);
        same.signed_header_2.message = same.signed_header_1.message.clone();
        assert_eq!(refused(&same), Err(StfError::ProposerSlashingSameHeaders));
        assert_eq!(
            refused(&proposer_slashing(8)),
            Err(StfError::UnknownValidator(8))
        );

        // `is_slashable_validator`: slashed, not active yet, or withdrawable.
        let not_slashable = |edit: &dyn Fn(&mut Validator)| {
            let mut copy = state.clone();
            edit(copy.validators.get_mut(3).unwrap());
            process_proposer_slashing(&mut copy, &proposer_slashing(3))
        };
        let want = Err(StfError::ValidatorNotSlashable(3));
        assert_eq!(not_slashable(&|v| v.slashed = true), want);
        assert_eq!(not_slashable(&|v| v.activation_epoch = 2), want);
        assert_eq!(not_slashable(&|v| v.withdrawable_epoch = 1), want);
        // Active from the current epoch, and withdrawable in the next one: slashable.
        assert_eq!(
            not_slashable(&|v| {
                v.activation_epoch = 1;
                v.withdrawable_epoch = 2;
            }),
            Ok(())
        );
    }

    #[test]
    fn attester_slashing_cases() {
        // A double vote slashes the validators in both attestations, in index order.
        let mut state = state();
        let slashing = double_vote(&[1, 2, 5], &[2, 3, 5]);
        assert_eq!(process_attester_slashing(&mut state, &slashing), Ok(()));
        let slashed: Vec<bool> = state.validators.iter().map(|v| v.slashed).collect();
        assert_eq!(
            slashed,
            [false, false, true, false, false, true, false, false]
        );

        // A surround vote: source 0 < 1 and target 2 < 3.
        let mut state = self::state();
        let surround = AttesterSlashing {
            attestation_1: indexed(&[4], data(0, 3, 1)),
            attestation_2: indexed(&[4], data(1, 2, 1)),
        };
        assert_eq!(process_attester_slashing(&mut state, &surround), Ok(()));
        assert!(state.validators.get(4).unwrap().slashed);

        let state = self::state();
        let refused = |slashing: &AttesterSlashing<Minimal>| {
            let mut copy = state.clone();
            let before = state_root(&mut copy).unwrap();
            let result = process_attester_slashing(&mut copy, slashing);
            assert_eq!(state_root(&mut copy).unwrap(), before);
            result
        };
        // The same data, and two votes of other target epochs that do not surround.
        let same = AttesterSlashing {
            attestation_1: indexed(&[4], data(0, 1, 1)),
            attestation_2: indexed(&[4], data(0, 1, 1)),
        };
        assert_eq!(refused(&same), Err(StfError::NotSlashableAttestationData));
        let apart = AttesterSlashing {
            attestation_1: indexed(&[4], data(0, 1, 1)),
            attestation_2: indexed(&[4], data(0, 2, 1)),
        };
        assert_eq!(refused(&apart), Err(StfError::NotSlashableAttestationData));
        // Indices that are empty, not sorted, or not unique, in either attestation.
        for (indices_1, indices_2) in [
            (&[][..], &[4][..]),
            (&[4], &[]),
            (&[5, 4], &[4]),
            (&[4], &[4, 4]),
        ] {
            assert_eq!(
                refused(&double_vote(indices_1, indices_2)),
                Err(StfError::InvalidIndexedAttestation),
                "{indices_1:?} {indices_2:?}"
            );
        }
        assert_eq!(
            refused(&double_vote(&[4], &[4, 8])),
            Err(StfError::UnknownValidator(8))
        );
        // No common index, or only validators that are slashed already.
        assert_eq!(
            refused(&double_vote(&[1], &[2])),
            Err(StfError::NoValidatorSlashed)
        );
        let mut slashed = state.clone();
        slashed.validators.get_mut(4).unwrap().slashed = true;
        assert_eq!(
            process_attester_slashing(&mut slashed, &double_vote(&[4], &[4])),
            Err(StfError::NoValidatorSlashed)
        );
    }

    #[test]
    fn slash_reads_the_guarded_proposer() {
        // A proposer index of our own lookahead past the registry is a fault of our state,
        // not a proof that the slashing is invalid.
        let mut state = state();
        let proposer = get_beacon_proposer_index(&state).unwrap();
        let slashed = (proposer + 1) % 8;
        *state.proposer_lookahead.get_mut(9 % 8).unwrap() = 8;
        let fault = StfError::ListIndexOutOfRange {
            list: "validators",
            index: 8,
        };
        let result = process_proposer_slashing(&mut state.clone(), &proposer_slashing(slashed));
        assert_eq!(result, Err(fault.clone()));
        assert!(!fault.proves_invalid());
        assert_eq!(
            process_attester_slashing(&mut state, &double_vote(&[slashed], &[slashed])),
            Err(fault)
        );
    }
}
