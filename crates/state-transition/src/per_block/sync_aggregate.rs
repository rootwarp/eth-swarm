//! `process_sync_aggregate` (A L635-695, which Gloas keeps) and the indices of the sync
//! committee members.
//!
//! The signature check of L640-664 is in [`crate::signatures::sync_aggregate_signature_set`];
//! [`process_sync_aggregate`] applies the rewards only.

use crate::accessors::{base_reward_per_increment, get_total_active_balance};
use crate::mutators::{decrease_balance, increase_balance};
use crate::per_block::{state_proposer_index, BlockContext};
use crate::preset::{EFFECTIVE_BALANCE_INCREMENT, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR};
use crate::signatures::G2_POINT_AT_INFINITY;
use crate::{Preset, StfError};
use consensus_types::common::SyncAggregate;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{BLSPubkey, ValidatorIndex};
use ssz_types::typenum::Unsigned;
use std::collections::HashMap;

/// `SYNC_REWARD_WEIGHT` (A L142).
const SYNC_REWARD_WEIGHT: u64 = 2;

/// `process_sync_aggregate` (A L635-695): rewards each participant of the current sync
/// committee and the proposer, and penalizes each member that did not participate.
///
/// The BLS check of the aggregate signature (L640-664) is not here: the caller gives
/// [`crate::signatures::sync_aggregate_signature_set`] to the backend, in the one batch of
/// [`crate::signatures::block_signature_sets`], or calls
/// [`crate::signatures::verify_sync_aggregate_signature`]. The part of
/// `eth_fast_aggregate_verify` that needs no BLS is here, so it runs in every mode: an empty
/// aggregate whose signature is not `G2_POINT_AT_INFINITY` is
/// [`StfError::InvalidSyncAggregateSignature`].
pub fn process_sync_aggregate<E: Preset>(
    state: &mut BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
) -> Result<(), StfError> {
    process_sync_aggregate_with(state, sync_aggregate, &mut BlockContext::default())
}

/// [`process_sync_aggregate`] with the committee indices of `ctx`, which the signature set
/// of the same block can compute first.
pub fn process_sync_aggregate_with<E: Preset>(
    state: &mut BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    if sync_aggregate.sync_committee_bits.is_zero()
        && sync_aggregate.sync_committee_signature != G2_POINT_AT_INFINITY
    {
        return Err(StfError::InvalidSyncAggregateSignature);
    }
    // Compute participant and proposer rewards
    let total_active_balance = get_total_active_balance(state)?;
    let total_active_increments = total_active_balance / EFFECTIVE_BALANCE_INCREMENT;
    let total_base_rewards = base_reward_per_increment(total_active_balance)
        .checked_mul(total_active_increments)
        .ok_or(StfError::ArithmeticOverflow)?;
    let max_participant_rewards = total_base_rewards
        .checked_mul(SYNC_REWARD_WEIGHT)
        .ok_or(StfError::ArithmeticOverflow)?
        / WEIGHT_DENOMINATOR
        / E::slots_per_epoch();
    let participant_reward = max_participant_rewards / E::SyncCommitteeSize::to_u64();
    let proposer_reward = participant_reward
        .checked_mul(PROPOSER_WEIGHT)
        .ok_or(StfError::ArithmeticOverflow)?
        / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

    // Apply participant and proposer rewards
    let committee_indices = ctx.sync_committee_indices(state)?;
    let proposer_index = state_proposer_index(state)?;
    for (&participant_index, participation_bit) in committee_indices
        .iter()
        .zip(sync_aggregate.sync_committee_bits.iter())
    {
        if participation_bit {
            increase_balance(state, participant_index, participant_reward)?;
            increase_balance(state, proposer_index, proposer_reward)?;
        } else {
            decrease_balance(state, participant_index, participant_reward)?;
        }
    }
    Ok(())
}

/// `committee_indices` of `process_sync_aggregate` (A L684-686): the validator index of each
/// pubkey of `state.current_sync_committee`, the first one with that pubkey, as
/// `all_pubkeys.index(pubkey)` gives it. A pubkey that no validator has is
/// [`StfError::UnknownSyncCommitteeMember`].
///
/// One pass over the registry, which stops when every committee pubkey is found.
pub fn sync_committee_indices<E: Preset>(
    state: &BeaconState<E>,
) -> Result<Vec<ValidatorIndex>, StfError> {
    let pubkeys = &state.current_sync_committee.pubkeys;
    let mut found: HashMap<&BLSPubkey, Option<ValidatorIndex>> =
        pubkeys.iter().map(|pubkey| (pubkey, None)).collect();
    let mut missing = found.len();
    for (index, validator) in state.validators.iter().enumerate() {
        if missing == 0 {
            break;
        }
        if let Some(slot @ None) = found.get_mut(&validator.pubkey) {
            *slot = Some(index as ValidatorIndex);
            missing -= 1;
        }
    }
    pubkeys
        .iter()
        .enumerate()
        .map(|(position, pubkey)| {
            found
                .get(pubkey)
                .copied()
                .flatten()
                .ok_or(StfError::UnknownSyncCommitteeMember { position })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caches::get_beacon_proposer_index;
    use crate::testing::genesis_state;
    use consensus_types::{EthSpec, Minimal};

    const ETH: u64 = 1_000_000_000;
    type Size = <Minimal as EthSpec>::SyncCommitteeSize;

    /// 64 validators of 32 ETH at slot 1, whose sync committee is validators `0..32` in order.
    fn state() -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        state.slot = 1;
        for i in 0..Size::to_usize() {
            let pubkey = state.validators.get(i).unwrap().pubkey;
            state.current_sync_committee.pubkeys[i] = pubkey;
        }
        state
    }

    fn aggregate(participants: &[usize]) -> SyncAggregate<Minimal> {
        let mut aggregate = SyncAggregate {
            sync_committee_bits: Default::default(),
            sync_committee_signature: G2_POINT_AT_INFINITY,
        };
        for &i in participants {
            aggregate.sync_committee_bits.set(i, true).unwrap();
        }
        aggregate
    }

    #[test]
    fn rewards_follow_the_spec_arithmetic() {
        let mut state = state();
        let proposer = get_beacon_proposer_index(&state).unwrap() as usize;
        // 64 * 32 ETH active: base reward per increment 64e9 / isqrt(2048e9) = 44721.
        let total = 64 * 32 * ETH;
        assert_eq!(get_total_active_balance(&state), Ok(total));
        assert_eq!(base_reward_per_increment(total), 44_721);
        let participant_reward = 44_721 * 2048 * 2 / 64 / 8 / 32;
        let proposer_reward = participant_reward * 8 / 56;

        let participants = [0usize, 5, 31];
        process_sync_aggregate(&mut state, &aggregate(&participants)).unwrap();
        for i in 0..64usize {
            let mut want = 32 * ETH;
            if i < 32 {
                if participants.contains(&i) {
                    want += participant_reward;
                } else {
                    want -= participant_reward;
                }
            }
            if i == proposer {
                want += proposer_reward * participants.len() as u64;
            }
            assert_eq!(*state.balances.get(i).unwrap(), want, "validator {i}");
        }
    }

    #[test]
    fn empty_participation_penalizes_every_member() {
        let mut state = state();
        // A member at a zero balance stays at zero.
        *state.balances.get_mut(3).unwrap() = 0;
        process_sync_aggregate(&mut state, &aggregate(&[])).unwrap();
        assert_eq!(*state.balances.get(3).unwrap(), 0);
        assert!(*state.balances.get(4).unwrap() < 32 * ETH);
        assert_eq!(*state.balances.get(40).unwrap(), 32 * ETH);
    }

    #[test]
    fn committee_indices_take_the_first_validator_with_the_key() {
        let mut state = state();
        // Two members with the key of validator 7, and validator 50 with that key too.
        let key7 = state.validators.get(7).unwrap().pubkey;
        state.current_sync_committee.pubkeys[1] = key7;
        state.validators.get_mut(50).unwrap().pubkey = key7;
        let indices = sync_committee_indices(&state).unwrap();
        assert_eq!(indices.len(), Size::to_usize());
        assert_eq!((indices[0], indices[1], indices[7]), (0, 7, 7));

        state.current_sync_committee.pubkeys[9] = [0xff; 48];
        assert_eq!(
            sync_committee_indices(&state),
            Err(StfError::UnknownSyncCommitteeMember { position: 9 })
        );
        assert_eq!(
            process_sync_aggregate(&mut state, &aggregate(&[0])),
            Err(StfError::UnknownSyncCommitteeMember { position: 9 })
        );
    }

    #[test]
    fn empty_aggregate_needs_the_infinity_signature() {
        // The check is a byte compare, not a BLS check, so it runs in every mode.
        let mut empty = aggregate(&[]);
        empty.sync_committee_signature = [0; 96];
        let mut state = state();
        let before = state.balances.get(0).copied();
        assert_eq!(
            process_sync_aggregate(&mut state, &empty),
            Err(StfError::InvalidSyncAggregateSignature)
        );
        assert_eq!(state.balances.get(0).copied(), before);
        // With participants, the signature is for the backend only.
        let mut one = aggregate(&[0]);
        one.sync_committee_signature = [0; 96];
        assert_eq!(process_sync_aggregate(&mut state, &one), Ok(()));
    }

    #[test]
    fn proposer_outside_the_registry_is_a_state_fault() {
        let mut state = state();
        *state.proposer_lookahead.get_mut(1).unwrap() = 64;
        let err = process_sync_aggregate(&mut state, &aggregate(&[0])).unwrap_err();
        assert_eq!(
            err,
            StfError::ListIndexOutOfRange {
                list: "validators",
                index: 64
            }
        );
        assert!(!err.proves_invalid());
    }

    #[test]
    fn balance_errors_stop_the_rewards() {
        // A total active balance that overflows.
        let mut huge = state();
        huge.validators.get_mut(0).unwrap().effective_balance = u64::MAX;
        assert_eq!(
            process_sync_aggregate(&mut huge, &aggregate(&[])),
            Err(StfError::ArithmeticOverflow)
        );
        // A participant whose balance overflows.
        let mut full = state();
        *full.balances.get_mut(0).unwrap() = u64::MAX;
        assert_eq!(
            process_sync_aggregate(&mut full, &aggregate(&[0])),
            Err(StfError::ArithmeticOverflow)
        );
    }
}
