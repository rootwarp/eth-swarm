//! The spec-literal epoch accounting: the test oracles of the cached steps. Each function
//! is the spec text line by line, with a set of participants built for each query.
//!
//! The oracle writes `weigh_justification_and_finalization`, the leak and eligibility
//! predicates, the total active balance, the base reward and the balance helpers again from
//! the spec text, so `cached_vs_literal` can find a bug in any of them.
//!
//! The oracle calls these functions of the crate, and does not write them again:
//!
//! - `get_unslashed_participating_indices` and `get_total_balance`, which the cached steps
//!   do not call.
//! - `get_active_validator_indices`, which the cached steps do not call, but which calls
//!   `is_active_validator`.
//! - `get_block_root` (and `get_block_root_at_slot` under it), `is_active_validator`,
//!   `has_flag` (in `get_unslashed_participating_indices`), `get_current_epoch` and
//!   `get_previous_epoch`, which the cached steps also call.
//!
//! Thus `cached_vs_literal` cannot find a bug in the functions of the last two items. Their
//! own unit tests and the spec vectors test them.

use super::inactivity::INACTIVITY_SCORE;
use super::justification::{JUSTIFICATION_TARGET_BALANCE, JUSTIFICATION_TOTAL_BALANCE};
use super::participation::{get_total_balance, get_unslashed_participating_indices};
use super::rewards::{
    Deltas, FLAG_PENALTY, FLAG_REWARD_NUMERATOR, INACTIVITY_PENALTY_NUMERATOR, REWARD_BALANCE,
};
use crate::accessors::{
    get_active_validator_indices, get_block_root, get_current_epoch, get_previous_epoch,
    is_active_validator,
};
use crate::preset::{
    BASE_REWARD_FACTOR, EFFECTIVE_BALANCE_INCREMENT, GENESIS_EPOCH,
    INACTIVITY_PENALTY_QUOTIENT_BELLATRIX, INACTIVITY_SCORE_BIAS, INACTIVITY_SCORE_RECOVERY_RATE,
    MIN_EPOCHS_TO_INACTIVITY_PENALTY, PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX, WEIGHT_DENOMINATOR,
};
use crate::{Preset, StfError};
use consensus_types::common::Checkpoint;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Epoch, Gwei, ValidatorIndex};
use std::collections::BTreeSet;

const OVERFLOW: StfError = StfError::ArithmeticOverflow;

/// The error of a failed sum of values of our own state: the cached steps give the same.
fn state_arithmetic(what: &'static str) -> StfError {
    StfError::StateArithmetic { what }
}

/// `process_justification_and_finalization` (A L730-746).
pub(crate) fn process_justification_and_finalization<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    // Initial FFG checkpoint values have a `0x00` stub for `root`.
    // Skip FFG updates in the first two epochs to avoid corner cases that might result in
    // modifying this stub.
    if get_current_epoch(state) <= GENESIS_EPOCH + 1 {
        return Ok(());
    }
    let previous_indices = get_unslashed_participating_indices(
        state,
        TIMELY_TARGET_FLAG_INDEX,
        get_previous_epoch(state),
    )?;
    let current_indices = get_unslashed_participating_indices(
        state,
        TIMELY_TARGET_FLAG_INDEX,
        get_current_epoch(state),
    )?;
    let total_active_balance = get_total_active_balance(state)?;
    let previous_target_balance = get_total_balance(state, &previous_indices)?;
    let current_target_balance = get_total_balance(state, &current_indices)?;
    weigh_justification_and_finalization(
        state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}

/// `process_inactivity_updates` (A L754-771).
pub(crate) fn process_inactivity_updates<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    if get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(());
    }
    for index in get_eligible_validator_indices(state) {
        let i = index as usize;
        let range = StfError::ListIndexOutOfRange {
            list: "inactivity_scores",
            index,
        };
        if get_unslashed_participating_indices(
            state,
            TIMELY_TARGET_FLAG_INDEX,
            get_previous_epoch(state),
        )?
        .contains(&index)
        {
            let score = state.inactivity_scores.get_mut(i).ok_or(range.clone())?;
            *score = score.saturating_sub(1);
        } else {
            let score = state.inactivity_scores.get_mut(i).ok_or(range.clone())?;
            *score = score
                .checked_add(INACTIVITY_SCORE_BIAS)
                .ok_or(state_arithmetic(INACTIVITY_SCORE))?;
        }
        if !is_in_inactivity_leak(state)? {
            let score = state.inactivity_scores.get_mut(i).ok_or(range)?;
            *score = score.saturating_sub(INACTIVITY_SCORE_RECOVERY_RATE);
        }
    }
    Ok(())
}

/// `get_flag_index_deltas` (A L459-485).
pub(crate) fn get_flag_index_deltas<E: Preset>(
    state: &BeaconState<E>,
    flag_index: usize,
) -> Result<Deltas, StfError> {
    let n = state.validators.len();
    let mut rewards: Vec<Gwei> = vec![0; n];
    let mut penalties: Vec<Gwei> = vec![0; n];
    let previous_epoch = get_previous_epoch(state);
    let unslashed_participating_indices =
        get_unslashed_participating_indices(state, flag_index, previous_epoch)?;
    let weight =
        *PARTICIPATION_FLAG_WEIGHTS
            .get(flag_index)
            .ok_or(StfError::ListIndexOutOfRange {
                list: "PARTICIPATION_FLAG_WEIGHTS",
                index: flag_index as u64,
            })?;
    let unslashed_participating_balance =
        get_total_balance(state, &unslashed_participating_indices)?;
    let unslashed_participating_increments =
        unslashed_participating_balance / EFFECTIVE_BALANCE_INCREMENT;
    let active_increments = get_total_active_balance(state)? / EFFECTIVE_BALANCE_INCREMENT;
    for index in get_eligible_validator_indices(state) {
        let i = index as usize;
        let base_reward = get_base_reward(state, index)?;
        if unslashed_participating_indices.contains(&index) {
            if !is_in_inactivity_leak(state)? {
                let reward_numerator = base_reward
                    .checked_mul(weight)
                    .and_then(|r| r.checked_mul(unslashed_participating_increments))
                    .ok_or(state_arithmetic(FLAG_REWARD_NUMERATOR))?;
                let denominator = active_increments
                    .checked_mul(WEIGHT_DENOMINATOR)
                    .ok_or(OVERFLOW)?;
                rewards[i] = rewards[i]
                    .checked_add(reward_numerator / denominator)
                    .ok_or(OVERFLOW)?;
            }
        } else if flag_index != TIMELY_HEAD_FLAG_INDEX {
            let penalty = base_reward
                .checked_mul(weight)
                .ok_or(state_arithmetic(FLAG_PENALTY))?
                / WEIGHT_DENOMINATOR;
            penalties[i] = penalties[i].checked_add(penalty).ok_or(OVERFLOW)?;
        }
    }
    Ok((rewards, penalties))
}

/// `get_inactivity_penalty_deltas` (Bx L292-310).
pub(crate) fn get_inactivity_penalty_deltas<E: Preset>(
    state: &BeaconState<E>,
) -> Result<Deltas, StfError> {
    let n = state.validators.len();
    let rewards = vec![0; n];
    let mut penalties: Vec<Gwei> = vec![0; n];
    let previous_epoch = get_previous_epoch(state);
    let matching_target_indices =
        get_unslashed_participating_indices(state, TIMELY_TARGET_FLAG_INDEX, previous_epoch)?;
    for index in get_eligible_validator_indices(state) {
        if !matching_target_indices.contains(&index) {
            let i = index as usize;
            let effective_balance = state
                .validators
                .get(i)
                .ok_or(StfError::UnknownValidator(index))?
                .effective_balance;
            let score = *state
                .inactivity_scores
                .get(i)
                .ok_or(StfError::ListIndexOutOfRange {
                    list: "inactivity_scores",
                    index,
                })?;
            let penalty_numerator = effective_balance
                .checked_mul(score)
                .ok_or(state_arithmetic(INACTIVITY_PENALTY_NUMERATOR))?;
            let penalty_denominator = INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
            penalties[i] = penalties[i]
                .checked_add(penalty_numerator / penalty_denominator)
                .ok_or(OVERFLOW)?;
        }
    }
    Ok((rewards, penalties))
}

/// `process_rewards_and_penalties` (A L780-793).
pub(crate) fn process_rewards_and_penalties<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    if get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(());
    }
    let mut deltas = Vec::new();
    for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
        deltas.push(get_flag_index_deltas(state, flag_index)?);
    }
    deltas.push(get_inactivity_penalty_deltas(state)?);
    for (rewards, penalties) in deltas {
        for index in 0..state.validators.len() {
            increase_balance(state, index as ValidatorIndex, rewards[index])?;
            decrease_balance(state, index as ValidatorIndex, penalties[index])?;
        }
    }
    Ok(())
}

/// `increase_balance` (P0 L1653-1657).
fn increase_balance<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
    delta: Gwei,
) -> Result<(), StfError> {
    let balance = balance_mut(state, index)?;
    *balance = balance
        .checked_add(delta)
        .ok_or(state_arithmetic(REWARD_BALANCE))?;
    Ok(())
}

/// `decrease_balance` (P0 L1663-1667).
fn decrease_balance<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
    delta: Gwei,
) -> Result<(), StfError> {
    let balance = balance_mut(state, index)?;
    *balance = balance.saturating_sub(delta);
    Ok(())
}

fn balance_mut<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
) -> Result<&mut Gwei, StfError> {
    state
        .balances
        .get_mut(index as usize)
        .ok_or(StfError::ListIndexOutOfRange {
            list: "balances",
            index,
        })
}

/// `weigh_justification_and_finalization` (P0 L1963-2002).
fn weigh_justification_and_finalization<E: Preset>(
    state: &mut BeaconState<E>,
    total_active_balance: Gwei,
    previous_epoch_target_balance: Gwei,
    current_epoch_target_balance: Gwei,
) -> Result<(), StfError> {
    let bit = |state: &BeaconState<E>, i: usize| state.justification_bits.get(i).unwrap();
    let previous_epoch = get_previous_epoch(state);
    let current_epoch = get_current_epoch(state);
    let old_previous_justified_checkpoint = state.previous_justified_checkpoint.clone();
    let old_current_justified_checkpoint = state.current_justified_checkpoint.clone();

    // Process justifications
    state.previous_justified_checkpoint = state.current_justified_checkpoint.clone();
    // state.justification_bits[1:] = state.justification_bits[:JUSTIFICATION_BITS_LENGTH - 1]
    let shifted: Vec<bool> = (0..3).map(|i| bit(state, i)).collect();
    for (i, b) in shifted.into_iter().enumerate() {
        state.justification_bits.set(i + 1, b).unwrap();
    }
    state.justification_bits.set(0, false).unwrap();
    let times = |a: Gwei, k: u64, what| a.checked_mul(k).ok_or(state_arithmetic(what));
    let target = |balance| times(balance, 3, JUSTIFICATION_TARGET_BALANCE);
    let total = || times(total_active_balance, 2, JUSTIFICATION_TOTAL_BALANCE);
    if target(previous_epoch_target_balance)? >= total()? {
        state.current_justified_checkpoint = Checkpoint {
            epoch: previous_epoch,
            root: get_block_root(state, previous_epoch)?,
        };
        state.justification_bits.set(1, true).unwrap();
    }
    if target(current_epoch_target_balance)? >= total()? {
        state.current_justified_checkpoint = Checkpoint {
            epoch: current_epoch,
            root: get_block_root(state, current_epoch)?,
        };
        state.justification_bits.set(0, true).unwrap();
    }

    // Process finalizations
    let all = |state: &BeaconState<E>, from: usize, to: usize| (from..to).all(|i| bit(state, i));
    let plus = |e: Epoch, k: u64| e.checked_add(k).ok_or(OVERFLOW);
    // The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if all(state, 1, 4) && plus(old_previous_justified_checkpoint.epoch, 3)? == current_epoch {
        state.finalized_checkpoint = old_previous_justified_checkpoint.clone();
    }
    // The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if all(state, 1, 3) && plus(old_previous_justified_checkpoint.epoch, 2)? == current_epoch {
        state.finalized_checkpoint = old_previous_justified_checkpoint;
    }
    // The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if all(state, 0, 3) && plus(old_current_justified_checkpoint.epoch, 2)? == current_epoch {
        state.finalized_checkpoint = old_current_justified_checkpoint.clone();
    }
    // The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if all(state, 0, 2) && plus(old_current_justified_checkpoint.epoch, 1)? == current_epoch {
        state.finalized_checkpoint = old_current_justified_checkpoint;
    }
    Ok(())
}

/// `integer_squareroot` (P0 L989-1000), the Newton loop of the spec.
fn integer_squareroot(n: u64) -> u64 {
    if n == u64::MAX {
        return 4_294_967_295;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// `get_total_active_balance` (P0 L1576-1583).
fn get_total_active_balance<E: Preset>(state: &BeaconState<E>) -> Result<Gwei, StfError> {
    let active: BTreeSet<ValidatorIndex> =
        get_active_validator_indices(state, get_current_epoch(state))
            .into_iter()
            .collect();
    get_total_balance(state, &active)
}

/// `get_base_reward_per_increment` (A L369-374).
fn get_base_reward_per_increment<E: Preset>(state: &BeaconState<E>) -> Result<Gwei, StfError> {
    Ok(EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR
        / integer_squareroot(get_total_active_balance(state)?))
}

/// `get_base_reward` (A L386-391).
fn get_base_reward<E: Preset>(
    state: &BeaconState<E>,
    index: ValidatorIndex,
) -> Result<Gwei, StfError> {
    let increments = state
        .validators
        .get(index as usize)
        .unwrap()
        .effective_balance
        / EFFECTIVE_BALANCE_INCREMENT;
    increments
        .checked_mul(get_base_reward_per_increment(state)?)
        .ok_or(OVERFLOW)
}

/// `get_finality_delay` (P0 L2027-2028).
fn get_finality_delay<E: Preset>(state: &BeaconState<E>) -> Result<Epoch, StfError> {
    get_previous_epoch(state)
        .checked_sub(state.finalized_checkpoint.epoch)
        .ok_or(state_arithmetic("finality delay"))
}

/// `is_in_inactivity_leak` (P0 L2032-2033).
fn is_in_inactivity_leak<E: Preset>(state: &BeaconState<E>) -> Result<bool, StfError> {
    Ok(get_finality_delay(state)? > MIN_EPOCHS_TO_INACTIVITY_PENALTY)
}

/// `get_eligible_validator_indices` (P0 L2037-2044).
fn get_eligible_validator_indices<E: Preset>(state: &BeaconState<E>) -> Vec<ValidatorIndex> {
    let previous_epoch = get_previous_epoch(state);
    state
        .validators
        .iter()
        .enumerate()
        .filter(|(_, v)| {
            is_active_validator(v, previous_epoch)
                || (v.slashed && previous_epoch + 1 < v.withdrawable_epoch)
        })
        .map(|(i, _)| i as ValidatorIndex)
        .collect()
}
