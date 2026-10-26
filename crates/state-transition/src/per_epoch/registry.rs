//! The registry steps of the epoch: activations and ejections (E L1057-1073), the slashing
//! penalties (E L1082-1102) and the effective balances (E L1238-1254), with the Electra
//! predicates that they read.
//!
//! Each step reads the registry in one pass, and then writes only the validators and the
//! balances that change. The decision for one validator reads only that validator and
//! fields that the step does not write, so the result is the result of the spec loop.

use crate::accessors::{
    compute_activation_exit_epoch, get_current_epoch, has_compounding_withdrawal_credential,
    is_active_validator, TotalActiveBalanceCache,
};
use crate::mutators::{decrease_balance, initiate_validator_exit};
use crate::preset::{
    EFFECTIVE_BALANCE_INCREMENT, EJECTION_BALANCE, HYSTERESIS_DOWNWARD_MULTIPLIER,
    HYSTERESIS_QUOTIENT, HYSTERESIS_UPWARD_MULTIPLIER, MAX_EFFECTIVE_BALANCE_ELECTRA,
    MIN_ACTIVATION_BALANCE, PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
};
use crate::{Preset, StfError};
use consensus_types::common::Validator;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Gwei, ValidatorIndex, FAR_FUTURE_EPOCH};
use ssz_types::typenum::Unsigned;

/// `is_eligible_for_activation_queue` (E L630-638, Modified in Electra).
pub fn is_eligible_for_activation_queue(validator: &Validator) -> bool {
    validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
        && validator.effective_balance >= MIN_ACTIVATION_BALANCE
}

/// `is_eligible_for_activation` (P0 L1114-1123).
pub fn is_eligible_for_activation<E: Preset>(
    state: &BeaconState<E>,
    validator: &Validator,
) -> bool {
    // Placement in queue is finalized
    validator.activation_eligibility_epoch <= state.finalized_checkpoint.epoch
        // Has not yet been activated
        && validator.activation_epoch == FAR_FUTURE_EPOCH
}

/// `get_max_effective_balance` (E L743-750, New in Electra).
pub fn get_max_effective_balance(validator: &Validator) -> Gwei {
    if has_compounding_withdrawal_credential(validator) {
        MAX_EFFECTIVE_BALANCE_ELECTRA
    } else {
        MIN_ACTIVATION_BALANCE
    }
}

/// What `process_registry_updates` does to one validator.
enum RegistryUpdate {
    Queue(ValidatorIndex),
    Eject(ValidatorIndex),
    Activate(ValidatorIndex),
}

/// `process_registry_updates` (E L1057-1073, Modified in Electra; Gloas keeps it).
pub fn process_registry_updates<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    process_registry_updates_with(state, &mut TotalActiveBalanceCache::default())
}

/// [`process_registry_updates`] with the exit churn from `totals`.
///
/// An ejection moves the exit queue, so the ejections run in registry order, as in the
/// spec. The decision for each validator reads only its own fields, the current epoch and
/// the finalized checkpoint, which the step does not write.
pub(crate) fn process_registry_updates_with<E: Preset>(
    state: &mut BeaconState<E>,
    totals: &mut TotalActiveBalanceCache,
) -> Result<(), StfError> {
    let current_epoch = get_current_epoch(state);
    let activation_epoch = compute_activation_exit_epoch(current_epoch)?;
    let updates: Vec<RegistryUpdate> = state
        .validators
        .iter()
        .enumerate()
        .filter_map(|(i, validator)| {
            let index = i as ValidatorIndex;
            if is_eligible_for_activation_queue(validator) {
                Some(RegistryUpdate::Queue(index))
            } else if is_active_validator(validator, current_epoch)
                && validator.effective_balance <= EJECTION_BALANCE
            {
                Some(RegistryUpdate::Eject(index))
            } else if is_eligible_for_activation(state, validator) {
                Some(RegistryUpdate::Activate(index))
            } else {
                None
            }
        })
        .collect();
    // Process activation eligibility, ejections, and activations
    for update in updates {
        match update {
            RegistryUpdate::Queue(index) => {
                let epoch = current_epoch
                    .checked_add(1)
                    .ok_or(StfError::ArithmeticOverflow)?;
                validator_mut(state, index)?.activation_eligibility_epoch = epoch;
            }
            RegistryUpdate::Eject(index) => initiate_validator_exit(state, index, totals)?,
            RegistryUpdate::Activate(index) => {
                validator_mut(state, index)?.activation_epoch = activation_epoch;
            }
        }
    }
    Ok(())
}

/// `state.validators[index]`, for an index that the step read from the registry.
fn validator_mut<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
) -> Result<&mut Validator, StfError> {
    state
        .validators
        .get_mut(index as usize)
        .ok_or(StfError::UnknownValidator(index))
}

/// `process_slashings` (E L1082-1102, Modified in Electra; Gloas keeps it).
pub fn process_slashings<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    process_slashings_with(state, &mut TotalActiveBalanceCache::default())
}

/// [`process_slashings`] with the total active balance from `totals`.
pub(crate) fn process_slashings_with<E: Preset>(
    state: &mut BeaconState<E>,
    totals: &mut TotalActiveBalanceCache,
) -> Result<(), StfError> {
    let overflow = || StfError::ArithmeticOverflow;
    let epoch = get_current_epoch(state);
    let total_balance = totals.get(state)?;
    let adjusted_total_slashing_balance = state
        .slashings
        .iter()
        .try_fold(0u64, |sum, s| sum.checked_add(*s))
        .and_then(|sum| sum.checked_mul(PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX))
        .ok_or_else(overflow)?
        .min(total_balance);
    // Factored out from total balance to avoid Uint64 overflow
    let increment = EFFECTIVE_BALANCE_INCREMENT;
    // `total_balance` is at least one increment, so the divisor is not zero.
    let penalty_per_effective_balance_increment =
        adjusted_total_slashing_balance / (total_balance / increment);
    let half_vector = E::EpochsPerSlashingsVector::to_u64() / 2;
    // The spec computes `epoch + EPOCHS_PER_SLASHINGS_VECTOR // 2` only for a slashed
    // validator, so an overflow fails only then.
    let withdrawable_epoch = epoch.checked_add(half_vector);
    let mut penalties = Vec::new();
    for (i, validator) in state.validators.iter().enumerate() {
        if !validator.slashed {
            continue;
        }
        if withdrawable_epoch.ok_or_else(overflow)? != validator.withdrawable_epoch {
            continue;
        }
        let effective_balance_increments = validator.effective_balance / increment;
        let penalty = penalty_per_effective_balance_increment
            .checked_mul(effective_balance_increments)
            .ok_or_else(overflow)?;
        penalties.push((i as ValidatorIndex, penalty));
    }
    for (index, penalty) in penalties {
        decrease_balance(state, index, penalty)?;
    }
    Ok(())
}

/// `process_effective_balance_updates` (E L1238-1254, Modified in Electra; Gloas keeps it).
///
/// It changes the effective balances, so a [`TotalActiveBalanceCache`] of this epoch is
/// stale after it (see the limits of that cache).
pub fn process_effective_balance_updates<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    let overflow = || StfError::ArithmeticOverflow;
    let hysteresis_increment = EFFECTIVE_BALANCE_INCREMENT / HYSTERESIS_QUOTIENT;
    let downward_threshold = hysteresis_increment * HYSTERESIS_DOWNWARD_MULTIPLIER;
    let upward_threshold = hysteresis_increment * HYSTERESIS_UPWARD_MULTIPLIER;
    let mut updates: Vec<(usize, Gwei)> = Vec::new();
    // Update effective balances with hysteresis
    for (index, validator) in state.validators.iter().enumerate() {
        let balance = *state
            .balances
            .get(index)
            .ok_or(StfError::ListIndexOutOfRange {
                list: "balances",
                index: index as u64,
            })?;
        let max_effective_balance = get_max_effective_balance(validator);
        let effective_balance = validator.effective_balance;
        let below = balance
            .checked_add(downward_threshold)
            .ok_or_else(overflow)?
            < effective_balance;
        if below
            || effective_balance
                .checked_add(upward_threshold)
                .ok_or_else(overflow)?
                < balance
        {
            let new = (balance - balance % EFFECTIVE_BALANCE_INCREMENT).min(max_effective_balance);
            updates.push((index, new));
        }
    }
    for (index, effective_balance) in updates {
        validator_mut(state, index as ValidatorIndex)?.effective_balance = effective_balance;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::{is_compounding_withdrawal_credential, TotalActiveBalanceCache};
    use crate::preset::{EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE_ELECTRA};
    use crate::testing::registry_state;
    use crate::StfError;
    use consensus_types::gloas::BeaconState;
    use consensus_types::primitives::{Bytes32, Gwei, FAR_FUTURE_EPOCH};
    use consensus_types::{EthSpec, Minimal};
    use ssz_types::typenum::Unsigned;

    const ETH: Gwei = 1_000_000_000;

    /// A minimal state of `balances` (also the effective balances) at the last slot of
    /// `epoch`, with a zero lookahead.
    fn state_at(balances: &[Gwei], epoch: u64) -> BeaconState<Minimal> {
        let mut state = registry_state::<Minimal>(balances, Bytes32::ZERO);
        state.slot = Minimal::start_slot_at_epoch(epoch + 1) - 1;
        state
    }

    #[test]
    fn registry_updates_queue_eject_and_activate() {
        let mut state = state_at(&[32 * ETH; 6], 4);
        state.finalized_checkpoint.epoch = 3;
        let set = |state: &mut BeaconState<Minimal>, i: usize, f: fn(&mut _)| {
            f(state.validators.get_mut(i).unwrap())
        };
        // 0: a new deposit of the minimum activation balance joins the queue.
        set(&mut state, 0, |v| {
            v.activation_eligibility_epoch = FAR_FUTURE_EPOCH;
            v.activation_epoch = FAR_FUTURE_EPOCH;
        });
        // 1: below the minimum activation balance, it does not join the queue.
        set(&mut state, 1, |v| {
            v.activation_eligibility_epoch = FAR_FUTURE_EPOCH;
            v.activation_epoch = FAR_FUTURE_EPOCH;
            v.effective_balance = 31 * ETH;
        });
        // 2: active at the ejection balance, it exits.
        set(&mut state, 2, |v| v.effective_balance = 16 * ETH);
        // 3: in the queue at a finalized epoch, it activates.
        set(&mut state, 3, |v| {
            v.activation_eligibility_epoch = 3;
            v.activation_epoch = FAR_FUTURE_EPOCH;
        });
        // 4: in the queue at an epoch that is not finalized, it waits.
        set(&mut state, 4, |v| {
            v.activation_eligibility_epoch = 4;
            v.activation_epoch = FAR_FUTURE_EPOCH;
        });
        let pre = state.clone();
        process_registry_updates(&mut state).unwrap();
        let v = |i: usize| state.validators.get(i).unwrap().clone();
        assert_eq!(v(0).activation_eligibility_epoch, 5);
        assert_eq!(v(1), pre.validators.get(1).unwrap().clone());
        // compute_activation_exit_epoch(4) = 9, and the exit churn has room for 16 ETH.
        assert_eq!((v(2).exit_epoch, v(2).withdrawable_epoch), (9, 9 + 256));
        assert_eq!(v(3).activation_epoch, 9);
        assert_eq!(v(4).activation_epoch, FAR_FUTURE_EPOCH);
        assert_eq!(v(5), pre.validators.get(5).unwrap().clone());
        assert_eq!(state.earliest_exit_epoch, 9);

        // The cached variant gives the same state.
        let mut cached = pre.clone();
        process_registry_updates_with(&mut cached, &mut TotalActiveBalanceCache::default())
            .unwrap();
        assert_eq!(cached, state);
    }

    #[test]
    fn eligibility_predicates() {
        let state = state_at(&[32 * ETH], 4);
        let mut v = state.validators.get(0).unwrap().clone();
        v.activation_eligibility_epoch = FAR_FUTURE_EPOCH;
        assert!(is_eligible_for_activation_queue(&v));
        v.effective_balance = 32 * ETH - 1;
        assert!(!is_eligible_for_activation_queue(&v));
        v.activation_eligibility_epoch = 0;
        v.activation_epoch = FAR_FUTURE_EPOCH;
        assert!(is_eligible_for_activation(&state, &v));
        v.activation_epoch = 7;
        assert!(!is_eligible_for_activation(&state, &v));
        v.activation_epoch = FAR_FUTURE_EPOCH;
        v.activation_eligibility_epoch = 1;
        assert!(!is_eligible_for_activation(&state, &v));

        let mut credentials = Bytes32::ZERO;
        assert_eq!(get_max_effective_balance(&v), 32 * ETH);
        credentials[0] = 0x02;
        assert!(is_compounding_withdrawal_credential(&credentials));
        v.withdrawal_credentials = credentials;
        assert!(has_compounding_withdrawal_credential(&v));
        assert_eq!(get_max_effective_balance(&v), MAX_EFFECTIVE_BALANCE_ELECTRA);
        credentials[0] = 0x01;
        assert!(!is_compounding_withdrawal_credential(&credentials));
    }

    #[test]
    fn slashings_penalize_at_the_half_of_the_vector() {
        let n = <Minimal as EthSpec>::EpochsPerSlashingsVector::to_u64();
        let mut state = state_at(&[32 * ETH; 4], 10);
        for i in [0, 1] {
            let v = state.validators.get_mut(i).unwrap();
            v.slashed = true;
            v.withdrawable_epoch = 10 + n / 2;
        }
        // 2: slashed, but not at the half of the vector.
        let v = state.validators.get_mut(2).unwrap();
        v.slashed = true;
        v.withdrawable_epoch = 10 + n / 2 + 1;
        *state.slashings.get_mut(3).unwrap() = 10 * ETH;
        *state.slashings.get_mut(9).unwrap() = 6 * ETH;
        let mut post = state.clone();
        process_slashings(&mut post).unwrap();
        // The total is 128 ETH, so min(16 ETH * 3, 128 ETH) // 128 = 375,000,000 Gwei for
        // each increment of 32.
        let penalty = 48 * ETH / 128 * 32;
        assert_eq!(
            post.balances.to_vec(),
            [32 * ETH - penalty, 32 * ETH - penalty, 32 * ETH, 32 * ETH]
        );

        // The adjusted total is capped at the total active balance.
        *state.slashings.get_mut(9).unwrap() = 1_000 * ETH;
        process_slashings_with(&mut state, &mut TotalActiveBalanceCache::default()).unwrap();
        assert_eq!(state.balances.get(0), Some(&0));

        // The sum of the vector overflows.
        *state.slashings.get_mut(4).unwrap() = u64::MAX;
        assert_eq!(
            process_slashings(&mut state),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn effective_balances_follow_the_hysteresis() {
        let mut state = state_at(&[32 * ETH; 6], 4);
        let mut compounding = Bytes32::ZERO;
        compounding[0] = 0x02;
        state.validators.get_mut(4).unwrap().withdrawal_credentials = compounding;
        let quarter = EFFECTIVE_BALANCE_INCREMENT / 4;
        let balances = [
            // A drop of one quarter increment keeps the effective balance.
            32 * ETH - quarter,
            // A drop past it rounds down.
            32 * ETH - quarter - 1,
            // A rise past five quarters is capped at MIN_ACTIVATION_BALANCE for 0x00.
            40 * ETH,
            // A rise of exactly five quarters keeps it.
            32 * ETH + 5 * quarter,
            // A compounding validator rises to its rounded balance.
            40 * ETH + 7,
            // A compounding cap of 2048 ETH: not this validator, so the cap is 32 ETH.
            3_000 * ETH,
        ];
        for (i, b) in balances.iter().enumerate() {
            *state.balances.get_mut(i).unwrap() = *b;
        }
        process_effective_balance_updates(&mut state).unwrap();
        let effective: Vec<Gwei> = state
            .validators
            .iter()
            .map(|v| v.effective_balance)
            .collect();
        assert_eq!(
            effective,
            [32 * ETH, 31 * ETH, 32 * ETH, 32 * ETH, 40 * ETH, 32 * ETH]
        );

        // A balances list shorter than the registry is our own state error.
        state.balances = milhouse::ProgressiveList::try_from_iter([32 * ETH]).unwrap();
        let err = process_effective_balance_updates(&mut state).unwrap_err();
        assert_eq!(
            err,
            StfError::ListIndexOutOfRange {
                list: "balances",
                index: 1
            }
        );
        // `balance + DOWNWARD_THRESHOLD` overflows.
        let mut state = state_at(&[32 * ETH], 4);
        *state.balances.get_mut(0).unwrap() = u64::MAX;
        assert_eq!(
            process_effective_balance_updates(&mut state),
            Err(StfError::ArithmeticOverflow)
        );
    }
}
