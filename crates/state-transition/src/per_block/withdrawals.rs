//! The Gloas withdrawals sweep: `process_withdrawals(state)` (G L2067-2092, Modified in
//! Gloas) and the functions that it calls.
//!
//! In Gloas the step takes the state only. The withdrawals follow from the state, and the
//! execution payload whose parent beacon block is this block must honor them. The step
//! returns early when the parent block is EMPTY (its payload did not arrive).
//!
//! The sweep has four parts, in this order:
//!
//! 1. The builder withdrawals that the epoch processing queued in
//!    `state.builder_pending_withdrawals` ([`get_builder_withdrawals`]).
//! 2. The pending partial withdrawals of the validators ([`get_pending_partial_withdrawals`]).
//! 3. The sweep of the builders ([`get_builders_sweep_withdrawals`]).
//! 4. The sweep of the validators ([`get_validators_sweep_withdrawals`]).
//!
//! Each part reads at most `MAX_WITHDRAWALS_PER_PAYLOAD` withdrawals, at most
//! `MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP` pending partial withdrawals, and at most
//! `MAX_BUILDERS_PER_WITHDRAWALS_SWEEP` builders or `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP`
//! validators. Thus no part reads the full registry.
//!
//! Every index that the sweep reads comes from the state: the queues and the two sweep
//! cursors. A state that the transition makes keeps them inside `validators`, `balances` and
//! `builders`. Thus an index past one of these lists is a fault of our own state
//! ([`StfError::ListIndexOutOfRange`]), never a proof that a block is invalid.
//!
//! The `Uint64` operands of the sweep come from the state only, too. A failed operation
//! (an overflow, an underflow or a division by zero) is [`StfError::StateArithmetic`], which
//! is not a proof either.

use crate::accessors::{
    convert_builder_index_to_validator_index, convert_validator_index_to_builder_index,
    get_current_epoch, has_execution_withdrawal_credential, is_builder_index,
};
use crate::mutators::decrease_balance;
use crate::per_epoch::registry::get_max_effective_balance;
use crate::preset::MIN_ACTIVATION_BALANCE;
use crate::{Preset, StfError};
use consensus_types::common::{Validator, Withdrawal};
use consensus_types::gloas::{BeaconState, Builder};
use consensus_types::primitives::{
    BuilderIndex, Epoch, ExecutionAddress, Gwei, ValidatorIndex, WithdrawalIndex, FAR_FUTURE_EPOCH,
};
use milhouse::ProgressiveList;
use ssz_types::typenum::Unsigned;

/// `ExpectedWithdrawals` (G L1005-1012, Modified in Gloas): the withdrawals of the sweep, and
/// the number of entries that each part of the sweep processed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExpectedWithdrawals {
    /// The withdrawals, in the order of the sweep.
    pub withdrawals: Vec<Withdrawal>,
    /// The number of `state.builder_pending_withdrawals` entries that the sweep processed.
    pub processed_builder_withdrawals_count: u64,
    /// The number of `state.pending_partial_withdrawals` entries that the sweep processed.
    pub processed_partial_withdrawals_count: u64,
    /// The number of builders that the builder sweep processed.
    pub processed_builders_sweep_count: u64,
    /// The number of validators that the validator sweep processed.
    pub processed_sweep_withdrawals_count: u64,
}

/// What each part of the sweep gives: the new withdrawals, the next withdrawal index, and
/// the number of entries that the part processed.
pub type SweepPart = (Vec<Withdrawal>, WithdrawalIndex, u64);

/// `MAX_WITHDRAWALS_PER_PAYLOAD` (`presets/{minimal,mainnet}/capella.yaml`).
fn max_withdrawals_per_payload<E: Preset>() -> u64 {
    E::MaxWithdrawalsPerPayload::to_u64()
}

/// The `assert len(prior_withdrawals) <= withdrawals_limit` of each part of the sweep. The
/// validator sweep asserts `<` and gives `withdrawals_limit - 1` here.
fn check_prior(prior_withdrawals: &[Withdrawal], limit: u64) -> Result<(), StfError> {
    let prior = prior_withdrawals.len() as u64;
    if prior > limit {
        return Err(StfError::PriorWithdrawalsPastLimit { prior, limit });
    }
    Ok(())
}

/// The error of a failed `Uint64` operation of the sweep on `what`.
fn state_arithmetic(what: &'static str) -> StfError {
    StfError::StateArithmetic { what }
}

/// `withdrawal_index + 1`, checked.
fn next_index(withdrawal_index: WithdrawalIndex) -> Result<WithdrawalIndex, StfError> {
    withdrawal_index
        .checked_add(1)
        .ok_or_else(|| state_arithmetic("withdrawal index"))
}

/// The sum of the amounts of `withdrawals` to `validator_index`, checked.
fn withdrawn(
    withdrawals: &[Withdrawal],
    validator_index: ValidatorIndex,
) -> Result<Gwei, StfError> {
    withdrawals
        .iter()
        .filter(|withdrawal| withdrawal.validator_index == validator_index)
        .try_fold(0u64, |sum, withdrawal| sum.checked_add(withdrawal.amount))
        .ok_or_else(|| state_arithmetic("withdrawn amount"))
}

/// `state.validators[index]`. The index comes from the state: see the module documentation.
fn validator_at<E: Preset>(
    state: &BeaconState<E>,
    index: ValidatorIndex,
) -> Result<&Validator, StfError> {
    state
        .validators
        .get(index as usize)
        .ok_or(StfError::ListIndexOutOfRange {
            list: "validators",
            index,
        })
}

/// `state.builders[index]`. The index comes from the state: see the module documentation.
fn builder_at<E: Preset>(
    state: &BeaconState<E>,
    index: BuilderIndex,
) -> Result<&Builder, StfError> {
    state
        .builders
        .get(index as usize)
        .ok_or(StfError::ListIndexOutOfRange {
            list: "builders",
            index,
        })
}

/// `ExecutionAddress(validator.withdrawal_credentials[12:])`.
fn execution_address(validator: &Validator) -> ExecutionAddress {
    ExecutionAddress::from_slice(&validator.withdrawal_credentials[12..])
}

/// `is_fully_withdrawable_validator` (E L678-687, Modified in Electra).
pub fn is_fully_withdrawable_validator(validator: &Validator, balance: Gwei, epoch: Epoch) -> bool {
    has_execution_withdrawal_credential(validator)
        && validator.withdrawable_epoch <= epoch
        && balance > 0
}

/// `is_partially_withdrawable_validator` (E L698-712, Modified in Electra).
pub fn is_partially_withdrawable_validator(validator: &Validator, balance: Gwei) -> bool {
    let max_effective_balance = get_max_effective_balance(validator);
    let has_max_effective_balance = validator.effective_balance == max_effective_balance;
    let has_excess_balance = balance > max_effective_balance;
    has_execution_withdrawal_credential(validator)
        && has_max_effective_balance
        && has_excess_balance
}

/// `is_eligible_for_partial_withdrawals` (E L718-728, New in Electra).
pub fn is_eligible_for_partial_withdrawals(validator: &Validator, balance: Gwei) -> bool {
    let has_sufficient_effective_balance = validator.effective_balance >= MIN_ACTIVATION_BALANCE;
    let has_excess_balance = balance > MIN_ACTIVATION_BALANCE;
    validator.exit_epoch == FAR_FUTURE_EPOCH
        && has_sufficient_effective_balance
        && has_excess_balance
}

/// `get_balance_after_withdrawals` (C L411-421): `state.balances[validator_index]` less the
/// amounts of `withdrawals` to the validator. The difference is checked.
pub fn get_balance_after_withdrawals<E: Preset>(
    state: &BeaconState<E>,
    validator_index: ValidatorIndex,
    withdrawals: &[Withdrawal],
) -> Result<Gwei, StfError> {
    let balance =
        *state
            .balances
            .get(validator_index as usize)
            .ok_or(StfError::ListIndexOutOfRange {
                list: "balances",
                index: validator_index,
            })?;
    balance
        .checked_sub(withdrawn(withdrawals, validator_index)?)
        .ok_or_else(|| state_arithmetic("balance after withdrawals"))
}

/// `get_builder_withdrawals` (G L1861-1889, New in Gloas): a withdrawal for each entry of
/// `state.builder_pending_withdrawals`, in order, until the withdrawals fill
/// `MAX_WITHDRAWALS_PER_PAYLOAD - 1`.
pub fn get_builder_withdrawals<E: Preset>(
    state: &BeaconState<E>,
    mut withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[Withdrawal],
) -> Result<SweepPart, StfError> {
    let withdrawals_limit = max_withdrawals_per_payload::<E>() - 1;
    check_prior(prior_withdrawals, withdrawals_limit)?;

    let mut processed_count = 0u64;
    let mut withdrawals = Vec::new();
    for withdrawal in state.builder_pending_withdrawals.iter() {
        let all_withdrawals = (prior_withdrawals.len() + withdrawals.len()) as u64;
        if all_withdrawals >= withdrawals_limit {
            break;
        }
        withdrawals.push(Withdrawal {
            index: withdrawal_index,
            validator_index: convert_builder_index_to_validator_index(withdrawal.builder_index),
            address: withdrawal.fee_recipient,
            amount: withdrawal.amount,
        });
        withdrawal_index = next_index(withdrawal_index)?;
        processed_count += 1;
    }
    Ok((withdrawals, withdrawal_index, processed_count))
}

/// `get_builder_balance_after_withdrawals` (G L1895-1906, New in Gloas): the balance of the
/// builder less the amounts of `withdrawals` to it, saturated at 0.
pub fn get_builder_balance_after_withdrawals<E: Preset>(
    state: &BeaconState<E>,
    builder_index: BuilderIndex,
    withdrawals: &[Withdrawal],
) -> Result<Gwei, StfError> {
    let validator_index = convert_builder_index_to_validator_index(builder_index);
    let withdrawn = withdrawn(withdrawals, validator_index)?;
    Ok(builder_at(state, builder_index)?
        .balance
        .saturating_sub(withdrawn))
}

/// `get_pending_partial_withdrawals` (E L1356-1394, New in Electra): a withdrawal for each
/// withdrawable entry of `state.pending_partial_withdrawals` whose validator is eligible. It
/// stops at the first entry that is not withdrawable yet, after
/// `MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP` withdrawals, or when the withdrawals fill
/// `MAX_WITHDRAWALS_PER_PAYLOAD - 1`.
pub fn get_pending_partial_withdrawals<E: Preset>(
    state: &BeaconState<E>,
    mut withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[Withdrawal],
) -> Result<SweepPart, StfError> {
    let epoch = get_current_epoch(state);
    let withdrawals_limit = (prior_withdrawals.len() as u64)
        .saturating_add(E::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP)
        .min(max_withdrawals_per_payload::<E>() - 1);
    check_prior(prior_withdrawals, withdrawals_limit)?;

    let mut processed_count = 0u64;
    // `list(prior_withdrawals) + withdrawals`: the new withdrawals follow the prior ones.
    let mut all_withdrawals = prior_withdrawals.to_vec();
    for withdrawal in state.pending_partial_withdrawals.iter() {
        let is_withdrawable = withdrawal.withdrawable_epoch <= epoch;
        let has_reached_limit = all_withdrawals.len() as u64 >= withdrawals_limit;
        if !is_withdrawable || has_reached_limit {
            break;
        }

        let validator_index = withdrawal.validator_index;
        let validator = validator_at(state, validator_index)?;
        let balance = get_balance_after_withdrawals(state, validator_index, &all_withdrawals)?;
        if is_eligible_for_partial_withdrawals(validator, balance) {
            // Eligible means `balance > MIN_ACTIVATION_BALANCE`, so the difference is positive.
            let withdrawal_amount = (balance - MIN_ACTIVATION_BALANCE).min(withdrawal.amount);
            all_withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: execution_address(validator),
                amount: withdrawal_amount,
            });
            withdrawal_index = next_index(withdrawal_index)?;
        }
        processed_count += 1;
    }
    let withdrawals = all_withdrawals.split_off(prior_withdrawals.len());
    Ok((withdrawals, withdrawal_index, processed_count))
}

/// `get_builders_sweep_withdrawals` (G L1912-1947, New in Gloas): from
/// `state.next_withdrawal_builder_index`, a withdrawal of the full balance of each builder
/// that is withdrawable and has a balance left after the prior withdrawals. It reads at most
/// `MAX_BUILDERS_PER_WITHDRAWALS_SWEEP` builders, and stops when the withdrawals fill
/// `MAX_WITHDRAWALS_PER_PAYLOAD - 1`.
pub fn get_builders_sweep_withdrawals<E: Preset>(
    state: &BeaconState<E>,
    mut withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[Withdrawal],
) -> Result<SweepPart, StfError> {
    let epoch = get_current_epoch(state);
    let builders_len = state.builders.len() as u64;
    let builders_limit = builders_len.min(E::MAX_BUILDERS_PER_WITHDRAWALS_SWEEP);
    let withdrawals_limit = max_withdrawals_per_payload::<E>() - 1;
    check_prior(prior_withdrawals, withdrawals_limit)?;

    let mut processed_count = 0u64;
    let mut all_withdrawals = prior_withdrawals.to_vec();
    let mut builder_index = state.next_withdrawal_builder_index;
    for _ in 0..builders_limit {
        if all_withdrawals.len() as u64 >= withdrawals_limit {
            break;
        }

        let builder = builder_at(state, builder_index)?;
        let balance =
            get_builder_balance_after_withdrawals(state, builder_index, &all_withdrawals)?;
        if builder.withdrawable_epoch <= epoch && balance > 0 {
            all_withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index: convert_builder_index_to_validator_index(builder_index),
                address: builder.execution_address,
                amount: balance,
            });
            withdrawal_index = next_index(withdrawal_index)?;
        }

        // `builder_at` checked `builder_index < len(state.builders)`, so `+ 1` cannot
        // overflow and the divisor is not zero.
        builder_index = (builder_index + 1) % builders_len;
        processed_count += 1;
    }
    let withdrawals = all_withdrawals.split_off(prior_withdrawals.len());
    Ok((withdrawals, withdrawal_index, processed_count))
}

/// `get_validators_sweep_withdrawals` (E L1403-1450, Modified in Electra): from
/// `state.next_withdrawal_validator_index`, a full withdrawal of each fully withdrawable
/// validator and a withdrawal of the excess balance of each partially withdrawable validator.
/// It reads at most `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` validators, and stops when the
/// withdrawals fill `MAX_WITHDRAWALS_PER_PAYLOAD`.
pub fn get_validators_sweep_withdrawals<E: Preset>(
    state: &BeaconState<E>,
    mut withdrawal_index: WithdrawalIndex,
    prior_withdrawals: &[Withdrawal],
) -> Result<SweepPart, StfError> {
    let epoch = get_current_epoch(state);
    let validators_len = state.validators.len() as u64;
    let validators_limit = validators_len.min(E::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP);
    let withdrawals_limit = max_withdrawals_per_payload::<E>();
    // There must be at least one space reserved for validator sweep withdrawals.
    check_prior(prior_withdrawals, withdrawals_limit - 1)?;

    let mut processed_count = 0u64;
    let mut all_withdrawals = prior_withdrawals.to_vec();
    let mut validator_index = state.next_withdrawal_validator_index;
    for _ in 0..validators_limit {
        if all_withdrawals.len() as u64 >= withdrawals_limit {
            break;
        }

        let validator = validator_at(state, validator_index)?;
        let balance = get_balance_after_withdrawals(state, validator_index, &all_withdrawals)?;
        let amount = if is_fully_withdrawable_validator(validator, balance, epoch) {
            Some(balance)
        } else if is_partially_withdrawable_validator(validator, balance) {
            // Partially withdrawable means `balance > get_max_effective_balance(validator)`.
            Some(balance - get_max_effective_balance(validator))
        } else {
            None
        };
        if let Some(amount) = amount {
            all_withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: execution_address(validator),
                amount,
            });
            withdrawal_index = next_index(withdrawal_index)?;
        }

        // `validator_at` checked `validator_index < len(state.validators)`, so `+ 1` cannot
        // overflow and the divisor is not zero.
        validator_index = (validator_index + 1) % validators_len;
        processed_count += 1;
    }
    let withdrawals = all_withdrawals.split_off(prior_withdrawals.len());
    Ok((withdrawals, withdrawal_index, processed_count))
}

/// `get_expected_withdrawals` (G L1953-1991, Modified in Gloas): the four parts of the sweep,
/// in order, each after the withdrawals of the parts before it.
pub fn get_expected_withdrawals<E: Preset>(
    state: &BeaconState<E>,
) -> Result<ExpectedWithdrawals, StfError> {
    let withdrawal_index = state.next_withdrawal_index;
    let mut withdrawals = Vec::new();

    let (builder_withdrawals, withdrawal_index, processed_builder_withdrawals_count) =
        get_builder_withdrawals(state, withdrawal_index, &withdrawals)?;
    withdrawals.extend(builder_withdrawals);

    let (partial_withdrawals, withdrawal_index, processed_partial_withdrawals_count) =
        get_pending_partial_withdrawals(state, withdrawal_index, &withdrawals)?;
    withdrawals.extend(partial_withdrawals);

    let (builders_sweep_withdrawals, withdrawal_index, processed_builders_sweep_count) =
        get_builders_sweep_withdrawals(state, withdrawal_index, &withdrawals)?;
    withdrawals.extend(builders_sweep_withdrawals);

    let (validators_sweep_withdrawals, _, processed_sweep_withdrawals_count) =
        get_validators_sweep_withdrawals(state, withdrawal_index, &withdrawals)?;
    withdrawals.extend(validators_sweep_withdrawals);

    Ok(ExpectedWithdrawals {
        withdrawals,
        processed_builder_withdrawals_count,
        processed_partial_withdrawals_count,
        processed_builders_sweep_count,
        processed_sweep_withdrawals_count,
    })
}

/// `apply_withdrawals` (G L1997-2006, Modified in Gloas): takes the amount of each withdrawal
/// from the balance of its builder or its validator. Both saturate at 0.
pub fn apply_withdrawals<E: Preset>(
    state: &mut BeaconState<E>,
    withdrawals: &[Withdrawal],
) -> Result<(), StfError> {
    for withdrawal in withdrawals {
        if is_builder_index(withdrawal.validator_index) {
            let builder_index =
                convert_validator_index_to_builder_index(withdrawal.validator_index);
            let builder = state.builders.get_mut(builder_index as usize).ok_or(
                StfError::ListIndexOutOfRange {
                    list: "builders",
                    index: builder_index,
                },
            )?;
            builder.balance = builder.balance.saturating_sub(withdrawal.amount);
        } else {
            decrease_balance(state, withdrawal.validator_index, withdrawal.amount)?;
        }
    }
    Ok(())
}

/// `update_next_withdrawal_index` (C L506-510): one past the index of the last withdrawal,
/// if there is one. The sum is checked.
pub fn update_next_withdrawal_index<E: Preset>(
    state: &mut BeaconState<E>,
    withdrawals: &[Withdrawal],
) -> Result<(), StfError> {
    if let Some(latest_withdrawal) = withdrawals.last() {
        state.next_withdrawal_index = next_index(latest_withdrawal.index)?;
    }
    Ok(())
}

/// `update_payload_expected_withdrawals` (G L2012-2015, New in Gloas).
pub fn update_payload_expected_withdrawals<E: Preset>(
    state: &mut BeaconState<E>,
    withdrawals: &[Withdrawal],
) -> Result<(), StfError> {
    state.payload_expected_withdrawals =
        ProgressiveList::try_from_iter(withdrawals.iter().cloned())?;
    Ok(())
}

/// `update_builder_pending_withdrawals` (G L2021-2026, New in Gloas): removes the processed
/// entries from the front of `state.builder_pending_withdrawals`.
pub fn update_builder_pending_withdrawals<E: Preset>(
    state: &mut BeaconState<E>,
    processed_builder_withdrawals_count: u64,
) -> Result<(), StfError> {
    state
        .builder_pending_withdrawals
        .pop_front(processed_builder_withdrawals_count as usize)?;
    Ok(())
}

/// `update_pending_partial_withdrawals` (E L1486-1491, New in Electra): removes the processed
/// entries from the front of `state.pending_partial_withdrawals`.
pub fn update_pending_partial_withdrawals<E: Preset>(
    state: &mut BeaconState<E>,
    processed_partial_withdrawals_count: u64,
) -> Result<(), StfError> {
    state
        .pending_partial_withdrawals
        .pop_front(processed_partial_withdrawals_count as usize)?;
    Ok(())
}

/// `update_next_withdrawal_builder_index` (G L2032-2039, New in Gloas): the builder sweep
/// starts after the builders that it processed. The sum is checked.
pub fn update_next_withdrawal_builder_index<E: Preset>(
    state: &mut BeaconState<E>,
    processed_builders_sweep_count: u64,
) -> Result<(), StfError> {
    let builders_len = state.builders.len() as u64;
    if builders_len > 0 {
        let next_index = state
            .next_withdrawal_builder_index
            .checked_add(processed_builders_sweep_count)
            .ok_or_else(|| state_arithmetic("builder sweep cursor"))?;
        state.next_withdrawal_builder_index = next_index % builders_len;
    }
    Ok(())
}

/// `update_next_withdrawal_validator_index` (C L516-528): after a full set of withdrawals,
/// the validator sweep starts after the validator of the last one. Else it moves on by
/// `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP`. The arithmetic is checked: an overflow of the
/// cursor, or an empty registry (a division by zero), is [`StfError::StateArithmetic`].
pub fn update_next_withdrawal_validator_index<E: Preset>(
    state: &mut BeaconState<E>,
    withdrawals: &[Withdrawal],
) -> Result<(), StfError> {
    let overflow = || state_arithmetic("validator sweep cursor");
    let validators_len = state.validators.len() as u64;
    let next_index = match withdrawals.last() {
        // Next sweep starts after the latest withdrawal's validator index.
        Some(latest) if withdrawals.len() as u64 == max_withdrawals_per_payload::<E>() => {
            latest.validator_index.checked_add(1).ok_or_else(overflow)?
        }
        // Advance sweep by the max length of the sweep if there was not a full set of
        // withdrawals.
        _ => state
            .next_withdrawal_validator_index
            .checked_add(E::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
            .ok_or_else(overflow)?,
    };
    state.next_withdrawal_validator_index = next_index
        .checked_rem(validators_len)
        .ok_or_else(|| state_arithmetic("empty validator registry"))?;
    Ok(())
}

/// Whether the parent block is EMPTY: its payload did not arrive, so `state.latest_block_hash`
/// is not the block hash of the latest bid (G L2074).
pub fn is_parent_block_empty<E: Preset>(state: &BeaconState<E>) -> bool {
    state.latest_block_hash != state.latest_execution_payload_bid.block_hash
}

/// `process_withdrawals` (G L2067-2092, Modified in Gloas): it takes the state only. On an
/// EMPTY parent block it changes nothing. Else it applies the withdrawals of
/// [`get_expected_withdrawals`] at once, records them in `state.payload_expected_withdrawals`,
/// and moves the queues and the sweep cursors.
///
/// Call it after `process_parent_execution_payload`, which sets `state.latest_block_hash`,
/// and before `process_execution_payload_bid`, which changes the balances. On `Err`, `state`
/// is partly updated: the caller drops it.
pub fn process_withdrawals<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    // Return early if the parent block is empty.
    if is_parent_block_empty(state) {
        return Ok(());
    }

    let expected = get_expected_withdrawals(state)?;
    apply_withdrawals(state, &expected.withdrawals)?;

    update_next_withdrawal_index(state, &expected.withdrawals)?;
    update_payload_expected_withdrawals(state, &expected.withdrawals)?;
    update_builder_pending_withdrawals(state, expected.processed_builder_withdrawals_count)?;
    update_pending_partial_withdrawals(state, expected.processed_partial_withdrawals_count)?;
    update_next_withdrawal_builder_index(state, expected.processed_builders_sweep_count)?;
    update_next_withdrawal_validator_index(state, &expected.withdrawals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preset::{
        COMPOUNDING_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX,
        MAX_EFFECTIVE_BALANCE_ELECTRA,
    };
    use crate::state_root;
    use crate::testing::{builder, genesis_state, registry_state};
    use consensus_types::common::PendingPartialWithdrawal;
    use consensus_types::gloas::BuilderPendingWithdrawal;
    use consensus_types::primitives::{Address, Bytes32, Root};
    use consensus_types::{Mainnet, Minimal};

    const ETH: u64 = 1_000_000_000;

    /// A minimal genesis state with `n` validators of 32 ETH and 0x00 credentials. Its parent
    /// block is FULL: `latest_block_hash` and the block hash of the bid are both zero.
    fn state(n: usize) -> BeaconState<Minimal> {
        genesis_state::<Minimal>(&vec![32 * ETH; n])
    }

    /// Gives validator `index` the credentials of `prefix` with the address `[index + 1; 20]`.
    fn set_credentials<E: Preset>(state: &mut BeaconState<E>, index: usize, prefix: u8) {
        let validator = state.validators.get_mut(index).unwrap();
        validator.withdrawal_credentials = Bytes32::ZERO;
        validator.withdrawal_credentials[0] = prefix;
        validator.withdrawal_credentials[12..].fill(index as u8 + 1);
    }

    /// Makes validator `index` fully withdrawable at epoch 0, with 0x01 credentials.
    fn set_fully_withdrawable<E: Preset>(state: &mut BeaconState<E>, index: usize) {
        set_credentials(state, index, ETH1_ADDRESS_WITHDRAWAL_PREFIX);
        state.validators.get_mut(index).unwrap().withdrawable_epoch = 0;
    }

    fn set_balance<E: Preset>(state: &mut BeaconState<E>, index: usize, balance: Gwei) {
        *state.balances.get_mut(index).unwrap() = balance;
    }

    fn push_builder_withdrawal<E: Preset>(
        state: &mut BeaconState<E>,
        builder_index: BuilderIndex,
        amount: Gwei,
    ) {
        state
            .builder_pending_withdrawals
            .push(BuilderPendingWithdrawal {
                fee_recipient: Address::repeat_byte(0xfe),
                amount,
                builder_index,
            })
            .unwrap();
    }

    fn push_partial<E: Preset>(
        state: &mut BeaconState<E>,
        validator_index: ValidatorIndex,
        amount: Gwei,
        withdrawable_epoch: Epoch,
    ) {
        state
            .pending_partial_withdrawals
            .push(PendingPartialWithdrawal {
                validator_index,
                amount,
                withdrawable_epoch,
            })
            .unwrap();
    }

    /// A builder that can withdraw at epoch 0, with the key and the address of `key`.
    fn withdrawable_builder(key: u8, balance: Gwei) -> Builder {
        Builder {
            withdrawable_epoch: 0,
            ..builder(key, balance, 0)
        }
    }

    /// `n` withdrawals to validator 0, as prior withdrawals of a sweep part.
    fn prior(n: usize) -> Vec<Withdrawal> {
        (0..n)
            .map(|i| Withdrawal {
                index: i as u64,
                validator_index: 0,
                address: Address::ZERO,
                amount: 0,
            })
            .collect()
    }

    /// A state with work for each part of the sweep: one builder pending withdrawal, one
    /// pending partial withdrawal, a withdrawable builder and a fully withdrawable validator.
    fn busy_state() -> BeaconState<Minimal> {
        let mut state = state(8);
        state
            .builders
            .push(withdrawable_builder(1, 5 * ETH))
            .unwrap();
        push_builder_withdrawal(&mut state, 0, ETH);
        set_credentials(&mut state, 1, ETH1_ADDRESS_WITHDRAWAL_PREFIX);
        set_balance(&mut state, 1, 40 * ETH);
        push_partial(&mut state, 1, 3 * ETH, 0);
        set_fully_withdrawable(&mut state, 2);
        state
    }

    #[test]
    fn empty_parent_noop() {
        let mut state = busy_state();
        state.latest_execution_payload_bid.block_hash = Root::repeat_byte(1);
        assert!(is_parent_block_empty(&state));
        let before = state_root(&mut state).unwrap();
        assert_eq!(process_withdrawals(&mut state), Ok(()));
        assert_eq!(state_root(&mut state).unwrap(), before);

        // The same state on a FULL parent has withdrawals to pay.
        state.latest_block_hash = Root::repeat_byte(1);
        assert!(!is_parent_block_empty(&state));
        assert_eq!(process_withdrawals(&mut state), Ok(()));
        assert_ne!(state_root(&mut state).unwrap(), before);
        assert_eq!(state.payload_expected_withdrawals.len(), 4);
    }

    #[test]
    fn process_withdrawals_pays_each_part_in_order() {
        let mut state = busy_state();
        state.next_withdrawal_index = 7;
        let expected = get_expected_withdrawals(&state).unwrap();
        let want = vec![
            // The builder pending withdrawal, to its fee recipient.
            Withdrawal {
                index: 7,
                validator_index: convert_builder_index_to_validator_index(0),
                address: Address::repeat_byte(0xfe),
                amount: ETH,
            },
            // The pending partial withdrawal of validator 1.
            Withdrawal {
                index: 8,
                validator_index: 1,
                address: Address::repeat_byte(2),
                amount: 3 * ETH,
            },
            // The builder sweep: the balance of builder 0 less its pending withdrawal.
            Withdrawal {
                index: 9,
                validator_index: convert_builder_index_to_validator_index(0),
                address: Address::repeat_byte(1),
                amount: 4 * ETH,
            },
            // The validator sweep: validator 1 keeps 37 ETH, but 0x01 credentials cap it at
            // 32 ETH and its effective balance is 32 ETH, so it gets the excess 5 ETH too.
            Withdrawal {
                index: 10,
                validator_index: 1,
                address: Address::repeat_byte(2),
                amount: 5 * ETH,
            },
        ];
        assert_eq!(
            expected,
            ExpectedWithdrawals {
                withdrawals: want.clone(),
                processed_builder_withdrawals_count: 1,
                processed_partial_withdrawals_count: 1,
                processed_builders_sweep_count: 1,
                processed_sweep_withdrawals_count: 2,
            }
        );

        assert_eq!(process_withdrawals(&mut state), Ok(()));
        assert_eq!(state.builders.get(0).unwrap().balance, 0);
        assert_eq!(*state.balances.get(1).unwrap(), 32 * ETH);
        assert_eq!(*state.balances.get(2).unwrap(), 32 * ETH);
        assert_eq!(state.next_withdrawal_index, 11);
        assert_eq!(state.payload_expected_withdrawals.to_vec(), want);
        assert_eq!(state.builder_pending_withdrawals.len(), 0);
        assert_eq!(state.pending_partial_withdrawals.len(), 0);
        assert_eq!(state.next_withdrawal_builder_index, 0);
        // A full set of 4: the validator sweep starts after the last validator, 1.
        assert_eq!(state.next_withdrawal_validator_index, 2);
    }

    #[test]
    fn builder_withdrawals_leave_one_slot() {
        let mut state = state(8);
        for amount in 1..=5 {
            push_builder_withdrawal(&mut state, amount, amount * ETH);
        }
        // MAX_WITHDRAWALS_PER_PAYLOAD - 1 = 3 on minimal.
        let (withdrawals, next, processed) = get_builder_withdrawals(&state, 7, &[]).unwrap();
        assert_eq!((next, processed), (10, 3));
        let got: Vec<_> = withdrawals
            .iter()
            .map(|w| (w.index, w.validator_index, w.amount))
            .collect();
        let flag = convert_builder_index_to_validator_index;
        assert_eq!(
            got,
            vec![
                (7, flag(1), ETH),
                (8, flag(2), 2 * ETH),
                (9, flag(3), 3 * ETH)
            ]
        );
        // Two prior withdrawals leave one slot.
        let (withdrawals, next, processed) = get_builder_withdrawals(&state, 7, &prior(2)).unwrap();
        assert_eq!((withdrawals.len(), next, processed), (1, 8, 1));
        // Four prior withdrawals are past the limit of the part.
        assert_eq!(
            get_builder_withdrawals(&state, 7, &prior(4)),
            Err(StfError::PriorWithdrawalsPastLimit { prior: 4, limit: 3 })
        );

        // On mainnet the limit is 15.
        let mut state = registry_state::<Mainnet>(&[32 * ETH; 4], Bytes32::ZERO);
        for builder_index in 0..20 {
            push_builder_withdrawal(&mut state, builder_index, ETH);
        }
        let (withdrawals, next, processed) = get_builder_withdrawals(&state, 0, &[]).unwrap();
        assert_eq!((withdrawals.len(), next, processed), (15, 15, 15));
    }

    #[test]
    fn pending_partial_withdrawals() {
        let mut state = state(8);
        set_credentials(&mut state, 1, ETH1_ADDRESS_WITHDRAWAL_PREFIX);
        set_balance(&mut state, 1, 40 * ETH);
        push_partial(&mut state, 1, 3 * ETH, 0);
        // Validator 2 has no excess balance: processed, but no withdrawal.
        push_partial(&mut state, 2, ETH, 0);
        // The balance after the first withdrawal is 37 ETH, so 5 ETH of 10 is left.
        push_partial(&mut state, 1, 10 * ETH, 0);
        // MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP = 2 withdrawals on minimal.
        push_partial(&mut state, 1, ETH, 0);
        let (withdrawals, next, processed) =
            get_pending_partial_withdrawals(&state, 4, &[]).unwrap();
        assert_eq!((next, processed), (6, 3));
        let got: Vec<_> = withdrawals
            .iter()
            .map(|w| (w.index, w.validator_index, w.address, w.amount))
            .collect();
        let address = Address::repeat_byte(2);
        assert_eq!(
            got,
            vec![(4, 1, address, 3 * ETH), (5, 1, address, 5 * ETH)]
        );

        // The limit is `MAX_WITHDRAWALS_PER_PAYLOAD - 1` = 3 with two prior withdrawals.
        let (withdrawals, _, processed) =
            get_pending_partial_withdrawals(&state, 4, &prior(2)).unwrap();
        assert_eq!((withdrawals.len(), processed), (1, 1));
        assert_eq!(
            get_pending_partial_withdrawals(&state, 4, &prior(4)),
            Err(StfError::PriorWithdrawalsPastLimit { prior: 4, limit: 3 })
        );

        // An entry that is not withdrawable yet stops the part.
        let mut later = state.clone();
        later.pending_partial_withdrawals = ProgressiveList::default();
        push_partial(&mut later, 1, ETH, 1);
        push_partial(&mut later, 1, ETH, 0);
        assert_eq!(
            get_pending_partial_withdrawals(&later, 4, &[]),
            Ok((vec![], 4, 0))
        );

        // An exiting validator is not eligible.
        state.validators.get_mut(1).unwrap().exit_epoch = 10;
        let (withdrawals, _, processed) = get_pending_partial_withdrawals(&state, 4, &[]).unwrap();
        assert_eq!((withdrawals.len(), processed), (0, 4));
    }

    #[test]
    fn builders_sweep() {
        let mut state = state(8);
        state
            .builders
            .push(withdrawable_builder(1, 5 * ETH))
            .unwrap();
        state.builders.push(builder(2, 9 * ETH, 0)).unwrap();
        state
            .builders
            .push(withdrawable_builder(3, 2 * ETH))
            .unwrap();
        state.builders.push(withdrawable_builder(4, ETH)).unwrap();
        state.next_withdrawal_builder_index = 2;
        let flag = convert_builder_index_to_validator_index;
        // A prior withdrawal of 1 ETH from builder 0, and all of builder 3.
        let prior = vec![
            Withdrawal {
                index: 0,
                validator_index: flag(0),
                address: Address::ZERO,
                amount: ETH,
            },
            Withdrawal {
                index: 1,
                validator_index: flag(3),
                address: Address::ZERO,
                amount: 2 * ETH,
            },
        ];
        assert_eq!(
            get_builder_balance_after_withdrawals(&state, 0, &prior),
            Ok(4 * ETH)
        );
        assert_eq!(
            get_builder_balance_after_withdrawals(&state, 3, &prior),
            Ok(0)
        );
        // From builder 2: its 2 ETH fill the limit of 3, so the sweep stops after one builder.
        let (withdrawals, next, processed) =
            get_builders_sweep_withdrawals(&state, 2, &prior).unwrap();
        let got: Vec<_> = withdrawals
            .iter()
            .map(|w| (w.index, w.validator_index, w.address, w.amount))
            .collect();
        assert_eq!(got, vec![(2, flag(2), Address::repeat_byte(3), 2 * ETH)]);
        assert_eq!((next, processed), (3, 1));

        // Without prior withdrawals the sweep wraps: 2, 3, 0 (1 is not withdrawable).
        let (withdrawals, _, processed) = get_builders_sweep_withdrawals(&state, 0, &[]).unwrap();
        let got: Vec<_> = withdrawals
            .iter()
            .map(|w| (w.validator_index, w.amount))
            .collect();
        assert_eq!(
            got,
            vec![(flag(2), 2 * ETH), (flag(3), ETH), (flag(0), 5 * ETH)]
        );
        assert_eq!(processed, 3);
        assert_eq!(
            get_builders_sweep_withdrawals(&state, 0, &self::prior(4)),
            Err(StfError::PriorWithdrawalsPastLimit { prior: 4, limit: 3 })
        );

        // No builders: nothing to sweep, and the cursor does not move.
        let mut empty = self::state(8);
        empty.next_withdrawal_builder_index = 5;
        assert_eq!(
            get_builders_sweep_withdrawals(&empty, 0, &[]),
            Ok((vec![], 0, 0))
        );
        update_next_withdrawal_builder_index(&mut empty, 3).unwrap();
        assert_eq!(empty.next_withdrawal_builder_index, 5);
        // With builders, the cursor wraps.
        update_next_withdrawal_builder_index(&mut state, 3).unwrap();
        assert_eq!(state.next_withdrawal_builder_index, 1);
    }

    #[test]
    fn validators_sweep() {
        let mut state = state(8);
        // 2: fully withdrawable. 3: compounding, 2 ETH past its maximum. 4: 0x01, 1 ETH past.
        // 5: withdrawable, but 0x00 credentials.
        set_fully_withdrawable(&mut state, 2);
        set_credentials(&mut state, 3, COMPOUNDING_WITHDRAWAL_PREFIX);
        state.validators.get_mut(3).unwrap().effective_balance = MAX_EFFECTIVE_BALANCE_ELECTRA;
        set_balance(&mut state, 3, MAX_EFFECTIVE_BALANCE_ELECTRA + 2 * ETH);
        set_credentials(&mut state, 4, ETH1_ADDRESS_WITHDRAWAL_PREFIX);
        set_balance(&mut state, 4, 33 * ETH);
        state.validators.get_mut(5).unwrap().withdrawable_epoch = 0;
        state.next_withdrawal_validator_index = 6;

        let (withdrawals, next, processed) =
            get_validators_sweep_withdrawals(&state, 0, &[]).unwrap();
        let got: Vec<_> = withdrawals
            .iter()
            .map(|w| (w.index, w.validator_index, w.address, w.amount))
            .collect();
        assert_eq!(
            got,
            vec![
                (0, 2, Address::repeat_byte(3), 32 * ETH),
                (1, 3, Address::repeat_byte(4), 2 * ETH),
                (2, 4, Address::repeat_byte(5), ETH),
            ]
        );
        // From 6 it wraps over all 8 validators.
        assert_eq!((next, processed), (3, 8));

        // Three prior withdrawals leave one slot: 6, 7, 0, 1, 2, then the limit.
        let (withdrawals, _, processed) =
            get_validators_sweep_withdrawals(&state, 0, &prior(3)).unwrap();
        assert_eq!((withdrawals.len(), processed), (1, 5));
        // A prior withdrawal of all of validator 2 leaves it nothing.
        let all_of_two = vec![Withdrawal {
            index: 0,
            validator_index: 2,
            address: Address::ZERO,
            amount: 32 * ETH,
        }];
        let (withdrawals, _, _) = get_validators_sweep_withdrawals(&state, 1, &all_of_two).unwrap();
        assert_eq!(withdrawals.len(), 2);
        assert_eq!(
            get_validators_sweep_withdrawals(&state, 0, &prior(4)),
            Err(StfError::PriorWithdrawalsPastLimit { prior: 4, limit: 3 })
        );
        // A prior withdrawal that takes more than the balance is a `Uint64` underflow.
        let too_much = vec![Withdrawal {
            amount: 33 * ETH,
            ..all_of_two[0].clone()
        }];
        let err = get_balance_after_withdrawals(&state, 2, &too_much).unwrap_err();
        assert_eq!(
            err,
            StfError::StateArithmetic {
                what: "balance after withdrawals"
            }
        );
        assert!(!err.proves_invalid());
    }

    #[test]
    fn sweep_reads_at_most_the_sweep_limit() {
        // 40 validators and none can withdraw: the sweep reads 16, not the registry.
        let mut state = state(40);
        let (withdrawals, _, processed) = get_validators_sweep_withdrawals(&state, 0, &[]).unwrap();
        assert_eq!((withdrawals.len(), processed), (0, 16));
        assert_eq!(
            get_expected_withdrawals(&state).unwrap().withdrawals,
            vec![]
        );
        process_withdrawals(&mut state).unwrap();
        assert_eq!(state.next_withdrawal_validator_index, 16);
        state.next_withdrawal_validator_index = 30;
        process_withdrawals(&mut state).unwrap();
        assert_eq!(state.next_withdrawal_validator_index, 6);
        assert_eq!(state.next_withdrawal_index, 0);

        // An empty registry divides by zero: a fault of our own state, not a proof.
        let mut empty = self::state(8);
        empty.validators = ProgressiveList::default();
        let err = update_next_withdrawal_validator_index(&mut empty, &[]).unwrap_err();
        assert_eq!(
            err,
            StfError::StateArithmetic {
                what: "empty validator registry"
            }
        );
        assert!(!err.proves_invalid());
    }

    #[test]
    fn sweep_arithmetic_is_not_a_proof() {
        // Each `Uint64` error of the sweep comes from values of the state only.
        let fault = |what: &'static str| StfError::StateArithmetic { what };
        let mut errors = Vec::new();

        // The next withdrawal index is at its maximum.
        let mut state = state(8);
        set_fully_withdrawable(&mut state, 0);
        state.next_withdrawal_index = u64::MAX;
        errors.push((
            process_withdrawals(&mut state).unwrap_err(),
            fault("withdrawal index"),
        ));
        errors.push((
            update_next_withdrawal_index(
                &mut state,
                &[Withdrawal {
                    index: u64::MAX,
                    validator_index: 0,
                    address: Address::ZERO,
                    amount: 0,
                }],
            )
            .unwrap_err(),
            fault("withdrawal index"),
        ));

        // The amounts to one validator overflow their sum.
        let huge = vec![
            Withdrawal {
                index: 0,
                validator_index: 1,
                address: Address::ZERO,
                amount: u64::MAX,
            };
            2
        ];
        errors.push((
            get_balance_after_withdrawals(&self::state(8), 1, &huge).unwrap_err(),
            fault("withdrawn amount"),
        ));

        // The sweep cursors are at their maximum.
        let mut cursors = self::state(8);
        cursors.builders.push(builder(1, ETH, 0)).unwrap();
        cursors.next_withdrawal_builder_index = u64::MAX;
        errors.push((
            update_next_withdrawal_builder_index(&mut cursors, 1).unwrap_err(),
            fault("builder sweep cursor"),
        ));
        cursors.next_withdrawal_validator_index = u64::MAX;
        errors.push((
            update_next_withdrawal_validator_index(&mut cursors, &[]).unwrap_err(),
            fault("validator sweep cursor"),
        ));
        let full: Vec<_> = (0..4)
            .map(|index| Withdrawal {
                index,
                validator_index: u64::MAX,
                address: Address::ZERO,
                amount: 0,
            })
            .collect();
        errors.push((
            update_next_withdrawal_validator_index(&mut cursors, &full).unwrap_err(),
            fault("validator sweep cursor"),
        ));

        for (err, want) in errors {
            assert_eq!(err, want);
            assert!(!err.proves_invalid(), "{err}");
        }
    }

    #[test]
    fn apply_withdrawals_saturates() {
        let mut state = state(8);
        state.builders.push(builder(1, ETH, 0)).unwrap();
        let withdrawals = [
            Withdrawal {
                index: 0,
                validator_index: convert_builder_index_to_validator_index(0),
                address: Address::ZERO,
                amount: 2 * ETH,
            },
            Withdrawal {
                index: 1,
                validator_index: 3,
                address: Address::ZERO,
                amount: 40 * ETH,
            },
            Withdrawal {
                index: 2,
                validator_index: 4,
                address: Address::ZERO,
                amount: ETH,
            },
        ];
        apply_withdrawals(&mut state, &withdrawals).unwrap();
        assert_eq!(state.builders.get(0).unwrap().balance, 0);
        assert_eq!(*state.balances.get(3).unwrap(), 0);
        assert_eq!(*state.balances.get(4).unwrap(), 31 * ETH);
        update_next_withdrawal_index(&mut state, &[]).unwrap();
        assert_eq!(state.next_withdrawal_index, 0);
        update_next_withdrawal_index(&mut state, &withdrawals).unwrap();
        assert_eq!(state.next_withdrawal_index, 3);
    }

    #[test]
    fn state_indices_past_their_list_are_not_proofs() {
        // The four invalid cases of `operations/withdrawals`: each index comes from the state.
        let fault = |list: &'static str, index: u64| StfError::ListIndexOutOfRange { list, index };
        let mut cases = Vec::new();

        let mut pending_builder = state(8);
        push_builder_withdrawal(&mut pending_builder, 0, ETH);
        cases.push((pending_builder, fault("builders", 0)));

        let mut sweep_builder = state(8);
        sweep_builder.builders.push(builder(1, ETH, 0)).unwrap();
        sweep_builder.next_withdrawal_builder_index = 1;
        cases.push((sweep_builder, fault("builders", 1)));

        let mut pending_partial = state(8);
        push_partial(&mut pending_partial, 8, ETH, 0);
        cases.push((pending_partial, fault("validators", 8)));

        let mut sweep_validator = state(8);
        sweep_validator.next_withdrawal_validator_index = 8;
        cases.push((sweep_validator, fault("validators", 8)));

        for (mut state, want) in cases {
            let err = process_withdrawals(&mut state).unwrap_err();
            assert_eq!(err, want);
            assert!(!err.proves_invalid(), "{err}");
        }

        // A registry longer than `balances` is a fault of our own state too.
        let mut short = state(8);
        short.balances.pop_front(1).unwrap();
        assert_eq!(
            get_balance_after_withdrawals(&short, 7, &[]),
            Err(fault("balances", 7))
        );
    }
}
