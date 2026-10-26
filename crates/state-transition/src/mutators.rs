//! Beacon-state mutators: the balance helpers, the exit and consolidation churn, validator
//! and builder exits, builder-payment settlement and `slash_validator`.
//!
//! The churn functions read the total active balance through a
//! [`TotalActiveBalanceCache`] that the caller keeps for the state, so that a block or an
//! epoch with many exits reads the registry one time. On `Err`, `state` is partly updated:
//! the caller drops it.
//!
//! The arithmetic is as in the spec: `decrease_balance` saturates at 0, and every other
//! `Uint64` operation is checked. A failed operation is [`StfError::ArithmeticOverflow`],
//! but [`StfError::StateArithmetic`] (not a proof) for the churn queue, whose operands come
//! from our own state only.

use crate::accessors::{
    compute_activation_exit_epoch, get_consolidation_churn_limit, get_current_epoch,
    get_exit_churn_limit, TotalActiveBalanceCache,
};
use crate::per_block::state_proposer_index;
use crate::preset::{
    MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA, MIN_VALIDATOR_WITHDRAWABILITY_DELAY, PROPOSER_WEIGHT,
    WEIGHT_DENOMINATOR, WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
};
use crate::{Preset, StfError};
use consensus_types::gloas::{BeaconState, BuilderPendingPayment, BuilderPendingWithdrawal};
use consensus_types::primitives::{
    Address, BuilderIndex, Epoch, Gwei, ValidatorIndex, FAR_FUTURE_EPOCH,
};
use ssz_types::typenum::Unsigned;

/// `increase_balance` (P0 L1653-1657). The sum is checked.
pub fn increase_balance<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
    delta: Gwei,
) -> Result<(), StfError> {
    let balance = balance_mut(state, index)?;
    *balance = balance
        .checked_add(delta)
        .ok_or(StfError::ArithmeticOverflow)?;
    Ok(())
}

/// `decrease_balance` (P0 L1663-1667). The difference saturates at 0, as in the spec.
pub fn decrease_balance<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
    delta: Gwei,
) -> Result<(), StfError> {
    let balance = balance_mut(state, index)?;
    *balance = balance.saturating_sub(delta);
    Ok(())
}

/// `state.balances[index]`. The spec reads only `balances`, so an index inside `balances`
/// succeeds, also when it is past the registry. An index past `balances` and past the
/// registry is the error of the object that names it (`UnknownValidator`). An index inside
/// the registry but past `balances` means that our own state is bad, so it is not a proof
/// (`ListIndexOutOfRange`).
fn balance_mut<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
) -> Result<&mut Gwei, StfError> {
    let in_registry = index < state.validators.len() as u64;
    match state.balances.get_mut(index as usize) {
        Some(balance) => Ok(balance),
        None if in_registry => Err(StfError::ListIndexOutOfRange {
            list: "balances",
            index,
        }),
        None => Err(StfError::UnknownValidator(index)),
    }
}

/// The queue of exits or of consolidations: its earliest epoch, and the balance that is
/// left to consume in that epoch.
struct ChurnQueue {
    earliest_epoch: Epoch,
    balance_to_consume: Gwei,
}

/// The common body of `compute_exit_epoch_and_update_churn` (G L1495-1518) and
/// `compute_consolidation_epoch_and_update_churn` (E L948-974): the new queue after
/// `balance` is added to `queue` in `current_epoch`, with `per_epoch_churn` per epoch.
///
/// Each operand comes from our own state: the queue, the epoch, the churn of the total
/// active balance, and a balance that each caller reads from the state (an effective
/// balance, or the excess balance of a withdrawal request). A state that the transition
/// makes keeps them in range, so a failed operation is [`StfError::StateArithmetic`], not
/// a proof.
fn update_churn(
    queue: ChurnQueue,
    current_epoch: Epoch,
    per_epoch_churn: Gwei,
    balance: Gwei,
) -> Result<ChurnQueue, StfError> {
    let overflow = || StfError::StateArithmetic {
        what: "churn queue",
    };
    let mut earliest_epoch = queue
        .earliest_epoch
        .max(compute_activation_exit_epoch(current_epoch).map_err(|_| overflow())?);
    // New epoch for the queue.
    let mut balance_to_consume = if queue.earliest_epoch < earliest_epoch {
        per_epoch_churn
    } else {
        queue.balance_to_consume
    };
    // The balance does not fit in the current earliest epoch.
    if balance > balance_to_consume {
        let balance_to_process = balance - balance_to_consume;
        // A zero churn divides by zero in the spec (a `Uint64` error, so invalid). The
        // quotient is at most `u64::MAX - 1`, so `+ 1` does not overflow.
        let additional_epochs = (balance_to_process - 1)
            .checked_div(per_epoch_churn)
            .ok_or_else(overflow)?
            + 1;
        earliest_epoch = earliest_epoch
            .checked_add(additional_epochs)
            .ok_or_else(overflow)?;
        balance_to_consume = additional_epochs
            .checked_mul(per_epoch_churn)
            .and_then(|added| balance_to_consume.checked_add(added))
            .ok_or_else(overflow)?;
    }
    // Consume the balance.
    Ok(ChurnQueue {
        earliest_epoch,
        balance_to_consume: balance_to_consume
            .checked_sub(balance)
            .ok_or_else(overflow)?,
    })
}

/// `compute_exit_epoch_and_update_churn` (G L1495-1518, Modified in Gloas): the exit epoch of
/// a balance of `exit_balance`, with the uncapped exit churn. It moves the exit queue of the
/// state.
pub fn compute_exit_epoch_and_update_churn<E: Preset>(
    state: &mut BeaconState<E>,
    exit_balance: Gwei,
    cache: &mut TotalActiveBalanceCache,
) -> Result<Epoch, StfError> {
    let per_epoch_churn = get_exit_churn_limit(state, cache)?;
    let queue = ChurnQueue {
        earliest_epoch: state.earliest_exit_epoch,
        balance_to_consume: state.exit_balance_to_consume,
    };
    let queue = update_churn(
        queue,
        get_current_epoch(state),
        per_epoch_churn,
        exit_balance,
    )?;
    state.exit_balance_to_consume = queue.balance_to_consume;
    state.earliest_exit_epoch = queue.earliest_epoch;
    Ok(state.earliest_exit_epoch)
}

/// `compute_consolidation_epoch_and_update_churn` (E L948-974; Gloas keeps it, with the
/// Gloas `get_consolidation_churn_limit`): the epoch of a consolidation of
/// `consolidation_balance`. It moves the consolidation queue of the state.
pub fn compute_consolidation_epoch_and_update_churn<E: Preset>(
    state: &mut BeaconState<E>,
    consolidation_balance: Gwei,
    cache: &mut TotalActiveBalanceCache,
) -> Result<Epoch, StfError> {
    let per_epoch_churn = get_consolidation_churn_limit(state, cache)?;
    let queue = ChurnQueue {
        earliest_epoch: state.earliest_consolidation_epoch,
        balance_to_consume: state.consolidation_balance_to_consume,
    };
    let queue = update_churn(
        queue,
        get_current_epoch(state),
        per_epoch_churn,
        consolidation_balance,
    )?;
    state.consolidation_balance_to_consume = queue.balance_to_consume;
    state.earliest_consolidation_epoch = queue.earliest_epoch;
    Ok(state.earliest_consolidation_epoch)
}

/// `initiate_validator_exit` (E L867-881, Modified in Electra; Gloas keeps it). It does
/// nothing for a validator that already initiated its exit.
///
/// An index past the registry gives `UnknownValidator`, because a voluntary exit names the
/// index. A caller that reads the index from the registry checks it first (the ejection of
/// `process_registry_updates`), so that a fault of our own state is not a proof.
pub fn initiate_validator_exit<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
    cache: &mut TotalActiveBalanceCache,
) -> Result<(), StfError> {
    let validator = state
        .validators
        .get(index as usize)
        .ok_or(StfError::UnknownValidator(index))?;
    // Return if validator already initiated exit
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    let effective_balance = validator.effective_balance;
    // Compute exit queue epoch
    let exit_queue_epoch = compute_exit_epoch_and_update_churn(state, effective_balance, cache)?;
    let withdrawable_epoch = exit_queue_epoch
        .checked_add(MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
        .ok_or(StfError::ArithmeticOverflow)?;
    // Set validator exit epoch and withdrawable epoch
    // The first read found `index` in the registry, so a miss here is our own fault.
    let validator =
        state
            .validators
            .get_mut(index as usize)
            .ok_or(StfError::ListIndexOutOfRange {
                list: "validators",
                index,
            })?;
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch = withdrawable_epoch;
    Ok(())
}

/// `initiate_builder_exit` (G L1526-1532, New in Gloas): the builder can withdraw
/// `MIN_BUILDER_WITHDRAWABILITY_DELAY` epochs after the current epoch. As in the spec text,
/// it does not check an earlier exit: its callers do.
pub fn initiate_builder_exit<E: Preset>(
    state: &mut BeaconState<E>,
    builder_index: BuilderIndex,
) -> Result<(), StfError> {
    let withdrawable_epoch = get_current_epoch(state)
        .checked_add(E::MIN_BUILDER_WITHDRAWABILITY_DELAY)
        .ok_or(StfError::ArithmeticOverflow)?;
    let builder = state
        .builders
        .get_mut(builder_index as usize)
        .ok_or(StfError::UnknownBuilder(builder_index))?;
    // Set builder exit epoch
    builder.withdrawable_epoch = withdrawable_epoch;
    Ok(())
}

/// `BuilderPendingPayment()`: the empty payment, every field zero.
pub fn empty_payment() -> BuilderPendingPayment {
    BuilderPendingPayment {
        weight: 0,
        withdrawal: BuilderPendingWithdrawal {
            fee_recipient: Address::ZERO,
            amount: 0,
            builder_index: 0,
        },
        proposer_index: 0,
    }
}

/// `settle_builder_payment` (G L1538-1543, New in Gloas): moves the withdrawal of the
/// payment at `payment_index` to `state.builder_pending_withdrawals` (only if its amount is
/// not zero), and empties the payment.
///
/// The callers enforce the order of the settlement against the other steps of their
/// function (consensus-specs PR 5695).
///
/// # Caller defect
///
/// [`StfError::PaymentIndexOutOfRange`] comes only from a caller defect: the spec callers
/// (G L1799-1804) give an index below `2 * SLOTS_PER_EPOCH`, the length of the vector. Put a
/// `debug_assert!(payment_index < 2 * SLOTS_PER_EPOCH)` at each call site, so that a defect
/// fails the tests and does not REJECT a valid block.
pub fn settle_builder_payment<E: Preset>(
    state: &mut BeaconState<E>,
    payment_index: u64,
) -> Result<(), StfError> {
    let len = state.builder_pending_payments.len() as u64;
    let out_of_range = StfError::PaymentIndexOutOfRange {
        index: payment_index,
        len,
    };
    if payment_index >= len {
        return Err(out_of_range);
    }
    let payment = state
        .builder_pending_payments
        .get_mut(payment_index as usize)
        .ok_or(out_of_range)?;
    let withdrawal = payment.withdrawal.clone();
    *payment = empty_payment();
    if withdrawal.amount > 0 {
        // `BuilderPendingWithdrawals` is a `ProgressiveList` without a limit, so the append
        // of the spec cannot fail. milhouse fails only at a length of `usize::MAX`, a limit of
        // the implementation: `StfError::Tree`, which is not a proof of an invalid input.
        state.builder_pending_withdrawals.push(withdrawal)?;
    }
    Ok(())
}

/// `slash_validator` (G L1549-1581, Modified in Gloas): the Electra penalty and rewards,
/// and the pending builder payments of the blocks that the slashed validator proposed are
/// emptied (consensus-specs PR 5719). `None` as `whistleblower_index` is the proposer.
///
/// The proposer comes from `state.proposer_lookahead`, not from the slashing, so an index
/// there past the registry is a fault of our own state: `ListIndexOutOfRange`, not a proof
/// that the slashing is invalid.
pub fn slash_validator<E: Preset>(
    state: &mut BeaconState<E>,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
    cache: &mut TotalActiveBalanceCache,
) -> Result<(), StfError> {
    let overflow = || StfError::ArithmeticOverflow;
    let epoch = get_current_epoch(state);
    initiate_validator_exit(state, slashed_index, cache)?;
    let slashings_vector = E::EpochsPerSlashingsVector::to_u64();
    // `initiate_validator_exit` found the same index first, so a miss here is a fault of
    // our own state, not a proof that the slashing is invalid.
    let validator =
        state
            .validators
            .get_mut(slashed_index as usize)
            .ok_or(StfError::ListIndexOutOfRange {
                list: "validators",
                index: slashed_index,
            })?;
    validator.slashed = true;
    validator.withdrawable_epoch = validator
        .withdrawable_epoch
        .max(epoch.checked_add(slashings_vector).ok_or_else(overflow)?);
    let effective_balance = validator.effective_balance;
    let slashing = state
        .slashings
        .get_mut((epoch % slashings_vector) as usize)
        .ok_or_else(|| StfError::Tree("slashings is shorter than its length".into()))?;
    *slashing = slashing
        .checked_add(effective_balance)
        .ok_or_else(overflow)?;
    let slashing_penalty = effective_balance / MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA;
    decrease_balance(state, slashed_index, slashing_penalty)?;

    // Apply proposer and whistleblower rewards
    let proposer_index = state_proposer_index(state)?;
    let whistleblower_index = whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
    let proposer_reward = whistleblower_reward
        .checked_mul(PROPOSER_WEIGHT)
        .ok_or_else(overflow)?
        / WEIGHT_DENOMINATOR;
    increase_balance(state, proposer_index, proposer_reward)?;
    increase_balance(
        state,
        whistleblower_index,
        whistleblower_reward - proposer_reward,
    )?;

    // Remove pending builder payments for blocks proposed by the slashed validator
    let proposed: Vec<usize> = state
        .builder_pending_payments
        .iter()
        .enumerate()
        .filter(|(_, payment)| payment.proposer_index == slashed_index)
        .map(|(i, _)| i)
        .collect();
    for payment_index in proposed {
        if let Some(payment) = state.builder_pending_payments.get_mut(payment_index) {
            *payment = empty_payment();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::{
        activation_churn_limit, consolidation_churn_limit, exit_churn_limit,
        get_activation_churn_limit, get_consolidation_churn_limit, get_exit_churn_limit,
        get_total_active_balance, TotalActiveBalanceCache,
    };
    use crate::caches::get_beacon_proposer_index;
    use crate::testing::{genesis_state, registry_state};
    use crate::{state_root, Preset, StfError};
    use consensus_types::gloas::{
        BeaconState, Builder, BuilderPendingPayment, BuilderPendingWithdrawal,
    };
    use consensus_types::primitives::{Address, Bytes32, Gwei, FAR_FUTURE_EPOCH};
    use consensus_types::{EthSpec, Mainnet, Minimal};

    const ETH: Gwei = 1_000_000_000;
    /// The Hoodi registry size: 1,664,885 validators of 32 ETH.
    const HOODI: Gwei = 1_664_885 * 32 * ETH;

    /// The three limits for one total, as `(activation, exit, consolidation)`.
    fn limits<E: Preset>(total: Gwei) -> (Gwei, Gwei, Gwei) {
        (
            activation_churn_limit::<E>(total),
            exit_churn_limit::<E>(total),
            consolidation_churn_limit::<E>(total),
        )
    }

    #[test]
    fn churn_limits() {
        // Minimal: MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA 64 ETH, CHURN_LIMIT_QUOTIENT_GLOAS 16,
        // CONSOLIDATION_CHURN_LIMIT_QUOTIENT 32, MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS
        // 128 ETH. Each value is the spec formula, worked by hand.
        // Small: 256 ETH // 16 = 16 ETH < 64 ETH, and 256 ETH // 32 = 8 ETH.
        assert_eq!(limits::<Minimal>(256 * ETH), (64 * ETH, 64 * ETH, 8 * ETH));
        // Boundary of the minimum: 1024 ETH // 16 = 64 ETH, then 1040 ETH // 16 = 65 ETH.
        assert_eq!(
            limits::<Minimal>(1024 * ETH),
            (64 * ETH, 64 * ETH, 32 * ETH)
        );
        assert_eq!(
            limits::<Minimal>(1040 * ETH),
            (65 * ETH, 65 * ETH, 32 * ETH)
        );
        // Boundary of the activation cap: 2048 ETH // 16 = 128 ETH, then 129 ETH is capped.
        assert_eq!(
            limits::<Minimal>(2048 * ETH),
            (128 * ETH, 128 * ETH, 64 * ETH)
        );
        assert_eq!(
            limits::<Minimal>(2064 * ETH),
            (128 * ETH, 129 * ETH, 64 * ETH)
        );
        // Rounding down to EFFECTIVE_BALANCE_INCREMENT: 2079 ETH + 31 Gwei gives 129.94 ETH
        // and 64.97 ETH.
        let odd = 2064 * ETH + 15 * ETH + 31;
        assert_eq!(limits::<Minimal>(odd), (128 * ETH, 129 * ETH, 64 * ETH));
        // Hoodi: 53,276,320 ETH // 16 = 3,329,770 ETH, and // 32 = 1,664,885 ETH.
        assert_eq!(
            limits::<Minimal>(HOODI),
            (128 * ETH, 3_329_770 * ETH, 1_664_885 * ETH)
        );

        // Mainnet: 128 ETH, 2**15, 2**16, 256 ETH.
        // Small: 256 ETH // 2**15 < 128 ETH, and 256 ETH // 2**16 = 3,906,250 Gwei, rounded to 0.
        assert_eq!(limits::<Mainnet>(256 * ETH), (128 * ETH, 128 * ETH, 0));
        // Boundary of the minimum: 128 ETH * 2**15 = 4,194,304 ETH, then one more increment
        // per 2**15 ETH.
        let min_edge = 4_194_304 * ETH;
        assert_eq!(
            limits::<Mainnet>(min_edge),
            (128 * ETH, 128 * ETH, 64 * ETH)
        );
        assert_eq!(
            limits::<Mainnet>(min_edge + 32_768 * ETH),
            (129 * ETH, 129 * ETH, 64 * ETH)
        );
        assert_eq!(
            limits::<Mainnet>(min_edge + 32_768 * ETH - 1),
            (128 * ETH, 128 * ETH, 64 * ETH)
        );
        // Boundary of the activation cap: 256 ETH * 2**15 = 8,388,608 ETH.
        let cap_edge = 8_388_608 * ETH;
        assert_eq!(
            limits::<Mainnet>(cap_edge),
            (256 * ETH, 256 * ETH, 128 * ETH)
        );
        assert_eq!(
            limits::<Mainnet>(cap_edge + 32_768 * ETH),
            (256 * ETH, 257 * ETH, 128 * ETH)
        );
        // Hoodi: 53,276,320 ETH // 2**15 = 1625.86 ETH, rounded to 1625 ETH, and // 2**16 =
        // 812.93 ETH, rounded to 812 ETH.
        assert_eq!(limits::<Mainnet>(HOODI), (256 * ETH, 1625 * ETH, 812 * ETH));

        // The state getters apply the same formulas to the state's total active balance.
        let state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        let mut cache = TotalActiveBalanceCache::default();
        assert_eq!(get_total_active_balance(&state), Ok(256 * ETH));
        assert_eq!(get_activation_churn_limit(&state, &mut cache), Ok(64 * ETH));
        assert_eq!(get_exit_churn_limit(&state, &mut cache), Ok(64 * ETH));
        assert_eq!(
            get_consolidation_churn_limit(&state, &mut cache),
            Ok(8 * ETH)
        );
    }

    #[test]
    fn exit_churn_rollover() {
        // 2 validators of 40 ETH and 6 of 32 ETH: 272 ETH, an exit churn of 64 ETH (the
        // minimum). The first exit epoch is compute_activation_exit_epoch(0) = 5.
        let mut balances = [32 * ETH; 8];
        balances[..2].copy_from_slice(&[40 * ETH; 2]);
        let mut state = genesis_state::<Minimal>(&balances);
        let mut cache = TotalActiveBalanceCache::default();
        assert_eq!(get_exit_churn_limit(&state, &mut cache), Ok(64 * ETH));

        // The first exit fits in epoch 5 and leaves 24 ETH of its churn.
        assert_eq!(initiate_validator_exit(&mut state, 0, &mut cache), Ok(()));
        assert_eq!(state.earliest_exit_epoch, 5);
        assert_eq!(state.exit_balance_to_consume, 24 * ETH);
        // The second does not fit: 16 ETH go to epoch 6, which keeps 64 - 16 = 48 ETH.
        assert_eq!(initiate_validator_exit(&mut state, 1, &mut cache), Ok(()));
        assert_eq!(state.earliest_exit_epoch, 6);
        assert_eq!(state.exit_balance_to_consume, 48 * ETH);
        for (index, epoch) in [(0, 5), (1, 6)] {
            let validator = state.validators.get(index).unwrap();
            assert_eq!(validator.exit_epoch, epoch);
            assert_eq!(validator.withdrawable_epoch, epoch + 256);
        }
        // A balance of many epochs: 2048 - 48 = 2000 ETH, 32 more epochs, 48 ETH left.
        assert_eq!(
            compute_exit_epoch_and_update_churn(&mut state, 2048 * ETH, &mut cache),
            Ok(38)
        );
        assert_eq!(state.exit_balance_to_consume, 48 * ETH);
        // An exactly full epoch keeps the epoch and leaves nothing.
        assert_eq!(
            compute_exit_epoch_and_update_churn(&mut state, 48 * ETH, &mut cache),
            Ok(38)
        );
        assert_eq!(state.exit_balance_to_consume, 0);

        // A queue that ends before the activation-exit epoch restarts there with a full churn.
        let mut late = genesis_state::<Minimal>(&balances);
        late.slot = Minimal::start_slot_at_epoch(10);
        late.earliest_exit_epoch = 7;
        late.exit_balance_to_consume = ETH;
        let mut cache = TotalActiveBalanceCache::default();
        assert_eq!(
            compute_exit_epoch_and_update_churn(&mut late, 10 * ETH, &mut cache),
            Ok(15)
        );
        assert_eq!(late.exit_balance_to_consume, 54 * ETH);

        // Epochs and balances never wrap.
        let mut end = genesis_state::<Minimal>(&balances);
        end.earliest_exit_epoch = u64::MAX;
        end.exit_balance_to_consume = 0;
        let mut cache = TotalActiveBalanceCache::default();
        let churn = StfError::StateArithmetic {
            what: "churn queue",
        };
        assert_eq!(
            compute_exit_epoch_and_update_churn(&mut end, ETH, &mut cache),
            Err(churn.clone())
        );
        end.earliest_exit_epoch = 5;
        assert_eq!(
            compute_exit_epoch_and_update_churn(&mut end, u64::MAX, &mut cache),
            Err(churn)
        );
    }

    #[test]
    fn exit_idempotent() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        state.validators.get_mut(3).unwrap().exit_epoch = 9;
        state.earliest_exit_epoch = 9;
        state.exit_balance_to_consume = 5 * ETH;
        let mut cache = TotalActiveBalanceCache::default();
        let before = state_root(&mut state).unwrap();
        assert_eq!(initiate_validator_exit(&mut state, 3, &mut cache), Ok(()));
        assert_eq!(state_root(&mut state).unwrap(), before);
        // A second exit of the same validator also changes nothing.
        assert_eq!(initiate_validator_exit(&mut state, 4, &mut cache), Ok(()));
        let after_first = state_root(&mut state).unwrap();
        assert_ne!(after_first, before);
        assert_eq!(initiate_validator_exit(&mut state, 4, &mut cache), Ok(()));
        assert_eq!(state_root(&mut state).unwrap(), after_first);
        // An index past the registry is out of range.
        assert_eq!(
            initiate_validator_exit(&mut state, 8, &mut cache),
            Err(StfError::UnknownValidator(8))
        );
        // The withdrawable epoch never wraps.
        state.earliest_exit_epoch = u64::MAX - 10;
        assert_eq!(
            initiate_validator_exit(&mut state, 5, &mut cache),
            Err(StfError::ArithmeticOverflow)
        );
        assert_eq!(
            state.validators.get(5).unwrap().exit_epoch,
            FAR_FUTURE_EPOCH
        );
    }

    #[test]
    fn consolidation_churn_rollover() {
        // 256 ETH: a consolidation churn of 8 ETH on minimal.
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        let mut cache = TotalActiveBalanceCache::default();
        // 20 ETH: 8 ETH in epoch 5, 12 ETH need 2 more epochs, 24 - 20 = 4 ETH left.
        assert_eq!(
            compute_consolidation_epoch_and_update_churn(&mut state, 20 * ETH, &mut cache),
            Ok(7)
        );
        assert_eq!(state.earliest_consolidation_epoch, 7);
        assert_eq!(state.consolidation_balance_to_consume, 4 * ETH);
        assert_eq!(
            compute_consolidation_epoch_and_update_churn(&mut state, 3 * ETH, &mut cache),
            Ok(7)
        );
        assert_eq!(state.consolidation_balance_to_consume, ETH);
        // The exit queue does not move.
        assert_eq!(
            (state.earliest_exit_epoch, state.exit_balance_to_consume),
            (0, 0)
        );

        // A zero churn (mainnet, 256 ETH) divides by zero in the spec for any balance that
        // does not fit, and takes nothing for a zero balance.
        let mut small = registry_state::<Mainnet>(&[32 * ETH; 8], Bytes32::ZERO);
        let mut cache = TotalActiveBalanceCache::default();
        assert_eq!(get_consolidation_churn_limit(&small, &mut cache), Ok(0));
        assert_eq!(
            compute_consolidation_epoch_and_update_churn(&mut small, 0, &mut cache),
            Ok(5)
        );
        assert_eq!(
            compute_consolidation_epoch_and_update_churn(&mut small, ETH, &mut cache),
            Err(StfError::StateArithmetic {
                what: "churn queue"
            })
        );
    }

    /// A builder with `balance`, deposited in epoch 0 and not exiting.
    fn builder(balance: Gwei) -> Builder {
        Builder {
            pubkey: [0xb0; 48],
            version: 0,
            execution_address: Address::repeat_byte(0xb1),
            balance,
            deposit_epoch: 0,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        }
    }

    /// A pending payment of `amount` to `builder_index` for a block of `proposer_index`.
    fn payment(amount: Gwei, builder_index: u64, proposer_index: u64) -> BuilderPendingPayment {
        BuilderPendingPayment {
            weight: 7 * ETH,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: Address::repeat_byte(0xfe),
                amount,
                builder_index,
            },
            proposer_index,
        }
    }

    fn builder_state<E: Preset>(epoch: u64) -> BeaconState<E> {
        let mut state = registry_state::<E>(&[32 * ETH; 8], Bytes32::ZERO);
        state.slot = E::start_slot_at_epoch(epoch) + 1;
        state.builders.push(builder(5 * ETH)).unwrap();
        state.builders.push(builder(6 * ETH)).unwrap();
        state
    }

    #[test]
    fn builder_exit() {
        // G L1526-1532: withdrawable_epoch = current epoch + MIN_BUILDER_WITHDRAWABILITY_DELAY.
        let mut state = builder_state::<Minimal>(3);
        assert_eq!(initiate_builder_exit(&mut state, 1), Ok(()));
        assert_eq!(state.builders.get(1).unwrap().withdrawable_epoch, 3 + 2);
        assert_eq!(state.builders.get(0).unwrap(), &builder(5 * ETH));
        let mut state = builder_state::<Mainnet>(3);
        assert_eq!(initiate_builder_exit(&mut state, 0), Ok(()));
        assert_eq!(state.builders.get(0).unwrap().withdrawable_epoch, 3 + 64);
        // No exit check in the spec text: a second call sets the epoch again.
        state.slot = Mainnet::start_slot_at_epoch(4);
        assert_eq!(initiate_builder_exit(&mut state, 0), Ok(()));
        assert_eq!(state.builders.get(0).unwrap().withdrawable_epoch, 4 + 64);

        // Early return: an index past the registry is an out-of-range access, and the
        // state does not change.
        let before = state_root(&mut state).unwrap();
        assert_eq!(
            initiate_builder_exit(&mut state, 2),
            Err(StfError::UnknownBuilder(2))
        );
        assert_eq!(state_root(&mut state).unwrap(), before);
    }

    #[test]
    fn builder_payment_settlement() {
        // G L1538-1543: a payment with an amount becomes a pending withdrawal, and its slot
        // is reset to BuilderPendingPayment.empty().
        let mut state = builder_state::<Minimal>(1);
        *state.builder_pending_payments.get_mut(3).unwrap() = payment(9 * ETH, 1, 4);
        *state.builder_pending_payments.get_mut(4).unwrap() = payment(8 * ETH, 0, 2);
        assert_eq!(settle_builder_payment(&mut state, 3), Ok(()));
        assert_eq!(
            state.builder_pending_withdrawals.to_vec(),
            vec![payment(9 * ETH, 1, 4).withdrawal]
        );
        assert_eq!(
            state.builder_pending_payments.get(3),
            Some(&empty_payment())
        );
        assert_eq!(
            state.builder_pending_payments.get(4),
            Some(&payment(8 * ETH, 0, 2))
        );

        // Early return of the append: a zero amount adds no withdrawal, but the slot is still
        // reset.
        *state.builder_pending_payments.get_mut(5).unwrap() = payment(0, 1, 6);
        assert_eq!(settle_builder_payment(&mut state, 5), Ok(()));
        assert_eq!(state.builder_pending_withdrawals.len(), 1);
        assert_eq!(
            state.builder_pending_payments.get(5),
            Some(&empty_payment())
        );

        // The assert: an index past the vector.
        let len = state.builder_pending_payments.len() as u64;
        assert_eq!(len, 2 * Minimal::slots_per_epoch());
        let before = state_root(&mut state).unwrap();
        assert_eq!(
            settle_builder_payment(&mut state, len),
            Err(StfError::PaymentIndexOutOfRange { index: len, len })
        );
        assert_eq!(state_root(&mut state).unwrap(), before);
    }

    #[test]
    fn slash_clears_pending_payment() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        let proposer = get_beacon_proposer_index(&state).unwrap();
        let slashed = (proposer + 1) % 8;
        let other = (proposer + 2) % 8;
        *state.builder_pending_payments.get_mut(2).unwrap() = payment(9 * ETH, 0, slashed);
        *state.builder_pending_payments.get_mut(5).unwrap() = payment(4 * ETH, 1, other);
        *state.builder_pending_payments.get_mut(9).unwrap() = payment(3 * ETH, 1, proposer);
        let payments_before = state.builder_pending_payments.to_vec();
        let mut cache = TotalActiveBalanceCache::default();

        assert_eq!(
            slash_validator(&mut state, slashed, None, &mut cache),
            Ok(())
        );

        // G L1577-1581: the payment of the slashed proposer is empty, every other is kept.
        for (i, before) in payments_before.iter().enumerate() {
            let want = if i == 2 {
                empty_payment()
            } else {
                before.clone()
            };
            assert_eq!(state.builder_pending_payments.get(i), Some(&want), "{i}");
        }
        // The exit, the slashing and the penalty (G L1558-1566).
        let validator = state.validators.get(slashed as usize).unwrap();
        assert!(validator.slashed);
        assert_eq!(validator.exit_epoch, 5);
        assert_eq!(validator.withdrawable_epoch, 5 + 256);
        assert_eq!(state.slashings.get(0), Some(&(32 * ETH)));
        // 32 ETH // 4096 = 7,812,500 Gwei.
        let penalty = 7_812_500;
        assert_eq!(
            state.balances.get(slashed as usize),
            Some(&(32 * ETH - penalty))
        );
        // The proposer is also the whistleblower: 7,812,500 * 8 // 64 = 976,562 Gwei, plus
        // the rest of the whistleblower reward, 6,835,938 Gwei.
        assert_eq!(
            state.balances.get(proposer as usize),
            Some(&(32 * ETH + 7_812_500))
        );
        assert_eq!(state.balances.get(other as usize), Some(&(32 * ETH)));
    }

    #[test]
    fn slash_with_a_whistleblower() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        state.slot = Minimal::start_slot_at_epoch(1);
        crate::testing::refresh_lookahead(&mut state);
        let proposer = get_beacon_proposer_index(&state).unwrap();
        let slashed = (proposer + 1) % 8;
        let whistleblower = (proposer + 2) % 8;
        // A validator that already exits keeps its exit epoch, and the withdrawable epoch is
        // at least `epoch + EPOCHS_PER_SLASHINGS_VECTOR` (64 on minimal).
        let validator = state.validators.get_mut(slashed as usize).unwrap();
        validator.exit_epoch = 3;
        validator.withdrawable_epoch = 10;
        *state.balances.get_mut(slashed as usize).unwrap() = 1_000;
        *state.slashings.get_mut(1).unwrap() = ETH;
        let mut cache = TotalActiveBalanceCache::default();
        let reward_before = |s: &BeaconState<Minimal>, i: u64| *s.balances.get(i as usize).unwrap();
        let (p0, w0) = (
            reward_before(&state, proposer),
            reward_before(&state, whistleblower),
        );

        assert_eq!(
            slash_validator(&mut state, slashed, Some(whistleblower), &mut cache),
            Ok(())
        );
        let validator = state.validators.get(slashed as usize).unwrap();
        assert_eq!(
            (validator.exit_epoch, validator.withdrawable_epoch),
            (3, 65)
        );
        assert_eq!(state.slashings.get(1), Some(&(33 * ETH)));
        // decrease_balance saturates at 0.
        assert_eq!(state.balances.get(slashed as usize), Some(&0));
        assert_eq!(reward_before(&state, proposer), p0 + 976_562);
        assert_eq!(reward_before(&state, whistleblower), w0 + 6_835_938);
        // The exit queue did not move.
        assert_eq!(state.earliest_exit_epoch, 0);
    }

    #[test]
    fn slash_errors() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        assert_eq!(
            slash_validator(&mut state, 8, None, &mut TotalActiveBalanceCache::default()),
            Err(StfError::UnknownValidator(8))
        );
        assert_eq!(
            slash_validator(
                &mut state,
                1,
                Some(8),
                &mut TotalActiveBalanceCache::default()
            ),
            Err(StfError::UnknownValidator(8))
        );
        // A slashings sum that does not fit in a Uint64.
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        *state.slashings.get_mut(0).unwrap() = u64::MAX;
        assert_eq!(
            slash_validator(&mut state, 1, None, &mut TotalActiveBalanceCache::default()),
            Err(StfError::ArithmeticOverflow)
        );
        // A reward that does not fit.
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        let proposer = get_beacon_proposer_index(&state).unwrap();
        *state.balances.get_mut(proposer as usize).unwrap() = u64::MAX;
        assert_eq!(
            slash_validator(
                &mut state,
                (proposer + 1) % 8,
                None,
                &mut TotalActiveBalanceCache::default()
            ),
            Err(StfError::ArithmeticOverflow)
        );
        // The balance helpers check the index: past the registry it is the object's
        // error, past a `balances` list that is shorter than the registry it is ours.
        assert_eq!(
            increase_balance(&mut state, 8, 1),
            Err(StfError::UnknownValidator(8))
        );
        assert_eq!(
            decrease_balance(&mut state, 8, 1),
            Err(StfError::UnknownValidator(8))
        );
        let mut short = state.clone();
        short.balances = milhouse::ProgressiveList::try_from_iter([32 * ETH; 7]).unwrap();
        let past_balances = StfError::ListIndexOutOfRange {
            list: "balances",
            index: 7,
        };
        assert_eq!(
            increase_balance(&mut short, 7, 1),
            Err(past_balances.clone())
        );
        assert_eq!(
            decrease_balance(&mut short, 7, 1),
            Err(past_balances.clone())
        );
        assert!(!past_balances.proves_invalid());
        // The spec reads only `state.balances[index]`, so an index inside a `balances` list
        // that is longer than the registry succeeds.
        let mut long = state.clone();
        long.balances.push(5).unwrap();
        assert_eq!(increase_balance(&mut long, 8, 1), Ok(()));
        assert_eq!(decrease_balance(&mut long, 8, 2), Ok(()));
        assert_eq!(long.balances.get(8), Some(&4));
        // A full milhouse list is a limit of the implementation, not of the spec.
        let full = StfError::from(milhouse::Error::ListFull { len: usize::MAX });
        assert!(matches!(full, StfError::Tree(_)) && !full.proves_invalid());
        // The new errors prove an invalid input.
        assert!(StfError::UnknownBuilder(0).proves_invalid());
        assert!(StfError::PaymentIndexOutOfRange { index: 16, len: 16 }.proves_invalid());
    }

    #[test]
    fn slash_with_a_lookahead_past_the_registry() {
        // The proposer of the rewards comes from our own lookahead. An index there past the
        // registry is a fault of our state, not a proof against the slashing.
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        *state.proposer_lookahead.get_mut(0).unwrap() = 8;
        let result = slash_validator(&mut state, 1, None, &mut TotalActiveBalanceCache::default());
        let fault = StfError::ListIndexOutOfRange {
            list: "validators",
            index: 8,
        };
        assert_eq!(result, Err(fault.clone()));
        assert!(!fault.proves_invalid());
    }
}
