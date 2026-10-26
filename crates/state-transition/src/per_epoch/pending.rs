//! The pending deposits (G L1659-1713) and the pending consolidations (E L1208-1229), with
//! the deposit helpers they read: `apply_pending_deposit` (E L1108-1123), the registry of a
//! new validator (E L1707-1746) and `is_pending_validator` (G L1119-1133).
//!
//! The proof of possession of a new key goes through a [`SignatureBackend`]. The caller
//! fetches its verdict before the transition (ADR-011): a missing verdict is
//! [`StfError::MissingVerdict`], and an invalid signature skips the deposit.
//!
//! # Verdicts to prefetch
//!
//! A caller that prefetches verdicts must fetch one for each pending deposit that the step
//! can reach (the finalized deposits up to `MAX_PENDING_DEPOSITS_PER_EPOCH`) and whose key
//! is not in the registry of the pre-state. An earlier deposit of the same epoch can add the
//! key, and then a later deposit for it is a top-up that needs no verdict. A deposit for a
//! key whose earlier deposit was invalid needs its own verdict.

use super::registry::get_max_effective_balance;
use crate::accessors::{get_activation_churn_limit, get_current_epoch, TotalActiveBalanceCache};
use crate::mutators::{decrease_balance, increase_balance};
use crate::preset::{EFFECTIVE_BALANCE_INCREMENT, MAX_PENDING_DEPOSITS_PER_EPOCH};
use crate::signatures::is_valid_deposit_signature;
use crate::{Preset, SignatureBackend, StfError};
use consensus_types::common::{PendingDeposit, Validator};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{
    BLSPubkey, Bytes32, Gwei, ValidatorIndex, Version, FAR_FUTURE_EPOCH,
};
use milhouse::{ProgressiveList, Value};

/// `validator_pubkeys.index(pubkey)`: the index of the first validator with `pubkey`. It
/// reads the registry until the first match.
fn validator_index_of<E: Preset>(
    state: &BeaconState<E>,
    pubkey: &BLSPubkey,
) -> Option<ValidatorIndex> {
    state
        .validators
        .iter()
        .position(|validator| validator.pubkey == *pubkey)
        .map(|index| index as ValidatorIndex)
}

/// `get_validator_from_deposit` (E L1707-1727, Modified in Electra): a validator that is not
/// in the activation queue yet, with the effective balance of `amount`, rounded down and
/// capped at its maximum.
pub fn get_validator_from_deposit(
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
) -> Validator {
    let mut validator = Validator {
        pubkey,
        withdrawal_credentials,
        effective_balance: 0,
        slashed: false,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };
    let max_effective_balance = get_max_effective_balance(&validator);
    validator.effective_balance =
        (amount - amount % EFFECTIVE_BALANCE_INCREMENT).min(max_effective_balance);
    validator
}

/// `set_or_append_list` (A L308-316): appends at `index == len(list)`, else sets. The spec
/// raises on an index past the end. The registry index is the length of the validators, so
/// that error means that a state list is shorter than the registry: our own state error
/// (`ListIndexOutOfRange`), not a proof.
fn set_or_append_list<T: Value>(
    list: &mut ProgressiveList<T>,
    name: &'static str,
    index: ValidatorIndex,
    value: T,
) -> Result<(), StfError> {
    if index == list.len() as u64 {
        list.push(value)?;
    } else {
        *list
            .get_mut(index as usize)
            .ok_or(StfError::ListIndexOutOfRange { list: name, index })? = value;
    }
    Ok(())
}

/// `add_validator_to_registry` (E L1736-1746, Modified in Electra), with
/// `get_index_for_new_validator` (A L301-302): the end of the registry.
pub fn add_validator_to_registry<E: Preset>(
    state: &mut BeaconState<E>,
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
) -> Result<(), StfError> {
    let index = state.validators.len() as ValidatorIndex;
    let validator = get_validator_from_deposit(pubkey, withdrawal_credentials, amount);
    set_or_append_list(&mut state.validators, "validators", index, validator)?;
    set_or_append_list(&mut state.balances, "balances", index, amount)?;
    set_or_append_list(
        &mut state.previous_epoch_participation,
        "previous_epoch_participation",
        index,
        0b0000_0000,
    )?;
    set_or_append_list(
        &mut state.current_epoch_participation,
        "current_epoch_participation",
        index,
        0b0000_0000,
    )?;
    set_or_append_list(&mut state.inactivity_scores, "inactivity_scores", index, 0)
}

/// `apply_pending_deposit` (E L1108-1123, New in Electra; Gloas keeps it): a new key becomes
/// a validator only with a valid proof of possession, and a known key gets a top-up.
///
/// `genesis_fork_version` is the `GENESIS_FORK_VERSION` of the network (see
/// [`crate::BlsContext::genesis_fork_version`]). A missing verdict gives
/// [`StfError::MissingVerdict`].
pub fn apply_pending_deposit<E: Preset>(
    state: &mut BeaconState<E>,
    deposit: &PendingDeposit,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let index = validator_index_of(state, &deposit.pubkey);
    apply_pending_deposit_at(state, deposit, index, genesis_fork_version, backend)
}

/// [`apply_pending_deposit`] with the registry index of the key, which the caller read from
/// the same state.
fn apply_pending_deposit_at<E: Preset>(
    state: &mut BeaconState<E>,
    deposit: &PendingDeposit,
    index: Option<ValidatorIndex>,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    match index {
        None => {
            // Verify the deposit signature (proof of possession) which is not checked by the
            // deposit contract
            if is_valid_deposit_signature(
                deposit.pubkey,
                deposit.withdrawal_credentials,
                deposit.amount,
                deposit.signature,
                genesis_fork_version,
                backend,
            )? {
                add_validator_to_registry(
                    state,
                    deposit.pubkey,
                    deposit.withdrawal_credentials,
                    deposit.amount,
                )?;
            }
            Ok(())
        }
        Some(index) => increase_balance(state, index, deposit.amount),
    }
}

/// `is_pending_validator` (G L1119-1133, New in Gloas): whether `pending_deposits` holds a
/// deposit for `pubkey` with a valid signature. It asks `backend` for each deposit for the
/// key, in sequence, up to the first valid one.
pub fn is_pending_validator<'a>(
    pending_deposits: impl IntoIterator<Item = &'a PendingDeposit>,
    pubkey: BLSPubkey,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<bool, StfError> {
    for pending_deposit in pending_deposits {
        if pending_deposit.pubkey != pubkey {
            continue;
        }
        if is_valid_deposit_signature(
            pending_deposit.pubkey,
            pending_deposit.withdrawal_credentials,
            pending_deposit.amount,
            pending_deposit.signature,
            genesis_fork_version,
            backend,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `process_pending_deposits` (G L1659-1713, Modified in Gloas): the finalized deposits, up
/// to `MAX_PENDING_DEPOSITS_PER_EPOCH`, within the activation churn. Gloas removed the
/// Electra wait for the eth1 bridge deposits.
///
/// See the module documentation for the verdicts that `backend` must hold.
pub fn process_pending_deposits<E: Preset>(
    state: &mut BeaconState<E>,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    process_pending_deposits_with(
        state,
        genesis_fork_version,
        backend,
        &mut TotalActiveBalanceCache::default(),
    )
}

/// [`process_pending_deposits`] with the activation churn from `totals`.
pub(crate) fn process_pending_deposits_with<E: Preset>(
    state: &mut BeaconState<E>,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
    totals: &mut TotalActiveBalanceCache,
) -> Result<(), StfError> {
    let overflow = || StfError::ArithmeticOverflow;
    let next_epoch = get_current_epoch(state)
        .checked_add(1)
        .ok_or_else(overflow)?;
    // Deposits still consume the activation-only churn budget in Gloas.
    let available_for_processing = state
        .deposit_balance_to_consume
        .checked_add(get_activation_churn_limit(state, totals)?)
        .ok_or_else(overflow)?;
    let mut processed_amount: Gwei = 0;
    let mut next_deposit_index: u64 = 0;
    let mut deposits_to_postpone = Vec::new();
    let mut is_churn_limit_reached = false;
    let finalized_slot = state
        .finalized_checkpoint
        .epoch
        .checked_mul(E::slots_per_epoch())
        .ok_or_else(overflow)?;

    // The loop applies at most `MAX_PENDING_DEPOSITS_PER_EPOCH` deposits and does not change
    // the queue, so a copy of them lets it change the state. A deposit past them only stops
    // the loop.
    let deposits: Vec<PendingDeposit> = state
        .pending_deposits
        .iter()
        .take(MAX_PENDING_DEPOSITS_PER_EPOCH as usize)
        .cloned()
        .collect();
    for deposit in &deposits {
        // Check if deposit has been finalized, otherwise, stop processing.
        if deposit.slot > finalized_slot {
            break;
        }
        // Check if number of processed deposits has not reached the limit, otherwise, stop
        // processing.
        if next_deposit_index >= MAX_PENDING_DEPOSITS_PER_EPOCH {
            break;
        }
        // Read validator state
        let mut is_validator_exited = false;
        let mut is_validator_withdrawn = false;
        let index = validator_index_of(state, &deposit.pubkey);
        if let Some(index) = index {
            let validator = state
                .validators
                .get(index as usize)
                .ok_or(StfError::UnknownValidator(index))?;
            is_validator_exited = validator.exit_epoch < FAR_FUTURE_EPOCH;
            is_validator_withdrawn = validator.withdrawable_epoch < next_epoch;
        }
        if is_validator_withdrawn {
            // Deposited balance will never become active. Increase balance but do not
            // consume churn
            apply_pending_deposit_at(state, deposit, index, genesis_fork_version, backend)?;
        } else if is_validator_exited {
            // Validator is exiting, postpone the deposit until after withdrawable epoch
            deposits_to_postpone.push(deposit.clone());
        } else {
            // Check if deposit fits in the churn, otherwise, do no more deposit processing in
            // this epoch.
            let amount = processed_amount
                .checked_add(deposit.amount)
                .ok_or_else(overflow)?;
            is_churn_limit_reached = amount > available_for_processing;
            if is_churn_limit_reached {
                break;
            }
            // Consume churn and apply deposit.
            processed_amount = amount;
            apply_pending_deposit_at(state, deposit, index, genesis_fork_version, backend)?;
        }
        // Regardless of how the deposit was handled, we move on in the queue.
        next_deposit_index += 1;
    }

    state
        .pending_deposits
        .pop_front(next_deposit_index as usize)?;
    for deposit in deposits_to_postpone {
        // The queue is not longer than before, so the append cannot pass its limit.
        state.pending_deposits.push(deposit)?;
    }

    // Accumulate churn only if the churn limit has been hit.
    state.deposit_balance_to_consume = if is_churn_limit_reached {
        // The loop stops before `processed_amount` passes `available_for_processing`.
        available_for_processing - processed_amount
    } else {
        0
    };
    Ok(())
}

/// `process_pending_consolidations` (E L1208-1229, New in Electra; Gloas keeps it).
pub fn process_pending_consolidations<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    let next_epoch = get_current_epoch(state)
        .checked_add(1)
        .ok_or(StfError::ArithmeticOverflow)?;
    let mut next_pending_consolidation = 0usize;
    // The loop changes only the balances, so it can read the queue in place: a copy of each
    // entry ends the borrow before the balances change.
    while let Some(pending_consolidation) = state
        .pending_consolidations
        .get(next_pending_consolidation)
        .cloned()
    {
        let source_index = pending_consolidation.source_index;
        let source_validator = state
            .validators
            .get(source_index as usize)
            .ok_or(StfError::UnknownValidator(source_index))?;
        if source_validator.slashed {
            next_pending_consolidation += 1;
            continue;
        }
        if source_validator.withdrawable_epoch > next_epoch {
            break;
        }
        // Calculate the consolidated balance
        let balance =
            *state
                .balances
                .get(source_index as usize)
                .ok_or(StfError::ListIndexOutOfRange {
                    list: "balances",
                    index: source_index,
                })?;
        let source_effective_balance = balance.min(source_validator.effective_balance);
        // Move active balance to target. Excess balance is withdrawable.
        decrease_balance(state, source_index, source_effective_balance)?;
        increase_balance(
            state,
            pending_consolidation.target_index,
            source_effective_balance,
        )?;
        next_pending_consolidation += 1;
    }
    state
        .pending_consolidations
        .pop_front(next_pending_consolidation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::deposit_signature_set;
    use crate::testing::{registry_state, ScriptedBackend, GENESIS_FORK_VERSION};
    use crate::{BackendError, StfError};
    use consensus_types::common::{PendingConsolidation, PendingDeposit};
    use consensus_types::gloas::BeaconState;
    use consensus_types::primitives::{BLSPubkey, Bytes32, Gwei, FAR_FUTURE_EPOCH};
    use consensus_types::{EthSpec, Minimal};

    const ETH: Gwei = 1_000_000_000;

    /// A minimal state of 8 validators of 32 ETH at the last slot of epoch 4, finalized at
    /// epoch 2. The total is 256 ETH, so the activation churn is 64 ETH.
    fn state() -> BeaconState<Minimal> {
        let mut state = registry_state::<Minimal>(&[32 * ETH; 8], Bytes32::ZERO);
        state.slot = Minimal::start_slot_at_epoch(5) - 1;
        state.finalized_checkpoint.epoch = 2;
        state
    }

    /// The key of validator `i` of [`registry_state`].
    fn key_of(i: u64) -> BLSPubkey {
        let mut pubkey = [0u8; 48];
        pubkey[..8].copy_from_slice(&i.to_le_bytes());
        pubkey
    }

    /// A deposit of `amount` for `pubkey` at `slot`, with 0x01 credentials.
    fn deposit(pubkey: BLSPubkey, amount: Gwei, slot: u64) -> PendingDeposit {
        let mut withdrawal_credentials = Bytes32::ZERO;
        withdrawal_credentials[0] = 0x01;
        PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount,
            signature: [0x44; 96],
            slot,
        }
    }

    fn set_of(deposit: &PendingDeposit) -> crate::SignatureSet {
        deposit_signature_set(
            deposit.pubkey,
            deposit.withdrawal_credentials,
            deposit.amount,
            deposit.signature,
            GENESIS_FORK_VERSION,
        )
    }

    fn queue(state: &mut BeaconState<Minimal>, deposits: &[PendingDeposit]) {
        for d in deposits {
            state.pending_deposits.push(d.clone()).unwrap();
        }
    }

    fn run(state: &mut BeaconState<Minimal>, backend: &ScriptedBackend) -> Result<(), StfError> {
        process_pending_deposits(state, GENESIS_FORK_VERSION, backend)
    }

    #[test]
    fn deposits_of_new_keys_need_a_verdict() {
        let mut state = state();
        let invalid = deposit([0xa1; 48], 16 * ETH, 0);
        let valid = deposit([0xb1; 48], 32 * ETH + 7, 0);
        // A second deposit for the new key is a top-up: no other verdict.
        let again = deposit([0xb1; 48], ETH, 0);
        // The invalid key is still new, so its second deposit needs a verdict again.
        let retry = deposit([0xa1; 48], ETH, 0);
        let top_up = deposit(key_of(3), ETH, 0);
        queue(
            &mut state,
            &[invalid.clone(), valid.clone(), again, retry.clone(), top_up],
        );
        let backend = ScriptedBackend::new([Ok(false), Ok(true), Ok(false)]);
        run(&mut state, &backend).unwrap();
        assert_eq!(
            backend.seen(),
            vec![set_of(&invalid), set_of(&valid), set_of(&retry)]
        );
        assert_eq!(state.validators.len(), 9);
        let added = state.validators.get(8).unwrap();
        assert_eq!(added.pubkey, [0xb1; 48]);
        assert_eq!(added.withdrawal_credentials, valid.withdrawal_credentials);
        assert_eq!(added.effective_balance, 32 * ETH);
        assert_eq!(added.activation_eligibility_epoch, FAR_FUTURE_EPOCH);
        assert_eq!(state.balances.get(8), Some(&(33 * ETH + 7)));
        assert_eq!(state.balances.get(3), Some(&(33 * ETH)));
        for list in [
            state.previous_epoch_participation.len(),
            state.current_epoch_participation.len(),
            state.inactivity_scores.len(),
        ] {
            assert_eq!(list, 9);
        }
        // Every deposit consumed churn (the invalid ones too), and 51 ETH fit in 64 ETH.
        assert!(state.pending_deposits.is_empty());
        assert_eq!(state.deposit_balance_to_consume, 0);

        // A missing verdict stops the step. It is not a proof of an invalid input.
        let mut state = self::state();
        queue(&mut state, &[deposit([0xa1; 48], ETH, 0)]);
        let missing = ScriptedBackend::new([Err(BackendError("not prefetched".into()))]);
        let err = run(&mut state, &missing).unwrap_err();
        assert_eq!(
            err,
            StfError::MissingVerdict(BackendError("not prefetched".into()))
        );
        assert!(!err.proves_invalid());
    }

    #[test]
    fn churn_finality_and_the_per_epoch_limit() {
        let none = || ScriptedBackend::new([]);
        // The second top-up does not fit in the churn of 64 ETH: the loop stops, and the
        // rest of the churn carries over.
        let mut state = state();
        let second = deposit(key_of(1), 30 * ETH, 0);
        queue(
            &mut state,
            &[deposit(key_of(0), 40 * ETH, 0), second.clone()],
        );
        run(&mut state, &none()).unwrap();
        assert_eq!(state.pending_deposits.to_vec(), vec![second.clone()]);
        assert_eq!(state.deposit_balance_to_consume, 24 * ETH);
        assert_eq!(state.balances.get(0), Some(&(72 * ETH)));
        // The carried churn adds to the next epoch: 24 + 64 ETH.
        run(&mut state, &none()).unwrap();
        assert!(state.pending_deposits.is_empty());
        assert_eq!(state.deposit_balance_to_consume, 0);

        // A deposit after the finalized slot (16) waits.
        let mut state = self::state();
        let late = deposit(key_of(0), ETH, 17);
        queue(&mut state, &[deposit(key_of(0), ETH, 16), late.clone()]);
        run(&mut state, &none()).unwrap();
        assert_eq!(state.pending_deposits.to_vec(), vec![late]);

        // At most MAX_PENDING_DEPOSITS_PER_EPOCH (16) deposits in one epoch.
        let mut state = self::state();
        let top_ups: Vec<_> = (0..17).map(|_| deposit(key_of(2), ETH, 0)).collect();
        queue(&mut state, &top_ups);
        run(&mut state, &none()).unwrap();
        assert_eq!(state.pending_deposits.len(), 1);
        assert_eq!(state.balances.get(2), Some(&(48 * ETH)));
        assert_eq!(state.deposit_balance_to_consume, 0);

        // The sum of the carried churn and the churn limit overflows.
        let mut state = self::state();
        state.deposit_balance_to_consume = u64::MAX;
        assert_eq!(run(&mut state, &none()), Err(StfError::ArithmeticOverflow));
        // So does the start slot of a finalized epoch past 2**64 / SLOTS_PER_EPOCH.
        let mut state = self::state();
        state.finalized_checkpoint.epoch = u64::MAX / 4;
        assert_eq!(run(&mut state, &none()), Err(StfError::ArithmeticOverflow));
    }

    #[test]
    fn exiting_validators_wait_and_withdrawn_ones_take_no_churn() {
        let mut state = state();
        // 0 exits but is not withdrawable: its deposit goes to the end of the queue.
        let v = state.validators.get_mut(0).unwrap();
        v.exit_epoch = 10;
        v.withdrawable_epoch = 300;
        // 1 is withdrawable before the next epoch (5): its deposit takes no churn.
        let v = state.validators.get_mut(1).unwrap();
        v.exit_epoch = 3;
        v.withdrawable_epoch = 4;
        let exiting = deposit(key_of(0), ETH, 0);
        queue(
            &mut state,
            &[
                exiting.clone(),
                deposit(key_of(1), 100 * ETH, 0),
                deposit(key_of(2), 64 * ETH, 0),
            ],
        );
        run(&mut state, &ScriptedBackend::new([])).unwrap();
        assert_eq!(state.pending_deposits.to_vec(), vec![exiting]);
        assert_eq!(state.balances.get(0), Some(&(32 * ETH)));
        assert_eq!(state.balances.get(1), Some(&(132 * ETH)));
        assert_eq!(state.balances.get(2), Some(&(96 * ETH)));
        assert_eq!(state.deposit_balance_to_consume, 0);
    }

    #[test]
    fn new_validators_get_their_capped_effective_balance() {
        let mut compounding = Bytes32::ZERO;
        compounding[0] = 0x02;
        let v = get_validator_from_deposit([0xc1; 48], compounding, 3_000 * ETH);
        assert_eq!(v.effective_balance, 2_048 * ETH);
        let v = get_validator_from_deposit([0xc1; 48], compounding, 40 * ETH + 1);
        assert_eq!(v.effective_balance, 40 * ETH);
        let v = get_validator_from_deposit([0xc1; 48], Bytes32::ZERO, 40 * ETH);
        assert_eq!(v.effective_balance, 32 * ETH);
        assert_eq!(
            (
                v.activation_epoch,
                v.exit_epoch,
                v.withdrawable_epoch,
                v.slashed
            ),
            (FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH, false)
        );

        // `set_or_append_list` sets an entry at an index inside the list.
        let mut state = state();
        state.inactivity_scores = milhouse::ProgressiveList::try_from_iter([5; 9]).unwrap();
        add_validator_to_registry(&mut state, [0xc1; 48], compounding, 7).unwrap();
        assert_eq!(
            state.inactivity_scores.to_vec(),
            [5, 5, 5, 5, 5, 5, 5, 5, 0]
        );
        // An index past the end of a list is our own state error.
        state.balances = milhouse::ProgressiveList::try_from_iter([ETH; 3]).unwrap();
        assert_eq!(
            add_validator_to_registry(&mut state, [0xc2; 48], compounding, 7),
            Err(StfError::ListIndexOutOfRange {
                list: "balances",
                index: 9
            })
        );
    }

    #[test]
    fn pending_validator_needs_a_valid_deposit_for_its_key() {
        let deposits = [
            deposit([0xa1; 48], ETH, 0),
            deposit([0xb1; 48], ETH, 0),
            deposit([0xa1; 48], 2 * ETH, 0),
        ];
        let check = |backend: &ScriptedBackend, key: BLSPubkey| {
            is_pending_validator(&deposits, key, GENESIS_FORK_VERSION, backend)
        };
        // The first deposit for the key is invalid, the second is valid.
        let backend = ScriptedBackend::new([Ok(false), Ok(true)]);
        assert_eq!(check(&backend, [0xa1; 48]), Ok(true));
        assert_eq!(
            backend.seen(),
            vec![set_of(&deposits[0]), set_of(&deposits[2])]
        );
        // The first valid deposit stops the search.
        let backend = ScriptedBackend::new([Ok(true)]);
        assert_eq!(check(&backend, [0xb1; 48]), Ok(true));
        assert_eq!(check(&ScriptedBackend::new([]), [0xc1; 48]), Ok(false));
        let backend = ScriptedBackend::new([Ok(false), Ok(false)]);
        assert_eq!(check(&backend, [0xa1; 48]), Ok(false));
        let backend = ScriptedBackend::new([Err(BackendError("x".into()))]);
        assert_eq!(
            check(&backend, [0xa1; 48]),
            Err(StfError::MissingVerdict(BackendError("x".into())))
        );
    }

    #[test]
    fn consolidations_move_the_active_balance() {
        let mut state = state();
        let consolidation = |source_index, target_index| PendingConsolidation {
            source_index,
            target_index,
        };
        // 0 is slashed: skipped. 1 is withdrawable at the next epoch: it moves
        // min(balance, effective balance). 3 is not withdrawable yet: the loop stops there.
        state.validators.get_mut(0).unwrap().slashed = true;
        state.validators.get_mut(1).unwrap().withdrawable_epoch = 5;
        *state.balances.get_mut(1).unwrap() = 33 * ETH;
        state.validators.get_mut(3).unwrap().withdrawable_epoch = 6;
        let waiting = consolidation(3, 4);
        for c in [consolidation(0, 2), consolidation(1, 2), waiting.clone()] {
            state.pending_consolidations.push(c).unwrap();
        }
        process_pending_consolidations(&mut state).unwrap();
        assert_eq!(state.pending_consolidations.to_vec(), vec![waiting]);
        assert_eq!(state.balances.get(1), Some(&ETH));
        assert_eq!(state.balances.get(2), Some(&(64 * ETH)));
        assert_eq!(state.balances.get(0), Some(&(32 * ETH)));

        // A source past the registry is a spec error.
        let mut state = self::state();
        state
            .pending_consolidations
            .push(consolidation(8, 0))
            .unwrap();
        assert_eq!(
            process_pending_consolidations(&mut state),
            Err(StfError::UnknownValidator(8))
        );
    }
}
