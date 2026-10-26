//! Execution-layer requests of the parent payload: `process_consolidation_request`
//! (E L2000-2072, New in Electra; Gloas keeps it) and its helpers.
//!
//! Gloas removes the request calls from `process_operations` (G L2228-2263).
//! `apply_parent_execution_payload` (G L1784-1830) calls them for the requests of the parent
//! payload, at the slot of the child block. A request that is not valid does nothing, as in
//! the spec: it is never an error. An `Err` comes only from a `Uint64` overflow or from a
//! fault of our own state.
//!
//! Each request finds its validators by key, with a scan of the registry
//! (`validator_pubkeys.index(pubkey)`, the first match). A payload has at most
//! `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD` (2) consolidation requests.

use crate::accessors::{
    get_consolidation_churn_limit, get_current_epoch, get_pending_balance_to_withdraw,
    has_compounding_withdrawal_credential, has_eth1_withdrawal_credential,
    has_execution_withdrawal_credential, is_active_validator, TotalActiveBalanceCache,
};
use crate::mutators::compute_consolidation_epoch_and_update_churn;
use crate::preset::{
    COMPOUNDING_WITHDRAWAL_PREFIX, GENESIS_SLOT, MIN_ACTIVATION_BALANCE,
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
};
use crate::signatures::G2_POINT_AT_INFINITY;
use crate::{Preset, StfError};
use consensus_types::common::{
    ConsolidationRequest, PendingConsolidation, PendingDeposit, Validator,
};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{BLSPubkey, ValidatorIndex, FAR_FUTURE_EPOCH};
use ssz_types::typenum::Unsigned;

/// The index of the validator with `pubkey`: `validator_pubkeys.index(pubkey)`, the first
/// match. It reads the registry.
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

/// `state.validators[index]` for an index from [`validator_index_of`].
fn validator<E: Preset>(
    state: &BeaconState<E>,
    index: ValidatorIndex,
) -> Result<&Validator, StfError> {
    state
        .validators
        .get(index as usize)
        .ok_or(StfError::UnknownValidator(index))
}

/// The source index of a valid switch to compounding credentials, with the checks of
/// `is_valid_switch_to_compounding_request` (E L1962-1994), so that the registry is read
/// one time.
fn switch_to_compounding_source<E: Preset>(
    state: &BeaconState<E>,
    consolidation_request: &ConsolidationRequest,
) -> Option<ValidatorIndex> {
    // Switch to compounding requires source and target be equal
    if consolidation_request.source_pubkey != consolidation_request.target_pubkey {
        return None;
    }
    // Verify pubkey exists
    let source_index = validator_index_of(state, &consolidation_request.source_pubkey)?;
    let source_validator = state.validators.get(source_index as usize)?;
    // Verify request has been authorized
    if source_validator.withdrawal_credentials[12..] != consolidation_request.source_address[..] {
        return None;
    }
    // Verify source withdrawal credentials
    if !has_eth1_withdrawal_credential(source_validator) {
        return None;
    }
    // Verify the source is active
    if !is_active_validator(source_validator, get_current_epoch(state)) {
        return None;
    }
    // Verify exit for source has not been initiated
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH {
        return None;
    }
    Some(source_index)
}

/// `is_valid_switch_to_compounding_request` (E L1962-1994, New in Electra): the request
/// switches the 0x01 credentials of an active validator, from the address of the
/// credentials, to 0x02 credentials. It reads the registry.
pub fn is_valid_switch_to_compounding_request<E: Preset>(
    state: &BeaconState<E>,
    consolidation_request: &ConsolidationRequest,
) -> bool {
    switch_to_compounding_source(state, consolidation_request).is_some()
}

/// `switch_to_compounding_validator` (E L887-892, New in Electra): the validator gets the
/// 0x02 prefix, and the balance above `MIN_ACTIVATION_BALANCE` goes to a pending deposit.
pub fn switch_to_compounding_validator<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
) -> Result<(), StfError> {
    let validator = state
        .validators
        .get_mut(index as usize)
        .ok_or(StfError::UnknownValidator(index))?;
    validator.withdrawal_credentials[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
    queue_excess_active_balance(state, index)
}

/// `queue_excess_active_balance` (E L898-914, New in Electra): the balance above
/// `MIN_ACTIVATION_BALANCE` goes to a pending deposit with the infinity signature and
/// `GENESIS_SLOT`, which marks it as not a deposit request.
pub fn queue_excess_active_balance<E: Preset>(
    state: &mut BeaconState<E>,
    index: ValidatorIndex,
) -> Result<(), StfError> {
    let (pubkey, withdrawal_credentials) = {
        let validator = validator(state, index)?;
        (validator.pubkey, validator.withdrawal_credentials)
    };
    // The index is in the registry, so a short `balances` is a fault of our own state.
    let balance = state
        .balances
        .get_mut(index as usize)
        .ok_or(StfError::ListIndexOutOfRange {
            list: "balances",
            index,
        })?;
    if *balance > MIN_ACTIVATION_BALANCE {
        let excess_balance = *balance - MIN_ACTIVATION_BALANCE;
        *balance = MIN_ACTIVATION_BALANCE;
        // Use G2_POINT_AT_INFINITY as a signature field placeholder
        // and GENESIS_SLOT to distinguish from a pending deposit request
        state.pending_deposits.push(PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount: excess_balance,
            signature: G2_POINT_AT_INFINITY,
            slot: GENESIS_SLOT,
        })?;
    }
    Ok(())
}

/// `process_consolidation_request` (E L2000-2072, New in Electra; Gloas keeps it, with the
/// Gloas `get_consolidation_churn_limit`): a switch to compounding credentials, or a
/// consolidation of the source validator into the target validator. `cache` gives the total
/// active balance of the consolidation churn.
///
/// A request that is not valid does nothing and gives `Ok(())`, as in the spec.
/// `apply_parent_execution_payload` (G L1824) calls it for each consolidation request of the
/// parent payload. On `Err`, `state` is partly updated: the caller drops it.
pub fn process_consolidation_request<E: Preset>(
    state: &mut BeaconState<E>,
    consolidation_request: &ConsolidationRequest,
    cache: &mut TotalActiveBalanceCache,
) -> Result<(), StfError> {
    if let Some(source_index) = switch_to_compounding_source(state, consolidation_request) {
        return switch_to_compounding_validator(state, source_index);
    }

    // Verify that source != target, so a consolidation cannot be used as an exit
    if consolidation_request.source_pubkey == consolidation_request.target_pubkey {
        return Ok(());
    }
    // If the pending consolidations queue is full, consolidation requests are ignored
    if state.pending_consolidations.len() as u64 == E::PendingConsolidationsLimit::to_u64() {
        return Ok(());
    }
    // If there is too little available consolidation churn limit, consolidation requests are ignored
    if get_consolidation_churn_limit(state, cache)? <= MIN_ACTIVATION_BALANCE {
        return Ok(());
    }

    // Verify pubkeys exists
    let Some(source_index) = validator_index_of(state, &consolidation_request.source_pubkey) else {
        return Ok(());
    };
    let Some(target_index) = validator_index_of(state, &consolidation_request.target_pubkey) else {
        return Ok(());
    };
    let source_validator = validator(state, source_index)?;
    let target_validator = validator(state, target_index)?;

    // Verify source withdrawal credentials
    let has_correct_credential = has_execution_withdrawal_credential(source_validator);
    let is_correct_source_address =
        source_validator.withdrawal_credentials[12..] == consolidation_request.source_address[..];
    if !(has_correct_credential && is_correct_source_address) {
        return Ok(());
    }
    // Verify that target has compounding withdrawal credentials
    if !has_compounding_withdrawal_credential(target_validator) {
        return Ok(());
    }
    // Verify the source and the target are active
    let current_epoch = get_current_epoch(state);
    if !is_active_validator(source_validator, current_epoch)
        || !is_active_validator(target_validator, current_epoch)
    {
        return Ok(());
    }
    // Verify exits for source and target have not been initiated
    if source_validator.exit_epoch != FAR_FUTURE_EPOCH
        || target_validator.exit_epoch != FAR_FUTURE_EPOCH
    {
        return Ok(());
    }
    // Verify the source has been active long enough
    let earliest_epoch = source_validator
        .activation_epoch
        .checked_add(E::SHARD_COMMITTEE_PERIOD)
        .ok_or(StfError::ArithmeticOverflow)?;
    if current_epoch < earliest_epoch {
        return Ok(());
    }
    // Verify the source has no pending withdrawals in the queue
    if get_pending_balance_to_withdraw(state, source_index)? > 0 {
        return Ok(());
    }

    // Initiate source validator exit and append pending consolidation
    let effective_balance = source_validator.effective_balance;
    let exit_epoch = compute_consolidation_epoch_and_update_churn(state, effective_balance, cache)?;
    let withdrawable_epoch = exit_epoch
        .checked_add(MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
        .ok_or(StfError::ArithmeticOverflow)?;
    let source_validator = state
        .validators
        .get_mut(source_index as usize)
        .ok_or(StfError::UnknownValidator(source_index))?;
    source_validator.exit_epoch = exit_epoch;
    source_validator.withdrawable_epoch = withdrawable_epoch;
    // `PendingConsolidations` is a `ProgressiveList` without a limit. milhouse fails only at
    // a length of `usize::MAX`: `StfError::Tree`, which is not a proof of an invalid input.
    state.pending_consolidations.push(PendingConsolidation {
        source_index,
        target_index,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::compute_activation_exit_epoch;
    use crate::preset::{MIN_ACTIVATION_BALANCE, MIN_VALIDATOR_WITHDRAWABILITY_DELAY};
    use crate::signatures::G2_POINT_AT_INFINITY;
    use crate::state_root;
    use crate::testing::genesis_state;
    use consensus_types::common::{
        ConsolidationRequest, PendingConsolidation, PendingDeposit, PendingPartialWithdrawal,
    };
    use consensus_types::gloas::BeaconState;
    use consensus_types::primitives::{Address, BLSPubkey, Bytes32};
    use consensus_types::{EthSpec, Minimal};

    const ETH: u64 = 1_000_000_000;

    /// The key of validator `index` in [`genesis_state`].
    fn key(index: u64) -> BLSPubkey {
        let mut pubkey = [0u8; 48];
        pubkey[..8].copy_from_slice(&index.to_le_bytes());
        pubkey
    }

    /// Withdrawal credentials with `prefix` and the address `[address; 20]`.
    fn credentials(prefix: u8, address: u8) -> Bytes32 {
        let mut credentials = Bytes32::ZERO;
        credentials[0] = prefix;
        credentials[12..].fill(address);
        credentials
    }

    /// `validators` validators of 32 ETH in epoch 64 of the minimal preset (each one active
    /// for `SHARD_COMMITTEE_PERIOD`). Validator 1 has the 0x01 credentials of the address
    /// `[0x11; 20]`, and validator 2 the 0x02 credentials of `[0x22; 20]`.
    fn state_of(validators: usize) -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&vec![32 * ETH; validators]);
        state.slot = Minimal::start_slot_at_epoch(64) + 1;
        state.validators.get_mut(1).unwrap().withdrawal_credentials = credentials(0x01, 0x11);
        state.validators.get_mut(2).unwrap().withdrawal_credentials = credentials(0x02, 0x22);
        state
    }

    /// [`state_of`] 64 validators: a consolidation churn of 2048 ETH / 32 = 64 ETH.
    fn state() -> BeaconState<Minimal> {
        state_of(64)
    }

    fn request(source: BLSPubkey, target: BLSPubkey) -> ConsolidationRequest {
        ConsolidationRequest {
            source_address: Address::repeat_byte(0x11),
            source_pubkey: source,
            target_pubkey: target,
        }
    }

    fn process(
        state: &mut BeaconState<Minimal>,
        request: &ConsolidationRequest,
    ) -> Result<(), StfError> {
        process_consolidation_request(state, request, &mut TotalActiveBalanceCache::default())
    }

    #[test]
    fn consolidation_noop() {
        let mut state = state();
        let before = state_root(&mut state).unwrap();
        // An unknown source key, and an unknown target key.
        for request in [request([0xff; 48], key(2)), request(key(1), [0xff; 48])] {
            assert_eq!(process(&mut state, &request), Ok(()));
            assert_eq!(state_root(&mut state).unwrap(), before);
        }
    }

    #[test]
    fn consolidation_moves_the_source() {
        let mut state = state();
        assert_eq!(process(&mut state, &request(key(1), key(2))), Ok(()));
        let exit_epoch = compute_activation_exit_epoch(64).unwrap();
        let source = state.validators.get(1).unwrap();
        assert_eq!(source.exit_epoch, exit_epoch);
        assert_eq!(
            source.withdrawable_epoch,
            exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY
        );
        assert_eq!(
            state.pending_consolidations.iter().collect::<Vec<_>>(),
            vec![&PendingConsolidation {
                source_index: 1,
                target_index: 2
            }]
        );
        // The churn of the epoch is 64 ETH, and the source used 32 ETH of it.
        assert_eq!(state.earliest_consolidation_epoch, exit_epoch);
        assert_eq!(state.consolidation_balance_to_consume, 32 * ETH);
        // The target and the balances do not change.
        assert_eq!(state.validators.get(2).unwrap().exit_epoch, u64::MAX);
        assert_eq!(*state.balances.get(1).unwrap(), 32 * ETH);
    }

    #[test]
    fn switch_to_compounding() {
        let mut state = state();
        *state.balances.get_mut(1).unwrap() = 40 * ETH;
        assert!(is_valid_switch_to_compounding_request(
            &state,
            &request(key(1), key(1))
        ));
        assert_eq!(process(&mut state, &request(key(1), key(1))), Ok(()));
        assert_eq!(
            state.validators.get(1).unwrap().withdrawal_credentials,
            credentials(0x02, 0x11)
        );
        // The balance above MIN_ACTIVATION_BALANCE goes to a pending deposit.
        assert_eq!(*state.balances.get(1).unwrap(), MIN_ACTIVATION_BALANCE);
        assert_eq!(
            state.pending_deposits.iter().collect::<Vec<_>>(),
            vec![&PendingDeposit {
                pubkey: key(1),
                withdrawal_credentials: credentials(0x02, 0x11),
                amount: 8 * ETH,
                signature: G2_POINT_AT_INFINITY,
                slot: 0,
            }]
        );
        assert_eq!(state.validators.get(1).unwrap().exit_epoch, u64::MAX);

        // A balance that is not above MIN_ACTIVATION_BALANCE queues nothing.
        let mut state = self::state();
        *state.balances.get_mut(1).unwrap() = MIN_ACTIVATION_BALANCE;
        assert_eq!(process(&mut state, &request(key(1), key(1))), Ok(()));
        assert_eq!(
            state.validators.get(1).unwrap().withdrawal_credentials,
            credentials(0x02, 0x11)
        );
        assert_eq!(state.pending_deposits.len(), 0);
    }

    #[test]
    fn invalid_switch_requests() {
        let state = state();
        let switch = request(key(1), key(1));
        assert!(!is_valid_switch_to_compounding_request(
            &state,
            &request(key(1), key(2))
        ));
        assert!(!is_valid_switch_to_compounding_request(
            &state,
            &request([0xff; 48], [0xff; 48])
        ));
        let other_address = ConsolidationRequest {
            source_address: Address::repeat_byte(0x12),
            ..switch.clone()
        };
        assert!(!is_valid_switch_to_compounding_request(
            &state,
            &other_address
        ));
        // Validator 2 has 0x02 credentials already.
        let mut compounding = state.clone();
        compounding
            .validators
            .get_mut(2)
            .unwrap()
            .withdrawal_credentials = credentials(0x02, 0x11);
        assert!(!is_valid_switch_to_compounding_request(
            &compounding,
            &request(key(2), key(2))
        ));
        let mut inactive = state.clone();
        inactive.validators.get_mut(1).unwrap().activation_epoch = 65;
        assert!(!is_valid_switch_to_compounding_request(&inactive, &switch));
        let mut exiting = state.clone();
        exiting.validators.get_mut(1).unwrap().exit_epoch = 70;
        assert!(!is_valid_switch_to_compounding_request(&exiting, &switch));
    }

    /// Changes the state or the request of a valid consolidation of validator 1 into
    /// validator 2.
    type Change = dyn Fn(&mut BeaconState<Minimal>, &mut ConsolidationRequest);

    #[test]
    fn invalid_consolidations_are_ignored() {
        let cases: [(&str, &Change); 13] = [
            // Validator 2 has 0x02 credentials, so this is not a valid switch either.
            ("source is the target", &|_, r| r.source_pubkey = key(2)),
            ("queue is full", &|s, _| {
                for _ in 0..64 {
                    s.pending_consolidations
                        .push(PendingConsolidation {
                            source_index: 3,
                            target_index: 4,
                        })
                        .unwrap();
                }
            }),
            ("other source address", &|_, r| {
                r.source_address = Address::repeat_byte(0x12)
            }),
            ("source has BLS credentials", &|s, _| {
                s.validators.get_mut(1).unwrap().withdrawal_credentials = credentials(0x00, 0x11)
            }),
            ("target is not compounding", &|s, _| {
                s.validators.get_mut(2).unwrap().withdrawal_credentials = credentials(0x01, 0x22)
            }),
            ("source is not active", &|s, _| {
                s.validators.get_mut(1).unwrap().activation_epoch = 65
            }),
            ("target is not active", &|s, _| {
                s.validators.get_mut(2).unwrap().activation_epoch = 65
            }),
            ("source exits", &|s, _| {
                s.validators.get_mut(1).unwrap().exit_epoch = 70
            }),
            ("target exits", &|s, _| {
                s.validators.get_mut(2).unwrap().exit_epoch = 70
            }),
            ("source is too young", &|s, _| {
                s.validators.get_mut(1).unwrap().activation_epoch = 1
            }),
            ("source has a pending withdrawal", &|s, _| {
                s.pending_partial_withdrawals
                    .push(PendingPartialWithdrawal {
                        validator_index: 1,
                        amount: 1,
                        withdrawable_epoch: 0,
                    })
                    .unwrap()
            }),
            ("unknown source", &|_, r| r.source_pubkey = [0xff; 48]),
            ("unknown target", &|_, r| r.target_pubkey = [0xff; 48]),
        ];
        for (name, change) in cases {
            let mut state = state();
            let mut request = request(key(1), key(2));
            change(&mut state, &mut request);
            let before = state_root(&mut state).unwrap();
            assert_eq!(process(&mut state, &request), Ok(()), "{name}");
            assert_eq!(state_root(&mut state).unwrap(), before, "{name}");
        }

        // 8 validators: a consolidation churn of 256 ETH / 32 = 8 ETH, which is not above
        // MIN_ACTIVATION_BALANCE.
        let mut low_churn = state_of(8);
        let before = state_root(&mut low_churn).unwrap();
        assert_eq!(process(&mut low_churn, &request(key(1), key(2))), Ok(()));
        assert_eq!(state_root(&mut low_churn).unwrap(), before);
    }
}
