//! Voluntary exits and BLS-to-execution changes: `process_voluntary_exit` (E L1838-1859,
//! Modified in Electra; Gloas keeps it) and `process_bls_to_execution_change` (C L619-640;
//! Gloas keeps it).
//!
//! The functions make the checks that need no BLS. The signature of each operation goes to
//! the backend as a set, in the one batch of [`crate::signatures::block_signature_sets`]
//! ([`crate::signatures::voluntary_exit_signature_set`] and
//! [`crate::signatures::bls_to_execution_change_signature_set`]). A caller that processes
//! one operation outside a block checks its signature first, with
//! [`crate::signatures::verify_voluntary_exit_signature`] or
//! [`crate::signatures::verify_bls_to_execution_change_signature`].
//!
//! Gloas does not change these two functions (`process_operations`, G L2228-2263, calls
//! them as Electra does). A builder exits through a builder exit request of the parent
//! payload ([`crate::per_block::builder::process_builder_exit_request`]), not through a
//! voluntary exit: a `BUILDER_INDEX_FLAG` index is past the validator registry, so it fails
//! with [`StfError::UnknownValidator`].

use crate::accessors::{
    get_current_epoch, get_pending_balance_to_withdraw, hash, is_active_validator,
    TotalActiveBalanceCache,
};
use crate::mutators::{initiate_validator_exit, state_sum};
use crate::preset::{BLS_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX};
use crate::{Preset, StfError};
use consensus_types::common::{SignedBLSToExecutionChange, SignedVoluntaryExit};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::FAR_FUTURE_EPOCH;

/// `process_voluntary_exit` (E L1838-1859, Modified in Electra) without the `bls.Verify`:
/// the asserts on the validator and the exit, then `initiate_validator_exit`. `cache` gives
/// the total active balance of the exit churn.
///
/// The asserts fail before any change to `state`. On a later `Err` (an overflow in the
/// exit churn), `state` is partly updated: the caller drops it.
pub fn process_voluntary_exit<E: Preset>(
    state: &mut BeaconState<E>,
    signed_voluntary_exit: &SignedVoluntaryExit,
    cache: &mut TotalActiveBalanceCache,
) -> Result<(), StfError> {
    let voluntary_exit = &signed_voluntary_exit.message;
    let index = voluntary_exit.validator_index;
    let validator = state
        .validators
        .get(index as usize)
        .ok_or(StfError::UnknownValidator(index))?;
    let current_epoch = get_current_epoch(state);
    // Verify the validator is active
    if !is_active_validator(validator, current_epoch) {
        return Err(StfError::ExitNotActive(index));
    }
    // Verify exit has not been initiated
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Err(StfError::ExitAlreadyInitiated(index));
    }
    // Exits must specify an epoch when they become valid; they are not valid before then
    if current_epoch < voluntary_exit.epoch {
        return Err(StfError::ExitEpochInFuture {
            exit_epoch: voluntary_exit.epoch,
            current_epoch,
        });
    }
    // Verify the validator has been active long enough
    // The activation epoch comes from our own state, not from the exit. An active
    // validator has it at most the current epoch, so the sum does not fail.
    let earliest_epoch = state_sum(
        validator.activation_epoch,
        E::SHARD_COMMITTEE_PERIOD,
        "exit eligibility epoch",
    )?;
    if current_epoch < earliest_epoch {
        return Err(StfError::ExitTooEarly {
            index,
            earliest_epoch,
            current_epoch,
        });
    }
    // Only exit validator if it has no pending withdrawals in the queue
    let pending = get_pending_balance_to_withdraw(state, index)?;
    if pending != 0 {
        return Err(StfError::ExitPendingWithdrawals { index, pending });
    }
    // Initiate exit
    initiate_validator_exit(state, index, cache)
}

/// `process_bls_to_execution_change` (C L619-640) without the `bls.Verify`: the validator
/// has BLS withdrawal credentials of `from_bls_pubkey`, and they become the 0x01
/// credentials of `to_execution_address`.
///
/// On `Err`, `state` did not change.
pub fn process_bls_to_execution_change<E: Preset>(
    state: &mut BeaconState<E>,
    signed_address_change: &SignedBLSToExecutionChange,
) -> Result<(), StfError> {
    let address_change = &signed_address_change.message;
    let index = address_change.validator_index;
    let validator = state
        .validators
        .get_mut(index as usize)
        .ok_or(StfError::UnknownValidator(index))?;
    let credentials = &mut validator.withdrawal_credentials;
    if credentials[0] != BLS_WITHDRAWAL_PREFIX {
        return Err(StfError::NotBlsWithdrawalCredentials(index));
    }
    if credentials[1..] != hash(&[&address_change.from_bls_pubkey])[1..] {
        return Err(StfError::BlsChangeKeyMismatch(index));
    }
    credentials[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    credentials[1..12].fill(0);
    credentials[12..].copy_from_slice(address_change.to_execution_address.as_slice());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::{compute_activation_exit_epoch, hash, TotalActiveBalanceCache};
    use crate::preset::MIN_VALIDATOR_WITHDRAWABILITY_DELAY;
    use crate::state_root;
    use crate::testing::genesis_state;
    use consensus_types::common::{
        BLSToExecutionChange, PendingPartialWithdrawal, SignedBLSToExecutionChange,
        SignedVoluntaryExit, VoluntaryExit,
    };
    use consensus_types::gloas::BeaconState;
    use consensus_types::primitives::{Address, Bytes32, FAR_FUTURE_EPOCH};
    use consensus_types::{EthSpec, Minimal};

    const ETH: u64 = 1_000_000_000;

    /// 64 validators of 32 ETH, active from epoch 0, in epoch `SHARD_COMMITTEE_PERIOD` (64)
    /// of the minimal preset: each validator can exit.
    fn state() -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        state.slot = Minimal::start_slot_at_epoch(64) + 1;
        state
    }

    fn exit(validator_index: u64, epoch: u64) -> SignedVoluntaryExit {
        SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch,
                validator_index,
            },
            signature: [0x33; 96],
        }
    }

    fn process_exit(
        state: &mut BeaconState<Minimal>,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), StfError> {
        process_voluntary_exit(state, exit, &mut TotalActiveBalanceCache::default())
    }

    #[test]
    fn voluntary_exit_starts_the_exit() {
        let mut state = state();
        assert_eq!(process_exit(&mut state, &exit(3, 64)), Ok(()));
        let validator = state.validators.get(3).unwrap();
        let exit_epoch = compute_activation_exit_epoch(64).unwrap();
        assert_eq!(validator.exit_epoch, exit_epoch);
        assert_eq!(
            validator.withdrawable_epoch,
            exit_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY
        );
        assert_eq!(state.earliest_exit_epoch, exit_epoch);
        // An exit of an earlier epoch is valid too.
        assert_eq!(process_exit(&mut state, &exit(4, 0)), Ok(()));
        // The second exit of the same validator fails.
        assert_eq!(
            process_exit(&mut state, &exit(3, 64)),
            Err(StfError::ExitAlreadyInitiated(3))
        );
    }

    #[test]
    fn voluntary_exit_asserts() {
        let state = state();
        let fails = |state: &BeaconState<Minimal>, exit: &SignedVoluntaryExit| {
            let mut post = state.clone();
            let result = process_exit(&mut post, exit);
            // The state does not change before the asserts pass.
            assert_eq!(
                state_root(&mut post).unwrap(),
                state_root(&mut state.clone()).unwrap()
            );
            result
        };
        assert_eq!(
            fails(&state, &exit(64, 64)),
            Err(StfError::UnknownValidator(64))
        );
        assert_eq!(
            fails(&state, &exit(3, 65)),
            Err(StfError::ExitEpochInFuture {
                exit_epoch: 65,
                current_epoch: 64
            })
        );
        let mut not_active = state.clone();
        not_active.validators.get_mut(3).unwrap().activation_epoch = 65;
        assert_eq!(
            fails(&not_active, &exit(3, 64)),
            Err(StfError::ExitNotActive(3))
        );
        let mut exited = state.clone();
        exited.validators.get_mut(3).unwrap().exit_epoch = 70;
        assert_eq!(
            fails(&exited, &exit(3, 64)),
            Err(StfError::ExitAlreadyInitiated(3))
        );
        let mut young = state.clone();
        young.validators.get_mut(3).unwrap().activation_epoch = 1;
        assert_eq!(
            fails(&young, &exit(3, 64)),
            Err(StfError::ExitTooEarly {
                index: 3,
                earliest_epoch: 65,
                current_epoch: 64
            })
        );
        let mut pending = state.clone();
        for (validator_index, amount) in [(3, 5), (4, 9), (3, 6)] {
            pending
                .pending_partial_withdrawals
                .push(PendingPartialWithdrawal {
                    validator_index,
                    amount,
                    withdrawable_epoch: 0,
                })
                .unwrap();
        }
        assert_eq!(
            fails(&pending, &exit(3, 64)),
            Err(StfError::ExitPendingWithdrawals {
                index: 3,
                pending: 11
            })
        );
    }

    /// The BLS withdrawal credentials of `pubkey`: `BLS_WITHDRAWAL_PREFIX + sha256(pubkey)[1:]`.
    fn bls_credentials(pubkey: &[u8; 48]) -> Bytes32 {
        let mut credentials = Bytes32::from(hash(&[pubkey]));
        credentials[0] = 0x00;
        credentials
    }

    fn change(validator_index: u64, from_bls_pubkey: [u8; 48]) -> SignedBLSToExecutionChange {
        SignedBLSToExecutionChange {
            message: BLSToExecutionChange {
                validator_index,
                from_bls_pubkey,
                to_execution_address: Address::repeat_byte(0xee),
            },
            signature: [0x44; 96],
        }
    }

    #[test]
    fn bls_change_sets_the_eth1_credentials() {
        let mut state = state();
        let key = [0x77; 48];
        state.validators.get_mut(5).unwrap().withdrawal_credentials = bls_credentials(&key);
        assert_eq!(
            process_bls_to_execution_change(&mut state, &change(5, key)),
            Ok(())
        );
        let mut want = Bytes32::ZERO;
        want[0] = 0x01;
        want[12..].fill(0xee);
        assert_eq!(
            state.validators.get(5).unwrap().withdrawal_credentials,
            want
        );
        // The validator has 0x01 credentials now, so a second change fails.
        assert_eq!(
            process_bls_to_execution_change(&mut state, &change(5, key)),
            Err(StfError::NotBlsWithdrawalCredentials(5))
        );
        assert_eq!(
            state.validators.get(5).unwrap().exit_epoch,
            FAR_FUTURE_EPOCH
        );
    }

    #[test]
    fn bls_change_asserts() {
        let mut state = state();
        let key = [0x77; 48];
        state.validators.get_mut(5).unwrap().withdrawal_credentials = bls_credentials(&key);
        let before = state_root(&mut state).unwrap();
        assert_eq!(
            process_bls_to_execution_change(&mut state, &change(64, key)),
            Err(StfError::UnknownValidator(64))
        );
        // Another key than the key of the credentials.
        assert_eq!(
            process_bls_to_execution_change(&mut state, &change(5, [0x78; 48])),
            Err(StfError::BlsChangeKeyMismatch(5))
        );
        // The first byte of the hash is not compared: only the prefix is in its place.
        let mut other_first_byte = state.clone();
        other_first_byte
            .validators
            .get_mut(5)
            .unwrap()
            .withdrawal_credentials[0] = 0x02;
        assert_eq!(
            process_bls_to_execution_change(&mut other_first_byte, &change(5, key)),
            Err(StfError::NotBlsWithdrawalCredentials(5))
        );
        assert_eq!(state_root(&mut state).unwrap(), before);
    }
}
