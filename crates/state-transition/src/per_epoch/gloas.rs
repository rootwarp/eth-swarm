//! The Gloas steps at the end of the epoch: the builder payments (G L1719-1731), the Fulu
//! proposer lookahead (Fu L481-489) and the PTC window (G L1737-1748).

use crate::accessors::{get_current_epoch, TotalActiveBalanceCache};
use crate::caches::{compute_ptc_with, get_beacon_proposer_indices, CommitteeCache};
use crate::mutators::empty_payment;
use crate::preset::{
    BUILDER_PAYMENT_THRESHOLD_DENOMINATOR, BUILDER_PAYMENT_THRESHOLD_NUMERATOR, MIN_SEED_LOOKAHEAD,
};
use crate::{Preset, StfError};
use consensus_types::gloas::{BeaconState, PayloadTimelinessCommittee};
use consensus_types::primitives::{Epoch, Gwei};
use milhouse::Vector;

/// `get_builder_payment_quorum_threshold` (G L1433-1439, New in Gloas) for a total active
/// balance of `total_active_balance`: 6/10 of the balance of one slot.
///
/// The slot balance is at most `u64::MAX / SLOTS_PER_EPOCH`, and both presets have 8 or more
/// slots in an epoch, so the `Uint64` product of the spec cannot overflow. The product is
/// in `u128` here, so the function does not depend on that preset value. The quotient is
/// less than the slot balance, so it fits in a `u64`.
pub fn builder_payment_quorum_threshold<E: Preset>(total_active_balance: Gwei) -> Gwei {
    let per_slot_balance = total_active_balance / E::slots_per_epoch();
    let quorum = u128::from(per_slot_balance) * u128::from(BUILDER_PAYMENT_THRESHOLD_NUMERATOR);
    (quorum / u128::from(BUILDER_PAYMENT_THRESHOLD_DENOMINATOR)) as Gwei
}

/// `get_builder_payment_quorum_threshold` (G L1433-1439, New in Gloas), with the total from
/// `cache`.
pub fn get_builder_payment_quorum_threshold<E: Preset>(
    state: &BeaconState<E>,
    cache: &mut TotalActiveBalanceCache,
) -> Result<Gwei, StfError> {
    Ok(builder_payment_quorum_threshold::<E>(cache.get(state)?))
}

/// `process_builder_pending_payments` (G L1719-1731, New in Gloas): each payment of the
/// previous epoch (the first `SLOTS_PER_EPOCH` entries) with a weight at the quorum or above
/// becomes a pending builder withdrawal. Then the payments of the current epoch move to the
/// first half, and the second half is empty. A payment below the quorum is dropped.
pub fn process_builder_pending_payments<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    process_builder_pending_payments_with(state, &mut TotalActiveBalanceCache::default())
}

/// [`process_builder_pending_payments`] with the total active balance from `totals`.
///
/// On `Err`, `state` is partly updated: the caller drops it.
pub(crate) fn process_builder_pending_payments_with<E: Preset>(
    state: &mut BeaconState<E>,
    totals: &mut TotalActiveBalanceCache,
) -> Result<(), StfError> {
    let spe = E::slots_per_epoch() as usize;
    let quorum = get_builder_payment_quorum_threshold(state, totals)?;
    let payments = state.builder_pending_payments.to_vec();
    for payment in payments.iter().take(spe) {
        if payment.weight >= quorum {
            // `BuilderPendingWithdrawals` has no limit, so the append of the spec cannot
            // fail. milhouse fails only at a length of `usize::MAX`: `StfError::Tree`.
            state
                .builder_pending_withdrawals
                .push(payment.withdrawal.clone())?;
        }
    }
    let new_payments = vec![empty_payment(); spe];
    state.builder_pending_payments = Vector::new(shift_window(payments, spe, new_payments))?;
    Ok(())
}

/// `get_current_epoch(state) + MIN_SEED_LOOKAHEAD + 1`: the epoch that the step adds to its
/// window.
fn last_window_epoch<E: Preset>(state: &BeaconState<E>) -> Result<Epoch, StfError> {
    // Kept a proof: unreachable, an epoch is at most `u64::MAX / SLOTS_PER_EPOCH`.
    get_current_epoch(state)
        .checked_add(MIN_SEED_LOOKAHEAD + 1)
        .ok_or(StfError::ArithmeticOverflow)
}

/// The window `old` without its first epoch of `spe` entries, and then `last_epoch`.
fn shift_window<T>(old: Vec<T>, spe: usize, last_epoch: Vec<T>) -> Vec<T> {
    old.into_iter().skip(spe).chain(last_epoch).collect()
}

/// `process_proposer_lookahead` (Fu L481-489, New in Fulu; Gloas keeps it): shifts out the
/// proposers of the first epoch and appends the proposers of the next epoch past the window.
pub fn process_proposer_lookahead<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    let spe = E::slots_per_epoch() as usize;
    let last_epoch = last_window_epoch(state)?;
    // `compute_proposer_indices` reads the slots of `last_epoch`. The epoch comes from the
    // slot of our own state, so a slot past `u64::MAX` is `StateArithmetic`, not a proof.
    // The check runs here, so a caller with the epoch of an object still gets a proof.
    last_epoch
        .checked_mul(E::slots_per_epoch())
        .and_then(|start| start.checked_add(E::slots_per_epoch() - 1))
        .ok_or(StfError::StateArithmetic {
            what: "proposer lookahead slot",
        })?;
    // Fill in the last epoch with new proposer indices
    let last_epoch_proposers = get_beacon_proposer_indices(state, last_epoch)?;
    // Shift out proposers in the first epoch
    let lookahead = shift_window(state.proposer_lookahead.to_vec(), spe, last_epoch_proposers);
    state.proposer_lookahead = Vector::new(lookahead)?;
    Ok(())
}

/// `process_ptc_window` (G L1737-1748, New in Gloas): shifts the PTC window one epoch
/// forward and fills its last epoch with `compute_ptc`. The committees of that epoch come
/// from one [`CommitteeCache`].
pub fn process_ptc_window<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    let spe = E::slots_per_epoch();
    // Fill in the last epoch
    let next_epoch = last_window_epoch(state)?;
    let cache = CommitteeCache::new(state, next_epoch)?;
    // The epoch comes from the slot of our own state, so a slot past `u64::MAX` is
    // `StateArithmetic`, not a proof.
    let window_slot = || StfError::StateArithmetic {
        what: "PTC window slot",
    };
    let start_slot = next_epoch.checked_mul(spe).ok_or_else(window_slot)?;
    let end_slot = start_slot.checked_add(spe).ok_or_else(window_slot)?;
    let last_epoch = (start_slot..end_slot)
        .map(|slot| {
            PayloadTimelinessCommittee::<E>::new(compute_ptc_with(state, &cache, slot)?)
                .map_err(|e| StfError::Tree(format!("PTC length: {e:?}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Shift all epochs forward by one
    let window = shift_window(state.ptc_window.to_vec(), spe as usize, last_epoch);
    state.ptc_window = Vector::new(window)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::TotalActiveBalanceCache;
    use crate::caches::{compute_ptc, get_beacon_proposer_indices};
    use crate::mutators::empty_payment;
    use crate::testing::genesis_state_with_mix;
    use consensus_types::gloas::BeaconState;
    use consensus_types::gloas::{BuilderPendingPayment, BuilderPendingWithdrawal};
    use consensus_types::primitives::{Address, Bytes32, Gwei};
    use consensus_types::{EthSpec, Mainnet, Minimal};

    /// A minimal state of 64 validators at the last slot of epoch 3, with the lookahead and
    /// the window of that epoch. Each epoch has another RANDAO mix, so each epoch has other
    /// proposers and PTCs.
    fn state() -> BeaconState<Minimal> {
        let mut state = genesis_state_with_mix::<Minimal>(&[32_000_000_000; 64], Bytes32::ZERO);
        for i in 0..64 {
            *state.randao_mixes.get_mut(i).unwrap() = Bytes32::repeat_byte(i as u8);
        }
        state.slot = Minimal::start_slot_at_epoch(4) - 1;
        crate::testing::refresh_lookahead(&mut state);
        state
    }

    #[test]
    fn proposer_lookahead_shifts_one_epoch() {
        let spe = Minimal::slots_per_epoch() as usize;
        let mut state = state();
        let pre = state.proposer_lookahead.to_vec();
        process_proposer_lookahead(&mut state).unwrap();
        let post = state.proposer_lookahead.to_vec();
        assert_eq!(post[..spe], pre[spe..]);
        // The current epoch is 3, so the new last epoch is 3 + MIN_SEED_LOOKAHEAD + 1.
        assert_eq!(post[spe..], get_beacon_proposer_indices(&state, 5).unwrap());
        assert_ne!(post[spe..], pre[spe..]);
    }

    #[test]
    fn proposer_lookahead_slots_past_u64_are_not_a_proof() {
        // The slot of our own state puts the start slot of the new lookahead epoch past
        // `u64::MAX`.
        let mut state = state();
        state.slot = u64::MAX;
        let err = process_proposer_lookahead(&mut state).unwrap_err();
        assert_eq!(
            err,
            StfError::StateArithmetic {
                what: "proposer lookahead slot"
            }
        );
        assert!(!err.proves_invalid());
    }

    #[test]
    fn ptc_window_slots_past_u64_are_not_a_proof() {
        // The slot of our own state puts the start slot of the new window epoch past
        // `u64::MAX`, or its end slot one epoch further.
        let spe = Minimal::slots_per_epoch();
        let window_slot = StfError::StateArithmetic {
            what: "PTC window slot",
        };
        for slot in [u64::MAX, (u64::MAX / spe - 2) * spe] {
            let mut state = state();
            state.slot = slot;
            let err = process_ptc_window(&mut state).unwrap_err();
            assert_eq!(err, window_slot, "{slot}");
            assert!(!err.proves_invalid());
        }
    }

    #[test]
    fn ptc_window_shifts_one_epoch() {
        let spe = Minimal::slots_per_epoch() as usize;
        let mut state = state();
        let pre = state.ptc_window.to_vec();
        process_ptc_window(&mut state).unwrap();
        let post = state.ptc_window.to_vec();
        assert_eq!(post[..2 * spe], pre[spe..]);
        let start = Minimal::start_slot_at_epoch(5);
        let want: Vec<Vec<u64>> = (start..start + spe as u64)
            .map(|slot| compute_ptc(&state, slot).unwrap())
            .collect();
        let got: Vec<Vec<u64>> = post[2 * spe..].iter().map(|ptc| ptc.to_vec()).collect();
        assert_eq!(got, want);
        assert_ne!(post[2 * spe..], pre[2 * spe..]);
    }

    const ETH: Gwei = 1_000_000_000;

    /// A payment of `amount` to builder `builder_index` with `weight`, from proposer 3.
    fn payment(weight: Gwei, amount: Gwei, builder_index: u64) -> BuilderPendingPayment {
        BuilderPendingPayment {
            weight,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: Address::repeat_byte(0xfe),
                amount,
                builder_index,
            },
            proposer_index: 3,
        }
    }

    /// A minimal state of 64 validators of 32 ETH: a total active balance of 2048 ETH, so
    /// 256 ETH for each slot and a quorum of 153.6 ETH.
    fn payments_state() -> BeaconState<Minimal> {
        genesis_state_with_mix::<Minimal>(&[32 * ETH; 64], Bytes32::ZERO)
    }

    #[test]
    fn quorum_threshold() {
        // G L1433-1439: the balance of one slot first, then the fraction 6/10.
        let state = payments_state();
        let mut cache = TotalActiveBalanceCache::default();
        assert_eq!(
            get_builder_payment_quorum_threshold(&state, &mut cache),
            Ok(153_600_000_000)
        );
        assert_eq!(cache.key().map(|(epoch, _)| epoch), Some(0));
        // 15 // 8 = 1, and 1 * 6 // 10 = 0. The other order gives 15 * 6 // 10 // 8 = 1.
        assert_eq!(builder_payment_quorum_threshold::<Minimal>(15), 0);
        assert_eq!(builder_payment_quorum_threshold::<Minimal>(16), 1);
        // Mainnet has 32 slots in an epoch.
        assert_eq!(
            builder_payment_quorum_threshold::<Mainnet>(2048 * ETH),
            38_400_000_000
        );
        // The product cannot overflow: the slot balance is at most u64::MAX // 8.
        assert_eq!(
            builder_payment_quorum_threshold::<Minimal>(u64::MAX),
            u64::MAX / 8 * 6 / 10
        );
    }

    #[test]
    fn quorum_boundary() {
        // G L1719-1731: a payment of the previous epoch with a weight at the quorum becomes
        // a pending withdrawal. A weight one Gwei below the quorum drops the payment.
        let spe = Minimal::slots_per_epoch() as usize;
        let quorum = 153_600_000_000;
        let mut state = payments_state();
        let at_quorum = payment(quorum, 9 * ETH, 1);
        let below = payment(quorum - 1, 8 * ETH, 2);
        let current = payment(quorum, 7 * ETH, 3);
        *state.builder_pending_payments.get_mut(2).unwrap() = at_quorum.clone();
        *state.builder_pending_payments.get_mut(5).unwrap() = below;
        *state.builder_pending_payments.get_mut(spe + 4).unwrap() = current.clone();
        assert_eq!(process_builder_pending_payments(&mut state), Ok(()));
        assert_eq!(
            state.builder_pending_withdrawals.to_vec(),
            vec![at_quorum.withdrawal]
        );
        // The payments of the current epoch move to the first half, and the second half is
        // empty. The payment below the quorum is gone.
        let mut want = vec![empty_payment(); 2 * spe];
        want[4] = current;
        assert_eq!(state.builder_pending_payments.to_vec(), want);
    }

    #[test]
    fn quorum_ignores_the_amount_and_the_current_epoch() {
        // The step reads the weight only: a payment with no amount at the quorum also
        // becomes a withdrawal (of 0 Gwei), as in the spec. A payment of the current epoch
        // above the quorum is not paid in this epoch.
        let spe = Minimal::slots_per_epoch() as usize;
        let quorum = 153_600_000_000;
        let mut state = payments_state();
        let no_amount = payment(quorum, 0, 1);
        *state.builder_pending_payments.get_mut(0).unwrap() = no_amount.clone();
        *state.builder_pending_payments.get_mut(spe).unwrap() = payment(u64::MAX, ETH, 2);
        process_builder_pending_payments(&mut state).unwrap();
        assert_eq!(
            state.builder_pending_withdrawals.to_vec(),
            vec![no_amount.withdrawal]
        );
        assert_eq!(
            state.builder_pending_payments.get(0),
            Some(&payment(u64::MAX, ETH, 2))
        );
        // The next epoch pays it.
        process_builder_pending_payments(&mut state).unwrap();
        assert_eq!(state.builder_pending_withdrawals.len(), 2);
        assert!(state
            .builder_pending_payments
            .iter()
            .all(|p| *p == empty_payment()));
    }

    #[test]
    fn empty_payments_pay_nothing() {
        // The weight of an empty payment (0) is below every quorum, also the smallest one.
        let mut state = payments_state();
        let before = state.builder_pending_payments.to_vec();
        process_builder_pending_payments(&mut state).unwrap();
        assert!(state.builder_pending_withdrawals.is_empty());
        assert_eq!(state.builder_pending_payments.to_vec(), before);
    }
}
