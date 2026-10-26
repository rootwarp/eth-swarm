//! The participation accounting that the justification, inactivity and reward steps share:
//! the epoch accessors of Altair and phase0 and `ParticipationCache`, one pass over the
//! registry for each epoch boundary. The accessors that block processing also reads
//! (`get_block_root`, `has_flag`, `get_base_reward` and the other ones) are in
//! [`crate::accessors`].

use crate::accessors::{
    get_active_validator_indices, get_current_epoch, get_previous_epoch, has_flag,
    is_active_validator, TotalActiveBalanceCache,
};
use crate::mutators::state_sum;
use crate::preset::{
    EFFECTIVE_BALANCE_INCREMENT, MIN_EPOCHS_TO_INACTIVITY_PENALTY, TIMELY_TARGET_FLAG_INDEX,
};
use crate::{Preset, StfError};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Epoch, Gwei, ParticipationFlags, ValidatorIndex};
use std::collections::BTreeSet;

/// The `what` of a failed `get_total_balance` sum.
const TOTAL_BALANCE: &str = "total balance";

/// `get_total_balance` (P0 L1559-1570). The spec gives it only indices from the registry
/// of `state`, so an index past the registry is a fault of our own state
/// (`ListIndexOutOfRange`), not a proof. The effective balances also come from our own
/// state, so a failed sum is [`StfError::StateArithmetic`], not a proof.
pub fn get_total_balance<E: Preset>(
    state: &BeaconState<E>,
    indices: &BTreeSet<ValidatorIndex>,
) -> Result<Gwei, StfError> {
    let mut sum: Gwei = 0;
    for &index in indices {
        let validator = super::state_validator(state, index)?;
        sum = state_sum(sum, validator.effective_balance, TOTAL_BALANCE)?;
    }
    Ok(sum.max(EFFECTIVE_BALANCE_INCREMENT))
}

/// `get_unslashed_participating_indices` (A L397-414): the active, unslashed validators of
/// `epoch` with `flag_index` set. `epoch` must be the previous or the current epoch.
pub fn get_unslashed_participating_indices<E: Preset>(
    state: &BeaconState<E>,
    flag_index: usize,
    epoch: Epoch,
) -> Result<BTreeSet<ValidatorIndex>, StfError> {
    let current_epoch = get_current_epoch(state);
    if epoch != get_previous_epoch(state) && epoch != current_epoch {
        return Err(StfError::ParticipationEpochOutOfRange {
            epoch,
            state_epoch: current_epoch,
        });
    }
    let (epoch_participation, list) = participation_of(state, epoch);
    let mut output = BTreeSet::new();
    for index in get_active_validator_indices(state, epoch) {
        let flags = epoch_participation
            .get(index as usize)
            .ok_or(StfError::ListIndexOutOfRange { list, index })?;
        if has_flag(*flags, flag_index)? {
            output.insert(index);
        }
    }
    output.retain(|&index| {
        state
            .validators
            .get(index as usize)
            .is_some_and(|v| !v.slashed)
    });
    Ok(output)
}

/// The participation list that `get_unslashed_participating_indices` reads for `epoch`, and
/// its name.
fn participation_of<E: Preset>(
    state: &BeaconState<E>,
    epoch: Epoch,
) -> (&milhouse::ProgressiveList<ParticipationFlags>, &'static str) {
    if epoch == get_current_epoch(state) {
        (
            &state.current_epoch_participation,
            "current_epoch_participation",
        )
    } else {
        (
            &state.previous_epoch_participation,
            "previous_epoch_participation",
        )
    }
}

/// Whether `get_eligible_validator_indices` (P0 L2037-2044) holds `validator`.
fn is_eligible(validator: &consensus_types::common::Validator, previous_epoch: Epoch) -> bool {
    // `previous_epoch` is at most `u64::MAX / SLOTS_PER_EPOCH`, so `+ 1` cannot overflow.
    is_active_validator(validator, previous_epoch)
        || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)
}

/// `get_eligible_validator_indices` (P0 L2037-2044).
pub fn get_eligible_validator_indices<E: Preset>(state: &BeaconState<E>) -> Vec<ValidatorIndex> {
    let previous_epoch = get_previous_epoch(state);
    state
        .validators
        .iter()
        .enumerate()
        .filter(|(_, v)| is_eligible(v, previous_epoch))
        .map(|(i, _)| i as ValidatorIndex)
        .collect()
}

/// `get_finality_delay` (P0 L2027-2028). Both epochs come from our own state, so a
/// finalized epoch past the previous epoch is [`StfError::StateArithmetic`], not a proof.
pub fn get_finality_delay<E: Preset>(state: &BeaconState<E>) -> Result<Epoch, StfError> {
    get_previous_epoch(state)
        .checked_sub(state.finalized_checkpoint.epoch)
        .ok_or(StfError::StateArithmetic {
            what: "finality delay",
        })
}

/// `is_in_inactivity_leak` (P0 L2032-2033).
pub fn is_in_inactivity_leak<E: Preset>(state: &BeaconState<E>) -> Result<bool, StfError> {
    Ok(get_finality_delay(state)? > MIN_EPOCHS_TO_INACTIVITY_PENALTY)
}

/// What the epoch steps need of one validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValidatorParticipation {
    /// `validator.effective_balance`.
    pub(crate) effective_balance: Gwei,
    /// In `get_eligible_validator_indices(state)`.
    pub(crate) eligible: bool,
    /// Bit `f` is set if the validator is in
    /// `get_unslashed_participating_indices(state, f, previous_epoch)`.
    pub(crate) previous_flags: ParticipationFlags,
}

/// One pass over the registry and the participation lists at an epoch boundary. It gives
/// every value that `get_unslashed_participating_indices`, `get_total_balance` and
/// `get_eligible_validator_indices` give the justification, inactivity and reward steps.
///
/// Those steps change only the checkpoints, the justification bits, `inactivity_scores` and
/// `balances`. Thus one cache, built before the first step, stays valid for all three.
///
/// A value that the spec cannot compute (a participation list shorter than the registry, a
/// sum that overflows) is kept as its error. A step gets the error only where the spec
/// computes the value, so a step that the spec skips does not fail.
#[derive(Debug, Clone)]
pub(crate) struct ParticipationCache {
    /// One entry for each validator, in registry order.
    pub(crate) validators: Vec<ValidatorParticipation>,
    /// The previous-epoch flags of [`Self::validators`] are valid only if this is `Ok`.
    previous_participation: Result<(), StfError>,
    /// `Ok` if `current_epoch_participation` holds every validator that is active in the
    /// current epoch.
    current_participation: Result<(), StfError>,
    /// `get_total_balance` of the previous-epoch participants of each flag.
    previous_flag_balances: [Result<Gwei, StfError>; 3],
    /// `get_total_balance` of the current-epoch participants of the target flag.
    current_target_balance: Result<Gwei, StfError>,
    /// `get_total_active_balance(state)`.
    total_active_balance: Result<Gwei, StfError>,
}

impl ParticipationCache {
    /// Reads `state` once. The total active balance comes from `totals`, so the later
    /// epoch steps can read it again without a pass over the registry.
    pub(crate) fn new<E: Preset>(
        state: &BeaconState<E>,
        totals: &mut TotalActiveBalanceCache,
    ) -> Self {
        let current_epoch = get_current_epoch(state);
        let previous_epoch = get_previous_epoch(state);
        let (previous_list, previous_name) = participation_of(state, previous_epoch);
        let mut validators = Vec::with_capacity(state.validators.len());
        let mut previous_participation = Ok(());
        let mut current_participation = Ok(());
        let mut previous_sums = [Some(0u64); 3];
        let mut current_target_sum = Some(0u64);
        for (i, v) in state.validators.iter().enumerate() {
            let index = i as ValidatorIndex;
            let mut previous_flags = 0;
            if is_active_validator(v, previous_epoch) {
                match previous_list.get(i) {
                    Some(&flags) if !v.slashed => previous_flags = flags & 0b111,
                    Some(_) => {}
                    None => {
                        previous_participation =
                            previous_participation.and(Err(StfError::ListIndexOutOfRange {
                                list: previous_name,
                                index,
                            }))
                    }
                }
            }
            if is_active_validator(v, current_epoch) {
                match state.current_epoch_participation.get(i) {
                    Some(&flags)
                        if !v.slashed && has_flag(flags, TIMELY_TARGET_FLAG_INDEX) == Ok(true) =>
                    {
                        current_target_sum =
                            current_target_sum.and_then(|s| s.checked_add(v.effective_balance));
                    }
                    Some(_) => {}
                    None => {
                        current_participation =
                            current_participation.and(Err(StfError::ListIndexOutOfRange {
                                list: "current_epoch_participation",
                                index,
                            }))
                    }
                }
            }
            for (flag, sum) in previous_sums.iter_mut().enumerate() {
                // `flag` is 0, 1 or 2, so `has_flag` cannot fail.
                if has_flag(previous_flags, flag) == Ok(true) {
                    *sum = sum.and_then(|s| s.checked_add(v.effective_balance));
                }
            }
            validators.push(ValidatorParticipation {
                effective_balance: v.effective_balance,
                eligible: is_eligible(v, previous_epoch),
                previous_flags,
            });
        }
        // The same sum as `get_total_balance`, so the same class.
        let total = |sum: Option<Gwei>| {
            sum.map(|s| s.max(EFFECTIVE_BALANCE_INCREMENT))
                .ok_or(StfError::StateArithmetic {
                    what: TOTAL_BALANCE,
                })
        };
        let previous_flag_balances =
            previous_sums.map(|sum| previous_participation.clone().and(total(sum)));
        Self {
            validators,
            previous_flag_balances,
            current_target_balance: current_participation.clone().and(total(current_target_sum)),
            previous_participation,
            current_participation,
            total_active_balance: totals.get(state),
        }
    }

    /// [`Self::new`] with a new total-balance cache, for a step that runs alone.
    pub(crate) fn of<E: Preset>(state: &BeaconState<E>) -> Self {
        Self::new(state, &mut TotalActiveBalanceCache::default())
    }

    /// `Ok` if the previous-epoch flags of [`Self::validators`] are valid.
    pub(crate) fn previous_participation(&self) -> Result<(), StfError> {
        self.previous_participation.clone()
    }

    /// `Ok` if `get_unslashed_participating_indices(state, f, current_epoch)` can read
    /// `current_epoch_participation` for each active validator.
    pub(crate) fn current_participation(&self) -> Result<(), StfError> {
        self.current_participation.clone()
    }

    /// `get_total_balance(state, get_unslashed_participating_indices(state, flag_index,
    /// previous_epoch))`.
    pub(crate) fn previous_flag_balance(&self, flag_index: usize) -> Result<Gwei, StfError> {
        self.previous_flag_balances
            .get(flag_index)
            .cloned()
            .unwrap_or(Err(StfError::ListIndexOutOfRange {
                list: "PARTICIPATION_FLAG_WEIGHTS",
                index: flag_index as u64,
            }))
    }

    /// `get_total_balance(state, get_unslashed_participating_indices(state,
    /// TIMELY_TARGET_FLAG_INDEX, current_epoch))`.
    pub(crate) fn current_target_balance(&self) -> Result<Gwei, StfError> {
        self.current_target_balance.clone()
    }

    /// `get_total_active_balance(state)`.
    pub(crate) fn total_active_balance(&self) -> Result<Gwei, StfError> {
        self.total_active_balance.clone()
    }

    /// Whether `get_eligible_validator_indices(state)` is not empty.
    pub(crate) fn any_eligible(&self) -> bool {
        self.validators.iter().any(|v| v.eligible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preset::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX};
    use crate::testing::genesis_state;
    use consensus_types::{EthSpec, Minimal};

    const ETH: Gwei = 1_000_000_000;

    fn cache_of(state: &BeaconState<Minimal>) -> ParticipationCache {
        ParticipationCache::new(state, &mut TotalActiveBalanceCache::default())
    }

    /// A minimal state at the last slot of `epoch` with 8 validators of 32 ETH.
    fn state_at(epoch: Epoch) -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        state.slot = Minimal::start_slot_at_epoch(epoch + 1) - 1;
        state
    }

    #[test]
    fn total_balance_has_a_floor_of_one_increment() {
        let mut state = state_at(0);
        assert_eq!(get_total_balance(&state, &BTreeSet::new()), Ok(ETH));
        assert_eq!(
            get_total_balance(&state, &BTreeSet::from([0, 7])),
            Ok(64 * ETH)
        );
        // The indices come from our own registry, so an index past it is not a proof.
        let err = get_total_balance(&state, &BTreeSet::from([8])).unwrap_err();
        assert_eq!(
            err,
            StfError::ListIndexOutOfRange {
                list: "validators",
                index: 8
            }
        );
        assert!(!err.proves_invalid());
        assert_eq!(cache_of(&state).total_active_balance(), Ok(256 * ETH));
        state.validators.get_mut(0).unwrap().effective_balance = u64::MAX;
        assert_eq!(
            cache_of(&state).total_active_balance(),
            Err(StfError::StateArithmetic {
                what: "total active balance"
            })
        );
    }

    #[test]
    fn unslashed_participating_indices() {
        let mut state = state_at(3);
        for i in 0..8 {
            *state.previous_epoch_participation.get_mut(i).unwrap() = i as u8;
            *state.current_epoch_participation.get_mut(i).unwrap() = 0b010;
        }
        state.validators.get_mut(3).unwrap().slashed = true;
        state.validators.get_mut(6).unwrap().exit_epoch = 2;
        // Previous epoch 2: flag 1 is set on 2, 3, 6 and 7; 3 is slashed, 6 exited.
        assert_eq!(
            get_unslashed_participating_indices(&state, TIMELY_TARGET_FLAG_INDEX, 2),
            Ok(BTreeSet::from([2, 7]))
        );
        // Current epoch 3: every validator but the slashed and the exited one.
        assert_eq!(
            get_unslashed_participating_indices(&state, TIMELY_TARGET_FLAG_INDEX, 3),
            Ok(BTreeSet::from([0, 1, 2, 4, 5, 7]))
        );
        assert_eq!(
            get_unslashed_participating_indices(&state, TIMELY_TARGET_FLAG_INDEX, 1),
            Err(StfError::ParticipationEpochOutOfRange {
                epoch: 1,
                state_epoch: 3
            })
        );
        let cache = cache_of(&state);
        assert_eq!(
            cache.previous_flag_balance(TIMELY_TARGET_FLAG_INDEX),
            Ok(64 * ETH)
        );
        assert_eq!(
            cache.previous_flag_balance(TIMELY_SOURCE_FLAG_INDEX),
            Ok(96 * ETH)
        );
        assert_eq!(cache.current_target_balance(), Ok(192 * ETH));
        assert_eq!(cache.total_active_balance(), Ok(224 * ETH));
        assert!(matches!(
            cache.previous_flag_balance(3),
            Err(StfError::ListIndexOutOfRange { index: 3, .. })
        ));

        // A participation list shorter than the registry.
        state.previous_epoch_participation = milhouse::ProgressiveList::default();
        assert_eq!(
            get_unslashed_participating_indices(&state, TIMELY_SOURCE_FLAG_INDEX, 2),
            Err(StfError::ListIndexOutOfRange {
                list: "previous_epoch_participation",
                index: 0
            })
        );
        let cache = cache_of(&state);
        assert!(cache.previous_participation().is_err());
        assert!(cache.previous_flag_balance(0).is_err());
        assert_eq!(cache.current_target_balance(), Ok(192 * ETH));
        state.current_epoch_participation = milhouse::ProgressiveList::default();
        assert_eq!(
            cache_of(&state).current_target_balance(),
            Err(StfError::ListIndexOutOfRange {
                list: "current_epoch_participation",
                index: 0
            })
        );
    }

    #[test]
    fn genesis_reads_the_current_participation_for_both_epochs() {
        let mut state = state_at(0);
        *state.current_epoch_participation.get_mut(1).unwrap() = 0b111;
        *state.previous_epoch_participation.get_mut(2).unwrap() = 0b111;
        assert_eq!(get_previous_epoch(&state), 0);
        assert_eq!(
            get_unslashed_participating_indices(&state, TIMELY_HEAD_FLAG_INDEX, 0),
            Ok(BTreeSet::from([1]))
        );
        let cache = cache_of(&state);
        assert_eq!(cache.validators[1].previous_flags, 0b111);
        assert_eq!(cache.validators[2].previous_flags, 0);
    }

    #[test]
    fn eligibility_and_leak() {
        let mut state = state_at(10);
        // Exited before the previous epoch 9; slashed and still before its withdrawable epoch.
        state.validators.get_mut(0).unwrap().exit_epoch = 9;
        let slashed = state.validators.get_mut(1).unwrap();
        slashed.exit_epoch = 9;
        slashed.slashed = true;
        slashed.withdrawable_epoch = 11;
        // Slashed, at its withdrawable epoch: not eligible.
        let done = state.validators.get_mut(2).unwrap();
        done.exit_epoch = 9;
        done.slashed = true;
        done.withdrawable_epoch = 10;
        assert_eq!(get_eligible_validator_indices(&state), [1, 3, 4, 5, 6, 7]);
        assert!(cache_of(&state).any_eligible());

        state.finalized_checkpoint.epoch = 5;
        assert_eq!(get_finality_delay(&state), Ok(4));
        assert_eq!(is_in_inactivity_leak(&state), Ok(false));
        state.finalized_checkpoint.epoch = 4;
        assert_eq!(is_in_inactivity_leak(&state), Ok(true));
        // A finalized epoch past the previous epoch is a fault of our own state.
        state.finalized_checkpoint.epoch = 10;
        let err = is_in_inactivity_leak(&state).unwrap_err();
        assert_eq!(
            err,
            StfError::StateArithmetic {
                what: "finality delay"
            }
        );
        assert!(!err.proves_invalid());
    }

    #[test]
    fn total_balance_sums_are_not_a_proof() {
        // The effective balances come from our own state, so a sum past `u64::MAX` is not
        // a proof.
        let mut state = state_at(3);
        for i in 0..8 {
            *state.previous_epoch_participation.get_mut(i).unwrap() = 0b111;
            *state.current_epoch_participation.get_mut(i).unwrap() = 0b111;
        }
        state.validators.get_mut(0).unwrap().effective_balance = u64::MAX;
        let total_balance = StfError::StateArithmetic {
            what: "total balance",
        };
        let err = get_total_balance(&state, &BTreeSet::from([0, 1])).unwrap_err();
        assert_eq!(err, total_balance);
        assert!(!err.proves_invalid());
        let cache = cache_of(&state);
        for flag in 0..3 {
            assert_eq!(
                cache.previous_flag_balance(flag),
                Err(total_balance.clone())
            );
        }
        assert_eq!(cache.current_target_balance(), Err(total_balance));
    }
}
