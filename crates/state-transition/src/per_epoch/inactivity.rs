//! Inactivity scores (A L754-771).

use super::participation::{is_in_inactivity_leak, ParticipationCache};
use crate::accessors::{get_current_epoch, has_flag};
use crate::mutators::state_sum;
use crate::preset::{
    GENESIS_EPOCH, INACTIVITY_SCORE_BIAS, INACTIVITY_SCORE_RECOVERY_RATE, TIMELY_TARGET_FLAG_INDEX,
};
use crate::{Preset, StfError};
use consensus_types::gloas::BeaconState;

/// The `what` of `inactivity_score + INACTIVITY_SCORE_BIAS`. The score comes from our own
/// state, so a failed sum is `StateArithmetic`, not a proof.
pub(crate) const INACTIVITY_SCORE: &str = "inactivity score";

/// `process_inactivity_updates` (A L754-771, New in Altair; Gloas keeps it).
pub fn process_inactivity_updates<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    if get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(());
    }
    let participation = ParticipationCache::of(state);
    process_inactivity_updates_with(state, &participation)
}

/// [`process_inactivity_updates`] with the participation of `participation`, which must be
/// the cache of `state` at this epoch boundary.
pub(crate) fn process_inactivity_updates_with<E: Preset>(
    state: &mut BeaconState<E>,
    participation: &ParticipationCache,
) -> Result<(), StfError> {
    // Skip the genesis epoch as score updates are based on the previous epoch participation
    if get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(());
    }
    if !participation.any_eligible() {
        return Ok(());
    }
    // The spec reads the participation, the score and then the leak status inside the loop.
    // Thus each can fail only when there is an eligible validator, and the first failure in
    // that order is the error.
    participation.previous_participation()?;
    let leaking = is_in_inactivity_leak(state);
    for (index, v) in participation.validators.iter().enumerate() {
        if !v.eligible {
            continue;
        }
        let score =
            state
                .inactivity_scores
                .get_mut(index)
                .ok_or(StfError::ListIndexOutOfRange {
                    list: "inactivity_scores",
                    index: index as u64,
                })?;
        // Increase the inactivity score of inactive validators
        if has_flag(v.previous_flags, TIMELY_TARGET_FLAG_INDEX)? {
            *score = score.saturating_sub(1);
        } else {
            *score = state_sum(*score, INACTIVITY_SCORE_BIAS, INACTIVITY_SCORE)?;
        }
        // Decrease the inactivity score of all eligible validators during a leak-free epoch
        if !leaking.clone()? {
            *score = score.saturating_sub(INACTIVITY_SCORE_RECOVERY_RATE);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::registry_state;
    use consensus_types::primitives::Gwei;
    use consensus_types::{EthSpec, Minimal};

    const ETH: Gwei = 1_000_000_000;

    /// 4 validators at the last slot of `epoch`, finalized at `finalized`. Validators 0 and 1
    /// hit the previous target, and the scores are 0, 20, 0 and 20.
    fn state(epoch: u64, finalized: u64) -> BeaconState<Minimal> {
        let mut state = registry_state::<Minimal>(&[32 * ETH; 4], Default::default());
        state.slot = Minimal::start_slot_at_epoch(epoch + 1) - 1;
        state.finalized_checkpoint.epoch = finalized;
        for i in 0..4 {
            *state.inactivity_scores.get_mut(i).unwrap() = [0, 20, 0, 20][i];
        }
        for i in 0..2 {
            *state.previous_epoch_participation.get_mut(i).unwrap() = 0b010;
        }
        state
    }

    fn scores(state: &BeaconState<Minimal>) -> Vec<u64> {
        state.inactivity_scores.to_vec()
    }

    #[test]
    fn scores_rise_without_target_and_recover_without_leak() {
        let mut leaking = state(9, 0);
        process_inactivity_updates(&mut leaking).unwrap();
        assert_eq!(scores(&leaking), [0, 19, 4, 24]);
        let mut finalizing = state(9, 7);
        process_inactivity_updates(&mut finalizing).unwrap();
        assert_eq!(scores(&finalizing), [0, 3, 0, 8]);
        let mut genesis = state(0, 0);
        process_inactivity_updates(&mut genesis).unwrap();
        assert_eq!(scores(&genesis), [0, 20, 0, 20]);
    }

    #[test]
    fn invalid_states_fail() {
        let mut overflow = state(9, 0);
        *overflow.inactivity_scores.get_mut(3).unwrap() = u64::MAX;
        // The score comes from our own state, so its overflow is not a proof.
        let err = process_inactivity_updates(&mut overflow).unwrap_err();
        assert_eq!(
            err,
            StfError::StateArithmetic {
                what: "inactivity score"
            }
        );
        assert!(!err.proves_invalid());
        let mut short = state(9, 0);
        short.inactivity_scores = milhouse::ProgressiveList::default();
        assert_eq!(
            process_inactivity_updates(&mut short),
            Err(StfError::ListIndexOutOfRange {
                list: "inactivity_scores",
                index: 0
            })
        );
        // The spec reads the score before the leak check: an empty score list fails with
        // its index even when the leak check would overflow too.
        let mut both = state(9, 9);
        both.inactivity_scores = milhouse::ProgressiveList::default();
        assert_eq!(
            process_inactivity_updates(&mut both),
            Err(StfError::ListIndexOutOfRange {
                list: "inactivity_scores",
                index: 0
            })
        );
        // The finalized epoch is after the previous epoch: a fault of our own state.
        let mut future = state(9, 9);
        assert_eq!(
            process_inactivity_updates(&mut future),
            Err(StfError::StateArithmetic {
                what: "finality delay"
            })
        );
        // Without an eligible validator the loop body, and thus the leak check, never runs.
        for i in 0..4 {
            future.validators.get_mut(i).unwrap().exit_epoch = 0;
        }
        assert_eq!(process_inactivity_updates(&mut future), Ok(()));
    }
}
