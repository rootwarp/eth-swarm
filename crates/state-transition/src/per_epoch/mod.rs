//! Epoch processing (`process_epoch`, G L1633-1653).
//!
//! - [`justification`] holds `process_justification_and_finalization`.
//! - [`inactivity`] holds `process_inactivity_updates`.
//! - [`rewards`] holds `process_rewards_and_penalties` and its delta functions.
//! - [`participation`] holds the accessors and the one-pass participation cache they share.
//!
//! The steps after `process_rewards_and_penalties` are not ported yet.

pub mod inactivity;
pub mod justification;
#[cfg(test)]
mod literal;
pub mod participation;
pub mod rewards;

pub use inactivity::process_inactivity_updates;
pub use justification::{
    process_justification_and_finalization, weigh_justification_and_finalization,
};
pub use participation::get_unslashed_participating_indices;
pub use rewards::{
    get_flag_index_deltas, get_inactivity_penalty_deltas, process_rewards_and_penalties,
};

use crate::accessors::TotalActiveBalanceCache;
use crate::{Preset, StfError};
use consensus_types::gloas::BeaconState;
use participation::ParticipationCache;

/// `process_epoch` (G L1633-1653, Modified in Gloas). The justification, inactivity and
/// reward steps run in the spec order, over one `ParticipationCache`. Then the call
/// returns [`StfError::Unimplemented`] at `process_registry_updates`, so `process_slots`
/// still stops at the first epoch boundary.
pub fn process_epoch<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    // One total-balance cache for the epoch boundary. The later steps can share it only up
    // to `process_effective_balance_updates`: see the limits in the rustdoc of
    // `TotalActiveBalanceCache`.
    let mut totals = TotalActiveBalanceCache::default();
    let participation = ParticipationCache::new(state, &mut totals);
    justification::process_justification_and_finalization_with(state, &participation)?;
    inactivity::process_inactivity_updates_with(state, &participation)?;
    rewards::process_rewards_and_penalties_with(state, &participation)?;
    // process_registry_updates and every later step.
    Err(StfError::Unimplemented("4.2b/4.6b"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::genesis_state;
    use consensus_types::{EthSpec, Minimal};

    #[test]
    fn process_epoch_is_a_stub() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        assert_eq!(
            process_epoch(&mut state),
            Err(StfError::Unimplemented("4.2b/4.6b"))
        );
    }

    #[test]
    fn process_epoch_runs_the_ported_steps_first() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        state.slot = Minimal::start_slot_at_epoch(5) - 1;
        for i in 0..8 {
            *state.previous_epoch_participation.get_mut(i).unwrap() = 0b111;
            *state.current_epoch_participation.get_mut(i).unwrap() = 0b011;
        }
        let mut want = state.clone();
        process_justification_and_finalization(&mut want).unwrap();
        process_inactivity_updates(&mut want).unwrap();
        process_rewards_and_penalties(&mut want).unwrap();
        assert_ne!(want.balances, state.balances);
        assert_eq!(
            process_epoch(&mut state),
            Err(StfError::Unimplemented("4.2b/4.6b"))
        );
        assert_eq!(state, want);
    }
}
