//! The window steps at the end of the epoch: the Fulu proposer lookahead (Fu L481-489) and
//! the Gloas PTC window (G L1737-1748). `process_builder_pending_payments` (G L1719-1731)
//! is not ported yet.

use crate::accessors::get_current_epoch;
use crate::caches::{compute_ptc_with, get_beacon_proposer_indices, CommitteeCache};
use crate::preset::MIN_SEED_LOOKAHEAD;
use crate::{Preset, StfError};
use consensus_types::gloas::{BeaconState, PayloadTimelinessCommittee};
use consensus_types::primitives::Epoch;
use milhouse::Vector;

/// `get_current_epoch(state) + MIN_SEED_LOOKAHEAD + 1`: the epoch that the step adds to its
/// window.
fn last_window_epoch<E: Preset>(state: &BeaconState<E>) -> Result<Epoch, StfError> {
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
    // Fill in the last epoch with new proposer indices
    let last_epoch_proposers = get_beacon_proposer_indices(state, last_window_epoch(state)?)?;
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
    let start_slot = next_epoch
        .checked_mul(spe)
        .ok_or(StfError::ArithmeticOverflow)?;
    let end_slot = start_slot
        .checked_add(spe)
        .ok_or(StfError::ArithmeticOverflow)?;
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
    use crate::caches::{compute_ptc, get_beacon_proposer_indices};
    use crate::testing::genesis_state_with_mix;
    use consensus_types::gloas::BeaconState;
    use consensus_types::primitives::Bytes32;
    use consensus_types::{EthSpec, Minimal};

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
}
