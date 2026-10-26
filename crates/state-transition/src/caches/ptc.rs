//! The payload timeliness committee (PTC) of Gloas and its window in the state.

use crate::accessors::{compute_balance_weighted_selection, get_current_epoch, get_seed, hash};
use crate::caches::committee::CommitteeCache;
use crate::preset::MIN_SEED_LOOKAHEAD;
use crate::{Preset, StfError};
use consensus_types::gloas::{BeaconState, PayloadTimelinessCommittee};
use consensus_types::primitives::{Bytes32, Slot, ValidatorIndex};
use consensus_types::signing::DOMAIN_PTC_ATTESTER;
use ssz_types::typenum::Unsigned;

/// `compute_ptc` (G L1266-1282, New in Gloas): `PTC_SIZE` members, with possible
/// duplicates, drawn by balance from the beacon committees of `slot` in order. It shuffles
/// the slot's epoch on each call; [`compute_ptc_with`] reuses a cache.
pub fn compute_ptc<E: Preset>(
    state: &BeaconState<E>,
    slot: Slot,
) -> Result<Vec<ValidatorIndex>, StfError> {
    let cache = CommitteeCache::new(state, E::epoch_at_slot(slot))?;
    compute_ptc_with(state, &cache, slot)
}

/// [`compute_ptc`] over the committees of `cache`, which must be the cache of `slot`'s epoch
/// (else `Err(CacheEpochMismatch)`).
pub fn compute_ptc_with<E: Preset>(
    state: &BeaconState<E>,
    cache: &CommitteeCache,
    slot: Slot,
) -> Result<Vec<ValidatorIndex>, StfError> {
    cache.check_slot(slot)?;
    let epoch = E::epoch_at_slot(slot);
    let seed = get_seed(state, epoch, DOMAIN_PTC_ATTESTER)?;
    let seed = Bytes32::from(hash(&[seed.as_slice(), &slot.to_le_bytes()]));
    let mut indices = Vec::new();
    for i in 0..cache.committees_per_slot() {
        indices.extend_from_slice(cache.committee(slot, i)?);
    }
    compute_balance_weighted_selection(state, &indices, &seed, E::PtcSize::to_u64(), false)
}

/// `get_ptc` (G L1392-1404, New in Gloas): the PTC of `slot` from `state.ptc_window`.
///
/// `slot` must be in the previous epoch, the current epoch or the next `MIN_SEED_LOOKAHEAD`
/// epochs, and not before the Gloas fork. A Gloas state's `fork.epoch` is
/// `GLOAS_FORK_EPOCH` (`upgrade_to_gloas` sets it, and genesis at Gloas has epoch 0), so the
/// fork check reads it from the state instead of from a network config.
pub fn get_ptc<E: Preset>(
    state: &BeaconState<E>,
    slot: Slot,
) -> Result<PayloadTimelinessCommittee<E>, StfError> {
    let epoch = E::epoch_at_slot(slot);
    let state_epoch = get_current_epoch(state);
    let out_of_window = StfError::EpochOutOfWindow { epoch, state_epoch };
    if epoch < state.fork.epoch {
        return Err(out_of_window);
    }
    let spe = E::slots_per_epoch();
    let index = if epoch < state_epoch {
        if epoch + 1 != state_epoch {
            return Err(out_of_window);
        }
        slot % spe
    } else {
        if epoch > state_epoch.saturating_add(MIN_SEED_LOOKAHEAD) {
            return Err(out_of_window);
        }
        (epoch - state_epoch + 1) * spe + slot % spe
    };
    state
        .ptc_window
        .get(index as usize)
        .cloned()
        .ok_or(out_of_window)
}

/// `initialize_ptc_window` (`gloas/fork.md` L37-56): a zero previous epoch, then the PTCs of
/// the current epoch and the next `MIN_SEED_LOOKAHEAD` epochs, the value of
/// `state.ptc_window` at genesis and after the fork.
pub fn initialize_ptc_window<E: Preset>(
    state: &BeaconState<E>,
) -> Result<Vec<PayloadTimelinessCommittee<E>>, StfError> {
    let spe = E::slots_per_epoch();
    let mut window = vec![PayloadTimelinessCommittee::<E>::default(); spe as usize];
    let current_epoch = get_current_epoch(state);
    for e in 0..=MIN_SEED_LOOKAHEAD {
        let epoch = current_epoch
            .checked_add(e)
            .ok_or(StfError::ArithmeticOverflow)?;
        let cache = CommitteeCache::new(state, epoch)?;
        let start_slot = epoch.checked_mul(spe).ok_or(StfError::ArithmeticOverflow)?;
        let end_slot = start_slot
            .checked_add(spe)
            .ok_or(StfError::ArithmeticOverflow)?;
        for slot in start_slot..end_slot {
            let ptc = compute_ptc_with(state, &cache, slot)?;
            window.push(
                PayloadTimelinessCommittee::<E>::new(ptc)
                    .map_err(|e| StfError::Tree(format!("PTC length: {e:?}")))?,
            );
        }
    }
    Ok(window)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::genesis_state;
    use consensus_types::{EthSpec, Minimal};

    #[test]
    fn window_reads_and_bounds() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        let spe = Minimal::slots_per_epoch();
        // Genesis window: a zero previous epoch, then epochs 0 and 1.
        assert_eq!(state.ptc_window.len() as u64, 3 * spe);
        assert_eq!(
            get_ptc(&state, 3).unwrap().to_vec(),
            compute_ptc(&state, 3).unwrap()
        );
        assert_eq!(
            get_ptc(&state, spe + 2).unwrap().to_vec(),
            compute_ptc(&state, spe + 2).unwrap()
        );
        // The cached variant gives the same PTC for every slot of the epoch.
        let cache = CommitteeCache::new(&state, 0).unwrap();
        for slot in 0..spe {
            assert_eq!(
                compute_ptc_with(&state, &cache, slot),
                compute_ptc(&state, slot)
            );
        }
        assert_eq!(
            compute_ptc_with(&state, &cache, spe),
            Err(StfError::CacheEpochMismatch {
                cache_epoch: 0,
                epoch: 1
            })
        );
        let out = |epoch, state_epoch| Err(StfError::EpochOutOfWindow { epoch, state_epoch });
        assert_eq!(get_ptc(&state, 2 * spe), out(2, 0));

        // One epoch later the previous epoch is the first third of the window.
        state.slot = spe;
        let previous = state.ptc_window.get(5).unwrap().clone();
        assert_eq!(get_ptc(&state, 5), Ok(previous));
        state.slot = 3 * spe;
        assert_eq!(get_ptc(&state, 5), out(0, 3));

        // No PTC before the Gloas fork epoch.
        state.fork.epoch = 2;
        assert_eq!(get_ptc(&state, spe), out(1, 3));
    }
}
