//! Proposer selection and the Fulu proposer lookahead.

use crate::accessors::{
    compute_balance_weighted_selection, get_active_validator_indices, get_current_epoch, get_seed,
    hash,
};
use crate::preset::MIN_SEED_LOOKAHEAD;
use crate::{Preset, StfError};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Bytes32, Epoch, ValidatorIndex};
use consensus_types::signing::DOMAIN_BEACON_PROPOSER;

/// `compute_proposer_indices` (G L1240-1260, Modified in Gloas): one balance-weighted draw
/// per slot of `epoch`, `SLOTS_PER_EPOCH` entries.
pub fn compute_proposer_indices<E: Preset>(
    state: &BeaconState<E>,
    epoch: Epoch,
    seed: &Bytes32,
    indices: &[ValidatorIndex],
) -> Result<Vec<ValidatorIndex>, StfError> {
    let start_slot = epoch
        .checked_mul(E::slots_per_epoch())
        .ok_or(StfError::ArithmeticOverflow)?;
    (0..E::slots_per_epoch())
        .map(|index| {
            let slot = start_slot
                .checked_add(index)
                .ok_or(StfError::ArithmeticOverflow)?;
            let slot_seed = Bytes32::from(hash(&[seed.as_slice(), &slot.to_le_bytes()]));
            compute_balance_weighted_selection(state, indices, &slot_seed, 1, true)?
                .first()
                .copied()
                .ok_or(StfError::NoCandidates)
        })
        .collect()
}

/// `get_beacon_proposer_indices` (G L1294-1305, Modified in Gloas): slashed validators are
/// not candidates.
pub fn get_beacon_proposer_indices<E: Preset>(
    state: &BeaconState<E>,
    epoch: Epoch,
) -> Result<Vec<ValidatorIndex>, StfError> {
    let indices: Vec<ValidatorIndex> = get_active_validator_indices(state, epoch)
        .into_iter()
        .filter(|&i| state.validators.get(i as usize).is_some_and(|v| !v.slashed))
        .collect();
    let seed = get_seed(state, epoch, DOMAIN_BEACON_PROPOSER)?;
    compute_proposer_indices(state, epoch, &seed, &indices)
}

/// `get_beacon_proposer_index` (Fu L362-366, Modified in Fulu; Gloas keeps it): the
/// proposer of the current slot from `state.proposer_lookahead`.
pub fn get_beacon_proposer_index<E: Preset>(
    state: &BeaconState<E>,
) -> Result<ValidatorIndex, StfError> {
    let index = state.slot % E::slots_per_epoch();
    state
        .proposer_lookahead
        .get(index as usize)
        .copied()
        .ok_or_else(|| StfError::Tree("proposer_lookahead is shorter than SLOTS_PER_EPOCH".into()))
}

/// `initialize_proposer_lookahead` (`fulu/fork.md` L33-44): the proposers of the current
/// epoch and the next `MIN_SEED_LOOKAHEAD` epochs, the value of `state.proposer_lookahead` at
/// genesis and after the fork.
pub fn initialize_proposer_lookahead<E: Preset>(
    state: &BeaconState<E>,
) -> Result<Vec<ValidatorIndex>, StfError> {
    let current_epoch = get_current_epoch(state);
    let mut lookahead = Vec::new();
    for i in 0..=MIN_SEED_LOOKAHEAD {
        let epoch = current_epoch
            .checked_add(i)
            .ok_or(StfError::ArithmeticOverflow)?;
        lookahead.extend(get_beacon_proposer_indices(state, epoch)?);
    }
    Ok(lookahead)
}
