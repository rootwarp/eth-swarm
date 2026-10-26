//! Slot processing: `process_slots` (P0 L1848-1855) and the Gloas `process_slot`.

use crate::{per_epoch, state_root, Preset, StfError};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Root, Slot};
use ssz_types::typenum::Unsigned;
use tree_hash::TreeHash;

/// `process_slots` (P0 L1848-1855): runs [`process_slot`] for every slot from `state.slot`
/// up to `slot`, and `process_epoch` on the last slot of each epoch.
///
/// The work is linear in `slot - state.slot`, and, as in the spec, there is no upper bound.
/// Bound `slot` against the wall clock before you call it with a slot from the network.
pub fn process_slots<E: Preset>(state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
    if state.slot >= slot {
        return Err(StfError::SlotNotLater {
            state_slot: state.slot,
            slot,
        });
    }
    while state.slot < slot {
        process_slot(state)?;
        // `state.slot < slot`, so `state.slot + 1` cannot overflow.
        let next_slot = state.slot + 1;
        if next_slot.is_multiple_of(E::slots_per_epoch()) {
            per_epoch::process_epoch(state)?;
        }
        state.slot = next_slot;
    }
    Ok(())
}

/// `process_slot` (G L1608-1622, Modified in Gloas): caches the state and block roots of
/// `state.slot` and clears the payload-availability bit of the next slot.
pub fn process_slot<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    let history = E::SlotsPerHistoricalRoot::to_u64();
    let slot_index = (state.slot % history) as usize;
    let out_of_range = || StfError::Tree("historical root index out of range".into());
    // Cache state root
    let previous_state_root = state_root(state)?;
    *state
        .state_roots
        .get_mut(slot_index)
        .ok_or_else(out_of_range)? = previous_state_root;
    // Cache latest block header state root
    if state.latest_block_header.state_root == Root::ZERO {
        state.latest_block_header.state_root = previous_state_root;
    }
    // Cache block root
    let previous_block_root = state.latest_block_header.tree_hash_root();
    *state
        .block_roots
        .get_mut(slot_index)
        .ok_or_else(out_of_range)? = previous_block_root;
    // [New in Gloas:EIP7732] Unset the next payload availability
    let next_slot = state
        .slot
        .checked_add(1)
        .ok_or(StfError::ArithmeticOverflow)?;
    let next_slot_index = (next_slot % history) as usize;
    state
        .execution_payload_availability
        .set(next_slot_index, false)
        .map_err(|_| out_of_range())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::genesis_state;
    use consensus_types::Minimal;

    type Spe = <Minimal as consensus_types::EthSpec>::SlotsPerHistoricalRoot;

    #[test]
    fn clears_next_availability_bit() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        let len = Spe::to_usize();
        for i in 0..len {
            state.execution_payload_availability.set(i, true).unwrap();
        }
        state.slot = 5;
        process_slot(&mut state).unwrap();
        for i in 0..len {
            let bit = state.execution_payload_availability.get(i).unwrap();
            assert_eq!(bit, i != 6, "bit {i}");
        }
        // The last slot of the historical window clears bit 0 (the index wraps).
        state.slot = len as u64 - 1;
        process_slot(&mut state).unwrap();
        assert!(!state.execution_payload_availability.get(0).unwrap());
        assert!(state.execution_payload_availability.get(1).unwrap());
    }

    #[test]
    fn caches_the_roots_of_each_slot() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        let pre_root = state_root(&mut state).unwrap();
        process_slots(&mut state, 2).unwrap();
        assert_eq!(state.slot, 2);
        assert_eq!(state.state_roots.get(0), Some(&pre_root));
        // The empty header state root is filled with the root of slot 0.
        assert_eq!(state.latest_block_header.state_root, pre_root);
        let header_root = state.latest_block_header.tree_hash_root();
        assert_eq!(state.block_roots.get(0), Some(&header_root));
        assert_eq!(state.block_roots.get(1), Some(&header_root));
        assert_ne!(state.state_roots.get(1), Some(&pre_root));
        assert_eq!(state.state_roots.get(2), Some(&Root::ZERO));
    }

    #[test]
    fn stops_at_the_epoch_boundary_until_process_epoch_lands() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        // Slot 7 is the last slot of epoch 0 in the minimal preset.
        assert_eq!(process_slots(&mut state, 7), Ok(()));
        assert_eq!(
            process_slots(&mut state, 8),
            Err(StfError::Unimplemented("4.2b/4.6b"))
        );
    }

    #[test]
    fn target_slot_must_be_later() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        state.slot = 3;
        for slot in [0, 3] {
            assert_eq!(
                process_slots(&mut state, slot),
                Err(StfError::SlotNotLater {
                    state_slot: 3,
                    slot
                })
            );
        }
        state.slot = u64::MAX;
        assert_eq!(process_slot(&mut state), Err(StfError::ArithmeticOverflow));
    }
}
