//! Block processing (`process_block`, G L1754-1771). Not ported yet.

use crate::{Preset, StfError};
use consensus_types::gloas::{BeaconBlock, BeaconState};

/// `process_block` (G L1754-1771). A placeholder that applies nothing and returns `Ok(())`:
/// until block processing is ported, [`crate::state_transition`] checks only the slot loop,
/// the proposer signature and the state root. No vector runner calls it.
///
/// # Warning
///
/// Do not use this function, or [`crate::state_transition`], on real blocks until block
/// processing is ported. The post-state does not include the block.
pub fn process_block<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
) -> Result<(), StfError> {
    let _ = (state, block);
    Ok(())
}
