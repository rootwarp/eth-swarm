//! Epoch processing (`process_epoch`, G L1633-1653). Not ported yet.

use crate::{Preset, StfError};
use consensus_types::gloas::BeaconState;

/// `process_epoch` (G L1633-1653, Modified in Gloas). A stub: every call returns
/// [`StfError::Unimplemented`], so `process_slots` stops at the first epoch boundary.
pub fn process_epoch<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    let _ = state;
    Err(StfError::Unimplemented("4.2a/4.2b/4.6b"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::genesis_state;
    use consensus_types::Minimal;

    #[test]
    fn process_epoch_is_a_stub() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        assert_eq!(
            process_epoch(&mut state),
            Err(StfError::Unimplemented("4.2a/4.2b/4.6b"))
        );
    }
}
