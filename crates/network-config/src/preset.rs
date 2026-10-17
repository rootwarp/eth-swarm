//! Preset constants, equal in `presets/minimal` and `presets/mainnet` at the pinned spec.

use crate::fork_schedule::Epoch;

/// `MAX_SEED_LOOKAHEAD` (`presets/{minimal,mainnet}/phase0.yaml`, 4 in both): the epochs past
/// `epoch + 1` at which activations and exits initiated in `epoch` take effect
/// (`compute_activation_exit_epoch`, `phase0/beacon-chain.md`).
pub const MAX_SEED_LOOKAHEAD: Epoch = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_seed_lookahead_matches_both_presets() {
        // presets/{minimal,mainnet}/phase0.yaml L38 at consensus-specs v1.7.0-beta.4.
        assert_eq!(MAX_SEED_LOOKAHEAD, 4);
    }
}
