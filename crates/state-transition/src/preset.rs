//! Preset values the state transition reads that are not SSZ lengths
//! (`presets/{minimal,mainnet}/{phase0,electra}.yaml`).
//!
//! The SSZ lengths stay on [`EthSpec`]; this trait adds the plain numbers, so every function
//! takes one type parameter for both.

use consensus_types::primitives::{Epoch, Gwei};
use consensus_types::{EthSpec, Mainnet, Minimal};

/// `MIN_SEED_LOOKAHEAD` (`presets/*/phase0.yaml`, 1 in both presets).
pub const MIN_SEED_LOOKAHEAD: Epoch = 1;
/// `MAX_EFFECTIVE_BALANCE_ELECTRA` (`presets/*/electra.yaml`, 2048 ETH in both presets).
pub const MAX_EFFECTIVE_BALANCE_ELECTRA: Gwei = 2_048_000_000_000;

/// The preset values of the state transition, on top of the SSZ lengths of [`EthSpec`].
pub trait Preset: EthSpec {
    /// `SHUFFLE_ROUND_COUNT`.
    const SHUFFLE_ROUND_COUNT: u8;
    /// `TARGET_COMMITTEE_SIZE`.
    const TARGET_COMMITTEE_SIZE: u64;
}

impl Preset for Minimal {
    const SHUFFLE_ROUND_COUNT: u8 = 10;
    const TARGET_COMMITTEE_SIZE: u64 = 4;
}

impl Preset for Mainnet {
    const SHUFFLE_ROUND_COUNT: u8 = 90;
    const TARGET_COMMITTEE_SIZE: u64 = 128;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_the_pinned_presets() {
        // presets/{minimal,mainnet}/phase0.yaml L8 and L12 at consensus-specs v1.7.0-beta.4.
        assert_eq!(Minimal::SHUFFLE_ROUND_COUNT, 10);
        assert_eq!(Mainnet::SHUFFLE_ROUND_COUNT, 90);
        assert_eq!(Minimal::TARGET_COMMITTEE_SIZE, 4);
        assert_eq!(Mainnet::TARGET_COMMITTEE_SIZE, 128);
        assert_eq!(MIN_SEED_LOOKAHEAD, 1);
        assert_eq!(MAX_EFFECTIVE_BALANCE_ELECTRA, 2048 * 1_000_000_000);
    }
}
