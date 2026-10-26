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
/// `MAX_SEED_LOOKAHEAD` (`presets/*/phase0.yaml`, 4 in both presets).
pub const MAX_SEED_LOOKAHEAD: Epoch = 4;
/// `EFFECTIVE_BALANCE_INCREMENT` (`presets/*/phase0.yaml`, 1 ETH in both presets).
pub const EFFECTIVE_BALANCE_INCREMENT: Gwei = 1_000_000_000;
/// `MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA` (`presets/*/electra.yaml`, 4096 in both presets).
pub const MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA: u64 = 4096;
/// `WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA` (`presets/*/electra.yaml`, 4096 in both presets).
pub const WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA: u64 = 4096;
/// `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` (`configs/{minimal,mainnet}.yaml`, 256 in both).
pub const MIN_VALIDATOR_WITHDRAWABILITY_DELAY: Epoch = 256;
/// `PROPOSER_WEIGHT` (A "Incentivization weights", a constant).
pub const PROPOSER_WEIGHT: u64 = 8;
/// `WEIGHT_DENOMINATOR` (A "Incentivization weights", a constant).
pub const WEIGHT_DENOMINATOR: u64 = 64;
/// `BASE_REWARD_FACTOR` (`presets/*/phase0.yaml`, 64 in both presets).
pub const BASE_REWARD_FACTOR: u64 = 64;
/// `TIMELY_SOURCE_FLAG_INDEX` (A L131).
pub const TIMELY_SOURCE_FLAG_INDEX: usize = 0;
/// `TIMELY_TARGET_FLAG_INDEX` (A L132).
pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;
/// `TIMELY_HEAD_FLAG_INDEX` (A L133).
pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;
/// `PARTICIPATION_FLAG_WEIGHTS` (A L160): the source, target and head weights (A L139-141).
pub const PARTICIPATION_FLAG_WEIGHTS: [u64; 3] = [14, 26, 14];
/// `GENESIS_EPOCH` (P0 "Misc").
pub const GENESIS_EPOCH: Epoch = 0;
/// `MIN_EPOCHS_TO_INACTIVITY_PENALTY` (`presets/*/phase0.yaml`, 4 in both presets).
pub const MIN_EPOCHS_TO_INACTIVITY_PENALTY: Epoch = 4;
/// `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX` (`presets/*/bellatrix.yaml`, 2**24 in both).
pub const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64 = 1 << 24;
/// `INACTIVITY_SCORE_BIAS` (`configs/{minimal,mainnet}.yaml`, 4 in both).
pub const INACTIVITY_SCORE_BIAS: u64 = 4;
/// `INACTIVITY_SCORE_RECOVERY_RATE` (`configs/{minimal,mainnet}.yaml`, 16 in both).
pub const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;
/// `BUILDER_INDEX_FLAG` (G "Index flags", a constant): the bit of a `ValidatorIndex` that
/// marks a `BuilderIndex`.
pub const BUILDER_INDEX_FLAG: u64 = 1 << 40;
/// `BUILDER_WITHDRAWAL_PREFIX` (G "Withdrawal prefixes", a constant).
pub const BUILDER_WITHDRAWAL_PREFIX: u8 = 0xb0;
/// `PAYLOAD_BUILDER_VERSION` (G "Builder versions", a constant).
pub const PAYLOAD_BUILDER_VERSION: u8 = 0;
/// `BUILDER_INDEX_SELF_BUILD` (G L571, a constant): the builder index of a bid that the
/// proposer builds itself.
pub const BUILDER_INDEX_SELF_BUILD: u64 = u64::MAX;

/// The preset values of the state transition, on top of the SSZ lengths of [`EthSpec`].
///
/// The churn and builder constants are config values. Each preset takes the value of the
/// config of the same name, which is also the config of its spec vectors.
pub trait Preset: EthSpec {
    /// `SHUFFLE_ROUND_COUNT`.
    const SHUFFLE_ROUND_COUNT: u8;
    /// `TARGET_COMMITTEE_SIZE`.
    const TARGET_COMMITTEE_SIZE: u64;
    /// `MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA` (`configs/{minimal,mainnet}.yaml`).
    const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: Gwei;
    /// `CHURN_LIMIT_QUOTIENT_GLOAS` (`configs/{minimal,mainnet}.yaml`).
    const CHURN_LIMIT_QUOTIENT_GLOAS: u64;
    /// `CONSOLIDATION_CHURN_LIMIT_QUOTIENT` (`configs/{minimal,mainnet}.yaml`).
    const CONSOLIDATION_CHURN_LIMIT_QUOTIENT: u64;
    /// `MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS` (`configs/{minimal,mainnet}.yaml`).
    const MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS: Gwei;
    /// `MIN_BUILDER_WITHDRAWABILITY_DELAY` (`configs/{minimal,mainnet}.yaml`).
    const MIN_BUILDER_WITHDRAWABILITY_DELAY: Epoch;
}

impl Preset for Minimal {
    const SHUFFLE_ROUND_COUNT: u8 = 10;
    const TARGET_COMMITTEE_SIZE: u64 = 4;
    const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: Gwei = 64_000_000_000;
    const CHURN_LIMIT_QUOTIENT_GLOAS: u64 = 16;
    const CONSOLIDATION_CHURN_LIMIT_QUOTIENT: u64 = 32;
    const MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS: Gwei = 128_000_000_000;
    const MIN_BUILDER_WITHDRAWABILITY_DELAY: Epoch = 2;
}

impl Preset for Mainnet {
    const SHUFFLE_ROUND_COUNT: u8 = 90;
    const TARGET_COMMITTEE_SIZE: u64 = 128;
    const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: Gwei = 128_000_000_000;
    const CHURN_LIMIT_QUOTIENT_GLOAS: u64 = 32_768;
    const CONSOLIDATION_CHURN_LIMIT_QUOTIENT: u64 = 65_536;
    const MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS: Gwei = 256_000_000_000;
    const MIN_BUILDER_WITHDRAWABILITY_DELAY: Epoch = 64;
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

    #[test]
    fn churn_values_match_the_pinned_configs() {
        // configs/{minimal,mainnet}.yaml at consensus-specs v1.7.0-beta.4.
        assert_eq!(
            Minimal::MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
            64 * 1_000_000_000
        );
        assert_eq!(
            Mainnet::MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
            128 * 1_000_000_000
        );
        assert_eq!(Minimal::CHURN_LIMIT_QUOTIENT_GLOAS, 16);
        assert_eq!(Mainnet::CHURN_LIMIT_QUOTIENT_GLOAS, 1 << 15);
        assert_eq!(Minimal::CONSOLIDATION_CHURN_LIMIT_QUOTIENT, 32);
        assert_eq!(Mainnet::CONSOLIDATION_CHURN_LIMIT_QUOTIENT, 1 << 16);
        assert_eq!(
            Minimal::MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS,
            128 * 1_000_000_000
        );
        assert_eq!(
            Mainnet::MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS,
            256 * 1_000_000_000
        );
        assert_eq!(Minimal::MIN_BUILDER_WITHDRAWABILITY_DELAY, 2);
        assert_eq!(Mainnet::MIN_BUILDER_WITHDRAWABILITY_DELAY, 64);
        assert_eq!(MIN_VALIDATOR_WITHDRAWABILITY_DELAY, 256);
        assert_eq!(MAX_SEED_LOOKAHEAD, 4);
        assert_eq!(EFFECTIVE_BALANCE_INCREMENT, 1_000_000_000);
        assert_eq!(MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA, 4096);
        assert_eq!(WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA, 4096);
        assert_eq!((PROPOSER_WEIGHT, WEIGHT_DENOMINATOR), (8, 64));
    }

    #[test]
    fn builder_values_match_the_pinned_specs() {
        // G "Constants": 2**40, 0xB0 and Uint8(0).
        assert_eq!(BUILDER_INDEX_FLAG, 1_099_511_627_776);
        assert_eq!(BUILDER_WITHDRAWAL_PREFIX, 0xb0);
        assert_eq!(PAYLOAD_BUILDER_VERSION, 0);
        assert_eq!(BUILDER_INDEX_SELF_BUILD, u64::MAX);
    }
}
