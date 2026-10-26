//! Preset values the state transition reads that are not SSZ lengths
//! (`presets/{minimal,mainnet}/{phase0,altair,bellatrix,capella,electra,gloas}.yaml`).
//!
//! The SSZ lengths stay on [`EthSpec`]; this trait adds the plain numbers, so every function
//! takes one type parameter for both.

use consensus_types::primitives::{Epoch, Gwei, Slot};
use consensus_types::{EthSpec, Mainnet, Minimal};
use ssz_types::typenum::Unsigned;

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
/// `MIN_ACTIVATION_BALANCE` (`presets/*/electra.yaml`, 32 ETH in both presets).
pub const MIN_ACTIVATION_BALANCE: Gwei = 32_000_000_000;
/// `EJECTION_BALANCE` (`configs/{minimal,mainnet}.yaml`, 16 ETH in both). A config value,
/// but Sepolia and Hoodi have the same value as mainnet.
pub const EJECTION_BALANCE: Gwei = 16_000_000_000;
/// `HYSTERESIS_QUOTIENT` (`presets/*/phase0.yaml`, 4 in both presets).
pub const HYSTERESIS_QUOTIENT: u64 = 4;
/// `HYSTERESIS_DOWNWARD_MULTIPLIER` (`presets/*/phase0.yaml`, 1 in both presets).
pub const HYSTERESIS_DOWNWARD_MULTIPLIER: u64 = 1;
/// `HYSTERESIS_UPWARD_MULTIPLIER` (`presets/*/phase0.yaml`, 5 in both presets).
pub const HYSTERESIS_UPWARD_MULTIPLIER: u64 = 5;
/// `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX` (`presets/*/bellatrix.yaml`, 3 in both).
pub const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;
/// `MAX_PENDING_DEPOSITS_PER_EPOCH` (`presets/*/electra.yaml`, 16 in both presets).
pub const MAX_PENDING_DEPOSITS_PER_EPOCH: u64 = 16;
/// `MIN_DEPOSIT_AMOUNT` (`presets/*/phase0.yaml` L23, 1 ETH in both presets).
pub const MIN_DEPOSIT_AMOUNT: Gwei = 1_000_000_000;
/// `GENESIS_SLOT` (P0 "Misc").
pub const GENESIS_SLOT: Slot = 0;
/// `BLS_WITHDRAWAL_PREFIX` (P0 "Withdrawal prefixes", a constant).
pub const BLS_WITHDRAWAL_PREFIX: u8 = 0x00;
/// `ETH1_ADDRESS_WITHDRAWAL_PREFIX` (P0 "Withdrawal prefixes", a constant).
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;
/// `COMPOUNDING_WITHDRAWAL_PREFIX` (E "Withdrawal prefixes", a constant).
pub const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;

/// `EPOCHS_PER_ETH1_VOTING_PERIOD` (`presets/*/phase0.yaml`): the SSZ length
/// `SlotsPerEth1VotingPeriod` divided by `SLOTS_PER_EPOCH`.
pub fn epochs_per_eth1_voting_period<E: EthSpec>() -> Epoch {
    E::SlotsPerEth1VotingPeriod::to_u64() / E::slots_per_epoch()
}

/// The preset values of the state transition, on top of the SSZ lengths of [`EthSpec`].
///
/// The churn and builder constants are config values. Each preset takes the value of the
/// config of the same name, which is also the config of its spec vectors.
pub trait Preset: EthSpec {
    /// `SHUFFLE_ROUND_COUNT`.
    const SHUFFLE_ROUND_COUNT: u8;
    /// `TARGET_COMMITTEE_SIZE`.
    const TARGET_COMMITTEE_SIZE: u64;
    /// `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` (`presets/{minimal,mainnet}/capella.yaml`).
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64;
    /// `MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP` (`presets/{minimal,mainnet}/electra.yaml`).
    const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: u64;
    /// `MAX_BUILDERS_PER_WITHDRAWALS_SWEEP` (`presets/{minimal,mainnet}/gloas.yaml`).
    const MAX_BUILDERS_PER_WITHDRAWALS_SWEEP: u64;
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
    /// `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` (`presets/{minimal,mainnet}/altair.yaml`).
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: Epoch;
    /// `SHARD_COMMITTEE_PERIOD` (`configs/{minimal,mainnet}.yaml`). Sepolia and Hoodi have
    /// the value of mainnet (256).
    const SHARD_COMMITTEE_PERIOD: Epoch;
}

impl Preset for Minimal {
    const SHUFFLE_ROUND_COUNT: u8 = 10;
    const TARGET_COMMITTEE_SIZE: u64 = 4;
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16;
    const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: u64 = 2;
    const MAX_BUILDERS_PER_WITHDRAWALS_SWEEP: u64 = 16;
    const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: Gwei = 64_000_000_000;
    const CHURN_LIMIT_QUOTIENT_GLOAS: u64 = 16;
    const CONSOLIDATION_CHURN_LIMIT_QUOTIENT: u64 = 32;
    const MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS: Gwei = 128_000_000_000;
    const MIN_BUILDER_WITHDRAWABILITY_DELAY: Epoch = 2;
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: Epoch = 8;
    const SHARD_COMMITTEE_PERIOD: Epoch = 64;
}

impl Preset for Mainnet {
    const SHUFFLE_ROUND_COUNT: u8 = 90;
    const TARGET_COMMITTEE_SIZE: u64 = 128;
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16_384;
    const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: u64 = 8;
    const MAX_BUILDERS_PER_WITHDRAWALS_SWEEP: u64 = 16_384;
    const MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: Gwei = 128_000_000_000;
    const CHURN_LIMIT_QUOTIENT_GLOAS: u64 = 32_768;
    const CONSOLIDATION_CHURN_LIMIT_QUOTIENT: u64 = 65_536;
    const MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS: Gwei = 256_000_000_000;
    const MIN_BUILDER_WITHDRAWABILITY_DELAY: Epoch = 64;
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: Epoch = 256;
    const SHARD_COMMITTEE_PERIOD: Epoch = 256;
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
    fn withdrawal_sweep_values_match_the_pinned_presets() {
        // presets/{minimal,mainnet}/capella.yaml L11 and L16, electra.yaml L45 and
        // gloas.yaml L23 at consensus-specs v1.7.0-beta.4.
        assert_eq!(<Minimal as EthSpec>::MaxWithdrawalsPerPayload::to_u64(), 4);
        assert_eq!(<Mainnet as EthSpec>::MaxWithdrawalsPerPayload::to_u64(), 16);
        assert_eq!(Minimal::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP, 16);
        assert_eq!(Mainnet::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP, 1 << 14);
        assert_eq!(Minimal::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP, 2);
        assert_eq!(Mainnet::MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP, 8);
        assert_eq!(Minimal::MAX_BUILDERS_PER_WITHDRAWALS_SWEEP, 16);
        assert_eq!(Mainnet::MAX_BUILDERS_PER_WITHDRAWALS_SWEEP, 1 << 14);
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

    #[test]
    fn epoch_values_match_the_pinned_presets() {
        // presets/{minimal,mainnet}/{phase0,altair,bellatrix,electra}.yaml and
        // configs/{minimal,mainnet}.yaml at consensus-specs v1.7.0-beta.4.
        assert_eq!(MIN_ACTIVATION_BALANCE, 32 * 1_000_000_000);
        assert_eq!(EJECTION_BALANCE, 16 * 1_000_000_000);
        assert_eq!(
            (
                HYSTERESIS_QUOTIENT,
                HYSTERESIS_DOWNWARD_MULTIPLIER,
                HYSTERESIS_UPWARD_MULTIPLIER
            ),
            (4, 1, 5)
        );
        assert_eq!(PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX, 3);
        assert_eq!(MAX_PENDING_DEPOSITS_PER_EPOCH, 16);
        assert_eq!(MIN_DEPOSIT_AMOUNT, 1_000_000_000);
        assert_eq!(COMPOUNDING_WITHDRAWAL_PREFIX, 0x02);
        assert_eq!(Minimal::EPOCHS_PER_SYNC_COMMITTEE_PERIOD, 8);
        assert_eq!(Mainnet::EPOCHS_PER_SYNC_COMMITTEE_PERIOD, 256);
        assert_eq!(epochs_per_eth1_voting_period::<Minimal>(), 4);
        assert_eq!(epochs_per_eth1_voting_period::<Mainnet>(), 64);
    }

    #[test]
    fn exit_and_credential_values_match_the_pinned_specs() {
        // configs/minimal.yaml L76 and configs/mainnet.yaml L80; the network configs of
        // Sepolia and Hoodi (L62) have 256 too.
        assert_eq!(Minimal::SHARD_COMMITTEE_PERIOD, 64);
        assert_eq!(Mainnet::SHARD_COMMITTEE_PERIOD, 256);
        // P0 "Withdrawal prefixes" and "Misc", and E "Withdrawal prefixes".
        assert_eq!(GENESIS_SLOT, 0);
        assert_eq!(
            (
                BLS_WITHDRAWAL_PREFIX,
                ETH1_ADDRESS_WITHDRAWAL_PREFIX,
                COMPOUNDING_WITHDRAWAL_PREFIX
            ),
            (0x00, 0x01, 0x02)
        );
    }
}
