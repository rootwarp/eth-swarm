//! Preset-dependent lengths as `typenum` types (`presets/{minimal,mainnet}/*.yaml`).
//!
//! Containers are generic over [`EthSpec`], so one definition serves both presets. Values that are
//! the same in both presets live on the trait as well, so every SSZ bound has one home.

use crate::primitives::{Epoch, Slot};
use ssz_types::typenum::{
    Unsigned, U1, U1048576, U1073741824, U1099511627776, U128, U131072, U134217728, U16, U16777216,
    U2, U2048, U24, U256, U262144, U32, U4, U4096, U512, U64, U65536, U8, U8192, U96,
};
use std::fmt::Debug;

macro_rules! eth_spec {
    ($( $(#[$doc:meta])* $name:ident ),* $(,)?) => {
        /// The preset a container is instantiated with.
        pub trait EthSpec:
            'static + Copy + Clone + Debug + Default + PartialEq + Eq + Send + Sync
        {
            /// Preset name, as in `presets/<name>/` and the vector tree.
            const NAME: &'static str;
            /// `MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE` (`gloas/p2p-interface.md` "Type-specific SSZ
            /// bounds", L76; `presets/<name>/gloas.yaml`). Gloas aggregation bits have no type
            /// bound, so this spec constant is the aggregate's cap.
            const MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE: u64;
            $(
                $(#[$doc])*
                type $name: Unsigned + Copy + Clone + Debug + Default + PartialEq + Eq + Send
                    + Sync + 'static;
            )*

            /// `SLOTS_PER_EPOCH`.
            fn slots_per_epoch() -> u64 {
                Self::SlotsPerEpoch::to_u64()
            }

            /// `compute_epoch_at_slot`.
            fn epoch_at_slot(slot: Slot) -> Epoch {
                slot / Self::slots_per_epoch()
            }

            /// `compute_start_slot_at_epoch`, saturating at `u64::MAX`.
            fn start_slot_at_epoch(epoch: Epoch) -> Slot {
                epoch.saturating_mul(Self::slots_per_epoch())
            }
        }
    };
}

eth_spec! {
    /// `SLOTS_PER_EPOCH`.
    SlotsPerEpoch,
    /// `SLOTS_PER_HISTORICAL_ROOT`.
    SlotsPerHistoricalRoot,
    /// `HISTORICAL_ROOTS_LIMIT`.
    HistoricalRootsLimit,
    /// `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH`.
    SlotsPerEth1VotingPeriod,
    /// `EPOCHS_PER_HISTORICAL_VECTOR`.
    EpochsPerHistoricalVector,
    /// `EPOCHS_PER_SLASHINGS_VECTOR`.
    EpochsPerSlashingsVector,
    /// `VALIDATOR_REGISTRY_LIMIT`.
    ValidatorRegistryLimit,
    /// `MAX_VALIDATORS_PER_COMMITTEE`.
    MaxValidatorsPerCommittee,
    /// `MAX_COMMITTEES_PER_SLOT`.
    MaxCommitteesPerSlot,
    /// `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`.
    MaxValidatorsPerSlot,
    /// `SYNC_COMMITTEE_SIZE`.
    SyncCommitteeSize,
    /// `SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT`.
    SyncSubcommitteeSize,
    /// `MAX_PROPOSER_SLASHINGS`.
    MaxProposerSlashings,
    /// `MAX_ATTESTER_SLASHINGS_ELECTRA`.
    MaxAttesterSlashings,
    /// `MAX_ATTESTATIONS_ELECTRA`.
    MaxAttestations,
    /// `MAX_DEPOSITS`.
    MaxDeposits,
    /// `MAX_VOLUNTARY_EXITS`.
    MaxVoluntaryExits,
    /// `MAX_BLS_TO_EXECUTION_CHANGES`.
    MaxBlsToExecutionChanges,
    /// `MAX_BYTES_PER_TRANSACTION`.
    MaxBytesPerTransaction,
    /// `MAX_TRANSACTIONS_PER_PAYLOAD`.
    MaxTransactionsPerPayload,
    /// `BYTES_PER_LOGS_BLOOM`.
    BytesPerLogsBloom,
    /// `MAX_EXTRA_DATA_BYTES`.
    MaxExtraDataBytes,
    /// `MAX_WITHDRAWALS_PER_PAYLOAD`.
    MaxWithdrawalsPerPayload,
    /// `MAX_BLOB_COMMITMENTS_PER_BLOCK`.
    MaxBlobCommitmentsPerBlock,
    /// `PENDING_DEPOSITS_LIMIT`.
    PendingDepositsLimit,
    /// `PENDING_PARTIAL_WITHDRAWALS_LIMIT`.
    PendingPartialWithdrawalsLimit,
    /// `PENDING_CONSOLIDATIONS_LIMIT`.
    PendingConsolidationsLimit,
    /// `MAX_DEPOSIT_REQUESTS_PER_PAYLOAD`.
    MaxDepositRequestsPerPayload,
    /// `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD`.
    MaxWithdrawalRequestsPerPayload,
    /// `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD`.
    MaxConsolidationRequestsPerPayload,
    /// `(MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH` (Fulu `ProposerLookahead`).
    ProposerLookaheadLength,
    /// `PTC_SIZE` (Gloas).
    PtcSize,
    /// `MAX_PAYLOAD_ATTESTATIONS` (Gloas).
    MaxPayloadAttestations,
    /// `MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD` (Gloas).
    MaxBuilderDepositRequestsPerPayload,
    /// `MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD` (Gloas).
    MaxBuilderExitRequestsPerPayload,
    /// `(MIN_SEED_LOOKAHEAD + 2) * SLOTS_PER_EPOCH` (Gloas `PayloadTimelinessCommitteeWindow`).
    PtcWindowLength,
    /// `2 * SLOTS_PER_EPOCH` (Gloas `BuilderPendingPayments`).
    BuilderPendingPaymentsLength,
}

/// `DEPOSIT_CONTRACT_TREE_DEPTH + 1` (`DepositProof`), the same in every preset.
pub type DepositProofLength = ssz_types::typenum::U33;
/// `JUSTIFICATION_BITS_LENGTH`.
pub type JustificationBitsLength = U4;

macro_rules! impl_preset {
    ($spec:ident, $name:literal, $agg:literal { $($assoc:ident = $val:ty),* $(,)? }) => {
        impl EthSpec for $spec {
            const NAME: &'static str = $name;
            const MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE: u64 = $agg;
            $(type $assoc = $val;)*
        }
    };
}

/// The `minimal` preset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Minimal;

/// The `mainnet` preset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mainnet;

impl_preset!(Minimal, "minimal", 1462 {
    SlotsPerEpoch = U8,
    SlotsPerHistoricalRoot = U64,
    HistoricalRootsLimit = U16777216,
    SlotsPerEth1VotingPeriod = U32,
    EpochsPerHistoricalVector = U64,
    EpochsPerSlashingsVector = U64,
    ValidatorRegistryLimit = U1099511627776,
    MaxValidatorsPerCommittee = U2048,
    MaxCommitteesPerSlot = U4,
    MaxValidatorsPerSlot = U8192,
    SyncCommitteeSize = U32,
    SyncSubcommitteeSize = U8,
    MaxProposerSlashings = U16,
    MaxAttesterSlashings = U1,
    MaxAttestations = U8,
    MaxDeposits = U16,
    MaxVoluntaryExits = U16,
    MaxBlsToExecutionChanges = U16,
    MaxBytesPerTransaction = U1073741824,
    MaxTransactionsPerPayload = U1048576,
    BytesPerLogsBloom = U256,
    MaxExtraDataBytes = U32,
    MaxWithdrawalsPerPayload = U4,
    MaxBlobCommitmentsPerBlock = U4096,
    PendingDepositsLimit = U134217728,
    PendingPartialWithdrawalsLimit = U64,
    PendingConsolidationsLimit = U64,
    MaxDepositRequestsPerPayload = U8192,
    MaxWithdrawalRequestsPerPayload = U16,
    MaxConsolidationRequestsPerPayload = U2,
    ProposerLookaheadLength = U16,
    PtcSize = U16,
    MaxPayloadAttestations = U4,
    MaxBuilderDepositRequestsPerPayload = U64,
    MaxBuilderExitRequestsPerPayload = U16,
    PtcWindowLength = U24,
    BuilderPendingPaymentsLength = U16,
});

impl_preset!(Mainnet, "mainnet", 16829 {
    SlotsPerEpoch = U32,
    SlotsPerHistoricalRoot = U8192,
    HistoricalRootsLimit = U16777216,
    SlotsPerEth1VotingPeriod = U2048,
    EpochsPerHistoricalVector = U65536,
    EpochsPerSlashingsVector = U8192,
    ValidatorRegistryLimit = U1099511627776,
    MaxValidatorsPerCommittee = U2048,
    MaxCommitteesPerSlot = U64,
    MaxValidatorsPerSlot = U131072,
    SyncCommitteeSize = U512,
    SyncSubcommitteeSize = U128,
    MaxProposerSlashings = U16,
    MaxAttesterSlashings = U1,
    MaxAttestations = U8,
    MaxDeposits = U16,
    MaxVoluntaryExits = U16,
    MaxBlsToExecutionChanges = U16,
    MaxBytesPerTransaction = U1073741824,
    MaxTransactionsPerPayload = U1048576,
    BytesPerLogsBloom = U256,
    MaxExtraDataBytes = U32,
    MaxWithdrawalsPerPayload = U16,
    MaxBlobCommitmentsPerBlock = U4096,
    PendingDepositsLimit = U134217728,
    PendingPartialWithdrawalsLimit = U134217728,
    PendingConsolidationsLimit = U262144,
    MaxDepositRequestsPerPayload = U8192,
    MaxWithdrawalRequestsPerPayload = U16,
    MaxConsolidationRequestsPerPayload = U2,
    ProposerLookaheadLength = U64,
    PtcSize = U512,
    MaxPayloadAttestations = U4,
    MaxBuilderDepositRequestsPerPayload = U64,
    MaxBuilderExitRequestsPerPayload = U16,
    PtcWindowLength = U96,
    BuilderPendingPaymentsLength = U64,
});

#[cfg(test)]
mod tests {
    use super::*;

    /// Derived lengths must equal the products the spec defines them as.
    fn derived_lengths_hold<E: EthSpec>(min_seed_lookahead: u64, sync_subnets: u64) {
        let spe = E::SlotsPerEpoch::to_u64();
        assert_eq!(
            E::MaxValidatorsPerSlot::to_u64(),
            E::MaxValidatorsPerCommittee::to_u64() * E::MaxCommitteesPerSlot::to_u64()
        );
        assert_eq!(
            E::SyncSubcommitteeSize::to_u64(),
            E::SyncCommitteeSize::to_u64() / sync_subnets
        );
        assert_eq!(
            E::ProposerLookaheadLength::to_u64(),
            (min_seed_lookahead + 1) * spe
        );
        assert_eq!(E::PtcWindowLength::to_u64(), (min_seed_lookahead + 2) * spe);
        assert_eq!(E::BuilderPendingPaymentsLength::to_u64(), 2 * spe);
    }

    #[test]
    fn presets_are_consistent() {
        // MIN_SEED_LOOKAHEAD = 1 and SYNC_COMMITTEE_SUBNET_COUNT = 4 in both presets.
        derived_lengths_hold::<Minimal>(1, 4);
        derived_lengths_hold::<Mainnet>(1, 4);
        assert_eq!(
            <Minimal as EthSpec>::SlotsPerEth1VotingPeriod::to_u64(),
            4 * 8
        );
        assert_eq!(
            <Mainnet as EthSpec>::SlotsPerEth1VotingPeriod::to_u64(),
            64 * 32
        );
    }

    #[test]
    fn slot_epoch_conversions() {
        assert_eq!(Mainnet::epoch_at_slot(63), 1);
        assert_eq!(Mainnet::start_slot_at_epoch(2), 64);
        assert_eq!(Minimal::start_slot_at_epoch(u64::MAX), u64::MAX);
        assert_eq!(Minimal::NAME, "minimal");
        assert_eq!(Mainnet::NAME, "mainnet");
    }
}
