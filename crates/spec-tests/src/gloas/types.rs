//! Minimal local Gloas container definitions (per preset) for ssz_static vectors.
//!
//! Transcribed from consensus-specs v1.7.0-beta.4 `specs/{phase0..gloas}/*.md`. These are
//! test-only shapes, not the client's production types (those stay behind adapters).
//! `active_fields(width=N)` is taken to mean N consecutive active fields.

#![allow(missing_docs)]

/// Shapes for the minimal preset (`presets/minimal/*.yaml`).
pub mod minimal {
    use ssz_types::typenum::*;
    pub type SlotsPerEpoch = U8;
    pub type SlotsPerHistoricalRoot = U64;
    pub type HistoricalRootsLimit = U16777216;
    pub type Eth1VotesLimit = U32; // EPOCHS_PER_ETH1_VOTING_PERIOD(4) * SLOTS_PER_EPOCH(8)
    pub type EpochsPerHistoricalVector = U64;
    pub type EpochsPerSlashingsVector = U64;
    pub type SyncCommitteeSize = U32;
    pub type SyncSubcommitteeSize = U8; // SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT(4)
    pub type PtcSize = U16;
    pub type MaxCommitteesPerSlot = U4;
    pub type MaxBlobCommitmentsPerBlock = U4096;
    pub type ProposerLookaheadLen = U16; // (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH
    pub type PtcWindowLen = U24; // (MIN_SEED_LOOKAHEAD + 2) * SLOTS_PER_EPOCH
    pub type BuilderPendingPaymentsLen = U16; // 2 * SLOTS_PER_EPOCH
    pub type DepositProofLen = U33; // DEPOSIT_CONTRACT_TREE_DEPTH + 1
    /// BYTES_PER_LOGS_BLOOM (typenum U256; named to avoid clashing with alloy's U256).
    pub type U256Len = ssz_types::typenum::U256;
    include!("containers.rs");
}

/// Shapes for the mainnet preset (`presets/mainnet/*.yaml`).
pub mod mainnet {
    use ssz_types::typenum::*;
    pub type SlotsPerEpoch = U32;
    pub type SlotsPerHistoricalRoot = U8192;
    pub type HistoricalRootsLimit = U16777216;
    pub type Eth1VotesLimit = U2048; // EPOCHS_PER_ETH1_VOTING_PERIOD(64) * SLOTS_PER_EPOCH(32)
    pub type EpochsPerHistoricalVector = U65536;
    pub type EpochsPerSlashingsVector = U8192;
    pub type SyncCommitteeSize = U512;
    pub type SyncSubcommitteeSize = U128; // SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT(4)
    pub type PtcSize = U512;
    pub type MaxCommitteesPerSlot = U64;
    pub type MaxBlobCommitmentsPerBlock = U4096;
    pub type ProposerLookaheadLen = U64; // (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH
    pub type PtcWindowLen = U96; // (MIN_SEED_LOOKAHEAD + 2) * SLOTS_PER_EPOCH
    pub type BuilderPendingPaymentsLen = U64; // 2 * SLOTS_PER_EPOCH
    pub type DepositProofLen = U33; // DEPOSIT_CONTRACT_TREE_DEPTH + 1
    /// BYTES_PER_LOGS_BLOOM (typenum U256; named to avoid clashing with alloy's U256).
    pub type U256Len = ssz_types::typenum::U256;
    include!("containers.rs");
}
