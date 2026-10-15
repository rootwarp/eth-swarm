// Included by `types.rs` once per preset; the preset aliases must be in scope.

use alloy_primitives::{Address, B256, U256};
use ssz::{BitVector, ProgressiveBitList};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, ProgressiveVariableList as PList, VariableList};
use tree_hash_derive::TreeHash;

pub type Pubkey = [u8; 48];
pub type Signature = [u8; 96];
pub type Version = [u8; 4];


macro_rules! container {
    ($name:ident { $($f:ident : $t:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
        pub struct $name { $(pub $f: $t),* }
    };
}

macro_rules! progressive {
    ($name:ident [$($af:literal),*] { $($f:ident : $t:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Encode, Decode, TreeHash)]
        #[tree_hash(struct_behaviour = "progressive_container", active_fields($($af),*))]
        pub struct $name { $(pub $f: $t),* }
    };
}

container!(Checkpoint {
    epoch: u64,
    root: B256
});
container!(Fork {
    previous_version: Version,
    current_version: Version,
    epoch: u64
});
container!(ForkData {
    current_version: Version,
    genesis_validators_root: B256
});
container!(SigningData {
    object_root: B256,
    domain: B256
});
container!(AttestationData {
    slot: u64,
    index: u64,
    beacon_block_root: B256,
    source: Checkpoint,
    target: Checkpoint
});
progressive!(Attestation [1, 1, 1, 1] {
    aggregation_bits: ProgressiveBitList, data: AttestationData, signature: Signature,
    committee_bits: BitVector<MaxCommitteesPerSlot>,
});
progressive!(IndexedAttestation [1, 1, 1] { attesting_indices: PList<u64>, data: AttestationData, signature: Signature });
container!(SingleAttestation {
    committee_index: u64,
    attester_index: u64,
    data: AttestationData,
    signature: Signature
});
container!(AttesterSlashing {
    attestation_1: IndexedAttestation,
    attestation_2: IndexedAttestation
});
container!(AggregateAndProof {
    aggregator_index: u64,
    aggregate: Attestation,
    selection_proof: Signature
});
container!(SignedAggregateAndProof {
    message: AggregateAndProof,
    signature: Signature
});
container!(BeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: B256,
    state_root: B256,
    body_root: B256
});
container!(SignedBeaconBlockHeader {
    message: BeaconBlockHeader,
    signature: Signature
});
container!(ProposerSlashing {
    signed_header_1: SignedBeaconBlockHeader,
    signed_header_2: SignedBeaconBlockHeader
});
container!(Eth1Data {
    deposit_root: B256,
    deposit_count: u64,
    block_hash: B256
});
container!(Eth1Block {
    timestamp: u64,
    deposit_root: B256,
    deposit_count: u64
});
container!(PowBlock {
    block_hash: B256,
    parent_hash: B256,
    total_difficulty: U256
});
container!(DepositMessage {
    pubkey: Pubkey,
    withdrawal_credentials: B256,
    amount: u64
});
container!(DepositData {
    pubkey: Pubkey,
    withdrawal_credentials: B256,
    amount: u64,
    signature: Signature
});
container!(Deposit { proof: FixedVector<B256, DepositProofLen>, data: DepositData });
container!(VoluntaryExit {
    epoch: u64,
    validator_index: u64
});
container!(SignedVoluntaryExit {
    message: VoluntaryExit,
    signature: Signature
});
container!(SyncAggregate { sync_committee_bits: BitVector<SyncCommitteeSize>, sync_committee_signature: Signature });
container!(SyncCommittee { pubkeys: FixedVector<Pubkey, SyncCommitteeSize>, aggregate_pubkey: Pubkey });
container!(SyncCommitteeMessage {
    slot: u64,
    beacon_block_root: B256,
    validator_index: u64,
    signature: Signature
});
container!(SyncCommitteeContribution {
    slot: u64, beacon_block_root: B256, subcommittee_index: u64,
    aggregation_bits: BitVector<SyncSubcommitteeSize>, signature: Signature,
});
container!(ContributionAndProof {
    aggregator_index: u64,
    contribution: SyncCommitteeContribution,
    selection_proof: Signature
});
container!(SignedContributionAndProof {
    message: ContributionAndProof,
    signature: Signature
});
container!(SyncAggregatorSelectionData {
    slot: u64,
    subcommittee_index: u64
});
container!(BLSToExecutionChange {
    validator_index: u64,
    from_bls_pubkey: Pubkey,
    to_execution_address: Address
});
container!(SignedBLSToExecutionChange {
    message: BLSToExecutionChange,
    signature: Signature
});
container!(Withdrawal {
    index: u64,
    validator_index: u64,
    address: Address,
    amount: u64
});
container!(DepositRequest {
    pubkey: Pubkey,
    withdrawal_credentials: B256,
    amount: u64,
    signature: Signature,
    index: u64
});
container!(WithdrawalRequest {
    source_address: Address,
    validator_pubkey: Pubkey,
    amount: u64
});
container!(ConsolidationRequest {
    source_address: Address,
    source_pubkey: Pubkey,
    target_pubkey: Pubkey
});
container!(BuilderDepositRequest {
    pubkey: Pubkey,
    withdrawal_credentials: B256,
    amount: u64,
    signature: Signature
});
container!(BuilderExitRequest {
    source_address: Address,
    pubkey: Pubkey
});
progressive!(ExecutionRequests [1, 1, 1, 1, 1] {
    deposits: PList<DepositRequest>, withdrawals: PList<WithdrawalRequest>,
    consolidations: PList<ConsolidationRequest>, builder_deposits: PList<BuilderDepositRequest>,
    builder_exits: PList<BuilderExitRequest>,
});
progressive!(ExecutionPayload [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] {
    parent_hash: B256, fee_recipient: Address, state_root: B256, receipts_root: B256,
    logs_bloom: FixedVector<u8, U256Len>, prev_randao: B256, block_number: u64, gas_limit: u64,
    gas_used: u64, timestamp: u64, extra_data: VariableList<u8, U32>, base_fee_per_gas: U256,
    block_hash: B256, transactions: PList<PList<u8>>, withdrawals: PList<Withdrawal>,
    blob_gas_used: u64, excess_blob_gas: u64, block_access_list: PList<u8>, slot_number: u64,
});
progressive!(NewPayloadRequest [1, 1, 1, 1] {
    execution_payload: ExecutionPayload, versioned_hashes: VariableList<B256, MaxBlobCommitmentsPerBlock>,
    parent_beacon_block_root: B256, execution_requests: ExecutionRequests,
});
progressive!(ExecutionPayloadBid [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] {
    parent_block_hash: B256, parent_block_root: B256, block_hash: B256, prev_randao: B256,
    fee_recipient: Address, gas_limit: u64, builder_index: u64, slot: u64, value: u64,
    execution_payment: u64, blob_kzg_commitments: PList<Pubkey>, execution_requests_root: B256,
});
container!(SignedExecutionPayloadBid {
    message: ExecutionPayloadBid,
    signature: Signature
});
progressive!(ExecutionPayloadEnvelope [1, 1, 1, 1, 1] {
    payload: ExecutionPayload, execution_requests: ExecutionRequests, builder_index: u64,
    beacon_block_root: B256, parent_beacon_block_root: B256,
});
container!(SignedExecutionPayloadEnvelope {
    message: ExecutionPayloadEnvelope,
    signature: Signature
});
container!(PayloadAttestationData {
    beacon_block_root: B256,
    slot: u64,
    payload_present: bool,
    blob_data_available: bool
});
progressive!(PayloadAttestation [1, 1, 1] { aggregation_bits: BitVector<PtcSize>, data: PayloadAttestationData, signature: Signature });
container!(PayloadAttestationMessage {
    validator_index: u64,
    data: PayloadAttestationData,
    signature: Signature
});
progressive!(IndexedPayloadAttestation [1, 1, 1] {
    attesting_indices: VariableList<u64, PtcSize>, data: PayloadAttestationData, signature: Signature,
});
container!(ProposerPreferences {
    dependent_root: B256,
    proposal_slot: u64,
    validator_index: u64,
    fee_recipient: Address,
    target_gas_limit: u64
});
container!(SignedProposerPreferences {
    message: ProposerPreferences,
    signature: Signature
});
progressive!(BeaconBlockBody [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] {
    randao_reveal: Signature, eth1_data: Eth1Data, graffiti: B256,
    proposer_slashings: PList<ProposerSlashing>, attester_slashings: PList<AttesterSlashing>,
    attestations: PList<Attestation>, deposits: PList<Deposit>, voluntary_exits: PList<SignedVoluntaryExit>,
    sync_aggregate: SyncAggregate, bls_to_execution_changes: PList<SignedBLSToExecutionChange>,
    signed_execution_payload_bid: SignedExecutionPayloadBid, payload_attestations: PList<PayloadAttestation>,
    parent_execution_requests: ExecutionRequests,
});
container!(BeaconBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: B256,
    state_root: B256,
    body: BeaconBlockBody
});
container!(SignedBeaconBlock {
    message: BeaconBlock,
    signature: Signature
});
container!(Validator {
    pubkey: Pubkey,
    withdrawal_credentials: B256,
    effective_balance: u64,
    slashed: bool,
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
});
container!(PendingDeposit {
    pubkey: Pubkey,
    withdrawal_credentials: B256,
    amount: u64,
    signature: Signature,
    slot: u64
});
container!(PendingPartialWithdrawal {
    validator_index: u64,
    amount: u64,
    withdrawable_epoch: u64
});
container!(PendingConsolidation {
    source_index: u64,
    target_index: u64
});
container!(HistoricalSummary {
    block_summary_root: B256,
    state_summary_root: B256
});
container!(Builder {
    pubkey: Pubkey,
    version: u8,
    execution_address: Address,
    balance: u64,
    deposit_epoch: u64,
    withdrawable_epoch: u64,
});
container!(BuilderPendingWithdrawal {
    fee_recipient: Address,
    amount: u64,
    builder_index: u64
});
container!(BuilderPendingPayment {
    weight: u64,
    withdrawal: BuilderPendingWithdrawal,
    proposer_index: u64
});
progressive!(BeaconState [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1] {
    genesis_time: u64, genesis_validators_root: B256, slot: u64, fork: Fork,
    latest_block_header: BeaconBlockHeader,
    block_roots: FixedVector<B256, SlotsPerHistoricalRoot>,
    state_roots: FixedVector<B256, SlotsPerHistoricalRoot>,
    historical_roots: VariableList<B256, HistoricalRootsLimit>,
    eth1_data: Eth1Data, eth1_data_votes: VariableList<Eth1Data, Eth1VotesLimit>, eth1_deposit_index: u64,
    validators: PList<Validator>, balances: PList<u64>,
    randao_mixes: FixedVector<B256, EpochsPerHistoricalVector>,
    slashings: FixedVector<u64, EpochsPerSlashingsVector>,
    previous_epoch_participation: PList<u8>, current_epoch_participation: PList<u8>,
    justification_bits: BitVector<U4>,
    previous_justified_checkpoint: Checkpoint, current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint, inactivity_scores: PList<u64>,
    current_sync_committee: SyncCommittee, next_sync_committee: SyncCommittee,
    latest_block_hash: B256, next_withdrawal_index: u64, next_withdrawal_validator_index: u64,
    historical_summaries: VariableList<HistoricalSummary, HistoricalRootsLimit>,
    deposit_requests_start_index: u64, deposit_balance_to_consume: u64, exit_balance_to_consume: u64,
    earliest_exit_epoch: u64, consolidation_balance_to_consume: u64, earliest_consolidation_epoch: u64,
    pending_deposits: PList<PendingDeposit>, pending_partial_withdrawals: PList<PendingPartialWithdrawal>,
    pending_consolidations: PList<PendingConsolidation>,
    proposer_lookahead: FixedVector<u64, ProposerLookaheadLen>,
    builders: PList<Builder>, next_withdrawal_builder_index: u64,
    execution_payload_availability: BitVector<SlotsPerHistoricalRoot>,
    builder_pending_payments: FixedVector<BuilderPendingPayment, BuilderPendingPaymentsLen>,
    builder_pending_withdrawals: PList<BuilderPendingWithdrawal>,
    latest_execution_payload_bid: ExecutionPayloadBid, payload_expected_withdrawals: PList<Withdrawal>,
    ptc_window: FixedVector<FixedVector<u64, PtcSize>, PtcWindowLen>,
});
