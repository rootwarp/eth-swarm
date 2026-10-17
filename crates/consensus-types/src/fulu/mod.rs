//! Fulu containers (`specs/fulu/beacon-chain.md` and the Electra shapes Fulu inherits).
//!
//! Codec only: decode, encode and `hash_tree_root`, no state transition. Fulu lists keep their
//! spec `List[T, N]` limits, which the decoder enforces before allocating. The data-column
//! containers (`fulu/das-core.md`, `fulu/p2p-interface.md`) are not defined here.

pub use crate::common::*;

use crate::macros::container;
use crate::preset::{EthSpec, JustificationBitsLength};
use crate::primitives::*;
use milhouse::{List, Vector};
use ssz::{BitList, BitVector};
use ssz_types::{FixedVector, VariableList};

/// `Transaction` (Bellatrix): an opaque EL transaction.
pub type Transaction<E> = VariableList<u8, <E as EthSpec>::MaxBytesPerTransaction>;

container! {
    /// `Attestation` (Electra).
    Attestation<E> {
        aggregation_bits: BitList<E::MaxValidatorsPerSlot>,
        data: AttestationData,
        signature: BLSSignature,
        committee_bits: BitVector<E::MaxCommitteesPerSlot>,
    }
}

container! {
    /// `IndexedAttestation` (Electra).
    IndexedAttestation<E> {
        attesting_indices: VariableList<ValidatorIndex, E::MaxValidatorsPerSlot>,
        data: AttestationData,
        signature: BLSSignature,
    }
}

container! {
    /// `AttesterSlashing` (Electra).
    AttesterSlashing<E> {
        attestation_1: IndexedAttestation<E>,
        attestation_2: IndexedAttestation<E>,
    }
}

container! {
    /// `AggregateAndProof` (Electra validator guide).
    AggregateAndProof<E> {
        aggregator_index: ValidatorIndex,
        aggregate: Attestation<E>,
        selection_proof: BLSSignature,
    }
}

container! {
    /// `SignedAggregateAndProof` (Electra validator guide).
    SignedAggregateAndProof<E> { message: AggregateAndProof<E>, signature: BLSSignature }
}

container! {
    /// `ExecutionPayload` (Deneb).
    ExecutionPayload<E> {
        parent_hash: Hash32,
        fee_recipient: ExecutionAddress,
        state_root: Bytes32,
        receipts_root: Bytes32,
        logs_bloom: FixedVector<u8, E::BytesPerLogsBloom>,
        prev_randao: Bytes32,
        block_number: u64,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        extra_data: VariableList<u8, E::MaxExtraDataBytes>,
        base_fee_per_gas: U256,
        block_hash: Hash32,
        transactions: VariableList<Transaction<E>, E::MaxTransactionsPerPayload>,
        withdrawals: VariableList<Withdrawal, E::MaxWithdrawalsPerPayload>,
        blob_gas_used: u64,
        excess_blob_gas: u64,
    }
}

container! {
    /// `ExecutionPayloadHeader` (Deneb).
    ExecutionPayloadHeader<E> {
        parent_hash: Hash32,
        fee_recipient: ExecutionAddress,
        state_root: Bytes32,
        receipts_root: Bytes32,
        logs_bloom: FixedVector<u8, E::BytesPerLogsBloom>,
        prev_randao: Bytes32,
        block_number: u64,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        extra_data: VariableList<u8, E::MaxExtraDataBytes>,
        base_fee_per_gas: U256,
        block_hash: Hash32,
        transactions_root: Root,
        withdrawals_root: Root,
        blob_gas_used: u64,
        excess_blob_gas: u64,
    }
}

container! {
    /// `ExecutionRequests` (Electra).
    ExecutionRequests<E> {
        deposits: VariableList<DepositRequest, E::MaxDepositRequestsPerPayload>,
        withdrawals: VariableList<WithdrawalRequest, E::MaxWithdrawalRequestsPerPayload>,
        consolidations: VariableList<ConsolidationRequest, E::MaxConsolidationRequestsPerPayload>,
    }
}

container! {
    /// `NewPayloadRequest` (Electra).
    NewPayloadRequest<E> {
        execution_payload: ExecutionPayload<E>,
        versioned_hashes: VariableList<VersionedHash, E::MaxBlobCommitmentsPerBlock>,
        parent_beacon_block_root: Root,
        execution_requests: ExecutionRequests<E>,
    }
}

container! {
    /// `BeaconBlockBody` (Electra).
    BeaconBlockBody<E> {
        randao_reveal: BLSSignature,
        eth1_data: Eth1Data,
        graffiti: Bytes32,
        proposer_slashings: VariableList<ProposerSlashing, E::MaxProposerSlashings>,
        attester_slashings: VariableList<AttesterSlashing<E>, E::MaxAttesterSlashings>,
        attestations: VariableList<Attestation<E>, E::MaxAttestations>,
        deposits: VariableList<Deposit, E::MaxDeposits>,
        voluntary_exits: VariableList<SignedVoluntaryExit, E::MaxVoluntaryExits>,
        sync_aggregate: SyncAggregate<E>,
        execution_payload: ExecutionPayload<E>,
        bls_to_execution_changes: VariableList<SignedBLSToExecutionChange, E::MaxBlsToExecutionChanges>,
        blob_kzg_commitments: VariableList<KZGCommitment, E::MaxBlobCommitmentsPerBlock>,
        execution_requests: ExecutionRequests<E>,
    }
}

container! {
    /// `BeaconBlock`.
    BeaconBlock<E> {
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        state_root: Root,
        body: BeaconBlockBody<E>,
    }
}

container! {
    /// `SignedBeaconBlock`.
    SignedBeaconBlock<E> { message: BeaconBlock<E>, signature: BLSSignature }
}

container! {
    /// `BeaconState` (`fulu/beacon-chain.md`). Lists and vectors are `milhouse` trees; call
    /// `apply_updates()` on any mutated one before `tree_hash_root`, which panics otherwise.
    BeaconState<E> {
        genesis_time: u64,
        genesis_validators_root: Root,
        slot: Slot,
        fork: Fork,
        latest_block_header: BeaconBlockHeader,
        block_roots: Vector<Root, E::SlotsPerHistoricalRoot>,
        state_roots: Vector<Root, E::SlotsPerHistoricalRoot>,
        historical_roots: List<Root, E::HistoricalRootsLimit>,
        eth1_data: Eth1Data,
        eth1_data_votes: List<Eth1Data, E::SlotsPerEth1VotingPeriod>,
        eth1_deposit_index: u64,
        validators: List<Validator, E::ValidatorRegistryLimit>,
        balances: List<Gwei, E::ValidatorRegistryLimit>,
        randao_mixes: Vector<Bytes32, E::EpochsPerHistoricalVector>,
        slashings: Vector<Gwei, E::EpochsPerSlashingsVector>,
        previous_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
        current_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
        justification_bits: BitVector<JustificationBitsLength>,
        previous_justified_checkpoint: Checkpoint,
        current_justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        inactivity_scores: List<u64, E::ValidatorRegistryLimit>,
        current_sync_committee: SyncCommittee<E>,
        next_sync_committee: SyncCommittee<E>,
        latest_execution_payload_header: ExecutionPayloadHeader<E>,
        next_withdrawal_index: WithdrawalIndex,
        next_withdrawal_validator_index: ValidatorIndex,
        historical_summaries: List<HistoricalSummary, E::HistoricalRootsLimit>,
        deposit_requests_start_index: u64,
        deposit_balance_to_consume: Gwei,
        exit_balance_to_consume: Gwei,
        earliest_exit_epoch: Epoch,
        consolidation_balance_to_consume: Gwei,
        earliest_consolidation_epoch: Epoch,
        pending_deposits: List<PendingDeposit, E::PendingDepositsLimit>,
        pending_partial_withdrawals: List<PendingPartialWithdrawal, E::PendingPartialWithdrawalsLimit>,
        pending_consolidations: List<PendingConsolidation, E::PendingConsolidationsLimit>,
        proposer_lookahead: Vector<ValidatorIndex, E::ProposerLookaheadLength>,
    }
}
