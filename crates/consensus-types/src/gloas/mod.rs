//! Gloas containers (`specs/gloas/beacon-chain.md`, plus `ProposerPreferences` and
//! `DataColumnSidecar` from `gloas/p2p-interface.md` and the partial-column containers from
//! `gloas/partial-columns/p2p-interface.md`).
//!
//! EIP-7688 turns most lists into `ProgressiveList`s, which have no type-level limit. Every
//! block-borne list here is a `ProgressiveVariableList<T, N>`. `N` is a bound the Gloas spec
//! itself asserts (in `process_operations`, the parent-payload asserts, gossip validation or the
//! Gloas size presets), or `U0` where beta.4 asserts none. Earlier-fork limits that Gloas dropped
//! are not carried over: rejecting at decode what the spec accepts would split consensus. `N`
//! only gates decoding (an oversized count is rejected before allocating); the encoding and
//! `hash_tree_root` do not depend on it. An unbounded list still allocates no more items than its
//! input holds, and [`crate::caps`] bounds the input. State lists are `milhouse` trees and stay
//! unbounded, as in the spec.
//!
//! Bounds, by field:
//! - `BeaconBlockBody` operations: `MAX_PROPOSER_SLASHINGS`, `MAX_ATTESTER_SLASHINGS_ELECTRA`,
//!   `MAX_ATTESTATIONS_ELECTRA`, `MAX_VOLUNTARY_EXITS`, `MAX_BLS_TO_EXECUTION_CHANGES`,
//!   `MAX_PAYLOAD_ATTESTATIONS` (`process_operations`, `verify_block_body_operation_limits`).
//!   `deposits` must be empty (`assert len(body.deposits) == 0`); its `MAX_DEPOSITS` bound only
//!   rejects blocks the spec rejects anyway.
//! - `ExecutionRequests`: `withdrawals`, `consolidations`, `builder_deposits`, `builder_exits`
//!   use the `MAX_*_REQUESTS_PER_PAYLOAD` presets (parent-payload asserts and
//!   `verify_execution_requests_limits`). `deposits` is unbounded (`U0`): Gloas asserts no count.
//! - `IndexedAttestation.attesting_indices`: `MAX_VALIDATORS_PER_COMMITTEE *
//!   MAX_COMMITTEES_PER_SLOT` (`is_valid_indexed_attestation` asserts it on the participants).
//! - `Attestation.aggregation_bits` is an unbounded `ProgressiveBitList`, as in the spec:
//!   `process_attestation` only requires `len == committee_offset`, and committee size has no
//!   cap, so a sparse attestation can be longer than the participant bound. The enclosing
//!   message's byte cap limits it; for `SignedAggregateAndProof` that is the spec constant
//!   `MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE` (see [`crate::caps`]).
//! - `ExecutionPayloadBid.blob_kzg_commitments`: `MAX_BLOB_COMMITMENTS_PER_BLOCK`, which bounds
//!   every `get_blob_parameters` limit that `process_execution_payload_bid` asserts, and is the
//!   bound behind `MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE`.
//! - `ExecutionPayload.withdrawals`: `MAX_WITHDRAWALS_PER_PAYLOAD` (`execution_payload` gossip;
//!   fork choice requires them to equal `payload_expected_withdrawals`).
//!   `transactions`, each `Transaction` and `block_access_list` are unbounded (`U0`): Gloas
//!   asserts no count or length, so only the message cap limits them.
//! - `DataColumn`, `KZGProofs` and `CellsBitList` (`DataColumnSidecar`, the partial-column
//!   containers) are unbounded `ProgressiveList`s / `ProgressiveBitList`s (EIP-7688): Gloas
//!   asserts only that their lengths match the bid's commitments, which is a validation rule,
//!   not a type bound. The `DataColumnSidecar` byte cap is
//!   `compute_max_data_column_sidecar_size()` over the configured blob schedule
//!   (`gloas/p2p-interface.md` L324-341, [`crate::caps::NetworkCaps`]).

pub use crate::common::*;

use crate::macros::container;
use crate::preset::{EthSpec, JustificationBitsLength};
use crate::primitives::*;
use milhouse::{List, ProgressiveList, Vector};
use ssz::{BitVector, ProgressiveBitList};
use ssz_types::typenum::U0;
use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};

/// `Transaction` (EIP-7688 `ProgressiveList[Byte]`): no Gloas bound.
///
/// Decode memory: an empty transaction is 4 input bytes and a 24-byte heap header, and a 1-byte
/// transaction adds its own small allocation. Cap-sized envelopes of these are the worst cases of
/// the decode-memory budget in [`crate::caps`]: at most 18 bytes of peak heap per input byte in
/// requested bytes (empty transactions), which exclude allocator overhead, and at most 21 in the
/// allocator-adjusted heap model that counts each allocation as at least 32 bytes (1-byte
/// transactions). Neither is a process-RSS bound.
pub type Transaction = ProgressiveVariableList<u8, U0>;
/// `BlockAccessList` (EIP-7928): no spec bound.
pub type BlockAccessList = ProgressiveVariableList<u8, U0>;
/// `PayloadTimelinessCommittee`.
pub type PayloadTimelinessCommittee<E> = FixedVector<ValidatorIndex, <E as EthSpec>::PtcSize>;
/// `DataColumn` (EIP-7688 `ProgressiveList[Cell]`): no Gloas bound.
pub type DataColumn<E> = ProgressiveVariableList<Cell<E>, U0>;
/// `KZGProofs` (EIP-7688 `ProgressiveList[KZGProof]`): no Gloas bound.
pub type KZGProofs = ProgressiveVariableList<KZGProof, U0>;
/// `CellsBitList` (EIP-7688 `ProgressiveBitList`, `gloas/partial-columns/p2p-interface.md`).
pub type CellsBitList = ProgressiveBitList;

container! {
    /// `Attestation` (EIP-7688 progressive container).
    #[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1))]
    Attestation<E> {
        aggregation_bits: ProgressiveBitList,
        data: AttestationData,
        signature: BLSSignature,
        committee_bits: BitVector<E::MaxCommitteesPerSlot>,
    }
}

container! {
    /// `IndexedAttestation` (EIP-7688 progressive container).
    #[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1))]
    IndexedAttestation<E> {
        attesting_indices: ProgressiveVariableList<ValidatorIndex, E::MaxValidatorsPerSlot>,
        data: AttestationData,
        signature: BLSSignature,
    }
}

container! {
    /// `AttesterSlashing`.
    AttesterSlashing<E> {
        attestation_1: IndexedAttestation<E>,
        attestation_2: IndexedAttestation<E>,
    }
}

container! {
    /// `AggregateAndProof`.
    AggregateAndProof<E> {
        aggregator_index: ValidatorIndex,
        aggregate: Attestation<E>,
        selection_proof: BLSSignature,
    }
}

container! {
    /// `SignedAggregateAndProof`.
    SignedAggregateAndProof<E> { message: AggregateAndProof<E>, signature: BLSSignature }
}

container! {
    /// `Builder`.
    Builder {
        pubkey: BLSPubkey,
        version: u8,
        execution_address: ExecutionAddress,
        balance: Gwei,
        deposit_epoch: Epoch,
        withdrawable_epoch: Epoch,
    }
}

container! {
    /// `BuilderPendingWithdrawal`.
    BuilderPendingWithdrawal {
        fee_recipient: ExecutionAddress,
        amount: Gwei,
        builder_index: BuilderIndex,
    }
}

container! {
    /// `BuilderPendingPayment`.
    BuilderPendingPayment {
        weight: Gwei,
        withdrawal: BuilderPendingWithdrawal,
        proposer_index: ValidatorIndex,
    }
}

container! {
    /// `BuilderDepositRequest` (EIP-8282).
    BuilderDepositRequest {
        pubkey: BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: BLSSignature,
    }
}

container! {
    /// `BuilderExitRequest` (EIP-8282).
    BuilderExitRequest { source_address: ExecutionAddress, pubkey: BLSPubkey }
}

container! {
    /// `PayloadAttestationData`.
    PayloadAttestationData {
        beacon_block_root: Root,
        slot: Slot,
        payload_present: bool,
        blob_data_available: bool,
    }
}

container! {
    /// `PayloadAttestation`.
    #[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1))]
    PayloadAttestation<E> {
        aggregation_bits: BitVector<E::PtcSize>,
        data: PayloadAttestationData,
        signature: BLSSignature,
    }
}

container! {
    /// `PayloadAttestationMessage`.
    PayloadAttestationMessage {
        validator_index: ValidatorIndex,
        data: PayloadAttestationData,
        signature: BLSSignature,
    }
}

container! {
    /// `IndexedPayloadAttestation`.
    #[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1))]
    IndexedPayloadAttestation<E> {
        attesting_indices: VariableList<ValidatorIndex, E::PtcSize>,
        data: PayloadAttestationData,
        signature: BLSSignature,
    }
}

container! {
    /// `ExecutionPayloadBid`.
    #[tree_hash(
        struct_behaviour = "progressive_container",
        active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
    )]
    ExecutionPayloadBid<E> {
        parent_block_hash: Hash32,
        parent_block_root: Root,
        block_hash: Hash32,
        prev_randao: Bytes32,
        fee_recipient: ExecutionAddress,
        gas_limit: u64,
        builder_index: BuilderIndex,
        slot: Slot,
        value: Gwei,
        execution_payment: Gwei,
        blob_kzg_commitments: ProgressiveVariableList<KZGCommitment, E::MaxBlobCommitmentsPerBlock>,
        execution_requests_root: Root,
    }
}

container! {
    /// `SignedExecutionPayloadBid`.
    SignedExecutionPayloadBid<E> { message: ExecutionPayloadBid<E>, signature: BLSSignature }
}

container! {
    /// `ExecutionPayload` (EIP-7688 progressive container).
    #[tree_hash(
        struct_behaviour = "progressive_container",
        active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
    )]
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
        transactions: ProgressiveVariableList<Transaction, U0>,
        withdrawals: ProgressiveVariableList<Withdrawal, E::MaxWithdrawalsPerPayload>,
        blob_gas_used: u64,
        excess_blob_gas: u64,
        block_access_list: BlockAccessList,
        slot_number: u64,
    }
}

container! {
    /// `ExecutionRequests` (EIP-7688 progressive container).
    #[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1, 1))]
    ExecutionRequests<E> {
        deposits: ProgressiveVariableList<DepositRequest, U0>,
        withdrawals: ProgressiveVariableList<WithdrawalRequest, E::MaxWithdrawalRequestsPerPayload>,
        consolidations:
            ProgressiveVariableList<ConsolidationRequest, E::MaxConsolidationRequestsPerPayload>,
        builder_deposits:
            ProgressiveVariableList<BuilderDepositRequest, E::MaxBuilderDepositRequestsPerPayload>,
        builder_exits:
            ProgressiveVariableList<BuilderExitRequest, E::MaxBuilderExitRequestsPerPayload>,
    }
}

container! {
    /// `NewPayloadRequest` (EIP-7688 progressive container).
    #[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1))]
    NewPayloadRequest<E> {
        execution_payload: ExecutionPayload<E>,
        versioned_hashes: VariableList<VersionedHash, E::MaxBlobCommitmentsPerBlock>,
        parent_beacon_block_root: Root,
        execution_requests: ExecutionRequests<E>,
    }
}

container! {
    /// `ExecutionPayloadEnvelope`.
    #[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1, 1))]
    ExecutionPayloadEnvelope<E> {
        payload: ExecutionPayload<E>,
        execution_requests: ExecutionRequests<E>,
        builder_index: BuilderIndex,
        beacon_block_root: Root,
        parent_beacon_block_root: Root,
    }
}

container! {
    /// `SignedExecutionPayloadEnvelope`.
    SignedExecutionPayloadEnvelope<E> {
        message: ExecutionPayloadEnvelope<E>,
        signature: BLSSignature,
    }
}

container! {
    /// `ProposerPreferences` (`gloas/p2p-interface.md`).
    ProposerPreferences {
        dependent_root: Root,
        proposal_slot: Slot,
        validator_index: ValidatorIndex,
        fee_recipient: ExecutionAddress,
        target_gas_limit: u64,
    }
}

container! {
    /// `SignedProposerPreferences` (`gloas/p2p-interface.md`).
    SignedProposerPreferences { message: ProposerPreferences, signature: BLSSignature }
}

container! {
    /// `DataColumnSidecar` (`gloas/p2p-interface.md`): the Fulu sidecar without
    /// `kzg_commitments`, `signed_block_header` and `kzg_commitments_inclusion_proof`, and with
    /// the block's `slot` and `beacon_block_root`.
    DataColumnSidecar<E> {
        index: ColumnIndex,
        column: DataColumn<E>,
        kzg_proofs: KZGProofs,
        slot: Slot,
        beacon_block_root: Root,
    }
}

container! {
    /// `PartialDataColumnSidecar` (`gloas/partial-columns/p2p-interface.md`): no `header`.
    PartialDataColumnSidecar<E> {
        cells_present_bitmap: CellsBitList,
        partial_column: DataColumn<E>,
        kzg_proofs: KZGProofs,
    }
}

container! {
    /// `PartialDataColumnPartsMetadata` (`gloas/partial-columns/p2p-interface.md`).
    PartialDataColumnPartsMetadata { available: CellsBitList, requests: CellsBitList }
}

container! {
    /// `PartialDataColumnGroupID` (`gloas/partial-columns/p2p-interface.md`): adds `slot`.
    PartialDataColumnGroupID { beacon_block_root: Root, slot: Slot }
}

container! {
    /// `BeaconBlockBody` (EIP-7688 progressive container).
    #[tree_hash(
        struct_behaviour = "progressive_container",
        active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
    )]
    BeaconBlockBody<E> {
        randao_reveal: BLSSignature,
        eth1_data: Eth1Data,
        graffiti: Bytes32,
        proposer_slashings: ProgressiveVariableList<ProposerSlashing, E::MaxProposerSlashings>,
        attester_slashings: ProgressiveVariableList<AttesterSlashing<E>, E::MaxAttesterSlashings>,
        attestations: ProgressiveVariableList<Attestation<E>, E::MaxAttestations>,
        deposits: ProgressiveVariableList<Deposit, E::MaxDeposits>,
        voluntary_exits: ProgressiveVariableList<SignedVoluntaryExit, E::MaxVoluntaryExits>,
        sync_aggregate: SyncAggregate<E>,
        bls_to_execution_changes:
            ProgressiveVariableList<SignedBLSToExecutionChange, E::MaxBlsToExecutionChanges>,
        signed_execution_payload_bid: SignedExecutionPayloadBid<E>,
        payload_attestations: ProgressiveVariableList<PayloadAttestation<E>, E::MaxPayloadAttestations>,
        parent_execution_requests: ExecutionRequests<E>,
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
    /// `BeaconState` (EIP-7688 progressive container). Lists and vectors are `milhouse` trees;
    /// call `apply_updates()` on any mutated one before `tree_hash_root`, which panics otherwise.
    #[tree_hash(
        struct_behaviour = "progressive_container",
        active_fields(
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        )
    )]
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
        validators: ProgressiveList<Validator>,
        balances: ProgressiveList<Gwei>,
        randao_mixes: Vector<Bytes32, E::EpochsPerHistoricalVector>,
        slashings: Vector<Gwei, E::EpochsPerSlashingsVector>,
        previous_epoch_participation: ProgressiveList<ParticipationFlags>,
        current_epoch_participation: ProgressiveList<ParticipationFlags>,
        justification_bits: BitVector<JustificationBitsLength>,
        previous_justified_checkpoint: Checkpoint,
        current_justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        inactivity_scores: ProgressiveList<u64>,
        current_sync_committee: SyncCommittee<E>,
        next_sync_committee: SyncCommittee<E>,
        latest_block_hash: Hash32,
        next_withdrawal_index: WithdrawalIndex,
        next_withdrawal_validator_index: ValidatorIndex,
        historical_summaries: List<HistoricalSummary, E::HistoricalRootsLimit>,
        deposit_requests_start_index: u64,
        deposit_balance_to_consume: Gwei,
        exit_balance_to_consume: Gwei,
        earliest_exit_epoch: Epoch,
        consolidation_balance_to_consume: Gwei,
        earliest_consolidation_epoch: Epoch,
        pending_deposits: ProgressiveList<PendingDeposit>,
        pending_partial_withdrawals: ProgressiveList<PendingPartialWithdrawal>,
        pending_consolidations: ProgressiveList<PendingConsolidation>,
        proposer_lookahead: Vector<ValidatorIndex, E::ProposerLookaheadLength>,
        builders: ProgressiveList<Builder>,
        next_withdrawal_builder_index: BuilderIndex,
        execution_payload_availability: BitVector<E::SlotsPerHistoricalRoot>,
        builder_pending_payments: Vector<BuilderPendingPayment, E::BuilderPendingPaymentsLength>,
        builder_pending_withdrawals: ProgressiveList<BuilderPendingWithdrawal>,
        latest_execution_payload_bid: ExecutionPayloadBid<E>,
        payload_expected_withdrawals: ProgressiveList<Withdrawal>,
        ptc_window: Vector<PayloadTimelinessCommittee<E>, E::PtcWindowLength>,
    }
}

impl<E: EthSpec> BeaconState<E> {
    /// Flushes the pending updates of every `milhouse` field, as `tree_hash_root` requires (it
    /// panics on a tree with pending updates). A freshly decoded state has none.
    ///
    /// The destructuring names every field, so adding one to the container does not compile
    /// until it is listed here: as a tree to flush, or as `_` for a plain field.
    pub fn apply_updates(&mut self) -> Result<(), milhouse::Error> {
        let BeaconState {
            genesis_time: _,
            genesis_validators_root: _,
            slot: _,
            fork: _,
            latest_block_header: _,
            block_roots,
            state_roots,
            historical_roots,
            eth1_data: _,
            eth1_data_votes,
            eth1_deposit_index: _,
            validators,
            balances,
            randao_mixes,
            slashings,
            previous_epoch_participation,
            current_epoch_participation,
            justification_bits: _,
            previous_justified_checkpoint: _,
            current_justified_checkpoint: _,
            finalized_checkpoint: _,
            inactivity_scores,
            current_sync_committee: _,
            next_sync_committee: _,
            latest_block_hash: _,
            next_withdrawal_index: _,
            next_withdrawal_validator_index: _,
            historical_summaries,
            deposit_requests_start_index: _,
            deposit_balance_to_consume: _,
            exit_balance_to_consume: _,
            earliest_exit_epoch: _,
            consolidation_balance_to_consume: _,
            earliest_consolidation_epoch: _,
            pending_deposits,
            pending_partial_withdrawals,
            pending_consolidations,
            proposer_lookahead,
            builders,
            next_withdrawal_builder_index: _,
            execution_payload_availability: _,
            builder_pending_payments,
            builder_pending_withdrawals,
            latest_execution_payload_bid: _,
            payload_expected_withdrawals,
            ptc_window,
        } = self;
        block_roots.apply_updates()?;
        state_roots.apply_updates()?;
        historical_roots.apply_updates()?;
        eth1_data_votes.apply_updates()?;
        validators.apply_updates()?;
        balances.apply_updates()?;
        randao_mixes.apply_updates()?;
        slashings.apply_updates()?;
        previous_epoch_participation.apply_updates()?;
        current_epoch_participation.apply_updates()?;
        inactivity_scores.apply_updates()?;
        historical_summaries.apply_updates()?;
        pending_deposits.apply_updates()?;
        pending_partial_withdrawals.apply_updates()?;
        pending_consolidations.apply_updates()?;
        proposer_lookahead.apply_updates()?;
        builders.apply_updates()?;
        builder_pending_payments.apply_updates()?;
        builder_pending_withdrawals.apply_updates()?;
        payload_expected_withdrawals.apply_updates()?;
        ptc_window.apply_updates()
    }
}

#[cfg(test)]
mod tests;
