//! Containers with the same shape in Fulu and Gloas.
//!
//! Transcribed from consensus-specs v1.7.0-beta.4 `specs/{phase0,altair,capella,electra}`; the
//! fork modules re-export them next to their fork-specific containers.

use crate::macros::container;
use crate::preset::DepositProofLength;
use crate::primitives::*;
use ssz::BitVector;
use ssz_types::FixedVector;

container! {
    /// `Checkpoint`.
    Checkpoint { epoch: Epoch, root: Root }
}

container! {
    /// `Fork`.
    Fork { previous_version: Version, current_version: Version, epoch: Epoch }
}

container! {
    /// `ForkData`: hashed into every signing domain.
    ForkData { current_version: Version, genesis_validators_root: Root }
}

container! {
    /// `SigningData`: the message a BLS signature commits to.
    SigningData { object_root: Root, domain: Domain }
}

container! {
    /// `AttestationData`.
    AttestationData {
        slot: Slot,
        index: CommitteeIndex,
        beacon_block_root: Root,
        source: Checkpoint,
        target: Checkpoint,
    }
}

container! {
    /// `SingleAttestation` (Electra).
    SingleAttestation {
        committee_index: CommitteeIndex,
        attester_index: ValidatorIndex,
        data: AttestationData,
        signature: BLSSignature,
    }
}

container! {
    /// `BeaconBlockHeader`.
    BeaconBlockHeader {
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Root,
        state_root: Root,
        body_root: Root,
    }
}

container! {
    /// `SignedBeaconBlockHeader`.
    SignedBeaconBlockHeader { message: BeaconBlockHeader, signature: BLSSignature }
}

container! {
    /// `ProposerSlashing`.
    ProposerSlashing {
        signed_header_1: SignedBeaconBlockHeader,
        signed_header_2: SignedBeaconBlockHeader,
    }
}

container! {
    /// `Eth1Data`.
    Eth1Data { deposit_root: Root, deposit_count: u64, block_hash: Hash32 }
}

container! {
    /// `Eth1Block` (validator guide).
    Eth1Block { timestamp: u64, deposit_root: Root, deposit_count: u64 }
}

container! {
    /// `PowBlock` (Bellatrix fork choice).
    PowBlock { block_hash: Hash32, parent_hash: Hash32, total_difficulty: U256 }
}

container! {
    /// `DepositMessage`.
    DepositMessage { pubkey: BLSPubkey, withdrawal_credentials: Bytes32, amount: Gwei }
}

container! {
    /// `DepositData`.
    DepositData {
        pubkey: BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: BLSSignature,
    }
}

container! {
    /// `Deposit`.
    Deposit { proof: FixedVector<Bytes32, DepositProofLength>, data: DepositData }
}

container! {
    /// `VoluntaryExit`.
    VoluntaryExit { epoch: Epoch, validator_index: ValidatorIndex }
}

container! {
    /// `SignedVoluntaryExit`.
    SignedVoluntaryExit { message: VoluntaryExit, signature: BLSSignature }
}

container! {
    /// `SyncAggregate` (Altair).
    SyncAggregate<E> {
        sync_committee_bits: BitVector<E::SyncCommitteeSize>,
        sync_committee_signature: BLSSignature,
    }
}

container! {
    /// `SyncCommittee` (Altair).
    SyncCommittee<E> {
        pubkeys: FixedVector<BLSPubkey, E::SyncCommitteeSize>,
        aggregate_pubkey: BLSPubkey,
    }
}

container! {
    /// `SyncCommitteeMessage` (Altair validator guide).
    SyncCommitteeMessage {
        slot: Slot,
        beacon_block_root: Root,
        validator_index: ValidatorIndex,
        signature: BLSSignature,
    }
}

container! {
    /// `SyncCommitteeContribution` (Altair validator guide).
    SyncCommitteeContribution<E> {
        slot: Slot,
        beacon_block_root: Root,
        subcommittee_index: u64,
        aggregation_bits: BitVector<E::SyncSubcommitteeSize>,
        signature: BLSSignature,
    }
}

container! {
    /// `ContributionAndProof` (Altair validator guide).
    ContributionAndProof<E> {
        aggregator_index: ValidatorIndex,
        contribution: SyncCommitteeContribution<E>,
        selection_proof: BLSSignature,
    }
}

container! {
    /// `SignedContributionAndProof` (Altair validator guide).
    SignedContributionAndProof<E> { message: ContributionAndProof<E>, signature: BLSSignature }
}

container! {
    /// `SyncAggregatorSelectionData` (Altair validator guide).
    SyncAggregatorSelectionData { slot: Slot, subcommittee_index: u64 }
}

container! {
    /// `BLSToExecutionChange` (Capella).
    BLSToExecutionChange {
        validator_index: ValidatorIndex,
        from_bls_pubkey: BLSPubkey,
        to_execution_address: ExecutionAddress,
    }
}

container! {
    /// `SignedBLSToExecutionChange` (Capella).
    SignedBLSToExecutionChange { message: BLSToExecutionChange, signature: BLSSignature }
}

container! {
    /// `Withdrawal` (Capella).
    Withdrawal {
        index: WithdrawalIndex,
        validator_index: ValidatorIndex,
        address: ExecutionAddress,
        amount: Gwei,
    }
}

container! {
    /// `HistoricalSummary` (Capella).
    HistoricalSummary { block_summary_root: Root, state_summary_root: Root }
}

container! {
    /// `DepositRequest` (Electra).
    DepositRequest {
        pubkey: BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: BLSSignature,
        index: u64,
    }
}

container! {
    /// `WithdrawalRequest` (Electra).
    WithdrawalRequest {
        source_address: ExecutionAddress,
        validator_pubkey: BLSPubkey,
        amount: Gwei,
    }
}

container! {
    /// `ConsolidationRequest` (Electra).
    ConsolidationRequest {
        source_address: ExecutionAddress,
        source_pubkey: BLSPubkey,
        target_pubkey: BLSPubkey,
    }
}

container! {
    /// `Validator`.
    Validator {
        pubkey: BLSPubkey,
        withdrawal_credentials: Bytes32,
        effective_balance: Gwei,
        slashed: bool,
        activation_eligibility_epoch: Epoch,
        activation_epoch: Epoch,
        exit_epoch: Epoch,
        withdrawable_epoch: Epoch,
    }
}

container! {
    /// `PendingDeposit` (Electra).
    PendingDeposit {
        pubkey: BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: BLSSignature,
        slot: Slot,
    }
}

container! {
    /// `PendingPartialWithdrawal` (Electra).
    PendingPartialWithdrawal {
        validator_index: ValidatorIndex,
        amount: Gwei,
        withdrawable_epoch: Epoch,
    }
}

container! {
    /// `PendingConsolidation` (Electra).
    PendingConsolidation { source_index: ValidatorIndex, target_index: ValidatorIndex }
}
