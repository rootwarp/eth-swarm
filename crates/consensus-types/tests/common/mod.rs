//! Small but complete Fulu and Gloas objects for the integration tests.

#![allow(dead_code)]

use consensus_types::primitives::*;
use consensus_types::{fulu, gloas, EthSpec};
use ssz::BitVector;
use ssz_types::FixedVector;

pub const SIG: BLSSignature = [0xaa; 96];
pub const PUBKEY: BLSPubkey = [0xbb; 48];

pub fn root(byte: u8) -> Root {
    B256::repeat_byte(byte)
}

fn header(slot: Slot) -> fulu::BeaconBlockHeader {
    fulu::BeaconBlockHeader {
        slot,
        proposer_index: 3,
        parent_root: root(1),
        state_root: root(2),
        body_root: root(3),
    }
}

fn sync_aggregate<E: EthSpec>() -> fulu::SyncAggregate<E> {
    fulu::SyncAggregate {
        sync_committee_bits: BitVector::new(),
        sync_committee_signature: SIG,
    }
}

fn sync_committee<E: EthSpec>() -> fulu::SyncCommittee<E> {
    fulu::SyncCommittee {
        pubkeys: FixedVector::from_elem(PUBKEY),
        aggregate_pubkey: PUBKEY,
    }
}

fn eth1_data() -> fulu::Eth1Data {
    fulu::Eth1Data {
        deposit_root: root(4),
        deposit_count: 5,
        block_hash: root(6),
    }
}

pub fn fulu_execution_payload<E: EthSpec>() -> fulu::ExecutionPayload<E> {
    fulu::ExecutionPayload {
        parent_hash: root(7),
        fee_recipient: Address::repeat_byte(8),
        state_root: root(9),
        receipts_root: root(10),
        logs_bloom: FixedVector::default(),
        prev_randao: root(11),
        block_number: 12,
        gas_limit: 13,
        gas_used: 14,
        timestamp: 15,
        extra_data: vec![1, 2, 3].try_into().unwrap(),
        base_fee_per_gas: U256::from(16),
        block_hash: root(17),
        transactions: vec![vec![0xde, 0xad].try_into().unwrap()]
            .try_into()
            .unwrap(),
        withdrawals: Default::default(),
        blob_gas_used: 18,
        excess_blob_gas: 19,
    }
}

pub fn fulu_block<E: EthSpec>(slot: Slot) -> fulu::SignedBeaconBlock<E> {
    fulu::SignedBeaconBlock {
        message: fulu::BeaconBlock {
            slot,
            proposer_index: 3,
            parent_root: root(1),
            state_root: root(2),
            body: fulu::BeaconBlockBody {
                randao_reveal: SIG,
                eth1_data: eth1_data(),
                graffiti: root(0x20),
                proposer_slashings: Default::default(),
                attester_slashings: Default::default(),
                attestations: Default::default(),
                deposits: Default::default(),
                voluntary_exits: Default::default(),
                sync_aggregate: sync_aggregate(),
                execution_payload: fulu_execution_payload(),
                bls_to_execution_changes: Default::default(),
                blob_kzg_commitments: vec![PUBKEY].try_into().unwrap(),
                execution_requests: fulu::ExecutionRequests {
                    deposits: Default::default(),
                    withdrawals: Default::default(),
                    consolidations: vec![fulu::ConsolidationRequest {
                        source_address: Address::repeat_byte(0x21),
                        source_pubkey: PUBKEY,
                        target_pubkey: PUBKEY,
                    }]
                    .try_into()
                    .unwrap(),
                },
            },
        },
        signature: SIG,
    }
}

pub fn gloas_execution_payload<E: EthSpec>() -> gloas::ExecutionPayload<E> {
    let fulu = fulu_execution_payload::<E>();
    gloas::ExecutionPayload {
        parent_hash: fulu.parent_hash,
        fee_recipient: fulu.fee_recipient,
        state_root: fulu.state_root,
        receipts_root: fulu.receipts_root,
        logs_bloom: fulu.logs_bloom,
        prev_randao: fulu.prev_randao,
        block_number: fulu.block_number,
        gas_limit: fulu.gas_limit,
        gas_used: fulu.gas_used,
        timestamp: fulu.timestamp,
        extra_data: fulu.extra_data,
        base_fee_per_gas: fulu.base_fee_per_gas,
        block_hash: fulu.block_hash,
        transactions: vec![vec![0xbe, 0xef].try_into().unwrap()]
            .try_into()
            .unwrap(),
        withdrawals: Default::default(),
        blob_gas_used: fulu.blob_gas_used,
        excess_blob_gas: fulu.excess_blob_gas,
        block_access_list: vec![0xc0].try_into().unwrap(),
        slot_number: 21,
    }
}

pub fn gloas_bid<E: EthSpec>(slot: Slot) -> gloas::ExecutionPayloadBid<E> {
    gloas::ExecutionPayloadBid {
        parent_block_hash: root(0x30),
        parent_block_root: root(0x31),
        block_hash: root(0x32),
        prev_randao: root(0x33),
        fee_recipient: Address::repeat_byte(0x34),
        gas_limit: 35,
        builder_index: 36,
        slot,
        value: 37,
        execution_payment: 38,
        blob_kzg_commitments: vec![PUBKEY].try_into().unwrap(),
        execution_requests_root: root(0x39),
    }
}

fn gloas_execution_requests<E: EthSpec>() -> gloas::ExecutionRequests<E> {
    gloas::ExecutionRequests {
        deposits: Default::default(),
        withdrawals: Default::default(),
        consolidations: Default::default(),
        builder_deposits: Default::default(),
        builder_exits: vec![gloas::BuilderExitRequest {
            source_address: Address::repeat_byte(0x3a),
            pubkey: PUBKEY,
        }]
        .try_into()
        .unwrap(),
    }
}

pub fn gloas_block<E: EthSpec>(slot: Slot) -> gloas::SignedBeaconBlock<E> {
    gloas::SignedBeaconBlock {
        message: gloas::BeaconBlock {
            slot,
            proposer_index: 3,
            parent_root: root(1),
            state_root: root(2),
            body: gloas::BeaconBlockBody {
                randao_reveal: SIG,
                eth1_data: eth1_data(),
                graffiti: root(0x20),
                proposer_slashings: Default::default(),
                attester_slashings: Default::default(),
                attestations: Default::default(),
                deposits: Default::default(),
                voluntary_exits: Default::default(),
                sync_aggregate: sync_aggregate(),
                bls_to_execution_changes: Default::default(),
                signed_execution_payload_bid: gloas::SignedExecutionPayloadBid {
                    message: gloas_bid(slot),
                    signature: SIG,
                },
                payload_attestations: Default::default(),
                parent_execution_requests: gloas_execution_requests(),
            },
        },
        signature: SIG,
    }
}

fn checkpoint(epoch: Epoch) -> fulu::Checkpoint {
    fulu::Checkpoint {
        epoch,
        root: root(0x40),
    }
}

fn fork(epoch: Epoch) -> fulu::Fork {
    fulu::Fork {
        previous_version: [1, 0, 0, 0],
        current_version: [2, 0, 0, 0],
        epoch,
    }
}

fn validator() -> fulu::Validator {
    fulu::Validator {
        pubkey: PUBKEY,
        withdrawal_credentials: root(0x41),
        effective_balance: 32_000_000_000,
        slashed: false,
        activation_eligibility_epoch: 0,
        activation_epoch: 0,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}

pub fn fulu_state<E: EthSpec>(slot: Slot) -> fulu::BeaconState<E> {
    let payload = fulu_execution_payload::<E>();
    fulu::BeaconState {
        genesis_time: 1,
        genesis_validators_root: root(0x42),
        slot,
        fork: fork(E::epoch_at_slot(slot)),
        latest_block_header: header(slot),
        block_roots: Default::default(),
        state_roots: Default::default(),
        historical_roots: Default::default(),
        eth1_data: eth1_data(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: milhouse::List::new(vec![validator()]).unwrap(),
        balances: milhouse::List::new(vec![32_000_000_000]).unwrap(),
        randao_mixes: Default::default(),
        slashings: Default::default(),
        previous_epoch_participation: milhouse::List::new(vec![0]).unwrap(),
        current_epoch_participation: milhouse::List::new(vec![7]).unwrap(),
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: checkpoint(0),
        current_justified_checkpoint: checkpoint(0),
        finalized_checkpoint: checkpoint(0),
        inactivity_scores: milhouse::List::new(vec![0]).unwrap(),
        current_sync_committee: sync_committee(),
        next_sync_committee: sync_committee(),
        latest_execution_payload_header: fulu::ExecutionPayloadHeader {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: root(0x43),
            withdrawals_root: root(0x44),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
        },
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: Default::default(),
        deposit_requests_start_index: 0,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch: 0,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: 0,
        pending_deposits: Default::default(),
        pending_partial_withdrawals: Default::default(),
        pending_consolidations: Default::default(),
        proposer_lookahead: Default::default(),
    }
}

pub fn gloas_state<E: EthSpec>(slot: Slot) -> gloas::BeaconState<E> {
    gloas::BeaconState {
        genesis_time: 1,
        genesis_validators_root: root(0x42),
        slot,
        fork: fork(E::epoch_at_slot(slot)),
        latest_block_header: header(slot),
        block_roots: Default::default(),
        state_roots: Default::default(),
        historical_roots: Default::default(),
        eth1_data: eth1_data(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: milhouse::ProgressiveList::new(vec![validator()]).unwrap(),
        balances: milhouse::ProgressiveList::new(vec![32_000_000_000]).unwrap(),
        randao_mixes: Default::default(),
        slashings: Default::default(),
        previous_epoch_participation: milhouse::ProgressiveList::new(vec![0]).unwrap(),
        current_epoch_participation: milhouse::ProgressiveList::new(vec![7]).unwrap(),
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: checkpoint(0),
        current_justified_checkpoint: checkpoint(0),
        finalized_checkpoint: checkpoint(0),
        inactivity_scores: milhouse::ProgressiveList::new(vec![0]).unwrap(),
        current_sync_committee: sync_committee(),
        next_sync_committee: sync_committee(),
        latest_block_hash: root(0x45),
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: Default::default(),
        deposit_requests_start_index: 0,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch: 0,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: 0,
        pending_deposits: Default::default(),
        pending_partial_withdrawals: Default::default(),
        pending_consolidations: Default::default(),
        proposer_lookahead: Default::default(),
        builders: Default::default(),
        next_withdrawal_builder_index: 0,
        execution_payload_availability: BitVector::new(),
        builder_pending_payments: milhouse::Vector::from_elem(gloas::BuilderPendingPayment {
            weight: 0,
            withdrawal: gloas::BuilderPendingWithdrawal {
                fee_recipient: Address::ZERO,
                amount: 0,
                builder_index: 0,
            },
            proposer_index: 0,
        })
        .unwrap(),
        builder_pending_withdrawals: Default::default(),
        latest_execution_payload_bid: gloas_bid(slot),
        payload_expected_withdrawals: Default::default(),
        ptc_window: Default::default(),
    }
}
