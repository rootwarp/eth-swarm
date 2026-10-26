//! A Gloas state with a given builder registry, for the builder key feed tests (the unit tests
//! of `verify::pubkey_feed` and `tests/builders.rs` both include this file).

use consensus_types::gloas::{
    BeaconBlockHeader, BeaconState, Builder, BuilderPendingPayment, BuilderPendingWithdrawal,
    Checkpoint, Eth1Data, ExecutionPayloadBid, Fork, SyncCommittee,
};
use consensus_types::primitives::{Address, Root, FAR_FUTURE_EPOCH};
use consensus_types::EthSpec;
use milhouse::{List, ProgressiveList, Vector};
use ssz::BitVector;
use ssz_types::FixedVector;

fn bid<E: EthSpec>() -> ExecutionPayloadBid<E> {
    ExecutionPayloadBid {
        parent_block_hash: Root::ZERO,
        parent_block_root: Root::ZERO,
        block_hash: Root::ZERO,
        prev_randao: Root::ZERO,
        fee_recipient: Address::ZERO,
        gas_limit: 0,
        builder_index: 0,
        slot: 0,
        value: 0,
        execution_payment: 0,
        blob_kzg_commitments: Default::default(),
        execution_requests_root: Root::ZERO,
    }
}

/// A Gloas state with no validators and builders with keys `keys` (key `[k; 48]`).
pub fn state_with_builders<E: EthSpec>(keys: &[u8]) -> BeaconState<E> {
    let checkpoint = Checkpoint {
        epoch: 0,
        root: Root::ZERO,
    };
    let sync_committee = SyncCommittee {
        pubkeys: FixedVector::from_elem([0; 48]),
        aggregate_pubkey: [0; 48],
    };
    let builders = keys.iter().map(|k| Builder {
        pubkey: [*k; 48],
        version: 0,
        execution_address: Address::repeat_byte(*k),
        balance: 1,
        deposit_epoch: 0,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    });
    BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::ZERO,
        slot: 0,
        fork: Fork {
            previous_version: [0; 4],
            current_version: [0; 4],
            epoch: 0,
        },
        latest_block_header: BeaconBlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body_root: Root::ZERO,
        },
        block_roots: Vector::default(),
        state_roots: Vector::default(),
        historical_roots: List::default(),
        eth1_data: Eth1Data {
            deposit_root: Root::ZERO,
            deposit_count: 0,
            block_hash: Root::ZERO,
        },
        eth1_data_votes: List::default(),
        eth1_deposit_index: 0,
        validators: ProgressiveList::default(),
        balances: ProgressiveList::default(),
        randao_mixes: Vector::default(),
        slashings: Vector::default(),
        previous_epoch_participation: ProgressiveList::default(),
        current_epoch_participation: ProgressiveList::default(),
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: checkpoint.clone(),
        current_justified_checkpoint: checkpoint.clone(),
        finalized_checkpoint: checkpoint,
        inactivity_scores: ProgressiveList::default(),
        current_sync_committee: sync_committee.clone(),
        next_sync_committee: sync_committee,
        latest_block_hash: Root::ZERO,
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: List::default(),
        deposit_requests_start_index: 0,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch: 0,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: 0,
        pending_deposits: ProgressiveList::default(),
        pending_partial_withdrawals: ProgressiveList::default(),
        pending_consolidations: ProgressiveList::default(),
        proposer_lookahead: Vector::default(),
        builders: ProgressiveList::try_from_iter(builders).unwrap(),
        next_withdrawal_builder_index: 0,
        execution_payload_availability: BitVector::new(),
        builder_pending_payments: Vector::from_elem(BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: Address::ZERO,
                amount: 0,
                builder_index: 0,
            },
            proposer_index: 0,
        })
        .unwrap(),
        builder_pending_withdrawals: ProgressiveList::default(),
        latest_execution_payload_bid: bid(),
        payload_expected_withdrawals: ProgressiveList::default(),
        ptc_window: Vector::default(),
    }
}
