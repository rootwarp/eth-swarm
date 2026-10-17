//! `BeaconState::apply_updates`: every milhouse field of a mutated state is flushed, so the
//! state hashes (instead of panicking) to the root of its own re-decoded encoding.

use super::*;
use crate::preset::Minimal;
use ssz::{Decode, Encode};
use tree_hash::TreeHash;

fn checkpoint() -> Checkpoint {
    Checkpoint {
        epoch: 0,
        root: Root::ZERO,
    }
}

fn eth1_data() -> Eth1Data {
    Eth1Data {
        deposit_root: Root::ZERO,
        deposit_count: 0,
        block_hash: Root::ZERO,
    }
}

fn sync_committee<E: EthSpec>() -> SyncCommittee<E> {
    SyncCommittee {
        pubkeys: FixedVector::from_elem([0; 48]),
        aggregate_pubkey: [0; 48],
    }
}

fn withdrawal() -> BuilderPendingWithdrawal {
    BuilderPendingWithdrawal {
        fee_recipient: Address::ZERO,
        amount: 0,
        builder_index: 0,
    }
}

fn payment() -> BuilderPendingPayment {
    BuilderPendingPayment {
        weight: 0,
        withdrawal: withdrawal(),
        proposer_index: 0,
    }
}

fn zero_state<E: EthSpec>() -> BeaconState<E> {
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
        eth1_data: eth1_data(),
        eth1_data_votes: List::default(),
        eth1_deposit_index: 0,
        validators: ProgressiveList::default(),
        balances: ProgressiveList::default(),
        randao_mixes: Vector::default(),
        slashings: Vector::default(),
        previous_epoch_participation: ProgressiveList::default(),
        current_epoch_participation: ProgressiveList::default(),
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: checkpoint(),
        current_justified_checkpoint: checkpoint(),
        finalized_checkpoint: checkpoint(),
        inactivity_scores: ProgressiveList::default(),
        current_sync_committee: sync_committee(),
        next_sync_committee: sync_committee(),
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
        builders: ProgressiveList::default(),
        next_withdrawal_builder_index: 0,
        execution_payload_availability: BitVector::new(),
        builder_pending_payments: Vector::from_elem(payment()).unwrap(),
        builder_pending_withdrawals: ProgressiveList::default(),
        latest_execution_payload_bid: ExecutionPayloadBid {
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
        },
        payload_expected_withdrawals: ProgressiveList::default(),
        ptc_window: Vector::default(),
    }
}

/// Leaves a pending update in every milhouse field.
fn mutate_every_tree<E: EthSpec>(s: &mut BeaconState<E>) {
    let one = Root::repeat_byte(1);
    *s.block_roots.get_mut(0).unwrap() = one;
    *s.state_roots.get_mut(1).unwrap() = one;
    s.historical_roots.push(one).unwrap();
    s.eth1_data_votes.push(eth1_data()).unwrap();
    s.validators
        .push(Validator {
            pubkey: [2; 48],
            withdrawal_credentials: one,
            effective_balance: 32,
            slashed: false,
            activation_eligibility_epoch: 0,
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        })
        .unwrap();
    s.balances.push(32).unwrap();
    *s.randao_mixes.get_mut(2).unwrap() = one;
    *s.slashings.get_mut(3).unwrap() = 4;
    s.previous_epoch_participation.push(1).unwrap();
    s.current_epoch_participation.push(2).unwrap();
    s.inactivity_scores.push(3).unwrap();
    s.historical_summaries
        .push(HistoricalSummary {
            block_summary_root: one,
            state_summary_root: one,
        })
        .unwrap();
    s.pending_deposits
        .push(PendingDeposit {
            pubkey: [3; 48],
            withdrawal_credentials: one,
            amount: 1,
            signature: [0; 96],
            slot: 0,
        })
        .unwrap();
    s.pending_partial_withdrawals
        .push(PendingPartialWithdrawal {
            validator_index: 0,
            amount: 1,
            withdrawable_epoch: 0,
        })
        .unwrap();
    s.pending_consolidations
        .push(PendingConsolidation {
            source_index: 0,
            target_index: 1,
        })
        .unwrap();
    *s.proposer_lookahead.get_mut(0).unwrap() = 5;
    s.builders
        .push(Builder {
            pubkey: [4; 48],
            version: 0,
            execution_address: Address::ZERO,
            balance: 1,
            deposit_epoch: 0,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        })
        .unwrap();
    s.builder_pending_payments.get_mut(0).unwrap().weight = 6;
    s.builder_pending_withdrawals.push(withdrawal()).unwrap();
    s.payload_expected_withdrawals
        .push(Withdrawal {
            index: 0,
            validator_index: 0,
            address: Address::ZERO,
            amount: 1,
        })
        .unwrap();
    s.ptc_window.get_mut(0).unwrap()[0] = 7;
}

#[test]
fn apply_updates_then_hash_equals_the_hash_of_the_decoded_state() {
    let mut state = zero_state::<Minimal>();
    let untouched = state.tree_hash_root();
    mutate_every_tree(&mut state);
    state.apply_updates().unwrap();
    let root = state.tree_hash_root();
    assert_ne!(root, untouched);
    let decoded = BeaconState::<Minimal>::from_ssz_bytes(&state.as_ssz_bytes()).unwrap();
    assert_eq!(root, decoded.tree_hash_root());
    assert_eq!(decoded, state);
}

#[test]
fn apply_updates_on_a_decoded_state_is_a_no_op() {
    let state = zero_state::<Minimal>();
    let mut decoded = BeaconState::<Minimal>::from_ssz_bytes(&state.as_ssz_bytes()).unwrap();
    decoded.apply_updates().unwrap();
    assert_eq!(decoded.tree_hash_root(), state.tree_hash_root());
}
