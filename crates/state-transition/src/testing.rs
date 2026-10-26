//! Test inputs: a Gloas genesis-like state with a given registry, and empty blocks.

use crate::caches::{initialize_proposer_lookahead, initialize_ptc_window};
use crate::Preset;
use consensus_types::gloas::*;
use consensus_types::primitives::{Address, Bytes32, Gwei, Root, FAR_FUTURE_EPOCH};
use milhouse::{List, ProgressiveList, Vector};
use ssz::BitVector;
use ssz_types::FixedVector;

/// A Gloas state at slot 0 whose validators have `effective_balances` (each also its
/// balance), all active from epoch 0. Every RANDAO mix is `mix`. The proposer lookahead and
/// the PTC window are initialized as at genesis.
pub(crate) fn genesis_state_with_mix<E: Preset>(
    effective_balances: &[Gwei],
    mix: Bytes32,
) -> BeaconState<E> {
    let mut state = registry_state(effective_balances, mix);
    refresh_lookahead(&mut state);
    state
}

/// [`genesis_state_with_mix`] with a zero proposer lookahead and PTC window, for registries
/// too small to give every slot a non-empty committee (the PTC of such a slot does not exist).
pub(crate) fn registry_state<E: Preset>(
    effective_balances: &[Gwei],
    mix: Bytes32,
) -> BeaconState<E> {
    let validators = effective_balances.iter().enumerate().map(|(i, &b)| {
        let mut pubkey = [0u8; 48];
        pubkey[..8].copy_from_slice(&(i as u64).to_le_bytes());
        Validator {
            pubkey,
            withdrawal_credentials: Bytes32::ZERO,
            effective_balance: b,
            slashed: false,
            activation_eligibility_epoch: 0,
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        }
    });
    let checkpoint = Checkpoint {
        epoch: 0,
        root: Root::ZERO,
    };
    let eth1_data = Eth1Data {
        deposit_root: Root::ZERO,
        deposit_count: 0,
        block_hash: mix,
    };
    let sync_committee = SyncCommittee {
        pubkeys: FixedVector::from_elem([0; 48]),
        aggregate_pubkey: [0; 48],
    };
    let payment = BuilderPendingPayment {
        weight: 0,
        withdrawal: BuilderPendingWithdrawal {
            fee_recipient: Address::ZERO,
            amount: 0,
            builder_index: 0,
        },
        proposer_index: 0,
    };
    BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::repeat_byte(0x42),
        slot: 0,
        fork: Fork {
            previous_version: [0x07, 0, 0, 0x01],
            current_version: [0x07, 0, 0, 0x01],
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
        eth1_data,
        eth1_data_votes: List::default(),
        eth1_deposit_index: 0,
        validators: ProgressiveList::try_from_iter(validators).unwrap(),
        balances: ProgressiveList::try_from_iter(effective_balances.iter().copied()).unwrap(),
        randao_mixes: Vector::from_elem(mix).unwrap(),
        slashings: Vector::default(),
        previous_epoch_participation: ProgressiveList::try_from_iter(
            effective_balances.iter().map(|_| 0),
        )
        .unwrap(),
        current_epoch_participation: ProgressiveList::try_from_iter(
            effective_balances.iter().map(|_| 0),
        )
        .unwrap(),
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: checkpoint.clone(),
        current_justified_checkpoint: checkpoint.clone(),
        finalized_checkpoint: checkpoint,
        inactivity_scores: ProgressiveList::try_from_iter(effective_balances.iter().map(|_| 0))
            .unwrap(),
        current_sync_committee: sync_committee.clone(),
        next_sync_committee: sync_committee,
        latest_block_hash: Root::ZERO,
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: List::default(),
        deposit_requests_start_index: u64::MAX,
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
        builder_pending_payments: Vector::from_elem(payment).unwrap(),
        builder_pending_withdrawals: ProgressiveList::default(),
        latest_execution_payload_bid: empty_bid(0),
        payload_expected_withdrawals: ProgressiveList::default(),
        ptc_window: Vector::default(),
    }
}

/// [`genesis_state_with_mix`] with a fixed mix.
pub(crate) fn genesis_state<E: Preset>(effective_balances: &[Gwei]) -> BeaconState<E> {
    genesis_state_with_mix(effective_balances, Bytes32::repeat_byte(0x5a))
}

/// Sets `proposer_lookahead` and `ptc_window` as the fork upgrade does at the state's epoch.
pub(crate) fn refresh_lookahead<E: Preset>(state: &mut BeaconState<E>) {
    state.proposer_lookahead = Vector::new(initialize_proposer_lookahead(state).unwrap()).unwrap();
    state.ptc_window = Vector::new(initialize_ptc_window(state).unwrap()).unwrap();
}

/// An empty Gloas bid for `slot`.
fn empty_bid<E: Preset>(slot: u64) -> ExecutionPayloadBid<E> {
    ExecutionPayloadBid {
        parent_block_hash: Root::ZERO,
        parent_block_root: Root::ZERO,
        block_hash: Root::ZERO,
        prev_randao: Root::ZERO,
        fee_recipient: Address::ZERO,
        gas_limit: 0,
        builder_index: 0,
        slot,
        value: 0,
        execution_payment: 0,
        blob_kzg_commitments: Default::default(),
        execution_requests_root: Root::ZERO,
    }
}

/// A block at `slot` by `proposer_index` with an empty body, a zero `state_root` and the
/// signature `[0x11; 96]`.
pub(crate) fn signed_block<E: Preset>(slot: u64, proposer_index: u64) -> SignedBeaconBlock<E> {
    let body = BeaconBlockBody {
        randao_reveal: [0; 96],
        eth1_data: Eth1Data {
            deposit_root: Root::ZERO,
            deposit_count: 0,
            block_hash: Root::ZERO,
        },
        graffiti: Bytes32::ZERO,
        proposer_slashings: Default::default(),
        attester_slashings: Default::default(),
        attestations: Default::default(),
        deposits: Default::default(),
        voluntary_exits: Default::default(),
        sync_aggregate: SyncAggregate {
            sync_committee_bits: BitVector::new(),
            sync_committee_signature: [0; 96],
        },
        bls_to_execution_changes: Default::default(),
        signed_execution_payload_bid: SignedExecutionPayloadBid {
            message: empty_bid(slot),
            signature: [0; 96],
        },
        payload_attestations: Default::default(),
        parent_execution_requests: ExecutionRequests {
            deposits: Default::default(),
            withdrawals: Default::default(),
            consolidations: Default::default(),
            builder_deposits: Default::default(),
            builder_exits: Default::default(),
        },
    };
    SignedBeaconBlock {
        message: BeaconBlock {
            slot,
            proposer_index,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body,
        },
        signature: [0x11; 96],
    }
}
