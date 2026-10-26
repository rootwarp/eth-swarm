//! The builder payment lifecycle on a minimal state, through the real handlers:
//!
//! 1. A block at slot 17 (epoch 2): `process_block_header` and a builder bid
//!    (`process_execution_payload_bid`, G L2162-2215), which records a pending payment.
//! 2. Same-slot attestations for that block at slot 18 (`process_attestation`, G L2396-2480),
//!    which add the effective balance of each new attester to the weight of the payment.
//! 3. The epoch boundaries at slots 24 and 32 (`process_slots`, with
//!    `process_builder_pending_payments`, G L1719-1731). The first one moves the payment to
//!    the first half of the vector. The second one pays it or drops it on the quorum
//!    (`get_builder_payment_quorum_threshold`, G L1433-1439).
//! 4. The builder withdrawals (`get_builder_withdrawals` and `process_withdrawals`).
//!
//! The paths: quorum reached (the withdrawal is paid), no quorum (the payment is dropped), and
//! the proposer slashed between the two boundaries (consensus-specs PR 5719: `slash_validator`
//! empties the payments of the blocks of the slashed proposer).
//!
//! These handlers make no BLS call: the block runs their signature sets in one batch before
//! the steps. The epoch boundaries ask for a verdict only for a pending deposit of a new key,
//! and for an aggregate key only at a sync committee period. This state has neither, so the
//! BLS context of the test fails each call ([`NoBls`]). Thus the test also proves that the
//! lifecycle asks the backend for nothing.

use consensus_types::common::{
    BeaconBlockHeader, Checkpoint, Eth1Data, Fork, ProposerSlashing, SignedBeaconBlockHeader,
    SyncCommittee, Validator,
};
use consensus_types::gloas::{
    Attestation, AttestationData, BeaconBlock, BeaconBlockBody, BeaconState, Builder,
    BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid, ExecutionRequests,
    SignedExecutionPayloadBid, SyncAggregate,
};
use consensus_types::primitives::{
    Address, BLSPubkey, Bytes32, Epoch, Gwei, Root, Slot, FAR_FUTURE_EPOCH,
};
use consensus_types::{EthSpec, Minimal};
use milhouse::{List, ProgressiveList, Vector};
use ssz::{BitVector, ProgressiveBitList};
use ssz_types::FixedVector;
use state_transition::accessors::{
    convert_builder_index_to_validator_index, get_block_root, get_block_root_at_slot,
    get_randao_mix, TotalActiveBalanceCache,
};
use state_transition::caches::{
    get_beacon_proposer_index, initialize_proposer_lookahead, initialize_ptc_window, CommitteeCache,
};
use state_transition::mutators::empty_payment;
use state_transition::per_block::withdrawals::{get_builder_withdrawals, process_withdrawals};
use state_transition::per_block::{
    process_attestation_with, process_block_header, process_execution_payload_bid,
    process_proposer_slashing, BlockContext,
};
use state_transition::per_epoch::gloas::get_builder_payment_quorum_threshold;
use state_transition::per_slot::process_slots;
use state_transition::signatures::G2_POINT_AT_INFINITY;
use state_transition::{
    AggregationError, BackendError, BlsContext, PubkeyAggregator, SignatureBackend, SignatureSet,
};
use tree_hash::TreeHash;

const ETH: Gwei = 1_000_000_000;
/// The minimal `SLOTS_PER_EPOCH`.
const SPE: u64 = 8;
/// The first slot of the state: the start of epoch 2.
const START_SLOT: Slot = 16;
/// The slot of the block with the bid, in epoch 2.
const BID_SLOT: Slot = 17;
/// The value of the bid.
const BID_VALUE: Gwei = 3 * ETH;
/// The balance of builder 0.
const BUILDER_BALANCE: Gwei = 100 * ETH;
/// The fee recipient of the bid.
const FEE_RECIPIENT: Address = Address::repeat_byte(0xfe);
/// The quorum of 64 validators of 32 ETH: 2048 ETH // 8 * 6 // 10.
const QUORUM: Gwei = 153_600_000_000;
/// `get_blob_parameters(epoch).max_blobs_per_block` of `configs/minimal.yaml`.
const MAX_BLOBS_PER_BLOCK: u64 = 9;

/// A BLS context that fails each call. The lifecycle needs no verdict and no aggregate key.
struct NoBls;

impl SignatureBackend for NoBls {
    fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
        Err(BackendError("the lifecycle asks for no verdict".into()))
    }
}

impl PubkeyAggregator for NoBls {
    fn aggregate_pubkeys(&self, _: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError> {
        Err(AggregationError(
            "the lifecycle asks for no aggregate".into(),
        ))
    }
}

fn minimal_blob_schedule(_: Epoch) -> u64 {
    MAX_BLOBS_PER_BLOCK
}

fn bls() -> BlsContext<'static> {
    BlsContext {
        backend: &NoBls,
        aggregator: &NoBls,
        genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
        capella_fork_version: [0x03, 0x00, 0x00, 0x01],
        blob_schedule: &minimal_blob_schedule,
    }
}

/// A minimal Gloas state at slot 16 with 64 validators of 32 ETH (two committees of four
/// for each slot) and builder 0, which has 100 ETH and is active: it deposited in epoch 0,
/// and epoch 1 is finalized.
fn state() -> BeaconState<Minimal> {
    let validators = (0..64u64).map(|i| {
        let mut pubkey = [0u8; 48];
        pubkey[..8].copy_from_slice(&i.to_le_bytes());
        Validator {
            pubkey,
            withdrawal_credentials: Bytes32::ZERO,
            effective_balance: 32 * ETH,
            slashed: false,
            activation_eligibility_epoch: 0,
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        }
    });
    let zeros = || ProgressiveList::try_from_iter((0..64).map(|_| 0)).unwrap();
    let checkpoint = Checkpoint {
        epoch: 1,
        root: Root::repeat_byte(0x01),
    };
    let sync_committee = SyncCommittee {
        pubkeys: FixedVector::from_elem([0; 48]),
        aggregate_pubkey: [0; 48],
    };
    let builder = Builder {
        pubkey: [0xb0; 48],
        version: 0,
        execution_address: Address::repeat_byte(0xb0),
        balance: BUILDER_BALANCE,
        deposit_epoch: 0,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };
    let mut state = BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::repeat_byte(0x42),
        slot: START_SLOT,
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
        eth1_data: Eth1Data {
            deposit_root: Root::ZERO,
            deposit_count: 0,
            block_hash: Root::ZERO,
        },
        eth1_data_votes: List::default(),
        eth1_deposit_index: 0,
        validators: ProgressiveList::try_from_iter(validators).unwrap(),
        balances: ProgressiveList::try_from_iter((0..64).map(|_| 32 * ETH)).unwrap(),
        randao_mixes: Vector::from_elem(Bytes32::repeat_byte(0x5a)).unwrap(),
        slashings: Vector::default(),
        previous_epoch_participation: zeros(),
        current_epoch_participation: zeros(),
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: checkpoint.clone(),
        current_justified_checkpoint: checkpoint.clone(),
        finalized_checkpoint: checkpoint,
        inactivity_scores: ProgressiveList::try_from_iter((0..64).map(|_| 0)).unwrap(),
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
        builders: ProgressiveList::try_from_iter([builder]).unwrap(),
        next_withdrawal_builder_index: 0,
        execution_payload_availability: BitVector::new(),
        builder_pending_payments: Vector::from_elem(empty_payment()).unwrap(),
        builder_pending_withdrawals: ProgressiveList::default(),
        latest_execution_payload_bid: empty_bid(0),
        payload_expected_withdrawals: ProgressiveList::default(),
        ptc_window: Vector::default(),
    };
    state.proposer_lookahead = Vector::new(initialize_proposer_lookahead(&state).unwrap()).unwrap();
    state.ptc_window = Vector::new(initialize_ptc_window(&state).unwrap()).unwrap();
    state
}

/// An empty bid for `slot`.
fn empty_bid(slot: Slot) -> ExecutionPayloadBid<Minimal> {
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

/// A block at `state.slot` by the proposer of the slot, on the latest block header, with an
/// empty body.
fn block(state: &BeaconState<Minimal>) -> BeaconBlock<Minimal> {
    let body = BeaconBlockBody {
        randao_reveal: [0; 96],
        eth1_data: state.eth1_data.clone(),
        graffiti: Bytes32::ZERO,
        proposer_slashings: Default::default(),
        attester_slashings: Default::default(),
        attestations: Default::default(),
        deposits: Default::default(),
        voluntary_exits: Default::default(),
        sync_aggregate: SyncAggregate {
            sync_committee_bits: BitVector::new(),
            sync_committee_signature: G2_POINT_AT_INFINITY,
        },
        bls_to_execution_changes: Default::default(),
        signed_execution_payload_bid: SignedExecutionPayloadBid {
            message: empty_bid(state.slot),
            signature: G2_POINT_AT_INFINITY,
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
    BeaconBlock {
        slot: state.slot,
        proposer_index: get_beacon_proposer_index(state).unwrap(),
        parent_root: state.latest_block_header.tree_hash_root(),
        state_root: Root::ZERO,
        body,
    }
}

/// The bid of builder 0 for `state.slot`, with `BID_VALUE` to `FEE_RECIPIENT`, that the
/// asserts of `process_execution_payload_bid` accept on `state`.
fn bid(state: &BeaconState<Minimal>) -> SignedExecutionPayloadBid<Minimal> {
    let epoch = state.slot / SPE;
    SignedExecutionPayloadBid {
        message: ExecutionPayloadBid {
            parent_block_hash: state.latest_block_hash,
            parent_block_root: get_block_root_at_slot(state, state.slot - 1).unwrap(),
            block_hash: Root::repeat_byte(0xbb),
            prev_randao: get_randao_mix(state, epoch),
            fee_recipient: FEE_RECIPIENT,
            builder_index: 0,
            value: BID_VALUE,
            ..empty_bid(state.slot)
        },
        signature: [0x33; 96],
    }
}

/// The same-slot attestations for the block at `BID_SLOT` of the first `count` attesters of
/// the slot, in committee order: one attestation for each committee with an attester. Each
/// has the head, the target and the source of the state.
fn attestations(state: &BeaconState<Minimal>, count: usize) -> Vec<Attestation<Minimal>> {
    let epoch = BID_SLOT / SPE;
    let cache = CommitteeCache::new(state, epoch).unwrap();
    let data = AttestationData {
        slot: BID_SLOT,
        index: 0,
        beacon_block_root: get_block_root_at_slot(state, BID_SLOT).unwrap(),
        source: state.current_justified_checkpoint.clone(),
        target: Checkpoint {
            epoch,
            root: get_block_root(state, epoch).unwrap(),
        },
    };
    let mut left = count;
    let mut out = Vec::new();
    for index in 0..cache.committees_per_slot() {
        let size = cache.committee(BID_SLOT, index).unwrap().len();
        let attesters = left.min(size);
        if attesters == 0 {
            break;
        }
        left -= attesters;
        let mut aggregation_bits = ProgressiveBitList::with_capacity(size);
        for position in 0..attesters {
            aggregation_bits.set(position, true).unwrap();
        }
        let mut committee_bits = BitVector::new();
        committee_bits.set(index as usize, true).unwrap();
        out.push(Attestation {
            aggregation_bits,
            data: data.clone(),
            signature: [0x44; 96],
            committee_bits,
        });
    }
    assert_eq!(left, 0, "slot {BID_SLOT} has fewer than {count} attesters");
    out
}

/// The payment of the bid, with `weight`.
fn bid_payment(proposer_index: u64, weight: Gwei) -> BuilderPendingPayment {
    BuilderPendingPayment {
        weight,
        withdrawal: BuilderPendingWithdrawal {
            fee_recipient: FEE_RECIPIENT,
            amount: BID_VALUE,
            builder_index: 0,
        },
        proposer_index,
    }
}

fn payment(state: &BeaconState<Minimal>, index: u64) -> BuilderPendingPayment {
    state
        .builder_pending_payments
        .get(index as usize)
        .unwrap()
        .clone()
}

/// Steps 1 and 2 of the lifecycle: the block with the bid at `BID_SLOT`, and the same-slot
/// attestations of `attesters` attesters at the next slot. Returns the state at slot 18 and
/// the proposer of the block.
fn bid_and_attest(attesters: usize) -> (BeaconState<Minimal>, u64) {
    let mut state = state();
    process_slots(&mut state, BID_SLOT, &bls()).unwrap();
    let block = block(&state);
    process_block_header(&mut state, &block).unwrap();
    let bid = bid(&state);
    process_execution_payload_bid(&mut state, &bid, MAX_BLOBS_PER_BLOCK).unwrap();
    // G L2210: the payment of the current epoch is at SLOTS_PER_EPOCH + slot % SLOTS_PER_EPOCH.
    let index = SPE + BID_SLOT % SPE;
    assert_eq!(payment(&state, index), bid_payment(block.proposer_index, 0));

    process_slots(&mut state, BID_SLOT + 1, &bls()).unwrap();
    // One context for the block: the attestations share one shuffle of the epoch.
    let mut ctx = BlockContext::default();
    for attestation in attestations(&state, attesters) {
        process_attestation_with(&mut state, &attestation, BID_SLOT, &mut ctx).unwrap();
    }
    let weight = attesters as Gwei * 32 * ETH;
    assert_eq!(
        payment(&state, index),
        bid_payment(block.proposer_index, weight)
    );
    (state, block.proposer_index)
}

/// Step 3 up to the first boundary: the payment moves to the first half of the vector, and
/// no withdrawal is made yet.
fn first_boundary(state: &mut BeaconState<Minimal>, proposer: u64, weight: Gwei) {
    process_slots(state, 3 * SPE, &bls()).unwrap();
    assert_eq!(
        payment(state, BID_SLOT % SPE),
        bid_payment(proposer, weight)
    );
    assert_eq!(payment(state, SPE + BID_SLOT % SPE), empty_payment());
    assert!(state.builder_pending_withdrawals.is_empty());
    // The quorum of the second boundary: the effective balances did not change.
    assert_eq!(
        get_builder_payment_quorum_threshold(state, &mut TotalActiveBalanceCache::default()),
        Ok(QUORUM)
    );
}

/// The second boundary: every payment is empty after it.
fn second_boundary(state: &mut BeaconState<Minimal>) {
    process_slots(state, 4 * SPE, &bls()).unwrap();
    assert!(state
        .builder_pending_payments
        .iter()
        .all(|p| *p == empty_payment()));
}

#[test]
fn lifecycle() {
    // Five attesters of 32 ETH give 160 ETH, at or above the quorum of 153.6 ETH. Four give
    // 128 ETH, below it.
    quorum_reached_pays_the_withdrawal(5);
    no_quorum_drops_the_payment(4);
    proposer_slashed_mid_window_clears_the_payment(5);
}

/// Quorum reached: the second boundary makes a builder withdrawal of the bid, and the
/// withdrawals of the next block pay it from the builder balance.
fn quorum_reached_pays_the_withdrawal(attesters: usize) {
    let (mut state, proposer) = bid_and_attest(attesters);
    let weight = attesters as Gwei * 32 * ETH;
    assert!(weight >= QUORUM);
    first_boundary(&mut state, proposer, weight);
    second_boundary(&mut state);
    let withdrawal = bid_payment(proposer, weight).withdrawal;
    assert_eq!(
        state.builder_pending_withdrawals.to_vec(),
        vec![withdrawal.clone()]
    );

    let (withdrawals, next_index, processed) =
        get_builder_withdrawals(&state, state.next_withdrawal_index, &[]).unwrap();
    assert_eq!(processed, 1);
    assert_eq!(next_index, 1);
    assert_eq!(withdrawals.len(), 1);
    assert_eq!(
        withdrawals[0].validator_index,
        convert_builder_index_to_validator_index(0)
    );
    assert_eq!(withdrawals[0].address, FEE_RECIPIENT);
    assert_eq!(withdrawals[0].amount, BID_VALUE);

    // The payload of the bid arrived: the parent payload step of the next block (G L1830)
    // sets the latest block hash to the block hash of the bid, so the parent is FULL.
    state.latest_block_hash = state.latest_execution_payload_bid.block_hash;
    process_withdrawals(&mut state).unwrap();
    assert_eq!(
        state.builders.get(0).unwrap().balance,
        BUILDER_BALANCE - BID_VALUE
    );
    assert!(state.builder_pending_withdrawals.is_empty());
    assert_eq!(state.payload_expected_withdrawals.to_vec(), withdrawals);
}

/// No quorum: the second boundary drops the payment, and no withdrawal is made.
fn no_quorum_drops_the_payment(attesters: usize) {
    let (mut state, proposer) = bid_and_attest(attesters);
    let weight = attesters as Gwei * 32 * ETH;
    assert!(weight < QUORUM);
    first_boundary(&mut state, proposer, weight);
    second_boundary(&mut state);
    assert!(state.builder_pending_withdrawals.is_empty());
    let (withdrawals, _, processed) =
        get_builder_withdrawals(&state, state.next_withdrawal_index, &[]).unwrap();
    assert!(withdrawals.is_empty());
    assert_eq!(processed, 0);
    assert_eq!(state.builders.get(0).unwrap().balance, BUILDER_BALANCE);
}

/// The proposer of the bid block is slashed between the two boundaries (consensus-specs PR
/// 5719): `slash_validator` empties its payment, so the quorum of the payment pays nothing.
fn proposer_slashed_mid_window_clears_the_payment(attesters: usize) {
    let (mut state, proposer) = bid_and_attest(attesters);
    let weight = attesters as Gwei * 32 * ETH;
    assert!(weight >= QUORUM);
    first_boundary(&mut state, proposer, weight);

    let header = |body_root: u8| SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: BID_SLOT,
            proposer_index: proposer,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body_root: Root::repeat_byte(body_root),
        },
        signature: [0x55; 96],
    };
    let slashing = ProposerSlashing {
        signed_header_1: header(1),
        signed_header_2: header(2),
    };
    process_proposer_slashing(&mut state, &slashing).unwrap();
    assert!(state.validators.get(proposer as usize).unwrap().slashed);
    assert_eq!(payment(&state, BID_SLOT % SPE), empty_payment());

    second_boundary(&mut state);
    assert!(state.builder_pending_withdrawals.is_empty());
    assert_eq!(state.builders.get(0).unwrap().balance, BUILDER_BALANCE);
}

#[test]
fn the_state_has_two_committees_of_four_for_each_slot() {
    // The paths of `lifecycle` count on this shape: four attesters fill one committee, and
    // the fifth is in the second one.
    let state = state();
    let cache = CommitteeCache::new(&state, START_SLOT / SPE).unwrap();
    assert_eq!(cache.committees_per_slot(), 2);
    for index in 0..2 {
        assert_eq!(cache.committee(BID_SLOT, index).unwrap().len(), 4);
    }
    assert_eq!(Minimal::slots_per_epoch(), SPE);
}
