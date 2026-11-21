//! `validate_execution_payload_envelope_gossip` (`gloas/p2p-interface.md` L811-885) against a
//! fork-choice store that the tests build, and `Seen::resolve` after the signature check.
//!
//! The test provider does not run the state transition. The post-state of a block is the parent
//! state at the slot of the block, with the header and the bid of the block. The gossip checks
//! read only the block, its bid, and the builders, the proposer and the fork of that state.
//! `on_execution_payload_envelope` of fork choice reads the header and the bid of the
//! post-state, so a test can run both on the same store.
//!
//! This crate links no BLS library. A test gives the BLS verdict of a pending set itself, and
//! the hooks of fork choice give theirs.

use consensus_types::gloas::{
    BeaconBlock, BeaconBlockHeader, BeaconState, Checkpoint, ConsolidationRequest,
    ExecutionPayload, ExecutionPayloadEnvelope, ExecutionRequests, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope, Withdrawal, WithdrawalRequest,
};
use consensus_types::primitives::{Address, BLSSignature, BuilderIndex, Root, Slot, U256};
use consensus_types::signing::{
    compute_signing_root, SignatureSet, SignerRef, BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER,
};
use consensus_types::{EthSpec, Mainnet, Minimal};
use fork_choice::{
    get_forkchoice_store, is_payload_verified, on_block, on_execution_payload_envelope, on_tick,
    DataAvailability, DataAvailabilityCheck, ExecutionEngine, NewPayloadRequestRef, PayloadImport,
    SignatureVerifier, StateProvider, Store,
};
use gossip_validation::{
    oldest_current_slot, validate_execution_payload_envelope_gossip,
    verify_execution_requests_limits, verify_withdrawals_limit, IgnoreReason, RejectReason,
    RequestCounts, RequestKind, Seen, SeenKey, StoreView, Verdict,
    MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS, MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT,
    MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS,
};
use ssz::{Decode, Encode};
use ssz_types::FixedVector;
use state_transition::accessors::{builder_key_version, get_domain};
use state_transition::testing::{builder, empty_requests, genesis_state, signed_block};
use state_transition::{state_root, BackendError, StfError};
use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroU64;
use tree_hash::TreeHash;

type E = Minimal;

const SLOT_MS: u64 = 6000;
const GENESIS_TIME: u64 = 1_700_000_000;
/// The proposer of the block of each test.
const PROPOSER: u64 = 7;
/// The builder of the bid of each test, unless the test says another.
const BUILDER: BuilderIndex = 1;
const GAS_LIMIT: u64 = 30_000_000;
const SIG: BLSSignature = [0x44; 96];
const OTHER_SIG: BLSSignature = [0x55; 96];
/// `MAX_WITHDRAWALS_PER_PAYLOAD` of `presets/minimal/capella.yaml`.
const MINIMAL_MAX_WITHDRAWALS: usize = 4;
/// `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD` of `presets/minimal/electra.yaml`.
const MAX_WITHDRAWAL_REQUESTS: usize = 16;
/// `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD` of `presets/minimal/electra.yaml`.
const MAX_CONSOLIDATION_REQUESTS: usize = 2;
/// `MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD` of `presets/minimal/gloas.yaml`.
const MAX_BUILDER_DEPOSIT_REQUESTS: usize = 64;
/// `MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD` of `presets/minimal/gloas.yaml`.
const MAX_BUILDER_EXIT_REQUESTS: usize = 16;

fn time_at(slot: Slot) -> u64 {
    GENESIS_TIME * 1000 + slot * SLOT_MS
}

fn block_hash() -> Root {
    Root::repeat_byte(0xbb)
}

/// A genesis state at `slot` with 64 validators and the builders 0 and 1, and its anchor block.
fn anchor(slot: Slot) -> (BeaconState<E>, BeaconBlock<E>) {
    let mut state = genesis_state::<E>(&[32_000_000_000; 64]);
    state.genesis_time = GENESIS_TIME;
    state.slot = slot;
    for key in [0xa0, 0xa1] {
        state.builders.push(builder(key, 5_000_000_000, 0)).unwrap();
    }
    let mut block = signed_block::<E>(slot, 0).message;
    block.state_root = state_root(&mut state).unwrap();
    (state, block)
}

/// The test provider: the post-state is the parent state at the slot of the block, with the
/// header and the bid of the block, as `process_block_header` and
/// `process_execution_payload_bid` set them. `process_slots` only sets the slot.
struct Provider;

impl StateProvider<E> for Provider {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        signed_block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        let block = &signed_block.message;
        state.slot = block.slot;
        state.latest_block_header = BeaconBlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: Root::ZERO,
            body_root: block.body.tree_hash_root(),
        };
        state.latest_execution_payload_bid =
            block.body.signed_execution_payload_bid.message.clone();
        Ok(())
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        state.slot = slot;
        Ok(())
    }
}

/// [`Provider`], and the post-state justifies and finalizes the checkpoint.
struct Finalizing(Checkpoint);

impl StateProvider<E> for Finalizing {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        signed_block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        Provider.state_transition(state, signed_block)?;
        state.current_justified_checkpoint = self.0.clone();
        state.finalized_checkpoint = self.0.clone();
        Ok(())
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        Provider.process_slots(state, slot)
    }
}

/// A store with an anchor and one block after it, and that block.
struct Chain {
    store: Store<E>,
    block: SignedBeaconBlock<E>,
    root: Root,
}

/// [`chain_at`] with the anchor at slot 0.
fn chain(builder_index: BuilderIndex, requests: &ExecutionRequests<E>) -> Chain {
    chain_at(0, builder_index, requests)
}

/// A block at `slot` by `proposer` on the EMPTY payload of `parent`.
fn block_on(parent: Root, slot: Slot, proposer: u64) -> SignedBeaconBlock<E> {
    let mut block = signed_block::<E>(slot, proposer);
    block.message.parent_root = parent;
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.parent_block_hash = Root::repeat_byte(0xee);
    block
}

/// A block at `slot` by [`PROPOSER`] on the EMPTY payload of `parent`. The bid of the block is
/// by `builder_index`, has the block hash `[0xbb; 32]` and commits to `requests`.
fn block_with_bid(
    parent: Root,
    slot: Slot,
    builder_index: BuilderIndex,
    requests: &ExecutionRequests<E>,
) -> SignedBeaconBlock<E> {
    let mut block = block_on(parent, slot, PROPOSER);
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.builder_index = builder_index;
    bid.block_hash = block_hash();
    bid.gas_limit = GAS_LIMIT;
    bid.execution_requests_root = requests.tree_hash_root();
    block
}

/// A store with the anchor at `anchor_slot`, and a block at the next slot on it. The bid of
/// the block is by `builder_index`, has the block hash `[0xbb; 32]` and commits to `requests`.
fn chain_at(
    anchor_slot: Slot,
    builder_index: BuilderIndex,
    requests: &ExecutionRequests<E>,
) -> Chain {
    let (state, anchor_block) = anchor(anchor_slot);
    let anchor_root = anchor_block.tree_hash_root();
    let slot_duration = NonZeroU64::new(SLOT_MS).unwrap();
    let mut store = get_forkchoice_store(state, anchor_block, slot_duration).unwrap();
    let slot = anchor_slot + 1;
    on_tick(&mut store, time_at(slot)).unwrap();
    let block = block_with_bid(anchor_root, slot, builder_index, requests);
    on_block(&mut store, &Provider, &block).unwrap();
    let root = block.message.tree_hash_root();
    Chain { store, block, root }
}

/// Sets the state root of `block` to the root of its [`Provider`] post-state on its parent in
/// `store`. Then the root of the latest block header of that post-state is the block root, as
/// `verify_execution_payload_envelope` of fork choice checks.
fn commit_state_root(store: &Store<E>, block: &mut SignedBeaconBlock<E>) {
    let mut post = store
        .block_state(block.message.parent_root)
        .unwrap()
        .clone();
    Provider.state_transition(&mut post, block).unwrap();
    block.message.state_root = state_root(&mut post).unwrap();
}

/// A store in which a prune dropped the block of `chain`, and the post-state of that block
/// from before the prune.
struct Dropped {
    chain: Chain,
    state: BeaconState<E>,
}

/// The anchor at slot 0, `a` and `b` at slot 1 on it, the block at slot 9 on `b`, and `c` at
/// slot 9 on `a`. The bid of the block is by `builder_index`, has the block hash `[0xbb; 32]`
/// and commits to `requests`, and the block commits to its post-state. The post-state of `c`
/// justifies and finalizes epoch 1 (first slot 8) with `a`, and the tick after it, in slot 10,
/// drops the anchor, `b` and the block.
///
/// The prune in epoch 1 keeps the dropped block and its post-state through the end of epoch 3
/// (slot 31), but [`Store::block`] and [`Store::block_state`] no longer have them.
fn dropped(builder_index: BuilderIndex, requests: &ExecutionRequests<E>) -> Dropped {
    let (state, anchor_block) = anchor(0);
    let anchor_root = anchor_block.tree_hash_root();
    let slot_duration = NonZeroU64::new(SLOT_MS).unwrap();
    let mut store = get_forkchoice_store(state, anchor_block, slot_duration).unwrap();
    on_tick(&mut store, time_at(1)).unwrap();
    let a = block_on(anchor_root, 1, 1);
    let b = block_on(anchor_root, 1, 2);
    for block in [&a, &b] {
        on_block(&mut store, &Provider, block).unwrap();
    }
    on_tick(&mut store, time_at(10)).unwrap();
    let mut block = block_with_bid(b.message.tree_hash_root(), 9, builder_index, requests);
    commit_state_root(&store, &mut block);
    on_block(&mut store, &Provider, &block).unwrap();
    let root = block.message.tree_hash_root();
    let state = store.block_state(root).unwrap().clone();
    let checkpoint = Checkpoint {
        epoch: 1,
        root: a.message.tree_hash_root(),
    };
    let c = block_on(checkpoint.root, 9, 3);
    on_block(&mut store, &Finalizing(checkpoint.clone()), &c).unwrap();
    assert_eq!(store.finalized_checkpoint(), &checkpoint);
    // A tick in the same slot prunes.
    on_tick(&mut store, time_at(10)).unwrap();
    assert!(Store::block(&store, anchor_root).is_none());
    Dropped {
        chain: Chain { store, block, root },
        state,
    }
}

/// The block of `chain` is not in the live tree of the store: [`Store::block`] and
/// [`Store::block_state`] do not have it.
fn assert_not_live(chain: &Chain) {
    assert!(Store::block(&chain.store, chain.root).is_none());
    assert!(Store::block_state(&chain.store, chain.root).is_none());
}

fn withdrawal(index: u64) -> Withdrawal {
    Withdrawal {
        index,
        validator_index: index,
        address: Address::repeat_byte(0x22),
        amount: 1,
    }
}

/// A payload of `slot` with the block hash `block_hash` and `withdrawals`.
fn payload<P: EthSpec>(
    slot: Slot,
    block_hash: Root,
    withdrawals: Vec<Withdrawal>,
) -> ExecutionPayload<P> {
    ExecutionPayload {
        parent_hash: Root::repeat_byte(0x01),
        fee_recipient: Address::repeat_byte(0xfe),
        state_root: Root::repeat_byte(0x02),
        receipts_root: Root::repeat_byte(0x03),
        logs_bloom: FixedVector::default(),
        prev_randao: Root::repeat_byte(0x04),
        block_number: 1,
        gas_limit: GAS_LIMIT,
        gas_used: 0,
        timestamp: GENESIS_TIME + slot * SLOT_MS / 1000,
        extra_data: Default::default(),
        base_fee_per_gas: U256::from(7),
        block_hash,
        transactions: Default::default(),
        withdrawals: withdrawals.try_into().unwrap(),
        blob_gas_used: 0,
        excess_blob_gas: 0,
        block_access_list: Default::default(),
        slot_number: slot,
    }
}

/// The envelope of the block of `chain` that the bid commits to, with `requests` and the
/// signature [`SIG`].
fn envelope(chain: &Chain, requests: ExecutionRequests<E>) -> SignedExecutionPayloadEnvelope<E> {
    let block = &chain.block.message;
    let bid = &block.body.signed_execution_payload_bid.message;
    SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload: payload(block.slot, bid.block_hash, vec![]),
            execution_requests: requests,
            builder_index: bid.builder_index,
            beacon_block_root: chain.root,
            parent_beacon_block_root: block.parent_root,
        },
        signature: SIG,
    }
}

/// The set of `verify_execution_payload_envelope_signature` (`gloas/beacon-chain.md`
/// L2107-2120) for `signed` on the post-state of the block of `chain`.
fn expected_set(chain: &Chain, signed: &SignedExecutionPayloadEnvelope<E>) -> SignatureSet {
    expected_set_on(chain.store.block_state(chain.root).unwrap(), signed)
}

/// The set of `verify_execution_payload_envelope_signature` for `signed` on `state`.
fn expected_set_on(
    state: &BeaconState<E>,
    signed: &SignedExecutionPayloadEnvelope<E>,
) -> SignatureSet {
    let index = signed.message.builder_index;
    let signer = if index == BUILDER_INDEX_SELF_BUILD {
        SignerRef::Validator(PROPOSER)
    } else {
        SignerRef::Builder {
            index,
            version: builder_key_version(state, index).unwrap(),
        }
    };
    let domain = get_domain(state, DOMAIN_BEACON_BUILDER, None);
    SignatureSet::single(
        signer,
        compute_signing_root(&signed.message, domain),
        signed.signature,
    )
}

/// The sets and the key of a pending verdict. Any other verdict fails the test.
fn pending(verdict: Verdict) -> (Vec<SignatureSet>, SeenKey) {
    match verdict {
        Verdict::Pending { bls_sets, seen_key } => (bls_sets, seen_key),
        other => panic!("expected a pending verdict, got {other:?}"),
    }
}

fn validate(seen: &Seen, chain: &Chain, signed: &SignedExecutionPayloadEnvelope<E>) -> Verdict {
    validate_execution_payload_envelope_gossip(seen, &chain.store, signed)
}

#[test]
fn a_valid_envelope_must_wait_for_its_signature_and_then_accept() {
    let chain = chain(BUILDER, &empty_requests());
    let signed = envelope(&chain, empty_requests());
    let mut seen = Seen::default();
    let (sets, key) = pending(validate(&seen, &chain, &signed));
    assert_eq!(sets, vec![expected_set(&chain, &signed)]);
    assert_eq!(
        sets[0].signers(),
        &[SignerRef::Builder {
            index: BUILDER,
            version: builder_key_version(chain.store.block_state(chain.root).unwrap(), BUILDER)
                .unwrap(),
        }]
    );
    assert!(!seen.has_execution_payload_envelope(chain.root, BUILDER));
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    assert!(seen.has_execution_payload_envelope(chain.root, BUILDER));
    let payload = seen.execution_payload(block_hash()).unwrap();
    assert_eq!(payload.gas_limit, GAS_LIMIT);
}

#[test]
fn an_envelope_already_seen_for_the_block_and_builder_must_ignore() {
    let chain = chain(BUILDER, &empty_requests());
    let signed = envelope(&chain, empty_requests());
    let mut seen = Seen::default();
    let (_, key) = pending(validate(&seen, &chain, &signed));
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    let mut other_copy = signed.clone();
    other_copy.signature = OTHER_SIG;
    for copy in [&signed, &other_copy] {
        assert_eq!(
            validate(&seen, &chain, copy),
            Verdict::Ignore(IgnoreReason::EnvelopeAlreadySeen {
                block_root: chain.root,
                builder_index: BUILDER,
            })
        );
    }
}

#[test]
fn an_envelope_for_an_unknown_block_must_ignore() {
    let chain = chain(BUILDER, &empty_requests());
    let mut signed = envelope(&chain, empty_requests());
    let unknown = Root::repeat_byte(0x42);
    signed.message.beacon_block_root = unknown;
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Ignore(IgnoreReason::UnknownBlock(unknown))
    );
}

#[test]
fn a_valid_envelope_for_a_retained_dropped_block_must_wait_for_its_signature_and_then_accept() {
    let Dropped { chain, state } = dropped(BUILDER, &empty_requests());
    assert_not_live(&chain);
    let signed = envelope(&chain, empty_requests());
    let mut seen = Seen::default();
    let (sets, key) = pending(validate(&seen, &chain, &signed));
    assert_eq!(sets, vec![expected_set_on(&state, &signed)]);
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    assert!(seen.has_execution_payload_envelope(chain.root, BUILDER));
    assert_eq!(
        seen.execution_payload(block_hash()).unwrap().gas_limit,
        GAS_LIMIT
    );
}

#[test]
fn an_invalid_signature_for_a_retained_dropped_block_must_reject() {
    let Dropped { chain, .. } = dropped(BUILDER, &empty_requests());
    assert_not_live(&chain);
    let mut signed = envelope(&chain, empty_requests());
    signed.signature = OTHER_SIG;
    let mut seen = Seen::default();
    let (_, key) = pending(validate(&seen, &chain, &signed));
    assert_eq!(
        seen.resolve(key, Ok(false)),
        Verdict::Reject(RejectReason::InvalidSignature)
    );
    assert_eq!(seen, Seen::default());
}

#[test]
fn an_envelope_that_does_not_match_a_retained_dropped_block_must_reject() {
    let Dropped { chain, .. } = dropped(BUILDER, &empty_requests());
    assert_not_live(&chain);
    // Slot 10 is after the finalized slot 8, so only the block slot 9 refuses it.
    let mut signed = envelope(&chain, empty_requests());
    signed.message.payload.slot_number = 10;
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Reject(RejectReason::SlotMismatch {
            block: 9,
            payload: 10,
        })
    );
    let mut signed = envelope(&chain, empty_requests());
    signed.message.builder_index = 0;
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Reject(RejectReason::BuilderIndexMismatch {
            envelope: 0,
            bid: BUILDER,
        })
    );
}

#[test]
fn an_envelope_for_a_dropped_block_must_ignore_once_the_store_forgets_it() {
    let Dropped { mut chain, .. } = dropped(BUILDER, &empty_requests());
    let signed = envelope(&chain, empty_requests());
    // The last slot of epoch 3, the second epoch after the prune: the store keeps the block.
    on_tick(&mut chain.store, time_at(31)).unwrap();
    assert_not_live(&chain);
    pending(validate(&Seen::default(), &chain, &signed));
    // The first tick of epoch 4 forgets it.
    on_tick(&mut chain.store, time_at(32)).unwrap();
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Ignore(IgnoreReason::UnknownBlock(chain.root))
    );
}

/// The hooks of `on_execution_payload_envelope`: a valid signature, available data and a VALID
/// engine answer, and a record of each call.
#[derive(Default)]
struct Hooks {
    sets: RefCell<Vec<SignatureSet>>,
    availability_checks: RefCell<Vec<Root>>,
    payload_block_hashes: RefCell<Vec<Root>>,
}

impl SignatureVerifier<E> for Hooks {
    fn verify_signature_sets(
        &self,
        _: &BeaconState<E>,
        sets: &[SignatureSet],
    ) -> Result<bool, BackendError> {
        self.sets.borrow_mut().extend_from_slice(sets);
        Ok(true)
    }
}

impl DataAvailabilityCheck for Hooks {
    fn is_data_available(&self, beacon_block_root: Root) -> DataAvailability {
        self.availability_checks
            .borrow_mut()
            .push(beacon_block_root);
        DataAvailability::Available
    }
}

impl ExecutionEngine<E> for Hooks {
    fn verify_and_notify_new_payload(
        &self,
        request: &NewPayloadRequestRef<'_, E>,
    ) -> PayloadImport {
        self.payload_block_hashes
            .borrow_mut()
            .push(request.execution_payload.block_hash);
        PayloadImport::Valid
    }
}

/// [`envelope`] with no requests, and with the parent hash of `state` and the prev_randao of
/// its bid: the gossip checks and `verify_execution_payload_envelope` of fork choice on
/// `state`, the post-state of the block of `chain`, both accept it.
fn envelope_on(chain: &Chain, state: &BeaconState<E>) -> SignedExecutionPayloadEnvelope<E> {
    let mut signed = envelope(chain, empty_requests());
    let payload = &mut signed.message.payload;
    payload.parent_hash = state.latest_block_hash;
    payload.prev_randao = state.latest_execution_payload_bid.prev_randao;
    signed
}

#[test]
fn gossip_and_fork_choice_must_both_accept_a_valid_envelope_for_a_retained_dropped_block() {
    let Dropped { mut chain, state } = dropped(BUILDER, &empty_requests());
    assert_not_live(&chain);
    let signed = envelope_on(&chain, &state);

    // Gossip: the checks before the signature pass, and the valid signature accepts.
    let mut seen = Seen::default();
    let (gossip_sets, gossip) = match validate(&seen, &chain, &signed) {
        Verdict::Pending { bls_sets, seen_key } => (bls_sets, seen.resolve(seen_key, Ok(true))),
        other => (vec![], other),
    };
    // Fork choice: the signature is valid, the data is available and the engine says VALID.
    let hooks = Hooks::default();
    let fork_choice = on_execution_payload_envelope(&mut chain.store, &hooks, &signed);

    // Neither path may ignore the envelope as unknown while the other accepts it.
    assert_eq!((gossip, fork_choice), (Verdict::Accept, Ok(())));
    // Both check the same signature set, on the post-state of the dropped block.
    assert_eq!(gossip_sets, vec![expected_set_on(&state, &signed)]);
    assert_eq!(*hooks.sets.borrow(), gossip_sets);
    assert_eq!(*hooks.availability_checks.borrow(), vec![chain.root]);
    assert_eq!(*hooks.payload_block_hashes.borrow(), vec![block_hash()]);
    assert!(seen.has_execution_payload_envelope(chain.root, BUILDER));
    assert!(is_payload_verified(&chain.store, chain.root));
    // The payload is verified, and the block stays out of the live tree.
    assert_not_live(&chain);
}

/// A view of the store that has the blocks but no post-state: each block failed validation.
struct NoPostStates<'a>(&'a Store<E>);

impl StoreView<E> for NoPostStates<'_> {
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>> {
        self.0.block(root)
    }

    fn block_state(&self, _: Root) -> Option<&BeaconState<E>> {
        None
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        self.0.finalized_checkpoint()
    }

    fn genesis_time_ms(&self) -> u64 {
        self.0.genesis_time_ms()
    }

    fn slot_duration_ms(&self) -> NonZeroU64 {
        self.0.slot_duration_ms()
    }

    fn head_state(&self) -> Option<&BeaconState<E>> {
        StoreView::head_state(self.0)
    }

    fn time_ms(&self) -> u64 {
        self.0.time_ms()
    }
}

#[test]
fn an_envelope_for_a_block_with_no_post_state_must_reject() {
    let chain = chain(BUILDER, &empty_requests());
    let signed = envelope(&chain, empty_requests());
    let view = NoPostStates(&chain.store);
    assert_eq!(
        validate_execution_payload_envelope_gossip(&Seen::default(), &view, &signed),
        Verdict::Reject(RejectReason::BlockNotValid(chain.root))
    );
}

#[test]
fn an_envelope_from_a_slot_before_the_finalized_slot_must_ignore() {
    // The anchor at slot 16 finalizes epoch 2, whose first slot is 16. The block is at slot 17.
    let chain = chain_at(16, BUILDER, &empty_requests());
    assert_eq!(chain.store.finalized_checkpoint().epoch, 2);
    let mut signed = envelope(&chain, empty_requests());
    signed.message.payload.slot_number = 15;
    // The IGNORE comes before the REJECT for the slot that is not the block slot.
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Ignore(IgnoreReason::BeforeFinalizedSlot {
            slot: 15,
            finalized_slot: 16,
        })
    );
    signed.message.payload.slot_number = 16;
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Reject(RejectReason::SlotMismatch {
            block: 17,
            payload: 16,
        })
    );
}

#[test]
fn a_payload_slot_that_is_not_the_block_slot_must_reject() {
    let chain = chain(BUILDER, &empty_requests());
    let mut signed = envelope(&chain, empty_requests());
    signed.message.payload.slot_number = 2;
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Reject(RejectReason::SlotMismatch {
            block: 1,
            payload: 2,
        })
    );
}

#[test]
fn a_builder_index_that_is_not_the_bid_builder_must_reject() {
    let chain = chain(BUILDER, &empty_requests());
    let mut signed = envelope(&chain, empty_requests());
    signed.message.builder_index = 0;
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Reject(RejectReason::BuilderIndexMismatch {
            envelope: 0,
            bid: BUILDER,
        })
    );
}

#[test]
fn a_block_hash_that_is_not_the_bid_block_hash_must_reject() {
    let chain = chain(BUILDER, &empty_requests());
    let mut signed = envelope(&chain, empty_requests());
    signed.message.payload.block_hash = Root::repeat_byte(0xcc);
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Reject(RejectReason::BlockHashMismatch {
            payload: Root::repeat_byte(0xcc),
            bid: block_hash(),
        })
    );
}

fn withdrawal_request() -> WithdrawalRequest {
    WithdrawalRequest {
        source_address: Address::repeat_byte(0x31),
        validator_pubkey: [0x32; 48],
        amount: 1,
    }
}

#[test]
fn execution_requests_that_are_not_the_bid_commitment_must_reject() {
    let chain = chain(BUILDER, &empty_requests());
    let mut requests = empty_requests::<E>();
    requests.withdrawals = vec![withdrawal_request()].try_into().unwrap();
    let signed = envelope(&chain, requests.clone());
    assert_eq!(
        validate(&Seen::default(), &chain, &signed),
        Verdict::Reject(RejectReason::ExecutionRequestsRootMismatch {
            envelope: requests.tree_hash_root(),
            bid: empty_requests::<E>().tree_hash_root(),
        })
    );
}

fn consolidation(key: u8) -> ConsolidationRequest {
    ConsolidationRequest {
        source_address: Address::repeat_byte(key),
        source_pubkey: [key; 48],
        target_pubkey: [key.wrapping_add(1); 48],
    }
}

/// The SSZ bytes of `ExecutionRequests` with `consolidations` and no other request: five
/// offsets, then the consolidations. The list bound of the type does not limit this encoding.
fn requests_bytes(consolidations: &[ConsolidationRequest]) -> Vec<u8> {
    let fixed = 5 * 4;
    let end = fixed
        + consolidations
            .iter()
            .map(|c| c.as_ssz_bytes().len())
            .sum::<usize>();
    let mut bytes = Vec::new();
    for offset in [fixed, fixed, fixed, end, end] {
        bytes.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
    }
    for c in consolidations {
        bytes.extend_from_slice(&c.as_ssz_bytes());
    }
    bytes
}

#[test]
fn request_counts_past_a_limit_must_reject() {
    let at_limit = RequestCounts {
        withdrawals: MAX_WITHDRAWAL_REQUESTS,
        consolidations: MAX_CONSOLIDATION_REQUESTS,
        builder_deposits: MAX_BUILDER_DEPOSIT_REQUESTS,
        builder_exits: MAX_BUILDER_EXIT_REQUESTS,
    };
    assert_eq!(verify_execution_requests_limits::<E>(&at_limit), Ok(()));
    let past = [
        (
            RequestKind::Withdrawal,
            RequestCounts {
                withdrawals: MAX_WITHDRAWAL_REQUESTS + 1,
                ..at_limit
            },
            MAX_WITHDRAWAL_REQUESTS,
        ),
        (
            RequestKind::Consolidation,
            RequestCounts {
                consolidations: MAX_CONSOLIDATION_REQUESTS + 1,
                ..at_limit
            },
            MAX_CONSOLIDATION_REQUESTS,
        ),
        (
            RequestKind::BuilderDeposit,
            RequestCounts {
                builder_deposits: MAX_BUILDER_DEPOSIT_REQUESTS + 1,
                ..at_limit
            },
            MAX_BUILDER_DEPOSIT_REQUESTS,
        ),
        (
            RequestKind::BuilderExit,
            RequestCounts {
                builder_exits: MAX_BUILDER_EXIT_REQUESTS + 1,
                ..at_limit
            },
            MAX_BUILDER_EXIT_REQUESTS,
        ),
    ];
    for (kind, counts, limit) in past {
        assert_eq!(
            verify_execution_requests_limits::<E>(&counts),
            Err(RejectReason::TooManyRequests {
                kind,
                count: limit + 1,
                limit,
            })
        );
    }

    // The typed envelope cannot hold a count past a limit: the wire form fails to decode, so
    // the REJECT comes at deserialization, as the spec allows.
    let two: Vec<_> = (0..2).map(consolidation).collect();
    let mut requests = empty_requests::<E>();
    requests.consolidations = two.clone().try_into().unwrap();
    assert_eq!(
        ExecutionRequests::<E>::from_ssz_bytes(&requests_bytes(&two)),
        Ok(requests.clone())
    );
    let three: Vec<_> = (0..3).map(consolidation).collect();
    assert!(ExecutionRequests::<E>::from_ssz_bytes(&requests_bytes(&three)).is_err());

    // An envelope at the limit passes the count check.
    let chain = chain(BUILDER, &requests);
    let signed = envelope(&chain, requests);
    assert_eq!(
        RequestCounts::of(&signed.message.execution_requests).consolidations,
        MAX_CONSOLIDATION_REQUESTS
    );
    pending(validate(&Seen::default(), &chain, &signed));
}

#[test]
fn a_payload_with_too_many_withdrawals_must_reject() {
    assert_eq!(
        verify_withdrawals_limit::<E>(MINIMAL_MAX_WITHDRAWALS),
        Ok(())
    );
    assert_eq!(
        verify_withdrawals_limit::<E>(MINIMAL_MAX_WITHDRAWALS + 1),
        Err(RejectReason::TooManyWithdrawals {
            count: MINIMAL_MAX_WITHDRAWALS + 1,
            limit: MINIMAL_MAX_WITHDRAWALS,
        })
    );

    // The typed envelope cannot hold more withdrawals than the limit: the wire form fails to
    // decode. The mainnet limit is 16, so a mainnet envelope carries the extra withdrawal.
    let wire = |count: u64| {
        SignedExecutionPayloadEnvelope::<Mainnet> {
            message: ExecutionPayloadEnvelope {
                payload: payload(1, block_hash(), (0..count).map(withdrawal).collect()),
                execution_requests: ExecutionRequests {
                    deposits: Default::default(),
                    withdrawals: Default::default(),
                    consolidations: Default::default(),
                    builder_deposits: Default::default(),
                    builder_exits: Default::default(),
                },
                builder_index: BUILDER,
                beacon_block_root: Root::repeat_byte(0x09),
                parent_beacon_block_root: Root::repeat_byte(0x0a),
            },
            signature: SIG,
        }
        .as_ssz_bytes()
    };
    let at_limit = MINIMAL_MAX_WITHDRAWALS as u64;
    assert!(SignedExecutionPayloadEnvelope::<E>::from_ssz_bytes(&wire(at_limit)).is_ok());
    assert!(SignedExecutionPayloadEnvelope::<E>::from_ssz_bytes(&wire(at_limit + 1)).is_err());

    // An envelope at the limit passes the withdrawal check.
    let chain = chain(BUILDER, &empty_requests());
    let mut signed = envelope(&chain, empty_requests());
    signed.message.payload.withdrawals = (0..at_limit)
        .map(withdrawal)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    pending(validate(&Seen::default(), &chain, &signed));
}

#[test]
fn an_invalid_signature_must_reject_and_leave_seen_unchanged() {
    let chain = chain(BUILDER, &empty_requests());
    let signed = envelope(&chain, empty_requests());
    let mut seen = Seen::default();
    let (_, key) = pending(validate(&seen, &chain, &signed));
    assert_eq!(
        seen.resolve(key, Ok(false)),
        Verdict::Reject(RejectReason::InvalidSignature)
    );
    assert_eq!(seen, Seen::default());
}

#[test]
fn a_signature_check_with_no_verdict_must_ignore_and_leave_seen_unchanged() {
    let chain = chain(BUILDER, &empty_requests());
    let signed = envelope(&chain, empty_requests());
    let mut seen = Seen::default();
    let (_, key) = pending(validate(&seen, &chain, &signed));
    let verdict = seen.resolve(key, Err(BackendError("the verifier is down".into())));
    assert_eq!(verdict, Verdict::Ignore(IgnoreReason::NoSignatureVerdict));
    assert_eq!(seen, Seen::default());
}

#[test]
fn invalid_then_valid_copy() {
    let chain = chain(BUILDER, &empty_requests());
    let mut invalid_copy = envelope(&chain, empty_requests());
    invalid_copy.signature = OTHER_SIG;
    let valid_copy = envelope(&chain, empty_requests());
    let mut seen = Seen::default();

    let (_, key) = pending(validate(&seen, &chain, &invalid_copy));
    assert_eq!(
        seen.resolve(key, Ok(false)),
        Verdict::Reject(RejectReason::InvalidSignature)
    );
    assert_eq!(seen, Seen::default());

    let (sets, key) = pending(validate(&seen, &chain, &valid_copy));
    assert_eq!(sets, vec![expected_set(&chain, &valid_copy)]);
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    assert!(seen.has_execution_payload_envelope(chain.root, BUILDER));
}

#[test]
fn two_valid_copies_must_accept_only_one() {
    let chain = chain(BUILDER, &empty_requests());
    let signed = envelope(&chain, empty_requests());
    let mut seen = Seen::default();
    let (_, first) = pending(validate(&seen, &chain, &signed));
    let (_, second) = pending(validate(&seen, &chain, &signed));
    assert_eq!(seen.resolve(first, Ok(true)), Verdict::Accept);
    assert_eq!(
        seen.resolve(second, Ok(true)),
        Verdict::Ignore(IgnoreReason::EnvelopeAlreadySeen {
            block_root: chain.root,
            builder_index: BUILDER,
        })
    );
}

#[test]
fn a_self_build_envelope_must_name_the_proposer_as_signer() {
    let chain = chain(BUILDER_INDEX_SELF_BUILD, &empty_requests());
    let signed = envelope(&chain, empty_requests());
    assert_eq!(signed.message.builder_index, BUILDER_INDEX_SELF_BUILD);
    let mut seen = Seen::default();
    let (sets, key) = pending(validate(&seen, &chain, &signed));
    assert_eq!(sets, vec![expected_set(&chain, &signed)]);
    assert_eq!(sets[0].signers(), &[SignerRef::Validator(PROPOSER)]);
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    assert!(seen.has_execution_payload_envelope(chain.root, BUILDER_INDEX_SELF_BUILD));
}

/// The first time at which `slot` is the oldest current slot: the slot before it is past the
/// clock disparity. A prune at that time removes each slot before `slot`.
fn prune_time(slot: Slot) -> u64 {
    time_at(slot) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS + 1
}

/// `envelope.beacon_block_root` of `signed`.
fn root(signed: &SignedExecutionPayloadEnvelope<E>) -> Root {
    signed.message.beacon_block_root
}

/// The gas limit that `seen` keeps for the payload of `signed`.
fn gas_limit_of(seen: &Seen, signed: &SignedExecutionPayloadEnvelope<E>) -> Option<u64> {
    seen.execution_payload(signed.message.payload.block_hash)
        .map(|payload| payload.gas_limit)
}

/// The IGNORE of a copy of `signed` whose envelope is already seen.
fn already_seen(signed: &SignedExecutionPayloadEnvelope<E>) -> Verdict {
    Verdict::Ignore(IgnoreReason::EnvelopeAlreadySeen {
        block_root: root(signed),
        builder_index: signed.message.builder_index,
    })
}

/// The IGNORE of an envelope of `slot`, before the floor of `Seen`.
fn not_current(slot: Slot) -> Verdict {
    Verdict::Ignore(IgnoreReason::NotCurrentSlot { slot })
}

/// The verdicts of a signature that is not valid, and of a signature check with no verdict.
fn invalid_or_unverified() -> [(Result<bool, BackendError>, Verdict); 2] {
    [
        (Ok(false), Verdict::Reject(RejectReason::InvalidSignature)),
        (
            Err(BackendError("timeout".into())),
            Verdict::Ignore(IgnoreReason::NoSignatureVerdict),
        ),
    ]
}

fn validate_on<S: StoreView<E>>(
    seen: &Seen,
    store: &S,
    signed: &SignedExecutionPayloadEnvelope<E>,
) -> Verdict {
    validate_execution_payload_envelope_gossip(seen, store, signed)
}

/// Validates `signed` against `store`. A pending verdict resolves with a valid signature.
/// Gives the verdict of a valid copy of `signed`.
fn offer<S: StoreView<E>>(
    seen: &mut Seen,
    store: &S,
    signed: &SignedExecutionPayloadEnvelope<E>,
) -> Verdict {
    match validate_on(seen, store, signed) {
        Verdict::Pending { seen_key, .. } => seen.resolve(seen_key, Ok(true)),
        other => other,
    }
}

/// Validates `signed` against the store of `chain`, and resolves the pending verdict with a
/// valid signature. Gives the verdict of [`Seen::resolve`].
fn accept(seen: &mut Seen, chain: &Chain, signed: &SignedExecutionPayloadEnvelope<E>) -> Verdict {
    let (_, key) = pending(validate(seen, chain, signed));
    seen.resolve(key, Ok(true))
}

/// The envelope that the bid of `block` commits to, with no requests and the signature
/// [`SIG`].
fn envelope_of(block: &BeaconBlock<E>) -> SignedExecutionPayloadEnvelope<E> {
    let bid = &block.body.signed_execution_payload_bid.message;
    SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload: payload(block.slot, bid.block_hash, vec![]),
            execution_requests: empty_requests(),
            builder_index: bid.builder_index,
            beacon_block_root: block.tree_hash_root(),
            parent_beacon_block_root: block.parent_root,
        },
        signature: SIG,
    }
}

/// A block at `slot` on `parent` by [`PROPOSER`]. The bid of the block is by [`BUILDER`], has
/// the block hash `block_hash` and commits to no requests.
fn block_with_hash(parent: Root, slot: Slot, block_hash: Root) -> SignedBeaconBlock<E> {
    let mut block = block_with_bid(parent, slot, BUILDER, &empty_requests());
    block
        .message
        .body
        .signed_execution_payload_bid
        .message
        .block_hash = block_hash;
    block
}

/// The envelopes of four blocks on one store, at the start of slot 2: `a`, the block of
/// [`chain`], and `d` at slot 1 on the anchor, and `b` and `c` at slot 2 on `a`. Each bid is by
/// [`BUILDER`] and has its own block hash.
struct TwoSlots {
    chain: Chain,
    a: SignedExecutionPayloadEnvelope<E>,
    b: SignedExecutionPayloadEnvelope<E>,
    c: SignedExecutionPayloadEnvelope<E>,
    d: SignedExecutionPayloadEnvelope<E>,
}

fn two_slots() -> TwoSlots {
    let mut chain = chain(BUILDER, &empty_requests());
    let anchor_root = chain.block.message.parent_root;
    let d = block_with_hash(anchor_root, 1, Root::repeat_byte(0xd1));
    on_block(&mut chain.store, &Provider, &d).unwrap();
    on_tick(&mut chain.store, time_at(2)).unwrap();
    let b = block_with_hash(chain.root, 2, Root::repeat_byte(0xb2));
    let c = block_with_hash(chain.root, 2, Root::repeat_byte(0xc2));
    for block in [&b, &c] {
        on_block(&mut chain.store, &Provider, block).unwrap();
    }
    TwoSlots {
        a: envelope(&chain, empty_requests()),
        b: envelope_of(&b.message),
        c: envelope_of(&c.message),
        d: envelope_of(&d.message),
        chain,
    }
}

impl TwoSlots {
    /// Sets the clock of the store to `time_ms`, also to an earlier time.
    fn tick(&mut self, time_ms: u64) {
        on_tick(&mut self.chain.store, time_ms).unwrap();
        assert_eq!(self.chain.store.time_ms(), time_ms);
    }
}

/// The end of slot 1 plus the clock disparity: the last time at which slot 1 is current.
fn edge() -> u64 {
    time_at(2) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS
}

#[test]
fn an_envelope_slot_stays_through_the_clock_disparity_and_a_valid_envelope_then_removes_it() {
    let mut fx = two_slots();
    let mut seen = Seen::default();
    assert_eq!(accept(&mut seen, &fx.chain, &fx.a), Verdict::Accept);

    // At the end of slot 1 plus the clock disparity, slot 1 is still current. A valid envelope
    // of slot 2 at that time keeps slot 1 and its payload.
    fx.tick(edge());
    assert_eq!(accept(&mut seen, &fx.chain, &fx.b), Verdict::Accept);
    assert!(seen.has_execution_payload_envelope(root(&fx.a), BUILDER));
    assert_eq!(gas_limit_of(&seen, &fx.a), Some(GAS_LIMIT));
    assert_eq!(seen.execution_payload_envelope_slot_count(), 2);
    assert_eq!(seen.min_execution_payload_envelope_slot(), 1);
    assert_eq!(validate(&seen, &fx.chain, &fx.a), already_seen(&fx.a));

    // One millisecond later, slot 1 is not current. A valid envelope of slot 2 removes it and
    // its payload.
    fx.tick(edge() + 1);
    assert_eq!(accept(&mut seen, &fx.chain, &fx.c), Verdict::Accept);
    assert!(!seen.has_execution_payload_envelope(root(&fx.a), BUILDER));
    assert_eq!(gas_limit_of(&seen, &fx.a), None);
    for kept in [&fx.b, &fx.c] {
        assert!(seen.has_execution_payload_envelope(root(kept), BUILDER));
        assert_eq!(gas_limit_of(&seen, kept), Some(GAS_LIMIT));
    }
    assert_eq!(seen.execution_payload_envelope_slot_count(), 1);
    assert_eq!(seen.execution_payload_envelope_count(), 2);
    assert_eq!(seen.execution_payload_count(), 2);
    assert_eq!(seen.min_execution_payload_envelope_slot(), 2);
    // A copy of the accepted envelope of slot 1 is a duplicate. An envelope of another block
    // of slot 1 is not current.
    assert_eq!(validate(&seen, &fx.chain, &fx.a), already_seen(&fx.a));
    assert_eq!(validate(&seen, &fx.chain, &fx.d), not_current(1));
}

#[test]
fn an_explicit_prune_removes_an_envelope_slot_only_after_the_clock_disparity() {
    let fx = two_slots();
    let store = &fx.chain.store;
    let mut seen = Seen::default();
    for signed in [&fx.a, &fx.b] {
        assert_eq!(accept(&mut seen, &fx.chain, signed), Verdict::Accept);
    }

    seen.prune_execution_payload_envelopes(store, edge());
    assert!(seen.has_execution_payload_envelope(root(&fx.a), BUILDER));
    assert_eq!(gas_limit_of(&seen, &fx.a), Some(GAS_LIMIT));
    assert_eq!(seen.execution_payload_envelope_slot_count(), 2);
    assert_eq!(seen.min_execution_payload_envelope_slot(), 1);

    seen.prune_execution_payload_envelopes(store, edge() + 1);
    assert!(!seen.has_execution_payload_envelope(root(&fx.a), BUILDER));
    assert_eq!(gas_limit_of(&seen, &fx.a), None);
    assert!(seen.has_pruned_execution_payload_envelope(1, root(&fx.a), BUILDER));
    assert!(seen.has_execution_payload_envelope(root(&fx.b), BUILDER));
    assert_eq!(gas_limit_of(&seen, &fx.b), Some(GAS_LIMIT));
    assert_eq!(seen.execution_payload_envelope_slot_count(), 1);
    assert_eq!(seen.execution_payload_envelope_count(), 1);
    assert_eq!(seen.execution_payload_count(), 1);
    assert_eq!(seen.min_execution_payload_envelope_slot(), 2);
}

#[test]
fn a_pending_duplicate_envelope_across_a_prune_must_ignore() {
    // `false` is an explicit prune. `true` is a valid envelope of slot 2 that prunes.
    for automatic in [false, true] {
        let mut fx = two_slots();
        fx.tick(edge());
        let mut seen = Seen::default();
        // Two copies of the envelope of slot 1 pass validation at `edge`. The first copy
        // accepts before the prune.
        let (_, first) = pending(validate(&seen, &fx.chain, &fx.a));
        let (_, second) = pending(validate(&seen, &fx.chain, &fx.a));
        assert_eq!(seen.resolve(first, Ok(true)), Verdict::Accept);

        // At `edge + 1`, slot 1 is not current, and a prune removes it.
        fx.tick(edge() + 1);
        if automatic {
            assert_eq!(accept(&mut seen, &fx.chain, &fx.b), Verdict::Accept);
        } else {
            seen.prune_execution_payload_envelopes(&fx.chain.store, edge() + 1);
        }
        assert!(!seen.has_execution_payload_envelope(root(&fx.a), BUILDER));
        let pruned = seen.clone();

        // The second copy is IGNORE as a duplicate, and does not add slot 1 again.
        assert_eq!(
            seen.resolve(second, Ok(true)),
            already_seen(&fx.a),
            "{automatic}"
        );
        assert_eq!(seen, pruned, "{automatic}");
        assert_eq!(
            validate(&seen, &fx.chain, &fx.a),
            already_seen(&fx.a),
            "{automatic}"
        );
    }
}

#[test]
fn pending_envelopes_that_resolve_only_after_a_prune_must_ignore() {
    // `false` is an explicit prune. `true` is a valid envelope of slot 2 that prunes.
    for automatic in [false, true] {
        let mut fx = two_slots();
        fx.tick(edge());
        let mut seen = Seen::default();
        // Two copies pass validation at `edge`. Neither resolves before the prune.
        let (_, first) = pending(validate(&seen, &fx.chain, &fx.a));
        let (_, second) = pending(validate(&seen, &fx.chain, &fx.a));
        fx.tick(edge() + 1);
        if automatic {
            assert_eq!(accept(&mut seen, &fx.chain, &fx.b), Verdict::Accept);
        } else {
            seen.prune_execution_payload_envelopes(&fx.chain.store, edge() + 1);
        }
        let pruned = seen.clone();

        // Slot 1 is not current. Neither copy accepts, and neither adds slot 1 again.
        for key in [first, second] {
            assert_eq!(seen.resolve(key, Ok(true)), not_current(1), "{automatic}");
            assert_eq!(seen, pruned, "{automatic}");
        }
        assert!(!seen.has_execution_payload_envelope(root(&fx.a), BUILDER));
        assert!(!seen.has_pruned_execution_payload_envelope(1, root(&fx.a), BUILDER));
        assert_eq!(gas_limit_of(&seen, &fx.a), None);
    }
}

#[test]
fn an_envelope_of_a_pruned_slot_must_ignore_also_at_an_earlier_time() {
    let mut fx = two_slots();
    let mut seen = Seen::default();
    // Copies of slot 1 that pass validation before the prune, and resolve after it.
    let (_, late_a) = pending(validate(&seen, &fx.chain, &fx.a));
    let (_, late_d) = pending(validate(&seen, &fx.chain, &fx.d));
    assert_eq!(accept(&mut seen, &fx.chain, &fx.a), Verdict::Accept);
    fx.tick(edge() + 1);
    assert_eq!(accept(&mut seen, &fx.chain, &fx.b), Verdict::Accept);
    assert_eq!(seen.min_execution_payload_envelope_slot(), 2);
    let pruned = seen.clone();

    // The clock goes back to times at which slot 1 is current again.
    for time_ms in [edge(), time_at(2), time_at(1)] {
        fx.tick(time_ms);
        // A prune at an earlier time changes nothing.
        seen.prune_execution_payload_envelopes(&fx.chain.store, time_ms);
        assert_eq!(seen, pruned, "{time_ms}");
        // A copy of the accepted envelope of slot 1 is a duplicate. An envelope of another
        // block of slot 1 is not current.
        assert_eq!(
            validate(&seen, &fx.chain, &fx.a),
            already_seen(&fx.a),
            "{time_ms}"
        );
        assert_eq!(
            validate(&seen, &fx.chain, &fx.d),
            not_current(1),
            "{time_ms}"
        );
    }

    // The floor check comes after the block checks and before the slot check.
    let unknown = Root::repeat_byte(0x42);
    let mut unknown_block = fx.d.clone();
    unknown_block.message.beacon_block_root = unknown;
    assert_eq!(
        validate(&seen, &fx.chain, &unknown_block),
        Verdict::Ignore(IgnoreReason::UnknownBlock(unknown))
    );
    let mut wrong_slot = fx.c.clone();
    wrong_slot.message.payload.slot_number = 1;
    assert_eq!(validate(&seen, &fx.chain, &wrong_slot), not_current(1));

    // The copies that passed validation before the prune do not accept, and do not add slot 1
    // again.
    assert_eq!(seen.resolve(late_a, Ok(true)), already_seen(&fx.a));
    assert_eq!(seen.resolve(late_d, Ok(true)), not_current(1));
    assert_eq!(seen, pruned);

    // An envelope of a kept slot at the earlier time accepts, and the floor stays.
    assert_eq!(accept(&mut seen, &fx.chain, &fx.c), Verdict::Accept);
    assert_eq!(seen.min_execution_payload_envelope_slot(), 2);
    assert!(seen.has_pruned_execution_payload_envelope(1, root(&fx.a), BUILDER));
}

#[test]
fn seen_keeps_the_envelopes_of_the_last_pruned_slot_until_the_floor_moves_again() {
    let fx = two_slots();
    let store = &fx.chain.store;
    let (a, b, d) = (root(&fx.a), root(&fx.b), root(&fx.d));
    let mut seen = Seen::default();
    // Two copies of the envelopes of `a` and `b` pass validation at the start of slot 2. The
    // first copies accept.
    let [(_, a_first), (_, a_second)] =
        [(); 2].map(|()| pending(validate(&seen, &fx.chain, &fx.a)));
    let [(_, b_first), (_, b_second)] =
        [(); 2].map(|()| pending(validate(&seen, &fx.chain, &fx.b)));
    assert_eq!(seen.resolve(a_first, Ok(true)), Verdict::Accept);
    assert_eq!(seen.resolve(b_first, Ok(true)), Verdict::Accept);

    // The floor moves to 2. The record has the envelope of slot 1, for its slot, block and
    // builder only.
    seen.prune_execution_payload_envelopes(store, prune_time(2));
    assert!(seen.has_pruned_execution_payload_envelope(1, a, BUILDER));
    assert!(!seen.has_pruned_execution_payload_envelope(2, a, BUILDER));
    assert!(!seen.has_pruned_execution_payload_envelope(1, a, 0));
    assert!(!seen.has_pruned_execution_payload_envelope(1, d, BUILDER));
    assert!(!seen.has_pruned_execution_payload_envelope(2, b, BUILDER));
    let at_floor_2 = seen.clone();

    // The floor moves to 3. The record has the envelope of slot 2 only.
    seen.prune_execution_payload_envelopes(store, prune_time(3));
    assert!(!seen.has_pruned_execution_payload_envelope(1, a, BUILDER));
    assert!(seen.has_pruned_execution_payload_envelope(2, b, BUILDER));
    assert!(!seen.has_execution_payload_envelope(b, BUILDER));
    assert_eq!(seen.execution_payload_envelope_count(), 0);
    assert_eq!(seen.execution_payload_count(), 0);
    assert_eq!(seen.execution_payload_envelope_slot_count(), 0);
    let at_floor_3 = seen.clone();
    assert_eq!(
        seen.resolve(b_second.clone(), Ok(true)),
        already_seen(&fx.b)
    );
    assert_eq!(seen.resolve(a_second.clone(), Ok(true)), not_current(1));
    assert_eq!(seen, at_floor_3);

    // From the floor 2, a move to 4 removes the record: slot 3 has no envelope.
    let mut jumped = at_floor_2;
    jumped.prune_execution_payload_envelopes(store, prune_time(4));
    assert!(!jumped.has_pruned_execution_payload_envelope(1, a, BUILDER));
    assert!(!jumped.has_pruned_execution_payload_envelope(2, b, BUILDER));
    assert_eq!(jumped.execution_payload_envelope_count(), 0);
    for (key, slot) in [(a_second, 1), (b_second, 2)] {
        assert_eq!(jumped.resolve(key, Ok(true)), not_current(slot));
    }
}

#[test]
fn an_invalid_or_unverified_envelope_does_not_prune_seen() {
    let mut fx = two_slots();
    let mut seen = Seen::default();
    assert_eq!(accept(&mut seen, &fx.chain, &fx.a), Verdict::Accept);
    // A valid envelope of slot 2 at this time removes slot 1.
    fx.tick(prune_time(2));
    let before = seen.clone();

    for (signatures, want) in invalid_or_unverified() {
        let (_, key) = pending(validate(&seen, &fx.chain, &fx.b));
        assert_eq!(seen.resolve(key, signatures), want);
        assert_eq!(seen, before);
    }
    // A copy that fails a check before the signature gives no key.
    let b_hash = fx.b.message.payload.block_hash;
    let mut wrong_slot = fx.b.clone();
    wrong_slot.message.payload.slot_number = 3;
    let mut wrong_builder = fx.b.clone();
    wrong_builder.message.builder_index = 0;
    let mut wrong_hash = fx.b.clone();
    wrong_hash.message.payload.block_hash = Root::repeat_byte(0xcc);
    let mut wrong_requests = fx.b.clone();
    wrong_requests.message.execution_requests.withdrawals =
        vec![withdrawal_request()].try_into().unwrap();
    let requests_root = wrong_requests.message.execution_requests.tree_hash_root();
    let unknown = Root::repeat_byte(0x42);
    let mut unknown_block = fx.b.clone();
    unknown_block.message.beacon_block_root = unknown;
    for (copy, want) in [
        (
            &wrong_slot,
            Verdict::Reject(RejectReason::SlotMismatch {
                block: 2,
                payload: 3,
            }),
        ),
        (
            &wrong_builder,
            Verdict::Reject(RejectReason::BuilderIndexMismatch {
                envelope: 0,
                bid: BUILDER,
            }),
        ),
        (
            &wrong_hash,
            Verdict::Reject(RejectReason::BlockHashMismatch {
                payload: Root::repeat_byte(0xcc),
                bid: b_hash,
            }),
        ),
        (
            &wrong_requests,
            Verdict::Reject(RejectReason::ExecutionRequestsRootMismatch {
                envelope: requests_root,
                bid: empty_requests::<E>().tree_hash_root(),
            }),
        ),
        (
            &unknown_block,
            Verdict::Ignore(IgnoreReason::UnknownBlock(unknown)),
        ),
    ] {
        assert_eq!(validate(&seen, &fx.chain, copy), want);
    }
    assert_eq!(seen, before);
    assert!(seen.has_execution_payload_envelope(root(&fx.a), BUILDER));
    assert_eq!(seen.min_execution_payload_envelope_slot(), 1);

    // The valid copy removes slot 1.
    assert_eq!(accept(&mut seen, &fx.chain, &fx.b), Verdict::Accept);
    assert!(!seen.has_execution_payload_envelope(root(&fx.a), BUILDER));
    assert_eq!(seen.min_execution_payload_envelope_slot(), 2);
}

/// A view of the store of `chain` with other blocks, a slot duration of 1 ms, and the clock at
/// the genesis time. Each block is the block of `chain` with another slot and block hash, and
/// has the post-state of that block. At the genesis time the oldest current slot is 0, so the
/// clock removes no slot of these blocks.
struct ManyBlocks<'a> {
    chain: &'a Chain,
    blocks: HashMap<Root, BeaconBlock<E>>,
}

impl<'a> ManyBlocks<'a> {
    fn new(chain: &'a Chain) -> Self {
        Self {
            chain,
            blocks: HashMap::new(),
        }
    }

    /// Adds a block of `slot` whose block hash has `slot` and `index`, and gives its envelope.
    fn add(&mut self, slot: Slot, index: u8) -> SignedExecutionPayloadEnvelope<E> {
        let mut hash = [0x77; 32];
        hash[..8].copy_from_slice(&slot.to_le_bytes());
        hash[8] = index;
        let mut block = self.chain.block.message.clone();
        block.slot = slot;
        block.body.signed_execution_payload_bid.message.block_hash = Root::from(hash);
        let signed = envelope_of(&block);
        self.blocks.insert(block.tree_hash_root(), block);
        signed
    }
}

impl StoreView<E> for ManyBlocks<'_> {
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>> {
        self.blocks.get(&root)
    }

    fn block_state(&self, root: Root) -> Option<&BeaconState<E>> {
        if self.blocks.contains_key(&root) {
            self.chain.store.block_state(self.chain.root)
        } else {
            None
        }
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        self.chain.store.finalized_checkpoint()
    }

    fn genesis_time_ms(&self) -> u64 {
        self.chain.store.genesis_time_ms()
    }

    fn slot_duration_ms(&self) -> NonZeroU64 {
        NonZeroU64::MIN
    }

    fn head_state(&self) -> Option<&BeaconState<E>> {
        StoreView::head_state(&self.chain.store)
    }

    fn time_ms(&self) -> u64 {
        self.genesis_time_ms()
    }
}

#[test]
fn seen_keeps_at_most_the_envelope_slot_limit_and_a_removed_slot_must_not_accept_again() {
    assert_eq!(MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS, 8);
    let chain = chain(BUILDER, &empty_requests());
    let mut view = ManyBlocks::new(&chain);
    let extra = 4;
    let slots = (MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS + extra) as Slot;
    let envelopes: Vec<_> = (1..=slots).map(|slot| view.add(slot, 0)).collect();
    let next = view.add(slots + 1, 0);
    assert_eq!(oldest_current_slot(&view, view.time_ms()), 0);
    let mut seen = Seen::default();
    let last_removed = extra as Slot;
    // Keys that are pending before the limit removes their slots: the first slot, and the
    // last slot that the limit removes.
    let early = [1, last_removed].map(|slot| {
        let signed = &envelopes[slot as usize - 1];
        (slot, signed, pending(validate_on(&seen, &view, signed)).1)
    });
    for signed in &envelopes {
        assert_eq!(offer(&mut seen, &view, signed), Verdict::Accept);
        assert!(seen.has_execution_payload_envelope(root(signed), BUILDER));
        assert!(
            seen.execution_payload_envelope_slot_count()
                <= MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS
        );
    }
    assert_eq!(
        seen.execution_payload_envelope_slot_count(),
        MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS
    );
    assert_eq!(
        seen.execution_payload_envelope_count(),
        MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS
    );
    assert_eq!(
        seen.execution_payload_count(),
        MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS
    );
    // The oldest slots go first, with their payloads.
    for (slot, signed) in (1..).zip(&envelopes) {
        let kept = slot > extra as Slot;
        assert_eq!(
            seen.has_execution_payload_envelope(root(signed), BUILDER),
            kept,
            "{slot}"
        );
        assert_eq!(gas_limit_of(&seen, signed).is_some(), kept, "{slot}");
    }
    assert_eq!(seen.min_execution_payload_envelope_slot(), last_removed + 1);
    let full = seen.clone();

    // A valid copy of an envelope of a removed slot must not accept again. The last removed
    // slot is a duplicate, and the slots before it are not current.
    for (slot, signed) in (1..=last_removed).zip(&envelopes) {
        let want = if slot == last_removed {
            already_seen(signed)
        } else {
            not_current(slot)
        };
        assert_eq!(offer(&mut seen, &view, signed), want, "{slot}");
        assert_eq!(seen, full, "{slot}");
    }
    // A key that was pending before the limit removed its slot must not accept either, and
    // leaves Seen as it is.
    for (slot, signed, key) in early {
        let want = if slot == last_removed {
            already_seen(signed)
        } else {
            not_current(slot)
        };
        assert_eq!(seen.resolve(key, Ok(true)), want, "{slot}");
        assert_eq!(seen, full, "{slot}");
    }
    // Each kept slot stays a duplicate.
    for signed in &envelopes[extra..] {
        assert_eq!(offer(&mut seen, &view, signed), already_seen(signed));
    }
    assert_eq!(seen, full);

    // An invalid or unverified envelope of a new slot removes no slot.
    for (signatures, want) in invalid_or_unverified() {
        let (_, key) = pending(validate_on(&seen, &view, &next));
        assert_eq!(seen.resolve(key, signatures), want);
        assert_eq!(seen, full);
    }
    // A valid envelope of a new slot removes the oldest kept slot.
    let oldest_kept = &envelopes[extra];
    assert_eq!(offer(&mut seen, &view, &next), Verdict::Accept);
    assert!(!seen.has_execution_payload_envelope(root(oldest_kept), BUILDER));
    assert!(seen.has_pruned_execution_payload_envelope(
        last_removed + 1,
        root(oldest_kept),
        BUILDER
    ));
    assert_eq!(seen.min_execution_payload_envelope_slot(), last_removed + 2);
    assert_eq!(
        seen.execution_payload_envelope_slot_count(),
        MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS
    );
}

#[test]
fn a_full_envelope_slot_keeps_each_envelope_and_ignores_a_new_block() {
    assert_eq!(MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT, 16);
    let limit = MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT;
    let chain = chain(BUILDER, &empty_requests());
    let mut view = ManyBlocks::new(&chain);
    // 17 blocks of slot 1, each with its own block hash, and a block of slot 2.
    let envelopes: Vec<_> = (0..=limit).map(|i| view.add(1, i as u8)).collect();
    let other_slot = view.add(2, 0);
    let (kept, new) = (&envelopes[..limit], &envelopes[limit]);
    let mut seen = Seen::default();
    for signed in kept {
        assert_eq!(offer(&mut seen, &view, signed), Verdict::Accept);
    }
    assert_eq!(seen.execution_payload_envelope_count(), limit);
    assert_eq!(seen.execution_payload_count(), limit);
    assert_eq!(seen.execution_payload_envelope_slot_count(), 1);
    let full = seen.clone();

    // An invalid or unverified envelope of the new block leaves Seen as it was.
    for (signatures, want) in invalid_or_unverified() {
        let (_, key) = pending(validate_on(&seen, &view, new));
        assert_eq!(seen.resolve(key, signatures), want);
        assert_eq!(seen, full);
    }
    // A valid envelope of the new block is IGNORE: the slot is full. It removes no envelope
    // and no payload, also a second time.
    let slot_full = Verdict::Ignore(IgnoreReason::ExecutionPayloadEnvelopeSlotFull { slot: 1 });
    for _ in 0..2 {
        assert_eq!(offer(&mut seen, &view, new), slot_full);
        assert_eq!(seen, full);
    }
    assert!(!seen.has_execution_payload_envelope(root(new), BUILDER));
    assert_eq!(gas_limit_of(&seen, new), None);
    // Each kept envelope stays a duplicate, and its payload stays.
    for signed in kept {
        assert_eq!(validate_on(&seen, &view, signed), already_seen(signed));
        assert_eq!(gas_limit_of(&seen, signed), Some(GAS_LIMIT));
    }
    // Another slot is not full.
    assert_eq!(offer(&mut seen, &view, &other_slot), Verdict::Accept);
    assert_eq!(seen.execution_payload_envelope_slot_count(), 2);
    assert_eq!(seen.execution_payload_envelope_count(), limit + 1);
}
