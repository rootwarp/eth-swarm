//! `on_execution_payload_envelope` (G L1113-1135) and `verify_execution_payload_envelope`
//! (G L683-728) on a block that the tests build.
//!
//! The test provider does not run the state transition. The post-state of a block is the parent
//! state at the slot of the block, with the header and the bid of the block. The block commits
//! to that post-state, so the root of the latest block header of the post-state is the block
//! root. The hooks give the signature, data availability and execution engine verdicts that
//! each test chooses, and record each call.

use consensus_types::gloas::{
    BeaconBlock, BeaconBlockHeader, BeaconState, DepositRequest, ExecutionPayload,
    ExecutionPayloadEnvelope, ExecutionRequests, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
    Withdrawal,
};
use consensus_types::primitives::{
    Address, BLSSignature, BuilderIndex, KZGCommitment, Root, Slot, VersionedHash, U256,
};
use consensus_types::signing::{
    compute_signing_root, SignatureSet, SignerRef, BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER,
};
use consensus_types::Minimal;
use fork_choice::{
    get_forkchoice_store, is_payload_verified, on_block, on_execution_payload_envelope, on_tick,
    verify_execution_payload_envelope, DataAvailability, DataAvailabilityCheck, EnvelopeError,
    Error, ExecutionEngine, NewPayloadRequestRef, PayloadImport, SignatureVerifier, StateProvider,
    Store,
};
use sha2::{Digest, Sha256};
use ssz_types::FixedVector;
use state_transition::accessors::{builder_key_version, get_domain};
use state_transition::testing::{builder, empty_requests, genesis_state, signed_block};
use state_transition::{state_root, BackendError, StfError};
use std::cell::RefCell;
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
const COMMITMENT: KZGCommitment = [0xc0; 48];

fn slot_duration() -> NonZeroU64 {
    NonZeroU64::new(SLOT_MS).unwrap()
}

fn time_at(slot: Slot) -> u64 {
    GENESIS_TIME * 1000 + slot * SLOT_MS
}

fn withdrawal() -> Withdrawal {
    Withdrawal {
        index: 0,
        validator_index: 0,
        address: Address::repeat_byte(0x22),
        amount: 1,
    }
}

/// A genesis state with 64 validators, the builders 0 and 1, a latest block hash and one
/// expected withdrawal, and its anchor block.
fn anchor() -> (BeaconState<E>, BeaconBlock<E>) {
    let mut state = genesis_state::<E>(&[32_000_000_000; 64]);
    state.genesis_time = GENESIS_TIME;
    state.latest_block_hash = Root::repeat_byte(0x01);
    state
        .payload_expected_withdrawals
        .push(withdrawal())
        .unwrap();
    for key in [0xa0, 0xa1] {
        state.builders.push(builder(key, 5_000_000_000, 0)).unwrap();
    }
    let mut block = signed_block::<E>(0, 0).message;
    block.state_root = state_root(&mut state).unwrap();
    (state, block)
}

/// The post-state of `block` on `parent`: the slot, the header and the bid of the block, as
/// `process_block_header` and `process_execution_payload_bid` set them.
fn post_state(parent: &BeaconState<E>, block: &BeaconBlock<E>) -> BeaconState<E> {
    let mut state = parent.clone();
    state.slot = block.slot;
    state.latest_block_header = BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: Root::ZERO,
        body_root: block.body.tree_hash_root(),
    };
    state.latest_execution_payload_bid = block.body.signed_execution_payload_bid.message.clone();
    state
}

/// The test provider: [`post_state`]. `process_slots` only sets the slot.
struct Provider;

impl StateProvider<E> for Provider {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        signed_block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        *state = post_state(state, &signed_block.message);
        Ok(())
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        state.slot = slot;
        Ok(())
    }
}

/// A store with the anchor and one block at slot 1, and that block.
struct Chain {
    store: Store<E>,
    anchor_root: Root,
    block: SignedBeaconBlock<E>,
    root: Root,
}

impl Chain {
    /// The post-state of the block in the store.
    fn state(&self) -> &BeaconState<E> {
        self.store.block_state(self.root).unwrap()
    }
}

/// A block at `slot` on `parent` whose bid is by `builder_index`. If `full` is true, its bid
/// builds on the payload of the bid of `parent` (a FULL parent), else on another hash.
fn child(
    parent: &BeaconBlock<E>,
    parent_state: &BeaconState<E>,
    slot: Slot,
    builder_index: BuilderIndex,
    full: bool,
) -> SignedBeaconBlock<E> {
    let mut block = signed_block::<E>(slot, PROPOSER);
    block.message.parent_root = parent.tree_hash_root();
    let parent_bid = &parent.body.signed_execution_payload_bid.message;
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.builder_index = builder_index;
    bid.parent_block_hash = if full {
        parent_bid.block_hash
    } else {
        Root::repeat_byte(0xee)
    };
    bid.block_hash = Root::repeat_byte(0xb0 + slot as u8);
    bid.prev_randao = Root::repeat_byte(0x5a);
    bid.gas_limit = GAS_LIMIT;
    bid.execution_requests_root = empty_requests::<E>().tree_hash_root();
    bid.blob_kzg_commitments = vec![COMMITMENT].try_into().unwrap();
    let mut post = post_state(parent_state, &block.message);
    block.message.state_root = state_root(&mut post).unwrap();
    block
}

/// A store with the anchor and a block at slot 1 on its EMPTY payload, by `builder_index`.
fn chain(builder_index: BuilderIndex) -> Chain {
    let (state, anchor_block) = anchor();
    let anchor_root = anchor_block.tree_hash_root();
    let mut store =
        get_forkchoice_store(state.clone(), anchor_block.clone(), slot_duration()).unwrap();
    on_tick(&mut store, time_at(1)).unwrap();
    let block = child(&anchor_block, &state, 1, builder_index, false);
    on_block(&mut store, &Provider, &block).unwrap();
    let root = block.message.tree_hash_root();
    Chain {
        store,
        anchor_root,
        block,
        root,
    }
}

/// The envelope of the block of `chain` that every check of `verify_execution_payload_envelope`
/// accepts, with the signature [`SIG`].
fn envelope(chain: &Chain) -> SignedExecutionPayloadEnvelope<E> {
    let state = chain.state();
    let bid = &state.latest_execution_payload_bid;
    let payload = ExecutionPayload {
        parent_hash: state.latest_block_hash,
        fee_recipient: Address::repeat_byte(0xfe),
        state_root: Root::repeat_byte(0x02),
        receipts_root: Root::repeat_byte(0x03),
        logs_bloom: FixedVector::default(),
        prev_randao: bid.prev_randao,
        block_number: 1,
        gas_limit: bid.gas_limit,
        gas_used: 0,
        timestamp: GENESIS_TIME + state.slot * SLOT_MS / 1000,
        extra_data: Default::default(),
        base_fee_per_gas: U256::from(7),
        block_hash: bid.block_hash,
        transactions: Default::default(),
        withdrawals: vec![withdrawal()].try_into().unwrap(),
        blob_gas_used: 0,
        excess_blob_gas: 0,
        block_access_list: Default::default(),
        slot_number: state.slot,
    };
    SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload,
            execution_requests: empty_requests(),
            builder_index: bid.builder_index,
            beacon_block_root: chain.root,
            parent_beacon_block_root: state.latest_block_header.parent_root,
        },
        signature: SIG,
    }
}

/// What the execution engine hook got from one call.
#[derive(Debug, Clone, PartialEq)]
struct Request {
    block_hash: Root,
    versioned_hashes: Vec<VersionedHash>,
    parent_beacon_block_root: Root,
    execution_requests_root: Root,
}

/// The hooks of one test: fixed verdicts, and a record of each call.
struct Hooks {
    signature: Result<bool, BackendError>,
    availability: DataAvailability,
    import: PayloadImport,
    sets: RefCell<Vec<SignatureSet>>,
    availability_checks: RefCell<Vec<Root>>,
    requests: RefCell<Vec<Request>>,
}

impl Hooks {
    fn new(import: PayloadImport) -> Self {
        Self {
            signature: Ok(true),
            availability: DataAvailability::Available,
            import,
            sets: RefCell::default(),
            availability_checks: RefCell::default(),
            requests: RefCell::default(),
        }
    }
}

impl SignatureVerifier<E> for Hooks {
    fn verify_signature_sets(
        &self,
        _: &BeaconState<E>,
        sets: &[SignatureSet],
    ) -> Result<bool, BackendError> {
        self.sets.borrow_mut().extend_from_slice(sets);
        self.signature.clone()
    }
}

impl DataAvailabilityCheck for Hooks {
    fn is_data_available(&self, beacon_block_root: Root) -> DataAvailability {
        self.availability_checks
            .borrow_mut()
            .push(beacon_block_root);
        self.availability
    }
}

impl ExecutionEngine<E> for Hooks {
    fn verify_and_notify_new_payload(
        &self,
        request: &NewPayloadRequestRef<'_, E>,
    ) -> PayloadImport {
        self.requests.borrow_mut().push(Request {
            block_hash: request.execution_payload.block_hash,
            versioned_hashes: request.versioned_hashes.to_vec(),
            parent_beacon_block_root: request.parent_beacon_block_root,
            execution_requests_root: request.execution_requests.tree_hash_root(),
        });
        self.import
    }
}

/// `kzg_commitment_to_versioned_hash` (`deneb/beacon-chain.md`):
/// `VERSIONED_HASH_VERSION_KZG + sha256(commitment)[1:]`.
fn versioned_hash(commitment: &KZGCommitment) -> VersionedHash {
    let mut hash: [u8; 32] = Sha256::digest(commitment).into();
    hash[0] = 0x01;
    VersionedHash::from(hash)
}

/// The set of `verify_execution_payload_envelope_signature` (`gloas/beacon-chain.md`
/// L2107-2120) for `signed` on `state`.
fn expected_set(
    state: &BeaconState<E>,
    signed: &SignedExecutionPayloadEnvelope<E>,
) -> SignatureSet {
    let index = signed.message.builder_index;
    let signer = if index == BUILDER_INDEX_SELF_BUILD {
        SignerRef::Validator(state.latest_block_header.proposer_index)
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

#[test]
fn a_permitted_valid_answer_with_available_data_verifies_the_payload() {
    let mut chain = chain(BUILDER);
    let signed = envelope(&chain);
    let hooks = Hooks::new(PayloadImport::Valid);
    assert!(!is_payload_verified(&chain.store, chain.root));
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Ok(())
    );
    assert!(is_payload_verified(&chain.store, chain.root));
    assert_eq!(*hooks.availability_checks.borrow(), vec![chain.root]);
    assert_eq!(
        *hooks.sets.borrow(),
        vec![expected_set(chain.state(), &signed)]
    );
    assert_eq!(
        *hooks.requests.borrow(),
        vec![Request {
            block_hash: signed.message.payload.block_hash,
            versioned_hashes: vec![versioned_hash(&COMMITMENT)],
            parent_beacon_block_root: chain.anchor_root,
            execution_requests_root: empty_requests::<E>().tree_hash_root(),
        }]
    );
}

#[test]
fn a_permitted_optimistic_answer_with_available_data_verifies_the_payload() {
    let mut chain = chain(BUILDER);
    let signed = envelope(&chain);
    let hooks = Hooks::new(PayloadImport::Optimistic);
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Ok(())
    );
    assert!(is_payload_verified(&chain.store, chain.root));
}

#[test]
fn missing_data_availability_leaves_the_payload_unverified() {
    let mut chain = chain(BUILDER);
    let signed = envelope(&chain);
    let mut hooks = Hooks::new(PayloadImport::Valid);
    hooks.availability = DataAvailability::Unavailable;
    let before = chain.store.clone();
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Err(Error::DataUnavailable(chain.root))
    );
    assert!(!is_payload_verified(&chain.store, chain.root));
    assert_eq!(chain.store, before);
    // The spec checks availability before the envelope: no signature check and no
    // execution engine call.
    assert!(hooks.sets.borrow().is_empty());
    assert!(hooks.requests.borrow().is_empty());
}

#[test]
fn a_refused_execution_answer_leaves_the_payload_unverified() {
    let mut chain = chain(BUILDER);
    let signed = envelope(&chain);
    let hooks = Hooks::new(PayloadImport::Refused);
    let before = chain.store.clone();
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Err(Error::PayloadRefused(chain.root))
    );
    assert!(!is_payload_verified(&chain.store, chain.root));
    assert_eq!(chain.store, before);
    assert_eq!(hooks.requests.borrow().len(), 1);
}

#[test]
fn an_envelope_for_an_unknown_beacon_block_root_fails() {
    let mut chain = chain(BUILDER);
    let mut signed = envelope(&chain);
    let unknown = Root::repeat_byte(0x42);
    signed.message.beacon_block_root = unknown;
    let hooks = Hooks::new(PayloadImport::Valid);
    let before = chain.store.clone();
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Err(Error::InvalidEnvelope(EnvelopeError::UnknownBeaconBlock(
            unknown
        )))
    );
    assert_eq!(chain.store, before);
    assert!(hooks.availability_checks.borrow().is_empty());
}

#[test]
fn an_envelope_with_a_wrong_beacon_block_root_fails_verification() {
    let chain = chain(BUILDER);
    let mut signed = envelope(&chain);
    // Another block of the store, which the post-state of this block is not.
    signed.message.beacon_block_root = chain.anchor_root;
    let hooks = Hooks::new(PayloadImport::Valid);
    assert_eq!(
        verify_execution_payload_envelope(chain.state(), &signed, slot_duration(), &hooks),
        Err(Error::InvalidEnvelope(EnvelopeError::BeaconBlockRoot {
            envelope: chain.anchor_root,
            block: chain.root,
        }))
    );
    assert!(hooks.requests.borrow().is_empty());
}

#[test]
fn an_envelope_with_a_wrong_slot_fails() {
    let mut chain = chain(BUILDER);
    let mut signed = envelope(&chain);
    signed.message.payload.slot_number = 2;
    let hooks = Hooks::new(PayloadImport::Valid);
    let before = chain.store.clone();
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Err(Error::InvalidEnvelope(EnvelopeError::Slot {
            payload: 2,
            state: 1,
        }))
    );
    assert_eq!(chain.store, before);
    assert!(hooks.requests.borrow().is_empty());
}

#[test]
fn an_envelope_with_a_wrong_builder_index_fails() {
    let mut chain = chain(BUILDER);
    let mut signed = envelope(&chain);
    signed.message.builder_index = 0;
    let hooks = Hooks::new(PayloadImport::Valid);
    let before = chain.store.clone();
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Err(Error::InvalidEnvelope(EnvelopeError::BuilderIndex {
            envelope: 0,
            bid: BUILDER,
        }))
    );
    assert_eq!(chain.store, before);
    // The signature check comes first, with the key of the builder that the envelope names.
    assert_eq!(
        *hooks.sets.borrow(),
        vec![expected_set(chain.state(), &signed)]
    );
    assert!(hooks.requests.borrow().is_empty());
}

#[test]
fn an_envelope_of_a_builder_outside_the_registry_fails() {
    let mut chain = chain(BUILDER);
    let mut signed = envelope(&chain);
    signed.message.builder_index = 9;
    let hooks = Hooks::new(PayloadImport::Valid);
    let before = chain.store.clone();
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Err(Error::InvalidEnvelope(EnvelopeError::UnknownBuilder(9)))
    );
    assert_eq!(chain.store, before);
    assert!(hooks.sets.borrow().is_empty());
}

#[test]
fn an_invalid_signature_fails_and_leaves_the_store_unchanged() {
    let mut chain = chain(BUILDER);
    let signed = envelope(&chain);
    let mut hooks = Hooks::new(PayloadImport::Valid);
    hooks.signature = Ok(false);
    let before = chain.store.clone();
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Err(Error::InvalidEnvelope(EnvelopeError::InvalidSignature))
    );
    assert_eq!(chain.store, before);
    assert!(hooks.requests.borrow().is_empty());
}

#[test]
fn a_signature_check_with_no_verdict_fails_and_leaves_the_store_unchanged() {
    let mut chain = chain(BUILDER);
    let signed = envelope(&chain);
    let mut hooks = Hooks::new(PayloadImport::Valid);
    let down = BackendError("the verifier is down".into());
    hooks.signature = Err(down.clone());
    let before = chain.store.clone();
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Err(Error::NoSignatureVerdict(down))
    );
    assert_eq!(chain.store, before);
    assert!(hooks.requests.borrow().is_empty());
}

#[test]
fn a_self_build_envelope_is_checked_with_the_proposer_key() {
    let mut chain = chain(BUILDER_INDEX_SELF_BUILD);
    let signed = envelope(&chain);
    let hooks = Hooks::new(PayloadImport::Valid);
    assert_eq!(
        on_execution_payload_envelope(&mut chain.store, &hooks, &signed),
        Ok(())
    );
    let sets = hooks.sets.borrow();
    assert_eq!(*sets, vec![expected_set(chain.state(), &signed)]);
    assert_eq!(sets[0].signers(), &[SignerRef::Validator(PROPOSER)]);
}

#[test]
fn a_child_of_a_verified_full_parent_passes_the_parent_payload_check() {
    let mut chain = chain(BUILDER);
    on_tick(&mut chain.store, time_at(2)).unwrap();
    let full_child = child(&chain.block.message, chain.state(), 2, BUILDER, true);
    assert_eq!(
        on_block(&mut chain.store.clone(), &Provider, &full_child),
        Err(Error::ParentPayloadNotVerified(chain.root))
    );
    let signed = envelope(&chain);
    let hooks = Hooks::new(PayloadImport::Optimistic);
    on_execution_payload_envelope(&mut chain.store, &hooks, &signed).unwrap();
    assert_eq!(on_block(&mut chain.store, &Provider, &full_child), Ok(()));
    let child_root = full_child.message.tree_hash_root();
    assert!(chain.store.block(child_root).is_some());
}

/// Requests with one deposit, which the bid of each test does not commit to.
fn one_deposit() -> ExecutionRequests<E> {
    let mut requests = empty_requests::<E>();
    requests.deposits = vec![DepositRequest {
        pubkey: [0x01; 48],
        withdrawal_credentials: Root::repeat_byte(0x02),
        amount: 32_000_000_000,
        signature: [0x03; 96],
        index: 0,
    }]
    .try_into()
    .unwrap();
    requests
}

#[test]
fn a_failed_call_leaves_the_store_unchanged() {
    let mut chain = chain(BUILDER);
    let state = chain.state().clone();
    let bid = state.latest_execution_payload_bid.clone();
    let other = Root::repeat_byte(0x42);
    let requests = one_deposit();
    let requests_root = requests.tree_hash_root();
    let expected_time = GENESIS_TIME + SLOT_MS / 1000;
    type Edit = Box<dyn Fn(&mut ExecutionPayloadEnvelope<E>)>;
    let cases: Vec<(Edit, EnvelopeError)> = vec![
        (
            Box::new(move |e| e.parent_beacon_block_root = other),
            EnvelopeError::ParentBeaconBlockRoot {
                envelope: other,
                state: chain.anchor_root,
            },
        ),
        (
            Box::new(move |e| e.payload.prev_randao = other),
            EnvelopeError::PrevRandao {
                payload: other,
                bid: bid.prev_randao,
            },
        ),
        (
            Box::new(|e| e.payload.gas_limit = GAS_LIMIT + 1),
            EnvelopeError::GasLimit {
                payload: GAS_LIMIT + 1,
                bid: GAS_LIMIT,
            },
        ),
        (
            Box::new(move |e| e.payload.block_hash = other),
            EnvelopeError::BlockHash {
                payload: other,
                bid: bid.block_hash,
            },
        ),
        (
            Box::new(move |e| e.execution_requests = requests.clone()),
            EnvelopeError::ExecutionRequestsRoot {
                envelope: requests_root,
                bid: bid.execution_requests_root,
            },
        ),
        (
            Box::new(move |e| e.payload.parent_hash = other),
            EnvelopeError::ParentHash {
                payload: other,
                state: state.latest_block_hash,
            },
        ),
        (
            Box::new(move |e| e.payload.timestamp = expected_time + 1),
            EnvelopeError::Timestamp {
                payload: expected_time + 1,
                expected: expected_time,
            },
        ),
        (
            Box::new(|e| e.payload.withdrawals = Default::default()),
            EnvelopeError::WithdrawalsRoot {
                payload: Default::default(),
                expected: Default::default(),
            },
        ),
    ];
    for (edit, want) in cases {
        let mut signed = envelope(&chain);
        edit(&mut signed.message);
        let hooks = Hooks::new(PayloadImport::Valid);
        let before = chain.store.clone();
        let got = on_execution_payload_envelope(&mut chain.store, &hooks, &signed);
        match (&got, &want) {
            // The roots of the withdrawals: compare the kind of the failure only.
            (
                Err(Error::InvalidEnvelope(EnvelopeError::WithdrawalsRoot { payload, expected })),
                EnvelopeError::WithdrawalsRoot { .. },
            ) => {
                assert_eq!(
                    *payload,
                    signed.message.payload.withdrawals.tree_hash_root()
                );
                assert_ne!(payload, expected);
            }
            _ => assert_eq!(got, Err(Error::InvalidEnvelope(want))),
        }
        assert_eq!(chain.store, before);
        assert!(!is_payload_verified(&chain.store, chain.root));
        assert!(hooks.requests.borrow().is_empty());
    }
}
