//! `validate_execution_payload_envelope_gossip` (`gloas/p2p-interface.md` L811-885) against a
//! fork-choice store that the tests build, and `Seen::resolve` after the signature check.
//!
//! The test provider does not run the state transition. The post-state of a block is the parent
//! state at the slot of the block, with the header of the block. The gossip checks read only the
//! block, its bid, and the builders, the proposer and the fork of that state.
//!
//! This crate links no BLS library. A test gives the BLS verdict of a pending set itself.

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
use fork_choice::{get_forkchoice_store, on_block, on_tick, StateProvider, Store};
use gossip_validation::{
    validate_execution_payload_envelope_gossip, verify_execution_requests_limits,
    verify_withdrawals_limit, IgnoreReason, RejectReason, RequestCounts, RequestKind, Seen,
    SeenKey, StoreView, Verdict,
};
use ssz::{Decode, Encode};
use ssz_types::FixedVector;
use state_transition::accessors::{builder_key_version, get_domain};
use state_transition::testing::{builder, empty_requests, genesis_state, signed_block};
use state_transition::{state_root, BackendError, StfError};
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
/// header of the block. `process_slots` only sets the slot.
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

/// A store in which a prune dropped the block of `chain`, and the post-state of that block
/// from before the prune.
struct Dropped {
    chain: Chain,
    state: BeaconState<E>,
}

/// The anchor at slot 0, `a` and `b` at slot 1 on it, the block at slot 9 on `b`, and `c` at
/// slot 9 on `a`. The bid of the block is by `builder_index`, has the block hash `[0xbb; 32]`
/// and commits to `requests`. The post-state of `c` justifies and finalizes epoch 1 (first
/// slot 8) with `a`, and the tick after it, in slot 10, drops the anchor, `b` and the block.
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
    let block = block_with_bid(b.message.tree_hash_root(), 9, builder_index, requests);
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
