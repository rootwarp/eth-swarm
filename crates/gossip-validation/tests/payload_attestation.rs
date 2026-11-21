//! `validate_payload_attestation_message_gossip` (`gloas/p2p-interface.md` L891-954) against a
//! fork-choice store that the tests build, and `Seen::resolve` after the signature check.
//!
//! The test provider does not run the state transition. The post-state of a block is the parent
//! state at the slot of the block. The anchor state sets the PTC of slot 1 to [`HEAD_PTC`]. The
//! post-state of a block of [`OTHER_PROPOSER`] has the PTC [`OTHER_PTC`] and another fork
//! version, so a test can tell which state a check reads.
//!
//! The store has two blocks of slot 1 on the anchor: `p`, the first and thus the head (it gets
//! the proposer boost), and `q` of [`OTHER_PROPOSER`].
//!
//! The provider does not move the PTC window. In a state of epoch 1, the PTC of slot 9 is the
//! entry that a state of epoch 0 has for slot 1, so [`HEAD_PTC`] is also the PTC of slot 9 in
//! the later states.
//!
//! This crate links no BLS library. A test gives the BLS verdict of a pending set itself.

use consensus_types::gloas::{
    BeaconBlock, BeaconState, Checkpoint, PayloadAttestationData, PayloadAttestationMessage,
    SignedBeaconBlock,
};
use consensus_types::primitives::{BLSSignature, Root, Slot, ValidatorIndex};
use consensus_types::signing::{
    compute_signing_root, SignatureSet, SignerRef, DOMAIN_PTC_ATTESTER,
};
use consensus_types::Minimal;
use fork_choice::{
    get_forkchoice_store, get_head, on_block, on_payload_attestation_message, on_tick,
    store_target_checkpoint_state, Error, PayloadAttestationError, SignatureVerifier,
    StateProvider, Store,
};
use gossip_validation::{
    is_current_slot, oldest_current_slot, validate_payload_attestation_message_gossip,
    IgnoreReason, RejectReason, Seen, SeenKey, StoreView, Verdict,
    MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS, MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT,
    MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS,
};
use state_transition::accessors::get_domain;
use state_transition::caches::get_ptc;
use state_transition::testing::{genesis_state, signed_block};
use state_transition::{state_root, BackendError, StfError};
use std::collections::HashMap;
use std::num::NonZeroU64;
use tree_hash::TreeHash;

type E = Minimal;

const SLOT_MS: u64 = 6000;
const GENESIS_TIME: u64 = 1_700_000_000;
/// `PTC_SIZE` of the minimal preset.
const PTC_SIZE: usize = 16;
const SIG: BLSSignature = [0x33; 96];
/// `GLOAS_FORK_EPOCH` of the store: Gloas from genesis.
const GLOAS: u64 = 0;
/// The PTC of slot 1 in the anchor state and in the post-state of `p`.
const HEAD_PTC: [ValidatorIndex; PTC_SIZE] = [
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];
/// The PTC of slot 1 in the post-state of a block of [`OTHER_PROPOSER`].
const OTHER_PTC: [ValidatorIndex; PTC_SIZE] = [
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
];
const OTHER_PROPOSER: u64 = 2;
/// The fork version of the post-state of a block of [`OTHER_PROPOSER`].
const OTHER_VERSION: [u8; 4] = [9, 9, 9, 9];

/// The start of `slot`, in milliseconds.
fn time_at(slot: Slot) -> u64 {
    GENESIS_TIME * 1000 + slot * SLOT_MS
}

/// The middle of slot 1, in milliseconds.
fn mid_slot_1() -> u64 {
    time_at(1) + SLOT_MS / 2
}

/// Sets the PTC of slot 1 of `state`, a state of epoch 0.
fn set_ptc(state: &mut BeaconState<E>, ptc: [ValidatorIndex; PTC_SIZE]) {
    let mut committee = get_ptc(state, 1).unwrap();
    for (member, validator) in committee.iter_mut().zip(ptc) {
        *member = validator;
    }
    // In epoch 0, the PTC of slot 1 is at index `SLOTS_PER_EPOCH + 1`.
    *state.ptc_window.get_mut(9).unwrap() = committee;
}

/// The post-state is the parent state at the slot of the block. A block of [`OTHER_PROPOSER`]
/// also sets the PTC [`OTHER_PTC`] and the fork version [`OTHER_VERSION`].
struct Provider;

impl StateProvider<E> for Provider {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        state.slot = block.message.slot;
        if block.message.proposer_index == OTHER_PROPOSER {
            set_ptc(state, OTHER_PTC);
            state.fork.current_version = OTHER_VERSION;
        }
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
        block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        Provider.state_transition(state, block)?;
        state.current_justified_checkpoint = self.0.clone();
        state.finalized_checkpoint = self.0.clone();
        Ok(())
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        Provider.process_slots(state, slot)
    }
}

/// The verifier of fork choice: each signature is valid.
struct ValidSignatures;

impl SignatureVerifier<E> for ValidSignatures {
    fn verify_signature_sets(
        &self,
        _: &BeaconState<E>,
        _: &[SignatureSet],
    ) -> Result<bool, BackendError> {
        Ok(true)
    }
}

/// The store, and the roots of `p` (the head) and `q`.
struct Chain {
    store: Store<E>,
    p: Root,
    q: Root,
}

impl Chain {
    /// The post-state of the head.
    fn head_state(&self) -> &BeaconState<E> {
        self.store.block_state(self.p).unwrap()
    }
}

/// A block at `slot` on the EMPTY anchor by `proposer`.
fn block_on(anchor: &BeaconBlock<E>, slot: Slot, proposer: u64) -> SignedBeaconBlock<E> {
    let mut block = signed_block::<E>(slot, proposer);
    block.message.parent_root = anchor.tree_hash_root();
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.parent_block_hash = Root::repeat_byte(0xee);
    bid.block_hash = Root::repeat_byte(proposer as u8);
    block
}

/// The anchor state with the PTC [`HEAD_PTC`] for slot 1 and `validators` validators, and its
/// block.
fn anchor(validators: usize) -> (BeaconState<E>, BeaconBlock<E>) {
    let mut state = genesis_state::<E>(&vec![32_000_000_000; validators]);
    state.genesis_time = GENESIS_TIME;
    set_ptc(&mut state, HEAD_PTC);
    let mut anchor = signed_block::<E>(0, 0).message;
    anchor.state_root = state_root(&mut state).unwrap();
    (state, anchor)
}

/// A store at the anchor of [`anchor`], at the start of slot 1.
fn store_at_anchor(validators: usize) -> (Store<E>, BeaconBlock<E>) {
    let (state, anchor) = anchor(validators);
    let slot_duration = NonZeroU64::new(SLOT_MS).unwrap();
    let mut store = get_forkchoice_store(state, anchor.clone(), slot_duration).unwrap();
    on_tick(&mut store, time_at(1)).unwrap();
    (store, anchor)
}

fn chain() -> Chain {
    chain_with(64)
}

/// The [`Chain`] with `validators` validators.
fn chain_with(validators: usize) -> Chain {
    let (mut store, anchor) = store_at_anchor(validators);
    let p = block_on(&anchor, 1, 1);
    let q = block_on(&anchor, 1, OTHER_PROPOSER);
    for block in [&p, &q] {
        on_block(&mut store, &Provider, block).unwrap();
    }
    let p = p.message.tree_hash_root();
    let q = q.message.tree_hash_root();
    assert_eq!(get_head(&store).unwrap().root, p);
    Chain { store, p, q }
}

/// A message of `validator` for `root` at `slot`, with the signature [`SIG`].
fn message(validator: ValidatorIndex, root: Root, slot: Slot) -> PayloadAttestationMessage {
    PayloadAttestationMessage {
        validator_index: validator,
        data: PayloadAttestationData {
            beacon_block_root: root,
            slot,
            payload_present: true,
            blob_data_available: true,
        },
        signature: SIG,
    }
}

/// The set of the signature check of the topic: the key of `validator`, and the signing root
/// of the data in the PTC domain of the head state at the epoch of the data slot.
fn expected_set(chain: &Chain, m: &PayloadAttestationMessage) -> SignatureSet {
    set_on(chain.head_state(), m)
}

/// The set of the signature check of `m` with the head state `state`.
fn set_on(state: &BeaconState<E>, m: &PayloadAttestationMessage) -> SignatureSet {
    let epoch = m.data.slot / 8;
    let domain = get_domain(state, DOMAIN_PTC_ATTESTER, Some(epoch));
    SignatureSet::single(
        SignerRef::Validator(m.validator_index),
        compute_signing_root(&m.data, domain),
        m.signature,
    )
}

/// The verdict of `m` at the middle of slot 1, with Gloas from genesis.
fn validate(seen: &Seen, chain: &Chain, m: &PayloadAttestationMessage) -> Verdict {
    validate_at(seen, &chain.store, m, mid_slot_1())
}

fn validate_at<S: StoreView<E>>(
    seen: &Seen,
    store: &S,
    m: &PayloadAttestationMessage,
    time_ms: u64,
) -> Verdict {
    validate_payload_attestation_message_gossip(seen, store, m, time_ms, GLOAS)
}

/// The sets and the key of a pending verdict. Any other verdict fails the test.
fn pending(verdict: Verdict) -> (Vec<SignatureSet>, SeenKey) {
    match verdict {
        Verdict::Pending { bls_sets, seen_key } => (bls_sets, seen_key),
        other => panic!("expected a pending verdict, got {other:?}"),
    }
}

/// A [`Seen`] that has the key of `m`.
fn seen_with(chain: &Chain, m: &PayloadAttestationMessage) -> Seen {
    let mut seen = Seen::default();
    let (_, key) = pending(validate(&seen, chain, m));
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    seen
}

#[test]
fn a_valid_message_waits_for_its_signature_and_then_accepts() {
    let chain = chain();
    let m = message(12, chain.p, 1);
    let mut seen = Seen::default();
    let (sets, key) = pending(validate(&seen, &chain, &m));
    assert_eq!(sets, vec![expected_set(&chain, &m)]);
    assert!(!seen.has_payload_attestation(1, 12));
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    assert!(seen.has_payload_attestation(1, 12));
    assert!(!seen.has_payload_attestation(1, 13));
    assert!(!seen.has_payload_attestation(2, 12));
}

#[test]
fn a_message_before_the_gloas_fork_must_reject() {
    let chain = chain();
    let m = message(12, chain.p, 1);
    let unknown = message(12, Root::repeat_byte(0x42), 1);
    // The fork check is the first check: it comes before the seen check and the block checks.
    let seen = seen_with(&chain, &m);
    for (seen, m) in [(&seen, &m), (&Seen::default(), &unknown)] {
        assert_eq!(
            validate_payload_attestation_message_gossip(seen, &chain.store, m, time_at(1), 1),
            Verdict::Reject(RejectReason::BeforeGloasFork {
                slot: 1,
                fork_epoch: 1
            })
        );
    }
    // A slot of the fork epoch passes the check.
    assert_eq!(
        validate_payload_attestation_message_gossip(&seen, &chain.store, &m, time_at(1), 0),
        Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
            slot: 1,
            validator_index: 12
        })
    );
}

#[test]
fn a_message_of_a_seen_slot_and_validator_must_ignore() {
    let chain = chain();
    let m = message(12, chain.p, 1);
    let seen = seen_with(&chain, &m);
    let mut other_data = m.clone();
    other_data.data.payload_present = false;
    let want = Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
        slot: 1,
        validator_index: 12,
    });
    for copy in [&m, &other_data] {
        assert_eq!(validate(&seen, &chain, copy), want);
    }
    // The seen check comes before the current slot check.
    assert_eq!(validate_at(&seen, &chain.store, &m, time_at(5)), want);
    // Another validator of the PTC is not seen.
    pending(validate(&seen, &chain, &message(13, chain.p, 1)));
}

#[test]
fn a_message_outside_the_current_slot_and_the_clock_disparity_must_ignore() {
    let chain = chain();
    let m = message(12, chain.p, 1);
    let disparity = MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
    assert_eq!(disparity, 500);
    let start = time_at(1);
    let end = time_at(2);
    for (time_ms, current) in [
        (start - disparity - 1, false),
        (start - disparity, true),
        (start, true),
        (end - 1, true),
        (end, true),
        (end + disparity, true),
        (end + disparity + 1, false),
    ] {
        assert_eq!(
            is_current_slot(&chain.store, 1, time_ms),
            current,
            "{time_ms}"
        );
        let verdict = validate_at(&Seen::default(), &chain.store, &m, time_ms);
        if current {
            pending(verdict);
        } else {
            assert_eq!(
                verdict,
                Verdict::Ignore(IgnoreReason::NotCurrentSlot { slot: 1 }),
                "{time_ms}"
            );
        }
    }
    // A slot so far away that its time does not fit in 64 bits is not current.
    assert!(!is_current_slot(&chain.store, u64::MAX, u64::MAX));
    // The current slot check comes before the block checks.
    let unknown = message(12, Root::repeat_byte(0x42), 1);
    assert_eq!(
        validate_at(&Seen::default(), &chain.store, &unknown, time_at(3)),
        Verdict::Ignore(IgnoreReason::NotCurrentSlot { slot: 1 })
    );
}

#[test]
fn a_message_for_an_unknown_block_must_ignore() {
    let chain = chain();
    let unknown = Root::repeat_byte(0x42);
    assert_eq!(
        validate(&Seen::default(), &chain, &message(12, unknown, 1)),
        Verdict::Ignore(IgnoreReason::UnknownBlock(unknown))
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

    fn genesis_time_ms(&self) -> u64 {
        self.0.genesis_time_ms()
    }

    fn slot_duration_ms(&self) -> NonZeroU64 {
        self.0.slot_duration_ms()
    }

    fn head_state(&self) -> Option<&BeaconState<E>> {
        StoreView::head_state(self.0)
    }
}

#[test]
fn a_message_for_a_block_with_no_post_state_must_reject() {
    let chain = chain();
    let view = NoPostStates(&chain.store);
    assert_eq!(
        validate_at(
            &Seen::default(),
            &view,
            &message(12, chain.p, 1),
            time_at(1)
        ),
        Verdict::Reject(RejectReason::BlockNotValid(chain.p))
    );
}

#[test]
fn a_message_of_another_slot_than_its_block_must_ignore() {
    let chain = chain();
    let m = message(12, chain.p, 2);
    assert_eq!(
        validate_at(&Seen::default(), &chain.store, &m, time_at(2)),
        Verdict::Ignore(IgnoreReason::BlockSlotMismatch {
            block: 1,
            message: 2
        })
    );
}

/// A view of the store with another head state.
struct Head<'a> {
    store: &'a Store<E>,
    head: Option<&'a BeaconState<E>>,
}

impl StoreView<E> for Head<'_> {
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>> {
        self.store.block(root)
    }

    fn block_state(&self, root: Root) -> Option<&BeaconState<E>> {
        self.store.block_state(root)
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        self.store.finalized_checkpoint()
    }

    fn genesis_time_ms(&self) -> u64 {
        self.store.genesis_time_ms()
    }

    fn slot_duration_ms(&self) -> NonZeroU64 {
        self.store.slot_duration_ms()
    }

    fn head_state(&self) -> Option<&BeaconState<E>> {
        self.head
    }
}

#[test]
fn a_store_with_no_head_state_must_ignore() {
    let chain = chain();
    let view = Head {
        store: &chain.store,
        head: None,
    };
    let m = message(12, chain.p, 1);
    assert_eq!(
        validate_at(&Seen::default(), &view, &m, time_at(1)),
        Verdict::Ignore(IgnoreReason::NoHeadState)
    );
}

#[test]
fn a_validator_index_past_the_head_registry_must_reject() {
    let chain = chain();
    assert_eq!(chain.head_state().validators.len(), 64);
    let m = message(64, chain.p, 1);
    assert_eq!(
        validate(&Seen::default(), &chain, &m),
        Verdict::Reject(RejectReason::UnknownValidator(64))
    );
}

#[test]
fn the_ptc_check_and_the_signature_set_read_the_head_state() {
    let chain = chain();
    // 30 is in the PTC of the post-state of `q`, but not in the PTC of the head state.
    for root in [chain.p, chain.q] {
        assert_eq!(
            validate(&Seen::default(), &chain, &message(30, root, 1)),
            Verdict::Reject(RejectReason::NotInPtc {
                validator_index: 30,
                slot: 1
            })
        );
    }
    // 12 is in the PTC of the head state, but not in the PTC of the post-state of `q`. The
    // signing root has the fork version of the head state.
    let m = message(12, chain.q, 1);
    let (sets, _) = pending(validate(&Seen::default(), &chain, &m));
    assert_eq!(sets, vec![expected_set(&chain, &m)]);
    let q_state = chain.store.block_state(chain.q).unwrap();
    assert_eq!(q_state.fork.current_version, OTHER_VERSION);
    let q_domain = get_domain(q_state, DOMAIN_PTC_ATTESTER, Some(0));
    assert_ne!(
        sets[0].signing_root(),
        compute_signing_root(&m.data, q_domain)
    );
}

#[test]
fn a_head_state_with_no_ptc_of_the_slot_must_ignore() {
    let chain = chain();
    // A head state three epochs after the slot of the message has no PTC of that slot.
    let mut late = chain.head_state().clone();
    late.slot = 24;
    let view = Head {
        store: &chain.store,
        head: Some(&late),
    };
    let m = message(12, chain.p, 1);
    assert_eq!(
        validate_at(&Seen::default(), &view, &m, time_at(1)),
        Verdict::Ignore(IgnoreReason::NoPtc { slot: 1 })
    );
}

#[test]
fn a_head_state_two_epochs_before_the_slot_must_ignore() {
    let mut chain = chain();
    on_tick(&mut chain.store, time_at(17)).unwrap();
    let p = chain.store.block(chain.p).unwrap().clone();
    let block = block_on(&p, 17, 3);
    on_block(&mut chain.store, &Provider, &block).unwrap();
    let root = block.message.tree_hash_root();
    let m = message(12, root, 17);
    // The head state of the view is the post-state of `p`, of epoch 0, for example a head that
    // is behind during a sync. Slot 17 is in epoch 2, after the PTC window of that state.
    let behind = with_head(&chain, chain.head_state());
    assert_eq!(
        validate_at(&Seen::default(), &behind, &m, time_at(17)),
        Verdict::Ignore(IgnoreReason::NoPtc { slot: 17 })
    );
    // With the post-state of the block of slot 17 as the head state, the same message passes.
    let current = with_head(&chain, chain.store.block_state(root).unwrap());
    pending(validate_at(&Seen::default(), &current, &m, time_at(17)));
}

#[test]
fn seen_takes_the_key_only_after_a_valid_signature() {
    let chain = chain();
    let m = message(12, chain.p, 1);
    let mut seen = Seen::default();

    // An invalid signature rejects, and does not occupy the key.
    let (_, key) = pending(validate(&seen, &chain, &m));
    assert_eq!(
        seen.resolve(key, Ok(false)),
        Verdict::Reject(RejectReason::InvalidSignature)
    );
    assert_eq!(seen, Seen::default());

    // No verdict ignores, and does not occupy the key.
    let (_, key) = pending(validate(&seen, &chain, &m));
    assert_eq!(
        seen.resolve(key, Err(BackendError("timeout".into()))),
        Verdict::Ignore(IgnoreReason::NoSignatureVerdict)
    );
    assert_eq!(seen, Seen::default());

    // A later valid copy accepts. A second copy that was pending at the same time ignores.
    let (_, first) = pending(validate(&seen, &chain, &m));
    let (_, second) = pending(validate(&seen, &chain, &m));
    assert_eq!(seen.resolve(first, Ok(true)), Verdict::Accept);
    let want = Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
        slot: 1,
        validator_index: 12,
    });
    assert_eq!(seen.resolve(second, Ok(true)), want);
    assert_eq!(validate(&seen, &chain, &m), want);
}

#[test]
fn a_validator_index_past_a_head_registry_that_is_shorter_than_the_block_registry_must_reject() {
    let chain = chain();
    // The head state has 48 validators, and the post-state of the attested block has 64.
    let (mut short, _) = anchor(48);
    short.slot = 1;
    assert_eq!(short.validators.len(), 48);
    let block_state = chain.store.block_state(chain.p).unwrap();
    assert_eq!(block_state.validators.len(), 64);
    let view = Head {
        store: &chain.store,
        head: Some(&short),
    };
    let m = message(50, chain.p, 1);
    assert_eq!(
        validate_at(&Seen::default(), &view, &m, time_at(1)),
        Verdict::Reject(RejectReason::UnknownValidator(50))
    );
    // An index of the head registry and of its PTC passes.
    pending(validate_at(
        &Seen::default(),
        &view,
        &message(12, chain.p, 1),
        time_at(1),
    ));
}

/// A store in which the finality prune at slot 9 dropped the block `b`.
struct Pruned {
    store: Store<E>,
    b: Root,
}

/// The anchor at slot 0, `a` and `x` at slot 1 on it, `b` at slot 9 on `x`, and `c` at slot 9
/// on `a`. The post-state of `c` justifies and finalizes epoch 1 (first slot 8) with `a`. The
/// blocks of slot 9 come after the attestation deadline, so neither gets the proposer boost,
/// and the next tick in slot 9 prunes: it drops the anchor, `x` and `b`.
///
/// The prune in epoch 1 keeps the dropped blocks and their post-states through the end of
/// epoch 3 (slot 31). The head is `c`. The PTC of slot 9 is [`HEAD_PTC`] in the post-states of
/// `b` and `c`.
fn pruned() -> Pruned {
    let (mut store, anchor) = store_at_anchor(64);
    let a = block_on(&anchor, 1, 1);
    let x = block_on(&anchor, 1, 3);
    for block in [&a, &x] {
        on_block(&mut store, &Provider, block).unwrap();
    }
    let late = time_at(9) + SLOT_MS / 2;
    on_tick(&mut store, late).unwrap();
    let b = block_on(&x.message, 9, 4);
    on_block(&mut store, &Provider, &b).unwrap();
    let checkpoint = Checkpoint {
        epoch: 1,
        root: a.message.tree_hash_root(),
    };
    let c = block_on(&a.message, 9, 5);
    on_block(&mut store, &Finalizing(checkpoint.clone()), &c).unwrap();
    assert_eq!(store.finalized_checkpoint(), &checkpoint);
    // On the spec path, `on_attestation` stores the state of the justified checkpoint.
    store_target_checkpoint_state(&mut store, &Provider, &checkpoint).unwrap();
    on_tick(&mut store, late).unwrap();
    let b = b.message.tree_hash_root();
    assert!(store.block(b).is_none());
    assert!(store.block_or_dropped(b).is_some());
    assert_eq!(get_head(&store).unwrap().root, c.message.tree_hash_root());
    for state in [
        StoreView::head_state(&store).unwrap(),
        store.block_state_or_dropped(b).unwrap(),
    ] {
        assert_eq!(get_ptc(state, 9).unwrap().to_vec(), HEAD_PTC.to_vec());
    }
    Pruned { store, b }
}

#[test]
fn gossip_and_fork_choice_agree_on_a_retained_and_then_a_forgotten_dropped_block() {
    let Pruned { mut store, b } = pruned();
    let m = message(12, b, 9);
    let head = get_head(&store).unwrap();

    // While the store retains `b`, gossip checks the message on the head state and accepts it.
    let mut seen = Seen::default();
    let (sets, key) = pending(validate_at(&seen, &store, &m, time_at(9)));
    let head_state = StoreView::head_state(&store).unwrap();
    let domain = get_domain(head_state, DOMAIN_PTC_ATTESTER, Some(1));
    let want = SignatureSet::single(
        SignerRef::Validator(12),
        compute_signing_root(&m.data, domain),
        SIG,
    );
    assert_eq!(sets, vec![want]);
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    assert!(seen.has_payload_attestation(9, 12));
    // Fork choice takes the message, but the store has no votes of `b`, so nothing changes.
    let before = store.clone();
    assert_eq!(
        on_payload_attestation_message(&mut store, &ValidSignatures, &m, false),
        Ok(())
    );
    assert_eq!(store, before);
    assert_eq!(get_head(&store), Ok(head));
    assert!(store.payload_timeliness_vote(b).is_none());

    // The prune ran in epoch 1, so the first tick of epoch 4 forgets `b`. Then gossip ignores
    // the message as a message for an unknown block, and fork choice refuses it.
    on_tick(&mut store, time_at(32)).unwrap();
    assert!(store.block_or_dropped(b).is_none());
    assert_eq!(
        validate_at(&Seen::default(), &store, &m, time_at(9)),
        Verdict::Ignore(IgnoreReason::UnknownBlock(b))
    );
    let before = store.clone();
    let head = get_head(&store).unwrap();
    assert_eq!(
        on_payload_attestation_message(&mut store, &ValidSignatures, &m, false),
        Err(Error::InvalidPayloadAttestation(
            PayloadAttestationError::UnknownBeaconBlock(b)
        ))
    );
    assert_eq!(store, before);
    assert_eq!(get_head(&store), Ok(head));
}

/// Validates `m` against `store` at `time_ms`, and resolves the pending verdict with a valid
/// signature. Gives the verdict of [`Seen::resolve`].
fn accept_at<S: StoreView<E>>(
    seen: &mut Seen,
    store: &S,
    m: &PayloadAttestationMessage,
    time_ms: u64,
) -> Verdict {
    let (_, key) = pending(validate_at(seen, store, m, time_ms));
    seen.resolve(key, Ok(true))
}

/// The view of `chain` with the head state `head`.
fn with_head<'a>(chain: &'a Chain, head: &'a BeaconState<E>) -> Head<'a> {
    Head {
        store: &chain.store,
        head: Some(head),
    }
}

/// The PTC with the validators `16 * k` to `16 * k + 15`.
fn ptc_of(k: usize) -> [ValidatorIndex; PTC_SIZE] {
    std::array::from_fn(|i| (k * PTC_SIZE + i) as ValidatorIndex)
}

/// `count` head states of slot 1. Head `k` is the head state of `chain` with the PTC
/// [`ptc_of`]`(k)` for slot 1, so no two heads have a validator in common.
fn disjoint_heads(chain: &Chain, count: usize) -> Vec<BeaconState<E>> {
    (0..count)
        .map(|k| {
            let mut state = chain.head_state().clone();
            set_ptc(&mut state, ptc_of(k));
            state
        })
        .collect()
}

/// [`chain`] at the start of slot 2, with `r`, a block of slot 2 on `p`. `r` gets the proposer
/// boost and is the head. Its PTC of slot 1 is [`HEAD_PTC`]. Gives the chain and the root of
/// `r`.
fn chain_at_slot_2() -> (Chain, Root) {
    let mut chain = chain();
    on_tick(&mut chain.store, time_at(2)).unwrap();
    let p = chain.store.block(chain.p).unwrap().clone();
    let r = block_on(&p, 2, 3);
    on_block(&mut chain.store, &Provider, &r).unwrap();
    let r = r.message.tree_hash_root();
    assert_eq!(get_head(&chain.store).unwrap().root, r);
    let head_state = StoreView::head_state(&chain.store).unwrap();
    assert_eq!(get_ptc(head_state, 1).unwrap().to_vec(), HEAD_PTC.to_vec());
    (chain, r)
}

/// Two different validators of the PTC of slot 2 in the head state of `store`.
fn two_of_slot_2(store: &Store<E>) -> [ValidatorIndex; 2] {
    let ptc = get_ptc(StoreView::head_state(store).unwrap(), 2).unwrap();
    let first = ptc[0];
    let second = *ptc.iter().find(|v| **v != first).unwrap();
    [first, second]
}

#[test]
fn the_oldest_current_slot_is_the_first_slot_in_the_clock_disparity() {
    let chain = chain();
    let store = &chain.store;
    let disparity = MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
    for (time_ms, oldest) in [
        (0, 0),
        (time_at(0), 0),
        (time_at(0) + disparity + 1, 0),
        (time_at(1) + disparity, 0),
        (time_at(1) + disparity + 1, 1),
        (time_at(2) + disparity, 1),
        (time_at(2) + disparity + 1, 2),
        (u64::MAX, (u64::MAX - time_at(0) - disparity - 1) / SLOT_MS),
    ] {
        assert_eq!(oldest_current_slot(store, time_ms), oldest, "{time_ms}");
    }
    // From genesis on, the oldest current slot is current, and the slot before it is not.
    for slot in 0..4 {
        for offset in [0, 1, disparity - 1, disparity, disparity + 1, SLOT_MS - 1] {
            let time_ms = time_at(slot) + offset;
            let oldest = oldest_current_slot(store, time_ms);
            assert!(is_current_slot(store, oldest, time_ms), "{time_ms}");
            assert!(
                oldest == 0 || !is_current_slot(store, oldest - 1, time_ms),
                "{time_ms}"
            );
        }
    }
}

#[test]
fn a_slot_stays_in_seen_through_the_clock_disparity_and_a_valid_message_then_removes_it() {
    let (chain, r) = chain_at_slot_2();
    let store = &chain.store;
    let [v, w] = two_of_slot_2(store);
    let edge = time_at(2) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
    let mut seen = Seen::default();
    let m = message(10, chain.p, 1);
    assert_eq!(
        accept_at(&mut seen, store, &m, mid_slot_1()),
        Verdict::Accept
    );

    // At the end of slot 1 plus the clock disparity, slot 1 is still current. A valid message
    // of slot 2 at that time keeps slot 1.
    assert_eq!(
        accept_at(&mut seen, store, &message(v, r, 2), edge),
        Verdict::Accept
    );
    assert!(seen.has_payload_attestation(1, 10));
    assert_eq!(seen.payload_attestation_slot_count(), 2);
    assert_eq!(
        validate_at(&seen, store, &m, edge),
        Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
            slot: 1,
            validator_index: 10
        })
    );
    // A copy of slot 1 that is pending at that time, and resolves after the prune below.
    let (_, late) = pending(validate_at(&seen, store, &message(11, chain.p, 1), edge));

    // One millisecond later, slot 1 is not current. A valid message of slot 2 removes it.
    assert_eq!(
        accept_at(&mut seen, store, &message(w, r, 2), edge + 1),
        Verdict::Accept
    );
    assert!(!seen.has_payload_attestation(1, 10));
    assert!(seen.has_payload_attestation(2, v));
    assert!(seen.has_payload_attestation(2, w));
    assert_eq!(seen.payload_attestation_slot_count(), 1);
    assert_eq!(seen.payload_attestation_count(), 2);
    assert_eq!(
        validate_at(&seen, store, &m, edge + 1),
        Verdict::Ignore(IgnoreReason::NotCurrentSlot { slot: 1 })
    );

    // The late copy accepts, and does not add slot 1 again.
    assert_eq!(seen.resolve(late, Ok(true)), Verdict::Accept);
    assert!(!seen.has_payload_attestation(1, 11));
    assert_eq!(seen.payload_attestation_slot_count(), 1);
    assert_eq!(seen.payload_attestation_count(), 2);
}

#[test]
fn an_explicit_prune_removes_a_slot_only_after_the_clock_disparity() {
    let (chain, r) = chain_at_slot_2();
    let store = &chain.store;
    let [v, w] = two_of_slot_2(store);
    let edge = time_at(2) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
    let mut seen = Seen::default();
    let m = message(10, chain.p, 1);
    assert_eq!(
        accept_at(&mut seen, store, &m, mid_slot_1()),
        Verdict::Accept
    );
    assert_eq!(
        accept_at(&mut seen, store, &message(v, r, 2), time_at(2)),
        Verdict::Accept
    );

    seen.prune_payload_attestations(store, edge);
    assert!(seen.has_payload_attestation(1, 10));
    assert_eq!(seen.payload_attestation_slot_count(), 2);
    assert_eq!(
        validate_at(&seen, store, &m, edge),
        Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
            slot: 1,
            validator_index: 10
        })
    );

    seen.prune_payload_attestations(store, edge + 1);
    assert!(!seen.has_payload_attestation(1, 10));
    assert!(seen.has_payload_attestation(2, v));
    assert_eq!(seen.payload_attestation_slot_count(), 1);
    assert_eq!(seen.payload_attestation_count(), 1);

    // A prune by slot removes each slot before that slot. A copy of slot 2 that resolves
    // after it accepts, and does not add slot 2 again.
    let (_, late) = pending(validate_at(&seen, store, &message(w, r, 2), time_at(2)));
    seen.prune_payload_attestations_before(3);
    assert_eq!(seen.payload_attestation_count(), 0);
    assert_eq!(seen.payload_attestation_slot_count(), 0);
    assert_eq!(seen.resolve(late, Ok(true)), Verdict::Accept);
    assert_eq!(seen.payload_attestation_count(), 0);
}

#[test]
fn a_pending_duplicate_across_a_prune_must_ignore() {
    let (chain, r) = chain_at_slot_2();
    let store = &chain.store;
    let [v, _] = two_of_slot_2(store);
    let edge = time_at(2) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
    let mut seen = Seen::default();
    let m = message(10, chain.p, 1);

    // Two copies for slot 1 and validator 10 pass validation at `edge` before either resolves.
    let (_, first) = pending(validate_at(&seen, store, &m, edge));
    let (_, second) = pending(validate_at(&seen, store, &m, edge));

    // The first copy resolves before the prune and returns Accept.
    assert_eq!(seen.resolve(first, Ok(true)), Verdict::Accept);

    // A valid message of slot 2 at `edge + 1` prunes slot 1.
    assert_eq!(
        accept_at(&mut seen, store, &message(v, r, 2), edge + 1),
        Verdict::Accept
    );
    assert!(!seen.has_payload_attestation(1, 10));

    // The second pending copy must return Ignore(PayloadAttestationAlreadySeen), not Accept.
    assert_eq!(
        seen.resolve(second, Ok(true)),
        Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
            slot: 1,
            validator_index: 10,
        })
    );
}

#[test]
fn a_pending_duplicate_across_an_explicit_prune_must_ignore() {
    let (chain, _) = chain_at_slot_2();
    let store = &chain.store;
    let edge = time_at(2) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
    let mut seen = Seen::default();
    let m = message(10, chain.p, 1);
    let already_seen = Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
        slot: 1,
        validator_index: 10,
    });

    // Two copies pass validation at `edge`. The first copy accepts before the prune.
    let (_, first) = pending(validate_at(&seen, store, &m, edge));
    let (_, second) = pending(validate_at(&seen, store, &m, edge));
    assert_eq!(seen.resolve(first, Ok(true)), Verdict::Accept);

    // An explicit prune at `edge + 1` removes slot 1.
    seen.prune_payload_attestations(store, edge + 1);
    assert!(!seen.has_payload_attestation(1, 10));
    assert_eq!(seen.payload_attestation_slot_count(), 0);
    let pruned = seen.clone();

    // The second copy is IGNORE, and does not add slot 1 again.
    assert_eq!(seen.resolve(second, Ok(true)), already_seen);
    assert_eq!(seen, pruned);
    // A new copy at `edge + 1` is IGNORE for the same reason.
    assert_eq!(validate_at(&seen, store, &m, edge + 1), already_seen);
}

#[test]
fn pending_copies_that_resolve_only_after_a_prune_must_ignore() {
    let (chain, r) = chain_at_slot_2();
    let store = &chain.store;
    let [v, _] = two_of_slot_2(store);
    let edge = time_at(2) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
    let m = message(10, chain.p, 1);
    // `None` is an explicit prune. `Some` is a valid message of slot 2 that prunes.
    for slot_2_message in [None, Some(message(v, r, 2))] {
        let mut seen = Seen::default();
        // Two copies pass validation at `edge`. Neither resolves before the prune.
        let (_, first) = pending(validate_at(&seen, store, &m, edge));
        let (_, second) = pending(validate_at(&seen, store, &m, edge));
        match &slot_2_message {
            Some(m2) => assert_eq!(accept_at(&mut seen, store, m2, edge + 1), Verdict::Accept),
            None => seen.prune_payload_attestations(store, edge + 1),
        }
        let pruned = seen.clone();

        // Slot 1 is not current. Neither copy accepts, and neither adds slot 1 again.
        for key in [first, second] {
            assert_eq!(
                seen.resolve(key, Ok(true)),
                Verdict::Ignore(IgnoreReason::NotCurrentSlot { slot: 1 }),
                "{slot_2_message:?}"
            );
            assert_eq!(seen, pruned);
            assert!(!seen.has_payload_attestation(1, 10));
        }
    }
}

#[test]
fn a_message_of_a_pruned_slot_must_ignore_also_at_an_earlier_time() {
    let (chain, r) = chain_at_slot_2();
    let store = &chain.store;
    let [v, _] = two_of_slot_2(store);
    let edge = time_at(2) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
    let mut seen = Seen::default();
    let m = message(10, chain.p, 1);
    assert_eq!(
        accept_at(&mut seen, store, &m, mid_slot_1()),
        Verdict::Accept
    );
    assert_eq!(
        accept_at(&mut seen, store, &message(v, r, 2), edge + 1),
        Verdict::Accept
    );
    assert!(!seen.has_payload_attestation(1, 10));
    let pruned = seen.clone();

    // The clock goes back. At these times slot 1 is current again.
    for time_ms in [edge, mid_slot_1()] {
        assert!(is_current_slot(store, 1, time_ms));
        // A prune at an earlier time changes nothing.
        seen.prune_payload_attestations(store, time_ms);
        assert_eq!(seen, pruned);
        // A copy of the accepted message is a duplicate.
        assert_eq!(
            validate_at(&seen, store, &m, time_ms),
            Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
                slot: 1,
                validator_index: 10
            }),
            "{time_ms}"
        );
        // A message of another validator is not current: slot 1 is before the kept slots.
        assert_eq!(
            validate_at(&seen, store, &message(11, chain.p, 1), time_ms),
            Verdict::Ignore(IgnoreReason::NotCurrentSlot { slot: 1 }),
            "{time_ms}"
        );
    }
    assert!(seen.has_payload_attestation(2, v));
}

/// A view with a block of each slot from 1 to `slots` and a slot duration of 1 ms. Each block
/// is `p` with another slot. Each block has the post-state of `p`, which is also the head
/// state. At the genesis time, the clock disparity of 500 ms makes each of these slots
/// current, and the oldest current slot is 0.
struct ManySlots<'a> {
    chain: &'a Chain,
    roots: Vec<Root>,
    blocks: HashMap<Root, BeaconBlock<E>>,
}

impl<'a> ManySlots<'a> {
    fn new(chain: &'a Chain, slots: Slot) -> Self {
        let mut roots = Vec::new();
        let mut blocks = HashMap::new();
        for slot in 1..=slots {
            let mut block = chain.store.block(chain.p).unwrap().clone();
            block.slot = slot;
            let root = block.tree_hash_root();
            roots.push(root);
            blocks.insert(root, block);
        }
        Self {
            chain,
            roots,
            blocks,
        }
    }

    /// The root of the block of `slot`.
    fn root(&self, slot: Slot) -> Root {
        self.roots[slot as usize - 1]
    }
}

impl StoreView<E> for ManySlots<'_> {
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>> {
        self.blocks.get(&root)
    }

    fn block_state(&self, root: Root) -> Option<&BeaconState<E>> {
        self.blocks
            .contains_key(&root)
            .then(|| self.chain.head_state())
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
        Some(self.chain.head_state())
    }
}

#[test]
fn seen_keeps_at_most_the_slot_limit_and_removes_the_oldest_slot() {
    assert_eq!(MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS, 8);
    let chain = chain();
    let extra = 4;
    let slots = (MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS + extra) as Slot;
    let view = ManySlots::new(&chain, slots);
    let now = view.genesis_time_ms();
    assert_eq!(oldest_current_slot(&view, now), 0);
    let validator = |slot| get_ptc(chain.head_state(), slot).unwrap()[0];
    let mut seen = Seen::default();
    for slot in 1..=slots {
        let m = message(validator(slot), view.root(slot), slot);
        assert_eq!(accept_at(&mut seen, &view, &m, now), Verdict::Accept);
        assert!(seen.has_payload_attestation(slot, validator(slot)));
        assert!(seen.payload_attestation_slot_count() <= MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS);
    }
    assert_eq!(
        seen.payload_attestation_slot_count(),
        MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS
    );
    assert_eq!(
        seen.payload_attestation_count(),
        MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS
    );
    // The oldest slots go first.
    for slot in 1..=slots {
        assert_eq!(
            seen.has_payload_attestation(slot, validator(slot)),
            slot > extra as Slot,
            "{slot}"
        );
    }
}

#[test]
fn a_head_change_in_a_slot_admits_the_ptc_of_each_head() {
    let chain = chain();
    let q_state = chain.store.block_state(chain.q).unwrap();
    let q_head = with_head(&chain, q_state);
    let mut seen = Seen::default();
    // Each validator of the PTC of the head `p`.
    for validator in HEAD_PTC {
        let m = message(validator, chain.p, 1);
        assert_eq!(
            accept_at(&mut seen, &chain.store, &m, mid_slot_1()),
            Verdict::Accept
        );
    }
    // The head changes to `q`. Each validator of its PTC passes too, with the signature domain
    // of `q`. Slot 1 then has more validators than `PTC_SIZE`, and keeps each of them.
    for validator in OTHER_PTC {
        let m = message(validator, chain.q, 1);
        let (sets, key) = pending(validate_at(&seen, &q_head, &m, mid_slot_1()));
        assert_eq!(sets, vec![set_on(q_state, &m)]);
        assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    }
    assert_eq!(seen.payload_attestation_count(), 2 * PTC_SIZE);
    assert_eq!(seen.payload_attestation_slot_count(), 1);
    for validator in HEAD_PTC.iter().chain(&OTHER_PTC) {
        assert!(seen.has_payload_attestation(1, *validator), "{validator}");
    }
    // The head changes back to `p`. Each validator of its PTC is still seen.
    for validator in HEAD_PTC {
        assert_eq!(
            validate(&seen, &chain, &message(validator, chain.p, 1)),
            Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
                slot: 1,
                validator_index: validator
            })
        );
    }
}

#[test]
fn a_slot_keeps_at_most_the_validator_limit_and_removes_the_oldest_validator() {
    assert_eq!(MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT, 4);
    let limit = MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT * PTC_SIZE;
    let chain = chain_with(96);
    // Five heads with disjoint PTCs: 80 validators for slot 1, more than the limit of 64.
    let heads = disjoint_heads(&chain, MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT + 1);
    let mut seen = Seen::default();
    let mut accepted = Vec::new();
    for (k, head) in heads.iter().enumerate() {
        let view = with_head(&chain, head);
        for validator in ptc_of(k) {
            let m = message(validator, chain.p, 1);
            assert_eq!(
                accept_at(&mut seen, &view, &m, mid_slot_1()),
                Verdict::Accept
            );
            accepted.push(validator);
            assert_eq!(seen.payload_attestation_count(), accepted.len().min(limit));
            // Seen keeps the last `limit` validators, and removes only the oldest.
            let first_kept = accepted.len().saturating_sub(limit);
            for (i, v) in accepted.iter().enumerate() {
                assert_eq!(seen.has_payload_attestation(1, *v), i >= first_kept, "{v}");
            }
        }
    }
    assert_eq!(accepted.len(), 80);
    assert_eq!(seen.payload_attestation_count(), limit);
    assert_eq!(seen.payload_attestation_slot_count(), 1);
}

#[test]
fn an_invalid_copy_at_the_validator_limit_removes_no_validator() {
    let chain = chain_with(96);
    let heads = disjoint_heads(&chain, MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT + 1);
    let mut seen = Seen::default();
    // The PTCs of the first four heads fill slot 1 to the limit.
    for (k, head) in heads
        .iter()
        .enumerate()
        .take(MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT)
    {
        let view = with_head(&chain, head);
        for validator in ptc_of(k) {
            let m = message(validator, chain.p, 1);
            assert_eq!(
                accept_at(&mut seen, &view, &m, mid_slot_1()),
                Verdict::Accept
            );
        }
    }
    assert_eq!(seen.payload_attestation_count(), 64);
    let full = seen.clone();

    // 64 is in the PTC of the fifth head only. Under the first head it is not in the PTC.
    let m = message(64, chain.p, 1);
    assert_eq!(
        validate_at(&seen, &with_head(&chain, &heads[0]), &m, mid_slot_1()),
        Verdict::Reject(RejectReason::NotInPtc {
            validator_index: 64,
            slot: 1
        })
    );
    assert_eq!(seen, full);
    // Under the fifth head, an invalid signature and no verdict leave Seen as it was.
    let fifth = with_head(&chain, &heads[4]);
    for (signatures, want) in [
        (Ok(false), Verdict::Reject(RejectReason::InvalidSignature)),
        (
            Err(BackendError("timeout".into())),
            Verdict::Ignore(IgnoreReason::NoSignatureVerdict),
        ),
    ] {
        let (_, key) = pending(validate_at(&seen, &fifth, &m, mid_slot_1()));
        assert_eq!(seen.resolve(key, signatures), want);
        assert_eq!(seen, full);
        assert!(seen.has_payload_attestation(1, 0));
        assert!(!seen.has_payload_attestation(1, 64));
    }

    // A valid copy accepts, and removes only the oldest validator.
    assert_eq!(
        accept_at(&mut seen, &fifth, &m, mid_slot_1()),
        Verdict::Accept
    );
    assert!(seen.has_payload_attestation(1, 64));
    assert!(!seen.has_payload_attestation(1, 0));
    for validator in 1..64 {
        assert!(seen.has_payload_attestation(1, validator), "{validator}");
    }
    assert_eq!(seen.payload_attestation_count(), 64);
}

#[test]
fn an_invalid_copy_does_not_prune_seen() {
    let (chain, r) = chain_at_slot_2();
    let store = &chain.store;
    let [v, _] = two_of_slot_2(store);
    let mut seen = Seen::default();
    let m = message(10, chain.p, 1);
    assert_eq!(
        accept_at(&mut seen, store, &m, mid_slot_1()),
        Verdict::Accept
    );
    let before = seen.clone();

    // A valid message of slot 2 at this time would remove slot 1.
    let late = time_at(2) + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS + 1;
    let copy = message(v, r, 2);
    for (signatures, want) in [
        (Ok(false), Verdict::Reject(RejectReason::InvalidSignature)),
        (
            Err(BackendError("timeout".into())),
            Verdict::Ignore(IgnoreReason::NoSignatureVerdict),
        ),
    ] {
        let (_, key) = pending(validate_at(&seen, store, &copy, late));
        assert_eq!(seen.resolve(key, signatures), want);
        assert_eq!(seen, before);
        assert!(seen.has_payload_attestation(1, 10));
    }
    // A validator outside the PTC rejects before the signature, and Seen does not change.
    let ptc = get_ptc(StoreView::head_state(store).unwrap(), 2).unwrap();
    let outsider = (0..64).find(|i| !ptc.contains(i)).unwrap();
    assert_eq!(
        validate_at(&seen, store, &message(outsider, r, 2), late),
        Verdict::Reject(RejectReason::NotInPtc {
            validator_index: outsider,
            slot: 2
        })
    );
    assert_eq!(seen, before);

    // The valid copy removes slot 1.
    assert_eq!(accept_at(&mut seen, store, &copy, late), Verdict::Accept);
    assert!(!seen.has_payload_attestation(1, 10));
    assert!(seen.has_payload_attestation(2, v));
}

#[test]
fn a_copy_outside_the_ptc_of_the_head_does_not_stop_a_copy_after_a_head_change() {
    let chain = chain();
    let q_state = chain.store.block_state(chain.q).unwrap();
    let q_head = with_head(&chain, q_state);
    let mut seen = Seen::default();
    let m = message(30, chain.q, 1);
    // Under the head `p`, 30 is not in the PTC.
    assert_eq!(
        validate(&seen, &chain, &m),
        Verdict::Reject(RejectReason::NotInPtc {
            validator_index: 30,
            slot: 1
        })
    );
    assert_eq!(seen, Seen::default());
    // Under the head `q`, an invalid signature and no verdict leave Seen as it was.
    for (signatures, want) in [
        (Ok(false), Verdict::Reject(RejectReason::InvalidSignature)),
        (
            Err(BackendError("timeout".into())),
            Verdict::Ignore(IgnoreReason::NoSignatureVerdict),
        ),
    ] {
        let (_, key) = pending(validate_at(&seen, &q_head, &m, mid_slot_1()));
        assert_eq!(seen.resolve(key, signatures), want);
        assert_eq!(seen, Seen::default());
    }
    // A valid copy under the head `q` accepts.
    let (sets, key) = pending(validate_at(&seen, &q_head, &m, mid_slot_1()));
    assert_eq!(sets, vec![set_on(q_state, &m)]);
    assert_eq!(seen.resolve(key, Ok(true)), Verdict::Accept);
    assert!(seen.has_payload_attestation(1, 30));
    assert_eq!(seen.payload_attestation_count(), 1);
}

#[test]
fn seen_equality_does_not_depend_on_the_order_of_the_keys() {
    let chain = chain();
    let mut first = Seen::default();
    let mut second = Seen::default();
    for validator in [10, 11, 12] {
        let m = message(validator, chain.p, 1);
        assert_eq!(
            accept_at(&mut first, &chain.store, &m, mid_slot_1()),
            Verdict::Accept
        );
    }
    for validator in [12, 10, 11] {
        let m = message(validator, chain.p, 1);
        assert_eq!(
            accept_at(&mut second, &chain.store, &m, mid_slot_1()),
            Verdict::Accept
        );
    }
    assert_eq!(first, second);
}
