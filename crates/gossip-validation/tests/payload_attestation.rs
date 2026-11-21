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
use fork_choice::{get_forkchoice_store, get_head, on_block, on_tick, StateProvider, Store};
use gossip_validation::{
    is_current_slot, validate_payload_attestation_message_gossip, IgnoreReason, RejectReason, Seen,
    SeenKey, StoreView, Verdict, MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS,
};
use state_transition::accessors::get_domain;
use state_transition::caches::get_ptc;
use state_transition::testing::{genesis_state, signed_block};
use state_transition::{state_root, BackendError, StfError};
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

fn chain() -> Chain {
    let mut state = genesis_state::<E>(&[32_000_000_000; 64]);
    state.genesis_time = GENESIS_TIME;
    set_ptc(&mut state, HEAD_PTC);
    let mut anchor = signed_block::<E>(0, 0).message;
    anchor.state_root = state_root(&mut state).unwrap();
    let slot_duration = NonZeroU64::new(SLOT_MS).unwrap();
    let mut store = get_forkchoice_store(state, anchor.clone(), slot_duration).unwrap();
    on_tick(&mut store, time_at(1)).unwrap();
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
    let epoch = m.data.slot / 8;
    let domain = get_domain(chain.head_state(), DOMAIN_PTC_ATTESTER, Some(epoch));
    SignatureSet::single(
        SignerRef::Validator(m.validator_index),
        compute_signing_root(&m.data, domain),
        m.signature,
    )
}

/// The verdict of `m` at the middle of slot 1, with Gloas from genesis.
fn validate(seen: &Seen, chain: &Chain, m: &PayloadAttestationMessage) -> Verdict {
    validate_at(seen, &chain.store, m, time_at(1) + SLOT_MS / 2)
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
