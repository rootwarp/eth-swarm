//! `on_payload_attestation_message` (G L1139-1187) on a store that the tests build, from the
//! wire and from a block.
//!
//! The test provider does not run the state transition. The post-state of a block is the parent
//! state at the slot of the block. The anchor state sets the PTC of slot 1, so the tests know
//! the PTC position of each member. The verifier gives the signature verdict that each test
//! chooses, and records each call.
//!
//! The provider does not move the PTC window. In a state of epoch 1, the PTC of slot 9 is the
//! entry that a state of epoch 0 has for slot 1, so the PTC that a test sets for slot 1 is also
//! the PTC of slot 9 in the later states.

use consensus_types::gloas::{
    BeaconBlock, BeaconState, Checkpoint, PayloadAttestationData, PayloadAttestationMessage,
    SignedBeaconBlock,
};
use consensus_types::primitives::{BLSSignature, Root, Slot, ValidatorIndex};
use consensus_types::signing::{
    compute_signing_root, SignatureSet, SignerRef, DOMAIN_PTC_ATTESTER,
};
use consensus_types::Minimal;
use fork_choice::testing::mark_payload_verified;
use fork_choice::{
    get_forkchoice_store, get_head, on_block, on_payload_attestation_message, on_tick,
    store_target_checkpoint_state, Error, ForkChoiceNode, PayloadAttestationError, PayloadStatus,
    SignatureVerifier, StateProvider, Store,
};
use state_transition::accessors::get_domain;
use state_transition::caches::get_ptc;
use state_transition::testing::{genesis_state, signed_block};
use state_transition::{state_root, BackendError, StfError};
use std::cell::RefCell;
use std::num::NonZeroU64;
use tree_hash::TreeHash;

type E = Minimal;

const SLOT_MS: u64 = 6000;
const GENESIS_TIME: u64 = 1_700_000_000;
/// `PTC_SIZE` of the minimal preset.
const PTC_SIZE: usize = 16;
/// `PAYLOAD_TIMELY_THRESHOLD` and `DATA_AVAILABILITY_TIMELY_THRESHOLD`: `PTC_SIZE // 2`.
const THRESHOLD: usize = PTC_SIZE / 2;
const SIG: BLSSignature = [0x33; 96];
/// The PTC of slot 1 in most tests: validator `10 + i` at position `i`.
const DISTINCT: [ValidatorIndex; PTC_SIZE] = [
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];
/// A validator that is not in [`DISTINCT`].
const OUTSIDER: ValidatorIndex = 40;
/// The PTC of slot 1 in the post-state of a block of [`OtherPtc`]: validator `48 + i` at
/// position `i`. It has no validator of [`DISTINCT`].
const OTHER_PTC: [ValidatorIndex; PTC_SIZE] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
];
/// The fork version of the post-state of a block of [`OtherPtc`].
const OTHER_VERSION: [u8; 4] = [9, 9, 9, 9];

fn time_at(slot: Slot) -> u64 {
    GENESIS_TIME * 1000 + slot * SLOT_MS
}

fn tick(store: &mut Store<E>, slot: Slot) {
    on_tick(store, time_at(slot)).unwrap();
}

/// The post-state is the parent state at the slot of the block.
struct Provider;

impl StateProvider<E> for Provider {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        state.slot = block.message.slot;
        Ok(())
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        state.slot = slot;
        Ok(())
    }
}

/// [`Provider`], and the post-state has the PTC [`OTHER_PTC`] for slot 1 and the fork version
/// [`OTHER_VERSION`].
struct OtherPtc;

impl StateProvider<E> for OtherPtc {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        Provider.state_transition(state, block)?;
        set_ptc(state, OTHER_PTC);
        state.fork.current_version = OTHER_VERSION;
        Ok(())
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        Provider.process_slots(state, slot)
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

/// Sets the PTC of slot 1 of `state`, a state of epoch 0, to `ptc`.
fn set_ptc(state: &mut BeaconState<E>, ptc: [ValidatorIndex; PTC_SIZE]) {
    let mut committee = get_ptc(state, 1).unwrap();
    for (member, validator) in committee.iter_mut().zip(ptc) {
        *member = validator;
    }
    // In epoch 0, the PTC of slot 1 is at index `SLOTS_PER_EPOCH + 1`.
    *state.ptc_window.get_mut(9).unwrap() = committee;
}

/// A verifier with a fixed verdict. It records the slot of the state and the sets of each call.
struct Verifier {
    verdict: Result<bool, BackendError>,
    calls: RefCell<Vec<(Slot, Vec<SignatureSet>)>>,
}

impl Verifier {
    fn new(verdict: Result<bool, BackendError>) -> Self {
        Self {
            verdict,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(Slot, Vec<SignatureSet>)> {
        self.calls.borrow().clone()
    }
}

impl SignatureVerifier<E> for Verifier {
    fn verify_signature_sets(
        &self,
        state: &BeaconState<E>,
        sets: &[SignatureSet],
    ) -> Result<bool, BackendError> {
        self.calls.borrow_mut().push((state.slot, sets.to_vec()));
        self.verdict.clone()
    }
}

fn accept() -> Verifier {
    Verifier::new(Ok(true))
}

fn refuse() -> Verifier {
    Verifier::new(Ok(false))
}

fn no_verdict() -> Verifier {
    Verifier::new(Err(BackendError("timeout".into())))
}

/// A store at a genesis anchor and one block `p` at slot 1 on the EMPTY anchor, at the start
/// of slot 1.
struct Chain {
    store: Store<E>,
    p: SignedBeaconBlock<E>,
    root: Root,
}

/// The [`Chain`] with `ptc` as the PTC of slot 1.
fn chain_with_ptc(ptc: [ValidatorIndex; PTC_SIZE]) -> Chain {
    let mut state = genesis_state::<E>(&[32_000_000_000; 64]);
    state.genesis_time = GENESIS_TIME;
    set_ptc(&mut state, ptc);
    assert_eq!(get_ptc(&state, 1).unwrap().to_vec(), ptc.to_vec());
    let mut anchor = signed_block::<E>(0, 0).message;
    anchor.state_root = state_root(&mut state).unwrap();
    let mut store =
        get_forkchoice_store(state, anchor.clone(), NonZeroU64::new(SLOT_MS).unwrap()).unwrap();
    tick(&mut store, 1);
    let p = child(&anchor, 1, 1);
    on_block(&mut store, &Provider, &p).unwrap();
    let root = p.message.tree_hash_root();
    Chain { store, p, root }
}

fn chain() -> Chain {
    chain_with_ptc(DISTINCT)
}

/// A block at `slot` on the EMPTY node of `parent` by proposer `tag`.
fn child(parent: &BeaconBlock<E>, slot: Slot, tag: u8) -> SignedBeaconBlock<E> {
    child_of(parent.tree_hash_root(), slot, tag)
}

/// A block at `slot` on the EMPTY node of the block `parent_root` by proposer `tag`.
fn child_of(parent_root: Root, slot: Slot, tag: u8) -> SignedBeaconBlock<E> {
    let mut block = signed_block::<E>(slot, u64::from(tag));
    block.message.parent_root = parent_root;
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.parent_block_hash = Root::repeat_byte(0xee);
    bid.block_hash = Root::repeat_byte(tag);
    block
}

/// A message of `validator` for `root` at `slot`, with the signature [`SIG`].
fn message(
    validator: ValidatorIndex,
    root: Root,
    slot: Slot,
    present: bool,
    available: bool,
) -> PayloadAttestationMessage {
    PayloadAttestationMessage {
        validator_index: validator,
        data: PayloadAttestationData {
            beacon_block_root: root,
            slot,
            payload_present: present,
            blob_data_available: available,
        },
        signature: SIG,
    }
}

/// `PTC_SIZE` votes: `value` at `positions`, and no vote at the others.
fn votes(positions: &[usize], value: bool) -> Vec<Option<bool>> {
    (0..PTC_SIZE)
        .map(|i| positions.contains(&i).then_some(value))
        .collect()
}

/// The timeliness and data availability votes of `root`.
fn votes_of(store: &Store<E>, root: Root) -> (Vec<Option<bool>>, Vec<Option<bool>>) {
    (
        store.payload_timeliness_vote(root).unwrap().to_vec(),
        store.payload_data_availability_vote(root).unwrap().to_vec(),
    )
}

fn invalid(error: PayloadAttestationError) -> Result<(), Error> {
    Err(Error::InvalidPayloadAttestation(error))
}

/// The set of the signature check of `m` on `state`: the key of the validator, and the signing
/// root of the data in the PTC domain of `state` at the epoch of the data slot.
fn set_on(state: &BeaconState<E>, m: &PayloadAttestationMessage) -> SignatureSet {
    let epoch = m.data.slot / 8;
    let domain = get_domain(state, DOMAIN_PTC_ATTESTER, Some(epoch));
    SignatureSet::single(
        SignerRef::Validator(m.validator_index),
        compute_signing_root(&m.data, domain),
        m.signature,
    )
}

#[test]
fn a_message_for_an_unknown_block_fails() {
    let mut c = chain();
    let unknown = Root::repeat_byte(0xff);
    let before = c.store.clone();
    for is_from_block in [false, true] {
        let verifier = accept();
        let m = message(10, unknown, 1, true, true);
        assert_eq!(
            on_payload_attestation_message(&mut c.store, &verifier, &m, is_from_block),
            invalid(PayloadAttestationError::UnknownBeaconBlock(unknown))
        );
        assert!(verifier.calls().is_empty());
        assert_eq!(c.store, before);
    }
}

#[test]
fn a_message_of_another_slot_than_its_block_returns_early_with_no_vote() {
    let mut c = chain();
    let before = c.store.clone();
    // The block is of slot 1. The early return comes before the PTC check, the current slot
    // check and the signature, so a validator outside the PTC also passes.
    for (validator, slot) in [(10, 2), (10, 0), (OUTSIDER, 2)] {
        for is_from_block in [false, true] {
            let verifier = refuse();
            let m = message(validator, c.root, slot, true, true);
            assert_eq!(
                on_payload_attestation_message(&mut c.store, &verifier, &m, is_from_block),
                Ok(())
            );
            assert!(verifier.calls().is_empty());
            assert_eq!(c.store, before);
        }
    }
}

#[test]
fn a_validator_outside_the_ptc_fails() {
    let mut c = chain();
    let before = c.store.clone();
    let want = invalid(PayloadAttestationError::NotInPtc {
        validator: OUTSIDER,
        slot: 1,
    });
    for is_from_block in [false, true] {
        let verifier = accept();
        let m = message(OUTSIDER, c.root, 1, true, true);
        assert_eq!(
            on_payload_attestation_message(&mut c.store, &verifier, &m, is_from_block),
            want
        );
        assert!(verifier.calls().is_empty());
        assert_eq!(c.store, before);
    }
    // The PTC check comes before the current slot check.
    tick(&mut c.store, 2);
    let verifier = accept();
    let m = message(OUTSIDER, c.root, 1, true, true);
    assert_eq!(
        on_payload_attestation_message(&mut c.store, &verifier, &m, false),
        want
    );
}

#[test]
fn a_repeated_ptc_member_votes_at_each_of_its_positions() {
    let mut ptc = DISTINCT;
    ptc[2] = 30;
    ptc[5] = 30;
    let mut c = chain_with_ptc(ptc);
    let verifier = accept();
    let m = message(30, c.root, 1, true, false);
    assert_eq!(
        on_payload_attestation_message(&mut c.store, &verifier, &m, false),
        Ok(())
    );
    assert_eq!(
        votes_of(&c.store, c.root),
        (votes(&[2, 5], true), votes(&[2, 5], false))
    );
    // One message gives one signature set of one signer.
    let calls = verifier.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 1);
    assert_eq!(calls[0].1[0].signers(), &[SignerRef::Validator(30)]);
}

#[test]
fn a_wire_message_of_a_past_slot_fails() {
    let mut c = chain();
    tick(&mut c.store, 2);
    let before = c.store.clone();
    let verifier = accept();
    let m = message(10, c.root, 1, true, true);
    assert_eq!(
        on_payload_attestation_message(&mut c.store, &verifier, &m, false),
        invalid(PayloadAttestationError::NotCurrentSlot {
            slot: 1,
            current: 2
        })
    );
    // The current slot check comes before the signature.
    assert!(verifier.calls().is_empty());
    assert_eq!(c.store, before);
}

#[test]
fn a_wire_message_needs_a_valid_signature() {
    let c = chain();
    let state = c.store.block_state(c.root).unwrap();
    let m = message(13, c.root, 1, true, false);
    let domain = get_domain(state, DOMAIN_PTC_ATTESTER, Some(0));
    let set = SignatureSet::single(
        SignerRef::Validator(13),
        compute_signing_root(&m.data, domain),
        SIG,
    );

    // A refused signature proves the message invalid.
    let mut store = c.store.clone();
    let verifier = refuse();
    assert_eq!(
        on_payload_attestation_message(&mut store, &verifier, &m, false),
        invalid(PayloadAttestationError::InvalidSignature)
    );
    assert_eq!(store, c.store);
    // The verifier checks the set on the post-state of the attested block (slot 1).
    assert_eq!(verifier.calls(), vec![(1, vec![set.clone()])]);

    // No verdict is not a proof.
    let verifier = no_verdict();
    assert_eq!(
        on_payload_attestation_message(&mut store, &verifier, &m, false),
        Err(Error::NoSignatureVerdict(BackendError("timeout".into())))
    );
    assert_eq!(store, c.store);

    // A valid signature writes the votes of the position of the validator.
    let verifier = accept();
    assert_eq!(
        on_payload_attestation_message(&mut store, &verifier, &m, false),
        Ok(())
    );
    assert_eq!(verifier.calls(), vec![(1, vec![set])]);
    assert_eq!(
        votes_of(&store, c.root),
        (votes(&[3], true), votes(&[3], false))
    );
}

#[test]
fn a_message_from_a_block_skips_the_current_slot_and_the_signature() {
    let mut c = chain();
    tick(&mut c.store, 2);
    let verifier = refuse();
    let m = message(11, c.root, 1, false, true);
    assert_eq!(
        on_payload_attestation_message(&mut c.store, &verifier, &m, true),
        Ok(())
    );
    assert!(verifier.calls().is_empty());
    assert_eq!(
        votes_of(&c.store, c.root),
        (votes(&[1], false), votes(&[1], true))
    );
}

#[test]
fn a_later_message_replaces_the_earlier_vote_at_its_positions() {
    let mut c = chain();
    let verifier = accept();
    for m in [
        message(10, c.root, 1, true, true),
        message(14, c.root, 1, true, true),
        message(10, c.root, 1, false, false),
    ] {
        assert_eq!(
            on_payload_attestation_message(&mut c.store, &verifier, &m, false),
            Ok(())
        );
    }
    let mut want = votes(&[4], true);
    want[0] = Some(false);
    assert_eq!(votes_of(&c.store, c.root), (want.clone(), want));
}

#[test]
fn a_failed_call_leaves_the_store_unchanged() {
    let mut c = chain();
    // A vote before the failed calls, so that the votes are not all empty.
    let m = message(10, c.root, 1, true, false);
    on_payload_attestation_message(&mut c.store, &accept(), &m, false).unwrap();
    let unknown = message(11, Root::repeat_byte(0xff), 1, false, true);
    let outsider = message(OUTSIDER, c.root, 1, false, true);
    let member = message(11, c.root, 1, false, true);
    let cases: [(&PayloadAttestationMessage, Verifier, bool); 4] = [
        (&unknown, accept(), false),
        (&outsider, accept(), true),
        (&member, refuse(), false),
        (&member, no_verdict(), false),
    ];
    for (m, verifier, is_from_block) in cases {
        let before = c.store.clone();
        assert!(
            on_payload_attestation_message(&mut c.store, &verifier, m, is_from_block).is_err(),
            "{m:?}"
        );
        assert_eq!(c.store, before, "{m:?}");
    }
    // The current slot check, one slot later.
    tick(&mut c.store, 2);
    let before = c.store.clone();
    assert!(on_payload_attestation_message(&mut c.store, &accept(), &member, false).is_err());
    assert_eq!(c.store, before);
}

#[test]
fn votes_past_the_thresholds_make_the_full_payload_win_the_tiebreak() {
    // (timely votes, available votes, FULL wins). A vote counts only above half of the PTC,
    // and the FULL node needs both majorities.
    for (timely, available, full_wins) in [
        (THRESHOLD, THRESHOLD, false),
        (THRESHOLD + 1, THRESHOLD, false),
        (THRESHOLD, THRESHOLD + 1, false),
        (THRESHOLD + 1, THRESHOLD + 1, true),
        (PTC_SIZE, PTC_SIZE, true),
    ] {
        let mut c = chain();
        mark_payload_verified(&mut c.store, c.root);
        let verifier = accept();
        for (position, validator) in DISTINCT.iter().enumerate() {
            let m = message(
                *validator,
                c.root,
                1,
                position < timely,
                position < available,
            );
            on_payload_attestation_message(&mut c.store, &verifier, &m, false).unwrap();
        }
        // `q` at slot 2 builds on the EMPTY node of `p` and gets the boost. Both payload
        // nodes of `p` are of the previous slot and have no weight, so the tiebreak decides.
        tick(&mut c.store, 2);
        let q = child(&c.p.message, 2, 2);
        on_block(&mut c.store, &Provider, &q).unwrap();
        let want = if full_wins {
            ForkChoiceNode {
                root: c.root,
                payload_status: PayloadStatus::Full,
            }
        } else {
            ForkChoiceNode {
                root: q.message.tree_hash_root(),
                payload_status: PayloadStatus::Empty,
            }
        };
        assert_eq!(
            get_head(&c.store),
            Ok(want),
            "timely {timely}, available {available}"
        );
    }
}

#[test]
fn a_message_for_a_block_that_is_not_the_head_reads_the_post_state_of_that_block() {
    let mut c = chain();
    // `competing` is a second block of slot 1. It comes after `p`, so `p` keeps the proposer
    // boost and stays the head.
    let competing = child_of(c.p.message.parent_root, 1, 7);
    on_block(&mut c.store, &OtherPtc, &competing).unwrap();
    let competing = competing.message.tree_hash_root();
    assert_eq!(get_head(&c.store).unwrap().root, c.root);
    let state = c.store.block_state(competing).unwrap().clone();
    let head_state = c.store.block_state(c.root).unwrap().clone();
    assert_eq!(get_ptc(&state, 1).unwrap().to_vec(), OTHER_PTC.to_vec());
    assert_eq!(get_ptc(&head_state, 1).unwrap().to_vec(), DISTINCT.to_vec());

    // 49 is at position 1 of the PTC of `competing`, and not in the PTC of the head. The
    // signature set has the domain of the post-state of `competing`, not of the head state.
    let m = message(49, competing, 1, true, false);
    let set = set_on(&state, &m);
    assert_ne!(set, set_on(&head_state, &m));
    let verifier = accept();
    assert_eq!(
        on_payload_attestation_message(&mut c.store, &verifier, &m, false),
        Ok(())
    );
    assert_eq!(verifier.calls(), vec![(1, vec![set])]);
    assert_eq!(
        votes_of(&c.store, competing),
        (votes(&[1], true), votes(&[1], false))
    );
    // The votes of the head do not change.
    assert_eq!(
        votes_of(&c.store, c.root),
        (votes(&[], true), votes(&[], true))
    );

    // 10 is in the PTC of the head, and not in the PTC of `competing`.
    let before = c.store.clone();
    for is_from_block in [false, true] {
        let verifier = accept();
        let m = message(10, competing, 1, true, true);
        assert_eq!(
            on_payload_attestation_message(&mut c.store, &verifier, &m, is_from_block),
            invalid(PayloadAttestationError::NotInPtc {
                validator: 10,
                slot: 1
            })
        );
        assert!(verifier.calls().is_empty());
        assert_eq!(c.store, before);
    }
}

/// A store in which the finality prune at slot 9 dropped the block `b`.
struct Pruned {
    store: Store<E>,
    b: Root,
}

/// The anchor at slot 0 with the PTC [`DISTINCT`] for slot 1, `p` and `x` at slot 1 on it, `b`
/// of [`OtherPtc`] at slot 9 on `x`, and `c` at slot 9 on `p`. The post-state of `c` justifies
/// and finalizes epoch 1 (first slot 8) with `p`. The blocks of slot 9 come after the
/// attestation deadline, so neither gets the proposer boost, and the next tick in slot 9
/// prunes: it drops the anchor, `x` and `b`.
///
/// The prune in epoch 1 keeps the dropped blocks and their post-states through the end of
/// epoch 3 (slot 31). The head is `c`, whose PTC of slot 9 is [`DISTINCT`]. The PTC of slot 9
/// of `b` is [`OTHER_PTC`].
fn pruned() -> Pruned {
    let mut c = chain();
    let x = child_of(c.p.message.parent_root, 1, 2);
    on_block(&mut c.store, &Provider, &x).unwrap();
    let late = time_at(9) + SLOT_MS / 2;
    on_tick(&mut c.store, late).unwrap();
    let b = child(&x.message, 9, 3);
    on_block(&mut c.store, &OtherPtc, &b).unwrap();
    let checkpoint = Checkpoint {
        epoch: 1,
        root: c.root,
    };
    let finalizing = child(&c.p.message, 9, 4);
    on_block(&mut c.store, &Finalizing(checkpoint.clone()), &finalizing).unwrap();
    assert_eq!(c.store.finalized_checkpoint(), &checkpoint);
    // On the spec path, `on_attestation` stores the state of the justified checkpoint.
    store_target_checkpoint_state(&mut c.store, &Provider, &checkpoint).unwrap();
    on_tick(&mut c.store, late).unwrap();
    let b = b.message.tree_hash_root();
    assert!(c.store.block(b).is_none());
    assert!(c.store.block_or_dropped(b).is_some());
    let head = get_head(&c.store).unwrap().root;
    assert_eq!(head, finalizing.message.tree_hash_root());
    let head_state = c.store.block_state(head).unwrap();
    assert_eq!(get_ptc(head_state, 9).unwrap().to_vec(), DISTINCT.to_vec());
    let state = c.store.block_state_or_dropped(b).unwrap();
    assert_eq!(get_ptc(state, 9).unwrap().to_vec(), OTHER_PTC.to_vec());
    Pruned { store: c.store, b }
}

#[test]
fn a_message_for_a_retained_dropped_block_checks_its_state_and_writes_no_vote() {
    let mut f = pruned();
    let state = f.store.block_state_or_dropped(f.b).unwrap().clone();
    let head = get_head(&f.store).unwrap();
    let before = f.store.clone();

    // 49 is at position 1 of the PTC of `b`, and not in the PTC of the head. The message
    // passes, but the store has no votes of `b`, so nothing changes.
    let m = message(49, f.b, 9, true, true);
    for is_from_block in [false, true] {
        let verifier = accept();
        assert_eq!(
            on_payload_attestation_message(&mut f.store, &verifier, &m, is_from_block),
            Ok(())
        );
        // A message from the wire has the signature set of the post-state of `b`.
        let want = if is_from_block {
            vec![]
        } else {
            vec![(9, vec![set_on(&state, &m)])]
        };
        assert_eq!(verifier.calls(), want);
        assert_eq!(f.store, before);
        assert_eq!(get_head(&f.store), Ok(head));
    }
    assert!(f.store.payload_timeliness_vote(f.b).is_none());
    assert!(f.store.payload_data_availability_vote(f.b).is_none());

    // The checks still apply. 10 is in the PTC of the head, and not in the PTC of `b`.
    for is_from_block in [false, true] {
        let verifier = accept();
        let m = message(10, f.b, 9, true, true);
        assert_eq!(
            on_payload_attestation_message(&mut f.store, &verifier, &m, is_from_block),
            invalid(PayloadAttestationError::NotInPtc {
                validator: 10,
                slot: 9
            })
        );
        assert!(verifier.calls().is_empty());
        assert_eq!(f.store, before);
    }
    // A refused signature fails, and no verdict is not a proof.
    assert_eq!(
        on_payload_attestation_message(&mut f.store, &refuse(), &m, false),
        invalid(PayloadAttestationError::InvalidSignature)
    );
    assert_eq!(
        on_payload_attestation_message(&mut f.store, &no_verdict(), &m, false),
        Err(Error::NoSignatureVerdict(BackendError("timeout".into())))
    );
    assert_eq!(f.store, before);
    assert_eq!(get_head(&f.store), Ok(head));
}

#[test]
fn a_message_for_a_forgotten_block_fails_as_unknown() {
    let mut f = pruned();
    // The prune ran in epoch 1. The store keeps `b` through the end of epoch 3, and the first
    // tick of epoch 4 forgets it.
    tick(&mut f.store, 31);
    assert!(f.store.block_or_dropped(f.b).is_some());
    tick(&mut f.store, 32);
    assert!(f.store.block_or_dropped(f.b).is_none());
    let head = get_head(&f.store).unwrap();
    let before = f.store.clone();
    for is_from_block in [false, true] {
        let verifier = accept();
        let m = message(49, f.b, 9, true, true);
        assert_eq!(
            on_payload_attestation_message(&mut f.store, &verifier, &m, is_from_block),
            invalid(PayloadAttestationError::UnknownBeaconBlock(f.b))
        );
        assert!(verifier.calls().is_empty());
        assert_eq!(f.store, before);
        assert_eq!(get_head(&f.store), Ok(head));
    }
}
