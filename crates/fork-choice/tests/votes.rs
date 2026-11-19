//! `on_attestation` and `on_attester_slashing`: the Gloas checks of an attestation, the latest
//! messages that it sets, the checkpoint state of its target, and the equivocations of a
//! slashing, seen through the store, `get_weight` and `get_head`.
//!
//! The test provider does not run the state transition. The post-state of a block is the
//! parent state at the slot of the block, after an optional edit, and `process_slots` sets only
//! the slot. Its signature check refuses only the signature [`BAD_SIGNATURE`], and it records
//! the slot of each state that it checks a signature against. The registry has 64 validators
//! of 32 ETH, and the minimal preset has two committees of four for each slot.

use consensus_types::common::AttestationData;
use consensus_types::gloas::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, Checkpoint, IndexedAttestation,
    SignedBeaconBlock,
};
use consensus_types::primitives::{BLSSignature, Gwei, Root, Slot, ValidatorIndex};
use consensus_types::Minimal;
use fork_choice::testing::mark_payload_verified;
use fork_choice::{
    get_forkchoice_store, get_head, get_weight, on_attestation, on_attester_slashing, on_block,
    on_tick, AttestationError, Error, ForkChoiceNode, LatestMessage, PayloadStatus,
    SignatureVerifier, StateProvider, Store,
};
use ssz::{BitVector, ProgressiveBitList};
use ssz_types::ProgressiveVariableList;
use state_transition::caches::CommitteeCache;
use state_transition::testing::{genesis_state, signed_block};
use state_transition::{state_root, BackendError, SignatureSet, StfError};
use std::cell::RefCell;
use std::num::NonZeroU64;
use tree_hash::TreeHash;

type E = Minimal;

const SLOT_MS: u64 = 6000;
const GENESIS_TIME: u64 = 1_700_000_000;
const VALIDATORS: usize = 64;
const BALANCE: Gwei = 32_000_000_000;
/// `SLOTS_PER_EPOCH` of the minimal preset.
const SLOTS_PER_EPOCH: Slot = 8;
/// The one signature that the test provider refuses.
const BAD_SIGNATURE: BLSSignature = [0xff; 96];
const GOOD_SIGNATURE: BLSSignature = [0x22; 96];

fn time_at(slot: Slot) -> u64 {
    GENESIS_TIME * 1000 + slot * SLOT_MS
}

fn tick(store: &mut Store<E>, slot: Slot) {
    on_tick(store, time_at(slot)).unwrap();
}

/// A store at an anchor of `slot` with 64 validators of 32 ETH, and the anchor block. The
/// anchor block is of `block_slot`, at or before `slot`.
fn store_at(slot: Slot, block_slot: Slot) -> (Store<E>, BeaconBlock<E>) {
    let mut state = genesis_state::<E>(&[BALANCE; VALIDATORS]);
    state.genesis_time = GENESIS_TIME;
    state.slot = slot;
    let mut block = signed_block::<E>(block_slot, 0).message;
    block.state_root = state_root(&mut state).unwrap();
    let slot_duration = NonZeroU64::new(SLOT_MS).unwrap();
    let store = get_forkchoice_store(state, block.clone(), slot_duration).unwrap();
    (store, block)
}

/// A store at a genesis anchor, and the anchor block.
fn new_store() -> (Store<E>, BeaconBlock<E>) {
    store_at(0, 0)
}

/// The post-state is the parent state at the slot of the block, after `edit`.
struct Provider<F = fn(&mut BeaconState<E>)> {
    edit: F,
    /// The slot of each state that a signature was checked against.
    checked: RefCell<Vec<Slot>>,
}

impl<F: Fn(&mut BeaconState<E>)> Provider<F> {
    fn new(edit: F) -> Self {
        Self {
            edit,
            checked: RefCell::new(Vec::new()),
        }
    }
}

fn keep(_: &mut BeaconState<E>) {}

fn plain() -> Provider {
    Provider::new(keep)
}

impl<F: Fn(&mut BeaconState<E>)> StateProvider<E> for Provider<F> {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        state.slot = block.message.slot;
        (self.edit)(state);
        Ok(())
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        state.slot = slot;
        Ok(())
    }
}

impl<F> SignatureVerifier<E> for Provider<F> {
    fn verify_signature_sets(
        &self,
        state: &BeaconState<E>,
        sets: &[SignatureSet],
    ) -> Result<bool, BackendError> {
        self.checked.borrow_mut().push(state.slot);
        Ok(sets.iter().all(|set| *set.signature() != BAD_SIGNATURE))
    }
}

/// A block at `slot` on `parent` by proposer `tag`. If `full` is true, its bid builds on the
/// payload of the bid of `parent` (a FULL parent). Else it builds on an EMPTY parent.
fn child(parent: &BeaconBlock<E>, slot: Slot, full: bool, tag: u8) -> SignedBeaconBlock<E> {
    let mut block = signed_block::<E>(slot, u64::from(tag));
    block.message.parent_root = parent.tree_hash_root();
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.parent_block_hash = if full {
        parent.body.signed_execution_payload_bid.message.block_hash
    } else {
        Root::repeat_byte(0xee)
    };
    let mut hash = [0u8; 32];
    hash[0] = slot as u8;
    hash[1] = tag;
    hash[2] = 0xbb;
    bid.block_hash = Root::from(hash);
    block
}

fn root_of(block: &SignedBeaconBlock<E>) -> Root {
    block.message.tree_hash_root()
}

fn node(root: Root, payload_status: PayloadStatus) -> ForkChoiceNode {
    ForkChoiceNode {
        root,
        payload_status,
    }
}

fn pending(root: Root) -> ForkChoiceNode {
    node(root, PayloadStatus::Pending)
}

fn empty(root: Root) -> ForkChoiceNode {
    node(root, PayloadStatus::Empty)
}

fn full(root: Root) -> ForkChoiceNode {
    node(root, PayloadStatus::Full)
}

/// The state that `on_attestation` reads the committees from: the state of the target block
/// at the first slot of the target epoch, as the test provider advances it.
fn target_state(store: &Store<E>, target: &Checkpoint) -> BeaconState<E> {
    let mut state = store.block_state(target.root).unwrap().clone();
    state.slot = state.slot.max(target.epoch * SLOTS_PER_EPOCH);
    state
}

/// The committee `index` of `slot`, from the state of `target`.
fn committee(store: &Store<E>, target: &Checkpoint, slot: Slot, index: u64) -> Vec<ValidatorIndex> {
    let state = target_state(store, target);
    let cache = CommitteeCache::new(&state, target.epoch).unwrap();
    cache.committee(slot, index).unwrap().to_vec()
}

/// The slot, the committee and the position of `validator` in the epoch of `target`. Each
/// validator is in one committee of each epoch.
fn duty(store: &Store<E>, target: &Checkpoint, validator: ValidatorIndex) -> (Slot, u64, usize) {
    let first = target.epoch * SLOTS_PER_EPOCH;
    (first..first + SLOTS_PER_EPOCH)
        .flat_map(|slot| [(slot, 0), (slot, 1)])
        .find_map(|(slot, index)| {
            let members = committee(store, target, slot, index);
            let position = members.iter().position(|v| *v == validator)?;
            Some((slot, index, position))
        })
        .unwrap()
}

/// A vote of a committee of `slot` for `root`.
struct Vote {
    slot: Slot,
    root: Root,
    index: u64,
    target: Checkpoint,
    /// The committee of the slot.
    committee: u64,
    /// The positions in the committee that attest.
    positions: Vec<usize>,
    signature: BLSSignature,
}

impl Vote {
    /// A vote of the member at `position` with index 0 and a good signature. The target is
    /// the anchor of epoch 0: give another with [`Vote::target`].
    fn new(store: &Store<E>, slot: Slot, root: Root, position: usize) -> Self {
        Self {
            slot,
            root,
            index: 0,
            target: store.finalized_checkpoint().clone(),
            committee: 0,
            positions: vec![position],
            signature: GOOD_SIGNATURE,
        }
    }

    fn index(mut self, index: u64) -> Self {
        self.index = index;
        self
    }

    fn target(mut self, epoch: u64, root: Root) -> Self {
        self.target = Checkpoint { epoch, root };
        self
    }

    fn committee(mut self, committee: u64) -> Self {
        self.committee = committee;
        self
    }

    fn positions(mut self, positions: &[usize]) -> Self {
        self.positions = positions.to_vec();
        self
    }

    fn signature(mut self, signature: BLSSignature) -> Self {
        self.signature = signature;
        self
    }

    fn data(&self, store: &Store<E>) -> AttestationData {
        AttestationData {
            slot: self.slot,
            index: self.index,
            beacon_block_root: self.root,
            source: store.justified_checkpoint().clone(),
            target: self.target.clone(),
        }
    }

    /// The validators that attest.
    fn attesters(&self, store: &Store<E>) -> Vec<ValidatorIndex> {
        let members = committee(store, &self.target, self.slot, self.committee);
        self.positions.iter().map(|p| members[*p]).collect()
    }

    fn attestation(&self, store: &Store<E>) -> Attestation<E> {
        let size = committee(store, &self.target, self.slot, self.committee).len();
        let mut aggregation_bits = ProgressiveBitList::with_capacity(size);
        for &position in &self.positions {
            aggregation_bits.set(position, true).unwrap();
        }
        let mut committee_bits = BitVector::new();
        committee_bits.set(self.committee as usize, true).unwrap();
        Attestation {
            aggregation_bits,
            data: self.data(store),
            signature: self.signature,
            committee_bits,
        }
    }

    /// The indexed attestation of the vote, for a slashing.
    fn indexed(&self, store: &Store<E>) -> IndexedAttestation<E> {
        let mut indices = self.attesters(store);
        indices.sort_unstable();
        IndexedAttestation {
            attesting_indices: ProgressiveVariableList::new(indices).unwrap(),
            data: self.data(store),
            signature: self.signature,
        }
    }
}

/// `on_attestation` of `vote` from the wire, with the plain provider.
fn gossip(store: &mut Store<E>, vote: &Vote) -> Result<(), Error> {
    let attestation = vote.attestation(store);
    on_attestation(store, &plain(), &attestation, false)
}

/// `on_attestation` of `vote` from a block, with the plain provider.
fn from_block(store: &mut Store<E>, vote: &Vote) -> Result<(), Error> {
    let attestation = vote.attestation(store);
    on_attestation(store, &plain(), &attestation, true)
}

fn refused(reason: AttestationError) -> Result<(), Error> {
    Err(Error::InvalidAttestation(reason))
}

/// anchor, then `a` at slot 1. The store is at the start of `now`.
struct One {
    store: Store<E>,
    anchor: BeaconBlock<E>,
    a: SignedBeaconBlock<E>,
}

impl One {
    fn root(&self) -> Root {
        root_of(&self.a)
    }
}

fn one_block(now: Slot) -> One {
    let (mut store, anchor) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor, 1, false, 1);
    on_block(&mut store, &plain(), &a).unwrap();
    tick(&mut store, now);
    One { store, anchor, a }
}

#[test]
fn payload_status_tiebreak() {
    // A node of a slot before the previous slot: with equal weights, the tiebreaker is the
    // payload status, so FULL (1) wins over EMPTY (0).
    let mut f = one_block(3);
    let a = f.root();
    mark_payload_verified(&mut f.store, a);
    let full_vote = Vote::new(&f.store, 2, a, 0).index(1);
    let empty_vote = Vote::new(&f.store, 2, a, 1).index(0);
    gossip(&mut f.store, &full_vote).unwrap();
    gossip(&mut f.store, &empty_vote).unwrap();
    assert_eq!(get_weight(&f.store, &full(a)), Ok(BALANCE));
    assert_eq!(get_weight(&f.store, &empty(a)), Ok(BALANCE));
    assert_eq!(get_head(&f.store), Ok(full(a)));
    // A heavier EMPTY node wins: the weight decides before the tiebreaker.
    let empty_vote = Vote::new(&f.store, 2, a, 2).index(0);
    gossip(&mut f.store, &empty_vote).unwrap();
    assert_eq!(get_weight(&f.store, &empty(a)), Ok(2 * BALANCE));
    assert_eq!(get_head(&f.store), Ok(empty(a)));

    // A node of the previous slot decides its payload: both nodes have no weight. With a
    // verified payload and no proposer boost, `should_extend_payload` is true, so FULL (2)
    // wins over EMPTY (1).
    let mut f = one_block(2);
    let a = f.root();
    mark_payload_verified(&mut f.store, a);
    assert_eq!(get_weight(&f.store, &full(a)), Ok(0));
    assert_eq!(get_weight(&f.store, &empty(a)), Ok(0));
    assert_eq!(get_head(&f.store), Ok(full(a)));
    // A timely child on the EMPTY node gets the boost. The PTC did not vote for the payload,
    // so `should_extend_payload` is false: FULL becomes 0, and EMPTY (1) wins.
    let c = child(&f.a.message, 2, false, 2);
    on_block(&mut f.store, &plain(), &c).unwrap();
    assert_eq!(f.store.proposer_boost_root(), root_of(&c));
    assert_eq!(get_weight(&f.store, &full(a)), Ok(0));
    assert_eq!(get_weight(&f.store, &empty(a)), Ok(0));
    assert_eq!(get_head(&f.store), Ok(empty(root_of(&c))));
}

/// anchor, then `a` at slot 1 with a verified payload, then `b` at slot 2 on the FULL `a` and
/// `c` at slot 2 on the EMPTY `a`. The store is at the start of slot 4.
struct Fork {
    store: Store<E>,
    roots: [Root; 4],
    b: Root,
    c: Root,
}

fn fork() -> Fork {
    let (mut store, anchor) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor, 1, false, 1);
    on_block(&mut store, &plain(), &a).unwrap();
    mark_payload_verified(&mut store, root_of(&a));
    tick(&mut store, 2);
    let b = child(&a.message, 2, true, 2);
    let c = child(&a.message, 2, false, 3);
    for block in [&b, &c] {
        on_block(&mut store, &plain(), block).unwrap();
    }
    tick(&mut store, 4);
    Fork {
        store,
        roots: [
            anchor.tree_hash_root(),
            root_of(&a),
            root_of(&b),
            root_of(&c),
        ],
        b: root_of(&b),
        c: root_of(&c),
    }
}

/// The weight of every node of the store.
fn all_weights(f: &Fork) -> Vec<(ForkChoiceNode, Gwei)> {
    let statuses = [
        PayloadStatus::Pending,
        PayloadStatus::Empty,
        PayloadStatus::Full,
    ];
    f.roots
        .iter()
        .flat_map(|root| statuses.map(|status| node(*root, status)))
        .map(|n| (n, get_weight(&f.store, &n).unwrap()))
        .collect()
}

#[test]
fn slashed_weight_removed() {
    // Positions 0 and 1 of committee 0 of slot 3 vote for `b`, position 2 for `c`. The member
    // at position 0 equivocates: a second vote of the same target epoch for `c`. The member at
    // position 3 is in both attestations of the slashing too, but has not voted yet.
    let mut slashed = fork();
    let mut honest = fork();
    let (b, c) = (slashed.b, slashed.c);
    let for_b = Vote::new(&slashed.store, 3, b, 0).positions(&[0, 1]);
    let for_c = Vote::new(&slashed.store, 3, c, 2);
    gossip(&mut slashed.store, &for_b).unwrap();
    gossip(&mut slashed.store, &for_c).unwrap();
    // The honest store has the same votes without the equivocator.
    let honest_for_b = Vote::new(&honest.store, 3, b, 1);
    gossip(&mut honest.store, &honest_for_b).unwrap();
    gossip(&mut honest.store, &for_c).unwrap();
    assert_eq!(get_weight(&slashed.store, &pending(b)), Ok(2 * BALANCE));
    assert_ne!(all_weights(&slashed), all_weights(&honest));

    let attesters = Vote::new(&slashed.store, 3, b, 0)
        .positions(&[0, 1, 2, 3])
        .attesters(&slashed.store);
    let slashing = AttesterSlashing {
        attestation_1: Vote::new(&slashed.store, 3, b, 0)
            .positions(&[0, 1, 3])
            .indexed(&slashed.store),
        attestation_2: Vote::new(&slashed.store, 3, c, 0)
            .positions(&[0, 2, 3])
            .indexed(&slashed.store),
    };
    let provider = plain();
    on_attester_slashing(&mut slashed.store, &provider, &slashing).unwrap();
    // Both attestations are checked against the state of the justified block (slot 0).
    assert_eq!(*provider.checked.borrow(), [0, 0]);
    // Only the validators of both attestations equivocate.
    let mut equivocators = vec![attesters[0], attesters[3]];
    equivocators.sort_unstable();
    assert_eq!(
        slashed
            .store
            .equivocating_indices()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        equivocators
    );
    // The weight of the equivocator is gone from every node: each node has the weight of the
    // store without its vote.
    assert_eq!(all_weights(&slashed), all_weights(&honest));
    assert_eq!(get_weight(&slashed.store, &pending(b)), Ok(BALANCE));
    assert_eq!(get_head(&slashed.store), get_head(&honest.store));

    // A vote of an equivocator sets no message and adds no weight.
    let late_vote = Vote::new(&slashed.store, 3, c, 3);
    gossip(&mut slashed.store, &late_vote).unwrap();
    assert_eq!(slashed.store.latest_message(attesters[3]), None);
    assert_eq!(all_weights(&slashed), all_weights(&honest));
}

#[test]
fn attester_slashing_must_be_slashable_and_signed() {
    let mut f = fork();
    let vote = Vote::new(&f.store, 3, f.b, 0).positions(&[0, 1]);
    let before = f.store.clone();
    // The same data twice is not a double vote or a surround vote.
    let same = AttesterSlashing {
        attestation_1: vote.indexed(&f.store),
        attestation_2: vote.indexed(&f.store),
    };
    assert_eq!(
        on_attester_slashing(&mut f.store, &plain(), &same),
        Err(Error::InvalidAttestation(AttestationError::NotSlashable))
    );
    let other = Vote::new(&f.store, 3, f.c, 0).positions(&[0, 1]);
    let bad = other.signature(BAD_SIGNATURE);
    for (attestation_1, attestation_2) in [
        (vote.indexed(&f.store), bad.indexed(&f.store)),
        (bad.indexed(&f.store), vote.indexed(&f.store)),
    ] {
        let slashing = AttesterSlashing {
            attestation_1,
            attestation_2,
        };
        assert_eq!(
            on_attester_slashing(&mut f.store, &plain(), &slashing),
            Err(Error::InvalidAttestation(
                AttestationError::InvalidIndexedAttestation
            ))
        );
    }
    assert_eq!(f.store, before);
}

#[test]
fn same_slot_empty_vote_is_accepted() {
    let mut f = one_block(3);
    let a = f.root();
    let vote = Vote::new(&f.store, 1, a, 0);
    let validator = vote.attesters(&f.store)[0];
    assert_eq!(gossip(&mut f.store, &vote), Ok(()));
    let message = LatestMessage {
        slot: 1,
        root: a,
        payload_present: false,
    };
    assert_eq!(f.store.latest_message(validator), Some(&message));
    // A vote of the slot of its block supports the PENDING node only.
    assert_eq!(get_weight(&f.store, &pending(a)), Ok(BALANCE));
    assert_eq!(get_weight(&f.store, &empty(a)), Ok(0));
}

#[test]
fn same_slot_full_vote_is_refused_even_with_a_verified_payload() {
    let mut f = one_block(2);
    let a = f.root();
    let vote = Vote::new(&f.store, 1, a, 0).index(1);
    let before = f.store.clone();
    assert_eq!(
        gossip(&mut f.store, &vote),
        refused(AttestationError::SameSlotFullVote(a))
    );
    assert_eq!(f.store, before);
    mark_payload_verified(&mut f.store, a);
    let before = f.store.clone();
    for result in [gossip(&mut f.store, &vote), from_block(&mut f.store, &vote)] {
        assert_eq!(result, refused(AttestationError::SameSlotFullVote(a)));
    }
    assert_eq!(f.store, before);
}

#[test]
fn later_slot_full_vote_needs_a_verified_payload() {
    let mut f = one_block(3);
    let a = f.root();
    let vote = Vote::new(&f.store, 2, a, 0).index(1);
    let validator = vote.attesters(&f.store)[0];
    let before = f.store.clone();
    assert_eq!(
        gossip(&mut f.store, &vote),
        refused(AttestationError::PayloadNotVerified(a))
    );
    assert_eq!(f.store, before);
    mark_payload_verified(&mut f.store, a);
    assert_eq!(gossip(&mut f.store, &vote), Ok(()));
    let message = LatestMessage {
        slot: 2,
        root: a,
        payload_present: true,
    };
    assert_eq!(f.store.latest_message(validator), Some(&message));
    assert_eq!(get_weight(&f.store, &full(a)), Ok(BALANCE));
    assert_eq!(get_weight(&f.store, &empty(a)), Ok(0));
}

#[test]
fn index_other_than_zero_or_one_is_refused() {
    let mut f = one_block(3);
    let a = f.root();
    mark_payload_verified(&mut f.store, a);
    let before = f.store.clone();
    for index in [2, 3, u64::MAX] {
        let vote = Vote::new(&f.store, 2, a, 0).index(index);
        for result in [gossip(&mut f.store, &vote), from_block(&mut f.store, &vote)] {
            assert_eq!(result, refused(AttestationError::IndexOutOfRange(index)));
        }
    }
    assert_eq!(f.store, before);
}

#[test]
fn justifying_attestation_stores_the_target_state_for_get_head() {
    let (mut store, anchor) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor, 1, false, 1);
    let b = child(&anchor, 1, false, 2);
    for block in [&a, &b] {
        on_block(&mut store, &plain(), block).unwrap();
    }
    let ra = root_of(&a);
    // The post-state of `c` on `a` justifies epoch 1 with `a`.
    let justified = Checkpoint { epoch: 1, root: ra };
    let checkpoint = justified.clone();
    let justifying = Provider::new(move |state: &mut BeaconState<E>| {
        state.current_justified_checkpoint = checkpoint.clone();
    });
    tick(&mut store, 9);
    let c = child(&a.message, 9, false, 3);
    on_block(&mut store, &justifying, &c).unwrap();
    let rc = root_of(&c);
    tick(&mut store, 10);
    assert_eq!(store.justified_checkpoint(), &justified);
    assert_eq!(
        get_head(&store),
        Err(Error::MissingCheckpointState { epoch: 1, root: ra })
    );
    // A vote for `c` with the target `a` of epoch 1: `on_attestation` stores the state of the
    // target, which is the state of the justified checkpoint.
    let vote = Vote::new(&store, 9, rc, 0).target(1, ra);
    let attestation = vote.attestation(&store);
    let provider = plain();
    on_attestation(&mut store, &provider, &attestation, false).unwrap();
    // The signature is checked against the state of the target at the start of epoch 1.
    assert_eq!(*provider.checked.borrow(), [SLOTS_PER_EPOCH]);
    let state = store.checkpoint_state(&justified).unwrap();
    assert_eq!(state.slot, SLOTS_PER_EPOCH);
    assert_eq!(get_head(&store), Ok(empty(rc)));
    assert_eq!(get_weight(&store, &pending(rc)), Ok(BALANCE));
}

#[test]
fn attestation_must_be_of_a_past_slot() {
    let mut f = one_block(1);
    let a = f.root();
    let vote = Vote::new(&f.store, 1, a, 0);
    let before = f.store.clone();
    let too_early = refused(AttestationError::SlotNotPast {
        slot: 1,
        current: 1,
    });
    // The Gloas check is the same for a vote from the wire and a vote from a block.
    assert_eq!(gossip(&mut f.store, &vote), too_early);
    assert_eq!(from_block(&mut f.store, &vote), too_early);
    assert_eq!(f.store, before);
    // A slot that has no next slot is never in the past.
    let mut last = vote.attestation(&f.store);
    last.data.slot = u64::MAX;
    last.data.target = Checkpoint {
        epoch: u64::MAX / SLOTS_PER_EPOCH,
        root: a,
    };
    assert_eq!(
        on_attestation(&mut f.store, &plain(), &last, true),
        refused(AttestationError::SlotNotPast {
            slot: u64::MAX,
            current: 1
        })
    );
    tick(&mut f.store, 2);
    assert_eq!(gossip(&mut f.store, &vote), Ok(()));
}

#[test]
fn gossip_target_must_be_of_the_current_or_previous_epoch() {
    // At slot 16 (epoch 2), a vote of slot 1 has the target epoch 0.
    let mut f = one_block(2 * SLOTS_PER_EPOCH);
    let a = f.root();
    let vote = Vote::new(&f.store, 1, a, 0);
    let before = f.store.clone();
    assert_eq!(
        gossip(&mut f.store, &vote),
        refused(AttestationError::TargetEpochNotCurrent {
            target: 0,
            current: 2
        })
    );
    assert_eq!(f.store, before);
    // A vote from a block has no such check.
    assert_eq!(from_block(&mut f.store, &vote), Ok(()));
    // At epoch 1, epoch 0 is the previous epoch.
    let mut f = one_block(SLOTS_PER_EPOCH);
    let vote = Vote::new(&f.store, 1, f.root(), 0);
    assert_eq!(gossip(&mut f.store, &vote), Ok(()));
}

#[test]
fn target_and_block_must_be_known_and_agree() {
    let mut f = one_block(3);
    let a = f.root();
    let anchor = f.anchor.tree_hash_root();
    let unknown = Root::repeat_byte(0x99);
    let before = f.store.clone();
    let vote = Vote::new(&f.store, 2, a, 0);
    // The target epoch must be the epoch of the slot.
    let mut wrong_epoch = vote.attestation(&f.store);
    wrong_epoch.data.target.epoch = 1;
    assert_eq!(
        on_attestation(&mut f.store, &plain(), &wrong_epoch, true),
        refused(AttestationError::TargetEpochMismatch { target: 1, slot: 2 })
    );
    let mut unknown_target = vote.attestation(&f.store);
    unknown_target.data.target.root = unknown;
    assert_eq!(
        on_attestation(&mut f.store, &plain(), &unknown_target, true),
        refused(AttestationError::UnknownTarget(unknown))
    );
    let mut unknown_block = vote.attestation(&f.store);
    unknown_block.data.beacon_block_root = unknown;
    assert_eq!(
        on_attestation(&mut f.store, &plain(), &unknown_block, true),
        refused(AttestationError::UnknownBeaconBlock(unknown))
    );
    // A vote of slot 0 for the block of slot 1 is for a block of the future.
    let mut future = Vote::new(&f.store, 0, anchor, 0).attestation(&f.store);
    future.data.beacon_block_root = a;
    assert_eq!(
        on_attestation(&mut f.store, &plain(), &future, true),
        refused(AttestationError::FutureBlock { block: 1, slot: 0 })
    );
    // The target must be the checkpoint block of the voted block.
    let mut wrong_target = vote.attestation(&f.store);
    wrong_target.data.target.root = a;
    assert_eq!(
        on_attestation(&mut f.store, &plain(), &wrong_target, true),
        refused(AttestationError::TargetNotCheckpointBlock {
            target: a,
            checkpoint_block: anchor
        })
    );
    // A bad signature is refused after the store computes the state of the target.
    let bad = Vote::new(&f.store, 2, a, 0).signature(BAD_SIGNATURE);
    assert_eq!(
        gossip(&mut f.store, &bad),
        refused(AttestationError::InvalidIndexedAttestation)
    );
    assert_eq!(f.store, before);
}

#[test]
fn refused_signature_leaves_no_checkpoint_state() {
    // A vote of slot 9 for `a` has the target `a` of epoch 1, whose state the store does
    // not have yet.
    let mut f = one_block(10);
    let a = f.root();
    let target = Checkpoint { epoch: 1, root: a };
    let bad = Vote::new(&f.store, 9, a, 0)
        .target(1, a)
        .signature(BAD_SIGNATURE);
    let before = f.store.clone();
    assert_eq!(
        gossip(&mut f.store, &bad),
        refused(AttestationError::InvalidIndexedAttestation)
    );
    assert_eq!(f.store, before);
    assert!(f.store.checkpoint_state(&target).is_none());
    let good = Vote::new(&f.store, 9, a, 0).target(1, a);
    assert_eq!(gossip(&mut f.store, &good), Ok(()));
    assert!(f.store.checkpoint_state(&target).is_some());
}

#[test]
fn attesting_indices_that_the_committees_cannot_give_are_indexed_attestation_errors() {
    let mut f = one_block(SLOTS_PER_EPOCH);
    let a = f.root();
    let vote = Vote::new(&f.store, SLOTS_PER_EPOCH - 1, a, 0);
    // Fewer bits than the committee has members: the spec fails on the index of a bit.
    let mut short = vote.attestation(&f.store);
    let mut bits = ProgressiveBitList::with_capacity(1);
    bits.set(0, true).unwrap();
    short.aggregation_bits = bits;
    // The spec does not check the committee index against the committees of the slot: an
    // index past them gives a committee of a later slot. Past the last committee of the
    // epoch, the spec fails in `compute_shuffled_index`.
    let mut no_committee = vote.attestation(&f.store);
    no_committee.committee_bits = BitVector::new();
    no_committee.committee_bits.set(3, true).unwrap();
    let before = f.store.clone();
    for attestation in [short, no_committee] {
        match on_attestation(&mut f.store, &plain(), &attestation, false) {
            Err(Error::IndexedAttestation(e)) => assert!(e.proves_invalid(), "{e:?}"),
            other => panic!("got {other:?}"),
        }
    }
    assert_eq!(f.store, before);
}

#[test]
fn later_slot_replaces_the_message_and_others_do_not() {
    // At slot 16 the votes of epochs 0 and 1 come from blocks, which have no check of the
    // target epoch against the current time.
    let mut f = fork();
    tick(&mut f.store, 2 * SLOTS_PER_EPOCH);
    let (b, c) = (f.b, f.c);
    let vote = Vote::new(&f.store, 2, b, 0);
    let validator = vote.attesters(&f.store)[0];
    from_block(&mut f.store, &vote).unwrap();
    let first = LatestMessage {
        slot: 2,
        root: b,
        payload_present: false,
    };
    assert_eq!(f.store.latest_message(validator), Some(&first));
    // A vote of the same slot for another block does not replace the message.
    let same_slot = Vote::new(&f.store, 2, c, 0);
    assert_eq!(same_slot.attesters(&f.store), [validator]);
    from_block(&mut f.store, &same_slot).unwrap();
    assert_eq!(f.store.latest_message(validator), Some(&first));
    // A vote of the validator in epoch 1 replaces it.
    let target = Checkpoint { epoch: 1, root: c };
    let (slot, committee, position) = duty(&f.store, &target, validator);
    let later = Vote::new(&f.store, slot, c, position)
        .committee(committee)
        .target(1, c);
    assert_eq!(later.attesters(&f.store), [validator]);
    from_block(&mut f.store, &later).unwrap();
    let replaced = LatestMessage {
        slot,
        root: c,
        payload_present: false,
    };
    assert_eq!(f.store.latest_message(validator), Some(&replaced));
    // A vote of an earlier slot does not replace it.
    from_block(&mut f.store, &vote).unwrap();
    assert_eq!(f.store.latest_message(validator), Some(&replaced));
}

#[test]
fn target_before_the_anchor_block_is_refused() {
    // A checkpoint-sync anchor: the state of slot 16 (epoch 2) and its block of slot 13. The
    // spec walks below the anchor for the checkpoint block of epoch 1, and the store has no
    // block there.
    let (mut store, anchor) = store_at(2 * SLOTS_PER_EPOCH, 13);
    let root = anchor.tree_hash_root();
    tick(&mut store, 2 * SLOTS_PER_EPOCH + 1);
    let before = store.clone();
    let old = Vote::new(&store, 13, root, 0).target(1, root);
    // `Vote::attestation` reads the committees of epoch 1 from the anchor state.
    let attestation = old.attestation(&store);
    for is_from_block in [false, true] {
        assert_eq!(
            on_attestation(&mut store, &plain(), &attestation, is_from_block),
            refused(AttestationError::TargetBeforeAnchor {
                epoch: 1,
                anchor_slot: 13
            })
        );
    }
    assert_eq!(store, before);
    // A target of the epoch of the anchor state is at or after the anchor block.
    let vote = Vote::new(&store, 2 * SLOTS_PER_EPOCH, root, 0).target(2, root);
    assert_eq!(gossip(&mut store, &vote), Ok(()));
}
