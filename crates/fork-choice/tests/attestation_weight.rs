//! The attestation weight of fork choice: `get_attestation_score`, `get_supported_node` and the
//! equivocation term of `is_head_weak`, through the test seams `testing::set_latest_message`
//! and `testing::add_equivocating_index`, and the PTC votes that a block carries.
//!
//! The test provider does not run the state transition. The post-state of a block is the
//! parent state at the slot of the block, after an optional edit. Each validator has 32 ETH and
//! the registry has 64 validators, so one slot of the registry is 256 ETH. The proposer score is
//! 40% of that (102.4 ETH), and a head is weak below 20% of it (51.2 ETH).

use consensus_types::gloas::{
    BeaconBlock, BeaconState, Checkpoint, PayloadAttestation, PayloadAttestationData,
    SignedBeaconBlock,
};
use consensus_types::primitives::{Bytes32, Gwei, Root, Slot, ValidatorIndex};
use consensus_types::Minimal;
use fork_choice::testing::{add_equivocating_index, mark_payload_verified, set_latest_message};
use fork_choice::{
    get_forkchoice_store, get_head, get_weight, on_block, on_tick, store_target_checkpoint_state,
    Error, ForkChoiceNode, LatestMessage, PayloadStatus, StateProvider, Store,
};
use ssz::BitVector;
use state_transition::caches::CommitteeCache;
use state_transition::testing::{genesis_state, signed_block};
use state_transition::{state_root, StfError};
use std::num::NonZeroU64;
use tree_hash::TreeHash;

type E = Minimal;

const SLOT_MS: u64 = 6000;
const GENESIS_TIME: u64 = 1_700_000_000;
const VALIDATORS: usize = 64;
const BALANCE: Gwei = 32_000_000_000;
/// `PTC_SIZE` of the minimal preset.
const PTC_SIZE: usize = 16;
/// 40% of one slot of the registry: `PROPOSER_SCORE_BOOST` of 2048 ETH / 8.
const PROPOSER_SCORE: Gwei = 102_400_000_000;

fn time_at(slot: Slot) -> u64 {
    GENESIS_TIME * 1000 + slot * SLOT_MS
}

fn tick(store: &mut Store<E>, slot: Slot) {
    on_tick(store, time_at(slot)).unwrap();
}

/// A store at a genesis anchor with 64 validators of 32 ETH, and the anchor block.
fn new_store() -> (Store<E>, BeaconBlock<E>) {
    let mut state = genesis_state::<E>(&[BALANCE; VALIDATORS]);
    state.genesis_time = GENESIS_TIME;
    let mut block = signed_block::<E>(0, 0).message;
    block.state_root = state_root(&mut state).unwrap();
    let slot_duration = NonZeroU64::new(SLOT_MS).unwrap();
    let store = get_forkchoice_store(state, block.clone(), slot_duration).unwrap();
    (store, block)
}

/// The post-state is the parent state at the slot of the block, after `edit`.
/// `process_slots` only sets the slot.
struct Provider<F = fn(&mut BeaconState<E>)>(F);

impl<F: Fn(&mut BeaconState<E>)> StateProvider<E> for Provider<F> {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        state.slot = block.message.slot;
        (self.0)(state);
        Ok(())
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        state.slot = slot;
        Ok(())
    }
}

fn keep(_: &mut BeaconState<E>) {}

const PLAIN: Provider = Provider(keep);

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

/// Another block of the slot and of the proposer of `block`, with another root.
fn equivocation(block: &SignedBeaconBlock<E>) -> SignedBeaconBlock<E> {
    let mut other = block.clone();
    other.message.body.graffiti = Bytes32::repeat_byte(0x0e);
    other
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

fn vote(store: &mut Store<E>, validator: ValidatorIndex, slot: Slot, root: Root, present: bool) {
    let message = LatestMessage {
        slot,
        root,
        payload_present: present,
    };
    set_latest_message(store, validator, message);
}

/// anchor, then `a` at slot 1 with a verified payload, then `b` at slot 2 on the FULL `a` and
/// `c` at slot 2 on the EMPTY `a`. The store is at the start of slot 3.
struct Fork {
    store: Store<E>,
    anchor: Root,
    a: Root,
    b: Root,
    c: Root,
}

fn fork() -> Fork {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor_block, 1, false, 1);
    on_block(&mut store, &PLAIN, &a).unwrap();
    mark_payload_verified(&mut store, root_of(&a));
    tick(&mut store, 2);
    let b = child(&a.message, 2, true, 2);
    let c = child(&a.message, 2, false, 3);
    for block in [&b, &c] {
        on_block(&mut store, &PLAIN, block).unwrap();
    }
    tick(&mut store, 3);
    Fork {
        store,
        anchor: anchor_block.tree_hash_root(),
        a: root_of(&a),
        b: root_of(&b),
        c: root_of(&c),
    }
}

#[test]
fn latest_messages_add_weight_to_the_supported_node_and_its_ancestors() {
    let mut f = fork();
    let w = |f: &Fork, n: ForkChoiceNode| get_weight(&f.store, &n).unwrap();
    assert_eq!(get_head(&f.store), Ok(empty(f.b)));
    // A message of the slot of its block supports the PENDING node of the block.
    vote(&mut f.store, 0, 2, f.b, false);
    // A message of a later slot supports the FULL or the EMPTY node, by `payload_present`.
    vote(&mut f.store, 1, 3, f.a, true);
    vote(&mut f.store, 2, 3, f.a, false);
    assert_eq!(w(&f, pending(f.b)), BALANCE);
    assert_eq!(w(&f, pending(f.c)), 0);
    // `b` builds on the FULL `a`, so the message for `b` also supports FULL `a`.
    assert_eq!(w(&f, full(f.a)), 2 * BALANCE);
    assert_eq!(w(&f, empty(f.a)), BALANCE);
    assert_eq!(w(&f, pending(f.a)), 3 * BALANCE);
    assert_eq!(w(&f, empty(f.anchor)), 3 * BALANCE);
    assert_eq!(w(&f, full(f.anchor)), 0);
    // The nodes of `b` of the previous slot that decide its payload have no weight.
    assert_eq!(w(&f, empty(f.b)), 0);
    assert_eq!(get_head(&f.store), Ok(empty(f.b)));

    // Two messages for `c` of a later slot make EMPTY `a` the heavier node.
    vote(&mut f.store, 3, 3, f.c, false);
    vote(&mut f.store, 4, 3, f.c, false);
    assert_eq!(w(&f, empty(f.a)), 3 * BALANCE);
    assert_eq!(w(&f, pending(f.c)), 2 * BALANCE);
    assert_eq!(get_head(&f.store), Ok(empty(f.c)));

    // A new message of a validator replaces its earlier one.
    vote(&mut f.store, 3, 3, f.b, false);
    assert_eq!(w(&f, pending(f.c)), BALANCE);
    assert_eq!(w(&f, full(f.a)), 3 * BALANCE);
    assert_eq!(get_head(&f.store), Ok(empty(f.b)));
}

#[test]
fn equivocating_validators_add_no_attestation_weight() {
    let mut f = fork();
    for validator in [3, 4, 5] {
        vote(&mut f.store, validator, 3, f.c, false);
    }
    assert_eq!(get_weight(&f.store, &pending(f.c)), Ok(3 * BALANCE));
    assert_eq!(get_head(&f.store), Ok(empty(f.c)));
    add_equivocating_index(&mut f.store, 3);
    add_equivocating_index(&mut f.store, 4);
    assert_eq!(get_weight(&f.store, &pending(f.c)), Ok(BALANCE));
    // A validator outside the registry adds no weight, and is not an error.
    vote(&mut f.store, VALIDATORS as u64 + 7, 3, f.b, false);
    assert_eq!(get_weight(&f.store, &pending(f.b)), Ok(0));
    vote(&mut f.store, 6, 3, f.b, false);
    vote(&mut f.store, 7, 3, f.b, false);
    // FULL `a` (2 votes) now outweighs EMPTY `a` (1 vote that is not an equivocation).
    assert_eq!(get_head(&f.store), Ok(empty(f.b)));
}

#[test]
fn finalized_branch_wins_over_heavier_votes_and_refuses_a_block_off_it() {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor_block, 1, false, 1);
    let b = child(&anchor_block, 1, false, 2);
    for block in [&a, &b] {
        on_block(&mut store, &PLAIN, block).unwrap();
    }
    let (ra, rb) = (root_of(&a), root_of(&b));
    for validator in 0..8 {
        vote(&mut store, validator, 1, rb, false);
    }
    // Eight votes (256 ETH) outweigh the proposer boost of `a` (102.4 ETH).
    assert_eq!(get_head(&store).map(|n| n.root), Ok(rb));

    // The post-state of `c` on `a` justifies and finalizes epoch 1 with `a` as its checkpoint
    // block.
    let finalized = Checkpoint { epoch: 1, root: ra };
    let checkpoint = finalized.clone();
    let finalizing = Provider(move |state: &mut BeaconState<E>| {
        state.current_justified_checkpoint = checkpoint.clone();
        state.finalized_checkpoint = checkpoint.clone();
    });
    tick(&mut store, 9);
    let c = child(&a.message, 9, false, 3);
    on_block(&mut store, &finalizing, &c).unwrap();
    let rc = root_of(&c);
    assert_eq!(store.finalized_checkpoint(), &finalized);
    assert_eq!(store.justified_checkpoint(), &finalized);
    // `get_head` reads the state of the justified checkpoint. On the spec path,
    // `on_attestation` stores it first.
    assert_eq!(
        get_head(&store),
        Err(Error::MissingCheckpointState { epoch: 1, root: ra })
    );
    store_target_checkpoint_state(&mut store, &PLAIN, &finalized).unwrap();

    // `b` keeps more weight than `c`, but the head must descend from the finalized block.
    let weight_b = get_weight(&store, &pending(rb)).unwrap();
    let weight_c = get_weight(&store, &pending(rc)).unwrap();
    assert_eq!((weight_b, weight_c), (8 * BALANCE, PROPOSER_SCORE));
    assert_eq!(get_head(&store), Ok(empty(rc)));

    // A block on `b` does not descend from the finalized checkpoint. on_block must refuse it
    // and keep the store.
    tick(&mut store, 10);
    let d = child(&b.message, 10, false, 4);
    assert_eq!(
        on_block(&mut store, &PLAIN, &d),
        Err(Error::NotFinalizedDescendant {
            finalized: ra,
            checkpoint_block: rb,
        })
    );
    assert_eq!(store.block(root_of(&d)), None);
    assert_eq!(get_head(&store), Ok(empty(rc)));
}

/// The proposer of the parent block of the boost scenarios.
const PROPOSER: u8 = 5;

/// The parent `p` of slot 1 by [`PROPOSER`], and its timely child `c` at the start of slot 2,
/// which gets the proposer boost. With `equivocate`, the store also has `q`: a block of slot
/// 1 by the same proposer, timely for the PTC deadline (an early equivocation).
struct Boost {
    store: Store<E>,
    p: Root,
    c: Root,
}

fn boost(equivocate: bool) -> Boost {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let p = child(&anchor_block, 1, false, PROPOSER);
    on_block(&mut store, &PLAIN, &p).unwrap();
    if equivocate {
        let q = equivocation(&p);
        assert_ne!(root_of(&q), root_of(&p));
        on_block(&mut store, &PLAIN, &q).unwrap();
        assert_eq!(store.block_timeliness(root_of(&q)), Some([true, true]));
    }
    tick(&mut store, 2);
    let c = child(&p.message, 2, false, PROPOSER + 1);
    on_block(&mut store, &PLAIN, &c).unwrap();
    assert_eq!(store.proposer_boost_root(), root_of(&c));
    Boost {
        store,
        p: root_of(&p),
        c: root_of(&c),
    }
}

/// The beacon committee of `slot` (one committee for each slot of 64 validators) from the
/// state of `root`.
fn committee(store: &Store<E>, root: Root, slot: Slot) -> Vec<ValidatorIndex> {
    let state = store.block_state(root).unwrap();
    let cache = CommitteeCache::new(state, 0).unwrap();
    assert_eq!(cache.committees_per_slot(), 1);
    cache.committee(slot, 0).unwrap().to_vec()
}

#[test]
fn proposer_boost_is_withheld_when_a_weak_parent_has_an_early_equivocation() {
    let honest = boost(false);
    assert_eq!(
        get_weight(&honest.store, &pending(honest.c)),
        Ok(PROPOSER_SCORE)
    );
    let b = boost(true);
    // The parent has no votes, so it is weak, and its proposer equivocated in time for the
    // PTC deadline. The boost must not apply.
    assert_eq!(get_weight(&b.store, &pending(b.c)), Ok(0));
    assert_eq!(get_weight(&b.store, &pending(b.p)), Ok(0));
}

#[test]
fn votes_for_the_parent_make_it_strong_and_the_boost_applies() {
    let mut b = boost(true);
    // One vote (32 ETH) is below the threshold of a weak head (51.2 ETH).
    vote(&mut b.store, 0, 1, b.p, false);
    assert_eq!(get_weight(&b.store, &pending(b.c)), Ok(0));
    vote(&mut b.store, 1, 1, b.p, false);
    assert_eq!(get_weight(&b.store, &pending(b.c)), Ok(PROPOSER_SCORE));
    assert_eq!(
        get_weight(&b.store, &pending(b.p)),
        Ok(2 * BALANCE + PROPOSER_SCORE)
    );
    assert_eq!(get_head(&b.store), Ok(empty(b.c)));
}

#[test]
fn equivocators_of_the_parent_slot_committee_make_the_parent_strong() {
    let mut b = boost(true);
    let parent_committee = committee(&b.store, b.p, 1);
    let other_committee = committee(&b.store, b.p, 2);
    // Equivocators outside the committee of the parent slot do not count.
    for &validator in &other_committee[..2] {
        add_equivocating_index(&mut b.store, validator);
    }
    assert_eq!(get_weight(&b.store, &pending(b.c)), Ok(0));
    // Two equivocators of the parent slot (64 ETH) make the parent strong. Their votes for
    // the parent do not count in its attestation score, but the equivocation term of
    // `is_head_weak` adds their balance.
    for &validator in &parent_committee[..2] {
        vote(&mut b.store, validator, 1, b.p, false);
        add_equivocating_index(&mut b.store, validator);
    }
    assert_eq!(get_weight(&b.store, &pending(b.c)), Ok(PROPOSER_SCORE));
    assert_eq!(get_weight(&b.store, &pending(b.p)), Ok(PROPOSER_SCORE));
}

/// A payload attestation of every PTC member for the block `root` of `slot`.
fn payload_attestation(root: Root, slot: Slot, present: bool) -> PayloadAttestation<E> {
    let mut aggregation_bits = BitVector::new();
    for position in 0..PTC_SIZE {
        aggregation_bits.set(position, true).unwrap();
    }
    PayloadAttestation {
        aggregation_bits,
        data: PayloadAttestationData {
            beacon_block_root: root,
            slot,
            payload_present: present,
            blob_data_available: present,
        },
        signature: [0; 96],
    }
}

#[test]
fn ptc_votes_in_a_block_decide_the_payload_of_its_parent() {
    for present in [true, false] {
        let (mut store, anchor_block) = new_store();
        tick(&mut store, 1);
        let p = child(&anchor_block, 1, false, 1);
        on_block(&mut store, &PLAIN, &p).unwrap();
        let rp = root_of(&p);
        mark_payload_verified(&mut store, rp);
        tick(&mut store, 2);
        let mut c = child(&p.message, 2, false, 2);
        c.message
            .body
            .payload_attestations
            .push(payload_attestation(rp, 1, present))
            .unwrap();
        on_block(&mut store, &PLAIN, &c).unwrap();
        let rc = root_of(&c);
        let votes = [Some(present); PTC_SIZE];
        assert_eq!(store.payload_timeliness_vote(rp), Some(&votes[..]));
        assert_eq!(store.payload_data_availability_vote(rp), Some(&votes[..]));
        assert_eq!(
            store.payload_timeliness_vote(rc),
            Some(&[None; PTC_SIZE][..])
        );
        // Both payload nodes of `p` are of the previous slot and have no weight, so the
        // payload tiebreaker decides: FULL if the PTC saw the payload, else the EMPTY branch
        // of the boosted `c`.
        let want = if present { full(rp) } else { empty(rc) };
        assert_eq!(get_head(&store), Ok(want), "payload present: {present}");
    }
}
