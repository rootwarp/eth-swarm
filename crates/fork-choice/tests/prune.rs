//! The store drops the blocks below and beside the finalized checkpoint block once finality
//! moves, at the next `on_tick`. The tests compare the store just before that tick with the
//! store after it, at the same time: the justified and the finalized checkpoints are the same,
//! so `get_head` and `get_weight` must give the same result.
//!
//! The test provider does not run the state transition. The post-state of a block is the
//! parent state at the slot of the block, after an optional edit. It accepts every signature.
//! Each validator has 32 ETH and the registry has 64 validators, so the proposer score is
//! 102.4 ETH, and a head is weak below 51.2 ETH. The minimal preset has two committees of four
//! for each slot.

use consensus_types::common::AttestationData;
use consensus_types::gloas::{
    Attestation, BeaconBlock, BeaconState, Checkpoint, SignedBeaconBlock,
};
use consensus_types::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex};
use consensus_types::Minimal;
use fork_choice::testing::{add_equivocating_index, mark_payload_verified, set_latest_message};
use fork_choice::{
    get_ancestor, get_filtered_node_tree, get_forkchoice_store, get_head, get_weight,
    is_payload_verified, is_valid_dependent_root, on_attestation, on_block, on_tick,
    store_target_checkpoint_state, AttestationError, Error, ForkChoiceNode, LatestMessage,
    PayloadStatus, SignatureVerifier, StateProvider, Store,
};
use ssz::{BitVector, ProgressiveBitList};
use state_transition::caches::CommitteeCache;
use state_transition::testing::{genesis_state, signed_block};
use state_transition::{state_root, BackendError, SignatureSet, StfError};
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use tree_hash::TreeHash;

type E = Minimal;

const SLOT_MS: u64 = 6000;
const GENESIS_TIME: u64 = 1_700_000_000;
const VALIDATORS: usize = 64;
const BALANCE: Gwei = 32_000_000_000;
/// 40% of one slot of the registry: `PROPOSER_SCORE_BOOST` of 2048 ETH / 8.
const PROPOSER_SCORE: Gwei = 102_400_000_000;
/// `SLOTS_PER_EPOCH` of the minimal preset.
const SLOTS_PER_EPOCH: Slot = 8;

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

impl<F> SignatureVerifier<E> for Provider<F> {
    fn verify_signature_sets(
        &self,
        _: &BeaconState<E>,
        _: &[SignatureSet],
    ) -> Result<bool, BackendError> {
        Ok(true)
    }
}

fn keep(_: &mut BeaconState<E>) {}

const PLAIN: Provider = Provider(keep);

/// A provider whose post-state justifies and finalizes `checkpoint`.
fn finalizing(checkpoint: Checkpoint) -> Provider<impl Fn(&mut BeaconState<E>)> {
    Provider(move |state: &mut BeaconState<E>| {
        state.current_justified_checkpoint = checkpoint.clone();
        state.finalized_checkpoint = checkpoint.clone();
    })
}

/// A provider whose post-state justifies `checkpoint`.
fn justifying(checkpoint: Checkpoint) -> Provider<impl Fn(&mut BeaconState<E>)> {
    Provider(move |state: &mut BeaconState<E>| {
        state.current_justified_checkpoint = checkpoint.clone();
    })
}

/// A block at `slot` on the EMPTY `parent` by proposer `tag`.
fn child(parent: &BeaconBlock<E>, slot: Slot, tag: u8) -> SignedBeaconBlock<E> {
    let mut block = signed_block::<E>(slot, u64::from(tag));
    block.message.parent_root = parent.tree_hash_root();
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.parent_block_hash = Root::repeat_byte(0xee);
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

fn pending(root: Root) -> ForkChoiceNode {
    ForkChoiceNode {
        root,
        payload_status: PayloadStatus::Pending,
    }
}

fn empty(root: Root) -> ForkChoiceNode {
    ForkChoiceNode {
        root,
        payload_status: PayloadStatus::Empty,
    }
}

fn full(root: Root) -> ForkChoiceNode {
    ForkChoiceNode {
        root,
        payload_status: PayloadStatus::Full,
    }
}

fn vote(store: &mut Store<E>, validator: ValidatorIndex, slot: Slot, root: Root) {
    let message = LatestMessage {
        slot,
        root,
        payload_present: false,
    };
    set_latest_message(store, validator, message);
}

/// The anchor, `a` and `b` at slot 1 on the anchor, `x` at slot 9 on `b`, `c` at slot 9 on
/// `a`, and `d` on `c` and `e` on `a` at slot 10. The post-state of `c` justifies and finalizes
/// epoch 1 with `a`. The store is at the start of slot 10, and it has not had a tick since
/// finality moved.
struct Finalized {
    store: Store<E>,
    anchor: Root,
    a: Root,
    b: Root,
    x: Root,
    c: Root,
    d: Root,
    e: Root,
}

fn finalized() -> Finalized {
    finalized_layout(false)
}

/// The layout of [`finalized`], but the post-state of `e` justifies epoch 1 with `a`, as the
/// post-state of `c` does. Then the voting source of `e` has the epoch of the justified
/// checkpoint of the store, and `e` stays a viable leaf after epoch 2.
fn finalized_with_justified_e() -> Finalized {
    finalized_layout(true)
}

fn finalized_layout(justified_e: bool) -> Finalized {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor_block, 1, 1);
    let b = child(&anchor_block, 1, 2);
    for block in [&a, &b] {
        on_block(&mut store, &PLAIN, block).unwrap();
    }
    tick(&mut store, 10);
    let x = child(&b.message, 9, 6);
    on_block(&mut store, &PLAIN, &x).unwrap();
    let checkpoint = Checkpoint {
        epoch: 1,
        root: root_of(&a),
    };
    let c = child(&a.message, 9, 3);
    on_block(&mut store, &finalizing(checkpoint.clone()), &c).unwrap();
    assert_eq!(store.finalized_checkpoint(), &checkpoint);
    assert_eq!(store.justified_checkpoint(), &checkpoint);
    // On the spec path, `on_attestation` stores the state of the justified checkpoint.
    store_target_checkpoint_state(&mut store, &PLAIN, &checkpoint).unwrap();
    let d = child(&c.message, 10, 4);
    let e = child(&a.message, 10, 5);
    on_block(&mut store, &PLAIN, &d).unwrap();
    if justified_e {
        on_block(&mut store, &justifying(checkpoint), &e).unwrap();
    } else {
        on_block(&mut store, &PLAIN, &e).unwrap();
    }
    Finalized {
        store,
        anchor: anchor_block.tree_hash_root(),
        a: root_of(&a),
        b: root_of(&b),
        x: root_of(&x),
        c: root_of(&c),
        d: root_of(&d),
        e: root_of(&e),
    }
}

/// The head, and the weight of each node of the filtered tree.
fn head_and_weights(store: &Store<E>) -> (ForkChoiceNode, BTreeMap<String, Gwei>) {
    let head = get_head(store).unwrap();
    let weights = get_filtered_node_tree(store)
        .unwrap()
        .into_iter()
        .map(|node| (format!("{node:?}"), get_weight(store, &node).unwrap()))
        .collect();
    (head, weights)
}

#[test]
fn a_tick_after_finality_drops_the_blocks_below_and_beside_the_finalized_block() {
    let mut f = finalized();
    let genesis = Checkpoint {
        epoch: 0,
        root: f.anchor,
    };
    for root in [f.anchor, f.b, f.x] {
        assert!(f.store.block(root).is_some());
    }
    assert!(f.store.checkpoint_state(&genesis).is_some());
    // A tick in the same slot keeps the time, and the store prunes.
    let time = f.store.time_ms();
    on_tick(&mut f.store, time).unwrap();
    assert_eq!(f.store.time_ms(), time);
    for root in [f.anchor, f.b, f.x] {
        assert!(f.store.block(root).is_none());
        assert!(f.store.block_state(root).is_none());
        assert_eq!(f.store.block_timeliness(root), None);
        assert_eq!(f.store.payload_timeliness_vote(root), None);
        assert_eq!(f.store.payload_data_availability_vote(root), None);
    }
    assert!(f.store.checkpoint_state(&genesis).is_none());
    for root in [f.a, f.c, f.d, f.e] {
        assert!(f.store.block(root).is_some());
        assert!(f.store.block_state(root).is_some());
    }
    assert!(f
        .store
        .checkpoint_state(f.store.justified_checkpoint())
        .is_some());
    // The finalized block is the new anchor: the ancestor walk stops there.
    assert_eq!(get_ancestor(&f.store, pending(f.d), 0), Ok(empty(f.a)));
}

#[test]
fn get_head_after_the_prune_matches_the_store_before_it() {
    let mut f = finalized();
    // Messages for blocks that the prune drops, and for blocks that it keeps.
    for validator in 0..3 {
        vote(&mut f.store, validator, 1, f.b);
    }
    vote(&mut f.store, 3, 9, f.x);
    vote(&mut f.store, 4, 9, f.x);
    vote(&mut f.store, 5, 0, f.anchor);
    vote(&mut f.store, 6, 10, f.d);
    vote(&mut f.store, 7, 10, f.e);
    vote(&mut f.store, 8, 10, f.e);
    vote(&mut f.store, 9, 9, f.a);
    add_equivocating_index(&mut f.store, 7);
    assert_eq!(f.store.proposer_boost_root(), f.d);
    let before = head_and_weights(&f.store);
    // `c` has one vote and the boost of `d`, `e` has one vote that is not an equivocation.
    assert_eq!(before.0, empty(f.d));
    assert_eq!(
        get_weight(&f.store, &pending(f.c)),
        Ok(BALANCE + PROPOSER_SCORE)
    );
    assert_eq!(get_weight(&f.store, &pending(f.e)), Ok(BALANCE));

    let time = f.store.time_ms();
    on_tick(&mut f.store, time).unwrap();
    assert!(f.store.block(f.b).is_none());
    assert_eq!(head_and_weights(&f.store), before);
    assert_eq!(f.store.proposer_boost_root(), f.d);
}

#[test]
fn a_block_on_a_dropped_branch_is_refused_and_keeps_the_store() {
    let mut f = finalized();
    tick(&mut f.store, 11);
    assert!(f.store.block(f.x).is_none());
    let (_, anchor_block) = new_store();
    for parent in [f.x, f.anchor] {
        let mut block = child(&anchor_block, 11, 7);
        block.message.parent_root = parent;
        assert_eq!(
            on_block(&mut f.store, &PLAIN, &block),
            Err(Error::UnknownParent(parent))
        );
        assert!(f.store.block(root_of(&block)).is_none());
    }
    assert_eq!(get_head(&f.store), Ok(empty(f.d)));
}

/// The blocks `b` and `x` of [`finalized`]. The prune drops them.
fn dropped_branch() -> [SignedBeaconBlock<E>; 2] {
    let (_, anchor_block) = new_store();
    let b = child(&anchor_block, 1, 2);
    let x = child(&b.message, 9, 6);
    [b, x]
}

#[test]
fn a_dropped_block_is_a_known_block_and_keeps_the_store() {
    let mut f = finalized();
    tick(&mut f.store, 11);
    let [b, x] = dropped_branch();
    assert_eq!([root_of(&b), root_of(&x)], [f.b, f.x]);
    let before = f.store.clone();
    // The spec's store keeps every block, and `on_block` returns early for a known block.
    // The parent of each block is dropped too.
    for block in [&x, &b] {
        let root = root_of(block);
        assert!(f.store.block(root).is_none());
        assert_eq!(on_block(&mut f.store, &PLAIN, block), Ok(()));
        assert_eq!(f.store, before);
        assert!(f.store.block(root).is_none());
        assert!(f.store.block_or_dropped(root).is_some());
    }
    assert_eq!(get_head(&f.store), Ok(empty(f.d)));
    // A new block on a dropped block is not a known block.
    let new = child(&x.message, 11, 7);
    assert_eq!(
        on_block(&mut f.store, &PLAIN, &new),
        Err(Error::UnknownParent(f.x))
    );
    assert_eq!(f.store, before);
}

#[test]
fn a_forgotten_block_stays_a_known_block_and_does_not_go_back_into_the_tree() {
    let mut f = finalized();
    // The prune runs in epoch 1. The store keeps the dropped blocks through the end of epoch 3.
    tick(&mut f.store, 11);
    tick(&mut f.store, 4 * SLOTS_PER_EPOCH - 1);
    assert!(f.store.block_or_dropped(f.x).is_some());
    // The first tick of epoch 4 forgets them.
    tick(&mut f.store, 4 * SLOTS_PER_EPOCH);
    let [b, x] = dropped_branch();
    let before = f.store.clone();
    for block in [&x, &b] {
        let root = root_of(block);
        assert!(f.store.block_or_dropped(root).is_none());
        assert_eq!(on_block(&mut f.store, &PLAIN, block), Ok(()));
        assert_eq!(f.store, before);
        assert!(f.store.block_or_dropped(root).is_none());
    }
    // A new block on a forgotten block is not a known block.
    let new = child(&x.message, 4 * SLOTS_PER_EPOCH, 7);
    assert_eq!(
        on_block(&mut f.store, &PLAIN, &new),
        Err(Error::UnknownParent(f.x))
    );
    assert_eq!(f.store, before);
}

#[test]
fn a_block_that_the_store_never_had_is_not_a_known_block() {
    let mut f = finalized();
    tick(&mut f.store, 11);
    tick(&mut f.store, 4 * SLOTS_PER_EPOCH);
    assert!(f.store.block_or_dropped(f.x).is_none());
    let before = f.store.clone();
    // The parent of this block is not a block of the store.
    let unknown = Root::repeat_byte(0x5a);
    let mut orphan = child(&dropped_branch()[1].message, 4 * SLOTS_PER_EPOCH, 8);
    orphan.message.parent_root = unknown;
    assert_eq!(
        on_block(&mut f.store, &PLAIN, &orphan),
        Err(Error::UnknownParent(unknown))
    );
    assert_eq!(f.store, before);
    // A new block on a kept block goes into the tree.
    let d = f.store.block(f.d).unwrap().clone();
    let new = child(&d, 4 * SLOTS_PER_EPOCH, 8);
    assert_eq!(on_block(&mut f.store, &PLAIN, &new), Ok(()));
    assert!(f.store.block(root_of(&new)).is_some());
}

/// The proposer of the parent block of the boost scenario.
const PROPOSER: u8 = 9;

#[test]
fn a_dropped_early_equivocation_still_withholds_the_proposer_boost() {
    for equivocate in [false, true] {
        let (mut store, anchor_block) = new_store();
        tick(&mut store, 1);
        let a = child(&anchor_block, 1, 1);
        let fork = child(&anchor_block, 1, 2);
        for block in [&a, &fork] {
            on_block(&mut store, &PLAIN, block).unwrap();
        }
        tick(&mut store, 9);
        // `x` is a second block of the proposer of `p` in slot 9, timely for the PTC
        // deadline, on a branch that does not descend from `a`.
        let x = child(&fork.message, 9, PROPOSER);
        if equivocate {
            on_block(&mut store, &PLAIN, &x).unwrap();
            assert_eq!(store.block_timeliness(root_of(&x)), Some([true, true]));
        }
        let checkpoint = Checkpoint {
            epoch: 1,
            root: root_of(&a),
        };
        let p = child(&a.message, 9, PROPOSER);
        on_block(&mut store, &finalizing(checkpoint.clone()), &p).unwrap();
        store_target_checkpoint_state(&mut store, &PLAIN, &checkpoint).unwrap();
        tick(&mut store, 10);
        assert!(store.block(root_of(&fork)).is_none());
        assert!(store.block(root_of(&x)).is_none());
        let c = child(&p.message, 10, PROPOSER + 1);
        on_block(&mut store, &PLAIN, &c).unwrap();
        assert_eq!(store.proposer_boost_root(), root_of(&c));
        // The parent `p` has no votes, so it is weak. The spec's store keeps `x`, so the boost
        // must not apply when its proposer equivocated in time for the PTC deadline.
        let want = if equivocate { 0 } else { PROPOSER_SCORE };
        assert_eq!(
            get_weight(&store, &pending(root_of(&c))),
            Ok(want),
            "equivocate: {equivocate}"
        );
    }
}

#[test]
fn the_store_keeps_every_block_while_the_justified_block_is_off_the_finalized_branch() {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor_block, 1, 1);
    let b = child(&anchor_block, 1, 2);
    for block in [&a, &b] {
        on_block(&mut store, &PLAIN, block).unwrap();
    }
    tick(&mut store, 9);
    // Only a slashable majority can justify `b` after it finalizes `a`. The walks of the
    // subtree of `b` need the blocks below `a`, so the prune must wait.
    let (finalized, justified) = (
        Checkpoint {
            epoch: 1,
            root: root_of(&a),
        },
        Checkpoint {
            epoch: 1,
            root: root_of(&b),
        },
    );
    let conflicting = Provider(move |state: &mut BeaconState<E>| {
        state.current_justified_checkpoint = justified.clone();
        state.finalized_checkpoint = finalized.clone();
    });
    let c = child(&a.message, 9, 3);
    on_block(&mut store, &conflicting, &c).unwrap();
    assert_eq!(store.justified_checkpoint().root, root_of(&b));
    assert_eq!(store.finalized_checkpoint().root, root_of(&a));
    tick(&mut store, 10);
    for root in [anchor_block.tree_hash_root(), root_of(&b)] {
        assert!(store.block(root).is_some());
    }
}

#[test]
fn the_parent_of_the_new_anchor_stays_a_valid_dependent_root_after_the_prune() {
    let mut f = finalized();
    assert_eq!(is_valid_dependent_root(&f.store, f.anchor, 0), Ok(true));
    let time = f.store.time_ms();
    on_tick(&mut f.store, time).unwrap();
    assert!(f.store.block(f.anchor).is_none());
    // `a` of slot 1 is the new anchor, and it builds on the dropped genesis anchor. The spec's
    // store keeps `a` and its parent edge, so the genesis anchor stays a dependent root for
    // slot 0.
    assert_eq!(is_valid_dependent_root(&f.store, f.anchor, 0), Ok(true));
    assert_eq!(is_valid_dependent_root(&f.store, f.anchor, 1), Ok(false));
}

/// A store at the start of slot 10, with `a` and `b` of slot 1 on the anchor.
fn two_branches() -> (Store<E>, SignedBeaconBlock<E>, SignedBeaconBlock<E>) {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor_block, 1, 1);
    let b = child(&anchor_block, 1, 2);
    for block in [&a, &b] {
        on_block(&mut store, &PLAIN, block).unwrap();
    }
    tick(&mut store, 10);
    (store, a, b)
}

/// Adds `c` of slot 9 on `a`, late in slot 10, with no proposer boost. The post-state of `c`
/// justifies and finalizes epoch 1 with `a`. Then the store keeps the state of the justified
/// checkpoint, as `on_attestation` does on the spec path.
fn finalize_late(store: &mut Store<E>, a: &SignedBeaconBlock<E>) -> SignedBeaconBlock<E> {
    let checkpoint = Checkpoint {
        epoch: 1,
        root: root_of(a),
    };
    let c = child(&a.message, 9, 3);
    on_block(store, &finalizing(checkpoint.clone()), &c).unwrap();
    assert_eq!(store.finalized_checkpoint(), &checkpoint);
    store_target_checkpoint_state(store, &PLAIN, &checkpoint).unwrap();
    c
}

#[test]
fn a_same_slot_prune_keeps_the_head_when_the_boosted_block_is_on_a_dropped_branch() {
    let (mut store, a, b) = two_branches();
    // `y` is timely, so it takes the proposer boost. It is on `b`, and the finality of `a`
    // drops `b`.
    let y = child(&b.message, 10, 6);
    on_block(&mut store, &PLAIN, &y).unwrap();
    let y = root_of(&y);
    assert_eq!(store.proposer_boost_root(), y);
    let c = finalize_late(&mut store, &a);
    let c_root = root_of(&c);
    mark_payload_verified(&mut store, c_root);
    // `c` is of the previous slot, its payload is verified, and `y` does not build on `c`. So
    // should_extend_payload is true and the FULL node of `c` wins.
    assert_eq!(get_head(&store), Ok(full(c_root)));

    // A tick in the same slot keeps the boost of `y`. The spec reads `store.blocks[y]` in
    // should_extend_payload, so the prune must not make `y` unknown.
    let time = store.time_ms();
    on_tick(&mut store, time).unwrap();
    assert_eq!(store.proposer_boost_root(), y);
    assert_eq!(get_head(&store), Ok(full(c_root)), "boosted block y: {y}");
    let d = child(&c.message, 10, 4);
    assert_eq!(on_block(&mut store, &PLAIN, &d), Ok(()));
    assert!(store.block(root_of(&d)).is_some());
    assert_eq!(get_head(&store), Ok(full(c_root)));

    // The next slot clears the boost. Then the store drops the blocks beside `a`.
    tick(&mut store, 11);
    assert_eq!(store.proposer_boost_root(), Root::ZERO);
    for root in [root_of(&b), y] {
        assert!(store.block(root).is_none());
    }
    for root in [root_of(&a), c_root, root_of(&d)] {
        assert!(store.block(root).is_some());
    }
}

#[test]
fn a_same_slot_prune_keeps_the_empty_choice_of_a_boosted_child_of_the_previous_slot_block() {
    let (mut store, a, b) = two_branches();
    let c = finalize_late(&mut store, &a);
    let c_root = root_of(&c);
    // `z` is timely, so it takes the proposer boost. It builds on the EMPTY node of `c`, and
    // the payload of `c` is verified after `z`.
    let z = child(&c.message, 10, 4);
    on_block(&mut store, &PLAIN, &z).unwrap();
    let z = root_of(&z);
    assert_eq!(store.proposer_boost_root(), z);
    mark_payload_verified(&mut store, c_root);
    // `z` builds on `c`, and is_parent_node_full of `z` is false. So should_extend_payload is
    // false and the EMPTY node of `c` wins.
    assert_eq!(get_head(&store), Ok(empty(z)));

    // `z` descends from `a`, so a tick in the same slot drops the blocks beside `a`.
    let time = store.time_ms();
    on_tick(&mut store, time).unwrap();
    assert_eq!(store.proposer_boost_root(), z);
    assert!(store.block(root_of(&b)).is_none());
    assert_eq!(get_head(&store), Ok(empty(z)));
}

/// A block at `slot` on the FULL `parent` by proposer `tag`: its bid builds on the payload of
/// the bid of `parent`.
fn on_full(parent: &BeaconBlock<E>, slot: Slot, tag: u8) -> SignedBeaconBlock<E> {
    let mut block = child(parent, slot, tag);
    block
        .message
        .body
        .signed_execution_payload_bid
        .message
        .parent_block_hash = parent.body.signed_execution_payload_bid.message.block_hash;
    block
}

#[test]
fn children_of_a_full_parent_keep_their_dependent_root_boost_and_place_across_a_prune() {
    let (mut store, a, b) = two_branches();
    let ra = root_of(&a);
    mark_payload_verified(&mut store, ra);
    // `c` of slot 9 builds on the FULL node of `a`, late in slot 10, and its post-state
    // justifies and finalizes epoch 1 with `a`.
    let checkpoint = Checkpoint { epoch: 1, root: ra };
    let c = on_full(&a.message, 9, 3);
    on_block(&mut store, &finalizing(checkpoint.clone()), &c).unwrap();
    assert_eq!(store.finalized_checkpoint(), &checkpoint);
    store_target_checkpoint_state(&mut store, &PLAIN, &checkpoint).unwrap();
    // The one child of `a` builds on its FULL node, so `a` is a dependent root for slot 8.
    assert_ne!(get_head(&store).map(|n| n.root), Ok(ra));
    assert_eq!(is_valid_dependent_root(&store, ra, 8), Ok(true));

    // `d` of slot 10 on the FULL node of `a` is timely, so it takes the proposer boost. The
    // boost supports the FULL node of `a`, and not its EMPTY node.
    let d = on_full(&a.message, 10, 4);
    on_block(&mut store, &PLAIN, &d).unwrap();
    assert_eq!(store.proposer_boost_root(), root_of(&d));
    assert_eq!(get_weight(&store, &full(ra)), Ok(PROPOSER_SCORE));
    assert_eq!(get_weight(&store, &empty(ra)), Ok(0));
    assert_eq!(get_weight(&store, &pending(ra)), Ok(PROPOSER_SCORE));

    // A tick in the same slot drops `b`, beside `a`, and keeps the children of the FULL node
    // of `a`, with the same head and weights.
    let before = head_and_weights(&store);
    let time = store.time_ms();
    on_tick(&mut store, time).unwrap();
    assert!(store.block(root_of(&b)).is_none());
    for root in [ra, root_of(&c), root_of(&d)] {
        assert!(store.block(root).is_some(), "{root}");
    }
    assert_eq!(head_and_weights(&store), before);
    assert_eq!(get_weight(&store, &empty(ra)), Ok(0));
    assert_eq!(is_valid_dependent_root(&store, ra, 8), Ok(true));
}

/// The committee `index` of `slot`, from the state of `target` at the first slot of the target
/// epoch, as `on_attestation` reads it. The store must still have the target block.
fn committee(store: &Store<E>, target: &Checkpoint, slot: Slot, index: u64) -> Vec<ValidatorIndex> {
    let mut state = store.block_state(target.root).unwrap().clone();
    state.slot = state.slot.max(target.epoch * SLOTS_PER_EPOCH);
    let cache = CommitteeCache::new(&state, target.epoch).unwrap();
    cache.committee(slot, index).unwrap().to_vec()
}

/// An attestation of committee 0 of `slot` with index 0 (an EMPTY vote) for `root` and
/// `target`, by the members at `positions`. The store must still have the target block.
fn attestation(
    store: &Store<E>,
    slot: Slot,
    root: Root,
    target: &Checkpoint,
    positions: &[usize],
) -> Attestation<E> {
    let size = committee(store, target, slot, 0).len();
    let mut aggregation_bits = ProgressiveBitList::with_capacity(size);
    for &position in positions {
        aggregation_bits.set(position, true).unwrap();
    }
    let mut committee_bits = BitVector::new();
    committee_bits.set(0, true).unwrap();
    Attestation {
        aggregation_bits,
        data: AttestationData {
            slot,
            index: 0,
            beacon_block_root: root,
            source: store.justified_checkpoint().clone(),
            target: target.clone(),
        },
        signature: [0x22; 96],
        committee_bits,
    }
}

/// The first two members of committee 0 of `slot` for `target`, and one validator that is
/// not one of them.
fn attesters_and_other(
    store: &Store<E>,
    target: &Checkpoint,
    slot: Slot,
) -> ([ValidatorIndex; 2], ValidatorIndex) {
    let members = committee(store, target, slot, 0);
    let attesters = [members[0], members[1]];
    let other = (0..VALIDATORS as ValidatorIndex)
        .find(|v| !attesters.contains(v))
        .unwrap();
    (attesters, other)
}

#[test]
fn a_vote_for_a_dropped_branch_after_the_prune_takes_the_weight_of_its_attesters_off_the_kept_tree()
{
    let mut f = finalized();
    // Two members of committee 0 of slot 9 vote for `e` and one other validator votes for
    // `d`, all at slot 8. Then the two members vote for `x` at slot 9. The checkpoint block of
    // `x` in epoch 1 is `b`.
    let target = Checkpoint {
        epoch: 1,
        root: f.b,
    };
    let (attesters, other) = attesters_and_other(&f.store, &target, 9);
    for validator in attesters {
        vote(&mut f.store, validator, 8, f.e);
    }
    vote(&mut f.store, other, 8, f.d);
    let attestation = attestation(&f.store, 9, f.x, &target, &[0, 1]);

    // The store before the prune tick takes the vote.
    let mut before = f.store.clone();
    assert_eq!(
        on_attestation(&mut before, &PLAIN, &attestation, false),
        Ok(())
    );
    tick(&mut before, 11);

    // The tick of slot 11 drops `b` and `x`. Then `e` has two votes and `c` has one.
    tick(&mut f.store, 11);
    for root in [f.anchor, f.b, f.x] {
        assert!(f.store.block(root).is_none());
    }
    assert_eq!(get_head(&f.store), Ok(empty(f.e)));

    // The spec's store keeps `b` and `x`, so the vote passes every check. It moves the two
    // members to `x`, which supports no kept node, and `d` becomes the head.
    let result = on_attestation(&mut f.store, &PLAIN, &attestation, false);
    assert_eq!(
        (result, get_head(&f.store)),
        (Ok(()), Ok(empty(f.d))),
        "d: {}, e: {}",
        f.d,
        f.e
    );
    let message = LatestMessage {
        slot: 9,
        root: f.x,
        payload_present: false,
    };
    for validator in attesters {
        assert_eq!(f.store.latest_message(validator), Some(&message));
    }
    // The justified block `a` is the root of the filtered tree: it has the vote for `d` only.
    assert_eq!(get_weight(&f.store, &pending(f.a)), Ok(BALANCE));
    assert_eq!(get_weight(&f.store, &pending(f.e)), Ok(0));
    // The vote before the prune and the vote after it must give the same head and weights.
    assert_eq!(head_and_weights(&f.store), head_and_weights(&before));
}

#[test]
fn a_previous_epoch_target_below_the_new_anchor_is_taken_after_the_prune() {
    let mut f = finalized();
    // At slot 11 epoch 0 is the previous epoch. The checkpoint block of `a` in epoch 0 is the
    // genesis anchor, which the prune drops.
    let target = Checkpoint {
        epoch: 0,
        root: f.anchor,
    };
    let (attesters, other) = attesters_and_other(&f.store, &target, 7);
    for validator in attesters {
        vote(&mut f.store, validator, 6, f.e);
    }
    vote(&mut f.store, other, 6, f.d);
    let attestation = attestation(&f.store, 7, f.a, &target, &[0, 1]);

    let mut before = f.store.clone();
    assert_eq!(
        on_attestation(&mut before, &PLAIN, &attestation, false),
        Ok(())
    );
    tick(&mut before, 11);

    tick(&mut f.store, 11);
    assert!(f.store.block(f.anchor).is_none());
    assert_eq!(get_head(&f.store), Ok(empty(f.e)));

    // The two members move to the EMPTY node of `a`, below `c` and `e`.
    let result = on_attestation(&mut f.store, &PLAIN, &attestation, false);
    assert_eq!(
        (result, get_head(&f.store)),
        (Ok(()), Ok(empty(f.d))),
        "d: {}, e: {}",
        f.d,
        f.e
    );
    let message = LatestMessage {
        slot: 7,
        root: f.a,
        payload_present: false,
    };
    for validator in attesters {
        assert_eq!(f.store.latest_message(validator), Some(&message));
    }
    assert_eq!(get_weight(&f.store, &empty(f.a)), Ok(3 * BALANCE));
    assert_eq!(get_weight(&f.store, &pending(f.e)), Ok(0));
    assert_eq!(head_and_weights(&f.store), head_and_weights(&before));
}

#[test]
fn a_previous_epoch_vote_from_the_wire_for_a_dropped_block_moves_the_head_two_epochs_after_the_prune(
) {
    let mut f = finalized_with_justified_e();
    // `x` of slot 9 is its own checkpoint block in epoch 2. Two members of committee 0 of slot
    // 16 vote for `x` with the target `(2, x)`. The test makes the vote while the store has
    // the state of `x`.
    let slot = 2 * SLOTS_PER_EPOCH;
    let target = Checkpoint {
        epoch: 2,
        root: f.x,
    };
    let (attesters, other) = attesters_and_other(&f.store, &target, slot);
    let attestation = attestation(&f.store, slot, f.x, &target, &[0, 1]);
    // The two members have older messages for `e`, and one other validator has an older
    // message for `d`, all of slot 8.
    for validator in attesters {
        vote(&mut f.store, validator, 8, f.e);
    }
    vote(&mut f.store, other, 8, f.d);

    // The tick of slot 11 in epoch 1 drops `b` and `x`. Then `e` has two votes and `c` has one.
    tick(&mut f.store, 11);
    assert!(f.store.block(f.x).is_none());

    // At slot 17 the target epoch 2 is the current epoch. The vote moves the two members to
    // `x`, which supports no kept node, and `d` must become the head.
    let mut early = f.store.clone();
    tick(&mut early, slot + 1);
    assert_eq!(get_head(&early), Ok(empty(f.e)));
    assert_eq!(
        on_attestation(&mut early, &PLAIN, &attestation, false),
        Ok(())
    );
    assert_eq!(get_head(&early), Ok(empty(f.d)));

    // At slot 24, the first slot of epoch 3, the target epoch 2 is the previous epoch, so the
    // vote can still come from the wire. Its target is the dropped block `x`. The spec's store
    // keeps `x` and takes the vote. This store must take the vote too, and `d` must be the
    // head, as in the store that took the vote at slot 17.
    let mut late = f.store.clone();
    tick(&mut late, 3 * SLOTS_PER_EPOCH);
    tick(&mut early, 3 * SLOTS_PER_EPOCH);
    assert_eq!(get_head(&early), Ok(empty(f.d)));
    // The post-state of `e` justifies epoch 1, so `e` is a viable leaf in epoch 3 and its two
    // votes make it the head before the vote.
    assert_eq!(get_head(&late), Ok(empty(f.e)));
    let result = on_attestation(&mut late, &PLAIN, &attestation, false);
    assert_eq!(
        (result, get_head(&late)),
        (Ok(()), Ok(empty(f.d))),
        "d: {}, e: {}",
        f.d,
        f.e
    );
    let message = LatestMessage {
        slot,
        root: f.x,
        payload_present: false,
    };
    for validator in attesters {
        assert_eq!(late.latest_message(validator), Some(&message));
    }
    assert_eq!(get_weight(&late, &pending(f.e)), Ok(0));
    assert_eq!(head_and_weights(&late), head_and_weights(&early));
}

#[test]
fn the_store_keeps_a_dropped_block_for_attestations_until_the_end_of_the_second_epoch_after_the_prune(
) {
    let mut f = finalized();
    let target = Checkpoint {
        epoch: 1,
        root: f.b,
    };
    let attestation = attestation(&f.store, 9, f.x, &target, &[0]);
    // The prune runs in epoch 1. In epoch 2 a vote from the wire with the target epoch 1 is
    // of the previous epoch, and the store must take it.
    tick(&mut f.store, 11);
    tick(&mut f.store, 2 * SLOTS_PER_EPOCH);
    assert!(f.store.block(f.x).is_none());
    assert_eq!(
        on_attestation(&mut f.store, &PLAIN, &attestation, false),
        Ok(())
    );
    assert!(f.store.checkpoint_state(&target).is_some());
    // The store keeps the dropped blocks, their states and their checkpoint states through
    // the end of epoch 3. At the first and at the last slot of epoch 3 the store must still
    // have the checkpoint state, and it must take the vote from a block.
    for slot in [3 * SLOTS_PER_EPOCH, 4 * SLOTS_PER_EPOCH - 1] {
        tick(&mut f.store, slot);
        let kept = f.store.checkpoint_state(&target).is_some();
        let result = on_attestation(&mut f.store, &PLAIN, &attestation, true);
        assert_eq!((kept, result), (true, Ok(())), "slot {slot}");
    }
    // The first tick of epoch 4 forgets the dropped blocks, their states and their checkpoint
    // states. The spec's store keeps every block, and it takes this vote from a block.
    tick(&mut f.store, 4 * SLOTS_PER_EPOCH);
    assert!(f.store.checkpoint_state(&target).is_none());
    assert_eq!(
        on_attestation(&mut f.store, &PLAIN, &attestation, true),
        Err(Error::InvalidAttestation(AttestationError::UnknownTarget(
            f.b
        )))
    );
}

/// Gives the two `attesters` older messages for `d2` and `other` an older message for `d`, all
/// of slot 12.
fn older_messages(
    store: &mut Store<E>,
    (attesters, other): ([ValidatorIndex; 2], ValidatorIndex),
    d2: Root,
    d: Root,
) {
    for validator in attesters {
        vote(store, validator, 12, d2);
    }
    vote(store, other, 12, d);
}

/// A vote of committee 0 of the first slot of `epoch` for `x`, with the target `x` in that
/// epoch, by its first two members. Also gives the two members and one other validator. The
/// store must still have the state of `x`.
fn vote_for_x(
    store: &Store<E>,
    x: Root,
    epoch: Epoch,
) -> (([ValidatorIndex; 2], ValidatorIndex), Attestation<E>) {
    let target = Checkpoint { epoch, root: x };
    let slot = epoch * SLOTS_PER_EPOCH;
    let voters = attesters_and_other(store, &target, slot);
    (voters, attestation(store, slot, x, &target, &[0, 1]))
}

#[test]
fn after_the_window_a_refused_block_vote_for_a_forgotten_block_keeps_the_head_that_the_spec_moves()
{
    let mut f = finalized();
    // Each vote is for `x` of slot 9 at the first slot of its epoch, with the target `x` in that
    // epoch: `x` is its own checkpoint block in each epoch after epoch 1. The test makes the
    // votes while the store has the state of `x`. The prune runs in epoch 1, so the store
    // keeps `x` through the end of epoch 3.
    let in_window = [2, 3].map(|epoch| (epoch, vote_for_x(&f.store, f.x, epoch)));
    let after_window_epoch = 4;
    let after_window_slot = after_window_epoch * SLOTS_PER_EPOCH;
    let (after_window_voters, after_window_vote) = vote_for_x(&f.store, f.x, after_window_epoch);

    // The tick of slot 11 drops `b` and `x`. `d2` of slot 11 on `c` is a kept block beside `d`.
    tick(&mut f.store, 11);
    assert!(f.store.block(f.x).is_none());
    let c_block = f.store.block(f.c).unwrap().clone();
    let d2 = child(&c_block, 11, 7);
    on_block(&mut f.store, &PLAIN, &d2).unwrap();
    let d2 = root_of(&d2);

    // The spec's store keeps `x`. In epochs 2 and 3 this store still keeps `x` too, so it must
    // give the result of the spec. A block of the second slot of the epoch has the vote. The
    // two attesters of the vote have older messages for `d2`, and one other validator has an
    // older message for `d`. The vote moves the two attesters to `x`, and then `d` must be the
    // head.
    for (epoch, (voters, vote)) in in_window {
        let slot = epoch * SLOTS_PER_EPOCH;
        tick(&mut f.store, slot);
        tick(&mut f.store, slot + 1);
        let mut spec = f.store.clone();
        older_messages(&mut spec, voters, d2, f.d);
        assert_eq!(get_head(&spec), Ok(empty(d2)), "epoch {epoch}");
        assert_eq!(
            on_attestation(&mut spec, &PLAIN, &vote, true),
            Ok(()),
            "epoch {epoch}"
        );
        let moved = LatestMessage {
            slot,
            root: f.x,
            payload_present: false,
        };
        for validator in voters.0 {
            assert_eq!(
                spec.latest_message(validator),
                Some(&moved),
                "epoch {epoch}"
            );
        }
        assert_eq!(
            get_head(&spec),
            Ok(empty(f.d)),
            "epoch {epoch}, d: {}, d2: {}",
            f.d,
            d2
        );
    }

    // The same older messages for the attesters of the vote of epoch 4. The first tick of
    // epoch 4 forgets `x`. A block of slot 33 has the vote of slot 32. All states of this test
    // have one shuffling, so the state of that block and the state of `x` give the vote the
    // same attesters.
    older_messages(&mut f.store, after_window_voters, d2, f.d);
    tick(&mut f.store, after_window_slot);
    tick(&mut f.store, after_window_slot + 1);
    // `d` and `d2` have the voting source of the justified checkpoint of the store, so both
    // stay viable leaves in epoch 4.
    assert_eq!(get_head(&f.store), Ok(empty(d2)));
    // The spec's store takes this vote, as in epochs 2 and 3. It gives the two attesters
    // messages for `x`, which support no kept node, and then `d` is the head.
    let mut spec = f.store.clone();
    for validator in after_window_voters.0 {
        vote(&mut spec, validator, after_window_slot, f.x);
    }
    assert_eq!(get_head(&spec), Ok(empty(f.d)));
    // This store must refuse the vote and keep the older messages, so `d2` must stay the head.
    let before = f.store.clone();
    assert_eq!(
        on_attestation(&mut f.store, &PLAIN, &after_window_vote, true),
        Err(Error::InvalidAttestation(AttestationError::UnknownTarget(
            f.x
        )))
    );
    assert_eq!(f.store, before);
    let older = LatestMessage {
        slot: 12,
        root: d2,
        payload_present: false,
    };
    for validator in after_window_voters.0 {
        assert_eq!(f.store.latest_message(validator), Some(&older));
    }
    assert_eq!(get_head(&f.store), Ok(empty(d2)), "d: {}, d2: {}", f.d, d2);
}

#[test]
fn a_full_vote_for_a_dropped_block_reads_its_verified_payload_after_the_prune() {
    for verified in [false, true] {
        let mut f = finalized();
        if verified {
            mark_payload_verified(&mut f.store, f.x);
        }
        // A FULL vote of slot 10 for `x` of slot 9, with the target `b` of epoch 1.
        let target = Checkpoint {
            epoch: 1,
            root: f.b,
        };
        let mut attestation = attestation(&f.store, 10, f.x, &target, &[0]);
        attestation.data.index = 1;
        tick(&mut f.store, 11);
        assert!(f.store.block(f.x).is_none());
        // The spec's store keeps `x` and the root of its payload.
        assert_eq!(is_payload_verified(&f.store, f.x), verified);
        let want = if verified {
            Ok(())
        } else {
            Err(Error::InvalidAttestation(
                AttestationError::PayloadNotVerified(f.x),
            ))
        };
        assert_eq!(
            on_attestation(&mut f.store, &PLAIN, &attestation, false),
            want,
            "verified: {verified}"
        );
        // The store keeps the root of the payload with the dropped block through the end of
        // epoch 3, and the first tick of epoch 4 forgets it.
        tick(&mut f.store, 4 * SLOTS_PER_EPOCH - 1);
        assert_eq!(
            is_payload_verified(&f.store, f.x),
            verified,
            "verified: {verified}"
        );
        tick(&mut f.store, 4 * SLOTS_PER_EPOCH);
        assert!(!is_payload_verified(&f.store, f.x));
    }
}
