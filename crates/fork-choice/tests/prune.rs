//! The store drops the blocks below and beside the finalized checkpoint block once finality
//! moves, at the next `on_tick`. The tests compare the store just before that tick with the
//! store after it, at the same time: the justified and the finalized checkpoints are the same,
//! so `get_head` and `get_weight` must give the same result.
//!
//! The test provider does not run the state transition. The post-state of a block is the
//! parent state at the slot of the block, after an optional edit. Each validator has 32 ETH and
//! the registry has 64 validators, so the proposer score is 102.4 ETH, and a head is weak below
//! 51.2 ETH.

use consensus_types::gloas::{BeaconBlock, BeaconState, Checkpoint, SignedBeaconBlock};
use consensus_types::primitives::{Gwei, Root, Slot, ValidatorIndex};
use consensus_types::Minimal;
use fork_choice::testing::{add_equivocating_index, set_latest_message};
use fork_choice::{
    get_ancestor, get_filtered_node_tree, get_forkchoice_store, get_head, get_weight, on_block,
    on_tick, store_target_checkpoint_state, Error, ForkChoiceNode, LatestMessage, PayloadStatus,
    StateProvider, Store,
};
use state_transition::testing::{genesis_state, signed_block};
use state_transition::{state_root, StfError};
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

/// A provider whose post-state justifies and finalizes `checkpoint`.
fn finalizing(checkpoint: Checkpoint) -> Provider<impl Fn(&mut BeaconState<E>)> {
    Provider(move |state: &mut BeaconState<E>| {
        state.current_justified_checkpoint = checkpoint.clone();
        state.finalized_checkpoint = checkpoint.clone();
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
    for block in [&d, &e] {
        on_block(&mut store, &PLAIN, block).unwrap();
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
