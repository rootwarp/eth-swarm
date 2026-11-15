//! The Store, `on_tick`, `on_block` and `get_head` on small chains that the tests build.
//!
//! The test provider does not run the state transition. The post-state of a block is the
//! parent state at the slot of the block, and a test can change it. Fork choice reads only the
//! slot, the registry, the participation and the checkpoints of these states, so each test
//! sets them directly.

use consensus_types::gloas::{BeaconBlock, BeaconState, Checkpoint, SignedBeaconBlock};
use consensus_types::primitives::{Root, Slot};
use consensus_types::Minimal;
use fork_choice::testing::mark_payload_verified;
use fork_choice::{
    compute_slots_since_epoch_start, get_ancestor, get_checkpoint_block, get_current_slot,
    get_current_store_epoch, get_filtered_node_tree, get_forkchoice_store, get_head,
    get_node_children, get_parent_payload_status, get_slots_since_genesis, get_time_into_slot_ms,
    get_weight, is_ancestor, is_parent_node_full, is_payload_verified, is_valid_dependent_root,
    milliseconds_to_seconds, on_block, on_tick, seconds_to_milliseconds,
    store_target_checkpoint_state, Error, ForkChoiceNode, PayloadStatus, StateProvider, Store,
};
use state_transition::testing::{genesis_state, signed_block};
use state_transition::{state_root, StfError};
use std::num::NonZeroU64;
use tree_hash::TreeHash;

type E = Minimal;

const SLOT_MS: u64 = 6000;
const GENESIS_TIME: u64 = 1_700_000_000;
const VALIDATORS: usize = 64;
const BALANCE: u64 = 32_000_000_000;
/// `PTC_SIZE` of the minimal preset.
const PTC_SIZE: usize = 16;

fn slot_duration() -> NonZeroU64 {
    NonZeroU64::new(SLOT_MS).unwrap()
}

/// The time in milliseconds at the start of `slot`.
fn time_at(slot: Slot) -> u64 {
    GENESIS_TIME * 1000 + slot * SLOT_MS
}

fn tick(store: &mut Store<E>, slot: Slot) {
    on_tick(store, time_at(slot)).unwrap();
}

/// A genesis state with 64 validators of 32 ETH, and its anchor block.
fn anchor() -> (BeaconState<E>, BeaconBlock<E>) {
    let mut state = genesis_state::<E>(&[BALANCE; VALIDATORS]);
    state.genesis_time = GENESIS_TIME;
    let mut block = signed_block::<E>(0, 0).message;
    block.state_root = state_root(&mut state).unwrap();
    (state, block)
}

/// A store at the anchor, and the anchor block.
fn new_store() -> (Store<E>, BeaconBlock<E>) {
    let (state, block) = anchor();
    let store = get_forkchoice_store(state, block.clone(), slot_duration()).unwrap();
    (store, block)
}

/// The test provider: the post-state is the parent state at the slot of the block, after
/// `edit`. `process_slots` only sets the slot.
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

/// A provider whose state transition always fails.
struct Refuse;

impl StateProvider<E> for Refuse {
    fn state_transition(
        &self,
        _: &mut BeaconState<E>,
        _: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        Err(StfError::InvalidBlockSignature)
    }

    fn process_slots(&self, _: &mut BeaconState<E>, _: Slot) -> Result<(), StfError> {
        Err(StfError::InvalidBlockSignature)
    }
}

/// A block at `slot` on `parent`. If `full` is true, its bid builds on the payload of the bid
/// of `parent` (a FULL parent). Else its bid builds on another hash (an EMPTY parent). `tag`
/// is the proposer index, so two blocks of one slot have different roots.
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

#[test]
fn forkchoice_store_starts_at_the_anchor_with_no_payloads() {
    let (store, anchor_block) = new_store();
    let root = anchor_block.tree_hash_root();
    let checkpoint = Checkpoint { epoch: 0, root };
    assert_eq!(store.justified_checkpoint(), &checkpoint);
    assert_eq!(store.finalized_checkpoint(), &checkpoint);
    assert_eq!(store.unrealized_justified_checkpoint(), &checkpoint);
    assert_eq!(store.unrealized_finalized_checkpoint(), &checkpoint);
    assert_eq!(store.genesis_time_ms(), GENESIS_TIME * 1000);
    assert_eq!(store.time_ms(), GENESIS_TIME * 1000);
    assert_eq!(store.proposer_boost_root(), Root::ZERO);
    assert_eq!(store.block(root), Some(&anchor_block));
    assert_eq!(store.block_state(root).map(|s| s.slot), Some(0));
    assert!(store.checkpoint_state(&checkpoint).is_some());
    assert!(!is_payload_verified(&store, root));
    assert_eq!(store.block_timeliness(root), Some([true, true]));
    let votes = [None; PTC_SIZE];
    assert_eq!(store.payload_timeliness_vote(root), Some(&votes[..]));
    assert_eq!(store.payload_data_availability_vote(root), Some(&votes[..]));
}

#[test]
fn forkchoice_store_time_starts_at_the_anchor_slot() {
    let (mut state, mut block) = anchor();
    state.slot = 13;
    block.slot = 13;
    block.state_root = state_root(&mut state).unwrap();
    let store = get_forkchoice_store(state, block, slot_duration()).unwrap();
    assert_eq!(store.time_ms(), time_at(13));
    assert_eq!(get_current_slot(&store), 13);
    assert_eq!(store.justified_checkpoint().epoch, 1);
}

#[test]
fn forkchoice_store_refuses_an_anchor_block_of_another_state() {
    let (state, mut block) = anchor();
    block.state_root = Root::repeat_byte(1);
    let got = get_forkchoice_store(state, block, slot_duration());
    assert!(matches!(got, Err(Error::AnchorStateRoot { .. })), "{got:?}");
}

#[test]
fn time_helpers_follow_the_store_time() {
    assert_eq!(seconds_to_milliseconds(3), 3000);
    assert_eq!(seconds_to_milliseconds(u64::MAX), u64::MAX);
    assert_eq!(milliseconds_to_seconds(5999), 5);
    assert_eq!(compute_slots_since_epoch_start::<E>(9), 1);
    assert_eq!(compute_slots_since_epoch_start::<E>(16), 0);
    let (mut store, _) = new_store();
    on_tick(&mut store, time_at(9) + 1500).unwrap();
    assert_eq!(store.time_ms(), time_at(9) + 1500);
    assert_eq!(get_slots_since_genesis(&store), 9);
    assert_eq!(get_current_slot(&store), 9);
    assert_eq!(get_current_store_epoch(&store), 1);
    assert_eq!(get_time_into_slot_ms(&store), 1500);
}

#[test]
fn on_tick_refuses_a_time_before_genesis() {
    let (mut store, _) = new_store();
    let got = on_tick(&mut store, GENESIS_TIME * 1000 - 1);
    assert!(matches!(got, Err(Error::BeforeGenesis { .. })), "{got:?}");
    assert_eq!(store.time_ms(), GENESIS_TIME * 1000);
}

#[test]
fn on_tick_clears_the_proposer_boost_in_a_new_slot_only() {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let block = child(&anchor_block, 1, false, 1);
    on_block(&mut store, &PLAIN, &block).unwrap();
    assert_eq!(store.proposer_boost_root(), root_of(&block));
    on_tick(&mut store, time_at(1) + 5000).unwrap();
    assert_eq!(store.proposer_boost_root(), root_of(&block));
    tick(&mut store, 2);
    assert_eq!(store.proposer_boost_root(), Root::ZERO);
}

/// A provider whose post-state has target votes of every validator in the previous and the
/// current epoch, and `target` as the block root of slot 16. At slot 17, the justification of
/// that state justifies epoch 2 with `target`.
fn justifying(target: Root) -> Provider<impl Fn(&mut BeaconState<E>)> {
    Provider(move |state: &mut BeaconState<E>| {
        for i in 0..VALIDATORS {
            *state.previous_epoch_participation.get_mut(i).unwrap() = 0b111;
            *state.current_epoch_participation.get_mut(i).unwrap() = 0b111;
        }
        *state.block_roots.get_mut(8).unwrap() = Root::repeat_byte(0x08);
        *state.block_roots.get_mut(16).unwrap() = target;
        state.apply_updates().unwrap();
    })
}

#[test]
fn on_tick_pulls_up_the_unrealized_checkpoints_at_an_epoch_boundary() {
    let (mut store, anchor_block) = new_store();
    let genesis = Checkpoint {
        epoch: 0,
        root: anchor_block.tree_hash_root(),
    };
    let target = Root::repeat_byte(0x16);
    tick(&mut store, 17);
    on_block(
        &mut store,
        &justifying(target),
        &child(&anchor_block, 17, false, 1),
    )
    .unwrap();
    let justified = Checkpoint {
        epoch: 2,
        root: target,
    };
    // The block is of the current epoch, so its justification stays unrealized.
    assert_eq!(store.unrealized_justified_checkpoint(), &justified);
    assert_eq!(store.justified_checkpoint(), &genesis);
    tick(&mut store, 23);
    assert_eq!(store.justified_checkpoint(), &genesis);
    // The first slot of epoch 3 realizes it.
    tick(&mut store, 24);
    assert_eq!(store.justified_checkpoint(), &justified);
    assert_eq!(store.finalized_checkpoint(), &genesis);
}

#[test]
fn on_block_realizes_the_pulled_up_checkpoints_of_a_block_of_a_past_epoch() {
    let (mut store, anchor_block) = new_store();
    let target = Root::repeat_byte(0x16);
    tick(&mut store, 24);
    on_block(
        &mut store,
        &justifying(target),
        &child(&anchor_block, 17, false, 1),
    )
    .unwrap();
    let justified = Checkpoint {
        epoch: 2,
        root: target,
    };
    assert_eq!(store.justified_checkpoint(), &justified);
    assert_eq!(store.unrealized_justified_checkpoint(), &justified);
}

#[test]
fn full_parent_needs_verified_payload() {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 2);
    let a = child(&anchor_block, 1, false, 1);
    on_block(&mut store, &PLAIN, &a).unwrap();
    let a_root = root_of(&a);
    let b = child(&a.message, 2, true, 2);
    assert_eq!(
        get_parent_payload_status(&store, &b.message),
        Ok(PayloadStatus::Full)
    );
    // The block builds on the FULL payload of a. on_block must refuse it, and the store must
    // not change, while a has no verified payload.
    assert_eq!(
        on_block(&mut store, &PLAIN, &b),
        Err(Error::ParentPayloadNotVerified(a_root))
    );
    assert_eq!(store.block(root_of(&b)), None);
    mark_payload_verified(&mut store, a_root);
    assert!(is_payload_verified(&store, a_root));
    assert_eq!(on_block(&mut store, &PLAIN, &b), Ok(()));
    assert_eq!(store.block(root_of(&b)), Some(&b.message));
}

#[test]
fn empty_parent_needs_no_verified_payload() {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 2);
    let a = child(&anchor_block, 1, false, 1);
    on_block(&mut store, &PLAIN, &a).unwrap();
    let c = child(&a.message, 2, false, 3);
    assert_eq!(
        get_parent_payload_status(&store, &c.message),
        Ok(PayloadStatus::Empty)
    );
    assert_eq!(on_block(&mut store, &PLAIN, &c), Ok(()));
    assert!(!is_payload_verified(&store, root_of(&a)));
}

#[test]
fn on_block_refuses_invalid_blocks_and_keeps_the_store() {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor_block, 1, false, 1);
    let orphan = child(&a.message, 1, false, 2);
    assert_eq!(
        on_block(&mut store, &PLAIN, &orphan),
        Err(Error::UnknownParent(root_of(&a)))
    );
    let future = child(&anchor_block, 2, false, 1);
    assert_eq!(
        on_block(&mut store, &PLAIN, &future),
        Err(Error::FutureBlock {
            block: 2,
            current: 1
        })
    );
    assert_eq!(
        on_block(&mut store, &Refuse, &a),
        Err(Error::StateTransition(StfError::InvalidBlockSignature))
    );
    for block in [&a, &orphan, &future] {
        assert_eq!(store.block(root_of(block)), None);
    }
    assert_eq!(store.proposer_boost_root(), Root::ZERO);
    // A known block is a no-op, also for a provider that refuses every block.
    on_block(&mut store, &PLAIN, &a).unwrap();
    assert_eq!(on_block(&mut store, &Refuse, &a), Ok(()));
}

#[test]
fn on_block_records_timeliness_and_a_late_block_gets_no_boost() {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 2);
    let late = child(&anchor_block, 1, false, 1);
    on_block(&mut store, &PLAIN, &late).unwrap();
    assert_eq!(store.block_timeliness(root_of(&late)), Some([false, false]));
    assert_eq!(store.proposer_boost_root(), Root::ZERO);
    // 2000 ms into the slot is after the attestation deadline (25% of the slot: 1500 ms) and
    // before the PTC deadline (75% of the slot: 4500 ms).
    on_tick(&mut store, time_at(2) + 2000).unwrap();
    let block = child(&late.message, 2, false, 2);
    on_block(&mut store, &PLAIN, &block).unwrap();
    assert_eq!(store.block_timeliness(root_of(&block)), Some([false, true]));
    assert_eq!(store.proposer_boost_root(), Root::ZERO);
    let votes = [None; PTC_SIZE];
    assert_eq!(
        store.payload_timeliness_vote(root_of(&block)),
        Some(&votes[..])
    );
}

/// anchor, then a at slot 1, then b at slot 2 on a, and c at slot 2 on a. A full `b` builds on
/// the FULL payload of `a`, and `c` builds on the EMPTY `a`.
struct Fork {
    store: Store<E>,
    anchor: Root,
    a: Root,
    b: Root,
    c: Root,
}

/// [`Fork`] at the start of slot 2. `a` has a verified payload. `b_first` sets which block of
/// slot 2 comes first and gets the proposer boost.
fn fork(b_first: bool) -> Fork {
    let (mut store, anchor_block) = new_store();
    tick(&mut store, 1);
    let a = child(&anchor_block, 1, false, 1);
    on_block(&mut store, &PLAIN, &a).unwrap();
    mark_payload_verified(&mut store, root_of(&a));
    tick(&mut store, 2);
    let b = child(&a.message, 2, true, 2);
    let c = child(&a.message, 2, false, 3);
    let order = if b_first { [&b, &c] } else { [&c, &b] };
    for block in order {
        on_block(&mut store, &PLAIN, block).unwrap();
    }
    Fork {
        store,
        anchor: anchor_block.tree_hash_root(),
        a: root_of(&a),
        b: root_of(&b),
        c: root_of(&c),
    }
}

#[test]
fn ancestors_carry_the_payload_status_of_each_child() {
    let (mut store, anchor_block) = new_store();
    let anchor = anchor_block.tree_hash_root();
    tick(&mut store, 3);
    let b1 = child(&anchor_block, 1, false, 1);
    on_block(&mut store, &PLAIN, &b1).unwrap();
    mark_payload_verified(&mut store, root_of(&b1));
    let b2 = child(&b1.message, 2, true, 1);
    on_block(&mut store, &PLAIN, &b2).unwrap();
    let b3 = child(&b2.message, 3, false, 1);
    on_block(&mut store, &PLAIN, &b3).unwrap();
    let (r1, r2, r3) = (root_of(&b1), root_of(&b2), root_of(&b3));
    assert_eq!(is_parent_node_full(&store, &b2.message), Ok(true));
    assert_eq!(is_parent_node_full(&store, &b3.message), Ok(false));
    assert_eq!(get_ancestor(&store, pending(r3), 3), Ok(pending(r3)));
    assert_eq!(get_ancestor(&store, pending(r3), 2), Ok(empty(r2)));
    assert_eq!(get_ancestor(&store, pending(r3), 1), Ok(full(r1)));
    assert_eq!(get_ancestor(&store, pending(r3), 0), Ok(empty(anchor)));
    assert_eq!(is_ancestor(&store, pending(r3), full(r1)), Ok(true));
    assert_eq!(is_ancestor(&store, pending(r3), empty(r1)), Ok(false));
    assert_eq!(is_ancestor(&store, pending(r3), pending(r1)), Ok(true));
    assert_eq!(is_ancestor(&store, pending(r1), pending(r3)), Ok(false));
    assert_eq!(get_checkpoint_block(&store, r3, 0), Ok(anchor));
    assert_eq!(get_checkpoint_block(&store, r3, 1), Ok(r3));
    let unknown = Root::repeat_byte(0x55);
    assert_eq!(
        get_ancestor(&store, pending(unknown), 0),
        Err(Error::UnknownBlock(unknown))
    );
}

#[test]
fn get_head_of_a_lone_anchor_is_its_empty_node() {
    let (store, anchor_block) = new_store();
    let anchor = anchor_block.tree_hash_root();
    assert_eq!(get_head(&store), Ok(empty(anchor)));
    let nodes = get_filtered_node_tree(&store).unwrap();
    assert_eq!(nodes.len(), 2);
    assert!(nodes.contains(&pending(anchor)) && nodes.contains(&empty(anchor)));
}

#[test]
fn pending_node_children_are_its_empty_and_verified_full_nodes() {
    let f = fork(true);
    let s = &f.store;
    assert_eq!(
        get_node_children(s, &pending(f.anchor)),
        Ok(vec![empty(f.anchor)])
    );
    assert_eq!(
        get_node_children(s, &pending(f.a)),
        Ok(vec![empty(f.a), full(f.a)])
    );
    assert_eq!(get_node_children(s, &empty(f.a)), Ok(vec![pending(f.c)]));
    assert_eq!(get_node_children(s, &full(f.a)), Ok(vec![pending(f.b)]));
    assert_eq!(get_node_children(s, &empty(f.b)), Ok(vec![]));
    // Every node is viable: the justified and the finalized checkpoints are at genesis.
    assert_eq!(get_filtered_node_tree(s).unwrap().len(), 9);
}

#[test]
fn get_head_extends_the_payload_that_the_boosted_block_builds_on() {
    let f = fork(true);
    assert_eq!(f.store.proposer_boost_root(), f.b);
    // `a` is of the previous slot: its EMPTY and FULL nodes have no weight, and
    // should_extend_payload gives FULL, because the boosted block builds on the FULL `a`.
    assert_eq!(get_weight(&f.store, &empty(f.a)), Ok(0));
    assert_eq!(get_weight(&f.store, &full(f.a)), Ok(0));
    // The proposer score: 40% of one slot of the 2048 ETH of the registry.
    assert_eq!(get_weight(&f.store, &pending(f.b)), Ok(102_400_000_000));
    assert_eq!(get_weight(&f.store, &pending(f.c)), Ok(0));
    assert_eq!(get_head(&f.store), Ok(empty(f.b)));
}

#[test]
fn get_head_drops_the_payload_when_the_boosted_block_builds_on_the_empty_parent() {
    let f = fork(false);
    assert_eq!(f.store.proposer_boost_root(), f.c);
    assert_eq!(get_head(&f.store), Ok(empty(f.c)));
}

#[test]
fn get_head_prefers_full_to_empty_after_the_payload_slot() {
    for b_first in [true, false] {
        let mut f = fork(b_first);
        tick(&mut f.store, 3);
        assert_eq!(f.store.proposer_boost_root(), Root::ZERO);
        assert_eq!(get_head(&f.store), Ok(empty(f.b)), "b first: {b_first}");
    }
}

#[test]
fn dependent_root_is_valid_for_the_head_or_a_block_with_a_later_child() {
    let f = fork(true);
    assert_eq!(is_valid_dependent_root(&f.store, f.b, 0), Ok(true));
    assert_eq!(is_valid_dependent_root(&f.store, f.a, 1), Ok(true));
    assert_eq!(is_valid_dependent_root(&f.store, f.a, 2), Ok(false));
    assert_eq!(is_valid_dependent_root(&f.store, f.c, 2), Ok(false));
}

#[test]
fn store_target_checkpoint_state_advances_the_target_block_state() {
    let (mut store, anchor_block) = new_store();
    let target = Checkpoint {
        epoch: 1,
        root: anchor_block.tree_hash_root(),
    };
    assert!(store.checkpoint_state(&target).is_none());
    store_target_checkpoint_state(&mut store, &PLAIN, &target).unwrap();
    assert_eq!(store.checkpoint_state(&target).map(|s| s.slot), Some(8));
    let unknown = Checkpoint {
        epoch: 1,
        root: Root::repeat_byte(0x55),
    };
    assert_eq!(
        store_target_checkpoint_state(&mut store, &PLAIN, &unknown),
        Err(Error::UnknownBlock(unknown.root))
    );
}

/// A store whose anchor is a block of `slot` and the state of that block. The parent of the
/// anchor block is not in the store, as after a checkpoint sync. The anchor block is the
/// checkpoint block of its epoch only if `slot` is the first slot of that epoch.
fn checkpoint_store(slot: Slot) -> (Store<E>, BeaconBlock<E>) {
    let (mut state, mut block) = anchor();
    state.slot = slot;
    block.slot = slot;
    block.parent_root = Root::repeat_byte(0xa0);
    block.state_root = state_root(&mut state).unwrap();
    let store = get_forkchoice_store(state, block.clone(), slot_duration()).unwrap();
    (store, block)
}

#[test]
fn checkpoint_anchor_accepts_a_first_child_in_the_next_slot() {
    let (mut store, anchor_block) = checkpoint_store(24);
    let anchor = anchor_block.tree_hash_root();
    let checkpoint = Checkpoint {
        epoch: 3,
        root: anchor,
    };
    assert_eq!(store.finalized_checkpoint(), &checkpoint);
    tick(&mut store, 25);
    let block = child(&anchor_block, 25, false, 1);
    // The shuffling dependent slot of epoch 3 is slot 15, before the anchor. The walk to it
    // must stop at the anchor and must not look up the parent of the anchor.
    assert_eq!(on_block(&mut store, &PLAIN, &block), Ok(()));
    let root = root_of(&block);
    assert_eq!(store.block(root), Some(&block.message));
    // The head and the new block both have the anchor as their dependent root, so the timely
    // block gets the proposer boost.
    assert_eq!(store.proposer_boost_root(), root);
    assert_eq!(get_head(&store), Ok(empty(root)));
    assert_eq!(store.finalized_checkpoint(), &checkpoint);
}

#[test]
fn checkpoint_anchor_in_the_middle_of_an_epoch_accepts_a_child() {
    // The first slot of the finalized epoch 3 is slot 24, before the anchor of slot 27. The
    // finalized checkpoint block of the parent must be the anchor.
    let (mut store, anchor_block) = checkpoint_store(27);
    let anchor = anchor_block.tree_hash_root();
    assert_eq!(store.finalized_checkpoint().root, anchor);
    tick(&mut store, 28);
    let block = child(&anchor_block, 28, false, 1);
    assert_eq!(on_block(&mut store, &PLAIN, &block), Ok(()));
    assert_eq!(get_checkpoint_block(&store, root_of(&block), 3), Ok(anchor));
    assert_eq!(get_head(&store), Ok(empty(root_of(&block))));
}

#[test]
fn checkpoint_anchor_ancestor_walk_stops_at_the_anchor() {
    let (mut store, anchor_block) = checkpoint_store(24);
    let anchor = anchor_block.tree_hash_root();
    tick(&mut store, 26);
    let b25 = child(&anchor_block, 25, false, 1);
    on_block(&mut store, &PLAIN, &b25).unwrap();
    let b26 = child(&b25.message, 26, false, 2);
    on_block(&mut store, &PLAIN, &b26).unwrap();
    let (r25, r26) = (root_of(&b25), root_of(&b26));
    // Below the anchor, the walk gives the anchor with the payload status that its child
    // builds on.
    assert_eq!(get_ancestor(&store, pending(r26), 10), Ok(empty(anchor)));
    assert_eq!(get_ancestor(&store, pending(r26), 25), Ok(empty(r25)));
    assert_eq!(
        get_ancestor(&store, pending(anchor), 0),
        Ok(pending(anchor))
    );
    assert_eq!(get_checkpoint_block(&store, r26, 1), Ok(anchor));
    assert_eq!(is_ancestor(&store, pending(r26), pending(anchor)), Ok(true));
    assert_eq!(is_ancestor(&store, pending(r26), empty(anchor)), Ok(true));
    assert_eq!(is_ancestor(&store, pending(r26), full(anchor)), Ok(false));
    // The walk must not make up a block below the anchor: the parent of the anchor and any
    // other root that the store does not have stay unknown.
    let below = anchor_block.parent_root;
    assert_eq!(
        get_ancestor(&store, pending(below), 0),
        Err(Error::UnknownBlock(below))
    );
    assert_eq!(store.block(below), None);
}
