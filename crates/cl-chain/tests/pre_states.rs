//! Tests of the pre-state LRU of the chain core.
//!
//! The tests through the core use the fixture of [`support`]. Siblings of the slot 1 block (the
//! same block with another graffiti) fill the LRU, so that a test can see which pre-state the
//! next commit removes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod support;

use cl_chain::core::snapshot::{max_pre_states, Snapshots};
use cl_chain::core::{ChainCore, Outcome};
use consensus_types::gloas::SignedBeaconBlock;
use consensus_types::primitives::{Bytes32, Root};
use consensus_types::{Mainnet, Minimal};
use state_transition::StfError;
use support::{export_block, fixture, import_one, Answer};
use tree_hash::TreeHash;

/// The block type of the fixture.
type Block = SignedBeaconBlock<Minimal>;

fn root(byte: u8) -> Root {
    Root::repeat_byte(byte)
}

#[test]
fn the_bound_is_two_epochs_and_the_anchor() {
    assert_eq!(max_pre_states::<Minimal>(), 17);
    assert_eq!(max_pre_states::<Mainnet>(), 65);
}

#[test]
fn the_least_recent_goes_first_and_the_anchor_stays() {
    let mut lru = Snapshots::new(root(0), 0u8, 3);
    lru.insert(root(1), 1);
    lru.insert(root(2), 2);
    assert_eq!(lru.len(), 3);
    // A read makes 1 the most recent.
    assert_eq!(lru.get(&root(1)), Some(&1));
    lru.insert(root(3), 3);
    assert_eq!(lru.len(), 3, "the bound must hold");
    assert_eq!(lru.peek(&root(2)), None, "the least recent must go first");
    assert_eq!(lru.peek(&root(1)), Some(&1));
    assert_eq!(lru.peek(&root(3)), Some(&3));
    for byte in 4..40 {
        lru.insert(root(byte), byte);
    }
    assert_eq!(lru.len(), 3);
    assert_eq!(lru.peek(&root(0)), Some(&0), "the anchor must stay");
    assert_eq!(lru.peek(&root(39)), Some(&39), "the newest must stay");
}

#[test]
fn an_insert_of_a_known_root_replaces_it() {
    let mut lru = Snapshots::new(root(0), 0u8, 3);
    lru.insert(root(1), 1);
    lru.insert(root(1), 9);
    assert_eq!(lru.len(), 2);
    assert_eq!(lru.peek(&root(1)), Some(&9));
    lru.insert(root(0), 7);
    assert_eq!(
        lru.peek(&root(0)),
        Some(&0),
        "an insert must not replace the anchor"
    );
}

#[test]
fn a_promote_makes_a_pre_state_the_most_recent() {
    let mut lru = Snapshots::new(root(0), 0u8, 3);
    lru.insert(root(1), 1);
    lru.insert(root(2), 2);
    lru.promote(&root(1));
    // A promote of the anchor or of an unknown root changes nothing.
    lru.promote(&root(0));
    lru.promote(&root(9));
    lru.insert(root(3), 3);
    assert_eq!(lru.peek(&root(2)), None, "2 is now the least recent");
    assert_eq!(lru.peek(&root(1)), Some(&1));
    assert_eq!(lru.peek(&root(0)), Some(&0));
}

#[test]
fn a_peek_does_not_change_the_order_of_use() {
    let mut lru = Snapshots::new(root(0), 0u8, 3);
    lru.insert(root(1), 1);
    lru.insert(root(2), 2);
    assert_eq!(lru.peek(&root(1)), Some(&1));
    lru.insert(root(3), 3);
    assert_eq!(lru.peek(&root(1)), None, "1 must stay the least recent");
    assert_eq!(lru.peek(&root(2)), Some(&2));
}

#[test]
fn the_newest_stays_under_any_bound() {
    let mut lru = Snapshots::new(root(0), 0u8, 0);
    lru.insert(root(1), 1);
    lru.insert(root(2), 2);
    assert_eq!(lru.len(), 2, "the anchor and the newest post-state");
    assert_eq!(lru.peek(&root(2)), Some(&2));
}

/// Commits `block` on `core` with a fake cl-verify that answers VALID.
async fn commit(core: ChainCore<Minimal>, block: Block) -> ChainCore<Minimal> {
    let (outcome, core, _) = import_one(core, block, Answer::Valid).await;
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
    core
}

/// `block` with the graffiti `byte` and the state root of its post-state: a sibling of `block`
/// that commits. The core gives that root: it refuses the sibling with the old state root, and
/// says which root it computed.
async fn sibling(core: ChainCore<Minimal>, block: &Block, byte: u8) -> (ChainCore<Minimal>, Block) {
    let mut sibling = block.clone();
    sibling.message.body.graffiti = Bytes32::repeat_byte(byte);
    let (outcome, core, _) = import_one(core, sibling.clone(), Answer::Valid).await;
    let Outcome::Invalid(StfError::StateRootMismatch { computed, .. }) = outcome else {
        panic!("the sibling with the old state root must be INVALID: {outcome:?}");
    };
    sibling.message.state_root = computed;
    (core, sibling)
}

/// A core that holds the most pre-states: the anchor, the slot 1 block (the least recently
/// used), then 15 siblings of it. Returns the core, the slot 1 block, the slot 2 block (a
/// child of the slot 1 block) and the roots of the siblings, least recently used first.
async fn full_core() -> (ChainCore<Minimal>, Block, Block, Vec<Root>) {
    let f = fixture();
    let first = f.block;
    let mut core = commit(f.core, first.clone()).await;
    let mut siblings = Vec::new();
    for byte in 1..u8::try_from(max_pre_states::<Minimal>() - 1).unwrap() {
        let (next, block) = sibling(core, &first, byte).await;
        siblings.push(block.message.tree_hash_root());
        core = commit(next, block).await;
    }
    assert_eq!(core.pre_states(), max_pre_states::<Minimal>());
    (core, first, export_block(2), siblings)
}

#[tokio::test(start_paused = true)]
async fn a_failed_child_does_not_make_its_parent_more_recent() {
    let (core, first, second, siblings) = full_core().await;
    let first_root = first.message.tree_hash_root();
    // An INVALID child of the least recently used pre-state.
    let mut invalid = second.clone();
    invalid.message.state_root = Root::repeat_byte(0x11);
    let (outcome, core, _) = import_one(core, invalid, Answer::Valid).await;
    assert!(matches!(outcome, Outcome::Invalid(_)), "{outcome:?}");
    // An IGNORE child of it: no verdict from cl-verify.
    let (outcome, core, _) = import_one(core, second, Answer::Never).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    // The next commit removes the least recently used pre-state.
    let (core, last) = sibling(core, &first, 0xff).await;
    let core = commit(core, last).await;
    assert!(
        core.state(&first_root).is_none(),
        "a failed child must not make its parent more recently used"
    );
    assert!(core.state(&siblings[0]).is_some());
}

#[tokio::test]
async fn a_committed_child_makes_its_parent_the_most_recent() {
    let (core, first, second, siblings) = full_core().await;
    let first_root = first.message.tree_hash_root();
    let mut invalid = second.clone();
    invalid.message.state_root = Root::repeat_byte(0x11);
    let (outcome, core, _) = import_one(core, invalid, Answer::Valid).await;
    assert!(matches!(outcome, Outcome::Invalid(_)), "{outcome:?}");
    // A later child of the same parent commits: the parent is now the most recently used, and
    // the commit removes the least recently used of the others.
    let core = commit(core, second).await;
    assert!(
        core.state(&first_root).is_some(),
        "the parent of a committed block must stay"
    );
    assert!(
        core.state(&siblings[0]).is_none(),
        "the least recently used pre-state must go"
    );
}
