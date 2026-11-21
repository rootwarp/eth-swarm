//! Tests of the wall-clock bound of block import through the chain core.
//!
//! A test clock sets the time of the core ([`ChainCore::with_clock`]). The anchor is the
//! genesis of the pinned minimal Gloas export, so the slot of the wall clock is
//! `(now - genesis_time) / SLOT_DURATION_MS`. The core must IGNORE a block after the current slot
//! of fork choice at that clock, one slot ahead included, before cl-verify and the slot loop of
//! the transition. A block far after the slot of its parent state, at the slot of the wall
//! clock, must also be IGNORE before the slot loop.
//! The core must not keep that refusal. A block past the pre-state window, but near its parent
//! state, goes on to the proposer check (`tests/state_advance.rs` has the tests of that walk).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod support;

use cl_chain::core::snapshot::PRE_STATE_EPOCHS;
use cl_chain::core::{queue, ChainCore, Head, Outcome};
use consensus_types::gloas::SignedBeaconBlock;
use consensus_types::{EthSpec, Minimal};
use state_transition::StfError;
use std::sync::Arc;
use std::time::Duration;
use support::{
    assert_unchanged, clock_at, fixture, import_one, slot_start, Answer, FakeVerify, Fixture, QUEUE,
};
use tokio::runtime::Handle;
use tree_hash::TreeHash;

/// The block type of the fixture.
type Block = SignedBeaconBlock<Minimal>;

/// A time of the test clock, from the fixture.
type Now = fn(&Fixture) -> u128;

/// The fixture core with a clock that reads the time `now` gives, the anchor and the slot 1
/// block.
fn core_at(now: impl FnOnce(&Fixture) -> u128) -> (ChainCore<Minimal>, Head, Block) {
    let f = fixture();
    let clock = clock_at(now(&f));
    (f.core.with_clock(clock), f.anchor, f.block)
}

/// A block one slot ahead of the wall clock is after the current slot of fork choice, the slot
/// `on_tick` takes from that clock: `on_block` would refuse it. The core IGNOREs it before
/// cl-verify, so also before the transition (the proposer check comes first), and commits
/// nothing and keeps no refusal. At its slot the same block commits in both.
#[tokio::test]
async fn a_block_ahead_of_the_fork_choice_clock_is_ignored_before_verify_bls_and_commits_nothing() {
    let times: [Now; 2] = [|f| slot_start(f, 0), |f| slot_start(f, 1) - 1];
    for now in times {
        let f = fixture();
        let at_slot = clock_at(slot_start(&f, 1));
        let ahead = clock_at(now(&f));
        let Fixture {
            core,
            anchor,
            block,
            ..
        } = f;
        let block_root = block.message.tree_hash_root();
        let (outcome, core, verify) =
            import_one(core.with_clock(ahead), block.clone(), Answer::Valid).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "fork choice must refuse a slot 1 block before slot 1: {outcome:?}"
        );
        assert!(
            verify.calls().is_empty(),
            "the block must not reach cl-verify or the transition"
        );
        assert_unchanged(&core, anchor, block_root);
        assert!(!core.is_committed(&block_root));
        assert!(
            !core.is_refused(&block_root),
            "the refusal must not be kept"
        );
        assert!(
            core.fork_choice().block(block_root).is_none(),
            "the store must not hold the block"
        );

        let (outcome, core, _) = import_one(core.with_clock(at_slot), block, Answer::Valid).await;
        assert!(
            matches!(outcome, Outcome::Committed { .. }),
            "at its slot the block must commit: {outcome:?}"
        );
        assert!(core.fork_choice().block(block_root).is_some());
        assert_eq!(core.head().block_root, block_root);
    }
}

#[tokio::test]
async fn a_block_at_the_slot_of_the_wall_clock_commits() {
    let (core, _, block) = core_at(|f| slot_start(f, 1));
    let (outcome, _, _) = import_one(core, block, Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Committed { .. }),
        "a slot 1 block must commit at the start of slot 1: {outcome:?}"
    );
}

#[tokio::test]
async fn a_block_two_slots_ahead_is_ignored_before_the_transition() {
    let times: [Now; 2] = [|f| slot_start(f, 0), |f| slot_start(f, 1) - 1];
    for now in times {
        let (core, anchor, mut block) = core_at(now);
        block.message.slot = 2;
        let block_root = block.message.tree_hash_root();
        let (outcome, core, verify) = import_one(core, block, Answer::Valid).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "a block two slots ahead of the wall clock must be IGNORE: {outcome:?}"
        );
        assert!(
            verify.calls().is_empty(),
            "the block must not reach cl-verify"
        );
        assert_unchanged(&core, anchor, block_root);
    }
}

/// The slot loop of the transition runs one `process_slot` for each slot. Over 2^40 slots it
/// cannot end in [`AT_ONCE`]. So an answer in that time shows that the loop did not run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_future_block_is_ignored_without_the_slot_loop() {
    /// The time the core has to answer.
    const AT_ONCE: Duration = Duration::from_secs(20);
    let (core, anchor, mut block) = core_at(|f| slot_start(f, 0));
    block.message.slot = 1 << 40;
    let verify = FakeVerify::new(Answer::Valid);
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let writer = core
        .spawn(queue, Arc::clone(&verify), Handle::current())
        .unwrap();
    let reply = sender.import(block).unwrap();
    let served = tokio::time::timeout(AT_ONCE, reply)
        .await
        .expect("the core must answer at once: it must not run the slot loop")
        .unwrap();
    assert!(
        matches!(served.outcome, Outcome::Ignored(_)),
        "{:?}",
        served.outcome
    );
    assert!(verify.calls().is_empty());
    drop(sender);
    let core = writer.join().unwrap();
    assert_eq!(core.head(), anchor, "the head must stay the anchor");
}

#[tokio::test]
async fn before_genesis_a_block_is_ignored() {
    let (core, anchor, block) = core_at(|f| slot_start(f, 0) - 1);
    let block_root = block.message.tree_hash_root();
    let (outcome, core, verify) = import_one(core, block, Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "a block before genesis must be IGNORE: {outcome:?}"
    );
    assert!(verify.calls().is_empty());
    assert_unchanged(&core, anchor, block_root);
}

/// The anchor is at slot 0, and the wall clock is at the block slot, 2^40. Without a bound on
/// the distance to the parent, the slot loop runs 2^40 slots, and the core cannot answer in
/// [`AT_ONCE`]. The block can import later from a nearer state, so the core must not keep the
/// refusal of its root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_far_from_its_parent_is_ignored_without_the_slot_loop() {
    /// The time the core has to answer.
    const AT_ONCE: Duration = Duration::from_secs(20);
    let far = 1 << 40;
    let (core, anchor, mut block) = core_at(|f| slot_start(f, far));
    block.message.slot = far;
    let block_root = block.message.tree_hash_root();
    let verify = FakeVerify::new(Answer::Valid);
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let writer = core
        .spawn(queue, Arc::clone(&verify), Handle::current())
        .unwrap();
    let reply = sender.import(block).unwrap();
    let served = tokio::time::timeout(AT_ONCE, reply)
        .await
        .expect("the core must answer at once: it must not run the slot loop")
        .unwrap();
    assert!(
        matches!(served.outcome, Outcome::Ignored(_)),
        "a block at the wall-clock slot far from its parent must be IGNORE: {:?}",
        served.outcome
    );
    assert!(
        verify.calls().is_empty(),
        "the block must not reach cl-verify"
    );
    drop(sender);
    let core = writer.join().unwrap();
    assert_eq!(core.head(), anchor, "the head must stay the anchor");
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal of a block far from its parent"
    );
    assert!(
        core.advanced_state(&anchor.block_root, 1).is_none(),
        "the core must not walk the slots after the parent"
    );
}

/// At the window, the block goes on to the proposer check on the parent state: cl-verify
/// refuses its signature. One slot past the window, the block also goes on to the proposer
/// check, before the walk over the slots after the parent state. The refused signature stops
/// the import before the walk.
#[tokio::test]
async fn the_parent_distance_bound_is_the_pre_state_window() {
    let bound = PRE_STATE_EPOCHS * Minimal::slots_per_epoch();
    let (core, _, mut block) = core_at(|f| slot_start(f, bound));
    block.message.slot = bound;
    let (outcome, _, verify) = import_one(core, block, Answer::Invalid).await;
    assert_eq!(
        outcome,
        Outcome::Invalid(StfError::InvalidBlockSignature),
        "a block at the bound must reach the proposer check"
    );
    assert_eq!(verify.calls().len(), 1);

    let (core, anchor, mut block) = core_at(|f| slot_start(f, bound + 1));
    block.message.slot = bound + 1;
    let block_root = block.message.tree_hash_root();
    let (outcome, core, verify) = import_one(core, block, Answer::Invalid).await;
    assert_eq!(
        outcome,
        Outcome::Invalid(StfError::InvalidBlockSignature),
        "a block one slot past the bound must reach the proposer check"
    );
    assert_eq!(
        verify.calls().len(),
        1,
        "only the proposer set must go to cl-verify"
    );
    assert!(
        core.advanced_state(&anchor.block_root, 1).is_none(),
        "a refused signature must stop the import before the walk"
    );
    assert_unchanged(&core, anchor, block_root);
}
