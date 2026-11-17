//! Tests of the wall-clock bound of block import through the chain core.
//!
//! A test clock sets the time of the core ([`ChainCore::with_clock`]). The anchor is the
//! genesis of the pinned minimal Gloas export, so the slot of the wall clock is
//! `(now - genesis_time) / SLOT_DURATION_MS`. The core must IGNORE a block more than one slot
//! ahead of that slot, before the slot loop of the transition.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod support;

use cl_chain::core::{queue, ChainCore, Head, Outcome};
use cl_chain::verify::client::UnixClock;
use consensus_types::gloas::SignedBeaconBlock;
use consensus_types::Minimal;
use std::sync::Arc;
use std::time::Duration;
use support::{assert_unchanged, fixture, import_one, Answer, FakeVerify, Fixture, QUEUE};
use tokio::runtime::Handle;
use tree_hash::TreeHash;

/// The block type of the fixture.
type Block = SignedBeaconBlock<Minimal>;

/// A time of the test clock, from the fixture.
type Now = fn(&Fixture) -> u128;

/// A clock that always reads `unix_ms`.
fn clock_at(unix_ms: u128) -> UnixClock {
    Arc::new(move || unix_ms)
}

/// The start of slot `slot` of the fixture chain, in Unix milliseconds.
fn slot_start(f: &Fixture, slot: u64) -> u128 {
    let genesis = f.core.state(&f.anchor.block_root).unwrap().genesis_time;
    u128::from(genesis) * 1000 + u128::from(slot) * u128::from(f.config.slot_duration_ms())
}

/// The fixture core with a clock that reads the time `now` gives, the anchor and the slot 1
/// block.
fn core_at(now: impl FnOnce(&Fixture) -> u128) -> (ChainCore<Minimal>, Head, Block) {
    let f = fixture();
    let clock = clock_at(now(&f));
    (f.core.with_clock(clock), f.anchor, f.block)
}

#[tokio::test]
async fn a_block_one_slot_ahead_of_the_wall_clock_commits() {
    let times: [Now; 3] = [
        |f| slot_start(f, 0),
        |f| slot_start(f, 1) - 1,
        |f| slot_start(f, 1),
    ];
    for now in times {
        let (core, _, block) = core_at(now);
        let (outcome, _, _) = import_one(core, block, Answer::Valid).await;
        assert!(
            matches!(outcome, Outcome::Committed { .. }),
            "a slot 1 block must commit from the start of slot 0: {outcome:?}"
        );
    }
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
