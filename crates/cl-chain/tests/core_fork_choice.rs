//! The fork choice store of the chain core, its head and its forkchoiceUpdated calls, against a
//! mock EL.
//!
//! The mock EL behind an in-process cl-engine, the steps of a test and the blocks whose
//! envelopes verify are those of `support/el.rs` (see its docs). A [`Sink`] records each
//! forkchoiceUpdated the core sends and, when a test gives it one, forwards it to the production
//! `FcuSender`, which sends it to cl-engine and so to the mock EL. A fake cl-verify gives the
//! VerifyBls verdicts.
//!
//! The fixture anchor builds on no payload hash (its bid's `block_hash` and `parent_block_hash`
//! are zero), so the forkchoiceUpdated of a head on its EMPTY payload, and its safe and finalized
//! hashes while the anchor is the justified and the finalized block, are zero hashes.
//!
//! The core reads the sender's latest answer at the start of each turn. A gossip commit item
//! (`Item::Gossip`) is a turn that changes nothing else.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "support/el.rs"]
mod el;
#[allow(dead_code)]
mod support;

use cl_chain::core::snapshot::max_pre_states;
use cl_chain::core::{ChainCore, Head, Outcome};
use cl_chain::engine::client::{FcuOutcome, FcuSender, BACKOFF_MIN};
use cl_chain::engine::fcu::{
    Bid, ForkchoiceArgs, ForkchoiceSink, PayloadStatus, CUSTODY_COLUMN_BYTES,
};
use cl_chain::engine::verdict::ExecutionStatus;
use consensus_types::gloas::{BeaconState, Checkpoint};
use consensus_types::primitives::{Bytes32, Hash32};
use consensus_types::{EthSpec, Minimal};
use el::{
    advanced, block_item, commit_all, empty_child, envelope, full_child, full_child_at, hash,
    invalid_on, payload_block, ready, root, sealed, step, Block, El, Item,
};
use ethswarm_proto::engine as pb;
use fork_choice::testing::{
    remove_checkpoint_state, set_finalized_checkpoint, set_justified_checkpoint,
    set_unrealized_finalized_checkpoint, set_unrealized_justified_checkpoint,
};
use fork_choice::{get_head, invalidate_payloads, is_payload_verified};
use std::cmp::Reverse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::{clock_at, fixture, Answer, FakeVerify, Fixture, PayloadVerified};
use testkit::mock_el::Reply;

/// Any custody set: each forkchoiceUpdated carries it as configured.
const CUSTODY: [u8; CUSTODY_COLUMN_BYTES] = [0x3c; CUSTODY_COLUMN_BYTES];
/// How long a test waits for something that should happen.
const WAIT: Duration = Duration::from_secs(20);
/// How long a test waits to see that nothing more happens.
const QUIET: Duration = Duration::from_millis(300);

/// Records each forkchoiceUpdated the core sends and whether the core halted it, and forwards
/// both to an `FcuSender` if it has one. The core takes the sender's answers through it, after
/// an answer a test gives it ([`Sink::script`]).
#[derive(Clone, Default)]
struct Sink {
    sent: Arc<Mutex<Vec<ForkchoiceArgs>>>,
    halted: Arc<AtomicBool>,
    fcu: Option<Arc<FcuSender>>,
    script: Arc<Mutex<Option<FcuOutcome>>>,
}

impl Sink {
    /// A sink that forwards to a new `FcuSender` of `el`.
    fn to(el: &El) -> Self {
        Self {
            fcu: Some(Arc::new(el.fcu())),
            ..Self::default()
        }
    }

    fn sent(&self) -> Vec<ForkchoiceArgs> {
        self.sent.lock().unwrap().clone()
    }

    fn halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    /// The answer the core takes next, once: one the mock EL cannot give.
    fn script(&self, outcome: FcuOutcome) {
        *self.script.lock().unwrap() = Some(outcome);
    }

    /// Waits until the sender has the EL's answer to `args`.
    async fn answered(&self, args: &ForkchoiceArgs) {
        let mut outcomes = self.fcu.as_ref().expect("a sender").outcomes();
        let answered = outcomes.wait_for(|o| o.as_ref().is_some_and(|o| o.args == *args));
        drop(
            tokio::time::timeout(WAIT, answered)
                .await
                .expect("the sender must get an answer")
                .unwrap(),
        );
    }
}

impl ForkchoiceSink for Sink {
    fn send(&self, args: ForkchoiceArgs) {
        self.sent.lock().unwrap().push(args);
        if let Some(fcu) = &self.fcu {
            fcu.send(args);
        }
    }

    fn take_outcome(&self) -> Option<FcuOutcome> {
        if let Some(outcome) = self.script.lock().unwrap().take() {
            return Some(outcome);
        }
        self.fcu.as_ref()?.take_outcome()
    }

    fn halt(&self) {
        self.halted.store(true, Ordering::SeqCst);
        if let Some(fcu) = &self.fcu {
            fcu.halt();
        }
    }
}

/// The arguments with these head, safe and finalized hashes.
fn args(head: Hash32, safe: Hash32, finalized: Hash32) -> ForkchoiceArgs {
    ForkchoiceArgs {
        head_block_hash: head,
        safe_block_hash: safe,
        finalized_block_hash: finalized,
        custody_columns: CUSTODY,
    }
}

/// The head, safe and finalized hashes of `args`, as the mock EL reads them.
fn hashes(args: &ForkchoiceArgs) -> [Hash32; 3] {
    [
        args.head_block_hash,
        args.safe_block_hash,
        args.finalized_block_hash,
    ]
}

/// The bid of `block`.
fn bid(block: &Block) -> Bid {
    let bid = &block.message.body.signed_execution_payload_bid.message;
    Bid {
        block_hash: bid.block_hash,
        parent_block_hash: bid.parent_block_hash,
    }
}

/// The bid of the anchor, from the store of `core`.
fn anchor_bid(core: &ChainCore<Minimal>, anchor: &Head) -> Bid {
    let block = core.fork_choice().block(anchor.block_root).unwrap();
    let bid = &block.body.signed_execution_payload_bid.message;
    Bid {
        block_hash: bid.block_hash,
        parent_block_hash: bid.parent_block_hash,
    }
}

/// A sibling of `block` with the same bid and so the same payload: another graffiti, on the same
/// parent, whose post-state is `parent_post`. Sealed, with its post-state.
fn sibling(
    config: &network_config::ChainConfig,
    block: &Block,
    parent_post: &BeaconState<Minimal>,
) -> (Block, BeaconState<Minimal>) {
    let mut block = block.clone();
    block.message.body.graffiti = Bytes32::repeat_byte(0x5c);
    sealed(parent_post, block, config)
}

/// The head node of `block` with `payload_status`.
fn head_of(block: &Block, payload_status: PayloadStatus) -> Head {
    Head {
        block_root: root(block),
        slot: block.message.slot,
        state_root: block.message.state_root,
        payload_status,
    }
}

/// Waits until the last forkchoiceUpdated that reached the mock EL carries the hashes of
/// `want`.
async fn el_sees(el: &El, want: &ForkchoiceArgs) {
    let want = hashes(want);
    tokio::time::timeout(WAIT, async {
        while el.forkchoice_updates().last() != Some(&want) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the mock EL must get {want:?}, it got {:?}",
            el.forkchoice_updates()
        )
    });
}

// ---------------------------------------------------------------------------------------------
// The head and forkchoiceUpdated.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_committed_block_moves_the_head_and_sends_one_forkchoice_update() {
    let el = El::start().await;
    let f = fixture();
    let (p, _) = payload_block(&f, 0x31, 1);
    let Fixture { core, anchor, .. } = f;
    let sink = Sink::to(&el);
    let core = ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY);
    let verify = FakeVerify::new(Answer::Valid);
    assert!(sink.sent().is_empty(), "nothing is sent before a commit");

    let core = commit_all(core, &[&p], &verify).await;
    assert_eq!(
        core.head(),
        head_of(&p, PayloadStatus::Empty),
        "the head is the EMPTY node of the block: its payload is not verified"
    );
    // An EMPTY head is the payload its bid builds on; the anchor is the justified (safe) and the
    // finalized block, so both are the payload its bid builds on.
    let anchor = anchor_bid(&core, &anchor).parent_block_hash;
    let want = args(bid(&p).parent_block_hash, anchor, anchor);
    assert_eq!(sink.sent(), vec![want], "one forkchoiceUpdated");
    assert_eq!(core.forkchoice_sent(), Some(want));
    el_sees(&el, &want).await;
    assert_eq!(el.forkchoice_updates(), vec![hashes(&want)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_imported_envelope_moves_the_head_to_the_full_node_and_the_el_head_to_its_payload() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0x31, 1);
    let Fixture {
        core,
        anchor,
        config,
        ..
    } = f;
    let sink = Sink::to(&el);
    let core = ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY);
    let verify = FakeVerify::new(Answer::Valid);
    let core = commit_all(core, &[&p], &verify).await;
    assert_eq!(sink.sent().len(), 1);

    let (outcome, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p)
        }
    );
    assert_eq!(core.head(), head_of(&p, PayloadStatus::Full));
    let anchor = anchor_bid(&core, &anchor).parent_block_hash;
    let want = args(bid(&p).block_hash, anchor, anchor);
    assert_eq!(want.head_block_hash, hash(0x31), "the bid's block_hash");
    assert_eq!(sink.sent().len(), 2);
    assert_eq!(sink.sent().last(), Some(&want));
    assert_eq!(core.forkchoice_sent(), Some(want));
    el_sees(&el, &want).await;
}

/// A block on the FULL head moves the head to its EMPTY node, which is the same payload for the
/// EL. A block that is already committed is IGNORE. A sibling of a lower root does not move the
/// head. None of them changes the head, safe or finalized hash, so none sends a forkchoiceUpdated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_forkchoice_update_is_sent_while_the_head_safe_and_finalized_hashes_stay() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0x31, 1);
    let (c, _) = full_child(&f, &p, &post, 0x32);
    // A sibling of `p` that loses the root tiebreak to it.
    let (lower, _) = (2..=40)
        .map(|graffiti| payload_block(&f, 0x33, graffiti))
        .find(|(sibling, _)| root(sibling) < root(&p))
        .expect("a sibling with a lower root");
    let Fixture { core, config, .. } = f;
    let sink = Sink::default();
    let core = ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY);
    let verify = FakeVerify::new(Answer::Valid);
    let core = commit_all(core, &[&p], &verify).await;
    let (_, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert_eq!(core.head(), head_of(&p, PayloadStatus::Full));
    assert_eq!(sink.sent().len(), 2, "the commit and the envelope");
    let sent = core.forkchoice_sent();

    let core = commit_all(core, &[&c], &verify).await;
    assert_eq!(core.head(), head_of(&c, PayloadStatus::Empty));
    assert_eq!(bid(&c).parent_block_hash, hash(0x31));
    assert_eq!(
        sink.sent().len(),
        2,
        "the EL head is still the payload of the parent"
    );

    let (outcome, core) = step(core, block_item(&c), &verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    let core = commit_all(core, &[&lower], &verify).await;
    assert_eq!(core.head(), head_of(&c, PayloadStatus::Empty));
    assert_eq!(sink.sent().len(), 2, "nothing changed for the EL");
    assert_eq!(core.forkchoice_sent(), sent);
}

/// When `get_head` fails, the head stays and no forkchoiceUpdated is sent: the old head with the
/// safe and finalized hashes that the store has now is no fork choice of the store. Here test
/// seams take the state of the justified checkpoint out of the store, which `get_head` reads,
/// and finalize `c`, before the envelope of `c` imports. The prune at finality reads only the
/// finalized checkpoint, so it still runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_forkchoice_update_is_sent_when_fork_choice_gives_no_head() {
    let el = El::start().await;
    let f = fixture();
    let (p, p_post) = payload_block(&f, 0x51, 1);
    let (c, c_post) = full_child(&f, &p, &p_post, 0x52);
    let Fixture { core, config, .. } = f;
    let sink = Sink::default();
    let verify = FakeVerify::new(Answer::Valid);
    let core = ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY);
    let core = commit_all(core, &[&p], &verify).await;
    let (outcome, core) = step(core, envelope(&config, &p, &p_post), &verify).await;
    assert!(
        matches!(outcome, Outcome::PayloadVerified { .. }),
        "{outcome:?}"
    );
    let core = commit_all(core, &[&c], &verify).await;
    let head = core.head();
    assert_eq!(head, head_of(&c, PayloadStatus::Empty));
    let sent = sink.sent();
    assert_eq!(sent.len(), 2, "the commit of p and its envelope");
    let forkchoice_sent = core.forkchoice_sent();
    assert_eq!(forkchoice_sent.as_ref(), sent.last());

    let justified = core.fork_choice().justified_checkpoint().clone();
    let finalized = Checkpoint {
        epoch: 1,
        root: root(&c),
    };
    let core = core.with_fork_choice(|store| {
        remove_checkpoint_state(store, &justified);
        set_finalized_checkpoint(store, finalized);
    });
    assert!(
        get_head(core.fork_choice()).is_err(),
        "fork choice must give no head"
    );
    let (outcome, core) = step(core, envelope(&config, &c, &c_post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&c)
        }
    );
    assert_eq!(core.head(), head, "the head stays");
    assert_eq!(
        sink.sent(),
        sent,
        "no forkchoiceUpdated may pair the old head with the new finalized hash"
    );
    assert_eq!(core.forkchoice_sent(), forkchoice_sent);
    assert_eq!(
        core.execution_statuses().status(&hash(0x51)),
        None,
        "the prune at the new finalized checkpoint runs"
    );
}

// ---------------------------------------------------------------------------------------------
// A head whose pre-state left the LRU.

/// `get_head` reads the fork choice store, not the pre-state LRU of the core, so the head can be
/// a block whose pre-state the LRU dropped. The store still holds that post-state, and the core
/// reads it from there: the envelope of the head imports and moves the head to its FULL node,
/// and a child on that payload commits and becomes the head. The head block sent again is still
/// IGNORE, and its envelope sent again does not reach the EL again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_head_whose_pre_state_left_the_lru_imports_its_envelope_and_a_child() {
    let el = El::start().await;
    let f = fixture();
    // One sibling on the anchor's FULL payload more than the LRU holds besides the anchor. With
    // no votes and no proposer boost (the system clock is far past slot 1), the highest root
    // wins: committed first, it is the least recently used when the last sibling commits.
    let lru = u8::try_from(max_pre_states::<Minimal>()).unwrap();
    let mut siblings: Vec<_> = (1..=lru)
        .map(|graffiti| payload_block(&f, 0x41, graffiti))
        .collect();
    siblings.sort_by_cached_key(|(block, _)| Reverse(root(block)));
    let (head, head_post) = siblings[0].clone();
    let (child, _) = full_child(&f, &head, &head_post, 0x42);
    let Fixture { core, config, .. } = f;
    let sink = Sink::default();
    let verify = FakeVerify::new(Answer::Valid);
    let core = ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY);
    let blocks: Vec<&Block> = siblings.iter().map(|(block, _)| block).collect();
    let core = commit_all(core, &blocks, &verify).await;
    assert_eq!(core.head(), head_of(&head, PayloadStatus::Empty));
    assert!(
        core.state(&root(&head)).is_none(),
        "the LRU dropped the pre-state of the head"
    );
    assert!(
        core.fork_choice().block_state(root(&head)).is_some(),
        "the fork choice store still holds it"
    );

    let (outcome, core) = step(core, block_item(&head), &verify).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "a committed block sent again must be IGNORE: {outcome:?}"
    );
    // Both steps read the pre-state of the head, which only the store holds.
    let (verified, core) = step(core, envelope(&config, &head, &head_post), &verify).await;
    let full_head = core.head();
    let el_head = sink.sent().last().map(|args| args.head_block_hash);
    let (committed, core) = step(core, block_item(&child), &verify).await;
    assert_eq!(
        [verified, committed],
        [
            Outcome::PayloadVerified {
                block_root: root(&head)
            },
            Outcome::Committed {
                block_root: root(&child),
                state_root: child.message.state_root
            },
        ],
        "the envelope of the head and a child on its payload must import"
    );
    assert_eq!(full_head, head_of(&head, PayloadStatus::Full));
    assert_eq!(el_head, Some(hash(0x41)), "the EL head is its payload");
    assert_eq!(core.head(), head_of(&child, PayloadStatus::Empty));

    let payloads = el.new_payloads().len();
    let (outcome, core) = step(core, envelope(&config, &head, &head_post), &verify).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "a verified payload: {outcome:?}"
    );
    assert_eq!(
        el.new_payloads().len(),
        payloads,
        "its envelope sent again must not reach the EL"
    );
    assert_eq!(core.head(), head_of(&child, PayloadStatus::Empty));
}

// ---------------------------------------------------------------------------------------------
// Fail closed on an EL contradiction.

/// A core whose EL is about to contradict itself, with its forkchoiceUpdated calls going through
/// the production sender to the mock EL, and what the tests read before the contradiction.
struct Contradicting {
    el: El,
    sink: Sink,
    core: ChainCore<Minimal>,
    verify: Arc<FakeVerify>,
    config: network_config::ChainConfig,
    /// The block whose envelope sets the contradiction, and its post-state.
    second: (Block, BeaconState<Minimal>),
    /// A committed block whose payload is not verified, and its post-state.
    pending: (Block, BeaconState<Minimal>),
    /// A block on the FULL payload of a block whose payload is verified: not imported.
    child: Block,
}

/// Three committed siblings, two with the same payload hash, and the first's payload verified
/// (VALID). The mock EL has the latest forkchoiceUpdated. It will answer INVALID with a
/// `latestValidHash` to the same payload, through the envelope of the second sibling: it calls a
/// VALID payload INVALID.
async fn contradicting() -> Contradicting {
    let el = El::start().await;
    let f = fixture();
    let (first, first_post) = payload_block(&f, 0x71, 1);
    let second = payload_block(&f, 0x71, 2);
    let pending = payload_block(&f, 0x73, 3);
    let (child, _) = full_child(&f, &first, &first_post, 0x74);
    let Fixture { core, config, .. } = f;
    let sink = Sink::to(&el);
    let verify = FakeVerify::new(Answer::Valid);
    let core = ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY);
    let core = commit_all(core, &[&first, &second.0, &pending.0], &verify).await;
    let (outcome, core) = step(core, envelope(&config, &first, &first_post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&first)
        }
    );
    let last = *sink
        .sent()
        .last()
        .expect("the commits send forkchoiceUpdated");
    assert_eq!(core.forkchoice_sent(), Some(last));
    el_sees(&el, &last).await;
    el.answer(hash(0x71), invalid_on(&second.1));
    Contradicting {
        el,
        sink,
        core,
        verify,
        config,
        second,
        pending,
        child,
    }
}

/// What the fail-closed tests compare: the head, the store, and what was sent.
#[derive(Debug, PartialEq)]
struct Seen {
    head: Head,
    store: fork_choice::Store<Minimal>,
    sent: usize,
    forkchoice_sent: Option<ForkchoiceArgs>,
}

fn seen(core: &ChainCore<Minimal>, sink: &Sink) -> Seen {
    Seen {
        head: core.head(),
        store: core.fork_choice().clone(),
        sent: sink.sent().len(),
        forkchoice_sent: core.forkchoice_sent(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_answer_that_sets_the_el_contradiction_sends_no_forkchoice_update() {
    let t = contradicting().await;
    let before = seen(&t.core, &t.sink);
    let updates = t.el.forkchoice_updates().len();
    let (block, post) = &t.second;
    let (outcome, core) = step(t.core, envelope(&t.config, block, post), &t.verify).await;
    assert!(
        core.execution_statuses().el_contradiction(),
        "the EL called a VALID payload INVALID"
    );
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(
        seen(&core, &t.sink),
        before,
        "no forkchoiceUpdated, and the head and the store stay"
    );
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_the_el_contradiction_nothing_reaches_fork_choice_and_no_forkchoice_update_is_sent() {
    let t = contradicting().await;
    let (block, post) = &t.second;
    let (_, core) = step(t.core, envelope(&t.config, block, post), &t.verify).await;
    assert!(core.execution_statuses().el_contradiction());
    let before = seen(&core, &t.sink);
    let updates = t.el.forkchoice_updates().len();
    let payloads = t.el.new_payloads().len();

    let (outcome, core) = step(core, block_item(&t.child), &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(seen(&core, &t.sink), before, "a block");
    let (block, post) = &t.pending;
    let (outcome, core) = step(core, envelope(&t.config, block, post), &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(seen(&core, &t.sink), before, "an envelope");
    assert!(
        core.fork_choice().block(root(&t.child)).is_none(),
        "the store must not hold the block"
    );

    tokio::time::sleep(QUIET).await;
    assert_eq!(
        t.el.forkchoice_updates().len(),
        updates,
        "no forkchoiceUpdated may reach the EL"
    );
    assert_eq!(t.el.new_payloads().len(), payloads, "no newPayload either");
}

/// The forkchoiceUpdated of the FULL head `p` is lost on its way to the EL (the mock EL drops the
/// connection), so the sender tries it again after each backoff. The envelope of `second`, a
/// sibling of `p` with the same payload, sets the EL contradiction: the EL calls that VALID
/// payload INVALID. That answer halts the sender, and no later try reaches the EL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retrying_forkchoice_update_does_not_reach_the_el_after_the_contradiction_latch() {
    let el = El::start().await;
    let f = fixture();
    let (p, p_post) = payload_block(&f, 0x71, 1);
    // It loses the root tiebreak to `p`, so the head stays on `p`.
    let (second, second_post) = (2..=40)
        .map(|graffiti| payload_block(&f, 0x71, graffiti))
        .find(|(sibling, _)| root(sibling) < root(&p))
        .expect("a sibling with a lower root");
    let Fixture { core, config, .. } = f;
    let sink = Sink::to(&el);
    let verify = FakeVerify::new(Answer::Valid);
    let core = ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY);
    el.mock.on_forkchoice_updated(hash(0x71).0, Reply::Drop);
    let core = commit_all(core, &[&p, &second], &verify).await;
    let (outcome, core) = step(core, envelope(&config, &p, &p_post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p)
        }
    );
    assert_eq!(core.head(), head_of(&p, PayloadStatus::Full));
    let lost = *sink.sent().last().unwrap();
    assert_eq!(lost.head_block_hash, hash(0x71));
    let tries = || {
        let updates = el.forkchoice_updates();
        updates.iter().filter(|u| **u == hashes(&lost)).count()
    };
    tokio::time::timeout(WAIT, async {
        while tries() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the sender must try the lost call again");

    el.answer(hash(0x71), invalid_on(&second_post));
    let before = seen(&core, &sink);
    let (outcome, core) = step(core, envelope(&config, &second, &second_post), &verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(core.execution_statuses().el_contradiction());
    assert!(
        sink.halted(),
        "the answer that sets the contradiction halts the sender"
    );
    assert_eq!(seen(&core, &sink), before);
    let updates = el.forkchoice_updates().len();
    // Past the next backoff of the sender: 2 s after its second try, then 4 s.
    tokio::time::sleep(BACKOFF_MIN * 4 + QUIET).await;
    assert_eq!(
        el.forkchoice_updates().len(),
        updates,
        "no try of the lost call may reach the EL after the latch"
    );
}

// ---------------------------------------------------------------------------------------------
// Finality.

/// Two payloads on the anchor's (VALID), one on the first of them that the EL found INVALID,
/// and the block `c` on the first FULL. Fork choice finalizes `c` (a test seam stands for a
/// finalizing chain), and the next envelope import, of `c`, sees the new finalized checkpoint.
/// The core prunes its execution statuses at the payload the forkchoiceUpdated sends as
/// `finalizedBlockHash`, the bid `parent_block_hash` of `c`: that payload and the fork off its
/// ancestors go, and the INVALID payload that descends from it stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_finalized_checkpoint_prunes_the_execution_statuses_at_its_bid_parent_hash() {
    let el = El::start().await;
    let f = fixture();
    let (p, p_post) = payload_block(&f, 0x31, 1);
    let (fork, fork_post) = payload_block(&f, 0x33, 2);
    let (c, c_post) = full_child(&f, &p, &p_post, 0x32);
    let (bad, bad_post) = full_child(&f, &p, &p_post, 0x35);
    let Fixture {
        core,
        anchor,
        config,
        ..
    } = f;
    let sink = Sink::default();
    let verify = FakeVerify::new(Answer::Valid);
    let core = ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY);
    let mut core = commit_all(core, &[&p, &fork], &verify).await;
    for (block, post) in [(&p, &p_post), (&fork, &fork_post)] {
        let (outcome, next) = step(core, envelope(&config, block, post), &verify).await;
        assert!(
            matches!(outcome, Outcome::PayloadVerified { .. }),
            "{outcome:?}"
        );
        core = next;
    }
    let core = commit_all(core, &[&c, &bad], &verify).await;
    el.answer(hash(0x35), invalid_on(&bad_post));
    let (outcome, core) = step(core, envelope(&config, &bad, &bad_post), &verify).await;
    assert!(
        matches!(outcome, Outcome::InvalidEnvelope(_)),
        "{outcome:?}"
    );
    let statuses = core.execution_statuses();
    assert_eq!(statuses.len(), 3);
    assert_eq!(statuses.status(&hash(0x35)), Some(ExecutionStatus::Invalid));

    let finalized = Checkpoint {
        epoch: 1,
        root: root(&c),
    };
    let core = core.with_fork_choice(|store| set_finalized_checkpoint(store, finalized));
    let (outcome, core) = step(core, envelope(&config, &c, &c_post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&c)
        }
    );
    assert_eq!(core.head(), head_of(&c, PayloadStatus::Full));
    let safe = anchor_bid(&core, &anchor).parent_block_hash;
    let want = args(hash(0x32), safe, bid(&c).parent_block_hash);
    assert_eq!(want.finalized_block_hash, hash(0x31));
    assert_eq!(sink.sent().last(), Some(&want));

    let statuses = core.execution_statuses();
    assert_eq!(
        statuses.len(),
        2,
        "the table shrinks: 0x32 came in, the finalized payload and the fork went"
    );
    for gone in [0x31, 0x33] {
        assert_eq!(statuses.status(&hash(gone)), None, "{gone:#x}");
    }
    assert_eq!(statuses.status(&hash(0x32)), Some(ExecutionStatus::Valid));
    assert_eq!(
        statuses.status(&hash(0x35)),
        Some(ExecutionStatus::Invalid),
        "an INVALID payload after the finalized one stays"
    );
}

// ---------------------------------------------------------------------------------------------
// A later INVALID.

/// A core with the payload of `p` imported (the EL answers `p_answer` to its newPayload) and,
/// for the tests that need it, `c` on that FULL payload committed: the core, its sink, the
/// blocks and their post-states.
struct Later {
    el: El,
    sink: Sink,
    core: ChainCore<Minimal>,
    verify: Arc<FakeVerify>,
    config: network_config::ChainConfig,
    p: (Block, BeaconState<Minimal>),
    c: (Block, BeaconState<Minimal>),
}

/// The EL answers `p_answer` to the newPayload of the payload of `p`, `0x31`, and `fcu_answer` of
/// the post-state of `p` to its forkchoiceUpdated; `c` builds on it with the payload `0x32`.
/// Commits `p`, imports its envelope, and waits for the answer to the forkchoiceUpdated of the
/// FULL head `p`.
async fn later(p_answer: Reply, fcu_answer: impl FnOnce(&BeaconState<Minimal>) -> Reply) -> Later {
    later_with(p_answer, fcu_answer, |core| core).await
}

/// [`later`] on the core that `edit` gives before the commit of `p`, for example with a test
/// clock.
async fn later_with(
    p_answer: Reply,
    fcu_answer: impl FnOnce(&BeaconState<Minimal>) -> Reply,
    edit: impl FnOnce(ChainCore<Minimal>) -> ChainCore<Minimal>,
) -> Later {
    let el = El::start().await;
    let f = fixture();
    let p = payload_block(&f, 0x31, 1);
    let c = full_child(&f, &p.0, &p.1, 0x32);
    let Fixture { core, config, .. } = f;
    let sink = Sink::to(&el);
    let verify = FakeVerify::new(Answer::Valid);
    let core = edit(ready(core, &el).with_forkchoice_sink(sink.clone(), CUSTODY));
    el.answer(hash(0x31), p_answer);
    el.mock
        .on_forkchoice_updated(hash(0x31).0, fcu_answer(&p.1));
    let core = commit_all(core, &[&p.0], &verify).await;
    let (outcome, core) = step(core, envelope(&config, &p.0, &p.1), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p.0)
        }
    );
    assert_eq!(core.head(), head_of(&p.0, PayloadStatus::Full));
    let sent = sink.sent();
    assert_eq!(sent.len(), 2, "the commit and the envelope");
    assert_eq!(
        sent[1].head_block_hash,
        hash(0x31),
        "the EL head is the payload of p"
    );
    sink.answered(&sent[1]).await;
    Later {
        el,
        sink,
        core,
        verify,
        config,
        p,
        c,
    }
}

/// The EL took the payload of `p` optimistically (SYNCING), and answers INVALID to the
/// forkchoiceUpdated of the FULL head `p`, with the parent of that payload as `latestValidHash`.
/// At its next turn the core records it: the payload is Invalid, the store no longer has it
/// verified, the head moves to the EMPTY node of `p`, and the core sends one forkchoiceUpdated
/// with that head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_fcu_invalid_with_a_latest_valid_hash_moves_the_head_off_its_payload() {
    let t = later(Reply::Syncing, invalid_on).await;
    let (p, _) = &t.p;
    let sent = t.sink.sent();
    let [empty, full] = sent[..] else {
        panic!("{sent:?}")
    };

    let (outcome, core) = step(t.core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(!core.execution_statuses().el_contradiction());
    assert_eq!(
        core.execution_statuses().status(&hash(0x31)),
        Some(ExecutionStatus::Invalid)
    );
    assert!(
        !is_payload_verified(core.fork_choice(), root(p)),
        "the store must no longer have the payload verified"
    );
    assert_eq!(core.head(), head_of(p, PayloadStatus::Empty));
    assert_eq!(
        t.sink.sent(),
        vec![empty, full, empty],
        "one forkchoiceUpdated with the new head"
    );
    assert_eq!(core.forkchoice_sent(), Some(empty));
    el_sees(&t.el, &empty).await;
}

/// The same INVALID answer to the forkchoiceUpdated of `p`, but the EL found that payload
/// VALID: it contradicts itself. The core halts the sender and changes nothing: the store still
/// has the payload verified, the head stays, and no forkchoiceUpdated is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_fcu_invalid_that_contradicts_the_el_moves_nothing_and_halts_the_sender() {
    let t = later(Reply::Valid, invalid_on).await;
    let (p, _) = &t.p;
    let full = *t.sink.sent().last().unwrap();
    el_sees(&t.el, &full).await;
    let updates = t.el.forkchoice_updates().len();
    let before = seen(&t.core, &t.sink);

    let (outcome, core) = step(t.core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(core.execution_statuses().el_contradiction());
    assert!(t.sink.halted(), "the contradiction halts the sender");
    assert_eq!(seen(&core, &t.sink), before);
    assert!(is_payload_verified(core.fork_choice(), root(p)));
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// The EL took the payload of `p` optimistically (SYNCING, also for its forkchoiceUpdated), and
/// `c` builds on that FULL payload. The newPayload of the envelope of `c` is INVALID with the
/// parent of the payload of `p` as `latestValidHash`: both payloads are Invalid. The store no
/// longer has the payload of `p` verified, the head moves off its FULL node (and off `c`) to its
/// EMPTY node, and the core sends one forkchoiceUpdated with that head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_new_payload_invalid_moves_the_head_off_the_full_node() {
    let t = later(Reply::Syncing, |_| Reply::Syncing).await;
    let (p, p_post) = &t.p;
    let (c, c_post) = &t.c;
    let core = commit_all(t.core, &[c], &t.verify).await;
    assert_eq!(core.head(), head_of(c, PayloadStatus::Empty));
    let sent = t.sink.sent();
    let [empty, full] = sent[..] else {
        panic!("the EL head is still the payload of p: {sent:?}")
    };

    t.el.answer(hash(0x32), invalid_on(p_post));
    let (outcome, core) = step(core, envelope(&t.config, c, c_post), &t.verify).await;
    assert!(
        matches!(outcome, Outcome::InvalidEnvelope(_)),
        "{outcome:?}"
    );
    let statuses = core.execution_statuses();
    assert!(!statuses.el_contradiction());
    for n in [0x31, 0x32] {
        assert_eq!(
            statuses.status(&hash(n)),
            Some(ExecutionStatus::Invalid),
            "{n:#x}"
        );
    }
    assert!(
        !is_payload_verified(core.fork_choice(), root(p)),
        "the store must no longer have the payload of p verified"
    );
    assert_eq!(core.head(), head_of(p, PayloadStatus::Empty));
    assert_eq!(
        t.sink.sent(),
        vec![empty, full, empty],
        "one forkchoiceUpdated with the new head"
    );
    assert_eq!(core.forkchoice_sent(), Some(empty));
    el_sees(&t.el, &empty).await;
}

/// The same newPayload INVALID for `c`, but the EL found the payload of `p` VALID: the INVALID
/// contradicts it. The core halts the sender and changes nothing: the store still has the
/// payload of `p` verified, the head stays on `c`, and no forkchoiceUpdated is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_new_payload_invalid_that_contradicts_the_el_moves_nothing() {
    let t = later(Reply::Valid, |_| Reply::Valid).await;
    let (p, p_post) = &t.p;
    let (c, c_post) = &t.c;
    let core = commit_all(t.core, &[c], &t.verify).await;
    el_sees(&t.el, t.sink.sent().last().unwrap()).await;
    let updates = t.el.forkchoice_updates().len();
    let before = seen(&core, &t.sink);

    t.el.answer(hash(0x32), invalid_on(p_post));
    let (outcome, core) = step(core, envelope(&t.config, c, c_post), &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(core.execution_statuses().el_contradiction());
    assert!(
        t.sink.halted(),
        "the answer that sets the contradiction halts the sender"
    );
    assert_eq!(seen(&core, &t.sink), before, "the head and the store stay");
    assert!(is_payload_verified(core.fork_choice(), root(p)));
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// Fork choice finalizes `c`, on the FULL payload of `p` (a test seam stands for a finalizing
/// chain): the finalized execution hash, the `finalizedBlockHash` the core sends, is the payload
/// of `p`, which the EL took optimistically. The newPayload of the envelope of `c` is INVALID
/// with the parent of that payload, an ancestor of the finalized execution hash, as
/// `latestValidHash`: it calls the finalized payload invalid. That is an EL contradiction, and
/// the core fails closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_below_the_finalized_execution_hash_is_an_el_contradiction() {
    let t = later(Reply::Syncing, |_| Reply::Syncing).await;
    let (p, p_post) = &t.p;
    let (c, c_post) = &t.c;
    let core = commit_all(t.core, &[c], &t.verify).await;
    el_sees(&t.el, t.sink.sent().last().unwrap()).await;
    let finalized = Checkpoint {
        epoch: 1,
        root: root(c),
    };
    let core = core.with_fork_choice(|store| set_finalized_checkpoint(store, finalized));
    assert_eq!(
        bid(c).parent_block_hash,
        hash(0x31),
        "the finalized execution hash"
    );
    let updates = t.el.forkchoice_updates().len();
    let before = seen(&core, &t.sink);

    t.el.answer(hash(0x32), invalid_on(p_post));
    let (outcome, core) = step(core, envelope(&t.config, c, c_post), &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(
        core.execution_statuses().el_contradiction(),
        "an INVALID below the finalized execution hash contradicts finality"
    );
    assert_eq!(
        core.execution_statuses().status(&hash(0x32)),
        Some(ExecutionStatus::Invalid),
        "the invalid payload stays recorded"
    );
    assert!(t.sink.halted());
    assert_eq!(seen(&core, &t.sink), before, "the head and the store stay");
    assert!(is_payload_verified(core.fork_choice(), root(p)));
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// The `later` core with `c` committed, and its payload `0x32`, which the EL takes
/// optimistically, imported. With `twin`, a sibling of `c` with the same payload is committed
/// with `c`, and returned. If the head is the FULL node of `c`, the EL answers `fcu_answer` to its
/// forkchoiceUpdated, and the core has not taken the answer yet.
async fn with_the_payload_of_c(
    fcu_answer: Reply,
    twin: bool,
) -> (Later, Option<(Block, BeaconState<Minimal>)>) {
    let mut t = later(Reply::Syncing, |_| Reply::Syncing).await;
    let (c, c_post) = &t.c;
    let twin = twin.then(|| sibling(&t.config, c, &t.p.1));
    let blocks: Vec<&Block> = [c]
        .into_iter()
        .chain(twin.as_ref().map(|(block, _)| block))
        .collect();
    let core = commit_all(t.core, &blocks, &t.verify).await;
    t.el.answer(hash(0x32), Reply::Syncing);
    t.el.mock.on_forkchoice_updated(hash(0x32).0, fcu_answer);
    let (outcome, core) = step(core, envelope(&t.config, c, c_post), &t.verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(c)
        }
    );
    if core.head() == head_of(c, PayloadStatus::Full) {
        let full = *t.sink.sent().last().unwrap();
        assert_eq!(full.head_block_hash, hash(0x32));
        t.sink.answered(&full).await;
    }
    t.core = core;
    (t, twin)
}

/// [`with_the_payload_of_c`], then fork choice finalizes `c` (a test seam stands for a
/// finalizing chain): the finalized execution hash, the `finalizedBlockHash` the core sends, is
/// the payload of `p`, `0x31`.
async fn finalized_on_the_payload_of_p(
    fcu_answer: Reply,
    twin: bool,
) -> (Later, Option<(Block, BeaconState<Minimal>)>) {
    let (mut t, twin) = with_the_payload_of_c(fcu_answer, twin).await;
    let (c, _) = &t.c;
    let finalized = Checkpoint {
        epoch: 1,
        root: root(c),
    };
    t.core = t
        .core
        .with_fork_choice(|store| set_finalized_checkpoint(store, finalized));
    assert_eq!(
        bid(c).parent_block_hash,
        hash(0x31),
        "the finalized execution hash"
    );
    (t, twin)
}

/// After an INVALID whose `latestValidHash` is the finalized execution hash `0x31`: no EL
/// contradiction and no halt, the payload of `c` is Invalid and the store no longer has it
/// verified, the head moves from `before` to the EMPTY node of `c`, and the core sends one
/// forkchoiceUpdated with it after the `sent` before, which reaches the EL.
async fn moved_off_the_payload_of_c(
    el: &El,
    sink: &Sink,
    c: &Block,
    core: &ChainCore<Minimal>,
    before: Head,
    sent: usize,
) {
    let statuses = core.execution_statuses();
    assert!(
        !statuses.el_contradiction(),
        "a latestValidHash equal to the finalized execution hash is honest"
    );
    assert!(!sink.halted(), "the sender must not halt");
    assert_eq!(statuses.status(&hash(0x32)), Some(ExecutionStatus::Invalid));
    assert!(
        !is_payload_verified(core.fork_choice(), root(c)),
        "the store must no longer have the payload of c verified"
    );
    assert_ne!(core.head(), before, "the head moves");
    assert_eq!(core.head(), head_of(c, PayloadStatus::Empty));
    let all = sink.sent();
    assert_eq!(all.len(), sent + 1, "one forkchoiceUpdated: {all:?}");
    let last = all[sent];
    assert_eq!(
        (last.head_block_hash, last.finalized_block_hash),
        (hash(0x31), hash(0x31))
    );
    assert_eq!(core.forkchoice_sent(), Some(last));
    el_sees(el, &last).await;
}

/// The EL answers INVALID to the forkchoiceUpdated of the FULL head `c`, with the finalized
/// execution hash `0x31` as `latestValidHash`. That is the ordinary boundary: the payload of `c`,
/// above it, is invalid, and finality is not contradicted. At its next turn the core records it,
/// and the head moves off the payload of `c` with one forkchoiceUpdated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_fcu_invalid_whose_latest_valid_hash_is_the_finalized_execution_hash_moves_the_head() {
    let at_finalized = Reply::Invalid {
        lvh: Some(hash(0x31).0),
    };
    let (t, _) = finalized_on_the_payload_of_p(at_finalized, false).await;
    let (c, _) = &t.c;
    let before = t.core.head();
    assert_eq!(before, head_of(c, PayloadStatus::Full));
    let sent = t.sink.sent().len();

    let (outcome, core) = step(t.core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    moved_off_the_payload_of_c(&t.el, &t.sink, c, &core, before, sent).await;
}

/// The same boundary through newPayload. A sibling of `c` with the same payload `0x32` is
/// committed with `c`. The newPayload of its envelope is INVALID with the finalized execution
/// hash `0x31` as `latestValidHash`: the envelope is refused, and the head moves off the payload
/// of `c` with one forkchoiceUpdated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_payload_invalid_whose_latest_valid_hash_is_the_finalized_execution_hash_moves_the_head(
) {
    let (t, twin) = finalized_on_the_payload_of_p(Reply::Syncing, true).await;
    let (c, _) = &t.c;
    let (twin, twin_post) = twin.unwrap();
    assert_eq!(bid(&twin), bid(c), "the same payload");
    assert_ne!(root(&twin), root(c));
    let before = t.core.head();
    let sent = t.sink.sent().len();

    t.el.answer(
        hash(0x32),
        Reply::Invalid {
            lvh: Some(hash(0x31).0),
        },
    );
    let (outcome, core) = step(t.core, envelope(&t.config, &twin, &twin_post), &t.verify).await;
    assert!(
        matches!(outcome, Outcome::InvalidEnvelope(_)),
        "{outcome:?}"
    );
    moved_off_the_payload_of_c(&t.el, &t.sink, c, &core, before, sent).await;
}
/// INVALID_BLOCK_HASH is a newPayload status, which a forkchoiceUpdated must not answer. Here
/// the answer to the forkchoiceUpdated of the FULL head `p` is INVALID_BLOCK_HASH (the mock EL
/// gives no such answer, so the test sink does): a protocol fault, and so an EL contradiction.
/// At its next turn the core halts the sender and changes nothing. It records nothing for the
/// head hash (the payload of `p` stays Optimistic), the store still has that payload verified,
/// the head stays, and no forkchoiceUpdated is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_fcu_invalid_block_hash_is_a_protocol_fault_that_halts_and_records_nothing() {
    let t = later(Reply::Syncing, |_| Reply::Syncing).await;
    let (p, _) = &t.p;
    let fcu = t.sink.fcu.as_ref().unwrap();
    let mut answer = fcu
        .take_outcome()
        .expect("the answer to the forkchoiceUpdated of p");
    assert_eq!(answer.args.head_block_hash, hash(0x31));
    answer.response.status = Some(pb::PayloadStatus {
        status: pb::PayloadStatusKind::InvalidBlockHash as i32,
        latest_valid_hash: Vec::new(),
        validation_error: String::new(),
    });
    t.sink.script(answer);
    let recorded = t.core.execution_statuses().len();
    assert_eq!(
        t.core.execution_statuses().status(&hash(0x31)),
        Some(ExecutionStatus::Optimistic)
    );
    el_sees(&t.el, t.sink.sent().last().unwrap()).await;
    let updates = t.el.forkchoice_updates().len();
    let before = seen(&t.core, &t.sink);

    let (outcome, core) = step(t.core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    let statuses = core.execution_statuses();
    assert!(
        statuses.el_contradiction(),
        "INVALID_BLOCK_HASH to a forkchoiceUpdated is a protocol fault"
    );
    assert!(t.sink.halted(), "the fault halts the sender");
    assert_eq!(
        statuses.status(&hash(0x31)),
        Some(ExecutionStatus::Optimistic),
        "nothing is recorded for the head hash"
    );
    assert_eq!(statuses.len(), recorded);
    assert_eq!(seen(&core, &t.sink), before, "the head and the store stay");
    assert!(is_payload_verified(core.fork_choice(), root(p)));
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// The EL took the payloads of `p` and `c` optimistically, and `e` builds on the FULL payload of
/// `c`. The answer to the forkchoiceUpdated of the FULL head `p` comes late: fork choice
/// finalizes `e` first (a test seam stands for a finalizing chain), so the finalized execution
/// hash is the payload of `c`, and at the start of the next turn the core prunes it and its
/// parent, the payload of `p`, from the table. Then it takes the answer: INVALID for the payload
/// of `p`, with its execution parent as `latestValidHash`. Finality has passed that payload, so
/// this is an EL contradiction: the core halts the sender and records nothing for the gone
/// payload, and the head, the store and the forkchoiceUpdated calls stay as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_fcu_invalid_for_a_payload_finality_pruned_halts_and_records_nothing() {
    let t = later(Reply::Syncing, |_| Reply::Syncing).await;
    let (p, p_post) = &t.p;
    let (c, c_post) = &t.c;
    let fcu = t.sink.fcu.as_ref().unwrap();
    let answer = fcu
        .take_outcome()
        .expect("the answer to the forkchoiceUpdated of p");
    assert_eq!(answer.args.head_block_hash, hash(0x31));
    let core = commit_all(t.core, &[c], &t.verify).await;
    t.el.answer(hash(0x32), Reply::Syncing);
    let (outcome, core) = step(core, envelope(&t.config, c, c_post), &t.verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(c)
        }
    );
    let (e, _) = full_child_at(&t.config, c, c_post, c.message.slot + 1, 0x36);
    let core = commit_all(core, &[&e], &t.verify).await;
    let finalized = Checkpoint {
        epoch: 1,
        root: root(&e),
    };
    let core = core.with_fork_choice(|store| set_finalized_checkpoint(store, finalized));
    assert_eq!(
        bid(&e).parent_block_hash,
        hash(0x32),
        "the finalized execution hash"
    );
    assert_eq!(
        [0x31, 0x32].map(|n| core.execution_statuses().status(&hash(n))),
        [Some(ExecutionStatus::Optimistic); 2]
    );
    el_sees(&t.el, t.sink.sent().last().unwrap()).await;
    let updates = t.el.forkchoice_updates().len();
    let before = seen(&core, &t.sink);

    t.sink
        .script(invalid_answer(answer, p_post.latest_block_hash));
    let (outcome, core) = step(core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    let statuses = core.execution_statuses();
    assert_eq!(
        [0x31, 0x32].map(|n| statuses.status(&hash(n))),
        [None, None],
        "finality pruned both payloads, and the answer records nothing"
    );
    assert!(
        statuses.el_contradiction(),
        "an INVALID for a payload below the finalized execution hash contradicts finality"
    );
    assert!(t.sink.halted(), "the contradiction halts the sender");
    assert_eq!(seen(&core, &t.sink), before, "the head and the store stay");
    assert!(is_payload_verified(core.fork_choice(), root(p)));
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

// ---------------------------------------------------------------------------------------------
// The justified checkpoint on an invalid payload, and a later INVALID that changes nothing.

/// `outcome`, the answer to a forkchoiceUpdated, as INVALID with `latest_valid_hash`.
fn invalid_answer(mut outcome: FcuOutcome, latest_valid_hash: Hash32) -> FcuOutcome {
    outcome.response.status = Some(pb::PayloadStatus {
        status: pb::PayloadStatusKind::Invalid as i32,
        latest_valid_hash: latest_valid_hash.0.to_vec(),
        validation_error: String::new(),
    });
    outcome
}

/// The `later` core where the EL took the payload of `p` optimistically, with `c` on that FULL
/// payload committed. Fork choice finalizes `p` and justifies `c` (test seams stand for a
/// finalizing chain), so the finalized execution hash is the execution parent of the payload of
/// `p`. Then the EL answers INVALID to the forkchoiceUpdated of that payload, with that
/// execution parent as `latestValidHash`: honest, as it is not below the finalized execution
/// hash. The justified block builds on a payload that the EL found invalid, and `get_head`
/// starts there (`bellatrix/optimistic-sync.md`, Re-Orgs: the justified checkpoint becomes
/// `INVALIDATED`). The core fails closed: it sets the EL contradiction and halts the sender, and
/// the head, the store and the forkchoiceUpdated calls stay as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_payload_below_the_justified_checkpoint_halts_and_moves_nothing() {
    let t = later(Reply::Syncing, |_| Reply::Syncing).await;
    let (p, p_post) = &t.p;
    let (c, _) = &t.c;
    let fcu = t.sink.fcu.as_ref().unwrap();
    let answer = fcu
        .take_outcome()
        .expect("the answer to the forkchoiceUpdated of p");
    assert_eq!(answer.args.head_block_hash, hash(0x31));
    let core = commit_all(t.core, &[c], &t.verify).await;
    assert_eq!(core.head(), head_of(c, PayloadStatus::Empty));
    let finalized = Checkpoint {
        epoch: 1,
        root: root(p),
    };
    let justified = Checkpoint {
        epoch: 2,
        root: root(c),
    };
    let core = core.with_fork_choice(|store| {
        set_finalized_checkpoint(store, finalized);
        set_justified_checkpoint(store, justified);
    });
    let execution_parent = p_post.latest_block_hash;
    assert_eq!(
        bid(p).parent_block_hash,
        execution_parent,
        "the finalized execution hash"
    );
    el_sees(&t.el, t.sink.sent().last().unwrap()).await;
    let updates = t.el.forkchoice_updates().len();
    let before = seen(&core, &t.sink);

    t.sink.script(invalid_answer(answer, execution_parent));
    let (outcome, core) = step(core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    let statuses = core.execution_statuses();
    assert_eq!(statuses.status(&hash(0x31)), Some(ExecutionStatus::Invalid));
    assert!(
        statuses.el_contradiction(),
        "the justified checkpoint builds on an invalid payload"
    );
    assert!(t.sink.halted(), "the core halts the sender");
    assert_eq!(seen(&core, &t.sink), before, "the head and the store stay");
    assert!(is_payload_verified(core.fork_choice(), root(p)));
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// Fork choice justifies `c` (a test seam stands for a justifying chain), and the EL answers
/// INVALID to the forkchoiceUpdated of the FULL head `c`, with the payload of `p` as
/// `latestValidHash`: only the justified block's own payload is invalid. `get_head` can stay on
/// the EMPTY node of `c`, so this is no contradiction: the core does not halt, the payload of `c`
/// leaves the store, and the head moves to the EMPTY node of `c` with one forkchoiceUpdated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_payload_of_the_justified_block_alone_moves_the_head_to_its_empty_node() {
    let at_p = Reply::Invalid {
        lvh: Some(hash(0x31).0),
    };
    let (mut t, _) = with_the_payload_of_c(at_p, false).await;
    let (p, _) = &t.p;
    let (c, _) = &t.c;
    assert_eq!(t.core.head(), head_of(c, PayloadStatus::Full));
    let justified = Checkpoint {
        epoch: 1,
        root: root(c),
    };
    t.core = t
        .core
        .with_fork_choice(|store| set_justified_checkpoint(store, justified));
    let sent = t.sink.sent().len();

    let (outcome, core) = step(t.core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    let statuses = core.execution_statuses();
    assert!(!statuses.el_contradiction());
    assert!(!t.sink.halted(), "the sender must not halt");
    assert_eq!(
        [0x31, 0x32].map(|n| statuses.status(&hash(n))),
        [Some(ExecutionStatus::Valid), Some(ExecutionStatus::Invalid)]
    );
    assert!(!is_payload_verified(core.fork_choice(), root(c)));
    assert!(is_payload_verified(core.fork_choice(), root(p)));
    assert_eq!(core.head(), head_of(c, PayloadStatus::Empty));
    let all = t.sink.sent();
    assert_eq!(all.len(), sent + 1, "one forkchoiceUpdated: {all:?}");
    let last = all[sent];
    assert_eq!(
        (last.head_block_hash, last.safe_block_hash),
        (hash(0x31), hash(0x31))
    );
    el_sees(&t.el, &last).await;
}

/// The start of slot `slot` of the chain of `core`, in Unix milliseconds.
fn slot_time(core: &ChainCore<Minimal>, slot: u64) -> u128 {
    let store = core.fork_choice();
    u128::from(store.genesis_time_ms() + slot * store.slot_duration_ms().get())
}

/// A sibling of `p` on the anchor of `core` with another graffiti and another payload, `0x33`:
/// a block that the core still admits once the payload of `p` is Invalid. Sealed.
fn other_payload(
    core: &ChainCore<Minimal>,
    p: &Block,
    config: &network_config::ChainConfig,
) -> Block {
    let mut other = p.clone();
    other.message.body.graffiti = Bytes32::repeat_byte(0x5d);
    other
        .message
        .body
        .signed_execution_payload_bid
        .message
        .block_hash = hash(0x33);
    let anchor = p.message.parent_root;
    sealed(core.state(&anchor).unwrap(), other, config).0
}

/// The `later` core on a test clock in the last slot of epoch 0, where the EL took the payload of
/// `p` optimistically, with `c` on that FULL payload committed. The anchor is the justified and
/// the finalized block. The newPayload of the envelope of `c` is INVALID with the execution
/// parent of the payload of `p` as `latestValidHash`: the justified block builds on neither
/// payload, so the payload of `p` leaves the store and the head moves to the EMPTY node of `p`.
/// Then a block pulls the unrealized justified checkpoint up to `c` (a test seam stands for a
/// justifying chain), and the clock reaches the first slot of epoch 1. The next import, a
/// sibling of `p` with another payload, ticks the store there: `on_tick` makes `c` the justified
/// block, and `c` builds on the payload that left the store, where `get_head` would start. The
/// core fails closed: it sets the EL contradiction, halts the sender and commits nothing, and the
/// head, the verified payloads and the forkchoiceUpdated calls stay as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_justified_checkpoint_promoted_onto_a_removed_payload_halts_and_commits_nothing() {
    let epoch = Minimal::slots_per_epoch();
    let end_of_epoch_0 = |core: ChainCore<Minimal>| {
        let at = slot_time(&core, epoch - 1);
        core.with_clock(clock_at(at))
    };
    let t = later_with(Reply::Syncing, |_| Reply::Syncing, end_of_epoch_0).await;
    let (p, p_post) = &t.p;
    let (c, c_post) = &t.c;
    let anchor = p.message.parent_root;
    let core = commit_all(t.core, &[c], &t.verify).await;
    t.el.answer(hash(0x32), invalid_on(p_post));
    let (outcome, core) = step(core, envelope(&t.config, c, c_post), &t.verify).await;
    assert!(
        matches!(outcome, Outcome::InvalidEnvelope(_)),
        "{outcome:?}"
    );
    assert!(!core.execution_statuses().el_contradiction());
    assert!(!t.sink.halted());
    assert_eq!(core.fork_choice().justified_checkpoint().root, anchor);
    let verified = |core: &ChainCore<Minimal>| {
        [anchor, root(p), root(c)].map(|block| is_payload_verified(core.fork_choice(), block))
    };
    assert_eq!(
        verified(&core),
        [true, false, false],
        "the payload of p left the store"
    );
    let head = core.head();
    assert_eq!(head, head_of(p, PayloadStatus::Empty));
    let sent = t.sink.sent();
    let forkchoice_sent = core.forkchoice_sent();
    assert_eq!(forkchoice_sent.as_ref(), sent.last());
    el_sees(&t.el, sent.last().unwrap()).await;
    let updates = t.el.forkchoice_updates().len();

    let other = other_payload(&core, p, &t.config);
    let justified = Checkpoint {
        epoch: 1,
        root: root(c),
    };
    let start_of_epoch_1 = clock_at(slot_time(&core, epoch));
    let core = core
        .with_fork_choice(|store| set_unrealized_justified_checkpoint(store, justified.clone()))
        .with_clock(start_of_epoch_1);
    let (outcome, core) = step(core, block_item(&other), &t.verify).await;
    assert_eq!(
        core.fork_choice().justified_checkpoint(),
        &justified,
        "on_tick of the import makes c the justified block"
    );
    assert!(
        core.execution_statuses().el_contradiction(),
        "the justified block builds on a payload that left the store"
    );
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(t.sink.halted(), "the core halts the sender");
    assert!(
        !core.is_committed(&root(&other)),
        "the import commits nothing"
    );
    assert!(
        core.fork_choice().block(root(&other)).is_none(),
        "on_block does not run"
    );
    assert_eq!(core.head(), head, "the head stays");
    assert_eq!(verified(&core), [true, false, false]);
    assert_eq!(t.sink.sent(), sent, "no forkchoiceUpdated");
    assert_eq!(core.forkchoice_sent(), forkchoice_sent);
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// The justified checkpoint `(2, d)` and the finalized checkpoint `(1, c)` that a test seam gives
/// a store, with `d` the block of slot 9 on the EMPTY node of `c`: `c` is the last block of the
/// chain of `d` at the first slot of epoch 1, and `d` at the first slot of epoch 2.
fn justified_on_d_finalized_on_c(c: &Block, d: &Block) -> (Checkpoint, Checkpoint) {
    let justified = Checkpoint {
        epoch: 2,
        root: root(d),
    };
    let finalized = Checkpoint {
        epoch: 1,
        root: root(c),
    };
    (justified, finalized)
}

/// The `later` core on a test clock in the last slot of epoch 1, where the EL took the payload of
/// `p` optimistically, with `c` on that FULL payload and `d` on the EMPTY node of `c` committed.
/// The anchor is the justified and the finalized block. The newPayload of the envelope of `c` is
/// INVALID with the execution parent of the payload of `p` as `latestValidHash`: the justified
/// block builds on neither payload, so the payload of `p` leaves the store. Then blocks pull the
/// unrealized justified checkpoint up to `d` and the unrealized finalized checkpoint up to `c`
/// (test seams stand for a justifying and finalizing chain), and the clock reaches the first slot
/// of epoch 2. The next import, a sibling of `p` with another payload, ticks the store there: one
/// `on_tick` makes `d` the justified and `c` the finalized block, and its prune drops `p`, the
/// parent of `c`. Below `d` the walk must not stop at the new finalized block: `c` builds on the
/// payload that left the store, so the walk goes down to the finalized block before the tick, and
/// before the prune. The core fails closed: it sets the EL contradiction, halts the sender and
/// commits nothing, and the head, the verified payloads and the forkchoiceUpdated calls stay as
/// they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tick_that_moves_justified_and_finalized_past_a_removed_payload_halts_and_commits_nothing(
) {
    let epoch = Minimal::slots_per_epoch();
    let end_of_epoch_1 = |core: ChainCore<Minimal>| {
        let at = slot_time(&core, 2 * epoch - 1);
        core.with_clock(clock_at(at))
    };
    let t = later_with(Reply::Syncing, |_| Reply::Syncing, end_of_epoch_1).await;
    let (p, p_post) = &t.p;
    let (c, c_post) = &t.c;
    let (d, _) = empty_child(&t.config, c, c_post, epoch + 1, 0x34);
    let anchor = p.message.parent_root;
    let core = commit_all(t.core, &[c, &d], &t.verify).await;
    t.el.answer(hash(0x32), invalid_on(p_post));
    let (outcome, core) = step(core, envelope(&t.config, c, c_post), &t.verify).await;
    assert!(
        matches!(outcome, Outcome::InvalidEnvelope(_)),
        "{outcome:?}"
    );
    assert!(!core.execution_statuses().el_contradiction());
    assert!(!t.sink.halted());
    let store = core.fork_choice();
    assert_eq!(
        [store.justified_checkpoint(), store.finalized_checkpoint()]
            .map(|checkpoint| checkpoint.root),
        [anchor, anchor]
    );
    let verified = |core: &ChainCore<Minimal>| {
        [anchor, root(p), root(c), root(&d)]
            .map(|block| is_payload_verified(core.fork_choice(), block))
    };
    assert_eq!(
        verified(&core),
        [true, false, false, false],
        "the payload of p left the store"
    );
    let head = core.head();
    assert_eq!(head, head_of(p, PayloadStatus::Empty));
    let sent = t.sink.sent();
    let forkchoice_sent = core.forkchoice_sent();
    assert_eq!(forkchoice_sent.as_ref(), sent.last());
    el_sees(&t.el, sent.last().unwrap()).await;
    let updates = t.el.forkchoice_updates().len();

    let other = other_payload(&core, p, &t.config);
    let (justified, finalized) = justified_on_d_finalized_on_c(c, &d);
    let start_of_epoch_2 = clock_at(slot_time(&core, 2 * epoch));
    let core = core
        .with_fork_choice(|store| {
            set_unrealized_justified_checkpoint(store, justified.clone());
            set_unrealized_finalized_checkpoint(store, finalized.clone());
        })
        .with_clock(start_of_epoch_2);
    let (outcome, core) = step(core, block_item(&other), &t.verify).await;
    let store = core.fork_choice();
    assert_eq!(
        (store.justified_checkpoint(), store.finalized_checkpoint()),
        (&justified, &finalized),
        "one on_tick of the import makes d the justified and c the finalized block"
    );
    assert!(
        core.execution_statuses().el_contradiction(),
        "c, below the justified block, builds on a payload that left the store"
    );
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(t.sink.halted(), "the core halts the sender");
    assert!(
        !core.is_committed(&root(&other)),
        "the import commits nothing"
    );
    assert!(
        core.fork_choice().block(root(&other)).is_none(),
        "on_block does not run"
    );
    assert_eq!(core.head(), head, "the head stays");
    assert_eq!(verified(&core), [true, false, false, false]);
    assert_eq!(t.sink.sent(), sent, "no forkchoiceUpdated");
    assert_eq!(core.forkchoice_sent(), forkchoice_sent);
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// The `later` core on a test clock in the last slot of epoch 1, where the EL took the payload of
/// `p` optimistically, with `c` on that FULL payload and `d` on the EMPTY node of `c` committed:
/// the anchor is the justified and the finalized block, and the head is the EMPTY node of `d`.
/// Test seams then apply `edit` to the store and pull the unrealized justified checkpoint up to
/// `d` and the unrealized finalized checkpoint up to `c` (a justifying and finalizing chain), and
/// the clock reaches the first slot of epoch 2: the next import ticks the store there. Returns
/// the core, `d`, and `other`, a sibling of `p` with another payload, whose parent (the anchor)
/// the prune of that tick drops, so `on_block` refuses it.
async fn before_a_tick_to_d(
    edit: impl FnOnce(&mut fork_choice::Store<Minimal>),
) -> (Later, Block, Block) {
    let epoch = Minimal::slots_per_epoch();
    let end_of_epoch_1 = |core: ChainCore<Minimal>| {
        let at = slot_time(&core, 2 * epoch - 1);
        core.with_clock(clock_at(at))
    };
    let mut t = later_with(Reply::Syncing, |_| Reply::Syncing, end_of_epoch_1).await;
    let (p, _) = &t.p;
    let (c, c_post) = &t.c;
    let (d, _) = empty_child(&t.config, c, c_post, epoch + 1, 0x34);
    let core = commit_all(t.core, &[c, &d], &t.verify).await;
    assert_eq!(core.head(), head_of(&d, PayloadStatus::Empty));
    let other = other_payload(&core, p, &t.config);
    let (justified, finalized) = justified_on_d_finalized_on_c(c, &d);
    let start_of_epoch_2 = clock_at(slot_time(&core, 2 * epoch));
    t.core = core
        .with_fork_choice(|store| {
            edit(store);
            set_unrealized_justified_checkpoint(store, justified);
            set_unrealized_finalized_checkpoint(store, finalized);
        })
        .with_clock(start_of_epoch_2);
    (t, d, other)
}

/// [`before_a_tick_to_d`] with the store as the commits left it. The import of `other` ticks the
/// store: `on_tick` makes `d` the justified and `c` the finalized block, with no EL contradiction
/// (both build on the payload of `p`, which the store has), and its prune drops the anchor. Then
/// `on_block` refuses `other`: the import is IGNORE and commits nothing. The core still follows
/// the tick, as after a commit: it prunes the table at the new finalized execution hash (the
/// payload of `p`), the head is the EMPTY node of `d`, and one forkchoiceUpdated carries the new
/// safe and finalized hashes to the EL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tick_before_a_refused_block_moves_the_head_and_the_forkchoice_update() {
    let (t, d, other) = before_a_tick_to_d(|_| {}).await;
    let (justified, finalized) = justified_on_d_finalized_on_c(&t.c.0, &d);
    let sent = t.sink.sent();
    let last = *sent.last().unwrap();
    assert_eq!(
        hashes(&last),
        [hash(0x31), Hash32::ZERO, Hash32::ZERO],
        "the EMPTY node of d builds on the payload of p, and the anchor is safe and finalized"
    );
    assert_eq!(t.core.forkchoice_sent(), Some(last));

    let (outcome, core) = step(t.core, block_item(&other), &t.verify).await;
    let store = core.fork_choice();
    assert_eq!(
        (store.justified_checkpoint(), store.finalized_checkpoint()),
        (&justified, &finalized),
        "on_tick of the import makes d the justified and c the finalized block"
    );
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(!core.execution_statuses().el_contradiction());
    assert!(!t.sink.halted());
    assert!(
        !core.is_committed(&root(&other)),
        "the import commits nothing"
    );
    assert!(
        store.block(root(&other)).is_none(),
        "on_block refuses the block"
    );
    assert_eq!(core.head(), head_of(&d, PayloadStatus::Empty));
    let want = args(hash(0x31), hash(0x31), hash(0x31));
    assert_eq!(
        t.sink.sent(),
        [sent, vec![want]].concat(),
        "one forkchoiceUpdated with the new safe and finalized hashes"
    );
    assert_eq!(core.forkchoice_sent(), Some(want));
    assert_eq!(
        core.execution_statuses().status(&hash(0x31)),
        None,
        "the table is pruned at the new finalized execution hash"
    );
    el_sees(&t.el, &want).await;
}

/// [`before_a_tick_to_d`] where the payload of `p` left the store first (`invalidate_payloads`
/// through a test seam, with no refresh after it): `c` and `d` build on it. The same tick then
/// makes `d` the justified block, which builds on a payload that left the store: an EL
/// contradiction, and `on_block` does not run. The core halts the sender, commits nothing and
/// does not refresh from the tick: the head stays, no forkchoiceUpdated is sent, and the table is
/// not pruned at the new finalized execution hash in that turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tick_that_latches_before_a_refused_block_does_not_refresh() {
    let (t, d, other) = before_a_tick_to_d(|store| {
        assert!(invalidate_payloads(store, |payload| *payload == hash(0x31)));
    })
    .await;
    let (justified, finalized) = justified_on_d_finalized_on_c(&t.c.0, &d);
    let head = t.core.head();
    let sent = t.sink.sent();
    let forkchoice_sent = t.core.forkchoice_sent();
    el_sees(&t.el, sent.last().unwrap()).await;
    let updates = t.el.forkchoice_updates().len();

    let (outcome, core) = step(t.core, block_item(&other), &t.verify).await;
    let store = core.fork_choice();
    assert_eq!(
        (store.justified_checkpoint(), store.finalized_checkpoint()),
        (&justified, &finalized),
        "on_tick of the import makes d the justified and c the finalized block"
    );
    assert!(
        core.execution_statuses().el_contradiction(),
        "d builds on a payload that left the store"
    );
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(t.sink.halted(), "the core halts the sender");
    assert!(
        !core.is_committed(&root(&other)),
        "the import commits nothing"
    );
    assert!(store.block(root(&other)).is_none(), "on_block does not run");
    assert_eq!(core.head(), head, "the head stays");
    assert_eq!(t.sink.sent(), sent, "no forkchoiceUpdated");
    assert_eq!(core.forkchoice_sent(), forkchoice_sent);
    assert_eq!(
        core.execution_statuses().status(&hash(0x31)),
        Some(ExecutionStatus::Optimistic),
        "no refresh: the table is not pruned at the new finalized execution hash"
    );
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// `on_block` itself moves the checkpoints. The `later` core on a test clock in slot 27, with `c`
/// on the FULL payload of `p` and `d` on the EMPTY node of `c` committed. The anchor is the
/// justified and the finalized block, and the unrealized ones too, so the tick of the next import
/// promotes nothing. The payload of `p` leaves the store (`invalidate_payloads` through a test
/// seam: an INVALID for it would also make the core refuse each block on `d`, whose bid builds on
/// that payload). A test seam stands for a justifying and finalizing chain: the walk state of `d`
/// at the end of epoch 2 has `d` justified and `c` finalized. The block `j` of slot 26 on the
/// EMPTY node of `d`, far after it, imports from that state, and its post-state realizes both: its
/// `on_block` makes `d` the justified and `c` the finalized block. `c` builds on the payload that
/// left the store, and the walk goes down to the finalized block before `on_block`. The core
/// fails closed after `on_block`: it sets the EL contradiction, halts the sender and commits
/// nothing, and the head, the verified payloads and the forkchoiceUpdated calls stay as they
/// were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_that_moves_justified_and_finalized_past_a_removed_payload_halts_and_commits_nothing(
) {
    let epoch = Minimal::slots_per_epoch();
    let in_epoch_3 = |core: ChainCore<Minimal>| {
        let at = slot_time(&core, 3 * epoch + 3);
        core.with_clock(clock_at(at))
    };
    let t = later_with(Reply::Syncing, |_| Reply::Syncing, in_epoch_3).await;
    let (p, _) = &t.p;
    let (c, c_post) = &t.c;
    let (d, d_post) = empty_child(&t.config, c, c_post, epoch + 1, 0x34);
    let anchor = p.message.parent_root;
    let core = commit_all(t.core, &[c, &d], &t.verify).await;
    let core = core.with_fork_choice(|store| {
        assert!(invalidate_payloads(store, |payload| *payload == hash(0x31)));
    });
    let verified = |core: &ChainCore<Minimal>| {
        [anchor, root(p), root(c), root(&d)]
            .map(|block| is_payload_verified(core.fork_choice(), block))
    };
    assert_eq!(
        verified(&core),
        [true, false, false, false],
        "the payload of p left the store"
    );
    let store = core.fork_choice();
    assert_eq!(
        [
            store.justified_checkpoint(),
            store.finalized_checkpoint(),
            store.unrealized_justified_checkpoint(),
            store.unrealized_finalized_checkpoint(),
        ]
        .map(|checkpoint| checkpoint.root),
        [anchor; 4],
        "the tick of the import has nothing to promote"
    );

    let (justified, finalized) = justified_on_d_finalized_on_c(c, &d);
    let mut kept = advanced(&d_post, 3 * epoch - 1, &t.config);
    kept.current_justified_checkpoint = justified.clone();
    kept.finalized_checkpoint = finalized.clone();
    let (j, _) = empty_child(&t.config, &d, &kept, 3 * epoch + 2, 0x35);
    let core = core.with_advanced_state(root(&d), 3, kept);
    let head = core.head();
    let sent = t.sink.sent();
    let forkchoice_sent = core.forkchoice_sent();
    assert_eq!(forkchoice_sent.as_ref(), sent.last());
    el_sees(&t.el, sent.last().unwrap()).await;
    let updates = t.el.forkchoice_updates().len();

    let (outcome, core) = step(core, block_item(&j), &t.verify).await;
    let store = core.fork_choice();
    assert!(store.block(root(&j)).is_some(), "on_block takes the block");
    assert_eq!(
        (store.justified_checkpoint(), store.finalized_checkpoint()),
        (&justified, &finalized),
        "on_block of the import makes d the justified and c the finalized block"
    );
    assert!(
        core.execution_statuses().el_contradiction(),
        "c, below the justified block, builds on a payload that left the store"
    );
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(t.sink.halted(), "the core halts the sender");
    assert!(!core.is_committed(&root(&j)), "the import commits nothing");
    assert!(core.state(&root(&j)).is_none(), "no pre-state of the block");
    assert_eq!(core.head(), head, "the head stays");
    assert_eq!(verified(&core), [true, false, false, false]);
    assert_eq!(t.sink.sent(), sent, "no forkchoiceUpdated");
    assert_eq!(core.forkchoice_sent(), forkchoice_sent);
    tokio::time::sleep(QUIET).await;
    assert_eq!(t.el.forkchoice_updates().len(), updates);
}

/// A later INVALID that changes no status of the table does not scan the store. The EL answers
/// INVALID to the forkchoiceUpdated of the FULL head `p`: the payload of `p` is Invalid, it
/// leaves the store, and the head moves to the EMPTY node of `p`. A test seam puts the payload
/// back, as a store that still has it, and the core takes the same answer again. The payload is
/// Invalid already, so no status changed and the payload stays: a scan would take it out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_invalid_that_changes_no_status_does_not_scan_the_store() {
    let t = later(Reply::Syncing, |_| Reply::Syncing).await;
    let (p, p_post) = &t.p;
    let fcu = t.sink.fcu.as_ref().unwrap();
    let answer = fcu
        .take_outcome()
        .expect("the answer to the forkchoiceUpdated of p");
    let answer = invalid_answer(answer, p_post.latest_block_hash);
    t.sink.script(answer.clone());
    let (outcome, core) = step(t.core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(
        core.execution_statuses().status(&hash(0x31)),
        Some(ExecutionStatus::Invalid)
    );
    assert!(
        !is_payload_verified(core.fork_choice(), root(p)),
        "a new Invalid scans the store"
    );
    assert_eq!(core.head(), head_of(p, PayloadStatus::Empty));

    let core = core.with_payload_verified(root(p));
    let sent = t.sink.sent();
    t.sink.script(answer);
    let (outcome, core) = step(core, Item::Gossip, &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(!core.execution_statuses().el_contradiction());
    assert!(!t.sink.halted());
    assert!(
        is_payload_verified(core.fork_choice(), root(p)),
        "no status changed, so the store must not be scanned"
    );
    assert_eq!(core.head(), head_of(p, PayloadStatus::Empty));
    assert_eq!(t.sink.sent(), sent, "no forkchoiceUpdated");
}
