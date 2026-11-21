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
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "support/el.rs"]
mod el;
#[allow(dead_code)]
mod support;

use cl_chain::core::{ChainCore, Head, Outcome};
use cl_chain::engine::client::FcuSender;
use cl_chain::engine::fcu::{
    Bid, ForkchoiceArgs, ForkchoiceSink, PayloadStatus, CUSTODY_COLUMN_BYTES,
};
use cl_chain::engine::verdict::ExecutionStatus;
use consensus_types::gloas::{BeaconState, Checkpoint};
use consensus_types::primitives::Hash32;
use consensus_types::Minimal;
use el::{
    block_item, commit_all, envelope, full_child, hash, invalid_on, payload_block, ready, root,
    step, Block, El,
};
use fork_choice::testing::set_finalized_checkpoint;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::{fixture, Answer, FakeVerify, Fixture};

/// Any custody set: each forkchoiceUpdated carries it as configured.
const CUSTODY: [u8; CUSTODY_COLUMN_BYTES] = [0x3c; CUSTODY_COLUMN_BYTES];
/// How long a test waits for something that should happen.
const WAIT: Duration = Duration::from_secs(20);
/// How long a test waits to see that nothing more happens.
const QUIET: Duration = Duration::from_millis(300);

/// Records each forkchoiceUpdated the core sends, and forwards it to an `FcuSender` if it has
/// one.
#[derive(Clone, Default)]
struct Sink {
    sent: Arc<Mutex<Vec<ForkchoiceArgs>>>,
    fcu: Option<Arc<FcuSender>>,
}

impl Sink {
    /// A sink that forwards to a new `FcuSender` of `el`.
    fn to(el: &El) -> Self {
        Self {
            sent: Arc::default(),
            fcu: Some(Arc::new(el.fcu())),
        }
    }

    fn sent(&self) -> Vec<ForkchoiceArgs> {
        self.sent.lock().unwrap().clone()
    }
}

impl ForkchoiceSink for Sink {
    fn send(&self, args: ForkchoiceArgs) {
        self.sent.lock().unwrap().push(args);
        if let Some(fcu) = &self.fcu {
            fcu.send(args);
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
