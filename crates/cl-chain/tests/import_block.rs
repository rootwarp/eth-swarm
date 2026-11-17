//! Acceptance tests of block import through the chain core.
//!
//! The fixture is in [`support`]: the genesis anchor of the pinned minimal Gloas export, its
//! slot 1 block, and a fake cl-verify behind `BlsVerifier`. Two tests use the production
//! `BlsClient` instead, one with an in-process cl-verify and one with a silent stub. One test
//! sets a fake payload gate that refuses each payload.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "../src/testing.rs"]
mod testing;

/// [`testing`] names cl-chain's verify.v1 client by its path inside the library.
mod verify {
    pub use cl_chain::verify::client;
}

#[allow(dead_code)]
mod support;

use cl_chain::core::{queue, ChainCore, Head, Outcome, SubmitError};
use cl_chain::import::block::{PayloadImportGate, PermitAll};
use cl_chain::verify::client::{BlsClient, BlsOutcome, BlsVerifier, DEFAULT_MAX_OUTSTANDING};
use consensus_types::primitives::{Hash32, Root};
use consensus_types::Minimal;
use ethswarm_proto::verify::{BlsSet, KeyNamespace};
use state_transition::StfError;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::{
    assert_unchanged, fixture, import_one, import_with, ungated_fixture, Answer, FakeVerify, QUEUE,
    VERIFY_TIMEOUT,
};
use testkit::anchor::fixtures::{pinned_export, AnchorFiles};
use testkit::anchor::load_anchor;
use tokio::runtime::Handle;
use tree_hash::TreeHash;

/// A fake payload gate. It refuses each payload and keeps the hashes of each call.
struct RefusingGate {
    calls: Arc<Mutex<Vec<(Hash32, Hash32)>>>,
}

impl PayloadImportGate for RefusingGate {
    fn permits(&self, block_hash: &Hash32, parent_block_hash: &Hash32) -> bool {
        self.calls
            .lock()
            .unwrap()
            .push((*block_hash, *parent_block_hash));
        false
    }
}

#[tokio::test]
async fn valid_block_commits() {
    let f = fixture();
    let block_root = f.block.message.tree_hash_root();
    let state_root = f.block.message.state_root;
    let proposer = f.block.message.proposer_index;
    let (outcome, core, verify) = import_one(f.core, f.block, Answer::Valid).await;
    assert_eq!(
        outcome,
        Outcome::Committed {
            block_root,
            state_root
        }
    );
    let calls = verify.calls();
    assert_eq!(
        calls.len(),
        1,
        "the block sets must go to cl-verify one time"
    );
    let proposer_set = &calls[0][0];
    let signer = &proposer_set.signers[0];
    assert_eq!(signer.namespace, KeyNamespace::Validator as i32);
    assert_eq!(signer.validator_index, proposer);
    assert_eq!(
        signer.inline_pubkey.len(),
        48,
        "without a key feed, each import signer must carry its key"
    );
    assert_eq!(
        core.head(),
        Head {
            block_root,
            slot: 1,
            state_root
        }
    );
    assert_eq!(core.pre_states(), 2, "the anchor and the new post-state");
    let mut post = core.state(&block_root).unwrap().clone();
    assert_eq!(
        state_transition::state_root(&mut post).unwrap(),
        state_root,
        "the post-state root must equal block.state_root"
    );
}

#[tokio::test]
async fn bad_signature_not_committed() {
    let f = fixture();
    let block_root = f.block.message.tree_hash_root();
    let (outcome, core, verify) = import_one(f.core, f.block, Answer::Invalid).await;
    assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
    assert_eq!(verify.calls().len(), 1);
    assert_unchanged(&core, f.anchor, block_root);
}

#[tokio::test(start_paused = true)]
async fn missing_verdict_ignores() {
    for answer in [Answer::Never, Answer::Late] {
        let f = fixture();
        let block_root = f.block.message.tree_hash_root();
        let start = tokio::time::Instant::now();
        let (outcome, core, verify) = import_one(f.core, f.block, answer).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "{answer:?}: {outcome:?}"
        );
        assert!(
            start.elapsed() >= VERIFY_TIMEOUT,
            "{answer:?}: the core must wait for the deadline"
        );
        assert_eq!(verify.calls().len(), 1, "{answer:?}");
        assert_unchanged(&core, f.anchor, block_root);
    }
}

#[tokio::test]
async fn queue_order() {
    let f = fixture();
    let verify = FakeVerify::new(Answer::Valid);
    let (sender, queue) = queue::<Minimal>(QUEUE);
    // Each item waits in its queue before the writer starts. The import is the last to arrive.
    let gossip = sender.gossip().unwrap();
    let envelope = sender.envelope().unwrap();
    let import = sender.import(f.block).unwrap();
    let writer = f
        .core
        .spawn(queue, Arc::clone(&verify), Handle::current())
        .unwrap();
    let (gossip, envelope, import) = (
        gossip.await.unwrap(),
        envelope.await.unwrap(),
        import.await.unwrap(),
    );
    assert_eq!(import.turn, 1, "the import must run first");
    assert_eq!(envelope.turn, 2, "the envelope must run second");
    assert_eq!(gossip.turn, 3, "the gossip item must run last");
    assert!(matches!(import.outcome, Outcome::Committed { .. }));
    assert!(matches!(envelope.outcome, Outcome::Ignored(_)));
    assert!(matches!(gossip.outcome, Outcome::Ignored(_)));
    drop(sender);
    writer.join().unwrap();
}

#[tokio::test]
async fn full_queue_ignores() {
    let f = fixture();
    let (sender, queue) = queue::<Minimal>(1);
    let _first = sender.import(f.block.clone()).unwrap();
    assert_eq!(
        sender.import(f.block.clone()).unwrap_err(),
        SubmitError::Full
    );
    let _envelope = sender.envelope().unwrap();
    assert_eq!(sender.envelope().unwrap_err(), SubmitError::Full);
    let _gossip = sender.gossip().unwrap();
    assert_eq!(sender.gossip().unwrap_err(), SubmitError::Full);
    drop(queue);
    assert_eq!(sender.import(f.block).unwrap_err(), SubmitError::Stopped);
}

#[tokio::test]
async fn state_root_mismatch_not_committed() {
    let f = fixture();
    let mut block = f.block;
    block.message.state_root = Root::repeat_byte(0x11);
    let block_root = block.message.tree_hash_root();
    let (outcome, core, _) = import_one(f.core, block, Answer::Valid).await;
    assert!(
        matches!(
            outcome,
            Outcome::Invalid(StfError::StateRootMismatch { .. })
        ),
        "{outcome:?}"
    );
    assert_unchanged(&core, f.anchor, block_root);
}

#[tokio::test]
async fn refused_payload_gate_ignores() {
    let f = fixture();
    let block_root = f.block.message.tree_hash_root();
    let bid = &f.block.message.body.signed_execution_payload_bid.message;
    let expected = (bid.block_hash, bid.parent_block_hash);
    let calls = Arc::default();
    let core = f.core.with_payload_gate(RefusingGate {
        calls: Arc::clone(&calls),
    });
    let (outcome, core, verify) = import_one(core, f.block, Answer::Valid).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(
        verify.calls().len(),
        1,
        "the block sets must go to cl-verify one time"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec![expected],
        "the gate must get the hashes of the payload bid of the block"
    );
    assert_unchanged(&core, f.anchor, block_root);
}

#[tokio::test]
async fn unknown_parent_ignores() {
    let f = fixture();
    let mut block = f.block;
    block.message.parent_root = Root::repeat_byte(0x22);
    let block_root = block.message.tree_hash_root();
    let (outcome, core, verify) = import_one(f.core, block, Answer::Valid).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert!(
        verify.calls().is_empty(),
        "a block without a pre-state must not reach cl-verify"
    );
    assert_unchanged(&core, f.anchor, block_root);
}

#[test]
fn anchor_mismatch_refused() {
    let f = fixture();
    let pinned = pinned_export().unwrap();
    let dir = tempfile::tempdir().unwrap();
    AnchorFiles::genesis(&pinned.export)
        .unwrap()
        .write(dir.path())
        .unwrap();
    let (state, _) = load_anchor::<Minimal>(dir.path()).unwrap().into_parts();
    // The slot 1 block does not commit to the genesis state.
    let refused = ChainCore::from_anchor(state, f.block, f.config);
    assert!(
        refused.is_err(),
        "a block and a state that disagree must not install"
    );
}

/// The production VerifyBls client and a real cl-verify in process. cl-verify checks each set
/// with BLS, with the keys that the core sends inline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cl_verify_checks_the_block_sets() {
    let served = testing::ClVerify::start();
    let client = Arc::new(served.bls_client().await);

    let f = fixture();
    let block_root = f.block.message.tree_hash_root();
    let state_root = f.block.message.state_root;
    let (outcome, core) = import_with(f.core, f.block, Arc::clone(&client)).await;
    assert_eq!(
        outcome,
        Outcome::Committed {
            block_root,
            state_root
        }
    );
    assert_eq!(core.head().block_root, block_root);

    let f = fixture();
    let mut block = f.block;
    block.signature[10] ^= 0x01;
    let (outcome, core) = import_with(f.core, block, client).await;
    assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
    assert_unchanged(&core, f.anchor, block_root);
}

#[tokio::test]
async fn a_core_commits_only_with_an_explicit_payload_gate() {
    let f = ungated_fixture();
    let block_root = f.block.message.tree_hash_root();
    let (outcome, core, _) = import_one(f.core, f.block, Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "a core without a payload gate must not commit: {outcome:?}"
    );
    assert_unchanged(&core, f.anchor, block_root);

    let f = ungated_fixture();
    let core = f.core.with_payload_gate(PermitAll);
    let (outcome, _, _) = import_one(core, f.block, Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Committed { .. }),
        "the explicit gate PermitAll must let the block commit: {outcome:?}"
    );
}

#[tokio::test]
async fn a_committed_block_again_is_ignored_without_a_transition() {
    let f = fixture();
    let verify = FakeVerify::new(Answer::Valid);
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let writer = f
        .core
        .spawn(queue, Arc::clone(&verify), Handle::current())
        .unwrap();
    let first = sender.import(f.block.clone()).unwrap().await.unwrap();
    assert!(
        matches!(first.outcome, Outcome::Committed { .. }),
        "{:?}",
        first.outcome
    );
    let again = sender.import(f.block.clone()).unwrap().await.unwrap();
    assert!(
        matches!(again.outcome, Outcome::Ignored(_)),
        "a block that is the head must be IGNORE: {:?}",
        again.outcome
    );
    assert_eq!(
        verify.calls().len(),
        1,
        "a committed block must not run the transition again"
    );
    drop(sender);
    let core = writer.join().unwrap();
    assert_eq!(core.pre_states(), 2, "the anchor and the one post-state");
}

#[tokio::test]
async fn an_out_of_range_proposer_is_invalid_before_the_transition() {
    let f = fixture();
    let validators = f.core.state(&f.anchor.block_root).unwrap().validators.len();
    let first_out = u64::try_from(validators).unwrap();
    for proposer in [first_out, u64::MAX] {
        let f = fixture();
        let mut block = f.block;
        block.message.proposer_index = proposer;
        let block_root = block.message.tree_hash_root();
        let (outcome, core, verify) = import_one(f.core, block, Answer::Valid).await;
        assert_eq!(
            outcome,
            Outcome::Invalid(StfError::UnknownValidator(proposer)),
            "a proposer past the registry of the parent state must be refused before the slot loop"
        );
        assert!(verify.calls().is_empty(), "{proposer}");
        assert_unchanged(&core, f.anchor, block_root);
    }
}

#[tokio::test]
async fn one_verify_deadline_runs_from_the_start_of_the_import() {
    let f = fixture();
    let (outcome, _, verify) = import_one(f.core, f.block, Answer::Valid).await;
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
    let called = verify.called();
    assert!(!called.is_empty(), "the block sets must go to cl-verify");
    for call in &called {
        // The core starts the deadline before the transition, so the transition time is
        // already gone when the call comes.
        assert!(
            call.deadline < call.at + VERIFY_TIMEOUT,
            "the deadline must not start at the VerifyBls call: {call:?}"
        );
        assert_eq!(
            call.deadline, called[0].deadline,
            "each call of one import must have the same deadline"
        );
    }
}

/// The deadline of the core in the silent cl-verify test.
const SHORT_TIMEOUT: Duration = Duration::from_millis(60);
/// The wait of [`Paused`] before each call.
const PAUSE: Duration = Duration::from_millis(15);

/// The production client, with a pause before each call. The pause stands for work that the
/// caller does before the client gets the call.
struct Paused(BlsClient);

impl BlsVerifier for Paused {
    async fn verify_sets(&self, sets: Vec<BlsSet>, timeout: Duration) -> BlsOutcome {
        tokio::time::sleep(PAUSE).await;
        self.0.verify_sets(sets, timeout).await
    }
}

/// A silent cl-verify behind the production client. Each import must end at its deadline and
/// close its VerifyBls stream, so that no request stays in the window. The import after a full
/// window of such imports must still reach cl-verify.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_cl_verify_does_not_fill_the_request_window() {
    let served = testing::StubVerify::start(testing::Stub::Silent);
    let verifier = Arc::new(Paused(served.bls_client().await));
    let f = fixture();
    let block_root = f.block.message.tree_hash_root();
    let core = f.core.with_verify_timeout(SHORT_TIMEOUT);
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let writer = core.spawn(queue, verifier, Handle::current()).unwrap();
    for import in 1..=DEFAULT_MAX_OUTSTANDING + 1 {
        let reply = sender.import(f.block.clone()).unwrap();
        let outcome = reply.await.unwrap().outcome;
        assert!(
            matches!(&outcome, Outcome::Ignored(why) if why.contains("no verdict by the deadline")),
            "import {import}: {outcome:?}"
        );
        assert_eq!(
            served.streams_opened(),
            import,
            "import {import}: each import must close its VerifyBls stream at its deadline"
        );
    }
    drop(sender);
    let core = writer.join().unwrap();
    assert_unchanged(&core, f.anchor, block_root);
}
