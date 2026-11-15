//! Acceptance tests of block import through the chain core.
//!
//! Each test installs the genesis anchor of the pinned minimal Gloas export. The anchor comes
//! from a temporary directory in the `anchor-fetch` layout, through
//! `testkit::anchor::load_anchor`. The block to import is the slot 1 block of the same export.
//! A fake cl-verify behind `BlsVerifier` gives the VerifyBls verdicts. One test uses the
//! production `BlsClient` and an in-process cl-verify instead.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "../src/testing.rs"]
mod testing;

/// [`testing`] names cl-chain's verify.v1 client by its path inside the library.
mod verify {
    pub use cl_chain::verify::client;
}

use cl_chain::core::{queue, ChainCore, Head, Outcome, SubmitError};
use cl_chain::verify::client::{BlsOutcome, BlsVerifier};
use consensus_types::gloas::SignedBeaconBlock;
use consensus_types::primitives::Root;
use consensus_types::Minimal;
use ethswarm_proto::verify::{BlsSet, KeyNamespace};
use network_config::ChainConfig;
use ssz::Decode;
use state_transition::StfError;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use testkit::anchor::fixtures::{pinned_export, AnchorFiles};
use testkit::anchor::load_anchor;
use tokio::runtime::Handle;
use tree_hash::TreeHash;

/// Room in each queue of the core.
const QUEUE: usize = 4;
/// The VerifyBls deadline of the core in these tests.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(4);

/// What the fake cl-verify answers.
#[derive(Clone, Copy, Debug)]
enum Answer {
    /// `VERIFY_STATUS_VALID` for each set.
    Valid,
    /// `VERIFY_STATUS_INVALID`.
    Invalid,
    /// No answer.
    Never,
    /// `VERIFY_STATUS_VALID`, but only after two deadlines.
    Late,
}

/// A fake cl-verify. It gives one answer to each call and keeps the sets of each call.
struct FakeVerify {
    answer: Answer,
    calls: Mutex<Vec<Vec<BlsSet>>>,
}

impl FakeVerify {
    fn new(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            answer,
            calls: Mutex::default(),
        })
    }

    fn calls(&self) -> Vec<Vec<BlsSet>> {
        self.calls.lock().unwrap().clone()
    }
}

impl BlsVerifier for FakeVerify {
    async fn verify_sets(&self, sets: Vec<BlsSet>, _timeout: Duration) -> BlsOutcome {
        self.calls.lock().unwrap().push(sets);
        match self.answer {
            Answer::Valid => BlsOutcome::Valid,
            Answer::Invalid => BlsOutcome::Invalid,
            Answer::Never => std::future::pending().await,
            Answer::Late => {
                tokio::time::sleep(VERIFY_TIMEOUT * 2).await;
                BlsOutcome::Valid
            }
        }
    }
}

/// The installed genesis anchor and the slot 1 block.
struct Fixture {
    core: ChainCore<Minimal>,
    anchor: Head,
    block: SignedBeaconBlock<Minimal>,
    config: ChainConfig,
}

fn fixture() -> Fixture {
    let pinned = pinned_export().expect("the pinned export must open");
    let dir = tempfile::tempdir().unwrap();
    AnchorFiles::genesis(&pinned.export)
        .unwrap()
        .write(dir.path())
        .unwrap();
    let loaded = load_anchor::<Minimal>(dir.path()).expect("the anchor must load");
    let anchor = Head {
        block_root: loaded.block_root(),
        slot: loaded.slot(),
        state_root: loaded.state_root(),
    };
    let (state, block) = loaded.into_parts();
    let core = ChainCore::from_anchor(state, block, pinned.config.clone())
        .expect("the anchor must install")
        .with_verify_timeout(VERIFY_TIMEOUT);
    assert_eq!(core.head(), anchor, "the head must be the anchor");
    let entry = pinned
        .export
        .manifest()
        .blocks
        .iter()
        .find(|entry| entry.slot == 1)
        .expect("the export must hold a slot 1 block");
    let bytes = pinned.export.block_ssz(entry).unwrap();
    Fixture {
        core,
        anchor,
        block: SignedBeaconBlock::from_ssz_bytes(&bytes).unwrap(),
        config: pinned.config,
    }
}

/// Imports `block` on a core with a fake cl-verify that gives `answer`. Returns the outcome,
/// the core after its writer thread stops, and the fake.
async fn import_one(
    core: ChainCore<Minimal>,
    block: SignedBeaconBlock<Minimal>,
    answer: Answer,
) -> (Outcome, ChainCore<Minimal>, Arc<FakeVerify>) {
    let verify = FakeVerify::new(answer);
    let (outcome, core) = import_with(core, block, Arc::clone(&verify)).await;
    (outcome, core, verify)
}

/// Imports `block` on a core that sends its sets to `verifier`. Returns the outcome and the
/// core after its writer thread stops.
async fn import_with<V: BlsVerifier + 'static>(
    core: ChainCore<Minimal>,
    block: SignedBeaconBlock<Minimal>,
    verifier: Arc<V>,
) -> (Outcome, ChainCore<Minimal>) {
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let writer = core.spawn(queue, verifier, Handle::current()).unwrap();
    let reply = sender
        .import(block)
        .expect("the import queue must have room");
    let served = reply.await.expect("the core must answer");
    drop(sender);
    let core = writer.join().expect("the writer thread must not panic");
    (served.outcome, core)
}

/// The core holds only the anchor: its head and its pre-state did not change.
fn assert_unchanged(core: &ChainCore<Minimal>, anchor: Head, block_root: Root) {
    assert_eq!(core.head(), anchor, "the head must stay the anchor");
    assert_eq!(core.pre_states(), 1, "the core must hold only the anchor");
    assert!(
        core.state(&block_root).is_none(),
        "the core must not hold a post-state of the block"
    );
    let mut state = core.state(&anchor.block_root).unwrap().clone();
    assert_eq!(
        state_transition::state_root(&mut state).unwrap(),
        anchor.state_root,
        "the anchor state must not change"
    );
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
