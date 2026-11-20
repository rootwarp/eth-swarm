//! Acceptance tests of block import through the chain core.
//!
//! The fixture is in [`support`]: the genesis anchor of the pinned minimal Gloas export, its
//! slot 1 block, and a fake cl-verify behind `BlsVerifier`. Some tests use the production
//! `BlsClient` instead, with an in-process cl-verify or with a stub. One test sets a fake
//! payload gate that refuses each payload.
//!
//! The core sends the proposer set of a block in a first VerifyBls call, before the slot loop.
//! The block sets go in a second call, during the transition. So a first call that carries
//! only the proposer set, with no call after it, shows that the slot loop did not run.
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

use cl_chain::core::{queue, ChainCore, Head, Outcome, SubmitError, MAX_REFUSED_ROOTS};
use cl_chain::import::block::{PayloadImportGate, PermitAll};
use cl_chain::verify::client::{BlsClient, BlsOutcome, BlsVerifier, DEFAULT_MAX_OUTSTANDING};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{Bytes32, Hash32, Root};
use consensus_types::signing::{compute_signing_root, DOMAIN_BEACON_PROPOSER};
use consensus_types::{EthSpec, Minimal};
use ethswarm_proto::verify::{BlsSet, KeyNamespace, Signer};
use state_transition::accessors::get_domain;
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
use tokio::time::Instant;
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
        2,
        "the proposer set must go to cl-verify first, then the block sets"
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
        2,
        "the proposer set and the block sets must go to cl-verify one time each"
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
        2,
        "a committed block must not reach cl-verify again"
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

/// The wait of the fake cl-verify before each answer, in the shared deadline test.
const STEP: Duration = Duration::from_millis(500);

/// The clock is paused, so only the waits of the fake move it: the import starts at `start`,
/// the first call comes at `start`, and the second call comes [`STEP`] later. A deadline taken
/// again for each call is then later than `start + VERIFY_TIMEOUT` for the second call.
#[tokio::test(start_paused = true)]
async fn one_verify_deadline_runs_from_the_start_of_the_import() {
    let f = fixture();
    let start = Instant::now();
    let (outcome, _, verify) = import_one(f.core, f.block, Answer::ValidAfter(STEP)).await;
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
    let called = verify.called();
    assert_eq!(
        called.len(),
        2,
        "the import must make two VerifyBls calls: {called:?}"
    );
    assert_eq!(called[0].at, start, "{called:?}");
    assert_eq!(
        called[1].at,
        start + STEP,
        "the second call must come after the answer to the first: {called:?}"
    );
    for call in &called {
        assert_eq!(
            call.deadline,
            start + VERIFY_TIMEOUT,
            "each call must have the deadline of the start of the import: {call:?}"
        );
    }
}

/// The proposer set of `block` on `pre`, the state of its parent: the registry key of
/// `proposer_index`, and the signing root in the proposer domain of the epoch of the block.
fn proposer_set(pre: &BeaconState<Minimal>, block: &SignedBeaconBlock<Minimal>) -> BlsSet {
    let proposer = block.message.proposer_index;
    let key = pre
        .validators
        .get(usize::try_from(proposer).unwrap())
        .unwrap()
        .pubkey;
    let epoch = Minimal::epoch_at_slot(block.message.slot);
    let domain = get_domain(pre, DOMAIN_BEACON_PROPOSER, Some(epoch));
    BlsSet {
        signers: vec![Signer {
            validator_index: proposer,
            inline_pubkey: key.to_vec(),
            namespace: KeyNamespace::Validator as i32,
            builder: None,
        }],
        signing_root: compute_signing_root(&block.message, domain).to_vec(),
        signature: block.signature.to_vec(),
    }
}

#[tokio::test]
async fn an_invalid_proposer_signature_is_invalid_before_the_slot_loop() {
    let f = fixture();
    let block_root = f.block.message.tree_hash_root();
    let expected = proposer_set(f.core.state(&f.anchor.block_root).unwrap(), &f.block);
    let (outcome, core, verify) = import_one(f.core, f.block, Answer::Invalid).await;
    assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
    assert_eq!(
        verify.calls(),
        vec![vec![expected]],
        "only the proposer set must go to cl-verify, before the slot loop"
    );
    assert_unchanged(&core, f.anchor, block_root);
}

#[tokio::test(start_paused = true)]
async fn a_missing_proposer_verdict_is_ignored_before_the_slot_loop() {
    for answer in [Answer::Never, Answer::Late, Answer::AtDeadline] {
        let f = fixture();
        let block_root = f.block.message.tree_hash_root();
        let expected = proposer_set(f.core.state(&f.anchor.block_root).unwrap(), &f.block);
        let (outcome, core, verify) = import_one(f.core, f.block, answer).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "{answer:?}: {outcome:?}"
        );
        assert_eq!(
            verify.calls(),
            vec![vec![expected]],
            "{answer:?}: only the proposer set must go to cl-verify, before the slot loop"
        );
        assert_unchanged(&core, f.anchor, block_root);
    }
}

/// tokio's `timeout_at` polls the call before its timer. So a VALID that is ready at the
/// deadline passes through it, and only the check of the core stops it. The VALID at the
/// deadline comes in the first call (the proposer set) or in the last call (the block sets).
/// In the last call, nothing after it can stop the import.
#[tokio::test(start_paused = true)]
async fn a_valid_verdict_at_the_deadline_does_not_commit() {
    let late_calls = [
        vec![Answer::AtDeadline],
        vec![Answer::Valid, Answer::AtDeadline],
    ];
    for answers in late_calls {
        let f = fixture();
        let block_root = f.block.message.tree_hash_root();
        let verify = FakeVerify::answers(answers.clone());
        let (outcome, core) = import_with(f.core, f.block.clone(), Arc::clone(&verify)).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "{answers:?}: a VALID at the deadline must not commit: {outcome:?}"
        );
        assert_eq!(verify.calls().len(), answers.len(), "{answers:?}");
        assert_unchanged(&core, f.anchor, block_root);
        let (outcome, _, _) = import_one(core, f.block, Answer::Valid).await;
        assert!(
            matches!(outcome, Outcome::Committed { .. }),
            "{answers:?}: a block without a verdict in time must be able to come again: \
             {outcome:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_root_without_a_verdict_can_come_again() {
    for answer in [Answer::Never, Answer::Late] {
        let f = fixture();
        let (outcome, core, _) = import_one(f.core, f.block.clone(), answer).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "{answer:?}: {outcome:?}"
        );
        let (outcome, _, verify) = import_one(core, f.block, Answer::Valid).await;
        assert!(
            matches!(outcome, Outcome::Committed { .. }),
            "{answer:?}: no verdict must not refuse the root for good: {outcome:?}"
        );
        assert_eq!(
            verify.calls().len(),
            2,
            "{answer:?}: the import again must send the proposer set and the block sets"
        );
    }
}

#[tokio::test]
async fn an_invalid_root_again_is_refused_before_cl_verify() {
    // A proposer signature that cl-verify refuses: the refusal holds for that signature only.
    let f = fixture();
    let (first, core, _) = import_one(f.core, f.block.clone(), Answer::Invalid).await;
    assert_eq!(first, Outcome::Invalid(StfError::InvalidBlockSignature));
    let (again, core, verify) = import_one(core, f.block.clone(), Answer::Valid).await;
    assert_eq!(again, first, "the same block must get the same answer");
    assert!(
        verify.calls().is_empty(),
        "a refused block must not reach cl-verify again"
    );
    let mut signed_again = f.block.clone();
    signed_again.signature[10] ^= 0x01;
    let (outcome, _, _) = import_one(core, signed_again, Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Committed { .. }),
        "a bad signature on a copy must not refuse the block: {outcome:?}"
    );

    // An invalid message: the refusal holds for each signature.
    let f = fixture();
    let mut block = f.block;
    block.message.state_root = Root::repeat_byte(0x11);
    let block_root = block.message.tree_hash_root();
    let (first, core, _) = import_one(f.core, block.clone(), Answer::Valid).await;
    assert!(
        matches!(first, Outcome::Invalid(StfError::StateRootMismatch { .. })),
        "{first:?}"
    );
    let mut signed_again = block.clone();
    signed_again.signature[10] ^= 0x01;
    let mut core = core;
    for copy in [block, signed_again] {
        let (again, next, verify) = import_one(core, copy, Answer::Valid).await;
        assert_eq!(again, first, "the same message must get the same answer");
        assert!(
            verify.calls().is_empty(),
            "a refused message must not reach cl-verify again"
        );
        core = next;
    }
    assert_unchanged(&core, f.anchor, block_root);
}

/// `block` with graffiti that holds `n`: a block with its own root.
fn numbered(block: &SignedBeaconBlock<Minimal>, n: usize) -> SignedBeaconBlock<Minimal> {
    let mut graffiti = [0u8; 32];
    graffiti[..8].copy_from_slice(&u64::try_from(n).unwrap().to_le_bytes());
    let mut block = block.clone();
    block.message.body.graffiti = Bytes32::from(graffiti);
    block
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_refused_roots_are_bounded_and_the_oldest_goes_first() {
    let f = fixture();
    let verify = FakeVerify::new(Answer::Invalid);
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let writer = f
        .core
        .spawn(queue, Arc::clone(&verify), Handle::current())
        .unwrap();
    let import = |block: SignedBeaconBlock<Minimal>| {
        let reply = sender.import(block).unwrap();
        async move { reply.await.unwrap().outcome }
    };
    let blocks: Vec<_> = (0..=MAX_REFUSED_ROOTS)
        .map(|n| numbered(&f.block, n))
        .collect();
    for block in &blocks {
        let outcome = import(block.clone()).await;
        assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
    }
    let sent = verify.calls().len();
    let outcome = import(blocks[MAX_REFUSED_ROOTS].clone()).await;
    assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
    assert_eq!(
        verify.calls().len(),
        sent,
        "the newest refused root must not reach cl-verify again"
    );
    let outcome = import(blocks[0].clone()).await;
    assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
    assert_eq!(
        verify.calls().len(),
        sent + 1,
        "past the bound, the oldest refused root must go first"
    );
    drop(sender);
    let core = writer.join().unwrap();
    assert_eq!(core.head(), f.anchor, "the head must stay the anchor");
}

/// A stub cl-verify that answers VALID for each set, behind the production client. An import
/// whose deadline passed before its first call must send no request and must not close the
/// stream: the next import uses the same stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_import_out_of_time_sends_no_request_and_keeps_the_stream() {
    let served = testing::StubVerify::start(testing::Stub::ValidAfter(Duration::from_millis(1)));
    let client = Arc::new(served.bls_client().await);
    let f = fixture();
    let (outcome, _) = import_with(f.core, f.block, Arc::clone(&client)).await;
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
    let requests = served.bls_requests();
    assert_eq!(served.streams_opened(), 1);

    let f = fixture();
    let block_root = f.block.message.tree_hash_root();
    let core = f.core.with_verify_timeout(Duration::ZERO);
    let (outcome, core) = import_with(core, f.block, Arc::clone(&client)).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "an import without time must be IGNORE: {outcome:?}"
    );
    assert_unchanged(&core, f.anchor, block_root);

    let f = fixture();
    let (outcome, _) = import_with(f.core, f.block, client).await;
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
    assert_eq!(
        served.streams_opened(),
        1,
        "an import out of time must not close the stream"
    );
    assert_eq!(
        served.bls_requests(),
        2 * requests,
        "an import out of time must send no request"
    );
}

/// The deadline of the core in the silent cl-verify test.
const SHORT_TIMEOUT: Duration = Duration::from_millis(80);
/// The wait of [`Paused`] before each call.
const PAUSE: Duration = Duration::from_millis(15);

/// The production client, with a pause before each call. The pause stands for work that the
/// caller does before the client gets the call.
struct Paused(BlsClient);

impl BlsVerifier for Paused {
    async fn verify_sets(&self, sets: Vec<BlsSet>, deadline: Instant) -> BlsOutcome {
        tokio::time::sleep(PAUSE).await;
        self.0.verify_sets(sets, deadline).await
    }
}

/// A silent cl-verify behind the production client. Each import must end at its deadline and
/// close its VerifyBls stream, so that a stream never carries a second request and no request
/// stays in the window. More requests than the window holds must reach cl-verify.
///
/// The deadline starts before the transition, so an import on a slow machine can run out of
/// time before it sends its request. The test thus counts the requests that cl-verify reads,
/// not the imports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_cl_verify_does_not_fill_the_request_window() {
    let served = testing::StubVerify::start(testing::Stub::Silent);
    let verifier = Arc::new(Paused(served.bls_client().await));
    let f = fixture();
    let block_root = f.block.message.tree_hash_root();
    let core = f.core.with_verify_timeout(SHORT_TIMEOUT);
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let writer = core.spawn(queue, verifier, Handle::current()).unwrap();
    for import in 1..=4 * DEFAULT_MAX_OUTSTANDING {
        let reply = sender.import(f.block.clone()).unwrap();
        let outcome = reply.await.unwrap().outcome;
        assert!(
            matches!(&outcome, Outcome::Ignored(why) if why.contains("no verdict by the deadline")),
            "import {import}: {outcome:?}"
        );
        assert!(
            served.bls_requests() <= served.streams_opened(),
            "import {import}: a stream must close at the deadline of its request, so it must \
             not carry a second request ({} requests on {} streams)",
            served.bls_requests(),
            served.streams_opened()
        );
        if served.bls_requests() > DEFAULT_MAX_OUTSTANDING {
            break;
        }
    }
    assert!(
        served.bls_requests() > DEFAULT_MAX_OUTSTANDING,
        "more requests than the window holds must reach cl-verify: {}",
        served.bls_requests()
    );
    drop(sender);
    let core = writer.join().unwrap();
    assert_unchanged(&core, f.anchor, block_root);
}
