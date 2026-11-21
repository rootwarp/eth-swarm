//! The fixture of the chain core tests.
//!
//! Each test installs the genesis anchor of the pinned minimal Gloas export. The anchor comes
//! from a temporary directory in the `anchor-fetch` layout, through
//! `testkit::anchor::load_anchor`. The block to import is the slot 1 block of the same export.
//! A fake cl-verify behind `BlsVerifier` gives the VerifyBls verdicts.

use cl_chain::core::{queue, ChainCore, Head, Outcome};
use cl_chain::engine::fcu::PayloadStatus;
use cl_chain::import::block::PermitAll;
use cl_chain::verify::client::{BlsOutcome, BlsVerifier, UnixClock};
use consensus_types::gloas::{
    BeaconState, ExecutionPayload, ExecutionPayloadEnvelope, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope,
};
use consensus_types::primitives::{Bytes32, Domain, Root, U256};
use consensus_types::signing::{compute_signing_root, DOMAIN_BEACON_PROPOSER};
use consensus_types::{EthSpec, Minimal};
use ethswarm_proto::verify::{BlsSet, KeyNamespace, Signer};
use network_config::ChainConfig;
use ssz::Decode;
use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};
use state_transition::accessors::get_domain;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use testkit::anchor::fixtures::{pinned_export, AnchorFiles};
use testkit::anchor::load_anchor;
use tokio::runtime::Handle;
use tokio::time::Instant;
use tree_hash::TreeHash;

/// Room in each queue of the core.
pub const QUEUE: usize = 4;
/// The VerifyBls deadline of the core in these tests.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(4);

/// What the fake cl-verify answers.
#[derive(Clone, Copy, Debug)]
pub enum Answer {
    /// `VERIFY_STATUS_VALID` for each set.
    Valid,
    /// `VERIFY_STATUS_INVALID`.
    Invalid,
    /// No answer.
    Never,
    /// `VERIFY_STATUS_VALID`, but only after two deadlines.
    Late,
    /// `VERIFY_STATUS_VALID` after this wait, for each call.
    ValidAfter(Duration),
    /// `VERIFY_STATUS_VALID` at the deadline of the call, not before.
    AtDeadline,
}

/// One call to the fake cl-verify: when it came, and its deadline.
#[derive(Clone, Copy, Debug)]
pub struct Called {
    /// The time of the call.
    pub at: Instant,
    /// The deadline of the call.
    pub deadline: Instant,
}

/// A fake cl-verify. It answers each call and keeps the sets and the deadline of each call.
pub struct FakeVerify {
    /// The answer to each call in order. The last answer is also the answer to each later call.
    answers: Vec<Answer>,
    calls: Mutex<Vec<Vec<BlsSet>>>,
    called: Mutex<Vec<Called>>,
}

impl FakeVerify {
    /// A fake that gives `answer` to each call.
    pub fn new(answer: Answer) -> Arc<Self> {
        Self::answers(vec![answer])
    }

    /// A fake that gives `answers` to its calls in order, and the last one to each later call.
    pub fn answers(answers: Vec<Answer>) -> Arc<Self> {
        assert!(!answers.is_empty(), "the fake needs an answer");
        Arc::new(Self {
            answers,
            calls: Mutex::default(),
            called: Mutex::default(),
        })
    }

    /// The sets of each call.
    pub fn calls(&self) -> Vec<Vec<BlsSet>> {
        self.calls.lock().unwrap().clone()
    }

    /// The time and the deadline of each call.
    pub fn called(&self) -> Vec<Called> {
        self.called.lock().unwrap().clone()
    }
}

impl BlsVerifier for FakeVerify {
    async fn verify_sets(&self, sets: Vec<BlsSet>, deadline: Instant) -> BlsOutcome {
        let call = {
            let mut called = self.called.lock().unwrap();
            called.push(Called {
                at: Instant::now(),
                deadline,
            });
            called.len() - 1
        };
        self.calls.lock().unwrap().push(sets);
        match self.answers[call.min(self.answers.len() - 1)] {
            Answer::Valid => BlsOutcome::Valid,
            Answer::Invalid => BlsOutcome::Invalid,
            Answer::Never => std::future::pending().await,
            Answer::Late => {
                tokio::time::sleep(VERIFY_TIMEOUT * 2).await;
                BlsOutcome::Valid
            }
            Answer::ValidAfter(wait) => {
                tokio::time::sleep(wait).await;
                BlsOutcome::Valid
            }
            Answer::AtDeadline => {
                tokio::time::sleep_until(deadline).await;
                BlsOutcome::Valid
            }
        }
    }
}

/// The installed genesis anchor and the slot 1 block.
pub struct Fixture {
    pub core: ChainCore<Minimal>,
    pub anchor: Head,
    pub block: SignedBeaconBlock<Minimal>,
    pub config: ChainConfig,
}

/// [`ungated_fixture`] with the explicit gate [`PermitAll`].
pub fn fixture() -> Fixture {
    let f = ungated_fixture();
    Fixture {
        core: f.core.with_payload_gate(PermitAll),
        ..f
    }
}

/// [`anchored`] with the payload of the anchor verified ([`PayloadVerified`]), and no payload
/// gate.
///
/// The export's blocks on the anchor build on its FULL payload: their bid's
/// `parent_block_hash` is the anchor bid's `block_hash` (both zero). Its envelope cannot verify:
/// the anchor bid names builder 0, which is not in the registry. So the fixture marks that
/// payload verified, as an imported envelope would.
pub fn ungated_fixture() -> Fixture {
    let f = anchored();
    let root = f.anchor.block_root;
    Fixture {
        core: f.core.with_payload_verified(root),
        ..f
    }
}

/// A core with the payload of a block verified in its fork choice store, as if its envelope
/// imported: `fork_choice::testing::mark_payload_verified` through the test seam
/// `ChainCore::with_fork_choice`.
pub trait PayloadVerified {
    /// The same core with the payload of block `block_root` verified.
    fn with_payload_verified(self, block_root: Root) -> Self;
}

impl PayloadVerified for ChainCore<Minimal> {
    fn with_payload_verified(self, block_root: Root) -> Self {
        self.with_fork_choice(|store| {
            fork_choice::testing::mark_payload_verified(store, block_root);
        })
    }
}

/// The core of `ChainCore::from_anchor`, with [`VERIFY_TIMEOUT`], no payload gate and no
/// verified payload.
pub fn anchored() -> Fixture {
    let pinned = pinned_export().expect("the pinned export must open");
    let dir = tempfile::tempdir().unwrap();
    AnchorFiles::genesis(&pinned.export)
        .unwrap()
        .write(dir.path())
        .unwrap();
    let loaded = load_anchor::<Minimal>(dir.path()).expect("the anchor must load");
    // No payload is verified yet: the head is the EMPTY node of the anchor.
    let anchor = Head {
        block_root: loaded.block_root(),
        slot: loaded.slot(),
        state_root: loaded.state_root(),
        payload_status: PayloadStatus::Empty,
    };
    let (state, block) = loaded.into_parts();
    let core = ChainCore::from_anchor(state, block, pinned.config.clone())
        .expect("the anchor must install")
        .with_verify_timeout(VERIFY_TIMEOUT);
    assert_eq!(core.head(), anchor, "the head must be the anchor");
    Fixture {
        core,
        anchor,
        block: export_block(1),
        config: pinned.config,
    }
}

/// The block at `slot` of the pinned export.
pub fn export_block(slot: u64) -> SignedBeaconBlock<Minimal> {
    let pinned = pinned_export().expect("the pinned export must open");
    let entry = pinned
        .export
        .manifest()
        .blocks
        .iter()
        .find(|entry| entry.slot == slot)
        .expect("the export must hold a block at the slot");
    let bytes = pinned.export.block_ssz(entry).unwrap();
    SignedBeaconBlock::from_ssz_bytes(&bytes).unwrap()
}

/// Imports `block` on a core with a fake cl-verify that gives `answer`. Returns the outcome,
/// the core after its writer thread stops, and the fake.
pub async fn import_one(
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
pub async fn import_with<V: BlsVerifier + 'static>(
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
pub fn assert_unchanged(core: &ChainCore<Minimal>, anchor: Head, block_root: Root) {
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

/// The envelope of `block`, whose post-state is `post`, on the network of `config`. It passes
/// each check of `verify_execution_payload_envelope` on `post` when the bid of the block commits
/// to the empty execution requests. Its signature is no real one.
pub fn envelope_of(
    block: &SignedBeaconBlock<Minimal>,
    post: &BeaconState<Minimal>,
    config: &ChainConfig,
) -> SignedExecutionPayloadEnvelope<Minimal> {
    let bid = &post.latest_execution_payload_bid;
    let payload = ExecutionPayload::<Minimal> {
        parent_hash: post.latest_block_hash,
        fee_recipient: bid.fee_recipient,
        state_root: Bytes32::repeat_byte(0x33),
        receipts_root: Bytes32::repeat_byte(0x44),
        logs_bloom: FixedVector::from_elem(0),
        prev_randao: bid.prev_randao,
        block_number: post.slot,
        gas_limit: bid.gas_limit,
        gas_used: 0,
        timestamp: post.genesis_time + post.slot * config.slot_duration_ms() / 1000,
        extra_data: VariableList::empty(),
        base_fee_per_gas: U256::from(7u64),
        block_hash: bid.block_hash,
        transactions: ProgressiveVariableList::new(vec![]).unwrap(),
        withdrawals: ProgressiveVariableList::new(
            post.payload_expected_withdrawals.iter().cloned().collect(),
        )
        .unwrap(),
        blob_gas_used: 0,
        excess_blob_gas: 0,
        // The RLP encoding of an empty list.
        block_access_list: ProgressiveVariableList::new(vec![0xc0]).unwrap(),
        slot_number: post.slot,
    };
    SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload,
            // The export's blocks carry the empty requests for their parent payload.
            execution_requests: block.message.body.parent_execution_requests.clone(),
            builder_index: bid.builder_index,
            beacon_block_root: block.message.tree_hash_root(),
            parent_beacon_block_root: post.latest_block_header.parent_root,
        },
        // Any bytes: the fake cl-verify gives the verdict.
        signature: block.signature,
    }
}

/// An envelope of the slot 1 block, for the tests that only queue one.
pub fn some_envelope(f: &Fixture) -> SignedExecutionPayloadEnvelope<Minimal> {
    let anchor = f.core.state(&f.anchor.block_root).unwrap();
    envelope_of(&f.block, anchor, &f.config)
}

/// A clock that always reads `unix_ms`.
pub fn clock_at(unix_ms: u128) -> UnixClock {
    Arc::new(move || unix_ms)
}

/// The start of slot `slot` of the fixture chain, in Unix milliseconds.
pub fn slot_start(f: &Fixture, slot: u64) -> u128 {
    let genesis = f.core.state(&f.anchor.block_root).unwrap().genesis_time;
    u128::from(genesis) * 1000 + u128::from(slot) * u128::from(f.config.slot_duration_ms())
}

/// The proposer set of `block` on `pre`, the state that the core checks the proposer on: the
/// registry key of `proposer_index`, and the signing root in the proposer domain of the epoch
/// of the block.
pub fn proposer_set(pre: &BeaconState<Minimal>, block: &SignedBeaconBlock<Minimal>) -> BlsSet {
    let epoch = Minimal::epoch_at_slot(block.message.slot);
    let domain = get_domain(pre, DOMAIN_BEACON_PROPOSER, Some(epoch));
    proposer_set_in(pre, block, domain)
}

/// The proposer set of `block` with the registry key of `proposer_index` in `keys`, and the
/// signing root in `domain`.
pub fn proposer_set_in(
    keys: &BeaconState<Minimal>,
    block: &SignedBeaconBlock<Minimal>,
    domain: Domain,
) -> BlsSet {
    let proposer = block.message.proposer_index;
    let key = keys
        .validators
        .get(usize::try_from(proposer).unwrap())
        .unwrap()
        .pubkey;
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
