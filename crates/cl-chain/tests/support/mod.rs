//! The fixture of the chain core tests.
//!
//! Each test installs the genesis anchor of the pinned minimal Gloas export. The anchor comes
//! from a temporary directory in the `anchor-fetch` layout, through
//! `testkit::anchor::load_anchor`. The block to import is the slot 1 block of the same export.
//! A fake cl-verify behind `BlsVerifier` gives the VerifyBls verdicts.

use cl_chain::core::{queue, ChainCore, Head, Outcome};
use cl_chain::import::block::PermitAll;
use cl_chain::verify::client::{BlsOutcome, BlsVerifier};
use consensus_types::gloas::SignedBeaconBlock;
use consensus_types::primitives::Root;
use consensus_types::Minimal;
use ethswarm_proto::verify::BlsSet;
use network_config::ChainConfig;
use ssz::Decode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use testkit::anchor::fixtures::{pinned_export, AnchorFiles};
use testkit::anchor::load_anchor;
use tokio::runtime::Handle;
use tokio::time::Instant;

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
}

/// One call to the fake cl-verify: when it came, and its deadline.
#[derive(Clone, Copy, Debug)]
pub struct Called {
    /// The time of the call.
    pub at: Instant,
    /// The deadline of the call.
    pub deadline: Instant,
}

/// A fake cl-verify. It gives one answer to each call and keeps the sets and the deadline of
/// each call.
pub struct FakeVerify {
    answer: Answer,
    calls: Mutex<Vec<Vec<BlsSet>>>,
    called: Mutex<Vec<Called>>,
}

impl FakeVerify {
    pub fn new(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            answer,
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
        self.called.lock().unwrap().push(Called {
            at: Instant::now(),
            deadline,
        });
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

/// The core of `ChainCore::from_anchor`, with [`VERIFY_TIMEOUT`] and no payload gate.
pub fn ungated_fixture() -> Fixture {
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
