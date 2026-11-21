//! Envelope import through the chain core, the execution status table of the core, and the
//! block import checks that read it, against a mock EL.
//!
//! The newPayload path is the production one: the core's `NewPayloadClient` calls an in-process
//! cl-engine (`EngineServer` and its queue) over a Unix socket, and cl-engine calls the
//! scriptable mock EL of `testkit::mock_el` over loopback HTTP with a JWT. The mock EL answers
//! VALID to a payload it has no script for. A fake cl-verify gives the VerifyBls verdicts.
//!
//! Each step spawns the core, serves one item and joins the writer thread, so a test reads the
//! core between steps. The core keeps its newPayload client, and so its connection, across steps.
//!
//! No export block has an envelope that verifies: their bids commit to a zero execution requests
//! root. So the tests use the slot 1 block with a bid that commits to the empty requests and has
//! a payload hash of its own (`payload_block`), and the slot 2 block on its FULL payload
//! (`full_child`). A local transition gives their state roots and post-states, and each envelope
//! is built from the post-state of its block (`support::envelope_of`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod support;

use cl_chain::core::{queue, ChainCore, Head, Outcome};
use cl_chain::engine::client::{EngineSeq, NewPayloadClient, NewPayloadMetrics};
use cl_chain::engine::verdict::ExecutionStatus;
use cl_engine::client::{Config, EngineEndpoint};
use cl_engine::jwt::{self, JwtSecret};
use cl_engine::queue::Queue;
use cl_engine::server::{serve, EngineServer, Limits};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock, SignedExecutionPayloadEnvelope};
use consensus_types::primitives::{BLSPubkey, Bytes32, Epoch, Hash32, Root};
use consensus_types::Minimal;
use ethswarm_proto::verify::KeyNamespace;
use fork_choice::{DataAvailability, DataAvailabilityCheck};
use ipc::acl::{AclTables, MethodAcl};
use network_config::ChainConfig;
use state_transition::{
    state_root, state_transition, AggregationError, BackendError, BlsContext, PubkeyAggregator,
    SignatureBackend, SignatureSet,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use support::{envelope_of, export_block, fixture, Answer, FakeVerify, Fixture, QUEUE};
use testkit::mock_el::{self, MockEl, Reply};
use tokio::net::UnixListener;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tree_hash::TreeHash;

type Block = SignedBeaconBlock<Minimal>;
type State = BeaconState<Minimal>;
type Envelope = SignedExecutionPayloadEnvelope<Minimal>;

/// The JWT key of the mock EL and of cl-engine: a test value.
const KEY: [u8; 32] = [0x5a; 32];
const NEW_PAYLOAD: &str = "engine_newPayloadV5";
const NEW_PAYLOAD_PATH: &str = "/ethswarm.engine.v1.EngineService/NewPayload";
/// The engine wait of the core in these tests: the mock EL answers at once unless a script
/// makes it wait.
const ENGINE_TIMEOUT: Duration = Duration::from_secs(5);

fn hash(n: u8) -> Hash32 {
    Hash32::repeat_byte(n)
}

fn root(block: &Block) -> Root {
    block.message.tree_hash_root()
}

// ---------------------------------------------------------------------------------------------
// The mock EL behind an in-process cl-engine.

/// The mock EL, and cl-engine's engine.v1 server in front of it on `socket`.
struct El {
    mock: MockEl,
    socket: PathBuf,
    _dir: tempfile::TempDir,
    _stop: oneshot::Sender<()>,
}

/// `KEY` loaded as cl-engine loads it: an owner-only `jwtsecret` credential file.
fn secret() -> JwtSecret {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(jwt::CREDENTIAL);
    std::fs::write(&path, hex::encode(KEY)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // A root-owned credential is read as an ACL grant; as root, own it as another UID.
    let euid = match rustix::process::geteuid().as_raw() {
        0 => {
            rustix::fs::chown(&path, Some(rustix::process::Uid::from_raw(4242)), None).unwrap();
            4242
        }
        uid => uid,
    };
    jwt::load(
        Some(dir.path().as_os_str()),
        euid,
        "ethswarm-engine.service",
    )
    .unwrap()
}

impl El {
    async fn start() -> Self {
        let mock = MockEl::start(mock_el::Config {
            key: KEY,
            skew: Duration::from_secs(60),
            now: SystemTime::now,
        })
        .await
        .unwrap();
        let endpoint = EngineEndpoint::parse(&mock.url(), false).unwrap();
        let queue = Queue::connect(Config::new(endpoint, secret()), 1)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut tables = AclTables::default();
        tables
            .callers
            .insert("cl-chain".into(), ipc::testkit::own_cred().uid());
        tables
            .methods
            .insert(NEW_PAYLOAD_PATH.into(), vec!["cl-chain".into()]);
        let acl = Arc::new(MethodAcl::from_tables("cl-engine", &tables).unwrap());
        let server = EngineServer::new(ipc::testkit::fixture::v1_link(), acl, queue);
        let dir = ipc::testkit::tempdir();
        let socket = dir.path().join("engine.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = oneshot::channel();
        tokio::spawn(serve(listener, server, Limits::default(), async {
            let _ = stopped.await;
        }));
        Self {
            mock,
            socket,
            _dir: dir,
            _stop: stop,
        }
    }

    /// A new newPayload client of cl-engine's socket.
    fn client(&self) -> NewPayloadClient {
        NewPayloadClient::new(
            &self.socket,
            ipc::testkit::own_cred().uid(),
            EngineSeq::new(),
            NewPayloadMetrics::default(),
        )
    }

    /// The payload hash of each newPayload request that reached the mock EL, in order.
    fn new_payloads(&self) -> Vec<Hash32> {
        self.mock
            .requests()
            .into_iter()
            .filter(|r| r.method == NEW_PAYLOAD)
            .map(|r| {
                let hex = r.params[0]["blockHash"].as_str().unwrap().to_owned();
                Hash32::from_slice(&hex::decode(hex.trim_start_matches("0x")).unwrap())
            })
            .collect()
    }

    /// The mock EL answers `reply` to each later newPayload of payload `hash`.
    fn answer(&self, hash: Hash32, reply: Reply) {
        self.mock.on_new_payload(hash.0, reply);
    }
}

// ---------------------------------------------------------------------------------------------
// The core and its steps.

/// A data availability check with one answer.
struct Data(DataAvailability);

impl DataAvailabilityCheck for Data {
    fn is_data_available(&self, _: Root) -> DataAvailability {
        self.0
    }
}

/// `core` with available data, the newPayload client of `el` and [`ENGINE_TIMEOUT`].
fn ready(core: ChainCore<Minimal>, el: &El) -> ChainCore<Minimal> {
    core.with_data_availability(Data(DataAvailability::Available))
        .with_engine(el.client())
        .with_engine_timeout(ENGINE_TIMEOUT)
}

/// An item of one step.
enum Item {
    Block(Box<Block>),
    Envelope(Box<Envelope>),
}

/// Serves `item` on `core`, whose VerifyBls calls go to `verify`. Returns the outcome and the
/// core after its writer thread stops.
async fn step(
    core: ChainCore<Minimal>,
    item: Item,
    verify: &Arc<FakeVerify>,
) -> (Outcome, ChainCore<Minimal>) {
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let reply = match item {
        Item::Block(block) => sender.import(*block),
        Item::Envelope(envelope) => sender.envelope(*envelope),
    }
    .expect("the queue must have room");
    let writer = core
        .spawn(queue, Arc::clone(verify), Handle::current())
        .unwrap();
    let served = reply.await.expect("the core must answer");
    drop(sender);
    let core = tokio::task::spawn_blocking(move || writer.join().unwrap())
        .await
        .unwrap();
    (served.outcome, core)
}

/// Commits `blocks` in order on `core`.
async fn commit_all(
    mut core: ChainCore<Minimal>,
    blocks: &[&Block],
    verify: &Arc<FakeVerify>,
) -> ChainCore<Minimal> {
    for block in blocks {
        let (outcome, next) = step(core, Item::Block(Box::new((*block).clone())), verify).await;
        assert_eq!(
            outcome,
            Outcome::Committed {
                block_root: root(block),
                state_root: block.message.state_root
            }
        );
        core = next;
    }
    core
}

/// What a test can read of the core state, for the roots of `roots`.
#[derive(Debug, PartialEq)]
struct Observed {
    head: Head,
    pre_states: usize,
    /// For each root: a pre-state, committed, payload verified, a kept refusal.
    roots: Vec<(Root, bool, bool, bool, bool)>,
}

fn observe(core: &ChainCore<Minimal>, roots: &[Root]) -> Observed {
    Observed {
        head: core.head(),
        pre_states: core.pre_states(),
        roots: roots
            .iter()
            .map(|r| {
                (
                    *r,
                    core.state(r).is_some(),
                    core.is_committed(r),
                    core.payload_verified(r),
                    core.is_refused(r),
                )
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------------------------
// Blocks whose envelopes verify.

/// A local transition checks no signature: the fake cl-verify of the core answers VALID.
struct AllValid;

impl SignatureBackend for AllValid {
    fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
        Ok(true)
    }
}

/// The test blocks are in the first sync committee period: no aggregate.
struct NoAggregate;

impl PubkeyAggregator for NoAggregate {
    fn aggregate_pubkeys(&self, _: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError> {
        Err(AggregationError("no aggregate in these tests".into()))
    }
}

/// `block` with the state root of its post-state on `parent`, and that post-state.
fn sealed(parent: &State, mut block: Block, config: &ChainConfig) -> (Block, State) {
    let schedule = |epoch: Epoch| config.get_blob_parameters(epoch).max_blobs_per_block;
    let bls = BlsContext {
        backend: &AllValid,
        aggregator: &NoAggregate,
        genesis_fork_version: config.genesis_fork_version(),
        capella_fork_version: config.capella_fork_version().unwrap(),
        blob_schedule: &schedule,
    };
    let mut post = parent.clone();
    state_transition(&mut post, &block, false, &bls).expect("the test block must apply");
    block.message.state_root = state_root(&mut post).unwrap();
    (block, post)
}

/// The slot 1 block on the anchor with the graffiti `graffiti` and a bid for the payload
/// `hash(n)` that commits to the empty execution requests: blocks with the same `n` and another
/// graffiti are siblings with the same payload hash. Sealed, with its post-state.
fn payload_block(f: &Fixture, n: u8, graffiti: u8) -> (Block, State) {
    let mut block = f.block.clone();
    let requests_root = block
        .message
        .body
        .parent_execution_requests
        .tree_hash_root();
    block.message.body.graffiti = Bytes32::repeat_byte(graffiti);
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.block_hash = hash(n);
    bid.execution_requests_root = requests_root;
    let anchor = f.core.state(&f.anchor.block_root).unwrap();
    sealed(anchor, block, &f.config)
}

/// The slot 2 block on the FULL payload of `parent`, whose post-state is `post`, with a bid for
/// the payload `hash(n)` that commits to the empty execution requests. Sealed, with its
/// post-state.
fn full_child(f: &Fixture, parent: &Block, post: &State, n: u8) -> (Block, State) {
    let parent_root = root(parent);
    let mut block = export_block(2);
    let requests_root = block
        .message
        .body
        .parent_execution_requests
        .tree_hash_root();
    block.message.parent_root = parent_root;
    // They name the slot 1 block of the export.
    block.message.body.attestations = vec![].try_into().unwrap();
    block.message.body.payload_attestations = vec![].try_into().unwrap();
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.parent_block_root = parent_root;
    bid.parent_block_hash = post.latest_execution_payload_bid.block_hash;
    bid.block_hash = hash(n);
    bid.execution_requests_root = requests_root;
    sealed(post, block, &f.config)
}

/// The envelope of `block`, whose post-state is `post`, on the network of `config`.
fn envelope(config: &ChainConfig, block: &Block, post: &State) -> Item {
    Item::Envelope(Box::new(envelope_of(block, post, config)))
}

/// INVALID for the payload of the envelope of a block whose post-state is `post`, with that
/// payload's execution parent as `latestValidHash`: the table records the payload `Invalid`. (A
/// `null` one records nothing.)
fn invalid_on(post: &State) -> Reply {
    Reply::Invalid {
        lvh: Some(post.latest_block_hash.0),
    }
}

// ---------------------------------------------------------------------------------------------
// Envelope import.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_valid_answer_verifies_the_payload_and_a_block_on_it_commits() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0x31, 1);
    let (c, _) = full_child(&f, &p, &post, 0x32);
    let Fixture { core, config, .. } = f;
    let verify = FakeVerify::new(Answer::Valid);
    let core = commit_all(ready(core, &el), &[&p], &verify).await;
    // Its payload is not verified yet: a block on it is IGNORE, before cl-verify.
    let calls = verify.calls().len();
    let (outcome, core) = step(core, Item::Block(Box::new(c.clone())), &verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(verify.calls().len(), calls, "no VerifyBls call");

    let (outcome, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p)
        }
    );
    assert!(core.payload_verified(&root(&p)));
    assert_eq!(
        core.execution_statuses().status(&hash(0x31)),
        Some(ExecutionStatus::Valid)
    );
    assert_eq!(el.new_payloads(), vec![hash(0x31)]);
    let calls_now = verify.calls();
    assert_eq!(
        calls_now.len(),
        calls + 1,
        "the envelope signature goes to cl-verify in one call"
    );
    let signer = &calls_now[calls][0].signers[0];
    assert_eq!(signer.namespace, KeyNamespace::Validator as i32);
    assert_eq!(
        signer.validator_index, p.message.proposer_index,
        "a self-build envelope is signed by the proposer of its block"
    );

    let (outcome, core) = step(core, Item::Block(Box::new(c.clone())), &verify).await;
    assert_eq!(
        outcome,
        Outcome::Committed {
            block_root: root(&c),
            state_root: c.message.state_root
        }
    );
    // The same envelope again: IGNORE, with no VerifyBls call and no newPayload.
    let calls = verify.calls().len();
    let (outcome, _) = step(core, envelope(&config, &p, &post), &verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(verify.calls().len(), calls);
    assert_eq!(el.new_payloads().len(), 1);
}

/// An INVALID answer with a `latestValidHash` rejects the envelope and records its payload
/// `Invalid`. A block whose bid builds on that payload, or claims it, is then IGNORE before
/// cl-verify, and the core keeps no refusal of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_answer_rejects_the_envelope_and_refuses_blocks_on_its_payload_hash() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0x41, 1);
    // A sibling that claims the same payload, and a block on the anchor whose bid builds on it.
    let (claims, _) = payload_block(&f, 0x41, 2);
    let mut builds_on = f.block.clone();
    builds_on
        .message
        .body
        .signed_execution_payload_bid
        .message
        .parent_block_hash = hash(0x41);
    let Fixture { core, config, .. } = f;
    let verify = FakeVerify::new(Answer::Valid);
    let core = commit_all(ready(core, &el), &[&p], &verify).await;
    el.answer(hash(0x41), invalid_on(&post));
    let roots = [root(&p), root(&claims), root(&builds_on)];
    let before = observe(&core, &roots);

    let (outcome, mut core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert!(
        matches!(outcome, Outcome::InvalidEnvelope(_)),
        "{outcome:?}"
    );
    assert_eq!(el.new_payloads(), vec![hash(0x41)]);
    let statuses = core.execution_statuses();
    assert_eq!(statuses.status(&hash(0x41)), Some(ExecutionStatus::Invalid));
    assert!(!statuses.el_contradiction());
    assert_eq!(
        observe(&core, &roots),
        before,
        "a REJECT changes no core state"
    );

    for block in [builds_on, claims] {
        let calls = verify.calls().len();
        let (outcome, next) = step(core, Item::Block(Box::new(block)), &verify).await;
        assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
        assert_eq!(verify.calls().len(), calls, "no VerifyBls call");
        assert_eq!(
            observe(&next, &roots),
            before,
            "nothing kept, nothing committed"
        );
        core = next;
    }
}

/// SYNCING imports the payload optimistically: the table permits it. The same answer for a
/// payload whose execution parent the EL has found INVALID since is refused by the table: IGNORE,
/// and the payload is not verified.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_syncing_answer_is_optimistic_and_not_permitted_on_an_invalid_parent() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0x51, 1);
    let (sibling, sibling_post) = payload_block(&f, 0x51, 2);
    let (c, c_post) = full_child(&f, &p, &post, 0x52);
    let Fixture { core, config, .. } = f;
    let verify = FakeVerify::new(Answer::Valid);
    let core = commit_all(ready(core, &el), &[&p, &sibling], &verify).await;

    el.answer(hash(0x51), Reply::Syncing);
    let (outcome, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p)
        }
    );
    assert_eq!(
        core.execution_statuses().status(&hash(0x51)),
        Some(ExecutionStatus::Optimistic)
    );
    let core = commit_all(core, &[&c], &verify).await;

    // The EL finds that payload INVALID, through the envelope of the sibling.
    el.answer(hash(0x51), invalid_on(&sibling_post));
    let (outcome, core) = step(core, envelope(&config, &sibling, &sibling_post), &verify).await;
    assert!(
        matches!(outcome, Outcome::InvalidEnvelope(_)),
        "{outcome:?}"
    );
    assert_eq!(
        core.execution_statuses().status(&hash(0x51)),
        Some(ExecutionStatus::Invalid)
    );

    el.answer(hash(0x52), Reply::Syncing);
    let roots = [root(&p), root(&sibling), root(&c)];
    let before = observe(&core, &roots);
    let (outcome, core) = step(core, envelope(&config, &c, &c_post), &verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(el.new_payloads(), vec![hash(0x51), hash(0x51), hash(0x52)]);
    let statuses = core.execution_statuses();
    assert_eq!(
        statuses.status(&hash(0x52)),
        Some(ExecutionStatus::Invalid),
        "a payload on an INVALID parent is INVALID"
    );
    assert!(!statuses.el_contradiction());
    assert!(!core.payload_verified(&root(&c)));
    assert_eq!(observe(&core, &roots), before);
}

/// A payload verified on SYNCING stays as the table has it when its envelope comes again: that
/// envelope is IGNORE, with no VerifyBls call and no newPayload, also when the EL would now
/// answer VALID. Its status changes only through a later verdict on a descendant or a later
/// fork-choice update.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_optimistic_payload_is_not_checked_again_by_its_envelope() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0x56, 1);
    let Fixture { core, config, .. } = f;
    let verify = FakeVerify::new(Answer::Valid);
    let core = commit_all(ready(core, &el), &[&p], &verify).await;
    el.answer(hash(0x56), Reply::Syncing);
    let (outcome, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p)
        }
    );
    assert_eq!(
        core.execution_statuses().status(&hash(0x56)),
        Some(ExecutionStatus::Optimistic)
    );

    el.answer(hash(0x56), Reply::Valid);
    let roots = [root(&p)];
    let before = observe(&core, &roots);
    let calls = verify.calls().len();
    let (outcome, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(verify.calls().len(), calls, "no VerifyBls call");
    assert_eq!(el.new_payloads(), vec![hash(0x56)], "no second newPayload");
    let statuses = core.execution_statuses();
    assert_eq!(
        statuses.status(&hash(0x56)),
        Some(ExecutionStatus::Optimistic)
    );
    assert!(!statuses.el_contradiction());
    assert_eq!(observe(&core, &roots), before);
}

/// INVALID with a `null` `latestValidHash` is the Engine API's answer to a payload that does not
/// hash to the `block_hash` that it claims. A tampered envelope can keep the claimed hash and each
/// field that the bid binds, and change one that it does not. That answer refuses that envelope
/// only: the table records no status for the hash and no EL contradiction, and the core state
/// does not change. The honest envelope of the block then imports on VALID, and a block on its
/// FULL payload commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_envelope_answered_invalid_with_null_leaves_the_honest_payload_importable() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0xc1, 1);
    let (c, _) = full_child(&f, &p, &post, 0xc2);
    let Fixture { core, config, .. } = f;
    let verify = FakeVerify::new(Answer::Valid);
    let core = commit_all(ready(core, &el), &[&p], &verify).await;
    let honest = envelope_of(&p, &post, &config);
    let mut tampered = honest.clone();
    tampered.message.payload.extra_data = vec![0xee; 4].try_into().unwrap();
    tampered.message.payload.gas_used = 21_000;
    assert_eq!(tampered.message.payload.block_hash, hash(0xc1));
    assert_ne!(tampered, honest);

    el.answer(hash(0xc1), Reply::Invalid { lvh: None });
    let roots = [root(&p), root(&c)];
    let before = observe(&core, &roots);
    let (outcome, core) = step(core, Item::Envelope(Box::new(tampered)), &verify).await;
    assert!(
        matches!(outcome, Outcome::InvalidEnvelope(_) | Outcome::Ignored(_)),
        "{outcome:?}"
    );
    assert_eq!(
        el.new_payloads(),
        vec![hash(0xc1)],
        "the tampered payload passes the bid checks and reaches the EL"
    );
    let statuses = core.execution_statuses();
    assert_eq!(statuses.status(&hash(0xc1)), None, "no status for the hash");
    assert!(!statuses.el_contradiction());
    assert_eq!(observe(&core, &roots), before, "no core state changes");

    el.answer(hash(0xc1), Reply::Valid);
    let (outcome, core) = step(core, Item::Envelope(Box::new(honest)), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p)
        }
    );
    assert_eq!(el.new_payloads(), vec![hash(0xc1), hash(0xc1)]);
    let statuses = core.execution_statuses();
    assert_eq!(statuses.status(&hash(0xc1)), Some(ExecutionStatus::Valid));
    assert!(!statuses.el_contradiction());
    assert!(core.payload_verified(&root(&p)));

    commit_all(core, &[&c], &verify).await;
}

/// No verdict is IGNORE and records nothing: no cl-engine at the socket, an EL that drops the
/// call, and an EL that answers after the engine wait of the core.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_answer_in_time_is_ignored_and_records_nothing() {
    let el = El::start().await;
    let late = El::start().await;
    let f = fixture();
    let blocks: Vec<(Block, State)> = (1..=3).map(|i| payload_block(&f, 0x60 + i, i)).collect();
    let Fixture { core, config, .. } = f;
    let verify = FakeVerify::new(Answer::Valid);
    let refs: Vec<&Block> = blocks.iter().map(|(block, _)| block).collect();
    let core = commit_all(ready(core, &el), &refs, &verify).await;
    let roots: Vec<Root> = refs.iter().map(|block| root(block)).collect();
    let before = observe(&core, &roots);
    let wait = Duration::from_millis(500);
    let nowhere = tempfile::tempdir().unwrap();
    let nobody = NewPayloadClient::new(
        nowhere.path().join("engine.sock"),
        ipc::testkit::own_cred().uid(),
        EngineSeq::new(),
        NewPayloadMetrics::default(),
    );
    el.answer(hash(0x62), Reply::Drop);
    late.answer(hash(0x63), Reply::Delay(Duration::from_secs(30)));
    let engines = [nobody, el.client(), late.client()];
    let mut core = core.with_engine_timeout(wait);
    for ((block, post), engine) in blocks.iter().zip(engines) {
        let hash = block
            .message
            .body
            .signed_execution_payload_bid
            .message
            .block_hash;
        let started = std::time::Instant::now();
        let (outcome, next) = step(
            core.with_engine(engine),
            envelope(&config, block, post),
            &verify,
        )
        .await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "{hash}: {outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{hash}: the engine wait of the core bounds the call"
        );
        assert_eq!(next.execution_statuses().status(&hash), None, "{hash}");
        assert_eq!(observe(&next, &roots), before, "{hash}");
        core = next;
    }
    assert!(el.new_payloads().contains(&hash(0x62)));
    assert_eq!(late.new_payloads(), vec![hash(0x63)]);
}

/// The checks before cl-verify and the EL: a core with no data availability check, data that
/// is not available, a core with no engine, and an envelope whose block is not committed are
/// each IGNORE, with no VerifyBls call and no newPayload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_envelope_without_its_block_its_data_or_an_engine_is_ignored_before_cl_verify() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0x81, 1);
    let (unknown, unknown_post) = payload_block(&f, 0x82, 2);
    let Fixture { core, config, .. } = f;
    let verify = FakeVerify::new(Answer::Valid);
    // No data availability check and no engine.
    let core = commit_all(core, &[&p], &verify).await;
    let calls = verify.calls().len();
    let roots = [root(&p), root(&unknown)];
    let before = observe(&core, &roots);

    let (outcome, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "no check: {outcome:?}"
    );
    let core = core.with_data_availability(Data(DataAvailability::Unavailable));
    let (outcome, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "unavailable: {outcome:?}"
    );
    let core = core.with_data_availability(Data(DataAvailability::Available));
    let (outcome, core) = step(core, envelope(&config, &p, &post), &verify).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "no engine: {outcome:?}"
    );
    let core = ready(core, &el);
    let (outcome, core) = step(core, envelope(&config, &unknown, &unknown_post), &verify).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "not committed: {outcome:?}"
    );
    assert_eq!(verify.calls().len(), calls, "no VerifyBls call");
    assert!(el.new_payloads().is_empty(), "no newPayload");
    assert_eq!(observe(&core, &roots), before);

    let (outcome, _) = step(core, envelope(&config, &p, &post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p)
        }
    );
}

/// A failed consensus check keeps the outcome that fork choice gives it, before the EL: a bad
/// signature and a payload that does not match the bid are REJECT, and no verdict from cl-verify
/// is IGNORE. None changes the core state, and the envelope imports after them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_envelope_is_refused_before_the_el() {
    let el = El::start().await;
    let f = fixture();
    let (p, post) = payload_block(&f, 0x91, 1);
    let Fixture { core, config, .. } = f;
    let core = commit_all(ready(core, &el), &[&p], &FakeVerify::new(Answer::Valid)).await;
    let roots = [root(&p)];
    let before = observe(&core, &roots);
    let good = envelope_of(&p, &post, &config);
    let mut gas = good.clone();
    gas.message.payload.gas_limit += 1;
    let cases = [
        (good.clone(), Answer::Invalid, true),
        (good.clone(), Answer::Never, false),
        (gas, Answer::Valid, true),
    ];
    let mut core = core.with_verify_timeout(Duration::from_millis(300));
    for (i, (envelope, answer, rejected)) in cases.into_iter().enumerate() {
        let verify = FakeVerify::new(answer);
        let (outcome, next) = step(core, Item::Envelope(Box::new(envelope)), &verify).await;
        if rejected {
            assert!(
                matches!(outcome, Outcome::InvalidEnvelope(_)),
                "case {i}: {outcome:?}"
            );
        } else {
            assert!(
                matches!(outcome, Outcome::Ignored(_)),
                "case {i}: {outcome:?}"
            );
        }
        assert_eq!(verify.calls().len(), 1, "case {i}: the envelope signature");
        assert!(el.new_payloads().is_empty(), "case {i}: no newPayload");
        assert_eq!(observe(&next, &roots), before, "case {i}");
        core = next;
    }
    let (outcome, _) = step(
        core,
        Item::Envelope(Box::new(good)),
        &FakeVerify::new(Answer::Valid),
    )
    .await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&p)
        }
    );
}

// ---------------------------------------------------------------------------------------------
// Fail closed on an EL contradiction.

/// A core whose EL contradicted itself, and what the tests read after it.
struct Contradicted {
    el: El,
    config: ChainConfig,
    core: ChainCore<Minimal>,
    verify: Arc<FakeVerify>,
    /// The outcome of the envelope whose answer set the contradiction.
    outcome: Outcome,
    /// The core state before that envelope.
    before: Observed,
    roots: Vec<Root>,
    /// The block of that envelope.
    refused: Block,
    /// A committed block whose payload is not verified, with its post-state.
    pending: (Block, State),
    /// A block on the FULL payload of a block whose payload is verified: not imported.
    child: Block,
}

/// Two committed siblings with the same payload hash, and a third committed block with another.
/// The EL answers VALID to the envelope of the first, and then INVALID with a `latestValidHash` to
/// the same payload, through the envelope of the second: it calls a VALID payload INVALID.
async fn contradicted() -> Contradicted {
    let el = El::start().await;
    let f = fixture();
    let (first, first_post) = payload_block(&f, 0x71, 1);
    let (second, second_post) = payload_block(&f, 0x71, 2);
    let pending = payload_block(&f, 0x73, 3);
    let (child, _) = full_child(&f, &first, &first_post, 0x74);
    let Fixture { core, config, .. } = f;
    let verify = FakeVerify::new(Answer::Valid);
    let core = commit_all(ready(core, &el), &[&first, &second, &pending.0], &verify).await;
    let (outcome, core) = step(core, envelope(&config, &first, &first_post), &verify).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&first)
        }
    );
    assert!(!core.execution_statuses().el_contradiction());
    let roots = vec![root(&first), root(&second), root(&pending.0), root(&child)];
    let before = observe(&core, &roots);
    el.answer(hash(0x71), invalid_on(&second_post));
    let (outcome, core) = step(core, envelope(&config, &second, &second_post), &verify).await;
    Contradicted {
        el,
        config,
        core,
        verify,
        outcome,
        before,
        roots,
        refused: second,
        pending,
        child,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_answer_that_sets_the_el_contradiction_is_refused() {
    let t = contradicted().await;
    let statuses = t.core.execution_statuses();
    assert!(
        statuses.el_contradiction(),
        "the EL called a VALID payload INVALID"
    );
    assert!(
        matches!(t.outcome, Outcome::Ignored(_)),
        "the envelope must be IGNORE, neither imported nor REJECT: {:?}",
        t.outcome
    );
    assert!(
        !t.core.payload_verified(&root(&t.refused)),
        "its payload must not be verified"
    );
    assert_eq!(
        t.el.new_payloads(),
        vec![hash(0x71), hash(0x71)],
        "the EL gave that answer"
    );
    assert_eq!(
        statuses.status(&hash(0x71)),
        Some(ExecutionStatus::Valid),
        "the table keeps the status it had"
    );
    assert_eq!(observe(&t.core, &t.roots), t.before, "nothing else changes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_the_el_contradiction_an_envelope_is_refused_with_no_new_payload_and_no_verify_bls() {
    let t = contradicted().await;
    let (block, post) = &t.pending;
    let requests = t.el.new_payloads().len();
    let calls = t.verify.calls().len();
    let (outcome, core) = step(t.core, envelope(&t.config, block, post), &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(
        t.el.new_payloads().len(),
        requests,
        "no newPayload request may reach the EL"
    );
    assert_eq!(t.verify.calls().len(), calls, "no VerifyBls call");
    assert!(!core.payload_verified(&root(block)));
    assert_eq!(observe(&core, &t.roots), t.before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_the_el_contradiction_a_block_is_refused_and_the_head_and_committed_roots_stay() {
    let t = contradicted().await;
    let child = root(&t.child);
    let calls = t.verify.calls().len();
    let head = t.core.head();
    let (outcome, core) = step(t.core, Item::Block(Box::new(t.child.clone())), &t.verify).await;
    assert!(matches!(outcome, Outcome::Ignored(_)), "{outcome:?}");
    assert_eq!(t.verify.calls().len(), calls, "no VerifyBls call");
    assert_eq!(core.head(), head, "the head must stay");
    assert!(
        !core.is_committed(&child),
        "the block must not be committed"
    );
    assert!(
        core.state(&child).is_none(),
        "the block must have no pre-state"
    );
    assert!(!core.is_refused(&child), "the refusal must not be kept");
    assert_eq!(observe(&core, &t.roots), t.before);
}

/// Each refused path, in turn on one core: the observable core state (the head, the pre-states,
/// the committed roots, the payload-verified roots and the kept refusals) is the same before and
/// after it. Only the table records the verdicts the EL gave.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_refused_path_leaves_the_core_state_as_it_was() {
    let el = El::start().await;
    let f = fixture();
    let (first, first_post) = payload_block(&f, 0xa1, 1);
    let (second, second_post) = payload_block(&f, 0xa1, 2);
    let (bad, bad_post) = payload_block(&f, 0xa3, 3);
    let (unknown, unknown_post) = payload_block(&f, 0xa5, 5);
    let (child, _) = full_child(&f, &first, &first_post, 0xa4);
    let mut builds_on_bad = f.block.clone();
    builds_on_bad
        .message
        .body
        .signed_execution_payload_bid
        .message
        .parent_block_hash = hash(0xa3);
    let Fixture { core, config, .. } = f;
    let valid = FakeVerify::new(Answer::Valid);
    let core = commit_all(ready(core, &el), &[&first, &second, &bad], &valid).await;
    let (outcome, mut core) = step(core, envelope(&config, &first, &first_post), &valid).await;
    assert_eq!(
        outcome,
        Outcome::PayloadVerified {
            block_root: root(&first)
        }
    );
    let roots = [&first, &second, &bad, &unknown, &child, &builds_on_bad].map(root);

    let steps = [
        (
            "an envelope of a block that is not committed",
            envelope(&config, &unknown, &unknown_post),
            Answer::Valid,
            None,
        ),
        (
            "an envelope with a bad signature",
            envelope(&config, &bad, &bad_post),
            Answer::Invalid,
            None,
        ),
        (
            "an envelope that the EL finds INVALID",
            envelope(&config, &bad, &bad_post),
            Answer::Valid,
            Some((hash(0xa3), invalid_on(&bad_post))),
        ),
        (
            "a block on an INVALID payload",
            Item::Block(Box::new(builds_on_bad.clone())),
            Answer::Valid,
            None,
        ),
        (
            "the answer that sets the EL contradiction",
            envelope(&config, &second, &second_post),
            Answer::Valid,
            Some((hash(0xa1), invalid_on(&second_post))),
        ),
        (
            "an envelope after the EL contradiction",
            envelope(&config, &bad, &bad_post),
            Answer::Valid,
            None,
        ),
        (
            "a block after the EL contradiction",
            Item::Block(Box::new(child.clone())),
            Answer::Valid,
            None,
        ),
    ];
    for (what, item, answer, script) in steps {
        if let Some((hash, reply)) = script {
            el.answer(hash, reply);
        }
        let before = observe(&core, &roots);
        let (outcome, next) = step(core, item, &FakeVerify::new(answer)).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_) | Outcome::InvalidEnvelope(_)),
            "{what}: {outcome:?}"
        );
        assert_eq!(observe(&next, &roots), before, "{what}");
        core = next;
    }
    assert!(core.execution_statuses().el_contradiction());
}
