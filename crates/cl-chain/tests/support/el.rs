//! The mock EL behind an in-process cl-engine, the steps of a core test, and blocks whose
//! envelopes verify. Included by the test files that need them (`#[path]`), next to `support`.
//!
//! The newPayload and forkchoiceUpdated paths are the production ones: the core's
//! `NewPayloadClient` and an `FcuSender` call an in-process cl-engine (`EngineServer` and its
//! queue) over a Unix socket, with one `EngineSeq`, and cl-engine calls the scriptable mock EL of
//! `testkit::mock_el` over loopback HTTP with a JWT. The mock EL answers VALID to a payload or a
//! head it has no script for.
//!
//! Each step spawns the core, serves one item and joins the writer thread, so a test reads the
//! core between steps. The core keeps its newPayload client, and so its connection, across steps.
//!
//! No export block has an envelope that verifies: their bids commit to a zero execution requests
//! root. So the tests use the slot 1 block with a bid that commits to the empty requests and has
//! a payload hash of its own (`payload_block`), the slot 2 block on its FULL payload
//! (`full_child`), and that block moved to any later slot on the EMPTY node of a block
//! (`empty_child`). A local transition gives their state roots and post-states, and each
//! envelope is built from the post-state of its block (`support::envelope_of`).

use crate::support::{envelope_of, export_block, FakeVerify, Fixture, QUEUE};
use cl_chain::core::{queue, ChainCore, Outcome};
use cl_chain::engine::client::{
    EngineSeq, FcuMetrics, FcuSender, NewPayloadClient, NewPayloadMetrics,
};
use cl_engine::client::{Config, EngineEndpoint};
use cl_engine::jwt::{self, JwtSecret};
use cl_engine::queue::Queue;
use cl_engine::server::{serve, EngineServer, Limits};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock, SignedExecutionPayloadEnvelope};
use consensus_types::primitives::{BLSPubkey, Bytes32, Epoch, Hash32, Root};
use consensus_types::{EthSpec, Minimal};
use fork_choice::{DataAvailability, DataAvailabilityCheck};
use ipc::acl::{AclTables, MethodAcl};
use network_config::ChainConfig;
use state_transition::accessors::get_randao_mix;
use state_transition::caches::proposer::get_beacon_proposer_index;
use state_transition::per_slot::process_slots;
use state_transition::{
    state_root, state_transition, AggregationError, BackendError, BlsContext, PubkeyAggregator,
    SignatureBackend, SignatureSet,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use testkit::mock_el::{self, MockEl, Reply};
use tokio::net::UnixListener;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tree_hash::TreeHash;

pub type Block = SignedBeaconBlock<Minimal>;
pub type State = BeaconState<Minimal>;
pub type Envelope = SignedExecutionPayloadEnvelope<Minimal>;

/// The JWT key of the mock EL and of cl-engine: a test value.
const KEY: [u8; 32] = [0x5a; 32];
const NEW_PAYLOAD: &str = "engine_newPayloadV5";
const FORKCHOICE_UPDATED: &str = "engine_forkchoiceUpdatedV4";
const ENGINE_PATHS: [&str; 2] = [
    "/ethswarm.engine.v1.EngineService/NewPayload",
    "/ethswarm.engine.v1.EngineService/ForkchoiceUpdated",
];
/// The engine wait of the core in these tests: the mock EL answers at once unless a script
/// makes it wait.
pub const ENGINE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn hash(n: u8) -> Hash32 {
    Hash32::repeat_byte(n)
}

pub fn root(block: &Block) -> Root {
    block.message.tree_hash_root()
}

// ---------------------------------------------------------------------------------------------
// The mock EL behind an in-process cl-engine.

/// The mock EL, and cl-engine's engine.v1 server in front of it on `socket`.
pub struct El {
    pub mock: MockEl,
    socket: PathBuf,
    /// The `seq` of every engine.v1 call to this cl-engine, as in one cl-chain process.
    seq: EngineSeq,
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

/// The `0x`-hex hash `value` of a request.
fn hash_of(value: &serde_json::Value) -> Hash32 {
    let hex = value.as_str().unwrap().trim_start_matches("0x");
    Hash32::from_slice(&hex::decode(hex).unwrap())
}

impl El {
    pub async fn start() -> Self {
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
        for path in ENGINE_PATHS {
            tables.methods.insert(path.into(), vec!["cl-chain".into()]);
        }
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
            seq: EngineSeq::new(),
            _dir: dir,
            _stop: stop,
        }
    }

    /// A new newPayload client of cl-engine's socket.
    pub fn client(&self) -> NewPayloadClient {
        NewPayloadClient::new(
            &self.socket,
            ipc::testkit::own_cred().uid(),
            self.seq.clone(),
            NewPayloadMetrics::default(),
        )
    }

    /// A new forkchoiceUpdated sender to cl-engine's socket. Must be called within a Tokio
    /// runtime.
    pub fn fcu(&self) -> FcuSender {
        FcuSender::spawn(
            &self.socket,
            ipc::testkit::own_cred().uid(),
            self.seq.clone(),
            FcuMetrics::default(),
        )
    }

    /// The payload hash of each newPayload request that reached the mock EL, in order.
    pub fn new_payloads(&self) -> Vec<Hash32> {
        self.mock
            .requests()
            .into_iter()
            .filter(|r| r.method == NEW_PAYLOAD)
            .map(|r| hash_of(&r.params[0]["blockHash"]))
            .collect()
    }

    /// The head, safe and finalized hashes of each forkchoiceUpdated request that reached the
    /// mock EL, in order.
    pub fn forkchoice_updates(&self) -> Vec<[Hash32; 3]> {
        self.mock
            .requests()
            .into_iter()
            .filter(|r| r.method == FORKCHOICE_UPDATED)
            .map(|r| {
                let state = &r.params[0];
                ["headBlockHash", "safeBlockHash", "finalizedBlockHash"]
                    .map(|key| hash_of(&state[key]))
            })
            .collect()
    }

    /// The mock EL answers `reply` to each later newPayload of payload `hash`.
    pub fn answer(&self, hash: Hash32, reply: Reply) {
        self.mock.on_new_payload(hash.0, reply);
    }
}

// ---------------------------------------------------------------------------------------------
// The core and its steps.

/// A data availability check with one answer.
pub struct Data(pub DataAvailability);

impl DataAvailabilityCheck for Data {
    fn is_data_available(&self, _: Root) -> DataAvailability {
        self.0
    }
}

/// `core` with available data, the newPayload client of `el` and [`ENGINE_TIMEOUT`].
pub fn ready(core: ChainCore<Minimal>, el: &El) -> ChainCore<Minimal> {
    core.with_data_availability(Data(DataAvailability::Available))
        .with_engine(el.client())
        .with_engine_timeout(ENGINE_TIMEOUT)
}

/// An item of one step. A gossip commit item changes nothing: it is a turn of the core.
pub enum Item {
    Block(Box<Block>),
    Envelope(Box<Envelope>),
    Gossip,
}

/// Serves `item` on `core`, whose VerifyBls calls go to `verify`. Returns the outcome and the
/// core after its writer thread stops.
pub async fn step(
    core: ChainCore<Minimal>,
    item: Item,
    verify: &Arc<FakeVerify>,
) -> (Outcome, ChainCore<Minimal>) {
    let (sender, queue) = queue::<Minimal>(QUEUE);
    let reply = match item {
        Item::Block(block) => sender.import(*block),
        Item::Envelope(envelope) => sender.envelope(*envelope),
        Item::Gossip => sender.gossip(),
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

/// The block item of `block`.
pub fn block_item(block: &Block) -> Item {
    Item::Block(Box::new(block.clone()))
}

/// Commits `blocks` in order on `core`.
pub async fn commit_all(
    mut core: ChainCore<Minimal>,
    blocks: &[&Block],
    verify: &Arc<FakeVerify>,
) -> ChainCore<Minimal> {
    for block in blocks {
        let (outcome, next) = step(core, block_item(block), verify).await;
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

/// Runs `f` with the BLS context of a local transition on the network of `config`.
fn local<R>(config: &ChainConfig, f: impl FnOnce(&BlsContext) -> R) -> R {
    let schedule = |epoch: Epoch| config.get_blob_parameters(epoch).max_blobs_per_block;
    let bls = BlsContext {
        backend: &AllValid,
        aggregator: &NoAggregate,
        genesis_fork_version: config.genesis_fork_version(),
        capella_fork_version: config.capella_fork_version().unwrap(),
        blob_schedule: &schedule,
    };
    f(&bls)
}

/// `block` with the state root of its post-state on `parent`, and that post-state.
pub fn sealed(parent: &State, mut block: Block, config: &ChainConfig) -> (Block, State) {
    let mut post = parent.clone();
    local(config, |bls| {
        state_transition(&mut post, &block, false, bls)
    })
    .expect("the test block must apply");
    block.message.state_root = state_root(&mut post).unwrap();
    (block, post)
}

/// `state` after `process_slots` to `slot`: the empty slots up to it.
pub fn advanced(state: &State, slot: u64, config: &ChainConfig) -> State {
    let mut state = state.clone();
    local(config, |bls| process_slots(&mut state, slot, bls)).expect("the empty slots must apply");
    state
}

/// The slot 1 block on the anchor with the graffiti `graffiti` and a bid for the payload
/// `hash(n)` that commits to the empty execution requests: blocks with the same `n` and another
/// graffiti are siblings with the same payload hash. Sealed, with its post-state.
pub fn payload_block(f: &Fixture, n: u8, graffiti: u8) -> (Block, State) {
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
pub fn full_child(f: &Fixture, parent: &Block, post: &State, n: u8) -> (Block, State) {
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

/// The block at `slot` on the EMPTY node of `parent`, with a bid for the payload `hash(n)` that
/// commits to the empty execution requests: the slot 2 block of the export moved to `slot`, with
/// the proposer of `slot`. `pre` is the post-state of `parent`, or that state after empty slots.
/// Sealed on `pre`, with its post-state.
pub fn empty_child(
    config: &ChainConfig,
    parent: &Block,
    pre: &State,
    slot: u64,
    n: u8,
) -> (Block, State) {
    let parent_root = root(parent);
    let at = advanced(pre, slot, config);
    let mut block = export_block(2);
    let requests_root = block
        .message
        .body
        .parent_execution_requests
        .tree_hash_root();
    block.message.slot = slot;
    block.message.proposer_index = get_beacon_proposer_index(&at).unwrap();
    block.message.parent_root = parent_root;
    block.message.body.attestations = vec![].try_into().unwrap();
    block.message.body.payload_attestations = vec![].try_into().unwrap();
    let bid = &mut block.message.body.signed_execution_payload_bid.message;
    bid.slot = slot;
    bid.parent_block_root = parent_root;
    // The payload that `parent` builds on, not its own.
    bid.parent_block_hash = pre.latest_block_hash;
    bid.block_hash = hash(n);
    bid.prev_randao = get_randao_mix(&at, Minimal::epoch_at_slot(slot));
    bid.execution_requests_root = requests_root;
    sealed(pre, block, config)
}

/// The envelope of `block`, whose post-state is `post`, on the network of `config`.
pub fn envelope(config: &ChainConfig, block: &Block, post: &State) -> Item {
    Item::Envelope(Box::new(envelope_of(block, post, config)))
}

/// INVALID for the payload of the envelope of a block whose post-state is `post`, with that
/// payload's execution parent as `latestValidHash`: the table records the payload `Invalid`. (A
/// `null` one records nothing.)
pub fn invalid_on(post: &State) -> Reply {
    Reply::Invalid {
        lvh: Some(post.latest_block_hash.0),
    }
}
