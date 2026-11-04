//! #146, step 7: the in-repo stand-in for the Kurtosis acceptance criterion ("a Lighthouse node
//! range-syncs with our node as its only server"). The real cl-store `StoreServer` and the real
//! cl-chain `ReqRespServer` serve one env over Unix sockets; our swarm answers BeaconBlocksByRange
//! v2 with the production responder over the production IPC client; the requester is the probe's
//! own `RangeRequester`, which checks every block's context bytes and parent link. It syncs the
//! fixture's five epochs across finality and the Fulu→Gloas switch.

use cl_chain::reqresp::{
    BlockStore, ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock,
};
use cl_chain_columns::ColumnWriter;
use cl_p2p::behaviour::SpecBehaviour;
use cl_p2p::rpc::blocks::ByRangeResponder;
use cl_p2p::rpc::blocks_ipc::IpcBlocks;
use cl_p2p::rpc::inbound::{Control, SharedStatus, StatusSource};
use cl_p2p::rpc::metrics::RpcMetrics;
use cl_p2p::rpc::outbound::RangeRequester;
use cl_p2p::transport::{build_swarm, MuxerBudget, SwarmConfig, TransportMetrics};
use consensus_types::caps::NetworkCaps;
use consensus_types::primitives::U256;
use consensus_types::{forked, Minimal};
use ethswarm_proto::common::Hello;
use futures::StreamExt as _;
use ipc::envelope::DigestTable;
use ipc::Link;
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::Swarm;
use network_config::{Epoch, ForkName, ForkSchedule, ScheduledFork};
use p2p_wire::rpc::codec::ContextTable;
use p2p_wire::rpc::messages::{ForkDigest, StatusV2};
use p2p_wire::testkit::{fulu_block, gloas_block, FULU_BPO_DIGEST, FULU_DIGEST, GLOAS_DIGEST};
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::borrow::Borrow;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use store_schema::env::{test_writer, Env, RoTxn, WriterEnv};
use store_schema::stamp::Stamp;
use store_schema::txn::{self, Update};
use tokio::net::UnixListener;

type E = Minimal;

const WAIT: Duration = Duration::from_secs(20);
/// The fixture: slots 1 to 40 but these, each block on the one before; a fork block at 36.
const SKIPPED: [u64; 4] = [5, 17, 33, 36];
const HEAD: u64 = 40;
const FINALIZED: u64 = 20;

/// Fulu from epoch 0, Gloas from epoch 4 (8 slots an epoch).
fn schedule() -> ForkSchedule {
    let at = |version, epoch| ScheduledFork { version, epoch };
    ForkSchedule::new(at([6, 0, 0, 1], 0), at([7, 0, 0, 1], 4)).unwrap()
}

/// Fulu's digest from epoch 0, its BPO digest from 2, Gloas's from 4.
fn digest_at(epoch: Epoch) -> ForkDigest {
    match epoch {
        0..=1 => FULU_DIGEST,
        2..=3 => FULU_BPO_DIGEST,
        _ => GLOAS_DIGEST,
    }
}

/// The link every side holds: the fixture schedule and digests.
fn link() -> Link {
    let hello = Hello {
        api_version: 1,
        min_api_version: 1,
        max_api_version: 1,
        ..Default::default()
    };
    let digests = DigestTable::new(vec![
        (0, ForkName::Fulu, FULU_DIGEST),
        (2, ForkName::Fulu, FULU_BPO_DIGEST),
        (4, ForkName::Gloas, GLOAS_DIGEST),
    ])
    .unwrap();
    Link::new::<E>(hello, 1, schedule(), digests)
}

/// The context table a swarm serves and reads with.
fn contexts() -> Arc<ContextTable> {
    let mut table = ContextTable::new().with_network_caps(NetworkCaps::PRESET_BOUND);
    table.insert_from(0, FULU_DIGEST, ForkName::Fulu);
    table.insert_from(2, FULU_BPO_DIGEST, ForkName::Fulu);
    table.insert_from(4, GLOAS_DIGEST, ForkName::Gloas);
    Arc::new(table)
}

/// A block at `slot` on `parent`, Fulu before epoch 4 and Gloas from it.
fn block(slot: u64, parent: [u8; 32], salt: u64) -> forked::SignedBeaconBlock<E> {
    if slot < 32 {
        let mut b = fulu_block::<E>(slot);
        b.message.parent_root = parent.into();
        b.message.proposer_index = salt;
        forked::SignedBeaconBlock::Fulu(b)
    } else {
        let mut b = gloas_block::<E>(slot);
        b.message.parent_root = parent.into();
        b.message.proposer_index = salt;
        forked::SignedBeaconBlock::Gloas(b)
    }
}

/// The canonical chain, and the fork block at 36 on the block at 35.
fn fixture() -> (
    Vec<forked::SignedBeaconBlock<E>>,
    forked::SignedBeaconBlock<E>,
) {
    let mut chain: Vec<forked::SignedBeaconBlock<E>> = Vec::new();
    for slot in (1..=HEAD).filter(|s| !SKIPPED.contains(s)) {
        let parent = chain.last().map_or([0; 32], |b| b.message_root().0);
        chain.push(block(slot, parent, 0));
    }
    let at_35 = chain
        .iter()
        .find(|b| b.slot() == 35)
        .unwrap()
        .message_root()
        .0;
    (chain, block(36, at_35, 9))
}

/// cl-chain's env, shared by both servers (one process opens an env once).
#[derive(Clone)]
struct Shared(Arc<WriterEnv>);

impl Borrow<Env> for Shared {
    fn borrow(&self) -> &Env {
        self.0.raw_env()
    }
}

impl BlockStore for Shared {
    fn read_txn(&self) -> Result<RoTxn<'_>, String> {
        self.0.begin_ro_txn().map_err(|e| e.to_string())
    }
}

/// The env holding the fixture, stamped head [`HEAD`], finalized [`FINALIZED`].
fn seeded(dir: &Path) -> (Shared, Vec<forked::SignedBeaconBlock<E>>) {
    let writer = test_writer(dir).unwrap();
    let (chain, fork) = fixture();
    let root = |slot: u64| {
        chain
            .iter()
            .find(|b| b.slot() == slot)
            .unwrap()
            .message_root()
            .0
    };
    let txn = txn::begin(&writer).unwrap();
    for b in chain.iter().chain([&fork]) {
        store_schema::blocks::put::<E>(&txn, &schedule(), &b.as_ssz_bytes()).unwrap();
    }
    let stamp = Stamp {
        head_seq: 5,
        head_root: root(HEAD),
        head_slot: HEAD,
        finalized_root: root(FINALIZED),
        finalized_slot: FINALIZED,
    };
    txn::commit(txn, Update::New(stamp)).unwrap();
    (Shared(Arc::new(writer)), chain)
}

/// A clock for the column server the chain.v1 server is built with (no column is served).
struct Clock;

impl ServeClock for Clock {
    fn serve_range(&self) -> Option<(u64, u64)> {
        None
    }

    fn fork_digest(&self, slot: u64) -> Option<[u8; 4]> {
        Some(digest_at(slot / 8))
    }
}

/// Serves `routes` on a new socket in `dir`; a channel to it.
async fn serve(
    dir: &Path,
    name: &str,
    routes: tonic::service::Routes,
) -> tonic::transport::Channel {
    let path = dir.join(name);
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        routes,
        std::future::pending(),
    ));
    let uid = rustix::process::geteuid().as_raw();
    ipc::uds::connect_path(&path, uid).await.unwrap()
}

/// Our Status: the fixture digest, blocks from slot 0.
fn status() -> StatusV2 {
    StatusV2 {
        fork_digest: GLOAS_DIGEST,
        finalized_root: [1; 32].into(),
        finalized_epoch: FINALIZED / 8,
        head_root: [2; 32].into(),
        head_slot: HEAD,
        earliest_available_slot: 0,
    }
}

fn swarm(control: Control<E>, listen: bool, registry: &mut Registry) -> Swarm<SpecBehaviour<E>> {
    let transport = TransportMetrics::register(registry);
    let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
    cfg.listen_addrs = if listen {
        vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()]
    } else {
        Vec::new()
    };
    cfg.idle_connection_timeout = WAIT;
    build_swarm(Keypair::generate_secp256k1(), &cfg, control).unwrap()
}

fn control(registry: &mut Registry, status: &Arc<SharedStatus>) -> Control<E> {
    let mut cfg = cl_p2p::testkit::control_config(None);
    cfg.status = Arc::clone(status) as Arc<dyn StatusSource>;
    cfg.contexts = contexts();
    Control::new(cfg, RpcMetrics::register(registry))
}

/// #146: a range-sync from our node alone, through cl-store (the finalized half) and cl-chain
/// (the rest): every canonical block of the fixture, the fork block never, each block's context
/// its epoch's digest and its parent the block before (both checked by the requester), whole
/// and as stored; a range below the store's first block starts at it, one past the head is
/// empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn range_sync_across_finality_and_the_gloas_fork() {
    let env_dir = tempfile::tempdir().unwrap();
    let (env, chain) = seeded(env_dir.path());
    let sockets = tempfile::tempdir().unwrap();
    let store = cl_store::StoreServer::new(link(), Arc::new(cl_store::Reader::over(env.clone())));
    let store = serve(sockets.path(), "cl-store.sock", store.routes()).await;
    let columns_dir = tempfile::tempdir().unwrap();
    let columns = Arc::new(ColumnServer::new(
        Arc::new(ColumnWriter::open_seeded(columns_dir.path()).unwrap()) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Clock),
        ServeBudget::default(),
    ));
    let chain_server = ReqRespServer::new(link(), columns).serving_blocks(Arc::new(env.clone()));
    let chain_routes = tonic::service::Routes::new(chain_server.into_service());
    let chain_channel = serve(sockets.path(), "cl-chain.sock", chain_routes).await;

    let ours = Arc::new(SharedStatus::new(Some(status())));
    let mut registry = Registry::default();
    let source = IpcBlocks::new(store, chain_channel, link());
    let responder = ByRangeResponder::new(
        Arc::new(source),
        Arc::clone(&ours) as Arc<dyn StatusSource>,
        16,
        None,
    );
    let node = control(&mut registry, &ours).with_blocks_responder(Arc::new(responder));
    let mut node = swarm(node, true, &mut registry);
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
            break address;
        }
    };
    let node_id = *node.local_peer_id();
    tokio::spawn(async move {
        loop {
            node.select_next_some().await;
        }
    });

    let theirs = Arc::new(SharedStatus::new(Some(status())));
    let mut requester = swarm(control(&mut registry, &theirs), false, &mut registry);
    requester.dial(addr).unwrap();
    tokio::time::timeout(WAIT, async {
        while requester
            .behaviour()
            .req_resp
            .status_valid_peers()
            .is_empty()
        {
            requester.select_next_some().await;
        }
    })
    .await
    .expect("our node is Status-valid");

    let digests = |epoch: Epoch| Some(digest_at(epoch));
    let mut sync = RangeRequester::new(&mut requester, &digests);
    let canonical = |start: u64, end: u64| -> Vec<Vec<u8>> {
        chain
            .iter()
            .filter(|b| (start..end).contains(&b.slot()))
            .map(Encode::as_ssz_bytes)
            .collect()
    };
    for (start, count) in [(8, 24), (10, 30), (0, 128), (FINALIZED, 2), (HEAD + 1, 8)] {
        let blocks = tokio::time::timeout(WAIT, sync.blocks_by_range(node_id, start, count))
            .await
            .expect("answered")
            .unwrap_or_else(|e| panic!("[{start}, +{count}): {e}"));
        let got: Vec<Vec<u8>> = blocks.iter().map(Encode::as_ssz_bytes).collect();
        assert_eq!(got, canonical(start, start + count), "[{start}, +{count})");
        assert!(blocks.iter().all(|b| b.slot() != 36), "the fork block");
    }
}

/// Cole B1, Vera N1: cl-p2p refuses a range that starts deeper below the store's finalized slot
/// than it lets cl-store walk before it asks cl-store, and cl-store refuses the same depth
/// itself: one value on both sides.
#[test]
fn finalized_depth_matches_the_store() {
    assert_eq!(
        cl_p2p::rpc::blocks::MAX_FINALIZED_DEPTH,
        cl_store::MAX_FINALIZED_DEPTH
    );
}
