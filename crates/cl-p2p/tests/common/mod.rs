//! The env fixture of the block-serving stand-ins for the Kurtosis acceptance criteria
//! (`tests/byrange_serve.rs`, #146; `tests/byhead_serve.rs`, #230): one cl-chain env holding a
//! linked Fulu→Gloas chain on the minimal preset, served by the real cl-store `StoreServer` and
//! the real cl-chain `ReqRespServer` over Unix sockets, and our swarm's pieces.
//!
//! Each test binary uses part of it.
#![allow(dead_code)]

use cl_chain::reqresp::{
    BlockStore, ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock,
};
use cl_chain_columns::ColumnWriter;
use cl_p2p::behaviour::SpecBehaviour;
use cl_p2p::rpc::inbound::{Control, SharedStatus, StatusSource};
use cl_p2p::rpc::metrics::RpcMetrics;
use cl_p2p::transport::{build_swarm, MuxerBudget, SwarmConfig, TransportMetrics};
use consensus_types::caps::NetworkCaps;
use consensus_types::primitives::U256;
use consensus_types::{forked, Minimal};
use ethswarm_proto::common::Hello;
use ipc::envelope::DigestTable;
use ipc::Link;
use libp2p::identity::Keypair;
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

pub type E = Minimal;

pub const WAIT: Duration = Duration::from_secs(20);
/// The fixture: slots 1 to 40 but these, each block on the one before; a fork block at 36.
pub const SKIPPED: [u64; 4] = [5, 17, 33, 36];
pub const HEAD: u64 = 40;
pub const FINALIZED: u64 = 20;

/// Fulu from epoch 0, Gloas from epoch 4 (8 slots an epoch).
pub fn schedule() -> ForkSchedule {
    let at = |version, epoch| ScheduledFork { version, epoch };
    ForkSchedule::new(at([6, 0, 0, 1], 0), at([7, 0, 0, 1], 4)).unwrap()
}

/// Fulu's digest from epoch 0, its BPO digest from 2, Gloas's from 4.
pub fn digest_at(epoch: Epoch) -> ForkDigest {
    match epoch {
        0..=1 => FULU_DIGEST,
        2..=3 => FULU_BPO_DIGEST,
        _ => GLOAS_DIGEST,
    }
}

/// The link every side holds: the fixture schedule and digests.
pub fn link() -> Link {
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
pub fn contexts() -> Arc<ContextTable> {
    let mut table = ContextTable::new().with_network_caps(NetworkCaps::PRESET_BOUND);
    table.insert_from(0, FULU_DIGEST, ForkName::Fulu);
    table.insert_from(2, FULU_BPO_DIGEST, ForkName::Fulu);
    table.insert_from(4, GLOAS_DIGEST, ForkName::Gloas);
    Arc::new(table)
}

/// A block at `slot` on `parent`, Fulu before epoch 4 and Gloas from it.
pub fn block(slot: u64, parent: [u8; 32], salt: u64) -> forked::SignedBeaconBlock<E> {
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
pub fn fixture() -> (
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
pub struct Shared(Arc<WriterEnv>);

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

/// The env holding the fixture, stamped head [`HEAD`], finalized [`FINALIZED`]: the env, the
/// canonical chain and the fork block.
pub fn seeded(
    dir: &Path,
) -> (
    Shared,
    Vec<forked::SignedBeaconBlock<E>>,
    forked::SignedBeaconBlock<E>,
) {
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
    (Shared(Arc::new(writer)), chain, fork)
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
pub async fn serve(
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

/// The real cl-store `StoreServer` and cl-chain `ReqRespServer` over `env`, each on its own
/// socket in `sockets`, its column store in `columns`: channels to cl-store and cl-chain.
pub async fn servers(
    env: &Shared,
    sockets: &Path,
    columns: &Path,
) -> (tonic::transport::Channel, tonic::transport::Channel) {
    let store = cl_store::StoreServer::new(link(), Arc::new(cl_store::Reader::over(env.clone())));
    let store = serve(sockets, "cl-store.sock", store.routes()).await;
    let columns = Arc::new(ColumnServer::new(
        Arc::new(ColumnWriter::open_seeded(columns).unwrap()) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Clock),
        ServeBudget::default(),
    ));
    let chain_server = ReqRespServer::new(link(), columns).serving_blocks(Arc::new(env.clone()));
    let chain_routes = tonic::service::Routes::new(chain_server.into_service());
    let chain = serve(sockets, "cl-chain.sock", chain_routes).await;
    (store, chain)
}

/// Our Status: the fixture digest, blocks from slot 0.
pub fn status() -> StatusV2 {
    StatusV2 {
        fork_digest: GLOAS_DIGEST,
        finalized_root: [1; 32].into(),
        finalized_epoch: FINALIZED / 8,
        head_root: [2; 32].into(),
        head_slot: HEAD,
        earliest_available_slot: 0,
    }
}

pub fn swarm(
    control: Control<E>,
    listen: bool,
    registry: &mut Registry,
) -> Swarm<SpecBehaviour<E>> {
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

pub fn control(registry: &mut Registry, status: &Arc<SharedStatus>) -> Control<E> {
    let mut cfg = cl_p2p::testkit::control_config(None);
    cfg.status = Arc::clone(status) as Arc<dyn StatusSource>;
    cfg.contexts = contexts();
    Control::new(cfg, RpcMetrics::register(registry))
}
