//! BeaconBlocksByRoot v2 through the whole stack: the real cl-store `StoreServer` and the real
//! cl-chain `ReqRespServer` serve one env over Unix sockets; our swarm answers with the
//! production ByRoot responder over the production IPC client; the requester is a swarm of its
//! own (TCP, noise, yamux) that writes the request's bytes and reads the answer's.
//!
//! The env holds a Fulu→Gloas chain finalized at slot 20, its head at 40, a fork block at 36 (off
//! the head's chain, above finality) and an orphan at 12 (below finality, off the finalized
//! chain). Finalized roots come from cl-store, unfinalized ones from cl-chain, on any branch;
//! the orphan below finality and unknown roots get no chunk, a duplicate is served once, the
//! blocks follow the request's order, each chunk carries the digest of its block's epoch, and
//! 129 roots are `1: InvalidRequest`.

use cl_chain::reqresp::{
    BlockStore, ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock,
};
use cl_chain_columns::ColumnWriter;
use cl_p2p::rpc::blocks::ByRangeResponder;
use cl_p2p::rpc::blocks_ipc::IpcBlocks;
use cl_p2p::rpc::codec::{read_response_chunks, Deadlines, ReceivedChunk, RpcCodec, RpcRequest};
use cl_p2p::rpc::inbound::{Control, SharedStatus, StatusSource};
use cl_p2p::rpc::metrics::RpcMetrics;
use cl_p2p::transport::{build_swarm, MuxerBudget, SwarmConfig, TransportMetrics};
use consensus_types::caps::NetworkCaps;
use consensus_types::primitives::U256;
use consensus_types::{forked, Minimal};
use ethswarm_proto::common::Hello;
use futures::{AsyncRead, AsyncWrite, StreamExt as _};
use ipc::envelope::DigestTable;
use ipc::Link;
use libp2p::identity::Keypair;
use libp2p::request_response::{self, Codec as _, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use network_config::{Epoch, ForkName, ForkSchedule, ScheduledFork};
use p2p_wire::rpc::codec::{encode_chunk, encode_request, ContextTable};
use p2p_wire::rpc::messages::{BlocksByRootV2Request, ForkDigest, StatusV2};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
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
const ROOT: Protocol = Protocol::BlocksByRootV2;
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

/// The env's blocks: the canonical chain, the fork block at 36 and the orphan at 12.
struct Fixture {
    chain: Vec<forked::SignedBeaconBlock<E>>,
    fork: forked::SignedBeaconBlock<E>,
    orphan: forked::SignedBeaconBlock<E>,
}

impl Fixture {
    fn new() -> Self {
        let mut chain: Vec<forked::SignedBeaconBlock<E>> = Vec::new();
        for slot in (1..=HEAD).filter(|s| !SKIPPED.contains(s)) {
            let parent = chain.last().map_or([0; 32], |b| b.message_root().0);
            chain.push(block(slot, parent, 0));
        }
        let mut fixture = Self {
            fork: block(1, [0; 32], 0),
            orphan: block(1, [0; 32], 0),
            chain,
        };
        fixture.fork = block(36, fixture.root(35), 9);
        fixture.orphan = block(12, fixture.root(11), 7);
        fixture
    }

    fn at(&self, slot: u64) -> &forked::SignedBeaconBlock<E> {
        self.chain.iter().find(|b| b.slot() == slot).unwrap()
    }

    fn root(&self, slot: u64) -> [u8; 32] {
        self.at(slot).message_root().0
    }
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

/// The env holding `fixture`, stamped head [`HEAD`], finalized [`FINALIZED`].
fn seeded(dir: &Path, fixture: &Fixture) -> Shared {
    let writer = test_writer(dir).unwrap();
    let txn = txn::begin(&writer).unwrap();
    for b in fixture.chain.iter().chain([&fixture.fork, &fixture.orphan]) {
        store_schema::blocks::put::<E>(&txn, &schedule(), &b.as_ssz_bytes()).unwrap();
    }
    let stamp = Stamp {
        head_seq: 5,
        head_root: fixture.root(HEAD),
        head_slot: HEAD,
        finalized_root: fixture.root(FINALIZED),
        finalized_slot: FINALIZED,
    };
    txn::commit(txn, Update::New(stamp)).unwrap();
    Shared(Arc::new(writer))
}

struct Clock;

impl ServeClock for Clock {
    fn serve_range(&self) -> Option<(u64, u64)> {
        None
    }

    fn fork_digest(&self, slot: u64) -> Option<[u8; 4]> {
        Some(digest_at(slot / 8))
    }
}

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

/// Writes raw request bytes and reads the raw answer to its end.
#[derive(Clone, Default)]
struct Raw;

impl request_response::Codec for Raw {
    type Protocol = Protocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Protocol, _: &mut T) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    async fn read_response<T>(&mut self, _: &Protocol, io: &mut T) -> std::io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt as _;
        let mut buf = Vec::new();
        io.take(16 << 20).read_to_end(&mut buf).await?;
        Ok(buf)
    }

    async fn write_request<T>(
        &mut self,
        _: &Protocol,
        io: &mut T,
        bytes: Vec<u8>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt as _;
        io.write_all(&bytes).await?;
        io.flush().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Protocol,
        _: &mut T,
        _: Vec<u8>,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

type Requester = Swarm<request_response::Behaviour<Raw>>;

/// A BlocksByRoot requester connected to `addr`.
async fn requester(addr: &Multiaddr) -> Requester {
    let behaviour = request_response::Behaviour::with_codec(
        Raw,
        [(ROOT, ProtocolSupport::Outbound)],
        request_response::Config::default().with_request_timeout(WAIT),
    );
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
        .build();
    swarm.dial(addr.clone()).unwrap();
    tokio::time::timeout(WAIT, async {
        while !matches!(
            swarm.select_next_some().await,
            SwarmEvent::ConnectionEstablished { .. }
        ) {}
    })
    .await
    .expect("connected");
    swarm
}

/// Sends `bytes` to `node`: the answer's bytes.
async fn exchange(swarm: &mut Requester, node: PeerId, bytes: Vec<u8>) -> Vec<u8> {
    use request_response::{Event, Message};
    let id = swarm.behaviour_mut().send_request(&node, bytes);
    tokio::time::timeout(WAIT, async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(Event::Message {
                    message:
                        Message::Response {
                            request_id,
                            response,
                        },
                    ..
                }) if request_id == id => return response,
                SwarmEvent::Behaviour(Event::OutboundFailure { error, .. }) => {
                    panic!("the request failed: {error}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("answered")
}

/// What a requester of `request` reads from `wire`, context bytes included.
async fn received(wire: &[u8], request: &Request) -> Vec<ReceivedChunk<E>> {
    let mut codec = RpcCodec::<E>::new(contexts(), Deadlines::default());
    let mut sent = futures::io::sink();
    let valid = RpcRequest::Valid(request.clone());
    codec.write_request(&ROOT, &mut sent, valid).await.unwrap();
    codec.read_response(&ROOT, &mut &wire[..]).await.unwrap()
}

fn by_root(roots: &[[u8; 32]]) -> Request {
    let roots: Vec<_> = roots.iter().map(|r| (*r).into()).collect();
    Request::BlocksByRoot(BlocksByRootV2Request(roots.try_into().unwrap()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byroot_served_across_finality_and_branches() {
    let fixture = Fixture::new();
    let env_dir = tempfile::tempdir().unwrap();
    let env = seeded(env_dir.path(), &fixture);
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
    let chain = serve(sockets.path(), "cl-chain.sock", chain_routes).await;

    let mut registry = Registry::default();
    let metrics = RpcMetrics::register(&mut registry);
    let ours = Arc::new(SharedStatus::new(Some(status())));
    let range = ByRangeResponder::new(
        Arc::new(IpcBlocks::new(store, chain, link())),
        Arc::clone(&ours) as Arc<dyn StatusSource>,
        16,
        Some(metrics.clone()),
    );
    let mut cfg = cl_p2p::testkit::control_config(None);
    cfg.status = ours as Arc<dyn StatusSource>;
    cfg.contexts = contexts();
    let control = Control::<E>::new(cfg, metrics.clone())
        .with_root_responder(Arc::new(range.root_responder()));
    let transport = TransportMetrics::register(&mut registry);
    let mut swarm_cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
    swarm_cfg.listen_addrs = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    swarm_cfg.idle_connection_timeout = WAIT;
    let mut node = build_swarm(Keypair::generate_secp256k1(), &swarm_cfg, control).unwrap();
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
    let mut peer = requester(&addr).await;

    let fork = fixture.fork.message_root().0;
    let orphan = fixture.orphan.message_root().0;
    let asked = [
        fixture.root(30),
        fixture.root(10),
        fork,
        [0xee; 32],
        fixture.root(30),
        orphan,
        fixture.root(FINALIZED),
        fixture.root(HEAD),
    ];
    let request = by_root(&asked);
    let wire = exchange(&mut peer, node_id, encode_request(&request).unwrap()).await;
    let chunks = received(&wire, &request).await;
    let want = [
        fixture.at(30),
        fixture.at(10),
        &fixture.fork,
        fixture.at(FINALIZED),
        fixture.at(HEAD),
    ];
    assert_eq!(chunks.len(), want.len(), "{chunks:?}");
    for (chunk, b) in chunks.iter().zip(want) {
        let ResponseChunk::Success(Response::Block(got)) = &chunk.chunk else {
            panic!("not a block: {chunk:?}");
        };
        assert_eq!(got.as_ssz_bytes(), b.as_ssz_bytes(), "slot {}", b.slot());
        assert_eq!(got.fork_name(), b.fork_name(), "slot {}", b.slot());
        assert_eq!(
            chunk.context,
            Some(digest_at(b.slot() / 8)),
            "slot {}",
            b.slot()
        );
    }
    let digests: std::collections::HashSet<_> = chunks.iter().map(|c| c.context).collect();
    assert_eq!(digests.len(), 3, "Fulu, its BPO digest and Gloas");

    let unknown = by_root(&[[0xee; 32]; 128]);
    let wire = exchange(&mut peer, node_id, encode_request(&unknown).unwrap()).await;
    assert!(
        received(&wire, &unknown).await.is_empty(),
        "no chunk at all"
    );

    let over: Vec<u8> = (0..129u8).flat_map(|i| [i; 32]).collect();
    let wire = exchange(&mut peer, node_id, encode_chunk(&over).unwrap()).await;
    let read = read_response_chunks::<E, _>(&mut &wire[..], ROOT, 128, &contexts())
        .await
        .unwrap();
    assert!(
        matches!(
            read.as_slice(),
            [ResponseChunk::Error {
                code: ResultCode::InvalidRequest,
                ..
            }]
        ),
        "{read:?}"
    );
    assert_eq!(metrics.block_lookup_failures("chain", "status"), 0);
    assert_eq!(metrics.block_lookup_failures("store", "status"), 0);
}
