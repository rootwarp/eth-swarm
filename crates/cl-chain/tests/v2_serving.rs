//! Bad column sidecars that arrive on gossip are never stored, and so never served by
//! `DataColumnSidecarsByRange` or `DataColumnSidecarsByRoot` (`gloas/p2p-interface.md`
//! L1286–1289; `fulu/p2p-interface.md` L605–790): only a sidecar that passed the storage
//! contract is in the column store, and the column servers read nothing else.
//!
//! The services run in process:
//!
//! - **cl-verify** is the real one (`VerifyServer::new`, the pinned trusted setup) on a Unix
//!   socket in a temp dir, so every KZG check below really runs. cl-chain talks to it through
//!   its verify.v1 client.
//! - **The reference node** is an HTTP fixture of the Beacon API (`testkit`'s `FixtureServer`)
//!   that serves the headers and blocks of the test's blocks, and 404 for any other root. A test
//!   adds a block to it when the reference should learn it.
//! - **cl-chain** is the probe's column store (`ColumnIngest`: pending queue, root wait,
//!   storage contract, writer thread) on a temp column env, custody of node `U256::MAX`
//!   (columns 1, 47, 87 and 102) from [`CGC_SET_SLOT`], and its `ReqRespService` column RPCs
//!   (`ReqRespServer` over `ColumnServer`) on a second Unix socket.
//!
//! **Where the sidecars come in.** cl-p2p hands each gossip column sidecar to cl-chain at
//! `ColumnIngest::on_column`, and that is where they are injected here: the bytes a publishing
//! peer puts on a `data_column_sidecar_{subnet_id}` topic (SSZ, snappy-compressed by the wire
//! transform), decompressed by the same transform, decoded by the fork of the sidecar's slot and
//! tagged with the subnet of its topic, as cl-p2p's gossip path does. A libp2p publish from a
//! local peer is not used: the ignore-all gossipsub and its capture tap live in cl-p2p, which
//! already dev-depends on cl-chain, so this crate cannot depend on it back
//! (`scripts/check-dep-cycles.sh`), and cl-p2p's
//! `gossip::tests::custody_columns::storing_custody_columns_sends_no_data` already runs that
//! path from a libp2p publish to this entry point.
//!
//! **Where the answers are read.** Each query goes to cl-chain's `ReqRespService` over its
//! socket as cl-p2p's chain.v1 client sends it (our hello in line), and the response is read
//! through the `ipc` contract layer: the server's hello, then each chunk, every envelope's `seq`
//! and fork digest checked. An error chunk is the code cl-p2p puts on the wire:
//! `ERROR_CODE_RESOURCE_UNAVAILABLE` is `3: ResourceUnavailable`.
//!
//! **What the answers must be.** After each injection the store has settled (the pending queue
//! empty, the drop counted under its reason) before the queries go out, except where a test
//! queries on purpose while columns are on their way in (waiting for a root, or a write held
//! before its commit). The answers follow the serving rules (`cl_chain::reqresp`): a range is
//! answered with the longest prefix of whole blocks of its one chain, an empty success for a
//! range where the store knows of no block, and `3` for a range below `earliest_available_slot`,
//! one that names a column we do not custody, one whose first block lacks a requested column, or
//! one that covers the slot of a blob-carrying block a stored block waits for; a by-root request
//! leaves out what is not stored.
//!
//! Every block is a Gloas block (the preset is minimal, Gloas from slot 8) whose bid commits to
//! the fixture blobs `e_0` and `e_1` (`tests/kzg_fixture.rs`), in the order it names. A valid
//! anchor block at [`CGC_SET_SLOT`] is stored first in every test, so the store serves from
//! there and an empty answer is never just an empty store.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "../src/testing.rs"]
mod testing;

/// [`testing`] names cl-chain's verify.v1 client by its path inside the library.
mod verify {
    pub use cl_chain::verify::client;
}

use cl_chain::da::custody::{Advertise, Custody, EnrCgc, EnrError};
use cl_chain::probe::{
    BeaconApi, ColumnContract, ColumnIngest, ColumnMetrics, Drop, GossipColumn, IngestLimits,
    QueueMetrics, RefLimits, RefView, Root, DEFAULT_API_TIMEOUT,
};
use cl_chain::reqresp::{ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock};
use cl_chain::verify::client::KzgClient;
use cl_chain_columns::{BlockLink, ColumnWriter};
use consensus_types::caps::NetworkCaps;
use consensus_types::forked;
use consensus_types::gloas::DataColumnSidecar;
use consensus_types::primitives::U256;
use ethswarm_proto::chain as pb;
use ethswarm_proto::common::{ErrorCode, PayloadType, Verdict};
use ipc::envelope::{DigestTable, Envelopes};
use ipc::frame::{InFrame, Inbound};
use ipc::Link;
use network_config::ForkName;
use p2p_wire::gossip::{GossipKind, GossipTopic, SnappyTransform, TopicCaps};
use pb::req_resp_service_client::ReqRespServiceClient;
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;
use testing::{blobs, gloas_block, gloas_block_on, hello, my_uid, schedule, ClVerify, Spec};
use testkit::collector::testing::{FixtureServer, Reply};
use tokio::sync::oneshot;
use tokio::time::Instant;
use tonic::transport::Channel;

/// The custody columns of node `U256::MAX` (`get_custody_groups(U256::MAX, 4)`).
const CUSTODY: [u64; 4] = [1, 47, 87, 102];
/// Columns in the KZG fixture that node `U256::MAX` does not custody.
const NOT_CUSTODY: [u64; 3] = [0, 5, 127];
/// The slot custody is set at, the first Gloas slot: the anchor block's slot.
const CGC_SET_SLOT: u64 = 8;
/// The fork digests of the test link: Fulu in epoch 0, Gloas from epoch 1 (slot 8).
const FULU_DIGEST: [u8; 4] = [0x99, 0x88, 0x77, 0x66];
const GLOAS_DIGEST: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
/// How long the store may take to settle.
const SETTLE: Duration = Duration::from_secs(20);
/// How long a column waits for its root in every test but one: far past what a test does while
/// columns wait (a few queries, or seeing the root missed and retried), so a stalled runner
/// cannot time out a column whose root the test is about to let the reference learn. No test
/// waits for it to run out: each lets the reference learn the root as soon as it has seen what
/// it waits for.
const ROOT_WAIT: Duration = Duration::from_secs(20);
/// The root wait of [`wrong_root_never_served`], which waits for a made-up root to time out.
const SHORT_ROOT_WAIT: Duration = Duration::from_secs(3);
/// How often a waiting root is asked again.
const ROOT_RETRY: Duration = Duration::from_millis(100);

/// The store's bounds: the defaults, with the root wait `root_wait`, retried more often.
fn limits(root_wait: Duration) -> IngestLimits {
    IngestLimits {
        root_wait,
        root_retry: ROOT_RETRY,
        // One retry of each of the 16 seats every 100 ms.
        retries_per_sec: 160,
        unknown_root_ttl: root_wait,
        ..IngestLimits::default()
    }
}

/// The ENR is not under test here.
struct NoEnr;

impl EnrCgc for NoEnr {
    fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
        Ok(())
    }
}

/// Every slot within `data_column_serve_range`; the digest of each slot's fork.
struct TestClock;

impl ServeClock for TestClock {
    fn serve_range(&self) -> Option<(u64, u64)> {
        Some((0, 10_000))
    }

    fn fork_digest(&self, slot: u64) -> Option<[u8; 4]> {
        Some(if slot < CGC_SET_SLOT {
            FULU_DIGEST
        } else {
            GLOAS_DIGEST
        })
    }
}

/// The link both ends of the chain.v1 socket hold.
fn link() -> Link {
    let digests = DigestTable::new(vec![
        (0, ForkName::Fulu, FULU_DIGEST),
        (1, ForkName::Gloas, GLOAS_DIGEST),
    ])
    .unwrap();
    Link::new::<Spec>(hello(), 1, schedule(), digests)
}

/// A Gloas block of the test chain.
#[derive(Clone)]
struct Block {
    slot: u64,
    root: Root,
    ssz: Vec<u8>,
    /// The fixture blobs its bid commits to, in order.
    rows: Vec<usize>,
}

impl Block {
    /// The block at `slot` whose parent is `parent` and whose bid commits to the fixture blobs
    /// `rows`, in that order.
    fn on(slot: u64, parent: &Block, rows: &[usize]) -> Self {
        let (_, ssz, root) = gloas_block_on(slot, &commitments(rows), parent.root);
        Self {
            slot,
            root,
            ssz,
            rows: rows.to_vec(),
        }
    }

    /// The anchor: at [`CGC_SET_SLOT`], both blobs, a parent the reference does not know.
    fn anchor() -> Self {
        let rows = [0, 1];
        let (_, ssz, root) = gloas_block(CGC_SET_SLOT, &commitments(&rows));
        Self {
            slot: CGC_SET_SLOT,
            root,
            ssz,
            rows: rows.to_vec(),
        }
    }

    /// Column `index` of this block: the cell and proof of each of its blobs, valid against
    /// its bid's commitments.
    fn sidecar(&self, index: u64) -> DataColumnSidecar<Spec> {
        let b = blobs();
        let cells: Vec<_> = self
            .rows
            .iter()
            .map(|&blob| b.cell(blob, index).to_vec().try_into().unwrap())
            .collect();
        let proofs: Vec<_> = self.rows.iter().map(|&blob| b.proof(blob, index)).collect();
        DataColumnSidecar {
            index,
            column: cells.try_into().unwrap(),
            kzg_proofs: proofs.try_into().unwrap(),
            slot: self.slot,
            beacon_block_root: self.root.into(),
        }
    }

    fn sidecars(&self, indices: &[u64]) -> Vec<DataColumnSidecar<Spec>> {
        indices.iter().map(|&i| self.sidecar(i)).collect()
    }
}

fn commitments(rows: &[usize]) -> Vec<[u8; 48]> {
    rows.iter().map(|&blob| blobs().commitments[blob]).collect()
}

/// `sidecar` with one cell byte flipped: the low byte of a field element, so the cell is still
/// canonical and only the KZG check can tell.
fn flipped(mut sidecar: DataColumnSidecar<Spec>) -> DataColumnSidecar<Spec> {
    let last = sidecar.column.len() - 1;
    sidecar.column[last][31] ^= 1;
    sidecar
}

/// `sidecar` claiming the block `root` at `slot`, its cells and proofs unchanged.
fn claiming(
    mut sidecar: DataColumnSidecar<Spec>,
    root: Root,
    slot: u64,
) -> DataColumnSidecar<Spec> {
    sidecar.beacon_block_root = root.into();
    sidecar.slot = slot;
    sidecar
}

/// A reference node over HTTP: the headers and blocks it serves, 404 for any other, counted by
/// path.
struct Reference {
    server: FixtureServer,
    replies: Arc<Mutex<HashMap<String, Reply>>>,
    misses: Arc<Mutex<HashMap<String, usize>>>,
}

impl Reference {
    async fn start() -> Self {
        let replies = Arc::<Mutex<HashMap<String, Reply>>>::default();
        let misses = Arc::<Mutex<HashMap<String, usize>>>::default();
        let (served, missed) = (Arc::clone(&replies), Arc::clone(&misses));
        let server = FixtureServer::start(move |_, path| {
            let reply = served.lock().unwrap().get(path).cloned();
            reply.unwrap_or_else(|| {
                *missed.lock().unwrap().entry(path.to_owned()).or_default() += 1;
                Reply::status(404)
            })
        })
        .await;
        Self {
            server,
            replies,
            misses,
        }
    }

    fn header_path(root: &Root) -> String {
        format!("/eth/v1/beacon/headers/0x{}", hex::encode(root))
    }

    /// From now on, vouches for `block`: its header and its SSZ.
    fn serve(&self, block: &Block) {
        let id = format!("0x{}", hex::encode(block.root));
        let slot = block.slot;
        let header = format!(
            r#"{{"data":{{"root":"{id}","canonical":true,"header":{{"message":{{"slot":"{slot}"}}}}}}}}"#
        );
        let mut replies = self.replies.lock().unwrap();
        replies.insert(Self::header_path(&block.root), Reply::json(&header));
        replies.insert(
            format!("/eth/v2/beacon/blocks/{id}"),
            Reply::ssz(block.ssz.clone()),
        );
    }

    /// How many times the header of `block` was asked for and answered 404.
    fn header_misses(&self, block: &Block) -> usize {
        let misses = self.misses.lock().unwrap();
        misses
            .get(&Self::header_path(&block.root))
            .copied()
            .unwrap_or(0)
    }

    fn api(&self) -> BeaconApi {
        BeaconApi::new(&format!("http://{}", self.server.addr), DEFAULT_API_TIMEOUT).unwrap()
    }
}

/// Waits until `done` holds; fails after [`SETTLE`].
async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + SETTLE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The column env's writes of one slot, held open after their puts and before their commit
/// (`ColumnWriter::set_before_commit`) until [`Self::release`]d or dropped. A held column has
/// passed the contract and still holds its place in the pending queue.
struct HeldWrites {
    gate: Arc<(Mutex<Hold>, Condvar)>,
}

#[derive(Default)]
struct Hold {
    released: bool,
    /// The held writes that reached the hook.
    entered: usize,
}

impl HeldWrites {
    /// Holds every write of `slot` through `writer`, which no hook was set on before.
    fn new(writer: &ColumnWriter, slot: u64) -> Self {
        let gate = Arc::new((Mutex::new(Hold::default()), Condvar::new()));
        let hook = Arc::clone(&gate);
        writer.set_before_commit(Box::new(move |written| {
            if written != slot {
                return;
            }
            let (hold, changed) = &*hook;
            let mut hold = hold.lock().unwrap_or_else(PoisonError::into_inner);
            hold.entered += 1;
            while !hold.released {
                hold = changed.wait(hold).unwrap_or_else(PoisonError::into_inner);
            }
        }));
        Self { gate }
    }

    /// Waits until a held write reached the hook: its puts are made and not committed.
    async fn entered(&self) {
        wait_for("a held write", || self.lock().entered > 0).await;
    }

    /// Lets every held write, and every later one, commit.
    fn release(&self) {
        self.lock().released = true;
        self.gate.1.notify_all();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Hold> {
        self.gate.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::ops::Drop for HeldWrites {
    /// Released, so the store's writer thread can finish and be joined.
    fn drop(&mut self) {
        self.release();
    }
}

/// One sidecar of an answer: its envelope's slot and root, and its SSZ.
#[derive(Clone, PartialEq, Eq)]
struct Chunk {
    slot: u64,
    root: Root,
    ssz: Vec<u8>,
}

impl std::fmt::Debug for Chunk {
    /// The slot, the root's first bytes and the column index (the SSZ's first field).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let index = self
            .ssz
            .get(..8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
        write!(
            f,
            "slot {} root {} column {index:?} ({} B)",
            self.slot,
            hex::encode(&self.root[..4]),
            self.ssz.len()
        )
    }
}

/// What a column request got from cl-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// A success: these sidecars, in order (none is an empty success).
    Sidecars(Vec<Chunk>),
    /// One error chunk with this code.
    Refused(ErrorCode),
}

/// `3: ResourceUnavailable` on the wire.
const UNAVAILABLE: Answer = Answer::Refused(ErrorCode::ResourceUnavailable);

/// The empty success.
fn none() -> Answer {
    Answer::Sidecars(Vec::new())
}

/// A success carrying exactly `sidecars`, in order, as they were gossiped.
fn served(sidecars: &[DataColumnSidecar<Spec>]) -> Answer {
    Answer::Sidecars(
        sidecars
            .iter()
            .map(|s| Chunk {
                slot: s.slot,
                root: s.beacon_block_root.0,
                ssz: s.as_ssz_bytes(),
            })
            .collect(),
    )
}

/// Reads one column response through the contract layer: the server's hello, then each chunk;
/// an envelope the link drops, or a contract error, fails the test.
async fn read<T>(
    link: &Link,
    stream: tonic::Streaming<T>,
    item: fn(T::Body) -> Option<pb::ResponseChunk>,
) -> Answer
where
    T: InFrame,
    T::Body: Envelopes,
{
    let mut guarded = link.open(Inbound::from_server(stream)).await.unwrap();
    let mut chunks = Vec::new();
    while let Some(accepted) = guarded.body().await.unwrap() {
        assert!(accepted.dropped.is_empty(), "{:?}", accepted.dropped);
        match item(accepted.body).and_then(|chunk| chunk.result) {
            Some(pb::response_chunk::Result::Chunk(envelope)) => {
                assert_eq!(envelope.payload_type, PayloadType::DataColumnSidecar as i32);
                chunks.push(Chunk {
                    slot: envelope.slot,
                    root: envelope.root.as_slice().try_into().unwrap(),
                    ssz: envelope.ssz,
                });
            }
            Some(pb::response_chunk::Result::Error(error)) => {
                assert!(chunks.is_empty(), "an error chunk after {chunks:?}");
                assert!(
                    guarded.body().await.unwrap().is_none(),
                    "a chunk past the error"
                );
                return Answer::Refused(ErrorCode::try_from(error.code).unwrap());
            }
            None => panic!("an empty column chunk"),
        }
    }
    Answer::Sidecars(chunks)
}

type Ingest = ColumnIngest<BeaconApi, Spec, KzgClient, Arc<ColumnWriter>, NoEnr>;

/// The probe: the reference, cl-verify, cl-chain's column store and its column RPCs, with the
/// anchor block stored.
struct Node {
    ingest: Ingest,
    writer: Arc<ColumnWriter>,
    reference: Reference,
    client: ReqRespServiceClient<Channel>,
    link: Link,
    transform: SnappyTransform,
    caps: NetworkCaps,
    anchor: Block,
    _verify: testing::Served,
    _stop: oneshot::Sender<()>,
    _dir: tempfile::TempDir,
}

impl Node {
    /// The probe with the root wait [`ROOT_WAIT`].
    async fn start() -> Self {
        Self::start_with(ROOT_WAIT).await
    }

    /// The probe with the root wait `root_wait`.
    async fn start_with(root_wait: Duration) -> Self {
        let reference = Reference::start().await;
        let anchor = Block::anchor();
        reference.serve(&anchor);
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path().join("columns")).unwrap());
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            U256::MAX,
            Advertise::Withheld,
            CGC_SET_SLOT,
        )
        .unwrap();
        assert_eq!(custody.custody_columns(), CUSTODY);
        let verify = ClVerify::start();
        let mut registry = Registry::default();
        let contract = ColumnContract {
            kzg: verify.kzg_client().await,
            verify_timeout: Duration::from_secs(10),
            metrics: ColumnMetrics::register(&mut registry),
        };
        let ingest = ColumnIngest::start(
            RefView::new(reference.api(), schedule(), RefLimits::default()),
            custody,
            contract,
            Arc::clone(&writer),
            limits(root_wait),
            QueueMetrics::register(&mut registry),
        )
        .unwrap();

        // The column RPCs read the column env through `ColumnStore` alone.
        let server = ColumnServer::new(
            Arc::clone(&writer) as Arc<dyn ColumnStore>,
            U256::MAX,
            Arc::new(TestClock),
            ServeBudget::default(),
        );
        let socket = dir.path().join("chain.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let routes = tonic::service::Routes::new(
            ReqRespServer::new(link(), Arc::new(server)).into_service(),
        );
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(ipc::stub::serve_uds(listener, routes, async {
            let _ = stopped.await;
        }));
        let channel = ipc::uds::connect_path(&socket, my_uid()).await.unwrap();
        let caps = NetworkCaps::from_blob_schedule(21, &[]);
        let node = Self {
            ingest,
            writer,
            reference,
            client: ReqRespServiceClient::new(channel),
            link: link(),
            transform: SnappyTransform::new(TopicCaps::gloas::<Spec>(&caps)),
            caps,
            anchor,
            _verify: verify,
            _stop: stop,
            _dir: dir,
        };

        // The anchor: stored, and served from its slot; before it, unavailable.
        let columns = node.anchor.sidecars(&CUSTODY);
        node.gossip_all(&columns).await;
        node.settle("the anchor to be stored", || {
            node.stored(&node.anchor) == CUSTODY
        })
        .await;
        assert_eq!(
            node.by_range(CGC_SET_SLOT, 1, &CUSTODY).await,
            served(&columns)
        );
        assert_eq!(node.by_range(0, CGC_SET_SLOT, &CUSTODY).await, UNAVAILABLE);
        node
    }

    /// Publishes `sidecar` on `data_column_sidecar_{subnet_id}` and hands it to cl-chain as
    /// cl-p2p does (see the module docs). The verdict is IGNORE, stored or not.
    fn publish(&self, sidecar: &DataColumnSidecar<Spec>, subnet_id: u64) {
        let topic =
            GossipTopic::new(GLOAS_DIGEST, GossipKind::DataColumnSidecar { subnet_id }).to_string();
        let wire = self
            .transform
            .outbound(&topic, &sidecar.as_ssz_bytes())
            .unwrap();
        // The probe's side: decompressed, decoded by the fork of the sidecar's slot.
        let data = self.transform.inbound(&topic, &wire).unwrap();
        let decoded = forked::DataColumnSidecar::<Spec>::from_ssz_bytes_by_slot(
            &data,
            &schedule(),
            &self.caps,
        );
        let Ok(forked::DataColumnSidecar::Gloas(sidecar)) = decoded else {
            panic!("not a Gloas sidecar: {decoded:?}");
        };
        let GossipKind::DataColumnSidecar { subnet_id } = GossipTopic::parse(&topic).unwrap().kind
        else {
            panic!("not a column subnet: {topic}");
        };
        let column = GossipColumn { sidecar, subnet_id };
        assert_eq!(self.ingest.on_column(column), Verdict::Ignore);
    }

    /// [`Self::publish`] on the sidecar's own subnet (its index: 128 subnets).
    fn gossip(&self, sidecar: &DataColumnSidecar<Spec>) {
        self.publish(sidecar, sidecar.index);
    }

    /// Gossips every one of `sidecars` and waits until the queue is empty again.
    async fn gossip_all(&self, sidecars: &[DataColumnSidecar<Spec>]) {
        for sidecar in sidecars {
            self.gossip(sidecar);
        }
        self.settle("the queue to drain", || true).await;
    }

    /// Waits until nothing is queued and `done` holds; fails after [`SETTLE`].
    async fn settle(&self, what: &str, mut done: impl FnMut() -> bool) {
        wait_for(what, || self.ingest.pending() == 0 && done()).await;
    }

    /// Waits until `count` columns were dropped as `reason` and nothing is queued.
    async fn dropped(&self, reason: Drop, count: u64) {
        let metrics = &self.ingest.contract().metrics;
        self.settle(&format!("{count} drops as {}", reason.reason()), || {
            metrics.dropped(reason) >= count
        })
        .await;
        assert_eq!(metrics.dropped(reason), count, "{}", reason.reason());
    }

    /// Every drop reason's count so far, those above zero.
    fn drops(&self) -> Vec<(&'static str, u64)> {
        let metrics = &self.ingest.contract().metrics;
        Drop::ALL
            .iter()
            .map(|d| (d.reason(), metrics.dropped(*d)))
            .filter(|(_, n)| *n > 0)
            .collect()
    }

    /// The column indices the store holds for `block`.
    fn stored(&self, block: &Block) -> Vec<u64> {
        self.stored_root(&block.root)
    }

    fn stored_root(&self, root: &Root) -> Vec<u64> {
        let columns = self.writer.reader().columns_for_root(root).unwrap();
        columns.into_iter().map(|(index, _)| index).collect()
    }

    /// `DataColumnsByRange` as cl-p2p asks it.
    async fn by_range(&self, start_slot: u64, count: u64, columns: &[u64]) -> Answer {
        let request = pb::DataColumnsByRangeRequest {
            start_slot,
            count,
            columns: columns.to_vec(),
            hello: Some(self.link.local().clone()),
        };
        let stream = self
            .client
            .clone()
            .data_columns_by_range(request)
            .await
            .unwrap()
            .into_inner();
        read(
            &self.link,
            stream,
            |b: pb::DataColumnsByRangeResponseBody| b.item,
        )
        .await
    }

    /// `DataColumnsByRoot` as cl-p2p asks it.
    async fn by_root(&self, ids: &[(Root, &[u64])]) -> Answer {
        let request = pb::DataColumnsByRootRequest {
            ids: ids
                .iter()
                .map(|(root, columns)| pb::DataColumnsByRootIdentifier {
                    block_root: root.to_vec(),
                    columns: columns.to_vec(),
                })
                .collect(),
            hello: Some(self.link.local().clone()),
        };
        let stream = self
            .client
            .clone()
            .data_columns_by_root(request)
            .await
            .unwrap()
            .into_inner();
        read(
            &self.link,
            stream,
            |b: pb::DataColumnsByRootResponseBody| b.item,
        )
        .await
    }

    /// A block at `slot` on `parent`, committing to both blobs, that the reference vouches for.
    fn block(&self, slot: u64, parent: &Block) -> Block {
        let block = Block::on(slot, parent, &[0, 1]);
        self.reference.serve(&block);
        block
    }
}

/// A KZG-invalid sidecar (one cell byte flipped) is never stored or served: a block all of whose
/// columns are invalid is not held, and a block with one invalid column is held without it.
#[tokio::test]
async fn kzg_invalid_never_served() {
    let node = Node::start().await;
    let anchor = node.anchor.clone();
    // 9: every custody column invalid. 10, its child: valid. 11, the next: column 47 invalid.
    let bad = node.block(9, &anchor);
    let child = node.block(10, &bad);
    let partial = node.block(11, &child);
    let invalid: Vec<_> = bad.sidecars(&CUSTODY).into_iter().map(flipped).collect();
    node.gossip_all(&invalid).await;
    node.dropped(Drop::KzgInvalid, 4).await;
    node.gossip_all(&child.sidecars(&CUSTODY)).await;
    node.gossip_all(&partial.sidecars(&[1, 87, 102])).await;
    node.gossip(&flipped(partial.sidecar(47)));
    node.dropped(Drop::KzgInvalid, 5).await;
    assert_eq!(node.drops(), [("kzg_invalid", 5)]);

    // Never stored: not the bad block, not column 47 of the partial one.
    assert_eq!(node.stored(&bad), Vec::<u64>::new());
    assert_eq!(node.stored(&child), CUSTODY);
    assert_eq!(node.stored(&partial), [1, 87, 102]);
    // The child waits for the bad block, which carries blobs and is not held.
    assert_eq!(
        node.writer.reader().link_of(&child.root).unwrap(),
        Some(BlockLink::Pending(bad.root, bad.slot))
    );

    // By range: the slot of the bad block is not held, and a range over it ends before it.
    assert_eq!(node.by_range(9, 1, &CUSTODY).await, UNAVAILABLE);
    assert_eq!(node.by_range(9, 3, &CUSTODY).await, UNAVAILABLE);
    assert_eq!(node.by_range(9, 1, &[47]).await, UNAVAILABLE);
    assert_eq!(
        node.by_range(8, 4, &CUSTODY).await,
        served(&anchor.sidecars(&CUSTODY))
    );
    // From the child: the child, then the partial block ends the answer, which lacks 47.
    assert_eq!(
        node.by_range(10, 2, &CUSTODY).await,
        served(&child.sidecars(&CUSTODY))
    );
    assert_eq!(node.by_range(11, 1, &[47]).await, UNAVAILABLE);
    assert_eq!(node.by_range(11, 1, &CUSTODY).await, UNAVAILABLE);
    assert_eq!(
        node.by_range(11, 1, &[1, 87, 102]).await,
        served(&partial.sidecars(&[1, 87, 102]))
    );

    // By root: nothing of the bad block, the partial block without 47.
    assert_eq!(node.by_root(&[(bad.root, &CUSTODY)]).await, none());
    assert_eq!(node.by_root(&[(partial.root, &[47])]).await, none());
    assert_eq!(
        node.by_root(&[(bad.root, &CUSTODY), (partial.root, &CUSTODY)])
            .await,
        served(&partial.sidecars(&[1, 87, 102]))
    );
}

/// A sidecar of a root the reference does not know, or of a known root at another slot, is never
/// stored or served, and the block's real sidecars still are.
#[tokio::test]
async fn wrong_root_never_served() {
    let node = Node::start_with(SHORT_ROOT_WAIT).await;
    let block = node.block(9, &node.anchor);
    let unknown = [0x5a; 32];
    let columns = block.sidecars(&CUSTODY);
    // Valid cells and proofs of the block, for a made-up root at its slot.
    let made_up: Vec<_> = columns
        .iter()
        .map(|s| claiming(s.clone(), unknown, block.slot))
        .collect();
    // The block's root, at the next slot.
    let moved: Vec<_> = columns
        .iter()
        .map(|s| claiming(s.clone(), block.root, block.slot + 1))
        .collect();
    node.gossip_all(&moved).await;
    node.dropped(Drop::UnknownRoot, 4).await;
    for sidecar in &made_up {
        node.gossip(sidecar);
    }
    node.dropped(Drop::RootTimeout, 4).await;
    assert_eq!(node.drops(), [("unknown_root", 4), ("root_timeout", 4)]);

    assert_eq!(node.stored_root(&unknown), Vec::<u64>::new());
    assert_eq!(node.stored(&block), Vec::<u64>::new());
    // Nothing at either slot, so both ranges are empty; by root, nothing.
    assert_eq!(node.by_range(9, 1, &CUSTODY).await, none());
    assert_eq!(node.by_range(10, 1, &CUSTODY).await, none());
    assert_eq!(
        node.by_range(8, 3, &CUSTODY).await,
        served(&node.anchor.sidecars(&CUSTODY))
    );
    assert_eq!(node.by_root(&[(unknown, &CUSTODY)]).await, none());
    assert_eq!(node.by_root(&[(block.root, &CUSTODY)]).await, none());

    // The real sidecars: stored and served as they are, at their slot, under their root only.
    node.gossip_all(&columns).await;
    assert_eq!(node.stored(&block), CUSTODY);
    assert_eq!(node.by_range(9, 1, &CUSTODY).await, served(&columns));
    assert_eq!(node.by_range(10, 1, &CUSTODY).await, none());
    assert_eq!(
        node.by_root(&[(unknown, &CUSTODY), (block.root, &CUSTODY)])
            .await,
        served(&columns)
    );
}

/// A sidecar whose cells are another block's, under a root whose bid commits to other blobs, is
/// never stored or served: KZG fails against that bid's commitments (the same blobs in another
/// order), or the bid commits to fewer blobs than the sidecar has cells.
#[tokio::test]
async fn other_block_commitments_never_served() {
    let node = Node::start().await;
    let block = node.block(9, &node.anchor);
    // Two blocks at slot 10: the blobs swapped, and the first blob only.
    let swapped = Block::on(10, &block, &[1, 0]);
    let one_blob = Block::on(10, &block, &[0]);
    node.reference.serve(&swapped);
    node.reference.serve(&one_blob);
    let columns = block.sidecars(&CUSTODY);
    let as_swapped: Vec<_> = columns
        .iter()
        .map(|s| claiming(s.clone(), swapped.root, swapped.slot))
        .collect();
    let as_one_blob: Vec<_> = columns
        .iter()
        .map(|s| claiming(s.clone(), one_blob.root, one_blob.slot))
        .collect();
    node.gossip_all(&as_swapped).await;
    node.dropped(Drop::KzgInvalid, 4).await;
    node.gossip_all(&as_one_blob).await;
    node.dropped(Drop::CommitmentsMismatch, 4).await;
    assert_eq!(
        node.drops(),
        [("kzg_invalid", 4), ("commitments_mismatch", 4)]
    );

    for b in [&block, &swapped, &one_blob] {
        assert_eq!(node.stored(b), Vec::<u64>::new(), "slot {}", b.slot);
    }
    assert_eq!(node.by_range(10, 1, &CUSTODY).await, none());
    assert_eq!(node.by_range(9, 2, &CUSTODY).await, none());
    assert_eq!(
        node.by_root(&[(swapped.root, &CUSTODY), (one_blob.root, &CUSTODY)])
            .await,
        none()
    );

    // The block's own sidecars, then the swapped block's own (its cells in its order): stored
    // and served; the one-blob block still holds nothing.
    node.gossip_all(&columns).await;
    let swapped_columns = swapped.sidecars(&CUSTODY);
    node.gossip_all(&swapped_columns).await;
    assert_eq!(node.stored(&block), CUSTODY);
    assert_eq!(node.stored(&swapped), CUSTODY);
    // No new drop.
    assert_eq!(
        node.drops(),
        [("kzg_invalid", 4), ("commitments_mismatch", 4)]
    );
    let both = [columns.clone(), swapped_columns.clone()].concat();
    assert_eq!(node.by_range(9, 2, &CUSTODY).await, served(&both));
    assert_eq!(
        node.by_root(&[(one_blob.root, &CUSTODY), (swapped.root, &CUSTODY)])
            .await,
        served(&swapped_columns)
    );
}

/// A column this node does not custody, or one on another column's subnet, is never stored or
/// served, beside the block's custody columns that are.
#[tokio::test]
async fn non_custody_never_served() {
    let node = Node::start().await;
    let block = node.block(9, &node.anchor);
    let columns = block.sidecars(&CUSTODY);

    // Custody column 47 on subnet 5, while the block holds every custody column but 47: kept
    // out, so the block still lacks it.
    let others = block.sidecars(&[1, 87, 102]);
    node.gossip_all(&others).await;
    node.publish(&block.sidecar(47), 5);
    node.dropped(Drop::WrongSubnet, 1).await;
    assert_eq!(node.stored(&block), [1, 87, 102]);
    assert_eq!(node.by_root(&[(block.root, &[47])]).await, none());
    assert_eq!(
        node.by_root(&[(block.root, &CUSTODY)]).await,
        served(&others)
    );
    assert_eq!(node.by_range(9, 1, &[47]).await, UNAVAILABLE);
    assert_eq!(node.by_range(9, 1, &CUSTODY).await, UNAVAILABLE);
    // On its own subnet it is stored.
    node.gossip_all(&[block.sidecar(47)]).await;
    assert_eq!(node.stored(&block), CUSTODY);

    // Valid columns we do not custody, on their own subnets, and column 5 on custody subnet 47.
    node.gossip_all(&block.sidecars(&NOT_CUSTODY)).await;
    node.dropped(Drop::NotCustody, 3).await;
    node.publish(&block.sidecar(5), 47);
    node.dropped(Drop::WrongSubnet, 2).await;
    assert_eq!(node.drops(), [("not_custody", 3), ("wrong_subnet", 2)]);
    assert_eq!(node.stored(&block), CUSTODY);

    // By range: a column we do not custody is unavailable, alone or with custody columns.
    assert_eq!(node.by_range(9, 1, &[5]).await, UNAVAILABLE);
    assert_eq!(node.by_range(9, 1, &NOT_CUSTODY).await, UNAVAILABLE);
    assert_eq!(node.by_range(8, 2, &[1, 5]).await, UNAVAILABLE);
    assert_eq!(node.by_range(9, 1, &CUSTODY).await, served(&columns));
    // By root: only the custody column asked for.
    assert_eq!(node.by_root(&[(block.root, &NOT_CUSTODY)]).await, none());
    assert_eq!(
        node.by_root(&[(block.root, &[5, 47])]).await,
        served(&[block.sidecar(47)])
    );
}

/// An invalid copy of an identifier that arrives first does not keep out the valid copy: it is
/// stored and served, whether the invalid one was dropped before it came, is checked beside it,
/// or waited with it for a root the reference did not know yet, through a missed first ask and
/// a missed retry. Nothing ahead of the contract remembers an identifier it has seen.
#[tokio::test]
async fn invalid_then_valid_copy() {
    let node = Node::start().await;
    let block = node.block(9, &node.anchor);

    // Dropped first: column 47.
    node.gossip(&flipped(block.sidecar(47)));
    node.dropped(Drop::KzgInvalid, 1).await;
    assert_eq!(node.by_root(&[(block.root, &[47])]).await, none());
    assert_eq!(node.by_range(9, 1, &[47]).await, none());
    node.gossip_all(&[block.sidecar(47)]).await;
    assert_eq!(node.stored(&block), [47]);
    assert_eq!(
        node.by_root(&[(block.root, &[47])]).await,
        served(&[block.sidecar(47)])
    );
    assert_eq!(
        node.by_range(9, 1, &[47]).await,
        served(&[block.sidecar(47)])
    );

    // Checked together: columns 1, 87 and 102, each invalid copy right before its valid one.
    for index in [1, 87, 102] {
        node.gossip(&flipped(block.sidecar(index)));
        node.gossip(&block.sidecar(index));
    }
    node.dropped(Drop::KzgInvalid, 4).await;
    node.settle("every valid copy to be stored", || {
        node.stored(&block) == CUSTODY
    })
    .await;
    assert_eq!(
        node.by_range(9, 1, &CUSTODY).await,
        served(&block.sidecars(&CUSTODY))
    );

    // Waiting together: both copies of each column of the block at 10 wait for its root, which
    // the reference learns only once its header was missed twice: on the root's first ask and
    // on a retry (one header request each).
    let later = Block::on(10, &block, &[0, 1]);
    for index in CUSTODY {
        node.gossip(&flipped(later.sidecar(index)));
        node.gossip(&later.sidecar(index));
    }
    wait_for("the later root to be missed and retried", || {
        node.reference.header_misses(&later) >= 2
    })
    .await;
    // All eight still wait: none checked, none dropped, none stored.
    assert_eq!(node.ingest.pending(), 8);
    assert_eq!(node.drops(), [("kzg_invalid", 4)]);
    assert_eq!(node.stored(&later), Vec::<u64>::new());
    assert_eq!(node.by_root(&[(later.root, &CUSTODY)]).await, none());
    node.reference.serve(&later);
    node.dropped(Drop::KzgInvalid, 8).await;
    node.settle("the later block to be stored", || {
        node.stored(&later) == CUSTODY
    })
    .await;
    assert_eq!(node.drops(), [("kzg_invalid", 8)]);
    assert_eq!(
        node.by_root(&[(later.root, &CUSTODY)]).await,
        served(&later.sidecars(&CUSTODY))
    );
    let both = [block.sidecars(&CUSTODY), later.sidecars(&CUSTODY)].concat();
    assert_eq!(node.by_range(9, 2, &CUSTODY).await, served(&both));
}

/// The column RPCs answer from the column store alone, never from a column still on its way in:
/// not a column of a stored block that passed the contract and whose write is held open before
/// its commit, and not columns waiting for a root the reference does not know yet. Each is
/// served once it was written. No serving path can reach the pending queue (`ColumnServer`
/// holds only a `ColumnStore`, whose one method is the column env's `ColumnReader`); this test
/// shows the answers agree with that while columns of a block it already stores are in flight.
#[tokio::test]
async fn serving_reads_contract_store_only() {
    let node = Node::start().await;
    let anchor = served(&node.anchor.sidecars(&CUSTODY));
    // 9: three custody columns stored, then 47 checked and put, its commit held.
    let block = node.block(9, &node.anchor);
    let stored = block.sidecars(&[1, 87, 102]);
    node.gossip_all(&stored).await;
    let held = HeldWrites::new(&node.writer, block.slot);
    node.gossip(&block.sidecar(47));
    held.entered().await;
    // 10, its child: every custody column waits for a root the reference does not know yet.
    let later = Block::on(10, &block, &[0, 1]);
    let waiting = later.sidecars(&CUSTODY);
    for sidecar in &waiting {
        node.gossip(sidecar);
    }
    wait_for("the later root to be missed", || {
        node.reference.header_misses(&later) >= 1
    })
    .await;
    assert_eq!(node.ingest.pending(), 5);

    // By root: the stored columns only.
    assert_eq!(node.by_root(&[(block.root, &[47])]).await, none());
    assert_eq!(
        node.by_root(&[(block.root, &CUSTODY), (later.root, &CUSTODY)])
            .await,
        served(&stored)
    );
    // By range: the block at 9 lacks 47, so a range from it that asks for 47 is unavailable
    // and one from the anchor ends before it; the store knows of no block at 10.
    assert_eq!(node.by_range(9, 1, &[47]).await, UNAVAILABLE);
    assert_eq!(node.by_range(9, 2, &CUSTODY).await, UNAVAILABLE);
    assert_eq!(node.by_range(9, 2, &[1, 87, 102]).await, served(&stored));
    assert_eq!(node.by_range(8, 3, &CUSTODY).await, anchor);
    assert_eq!(node.by_range(10, 1, &CUSTODY).await, none());
    // Still on their way in through every query: none was answered from the queue.
    assert_eq!(node.ingest.pending(), 5);
    assert_eq!(node.stored(&block), [1, 87, 102]);
    assert_eq!(node.stored(&later), Vec::<u64>::new());

    held.release();
    node.reference.serve(&later);
    node.settle("both blocks to be stored", || {
        node.stored(&block) == CUSTODY && node.stored(&later) == CUSTODY
    })
    .await;
    assert!(node.drops().is_empty(), "{:?}", node.drops());
    let columns = block.sidecars(&CUSTODY);
    assert_eq!(
        node.by_root(&[(block.root, &CUSTODY), (later.root, &CUSTODY)])
            .await,
        served(&[columns.clone(), waiting.clone()].concat())
    );
    assert_eq!(
        node.by_range(8, 3, &CUSTODY).await,
        served(&[node.anchor.sidecars(&CUSTODY), columns, waiting].concat())
    );
}
