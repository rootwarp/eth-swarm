//! `ethswarm.store.v1` `StoreService` over a [`Reader`].
//!
//! - Every read runs on `spawn_blocking` under the call's [`Deadline`] ([`DEFAULT_TIMEOUT`]),
//!   on the env a [`Recovering`] holds: while the env is down (it wants recovery, or did not
//!   open) every read is `UNAVAILABLE`, and it is reopened read-only on a backoff
//!   ([`crate::recover`]).
//! - A failed read fails the call with a fixed message and the `common.v1.Error` in the status
//!   details: `UNAVAILABLE` (`ERROR_CODE_RESOURCE_UNAVAILABLE`: nothing stamped to serve, or
//!   the env cannot be read now), `NOT_FOUND`, `DEADLINE_EXCEEDED`; a malformed request is
//!   `INVALID_ARGUMENT` (`ERROR_CODE_INVALID`); anything else is `INTERNAL`.
//! - `GetBlock` (a root, a slot, `head` or `finalized`) and `GetChainHead` answer from one read
//!   transaction and its stamp. `GetBlocksByRange` serves finalized blocks only, at most
//!   [`MAX_BLOCKS`], read in one transaction before its stream opens, from the finalized slot
//!   index at any depth; a range that starts below the index's floor (what cl-chain has not
//!   indexed yet) is `UNAVAILABLE` (`ERROR_CODE_RESOURCE_UNAVAILABLE`), unread. Envelope
//!   `root`s are block roots.
//! - `GetBlocksByHead` is a [`ParentWalk`]: `count` capped at [`MAX_BLOCKS`], stamped by its
//!   first read (before the stream opens), then one block per read as the client reads, at
//!   most one body ahead. cl-p2p reads it at its peer's pace for BeaconBlocksByHead (#230), so
//!   the stream lives [`HEAD_WALK_TIMEOUT`] while each step's read transaction is checked
//!   against the call timeout from the step's start (the first step's from the call's); its
//!   `finalized` is a lookup in the finalized slot index, `false` below the index's floor (not
//!   proven). Each frame waits for the client until the
//!   stream's end at most, so a stalled client holds nothing past it, and at most
//!   [`MAX_HEAD_STREAMS`] streams are open at once: a call past them is `UNAVAILABLE`, unread.
//! - `GetChainHead` carries the stamp's head and its finalized block's slot (`finalized_slot`,
//!   where cl-p2p splits a BeaconBlocksByRange answer between cl-store and cl-chain); the stamp
//!   holds no checkpoint epoch, justified checkpoint, head state root or earliest slot, so those
//!   fields stay empty.
//! - `GetState`, `GetPayloadEnvelope`, `GetDataColumns` and `GetDataColumnsByRange` run the
//!   contract checks and answer `UNIMPLEMENTED`; so does `include_envelopes`.
//! - The method ACL is [`store_acl`]: the server's owner puts it in front as an
//!   [`ipc::acl::AclLayer`].

use std::{sync::Arc, time::Duration};

use ethswarm_proto::common::{Envelope, ErrorCode, Hello, PayloadType};
use ethswarm_proto::store as pb;
use ipc::{
    acl::{AclError, AclTables, MethodAcl},
    error::wire_error,
    frame::OutFrame,
    hello::stream_hello,
    stub::{self, StubStream},
    Link,
};
use pb::{
    block_id::Id,
    store_service_server::{StoreService, StoreServiceServer},
};
use prost::Message;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{service::Routes, Code, Request, Response, Status};

use crate::{
    reader::{
        system_clock, Block, BlockRef, Clock, Deadline, ParentWalk, ReadError, Reader, Root, Stamp,
        Stamped,
    },
    recover::Recovering,
};

/// The callers of every `StoreService` method.
const CALLERS: [&str; 3] = ["cl-api", "cl-sync", "cl-p2p"];

/// Every `StoreService` method.
const METHODS: [&str; 8] = [
    "/ethswarm.store.v1.StoreService/GetBlock",
    "/ethswarm.store.v1.StoreService/GetState",
    "/ethswarm.store.v1.StoreService/GetDataColumns",
    "/ethswarm.store.v1.StoreService/GetPayloadEnvelope",
    "/ethswarm.store.v1.StoreService/GetBlocksByRange",
    "/ethswarm.store.v1.StoreService/GetDataColumnsByRange",
    "/ethswarm.store.v1.StoreService/GetChainHead",
    "/ethswarm.store.v1.StoreService/GetBlocksByHead",
];

/// `MAX_REQUEST_BLOCKS_DENEB`: the most blocks one range or parent walk serves.
pub const MAX_BLOCKS: u64 = 128;

/// The UIDs of cl-store's callers: cl-api, cl-sync and cl-p2p.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Callers {
    pub api: u32,
    pub sync: u32,
    pub p2p: u32,
}

/// cl-store's method ACL: every method to cl-api, cl-sync and cl-p2p, nobody else.
///
/// # Errors
///
/// The ACL does not load.
pub fn store_acl(callers: Callers) -> Result<MethodAcl, AclError> {
    let uids = [callers.api, callers.sync, callers.p2p];
    let tables = AclTables {
        callers: CALLERS
            .iter()
            .zip(uids)
            .map(|(name, uid)| ((*name).to_owned(), uid))
            .collect(),
        methods: METHODS
            .iter()
            .map(|method| ((*method).to_owned(), CALLERS.map(str::to_owned).to_vec()))
            .collect(),
    };
    MethodAcl::from_tables("cl-store", &tables)
}

/// How long one call's reads may take, unless [`StoreServer::with_timeout`] says otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a `GetBlocksByHead` stream may run \[est\]: 10 s, past the 9.5 s cl-p2p's
/// BeaconBlocksByHead answer runs while it reads a block per peer token (#230). A step that
/// would start later fails `DEADLINE_EXCEEDED`, and a frame the client has not taken by then
/// ends the stream after the frames queued; each step's read transaction is still checked
/// against the call timeout from the step's start (the first step's from the call's start), so
/// no transaction pins MVCC pages much longer than a unary call's.
pub const HEAD_WALK_TIMEOUT: Duration = Duration::from_secs(10);

/// `GetBlocksByHead` streams open at once \[est\]: 32, twice cl-p2p's block lookups. Each holds
/// its walk and at most two blocks (one queued, one in hand) until it ends, by
/// [`HEAD_WALK_TIMEOUT`] at the latest; a call past them is `UNAVAILABLE` before any read.
pub const MAX_HEAD_STREAMS: usize = 32;

/// The `StoreService`.
#[derive(Clone)]
pub struct StoreServer {
    link: Link,
    store: Arc<Recovering>,
    timeout: Duration,
    clock: Clock,
    /// How long a `GetBlocksByHead` stream lives ([`HEAD_WALK_TIMEOUT`]).
    walk: Duration,
    /// The open `GetBlocksByHead` streams' places ([`MAX_HEAD_STREAMS`]).
    head_streams: Arc<Semaphore>,
}

impl StoreServer {
    /// The `StoreService` over `reader`, an env this process opened already and never reopens.
    #[must_use]
    pub fn new(link: Link, reader: Arc<Reader>) -> Self {
        Self::recovering(link, Arc::new(Recovering::fixed(reader)))
    }

    /// The `StoreService` over the env `store` holds, reopened when it fails.
    #[must_use]
    pub fn recovering(link: Link, store: Arc<Recovering>) -> Self {
        Self {
            link,
            store,
            timeout: DEFAULT_TIMEOUT,
            clock: system_clock(),
            walk: HEAD_WALK_TIMEOUT,
            head_streams: Arc::new(Semaphore::new(MAX_HEAD_STREAMS)),
        }
    }

    /// The same server with another per-call deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    #[cfg(test)]
    fn with_walk_timeout(mut self, walk: Duration) -> Self {
        self.walk = walk;
        self
    }

    #[cfg(test)]
    fn with_head_streams(mut self, streams: usize) -> Self {
        self.head_streams = Arc::new(Semaphore::new(streams));
        self
    }

    /// Every `ethswarm.store.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(StoreServiceServer::new(self))
    }

    /// The deadline of a call starting now.
    fn deadline(&self) -> Deadline {
        Deadline::after(Arc::clone(&self.clock), self.timeout)
    }

    /// `read` on `spawn_blocking`, under the deadline of a call starting now.
    async fn blocking<T: Send + 'static>(
        &self,
        read: impl FnOnce(&Reader, &Deadline) -> Result<T, ReadError> + Send + 'static,
    ) -> Result<T, Status> {
        let store = Arc::clone(&self.store);
        let deadline = self.deadline();
        tokio::task::spawn_blocking(move || store.read(|reader| read(reader, &deadline)))
            .await
            .map_err(|_| status(ReadError::Internal))?
            .map_err(status)
    }

    /// `block` as an envelope at `seq` (0 in a unary response), with its slot's fork digest.
    fn envelope(&self, block: Block, seq: u64) -> Result<Envelope, Status> {
        let digest = self
            .link
            .fork_digest_at_slot(block.slot)
            .ok_or_else(|| status(ReadError::Internal))?;
        Ok(Envelope {
            fork_digest: digest.to_vec(),
            slot: block.slot,
            root: block.root.to_vec(),
            ssz: block.ssz,
            payload_type: PayloadType::SignedBeaconBlock as i32,
            trace_id: Vec::new(),
            seq,
        })
    }

    /// The hello a stream opens with (a fresh server generation).
    fn hello(&self) -> Result<Hello, Status> {
        stream_hello(&self.link.local())
            .map(|(_, hello)| hello)
            .map_err(|e| e.to_status())
    }

    fn head_body(
        &self,
        read: Stamped<Block>,
        seq: u64,
    ) -> Result<pb::GetBlocksByHeadResponseBody, Status> {
        let meta = read_meta(&read.stamp, read.value.finalized);
        Ok(pb::GetBlocksByHeadResponseBody {
            block: Some(self.envelope(read.value, seq)?),
            meta: Some(meta),
            error: None,
        })
    }
}

/// The status a failed read fails its call with.
fn status(err: ReadError) -> Status {
    let (code, error) = match err {
        ReadError::Unavailable => (Code::Unavailable, ErrorCode::ResourceUnavailable),
        ReadError::NotFound => (Code::NotFound, ErrorCode::NotFound),
        ReadError::DeadlineExceeded => (Code::DeadlineExceeded, ErrorCode::DeadlineExceeded),
        ReadError::Internal => return Status::internal(err.to_string()),
    };
    failed(code, error, &err.to_string())
}

/// `code`, with `error` and `detail` as the `common.v1.Error` in the details.
fn failed(code: Code, error: ErrorCode, detail: &str) -> Status {
    let details = wire_error(error, detail).encode_to_vec();
    Status::with_details(code, detail, details.into())
}

fn invalid(detail: &str) -> Status {
    failed(Code::InvalidArgument, ErrorCode::Invalid, detail)
}

fn root_of(bytes: &[u8]) -> Result<Root, Status> {
    bytes
        .try_into()
        .map_err(|_| invalid("a block root is 32 bytes"))
}

fn read_meta(stamp: &Stamp, finalized: bool) -> pb::ReadMeta {
    pb::ReadMeta {
        as_of_seq: stamp.head_seq,
        as_of_root: stamp.head_root.to_vec(),
        as_of_slot: stamp.head_slot,
        execution_optimistic: false,
        finalized,
    }
}

/// Sends `frame` unless `until` passes first: whether it went.
async fn send_by<T>(tx: &mpsc::Sender<T>, frame: T, until: tokio::time::Instant) -> bool {
    matches!(
        tokio::time::timeout_at(until, tx.send(frame)).await,
        Ok(Ok(()))
    )
}

/// The walk's next block, read on `spawn_blocking`.
async fn step(mut walk: ParentWalk) -> Result<(ParentWalk, Option<Stamped<Block>>), Status> {
    let (walk, next) = tokio::task::spawn_blocking(move || {
        let next = walk.next();
        (walk, next)
    })
    .await
    .map_err(|_| status(ReadError::Internal))?;
    Ok((walk, next.transpose().map_err(status)?))
}

#[tonic::async_trait]
impl StoreService for StoreServer {
    type GetDataColumnsStream = StubStream<pb::GetDataColumnsResponse>;
    type GetBlocksByRangeStream = StubStream<pb::GetBlocksByRangeResponse>;
    type GetDataColumnsByRangeStream = StubStream<pb::GetDataColumnsByRangeResponse>;
    type GetBlocksByHeadStream = StubStream<pb::GetBlocksByHeadResponse>;

    async fn get_block(
        &self,
        request: Request<pb::GetBlockRequest>,
    ) -> Result<Response<pb::GetBlockResponse>, Status> {
        let at = match request.into_inner().id.and_then(|id| id.id) {
            Some(Id::Root(root)) => BlockRef::Root(root_of(&root)?),
            Some(Id::Slot(slot)) => BlockRef::Slot(slot),
            Some(Id::Named(name)) if name == "head" => BlockRef::Head,
            Some(Id::Named(name)) if name == "finalized" => BlockRef::Finalized,
            _ => return Err(invalid("block id: a root, a slot, head or finalized")),
        };
        let read = self.blocking(move |r, d| r.block(at, d)).await?;
        let meta = read_meta(&read.stamp, read.value.finalized);
        Ok(Response::new(pb::GetBlockResponse {
            block: Some(self.envelope(read.value, 0)?),
            meta: Some(meta),
            error: None,
        }))
    }

    async fn get_state(
        &self,
        _: Request<pb::GetStateRequest>,
    ) -> Result<Response<pb::GetStateResponse>, Status> {
        stub::unary(&self.link, "get_state", &[])
    }

    async fn get_data_columns(
        &self,
        request: Request<pb::GetDataColumnsRequest>,
    ) -> Result<Response<Self::GetDataColumnsStream>, Status> {
        stub::server_stream(&self.link, "get_data_columns", request.get_ref())
    }

    async fn get_payload_envelope(
        &self,
        _: Request<pb::GetPayloadEnvelopeRequest>,
    ) -> Result<Response<pb::GetPayloadEnvelopeResponse>, Status> {
        stub::unary(&self.link, "get_payload_envelope", &[])
    }

    async fn get_blocks_by_range(
        &self,
        request: Request<pb::GetBlocksByRangeRequest>,
    ) -> Result<Response<Self::GetBlocksByRangeStream>, Status> {
        let req = request.into_inner();
        self.link
            .accept_hello_field(req.hello.as_ref())
            .map_err(|e| e.to_status())?;
        if req.count > MAX_BLOCKS {
            return Err(invalid("count is at most 128"));
        }
        if req.include_envelopes {
            return Err(Status::unimplemented(
                "payload envelopes are not stored yet",
            ));
        }
        let (start, count) = (req.start_slot, req.count);
        let read = self
            .blocking(move |r, d| r.finalized_blocks(start, count, d))
            .await?;
        let meta = read_meta(&read.stamp, true);
        let mut frames = vec![Ok(pb::GetBlocksByRangeResponse::hello(self.hello()?))];
        for (seq, block) in (1..).zip(read.value) {
            let body = pb::GetBlocksByRangeResponseBody {
                item: Some(self.envelope(block, seq)?),
                meta: Some(meta.clone()),
                error: None,
            };
            frames.push(Ok(pb::GetBlocksByRangeResponse::body(body)));
        }
        Ok(Response::new(Box::pin(tokio_stream::iter(frames))))
    }

    async fn get_data_columns_by_range(
        &self,
        request: Request<pb::GetDataColumnsByRangeRequest>,
    ) -> Result<Response<Self::GetDataColumnsByRangeStream>, Status> {
        stub::server_stream(&self.link, "get_data_columns_by_range", request.get_ref())
    }

    async fn get_chain_head(
        &self,
        _: Request<pb::GetChainHeadRequest>,
    ) -> Result<Response<pb::GetChainHeadResponse>, Status> {
        let stamp = self.blocking(|r, d| r.head(d)).await?;
        Ok(Response::new(pb::GetChainHeadResponse {
            head_slot: stamp.head_slot,
            head_root: stamp.head_root.to_vec(),
            meta: Some(read_meta(&stamp, stamp.head_slot <= stamp.finalized_slot)),
            finalized_slot: stamp.finalized_slot,
            ..Default::default()
        }))
    }

    async fn get_blocks_by_head(
        &self,
        request: Request<pb::GetBlocksByHeadRequest>,
    ) -> Result<Response<Self::GetBlocksByHeadStream>, Status> {
        // The call's start: its first read's deadline, queue time in the blocking hops included.
        let first = self.deadline();
        let req = request.into_inner();
        self.link
            .accept_hello_field(req.hello.as_ref())
            .map_err(|e| e.to_status())?;
        let root = root_of(&req.root)?;
        let count = req.count.min(MAX_BLOCKS);
        // Held by the stream's task to its end; past the cap the call reads nothing.
        let place = Arc::clone(&self.head_streams)
            .try_acquire_owned()
            .map_err(|_| status(ReadError::Unavailable))?;
        let (store, timeout, lives) = (Arc::clone(&self.store), self.timeout, self.walk);
        let lives = lives.max(timeout);
        let until = tokio::time::Instant::now() + lives;
        let deadline = Deadline::after(Arc::clone(&self.clock), lives);
        let walk = tokio::task::spawn_blocking(move || {
            store.reader().map(|reader| {
                ParentWalk::new(reader, root, count, deadline)
                    .with_step_timeout(timeout)
                    .with_first_deadline(first)
            })
        })
        .await
        .map_err(|_| status(ReadError::Internal))?
        .map_err(status)?;
        // The stamped first read, before the stream opens: with no stamp the call fails.
        let (mut walk, mut next) = step(walk).await?;
        let hello = pb::GetBlocksByHeadResponse::hello(self.hello()?);
        let (tx, rx) = mpsc::channel(1);
        let server = self.clone();
        ipc::spawn_in_span(async move {
            let _place = place;
            // Each frame waits for the client until the stream's end at most: a stalled client
            // gets the frames queued, then the end, and holds nothing past it.
            if !send_by(&tx, Ok(hello), until).await {
                return;
            }
            let mut seq = 0;
            while let Some(read) = next {
                seq += 1;
                let body = server.head_body(read, seq);
                let failed = body.is_err();
                let body = body.map(pb::GetBlocksByHeadResponse::body);
                if !send_by(&tx, body, until).await || failed {
                    return;
                }
                match step(walk).await {
                    Ok((rest, after)) => (walk, next) = (rest, after),
                    Err(status) => {
                        send_by(&tx, Err(status), until).await;
                        return;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        reader::{Root, Stamp},
        stamp::StoreReader,
        testkit::{block, stamp, Store},
    };
    use ethswarm_proto::common::{ErrorCode, PayloadType};
    use ipc::{
        frame::{Frame, InFrame},
        testkit::{fixture, own_cred, probe::call_unary_empty, surface::surface, Mode, Server},
    };
    use network_config::ForkName;
    use pb::{store_service_client::StoreServiceClient, ReadMeta};
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
        time::Instant,
    };
    use tonic::Code;

    /// One stored block of a test chain.
    #[derive(Clone)]
    struct Stored {
        slot: u64,
        root: Root,
        ssz: Vec<u8>,
    }

    /// The first Fulu slot of the fixture link's schedule (Sepolia, mainnet preset): every
    /// test block is at or after it, so its fork digest is Fulu's.
    fn fulu_start() -> u64 {
        fixture::sepolia_schedule()
            .fork_epoch(ForkName::Fulu)
            .unwrap()
            * fixture::SLOTS_PER_EPOCH
    }

    /// `n` blocks, each on the one before, from the Fulu start, one per slot but the 6th slot
    /// skipped.
    fn chain(n: u64) -> Vec<Stored> {
        let mut blocks: Vec<Stored> = Vec::new();
        for i in 0..n {
            let slot = fulu_start() + i + u64::from(i >= 5);
            let parent = blocks.last().map_or([0; 32], |b| b.root);
            let (ssz, root) = block(slot, parent, i);
            blocks.push(Stored { slot, root, ssz });
        }
        blocks
    }

    /// The stamp with `head` and `finalized` blocks.
    fn stamp_of(seq: u64, head: &Stored, finalized: &Stored) -> Stamp {
        stamp(
            seq,
            (head.slot, head.root),
            (finalized.slot, finalized.root),
        )
    }

    /// The `ReadMeta` of `stamp`, for a block `finalized` or not.
    fn meta(stamp: &Stamp, finalized: bool) -> Option<ReadMeta> {
        Some(ReadMeta {
            as_of_seq: stamp.head_seq,
            as_of_root: stamp.head_root.to_vec(),
            as_of_slot: stamp.head_slot,
            execution_optimistic: false,
            finalized,
        })
    }

    fn server(store: &Store) -> StoreServer {
        StoreServer::new(fixture::v1_link(), Arc::new(store.reader()))
    }

    /// The contract-checking client of `server`, in process.
    async fn client(server: StoreServer) -> StoreReader<ipc::testkit::Transport> {
        let conn = Mode::InProcess.connect(Server::new(server.routes())).await;
        StoreReader::new(conn.transport.clone(), fixture::v1_link())
    }

    fn by_head(root: &[u8], count: u64) -> pb::GetBlocksByHeadRequest {
        pb::GetBlocksByHeadRequest {
            root: root.to_vec(),
            count,
            hello: None,
        }
    }

    /// `(slot, root, ssz, meta)` of each body.
    fn walked(bodies: &[pb::GetBlocksByHeadResponseBody]) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        bodies
            .iter()
            .map(|b| {
                let block = b.block.as_ref().expect("a block per body");
                assert_eq!(block.payload_type, PayloadType::SignedBeaconBlock as i32);
                (block.slot, block.root.clone(), block.ssz.clone())
            })
            .collect()
    }

    fn want(blocks: &[&Stored]) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        blocks
            .iter()
            .map(|b| (b.slot, b.root.to_vec(), b.ssz.clone()))
            .collect()
    }

    /// `GetBlocksByHead`: newest first along the parents, every body stamped with the stamp of
    /// the first read; `count` over 128 is served as 128; a parent that is not stored ends the
    /// stream OK; an unknown root gives no body, OK; with no stamp the call is UNAVAILABLE.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_by_head_stream() {
        let store = Store::new();
        let blocks = chain(140);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        let (head, fin) = (&blocks[139], &blocks[99]);
        let stamped = stamp_of(1, head, fin);
        store.import(&all, stamped);
        let mut client = client(server(&store)).await;

        let bodies = client
            .get_blocks_by_head(by_head(&head.root, 5))
            .await
            .unwrap();
        let newest: Vec<&Stored> = blocks[135..].iter().rev().collect();
        assert_eq!(walked(&bodies), want(&newest));
        for body in &bodies {
            assert_eq!(body.meta, meta(&stamped, false));
        }

        let bodies = client
            .get_blocks_by_head(by_head(&head.root, 1_000))
            .await
            .unwrap();
        assert_eq!(bodies.len(), 128, "count is clamped to 128");
        let newest: Vec<&Stored> = blocks[12..].iter().rev().collect();
        assert_eq!(walked(&bodies), want(&newest));
        for (body, b) in bodies.iter().zip(&newest) {
            assert_eq!(body.meta, meta(&stamped, b.slot <= fin.slot), "{}", b.slot);
        }

        let from = &blocks[30];
        let bodies = client
            .get_blocks_by_head(by_head(&from.root, 100))
            .await
            .unwrap();
        let down: Vec<&Stored> = blocks[..=30].iter().rev().collect();
        assert_eq!(
            walked(&bodies),
            want(&down),
            "ends at the first unstored parent"
        );

        let none = client
            .get_blocks_by_head(by_head(&[0xee; 32], 10))
            .await
            .unwrap();
        assert!(none.is_empty(), "an unknown root streams no body");

        let short = client.get_blocks_by_head(by_head(&[1; 31], 10)).await;
        assert_eq!(short.unwrap_err().code(), ErrorCode::Invalid);

        let empty = Store::new();
        let err = client_of(&empty)
            .await
            .get_blocks_by_head(by_head(&head.root, 10))
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceUnavailable, "{err}");
    }

    async fn client_of(store: &Store) -> StoreReader<ipc::testkit::Transport> {
        client(server(store)).await
    }

    /// #146: `GetChainHead` carries the stamp's finalized slot (`finalized_slot`, 8), the split
    /// point cl-p2p serves a BlocksByRange answer around, from the same read as the head; in
    /// process and over a Unix socket.
    #[tokio::test(flavor = "multi_thread")]
    async fn chain_head_carries_finalized_slot() {
        let store = Store::new();
        let blocks = chain(8);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        store.import(&all, stamp_of(1, &blocks[7], &blocks[4]));
        let dir = ipc::testkit::tempdir();
        for mode in [Mode::InProcess, Mode::over_uds(dir.path())] {
            let conn = mode.connect(Server::new(server(&store).routes())).await;
            let mut reader = StoreReader::new(conn.transport.clone(), fixture::v1_link());
            let head = reader.get_chain_head().await.unwrap();
            assert_eq!(head.head_slot, blocks[7].slot, "{}", mode.name());
            assert_eq!(head.finalized_slot, blocks[4].slot, "{}", mode.name());
        }
    }

    /// A commit that lands while a `GetBlocksByHead` stream is being read (a new head, a new
    /// stamp) leaves the stream gap-free and without a duplicate: every parent of the root,
    /// once each, all under the first read's stamp. The stream produces at most a body ahead
    /// of the reader, so the commit lands after three bodies and before most reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_by_head_commit_mid_walk() {
        let store = Store::new();
        let blocks = chain(40);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        let first = stamp_of(1, &blocks[39], &blocks[9]);
        store.import(&all, first);
        let link = fixture::v1_link();
        let conn = Mode::InProcess
            .connect(Server::new(server(&store).routes()))
            .await;
        let mut raw = StoreServiceClient::new(conn.transport.clone());
        let mut stream = raw
            .get_blocks_by_head(pb::GetBlocksByHeadRequest {
                root: blocks[39].root.to_vec(),
                count: 40,
                hello: Some(link.local()),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(frame(&mut stream).await, Some(Frame::Hello(_))));
        let mut bodies = Vec::new();
        for _ in 0..3 {
            match frame(&mut stream).await {
                Some(Frame::Body(b)) => bodies.push(b),
                other => panic!("{other:?}"),
            }
        }
        // cl-chain commits: five blocks on the head, a new stamp, finality moved.
        let mut parent = blocks[39].root;
        let mut more = Vec::new();
        for i in 0..5 {
            let (ssz, root) = block(blocks[39].slot + 1 + i, parent, 100 + i);
            more.push((ssz, root));
            parent = root;
        }
        let ssz: Vec<&[u8]> = more.iter().map(|(s, _)| s.as_slice()).collect();
        let new_head = Stored {
            slot: blocks[39].slot + 5,
            root: parent,
            ssz: Vec::new(),
        };
        store.import(&ssz, stamp_of(2, &new_head, &blocks[29]));
        while let Some(f) = frame(&mut stream).await {
            match f {
                Frame::Body(b) => bodies.push(b),
                Frame::Hello(h) => panic!("a second hello {h:?}"),
            }
        }

        let down: Vec<&Stored> = blocks.iter().rev().collect();
        assert_eq!(walked(&bodies), want(&down), "no gap, no duplicate");
        let seqs: Vec<u64> = bodies
            .iter()
            .map(|b| b.block.as_ref().unwrap().seq)
            .collect();
        assert_eq!(seqs, (1..=40).collect::<Vec<_>>());
        for (body, b) in bodies.iter().zip(&down) {
            assert_eq!(
                body.meta,
                meta(&first, b.slot <= blocks[9].slot),
                "{}",
                b.slot
            );
        }
        let now = store.reader().head(&crate::testkit::deadline()).unwrap();
        assert_eq!(now.head_seq, 2, "the commit landed");
    }

    /// The next frame of a `GetBlocksByHead` stream, `None` at its end.
    async fn frame(
        stream: &mut tonic::Streaming<pb::GetBlocksByHeadResponse>,
    ) -> Option<Frame<pb::GetBlocksByHeadResponseBody>> {
        let message = stream.message().await.unwrap()?;
        Some(message.into_frame().expect("hello or body"))
    }

    /// A clock the test moves: `t0` and the milliseconds added to the counter.
    fn manual() -> (Clock, Arc<AtomicU64>) {
        let (t0, ms) = (Instant::now(), Arc::new(AtomicU64::new(0)));
        let read = Arc::clone(&ms);
        let clock: Clock =
            Arc::new(move || t0 + Duration::from_millis(read.load(Ordering::SeqCst)));
        (clock, ms)
    }

    /// #230 D3b: cl-p2p reads a `GetBlocksByHead` stream at its peer's pace, a block per token
    /// (20 ms by default), for up to its 9.5 s answer. The stream lives 10 s, past the call's
    /// 2 s (each step's read transaction still under it): 128 bodies read 50 ms apart (6.4 s)
    /// all arrive, and a reader that comes back past 10 s gets `DEADLINE_EXCEEDED` after what
    /// was sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_by_head_paced_reader() {
        let store = Store::new();
        let blocks = chain(140);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        store.import(&all, stamp_of(1, &blocks[139], &blocks[99]));
        let (clock, ms) = manual();
        let server = server(&store).with_clock(clock);
        let conn = Mode::InProcess.connect(Server::new(server.routes())).await;
        let mut raw = StoreServiceClient::new(conn.transport.clone());
        let link = fixture::v1_link();
        let request = || pb::GetBlocksByHeadRequest {
            root: blocks[139].root.to_vec(),
            count: 128,
            hello: Some(link.local()),
        };
        // Reads to the end: the bodies, and the status the stream ended with.
        async fn drain(
            stream: &mut tonic::Streaming<pb::GetBlocksByHeadResponse>,
            ms: &AtomicU64,
            pause: impl Fn(usize) -> u64,
        ) -> (usize, Option<Code>) {
            let mut bodies = 0;
            loop {
                match stream.message().await {
                    Ok(Some(m)) => match m.into_frame().expect("hello or body") {
                        Frame::Hello(_) => continue,
                        Frame::Body(_) => bodies += 1,
                    },
                    Ok(None) => return (bodies, None),
                    Err(status) => return (bodies, Some(status.code())),
                }
                ms.fetch_add(pause(bodies), Ordering::SeqCst);
            }
        }
        let mut paced = raw
            .get_blocks_by_head(request())
            .await
            .unwrap()
            .into_inner();
        let read = drain(&mut paced, &ms, |_| 50).await;
        assert_eq!(read, (128, None), "every body, read over 6.4 s");

        let mut late = raw
            .get_blocks_by_head(request())
            .await
            .unwrap()
            .into_inner();
        let (bodies, ended) = drain(&mut late, &ms, |n| if n == 3 { 11_000 } else { 0 }).await;
        assert_eq!(ended, Some(Code::DeadlineExceeded));
        assert!((3..=6).contains(&bodies), "what was sent first: {bodies}");
    }

    /// A clock that reads `t0` its first `reads` times, then an hour later: time passes once
    /// the call's read txn is open (its first two reads are the call's start and the txn's
    /// open).
    fn late_after(reads: usize) -> Clock {
        late_by(reads, Duration::from_secs(3600))
    }

    /// A clock that reads `t0` its first `reads` times, then `by` later.
    fn late_by(reads: usize, by: Duration) -> Clock {
        let t0 = Instant::now();
        let calls = AtomicUsize::new(0);
        Arc::new(move || {
            if calls.fetch_add(1, Ordering::SeqCst) < reads {
                t0
            } else {
                t0 + by
            }
        })
    }

    /// #230 (Cole NIT 3 of part A): a `GetBlocksByHead` call's first read is checked against
    /// the call's deadline from when the call came in, not from when its first step started.
    /// On a clock that reads `t0` once (the call's start) and later from then on (time queued
    /// in the blocking hops), a 1 s call 1.5 s late fails `DEADLINE_EXCEEDED` before its
    /// stream opens; 0.5 s late it walks.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_by_head_first_read_from_the_call() {
        async fn walk(server: StoreServer, root: &[u8]) -> Result<usize, ErrorCode> {
            let bodies = client(server)
                .await
                .get_blocks_by_head(by_head(root, 4))
                .await;
            bodies.map(|b| b.len()).map_err(|e| e.code())
        }
        let store = Store::new();
        let blocks = chain(4);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        store.import(&all, stamp_of(1, &blocks[3], &blocks[2]));
        let late = |ms| {
            server(&store)
                .with_timeout(Duration::from_secs(1))
                .with_clock(late_by(1, Duration::from_millis(ms)))
        };
        let head = blocks[3].root;
        assert_eq!(
            walk(late(1_500), &head).await,
            Err(ErrorCode::DeadlineExceeded),
            "queued past the call's 1 s"
        );
        assert_eq!(walk(late(500), &head).await, Ok(4), "within it");
    }

    /// #230 (Vera N2, Cole NIT 2 of part A): a client that stops reading a `GetBlocksByHead`
    /// stream holds it no longer than the stream lives: each frame waits for the client until
    /// then at most, and the stream ends there, after what was queued, freeing its walk, its
    /// block and its place. The server holds a place per open stream, at most
    /// `with_head_streams` (here 1): a call past them is `UNAVAILABLE` before any read; once the
    /// stalled stream ended a call is served again, and a stream read to its end gives its
    /// place back.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_by_head_stalled_reader_released() {
        use tokio_stream::StreamExt as _;
        let store = Store::new();
        let blocks = chain(8);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        store.import(&all, stamp_of(1, &blocks[7], &blocks[0]));
        let lives = Duration::from_millis(300);
        let server = server(&store).with_walk_timeout(lives).with_head_streams(1);
        let request = || {
            Request::new(pb::GetBlocksByHeadRequest {
                root: blocks[7].root.to_vec(),
                count: 8,
                hello: Some(fixture::v1_link().local()),
            })
        };
        // A place: retried until the one place is free again, for at most 5 s.
        let (server, request) = (&server, &request);
        let placed = move || async move {
            let start = Instant::now();
            loop {
                match server.get_blocks_by_head(request()).await {
                    Ok(stream) => return stream.into_inner(),
                    Err(status) => assert_eq!(status.code(), Code::Unavailable, "{status:?}"),
                }
                assert!(start.elapsed() < Duration::from_secs(5), "no place in 5 s");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };

        let called = Instant::now();
        // Never read: its one-frame queue holds the hello, and its first body waits.
        let stalled = placed().await;
        let refused = server.get_blocks_by_head(request()).await.err();
        let refused = refused.expect("a call past the cap");
        assert_eq!(refused.code(), Code::Unavailable, "{refused:?}");
        let served = placed().await;
        assert!(
            called.elapsed() >= lives,
            "the stalled stream lived out its time"
        );
        let frames: Vec<_> = stalled.collect().await;
        assert_eq!(
            frames.len(),
            1,
            "the hello it never read, then the end: {frames:?}"
        );
        assert!(frames[0].is_ok());

        let frames: Vec<_> = served.collect().await;
        assert_eq!(frames.len(), 9, "the hello and 8 bodies");
        assert!(frames.iter().all(Result::is_ok));
        drop(placed().await);
    }

    /// A `GetBlocksByHead` request for `count` blocks down from `root`, with its hello.
    fn head_request(root: &Root, count: u64) -> Request<pb::GetBlocksByHeadRequest> {
        Request::new(pb::GetBlocksByHeadRequest {
            root: root.to_vec(),
            count,
            hello: Some(fixture::v1_link().local()),
        })
    }

    /// Vera N2, Cole NIT 3 (and #303 N4): a client that never reads its `GetBlocksByHead`
    /// stream holds the walk's reader only until that reader is found broken, not for the
    /// stream's life ([`HEAD_WALK_TIMEOUT`]). On a real env opened read-only (MDBX refuses a
    /// second open of it in this process while the old handle lives), once a read finds the
    /// reader broken the stalled stream ends and drops it, and the env reopens read-only far
    /// sooner, on a paused clock. The stream ends after the hello it never read: no room for
    /// an UNAVAILABLE frame, which is not waited for.
    #[test]
    fn blocks_by_head_broken_reader_ends_a_stalled_stream() {
        use tokio_stream::StreamExt as _;
        let _serial = crate::testkit::serial();
        let dir = tempfile::tempdir().unwrap();
        let blocks = chain(8);
        {
            let writer = store_schema::env::test_writer(dir.path()).unwrap();
            let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
            crate::testkit::import(&writer, &all, stamp_of(1, &blocks[7], &blocks[0]));
        }
        let store = Arc::new(Recovering::open(dir.path()));
        let server = StoreServer::recovering(fixture::v1_link(), Arc::clone(&store));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async {
            let start = tokio::time::Instant::now();
            let soon = HEAD_WALK_TIMEOUT / 10;
            // Never read: its one-frame queue holds the hello, and its first body waits.
            let stalled = server
                .get_blocks_by_head(head_request(&blocks[7].root, 8))
                .await
                .unwrap()
                .into_inner();
            let reader = store.reader().unwrap();
            let held = Arc::downgrade(&reader);
            reader.poison();
            drop(reader);
            // A hint makes each read try a reopen at once, whatever the backoff.
            loop {
                store.hint();
                if store.read(|r| r.head(&crate::testkit::deadline())).is_ok() {
                    break;
                }
                assert!(
                    start.elapsed() < soon,
                    "no reopen in {soon:?}: the stalled stream still holds the broken reader \
                     ({} holders)",
                    held.strong_count()
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(held.strong_count(), 0, "the broken reader is gone");
            assert!(start.elapsed() < soon, "reopened at {:?}", start.elapsed());
            let frames: Vec<_> = stalled.collect().await;
            assert_eq!(frames.len(), 1, "the hello, then the end: {frames:?}");
            assert!(frames[0].is_ok());
            assert!(
                start.elapsed() < soon,
                "the stream ended at {:?}",
                start.elapsed()
            );
        });
    }

    /// A reader found broken mid-walk ends the `GetBlocksByHead` stream before its next step:
    /// a client reading along gets at most the one body already queued, then the end
    /// (UNAVAILABLE when there was room for it), never the rest of the walk.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_by_head_broken_reader_takes_no_further_step() {
        use tokio_stream::StreamExt as _;
        let store = Store::new();
        let blocks = chain(8);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        store.import(&all, stamp_of(1, &blocks[7], &blocks[0]));
        let reader = Arc::new(store.reader());
        let server = StoreServer::new(fixture::v1_link(), Arc::clone(&reader));
        let mut stream = server
            .get_blocks_by_head(head_request(&blocks[7].root, 8))
            .await
            .unwrap()
            .into_inner();
        let mut bodies = 0;
        while bodies < 1 {
            let message = stream.next().await.expect("a frame").expect("not an error");
            if let Frame::Body(_) = message.into_frame().expect("hello or body") {
                bodies += 1;
            }
        }
        reader.poison();
        let rest: Vec<_> = stream.collect().await;
        let mut after = 0;
        for frame in &rest {
            match frame {
                Ok(message) => match message.clone().into_frame().expect("hello or body") {
                    Frame::Body(_) => after += 1,
                    Frame::Hello(_) => panic!("a second hello"),
                },
                Err(status) => assert_eq!(status.code(), Code::Unavailable, "{status:?}"),
            }
        }
        assert!(after <= 1, "{after} bodies after the reader broke");
    }

    /// A read txn held past the call's deadline fails the call `DEADLINE_EXCEEDED`, on every
    /// served RPC (`GetBlocksByHead`: its first step's txn, past the call timeout from the
    /// call's start). The method ACL gives every method of the descriptor to cl-api, cl-sync and
    /// cl-p2p: each of them passes on every method, and any other caller, or one with no
    /// credentials, is refused `PERMISSION_DENIED` before the service sees the call.
    #[tokio::test(flavor = "multi_thread")]
    async fn acl() {
        let store = Store::new();
        let blocks = chain(4);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        store.import(&all, stamp_of(1, &blocks[3], &blocks[2]));
        let reader = Arc::new(store.reader());
        let late = || {
            StoreServer::new(fixture::v1_link(), Arc::clone(&reader))
                .with_timeout(Duration::from_secs(1))
                .with_clock(late_after(2))
        };
        let head = blocks[3].root.to_vec();
        let block_req = || pb::GetBlockRequest {
            id: Some(pb::BlockId {
                id: Some(pb::block_id::Id::Root(head.clone())),
            }),
        };
        let conn = Mode::InProcess.connect(Server::new(late().routes())).await;
        let status = StoreServiceClient::new(conn.transport.clone())
            .get_block(block_req())
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::DeadlineExceeded, "{status:?}");
        let deadline = ErrorCode::DeadlineExceeded;
        let code = |e: ipc::ContractError| e.code();
        assert_eq!(
            client(late())
                .await
                .get_block(block_req())
                .await
                .map_err(code)
                .err(),
            Some(deadline)
        );
        assert_eq!(
            client(late())
                .await
                .get_chain_head()
                .await
                .map_err(code)
                .err(),
            Some(deadline)
        );
        let range = pb::GetBlocksByRangeRequest {
            start_slot: blocks[0].slot,
            count: 4,
            ..Default::default()
        };
        assert_eq!(
            client(late())
                .await
                .get_blocks_by_range(range)
                .await
                .map_err(code)
                .err(),
            Some(deadline)
        );
        assert_eq!(
            client(late())
                .await
                .get_blocks_by_head(by_head(&head, 4))
                .await
                .map_err(code)
                .err(),
            Some(deadline)
        );

        let methods: BTreeSet<String> = surface("ethswarm.store.v1")
            .rpcs
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert_eq!(methods.len(), METHODS.len());
        let me = own_cred().uid();
        let [a, b, c] = [1, 2, 3].map(|n| me.wrapping_add(n));
        let allowed = [
            Callers {
                api: me,
                sync: a,
                p2p: b,
            },
            Callers {
                api: a,
                sync: me,
                p2p: b,
            },
            Callers {
                api: a,
                sync: b,
                p2p: me,
            },
        ];
        let off = Callers {
            api: a,
            sync: b,
            p2p: c,
        };
        let through = |callers: Callers, credentials: bool| {
            let reader = Arc::clone(&reader);
            let methods = methods.clone();
            async move {
                let acl = store_acl(callers).expect("the ACL loads");
                assert_eq!(
                    acl.methods().map(str::to_owned).collect::<BTreeSet<_>>(),
                    methods
                );
                let server = StoreServer::new(fixture::v1_link(), reader);
                let conn = Mode::InProcess
                    .connect_behind_acl(Server::new(server.routes()), Arc::new(acl), credentials)
                    .await;
                let mut denied = Vec::new();
                for path in &methods {
                    let r = call_unary_empty(conn.connection.transport.clone(), path).await;
                    denied.push(r.err().is_some_and(|s| s.code() == Code::PermissionDenied));
                }
                (denied, conn.reached())
            }
        };
        let n = methods.len();
        for callers in allowed {
            assert_eq!(
                through(callers, true).await,
                (vec![false; n], n as u64),
                "{callers:?}"
            );
        }
        assert_eq!(
            through(off, true).await,
            (vec![true; n], 0),
            "off the allowlist"
        );
        assert_eq!(
            through(allowed[0], false).await,
            (vec![true; n], 0),
            "no credentials"
        );
    }
}
