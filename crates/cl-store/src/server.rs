//! `ethswarm.store.v1` `StoreService` over a [`Reader`].
//!
//! - Every read runs on `spawn_blocking` under the call's [`Deadline`] ([`DEFAULT_TIMEOUT`]).
//! - A failed read fails the call with a fixed message and the `common.v1.Error` in the status
//!   details: `UNAVAILABLE` (`ERROR_CODE_RESOURCE_UNAVAILABLE`: nothing stamped to serve, or
//!   the env cannot be read now), `NOT_FOUND`, `DEADLINE_EXCEEDED`; a malformed request is
//!   `INVALID_ARGUMENT` (`ERROR_CODE_INVALID`); anything else is `INTERNAL`.
//! - `GetBlock` (a root, a slot, `head` or `finalized`) and `GetChainHead` answer from one read
//!   transaction and its stamp. `GetBlocksByRange` serves finalized blocks only, at most
//!   [`MAX_BLOCKS`], read in one transaction before its stream opens. Envelope `root`s are
//!   block roots.
//! - `GetBlocksByHead` is a [`ParentWalk`]: `count` capped at [`MAX_BLOCKS`], stamped by its
//!   first read (before the stream opens), then one block per read as the client reads, at
//!   most one body ahead.
//! - `GetChainHead` carries the stamp's head; the stamp holds no checkpoint epoch, justified
//!   checkpoint, head state root or earliest slot, so those fields stay empty.
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
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{service::Routes, Code, Request, Response, Status};

use crate::reader::{
    system_clock, Block, BlockRef, Clock, Deadline, ParentWalk, ReadError, Reader, Root, Stamp,
    Stamped,
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

/// The `StoreService`.
#[derive(Clone)]
pub struct StoreServer {
    link: Link,
    reader: Arc<Reader>,
    timeout: Duration,
    clock: Clock,
}

impl StoreServer {
    #[must_use]
    pub fn new(link: Link, reader: Arc<Reader>) -> Self {
        Self {
            link,
            reader,
            timeout: DEFAULT_TIMEOUT,
            clock: system_clock(),
        }
    }

    /// The `StoreService` over the env `store` holds, reopened when it fails.
    #[must_use]
    pub fn recovering(link: Link, store: Arc<crate::recover::Recovering>) -> Self {
        let _ = (link, store);
        todo!()
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
        let reader = Arc::clone(&self.reader);
        let deadline = self.deadline();
        tokio::task::spawn_blocking(move || read(&reader, &deadline))
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
            ..Default::default()
        }))
    }

    async fn get_blocks_by_head(
        &self,
        request: Request<pb::GetBlocksByHeadRequest>,
    ) -> Result<Response<Self::GetBlocksByHeadStream>, Status> {
        let req = request.into_inner();
        self.link
            .accept_hello_field(req.hello.as_ref())
            .map_err(|e| e.to_status())?;
        let root = root_of(&req.root)?;
        let count = req.count.min(MAX_BLOCKS);
        let walk = ParentWalk::new(Arc::clone(&self.reader), root, count, self.deadline());
        // The stamped first read, before the stream opens: with no stamp the call fails.
        let (mut walk, mut next) = step(walk).await?;
        let hello = pb::GetBlocksByHeadResponse::hello(self.hello()?);
        let (tx, rx) = mpsc::channel(1);
        let server = self.clone();
        ipc::spawn_in_span(async move {
            if tx.send(Ok(hello)).await.is_err() {
                return;
            }
            let mut seq = 0;
            while let Some(read) = next {
                seq += 1;
                let body = server.head_body(read, seq);
                let failed = body.is_err();
                if tx
                    .send(body.map(pb::GetBlocksByHeadResponse::body))
                    .await
                    .is_err()
                    || failed
                {
                    return;
                }
                match step(walk).await {
                    Ok((rest, after)) => (walk, next) = (rest, after),
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
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
        sync::atomic::{AtomicUsize, Ordering},
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

    /// A clock that reads `t0` its first `reads` times, then an hour later: time passes once
    /// the call's read txn is open (its first two reads are the call's start and the txn's
    /// open).
    fn late_after(reads: usize) -> Clock {
        let t0 = Instant::now();
        let calls = AtomicUsize::new(0);
        Arc::new(move || {
            if calls.fetch_add(1, Ordering::SeqCst) < reads {
                t0
            } else {
                t0 + Duration::from_secs(3600)
            }
        })
    }

    /// A read txn held past the call's deadline fails the call `DEADLINE_EXCEEDED`, on every
    /// served RPC. The method ACL gives every method of the descriptor to cl-api, cl-sync and
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
