//! The ipc contract suite against `cl-store`: every rule in process and over a Unix socket,
//! plus the client rules of a cl-store reader ([`StoreReader`]):
//!
//! - `store_as_of_stamp`: every response and every streamed body carries its full read stamp;
//! - `store_response_envelopes`: response envelopes pass the envelope rules (seq 0 on unary
//!   responses, type, digest); a dropped one is removed, a broken one fails the call;
//! - `store_message_limit`: the reader accepts a stamped block up to the SSZ limit and refuses
//!   a response over its configured message limit;
//! - `store_stream_limits`: a streaming read refuses a stream over its configured total body
//!   count or total bytes.
//! - `store_stamp_real_server`: the stamp rule (ARCH §10 M1) against the real server over a
//!   stamped env: every served response and streamed body passes `check_read_meta` with the
//!   env's stamp; an unknown block fails NOT_FOUND, with no body.
//!
//! The target is the real server ([`StoreServer`]) over one env, seeded once per process and
//! then opened read-only: MDBX refuses a second open of one env in one process.

#[path = "../../store-schema/tests/common/mod.rs"]
mod common;

use std::sync::{Arc, OnceLock};

use cl_store::stamp::{check_read_meta, StoreReader, StreamLimits, MAX_SSZ_BYTES};
use cl_store::{Reader, StoreServer};
use ethswarm_proto::common::{Envelope, ErrorCode, Hello, PayloadType};
use ethswarm_proto::store::store_service_server::{StoreService, StoreServiceServer};
use ethswarm_proto::store::{self as pb, ReadMeta};
use ipc::frame::OutFrame;
use ipc::stub::StubStream;
use ipc::testkit::{fixture, probe, Mode, Server, Target};
use ipc::{ContractError, Link};
use network_config::ForkName;
use tonic::service::Routes;
use tonic::{Request, Response, Status};

fn target(link: Link) -> Target {
    let routes = StoreServer::new(link.clone(), Arc::clone(&seeded().reader)).routes();
    Target::new("ethswarm.store.v1", Server::new(routes), link)
        .with_probe(probe::store_get_data_columns())
}

/// The env every target serves: blocks written and stamped by store-schema's writer (cl-chain's
/// side), which then closes, and the env opened read-only.
struct Seeded {
    reader: Arc<Reader>,
    /// `(slot, root, ssz)` of every block, oldest first; one chain.
    blocks: Vec<(u64, [u8; 32], Vec<u8>)>,
    stamp: store_schema::stamp::Stamp,
    /// Kept for the process: the env lives under the target dir, not removed.
    _dir: tempfile::TempDir,
}

/// The first Fulu slot of the fixture link's schedule: the blocks get Fulu's digest.
fn fulu_start() -> u64 {
    fixture::sepolia_schedule()
        .fork_epoch(ForkName::Fulu)
        .expect("Sepolia schedules Fulu")
        * fixture::SLOTS_PER_EPOCH
}

fn seeded() -> &'static Seeded {
    static SEEDED: OnceLock<Seeded> = OnceLock::new();
    SEEDED.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("contract-env-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .expect("a temp dir");
        let mut blocks = Vec::new();
        let mut parent = [0; 32];
        for i in 0..8 {
            let slot = fulu_start() + i;
            let (ssz, root) = common::fulu_block_ssz(slot, parent, i);
            blocks.push((slot, root, ssz));
            parent = root;
        }
        let stamp = store_schema::stamp::Stamp {
            head_seq: 3,
            head_root: blocks[7].1,
            head_slot: blocks[7].0,
            finalized_root: blocks[5].1,
            finalized_slot: blocks[5].0,
        };
        {
            let writer = store_schema::env::test_writer(dir.path()).expect("the writer opens");
            let txn = store_schema::txn::begin(&writer).expect("a write txn");
            for (_, _, ssz) in &blocks {
                store_schema::blocks::put::<common::E>(&txn, &common::schedule(), ssz)
                    .expect("a block");
            }
            store_schema::txn::commit(txn, store_schema::txn::Update::New(stamp))
                .expect("the stamped commit");
        }
        let reader = Arc::new(Reader::open(dir.path()).expect("the env opens read-only"));
        Seeded {
            reader,
            blocks,
            stamp,
            _dir: dir,
        }
    })
}

/// A store peer that answers every read with `meta` as the stamp and `envelope` as the object.
#[derive(Clone)]
struct FakeStore {
    meta: Option<ReadMeta>,
    envelope: Option<Envelope>,
    hello: Hello,
    /// Bodies per streamed response.
    bodies: u64,
}

impl FakeStore {
    fn new(meta: Option<ReadMeta>, envelope: Option<Envelope>) -> Self {
        Self {
            meta,
            envelope,
            hello: fixture::hello(1, 1),
            bodies: 1,
        }
    }

    /// The same store with `bodies` bodies on every stream.
    fn streaming(self, bodies: u64) -> Self {
        Self { bodies, ..self }
    }

    /// Our hello, then the bodies, each built by `body` from the envelope at its seq.
    fn stream<M: OutFrame + Send + 'static>(
        &self,
        body: impl Fn(Option<Envelope>) -> M::Body,
    ) -> Response<StubStream<M>> {
        let mut frames = vec![Ok(M::hello(self.hello.clone()))];
        frames.extend((1..=self.bodies).map(|seq| Ok(M::body(body(self.streamed(seq))))));
        Response::new(Box::pin(tokio_stream::iter(frames)))
    }

    /// The envelope as the streamed item at `seq`.
    fn streamed(&self, seq: u64) -> Option<Envelope> {
        self.envelope.clone().map(|e| Envelope { seq, ..e })
    }
}

#[tonic::async_trait]
impl StoreService for FakeStore {
    type GetDataColumnsStream = StubStream<pb::GetDataColumnsResponse>;
    type GetBlocksByRangeStream = StubStream<pb::GetBlocksByRangeResponse>;
    type GetDataColumnsByRangeStream = StubStream<pb::GetDataColumnsByRangeResponse>;
    type GetBlocksByHeadStream = StubStream<pb::GetBlocksByHeadResponse>;

    async fn get_block(
        &self,
        _: Request<pb::GetBlockRequest>,
    ) -> Result<Response<pb::GetBlockResponse>, Status> {
        Ok(Response::new(pb::GetBlockResponse {
            block: self.envelope.clone(),
            meta: self.meta.clone(),
            error: None,
        }))
    }
    async fn get_state(
        &self,
        _: Request<pb::GetStateRequest>,
    ) -> Result<Response<pb::GetStateResponse>, Status> {
        Ok(Response::new(pb::GetStateResponse {
            state: self.envelope.clone(),
            meta: self.meta.clone(),
            ..Default::default()
        }))
    }
    async fn get_payload_envelope(
        &self,
        _: Request<pb::GetPayloadEnvelopeRequest>,
    ) -> Result<Response<pb::GetPayloadEnvelopeResponse>, Status> {
        Ok(Response::new(pb::GetPayloadEnvelopeResponse {
            envelope: self.envelope.clone(),
            meta: self.meta.clone(),
            error: None,
        }))
    }
    async fn get_chain_head(
        &self,
        _: Request<pb::GetChainHeadRequest>,
    ) -> Result<Response<pb::GetChainHeadResponse>, Status> {
        Ok(Response::new(pb::GetChainHeadResponse {
            meta: self.meta.clone(),
            ..Default::default()
        }))
    }
    async fn get_data_columns(
        &self,
        _: Request<pb::GetDataColumnsRequest>,
    ) -> Result<Response<Self::GetDataColumnsStream>, Status> {
        Ok(self.stream(|column| pb::GetDataColumnsResponseBody {
            column,
            meta: self.meta.clone(),
            error: None,
        }))
    }
    async fn get_blocks_by_range(
        &self,
        _: Request<pb::GetBlocksByRangeRequest>,
    ) -> Result<Response<Self::GetBlocksByRangeStream>, Status> {
        Ok(self.stream(|item| pb::GetBlocksByRangeResponseBody {
            item,
            meta: self.meta.clone(),
            error: None,
        }))
    }
    async fn get_data_columns_by_range(
        &self,
        _: Request<pb::GetDataColumnsByRangeRequest>,
    ) -> Result<Response<Self::GetDataColumnsByRangeStream>, Status> {
        Ok(self.stream(|column| pb::GetDataColumnsByRangeResponseBody {
            column,
            meta: self.meta.clone(),
            error: None,
        }))
    }
    async fn get_blocks_by_head(
        &self,
        _: Request<pb::GetBlocksByHeadRequest>,
    ) -> Result<Response<Self::GetBlocksByHeadStream>, Status> {
        Ok(self.stream(|block| pb::GetBlocksByHeadResponseBody {
            block,
            meta: self.meta.clone(),
            error: None,
        }))
    }
}

fn meta(seq: u64, root: usize, slot: u64) -> Option<ReadMeta> {
    Some(ReadMeta {
        as_of_seq: seq,
        as_of_root: vec![0xab; root],
        as_of_slot: slot,
        ..Default::default()
    })
}

fn full_stamp() -> Option<ReadMeta> {
    meta(7, 32, 11_289_600)
}

fn gloas_epoch() -> u64 {
    fixture::sepolia_schedule()
        .fork_epoch(ForkName::Gloas)
        .expect("Sepolia schedules Gloas")
}

/// A valid Gloas block envelope for a unary response (seq 0) with `ssz_len` bytes of SSZ.
fn block(ssz_len: usize) -> Envelope {
    let epoch = gloas_epoch();
    Envelope {
        fork_digest: fixture::digest_at(ForkName::Gloas, epoch).to_vec(),
        slot: epoch * fixture::SLOTS_PER_EPOCH,
        payload_type: PayloadType::SignedBeaconBlock as i32,
        ssz: vec![0; ssz_len],
        ..Default::default()
    }
}

/// `Ok(object present)` or the error code of one read.
type Outcome = Result<bool, ErrorCode>;

/// Every read of a reader over `store`.
async fn read_all(mode: &Mode, store: FakeStore) -> Vec<(&'static str, Outcome)> {
    let conn = mode
        .connect(Server::new(Routes::new(StoreServiceServer::new(store))))
        .await;
    let mut r = StoreReader::new(conn.transport.clone(), fixture::v1_link());
    let code = |e: ContractError| e.code();
    vec![
        (
            "GetBlock",
            r.get_block(Default::default())
                .await
                .map(|x| x.block.is_some())
                .map_err(code),
        ),
        (
            "GetState",
            r.get_state(Default::default())
                .await
                .map(|x| x.state.is_some())
                .map_err(code),
        ),
        (
            "GetPayloadEnvelope",
            r.get_payload_envelope(Default::default())
                .await
                .map(|x| x.envelope.is_some())
                .map_err(code),
        ),
        (
            "GetChainHead",
            r.get_chain_head().await.map(|_| true).map_err(code),
        ),
        (
            "GetDataColumns",
            r.get_data_columns(Default::default())
                .await
                .map(|b| b.len() == 1 && b[0].column.is_some())
                .map_err(code),
        ),
        (
            "GetBlocksByRange",
            r.get_blocks_by_range(Default::default())
                .await
                .map(|b| b.len() == 1 && b[0].item.is_some())
                .map_err(code),
        ),
        (
            "GetDataColumnsByRange",
            r.get_data_columns_by_range(Default::default())
                .await
                .map(|b| b.len() == 1 && b[0].column.is_some())
                .map_err(code),
        ),
    ]
}

async fn store_as_of_stamp(mode: Mode) {
    let cases = [
        ("full stamp", full_stamp(), true),
        ("no ReadMeta", None, false),
        ("no as_of_seq", meta(0, 32, 11_289_600), false),
        ("no as_of_root", meta(7, 0, 11_289_600), false),
        ("short as_of_root", meta(7, 31, 11_289_600), false),
        ("no as_of_slot", meta(7, 32, 0), false),
    ];
    for (what, stamp, accepted) in cases {
        for (rpc, got) in read_all(&mode, FakeStore::new(stamp, Some(block(8)))).await {
            let want = if accepted {
                Ok(true)
            } else {
                Err(ErrorCode::ContractViolation)
            };
            assert_eq!(got, want, "{rpc}, {what} ({})", mode.name());
        }
    }
}

async fn store_response_envelopes(mode: Mode) {
    let stale = Envelope {
        fork_digest: fixture::digest_at(ForkName::Fulu, gloas_epoch() - 1).to_vec(),
        ..block(8)
    };
    // (case, envelope, unary outcome, streamed outcome); `Ok(false)`: the envelope was dropped.
    let cases: [(&str, Envelope, Outcome, Outcome); 5] = [
        ("valid", block(8), Ok(true), Ok(true)),
        (
            "zero payload_type",
            Envelope {
                payload_type: 0,
                ..block(8)
            },
            Err(ErrorCode::ContractViolation),
            Err(ErrorCode::ContractViolation),
        ),
        (
            "unknown payload_type",
            Envelope {
                payload_type: 999,
                ..block(8)
            },
            Ok(false),
            Ok(false),
        ),
        ("stale fork digest", stale, Ok(false), Ok(false)),
        // A unary response carries seq 0; the streamed copy is re-numbered to 1 by the fake.
        (
            "seq 1 on a unary response",
            Envelope { seq: 1, ..block(8) },
            Err(ErrorCode::ContractViolation),
            Ok(true),
        ),
    ];
    for (what, envelope, unary, streamed) in cases {
        for (rpc, got) in
            read_all(&mode, FakeStore::new(full_stamp(), Some(envelope.clone()))).await
        {
            let want = match rpc {
                "GetChainHead" => Ok(true),
                "GetDataColumns" | "GetBlocksByRange" | "GetDataColumnsByRange" => streamed,
                _ => unary,
            };
            assert_eq!(got, want, "{rpc}, {what} ({})", mode.name());
        }
    }
}

async fn store_message_limit(mode: Mode) {
    // A block at the SSZ limit is well past tonic's 4 MiB default and still accepted.
    let store = FakeStore::new(full_stamp(), Some(block(MAX_SSZ_BYTES)));
    let conn = mode
        .connect(Server::new(Routes::new(StoreServiceServer::new(store))))
        .await;
    let mut reader = StoreReader::new(conn.transport.clone(), fixture::v1_link());
    let got = reader
        .get_block(Default::default())
        .await
        .expect("10 MiB block");
    assert_eq!(got.block.map(|b| b.ssz.len()), Some(MAX_SSZ_BYTES));

    // The limit is configurable and enforced on the encoded response.
    const LIMIT: usize = 1 << 20;
    for (ssz_len, ok) in [(LIMIT - 4096, true), (LIMIT + 1, false)] {
        let store = FakeStore::new(full_stamp(), Some(block(ssz_len)));
        let conn = mode
            .connect(Server::new(Routes::new(StoreServiceServer::new(store))))
            .await;
        let mut reader =
            StoreReader::with_max_message_bytes(conn.transport.clone(), fixture::v1_link(), LIMIT);
        let got = reader.get_block(Default::default()).await;
        assert_eq!(
            got.is_ok(),
            ok,
            "{ssz_len} bytes under a {LIMIT}-byte limit: {got:?}"
        );
        if !ok {
            assert_eq!(got.unwrap_err().code(), ErrorCode::ContractViolation);
        }
    }
}

/// The body count of each streaming read of a reader with `limits` over `store`.
async fn stream_all(
    mode: &Mode,
    store: FakeStore,
    limits: StreamLimits,
) -> Vec<(&'static str, Result<usize, ErrorCode>)> {
    let conn = mode
        .connect(Server::new(Routes::new(StoreServiceServer::new(store))))
        .await;
    let link = fixture::v1_link();
    let mut r = StoreReader::new(conn.transport.clone(), link.clone()).with_stream_limits(limits);
    let code = |e: ContractError| e.code();
    let got = vec![
        (
            "GetDataColumns",
            r.get_data_columns(Default::default())
                .await
                .map(|b| b.len())
                .map_err(code),
        ),
        (
            "GetBlocksByRange",
            r.get_blocks_by_range(Default::default())
                .await
                .map(|b| b.len())
                .map_err(code),
        ),
        (
            "GetDataColumnsByRange",
            r.get_data_columns_by_range(Default::default())
                .await
                .map(|b| b.len())
                .map_err(code),
        ),
    ];
    let refused = got.iter().filter(|(_, g)| g.is_err()).count() as u64;
    assert_eq!(link.metrics().counts().contract_violations, refused);
    got
}

async fn store_stream_limits(mode: Mode) {
    let defaults = StreamLimits::default();
    assert!(
        defaults.max_bodies >= 128 * 128,
        "a full by-range column read"
    );
    assert!(defaults.max_bytes >= 128 * MAX_SSZ_BYTES / 8);

    // The count cap: three bodies pass a cap of three, a fourth is refused.
    let count = StreamLimits {
        max_bodies: 3,
        ..defaults
    };
    for (bodies, want) in [(3, Ok(3)), (4, Err(ErrorCode::ContractViolation))] {
        let store = FakeStore::new(full_stamp(), Some(block(8))).streaming(bodies);
        for (rpc, got) in stream_all(&mode, store, count).await {
            assert_eq!(got, want, "{rpc}, {bodies} bodies ({})", mode.name());
        }
    }

    // The byte cap counts every body's encoded size: two 1,000-byte objects fit in 2,500
    // bytes, a third does not.
    let bytes = StreamLimits {
        max_bytes: 2_500,
        ..defaults
    };
    for (bodies, want) in [(2, Ok(2)), (3, Err(ErrorCode::ContractViolation))] {
        let store = FakeStore::new(full_stamp(), Some(block(1_000))).streaming(bodies);
        for (rpc, got) in stream_all(&mode, store, bytes).await {
            assert_eq!(got, want, "{rpc}, {bodies} bodies ({})", mode.name());
        }
    }
}

/// The stamp rule against the real server (see the module docs).
async fn store_stamp_real_server(mode: Mode) {
    let seeded = seeded();
    let link = fixture::v1_link();
    let routes = StoreServer::new(link.clone(), Arc::clone(&seeded.reader)).routes();
    let conn = mode.connect(Server::new(routes)).await;
    let mut r = StoreReader::new(conn.transport.clone(), link);
    let stamp = seeded.stamp;
    let full = |meta: &ReadMeta, finalized: bool| {
        assert_eq!(meta.as_of_seq, stamp.head_seq, "{}", mode.name());
        assert_eq!(meta.as_of_root, stamp.head_root, "{}", mode.name());
        assert_eq!(meta.as_of_slot, stamp.head_slot, "{}", mode.name());
        assert_eq!(meta.finalized, finalized, "{}", mode.name());
    };
    let block_id = |id| pb::GetBlockRequest {
        id: Some(pb::BlockId { id: Some(id) }),
    };
    let (head_slot, head_root, head_ssz) = seeded.blocks[7].clone();
    for (what, id, finalized) in [
        ("root", pb::block_id::Id::Root(head_root.to_vec()), false),
        ("slot", pb::block_id::Id::Slot(head_slot), false),
        ("head", pb::block_id::Id::Named("head".into()), false),
        (
            "finalized",
            pb::block_id::Id::Named("finalized".into()),
            true,
        ),
    ] {
        let got = r.get_block(block_id(id)).await.expect(what);
        full(check_read_meta(&got).expect(what), finalized);
        let block = got.block.expect(what);
        if what != "finalized" {
            assert_eq!((block.slot, &block.ssz), (head_slot, &head_ssz), "{what}");
        }
    }
    let head = r.get_chain_head().await.expect("GetChainHead");
    full(check_read_meta(&head).expect("GetChainHead"), false);
    assert_eq!(
        (head.head_slot, head.head_root.as_slice()),
        (head_slot, &head_root[..])
    );

    let range = r
        .get_blocks_by_range(pb::GetBlocksByRangeRequest {
            start_slot: seeded.blocks[0].0,
            count: 128,
            ..Default::default()
        })
        .await
        .expect("GetBlocksByRange");
    assert_eq!(range.len(), 6, "the finalized blocks");
    for body in &range {
        full(check_read_meta(body).expect("range body"), true);
    }
    let walk = r
        .get_blocks_by_head(pb::GetBlocksByHeadRequest {
            root: head_root.to_vec(),
            count: 128,
            hello: None,
        })
        .await
        .expect("GetBlocksByHead");
    assert_eq!(walk.len(), 8, "the head and every parent");
    for (body, (slot, ..)) in walk.iter().zip(seeded.blocks.iter().rev()) {
        full(
            check_read_meta(body).expect("walk body"),
            *slot <= stamp.finalized_slot,
        );
    }

    let unknown = r
        .get_block(block_id(pb::block_id::Id::Root(vec![0xee; 32])))
        .await;
    assert_eq!(unknown.unwrap_err().code(), ErrorCode::NotFound);
}

ipc::contract_suite!(target, extra: [store_as_of_stamp, store_response_envelopes, store_message_limit, store_stream_limits, store_stamp_real_server]);
