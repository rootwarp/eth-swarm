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

use cl_store::stamp::{StoreReader, StreamLimits, MAX_SSZ_BYTES};
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
    let routes = cl_store::StoreStub::new(link.clone()).routes();
    Target::new("ethswarm.store.v1", Server::new(routes), link)
        .with_probe(probe::store_get_data_columns())
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

ipc::contract_suite!(target, extra: [store_as_of_stamp, store_response_envelopes, store_message_limit, store_stream_limits]);
