//! The newPayload verdict contract: `verdict::map` of every `PayloadStatusV1`,
//! [`NewPayloadClient`] against a mock `ethswarm.engine.v1` server on a Unix socket, and the
//! per-block [`ExecutionStatuses`]. The client tests run on paused time, so the 6 s waits take
//! no wall-clock time; the concurrency tests, which wait for nothing, run on real time.

use cl_chain::engine::client::{
    EngineSeq, NewPayloadClient, NewPayloadMetrics, CALL_TIMEOUT, NEW_PAYLOAD_V5_TIMEOUT,
};
use cl_chain::engine::verdict::{self, ElVerdict, ExecutionStatus, ExecutionStatuses, Reason};
use consensus_types::gloas::{
    ExecutionPayload, ExecutionPayloadBid, ExecutionPayloadEnvelope, ExecutionRequests,
};
use consensus_types::primitives::{Address, Hash32, B256, U256};
use consensus_types::Minimal;
use engine_api::{
    new_payload_v5_params, FixedData, NewPayloadV5Params, PayloadStatusV1, ValidationStatus,
};
use ethswarm_proto::engine as pb;
use pb::engine_service_server::{EngineService, EngineServiceServer};
use pb::PayloadStatusKind as Kind;
use prometheus_client::registry::Registry;
use ssz_types::typenum::Unsigned;
use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch, Barrier};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Code, Request, Response, Status};

type E = Minimal;

fn hash(n: u8) -> Hash32 {
    Hash32::repeat_byte(n)
}

fn list<T, N: Unsigned>(items: Vec<T>) -> ProgressiveVariableList<T, N> {
    ProgressiveVariableList::new(items).expect("within the list bound")
}

/// An envelope and the bid it commits to.
struct Block {
    envelope: ExecutionPayloadEnvelope<E>,
    bid: ExecutionPayloadBid<E>,
}

impl Block {
    fn block_hash(&self) -> Hash32 {
        self.envelope.payload.block_hash
    }

    fn parent_hash(&self) -> Hash32 {
        self.envelope.payload.parent_hash
    }
}

/// The block whose payload has the hash `hash(n)` and builds on the payload `hash(parent)`.
fn block(n: u8, parent: u8) -> Block {
    let payload = ExecutionPayload::<E> {
        parent_hash: hash(parent),
        fee_recipient: Address::repeat_byte(0xab),
        state_root: B256::repeat_byte(0x33),
        receipts_root: B256::repeat_byte(0x44),
        logs_bloom: FixedVector::from_elem(0x55),
        prev_randao: B256::repeat_byte(0x66),
        block_number: u64::from(n),
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 0x6553_f100 + u64::from(n),
        extra_data: VariableList::new(b"ethswarm".to_vec()).unwrap(),
        base_fee_per_gas: U256::from(7u64),
        block_hash: hash(n),
        transactions: list(vec![]),
        withdrawals: list(vec![]),
        blob_gas_used: 0x20000,
        excess_blob_gas: 0,
        // The RLP encoding of an empty list.
        block_access_list: list(vec![0xc0]),
        slot_number: u64::from(n),
    };
    let bid = ExecutionPayloadBid {
        parent_block_hash: payload.parent_hash,
        parent_block_root: B256::repeat_byte(0xcc),
        block_hash: payload.block_hash,
        prev_randao: payload.prev_randao,
        fee_recipient: payload.fee_recipient,
        gas_limit: payload.gas_limit,
        builder_index: 3,
        slot: payload.slot_number,
        value: 0,
        execution_payment: 0,
        blob_kzg_commitments: list(vec![[0x01; 48]]),
        execution_requests_root: B256::ZERO,
    };
    let envelope = ExecutionPayloadEnvelope {
        payload,
        execution_requests: ExecutionRequests {
            deposits: list(vec![]),
            withdrawals: list(vec![]),
            consolidations: list(vec![]),
            builder_deposits: list(vec![]),
            builder_exits: list(vec![]),
        },
        builder_index: 3,
        beacon_block_root: B256::repeat_byte(n ^ 0xbb),
        parent_beacon_block_root: B256::repeat_byte(0xaa),
    };
    Block { envelope, bid }
}

/// What the mock does with one call.
#[derive(Clone, Debug)]
enum Answer {
    /// A response with this status and error, for the request's `seq` (or another one).
    Response {
        status: Option<pb::PayloadStatus>,
        error: Option<pb::EngineErrorKind>,
        other_seq: bool,
    },
    /// A gRPC status.
    Rpc(Code),
    /// No answer, ever: a stalled cl-engine.
    Stall,
}

fn raw(status: pb::PayloadStatus) -> Answer {
    Answer::Response {
        status: Some(status),
        error: None,
        other_seq: false,
    }
}

fn status(kind: Kind, latest_valid_hash: Option<Hash32>) -> Answer {
    raw(pb::PayloadStatus {
        status: kind as i32,
        latest_valid_hash: latest_valid_hash.map_or_else(Vec::new, |h| h.to_vec()),
        validation_error: String::new(),
    })
}

fn engine_error(kind: pb::EngineErrorKind) -> Answer {
    Answer::Response {
        status: None,
        error: Some(kind),
        other_seq: false,
    }
}

/// A mock engine.v1 server: it records each `NewPayload` request and gives the next scripted
/// answer after its delay. With `together`, it answers no request before that many are in
/// flight.
#[derive(Clone, Default)]
struct MockEngine {
    script: Arc<Mutex<VecDeque<(Duration, Answer)>>>,
    seen: Arc<Mutex<Vec<pb::NewPayloadRequest>>>,
    together: Option<Arc<Barrier>>,
}

impl MockEngine {
    fn answer(&self, after: Duration, answer: Answer) {
        self.script.lock().unwrap().push_back((after, answer));
    }

    fn seen(&self) -> Vec<pb::NewPayloadRequest> {
        self.seen.lock().unwrap().clone()
    }
}

#[tonic::async_trait]
impl EngineService for MockEngine {
    async fn new_payload(
        &self,
        request: Request<pb::NewPayloadRequest>,
    ) -> Result<Response<pb::NewPayloadResponse>, Status> {
        let req = request.into_inner();
        self.seen.lock().unwrap().push(req.clone());
        let next = self.script.lock().unwrap().pop_front();
        let Some((after, answer)) = next else {
            return Err(Status::internal("mock: no scripted answer"));
        };
        if let Some(together) = &self.together {
            together.wait().await;
        }
        tokio::time::sleep(after).await;
        match answer {
            Answer::Response {
                status,
                error,
                other_seq,
            } => Ok(Response::new(pb::NewPayloadResponse {
                seq: if other_seq { req.seq + 1 } else { req.seq },
                status,
                error: error.map(|kind| pb::EngineError {
                    kind: kind as i32,
                    rpc_code: 0,
                    message: "mock".to_owned(),
                }),
            })),
            Answer::Rpc(code) => Err(Status::new(code, "mock")),
            Answer::Stall => std::future::pending().await,
        }
    }

    async fn forkchoice_updated(
        &self,
        _: Request<pb::ForkchoiceUpdatedRequest>,
    ) -> Result<Response<pb::ForkchoiceUpdatedResponse>, Status> {
        Err(Status::unimplemented("mock"))
    }

    async fn get_payload(
        &self,
        _: Request<pb::GetPayloadRequest>,
    ) -> Result<Response<pb::GetPayloadResponse>, Status> {
        Err(Status::unimplemented("mock"))
    }

    async fn get_blobs(
        &self,
        _: Request<pb::GetBlobsRequest>,
    ) -> Result<Response<pb::GetBlobsResponse>, Status> {
        Err(Status::unimplemented("mock"))
    }

    async fn exchange_capabilities(
        &self,
        _: Request<pb::ExchangeCapabilitiesRequest>,
    ) -> Result<Response<pb::ExchangeCapabilitiesResponse>, Status> {
        Err(Status::unimplemented("mock"))
    }
}

/// Serves `mock` on `path` until the test's runtime ends.
fn serve(path: &Path, mock: MockEngine) -> JoinHandle<Result<(), tonic::transport::Error>> {
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let routes = tonic::service::Routes::new(EngineServiceServer::new(mock));
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        routes,
        std::future::pending(),
    ))
}

fn uid() -> u32 {
    ipc::uds::Ownership::current().uid
}

/// Serves `mock` on `path` through its own accept loop, which admits connections the way
/// cl-engine does: once `cap` connections are served, one more is closed on accept, unread.
/// Gives the number of connections accepted so far, the closed ones included. No served
/// connection closes during a test, so those admitted are the ones served at once.
fn serve_counted(path: &Path, mock: MockEngine, cap: Option<usize>) -> watch::Receiver<usize> {
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let (accepted_tx, accepted) = watch::channel(0);
    let (admit, admitted) = mpsc::channel::<std::io::Result<tokio::net::UnixStream>>(1);
    tokio::spawn(async move {
        let mut served = 0;
        while let Ok((stream, _)) = listener.accept().await {
            accepted_tx.send_modify(|n| *n += 1);
            if cap.is_some_and(|cap| served >= cap) {
                drop(stream);
                continue;
            }
            served += 1;
            if admit.send(Ok(stream)).await.is_err() {
                return;
            }
        }
    });
    let routes = tonic::service::Routes::new(EngineServiceServer::new(mock));
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_routes(routes)
            .serve_with_incoming(ReceiverStream::new(admitted)),
    );
    accepted
}

/// cl-engine's default cap on the connections it serves at once.
const ENGINE_CONNECTIONS: usize = 4;

/// The calls that start together in the concurrency tests.
const CALLERS: usize = 4;

/// `CALLERS` newPayload calls, each of its own block, that start together on a new client of
/// `path` (so with no connection yet); `mock` answers each VALID.
async fn concurrent_calls(path: &Path, mock: &MockEngine) -> Vec<ElVerdict> {
    let client = Arc::new(NewPayloadClient::new(
        path,
        uid(),
        EngineSeq::new(),
        NewPayloadMetrics::default(),
    ));
    let start = Arc::new(Barrier::new(CALLERS));
    let calls: Vec<_> = (1..=CALLERS as u8)
        .map(|n| {
            mock.answer(Duration::ZERO, status(Kind::Valid, Some(hash(n))));
            let (client, start) = (Arc::clone(&client), Arc::clone(&start));
            tokio::spawn(async move {
                let block = block(n, n - 1);
                start.wait().await;
                client.new_payload(&block.envelope, &block.bid).await
            })
        })
        .collect();
    let mut verdicts = Vec::new();
    for call in calls {
        verdicts.push(call.await.unwrap());
    }
    verdicts
}

/// A mock server on a fresh socket and a client of it.
struct Setup {
    dir: tempfile::TempDir,
    mock: MockEngine,
    client: NewPayloadClient,
    seq: EngineSeq,
    metrics: NewPayloadMetrics,
    registry: Registry,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let mock = MockEngine::default();
    serve(&path, mock.clone());
    let mut registry = Registry::default();
    let metrics = NewPayloadMetrics::register(&mut registry);
    let seq = EngineSeq::new();
    let client = NewPayloadClient::new(&path, uid(), seq.clone(), metrics.clone());
    Setup {
        dir,
        mock,
        client,
        seq,
        metrics,
        registry,
    }
}

impl Setup {
    /// Sends `block` with `answer` scripted after `after`.
    async fn send(&self, block: &Block, after: Duration, answer: Answer) -> ElVerdict {
        self.mock.answer(after, answer);
        self.client.new_payload(&block.envelope, &block.bid).await
    }
}

/// Every row of the verdict table: each `PayloadStatusV1` through `verdict::map` and, as JSON,
/// through `verdict::map_json`; JSON that names no known status; and each engine.v1 answer
/// (the five statuses, an unknown and an unspecified one, a timeout, engine errors and a
/// transport error) through `NewPayloadClient::new_payload`, whose requests carry the V5
/// params of the envelope and its bid.
#[tokio::test(start_paused = true)]
async fn status_table() {
    let lvh = hash(0x40);
    let v1 = |status, latest_valid_hash: Option<Hash32>| PayloadStatusV1 {
        status,
        latest_valid_hash: latest_valid_hash.map(|h| FixedData(h.0)),
        validation_error: None,
    };
    let invalid = |latest_valid_hash| ElVerdict::Invalid { latest_valid_hash };
    let rows = [
        (v1(ValidationStatus::Valid, Some(hash(1))), ElVerdict::Valid),
        (v1(ValidationStatus::Invalid, Some(lvh)), invalid(Some(lvh))),
        (v1(ValidationStatus::Invalid, None), invalid(None)),
        (
            v1(ValidationStatus::InvalidBlockHash, Some(lvh)),
            invalid(Some(lvh)),
        ),
        (v1(ValidationStatus::InvalidBlockHash, None), invalid(None)),
        (v1(ValidationStatus::Syncing, None), ElVerdict::Optimistic),
        (v1(ValidationStatus::Accepted, None), ElVerdict::Optimistic),
    ];
    for (status, want) in &rows {
        assert_eq!(verdict::map(status), *want, "{status:?}");
        let json = serde_json::to_vec(status).unwrap();
        assert_eq!(verdict::map_json(&json), *want, "{status:?} as JSON");
        let with_error = PayloadStatusV1 {
            validation_error: Some("mock".to_owned()),
            ..status.clone()
        };
        assert_eq!(verdict::map(&with_error), *want, "{with_error:?}");
    }
    // A status this version does not define, or none at all: never VALID.
    for json in [
        r#"{"status":"UNKNOWN","latestValidHash":null,"validationError":null}"#,
        r#"{"status":"valid","latestValidHash":null,"validationError":null}"#,
        r#"{"status":"VALID_PENDING"}"#,
        r#"{"status":null}"#,
        r#"{"status":1}"#,
        r#"{"latestValidHash":null}"#,
        "not json",
    ] {
        assert_eq!(
            verdict::map_json(json.as_bytes()),
            ElVerdict::NotVerified(Reason::UnknownStatus),
            "{json}"
        );
    }
    // A known status with a field that does not decode: never VALID either.
    for json in [
        r#"{"status":"VALID","latestValidHash":"0x01"}"#,
        r#"{"status":"INVALID","latestValidHash":"77"}"#,
    ] {
        assert_eq!(
            verdict::map_json(json.as_bytes()),
            ElVerdict::NotVerified(Reason::Malformed),
            "{json}"
        );
    }

    let s = setup();
    let not_verified = ElVerdict::NotVerified;
    let wire = [
        (status(Kind::Valid, Some(hash(1))), ElVerdict::Valid),
        (status(Kind::Invalid, Some(lvh)), invalid(Some(lvh))),
        (status(Kind::Invalid, None), invalid(None)),
        (
            status(Kind::InvalidBlockHash, Some(lvh)),
            invalid(Some(lvh)),
        ),
        (status(Kind::InvalidBlockHash, None), invalid(None)),
        (status(Kind::Syncing, None), ElVerdict::Optimistic),
        (status(Kind::Accepted, None), ElVerdict::Optimistic),
        (
            raw(pb::PayloadStatus {
                status: 99,
                ..Default::default()
            }),
            not_verified(Reason::UnknownStatus),
        ),
        (
            status(Kind::Unspecified, None),
            not_verified(Reason::Malformed),
        ),
        (
            raw(pb::PayloadStatus {
                status: Kind::Valid as i32,
                latest_valid_hash: vec![1; 31],
                validation_error: String::new(),
            }),
            not_verified(Reason::Malformed),
        ),
        (
            Answer::Response {
                status: None,
                error: None,
                other_seq: false,
            },
            not_verified(Reason::Malformed),
        ),
        (
            Answer::Response {
                status: status_of(Kind::Valid),
                error: None,
                other_seq: true,
            },
            not_verified(Reason::Malformed),
        ),
        (
            Answer::Response {
                status: status_of(Kind::Valid),
                error: Some(pb::EngineErrorKind::Other),
                other_seq: false,
            },
            not_verified(Reason::Engine(pb::EngineErrorKind::Other as i32)),
        ),
        (
            engine_error(pb::EngineErrorKind::Timeout),
            not_verified(Reason::Engine(pb::EngineErrorKind::Timeout as i32)),
        ),
        (
            engine_error(pb::EngineErrorKind::ElUnreachable),
            not_verified(Reason::Engine(pb::EngineErrorKind::ElUnreachable as i32)),
        ),
        (
            Answer::Rpc(Code::Unavailable),
            not_verified(Reason::Rpc(Code::Unavailable)),
        ),
        (
            Answer::Rpc(Code::InvalidArgument),
            not_verified(Reason::Rpc(Code::InvalidArgument)),
        ),
        (Answer::Stall, not_verified(Reason::Timeout)),
    ];
    let calls = wire.len();
    let block = block(1, 0);
    for (answer, want) in wire {
        let got = s.send(&block, Duration::ZERO, answer.clone()).await;
        assert_eq!(got, want, "{answer:?}");
    }

    // Each call is one engine_newPayloadV5 request with the next shared `seq`.
    let seen = s.mock.seen();
    assert_eq!(seen.len(), calls);
    let params: NewPayloadV5Params = new_payload_v5_params(&block.envelope, &block.bid);
    for (i, req) in seen.iter().enumerate() {
        assert_eq!(req.seq, i as u64 + 1);
        assert_eq!(req.timeout_ms, 0);
        let data = req.params.as_ref().expect("params");
        assert_eq!(data.version, pb::EngineMethodVersion::GloasAmsterdam as i32);
        assert_eq!(data.encoding, pb::PayloadEncoding::Json as i32);
        let sent: NewPayloadV5Params = serde_json::from_slice(&data.data).unwrap();
        assert_eq!(sent, params);
    }
    assert_eq!(s.seq.next(), calls as u64 + 1);
}

fn status_of(kind: Kind) -> Option<pb::PayloadStatus> {
    Some(pb::PayloadStatus {
        status: kind as i32,
        latest_valid_hash: hash(1).to_vec(),
        validation_error: String::new(),
    })
}

/// A VALID just under the 6 s floor is taken. cl-engine's own 6 s timeout, a cl-engine that
/// never answers, and a VALID that comes after the client gave up are all `NotVerified`,
/// never permit the import and record nothing. The client never gives up before the floor,
/// and never shortens cl-engine's wait (`timeout_ms` 0).
#[tokio::test(start_paused = true)]
async fn timeout_never_valid() {
    let s = setup();
    let mut statuses = ExecutionStatuses::new();
    let first = block(1, 0);
    let just_under = NEW_PAYLOAD_V5_TIMEOUT - Duration::from_millis(1);
    let start = Instant::now();
    let verdict = s
        .send(&first, just_under, status(Kind::Valid, Some(hash(1))))
        .await;
    assert_eq!(verdict, ElVerdict::Valid);
    assert!(start.elapsed() >= just_under, "{:?}", start.elapsed());

    let block = block(2, 1);
    let unverified = [
        // cl-engine's wait for the EL ran out at 6 s.
        (
            NEW_PAYLOAD_V5_TIMEOUT,
            engine_error(pb::EngineErrorKind::Timeout),
            Reason::Engine(pb::EngineErrorKind::Timeout as i32),
        ),
        // cl-engine never answers.
        (Duration::ZERO, Answer::Stall, Reason::Timeout),
        // The VALID comes after the client gave up.
        (
            CALL_TIMEOUT + Duration::from_secs(1),
            status(Kind::Valid, Some(hash(2))),
            Reason::Timeout,
        ),
    ];
    for (after, answer, reason) in unverified {
        let start = Instant::now();
        let verdict = s.send(&block, after, answer.clone()).await;
        let waited = start.elapsed();
        assert_eq!(verdict, ElVerdict::NotVerified(reason), "{answer:?}");
        assert!(!verdict.permits_payload_import());
        assert!(waited >= NEW_PAYLOAD_V5_TIMEOUT, "{answer:?}: {waited:?}");
        assert_eq!(
            statuses.record(block.block_hash(), block.parent_hash(), &verdict),
            None
        );
        assert_eq!(statuses.status(&block.block_hash()), None);
    }
    for req in s.mock.seen() {
        assert_eq!(req.timeout_ms, 0, "seq {}", req.seq);
    }
}

/// SYNCING and ACCEPTED leave a chain of payloads optimistic. A later VALID for one of them
/// makes it and every optimistic ancestor VALID, walking the recorded parent hashes; its
/// descendant and a sibling stay optimistic, and an INVALID ancestor stops the walk.
#[tokio::test(start_paused = true)]
async fn optimistic_then_valid() {
    use ExecutionStatus::{Invalid, Optimistic, Valid};
    let s = setup();
    let mut statuses = ExecutionStatuses::new();
    // 10 <- 11 <- 12 <- 13, and 14 on 11 beside 12.
    let chain = [
        (10, 9, Kind::Valid),
        (11, 10, Kind::Syncing),
        (12, 11, Kind::Accepted),
        (13, 12, Kind::Syncing),
        (14, 11, Kind::Syncing),
    ];
    for (n, parent, kind) in chain {
        let block = block(n, parent);
        let lvh = (kind == Kind::Valid).then(|| hash(n));
        let verdict = s.send(&block, Duration::ZERO, status(kind, lvh)).await;
        statuses.record(block.block_hash(), block.parent_hash(), &verdict);
    }
    let all =
        |statuses: &ExecutionStatuses| [10, 11, 12, 13, 14].map(|n| statuses.status(&hash(n)));
    assert_eq!(
        all(&statuses),
        [
            Some(Valid),
            Some(Optimistic),
            Some(Optimistic),
            Some(Optimistic),
            Some(Optimistic)
        ]
    );

    let twelve = block(12, 11);
    let verdict = s
        .send(&twelve, Duration::ZERO, status(Kind::Valid, Some(hash(12))))
        .await;
    assert_eq!(verdict, ElVerdict::Valid);
    assert_eq!(
        statuses.record(twelve.block_hash(), twelve.parent_hash(), &verdict),
        Some(Valid)
    );
    assert_eq!(
        all(&statuses),
        [
            Some(Valid),
            Some(Valid),
            Some(Valid),
            Some(Optimistic),
            Some(Optimistic)
        ]
    );

    let thirteen = block(13, 12);
    let verdict = s
        .send(
            &thirteen,
            Duration::ZERO,
            status(Kind::Valid, Some(hash(13))),
        )
        .await;
    statuses.record(thirteen.block_hash(), thirteen.parent_hash(), &verdict);
    assert_eq!(
        all(&statuses),
        [
            Some(Valid),
            Some(Valid),
            Some(Valid),
            Some(Valid),
            Some(Optimistic)
        ]
    );

    // 20 is INVALID, 21 and 22 optimistic on it: a VALID for 22 stops at 20.
    let invalid = ElVerdict::Invalid {
        latest_valid_hash: Some(hash(19)),
    };
    statuses.record(hash(20), hash(19), &invalid);
    statuses.record(hash(21), hash(20), &ElVerdict::Optimistic);
    statuses.record(hash(22), hash(21), &ElVerdict::Optimistic);
    statuses.record(hash(22), hash(21), &ElVerdict::Valid);
    assert_eq!(
        [20, 21, 22].map(|n| statuses.status(&hash(n))),
        [Some(Invalid), Some(Valid), Some(Valid)]
    );
}

/// `Optimistic` permits the import and records `ExecutionStatus::Optimistic`, as `Valid` does
/// `Valid`. `Invalid` and every `NotVerified` (a timeout, a transport error, an unknown status,
/// no connection) never permit it: INVALID replaces an optimistic status and later SYNCING or
/// VALID do not undo it; a NotVerified records nothing and leaves an earlier status as it was.
#[tokio::test(start_paused = true)]
async fn optimistic_permits_import() {
    use ExecutionStatus::{Invalid, Optimistic};
    assert!(ElVerdict::Valid.permits_payload_import());
    assert!(ElVerdict::Optimistic.permits_payload_import());
    let refused = [
        ElVerdict::Invalid {
            latest_valid_hash: Some(hash(1)),
        },
        ElVerdict::Invalid {
            latest_valid_hash: None,
        },
        ElVerdict::NotVerified(Reason::UnknownStatus),
        ElVerdict::NotVerified(Reason::Malformed),
        ElVerdict::NotVerified(Reason::Engine(pb::EngineErrorKind::Timeout as i32)),
        ElVerdict::NotVerified(Reason::Rpc(Code::Unavailable)),
        ElVerdict::NotVerified(Reason::Timeout),
        ElVerdict::NotVerified(Reason::Connect),
    ];
    for verdict in refused {
        assert!(!verdict.permits_payload_import(), "{verdict:?}");
    }

    let s = setup();
    let mut statuses = ExecutionStatuses::new();
    let (one, two, three) = (block(1, 0), block(2, 1), block(3, 2));
    for (block, kind) in [(&one, Kind::Syncing), (&two, Kind::Accepted)] {
        let verdict = s.send(block, Duration::ZERO, status(kind, None)).await;
        assert_eq!(verdict, ElVerdict::Optimistic);
        assert!(verdict.permits_payload_import());
        assert_eq!(
            statuses.record(block.block_hash(), block.parent_hash(), &verdict),
            Some(Optimistic)
        );
    }

    let unknown = raw(pb::PayloadStatus {
        status: 99,
        ..Default::default()
    });
    let no_verdict = [Answer::Stall, Answer::Rpc(Code::Unavailable), unknown];
    for answer in &no_verdict {
        let verdict = s.send(&three, Duration::ZERO, answer.clone()).await;
        assert!(matches!(verdict, ElVerdict::NotVerified(_)), "{verdict:?}");
        assert!(!verdict.permits_payload_import(), "{verdict:?}");
        assert_eq!(
            statuses.record(three.block_hash(), three.parent_hash(), &verdict),
            None
        );
        // Already optimistic: still optimistic, never VALID.
        let verdict = s.send(&one, Duration::ZERO, answer.clone()).await;
        assert!(!verdict.permits_payload_import(), "{verdict:?}");
        assert_eq!(
            statuses.record(one.block_hash(), one.parent_hash(), &verdict),
            Some(Optimistic)
        );
    }

    let verdict = s
        .send(&two, Duration::ZERO, status(Kind::Invalid, Some(hash(1))))
        .await;
    assert_eq!(
        verdict,
        ElVerdict::Invalid {
            latest_valid_hash: Some(hash(1))
        }
    );
    assert!(!verdict.permits_payload_import());
    assert_eq!(
        statuses.record(two.block_hash(), two.parent_hash(), &verdict),
        Some(Invalid)
    );
    for later in [ElVerdict::Optimistic, ElVerdict::Valid] {
        assert_eq!(
            statuses.record(two.block_hash(), two.parent_hash(), &later),
            Some(Invalid)
        );
    }
    assert_eq!(statuses.status(&one.block_hash()), Some(Optimistic));

    // No cl-engine on the socket.
    let gone = NewPayloadClient::new(
        s.dir.path().join("absent.sock"),
        uid(),
        s.seq.clone(),
        s.metrics.clone(),
    );
    let verdict = gone.new_payload(&three.envelope, &three.bid).await;
    assert_eq!(verdict, ElVerdict::NotVerified(Reason::Connect));
    assert!(!verdict.permits_payload_import());

    assert_eq!(s.metrics.verdicts("optimistic"), 2);
    assert_eq!(s.metrics.verdicts("not_verified"), 7);
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &s.registry).unwrap();
    for line in [
        "chain_new_payload_verdicts_total{verdict=\"valid\"} 0",
        "chain_new_payload_verdicts_total{verdict=\"invalid\"} 1",
        "chain_new_payload_verdicts_total{verdict=\"optimistic\"} 2",
        "chain_new_payload_verdicts_total{verdict=\"not_verified\"} 7",
    ] {
        assert!(text.contains(line), "{line} in\n{text}");
    }
}

/// Calls that start together on a client with no connection open one between them: the server
/// accepts exactly one connection, not one per call, and all the calls are in flight on it at
/// once (the mock answers none before all are), each answered VALID.
#[tokio::test]
async fn concurrent_cold_starts_share_one_connection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let mock = MockEngine {
        together: Some(Arc::new(Barrier::new(CALLERS))),
        ..MockEngine::default()
    };
    let accepted = serve_counted(&path, mock.clone(), None);

    let verdicts = concurrent_calls(&path, &mock).await;
    assert_eq!(verdicts, [ElVerdict::Valid; CALLERS]);
    assert_eq!(mock.seen().len(), CALLERS);
    assert_eq!(*accepted.borrow(), 1, "connections accepted");
}

/// cl-engine serves four connections at once and closes one more on accept. With one of them
/// taken (a channel held open, as the forkchoiceUpdated sender holds one), calls that start
/// together on a new client still all get VALID: they share one more connection, so none is
/// refused one, and no fifth connection is opened.
#[tokio::test]
async fn a_capped_server_still_serves_concurrent_calls() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let mock = MockEngine::default();
    let mut accepted = serve_counted(&path, mock.clone(), Some(ENGINE_CONNECTIONS));
    let held = ipc::uds::connect_path(&path, uid()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), accepted.wait_for(|n| *n == 1))
        .await
        .expect("the held connection is accepted")
        .unwrap();

    let verdicts = concurrent_calls(&path, &mock).await;
    let opened = *accepted.borrow();
    assert_eq!(
        verdicts,
        [ElVerdict::Valid; CALLERS],
        "connections accepted: {opened}"
    );
    assert_eq!(
        opened, 2,
        "connections accepted: the held one and one shared"
    );
    drop(held);
}
