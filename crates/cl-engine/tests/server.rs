//! The `ethswarm.engine.v1` socket server: who may connect, what may be called, and what a
//! hostile or stuck peer gets.

mod common;

use cl_engine::capabilities::{FORKCHOICE_UPDATED_V4, NEW_PAYLOAD_V5};
use cl_engine::client::{Config, EngineEndpoint};
use cl_engine::queue::Queue;
use cl_engine::server::{serve, EngineServer, Limits};
use common::{required_methods, test_secret, MockEl};
use ethswarm_proto::engine as pb;
use ethswarm_proto::engine::engine_service_client::EngineServiceClient;
use http::uri::PathAndQuery;
use hyper_util::rt::TokioIo;
use ipc::acl::{AclTables, MethodAcl};
use prost::Message as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Status};

const SECRET: [u8; 32] = [0x22; 32];
const NEW_PAYLOAD: &str = "/ethswarm.engine.v1.EngineService/NewPayload";

fn me() -> u32 {
    ipc::testkit::own_cred().uid()
}

/// The method ACL: `cl-chain` is `chain_uid`, allowed on `methods` only.
fn acl(chain_uid: u32, methods: &[&str]) -> Arc<MethodAcl> {
    let mut tables = AclTables::default();
    tables.callers.insert("cl-chain".into(), chain_uid);
    for method in methods {
        tables
            .methods
            .insert((*method).into(), vec!["cl-chain".into()]);
    }
    Arc::new(MethodAcl::from_tables("cl-engine", &tables).unwrap())
}

struct Running {
    mock: MockEl,
    path: PathBuf,
    _dir: tempfile::TempDir,
    _stop: oneshot::Sender<()>,
}

async fn start(acl: Arc<MethodAcl>, limits: Limits) -> Running {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let config = Config::new(EngineEndpoint::parse(&mock.url(), false).unwrap(), secret);
    let queue = Queue::connect(config, 1).await.unwrap();
    let server = EngineServer::new(ipc::testkit::fixture::v1_link(), acl, queue);
    let dir = ipc::testkit::tempdir();
    let path = dir.path().join("engine.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (stop, stopped) = oneshot::channel();
    tokio::spawn(serve(listener, server, limits, async {
        let _ = stopped.await;
    }));
    Running {
        mock,
        path,
        _dir: dir,
        _stop: stop,
    }
}

async fn channel(path: &Path) -> Channel {
    let path = path.to_path_buf();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap()
}

fn new_payload(seq: u64, data: Vec<u8>) -> pb::NewPayloadRequest {
    pb::NewPayloadRequest {
        seq,
        params: Some(pb::VersionedData {
            version: pb::EngineMethodVersion::GloasAmsterdam as i32,
            encoding: pb::PayloadEncoding::Json as i32,
            data,
        }),
        timeout_ms: 0,
    }
}

/// Whether the server closes `stream` (EOF or reset) within `within`.
async fn closed_within(stream: &mut UnixStream, within: Duration) -> bool {
    let mut buf = [0u8; 4096];
    let read = async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                // The server's own HTTP/2 preface and settings; keep reading.
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(within, read).await.is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cl_chain_reaches_the_el_over_the_socket() {
    let running = start(acl(me(), &[NEW_PAYLOAD]), Limits::default()).await;
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let reply = client
        .new_payload(new_payload(1, br#"[{"blockNumber":"0x1"}]"#.to_vec()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.seq, 1);
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert_eq!(
        reply.status.unwrap().status,
        pb::PayloadStatusKind::Valid as i32
    );
    assert_eq!(
        running
            .mock
            .seen()
            .iter()
            .filter(|seen| seen.method == "engine_newPayloadV5")
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_uid_peer_is_closed_before_anything_is_read() {
    let other = me().wrapping_add(1);
    let running = start(acl(other, &[NEW_PAYLOAD]), Limits::default()).await;
    let mut raw = UnixStream::connect(&running.path).await.unwrap();
    assert!(closed_within(&mut raw, Duration::from_secs(2)).await);

    let endpoint = Endpoint::from_static("http://[::]:50051");
    let path = running.path.clone();
    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await;
    if let Ok(channel) = channel {
        let err = EngineServiceClient::new(channel)
            .new_payload(new_payload(1, b"[{}]".to_vec()))
            .await
            .unwrap_err();
        // Closed by the server before any HTTP/2 exchange: a transport error, which tonic
        // reports as UNAVAILABLE, UNKNOWN or CANCELLED depending on when the close is seen.
        // Never a reply from the service.
        assert!(
            matches!(
                err.code(),
                Code::Unavailable | Code::Unknown | Code::Cancelled
            ),
            "{err:?}"
        );
    }
    assert!(running
        .mock
        .seen()
        .iter()
        .all(|seen| seen.method == "engine_exchangeCapabilities"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_and_unlisted_methods_are_denied_before_the_handler() {
    let running = start(acl(me(), &[NEW_PAYLOAD]), Limits::default()).await;
    let channel = channel(&running.path).await;

    // In the service, not in the ACL.
    let err = EngineServiceClient::new(channel.clone())
        .get_payload(pb::GetPayloadRequest::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");

    // Not a method of the service at all, and a near miss of a listed one: the ACL matches
    // exact paths, so neither reaches a handler (which would answer UNIMPLEMENTED).
    for path in [
        "/ethswarm.engine.v1.EngineService/Bogus",
        "/ethswarm.engine.v1.EngineService/NewPayload/",
        "/ethswarm.engine.v1.EngineService/newpayload",
    ] {
        let mut grpc = tonic::client::Grpc::new(channel.clone());
        grpc.ready().await.unwrap();
        let err = grpc
            .unary::<_, pb::NewPayloadResponse, _>(
                tonic::Request::new(new_payload(1, b"[{}]".to_vec())),
                PathAndQuery::from_static(path),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{path}: {err:?}");
    }
    assert!(running
        .mock
        .seen()
        .iter()
        .all(|seen| seen.method == "engine_exchangeCapabilities"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_frame_is_refused_from_its_length() {
    let limits = Limits {
        max_request_bytes: 1024,
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD]), limits).await;
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let mut data = b"[\"".to_vec();
    data.extend(std::iter::repeat_n(b'a', 4096));
    data.extend(b"\"]");
    let err = client.new_payload(new_payload(1, data)).await.unwrap_err();
    assert_eq!(err.code(), Code::OutOfRange, "{err:?}");
    assert!(!err.message().contains("aaaa"), "{err:?}");

    // The connection still serves a request within the limit.
    let reply = client
        .new_payload(new_payload(1, b"[{}]".to_vec()))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert_eq!(
        running
            .mock
            .seen()
            .iter()
            .filter(|seen| seen.method == "engine_newPayloadV5")
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_writer_is_closed_after_the_idle_timeout() {
    let limits = Limits {
        idle_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD]), limits).await;

    // Silent from the start.
    let mut silent = UnixStream::connect(&running.path).await.unwrap();
    // Half of the HTTP/2 client preface, then nothing.
    let mut partial = UnixStream::connect(&running.path).await.unwrap();
    partial.write_all(b"PRI * HTTP/2.0\r\n").await.unwrap();

    assert!(closed_within(&mut silent, Duration::from_secs(3)).await);
    assert!(closed_within(&mut partial, Duration::from_secs(3)).await);

    // A stalled peer does not keep others out.
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let reply = client
        .new_payload(new_payload(1, b"[{}]".to_vec()))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.error.is_none(), "{:?}", reply.error);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_over_the_cap_are_closed() {
    let limits = Limits {
        max_connections: 1,
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD]), limits).await;
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    client
        .new_payload(new_payload(1, b"[{}]".to_vec()))
        .await
        .unwrap();
    let mut second = UnixStream::connect(&running.path).await.unwrap();
    assert!(closed_within(&mut second, Duration::from_secs(2)).await);

    // Closing the first frees its slot.
    drop(client);
    let mut third = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut client = EngineServiceClient::new(channel(&running.path).await);
        if client
            .new_payload(new_payload(2, b"[{}]".to_vec()))
            .await
            .is_ok()
        {
            third = Some(client);
            break;
        }
    }
    assert!(third.is_some(), "the slot was not released");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_requests_release_their_seq() {
    const FORKCHOICE: &str = "/ethswarm.engine.v1.EngineService/ForkchoiceUpdated";
    const GET_BLOBS: &str = "/ethswarm.engine.v1.EngineService/GetBlobs";
    let running = start(
        acl(me(), &[NEW_PAYLOAD, FORKCHOICE, GET_BLOBS]),
        Limits::default(),
    )
    .await;
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    // seqs 1-4 are refused by the handlers before they reach the queue.
    let status = client
        .new_payload(new_payload(1, b"not json".to_vec()))
        .await
        .unwrap_err();
    assert_ne!(status.code(), Code::Ok);
    let mut ssz = new_payload(2, b"[]".to_vec());
    ssz.params.as_mut().unwrap().encoding = pb::PayloadEncoding::Ssz as i32;
    client.new_payload(ssz).await.unwrap_err();
    client
        .forkchoice_updated(pb::ForkchoiceUpdatedRequest {
            seq: 3,
            head_block_hash: vec![0; 4],
            ..Default::default()
        })
        .await
        .unwrap_err();
    client
        .get_blobs(pb::GetBlobsRequest {
            seq: 4,
            version: pb::EngineMethodVersion::Unspecified as i32,
            ..Default::default()
        })
        .await
        .unwrap_err();
    // seq 5 runs at once instead of waiting out the 8 s newPayload deadline behind the gap.
    let started = std::time::Instant::now();
    let reply = tokio::time::timeout(
        Duration::from_secs(3),
        client.new_payload(new_payload(5, br#"[{"blockNumber":"0x5"}]"#.to_vec())),
    )
    .await
    .expect("seq 5 waited behind refused seqs")
    .unwrap()
    .into_inner();
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert!(started.elapsed() < Duration::from_secs(1));
    let sent: Vec<Option<u64>> = running
        .mock
        .seen()
        .iter()
        .filter(|seen| seen.method != "engine_exchangeCapabilities")
        .map(|seen| seen.seq)
        .collect();
    assert_eq!(sent.len(), 1, "a refused request reached the EL");
}

const GET_BLOBS: &str = "/ethswarm.engine.v1.EngineService/GetBlobs";
const GET_PAYLOAD: &str = "/ethswarm.engine.v1.EngineService/GetPayload";
const FORKCHOICE: &str = "/ethswarm.engine.v1.EngineService/ForkchoiceUpdated";

/// What reached the EL apart from the capability exchanges.
fn sent(mock: &MockEl) -> Vec<String> {
    mock.seen()
        .into_iter()
        .filter(|seen| seen.method != "engine_exchangeCapabilities")
        .map(|seen| seen.method)
        .collect()
}

fn get_blobs(
    seq: u64,
    version: pb::EngineMethodVersion,
    hashes: Vec<Vec<u8>>,
    bits: Vec<u8>,
) -> pb::GetBlobsRequest {
    pb::GetBlobsRequest {
        seq,
        version: version as i32,
        partial: false,
        versioned_hashes: hashes,
        indices_bitarray: bits,
        timeout_ms: 0,
    }
}

/// getBlobs and getPayload requests the EL could not take (execution-apis: `payloadId` is 8
/// bytes, versioned hashes 32 bytes, at most 128 of them guaranteed, `indices_bitarray` 16
/// bytes) are refused before the queue with INVALID_ARGUMENT, release their seq, and never
/// reach the EL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_get_blobs_and_get_payload_are_refused_before_the_el() {
    use pb::EngineMethodVersion::{FuluOsaka, GloasAmsterdam};
    let running = start(
        acl(me(), &[NEW_PAYLOAD, GET_BLOBS, GET_PAYLOAD]),
        Limits::default(),
    )
    .await;
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let hash = vec![0xab; 32];
    let cases = [
        get_blobs(1, GloasAmsterdam, vec![hash.clone()], vec![0xff; 15]),
        get_blobs(2, GloasAmsterdam, vec![hash.clone()], vec![0xff; 17]),
        get_blobs(3, GloasAmsterdam, vec![hash.clone()], Vec::new()),
        get_blobs(4, FuluOsaka, vec![hash.clone(); 129], Vec::new()),
        get_blobs(5, GloasAmsterdam, vec![hash.clone(); 129], vec![0xff; 16]),
        get_blobs(6, FuluOsaka, vec![vec![0xab; 31]], Vec::new()),
        get_blobs(7, FuluOsaka, vec![hash.clone()], vec![0xff; 16]),
    ];
    for req in cases {
        let seq = req.seq;
        let err = client.get_blobs(req).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "seq {seq}: {err:?}");
    }
    for (seq, id) in [(8_u64, vec![1; 7]), (9, vec![1; 9]), (10, Vec::new())] {
        let err = client
            .get_payload(pb::GetPayloadRequest {
                seq,
                version: GloasAmsterdam as i32,
                payload_id: id,
                timeout_ms: 0,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "seq {seq}: {err:?}");
    }
    // Every refused seq was released: seq 11 runs at once.
    let reply = tokio::time::timeout(
        Duration::from_secs(3),
        client.new_payload(new_payload(11, b"[{}]".to_vec())),
    )
    .await
    .expect("seq 11 waited behind refused seqs")
    .unwrap()
    .into_inner();
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert_eq!(sent(&running.mock), ["engine_newPayloadV5"]);
}

/// A `payloadId` from the EL that is not 8 bytes (`DATA|null`, paris.md) is a malformed
/// response, reported as an error rather than passed on as a shorter id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payload_id_from_the_el_that_is_not_8_bytes_is_an_error() {
    let running = start(acl(me(), &[FORKCHOICE]), Limits::default()).await;
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let status =
        serde_json::json!({"status": "VALID", "latestValidHash": null, "validationError": null});
    running
        .mock
        .push_result(serde_json::json!({"payloadStatus": status, "payloadId": "0x0102"}));
    running.mock.push_result(
        serde_json::json!({"payloadStatus": status, "payloadId": "0x0102030405060708"}),
    );
    let request = |seq| pb::ForkchoiceUpdatedRequest {
        seq,
        head_block_hash: vec![1; 32],
        safe_block_hash: vec![2; 32],
        finalized_block_hash: vec![3; 32],
        ..Default::default()
    };
    let bad = client
        .forkchoice_updated(request(1))
        .await
        .unwrap()
        .into_inner();
    assert!(bad.payload_id.is_empty(), "{:?}", bad.payload_id);
    assert_eq!(
        bad.error.map(|err| err.kind),
        Some(pb::EngineErrorKind::Other as i32)
    );
    let good = client
        .forkchoice_updated(request(2))
        .await
        .unwrap()
        .into_inner();
    assert!(good.error.is_none(), "{:?}", good.error);
    assert_eq!(good.payload_id, [1, 2, 3, 4, 5, 6, 7, 8]);
}

/// The HTTP/2 client preface and an empty SETTINGS frame, then PING frames forever: valid
/// HTTP/2 that never makes a request.
fn no_request_bytes() -> impl Iterator<Item = u8> {
    let mut start = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    start.extend([0, 0, 0, 0x4, 0, 0, 0, 0, 0]);
    let ping = [0, 0, 8, 0x6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    start.into_iter().chain(ping.into_iter().cycle())
}

/// A permitted peer that sends one byte at a time, each well inside the idle timeout, but never
/// a request, holds a connection slot only until the first-request deadline; then the slot is
/// free for cl-chain again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trickling_peer_without_a_request_is_closed_at_the_first_request_deadline() {
    let limits = Limits {
        idle_timeout: Duration::from_millis(400),
        first_request_timeout: Duration::from_millis(800),
        max_connections: 1,
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD]), limits).await;
    let (mut read, mut write) = UnixStream::connect(&running.path)
        .await
        .unwrap()
        .into_split();
    let trickle = tokio::spawn(async move {
        // The pace of the slow peer, not a wait for the server.
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        for byte in no_request_bytes() {
            tick.tick().await;
            if write.write_all(&[byte]).await.is_err() {
                return;
            }
        }
    });
    let mut buf = [0u8; 4096];
    let closed = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    trickle.abort();
    assert!(
        closed.is_ok(),
        "a trickling peer held its slot past the deadline"
    );
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let reply = client
        .new_payload(new_payload(1, b"[{}]".to_vec()))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.error.is_none(), "{:?}", reply.error);
}

type OpenBody = http_body_util::StreamBody<
    tokio_stream::wrappers::ReceiverStream<
        Result<hyper::body::Frame<bytes::Bytes>, std::convert::Infallible>,
    >,
>;

/// Sends the rest of an [`OpenBody`]; dropping it ends the body.
type BodySender =
    tokio::sync::mpsc::Sender<Result<hyper::body::Frame<bytes::Bytes>, std::convert::Infallible>>;

/// What a request over a raw HTTP/2 connection got back.
struct RawReply {
    status: http::StatusCode,
    /// From the response headers (a trailers-only answer), else from the trailers.
    grpc_status: Option<String>,
    /// The response body: one gRPC message when the call succeeded.
    body: bytes::Bytes,
}

fn grpc_status_of(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get("grpc-status")
        .map(|v| v.to_str().unwrap().to_owned())
}

/// A request for `method` (its gRPC path) over a raw HTTP/2 connection, with `grpc_timeout` as
/// its `grpc-timeout` header when given. Its body is `sent`; with `open` the body then stays open
/// until the returned sender is dropped, else it ends there. tonic's client cannot leave a body
/// open, and it applies a `grpc-timeout` itself: only a raw request shows what the server does.
async fn raw_request(
    path: &Path,
    method: &str,
    grpc_timeout: Option<&str>,
    sent: Vec<u8>,
    open: bool,
) -> (RawReply, Option<BodySender>) {
    use http_body_util::BodyExt;
    let io = TokioIo::new(UnixStream::connect(path).await.unwrap());
    let (mut sender, conn) = hyper::client::conn::http2::handshake::<_, _, OpenBody>(
        hyper_util::rt::TokioExecutor::new(),
        io,
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    let (body_tx, body_rx) = tokio::sync::mpsc::channel(4);
    body_tx
        .send(Ok(hyper::body::Frame::data(bytes::Bytes::from(sent))))
        .await
        .unwrap();
    let body_tx = open.then_some(body_tx);
    let mut request = http::Request::post(format!("http://localhost{method}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    if let Some(value) = grpc_timeout {
        request = request.header("grpc-timeout", value);
    }
    let request = request
        .body(http_body_util::StreamBody::new(
            tokio_stream::wrappers::ReceiverStream::new(body_rx),
        ))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let (grpc_status, body) = match grpc_status_of(response.headers()) {
        Some(code) => (Some(code), bytes::Bytes::new()),
        None => match response.into_body().collect().await {
            Ok(collected) => {
                let code = collected.trailers().and_then(grpc_status_of);
                (code, collected.to_bytes())
            }
            Err(_) => (None, bytes::Bytes::new()),
        },
    };
    let reply = RawReply {
        status,
        grpc_status,
        body,
    };
    (reply, body_tx)
}

/// A NewPayload request over a raw HTTP/2 connection whose body is `sent` and then stays open:
/// what tonic's client cannot send. Returns the response status, `grpc-status`, and the body
/// sender (dropping it would end the body).
async fn open_body_request(
    path: &Path,
    sent: Vec<u8>,
) -> (http::StatusCode, Option<String>, BodySender) {
    let (reply, open) = raw_request(path, NEW_PAYLOAD, None, sent, true).await;
    (reply.status, reply.grpc_status, open.unwrap())
}

/// `message` as one uncompressed gRPC message: the flag byte, the 4-byte length, the message.
fn grpc_message(message: &impl prost::Message) -> Vec<u8> {
    let bytes = message.encode_to_vec();
    let mut framed = vec![0];
    framed.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    framed.extend(bytes);
    framed
}

/// A gRPC message prefix that declares 100 bytes, and 10 of them: a body that never finishes
/// while its sender is held.
fn unfinished_body() -> Vec<u8> {
    let mut partial = vec![0, 0, 0, 0, 100];
    partial.extend([b'['; 10]);
    partial
}

/// A gRPC message prefix that declares more than the limit, and nothing after it: refused from
/// the prefix alone (OUT_OF_RANGE), without waiting for a body that never comes, and nothing
/// reaches the EL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversize_length_prefix_alone_is_refused_without_waiting_for_the_body() {
    let limits = Limits {
        max_request_bytes: 1024,
        request_timeout: Duration::from_secs(30),
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD]), limits).await;
    // Not compressed, 1 MiB declared.
    let prefix = vec![0, 0, 0x10, 0, 0];
    let (status, grpc_status, _open) = tokio::time::timeout(
        Duration::from_secs(5),
        open_body_request(&running.path, prefix),
    )
    .await
    .expect("the server waited for the declared body");
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(grpc_status.as_deref(), Some("11"), "OUT_OF_RANGE");
    assert!(sent(&running.mock).is_empty());
}

/// A request whose body stops part way (the prefix declares 100 bytes, 10 arrive) ends at the
/// request deadline with an error status, and nothing reaches the EL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_body_that_never_finishes_ends_at_the_request_deadline() {
    let limits = Limits {
        request_timeout: Duration::from_millis(500),
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD]), limits).await;
    let mut partial = vec![0, 0, 0, 0, 100];
    partial.extend([b'['; 10]);
    let started = std::time::Instant::now();
    let (status, grpc_status, _open) = tokio::time::timeout(
        Duration::from_secs(5),
        open_body_request(&running.path, partial),
    )
    .await
    .expect("a request whose body never finishes was not ended");
    assert!(
        started.elapsed() >= Duration::from_millis(450),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(status, http::StatusCode::OK);
    assert!(
        grpc_status.as_deref().is_some_and(|code| code != "0"),
        "{grpc_status:?}"
    );
    assert!(sent(&running.mock).is_empty());
}

/// How late the EL answers in the deadline tests: past the shared request deadline they set,
/// inside the EL wait of each method (6 s and more).
const LATE_EL_ANSWER: Duration = Duration::from_millis(1500);

/// A forkchoiceUpdated request for the mock EL's VALID answer, with no payload attributes.
fn forkchoice_updated(seq: u64) -> pb::ForkchoiceUpdatedRequest {
    pb::ForkchoiceUpdatedRequest {
        seq,
        head_block_hash: vec![1; 32],
        safe_block_hash: vec![2; 32],
        finalized_block_hash: vec![3; 32],
        ..Default::default()
    }
}

/// forkchoiceUpdated has a request deadline of its own, longer than the shared one: an EL answer
/// that comes after the shared deadline, inside the EL wait, still reaches the caller. Every other
/// method keeps the shared deadline: a newPayload answer as late is cut off (`CANCELLED`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forkchoice_updated_runs_past_the_shared_request_deadline() {
    let limits = Limits {
        request_timeout: Duration::from_millis(300),
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD, FORKCHOICE]), limits).await;
    running
        .mock
        .set_method_delay("engine_forkchoiceUpdatedV4", LATE_EL_ANSWER);
    running
        .mock
        .set_method_delay("engine_newPayloadV5", LATE_EL_ANSWER);
    let status =
        serde_json::json!({"status": "VALID", "latestValidHash": null, "validationError": null});
    running
        .mock
        .push_result(serde_json::json!({"payloadStatus": status, "payloadId": null}));
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let started = std::time::Instant::now();
    let answer = client
        .forkchoice_updated(forkchoice_updated(1))
        .await
        .expect("forkchoiceUpdated was cut off at the shared request deadline")
        .into_inner();
    assert!(
        started.elapsed() >= LATE_EL_ANSWER,
        "{:?}",
        started.elapsed()
    );
    assert!(answer.error.is_none(), "{:?}", answer.error);
    assert_eq!(
        answer.status.map(|status| status.status),
        Some(pb::PayloadStatusKind::Valid as i32)
    );
    let started = std::time::Instant::now();
    let cut = client
        .new_payload(new_payload(2, br#"[{"blockNumber":"0x2"}]"#.to_vec()))
        .await
        .expect_err("newPayload ran past the shared request deadline");
    assert_eq!(cut.code(), Code::Cancelled, "{cut:?}");
    assert!(
        started.elapsed() < LATE_EL_ANSWER,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        sent(&running.mock),
        ["engine_forkchoiceUpdatedV4", "engine_newPayloadV5"]
    );
}

/// forkchoiceUpdated's own request deadline still ends a call: an EL answer later than it is cut
/// off (`CANCELLED`) at that deadline, not at the shared one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forkchoice_updated_ends_at_its_own_request_deadline() {
    let own = Duration::from_millis(800);
    let limits = Limits {
        request_timeout: Duration::from_millis(300),
        forkchoice_updated_timeout: own,
        ..Limits::default()
    };
    let running = start(acl(me(), &[FORKCHOICE]), limits).await;
    running
        .mock
        .set_method_delay("engine_forkchoiceUpdatedV4", LATE_EL_ANSWER);
    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let started = std::time::Instant::now();
    let cut = client
        .forkchoice_updated(forkchoice_updated(1))
        .await
        .expect_err("forkchoiceUpdated ran past its own request deadline");
    let elapsed = started.elapsed();
    assert_eq!(cut.code(), Code::Cancelled, "{cut:?}");
    assert!(elapsed >= own && elapsed < LATE_EL_ANSWER, "{elapsed:?}");
    assert_eq!(sent(&running.mock), ["engine_forkchoiceUpdatedV4"]);
}

/// The EL's VALID answer to a forkchoiceUpdated, with no payload.
fn forkchoice_valid() -> serde_json::Value {
    let status =
        serde_json::json!({"status": "VALID", "latestValidHash": null, "validationError": null});
    serde_json::json!({"payloadStatus": status, "payloadId": null})
}

/// A caller's `grpc-timeout` longer than the method's request deadline does not extend it: a late
/// EL answer is cut off (`CANCELLED`) at the method's deadline, not at the caller's. For
/// forkchoiceUpdated that is its own deadline, not the shared one; every other method keeps the
/// shared one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_longer_grpc_timeout_is_capped_at_the_method_deadline() {
    let shared = Duration::from_millis(300);
    let own = Duration::from_millis(800);
    let limits = Limits {
        request_timeout: shared,
        forkchoice_updated_timeout: own,
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD, FORKCHOICE]), limits).await;
    running
        .mock
        .set_method_delay(FORKCHOICE_UPDATED_V4, LATE_EL_ANSWER);
    running
        .mock
        .set_method_delay(NEW_PAYLOAD_V5, LATE_EL_ANSWER);
    let caller = Duration::from_secs(30);
    let mut client = EngineServiceClient::new(channel(&running.path).await);

    let mut request = tonic::Request::new(forkchoice_updated(1));
    request.set_timeout(caller);
    let started = std::time::Instant::now();
    let cut = client
        .forkchoice_updated(request)
        .await
        .expect_err("forkchoiceUpdated ran past its own request deadline");
    let elapsed = started.elapsed();
    assert_eq!(cut.code(), Code::Cancelled, "{cut:?}");
    assert!(elapsed >= own && elapsed < LATE_EL_ANSWER, "{elapsed:?}");

    let mut request = tonic::Request::new(new_payload(2, br#"[{"blockNumber":"0x2"}]"#.to_vec()));
    request.set_timeout(caller);
    let started = std::time::Instant::now();
    let cut = client
        .new_payload(request)
        .await
        .expect_err("newPayload ran past the shared request deadline");
    let elapsed = started.elapsed();
    assert_eq!(cut.code(), Code::Cancelled, "{cut:?}");
    assert!(elapsed >= shared && elapsed < own, "{elapsed:?}");
}

/// A caller's `grpc-timeout` shorter than the method's request deadline is honored: the call
/// ends (`CANCELLED`) at the caller's timeout, though the EL answers well inside the deadline, as
/// the same call without the header shows. Sent raw, so the server's answer is what comes back,
/// not tonic's client giving up at the same moment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shorter_grpc_timeout_ends_the_call_before_the_method_deadline() {
    let running = start(acl(me(), &[FORKCHOICE]), Limits::default()).await;
    running
        .mock
        .set_method_delay(FORKCHOICE_UPDATED_V4, LATE_EL_ANSWER);
    running.mock.push_result(forkchoice_valid());
    running.mock.push_result(forkchoice_valid());

    let started = std::time::Instant::now();
    let (answered, _) = raw_request(
        &running.path,
        FORKCHOICE,
        None,
        grpc_message(&forkchoice_updated(1)),
        false,
    )
    .await;
    assert!(
        started.elapsed() >= LATE_EL_ANSWER,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(answered.status, http::StatusCode::OK);
    assert_eq!(answered.grpc_status.as_deref(), Some("0"), "OK");
    let reply = pb::ForkchoiceUpdatedResponse::decode(&answered.body[5..]).unwrap();
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert_eq!(
        reply.status.map(|status| status.status),
        Some(pb::PayloadStatusKind::Valid as i32)
    );

    let caller = Duration::from_millis(300);
    let header = format!("{}m", caller.as_millis());
    let started = std::time::Instant::now();
    let (cut, _) = raw_request(
        &running.path,
        FORKCHOICE,
        Some(&header),
        grpc_message(&forkchoice_updated(2)),
        false,
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(cut.status, http::StatusCode::OK);
    assert_eq!(cut.grpc_status.as_deref(), Some("1"), "CANCELLED");
    assert!(elapsed >= caller && elapsed < LATE_EL_ANSWER, "{elapsed:?}");
}

/// `grpc-timeout` values that do not parse: no unit, a unit that is not one of `HMSmun`, more
/// than the eight digits the gRPC spec allows, a sign, a fraction, no digits, and no value.
const MALFORMED_GRPC_TIMEOUTS: [&str; 7] = ["15", "15s", "123456789S", "-1S", "1.5S", "S", ""];

/// A `grpc-timeout` that does not parse is the same as none: the call is served, and the
/// method's request deadline still ends it. An EL answer inside the deadline comes back; a body
/// that never finishes and an EL answer later than forkchoiceUpdated's own deadline are cut off
/// (`CANCELLED`) at the method's deadline, not sooner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_grpc_timeout_leaves_the_method_deadline_in_force() {
    let shared = Duration::from_millis(300);
    let own = Duration::from_millis(800);
    let limits = Limits {
        request_timeout: shared,
        forkchoice_updated_timeout: own,
        // One connection per raw request below, and the client's.
        max_connections: 16,
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD, FORKCHOICE]), limits).await;
    let client = EngineServiceClient::new(channel(&running.path).await);
    let with_header = |seq: u64, value: &'static str| {
        let mut request = tonic::Request::new(forkchoice_updated(seq));
        request
            .metadata_mut()
            .insert("grpc-timeout", MetadataValue::from_static(value));
        request
    };
    let mut seqs = 1..;

    for value in MALFORMED_GRPC_TIMEOUTS {
        running.mock.push_result(forkchoice_valid());
        let reply = client
            .clone()
            .forkchoice_updated(with_header(seqs.next().unwrap(), value))
            .await
            .unwrap_or_else(|err| panic!("{value:?}: {err:?}"))
            .into_inner();
        assert!(reply.error.is_none(), "{value:?}: {:?}", reply.error);
        assert_eq!(
            reply.status.map(|status| status.status),
            Some(pb::PayloadStatusKind::Valid as i32),
            "{value:?}"
        );
    }

    for value in MALFORMED_GRPC_TIMEOUTS {
        let started = std::time::Instant::now();
        let (cut, _open) = tokio::time::timeout(
            Duration::from_secs(5),
            raw_request(
                &running.path,
                NEW_PAYLOAD,
                Some(value),
                unfinished_body(),
                true,
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{value:?}: a body that never finishes was not ended"));
        let elapsed = started.elapsed();
        assert_eq!(cut.status, http::StatusCode::OK, "{value:?}");
        assert_eq!(
            cut.grpc_status.as_deref(),
            Some("1"),
            "{value:?}: CANCELLED"
        );
        assert!(elapsed >= shared && elapsed < own, "{value:?}: {elapsed:?}");
    }

    running
        .mock
        .set_method_delay(FORKCHOICE_UPDATED_V4, LATE_EL_ANSWER);
    // At once: each is cut at its own deadline, the first while the EL holds it, the rest while
    // they wait behind it.
    let calls: Vec<_> = MALFORMED_GRPC_TIMEOUTS
        .into_iter()
        .map(|value| {
            let mut client = client.clone();
            let request = with_header(seqs.next().unwrap(), value);
            tokio::spawn(async move {
                let started = std::time::Instant::now();
                let answer = client.forkchoice_updated(request).await;
                (value, started.elapsed(), answer)
            })
        })
        .collect();
    for call in calls {
        let (value, elapsed, answer) = call.await.unwrap();
        let cut = answer.expect_err("forkchoiceUpdated ran past its own request deadline");
        assert_eq!(cut.code(), Code::Cancelled, "{value:?}: {cut:?}");
        assert!(
            elapsed >= own && elapsed < LATE_EL_ANSWER,
            "{value:?}: {elapsed:?}"
        );
    }
}

/// A method the ACL does not allow, on a connection it admitted (the peer's UID is a caller), is
/// denied (`PERMISSION_DENIED`) at once: before its body is read, and not held until the method's
/// request deadline or the caller's `grpc-timeout`. Nothing reaches the EL, and the connection
/// still serves an allowed method.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_acl_denial_is_answered_at_once_not_at_the_request_deadline() {
    let deadline = Duration::from_secs(30);
    let limits = Limits {
        request_timeout: deadline,
        forkchoice_updated_timeout: deadline,
        ..Limits::default()
    };
    let running = start(acl(me(), &[NEW_PAYLOAD]), limits).await;
    running
        .mock
        .set_method_delay(FORKCHOICE_UPDATED_V4, LATE_EL_ANSWER);
    let at_once = Duration::from_secs(1);

    let header = format!("{}S", deadline.as_secs());
    let (denied, _open) = tokio::time::timeout(
        at_once,
        raw_request(
            &running.path,
            FORKCHOICE,
            Some(&header),
            unfinished_body(),
            true,
        ),
    )
    .await
    .expect("the denial waited for the body or the deadline");
    assert_eq!(denied.status, http::StatusCode::OK);
    assert_eq!(
        denied.grpc_status.as_deref(),
        Some("7"),
        "PERMISSION_DENIED"
    );

    let mut client = EngineServiceClient::new(channel(&running.path).await);
    let mut request = tonic::Request::new(forkchoice_updated(1));
    request.set_timeout(deadline);
    let err = tokio::time::timeout(at_once, client.forkchoice_updated(request))
        .await
        .expect("the denial waited for the deadline")
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied, "{err:?}");

    let reply = tokio::time::timeout(
        at_once,
        client.new_payload(new_payload(1, br#"[{"blockNumber":"0x1"}]"#.to_vec())),
    )
    .await
    .expect("the allowed call after a denial was held")
    .unwrap()
    .into_inner();
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert_eq!(sent(&running.mock), [NEW_PAYLOAD_V5]);
}

/// Holds the paused clock still until dropped, as in `tests/faults.rs`: tokio does not
/// auto-advance paused time while a blocking task runs, and without this, waiting on loopback
/// I/O would jump the clock to the next pending deadline.
struct Frozen {
    _release: std::sync::mpsc::Sender<()>,
}

fn freeze() -> Frozen {
    let (release, released) = std::sync::mpsc::channel::<()>();
    tokio::task::spawn_blocking(move || {
        // Returns once the sender is dropped.
        let _ = released.recv();
    });
    Frozen { _release: release }
}

/// Waits, with the paused clock still, until `mock` has been sent `method`: the clock is where
/// the EL's delay started.
async fn reached(mock: &MockEl, method: &str) {
    let wall = std::time::Instant::now();
    while !mock.seen().iter().any(|seen| seen.method == method) {
        assert!(
            wall.elapsed() < Duration::from_secs(10),
            "{method} never reached the EL"
        );
        tokio::task::yield_now().await;
    }
}

/// A forkchoiceUpdated on its own connection to `path` from a caller that raised its wait to
/// `wait`, as `timeout_ms` and as its `grpc-timeout`. The task returns the answer and when (on the
/// paused clock) it came.
async fn raised_forkchoice_updated(
    path: &Path,
    seq: u64,
    wait: Duration,
) -> JoinHandle<(
    Result<pb::ForkchoiceUpdatedResponse, Status>,
    tokio::time::Instant,
)> {
    let mut client = EngineServiceClient::new(channel(path).await);
    let mut request = tonic::Request::new(pb::ForkchoiceUpdatedRequest {
        timeout_ms: u32::try_from(wait.as_millis()).unwrap(),
        ..forkchoice_updated(seq)
    });
    request.set_timeout(wait);
    tokio::spawn(async move {
        let answer = client
            .forkchoice_updated(request)
            .await
            .map(tonic::Response::into_inner);
        (answer, tokio::time::Instant::now())
    })
}

/// With the default limits, a forkchoiceUpdated whose caller raised its wait past both request
/// deadlines (`timeout_ms` and `grpc-timeout`) runs past the shared deadline: an EL answer between
/// the shared deadline and forkchoiceUpdated's own comes back. It stops at its own deadline: an
/// EL answer after that never reaches the caller, and the call ends there, not at the caller's
/// longer wait. The raised EL wait is capped at that same deadline, so either ends the call at
/// that moment: the request deadline (`CANCELLED`) or the EL wait (a timeout error).
#[tokio::test(start_paused = true)]
async fn a_raised_forkchoice_updated_wait_runs_past_the_shared_deadline_up_to_its_own() {
    let _frozen = freeze();
    let limits = Limits::default();
    let (shared, own) = (limits.request_timeout, limits.forkchoice_updated_timeout);
    assert!(shared < own, "{shared:?} {own:?}");
    let raised = own + Duration::from_secs(3);
    let between = shared + (own - shared) / 2;
    let after = own + Duration::from_secs(1);
    let answers = start(acl(me(), &[FORKCHOICE]), limits).await;
    let late = start(acl(me(), &[FORKCHOICE]), limits).await;
    answers
        .mock
        .set_method_delay(FORKCHOICE_UPDATED_V4, between);
    late.mock.set_method_delay(FORKCHOICE_UPDATED_V4, after);
    answers.mock.push_result(forkchoice_valid());
    late.mock.push_result(forkchoice_valid());

    let started = tokio::time::Instant::now();
    let answered = raised_forkchoice_updated(&answers.path, 1, raised).await;
    let cut = raised_forkchoice_updated(&late.path, 1, raised).await;
    reached(&answers.mock, FORKCHOICE_UPDATED_V4).await;
    reached(&late.mock, FORKCHOICE_UPDATED_V4).await;

    // Past the shared deadline first, then to the first EL answer: a wait that stopped at the
    // shared deadline has run out before the EL answers.
    let past_shared = shared + Duration::from_millis(500);
    tokio::time::advance(past_shared).await;
    tokio::time::advance(between - past_shared).await;
    let (answer, at) = answered.await.unwrap();
    let reply = answer.expect("forkchoiceUpdated was cut off before its own request deadline");
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert_eq!(
        reply.status.map(|status| status.status),
        Some(pb::PayloadStatusKind::Valid as i32)
    );
    assert!(
        at - started > shared && at - started < own,
        "{:?}",
        at - started
    );
    assert!(!cut.is_finished(), "a call ended before its own deadline");

    tokio::time::advance(own - between).await;
    let (answer, at) = cut.await.unwrap();
    assert!(
        at - started >= own && at - started < after,
        "{:?}",
        at - started
    );
    match answer {
        Err(status) => assert_eq!(status.code(), Code::Cancelled, "{status:?}"),
        Ok(reply) => {
            assert!(
                reply.status.is_none(),
                "the late answer came back: {reply:?}"
            );
            assert_eq!(
                reply.error.map(|error| error.kind),
                Some(pb::EngineErrorKind::Timeout as i32)
            );
        }
    }
    assert_eq!(sent(&answers.mock), [FORKCHOICE_UPDATED_V4]);
    assert_eq!(sent(&late.mock), [FORKCHOICE_UPDATED_V4]);
}
