//! The `ethswarm.engine.v1` socket server: who may connect, what may be called, and what a
//! hostile or stuck peer gets.

mod common;

use cl_engine::client::{Config, EngineEndpoint};
use cl_engine::queue::Queue;
use cl_engine::server::{serve, EngineServer, Limits};
use common::{required_methods, test_secret, MockEl};
use ethswarm_proto::engine as pb;
use ethswarm_proto::engine::engine_service_client::EngineServiceClient;
use http::uri::PathAndQuery;
use hyper_util::rt::TokioIo;
use ipc::acl::{AclTables, MethodAcl};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::Code;

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

/// A NewPayload request over a raw HTTP/2 connection whose body is `sent` and then stays open:
/// what tonic's client cannot send. Returns the response status, `grpc-status`, and the body
/// sender (dropping it would end the body).
async fn open_body_request(
    path: &Path,
    sent: Vec<u8>,
) -> (
    http::StatusCode,
    Option<String>,
    tokio::sync::mpsc::Sender<Result<hyper::body::Frame<bytes::Bytes>, std::convert::Infallible>>,
) {
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
    let request = http::Request::post(format!("http://localhost{NEW_PAYLOAD}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(http_body_util::StreamBody::new(
            tokio_stream::wrappers::ReceiverStream::new(body_rx),
        ))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let in_headers = response
        .headers()
        .get("grpc-status")
        .map(|v| v.to_str().unwrap().to_owned());
    let grpc_status = match in_headers {
        Some(code) => Some(code),
        None => response
            .into_body()
            .collect()
            .await
            .ok()
            .and_then(|body| body.trailers().cloned())
            .and_then(|trailers| {
                trailers
                    .get("grpc-status")
                    .map(|v| v.to_str().unwrap().to_owned())
            }),
    };
    (status, grpc_status, body_tx)
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
