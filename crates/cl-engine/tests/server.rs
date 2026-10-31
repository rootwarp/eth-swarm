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
