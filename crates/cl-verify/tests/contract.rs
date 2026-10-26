//! The ipc contract suite against cl-verify: every rule in process and over a Unix socket, plus
//! the builder key feed rules ([`builder_key_feed_rules`]) both ways.
//!
//! cl-verify serves only cl-chain's UID. Over UDS the kernel supplies this process's
//! credentials; in process, where no socket exists, the same credentials (read once from a
//! socket pair) are attached to each request. The UID rule itself is not part of the suite.

mod common;

use std::sync::{Arc, OnceLock};

use cl_verify::bls::BlstBackend;
use cl_verify::feed::SharedCache;
use cl_verify::handshake::Handshake;
use cl_verify::kzg::{KzgBackend, KzgFailure, PreparedCells, TrustedSetupConfig};
use cl_verify::proto::common::{ErrorCode, Hello};
use cl_verify::proto::verify::verify_service_client::VerifyServiceClient;
use cl_verify::proto::verify::{
    builder_key_feed_response, verify_bls_response, BuilderKeyFeedRequest,
    BuilderKeyFeedRequestBody, BuilderKeyFeedResponse, KeyNamespace, VerifyBlsRequest,
    VerifyBlsRequestBody, VerifyBlsResponse, VerifyOrigin, VerifyStatus,
};
use cl_verify::server::{serve_uds, Limits, ServerConfig, VerifyServer, DEFAULT_SNAPSHOT_INTERVAL};
use cl_verify::wire::error_from_status;
use common::{
    bls_body, bls_hello, builder_body, builder_frame, builder_hello, builder_set, builder_signer,
    far_deadline, outcomes,
};
use ipc::testkit::{fixture, probe, Mode, Server, Target};
use ipc::Link;
use tokio::net::unix::UCred;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::service::Routes;
use tonic::transport::server::UdsConnectInfo;

/// The suite never sends KZG work; a verifier that refuses everything keeps the trusted setup
/// out of these tests.
struct NoKzg;

impl KzgBackend for NoKzg {
    fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
        Ok(false)
    }
}

/// This process's credentials, from a connected socket pair.
fn my_cred() -> UCred {
    static CRED: OnceLock<UCred> = OnceLock::new();
    *CRED.get_or_init(|| {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        a.set_nonblocking(true).expect("nonblocking");
        tokio::net::UnixStream::from_std(a)
            .expect("inside the test runtime")
            .peer_cred()
            .expect("peer credentials")
    })
}

/// The one place the suite builds a cl-verify server config. The pubkey snapshot lives in
/// `snapshot_dir`, a temp dir the target keeps alive; the suite never opens PubkeyFeed, so
/// nothing is restored or saved there.
fn server_config(link: &Link, snapshot_dir: &tempfile::TempDir) -> ServerConfig {
    ServerConfig {
        handshake: Handshake::new(link.local(), link.floor()),
        peer_uid: my_cred().uid(),
        // Not loaded: the server gets the backends below.
        trusted_setup: TrustedSetupConfig {
            path: "unused-by-the-contract-suite".into(),
        },
        limits: Limits::default(),
        pubkey_snapshot: snapshot_dir.path().join("pubkeys.bin"),
        snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
    }
}

fn verify_server(link: &Link, snapshot_dir: &tempfile::TempDir) -> VerifyServer {
    VerifyServer::with_backends(
        server_config(link, snapshot_dir),
        SharedCache::default(),
        Arc::new(BlstBackend),
        Arc::new(NoKzg),
    )
}

/// `server` as the testkit serves it: called directly in process (with this process's
/// credentials), or through `serve_uds` on a Unix socket.
fn served(server: VerifyServer) -> Server {
    let on_uds = server.clone();
    Server::new(Routes::new(server.into_service()))
        .with_in_process_extensions(|ext| {
            ext.insert(UdsConnectInfo {
                peer_addr: None,
                peer_cred: Some(my_cred()),
            });
        })
        .with_uds_server(Arc::new(move |listener, stop| {
            let server = on_uds.clone();
            Box::pin(async move {
                let _ = serve_uds(listener, server, async {
                    let _ = stop.await;
                })
                .await;
            })
        }))
}

fn target(link: Link) -> Target {
    let snapshot_dir = Arc::new(tempfile::tempdir().expect("snapshot dir"));
    let server = verify_server(&link, &snapshot_dir);
    let counted = server.clone();
    Target::new("ethswarm.verify.v1", served(server), link)
        .with_probe(probe::verify_bls())
        .with_violation_counter(move || {
            let _keep = &snapshot_dir;
            counted.contract_violations()
        })
}

/// The builder key feed and the builder namespace of VerifyBls, `mode` either way: the first
/// response reports the builder high-water mark, a zero or validator namespace on a feed frame and
/// a gap are in-band contract violations that apply nothing, a fed builder resolves as a builder
/// only with its full key, and a zero signer namespace fails the VerifyBls stream.
async fn builder_key_feed_rules(mode: Mode) {
    let link = fixture::v1_link();
    let dir = tempfile::tempdir().expect("snapshot dir");
    let server = verify_server(&link, &dir);
    let connection = mode.connect(served(server.clone())).await;
    let mut client = VerifyServiceClient::new(connection.transport.clone());

    let (feed, mut replies) = open_builder_feed(&mut client, link.local()).await;
    let send = |frame: BuilderKeyFeedRequestBody| {
        let feed = feed.clone();
        async move { feed.send(builder_body(frame)).await.expect("feed open") }
    };
    assert_eq!(
        next_builder_reply(&mut replies).await,
        (0, None),
        "first response"
    );
    let mut zero = builder_frame(0, [0]);
    zero.namespace = KeyNamespace::Unspecified as i32;
    let mut validator = builder_frame(0, [0]);
    validator.namespace = KeyNamespace::Validator as i32;
    for refused in [zero, validator, builder_frame(1, [1])] {
        send(refused).await;
        assert_eq!(
            next_builder_reply(&mut replies).await,
            (0, Some(ErrorCode::ContractViolation))
        );
    }
    assert_eq!(server.contract_violations(), 3);
    send(builder_frame(0, 0..2)).await;
    assert_eq!(next_builder_reply(&mut replies).await, (2, None));

    let (bls, mut results, generation) = open_bls(&mut client, link.local()).await;
    let mut other_key = builder_signer(1, 7, false);
    other_key.builder.as_mut().expect("builder").key_version = common::builder_version(1);
    let body = VerifyBlsRequestBody {
        request_id: 1,
        sets: vec![
            builder_set(builder_signer(1, 1, false), 1, 1),
            builder_set(other_key, 7, 2),
        ],
        deadline_unix_ms: far_deadline(),
        origin: VerifyOrigin::Gossip as i32,
        generation,
    };
    bls.send(bls_body(body)).await.expect("bls open");
    let reply = match results.message().await.expect("a reply").map(|r| r.frame) {
        Some(Some(verify_bls_response::Frame::Body(b))) => b,
        other => panic!("expected a VerifyBls body, got {other:?}"),
    };
    assert_eq!(
        outcomes(&reply),
        [Ok(VerifyStatus::Valid), Ok(VerifyStatus::UnknownIndex)]
    );
    let mut zero_signer = builder_set(builder_signer(1, 1, false), 1, 3);
    zero_signer.signers[0].namespace = KeyNamespace::Unspecified as i32;
    let body = VerifyBlsRequestBody {
        request_id: 2,
        sets: vec![zero_signer],
        deadline_unix_ms: far_deadline(),
        origin: VerifyOrigin::Import as i32,
        generation,
    };
    bls.send(bls_body(body)).await.expect("bls open");
    let failed = results.message().await.expect_err("the stream fails");
    assert_eq!(
        error_from_status(&failed).code(),
        ErrorCode::ContractViolation
    );
}

type Client = VerifyServiceClient<ipc::testkit::Transport>;

async fn open_builder_feed(
    client: &mut Client,
    hello: Hello,
) -> (
    mpsc::Sender<BuilderKeyFeedRequest>,
    tonic::Streaming<BuilderKeyFeedResponse>,
) {
    let (tx, rx) = mpsc::channel(8);
    tx.send(builder_hello(hello)).await.expect("feed open");
    let mut replies = client
        .builder_key_feed(ReceiverStream::new(rx))
        .await
        .expect("builder key feed served")
        .into_inner();
    let first = replies.message().await.expect("a hello").map(|r| r.frame);
    assert!(
        matches!(
            first,
            Some(Some(builder_key_feed_response::Frame::Hello(_)))
        ),
        "{first:?}"
    );
    (tx, replies)
}

/// The next builder feed reply: its high-water mark and error code.
async fn next_builder_reply(
    replies: &mut tonic::Streaming<BuilderKeyFeedResponse>,
) -> (u64, Option<ErrorCode>) {
    match replies.message().await.expect("a reply").map(|r| r.frame) {
        Some(Some(builder_key_feed_response::Frame::Body(b))) => {
            assert_eq!(b.namespace, KeyNamespace::Builder as i32);
            (b.high_water, b.err.map(|e| e.code()))
        }
        other => panic!("expected a builder feed body, got {other:?}"),
    }
}

async fn open_bls(
    client: &mut Client,
    hello: Hello,
) -> (
    mpsc::Sender<VerifyBlsRequest>,
    tonic::Streaming<VerifyBlsResponse>,
    u64,
) {
    let (tx, rx) = mpsc::channel(8);
    tx.send(bls_hello(hello)).await.expect("bls open");
    let mut results = client
        .verify_bls(ReceiverStream::new(rx))
        .await
        .expect("VerifyBls served")
        .into_inner();
    let generation = match results.message().await.expect("a hello").map(|r| r.frame) {
        Some(Some(verify_bls_response::Frame::Hello(h))) => h.generation,
        other => panic!("expected the server hello, got {other:?}"),
    };
    (tx, results, generation)
}

ipc::contract_suite!(target, extra: [builder_key_feed_rules]);
