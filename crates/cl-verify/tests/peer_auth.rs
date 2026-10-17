//! Only cl-chain's UID may call cl-verify. The peer UID comes from the Unix socket's credentials
//! (`UdsConnectInfo.peer_cred`) and is checked on every RPC before the hello is read.
//!
//! No second local UID is available to the test, so the "other process" is this process with the
//! server configured for a different UID: the real kernel credentials of the connection are what
//! is refused. A TCP connection, which has no Unix credentials, is refused as well.

mod common;

use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::verify_service_client::VerifyServiceClient;
use cl_verify::proto::verify::PubkeyFeedRequestBody;
use cl_verify::server::Limits;
use cl_verify::wire::error_from_status;
use common::*;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::Code;

fn assert_refused(status: tonic::Status) {
    assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
    assert_eq!(
        error_from_status(&status).code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn peer_with_another_uid_is_refused_on_every_rpc_and_cannot_feed() {
    let mut h = start_with(Options {
        peer_uid: Some(my_uid().wrapping_add(1)),
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    // Feed: a hello plus a frame appending index 2 must never reach the cache.
    let (tx, rx) = mpsc::channel(4);
    tx.send(feed_hello(hello())).await.unwrap();
    tx.send(feed_body(PubkeyFeedRequestBody {
        start_index: 2,
        count: 1,
        pubkeys: vec![pk_bytes(2)],
    }))
    .await
    .unwrap();
    assert_refused(
        h.client
            .pubkey_feed(ReceiverStream::new(rx))
            .await
            .unwrap_err(),
    );

    let (tx, rx) = mpsc::channel(4);
    tx.send(bls_hello(hello())).await.unwrap();
    assert_refused(
        h.client
            .verify_bls(ReceiverStream::new(rx))
            .await
            .unwrap_err(),
    );
    let (tx, rx) = mpsc::channel(4);
    tx.send(kzg_hello(hello())).await.unwrap();
    assert_refused(
        h.client
            .verify_kzg(ReceiverStream::new(rx))
            .await
            .unwrap_err(),
    );

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(h.cache.read().unwrap().high_water(), 2, "cache unchanged");
    assert_eq!(h.server.contract_violations(), 3);
}

#[tokio::test]
async fn configured_uid_is_served() {
    let mut h = start().await;
    let (_s, high_water) = feed_open(&mut h).await;
    assert_eq!(high_water, 0);
}

#[tokio::test]
async fn connection_without_unix_credentials_is_refused() {
    let server = cl_verify::server::VerifyServer::with_backends(
        config(my_uid(), Limits::default()),
        cl_verify::feed::SharedCache::default(),
        std::sync::Arc::new(cl_verify::bls::BlstBackend),
        kzg_backend(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let mut client = VerifyServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(4);
    tx.send(feed_hello(hello())).await.unwrap();
    assert_refused(
        client
            .pubkey_feed(ReceiverStream::new(rx))
            .await
            .unwrap_err(),
    );
}
