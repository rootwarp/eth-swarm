//! The `rpc` span (and its `trace_id`) reaches the workers streaming handlers spawn.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ethswarm_proto::chain::import_batch_request::Frame;
use ethswarm_proto::chain::import_service_client::ImportServiceClient;
use ethswarm_proto::chain::import_service_server::ImportServiceServer;
use ethswarm_proto::chain::{ImportBatchRequest, ImportBatchRequestBody};
use svc_runtime::telemetry::{json_subscriber, TraceLayer};
use tokio_stream::wrappers::UnixListenerStream;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

/// Collects what the subscriber writes.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buffer {
    type Writer = Buffer;
    fn make_writer(&'a self) -> Buffer {
        self.clone()
    }
}

// One thread, so the thread-local subscriber sees every task, the spawned worker included.
#[tokio::test(flavor = "current_thread")]
async fn bidi_worker_logs_carry_the_trace_id() {
    let buf = Buffer::default();
    let _default =
        tracing::subscriber::set_default(json_subscriber(LevelFilter::DEBUG, buf.clone()));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let chain = cl_chain::ChainStub::new(ipc::testkit::fixture::v1_link());
    tokio::spawn(
        tonic::transport::Server::builder()
            .layer(TraceLayer)
            .add_service(ImportServiceServer::new(chain))
            .serve_with_incoming(UnixListenerStream::new(listener)),
    );

    let channel = ipc::uds::connect_path(&path, ipc::peercred::effective_uid())
        .await
        .unwrap();
    // A body before any hello: the stub's stream worker fails it and logs the contract error.
    let first = ImportBatchRequest {
        frame: Some(Frame::Body(ImportBatchRequestBody::default())),
    };
    let mut request = tonic::Request::new(tokio_stream::iter(vec![first]));
    request.metadata_mut().insert(
        "traceparent",
        format!("00-{TRACE}-00f067aa0ba902b7-01").parse().unwrap(),
    );
    let mut stream = ImportServiceClient::new(channel)
        .import_batch(request)
        .await
        .unwrap()
        .into_inner();
    let end = tokio::time::timeout(Duration::from_secs(10), stream.message()).await;
    assert!(matches!(end, Ok(Err(_))), "{end:?}");

    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let logged = out
        .lines()
        .find(|l| l.contains("contract error"))
        .unwrap_or_else(|| panic!("no contract error logged:\n{out}"));
    assert!(
        logged.contains(&format!(r#""trace_id":"{TRACE}""#)),
        "{logged}"
    );
    assert!(logged.contains("ImportService/ImportBatch"), "{logged}");
}
