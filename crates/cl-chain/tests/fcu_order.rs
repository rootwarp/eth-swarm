//! [`FcuSender`] against a mock `ethswarm.engine.v1` server on a Unix socket: latest wins after
//! a stall, `seq` keeps increasing across a reconnect, and the request carries the custody bits
//! and no payload attributes. Also the `[chain.engine]` config of its socket.

use cl_chain::engine::client::{EngineSeq, FcuErrorKind, FcuMetrics, FcuSender};
use cl_chain::engine::fcu::{custody_column_bits, ForkchoiceArgs};
use cl_chain::probe::service::CHAIN_METHODS;
use consensus_types::das;
use consensus_types::primitives::{Hash32, U256};
use ethswarm_proto::engine as pb;
use pb::engine_service_server::{EngineService, EngineServiceServer};
use prometheus_client::registry::Registry;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};

/// How long a test waits for something that should happen.
const WAIT: Duration = Duration::from_secs(20);

/// A mock engine.v1 server: it records each `ForkchoiceUpdated` request, reports it on
/// `arrived`, and answers VALID once `gate` gives it a permit (a stalled EL until then).
#[derive(Clone)]
struct MockEngine {
    seen: Arc<Mutex<Vec<pb::ForkchoiceUpdatedRequest>>>,
    arrived: mpsc::UnboundedSender<pb::ForkchoiceUpdatedRequest>,
    gate: Arc<Semaphore>,
}

impl MockEngine {
    fn new(permits: usize) -> (Self, mpsc::UnboundedReceiver<pb::ForkchoiceUpdatedRequest>) {
        let (arrived, rx) = mpsc::unbounded_channel();
        let mock = Self {
            seen: Arc::default(),
            arrived,
            gate: Arc::new(Semaphore::new(permits)),
        };
        (mock, rx)
    }

    fn heads(&self) -> Vec<Vec<u8>> {
        let seen = self.seen.lock().unwrap();
        seen.iter().map(|req| req.head_block_hash.clone()).collect()
    }
}

#[tonic::async_trait]
impl EngineService for MockEngine {
    async fn new_payload(
        &self,
        _: Request<pb::NewPayloadRequest>,
    ) -> Result<Response<pb::NewPayloadResponse>, Status> {
        Err(Status::unimplemented("mock"))
    }

    async fn forkchoice_updated(
        &self,
        request: Request<pb::ForkchoiceUpdatedRequest>,
    ) -> Result<Response<pb::ForkchoiceUpdatedResponse>, Status> {
        let req = request.into_inner();
        self.seen.lock().unwrap().push(req.clone());
        let _ = self.arrived.send(req.clone());
        self.gate.acquire().await.unwrap().forget();
        Ok(Response::new(pb::ForkchoiceUpdatedResponse {
            seq: req.seq,
            status: Some(pb::PayloadStatus {
                status: pb::PayloadStatusKind::Valid as i32,
                latest_valid_hash: req.head_block_hash,
                validation_error: String::new(),
            }),
            payload_id: Vec::new(),
            error: None,
        }))
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

/// A running mock server and its stop.
struct Server {
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl Server {
    fn start(path: &Path, mock: MockEngine) -> Self {
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let routes = tonic::service::Routes::new(EngineServiceServer::new(mock));
        let task = tokio::spawn(ipc::stub::serve_uds(listener, routes, async {
            let _ = stopped.await;
        }));
        Self { stop, task }
    }

    /// Stops the server and waits until it no longer serves.
    async fn stop(self) {
        let _ = self.stop.send(());
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("the mock server stops")
            .unwrap()
            .unwrap();
    }
}

fn uid() -> u32 {
    ipc::uds::Ownership::current().uid
}

fn hash(n: u8) -> Hash32 {
    Hash32::repeat_byte(n)
}

/// Arguments told apart by their head hash `n`.
fn args(n: u8) -> ForkchoiceArgs {
    ForkchoiceArgs {
        head_block_hash: hash(n),
        safe_block_hash: hash(0x5a),
        finalized_block_hash: hash(0xf0),
        custody_columns: custody_column_bits(&[0, 1, 2, 3]),
    }
}

async fn next(
    arrived: &mut mpsc::UnboundedReceiver<pb::ForkchoiceUpdatedRequest>,
) -> pb::ForkchoiceUpdatedRequest {
    tokio::time::timeout(WAIT, arrived.recv())
        .await
        .expect("a ForkchoiceUpdated call in time")
        .expect("the mock is running")
}

fn sender(path: &Path) -> (FcuSender, FcuMetrics, Registry) {
    let mut registry = Registry::default();
    let metrics = FcuMetrics::register(&mut registry);
    let sender = FcuSender::spawn(path, uid(), EngineSeq::new(), metrics.clone());
    (sender, metrics, registry)
}

/// Waits until the sender has an answer to the call with `seq`.
async fn answered(sender: &FcuSender, seq: u64) -> cl_chain::engine::client::FcuOutcome {
    let mut outcomes = sender.outcomes();
    let outcome = tokio::time::timeout(
        WAIT,
        outcomes.wait_for(|o| o.as_ref().is_some_and(|o| o.seq == seq)),
    )
    .await
    .expect("an answer in time")
    .unwrap()
    .clone();
    outcome.unwrap()
}

/// Three head changes while the EL stalls on an earlier call: after it recovers only the last
/// of the three is sent, and its answer reaches the caller as it is.
#[tokio::test]
async fn latest_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let (mock, mut arrived) = MockEngine::new(0);
    let server = Server::start(&path, mock.clone());
    let (sender, metrics, registry) = sender(&path);
    sender.send(args(1));
    let first = next(&mut arrived).await;
    assert_eq!(first.head_block_hash, hash(1).to_vec());
    // The EL stalls on the first call; the head moves three times.
    for n in [2, 3, 4] {
        sender.send(args(n));
    }
    assert_eq!(metrics.coalesced(), 2);
    mock.gate.add_permits(16);
    let second = next(&mut arrived).await;
    assert_eq!(second.head_block_hash, hash(4).to_vec());
    assert!(second.seq > first.seq, "{} after {}", second.seq, first.seq);
    let outcome = answered(&sender, second.seq).await;
    assert_eq!(outcome.args, args(4));
    let status = outcome.response.status.expect("a payload status");
    assert_eq!(status.status, pb::PayloadStatusKind::Valid as i32);
    assert_eq!(status.latest_valid_hash, hash(4).to_vec());
    // Nothing else goes out.
    let more = tokio::time::timeout(Duration::from_millis(300), arrived.recv()).await;
    assert!(more.is_err(), "another call was sent: {more:?}");
    assert_eq!(mock.heads(), [hash(1).to_vec(), hash(4).to_vec()]);
    assert_eq!(metrics.sent(), 2);
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
    for line in [
        "chain_fcu_sent_total 2",
        "chain_fcu_coalesced_total 2",
        "chain_fcu_errors_total{kind=\"connect\"} 0",
    ] {
        assert!(text.contains(line), "{line} in\n{text}");
    }
    server.stop().await;
}

/// cl-engine goes away and comes back: the sender retries the latest arguments, connects again,
/// and the calls on the new connection carry `seq` values above every earlier one.
#[tokio::test]
async fn seq_increases_across_reconnect() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let (mock, mut arrived) = MockEngine::new(Semaphore::MAX_PERMITS);
    let server = Server::start(&path, mock);
    let (sender, metrics, _registry) = sender(&path);
    sender.send(args(1));
    let first = next(&mut arrived).await;
    answered(&sender, first.seq).await;
    server.stop().await;
    std::fs::remove_file(&path).unwrap();
    sender.send(args(2));
    let failed = || metrics.errors(FcuErrorKind::Connect) + metrics.errors(FcuErrorKind::Rpc);
    tokio::time::timeout(WAIT, async {
        while failed() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the sender sees cl-engine gone");
    let (mock, mut arrived) = MockEngine::new(Semaphore::MAX_PERMITS);
    let server = Server::start(&path, mock);
    let second = next(&mut arrived).await;
    assert_eq!(second.head_block_hash, hash(2).to_vec());
    assert!(second.seq > first.seq, "{} after {}", second.seq, first.seq);
    answered(&sender, second.seq).await;
    sender.send(args(3));
    let third = next(&mut arrived).await;
    assert!(third.seq > second.seq, "{} after {}", third.seq, second.seq);
    answered(&sender, third.seq).await;
    server.stop().await;
}

/// The request is the arguments as they are: three 32-byte hashes, the 16 custody bytes (never
/// empty, which cl-engine would send as `null`), no payload attributes and no raised wait.
#[tokio::test]
async fn custody_and_null_attributes_on_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let (mock, mut arrived) = MockEngine::new(Semaphore::MAX_PERMITS);
    let server = Server::start(&path, mock);
    let (sender, _metrics, _registry) = sender(&path);
    let custody = das::custody_columns(U256::from(7u64), das::CUSTODY_REQUIREMENT).unwrap();
    let sent = ForkchoiceArgs {
        head_block_hash: hash(1),
        safe_block_hash: hash(2),
        finalized_block_hash: hash(3),
        custody_columns: custody_column_bits(&custody),
    };
    sender.send(sent);
    let req = next(&mut arrived).await;
    assert_eq!(req.head_block_hash, hash(1).to_vec());
    assert_eq!(req.safe_block_hash, hash(2).to_vec());
    assert_eq!(req.finalized_block_hash, hash(3).to_vec());
    assert_eq!(req.custody_columns.len(), 16);
    assert_eq!(req.custody_columns, sent.custody_columns.to_vec());
    assert!(
        req.payload_attributes.is_none(),
        "{:?}",
        req.payload_attributes
    );
    assert_eq!(req.timeout_ms, 0);
    assert_eq!(req, sent.request(req.seq));
    server.stop().await;
}

/// A cl-chain config whose `[chain]` table ends with `extra`.
fn config(extra: &str) -> String {
    let mut text = "network = \"sepolia\"\nmetrics_port = 9102\n\n[socket]\ngroup = 990\n\n\
                    [callers]\ncl-p2p = 991\n\n[methods]\n"
        .to_owned();
    for method in CHAIN_METHODS {
        text.push_str(&format!("\"{method}\" = [\"cl-p2p\"]\n"));
    }
    text.push_str(
        "\n[chain]\nreference_api_url = \"http://127.0.0.1:5052\"\n\
         node_id = \"0x0000000000000000000000000000000000000000000000000000000000000007\"\n\
         verify_socket = \"/run/ethswarm/cl-verify/cl-verify.sock\"\nverify_uid = 993\n",
    );
    text.push_str(extra);
    text
}

fn engine_socket(text: &str) -> Result<PathBuf, cl_chain::service::SettingsError> {
    let config =
        svc_runtime::Config::from_toml("cl-chain", text, Path::new("cl-chain.toml")).unwrap();
    cl_chain::service::settings(&config).map(|settings| settings.engine_socket)
}

/// `[chain.engine] socket` is cl-engine's socket: the node's default unless given, an absolute
/// path, and the table's only key.
#[test]
fn engine_socket_defaults_to_the_node_socket() {
    let node = ipc::uds::SocketDir::new("cl-engine").unwrap().socket_path();
    assert_eq!(node, Path::new("/run/ethswarm/cl-engine/cl-engine.sock"));
    assert_eq!(engine_socket(&config("")).unwrap(), node);
    let given = config("\n[chain.engine]\nsocket = \"/srv/engine/engine.sock\"\n");
    assert_eq!(
        engine_socket(&given).unwrap(),
        Path::new("/srv/engine/engine.sock")
    );
    for refused in [
        "\n[chain.engine]\nsocket = \"engine.sock\"\n",
        "\n[chain.engine]\nsocket = \"/srv/engine.sock\"\nuid = 994\n",
    ] {
        assert!(engine_socket(&config(refused)).is_err(), "{refused}");
    }
}
