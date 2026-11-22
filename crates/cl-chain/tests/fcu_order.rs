//! [`FcuSender`] against a mock `ethswarm.engine.v1` server on a Unix socket: latest wins after
//! a stall, `seq` keeps increasing across a reconnect, the request carries the custody bits and
//! no payload attributes, a halted sender sends nothing more, the caller takes each answer once,
//! and a later answer does not replace an unread INVALID. Also the order of the waits on one call
//! and the `[chain.engine]` config of its socket. These run on real time, except the test of a
//! slow EL answer: it runs on paused time, held still ([`freeze`]), so only
//! `tokio::time::advance` moves the clock.

use cl_chain::engine::client::{
    EngineSeq, FcuErrorKind, FcuMetrics, FcuSender, BACKOFF_MAX, BACKOFF_MIN, FCU_CALL_TIMEOUT,
    FORKCHOICE_UPDATED_TIMEOUT,
};
use cl_chain::engine::fcu::{custody_column_bits, ForkchoiceArgs, ForkchoiceSink};
use cl_chain::probe::service::CHAIN_METHODS;
use consensus_types::das;
use consensus_types::primitives::{Hash32, U256};
use ethswarm_proto::engine as pb;
use pb::engine_service_server::{EngineService, EngineServiceServer};
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tonic::{Request, Response, Status};

/// How long a test waits for something that should happen.
const WAIT: Duration = Duration::from_secs(20);

/// A mock engine.v1 server: it records each `ForkchoiceUpdated` request, reports it on
/// `arrived`, and answers once `gate` gives it a permit (a stalled EL until then): VALID, or the
/// status [`MockEngine::answer`] set for the head hash.
#[derive(Clone)]
struct MockEngine {
    seen: Arc<Mutex<Vec<pb::ForkchoiceUpdatedRequest>>>,
    arrived: mpsc::UnboundedSender<pb::ForkchoiceUpdatedRequest>,
    gate: Arc<Semaphore>,
    statuses: Arc<Mutex<HashMap<Vec<u8>, pb::PayloadStatusKind>>>,
}

impl MockEngine {
    fn new(permits: usize) -> (Self, mpsc::UnboundedReceiver<pb::ForkchoiceUpdatedRequest>) {
        let (arrived, rx) = mpsc::unbounded_channel();
        let mock = Self {
            seen: Arc::default(),
            arrived,
            gate: Arc::new(Semaphore::new(permits)),
            statuses: Arc::default(),
        };
        (mock, rx)
    }

    /// Answers `status` to a call with the head `head`. INVALID carries a `latestValidHash`.
    fn answer(&self, head: Hash32, status: pb::PayloadStatusKind) {
        self.statuses.lock().unwrap().insert(head.to_vec(), status);
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
        let status = self
            .statuses
            .lock()
            .unwrap()
            .get(&req.head_block_hash)
            .copied();
        let (status, latest_valid_hash) = match status.unwrap_or(pb::PayloadStatusKind::Valid) {
            pb::PayloadStatusKind::Valid => (pb::PayloadStatusKind::Valid, req.head_block_hash),
            pb::PayloadStatusKind::Invalid => (pb::PayloadStatusKind::Invalid, hash(0x0f).to_vec()),
            other => (other, Vec::new()),
        };
        Ok(Response::new(pb::ForkchoiceUpdatedResponse {
            seq: req.seq,
            status: Some(pb::PayloadStatus {
                status: status as i32,
                latest_valid_hash,
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

/// The EL stalls on a call, and newer arguments wait in the slot. The halt drops them: the
/// stalled call is still answered, and nothing more is sent, a later send included.
#[tokio::test]
async fn a_halted_sender_drops_the_queued_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let (mock, mut arrived) = MockEngine::new(0);
    let server = Server::start(&path, mock.clone());
    let (sender, metrics, _registry) = sender(&path);
    sender.send(args(1));
    let first = next(&mut arrived).await;
    sender.send(args(2));
    ForkchoiceSink::halt(&sender);
    sender.send(args(3));
    mock.gate.add_permits(16);
    let outcome = answered(&sender, first.seq).await;
    assert_eq!(
        outcome.args,
        args(1),
        "the call on its way is still answered"
    );
    let more = tokio::time::timeout(Duration::from_millis(300), arrived.recv()).await;
    assert!(more.is_err(), "a call was sent after the halt: {more:?}");
    assert_eq!(mock.heads(), [hash(1).to_vec()]);
    assert_eq!(metrics.sent(), 1);
    server.stop().await;
}

/// cl-engine goes away, and the call is lost: the sender would try it again after the backoff.
/// Halted before that, it does not, also once cl-engine is back.
#[tokio::test]
async fn a_halted_sender_does_not_retry_a_lost_call() {
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
    ForkchoiceSink::halt(&sender);
    let (mock, mut arrived) = MockEngine::new(Semaphore::MAX_PERMITS);
    let server = Server::start(&path, mock.clone());
    // Past the backoff of the next try, and the one after it.
    let more = tokio::time::timeout(BACKOFF_MIN * 3, arrived.recv()).await;
    assert!(more.is_err(), "the lost call was tried again: {more:?}");
    assert!(mock.heads().is_empty());
    server.stop().await;
}

/// The caller takes each answer once ([`ForkchoiceSink::take_outcome`]): none before the first
/// answer, the latest one after it, and none again until a newer one comes.
#[tokio::test]
async fn the_caller_takes_each_answer_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let (mock, mut arrived) = MockEngine::new(Semaphore::MAX_PERMITS);
    let server = Server::start(&path, mock);
    let (sender, _metrics, _registry) = sender(&path);
    assert_eq!(sender.take_outcome(), None);
    for n in [1, 2] {
        sender.send(args(n));
        let call = next(&mut arrived).await;
        answered(&sender, call.seq).await;
        let taken = sender.take_outcome().expect("a new answer");
        assert_eq!((taken.seq, taken.args), (call.seq, args(n)));
        assert_eq!(sender.take_outcome(), None, "the same answer again");
    }
    server.stop().await;
}

/// An INVALID or INVALID_BLOCK_HASH answer that the caller has not taken yet stays until it is
/// taken: a later answer (VALID, SYNCING) that comes first does not replace it. The caller takes
/// it first, then the later answer, the latest, and then none.
#[tokio::test]
async fn a_later_answer_does_not_replace_an_unread_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let (mock, mut arrived) = MockEngine::new(Semaphore::MAX_PERMITS);
    mock.answer(hash(1), pb::PayloadStatusKind::Invalid);
    mock.answer(hash(3), pb::PayloadStatusKind::InvalidBlockHash);
    mock.answer(hash(4), pb::PayloadStatusKind::Syncing);
    let server = Server::start(&path, mock);
    let (sender, _metrics, _registry) = sender(&path);
    for (bad, kind, later) in [
        (1, pb::PayloadStatusKind::Invalid, 2),
        (3, pb::PayloadStatusKind::InvalidBlockHash, 4),
    ] {
        let mut seqs = Vec::new();
        for n in [bad, later] {
            sender.send(args(n));
            let call = next(&mut arrived).await;
            answered(&sender, call.seq).await;
            seqs.push(call.seq);
        }
        let taken = sender.take_outcome().expect("the unread answer");
        assert_eq!(
            (taken.seq, taken.args),
            (seqs[0], args(bad)),
            "the later answer replaced the unread {kind:?}"
        );
        assert_eq!(taken.response.status.unwrap().status, kind as i32);
        let taken = sender.take_outcome().expect("the latest answer");
        assert_eq!((taken.seq, taken.args), (seqs[1], args(later)));
        assert_eq!(sender.take_outcome(), None, "each answer once");
    }
    server.stop().await;
}

/// When the EL answers the slow call of [`a_slow_invalid_within_the_el_wait_is_kept`]: inside
/// cl-engine's wait for the EL on `engine_forkchoiceUpdated` (8 s), so cl-engine passes the
/// answer on, and past the 6 s a newPayload call waits.
const EL_ANSWER: Duration = Duration::from_secs(7);

/// The most wall-clock time a step has once the frozen clock is where it should happen: the
/// clock cannot move then, so no Tokio timer bounds the wait.
const WALL_LIMIT: Duration = Duration::from_secs(10);

/// Holds the paused clock still until dropped. Tokio does not auto-advance paused time while a
/// blocking task runs (`tokio::time::pause`, "Preventing auto-advance"). Without this, a wait on
/// Unix-socket I/O could move the clock to the sender's next timer.
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

/// The output of `fut`, or `None` if it has none within `limit` of wall-clock time.
async fn within_wall<T>(fut: impl std::future::Future<Output = T>, limit: Duration) -> Option<T> {
    let (done, over) = oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        let _ = done.send(());
    });
    tokio::select! {
        biased;
        out = fut => Some(out),
        _ = over => None,
    }
}

/// The EL takes [`EL_ANSWER`] to answer INVALID, with a `latestValidHash`: inside cl-engine's
/// wait for it, so cl-engine gives that answer then. The sender waits for it: 1 ms before, it
/// has not given up on the call; it takes the answer when it comes and keeps it for the caller,
/// who takes that call's INVALID (its `seq`, its arguments). The call is not lost: no error is
/// counted, and it is not sent again with a new `seq`, also past the longest backoff.
#[tokio::test(start_paused = true)]
async fn a_slow_invalid_within_the_el_wait_is_kept() {
    assert!(EL_ANSWER < cl_engine::client::FORKCHOICE_UPDATED_TIMEOUT);
    let frozen = freeze();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.sock");
    let (mock, mut arrived) = MockEngine::new(0);
    mock.answer(hash(1), pb::PayloadStatusKind::Invalid);
    let server = Server::start(&path, mock.clone());
    let (sender, metrics, _registry) = sender(&path);
    let lost = || metrics.errors(FcuErrorKind::Connect) + metrics.errors(FcuErrorKind::Rpc);
    let start = Instant::now();
    sender.send(args(1));
    let call = within_wall(arrived.recv(), WALL_LIMIT)
        .await
        .expect("a ForkchoiceUpdated call")
        .expect("the mock is running");
    assert_eq!(start.elapsed(), Duration::ZERO, "the clock must not move");
    // 1 ms before the EL answers: the sender still waits for it.
    tokio::time::advance(EL_ANSWER - Duration::from_millis(1)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        lost(),
        0,
        "the sender gave up on the call before the EL answered"
    );
    assert_eq!(sender.take_outcome(), None);
    // The EL answers.
    tokio::time::advance(Duration::from_millis(1)).await;
    mock.gate.add_permits(1);
    let mut outcomes = sender.outcomes();
    within_wall(outcomes.wait_for(Option::is_some), WALL_LIMIT)
        .await
        .expect("the EL's answer reaches the sender")
        .unwrap();
    assert_eq!(start.elapsed(), EL_ANSWER);
    let taken = sender.take_outcome().expect("the INVALID answer");
    assert_eq!((taken.seq, taken.args), (call.seq, args(1)));
    assert_eq!(taken.response.error, None);
    let status = taken.response.status.expect("a payload status");
    assert_eq!(status.status, pb::PayloadStatusKind::Invalid as i32);
    assert_eq!(status.latest_valid_hash, hash(0x0f).to_vec());
    assert_eq!(sender.take_outcome(), None, "each answer once");
    // Not sent again.
    tokio::time::advance(BACKOFF_MAX * 2).await;
    let more = within_wall(arrived.recv(), Duration::from_millis(300)).await;
    assert!(more.is_none(), "the call was sent again: {more:?}");
    assert_eq!(mock.heads(), [hash(1).to_vec()]);
    assert_eq!(metrics.sent(), 1);
    assert_eq!(lost(), 0);
    drop(frozen);
    server.stop().await;
}

/// One forkchoiceUpdated call has three waits, and they end in this order. cl-engine's wait for
/// the EL ends first (cl-chain's copy of it is cl-engine's own), so cl-engine answers, with the
/// EL's status or its `TIMEOUT`, while the sender still waits. The sender's wait ends next, so a
/// call held in cl-engine's queue, or by a stuck cl-engine, is given up by the sender (and sent
/// again with the latest arguments) before cl-engine's request deadline for forkchoiceUpdated
/// ends it: the two never end the call at the same moment.
#[test]
fn the_waits_on_a_forkchoice_call_end_in_order() {
    assert_eq!(
        FORKCHOICE_UPDATED_TIMEOUT,
        cl_engine::client::FORKCHOICE_UPDATED_TIMEOUT,
        "cl-chain's copy of cl-engine's wait for the EL"
    );
    // The request deadline cl-engine gives forkchoiceUpdated by default.
    let request_deadline = cl_engine::server::Limits::default().request_timeout;
    assert!(
        FORKCHOICE_UPDATED_TIMEOUT < FCU_CALL_TIMEOUT,
        "the EL wait ({FORKCHOICE_UPDATED_TIMEOUT:?}) must end before the sender's \
         ({FCU_CALL_TIMEOUT:?})"
    );
    assert!(
        FCU_CALL_TIMEOUT < request_deadline,
        "the sender's wait ({FCU_CALL_TIMEOUT:?}) must end before cl-engine's forkchoiceUpdated \
         request deadline ({request_deadline:?})"
    );
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
