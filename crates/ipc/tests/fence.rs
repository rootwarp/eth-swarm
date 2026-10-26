//! Request fencing over a real stream: a fake cl-verify answers `VerifyBls` honestly, or
//! reorders, duplicates, replays (old generation) or substitutes its results, or holds them
//! back until after the client's deadline or reconnect. The client is the ipc client guard plus
//! [`ipc::deadline::Calls`]. Every test runs in process and over a Unix socket in a temp dir.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ethswarm_proto::common::{ErrorCode, Verdict};
use ethswarm_proto::verify::verify_service_client::VerifyServiceClient;
use ethswarm_proto::verify::verify_service_server::{VerifyService, VerifyServiceServer};
use ethswarm_proto::verify::{
    bls_result, BlsResult, BlsSet, BuilderKeyFeedRequest, BuilderKeyFeedResponse,
    PubkeyFeedRequest, PubkeyFeedResponse, VerifyBlsRequest, VerifyBlsRequestBody,
    VerifyBlsResponse, VerifyBlsResponseBody, VerifyKzgRequest, VerifyKzgResponse, VerifyOrigin,
    VerifyStatus,
};
use ipc::deadline::{Calls, Delivery, FenceMetrics, Ignored, Pending};
use ipc::fence::{check_request, message_hash, FencedRequest, FencedResult, RequestTag};
use ipc::frame::{Inbound, OutFrame};
use ipc::hello::{stream_hello, Generation};
use ipc::testkit::{fixture, Connection, Mode, Server};
use ipc::ContractError;
use tokio::sync::{mpsc, Notify};
use tokio_stream::wrappers::ReceiverStream;
use tonic::service::Routes;
use tonic::{Request, Response, Status, Streaming};

/// How long a call waits unless a test says otherwise; only a broken test hits it.
const WAIT: Duration = Duration::from_secs(10);

/// How the fake server answers each request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mischief {
    Honest,
    /// Swaps the first two results.
    Reorder,
    /// Sends the honest response twice.
    Duplicate,
    /// Answers with a response recorded on an earlier stream for the same request id (so with
    /// that stream's generation) when it has one, else honestly.
    Replay,
    /// Answers item 0 as if it were another set.
    Substitute,
    /// Answers honestly once the test releases it.
    Hold,
}

/// State that outlives one server start: every generation issued, honest answers for replays,
/// and the release of held answers.
#[derive(Default)]
struct Tape {
    generations: Mutex<Vec<u64>>,
    answered: Mutex<Vec<VerifyBlsResponseBody>>,
    release: Notify,
}

impl Tape {
    fn generations(&self) -> Vec<u64> {
        self.generations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[derive(Clone)]
struct FakeVerify {
    link: ipc::Link,
    mischief: Mischief,
    tape: Arc<Tape>,
}

fn valid() -> BlsResult {
    BlsResult {
        result: Some(bls_result::Result::Status(VerifyStatus::Valid as i32)),
        fence: None,
    }
}

impl FakeVerify {
    async fn answer(&self, request: &VerifyBlsRequestBody) -> Vec<VerifyBlsResponseBody> {
        let mut honest = VerifyBlsResponseBody {
            request_id: request.request_id,
            results: vec![valid(); request.sets.len()],
        };
        let mut fences = request.result_fences();
        honest.stamp(&fences);
        let answered = || {
            self.tape
                .answered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        };
        match self.mischief {
            Mischief::Honest => vec![honest],
            Mischief::Reorder => {
                honest.results.swap(0, 1);
                vec![honest]
            }
            Mischief::Duplicate => vec![honest.clone(), honest],
            Mischief::Replay => {
                let mut tape = answered();
                match tape.iter().find(|r| r.request_id == request.request_id) {
                    Some(old) => vec![old.clone()],
                    None => {
                        tape.push(honest.clone());
                        vec![honest]
                    }
                }
            }
            Mischief::Substitute => {
                let other = BlsSet {
                    signing_root: vec![0xee; 32],
                    ..Default::default()
                };
                fences[0].item_hash = message_hash(&other);
                honest.stamp(&fences);
                vec![honest]
            }
            Mischief::Hold => {
                self.tape.release.notified().await;
                vec![honest]
            }
        }
    }
}

#[tonic::async_trait]
impl VerifyService for FakeVerify {
    type VerifyBlsStream = ReceiverStream<Result<VerifyBlsResponse, Status>>;
    type VerifyKzgStream = ReceiverStream<Result<VerifyKzgResponse, Status>>;
    type PubkeyFeedStream = ReceiverStream<Result<PubkeyFeedResponse, Status>>;
    type BuilderKeyFeedStream = ReceiverStream<Result<BuilderKeyFeedResponse, Status>>;

    async fn verify_bls(
        &self,
        request: Request<Streaming<VerifyBlsRequest>>,
    ) -> Result<Response<Self::VerifyBlsStream>, Status> {
        let (tx, rx) = mpsc::channel(16);
        let this = self.clone();
        tokio::spawn(async move {
            let run = async {
                let mut guarded = this.link.open(Inbound::new(request.into_inner())).await?;
                let (generation, hello) = stream_hello(&this.link.local())?;
                this.tape
                    .generations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(generation.get());
                if tx.send(Ok(VerifyBlsResponse::hello(hello))).await.is_err() {
                    return Ok(());
                }
                while let Some(accepted) = guarded.body().await? {
                    check_request(&accepted.body, generation)?;
                    for reply in this.answer(&accepted.body).await {
                        if tx.send(Ok(VerifyBlsResponse::body(reply))).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Ok::<_, ContractError>(())
            };
            if let Err(e) = run.await {
                let _ = tx.send(Err(e.to_status())).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn verify_kzg(
        &self,
        _: Request<Streaming<VerifyKzgRequest>>,
    ) -> Result<Response<Self::VerifyKzgStream>, Status> {
        Err(Status::unimplemented("fake serves VerifyBls only"))
    }

    async fn pubkey_feed(
        &self,
        _: Request<Streaming<PubkeyFeedRequest>>,
    ) -> Result<Response<Self::PubkeyFeedStream>, Status> {
        Err(Status::unimplemented("fake serves VerifyBls only"))
    }

    async fn builder_key_feed(
        &self,
        _: Request<Streaming<BuilderKeyFeedRequest>>,
    ) -> Result<Response<Self::BuilderKeyFeedStream>, Status> {
        Err(Status::unimplemented("fake serves VerifyBls only"))
    }
}

/// One server start.
async fn start(mode: &Mode, mischief: Mischief, tape: &Arc<Tape>) -> Connection {
    let fake = FakeVerify {
        link: fixture::v1_link(),
        mischief,
        tape: Arc::clone(tape),
    };
    mode.connect(Server::new(Routes::new(VerifyServiceServer::new(fake))))
        .await
}

/// The client side of one VerifyBls stream.
struct Client {
    calls: Calls<VerifyBlsResponseBody>,
    tx: mpsc::Sender<VerifyBlsRequest>,
    /// What the reader made of each response: the seam between the wire and the verdicts.
    seam: mpsc::UnboundedReceiver<Result<Delivery, ContractError>>,
}

/// A fenced request of `sets` distinct sets for `tag`.
fn request(tag: RequestTag, sets: u8) -> VerifyBlsRequestBody {
    VerifyBlsRequestBody {
        request_id: tag.request_id,
        generation: tag.generation.get(),
        sets: (0..sets)
            .map(|i| BlsSet {
                signing_root: vec![i; 32],
                signature: vec![i; 96],
                ..Default::default()
            })
            .collect(),
        deadline_unix_ms: u64::MAX,
        origin: VerifyOrigin::Gossip as i32,
    }
}

impl Client {
    /// Opens a stream: our hello, the server's hello (its generation), then a reader that
    /// delivers every response through the fences. A violation fails the stream: the reader
    /// closes the calls, so each outstanding one ends as IGNORE.
    async fn connect(conn: &Connection, metrics: &Arc<FenceMetrics>) -> Self {
        let link = fixture::v1_link();
        let (tx, rx) = mpsc::channel(16);
        tx.send(VerifyBlsRequest::hello(link.local()))
            .await
            .unwrap();
        let response = VerifyServiceClient::new(conn.transport.clone())
            .verify_bls(ReceiverStream::new(rx))
            .await
            .expect("stream opens");
        let mut guarded = link
            .open(Inbound::from_server(response.into_inner()))
            .await
            .expect("server hello");
        let generation = Generation::from_hello(guarded.peer()).expect("server generation");
        let calls = Calls::with_metrics(generation, 16, Arc::clone(metrics));
        let (seam_tx, seam) = mpsc::unbounded_channel();
        let reader = calls.clone();
        tokio::spawn(async move {
            loop {
                let outcome = match guarded.body().await {
                    Ok(Some(accepted)) => reader.deliver_body(accepted.body),
                    Ok(None) => break,
                    Err(e) => Err(e),
                };
                let failed = outcome.is_err();
                let _ = seam_tx.send(outcome);
                if failed {
                    reader.close();
                    break;
                }
            }
        });
        Self { calls, tx, seam }
    }

    fn generation(&self) -> u64 {
        self.calls.generation().get()
    }

    async fn send(&self, sets: u8) -> Pending<VerifyBlsResponseBody> {
        let (body, pending) = self
            .calls
            .start(|tag| {
                let body = request(tag, sets);
                let hashes = body.item_hashes();
                (body, hashes)
            })
            .expect("room for a call");
        self.tx.send(VerifyBlsRequest::body(body)).await.unwrap();
        pending
    }

    async fn verify(&self, sets: u8) -> Result<VerifyBlsResponseBody, Ignored> {
        self.send(sets).await.wait(WAIT).await
    }

    async fn next_seam(&mut self) -> Result<Delivery, ContractError> {
        tokio::time::timeout(WAIT, self.seam.recv())
            .await
            .expect("a response reaches the seam")
            .expect("reader alive")
    }
}

fn all_valid(r: &VerifyBlsResponseBody) -> bool {
    r.results.iter().all(|r| {
        matches!(r.result, Some(bls_result::Result::Status(s)) if s == VerifyStatus::Valid as i32)
    })
}

/// Runs one call against `mischief` and returns the contract error the seam refused it with.
/// The call itself must end as IGNORE (the stream failed), never with the forged result.
async fn refused(mode: &Mode, mischief: Mischief) -> ContractError {
    let tape = Arc::new(Tape::default());
    let metrics = Arc::new(FenceMetrics::default());
    let conn = start(mode, mischief, &tape).await;
    let mut client = Client::connect(&conn, &metrics).await;
    if mischief == Mischief::Replay {
        // Record an honest answer on a first stream, then replay it onto a second one.
        let first = Client::connect(&conn, &metrics).await;
        assert!(all_valid(&first.verify(2).await.unwrap()));
    }
    let call = client.verify(2).await;
    let err = if mischief == Mischief::Duplicate {
        // The first copy settles the call; the second is the duplicate.
        assert!(all_valid(&call.unwrap()));
        assert_eq!(client.next_seam().await, Ok(Delivery::Accepted));
        client.next_seam().await.unwrap_err()
    } else {
        assert_eq!(call, Err(Ignored::Reconnect), "{mischief:?}");
        client.next_seam().await.unwrap_err()
    };
    assert_eq!(metrics.counts().violations, 1, "{mischief:?}");
    assert_eq!(metrics.counts().late_dropped, 0, "{mischief:?}");
    err
}

async fn honest_results_are_accepted(mode: Mode) {
    let tape = Arc::new(Tape::default());
    let metrics = Arc::new(FenceMetrics::default());
    let conn = start(&mode, Mischief::Honest, &tape).await;
    let mut client = Client::connect(&conn, &metrics).await;
    for sets in [1, 3] {
        let reply = client.verify(sets).await.unwrap();
        assert_eq!(reply.results.len(), usize::from(sets));
        assert!(all_valid(&reply));
        assert_eq!(client.next_seam().await, Ok(Delivery::Accepted));
    }
    assert_eq!(metrics.counts(), Default::default());
}

async fn reordered_results_rejected(mode: Mode) {
    let err = refused(&mode, Mischief::Reorder).await;
    assert!(err.detail().contains("position 0 answers item 1"), "{err}");
}

async fn duplicated_results_rejected(mode: Mode) {
    let err = refused(&mode, Mischief::Duplicate).await;
    assert!(err.detail().contains("duplicate"), "{err}");
}

async fn stale_generation_results_rejected(mode: Mode) {
    let err = refused(&mode, Mischief::Replay).await;
    assert!(err.detail().contains("generation"), "{err}");
}

async fn substituted_results_rejected(mode: Mode) {
    let err = refused(&mode, Mischief::Substitute).await;
    assert!(err.detail().contains("item 0 hash differs"), "{err}");
}

async fn fence_violation_is_contract_error(mode: Mode) {
    for mischief in [
        Mischief::Reorder,
        Mischief::Duplicate,
        Mischief::Replay,
        Mischief::Substitute,
    ] {
        let err = refused(&mode, mischief).await;
        assert_eq!(err.code(), ErrorCode::ContractViolation, "{mischief:?}");
        // The same code reaches the peer when the client fails the stream with it.
        assert_eq!(
            ContractError::from_status(&err.to_status()).code(),
            ErrorCode::ContractViolation
        );
    }
}

async fn hello_generation_changes_on_restart(mode: Mode) {
    let tape = Arc::new(Tape::default());
    let metrics = Arc::new(FenceMetrics::default());
    let first = start(&mode, Mischief::Replay, &tape).await;
    let before = Client::connect(&first, &metrics).await;
    assert!(all_valid(&before.verify(1).await.unwrap()));
    drop(before);
    drop(first);

    // The restarted server replays what the first start answered.
    let second = start(&mode, Mischief::Replay, &tape).await;
    let mut after = Client::connect(&second, &metrics).await;
    let generations = tape.generations();
    assert_eq!(generations.len(), 2);
    assert!(generations.iter().all(|g| *g != 0), "{generations:x?}");
    assert_ne!(generations[0], generations[1]);
    assert_eq!(after.generation(), generations[1]);

    assert_eq!(after.verify(1).await, Err(Ignored::Reconnect));
    let err = after.next_seam().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ContractViolation);
    assert!(
        err.detail()
            .contains(&format!("generation {:#018x}", generations[0])),
        "{err}"
    );
}

async fn late_result_after_reconnect_dropped(mode: Mode) {
    let tape = Arc::new(Tape::default());
    let metrics = Arc::new(FenceMetrics::default());
    let old = start(&mode, Mischief::Hold, &tape).await;
    let mut stale = Client::connect(&old, &metrics).await;
    let pending = stale.send(2).await;

    // Reconnect: the old stream's calls fail as IGNORE before any result has come.
    assert_eq!(stale.calls.close(), 1);
    let ignored = pending.wait(WAIT).await.unwrap_err();
    assert_eq!(ignored, Ignored::Reconnect);
    assert_eq!(ignored.verdict(), Verdict::Ignore);
    let restarted = start(&mode, Mischief::Honest, &tape).await;
    let fresh = Client::connect(&restarted, &metrics).await;
    assert_ne!(fresh.generation(), stale.generation());

    // The held result now arrives on the old stream: dropped and counted, not a violation.
    tape.release.notify_one();
    assert_eq!(stale.next_seam().await, Ok(Delivery::LateDropped));
    let counts = metrics.counts();
    assert_eq!(
        (counts.late_dropped, counts.ignored, counts.violations),
        (1, 1, 0)
    );
    assert!(all_valid(&fresh.verify(1).await.unwrap()));
}

async fn late_result_after_deadline_dropped(mode: Mode) {
    let tape = Arc::new(Tape::default());
    let metrics = Arc::new(FenceMetrics::default());
    let conn = start(&mode, Mischief::Hold, &tape).await;
    let mut client = Client::connect(&conn, &metrics).await;
    let pending = client.send(1).await;
    assert_eq!(
        pending.wait(Duration::from_millis(20)).await,
        Err(Ignored::Deadline)
    );
    tape.release.notify_one();
    assert_eq!(client.next_seam().await, Ok(Delivery::LateDropped));
    assert_eq!(metrics.counts().late_dropped, 1);
    // The stream goes on: the next call is answered.
    tape.release.notify_one();
    assert!(all_valid(&client.verify(1).await.unwrap()));
}

macro_rules! both_transports {
    ($($name:ident),* $(,)?) => {
        mod in_process {
            $(
                #[test]
                fn $name() {
                    ipc::testkit::block_on(super::$name(ipc::testkit::Mode::InProcess));
                }
            )*
        }
        mod uds {
            $(
                #[test]
                fn $name() {
                    let dir = ipc::testkit::tempdir();
                    ipc::testkit::block_on(super::$name(ipc::testkit::Mode::over_uds(dir.path())));
                }
            )*
        }
    };
}

both_transports!(
    honest_results_are_accepted,
    reordered_results_rejected,
    duplicated_results_rejected,
    stale_generation_results_rejected,
    substituted_results_rejected,
    fence_violation_is_contract_error,
    hello_generation_changes_on_restart,
    late_result_after_reconnect_dropped,
    late_result_after_deadline_dropped,
);
