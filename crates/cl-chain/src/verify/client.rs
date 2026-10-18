//! cl-chain's `ethswarm.verify.v1` `VerifyKzg` client.
//!
//! cl-chain never runs KZG itself: it sends cells to cl-verify and maps the answer to a
//! [`KzgOutcome`]. Only `VERIFY_STATUS_VALID` is [`KzgOutcome::Valid`]; `INVALID` and
//! `DECODE_ERROR` are [`KzgOutcome::Invalid`]. Everything that is not a verdict is
//! [`KzgOutcome::NoVerdict`], never valid: no answer by the deadline, a stream that cannot be
//! opened or ends, a hello that does not match ours, a fence violation, an `err` result,
//! `DEADLINE_EXCEEDED`, `OVERLOADED`, `UNSPECIFIED` or a status this build does not know
//! (`proto/README.md`: a timeout, overload or unavailable core is never ACCEPT).
//!
//! One VerifyKzg stream at a time. It is opened at the first call: our hello first, then
//! cl-verify's, compared in full ([`ipc::hello::negotiate`]) and carrying the stream's server
//! generation. Every request is fenced with it ([`ipc::deadline::Calls`]): its `request_id`, the
//! generation, and a response settled only through its fence. cl-verify fails a stream whose
//! `request_id` does not increase, so a call holds the stream's send lock from taking its id
//! until its frame is sent, and only then waits for its verdict. A reader task delivers the
//! responses; when the stream ends, errs or breaks the contract, every call on it fails as
//! [`KzgOutcome::NoVerdict`] and the next call opens a new stream. At most
//! [`DEFAULT_MAX_OUTSTANDING`] requests are in flight on a stream; a call past that is no
//! verdict, never queued without bound. A request whose deadline passed still counts until its
//! late answer arrives ([`ipc::fence::Outstanding`]), so a cl-verify that stops answering makes
//! every call no verdict until it answers again or the stream ends.
//!
//! Each call carries its deadline twice: on the wire (`deadline_unix_ms`, so cl-verify drops work
//! it cannot finish in time) and locally, over the whole call, the stream's opening included.

use ethswarm_proto::common::Hello;
use ethswarm_proto::verify::verify_service_client::VerifyServiceClient;
use ethswarm_proto::verify::{
    verify_kzg_request, verify_kzg_response, KzgCellProof, VerifyKzgRequest, VerifyKzgRequestBody,
    VerifyKzgResponse, VerifyKzgResponseBody, VerifyStatus,
};
use ipc::deadline::{Calls, FenceMetrics, Ignored};
use ipc::fence::FencedRequest;
use ipc::hello::{negotiate, Generation, API_VERSION_V1};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::Streaming;

/// Requests in flight on one stream \[est\]: a block's custody columns several times over.
pub const DEFAULT_MAX_OUTSTANDING: usize = 64;

/// What cl-verify said about one batch of cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KzgOutcome {
    /// `VERIFY_STATUS_VALID`: every cell verified against its commitment and proof.
    Valid,
    /// `VERIFY_STATUS_INVALID` or `VERIFY_STATUS_DECODE_ERROR`: a proven bad batch.
    Invalid,
    /// No verdict: why, for the log. Never valid.
    NoVerdict(String),
}

/// Checks cells by KZG, through cl-verify.
pub trait KzgVerifier: Send + Sync {
    /// `verify_cell_kzg_proof_batch` over `cells`, with a verdict within `timeout` or none.
    fn verify_cells(
        &self,
        cells: Vec<KzgCellProof>,
        timeout: Duration,
    ) -> impl Future<Output = KzgOutcome> + Send;
}

/// cl-chain's VerifyKzg client (see the module docs).
pub struct KzgClient {
    client: VerifyServiceClient<Channel>,
    hello: Hello,
    max_outstanding: usize,
    metrics: Arc<FenceMetrics>,
    stream: Mutex<Option<KzgStream>>,
}

/// What a call uses of the open stream.
#[derive(Clone)]
struct Link {
    requests: mpsc::Sender<VerifyKzgRequest>,
    calls: Calls<VerifyKzgResponseBody>,
    /// Held from taking a `request_id` through sending its frame, so the ids go out in the
    /// order they were taken.
    send: Arc<Mutex<()>>,
}

/// One open VerifyKzg stream.
struct KzgStream {
    link: Link,
    reader: JoinHandle<()>,
}

impl KzgStream {
    fn is_live(&self) -> bool {
        !self.reader.is_finished() && !self.link.requests.is_closed()
    }
}

impl std::ops::Drop for KzgStream {
    fn drop(&mut self) {
        self.reader.abort();
        self.link.calls.close();
    }
}

impl KzgClient {
    /// A client that opens its stream on `client` with `hello` at the first call.
    #[must_use]
    pub fn new(client: VerifyServiceClient<Channel>, hello: Hello) -> Self {
        Self {
            client,
            hello,
            max_outstanding: DEFAULT_MAX_OUTSTANDING,
            metrics: Arc::default(),
            stream: Mutex::new(None),
        }
    }

    /// The fencing counters of every stream this client opened: late results, violations and
    /// calls failed locally.
    #[must_use]
    pub fn fence_metrics(&self) -> &Arc<FenceMetrics> {
        &self.metrics
    }

    async fn call(&self, cells: Vec<KzgCellProof>, deadline: Instant, unix_ms: u64) -> KzgOutcome {
        let late = || KzgOutcome::NoVerdict("no verdict by the deadline".into());
        let link = match tokio::time::timeout_at(deadline, self.live()).await {
            Ok(Ok(link)) => link,
            Ok(Err(why)) => return KzgOutcome::NoVerdict(why),
            Err(_) => return late(),
        };
        // The id is taken and sent under the send lock; the verdict is awaited without it.
        let Ok(send) = tokio::time::timeout_at(deadline, link.send.lock()).await else {
            return late();
        };
        let started = link.calls.start(|tag| {
            let body = VerifyKzgRequestBody {
                request_id: tag.request_id,
                cells,
                deadline_unix_ms: unix_ms,
                generation: tag.generation.get(),
            };
            let hashes = body.item_hashes();
            (body, hashes)
        });
        let (body, pending) = match started {
            Ok(started) => started,
            Err(e) => return KzgOutcome::NoVerdict(format!("not sent: {e}")),
        };
        let frame = VerifyKzgRequest {
            frame: Some(verify_kzg_request::Frame::Body(body)),
        };
        // Widens the window between taking the request id and sending it, so a test sees any
        // reordering the code allows.
        #[cfg(test)]
        tokio::task::yield_now().await;
        // A send still waiting at the deadline gives up; the wait below then expires the call.
        if let Ok(Err(_)) = tokio::time::timeout_at(deadline, link.requests.send(frame)).await {
            link.calls.close();
            return KzgOutcome::NoVerdict("the VerifyKzg stream is closed".into());
        }
        drop(send);
        match pending.wait_until(deadline).await {
            Ok(body) => outcome(&body),
            Err(Ignored::Deadline) => late(),
            Err(Ignored::Reconnect) => KzgOutcome::NoVerdict("the VerifyKzg stream ended".into()),
        }
    }

    /// The open stream's link, opening a new stream if there is none or it ended.
    async fn live(&self) -> Result<Link, String> {
        let mut slot = self.stream.lock().await;
        if let Some(stream) = slot.as_ref().filter(|s| s.is_live()) {
            return Ok(stream.link.clone());
        }
        *slot = None;
        let stream = self.open().await?;
        let link = stream.link.clone();
        *slot = Some(stream);
        Ok(link)
    }

    /// Opens a stream: our hello, then cl-verify's, compared in full.
    async fn open(&self) -> Result<KzgStream, String> {
        let (requests, outbound) = mpsc::channel(self.max_outstanding);
        let hello = VerifyKzgRequest {
            frame: Some(verify_kzg_request::Frame::Hello(self.hello.clone())),
        };
        requests
            .send(hello)
            .await
            .map_err(|_| "the VerifyKzg stream is closed".to_owned())?;
        let mut responses = self
            .client
            .clone()
            .verify_kzg(ReceiverStream::new(outbound))
            .await
            .map_err(|s| format!("VerifyKzg: {s}"))?
            .into_inner();
        let first = responses
            .message()
            .await
            .map_err(|s| format!("VerifyKzg: {s}"))?
            .ok_or("VerifyKzg ended before cl-verify's hello")?;
        let Some(verify_kzg_response::Frame::Hello(server)) = first.frame else {
            tracing::warn!("contract violation: cl-verify's first VerifyKzg frame is not hello");
            return Err("cl-verify's first VerifyKzg frame is not hello".into());
        };
        negotiate(&self.hello, &server, API_VERSION_V1).map_err(|e| e.to_string())?;
        let generation = Generation::from_hello(&server).map_err(|e| e.to_string())?;
        let calls =
            Calls::with_metrics(generation, self.max_outstanding, Arc::clone(&self.metrics));
        let reader = tokio::spawn(read(responses, calls.clone()));
        Ok(KzgStream {
            link: Link {
                requests,
                calls,
                send: Arc::default(),
            },
            reader,
        })
    }
}

impl KzgVerifier for KzgClient {
    async fn verify_cells(&self, cells: Vec<KzgCellProof>, timeout: Duration) -> KzgOutcome {
        if cells.is_empty() {
            // An empty batch verifies vacuously; it is never sent and never valid.
            return KzgOutcome::NoVerdict("no cells".into());
        }
        let deadline = Instant::now() + timeout;
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.call(cells, deadline, now_unix_ms().saturating_add(timeout_ms))
            .await
    }
}

/// Delivers every response body of a stream to its calls until the stream ends, errs or
/// breaks the contract; then fails the calls still waiting.
async fn read(mut responses: Streaming<VerifyKzgResponse>, calls: Calls<VerifyKzgResponseBody>) {
    loop {
        match responses.message().await {
            Ok(Some(VerifyKzgResponse {
                frame: Some(verify_kzg_response::Frame::Body(body)),
            })) => {
                if calls.deliver_body(body).is_err() {
                    // A fence violation: logged by `deliver_body`; the stream is failed.
                    break;
                }
            }
            Ok(Some(_)) => {
                tracing::warn!("contract violation: VerifyKzg frame after hello is not a body");
                break;
            }
            Ok(None) => break,
            Err(status) => {
                tracing::debug!(%status, "VerifyKzg stream failed");
                break;
            }
        }
    }
    calls.close();
}

/// The outcome of a settled response. An `err` wins over any status.
fn outcome(body: &VerifyKzgResponseBody) -> KzgOutcome {
    if let Some(err) = &body.err {
        return KzgOutcome::NoVerdict(format!("cl-verify error {:?}: {}", err.code(), err.detail));
    }
    match VerifyStatus::try_from(body.status) {
        Ok(VerifyStatus::Valid) => KzgOutcome::Valid,
        Ok(VerifyStatus::Invalid | VerifyStatus::DecodeError) => KzgOutcome::Invalid,
        Ok(VerifyStatus::Unspecified) => {
            tracing::warn!("contract violation: VERIFY_STATUS_UNSPECIFIED from cl-verify");
            KzgOutcome::NoVerdict("VERIFY_STATUS_UNSPECIFIED".into())
        }
        Ok(other) => KzgOutcome::NoVerdict(other.as_str_name().into()),
        Err(_) => KzgOutcome::NoVerdict(format!("unknown VerifyStatus {}", body.status)),
    }
}

/// Wall-clock ms since the Unix epoch, as `deadline_unix_ms` counts them.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{blobs, ClVerify, Stub, StubVerify};
    use std::time::Instant;

    const TIMEOUT: Duration = Duration::from_secs(10);

    /// Column `column` of both fixture blobs.
    fn column(column: u64) -> Vec<KzgCellProof> {
        let b = blobs();
        (0..b.commitments.len())
            .map(|blob| KzgCellProof {
                commitment: b.commitments[blob].to_vec(),
                cell_index: column,
                cell: b.cell(blob, column).to_vec(),
                proof: b.proof(blob, column).to_vec(),
            })
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_calls_send_their_ids_in_order() {
        let served = ClVerify::start();
        let client = Arc::new(served.kzg_client().await);
        // One call first opens the stream, so the calls below race on one stream only.
        assert_eq!(
            client.verify_cells(column(0), TIMEOUT).await,
            KzgOutcome::Valid
        );
        for round in 0..4 {
            let calls: Vec<_> = (0..24)
                .map(|i| {
                    let client = Arc::clone(&client);
                    tokio::spawn(async move {
                        client
                            .verify_cells(column([0, 47, 127][i % 3]), TIMEOUT)
                            .await
                    })
                })
                .collect();
            for call in calls {
                let outcome = tokio::time::timeout(TIMEOUT, call).await.unwrap().unwrap();
                assert_eq!(outcome, KzgOutcome::Valid, "round {round}");
            }
        }
    }

    #[tokio::test]
    async fn cl_verify_accepts_the_fixture_columns() {
        let served = ClVerify::start();
        let client = served.kzg_client().await;
        for c in [0, 47, 127] {
            assert_eq!(
                client.verify_cells(column(c), TIMEOUT).await,
                KzgOutcome::Valid
            );
        }
    }

    #[tokio::test]
    async fn a_flipped_cell_byte_is_invalid() {
        let served = ClVerify::start();
        let client = served.kzg_client().await;
        let mut cells = column(1);
        // The low byte of the first field element: still canonical, no longer the blob's.
        cells[1].cell[31] ^= 1;
        assert_eq!(
            client.verify_cells(cells, TIMEOUT).await,
            KzgOutcome::Invalid
        );
        // A commitment of the other blob is invalid too.
        let mut swapped = column(1);
        swapped[0].commitment = blobs().commitments[1].to_vec();
        assert_eq!(
            client.verify_cells(swapped, TIMEOUT).await,
            KzgOutcome::Invalid
        );
        // The stream is still good afterwards.
        assert_eq!(
            client.verify_cells(column(1), TIMEOUT).await,
            KzgOutcome::Valid
        );
    }

    #[tokio::test]
    async fn no_cells_are_never_sent_and_never_valid() {
        let served = StubVerify::start(Stub::Silent);
        let client = served.kzg_client().await;
        let outcome = client.verify_cells(Vec::new(), TIMEOUT).await;
        assert!(matches!(outcome, KzgOutcome::NoVerdict(_)), "{outcome:?}");
    }

    /// No verdict within the deadline, whatever the stub does, and no later than it.
    async fn no_verdict_by_the_deadline(stub: Stub) -> String {
        let served = StubVerify::start(stub);
        let client = served.kzg_client().await;
        let deadline = Duration::from_millis(300);
        let cells = column(1);
        let start = Instant::now();
        let outcome = client.verify_cells(cells, deadline).await;
        let took = start.elapsed();
        assert!(
            took < deadline + Duration::from_millis(250),
            "{stub:?}: {took:?}"
        );
        match outcome {
            KzgOutcome::NoVerdict(why) => why,
            other => panic!("{stub:?}: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_silent_cl_verify_is_no_verdict_at_the_deadline() {
        let why = no_verdict_by_the_deadline(Stub::Silent).await;
        assert!(why.contains("deadline"), "{why}");
        let served = StubVerify::start(Stub::Silent);
        let client = served.kzg_client().await;
        let cells = column(1);
        let outcome = client.verify_cells(cells, Duration::from_millis(50)).await;
        assert!(matches!(outcome, KzgOutcome::NoVerdict(_)));
        assert_eq!(client.fence_metrics().counts().ignored, 1, "failed locally");
        no_verdict_by_the_deadline(Stub::Mute).await;
    }

    #[tokio::test]
    async fn a_hello_without_generation_is_refused() {
        let why = no_verdict_by_the_deadline(Stub::ZeroGeneration).await;
        assert!(why.contains("generation 0"), "{why}");
    }

    #[tokio::test]
    async fn a_stream_that_ends_fails_its_calls_and_the_next_call_reopens() {
        let served = StubVerify::start(Stub::HangsUp);
        let client = served.kzg_client().await;
        for _ in 0..2 {
            let outcome = client.verify_cells(column(1), TIMEOUT).await;
            assert!(matches!(outcome, KzgOutcome::NoVerdict(_)), "{outcome:?}");
        }
        assert_eq!(
            served.streams_opened(),
            2,
            "the second call opened a new stream"
        );
    }

    #[tokio::test]
    async fn an_unfenced_valid_answer_is_never_valid() {
        let served = StubVerify::start(Stub::Unfenced);
        let client = served.kzg_client().await;
        let outcome = client.verify_cells(column(1), TIMEOUT).await;
        assert!(matches!(outcome, KzgOutcome::NoVerdict(_)), "{outcome:?}");
        assert_eq!(client.fence_metrics().counts().violations, 1);
    }

    #[tokio::test]
    async fn a_second_hello_fails_the_stream() {
        let served = StubVerify::start(Stub::HelloTwice);
        let client = served.kzg_client().await;
        let outcome = client.verify_cells(column(1), TIMEOUT).await;
        assert!(matches!(outcome, KzgOutcome::NoVerdict(_)), "{outcome:?}");
    }

    #[test]
    fn only_valid_is_valid_and_an_err_wins() {
        use ethswarm_proto::common::{Error, ErrorCode};
        let answer = |status: i32| VerifyKzgResponseBody {
            request_id: 1,
            status,
            err: None,
            fence: None,
        };
        assert_eq!(
            outcome(&answer(VerifyStatus::Valid as i32)),
            KzgOutcome::Valid
        );
        for invalid in [VerifyStatus::Invalid, VerifyStatus::DecodeError] {
            assert_eq!(outcome(&answer(invalid as i32)), KzgOutcome::Invalid);
        }
        for none in [
            VerifyStatus::Unspecified as i32,
            VerifyStatus::DeadlineExceeded as i32,
            VerifyStatus::Overloaded as i32,
            VerifyStatus::UnknownIndex as i32,
            99,
        ] {
            let got = outcome(&answer(none));
            assert!(matches!(got, KzgOutcome::NoVerdict(_)), "{none}: {got:?}");
        }
        let mut failed = answer(VerifyStatus::Valid as i32);
        failed.err = Some(Error {
            code: ErrorCode::ResourceUnavailable as i32,
            detail: "busy".into(),
        });
        assert!(matches!(outcome(&failed), KzgOutcome::NoVerdict(_)));
    }
}
