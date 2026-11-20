//! cl-chain's `ethswarm.verify.v1` stream clients: `VerifyKzg` ([`KzgClient`]) and `VerifyBls`
//! ([`BlsClient`]).
//!
//! cl-chain never runs KZG or BLS itself: it sends cells or signature sets to cl-verify and maps
//! the answer to a [`KzgOutcome`] or a [`BlsOutcome`]. Only `VERIFY_STATUS_VALID` is valid;
//! `INVALID` and `DECODE_ERROR` are invalid. Everything that is not a verdict is no verdict,
//! never valid: no answer by the deadline, a stream that cannot be opened or ends, a hello that
//! does not match ours, a fence violation, an `err` result, `DEADLINE_EXCEEDED`, `OVERLOADED`,
//! `UNKNOWN_INDEX`, `UNSPECIFIED` or a status this build does not know (`proto/README.md`: a
//! timeout, overload or unavailable core is never ACCEPT).
//!
//! Each client has one stream at a time. It is opened at the first call: our hello first, then
//! cl-verify's, compared in full ([`ipc::hello::negotiate`]) and carrying the stream's server
//! generation. A network client ([`KzgClient::network`]) computes its hello again at each
//! stream open, with the fork digest of the wall clock at that time
//! ([`NetworkHello::at`]), as cl-verify does. So a stream opened after a fork or BPO epoch
//! carries the new digest. We read the clock before the hello goes out and cl-verify reads its
//! clock after the hello comes in, so a boundary between the two reads refuses the stream with
//! `VERSION_MISMATCH`. The client then reads its clock again and, if the digest changed, opens
//! again one time within the same deadline. Before genesis or Fulu there is no digest, and the
//! call is no verdict without a stream.
//!
//! Every request is fenced with the stream's generation ([`ipc::deadline::Calls`]): its
//! `request_id`, the generation, and a response settled only through its fence. cl-verify fails a
//! stream whose `request_id` does not increase, so a call holds the stream's send lock from
//! reserving its frame's place on the stream until the frame is sent, and only then waits for its
//! verdict. It takes its id only once that place is reserved, and sends without waiting: a call
//! that is cancelled, or runs out of time, before its send holds no id. A call whose deadline
//! passed sends nothing. A call dropped after its send keeps its id until cl-verify's answer
//! settles it, as one past its deadline does; cl-verify answers every request it reads
//! (`DEADLINE_EXCEEDED` when too late). A reader task delivers the
//! responses; when the stream ends, errs or breaks the contract, every call on it fails as no
//! verdict and the next call opens a new stream. At most [`DEFAULT_MAX_OUTSTANDING`] requests are
//! in flight on a stream; a call past that is no verdict, never queued without bound. On a
//! VerifyKzg stream, a request whose deadline passed still counts until its late answer arrives
//! ([`ipc::fence::Outstanding`]), so a cl-verify that stops answering makes every call no verdict
//! until it answers again or the stream ends.
//!
//! Each call carries its deadline twice: on the wire (`deadline_unix_ms`, so cl-verify drops work
//! it cannot finish in time) and locally, over the whole call, the stream's opening included.
//!
//! # VerifyBls
//!
//! [`BlsClient`] serves block import (`VERIFY_ORIGIN_IMPORT`). It splits a batch into requests
//! within the caps of verify.v1, in order: at most [`MAX_BLS_SETS`] sets, [`MAX_BLS_SIGNERS`]
//! signers, [`MAX_INLINE_KEYS`] inline keys (a request of one set can carry more) and
//! [`MAX_BLS_MESSAGE_BYTES`] encoded. A set that does not fit alone makes the whole batch no
//! verdict: a batch is never sent in part. The caller gives the deadline as an instant, not as a
//! duration, so the calls of one import share the deadline of that import. The requests of a
//! batch share it too, and the batch is valid only if each request is. A request without an
//! answer closes its stream when its deadline passes or when its call is dropped first (a
//! stalled VerifyBls stream must close, and a dropped call must not keep its slot in the window),
//! and the next call opens a new one. Only a request that went out does that: a call that ends
//! before it takes its id (cancelled or out of time at the send lock or the queue) leaves the
//! stream to the requests on it.

use ethswarm_proto::common::{ErrorCode, Hello};
use ethswarm_proto::verify::verify_service_client::VerifyServiceClient;
use ethswarm_proto::verify::{
    bls_result, verify_bls_request, verify_bls_response, verify_kzg_request, verify_kzg_response,
    BlsSet, KzgCellProof, Signer, VerifyBlsRequest, VerifyBlsRequestBody, VerifyBlsResponse,
    VerifyBlsResponseBody, VerifyKzgRequest, VerifyKzgRequestBody, VerifyKzgResponse,
    VerifyKzgResponseBody, VerifyOrigin, VerifyStatus,
};
use ipc::deadline::{Calls, FenceMetrics, Ignored, Pending};
use ipc::fence::{FencedRequest, FencedResult, ItemHash, RequestTag};
use ipc::hello::{negotiate, Generation, NetworkHello, API_VERSION_V1};
use prost::Message;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tonic::Streaming;

/// Requests in flight on one stream \[est\]: a block's custody columns several times over.
pub const DEFAULT_MAX_OUTSTANDING: usize = 64;
/// verify.v1: the most sets in one `VerifyBlsRequestBody`.
pub const MAX_BLS_SETS: usize = 256;
/// verify.v1: the most signers across the sets of one VerifyBls request
/// (`MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`, so one maximal set fits alone).
pub const MAX_BLS_SIGNERS: usize = 131_072;
/// verify.v1: the most inline keys (validator and builder) in one import request of more than
/// one set.
pub const MAX_INLINE_KEYS: usize = 1_024;
/// verify.v1: the largest encoded VerifyBls request message, 4 MiB.
pub const MAX_BLS_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Room in a VerifyBls request message for all but its sets: the frame and body tags,
/// `request_id`, `deadline_unix_ms`, `origin` and `generation`.
const BLS_REQUEST_OVERHEAD: usize = 64;

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

/// What cl-verify said about one batch of BLS signature sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlsOutcome {
    /// `VERIFY_STATUS_VALID` for every set.
    Valid,
    /// `VERIFY_STATUS_INVALID` or `VERIFY_STATUS_DECODE_ERROR` for at least one set: a proven
    /// bad batch.
    Invalid,
    /// No verdict: why, for the log. Never valid.
    NoVerdict(String),
}

/// What a caller keeps charged for a request's cells (the column store's copy budget), handed
/// to [`KzgVerifier::verify_cells_holding`] and dropped once the cells are gone.
pub type Held = Box<dyn Send>;

/// Checks cells by KZG, through cl-verify.
pub trait KzgVerifier: Send + Sync {
    /// `verify_cell_kzg_proof_batch` over `cells`, with a verdict within `timeout` or none.
    fn verify_cells(
        &self,
        cells: Vec<KzgCellProof>,
        timeout: Duration,
    ) -> impl Future<Output = KzgOutcome> + Send;

    /// [`Self::verify_cells`], dropping `held` once `cells` are no longer held anywhere. By
    /// default that is when the call returns; a verifier that queues the cells past its call
    /// (the [`KzgClient`]) keeps `held` with them until they leave its queue.
    fn verify_cells_holding(
        &self,
        cells: Vec<KzgCellProof>,
        timeout: Duration,
        held: Held,
    ) -> impl Future<Output = KzgOutcome> + Send {
        async move {
            let outcome = self.verify_cells(cells, timeout).await;
            drop(held);
            outcome
        }
    }
}

/// Checks the BLS signature sets of a block import, through cl-verify.
pub trait BlsVerifier: Send + Sync {
    /// One verdict for all of `sets` by `deadline`, or none. The caller gives each call of one
    /// import the same `deadline`, so a later call does not get a new budget.
    fn verify_sets(
        &self,
        sets: Vec<BlsSet>,
        deadline: Instant,
    ) -> impl Future<Output = BlsOutcome> + Send;
}

/// One verify.v1 stream method: its frames, and how a stream of it opens.
trait Method: Send + Sync + 'static {
    /// A frame that cl-chain sends.
    type Request: Send + 'static;
    /// A frame that cl-verify sends.
    type Response: Send + 'static;
    /// The body of a response, settled through its fences.
    type Body: FencedResult + Send + 'static;
    /// The method name, for logs and no-verdict reasons.
    const NAME: &'static str;
    /// Our hello frame.
    fn hello(hello: Hello) -> Self::Request;
    /// What a response frame holds.
    fn received(response: Self::Response) -> Received<Self::Body>;
    /// Opens the stream on `client`, with `requests` as its outbound frames.
    fn open<S>(
        client: VerifyServiceClient<Channel>,
        requests: S,
    ) -> impl Future<Output = Opened<Self::Response>> + Send
    where
        S: tokio_stream::Stream<Item = Self::Request> + Send + 'static;
}

/// A stream that opened, or the status it failed with.
type Opened<R> = Result<tonic::Response<Streaming<R>>, tonic::Status>;

/// A response frame.
enum Received<B> {
    Hello(Hello),
    Body(B),
    /// A frame with no `oneof` set.
    Empty,
}

/// `VerifyKzg`.
struct Kzg;

impl Method for Kzg {
    type Request = VerifyKzgRequest;
    type Response = VerifyKzgResponse;
    type Body = VerifyKzgResponseBody;
    const NAME: &'static str = "VerifyKzg";

    fn hello(hello: Hello) -> VerifyKzgRequest {
        VerifyKzgRequest {
            frame: Some(verify_kzg_request::Frame::Hello(hello)),
        }
    }

    fn received(response: VerifyKzgResponse) -> Received<VerifyKzgResponseBody> {
        match response.frame {
            Some(verify_kzg_response::Frame::Hello(hello)) => Received::Hello(hello),
            Some(verify_kzg_response::Frame::Body(body)) => Received::Body(body),
            None => Received::Empty,
        }
    }

    async fn open<S>(
        mut client: VerifyServiceClient<Channel>,
        requests: S,
    ) -> Opened<VerifyKzgResponse>
    where
        S: tokio_stream::Stream<Item = VerifyKzgRequest> + Send + 'static,
    {
        client.verify_kzg(requests).await
    }
}

/// `VerifyBls`.
struct Bls;

impl Method for Bls {
    type Request = VerifyBlsRequest;
    type Response = VerifyBlsResponse;
    type Body = VerifyBlsResponseBody;
    const NAME: &'static str = "VerifyBls";

    fn hello(hello: Hello) -> VerifyBlsRequest {
        VerifyBlsRequest {
            frame: Some(verify_bls_request::Frame::Hello(hello)),
        }
    }

    fn received(response: VerifyBlsResponse) -> Received<VerifyBlsResponseBody> {
        match response.frame {
            Some(verify_bls_response::Frame::Hello(hello)) => Received::Hello(hello),
            Some(verify_bls_response::Frame::Body(body)) => Received::Body(body),
            None => Received::Empty,
        }
    }

    async fn open<S>(
        mut client: VerifyServiceClient<Channel>,
        requests: S,
    ) -> Opened<VerifyBlsResponse>
    where
        S: tokio_stream::Stream<Item = VerifyBlsRequest> + Send + 'static,
    {
        client.verify_bls(requests).await
    }
}

/// One frame of the outbound queue, and what it holds charged until it leaves the queue.
struct Queued<M: Method> {
    request: M::Request,
    _held: Option<Held>,
}

/// A frame of the VerifyKzg queue.
type Outbound = Queued<Kzg>;

impl From<VerifyKzgRequest> for Outbound {
    fn from(request: VerifyKzgRequest) -> Self {
        Self {
            request,
            _held: None,
        }
    }
}

/// The outbound queue as the stream tonic sends: each frame drops what it holds as it is taken
/// off the queue to be sent, and every frame still queued drops it with the stream.
fn outbound_frames<M: Method>(
    outbound: mpsc::Receiver<Queued<M>>,
) -> impl tokio_stream::Stream<Item = M::Request> + Send + 'static {
    ReceiverStream::new(outbound).map(|frame| frame.request)
}

/// Unix milliseconds of a wall clock.
pub type UnixClock = Arc<dyn Fn() -> u128 + Send + Sync>;

/// The hello a client opens each stream with.
enum OurHello {
    /// The same hello on every stream.
    Fixed(Hello),
    /// The network's hello at the time of `clock` when the stream opens.
    Network {
        network: Arc<NetworkHello>,
        clock: UnixClock,
    },
}

impl OurHello {
    /// The hello for a stream that opens now.
    fn now(&self) -> Result<Hello, String> {
        match self {
            Self::Fixed(hello) => Ok(hello.clone()),
            Self::Network { network, clock } => network
                .at(clock())
                .map_err(|e| format!("no fork digest yet: {e}")),
        }
    }
}

/// cl-chain's VerifyKzg client (see the module docs).
pub struct KzgClient {
    streams: Streams<Kzg>,
}

/// cl-chain's VerifyBls client for block import (see the module docs).
pub struct BlsClient {
    streams: Streams<Bls>,
}

/// The stream of one method: its hello, its fencing and the open stream.
struct Streams<M: Method> {
    client: VerifyServiceClient<Channel>,
    hello: OurHello,
    max_outstanding: usize,
    metrics: Arc<FenceMetrics>,
    stream: Mutex<Option<VerifyStream<M>>>,
}

/// A stream's outbound queue. Closed for good once the stream ends: its sender is taken, so the
/// queue, with any frame a call sent into it after the stream stopped taking them, is dropped as
/// soon as the calls still holding a sender return, not when the stream is next replaced.
struct Queue<M: Method>(Arc<std::sync::Mutex<Option<mpsc::Sender<Queued<M>>>>>);

/// The VerifyKzg queue.
#[cfg(test)]
type Requests = Queue<Kzg>;

impl<M: Method> Clone for Queue<M> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<M: Method> Queue<M> {
    fn new(sender: mpsc::Sender<Queued<M>>) -> Self {
        Self(Arc::new(std::sync::Mutex::new(Some(sender))))
    }

    /// A sender for one call, while the queue is open.
    fn sender(&self) -> Option<mpsc::Sender<Queued<M>>> {
        self.slot().clone()
    }

    fn close(&self) {
        drop(self.slot().take());
    }

    fn is_closed(&self) -> bool {
        self.slot().as_ref().is_none_or(mpsc::Sender::is_closed)
    }

    /// The slot holds a sender or none: nothing a panic could leave half-set.
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<mpsc::Sender<Queued<M>>>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What a call uses of the open stream.
struct StreamLink<M: Method> {
    requests: Queue<M>,
    calls: Calls<M::Body>,
    /// Held from reserving a frame's place through taking its `request_id` and sending it, so
    /// the ids go out in the order they were taken.
    send: Arc<Mutex<()>>,
}

impl<M: Method> Clone for StreamLink<M> {
    fn clone(&self) -> Self {
        Self {
            requests: self.requests.clone(),
            calls: self.calls.clone(),
            send: Arc::clone(&self.send),
        }
    }
}

/// What a VerifyKzg call uses of the open stream.
type Link = StreamLink<Kzg>;

/// The answer to a request that went out, until `deadline`.
async fn answer<M: Method>(
    pending: Pending<M::Body>,
    deadline: Instant,
) -> Result<M::Body, Failure> {
    match pending.wait_until(deadline).await {
        Ok(body) => Ok(body),
        Err(Ignored::Deadline) => Err(Failure::Late),
        Err(Ignored::Reconnect) => Err(Failure::Other(format!("the {} stream ended", M::NAME))),
    }
}

/// Why a call has no answer.
enum Failure {
    /// The deadline passed.
    Late,
    /// Anything else: why, for the log.
    Other(String),
}

impl Failure {
    fn why(self) -> String {
        match self {
            Self::Late => LATE.into(),
            Self::Other(why) => why,
        }
    }
}

/// The no-verdict reason of a call that ran out of time.
const LATE: &str = "no verdict by the deadline";

impl<M: Method> StreamLink<M> {
    /// Sends the request that `build` makes for its tag on this stream, and waits for its
    /// answer until `deadline`. `held` goes into the queue with the frame, and is dropped when
    /// the frame leaves it; a call that queues nothing drops it on return.
    async fn exchange(
        &self,
        build: impl FnOnce(RequestTag) -> (M::Request, Vec<ItemHash>),
        deadline: Instant,
        held: Held,
    ) -> Result<M::Body, Failure> {
        let pending = self.send(build, deadline, held).await?;
        answer::<M>(pending, deadline).await
    }

    /// Sends the request that `build` makes for its tag on this stream, and returns the wait
    /// for its answer. `Err` if it sends nothing: the stream is closed, or `deadline` passed
    /// first. Such a call holds no id.
    async fn send(
        &self,
        build: impl FnOnce(RequestTag) -> (M::Request, Vec<ItemHash>),
        deadline: Instant,
        held: Held,
    ) -> Result<Pending<M::Body>, Failure> {
        // Ids go out in the order they are taken: the lock is held from reserving the frame's
        // place through sending it. The verdict is awaited without it.
        let Ok(_send) = tokio::time::timeout_at(deadline, self.send.lock()).await else {
            return Err(Failure::Late);
        };
        let closed = || {
            self.requests.close();
            self.calls.close();
            Failure::Other(format!("the {} stream is closed", M::NAME))
        };
        let Some(sender) = self.requests.sender() else {
            return Err(closed());
        };
        // The frame's place on the stream first, so an id is taken only once its send is
        // certain: a call cancelled or out of time before then holds no id.
        let permit = match tokio::time::timeout_at(deadline, sender.reserve()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(closed()),
            Err(_) => return Err(Failure::Late),
        };
        // A seam where a test cancels a call that has its frame's place and no id yet.
        #[cfg(test)]
        tokio::task::yield_now().await;
        // `timeout_at` polls before its timer, so the lock and the place can come at or after
        // the deadline. Such a request could not be answered in time: it does not go out.
        if Instant::now() >= deadline {
            return Err(Failure::Late);
        }
        let (request, pending) = self
            .calls
            .start(build)
            .map_err(|e| Failure::Other(format!("not sent: {e}")))?;
        permit.send(Queued {
            request,
            _held: Some(held),
        });
        Ok(pending)
    }

    /// Whether `other` uses the same stream.
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.send, &other.send)
    }
}

impl Link {
    /// Sends one request for `cells` on this stream and waits for its verdict until `deadline`.
    async fn request(
        &self,
        cells: Vec<KzgCellProof>,
        deadline: Instant,
        unix_ms: u64,
        held: Held,
    ) -> KzgOutcome {
        let build = |tag: RequestTag| {
            let body = VerifyKzgRequestBody {
                request_id: tag.request_id,
                cells,
                deadline_unix_ms: unix_ms,
                generation: tag.generation.get(),
            };
            let hashes = body.item_hashes();
            let request = VerifyKzgRequest {
                frame: Some(verify_kzg_request::Frame::Body(body)),
            };
            (request, hashes)
        };
        match self.exchange(build, deadline, held).await {
            Ok(body) => outcome(&body),
            Err(failure) => KzgOutcome::NoVerdict(failure.why()),
        }
    }
}

/// One open stream.
struct VerifyStream<M: Method> {
    link: StreamLink<M>,
    reader: JoinHandle<()>,
}

impl<M: Method> VerifyStream<M> {
    fn is_live(&self) -> bool {
        !self.reader.is_finished() && !self.link.requests.is_closed()
    }
}

impl<M: Method> std::ops::Drop for VerifyStream<M> {
    fn drop(&mut self) {
        self.reader.abort();
        self.link.requests.close();
        self.link.calls.close();
    }
}

impl KzgClient {
    /// A client that opens each stream on `client` with the same `hello`. Its
    /// `current_fork_digest` does not follow the clock, so use it only for a link without a
    /// network; a client of a network is [`Self::network`].
    #[must_use]
    pub fn new(client: VerifyServiceClient<Channel>, hello: Hello) -> Self {
        Self {
            streams: Streams::new(client, OurHello::Fixed(hello)),
        }
    }

    /// A client that opens each stream on `client` with `network`'s hello at the system clock
    /// when the stream opens.
    #[must_use]
    pub fn network(client: VerifyServiceClient<Channel>, network: Arc<NetworkHello>) -> Self {
        Self::network_with_clock(client, network, Arc::new(|| u128::from(now_unix_ms())))
    }

    /// [`Self::network`] on `clock` (Unix milliseconds) in place of the system clock.
    #[must_use]
    pub fn network_with_clock(
        client: VerifyServiceClient<Channel>,
        network: Arc<NetworkHello>,
        clock: UnixClock,
    ) -> Self {
        Self {
            streams: Streams::new(client, OurHello::Network { network, clock }),
        }
    }

    /// The fencing counters of every stream this client opened: late results, violations and
    /// calls failed locally.
    #[must_use]
    pub fn fence_metrics(&self) -> &Arc<FenceMetrics> {
        &self.streams.metrics
    }

    async fn call(
        &self,
        cells: Vec<KzgCellProof>,
        deadline: Instant,
        unix_ms: u64,
        held: Held,
    ) -> KzgOutcome {
        match tokio::time::timeout_at(deadline, self.live()).await {
            Ok(Ok(link)) => link.request(cells, deadline, unix_ms, held).await,
            Ok(Err(why)) => KzgOutcome::NoVerdict(why),
            Err(_) => no_verdict_by_the_deadline(),
        }
    }

    /// The open stream's link, opening a new stream if there is none or it ended.
    async fn live(&self) -> Result<Link, String> {
        self.streams.live().await
    }
}

impl BlsClient {
    /// A client that opens each stream on `client` with the same `hello`, as
    /// [`KzgClient::new`]. A client that follows the fork digest of the clock comes with the
    /// import service that runs it.
    #[must_use]
    pub fn new(client: VerifyServiceClient<Channel>, hello: Hello) -> Self {
        Self {
            streams: Streams::new(client, OurHello::Fixed(hello)),
        }
    }

    /// Sends one request of `sets` and waits for its verdict until `deadline`. A request
    /// without an answer by then, or whose call is dropped before its answer, closes its stream.
    /// A call that sends nothing leaves the stream as it is.
    async fn request(&self, sets: Vec<BlsSet>, deadline: Instant, unix_ms: u64) -> BlsOutcome {
        if Instant::now() >= deadline {
            return BlsOutcome::NoVerdict(LATE.into());
        }
        let link = match tokio::time::timeout_at(deadline, self.streams.live()).await {
            Ok(Ok(link)) => link,
            Ok(Err(why)) => return BlsOutcome::NoVerdict(why),
            Err(_) => return BlsOutcome::NoVerdict(LATE.into()),
        };
        let build = |tag: RequestTag| {
            let body = VerifyBlsRequestBody {
                request_id: tag.request_id,
                sets,
                deadline_unix_ms: unix_ms,
                origin: VerifyOrigin::Import as i32,
                generation: tag.generation.get(),
            };
            let hashes = body.item_hashes();
            let request = VerifyBlsRequest {
                frame: Some(verify_bls_request::Frame::Body(body)),
            };
            (request, hashes)
        };
        // Not sent: the call holds no id, so there is no request on the stream to close it for.
        let pending = match link.send(build, deadline, Box::new(())).await {
            Ok(pending) => pending,
            Err(failure) => return BlsOutcome::NoVerdict(failure.why()),
        };
        // The request is on the stream from here, with no await before: until it is settled,
        // a drop or a late answer closes the stream.
        let mut unsettled = Unsettled {
            streams: &self.streams,
            link: &link,
            settled: false,
        };
        let outcome = match answer::<Bls>(pending, deadline).await {
            Ok(body) => bls_outcome(&body),
            // `unsettled` closes the stream on its drop.
            Err(Failure::Late) => return BlsOutcome::NoVerdict(LATE.into()),
            // The stream ended: there is no request on it to wait for.
            Err(Failure::Other(why)) => BlsOutcome::NoVerdict(why),
        };
        unsettled.settled = true;
        outcome
    }
}

/// A VerifyBls request in flight. Dropped before it is settled (late, or its call dropped), it
/// closes its stream: cl-verify may never answer, and the request must not keep its slot in
/// the window of that stream.
struct Unsettled<'a> {
    streams: &'a Streams<Bls>,
    link: &'a StreamLink<Bls>,
    settled: bool,
}

impl Drop for Unsettled<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.streams.close(self.link);
        }
    }
}

impl BlsVerifier for BlsClient {
    async fn verify_sets(&self, sets: Vec<BlsSet>, deadline: Instant) -> BlsOutcome {
        let requests = match bls_requests(sets) {
            Ok(requests) => requests,
            Err(why) => return BlsOutcome::NoVerdict(why),
        };
        let left = deadline.saturating_duration_since(Instant::now());
        let left_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
        let unix_ms = now_unix_ms().saturating_add(left_ms);
        for sets in requests {
            let outcome = self.request(sets, deadline, unix_ms).await;
            if outcome != BlsOutcome::Valid {
                return outcome;
            }
        }
        BlsOutcome::Valid
    }
}

/// The load of one VerifyBls request.
#[derive(Clone, Copy, Default)]
struct Load {
    sets: usize,
    signers: usize,
    inline: usize,
    bytes: usize,
}

impl Load {
    fn of(set: &BlsSet) -> Self {
        let len = set.encoded_len();
        Self {
            sets: 1,
            signers: set.signers.len(),
            inline: set.signers.iter().filter(|s| is_inline(s)).count(),
            // The field tag, the length and the set.
            bytes: 1 + prost::length_delimiter_len(len) + len,
        }
    }

    fn and(self, other: Self) -> Self {
        Self {
            sets: self.sets + other.sets,
            signers: self.signers + other.signers,
            inline: self.inline + other.inline,
            bytes: self.bytes + other.bytes,
        }
    }

    /// Whether one request with this load is within the caps of verify.v1.
    fn fits(self) -> bool {
        self.sets <= MAX_BLS_SETS
            && self.signers <= MAX_BLS_SIGNERS
            && (self.sets <= 1 || self.inline <= MAX_INLINE_KEYS)
            && self.bytes + BLS_REQUEST_OVERHEAD <= MAX_BLS_MESSAGE_BYTES
    }
}

/// A validator signer with an inline key, or a builder signer marked inline.
fn is_inline(signer: &Signer) -> bool {
    !signer.inline_pubkey.is_empty() || signer.builder.as_ref().is_some_and(|b| b.inline)
}

/// `sets` split into requests within the caps of verify.v1, in order (see the module docs).
/// `Err` for an empty batch, and for a set with no signer or that does not fit in a request
/// alone: no part of such a batch goes out.
fn bls_requests(sets: Vec<BlsSet>) -> Result<Vec<Vec<BlsSet>>, String> {
    if sets.is_empty() {
        return Err("no sets".into());
    }
    let mut requests: Vec<Vec<BlsSet>> = Vec::new();
    let mut load = Load::default();
    for set in sets {
        let one = Load::of(&set);
        if one.signers == 0 || !one.fits() {
            return Err(format!(
                "a set of {} signers and {} bytes does not fit in a VerifyBls request",
                one.signers, one.bytes
            ));
        }
        let more = load.and(one);
        match requests.last_mut() {
            Some(last) if more.fits() => {
                last.push(set);
                load = more;
            }
            _ => {
                requests.push(vec![set]);
                load = one;
            }
        }
    }
    Ok(requests)
}

/// The outcome of a settled VerifyBls response: invalid if a set is invalid, else valid only
/// if every set is valid.
fn bls_outcome(body: &VerifyBlsResponseBody) -> BlsOutcome {
    let mut outcome = BlsOutcome::Valid;
    if body.results.is_empty() {
        outcome = BlsOutcome::NoVerdict("no results".into());
    }
    for result in &body.results {
        let status = match result.result {
            Some(bls_result::Result::Status(status)) => VerifyStatus::try_from(status).ok(),
            _ => None,
        };
        match status {
            Some(VerifyStatus::Valid) => {}
            Some(VerifyStatus::Invalid | VerifyStatus::DecodeError) => return BlsOutcome::Invalid,
            _ => {
                if status == Some(VerifyStatus::Unspecified) {
                    tracing::warn!("contract violation: VERIFY_STATUS_UNSPECIFIED from cl-verify");
                }
                outcome =
                    BlsOutcome::NoVerdict(format!("a set has no verdict: {:?}", result.result));
            }
        }
    }
    outcome
}

impl<M: Method> Streams<M> {
    fn new(client: VerifyServiceClient<Channel>, hello: OurHello) -> Self {
        Self {
            client,
            hello,
            max_outstanding: DEFAULT_MAX_OUTSTANDING,
            metrics: Arc::default(),
            stream: Mutex::new(None),
        }
    }

    /// The open stream's link, opening a new stream if there is none or it ended.
    async fn live(&self) -> Result<StreamLink<M>, String> {
        let mut slot = self.stream.lock().await;
        if let Some(stream) = slot.as_ref().filter(|s| s.is_live()) {
            return Ok(stream.link.clone());
        }
        *slot = None;
        let ours = self.hello.now()?;
        let stream = match self.open(&ours).await {
            Ok(stream) => stream,
            // Our clock was read before the hello went out, cl-verify's after it came in: a
            // boundary in between refuses the stream. Read the clock again, and open again one
            // time if the digest changed. The caller's deadline covers both opens.
            Err(refused) if refused.version_mismatch => {
                let again = self.hello.now()?;
                if again.current_fork_digest == ours.current_fork_digest {
                    return Err(refused.why);
                }
                tracing::debug!(
                    method = M::NAME,
                    why = %refused.why,
                    "verify.v1 stream refused across a digest change; opening again"
                );
                self.open(&again).await.map_err(|e| e.why)?
            }
            Err(failed) => return Err(failed.why),
        };
        let link = stream.link.clone();
        *slot = Some(stream);
        Ok(link)
    }

    /// Closes the stream of `link`: no call sends on it again, every call that waits on it is
    /// no verdict, and its reader stops. A stream that a concurrent call holds open stops when
    /// that call finds it closed and opens a new one.
    fn close(&self, link: &StreamLink<M>) {
        link.requests.close();
        link.calls.close();
        if let Ok(mut slot) = self.stream.try_lock() {
            if slot.as_ref().is_some_and(|s| s.link.same(link)) {
                *slot = None;
            }
        }
    }

    /// Opens a stream: `ours`, then cl-verify's hello, compared in full.
    async fn open(&self, ours: &Hello) -> Result<VerifyStream<M>, OpenFailure> {
        let (requests, outbound) = mpsc::channel(self.max_outstanding);
        requests
            .send(Queued {
                request: M::hello(ours.clone()),
                _held: None,
            })
            .await
            .map_err(|_| OpenFailure::other(format!("the {} stream is closed", M::NAME)))?;
        let mut responses = M::open(self.client.clone(), outbound_frames(outbound))
            .await
            .map_err(|s| OpenFailure::status(M::NAME, &s))?
            .into_inner();
        let first = responses
            .message()
            .await
            .map_err(|s| OpenFailure::status(M::NAME, &s))?
            .ok_or_else(|| {
                OpenFailure::other(format!("{} ended before cl-verify's hello", M::NAME))
            })?;
        let Received::Hello(server) = M::received(first) else {
            tracing::warn!(
                method = M::NAME,
                "contract violation: cl-verify's first frame is not hello"
            );
            return Err(OpenFailure::other(format!(
                "cl-verify's first {} frame is not hello",
                M::NAME
            )));
        };
        negotiate(ours, &server, API_VERSION_V1).map_err(|e| OpenFailure {
            version_mismatch: e.code() == ErrorCode::VersionMismatch,
            why: e.to_string(),
        })?;
        let generation =
            Generation::from_hello(&server).map_err(|e| OpenFailure::other(e.to_string()))?;
        let calls =
            Calls::with_metrics(generation, self.max_outstanding, Arc::clone(&self.metrics));
        let requests = Queue::new(requests);
        let reader = tokio::spawn(read::<M>(responses, calls.clone(), requests.clone()));
        Ok(VerifyStream {
            link: StreamLink {
                requests,
                calls,
                send: Arc::default(),
            },
            reader,
        })
    }
}

/// Why a stream did not open.
struct OpenFailure {
    /// For the log and the no-verdict reason.
    why: String,
    /// The hellos differ (`ERROR_CODE_VERSION_MISMATCH`, from cl-verify or from our check).
    version_mismatch: bool,
}

impl OpenFailure {
    fn other(why: impl Into<String>) -> Self {
        Self {
            why: why.into(),
            version_mismatch: false,
        }
    }

    /// The status cl-verify failed the stream of `method` with, by its `common.v1.Error`.
    fn status(method: &str, status: &tonic::Status) -> Self {
        let err = ipc::error::error_from_status(status);
        Self {
            why: format!("{method}: {:?}: {}", err.code(), err.detail),
            version_mismatch: err.code() == ErrorCode::VersionMismatch,
        }
    }
}

impl KzgVerifier for KzgClient {
    async fn verify_cells(&self, cells: Vec<KzgCellProof>, timeout: Duration) -> KzgOutcome {
        self.verify_cells_holding(cells, timeout, Box::new(()))
            .await
    }

    /// `held` stays with the request's frame until it leaves the outbound queue: a call that
    /// runs out of time leaves its frame queued, cells and all.
    async fn verify_cells_holding(
        &self,
        cells: Vec<KzgCellProof>,
        timeout: Duration,
        held: Held,
    ) -> KzgOutcome {
        if cells.is_empty() {
            // An empty batch verifies vacuously; it is never sent and never valid.
            return KzgOutcome::NoVerdict("no cells".into());
        }
        let deadline = Instant::now() + timeout;
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.call(
            cells,
            deadline,
            now_unix_ms().saturating_add(timeout_ms),
            held,
        )
        .await
    }
}

/// Delivers every response body of a stream to its calls until the stream ends, errs or
/// breaks the contract; then fails the calls still waiting.
async fn read<M: Method>(
    mut responses: Streaming<M::Response>,
    calls: Calls<M::Body>,
    requests: Queue<M>,
) {
    loop {
        match responses.message().await {
            Ok(Some(frame)) => {
                let Received::Body(body) = M::received(frame) else {
                    tracing::warn!(
                        method = M::NAME,
                        "contract violation: a frame after hello is not a body"
                    );
                    break;
                };
                if calls.deliver_body(body).is_err() {
                    // A fence violation: logged by `deliver_body`; the stream is failed.
                    break;
                }
            }
            Ok(None) => break,
            Err(status) => {
                tracing::debug!(method = M::NAME, %status, "verify.v1 stream failed");
                break;
            }
        }
    }
    // Nothing more is taken off the queue: close it, so what is left in it is dropped.
    requests.close();
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

/// The outcome of a call that ran out of time.
fn no_verdict_by_the_deadline() -> KzgOutcome {
    KzgOutcome::NoVerdict(LATE.into())
}

/// Wall-clock ms since the Unix epoch, as `deadline_unix_ms` counts them.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
#[path = "bls_tests.rs"]
mod bls_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{blobs, ClVerify, ManualClock, Served, Stub, StubVerify};
    use cl_verify::handshake::Handshake;
    use ipc::testkit::devnet::{devnet_hello, devnet_ms};
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
    async fn calls_cancelled_before_their_send_hold_no_slot() {
        let served = ClVerify::start();
        let client = served.kzg_client().await;
        // One call first opens the stream, so each call below runs on it without waiting.
        assert_eq!(
            client.verify_cells(column(0), TIMEOUT).await,
            KzgOutcome::Valid
        );
        for _ in 0..=DEFAULT_MAX_OUTSTANDING {
            let call = client.verify_cells(column(0), TIMEOUT);
            // Polled once, the call stops at the seam before its send; then it is dropped.
            poll_pending(call, 1).await;
        }
        assert_eq!(
            client.verify_cells(column(47), TIMEOUT).await,
            KzgOutcome::Valid,
            "cancelled calls left the stream room for another"
        );
    }

    /// Polls `call` `polls` times, each time finding it still waiting.
    async fn poll_pending<F: Future>(call: F, polls: usize)
    where
        F::Output: std::fmt::Debug,
    {
        let mut call = std::pin::pin!(call);
        for poll in 0..polls {
            tokio::select! {
                biased;
                outcome = &mut call => panic!("the call finished at poll {poll}: {outcome:?}"),
                () = std::future::ready(()) => {}
            }
        }
    }

    #[tokio::test]
    async fn a_call_dropped_after_its_send_frees_its_slot_at_the_answer() {
        let served = ClVerify::start();
        let client = served.kzg_client().await;
        assert_eq!(
            client.verify_cells(column(0), TIMEOUT).await,
            KzgOutcome::Valid
        );
        // Twice polled, each call is sent and waiting for its verdict; then it is dropped.
        for _ in 0..DEFAULT_MAX_OUTSTANDING {
            poll_pending(client.verify_cells(column(0), TIMEOUT), 2).await;
        }
        let calls = client.live().await.unwrap().calls;
        let drained = tokio::time::timeout(TIMEOUT, async {
            while calls.outstanding() > 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        drained
            .await
            .expect("cl-verify answered every dropped call");
        assert_eq!(
            client.verify_cells(column(47), TIMEOUT).await,
            KzgOutcome::Valid
        );
    }

    #[tokio::test]
    async fn a_closed_stream_fails_the_call_and_its_calls() {
        let (requests, outbound) = mpsc::channel(1);
        let link = Link {
            requests: Requests::new(requests),
            calls: Calls::new(Generation::new(7).unwrap(), 2),
            send: Arc::default(),
        };
        drop(outbound);
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        let outcome = link.request(column(1), deadline, 0, Box::new(())).await;
        assert_eq!(
            outcome,
            KzgOutcome::NoVerdict("the VerifyKzg stream is closed".into())
        );
        let refused = link.calls.start(|_| ((), vec![[0; 32]])).unwrap_err();
        assert_eq!(
            refused.code(),
            ethswarm_proto::common::ErrorCode::ResourceUnavailable
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_queued_request_holds_its_charge_until_it_leaves_the_queue() {
        let (requests, outbound) = mpsc::channel(4);
        let link = Link {
            requests: Requests::new(requests),
            calls: Calls::new(Generation::new(7).unwrap(), 4),
            send: Arc::default(),
        };
        // cl-verify takes no frame: each call runs out of time with its frame still queued.
        let charges: Vec<_> = (0..2).map(|_| Arc::new(())).collect();
        for charge in &charges {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
            let held: Held = Box::new(Arc::clone(charge));
            let outcome = link.request(column(1), deadline, 0, held).await;
            assert_eq!(outcome, super::no_verdict_by_the_deadline());
            assert_eq!(Arc::strong_count(charge), 2, "queued: still charged");
        }
        // The first frame leaves the queue for the wire: its charge goes with it.
        let mut frames = outbound_frames(outbound);
        let frame = frames.next().await.unwrap();
        assert!(matches!(
            frame.frame,
            Some(verify_kzg_request::Frame::Body(_))
        ));
        assert_eq!(Arc::strong_count(&charges[0]), 1);
        assert_eq!(Arc::strong_count(&charges[1]), 2);
        // The stream is discarded with a frame still queued: that charge goes with it.
        drop((frames, link));
        assert_eq!(Arc::strong_count(&charges[1]), 1);
    }

    #[tokio::test]
    async fn a_frame_sent_into_an_ended_stream_is_released_when_its_queue_closes() {
        let (sender, outbound) = mpsc::channel(4);
        let requests = Requests::new(sender);
        let charge = Arc::new(());
        // A call reserved its frame's place just before the stream stopped taking frames, and
        // sends after: the frame is stranded in the queue.
        let call = requests.sender().unwrap();
        let permit = call.reserve().await.unwrap();
        drop(outbound);
        permit.send(Outbound {
            request: VerifyKzgRequest::default(),
            _held: Some(Box::new(Arc::clone(&charge))),
        });
        drop(call);
        assert_eq!(Arc::strong_count(&charge), 2, "stranded, still charged");
        assert!(requests.is_closed());
        // The stream's end closes the queue: the frame and its charge go with it.
        requests.close();
        assert_eq!(Arc::strong_count(&charge), 1);
        assert!(requests.sender().is_none());
    }

    /// A verifier without a queue of its own holds the charge until its call returns.
    #[tokio::test]
    async fn the_default_holds_the_charge_for_the_call() {
        struct Answers(Arc<()>);
        impl KzgVerifier for Answers {
            async fn verify_cells(&self, _: Vec<KzgCellProof>, _: Duration) -> KzgOutcome {
                assert_eq!(Arc::strong_count(&self.0), 3, "held during the call");
                KzgOutcome::Valid
            }
        }
        let charge = Arc::new(());
        let verifier = Answers(Arc::clone(&charge));
        let held: Held = Box::new(Arc::clone(&charge));
        let outcome = verifier
            .verify_cells_holding(column(1), TIMEOUT, held)
            .await;
        assert_eq!(outcome, KzgOutcome::Valid);
        assert_eq!(
            Arc::strong_count(&charge),
            2,
            "only the verifier's own copy"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_send_that_times_out_holds_no_slot() {
        let capacity = 2;
        let (requests, mut outbound) = mpsc::channel(1);
        let link = Link {
            requests: Requests::new(requests),
            calls: Calls::new(Generation::new(7).unwrap(), capacity),
            send: Arc::default(),
        };
        // The stream takes no frame: every send waits until its deadline.
        link.requests
            .sender()
            .unwrap()
            .try_send(VerifyKzgRequest::default().into())
            .unwrap();
        for _ in 0..=capacity {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
            let outcome = link.request(column(1), deadline, 0, Box::new(())).await;
            assert!(matches!(outcome, KzgOutcome::NoVerdict(_)), "{outcome:?}");
        }
        // The stream drains: the next request is sent, with the first id of the stream.
        outbound.try_recv().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let (outcome, sent) = tokio::join!(
            link.request(column(1), deadline, 0, Box::new(())),
            tokio::time::timeout(TIMEOUT, outbound.recv()),
        );
        assert!(matches!(outcome, KzgOutcome::NoVerdict(_)), "{outcome:?}");
        let sent = sent.expect("the request was sent").unwrap().request;
        let Some(verify_kzg_request::Frame::Body(body)) = sent.frame else {
            panic!("{sent:?}");
        };
        assert_eq!(body.request_id, 1, "no id was taken for a frame never sent");
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

    /// cl-verify checks each stream's hello against the digest of its clock at the stream open.
    /// Slot 8 of the devnet is epoch 1, after a blob change: another digest.
    fn across_a_digest_change(clock: &Arc<ManualClock>) -> Served {
        clock.set(devnet_ms(0));
        let ours = Handshake::network(devnet_hello("cl-verify/test"), 1);
        StubVerify::start_network(Stub::HangsUp, ours, Arc::clone(clock))
    }

    #[tokio::test]
    async fn a_network_client_sends_the_digest_of_each_stream_open() {
        let clock = ManualClock::at(0);
        let served = across_a_digest_change(&clock);
        let client = served
            .network_kzg_client(devnet_hello("cl-chain/test"), Arc::clone(&clock))
            .await;
        // Each stream ends at its first request, so each call opens a new stream.
        let first = client.verify_cells(column(1), TIMEOUT).await;
        assert!(matches!(first, KzgOutcome::NoVerdict(_)), "{first:?}");
        clock.set(devnet_ms(8));
        let second = client.verify_cells(column(1), TIMEOUT).await;
        assert!(matches!(second, KzgOutcome::NoVerdict(_)), "{second:?}");
        let digest = |slot| {
            devnet_hello("x")
                .at(u128::from(devnet_ms(slot)))
                .unwrap()
                .current_fork_digest
        };
        assert_ne!(digest(0), digest(8));
        assert_eq!(served.handshakes(), [Ok(digest(0)), Ok(digest(8))]);
    }

    /// The hello of the client's start, sent again after a digest change, is refused: why a
    /// production client opens each stream with the hello of the clock.
    #[tokio::test]
    async fn a_fixed_hello_is_refused_after_a_digest_change() {
        let clock = ManualClock::at(0);
        let served = across_a_digest_change(&clock);
        let channel = ipc::uds::connect_path(&served.socket, crate::testing::my_uid())
            .await
            .unwrap();
        let start = devnet_hello("cl-chain/test")
            .at(u128::from(devnet_ms(0)))
            .unwrap();
        let client = KzgClient::new(VerifyServiceClient::new(channel), start);
        let _ = client.verify_cells(column(1), TIMEOUT).await;
        clock.set(devnet_ms(8));
        let refused = client.verify_cells(column(1), TIMEOUT).await;
        assert!(matches!(refused, KzgOutcome::NoVerdict(_)), "{refused:?}");
        let handshakes = served.handshakes();
        assert!(handshakes[0].is_ok(), "{handshakes:?}");
        assert_eq!(handshakes[1], Err(ErrorCode::VersionMismatch));
    }

    /// The client reads its clock before it sends its hello, and cl-verify reads its own after
    /// it receives the hello. A boundary between the two reads gives `VERSION_MISMATCH`; the
    /// client then reads its clock again, finds another digest and opens again, one time.
    #[tokio::test]
    async fn a_stream_refused_across_a_digest_change_is_opened_again() {
        let clock = ManualClock::at(0);
        let served = across_a_digest_change(&clock);
        clock.set(devnet_ms(8) - 1);
        let jumped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reads = Arc::clone(&clock);
        let client_clock: UnixClock = Arc::new(move || {
            let now = reads.0.load(std::sync::atomic::Ordering::SeqCst);
            // The boundary passes right after the first read.
            if !jumped.swap(true, std::sync::atomic::Ordering::SeqCst) {
                reads.set(devnet_ms(8));
            }
            u128::from(now)
        });
        let client = served
            .network_kzg_client_on(devnet_hello("cl-chain/test"), client_clock)
            .await;
        let outcome = client.verify_cells(column(1), TIMEOUT).await;
        assert!(matches!(outcome, KzgOutcome::NoVerdict(_)), "{outcome:?}");
        let digest_8 = devnet_hello("x")
            .at(u128::from(devnet_ms(8)))
            .unwrap()
            .current_fork_digest;
        assert_eq!(
            served.handshakes(),
            [Err(ErrorCode::VersionMismatch), Ok(digest_8)]
        );
    }

    /// A `VERSION_MISMATCH` with the same digest on the next clock read is not tried again:
    /// the hellos differ for good.
    #[tokio::test]
    async fn a_mismatch_without_a_digest_change_is_not_tried_again() {
        let clock = ManualClock::at(devnet_ms(0));
        let theirs = Handshake::network(devnet_hello("cl-verify/test"), 1);
        let served = StubVerify::start_network(Stub::HangsUp, theirs, Arc::clone(&clock));
        let client = served
            .network_kzg_client(
                ipc::testkit::devnet::kurtosis_hello("cl-chain/test"),
                Arc::clone(&clock),
            )
            .await;
        match client.verify_cells(column(1), TIMEOUT).await {
            KzgOutcome::NoVerdict(why) => assert!(why.contains("VersionMismatch"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(served.handshakes(), [Err(ErrorCode::VersionMismatch)]);
        assert_eq!(served.streams_opened(), 1);
    }

    /// Before genesis there is no fork digest: no stream opens and the call is no verdict.
    #[tokio::test]
    async fn a_network_client_before_genesis_opens_no_stream() {
        let clock = ManualClock::at(0);
        let served = across_a_digest_change(&clock);
        let client = served
            .network_kzg_client(devnet_hello("cl-chain/test"), Arc::clone(&clock))
            .await;
        clock.set(devnet_ms(0) - 1);
        match client.verify_cells(column(1), TIMEOUT).await {
            KzgOutcome::NoVerdict(why) => assert!(why.contains("no fork digest"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(served.streams_opened(), 0);
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
