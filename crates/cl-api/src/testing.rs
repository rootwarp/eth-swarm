//! Fixtures the route, schema and service tests share: a fake chain.v1 `ImportService` and
//! `EventsService`, a fixed clock, Sepolia's config, requests through the router with tower's
//! `oneshot`, and a `text/event-stream` client over hyper ([`SseClient`]).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::Router;
use ethswarm_proto::chain as pb;
use http::header::{ACCEPT, HOST};
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use ipc::frame::OutFrame;
use ipc::hello::{stream_hello, NetworkHello, API_VERSION_V1};
use ipc::Link;
use network_config::{ChainConfig, Genesis, Network};
use pb::events_service_server::{EventsService, EventsServiceServer};
use pb::import_service_server::{ImportService, ImportServiceServer};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};
use tonic::service::Routes;
use tonic::{Status, Streaming};
use tower::ServiceExt;

use crate::node_state::{NodeState, SlotClock};
use crate::routes::config::ConfigData;
use crate::server::ApiState;
use crate::sse::EventHub;

/// The genesis of the fixed clock (Sepolia's).
pub const GENESIS_TIME: u64 = 1_655_733_600;
/// The slot duration of the fixed clock.
pub const SLOT_MS: u64 = 12_000;
/// The wall-clock slot of the fixed clock.
pub const WALL_SLOT: u64 = 1_000_000;

/// A clock fixed in the middle of [`WALL_SLOT`].
pub fn clock() -> SlotClock {
    SlotClock::with_now(GENESIS_TIME, SLOT_MS, || {
        Duration::from_millis(GENESIS_TIME * 1000 + WALL_SLOT * SLOT_MS + SLOT_MS / 2)
    })
}

pub fn sepolia() -> ChainConfig {
    ChainConfig::load(Network::Sepolia).unwrap()
}

/// Handlers over `node` and Sepolia's config, with an event hub that follows nothing.
pub fn api_state(node: NodeState) -> ApiState {
    ApiState {
        node,
        config: Arc::new(ConfigData::new(&sepolia()).unwrap()),
        events: EventHub::new(),
    }
}

/// Sepolia's genesis in these tests.
pub fn genesis() -> Genesis {
    Genesis {
        genesis_time: GENESIS_TIME,
        genesis_validators_root: [0x5e; 32],
    }
}

/// The ipc link of both ends of a test's chain.v1 streams: Sepolia's network hello.
pub fn link() -> Link {
    let hello = NetworkHello::new("cl-api-test", &sepolia(), genesis()).unwrap();
    Link::network(Arc::new(hello), API_VERSION_V1).unwrap()
}

/// How long a test waits for anything before it fails.
pub const WITHIN: Duration = Duration::from_secs(5);

/// [`crate::server::router`] over `state`, with the default request timeout.
pub fn router(state: ApiState) -> Router {
    crate::server::router(state, crate::server::HttpLimits::default().request_timeout)
}

/// `request` through `app`: its status, headers and body.
pub async fn request(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 64 << 20).await.unwrap();
    (parts.status, parts.headers, body.to_vec())
}

/// `GET uri` through `app`.
pub async fn get(app: &Router, uri: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    request(app, Request::get(uri).body(Body::empty()).unwrap()).await
}

/// `body` as JSON.
pub fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(body)))
}

/// A chain status with `head_slot`, `optimistic` and `el_offline`.
pub fn sync_status(head_slot: u64, optimistic: bool, el_offline: bool) -> pb::SyncStatus {
    pb::SyncStatus {
        head_slot,
        head_root: vec![0xab; 32],
        finalized: None,
        anchor_slot: 0,
        optimistic,
        el_offline,
    }
}

/// A fake cl-chain `ImportService`: `GetChainStatus` answers the status the test set last (or
/// never, [`Self::hanging`]); the other RPCs are not implemented.
#[derive(Clone)]
pub struct FakeChain {
    status: Arc<Mutex<pb::SyncStatus>>,
    hang: bool,
}

impl FakeChain {
    pub fn new(status: pb::SyncStatus) -> Self {
        Self {
            status: Arc::new(Mutex::new(status)),
            hang: false,
        }
    }

    /// A chain whose `GetChainStatus` never answers.
    pub fn hanging(mut self) -> Self {
        self.hang = true;
        self
    }

    pub fn set(&self, status: pb::SyncStatus) {
        *self.status.lock().unwrap() = status;
    }

    pub fn routes(&self) -> Routes {
        Routes::new(ImportServiceServer::new(self.clone()))
    }

    /// Serves on a Unix socket at `path` (replacing a stale one) until [`RunningChain::stop`].
    pub fn serve_uds(&self, path: &Path) -> RunningChain {
        serve_routes_uds(path, self.routes())
    }
}

/// Serves `routes` on a Unix socket at `path` (replacing a stale one) until
/// [`RunningChain::stop`].
pub fn serve_routes_uds(path: &Path, routes: Routes) -> RunningChain {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(ipc::stub::serve_uds(listener, routes, async {
        let _ = stopped.await;
    }));
    RunningChain { stop, task }
}

/// A [`FakeChain`] on a Unix socket.
pub struct RunningChain {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl RunningChain {
    /// Stops serving and waits until every connection is closed.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        self.task.await.unwrap().unwrap();
    }
}

#[tonic::async_trait]
impl ImportService for FakeChain {
    async fn bootstrap(
        &self,
        _: tonic::Request<pb::BootstrapRequest>,
    ) -> Result<tonic::Response<pb::BootstrapResponse>, Status> {
        Err(Status::unimplemented("bootstrap"))
    }

    type ImportBatchStream = ipc::stub::StubStream<pb::ImportBatchResponse>;

    async fn import_batch(
        &self,
        _: tonic::Request<Streaming<pb::ImportBatchRequest>>,
    ) -> Result<tonic::Response<Self::ImportBatchStream>, Status> {
        Err(Status::unimplemented("import_batch"))
    }

    async fn get_chain_status(
        &self,
        _: tonic::Request<pb::GetChainStatusRequest>,
    ) -> Result<tonic::Response<pb::GetChainStatusResponse>, Status> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        let status = self.status.lock().unwrap().clone();
        Ok(tonic::Response::new(pb::GetChainStatusResponse {
            status: Some(status),
        }))
    }
}

/// What [`FakeEvents`] sends next on every open stream.
#[derive(Clone, Debug)]
enum Feed {
    Body(pb::SubscribeResponseBody),
    /// End the stream with `UNAVAILABLE`.
    End,
}

/// A fake cl-chain `EventsService`. Each `Subscribe` (counted, its kinds kept) gets the
/// server's hello, then every body the test pushes, until the test ends the open streams.
#[derive(Clone)]
pub struct FakeEvents {
    link: Link,
    subscribes: Arc<AtomicUsize>,
    kinds: Arc<Mutex<Vec<i32>>>,
    feed: broadcast::Sender<Feed>,
}

impl Default for FakeEvents {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeEvents {
    pub fn new() -> Self {
        Self {
            link: link(),
            subscribes: Arc::default(),
            kinds: Arc::default(),
            feed: broadcast::channel(1 << 14).0,
        }
    }

    /// The `Subscribe` calls so far.
    pub fn subscribes(&self) -> usize {
        self.subscribes.load(Ordering::SeqCst)
    }

    /// The kinds the last `Subscribe` asked for.
    pub fn kinds(&self) -> Vec<i32> {
        self.kinds.lock().unwrap().clone()
    }

    /// Sends `body` on every open stream.
    pub fn push(&self, body: pb::SubscribeResponseBody) {
        let _ = self.feed.send(Feed::Body(body));
    }

    /// Ends every open stream with `UNAVAILABLE`, as a cl-chain that stops does.
    pub fn end_streams(&self) {
        let _ = self.feed.send(Feed::End);
    }

    /// Serves on a Unix socket at `path` until [`RunningChain::stop`].
    pub fn serve_uds(&self, path: &Path) -> RunningChain {
        serve_routes_uds(path, Routes::new(EventsServiceServer::new(self.clone())))
    }
}

#[tonic::async_trait]
impl EventsService for FakeEvents {
    type SubscribeStream = ipc::stub::StubStream<pb::SubscribeResponse>;

    async fn subscribe(
        &self,
        request: tonic::Request<pb::SubscribeRequest>,
    ) -> Result<tonic::Response<Self::SubscribeStream>, Status> {
        let request = request.into_inner();
        self.link
            .accept_hello_field(request.hello.as_ref())
            .map_err(|e| e.to_status())?;
        self.subscribes.fetch_add(1, Ordering::SeqCst);
        *self.kinds.lock().unwrap() = request.kinds;
        let (_, hello) = stream_hello(&self.link.local()).unwrap();
        let mut feed = self.feed.subscribe();
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            if tx
                .send(Ok(pb::SubscribeResponse::hello(hello)))
                .await
                .is_err()
            {
                return;
            }
            loop {
                let next = match feed.recv().await {
                    Ok(Feed::Body(body)) => Ok(pb::SubscribeResponse::body(body)),
                    Ok(Feed::End) | Err(_) => Err(Status::unavailable("ended by the test")),
                };
                let end = next.is_err();
                if tx.send(next).await.is_err() || end {
                    return;
                }
            }
        });
        let frames = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|frame| (frame, rx))
        });
        Ok(tonic::Response::new(Box::pin(frames)))
    }
}

/// A chain.v1 event frame body.
pub fn event(
    seq: u64,
    kind: pb::EventKind,
    slot: u64,
    data: &serde_json::Value,
) -> pb::SubscribeResponseBody {
    pb::SubscribeResponseBody {
        seq,
        kind: kind as i32,
        slot,
        root: vec![0xbb; 32],
        data_json: serde_json::to_vec(data).unwrap(),
        optimistic: false,
    }
}

/// One event of a `text/event-stream`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseEvent {
    /// The event type (`message` when the event names none).
    pub event: String,
    pub data: String,
}

impl SseEvent {
    /// `data` as JSON.
    pub fn json(&self) -> serde_json::Value {
        json(self.data.as_bytes())
    }
}

/// A `text/event-stream` parser: the WHATWG event-stream interpretation for `event` and
/// `data`. Lines end in LF or CRLF (a lone CR is not a line end here). A blank line dispatches
/// the event; a line starting with `:` is a comment; one space after the field's colon is
/// dropped; `data` lines join with LF; an event without data is not dispatched; `id`, `retry`
/// and unknown fields are ignored.
#[derive(Debug, Default)]
pub struct SseParser {
    line: Vec<u8>,
    event: String,
    data: Option<String>,
}

impl SseParser {
    /// The events that `bytes`, after everything pushed before, completes.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        let mut events = Vec::new();
        for &b in bytes {
            if b != b'\n' {
                self.line.push(b);
                continue;
            }
            let raw = std::mem::take(&mut self.line);
            let line = std::str::from_utf8(raw.strip_suffix(b"\r").unwrap_or(&raw))
                .expect("event-stream lines are UTF-8");
            if line.is_empty() {
                let event = std::mem::take(&mut self.event);
                if let Some(data) = self.data.take() {
                    let event = if event.is_empty() {
                        "message".into()
                    } else {
                        event
                    };
                    events.push(SseEvent { event, data });
                }
                continue;
            }
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = line
                .split_once(':')
                .map_or((line, ""), |(f, v)| (f, v.strip_prefix(' ').unwrap_or(v)));
            match field {
                "event" => self.event = value.to_owned(),
                "data" => match &mut self.data {
                    Some(data) => {
                        data.push('\n');
                        data.push_str(value);
                    }
                    None => self.data = Some(value.to_owned()),
                },
                _ => {}
            }
        }
        events
    }
}

/// A client of one `text/event-stream` response over hyper's HTTP/1 client.
pub struct SseClient {
    pub status: StatusCode,
    pub headers: HeaderMap,
    body: hyper::body::Incoming,
    parser: SseParser,
    ready: VecDeque<SseEvent>,
    _sender: hyper::client::conn::http1::SendRequest<http_body_util::Empty<Bytes>>,
}

impl SseClient {
    /// `GET target` (`Host: localhost`) on a new connection to `addr`.
    pub async fn connect(addr: SocketAddr, target: &str) -> Self {
        Self::over(TcpStream::connect(addr).await.unwrap(), target).await
    }

    /// `GET target` on `stream`; returns once the response head is in.
    pub async fn over(stream: TcpStream, target: &str) -> Self {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(connection);
        let request = Request::get(target)
            .header(HOST, "localhost")
            .header(ACCEPT, "text/event-stream")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let response = tokio::time::timeout(WITHIN, sender.send_request(request))
            .await
            .expect("a response head in time")
            .unwrap();
        let (parts, body) = response.into_parts();
        Self {
            status: parts.status,
            headers: parts.headers,
            body,
            parser: SseParser::default(),
            ready: VecDeque::new(),
            _sender: sender,
        }
    }

    /// The next event; `None` once the server has ended the stream or closed the connection.
    /// Fails the test if neither comes within [`WITHIN`].
    pub async fn next(&mut self) -> Option<SseEvent> {
        self.next_within(WITHIN)
            .await
            .expect("an event or the end of the stream in time")
    }

    /// [`Self::next`], or `Err` if neither an event nor the end comes within `wait`.
    pub async fn next_within(
        &mut self,
        wait: Duration,
    ) -> Result<Option<SseEvent>, tokio::time::error::Elapsed> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(event) = self.ready.pop_front() {
                return Ok(Some(event));
            }
            match tokio::time::timeout_at(deadline, self.body.frame()).await? {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        let events = self.parser.push(&data);
                        self.ready.extend(events);
                    }
                }
                Some(Err(_)) | None => return Ok(None),
            }
        }
    }

    /// The `n` next events, each within [`WITHIN`]; fails the test if the stream ends first.
    pub async fn take(&mut self, n: usize) -> Vec<SseEvent> {
        let mut events = Vec::with_capacity(n);
        for i in 0..n {
            let event = self.next().await;
            events
                .push(event.unwrap_or_else(|| panic!("the stream ended after {i} of {n} events")));
        }
        events
    }

    /// The whole body, for a response that is not a stream (an error body).
    pub async fn bytes(mut self) -> Vec<u8> {
        let body = tokio::time::timeout(WITHIN, (&mut self.body).collect())
            .await
            .expect("the whole body in time")
            .unwrap();
        body.to_bytes().to_vec()
    }
}
