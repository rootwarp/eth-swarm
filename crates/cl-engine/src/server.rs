//! `ethswarm.engine.v1` server: the trust boundary between cl-chain and the engine queue.
//!
//! [`EngineServer`] forwards JSON params unchanged (ADR-007: consensus types are never decoded;
//! SSZ payloads are refused rather than interpreted). [`serve`] puts it on a Unix socket:
//!
//! - On every accept, before a byte is read, the peer's `SO_PEERCRED` UID is read and checked
//!   against the callers of the method ACL from config. An unreadable credential or a UID that
//!   is not listed closes the connection.
//! - The method ACL ([`ipc::acl::AclLayer`]) runs ahead of the service: exact paths, deny by
//!   default, before the request body is decoded. Each handler checks the UID again.
//! - A gRPC message longer than [`Limits::max_request_bytes`] is refused from its length prefix,
//!   before the buffer is allocated. Each request (body read included) has a deadline, a
//!   connection that sends nothing for [`Limits::idle_timeout`] is closed, one whose first
//!   request has not arrived [`Limits::first_request_timeout`] after the accept is closed
//!   however steadily it sends, and connections and in-flight requests per connection are
//!   capped.
//! - Requests the EL could not take as specified are refused before the queue (and their `seq`
//!   released): lengths of `DATA` fields, at most 128 versioned hashes per getBlobs, and a
//!   caller's `timeout_ms` only ever raises the spec wait (up to the request deadline).
//! - Errors and logs carry codes, UIDs and fixed text: never the secret or a payload.
//!
//! The socket itself comes from [`ipc::uds::bind`] (owned directory, stale socket removed only
//! after `lstat` shows our own socket).
use crate::client::{
    CallError, FORKCHOICE_UPDATED_TIMEOUT, GET_BLOBS_TIMEOUT, GET_PAYLOAD_TIMEOUT,
    NEW_PAYLOAD_TIMEOUT, NEW_PAYLOAD_V5_TIMEOUT,
};
use crate::queue::Queue;
use ethswarm_proto::common::ErrorCode;
use ethswarm_proto::engine as pb;
use ipc::acl::{AclLayer, MethodAcl};
use ipc::error::{to_status, wire_error};
use ipc::Link;
use pb::engine_service_server::{EngineService, EngineServiceServer};
use prost::Message as _;
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::{Connected, UdsConnectInfo};
use tonic::{Code, Request, Response, Status};

/// The Engine API adapter. JSON params go to the EL as JSON-RPC params; the result is copied
/// back into the proto messages without being read as a consensus object.
#[derive(Clone)]
pub struct EngineServer {
    link: Link,
    acl: Arc<MethodAcl>,
    callers: Arc<BTreeSet<u32>>,
    queue: Queue,
    /// Ceiling of a caller's raised wait: the gRPC request deadline ([`Limits::request_timeout`]).
    max_wait: Duration,
}

impl EngineServer {
    /// `acl` is the method ACL from config (`ipc::acl`, which lets only cl-chain call
    /// cl-engine). Its callers are the only UIDs served.
    #[must_use]
    pub fn new(link: Link, acl: Arc<MethodAcl>, queue: Queue) -> Self {
        Self {
            link,
            callers: Arc::new(acl.callers()),
            acl,
            queue,
            max_wait: Limits::default().request_timeout,
        }
    }

    /// The ordered queue.
    #[must_use]
    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Every `ethswarm.engine.v1` service, with the message size caps of `limits`.
    #[must_use]
    pub fn routes(mut self, limits: &Limits) -> tonic::service::Routes {
        self.max_wait = limits.request_timeout;
        tonic::service::Routes::new(
            EngineServiceServer::new(self)
                .max_decoding_message_size(limits.max_request_bytes)
                .max_encoding_message_size(limits.max_response_bytes),
        )
    }

    fn admit<T>(&self, request: &Request<T>) -> Result<(), Status> {
        self.link.check_unary(&[]).map_err(|err| err.to_status())?;
        authorize(&self.callers, peer_uid(request))
    }

    /// An admitted request was refused before the queue: give its `seq` back so later calls
    /// do not wait out their deadline behind it. Only admitted callers can release a `seq`.
    async fn refuse(&self, seq: u64, status: Status) -> Status {
        let _ = self.queue.release(seq).await;
        status
    }
}

#[tonic::async_trait]
impl EngineService for EngineServer {
    async fn new_payload(
        &self,
        request: Request<pb::NewPayloadRequest>,
    ) -> Result<Response<pb::NewPayloadResponse>, Status> {
        self.admit(&request)?;
        let req = request.into_inner();
        let prepared = (|| {
            let method = new_payload_method(req.params.as_ref().map(|p| p.version).unwrap_or(0))?;
            let encoding = req.params.as_ref().map(|p| p.encoding).unwrap_or(0);
            require_json(encoding)?;
            let params = json_params(
                req.params
                    .as_ref()
                    .map(|p| p.data.as_slice())
                    .unwrap_or(b""),
            )
            .map_err(|_| contract("newPayload params are not JSON"))?;
            Ok((method, params))
        })();
        let (method, params) = match prepared {
            Ok(prepared) => prepared,
            Err(status) => return Err(self.refuse(req.seq, status).await),
        };
        let timeout = timeout_of(req.timeout_ms, spec_timeout(method), self.max_wait);
        match self.queue.call(req.seq, method, params, timeout).await {
            Ok(result) => {
                let status = payload_status(&result);
                Ok(Response::new(pb::NewPayloadResponse {
                    seq: req.seq,
                    error: status
                        .is_none()
                        .then(|| failure_error(CallError::BadResponse)),
                    status,
                }))
            }
            Err(err) => Ok(Response::new(pb::NewPayloadResponse {
                seq: req.seq,
                status: None,
                error: Some(failure_error(err)),
            })),
        }
    }

    async fn forkchoice_updated(
        &self,
        request: Request<pb::ForkchoiceUpdatedRequest>,
    ) -> Result<Response<pb::ForkchoiceUpdatedResponse>, Status> {
        self.admit(&request)?;
        let req = request.into_inner();
        let version = req
            .payload_attributes
            .as_ref()
            .map(|attrs| attrs.version)
            .unwrap_or(pb::EngineMethodVersion::GloasAmsterdam as i32);
        let prepared = (|| {
            let method = forkchoice_method(version)?;
            if let Some(attrs) = &req.payload_attributes {
                require_json(attrs.encoding)?;
            }
            let params = forkchoice_params(method, &req)
                .map_err(|_| contract("forkchoice params are malformed"))?;
            Ok((method, params))
        })();
        let (method, params) = match prepared {
            Ok(prepared) => prepared,
            Err(status) => return Err(self.refuse(req.seq, status).await),
        };
        let timeout = timeout_of(req.timeout_ms, spec_timeout(method), self.max_wait);
        match self.queue.call(req.seq, method, params, timeout).await {
            Ok(result) => {
                // `payloadId` is `DATA|null`, 8 bytes (paris.md): anything else is malformed.
                let decoded = result
                    .get("payloadStatus")
                    .and_then(payload_status)
                    .zip(data_or_null(result.get("payloadId"), PAYLOAD_ID_BYTES));
                let (status, payload_id) = decoded.unzip();
                Ok(Response::new(pb::ForkchoiceUpdatedResponse {
                    seq: req.seq,
                    error: status
                        .is_none()
                        .then(|| failure_error(CallError::BadResponse)),
                    status,
                    payload_id: payload_id.unwrap_or_default(),
                }))
            }
            Err(err) => Ok(Response::new(pb::ForkchoiceUpdatedResponse {
                seq: req.seq,
                status: None,
                payload_id: Vec::new(),
                error: Some(failure_error(err)),
            })),
        }
    }

    async fn get_payload(
        &self,
        request: Request<pb::GetPayloadRequest>,
    ) -> Result<Response<pb::GetPayloadResponse>, Status> {
        self.admit(&request)?;
        let req = request.into_inner();
        let method = get_payload_method(req.version).and_then(|method| {
            if req.payload_id.len() == PAYLOAD_ID_BYTES {
                Ok(method)
            } else {
                Err(contract("getPayload payload_id is not 8 bytes"))
            }
        });
        let method = match method {
            Ok(method) => method,
            Err(status) => return Err(self.refuse(req.seq, status).await),
        };
        let id = hex_id(&req.payload_id);
        let params = serde_json::json!([id]);
        let timeout = timeout_of(req.timeout_ms, spec_timeout(method), self.max_wait);
        match self.queue.call(req.seq, method, params, timeout).await {
            Ok(result) => Ok(Response::new(pb::GetPayloadResponse {
                seq: req.seq,
                result: Some(opaque_json(req.version, &result)),
                error: None,
            })),
            Err(err) => Ok(Response::new(pb::GetPayloadResponse {
                seq: req.seq,
                result: None,
                error: Some(failure_error(err)),
            })),
        }
    }

    async fn get_blobs(
        &self,
        request: Request<pb::GetBlobsRequest>,
    ) -> Result<Response<pb::GetBlobsResponse>, Status> {
        self.admit(&request)?;
        let req = request.into_inner();
        let prepared = get_blobs_method(req.version, req.partial)
            .and_then(|method| Ok((method, get_blobs_params(method, &req)?)));
        let (method, params) = match prepared {
            Ok(prepared) => prepared,
            Err(status) => return Err(self.refuse(req.seq, status).await),
        };
        let timeout = timeout_of(req.timeout_ms, spec_timeout(method), self.max_wait);
        match self.queue.call(req.seq, method, params, timeout).await {
            Ok(result) => Ok(Response::new(pb::GetBlobsResponse {
                seq: req.seq,
                result: Some(opaque_json(req.version, &result)),
                error: None,
            })),
            Err(err) => Ok(Response::new(pb::GetBlobsResponse {
                seq: req.seq,
                result: None,
                error: Some(failure_error(err)),
            })),
        }
    }

    async fn exchange_capabilities(
        &self,
        request: Request<pb::ExchangeCapabilitiesRequest>,
    ) -> Result<Response<pb::ExchangeCapabilitiesResponse>, Status> {
        self.admit(&request)?;
        let req = request.into_inner();
        let offered = if req.methods.is_empty() {
            crate::capabilities::ADVERTISED
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else {
            req.methods
        };
        let params = serde_json::json!([offered]);
        match self
            .queue
            .call_now(
                crate::client::EXCHANGE_CAPABILITIES,
                params,
                crate::client::EXCHANGE_CAPABILITIES_TIMEOUT,
            )
            .await
        {
            Ok(result) => {
                let methods: Vec<String> = result
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| item.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Err(missing) = crate::capabilities::check(methods.iter().map(String::as_str))
                {
                    return Ok(Response::new(pb::ExchangeCapabilitiesResponse {
                        methods,
                        error: Some(pb::EngineError {
                            kind: pb::EngineErrorKind::Other as i32,
                            rpc_code: 0,
                            message: truncate(&missing.to_string(), 1024),
                        }),
                    }));
                }
                Ok(Response::new(pb::ExchangeCapabilitiesResponse {
                    methods,
                    error: None,
                }))
            }
            Err(err) => Ok(Response::new(pb::ExchangeCapabilitiesResponse {
                methods: Vec::new(),
                error: Some(failure_error(err)),
            })),
        }
    }
}

/// Caps on the engine socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest gRPC request message: the proto's 32 MiB JSON bound plus room for the fields.
    pub max_request_bytes: usize,
    /// Largest gRPC response message: the 48 MiB `GetBlobs` bound plus room for the fields.
    pub max_response_bytes: usize,
    /// Connections served at once; one more is closed on accept.
    pub max_connections: usize,
    /// Requests in flight on one connection (HTTP/2 streams).
    pub max_requests_per_connection: u32,
    /// One request, from its headers through reading its body to the response. A queued engine
    /// call can take up to twice its own timeout (queue wait, then the EL's response; see
    /// [`crate::queue`]), so a request cut off here may still reach the EL: the caller must treat
    /// it as possibly applied.
    pub request_timeout: Duration,
    /// A connection that sends nothing for this long is closed.
    pub idle_timeout: Duration,
    /// A connection whose first request (the HTTP/2 preface through the end of a request's
    /// header block) has not arrived this long after the accept is closed, however steadily
    /// it sends bytes. Not from any spec: it bounds how long a peer can hold a slot without
    /// asking for anything; once a request has arrived, [`Limits::request_timeout`] and
    /// [`Limits::idle_timeout`] apply.
    pub first_request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: 32 * 1024 * 1024 + 64 * 1024,
            max_response_bytes: 48 * 1024 * 1024 + 64 * 1024,
            max_connections: 4,
            max_requests_per_connection: 16,
            // Above the 8 s newPayload / forkchoiceUpdated wait.
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            first_request_timeout: Duration::from_secs(10),
        }
    }
}

/// Serves `server` on `listener` (bound by [`ipc::uds::bind`]) until `shutdown` resolves.
pub async fn serve(
    listener: UnixListener,
    server: EngineServer,
    limits: Limits,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), tonic::transport::Error> {
    let (tx, rx) = mpsc::channel(1);
    let accept = tokio::spawn(accept(listener, Arc::clone(&server.callers), limits, tx));
    let acl = Arc::clone(&server.acl);
    let result = tonic::transport::Server::builder()
        .timeout(limits.request_timeout)
        .max_concurrent_streams(limits.max_requests_per_connection)
        .concurrency_limit_per_connection(limits.max_requests_per_connection as usize)
        .layer(AclLayer::new(acl))
        .add_routes(server.routes(&limits))
        .serve_with_incoming_shutdown(ReceiverStream::new(rx), shutdown)
        .await;
    accept.abort();
    result
}

/// Accepts connections; only a peer whose `SO_PEERCRED` UID is a caller, while a connection
/// slot is free, is handed to the server. Every other stream is dropped (closed) unread.
async fn accept(
    listener: UnixListener,
    callers: Arc<BTreeSet<u32>>,
    limits: Limits,
    tx: mpsc::Sender<io::Result<Admitted>>,
) {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                tracing::warn!(kind = ?err.kind(), "engine socket accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        match stream.peer_cred() {
            Ok(cred) if callers.contains(&cred.uid()) => {}
            Ok(cred) => {
                tracing::warn!(uid = cred.uid(), "engine socket: peer uid refused");
                continue;
            }
            Err(_) => {
                tracing::warn!("engine socket: peer credentials unreadable, refused");
                continue;
            }
        }
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::warn!(
                max = limits.max_connections,
                "engine socket: connection limit reached, refused"
            );
            continue;
        };
        let admitted = Admitted {
            stream,
            idle: limits.idle_timeout,
            deadline: Box::pin(tokio::time::sleep(limits.idle_timeout)),
            first_request: Some((
                FirstRequest::default(),
                Box::pin(tokio::time::sleep(limits.first_request_timeout)),
            )),
            _slot: slot,
        };
        if tx.send(Ok(admitted)).await.is_err() {
            return;
        }
    }
}

/// An accepted connection: holds a connection slot, and fails its read once the peer has sent
/// nothing for `idle`, or has not sent a first request by its absolute deadline.
struct Admitted {
    stream: UnixStream,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    /// Until the first request has arrived: where the client's bytes are in it, and the
    /// deadline from the accept.
    first_request: Option<(FirstRequest, Pin<Box<Sleep>>)>,
    _slot: OwnedSemaphorePermit,
}

/// Follows what an HTTP/2 client sends (RFC 9113 §3.4, §4.1) far enough to see its first
/// request: the 24-byte client preface, then frames of a 9-byte header (24-bit length, type,
/// flags, stream id) and a payload. The first request has arrived once a HEADERS (`0x1`) or
/// CONTINUATION (`0x9`) frame with END_HEADERS (`0x4`) has been read whole. Nothing is
/// buffered or allocated, and a frame that is not valid HTTP/2 is hyper's to refuse.
struct FirstRequest {
    /// Bytes still to pass over: the rest of the preface or of a frame payload.
    skip: usize,
    header: [u8; 9],
    have: usize,
    /// The payload being passed over ends a request's header block.
    ends_headers: bool,
}

impl Default for FirstRequest {
    fn default() -> Self {
        Self {
            skip: 24,
            header: [0; 9],
            have: 0,
            ends_headers: false,
        }
    }
}

impl FirstRequest {
    /// Takes the next bytes the client sent; true once its first request has arrived.
    fn arrived(&mut self, mut bytes: &[u8]) -> bool {
        loop {
            let passed = self.skip.min(bytes.len());
            self.skip -= passed;
            bytes = &bytes[passed..];
            if self.skip > 0 {
                return false;
            }
            if self.ends_headers {
                return true;
            }
            if bytes.is_empty() {
                return false;
            }
            let n = (self.header.len() - self.have).min(bytes.len());
            self.header[self.have..self.have + n].copy_from_slice(&bytes[..n]);
            self.have += n;
            bytes = &bytes[n..];
            if self.have < self.header.len() {
                return false;
            }
            self.have = 0;
            let [l0, l1, l2, kind, flags, ..] = self.header;
            self.skip = usize::from(l0) << 16 | usize::from(l1) << 8 | usize::from(l2);
            self.ends_headers = matches!(kind, 0x1 | 0x9) && flags & 0x4 != 0;
        }
    }
}

impl Connected for Admitted {
    type ConnectInfo = UdsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}

impl AsyncRead for Admitted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        // Polled on every read, not only when the peer is quiet: a peer that keeps sending
        // is still cut off at the deadline.
        if let Some((_, deadline)) = &mut this.first_request {
            if deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
            }
        }
        match Pin::new(&mut this.stream).poll_read(cx, buf) {
            Poll::Ready(result) => {
                let read = &buf.filled()[before..];
                if !read.is_empty() {
                    let next = Instant::now() + this.idle;
                    this.deadline.as_mut().reset(next);
                    if this
                        .first_request
                        .as_mut()
                        .is_some_and(|(seen, _)| seen.arrived(read))
                    {
                        this.first_request = None;
                    }
                }
                Poll::Ready(result)
            }
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncWrite for Admitted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// `PERMISSION_DENIED` unless `peer` is one of `allowed`. A missing credential is refused too.
pub(crate) fn authorize(allowed: &BTreeSet<u32>, peer: Option<u32>) -> Result<(), Status> {
    if peer.is_some_and(|uid| allowed.contains(&uid)) {
        return Ok(());
    }
    let who = peer.map_or_else(
        || "no peer credentials".to_owned(),
        |uid| format!("uid {uid}"),
    );
    let err = wire_error(
        ErrorCode::ContractViolation,
        format!("{who}: only cl-chain may call cl-engine"),
    );
    // Same shape as the method ACL: PERMISSION_DENIED, contract violation in the details.
    // `to_status` would map that code to INVALID_ARGUMENT.
    Err(Status::with_details(
        Code::PermissionDenied,
        err.detail.clone(),
        err.encode_to_vec().into(),
    ))
}

fn peer_uid<T>(request: &Request<T>) -> Option<u32> {
    request
        .extensions()
        .get::<UdsConnectInfo>()
        .and_then(|info| info.peer_cred)
        .map(|cred| cred.uid())
}

fn contract(detail: &str) -> Status {
    to_status(&wire_error(ErrorCode::ContractViolation, detail))
}

/// The caller's `timeout_ms` may raise the spec wait, never shorten it: common.md says the CL
/// MUST wait the method's timeout before aborting and MAY wait longer. A raised wait stops at
/// `ceiling` (the request deadline), unless the spec wait itself is longer.
fn timeout_of(override_ms: u32, spec: Duration, ceiling: Duration) -> Duration {
    Duration::from_millis(u64::from(override_ms))
        .min(ceiling)
        .max(spec)
}

/// The execution-apis timeout of `method`, one of the methods this server routes.
fn spec_timeout(method: &str) -> Duration {
    match method {
        "engine_newPayloadV5" => NEW_PAYLOAD_V5_TIMEOUT,
        "engine_newPayloadV4" => NEW_PAYLOAD_TIMEOUT,
        "engine_forkchoiceUpdatedV4" | "engine_forkchoiceUpdatedV3" => FORKCHOICE_UPDATED_TIMEOUT,
        "engine_getPayloadV6" | "engine_getPayloadV5" => GET_PAYLOAD_TIMEOUT,
        _ => GET_BLOBS_TIMEOUT,
    }
}

fn new_payload_method(version: i32) -> Result<&'static str, Status> {
    match pb::EngineMethodVersion::try_from(version) {
        Ok(pb::EngineMethodVersion::GloasAmsterdam) => Ok("engine_newPayloadV5"),
        Ok(pb::EngineMethodVersion::FuluOsaka) => Ok("engine_newPayloadV4"),
        Ok(pb::EngineMethodVersion::Unspecified) | Err(_) => {
            Err(contract("newPayload version is unspecified"))
        }
    }
}

fn forkchoice_method(version: i32) -> Result<&'static str, Status> {
    match pb::EngineMethodVersion::try_from(version) {
        Ok(pb::EngineMethodVersion::GloasAmsterdam) => Ok("engine_forkchoiceUpdatedV4"),
        Ok(pb::EngineMethodVersion::FuluOsaka) => Ok("engine_forkchoiceUpdatedV3"),
        Ok(pb::EngineMethodVersion::Unspecified) | Err(_) => {
            Err(contract("forkchoiceUpdated version is unspecified"))
        }
    }
}

fn get_payload_method(version: i32) -> Result<&'static str, Status> {
    match pb::EngineMethodVersion::try_from(version) {
        Ok(pb::EngineMethodVersion::GloasAmsterdam) => Ok("engine_getPayloadV6"),
        Ok(pb::EngineMethodVersion::FuluOsaka) => Ok("engine_getPayloadV5"),
        Ok(pb::EngineMethodVersion::Unspecified) | Err(_) => {
            Err(contract("getPayload version is unspecified"))
        }
    }
}

/// Versioned hashes per `engine_getBlobsV*` call: the request size every EL must support
/// (cancun.md, osaka.md, amsterdam.md); past it an EL may answer `-38004: Too large request`.
const MAX_BLOB_HASHES: usize = 128;
/// `engine_getBlobsV4` `indices_bitarray`: `DATA`, 16 bytes (amsterdam.md).
const INDICES_BITARRAY_BYTES: usize = 16;
/// `payloadId`: `DATA`, 8 bytes (paris.md).
const PAYLOAD_ID_BYTES: usize = 8;
/// `hash32` (`latestValidHash`, a versioned hash).
const HASH_BYTES: usize = 32;
/// `engine_forkchoiceUpdatedV4` `custodyColumns`: `DATA|null`, 16 bytes (amsterdam.md).
const CUSTODY_COLUMNS_BYTES: usize = 16;

/// JSON-RPC params for `engine_getBlobsV*`. Every `DATA` value is
/// `0x`-prefixed hex (execution-apis `common.md`), including the V4
/// `indices_bitarray`. A request the EL could not take as specified is refused here: more
/// than [`MAX_BLOB_HASHES`] hashes, a hash that is not 32 bytes, or an `indices_bitarray`
/// that is not 16 bytes for V4 (or is set at all for V2/V3, which have no such param).
fn get_blobs_params(method: &str, req: &pb::GetBlobsRequest) -> Result<Value, Status> {
    if req.versioned_hashes.len() > MAX_BLOB_HASHES {
        return Err(contract("getBlobs takes at most 128 versioned hashes"));
    }
    if req.versioned_hashes.iter().any(|h| h.len() != HASH_BYTES) {
        return Err(contract("getBlobs versioned hash is not 32 bytes"));
    }
    let hashes: Vec<String> = req.versioned_hashes.iter().map(|h| hex_id(h)).collect();
    if method == "engine_getBlobsV4" {
        if req.indices_bitarray.len() != INDICES_BITARRAY_BYTES {
            return Err(contract("getBlobsV4 indices_bitarray is not 16 bytes"));
        }
        Ok(serde_json::json!([hashes, hex_id(&req.indices_bitarray)]))
    } else if req.indices_bitarray.is_empty() {
        Ok(serde_json::json!([hashes]))
    } else {
        Err(contract("indices_bitarray is for getBlobsV4 only"))
    }
}

fn get_blobs_method(version: i32, partial: bool) -> Result<&'static str, Status> {
    match pb::EngineMethodVersion::try_from(version) {
        Ok(pb::EngineMethodVersion::GloasAmsterdam) => Ok("engine_getBlobsV4"),
        Ok(pb::EngineMethodVersion::FuluOsaka) if partial => Ok("engine_getBlobsV3"),
        Ok(pb::EngineMethodVersion::FuluOsaka) => Ok("engine_getBlobsV2"),
        Ok(pb::EngineMethodVersion::Unspecified) | Err(_) => {
            Err(contract("getBlobs version is unspecified"))
        }
    }
}

fn require_json(encoding: i32) -> Result<(), Status> {
    match pb::PayloadEncoding::try_from(encoding) {
        Ok(pb::PayloadEncoding::Json) => Ok(()),
        Ok(pb::PayloadEncoding::Ssz) => Err(contract(
            "SSZ engine payloads are not decoded; cl-engine does not decode consensus types",
        )),
        Ok(pb::PayloadEncoding::Unspecified) | Err(_) => {
            Err(contract("payload encoding is unspecified"))
        }
    }
}

fn json_params(data: &[u8]) -> Result<Value, ()> {
    if data.is_empty() {
        return Err(());
    }
    serde_json::from_slice(data).map_err(|_| ())
}

/// `payload_attributes` bound from the proto.
const MAX_PAYLOAD_ATTRIBUTES: usize = 64 * 1024;

/// JSON-RPC params for `engine_forkchoiceUpdatedV*`. V4 (amsterdam.md) takes a third
/// `custodyColumns` param, `DATA|null`, 16 bytes: the caller's `custody_columns` as is, or
/// `null` when it is empty. V3 has no such param, so a custody set there is refused.
fn forkchoice_params(method: &str, req: &pb::ForkchoiceUpdatedRequest) -> Result<Value, ()> {
    let hashes = [
        &req.head_block_hash,
        &req.safe_block_hash,
        &req.finalized_block_hash,
    ];
    if hashes.iter().any(|hash| hash.len() != 32) {
        return Err(());
    }
    if req
        .payload_attributes
        .as_ref()
        .is_some_and(|attrs| attrs.data.len() > MAX_PAYLOAD_ATTRIBUTES)
    {
        return Err(());
    }
    let state = serde_json::json!({
        "headBlockHash": hex_id(&req.head_block_hash),
        "safeBlockHash": hex_id(&req.safe_block_hash),
        "finalizedBlockHash": hex_id(&req.finalized_block_hash),
    });
    let attributes = match &req.payload_attributes {
        Some(attrs) if !attrs.data.is_empty() => json_params(&attrs.data)?,
        _ => Value::Null,
    };
    let custody = &req.custody_columns;
    match (method == "engine_forkchoiceUpdatedV4", custody.len()) {
        (true, 0) => Ok(serde_json::json!([state, attributes, Value::Null])),
        (true, CUSTODY_COLUMNS_BYTES) => {
            Ok(serde_json::json!([state, attributes, hex_id(custody)]))
        }
        (false, 0) => Ok(serde_json::json!([state, attributes])),
        _ => Err(()),
    }
}

fn payload_status(value: &Value) -> Option<pb::PayloadStatus> {
    let status = value.get("status")?.as_str()?;
    let kind = match status {
        "VALID" => pb::PayloadStatusKind::Valid,
        "INVALID" => pb::PayloadStatusKind::Invalid,
        "SYNCING" => pb::PayloadStatusKind::Syncing,
        "ACCEPTED" => pb::PayloadStatusKind::Accepted,
        "INVALID_BLOCK_HASH" => pb::PayloadStatusKind::InvalidBlockHash,
        _ => return None,
    };
    let latest_valid_hash = data_or_null(value.get("latestValidHash"), HASH_BYTES)?;
    let validation_error = value
        .get("validationError")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    Some(pb::PayloadStatus {
        status: kind as i32,
        latest_valid_hash,
        validation_error: truncate(&validation_error, 1024),
    })
}

fn opaque_json(version: i32, value: &Value) -> pb::VersionedData {
    let data = serde_json::to_vec(value).unwrap_or_default();
    pb::VersionedData {
        version,
        encoding: pb::PayloadEncoding::Json as i32,
        data,
    }
}

fn failure_error(err: CallError) -> pb::EngineError {
    let (kind, rpc_code) = match &err {
        CallError::Timeout => (pb::EngineErrorKind::Timeout, 0),
        CallError::BodyTooLarge { .. } => (pb::EngineErrorKind::TooLargeRequest, -38004),
        CallError::Rpc { code } => (kind_of(*code), i32::try_from(*code).unwrap_or(0)),
        CallError::Transport | CallError::NotConnected | CallError::Stopped => {
            (pb::EngineErrorKind::ElUnreachable, 0)
        }
        CallError::StaleConnection => (pb::EngineErrorKind::ElUnreachable, 0),
        CallError::Unauthorized => (pb::EngineErrorKind::Other, 401),
        CallError::BadResponse
        | CallError::MissingCaps(_)
        | CallError::Sequence
        | CallError::Overloaded => (pb::EngineErrorKind::Other, 0),
        CallError::HttpStatus { status } => (pb::EngineErrorKind::Other, i32::from(*status)),
    };
    pb::EngineError {
        kind: kind as i32,
        rpc_code,
        message: truncate(&err.to_string(), 1024),
    }
}

fn kind_of(code: i64) -> pb::EngineErrorKind {
    match code {
        -38001 => pb::EngineErrorKind::UnknownPayload,
        -38002 => pb::EngineErrorKind::InvalidForkchoiceState,
        -38003 => pb::EngineErrorKind::InvalidPayloadAttributes,
        -38004 => pb::EngineErrorKind::TooLargeRequest,
        -38005 => pb::EngineErrorKind::UnsupportedFork,
        -32602 => pb::EngineErrorKind::InvalidParams,
        _ => pb::EngineErrorKind::Other,
    }
}

fn hex_id(bytes: &[u8]) -> String {
    format!("0x{}", hex_encode(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// A `DATA|null` field of `len` bytes from the EL: empty for a missing or `null` field, `None`
/// for anything else that is not `0x`-hex of exactly `len` bytes.
fn data_or_null(value: Option<&Value>, len: usize) -> Option<Vec<u8>> {
    match value {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(value) => value
            .as_str()
            .and_then(decode_hex)
            .filter(|bytes| bytes.len() == len),
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.strip_prefix("0x")?;
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_nibble(*bytes.get(i)?)?;
        let lo = hex_nibble(*bytes.get(i + 1)?)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forkchoice_v4_sends_custody_columns_as_the_third_param() {
        let req = pb::ForkchoiceUpdatedRequest {
            head_block_hash: vec![1; 32],
            safe_block_hash: vec![2; 32],
            finalized_block_hash: vec![3; 32],
            ..Default::default()
        };
        let v4 = forkchoice_params("engine_forkchoiceUpdatedV4", &req).unwrap();
        let v4 = v4.as_array().unwrap();
        assert_eq!(v4.len(), 3);
        // No custody set: `null`.
        assert!(v4[1].is_null() && v4[2].is_null());
        let v3 = forkchoice_params("engine_forkchoiceUpdatedV3", &req).unwrap();
        assert_eq!(v3.as_array().unwrap().len(), 2);
        // The caller's 16-byte custody bitvector goes out as `DATA`.
        let custody = pb::ForkchoiceUpdatedRequest {
            custody_columns: vec![0x0f; 16],
            ..req.clone()
        };
        let v4 = forkchoice_params("engine_forkchoiceUpdatedV4", &custody).unwrap();
        assert_eq!(v4[2], format!("0x{}", "0f".repeat(16)));
    }

    #[test]
    fn custody_columns_must_be_16_bytes_and_only_for_v4() {
        let base = pb::ForkchoiceUpdatedRequest {
            head_block_hash: vec![1; 32],
            safe_block_hash: vec![2; 32],
            finalized_block_hash: vec![3; 32],
            ..Default::default()
        };
        for len in [1, 15, 17, 32] {
            let req = pb::ForkchoiceUpdatedRequest {
                custody_columns: vec![0xff; len],
                ..base.clone()
            };
            assert!(
                forkchoice_params("engine_forkchoiceUpdatedV4", &req).is_err(),
                "{len} bytes"
            );
        }
        // V3 has no third param: a custody set there is a caller bug, not something to drop.
        let req = pb::ForkchoiceUpdatedRequest {
            custody_columns: vec![0xff; 16],
            ..base
        };
        assert!(forkchoice_params("engine_forkchoiceUpdatedV3", &req).is_err());
    }

    #[test]
    fn get_blobs_v4_sends_0x_prefixed_indices_bitarray() {
        let req = pb::GetBlobsRequest {
            versioned_hashes: vec![vec![0xab; 32]],
            indices_bitarray: vec![0x01; 16],
            ..Default::default()
        };
        let params = get_blobs_params("engine_getBlobsV4", &req).unwrap();
        let wire = serde_json::to_string(&params).unwrap();
        let hash = format!("0x{}", "ab".repeat(32));
        let bits = format!("0x{}", "01".repeat(16));
        assert_eq!(wire, format!("[[\"{hash}\"],\"{bits}\"]"));
        let req = pb::GetBlobsRequest {
            indices_bitarray: Vec::new(),
            ..req
        };
        let v2 = get_blobs_params("engine_getBlobsV2", &req).unwrap();
        assert_eq!(
            serde_json::to_string(&v2).unwrap(),
            format!("[[\"{hash}\"]]")
        );
    }

    fn frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
        let mut out = vec![len[1], len[2], len[3], kind, flags, 0, 0, 0, 1];
        out.extend_from_slice(payload);
        out
    }

    fn preface() -> Vec<u8> {
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()
    }

    /// Fed one byte at a time; the index of the byte at which the first request arrived.
    fn arrives_at(bytes: &[u8]) -> Option<usize> {
        let mut seen = FirstRequest::default();
        bytes.iter().position(|byte| seen.arrived(&[*byte]))
    }

    #[test]
    fn the_first_request_arrives_with_the_last_byte_of_its_header_block() {
        let mut bytes = preface();
        bytes.extend(frame(0x4, 0, &[]));
        bytes.extend(frame(0x6, 0, &[0; 8]));
        let start = bytes.len();
        bytes.extend(frame(0x1, 0x4, &[0xaa; 300]));
        assert_eq!(arrives_at(&bytes), Some(bytes.len() - 1));
        // All at once too.
        assert!(FirstRequest::default().arrived(&bytes));
        // Not before: the header block's payload is still being sent.
        assert!(!FirstRequest::default().arrived(&bytes[..bytes.len() - 1]));
        assert!(!FirstRequest::default().arrived(&bytes[..start + 9]));
    }

    #[test]
    fn a_header_block_split_into_continuation_frames_ends_at_end_headers() {
        let mut bytes = preface();
        bytes.extend(frame(0x1, 0x1, &[0xaa; 20]));
        let first = bytes.len();
        bytes.extend(frame(0x9, 0, &[0xbb; 20]));
        bytes.extend(frame(0x9, 0x4, &[0xcc; 20]));
        assert_eq!(arrives_at(&bytes), Some(bytes.len() - 1));
        assert!(!FirstRequest::default().arrived(&bytes[..first]));
    }

    #[test]
    fn frames_that_are_not_a_request_never_count_as_one() {
        let mut bytes = preface();
        for _ in 0..50 {
            bytes.extend(frame(0x6, 0, &[0; 8]));
            bytes.extend(frame(0x0, 0x4, &[0x1; 10]));
            bytes.extend(frame(0x8, 0x4, &[0, 0, 1, 0]));
        }
        assert_eq!(arrives_at(&bytes), None);
        // An empty header block counts as soon as its frame header is read.
        bytes.extend(frame(0x1, 0x5, &[]));
        assert_eq!(arrives_at(&bytes), Some(bytes.len() - 1));
    }

    #[test]
    fn only_the_configured_uid_may_call() {
        let allowed = BTreeSet::from([7]);
        assert!(authorize(&allowed, Some(7)).is_ok());
        let wrong = authorize(&allowed, Some(8)).unwrap_err();
        assert_eq!(wrong.code(), tonic::Code::PermissionDenied);
        assert!(!wrong.message().contains("secret"));
        let missing = authorize(&allowed, None).unwrap_err();
        assert_eq!(missing.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn forkchoice_hashes_and_attributes_are_bounded() {
        let mut req = pb::ForkchoiceUpdatedRequest {
            head_block_hash: vec![1; 32],
            safe_block_hash: vec![2; 32],
            finalized_block_hash: vec![3; 32],
            ..Default::default()
        };
        assert!(forkchoice_params("engine_forkchoiceUpdatedV4", &req).is_ok());
        req.safe_block_hash = vec![2; 31];
        assert!(forkchoice_params("engine_forkchoiceUpdatedV4", &req).is_err());
        req.safe_block_hash = vec![2; 32];
        req.payload_attributes = Some(pb::VersionedData {
            data: vec![b' '; MAX_PAYLOAD_ATTRIBUTES + 1],
            ..Default::default()
        });
        assert!(forkchoice_params("engine_forkchoiceUpdatedV4", &req).is_err());
    }

    /// common.md: the CL MUST wait the method's timeout and MAY wait longer. A caller's
    /// `timeout_ms` raises the wait, never shortens it.
    #[test]
    fn a_caller_timeout_never_shortens_the_spec_wait() {
        let (spec, ceiling) = (Duration::from_secs(8), Duration::from_secs(10));
        assert_eq!(timeout_of(0, spec, ceiling), spec);
        assert_eq!(timeout_of(500, spec, ceiling), spec);
        assert_eq!(timeout_of(9_000, spec, ceiling), Duration::from_secs(9));
    }

    /// A raised wait stops at the gRPC request deadline: past it the caller is gone, and a sent
    /// call would hold the queue for nothing. A deadline below the spec wait never shortens it.
    #[test]
    fn a_caller_timeout_is_capped_at_the_request_deadline() {
        let spec = Duration::from_secs(8);
        assert_eq!(
            timeout_of(u32::MAX, spec, Duration::from_secs(10)),
            Duration::from_secs(10)
        );
        assert_eq!(timeout_of(u32::MAX, spec, Duration::from_secs(1)), spec);
    }

    /// execution-apis timeouts: newPayloadV5 6 s (amsterdam.md), newPayloadV4 8 s (prague.md),
    /// forkchoiceUpdatedV3/V4 8 s (cancun.md, amsterdam.md), getBlobsV2/V3/V4 1 s (osaka.md,
    /// amsterdam.md). getPayload has stated none since execution-apis #958 ("served
    /// immediately"); 1 s is this client's own bound.
    #[test]
    fn each_method_waits_its_spec_timeout() {
        let secs = Duration::from_secs;
        for (method, want) in [
            ("engine_newPayloadV5", secs(6)),
            ("engine_newPayloadV4", secs(8)),
            ("engine_forkchoiceUpdatedV4", secs(8)),
            ("engine_forkchoiceUpdatedV3", secs(8)),
            ("engine_getPayloadV6", secs(1)),
            ("engine_getPayloadV5", secs(1)),
            ("engine_getBlobsV4", secs(1)),
            ("engine_getBlobsV3", secs(1)),
            ("engine_getBlobsV2", secs(1)),
        ] {
            assert_eq!(spec_timeout(method), want, "{method}");
        }
    }

    /// Every method this server can route is offered to the EL in the capability exchange.
    #[test]
    fn every_routed_method_is_advertised() {
        let advertised = crate::capabilities::ADVERTISED;
        for version in [
            pb::EngineMethodVersion::FuluOsaka,
            pb::EngineMethodVersion::GloasAmsterdam,
        ] {
            let version = version as i32;
            for method in [
                new_payload_method(version).unwrap(),
                forkchoice_method(version).unwrap(),
                get_payload_method(version).unwrap(),
                get_blobs_method(version, false).unwrap(),
                get_blobs_method(version, true).unwrap(),
            ] {
                assert!(advertised.contains(&method), "{method}");
            }
        }
    }

    #[test]
    fn versions_name_the_method_the_caller_asked_for() {
        assert_eq!(
            new_payload_method(pb::EngineMethodVersion::GloasAmsterdam as i32).unwrap(),
            "engine_newPayloadV5"
        );
        assert_eq!(
            new_payload_method(pb::EngineMethodVersion::FuluOsaka as i32).unwrap(),
            "engine_newPayloadV4"
        );
        assert!(new_payload_method(pb::EngineMethodVersion::Unspecified as i32).is_err());
        assert_eq!(
            forkchoice_method(pb::EngineMethodVersion::GloasAmsterdam as i32).unwrap(),
            "engine_forkchoiceUpdatedV4"
        );
        assert!(require_json(pb::PayloadEncoding::Ssz as i32).is_err());
        assert!(require_json(pb::PayloadEncoding::Json as i32).is_ok());
    }

    #[test]
    fn payload_status_reads_the_engine_strings_only() {
        let hash = format!("0x{}", "11".repeat(32));
        let value = serde_json::json!({
            "status": "VALID",
            "latestValidHash": hash,
            "validationError": null
        });
        let status = payload_status(&value).unwrap();
        assert_eq!(status.status, pb::PayloadStatusKind::Valid as i32);
        assert_eq!(status.latest_valid_hash, vec![0x11; 32]);
        let null = serde_json::json!({"status": "SYNCING", "latestValidHash": null});
        assert!(payload_status(&null).unwrap().latest_valid_hash.is_empty());
        assert!(payload_status(&serde_json::json!({"status": "OTHER"})).is_none());
    }

    /// `latestValidHash` is `DATA|null`, 32 bytes (paris.md): anything else is a malformed
    /// response, not a null hash.
    #[test]
    fn a_latest_valid_hash_that_is_not_32_bytes_is_malformed() {
        for hash in [
            serde_json::json!("0x11"),
            serde_json::json!(format!("0x{}", "11".repeat(33))),
            serde_json::json!(format!("0x{}", "zz".repeat(32))),
            serde_json::json!("11".repeat(32)),
            serde_json::json!(7),
        ] {
            let value = serde_json::json!({"status": "INVALID", "latestValidHash": hash});
            assert!(payload_status(&value).is_none(), "{hash}");
        }
    }
}
