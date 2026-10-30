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
//!   connection that sends nothing for [`Limits::idle_timeout`] is closed, and connections and
//!   in-flight requests per connection are capped.
//! - Errors and logs carry codes, UIDs and fixed text: never the secret or a payload.
//!
//! The socket itself comes from [`ipc::uds::bind`] (owned directory, stale socket removed only
//! after `lstat` shows our own socket).
use crate::client::{
    CallError, FORKCHOICE_UPDATED_TIMEOUT, GET_BLOBS_TIMEOUT, GET_PAYLOAD_TIMEOUT,
    NEW_PAYLOAD_TIMEOUT,
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
        }
    }

    /// The ordered queue.
    #[must_use]
    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Every `ethswarm.engine.v1` service, with the message size caps of `limits`.
    #[must_use]
    pub fn routes(self, limits: &Limits) -> tonic::service::Routes {
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
        let timeout = timeout_of(req.timeout_ms, NEW_PAYLOAD_TIMEOUT);
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
        let timeout = timeout_of(req.timeout_ms, FORKCHOICE_UPDATED_TIMEOUT);
        match self.queue.call(req.seq, method, params, timeout).await {
            Ok(result) => {
                let status = result.get("payloadStatus").and_then(payload_status);
                let payload_id = result
                    .get("payloadId")
                    .and_then(Value::as_str)
                    .and_then(decode_hex)
                    .unwrap_or_default();
                Ok(Response::new(pb::ForkchoiceUpdatedResponse {
                    seq: req.seq,
                    error: status
                        .is_none()
                        .then(|| failure_error(CallError::BadResponse)),
                    status,
                    payload_id,
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
        let method = match get_payload_method(req.version) {
            Ok(method) => method,
            Err(status) => return Err(self.refuse(req.seq, status).await),
        };
        let id = hex_id(&req.payload_id);
        let params = serde_json::json!([id]);
        let timeout = timeout_of(req.timeout_ms, GET_PAYLOAD_TIMEOUT);
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
        let method = match get_blobs_method(req.version, req.partial) {
            Ok(method) => method,
            Err(status) => return Err(self.refuse(req.seq, status).await),
        };
        let params = get_blobs_params(method, &req);
        let timeout = timeout_of(req.timeout_ms, GET_BLOBS_TIMEOUT);
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
                "engine_exchangeCapabilities",
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
    /// One request, from its headers through reading its body to the response.
    pub request_timeout: Duration,
    /// A connection that sends nothing for this long is closed.
    pub idle_timeout: Duration,
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
            _slot: slot,
        };
        if tx.send(Ok(admitted)).await.is_err() {
            return;
        }
    }
}

/// An accepted connection: holds a connection slot, and fails its read once the peer has sent
/// nothing for `idle`.
struct Admitted {
    stream: UnixStream,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    _slot: OwnedSemaphorePermit,
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
        match Pin::new(&mut this.stream).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if buf.filled().len() > before {
                    let next = Instant::now() + this.idle;
                    this.deadline.as_mut().reset(next);
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

/// The caller's `timeout_ms` may shorten the spec wait, never lengthen it.
fn timeout_of(override_ms: u32, default: Duration) -> Duration {
    if override_ms == 0 {
        default
    } else {
        Duration::from_millis(u64::from(override_ms)).min(default)
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

/// JSON-RPC params for `engine_getBlobsV*`. Every `DATA` value is
/// `0x`-prefixed hex (execution-apis `common.md`), including the V4
/// `indices_bitarray`.
fn get_blobs_params(method: &str, req: &pb::GetBlobsRequest) -> Value {
    let hashes: Vec<String> = req.versioned_hashes.iter().map(|h| hex_id(h)).collect();
    if method == "engine_getBlobsV4" {
        serde_json::json!([hashes, hex_id(&req.indices_bitarray)])
    } else {
        serde_json::json!([hashes])
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
/// `custodyColumns` param; the proto has no field for it yet, so it goes out as `null`.
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
    if method == "engine_forkchoiceUpdatedV4" {
        Ok(serde_json::json!([state, attributes, Value::Null]))
    } else {
        Ok(serde_json::json!([state, attributes]))
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
    let latest_valid_hash = value
        .get("latestValidHash")
        .and_then(Value::as_str)
        .and_then(decode_hex)
        .unwrap_or_default();
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
        assert!(v4[1].is_null() && v4[2].is_null());
        let v3 = forkchoice_params("engine_forkchoiceUpdatedV3", &req).unwrap();
        assert_eq!(v3.as_array().unwrap().len(), 2);
    }

    #[test]
    fn get_blobs_v4_sends_0x_prefixed_indices_bitarray() {
        let req = pb::GetBlobsRequest {
            versioned_hashes: vec![vec![0xab; 32]],
            indices_bitarray: vec![0x01; 16],
            ..Default::default()
        };
        let params = get_blobs_params("engine_getBlobsV4", &req);
        let wire = serde_json::to_string(&params).unwrap();
        let hash = format!("0x{}", "ab".repeat(32));
        let bits = format!("0x{}", "01".repeat(16));
        assert_eq!(wire, format!("[[\"{hash}\"],\"{bits}\"]"));
        let v2 = get_blobs_params("engine_getBlobsV2", &req);
        assert_eq!(
            serde_json::to_string(&v2).unwrap(),
            format!("[[\"{hash}\"]]")
        );
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

    #[test]
    fn a_caller_timeout_only_shortens_the_spec_wait() {
        let spec = Duration::from_secs(8);
        assert_eq!(timeout_of(0, spec), spec);
        assert_eq!(timeout_of(500, spec), Duration::from_millis(500));
        assert_eq!(timeout_of(60_000, spec), spec);
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
        let value = serde_json::json!({
            "status": "VALID",
            "latestValidHash": "0x11",
            "validationError": null
        });
        let status = payload_status(&value).unwrap();
        assert_eq!(status.status, pb::PayloadStatusKind::Valid as i32);
        assert_eq!(status.latest_valid_hash, vec![0x11]);
        assert!(payload_status(&serde_json::json!({"status": "OTHER"})).is_none());
    }
}
