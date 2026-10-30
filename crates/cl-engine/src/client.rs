//! HTTP/1.1 Engine API client (hyper) to one execution layer.
//!
//! Every call carries a fresh HS256 JWT. The URL must be loopback unless
//! [`EngineEndpoint::parse`] is given the operator opt-out. Response bodies are capped and every
//! call has a timeout. A reconnect bumps the connection generation; a body that arrives for an
//! earlier generation is dropped and never returned.

use crate::capabilities::{self, MissingCaps, ADVERTISED};
use crate::jwt::{self, JwtSecret};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use http::{HeaderValue, Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use zeroize::Zeroize;

/// Default authenticated Engine API port (`authentication.md`).
pub const DEFAULT_PORT: u16 = 8551;
/// Largest EL response body we will buffer.
///
/// `engine.proto` caps ordinary JSON at 32 MiB and `GetBlobs` at 48 MiB. One cap covers both.
pub const MAX_RESPONSE_BYTES: usize = 48 * 1024 * 1024;
/// `engine_newPayload` (`paris.md`, inherited by later versions). The proto comment says 6s;
/// execution-apis says 8s, and that is what we wait.
pub const NEW_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(8);
/// `engine_forkchoiceUpdated` (`paris.md`, inherited).
pub const FORKCHOICE_UPDATED_TIMEOUT: Duration = Duration::from_secs(8);
/// `engine_getPayload` (1s in every version that states a timeout).
pub const GET_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(1);
/// `engine_getBlobs` (1s where the spec states it; methods that state none use the same bound).
pub const GET_BLOBS_TIMEOUT: Duration = Duration::from_secs(1);
/// `engine_exchangeCapabilities` (`common.md`).
pub const EXCHANGE_CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(1);
/// TCP connect plus the HTTP/1.1 handshake of one dial. The spec sets no number; without a
/// bound, a dial to an address that drops packets would hold the queue.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(1);

/// Where `now` comes from. A test clock makes two requests carry different `iat` values
/// without sleeping.
pub trait Clock: Send + Sync {
    /// The time stamped into `iat`.
    fn now(&self) -> SystemTime;
}

/// [`SystemTime::now`].
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Capped exponential backoff between reconnect attempts. The spec does not set these
/// numbers; 200 ms growing to 5 s is the operational default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// Delay before the second attempt. The first attempt is immediate.
    pub initial: Duration,
    /// The delay never grows past this.
    pub cap: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(200),
            cap: Duration::from_secs(5),
        }
    }
}

impl Backoff {
    /// The delay before attempt `attempt` (0 is the first retry, after an immediate failure).
    #[must_use]
    pub fn delay(self, attempt: u32) -> Duration {
        let shift = attempt.min(16);
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.cap)
    }
}

/// Why an engine URL was refused. The URL itself is not included: it may carry userinfo.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// Not `http`.
    #[error("engine URL is not http")]
    NotHttp,
    /// Missing host, a path other than `/`, or a URL `http::Uri` refused.
    #[error("engine URL is malformed")]
    BadUrl,
    /// `user:password@` in the URL.
    #[error("credentials in the engine URL are refused")]
    Userinfo,
    /// Not a loopback address, and the opt-out was not set.
    #[error("engine URL is not a loopback address")]
    NotLoopback,
}

/// A parsed engine URL. Non-loopback targets exist only when the opt-out was set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineEndpoint {
    target: Target,
    authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Addr(SocketAddr),
    /// A hostname, allowed only with the operator opt-out. Resolved when dialing.
    Host {
        host: String,
        port: u16,
    },
}

impl EngineEndpoint {
    /// Parses `url` (`http://127.0.0.1:8551`).
    ///
    /// Loopback is `127.0.0.0/8`, `::1`, or an IPv4-mapped loopback address. Any other host,
    /// including a name, is rejected unless `allow_non_loopback` is set.
    pub fn parse(url: &str, allow_non_loopback: bool) -> Result<Self, EndpointError> {
        if url.chars().any(char::is_control) {
            return Err(EndpointError::BadUrl);
        }
        let uri: http::Uri = url.parse().map_err(|_| EndpointError::BadUrl)?;
        if uri.scheme_str() != Some("http") {
            return Err(EndpointError::NotHttp);
        }
        if uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err(EndpointError::Userinfo);
        }
        if uri.query().is_some() {
            return Err(EndpointError::BadUrl);
        }
        let path = uri.path();
        if !path.is_empty() && path != "/" {
            return Err(EndpointError::BadUrl);
        }
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or(EndpointError::BadUrl)?;
        // `http::Uri::host` keeps the brackets on an IPv6 address (`[::1]`).
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let port = uri.port_u16().unwrap_or(DEFAULT_PORT);
        match host.parse::<IpAddr>() {
            Ok(ip) => {
                if !allow_non_loopback && !is_loopback(ip) {
                    return Err(EndpointError::NotLoopback);
                }
                let authority = match ip {
                    IpAddr::V4(v4) => format!("{v4}:{port}"),
                    IpAddr::V6(v6) => format!("[{v6}]:{port}"),
                };
                Ok(Self {
                    target: Target::Addr(SocketAddr::new(ip, port)),
                    authority,
                })
            }
            Err(_) => {
                if !allow_non_loopback {
                    return Err(EndpointError::NotLoopback);
                }
                Ok(Self {
                    target: Target::Host {
                        host: host.to_owned(),
                        port,
                    },
                    authority: format!("{host}:{port}"),
                })
            }
        }
    }

    /// The `Host` header value.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    async fn resolve(&self) -> Result<SocketAddr, CallError> {
        match &self.target {
            Target::Addr(addr) => Ok(*addr),
            Target::Host { host, port } => {
                let mut found = tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .map_err(|_| CallError::Transport)?;
                found.next().ok_or(CallError::Transport)
            }
        }
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// What a caller passes to [`Session::connect`].
pub struct Config {
    /// Where the EL listens.
    pub endpoint: EngineEndpoint,
    /// The JWT secret. `Debug` of the session does not print it.
    pub secret: JwtSecret,
    /// Clock for `iat`. Defaults to [`SystemClock`].
    pub clock: Arc<dyn Clock>,
    /// Response body cap. Defaults to [`MAX_RESPONSE_BYTES`].
    pub max_body_bytes: usize,
    /// Reconnect backoff. Defaults to [`Backoff::default`].
    pub backoff: Backoff,
    /// How many dials one [`Session::reconnect`] attempts. Defaults to 5.
    pub max_reconnect_attempts: u32,
}

impl Config {
    /// `endpoint` and `secret`, with the operational defaults.
    #[must_use]
    pub fn new(endpoint: EngineEndpoint, secret: JwtSecret) -> Self {
        Self {
            endpoint,
            secret,
            clock: Arc::new(SystemClock),
            max_body_bytes: MAX_RESPONSE_BYTES,
            backoff: Backoff::default(),
            max_reconnect_attempts: 5,
        }
    }

    /// Replaces the clock.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Replaces the body cap.
    #[must_use]
    pub fn max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Replaces the backoff.
    #[must_use]
    pub fn backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Replaces how many times one reconnect dials.
    #[must_use]
    pub fn max_reconnect_attempts(mut self, max_reconnect_attempts: u32) -> Self {
        self.max_reconnect_attempts = max_reconnect_attempts.max(1);
        self
    }
}

/// Why connecting, or reconnecting, failed.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The URL was refused.
    #[error(transparent)]
    Endpoint(EndpointError),
    /// The TCP or HTTP connection failed.
    #[error("engine connection failed")]
    Transport,
    /// The EL rejected the JWT.
    #[error("engine rejected the JWT")]
    Unauthorized,
    /// The EL did not list the required methods.
    #[error("engine capabilities: {0}")]
    MissingCaps(MissingCaps),
    /// The capabilities response was not a JSON-RPC result.
    #[error("engine capabilities response was not JSON-RPC")]
    BadResponse,
    /// Every reconnect attempt failed.
    #[error("engine stayed unreachable")]
    Unavailable,
}

/// Why one engine call failed. No variant carries the secret, the token, or the response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// The deadline passed.
    #[error("engine call timed out")]
    Timeout,
    /// The response was larger than the cap.
    #[error("engine response exceeds {limit} bytes")]
    BodyTooLarge {
        /// The cap, in bytes.
        limit: usize,
    },
    /// HTTP status other than 200 or 401.
    #[error("engine HTTP {status}")]
    HttpStatus {
        /// The status code.
        status: u16,
    },
    /// HTTP 401.
    #[error("engine rejected the JWT")]
    Unauthorized,
    /// The connection failed.
    #[error("engine connection failed")]
    Transport,
    /// There is no connection.
    #[error("engine is not connected")]
    NotConnected,
    /// JSON-RPC was missing, or `id` did not match.
    #[error("engine response is not a JSON-RPC result for this call")]
    BadResponse,
    /// The EL returned a JSON-RPC error. The message is omitted.
    #[error("engine JSON-RPC error {code}")]
    Rpc {
        /// The JSON-RPC error code.
        code: i64,
    },
    /// The body belonged to a connection generation that has been replaced.
    #[error("engine result from an earlier connection was dropped")]
    StaleConnection,
    /// The capability check failed.
    #[error("engine capabilities: {0}")]
    MissingCaps(String),
    /// The worker is gone.
    #[error("engine queue stopped")]
    Stopped,
    /// `seq` was already executed or duplicated.
    #[error("engine seq was not accepted")]
    Sequence,
    /// Too many calls are already waiting for an earlier `seq`.
    #[error("engine queue is full")]
    Overloaded,
}

impl CallError {
    /// A failure that leaves no usable connection: the next call reconnects before it is sent.
    /// The call that failed is not sent again.
    #[must_use]
    pub fn reconnects(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Transport | Self::NotConnected | Self::StaleConnection
        )
    }
}

impl From<StartError> for CallError {
    fn from(err: StartError) -> Self {
        match err {
            StartError::Unauthorized => Self::Unauthorized,
            StartError::MissingCaps(missing) => Self::MissingCaps(missing.to_string()),
            StartError::BadResponse => Self::BadResponse,
            StartError::Endpoint(_) | StartError::Transport | StartError::Unavailable => {
                Self::Transport
            }
        }
    }
}

struct Slot {
    generation: u64,
    sender: SendRequest<Full<Bytes>>,
}

struct Inner {
    endpoint: EngineEndpoint,
    secret: JwtSecret,
    clock: Arc<dyn Clock>,
    max_body: usize,
    backoff: Backoff,
    max_attempts: u32,
    generation: AtomicU64,
    rpc_id: AtomicU64,
    late_dropped: AtomicU64,
    slot: Mutex<Option<Slot>>,
    #[cfg(test)]
    install_gate: Mutex<Option<tests::InstallGate>>,
}

/// One EL connection. Cloning shares it.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("authority", &self.inner.endpoint.authority())
            .field("generation", &self.generation())
            .field("max_body_bytes", &self.inner.max_body)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Dials `config.endpoint`, checks capabilities, and returns a session on success.
    ///
    /// A missing required method, or a JWT the EL rejects, refuses the start: no later call is
    /// attempted.
    pub async fn connect(config: Config) -> Result<Self, StartError> {
        let session = Self {
            inner: Arc::new(Inner {
                endpoint: config.endpoint,
                secret: config.secret,
                clock: config.clock,
                max_body: config.max_body_bytes,
                backoff: config.backoff,
                max_attempts: config.max_reconnect_attempts,
                generation: AtomicU64::new(1),
                rpc_id: AtomicU64::new(1),
                late_dropped: AtomicU64::new(0),
                slot: Mutex::new(None),
                #[cfg(test)]
                install_gate: Mutex::new(None),
            }),
        };
        let sender = session.dial_and_check().await?;
        *lock(&session.inner.slot) = Some(Slot {
            generation: 1,
            sender,
        });
        Ok(session)
    }

    /// JSON-RPC `method` with `params`, bounded by `timeout`.
    ///
    /// A fresh JWT is minted from the clock for this call. When the connection generation
    /// changes before the body is returned, the body is discarded.
    pub async fn call(
        &self,
        method: &str,
        params: &Value,
        timeout: Duration,
    ) -> Result<Value, CallError> {
        // `SendRequest` is not `Clone`. Take it for this call so a reconnect can install a
        // new one without sharing the old connection. The old sender stays alive until the
        // body has been read, which is what lets a late reply be discarded instead of applied.
        let (generation, mut sender) = self.take_sender()?;
        let result =
            tokio::time::timeout(timeout, self.round_trip(&mut sender, method, params)).await;
        if self.generation() != generation {
            self.inner.late_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(CallError::StaleConnection);
        }
        match result {
            Err(_) => {
                drop(sender);
                self.drop_if(generation);
                Err(CallError::Timeout)
            }
            Ok(Err(CallError::Transport)) => {
                drop(sender);
                self.drop_if(generation);
                Err(CallError::Transport)
            }
            Ok(other) => {
                self.restore(generation, sender);
                other
            }
        }
    }

    /// Bumps the connection generation, drops the old connection, and dials again.
    ///
    /// The capability check runs on the new connection before this returns. A missing
    /// capability does not install the connection. Safe to call concurrently with calls and
    /// with other reconnects: the generation only changes under the slot lock, and a reconnect
    /// that a newer one has overtaken drops its connection instead of installing it (it still
    /// returns `Ok`; the newer reconnect owns the slot).
    pub async fn reconnect(&self) -> Result<(), StartError> {
        let new_gen = {
            let mut slot = lock(&self.inner.slot);
            *slot = None;
            self.inner.generation.fetch_add(1, Ordering::AcqRel) + 1
        };
        tracing::info!(generation = new_gen, "engine reconnecting");
        let mut attempt = 0u32;
        loop {
            if attempt > 0 {
                let delay = self.inner.backoff.delay(attempt - 1);
                tokio::time::sleep(delay).await;
            }
            if self.generation() != new_gen {
                return Ok(());
            }
            if attempt == self.inner.max_attempts {
                return Err(StartError::Unavailable);
            }
            attempt += 1;
            match self.dial_and_check().await {
                Ok(sender) => {
                    #[cfg(test)]
                    self.install_gate(new_gen).await;
                    // Compare and install under one lock: a newer reconnect cannot slip in
                    // between, and the connection of a reconnect it overtook is dropped.
                    let mut slot = lock(&self.inner.slot);
                    if self.generation() == new_gen {
                        *slot = Some(Slot {
                            generation: new_gen,
                            sender,
                        });
                        tracing::info!(generation = new_gen, "engine reconnected");
                    }
                    return Ok(());
                }
                Err(
                    err @ (StartError::MissingCaps(_)
                    | StartError::Unauthorized
                    | StartError::Endpoint(_)),
                ) => {
                    return Err(err);
                }
                Err(_) => continue,
            }
        }
    }

    /// The current connection generation. Starts at 1 and increases on each reconnect.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::Acquire)
    }

    /// Bodies discarded because they arrived for an older generation.
    #[must_use]
    pub fn late_dropped(&self) -> u64 {
        self.inner.late_dropped.load(Ordering::Relaxed)
    }

    /// Whether a connection of the current generation is installed. When this is `false`, the
    /// queue reconnects before its next call.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        lock(&self.inner.slot)
            .as_ref()
            .is_some_and(|slot| slot.generation == self.generation())
    }

    fn take_sender(&self) -> Result<(u64, SendRequest<Full<Bytes>>), CallError> {
        let mut guard = lock(&self.inner.slot);
        let Some(slot) = guard.take() else {
            return Err(CallError::NotConnected);
        };
        let generation = self.generation();
        if slot.generation != generation {
            // Never put a stale connection back: leaving the slot empty makes the next call
            // reconnect.
            return Err(CallError::StaleConnection);
        }
        Ok((generation, slot.sender))
    }

    fn restore(&self, generation: u64, sender: SendRequest<Full<Bytes>>) {
        let mut guard = lock(&self.inner.slot);
        if guard.is_none() && self.generation() == generation {
            *guard = Some(Slot { generation, sender });
        }
    }

    fn drop_if(&self, generation: u64) {
        let mut guard = lock(&self.inner.slot);
        if guard
            .as_ref()
            .is_some_and(|slot| slot.generation == generation)
        {
            *guard = None;
        }
    }

    async fn dial_and_check(&self) -> Result<SendRequest<Full<Bytes>>, StartError> {
        let addr = self
            .inner
            .endpoint
            .resolve()
            .await
            .map_err(|_| StartError::Transport)?;
        let dial = async {
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(std::io::Error::other)
        };
        let (mut sender, connection) = tokio::time::timeout(DIAL_TIMEOUT, dial)
            .await
            .map_err(|_| StartError::Transport)?
            .map_err(|_| StartError::Transport)?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(error = %err, "engine http connection closed");
            }
        });
        let params = serde_json::json!([ADVERTISED]);
        let result = tokio::time::timeout(
            EXCHANGE_CAPABILITIES_TIMEOUT,
            self.round_trip(&mut sender, "engine_exchangeCapabilities", &params),
        )
        .await
        .map_err(|_| StartError::Transport)?
        .map_err(|err| match err {
            CallError::Unauthorized => StartError::Unauthorized,
            CallError::BadResponse | CallError::Rpc { .. } => StartError::BadResponse,
            CallError::BodyTooLarge { .. } | CallError::Timeout => StartError::BadResponse,
            _ => StartError::Transport,
        })?;
        let methods = result
            .as_array()
            .ok_or(StartError::BadResponse)?
            .iter()
            .map(|item| item.as_str().ok_or(StartError::BadResponse))
            .collect::<Result<Vec<_>, _>>()?;
        capabilities::check(methods).map_err(StartError::MissingCaps)?;
        Ok(sender)
    }

    async fn round_trip(
        &self,
        sender: &mut SendRequest<Full<Bytes>>,
        method: &str,
        params: &Value,
    ) -> Result<Value, CallError> {
        let id = self.inner.rpc_id.fetch_add(1, Ordering::Relaxed);
        let mut token = jwt::token(self.inner.secret.expose_secret(), self.inner.clock.now());
        if token.is_empty() {
            return Err(CallError::Transport);
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|_| CallError::BadResponse)?;
        let mut bearer = format!("Bearer {token}");
        token.zeroize();
        let authorization = HeaderValue::from_str(&bearer).map_err(|_| {
            bearer.zeroize();
            CallError::Transport
        })?;
        bearer.zeroize();
        let request = Request::post("/")
            .header(HOST, self.inner.endpoint.authority())
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, authorization)
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| CallError::Transport)?;
        sender.ready().await.map_err(|_| CallError::Transport)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| CallError::Transport)?;
        let status = response.status();
        let declared = content_length(response.headers());
        if declared.is_some_and(|len| len > self.inner.max_body) {
            return Err(CallError::BodyTooLarge {
                limit: self.inner.max_body,
            });
        }
        let collected = Limited::new(response.into_body(), self.inner.max_body)
            .collect()
            .await
            .map_err(|err| {
                if err
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    CallError::BodyTooLarge {
                        limit: self.inner.max_body,
                    }
                } else {
                    CallError::Transport
                }
            })?;
        if status == StatusCode::UNAUTHORIZED {
            return Err(CallError::Unauthorized);
        }
        if status != StatusCode::OK {
            return Err(CallError::HttpStatus {
                status: status.as_u16(),
            });
        }
        decode_rpc(id, &collected.to_bytes())
    }
}

fn content_length(headers: &http::HeaderMap) -> Option<usize> {
    let value = headers.get(CONTENT_LENGTH)?.to_str().ok()?;
    let parsed: u64 = value.trim().parse().ok()?;
    usize::try_from(parsed).ok()
}

fn decode_rpc(id: u64, bytes: &[u8]) -> Result<Value, CallError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| CallError::BadResponse)?;
    let got = value.get("id").and_then(Value::as_u64);
    if got != Some(id) {
        return Err(CallError::BadResponse);
    }
    if let Some(err) = value.get("error").filter(|err| !err.is_null()) {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        return Err(CallError::Rpc { code });
    }
    value.get("result").cloned().ok_or(CallError::BadResponse)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
impl Session {
    /// Test seam: a reconnect for the gated generation stops here, with its connection dialed
    /// and checked, until the test lets it go.
    async fn install_gate(&self, generation: u64) {
        let gate = lock(&self.inner.install_gate).take_if(|gate| gate.generation == generation);
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.go.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_mock::{required_methods, test_secret, MockEl};
    use tokio::sync::Notify;

    pub(super) struct InstallGate {
        pub(super) generation: u64,
        pub(super) reached: Arc<Notify>,
        pub(super) go: Arc<Notify>,
    }

    /// Two reconnects overlap: the older one (generation 2) finishes dialing only after the
    /// newer one (generation 3) has installed its connection. The older connection must not
    /// replace it, and `is_connected` must agree with what a call gets.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn losing_reconnect_does_not_install_its_connection() {
        let secret = test_secret([0x33; 32]);
        let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
        let config = Config::new(EngineEndpoint::parse(&mock.url(), false).unwrap(), secret);
        let session = Session::connect(config).await.unwrap();
        let reached = Arc::new(Notify::new());
        let go = Arc::new(Notify::new());
        *lock(&session.inner.install_gate) = Some(InstallGate {
            generation: 2,
            reached: Arc::clone(&reached),
            go: Arc::clone(&go),
        });
        let older = {
            let session = session.clone();
            tokio::spawn(async move { session.reconnect().await })
        };
        reached.notified().await;
        session.reconnect().await.unwrap();
        assert_eq!(session.generation(), 3);
        go.notify_one();
        older.await.unwrap().unwrap();
        assert_eq!(session.generation(), 3);
        for seq in 1..=3_u64 {
            assert!(session.is_connected());
            let value = session
                .call(
                    "engine_newPayloadV5",
                    &serde_json::json!([seq]),
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
            assert_eq!(value["status"], "VALID");
        }
    }

    /// Two reconnects race, 1,000 times: the installed connection is always the highest
    /// generation, and `is_connected` agrees with whether a call can take the connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn racing_reconnects_install_the_highest_generation() {
        let secret = test_secret([0x44; 32]);
        let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
        let config = Config::new(EngineEndpoint::parse(&mock.url(), false).unwrap(), secret);
        let session = Session::connect(config).await.unwrap();
        for round in 0..1_000 {
            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            let tasks: Vec<_> = (0..2)
                .map(|_| {
                    let session = session.clone();
                    let barrier = Arc::clone(&barrier);
                    tokio::spawn(async move {
                        barrier.wait().await;
                        session.reconnect().await
                    })
                })
                .collect();
            for task in tasks {
                task.await.unwrap().unwrap();
            }
            let highest = session.generation();
            let installed = lock(&session.inner.slot)
                .as_ref()
                .map(|slot| slot.generation);
            assert_eq!(installed, Some(highest), "round {round}");
            let connected = session.is_connected();
            let taken = session.take_sender();
            assert_eq!(connected, taken.is_ok(), "round {round}");
            let (generation, sender) = taken.unwrap();
            assert_eq!(generation, highest, "round {round}");
            session.restore(generation, sender);
        }
    }

    #[test]
    fn loopback_is_accepted_and_anything_else_needs_the_opt_out() {
        let ok = [
            "http://127.0.0.1:8551",
            "http://127.0.0.1",
            "http://127.1.2.3:8551/",
            "http://[::1]:8551",
            "http://[::ffff:127.0.0.1]:8551",
        ];
        for url in ok {
            assert!(EngineEndpoint::parse(url, false).is_ok(), "{url}");
        }
        let refused = [
            "http://10.1.2.3:8551",
            "http://8.8.8.8:8551",
            "http://0.0.0.0:8551",
            "http://[::]:8551",
            "http://localhost:8551",
            "http://example.com:8551",
            "https://127.0.0.1:8551",
            "http://user:secret@127.0.0.1:8551",
        ];
        for url in refused {
            let err = EngineEndpoint::parse(url, false).unwrap_err();
            let shown = err.to_string();
            assert!(!shown.contains("secret"), "{url}: {shown}");
            if url.contains("@") {
                assert_eq!(err, EndpointError::Userinfo);
            }
        }
        assert!(EngineEndpoint::parse("http://10.1.2.3:8551", true).is_ok());
        assert!(EngineEndpoint::parse("http://example.com:8551", true).is_ok());
        assert_eq!(
            EngineEndpoint::parse("http://10.1.2.3:8551", false).unwrap_err(),
            EndpointError::NotLoopback
        );
    }

    #[test]
    fn backoff_doubles_until_the_cap() {
        let backoff = Backoff {
            initial: Duration::from_millis(10),
            cap: Duration::from_millis(50),
        };
        assert_eq!(backoff.delay(0), Duration::from_millis(10));
        assert_eq!(backoff.delay(1), Duration::from_millis(20));
        assert_eq!(backoff.delay(2), Duration::from_millis(40));
        assert_eq!(backoff.delay(3), Duration::from_millis(50));
        assert_eq!(backoff.delay(20), Duration::from_millis(50));
    }
}
