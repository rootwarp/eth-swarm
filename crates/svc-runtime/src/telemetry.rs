//! Logs, trace ids and metrics.
//!
//! - **Logs** are JSON lines on stderr (journald keeps them) through `tracing`
//!   ([`init_tracing`]). Every call runs in an `rpc` span carrying the method and a `trace_id`
//!   ([`TraceLayer`]), so each line logged while serving it names the trace.
//! - **Trace ids** are W3C trace ids: taken from the caller's `traceparent` header when it is
//!   valid, otherwise 16 random bytes ([`trace_id`]).
//! - **Metrics** are a prometheus-client [`Registry`] served as OpenMetrics text at `/metrics`
//!   on `127.0.0.1` only ([`bind_metrics`], [`serve_metrics`]); there is no setting for another
//!   address. The runtime registers [`RuntimeMetrics`] under the `ethswarm_` prefix.

use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::{TokioIo, TokioTimer};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;
use tracing::Instrument;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

/// The OpenMetrics text content type prometheus-client encodes.
pub const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// How long a `/metrics` client gets to send its request headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The JSON subscriber the runtime installs, writing to `writer`.
pub fn json_subscriber<W>(level: LevelFilter, writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .json()
        .with_max_level(level)
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(writer)
        .finish()
}

/// Installs the JSON subscriber on stderr as the global default. `false` if one was already
/// installed (the existing one stays).
pub fn init_tracing(level: LevelFilter) -> bool {
    tracing::subscriber::set_global_default(json_subscriber(level, io::stderr)).is_ok()
}

/// A W3C trace id: 16 bytes, not all zero, shown as 32 lowercase hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceId(pub [u8; 16]);

impl TraceId {
    /// 16 random bytes.
    #[must_use]
    pub fn random() -> Self {
        loop {
            let bytes: [u8; 16] = rand::random();
            if bytes != [0; 16] {
                return Self(bytes);
            }
        }
    }

    /// The trace id of a `traceparent` header value
    /// (`<version>-<trace-id>-<parent-id>-<flags>`), if it is well formed.
    #[must_use]
    pub fn from_traceparent(value: &str) -> Option<Self> {
        let mut parts = value.split('-');
        let (version, trace, parent, flags) =
            (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        let hex = |s: &str, len: usize| {
            s.len() == len
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        // Version 00 has exactly four fields; later versions may append more.
        let extra = parts.next().is_some();
        if !hex(version, 2) || version == "ff" || (version == "00" && extra) {
            return None;
        }
        if !hex(trace, 32) || !hex(parent, 16) || !hex(flags, 2) {
            return None;
        }
        if parent.bytes().all(|b| b == b'0') {
            return None;
        }
        let mut id = [0u8; 16];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&trace[2 * i..2 * i + 2], 16).ok()?;
        }
        (id != [0; 16]).then_some(Self(id))
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// The trace id of a request: its `traceparent`, else a fresh random one.
#[must_use]
pub fn trace_id(headers: &http::HeaderMap) -> TraceId {
    headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(TraceId::from_traceparent)
        .unwrap_or_else(TraceId::random)
}

/// Runs every call in an `rpc` span with `method` and `trace_id`. The span covers the handler
/// and its response future; a task the handler spawns (a stream worker) must be spawned with
/// [`ipc::spawn_in_span`] to stay in it.
#[derive(Clone, Copy, Debug, Default)]
pub struct TraceLayer;

impl<S> tower::Layer<S> for TraceLayer {
    type Service = TraceService<S>;

    fn layer(&self, inner: S) -> TraceService<S> {
        TraceService { inner }
    }
}

/// The service [`TraceLayer`] wraps around `S`.
#[derive(Clone, Debug)]
pub struct TraceService<S> {
    inner: S,
}

impl<S, B> tower::Service<http::Request<B>> for TraceService<S>
where
    S: tower::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = tracing::instrument::Instrumented<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let id = trace_id(request.headers());
        let span = tracing::info_span!("rpc", method = %request.uri().path(), trace_id = %id);
        let future = span.in_scope(|| {
            tracing::debug!("call received");
            self.inner.call(request)
        });
        future.instrument(span)
    }
}

/// What the runtime itself counts.
#[derive(Clone, Debug, Default)]
pub struct RuntimeMetrics {
    /// gRPC calls received.
    pub requests: Counter,
    /// Calls whose response has not started yet.
    pub inflight: Gauge,
    /// Calls the method ACL refused.
    pub acl_denied: Counter,
    /// 1 between READY and STOPPING.
    pub ready: Gauge,
}

impl RuntimeMetrics {
    /// New metrics, registered in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let m = Self::default();
        registry.register("rpc_requests", "gRPC calls received", m.requests.clone());
        registry.register(
            "rpc_inflight",
            "gRPC calls whose response has not started",
            m.inflight.clone(),
        );
        registry.register(
            "acl_denied",
            "gRPC calls refused by the method ACL",
            m.acl_denied.clone(),
        );
        registry.register(
            "ready",
            "1 while the service accepts calls",
            m.ready.clone(),
        );
        m
    }

    /// The layer that counts calls into these metrics.
    #[must_use]
    pub fn layer(&self) -> MetricsLayer {
        MetricsLayer {
            metrics: self.clone(),
        }
    }
}

/// Counts calls and calls in flight.
#[derive(Clone, Debug)]
pub struct MetricsLayer {
    metrics: RuntimeMetrics,
}

impl<S> tower::Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> MetricsService<S> {
        MetricsService {
            inner,
            metrics: self.metrics.clone(),
        }
    }
}

/// The service [`MetricsLayer`] wraps around `S`.
#[derive(Clone, Debug)]
pub struct MetricsService<S> {
    inner: S,
    metrics: RuntimeMetrics,
}

/// Decrements the in-flight gauge when the call ends, however it ends.
struct InFlight(Gauge);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.dec();
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<S, B> tower::Service<http::Request<B>> for MetricsService<S>
where
    S: tower::Service<http::Request<B>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        self.metrics.requests.inc();
        self.metrics.inflight.inc();
        let guard = InFlight(self.metrics.inflight.clone());
        let future = self.inner.call(request);
        Box::pin(async move {
            let _guard = guard;
            future.await
        })
    }
}

/// Listens for `/metrics` on `127.0.0.1:port` (0: the OS picks a port).
pub async fn bind_metrics(port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await
}

/// Bounds on the `/metrics` listener. Any local user can connect to it (it is TCP on
/// loopback, outside the socket directory's group check), so it must not be able to use up the
/// service's descriptors or tasks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricsLimits {
    /// Connections served at once; one over this is accepted and closed at once. A config may
    /// ask for 1..=[`MAX_METRICS_CONNECTIONS`].
    pub max_connections: usize,
    /// The longest a connection lives, request and response included.
    pub connection_timeout: Duration,
}

/// Default [`MetricsLimits::max_connections`].
pub const DEFAULT_METRICS_CONNECTIONS: usize = 8;

/// The most [`MetricsLimits::max_connections`] a config may ask for. A scrape is one short
/// request per connection, so a handful is plenty; the cap keeps a typo from reserving
/// descriptors, and stays far below tokio's `Semaphore::MAX_PERMITS`, above which the semaphore
/// panics.
pub const MAX_METRICS_CONNECTIONS: usize = 1024;
const _: () = assert!(MAX_METRICS_CONNECTIONS <= tokio::sync::Semaphore::MAX_PERMITS);

impl Default for MetricsLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_METRICS_CONNECTIONS,
            connection_timeout: Duration::from_secs(10),
        }
    }
}

/// Serves `registry` at `GET /metrics` until `shutdown` resolves, one request per connection
/// (no keep-alive), at most `limits.max_connections` at a time.
pub async fn serve_metrics(
    listener: TcpListener,
    registry: Arc<Registry>,
    limits: MetricsLimits,
    shutdown: impl Future<Output = ()>,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    tokio::pin!(shutdown);
    loop {
        let stream = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::warn!(error = %e, "metrics accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        // Over the cap: close it now; no task, no descriptor kept.
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!("metrics connection refused: all slots busy");
            drop(stream);
            continue;
        };
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            let _slot = slot;
            let service = hyper::service::service_fn(move |req| {
                std::future::ready(Ok::<_, Infallible>(respond(&req, &registry)))
            });
            let connection = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            match tokio::time::timeout(limits.connection_timeout, connection).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::debug!(error = %e, "metrics connection ended"),
                Err(_) => tracing::debug!("metrics connection cut off at its time limit"),
            }
        });
    }
}

fn respond<B>(request: &http::Request<B>, registry: &Registry) -> http::Response<Full<Bytes>> {
    let reply = |status: http::StatusCode, content_type: &str, body: String| {
        http::Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, content_type)
            .body(Full::new(Bytes::from(body)))
            .expect("static response parts")
    };
    if request.uri().path() != "/metrics" {
        return reply(
            http::StatusCode::NOT_FOUND,
            "text/plain",
            "not found\n".into(),
        );
    }
    if request.method() != http::Method::GET {
        return reply(
            http::StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            "GET only\n".into(),
        );
    }
    let mut body = String::new();
    match prometheus_client::encoding::text::encode(&mut body, registry) {
        Ok(()) => reply(http::StatusCode::OK, METRICS_CONTENT_TYPE, body),
        Err(e) => reply(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "text/plain",
            format!("cannot encode metrics: {e}\n"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::{Layer, ServiceExt};

    #[test]
    fn traceparent_gives_the_trace_id() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let id = TraceId::from_traceparent(tp).unwrap();
        assert_eq!(id.to_string(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(TraceId::from_traceparent(&format!("01{}-extra", &tp[2..])).is_some());
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "0g-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ] {
            assert_eq!(TraceId::from_traceparent(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn requests_without_a_valid_traceparent_get_a_random_id() {
        let mut h = http::HeaderMap::new();
        let a = trace_id(&h);
        assert_ne!(a, trace_id(&h));
        assert_eq!(a.to_string().len(), 32);
        h.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        assert_eq!(trace_id(&h).to_string(), "4bf92f3577b34da6a3ce929d0e0e4736");
    }

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

    #[tokio::test]
    async fn every_log_line_of_a_call_is_json_with_its_trace_id() {
        let buf = Buffer::default();
        let _default =
            tracing::subscriber::set_default(json_subscriber(LevelFilter::DEBUG, buf.clone()));
        let inner = tower::service_fn(|_: http::Request<()>| async {
            tracing::info!(answer = 42, "handled");
            Ok::<_, Infallible>(())
        });
        let svc = TraceLayer.layer(inner);
        let req = http::Request::builder()
            .uri("/ethswarm.engine.v1.EngineService/NewPayload")
            .header(
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
            .body(())
            .unwrap();
        svc.oneshot(req).await.unwrap();
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        for line in lines {
            assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
            assert!(
                line.contains(r#""trace_id":"4bf92f3577b34da6a3ce929d0e0e4736""#),
                "{line}"
            );
            assert!(line.contains("EngineService/NewPayload"), "{line}");
        }
        assert!(out.contains(r#""answer":42"#), "{out}");
    }

    #[test]
    fn init_tracing_installs_once() {
        let _ = init_tracing(LevelFilter::OFF);
        assert!(
            !init_tracing(LevelFilter::OFF),
            "a second install is refused"
        );
    }

    #[tokio::test]
    async fn metrics_layer_counts_calls_in_flight() {
        let mut registry = Registry::with_prefix("ethswarm");
        let m = RuntimeMetrics::register(&mut registry);
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let wait = Arc::new(Mutex::new(Some(wait)));
        let inner = tower::service_fn(move |_: http::Request<()>| {
            let wait = wait.lock().unwrap().take();
            async move {
                if let Some(w) = wait {
                    let _ = w.await;
                }
                Ok::<_, Infallible>(())
            }
        });
        let svc = m.layer().layer(inner);
        let slow = tokio::spawn(svc.clone().oneshot(http::Request::new(())));
        tokio::task::yield_now().await;
        while m.inflight.get() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!((m.requests.get(), m.inflight.get()), (1, 1));
        release.send(()).unwrap();
        slow.await.unwrap().unwrap();
        svc.oneshot(http::Request::new(())).await.unwrap();
        assert_eq!((m.requests.get(), m.inflight.get()), (2, 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn metrics_connections_over_the_cap_are_closed() {
        let listener = bind_metrics(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limits = MetricsLimits {
            max_connections: 2,
            connection_timeout: Duration::from_secs(30),
        };
        assert_eq!(MetricsLimits::default().max_connections, 8);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_metrics(
            listener,
            Arc::new(Registry::default()),
            limits,
            async {
                let _ = stopped.await;
            },
        ));
        // Two idle connections take both slots.
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(tokio::net::TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let tasks = || {
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
        };
        let before = tasks();
        // Every connection over the cap is closed at once and spawns nothing.
        for _ in 0..50 {
            let mut extra = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut buf = [0u8; 1];
            let n = tokio::time::timeout(Duration::from_secs(5), extra.read(&mut buf))
                .await
                .expect("closed promptly")
                .unwrap_or(0);
            assert_eq!(n, 0);
        }
        assert!(tasks() <= before, "{} tasks, were {before}", tasks());
        // Freed slots serve again, and a response ends the connection (no keep-alive).
        drop(held);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let ok = get(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        stop.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_slow_metrics_client_is_cut_off() {
        let listener = bind_metrics(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limits = MetricsLimits {
            max_connections: 1,
            connection_timeout: Duration::from_millis(300),
        };
        tokio::spawn(serve_metrics(
            listener,
            Arc::new(Registry::default()),
            limits,
            std::future::pending(),
        ));
        // Headers trickle in and are never finished: the connection's lifetime bound ends it.
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /metrics HTTP/1.1\r\n").await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut buf))
            .await
            .expect("cut off")
            .ok();
        let ok = get(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(
            ok.starts_with("HTTP/1.1 200"),
            "the slot is free again: {ok}"
        );
    }

    async fn get(addr: SocketAddr, request: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn metrics_are_served_on_loopback_only() {
        let listener = bind_metrics(0).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
        let mut registry = Registry::with_prefix("ethswarm");
        let m = RuntimeMetrics::register(&mut registry);
        m.ready.set(1);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_metrics(
            listener,
            Arc::new(registry),
            MetricsLimits::default(),
            async {
                let _ = stopped.await;
            },
        ));
        let ok = get(
            addr,
            "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains(METRICS_CONTENT_TYPE), "{ok}");
        assert!(ok.contains("ethswarm_ready 1"), "{ok}");
        assert!(ok.contains("ethswarm_rpc_requests_total 0"), "{ok}");
        let missing = get(
            addr,
            "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
        let post = get(
            addr,
            "POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        stop.send(()).unwrap();
        server.await.unwrap();
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "closed"
        );
    }
}
