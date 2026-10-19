//! Logs, trace ids and metrics.
//!
//! - **Logs** are JSON lines on stderr (journald keeps them) through `tracing`
//!   ([`init_tracing`]). Every call runs in an `rpc` span carrying the method and a `trace_id`
//!   ([`TraceLayer`]), so each line logged while serving it names the trace. The subscriber is
//!   a registry with the JSON layer under its own level filter, so an owner's extra layer
//!   ([`init_tracing_with`]) can see more. Lines reach stderr through a bounded queue and one
//!   writer thread ([`crate::log_writer`]): a stderr nobody drains drops lines (counted in
//!   `ethswarm_log_lines_dropped_total`) instead of blocking a tokio worker. Panics are logged
//!   as one JSON line on the same queue by the hook [`init_tracing_with`] installs, not written
//!   to stderr by the default hook.
//! - **Trace ids** are W3C trace ids: taken from the caller's `traceparent` header when it is
//!   valid, otherwise 16 random bytes ([`trace_id`]).
//! - **Metrics** are a prometheus-client [`Registry`] served as OpenMetrics text at `/metrics`
//!   on `127.0.0.1` only ([`bind_metrics`], [`serve_metrics`]); there is no setting for another
//!   address. The runtime registers [`RuntimeMetrics`] under the `ethswarm_` prefix.

use std::backtrace::{Backtrace, BacktraceStatus};
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::{TokioIo, TokioTimer};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;
use tracing::{Instrument, Subscriber};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::{Format, Json, JsonFields, Writer};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, MakeWriter};
use tracing_subscriber::layer::{Identity, Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;

use crate::log_writer;
pub use crate::log_writer::{LogQueueBounds, LogWriter};

/// The OpenMetrics text content type prometheus-client encodes.
pub const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// How long a `/metrics` client gets to send its request headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The JSON formatting layer, writing to `writer`. `level` filters this layer only, so another
/// layer of the same subscriber can see more (a per-layer filter). Events are formatted by
/// [`GuardedEvent`] and span fields by [`SpanFields`], so a field whose `Debug` panics cannot
/// break the subscriber or a line.
pub fn json_layer<S, W>(level: LevelFilter, writer: W) -> impl Layer<S> + Send + Sync + 'static
where
    S: Subscriber + for<'span> LookupSpan<'span>,
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt::layer()
        .event_format(json_events())
        .fmt_fields(SpanFields(JsonFields::new()))
        .with_writer(writer)
        .with_filter(level)
}

/// The JSON event formatter: the current span, not the span list.
fn json_events() -> GuardedEvent<Format<Json, SystemTime>> {
    GuardedEvent(
        tracing_subscriber::fmt::format()
            .json()
            .with_current_span(true)
            .with_span_list(false),
    )
}

/// The message of the line written for an event that could not be formatted.
const UNFORMATTED: &str = "log event could not be formatted";

/// An event formatter, with a panic or an error while formatting an event contained.
///
/// The fmt layer formats an event into a buffer of its thread's, and clears it only after a
/// format that succeeded. A field whose `Debug` panicked left its half-written JSON there, and
/// once the panic was caught (a tokio task, a `catch_unwind`), the next event on that thread
/// was written onto it as one line that is not JSON; each such panic grew the buffer, outside
/// the log queue's bound. A format that failed made the fmt layer write a line of its own, not
/// JSON either. Here the event is formatted into a buffer of its own, kept only once the
/// format finished; otherwise the event's line is [`unformatted_line`], its level and target
/// without its fields (a panic is logged by the panic hook too).
#[derive(Debug)]
struct GuardedEvent<E>(E);

impl<S, N, E> FormatEvent<S, N> for GuardedEvent<E>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
    E: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        let mut formatted = String::new();
        let done = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.0.format_event(ctx, Writer::new(&mut formatted), event)
        }));
        match done {
            Ok(Ok(())) => writer.write_str(&formatted),
            Ok(Err(fmt::Error)) => writer.write_str(&unformatted_line(event.metadata())),
            Err(payload) => {
                dispose(payload);
                writer.write_str(&unformatted_line(event.metadata()))
            }
        }
    }
}

/// The line of an event that could not be formatted, in the subscriber's JSON shape: its level
/// and target, and [`UNFORMATTED`] for its fields.
fn unformatted_line(event: &tracing::Metadata<'_>) -> String {
    let mut line = format!(
        r#"{{"timestamp":"{}","level":"{}","fields":{{"message":"{UNFORMATTED}"}},"target":"#,
        log_writer::timestamp(),
        event.level()
    );
    log_writer::push_json_str(&mut line, event.target());
    line.push_str("}\n");
    line
}

/// Drops a caught panic's payload, where a panic of its own `Drop` must not get out (a span's
/// extensions lock is held): that panic is caught, and its payload leaked, since dropping that
/// one could panic again.
fn dispose(payload: Box<dyn std::any::Any + Send>) {
    if let Err(again) = std::panic::catch_unwind(AssertUnwindSafe(move || drop(payload))) {
        std::mem::forget(again);
    }
}

/// The span fields, with a panic or an error while formatting them contained.
///
/// The fmt layer formats a span's fields (at creation and on each `record`) while it holds
/// that span's extensions lock. A field whose `Debug` panicked unwound through the lock and
/// poisoned it, and the registry reuses the span's slot: every later span in that slot then
/// panicked in the subscriber ("Mutex poisoned"), anywhere, even in a `Drop` (an abort), so
/// one bad field could take the service down. Here the panic stops inside the formatting: the
/// panic hook still logs it, the fields it interrupted are left out (`{}` at creation, the
/// previous ones on `record`), its payload is [`dispose`]d of, and the lock is released
/// normally. A format that fails leaves the fields out the same way, and succeeds: on a
/// failure the fmt layer would write to stderr itself (`eprintln!`), past the log queue.
#[derive(Debug)]
struct SpanFields<N>(N);

impl<'writer, N> FormatFields<'writer> for SpanFields<N>
where
    N: for<'w> FormatFields<'w> + 'static,
{
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut formatted = String::new();
        let done = std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.0.format_fields(Writer::new(&mut formatted), fields)
        }));
        match done {
            Ok(Ok(())) => writer.write_str(&formatted),
            Ok(Err(fmt::Error)) => writer.write_str("{}"),
            Err(payload) => {
                dispose(payload);
                writer.write_str("{}")
            }
        }
    }

    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        let mut merged = FormattedFields::<N>::new(current.fields.clone());
        let done =
            std::panic::catch_unwind(AssertUnwindSafe(|| self.0.add_fields(&mut merged, fields)));
        match done {
            Ok(Ok(())) => current.fields = merged.fields,
            Ok(Err(fmt::Error)) => {}
            Err(payload) => dispose(payload),
        }
        Ok(())
    }
}

/// The JSON subscriber the runtime installs, writing to `writer`: a registry with
/// [`json_layer`].
pub fn json_subscriber<W>(level: LevelFilter, writer: W) -> impl Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::registry().with(json_layer(level, writer))
}

/// Lines the stderr log writer dropped: its queue was full, or stderr refused them.
static STDERR_DROPPED: LazyLock<Counter> = LazyLock::new(Counter::default);

/// The process's stderr log writer, once [`init_tracing_with`] started it.
static STDERR_LOG: OnceLock<LogWriter> = OnceLock::new();

/// [`init_tracing_with`] the default queue bounds and no other layer.
pub fn init_tracing(level: LevelFilter) -> bool {
    init_tracing_with(level, LogQueueBounds::default(), Identity::new())
}

/// Installs, as the global default, a registry with `extra` and the JSON layer on stderr. The
/// lines go through a [`LogWriter`] queue bounded by `bounds`, so no caller ever blocks on
/// stderr; its drops count in `ethswarm_log_lines_dropped_total` ([`RuntimeMetrics`]).
///
/// `extra` gets none of the JSON layer's panic protection ([`json_layer`]): a panic in one of
/// its callbacks, or in the `Drop` of data it keeps in a span's extensions, can still unwind
/// through a span's extensions lock and poison it, and with it every later span in that slot.
/// An owner's layer must not panic there.
///
/// `false` if a subscriber was already installed (the existing one stays), or the writer
/// thread could not start (nothing is installed).
pub fn init_tracing_with<L>(level: LevelFilter, bounds: LogQueueBounds, extra: L) -> bool
where
    L: Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    if STDERR_LOG.get().is_some() {
        return false;
    }
    let Ok(writer) = LogWriter::spawn(io::stderr(), bounds, STDERR_DROPPED.clone()) else {
        return false;
    };
    // A racing first call has installed its own; this writer's thread stays idle.
    if STDERR_LOG.set(writer.clone()).is_err() {
        return false;
    }
    let subscriber = tracing_subscriber::registry()
        .with(extra)
        .with(json_layer(level, writer));
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        return false;
    }
    if let Some(writer) = STDERR_LOG.get() {
        install_panic_hook(writer);
    }
    true
}

/// How long the panic hook waits for the queue, its own line included, to reach stderr: long
/// enough for a healthy stderr before a panic ends the process, short enough that a stalled
/// one costs little, and paid once per stall, not once per panic
/// ([`LogWriter::flush_unless_stalled`]).
const PANIC_FLUSH: Duration = Duration::from_millis(100);

/// Replaces the default panic hook, which writes the message to stderr from the panicking
/// thread and so blocks it on a stalled stderr. The new hook builds one JSON line itself (the
/// message, location, thread and, when `RUST_BACKTRACE` asks for one, the backtrace, at ERROR)
/// and queues it on `writer`, then waits for the queue as [`report_panic`] says. The default
/// hook is not called.
///
/// It never goes through `tracing`: the panic may come from inside the subscriber (a span
/// field's `Debug`, formatted while the fmt layer holds that span's lock, which the hook's own
/// event would take again on the same thread), and a layer that panicked on the hook's event
/// would abort the process with a message written straight to stderr.
fn install_panic_hook(writer: &'static LogWriter) {
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let panic = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("Box<dyn Any>");
        let location = info.location().map(ToString::to_string);
        let thread = std::thread::current();
        let backtrace = Backtrace::capture();
        let backtrace =
            (backtrace.status() == BacktraceStatus::Captured).then(|| backtrace.to_string());
        let line = panic_line(
            panic,
            location.as_deref(),
            thread.name().unwrap_or("<unnamed>"),
            backtrace.as_deref(),
        );
        report_panic(writer, line.as_bytes());
    }));
}

/// Queues a panic's `line`, then waits up to [`PANIC_FLUSH`] for it to be written: not at all
/// if the line was dropped (the queue is full), on the writer thread itself, or once a wait
/// timed out with the writer stuck since. `true` if it was written.
fn report_panic(writer: &LogWriter, line: &[u8]) -> bool {
    writer.push(line) && writer.flush_unless_stalled(PANIC_FLUSH)
}

/// A panic as one line in the subscriber's JSON shape.
fn panic_line(
    panic: &str,
    location: Option<&str>,
    thread: &str,
    backtrace: Option<&str>,
) -> String {
    let mut line = format!(
        r#"{{"timestamp":"{}","level":"ERROR","fields":{{"message":"panicked","panic":"#,
        log_writer::timestamp()
    );
    log_writer::push_json_str(&mut line, panic);
    for (name, value) in [
        ("location", location),
        ("thread", Some(thread)),
        ("backtrace", backtrace),
    ] {
        if let Some(value) = value {
            line.push_str(&format!(r#","{name}":"#));
            log_writer::push_json_str(&mut line, value);
        }
    }
    line.push_str(&format!(r#"}},"target":"{}"}}"#, module_path!()));
    line.push('\n');
    line
}

/// Waits up to `timeout` for the stderr log queue to be written out ([`LogWriter::flush`]).
/// `true` if it was, or no stderr writer was started.
pub fn flush_logs(timeout: Duration) -> bool {
    STDERR_LOG.get().is_none_or(|writer| writer.flush(timeout))
}

/// [`flush_logs`] from async code, on a blocking thread so no tokio worker waits on it. The
/// deadline runs from the call: a blocking pool too busy to start the flush in time does not
/// extend it. `false` if the queue was not written out by then.
pub async fn flush_logs_async(timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    let flush = tokio::task::spawn_blocking(move || {
        flush_logs(deadline.saturating_duration_since(std::time::Instant::now()))
    });
    matches!(tokio::time::timeout(timeout, flush).await, Ok(Ok(true)))
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
        registry.register(
            "log_lines_dropped",
            "log lines lost: the stderr log queue was full, or stderr refused them",
            STDERR_DROPPED.clone(),
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
///
/// Built only through [`MetricsLimits::new`] (or [`Default`]), which checks the connection cap:
/// 0 would serve nothing, and above tokio's `Semaphore::MAX_PERMITS` [`serve_metrics`] would
/// panic.
///
/// ```compile_fail,E0451
/// let _ = svc_runtime::telemetry::MetricsLimits {
///     max_connections: 0,
///     connection_timeout: std::time::Duration::from_secs(1),
/// };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricsLimits {
    /// Connections served at once; one over this is accepted and closed at once:
    /// 1..=[`MAX_METRICS_CONNECTIONS`]. Crate-visible only for the config loader, which checks
    /// the same range.
    pub(crate) max_connections: usize,
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

/// Why [`MetricsLimits::new`] refused a limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MetricsLimitsError {
    #[error("max_connections {0} is outside 1..={MAX_METRICS_CONNECTIONS}")]
    MaxConnections(usize),
}

impl MetricsLimits {
    /// Limits serving at most `max_connections` at once (1..=[`MAX_METRICS_CONNECTIONS`]), with
    /// the default connection timeout.
    pub fn new(max_connections: usize) -> Result<Self, MetricsLimitsError> {
        if max_connections == 0 || max_connections > MAX_METRICS_CONNECTIONS {
            return Err(MetricsLimitsError::MaxConnections(max_connections));
        }
        Ok(Self {
            max_connections,
            ..Self::default()
        })
    }

    /// Connections served at once.
    #[must_use]
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }
}

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
    fn the_json_layer_leaves_the_other_layers_levels_alone() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tracing_subscriber::layer::{Context, SubscriberExt as _};
        use tracing_subscriber::Layer as _;

        /// Counts the events it is given.
        struct Count(Arc<AtomicUsize>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Count {
            fn on_event(&self, _: &tracing::Event<'_>, _: Context<'_, S>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let buf = Buffer::default();
        let seen = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(json_layer(LevelFilter::INFO, buf.clone()))
            .with(Count(Arc::clone(&seen)).with_filter(LevelFilter::DEBUG));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("a debug line");
            tracing::info!("an info line");
        });
        assert_eq!(
            seen.load(Ordering::Relaxed),
            2,
            "the counting layer sees DEBUG"
        );
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("an info line"), "{out}");
    }

    #[test]
    fn a_panic_line_is_one_json_line_with_its_fields_escaped() {
        let line = panic_line(
            "a \"quoted\" \\ word\nand\ttab \u{1}",
            Some("src/x.rs:1:2"),
            "tokio-runtime-worker",
            None,
        );
        assert!(line.starts_with(r#"{"timestamp":""#), "{line}");
        assert!(line.ends_with("}\n"), "{line}");
        assert_eq!(line.matches('\n').count(), 1, "{line}");
        assert!(line.contains(r#""level":"ERROR""#), "{line}");
        assert!(
            line.contains(r#""panic":"a \"quoted\" \\ word\nand\ttab \u0001""#),
            "{line}"
        );
        assert!(line.contains(r#""location":"src/x.rs:1:2""#), "{line}");
        assert!(
            line.contains(r#""thread":"tokio-runtime-worker""#),
            "{line}"
        );
        assert!(!line.contains("backtrace"), "{line}");

        let line = panic_line("p", None, "t", Some("0: main\n1: start"));
        assert!(!line.contains("location"), "{line}");
        assert!(
            line.contains(r#""backtrace":"0: main\n1: start""#),
            "{line}"
        );
        assert_eq!(line.matches('\n').count(), 1, "{line}");
    }

    /// A sink that blocks every write until the test ends.
    struct Stuck(std::sync::mpsc::Receiver<()>);

    impl io::Write for Stuck {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_panic_report_waits_once_on_a_stalled_sink_and_never_for_a_dropped_line() {
        let (_release, stuck) = std::sync::mpsc::channel();
        let bounds = LogQueueBounds {
            max_bytes: 1 << 20,
            max_lines: 2,
        };
        let writer = LogWriter::spawn(Stuck(stuck), bounds, Counter::default()).unwrap();
        let timed = |line: &[u8]| {
            let started = std::time::Instant::now();
            let flushed = report_panic(&writer, line);
            (flushed, started.elapsed())
        };
        // Queued; the sink is stuck, so the flush runs out its time.
        let (flushed, took) = timed(b"first\n");
        assert!(!flushed);
        assert!(took >= PANIC_FLUSH, "{took:?}");
        // Queued, but nothing was written since: no second wait.
        let (flushed, took) = timed(b"second\n");
        assert!(!flushed);
        assert!(took < PANIC_FLUSH, "{took:?}");
        // Dropped (the queue is full): nothing to wait for.
        let (flushed, took) = timed(b"third\n");
        assert!(!flushed);
        assert!(took < PANIC_FLUSH, "{took:?}");
    }

    #[test]
    fn a_span_field_whose_debug_panics_leaves_the_subscriber_usable() {
        /// A value whose `Debug` panics.
        struct PanicsOnDebug;
        impl fmt::Debug for PanicsOnDebug {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("PanicsOnDebug formatted (expected by this test)");
            }
        }

        let buf = Buffer::default();
        tracing::subscriber::with_default(json_subscriber(LevelFilter::INFO, buf.clone()), || {
            // Recorded later, and given at creation: each formats the value under the span's
            // lock. The spans are dropped at once, so the next one reuses their slot.
            for _ in 0..3 {
                let span = tracing::info_span!("recorded", value = tracing::field::Empty);
                let _entered = span.enter();
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    span.record("value", tracing::field::debug(PanicsOnDebug));
                }));
                tracing::info!("in the recorded span");
            }
            for _ in 0..3 {
                let _ = std::panic::catch_unwind(|| {
                    let span = tracing::info_span!("created", value = ?PanicsOnDebug);
                    let _entered = span.enter();
                });
            }
            let span = tracing::info_span!("after", n = 7, later = tracing::field::Empty);
            let _entered = span.enter();
            span.record("later", 8);
            tracing::info!("still logging");
        });
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let last = out.lines().last().unwrap_or_default();
        assert!(last.contains("still logging"), "{out}");
        assert!(
            last.contains(r#""span":{"later":8,"n":7,"name":"after"}"#),
            "{out}"
        );
        assert_eq!(out.matches("in the recorded span").count(), 3, "{out}");
    }

    /// A value whose `Debug` panics.
    struct DebugPanics;
    impl fmt::Debug for DebugPanics {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("DebugPanics formatted (expected by this test)");
        }
    }

    /// A panic payload whose own `Drop` panics.
    struct DropPanics;
    impl Drop for DropPanics {
        fn drop(&mut self) {
            panic!("DropPanics dropped (expected by this test)");
        }
    }

    /// A value whose `Debug` panics with a [`DropPanics`] payload.
    struct DebugPanicsWithADropPanic;
    impl fmt::Debug for DebugPanicsWithADropPanic {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            std::panic::panic_any(DropPanics);
        }
    }

    /// `f()`, its panic caught.
    fn caught(f: impl FnOnce()) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    }

    /// The lines `buf` holds, each checked to be one JSON object.
    fn json_lines(buf: &Buffer) -> Vec<String> {
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(out.is_empty() || out.ends_with('\n'), "{out}");
        out.lines()
            .map(|line| {
                assert!(json::is_object(line), "not one JSON object: {line}");
                line.to_owned()
            })
            .collect()
    }

    /// Just enough of a JSON parser to tell whether a line is one JSON object (RFC 8259).
    mod json {
        pub fn is_object(text: &str) -> bool {
            let mut p = Parser(text.as_bytes(), 0);
            p.ws();
            p.peek() == Some(b'{') && p.value() && {
                p.ws();
                p.1 == p.0.len()
            }
        }

        struct Parser<'a>(&'a [u8], usize);

        impl Parser<'_> {
            fn peek(&self) -> Option<u8> {
                self.0.get(self.1).copied()
            }
            fn eat(&mut self, b: u8) -> bool {
                let hit = self.peek() == Some(b);
                self.1 += usize::from(hit);
                hit
            }
            fn ws(&mut self) {
                while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                    self.1 += 1;
                }
            }
            fn literal(&mut self, word: &[u8]) -> bool {
                let hit = self.0[self.1..].starts_with(word);
                self.1 += if hit { word.len() } else { 0 };
                hit
            }
            fn value(&mut self) -> bool {
                self.ws();
                let ok = match self.peek() {
                    Some(b'{') => self.seq(b'{', b'}', |p| {
                        p.ws();
                        p.string()
                            && {
                                p.ws();
                                p.eat(b':')
                            }
                            && p.value()
                    }),
                    Some(b'[') => self.seq(b'[', b']', Self::value),
                    Some(b'"') => self.string(),
                    Some(b't') => self.literal(b"true"),
                    Some(b'f') => self.literal(b"false"),
                    Some(b'n') => self.literal(b"null"),
                    _ => self.number(),
                };
                self.ws();
                ok
            }
            fn seq(&mut self, open: u8, close: u8, item: fn(&mut Self) -> bool) -> bool {
                self.eat(open);
                self.ws();
                if self.eat(close) {
                    return true;
                }
                loop {
                    if !item(self) {
                        return false;
                    }
                    self.ws();
                    if self.eat(close) {
                        return true;
                    }
                    if !self.eat(b',') {
                        return false;
                    }
                }
            }
            fn string(&mut self) -> bool {
                if !self.eat(b'"') {
                    return false;
                }
                while let Some(b) = self.peek() {
                    self.1 += 1;
                    match b {
                        b'"' => return true,
                        b'\\' => {
                            let Some(e) = self.peek() else { return false };
                            self.1 += 1;
                            if e == b'u' {
                                let hex = self.0.get(self.1..self.1 + 4);
                                if !hex.is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) {
                                    return false;
                                }
                                self.1 += 4;
                            } else if !b"\"\\/bfnrt".contains(&e) {
                                return false;
                            }
                        }
                        0..0x20 => return false,
                        _ => {}
                    }
                }
                false
            }
            fn digits(&mut self) -> bool {
                let start = self.1;
                while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.1 += 1;
                }
                self.1 > start
            }
            fn number(&mut self) -> bool {
                self.eat(b'-');
                if !self.eat(b'0') && !self.digits() {
                    return false;
                }
                if self.eat(b'.') && !self.digits() {
                    return false;
                }
                if self.eat(b'e') || self.eat(b'E') {
                    let _ = self.eat(b'+') || self.eat(b'-');
                    return self.digits();
                }
                true
            }
        }

        #[test]
        fn it_tells_one_object_from_the_rest() {
            for good in [
                "{}",
                r#"{"a":1,"b":[true,false,null,-0.5e+3],"c":{"d":"\"\\é"}}"#,
                r#" { "a" : [ ] } "#,
            ] {
                assert!(is_object(good), "{good}");
            }
            for bad in [
                "",
                "[]",
                "{",
                r#"{"a":1}{"b":2}"#,
                r#"{"a":1,}"#,
                r#"{"a"}"#,
                r#"{"a":01}"#,
                r#"{"a":"\x"}"#,
                "{\"a\":\"\u{1}\"}",
                r#"{"a":tru}"#,
                r#"{"a":"open}"#,
                r#"{"timestamp":"t","fields":{"bad":{"timestamp":"t"}"#,
            ] {
                assert!(!is_object(bad), "{bad}");
            }
        }
    }

    #[test]
    fn an_event_field_whose_debug_panics_leaves_the_next_line_whole() {
        let buf = Buffer::default();
        tracing::subscriber::with_default(json_subscriber(LevelFilter::INFO, buf.clone()), || {
            // The same line before the panics, after one, and after many more on the same
            // thread: none of them leaves anything behind for the next line.
            tracing::info!("probe");
            caught(|| tracing::info!(value = ?DebugPanics, "half written"));
            tracing::info!("probe");
            for _ in 0..16 {
                caught(|| tracing::info!(value = ?DebugPanics, "half written"));
            }
            tracing::info!("probe");
        });
        let lines = json_lines(&buf);
        let probes: Vec<_> = lines.iter().filter(|l| l.contains("probe")).collect();
        assert_eq!(probes.len(), 3, "{lines:#?}");
        assert!(
            probes.iter().all(|p| p.len() == probes[0].len()),
            "{probes:#?}"
        );
        // Each event that could not be formatted is still a line, with its level and target.
        let lost: Vec<_> = lines.iter().filter(|l| l.contains(UNFORMATTED)).collect();
        assert_eq!(lost.len(), 17, "{lines:#?}");
        assert!(lost[0].contains(r#""level":"INFO""#), "{}", lost[0]);
        assert!(lost[0].contains(module_path!()), "{}", lost[0]);
        assert!(
            !lines.iter().any(|l| l.contains("half written")),
            "{lines:#?}"
        );
    }

    /// An event formatter that writes half a line and fails.
    struct FailingEvents;
    impl<S, N> FormatEvent<S, N> for FailingEvents
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        N: for<'w> FormatFields<'w> + 'static,
    {
        fn format_event(
            &self,
            _: &FmtContext<'_, S, N>,
            mut writer: Writer<'_>,
            _: &tracing::Event<'_>,
        ) -> fmt::Result {
            writer.write_str(r#"{"half":"#)?;
            Err(fmt::Error)
        }
    }

    /// A field formatter that writes half its fields and fails.
    struct FailingFields;
    impl<'w> FormatFields<'w> for FailingFields {
        fn format_fields<R: RecordFields>(&self, mut writer: Writer<'w>, _: R) -> fmt::Result {
            writer.write_str(r#"{"half":"#)?;
            Err(fmt::Error)
        }
    }

    #[test]
    fn an_event_that_fails_to_format_is_one_json_line_without_its_fields() {
        let buf = Buffer::default();
        let layer = tracing_subscriber::fmt::layer()
            .event_format(GuardedEvent(FailingEvents))
            .with_writer(buf.clone());
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            tracing::warn!(n = 1, "fails");
        });
        let lines = json_lines(&buf);
        assert_eq!(lines.len(), 1, "{lines:#?}");
        assert!(lines[0].contains(UNFORMATTED), "{}", lines[0]);
        assert!(lines[0].contains(r#""level":"WARN""#), "{}", lines[0]);
    }

    #[test]
    fn span_fields_that_fail_to_format_are_left_out() {
        let buf = Buffer::default();
        let layer = tracing_subscriber::fmt::layer()
            .event_format(json_events())
            .fmt_fields(SpanFields(FailingFields))
            .with_writer(buf.clone());
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            let span = tracing::info_span!("failing", n = 1);
            let _entered = span.enter();
            tracing::info!("in the failing span");
        });
        let lines = json_lines(&buf);
        assert_eq!(lines.len(), 1, "{lines:#?}");
        assert!(
            lines[0].contains(r#""span":{"name":"failing"}"#),
            "{}",
            lines[0]
        );
    }

    #[test]
    fn a_panic_payload_whose_drop_panics_poisons_nothing() {
        let buf = Buffer::default();
        tracing::subscriber::with_default(json_subscriber(LevelFilter::INFO, buf.clone()), || {
            for _ in 0..3 {
                let span = tracing::info_span!("recorded", value = tracing::field::Empty);
                let _entered = span.enter();
                caught(|| {
                    span.record("value", tracing::field::debug(DebugPanicsWithADropPanic));
                });
                caught(|| tracing::info!(value = ?DebugPanicsWithADropPanic, "event"));
                tracing::info!("in the recorded span");
            }
            for _ in 0..3 {
                caught(|| {
                    let span = tracing::info_span!("created", value = ?DebugPanicsWithADropPanic);
                    let _entered = span.enter();
                });
            }
            let span = tracing::info_span!("after", n = 7);
            let _entered = span.enter();
            tracing::info!("still logging");
        });
        let lines = json_lines(&buf);
        let last = lines.last().cloned().unwrap_or_default();
        assert!(last.contains("still logging"), "{lines:#?}");
        assert!(last.contains(r#""span":{"n":7,"name":"after"}"#), "{last}");
        let recorded = lines
            .iter()
            .filter(|l| l.contains("in the recorded span"))
            .count();
        assert_eq!(recorded, 3, "{lines:#?}");
    }

    #[test]
    fn init_tracing_installs_once() {
        // ERROR, not OFF: the panic hook it installs logs a failing test's panic at ERROR.
        let _ = init_tracing(LevelFilter::ERROR);
        assert!(
            !init_tracing(LevelFilter::OFF),
            "a second install is refused"
        );
        assert!(
            !init_tracing_with(
                LevelFilter::OFF,
                LogQueueBounds::default(),
                tracing_subscriber::layer::Identity::new()
            ),
            "so is one with another layer"
        );
        tracing::info!("dropped by the ERROR filter");
        assert!(flush_logs(Duration::from_secs(10)));
    }

    #[test]
    fn the_async_flush_holds_its_deadline_with_the_blocking_pool_busy() {
        // A stderr writer exists, so the flush has a queue to wait on.
        let _ = init_tracing(LevelFilter::ERROR);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (release, held) = std::sync::mpsc::channel::<()>();
        runtime.spawn_blocking(move || held.recv());
        let started = std::time::Instant::now();
        let flushed = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                flush_logs_async(Duration::from_millis(300)),
            )
            .await
        });
        let took = started.elapsed();
        assert_eq!(flushed, Ok(false), "the flush never ran: it timed out");
        assert!(took < Duration::from_secs(3), "{took:?}");
        release.send(()).unwrap();
        runtime.shutdown_timeout(Duration::from_secs(10));
    }

    #[tokio::test]
    async fn the_async_flush_reports_a_written_queue() {
        let _ = init_tracing(LevelFilter::ERROR);
        assert!(flush_logs_async(Duration::from_secs(10)).await);
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

    #[test]
    fn metrics_limits_are_checked_when_built() {
        for n in [0, MAX_METRICS_CONNECTIONS + 1, usize::MAX] {
            let err = MetricsLimits::new(n).unwrap_err();
            assert_eq!(err, MetricsLimitsError::MaxConnections(n));
            assert_eq!(
                err.to_string(),
                format!("max_connections {n} is outside 1..={MAX_METRICS_CONNECTIONS}")
            );
        }
        for n in [1, DEFAULT_METRICS_CONNECTIONS, MAX_METRICS_CONNECTIONS] {
            let limits = MetricsLimits::new(n).unwrap();
            assert_eq!(limits.max_connections(), n);
            assert_eq!(
                limits.connection_timeout,
                MetricsLimits::default().connection_timeout
            );
        }
        assert_eq!(
            MetricsLimits::default().max_connections(),
            DEFAULT_METRICS_CONNECTIONS
        );
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
        assert!(
            ok.lines()
                .any(|l| l.starts_with("ethswarm_log_lines_dropped_total ")),
            "{ok}"
        );
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
