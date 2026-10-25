//! One service process from start to exit.
//!
//! Startup, in this order; any failure ends it before READY:
//! 0. every `[methods]` path of the ACL must be a method of a served service;
//! 1. bind the service socket ([`ipc::uds::bind`]: directory `0750`, stale-socket cleanup,
//!    instance lock, socket `0660` with its owner and group set explicitly);
//! 2. listen for `/metrics` on `127.0.0.1` ([`Hooks::registry`], then [`Hooks::unprefixed`]);
//! 3. serve the routes behind the trace, metrics and method-ACL layers (outermost first);
//! 4. `READY=1` to the service manager, with the socket and metrics address in `STATUS=`.
//!
//! Shutdown, on SIGTERM or SIGINT ([`termination`]):
//! 1. the socket path is removed and the server stops accepting connections, so new calls
//!    fail; then `STOPPING=1`;
//! 2. calls already in flight get the drain deadline (`drain_timeout_ms`) to finish;
//! 3. `run` returns `Ok` (exit 0) once they have, or [`RuntimeError::DrainTimeout`] (exit 1)
//!    as soon as the deadline passes; the process then exits, which drops the calls still
//!    running. The instance lock is released last.
//! 4. [`run`] first logs an error [`run_with`] did not, then gives the log queue up to
//!    [`LOG_FLUSH_DEADLINE`] to reach stderr, measured from then. Logging, panics included,
//!    never blocks a tokio worker ([`crate::log_writer`]), so a stalled stderr delays neither
//!    the signal nor the drain, and the exit comes at most the drain deadline plus this one
//!    after SIGTERM.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ipc::acl::AclLayer;
use ipc::uds::{self, BindError};
use prometheus_client::registry::Registry;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::oneshot;
use tokio_stream::wrappers::UnixListenerStream;
use tower::ServiceBuilder;

use crate::config::Config;
use crate::notify::{Notifier, Systemd, STOPPING};
use crate::services::Services;
use crate::telemetry::{self, RuntimeMetrics, TraceLayer, TracingInitError, EXIT_NO_LOG_WRITER};

/// Why a service stopped other than cleanly.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("socket: {0}")]
    Bind(#[from] BindError),
    #[error("{what}: {source}")]
    Io {
        what: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("cannot notify the service manager: {0}")]
    Notify(#[source] io::Error),
    #[error("serving failed: {0}")]
    Serve(#[from] tonic::transport::Error),
    #[error("server task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("the server stopped before shutdown was requested")]
    Exited,
    #[error("the method ACL lists paths no served service answers: {}", .0.join(", "))]
    UnservedMethods(Vec<String>),
    #[error("in-flight calls did not finish within the {0:?} drain deadline")]
    DrainTimeout(Duration),
    /// The stderr log writer could not start ([`telemetry::TracingInitError::WriterUnavailable`]).
    #[error("the stderr log writer could not start: {0}")]
    LogWriter(#[source] io::Error),
}

impl RuntimeError {
    /// Whether [`run_with`] logged this error where it arose.
    fn logged(&self) -> bool {
        matches!(
            self,
            Self::UnservedMethods(_) | Self::Notify(_) | Self::DrainTimeout(_)
        )
    }
}

fn io_err(what: &'static str) -> impl FnOnce(io::Error) -> RuntimeError {
    move |source| RuntimeError::Io { what, source }
}

/// The process exit status for `run`'s result: 0 after a clean drain, [`EXIT_NO_LOG_WRITER`]
/// if the log writer could not start, 1 otherwise.
#[must_use]
pub fn exit_code(result: &Result<(), RuntimeError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(RuntimeError::LogWriter(_)) => ExitCode::from(EXIT_NO_LOG_WRITER),
        Err(_) => ExitCode::FAILURE,
    }
}

/// Resolves on the first SIGTERM or SIGINT. The handlers are installed when this is called
/// (inside a runtime), so a signal that arrives before the future is polled is not lost.
pub fn termination() -> io::Result<impl Future<Output = ()> + Send + 'static> {
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    Ok(async move {
        let name = tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = int.recv() => "SIGINT",
        };
        tracing::info!(signal = name, "shutting down");
    })
}

/// What [`run_with`] reports to and waits on.
pub struct Hooks {
    /// Receives `READY=1` and `STOPPING=1`.
    pub notifier: Arc<dyn Notifier>,
    /// Shutdown begins when this resolves.
    pub shutdown: Pin<Box<dyn Future<Output = ()> + Send>>,
    /// Served at `/metrics`; the runtime adds its own metrics. Register service metrics here
    /// before calling [`run_with`].
    pub registry: Registry,
    /// Served at `/metrics` after [`Self::registry`], without its prefix: the metrics whose
    /// names readers outside the service fix (for example gossipsub's `topic_msg_*`, or
    /// `p2p_goodbye_received_total`, which the run reports read). A name here must not also be
    /// one in [`Self::registry`].
    pub unprefixed: Registry,
}

impl Hooks {
    /// systemd notification, SIGTERM/SIGINT, and an empty `ethswarm_` registry.
    pub fn systemd() -> io::Result<Self> {
        Ok(Self {
            notifier: Arc::new(Systemd),
            shutdown: Box::pin(termination()?),
            registry: Registry::with_prefix("ethswarm"),
            unprefixed: Registry::default(),
        })
    }
}

/// How long [`run`] waits, after the drain, for the queued log lines to reach stderr. A stderr
/// nobody drains holds the exit back this long at most; the lines still queued are lost.
pub const LOG_FLUSH_DEADLINE: Duration = Duration::from_secs(2);

/// Runs a service with JSON logs on stderr, systemd notification and SIGTERM/SIGINT handling.
/// Before returning, it logs its error (if [`run_with`] did not already) and flushes the log
/// queue for up to [`LOG_FLUSH_DEADLINE`], so the error reaches stderr before the exit.
///
/// A service does not run without its logs: if the stderr log writer cannot start, `run`
/// returns [`RuntimeError::LogWriter`] at once, before binding anything and without writing
/// to stderr, and [`exit_code`] makes it [`EXIT_NO_LOG_WRITER`]. An owner that would rather
/// serve without logs calls [`telemetry::try_init_tracing`] first and carries on past
/// [`TracingInitError::WriterUnavailable`]: that first call settles the process's logging, so
/// `run` then goes on.
pub async fn run(config: Config, services: Services) -> Result<(), RuntimeError> {
    if let Err(TracingInitError::WriterUnavailable(e)) =
        telemetry::try_init_tracing(config.log_level)
    {
        return Err(RuntimeError::LogWriter(e));
    }
    let result = match Hooks::systemd() {
        Ok(hooks) => run_with(config, services, hooks).await,
        Err(e) => Err(io_err("install signal handlers")(e)),
    };
    if let Some(e) = result.as_ref().err().filter(|e| !e.logged()) {
        tracing::error!(error = %e, "the service stopped on an error");
    }
    telemetry::flush_logs_async(LOG_FLUSH_DEADLINE).await;
    result
}

/// Serves `services` as `config` says until `hooks.shutdown`, then drains (module docs).
pub async fn run_with(
    config: Config,
    services: Services,
    hooks: Hooks,
) -> Result<(), RuntimeError> {
    let unserved = services.unserved(&config.acl);
    if !unserved.is_empty() {
        tracing::error!(paths = ?unserved, "method ACL lists paths no served service answers");
        return Err(RuntimeError::UnservedMethods(unserved));
    }
    let Hooks {
        notifier,
        shutdown,
        mut registry,
        unprefixed,
    } = hooks;
    let metrics = RuntimeMetrics::register(&mut registry);

    let (listener, mut socket) = uds::bind(&config.socket, config.ownership)?
        .into_tokio()
        .map_err(io_err("socket listener"))?;
    let metrics_listener = telemetry::bind_metrics(config.metrics_port)
        .await
        .map_err(io_err("listen for /metrics on 127.0.0.1"))?;
    let metrics_addr = metrics_listener
        .local_addr()
        .map_err(io_err("metrics address"))?;
    let (stop_metrics, metrics_stopped) = oneshot::channel::<()>();
    let metrics_task = tokio::spawn(telemetry::serve_metrics(
        metrics_listener,
        Arc::from(vec![registry, unprefixed]),
        config.metrics_limits,
        async {
            let _ = metrics_stopped.await;
        },
    ));

    let denied = metrics.acl_denied.clone();
    let layers = ServiceBuilder::new()
        .layer(TraceLayer)
        .layer(metrics.layer())
        .layer(AclLayer::new(Arc::new(config.acl)).on_denied(move |_| {
            denied.inc();
        }));
    let (stop_serving, serving_stopped) = oneshot::channel::<()>();
    let mut server = tokio::spawn(
        tonic::transport::Server::builder()
            .layer(layers)
            .add_routes(services.into_routes())
            .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                let _ = serving_stopped.await;
            }),
    );

    let socket_path = config.socket.socket_path();
    let ready = format!(
        "READY=1\nSTATUS=serving {} on {}; metrics on http://{metrics_addr}/metrics",
        config.service,
        socket_path.display()
    );
    if let Err(e) = notifier.notify(&ready) {
        server.abort();
        metrics_task.abort();
        tracing::error!(error = %e, "cannot notify the service manager");
        return Err(RuntimeError::Notify(e));
    }
    metrics.ready.set(1);
    tracing::info!(
        service = %config.service,
        network = %config.network.name(),
        socket = %socket_path.display(),
        metrics = %metrics_addr,
        "ready"
    );

    tokio::select! {
        () = shutdown => {}
        served = &mut server => {
            metrics_task.abort();
            served??;
            return Err(RuntimeError::Exited);
        }
    }

    // Stop accepting: new connections fail from here on.
    // The drain deadline runs from here, so nothing after it (a slow manager) can extend it.
    let deadline = tokio::time::Instant::now() + config.drain_timeout;
    socket.unlink();
    let _ = stop_serving.send(());
    metrics.ready.set(0);
    if let Err(e) = notifier.notify(STOPPING) {
        tracing::warn!(error = %e, "cannot notify the service manager of the shutdown");
    }
    tracing::info!(deadline = ?config.drain_timeout, "stopping; draining in-flight calls");
    let drained = tokio::time::timeout_at(deadline, &mut server).await;
    let result = match drained {
        Ok(joined) => joined?.map_err(RuntimeError::from),
        Err(_) => {
            server.abort();
            tracing::error!(
                deadline = ?config.drain_timeout,
                inflight = metrics.inflight.get(),
                "drain deadline passed; dropping the remaining calls"
            );
            Err(RuntimeError::DrainTimeout(config.drain_timeout))
        }
    };
    let _ = stop_metrics.send(());
    let _ = metrics_task.await;
    drop(socket);
    if result.is_ok() {
        tracing::info!("stopped");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(&Ok(())), ExitCode::SUCCESS);
        assert_eq!(
            exit_code(&Err(RuntimeError::DrainTimeout(Duration::from_secs(1)))),
            ExitCode::FAILURE
        );
        assert_eq!(
            exit_code(&Err(RuntimeError::LogWriter(
                io::ErrorKind::WouldBlock.into()
            ))),
            ExitCode::from(EXIT_NO_LOG_WRITER)
        );
    }

    #[tokio::test]
    async fn termination_installs_handlers() {
        let fut = termination().unwrap();
        drop(fut);
        assert!(Hooks::systemd().is_ok());
    }
}
