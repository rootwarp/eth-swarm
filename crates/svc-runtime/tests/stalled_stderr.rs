//! A service whose stderr nobody reads keeps serving, and still drains and exits on SIGTERM.
//!
//! Each test runs a real process: this test binary re-executed to run
//! `serve_chatty_engine_child` (ignored, and a no-op without its environment), with
//! `$NOTIFY_SOCKET` pointing at a datagram socket the test reads, as systemd would. In the
//! stalled tests its stderr is a pipe the test holds open and never reads. Each `NewPayload`
//! logs far more than a pipe holds, so the pipe fills on the first call; a log write, or a
//! panic message, that blocked the calling thread would freeze the call, the metrics and the
//! SIGTERM drain. The child's log queue is small, so it overflows and the drops show in
//! `/metrics`; the burst test gives it a roomy one instead, so the panic lines are queued.

mod common;

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::time::{Duration, Instant};

use common::child::OwnedChild;
use common::*;
use ethswarm_proto::engine as pb;
use ethswarm_proto::engine::engine_service_client::EngineServiceClient;
use ethswarm_proto::engine::engine_service_server::{EngineService, EngineServiceServer};
use svc_runtime::telemetry::{init_tracing_with, LogQueueBounds};
use svc_runtime::{Config, Services};
use tonic::transport::Channel;
use tonic::{Request, Response, Status};
use tracing_subscriber::layer::Identity;

/// The environment variable that turns `serve_chatty_engine_child` on: its config path.
const CHILD_CONFIG: &str = "SVC_RUNTIME_STALLED_STDERR_CONFIG";
/// Set, the child's log queue is [`ROOMY`] instead of [`SMALL`].
const CHILD_ROOMY_QUEUE: &str = "SVC_RUNTIME_STALLED_STDERR_ROOMY_QUEUE";
/// A queue a [`BURST`] overflows.
const SMALL: LogQueueBounds = LogQueueBounds {
    max_bytes: 64 << 10,
    max_lines: 256,
};
/// A queue that holds a [`BURST`] with plenty of room to spare.
const ROOMY: LogQueueBounds = LogQueueBounds {
    max_bytes: 16 << 20,
    max_lines: 65_536,
};
/// Lines each `NewPayload` logs: about 1 MiB, well past any pipe's capacity.
const BURST: usize = 4096;
/// The child's drain deadline.
const DRAIN_MS: u64 = 2000;
/// The child's tokio worker threads.
const WORKERS: usize = 2;
/// Every wait on the child is bounded by this.
const STEP: Duration = Duration::from_secs(30);
/// What the exit may take past its deadlines (process start-up and teardown, a loaded host).
const SLACK: Duration = Duration::from_secs(2);
/// The error `GetPayload` answers once its span field has panicked.
const SPAN_PANICKED: &str = "a span field panicked";
/// The panic message of `ForkchoiceUpdated`.
const PANIC: &str = "chatty forkchoice_updated panics";

/// A value whose `Debug` panics.
struct PanicsOnDebug;

impl fmt::Debug for PanicsOnDebug {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("PanicsOnDebug formatted");
    }
}

/// cl-engine whose `NewPayload` logs [`BURST`] long lines and answers, whose
/// `ForkchoiceUpdated` panics, and whose `GetPayload` catches a panic of the subscriber
/// formatting a span field and goes on; the rest unimplemented.
#[derive(Clone)]
struct ChattyEngine;

#[tonic::async_trait]
impl EngineService for ChattyEngine {
    async fn new_payload(
        &self,
        _: Request<pb::NewPayloadRequest>,
    ) -> Result<Response<pb::NewPayloadResponse>, Status> {
        let filler = "x".repeat(200);
        for n in 0..BURST {
            tracing::info!(n, filler = %filler, "chatty new_payload");
        }
        Ok(Response::new(pb::NewPayloadResponse::default()))
    }
    /// Panics: the panic message must not be written to stderr from the worker.
    async fn forkchoice_updated(
        &self,
        _: Request<pb::ForkchoiceUpdatedRequest>,
    ) -> Result<Response<pb::ForkchoiceUpdatedResponse>, Status> {
        panic!("{PANIC}");
    }
    /// Panics inside the fmt layer, while it holds the entered span's extensions: the panic
    /// hook must not go back through the subscriber, and the panic must not poison the span.
    async fn get_payload(
        &self,
        _: Request<pb::GetPayloadRequest>,
    ) -> Result<Response<pb::GetPayloadResponse>, Status> {
        // Twice, so the second span reuses the first one's slot.
        for _ in 0..2 {
            let span = tracing::info_span!("chatty get_payload", value = tracing::field::Empty);
            let _entered = span.enter();
            // The handler goes on after the panic, as a service that catches it would.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                span.record("value", tracing::field::debug(PanicsOnDebug));
            }));
            // Reads the span's extensions: a poisoned lock panics here.
            tracing::info!("chatty get_payload goes on");
        }
        Err(Status::internal(SPAN_PANICKED))
    }
    async fn get_blobs(
        &self,
        _: Request<pb::GetBlobsRequest>,
    ) -> Result<Response<pb::GetBlobsResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn exchange_capabilities(
        &self,
        _: Request<pb::ExchangeCapabilitiesRequest>,
    ) -> Result<Response<pb::ExchangeCapabilitiesResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
}

/// The process side of every test here.
#[test]
#[ignore = "run by the tests of this file in a child process"]
fn serve_chatty_engine_child() {
    let Some(path) = std::env::var_os(CHILD_CONFIG) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let config = Config::load("cl-engine", path.as_ref())
            .unwrap()
            .with_ephemeral_metrics_port();
        // `run` keeps this subscriber.
        let bounds = if std::env::var_os(CHILD_ROOMY_QUEUE).is_some() {
            ROOMY
        } else {
            SMALL
        };
        assert!(init_tracing_with(config.log_level, bounds, Identity::new()));
        svc_runtime::run(
            config,
            Services::new().add_service(EngineServiceServer::new(ChattyEngine)),
        )
        .await
    });
    // `run` has logged the error; the exit status tells the test it failed.
    if result.is_err() {
        std::process::exit(3);
    }
}

/// The child, with the read end of its stderr held open and never read. Killed and reaped on
/// every path that does not see it exit.
struct Stalled {
    child: Child,
    _stderr: ChildStderr,
}

impl Stalled {
    /// Panics, naming the exit status (a signal 6 is an abort), unless the child still runs.
    fn assert_alive(&mut self, after: &str) {
        let status = self.child.try_wait().expect("try_wait");
        assert!(
            status.is_none(),
            "the child exited after {after}: {status:?}"
        );
    }

    /// Waits up to `limit` for the exit, polling.
    async fn exit_within(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Stalled {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

async fn recv(manager: &tokio::net::UnixDatagram) -> String {
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(STEP, manager.recv(&mut buf))
        .await
        .expect("a notification in time")
        .unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

async fn bounded<F: std::future::Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(STEP, future)
        .await
        .unwrap_or_else(|_| {
            panic!("{what}: no answer within {STEP:?}; is a thread stuck writing stderr?")
        })
}

/// The arguments that run [`serve_chatty_engine_child`] in this test binary.
const CHILD_ARGS: [&str; 4] = [
    "--exact",
    "serve_chatty_engine_child",
    "--ignored",
    "--nocapture",
];

/// The child's cl-engine config, its socket under `root`.
fn config_text(root: &Path) -> String {
    engine_toml(
        root,
        ipc::peercred::effective_gid(),
        me(),
        &ENGINE_METHODS,
        r#"["cl-chain"]"#,
        DRAIN_MS,
    )
}

/// A child's directory, config and service manager socket.
struct Setup {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    notify: PathBuf,
    manager: tokio::net::UnixDatagram,
}

impl Setup {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = runtime_root(tmp.path());
        let config = tmp.path().join("cl-engine.toml");
        std::fs::write(&config, config_text(&root)).unwrap();
        let notify = tmp.path().join("notify.sock");
        let manager = tokio::net::UnixDatagram::bind(&notify).unwrap();
        Self {
            _tmp: tmp,
            root,
            config,
            notify,
            manager,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(CHILD_ARGS)
            .env(CHILD_CONFIG, &self.config)
            .env("NOTIFY_SOCKET", &self.notify)
            .stdout(Stdio::null());
        command
    }

    /// Waits for READY; the metrics address.
    async fn ready(&self) -> SocketAddr {
        let ready = recv(&self.manager).await;
        assert!(ready.starts_with("READY=1\n"), "{ready}");
        metrics_addr(&ready)
    }

    /// A new connection to the child's socket.
    async fn client(&self) -> EngineServiceClient<Channel> {
        let socket = ipc::uds::SocketDir::under(&self.root, "cl-engine").unwrap();
        let channel = bounded("connect", ipc::uds::connect(&socket, me()))
            .await
            .unwrap();
        EngineServiceClient::new(channel)
    }
}

/// Starts the child with its stderr a pipe nobody reads; waits for READY, then fills the pipe.
async fn start_stalled(setup: &Setup) -> (Stalled, rustix::process::Pid, SocketAddr) {
    start_stalled_with(setup, setup.command()).await
}

/// [`start_stalled`], running `command`.
async fn start_stalled_with(
    setup: &Setup,
    mut command: Command,
) -> (Stalled, rustix::process::Pid, SocketAddr) {
    let mut child = command.stderr(Stdio::piped()).spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let pid = rustix::process::Pid::from_child(&child);
    let mut child = Stalled {
        child,
        _stderr: stderr,
    };
    let metrics = setup.ready().await;
    // Logs past the pipe's capacity and the queue's, and still answers.
    let answer = bounded(
        "NewPayload",
        setup
            .client()
            .await
            .new_payload(pb::NewPayloadRequest::default()),
    )
    .await;
    if answer.is_err() {
        let _ = child.child.kill();
    }
    assert!(answer.is_ok(), "{answer:?}");
    (child, pid, metrics)
}

/// The child's `ethswarm_log_lines_dropped_total`.
async fn dropped_lines(metrics: SocketAddr) -> u64 {
    let scraped = bounded("/metrics", scrape(metrics)).await;
    scraped
        .lines()
        .find_map(|l| l.strip_prefix("ethswarm_log_lines_dropped_total "))
        .unwrap_or_else(|| panic!("no drop counter in\n{scraped}"))
        .parse()
        .unwrap()
}

/// SIGTERM, then STOPPING and an exit with status 0 within the drain deadline plus the log
/// flush deadline, all measured from the signal.
async fn terminate_in_time(setup: &Setup, child: &mut Stalled, pid: rustix::process::Pid) {
    let sigterm = Instant::now();
    let limit = Duration::from_millis(DRAIN_MS) + svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
    let deadline = sigterm + limit + SLACK;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let stopping = tokio::time::timeout_at(deadline.into(), recv(&setup.manager))
        .await
        .unwrap_or_else(|_| panic!("no STOPPING within {limit:?} (+{SLACK:?}) of SIGTERM"));
    assert_eq!(stopping, "STOPPING=1");
    let status = child
        .exit_within(deadline.saturating_duration_since(Instant::now()))
        .await
        .unwrap_or_else(|| panic!("no exit within {limit:?} (+{SLACK:?}) of SIGTERM"));
    let took = sigterm.elapsed();
    assert_eq!(status.code(), Some(0), "{status:?} after {took:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_stderr_keeps_serving_and_exits() {
    let setup = Setup::new();
    let (mut child, pid, metrics) = start_stalled(&setup).await;

    // Every call logs past the pipe's capacity, and every one still answers.
    let mut client = setup.client().await;
    for call in 0..3 {
        let answer = bounded(
            "NewPayload",
            client.new_payload(pb::NewPayloadRequest::default()),
        )
        .await;
        assert!(answer.is_ok(), "call {call}: {answer:?}");
    }
    // A handler panic on every worker (and then some), with stderr full: each is logged
    // through the queue, so no worker is left blocked writing its message.
    for call in 0..2 * WORKERS {
        let answer = bounded(
            "ForkchoiceUpdated",
            setup
                .client()
                .await
                .forkchoice_updated(pb::ForkchoiceUpdatedRequest::default()),
        )
        .await;
        assert!(answer.is_err(), "call {call} panicked: {answer:?}");
    }
    let answer = bounded(
        "NewPayload after the panics",
        setup
            .client()
            .await
            .new_payload(pb::NewPayloadRequest::default()),
    )
    .await;
    assert!(answer.is_ok(), "{answer:?}");

    // The metrics still answer, and show the lines the full queue dropped.
    let scraped = bounded("/metrics", scrape(metrics)).await;
    assert!(scraped.contains("ethswarm_ready 1"), "{scraped}");
    assert!(dropped_lines(metrics).await > 0, "{scraped}");

    terminate_in_time(&setup, &mut child, pid).await;
}

/// A panic while the fmt layer holds the current span's extensions (a span field whose
/// `Debug` panics): a hook that logged through `tracing` would look that span up again on
/// the same thread and deadlock the worker, and a panic unwinding through that lock would
/// poison the span's slot for every later span that reuses it.
#[tokio::test(flavor = "multi_thread")]
async fn a_panic_inside_the_subscriber_does_not_freeze_the_worker() {
    let setup = Setup::new();
    let (mut child, pid, _) = start_stalled(&setup).await;
    for call in 0..2 * WORKERS {
        let answer = bounded(
            "GetPayload",
            setup
                .client()
                .await
                .get_payload(pb::GetPayloadRequest::default()),
        )
        .await;
        child.assert_alive(&format!("GetPayload call {call}"));
        let message = answer.as_ref().map_err(|e| e.message().to_owned()).err();
        assert_eq!(
            message.as_deref(),
            Some(SPAN_PANICKED),
            "call {call} went on after the panic: {answer:?}"
        );
    }
    // Every call runs in a new `rpc` span, so these reuse the slots the panicking spans had:
    // they must still be usable, not left poisoned for the next span to panic on.
    for call in 0..32 {
        let answer = bounded(
            "GetBlobs",
            setup
                .client()
                .await
                .get_blobs(pb::GetBlobsRequest::default()),
        )
        .await;
        let code = answer.as_ref().map_err(Status::code).err();
        if code != Some(tonic::Code::Unimplemented) {
            child.assert_alive(&format!("GetBlobs call {call}"));
        }
        assert_eq!(
            code,
            Some(tonic::Code::Unimplemented),
            "call {call}: {answer:?}"
        );
    }
    let answer = bounded(
        "NewPayload after the panics",
        setup
            .client()
            .await
            .new_payload(pb::NewPayloadRequest::default()),
    )
    .await;
    if answer.is_err() {
        child.assert_alive("NewPayload");
    }
    assert!(answer.is_ok(), "{answer:?}");
    child.assert_alive("NewPayload");
    terminate_in_time(&setup, &mut child, pid).await;
}

/// Many panics at once with stderr stalled and room in the queue, so every panic line is
/// queued and its hook takes the wait path: the hook waits once per stall, not once per panic,
/// so the burst is over well inside the time the SIGTERM drain allows, and SIGTERM after it
/// still drains and exits in time.
#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_panics_does_not_hold_off_sigterm() {
    const CONNECTIONS: usize = 4;
    const CALLS: usize = 64;
    // Waiting its 100 ms flush per panic, the burst would take 12.8 s on the two workers.
    let limit = Duration::from_millis(DRAIN_MS) + svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
    let setup = Setup::new();
    let mut command = setup.command();
    // No backtraces: resolving one per panic is not what this measures.
    command
        .env(CHILD_ROOMY_QUEUE, "1")
        .env_remove("RUST_BACKTRACE")
        .env_remove("RUST_LIB_BACKTRACE");
    let (mut child, pid, metrics) = start_stalled_with(&setup, command).await;
    // The pipe is full and the writer stuck on it, but the queue took every line.
    assert_eq!(dropped_lines(metrics).await, 0, "the queue has room");

    let started = Instant::now();
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..CONNECTIONS {
        let client = setup.client().await;
        for _ in 0..CALLS {
            let mut client = client.clone();
            calls.spawn(async move {
                client
                    .forkchoice_updated(pb::ForkchoiceUpdatedRequest::default())
                    .await
                    .map(drop)
            });
        }
    }
    // Every handler has panicked (its hook returned before the call could fail) in time.
    let panicked = tokio::time::timeout(limit + SLACK, async {
        let mut panicked = 0;
        while let Some(answer) = calls.join_next().await {
            let answer = answer.expect("the call task");
            assert!(answer.is_err(), "call {panicked} panicked: {answer:?}");
            panicked += 1;
        }
        panicked
    })
    .await;
    let took = started.elapsed();
    calls.abort_all();
    child.assert_alive("the burst of panics");
    assert_eq!(
        panicked,
        Ok(CONNECTIONS * CALLS),
        "the burst took {took:?}, past {limit:?} (+{SLACK:?})"
    );
    // Each panic line was queued, not dropped.
    assert_eq!(dropped_lines(metrics).await, 0, "a panic line was dropped");
    terminate_in_time(&setup, &mut child, pid).await;
}

/// With stderr read, a panic shows as one JSON line at ERROR, with its message and location.
#[tokio::test(flavor = "multi_thread")]
async fn a_panic_is_logged_as_one_json_line() {
    let setup = Setup::new();
    let mut child = OwnedChild::spawn(setup.command()).unwrap();
    setup.ready().await;
    let answer = bounded(
        "ForkchoiceUpdated",
        setup
            .client()
            .await
            .forkchoice_updated(pb::ForkchoiceUpdatedRequest::default()),
    )
    .await;
    assert!(answer.is_err(), "it panicked: {answer:?}");
    rustix::process::kill_process(child.pid(), rustix::process::Signal::TERM).unwrap();
    let status = child
        .wait_until(tokio::time::Instant::now() + STEP)
        .await
        .expect("the service exits");
    let logs = child.stderr();
    assert_eq!(status.code(), Some(0), "{status:?}\n{logs}");
    let panicked = logs
        .lines()
        .find(|l| l.contains(PANIC))
        .unwrap_or_else(|| panic!("no panic line in\n{logs}"));
    assert!(panicked.starts_with(r#"{"timestamp":""#), "{panicked}");
    assert!(panicked.ends_with('}'), "{panicked}");
    assert!(panicked.contains(r#""level":"ERROR""#), "{panicked}");
    assert!(
        panicked.contains(&format!(r#""panic":"{PANIC}""#)),
        "{panicked}"
    );
    assert!(
        panicked.contains(&format!(r#""location":"{}:"#, file!())),
        "{panicked}"
    );
    assert!(panicked.contains(r#""thread":""#), "{panicked}");
}

/// A `run` that fails logs why, and the line reaches stderr before the process exits.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_run_logs_its_error_before_the_exit() {
    use std::os::unix::fs::PermissionsExt;
    let setup = Setup::new();
    // A service directory with a loose mode: the socket bind refuses it.
    let dir = setup.root.join("cl-engine");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut command = setup.command();
    command.env_remove("NOTIFY_SOCKET");
    let mut child = OwnedChild::spawn(command).unwrap();
    let status = child
        .wait_until(tokio::time::Instant::now() + STEP)
        .await
        .expect("the failed run exits");
    let logs = child.stderr();
    assert_eq!(status.code(), Some(3), "{status:?}\n{logs}");
    let failed = logs
        .lines()
        .find(|l| l.contains(r#""level":"ERROR""#) && l.contains("socket: "))
        .unwrap_or_else(|| panic!("the bind error is not logged:\n{logs}"));
    assert!(failed.starts_with('{'), "{failed}");
}
