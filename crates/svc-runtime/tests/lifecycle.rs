//! Startup order, READY/STOPPING, and the SIGTERM drain.
//!
//! `lifecycle_sigterm_drains` runs a real process: this test binary re-executed to run
//! `serve_slow_engine_child` (ignored, and a no-op without its environment), with
//! `$NOTIFY_SOCKET` pointing at a datagram socket the test reads, as systemd would. The child
//! is an [`OwnedChild`]: every wait on it has a deadline, its stderr is drained as it comes,
//! and it is killed and reaped however the test ends.

mod common;

use std::future::Future;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::child::OwnedChild;
use common::*;
use ethswarm_proto::engine as pb;
use ethswarm_proto::engine::engine_service_client::EngineServiceClient;
use ethswarm_proto::engine::engine_service_server::{EngineService, EngineServiceServer};
use svc_runtime::notify::Notifier;
use svc_runtime::{Config, Hooks, RuntimeError, Services};
use tonic::{Request, Response, Status};

/// The environment variable that turns `serve_slow_engine_child` on: its config path.
const CHILD_CONFIG: &str = "SVC_RUNTIME_CHILD_CONFIG";
/// How long the slow `NewPayload` takes.
const SLOW: Duration = Duration::from_millis(1500);

/// cl-engine with a `NewPayload` that takes `delay` (and answers); the rest unimplemented.
#[derive(Clone)]
struct SlowEngine {
    delay: Duration,
}

#[tonic::async_trait]
impl EngineService for SlowEngine {
    async fn new_payload(
        &self,
        _: Request<pb::NewPayloadRequest>,
    ) -> Result<Response<pb::NewPayloadResponse>, Status> {
        tracing::info!("new_payload started");
        tokio::time::sleep(self.delay).await;
        Ok(Response::new(pb::NewPayloadResponse::default()))
    }
    async fn forkchoice_updated(
        &self,
        _: Request<pb::ForkchoiceUpdatedRequest>,
    ) -> Result<Response<pb::ForkchoiceUpdatedResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn get_payload(
        &self,
        _: Request<pb::GetPayloadRequest>,
    ) -> Result<Response<pb::GetPayloadResponse>, Status> {
        Err(Status::unimplemented("test"))
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

fn slow_routes(delay: Duration) -> Services {
    Services::new().add_service(EngineServiceServer::new(SlowEngine { delay }))
}

fn config_text(root: &std::path::Path, drain_ms: u64) -> String {
    engine_toml(
        root,
        ipc::peercred::effective_gid(),
        me(),
        &ENGINE_METHODS,
        r#"["cl-chain"]"#,
        drain_ms,
    )
}

/// The process side of `lifecycle_sigterm_drains`.
#[test]
#[ignore = "run by lifecycle_sigterm_drains in a child process"]
fn serve_slow_engine_child() {
    let Some(path) = std::env::var_os(CHILD_CONFIG) else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let config = Config::load("cl-engine", path.as_ref())
            .unwrap()
            .with_ephemeral_metrics_port();
        svc_runtime::run(config, slow_routes(SLOW)).await
    });
    assert!(result.is_ok(), "{result:?}");
}

/// `sh -c script`.
fn sh(script: &str) -> Command {
    let mut command = Command::new("sh");
    command.args(["-c", script]).stdout(Stdio::null());
    command
}

fn in_secs(secs: u64) -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(secs)
}

#[tokio::test(flavor = "multi_thread")]
async fn owned_child_reports_its_exit() {
    let mut child = OwnedChild::spawn(sh("exit 3")).unwrap();
    let status = child.wait_until(in_secs(30)).await;
    assert_eq!(status.and_then(|s| s.code()), Some(3), "{status:?}");
}

/// A child that logs more than a pipe holds before the test reads anything. A pipe holds 64 KiB
/// on Linux and 16 KiB on macOS, but only 512 bytes on a macOS short of pipe memory (many
/// parallel test runs): the service's ~6 KiB of logs then filled it, its next log write
/// blocked a tokio worker, and that froze its runtime (no drain deadline, no SIGTERM).
#[tokio::test(flavor = "multi_thread")]
async fn owned_child_never_blocks_on_its_stderr() {
    const LOGGED: usize = 1 << 20;
    let mut child = OwnedChild::spawn(sh(&format!("head -c {LOGGED} /dev/zero >&2"))).unwrap();
    let status = child.wait_until(in_secs(30)).await;
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    assert_eq!(child.stderr().len(), LOGGED, "all of stderr is kept");
}

/// A child that ignores SIGTERM, as a service stuck in its drain does. Returns once it does:
/// a signal sent before the `trap` would kill it.
async fn stubborn() -> OwnedChild {
    let child = OwnedChild::spawn(sh("trap '' TERM; echo ready >&2; exec sleep 600")).unwrap();
    assert!(
        child.wait_for_stderr("ready", in_secs(30)).await,
        "no handshake"
    );
    child
}

/// Whether `pid` names a process, a zombie included: `false` once it is killed and reaped.
fn exists(pid: rustix::process::Pid) -> bool {
    rustix::process::test_kill_process(pid).is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn owned_child_wait_is_bounded() {
    let mut child = stubborn().await;
    rustix::process::kill_process(child.pid(), rustix::process::Signal::TERM).unwrap();
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    assert_eq!(child.wait_until(deadline).await, None);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert!(exists(child.pid()), "it ignored SIGTERM");
}

#[tokio::test]
async fn owned_child_is_killed_and_reaped_on_drop() {
    let child = stubborn().await;
    let pid = child.pid();
    drop(child);
    assert!(!exists(pid), "pid {pid:?} still there");
}

#[tokio::test]
async fn owned_child_is_killed_and_reaped_on_panic() {
    let child = stubborn().await;
    let pid = child.pid();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _child = child;
        panic!("a failing assertion");
    }));
    assert!(failed.is_err());
    assert!(!exists(pid), "pid {pid:?} still there");
}

/// The next notification the service sends.
async fn recv(manager: &tokio::net::UnixDatagram) -> String {
    let mut buf = vec![0u8; 1024];
    let n = manager.recv(&mut buf).await.unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

/// The child's drain deadline.
const DRAIN_MS: u64 = 10_000;
const DRAIN: Duration = Duration::from_millis(DRAIN_MS);
/// The longest one step of `lifecycle_sigterm_drains` may take: ample on a loaded machine, and
/// a stuck child fails the test instead of hanging it.
const STEP: Duration = Duration::from_secs(60);

/// `step`'s output if it comes within [`STEP`]; otherwise the test fails with `what` and the
/// child's log, and the child is killed as the panic drops it.
async fn within<T>(child: &OwnedChild, what: &str, step: impl Future<Output = T>) -> T {
    match tokio::time::timeout(STEP, step).await {
        Ok(out) => out,
        Err(_) => panic!(
            "timed out after {STEP:?} waiting for {what}; the child is killed. Its stderr:\n{}",
            child.stderr()
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_sigterm_drains() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let config = tmp.path().join("cl-engine.toml");
    std::fs::write(&config, config_text(&root, DRAIN_MS)).unwrap();
    let notify = tmp.path().join("notify.sock");
    let manager = tokio::net::UnixDatagram::bind(&notify).unwrap();

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "serve_slow_engine_child",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_CONFIG, &config)
        .env("NOTIFY_SOCKET", &notify)
        .stdout(Stdio::null());
    // Killed and reaped on every way out of this test; its stderr is drained as it comes.
    let mut child = OwnedChild::spawn(command).unwrap();

    // The readiness handshake: `run` installs the SIGTERM handler before it sends READY=1.
    let ready = within(&child, "READY=1", recv(&manager)).await;
    assert!(
        ready.starts_with("READY=1\nSTATUS=serving cl-engine on "),
        "{ready}"
    );
    let metrics = metrics_addr(&ready);
    assert!(metrics.ip().is_loopback(), "{metrics}");
    assert_eq!(
        metrics.ip().to_string(),
        "127.0.0.1",
        "/metrics listens on 127.0.0.1 only"
    );
    assert!(within(&child, "a /metrics scrape", scrape(metrics))
        .await
        .contains("ethswarm_ready 1"));

    let socket = ipc::uds::SocketDir::under(&root, "cl-engine").unwrap();
    let channel = within(&child, "a connection", ipc::uds::connect(&socket, me()))
        .await
        .unwrap();
    let mut client = EngineServiceClient::new(channel);
    let in_flight =
        tokio::spawn(async move { client.new_payload(pb::NewPayloadRequest::default()).await });
    within(
        &child,
        "the call in flight",
        wait_for_metric(metrics, "ethswarm_rpc_inflight 1"),
    )
    .await;

    rustix::process::kill_process(child.pid(), rustix::process::Signal::TERM).unwrap();
    assert_eq!(
        within(&child, "STOPPING=1", recv(&manager)).await,
        "STOPPING=1"
    );
    // No new calls: the socket is gone and nothing accepts on its path.
    assert!(std::fs::symlink_metadata(socket.socket_path()).is_err());
    assert!(std::os::unix::net::UnixStream::connect(socket.socket_path()).is_err());
    assert!(within(
        &child,
        "a refused connection",
        ipc::uds::connect(&socket, me())
    )
    .await
    .is_err());

    // The call in flight finishes within the drain deadline.
    let answered = within(&child, "the answer to the call in flight", in_flight)
        .await
        .unwrap();
    assert!(answered.is_ok(), "{answered:?}");

    let status = child
        .wait_until(tokio::time::Instant::now() + STEP)
        .await
        .unwrap_or_else(|| {
            panic!(
                "the service did not exit within {STEP:?} of SIGTERM (drain deadline {DRAIN:?}); \
                 the child is killed. Its stderr:\n{}",
                child.stderr()
            )
        });
    let logs = child.stderr();
    assert!(status.success(), "exit {status:?}\n{logs}");
    assert_eq!(status.code(), Some(0));
    // The JSON log line the handler wrote carries the call's trace id.
    let handled = logs
        .lines()
        .find(|l| l.contains("new_payload started"))
        .unwrap_or_else(|| panic!("no handler log line in\n{logs}"));
    assert!(handled.starts_with('{'), "{handled}");
    assert!(handled.contains(r#""trace_id":""#), "{handled}");
    assert!(handled.contains("EngineService/NewPayload"), "{handled}");
}

#[tokio::test(flavor = "multi_thread")]
async fn drain_deadline_bounds_shutdown() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let config = engine_config(tmp.path(), &config_text(&root, 200)).unwrap();
    let mut svc = start(config, slow_routes(Duration::from_secs(30))).await;
    let channel = ipc::uds::connect(&svc.socket, me()).await.unwrap();
    let mut client = EngineServiceClient::new(channel);
    let in_flight =
        tokio::spawn(async move { client.new_payload(pb::NewPayloadRequest::default()).await });
    wait_for_metric(svc.metrics, "ethswarm_rpc_inflight 1").await;
    let stopping = std::time::Instant::now();
    svc.terminate();
    assert_eq!(svc.next_state().await, "STOPPING=1");
    let result = svc.task.await.unwrap();
    // run returns at the deadline with the call still running; the process exit drops it.
    assert!(
        stopping.elapsed() < Duration::from_secs(10),
        "{:?}",
        stopping.elapsed()
    );
    assert!(!in_flight.is_finished(), "the slow call had not finished");
    in_flight.abort();
    assert!(
        matches!(result, Err(RuntimeError::DrainTimeout(d)) if d == Duration::from_millis(200)),
        "{result:?}"
    );
    assert_eq!(
        svc_runtime::exit_code(&result),
        std::process::ExitCode::FAILURE
    );
    assert!(std::fs::symlink_metadata(svc.socket.socket_path()).is_err());
}

/// Each notification, with the (socket, directory) modes at that moment.
type Seen = Arc<Mutex<Vec<(String, Option<(u32, u32)>)>>>;

/// Records, at READY, the socket's and directory's mode as they are at that moment.
struct ModesAtReady {
    socket: std::path::PathBuf,
    seen: Seen,
}

impl Notifier for ModesAtReady {
    fn notify(&self, state: &str) -> std::io::Result<()> {
        let modes = std::fs::symlink_metadata(&self.socket).ok().map(|s| {
            let dir = std::fs::metadata(self.socket.parent().unwrap()).unwrap();
            (s.mode() & 0o7777, dir.mode() & 0o7777)
        });
        self.seen.lock().unwrap().push((state.to_owned(), modes));
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ready_only_once_the_socket_is_0660() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let config = engine_config(tmp.path(), &config_text(&root, 1000)).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let hooks = Hooks {
        notifier: Arc::new(ModesAtReady {
            socket: config.socket.socket_path(),
            seen: Arc::clone(&seen),
        }),
        shutdown: Box::pin(async {
            let _ = stopped.await;
        }),
        registry: prometheus_client::registry::Registry::default(),
    };
    let task = tokio::spawn(svc_runtime::run_with(config, slow_routes(SLOW), hooks));
    while seen.lock().unwrap().is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    let seen = seen.lock().unwrap();
    assert!(seen[0].0.starts_with("READY=1"), "{seen:?}");
    assert_eq!(seen[0].1, Some((0o660, 0o750)), "modes at READY");
    assert_eq!(seen[1].0, "STOPPING=1");
    assert_eq!(seen[1].1, None, "socket removed before STOPPING");
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_startup_never_reports_ready() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    // A pre-existing service directory with a loose mode: bind refuses, READY is never sent.
    let dir = root.join("cl-engine");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = engine_config(tmp.path(), &config_text(&root, 1000)).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let hooks = Hooks {
        notifier: Arc::new(ModesAtReady {
            socket: config.socket.socket_path(),
            seen: Arc::clone(&seen),
        }),
        shutdown: Box::pin(std::future::pending()),
        registry: prometheus_client::registry::Registry::default(),
    };
    let result = svc_runtime::run_with(config, slow_routes(SLOW), hooks).await;
    assert!(matches!(result, Err(RuntimeError::Bind(_))), "{result:?}");
    assert!(seen.lock().unwrap().is_empty());
}

/// A manager that cannot be reached.
struct Unreachable;

impl Notifier for Unreachable {
    fn notify(&self, _: &str) -> std::io::Result<()> {
        Err(std::io::ErrorKind::ConnectionRefused.into())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ready_that_cannot_be_sent_stops_the_service() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let config = engine_config(tmp.path(), &config_text(&root, 1000)).unwrap();
    let socket = config.socket.socket_path();
    let hooks = Hooks {
        notifier: Arc::new(Unreachable),
        shutdown: Box::pin(std::future::pending()),
        registry: prometheus_client::registry::Registry::default(),
    };
    let result = svc_runtime::run_with(config, slow_routes(SLOW), hooks).await;
    assert!(matches!(result, Err(RuntimeError::Notify(_))), "{result:?}");
    assert!(std::fs::symlink_metadata(socket).is_err(), "socket removed");
}

/// A manager that takes `delay` to accept STOPPING (READY goes through at once).
struct SlowAtStopping {
    delay: Duration,
}

impl Notifier for SlowAtStopping {
    fn notify(&self, state: &str) -> std::io::Result<()> {
        if state.starts_with("STOPPING") {
            std::thread::sleep(self.delay);
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn drain_deadline_starts_before_stopping() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let config = engine_config(tmp.path(), &config_text(&root, 1000)).unwrap();
    let socket = config.socket.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let hooks = Hooks {
        notifier: Arc::new(SlowAtStopping {
            delay: Duration::from_secs(2),
        }),
        shutdown: Box::pin(async {
            let _ = stopped.await;
        }),
        registry: prometheus_client::registry::Registry::default(),
    };
    let task = tokio::spawn(svc_runtime::run_with(
        config,
        slow_routes(Duration::from_secs(30)),
        hooks,
    ));
    let channel = loop {
        if let Ok(c) = ipc::uds::connect(&socket, me()).await {
            break c;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let mut client = EngineServiceClient::new(channel);
    let in_flight =
        tokio::spawn(async move { client.new_payload(pb::NewPayloadRequest::default()).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stopping = std::time::Instant::now();
    stop.send(()).unwrap();
    let result = task.await.unwrap();
    // A slow STOPPING eats into the 1 s deadline instead of coming before it: about 2 s, not 3.
    let took = stopping.elapsed();
    assert!(took < Duration::from_millis(2600), "{took:?}");
    assert!(
        matches!(result, Err(RuntimeError::DrainTimeout(_))),
        "{result:?}"
    );
    in_flight.abort();
}

/// Open descriptors of this process.
fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_flood_does_not_starve_the_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let config = engine_config(tmp.path(), &config_text(&root, 1000)).unwrap();
    let cap = config.metrics_limits.max_connections();
    let svc = start(config, slow_routes(Duration::from_millis(1))).await;
    let channel = ipc::uds::connect(&svc.socket, me()).await.unwrap();
    let mut client = EngineServiceClient::new(channel);

    // Any local user can open TCP connections to /metrics and keep them open.
    const FLOOD: usize = 200;
    let before = open_fds();
    let mut flood = Vec::new();
    for _ in 0..FLOOD {
        flood.push(tokio::net::TcpStream::connect(svc.metrics).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Our client ends stay open; the service keeps at most `cap` of its ends.
    let grown = open_fds() - before;
    assert!(
        grown <= FLOOD + cap + 4,
        "{grown} new descriptors for {FLOOD} connections"
    );

    // cl-chain's calls over the socket still work, and new connections to it too.
    let answer = client.new_payload(pb::NewPayloadRequest::default()).await;
    assert!(answer.is_ok(), "{answer:?}");
    let fresh = ipc::uds::connect(&svc.socket, me()).await.unwrap();
    let answer = EngineServiceClient::new(fresh)
        .new_payload(pb::NewPayloadRequest::default())
        .await;
    assert!(answer.is_ok(), "{answer:?}");
    drop(flood);
}
