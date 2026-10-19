//! Startup order, READY/STOPPING, and the SIGTERM drain.
//!
//! `lifecycle_sigterm_drains` and `held_call_ends_only_on_its_release` run a real process:
//! this test binary re-executed to run `serve_slow_engine_child` (ignored, and a no-op without
//! its environment), with `$NOTIFY_SOCKET` pointing at a datagram socket the test reads, as
//! systemd would. Its `NewPayload` runs until the test creates a release file, which
//! `lifecycle_sigterm_drains` does only once the drain has begun. The child is an
//! [`OwnedChild`]: every wait on it has a deadline, its stderr is drained as it comes, and it
//! is killed and reaped however the test ends.

mod common;

use std::future::Future;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::child::{Handshake, OwnedChild, STDERR_CAP};
use common::*;
use ethswarm_proto::engine as pb;
use ethswarm_proto::engine::engine_service_client::EngineServiceClient;
use ethswarm_proto::engine::engine_service_server::{EngineService, EngineServiceServer};
use svc_runtime::notify::Notifier;
use svc_runtime::{Config, Hooks, RuntimeError, Services};
use tonic::{Request, Response, Status};

/// The environment variable that turns `serve_slow_engine_child` on: its config path.
const CHILD_CONFIG: &str = "SVC_RUNTIME_CHILD_CONFIG";
/// The environment variable naming the file whose creation releases the child's call.
const CHILD_RELEASE: &str = "SVC_RUNTIME_CHILD_RELEASE";
/// How long the slow `NewPayload` takes.
const SLOW: Duration = Duration::from_millis(1500);

/// How long a `NewPayload` runs before it answers.
#[derive(Clone)]
enum Hold {
    For(Duration),
    /// Until this file exists: the test's release, so the call ends only when the test says.
    UntilCreated(PathBuf),
}

/// cl-engine with a `NewPayload` that runs for its `hold` (and answers); the rest
/// unimplemented.
#[derive(Clone)]
struct SlowEngine {
    hold: Hold,
}

#[tonic::async_trait]
impl EngineService for SlowEngine {
    async fn new_payload(
        &self,
        _: Request<pb::NewPayloadRequest>,
    ) -> Result<Response<pb::NewPayloadResponse>, Status> {
        tracing::info!("new_payload started");
        match &self.hold {
            Hold::For(delay) => tokio::time::sleep(*delay).await,
            Hold::UntilCreated(release) => {
                while !release.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
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

fn routes(hold: Hold) -> Services {
    Services::new().add_service(EngineServiceServer::new(SlowEngine { hold }))
}

fn slow_routes(delay: Duration) -> Services {
    routes(Hold::For(delay))
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
    let release = std::env::var_os(CHILD_RELEASE).expect("the release path");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let config = Config::load("cl-engine", path.as_ref())
            .unwrap()
            .with_ephemeral_metrics_port();
        svc_runtime::run(config, routes(Hold::UntilCreated(release.into()))).await
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
    assert_eq!(child.stderr_read(), LOGGED as u64, "all of stderr is read");
}

/// A child that logs many MiB: all of it is read, at most [`STDERR_CAP`] of it is kept (and
/// the log says it was cut), and a handshake written after it all is still seen.
#[tokio::test(flavor = "multi_thread")]
async fn owned_child_keeps_a_bounded_stderr() {
    const LOGGED: usize = 16 << 20;
    let script = format!("head -c {LOGGED} /dev/zero >&2; echo ready >&2; exec sleep 600");
    // The whole line, so the count below cannot catch a read that ended inside it.
    let child = OwnedChild::spawn_with_handshake(sh(&script), "ready\n").unwrap();
    assert!(child.wait_for_handshake(in_secs(30)).await, "no handshake");
    assert_eq!(
        child.stderr_read(),
        LOGGED as u64 + 6,
        "all of stderr is read"
    );
    assert!(
        child.stderr_held() <= STDERR_CAP,
        "{} bytes held",
        child.stderr_held()
    );
    let log = child.stderr();
    assert_eq!(log.len() - log.trim_start_matches('\0').len(), STDERR_CAP);
    assert!(
        log.ends_with(&format!(
            "[stderr truncated: kept the first {STDERR_CAP} of {} bytes]",
            LOGGED + 6
        )),
        "{}",
        &log[STDERR_CAP..]
    );
}

/// A handshake split across reads of the pipe is still seen, and only once it is whole.
#[test]
fn handshake_matches_across_reads() {
    let mut handshake = Handshake::new("ready");
    handshake.feed(b"starting\nrea");
    assert!(!handshake.seen());
    handshake.feed(b"d");
    assert!(!handshake.seen());
    handshake.feed(b"y\n");
    assert!(handshake.seen());
    handshake.feed(b"more logs");
    assert!(handshake.seen(), "once seen, it stays seen");
}

#[tokio::test(flavor = "multi_thread")]
async fn owned_child_handshake_fails_at_the_exit() {
    let child = OwnedChild::spawn_with_handshake(sh("echo starting >&2"), "ready").unwrap();
    let started = std::time::Instant::now();
    assert!(!child.wait_for_handshake(in_secs(30)).await);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "gave up at the end of stderr, not the deadline: {:?}",
        started.elapsed()
    );
}

/// A child that ignores SIGTERM, as a service stuck in its drain does. Returns once it does:
/// a signal sent before the `trap` would kill it.
async fn stubborn() -> OwnedChild {
    let script = "trap '' TERM; echo ready >&2; exec sleep 600";
    let child = OwnedChild::spawn_with_handshake(sh(script), "ready").unwrap();
    assert!(child.wait_for_handshake(in_secs(30)).await, "no handshake");
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

/// The OS cannot create the stderr reader's thread: the spawn returns that error, and the child
/// already running is killed and reaped rather than left behind.
#[test]
fn owned_child_is_reaped_when_its_reader_cannot_start() {
    let tmp = tempfile::tempdir().unwrap();
    let pid_file = tmp.path().join("pid");
    // The pid is renamed into place, so it is read whole; `exec` keeps it for `sleep`.
    let script = format!(
        "echo $$ > '{0}.tmp' && mv '{0}.tmp' '{0}'; exec sleep 600",
        pid_file.display()
    );
    let mut pid = None;
    let spawned = OwnedChild::spawn_with(sh(&script), None, |_reader| {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !pid_file.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the child never wrote its pid"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let raw = std::fs::read_to_string(&pid_file).unwrap();
        pid = rustix::process::Pid::from_raw(raw.trim().parse().unwrap());
        Err(std::io::Error::other("cannot create a thread"))
    });
    let error = spawned.err().expect("the spawn fails");
    assert_eq!(error.to_string(), "cannot create a thread");
    let pid = pid.expect("a child pid");
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
/// The longest one step of the child tests may take, and the longest from SIGTERM to the exit:
/// ample on a loaded machine, and a stuck child fails the test instead of hanging it.
const STEP: Duration = Duration::from_secs(60);

/// `step`'s output if it comes by `deadline`; otherwise the test fails with `what` and the
/// child's log, and the child is killed as the panic drops it.
async fn by<T>(
    child: &OwnedChild,
    what: &str,
    deadline: tokio::time::Instant,
    step: impl Future<Output = T>,
) -> T {
    match tokio::time::timeout_at(deadline, step).await {
        Ok(out) => out,
        Err(_) => panic!(
            "timed out waiting for {what}; the child is killed. Its stderr:\n{}",
            child.stderr()
        ),
    }
}

/// [`by`] with [`STEP`] from now.
async fn within<T>(child: &OwnedChild, what: &str, step: impl Future<Output = T>) -> T {
    by(child, what, tokio::time::Instant::now() + STEP, step).await
}

/// The answer to a `NewPayload` call.
type Answer = Result<Response<pb::NewPayloadResponse>, Status>;

/// `serve_slow_engine_child` in its own process, serving one `NewPayload` that is held in
/// flight until the test creates `release`.
struct HeldCall {
    child: OwnedChild,
    manager: tokio::net::UnixDatagram,
    socket: ipc::uds::SocketDir,
    release: PathBuf,
    in_flight: tokio::task::JoinHandle<Answer>,
    /// Removed last, once the child is killed.
    _tmp: tempfile::TempDir,
}

/// Starts the child with a `drain_ms` drain deadline, and waits until its `NewPayload` is in
/// flight.
async fn hold_a_call(drain_ms: u64) -> HeldCall {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let config = tmp.path().join("cl-engine.toml");
    std::fs::write(&config, config_text(&root, drain_ms)).unwrap();
    let release = tmp.path().join("release");
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
        .env(CHILD_RELEASE, &release)
        .env("NOTIFY_SOCKET", &notify)
        .stdout(Stdio::null());
    // Killed and reaped on every way out of the test; its stderr is drained as it comes.
    let child = OwnedChild::spawn(command).unwrap();

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
    HeldCall {
        child,
        manager,
        socket,
        release,
        in_flight,
        _tmp: tmp,
    }
}

/// Without its release the call stays in flight through the drain: the child exits at the
/// drain deadline, dropping it. So in `lifecycle_sigterm_drains` the call cannot end before
/// the drain has begun, however late the test runs.
#[tokio::test(flavor = "multi_thread")]
async fn held_call_ends_only_on_its_release() {
    const SHORT_DRAIN_MS: u64 = 2_000;
    let mut held = hold_a_call(SHORT_DRAIN_MS).await;
    let child = &held.child;

    let sigterm = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + STEP;
    rustix::process::kill_process(child.pid(), rustix::process::Signal::TERM).unwrap();
    assert_eq!(
        by(child, "STOPPING=1", deadline, recv(&held.manager)).await,
        "STOPPING=1"
    );
    let answered = by(child, "the dropped call", deadline, &mut held.in_flight)
        .await
        .unwrap();
    assert!(answered.is_err(), "{answered:?}");
    let status = held.child.wait_until(deadline).await;
    let took = sigterm.elapsed();
    let logs = held.child.stderr();
    assert!(
        status.is_some_and(|s| !s.success()),
        "exit {status:?}\n{logs}"
    );
    assert!(
        took >= Duration::from_millis(SHORT_DRAIN_MS),
        "exited {took:?} after SIGTERM\n{logs}"
    );
    let timed_out = logs
        .lines()
        .find(|l| l.contains("drain deadline passed"))
        .unwrap_or_else(|| panic!("no drain timeout in\n{logs}"));
    assert!(timed_out.contains(r#""inflight":1"#), "{timed_out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_sigterm_drains() {
    let mut held = hold_a_call(DRAIN_MS).await;
    let child = &held.child;

    // One deadline for every step from SIGTERM to the exit.
    let deadline = tokio::time::Instant::now() + STEP;
    rustix::process::kill_process(child.pid(), rustix::process::Signal::TERM).unwrap();
    assert_eq!(
        by(child, "STOPPING=1", deadline, recv(&held.manager)).await,
        "STOPPING=1"
    );
    // No new calls: the socket is gone and nothing accepts on its path.
    let socket = &held.socket;
    assert!(std::fs::symlink_metadata(socket.socket_path()).is_err());
    assert!(std::os::unix::net::UnixStream::connect(socket.socket_path()).is_err());
    assert!(by(
        child,
        "a refused connection",
        deadline,
        ipc::uds::connect(socket, me())
    )
    .await
    .is_err());

    // The drain has begun with the call still in flight; only now may it finish.
    assert!(!held.in_flight.is_finished(), "the call ended unreleased");
    std::fs::write(&held.release, b"").unwrap();
    let answered = by(
        child,
        "the answer to the call in flight",
        deadline,
        &mut held.in_flight,
    )
    .await
    .unwrap();
    assert!(answered.is_ok(), "{answered:?}");

    let status = held.child.wait_until(deadline).await.unwrap_or_else(|| {
        panic!(
            "the service did not exit within {STEP:?} of SIGTERM (drain deadline {DRAIN:?}); \
             the child is killed. Its stderr:\n{}",
            held.child.stderr()
        )
    });
    let logs = held.child.stderr();
    // Exit 0: `run` drained the call within its drain deadline (a drain timeout exits 1).
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
