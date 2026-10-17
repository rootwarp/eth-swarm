//! Shared harness: cl-engine configs, a recording service manager, and the multi-UID helpers.
#![allow(dead_code)] // each test target uses part of it

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ipc::uds::SocketDir;
use svc_runtime::notify::Notifier;
use svc_runtime::{Config, Hooks, RuntimeError, Services};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Every `ethswarm.engine.v1` method.
pub const ENGINE_METHODS: [&str; 5] = [
    "/ethswarm.engine.v1.EngineService/NewPayload",
    "/ethswarm.engine.v1.EngineService/ForkchoiceUpdated",
    "/ethswarm.engine.v1.EngineService/GetPayload",
    "/ethswarm.engine.v1.EngineService/GetBlobs",
    "/ethswarm.engine.v1.EngineService/ExchangeCapabilities",
];

pub fn me() -> u32 {
    ipc::peercred::effective_uid()
}

/// A UID that is not ours (nor the invalid `u32::MAX`).
pub fn not_me() -> u32 {
    match me().checked_add(1) {
        Some(u) if u != u32::MAX => u,
        _ => 0,
    }
}

/// A runtime root for one test: `<tmp>/run`, with `tmp` and it mode 0755 so other users can
/// traverse them. Named without symlinks, which the socket bind refuses (macOS's temp dir is
/// under the `/var` symlink).
pub fn runtime_root(tmp: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let tmp = &std::fs::canonicalize(tmp).unwrap();
    let root = tmp.join("run");
    std::fs::create_dir(&root).unwrap();
    for dir in [tmp, &root] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    root
}

/// A cl-engine config: cl-chain is `chain_uid`, `methods` are given to `callers` (a TOML list).
pub fn engine_toml(
    root: &Path,
    group: u32,
    chain_uid: u32,
    methods: &[&str],
    callers: &str,
    drain_ms: u64,
) -> String {
    let mut text = format!(
        "network = \"sepolia\"\nmetrics_port = 9103\ndrain_timeout_ms = {drain_ms}\n\
         log_level = \"debug\"\n\n[socket]\nroot = \"{}\"\ngroup = {group}\n\n\
         [callers]\ncl-chain = {chain_uid}\ncl-api = {}\n\n[methods]\n",
        root.display(),
        not_me().wrapping_add(1)
    );
    for m in methods {
        text.push_str(&format!("\"{m}\" = {callers}\n"));
    }
    text
}

/// Loads `text` as cl-engine's config file, with an OS-picked metrics port.
pub fn engine_config(dir: &Path, text: &str) -> Result<Config, svc_runtime::config::ConfigError> {
    let path = dir.join("cl-engine.toml");
    std::fs::write(&path, text).unwrap();
    Config::load("cl-engine", &path).map(Config::with_ephemeral_metrics_port)
}

/// A service manager that records every notification.
pub struct Recorder(mpsc::UnboundedSender<String>);

impl Default for Recorder {
    /// A recorder nobody reads.
    fn default() -> Self {
        Self(mpsc::unbounded_channel().0)
    }
}

impl Notifier for Recorder {
    fn notify(&self, state: &str) -> std::io::Result<()> {
        let _ = self.0.send(state.to_owned());
        Ok(())
    }
}

/// A service started with [`start`].
pub struct Running {
    pub states: mpsc::UnboundedReceiver<String>,
    pub stop: Option<oneshot::Sender<()>>,
    pub task: JoinHandle<Result<(), RuntimeError>>,
    pub socket: SocketDir,
    pub metrics: SocketAddr,
}

impl Running {
    /// Sends the shutdown signal (what SIGTERM does in a real process).
    pub fn terminate(&mut self) {
        let _ = self.stop.take().expect("not stopped yet").send(());
    }

    pub async fn next_state(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(30), self.states.recv())
            .await
            .expect("a notification")
            .expect("notifier alive")
    }
}

/// The metrics address in a READY notification's `STATUS=`.
pub fn metrics_addr(ready: &str) -> SocketAddr {
    let start = ready.find("http://").expect("metrics url") + "http://".len();
    let rest = &ready[start..];
    rest[..rest.find('/').expect("path")]
        .parse()
        .expect("socket address")
}

/// Starts `services` under `config` and waits for READY.
pub async fn start(config: Config, services: Services) -> Running {
    let (tx, mut states) = mpsc::unbounded_channel();
    let (stop, stopped) = oneshot::channel::<()>();
    let socket = config.socket.clone();
    let hooks = Hooks {
        notifier: Arc::new(Recorder(tx)),
        shutdown: Box::pin(async {
            let _ = stopped.await;
        }),
        registry: prometheus_client_registry(),
    };
    let task = tokio::spawn(svc_runtime::run_with(config, services, hooks));
    let ready = tokio::time::timeout(Duration::from_secs(30), states.recv())
        .await
        .expect("READY in time")
        .expect("READY before the runtime stopped");
    assert!(ready.starts_with("READY=1\nSTATUS="), "{ready}");
    Running {
        states,
        stop: Some(stop),
        task,
        socket,
        metrics: metrics_addr(&ready),
    }
}

fn prometheus_client_registry() -> prometheus_client::registry::Registry {
    prometheus_client::registry::Registry::with_prefix("ethswarm")
}

/// `GET /metrics` from `addr`.
pub async fn scrape(addr: SocketAddr) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: metrics\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    out
}

/// Waits until `/metrics` shows `line`.
pub async fn wait_for_metric(addr: SocketAddr, line: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if scrape(addr).await.lines().any(|l| l == line) {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "{line} never shown");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---- the multi-UID part ----------------------------------------------------------------------

/// The throwaway users of the root-tests job: (uid, gid) each.
#[derive(Clone, Copy, Debug)]
pub struct Users {
    pub chain: (u32, u32),
    pub api: (u32, u32),
    pub other: (u32, u32),
}

/// The users for the multi-UID part of `test`, or `None` (skip) without root on Linux.
pub fn users(test: &str) -> Option<Users> {
    let required = std::env::var("ETHSWARM_ROOT_TESTS").is_ok_and(|v| v == "1");
    let id = |name: String| {
        std::env::var(format!("ETHSWARM_{name}"))
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
    };
    let pair = |user: &str| Some((id(format!("{user}_UID"))?, id(format!("{user}_GID"))?));
    let found = (|| {
        Some(Users {
            chain: pair("CHAIN")?,
            api: pair("API")?,
            other: pair("OTHER")?,
        })
    })();
    let why = if !cfg!(target_os = "linux") {
        "needs Linux (per-thread credentials)".to_owned()
    } else if me() != 0 {
        format!("needs root (euid {})", me())
    } else if found.is_none() {
        "needs ETHSWARM_{CHAIN,API,OTHER}_{UID,GID}".to_owned()
    } else {
        return found;
    };
    assert!(
        !required,
        "{test}: multi-UID part {why}; mandatory with ETHSWARM_ROOT_TESTS=1"
    );
    eprintln!(
        "SKIPPED the multi-UID part of {test}: {why} (runs in the root-tests CI job; locally \
         `sudo -E cargo test -p svc-runtime`)"
    );
    None
}

/// Connects to `path` from a thread holding `user`'s credentials and `groups`.
pub fn connect_as(
    user: (u32, u32),
    groups: &[u32],
    path: PathBuf,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    let groups = groups.to_vec();
    std::thread::spawn(move || {
        become_user(user, &groups);
        std::os::unix::net::UnixStream::connect(path)
    })
    .join()
    .unwrap()
}

#[cfg(target_os = "linux")]
fn become_user((uid, gid): (u32, u32), groups: &[u32]) {
    use rustix::process::{Gid, Uid};
    use rustix::thread::{set_thread_groups, set_thread_res_gid, set_thread_res_uid};
    let groups: Vec<Gid> = groups.iter().copied().map(Gid::from_raw).collect();
    set_thread_groups(&groups).unwrap();
    let g = Gid::from_raw(gid);
    set_thread_res_gid(g, g, g).unwrap();
    let u = Uid::from_raw(uid);
    set_thread_res_uid(u, u, u).unwrap();
}

#[cfg(not(target_os = "linux"))]
fn become_user(_: (u32, u32), _: &[u32]) {
    unreachable!("users() is None off Linux");
}

/// A channel over an already connected stream.
pub async fn channel_over(stream: std::os::unix::net::UnixStream) -> tonic::transport::Channel {
    stream.set_nonblocking(true).unwrap();
    let slot = Arc::new(std::sync::Mutex::new(Some(stream)));
    tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let s = slot.lock().unwrap().take();
            async move {
                let s = s.ok_or_else(|| std::io::Error::other("one connection only"))?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                    tokio::net::UnixStream::from_std(s)?,
                ))
            }
        }))
        .await
        .unwrap()
}
