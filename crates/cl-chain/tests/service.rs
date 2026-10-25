//! The `cl-chain` process as its unit runs it: no argument, its config file, its socket, and a
//! clean stop on SIGTERM.
//!
//! - `cl-chain` itself: an argument is a usage error (exit 64), and a config that is not at
//!   `/etc/ethswarm/cl-chain.toml` is refused (exit 2).
//! - `cl-chain-test` (the same code, its config from `$CL_CHAIN_TEST_CONFIG`, owned by the
//!   test user): it serves chain.v1 on its socket behind its ACL, keeps a `WatchSubscriptions`
//!   stream open, and on SIGTERM ends that stream, drains, removes its socket and exits 0. A
//!   second start on the same state directory opens the store again, with the same custody.
//!
//! The child gets a cl-verify socket (a tonic server of this test, as its own user) and a
//! reference API that refuses every connection: its Status then has no sample, which is
//! `UNAVAILABLE`, never a guess.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cl_chain::probe::service::{chain_link, ProbeNetwork, CHAIN_METHODS};
use cl_chain::ChainStub;
use consensus_types::Minimal;
use ethswarm_proto::chain as pb;
use ipc::testkit::devnet::{
    devnet_genesis_state, write_network_file, DEVNET_GENESIS, KURTOSIS_CONFIG,
};
use network_config::ChainConfig;
use pb::gossip_service_client::GossipServiceClient;
use pb::req_resp_service_client::ReqRespServiceClient;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use svc_runtime::owned::testkit::{config_root, write_read_only, Sealed};

/// How long a child may take to serve, or to exit once signalled.
const WAIT: Duration = Duration::from_secs(60);

/// The Kurtosis devnet's shape (Gloas from genesis, so no digest change while a test runs),
/// with the serve range's config value.
fn network_yaml() -> String {
    format!("{KURTOSIS_CONFIG}MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS: 4096\n")
}

fn network() -> ProbeNetwork {
    let config = ChainConfig::from_devnet_yaml(network_yaml().as_bytes()).unwrap();
    ProbeNetwork::new("test", config, DEVNET_GENESIS).unwrap()
}

fn me() -> (u32, u32) {
    let current = ipc::uds::Ownership::current();
    (current.uid, current.gid)
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A child that is killed and reaped however the test ends; its stderr is read as it comes.
struct Owned {
    child: Child,
    stderr: Arc<Mutex<Vec<u8>>>,
}

impl Owned {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let mut pipe = child.stderr.take().unwrap();
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Self { child, stderr }
    }

    fn log(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }

    /// The exit code within [`WAIT`].
    fn wait(&mut self) -> Option<i32> {
        let by = Instant::now() + WAIT;
        while Instant::now() < by {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the child did not exit in time:\n{}", self.log());
    }

    fn terminate(&self) {
        let pid = rustix::process::Pid::from_child(&self.child);
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Every stderr line is one JSON object.
fn assert_json_lines(log: &str) {
    assert!(!log.is_empty(), "nothing logged");
    for line in log.lines() {
        assert!(line.starts_with(r#"{"timestamp":""#), "{line}");
    }
}

#[test]
fn an_argument_is_a_usage_error() {
    let mut child = Owned::spawn({
        let mut c = Command::new(env!("CARGO_BIN_EXE_cl-chain"));
        c.arg("--config").arg("/tmp/x.toml");
        c
    });
    assert_eq!(child.wait(), Some(64));
    let log = child.log();
    assert_json_lines(&log);
    assert!(log.contains("takes no argument"), "{log}");
    assert!(!log.contains("/tmp/x.toml"), "{log}");
}

#[test]
fn a_config_that_is_not_installed_is_refused() {
    if Path::new(cl_chain::service::CONFIG_PATH).exists() {
        eprintln!("skipped: this host has {}", cl_chain::service::CONFIG_PATH);
        return;
    }
    let mut child = Owned::spawn(Command::new(env!("CARGO_BIN_EXE_cl-chain")));
    assert_eq!(child.wait(), Some(2));
    let log = child.log();
    assert_json_lines(&log);
    assert!(log.contains("config refused"), "{log}");
}

/// The files of one service: its config, network, runtime root, state and cl-verify's socket,
/// on a path with no symlink and no directory that the test user can write above its own.
struct Host {
    _dir: tempfile::TempDir,
    config: PathBuf,
    socket: PathBuf,
    verify: PathBuf,
    /// The store's directory (made by the service).
    columns: PathBuf,
    _sealed: Sealed,
}

impl Host {
    fn new(extra: &str) -> Self {
        Self::with_verify_dir("verify", extra)
    }

    /// A host whose cl-verify socket is in `<root>/<verify_dir>`, which is made only if it is
    /// `verify`.
    fn with_verify_dir(verify_dir: &str, extra: &str) -> Self {
        let dir = tempfile::Builder::new().tempdir_in(config_root()).unwrap();
        let root = dir.path();
        let (uid, gid) = me();
        let net = root.join("network");
        mkdir(&net, 0o755);
        write_network_file(net.join("config.yaml"), network_yaml());
        write_network_file(net.join("genesis.ssz"), devnet_genesis_state(64));
        mkdir(&root.join("run"), 0o755);
        mkdir(&root.join("state"), 0o700);
        mkdir(&root.join("verify"), 0o700);
        let mut text = format!(
            "network_dir = \"{}\"\nmetrics_port = 9102\nlog_level = \"debug\"\n\
             drain_timeout_ms = 5000\n\n[socket]\nroot = \"{}\"\ngroup = {gid}\n\n\
             [callers]\ncl-p2p = {uid}\n\n[methods]\n",
            net.display(),
            root.join("run").display()
        );
        for m in CHAIN_METHODS {
            text.push_str(&format!("\"{m}\" = [\"cl-p2p\"]\n"));
        }
        text.push_str(&format!(
            "\n[chain]\nreference_api_url = \"http://127.0.0.1:1\"\n\
             node_id = \"0x{}07\"\nverify_socket = \"{}\"\nverify_uid = {uid}\n\
             columns_dir = \"{}\"\n",
            "00".repeat(31),
            root.join(verify_dir).join("cl-verify.sock").display(),
            root.join("state/columns").display()
        ));
        text.push_str(extra);
        let config = root.join("cl-chain.toml");
        write_read_only(&config, &text);
        let sealed = Sealed::new(root);
        Self {
            socket: root.join("run/cl-chain/cl-chain.sock"),
            verify: root.join(verify_dir).join("cl-verify.sock"),
            columns: root.join("state/columns"),
            config,
            _sealed: sealed,
            _dir: dir,
        }
    }

    fn start(&self) -> Owned {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cl-chain-test"));
        command.env(cl_chain::service::TEST_CONFIG_ENV, &self.config);
        Owned::spawn(command)
    }
}

/// A channel to the child's socket once it serves.
async fn connect(socket: &Path, child: &Owned) -> tonic::transport::Channel {
    let by = tokio::time::Instant::now() + WAIT;
    loop {
        if let Ok(channel) = ipc::uds::connect_path(socket, me().0).await {
            return channel;
        }
        assert!(
            tokio::time::Instant::now() < by,
            "never served:\n{}",
            child.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One run: serves, holds a `WatchSubscriptions` stream open, then stops on SIGTERM with exit
/// 0 and no socket left. Returns the custody columns it named.
async fn one_run(host: &Host) -> Vec<u64> {
    let mut child = host.start();
    let channel = connect(&host.socket, &child).await;
    let hello = chain_link::<Minimal>(&network(), cl_chain::probe::service::system_ms())
        .unwrap()
        .local()
        .clone();
    // Admitted by the ACL; no reference sample yet: UNAVAILABLE.
    let status = ReqRespServiceClient::new(channel.clone())
        .get_status(pb::GetStatusRequest {})
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status:?}");
    let mut stream = GossipServiceClient::new(channel)
        .watch_subscriptions(pb::WatchSubscriptionsRequest { hello: Some(hello) })
        .await
        .unwrap()
        .into_inner();
    assert!(stream.message().await.unwrap().is_some(), "the hello");
    let columns = match stream.message().await.unwrap().and_then(|m| m.frame) {
        Some(pb::watch_subscriptions_response::Frame::Body(body)) => body.custody_columns,
        other => panic!("a body, got {other:?}"),
    };
    assert_eq!(columns.len(), 4);
    child.terminate();
    // The open stream ends first, so it cannot hold the drain.
    let end = stream.message().await.unwrap_err();
    assert_eq!(end.code(), tonic::Code::Unavailable, "{end:?}");
    let code = tokio::task::spawn_blocking(move || {
        let code = child.wait();
        (code, child.log())
    })
    .await
    .unwrap();
    assert_eq!(code.0, Some(0), "{}", code.1);
    assert!(
        std::fs::symlink_metadata(&host.socket).is_err(),
        "the socket is removed"
    );
    assert_json_lines(&code.1);
    assert!(code.1.contains(r#""message":"ready""#), "{}", code.1);
    assert!(code.1.contains(r#""message":"stopped""#), "{}", code.1);
    columns
}

#[tokio::test(flavor = "multi_thread")]
async fn the_service_serves_and_stops_cleanly_on_sigterm() {
    let host = Host::new("");
    // cl-verify's socket: any chain.v1 server of our own user accepts the connection.
    let listener = tokio::net::UnixListener::bind(&host.verify).unwrap();
    let link = chain_link::<Minimal>(&network(), cl_chain::probe::service::system_ms()).unwrap();
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        ChainStub::new(link).routes(),
        std::future::pending(),
    ));
    let first = one_run(&host).await;
    // A restart opens the same store, with the same custody.
    let again = one_run(&host).await;
    assert_eq!(first, again);
}

/// Without cl-verify the start ends with 69 (a restart may find it), after the bounded wait
/// (`verify_wait_ms`).
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_cl_verify_is_retried_by_systemd() {
    let host = Host::new("verify_wait_ms = 500\n");
    let mut child = host.start();
    let code = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code.0, Some(69), "{}", code.1);
    assert!(code.1.contains("cl-verify"), "{}", code.1);
}

/// A SIGTERM while the start still waits for cl-verify stops it at once, cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn a_sigterm_during_the_wait_for_cl_verify_is_a_clean_stop() {
    let host = Host::new("verify_wait_ms = 600000\n");
    let mut child = host.start();
    let by = Instant::now() + WAIT;
    while !child.log().contains("cl-verify is not accepting yet") {
        assert!(Instant::now() < by, "never waited:\n{}", child.log());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let signalled = Instant::now();
    child.terminate();
    let code = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code.0, Some(0), "{}", code.1);
    assert!(signalled.elapsed() < Duration::from_secs(10), "{}", code.1);
}

/// cl-verify's runtime directory is not there (after a reboot, or after systemd removed it with
/// cl-verify's stop): the start waits for it, then ends with 69, so systemd starts it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_cl_verify_directory_is_retried_by_systemd() {
    let host = Host::with_verify_dir("absent", "verify_wait_ms = 500\n");
    let mut child = host.start();
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(69), "{log}");
    assert!(log.contains("cl-verify"), "{log}");
}

/// A cl-verify directory that others can write is a refusal that a restart cannot fix: 1.
#[tokio::test(flavor = "multi_thread")]
async fn an_open_cl_verify_directory_is_a_failed_start() {
    let host = Host::new("verify_wait_ms = 500\n");
    let dir = host.verify.parent().unwrap().to_owned();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut child = host.start();
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains("verify socket directory"), "{log}");
}

/// A store of another node ID: its custody columns are another key's. The start refuses it
/// with 2 and tells the operator to clear the store.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_of_another_node_id_is_refused() {
    let host = Host::new("verify_wait_ms = 500\n");
    // cl-verify's socket, so the start reaches the store.
    let listener = tokio::net::UnixListener::bind(&host.verify).unwrap();
    let link = chain_link::<Minimal>(&network(), cl_chain::probe::service::system_ms()).unwrap();
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        ChainStub::new(link).routes(),
        std::future::pending(),
    ));
    mkdir(&host.columns, 0o700);
    let marker = host.columns.join(cl_chain::probe::service::NODE_ID_FILE);
    std::fs::write(&marker, format!("0x{}09\n", "00".repeat(31))).unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut child = host.start();
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(2), "{log}");
    assert!(log.contains("clear the store"), "{log}");
}
