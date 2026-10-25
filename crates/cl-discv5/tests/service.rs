//! The `cl-discv5` process as its unit runs it: no argument, its config file, its socket, and a
//! clean stop on SIGTERM.
//!
//! - `cl-discv5` itself: an argument is a usage error (exit 64).
//! - `cl-discv5-test` (the same code, its config from `$CL_DISCV5_TEST_CONFIG`, owned by the
//!   test user): discv5 on a loopback UDP port in local mode, `WatchPeers` and `GetLocalEnr` on
//!   its socket behind its ACL. On SIGTERM the open `WatchPeers` stream ends, the socket drains
//!   and is removed, and the process exits 0. Its log names its node ID and never the key.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use data_encoding::{BASE64, HEXLOWER};
use ethswarm_proto::discv5 as pb;
use ipc::testkit::devnet::{devnet_genesis_state, write_network_file, KURTOSIS_CONFIG};
use pb::discovery_service_client::DiscoveryServiceClient;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use svc_runtime::owned::testkit::{config_root, write_read_only, Sealed};

const SECRET: [u8; 32] = [0x42; 32];
const WAIT: Duration = Duration::from_secs(60);

fn me() -> (u32, u32) {
    let c = ipc::uds::Ownership::current();
    (c.uid, c.gid)
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

#[test]
fn an_argument_is_a_usage_error() {
    let mut child = Owned::spawn({
        let mut c = Command::new(env!("CARGO_BIN_EXE_cl-discv5"));
        c.arg("--listen");
        c
    });
    assert_eq!(child.wait(), Some(64));
    assert!(child.log().contains("takes no argument"), "{}", child.log());
}

/// The files of one cl-discv5: its config, network, runtime root and credential.
struct Host {
    _dir: tempfile::TempDir,
    config: PathBuf,
    socket: PathBuf,
    credentials: PathBuf,
    _sealed: Sealed,
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::Builder::new().tempdir_in(config_root()).unwrap();
        let root = dir.path();
        let (uid, gid) = me();
        let net = root.join("network");
        mkdir(&net, 0o755);
        write_network_file(net.join("config.yaml"), KURTOSIS_CONFIG);
        write_network_file(net.join("genesis.ssz"), devnet_genesis_state(64));
        mkdir(&root.join("run"), 0o755);
        let credentials = root.join("credentials");
        mkdir(&credentials, 0o700);
        let key = credentials.join(node_key::CREDENTIAL);
        std::fs::File::create(&key)
            .unwrap()
            .write_all(&SECRET)
            .unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
        let text = format!(
            "network_dir = \"{}\"\nmetrics_port = 9103\ndrain_timeout_ms = 5000\n\n\
             [socket]\nroot = \"{}\"\ngroup = {gid}\n\n[callers]\ncl-p2p = {uid}\n\n[methods]\n\
             \"/ethswarm.discv5.v1.DiscoveryService/WatchPeers\" = [\"cl-p2p\"]\n\
             \"/ethswarm.discv5.v1.DiscoveryService/GetLocalEnr\" = [\"cl-p2p\"]\n\n\
             [discv5]\nmode = \"local\"\nlisten_ip = \"127.0.0.1\"\nudp_port = {}\n\
             enr_ip = \"127.0.0.1\"\ntcp_port = 9000\nlookup_interval_ms = 200\n",
            net.display(),
            root.join("run").display(),
            free_udp_port()
        );
        let config = root.join("cl-discv5.toml");
        write_read_only(&config, &text);
        let sealed = Sealed::new(root);
        Self {
            socket: root.join("run/cl-discv5/cl-discv5.sock"),
            config,
            credentials,
            _sealed: sealed,
            _dir: dir,
        }
    }

    fn start(&self) -> Owned {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cl-discv5-test"));
        command
            .env(cl_discv5::process::TEST_CONFIG_ENV, &self.config)
            .env(node_key::CREDENTIALS_DIRECTORY, &self.credentials);
        Owned::spawn(command)
    }
}

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

#[tokio::test(flavor = "multi_thread")]
async fn the_service_serves_and_stops_cleanly_on_sigterm() {
    let host = Host::new();
    let mut child = host.start();
    let channel = connect(&host.socket, &child).await;
    let mut client = DiscoveryServiceClient::new(channel);
    let enr = client
        .get_local_enr(pb::GetLocalEnrRequest {})
        .await
        .unwrap()
        .into_inner()
        .enr
        .unwrap()
        .text;
    assert!(enr.starts_with("enr:"), "{enr}");
    let network = Arc::new(ipc::testkit::devnet::kurtosis_hello("test"));
    let link = ipc::Link::network(network, 1).unwrap();
    let mut stream = client
        .watch_peers(pb::WatchPeersRequest {
            hello: Some(link.local()),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(stream.message().await.unwrap().is_some(), "the hello");
    child.terminate();
    // The open stream ends first, so it cannot hold the drain.
    assert_eq!(
        stream.message().await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(0), "{log}");
    assert!(
        std::fs::symlink_metadata(&host.socket).is_err(),
        "socket removed"
    );
    assert!(log.contains(r#""message":"discv5 started""#), "{log}");
    assert!(log.contains(&enr), "the record is logged:\n{log}");
    assert!(log.contains(r#""message":"stopped""#), "{log}");
    // The key never shows, in hex or base64.
    assert!(!log.contains(&HEXLOWER.encode(&SECRET)), "{log}");
    assert!(!log.contains(&BASE64.encode(&SECRET)), "{log}");
}
