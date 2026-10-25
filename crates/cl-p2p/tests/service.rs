//! The `cl-p2p` process as its unit runs it: no argument, its config file, its identity from
//! the credential, cl-chain over its socket, its own socket and `/metrics`, and a clean stop on
//! SIGTERM.
//!
//! cl-chain is the real probe service (`cl_chain::probe::service::ProbeService`) in this test
//! process, as the test user, its reference API refusing every connection (so our Status has
//! no sample and nothing is dialled). cl-discv5 is a fake ([`FakeDiscovery`]): `GetLocalEnr`
//! answers a record with a chosen `cgc`, and `WatchPeers` sends its hello and fails, so cl-p2p
//! tries again. Without it cl-p2p runs on and keeps trying.
//!
//! - `cl-p2p` itself: an argument is a usage error (exit 64).
//! - `cl-p2p-test` with cl-chain's custody of our key and cl-discv5's record of its group count:
//!   it starts, reads the record and watches the peers, `/metrics` shows the swarm's names
//!   without a prefix, and SIGTERM ends it with Goodbye to every peer, exit 0 and no socket
//!   left. Its log never shows the key.
//! - With cl-chain's custody of another key (cl-chain's `node_id` is wrong): exit 2.
//! - With cl-discv5's record of another `cgc` than cl-chain's custody: exit 2.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cl_chain::probe::service::{chain_link, system_ms, ProbeNetwork, ProbePlan, ProbeService};
use cl_chain::probe::BeaconApi;
use cl_chain::verify::client::{KzgOutcome, KzgVerifier};
use consensus_types::das::CUSTODY_REQUIREMENT;
use consensus_types::primitives::U256;
use consensus_types::Minimal;
use ethswarm_proto::discv5 as dpb;
use ethswarm_proto::verify::KzgCellProof;
use ipc::stub::StubStream;
use ipc::testkit::devnet::{
    devnet_genesis_state, write_network_file, DEVNET_GENESIS, KURTOSIS_CONFIG,
};
use network_config::ChainConfig;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use svc_runtime::owned::testkit::{config_root, write_read_only, Sealed};
use tonic::{Request, Response, Status};

const SECRET: [u8; 32] = [0x42; 32];
const WAIT: Duration = Duration::from_secs(60);
const TOPICS: &str = include_str!("../../../ops/probe/gossip-topics.toml");

/// Passes every cell.
struct Valid;

impl KzgVerifier for Valid {
    async fn verify_cells(&self, _: Vec<KzgCellProof>, _: Duration) -> KzgOutcome {
        KzgOutcome::Valid
    }
}

fn me() -> (u32, u32) {
    let c = ipc::uds::Ownership::current();
    (c.uid, c.gid)
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn network_yaml() -> String {
    format!("{KURTOSIS_CONFIG}MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS: 4096\n")
}

/// The node ID of [`SECRET`], as cl-p2p computes it.
fn our_node_id() -> U256 {
    let mut secret = SECRET;
    let key = libp2p::identity::secp256k1::SecretKey::try_from_bytes(&mut secret).unwrap();
    let keypair = libp2p::identity::Keypair::from(libp2p::identity::secp256k1::Keypair::from(key));
    cl_p2p::service::node_id(&keypair).unwrap()
}

/// cl-discv5 as cl-p2p reads it: its record, with `cgc`, from `GetLocalEnr`, and a `WatchPeers`
/// stream that sends its hello and fails. The other RPCs are stubs.
struct FakeDiscovery {
    link: ipc::Link,
    /// The record of each `GetLocalEnr`, in turn; the last one again past them.
    records: Vec<String>,
    asked: std::sync::atomic::AtomicUsize,
}

#[tonic::async_trait]
impl dpb::discovery_service_server::DiscoveryService for FakeDiscovery {
    type WatchPeersStream = StubStream<dpb::WatchPeersResponse>;

    async fn watch_peers(
        &self,
        request: Request<dpb::WatchPeersRequest>,
    ) -> Result<Response<Self::WatchPeersStream>, Status> {
        ipc::stub::server_stream(&self.link, "watch_peers", request.get_ref())
    }

    type FindPeersStream = StubStream<dpb::FindPeersResponse>;

    async fn find_peers(
        &self,
        request: Request<dpb::FindPeersRequest>,
    ) -> Result<Response<Self::FindPeersStream>, Status> {
        ipc::stub::server_stream(&self.link, "find_peers", request.get_ref())
    }

    async fn update_enr(
        &self,
        _: Request<dpb::UpdateEnrRequest>,
    ) -> Result<Response<dpb::UpdateEnrResponse>, Status> {
        ipc::stub::unary(&self.link, "update_enr", &[])
    }

    async fn get_local_enr(
        &self,
        _: Request<dpb::GetLocalEnrRequest>,
    ) -> Result<Response<dpb::GetLocalEnrResponse>, Status> {
        let n = self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let text = self.records[n.min(self.records.len() - 1)].clone();
        Ok(Response::new(dpb::GetLocalEnrResponse {
            enr: Some(dpb::Enr { text }),
        }))
    }
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
        let mut c = Command::new(env!("CARGO_BIN_EXE_cl-p2p"));
        c.arg("--listen");
        c
    });
    assert_eq!(child.wait(), Some(64));
    assert!(child.log().contains("takes no argument"), "{}", child.log());
}

/// The files of one cl-p2p, and cl-chain's socket, on a path the owner walk accepts.
struct Host {
    dir: tempfile::TempDir,
    config: PathBuf,
    credentials: PathBuf,
    chain_socket: PathBuf,
    discv5_socket: PathBuf,
    p2p_socket: PathBuf,
    _sealed: Sealed,
}

impl Host {
    fn new() -> Self {
        Self::with_chain_dir("chain", 10_000)
    }

    /// A host whose cl-chain socket is in `<root>/<chain_dir>` (made only if it is `chain`),
    /// waited for `chain_wait_ms`.
    fn with_chain_dir(chain_dir: &str, chain_wait_ms: u64) -> Self {
        let dir = tempfile::Builder::new().tempdir_in(config_root()).unwrap();
        let root = dir.path();
        let (uid, gid) = me();
        let net = root.join("network");
        mkdir(&net, 0o755);
        write_network_file(net.join("config.yaml"), network_yaml());
        write_network_file(net.join("genesis.ssz"), devnet_genesis_state(64));
        mkdir(&root.join("run"), 0o755);
        mkdir(&root.join("chain"), 0o700);
        mkdir(&root.join("discv5"), 0o700);
        mkdir(&root.join("state"), 0o700);
        let credentials = root.join("credentials");
        mkdir(&credentials, 0o700);
        let key = credentials.join(node_key::CREDENTIAL);
        std::fs::File::create(&key)
            .unwrap()
            .write_all(&SECRET)
            .unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
        let topics = root.join("gossip-topics.toml");
        write_read_only(&topics, TOPICS);
        let chain_socket = root.join(chain_dir).join("cl-chain.sock");
        let text = format!(
            "network_dir = \"{}\"\nmetrics_port = 9101\ndrain_timeout_ms = 5000\n\n\
             [socket]\nroot = \"{}\"\ngroup = {gid}\n\n[callers]\ncl-sync = {uid}\n\n[methods]\n\
             \"/ethswarm.p2p.v1.NetworkService/ListPeers\" = [\"cl-sync\"]\n\n\
             [p2p]\nlisten = [\"/ip4/127.0.0.1/tcp/0\"]\nchain_socket = \"{}\"\n\
             chain_uid = {uid}\ndiscv5_socket = \"{}\"\ndiscv5_uid = {uid}\n\
             gossip_topics = \"{}\"\nchain_wait_ms = {chain_wait_ms}\n",
            net.display(),
            root.join("run").display(),
            chain_socket.display(),
            root.join("discv5/cl-discv5.sock").display(),
            topics.display()
        );
        let config = root.join("cl-p2p.toml");
        write_read_only(&config, &text);
        let sealed = Sealed::new(root);
        Self {
            config,
            credentials,
            p2p_socket: root.join("run/cl-p2p/cl-p2p.sock"),
            discv5_socket: root.join("discv5/cl-discv5.sock"),
            chain_socket,
            _sealed: sealed,
            dir,
        }
    }

    fn start(&self) -> Owned {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cl-p2p-test"));
        command
            .env(cl_p2p::service::TEST_CONFIG_ENV, &self.config)
            .env(node_key::CREDENTIALS_DIRECTORY, &self.credentials);
        Owned::spawn(command)
    }

    /// cl-chain's probe service for `node_id`, served on its socket until dropped.
    fn chain(&self, node_id: U256) -> tokio::task::JoinHandle<()> {
        let config = ChainConfig::from_devnet_yaml(network_yaml().as_bytes()).unwrap();
        let net = ProbeNetwork::new("cl-chain/test", config, DEVNET_GENESIS).unwrap();
        let plan = ProbePlan {
            link: chain_link::<Minimal>(&net, system_ms()).unwrap(),
            node_id,
            columns_dir: self.dir.path().join("state/columns"),
            reference: BeaconApi::new("http://127.0.0.1:1", Duration::from_millis(200)).unwrap(),
            kzg: Valid,
            verify_timeout: Duration::from_secs(5),
            cgc_set_slot: 0,
        };
        let service = ProbeService::<Minimal, Valid>::open(
            &net,
            plan,
            &mut prometheus_client::registry::Registry::default(),
        )
        .unwrap();
        let listener = tokio::net::UnixListener::bind(&self.chain_socket).unwrap();
        let routes = service.routes();
        tokio::spawn(async move {
            let _service = service;
            let _ = ipc::stub::serve_uds(listener, routes, std::future::pending()).await;
        })
    }
}

impl Host {
    /// A fake cl-discv5 whose record advertises `cgc`, served on its socket until dropped.
    fn discv5(&self, cgc: u64) -> tokio::task::JoinHandle<()> {
        self.discv5_records(&[cgc])
    }

    /// A fake cl-discv5 whose record advertises `cgcs[n]` at its n-th `GetLocalEnr` (the last
    /// one past them), served on its socket until dropped.
    fn discv5_records(&self, cgcs: &[u64]) -> tokio::task::JoinHandle<()> {
        let config = ChainConfig::from_devnet_yaml(network_yaml().as_bytes()).unwrap();
        let net = ProbeNetwork::new("cl-discv5/test", config, DEVNET_GENESIS).unwrap();
        let records = cgcs
            .iter()
            .map(|&cgc| {
                let cgc = p2p_wire::enr::encode_cgc(cgc);
                cl_p2p::testkit::record_text(&[(b"cgc", &cgc), (b"eth2", &[0; 16])])
            })
            .collect();
        let fake = FakeDiscovery {
            link: chain_link::<Minimal>(&net, system_ms()).unwrap(),
            records,
            asked: std::sync::atomic::AtomicUsize::new(0),
        };
        let listener = tokio::net::UnixListener::bind(&self.discv5_socket).unwrap();
        let routes = tonic::service::Routes::new(
            dpb::discovery_service_server::DiscoveryServiceServer::new(fake),
        );
        tokio::spawn(async move {
            let _ = ipc::stub::serve_uds(listener, routes, std::future::pending()).await;
        })
    }
}

/// The `/metrics` address in the "ready" log line.
fn metrics_addr(log: &str) -> Option<String> {
    let line = log.lines().find(|l| l.contains(r#""message":"ready""#))?;
    let rest = &line[line.find(r#""metrics":""#)? + r#""metrics":""#.len()..];
    Some(rest[..rest.find('"')?].to_owned())
}

async fn scrape(addr: &str) -> String {
    let addr = addr.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: m\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_service_runs_and_stops_cleanly_on_sigterm() {
    let host = Host::new();
    let chain = host.chain(our_node_id());
    let discv5 = host.discv5(CUSTODY_REQUIREMENT);
    let mut child = host.start();
    let by = Instant::now() + WAIT;
    let addr = loop {
        if let Some(addr) = metrics_addr(&child.log()) {
            break addr;
        }
        assert!(Instant::now() < by, "never ready:\n{}", child.log());
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        child.log().contains("custody columns are our key's"),
        "{}",
        child.log()
    );
    // cl-discv5's record has our group count: the peers are watched.
    while !child.log().contains("watching cl-discv5's peers") {
        assert!(Instant::now() < by, "never watched:\n{}", child.log());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        std::fs::symlink_metadata(&host.p2p_socket).is_ok(),
        "our socket"
    );
    let metrics = scrape(&addr).await;
    for name in [
        "p2p_peers{direction=\"inbound\"} 0",
        "# TYPE p2p_goodbye_received counter",
        "# TYPE mesh_peer_counts gauge",
        "ethswarm_rpc_inflight 0",
        // The column hand-off to cl-chain's Validate, and the column answers to peers.
        "p2p_column_handoff_total{result=\"unsent\"} 0",
        "# TYPE rpc_column_sidecars_answered counter",
    ] {
        assert!(metrics.contains(name), "{name}:\n{metrics}");
    }
    assert!(!metrics.contains("ethswarm_p2p_"), "{metrics}");
    child.terminate();
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(0), "{log}");
    assert!(
        std::fs::symlink_metadata(&host.p2p_socket).is_err(),
        "socket removed"
    );
    assert!(log.contains("Goodbye sent to every peer"), "{log}");
    assert!(log.contains(r#""message":"stopped""#), "{log}");
    use data_encoding::{BASE64, HEXLOWER};
    assert!(!log.contains(&HEXLOWER.encode(&SECRET)), "{log}");
    assert!(!log.contains(&BASE64.encode(&SECRET)), "{log}");
    chain.abort();
    discv5.abort();
}

/// cl-discv5's record advertises another custody group count than cl-chain's custody, which
/// our MetaData carries: peers would read two counts. cl-p2p stops with exit 2, naming the key
/// to set, and says Goodbye first.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_of_another_cgc_is_refused() {
    let host = Host::new();
    let chain = host.chain(our_node_id());
    let discv5 = host.discv5(CUSTODY_REQUIREMENT * 2);
    let mut child = host.start();
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(2), "{log}");
    assert!(
        log.contains(&format!("set cgc = {CUSTODY_REQUIREMENT}")),
        "{log}"
    );
    assert!(log.contains("Goodbye sent to every peer"), "{log}");
    assert!(!log.contains("watching cl-discv5's peers"), "{log}");
    chain.abort();
    discv5.abort();
}

/// cl-discv5's record changes its custody group count after the start: cl-p2p logs an ERROR
/// and stops with 70, so systemd starts it again, and its start then refuses with exit 2. A
/// bad peer service cannot stop cl-p2p for good this way.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_whose_cgc_changes_after_the_start_restarts_the_unit() {
    let host = Host::new();
    let chain = host.chain(our_node_id());
    let discv5 = host.discv5_records(&[CUSTODY_REQUIREMENT, CUSTODY_REQUIREMENT * 2]);
    let mut child = host.start();
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(70), "{log}");
    assert!(
        log.contains("watching cl-discv5's peers"),
        "the first record passed: {log}"
    );
    assert!(log.contains(r#""level":"ERROR""#), "{log}");
    chain.abort();
    discv5.abort();
}

/// cl-chain custodies another key's columns (its `node_id` is wrong): cl-p2p refuses to start
/// with exit 2, naming both.
#[tokio::test(flavor = "multi_thread")]
async fn custody_of_another_key_is_refused() {
    let host = Host::new();
    let chain = host.chain(U256::from(7u64));
    let mut child = host.start();
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(2), "{log}");
    assert!(log.contains("set cl-chain's node_id"), "{log}");
    chain.abort();
}

/// cl-chain's runtime directory is not there (after a reboot, or after systemd removed it at
/// cl-chain's stop): the start waits for it, then ends with 69, so systemd starts it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_cl_chain_directory_is_retried_by_systemd() {
    let host = Host::with_chain_dir("absent", 500);
    let mut child = host.start();
    let (code, log) = tokio::task::spawn_blocking(move || (child.wait(), child.log()))
        .await
        .unwrap();
    assert_eq!(code, Some(69), "{log}");
    assert!(log.contains("cl-chain"), "{log}");
}
