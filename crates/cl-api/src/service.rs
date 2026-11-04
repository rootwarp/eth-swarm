//! The `cl-api` process. It reads `/etc/ethswarm/cl-api.toml` through the owner walk
//! (`svc_runtime::Config::load_root_owned`). It serves `ethswarm.api.v1` on its socket through
//! svc-runtime and the Beacon API on HTTP, and polls cl-chain for the node state, until SIGTERM.
//!
//! ```toml
//! network = "sepolia"
//! metrics_port = 9105
//!
//! [socket]
//! group = 994
//!
//! [callers]
//! supervisor = 996
//!
//! [methods]
//! "/ethswarm.api.v1.ApiService/GetHealth" = ["supervisor"]
//!
//! [api]
//! http_listen = "127.0.0.1:5052"                         # optional, this default
//! http_allow_non_loopback = false                        # the operator flag (ARCH §2b)
//! chain_socket = "/run/ethswarm/cl-chain/cl-chain.sock"  # optional, this default
//! chain_uid = 990                                        # the UID cl-chain runs as
//! poll_interval_ms = 1000                                # optional, this default
//! http_header_read_timeout_ms = 5000                     # optional, this default
//! http_request_timeout_ms = 30000                        # optional, this default
//! http_write_timeout_ms = 30000                          # optional, this default
//! http_max_connections = 64                              # optional, this default
//! http_allowed_hosts = ["localhost", "127.0.0.1", "[::1]"]  # optional, this default
//! ```
//!
//! - **`http_listen`** must be a loopback address unless `http_allow_non_loopback = true`
//!   ([`HttpBind`]). A refused address stops the process before anything listens.
//! - **HTTP limits** ([`HttpLimits`]). `http_header_read_timeout_ms` bounds a request head and
//!   an idle keep-alive connection. `http_request_timeout_ms` bounds a non-streaming handler
//!   (503). `http_write_timeout_ms` closes a connection whose writes have made no progress for
//!   that long (a client that stopped reading), so it frees its slot and does not hold up
//!   shutdown. `http_max_connections` caps open connections. A request whose `Host` is not one of
//!   `http_allowed_hosts` (any port) answers 421. A non-loopback `http_listen` needs the names
//!   its clients use added here.
//! - **cl-chain** is reached on `chain_socket` only if its server runs as `chain_uid`
//!   (`ipc::uds::PeerCheckedConnector`). The channel connects lazily, so cl-api starts, and
//!   answers 503 from `node/health`, while cl-chain is still down. cl-chain's ACL must give
//!   cl-api [`CHAIN_METHODS`]: `ImportService/GetChainStatus` (the poller) and
//!   `EventsService/Subscribe` (`/eth/v1/events`, one subscription for every client:
//!   [`crate::sse`]). Without the subscription, `/eth/v1/events` answers 503.
//! - **Shutdown.** At SIGTERM, the gRPC socket drains (svc-runtime), and the HTTP server stops
//!   accepting and lets its open requests finish. Every `/eth/v1/events` stream ends then, so
//!   none holds up the drain.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ethswarm_proto::api::api_service_server::ApiServiceServer;
use ethswarm_proto::chain::events_service_client::EventsServiceClient;
use ethswarm_proto::chain::import_service_client::ImportServiceClient;
use ipc::hello::{NetworkHello, API_VERSION_V1};
use ipc::uds::PeerCheckedConnector;
use ipc::Link;
use network_config::{ChainConfig, Genesis};
use serde::Deserialize;
use svc_runtime::{Config, Hooks, Services};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tonic::transport::Endpoint;

use crate::node_state::{poll_chain, NodeState, SlotClock};
use crate::routes::config::{ConfigData, ConfigDataError};
use crate::server::{is_bare_host, router, ApiState, BindError, HttpBind, HttpLimits};
use crate::sse::EventHub;
use crate::ApiStub;

/// The exit code of a config that does not load.
pub const EXIT_CONFIG: u8 = 2;

/// The exit code of a command line with arguments.
pub const EXIT_USAGE: u8 = 64;

/// The service name: its config file, socket and ACL.
pub const SERVICE: &str = "cl-api";

/// cl-chain's socket unless `chain_socket` says otherwise.
pub const DEFAULT_CHAIN_SOCKET: &str = "/run/ethswarm/cl-chain/cl-chain.sock";

/// The chain.v1 methods cl-api calls. cl-chain's method ACL must give each of them to cl-api.
pub const CHAIN_METHODS: [&str; 2] = [
    "/ethswarm.chain.v1.ImportService/GetChainStatus",
    "/ethswarm.chain.v1.EventsService/Subscribe",
];

/// How often cl-chain is polled unless `poll_interval_ms` says otherwise.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;

/// The `[api]` table.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSettings {
    #[serde(default = "default_http_listen")]
    pub http_listen: SocketAddr,
    /// The operator flag that allows a non-loopback `http_listen`.
    #[serde(default)]
    pub http_allow_non_loopback: bool,
    #[serde(default = "default_chain_socket")]
    pub chain_socket: PathBuf,
    /// The UID cl-chain's server must run as.
    pub chain_uid: u32,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// [`HttpLimits::header_read_timeout`].
    #[serde(default = "default_http_header_read_timeout_ms")]
    pub http_header_read_timeout_ms: u64,
    /// [`HttpLimits::request_timeout`].
    #[serde(default = "default_http_request_timeout_ms")]
    pub http_request_timeout_ms: u64,
    /// [`HttpLimits::write_timeout`].
    #[serde(default = "default_http_write_timeout_ms")]
    pub http_write_timeout_ms: u64,
    /// [`HttpLimits::max_connections`].
    #[serde(default = "default_http_max_connections")]
    pub http_max_connections: usize,
    /// [`HttpLimits::allowed_hosts`].
    #[serde(default = "default_http_allowed_hosts")]
    pub http_allowed_hosts: Vec<String>,
}

fn default_http_listen() -> SocketAddr {
    crate::server::DEFAULT_HTTP_ADDR
}

fn default_chain_socket() -> PathBuf {
    PathBuf::from(DEFAULT_CHAIN_SOCKET)
}

fn default_poll_interval_ms() -> u64 {
    DEFAULT_POLL_INTERVAL_MS
}

fn default_http_header_read_timeout_ms() -> u64 {
    crate::server::DEFAULT_HEADER_READ_TIMEOUT_MS
}

fn default_http_request_timeout_ms() -> u64 {
    crate::server::DEFAULT_REQUEST_TIMEOUT_MS
}

fn default_http_write_timeout_ms() -> u64 {
    crate::server::DEFAULT_WRITE_TIMEOUT_MS
}

fn default_http_max_connections() -> usize {
    crate::server::DEFAULT_MAX_CONNECTIONS
}

fn default_http_allowed_hosts() -> Vec<String> {
    crate::server::DEFAULT_ALLOWED_HOSTS
        .map(String::from)
        .to_vec()
}

/// Why cl-api stopped or did not start.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("config: {0}")]
    Config(String),
    #[error(transparent)]
    Bind(#[from] BindError),
    #[error(transparent)]
    ConfigData(#[from] ConfigDataError),
    #[error("the network has no genesis time, which the wall-clock slot needs")]
    NoGenesis,
    #[error(transparent)]
    Runtime(#[from] svc_runtime::RuntimeError),
}

impl ApiSettings {
    /// The `[api]` table of `config`.
    ///
    /// # Errors
    ///
    /// The table does not parse, has no `chain_uid`, or has a zero poll interval or a relative
    /// `chain_socket`. Or an HTTP limit is out of range: a zero timeout, a connection cap outside
    /// `1..=Semaphore::MAX_PERMITS`, no allowed host, or an allowed host that is not a bare host.
    pub fn load(config: &Config) -> Result<Self, ServiceError> {
        let settings: Self = config
            .section()
            .map_err(|e| ServiceError::Config(e.to_string()))?;
        if settings.poll_interval_ms == 0 {
            return Err(ServiceError::Config("[api] poll_interval_ms is 0".into()));
        }
        if !settings.chain_socket.is_absolute() {
            let socket = settings.chain_socket.display();
            return Err(ServiceError::Config(format!(
                "[api] chain_socket {socket} is not an absolute path"
            )));
        }
        for (key, ms) in [
            (
                "http_header_read_timeout_ms",
                settings.http_header_read_timeout_ms,
            ),
            ("http_request_timeout_ms", settings.http_request_timeout_ms),
            ("http_write_timeout_ms", settings.http_write_timeout_ms),
        ] {
            if ms == 0 {
                return Err(ServiceError::Config(format!("[api] {key} is 0")));
            }
        }
        let (max, cap) = (Semaphore::MAX_PERMITS, settings.http_max_connections);
        if !(1..=max).contains(&cap) {
            return Err(ServiceError::Config(format!(
                "[api] http_max_connections {cap} is outside 1..={max}"
            )));
        }
        if settings.http_allowed_hosts.is_empty() {
            return Err(ServiceError::Config(
                "[api] http_allowed_hosts is empty, so every request would answer 421".into(),
            ));
        }
        if let Some(bad) = settings
            .http_allowed_hosts
            .iter()
            .find(|h| !is_bare_host(h))
        {
            return Err(ServiceError::Config(format!(
                "[api] http_allowed_hosts entry {bad:?} is not a host without a port"
            )));
        }
        Ok(settings)
    }

    /// Where the Beacon API listens.
    #[must_use]
    pub fn bind(&self) -> HttpBind {
        HttpBind {
            addr: self.http_listen,
            allow_non_loopback: self.http_allow_non_loopback,
        }
    }

    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }

    /// The Beacon API's limits.
    #[must_use]
    pub fn limits(&self) -> HttpLimits {
        HttpLimits {
            header_read_timeout: Duration::from_millis(self.http_header_read_timeout_ms),
            request_timeout: Duration::from_millis(self.http_request_timeout_ms),
            write_timeout: Duration::from_millis(self.http_write_timeout_ms),
            max_connections: self.http_max_connections,
            allowed_hosts: self.http_allowed_hosts.clone(),
        }
    }
}

/// The Beacon API side, started: the server, the poller and the events subscription.
pub struct Http {
    /// The address the server listens on.
    pub addr: SocketAddr,
    pub server: JoinHandle<()>,
    pub poller: JoinHandle<()>,
    /// [`EventHub::follow`].
    pub events: JoinHandle<()>,
}

/// cl-api's link: the network's hello, on its gRPC service and on every chain.v1 stream.
fn link(chain: &ChainConfig, genesis: Genesis) -> Result<Link, ServiceError> {
    let build = format!("cl-api/{}", env!("CARGO_PKG_VERSION"));
    NetworkHello::new(&build, chain, genesis)
        .map_err(|e| e.to_string())
        .and_then(|hello| Link::network(Arc::new(hello), API_VERSION_V1).map_err(|e| e.to_string()))
        .map_err(|e| ServiceError::Config(format!("the ethswarm.api.v1 link: {e}")))
}

/// Binds the Beacon API, then starts the poller, the events subscription and the server. All
/// three stop once `stop` turns `true` or its sender is gone.
///
/// # Errors
///
/// The address is refused or does not bind, or the config cannot be served.
pub async fn start_http(
    settings: &ApiSettings,
    chain: &ChainConfig,
    genesis: Genesis,
    stop: watch::Receiver<bool>,
) -> Result<Http, ServiceError> {
    let config = Arc::new(ConfigData::new(chain)?);
    let link = link(chain, genesis)?;
    let listener = settings.bind().bind().await?;
    let addr = listener.local_addr().map_err(|source| BindError::Io {
        addr: settings.http_listen,
        source,
    })?;
    if !addr.ip().is_loopback() {
        tracing::warn!(%addr, "the Beacon API listens beyond loopback (http_allow_non_loopback)");
    }
    let node = NodeState::new(SlotClock::new(
        genesis.genesis_time,
        chain.slot_duration_ms(),
    ));
    let connector = PeerCheckedConnector::new(&settings.chain_socket, settings.chain_uid);
    // The authority routes nothing: the connector picks the socket.
    let channel = Endpoint::from_static("http://localhost").connect_with_connector_lazy(connector);
    let poller = tokio::spawn(poll_chain(
        ImportServiceClient::new(channel.clone()),
        node.clone(),
        settings.poll_interval(),
        stopped(stop.clone()),
    ));
    let events = EventHub::new();
    let follower = tokio::spawn(events.clone().follow(
        EventsServiceClient::new(channel),
        link,
        stopped(stop.clone()),
    ));
    let limits = settings.limits();
    let app = router(
        ApiState {
            node,
            config,
            events,
        },
        limits.request_timeout,
    );
    let server = tokio::spawn(crate::server::serve(listener, app, limits, stopped(stop)));
    Ok(Http {
        addr,
        server,
        poller,
        events: follower,
    })
}

/// Resolves once `stop` turns `true` or its sender is gone.
async fn stopped(mut stop: watch::Receiver<bool>) {
    let _ = stop.wait_for(|stop| *stop).await;
}

/// Serves `config` and `settings` until `hooks.shutdown`: the Beacon API first, then the gRPC
/// service through svc-runtime. Once svc-runtime has drained, the HTTP server gets at most the
/// config's drain timeout to finish.
///
/// # Errors
///
/// Anything [`start_http`] or `svc_runtime::run_with` refuses.
pub async fn serve(
    config: Config,
    settings: ApiSettings,
    mut hooks: Hooks,
) -> Result<(), ServiceError> {
    let genesis = config.genesis.ok_or(ServiceError::NoGenesis)?;
    let link = link(&config.chain, genesis)?;
    let (stop, stop_rx) = watch::channel(false);
    let http = start_http(&settings, &config.chain, genesis, stop_rx).await?;
    tracing::info!(
        addr = %http.addr,
        chain_socket = %settings.chain_socket.display(),
        "the Beacon API is listening"
    );
    // SIGTERM stops HTTP too. If svc-runtime returns early, it drops this future and `stop`.
    let termination = std::mem::replace(&mut hooks.shutdown, Box::pin(std::future::pending()));
    hooks.shutdown = Box::pin(async move {
        termination.await;
        let _ = stop.send(true);
    });
    let drain = config.drain_timeout;
    let services = Services::new().add_service(ApiServiceServer::new(ApiStub::new(link)));
    let result = svc_runtime::run_with(config, services, hooks).await;
    match tokio::time::timeout(drain, http.server).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "the Beacon API task failed"),
        Err(_) => tracing::warn!(
            ?drain,
            "the Beacon API did not finish within the drain timeout"
        ),
    }
    http.poller.abort();
    http.events.abort();
    result.map_err(ServiceError::from)
}

/// The process: no argument, the deployed config, the logs, the runtime; the exit code.
#[must_use]
pub fn main() -> ExitCode {
    use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
    use svc_runtime::telemetry::{flush_logs, init_binary_tracing};
    let arguments = std::env::args_os().len().saturating_sub(1);
    let path = svc_runtime::config::config_path(SERVICE);
    let loaded = (arguments == 0).then(|| {
        let euid = ipc::peercred::effective_uid();
        let config = Config::load_root_owned(SERVICE, &path, euid, 0).map_err(|e| e.to_string())?;
        let settings = ApiSettings::load(&config).map_err(|e| e.to_string())?;
        Ok::<_, String>((config, settings))
    });
    let level = match &loaded {
        Some(Ok((config, _))) => config.log_level,
        _ => tracing::level_filters::LevelFilter::INFO,
    };
    if let Err(code) = init_binary_tracing(level) {
        return code;
    }
    let code = match loaded {
        None => {
            let config = path.display();
            tracing::error!(arguments, %config, "cl-api takes no argument: it reads its config only");
            ExitCode::from(EXIT_USAGE)
        }
        Some(Err(e)) => {
            tracing::error!(error = %e, "config refused");
            ExitCode::from(EXIT_CONFIG)
        }
        Some(Ok((config, settings))) => run(config, settings),
    };
    flush_logs(LOG_FLUSH_DEADLINE);
    code
}

/// [`serve`] on a new multi-threaded runtime with systemd's hooks; the exit code.
fn run(config: Config, settings: ApiSettings) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        let hooks = Hooks::systemd().map_err(|e| ServiceError::Config(format!("signals: {e}")))?;
        serve(config, settings, hooks).await
    });
    runtime.shutdown_timeout(Duration::from_secs(5));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "cl-api stopped");
            match e {
                ServiceError::Runtime(e) => svc_runtime::exit_code(&Err(e)),
                ServiceError::Config(_)
                | ServiceError::ConfigData(_)
                | ServiceError::NoGenesis
                | ServiceError::Bind(BindError::NotLoopback(_)) => ExitCode::from(EXIT_CONFIG),
                ServiceError::Bind(BindError::Io { .. }) => ExitCode::FAILURE,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use ethswarm_proto::api::api_service_client::ApiServiceClient;
    use ethswarm_proto::api::GetHealthRequest;
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::server::DEFAULT_HTTP_ADDR;
    use crate::testing::{self, sync_status, FakeChain, SseClient, WITHIN};

    const HEALTH: &str = "/ethswarm.api.v1.ApiService/GetHealth";

    fn toml(root: &Path, api: &str) -> String {
        format!(
            "network = \"sepolia\"\nmetrics_port = 9105\ndrain_timeout_ms = 2000\n\
             [socket]\nroot = \"{}\"\ngroup = {}\n\
             [callers]\nsupervisor = {}\n\
             [methods]\n\"{HEALTH}\" = [\"supervisor\"]\n{api}",
            root.display(),
            ipc::peercred::effective_gid(),
            ipc::peercred::effective_uid(),
        )
    }

    fn config(root: &Path, api: &str) -> Config {
        Config::from_toml(SERVICE, &toml(root, api), Path::new("cl-api.toml"))
            .unwrap()
            .with_ephemeral_metrics_port()
    }

    #[test]
    fn settings_from_the_api_table() {
        let root = Path::new("/run/ethswarm");
        let settings = ApiSettings::load(&config(root, "[api]\nchain_uid = 990\n")).unwrap();
        assert_eq!(
            settings,
            ApiSettings {
                http_listen: DEFAULT_HTTP_ADDR,
                http_allow_non_loopback: false,
                chain_socket: DEFAULT_CHAIN_SOCKET.into(),
                chain_uid: 990,
                poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
                http_header_read_timeout_ms: 5000,
                http_request_timeout_ms: 30000,
                http_write_timeout_ms: 30000,
                http_max_connections: 64,
                http_allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()],
            }
        );
        assert_eq!(settings.bind(), HttpBind::default());
        assert_eq!(settings.poll_interval(), Duration::from_secs(1));
        assert_eq!(settings.limits(), HttpLimits::default());
        assert_eq!(
            HttpLimits::default(),
            HttpLimits {
                header_read_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(30),
                write_timeout: Duration::from_secs(30),
                max_connections: 64,
                allowed_hosts: vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()],
            }
        );
        let full = "[api]\nhttp_listen = \"0.0.0.0:5052\"\nhttp_allow_non_loopback = true\n\
                    chain_socket = \"/run/x/chain.sock\"\nchain_uid = 7\npoll_interval_ms = 250\n\
                    http_header_read_timeout_ms = 100\nhttp_request_timeout_ms = 200\n\
                    http_write_timeout_ms = 300\nhttp_max_connections = 3\n\
                    http_allowed_hosts = [\"beacon.internal\", \"10.0.0.1\", \"[fd00::1]\"]\n";
        let settings = ApiSettings::load(&config(root, full)).unwrap();
        assert_eq!(
            settings.bind(),
            HttpBind {
                addr: "0.0.0.0:5052".parse().unwrap(),
                allow_non_loopback: true,
            }
        );
        assert_eq!(settings.chain_socket, Path::new("/run/x/chain.sock"));
        assert_eq!(settings.poll_interval(), Duration::from_millis(250));
        assert_eq!(
            settings.limits(),
            HttpLimits {
                header_read_timeout: Duration::from_millis(100),
                request_timeout: Duration::from_millis(200),
                write_timeout: Duration::from_millis(300),
                max_connections: 3,
                allowed_hosts: vec![
                    "beacon.internal".into(),
                    "10.0.0.1".into(),
                    "[fd00::1]".into()
                ],
            }
        );
        // Refused: no table or no chain_uid, an unknown key, a zero interval, a relative socket,
        // a zero timeout or cap, no allowed host, or an allowed host that is not a bare host.
        let too_many = format!(
            "[api]\nchain_uid = 1\nhttp_max_connections = {}\n",
            tokio::sync::Semaphore::MAX_PERMITS + 1
        );
        for bad in [
            "",
            "[api]\n",
            "[api]\nchain_uid = 1\nhttp_listn = \"127.0.0.1:1\"\n",
            "[api]\nchain_uid = 1\npoll_interval_ms = 0\n",
            "[api]\nchain_uid = 1\nchain_socket = \"run/chain.sock\"\n",
            "[api]\nchain_uid = 1\nhttp_listen = \"localhost:5052\"\n",
            "[api]\nchain_uid = 1\nhttp_header_read_timeout_ms = 0\n",
            "[api]\nchain_uid = 1\nhttp_request_timeout_ms = 0\n",
            "[api]\nchain_uid = 1\nhttp_write_timeout_ms = 0\n",
            "[api]\nchain_uid = 1\nhttp_max_connections = 0\n",
            &too_many,
            "[api]\nchain_uid = 1\nhttp_allowed_hosts = []\n",
            "[api]\nchain_uid = 1\nhttp_allowed_hosts = [\"localhost:5052\"]\n",
            "[api]\nchain_uid = 1\nhttp_allowed_hosts = [\"user@localhost\"]\n",
            "[api]\nchain_uid = 1\nhttp_allowed_hosts = [\"\"]\n",
            "[api]\nchain_uid = 1\nhttp_allowed_hosts = [\"::1\"]\n",
        ] {
            let err = ApiSettings::load(&config(root, bad)).unwrap_err();
            assert!(matches!(err, ServiceError::Config(_)), "{bad:?}: {err}");
        }
    }

    /// `GET path` over TCP: the status and the body; `None` if nothing listens yet.
    async fn try_get(addr: SocketAddr, path: &str) -> Option<(u16, Vec<u8>)> {
        let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        let code = text.split(' ').nth(1).unwrap().parse().unwrap();
        let body = text.split_once("\r\n\r\n").unwrap().1.as_bytes().to_vec();
        Some((code, body))
    }

    async fn http_get(addr: SocketAddr, path: &str) -> (u16, Vec<u8>) {
        try_get(addr, path).await.expect("the Beacon API listens")
    }

    async fn wait_for_health(addr: SocketAddr, code: u16, within: Duration) -> Duration {
        let start = Instant::now();
        loop {
            if try_get(addr, "/eth/v1/node/health").await.map(|r| r.0) == Some(code) {
                return start.elapsed();
            }
            assert!(start.elapsed() < within, "health never answered {code}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    struct Recorded(Mutex<Vec<String>>);

    impl svc_runtime::notify::Notifier for Recorded {
        fn notify(&self, state: &str) -> std::io::Result<()> {
            self.0.lock().unwrap().push(state.to_owned());
            Ok(())
        }
    }

    /// A free loopback port (bound, then released).
    fn free_port() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serves_http_and_grpc_and_polls_chain() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = std::fs::canonicalize(tmp.path()).unwrap();
        let root = tmp_path.join("run");
        std::fs::create_dir(&root).unwrap();
        for dir in [&tmp_path, &root] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // The fake cl-chain, at the wall-clock slot of a network that started 1000 slots ago.
        let chain_socket = tmp_path.join("cl-chain.sock");
        let fake = FakeChain::new(sync_status(1000, false, false));
        let running = fake.serve_uds(&chain_socket);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let http_addr = free_port();
        let api = format!(
            "[api]\nhttp_listen = \"{http_addr}\"\nchain_socket = \"{}\"\nchain_uid = {}\n\
             poll_interval_ms = 50\n",
            chain_socket.display(),
            ipc::peercred::effective_uid()
        );
        let mut config = config(&root, &api);
        config.genesis = Some(Genesis {
            genesis_time: now - 1000 * 12,
            genesis_validators_root: [0; 32],
        });
        let settings = ApiSettings::load(&config).unwrap();
        let socket = config.socket.socket_path();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let notes = Arc::new(Recorded(Mutex::new(Vec::new())));
        let mut hooks = Hooks::systemd().unwrap();
        hooks.notifier = notes.clone();
        hooks.shutdown = Box::pin(async {
            let _ = stopped.await;
        });
        let service = tokio::spawn(serve(config, settings, hooks));

        // HTTP: the poller reaches cl-chain, so health turns 200.
        wait_for_health(http_addr, 200, Duration::from_secs(10)).await;
        let (code, body) = http_get(http_addr, "/eth/v1/node/syncing").await;
        assert_eq!(code, 200);
        let data = serde_json::from_slice::<Value>(&body).unwrap()["data"].clone();
        assert_eq!(data["head_slot"], "1000");
        assert_eq!(data["is_syncing"], false);
        let (code, body) = http_get(http_addr, "/eth/v1/config/deposit_contract").await;
        assert_eq!(code, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["data"]["chain_id"],
            "11155111"
        );

        // gRPC: the service socket answers, behind the ACL (GetHealth is still a stub).
        let channel = ipc::uds::connect_path(&socket, ipc::peercred::effective_uid())
            .await
            .unwrap();
        let err = ApiServiceClient::new(channel)
            .get_health(GetHealthRequest {})
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented, "{err}");
        assert!(notes
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.starts_with("READY=1")));

        // cl-chain stops: health turns 206 within about one poll interval.
        running.stop().await;
        let took = wait_for_health(http_addr, 206, Duration::from_secs(10)).await;
        assert!(took < Duration::from_secs(2), "took {took:?}");
        let (_, body) = http_get(http_addr, "/eth/v1/node/syncing").await;
        let data = serde_json::from_slice::<Value>(&body).unwrap()["data"].clone();
        assert_eq!(data["is_syncing"], true);
        assert_eq!(data["head_slot"], "1000");

        // SIGTERM: both sides stop.
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), service)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(tokio::net::TcpStream::connect(http_addr).await.is_err());
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn a_refused_bind_starts_nothing() {
        let root = Path::new("/run/ethswarm");
        let config = config(root, "[api]\nchain_uid = 1\nhttp_listen = \"0.0.0.0:0\"\n");
        let settings = ApiSettings::load(&config).unwrap();
        let genesis = Genesis {
            genesis_time: 0,
            genesis_validators_root: [0; 32],
        };
        let (_stop, stopped) = watch::channel(false);
        let err = start_http(&settings, &config.chain, genesis, stopped)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(err, ServiceError::Bind(BindError::NotLoopback(_))),
            "{err}"
        );
        // No genesis: the wall-clock slot is unknown, so nothing starts either.
        let mut config = config;
        config.genesis = None;
        let settings = ApiSettings {
            http_listen: "127.0.0.1:0".parse().unwrap(),
            ..settings
        };
        let err = serve(config, settings, Hooks::systemd().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, ServiceError::NoGenesis), "{err}");
    }

    const SUBSCRIBE: &str = "/ethswarm.chain.v1.EventsService/Subscribe";
    const CHAIN_STATUS: &str = "/ethswarm.chain.v1.ImportService/GetChainStatus";

    /// cl-chain's `routes` on `path`, behind a cl-chain method ACL that gives `methods` to cl-api
    /// (this process's UID); the count of calls it denied, and the server's stop.
    fn serve_chain(
        path: &Path,
        routes: tonic::service::Routes,
        methods: &[&str],
    ) -> (
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let uid = ipc::peercred::effective_uid();
        let mut acl = format!("[callers]\ncl-api = {uid}\n\n[methods]\n");
        for method in methods {
            acl.push_str(&format!("\"{method}\" = [\"cl-api\"]\n"));
        }
        let acl =
            ipc::acl::MethodAcl::from_toml(&acl, Path::new("cl-chain.toml"), "cl-chain").unwrap();
        let denied = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&denied);
        let layer = ipc::acl::AclLayer::new(Arc::new(acl)).on_denied(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
        });
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(
            tonic::transport::Server::builder()
                .layer(layer)
                .add_routes(routes)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::UnixListenerStream::new(listener),
                    async {
                        let _ = stopped.await;
                    },
                ),
        );
        (denied, stop)
    }

    /// The Beacon API on a free loopback port, reaching cl-chain on `chain_socket`.
    async fn api_for(chain_socket: &Path, stop: watch::Receiver<bool>) -> Http {
        let api = format!(
            "[api]\nhttp_listen = \"127.0.0.1:0\"\nchain_socket = \"{}\"\nchain_uid = {}\n",
            chain_socket.display(),
            ipc::peercred::effective_uid()
        );
        let config = config(Path::new("/run/ethswarm"), &api);
        let settings = ApiSettings::load(&config).unwrap();
        start_http(&settings, &config.chain, testing::genesis(), stop)
            .await
            .unwrap()
    }

    /// A stream on `query`'s topics, once cl-api has subscribed to cl-chain (503 until then).
    async fn live_client(addr: SocketAddr, query: &str) -> SseClient {
        let start = Instant::now();
        loop {
            let client = SseClient::connect(addr, &format!("/eth/v1/events?{query}")).await;
            if client.status == 200 {
                return client;
            }
            assert_eq!(client.status, 503);
            assert!(start.elapsed() < WITHIN, "/eth/v1/events was never served");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    type Root = consensus_types::primitives::Root;
    type Slot = consensus_types::primitives::Slot;

    /// A block tree of `(block, slot, parent)`.
    struct Tree(Vec<(u8, Slot, u8)>);

    fn root(n: u8) -> Root {
        Root::repeat_byte(n)
    }

    fn hex(n: u8) -> String {
        format!("0x{}", format!("{n:02x}").repeat(32))
    }

    impl cl_chain::events::BlockTree for Tree {
        fn parent(&self, block: &Root) -> Option<(Root, Slot)> {
            let (_, _, parent) = self.0.iter().find(|(n, _, _)| root(*n) == *block)?;
            let (_, slot, _) = self.0.iter().find(|(n, _, _)| n == parent)?;
            Some((root(*parent), *slot))
        }
    }

    /// End to end over the Unix socket: cl-chain's own `EventsService` (its routes, behind a
    /// method ACL that gives cl-api [`CHAIN_METHODS`]) publishes a head, a Gloas block, the head
    /// turning full, a finalized checkpoint and a re-org; one `/eth/v1/events` client on every
    /// topic gets them as the beacon APIs write them. Shutdown ends the stream.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chain_events_reach_sse_over_uds() {
        use cl_chain::events::{Bid, Finalized, Head, ImportedBlock};
        use cl_chain::persist::durable::PayloadStatus;
        let tmp = tempfile::tempdir().unwrap();
        let chain_socket = tmp.path().join("cl-chain.sock");
        let chain = cl_chain::ChainStub::new(testing::link());
        let events = chain.events().clone();
        let (denied, _chain) = serve_chain(&chain_socket, chain.routes(), &CHAIN_METHODS);
        let (stop, stopped) = watch::channel(false);
        let http = api_for(&chain_socket, stopped).await;
        let all = "topics=head,head_v2,block,finalized_checkpoint,chain_reorg";
        let mut client = live_client(http.addr, all).await;

        // Sepolia's Gloas epoch; blocks 1 (slot s) and 2 (slot s + 1) both build on block 9.
        let epoch = 353_024;
        let s = epoch * 32 + 5;
        let tree = Tree(vec![(9, s - 1, 0), (1, s, 9), (2, s + 1, 9)]);
        let head = |n: u8, slot, payload_status| Head {
            slot,
            block: root(n),
            state: root(n | 0x80),
            payload_status,
            previous_duty_dependent_root: root(0x71),
            current_duty_dependent_root: root(0x72),
            execution_optimistic: false,
        };
        events.head(head(1, s, PayloadStatus::Empty), &tree);
        events.block(&ImportedBlock {
            slot: s,
            block: root(1),
            execution_optimistic: false,
            bid: Some(Bid {
                builder_index: 42,
                block_hash: root(0xab),
            }),
        });
        events.head(head(1, s, PayloadStatus::Full), &tree);
        events.finalized(&Finalized {
            epoch,
            block: root(9),
            state: root(0x89),
            execution_optimistic: false,
        });
        events.head(head(2, s + 1, PayloadStatus::Empty), &tree);

        let got = client.take(9).await;
        let names: Vec<&str> = got.iter().map(|e| e.event.as_str()).collect();
        assert_eq!(
            names,
            [
                "head",
                "head_v2",
                "block",
                "head",
                "head_v2",
                "finalized_checkpoint",
                "chain_reorg",
                "head",
                "head_v2"
            ]
        );
        assert_eq!(
            got[0].json(),
            serde_json::json!({
                "slot": s.to_string(),
                "block": hex(1),
                "state": hex(0x81),
                "epoch_transition": false,
                "previous_duty_dependent_root": hex(0x71),
                "current_duty_dependent_root": hex(0x72),
                "execution_optimistic": false,
            })
        );
        assert_eq!(
            got[1].json(),
            serde_json::json!({
                "version": "gloas",
                "data": {
                    "slot": s.to_string(),
                    "block": hex(1),
                    "state": hex(0x81),
                    "payload_status": "empty",
                    "epoch_transition": false,
                    "current_epoch_dependent_root": hex(0x71),
                    "next_epoch_dependent_root": hex(0x72),
                    "execution_optimistic": false,
                },
            })
        );
        assert_eq!(
            got[2].json(),
            serde_json::json!({
                "slot": s.to_string(),
                "block": hex(1),
                "execution_optimistic": false,
                "builder_index": "42",
                "block_hash": hex(0xab),
            })
        );
        assert_eq!(got[3].json()["block"], hex(1));
        assert_eq!(got[4].json()["data"]["payload_status"], "full");
        assert_eq!(
            got[5].json(),
            serde_json::json!({
                "block": hex(9),
                "state": hex(0x89),
                "epoch": epoch.to_string(),
                "execution_optimistic": false,
            })
        );
        assert_eq!(
            got[6].json(),
            serde_json::json!({
                "slot": (s + 1).to_string(),
                "depth": "1",
                "old_head_block": hex(1),
                "new_head_block": hex(2),
                "old_head_state": hex(0x81),
                "new_head_state": hex(0x82),
                "epoch": epoch.to_string(),
                "execution_optimistic": false,
            })
        );
        assert_eq!(got[7].json()["block"], hex(2));
        assert_eq!(got[8].json()["data"]["block"], hex(2));
        assert_eq!(denied.load(std::sync::atomic::Ordering::SeqCst), 0);

        // Shutdown: the stream ends and the server returns.
        stop.send_replace(true);
        assert_eq!(client.next().await, None);
        tokio::time::timeout(WITHIN, http.server)
            .await
            .expect("the server returns")
            .unwrap();
    }

    /// cl-chain's ACL must give `EventsService/Subscribe` to cl-api ([`CHAIN_METHODS`]):
    /// without it, the subscription is refused and `/eth/v1/events` answers 503.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_need_the_subscribe_acl_entry() {
        assert!(CHAIN_METHODS.contains(&SUBSCRIBE), "{CHAIN_METHODS:?}");
        assert!(CHAIN_METHODS.contains(&CHAIN_STATUS), "{CHAIN_METHODS:?}");
        let tmp = tempfile::tempdir().unwrap();
        let chain_socket = tmp.path().join("cl-chain.sock");
        let chain = cl_chain::ChainStub::new(testing::link());
        let (denied, _chain) = serve_chain(&chain_socket, chain.routes(), &[CHAIN_STATUS]);
        let (_stop, stopped) = watch::channel(false);
        let http = api_for(&chain_socket, stopped).await;
        let start = Instant::now();
        while denied.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(start.elapsed() < WITHIN, "Subscribe was never refused");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let client = SseClient::connect(http.addr, "/eth/v1/events?topics=head").await;
        assert_eq!(client.status, 503);
    }
}
