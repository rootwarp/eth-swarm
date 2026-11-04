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
//!   `/ethswarm.chain.v1.ImportService/GetChainStatus` to cl-api.
//! - **Shutdown.** At SIGTERM, the gRPC socket drains (svc-runtime), and the HTTP server stops
//!   accepting and lets its open requests finish.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ethswarm_proto::api::api_service_server::ApiServiceServer;
use ethswarm_proto::chain::import_service_client::ImportServiceClient;
use ipc::hello::{NetworkHello, API_VERSION_V1};
use ipc::uds::PeerCheckedConnector;
use network_config::{ChainConfig, Genesis};
use serde::Deserialize;
use svc_runtime::{Config, Hooks, Services};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tonic::transport::Endpoint;

use crate::node_state::{poll_chain, NodeState, SlotClock};
use crate::routes::config::{ConfigData, ConfigDataError};
use crate::server::{is_bare_host, router, ApiState, BindError, HttpBind, HttpLimits};
use crate::ApiStub;

/// The exit code of a config that does not load.
pub const EXIT_CONFIG: u8 = 2;

/// The exit code of a command line with arguments.
pub const EXIT_USAGE: u8 = 64;

/// The service name: its config file, socket and ACL.
pub const SERVICE: &str = "cl-api";

/// cl-chain's socket unless `chain_socket` says otherwise.
pub const DEFAULT_CHAIN_SOCKET: &str = "/run/ethswarm/cl-chain/cl-chain.sock";

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

/// The Beacon API side, started: the server and the poller.
pub struct Http {
    /// The address the server listens on.
    pub addr: SocketAddr,
    pub server: JoinHandle<()>,
    pub poller: JoinHandle<()>,
}

/// Binds the Beacon API, then starts the poller and the server. Both stop once `stop` turns
/// `true` or its sender is gone.
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
        ImportServiceClient::new(channel),
        node.clone(),
        settings.poll_interval(),
        stopped(stop.clone()),
    ));
    let limits = settings.limits();
    let app = router(ApiState { node, config }, limits.request_timeout);
    let server = tokio::spawn(crate::server::serve(listener, app, limits, stopped(stop)));
    Ok(Http {
        addr,
        server,
        poller,
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
    let build = format!("cl-api/{}", env!("CARGO_PKG_VERSION"));
    let link = NetworkHello::new(&build, &config.chain, genesis)
        .map_err(|e| e.to_string())
        .and_then(|hello| {
            ipc::Link::network(Arc::new(hello), API_VERSION_V1).map_err(|e| e.to_string())
        })
        .map_err(|e| ServiceError::Config(format!("the ethswarm.api.v1 link: {e}")))?;
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
    use crate::testing::{sync_status, FakeChain};

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
}
