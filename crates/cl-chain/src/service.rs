//! The `cl-chain` process in probe mode: what `ops/probe/ethswarm-chain.service` runs.
//!
//! The unit passes no argument. The binary reads `/etc/ethswarm/cl-chain.toml` ([`CONFIG_PATH`])
//! through the owner walk ([`svc_runtime::Config::load_root_owned`]: root owns the file and its
//! path, and the service user cannot change either), then serves [`crate::probe::service`] on
//! its socket through [`svc_runtime::run_with`] until SIGTERM:
//!
//! ```toml
//! network_dir = "/etc/ethswarm/network"   # or: network = "sepolia"
//! metrics_port = 9102
//!
//! [socket]
//! group = 990                             # GID of ethswarm-chain: cl-p2p is a member
//!
//! [callers]
//! cl-p2p = 991                            # UID of ethswarm-p2p
//!
//! [methods]                               # exactly these four, to cl-p2p only
//! "/ethswarm.chain.v1.ReqRespService/GetStatus" = ["cl-p2p"]
//! "/ethswarm.chain.v1.ReqRespService/DataColumnsByRange" = ["cl-p2p"]
//! "/ethswarm.chain.v1.ReqRespService/DataColumnsByRoot" = ["cl-p2p"]
//! "/ethswarm.chain.v1.GossipService/WatchSubscriptions" = ["cl-p2p"]
//!
//! [chain]
//! reference_api_url = "http://127.0.0.1:5052"   # the reference node's beacon API
//! node_id = "0x…"                               # our discv5 node ID: 32 bytes of hex
//! verify_socket = "/run/ethswarm/cl-verify/cl-verify.sock"
//! verify_uid = 993                              # UID of cl-verify's user
//! columns_dir = "/var/lib/ethswarm-chain/columns"   # optional, this default
//! verify_timeout_ms = 5000                      # optional, this default
//! verify_wait_ms = 30000                        # optional, this default: cl-verify's start
//! ```
//!
//! - **The ACL** must be exactly [`chain_acl`] of the `cl-p2p` caller: a config that gives a
//!   method to another caller, or lists another method, is refused.
//! - **`reference_api_url`** is plain `http://` with no path, so it must reach the reference node
//!   on this host or a private network: `localhost`, a loopback address, or a private IPv4
//!   (10/8, 172.16/12, 192.168/16) or IPv6 unique-local (fc00::/7) address. Plain HTTP on a
//!   shared network has no integrity: anyone on it can change what cl-chain gets. So the
//!   preferred setup is an SSH tunnel to a loopback port; a private address is for a network
//!   that only the probe and the reference share (the Kurtosis enclave network).
//! - **`node_id`** is public (the discv5 node ID of the probe's key, which cl-discv5 logs).
//!   cl-chain never gets the key itself. The custody columns follow it.
//!
//! Exit codes, which `RestartPreventExitStatus=1 2 64` reads:
//!
//! | Code | Meaning | Restarted |
//! |---|---|---|
//! | 0 | stopped on SIGTERM or SIGINT, in-flight calls drained (also during the wait for cl-verify) | no (a stop) |
//! | 1 ([`EXIT_FAILED`]) | a start that a restart cannot fix: the store, the socket's bind, an ACL of unserved methods, a cl-verify directory open to others (or still of another user at the end of the wait), a cl-verify server of another user | no |
//! | 2 ([`EXIT_CONFIG`]) | the config was refused, or the store holds the custody of another `node_id` (or of an unrecorded one) | no |
//! | 64 ([`EXIT_USAGE`]) | a command-line argument: the unit passes none | no |
//! | 69 ([`EXIT_UNAVAILABLE`]) | cl-verify's directory or socket is not there within `verify_wait_ms`, or the clock is before genesis | yes |
//! | 70 ([`EXIT_SOFTWARE`]) | a fault of the run that a restart can fix: the server task, a drain past its deadline, `/metrics`, the service manager, a store that does not close within 10 s | yes |
//! | 71 | the log writer could not start (`svc_runtime::telemetry::EXIT_NO_LOG_WRITER`) | yes |

use crate::probe::service::{
    chain_acl, chain_link, connect_verify, error_chain, open_store_dir, system_ms, verify_client,
    verify_dir_state, ProbeNetwork, ProbePlan, ProbeService, VerifyDirError, CHAIN_METHODS,
    CHAIN_SERVICE, DEFAULT_VERIFY_TIMEOUT, P2P_CALLER, VERIFY_SOCKET_WAIT,
};
use crate::probe::BeaconApi;
use crate::verify::client::KzgVerifier;
use consensus_types::primitives::U256;
use consensus_types::{EthSpec, Mainnet, Minimal};
use ipc::hello::Preset;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use svc_runtime::{Config, Hooks, Services};

/// The config file of the deployed binary.
pub const CONFIG_PATH: &str = "/etc/ethswarm/cl-chain.toml";

/// Where the column store lives unless `columns_dir` says otherwise: under the unit's
/// `StateDirectory=ethswarm-chain`.
pub const DEFAULT_COLUMNS_DIR: &str = "/var/lib/ethswarm-chain/columns";

/// The environment variable that names the config of the test binary `cl-chain-test`. The
/// `cl-chain` binary never reads it.
pub const TEST_CONFIG_ENV: &str = "CL_CHAIN_TEST_CONFIG";

/// The build string of our hellos.
pub const BUILD: &str = concat!("cl-chain/", env!("CARGO_PKG_VERSION"));

/// A start or a run that a restart cannot fix.
pub const EXIT_FAILED: u8 = 1;
/// The config was refused.
pub const EXIT_CONFIG: u8 = 2;
/// A command-line argument (`EX_USAGE`).
pub const EXIT_USAGE: u8 = 64;
/// A peer that the start needs is not there yet (`EX_UNAVAILABLE`): restarted.
pub const EXIT_UNAVAILABLE: u8 = 69;
/// A fault of the run that a restart can fix (`EX_SOFTWARE`): restarted.
pub const EXIT_SOFTWARE: u8 = 70;

/// How long the store's writer gets to finish after the drain, so that the stop ends within
/// the unit's stop timeout.
pub const STORE_CLOSE: Duration = Duration::from_secs(10);

/// The longest `verify_timeout_ms`.
pub const MAX_VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

/// The longest `verify_wait_ms`: well within the unit's restart delay.
pub const MAX_VERIFY_WAIT: Duration = Duration::from_secs(600);

/// The `[chain]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainTable {
    reference_api_url: String,
    node_id: String,
    verify_socket: PathBuf,
    verify_uid: u32,
    columns_dir: Option<PathBuf>,
    verify_timeout_ms: Option<u64>,
    verify_wait_ms: Option<u64>,
}

/// What cl-chain runs with, read from its config and checked.
#[derive(Debug)]
pub struct ChainSettings {
    /// The network.
    pub network: ProbeNetwork,
    /// The reference node's beacon API.
    pub reference: BeaconApi,
    /// Our node ID.
    pub node_id: U256,
    /// cl-verify's socket.
    pub verify_socket: PathBuf,
    /// The UID cl-verify runs as.
    pub verify_uid: u32,
    /// The column store's directory.
    pub columns_dir: PathBuf,
    /// How long one KZG check may take.
    pub verify_timeout: Duration,
    /// How long the start waits for cl-verify to accept.
    pub verify_wait: Duration,
    /// cl-p2p's UID, the one caller.
    pub caller_uid: u32,
}

/// Why the config was refused.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// The file did not load.
    #[error("{0}")]
    Config(#[from] svc_runtime::config::ConfigError),
    /// The network has no pinned genesis.
    #[error("the network {0} has no pinned genesis: give network_dir")]
    NoGenesis(String),
    /// The network gives no network hello.
    #[error("the network: {0}")]
    Network(String),
    /// The ACL is not exactly cl-p2p on the four methods.
    #[error(
        "the method ACL must give exactly {methods:?} to [callers] {P2P_CALLER} and to nobody \
         else: {why}"
    )]
    Acl {
        /// The methods.
        methods: [&'static str; 4],
        /// What is wrong.
        why: String,
    },
    /// A key of `[chain]` was refused.
    #[error("[chain] {key}: {why}")]
    Key {
        /// The key.
        key: &'static str,
        /// Why, never the value.
        why: String,
    },
}

/// The settings of `config` (see the module docs).
///
/// # Errors
///
/// The first [`SettingsError`] found.
pub fn settings(config: &Config) -> Result<ChainSettings, SettingsError> {
    let table: ChainTable = config.section()?;
    let genesis = config
        .genesis
        .ok_or_else(|| SettingsError::NoGenesis(config.network.name()))?;
    let network = ProbeNetwork::new(BUILD, config.chain.clone(), genesis)
        .map_err(|e| SettingsError::Network(e.to_string()))?;
    let caller_uid = caller(config)?;
    let key = |key: &'static str, why: &str| SettingsError::Key {
        key,
        why: why.to_owned(),
    };
    let reference =
        reference_api(&table.reference_api_url).map_err(|why| key("reference_api_url", &why))?;
    let node_id = node_id(&table.node_id).map_err(|why| key("node_id", why))?;
    if !table.verify_socket.is_absolute() {
        return Err(key("verify_socket", "must be an absolute path"));
    }
    let columns_dir = table
        .columns_dir
        .unwrap_or_else(|| PathBuf::from(DEFAULT_COLUMNS_DIR));
    if !columns_dir.is_absolute() {
        return Err(key("columns_dir", "must be an absolute path"));
    }
    let verify_timeout = match table.verify_timeout_ms {
        None => DEFAULT_VERIFY_TIMEOUT,
        Some(ms) if ms > 0 && u128::from(ms) <= MAX_VERIFY_TIMEOUT.as_millis() => {
            Duration::from_millis(ms)
        }
        Some(_) => return Err(key("verify_timeout_ms", "want 1 to 60000")),
    };
    let verify_wait = match table.verify_wait_ms {
        None => VERIFY_SOCKET_WAIT,
        Some(ms) if ms > 0 && u128::from(ms) <= MAX_VERIFY_WAIT.as_millis() => {
            Duration::from_millis(ms)
        }
        Some(_) => return Err(key("verify_wait_ms", "want 1 to 600000")),
    };
    Ok(ChainSettings {
        network,
        reference,
        node_id,
        verify_socket: table.verify_socket,
        verify_uid: table.verify_uid,
        columns_dir,
        verify_timeout,
        verify_wait,
        caller_uid,
    })
}

/// The UID of `cl-p2p` in `[callers]`, once the ACL is exactly [`chain_acl`] of it.
fn caller(config: &Config) -> Result<u32, SettingsError> {
    let refused = |why: String| SettingsError::Acl {
        methods: CHAIN_METHODS,
        why,
    };
    let uid = *config
        .callers
        .get(P2P_CALLER)
        .ok_or_else(|| refused(format!("[callers] has no {P2P_CALLER}")))?;
    let want = chain_acl(uid).map_err(refused)?;
    if config.acl != want {
        let listed: Vec<&str> = config.acl.methods().collect();
        return Err(refused(format!("the config lists {listed:?}")));
    }
    Ok(uid)
}

/// The reference API at `url`, if it is on this host or a private network.
fn reference_api(url: &str) -> Result<BeaconApi, String> {
    let uri: http::Uri = url.parse().map_err(|_| "not a URL".to_owned())?;
    let host = uri.host().unwrap_or_default();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let local = host == "localhost"
        || host.parse::<IpAddr>().is_ok_and(|ip| match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
            IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        });
    if !local {
        return Err(
            "plain http:// reaches only localhost, a loopback or a private address".to_owned(),
        );
    }
    BeaconApi::new(url, crate::probe::DEFAULT_API_TIMEOUT).map_err(|e| e.to_string())
}

/// A node ID: `0x` and 64 hex digits, big-endian.
fn node_id(text: &str) -> Result<U256, &'static str> {
    let hex = text.strip_prefix("0x").ok_or("want 0x and 64 hex digits")?;
    let bytes: [u8; 32] = hex::decode(hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("want 0x and 64 hex digits")?;
    Ok(U256::from_be_bytes(bytes))
}

/// Why [`serve`] stopped other than cleanly.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// cl-verify did not accept, or the clock is before genesis: a restart can fix it.
    #[error("{0}")]
    Unavailable(String),
    /// The config does not fit the host: the store is another node ID's.
    #[error("{0}")]
    Config(String),
    /// The start failed in a way that a restart cannot fix.
    #[error("{0}")]
    Failed(String),
    /// A fault of the run that a restart can fix: the store did not close in time.
    #[error("{0}")]
    Software(String),
    /// The runtime stopped on an error.
    #[error("{0}")]
    Runtime(#[from] svc_runtime::RuntimeError),
}

impl ServeError {
    /// The exit code (see the module docs).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        use svc_runtime::RuntimeError;
        match self {
            Self::Unavailable(_) => EXIT_UNAVAILABLE,
            Self::Config(_) => EXIT_CONFIG,
            Self::Failed(_) => EXIT_FAILED,
            Self::Software(_) => EXIT_SOFTWARE,
            // The socket and the ACL do not fix themselves; every other fault of the run (the
            // server task, a drain past its deadline, /metrics, the manager) may.
            Self::Runtime(RuntimeError::Bind(_) | RuntimeError::UnservedMethods(_)) => EXIT_FAILED,
            Self::Runtime(RuntimeError::LogWriter(_)) => svc_runtime::telemetry::EXIT_NO_LOG_WRITER,
            Self::Runtime(_) => EXIT_SOFTWARE,
        }
    }
}

/// Why cl-verify at `socket` did not accept: a server of another user is a refusal that a
/// restart cannot fix ([`ServeError::Failed`]); anything else is [`ServeError::Unavailable`].
#[must_use]
pub fn verify_unreachable(socket: &Path, err: &tonic::transport::Error) -> ServeError {
    let shown = format!("cl-verify at {}: {}", socket.display(), error_chain(err));
    if ipc::uds::peer_refusal(err).is_some() {
        ServeError::Failed(format!("{shown}: the server is not cl-verify's user"))
    } else {
        ServeError::Unavailable(shown)
    }
}

/// Closes the store `value` (drops it on a blocking thread), waiting `limit` at most. `pending`
/// is how many columns were still on their way into it.
///
/// # Errors
///
/// [`ServeError::Software`] (70) if it did not close in time: the columns still on their way
/// are lost, and the drop goes on alone.
pub async fn close_within<T: Send + 'static>(
    value: T,
    pending: usize,
    limit: Duration,
) -> Result<(), ServeError> {
    if drop_within(value, limit).await {
        return Ok(());
    }
    tracing::warn!(
        limit_ms = limit.as_millis() as u64,
        pending,
        "the column store did not close in time; stopping without it"
    );
    Err(ServeError::Software(format!(
        "the column store did not close within {limit:?}: {pending} columns were still on their \
         way into it and are lost"
    )))
}

/// Drops `value` on a blocking thread, waiting `limit` at most; whether it was dropped in time.
/// A drop that takes longer goes on alone.
pub async fn drop_within<T: Send + 'static>(value: T, limit: Duration) -> bool {
    let dropping = tokio::task::spawn_blocking(move || drop(value));
    matches!(tokio::time::timeout(limit, dropping).await, Ok(Ok(())))
}

/// The pause between two looks for cl-verify's directory.
const DIR_RETRY: Duration = Duration::from_millis(200);

/// Waits until the directory of cl-verify's socket is there and closed to other users, until
/// `deadline` ([`verify_dir_state`]). A directory that is not there yet (a typed `NotFound`: after
/// a reboot, or after systemd removed cl-verify's runtime directory at its stop) is waited for,
/// and at the end of the wait is [`ServeError::Unavailable`]. A directory that another user
/// still owns (systemd makes it, then gives it to its user) is waited for too, and at the end of
/// the wait is [`ServeError::Failed`]. A directory, or one above it, that others can write is
/// [`ServeError::Failed`] at once.
async fn wait_for_verify_dir(
    socket: &Path,
    uid: u32,
    deadline: tokio::time::Instant,
) -> Result<(), ServeError> {
    let mut told = false;
    loop {
        let wait = match verify_dir_state(socket, uid) {
            Ok(()) => return Ok(()),
            Err(VerifyDirError::Refused(e)) => return Err(ServeError::Failed(e)),
            Err(wait) => wait,
        };
        if tokio::time::Instant::now() + DIR_RETRY > deadline {
            return Err(match wait {
                VerifyDirError::Missing(e) => ServeError::Unavailable(e),
                VerifyDirError::Owner(e) | VerifyDirError::Refused(e) => ServeError::Failed(e),
            });
        }
        if !told {
            tracing::info!(
                socket = %socket.display(),
                why = %wait,
                "cl-verify's directory is not ready yet; waiting for it"
            );
            told = true;
        }
        tokio::time::sleep(DIR_RETRY).await;
    }
}

/// Opens the probe service of `settings` with `kzg`, serves it as `config` says until
/// `hooks.shutdown`, ends its `WatchSubscriptions` streams and drains. Its metrics go to
/// `hooks.unprefixed`. Must be called within a tokio runtime.
///
/// # Errors
///
/// The clock is before genesis ([`ServeError::Unavailable`]), the store does not open, or the
/// runtime stopped on an error.
pub async fn serve<E: EthSpec, V: KzgVerifier + 'static>(
    config: Config,
    settings: &ChainSettings,
    kzg: V,
    mut hooks: Hooks,
) -> Result<(), ServeError> {
    let now = system_ms();
    let net = &settings.network;
    let link = chain_link::<E>(net, now).map_err(ServeError::Unavailable)?;
    let cgc_set_slot = net
        .slot_at(now)
        .ok_or_else(|| ServeError::Unavailable("the clock is before genesis".into()))?;
    open_store_dir(&settings.columns_dir, config.ownership.uid).map_err(ServeError::Failed)?;
    let plan = ProbePlan {
        link,
        node_id: settings.node_id,
        columns_dir: settings.columns_dir.clone(),
        reference: settings.reference.clone(),
        kzg,
        verify_timeout: settings.verify_timeout,
        cgc_set_slot,
    };
    let service =
        ProbeService::<E, V>::open(net, plan, &mut hooks.unprefixed).map_err(|e| match e {
            crate::probe::service::OpenError::NodeIdChanged { .. }
            | crate::probe::service::OpenError::NodeIdUnknown { .. } => {
                ServeError::Config(e.to_string())
            }
            crate::probe::service::OpenError::Failed(why) => ServeError::Failed(why),
        })?;
    tracing::info!(
        columns = ?service.custody_columns(),
        cgc = service.custody_group_count(),
        cgc_set_slot = service.cgc_set_slot(),
        store = %settings.columns_dir.display(),
        "probe mode: custody columns"
    );
    // A Status never waits on the reference API: sampled now, so the first one has one.
    if let Err(e) = service.sample_reference().await {
        tracing::warn!(error = %e, "no reference sample for our Status yet");
    }
    let services = Services::new()
        .add_service(service.req_resp_server().into_service())
        .add_service(service.gossip_server().into_service());
    // Streams that stay open would hold the drain to its deadline: they end first.
    let stop = service.stream_stop();
    let shutdown = std::mem::replace(&mut hooks.shutdown, Box::pin(std::future::pending()));
    hooks.shutdown = Box::pin(async move {
        shutdown.await;
        stop.end_streams();
    });
    let result = svc_runtime::run_with(config, services, hooks).await;
    // The store's writer finishes what it was given, off the runtime's workers, within a
    // limit: the stop must end within the unit's stop timeout. A store that does not close in
    // time is 70, unless the run itself failed.
    let pending = service.pending();
    let closed = close_within(service, pending, STORE_CLOSE).await;
    result.map_err(ServeError::from)?;
    closed
}

/// Connects to cl-verify (its socket directory checked, its server's UID checked) and runs
/// [`serve`] under the preset of the network, with systemd's notification and SIGTERM/SIGINT.
/// A signal during the wait for cl-verify ends it at once, with `Ok`. Must be called within a
/// tokio runtime.
///
/// # Errors
///
/// As [`serve`]; and cl-verify's socket directory is open to other users
/// ([`ServeError::Failed`]) or cl-verify does not accept within `verify_wait_ms`
/// ([`ServeError::Unavailable`]).
pub async fn run(config: Config, settings: ChainSettings) -> Result<(), ServeError> {
    let mut hooks = Hooks::systemd().map_err(|e| ServeError::Failed(format!("signals: {e}")))?;
    let socket = &settings.verify_socket;
    // One wait for cl-verify's directory and then its socket, `verify_wait_ms` in all.
    let reach = async {
        let deadline = tokio::time::Instant::now() + settings.verify_wait;
        wait_for_verify_dir(socket, settings.verify_uid, deadline).await?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        connect_verify(socket, settings.verify_uid, left)
            .await
            .map_err(|e| verify_unreachable(socket, &e))
    };
    // A stop while the start waits for cl-verify is a clean stop, at once.
    let channel = tokio::select! {
        () = &mut hooks.shutdown => {
            tracing::info!("stopped before cl-verify accepted");
            return Ok(());
        }
        reached = reach => reached?,
    };
    let kzg = verify_client(&settings.network, channel);
    match settings.network.preset() {
        Preset::Minimal => serve::<Minimal, _>(config, &settings, kzg, hooks).await,
        Preset::Mainnet => serve::<Mainnet, _>(config, &settings, kzg, hooks).await,
    }
}

/// Which binary runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Build {
    /// `cl-chain`: [`CONFIG_PATH`], owned by root.
    Deployed,
    /// `cl-chain-test`: the config at [`TEST_CONFIG_ENV`], which the test user may own, and a
    /// `/metrics` port that the OS picks.
    Test,
}

/// Loads the config of `build` for this process's effective UID.
///
/// # Errors
///
/// The file is refused, or (`Test`) the variable is not set.
pub fn load(build: Build) -> Result<(Config, ChainSettings), SettingsError> {
    let euid = ipc::peercred::effective_uid();
    let config = match build {
        Build::Deployed => Config::load_root_owned(CHAIN_SERVICE, Path::new(CONFIG_PATH), euid, 0)?,
        Build::Test => {
            let path = std::env::var_os(TEST_CONFIG_ENV).ok_or_else(|| SettingsError::Key {
                key: "path",
                why: format!("{TEST_CONFIG_ENV} is not set"),
            })?;
            Config::load_root_owned(CHAIN_SERVICE, Path::new(&path), euid, euid)?
                .with_ephemeral_metrics_port()
        }
    };
    let settings = settings(&config)?;
    Ok((config, settings))
}

/// The process: no argument, the config of `build`, the logs, the runtime; the exit code.
#[must_use]
pub fn main(build: Build) -> u8 {
    use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
    use svc_runtime::telemetry::{flush_logs, init_binary_tracing, EXIT_NO_LOG_WRITER};
    use tracing::level_filters::LevelFilter;
    let arguments = std::env::args_os().len().saturating_sub(1);
    let loaded = (arguments == 0).then(|| load(build));
    let level = match &loaded {
        Some(Ok((config, _))) => config.log_level,
        _ => LevelFilter::INFO,
    };
    if init_binary_tracing(level).is_err() {
        return EXIT_NO_LOG_WRITER;
    }
    let code = match loaded {
        None => {
            tracing::error!(
                arguments,
                config = CONFIG_PATH,
                "cl-chain takes no argument: it reads its config file only"
            );
            EXIT_USAGE
        }
        Some(Err(e)) => {
            tracing::error!(error = %e, "config refused");
            EXIT_CONFIG
        }
        Some(Ok((config, settings))) => run_runtime(config, settings),
    };
    flush_logs(LOG_FLUSH_DEADLINE);
    code
}

/// How long blocking jobs still running get after the runtime is done, before the exit.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(5);

/// [`run`] on a new multi-threaded runtime; the exit code.
fn run_runtime(config: Config, settings: ChainSettings) -> u8 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return EXIT_FAILED;
        }
    };
    let code = match runtime.block_on(run(config, settings)) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = %e, code = e.exit_code(), "cl-chain stopped");
            e.exit_code()
        }
    };
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_ID: &str = "0x0000000000000000000000000000000000000000000000000000000000000007";

    /// A cl-chain config with `chain` as its `[chain]` table, cl-p2p at UID 991 on `methods`.
    fn text(methods: &[&str], chain: &str) -> String {
        let mut text = "network = \"sepolia\"\nmetrics_port = 9102\n\n[socket]\ngroup = 990\n\n\
                        [callers]\ncl-p2p = 991\ncl-api = 995\n\n[methods]\n"
            .to_owned();
        for m in methods {
            text.push_str(&format!("\"{m}\" = [\"cl-p2p\"]\n"));
        }
        text.push_str("\n[chain]\n");
        text.push_str(chain);
        text
    }

    fn chain_table(extra: &str) -> String {
        format!(
            "reference_api_url = \"http://127.0.0.1:5052\"\nnode_id = \"{NODE_ID}\"\n\
             verify_socket = \"/run/ethswarm/cl-verify/cl-verify.sock\"\nverify_uid = 993\n{extra}"
        )
    }

    fn parse(text: &str) -> Result<ChainSettings, SettingsError> {
        let config = Config::from_toml(CHAIN_SERVICE, text, Path::new("cl-chain.toml"))?;
        settings(&config)
    }

    #[test]
    fn loads_the_chain_table() {
        let s = parse(&text(&CHAIN_METHODS, &chain_table(""))).unwrap();
        assert_eq!(s.node_id, U256::from(7u64));
        assert_eq!(s.caller_uid, 991);
        assert_eq!(s.verify_uid, 993);
        assert_eq!(
            s.verify_socket,
            Path::new("/run/ethswarm/cl-verify/cl-verify.sock")
        );
        assert_eq!(s.columns_dir, Path::new(DEFAULT_COLUMNS_DIR));
        assert_eq!(s.verify_timeout, DEFAULT_VERIFY_TIMEOUT);
        assert_eq!(s.verify_wait, VERIFY_SOCKET_WAIT);
        assert_eq!(s.network.config().config_name(), "sepolia");
        assert_eq!(s.network.preset(), Preset::Mainnet);
        let s = parse(&text(
            &CHAIN_METHODS,
            &chain_table(
                "columns_dir = \"/srv/columns\"\nverify_timeout_ms = 900\nverify_wait_ms = 70\n",
            ),
        ))
        .unwrap();
        assert_eq!(s.verify_wait, Duration::from_millis(70));
        assert_eq!(s.columns_dir, Path::new("/srv/columns"));
        assert_eq!(s.verify_timeout, Duration::from_millis(900));
        assert_eq!(
            CONFIG_PATH,
            svc_runtime::config::config_path(CHAIN_SERVICE)
                .to_str()
                .unwrap()
        );
    }

    /// The ACL is exactly cl-p2p on the four methods: one fewer, one more, or another caller is
    /// refused.
    #[test]
    fn the_acl_is_cl_p2p_on_four_methods_only() {
        let three = &CHAIN_METHODS[..3];
        let err = parse(&text(three, &chain_table(""))).unwrap_err();
        assert!(matches!(err, SettingsError::Acl { .. }), "{err}");
        let mut five = CHAIN_METHODS.to_vec();
        five.push("/ethswarm.chain.v1.ReqRespService/GetMetadata");
        let err = parse(&text(&five, &chain_table(""))).unwrap_err();
        assert!(matches!(err, SettingsError::Acl { .. }), "{err}");
        let api = text(&CHAIN_METHODS, &chain_table("")).replace(
            "GetStatus\" = [\"cl-p2p\"]",
            "GetStatus\" = [\"cl-p2p\", \"cl-api\"]",
        );
        let err = parse(&api).unwrap_err();
        assert!(matches!(err, SettingsError::Acl { .. }), "{err}");
        let no_p2p = text(&CHAIN_METHODS, &chain_table(""))
            .replace("cl-p2p = 991\n", "")
            .replace("[\"cl-p2p\"]", "[\"cl-api\"]");
        let err = parse(&no_p2p).unwrap_err();
        assert!(err.to_string().contains("no cl-p2p"), "{err}");
    }

    #[test]
    fn the_chain_table_is_checked() {
        let cases = [
            (
                chain_table("").replace("127.0.0.1:5052", "203.0.113.9:5052"),
                "reference_api_url",
            ),
            (
                chain_table("").replace("127.0.0.1:5052", "ref.example:5052"),
                "reference_api_url",
            ),
            (
                chain_table("").replace("http://127.0.0.1:5052", "https://127.0.0.1"),
                "reference_api_url",
            ),
            (
                chain_table("").replace("127.0.0.1:5052", "127.0.0.1:5052/key"),
                "reference_api_url",
            ),
            (chain_table("").replace(NODE_ID, "0x07"), "node_id"),
            (chain_table("").replace(NODE_ID, &NODE_ID[2..]), "node_id"),
            (
                chain_table("").replace("/run/ethswarm/cl-verify", "run"),
                "verify_socket",
            ),
            (chain_table("columns_dir = \"columns\"\n"), "columns_dir"),
            (chain_table("verify_timeout_ms = 0\n"), "verify_timeout_ms"),
            (
                chain_table("verify_timeout_ms = 60001\n"),
                "verify_timeout_ms",
            ),
            (chain_table("verify_wait_ms = 0\n"), "verify_wait_ms"),
            (chain_table("verify_wait_ms = 600001\n"), "verify_wait_ms"),
        ];
        for (table, want) in cases {
            let err = parse(&text(&CHAIN_METHODS, &table)).unwrap_err();
            assert!(
                matches!(&err, SettingsError::Key { key, .. } if *key == want),
                "{table}: {err}"
            );
            // The refusal never quotes the value.
            assert!(!err.to_string().contains("203.0.113.9"), "{err}");
        }
        // Private and unique-local addresses are local, as on the devnet's network.
        for host in [
            "10.1.2.3",
            "172.16.0.2",
            "192.168.1.1",
            "[fd00::1]",
            "[::1]",
            "localhost",
        ] {
            let table = chain_table("").replace("127.0.0.1", host);
            assert!(parse(&text(&CHAIN_METHODS, &table)).is_ok(), "{host}");
        }
        // An unknown key, and a missing one.
        let err = parse(&text(&CHAIN_METHODS, &chain_table("listen = 1\n"))).unwrap_err();
        assert!(matches!(err, SettingsError::Config(_)), "{err}");
        let missing = chain_table("").replace("verify_uid = 993\n", "");
        let err = parse(&text(&CHAIN_METHODS, &missing)).unwrap_err();
        assert!(err.to_string().contains("verify_uid"), "{err}");
    }

    #[test]
    fn a_network_without_a_genesis_is_refused() {
        let hoodi = text(&CHAIN_METHODS, &chain_table("")).replace("sepolia", "hoodi");
        let err = parse(&hoodi).unwrap_err();
        assert!(matches!(err, SettingsError::NoGenesis(_)), "{err}");
    }

    #[test]
    fn exit_codes_follow_the_unit() {
        assert_eq!(ServeError::Unavailable(String::new()).exit_code(), 69);
        assert_eq!(ServeError::Failed(String::new()).exit_code(), 1);
        // The unit's RestartPreventExitStatus=1 2 64: a missing cl-verify is not among them.
        for code in [EXIT_FAILED, EXIT_CONFIG, EXIT_USAGE] {
            assert!([1, 2, 64].contains(&code));
        }
        assert!(![1, 2, 64].contains(&EXIT_UNAVAILABLE));
    }

    /// Only a refusal that a restart cannot fix stops the unit for good (1): the socket's bind
    /// and an ACL that names unserved methods. Every other runtime fault is 70 (`EX_SOFTWARE`),
    /// which `RestartPreventExitStatus=1 2 64` does not hold, so systemd restarts it.
    #[test]
    fn a_runtime_fault_that_a_restart_can_fix_is_70() {
        use svc_runtime::RuntimeError;
        let runtime = |e| ServeError::Runtime(e).exit_code();
        assert_eq!(
            runtime(RuntimeError::Bind(ipc::uds::BindError::Service("X".into()))),
            1
        );
        assert_eq!(runtime(RuntimeError::UnservedMethods(Vec::new())), 1);
        assert_eq!(runtime(RuntimeError::Exited), 70);
        assert_eq!(
            runtime(RuntimeError::DrainTimeout(Duration::from_secs(1))),
            70
        );
        assert_eq!(
            runtime(RuntimeError::Io {
                what: "listen for /metrics on 127.0.0.1",
                source: std::io::ErrorKind::AddrInUse.into(),
            }),
            70
        );
        assert_eq!(
            runtime(RuntimeError::Notify(std::io::ErrorKind::WouldBlock.into())),
            70
        );
        assert_eq!(
            runtime(RuntimeError::LogWriter(
                std::io::ErrorKind::WouldBlock.into()
            )),
            71
        );
        assert_eq!(EXIT_SOFTWARE, 70);
        assert!(![1, 2, 64].contains(&EXIT_SOFTWARE));
        assert_eq!(ServeError::Config(String::new()).exit_code(), 2);
    }

    /// cl-verify's socket that is not there yet is a restart (69); a server of another user is
    /// a refusal that a restart cannot fix (1).
    #[tokio::test]
    async fn a_cl_verify_of_another_user_is_a_failed_start() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("cl-verify.sock");
        let me = ipc::uds::Ownership::current().uid;
        let missing = connect_verify(&socket, me, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(verify_unreachable(&socket, &missing).exit_code(), 69);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(ipc::stub::serve_uds(
            listener,
            tonic::service::Routes::default(),
            std::future::pending(),
        ));
        let other = connect_verify(&socket, me + 1, Duration::from_secs(5))
            .await
            .unwrap_err();
        let refused = verify_unreachable(&socket, &other);
        assert_eq!(refused.exit_code(), 1, "{refused}");
    }

    /// The store's writer gets [`STORE_CLOSE`] at most after the drain: a drop that takes
    /// longer is left behind and logged, so the stop ends within the unit's stop timeout.
    #[tokio::test]
    async fn a_slow_store_close_is_bounded() {
        struct Slow;
        impl Drop for Slow {
            fn drop(&mut self) {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        let started = std::time::Instant::now();
        assert!(!drop_within(Slow, Duration::from_millis(20)).await);
        assert!(started.elapsed() < Duration::from_millis(400));
        assert!(drop_within(1u8, Duration::from_secs(5)).await);
        assert!(STORE_CLOSE < Duration::from_secs(30));
    }

    /// A store that does not close in time is a fault a restart can fix (70), and the error
    /// names how many columns were still on their way.
    #[tokio::test]
    async fn a_store_that_does_not_close_in_time_is_70() {
        struct Slow;
        impl Drop for Slow {
            fn drop(&mut self) {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        let err = close_within(Slow, 3, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), 70);
        assert!(err.to_string().contains("3 columns"), "{err}");
        assert!(close_within(1u8, 0, Duration::from_secs(5)).await.is_ok());
    }

    /// The wait for cl-verify's directory: one not there is 69 at the end of the wait, one of
    /// another user is 1 at the end of the wait (it is retried until then), and one open to
    /// others is 1 at once.
    #[tokio::test]
    async fn the_verify_dir_wait_ends_by_what_it_found() {
        use std::os::unix::fs::PermissionsExt;
        let uid = ipc::uds::Ownership::current().uid;
        let root = tempfile::Builder::new()
            .tempdir_in(svc_runtime::owned::testkit::config_root())
            .unwrap();
        let sock = |dir: &str| root.path().join(dir).join("cl-verify.sock");
        let soon = || tokio::time::Instant::now() + Duration::from_millis(300);
        let err = wait_for_verify_dir(&sock("absent"), uid, soon())
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), 69, "{err}");
        let dir = root.path().join("verify");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        let started = tokio::time::Instant::now();
        let err = wait_for_verify_dir(&sock("verify"), uid + 1, soon())
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "retried until the end"
        );
        let open = root.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let started = tokio::time::Instant::now();
        let far = tokio::time::Instant::now() + Duration::from_secs(30);
        let err = wait_for_verify_dir(&sock("open/absent"), uid, far)
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "refused at once"
        );
    }
}
