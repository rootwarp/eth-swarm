//! The `cl-discv5` process: what `ops/probe/ethswarm-discv5.service` runs.
//!
//! The unit passes no argument. The binary reads `/etc/ethswarm/cl-discv5.toml`
//! ([`CONFIG_PATH`]) through the owner walk (`svc_runtime::Config::load_root_owned`), loads the
//! node key from its systemd credential (`node_key`, [`crate::enr::signing_key`]), and runs until
//! SIGTERM:
//!
//! ```toml
//! network_dir = "/etc/ethswarm/network"   # or: network = "sepolia"
//! metrics_port = 9103
//!
//! [socket]
//! group = 992                             # the GID of ethswarm-discv5: cl-p2p is a member
//!
//! [callers]
//! cl-p2p = 991                            # the UID of ethswarm-p2p
//!
//! [methods]                               # exactly these three, to cl-p2p only
//! "/ethswarm.discv5.v1.DiscoveryService/WatchPeers" = ["cl-p2p"]
//! "/ethswarm.discv5.v1.DiscoveryService/GetLocalEnr" = ["cl-p2p"]
//! "/ethswarm.discv5.v1.DiscoveryService/FindPeers" = ["cl-p2p"]
//!
//! [discv5]
//! mode = "public"                  # public, devnet or local: the routing table's IP rules
//! bootnodes = ["enr:…"]            # the records the table starts from
//! listen_ip = "0.0.0.0"            # optional, this default: the UDP address
//! udp_port = 9000                  # optional, this default
//! tcp_port = 9000                  # optional, this default: cl-p2p's port, in our record
//! enr_ip = "203.0.113.7"           # optional: the IPv4 address in our record
//! cgc = 4                          # optional, this default: the record's custody group count
//! lookup_interval_ms = 30000       # optional, this default: one lookup this often
//! lookup_peers = 16                # optional, this default: the most one lookup returns
//! ```
//!
//! - **Our record** carries the fork fields of the wall-clock epoch, and takes the new ones at
//!   each fork or BPO digest change ([`Discovery::set_fork_fields`], checked every
//!   [`FORK_CHECK`]). It logs its node ID and record at start: both are public.
//! - **Lookups** run every `lookup_interval_ms` towards a random node ID. Every record found,
//!   and every record discv5 reports, goes to the watchers ([`PeerFeed`]). `FindPeers` runs
//!   lookups of its own ([`crate::subnet_query`]), cached by the wall-clock slot (`genesis_time`
//!   and the slot duration of the network config; slot 0 before genesis).
//! - **The ACL** must be exactly [`discv5_acl`] of the `cl-p2p` caller.
//!
//! Exit codes, which `RestartPreventExitStatus=1 2 64` reads: 0 a clean stop; 1 a refused
//! credential or a start that a restart cannot fix (discv5's UDP socket, the service socket's
//! bind, an ACL of unserved methods); 2 a refused config; 64 an argument; 70 a fault of the run
//! that a restart can fix (restarted); 71 no log writer (restarted).

use crate::enr::{build_local_enr, CombinedKey, Enr, EnrFields, LocalAddr, NodeId, DEFAULT_PORT};
use crate::metrics::EvictionMetrics;
use crate::server::{DiscoveryServer, PeerFeed};
use crate::service::{Discovery, DiscoveryConfig, Events, NetworkMode, PeerEvent, SWEEP_INTERVAL};
use ipc::acl::{AclTables, MethodAcl};
use ipc::hello::NetworkHello;
use ipc::Link;
use network_config::digest::current_epoch;
use network_config::{ChainConfig, Genesis};
use p2p_wire::enr::ForkFields;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use svc_runtime::{Config, Hooks, Services};
use tokio::sync::watch;

/// The config file of the deployed binary.
pub const CONFIG_PATH: &str = "/etc/ethswarm/cl-discv5.toml";

/// The environment variable that names the config of the test binary `cl-discv5-test`. The
/// `cl-discv5` binary never reads it.
pub const TEST_CONFIG_ENV: &str = "CL_DISCV5_TEST_CONFIG";

/// The service's name.
pub const SERVICE: &str = "cl-discv5";

/// The probe unit this service runs as: a root-owned, ACL-granted credential is accepted only
/// from `/run/credentials/<UNIT>`.
pub const UNIT: &str = "ethswarm-discv5.service";

/// The build string of our hellos.
pub const BUILD: &str = concat!("cl-discv5/", env!("CARGO_PKG_VERSION"));

/// The one caller.
pub const P2P_CALLER: &str = "cl-p2p";

/// The methods cl-p2p calls, and only those.
pub const DISCV5_METHODS: [&str; 3] = [
    "/ethswarm.discv5.v1.DiscoveryService/WatchPeers",
    "/ethswarm.discv5.v1.DiscoveryService/GetLocalEnr",
    "/ethswarm.discv5.v1.DiscoveryService/FindPeers",
];

/// A refused credential, or a start or run that a restart cannot fix.
pub const EXIT_FAILED: u8 = 1;
/// A refused config.
pub const EXIT_CONFIG: u8 = 2;
/// A command-line argument (`EX_USAGE`).
pub const EXIT_USAGE: u8 = 64;
/// A fault of the run that a restart can fix (`EX_SOFTWARE`): restarted.
pub const EXIT_SOFTWARE: u8 = 70;

/// The custody group count of our record unless `cgc` says otherwise: `CUSTODY_REQUIREMENT`.
pub const DEFAULT_CGC: u64 = 4;

/// One lookup this often unless `lookup_interval_ms` says otherwise \[est\].
pub const DEFAULT_LOOKUP_INTERVAL: Duration = Duration::from_secs(30);

/// The most one lookup returns unless `lookup_peers` says otherwise.
pub const DEFAULT_LOOKUP_PEERS: usize = 16;

/// How often our record's fork fields are checked against the wall clock \[est\]: within a
/// slot of a digest change.
pub const FORK_CHECK: Duration = Duration::from_secs(6);

/// The `[discv5]` table.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Discv5Table {
    mode: Option<String>,
    #[serde(default)]
    bootnodes: Vec<String>,
    listen_ip: Option<IpAddr>,
    udp_port: Option<u16>,
    tcp_port: Option<u16>,
    enr_ip: Option<Ipv4Addr>,
    cgc: Option<u64>,
    lookup_interval_ms: Option<u64>,
    lookup_peers: Option<usize>,
}

/// What cl-discv5 runs with, from its config, checked.
#[derive(Debug)]
pub struct Discv5Settings {
    /// The network's hello (its config and genesis).
    pub network: Arc<NetworkHello>,
    /// The routing table's IP rules.
    pub mode: NetworkMode,
    /// The records the table starts from.
    pub bootnodes: Vec<Enr>,
    /// The UDP address.
    pub listen_ip: IpAddr,
    /// The UDP port.
    pub udp_port: u16,
    /// cl-p2p's TCP port, in our record.
    pub tcp_port: u16,
    /// The IPv4 address in our record; unspecified leaves it to what peers observe.
    pub enr_ip: Ipv4Addr,
    /// Our record's `cgc`.
    pub cgc: u64,
    /// One lookup this often.
    pub lookup_interval: Duration,
    /// The most one lookup returns.
    pub lookup_peers: usize,
    /// cl-p2p's UID.
    pub caller_uid: u32,
}

/// The ACL of cl-discv5: [`DISCV5_METHODS`] to [`P2P_CALLER`] at `caller_uid`, nothing else.
///
/// # Errors
///
/// The ACL does not load (it always does).
pub fn discv5_acl(caller_uid: u32) -> Result<MethodAcl, String> {
    let tables = AclTables {
        callers: [(P2P_CALLER.to_owned(), caller_uid)].into(),
        methods: DISCV5_METHODS
            .iter()
            .map(|m| ((*m).to_owned(), vec![P2P_CALLER.to_owned()]))
            .collect(),
    };
    MethodAcl::from_tables(SERVICE, &tables).map_err(|e| e.to_string())
}

/// The settings of `config`; the text names what was refused, never a value.
///
/// # Errors
///
/// The first refusal.
pub fn settings(config: &Config) -> Result<Discv5Settings, String> {
    let table: Discv5Table = config.section().map_err(|e| e.to_string())?;
    let key = |key: &str, why: &str| format!("[discv5] {key}: {why}");
    let mode = match table.mode.as_deref().unwrap_or("public") {
        "public" => NetworkMode::Public,
        "devnet" => NetworkMode::Devnet,
        "local" => NetworkMode::Local,
        _ => return Err(key("mode", "want public, devnet or local")),
    };
    let bootnodes = table
        .bootnodes
        .iter()
        .map(|text| {
            let enr: Enr = text.parse().map_err(|_| key("bootnodes", "not a record"))?;
            EnrFields::read(&enr).map_err(|e| key("bootnodes", &e.to_string()))?;
            Ok(enr)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let cgc = table.cgc.unwrap_or(DEFAULT_CGC);
    if cgc > 128 {
        return Err(key("cgc", "want at most NUMBER_OF_CUSTODY_GROUPS (128)"));
    }
    let lookup_interval = match table.lookup_interval_ms {
        None => DEFAULT_LOOKUP_INTERVAL,
        Some(ms) if (100..=3_600_000).contains(&ms) => Duration::from_millis(ms),
        Some(_) => return Err(key("lookup_interval_ms", "want 100 to 3600000")),
    };
    let lookup_peers = table.lookup_peers.unwrap_or(DEFAULT_LOOKUP_PEERS);
    if !(1..=256).contains(&lookup_peers) {
        return Err(key("lookup_peers", "want 1 to 256"));
    }
    let caller_uid = *config
        .callers
        .get(P2P_CALLER)
        .ok_or_else(|| format!("[callers] has no {P2P_CALLER}"))?;
    if config.acl != discv5_acl(caller_uid)? {
        return Err(format!(
            "the method ACL must give exactly {DISCV5_METHODS:?} to {P2P_CALLER} and to nobody \
             else"
        ));
    }
    let genesis = config.genesis.ok_or_else(|| {
        format!(
            "the network {} has no pinned genesis: give network_dir",
            config.network.name()
        )
    })?;
    let network = NetworkHello::new(BUILD, &config.chain, genesis)
        .map(Arc::new)
        .map_err(|e| format!("the network: {e}"))?;
    Ok(Discv5Settings {
        network,
        mode,
        bootnodes,
        listen_ip: table.listen_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        udp_port: table.udp_port.unwrap_or(DEFAULT_PORT),
        tcp_port: table.tcp_port.unwrap_or(DEFAULT_PORT),
        enr_ip: table.enr_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
        cgc,
        lookup_interval,
        lookup_peers,
        caller_uid,
    })
}

/// The fork fields of the wall clock at `now_ms`; before genesis or Fulu, those of Fulu's first
/// epoch.
///
/// # Errors
///
/// The schedule gives no fork digest there.
fn fork_fields_at(
    config: &ChainConfig,
    genesis: Genesis,
    slots: u64,
    now_ms: u128,
) -> Result<ForkFields, String> {
    let fulu = config
        .fork_schedule()
        .fork_epoch(network_config::ForkName::Fulu)
        .unwrap_or(0);
    let epoch = current_epoch(
        genesis.genesis_time,
        config.slot_duration_ms(),
        slots,
        now_ms,
    )
    .unwrap_or(0)
    .max(fulu);
    ForkFields::from_schedule(config, &genesis.genesis_validators_root, epoch)
        .map_err(|e| format!("our record's fork fields: {e}"))
}

/// The wall-clock slot at `now_ms`, 0 before genesis: what `FindPeers` caches by.
fn slot_at(genesis_time: u64, slot_ms: u64, now_ms: u128) -> u64 {
    // An epoch of one slot is a slot.
    current_epoch(genesis_time, slot_ms, 1, now_ms).unwrap_or(0)
}

/// Why [`serve`] stopped other than cleanly.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The start failed.
    #[error("{0}")]
    Failed(String),
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
            Self::Failed(_) => EXIT_FAILED,
            // The socket and the ACL do not fix themselves; every other fault of the run may.
            Self::Runtime(RuntimeError::Bind(_) | RuntimeError::UnservedMethods(_)) => EXIT_FAILED,
            Self::Runtime(RuntimeError::LogWriter(_)) => svc_runtime::telemetry::EXIT_NO_LOG_WRITER,
            Self::Runtime(_) => EXIT_SOFTWARE,
        }
    }
}

/// Runs discv5 of `settings` with `key` and serves it as `config` says until `hooks.shutdown`
/// (see the module docs). Its metrics go to `hooks.unprefixed`.
///
/// # Errors
///
/// discv5 does not start, or the runtime stopped on an error.
pub async fn serve(
    config: Config,
    settings: Discv5Settings,
    key: CombinedKey,
    mut hooks: Hooks,
) -> Result<(), ServeError> {
    let network = &settings.network;
    let fork = fork_fields_at(
        network.config(),
        network.genesis(),
        network.slots_per_epoch(),
        ipc::hello::system_ms(),
    )
    .map_err(ServeError::Failed)?;
    let addr = LocalAddr {
        ip: settings.enr_ip,
        tcp_port: settings.tcp_port,
        udp_port: settings.udp_port,
    };
    let enr = build_local_enr(&key, &fork, settings.cgc, &addr)
        .map_err(|e| ServeError::Failed(e.to_string()))?;
    let mut discovery_config = DiscoveryConfig::new(settings.listen_ip, settings.mode);
    discovery_config.udp_port = settings.udp_port;
    discovery_config.sweep_interval = SWEEP_INTERVAL;
    // At a digest change, the records of the old digest stay two epochs: peers move to the new
    // one only when discv5 asks them again.
    let grace = fork_grace(
        network.config().slot_duration_ms(),
        network.slots_per_epoch(),
    );
    let mut discovery = Discovery::new(enr, key, &discovery_config)
        .map_err(|e| ServeError::Failed(e.to_string()))?
        .with_fork_grace(grace)
        .with_metrics(EvictionMetrics::register(&mut hooks.unprefixed));
    let events = discovery
        .start()
        .await
        .map_err(|e| ServeError::Failed(format!("discv5: {e}")))?;
    let local = discovery.local_enr();
    tracing::info!(
        node_id = %hex(&local.node_id().raw()),
        enr = %local.to_base64(),
        fork_digest = %hex(&discovery.fork_digest()),
        mode = ?settings.mode,
        "discv5 started"
    );
    for boot in &settings.bootnodes {
        if let Err(e) = discovery.add_enr(boot.clone()) {
            tracing::warn!(node_id = %hex(&boot.node_id().raw()), error = %e, "bootnode refused");
        }
    }
    let discovery = Arc::new(discovery);
    let feed = PeerFeed::default();
    let (stop_tx, stop) = watch::channel(false);
    let tasks = [
        tokio::spawn(report(events, feed.clone())),
        tokio::spawn(lookups(
            Arc::clone(&discovery),
            feed.clone(),
            settings.lookup_interval,
            settings.lookup_peers,
        )),
        tokio::spawn(follow_forks(
            Arc::clone(&discovery),
            Arc::clone(&settings.network),
        )),
    ];
    let link = Link::network(Arc::clone(&settings.network), 1)
        .map_err(|e| ServeError::Failed(format!("the digest schedule: {e}")))?;
    let genesis_time = network.genesis().genesis_time;
    let slot_ms = network.config().slot_duration_ms();
    let slots = Arc::new(move || slot_at(genesis_time, slot_ms, ipc::hello::system_ms()));
    let server = DiscoveryServer::new(link, Arc::clone(&discovery), feed, stop, slots);
    let services = Services::new().add_service(server.into_service());
    let shutdown = std::mem::replace(&mut hooks.shutdown, Box::pin(std::future::pending()));
    hooks.shutdown = Box::pin(async move {
        shutdown.await;
        stop_tx.send_replace(true);
    });
    let result = svc_runtime::run_with(config, services, hooks).await;
    for task in tasks {
        task.abort();
    }
    result.map_err(ServeError::from)
}

/// Every record discv5 reports, to the watchers.
async fn report(mut events: Events, feed: PeerFeed) {
    while let Some(event) = events.next().await {
        match event {
            PeerEvent::Discovered(enr) | PeerEvent::SessionEstablished(enr, _) => feed.send(enr),
            PeerEvent::SocketUpdated(addr) => tracing::info!(%addr, "our record's socket updated"),
        }
    }
}

/// A lookup towards a random node ID every `every`, its records to the watchers.
async fn lookups(discovery: Arc<Discovery>, feed: PeerFeed, every: Duration, max: usize) {
    let mut ticks = tokio::time::interval(every);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        match discovery.find_peers(NodeId::random(), max).await {
            Ok(found) => {
                tracing::debug!(found = found.len(), "lookup");
                for enr in found {
                    feed.send(enr);
                }
            }
            Err(e) => tracing::debug!(error = %e, "lookup failed"),
        }
    }
}

/// Our record's fork fields, checked against the wall clock every [`FORK_CHECK`].
async fn follow_forks(discovery: Arc<Discovery>, network: Arc<NetworkHello>) {
    let mut ticks = tokio::time::interval(FORK_CHECK);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let fork = match fork_fields_at(
            network.config(),
            network.genesis(),
            network.slots_per_epoch(),
            ipc::hello::system_ms(),
        ) {
            Ok(fork) => fork,
            Err(e) => {
                tracing::warn!(error = %e, "our record's fork fields");
                continue;
            }
        };
        match discovery.set_fork_fields(&fork) {
            Ok(true) => tracing::info!(
                fork_digest = %hex(&fork.eth2.fork_digest),
                "our record follows the new fork digest"
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, "our record's fork fields"),
        }
    }
}

/// `0x` and the lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Which binary runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Build {
    /// `cl-discv5`: [`CONFIG_PATH`], owned by root.
    Deployed,
    /// `cl-discv5-test`: the config at [`TEST_CONFIG_ENV`], which the test user may own, and a
    /// `/metrics` port that the OS picks.
    Test,
}

/// Loads the config of `build` for this process's effective UID.
///
/// # Errors
///
/// The config is refused; the text names why.
pub fn load(build: Build) -> Result<(Config, Discv5Settings), String> {
    let euid = ipc::peercred::effective_uid();
    let config = match build {
        Build::Deployed => Config::load_root_owned(SERVICE, Path::new(CONFIG_PATH), euid, 0),
        Build::Test => {
            let path = std::env::var_os(TEST_CONFIG_ENV)
                .ok_or_else(|| format!("{TEST_CONFIG_ENV} is not set"))?;
            Config::load_root_owned(SERVICE, Path::new(&path), euid, euid)
                .map(Config::with_ephemeral_metrics_port)
        }
    }
    .map_err(|e| e.to_string())?;
    let settings = settings(&config)?;
    Ok((config, settings))
}

/// The process: no argument, the config of `build`, the logs, the node key, the runtime; the
/// exit code.
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
                "cl-discv5 takes no argument: it reads its config file only"
            );
            EXIT_USAGE
        }
        // The credential first, as the unit's exit codes say: 1 before 2. A load and a refusal
        // are both logged, without key material; the key is wiped on drop.
        Some(loaded) => match (node_key::load_from_env(UNIT), loaded) {
            (Err(_), _) => EXIT_FAILED,
            (Ok(_), Err(e)) => {
                tracing::error!(error = %e, "config refused");
                EXIT_CONFIG
            }
            (Ok(secret), Ok((config, settings))) => match crate::enr::signing_key(secret) {
                Err(e) => {
                    tracing::error!(error = %e, "node key refused");
                    EXIT_FAILED
                }
                Ok(key) => run_runtime(config, settings, key),
            },
        },
    };
    flush_logs(LOG_FLUSH_DEADLINE);
    code
}

/// How long blocking jobs still running get after the runtime is done.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(5);

/// [`serve`] on a new multi-threaded runtime with systemd's hooks; the exit code.
fn run_runtime(config: Config, settings: Discv5Settings, key: CombinedKey) -> u8 {
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
    let result = runtime.block_on(async {
        let hooks = Hooks::systemd().map_err(|e| ServeError::Failed(format!("signals: {e}")))?;
        serve(config, settings, key, hooks).await
    });
    let code = match result {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = %e, code = e.exit_code(), "cl-discv5 stopped");
            e.exit_code()
        }
    };
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
    code
}

/// How many epochs the records of the old fork digest stay in the table after a change: as
/// long as the old gossip topics (`altair/p2p-interface.md`, "Transitioning the gossip": the
/// pre-fork topics SHOULD be unsubscribed two epochs after the fork).
pub const FORK_GRACE_EPOCHS: u64 = 2;

/// [`FORK_GRACE_EPOCHS`] epochs of `slots_per_epoch` slots of `slot_ms` milliseconds.
#[must_use]
pub fn fork_grace(slot_ms: u64, slots_per_epoch: u64) -> Duration {
    Duration::from_millis(
        slot_ms
            .saturating_mul(slots_per_epoch)
            .saturating_mul(FORK_GRACE_EPOCHS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enr::CombinedKey;

    fn text(methods: &[&str], table: &str) -> String {
        let mut text = "network = \"sepolia\"\nmetrics_port = 9103\n\n[socket]\ngroup = 992\n\n\
                        [callers]\ncl-p2p = 991\ncl-api = 995\n\n[methods]\n"
            .to_owned();
        for m in methods {
            text.push_str(&format!("\"{m}\" = [\"cl-p2p\"]\n"));
        }
        text.push_str("\n[discv5]\n");
        text.push_str(table);
        text
    }

    fn parse(text: &str) -> Result<Discv5Settings, String> {
        let config = Config::from_toml(SERVICE, text, Path::new("cl-discv5.toml"))
            .map_err(|e| e.to_string())?;
        settings(&config)
    }

    fn bootnode() -> String {
        let config = ChainConfig::load(network_config::Network::Sepolia).unwrap();
        let fulu = config
            .fork_schedule()
            .fork_epoch(network_config::ForkName::Fulu)
            .unwrap();
        let gvr = network_config::Network::Sepolia
            .genesis()
            .unwrap()
            .genesis_validators_root;
        let fork = ForkFields::from_schedule(&config, &gvr, fulu).unwrap();
        let addr = LocalAddr::new(Ipv4Addr::new(10, 0, 0, 2));
        build_local_enr(&CombinedKey::generate_secp256k1(), &fork, 4, &addr)
            .unwrap()
            .to_base64()
    }

    #[test]
    fn the_defaults_and_a_complete_table() {
        let s = parse(&text(&DISCV5_METHODS, "")).unwrap();
        assert_eq!(s.mode, NetworkMode::Public);
        assert!(s.bootnodes.is_empty());
        assert_eq!(s.listen_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!((s.udp_port, s.tcp_port), (DEFAULT_PORT, DEFAULT_PORT));
        assert_eq!(s.enr_ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(s.cgc, DEFAULT_CGC);
        assert_eq!(s.lookup_interval, DEFAULT_LOOKUP_INTERVAL);
        assert_eq!(s.lookup_peers, DEFAULT_LOOKUP_PEERS);
        assert_eq!(s.caller_uid, 991);
        let table = format!(
            "mode = \"local\"\nbootnodes = [\"{}\"]\nlisten_ip = \"127.0.0.1\"\nudp_port = 9100\n\
             tcp_port = 9200\nenr_ip = \"10.0.0.9\"\ncgc = 8\nlookup_interval_ms = 500\n\
             lookup_peers = 4\n",
            bootnode()
        );
        let s = parse(&text(&DISCV5_METHODS, &table)).unwrap();
        assert_eq!(s.mode, NetworkMode::Local);
        assert_eq!(s.bootnodes.len(), 1);
        assert_eq!((s.udp_port, s.tcp_port, s.cgc), (9100, 9200, 8));
        assert_eq!(s.enr_ip, Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(s.lookup_interval, Duration::from_millis(500));
        assert_eq!(s.lookup_peers, 4);
        assert_eq!(
            CONFIG_PATH,
            svc_runtime::config::config_path(SERVICE).to_str().unwrap()
        );
    }

    #[test]
    fn bad_tables_and_acls_are_refused() {
        for (table, want) in [
            ("mode = \"open\"\n", "mode"),
            ("bootnodes = [\"enr:nope\"]\n", "bootnodes"),
            ("cgc = 129\n", "cgc"),
            ("lookup_interval_ms = 99\n", "lookup_interval_ms"),
            ("lookup_peers = 0\n", "lookup_peers"),
            ("listen = 1\n", "listen"),
        ] {
            let err = parse(&text(&DISCV5_METHODS, table)).unwrap_err();
            assert!(err.contains(want), "{table}: {err}");
        }
        let err = parse(&text(&DISCV5_METHODS[..1], "")).unwrap_err();
        assert!(err.contains("method ACL"), "{err}");
        let other = text(&DISCV5_METHODS, "").replace(
            "WatchPeers\" = [\"cl-p2p\"]",
            "WatchPeers\" = [\"cl-p2p\", \"cl-api\"]",
        );
        assert!(parse(&other).unwrap_err().contains("method ACL"));
    }

    /// A restart can fix a fault of the run (70), not a failed start, the socket's bind or the
    /// ACL (1).
    /// The records of the old digest stay two epochs after a change, as the old gossip topics
    /// do (`altair/p2p-interface.md`, "Transitioning the gossip").
    #[test]
    fn the_fork_grace_is_two_epochs() {
        assert_eq!(fork_grace(6_000, 8), Duration::from_secs(96));
        assert_eq!(fork_grace(12_000, 32), Duration::from_secs(768));
    }

    #[test]
    fn exit_codes_follow_the_unit() {
        use svc_runtime::RuntimeError;
        assert_eq!(ServeError::Failed(String::new()).exit_code(), 1);
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
            runtime(RuntimeError::LogWriter(
                std::io::ErrorKind::WouldBlock.into()
            )),
            71
        );
        assert!(![1, 2, 64].contains(&EXIT_SOFTWARE));
    }

    /// cl-p2p may call `FindPeers`, and nobody else may; a config whose ACL leaves it out is
    /// refused.
    #[test]
    fn find_peers_is_in_the_acl() {
        let find = "/ethswarm.discv5.v1.DiscoveryService/FindPeers";
        let acl = discv5_acl(991).unwrap();
        assert!(acl.allows(find, 991));
        assert!(!acl.allows(find, 995));
        assert!(acl.methods().any(|m| m == find));
        let without: Vec<&str> = DISCV5_METHODS
            .iter()
            .copied()
            .filter(|m| *m != find)
            .collect();
        assert!(parse(&text(&without, ""))
            .unwrap_err()
            .contains("method ACL"));
        assert!(parse(&text(&DISCV5_METHODS, "")).is_ok());
    }

    /// The slot `FindPeers` caches by: the wall-clock slot, 0 before genesis.
    #[test]
    fn the_slot_of_the_clock() {
        use ipc::testkit::devnet::{devnet_ms, DEVNET_GENESIS, DEVNET_SLOT_MS};
        let at = |ms: u64| slot_at(DEVNET_GENESIS.genesis_time, DEVNET_SLOT_MS, u128::from(ms));
        assert_eq!(at(0), 0);
        assert_eq!(at(devnet_ms(0) - 1), 0);
        assert_eq!(at(devnet_ms(0)), 0);
        assert_eq!(at(devnet_ms(1) - 1), 0);
        assert_eq!(at(devnet_ms(1)), 1);
        assert_eq!(at(devnet_ms(1234) + 5_999), 1234);
    }

    /// The record's fork fields follow the clock; before genesis, epoch 0's.
    #[test]
    fn the_fork_fields_of_the_clock() {
        use ipc::testkit::devnet::{devnet_config, devnet_ms, DEVNET_GENESIS};
        let config = devnet_config();
        let at = |ms: u64| fork_fields_at(&config, DEVNET_GENESIS, 8, u128::from(ms)).unwrap();
        let gvr = DEVNET_GENESIS.genesis_validators_root;
        let of = |epoch| ForkFields::from_schedule(&config, &gvr, epoch).unwrap();
        assert_eq!(at(devnet_ms(0)), of(0));
        assert_eq!(at(devnet_ms(17)), of(2));
        assert_eq!(at(0), of(0));
        assert_eq!(hex(&[0xab, 1]), "0xab01");
    }
}
