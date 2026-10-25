//! A service's configuration, from `/etc/ethswarm/<service>.toml` ([`config_path`]; the path is a
//! parameter so tests and other layouts can point elsewhere).
//!
//! ```toml
//! network = "sepolia"          # resolved through network-config (embedded, sha256-pinned)
//! # network_dir = "/etc/ethswarm/network"   # or: a devnet's config.yaml and genesis.ssz
//! metrics_port = 9104          # /metrics on 127.0.0.1 only; 9100..=9199
//! metrics_max_connections = 8  # optional: /metrics connections served at once; 1..=1024
//! drain_timeout_ms = 10000     # optional: in-flight calls get this long after SIGTERM
//! log_level = "info"           # optional: error, warn, info, debug, trace
//!
//! [socket]
//! group = 991                  # GID of the callers allowed to connect
//! root = "/run/ethswarm"       # optional
//!
//! [callers]                    # the method ACL (ipc::acl)
//! cl-chain = 990
//!
//! [methods]
//! "/ethswarm.engine.v1.EngineService/NewPayload" = ["cl-chain"]
//!
//! [chain]                      # the service's own table: [chain], [discv5] or [p2p]
//! ```
//!
//! - **The network.** Exactly one of `network` (a pinned network, with its pinned genesis where
//!   there is one) and `network_dir` (an absolute path to a devnet's `config.yaml` and
//!   `genesis.ssz`, read by `network_config::network_dir`).
//! - **The service's table.** cl-chain reads `[chain]`, cl-discv5 `[discv5]` and cl-p2p `[p2p]`
//!   ([`Config::section`]); the table of another service is refused, so a config cannot be put
//!   at the wrong path by mistake. The service's own type refuses the keys it does not know.
//!
//! Unknown keys are refused, so a typo fails startup instead of silently falling back to a
//! default. The socket's owner is the user the service runs as. A deployed binary reads the
//! file through [`Config::load_root_owned`]: only if root owns it and its path, and the
//! service user cannot change either ([`crate::owned`]).

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipc::acl::{AclError, AclTables, MethodAcl};
use ipc::uds::{BindError, Ownership, SocketDir};
use network_config::network_dir::{NetworkDir, NetworkDirError};
use network_config::{ChainConfig, Genesis, Network};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tracing_subscriber::filter::LevelFilter;

use crate::telemetry::{MetricsLimits, MAX_METRICS_CONNECTIONS};

/// How long in-flight calls get after SIGTERM unless configured.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The `/metrics` ports services use (`127.0.0.1:91NN`).
pub const METRICS_PORTS: RangeInclusive<u16> = 9100..=9199;

/// `/etc/ethswarm/<service>.toml`.
#[must_use]
pub fn config_path(service: &str) -> PathBuf {
    ipc::acl::config_path(service)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    network: Option<String>,
    network_dir: Option<PathBuf>,
    metrics_port: u16,
    metrics_max_connections: Option<usize>,
    drain_timeout_ms: Option<u64>,
    log_level: Option<String>,
    socket: SocketSection,
    #[serde(default)]
    callers: BTreeMap<String, u32>,
    #[serde(default)]
    methods: BTreeMap<String, Vec<String>>,
    chain: Option<toml::Table>,
    discv5: Option<toml::Table>,
    p2p: Option<toml::Table>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SocketSection {
    root: Option<PathBuf>,
    group: u32,
}

/// Why a config did not load.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{}: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("unknown network {name:?} (known: {known:?})")]
    Network {
        name: String,
        known: Vec<&'static str>,
    },
    #[error("network config: {0}")]
    Chain(#[from] network_config::ConfigError),
    #[error("give exactly one of network and network_dir")]
    NetworkSource,
    #[error("network_dir {} must be an absolute path", .0.display())]
    NetworkDirRelative(PathBuf),
    #[error("network_dir: {0}")]
    NetworkDir(#[from] NetworkDirError),
    #[error("[{table}] is not a table of {service}: is this the config of another service?")]
    ForeignTable { table: String, service: String },
    #[error("[{table}]: {message}")]
    Section { table: String, message: String },
    #[error("{0}")]
    Owned(#[from] crate::owned::OwnedFileError),
    #[error("metrics_port {0} is outside 9100..=9199")]
    MetricsPort(u16),
    #[error("metrics_max_connections {0} is outside 1..={MAX_METRICS_CONNECTIONS}")]
    MetricsConnections(usize),
    #[error("drain_timeout_ms must be positive")]
    DrainTimeout,
    #[error("log_level {0:?} is not one of error, warn, info, debug, trace")]
    LogLevel(String),
    #[error("socket: {0}")]
    Socket(#[from] BindError),
    #[error("method ACL: {0}")]
    Acl(#[from] Box<AclError>),
}

/// Where the network's config comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkSource {
    /// A network embedded in network-config, sha256-pinned.
    Pinned(Network),
    /// A devnet's directory: its `config.yaml` and `genesis.ssz`.
    Dir(PathBuf),
}

impl NetworkSource {
    /// The pinned network's name, or the directory, for the log.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Pinned(network) => network.name().to_owned(),
            Self::Dir(dir) => dir.display().to_string(),
        }
    }
}

/// The table of `service` in its config file: `chain` for `cl-chain`, `discv5` for
/// `cl-discv5`, `p2p` for `cl-p2p`; `None` for a service without one.
#[must_use]
pub fn section_name(service: &str) -> Option<&'static str> {
    match service {
        "cl-chain" => Some("chain"),
        "cl-discv5" => Some("discv5"),
        "cl-p2p" => Some("p2p"),
        _ => None,
    }
}

/// A loaded, checked service configuration.
#[derive(Debug)]
pub struct Config {
    pub service: String,
    pub network: NetworkSource,
    /// The network's chain config (fork schedule, blob schedule).
    pub chain: ChainConfig,
    /// The network's genesis: the pinned one, or the one of `network_dir`'s genesis state.
    /// `None` for a pinned network without a pinned genesis yet.
    pub genesis: Option<Genesis>,
    /// The `/metrics` port on 127.0.0.1. 0 lets the OS pick one (tests only; a config file
    /// must name a 91NN port).
    pub metrics_port: u16,
    /// Bounds on `/metrics` connections.
    pub metrics_limits: MetricsLimits,
    pub drain_timeout: Duration,
    pub log_level: LevelFilter,
    pub socket: SocketDir,
    /// The socket's owner (this process's user) and group (its allowed callers).
    pub ownership: Ownership,
    pub acl: MethodAcl,
    /// `[callers]`: caller name to UID, as the ACL resolved them.
    pub callers: BTreeMap<String, u32>,
    /// The service's own table ([`section_name`]), if the file has one.
    section: Option<toml::Table>,
}

impl Config {
    /// Loads `service`'s config from `path`.
    pub fn load(service: &str, path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(service, &text, path)
    }

    /// Loads `service`'s config from `path`, for a service that runs as effective UID `euid`,
    /// only if root (or `accepted_owner`, 0 in a deployed binary) owns the file and every
    /// directory on its path, and `euid` can write none of them ([`crate::owned`]).
    pub fn load_root_owned(
        service: &str,
        path: &Path,
        euid: u32,
        accepted_owner: u32,
    ) -> Result<Self, ConfigError> {
        let text = crate::owned::read_root_owned(path, euid, accepted_owner)?;
        Self::from_toml(service, &text, path)
    }

    /// The service's own table as `T` ([`section_name`]); with no table in the file, `T` of an
    /// empty table.
    pub fn section<T: DeserializeOwned>(&self) -> Result<T, ConfigError> {
        let table = section_name(&self.service).unwrap_or("none");
        toml::Value::Table(self.section.clone().unwrap_or_default())
            .try_into()
            .map_err(|e: toml::de::Error| ConfigError::Section {
                table: table.to_owned(),
                message: e.message().trim_end().to_owned(),
            })
    }

    /// Parses config text (`path` names it in errors).
    pub fn from_toml(service: &str, text: &str, path: &Path) -> Result<Self, ConfigError> {
        let file: File = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        let (network, chain, genesis) = match (file.network, file.network_dir) {
            (Some(name), None) => {
                let network = Network::ALL
                    .into_iter()
                    .find(|n| n.name() == name)
                    .ok_or_else(|| ConfigError::Network {
                        name: name.clone(),
                        known: Network::ALL.iter().map(|n| n.name()).collect(),
                    })?;
                let chain = ChainConfig::load(network)?;
                (NetworkSource::Pinned(network), chain, network.genesis())
            }
            (None, Some(dir)) => {
                if !dir.is_absolute() {
                    return Err(ConfigError::NetworkDirRelative(dir));
                }
                let read = NetworkDir::read(&dir)?;
                (NetworkSource::Dir(dir), read.config, Some(read.genesis))
            }
            _ => return Err(ConfigError::NetworkSource),
        };
        let own = section_name(service);
        let mut section = None;
        for (name, table) in [
            ("chain", file.chain),
            ("discv5", file.discv5),
            ("p2p", file.p2p),
        ] {
            match table {
                Some(table) if own == Some(name) => section = Some(table),
                Some(_) => {
                    return Err(ConfigError::ForeignTable {
                        table: name.to_owned(),
                        service: service.to_owned(),
                    })
                }
                None => {}
            }
        }
        if !METRICS_PORTS.contains(&file.metrics_port) {
            return Err(ConfigError::MetricsPort(file.metrics_port));
        }
        let metrics_limits = match file.metrics_max_connections {
            None => MetricsLimits::default(),
            Some(n) if n == 0 || n > MAX_METRICS_CONNECTIONS => {
                return Err(ConfigError::MetricsConnections(n))
            }
            Some(n) => MetricsLimits {
                max_connections: n,
                ..MetricsLimits::default()
            },
        };
        let drain_timeout = match file.drain_timeout_ms {
            None => DEFAULT_DRAIN_TIMEOUT,
            Some(0) => return Err(ConfigError::DrainTimeout),
            Some(ms) => Duration::from_millis(ms),
        };
        let log_level = match file.log_level.as_deref() {
            None => LevelFilter::INFO,
            Some(level) => level
                .parse::<tracing::Level>()
                .map(LevelFilter::from_level)
                .ok()
                .filter(|_| level.bytes().all(|b| b.is_ascii_lowercase()))
                .ok_or_else(|| ConfigError::LogLevel(level.to_owned()))?,
        };
        let socket = match &file.socket.root {
            Some(root) => SocketDir::under(root, service)?,
            None => SocketDir::new(service)?,
        };
        let tables = AclTables {
            callers: file.callers,
            methods: file.methods,
        };
        let acl = MethodAcl::from_tables(service, &tables).map_err(Box::new)?;
        Ok(Self {
            service: service.to_owned(),
            network,
            chain,
            genesis,
            metrics_port: file.metrics_port,
            metrics_limits,
            drain_timeout,
            log_level,
            socket,
            ownership: Ownership {
                uid: ipc::peercred::effective_uid(),
                gid: file.socket.group,
            },
            acl,
            callers: tables.callers,
            section,
        })
    }

    /// The same config serving metrics on a port the OS picks (tests run many services).
    #[must_use]
    pub fn with_ephemeral_metrics_port(mut self) -> Self {
        self.metrics_port = 0;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEW_PAYLOAD: &str = "/ethswarm.engine.v1.EngineService/NewPayload";

    fn engine(extra: &str) -> String {
        format!(
            "network = \"sepolia\"\nmetrics_port = 9103\n{extra}\n[socket]\ngroup = 991\n\
             [callers]\ncl-chain = 990\n[methods]\n\"{NEW_PAYLOAD}\" = [\"cl-chain\"]\n"
        )
    }

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::from_toml("cl-engine", text, Path::new("cl-engine.toml"))
    }

    #[test]
    fn loads_a_complete_config() {
        let c = parse(&engine(
            "drain_timeout_ms = 2500\nlog_level = \"debug\"\nmetrics_max_connections = 3",
        ))
        .unwrap();
        assert_eq!(c.metrics_limits.max_connections, 3);
        assert_eq!(c.service, "cl-engine");
        assert_eq!(c.network, NetworkSource::Pinned(Network::Sepolia));
        assert_eq!(c.chain.config_name(), "sepolia");
        assert_eq!(c.metrics_port, 9103);
        assert_eq!(c.drain_timeout, Duration::from_millis(2500));
        assert_eq!(c.log_level, LevelFilter::DEBUG);
        assert_eq!(
            c.socket.socket_path(),
            Path::new("/run/ethswarm/cl-engine/cl-engine.sock")
        );
        assert_eq!(c.ownership.gid, 991);
        assert_eq!(c.ownership.uid, ipc::peercred::effective_uid());
        assert!(c.acl.allows(NEW_PAYLOAD, 990));
        assert_eq!(c.with_ephemeral_metrics_port().metrics_port, 0);
    }

    #[test]
    fn metrics_connections_up_to_the_cap_load() {
        for n in [1, MAX_METRICS_CONNECTIONS] {
            let c = parse(&engine(&format!("metrics_max_connections = {n}"))).unwrap();
            assert_eq!(c.metrics_limits.max_connections, n);
        }
        let err = parse(&engine("metrics_max_connections = 1025")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "metrics_max_connections 1025 is outside 1..=1024"
        );
    }

    #[test]
    fn defaults_and_socket_root() {
        let text = engine("").replace("group = 991", "group = 991\nroot = \"/tmp/rt\"");
        let c = parse(&text).unwrap();
        assert_eq!(c.drain_timeout, DEFAULT_DRAIN_TIMEOUT);
        assert_eq!(c.metrics_limits, MetricsLimits::default());
        assert_eq!(c.log_level, LevelFilter::INFO);
        assert_eq!(c.socket.dir(), Path::new("/tmp/rt/cl-engine"));
        assert_eq!(
            config_path("cl-engine"),
            Path::new("/etc/ethswarm/cl-engine.toml")
        );
    }

    type Case = (String, fn(&ConfigError) -> bool);

    #[test]
    fn bad_configs_fail_startup() {
        let cases: Vec<Case> = vec![
            (engine("").replace("sepolia", "mainnet"), |e| {
                matches!(e, ConfigError::Network { .. })
            }),
            (engine("").replace("9103", "8080"), |e| {
                matches!(e, ConfigError::MetricsPort(8080))
            }),
            (engine("").replace("9103", "0"), |e| {
                matches!(e, ConfigError::MetricsPort(0))
            }),
            (engine("metrics_max_connections = 0"), |e| {
                matches!(e, ConfigError::MetricsConnections(0))
            }),
            (engine("metrics_max_connections = 1025"), |e| {
                matches!(e, ConfigError::MetricsConnections(1025))
            }),
            // Above tokio's `Semaphore::MAX_PERMITS`, which would panic when /metrics starts.
            (
                engine("metrics_max_connections = 2305843009213693952"),
                |e| {
                    matches!(
                        e,
                        ConfigError::MetricsConnections(2_305_843_009_213_693_952)
                    )
                },
            ),
            (engine("drain_timeout_ms = 0"), |e| {
                matches!(e, ConfigError::DrainTimeout)
            }),
            (engine("log_level = \"loud\""), |e| {
                matches!(e, ConfigError::LogLevel(_))
            }),
            (engine("log_level = \"INFO\""), |e| {
                matches!(e, ConfigError::LogLevel(_))
            }),
            (engine("metrics_address = \"0.0.0.0\""), |e| {
                matches!(e, ConfigError::Parse { .. })
            }),
            (
                engine("").replace("group = 991", "group = 991\nmode = 511"),
                |e| matches!(e, ConfigError::Parse { .. }),
            ),
            (
                engine("").replace("[\"cl-chain\"]", "[\"cl-chain\", \"cl-api\"]"),
                |e| matches!(e, ConfigError::Acl(_)),
            ),
        ];
        for (text, want) in cases {
            let err = parse(&text).unwrap_err();
            assert!(want(&err), "{text}\n=> {err}");
        }
        let err = Config::from_toml("Engine", &engine(""), Path::new("x")).unwrap_err();
        assert!(matches!(err, ConfigError::Socket(_)), "{err}");
    }

    const GET_STATUS: &str = "/ethswarm.chain.v1.ReqRespService/GetStatus";

    /// A cl-chain config: `network` (a whole line), then `extra` before the tables.
    fn chain(network: &str, extra: &str) -> String {
        format!(
            "{network}\nmetrics_port = 9102\n{extra}\n[socket]\ngroup = 991\n\
             [callers]\ncl-p2p = 992\n[methods]\n\"{GET_STATUS}\" = [\"cl-p2p\"]\n"
        )
    }

    fn parse_chain(text: &str) -> Result<Config, ConfigError> {
        Config::from_toml("cl-chain", text, Path::new("cl-chain.toml"))
    }

    /// A devnet's `config.yaml` and `genesis.ssz` in a new directory.
    fn network_dir() -> tempfile::TempDir {
        use ipc::testkit::devnet::{devnet_genesis_state, write_network_file, DEVNET_CONFIG};
        let dir = tempfile::tempdir().unwrap();
        write_network_file(dir.path().join("config.yaml"), DEVNET_CONFIG);
        write_network_file(dir.path().join("genesis.ssz"), devnet_genesis_state(64));
        dir
    }

    #[test]
    fn a_network_dir_gives_the_devnets_config_and_genesis() {
        let dir = network_dir();
        let line = format!("network_dir = \"{}\"", dir.path().display());
        let c = parse_chain(&chain(&line, "")).unwrap();
        assert_eq!(c.network, NetworkSource::Dir(dir.path().to_owned()));
        assert_eq!(c.network.name(), dir.path().display().to_string());
        assert_eq!(c.chain.config_name(), "fixture-devnet");
        assert_eq!(c.genesis, Some(ipc::testkit::devnet::DEVNET_GENESIS));
        // A pinned network gives its pinned genesis.
        let c = parse_chain(&chain("network = \"sepolia\"", "")).unwrap();
        assert_eq!(c.network, NetworkSource::Pinned(Network::Sepolia));
        assert_eq!(c.network.name(), "sepolia");
        assert_eq!(c.genesis, Network::Sepolia.genesis());
    }

    #[test]
    fn the_network_is_named_once() {
        let dir = network_dir();
        let both = format!(
            "network = \"sepolia\"\nnetwork_dir = \"{}\"",
            dir.path().display()
        );
        for text in [chain(&both, ""), chain("", "")] {
            let err = parse_chain(&text).unwrap_err();
            assert!(matches!(err, ConfigError::NetworkSource), "{err}");
        }
        let err = parse_chain(&chain("network_dir = \"net\"", "")).unwrap_err();
        assert!(matches!(err, ConfigError::NetworkDirRelative(_)), "{err}");
        let missing = format!("network_dir = \"{}\"", dir.path().join("x").display());
        let err = parse_chain(&chain(&missing, "")).unwrap_err();
        assert!(matches!(err, ConfigError::NetworkDir(_)), "{err}");
    }

    #[derive(Debug, Default, PartialEq, serde::Deserialize)]
    #[serde(deny_unknown_fields, default)]
    struct ChainTable {
        node_id: String,
        verify_uid: u32,
    }

    /// Each service reads its own table (`[chain]` for cl-chain); a table of another service in
    /// its file is refused, and so is an unknown key in its own.
    #[test]
    fn a_service_reads_its_own_table() {
        let net = "network = \"sepolia\"";
        let table = "[chain]\nnode_id = \"0x01\"\nverify_uid = 7\n";
        let text = format!("{}{table}", chain(net, ""));
        let c = parse_chain(&text).unwrap();
        assert_eq!(
            c.section::<ChainTable>().unwrap(),
            ChainTable {
                node_id: "0x01".into(),
                verify_uid: 7
            }
        );
        // No table: the type's defaults.
        let c = parse_chain(&chain(net, "")).unwrap();
        assert_eq!(c.section::<ChainTable>().unwrap(), ChainTable::default());
        // Another service's table.
        let err = parse_chain(&format!("{}[p2p]\nlisten = 1\n", chain(net, ""))).unwrap_err();
        assert!(
            matches!(&err, ConfigError::ForeignTable { table, service }
                if table == "p2p" && service == "cl-chain"),
            "{err}"
        );
        let err = parse(&format!("{}[chain]\nnode_id = \"0x01\"\n", engine(""))).unwrap_err();
        assert!(matches!(err, ConfigError::ForeignTable { .. }), "{err}");
        // A key its type does not know.
        let c = parse_chain(&format!("{}[chain]\nnode_idd = \"0x01\"\n", chain(net, ""))).unwrap();
        let err = c.section::<ChainTable>().unwrap_err();
        assert!(
            matches!(&err, ConfigError::Section { table, .. } if table == "chain"),
            "{err}"
        );
    }

    #[test]
    fn the_callers_are_kept() {
        let c = parse_chain(&chain("network = \"sepolia\"", "")).unwrap();
        assert_eq!(c.callers.get("cl-p2p"), Some(&992));
        assert!(c.acl.allows(GET_STATUS, 992));
    }

    /// The deployed binaries read their config only through the owner walk
    /// ([`crate::owned::read_root_owned`]).
    #[test]
    fn load_root_owned_reads_through_the_walk() {
        use crate::owned::testkit::{config_root, write_read_only, Sealed};
        let me = ipc::peercred::effective_uid();
        let dir = tempfile::Builder::new().tempdir_in(config_root()).unwrap();
        let path = dir.path().join("cl-chain.toml");
        write_read_only(&path, &chain("network = \"sepolia\"", ""));
        let sealed = Sealed::new(dir.path());
        let c = Config::load_root_owned("cl-chain", &path, me + 1, me).unwrap();
        assert_eq!(c.metrics_port, 9102);
        // The service's own UID may write it: refused.
        drop(sealed);
        let err = Config::load_root_owned("cl-chain", &path, me, me).unwrap_err();
        assert!(matches!(err, ConfigError::Owned(_)), "{err}");
    }

    #[test]
    fn load_reads_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cl-engine.toml");
        let err = Config::load("cl-engine", &path).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err}");
        std::fs::write(&path, engine("")).unwrap();
        assert_eq!(Config::load("cl-engine", &path).unwrap().metrics_port, 9103);
    }
}
