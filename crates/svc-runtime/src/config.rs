//! A service's configuration, from `/etc/ethswarm/<service>.toml` ([`config_path`]; the path is a
//! parameter so tests and other layouts can point elsewhere).
//!
//! ```toml
//! network = "sepolia"          # resolved through network-config (embedded, sha256-pinned)
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
//! ```
//!
//! Unknown keys are refused, so a typo fails startup instead of silently falling back to a
//! default. The socket's owner is the user the service runs as.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipc::acl::{AclError, AclTables, MethodAcl};
use ipc::uds::{BindError, Ownership, SocketDir};
use network_config::{ChainConfig, Network};
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
    network: String,
    metrics_port: u16,
    metrics_max_connections: Option<usize>,
    drain_timeout_ms: Option<u64>,
    log_level: Option<String>,
    socket: SocketSection,
    #[serde(default)]
    callers: BTreeMap<String, u32>,
    #[serde(default)]
    methods: BTreeMap<String, Vec<String>>,
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

/// A loaded, checked service configuration.
#[derive(Debug)]
pub struct Config {
    pub service: String,
    pub network: Network,
    /// The network's chain config (fork schedule, blob schedule).
    pub chain: ChainConfig,
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

    /// Parses config text (`path` names it in errors).
    pub fn from_toml(service: &str, text: &str, path: &Path) -> Result<Self, ConfigError> {
        let file: File = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        let network = Network::ALL
            .into_iter()
            .find(|n| n.name() == file.network)
            .ok_or_else(|| ConfigError::Network {
                name: file.network.clone(),
                known: Network::ALL.iter().map(|n| n.name()).collect(),
            })?;
        let chain = ChainConfig::load(network)?;
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
        let acl = MethodAcl::from_tables(
            service,
            &AclTables {
                callers: file.callers,
                methods: file.methods,
            },
        )
        .map_err(Box::new)?;
        Ok(Self {
            service: service.to_owned(),
            network,
            chain,
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
        assert_eq!(c.network, Network::Sepolia);
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
