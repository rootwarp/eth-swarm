//! The systemd units of the eight services, and `ethswarm.target` that groups them.
//!
//! One unit per service (`ethswarm-<svc>.service`), each with its own user and primary group
//! `ethswarm-<svc>`. That group is also the group of the service's socket
//! (`/run/ethswarm/cl-<svc>/cl-<svc>.sock`, 0660 in a 0750 directory): svc-runtime refuses a
//! socket group that is not the process's primary group, because changing it would need a chown
//! that `SystemCallFilter=~@privileged` kills. So a caller reaches a socket by holding the
//! callee's group as a supplementary group, and the units list exactly the groups of ARCH V-9.
//!
//! The text is deterministic: no timestamps, fixed key order, one trailing newline.

use std::fmt::{self, Write as _};
use std::path::Path;

/// The unit that wants all eight services.
pub const TARGET: &str = "ethswarm.target";
/// Where `ExecStart=` looks for the service binaries unless `--bin-dir` says otherwise.
pub const DEFAULT_BIN_DIR: &str = "/usr/local/bin";
/// The network unless `--network` says otherwise. It only names itself in `Description=`.
pub const DEFAULT_NETWORK: &str = "mainnet";
/// Where `LoadCredential=` reads the secrets from (root-owned, ADR-009).
pub const CREDENTIALS_DIR: &str = "/etc/ethswarm/credentials";

/// cl-sync's address families. ARCH lists "cl-sync → providers HTTPS" (the checkpoint fetch),
/// but Vera's M4 list gives it none, and today's cl-sync service makes no network call: the
/// stricter profile wins until it does.
// TODO(cl-sync checkpoint fetch): add "AF_INET AF_INET6" here when cl-sync gains its checkpoint
// fetch (and a test that the fetch runs under the unit).
pub const SYNC_ADDRESS_FAMILIES: &str = "AF_UNIX";

/// The eight services.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Service {
    Verify,
    Engine,
    Chain,
    Store,
    Discv5,
    P2p,
    Sync,
    Api,
}

use Service::*;

impl Service {
    /// The start order (issue #205): each service is ready before the next one starts.
    pub const START_ORDER: [Service; 8] = [Verify, Engine, Chain, Store, Discv5, P2p, Sync, Api];

    /// `chain` for cl-chain.
    pub const fn short(self) -> &'static str {
        match self {
            Verify => "verify",
            Engine => "engine",
            Chain => "chain",
            Store => "store",
            Discv5 => "discv5",
            P2p => "p2p",
            Sync => "sync",
            Api => "api",
        }
    }

    /// The binary and service name, `cl-chain`.
    pub fn binary(self) -> String {
        format!("cl-{}", self.short())
    }

    /// The service's user, which is also its primary group and its socket's group.
    pub fn user(self) -> String {
        format!("ethswarm-{}", self.short())
    }

    /// `ethswarm-chain.service`.
    pub fn unit_name(self) -> String {
        format!("ethswarm-{}.service", self.short())
    }

    /// ARCH V-9: the services that call this one. cl-api's caller is the operator (cl-node),
    /// which is no unit: an operator account joins `ethswarm-api` by hand.
    pub const fn callers(self) -> &'static [Service] {
        match self {
            Chain => &[P2p, Sync, Api, Store],
            Verify | Engine => &[Chain],
            Store => &[Api, Sync, P2p],
            P2p => &[Chain, Sync, Api],
            Discv5 => &[P2p, Api],
            Sync => &[Api],
            Api => &[],
        }
    }

    /// The groups this service joins to call others (`SupplementaryGroups=`), sorted.
    pub fn caller_groups(self) -> Vec<String> {
        let mut groups: Vec<String> = Self::START_ORDER
            .into_iter()
            .filter(|callee| callee.callers().contains(&self))
            .map(Service::user)
            .collect();
        groups.sort();
        groups
    }

    /// ADR-009: the credentials this service gets, by systemd credential name. No other
    /// service gets one.
    pub const fn credentials(self) -> &'static [&'static str] {
        match self {
            Engine => &["jwt"],
            P2p | Discv5 => &["nodekey"],
            _ => &[],
        }
    }

    /// ARCH: the services that keep state (`StateDirectory=ethswarm-<svc>`, 0700).
    const fn stateful(self) -> bool {
        matches!(self, Chain | Verify | P2p | Discv5 | Sync)
    }

    /// `RestrictAddressFamilies=`: AF_UNIX for the sockets, IP only for the services that talk
    /// to the network (the EL, peers, discovery, the REST API).
    const fn address_families(self) -> &'static str {
        match self {
            // libp2p-tcp watches the interfaces (if-watch) through a netlink route socket for
            // its wildcard listen; without AF_NETLINK the listen fails at start.
            P2p => "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            Engine | Discv5 | Api => "AF_UNIX AF_INET AF_INET6",
            Sync => SYNC_ADDRESS_FAMILIES,
            Verify | Chain | Store => "AF_UNIX",
        }
    }

    /// ARCH §9: `(MemoryHigh, MemoryMax, MemorySwapMax=0)`. Only cl-chain gets a soft limit
    /// and no swap; the supernode profile (off by default) raises cl-p2p for its columns.
    const fn memory(self, supernode: bool) -> (Option<&'static str>, &'static str, bool) {
        match self {
            Chain => (Some("2G"), "3G", true),
            P2p if supernode => (Some("1G"), "1536M", false),
            P2p => (None, "768M", false),
            Verify | Store => (None, "512M", false),
            Engine => (None, "256M", false),
            Discv5 => (None, "128M", false),
            Sync | Api => (None, "1G", false),
        }
    }

    /// `After=` (ruling: ordering only, no Requires=/BindsTo=, so one service's failure never
    /// stops another): cl-chain after its two dependencies, everything later after cl-chain.
    fn after(self) -> &'static [Service] {
        match self {
            Verify | Engine => &[],
            Chain => &[Verify, Engine],
            Store | Discv5 | P2p | Sync | Api => &[Chain],
        }
    }
}

/// Why a [`Config`] value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// What the units depend on. The fields are checked by [`Config::new`]: systemd would expand
/// `%` specifiers, `$` variables, quotes, backslashes and whitespace in them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    network: String,
    supernode: bool,
    bin_dir: String,
}

impl Config {
    /// `network`: 1 to 32 of `a-z 0-9 . _ -`. `bin_dir`: an absolute path of `A-Z a-z 0-9 . _ + -`
    /// components, none `.` or `..`, not `/` itself.
    pub fn new(network: &str, supernode: bool, bin_dir: &Path) -> Result<Self, ConfigError> {
        let network_ok = (1..=32).contains(&network.len())
            && network
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        if !network_ok {
            return Err(ConfigError(format!(
                "network {network:?}: want 1 to 32 of a-z 0-9 . _ -"
            )));
        }
        let refused = || ConfigError(format!("bin dir {bin_dir:?}: {}", Self::BIN_DIR_RULE));
        let raw = bin_dir.to_str().ok_or_else(refused)?;
        let parts: Vec<&str> = raw.split('/').filter(|p| !p.is_empty()).collect();
        let part_ok = |p: &&str| {
            *p != "."
                && *p != ".."
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        };
        if !raw.starts_with('/')
            || raw.len() > 200
            || parts.is_empty()
            || !parts.iter().all(part_ok)
        {
            return Err(refused());
        }
        Ok(Self {
            network: network.to_owned(),
            supernode,
            bin_dir: format!("/{}", parts.join("/")),
        })
    }

    const BIN_DIR_RULE: &'static str =
        "want an absolute path of A-Z a-z 0-9 . _ + - components, none . or .., not /";

    /// The directory `ExecStart=` runs the binaries from.
    pub fn bin_dir(&self) -> &Path {
        Path::new(&self.bin_dir)
    }

    pub fn network(&self) -> &str {
        &self.network
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: DEFAULT_NETWORK.into(),
            supernode: false,
            bin_dir: DEFAULT_BIN_DIR.into(),
        }
    }
}

/// One unit file: its name and its full text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub name: String,
    pub text: String,
}

const HEADER: &str =
    "# Generated by `cl-node units`. Do not edit: regenerate it (crates/cl-node/README.md).\n";

/// `TimeoutStartSec=`, and `launch`'s default ready timeout: covers cl-chain's 30 s wait for
/// cl-verify and opening its store.
pub const START_TIMEOUT_SECS: u64 = 90;
/// `TimeoutStopSec=`, and `launch`'s default grace before SIGKILL: covers svc-runtime's 10 s
/// drain and cl-verify's snapshot flush.
pub const STOP_TIMEOUT_SECS: u64 = 30;

/// Type=notify: ready when the service sends READY=1 (its socket is bound with its final owner
/// and mode). RestartSec=5s stays under the default start limit, so a crash loop keeps retrying.
fn lifecycle() -> String {
    format!(
        "Type=notify\nNotifyAccess=main\nTimeoutStartSec={START_TIMEOUT_SECS}s\n\
         TimeoutStopSec={STOP_TIMEOUT_SECS}s\nRestart=on-failure\nRestartSec=5s\n"
    )
}

/// The ops/probe hardening block (Vera, M4). UMask=0077: ipc sets the socket (0660), its
/// directory (0750) and lock (0600) modes explicitly and systemd sets RuntimeDirectoryMode= and
/// StateDirectoryMode=, so nothing needs a looser umask.
const HARDENING: &str = "\
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
";

/// The eight service units in start order, then [`TARGET`].
pub fn generate(config: &Config) -> Vec<Unit> {
    let mut units: Vec<Unit> = Service::START_ORDER
        .into_iter()
        .map(|svc| service_unit(svc, config))
        .collect();
    units.push(target_unit(config));
    units
}

fn names(services: &[Service]) -> String {
    let names: Vec<String> = services.iter().map(|s| s.unit_name()).collect();
    names.join(" ")
}

fn service_unit(svc: Service, config: &Config) -> Unit {
    // Writing to a String cannot fail.
    let mut t = String::from(HEADER);
    let bin = svc.binary();
    let _ = write!(
        t,
        "[Unit]\nDescription=ETH Swarm ({}): {bin}\n",
        config.network
    );
    if !svc.after().is_empty() {
        let _ = writeln!(t, "After={}", names(svc.after()));
    }
    let _ = write!(t, "PartOf={TARGET}\n\n[Service]\n{}", lifecycle());
    let _ = writeln!(t, "ExecStart={}/{bin}", config.bin_dir);
    let user = svc.user();
    let _ = write!(t, "User={user}\nGroup={user}\n");
    let groups = svc.caller_groups();
    if !groups.is_empty() {
        t.push_str("# The groups of the sockets it calls (ARCH V-9).\n");
        let _ = writeln!(t, "SupplementaryGroups={}", groups.join(" "));
    }
    let _ = write!(
        t,
        "RuntimeDirectory=ethswarm/{bin}\nRuntimeDirectoryMode=0750\n"
    );
    if svc.stateful() {
        let _ = write!(t, "StateDirectory={user}\nStateDirectoryMode=0700\n");
    }
    for name in svc.credentials() {
        let _ = writeln!(t, "LoadCredential={name}:{CREDENTIALS_DIR}/{name}");
    }
    let (high, max, no_swap) = svc.memory(config.supernode);
    if let Some(high) = high {
        let _ = writeln!(t, "MemoryHigh={high}");
    }
    let _ = writeln!(t, "MemoryMax={max}");
    if no_swap {
        t.push_str("MemorySwapMax=0\n");
    }
    if svc == Sync {
        t.push_str("# No IP until cl-sync fetches its checkpoint (crates/cl-node/README.md).\n");
    }
    let _ = writeln!(t, "RestrictAddressFamilies={}", svc.address_families());
    let _ = write!(t, "{HARDENING}\n[Install]\nWantedBy={TARGET}\n");
    Unit {
        name: svc.unit_name(),
        text: t,
    }
}

fn target_unit(config: &Config) -> Unit {
    let mut t = String::from(HEADER);
    let _ = writeln!(
        t,
        "[Unit]\nDescription=ETH Swarm beacon node ({}): the eight services",
        config.network
    );
    for svc in Service::START_ORDER {
        let _ = writeln!(t, "Wants={}", svc.unit_name());
    }
    t.push_str("\n[Install]\nWantedBy=multi-user.target\n");
    Unit {
        name: TARGET.into(),
        text: t,
    }
}
