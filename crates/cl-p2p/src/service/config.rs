//! The `[p2p]` table of `/etc/ethswarm/cl-p2p.toml`.
//!
//! ```toml
//! [p2p]
//! listen = ["/ip4/0.0.0.0/tcp/9000"]                     # optional, this default
//! chain_socket = "/run/ethswarm/cl-chain/cl-chain.sock"  # optional, this default
//! chain_uid = 990                                        # the UID of ethswarm-chain
//! discv5_socket = "/run/ethswarm/cl-discv5/cl-discv5.sock"   # optional, this default
//! discv5_uid = 992                                       # the UID of ethswarm-discv5
//! gossip_topics = "/etc/ethswarm/gossip-topics.toml"     # optional, this default
//! target_peers = 32                                      # optional: 1 to 32, our dials
//! static_peers = ["/ip4/10.0.0.2/tcp/9000/p2p/16Uiu2…"]  # optional: always dialled
//! answer_prefix_v4 = 24                                  # optional: 1 to 32
//! answer_prefix_v6 = 48                                  # optional: 1 to 128
//! chain_wait_ms = 30000                                  # optional: cl-chain's start
//! mode = "public"                                        # optional: public, devnet or local
//!
//! [p2p.goodbye_ledger]                                   # optional: GoodbyeLedgerConfig
//! goodbye3_threshold_pct = 2.0
//! ```
//!
//! - **`gossip_topics`** is read as the config file is: only if root owns it and its path, and
//!   the service user can write none of them (`svc_runtime::owned`). It is
//!   `ops/probe/gossip-topics.toml` ([`TopicList`]).
//! - **`static_peers`** are `/ip4|ip6/<addr>/tcp/<port>/p2p/<peer id>` ([`PinnedPeer`]): the
//!   reference nodes. They are dialled at start and again after each disconnect, and the
//!   connection caps do not apply to them.
//! - **`mode`** is the IP rule of the candidates' addresses (`p2p_wire::ip::ip_rule`), the
//!   rule of cl-discv5's `mode`: give both the same value. The static peers do not obey it.

use crate::gossip::TopicList;
use crate::m2a_session::PinnedPeer;
use crate::peers::manager::{GoodbyeLedger, GoodbyeLedgerConfig};
use crate::rpc::answer_bucket::AnswerPrefixes;
use libp2p::Multiaddr;
use p2p_wire::ip::NetworkMode;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// cl-chain's socket unless `chain_socket` says otherwise.
pub const DEFAULT_CHAIN_SOCKET: &str = "/run/ethswarm/cl-chain/cl-chain.sock";

/// cl-discv5's socket unless `discv5_socket` says otherwise.
pub const DEFAULT_DISCV5_SOCKET: &str = "/run/ethswarm/cl-discv5/cl-discv5.sock";

/// The topic list unless `gossip_topics` says otherwise.
pub const DEFAULT_GOSSIP_TOPICS: &str = "/etc/ethswarm/gossip-topics.toml";

/// Where the swarm listens unless `listen` says otherwise.
pub const DEFAULT_LISTEN: &str = "/ip4/0.0.0.0/tcp/9000";

/// The most peers the dialer keeps: the outbound slots of the connection caps
/// (`ConnectionCaps::max_established` less `max_established_incoming`), which inbound peers
/// cannot take.
pub const MAX_TARGET_PEERS: usize = 32;

/// The peers the dialer keeps connected by default \[est\]: the 1 h exit run needs at least
/// 25 for 95 % of the hour, and inbound peers come in addition.
pub const DEFAULT_TARGET_PEERS: usize = MAX_TARGET_PEERS;

/// How long the start waits for cl-chain by default.
pub const DEFAULT_CHAIN_WAIT: Duration = Duration::from_secs(30);

/// The longest `chain_wait_ms`.
pub const MAX_CHAIN_WAIT: Duration = Duration::from_secs(600);

/// The `[p2p]` table as written.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct P2pTable {
    listen: Option<Vec<String>>,
    chain_socket: Option<PathBuf>,
    chain_uid: Option<u32>,
    discv5_socket: Option<PathBuf>,
    discv5_uid: Option<u32>,
    gossip_topics: Option<PathBuf>,
    target_peers: Option<usize>,
    #[serde(default)]
    static_peers: Vec<String>,
    answer_prefix_v4: Option<u8>,
    answer_prefix_v6: Option<u8>,
    chain_wait_ms: Option<u64>,
    mode: Option<String>,
    #[serde(default)]
    goodbye_ledger: GoodbyeLedgerConfig,
}

/// What cl-p2p runs with, from its `[p2p]` table, checked.
#[derive(Debug, Clone)]
pub struct P2pSettings {
    /// Where the swarm listens.
    pub listen: Vec<Multiaddr>,
    /// cl-chain's socket, and the UID its server must run as.
    pub chain_socket: PathBuf,
    /// The UID cl-chain runs as.
    pub chain_uid: u32,
    /// cl-discv5's socket.
    pub discv5_socket: PathBuf,
    /// The UID cl-discv5 runs as.
    pub discv5_uid: u32,
    /// The configured gossip topics.
    pub topics: TopicList,
    /// The peers the dialer keeps connected.
    pub target_peers: usize,
    /// The reference nodes, always dialled.
    pub static_peers: Vec<PinnedPeer>,
    /// The address blocks the column answer places are counted per.
    pub answer_prefixes: AnswerPrefixes,
    /// How long the start waits for cl-chain.
    pub chain_wait: Duration,
    /// The Goodbye ledger's configuration, checked.
    pub goodbye_ledger: GoodbyeLedgerConfig,
    /// The IP rule of the candidates' addresses.
    pub mode: NetworkMode,
}

/// Why the `[p2p]` table was refused. No variant quotes a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum P2pConfigError {
    /// The table does not parse.
    #[error("[p2p]: {0}")]
    Parse(String),
    /// A key is missing.
    #[error("[p2p] {0}: missing")]
    Missing(&'static str),
    /// A key's value was refused.
    #[error("[p2p] {key}: {why}")]
    Key {
        /// The key.
        key: &'static str,
        /// Why.
        why: String,
    },
    /// The topic list was refused.
    #[error("gossip_topics {}: {why}", path.display())]
    Topics {
        /// The file.
        path: PathBuf,
        /// Why.
        why: String,
    },
}

impl P2pSettings {
    /// The settings of a `[p2p]` table (`table`: the deserialized table, from
    /// `svc_runtime::Config::section`), its topic list read through the owner walk for the
    /// effective UID `euid`, with `accepted_owner` the one owner accepted next to root (0 in a
    /// deployed binary).
    ///
    /// # Errors
    ///
    /// The first [`P2pConfigError`] found.
    pub fn from_table(
        table: toml::Table,
        euid: u32,
        accepted_owner: u32,
    ) -> Result<Self, P2pConfigError> {
        let raw: P2pTable = toml::Value::Table(table)
            .try_into()
            .map_err(|e: toml::de::Error| P2pConfigError::Parse(e.message().trim_end().into()))?;
        let key = |key: &'static str, why: &str| P2pConfigError::Key {
            key,
            why: why.to_owned(),
        };
        let listen = raw
            .listen
            .unwrap_or_else(|| vec![DEFAULT_LISTEN.to_owned()])
            .iter()
            .map(|a| a.parse::<Multiaddr>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| key("listen", "not a multiaddr"))?;
        if listen.is_empty() {
            return Err(key("listen", "give at least one address"));
        }
        let absolute = |name: &'static str, path: Option<PathBuf>, default: &str| {
            let path = path.unwrap_or_else(|| PathBuf::from(default));
            if path.is_absolute() {
                Ok(path)
            } else {
                Err(key(name, "must be an absolute path"))
            }
        };
        let chain_socket = absolute("chain_socket", raw.chain_socket, DEFAULT_CHAIN_SOCKET)?;
        let discv5_socket = absolute("discv5_socket", raw.discv5_socket, DEFAULT_DISCV5_SOCKET)?;
        let topics_path = absolute("gossip_topics", raw.gossip_topics, DEFAULT_GOSSIP_TOPICS)?;
        let chain_uid = raw.chain_uid.ok_or(P2pConfigError::Missing("chain_uid"))?;
        let discv5_uid = raw
            .discv5_uid
            .ok_or(P2pConfigError::Missing("discv5_uid"))?;
        let target_peers = raw.target_peers.unwrap_or(DEFAULT_TARGET_PEERS);
        if !(1..=MAX_TARGET_PEERS).contains(&target_peers) {
            return Err(key(
                "target_peers",
                &format!("want 1 to {MAX_TARGET_PEERS}"),
            ));
        }
        let static_peers = raw
            .static_peers
            .iter()
            .map(|p| p.parse::<PinnedPeer>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                key(
                    "static_peers",
                    "want /ip4|ip6/<addr>/tcp/<port>/p2p/<peer id>",
                )
            })?;
        let defaults = AnswerPrefixes::default();
        let answer_prefixes = AnswerPrefixes {
            ipv4: prefix("answer_prefix_v4", raw.answer_prefix_v4, defaults.ipv4, 32)?,
            ipv6: prefix("answer_prefix_v6", raw.answer_prefix_v6, defaults.ipv6, 128)?,
        };
        let chain_wait = match raw.chain_wait_ms {
            None => DEFAULT_CHAIN_WAIT,
            Some(ms) if ms > 0 && u128::from(ms) <= MAX_CHAIN_WAIT.as_millis() => {
                Duration::from_millis(ms)
            }
            Some(_) => return Err(key("chain_wait_ms", "want 1 to 600000")),
        };
        let mode = match raw.mode.as_deref().unwrap_or("public") {
            "public" => NetworkMode::Public,
            "devnet" => NetworkMode::Devnet,
            "local" => NetworkMode::Local,
            _ => return Err(key("mode", "want public, devnet or local")),
        };
        GoodbyeLedger::new(raw.goodbye_ledger)
            .map_err(|e| key("goodbye_ledger", &e.to_string()))?;
        let topics = read_topics(&topics_path, euid, accepted_owner)?;
        Ok(Self {
            listen,
            chain_socket,
            chain_uid,
            discv5_socket,
            discv5_uid,
            topics,
            target_peers,
            static_peers,
            answer_prefixes,
            chain_wait,
            goodbye_ledger: raw.goodbye_ledger,
            mode,
        })
    }
}

/// A prefix length of 1 to `max` bits, `default` if not given.
fn prefix(
    key: &'static str,
    value: Option<u8>,
    default: u8,
    max: u8,
) -> Result<u8, P2pConfigError> {
    match value {
        None => Ok(default),
        Some(bits) if (1..=max).contains(&bits) => Ok(bits),
        Some(_) => Err(P2pConfigError::Key {
            key,
            why: format!("want 1 to {max} bits"),
        }),
    }
}

/// The topic list at `path`, read through the owner walk.
fn read_topics(path: &Path, euid: u32, accepted: u32) -> Result<TopicList, P2pConfigError> {
    let refused = |why: String| P2pConfigError::Topics {
        path: path.to_owned(),
        why,
    };
    let text = svc_runtime::owned::read_root_owned(path, euid, accepted)
        .map_err(|e| refused(e.to_string()))?;
    TopicList::parse(&text).map_err(|e| refused(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behaviour::ConnectionCaps;
    use svc_runtime::owned::testkit::{config_root, write_read_only, Sealed};

    const TOPICS: &str = include_str!("../../../../ops/probe/gossip-topics.toml");

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// A topic list on a path the owner walk accepts with the test user as the owner.
    struct Topics {
        _dir: tempfile::TempDir,
        path: PathBuf,
        _sealed: Sealed,
    }

    fn topics(text: &str) -> Topics {
        let dir = tempfile::Builder::new().tempdir_in(config_root()).unwrap();
        let path = dir.path().join("gossip-topics.toml");
        write_read_only(&path, text);
        let sealed = Sealed::new(dir.path());
        Topics {
            path,
            _sealed: sealed,
            _dir: dir,
        }
    }

    fn table(text: &str) -> toml::Table {
        toml::from_str(text).unwrap()
    }

    fn settings(text: &str, topics: &Topics) -> Result<P2pSettings, P2pConfigError> {
        let text = format!(
            "chain_uid = 990\ndiscv5_uid = 992\ngossip_topics = \"{}\"\n{text}",
            topics.path.display()
        );
        P2pSettings::from_table(table(&text), me() + 1, me())
    }

    #[test]
    fn the_defaults() {
        let t = topics(TOPICS);
        let s = settings("", &t).unwrap();
        assert_eq!(s.listen, [DEFAULT_LISTEN.parse::<Multiaddr>().unwrap()]);
        assert_eq!(s.chain_socket, Path::new(DEFAULT_CHAIN_SOCKET));
        assert_eq!(s.discv5_socket, Path::new(DEFAULT_DISCV5_SOCKET));
        assert_eq!((s.chain_uid, s.discv5_uid), (990, 992));
        assert_eq!(s.target_peers, DEFAULT_TARGET_PEERS);
        assert!(s.static_peers.is_empty());
        assert_eq!(s.answer_prefixes, AnswerPrefixes::default());
        assert_eq!(s.chain_wait, DEFAULT_CHAIN_WAIT);
        assert_eq!(s.goodbye_ledger, GoodbyeLedgerConfig::default());
        assert_eq!(s.topics.kinds().len(), 11);
        assert_eq!(s.mode, NetworkMode::Public);
    }

    #[test]
    fn a_complete_table() {
        let t = topics(TOPICS);
        let id = libp2p::identity::Keypair::generate_secp256k1()
            .public()
            .to_peer_id();
        let peer = format!("/ip4/10.0.0.2/tcp/9000/p2p/{id}");
        let s = settings(
            &format!(
                "listen = [\"/ip4/127.0.0.1/tcp/0\"]\ntarget_peers = 3\n\
                 static_peers = [\"{peer}\"]\nanswer_prefix_v4 = 32\nanswer_prefix_v6 = 128\n\
                 chain_wait_ms = 500\nmode = \"local\"\n\
                 [goodbye_ledger]\ngoodbye3_threshold_pct = 4.0\n"
            ),
            &t,
        )
        .unwrap();
        assert_eq!(s.target_peers, 3);
        assert_eq!(s.static_peers.len(), 1);
        assert_eq!(
            s.answer_prefixes,
            AnswerPrefixes {
                ipv4: 32,
                ipv6: 128
            }
        );
        assert_eq!(s.chain_wait, Duration::from_millis(500));
        assert_eq!(s.goodbye_ledger.goodbye3_threshold_pct, 4.0);
        assert_eq!(s.mode, NetworkMode::Local);
        let devnet = settings("mode = \"devnet\"", &t).unwrap();
        assert_eq!(devnet.mode, NetworkMode::Devnet);
    }

    /// The dialer's target fits in the outbound slots of the connection caps: what inbound
    /// peers cannot take.
    #[test]
    fn the_target_fits_the_outbound_slots() {
        let caps = ConnectionCaps::default();
        assert_eq!(
            MAX_TARGET_PEERS as u32,
            caps.max_established - caps.max_established_incoming
        );
        const { assert!(DEFAULT_TARGET_PEERS <= MAX_TARGET_PEERS) };
        let t = topics(TOPICS);
        let s = settings(&format!("target_peers = {MAX_TARGET_PEERS}"), &t).unwrap();
        assert_eq!(s.target_peers, MAX_TARGET_PEERS);
    }

    #[test]
    fn bad_tables_are_refused() {
        let t = topics(TOPICS);
        let cases: [(&str, &str); 12] = [
            ("listen = [\"nowhere\"]", "listen"),
            ("listen = []", "listen"),
            ("chain_socket = \"run/cl-chain.sock\"", "chain_socket"),
            ("discv5_socket = \"cl-discv5.sock\"", "discv5_socket"),
            ("target_peers = 0", "target_peers"),
            ("target_peers = 33", "target_peers"),
            (
                "static_peers = [\"/ip4/10.0.0.2/tcp/9000\"]",
                "static_peers",
            ),
            ("answer_prefix_v4 = 33", "answer_prefix_v4"),
            ("answer_prefix_v6 = 0", "answer_prefix_v6"),
            ("chain_wait_ms = 0", "chain_wait_ms"),
            ("mode = \"open\"", "mode"),
            (
                "[goodbye_ledger]\ngoodbye3_threshold_pct = 1.0",
                "goodbye_ledger",
            ),
        ];
        for (text, want) in cases {
            let err = settings(text, &t).unwrap_err();
            assert!(
                matches!(&err, P2pConfigError::Key { key, .. } if *key == want),
                "{text}: {err}"
            );
        }
        let err = settings("listen_addr = 1", &t).unwrap_err();
        assert!(matches!(err, P2pConfigError::Parse(_)), "{err}");
        let err = P2pSettings::from_table(table("discv5_uid = 1"), me() + 1, me()).unwrap_err();
        assert_eq!(err, P2pConfigError::Missing("chain_uid"));
        let err = P2pSettings::from_table(table("chain_uid = 1"), me() + 1, me()).unwrap_err();
        assert_eq!(err, P2pConfigError::Missing("discv5_uid"));
    }

    /// The topic list is read only through the owner walk, and must load.
    #[test]
    fn the_topic_list_is_read_as_a_config_is() {
        let bad = topics("topics = [\"no_such_topic\"]\n");
        let err = settings("", &bad).unwrap_err();
        assert!(matches!(err, P2pConfigError::Topics { .. }), "{err}");
        let t = topics(TOPICS);
        // Its own user may write the directory once unsealed: refused.
        drop(t._sealed);
        let text = format!(
            "chain_uid = 990\ndiscv5_uid = 992\ngossip_topics = \"{}\"\n",
            t.path.display()
        );
        let err = P2pSettings::from_table(table(&text), me(), me()).unwrap_err();
        assert!(err.to_string().contains("writable"), "{err}");
    }
}
