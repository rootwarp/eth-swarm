//! `/etc/ethswarm/m2a-session.toml`: the pinned reference node and how to reach it.
//!
//! ```toml
//! network = "sepolia"                                   # the only network accepted
//! peer = "/ip4/192.0.2.10/tcp/9000/p2p/16Uiu2HAm…"      # the reference node, its peer ID pinned
//! reference_api_url = "http://127.0.0.1:5052"           # its beacon API, on loopback
//! node_key = "/var/lib/m2a-session/node.key"            # optional: absent means ephemeral
//! trusted_by_reference = true                           # optional (false): see below
//!
//! [deadlines]                                           # optional, per req/resp exchange
//! ttfb_ms = 5000                                        # first response byte
//! total_ms = 10000                                      # the whole response
//! per_chunk_ms = 5000                                   # each response chunk
//! ```
//!
//! - **One peer.** `peer` is one multiaddr string or one `[peer]` table with a `multiaddr` key.
//!   A list (`peer = [..]`, `[[peer]]`), even of one, is refused, as is a second key or field
//!   naming another peer. The multiaddr is `/ip4|ip6/<addr>/tcp/<port>/p2p/<peer id>`
//!   ([`PinnedPeer`]); the peer ID is what Noise must prove, so a dial to anyone else fails.
//! - **`reference_api_url`** (optional: `--dial-only` never uses it, the Status probe requires
//!   it): `http://`, a loopback host (`localhost`, `127.0.0.0/8` or
//!   `[::1]`), an optional port (1..=65535) and base path, and no credentials, query or
//!   fragment. The API's answers decide the verdicts, and plaintext over any other path could be
//!   forged by anyone on it, so a remote node is reached through an SSH tunnel to a local port
//!   (`ssh -L 5052:127.0.0.1:5052 ref-host`). This is the only place the rule lives: a
//!   [`ReferenceApiUrl`] exists only once it passed. The URL may still carry a key in its path,
//!   so errors never quote it and `Debug` shows `scheme://host:port` only.
//! - **`deadlines`**: milliseconds, each positive; `ttfb_ms` and `per_chunk_ms` at most
//!   `total_ms`, and `total_ms` at most [`MAX_DEADLINE`], the `request_response` backstop
//!   ([`crate::rpc::REQUEST_TIMEOUT`]), so the configured total is the one that applies.
//! - **`node_key`**: an absolute path to the 32-byte secp256k1 secret; the pre-flight
//!   ([`super::preflight`]) requires a regular file of mode 0600 owned by the effective UID.
//! - **`trusted_by_reference = true`** says the reference node lists our peer ID as a trusted
//!   peer (Lighthouse `--trusted-peers`), so it does not descore us for refusing its inbound
//!   MetaData and Ping. That needs a peer ID that survives a restart: an ephemeral key would
//!   change it, so the flag requires `node_key`.
//!
//! Unknown keys are refused, so a typo fails startup instead of falling back to a default.

use super::{KeySource, PinnedPeer, PinnedPeerError};
use crate::rpc::codec::Deadlines;
use serde::Deserialize;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `/etc/ethswarm/m2a-session.toml`.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/ethswarm/m2a-session.toml";

/// The longest deadline a config may set: `request_response`'s own per-exchange timeout, which
/// would cut a longer one short.
pub const MAX_DEADLINE: Duration = crate::rpc::REQUEST_TIMEOUT;

/// The network the session runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Sepolia.
    Sepolia,
}

/// `reference_api_url`: checked, and printed in `Debug` as `scheme://host:port` only.
#[derive(Clone, PartialEq, Eq)]
pub struct ReferenceApiUrl(http::Uri);

impl ReferenceApiUrl {
    /// The URL.
    pub fn uri(&self) -> &http::Uri {
        &self.0
    }

    /// The explicit port, else 80.
    pub fn port(&self) -> u16 {
        self.0.port_u16().unwrap_or(80)
    }
}

impl fmt::Debug for ReferenceApiUrl {
    /// `scheme://host:port`, plus `/…` when there is a base path (it may hold a key).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = self.0.scheme_str().unwrap_or_default();
        let host = self.0.host().unwrap_or_default();
        write!(f, "{scheme}://{host}:{}", self.port())?;
        if self.0.path().trim_end_matches('/').is_empty() {
            Ok(())
        } else {
            f.write_str("/…")
        }
    }
}

/// A loaded, checked m2a-session config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M2aConfig {
    /// `network`.
    pub network: Network,
    /// The reference node: the peer ID Noise must prove and the one address dialed.
    pub peer: PinnedPeer,
    /// The reference node's beacon API: optional here, required by the Status probe.
    pub reference_api_url: Option<ReferenceApiUrl>,
    /// The req/resp deadlines.
    pub deadlines: Deadlines,
    /// `node_key`: a credential file, or ephemeral when absent.
    pub node_key: KeySource,
    /// `trusted_by_reference`: the reference node lists our peer ID as trusted.
    pub trusted_by_reference: bool,
}

/// Why a config was refused. Errors never quote `reference_api_url`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// Not TOML, an unknown key, a missing key or a wrong type. The input is not quoted.
    #[error("line {line}: {message}")]
    Parse {
        /// The 1-based line the error starts on.
        line: usize,
        /// The parser's message.
        message: String,
    },
    /// `network` is not one this session accepts.
    #[error("network {0:?}: only \"sepolia\" is accepted")]
    Network(String),
    /// No `peer`.
    #[error("no peer: name the reference node as peer = \"<multiaddr>/p2p/<peer id>\"")]
    MissingPeer,
    /// `peer` is a list: exactly one pinned peer is allowed.
    #[error("peer: exactly one pinned peer is allowed, found a list of {0}")]
    PeerList(usize),
    /// `peer` is neither a string nor a table.
    #[error("peer: want a multiaddr string or a [peer] table")]
    PeerType,
    /// The `[peer]` table is malformed (no `multiaddr`, or another key).
    #[error("[peer]: {0}")]
    PeerTable(String),
    /// The peer's multiaddr was refused.
    #[error("peer: {0}")]
    Peer(#[from] PinnedPeerError),
    /// `reference_api_url` was refused (why, never the URL).
    #[error("reference_api_url: {0}")]
    ReferenceApiUrl(&'static str),
    /// A deadline is out of range.
    #[error("deadlines.{name}: {why}")]
    Deadline {
        /// The key.
        name: &'static str,
        /// Why.
        why: &'static str,
    },
    /// `node_key` is a relative path.
    #[error("node_key must be an absolute path")]
    NodeKeyNotAbsolute,
    /// `trusted_by_reference` without `node_key`: an ephemeral key changes the peer ID.
    #[error(
        "trusted_by_reference = true needs node_key: the reference node trusts one peer ID, \
         and an ephemeral key changes it on every start"
    )]
    EphemeralKeyTrusted,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    network: String,
    peer: Option<toml::Value>,
    reference_api_url: Option<String>,
    #[serde(default)]
    deadlines: RawDeadlines,
    node_key: Option<PathBuf>,
    #[serde(default)]
    trusted_by_reference: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeadlines {
    ttfb_ms: Option<u64>,
    total_ms: Option<u64>,
    per_chunk_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeerTable {
    multiaddr: String,
}

impl M2aConfig {
    /// Loads the config from `path` ([`DEFAULT_CONFIG_PATH`] in production).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Parses and checks config text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
        let network = match raw.network.as_str() {
            "sepolia" => Network::Sepolia,
            _ => return Err(ConfigError::Network(raw.network)),
        };
        let peer = pinned_peer(raw.peer)?;
        let reference_api_url = raw
            .reference_api_url
            .as_deref()
            .map(reference_api_url)
            .transpose()?;
        let deadlines = deadlines(&raw.deadlines)?;
        let node_key = match raw.node_key {
            None => KeySource::Ephemeral,
            Some(path) if path.is_absolute() => KeySource::File(path),
            Some(_) => return Err(ConfigError::NodeKeyNotAbsolute),
        };
        if raw.trusted_by_reference && node_key == KeySource::Ephemeral {
            return Err(ConfigError::EphemeralKeyTrusted);
        }
        Ok(Self {
            network,
            peer,
            reference_api_url,
            deadlines,
            node_key,
            trusted_by_reference: raw.trusted_by_reference,
        })
    }
}

/// The parser's message and line, without the snippet of input `toml` would quote.
fn parse_error(text: &str, error: &toml::de::Error) -> ConfigError {
    let line = error.span().map_or(1, |span| {
        text[..span.start.min(text.len())].matches('\n').count() + 1
    });
    ConfigError::Parse {
        line,
        message: error.message().trim_end().to_owned(),
    }
}

fn pinned_peer(value: Option<toml::Value>) -> Result<PinnedPeer, ConfigError> {
    let multiaddr = match value {
        None => return Err(ConfigError::MissingPeer),
        Some(toml::Value::String(multiaddr)) => multiaddr,
        Some(table @ toml::Value::Table(_)) => {
            RawPeerTable::deserialize(table)
                .map_err(|e| ConfigError::PeerTable(e.message().trim_end().to_owned()))?
                .multiaddr
        }
        Some(toml::Value::Array(list)) => return Err(ConfigError::PeerList(list.len())),
        Some(_) => return Err(ConfigError::PeerType),
    };
    Ok(multiaddr.parse::<PinnedPeer>()?)
}

/// The anchor fetcher's URL rule, but plain `http://` to a loopback host only.
fn reference_api_url(url: &str) -> Result<ReferenceApiUrl, ConfigError> {
    let bad = ConfigError::ReferenceApiUrl;
    let uri: http::Uri = url.parse().map_err(|_| bad("not a valid URL"))?;
    match uri.scheme_str() {
        Some("http") => {}
        _ => {
            return Err(bad(
                "the scheme must be http:// (loopback only; tunnel to a remote node over SSH)",
            ))
        }
    }
    let authority = uri.authority().ok_or(bad("no host"))?;
    if authority.as_str().contains('@') {
        return Err(bad("credentials in the URL are refused"));
    }
    if uri.query().is_some() || url.contains('#') {
        return Err(bad("no query or fragment allowed"));
    }
    if authority.host().is_empty() {
        return Err(bad("no host"));
    }
    // `Authority::port` is `None` for an out-of-range port, and `http` accepts junk between an
    // IPv6 literal and the port (`[::1]junk:65536` is host `[::1]`, no port), so what follows
    // the host must be nothing, or `:` and a port.
    let after_host = authority
        .as_str()
        .strip_prefix(authority.host())
        .ok_or(bad("no host"))?;
    if !after_host.is_empty() {
        let port = after_host
            .strip_prefix(':')
            .ok_or(bad("only :<port> may follow the host"))?;
        match port.parse::<u16>() {
            Ok(p) if p != 0 && port.bytes().all(|b| b.is_ascii_digit()) => {}
            _ => return Err(bad("the port must be 1..=65535")),
        }
    }
    if !is_loopback_host(authority.host()) {
        return Err(bad(
            "the host must be loopback (localhost, 127.0.0.0/8 or [::1]); \
             tunnel to a remote node over SSH",
        ));
    }
    Ok(ReferenceApiUrl(uri))
}

/// `localhost` (any case), an IPv4 address in `127.0.0.0/8`, or `[::1]`.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback());
    }
    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| ip.is_loopback())
}

fn deadlines(raw: &RawDeadlines) -> Result<Deadlines, ConfigError> {
    let default = Deadlines::default();
    let read = |name, ms: Option<u64>, default| match ms.map(Duration::from_millis) {
        None => Ok(default),
        Some(Duration::ZERO) => Err(ConfigError::Deadline {
            name,
            why: "must be positive",
        }),
        Some(d) if d > MAX_DEADLINE => Err(ConfigError::Deadline {
            name,
            why: "exceeds the 10 s request_response backstop",
        }),
        Some(d) => Ok(d),
    };
    let deadlines = Deadlines {
        ttfb: read("ttfb_ms", raw.ttfb_ms, default.ttfb)?,
        total: read("total_ms", raw.total_ms, default.total)?,
        per_chunk: read("per_chunk_ms", raw.per_chunk_ms, default.per_chunk)?,
    };
    let within_total = |name, d: Duration| {
        if d > deadlines.total {
            Err(ConfigError::Deadline {
                name,
                why: "must not exceed total_ms",
            })
        } else {
            Ok(())
        }
    };
    within_total("ttfb_ms", deadlines.ttfb)?;
    within_total("per_chunk_ms", deadlines.per_chunk)?;
    Ok(deadlines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{Multiaddr, PeerId};

    fn peer_id() -> PeerId {
        "16Uiu2HAmPLe7Mzm8TsYUubgCAW1aJoeFScxrLj8ppHFivPo97bUZ"
            .parse()
            .unwrap()
    }

    fn peer() -> String {
        format!("/ip4/127.0.0.1/tcp/9000/p2p/{}", peer_id())
    }

    const URL: &str = "reference_api_url = \"http://127.0.0.1:5052\"\n";

    /// `network`, `reference_api_url` and `extra`, which names the peer.
    fn config(extra: &str) -> String {
        format!("network = \"sepolia\"\n{URL}{extra}\n")
    }

    fn with_peer(extra: &str) -> String {
        config(&format!("peer = \"{}\"\n{extra}", peer()))
    }

    fn parse(text: &str) -> Result<M2aConfig, ConfigError> {
        M2aConfig::from_toml(text)
    }

    #[test]
    fn loads_the_defaults() {
        let c = parse(&with_peer("")).unwrap();
        assert_eq!(c.network, Network::Sepolia);
        assert_eq!(c.peer.peer_id, peer_id());
        assert_eq!(
            c.peer.addr,
            "/ip4/127.0.0.1/tcp/9000".parse::<Multiaddr>().unwrap()
        );
        assert_eq!(
            c.reference_api_url.as_ref().unwrap().uri().to_string(),
            "http://127.0.0.1:5052/"
        );
        assert_eq!(c.deadlines, Deadlines::default());
        assert_eq!(c.node_key, KeySource::Ephemeral);
        assert!(!c.trusted_by_reference);
    }

    #[test]
    fn loads_a_complete_config() {
        let c = parse(&format!(
            "network = \"sepolia\"\nreference_api_url = \"http://localhost:5052/\"\n\
             node_key = \"/var/lib/m2a-session/node.key\"\ntrusted_by_reference = true\n\
             [peer]\nmultiaddr = \"{}\"\n\
             [deadlines]\nttfb_ms = 1500\ntotal_ms = 8000\nper_chunk_ms = 2500\n",
            peer()
        ))
        .unwrap();
        assert_eq!(c.peer.peer_id, peer_id());
        assert_eq!(
            c.deadlines,
            Deadlines {
                ttfb: Duration::from_millis(1500),
                total: Duration::from_millis(8000),
                per_chunk: Duration::from_millis(2500),
            }
        );
        assert_eq!(
            c.node_key,
            KeySource::File("/var/lib/m2a-session/node.key".into())
        );
        assert!(c.trusted_by_reference);
        assert_eq!(
            format!("{:?}", c.reference_api_url.unwrap()),
            "http://localhost:5052"
        );
    }

    #[test]
    fn missing_peer_id_rejected() {
        let no_suffix = config("peer = \"/ip4/127.0.0.1/tcp/9000\"");
        assert!(
            matches!(
                parse(&no_suffix),
                Err(ConfigError::Peer(PinnedPeerError::NoPeerId))
            ),
            "{:?}",
            parse(&no_suffix)
        );
        let only_id = config(&format!("peer = \"/p2p/{}\"", peer_id()));
        assert!(matches!(
            parse(&only_id),
            Err(ConfigError::Peer(PinnedPeerError::NoPeerId))
        ));
        let table = config("[peer]\nmultiaddr = \"/ip4/127.0.0.1/tcp/9000\"");
        assert!(matches!(
            parse(&table),
            Err(ConfigError::Peer(PinnedPeerError::NoPeerId))
        ));
        assert!(matches!(
            parse(&config("peer = \"\"")),
            Err(ConfigError::Peer(PinnedPeerError::NoPeerId))
        ));
        assert!(matches!(parse(&config("")), Err(ConfigError::MissingPeer)));
        assert!(matches!(
            parse(&config("[peer]")),
            Err(ConfigError::PeerTable(_))
        ));
    }

    #[test]
    fn two_peers_rejected() {
        let other = format!("/ip4/127.0.0.2/tcp/9000/p2p/{}", PeerId::random());
        let list = config(&format!("peer = [\"{}\", \"{other}\"]", peer()));
        assert!(matches!(parse(&list), Err(ConfigError::PeerList(2))));
        let tables = config(&format!(
            "[[peer]]\nmultiaddr = \"{}\"\n[[peer]]\nmultiaddr = \"{other}\"",
            peer()
        ));
        assert!(matches!(parse(&tables), Err(ConfigError::PeerList(2))));
        // A list is refused even with one entry: the schema has one peer, not a list of them.
        let one = config(&format!("peer = [\"{}\"]", peer()));
        assert!(matches!(parse(&one), Err(ConfigError::PeerList(1))));
        let twice = config(&format!("peer = \"{}\"\npeer = \"{other}\"", peer()));
        assert!(matches!(parse(&twice), Err(ConfigError::Parse { .. })));
        let both = config(&format!(
            "peer = \"{}\"\n[peer]\nmultiaddr = \"{other}\"",
            peer()
        ));
        assert!(matches!(parse(&both), Err(ConfigError::Parse { .. })));
        let second_key = with_peer(&format!("peers = [\"{other}\"]"));
        assert!(matches!(parse(&second_key), Err(ConfigError::Parse { .. })));
        let second_field = config(&format!(
            "[peer]\nmultiaddr = \"{}\"\nfallback = \"{other}\"",
            peer()
        ));
        assert!(matches!(
            parse(&second_field),
            Err(ConfigError::PeerTable(_))
        ));
        assert!(matches!(
            parse(&config("peer = 9000")),
            Err(ConfigError::PeerType)
        ));
    }

    #[test]
    fn malformed_multiaddr_rejected() {
        let id = peer_id();
        for bad in [
            "nonsense".to_owned(),
            "/ip4/127.0.0.1/tcp/9000/p2p/not-a-peer-id".to_owned(),
            "/ip4/127.0.0.1/tcp/9000/p2p/16Uiu2HAmPLe7Mzm8TsYUubgCAW1aJoeFScxrLj8ppHFivPo97bU"
                .to_owned(),
            "/ip4/127.0.0.256/tcp/9000".to_owned() + &format!("/p2p/{id}"),
            format!("/ip4/127.0.0.1/tcp/70000/p2p/{id}"),
        ] {
            let text = config(&format!("peer = \"{bad}\""));
            assert!(
                matches!(
                    parse(&text),
                    Err(ConfigError::Peer(PinnedPeerError::Multiaddr(_)))
                ),
                "{bad}: {:?}",
                parse(&text)
            );
        }
        for bad in [
            format!("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/{id}"),
            format!("/dns4/ref.example/tcp/9000/p2p/{id}"),
            format!("/ip4/127.0.0.1/tcp/0/p2p/{id}"),
            format!("/ip4/0.0.0.0/tcp/9000/p2p/{id}"),
        ] {
            let text = config(&format!("peer = \"{bad}\""));
            assert!(
                matches!(
                    parse(&text),
                    Err(ConfigError::Peer(PinnedPeerError::Transport))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn ephemeral_key_with_trusted_peer_rejected() {
        let text = with_peer("trusted_by_reference = true");
        assert!(matches!(
            parse(&text),
            Err(ConfigError::EphemeralKeyTrusted)
        ));
        // Trusted with a stable key, or untrusted and ephemeral, are both fine.
        let stable = with_peer("trusted_by_reference = true\nnode_key = \"/k\"");
        assert_eq!(
            parse(&stable).unwrap().node_key,
            KeySource::File("/k".into())
        );
        let untrusted = with_peer("trusted_by_reference = false");
        assert_eq!(parse(&untrusted).unwrap().node_key, KeySource::Ephemeral);
    }

    #[test]
    fn node_key_must_be_an_absolute_path() {
        for path in ["node.key", "./node.key", ""] {
            let text = with_peer(&format!("node_key = \"{path}\""));
            assert!(
                matches!(parse(&text), Err(ConfigError::NodeKeyNotAbsolute)),
                "{path:?}"
            );
        }
    }

    #[test]
    fn only_sepolia() {
        for name in ["mainnet", "hoodi", "Sepolia", ""] {
            let text = with_peer("").replace("\"sepolia\"", &format!("\"{name}\""));
            assert!(
                matches!(parse(&text), Err(ConfigError::Network(ref n)) if n == name),
                "{name}"
            );
        }
        let no_network = with_peer("").replace("network = \"sepolia\"\n", "");
        assert!(matches!(parse(&no_network), Err(ConfigError::Parse { .. })));
    }

    fn with_url(url: &str) -> String {
        with_peer("").replace("http://127.0.0.1:5052", url)
    }

    #[test]
    fn reference_api_url_rules() {
        for good in [
            "http://127.0.0.1:5052",
            "http://127.0.0.1/beacon/",
            "http://localhost:5052",
            "http://LOCALHOST:5052",
            "http://[::1]:5052",
        ] {
            assert!(parse(&with_url(good)).is_ok(), "{good}");
        }
        assert_eq!(
            format!(
                "{:?}",
                parse(&with_url("http://127.0.0.1/key/abc"))
                    .unwrap()
                    .reference_api_url
                    .unwrap()
            ),
            "http://127.0.0.1:80/…"
        );
        assert_eq!(
            format!(
                "{:?}",
                parse(&with_url("http://[::1]"))
                    .unwrap()
                    .reference_api_url
                    .unwrap()
            ),
            "http://[::1]:80"
        );
        for bad in [
            "ftp://127.0.0.1",
            "127.0.0.1:5052",
            "/eth/v1",
            "http://",
            "http://user:hunter2@127.0.0.1",
            "http://hunter2@127.0.0.1",
            "http://127.0.0.1/?token=hunter2",
            "http://127.0.0.1/#hunter2",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:hunter2",
            "http://[::1]junk:65536",
            "http://[::1]hunter2",
            "http://[::1]x:5052",
            "http://[::1]:",
            "http://127.0.0.1:",
            "http://127.0.0.1:+5052",
            "http://127.0.0.1:05052x",
            "not a url hunter2",
        ] {
            let err = parse(&with_url(bad)).unwrap_err();
            assert!(
                matches!(err, ConfigError::ReferenceApiUrl(_)),
                "{bad}: {err:?}"
            );
            assert!(
                !err.to_string().contains("hunter2"),
                "{bad}: the URL is quoted"
            );
            assert!(
                !format!("{err:?}").contains("hunter2"),
                "{bad}: the URL is quoted"
            );
        }
    }

    #[test]
    fn reference_api_url_is_optional() {
        // --dial-only never uses it; the Status probe requires it (m2a-session refuses).
        let without = with_peer("").replace(URL, "");
        let c = parse(&without).unwrap();
        assert_eq!(c.reference_api_url, None);
        // Given, it is still checked.
        let remote = with_url("http://192.0.2.10:5052");
        assert!(matches!(
            parse(&remote),
            Err(ConfigError::ReferenceApiUrl(_))
        ));
    }

    #[test]
    fn reference_api_url_must_be_plain_http_on_loopback() {
        // Plaintext to anywhere else lets anyone on the path forge finality and head answers;
        // a remote node is reached through an SSH tunnel to a local port.
        for remote in [
            "http://192.0.2.10:5052",
            "http://10.0.0.1:5052",
            "http://0.0.0.0:5052",
            "http://ref.example:5052",
            "http://localhost.:5052",
            "http://localhost.ref.example:5052",
            "http://127.0.0.1.ref.example:5052",
            "http://[::]:5052",
            "http://[::ffff:127.0.0.1]:5052",
            "http://[2001:db8::1]:5052",
        ] {
            let err = parse(&with_url(remote)).unwrap_err();
            assert!(
                matches!(err, ConfigError::ReferenceApiUrl(why) if why.contains("loopback")),
                "{remote}: {err:?}"
            );
        }
        for tls in ["https://127.0.0.1:5052", "https://ref.example"] {
            let err = parse(&with_url(tls)).unwrap_err();
            assert!(
                matches!(err, ConfigError::ReferenceApiUrl(why) if why.contains("http://")),
                "{tls}: {err:?}"
            );
        }
        for local in [
            "http://127.0.0.1:5052",
            "http://127.8.9.10:5052",
            "http://localhost",
            "http://[::1]:1",
        ] {
            assert!(parse(&with_url(local)).is_ok(), "{local}");
        }
    }

    fn with_deadlines(table: &str) -> String {
        with_peer(&format!("[deadlines]\n{table}"))
    }

    #[test]
    fn deadlines_are_positive_and_capped() {
        let partial = parse(&with_deadlines("ttfb_ms = 2000")).unwrap();
        assert_eq!(
            partial.deadlines,
            Deadlines {
                ttfb: Duration::from_secs(2),
                ..Deadlines::default()
            }
        );
        let at_cap = format!("total_ms = {}", MAX_DEADLINE.as_millis());
        assert_eq!(
            parse(&with_deadlines(&at_cap)).unwrap().deadlines.total,
            MAX_DEADLINE
        );
        for (table, name) in [
            ("ttfb_ms = 0", "ttfb_ms"),
            ("total_ms = 0", "total_ms"),
            ("per_chunk_ms = 0", "per_chunk_ms"),
            ("total_ms = 10001", "total_ms"),
            ("ttfb_ms = 6000\ntotal_ms = 5000", "ttfb_ms"),
            ("per_chunk_ms = 6000\ntotal_ms = 5000", "per_chunk_ms"),
            ("ttfb_ms = 9223372036854775807", "ttfb_ms"),
        ] {
            assert!(
                matches!(parse(&with_deadlines(table)), Err(ConfigError::Deadline { name: n, .. }) if n == name),
                "{table}: {:?}",
                parse(&with_deadlines(table))
            );
        }
        for table in ["ttfb_ms = -1", "ttfb = 5", "ttfb_ms = \"5s\""] {
            assert!(
                matches!(
                    parse(&with_deadlines(table)),
                    Err(ConfigError::Parse { .. })
                ),
                "{table}"
            );
        }
    }

    #[test]
    fn unknown_keys_rejected() {
        let text = with_peer("listen = \"/ip4/0.0.0.0/tcp/9000\"");
        let err = parse(&text).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { line: 4, .. }), "{err:?}");
        assert!(err.to_string().contains("listen"), "{err}");
    }

    #[test]
    fn parse_errors_do_not_quote_the_input() {
        let text = "reference_api_url = \"http://user:hunter2@ref.example\nnetwork = \"sepolia\"\n";
        let err = parse(text).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { line: 1, .. }), "{err:?}");
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }

    #[test]
    fn loads_from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m2a-session.toml");
        std::fs::write(&path, with_peer("")).unwrap();
        assert_eq!(
            M2aConfig::load(&path).unwrap(),
            parse(&with_peer("")).unwrap()
        );
        let missing = dir.path().join("missing.toml");
        let err = M2aConfig::load(&missing).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Read { path, .. } if *path == missing),
            "{err}"
        );
        assert_eq!(DEFAULT_CONFIG_PATH, "/etc/ethswarm/m2a-session.toml");
    }
}
