//! The `m2a-session` skeleton: one pinned outbound peer, no listener, its own OS user.
//!
//! - **Pre-flight** ([`preflight`]): refuses to run as root, and loads the node key: an
//!   ephemeral secp256k1 key, or a 32-byte secp256k1 secret from a credential file that must be
//!   a regular file (not a symlink) of mode 0600 owned by the effective UID. [`NodeKey`] prints
//!   `<redacted>` in `Debug` and `Display`, and nothing here logs key material.
//! - **Config** ([`config`]): `/etc/ethswarm/m2a-session.toml` pins the one reference peer
//!   (`/ip4|ip6/…/tcp/<port>/p2p/<peer id>`), the req/resp deadlines and the node key.
//! - **Swarm** ([`Session::start`]): TCP + Noise XX + yamux, built from the node key and
//!   negotiated with multistream-select `V1`, so an established connection proves the peer
//!   accepted yamux ([`Session::disconnect`] then ends it, for `--dial-only`). `listen_on`
//!   is never called, so the session has no listen address. The only dial is
//!   `DialOpts::peer_id(pinned).addresses([addr])`, which Noise fails unless the remote proves
//!   the pinned identity, and an allow list ([`allow_block_list`]) denies a connection to or from
//!   any other peer before it is established. A connection to another peer that is reported
//!   anyway is closed. There is no discovery: `cl-p2p` has no `discv5` dependency
//!   (`scripts/check-m2a-deps.sh`).
//! - **Logs**: `tests/m2a_session.rs` (its own test binary, so that no concurrent test races
//!   its subscriber) captures every log line of a session and checks that no key material is
//!   in it.
//! - **Req/resp**: one outbound-only [`request_response`] behaviour per protocol
//!   ([`crate::rpc`]). Status goes out through [`crate::rpc::outbound::status`] and MetaData
//!   through [`Session::request_metadata`], which keeps the peer's MetaData (its `seq_number`
//!   for Ping); later work sends Ping and BlocksByRange.

pub mod config;

use crate::rpc::codec::{Deadlines, RpcCodec};
use crate::rpc::outbound::OutboundError;
use crate::rpc::outbound_behaviour;
use consensus_types::EthSpec;
use futures::StreamExt;
use libp2p::allow_block_list::{self, AllowedPeers};
use libp2p::identity::{secp256k1, Keypair};
use libp2p::multiaddr::Protocol as AddrProtocol;
use libp2p::request_response;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{DialError, NetworkBehaviour, SwarmEvent};
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use p2p_wire::rpc::codec::ContextTable;
use p2p_wire::rpc::messages::MetaDataV3;
use p2p_wire::rpc::protocols::Protocol;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// The mode a node-key file must have.
pub const KEY_FILE_MODE: u32 = 0o600;
/// A secp256k1 secret key file holds exactly the 32 secret bytes.
pub const KEY_FILE_LEN: u64 = 32;
/// How long an idle connection to the pinned peer stays open.
pub const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// The libp2p node key. Its `Debug` and `Display` never show key material.
pub struct NodeKey(Keypair);

impl NodeKey {
    /// A fresh secp256k1 key that lives only as long as the process.
    pub fn ephemeral() -> Self {
        Self(Keypair::generate_secp256k1())
    }

    /// The peer ID the key proves (public).
    pub fn peer_id(&self) -> PeerId {
        self.0.public().to_peer_id()
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Where the node key comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// [`NodeKey::ephemeral`].
    Ephemeral,
    /// A 32-byte secp256k1 secret in a 0600 file owned by the effective UID.
    File(PathBuf),
}

/// What the session checks before it touches the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    /// The effective UID the process runs as (`geteuid()` in production).
    pub euid: u32,
    /// The node key.
    pub key: KeySource,
}

/// Why a key file was refused. The key bytes are never part of the error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyFileError {
    /// The file could not be opened (missing, a symlink, unreadable).
    #[error("cannot open: {0}")]
    Open(String),
    /// The path is not a regular file.
    #[error("not a regular file")]
    NotRegular,
    /// The permission bits are not 0600.
    #[error("mode {0:04o}, want 0600")]
    Mode(u32),
    /// Another UID owns the file.
    #[error("owned by uid {owner}, want {euid}")]
    Owner {
        /// The file's owner.
        owner: u32,
        /// The effective UID.
        euid: u32,
    },
    /// The file is not 32 bytes.
    #[error("{0} bytes, want {KEY_FILE_LEN}")]
    Length(u64),
    /// The bytes are not a valid secp256k1 secret key.
    #[error("not a secp256k1 secret key")]
    Invalid,
    /// Reading failed.
    #[error("read: {0}")]
    Read(String),
}

/// Why the pre-flight refused to start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreflightError {
    /// The process runs as root; the session must run as its own OS user.
    #[error("refusing to run as root: run m2a-session as its own OS user")]
    Root,
    /// The node-key file was refused.
    #[error("node key {path}: {reason}")]
    KeyFile {
        /// The file.
        path: PathBuf,
        /// Why.
        reason: KeyFileError,
    },
}

/// Runs the pre-flight and returns the node key.
pub fn preflight(check: &Preflight) -> Result<NodeKey, PreflightError> {
    if check.euid == 0 {
        return Err(PreflightError::Root);
    }
    match &check.key {
        KeySource::Ephemeral => Ok(NodeKey::ephemeral()),
        KeySource::File(path) => {
            load_key_file(path, check.euid).map_err(|reason| PreflightError::KeyFile {
                path: path.clone(),
                reason,
            })
        }
    }
}

/// Opens `path` without following a symlink and checks the open file (`fstat`), so the file
/// checked is the file read.
fn load_key_file(path: &Path, euid: u32) -> Result<NodeKey, KeyFileError> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = rustix::fs::open(path, flags, Mode::empty())
        .map_err(|e| KeyFileError::Open(e.to_string()))?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| KeyFileError::Read(e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(KeyFileError::NotRegular);
    }
    let mode = meta.mode() & 0o7777;
    if mode != KEY_FILE_MODE {
        return Err(KeyFileError::Mode(mode));
    }
    if meta.uid() != euid {
        return Err(KeyFileError::Owner {
            owner: meta.uid(),
            euid,
        });
    }
    if meta.len() != KEY_FILE_LEN {
        return Err(KeyFileError::Length(meta.len()));
    }
    // Wiped on drop, on every path: `try_from_bytes` zeroes its input only when it succeeds.
    let mut secret = Zeroizing::new([0u8; KEY_FILE_LEN as usize]);
    (&file)
        .take(KEY_FILE_LEN)
        .read_exact(&mut secret[..])
        .map_err(|e| KeyFileError::Read(e.to_string()))?;
    let secret =
        secp256k1::SecretKey::try_from_bytes(&mut secret[..]).map_err(|_| KeyFileError::Invalid)?;
    Ok(NodeKey(Keypair::from(secp256k1::Keypair::from(secret))))
}

/// The pinned peer: its identity and the one address it is dialed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedPeer {
    /// The identity Noise must prove.
    pub peer_id: PeerId,
    /// The address to dial, without the `/p2p/` suffix.
    pub addr: Multiaddr,
}

/// Why a pinned-peer address was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinnedPeerError {
    /// Not a multiaddr.
    #[error("not a multiaddr: {0}")]
    Multiaddr(String),
    /// The multiaddr does not end in `/p2p/<peer id>`.
    #[error("the multiaddr must end in /p2p/<peer id>")]
    NoPeerId,
    /// The part before `/p2p/` is not one dialable IP address and TCP port.
    #[error(
        "the address before /p2p/ must be /ip4/<addr>/tcp/<port> or /ip6/<addr>/tcp/<port> \
         (a specified address, port 1..=65535; the session has no DNS, QUIC or relay transport)"
    )]
    Transport,
}

impl std::str::FromStr for PinnedPeer {
    type Err = PinnedPeerError;

    /// Parses `/ip4|ip6/<addr>/tcp/<port>/p2p/<peer id>`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr: Multiaddr = s
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| PinnedPeerError::Multiaddr(e.to_string()))?;
        let peer_id = match addr.pop() {
            Some(AddrProtocol::P2p(peer_id)) if !addr.is_empty() => peer_id,
            _ => return Err(PinnedPeerError::NoPeerId),
        };
        if !is_tcp_dial_addr(&addr) {
            return Err(PinnedPeerError::Transport);
        }
        Ok(Self { peer_id, addr })
    }
}

/// `/ip4|ip6/<addr>/tcp/<port>` and nothing else: a specified address and a non-zero port. The
/// swarm has only the TCP transport, so a DNS name would never dial.
fn is_tcp_dial_addr(addr: &Multiaddr) -> bool {
    let mut parts = addr.iter();
    let ip = match parts.next() {
        Some(AddrProtocol::Ip4(ip)) => std::net::IpAddr::V4(ip),
        Some(AddrProtocol::Ip6(ip)) => std::net::IpAddr::V6(ip),
        _ => return false,
    };
    let port = match parts.next() {
        Some(AddrProtocol::Tcp(port)) => port,
        _ => return false,
    };
    parts.next().is_none() && !ip.is_unspecified() && port != 0
}

/// The session's behaviours: the allow list, then one outbound behaviour per protocol.
#[derive(NetworkBehaviour)]
pub struct SessionBehaviour<E: EthSpec> {
    allowed: allow_block_list::Behaviour<AllowedPeers>,
    /// `/eth2/beacon_chain/req/status/2/ssz_snappy`.
    pub status: request_response::Behaviour<RpcCodec<E>>,
    /// `/eth2/beacon_chain/req/metadata/3/ssz_snappy`.
    pub metadata: request_response::Behaviour<RpcCodec<E>>,
    /// `/eth2/beacon_chain/req/ping/1/ssz_snappy`.
    pub ping: request_response::Behaviour<RpcCodec<E>>,
    /// `/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy`.
    pub blocks_by_range: request_response::Behaviour<RpcCodec<E>>,
}

impl<E: EthSpec> SessionBehaviour<E> {
    /// Behaviours that allow only `pinned`.
    pub fn new(pinned: PeerId, contexts: Arc<ContextTable>, deadlines: Deadlines) -> Self {
        let mut allowed = allow_block_list::Behaviour::<AllowedPeers>::default();
        allowed.allow_peer(pinned);
        let codec = RpcCodec::new(contexts, deadlines);
        let rpc = |p| outbound_behaviour(p, codec.clone());
        Self {
            allowed,
            status: rpc(Protocol::StatusV2),
            metadata: rpc(Protocol::MetaDataV3),
            ping: rpc(Protocol::PingV1),
            blocks_by_range: rpc(Protocol::BlocksByRangeV2),
        }
    }
}

impl<E: EthSpec> crate::rpc::outbound::StatusRpc<E> for SessionBehaviour<E> {
    fn status_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>> {
        &mut self.status
    }

    fn status_event(event: SessionBehaviourEvent<E>) -> Option<crate::rpc::outbound::RpcEvent<E>> {
        match event {
            SessionBehaviourEvent::Status(e) => Some(e),
            _ => None,
        }
    }
}

impl<E: EthSpec> crate::rpc::outbound::MetaDataRpc<E> for SessionBehaviour<E> {
    fn metadata_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>> {
        &mut self.metadata
    }

    fn metadata_event(
        event: SessionBehaviourEvent<E>,
    ) -> Option<crate::rpc::outbound::RpcEvent<E>> {
        match event {
            SessionBehaviourEvent::Metadata(e) => Some(e),
            _ => None,
        }
    }
}

/// The transport a session runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TCP + Noise + yamux: the only production transport.
    Tcp,
    /// In-process `MemoryTransport` + Noise + yamux, for tests.
    #[cfg(test)]
    Memory,
}

/// The identities of a [`SessionError::WrongPeerId`] (boxed: two peer IDs are large).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongPeerId {
    /// The pinned peer.
    pub pinned: PeerId,
    /// The identity the peer proved.
    pub obtained: PeerId,
}

/// Why the session failed.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The swarm could not be built.
    #[error("swarm: {0}")]
    Build(String),
    /// The peer at the pinned address proved another identity: Noise completed, and the swarm
    /// closed the connection because the peer ID is not the pinned one.
    #[error(
        "wrong peer ID: pinned {}, the peer at the address is {}",
        .0.pinned,
        .0.obtained
    )]
    WrongPeerId(Box<WrongPeerId>),
    /// The dial could not start or failed.
    #[error("dial {peer}: {reason}")]
    Dial {
        /// The pinned peer.
        peer: PeerId,
        /// Why.
        reason: String,
    },
    /// The swarm reported a listen address, which it must never have.
    #[error("unexpected listen address {0}")]
    Listening(Multiaddr),
}

/// `error` and every `source()` under it, `: `-separated.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut next = error.source();
    while let Some(e) = next {
        out.push_str(": ");
        out.push_str(&e.to_string());
        next = e.source();
    }
    out
}

/// Builds the swarm on `transport`. No `listen_on` follows, here or anywhere.
fn build_swarm<E: EthSpec>(
    key: NodeKey,
    behaviour: SessionBehaviour<E>,
    transport: Transport,
) -> Result<Swarm<SessionBehaviour<E>>, SessionError> {
    let build = |e: &dyn fmt::Display| SessionError::Build(e.to_string());
    let upgraded: fn(&Keypair) -> TransportResult = match transport {
        Transport::Tcp => tcp_transport,
        #[cfg(test)]
        Transport::Memory => memory_transport,
    };
    Ok(SwarmBuilder::with_existing_identity(key.0)
        .with_tokio()
        .with_other_transport(upgraded)
        .map_err(|e| build(&e))?
        .with_behaviour(|_| behaviour)
        .map_err(|e| build(&e))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build())
}

/// An authenticated, multiplexed transport, or why it could not be built.
type TransportResult = Result<
    libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    Box<dyn std::error::Error + Send + Sync>,
>;

/// TCP + Noise XX + yamux: the production transport.
///
/// Negotiated with multistream-select `V1`, not the `V1Lazy` of `SwarmBuilder::with_tcp`: under
/// `V1Lazy` a dialer offering one protocol assumes the listener accepted it, so a connection to
/// a peer without yamux is reported established before it fails. Under `V1` the dialer waits
/// for each confirmation, so an established connection proves the peer completed Noise (and
/// with it the peer ID) and accepted yamux.
fn tcp_transport(key: &Keypair) -> TransportResult {
    use libp2p::core::upgrade::Version;
    use libp2p::Transport as _;
    Ok(tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(key)?)
        .multiplex(yamux::Config::default())
        .map(|(peer, muxer), _| (peer, libp2p::core::muxing::StreamMuxerBox::new(muxer)))
        .boxed())
}

/// `MemoryTransport` + Noise + yamux: the test transport, upgraded like the TCP one.
#[cfg(test)]
fn memory_transport(key: &Keypair) -> TransportResult {
    use libp2p::core::{transport::MemoryTransport, upgrade::Version};
    use libp2p::Transport as _;
    Ok(MemoryTransport::default()
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(key)?)
        .multiplex(yamux::Config::default())
        .boxed())
}

/// A running session: the swarm, its pinned peer and what the peer told us.
pub struct Session<E: EthSpec> {
    swarm: Swarm<SessionBehaviour<E>>,
    pinned: PinnedPeer,
    /// The peer's last decoded MetaData; its `seq_number` is what a Ping must carry.
    peer_metadata: Option<MetaDataV3>,
}

impl<E: EthSpec> Session<E> {
    /// Builds the swarm and starts the one dial, to `pinned` at its address.
    pub fn start(
        key: NodeKey,
        pinned: PinnedPeer,
        contexts: Arc<ContextTable>,
        deadlines: Deadlines,
        transport: Transport,
    ) -> Result<Self, SessionError> {
        let local = key.peer_id();
        tracing::info!(%local, pinned = %pinned.peer_id, addr = %pinned.addr, ?key, "m2a-session starting");
        let behaviour = SessionBehaviour::new(pinned.peer_id, contexts, deadlines);
        let mut swarm = build_swarm(key, behaviour, transport)?;
        let dial = DialOpts::peer_id(pinned.peer_id)
            .addresses(vec![pinned.addr.clone()])
            .build();
        swarm.dial(dial).map_err(|e| SessionError::Dial {
            peer: pinned.peer_id,
            reason: e.to_string(),
        })?;
        Ok(Self {
            swarm,
            pinned,
            peer_metadata: None,
        })
    }

    /// The swarm, for the req/resp work that follows the connection.
    pub fn swarm(&mut self) -> &mut Swarm<SessionBehaviour<E>> {
        &mut self.swarm
    }

    /// The pinned peer.
    pub fn pinned(&self) -> &PinnedPeer {
        &self.pinned
    }

    /// Requests the pinned peer's MetaData v3 ([`crate::rpc::outbound::metadata`]) and keeps
    /// it as [`Session::peer_metadata`]. A failed request keeps the previous one.
    pub async fn request_metadata(&mut self) -> Result<MetaDataV3, OutboundError> {
        let peer = self.pinned.peer_id;
        let m = crate::rpc::outbound::metadata(&mut self.swarm, peer).await?;
        self.peer_metadata = Some(m.clone());
        Ok(m)
    }

    /// The peer's last MetaData from [`Session::request_metadata`]; `None` before the first.
    pub fn peer_metadata(&self) -> Option<&MetaDataV3> {
        self.peer_metadata.as_ref()
    }

    /// Connections the swarm has established and not yet closed.
    pub fn open_connections(&self) -> u32 {
        self.swarm
            .network_info()
            .connection_counters()
            .num_established()
    }

    /// Drives the swarm until the pinned peer is connected, or the dial failed.
    pub async fn connect(&mut self) -> Result<(), SessionError> {
        let pinned = self.pinned.peer_id;
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    ..
                } => {
                    if peer_id == pinned {
                        tracing::info!(peer = %peer_id, "connected to the pinned peer");
                        return Ok(());
                    }
                    tracing::warn!(peer = %peer_id, "closing a connection to a peer that is not pinned");
                    self.swarm.close_connection(connection_id);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    tracing::warn!(peer = ?peer_id, %error, "dial failed");
                    return Err(match error {
                        DialError::WrongPeerId { obtained, .. } => {
                            SessionError::WrongPeerId(Box::new(WrongPeerId { pinned, obtained }))
                        }
                        error => SessionError::Dial {
                            peer: pinned,
                            reason: error_chain(&error),
                        },
                    });
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    return Err(SessionError::Listening(address));
                }
                other => tracing::debug!(event = ?other, "swarm event"),
            }
        }
    }

    /// Closes every connection to the pinned peer and drives the swarm until the last one is
    /// closed. A no-op when none is open.
    pub async fn disconnect(&mut self) -> Result<(), SessionError> {
        let pinned = self.pinned.peer_id;
        if self.swarm.disconnect_peer_id(pinned).is_err() {
            return Ok(());
        }
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    num_established: 0,
                    ..
                } if peer_id == pinned => {
                    tracing::info!(peer = %peer_id, "disconnected from the pinned peer");
                    return Ok(());
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    return Err(SessionError::Listening(address));
                }
                other => tracing::debug!(event = ?other, "swarm event"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::Minimal;
    use libp2p::swarm::dummy;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    type E = Minimal;

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn key_file(mode: u32, bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        file
    }

    fn secret_of(key: &NodeKey) -> [u8; 32] {
        key.0
            .clone()
            .try_into_secp256k1()
            .unwrap()
            .secret()
            .to_bytes()
    }

    #[test]
    fn refuses_root() {
        for key in [KeySource::Ephemeral, KeySource::File("/nonexistent".into())] {
            let err = preflight(&Preflight { euid: 0, key }).unwrap_err();
            assert_eq!(err, PreflightError::Root);
        }
        let key = preflight(&Preflight {
            euid: 1000,
            key: KeySource::Ephemeral,
        })
        .unwrap();
        assert!(
            key.0.clone().try_into_secp256k1().is_ok(),
            "ephemeral keys are secp256k1"
        );
    }

    #[test]
    fn refuses_key_mode_0644() {
        let file = key_file(0o644, &[7; 32]);
        let err = preflight(&Preflight {
            euid: euid(),
            key: KeySource::File(file.path().into()),
        });
        assert!(
            matches!(
                &err,
                Err(PreflightError::KeyFile {
                    reason: KeyFileError::Mode(0o644),
                    ..
                })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn key_file_0600_owned_by_euid_loads() {
        let file = key_file(0o600, &[7; 32]);
        let key = preflight(&Preflight {
            euid: euid(),
            key: KeySource::File(file.path().into()),
        })
        .unwrap();
        assert_eq!(secret_of(&key), [7; 32]);
    }

    #[test]
    fn key_file_refusals() {
        let check = |path: &Path, euid| match preflight(&Preflight {
            euid,
            key: KeySource::File(path.into()),
        }) {
            Err(PreflightError::KeyFile { reason, .. }) => reason,
            other => panic!("{other:?}"),
        };
        let file = key_file(0o600, &[7; 32]);
        // The euid is injected, so another owner is testable without root.
        assert_eq!(
            check(file.path(), euid() + 1),
            KeyFileError::Owner {
                owner: euid(),
                euid: euid() + 1
            }
        );
        assert_eq!(
            check(key_file(0o600, &[7; 31]).path(), euid()),
            KeyFileError::Length(31)
        );
        assert_eq!(
            check(key_file(0o600, &[0; 32]).path(), euid()),
            KeyFileError::Invalid
        );
        assert_eq!(
            check(key_file(0o400, &[7; 32]).path(), euid()),
            KeyFileError::Mode(0o400)
        );
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(file.path(), &link).unwrap();
        assert!(
            matches!(check(&link, euid()), KeyFileError::Open(_)),
            "symlinks are not followed"
        );
        assert!(matches!(
            check(&dir.path().join("missing"), euid()),
            KeyFileError::Open(_)
        ));
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(check(&sub, euid()), KeyFileError::NotRegular);
    }

    #[test]
    fn node_key_is_redacted() {
        let key = NodeKey::ephemeral();
        assert_eq!(format!("{key:?}"), "<redacted>");
        assert_eq!(format!("{key}"), "<redacted>");
        assert_eq!(format!("{:?}", Some(&key)), "Some(<redacted>)");
    }

    #[test]
    fn pinned_peer_parses_addr_and_id() {
        let id = PeerId::random();
        let pinned: PinnedPeer = format!("/ip4/127.0.0.1/tcp/9000/p2p/{id}").parse().unwrap();
        assert_eq!(pinned.peer_id, id);
        assert_eq!(
            pinned.addr,
            "/ip4/127.0.0.1/tcp/9000".parse::<Multiaddr>().unwrap()
        );
        assert_eq!(
            "/ip4/127.0.0.1/tcp/9000".parse::<PinnedPeer>(),
            Err(PinnedPeerError::NoPeerId)
        );
        assert_eq!(
            format!("/p2p/{id}").parse::<PinnedPeer>(),
            Err(PinnedPeerError::NoPeerId)
        );
        assert!(matches!(
            "nonsense".parse::<PinnedPeer>(),
            Err(PinnedPeerError::Multiaddr(_))
        ));
        let v6: PinnedPeer = format!("/ip6/::1/tcp/9000/p2p/{id}").parse().unwrap();
        assert_eq!(v6.addr, "/ip6/::1/tcp/9000".parse::<Multiaddr>().unwrap());
    }

    #[test]
    fn pinned_peer_must_be_an_ip_and_a_tcp_port() {
        let id = PeerId::random();
        for addr in [
            "/ip4/127.0.0.1/udp/9000/quic-v1",
            "/ip4/127.0.0.1",
            "/tcp/9000",
            "/ip4/127.0.0.1/tcp/0",
            "/ip4/0.0.0.0/tcp/9000",
            "/ip6/::/tcp/9000",
            "/ip4/127.0.0.1/tcp/9000/ws",
            "/ip4/127.0.0.1/tcp/9000/tcp/9001",
            "/dns4/localhost/tcp/9000",
            "/dns/localhost/tcp/9000",
            "/dnsaddr/example.org",
            "/memory/1",
        ] {
            let addr = format!("{addr}/p2p/{id}");
            assert_eq!(
                addr.parse::<PinnedPeer>(),
                Err(PinnedPeerError::Transport),
                "{addr}"
            );
        }
        let relayed = format!(
            "/ip4/127.0.0.1/tcp/9000/p2p/{}/p2p-circuit/p2p/{id}",
            PeerId::random()
        );
        assert_eq!(
            relayed.parse::<PinnedPeer>(),
            Err(PinnedPeerError::Transport)
        );
        let twice = format!("/ip4/127.0.0.1/tcp/9000/p2p/{}/p2p/{id}", PeerId::random());
        assert_eq!(twice.parse::<PinnedPeer>(), Err(PinnedPeerError::Transport));
    }

    /// A peer on the memory transport that accepts connections and serves nothing.
    async fn memory_peer() -> (PeerId, Multiaddr) {
        let mut swarm = SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
            .with_tokio()
            .with_other_transport(memory_transport)
            .unwrap()
            .with_behaviour(|_| dummy::Behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let id = *swarm.local_peer_id();
        swarm.listen_on("/memory/0".parse().unwrap()).unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        tokio::spawn(async move {
            loop {
                swarm.select_next_some().await;
            }
        });
        (id, addr)
    }

    fn start(pinned: PinnedPeer) -> Session<E> {
        Session::start(
            NodeKey::ephemeral(),
            pinned,
            Arc::new(ContextTable::new()),
            Deadlines::default(),
            Transport::Memory,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn connects_to_the_pinned_peer() {
        let (peer_id, addr) = memory_peer().await;
        let mut session = start(PinnedPeer { peer_id, addr });
        session.connect().await.unwrap();
        assert!(session.swarm().is_connected(&peer_id));
        assert_eq!(session.pinned().peer_id, peer_id);
    }

    #[tokio::test]
    async fn no_listen_addrs() {
        let (peer_id, addr) = memory_peer().await;
        let mut session = start(PinnedPeer { peer_id, addr });
        assert_eq!(session.swarm().listeners().count(), 0);
        session.connect().await.unwrap();
        assert_eq!(
            session.swarm().listeners().count(),
            0,
            "still none once connected"
        );
        assert_eq!(session.swarm().external_addresses().count(), 0);
    }

    #[tokio::test]
    async fn wrong_peer_id_refused() {
        // A real peer at the address, but with an identity other than the pinned one.
        let (other, addr) = memory_peer().await;
        let pinned = PeerId::random();
        let mut session = start(PinnedPeer {
            peer_id: pinned,
            addr: addr.clone(),
        });
        let err = session.connect().await.unwrap_err();
        assert!(
            matches!(&err, SessionError::WrongPeerId(ids) if ids.pinned == pinned && ids.obtained == other),
            "{err}"
        );
        assert!(!session.swarm().is_connected(&other));
        assert!(!session.swarm().is_connected(&pinned));

        // A dial that names no peer ID reaches `other`, and the allow list denies it.
        let mut session = start(PinnedPeer {
            peer_id: pinned,
            addr: addr.clone(),
        });
        let _ = session.connect().await;
        session
            .swarm()
            .dial(DialOpts::unknown_peer_id().address(addr).build())
            .unwrap();
        let err = session.connect().await.unwrap_err();
        assert!(err.to_string().contains("denied"), "{err}");
        assert!(!session.swarm().is_connected(&other));
    }

    #[tokio::test]
    async fn session_keeps_the_peers_metadata() {
        use crate::testkit::{MetaDataReply, StatusPeer, StatusReply};
        let canned = p2p_wire::testkit::metadata();
        let reply = canned.clone();
        let peer = StatusPeer::spawn_with_metadata(
            Box::new(|req, _| StatusReply::Status(req.clone())),
            Some(Box::new(move |_| MetaDataReply::MetaData(reply.clone()))),
            None,
        )
        .await;
        let mut session = Session::<E>::start(
            NodeKey::ephemeral(),
            peer.pinned(),
            Arc::new(ContextTable::new()),
            Deadlines::default(),
            Transport::Tcp,
        )
        .unwrap();
        assert_eq!(session.peer_metadata(), None, "nothing before the request");
        session.connect().await.unwrap();
        assert_eq!(session.request_metadata().await.unwrap(), canned);
        assert_eq!(session.peer_metadata(), Some(&canned));
        assert_eq!(session.peer_metadata().map(|m| m.seq_number), Some(7));
    }
}
