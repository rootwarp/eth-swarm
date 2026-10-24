//! The `m2a-session` skeleton: one pinned outbound peer, no listener, its own OS user.
//!
//! - **Pre-flight** ([`preflight`], with `test_build = false` in the deployed `m2a-session` and
//!   `true` only in the test binary `m2a-session-test`): refuses a platform other than Linux in
//!   production, and refuses to run as root, with a real or saved UID other than the effective
//!   one ([`check_process`]; macOS cannot read the saved UID, see [`os_user`]), or as any
//!   effective UID other than the session user's (the config's `run_as`, default
//!   `m2a-session`, resolved through `getpwnam_r`), and loads the node key: an ephemeral
//!   secp256k1 key, or a 32-byte secp256k1 secret from a credential file that must be a
//!   regular file (not a symlink) of mode 0600 owned by the effective UID. [`NodeKey`] prints
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
//!   ([`crate::rpc`]). Status goes out through [`crate::rpc::outbound::status`], MetaData
//!   through [`Session::request_metadata`], which keeps the peer's MetaData (its `seq_number`
//!   for Ping), Ping through [`crate::rpc::outbound::ping`] and one BlocksByRange through
//!   [`crate::rpc::outbound::blocks_by_range`].

pub mod config;
pub mod os_user;

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

    /// The key from a checked node-key credential ([`node_key::load`]); `None` if libp2p
    /// refuses the secret. The secret's bytes are wiped either way.
    pub fn from_secret(mut secret: node_key::NodeKeySecret) -> Option<Self> {
        // `try_from_bytes` zeroes its input on success; `secret` zeroizes itself on drop.
        let secret = secp256k1::SecretKey::try_from_bytes(secret.expose_secret_mut()).ok()?;
        Some(Self(Keypair::from(secp256k1::Keypair::from(secret))))
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

/// Whether `run_as` may name `name`: the session account [`config::DEFAULT_RUN_AS`] only, or any
/// name in a test build. `test_build` is the caller's: the `m2a-session` binary passes `false`,
/// and only the test binary `m2a-session-test` passes `true`.
fn run_as_allowed(name: &str, test_build: bool) -> bool {
    name == config::DEFAULT_RUN_AS || test_build
}

/// Whether the session user's supplementary groups are checked: always for the session account,
/// and for any user outside a test build. A test build runs as the developer's own user, with
/// that user's groups.
fn groups_checked(name: &str, test_build: bool) -> bool {
    name == config::DEFAULT_RUN_AS || !test_build
}

/// Whether the pre-flight runs on `os` (`std::env::consts::OS`): Linux only in production, any
/// platform in a test build. On macOS `initgroups` adds system groups (12, 61, 100, 701 and
/// others) to every user, which the supplementary-group rule refuses, so a production run
/// there could never pass; this says so at once.
fn platform_allowed(os: &str, test_build: bool) -> bool {
    os == "linux" || test_build
}

/// Refuses a platform `os` other than Linux, unless `test_build` (see [`platform_allowed`]). The
/// binary runs it right after [`check_process`], before it reads the config.
///
/// # Errors
///
/// [`PreflightError::NotLinux`].
pub fn check_platform(os: &str, test_build: bool) -> Result<(), PreflightError> {
    if platform_allowed(os, test_build) {
        Ok(())
    } else {
        Err(PreflightError::NotLinux(os.to_owned()))
    }
}

/// Refuses a `run_as` other than the session account [`config::DEFAULT_RUN_AS`], unless
/// `test_build` (see [`run_as_allowed`]). The binary runs it before it asks the name service
/// for the user.
///
/// # Errors
///
/// [`PreflightError::NotTheSessionAccount`].
pub fn check_run_as(name: &str, test_build: bool) -> Result<(), PreflightError> {
    if run_as_allowed(name, test_build) {
        Ok(())
    } else {
        Err(PreflightError::NotTheSessionAccount(name.to_owned()))
    }
}

/// The OS user the session must run as: the config's `run_as`, and the UID and primary GID its
/// passwd entry gives ([`os_user::user_of`] in production).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser {
    /// The user name.
    pub name: String,
    /// Its UID.
    pub uid: u32,
    /// Its primary GID.
    pub gid: u32,
}

/// What the session checks before it touches the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    /// The process's real, effective and saved UIDs ([`os_user::process_uids`] in production).
    pub uids: os_user::ProcessUids,
    /// The process's GIDs and supplementary groups ([`os_user::process_gids`] in production).
    pub gids: os_user::ProcessGids,
    /// The platform ([`Preflight::os_of_this_build`] in production).
    pub os: String,
    /// The session user: the effective UID must be its UID.
    pub user: SessionUser,
    /// The node key.
    pub key: KeySource,
}

impl Preflight {
    /// The platform this binary was built for: `std::env::consts::OS`.
    pub fn os_of_this_build() -> &'static str {
        std::env::consts::OS
    }
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
    /// The real UID, or the saved UID where the platform reads it, differs from the effective
    /// UID: the process could switch back to that UID (as after `setpriv --euid` from root).
    #[error(
        "refusing to run with real UID {real}, effective UID {effective} and saved UID {}: the \
         process could switch back to another UID; run m2a-session with all three set to its own \
         user",
        saved.map_or_else(|| "unknown".to_owned(), |s| s.to_string())
    )]
    MixedUids {
        /// The real UID.
        real: u32,
        /// The effective UID.
        effective: u32,
        /// The saved UID; `None` where the platform cannot read it.
        saved: Option<u32>,
    },
    /// A real, effective or saved GID is 0 (as after `setpriv --reuid` without `--regid`).
    #[error(
        "refusing to run with GID 0 (real, effective or saved): run m2a-session with its own \
         user's group"
    )]
    RootGroup,
    /// The real GID, or the saved GID where the platform reads it, differs from the effective
    /// GID.
    #[error(
        "refusing to run with real GID {real}, effective GID {effective} and saved GID {}: the \
         process could switch back to another group",
        saved.map_or_else(|| "unknown".to_owned(), |s| s.to_string())
    )]
    MixedGids {
        /// The real GID.
        real: u32,
        /// The effective GID.
        effective: u32,
        /// The saved GID; `None` where the platform cannot read it.
        saved: Option<u32>,
    },
    /// A production run on a platform other than Linux.
    #[error(
        "refusing to run on {0}: m2a-session runs in production on Linux only (on other \
         platforms the system adds groups that the session account must not have)"
    )]
    NotLinux(String),
    /// `run_as` names another user than the session account, outside a test build.
    #[error("refusing run_as {0:?}: m2a-session runs only as its own account \"m2a-session\"")]
    NotTheSessionAccount(String),
    /// The process runs as a UID other than the session user's: a shared login account can
    /// hold other credentials, so the session runs only as its own user.
    #[error(
        "refusing to run as effective UID {euid}: run m2a-session as its own OS user {user:?} \
         (UID {uid}), as run_as names it"
    )]
    WrongUser {
        /// The effective UID.
        euid: u32,
        /// The session user's name.
        user: String,
        /// The session user's UID.
        uid: u32,
    },
    /// The effective GID is not the session user's primary GID.
    #[error(
        "refusing to run as effective GID {egid}: run m2a-session with the primary group of \
         {user:?} (GID {gid})"
    )]
    WrongGroup {
        /// The effective GID.
        egid: u32,
        /// The session user's name.
        user: String,
        /// Its primary GID.
        gid: u32,
    },
    /// Supplementary groups other than the session user's primary GID (root's groups, say).
    #[error(
        "refusing to run with supplementary groups {groups:?}: run m2a-session with only the \
         primary group of {user:?}"
    )]
    ExtraGroups {
        /// The session user's name.
        user: String,
        /// The groups other than its primary GID.
        groups: Vec<u32>,
    },
    /// The node-key file was refused.
    #[error("node key {path}: {reason}")]
    KeyFile {
        /// The file.
        path: PathBuf,
        /// Why.
        reason: KeyFileError,
    },
}

/// The checks of the process alone, which need no lookup: an effective UID of root, a real or
/// saved UID other than the effective one, a GID of 0, then a real or saved GID other than the
/// effective one. The binary runs it before it reads the config or asks the name service for
/// the session user.
///
/// # Errors
///
/// [`PreflightError::Root`], [`PreflightError::MixedUids`], [`PreflightError::RootGroup`] or
/// [`PreflightError::MixedGids`].
pub fn check_process(
    uids: &os_user::ProcessUids,
    gids: &os_user::ProcessGids,
) -> Result<(), PreflightError> {
    if uids.effective == 0 {
        return Err(PreflightError::Root);
    }
    if !uids.all_equal() {
        return Err(PreflightError::MixedUids {
            real: uids.real,
            effective: uids.effective,
            saved: uids.saved,
        });
    }
    if gids.has_root_group() {
        return Err(PreflightError::RootGroup);
    }
    if !gids.all_equal() {
        return Err(PreflightError::MixedGids {
            real: gids.real,
            effective: gids.effective,
            saved: gids.saved,
        });
    }
    Ok(())
}

/// Runs the pre-flight and returns the node key: [`check_process`], the platform (Linux only
/// outside a test build), [`check_run_as`], then an effective UID other than the session
/// user's, an effective GID other than its primary GID, supplementary groups other than that
/// GID, then a node-key file that fails its checks. `test_build` is `false` in the
/// `m2a-session` binary, and `true` only in the test binary `m2a-session-test`.
pub fn preflight(check: &Preflight, test_build: bool) -> Result<NodeKey, PreflightError> {
    check_process(&check.uids, &check.gids)?;
    check_platform(&check.os, test_build)?;
    let user = &check.user;
    check_run_as(&user.name, test_build)?;
    let euid = check.uids.effective;
    if euid != user.uid {
        return Err(PreflightError::WrongUser {
            euid,
            user: user.name.clone(),
            uid: user.uid,
        });
    }
    if check.gids.effective != user.gid {
        return Err(PreflightError::WrongGroup {
            egid: check.gids.effective,
            user: user.name.clone(),
            gid: user.gid,
        });
    }
    let extra: Vec<u32> = check
        .gids
        .groups
        .iter()
        .copied()
        .filter(|g| *g != user.gid)
        .collect();
    if !extra.is_empty() && groups_checked(&user.name, test_build) {
        return Err(PreflightError::ExtraGroups {
            user: user.name.clone(),
            groups: extra,
        });
    }
    match &check.key {
        KeySource::Ephemeral => Ok(NodeKey::ephemeral()),
        KeySource::File(path) => {
            load_key_file(path, euid).map_err(|reason| PreflightError::KeyFile {
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

impl<E: EthSpec> crate::rpc::outbound::PingRpc<E> for SessionBehaviour<E> {
    fn ping_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>> {
        &mut self.ping
    }

    fn ping_event(event: SessionBehaviourEvent<E>) -> Option<crate::rpc::outbound::RpcEvent<E>> {
        match event {
            SessionBehaviourEvent::Ping(e) => Some(e),
            _ => None,
        }
    }
}

impl<E: EthSpec> crate::rpc::outbound::BlocksByRangeRpc<E> for SessionBehaviour<E> {
    fn blocks_by_range_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>> {
        &mut self.blocks_by_range
    }

    fn blocks_by_range_event(
        event: SessionBehaviourEvent<E>,
    ) -> Option<crate::rpc::outbound::RpcEvent<E>> {
        match event {
            SessionBehaviourEvent::BlocksByRange(e) => Some(e),
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
    idle_timeout: Duration,
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
        .with_swarm_config(|c| c.with_idle_connection_timeout(idle_timeout))
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
    /// Builds the swarm and starts the one dial, to `pinned` at its address. An idle
    /// connection closes after [`IDLE_CONNECTION_TIMEOUT`].
    pub fn start(
        key: NodeKey,
        pinned: PinnedPeer,
        contexts: Arc<ContextTable>,
        deadlines: Deadlines,
        transport: Transport,
    ) -> Result<Self, SessionError> {
        Self::start_with_idle_timeout(
            key,
            pinned,
            contexts,
            deadlines,
            transport,
            IDLE_CONNECTION_TIMEOUT,
        )
    }

    /// [`Session::start`], with a connection closing once no stream was open for
    /// `idle_timeout`.
    pub fn start_with_idle_timeout(
        key: NodeKey,
        pinned: PinnedPeer,
        contexts: Arc<ContextTable>,
        deadlines: Deadlines,
        transport: Transport,
        idle_timeout: Duration,
    ) -> Result<Self, SessionError> {
        let local = key.peer_id();
        tracing::info!(%local, pinned = %pinned.peer_id, addr = %pinned.addr, ?key, "m2a-session starting");
        let behaviour = SessionBehaviour::new(pinned.peer_id, contexts, deadlines);
        let mut swarm = build_swarm(key, behaviour, transport, idle_timeout)?;
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
    use super::os_user::{ProcessGids, ProcessUids};
    use super::*;
    use consensus_types::Minimal;
    use libp2p::swarm::dummy;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    type E = Minimal;

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    /// The session user `m2a-session`, injected as UID `uid` with primary GID `uid`.
    fn user(uid: u32) -> SessionUser {
        SessionUser {
            name: "m2a-session".into(),
            uid,
            gid: uid,
        }
    }

    /// GID 0 (real, effective or saved) and mixed GIDs are refused with the process checks:
    /// `setpriv --reuid` without `--regid` keeps root's GID.
    #[test]
    fn refuses_the_root_group_and_mixed_gids() {
        let uids = ProcessUids::same(1000);
        for gids in [
            ProcessGids::same(0),
            ProcessGids {
                real: 0,
                ..ProcessGids::same(1000)
            },
            ProcessGids {
                saved: Some(0),
                ..ProcessGids::same(1000)
            },
        ] {
            assert_eq!(
                check_process(&uids, &gids),
                Err(PreflightError::RootGroup),
                "{gids:?}"
            );
        }
        let mixed = ProcessGids {
            real: 1001,
            ..ProcessGids::same(1000)
        };
        assert_eq!(
            check_process(&uids, &mixed),
            Err(PreflightError::MixedGids {
                real: 1001,
                effective: 1000,
                saved: Some(1000)
            })
        );
        assert_eq!(
            PreflightError::RootGroup.to_string(),
            "refusing to run with GID 0 (real, effective or saved): run m2a-session with its own \
             user's group"
        );
        // Root's UID is refused before its group.
        assert_eq!(
            check_process(&ProcessUids::same(0), &ProcessGids::same(0)),
            Err(PreflightError::Root)
        );
    }

    /// The effective GID must be the session user's primary GID, and every supplementary group
    /// that GID: root's groups do not stay with the session.
    #[test]
    fn refuses_a_group_other_than_the_session_users() {
        let check = |gids: ProcessGids| {
            strict(&Preflight {
                uids: ProcessUids::same(1000),
                gids,
                user: user(1000),
                os: "linux".into(),
                key: KeySource::Ephemeral,
            })
            .map(|_| ())
        };
        assert_eq!(
            check(ProcessGids::same(1001)),
            Err(PreflightError::WrongGroup {
                egid: 1001,
                user: "m2a-session".into(),
                gid: 1000
            })
        );
        assert_eq!(
            check(ProcessGids {
                groups: vec![1000, 27, 4],
                ..ProcessGids::same(1000)
            }),
            Err(PreflightError::ExtraGroups {
                user: "m2a-session".into(),
                groups: vec![27, 4]
            })
        );
        assert_eq!(
            PreflightError::ExtraGroups {
                user: "m2a-session".into(),
                groups: vec![27, 4]
            }
            .to_string(),
            "refusing to run with supplementary groups [27, 4]: run m2a-session with only the \
             primary group of \"m2a-session\""
        );
        assert_eq!(
            check(ProcessGids {
                groups: vec![1000],
                ..ProcessGids::same(1000)
            }),
            Ok(())
        );
        assert_eq!(check(ProcessGids::same(1000)), Ok(()));
    }

    /// The pre-flight runs only as the session account `m2a-session` unless its caller passes
    /// `test_build = true`, which only the test binary `m2a-session-test` does; then it takes
    /// another `run_as`,
    /// and then it does not hold that user to the session account's groups.
    #[test]
    fn the_session_account_is_the_only_run_as_outside_a_test_build() {
        assert!(run_as_allowed("m2a-session", false));
        assert!(!run_as_allowed("alice", false));
        assert!(run_as_allowed("alice", true));
        assert!(groups_checked("m2a-session", false));
        assert!(groups_checked("m2a-session", true));
        assert!(groups_checked("alice", false));
        assert!(!groups_checked("alice", true));
        assert_eq!(
            check_run_as("alice", false),
            Err(PreflightError::NotTheSessionAccount("alice".into()))
        );
        assert_eq!(check_run_as("m2a-session", false), Ok(()));
        assert_eq!(check_run_as("alice", true), Ok(()));
        assert_eq!(
            PreflightError::NotTheSessionAccount("alice".into()).to_string(),
            "refusing run_as \"alice\": m2a-session runs only as its own account \"m2a-session\""
        );
        let alice = Preflight {
            uids: ProcessUids::same(1000),
            gids: ProcessGids {
                groups: vec![1000, 20, 80],
                ..ProcessGids::same(1000)
            },
            user: SessionUser {
                name: "alice".into(),
                uid: 1000,
                gid: 1000,
            },
            os: "linux".into(),
            key: KeySource::Ephemeral,
        };
        // The production binary passes `test_build = false`: refused, whatever the build.
        assert_eq!(
            strict(&alice).unwrap_err(),
            PreflightError::NotTheSessionAccount("alice".into())
        );
        // A test build takes another name, and its own groups.
        assert!(preflight(&alice, true).is_ok());
    }

    /// The production pre-flight runs on Linux only: on macOS `initgroups` adds system groups
    /// (12, 61, 100, 701 and others) that the supplementary-group rule refuses, so a `sudo -u`
    /// run there could never pass. A test build runs on any platform; the Linux rule is the
    /// same in both.
    #[test]
    fn production_runs_on_linux_only() {
        assert!(platform_allowed("linux", false));
        assert!(!platform_allowed("macos", false));
        assert!(platform_allowed("macos", true));
        let on = |os: &str| Preflight {
            os: os.into(),
            ..ok_check()
        };
        assert_eq!(
            strict(&on("macos")).unwrap_err(),
            PreflightError::NotLinux("macos".into())
        );
        assert_eq!(
            PreflightError::NotLinux("macos".into()).to_string(),
            "refusing to run on macos: m2a-session runs in production on Linux only (on other \
             platforms the system adds groups that the session account must not have)"
        );
        assert!(strict(&on("linux")).is_ok());
        assert!(preflight(&on("macos"), true).is_ok());
        // macOS's own groups are still refused for the session account on Linux.
        let linux_extra = Preflight {
            gids: ProcessGids {
                groups: vec![1000, 12, 61, 100, 701],
                ..ProcessGids::same(1000)
            },
            ..ok_check()
        };
        assert!(matches!(
            preflight(&linux_extra, true),
            Err(PreflightError::ExtraGroups { .. })
        ));
        assert_eq!(Preflight::os_of_this_build(), std::env::consts::OS);
    }

    /// A check that passes: the session account on Linux, its own IDs, an ephemeral key.
    fn ok_check() -> Preflight {
        Preflight {
            uids: ProcessUids::same(1000),
            gids: ProcessGids::same(1000),
            user: user(1000),
            os: "linux".into(),
            key: KeySource::Ephemeral,
        }
    }

    /// The production pre-flight: `test_build = false`.
    fn strict(check: &Preflight) -> Result<NodeKey, PreflightError> {
        preflight(check, false)
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
            let err = strict(&Preflight {
                uids: ProcessUids::same(0),
                gids: ProcessGids::same(0),
                user: user(0),
                os: "linux".into(),
                key,
            })
            .unwrap_err();
            assert_eq!(err, PreflightError::Root);
        }
        let key = strict(&Preflight {
            uids: ProcessUids::same(1000),
            gids: ProcessGids::same(1000),
            user: user(1000),
            os: "linux".into(),
            key: KeySource::Ephemeral,
        })
        .unwrap();
        assert!(
            key.0.clone().try_into_secp256k1().is_ok(),
            "ephemeral keys are secp256k1"
        );
    }

    /// A process whose real or saved UID differs from its effective UID can switch back (as after
    /// `setpriv --euid` from root), so it is refused before the session user is compared. A
    /// saved UID the platform cannot read (macOS) leaves the real and effective UIDs to compare.
    #[test]
    fn refuses_mixed_real_effective_or_saved_uids() {
        for (uids, real, saved) in [
            (
                ProcessUids {
                    real: 0,
                    effective: 1000,
                    saved: Some(1000),
                },
                0,
                Some(1000),
            ),
            (
                ProcessUids {
                    real: 1000,
                    effective: 1000,
                    saved: Some(0),
                },
                1000,
                Some(0),
            ),
            (
                ProcessUids {
                    real: 1001,
                    effective: 1000,
                    saved: None,
                },
                1001,
                None,
            ),
        ] {
            let check = Preflight {
                uids,
                gids: ProcessGids::same(1000),
                user: user(1000),
                os: "linux".into(),
                key: KeySource::Ephemeral,
            };
            let want = PreflightError::MixedUids {
                real,
                effective: 1000,
                saved,
            };
            assert_eq!(
                check_process(&uids, &ProcessGids::same(1000)),
                Err(want.clone())
            );
            assert_eq!(strict(&check).unwrap_err(), want);
        }
        assert_eq!(
            PreflightError::MixedUids {
                real: 0,
                effective: 1000,
                saved: Some(1000)
            }
            .to_string(),
            "refusing to run with real UID 0, effective UID 1000 and saved UID 1000: the process \
             could switch back to another UID; run m2a-session with all three set to its own user"
        );
        assert_eq!(
            PreflightError::MixedUids {
                real: 1001,
                effective: 1000,
                saved: None
            }
            .to_string(),
            "refusing to run with real UID 1001, effective UID 1000 and saved UID unknown: the \
             process could switch back to another UID; run m2a-session with all three set to its \
             own user"
        );
        let macos = ProcessUids {
            real: 1000,
            effective: 1000,
            saved: None,
        };
        assert_eq!(check_process(&macos, &ProcessGids::same(1000)), Ok(()));
        assert_eq!(
            check_process(&ProcessUids::same(0), &ProcessGids::same(0)),
            Err(PreflightError::Root)
        );
    }

    /// A non-root effective UID that is not the session user's is refused before the key is
    /// read, and the error names the user and both UIDs. Root stays refused even if the
    /// session user is root.
    #[test]
    fn refuses_an_euid_other_than_the_session_user() {
        for key in [KeySource::Ephemeral, KeySource::File("/nonexistent".into())] {
            let err = strict(&Preflight {
                uids: ProcessUids::same(1000),
                gids: ProcessGids::same(1000),
                user: user(1001),
                os: "linux".into(),
                key,
            })
            .unwrap_err();
            assert_eq!(
                err,
                PreflightError::WrongUser {
                    euid: 1000,
                    user: "m2a-session".into(),
                    uid: 1001,
                }
            );
            assert_eq!(
                err.to_string(),
                "refusing to run as effective UID 1000: run m2a-session as its own OS user \
                 \"m2a-session\" (UID 1001), as run_as names it"
            );
        }
        assert_eq!(
            strict(&Preflight {
                uids: ProcessUids::same(0),
                gids: ProcessGids::same(0),
                user: user(0),
                os: "linux".into(),
                key: KeySource::Ephemeral,
            })
            .unwrap_err(),
            PreflightError::Root
        );
        assert!(strict(&Preflight {
            uids: ProcessUids::same(1001),
            gids: ProcessGids::same(1001),
            user: user(1001),
            os: "linux".into(),
            key: KeySource::Ephemeral,
        })
        .is_ok());
    }

    #[test]
    fn refuses_key_mode_0644() {
        let file = key_file(0o644, &[7; 32]);
        let err = strict(&Preflight {
            uids: ProcessUids::same(euid()),
            gids: ProcessGids::same(euid()),
            user: user(euid()),
            os: "linux".into(),
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
        let key = strict(&Preflight {
            uids: ProcessUids::same(euid()),
            gids: ProcessGids::same(euid()),
            user: user(euid()),
            os: "linux".into(),
            key: KeySource::File(file.path().into()),
        })
        .unwrap();
        assert_eq!(secret_of(&key), [7; 32]);
    }

    #[test]
    fn key_file_refusals() {
        let check = |path: &Path, euid| match strict(&Preflight {
            uids: ProcessUids::same(euid),
            gids: ProcessGids::same(euid),
            user: user(euid),
            os: "linux".into(),
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

    #[tokio::test]
    async fn idle_timeout_is_the_sessions() {
        use crate::testkit::StatusPeer;
        let peer = StatusPeer::echoing(p2p_wire::testkit::status()).await;
        let start = |idle| {
            Session::<E>::start_with_idle_timeout(
                NodeKey::ephemeral(),
                peer.pinned(),
                Arc::new(ContextTable::new()),
                Deadlines::default(),
                Transport::Tcp,
                idle,
            )
            .unwrap()
        };
        // With no stream open, our side closes the connection once the idle timeout passed.
        let mut short = start(Duration::from_millis(200));
        short.connect().await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::ConnectionClosed { .. } = short.swarm().select_next_some().await
                {
                    break;
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "closed after 200 ms idle");
        // The default keeps it.
        let mut default = Session::<E>::start(
            NodeKey::ephemeral(),
            peer.pinned(),
            Arc::new(ContextTable::new()),
            Deadlines::default(),
            Transport::Tcp,
        )
        .unwrap();
        default.connect().await.unwrap();
        let _ = tokio::time::timeout(
            Duration::from_millis(400),
            default.swarm().select_next_some(),
        )
        .await;
        assert!(default.swarm().is_connected(&peer.id));
    }
}
