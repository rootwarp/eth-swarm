//! The pinned outbound dial on real TCP, against an in-process reference peer on 127.0.0.1.
//!
//! The session side is the production path ([`Transport::Tcp`]: TCP + Noise XX + yamux). The
//! reference peer listens on an ephemeral loopback port and records, for every connection it
//! upgrades, the peer ID Noise authenticated and the muxer multistream-select negotiated. No
//! test leaves the host.

use cl_p2p::m2a_session::{NodeKey, PinnedPeer, Session, SessionError, Transport};
use cl_p2p::rpc::codec::Deadlines;
use consensus_types::Minimal;
use futures::future::Either;
use futures::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::upgrade::{SelectUpgrade, Version};
use libp2p::identity::{secp256k1, Keypair};
use libp2p::swarm::{dummy, SwarmEvent};
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, SwarmBuilder, Transport as _};
use p2p_wire::rpc::codec::ContextTable;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The muxers the reference peer offers.
#[derive(Clone, Copy)]
enum Offers {
    /// mplex and yamux: the session must pick yamux.
    MplexAndYamux,
    /// mplex only: the session must refuse to connect.
    MplexOnly,
}

/// `(peer ID Noise authenticated, muxer negotiated)`, one per upgraded connection.
type Upgrades = Arc<Mutex<Vec<(PeerId, &'static str)>>>;

/// A reference peer on 127.0.0.1 that accepts connections and serves nothing.
struct RefPeer {
    id: PeerId,
    /// `/ip4/127.0.0.1/tcp/<port>`, without `/p2p/`.
    addr: Multiaddr,
    upgrades: Upgrades,
    /// What the peer's swarm reported.
    events: Arc<Events>,
}

/// Counts of the peer swarm's connection events, updated as it handles each one.
#[derive(Debug, Default)]
struct Events {
    /// `ConnectionEstablished`.
    established: AtomicU32,
    /// `ConnectionClosed`.
    closed: AtomicU32,
    /// `IncomingConnectionError`: an inbound connection that failed before it was established.
    failed: AtomicU32,
}

impl Events {
    fn counts(&self) -> (u32, u32, u32) {
        (
            self.established.load(Ordering::SeqCst),
            self.closed.load(Ordering::SeqCst),
            self.failed.load(Ordering::SeqCst),
        )
    }
}

impl RefPeer {
    async fn spawn(offers: Offers) -> Self {
        let upgrades = Upgrades::default();
        let events = Arc::new(Events::default());
        let record = upgrades.clone();
        let mut swarm = SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
            .with_tokio()
            .with_other_transport(move |key| ref_transport(key, offers, record))
            .unwrap()
            .with_behaviour(|_| dummy::Behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let id = *swarm.local_peer_id();
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        let counts = events.clone();
        tokio::spawn(async move {
            loop {
                let counter = match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { .. } => &counts.established,
                    SwarmEvent::ConnectionClosed { .. } => &counts.closed,
                    SwarmEvent::IncomingConnectionError { .. } => &counts.failed,
                    _ => continue,
                };
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        Self {
            id,
            addr,
            upgrades,
            events,
        }
    }

    fn pinned_as(&self, peer_id: PeerId) -> PinnedPeer {
        PinnedPeer {
            peer_id,
            addr: self.addr.clone(),
        }
    }

    fn upgrades(&self) -> Vec<(PeerId, &'static str)> {
        self.upgrades.lock().unwrap().clone()
    }

    /// Waits up to 5 s for the peer's swarm to have established at least one connection and
    /// closed every connection it established. A count that has not moved yet proves nothing,
    /// so a connection the swarm has not reported yet cannot pass for a closed one.
    async fn wait_until_every_connection_closed(&self) {
        for _ in 0..100 {
            let (established, closed, _) = self.events.counts();
            if established >= 1 && closed == established {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (established, closed, failed) = self.events.counts();
        panic!(
            "the reference peer established {established} connection(s) and closed {closed} \
             ({failed} failed inbound)"
        );
    }

    /// Waits up to 5 s for an inbound connection to fail at the peer, then checks that the
    /// peer's swarm never established one.
    async fn wait_for_failed_upgrade(&self) {
        for _ in 0..100 {
            if self.events.counts().2 >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (established, closed, failed) = self.events.counts();
        assert!(
            failed >= 1,
            "no inbound connection failed at the reference peer"
        );
        assert_eq!(
            (established, closed),
            (0, 0),
            "the reference peer established a connection"
        );
    }

    /// Waits up to 5 s for the peer to have upgraded `n` connections.
    async fn wait_for_upgrades(&self, n: usize) {
        for _ in 0..100 {
            if self.upgrades.lock().unwrap().len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the reference peer upgraded {:?}", self.upgrades());
    }
}

type RefTransport =
    Result<Boxed<(PeerId, StreamMuxerBox)>, Box<dyn std::error::Error + Send + Sync>>;

/// TCP + Noise XX + `offers`, recording each upgrade.
fn ref_transport(key: &Keypair, offers: Offers, record: Upgrades) -> RefTransport {
    let authenticated = tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(key)?);
    Ok(match offers {
        Offers::MplexAndYamux => authenticated
            .multiplex(SelectUpgrade::new(
                libp2p_mplex::Config::default(),
                yamux::Config::default(),
            ))
            .map(move |(peer, muxer), _| {
                let name = match &muxer {
                    Either::Left(_) => "mplex",
                    Either::Right(_) => "yamux",
                };
                record.lock().unwrap().push((peer, name));
                (peer, StreamMuxerBox::new(muxer))
            })
            .boxed(),
        Offers::MplexOnly => authenticated
            .multiplex(libp2p_mplex::Config::default())
            .map(move |(peer, muxer), _| {
                record.lock().unwrap().push((peer, "mplex"));
                (peer, StreamMuxerBox::new(muxer))
            })
            .boxed(),
    })
}

fn start(pinned: PinnedPeer) -> Session<Minimal> {
    Session::start(
        NodeKey::ephemeral(),
        pinned,
        Arc::new(ContextTable::new()),
        Deadlines::default(),
        Transport::Tcp,
    )
    .unwrap()
}

#[tokio::test]
async fn pinned_dial_completes_noise_and_negotiates_yamux() {
    let peer = RefPeer::spawn(Offers::MplexAndYamux).await;
    let mut session = start(peer.pinned_as(peer.id));
    let local = *session.swarm().local_peer_id();
    session.connect().await.unwrap();
    assert!(session.swarm().is_connected(&peer.id));
    assert_eq!(session.open_connections(), 1);
    assert_eq!(session.swarm().listeners().count(), 0, "no listener");
    // Noise proved our identity to the peer, and the peer offered mplex first: yamux it is.
    peer.wait_for_upgrades(1).await;
    assert_eq!(peer.upgrades(), vec![(local, "yamux")]);

    session.disconnect().await.unwrap();
    assert_eq!(session.open_connections(), 0);
    assert!(!session.swarm().is_connected(&peer.id));
    peer.wait_until_every_connection_closed().await;
}

#[tokio::test]
async fn wrong_peer_id_refused_and_no_connection_stays_open() {
    let peer = RefPeer::spawn(Offers::MplexAndYamux).await;
    let pinned = PeerId::from(Keypair::generate_secp256k1().public());
    let mut session = start(peer.pinned_as(pinned));
    let err = session.connect().await.unwrap_err();
    assert!(
        matches!(&err, SessionError::WrongPeerId(ids) if ids.pinned == pinned && ids.obtained == peer.id),
        "{err}"
    );
    assert!(err.to_string().contains(&peer.id.to_string()), "{err}");
    assert_eq!(session.open_connections(), 0);
    assert!(!session.swarm().is_connected(&peer.id));
    assert_eq!(session.swarm().network_info().num_peers(), 0);
    // The handshake did run (Noise and yamux), and then the peer's side closed too.
    peer.wait_for_upgrades(1).await;
    assert_eq!(peer.upgrades()[0].1, "yamux");
    peer.wait_until_every_connection_closed().await;
}

#[tokio::test]
async fn peer_without_yamux_refused() {
    let peer = RefPeer::spawn(Offers::MplexOnly).await;
    let mut session = start(peer.pinned_as(peer.id));
    let err = session.connect().await.unwrap_err();
    assert!(matches!(&err, SessionError::Dial { .. }), "{err}");
    assert_eq!(session.open_connections(), 0);
    assert!(peer.upgrades().is_empty(), "{:?}", peer.upgrades());
    peer.wait_for_failed_upgrade().await;
}

#[tokio::test]
async fn disconnect_without_a_connection_is_a_no_op() {
    let peer = RefPeer::spawn(Offers::MplexAndYamux).await;
    let mut session = start(peer.pinned_as(PeerId::random()));
    session.connect().await.unwrap_err();
    session.disconnect().await.unwrap();
    assert_eq!(session.open_connections(), 0);
}

// The binary, end to end.

const BIN: &str = env!("CARGO_BIN_EXE_m2a-session");
const SECRET: [u8; 32] = [7; 32];

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The peer ID of [`SECRET`].
fn secret_peer_id() -> PeerId {
    let mut secret = SECRET;
    let secret = secp256k1::SecretKey::try_from_bytes(&mut secret).unwrap();
    Keypair::from(secp256k1::Keypair::from(secret))
        .public()
        .to_peer_id()
}

/// A config file pinning `peer_id` at `addr`, with the 0600 key file holding [`SECRET`].
fn config_dir(addr: &Multiaddr, peer_id: PeerId) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    let mut file = std::fs::File::create(&key).unwrap();
    file.write_all(&SECRET).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let text = format!(
        "network = \"sepolia\"\npeer = \"{addr}/p2p/{peer_id}\"\n\
         reference_api_url = \"http://127.0.0.1:5052\"\nnode_key = \"{}\"\n\
         trusted_by_reference = true\n",
        key.display()
    );
    std::fs::write(dir.path().join("m2a-session.toml"), text).unwrap();
    dir
}

/// Runs the binary off the runtime thread, so the reference peer keeps running meanwhile.
async fn run_bin(dir: &Path, args: &[&str]) -> Output {
    let config = dir.join("m2a-session.toml");
    let mut command = Command::new(BIN);
    command.arg("--config").arg(config).args(args);
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn dial_only_binary_connects_and_exits_0() {
    let peer = RefPeer::spawn(Offers::MplexAndYamux).await;
    let dir = config_dir(&peer.addr, peer.id);
    let out = run_bin(dir.path(), &["--dial-only", "--connect-timeout-secs", "20"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if euid() == 0 {
        assert_eq!(out.status.code(), Some(2), "root is refused: {stderr}");
        return;
    }
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("dial-only"), "{stderr}");
    peer.wait_for_upgrades(1).await;
    assert_eq!(peer.upgrades(), vec![(secret_peer_id(), "yamux")]);
    peer.wait_until_every_connection_closed().await;
}

#[tokio::test]
async fn dial_only_binary_wrong_peer_id_exits_1() {
    let peer = RefPeer::spawn(Offers::MplexAndYamux).await;
    let pinned = PeerId::from(Keypair::generate_secp256k1().public());
    let dir = config_dir(&peer.addr, pinned);
    let out = run_bin(dir.path(), &["--dial-only", "--connect-timeout-secs", "20"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if euid() == 0 {
        assert_eq!(out.status.code(), Some(2), "root is refused: {stderr}");
        return;
    }
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("wrong peer ID"), "{stderr}");
    peer.wait_until_every_connection_closed().await;
}

#[tokio::test]
async fn print_peer_id_binary_prints_the_key_files_peer_id() {
    // Nothing listens at the pinned address: printing the peer ID never dials.
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9".parse().unwrap();
    let dir = config_dir(&addr, PeerId::random());
    let out = run_bin(dir.path(), &["--print-peer-id"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if euid() == 0 {
        assert_eq!(out.status.code(), Some(2), "root is refused: {stderr}");
        return;
    }
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{}\n", secret_peer_id())
    );
}
