//! A fixture reference CL's beacon API for the probe's tests: a [`FixtureServer`] on 127.0.0.1
//! answering from a [`FixtureChain`] the test changes as it goes.

use consensus_types::primitives::{Root, Slot};
use network_config::{Epoch, Genesis};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use testkit::collector::testing::{FixtureServer, Reply};

/// What the fixture API answers from.
#[derive(Debug, Clone, Default)]
pub struct ChainState {
    /// `/eth/v1/beacon/genesis`.
    pub genesis: Option<(Genesis, [u8; 4])>,
    /// `/eth/v1/node/identity`: the peer ID and the ENR.
    pub identity: Option<(String, String)>,
    /// `/eth/v1/beacon/states/head/finality_checkpoints`: the finalized checkpoint.
    pub finalized: Option<(Epoch, Root)>,
    /// `/eth/v1/beacon/headers/{root}`: each known root's slot.
    pub headers: HashMap<Root, Slot>,
    /// `/eth/v1/beacon/blocks/{slot}/root`: each slot with a block; any other answers 404.
    pub roots: BTreeMap<Slot, Root>,
    /// Every request answers 503 while set.
    pub down: bool,
}

/// The state behind a running fixture API, for the test to change.
#[derive(Debug, Clone, Default)]
pub struct FixtureChain(pub Arc<Mutex<ChainState>>);

/// `0x` and the lowercase hex of `bytes`.
pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

impl FixtureChain {
    /// Changes the state.
    pub fn with<T>(&self, f: impl FnOnce(&mut ChainState) -> T) -> T {
        f(&mut self.0.lock().unwrap())
    }

    /// Finalizes `epoch` at the block `root` of `slot`.
    pub fn finalize(&self, epoch: Epoch, root: Root, slot: Slot) {
        self.with(|s| {
            s.finalized = Some((epoch, root));
            s.headers.insert(root, slot);
        });
    }

    /// Serves the state on 127.0.0.1 until the test ends.
    pub async fn serve(&self) -> FixtureServer {
        let state = self.clone();
        FixtureServer::start(move |_, path| state.reply(path)).await
    }

    fn reply(&self, path: &str) -> Reply {
        let s = self.0.lock().unwrap().clone();
        if s.down {
            return Reply::status(503);
        }
        let found = match path {
            "/eth/v1/beacon/genesis" => s.genesis.map(|(g, version)| {
                format!(
                    r#"{{"data":{{"genesis_time":"{}","genesis_validators_root":"{}","genesis_fork_version":"{}"}}}}"#,
                    g.genesis_time,
                    hex0x(&g.genesis_validators_root),
                    hex0x(&version)
                )
            }),
            "/eth/v1/node/identity" => s.identity.map(|(peer_id, enr)| {
                format!(
                    r#"{{"data":{{"peer_id":"{peer_id}","enr":"{enr}","p2p_addresses":[],"discovery_addresses":[],"metadata":{{"seq_number":"1","attnets":"0x0000000000000000","syncnets":"0x00"}}}}}}"#
                )
            }),
            "/eth/v1/beacon/states/head/finality_checkpoints" => s.finalized.map(|(epoch, root)| {
                let zero = hex0x(&[0; 32]);
                format!(
                    r#"{{"execution_optimistic":false,"finalized":true,"data":{{"previous_justified":{{"epoch":"0","root":"{zero}"}},"current_justified":{{"epoch":"0","root":"{zero}"}},"finalized":{{"epoch":"{epoch}","root":"{}"}}}}}}"#,
                    hex0x(root.as_slice())
                )
            }),
            other => header(&s, other).or_else(|| block_root(&s, other)),
        };
        found.map_or_else(|| Reply::status(404), |body| Reply::json(&body))
    }
}

fn header(s: &ChainState, path: &str) -> Option<String> {
    let id = path.strip_prefix("/eth/v1/beacon/headers/")?;
    let (root, slot) = s
        .headers
        .iter()
        .find(|(root, _)| hex0x(root.as_slice()) == id)?;
    let zero = hex0x(&[0; 32]);
    Some(format!(
        r#"{{"execution_optimistic":false,"finalized":true,"data":{{"root":"{}","canonical":true,"header":{{"message":{{"slot":"{slot}","proposer_index":"0","parent_root":"{zero}","state_root":"{zero}","body_root":"{zero}"}},"signature":"0x{}"}}}}}}"#,
        hex0x(root.as_slice()),
        "00".repeat(96)
    ))
}

fn block_root(s: &ChainState, path: &str) -> Option<String> {
    let slot: Slot = path
        .strip_prefix("/eth/v1/beacon/blocks/")?
        .strip_suffix("/root")?
        .parse()
        .ok()?;
    let root = s.roots.get(&slot)?;
    Some(format!(
        r#"{{"execution_optimistic":false,"finalized":true,"data":{{"root":"{}"}}}}"#,
        hex0x(root.as_slice())
    ))
}

// ---------------------------------------------------------------------------------------------
// Stand-ins for a reference CL: our own probe swarm, and peers that break a rule.

use super::devnet::Devnet;
use super::swarm::{probe_swarm, SwarmPlan};
use cl_p2p::m2a_session::PinnedPeer;
use cl_p2p::rpc::inbound::SharedStatus;
use consensus_types::EthSpec;
use futures::channel::mpsc;
use futures::StreamExt;
use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use p2p_wire::rpc::messages::StatusV2;
use std::time::Duration;

/// The fixture devnet (`export_blocks::fixtures::CONFIG`: minimal, Fulu at 0, a blob change at
/// 1, Gloas at 2) with genesis validators root `0x42…`.
pub fn devnet() -> Devnet {
    Devnet::new(
        testkit::export_blocks::fixtures::CONFIG.as_bytes(),
        Genesis {
            genesis_time: testkit::export_blocks::fixtures::GENESIS_TIME,
            genesis_validators_root: [0x42; 32],
        },
    )
    .expect("the fixture devnet")
}

/// Unix milliseconds of the system clock.
pub fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// What a stand-in's script tells it to do.
#[derive(Debug)]
enum Cmd {
    /// Send our Status to the peer, as a CL's periodic re-Status does.
    Status(PeerId),
    /// Say Goodbye with this reason.
    Goodbye(PeerId, u64),
    /// Close the connection without a Goodbye.
    Disconnect(PeerId),
}

/// What a stand-in does on its own once a peer connects, as a CL would.
#[derive(Debug, Clone, Copy, Default)]
pub struct Script {
    /// Sends the peer our Status this long after it connected (a CL's periodic re-Status).
    pub restatus_after: Option<Duration>,
    /// Says Goodbye with this reason this long after the peer connected.
    pub goodbye_after: Option<(Duration, u64)>,
    /// Closes the connection, without a Goodbye, this long after the peer connected.
    pub disconnect_after: Option<Duration>,
}

/// A stand-in reference CL: our own probe swarm on 127.0.0.1, answering Status, Ping, MetaData
/// and Goodbye with the given Status, on its own task.
pub struct StandIn {
    /// Its peer ID.
    pub id: PeerId,
    /// `/ip4/127.0.0.1/tcp/<port>`.
    pub addr: Multiaddr,
}

impl StandIn {
    /// Starts one answering with `status` (`None`: no Status of its own), doing nothing on its
    /// own.
    pub async fn spawn<E: EthSpec>(devnet: &Devnet, status: Option<StatusV2>) -> Self {
        Self::scripted::<E>(devnet, status, Script::default()).await
    }

    /// Starts one answering with `status` and following `script` for every peer that connects.
    pub async fn scripted<E: EthSpec>(
        devnet: &Devnet,
        status: Option<StatusV2>,
        script: Script,
    ) -> Self {
        let plan = SwarmPlan {
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr")],
            idle: Duration::from_secs(60),
            bypass: Vec::new(),
            muxer_observer: None,
            ping_interval: cl_p2p::rpc::inbound::PING_INTERVAL,
            gossip: None,
        };
        let mut swarm =
            probe_swarm::<E>(devnet, Arc::new(SharedStatus::new(status)), plan).expect("swarm");
        let id = *swarm.local_peer_id();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        let (own, mut rx) = mpsc::unbounded();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = rx.next() => {
                        let control = &mut swarm.behaviour_mut().req_resp;
                        match cmd {
                            Some(Cmd::Status(peer)) => {
                                control.send_status(peer);
                            }
                            Some(Cmd::Goodbye(peer, reason)) => control.goodbye(peer, reason),
                            Some(Cmd::Disconnect(peer)) => {
                                let _ = swarm.disconnect_peer_id(peer);
                            }
                            None => return,
                        }
                    }
                    event = swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                            let later = |after: Option<Duration>, cmd: Cmd| {
                                let Some(after) = after else { return };
                                let own = own.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(after).await;
                                    let _ = own.unbounded_send(cmd);
                                });
                            };
                            later(script.restatus_after, Cmd::Status(peer_id));
                            if let Some((after, reason)) = script.goodbye_after {
                                later(Some(after), Cmd::Goodbye(peer_id, reason));
                            }
                            later(script.disconnect_after, Cmd::Disconnect(peer_id));
                        }
                    }
                }
            }
        });
        Self { id, addr }
    }

    /// The stand-in at its address.
    pub fn pinned(&self) -> PinnedPeer {
        PinnedPeer {
            peer_id: self.id,
            addr: self.addr.clone(),
        }
    }
}

/// A peer at a loopback address nothing listens on: bound once, then released.
pub fn closed_port_peer() -> PinnedPeer {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    PinnedPeer {
        peer_id: PeerId::random(),
        addr: format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap(),
    }
}

/// The muxer a stand-in from [`muxer_only_peer`] offers, and whether it answers identify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlyMuxer {
    /// mplex, answering identify: the round trip that confirms mplex comes back.
    Mplex,
    /// mplex, with no protocol on top: identify is refused (`na`), so nothing confirms mplex.
    SilentMplex,
    /// mplex under the name [`OTHER_MUXER`]: a peer that refuses both yamux and mplex.
    Other,
}

/// The muxer protocol of [`OnlyMuxer::Other`]: neither yamux nor mplex.
pub const OTHER_MUXER: &str = "/other-muxer/1.0.0";

/// A peer that offers mplex only (TCP, Noise, our capped mplex) and answers identify, serving
/// nothing else.
pub async fn mplex_only_peer() -> PinnedPeer {
    muxer_only_peer(OnlyMuxer::Mplex).await
}

/// A peer on TCP and Noise whose one muxer is `only` (our capped mplex, under its own name or
/// [`OTHER_MUXER`]), running identify if `only` says so and nothing else.
pub async fn muxer_only_peer(only: OnlyMuxer) -> PinnedPeer {
    use cl_p2p::behaviour::IDENTIFY_PROTOCOL_VERSION;
    use cl_p2p::transport::{mplex_config, Budgeted, MuxerBudget, TransportMetrics};
    use libp2p::swarm::behaviour::toggle::Toggle;
    use libp2p::{identify, noise, tcp, SwarmBuilder};
    let metrics = TransportMetrics::register(&mut prometheus_client::registry::Registry::default());
    let budget = MuxerBudget::with_defaults(&metrics);
    let name = match only {
        OnlyMuxer::Mplex | OnlyMuxer::SilentMplex => crate::connect::MPLEX,
        OnlyMuxer::Other => OTHER_MUXER,
    };
    let key = libp2p::identity::Keypair::generate_secp256k1();
    let identify = (only == OnlyMuxer::Mplex).then(|| {
        identify::Behaviour::new(identify::Config::new(
            IDENTIFY_PROTOCOL_VERSION.to_owned(),
            key.public(),
        ))
    });
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, move || {
            Named::new(name, Budgeted::new(mplex_config(), budget))
        })
        .expect("tcp")
        .with_behaviour(|_| Toggle::from(identify))
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    let peer_id = *swarm.local_peer_id();
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
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
    PinnedPeer { peer_id, addr }
}

/// The connection upgrade `inner` offered under the protocol name `name` alone.
#[derive(Clone)]
struct Named<U> {
    name: &'static str,
    inner: U,
}

impl<U: UpgradeInfo> Named<U> {
    fn new(name: &'static str, inner: U) -> Self {
        Self { name, inner }
    }

    /// The protocol `inner` runs under.
    fn inner_info(&self) -> U::Info {
        self.inner
            .protocol_info()
            .into_iter()
            .next()
            .expect("the upgrade names a protocol")
    }
}

impl<U> UpgradeInfo for Named<U> {
    type Info = &'static str;
    type InfoIter = std::iter::Once<&'static str>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(self.name)
    }
}

impl<C, U: InboundConnectionUpgrade<C>> InboundConnectionUpgrade<C> for Named<U> {
    type Output = U::Output;
    type Error = U::Error;
    type Future = U::Future;

    fn upgrade_inbound(self, socket: C, _: Self::Info) -> Self::Future {
        let info = self.inner_info();
        self.inner.upgrade_inbound(socket, info)
    }
}

impl<C, U: OutboundConnectionUpgrade<C>> OutboundConnectionUpgrade<C> for Named<U> {
    type Output = U::Output;
    type Error = U::Error;
    type Future = U::Future;

    fn upgrade_outbound(self, socket: C, _: Self::Info) -> Self::Future {
        let info = self.inner_info();
        self.inner.upgrade_outbound(socket, info)
    }
}

// ---------------------------------------------------------------------------------------------
// Loopback UDP ports for discv5 nodes: a port picked free can be taken by another process
// before the node binds it, so a bind that finds it taken moves on to a fresh one.

/// A loopback UDP port nothing listens on right now. Another process can take it before the
/// test binds it: bind it through [`on_free_udp_port`].
pub fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// How many ports a test tries before it fails.
pub const PORT_ATTEMPTS: usize = 10;

/// Whether `detail` reports a bind whose port another socket took first (the `Debug` of an
/// `AddrInUse` I/O error, which discv5's start error carries).
pub fn port_taken(detail: &str) -> bool {
    detail.contains("kind: AddrInUse")
}

/// `run` on a port from `ports`, then on the next one while its error reports the port taken
/// ([`port_taken`]), for at most [`PORT_ATTEMPTS`] ports. Any other error ends it at once.
pub async fn on_ports<T, E, Fut>(
    mut ports: impl FnMut() -> u16,
    mut run: impl FnMut(u16) -> Fut,
) -> Result<T, String>
where
    E: std::fmt::Display,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut taken = Vec::with_capacity(PORT_ATTEMPTS);
    for _ in 0..PORT_ATTEMPTS {
        let port = ports();
        match run(port).await {
            Ok(done) => return Ok(done),
            Err(e) if port_taken(&e.to_string()) => taken.push(port),
            Err(e) => return Err(format!("port {port}: {e}")),
        }
    }
    Err(format!(
        "every one of {PORT_ATTEMPTS} ports was taken before it was bound: {taken:?}"
    ))
}

/// `run` on a fresh loopback port, retried on a taken one ([`on_ports`]); panics if it never
/// succeeds.
pub async fn on_free_udp_port<T, E, Fut>(run: impl FnMut(u16) -> Fut) -> T
where
    E: std::fmt::Display,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    on_ports(free_udp_port, run)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A stand-in CL's discv5 node on a fresh loopback port, in devnet mode, with `fork`.
pub async fn discv5_node(
    fork: &p2p_wire::enr::ForkFields,
) -> (cl_discv5::service::Discovery, cl_discv5::service::Events) {
    on_free_udp_port(|port| discv5_node_on(port, fork)).await
}

/// A stand-in CL's discv5 node on loopback `port`, in devnet mode, with `fork`, and its start.
pub async fn discv5_node_on(
    port: u16,
    fork: &p2p_wire::enr::ForkFields,
) -> Result<
    (cl_discv5::service::Discovery, cl_discv5::service::Events),
    cl_discv5::service::ServiceError,
> {
    use cl_discv5::enr::{build_local_enr, CombinedKey, LocalAddr};
    use cl_discv5::service::{Discovery, DiscoveryConfig, NetworkMode};
    let key = CombinedKey::generate_secp256k1();
    let addr = LocalAddr {
        ip: std::net::Ipv4Addr::LOCALHOST,
        tcp_port: port,
        udp_port: port,
    };
    let enr = build_local_enr(&key, fork, 4, &addr).unwrap();
    let mut config =
        DiscoveryConfig::new(std::net::Ipv4Addr::LOCALHOST.into(), NetworkMode::Devnet);
    config.udp_port = port;
    let mut node = Discovery::new(enr, key, &config).unwrap();
    let events = node.start().await?;
    Ok((node, events))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port another socket holds: `run` reports it taken and the next port is tried.
    #[tokio::test]
    async fn a_taken_port_moves_on_to_the_next_one() {
        let fork = devnet().fork_fields(now_ms()).unwrap();
        let holder = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken = holder.local_addr().unwrap().port();
        let mut tried = Vec::new();
        let ports = || {
            let port = if tried.is_empty() {
                taken
            } else {
                free_udp_port()
            };
            tried.push(port);
            port
        };
        let (node, _events) = on_ports(ports, |port| discv5_node_on(port, &fork))
            .await
            .unwrap();
        assert_eq!(tried.len(), 2, "{tried:?}");
        assert_eq!(tried[0], taken);
        assert_eq!(node.local_enr().udp4(), Some(tried[1]));
        drop(holder);
    }

    /// A port that stays taken: it gives up after [`PORT_ATTEMPTS`] ports and names them.
    #[tokio::test]
    async fn every_port_taken_gives_up() {
        let fork = devnet().fork_fields(now_ms()).unwrap();
        let holder = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken = holder.local_addr().unwrap().port();
        let mut tried = 0;
        let ports = || {
            tried += 1;
            taken
        };
        let err = on_ports(ports, |port| discv5_node_on(port, &fork))
            .await
            .err()
            .expect("a held port never starts");
        assert_eq!(tried, PORT_ATTEMPTS);
        assert!(err.contains(&format!("{PORT_ATTEMPTS} ")), "{err}");
        assert!(err.contains(&taken.to_string()), "{err}");
        drop(holder);
    }

    /// Any other error ends it at once: only a taken port is retried.
    #[tokio::test]
    async fn an_error_that_is_not_a_taken_port_is_not_retried() {
        let mut tried = 0;
        let ports = || {
            tried += 1;
            free_udp_port()
        };
        let err = on_ports(ports, |_| async { Err::<(), _>("refused") })
            .await
            .expect_err("the run failed");
        assert_eq!(tried, 1);
        assert!(err.contains("refused"), "{err}");
    }
}
