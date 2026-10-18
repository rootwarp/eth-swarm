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

/// A peer that offers mplex only (TCP, Noise, our capped mplex), and serves nothing.
pub async fn mplex_only_peer() -> PinnedPeer {
    use cl_p2p::transport::{mplex_config, Budgeted, MuxerBudget, TransportMetrics};
    use libp2p::{noise, tcp, SwarmBuilder};
    let metrics = TransportMetrics::register(&mut prometheus_client::registry::Registry::default());
    let budget = MuxerBudget::with_defaults(&metrics);
    let mut swarm =
        SwarmBuilder::with_existing_identity(libp2p::identity::Keypair::generate_secp256k1())
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, move || {
                Budgeted::new(mplex_config(), budget)
            })
            .expect("tcp")
            .with_behaviour(|_| libp2p::swarm::dummy::Behaviour)
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
