//! The `goodbye_received` log event: exactly one line per received Goodbye, with the peer,
//! reason, Status validity, direction and time.
//!
//! Its own test binary with a single test, like `probe_log.rs`: `tracing` caches each callsite's
//! interest process-wide, so a thread-scoped subscriber in a unit test can miss lines whose
//! callsites another test registered first.

use cl_p2p::behaviour::BehaviourEvent;
use cl_p2p::rpc::inbound::{ControlEvent, Relevance};
use cl_p2p::transport::{build_swarm, MuxerBudget, SwarmConfig, TransportMetrics};
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt as _;
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use prometheus_client::registry::Registry;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(20);

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn lines_with(&self, needle: &str) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter(|l| l.contains(needle))
            .map(str::to_owned)
            .collect()
    }
}

enum Cmd {
    Dial(Multiaddr),
    Goodbye(PeerId, u64),
}

#[derive(Debug)]
enum Seen {
    Control(ControlEvent),
    Closed(PeerId),
}

struct Node {
    peer: PeerId,
    addr: Multiaddr,
    cmds: UnboundedSender<Cmd>,
    events: UnboundedReceiver<Seen>,
}

/// A probe swarm on 127.0.0.1, run on its own task like a service's event loop.
async fn spawn_node() -> Node {
    let mut registry = Registry::default();
    let transport = TransportMetrics::register(&mut registry);
    let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
    cfg.listen_addrs = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    cfg.idle_connection_timeout = WAIT;
    let (req_resp, _) = cl_p2p::testkit::control(
        &mut registry,
        cl_p2p::testkit::control_config(Some(p2p_wire::testkit::status())),
    );
    let mut swarm = build_swarm(Keypair::generate_secp256k1(), &cfg, req_resp).unwrap();
    let peer = *swarm.local_peer_id();
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            break address;
        }
    };
    let (cmds, mut cmd_rx) = unbounded();
    let (tx, events) = unbounded();
    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                cmd = cmd_rx.next() => {
                    match cmd {
                        Some(Cmd::Dial(addr)) => swarm.dial(addr).unwrap(),
                        Some(Cmd::Goodbye(peer, reason)) => {
                            swarm.behaviour_mut().req_resp.goodbye(peer, reason);
                        }
                        None => return,
                    }
                    continue;
                }
                event = swarm.select_next_some() => event,
            };
            let seen = match event {
                SwarmEvent::Behaviour(BehaviourEvent::ReqResp(e)) => Seen::Control(e),
                SwarmEvent::ConnectionClosed { peer_id, .. } => Seen::Closed(peer_id),
                _ => continue,
            };
            if tx.unbounded_send(seen).is_err() {
                return;
            }
        }
    });
    Node {
        peer,
        addr,
        cmds,
        events,
    }
}

impl Node {
    async fn next<T>(&mut self, mut pick: impl FnMut(&Seen) -> Option<T>) -> T {
        tokio::time::timeout(WAIT, async {
            loop {
                let seen = self.events.next().await.expect("the node stopped");
                if let Some(found) = pick(&seen) {
                    return found;
                }
            }
        })
        .await
        .expect("timed out")
    }

    async fn valid(&mut self, peer: PeerId) {
        let verdict = self
            .next(|seen| match seen {
                Seen::Control(ControlEvent::Status {
                    peer: p, relevance, ..
                }) if *p == peer => Some(*relevance),
                _ => None,
            })
            .await;
        assert_eq!(verdict, Relevance::Relevant);
    }
}

#[test]
fn one_goodbye_received_line_per_goodbye() {
    // First, before any callsite is hit: the one subscriber of this process.
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let ours = runtime.block_on(async {
        let mut ours = spawn_node().await;
        let mut theirs = spawn_node().await;
        theirs
            .cmds
            .unbounded_send(Cmd::Dial(ours.addr.clone()))
            .unwrap();
        ours.valid(theirs.peer).await;
        theirs.valid(ours.peer).await;
        ours.cmds
            .unbounded_send(Cmd::Goodbye(theirs.peer, 1))
            .unwrap();
        let ours_peer = ours.peer;
        theirs
            .next(|seen| match seen {
                Seen::Control(ControlEvent::GoodbyeReceived { peer, .. }) if *peer == ours_peer => {
                    Some(())
                }
                _ => None,
            })
            .await;
        let theirs_peer = theirs.peer;
        ours.next(|seen| matches!(seen, Seen::Closed(p) if *p == theirs_peer).then_some(()))
            .await;
        ours.peer
    });

    let received = log.lines_with("goodbye_received");
    assert_eq!(received.len(), 1, "{received:?}");
    let line = &received[0];
    for field in [
        format!("peer={ours}"),
        "reason=1".to_owned(),
        "status_valid=\"true\"".to_owned(),
        "direction=\"outbound\"".to_owned(),
        "unix_ms=".to_owned(),
    ] {
        assert!(line.contains(&field), "{field} missing from {line}");
    }
    let sent = log.lines_with("goodbye_sent");
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].contains("reason=1"), "{}", sent[0]);
}
