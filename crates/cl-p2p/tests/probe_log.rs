//! The probe swarm's connection log: the muxer each side negotiated, the address identify says
//! the peer sees us on, and the peer's identify strings escaped so they cannot forge a line.
//!
//! Its own test binary with a single test, like `m2a_session.rs`: `tracing` caches each
//! callsite's interest process-wide, so a thread-scoped subscriber in a unit test can miss lines
//! whose callsites another test registered first. Here the capturing subscriber is the global
//! default, installed before any callsite is hit, in a process where nothing else runs.

use cl_p2p::behaviour::{log_identify, BehaviourEvent};
use cl_p2p::transport::{build_swarm, MuxerBudget, PeerMetrics, SwarmConfig, TransportMetrics};
use futures::StreamExt as _;
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, Multiaddr, PeerId};
use prometheus_client::registry::Registry;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

#[derive(Debug)]
enum Seen {
    Listening(Multiaddr),
    Established(PeerId),
    Identified(PeerId),
    Failed(String),
}

/// A probe swarm on 127.0.0.1, run on its own task like a service's event loop.
/// A peer's agent string that would forge a log line if logged raw.
const FORGING_AGENT: &str = "ethswarm/test\nFORGED INFO a line the peer wrote";

fn spawn_probe(
    agent_version: &str,
) -> (
    PeerId,
    futures::channel::mpsc::UnboundedReceiver<Seen>,
    impl FnOnce(Multiaddr),
) {
    let mut registry = Registry::default();
    let transport = TransportMetrics::register(&mut registry);
    let metrics = PeerMetrics::register(&mut registry);
    let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
    cfg.listen_addrs = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    cfg.idle_connection_timeout = Duration::from_secs(20);
    agent_version.clone_into(&mut cfg.agent_version);
    let mut swarm = build_swarm(Keypair::generate_secp256k1(), &cfg).unwrap();
    let local = *swarm.local_peer_id();
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let (dial_tx, dial_rx) = futures::channel::oneshot::channel::<Multiaddr>();
    tokio::spawn(async move {
        let mut dial_rx = Some(dial_rx);
        loop {
            let event = match dial_rx.as_mut() {
                Some(rx) => tokio::select! {
                    addr = rx => {
                        dial_rx = None;
                        if let Ok(addr) = addr {
                            swarm.dial(addr).unwrap();
                        }
                        continue;
                    }
                    event = swarm.select_next_some() => event,
                },
                None => swarm.select_next_some().await,
            };
            metrics.observe(&event);
            let seen = match event {
                SwarmEvent::NewListenAddr { address, .. } => Seen::Listening(address),
                SwarmEvent::ConnectionEstablished { peer_id, .. } => Seen::Established(peer_id),
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    Seen::Failed(error.to_string())
                }
                SwarmEvent::IncomingConnectionError { error, .. } => {
                    Seen::Failed(error.to_string())
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => {
                    log_identify(&event);
                    match event {
                        identify::Event::Received { peer_id, .. } => Seen::Identified(peer_id),
                        _ => continue,
                    }
                }
                _ => continue,
            };
            if tx.unbounded_send(seen).is_err() {
                return;
            }
        }
    });
    (local, rx, move |addr| dial_tx.send(addr).unwrap())
}

async fn next(rx: &mut futures::channel::mpsc::UnboundedReceiver<Seen>) -> Seen {
    tokio::time::timeout(Duration::from_secs(20), rx.next())
        .await
        .expect("timed out")
        .expect("the probe stopped")
}

#[test]
fn connection_log_shows_muxer_and_observed_addr() {
    // First, before any callsite is hit: the one subscriber of this process.
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (ours, theirs) = runtime.block_on(async {
        let (ours, mut ours_rx, dial) = spawn_probe("ethswarm/test");
        let (theirs, mut theirs_rx, _) = spawn_probe(FORGING_AGENT);
        let Seen::Listening(_) = next(&mut ours_rx).await else {
            panic!("no listen address");
        };
        let Seen::Listening(addr) = next(&mut theirs_rx).await else {
            panic!("no listen address");
        };
        dial(addr);
        // Both sides connect and identify each other; a failed negotiation fails the test.
        for (rx, peer) in [(&mut ours_rx, theirs), (&mut theirs_rx, ours)] {
            let (mut established, mut identified) = (false, false);
            while !(established && identified) {
                match next(rx).await {
                    Seen::Established(p) if p == peer => established = true,
                    Seen::Identified(p) if p == peer => identified = true,
                    Seen::Failed(e) => panic!("{e}"),
                    _ => {}
                }
            }
        }
        (ours, theirs)
    });

    let log = log.text();
    for role in ["dialer", "listener"] {
        let line = log
            .lines()
            .find(|l| l.contains("negotiated a stream muxer") && l.contains(role))
            .unwrap_or_else(|| panic!("no muxer line for the {role}:\n{log}"));
        assert!(line.contains("muxer=\"/yamux/1.0.0\""), "{line}");
    }
    for peer in [ours, theirs] {
        assert!(
            log.lines().any(|l| l.contains(&format!("peer={peer}"))
                && l.contains("observed_addr=\"/ip4/127.0.0.1/tcp/")),
            "no observed_addr from {peer}:\n{log}"
        );
    }
    // The peer's newline is logged escaped, inside its quoted field: no line of its own.
    assert!(
        log.contains(r#"agent="ethswarm/test\nFORGED INFO a line the peer wrote""#),
        "{log}"
    );
    assert!(!log.lines().any(|l| l.starts_with("FORGED")), "{log}");
    assert!(log.contains("direction=\"outbound\""), "{log}");
    assert!(log.contains("direction=\"inbound\""), "{log}");
}
