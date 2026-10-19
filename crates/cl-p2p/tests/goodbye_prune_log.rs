//! The context layer recognises the pinned gossipsub's PRUNE event. Two real swarms on 127.0.0.1
//! mesh on one topic, one leaves it, and the test polls until the layer records a
//! `prune_received` entry for the other peer.
//!
//! Its own test binary with a single test: the layer must be the process's default subscriber
//! before any gossipsub callsite is hit (`tracing` caches each callsite's interest
//! process-wide).

use cl_p2p::peers::context::{self, ContextKind, GoodbyeContext};
use futures::StreamExt as _;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, Swarm, SwarmBuilder};
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt as _;

/// The whole test's bound.
const WAIT: Duration = Duration::from_secs(30);

fn gossip_swarm(topic: &IdentTopic) -> Swarm<gossipsub::Behaviour> {
    let config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Anonymous)
        .heartbeat_interval(Duration::from_millis(100))
        .heartbeat_initial_delay(Duration::from_millis(100))
        .build()
        .unwrap();
    let mut behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, config).unwrap();
    behaviour.subscribe(topic).unwrap();
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
        .build()
}

#[test]
fn a_real_prune_is_recorded() {
    // First, before any callsite is hit: the one subscriber of this process.
    let goodbye_context = GoodbyeContext::new();
    let subscriber = tracing_subscriber::registry().with(context::layer(goodbye_context.clone()));
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let topic = IdentTopic::new("/eth2/00000000/beacon_block/ssz_snappy");
        let hash = topic.hash();
        let mut ours = gossip_swarm(&topic);
        let mut theirs = gossip_swarm(&topic);
        ours.listen_on("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap())
            .unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = ours.select_next_some().await {
                break address;
            }
        };
        theirs.dial(addr).unwrap();
        let their_peer = *theirs.local_peer_id();
        let our_peer = *ours.local_peer_id();
        let pruned = tokio::time::timeout(WAIT, async {
            let mut left = false;
            // Poll every 50 ms until the entry appears.
            let mut look = tokio::time::interval(Duration::from_millis(50));
            loop {
                tokio::select! {
                    _ = ours.select_next_some() => {}
                    _ = theirs.select_next_some() => {}
                    _ = look.tick() => {}
                }
                // Once both sides mesh, the other peer leaves the topic.
                let meshed = ours.behaviour().mesh_peers(&hash).any(|p| *p == their_peer)
                    && theirs.behaviour().mesh_peers(&hash).any(|p| *p == our_peer);
                if !left && meshed {
                    assert!(theirs.behaviour_mut().unsubscribe(&topic));
                    left = true;
                }
                let entries = goodbye_context.entries(&their_peer);
                if let Some(entry) = entries
                    .iter()
                    .find(|e| e.kind == ContextKind::PruneReceived)
                {
                    return *entry;
                }
            }
        })
        .await
        .expect("no prune_received entry within 30 s");
        assert_eq!(pruned.detail, "");
        assert!(pruned.count >= 1, "{pruned:?}");
    });
}
