//! The probe swarm on a devnet: cl-p2p's [`build_swarm`] (TCP, Noise XX, yamux then mplex,
//! connection limits, identify) with its req/resp behaviour ([`Control`]) over the devnet's
//! preset and fork digests, and, if asked for, its ignore-all gossipsub ([`IgnoreAll`],
//! `build_swarm_with_gossip`) on `beacon_block`.

use super::devnet::Devnet;
use cl_p2p::behaviour::SpecBehaviour;
use cl_p2p::gossip::{GossipConfig, IgnoreAll};
use cl_p2p::rpc::codec::Deadlines;
use cl_p2p::rpc::inbound::{Control, ControlConfig, SharedMetaData, StatusSource};
use cl_p2p::rpc::limits::RpcLimits;
use cl_p2p::rpc::metrics::RpcMetrics;
use cl_p2p::transport::{
    build_swarm, build_swarm_with_gossip, MuxerBudget, MuxerObserver, SwarmConfig, TransportMetrics,
};
use consensus_types::caps::NetworkCaps;
use consensus_types::das::CUSTODY_REQUIREMENT;
use consensus_types::EthSpec;
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId, Swarm};
use p2p_wire::gossip::{GossipKind, GossipTopic, TopicCaps};
use p2p_wire::rpc::messages::{ForkDigest, MetaDataV3};
use prometheus_client::registry::Registry;
use std::sync::Arc;
use std::time::Duration;

/// How the probe swarm is built.
#[derive(Debug, Clone)]
pub struct SwarmPlan {
    /// Where it listens; none for a swarm that only dials.
    pub listen: Vec<Multiaddr>,
    /// How long a connection with no open stream stays up.
    pub idle: Duration,
    /// Peers exempt from the connection caps: the reference CLs.
    pub bypass: Vec<PeerId>,
    /// Told the muxer each connection negotiated.
    pub muxer_observer: Option<MuxerObserver>,
    /// How often the req/resp behaviour pings each connected peer: cl-p2p's Ping cadence
    /// (`cl_p2p::rpc::inbound::PING_INTERVAL` in production).
    pub ping_interval: Duration,
    /// The ignore-all gossipsub, subscribed to `beacon_block` at this fork digest; none if
    /// `None`. It reports IGNORE for every message, so it forwards nothing.
    pub gossip: Option<ForkDigest>,
}

/// The probe swarm for `devnet` under the preset `E`, with an ephemeral secp256k1 node key, our
/// Status from `status`, MetaData `seq_number` 0 and the custody group count
/// `CUSTODY_REQUIREMENT`. Its metrics go to a registry of its own, which nothing exports.
///
/// Must be called within a tokio runtime.
///
/// # Errors
///
/// The swarm could not be built or could not listen.
pub fn probe_swarm<E: EthSpec>(
    devnet: &Devnet,
    status: Arc<dyn StatusSource>,
    plan: SwarmPlan,
) -> Result<Swarm<SpecBehaviour<E>>, String> {
    let mut registry = Registry::default();
    let transport = TransportMetrics::register(&mut registry);
    let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
    cfg.listen_addrs = plan.listen;
    cfg.idle_connection_timeout = plan.idle;
    cfg.bypass = plan.bypass;
    cfg.muxer_observer = plan.muxer_observer;
    let control = Control::<E>::new(
        ControlConfig {
            status,
            metadata: Arc::new(SharedMetaData::new(MetaDataV3 {
                seq_number: 0,
                attnets: Default::default(),
                syncnets: Default::default(),
                custody_group_count: CUSTODY_REQUIREMENT,
            })),
            contexts: Arc::new(devnet.context_table()),
            deadlines: Deadlines::default(),
            limits: RpcLimits::default(),
            ping_interval: plan.ping_interval,
        },
        RpcMetrics::register(&mut registry),
    );
    let key = Keypair::generate_secp256k1();
    match plan.gossip {
        None => build_swarm(key, &cfg, control).map_err(|e| e.to_string()),
        Some(digest) => {
            let caps = TopicCaps::gloas::<E>(&NetworkCaps::from_config(devnet.config()));
            let topics = vec![GossipTopic::new(digest, GossipKind::BeaconBlock)];
            let gossip_cfg = GossipConfig::ethereum_profile::<E>(devnet.config(), topics, caps);
            let gossip = IgnoreAll::new(&gossip_cfg, &mut registry)
                .map_err(|e| format!("gossipsub: {e}"))?;
            build_swarm_with_gossip(key, &cfg, control, gossip).map_err(|e| e.to_string())
        }
    }
}

/// `error` and every `source()` under it, `: `-separated.
pub fn error_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut next = error.source();
    while let Some(e) = next {
        out.push_str(": ");
        out.push_str(&e.to_string());
        next = e.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::devnet;
    use cl_p2p::rpc::inbound::SharedStatus;
    use consensus_types::Minimal;

    fn plan(gossip: Option<ForkDigest>) -> SwarmPlan {
        SwarmPlan {
            listen: Vec::new(),
            idle: Duration::from_secs(10),
            bypass: Vec::new(),
            muxer_observer: None,
            ping_interval: cl_p2p::rpc::inbound::PING_INTERVAL,
            gossip,
        }
    }

    #[tokio::test]
    async fn gossip_is_the_ignore_all_gossipsub_on_beacon_block() {
        let devnet = devnet();
        let status = || Arc::new(SharedStatus::new(None));
        let swarm = probe_swarm::<Minimal>(&devnet, status(), plan(None)).unwrap();
        assert!(!swarm.behaviour().gossipsub.is_enabled());
        let digest = devnet.digest_at(2).unwrap();
        let swarm = probe_swarm::<Minimal>(&devnet, status(), plan(Some(digest))).unwrap();
        let gossip = swarm.behaviour().gossipsub.as_ref().expect("gossipsub on");
        let want = GossipTopic::new(digest, GossipKind::BeaconBlock).to_string();
        let topics: Vec<String> = gossip
            .gossipsub()
            .topics()
            .map(|t| t.as_str().to_owned())
            .collect();
        assert_eq!(topics, [want]);
        assert_eq!(gossip.ignored(), 0);
    }

    #[test]
    fn error_chains_name_every_cause() {
        let inner = std::io::Error::other("inner");
        let outer = std::io::Error::other(OuterError(inner));
        assert_eq!(error_chain(&outer), "outer: inner");
    }

    #[derive(Debug)]
    struct OuterError(std::io::Error);

    impl std::fmt::Display for OuterError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("outer")
        }
    }

    impl std::error::Error for OuterError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }
}
