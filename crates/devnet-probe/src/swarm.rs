//! The probe swarm on a devnet: cl-p2p's [`build_swarm`] (TCP, Noise XX, yamux then mplex,
//! connection limits, identify) with its req/resp behaviour ([`Control`]) over the devnet's
//! preset and fork digests, and, if asked for, its ignore-all gossipsub ([`IgnoreAll`],
//! `build_swarm_with_gossip`) on `beacon_block`.

use super::devnet::Devnet;
use cl_p2p::behaviour::SpecBehaviour;
use cl_p2p::gossip::{CaptureTap, GossipConfig, IgnoreAll};
use cl_p2p::rpc::codec::Deadlines;
use cl_p2p::rpc::columns::ColumnSource;
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
    /// The req/resp limits: the quotas, and the column answer places and their address blocks.
    pub limits: RpcLimits,
}

/// The probe swarm for `devnet` under the preset `E`, with an ephemeral secp256k1 node key, our
/// Status from `status`, MetaData `seq_number` 0 and the custody group count
/// `CUSTODY_REQUIREMENT`. Its metrics go to a registry of its own, which nothing exports.
///
/// Must be called within a tokio runtime.
///
/// # Errors
///
/// The req/resp limits were refused, or the swarm could not be built or could not listen.
pub fn probe_swarm<E: EthSpec>(
    devnet: &Devnet,
    status: Arc<dyn StatusSource>,
    plan: SwarmPlan,
) -> Result<Swarm<SpecBehaviour<E>>, String> {
    let gossip = plan.gossip.map(|digest| Gossip {
        topics: vec![GossipTopic::new(digest, GossipKind::BeaconBlock)],
        tap: None,
    });
    let sources = Sources {
        status,
        custody_group_count: CUSTODY_REQUIREMENT,
        // The devnet probe's checks store no columns.
        columns: None,
    };
    serving_swarm(devnet, Keypair::generate_secp256k1(), sources, plan, gossip)
}

/// Where the probe swarm's answers come from.
pub struct Sources {
    /// Our Status.
    pub status: Arc<dyn StatusSource>,
    /// The MetaData `custody_group_count` (`seq_number` 0, no attestation or sync subnets).
    pub custody_group_count: u64,
    /// The custody columns' source; `None` answers every column request
    /// `3: ResourceUnavailable`.
    pub columns: Option<Arc<dyn ColumnSource>>,
}

/// The ignore-all gossipsub's topics, and the tap each message also goes to.
pub struct Gossip {
    /// The topics it subscribes.
    pub topics: Vec<GossipTopic>,
    /// Every message, as gossipsub delivers it.
    pub tap: Option<CaptureTap>,
}

/// The probe swarm for `devnet` under the preset `E`, with the node key `key`, answering from
/// `sources`, with the ignore-all gossipsub on `gossip`'s topics if given (`plan.gossip` is not
/// read). Every column answer is read and served under the devnet's caps
/// ([`Devnet::context_table`]). Its metrics go to a registry of its own.
///
/// Must be called within a tokio runtime.
///
/// # Errors
///
/// The req/resp limits were refused ([`RpcLimits::validate`]), or the swarm could not be built
/// or could not listen.
pub fn serving_swarm<E: EthSpec>(
    devnet: &Devnet,
    key: Keypair,
    sources: Sources,
    plan: SwarmPlan,
    gossip: Option<Gossip>,
) -> Result<Swarm<SpecBehaviour<E>>, String> {
    plan.limits
        .validate()
        .map_err(|e| format!("req/resp limits: {e}"))?;
    let mut registry = Registry::default();
    let transport = TransportMetrics::register(&mut registry);
    let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
    cfg.listen_addrs = plan.listen;
    cfg.idle_connection_timeout = plan.idle;
    cfg.bypass = plan.bypass;
    cfg.muxer_observer = plan.muxer_observer;
    let control = Control::<E>::new(
        ControlConfig {
            status: sources.status,
            metadata: Arc::new(SharedMetaData::new(MetaDataV3 {
                seq_number: 0,
                attnets: Default::default(),
                syncnets: Default::default(),
                custody_group_count: sources.custody_group_count,
            })),
            contexts: Arc::new(devnet.context_table()),
            deadlines: Deadlines::default(),
            limits: plan.limits,
            ping_interval: plan.ping_interval,
            columns: sources.columns,
        },
        RpcMetrics::register(&mut registry),
    );
    match gossip {
        None => build_swarm(key, &cfg, control).map_err(|e| e.to_string()),
        Some(gossip) => {
            let caps = TopicCaps::gloas::<E>(&NetworkCaps::from_config(devnet.config()));
            let gossip_cfg =
                GossipConfig::ethereum_profile::<E>(devnet.config(), gossip.topics, caps);
            let mut ignore_all = IgnoreAll::new(&gossip_cfg, &mut registry)
                .map_err(|e| format!("gossipsub: {e}"))?;
            if let Some(tap) = gossip.tap {
                ignore_all = ignore_all.with_tap(tap);
            }
            build_swarm_with_gossip(key, &cfg, control, ignore_all).map_err(|e| e.to_string())
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
            limits: RpcLimits::default(),
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

    /// The req/resp limits are checked before the swarm is built: a column quota too slow for
    /// the largest block is refused with its field, the defaults are taken.
    #[tokio::test]
    async fn a_column_quota_too_slow_for_the_largest_block_is_refused() {
        let devnet = devnet();
        let status = || Arc::new(SharedStatus::new(None));
        let mut slow = plan(None);
        slow.limits.rate.data_columns_by_root =
            cl_p2p::rpc::limits::Quota::new(512, Duration::from_millis(50));
        let err = probe_swarm::<Minimal>(&devnet, status(), slow)
            .err()
            .expect("refused");
        assert!(err.contains("rate.data_columns_by_root"), "{err}");
        assert!(probe_swarm::<Minimal>(&devnet, status(), plan(None)).is_ok());
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
