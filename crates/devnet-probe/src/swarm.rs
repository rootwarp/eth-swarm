//! The probe swarm on a devnet: cl-p2p's service swarm (`cl_p2p::service::swarm`: TCP, Noise
//! XX, yamux then mplex, connection limits, identify, the req/resp behaviour) over the devnet's
//! preset and fork digests, and, if asked for, its ignore-all gossipsub on `beacon_block`.

use super::devnet::Devnet;
use cl_p2p::behaviour::SpecBehaviour;
use cl_p2p::rpc::inbound::StatusSource;
use consensus_types::das::CUSTODY_REQUIREMENT;
use consensus_types::EthSpec;
use libp2p::identity::Keypair;
use libp2p::Swarm;
use p2p_wire::gossip::{GossipKind, GossipTopic};
use prometheus_client::registry::Registry;
use std::sync::Arc;

pub use cl_p2p::service::swarm::{Gossip, Sources, SwarmPlan};

#[cfg(test)]
use cl_p2p::rpc::limits::RpcLimits;
#[cfg(test)]
use p2p_wire::rpc::messages::ForkDigest;
#[cfg(test)]
use std::time::Duration;

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

/// The probe swarm for `devnet` under the preset `E`, with the node key `key`, answering from
/// `sources`, with the ignore-all gossipsub on `gossip`'s topics if given (`plan.gossip` is not
/// read). Every column answer is read and served under the devnet's caps
/// ([`Devnet::context_table`]). Its metrics go to a registry of its own.
///
/// Must be called within a tokio runtime.
///
/// # Errors
///
/// The req/resp limits were refused for the devnet's blob schedule,
/// or the swarm could not be built or could not listen.
pub fn serving_swarm<E: EthSpec>(
    devnet: &Devnet,
    key: Keypair,
    sources: Sources,
    plan: SwarmPlan,
    gossip: Option<Gossip>,
) -> Result<Swarm<SpecBehaviour<E>>, String> {
    cl_p2p::service::swarm::serving_swarm::<E>(
        devnet.config(),
        &devnet.genesis(),
        key,
        sources,
        plan,
        gossip,
        &mut Registry::default(),
    )
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
