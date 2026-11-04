//! The probe swarm of a network: [`build_swarm`] (TCP, Noise XX, yamux then mplex, connection
//! limits, identify) with its req/resp behaviour ([`Control`]) over the network's preset and fork
//! digests, and, if asked for, the ignore-all gossipsub ([`IgnoreAll`],
//! [`build_swarm_with_gossip`]) on the given topics, with a capture tap.
//!
//! The service ([`super`]) and `devnet-probe` build it the same way ([`serving_swarm`]).

use crate::behaviour::SpecBehaviour;
use crate::gossip::{CaptureTap, GossipConfig, IgnoreAll};
use crate::rpc::blocks::{BlockSource, ByRangeResponder, WindowStart};
use crate::rpc::codec::Deadlines;
use crate::rpc::columns::ColumnSource;
use crate::rpc::inbound::{Control, ControlConfig, SharedMetaData, StatusSource};
use crate::rpc::limits::RpcLimits;
use crate::rpc::metrics::RpcMetrics;
use crate::transport::{
    build_swarm, build_swarm_with_gossip, MuxerBudget, MuxerObserver, SwarmConfig, TransportMetrics,
};
use consensus_types::caps::NetworkCaps;
use consensus_types::EthSpec;
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId, Swarm};
use network_config::digest::current_epoch;
use network_config::window::block_serve_window;
use network_config::{ChainConfig, Genesis};
use p2p_wire::gossip::{GossipTopic, TopicCaps};
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
    /// The ignore-all gossipsub on `beacon_block` at this fork digest, for a swarm that names
    /// only that topic (`devnet-probe`'s checks). [`serving_swarm`] does not read it: it takes
    /// its topics from [`Gossip`].
    pub gossip: Option<ForkDigest>,
    /// The req/resp limits: the quotas, and the column answer places and their address blocks.
    pub limits: RpcLimits,
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
    /// The blocks' source (cl-store and cl-chain, [`crate::rpc::blocks_ipc::IpcBlocks`]),
    /// served by a [`ByRangeResponder`] whose floor is [`Self::status`]'s; `None` answers every
    /// BlocksByRange request `3: ResourceUnavailable`.
    pub blocks: Option<Arc<dyn BlockSource>>,
}

/// The ignore-all gossipsub's topics, and the tap each message also goes to.
pub struct Gossip {
    /// The topics it subscribes.
    pub topics: Vec<GossipTopic>,
    /// Every message, as gossipsub delivers it.
    pub tap: Option<CaptureTap>,
}

/// The start slot of the block serve window by the wall clock (`network_config::window`), for
/// the responder's floor check; `None` before genesis or for a config without the window's
/// values.
fn window_start<E: EthSpec>(config: &ChainConfig, genesis: &Genesis) -> WindowStart {
    let (config, genesis_time) = (config.clone(), genesis.genesis_time);
    Arc::new(move || {
        let (slot_ms, per_epoch) = (config.slot_duration_ms(), E::slots_per_epoch());
        let now = ipc::hello::system_ms();
        let epoch = current_epoch(genesis_time, slot_ms, per_epoch, now).ok()?;
        let start = block_serve_window(&config, epoch).ok()?;
        Some(start.saturating_mul(per_epoch))
    })
}

/// The probe swarm of the network of `config` and `genesis` under the preset `E`, with the
/// node key `key`, answering from `sources` (BeaconBlocksByRange through a [`ByRangeResponder`]
/// over `sources.blocks`, at most `plan.limits.max_block_lookups` answers holding IPC calls), with the ignore-all gossipsub on `gossip`'s topics
/// if given (`plan.gossip` is not read). Every column answer is read and served under the
/// network's caps ([`crate::rpc::network_context_table`]). Its metrics (`p2p_peers` excepted,
/// which the owner of the swarm keeps: [`crate::transport::PeerMetrics`]) go to `registry`:
/// the transport's, req/resp's (`p2p_goodbye_*`) and gossipsub's own (`topic_msg_*`).
///
/// Must be called within a tokio runtime.
///
/// # Errors
///
/// The req/resp limits were refused for the network's blob schedule
/// ([`RpcLimits::validate`]), or the swarm could not be built or could not listen.
pub fn serving_swarm<E: EthSpec>(
    config: &ChainConfig,
    genesis: &Genesis,
    key: Keypair,
    sources: Sources,
    plan: SwarmPlan,
    gossip: Option<Gossip>,
    registry: &mut Registry,
) -> Result<Swarm<SpecBehaviour<E>>, String> {
    let gvr = &genesis.genesis_validators_root;
    plan.limits
        .validate::<E>(&NetworkCaps::from_config(config))
        .map_err(|e| format!("req/resp limits: {e}"))?;
    let transport = TransportMetrics::register(registry);
    let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
    cfg.listen_addrs = plan.listen;
    cfg.idle_connection_timeout = plan.idle;
    cfg.bypass = plan.bypass;
    cfg.muxer_observer = plan.muxer_observer;
    let metrics = RpcMetrics::register(registry);
    let max_lookups = plan.limits.max_block_lookups;
    let mut control = Control::<E>::new(
        ControlConfig {
            status: Arc::clone(&sources.status),
            metadata: Arc::new(SharedMetaData::new(MetaDataV3 {
                seq_number: 0,
                attnets: Default::default(),
                syncnets: Default::default(),
                custody_group_count: sources.custody_group_count,
            })),
            contexts: Arc::new(crate::rpc::network_context_table(config, gvr)),
            deadlines: Deadlines::default(),
            limits: plan.limits,
            ping_interval: plan.ping_interval,
            columns: sources.columns,
        },
        metrics.clone(),
    );
    if let Some(source) = sources.blocks {
        let responder = ByRangeResponder::new(source, sources.status, max_lookups, Some(metrics))
            .with_window(window_start::<E>(config, genesis));
        control = control.with_blocks_responder(Arc::new(responder));
    }
    match gossip {
        None => build_swarm(key, &cfg, control).map_err(|e| e.to_string()),
        Some(gossip) => {
            let gossip_cfg = GossipConfig::ethereum_profile::<E>(
                config,
                gossip.topics,
                TopicCaps::from_config::<E>(config, gvr),
            );
            let mut ignore_all =
                IgnoreAll::new(&gossip_cfg, registry).map_err(|e| format!("gossipsub: {e}"))?;
            if let Some(tap) = gossip.tap {
                ignore_all = ignore_all.with_tap(tap);
            }
            build_swarm_with_gossip(key, &cfg, control, ignore_all).map_err(|e| e.to_string())
        }
    }
}
