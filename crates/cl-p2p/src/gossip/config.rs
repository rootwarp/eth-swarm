//! What the probe's gossipsub is built from: the subscribed topics (configuration, so custody
//! column subnets and capture topics are added without code), the topic caps, and the
//! gossipsub settings the ignore-all profile needs.
//!
//! - `StrictNoSign`: `ValidationMode::Anonymous` with `MessageAuthenticity::Anonymous`
//!   (`phase0/p2p-interface.md` "Topics and messages"); messages carrying `from`, `seqno`,
//!   `signature` or `key` are refused.
//! - Manual validation (`validate_messages`): nothing is forwarded until the application
//!   reports `Accept`, which [`super::IgnoreAll`] never does.
//! - The Altair message-id over the decompressed data, and [`WireTransform`], the bounded
//!   snappy transform, which decodes and caches only subscribed topics.
//! - `max_message_size()` as the RPC cap, and the phase0 mesh and cache parameters.
//! - A subscription filter ([`ProbeSubscriptionFilter`]): gossipsub keeps, for each peer, only
//!   the subscriptions to topics we subscribe ourselves, from RPCs of bounded size.
//! - Metric labels for our own topics only ([`metrics_config`]).
//! - Mesh push only: IHAVE is ignored, so no IWANT is sent.

use super::GossipError;
use libp2p::gossipsub;
use libp2p::gossipsub::{
    DataTransform, MaxCountSubscriptionFilter, Message, MessageId, MetricsConfig, RawMessage,
    TopicHash, WhitelistSubscriptionFilter,
};
use p2p_wire::gossip::{message_id_of_decompressed, GossipTopic, SnappyTransform, TopicCaps};
use p2p_wire::rpc::codec::max_compressed_len;
use std::collections::HashSet;
use std::io;
use std::time::Duration;

/// `MAX_PAYLOAD_SIZE` (`phase0` config).
const MAX_PAYLOAD_SIZE: usize = consensus_types::caps::MAX_PAYLOAD_SIZE;

/// `heartbeat_interval` (`phase0/p2p-interface.md` "Gossipsub Parameters"): 0.7 s.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(700);
/// The delay before the first heartbeat: gossipsub's default.
pub const HEARTBEAT_INITIAL_DELAY: Duration = Duration::from_secs(5);
/// `D`: the mesh degree target.
pub const MESH_N: usize = 8;
/// `D_low`.
pub const MESH_N_LOW: usize = 6;
/// `D_high`.
pub const MESH_N_HIGH: usize = 12;
/// `D_lazy`.
pub const GOSSIP_LAZY: usize = 6;
/// `fanout_ttl`: 60 s.
pub const FANOUT_TTL: Duration = Duration::from_secs(60);
/// `mcache_len`: windows of full messages kept for IWANT.
pub const MCACHE_LEN: usize = 6;
/// `mcache_gossip`: windows gossiped about.
pub const MCACHE_GOSSIP: usize = 3;

/// Topics one Gloas fork digest has: 13 global topics (`beacon_block`,
/// `beacon_aggregate_and_proof`, `voluntary_exit`, `proposer_slashing`, `attester_slashing`,
/// `sync_committee_contribution_and_proof`, `bls_to_execution_change`, the two light-client
/// updates, `execution_payload_bid`, `execution_payload`, `payload_attestation_message`,
/// `proposer_preferences`) and 196 subnets (64 attestation, 4 sync committee, 128 column).
pub const TOPICS_PER_FORK_DIGEST: usize = 13 + 64 + 4 + 128;

/// Subscriptions one RPC may carry, or the whole RPC's subscriptions are ignored: every topic
/// of two fork digests (a peer joins the next fork's topics ahead of it). A supernode's first
/// RPC lists 128 column subnets alone, so a smaller cap would hide every topic of such a peer.
pub const MAX_SUBSCRIPTIONS_PER_REQUEST: usize = 2 * TOPICS_PER_FORK_DIGEST;

/// The longest topic name of a Gloas fork digest: `sync_committee_contribution_and_proof`.
pub const MAX_TOPIC_NAME_LEN: usize = "sync_committee_contribution_and_proof".len();

/// The longest topic string: `/eth2/` + 8 hex digits + `/` + name + `/ssz_snappy`.
pub const MAX_TOPIC_LEN: usize =
    "/eth2/".len() + 8 + "/".len() + MAX_TOPIC_NAME_LEN + "/ssz_snappy".len();

/// The encoded length of one `RPC.subscriptions` entry for the longest topic: the entry's tag
/// and length (1 + 1), `subscribe` (1 + 1), `topic_id`'s tag and length (1 + 1) and the topic,
/// and `requestsPartial` and `supportsPartial` (2 + 2) should a peer send them.
pub const MAX_SUBSCRIPTION_ENTRY_LEN: usize = 2 + 2 + 2 + MAX_TOPIC_LEN + 4;

/// gossipsub's own allowance for control messages (IHAVE, IWANT, GRAFT, ...) in one RPC: its
/// default, 16 KiB.
pub const CONTROL_ALLOWANCE: usize = 16 * 1024;

/// The bytes of subscriptions and control one RPC may carry, counted by gossipsub's codec
/// before any filter runs. Derived from the two-fork topic set: one entry for each of the
/// [`MAX_SUBSCRIPTIONS_PER_REQUEST`] topics (2 × [`TOPICS_PER_FORK_DIGEST`]), each at
/// [`MAX_SUBSCRIPTION_ENTRY_LEN`], plus [`CONTROL_ALLOWANCE`]: 46,898 bytes.
pub const MAX_CONTROL_MESSAGE_SIZE: usize =
    MAX_SUBSCRIPTIONS_PER_REQUEST * MAX_SUBSCRIPTION_ENTRY_LEN + CONTROL_ALLOWANCE;

/// gossipsub's metrics with labels for our own topics only (`max_never_subscribed_topics`
/// 0): only our topics get metric labels.
pub fn metrics_config() -> MetricsConfig {
    MetricsConfig {
        max_never_subscribed_topics: 0,
        ..MetricsConfig::default()
    }
}

/// Topics a peer may hold subscribed beyond our own: none can be held while the whitelist
/// stands, so this is a second bound, not one a peer can reach.
pub const SUBSCRIBED_TOPICS_HEADROOM: usize = 4;

/// What gossipsub keeps of a peer's subscriptions: only topics in the whitelist (ours), at
/// most our topic count plus [`SUBSCRIBED_TOPICS_HEADROOM`], from RPCs of at most
/// [`MAX_SUBSCRIPTIONS_PER_REQUEST`] subscriptions.
pub type ProbeSubscriptionFilter = MaxCountSubscriptionFilter<WhitelistSubscriptionFilter>;

/// `max_message_size()` (`phase0/p2p-interface.md`): the largest encoded RPC,
/// `max(max_compressed_len(MAX_PAYLOAD_SIZE) + 1024, 1 MiB)`.
pub fn max_message_size() -> usize {
    (max_compressed_len(MAX_PAYLOAD_SIZE) + 1024).max(1 << 20)
}

/// `seen_ttl`: `SLOT_DURATION_MS * SLOTS_PER_EPOCH * 2` milliseconds (768 s on mainnet).
pub fn seen_ttl(slot_duration_ms: u64, slots_per_epoch: u64) -> Duration {
    Duration::from_millis(
        slot_duration_ms
            .saturating_mul(slots_per_epoch)
            .saturating_mul(2),
    )
}

/// What [`super::IgnoreAll::new`] builds.
#[derive(Clone, Debug)]
pub struct GossipConfig {
    /// The topics subscribed at start. Every other topic stays unsubscribed.
    pub topics: Vec<GossipTopic>,
    /// The uncompressed cap of each topic kind.
    pub caps: TopicCaps,
    /// How long a seen message-id is remembered.
    pub seen_ttl: Duration,
    /// The heartbeat; [`HEARTBEAT_INTERVAL`] unless a test needs a faster one.
    pub heartbeat_interval: Duration,
    /// The delay before the first heartbeat; [`HEARTBEAT_INITIAL_DELAY`].
    pub heartbeat_initial_delay: Duration,
}

impl GossipConfig {
    /// Subscribes `topics`, holds messages to `caps`, and remembers ids for `seen_ttl`.
    pub fn new(topics: Vec<GossipTopic>, caps: TopicCaps, seen_ttl: Duration) -> Self {
        Self {
            topics,
            caps,
            seen_ttl,
            heartbeat_interval: HEARTBEAT_INTERVAL,
            heartbeat_initial_delay: HEARTBEAT_INITIAL_DELAY,
        }
    }

    /// The gossipsub configuration: see the module docs.
    ///
    /// # Errors
    ///
    /// [`GossipError::ZeroHeartbeat`] for a zero heartbeat (gossipsub would spin), else the
    /// builder's [`GossipError::Config`].
    pub fn gossipsub(&self) -> Result<gossipsub::Config, GossipError> {
        if self.heartbeat_interval.is_zero() {
            return Err(GossipError::ZeroHeartbeat);
        }
        let config = gossipsub::ConfigBuilder::default()
            .validation_mode(gossipsub::ValidationMode::Anonymous)
            .validate_messages()
            .message_id_fn(message_id)
            .max_transmit_size(max_message_size())
            .max_control_message_size(MAX_CONTROL_MESSAGE_SIZE)
            // The probe uses mesh push only; lazy pull is off: it asks for no message a peer
            // announces in IHAVE, because it forwards none and needs only what its mesh pushes.
            .max_ihave_messages_heartbeat(0)
            .heartbeat_interval(self.heartbeat_interval)
            .heartbeat_initial_delay(self.heartbeat_initial_delay)
            .mesh_n(MESH_N)
            .mesh_n_low(MESH_N_LOW)
            .mesh_n_high(MESH_N_HIGH)
            .gossip_lazy(GOSSIP_LAZY)
            .fanout_ttl(FANOUT_TTL)
            .history_length(MCACHE_LEN)
            .history_gossip(MCACHE_GOSSIP)
            .duplicate_cache_time(self.seen_ttl)
            .build()?;
        Ok(config)
    }

    /// The subscription filter for these topics: see [`ProbeSubscriptionFilter`].
    pub fn subscription_filter(&self) -> ProbeSubscriptionFilter {
        let whitelist = self.topic_hashes();
        MaxCountSubscriptionFilter {
            max_subscribed_topics: whitelist.len() + SUBSCRIBED_TOPICS_HEADROOM,
            max_subscriptions_per_request: MAX_SUBSCRIPTIONS_PER_REQUEST,
            filter: WhitelistSubscriptionFilter(whitelist),
        }
    }

    /// The data transform for these caps and topics.
    pub fn transform(&self) -> WireTransform {
        WireTransform::new(SnappyTransform::new(self.caps), self.topic_hashes())
    }

    /// The `TopicHash` of every subscribed topic.
    fn topic_hashes(&self) -> HashSet<TopicHash> {
        self.topics
            .iter()
            .map(|t| TopicHash::from_raw(t.to_string()))
            .collect()
    }
}

/// The Altair message-id of a message the transform has decompressed.
pub fn message_id(message: &Message) -> MessageId {
    MessageId::new(&message_id_of_decompressed(
        message.topic.as_str(),
        &message.data,
    ))
}

/// [`SnappyTransform`] as gossipsub's [`DataTransform`], for the subscribed topics only. A
/// refused message surfaces in gossipsub as `ValidationError::TransformFailed`.
///
/// It decodes and caches only subscribed topics: a message on any other topic, even a kind
/// [`SnappyTransform`] supports or our kind under another fork digest, is refused before its
/// data is decompressed.
#[derive(Clone, Debug)]
pub struct WireTransform {
    snappy: SnappyTransform,
    topics: HashSet<TopicHash>,
}

impl WireTransform {
    /// `snappy` for messages on `topics`; every other topic is refused.
    pub fn new(snappy: SnappyTransform, topics: HashSet<TopicHash>) -> Self {
        Self { snappy, topics }
    }

    /// Refuses a topic outside the subscribed set. The error does not carry the topic string,
    /// which is the peer's and of any length.
    fn subscribed(&self, topic: &TopicHash) -> Result<(), io::Error> {
        if self.topics.contains(topic) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a subscribed topic",
            ))
        }
    }
}

impl DataTransform for WireTransform {
    fn inbound_transform(&self, raw: RawMessage) -> Result<Message, io::Error> {
        self.subscribed(&raw.topic)?;
        let data = self
            .snappy
            .inbound(raw.topic.as_str(), &raw.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Message {
            source: raw.source,
            data,
            sequence_number: raw.sequence_number,
            topic: raw.topic,
        })
    }

    fn outbound_transform(&self, topic: &TopicHash, data: Vec<u8>) -> Result<Vec<u8>, io::Error> {
        self.subscribed(topic)?;
        self.snappy
            .outbound(topic.as_str(), &data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::caps::NetworkCaps;
    use consensus_types::Mainnet;
    use p2p_wire::gossip::GossipKind;

    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    fn config() -> GossipConfig {
        let caps = TopicCaps::gloas::<Mainnet>(&NetworkCaps::from_blob_schedule(21, &[]));
        GossipConfig::new(
            vec![GossipTopic::new([0; 4], GossipKind::BeaconBlock)],
            caps,
            seen_ttl(12_000, 32),
        )
    }

    fn raw(topic: &str, data: Vec<u8>) -> RawMessage {
        RawMessage {
            source: None,
            data,
            sequence_number: None,
            topic: TopicHash::from_raw(topic),
            signature: None,
            key: None,
            validated: false,
        }
    }

    #[test]
    fn the_profile_is_strict_no_sign_with_manual_validation() {
        let c = config().gossipsub().unwrap();
        assert!(c.validate_messages());
        assert!(matches!(
            c.validation_mode(),
            gossipsub::ValidationMode::Anonymous
        ));
        assert_eq!(c.max_transmit_size(), max_message_size());
        assert_eq!(c.max_control_message_size(), MAX_CONTROL_MESSAGE_SIZE);
        assert_eq!(MAX_TOPIC_LEN, 63);
        assert_eq!(MAX_CONTROL_MESSAGE_SIZE, 46_898);
        assert_eq!(metrics_config().max_never_subscribed_topics, 0);
        assert_eq!(c.max_ihave_messages_heartbeat(), 0);
        assert_eq!(c.heartbeat_interval(), HEARTBEAT_INTERVAL);
        assert_eq!(c.heartbeat_initial_delay(), HEARTBEAT_INITIAL_DELAY);
        assert_eq!(c.history_length(), MCACHE_LEN);
        assert_eq!(c.history_gossip(), MCACHE_GOSSIP);
        assert_eq!(c.mesh_n(), MESH_N);
        assert_eq!(c.duplicate_cache_time(), Duration::from_secs(768));
        let m = Message {
            source: None,
            data: b"hello".to_vec(),
            sequence_number: None,
            topic: TopicHash::from_raw(BLOCK),
        };
        assert_eq!(
            c.message_id(&m),
            MessageId::new(&message_id_of_decompressed(BLOCK, b"hello"))
        );
    }

    #[test]
    fn the_filter_lets_only_our_topics_through() {
        use libp2p::gossipsub::TopicSubscriptionFilter as _;
        let mut f = config().subscription_filter();
        assert_eq!(f.max_subscribed_topics, 1 + SUBSCRIBED_TOPICS_HEADROOM);
        assert_eq!(f.max_subscriptions_per_request, 418);
        assert!(f.can_subscribe(&TopicHash::from_raw(BLOCK)));
        assert!(!f.can_subscribe(&TopicHash::from_raw(
            "/eth2/00000000/beacon_aggregate_and_proof/ssz_snappy"
        )));
    }

    #[test]
    fn max_message_size_is_the_spec_formula() {
        assert_eq!(
            max_message_size(),
            32 + MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE / 6 + 1024
        );
    }

    #[test]
    fn the_transform_decompresses_inbound_and_compresses_outbound() {
        let t = config().transform();
        let data = t
            .outbound_transform(&TopicHash::from_raw(BLOCK), b"ssz".to_vec())
            .unwrap();
        assert_ne!(data, b"ssz");
        let m = t.inbound_transform(raw(BLOCK, data)).unwrap();
        assert_eq!(m.data, b"ssz");
        assert_eq!(m.topic.as_str(), BLOCK);
    }

    #[test]
    fn the_transform_refuses_what_the_wire_transform_refuses() {
        let t = config().transform();
        let err = t
            .inbound_transform(raw("/eth2/00000000/voluntary_exit/ssz_snappy", vec![0]))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let mut bomb = Vec::new();
        p2p_wire::rpc::codec::encode_varint(u64::from(u32::MAX), &mut bomb);
        assert!(t.inbound_transform(raw(BLOCK, bomb)).is_err());
        assert!(t
            .outbound_transform(&TopicHash::from_raw("/x"), vec![])
            .is_err());
    }

    /// The transform decodes and caches only subscribed topics: a supported kind under our
    /// digest that we do not subscribe, and our kind under another digest, are refused before
    /// anything is decompressed; our topic still decodes.
    #[test]
    fn the_transform_decodes_only_subscribed_topics() {
        let t = config().transform();
        let ssz = vec![7u8; 1000];
        let data = SnappyTransform::new(config().caps)
            .outbound("/eth2/00000000/beacon_aggregate_and_proof/ssz_snappy", &ssz)
            .unwrap();
        for topic in [
            "/eth2/00000000/beacon_aggregate_and_proof/ssz_snappy",
            "/eth2/00000001/beacon_block/ssz_snappy",
        ] {
            let err = t.inbound_transform(raw(topic, data.clone())).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{topic}");
            assert_eq!(err.to_string(), "not a subscribed topic", "{topic}");
            assert!(t
                .outbound_transform(&TopicHash::from_raw(topic), ssz.clone())
                .is_err());
        }
        assert_eq!(t.inbound_transform(raw(BLOCK, data)).unwrap().data, ssz);
    }

    #[test]
    fn a_zero_heartbeat_is_a_config_error() {
        let mut c = config();
        c.heartbeat_interval = Duration::ZERO;
        assert!(matches!(c.gossipsub(), Err(GossipError::ZeroHeartbeat)));
    }
}
