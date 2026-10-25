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
//!   the subscriptions to whitelisted topics, from RPCs of bounded size.
//! - Two [`TopicSet`]s, which grow all or nothing and never past [`MAX_TOPICS`], and shrink
//!   only by a whole fork digest ([`TopicSet::remove_digest`], when the probe retires it):
//!   - the subscribed set, behind the transform: [`GossipConfig::topics`] at start, and the
//!     topics subscribed later ([`super::IgnoreAll::subscribe`], e.g. the custody column
//!     subnets), so a topic is decodable from the moment we subscribe it;
//!   - the whitelist, behind the filter ([`GossipConfig::whitelist`]): the subscribed set and,
//!     from the start, every `data_column_sidecar_{subnet_id}` subnet of each configured fork
//!     digest. gossipsub drops a peer's subscription to a topic it does not allow, and meshes
//!     only with a peer it holds subscribed, so a custody subnet subscribed after peers
//!     announced it still meshes with them on the same connection. A whitelisted topic we do
//!     not subscribe is still refused by the transform before decompression.
//! - Metric labels for our own topics only ([`metrics_config`]).
//! - Mesh push only: IHAVE is ignored, so no IWANT is sent.
//!
//! [`GossipConfig::ethereum_profile`] takes `seen_ttl` from a network's [`ChainConfig`].

use super::GossipError;
use consensus_types::EthSpec;
use libp2p::gossipsub;
use libp2p::gossipsub::{
    DataTransform, MaxCountSubscriptionFilter, Message, MessageId, MetricsConfig, RawMessage,
    TopicHash, TopicSubscriptionFilter,
};
use network_config::ChainConfig;
use p2p_wire::gossip::topic::DATA_COLUMN_SIDECAR_SUBNET_COUNT;
use p2p_wire::gossip::{
    message_id_of_decompressed, GossipKind, GossipTopic, SnappyTransform, TopicCaps,
};
use p2p_wire::rpc::codec::max_compressed_len;
use p2p_wire::rpc::messages::ForkDigest;
use std::collections::{BTreeSet, HashSet};
use std::io;
use std::sync::{Arc, PoisonError, RwLock};
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

/// Topics a peer may hold subscribed beyond the whitelist: none can be held while the whitelist
/// stands, so this is a second bound, not one a peer can reach.
pub const SUBSCRIBED_TOPICS_HEADROOM: usize = 4;

/// The most topics we subscribe or whitelist: [`MAX_SUBSCRIPTIONS_PER_REQUEST`], every topic of
/// two fork digests. Our whole subscription list then fits the one RPC a new peer receives,
/// under the same per-RPC cap and [`MAX_CONTROL_MESSAGE_SIZE`] we hold peers to. The whitelist
/// of two digests' configured topics adds at most their 2 × 128 column subnets, all within the
/// two digests' 418 topics.
pub const MAX_TOPICS: usize = MAX_SUBSCRIPTIONS_PER_REQUEST;

/// A set of topics read by the subscription filter (the whitelist) or the transform (the
/// subscribed set); see the module docs. Clones share one set. It shrinks only by a whole fork
/// digest.
#[derive(Clone, Debug, Default)]
pub struct TopicSet(Arc<RwLock<HashSet<TopicHash>>>);

impl TopicSet {
    /// A set holding `topics`.
    ///
    /// # Errors
    ///
    /// [`GossipError::TooManyTopics`] for more than [`MAX_TOPICS`] distinct topics.
    pub fn new(topics: impl IntoIterator<Item = TopicHash>) -> Result<Self, GossipError> {
        let set = Self::default();
        set.extend(&topics.into_iter().collect::<Vec<_>>())?;
        Ok(set)
    }

    /// Whether `topic` is ours.
    pub fn contains(&self, topic: &TopicHash) -> bool {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(topic)
    }

    /// The number of topics.
    pub fn len(&self) -> usize {
        self.0.read().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes every topic under `digest`; returns how many there were.
    pub fn remove_digest(&self, digest: ForkDigest) -> usize {
        let mut set = self.0.write().unwrap_or_else(PoisonError::into_inner);
        let before = set.len();
        set.retain(|t| digest_of(t) != Some(digest));
        before - set.len()
    }

    /// Adds `topics`, all of them or none; returns how many were new.
    ///
    /// # Errors
    ///
    /// [`GossipError::TooManyTopics`] if the set would pass [`MAX_TOPICS`]; it is unchanged.
    pub fn extend(&self, topics: &[TopicHash]) -> Result<usize, GossipError> {
        let mut set = self.0.write().unwrap_or_else(PoisonError::into_inner);
        let new: HashSet<&TopicHash> = topics.iter().filter(|t| !set.contains(*t)).collect();
        if set.len() + new.len() > MAX_TOPICS {
            return Err(GossipError::TooManyTopics {
                have: set.len(),
                adding: new.len(),
                max: MAX_TOPICS,
            });
        }
        let added = new.len();
        set.extend(new.into_iter().cloned());
        Ok(added)
    }
}

/// gossipsub's subscription whitelist over a [`TopicSet`]: a topic is allowed while it is ours.
#[derive(Clone, Debug)]
pub struct TopicWhitelist(TopicSet);

impl TopicSubscriptionFilter for TopicWhitelist {
    fn can_subscribe(&mut self, topic_hash: &TopicHash) -> bool {
        self.0.contains(topic_hash)
    }
}

/// What gossipsub keeps of a peer's subscriptions: only topics in the whitelist, at most
/// [`MAX_TOPICS`] plus [`SUBSCRIBED_TOPICS_HEADROOM`], from RPCs of at most
/// [`MAX_SUBSCRIPTIONS_PER_REQUEST`] subscriptions.
pub type ProbeSubscriptionFilter = MaxCountSubscriptionFilter<TopicWhitelist>;

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
    /// The topics subscribed at start. Every other topic stays unsubscribed unless
    /// [`super::IgnoreAll::subscribe`] adds it.
    pub topics: Vec<GossipTopic>,
    /// The uncompressed cap of each topic kind under each fork digest
    /// (`TopicCaps::from_config` on a real network).
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

    /// The Ethereum gossip profile of `chain` under the preset `E`: `topics` held to `caps`,
    /// and seen ids remembered for [`seen_ttl`] of the network's `SLOT_DURATION_MS` and `E`'s
    /// `SLOTS_PER_EPOCH`. [`Self::gossipsub`] builds the gossipsub `Config` from it.
    pub fn ethereum_profile<E: EthSpec>(
        chain: &ChainConfig,
        topics: Vec<GossipTopic>,
        caps: TopicCaps,
    ) -> Self {
        Self::new(
            topics,
            caps,
            seen_ttl(chain.slot_duration_ms(), E::slots_per_epoch()),
        )
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

    /// A new [`TopicSet`] holding these topics: the subscribed set the transform reads.
    ///
    /// # Errors
    ///
    /// [`GossipError::TooManyTopics`] for more than [`MAX_TOPICS`] topics.
    pub fn topic_set(&self) -> Result<TopicSet, GossipError> {
        TopicSet::new(self.topics.iter().map(topic_hash))
    }

    /// A new [`TopicSet`] for the subscription whitelist: these topics and every
    /// `data_column_sidecar_{subnet_id}` subnet of each of their fork digests, so peers'
    /// subscriptions to a column subnet are kept before we subscribe it (see the module docs).
    ///
    /// # Errors
    ///
    /// [`GossipError::TooManyTopics`] for more than [`MAX_TOPICS`] topics.
    pub fn whitelist(&self) -> Result<TopicSet, GossipError> {
        let digests: BTreeSet<ForkDigest> = self.topics.iter().map(|t| t.fork_digest).collect();
        let columns = digests.into_iter().flat_map(|digest| {
            (0..DATA_COLUMN_SIDECAR_SUBNET_COUNT).map(move |subnet_id| {
                GossipTopic::new(digest, GossipKind::DataColumnSidecar { subnet_id })
            })
        });
        TopicSet::new(
            self.topics
                .iter()
                .copied()
                .chain(columns)
                .map(|t| topic_hash(&t)),
        )
    }

    /// The subscription filter over `whitelist` ([`Self::whitelist`]): see
    /// [`ProbeSubscriptionFilter`]. The per-peer count bound is [`MAX_TOPICS`], not the set's
    /// size now, because the set can grow to it.
    pub fn subscription_filter(&self, whitelist: &TopicSet) -> ProbeSubscriptionFilter {
        MaxCountSubscriptionFilter {
            max_subscribed_topics: MAX_TOPICS + SUBSCRIBED_TOPICS_HEADROOM,
            max_subscriptions_per_request: MAX_SUBSCRIPTIONS_PER_REQUEST,
            filter: TopicWhitelist(whitelist.clone()),
        }
    }

    /// The data transform for these caps, over `topics`.
    pub fn transform(&self, topics: &TopicSet) -> WireTransform {
        WireTransform::shared(SnappyTransform::new(self.caps.clone()), topics.clone())
    }
}

/// The fork digest of the topic `hash`, if it is an Ethereum topic.
pub fn digest_of(hash: &TopicHash) -> Option<ForkDigest> {
    GossipTopic::parse(hash.as_str())
        .ok()
        .map(|t| t.fork_digest)
}

/// The `TopicHash` of `topic`.
pub fn topic_hash(topic: &GossipTopic) -> TopicHash {
    TopicHash::from_raw(topic.to_string())
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
    topics: TopicSet,
}

impl WireTransform {
    /// `snappy` for messages on `topics`; every other topic is refused.
    pub fn new(snappy: SnappyTransform, topics: HashSet<TopicHash>) -> Self {
        Self {
            snappy,
            topics: TopicSet(Arc::new(RwLock::new(topics))),
        }
    }

    /// `snappy` for messages on the topics of `topics` as it is at each message.
    pub fn shared(snappy: SnappyTransform, topics: TopicSet) -> Self {
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
    use network_config::Network;

    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    fn config() -> GossipConfig {
        let caps = TopicCaps::gloas::<Mainnet>(&NetworkCaps::from_blob_schedule(21, &[]));
        GossipConfig::new(
            vec![GossipTopic::new([0; 4], GossipKind::BeaconBlock)],
            caps,
            seen_ttl(12_000, 32),
        )
    }

    fn transform() -> WireTransform {
        let c = config();
        c.transform(&c.topic_set().unwrap())
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

    /// The phase0 gossipsub parameters, read back from the built `Config` of the Ethereum
    /// profile of each pinned network (`phase0/p2p-interface.md` "The gossip domain").
    #[test]
    fn built_values() {
        for network in Network::ALL {
            let chain = ChainConfig::load(network).unwrap();
            let profile = GossipConfig::ethereum_profile::<Mainnet>(
                &chain,
                vec![GossipTopic::new([0; 4], GossipKind::BeaconBlock)],
                config().caps,
            );
            let c = profile.gossipsub().unwrap();
            let name = network.name();
            assert_eq!(
                (c.mesh_n(), c.mesh_n_low(), c.mesh_n_high(), c.gossip_lazy()),
                (8, 6, 12, 6),
                "{name}: D, D_low, D_high, D_lazy"
            );
            assert_eq!(c.heartbeat_interval(), Duration::from_millis(700), "{name}");
            assert_eq!(c.fanout_ttl(), Duration::from_secs(60), "{name}");
            assert_eq!(
                (c.history_length(), c.history_gossip()),
                (6, 3),
                "{name}: mcache_len, mcache_gossip"
            );
            // seen_ttl: 2 epochs of the network's SLOT_DURATION_MS.
            assert_eq!(chain.slot_duration_ms(), 12_000, "{name}");
            assert_eq!(
                c.duplicate_cache_time(),
                Duration::from_millis(2 * 32 * chain.slot_duration_ms()),
                "{name}"
            );
            assert_eq!(c.duplicate_cache_time(), Duration::from_secs(768), "{name}");
            // max_message_size() of the network's MAX_PAYLOAD_SIZE.
            assert_eq!(chain.max_payload_size(), MAX_PAYLOAD_SIZE as u64, "{name}");
            assert_eq!(c.max_transmit_size(), 12_234_442, "{name}");
            assert!(
                matches!(c.validation_mode(), gossipsub::ValidationMode::Anonymous),
                "{name}: StrictNoSign"
            );
            assert!(c.validate_messages(), "{name}");
            assert_eq!(c.max_ihave_messages_heartbeat(), 0, "{name}");
            assert_eq!(c.max_control_message_size(), 46_898, "{name}");
        }
    }

    /// The Altair message-id the built `Config` computes (`altair/p2p-interface.md` "Topics and
    /// messages"): `SHA256(MESSAGE_DOMAIN_VALID_SNAPPY ‖ uint_to_bytes(Uint64(len(topic))) ‖
    /// topic ‖ decompressed data)[:20]`. The expected ids were computed independently (Python
    /// hashlib) from that formula; `p2p_wire::gossip::message_id`'s tests hold the raw-data rule
    /// and its invalid-snappy branch.
    #[test]
    fn message_id_altair() {
        use p2p_wire::gossip::message_id::MESSAGE_DOMAIN_VALID_SNAPPY;
        assert_eq!(MESSAGE_DOMAIN_VALID_SNAPPY, [0x01, 0x00, 0x00, 0x00]);
        let c = config().gossipsub().unwrap();
        let data: Vec<u8> = (0..32).collect();
        let id = |topic: &str| {
            let m = Message {
                source: None,
                data: data.clone(),
                sequence_number: None,
                topic: TopicHash::from_raw(topic),
            };
            assert_eq!(c.message_id(&m), message_id(&m), "{topic}");
            c.message_id(&m)
        };
        let hex = |id: MessageId| -> String { id.0.iter().map(|b| format!("{b:02x}")).collect() };
        // Preimage: 01000000 ‖ 2600000000000000 (38, little-endian) ‖ topic ‖ 00 01 .. 1f.
        assert_eq!(BLOCK.len(), 38);
        assert_eq!(hex(id(BLOCK)), "a34b6f35360fd0be1a1eac23d85f04a71e75fc63");
        // Only the topic's fork digest differs: another id.
        let other = "/eth2/00000001/beacon_block/ssz_snappy";
        assert_eq!(hex(id(other)), "5fbf5fcb0858392bfb003e3cd88252f0b5216aaf");
        assert_ne!(id(BLOCK), id(other));
    }

    /// StrictNoSign on the wire (`phase0/p2p-interface.md` "Topics and messages"): a scripted
    /// peer writes raw protobuf `Message`s to the probe, each carrying one of `from`, `seqno`,
    /// `signature` and `key`. Each is refused and never delivered: a marker sent after it on
    /// the same stream is delivered, it is not. The same data on the same topic without the
    /// field is delivered afterwards, so only the field was refused. The `key` case holds only
    /// at a rust-libp2p revision with the gossipsub `key` rejection.
    #[tokio::test]
    async fn strict_no_sign_wire() {
        use crate::gossip::tests::{compressed, handled, id_of, payload, rpc, topic};
        use crate::gossip::tests::{Probe, Scripted};
        use libp2p::identity::Keypair;
        let probe = Probe::spawn(16).await;
        let center = &probe.center;
        let mut scripted = Scripted::connect(&center.addr).await;
        let topic = topic().to_string();
        let author = Keypair::generate_secp256k1().public();
        let from = author.to_peer_id().to_bytes();
        let key = author.encode_protobuf();
        let seqno = 1u64.to_be_bytes();
        let signature = [0x5a; 64];
        // `rpc.proto` field numbers of `Message`.
        let forbidden: [(&str, u64, &[u8]); 4] = [
            ("from", 1, &from),
            ("seqno", 3, &seqno),
            ("signature", 5, &signature),
            ("key", 6, &key),
        ];
        let ssz = |name: &str| payload(name, 0, 100);

        for (name, field, value) in forbidden {
            let data = compressed(&ssz(name));
            scripted
                .send(&rpc::publish_with(&topic, &data, &[(field, value)]))
                .await;
            handled(center, &mut scripted, &format!("after-{name}")).await;
            assert!(
                !center.has(&id_of(&ssz(name))),
                "a message carrying `{name}` was delivered"
            );
        }

        for (name, _, _) in forbidden {
            scripted
                .send(&rpc::publish(&topic, [&compressed(&ssz(name))[..]]))
                .await;
        }
        handled(center, &mut scripted, "after-clean").await;
        for (name, _, _) in forbidden {
            assert!(center.has(&id_of(&ssz(name))), "clean `{name}` message");
        }
        // Four markers, four clean messages and the last marker: nothing else reached the
        // probe's application or its counters.
        let delivered = 4 + 4 + 1;
        assert_eq!(center.delivered().len(), delivered);
        let metrics = probe.metrics();
        assert_eq!(metrics.sum("topic_msg_recv_counts"), delivered as u64);
        assert_eq!(metrics.sum("ignored_messages_per_topic"), delivered as u64);
        assert_eq!(metrics.sum("accepted_messages_per_topic"), 0);
    }

    #[test]
    fn the_filter_lets_only_our_topics_through() {
        use libp2p::gossipsub::TopicSubscriptionFilter as _;
        let c = config();
        let mut f = c.subscription_filter(&c.topic_set().unwrap());
        assert_eq!(
            f.max_subscribed_topics,
            MAX_TOPICS + SUBSCRIBED_TOPICS_HEADROOM
        );
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
        let t = transform();
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
        let t = transform();
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
        let t = transform();
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

    /// The topics of a fork digest leave the set together, and only they: the room they free
    /// takes new topics again.
    #[test]
    fn a_digest_leaves_the_topic_set() {
        let set = TopicSet::default();
        let fill: Vec<TopicHash> = (0..MAX_TOPICS as u64)
            .map(|i| {
                topic_hash(&GossipTopic::new(
                    [(i % 4) as u8; 4],
                    GossipKind::DataColumnSidecar {
                        subnet_id: i / 4 % 128,
                    },
                ))
            })
            .collect();
        let fill: Vec<TopicHash> = fill
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        set.extend(&fill).unwrap();
        let before = set.len();
        let removed = set.remove_digest([1; 4]);
        assert!(removed > 0);
        assert_eq!(set.len(), before - removed);
        assert!(fill
            .iter()
            .all(|t| set.contains(t) != t.as_str().starts_with("/eth2/01010101/")));
        assert_eq!(set.remove_digest([1; 4]), 0, "gone already");
        let again: Vec<TopicHash> = (0..removed as u64)
            .map(|i| TopicHash::from_raw(format!("/eth2/{:08x}/beacon_block/ssz_snappy", i + 9)))
            .collect();
        assert_eq!(set.extend(&again).unwrap(), removed);
    }

    /// The topic set grows all or nothing, never past [`MAX_TOPICS`], and duplicates are free.
    #[test]
    fn the_topic_set_is_bounded() {
        assert_eq!(MAX_TOPICS, MAX_SUBSCRIPTIONS_PER_REQUEST);
        let set = config().topic_set().unwrap();
        assert_eq!(set.len(), 1);
        let column = |i: u64| {
            TopicHash::from_raw(
                GossipTopic::new([0; 4], GossipKind::DataColumnSidecar { subnet_id: i % 128 })
                    .to_string(),
            )
        };
        assert_eq!(set.extend(&[column(1), column(1), column(2)]).unwrap(), 2);
        assert_eq!(set.extend(&[column(2)]).unwrap(), 0);
        assert_eq!(set.len(), 3);
        // Digests 1.. : digest 0's beacon_block is already in the set.
        let fill: Vec<TopicHash> = (1..=(MAX_TOPICS - 3) as u64)
            .map(|i| TopicHash::from_raw(format!("/eth2/{i:08x}/beacon_block/ssz_snappy")))
            .collect();
        assert_eq!(set.extend(&fill).unwrap(), MAX_TOPICS - 3);
        assert_eq!(set.len(), MAX_TOPICS);
        assert!(matches!(
            set.extend(&[column(3), column(4)]),
            Err(GossipError::TooManyTopics {
                have: 418,
                adding: 2,
                max: 418
            })
        ));
        assert_eq!(set.len(), MAX_TOPICS);
        assert!(!set.contains(&column(3)));

        let mut c = config();
        c.topics = (0..=MAX_TOPICS as u64)
            .map(|i| GossipTopic::new((i as u32).to_be_bytes(), GossipKind::BeaconBlock))
            .collect();
        assert!(matches!(
            c.topic_set(),
            Err(GossipError::TooManyTopics { .. })
        ));
    }

    /// The filter and the transform read one set: a topic added to it is subscribable and
    /// decodes, through both, at once.
    #[test]
    fn the_filter_and_the_transform_share_the_topic_set() {
        use libp2p::gossipsub::TopicSubscriptionFilter as _;
        let c = config();
        let set = c.topic_set().unwrap();
        let mut filter = c.subscription_filter(&set);
        let transform = c.transform(&set);
        let column = "/eth2/00000000/data_column_sidecar_5/ssz_snappy";
        let data = SnappyTransform::new(c.caps)
            .outbound(column, b"col")
            .unwrap();
        assert!(!filter.can_subscribe(&TopicHash::from_raw(column)));
        assert!(transform
            .inbound_transform(raw(column, data.clone()))
            .is_err());
        set.extend(&[TopicHash::from_raw(column)]).unwrap();
        assert!(filter.can_subscribe(&TopicHash::from_raw(column)));
        assert_eq!(
            transform.inbound_transform(raw(column, data)).unwrap().data,
            b"col"
        );
    }

    /// The whitelist holds our topics and every column subnet of each of their fork digests,
    /// so a peer's announcement of a column subnet is kept before we subscribe it; the
    /// transform, over the subscribed set, still refuses those subnets before decompressing.
    #[test]
    fn the_whitelist_holds_every_column_subnet_of_each_fork_digest() {
        use libp2p::gossipsub::TopicSubscriptionFilter as _;
        let mut c = config();
        c.topics
            .push(GossipTopic::new([1; 4], GossipKind::BeaconBlock));
        let column = |digest: [u8; 4], subnet_id: u64| {
            topic_hash(&GossipTopic::new(
                digest,
                GossipKind::DataColumnSidecar { subnet_id },
            ))
        };
        let whitelist = c.whitelist().unwrap();
        assert_eq!(whitelist.len(), 2 + 2 * 128);
        let mut filter = c.subscription_filter(&whitelist);
        for digest in [[0; 4], [1; 4]] {
            for subnet_id in 0..128 {
                assert!(filter.can_subscribe(&column(digest, subnet_id)));
            }
        }
        assert!(filter.can_subscribe(&TopicHash::from_raw(BLOCK)));
        assert!(!filter.can_subscribe(&column([2; 4], 0)));
        assert!(!filter.can_subscribe(&TopicHash::from_raw(
            "/eth2/00000000/beacon_aggregate_and_proof/ssz_snappy"
        )));

        let transform = c.transform(&c.topic_set().unwrap());
        let mut bomb = Vec::new();
        p2p_wire::rpc::codec::encode_varint(u64::from(u32::MAX), &mut bomb);
        let err = transform
            .inbound_transform(raw(column([0; 4], 5).as_str(), bomb))
            .unwrap_err();
        assert_eq!(err.to_string(), "not a subscribed topic");
    }

    /// Column subnets already listed are not counted twice, and the whitelist holds to the
    /// topic bound: three digests' beacon_block and column subnets fit (3 × 129 = 387), four
    /// (516) do not.
    #[test]
    fn the_whitelist_is_bounded() {
        let digests = |n: u32| (0..n).map(u32::to_be_bytes);
        let mut c = config();
        c.topics = digests(2)
            .flat_map(|d| {
                std::iter::once(GossipTopic::new(d, GossipKind::BeaconBlock)).chain((0..128).map(
                    move |subnet_id| {
                        GossipTopic::new(d, GossipKind::DataColumnSidecar { subnet_id })
                    },
                ))
            })
            .collect();
        assert_eq!(c.whitelist().unwrap().len(), 2 * 129);

        c.topics = digests(3)
            .map(|d| GossipTopic::new(d, GossipKind::BeaconBlock))
            .collect();
        assert_eq!(c.whitelist().unwrap().len(), 3 * 129);
        c.topics = digests(4)
            .map(|d| GossipTopic::new(d, GossipKind::BeaconBlock))
            .collect();
        assert!(matches!(
            c.whitelist(),
            Err(GossipError::TooManyTopics { max: 418, .. })
        ));
    }

    #[test]
    fn a_zero_heartbeat_is_a_config_error() {
        let mut c = config();
        c.heartbeat_interval = Duration::ZERO;
        assert!(matches!(c.gossipsub(), Err(GossipError::ZeroHeartbeat)));
    }
}
