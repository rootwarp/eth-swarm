//! [`TopicList`]: the probe's configured gossip topics, a TOML file of topic names
//! (`ops/probe/gossip-topics.toml`), so capture topics and custody column subnets are added
//! without code.
//!
//! ```toml
//! topics = ["beacon_block", "execution_payload", "data_column_sidecar_3"]
//! ```
//!
//! Each name goes through [`GossipTopic::parse`] as `/eth2/<digest>/<name>/ssz_snappy`: a name
//! `p2p-wire` does not handle, or a subnet id that is not canonical and in range, refuses the
//! whole file, and so does a name listed twice. The probe subscribes every name under each fork
//! digest it follows ([`TopicList::topics`]) and reports IGNORE for every message
//! ([`super::IgnoreAll`]).
//!
//! The bounds of [`super::config`] hold for any list: a name is a Gloas topic name, so at most
//! [`MAX_TOPIC_NAME_LEN`](super::config::MAX_TOPIC_NAME_LEN) long, and a list holds at most [`TOPICS_PER_FORK_DIGEST`] names, so
//! two fork digests' worth fits
//! [`MAX_SUBSCRIPTIONS_PER_REQUEST`](super::config::MAX_SUBSCRIPTIONS_PER_REQUEST); [`TopicList::parse`] checks
//! both. [`TopicList::byte_budget`] is what one message of each topic may hold once
//! decompressed, from [`TopicCaps`].

use super::config::TOPICS_PER_FORK_DIGEST;
use p2p_wire::gossip::{GossipKind, GossipTopic, TopicCaps};
use p2p_wire::rpc::messages::ForkDigest;
use serde::Deserialize;

/// The fork digests the probe follows at most at once: the current fork's and the next one's
/// (a node joins the next fork's topics ahead of it).
pub const MAX_FORK_DIGESTS: usize = 2;

/// Why a topic list was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopicListError {
    /// Not TOML of `topics = [...]` alone.
    #[error("topic list: {0}")]
    Format(String),
    /// A name [`GossipTopic::parse`] refuses.
    #[error("topic list: {name:?}: {reason}")]
    Name {
        /// The name.
        name: String,
        /// The parse error.
        reason: String,
    },
    /// A name listed twice.
    #[error("topic list: {0:?} is listed twice")]
    Duplicate(String),
    /// No name, or more than [`TOPICS_PER_FORK_DIGEST`].
    #[error("topic list: want 1 to {TOPICS_PER_FORK_DIGEST} topics, got {0}")]
    Count(usize),
}

/// A checked topic list: topic kinds in the file's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicList {
    kinds: Vec<GossipKind>,
}

/// What one message of each configured topic may hold, decompressed (the transform refuses
/// more before decompressing): see [`TopicList::byte_budget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteBudget {
    /// Each topic's cap, in the list's order.
    pub per_topic: Vec<(GossipKind, usize)>,
    /// The largest: what one capture-tap entry may hold.
    pub largest: usize,
    /// Their sum: one message of every topic.
    pub one_of_each: usize,
}

impl TopicList {
    /// Parses and checks `text` (see the module docs).
    pub fn parse(text: &str) -> Result<Self, TopicListError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct File {
            topics: Vec<String>,
        }
        let file: File =
            toml::from_str(text).map_err(|e| TopicListError::Format(e.message().to_owned()))?;
        if file.topics.is_empty() || file.topics.len() > TOPICS_PER_FORK_DIGEST {
            return Err(TopicListError::Count(file.topics.len()));
        }
        let mut kinds = Vec::with_capacity(file.topics.len());
        for name in &file.topics {
            let topic =
                GossipTopic::parse(&format!("/eth2/00000000/{name}/ssz_snappy")).map_err(|e| {
                    TopicListError::Name {
                        name: name.clone(),
                        reason: e.to_string(),
                    }
                })?;
            if kinds.contains(&topic.kind) {
                return Err(TopicListError::Duplicate(name.clone()));
            }
            kinds.push(topic.kind);
        }
        Ok(Self { kinds })
    }

    /// The topic kinds, in the file's order.
    pub fn kinds(&self) -> &[GossipKind] {
        &self.kinds
    }

    /// Every topic under each of `fork_digests` (at most [`MAX_FORK_DIGESTS`] are used, so the
    /// subscriptions fit [`MAX_SUBSCRIPTIONS_PER_REQUEST`](super::config::MAX_SUBSCRIPTIONS_PER_REQUEST)).
    pub fn topics(&self, fork_digests: &[ForkDigest]) -> Vec<GossipTopic> {
        let digests = &fork_digests[..fork_digests.len().min(MAX_FORK_DIGESTS)];
        digests
            .iter()
            .flat_map(|d| self.kinds.iter().map(|k| GossipTopic::new(*d, *k)))
            .collect()
    }

    /// Each topic's decompressed cap under `caps`, the largest and their sum.
    pub fn byte_budget(&self, caps: &TopicCaps) -> ByteBudget {
        let per_topic: Vec<(GossipKind, usize)> =
            self.kinds.iter().map(|k| (*k, caps.cap(*k))).collect();
        ByteBudget {
            largest: per_topic.iter().map(|(_, c)| *c).max().unwrap_or(0),
            one_of_each: per_topic.iter().map(|(_, c)| *c).sum(),
            per_topic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::{
        seen_ttl, GossipConfig, MAX_SUBSCRIPTIONS_PER_REQUEST, MAX_TOPICS, MAX_TOPIC_LEN,
        SUBSCRIBED_TOPICS_HEADROOM,
    };
    use super::*;
    use consensus_types::caps::NetworkCaps;
    use consensus_types::Mainnet;
    use libp2p::gossipsub::{TopicHash, TopicSubscriptionFilter as _};
    use network_config::{ChainConfig, Network};

    /// The probe's configured topic list, as shipped.
    const SHIPPED: &str = include_str!("../../../../ops/probe/gossip-topics.toml");

    fn sepolia_caps() -> TopicCaps {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        TopicCaps::gloas::<Mainnet>(&NetworkCaps::from_config(&config))
    }

    /// The shipped list holds the exit-14 topics, every name loads through
    /// `GossipTopic::parse`, and under two fork digests the whitelist, the 418-per-RPC cap and
    /// the control-message bound still hold.
    #[test]
    fn the_shipped_probe_topics_load_and_fit_the_bounds() {
        let list = TopicList::parse(SHIPPED).unwrap();
        for kind in [
            GossipKind::BeaconBlock,
            GossipKind::ExecutionPayloadBid,
            GossipKind::ExecutionPayload,
            GossipKind::PayloadAttestationMessage,
            GossipKind::BeaconAggregateAndProof,
        ] {
            assert!(list.kinds().contains(&kind), "{kind}");
        }
        let attestations = list
            .kinds()
            .iter()
            .filter(|k| matches!(k, GossipKind::BeaconAttestation { .. }))
            .count();
        let columns = list
            .kinds()
            .iter()
            .filter(|k| matches!(k, GossipKind::DataColumnSidecar { .. }))
            .count();
        assert_eq!((attestations, columns), (2, 4));

        // Fulu's and Gloas's digests at once, as around a fork.
        let digests = [[0xaa, 0xbb, 0xcc, 0x01], [0xaa, 0xbb, 0xcc, 0x02]];
        let topics = list.topics(&digests);
        assert_eq!(topics.len(), 2 * list.kinds().len());
        assert!(topics.len() <= MAX_SUBSCRIPTIONS_PER_REQUEST);
        assert!(topics.iter().all(|t| t.to_string().len() <= MAX_TOPIC_LEN));
        let config = GossipConfig::new(topics.clone(), sepolia_caps(), seen_ttl(12_000, 32));
        let set = config.topic_set().unwrap();
        assert_eq!(set.len(), topics.len());
        assert!(set.len() <= MAX_TOPICS);
        let mut filter = config.subscription_filter(&set);
        assert_eq!(filter.max_subscriptions_per_request, 418);
        assert_eq!(
            filter.max_subscribed_topics,
            MAX_TOPICS + SUBSCRIBED_TOPICS_HEADROOM
        );
        for topic in &topics {
            let hash = TopicHash::from_raw(topic.to_string());
            assert!(filter.can_subscribe(&hash), "{topic}");
        }
        for other in [
            "/eth2/aabbcc01/voluntary_exit/ssz_snappy",
            "/eth2/aabbcc01/beacon_attestation_63/ssz_snappy",
            "/eth2/aabbcc03/beacon_block/ssz_snappy",
        ] {
            assert!(
                !filter.can_subscribe(&TopicHash::from_raw(other)),
                "{other}"
            );
        }
        // gossipsub takes the configuration: the control-message bound is unchanged.
        let built = config.gossipsub().unwrap();
        assert_eq!(built.max_control_message_size(), 46_898);
        // Only two digests are ever used.
        let three = list.topics(&[digests[0], digests[1], [0; 4]]);
        assert_eq!(three, topics);
    }

    /// The byte budget of the shipped list on Sepolia (21 blobs at most), as its comments
    /// record it.
    #[test]
    fn the_shipped_probe_topics_byte_budget_is_recorded() {
        let budget = TopicList::parse(SHIPPED)
            .unwrap()
            .byte_budget(&sepolia_caps());
        let caps = sepolia_caps();
        assert_eq!(budget.per_topic.len(), 11);
        assert_eq!(
            budget.largest,
            caps.cap(GossipKind::BeaconBlock)
                .max(caps.cap(GossipKind::ExecutionPayload))
        );
        for (kind, cap) in &budget.per_topic {
            assert_eq!(*cap, caps.cap(*kind), "{kind}");
            let name = match kind {
                GossipKind::BeaconAttestation { .. } => "beacon_attestation_{subnet_id}".into(),
                GossipKind::DataColumnSidecar { .. } => "data_column_sidecar_{subnet_id}".into(),
                other => other.to_string(),
            };
            let line = format!("#   {name}: {cap} bytes");
            assert!(SHIPPED.contains(&line), "the file does not record {line:?}");
        }
        for line in [
            format!("# largest message: {} bytes", budget.largest),
            format!("# one message of every topic: {} bytes", budget.one_of_each),
        ] {
            assert!(SHIPPED.contains(&line), "the file does not record {line:?}");
        }
    }

    #[test]
    fn a_list_is_refused_whole() {
        for (text, want) in [
            ("topics = [\"voluntary_exit\"]", "unknown topic name"),
            ("topics = [\"beacon_attestation_64\"]", "bad subnet id"),
            ("topics = [\"data_column_sidecar_01\"]", "bad subnet id"),
            ("topics = [\"beacon_block/x\"]", "not an eth2 topic"),
            (
                "topics = [\"beacon_block\", \"beacon_block\"]",
                "listed twice",
            ),
            ("topics = []", "want 1 to 209 topics, got 0"),
            ("topics = [\"beacon_block\"]\nextra = 1", "unknown field"),
            ("topic = [\"beacon_block\"]", "unknown field"),
        ] {
            let err = TopicList::parse(text).unwrap_err().to_string();
            assert!(err.contains(want), "{text}: {err} (want {want})");
        }
        let many: Vec<String> = (0..64)
            .map(|i| format!("\"beacon_attestation_{i}\""))
            .chain((0..128).map(|i| format!("\"data_column_sidecar_{i}\"")))
            .chain(
                [
                    "beacon_block",
                    "beacon_aggregate_and_proof",
                    "execution_payload_bid",
                    "execution_payload",
                    "payload_attestation_message",
                ]
                .map(|n| format!("\"{n}\"")),
            )
            .collect();
        // Every topic p2p-wire handles: 197, within one digest's 209.
        let all = TopicList::parse(&format!("topics = [{}]", many.join(","))).unwrap();
        assert_eq!(all.kinds().len(), 197);
        assert_eq!(all.byte_budget(&sepolia_caps()).per_topic.len(), 197);
        let budget = TopicList { kinds: vec![] }.byte_budget(&sepolia_caps());
        assert_eq!((budget.largest, budget.one_of_each), (0, 0));
    }
}
