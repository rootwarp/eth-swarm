//! `gossip_transform` and `message_id`: a gossip message as the probe's gossipsub receives it.
//!
//! Both read the input as [`split_message`] does: a topic-length byte, that many bytes of topic
//! (UTF-8, as gossipsub's protobuf `string` field is; other bytes never reach the transform, so
//! the input is skipped) and the message `data`.
//!
//! - `gossip_transform` runs the transform gossipsub calls, `WireTransform::inbound_transform`
//!   (`cl_p2p::gossip`), subscribed to `beacon_block` under the fixture digests, and the
//!   `SnappyTransform::inbound` (`p2p_wire::gossip`) it wraps on the same topic: the wrapper
//!   accepts exactly the subscribed topics the inner transform accepts, with the same bytes (a
//!   topic the subscription filter whitelists but we have not subscribed, a column subnet, is
//!   refused before its data is read, as `IgnoreAll::new` builds the transform). An
//!   accepted message is at most its topic's cap, its compressed data at most
//!   `max_compressed_len(MAX_PAYLOAD_SIZE)`, and it decompresses to the length its snappy header
//!   declares. A `beacon_block` message then goes to the bounded Gloas `SignedBeaconBlock` decode
//!   (`consensus_types::codec::decode_for`), and a block it accepts re-encodes to those bytes.
//! - `message_id` holds `compute_message_id` to the spec's rule, written out here on its own, and
//!   to the id gossipsub's `message_id_fn` (`cl_p2p::gossip::config::message_id`) gives the
//!   message the transform accepted.
//!
//! The caps are the production ones: `TopicCaps::gloas` of the mainnet preset on the pinned
//! Sepolia config's blob schedule (computed once; no network-config code runs on the input).

use crate::E;
use cl_p2p::gossip::config::{message_id as gossipsub_message_id, seen_ttl};
use cl_p2p::gossip::{GossipConfig, WireTransform};
use consensus_types::caps::{NetworkCaps, ObjectKind, MAX_PAYLOAD_SIZE};
use consensus_types::codec::{decode_for, Object};
use consensus_types::ForkName;
use libp2p::gossipsub::{DataTransform, RawMessage, TopicHash};
use network_config::{ChainConfig, Network};
use p2p_wire::gossip::message_id::MESSAGE_ID_LEN;
use p2p_wire::gossip::{
    compute_message_id, GossipKind, GossipTopic, MessageId, SnappyTransform, TopicCaps,
};
use p2p_wire::rpc::codec::max_compressed_len;
use p2p_wire::testkit::{FULU_BPO_DIGEST, FULU_DIGEST, GLOAS_DIGEST};
use sha2::{Digest, Sha256};
use ssz::Encode;
use std::sync::OnceLock;

/// The probe's gossip setup: the network caps, the subscribed topics, and both transforms.
struct Gossip {
    network: NetworkCaps,
    /// The subscribed topics: the set the transform reads.
    topics: Vec<String>,
    /// The subscription filter's whitelist, a superset (every column subnet of the digests).
    #[cfg(test)]
    whitelist: cl_p2p::gossip::TopicSet,
    wire: WireTransform,
    snappy: SnappyTransform,
}

fn gossip() -> &'static Gossip {
    static GOSSIP: OnceLock<Gossip> = OnceLock::new();
    GOSSIP.get_or_init(|| {
        let config = ChainConfig::load(Network::Sepolia).expect("the pinned Sepolia config");
        let network = NetworkCaps::from_config(&config);
        let caps = TopicCaps::gloas::<E>(&network);
        let topics: Vec<GossipTopic> = [FULU_DIGEST, FULU_BPO_DIGEST, GLOAS_DIGEST]
            .into_iter()
            .map(|digest| GossipTopic::new(digest, GossipKind::BeaconBlock))
            .collect();
        let profile = GossipConfig::new(topics.clone(), caps, seen_ttl(12_000, 32));
        // As `IgnoreAll::new` builds it: the transform over the subscribed set, not the
        // whitelist the subscription filter reads.
        let subscribed = profile.topic_set().expect("three topics");
        Gossip {
            network,
            topics: topics.iter().map(ToString::to_string).collect(),
            #[cfg(test)]
            whitelist: profile.whitelist().expect("within MAX_TOPICS"),
            wire: profile.transform(&subscribed),
            snappy: SnappyTransform::new(caps),
        }
    })
}

/// The caps the gossip targets hold messages to.
pub fn topic_caps() -> TopicCaps {
    *gossip().snappy.caps()
}

/// The input of the gossip targets: `topic`'s length (at most 255 bytes), `topic`, then `data`.
pub fn message_input(topic: &str, data: &[u8]) -> Vec<u8> {
    let len = u8::try_from(topic.len()).expect("a topic of at most 255 bytes");
    [&[len][..], topic.as_bytes(), data].concat()
}

/// The topic and data of a gossip target's input; `None` if it is cut short or the topic is not
/// UTF-8.
pub fn split_message(input: &[u8]) -> Option<(&str, &[u8])> {
    let (&len, rest) = input.split_first()?;
    let len = usize::from(len);
    if rest.len() < len {
        return None;
    }
    let (topic, data) = rest.split_at(len);
    Some((std::str::from_utf8(topic).ok()?, data))
}

/// A message as gossipsub hands it to the transform: no source, sequence number or signature
/// (the probe's StrictNoSign profile refuses them before the transform).
fn raw(topic: &str, data: &[u8]) -> RawMessage {
    RawMessage {
        source: None,
        data: data.to_vec(),
        sequence_number: None,
        topic: TopicHash::from_raw(topic),
        signature: None,
        key: None,
        validated: false,
    }
}

/// `gossip_transform`: see the module docs.
pub fn gossip_transform(input: &[u8]) {
    let Some((topic, data)) = split_message(input) else {
        return;
    };
    let g = gossip();
    let inner = g.snappy.inbound(topic, data);
    if let Ok(ssz) = &inner {
        let kind = GossipTopic::parse(topic)
            .expect("an accepted message's topic parses")
            .kind;
        let cap = g.snappy.caps().cap(kind);
        assert!(
            cap <= MAX_PAYLOAD_SIZE,
            "{kind:?}: a cap over MAX_PAYLOAD_SIZE"
        );
        assert!(
            ssz.len() <= cap,
            "{} bytes accepted under a {cap}-byte cap",
            ssz.len()
        );
        assert!(
            data.len() <= max_compressed_len(MAX_PAYLOAD_SIZE),
            "{} compressed bytes accepted",
            data.len()
        );
        assert_eq!(
            snap::raw::decompress_len(data).ok(),
            Some(ssz.len()),
            "decompressed to another length than the header declares"
        );
        if kind == GossipKind::BeaconBlock {
            gloas_block(&g.network, ssz);
        }
    }
    let subscribed = g.topics.iter().any(|t| t == topic);
    match g.wire.inbound_transform(raw(topic, data)) {
        Ok(message) => {
            assert!(
                subscribed,
                "a message on an unsubscribed topic passed the transform"
            );
            assert_eq!(
                message.topic.as_str(),
                topic,
                "the transform changed the topic"
            );
            assert!(
                inner.as_ref().ok() == Some(&message.data),
                "the transform and the snappy transform disagree"
            );
        }
        Err(_) => assert!(
            !subscribed || inner.is_err(),
            "the transform refused a subscribed message the snappy transform accepts"
        ),
    }
}

/// The Gloas `SignedBeaconBlock` decode of a `beacon_block` message, bounded by its cap.
fn gloas_block(network: &NetworkCaps, ssz: &[u8]) {
    match decode_for::<E>(ObjectKind::SignedBeaconBlock, ForkName::Gloas, network, ssz) {
        Ok(Object::SignedBeaconBlock(block)) => {
            assert_eq!(
                block.fork_name(),
                ForkName::Gloas,
                "a Gloas decode of another fork"
            );
            assert!(
                block.as_ssz_bytes() == ssz,
                "the block re-encodes to other bytes"
            );
        }
        Ok(other) => panic!("a SignedBeaconBlock decode returned {:?}", other.kind()),
        Err(_) => {}
    }
}

/// `MESSAGE_DOMAIN_VALID_SNAPPY` (`phase0` constants).
const DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
/// `MESSAGE_DOMAIN_INVALID_SNAPPY` (`phase0` constants).
const DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// The message-id rule of `altair/p2p-interface.md` ("Topics and messages"):
/// `SHA256(domain + uint_to_bytes(uint64(len(topic))) + topic + payload)[:20]`, with the valid
/// domain and the decompressed data if `data` has a valid snappy decompression, else the invalid
/// domain and `data`. The node bounds "valid": at most `max_compressed_len(MAX_PAYLOAD_SIZE)`
/// compressed bytes declaring at most `MAX_PAYLOAD_SIZE`, checked before decompressing.
fn spec_message_id(topic: &str, data: &[u8]) -> MessageId {
    let decompressed = (data.len() <= max_compressed_len(MAX_PAYLOAD_SIZE))
        .then(|| snap::raw::decompress_len(data).ok())
        .flatten()
        .filter(|&n| n <= MAX_PAYLOAD_SIZE)
        .and_then(|_| snap::raw::Decoder::new().decompress_vec(data).ok());
    let (domain, payload) = match &decompressed {
        Some(d) => (DOMAIN_VALID_SNAPPY, d.as_slice()),
        None => (DOMAIN_INVALID_SNAPPY, data),
    };
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update((topic.len() as u64).to_le_bytes())
        .chain_update(topic.as_bytes())
        .chain_update(payload)
        .finalize();
    let mut id = MessageId::default();
    id.copy_from_slice(&digest[..MESSAGE_ID_LEN]);
    id
}

/// `message_id`: see the module docs.
pub fn message_id(input: &[u8]) {
    let Some((topic, data)) = split_message(input) else {
        return;
    };
    let id = compute_message_id(topic, data);
    assert_eq!(
        id,
        spec_message_id(topic, data),
        "the message-id breaks the spec rule"
    );
    if let Ok(message) = gossip().wire.inbound_transform(raw(topic, data)) {
        assert_eq!(
            gossipsub_message_id(&message).0,
            id.to_vec(),
            "gossipsub's message-id differs from compute_message_id"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subscribed_digests_are_the_fixture_table() {
        for digest in [FULU_DIGEST, FULU_BPO_DIGEST, GLOAS_DIGEST] {
            assert!(crate::contexts().fork(&digest).is_some());
        }
        assert_eq!(gossip().topics.len(), 3);
    }

    /// The production whitelist holds every column subnet of the subscribed digests, but the
    /// transform reads the subscribed set: a whitelisted, unsubscribed column topic is refused
    /// before its data is read, even with a header declaring 4 GiB.
    #[test]
    fn whitelisted_unsubscribed_topics_are_refused_before_decompression() {
        let g = gossip();
        let column = GossipTopic::new(GLOAS_DIGEST, GossipKind::DataColumnSidecar { subnet_id: 5 });
        let hash = TopicHash::from_raw(column.to_string());
        assert!(
            g.whitelist.contains(&hash),
            "the column subnet is whitelisted"
        );
        assert!(
            !g.topics.contains(&column.to_string()),
            "but not subscribed"
        );
        let mut bomb = Vec::new();
        p2p_wire::rpc::codec::encode_varint(u64::from(u32::MAX), &mut bomb);
        let err = g
            .wire
            .inbound_transform(raw(&column.to_string(), &bomb))
            .unwrap_err();
        assert_eq!(err.to_string(), "not a subscribed topic");
        // The same topic subscribed would reach the snappy header check.
        assert!(matches!(
            g.snappy.inbound(&column.to_string(), &bomb),
            Err(p2p_wire::gossip::TransformError::DeclaredTooLarge { .. })
        ));
        gossip_transform(&message_input(&column.to_string(), &bomb));
    }

    #[test]
    fn the_input_splits_into_topic_and_data() {
        let input = message_input("/t", b"data");
        assert_eq!(split_message(&input), Some(("/t", &b"data"[..])));
        assert_eq!(split_message(&[5, b'a']), None);
        assert_eq!(split_message(&[2, 0xff, 0xfe]), None);
        assert_eq!(split_message(&[]), None);
    }
}
