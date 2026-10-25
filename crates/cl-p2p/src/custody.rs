//! The custody column subnets: cl-chain's `WatchSubscriptions` body (`ethswarm.chain.v1`)
//! names the node's custody columns and the fork digests to join them under, and
//! [`subscribe`] joins exactly their `data_column_sidecar_{subnet_id}` topics on the ignore-all
//! gossipsub ([`IgnoreAll::subscribe`]), which reports IGNORE for their messages like for every
//! other topic.
//!
//! The body is checked before anything is subscribed ([`CustodySubscriptions::from_chain`]): at
//! most `NUMBER_OF_COLUMNS` columns, each below it and listed once, and at most
//! [`MAX_FORK_DIGESTS`] distinct 4-byte digests. The subnet of a column is
//! `compute_subnet_for_data_column_sidecar` (`fulu/p2p-interface.md`). The body's `attnets` and
//! `syncnets` are not custody and are not read here.

use crate::gossip::{GossipError, IgnoreAll};
use consensus_types::das::{compute_subnet_for_data_column_sidecar, NUMBER_OF_COLUMNS};
use ethswarm_proto::chain as pb;
use p2p_wire::gossip::{GossipKind, GossipTopic};
use p2p_wire::rpc::messages::ForkDigest;
use std::collections::BTreeSet;

/// Fork digests one body may name: the current one and each digest whose change comes within
/// cl-chain's lead (2 epochs), so two changes one epoch apart make three. The custody topics of
/// three digests (and the whitelist of their 3 × 128 column subnets) stay within the topic
/// bound ([`crate::gossip::config::MAX_TOPICS`]); the topic list goes under the first two only
/// ([`crate::gossip::TopicList::topics`]).
pub const MAX_FORK_DIGESTS: usize = 3;

/// Why a `WatchSubscriptions` body was refused: it breaks the contract, nothing is subscribed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    /// More columns than `NUMBER_OF_COLUMNS`.
    #[error("{0} custody columns, more than NUMBER_OF_COLUMNS ({NUMBER_OF_COLUMNS})")]
    TooManyColumns(usize),
    /// A column index not below `NUMBER_OF_COLUMNS`.
    #[error("custody column {0} is not below NUMBER_OF_COLUMNS ({NUMBER_OF_COLUMNS})")]
    ColumnOutOfRange(u64),
    /// A column listed twice.
    #[error("custody column {0} is listed twice")]
    DuplicateColumn(u64),
    /// No fork digest: nothing to join the subnets under.
    #[error("no fork digest")]
    NoForkDigest,
    /// More fork digests than [`MAX_FORK_DIGESTS`].
    #[error("{0} fork digests, more than {MAX_FORK_DIGESTS}")]
    TooManyForkDigests(usize),
    /// A fork digest that is not 4 bytes.
    #[error("fork digest of {0} bytes, want 4")]
    ForkDigestLen(usize),
    /// A fork digest listed twice.
    #[error("fork digest listed twice")]
    DuplicateForkDigest,
}

/// The custody columns and fork digests of one checked `WatchSubscriptions` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodySubscriptions {
    columns: BTreeSet<u64>,
    fork_digests: Vec<ForkDigest>,
}

impl CustodySubscriptions {
    /// Checks `body`; see the module docs.
    ///
    /// # Errors
    ///
    /// The first [`CustodyError`] found.
    pub fn from_chain(body: &pb::WatchSubscriptionsResponseBody) -> Result<Self, CustodyError> {
        if body.custody_columns.len() > NUMBER_OF_COLUMNS as usize {
            return Err(CustodyError::TooManyColumns(body.custody_columns.len()));
        }
        if body.fork_digests.is_empty() {
            return Err(CustodyError::NoForkDigest);
        }
        if body.fork_digests.len() > MAX_FORK_DIGESTS {
            return Err(CustodyError::TooManyForkDigests(body.fork_digests.len()));
        }
        let mut columns = BTreeSet::new();
        for &column in &body.custody_columns {
            if column >= NUMBER_OF_COLUMNS {
                return Err(CustodyError::ColumnOutOfRange(column));
            }
            if !columns.insert(column) {
                return Err(CustodyError::DuplicateColumn(column));
            }
        }
        let mut fork_digests = Vec::with_capacity(body.fork_digests.len());
        for digest in &body.fork_digests {
            let digest: ForkDigest = digest
                .as_slice()
                .try_into()
                .map_err(|_| CustodyError::ForkDigestLen(digest.len()))?;
            if fork_digests.contains(&digest) {
                return Err(CustodyError::DuplicateForkDigest);
            }
            fork_digests.push(digest);
        }
        Ok(Self {
            columns,
            fork_digests,
        })
    }

    /// The custody columns, in increasing order.
    pub fn columns(&self) -> impl Iterator<Item = u64> + '_ {
        self.columns.iter().copied()
    }

    /// The fork digests to join the subnets under: the current one, and the next one ahead of
    /// its change.
    pub fn fork_digests(&self) -> &[ForkDigest] {
        &self.fork_digests
    }

    /// The column subnets of the custody columns.
    pub fn subnets(&self) -> BTreeSet<u64> {
        self.columns()
            .map(compute_subnet_for_data_column_sidecar)
            .collect()
    }

    /// One `data_column_sidecar_{subnet_id}` topic per subnet and fork digest.
    pub fn topics(&self) -> Vec<GossipTopic> {
        let subnets = self.subnets();
        self.fork_digests
            .iter()
            .flat_map(|&digest| {
                subnets.iter().map(move |&subnet_id| {
                    GossipTopic::new(digest, GossipKind::DataColumnSidecar { subnet_id })
                })
            })
            .collect()
    }
}

/// Subscribes the topics of `subscriptions` on `gossip`; returns how many were new.
///
/// # Errors
///
/// As [`IgnoreAll::subscribe`]: nothing is subscribed past the topic bound.
pub fn subscribe(
    gossip: &mut IgnoreAll,
    subscriptions: &CustodySubscriptions,
) -> Result<usize, GossipError> {
    gossip.subscribe(&subscriptions.topics())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::GossipConfig;
    use consensus_types::caps::NetworkCaps;
    use consensus_types::das::custody_columns;
    use consensus_types::primitives::U256;
    use consensus_types::Mainnet;
    use libp2p::gossipsub::{DataTransform as _, RawMessage, TopicHash};
    use p2p_wire::gossip::{SnappyTransform, TopicCaps};
    use prometheus_client::registry::Registry;
    use std::time::Duration;

    /// A fixed discv5 node id (big-endian bytes).
    const NODE_ID: [u8; 32] = [
        0xb7, 0xa3, 0xc1, 0xd5, 0xe9, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
        0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
        0x89, 0x9a,
    ];
    /// Its four custody groups' columns, computed apart from this code base (Python, from the
    /// `get_custody_groups` pseudocode of `fulu/das-core.md`). One column per group, and each
    /// column is its own subnet.
    const CUSTODY_COLUMNS: [u64; 4] = [18, 47, 88, 114];
    const DIGEST: ForkDigest = [0xab, 0xcd, 0x00, 0x01];

    fn caps() -> TopicCaps {
        TopicCaps::gloas::<Mainnet>(&NetworkCaps::from_blob_schedule(21, &[]))
    }

    fn gossip() -> IgnoreAll {
        let cfg = GossipConfig::new(
            vec![GossipTopic::new(DIGEST, GossipKind::BeaconBlock)],
            caps(),
            Duration::from_secs(60),
        );
        IgnoreAll::new(&cfg, &mut Registry::default()).unwrap()
    }

    fn body(columns: Vec<u64>, digests: Vec<Vec<u8>>) -> pb::WatchSubscriptionsResponseBody {
        pb::WatchSubscriptionsResponseBody {
            attnets: vec![],
            syncnets: vec![],
            custody_columns: columns,
            fork_digests: digests,
        }
    }

    /// The column subnets gossipsub is subscribed to, per fork digest.
    fn subscribed_column_subnets(gossip: &IgnoreAll) -> BTreeSet<(ForkDigest, u64)> {
        gossip
            .gossipsub()
            .topics()
            .filter_map(|t| match GossipTopic::parse(t.as_str()).unwrap() {
                GossipTopic {
                    fork_digest,
                    kind: GossipKind::DataColumnSidecar { subnet_id },
                } => Some((fork_digest, subnet_id)),
                _ => None,
            })
            .collect()
    }

    /// The subscribed column subnets are exactly those of the node's four custody groups:
    /// any extra or missing subnet fails the equality.
    #[test]
    fn subscribes_exactly_the_custody_subnets() {
        let node_id = U256::from_be_bytes(NODE_ID);
        let columns = custody_columns(node_id, 4).unwrap();
        assert_eq!(columns, CUSTODY_COLUMNS);

        let mut gossip = gossip();
        let subs = CustodySubscriptions::from_chain(&body(columns, vec![DIGEST.to_vec()])).unwrap();
        assert_eq!(subscribe(&mut gossip, &subs).unwrap(), 4);

        let want: BTreeSet<(ForkDigest, u64)> =
            CUSTODY_COLUMNS.iter().map(|&c| (DIGEST, c)).collect();
        assert_eq!(subscribed_column_subnets(&gossip), want);
        // beacon_block stays; nothing else joined.
        assert_eq!(
            gossip.gossipsub().topics().count(),
            1 + CUSTODY_COLUMNS.len()
        );
        // Subscribing the same set again adds nothing.
        assert_eq!(subscribe(&mut gossip, &subs).unwrap(), 0);
        assert_eq!(subscribed_column_subnets(&gossip), want);
    }

    /// A custody subnet's messages decode; a column subnet outside custody is still refused.
    #[test]
    fn the_transform_learns_only_the_custody_subnets() {
        let cfg = GossipConfig::new(
            vec![GossipTopic::new(DIGEST, GossipKind::BeaconBlock)],
            caps(),
            Duration::from_secs(60),
        );
        let topics = cfg.topic_set().unwrap();
        let transform = cfg.transform(&topics);
        let subs = CustodySubscriptions::from_chain(&body(
            CUSTODY_COLUMNS.to_vec(),
            vec![DIGEST.to_vec()],
        ))
        .unwrap();
        let hashes: Vec<TopicHash> = subs
            .topics()
            .iter()
            .map(crate::gossip::config::topic_hash)
            .collect();
        topics.extend(&hashes).unwrap();
        let message = |subnet_id: u64| {
            let topic =
                GossipTopic::new(DIGEST, GossipKind::DataColumnSidecar { subnet_id }).to_string();
            let data = SnappyTransform::new(caps())
                .outbound(&topic, b"col")
                .unwrap();
            RawMessage {
                source: None,
                data,
                sequence_number: None,
                topic: TopicHash::from_raw(topic),
                signature: None,
                key: None,
                validated: false,
            }
        };
        assert_eq!(
            transform.inbound_transform(message(18)).unwrap().data,
            b"col"
        );
        assert!(transform.inbound_transform(message(19)).is_err());
    }

    #[test]
    fn two_digests_double_the_topics() {
        let subs = CustodySubscriptions::from_chain(&body(
            vec![3, 0],
            vec![vec![1, 1, 1, 1], vec![2, 2, 2, 2]],
        ))
        .unwrap();
        assert_eq!(subs.columns().collect::<Vec<_>>(), vec![0, 3]);
        assert_eq!(subs.subnets(), BTreeSet::from([0, 3]));
        assert_eq!(subs.topics().len(), 4);
        let no_columns = CustodySubscriptions::from_chain(&body(vec![], vec![vec![1; 4]])).unwrap();
        assert!(no_columns.topics().is_empty());
        // The current digest and two changes within cl-chain's lead: three digests.
        let three = CustodySubscriptions::from_chain(&body(
            vec![3],
            vec![vec![1; 4], vec![2; 4], vec![3; 4]],
        ))
        .unwrap();
        assert_eq!(three.fork_digests().len(), 3);
        assert_eq!(three.topics().len(), 3);
    }

    #[test]
    fn contract_breaking_bodies_are_refused() {
        let d = || vec![DIGEST.to_vec()];
        for (b, want) in [
            (
                body((0..129).collect(), d()),
                CustodyError::TooManyColumns(129),
            ),
            (body(vec![128], d()), CustodyError::ColumnOutOfRange(128)),
            (body(vec![5, 5], d()), CustodyError::DuplicateColumn(5)),
            (
                body(
                    vec![1],
                    vec![vec![1; 4], vec![2; 4], vec![3; 4], vec![4; 4]],
                ),
                CustodyError::TooManyForkDigests(4),
            ),
            (
                body(vec![1], vec![vec![1; 5]]),
                CustodyError::ForkDigestLen(5),
            ),
            (
                body(vec![1], vec![vec![1; 4], vec![1; 4]]),
                CustodyError::DuplicateForkDigest,
            ),
            (body(vec![1], Vec::new()), CustodyError::NoForkDigest),
        ] {
            assert_eq!(CustodySubscriptions::from_chain(&b), Err(want));
        }
    }

    /// A retired fork digest leaves gossipsub, the subscribed set and the whitelist, its
    /// whitelisted column subnets too; the other digests stay, and the freed room takes the
    /// topics of a new digest.
    #[test]
    fn a_retired_digest_leaves_gossip() {
        let mut gossip = gossip();
        let next: ForkDigest = [0x11; 4];
        let subs = CustodySubscriptions::from_chain(&body(
            CUSTODY_COLUMNS.to_vec(),
            vec![DIGEST.to_vec(), next.to_vec()],
        ))
        .unwrap();
        assert_eq!(subscribe(&mut gossip, &subs).unwrap(), 8);
        let whitelisted = gossip.whitelist_len();
        // beacon_block and every column subnet of the start digest, then the next digest's four.
        assert_eq!(whitelisted, 1 + 128 + 4);
        assert_eq!(gossip.retire_digest(DIGEST), 1 + 4);
        let want: BTreeSet<(ForkDigest, u64)> =
            CUSTODY_COLUMNS.iter().map(|&c| (next, c)).collect();
        assert_eq!(subscribed_column_subnets(&gossip), want);
        assert_eq!(gossip.gossipsub().topics().count(), 4);
        assert_eq!(gossip.whitelist_len(), 4);
        assert_eq!(gossip.subscribed_len(), 4);
        assert_eq!(gossip.retire_digest(DIGEST), 0, "retired already");
        // The freed room: 414 topics of new digests fit again.
        let many: Vec<GossipTopic> = (0..(crate::gossip::config::MAX_TOPICS - 4) as u32)
            .map(|i| GossipTopic::new((i + 7).to_be_bytes(), GossipKind::BeaconBlock))
            .collect();
        assert_eq!(gossip.subscribe(&many).unwrap(), many.len());
    }

    /// Past the topic bound nothing is subscribed, and the set stays as it was. The bound is
    /// the whitelist's: `beacon_block` and the 128 column subnets of its fork digest.
    #[test]
    fn subscriptions_past_the_topic_bound_are_refused_whole() {
        let mut gossip = gossip();
        let many: Vec<GossipTopic> = (0..crate::gossip::config::MAX_TOPICS as u32)
            .map(|i| {
                GossipTopic::new(
                    i.to_be_bytes(),
                    GossipKind::DataColumnSidecar { subnet_id: 1 },
                )
            })
            .collect();
        assert!(matches!(
            gossip.subscribe(&many),
            Err(GossipError::TooManyTopics {
                have: 129,
                adding: 418,
                max: 418
            })
        ));
        assert_eq!(gossip.gossipsub().topics().count(), 1);
    }
}
