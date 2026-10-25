#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::gossip::config::digest_of;
use crate::gossip::GossipConfig;
use cl_chain::probe::service::{ProbeNetwork, Subscriptions};
use consensus_types::caps::NetworkCaps;
use consensus_types::das::{custody_columns, CUSTODY_REQUIREMENT, NUMBER_OF_CUSTODY_GROUPS};
use consensus_types::primitives::U256;
use consensus_types::Mainnet;
use ethswarm_proto::chain as pb;
use ipc::testkit::devnet::{devnet_config_with, DEVNET_GENESIS, DEVNET_SLOT_MS};
use p2p_wire::gossip::TopicCaps;
use prometheus_client::registry::Registry;
use std::collections::BTreeSet;

/// The probe's configured topic list, as shipped.
const SHIPPED: &str = include_str!("../../../../../ops/probe/gossip-topics.toml");

/// One epoch of the fixture devnet (8 slots of 6 s): the grace.
const EPOCH: Duration = Duration::from_millis(DEVNET_SLOT_MS * 8);

/// The fixture devnet with digest changes at epochs 1 (BPO), 2 (Gloas), 4 and 5 (two BPOs one
/// epoch apart, so a body names three digests) and 8 (BPO).
fn network() -> ProbeNetwork {
    let from = "BLOB_SCHEDULE:\n  - EPOCH: 1\n    MAX_BLOBS_PER_BLOCK: 12\n";
    let to = format!(
        "{from}  - EPOCH: 4\n    MAX_BLOBS_PER_BLOCK: 15\n  - EPOCH: 5\n    \
         MAX_BLOBS_PER_BLOCK: 18\n  - EPOCH: 8\n    MAX_BLOBS_PER_BLOCK: 21\n"
    );
    ProbeNetwork::new("cl-p2p/test", devnet_config_with(from, &to), DEVNET_GENESIS).unwrap()
}

fn caps() -> TopicCaps {
    TopicCaps::gloas::<Mainnet>(&NetworkCaps::from_blob_schedule(21, &[]))
}

/// A topic list of `beacon_block` and the 64 attestation subnets: 65 topics a digest, so the
/// topics of a supernode's three digests do not fit together.
fn big_list() -> String {
    let names: Vec<String> = std::iter::once("\"beacon_block\"".to_owned())
        .chain((0..64).map(|i| format!("\"beacon_attestation_{i}\"")))
        .collect();
    format!("topics = [{}]\n", names.join(", "))
}

/// cl-chain's subscriptions on the fixture schedule, followed on a real ignore-all gossipsub.
struct Run {
    net: ProbeNetwork,
    subs: Subscriptions,
    gossip: IgnoreAll,
    digests: DigestTopics,
    t0: Instant,
}

impl Run {
    /// The swarm's start at epoch 0 with `list`, for `groups` custody groups.
    fn start(list: &str, groups: u64) -> Self {
        let net = network();
        let columns = custody_columns(U256::from(7u64), groups).unwrap();
        let subs = Subscriptions::new(&net, columns);
        let first = body_of(&subs.body_at(net.epoch_start_ms(0) + 1).unwrap());
        let mut digests = DigestTopics::new(TopicList::parse(list).unwrap(), EPOCH, first);
        let cfg = GossipConfig::new(digests.start_topics(), caps(), Duration::from_secs(60));
        let gossip = IgnoreAll::new(&cfg, &mut Registry::default()).unwrap();
        Self {
            net,
            subs,
            gossip,
            digests,
            t0: Instant::now(),
        }
    }

    /// cl-chain's body of `epoch`, then a follow at its start and one half an epoch later (a
    /// dial tick); checks each and returns both.
    fn epoch(&mut self, epoch: u64) -> [Followed; 2] {
        let body = body_of(
            &self
                .subs
                .body_at(self.net.epoch_start_ms(epoch) + 1)
                .unwrap(),
        );
        self.digests.set_body(body.clone());
        let at = self.t0 + EPOCH * epoch as u32;
        let first = self.digests.follow(&mut self.gossip, at).unwrap();
        self.check(&body, &first);
        let tick = self
            .digests
            .follow(&mut self.gossip, at + EPOCH / 2)
            .unwrap();
        self.check(&body, &tick);
        [first, tick]
    }

    /// The bound holds; every named digest that did not wait has all its topics; gossipsub and
    /// the subscribed set hold the same topics, all of tracked digests.
    fn check(&self, body: &CustodySubscriptions, followed: &Followed) {
        assert!(self.gossip.whitelist_len() <= MAX_TOPICS, "{followed:?}");
        let subscribed: BTreeSet<String> = self
            .gossip
            .gossipsub()
            .topics()
            .map(|t| t.as_str().to_owned())
            .collect();
        for (index, digest) in body.fork_digests().iter().enumerate() {
            if followed.deferred.contains(digest) {
                assert!(index >= 2, "only a third digest waits: {followed:?}");
                continue;
            }
            for topic in self.digests.topics_under(*digest, index) {
                assert!(subscribed.contains(&topic.to_string()), "{topic}");
            }
        }
        let tracked: Vec<ForkDigest> = self.digests.subscribed().collect();
        for topic in self.gossip.gossipsub().topics() {
            assert!(tracked.contains(&digest_of(topic).unwrap()), "{topic}");
        }
        assert_eq!(self.gossip.subscribed_len(), subscribed.len());
    }

    fn digest(&self, epoch: u64) -> ForkDigest {
        self.net.digest_at(epoch).unwrap()
    }

    fn tracked(&self) -> BTreeSet<ForkDigest> {
        self.digests.subscribed().collect()
    }
}

fn body_of(body: &pb::WatchSubscriptionsResponseBody) -> CustodySubscriptions {
    CustodySubscriptions::from_chain(body).unwrap()
}

/// Across five digest changes (three named in one body twice), the topics of each superseded
/// digest stay for one epoch and then leave, and the set stays within its bound: with the
/// shipped list, for `CUSTODY_REQUIREMENT` groups and for a supernode's 128.
#[test]
fn superseded_digests_retire_after_their_grace() {
    for groups in [CUSTODY_REQUIREMENT, NUMBER_OF_CUSTODY_GROUPS] {
        let mut run = Run::start(SHIPPED, groups);
        let d: Vec<ForkDigest> = [0, 1, 2, 4, 5, 8].map(|e| run.digest(e)).to_vec();
        assert_eq!(d.iter().collect::<BTreeSet<_>>().len(), 6, "five changes");
        let mut retired = Vec::new();
        let mut most = 0;
        for epoch in 0..=9 {
            for followed in run.epoch(epoch) {
                assert!(followed.deferred.is_empty(), "{groups}: {followed:?}");
                retired.extend(followed.retired);
            }
            most = most.max(run.gossip.whitelist_len());
            let want: BTreeSet<ForkDigest> = match epoch {
                // The current digest and the two changes within cl-chain's lead.
                0 => [d[0], d[1], d[2]].into(),
                // d0 in its grace.
                1 => [d[0], d[1], d[2]].into(),
                2 => [d[1], d[2], d[3]].into(),
                3 => [d[2], d[3], d[4]].into(),
                4 => [d[2], d[3], d[4]].into(),
                5 => [d[3], d[4]].into(),
                6 | 7 => [d[4], d[5]].into(),
                8 => [d[4], d[5]].into(),
                _ => [d[5]].into(),
            };
            assert_eq!(run.tracked(), want, "{groups} groups, epoch {epoch}");
        }
        // Each superseded digest retired once, in order, one epoch after its change.
        assert_eq!(retired, d[..5], "{groups} groups");
        // Three digests of 135 topics at most: the shipped list's 7 topics and the 128
        // column subnets each.
        assert!(most <= 3 * 135, "{groups} groups: {most}");
    }
}

/// A topic list too big for a supernode's three digests: the third waits until a retiring
/// digest makes room, the retiring digests go before their grace ends when a named digest
/// needs the room, and the current digest always has all its topics.
#[test]
fn the_named_digests_take_the_room_of_the_retiring_ones() {
    let mut run = Run::start(&big_list(), NUMBER_OF_CUSTODY_GROUPS);
    let d: Vec<ForkDigest> = [0, 1, 2, 4, 5, 8].map(|e| run.digest(e)).to_vec();
    // 193 topics a digest: two fit, three do not.
    assert_eq!(run.digests.topics_under(d[0], 0).len(), 65 + 128);
    let [first, _] = run.epoch(0);
    assert_eq!(first.deferred, [d[2]]);
    assert_eq!(run.tracked(), [d[0], d[1]].into());
    // d2 moves up and gets the room of d0, in its grace.
    let [first, _] = run.epoch(1);
    assert_eq!((first.retired, first.deferred), (vec![d[0]], vec![]));
    assert_eq!(run.tracked(), [d[1], d[2]].into());
    let [first, _] = run.epoch(2);
    assert_eq!(first.retired, [d[1]]);
    let [first, tick] = run.epoch(3);
    assert_eq!(first.deferred, [d[4]]);
    assert_eq!(tick.deferred, [d[4]], "tried again at the tick");
    for epoch in 4..=9 {
        run.epoch(epoch);
    }
    assert_eq!(run.tracked(), [d[5]].into());
}

/// A named digest takes the room of a later named one, which then waits; a digest named again
/// within its grace stays.
#[test]
fn a_later_named_digest_gives_way_to_an_earlier_one() {
    let (a, b, c) = ([0xa; 4], [0xb; 4], [0xc; 4]);
    let body = |digests: &[ForkDigest]| {
        body_of(&pb::WatchSubscriptionsResponseBody {
            attnets: Vec::new(),
            syncnets: Vec::new(),
            custody_columns: (0..128).collect(),
            fork_digests: digests.iter().map(|d| d.to_vec()).collect(),
        })
    };
    let list = TopicList::parse(&big_list()).unwrap();
    let mut digests = DigestTopics::new(list, EPOCH, body(&[a]));
    let cfg = GossipConfig::new(digests.start_topics(), caps(), Duration::from_secs(60));
    let mut gossip = IgnoreAll::new(&cfg, &mut Registry::default()).unwrap();
    let t0 = Instant::now();
    digests.set_body(body(&[a, c]));
    assert!(digests.follow(&mut gossip, t0).unwrap().deferred.is_empty());
    // b comes between a and c: c gives b its room, then waits as the third.
    digests.set_body(body(&[a, b, c]));
    let followed = digests.follow(&mut gossip, t0).unwrap();
    assert_eq!((followed.retired, followed.deferred), (vec![c], vec![c]));
    assert_eq!(digests.subscribed().collect::<Vec<_>>(), [a, b]);
    assert!(gossip.whitelist_len() <= MAX_TOPICS);
    // b leaves the body and comes back within its grace: it stays.
    digests.set_body(body(&[a]));
    assert!(digests.follow(&mut gossip, t0).unwrap().retired.is_empty());
    digests.set_body(body(&[a, b]));
    let back = digests.follow(&mut gossip, t0 + EPOCH / 2).unwrap();
    assert!(back.is_empty(), "{back:?}");
    let later = digests.follow(&mut gossip, t0 + EPOCH * 2).unwrap();
    assert!(later.retired.is_empty(), "named again: no grace runs");
    assert_eq!(digests.subscribed().collect::<Vec<_>>(), [a, b]);
}
