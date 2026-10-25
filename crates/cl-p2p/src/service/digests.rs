//! The fork digests whose topics cl-p2p subscribes ([`DigestTopics`]), so the topic set stays
//! within its bound ([`MAX_TOPICS`]) across every fork and BPO digest change.
//!
//! cl-chain's subscriptions body names the current fork digest first, then each digest whose
//! change comes within its lead. The topics of a named digest are the topic list (under the
//! first two digests of a body, as [`TopicList::topics`] gives them) and the custody column
//! subnets.
//!
//! - **Subscribe**: the topics of each named digest, in the body's order.
//! - **Retire**: a digest that the body no longer names stays subscribed for the grace (two
//!   epochs, [`crate::service::DIGEST_GRACE_EPOCHS`]: `altair/p2p-interface.md`, "Transitioning
//!   the gossip"), because messages of the old digest can arrive late. Then its topics leave
//!   gossipsub, the subscribed set and the whitelist ([`IgnoreAll::retire_digest`]), and the
//!   room takes the topics of later digests.
//! - **Make room**: when the topics of a named digest do not fit the bound, the retiring
//!   digests go first, the oldest first, then the named digests after it in the body, the last
//!   first. One digest has at most [`TOPICS_PER_FORK_DIGEST`] topics and the bound is two
//!   digests' worth, so the first two named digests always fit. A third that does not fit waits
//!   ([`Followed::deferred`]) and is tried again at the next [`DigestTopics::follow`].

use crate::custody::CustodySubscriptions;
use crate::gossip::config::{MAX_TOPICS, TOPICS_PER_FORK_DIGEST};
use crate::gossip::topics::MAX_FORK_DIGESTS as LIST_DIGESTS;
use crate::gossip::{GossipError, IgnoreAll, TopicList};
use p2p_wire::gossip::{GossipKind, GossipTopic};
use p2p_wire::rpc::messages::ForkDigest;
use std::time::Duration;
use tokio::time::Instant;

/// What one [`DigestTopics::follow`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Followed {
    /// The digests retired, in order: past their grace, or to make room.
    pub retired: Vec<ForkDigest>,
    /// The topics newly subscribed.
    pub subscribed: usize,
    /// The named digests whose topics did not fit: tried again at the next follow.
    pub deferred: Vec<ForkDigest>,
}

impl Followed {
    /// Whether nothing changed and nothing waits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.retired.is_empty() && self.subscribed == 0 && self.deferred.is_empty()
    }
}

/// The fork digests whose topics are subscribed (see the module docs).
#[derive(Debug, Clone)]
pub struct DigestTopics {
    list: TopicList,
    grace: Duration,
    /// The body followed: the last one cl-chain sent.
    body: CustodySubscriptions,
    /// The digests whose topics are subscribed, in the order they came, each with the time the
    /// body stopped naming it.
    subscribed: Vec<(ForkDigest, Option<Instant>)>,
}

impl DigestTopics {
    /// Follows `first` with `list`, each superseded digest kept for `grace`. Nothing is
    /// subscribed yet: [`Self::start_topics`] is what the swarm starts with.
    #[must_use]
    pub fn new(list: TopicList, grace: Duration, first: CustodySubscriptions) -> Self {
        Self {
            list,
            grace,
            body: first,
            subscribed: Vec::new(),
        }
    }

    /// The topics of the current digest of the body: what the swarm subscribes at its start,
    /// recorded as subscribed. The other named digests follow at the first [`Self::follow`].
    pub fn start_topics(&mut self) -> Vec<GossipTopic> {
        let Some(&current) = self.body.fork_digests().first() else {
            return Vec::new();
        };
        if !self.is_subscribed(current) {
            self.subscribed.push((current, None));
        }
        self.topics_under(current, 0)
    }

    /// Follows `body` from now on.
    pub fn set_body(&mut self, body: CustodySubscriptions) {
        self.body = body;
    }

    /// The digests whose topics are subscribed now, in the order they came.
    pub fn subscribed(&self) -> impl Iterator<Item = ForkDigest> + '_ {
        self.subscribed.iter().map(|(d, _)| *d)
    }

    /// The topics of the digest at `index` in the body: the topic list under the first two,
    /// and the custody column subnets under each.
    #[must_use]
    pub fn topics_under(&self, digest: ForkDigest, index: usize) -> Vec<GossipTopic> {
        let list: &[GossipKind] = if index < LIST_DIGESTS {
            self.list.kinds()
        } else {
            &[]
        };
        let custody = self
            .body
            .subnets()
            .into_iter()
            .map(|subnet_id| GossipKind::DataColumnSidecar { subnet_id });
        let mut kinds: Vec<GossipKind> = list.to_vec();
        for kind in custody {
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        debug_assert!(kinds.len() <= TOPICS_PER_FORK_DIGEST);
        kinds
            .into_iter()
            .map(|kind| GossipTopic::new(digest, kind))
            .collect()
    }

    /// Brings `gossip` to the body at `now`: retires the digests past their grace, then
    /// subscribes the topics of each named digest, making room as the module docs say.
    ///
    /// # Errors
    ///
    /// The current digest's topics do not fit with every other digest retired (they always
    /// do: see the module docs), or gossipsub refused a topic.
    pub fn follow(
        &mut self,
        gossip: &mut IgnoreAll,
        now: Instant,
    ) -> Result<Followed, GossipError> {
        let named: Vec<ForkDigest> = self.body.fork_digests().to_vec();
        for (digest, since) in &mut self.subscribed {
            if named.contains(digest) {
                *since = None;
            } else if since.is_none() {
                *since = Some(now);
            }
        }
        let mut followed = Followed::default();
        let grace = self.grace;
        let expired: Vec<ForkDigest> = self
            .subscribed
            .iter()
            .filter(|(_, since)| since.is_some_and(|t| now.saturating_duration_since(t) >= grace))
            .map(|(d, _)| *d)
            .collect();
        for digest in expired {
            self.retire(gossip, digest, &mut followed);
        }
        for (index, &digest) in named.iter().enumerate() {
            let topics = self.topics_under(digest, index);
            loop {
                match gossip.subscribe(&topics) {
                    Ok(new) => {
                        followed.subscribed += new;
                        if !self.is_subscribed(digest) {
                            self.subscribed.push((digest, None));
                        }
                        break;
                    }
                    Err(e @ GossipError::TooManyTopics { .. }) => {
                        match self.room_for(index, &named) {
                            Some(victim) => self.retire(gossip, victim, &mut followed),
                            None if index == 0 => return Err(e),
                            None => {
                                followed.deferred.extend_from_slice(&named[index..]);
                                return Ok(followed);
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(followed)
    }

    /// The digest to retire so the named digest at `index` fits: the oldest retiring one, else
    /// the last subscribed named digest after it.
    fn room_for(&self, index: usize, named: &[ForkDigest]) -> Option<ForkDigest> {
        if let Some((digest, _)) = self.subscribed.iter().find(|(_, since)| since.is_some()) {
            return Some(*digest);
        }
        named
            .iter()
            .skip(index + 1)
            .rev()
            .find(|d| self.is_subscribed(**d))
            .copied()
    }

    fn retire(&mut self, gossip: &mut IgnoreAll, digest: ForkDigest, followed: &mut Followed) {
        gossip.retire_digest(digest);
        self.subscribed.retain(|(d, _)| *d != digest);
        followed.retired.push(digest);
    }

    fn is_subscribed(&self, digest: ForkDigest) -> bool {
        self.subscribed.iter().any(|(d, _)| *d == digest)
    }
}

/// The bound holds for any two digests: it is the reason the first two always fit.
const _: () = assert!(2 * TOPICS_PER_FORK_DIGEST <= MAX_TOPICS);

#[cfg(test)]
mod tests;
