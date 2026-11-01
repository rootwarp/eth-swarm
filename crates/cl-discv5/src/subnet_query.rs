//! `FindPeers`: a lookup for the peers that serve what a request wants (consensus-specs
//! v1.7.0-beta.4).
//!
//! - [`SubnetQuery::parse`]: the request, checked and normalised into masks: attestation
//!   subnets below `ATTESTATION_SUBNET_COUNT` (64), sync-committee subnets below
//!   `SYNC_COMMITTEE_SUBNET_COUNT` (4) and custody columns below `NUMBER_OF_COLUMNS` (128), at
//!   least one of them; `target` at least 1, capped at [`MAX_TARGET`]; `fork_digest` empty
//!   (ours) or ours. Order and repeats do not matter.
//! - [`SubnetQuery::coverage`]: how many wanted subnets and columns a record serves: its
//!   `attnets` and `syncnets` bits (`phase0/p2p-interface.md`, `altair/p2p-interface.md`) and
//!   its custody columns, `get_custody_groups` of its node ID and `cgc` (`fulu/das-core.md`). A
//!   peer matches when it serves any one ([`SubnetQuery::matches`], the lookup's predicate, which
//!   [`crate::service::Discovery::find_peers_matching`] ANDs with the IP rules and our exact
//!   `eth2` fork digest); the peers found are ranked by coverage, most first, ties in node ID
//!   order.
//! - The finder (crate-internal, one per server): at most [`MAX_CONCURRENT_LOOKUPS`] lookups at
//!   once. A request waits for a slot until its deadline; once it holds one, its lookup runs in a
//!   task of its own that holds the slot until the lookup ends, whatever becomes of the request
//!   (discv5 cannot cancel a lookup it started; it ends at its query timeout). So the deadline
//!   bounds the request, not its lookup, and a request cancelled while it waits leaves the
//!   queue without starting one. Each lookup asks for [`MAX_TARGET`] peers whatever the
//!   request's `target`, and its ranked peers are cached by query for the rest of the slot
//!   ([`SlotClock`]) at our fork digest: a hit runs no lookup. A new slot or fork digest empties
//!   the cache; it holds at most [`MAX_CACHE_ENTRIES`] queries and drops the oldest first (a hit
//!   does not refresh one). A failed lookup, one that ends in a later slot, or one whose request
//!   is gone (its peers are dropped) is not cached.

use crate::enr::{Enr, EnrFields};
use crate::service::ServiceError;
use consensus_types::das::{
    self, CUSTODY_REQUIREMENT, NUMBER_OF_COLUMNS, NUMBER_OF_CUSTODY_GROUPS,
};
use consensus_types::primitives::U256;
use ethswarm_proto::discv5 as pb;
use p2p_wire::enr::SYNC_COMMITTEE_SUBNET_COUNT;
use p2p_wire::gossip::topic::ATTESTATION_SUBNET_COUNT;
use p2p_wire::rpc::messages::ForkDigest;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tonic::{Code, Status};

/// The most peers one request gets: a larger `target` is capped to it (Lighthouse's subnet
/// queries use 16).
pub const MAX_TARGET: usize = 16;
/// The most `FindPeers` lookups that run at once; the periodic lookups are not counted.
pub const MAX_CONCURRENT_LOOKUPS: usize = 2;
/// The most queries whose peers the cache holds within a slot.
pub const MAX_CACHE_ENTRIES: usize = 64;

/// The wall-clock slot now.
pub type SlotClock = Arc<dyn Fn() -> u64 + Send + Sync>;

// The masks of [`SubnetQuery`] hold every subnet and column.
const _: () = assert!(ATTESTATION_SUBNET_COUNT <= u64::BITS as u64);
const _: () = assert!(SYNC_COMMITTEE_SUBNET_COUNT <= u8::BITS as u64);
const _: () = assert!(NUMBER_OF_COLUMNS <= u128::BITS as u64);

/// Why a `FindPeers` request was refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueryError {
    /// An attestation subnet not below `ATTESTATION_SUBNET_COUNT`.
    #[error("attnet {0} is not below {ATTESTATION_SUBNET_COUNT}")]
    Attnet(u32),
    /// A sync-committee subnet not below `SYNC_COMMITTEE_SUBNET_COUNT`.
    #[error("syncnet {0} is not below {SYNC_COMMITTEE_SUBNET_COUNT}")]
    Syncnet(u32),
    /// A column not below `NUMBER_OF_COLUMNS`.
    #[error("custody column {0} is not below {NUMBER_OF_COLUMNS}")]
    Column(u64),
    /// No subnet and no column.
    #[error("the request wants no subnet and no column")]
    NothingWanted,
    /// `target` 0.
    #[error("target 0")]
    ZeroTarget,
    /// A `fork_digest` that is neither empty nor 4 bytes.
    #[error("fork_digest of {0} bytes, want 4 or none")]
    DigestLen(usize),
    /// A `fork_digest` that is not our current one.
    #[error("fork_digest is not our current fork digest")]
    OtherFork,
    /// The request's deadline passed before a lookup could run and end (the lookup runs on).
    #[error("the deadline passed before the lookup ended")]
    Deadline,
    /// The lookup failed.
    #[error(transparent)]
    Lookup(#[from] ServiceError),
}

/// `INVALID_ARGUMENT` for a malformed request, `FAILED_PRECONDITION` for another fork digest,
/// `DEADLINE_EXCEEDED` and `UNAVAILABLE` for a lookup that did not end or failed.
impl From<QueryError> for Status {
    fn from(e: QueryError) -> Self {
        let code = match e {
            QueryError::OtherFork => Code::FailedPrecondition,
            QueryError::Deadline => Code::DeadlineExceeded,
            QueryError::Lookup(_) => Code::Unavailable,
            _ => Code::InvalidArgument,
        };
        Status::new(code, e.to_string())
    }
}

/// What a `FindPeers` request wants, as masks: bit `i` of each is subnet or column `i`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubnetQuery {
    attnets: u64,
    syncnets: u8,
    columns: u128,
}

impl SubnetQuery {
    /// The query of `request` and how many peers it wants (at most [`MAX_TARGET`]); `ours` is
    /// our fork digest now. An empty `fork_digest` means ours.
    ///
    /// # Errors
    ///
    /// An index out of range, nothing wanted, `target` 0 or a `fork_digest` of another length
    /// than 4 is malformed; another 4-byte digest is [`QueryError::OtherFork`].
    pub fn parse(
        request: &pb::FindPeersRequest,
        ours: ForkDigest,
    ) -> Result<(Self, usize), QueryError> {
        let mut query = Self::default();
        for &subnet in &request.attnets {
            if u64::from(subnet) >= ATTESTATION_SUBNET_COUNT {
                return Err(QueryError::Attnet(subnet));
            }
            query.attnets |= 1 << subnet;
        }
        for &subnet in &request.syncnets {
            if u64::from(subnet) >= SYNC_COMMITTEE_SUBNET_COUNT {
                return Err(QueryError::Syncnet(subnet));
            }
            query.syncnets |= 1 << subnet;
        }
        for &column in &request.custody_columns {
            if column >= NUMBER_OF_COLUMNS {
                return Err(QueryError::Column(column));
            }
            query.columns |= 1 << column;
        }
        if query == Self::default() {
            return Err(QueryError::NothingWanted);
        }
        if request.target == 0 {
            return Err(QueryError::ZeroTarget);
        }
        match request.fork_digest.len() {
            0 => {}
            4 if request.fork_digest == ours => {}
            4 => return Err(QueryError::OtherFork),
            n => return Err(QueryError::DigestLen(n)),
        }
        let target = usize::try_from(request.target).map_or(MAX_TARGET, |t| t.min(MAX_TARGET));
        Ok((query, target))
    }

    /// How many of the wanted subnets and columns `enr` serves; 0 for a record whose fields do
    /// not decode ([`EnrFields::read`]). Its custody follows its `cgc`: without one, the
    /// `CUSTODY_REQUIREMENT` (4) every node keeps (`fulu/das-core.md`: a larger custody extends
    /// it); empty (0) or below 4, as advertised; above `NUMBER_OF_CUSTODY_GROUPS`, nothing at all
    /// matches.
    #[must_use]
    pub fn coverage(&self, enr: &Enr) -> u32 {
        let Ok(fields) = EnrFields::read(enr) else {
            return 0;
        };
        let cgc = fields.cgc.unwrap_or(CUSTODY_REQUIREMENT);
        if cgc > NUMBER_OF_CUSTODY_GROUPS {
            return 0;
        }
        let columns = if self.columns == 0 {
            0
        } else {
            self.columns & custody(enr, cgc)
        };
        (self.attnets & fields.attnets).count_ones()
            + (self.syncnets & fields.syncnets).count_ones()
            + columns.count_ones()
    }

    /// Whether `enr` serves at least one wanted subnet or column.
    #[must_use]
    pub fn matches(&self, enr: &Enr) -> bool {
        self.coverage(enr) > 0
    }

    /// The records of `found` that match, most coverage first, ties in node ID order (a stable,
    /// total order: a node ID is unique).
    fn rank(&self, found: Vec<Enr>) -> Vec<Enr> {
        let mut ranked: Vec<_> = found
            .into_iter()
            .map(|enr| (self.coverage(&enr), enr))
            .filter(|(coverage, _)| *coverage > 0)
            .collect();
        ranked.sort_by_key(|(coverage, enr)| (std::cmp::Reverse(*coverage), enr.node_id().raw()));
        ranked.into_iter().map(|(_, enr)| enr).collect()
    }
}

/// The lookups of `FindPeers`: at most [`MAX_CONCURRENT_LOOKUPS`] at once, their results cached
/// for the rest of the slot (see the module docs).
pub(crate) struct Finder {
    permits: Arc<Semaphore>,
    cache: Mutex<Cache>,
    slots: SlotClock,
}

/// The peers found for up to [`MAX_CACHE_ENTRIES`] queries, all at one slot and fork digest.
#[derive(Default)]
struct Cache {
    at: (u64, ForkDigest),
    /// Oldest first.
    entries: VecDeque<(SubnetQuery, Arc<[Enr]>)>,
}

impl Cache {
    /// The entries, emptied first unless they are of `at`.
    fn at(&mut self, at: (u64, ForkDigest)) -> &mut VecDeque<(SubnetQuery, Arc<[Enr]>)> {
        if self.at != at {
            self.entries.clear();
            self.at = at;
        }
        &mut self.entries
    }
}

impl Finder {
    /// No lookup running and nothing cached; `slots` reads the slot now.
    #[must_use]
    pub(crate) fn new(slots: SlotClock) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
            cache: Mutex::new(Cache::default()),
            slots,
        }
    }

    /// The peers for `query` while our fork digest is `ours`: those cached at this slot and
    /// digest, else those `lookup` finds once a permit is free, then cached. `deadline` bounds
    /// the wait for the permit and the lookup together; the lookup itself, once started, runs
    /// to its end in a task that holds the permit, even if this future is dropped first.
    ///
    /// # Errors
    ///
    /// [`QueryError::Deadline`] once `deadline` passes, [`QueryError::Lookup`] if the lookup
    /// fails (or its task panics); neither is cached.
    pub(crate) async fn find<F, Fut>(
        &self,
        query: SubnetQuery,
        ours: ForkDigest,
        deadline: Option<Instant>,
        lookup: F,
    ) -> Result<Arc<[Enr]>, QueryError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<Enr>, ServiceError>> + Send + 'static,
    {
        let at = ((self.slots)(), ours);
        let hit = (self.cache().at(at).iter())
            .find(|(q, _)| *q == query)
            .map(|(_, found)| Arc::clone(found));
        if let Some(found) = hit {
            return Ok(found);
        }
        let run = async {
            // The wait is ours: dropped while it waits, a request starts no lookup. `acquire`
            // fails only once the semaphore is closed, and this one never is.
            let permit = Arc::clone(&self.permits).acquire_owned().await.ok();
            let lookup = lookup();
            // The task, not this future, holds the permit until the lookup ends: dropping this
            // future (the deadline, the client gone) detaches the task and frees no slot.
            ipc::spawn_in_span(async move {
                let _permit = permit;
                lookup.await
            })
            .await
        };
        let found = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, run)
                .await
                .map_err(|_| QueryError::Deadline)?,
            None => run.await,
        };
        let found = found.map_err(|e| ServiceError::Query(e.to_string()))??;
        let found: Arc<[Enr]> = query.rank(found).into();
        // Cached only at the slot it was looked up in.
        if (self.slots)() == at.0 {
            let mut cache = self.cache();
            let entries = cache.at(at);
            entries.retain(|(q, _)| *q != query);
            if entries.len() == MAX_CACHE_ENTRIES {
                entries.pop_front();
            }
            entries.push_back((query, Arc::clone(&found)));
        }
        Ok(found)
    }

    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The custody columns of `enr`'s node at `cgc`, as a mask.
fn custody(enr: &Enr, cgc: u64) -> u128 {
    let node = U256::from_be_bytes(enr.node_id().raw());
    das::custody_columns(node, cgc).map_or(0, |columns| {
        columns.iter().fold(0, |mask, &column| mask | 1 << column)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    const OURS: ForkDigest = [1, 2, 3, 4];

    fn request(
        attnets: &[u32],
        syncnets: &[u32],
        columns: &[u64],
        target: u32,
    ) -> pb::FindPeersRequest {
        pb::FindPeersRequest {
            attnets: attnets.to_vec(),
            syncnets: syncnets.to_vec(),
            custody_columns: columns.to_vec(),
            target,
            fork_digest: Vec::new(),
            hello: None,
        }
    }

    fn code(request: &pb::FindPeersRequest) -> Code {
        tonic::Status::from(SubnetQuery::parse(request, OURS).unwrap_err()).code()
    }

    /// Every index below its count, something wanted, a target; the sets are normalised (order
    /// and repeats do not matter) and the target is capped at [`MAX_TARGET`].
    #[test]
    fn requests_are_validated_and_normalised() {
        let parse = |r: &pb::FindPeersRequest| SubnetQuery::parse(r, OURS).unwrap();
        let (query, target) = parse(&request(&[63, 0], &[3], &[127, 0], 1));
        assert_eq!(target, 1);
        assert_eq!(
            parse(&request(&[0, 63, 0], &[3, 3], &[0, 127, 0], 1)).0,
            query
        );
        assert_ne!(parse(&request(&[0], &[3], &[127, 0], 1)).0, query);
        assert_eq!(parse(&request(&[1], &[], &[], 16)).1, 16);
        assert_eq!(parse(&request(&[1], &[], &[], 17)).1, MAX_TARGET);
        assert_eq!(parse(&request(&[1], &[], &[], u32::MAX)).1, MAX_TARGET);
        assert_eq!(parse(&request(&[], &[0], &[], 2)).1, 2);
        assert_eq!(parse(&request(&[], &[], &[5], 2)).1, 2);

        for bad in [
            request(&[64], &[], &[], 1),
            request(&[0, u32::MAX], &[], &[], 1),
            request(&[], &[4], &[], 1),
            request(&[], &[], &[128], 1),
            request(&[], &[], &[u64::MAX], 1),
            request(&[], &[], &[], 1),
            request(&[1], &[], &[], 0),
        ] {
            assert_eq!(code(&bad), Code::InvalidArgument, "{bad:?}");
        }
    }

    /// `fork_digest`: empty is ours, our 4 bytes are ours, any other 4 bytes are another fork
    /// (`FAILED_PRECONDITION`), any other length is malformed (`INVALID_ARGUMENT`).
    #[test]
    fn the_fork_digest_must_be_ours() {
        let with = |digest: &[u8]| pb::FindPeersRequest {
            fork_digest: digest.to_vec(),
            ..request(&[1], &[], &[], 1)
        };
        assert!(SubnetQuery::parse(&with(&[]), OURS).is_ok());
        assert!(SubnetQuery::parse(&with(&OURS), OURS).is_ok());
        assert_eq!(code(&with(&[1, 2, 3, 5])), Code::FailedPrecondition);
        assert_eq!(code(&with(&[1, 2, 3])), Code::InvalidArgument);
        assert_eq!(code(&with(&[1, 2, 3, 4, 0])), Code::InvalidArgument);
    }
}
