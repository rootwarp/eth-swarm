//! Append-only validator pubkey cache for `cl-verify`.
//!
//! Invariant: once *finalized*, a validator index never changes pubkey (the registry is
//! append-only). Before finality, competing branches can assign the same new index to different
//! keys, so the cache holds only the finalized registry prefix `0..high_water()`. A set naming an
//! index at or past that must carry its pubkey inline; without one the lookup is
//! [`Lookup::Unknown`], which callers map to IGNORE or a retry, never ACCEPT. A lagging cache can
//! therefore only miss entries, never return a wrong key.
//!
//! Signers are checked with [`PubkeyCache::resolve_signer`] before any BLS work; the gossip and
//! import rules, and how large import batches are split, are in [`eligibility`].
//!
//! # Feed lag
//!
//! cl-chain feeds the finalized registry over `PubkeyFeed`, and the cache can trail it (a slow or
//! restarted feed, or a snapshot loaded at startup). Nothing turns wrong while it lags:
//! - Indices between `high_water()` and cl-chain's finalized registry length are unknown here. A
//!   gossip message signed by one is IGNOREd (`UnknownIndex`), never ACCEPTed. Gossip carries no
//!   inline keys, so those validators' gossip is dropped until the feed catches up.
//! - On import, cl-chain sends a signer inline only when its index is at or past
//!   `max(acked, sent)`: `acked` is the last high-water mark cl-verify reported
//!   (`PubkeyFeedResponseBody.high_water`), `sent` the end of the feed range cl-chain has sent.
//!   That covers ranges sent before the request, but PubkeyFeed and VerifyBls are separate
//!   streams with no ordering between them, so a range sent later could overtake the request.
//! - Hold-back rule: cl-chain does not send a `PubkeyFeed` range that covers an index carried
//!   inline by an in-flight VerifyBls request until that request has completed (its response is
//!   received) or been cancelled. After a reconnect of either stream, cl-chain first drains or
//!   cancels the in-flight requests, then sends the range. With both rules, a request's inline
//!   indices stay past `high_water()` until the request is resolved.
//! - Indices below the bound go as `Validator(i)`. If their append has not landed yet, they get
//!   a transient `UnknownIndex`: IGNORE, and cl-chain retries.
//! - After either side restarts, cl-chain sends no inline signers until the first
//!   `PubkeyFeedResponseBody` on the new feed stream: a snapshot can leave cl-verify ahead of
//!   what cl-chain knows it sent.
//! - If cl-chain breaks these rules anyway, the inline signer meets a cached index and
//!   [`PubkeyCache::resolve_signer`] returns `InlineForCachedIndex`, a contract violation. That
//!   is the intended signal: it marks a cl-chain bug, not a benign race.
//!
//! A sustained lag therefore costs gossip coverage, not safety. cl-chain alerts when the cache
//! trails the finalized registry for more than 4 epochs.

pub mod eligibility;
pub mod persist;

pub use eligibility::{
    split_import_batch, IgnoreReason, KeySource, Origin, Resolution, ResolvedKey, Signer,
    Violation, MAX_INLINE_KEYS_PER_BATCH, MAX_SETS_PER_BATCH,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppendError {
    /// Index already holds a different key: the feed broke the append-only invariant.
    #[error("validator {index} already has a different pubkey")]
    KeyChanged { index: u64 },
    /// Range starts below the next free index (PubkeyFeed overlap).
    #[error("expected start {expected}, got {got} (overlap)")]
    Overlap { expected: u64, got: u64 },
    /// Index is past the next free slot.
    #[error("expected index {expected}, got {got}")]
    Gap { expected: u64, got: u64 },
}

/// Result of a cache lookup.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<'a, K> {
    Known(&'a K),
    Unknown,
}

/// Pubkeys indexed by validator index, `0..high_water()`.
#[derive(Clone, Debug, Default)]
pub struct PubkeyCache<K> {
    keys: Vec<K>,
}

impl<K: PartialEq> PubkeyCache<K> {
    #[must_use]
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }
    /// Appends `key` at `index`. Re-sending an existing entry unchanged is a no-op (feed replay).
    pub fn append(&mut self, index: u64, key: K) -> Result<(), AppendError> {
        let expected = self.high_water();
        match self.get(index) {
            Lookup::Known(old) if *old == key => Ok(()),
            Lookup::Known(_) => Err(AppendError::KeyChanged { index }),
            Lookup::Unknown if index == expected => {
                self.keys.push(key);
                Ok(())
            }
            Lookup::Unknown => Err(AppendError::Gap {
                expected,
                got: index,
            }),
        }
    }

    /// Appends one PubkeyFeed message: finalized entries `start..start + keys.len()`.
    /// `start` must equal `high_water()`; anything else is a contract violation.
    pub fn append_range(&mut self, start: u64, keys: Vec<K>) -> Result<(), AppendError> {
        let expected = self.high_water();
        match start.cmp(&expected) {
            std::cmp::Ordering::Equal => {
                self.keys.extend(keys);
                Ok(())
            }
            std::cmp::Ordering::Less => Err(AppendError::Overlap {
                expected,
                got: start,
            }),
            std::cmp::Ordering::Greater => Err(AppendError::Gap {
                expected,
                got: start,
            }),
        }
    }

    /// Applies the eligibility rules to validator signer `signer` from `origin`; see
    /// [`eligibility`]. Builder keys and message-carried keys must not be resolved here.
    ///
    /// - `Validator(i)`: the cached key if `i < high_water()`, else `Ignore(UnknownIndex)`.
    /// - `Inline` on gossip: `ContractViolation(InlineOnGossip)`.
    /// - `Inline` on import for a cached index: `ContractViolation(InlineForCachedIndex)`.
    /// - `Inline` on import past the cache: the inline key, for this call only.
    pub fn resolve_signer<'a>(
        &'a self,
        signer: &'a Signer<K>,
        origin: Origin,
    ) -> Resolution<'a, K> {
        match (signer, origin) {
            (Signer::Validator(index), _) => match self.get(*index) {
                Lookup::Known(key) => Resolution::Resolved(ResolvedKey::new(key, KeySource::Cache)),
                Lookup::Unknown => Resolution::Ignore(IgnoreReason::UnknownIndex { index: *index }),
            },
            (Signer::Inline { index, .. }, Origin::Gossip) => {
                Resolution::ContractViolation(Violation::InlineOnGossip { index: *index })
            }
            (Signer::Inline { index, key }, Origin::Import) => match self.get(*index) {
                Lookup::Known(_) => {
                    Resolution::ContractViolation(Violation::InlineForCachedIndex { index: *index })
                }
                Lookup::Unknown => Resolution::Resolved(ResolvedKey::new(key, KeySource::Inline)),
            },
        }
    }

    /// Key for a signer: the cached finalized key if present, else the inline key, else Unknown.
    /// Inline keys are used for this call only and never enter the cache.
    ///
    /// A plain lookup that applies no eligibility rules (it accepts inline keys from any origin
    /// and ignores one for a cached index). Verify requests go through
    /// [`resolve_signer`](Self::resolve_signer).
    pub fn resolve<'a>(&'a self, index: u64, inline: Option<&'a K>) -> Lookup<'a, K> {
        match (self.get(index), inline) {
            (Lookup::Known(k), _) => Lookup::Known(k),
            (Lookup::Unknown, Some(k)) => Lookup::Known(k),
            (Lookup::Unknown, None) => Lookup::Unknown,
        }
    }

    pub fn get(&self, index: u64) -> Lookup<'_, K> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.keys.get(i))
            .map_or(Lookup::Unknown, Lookup::Known)
    }

    /// Number of entries held; the next index to be appended.
    pub fn high_water(&self) -> u64 {
        self.keys.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn filled(n: u64) -> PubkeyCache<u64> {
        let mut c = PubkeyCache::new();
        for i in 0..n {
            c.append(i, i * 10).unwrap();
        }
        c
    }

    #[test]
    fn existing_index_with_different_key_is_rejected() {
        let mut c = filled(3);
        assert_eq!(c.append(1, 99), Err(AppendError::KeyChanged { index: 1 }));
        assert_eq!(c.get(1), Lookup::Known(&10));
    }

    #[test]
    fn existing_index_with_same_key_is_idempotent() {
        let mut c = filled(3);
        assert_eq!(c.append(1, 10), Ok(()));
        assert_eq!(c.high_water(), 3);
    }

    #[test]
    fn non_contiguous_index_is_rejected() {
        let mut c = filled(3);
        assert_eq!(
            c.append(5, 50),
            Err(AppendError::Gap {
                expected: 3,
                got: 5
            })
        );
        assert_eq!(c.high_water(), 3);
    }

    #[test]
    fn lookup_past_high_water_is_unknown() {
        let c = filled(3);
        assert_eq!(c.get(2), Lookup::Known(&20));
        assert_eq!(c.get(3), Lookup::Unknown);
        assert_eq!(c.get(u64::MAX), Lookup::Unknown);
    }

    #[test]
    fn feed_range_rejects_gap_and_overlap() {
        let mut c = filled(3);
        assert_eq!(
            c.append_range(4, vec![40]),
            Err(AppendError::Gap {
                expected: 3,
                got: 4
            })
        );
        assert_eq!(
            c.append_range(2, vec![20, 30]),
            Err(AppendError::Overlap {
                expected: 3,
                got: 2
            })
        );
        assert_eq!(c.append_range(3, vec![30, 40]), Ok(()));
        assert_eq!(c.high_water(), 5);
    }

    #[test]
    fn reorg_across_deposit_epoch_only_finalized_key_is_cached() {
        // Finalized registry: 0..3. Branch A and branch B both assign index 3, to different keys.
        let mut c = filled(3);
        let (branch_a, branch_b) = (333u64, 777u64);
        // Unfinalized index: no inline key is IGNORE; inline key is used for that call only.
        assert_eq!(c.resolve(3, None), Lookup::Unknown);
        assert_eq!(c.resolve(3, Some(&branch_a)), Lookup::Known(&branch_a));
        assert_eq!(c.resolve(3, Some(&branch_b)), Lookup::Known(&branch_b));
        assert_eq!(c.high_water(), 3, "inline keys never enter the cache");
        // Branch B finalizes; the feed appends only the finalized entry.
        c.append_range(3, vec![branch_b]).unwrap();
        assert_eq!(c.resolve(3, None), Lookup::Known(&branch_b));
        assert_eq!(
            c.append_range(3, vec![branch_a]),
            Err(AppendError::Overlap {
                expected: 4,
                got: 3
            })
        );
        assert_eq!(
            c.append(3, branch_a),
            Err(AppendError::KeyChanged { index: 3 })
        );
        // A finalized index ignores a conflicting inline key: the cache is authoritative.
        assert_eq!(c.resolve(3, Some(&branch_a)), Lookup::Known(&branch_b));
    }

    proptest! {
        #[test]
        fn lagging_snapshot_is_never_wrong(
            keys in proptest::collection::vec(any::<u64>(), 0..200),
            lag in 0usize..200,
            probes in proptest::collection::vec(any::<u64>(), 1..50),
        ) {
            let mut full = PubkeyCache::new();
            let mut snap = None;
            let cut = lag.min(keys.len());
            for (i, k) in keys.iter().enumerate() {
                if i == cut { snap = Some(full.clone()); }
                full.append(i as u64, *k).unwrap();
            }
            let snap = snap.unwrap_or_else(|| full.clone());
            for p in probes.into_iter().map(|p| p % (keys.len() as u64 + 5)) {
                match snap.get(p) {
                    Lookup::Known(k) => prop_assert_eq!(full.get(p), Lookup::Known(k)),
                    Lookup::Unknown => {}
                }
            }
        }
    }
}
