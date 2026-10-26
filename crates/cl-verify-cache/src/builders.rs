//! Builder key cache for `cl-verify`: the keys of the Gloas builder registry (`state.builders`),
//! in a namespace separate from the validator [`PubkeyCache`](crate::PubkeyCache).
//!
//! Bids and envelopes are signed with `state.builders[i].pubkey` (`gloas/beacon-chain.md`
//! `verify_execution_payload_bid_signature`, `verify_execution_payload_envelope_signature`). A
//! builder index is not a validator index, so builder keys never go into the validator cache,
//! and a builder index never resolves to a validator key (or the other way round).
//!
//! # Why the cache compares the full key on every hit
//!
//! The builder registry is not append-only. A builder that exited and that the builders sweep
//! paid out frees its index, and the next new builder takes it with a new key
//! (`get_index_for_new_builder`, G L2322-2331). That can happen to a finalized builder on a
//! branch that is not finalized. Thus neither the index, nor `(index, version)`, nor a cache of
//! finalized entries only is a safe key:
//!
//! - The `version` of [`BuilderSigner::Cached`] is `builder_key_version` of the state: the first 8
//!   bytes of `sha256(pubkey)`. It is a lookup hint only. A party that controls two keys can find a
//!   64-bit collision (about 2^32 key generations), register one key, exit, and put the other key
//!   on the same index.
//! - A finalized entry is the right key only for a state whose `state.builders[index].pubkey` is
//!   that same key.
//!
//! So the signer carries the full 48-byte compressed key of `state.builders[index]` of the state
//! that the signature is verified against, and [`BuilderKeyCache::resolve`] gives the cached
//! (already validated) key only if the cached version AND the cached 48 bytes are equal to it.
//! Any other case is [`Lookup::Unknown`], which callers map to IGNORE, never ACCEPT. A stale,
//! replaced or lagging entry can therefore only miss; it never gives a wrong key.
//!
//! # Feed
//!
//! cl-chain feeds only the builder registry of its *finalized* state, in ranges
//! ([`BuilderKeyCache::append_range`]). A range can start below [`high_water`]: its entries
//! replace the cached entries of those indices (an index reused in a newer finalized state), and
//! the rest extend the cache. A range past `high_water` is a gap. Nothing above finality is
//! cached, so a reorg rolls nothing back. A builder that is not finalized travels inline on
//! import ([`BuilderSigner::Inline`]); its key is used for that call only. Gossip carries no
//! inline builder key: an active builder has a finalized placement (`is_active_builder`).
//!
//! An inline key for an index that the cache holds is allowed, unlike for validators: the key
//! comparison, not the high-water mark, decides what a cached entry is good for, so cl-chain
//! needs no hold-back between the builder feed and VerifyBls.
//!
//! The cache is in memory only. [`crate::persist`] writes the validator registry only; after a
//! restart the builder cache is empty until the feed refills it.
//!
//! [`high_water`]: BuilderKeyCache::high_water

use crate::eligibility::{IgnoreReason, KeySource, Origin, Resolution, ResolvedKey, Violation};
use crate::{AppendError, Lookup};

/// Length of a compressed BLS public key (`BLSPubkey`).
pub const BUILDER_PUBKEY_BYTES: usize = 48;

/// A compressed BLS public key, as `state.builders[i].pubkey` holds it.
pub type CompressedPubkey = [u8; BUILDER_PUBKEY_BYTES];

/// One finalized builder entry, as the feed delivers it: the key version, the compressed key and
/// the decoded (validated) key `K`.
///
/// The caller decodes `key` from `pubkey`; the cache does not check that the two agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuilderEntry<K> {
    version: u64,
    pubkey: CompressedPubkey,
    key: K,
}

impl<K> BuilderEntry<K> {
    #[must_use]
    pub fn new(version: u64, pubkey: CompressedPubkey, key: K) -> Self {
        Self {
            version,
            pubkey,
            key,
        }
    }

    /// `builder_key_version` of the finalized state for this index.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// `state.builders[i].pubkey` of the finalized state.
    #[must_use]
    pub fn pubkey(&self) -> &CompressedPubkey {
        &self.pubkey
    }
}

/// A builder signer as `cl-verify` sees it (the `verify.v1` `BuilderSigner` message, decoded).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuilderSigner<K> {
    /// Resolve from the cache: `pubkey` is `state.builders[index].pubkey` of the state that the
    /// signature is verified against, and `version` its `builder_key_version` (a hint).
    Cached {
        index: u64,
        version: u64,
        pubkey: CompressedPubkey,
    },
    /// A builder key carried inline (import only), used for this call only.
    Inline { index: u64, key: K },
}

impl<K> BuilderSigner<K> {
    /// The builder index this signer names.
    pub fn index(&self) -> u64 {
        match self {
            Self::Cached { index, .. } | Self::Inline { index, .. } => *index,
        }
    }

    /// Whether this signer carries an inline key.
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Inline { .. })
    }
}

/// Builder keys by builder index, `0..high_water()`, from finalized states only.
#[derive(Clone, Debug)]
pub struct BuilderKeyCache<K> {
    entries: Vec<BuilderEntry<K>>,
}

impl<K> Default for BuilderKeyCache<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> BuilderKeyCache<K> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Applies one feed range: finalized entries `start..start + entries.len()`. `start` must be
    /// at most [`high_water`](Self::high_water); an entry below it replaces the cached entry of
    /// its index. A range that starts past it is [`AppendError::Gap`] and changes nothing.
    pub fn append_range(
        &mut self,
        start: u64,
        entries: Vec<BuilderEntry<K>>,
    ) -> Result<(), AppendError> {
        let expected = self.high_water();
        let at = usize::try_from(start)
            .ok()
            .filter(|_| start <= expected)
            .ok_or(AppendError::Gap {
                expected,
                got: start,
            })?;
        for (i, entry) in entries.into_iter().enumerate() {
            match self.entries.get_mut(at + i) {
                Some(slot) => *slot = entry,
                None => self.entries.push(entry),
            }
        }
        Ok(())
    }

    /// The cached key of builder `index`, only if its entry has `version` and the 48 bytes of
    /// `pubkey` (`state.builders[index].pubkey` of the state verified against). Anything else,
    /// including a version match with another key, is [`Lookup::Unknown`].
    pub fn resolve(&self, index: u64, version: u64, pubkey: &CompressedPubkey) -> Lookup<'_, K> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.entries.get(i))
            .filter(|e| e.version == version && e.pubkey == *pubkey)
            .map_or(Lookup::Unknown, |e| Lookup::Known(&e.key))
    }

    /// Applies the eligibility rules to builder signer `signer` from `origin`.
    ///
    /// - `Cached`: the key from [`resolve`](Self::resolve), else `Ignore(UnknownBuilder)`.
    /// - `Inline` on gossip: `ContractViolation(BuilderInlineOnGossip)`.
    /// - `Inline` on import: the inline key, for this call only, whatever the cache holds.
    pub fn resolve_signer<'a>(
        &'a self,
        signer: &'a BuilderSigner<K>,
        origin: Origin,
    ) -> Resolution<'a, K> {
        match (signer, origin) {
            (
                BuilderSigner::Cached {
                    index,
                    version,
                    pubkey,
                },
                _,
            ) => match self.resolve(*index, *version, pubkey) {
                Lookup::Known(key) => Resolution::Resolved(ResolvedKey::new(key, KeySource::Cache)),
                Lookup::Unknown => {
                    Resolution::Ignore(IgnoreReason::UnknownBuilder { index: *index })
                }
            },
            (BuilderSigner::Inline { index, .. }, Origin::Gossip) => {
                Resolution::ContractViolation(Violation::BuilderInlineOnGossip { index: *index })
            }
            (BuilderSigner::Inline { key, .. }, Origin::Import) => {
                Resolution::Resolved(ResolvedKey::new(key, KeySource::Inline))
            }
        }
    }

    /// Number of entries held: the most a feed range may start at.
    pub fn high_water(&self) -> u64 {
        self.entries.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IgnoreReason, KeySource, Lookup, Origin, Resolution, Violation};
    use proptest::prelude::*;

    /// A distinct compressed key per tag. The decoded key of the tests is the compressed key.
    fn pk(tag: u8) -> CompressedPubkey {
        [tag; BUILDER_PUBKEY_BYTES]
    }

    fn entry(version: u64, tag: u8) -> BuilderEntry<CompressedPubkey> {
        BuilderEntry::new(version, pk(tag), pk(tag))
    }

    fn filled(tags: &[u8]) -> BuilderKeyCache<CompressedPubkey> {
        let mut c = BuilderKeyCache::new();
        let entries = tags.iter().map(|t| entry(u64::from(*t), *t)).collect();
        c.append_range(0, entries).unwrap();
        c
    }

    fn cached(index: u64, version: u64, tag: u8) -> BuilderSigner<CompressedPubkey> {
        BuilderSigner::Cached {
            index,
            version,
            pubkey: pk(tag),
        }
    }

    #[test]
    fn an_empty_cache_resolves_nothing() {
        let c = BuilderKeyCache::<CompressedPubkey>::new();
        assert_eq!(c.high_water(), 0);
        assert_eq!(c.resolve(0, 0, &pk(0)), Lookup::Unknown);
    }

    #[test]
    fn a_hit_needs_the_same_version_and_the_same_full_key() {
        let c = filled(&[10, 11, 12]);
        assert_eq!(c.high_water(), 3);
        assert_eq!(c.resolve(1, 11, &pk(11)), Lookup::Known(&pk(11)));
        // Another key with the same version (a 64-bit collision of the version digest).
        assert_eq!(c.resolve(1, 11, &pk(99)), Lookup::Unknown);
        // The same key under another version.
        assert_eq!(c.resolve(1, 12, &pk(11)), Lookup::Unknown);
        // Past the high-water mark.
        assert_eq!(c.resolve(3, 13, &pk(13)), Lookup::Unknown);
        assert_eq!(c.resolve(u64::MAX, 13, &pk(13)), Lookup::Unknown);
    }

    #[test]
    fn a_gap_is_refused_and_changes_nothing() {
        let mut c = filled(&[10, 11]);
        assert_eq!(
            c.append_range(3, vec![entry(13, 13)]),
            Err(AppendError::Gap {
                expected: 2,
                got: 3
            })
        );
        assert_eq!(c.high_water(), 2);
        assert_eq!(c.resolve(1, 11, &pk(11)), Lookup::Known(&pk(11)));
    }

    #[test]
    fn an_overlap_replaces_a_reused_index_and_extends_the_rest() {
        // The finalized registry reuses index 1 (an exited builder swept to 0) and adds index 3.
        let mut c = filled(&[10, 11, 12]);
        c.append_range(1, vec![entry(21, 21), entry(12, 12), entry(13, 13)])
            .unwrap();
        assert_eq!(c.high_water(), 4);
        assert_eq!(c.resolve(1, 11, &pk(11)), Lookup::Unknown, "old key gone");
        assert_eq!(c.resolve(1, 21, &pk(21)), Lookup::Known(&pk(21)));
        assert_eq!(c.resolve(2, 12, &pk(12)), Lookup::Known(&pk(12)));
        assert_eq!(c.resolve(3, 13, &pk(13)), Lookup::Known(&pk(13)));
        // An empty frame at or below the mark is a no-op.
        c.append_range(4, vec![]).unwrap();
        c.append_range(0, vec![]).unwrap();
        assert_eq!(c.high_water(), 4);
    }

    #[test]
    fn a_cached_signer_resolves_on_either_origin_only_with_the_state_key() {
        let c = filled(&[10, 11]);
        for origin in [Origin::Gossip, Origin::Import] {
            let hit = cached(1, 11, 11);
            match c.resolve_signer(&hit, origin) {
                Resolution::Resolved(k) => {
                    assert_eq!((k.key(), k.source()), (&pk(11), KeySource::Cache));
                }
                other => panic!("expected a hit, got {other:?}"),
            }
            for miss in [cached(1, 11, 99), cached(1, 12, 11), cached(2, 12, 12)] {
                assert_eq!(
                    c.resolve_signer(&miss, origin),
                    Resolution::Ignore(IgnoreReason::UnknownBuilder {
                        index: miss.index()
                    })
                );
            }
        }
    }

    #[test]
    fn an_inline_builder_key_is_for_import_only_and_never_enters_the_cache() {
        let c = filled(&[10, 11]);
        let inline = BuilderSigner::Inline {
            index: 1,
            key: pk(77),
        };
        assert_eq!(
            c.resolve_signer(&inline, Origin::Gossip),
            Resolution::ContractViolation(Violation::BuilderInlineOnGossip { index: 1 })
        );
        match c.resolve_signer(&inline, Origin::Import) {
            Resolution::Resolved(k) => {
                assert_eq!((k.key(), k.source()), (&pk(77), KeySource::Inline));
            }
            other => panic!("expected the inline key, got {other:?}"),
        }
        assert!(inline.is_inline() && !cached(1, 11, 11).is_inline());
        assert_eq!(c.high_water(), 2, "inline keys never enter the cache");
        assert_eq!(c.resolve(1, 77, &pk(77)), Lookup::Unknown);
    }

    #[test]
    fn an_entry_reports_what_the_feed_sent() {
        let e = entry(7, 3);
        assert_eq!((e.version(), e.pubkey()), (7, &pk(3)));
    }

    proptest! {
        /// Whatever finalized registries the feed delivers, in whatever order of overlapping
        /// ranges, a hit is always the exact key that the signer names, and only for an entry of
        /// the last range that covered the index.
        #[test]
        fn a_hit_is_always_the_named_key_of_the_latest_finalized_entry(
            ranges in proptest::collection::vec(
                (0usize..8, proptest::collection::vec((0u64..4, 0u8..6), 0..8)),
                1..12,
            ),
            probes in proptest::collection::vec((0u64..10, 0u64..4, 0u8..6), 1..40),
        ) {
            let mut c = BuilderKeyCache::new();
            let mut model: Vec<(u64, u8)> = Vec::new();
            for (start, entries) in ranges {
                let start = start.min(model.len());
                let built = entries.iter().map(|(v, t)| entry(*v, *t)).collect();
                c.append_range(start as u64, built).unwrap();
                for (i, e) in entries.into_iter().enumerate() {
                    if start + i < model.len() {
                        model[start + i] = e;
                    } else {
                        model.push(e);
                    }
                }
                prop_assert_eq!(c.high_water(), model.len() as u64);
            }
            for (index, version, tag) in probes {
                let expected = usize::try_from(index)
                    .ok()
                    .and_then(|i| model.get(i))
                    .filter(|(v, t)| *v == version && *t == tag);
                match c.resolve(index, version, &pk(tag)) {
                    Lookup::Known(k) => {
                        prop_assert!(expected.is_some());
                        prop_assert_eq!(k, &pk(tag));
                    }
                    Lookup::Unknown => prop_assert!(expected.is_none()),
                }
            }
        }
    }
}
