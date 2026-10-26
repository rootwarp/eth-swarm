//! Signer eligibility: the decision `cl-verify` makes about each signer before any BLS work.
//!
//! [`PubkeyCache::resolve_signer`](crate::PubkeyCache::resolve_signer) returns a [`Resolution`].
//! A caller that goes through `resolve_signer` reaches key material only by matching the
//! [`Resolution::Resolved`] arm, so a signer that must be IGNOREd or is a contract violation never
//! gets as far as a BLS call. The guarantee is structural for those callers only:
//! [`get`](crate::PubkeyCache::get) and [`resolve`](crate::PubkeyCache::resolve) stay public and
//! apply no rules. cl-verify's BLS entry point should therefore take [`ResolvedKey`], not a bare key.
//!
//! # Scope: validator signing keys only
//!
//! [`Signer`] names validator-registry signers. It is not a general signer type: a Gloas builder
//! (`SignerRef::Builder`, an index into the separate `state.builders` registry) and a key carried
//! by the message itself with no validator index (`SignerRef::Inline`: deposits,
//! BLS-to-execution-change withdrawal keys) must not be resolved through it. A builder index
//! passed as `Validator(i)` would resolve to an unrelated validator's key. Builder signers go
//! through [`crate::builders`], a separate cache with its own rules.
//!
//! # Why gossip needs no inline keys
//!
//! The registry grows only through deposits (`add_validator_to_registry`), and a new validator
//! becomes active only through `process_registry_updates` (electra `beacon-chain.md`), which
//! requires `is_eligible_for_activation` (phase0): `activation_eligibility_epoch <=
//! finalized_checkpoint.epoch`. Every validator that can sign a gossip message therefore sits in
//! the finalized registry prefix the cache holds. On gossip, an index at or past
//! [`high_water`](crate::PubkeyCache::high_water) is IGNOREd, and an inline key is a contract
//! violation.
//!
//! Import (blocks and their contents, possibly from unfinalized branches or during sync) can name
//! indices newer than the cache's finality. Such signers carry their key inline, used for that
//! call only. [`split_import_batch`] packs import items into batches of at most
//! [`MAX_INLINE_KEYS_PER_BATCH`] of them and [`MAX_SETS_PER_BATCH`] sets; larger inputs are
//! split, never rejected.
//!
//! # Inline-index rule
//!
//! An inline signer names its index. That index decides the outcome on import:
//! - `index < high_water()`: the cache already holds the finalized key, so sending one inline is
//!   a [`Violation::InlineForCachedIndex`], even when the two keys are equal.
//! - `index >= high_water()`: the inline key is used for this call only and never enters the
//!   cache. Any such index is allowed, including one past `high_water()` with a gap below it,
//!   because the cache is not extended.

/// Packing cap: the most inline pubkeys [`split_import_batch`] puts into one import batch.
///
/// Not a hard limit. A batch of exactly one indivisible set (e.g. an Electra on-chain aggregate
/// over more than 1,024 validators newer than the cache) may exceed it, and the server must accept
/// such a batch. A batch of more than one set over the cap is a contract violation. Gossip carries
/// no inline pubkeys at all.
pub const MAX_INLINE_KEYS_PER_BATCH: usize = 1_024;

/// Most signature sets [`split_import_batch`] puts into one import batch: the `verify.v1`
/// limit of 256 sets per `VerifyBlsRequestBody`.
pub const MAX_SETS_PER_BATCH: usize = 256;

/// A validator signer as `cl-verify` sees it (the `verify.v1` `Signer` message, decoded).
///
/// Validator signing keys only; builder keys and message-carried keys without a validator index
/// must not be expressed as a `Signer` (see the [module docs](self)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Signer<K> {
    /// A registry member whose key comes from the cache.
    Validator(u64),
    /// A registry member newer than the cache's finality, carrying its own key.
    Inline { index: u64, key: K },
}

impl<K> Signer<K> {
    /// The validator index this signer names.
    pub fn index(&self) -> u64 {
        match self {
            Self::Validator(index) | Self::Inline { index, .. } => *index,
        }
    }

    /// Whether this signer carries an inline key.
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Inline { .. })
    }
}

/// Where the message being verified came from (`verify.v1` `VerifyBlsRequestBody.origin`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin {
    /// Gossip validation: inline keys are never allowed.
    Gossip,
    /// Block or batch import: inline keys are allowed for indices past the cache.
    Import,
}

/// The outcome of resolving one signer. Only [`Resolution::Resolved`] yields a key.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a signer must be resolved before BLS work"]
pub enum Resolution<'a, K> {
    /// The key to verify against.
    Resolved(ResolvedKey<'a, K>),
    /// Skip without BLS work: IGNORE or retry, never ACCEPT.
    Ignore(IgnoreReason),
    /// The caller broke the `verify.v1` contract (`ERROR_CODE_CONTRACT_VIOLATION`).
    ContractViolation(Violation),
}

/// A key that passed the eligibility rules, and where it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedKey<'a, K> {
    key: &'a K,
    source: KeySource,
}

impl<'a, K> ResolvedKey<'a, K> {
    pub(crate) fn new(key: &'a K, source: KeySource) -> Self {
        Self { key, source }
    }

    pub fn key(&self) -> &'a K {
        self.key
    }

    pub fn source(&self) -> KeySource {
        self.source
    }
}

/// Where a resolved key came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeySource {
    /// The finalized registry prefix.
    Cache,
    /// The signer's inline key, for this call only.
    Inline,
}

/// Why a signer is IGNOREd before BLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IgnoreReason {
    /// Index at or past the cache high-water mark with no usable inline key
    /// (`VERIFY_STATUS_UNKNOWN_INDEX`).
    UnknownIndex { index: u64 },
    /// A builder with no cached entry of the same version and the same full key, and no inline
    /// key (`VERIFY_STATUS_UNKNOWN_INDEX`; see [`crate::builders`]).
    UnknownBuilder { index: u64 },
}

/// A signer the caller must never have sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Violation {
    #[error("validator {index} carries an inline pubkey on gossip")]
    InlineOnGossip { index: u64 },
    #[error("validator {index} carries an inline pubkey but is already cached")]
    InlineForCachedIndex { index: u64 },
    #[error("builder {index} carries an inline pubkey on gossip")]
    BuilderInlineOnGossip { index: u64 },
}

/// Splits import items (signature sets) into batches of at most [`MAX_SETS_PER_BATCH`] items and
/// at most [`MAX_INLINE_KEYS_PER_BATCH`] inline keys, in input order. `inline_keys` gives the
/// number of inline keys each item carries.
///
/// Items are packed greedily: a new batch starts only when the current one already holds
/// [`MAX_SETS_PER_BATCH`] items or the next item would push it over the inline cap, whichever
/// comes first. Empty input yields no batches. An item that alone exceeds the cap (it cannot
/// be divided, e.g. one aggregate set) is never rejected: it forms a batch by itself.
pub fn split_import_batch<T>(
    items: impl IntoIterator<Item = T>,
    inline_keys: impl Fn(&T) -> usize,
) -> Vec<Vec<T>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut weight = 0usize;
    for item in items {
        let w = inline_keys(&item);
        let full = current.len() == MAX_SETS_PER_BATCH;
        if !current.is_empty() && (full || weight.saturating_add(w) > MAX_INLINE_KEYS_PER_BATCH) {
            batches.push(std::mem::take(&mut current));
            weight = 0;
        }
        weight = weight.saturating_add(w);
        current.push(item);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}
