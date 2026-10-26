//! BLS signature-set verification (blst, `min_pk`, Ethereum POP ciphersuite).
//!
//! Each set's signers go through the cache of their namespace with the request's origin
//! ([`PubkeyCache::resolve_signer`] for validators, [`BuilderKeyCache::resolve_signer`] for Gloas
//! builders); only a [`ResolvedKey`] reaches BLS, and a [`PreparedSet`] can only be built from
//! resolved keys plus a [`ValidatedSignature`]. A builder signer resolves from the cache only if
//! the cached entry has the signer's key version AND its full 48-byte key; the key never comes
//! from the validator cache, and a validator never from the builder cache. The whole batch is
//! then checked with one random-linear-combination multi-pairing using non-zero 64-bit scalars.
//! If the batch fails, each set is re-checked on its own so one bad set never changes the verdict
//! of another.
//!
//! Per-item outcomes before BLS: an unknown index (or a builder with no matching cached entry and
//! no inline key) is `UNKNOWN_INDEX` (IGNORE); a signer of an unknown namespace is an `err` with
//! `ERROR_CODE_VERSION_MISMATCH` (IGNORE, nothing in the set decoded); an inline key for a cached
//! validator index, or a key that is not a valid 48-byte compressed key, is an `err` with
//! `ERROR_CODE_CONTRACT_VIOLATION` (IGNORE); a signing root that is not 32 bytes or a signature
//! that is not a 96-byte compressed, subgroup-checked G2 point is `DECODE_ERROR`. Request-shape
//! violations (a set without signers, an inline key on gossip, the caps) fail the stream in
//! [`crate::caps::check_bls`] before this module runs; the per-item handling of the first two here
//! is a second line of defence for direct callers.

use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::RwLock;

use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::{blst_scalar, BLST_ERROR};
use cl_verify_cache::{
    BuilderKeyCache, BuilderSigner, CompressedPubkey, IgnoreReason, Origin, PubkeyCache,
    Resolution, ResolvedKey, Signer,
};
use rand::RngCore;

use crate::proto::common::ErrorCode;
use crate::proto::verify::{
    bls_result, BlsResult, BlsSet, BuilderSigner as WireBuilderSigner, KeyNamespace,
    Signer as WireSigner, VerifyBlsRequestBody, VerifyOrigin, VerifyStatus,
};
use crate::wire::{wire_error, Deadline, SystemClock, WallClock};

/// Ethereum BLS domain separation tag (proof-of-possession ciphersuite).
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Bits of each random batch scalar.
pub const RAND_BITS: usize = 64;
/// Compressed G1 public key length.
pub const PUBKEY_BYTES: usize = 48;
/// Compressed G2 signature length.
pub const SIGNATURE_BYTES: usize = 96;

/// Decodes a 48-byte compressed public key and runs `KeyValidate` (on curve, in G1, not
/// infinity). blst would also take the 96-byte uncompressed form; the wire contract is compressed
/// only, so any other length is refused first.
#[must_use]
pub fn decode_pubkey(bytes: &[u8]) -> Option<PublicKey> {
    (bytes.len() == PUBKEY_BYTES)
        .then(|| PublicKey::key_validate(bytes).ok())
        .flatten()
}

/// A signature that decoded from exactly 96 compressed bytes and passed the G2 subgroup and
/// infinity checks.
#[derive(Clone, Copy, Debug)]
pub struct ValidatedSignature(Signature);

impl ValidatedSignature {
    #[must_use]
    pub fn from_compressed(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == SIGNATURE_BYTES)
            .then(|| Signature::sig_validate(bytes, true).ok().map(Self))
            .flatten()
    }
}

/// One set ready for the pairing check: signers resolved and aggregated, signature validated.
/// Constructed only by [`PreparedSet::new`] inside this crate; the fields are private so a
/// backend can rely on them having been validated.
#[derive(Clone, Debug)]
pub struct PreparedSet {
    pubkey: PublicKey,
    signing_root: [u8; 32],
    signature: Signature,
}

impl PreparedSet {
    /// `None` if `keys` is empty or the aggregate cannot be formed.
    pub(crate) fn new(
        keys: &[ResolvedKey<'_, PublicKey>],
        signing_root: [u8; 32],
        signature: ValidatedSignature,
    ) -> Option<Self> {
        let pubkey = match keys {
            [] => return None,
            [one] => *one.key(),
            many => {
                let refs: Vec<&PublicKey> = many.iter().map(ResolvedKey::key).collect();
                AggregatePublicKey::aggregate(&refs, false)
                    .ok()?
                    .to_public_key()
            }
        };
        Some(Self {
            pubkey,
            signing_root,
            signature: signature.0,
        })
    }

    /// The (aggregate) key of the set's signers.
    #[must_use]
    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    #[must_use]
    pub fn signing_root(&self) -> &[u8; 32] {
        &self.signing_root
    }

    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// The pairing check behind [`verify_sets`]. Injected so tests can stand in a slow or failing
/// verifier; the server uses [`BlstBackend`].
pub trait BlsBackend: Send + Sync + 'static {
    /// One entry per set, same order: `true` iff that set's signature verifies.
    fn verify(&self, sets: &[PreparedSet]) -> Vec<bool>;
}

/// blst random-linear-combination batch check with a per-set fallback.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlstBackend;

impl BlsBackend for BlstBackend {
    fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
        if sets.is_empty() {
            return Vec::new();
        }
        let mut rng = rand::thread_rng();
        let rands: Vec<blst_scalar> = sets
            .iter()
            .map(|_| scalar(nonzero_u64(|| rng.next_u64())))
            .collect();
        let msgs: Vec<&[u8]> = sets.iter().map(|s| s.signing_root.as_slice()).collect();
        let pks: Vec<&PublicKey> = sets.iter().map(|s| &s.pubkey).collect();
        let sigs: Vec<&Signature> = sets.iter().map(|s| &s.signature).collect();
        // A PreparedSet holds only validated keys and signatures, so blst need not re-check them.
        let batch = Signature::verify_multiple_aggregate_signatures(
            &msgs, DST, &pks, false, &sigs, false, &rands, RAND_BITS,
        );
        if batch == BLST_ERROR::BLST_SUCCESS {
            return vec![true; sets.len()];
        }
        sets.iter()
            .map(|s| {
                s.signature
                    .verify(false, &s.signing_root, DST, &[], &s.pubkey, false)
                    == BLST_ERROR::BLST_SUCCESS
            })
            .collect()
    }
}

/// Draws from `next` until it yields a non-zero value. A zero scalar would drop its set from the
/// batch equation, letting an invalid set pass.
pub fn nonzero_u64(mut next: impl FnMut() -> u64) -> u64 {
    loop {
        let v = next();
        if v != 0 {
            return v;
        }
    }
}

/// `v` as a little-endian blst scalar.
#[must_use]
pub fn scalar(v: u64) -> blst_scalar {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&v.to_le_bytes());
    blst_scalar { b }
}

/// The request's `origin` as the cache's [`Origin`]. `None` for `UNSPECIFIED` and for values this
/// build does not know.
#[must_use]
pub fn origin(wire: i32) -> Option<Origin> {
    match VerifyOrigin::try_from(wire) {
        Ok(VerifyOrigin::Gossip) => Some(Origin::Gossip),
        Ok(VerifyOrigin::Import) => Some(Origin::Import),
        Ok(VerifyOrigin::Unspecified) | Err(_) => None,
    }
}

/// Whether a request with `deadline_unix_ms` may still have its signers resolved at `now_unix_ms`:
/// `now <= deadline`, and never for an unset (0) deadline.
#[must_use]
pub fn deadline_open(deadline_unix_ms: u64, now_unix_ms: u64) -> bool {
    deadline_unix_ms != 0 && now_unix_ms <= deadline_unix_ms
}

/// The key caches a VerifyBls request reads, one per [`KeyNamespace`]. They are separate, so an
/// index of one namespace never resolves to a key of the other.
#[derive(Clone, Copy, Debug)]
pub struct KeyCaches<'a> {
    validators: &'a RwLock<PubkeyCache<PublicKey>>,
    builders: &'a RwLock<BuilderKeyCache<PublicKey>>,
}

impl<'a> KeyCaches<'a> {
    #[must_use]
    pub fn new(
        validators: &'a RwLock<PubkeyCache<PublicKey>>,
        builders: &'a RwLock<BuilderKeyCache<PublicKey>>,
    ) -> Self {
        Self {
            validators,
            builders,
        }
    }
}

/// Read snapshots of both caches, taken together.
struct Snapshot<'a> {
    validators: &'a PubkeyCache<PublicKey>,
    builders: &'a BuilderKeyCache<PublicKey>,
}

/// What stops signer resolution for a request.
enum Stop {
    /// Answer every set `DEADLINE_EXCEEDED`.
    Deadline,
    /// The request's stream is gone: answer nothing.
    Closed,
}

/// The checks made before a request's sets are decoded and right before each is resolved: its
/// stream is still open and its admission [`Deadline`] is open on both clocks (`None`: it had
/// already passed on admission).
struct ResolveGate<'a> {
    deadline: Option<Deadline>,
    closed: &'a AtomicBool,
    clock: &'a dyn WallClock,
}

impl ResolveGate<'_> {
    fn check(&self) -> Result<(), Stop> {
        if self.closed.load(AtomicOrdering::SeqCst) {
            return Err(Stop::Closed);
        }
        if !self.deadline.is_some_and(|d| d.open(self.clock)) {
            return Err(Stop::Deadline);
        }
        Ok(())
    }
}

/// [`verify_request_gated`] for a stream that stays open, with the deadline read now on the
/// system clock.
pub fn verify_request(
    body: &VerifyBlsRequestBody,
    caches: KeyCaches<'_>,
    backend: &dyn BlsBackend,
) -> Vec<BlsResult> {
    let gate = ResolveGate {
        deadline: Deadline::new(body.deadline_unix_ms, &SystemClock),
        closed: &AtomicBool::new(false),
        clock: &SystemClock,
    };
    verify_request_by(body, &gate, caches, backend).unwrap_or_default()
}

/// Verifies one request admitted with `deadline`: one result per set, in order, or `None` if
/// `closed` is set before its sets are decoded or resolved (the stream is gone; nothing is
/// answered and nothing is resolved).
///
/// The gate is the admission `deadline` on both clocks (monotonic and `clock`), so a wall clock
/// that steps backwards cannot reopen a deadline that has passed on the monotonic clock.
///
/// An origin this build does not know is IGNOREd without BLS work: every set gets an `err`
/// (`ERROR_CODE_VERSION_MISMATCH`). The server refuses `UNSPECIFIED` before this point; should it
/// get here, every set is a contract violation.
pub fn verify_request_gated(
    body: &VerifyBlsRequestBody,
    deadline: &Deadline,
    closed: &AtomicBool,
    clock: &dyn WallClock,
    caches: KeyCaches<'_>,
    backend: &dyn BlsBackend,
) -> Option<Vec<BlsResult>> {
    let gate = ResolveGate {
        deadline: Some(*deadline),
        closed,
        clock,
    };
    verify_request_by(body, &gate, caches, backend)
}

fn verify_request_by(
    body: &VerifyBlsRequestBody,
    gate: &ResolveGate<'_>,
    caches: KeyCaches<'_>,
    backend: &dyn BlsBackend,
) -> Option<Vec<BlsResult>> {
    match origin(body.origin) {
        Some(origin) => verify_gated(&body.sets, origin, gate, caches, backend, &decode_set),
        None if body.origin == VerifyOrigin::Unspecified as i32 => Some(
            body.sets
                .iter()
                .map(|_| error(ErrorCode::ContractViolation, "VERIFY_ORIGIN_UNSPECIFIED"))
                .collect(),
        ),
        None => {
            let detail = format!("unknown VerifyOrigin {}", body.origin);
            Some(
                body.sets
                    .iter()
                    .map(|_| error(ErrorCode::VersionMismatch, &detail))
                    .collect(),
            )
        }
    }
}

/// Verifies `sets` from `origin` and returns one result per set, in request order.
///
/// No signer is resolved once `deadline_unix_ms` has passed. The deadline is checked before the
/// signatures and inline keys are decoded (a job that waited past it, or past its stream, does no
/// decode work), again after decoding, then the cache snapshot (read lock) is taken and it is
/// checked right before each set is resolved, so time spent decoding or waiting for the lock
/// (behind a feed append, say) counts. If the deadline has gone by, every set is
/// `DEADLINE_EXCEEDED` with no BLS work, error branches included.
pub fn verify_sets(
    sets: &[BlsSet],
    origin: Origin,
    deadline_unix_ms: u64,
    caches: KeyCaches<'_>,
    backend: &dyn BlsBackend,
) -> Vec<BlsResult> {
    let closed = AtomicBool::new(false);
    let gate = ResolveGate {
        deadline: Deadline::new(deadline_unix_ms, &SystemClock),
        closed: &closed,
        clock: &SystemClock,
    };
    verify_gated(sets, origin, &gate, caches, backend, &decode_set).unwrap_or_default()
}

/// `decode` is [`decode_set`] outside the tests, which count the sets it decodes.
fn verify_gated(
    sets: &[BlsSet],
    origin: Origin,
    gate: &ResolveGate<'_>,
    caches: KeyCaches<'_>,
    backend: &dyn BlsBackend,
    decode: &dyn Fn(&BlsSet) -> Result<DecodedSet, BlsResult>,
) -> Option<Vec<BlsResult>> {
    let stopped = |stop: Stop| match stop {
        Stop::Closed => None,
        Stop::Deadline => Some(all_status(sets.len(), VerifyStatus::DeadlineExceeded)),
    };
    // A job that waited in the pool past its deadline or its stream does no decode work.
    if let Err(stop) = gate.check() {
        return stopped(stop);
    }
    // Cache-independent work first: signatures and inline keys are decoded and validated
    // before the post-decode gate, so time spent on them counts against the deadline.
    let decoded: Vec<Result<DecodedSet, BlsResult>> = sets.iter().map(decode).collect();
    if let Err(stop) = gate.check() {
        return stopped(stop);
    }
    // Then the snapshot of both caches (validators first, the one lock order of every reader),
    // and the gate again immediately before each cache-dependent check.
    let locked = caches
        .validators
        .read()
        .ok()
        .and_then(|v| caches.builders.read().ok().map(|b| (v, b)));
    let prepared: Result<Vec<Result<PreparedSet, BlsResult>>, Stop> = match &locked {
        Some((validators, builders)) => {
            let snapshot = Snapshot {
                validators,
                builders,
            };
            decoded
                .iter()
                .map(|d| {
                    gate.check().map(|()| match d {
                        Ok(d) => resolve_set(d, origin, &snapshot),
                        Err(early) => Err(early.clone()),
                    })
                })
                .collect()
        }
        None => {
            if let Err(stop) = gate.check() {
                return stopped(stop);
            }
            return Some(
                sets.iter()
                    .map(|_| error(ErrorCode::ResourceUnavailable, "pubkey cache unavailable"))
                    .collect(),
            );
        }
    };
    drop(locked);
    let prepared = match prepared {
        Ok(p) => p,
        Err(stop) => return stopped(stop),
    };
    let ready: Vec<PreparedSet> = prepared
        .iter()
        .filter_map(|p| p.as_ref().ok().cloned())
        .collect();
    let verdicts = if ready.is_empty() {
        Vec::new()
    } else {
        backend.verify(&ready)
    };
    // A verifier that answers for the wrong number of sets is not trusted for any of them.
    let mut verdicts = if verdicts.len() == ready.len() {
        verdicts.into_iter()
    } else {
        Vec::new().into_iter()
    };
    let results = prepared
        .into_iter()
        .map(|p| match p {
            Err(early) => early,
            Ok(_) => match verdicts.next() {
                Some(true) => status(VerifyStatus::Valid),
                Some(false) => status(VerifyStatus::Invalid),
                None => error(
                    ErrorCode::ResourceUnavailable,
                    "verifier returned no verdict",
                ),
            },
        })
        .collect();
    Some(results)
}

/// A set whose signature and inline keys have been decoded and validated; nothing in it depends
/// on the cache yet.
struct DecodedSet {
    signers: Vec<DecodedSigner>,
    signing_root: [u8; 32],
    signature: ValidatedSignature,
}

/// One decoded signer, in its namespace.
enum DecodedSigner {
    Validator(Signer<PublicKey>),
    Builder(BuilderSigner<PublicKey>),
}

/// Decodes and resolves one set. The `Err` side is the set's final result (never VALID).
pub fn prepare_set(
    set: &BlsSet,
    origin: Origin,
    validators: &PubkeyCache<PublicKey>,
    builders: &BuilderKeyCache<PublicKey>,
) -> Result<PreparedSet, BlsResult> {
    let snapshot = Snapshot {
        validators,
        builders,
    };
    resolve_set(&decode_set(set)?, origin, &snapshot)
}

/// The cache-independent part of [`prepare_set`].
fn decode_set(set: &BlsSet) -> Result<DecodedSet, BlsResult> {
    if set.signers.is_empty() {
        return Err(error(
            ErrorCode::ContractViolation,
            "BLS set has no signers",
        ));
    }
    // A signer of a namespace this build does not know is IGNOREd before anything is decoded.
    if let Some(unknown) = set
        .signers
        .iter()
        .find(|s| KeyNamespace::try_from(s.namespace).is_err())
    {
        return Err(error(
            ErrorCode::VersionMismatch,
            &format!("unknown KeyNamespace {}", unknown.namespace),
        ));
    }
    let signing_root: [u8; 32] = set
        .signing_root
        .as_slice()
        .try_into()
        .map_err(|_| status(VerifyStatus::DecodeError))?;
    let signature = ValidatedSignature::from_compressed(&set.signature)
        .ok_or_else(|| status(VerifyStatus::DecodeError))?;
    let signers = set
        .signers
        .iter()
        .map(decode_signer)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DecodedSet {
        signers,
        signing_root,
        signature,
    })
}

/// The cache-dependent part of [`prepare_set`]: eligibility, then aggregation.
fn resolve_set(
    set: &DecodedSet,
    origin: Origin,
    snapshot: &Snapshot<'_>,
) -> Result<PreparedSet, BlsResult> {
    let keys = set
        .signers
        .iter()
        .map(|s| resolve_signer(s, origin, snapshot))
        .collect::<Result<Vec<_>, _>>()?;
    PreparedSet::new(&keys, set.signing_root, set.signature)
        .ok_or_else(|| status(VerifyStatus::DecodeError))
}

/// The wire signer in its namespace. A key comes from cl-chain, not from a peer, so one that is
/// not a valid 48-byte compressed key is a contract violation, and so is a signer whose fields do
/// not fit its namespace (the request-shape check in [`crate::caps`] refuses those first).
fn decode_signer(s: &WireSigner) -> Result<DecodedSigner, BlsResult> {
    match (KeyNamespace::try_from(s.namespace), &s.builder) {
        (Ok(KeyNamespace::Validator), None) => decode_validator(s).map(DecodedSigner::Validator),
        (Ok(KeyNamespace::Builder), Some(b))
            if s.validator_index == 0 && s.inline_pubkey.is_empty() =>
        {
            decode_builder(b).map(DecodedSigner::Builder)
        }
        (Ok(KeyNamespace::Unspecified), _) => Err(violation("KEY_NAMESPACE_UNSPECIFIED")),
        (Ok(_), _) => Err(violation("signer fields do not fit its KeyNamespace")),
        (Err(_), _) => Err(error(
            ErrorCode::VersionMismatch,
            &format!("unknown KeyNamespace {}", s.namespace),
        )),
    }
}

fn decode_validator(s: &WireSigner) -> Result<Signer<PublicKey>, BlsResult> {
    if s.inline_pubkey.is_empty() {
        return Ok(Signer::Validator(s.validator_index));
    }
    decode_pubkey(&s.inline_pubkey)
        .map(|key| Signer::Inline {
            index: s.validator_index,
            key,
        })
        .ok_or_else(|| violation("inline pubkey is not a valid 48-byte compressed key"))
}

/// A builder signer: its 48-byte key is only compared with the cache, unless it is inline, when it
/// is decoded and validated.
fn decode_builder(b: &WireBuilderSigner) -> Result<BuilderSigner<PublicKey>, BlsResult> {
    let pubkey: CompressedPubkey = b
        .pubkey
        .as_slice()
        .try_into()
        .map_err(|_| violation("builder pubkey is not 48 bytes"))?;
    if !b.inline {
        return Ok(BuilderSigner::Cached {
            index: b.builder_index,
            version: b.key_version,
            pubkey,
        });
    }
    decode_pubkey(&pubkey)
        .map(|key| BuilderSigner::Inline {
            index: b.builder_index,
            key,
        })
        .ok_or_else(|| violation("inline builder pubkey is not a valid compressed key"))
}

/// The eligibility decision for one signer; the only place a signer becomes a key.
fn resolve_signer<'a>(
    signer: &'a DecodedSigner,
    origin: Origin,
    snapshot: &Snapshot<'a>,
) -> Result<ResolvedKey<'a, PublicKey>, BlsResult> {
    let resolution = match signer {
        DecodedSigner::Validator(s) => snapshot.validators.resolve_signer(s, origin),
        DecodedSigner::Builder(b) => snapshot.builders.resolve_signer(b, origin),
    };
    match resolution {
        Resolution::Resolved(key) => Ok(key),
        Resolution::Ignore(
            IgnoreReason::UnknownIndex { .. } | IgnoreReason::UnknownBuilder { .. },
        ) => Err(status(VerifyStatus::UnknownIndex)),
        Resolution::ContractViolation(v) => Err(violation(&v.to_string())),
    }
}

fn violation(detail: &str) -> BlsResult {
    error(ErrorCode::ContractViolation, detail)
}

fn status(s: VerifyStatus) -> BlsResult {
    BlsResult {
        result: Some(bls_result::Result::Status(s as i32)),
        fence: None,
    }
}

/// Per-item error result.
#[must_use]
pub fn error(code: ErrorCode, detail: &str) -> BlsResult {
    BlsResult {
        result: Some(bls_result::Result::Err(wire_error(code, detail))),
        fence: None,
    }
}

/// Per-item status result for every set (deadline, overload).
#[must_use]
pub fn all_status(n: usize, s: VerifyStatus) -> Vec<BlsResult> {
    vec![status(s); n]
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn sk(i: u64) -> SecretKey {
        let mut ikm = [9u8; 32];
        ikm[..8].copy_from_slice(&i.to_le_bytes());
        SecretKey::key_gen(&ikm, &[]).unwrap()
    }

    /// Both key caches: validators `0..n`, and no builder.
    struct Caches {
        validators: RwLock<PubkeyCache<PublicKey>>,
        builders: RwLock<BuilderKeyCache<PublicKey>>,
    }

    impl Caches {
        fn keys(&self) -> KeyCaches<'_> {
            KeyCaches::new(&self.validators, &self.builders)
        }
    }

    fn cache(n: u64) -> Caches {
        let mut c = PubkeyCache::new();
        c.append_range(0, (0..n).map(|i| sk(i).sk_to_pk()).collect())
            .unwrap();
        Caches {
            validators: RwLock::new(c),
            builders: RwLock::new(BuilderKeyCache::new()),
        }
    }

    fn signer(i: u64) -> WireSigner {
        WireSigner {
            validator_index: i,
            inline_pubkey: vec![],
            namespace: KeyNamespace::Validator as i32,
            builder: None,
        }
    }

    fn inline(i: u64) -> WireSigner {
        WireSigner {
            inline_pubkey: sk(i).sk_to_pk().compress().to_vec(),
            ..signer(i)
        }
    }

    /// Set signed by `keys` over `root`, naming `signers`.
    fn signed(signers: Vec<WireSigner>, keys: &[u64], root: u8) -> BlsSet {
        let msg = [root; 32];
        let sigs: Vec<Signature> = keys.iter().map(|i| sk(*i).sign(&msg, DST, &[])).collect();
        let refs: Vec<&Signature> = sigs.iter().collect();
        let agg = blst::min_pk::AggregateSignature::aggregate(&refs, false).unwrap();
        BlsSet {
            signers,
            signing_root: msg.to_vec(),
            signature: agg.to_signature().compress().to_vec(),
        }
    }

    /// Set signed by cached `signers` over `root`.
    fn set(signers: &[u64], root: u8) -> BlsSet {
        signed(signers.iter().map(|i| signer(*i)).collect(), signers, root)
    }

    fn statuses(results: &[BlsResult]) -> Vec<Result<VerifyStatus, ErrorCode>> {
        results
            .iter()
            .map(|r| match r.result.as_ref().unwrap() {
                bls_result::Result::Status(s) => Ok(VerifyStatus::try_from(*s).unwrap()),
                bls_result::Result::Err(e) => Err(e.code()),
            })
            .collect()
    }

    fn run_from(
        sets: &[BlsSet],
        origin: Origin,
        c: &Caches,
    ) -> Vec<Result<VerifyStatus, ErrorCode>> {
        statuses(&verify_sets(sets, origin, u64::MAX, c.keys(), &BlstBackend))
    }

    fn run(sets: &[BlsSet], c: &Caches) -> Vec<Result<VerifyStatus, ErrorCode>> {
        run_from(sets, Origin::Import, c)
    }

    #[derive(Default)]
    struct Counting(AtomicUsize);
    impl BlsBackend for Arc<Counting> {
        fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
            self.0.fetch_add(1, Ordering::SeqCst);
            BlstBackend.verify(sets)
        }
    }

    #[test]
    fn single_and_fast_aggregate_sets_verify() {
        let c = cache(4);
        assert_eq!(
            run(&[set(&[0], 1), set(&[1, 2, 3], 2)], &c),
            vec![Ok(VerifyStatus::Valid), Ok(VerifyStatus::Valid)]
        );
    }

    #[test]
    fn one_bad_set_does_not_change_the_others() {
        let c = cache(4);
        let mut bad = set(&[2], 3);
        bad.signing_root[0] ^= 1;
        assert_eq!(
            run(&[set(&[0], 1), bad, set(&[1, 3], 2)], &c),
            vec![
                Ok(VerifyStatus::Valid),
                Ok(VerifyStatus::Invalid),
                Ok(VerifyStatus::Valid)
            ]
        );
    }

    #[test]
    fn malformed_bytes_are_decode_errors() {
        let c = cache(2);
        let mut short_root = set(&[0], 1);
        short_root.signing_root.pop();
        let mut short_sig = set(&[0], 1);
        short_sig.signature.pop();
        let mut garbage_sig = set(&[0], 1);
        garbage_sig.signature = vec![0xff; 96];
        let mut infinity_sig = set(&[0], 1);
        infinity_sig.signature = [&[0xc0u8][..], &[0u8; 95][..]].concat();
        assert_eq!(
            run(&[short_root, short_sig, garbage_sig, infinity_sig], &c),
            vec![Ok(VerifyStatus::DecodeError); 4]
        );
    }

    #[test]
    fn uncompressed_encodings_are_refused() {
        let c = cache(2);
        // A correct signature, serialized uncompressed (192 bytes): blst would accept it.
        let mut uncompressed_sig = set(&[0], 1);
        let sig = Signature::from_bytes(&uncompressed_sig.signature).unwrap();
        uncompressed_sig.signature = sig.serialize().to_vec();
        assert_eq!(uncompressed_sig.signature.len(), 192);
        // A correct inline key past the cache, serialized uncompressed (96 bytes).
        let mut uncompressed_key = signed(vec![inline(5)], &[5], 2);
        uncompressed_key.signers[0].inline_pubkey = sk(5).sk_to_pk().serialize().to_vec();
        assert_eq!(
            run(&[uncompressed_sig, uncompressed_key], &c),
            vec![
                Ok(VerifyStatus::DecodeError),
                Err(ErrorCode::ContractViolation)
            ]
        );
        assert!(decode_pubkey(&sk(1).sk_to_pk().serialize()).is_none());
        assert!(decode_pubkey(&sk(1).sk_to_pk().compress()).is_some());
    }

    #[test]
    fn set_without_signers_is_a_per_item_error() {
        let c = cache(2);
        let mut empty = set(&[0], 1);
        empty.signers.clear();
        assert_eq!(
            run(&[empty, set(&[1], 2)], &c),
            vec![Err(ErrorCode::ContractViolation), Ok(VerifyStatus::Valid)]
        );
    }

    #[test]
    fn unknown_index_is_unknown_index_on_either_origin() {
        let c = cache(2);
        for origin in [Origin::Gossip, Origin::Import] {
            assert_eq!(
                run_from(&[set(&[7], 1), set(&[1], 2)], origin, &c),
                vec![Ok(VerifyStatus::UnknownIndex), Ok(VerifyStatus::Valid)]
            );
        }
    }

    #[test]
    fn import_inline_past_high_water_is_used_for_that_call_only() {
        let c = cache(2);
        let mixed = signed(vec![signer(0), inline(5)], &[0, 5], 3);
        let mut bad_inline = signed(vec![inline(6)], &[6], 4);
        bad_inline.signers[0].inline_pubkey = vec![0xaa; 48];
        assert_eq!(
            run(&[signed(vec![inline(5)], &[5], 1), mixed, bad_inline], &c),
            vec![
                Ok(VerifyStatus::Valid),
                Ok(VerifyStatus::Valid),
                Err(ErrorCode::ContractViolation)
            ]
        );
        assert_eq!(
            c.validators.read().unwrap().high_water(),
            2,
            "inline keys never enter the cache"
        );
    }

    #[test]
    fn import_inline_for_a_cached_index_is_a_violation_even_if_equal() {
        let c = cache(2);
        let equal = signed(vec![inline(1)], &[1], 1);
        assert_eq!(
            run(&[equal, set(&[0], 2)], &c),
            vec![Err(ErrorCode::ContractViolation), Ok(VerifyStatus::Valid)]
        );
    }

    #[test]
    fn gossip_inline_is_a_per_item_violation() {
        let c = cache(2);
        let past = signed(vec![inline(5)], &[5], 1);
        let cached = signed(vec![inline(1)], &[1], 2);
        assert_eq!(
            run_from(&[past, cached, set(&[0], 3)], Origin::Gossip, &c),
            vec![
                Err(ErrorCode::ContractViolation),
                Err(ErrorCode::ContractViolation),
                Ok(VerifyStatus::Valid)
            ]
        );
    }

    #[test]
    fn unknown_origin_does_no_bls_work_and_nothing_is_valid() {
        let c = cache(2);
        let counting = Arc::new(Counting::default());
        let body = VerifyBlsRequestBody {
            request_id: 1,
            sets: vec![set(&[0], 1), set(&[1], 2)],
            deadline_unix_ms: u64::MAX,
            origin: 99,
            generation: 0,
        };
        assert_eq!(
            statuses(&verify_request(&body, c.keys(), &counting)),
            vec![Err(ErrorCode::VersionMismatch); 2]
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 0);
        let unspecified = VerifyBlsRequestBody {
            origin: 0,
            ..body.clone()
        };
        assert_eq!(
            statuses(&verify_request(&unspecified, c.keys(), &counting)),
            vec![Err(ErrorCode::ContractViolation); 2]
        );
        let gossip = VerifyBlsRequestBody {
            origin: VerifyOrigin::Gossip as i32,
            ..body
        };
        assert_eq!(
            statuses(&verify_request(&gossip, c.keys(), &counting)),
            vec![Ok(VerifyStatus::Valid); 2]
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_deadline_resolves_no_signer() {
        // Index 1 is cached, so resolving this inline signer would be a contract violation; past
        // the deadline nothing is resolved and every set is DEADLINE_EXCEEDED.
        let c = cache(2);
        let counting = Arc::new(Counting::default());
        let body = VerifyBlsRequestBody {
            request_id: 1,
            sets: vec![signed(vec![inline(1)], &[1], 1), set(&[0], 2)],
            deadline_unix_ms: crate::wire::now_unix_ms() - 1,
            origin: VerifyOrigin::Import as i32,
            generation: 0,
        };
        assert_eq!(
            statuses(&verify_request(&body, c.keys(), &counting)),
            vec![Ok(VerifyStatus::DeadlineExceeded); 2]
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn deadline_is_checked_after_the_cache_snapshot_is_taken() {
        // The request reaches the cache lock while a feed append holds it; the append lands index
        // 5 and the deadline passes before the lock is released. Checking the deadline only before
        // waiting for the lock would resolve the inline signer against the new entry (a contract
        // violation); checking it after taking the snapshot gives DEADLINE_EXCEEDED.
        let c = Arc::new(cache(5));
        let mut writer = c.validators.write().unwrap();
        let body = VerifyBlsRequestBody {
            request_id: 1,
            sets: vec![signed(vec![inline(5)], &[5], 1)],
            deadline_unix_ms: crate::wire::now_unix_ms() + 100,
            origin: VerifyOrigin::Import as i32,
            generation: 0,
        };
        let reader = {
            let c = Arc::clone(&c);
            std::thread::spawn(move || statuses(&verify_request(&body, c.keys(), &BlstBackend)))
        };
        std::thread::sleep(std::time::Duration::from_millis(250));
        writer.append(5, sk(5).sk_to_pk()).unwrap();
        drop(writer);
        assert_eq!(
            reader.join().unwrap(),
            vec![Ok(VerifyStatus::DeadlineExceeded)]
        );
    }

    /// Reads `before` until `after` real time has passed, then `later`.
    struct StepsAfter {
        start: std::time::Instant,
        after: std::time::Duration,
        before: u64,
        later: u64,
    }
    impl WallClock for StepsAfter {
        fn now_unix_ms(&self) -> u64 {
            if self.start.elapsed() < self.after {
                self.before
            } else {
                self.later
            }
        }
    }

    #[test]
    fn deadline_passing_while_inline_keys_decode_stops_before_resolution() {
        // One import set with 3,000 inline signers (all validator 100's key, past the cache).
        // Decoding and KeyValidating them takes far longer than 1 ms; the wall clock passes the
        // deadline 1 ms in. The gate runs after decoding, so nothing is resolved or verified.
        let n = 3_000u64;
        let msg = [7u8; 32];
        let sig = sk(100).sign(&msg, DST, &[]);
        let refs = vec![&sig; n as usize];
        let agg = blst::min_pk::AggregateSignature::aggregate(&refs, false).unwrap();
        let key = sk(100).sk_to_pk().compress().to_vec();
        let body = VerifyBlsRequestBody {
            request_id: 1,
            sets: vec![BlsSet {
                signers: (0..n)
                    .map(|i| WireSigner {
                        inline_pubkey: key.clone(),
                        ..signer(1_000 + i)
                    })
                    .collect(),
                signing_root: msg.to_vec(),
                signature: agg.to_signature().compress().to_vec(),
            }],
            deadline_unix_ms: 10_000,
            origin: VerifyOrigin::Import as i32,
            generation: 0,
        };
        let c = cache(2);
        let counting = Arc::new(Counting::default());
        let clock = StepsAfter {
            start: std::time::Instant::now(),
            after: std::time::Duration::from_millis(1),
            before: 9_999,
            later: 10_001,
        };
        let deadline = Deadline::new(body.deadline_unix_ms, &clock).unwrap();
        let got = verify_request_gated(
            &body,
            &deadline,
            &AtomicBool::new(false),
            &clock,
            c.keys(),
            &counting,
        );
        assert_eq!(
            statuses(&got.unwrap()),
            vec![Ok(VerifyStatus::DeadlineExceeded)]
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 0);
    }

    /// A wall clock the test sets by hand.
    struct Manual(std::sync::atomic::AtomicU64);
    impl WallClock for Manual {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn import_body(sets: Vec<BlsSet>, deadline_unix_ms: u64) -> VerifyBlsRequestBody {
        VerifyBlsRequestBody {
            request_id: 1,
            sets,
            deadline_unix_ms,
            origin: VerifyOrigin::Import as i32,
            generation: 0,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_monotonic_deadline_past_stops_resolution_though_the_wall_clock_stepped_back() {
        let clock = Manual(std::sync::atomic::AtomicU64::new(1_000));
        let body = import_body(vec![set(&[0], 1), set(&[1], 2)], 1_010);
        let deadline = Deadline::new(body.deadline_unix_ms, &clock).unwrap();
        // The job waited past its monotonic deadline; meanwhile the wall clock stepped back, so
        // the wire deadline alone still looks open.
        tokio::time::advance(std::time::Duration::from_millis(20)).await;
        clock.0.store(500, Ordering::SeqCst);
        assert!(deadline_open(body.deadline_unix_ms, clock.now_unix_ms()));
        let c = cache(2);
        let counting = Arc::new(Counting::default());
        let got = verify_request_gated(
            &body,
            &deadline,
            &AtomicBool::new(false),
            &clock,
            c.keys(),
            &counting,
        );
        assert_eq!(
            statuses(&got.unwrap()),
            vec![Ok(VerifyStatus::DeadlineExceeded); 2]
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 0, "no BLS work");
    }

    /// Runs `body` through the gate with a decoder that counts the sets it decodes.
    fn decodes_through_gate(
        body: &VerifyBlsRequestBody,
        deadline: Option<Deadline>,
        closed: bool,
    ) -> (Option<Vec<BlsResult>>, usize) {
        let decoded = AtomicUsize::new(0);
        let counting_decode = |set: &BlsSet| {
            decoded.fetch_add(1, Ordering::SeqCst);
            decode_set(set)
        };
        let closed = AtomicBool::new(closed);
        let gate = ResolveGate {
            deadline,
            closed: &closed,
            clock: &SystemClock,
        };
        let c = cache(2);
        let got = verify_gated(
            &body.sets,
            Origin::Import,
            &gate,
            c.keys(),
            &BlstBackend,
            &counting_decode,
        );
        (got, decoded.load(Ordering::SeqCst))
    }

    #[test]
    fn a_job_past_its_deadline_or_stream_decodes_nothing() {
        // Inline keys past the cache: each would be decoded and KeyValidated.
        let sets = vec![
            signed(vec![inline(5)], &[5], 1),
            signed(vec![inline(6)], &[6], 2),
        ];
        let body = import_body(sets, crate::wire::now_unix_ms() + 60_000);
        let open = Deadline::new(body.deadline_unix_ms, &SystemClock);
        assert!(open.is_some());

        let (got, decoded) = decodes_through_gate(&body, None, false);
        assert_eq!(
            statuses(&got.unwrap()),
            vec![Ok(VerifyStatus::DeadlineExceeded); 2]
        );
        assert_eq!(decoded, 0, "past the deadline nothing is decoded");

        let (got, decoded) = decodes_through_gate(&body, open, true);
        assert!(got.is_none(), "a closed stream answers nothing");
        assert_eq!(decoded, 0, "after stream close nothing is decoded");

        let (got, decoded) = decodes_through_gate(&body, open, false);
        assert_eq!(statuses(&got.unwrap()), vec![Ok(VerifyStatus::Valid); 2]);
        assert_eq!(decoded, 2);
    }

    #[test]
    fn closed_stream_resolves_nothing() {
        let c = cache(2);
        let counting = Arc::new(Counting::default());
        let body = VerifyBlsRequestBody {
            request_id: 1,
            sets: vec![set(&[0], 1), signed(vec![inline(1)], &[1], 2)],
            deadline_unix_ms: u64::MAX,
            origin: VerifyOrigin::Import as i32,
            generation: 0,
        };
        let closed = AtomicBool::new(true);
        let deadline = Deadline::new(body.deadline_unix_ms, &SystemClock).unwrap();
        let run = |closed: &AtomicBool| {
            verify_request_gated(&body, &deadline, closed, &SystemClock, c.keys(), &counting)
        };
        assert!(run(&closed).is_none());
        assert_eq!(counting.0.load(Ordering::SeqCst), 0);
        closed.store(false, Ordering::SeqCst);
        assert_eq!(
            statuses(&run(&closed).unwrap()),
            vec![Ok(VerifyStatus::Valid), Err(ErrorCode::ContractViolation)]
        );
    }

    #[test]
    fn poisoned_cache_past_the_deadline_is_deadline_exceeded() {
        let c = Arc::new(cache(2));
        let c2 = Arc::clone(&c);
        let _ = std::thread::spawn(move || {
            let _g = c2.validators.write().unwrap();
            panic!("poison");
        })
        .join();
        assert_eq!(
            statuses(&verify_sets(
                &[set(&[0], 1)],
                Origin::Import,
                0,
                c.keys(),
                &BlstBackend
            )),
            vec![Ok(VerifyStatus::DeadlineExceeded)]
        );
    }

    #[test]
    fn deadline_is_open_up_to_and_including_its_millisecond() {
        assert!(deadline_open(1_000, 999));
        assert!(deadline_open(1_000, 1_000));
        assert!(!deadline_open(1_000, 1_001));
        assert!(!deadline_open(0, 0), "an unset deadline is never open");
    }

    #[test]
    fn prepared_set_needs_at_least_one_resolved_key() {
        let sig = ValidatedSignature::from_compressed(&set(&[0], 1).signature).unwrap();
        assert!(PreparedSet::new(&[], [1; 32], sig).is_none());
        let c = cache(1);
        let (validators, builders) = (c.validators.read().unwrap(), c.builders.read().unwrap());
        let snapshot = Snapshot {
            validators: &validators,
            builders: &builders,
        };
        let signer = DecodedSigner::Validator(Signer::Validator(0));
        let key = resolve_signer(&signer, Origin::Gossip, &snapshot).unwrap();
        let p = PreparedSet::new(&[key], [1; 32], sig).unwrap();
        assert_eq!(p.pubkey(), &sk(0).sk_to_pk());
        assert_eq!(p.signing_root(), &[1; 32]);
        assert!(BlstBackend.verify(std::slice::from_ref(&p)) == vec![true]);
        let _ = p.signature();
    }

    #[test]
    fn empty_request_yields_no_results() {
        assert!(
            verify_sets(&[], Origin::Gossip, u64::MAX, cache(1).keys(), &BlstBackend).is_empty()
        );
    }

    #[test]
    fn wrong_length_backend_answer_is_an_error_never_valid() {
        struct Short;
        impl BlsBackend for Short {
            fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
                vec![true; sets.len() - 1]
            }
        }
        let c = cache(2);
        assert_eq!(
            statuses(&verify_sets(
                &[set(&[0], 1), set(&[1], 2)],
                Origin::Import,
                u64::MAX,
                c.keys(),
                &Short
            )),
            vec![Err(ErrorCode::ResourceUnavailable); 2]
        );
    }

    #[test]
    fn poisoned_cache_is_an_error_for_every_set() {
        let c = Arc::new(cache(2));
        let c2 = Arc::clone(&c);
        let _ = std::thread::spawn(move || {
            let _g = c2.validators.write().unwrap();
            panic!("poison");
        })
        .join();
        assert_eq!(
            run(&[set(&[0], 1), set(&[1], 2)], &c),
            vec![Err(ErrorCode::ResourceUnavailable); 2]
        );
    }

    // Builder signers.

    /// Builder `i`'s key: another secret than validator `i`'s.
    fn builder_sk(i: u64) -> SecretKey {
        sk(1_000_000 + i)
    }

    fn builder_signer(i: u64, version: u64, key: &SecretKey, inline: bool) -> WireSigner {
        WireSigner {
            validator_index: 0,
            inline_pubkey: vec![],
            namespace: KeyNamespace::Builder as i32,
            builder: Some(WireBuilderSigner {
                builder_index: i,
                key_version: version,
                pubkey: key.sk_to_pk().compress().to_vec(),
                inline,
            }),
        }
    }

    /// A set over `[root; 32]` signed by `key`, naming `signer`.
    fn signed_by(signer: WireSigner, key: &SecretKey, root: u8) -> BlsSet {
        let msg = [root; 32];
        BlsSet {
            signers: vec![signer],
            signing_root: msg.to_vec(),
            signature: key.sign(&msg, DST, &[]).compress().to_vec(),
        }
    }

    /// Validators `0..n`, and builders `0..n` with version `100 + i`.
    fn with_builders(n: u64) -> Caches {
        let c = cache(n);
        let entries = (0..n)
            .map(|i| {
                let key = builder_sk(i).sk_to_pk();
                cl_verify_cache::BuilderEntry::new(100 + i, key.compress(), key)
            })
            .collect();
        c.builders
            .write()
            .unwrap()
            .append_range(0, entries)
            .unwrap();
        c
    }

    #[test]
    fn a_builder_resolves_only_from_the_builder_cache_and_only_with_its_full_key() {
        let c = with_builders(3);
        let b1 = builder_sk(1);
        let other = builder_sk(9);
        let sets = [
            // The cached builder key, named with its version and its full key.
            signed_by(builder_signer(1, 101, &b1, false), &b1, 1),
            // The right version with another key (a version collision): never the cached key.
            signed_by(builder_signer(1, 101, &other, false), &other, 2),
            // The right key with another version.
            signed_by(builder_signer(1, 102, &b1, false), &b1, 3),
            // Past the builder high-water mark.
            signed_by(
                builder_signer(3, 103, &builder_sk(3), false),
                &builder_sk(3),
                4,
            ),
            // Builder 1's signature named as validator 1: the validator key does not verify it.
            signed_by(signer(1), &b1, 5),
        ];
        for origin in [Origin::Gossip, Origin::Import] {
            assert_eq!(
                run_from(&sets, origin, &c),
                vec![
                    Ok(VerifyStatus::Valid),
                    Ok(VerifyStatus::UnknownIndex),
                    Ok(VerifyStatus::UnknownIndex),
                    Ok(VerifyStatus::UnknownIndex),
                    Ok(VerifyStatus::Invalid),
                ]
            );
        }
    }

    #[test]
    fn an_inline_builder_key_resolves_on_import_only() {
        let c = with_builders(2);
        let fresh = builder_sk(7);
        let inline = signed_by(builder_signer(5, 7, &fresh, true), &fresh, 1);
        // An inline key for a cached index is used too: the key, not the mark, decides.
        let reused = signed_by(builder_signer(1, 7, &fresh, true), &fresh, 2);
        assert_eq!(
            run(&[inline.clone(), reused], &c),
            vec![Ok(VerifyStatus::Valid), Ok(VerifyStatus::Valid)]
        );
        assert_eq!(
            run_from(&[inline], Origin::Gossip, &c),
            vec![Err(ErrorCode::ContractViolation)]
        );
        assert_eq!(c.builders.read().unwrap().high_water(), 2, "never cached");
    }

    #[test]
    fn a_malformed_builder_signer_is_a_per_item_violation() {
        let c = with_builders(2);
        let b0 = builder_sk(0);
        let mut short = signed_by(builder_signer(0, 100, &b0, false), &b0, 1);
        short.signers[0].builder.as_mut().unwrap().pubkey.pop();
        let mut bad_inline = signed_by(builder_signer(0, 100, &b0, true), &b0, 2);
        bad_inline.signers[0].builder.as_mut().unwrap().pubkey = vec![0xaa; 48];
        let mut no_builder = signed_by(builder_signer(0, 100, &b0, false), &b0, 3);
        no_builder.signers[0].builder = None;
        let mut validator_with_builder = set(&[0], 4);
        validator_with_builder.signers[0].builder = builder_signer(0, 100, &b0, false).builder;
        let mut unspecified = set(&[0], 5);
        unspecified.signers[0].namespace = KeyNamespace::Unspecified as i32;
        assert_eq!(
            run(
                &[
                    short,
                    bad_inline,
                    no_builder,
                    validator_with_builder,
                    unspecified
                ],
                &c
            ),
            vec![Err(ErrorCode::ContractViolation); 5]
        );
    }

    #[test]
    fn a_signer_of_an_unknown_namespace_is_ignored_before_anything_is_decoded() {
        let c = with_builders(2);
        let counting = Arc::new(Counting::default());
        let mut unknown = set(&[0], 1);
        unknown.signers[0].namespace = 99;
        // A signature that would be a DECODE_ERROR if it were decoded.
        unknown.signature = vec![0xff; 96];
        let body = import_body(vec![unknown, set(&[1], 2)], u64::MAX);
        assert_eq!(
            statuses(&verify_request(&body, c.keys(), &counting)),
            vec![Err(ErrorCode::VersionMismatch), Ok(VerifyStatus::Valid)]
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_poisoned_builder_cache_is_an_error_for_every_set() {
        let c = Arc::new(with_builders(1));
        let c2 = Arc::clone(&c);
        let _ = std::thread::spawn(move || {
            let _g = c2.builders.write().unwrap();
            panic!("poison");
        })
        .join();
        assert_eq!(
            run(&[set(&[0], 1)], &c),
            vec![Err(ErrorCode::ResourceUnavailable)]
        );
    }

    #[test]
    fn prepare_set_resolves_a_builder_from_the_given_caches() {
        let c = with_builders(1);
        let b0 = builder_sk(0);
        let (validators, builders) = (c.validators.read().unwrap(), c.builders.read().unwrap());
        let ok = signed_by(builder_signer(0, 100, &b0, false), &b0, 1);
        let p = prepare_set(&ok, Origin::Gossip, &validators, &builders).unwrap();
        assert_eq!(p.pubkey(), &b0.sk_to_pk());
        let miss = signed_by(builder_signer(0, 100, &builder_sk(5), false), &b0, 1);
        assert!(prepare_set(&miss, Origin::Gossip, &validators, &builders).is_err());
    }

    #[test]
    fn batch_scalars_are_never_zero() {
        let mut seq = [0u64, 0, 0, 42].into_iter();
        assert_eq!(nonzero_u64(|| seq.next().unwrap()), 42);
        let s = scalar(0x0102_0304_0506_0708);
        assert_eq!(&s.b[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert!(s.b[8..].iter().all(|b| *b == 0));
    }
}
