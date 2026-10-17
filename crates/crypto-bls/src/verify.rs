//! Signature verification (feature `verify`).

use crate::{Error, PublicKey, Signature, DST, G2_POINT_AT_INFINITY};
use blst::{blst_scalar, min_pk, BLST_ERROR};
use std::num::NonZeroU64;

/// Bits of each batch randomizer (`u64`).
const RAND_BITS: usize = 64;

/// `Verify(PK, message, signature)`.
///
/// `pk_validate` is off because a [`PublicKey`] has already passed `KeyValidate`; the
/// signature subgroup check is repeated as defence in depth.
#[must_use]
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    signature
        .0
        .verify(true, message, DST, &[], &public_key.0, false)
        == BLST_ERROR::BLST_SUCCESS
}

/// `eth_fast_aggregate_verify` from `altair/bls.md`.
///
/// An empty key set verifies only against `G2_POINT_AT_INFINITY`. That case is decided here,
/// before blst, whose `fast_aggregate_verify` reports `BLST_AGGR_TYPE_MISMATCH` for no keys.
///
/// The keys are summed before the pairing, so they must come from the validator registry
/// (proof of possession), never from gossip; see [`PublicKey`]. Keys that sum to the identity
/// make the check fail.
#[must_use]
pub fn eth_fast_aggregate_verify(
    public_keys: &[&PublicKey],
    message: &[u8],
    signature: &Signature,
) -> bool {
    if public_keys.is_empty() {
        return signature.to_bytes() == G2_POINT_AT_INFINITY;
    }
    let pks: Vec<&min_pk::PublicKey> = public_keys.iter().map(|pk| &pk.0).collect();
    signature.0.fast_aggregate_verify(true, message, DST, &pks) == BLST_ERROR::BLST_SUCCESS
}

/// One signature over `message` by the sum of `public_keys`, for [`verify_batch`]. Use one key
/// for a single signer and several for a fast-aggregate set; the keys must come from the
/// validator registry (proof of possession), see [`PublicKey`].
#[derive(Clone, Copy, Debug)]
pub struct SignatureSet<'a> {
    pub public_keys: &'a [&'a PublicKey],
    pub message: &'a [u8],
    pub signature: &'a Signature,
}

/// Verifies every set at once by random linear combination: `Ok(true)` only if all sets are
/// valid, `Ok(false)` if any is not.
///
/// The randomizers are drawn here, fresh per call, from the OS CSPRNG: if a caller could
/// predict them, invalid signatures could be crafted to cancel out (`S1 + D`, `S2 - D`).
/// Input the batch cannot use is an `Err`, decided before blst runs: no sets, or a set with
/// no keys (blst reports an empty batch as a plain verification failure). A set whose keys
/// sum to the identity fails the whole batch, since blst rejects an identity key.
pub fn verify_batch(sets: &[SignatureSet<'_>]) -> Result<bool, Error> {
    verify_batch_with(sets, os_randomizer)
}

/// [`verify_batch`] with an injected randomizer source. Private: only tests pass a
/// predictable one.
fn verify_batch_with(
    sets: &[SignatureSet<'_>],
    mut randomizer: impl FnMut() -> Result<NonZeroU64, Error>,
) -> Result<bool, Error> {
    if sets.is_empty() {
        return Err(Error::EmptyInput);
    }
    let keys = sets
        .iter()
        .map(|s| set_key(s.public_keys))
        .collect::<Result<Vec<_>, _>>()?;
    let scalars = sets
        .iter()
        .map(|_| randomizer().map(scalar))
        .collect::<Result<Vec<_>, _>>()?;

    let msgs: Vec<&[u8]> = sets.iter().map(|s| s.message).collect();
    let pks: Vec<&min_pk::PublicKey> = keys.iter().collect();
    let sigs: Vec<&min_pk::Signature> = sets.iter().map(|s| &s.signature.0).collect();

    let status = min_pk::Signature::verify_multiple_aggregate_signatures(
        &msgs, DST, &pks, false, &sigs, true, &scalars, RAND_BITS,
    );
    Ok(status == BLST_ERROR::BLST_SUCCESS)
}

/// The key a set is checked against: its only key, or the sum of its keys.
fn set_key(public_keys: &[&PublicKey]) -> Result<min_pk::PublicKey, Error> {
    match public_keys {
        [] => Err(Error::EmptyInput),
        [one] => Ok(one.0),
        many => {
            let pks: Vec<&min_pk::PublicKey> = many.iter().map(|pk| &pk.0).collect();
            Ok(min_pk::AggregatePublicKey::aggregate(&pks, false)?.to_public_key())
        }
    }
}

/// A fresh non-zero 64-bit randomizer from the OS CSPRNG.
fn os_randomizer() -> Result<NonZeroU64, Error> {
    non_zero(getrandom::u64)
}

/// Draws until a non-zero value: a zero randomizer would drop its set from the batch
/// equation. A source that keeps returning zero is broken, so give up after a few draws.
fn non_zero<E>(mut draw: impl FnMut() -> Result<u64, E>) -> Result<NonZeroU64, Error> {
    const MAX_DRAWS: usize = 8;
    for _ in 0..MAX_DRAWS {
        let value = draw().map_err(|_| Error::RandomnessUnavailable)?;
        if let Some(r) = NonZeroU64::new(value) {
            return Ok(r);
        }
    }
    Err(Error::RandomnessUnavailable)
}

/// A randomizer as a little-endian blst scalar.
fn scalar(r: NonZeroU64) -> blst_scalar {
    let mut s = blst_scalar::default();
    s.b[..8].copy_from_slice(&r.get().to_le_bytes());
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> (min_pk::SecretKey, PublicKey) {
        let sk = min_pk::SecretKey::key_gen(&[seed; 32], &[]).unwrap();
        let pk = PublicKey::from_validated_bytes(&sk.sk_to_pk().to_bytes()).unwrap();
        (sk, pk)
    }

    fn signature(sig: &min_pk::Signature) -> Signature {
        Signature::from_validated_bytes(&sig.to_bytes()).unwrap()
    }

    #[test]
    fn non_zero_refuses_zero_draws() {
        let mut draws = [0u64, 0, 7].into_iter();
        assert_eq!(
            non_zero(|| Ok::<_, ()>(draws.next().unwrap())),
            Ok(NonZeroU64::new(7).unwrap())
        );
        assert_eq!(
            non_zero(|| Ok::<_, ()>(0)),
            Err(Error::RandomnessUnavailable)
        );
        assert_eq!(
            non_zero(|| Err::<u64, _>(())),
            Err(Error::RandomnessUnavailable)
        );
        assert!(os_randomizer().is_ok());
    }

    #[test]
    fn randomizer_failure_is_an_error() {
        let (sk, pk) = key(1);
        let sig = signature(&sk.sign(b"m", DST, &[]));
        let set = SignatureSet {
            public_keys: &[&pk],
            message: b"m",
            signature: &sig,
        };
        assert_eq!(
            verify_batch_with(&[set], || Err(Error::RandomnessUnavailable)),
            Err(Error::RandomnessUnavailable)
        );
    }

    #[test]
    fn predictable_randomizers_let_forgeries_cancel() {
        // Why the randomizers are drawn internally: with equal (known) randomizers,
        // S1 + D and S2 - D pass although neither is valid.
        let ((sk1, pk1), (sk2, pk2), (skd, _)) = (key(1), key(2), key(9));
        let d = skd.sign(b"d", DST, &[]);
        let mut neg_d = d.to_bytes();
        neg_d[0] ^= 0x20;
        let neg_d = min_pk::Signature::from_bytes(&neg_d).unwrap();
        let sum = |a: &min_pk::Signature, b: &min_pk::Signature| {
            signature(
                &min_pk::AggregateSignature::aggregate(&[a, b], true)
                    .unwrap()
                    .to_signature(),
            )
        };
        let s1 = sum(&sk1.sign(b"one", DST, &[]), &d);
        let s2 = sum(&sk2.sign(b"two", DST, &[]), &neg_d);
        let sets = [
            SignatureSet {
                public_keys: &[&pk1],
                message: b"one",
                signature: &s1,
            },
            SignatureSet {
                public_keys: &[&pk2],
                message: b"two",
                signature: &s2,
            },
        ];
        let one = || Ok(NonZeroU64::new(1).unwrap());
        assert_eq!(verify_batch_with(&sets, one), Ok(true));
        assert_eq!(verify_batch(&sets), Ok(false));
    }
}
