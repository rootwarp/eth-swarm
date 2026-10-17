//! Spec-vector helpers (feature `test-vectors`). Only spec-tests may enable this feature;
//! `scripts/check-bls-features.sh` enforces that.

use crate::{Error, PublicKey, Signature, DST};
use blst::{min_pk, BLST_ERROR};

/// `Sign(SK, message)`. A zero or out-of-range secret key is [`Error::BadEncoding`].
pub fn sign(secret_key: &[u8; 32], message: &[u8]) -> Result<Signature, Error> {
    let sk = min_pk::SecretKey::from_bytes(secret_key)?;
    Ok(Signature(sk.sign(message, DST, &[])))
}

/// `Aggregate(signatures)`. Empty input is an error.
pub fn aggregate_signatures(signatures: &[&Signature]) -> Result<Signature, Error> {
    if signatures.is_empty() {
        return Err(Error::EmptyInput);
    }
    let sigs: Vec<&min_pk::Signature> = signatures.iter().map(|s| &s.0).collect();
    let aggregate = min_pk::AggregateSignature::aggregate(&sigs, false)?;
    Ok(Signature(aggregate.to_signature()))
}

/// `AggregateVerify(PKs, messages, signature)` of the proof-of-possession scheme (no message
/// uniqueness check). Empty or mismatched inputs are `false`.
#[must_use]
pub fn aggregate_verify(
    public_keys: &[&PublicKey],
    messages: &[&[u8]],
    signature: &Signature,
) -> bool {
    let pks: Vec<&min_pk::PublicKey> = public_keys.iter().map(|pk| &pk.0).collect();
    signature
        .0
        .aggregate_verify(true, messages, DST, &pks, false)
        == BLST_ERROR::BLST_SUCCESS
}
