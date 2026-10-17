//! Public-key aggregation (feature `aggregate`).

use crate::{Error, PublicKey, PUBLIC_KEY_BYTES_LEN};
use blst::min_pk;

/// The output of [`eth_aggregate_pubkeys`]: a sum of validated keys.
///
/// It is in the subgroup but may be the identity (keys `P` and `-P` cancel), which the spec
/// returns rather than rejects. It is output-only: there is no conversion to [`PublicKey`],
/// and its identity encoding fails [`PublicKey::from_validated_bytes`], so a cancelled sum can
/// never come back in as a signer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AggregatePublicKey(min_pk::PublicKey);

impl AggregatePublicKey {
    /// The compressed encoding (e.g. `SyncCommittee.aggregate_pubkey`).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.0.to_bytes()
    }
}

impl std::fmt::Debug for AggregatePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::fmt_encoded(f, "AggregatePublicKey", &self.to_bytes())
    }
}

/// `eth_aggregate_pubkeys` from `altair/bls.md`: the sum of `public_keys`.
///
/// Every input passed `KeyValidate` by construction, so blst skips re-validating them. Empty
/// input is an error because the spec asserts `len(pubkeys) > 0`. The keys must come from the
/// validator registry (proof of possession); see [`PublicKey`].
pub fn eth_aggregate_pubkeys(public_keys: &[&PublicKey]) -> Result<AggregatePublicKey, Error> {
    if public_keys.is_empty() {
        return Err(Error::EmptyInput);
    }
    let pks: Vec<&min_pk::PublicKey> = public_keys.iter().map(|pk| &pk.0).collect();
    let aggregate = min_pk::AggregatePublicKey::aggregate(&pks, false)?;
    Ok(AggregatePublicKey(aggregate.to_public_key()))
}
