use crate::Error;
use blst::min_pk;

/// Length of a compressed G1 public key.
pub const PUBLIC_KEY_BYTES_LEN: usize = 48;

/// A BLS public key that passed `KeyValidate`: a G1 point in the prime-order subgroup, not the
/// identity. Every `PublicKey` holds this; sums of keys get their own output-only type
/// (`AggregatePublicKey`, feature `aggregate`), which may be the identity.
///
/// `KeyValidate` is not proof of possession. Aggregating keys whose owner never proved
/// knowledge of the secret allows rogue-key forgeries (`-P + Q` keys that cancel an honest
/// signer). Keys fed to `eth_fast_aggregate_verify`, `eth_aggregate_pubkeys` or a
/// multi-signer batch set must come from the validator registry, whose deposits were
/// signature-checked; never aggregate keys taken from gossip or another untrusted source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub(crate) min_pk::PublicKey);

impl PublicKey {
    /// Decodes a compressed key and runs `KeyValidate` (subgroup check, identity rejected).
    /// This checks the point only, not proof of possession; see the type docs.
    pub fn from_validated_bytes(bytes: &[u8; PUBLIC_KEY_BYTES_LEN]) -> Result<Self, Error> {
        min_pk::PublicKey::key_validate(bytes)
            .map(Self)
            .map_err(Error::from)
    }

    /// The compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.0.to_bytes()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::fmt_encoded(f, "PublicKey", &self.to_bytes())
    }
}
