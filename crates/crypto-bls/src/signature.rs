use crate::Error;
use blst::min_pk;

/// Length of a compressed G2 signature.
pub const SIGNATURE_BYTES_LEN: usize = 96;

/// `G2_POINT_AT_INFINITY` from `altair/bls.md`: the compressed G2 identity.
pub const G2_POINT_AT_INFINITY: [u8; SIGNATURE_BYTES_LEN] = {
    let mut bytes = [0u8; SIGNATURE_BYTES_LEN];
    bytes[0] = 0xc0;
    bytes
};

/// A BLS signature: a G2 point in the prime-order subgroup.
///
/// The identity is allowed: it is a valid signature encoding (`G2_POINT_AT_INFINITY`), and
/// `eth_fast_aggregate_verify` accepts it for an empty key set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub(crate) min_pk::Signature);

impl Signature {
    /// Decodes a compressed signature and runs the G2 subgroup check.
    ///
    /// The identity passes the check (`sig_validate(bytes, false)`); every pairing check
    /// still rejects it against a non-identity key.
    pub fn from_validated_bytes(bytes: &[u8; SIGNATURE_BYTES_LEN]) -> Result<Self, Error> {
        min_pk::Signature::sig_validate(bytes, false)
            .map(Self)
            .map_err(Error::from)
    }

    /// The compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.0.to_bytes()
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::fmt_encoded(f, "Signature", &self.to_bytes())
    }
}
