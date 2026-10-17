//! Subgroup-checked BLS12-381 signatures for the Ethereum consensus layer, on blst `min_pk`.
//!
//! Follows consensus-specs `phase0/beacon-chain.md` §BLS signatures (the IETF proof-of-possession
//! scheme with `KeyValidate`) and `altair/bls.md` (`eth_aggregate_pubkeys`,
//! `eth_fast_aggregate_verify`).
//!
//! The only way to get a [`PublicKey`] or [`Signature`] from bytes is `from_validated_bytes`,
//! which runs the subgroup check (and, for keys, rejects the identity). The blst types stay
//! private, so nothing downstream can build an unchecked point.
//!
//! Cargo features pick what a service links:
//! - `verify`: `verify`, `eth_fast_aggregate_verify`, `verify_batch`.
//! - `aggregate`: `eth_aggregate_pubkeys`. cl-chain links only this one.
//! - `test-vectors` (dev-only, spec-tests only): `sign`, `aggregate_signatures`,
//!   `aggregate_verify`.
//!
//! `scripts/check-bls-features.sh` checks that only spec-tests *declares* `test-vectors`.
//! Cargo unifies features per build, so any build that includes spec-tests (such as
//! `cargo build --workspace`) has `test-vectors` on for every crate in it. Ship services from
//! per-service builds (`cargo build -p <svc> --locked`); CI will build each service alone once
//! service crates exist.
//!
//! Point validation is not proof of possession. Keys that are aggregated
//! (`eth_fast_aggregate_verify`, `eth_aggregate_pubkeys`, multi-signer batch sets) must come
//! from the validator registry, whose deposits were signature-checked.

#[cfg(feature = "aggregate")]
mod aggregate;
mod error;
mod keys;
mod signature;
#[cfg(feature = "test-vectors")]
mod test_vectors;
#[cfg(feature = "verify")]
mod verify;

#[cfg(feature = "aggregate")]
pub use aggregate::{eth_aggregate_pubkeys, AggregatePublicKey};
pub use error::Error;
pub use keys::{PublicKey, PUBLIC_KEY_BYTES_LEN};
pub use signature::{Signature, G2_POINT_AT_INFINITY, SIGNATURE_BYTES_LEN};
#[cfg(feature = "test-vectors")]
pub use test_vectors::{aggregate_signatures, aggregate_verify, sign};
#[cfg(feature = "verify")]
pub use verify::{eth_fast_aggregate_verify, verify, verify_batch, SignatureSet};

/// Hash-to-curve domain separation tag of the proof-of-possession ciphersuite.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Writes `name(0x<hex>)` for a point's compressed encoding.
fn fmt_encoded(f: &mut std::fmt::Formatter<'_>, name: &str, bytes: &[u8]) -> std::fmt::Result {
    write!(f, "{name}(0x")?;
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    write!(f, ")")
}
