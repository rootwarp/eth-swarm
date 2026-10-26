//! The signature seam of the pure state transition.
//!
//! The transition only builds [`SignatureSet`]s; a [`SignatureBackend`] that the caller
//! supplies checks them. cl-chain uses cl-verify, and the spec-vector runner can use an
//! in-process BLS backend. A set names its signers by [`SignerRef`], never by key material,
//! for registry members.

pub use consensus_types::signing::{SignatureSet, SignerRef};

use crate::accessors::get_domain;
use crate::{Preset, StfError};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::signing::{compute_signing_root, DOMAIN_BEACON_PROPOSER};

/// The backend gave no verdict (a timeout, an overload, an unknown signer). This is never a
/// proof that a signature is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("signature backend gave no verdict: {0}")]
pub struct BackendError(pub String);

/// Checks signature sets for the state transition. Calls are synchronous.
pub trait SignatureBackend {
    /// `Ok(true)` if every set in `sets` is valid, `Ok(false)` if at least one is not.
    ///
    /// A key or a signature that does not decode, or a key that fails `KeyValidate`, makes
    /// its set invalid: `Ok(false)`, never `Err`. The spec needs this for the inline keys of
    /// deposits ([`SignerRef::Inline`]): `bls.Verify` returns `False` for such a key, and the
    /// deposit is ignored. `Err` is only for a backend that is not available or that fails
    /// (for example a timeout, an overload or a verdict that was not fetched).
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError>;
}

/// The proposer signature set of a block: `verify_block_signature` (P0 L1839-1844) without
/// the BLS call.
pub fn block_proposer_signature_set<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
) -> Result<SignatureSet, StfError> {
    let block = &signed_block.message;
    if block.proposer_index >= state.validators.len() as u64 {
        return Err(StfError::UnknownValidator(block.proposer_index));
    }
    let domain = get_domain(state, DOMAIN_BEACON_PROPOSER, None);
    Ok(SignatureSet::single(
        SignerRef::Validator(block.proposer_index),
        compute_signing_root(block, domain),
        signed_block.signature,
    ))
}

/// `verify_block_signature` (P0 L1839-1844) through `backend`.
pub fn verify_block_signature<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let set = block_proposer_signature_set(state, signed_block)?;
    if backend.verify_signature_sets(std::slice::from_ref(&set))? {
        Ok(())
    } else {
        Err(StfError::InvalidBlockSignature)
    }
}
