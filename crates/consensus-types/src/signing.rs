//! Signing domains and roots (`phase0/beacon-chain.md`), and signature-set descriptions.
//!
//! A [`SignatureSet`] names who must have signed which root; it carries no key material for
//! registry members, so `cl-verify` resolves [`SignerRef::Validator`] through its finalized
//! pubkey cache and treats an unresolved signer as IGNORE, never ACCEPT.

use crate::common::{ForkData, SigningData};
use crate::primitives::{
    BLSPubkey, BLSSignature, BuilderIndex, Domain, DomainType, Root, ValidatorIndex, Version,
};
use tree_hash::TreeHash;

/// `DOMAIN_BEACON_PROPOSER`.
pub const DOMAIN_BEACON_PROPOSER: DomainType = [0x00, 0, 0, 0];
/// `DOMAIN_BEACON_ATTESTER`.
pub const DOMAIN_BEACON_ATTESTER: DomainType = [0x01, 0, 0, 0];
/// `DOMAIN_RANDAO`.
pub const DOMAIN_RANDAO: DomainType = [0x02, 0, 0, 0];
/// `DOMAIN_DEPOSIT`.
pub const DOMAIN_DEPOSIT: DomainType = [0x03, 0, 0, 0];
/// `DOMAIN_VOLUNTARY_EXIT`.
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = [0x04, 0, 0, 0];
/// `DOMAIN_SELECTION_PROOF`.
pub const DOMAIN_SELECTION_PROOF: DomainType = [0x05, 0, 0, 0];
/// `DOMAIN_AGGREGATE_AND_PROOF`.
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = [0x06, 0, 0, 0];
/// `DOMAIN_SYNC_COMMITTEE` (Altair).
pub const DOMAIN_SYNC_COMMITTEE: DomainType = [0x07, 0, 0, 0];
/// `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` (Altair).
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = [0x08, 0, 0, 0];
/// `DOMAIN_CONTRIBUTION_AND_PROOF` (Altair).
pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = [0x09, 0, 0, 0];
/// `DOMAIN_BLS_TO_EXECUTION_CHANGE` (Capella).
pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: DomainType = [0x0a, 0, 0, 0];
/// `DOMAIN_BEACON_BUILDER` (Gloas).
pub const DOMAIN_BEACON_BUILDER: DomainType = [0x0b, 0, 0, 0];
/// `DOMAIN_PTC_ATTESTER` (Gloas).
pub const DOMAIN_PTC_ATTESTER: DomainType = [0x0c, 0, 0, 0];
/// `DOMAIN_PROPOSER_PREFERENCES` (Gloas).
pub const DOMAIN_PROPOSER_PREFERENCES: DomainType = [0x0d, 0, 0, 0];
/// `DOMAIN_BUILDER_DEPOSIT` (Gloas).
pub const DOMAIN_BUILDER_DEPOSIT: DomainType = [0x0e, 0, 0, 0];
/// `DOMAIN_APPLICATION_MASK`.
pub const DOMAIN_APPLICATION_MASK: DomainType = [0x00, 0, 0, 0x01];

/// `BUILDER_INDEX_SELF_BUILD` (`gloas/beacon-chain.md` L571): the builder index of a bid and an
/// envelope that the proposer builds itself.
pub const BUILDER_INDEX_SELF_BUILD: BuilderIndex = u64::MAX;

/// `compute_fork_data_root`: `hash_tree_root(ForkData(current_version, genesis_validators_root))`.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root {
    ForkData {
        current_version,
        genesis_validators_root,
    }
    .tree_hash_root()
}

/// `compute_domain`: `domain_type + compute_fork_data_root(fork_version, gvr)[:28]`.
///
/// The spec's defaults (`GENESIS_FORK_VERSION`, a zero root) are network-specific, so both are
/// required here.
pub fn compute_domain(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Root,
) -> Domain {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    Domain::from(domain)
}

/// `compute_signing_root`: `hash_tree_root(SigningData(hash_tree_root(object), domain))`.
pub fn compute_signing_root<T: TreeHash>(object: &T, domain: Domain) -> Root {
    SigningData {
        object_root: object.tree_hash_root(),
        domain,
    }
    .tree_hash_root()
}

/// Who a signature must come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignerRef {
    /// A validator, by registry index.
    Validator(ValidatorIndex),
    /// A Gloas builder, by builder-registry index and the version of its key.
    ///
    /// A builder index is reusable: a new key can take the index of a builder that exited
    /// (see `state_transition::per_block::builder`), also on a branch that is not finalized.
    /// Thus `(index, version)` is not a safe cache key. The `version` is a lookup hint only:
    /// a cache of builder keys compares the cached full key with `state.builders[index].pubkey`
    /// of the state that the signature is verified against on every hit, or the signer
    /// carries its key inline (`verify.v1` `BuilderSigner`).
    Builder {
        /// Index into `state.builders`.
        index: BuilderIndex,
        /// `state_transition::accessors::builder_key_version` of the state: a 64-bit digest
        /// of `state.builders[index].pubkey`, so two keys can have the same value. It is not
        /// `Builder.version`, which is the same for each payload builder.
        version: u64,
    },
    /// A key carried by the message itself (deposits, BLS-to-execution changes, new indices past
    /// the finalized registry).
    ///
    /// The key is not checked. A verifier gives an invalid verdict (not an error) for a key
    /// that does not decode or fails `KeyValidate`, and also for a signature that does not
    /// decode. An error is only for a verifier that is not available or that fails.
    Inline(BLSPubkey),
}

/// The signer of an execution payload envelope by `builder_index`, as
/// `verify_execution_payload_envelope_signature` selects it (`gloas/beacon-chain.md`
/// L2104-2115).
///
/// - A self-build envelope ([`BUILDER_INDEX_SELF_BUILD`]) is signed by the proposer with its
///   validator key: [`SignerRef::Validator`] of `proposer_index`
///   (`state.latest_block_header.proposer_index`). A builder key never signs it, and the
///   verifier makes no builder-key lookup for it. `version` is not used.
/// - Any other envelope is signed by `state.builders[builder_index].pubkey`:
///   [`SignerRef::Builder`] with `version`, the `builder_key_version` of that state. The
///   version is a lookup hint only (see [`SignerRef::Builder`]).
///
/// The function selects the signer only. The signing root (`DOMAIN_BEACON_BUILDER`) and the
/// signature check are the caller's.
pub fn envelope_signer(
    builder_index: BuilderIndex,
    proposer_index: ValidatorIndex,
    version: u64,
) -> SignerRef {
    if builder_index == BUILDER_INDEX_SELF_BUILD {
        SignerRef::Validator(proposer_index)
    } else {
        SignerRef::Builder {
            index: builder_index,
            version,
        }
    }
}

/// A signature set with no signers cannot be verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureSetError {
    /// `signers` was empty.
    #[error("a signature set needs at least one signer")]
    NoSigners,
}

/// One BLS check: `signature` by all of `signers` over `signing_root` (aggregate when several).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureSet {
    signers: Vec<SignerRef>,
    signing_root: Root,
    signature: BLSSignature,
}

impl SignatureSet {
    /// A set with one signer (`bls.Verify`).
    pub fn single(signer: SignerRef, signing_root: Root, signature: BLSSignature) -> Self {
        Self {
            signers: vec![signer],
            signing_root,
            signature,
        }
    }

    /// A set with several signers over one root (`bls.FastAggregateVerify`).
    pub fn aggregate(
        signers: Vec<SignerRef>,
        signing_root: Root,
        signature: BLSSignature,
    ) -> Result<Self, SignatureSetError> {
        if signers.is_empty() {
            return Err(SignatureSetError::NoSigners);
        }
        Ok(Self {
            signers,
            signing_root,
            signature,
        })
    }

    /// The signers, never empty.
    pub fn signers(&self) -> &[SignerRef] {
        &self.signers
    }

    /// The root that was signed.
    pub fn signing_root(&self) -> Root {
        self.signing_root
    }

    /// The (aggregate) signature.
    pub fn signature(&self) -> &BLSSignature {
        &self.signature
    }
}
