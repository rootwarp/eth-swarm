//! Signing roots and domains as defined in `phase0/beacon-chain.md`.

mod common;

use consensus_types::common::{ForkData, SigningData, VoluntaryExit};
use consensus_types::primitives::*;
use consensus_types::signing::{
    compute_domain, compute_fork_data_root, compute_signing_root, SignatureSet, SignatureSetError,
    SignerRef, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_BUILDER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_VOLUNTARY_EXIT,
};
use consensus_types::Minimal;
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use tree_hash::TreeHash;

/// `hash_tree_root` of a two-field container of 32-byte leaves: `sha256(a || b)`.
fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn chunk(bytes: &[u8]) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..bytes.len()].copy_from_slice(bytes);
    c
}

proptest! {
    #[test]
    fn signing_root_matches_spec_def(
        domain_type in any::<[u8; 4]>(),
        version in any::<[u8; 4]>(),
        gvr in any::<[u8; 32]>(),
        epoch in any::<u64>(),
        validator_index in any::<u64>(),
    ) {
        let genesis_validators_root = B256::from(gvr);
        let domain = compute_domain(domain_type, version, genesis_validators_root);

        // compute_domain: domain_type || compute_fork_data_root(...)[:28], with
        // compute_fork_data_root = hash_tree_root(ForkData(current_version, gvr)).
        let fork_data = ForkData { current_version: version, genesis_validators_root };
        let fork_data_root = fork_data.tree_hash_root();
        prop_assert_eq!(compute_fork_data_root(version, genesis_validators_root), fork_data_root);
        prop_assert_eq!(fork_data_root.0, hash_pair(&chunk(&version), &gvr));
        prop_assert_eq!(&domain[..4], &domain_type[..]);
        prop_assert_eq!(&domain[4..], &fork_data_root[..28]);

        // compute_signing_root = hash_tree_root(SigningData(hash_tree_root(object), domain)).
        let exit = VoluntaryExit { epoch, validator_index };
        let expected = SigningData { object_root: exit.tree_hash_root(), domain }.tree_hash_root();
        prop_assert_eq!(compute_signing_root(&exit, domain), expected);
        prop_assert_eq!(expected.0, hash_pair(&exit.tree_hash_root().0, &domain.0));
    }
}

#[test]
fn signing_roots_cover_large_objects() {
    let block = common::gloas_block::<Minimal>(3);
    let domain = compute_domain(DOMAIN_BEACON_PROPOSER, [1, 2, 3, 4], B256::repeat_byte(9));
    assert_eq!(
        compute_signing_root(&block.message, domain),
        SigningData {
            object_root: block.message.tree_hash_root(),
            domain
        }
        .tree_hash_root()
    );
}

#[test]
fn domain_types_match_spec() {
    assert_eq!(DOMAIN_BEACON_PROPOSER, [0, 0, 0, 0]);
    assert_eq!(DOMAIN_BEACON_ATTESTER, [1, 0, 0, 0]);
    assert_eq!(DOMAIN_VOLUNTARY_EXIT, [4, 0, 0, 0]);
    assert_eq!(DOMAIN_BEACON_BUILDER, [0x0b, 0, 0, 0]);
}

#[test]
fn signature_sets_name_their_signers() {
    let root = B256::repeat_byte(1);
    let single = SignatureSet::single(SignerRef::Validator(7), root, common::SIG);
    assert_eq!(single.signers(), &[SignerRef::Validator(7)]);
    assert_eq!(single.signing_root(), root);
    assert_eq!(single.signature(), &common::SIG);

    let builder = SignerRef::Builder {
        index: 2,
        version: 0,
    };
    let inline = SignerRef::Inline(common::PUBKEY);
    let aggregate = SignatureSet::aggregate(
        vec![SignerRef::Validator(1), builder, inline],
        root,
        common::SIG,
    )
    .unwrap();
    assert_eq!(aggregate.signers().len(), 3);
    assert_eq!(
        SignatureSet::aggregate(vec![], root, common::SIG),
        Err(SignatureSetError::NoSigners)
    );
}
