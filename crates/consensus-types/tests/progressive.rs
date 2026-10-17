//! `ProgressiveVariableList<T, N>`: `N` bounds decoding and never changes the root.

mod common;

use consensus_types::{gloas, Minimal};
use proptest::collection::vec;
use proptest::prelude::*;
use ssz::{Decode, Encode, ProgressiveBitList};
use ssz_types::typenum::{U0, U16, U5};
use ssz_types::ProgressiveVariableList;
use tree_hash::TreeHash;

type Bounded = ProgressiveVariableList<u64, U16>;
type Unbounded = ProgressiveVariableList<u64, U0>;
type BoundedBytes = ProgressiveVariableList<ProgressiveVariableList<u8, U5>, U16>;
type UnboundedBytes = ProgressiveVariableList<ProgressiveVariableList<u8, U0>, U0>;
const N: usize = 16;

fn unbounded(items: &[u64]) -> Unbounded {
    Unbounded::new(items.to_vec()).unwrap()
}

proptest! {
    #[test]
    fn bound_keeps_root(items in vec(any::<u64>(), 0..=N), extra in vec(any::<u64>(), 1..4)) {
        // Up to N items decode, re-encode identically and hash like the unbounded list.
        let reference = unbounded(&items);
        let bytes = reference.as_ssz_bytes();
        let bounded = Bounded::from_ssz_bytes(&bytes).unwrap();
        prop_assert_eq!(bounded.as_ssz_bytes(), bytes);
        prop_assert_eq!(bounded.tree_hash_root(), reference.tree_hash_root());

        // Exactly N decodes; N + 1 (or more) is rejected.
        let mut full = items.clone();
        full.resize(N, 7);
        prop_assert!(Bounded::from_ssz_bytes(&unbounded(&full).as_ssz_bytes()).is_ok());
        full.extend(&extra);
        let over = unbounded(&full).as_ssz_bytes();
        prop_assert!(Bounded::from_ssz_bytes(&over).is_err());
        prop_assert!(Unbounded::from_ssz_bytes(&over).is_ok());
    }

    #[test]
    fn bound_keeps_root_for_variable_items(
        items in vec(vec(any::<u8>(), 0..=5), 0..=N),
    ) {
        let reference = UnboundedBytes::new(
            items.iter().map(|i| ProgressiveVariableList::new(i.clone()).unwrap()).collect(),
        )
        .unwrap();
        let bytes = reference.as_ssz_bytes();
        let bounded = BoundedBytes::from_ssz_bytes(&bytes).unwrap();
        prop_assert_eq!(bounded.tree_hash_root(), reference.tree_hash_root());
        prop_assert_eq!(bounded.as_ssz_bytes(), bytes);
    }
}

/// A zero value of a fixed-size SSZ type.
fn zero<T: Decode>() -> T {
    T::from_ssz_bytes(&vec![0; <T as Decode>::ssz_fixed_len()]).unwrap()
}

/// Asserts that `field`'s type decodes `n` copies of `item` and rejects `n + 1`.
fn assert_bound<T: Decode, I: Encode + Clone>(name: &str, _field: &T, item: I, n: usize) {
    let wire = |count: usize| {
        ProgressiveVariableList::<I>::new(vec![item.clone(); count])
            .unwrap()
            .as_ssz_bytes()
    };
    assert!(
        T::from_ssz_bytes(&wire(n)).is_ok(),
        "{name}: {n} must decode"
    );
    assert!(
        T::from_ssz_bytes(&wire(n + 1)).is_err(),
        "{name}: {} must be rejected",
        n + 1
    );
}

fn indexed_attestation() -> gloas::IndexedAttestation<Minimal> {
    gloas::IndexedAttestation {
        attesting_indices: vec![1].try_into().unwrap(),
        data: zero(),
        signature: common::SIG,
    }
}

/// Each block-borne Gloas list rejects one item past its spec bound (minimal preset).
#[test]
fn gloas_fields_enforce_spec_bounds() {
    let block = common::gloas_block::<Minimal>(1);
    let body = &block.message.body;
    let attestation = gloas::Attestation::<Minimal> {
        aggregation_bits: ProgressiveBitList::with_capacity(3),
        data: zero(),
        signature: common::SIG,
        committee_bits: Default::default(),
    };
    let slashing = gloas::AttesterSlashing {
        attestation_1: indexed_attestation(),
        attestation_2: indexed_attestation(),
    };
    assert_bound(
        "proposer_slashings",
        &body.proposer_slashings,
        zero::<gloas::ProposerSlashing>(),
        16,
    );
    assert_bound("attester_slashings", &body.attester_slashings, slashing, 1);
    assert_bound("attestations", &body.attestations, attestation, 8);
    assert_bound("deposits", &body.deposits, zero::<gloas::Deposit>(), 16);
    assert_bound(
        "voluntary_exits",
        &body.voluntary_exits,
        zero::<gloas::SignedVoluntaryExit>(),
        16,
    );
    assert_bound(
        "bls_to_execution_changes",
        &body.bls_to_execution_changes,
        zero::<gloas::SignedBLSToExecutionChange>(),
        16,
    );
    assert_bound(
        "payload_attestations",
        &body.payload_attestations,
        zero::<gloas::PayloadAttestation<Minimal>>(),
        4,
    );

    let requests = &body.parent_execution_requests;
    assert_bound(
        "withdrawal requests",
        &requests.withdrawals,
        zero::<gloas::WithdrawalRequest>(),
        16,
    );
    assert_bound(
        "consolidation requests",
        &requests.consolidations,
        zero::<gloas::ConsolidationRequest>(),
        2,
    );
    assert_bound(
        "builder deposit requests",
        &requests.builder_deposits,
        zero::<gloas::BuilderDepositRequest>(),
        64,
    );
    assert_bound(
        "builder exit requests",
        &requests.builder_exits,
        zero::<gloas::BuilderExitRequest>(),
        16,
    );

    let bid = &body.signed_execution_payload_bid.message;
    assert_bound(
        "blob_kzg_commitments",
        &bid.blob_kzg_commitments,
        [0u8; 48],
        4096,
    );
    let indexed = indexed_attestation();
    assert_bound("attesting_indices", &indexed.attesting_indices, 0u64, 8192);
    let payload = common::gloas_execution_payload::<Minimal>();
    assert_bound(
        "withdrawals",
        &payload.withdrawals,
        zero::<gloas::Withdrawal>(),
        4,
    );
}
