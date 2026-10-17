//! Compile-time guarantees, checked with trybuild:
//! - no public constructor turns bytes or a raw blst point into a key or signature without the
//!   subgroup check (`from_validated_bytes` is the only way in);
//! - an `AggregatePublicKey` (possibly the identity) never stands in for a `PublicKey`;
//! - `verify` does not exist unless the `verify` feature is on (cl-chain links only
//!   `aggregate`).
//!
//! The `.stderr` snapshots are taken on the pinned toolchain (rust-toolchain.toml). Regenerate
//! with `TRYBUILD=overwrite` after an intended change.
//!
//! Run the feature gate in its real configuration with
//! `cargo test -p crypto-bls --no-default-features --features aggregate --test compile_fail`.
//! With `verify` on, the same file must compile instead, which shows the error comes from the
//! feature gate and not from a mistake in the file.

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/no_unvalidated_public_key.rs");
    t.compile_fail("tests/compile_fail/no_unvalidated_signature.rs");
    if cfg!(feature = "aggregate") {
        t.compile_fail("tests/compile_fail/aggregate_is_output_only.rs");
    }
    if cfg!(feature = "verify") {
        t.pass("tests/compile_fail/verify_without_feature.rs");
    } else {
        t.compile_fail("tests/compile_fail/verify_without_feature.rs");
    }
}
