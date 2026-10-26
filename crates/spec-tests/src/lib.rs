//! Runner for the pinned test vectors (see `testing/vectors.manifest.toml`).
//!
//! - [`suite`]: which vector sets are scanned and which runner takes each case.
//! - [`coverage`]: the walk that turns every file into a case, and the guard that fails the run
//!   on any file no handler read.
//! - [`plan`]: the `skip.toml` rules. Every case must be either run or skipped with a reason;
//!   anything else is reported as unaccounted so the run fails.
//! - Runners: [`ssz_generic`] (ethereum/ssz-specs JSON fixtures), [`ssz_static`]
//!   (consensus-spec-tests `<preset>/{fulu,gloas}/ssz_static` against `consensus-types`),
//!   [`kzg`] (cryptography-specs cell handlers through `crypto-kzg`), [`bls`] (BLS handlers
//!   of bls12-381-tests, cryptography-specs and consensus-spec-tests `general` through
//!   `crypto-bls`), [`networking`] (the custody handlers of `<preset>/{fulu,gloas}/networking`
//!   through `consensus_types::das`), [`sanity`] (`<preset>/gloas/sanity/slots` through
//!   `state_transition::per_slot`), [`shuffling`] (`<preset>/phase0/shuffling/core` through
//!   `state_transition::caches`) and [`epoch_processing`] (`<preset>/gloas/epoch_processing`
//!   through `state_transition::per_epoch`).

pub mod bls;
pub mod check;
pub mod coverage;
pub mod epoch_processing;
pub mod fixture;
pub mod kzg;
pub mod networking;
pub mod plan;
pub mod sanity;
pub mod shuffling;
pub mod ssz_generic;
pub mod ssz_static;
pub mod suite;
