//! Runner for the pinned SSZ test vectors (see `vectors.toml`).
//!
//! Two vector sets are supported:
//! - [`VectorSet::SszGeneric`]: the ethereum/ssz-specs JSON fixtures.
//! - [`VectorSet::GloasSszStatic`]: consensus-spec-tests `minimal/gloas/ssz_static`.
//!
//! Every discovered case must be either run or listed in `skip.toml` with a reason;
//! [`plan`] reports anything else as unaccounted so the run fails.

pub mod check;
pub mod gloas;
pub mod plan;
pub mod ssz_generic;
pub mod ssz_static;
