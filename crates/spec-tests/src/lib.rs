//! Runner for the pinned SSZ test vectors (see `testing/vectors.manifest.toml`).
//!
//! Two vector sets are supported:
//! - [`ssz_generic`]: the ethereum/ssz-specs JSON fixtures.
//! - [`ssz_static`]: consensus-spec-tests `<preset>/{fulu,gloas}/ssz_static`, checked against the
//!   production containers in `consensus-types`.
//!
//! Every discovered case must be either run or listed in `skip.toml` with a reason;
//! [`plan`] reports anything else as unaccounted so the run fails.

pub mod check;
pub mod plan;
pub mod ssz_generic;
pub mod ssz_static;
