//! KZG for ETH Swarm: one pinned trusted-setup load path plus the PeerDAS cell API, on c-kzg.
//!
//! The functions are those of cryptography-specs `fulu/das-core.md`, as called from
//! consensus-specs `v1.7.0-beta.4` (`fulu/das-core.md`, `gloas/p2p-interface.md`).
//!
//! [`TrustedSetup::load_pinned`] is the only way to obtain settings: it checks the file's sha256
//! before parsing the spec's JSON setup and hands the decoded points to c-kzg with
//! [`PRECOMPUTE`]` = 0`. c-kzg's own file and embedded loaders are deliberately not used: the text
//! format is not what the spec ships, and an embedded setup escapes the digest pin.

mod cells;
mod setup;

pub use c_kzg::{
    Blob, Bytes48, Cell, Error as BackendError, KzgProof, BYTES_PER_BLOB, BYTES_PER_CELL,
    BYTES_PER_COMMITMENT, BYTES_PER_PROOF, CELLS_PER_EXT_BLOB,
};
pub use cells::KzgError;
pub use setup::{
    SetupError, TrustedSetup, MAX_SETUP_BYTES, NUM_G1_POINTS, NUM_G2_POINTS, PRECOMPUTE,
};
