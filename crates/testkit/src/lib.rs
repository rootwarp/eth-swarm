//! Capture and replay tooling for live-network runs.
//!
//! - [`archive`]: the block/column archiver. A capture writes gossip payloads exactly as the
//!   wire delivered them into `<network>/<slot_start>-<slot_end>/<topic>/<slot>_<root>.ssz_snappy`
//!   segments, each sealed by a `manifest.toml` with every file's sha256 and the fork digest
//!   schedule over its slot range; replay opens an archive only through
//!   [`archive::open_verified`], which refuses any mismatch, a fork digest that is not its
//!   slot's included.
//! - [`collector`]: the gossip/SSE arrival collector. Each arrival is stamped with a monotonic
//!   and a wall clock before anything decodes it; slot-relative and envelope-relative offsets
//!   are computed from the records afterwards.
//! - [`export_blocks`]: a devnet's blocks and roots from genesis to an export slot, plus its
//!   genesis state, read from a beacon API into an archive segment and an `export.toml` that
//!   [`export_blocks::open_export_pinned`] verifies (through [`archive::open_verified`]) against
//!   the `export_sha256` from the run log before replay.
//! - `replay` (feature `replay`): replay of that export from the genesis state. Each block runs
//!   `state_transition(..., validate_result = true)` on the in-process BLS backend, and the
//!   post-state root must equal `block.state_root`. The first mismatch writes the pre-state,
//!   the block and our post-state and stops. The feature is not default, so a dev-dependency
//!   on this crate does not link `crypto-bls/verify`.
//!
//! The crate never links `cl-sync`: replay reads `anchor-fetch`'s output directory instead.

pub mod archive;
pub mod collector;
pub mod export_blocks;
#[cfg(feature = "replay")]
pub mod replay;
