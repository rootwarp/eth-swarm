//! Capture and replay tooling for live-network runs.
//!
//! - [`archive`]: the block/column archiver. A capture writes gossip payloads exactly as the
//!   wire delivered them into `<network>/<slot_start>-<slot_end>/<topic>/<slot>_<root>.ssz_snappy`
//!   segments, each sealed by a `manifest.toml` with every file's sha256; replay opens an
//!   archive only through [`archive::open_verified`], which refuses any mismatch.
//! - [`collector`]: the gossip/SSE arrival collector. Each arrival is stamped with a monotonic
//!   and a wall clock before anything decodes it; slot-relative and envelope-relative offsets
//!   are computed from the records afterwards.
//!
//! The crate never links `cl-sync`: replay reads `anchor-fetch`'s output directory instead.

pub mod archive;
pub mod collector;
