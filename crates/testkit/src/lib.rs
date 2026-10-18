//! Capture and replay tooling for live-network runs.
//!
//! - [`archive`]: the block/column archiver. A capture writes gossip payloads exactly as the
//!   wire delivered them into `<network>/<slot_start>-<slot_end>/<topic>/<slot>_<root>.ssz_snappy`
//!   segments, each sealed by a `manifest.toml` with every file's sha256; replay opens an
//!   archive only through [`archive::open_verified`], which refuses any mismatch.
//!
//! The crate never links `cl-sync`: replay reads `anchor-fetch`'s output directory instead.

pub mod archive;
