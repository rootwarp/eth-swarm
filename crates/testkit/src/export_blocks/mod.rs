//! Devnet block and root export.
//!
//! [`export`] reads a devnet's chain from one CL's beacon API (plain `http://` to a loopback
//! host, as the collector does) and writes
//!
//! ```text
//! <out>/<devnet>/<slot_start>-<slot_end>/beacon_block/<slot>_0x<root>.ssz_snappy
//! <out>/<devnet>/<slot_start>-<slot_end>/manifest.toml
//! <out>/<devnet>/genesis_state.ssz
//! <out>/<devnet>/export.toml
//! ```
//!
//! The block files and their `manifest.toml` are an [archive](crate::archive) segment, written
//! by [`Writer`](crate::archive::Writer) and opened by
//! [`open_verified`](crate::archive::open_verified) like any capture. `export.toml`
//! ([`ExportManifest`]) adds what replay needs beyond the segment: the devnet name, the CL it
//! was read from, the genesis time, validators root, block root and state root, the config's
//! sha256, fork schedule and digests, the image digests, the slot range with its empty slots,
//! every block's root and parent root, the genesis state's sha256 and every segment's archive
//! digest. It is written last, so a directory without it is no export.
//!
//! Per slot, `GET /eth/v2/beacon/blocks/{slot}` (SSZ) answers the block or 404 (an empty
//! slot, recorded). Each block is decoded with the fork of its own slot, must be at that slot,
//! must hash (`hash_tree_root(message)`) to `GET /eth/v1/beacon/blocks/{slot}/root`, and must
//! have the previous exported block as its parent, across empty slots; the genesis block has a
//! zero parent and the genesis state's root (`GET /eth/v2/debug/beacon/states/genesis`) as its
//! `state_root`. Every body read is bounded: a block by `MAX_PAYLOAD_SIZE`, JSON by
//! [`MAX_JSON_BYTES`](crate::collector::MAX_JSON_BYTES), the state by
//! [`ExportConfig::max_state_bytes`].
//!
//! Replay opens an export only through [`open_export`], which verifies the manifest, every
//! segment, the block files against the manifest's blocks and the genesis state. Two exports
//! of one devnet from different CLs must have identical root lists ([`diff_root_lists`]).

mod api;
mod error;
mod export;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
mod manifest;
mod open;
#[cfg(test)]
mod tests;

pub use api::{BLOCK_PATH, BLOCK_ROOT_PATH, FINALIZED_HEADER_PATH, GENESIS_STATE_PATH};
pub use error::ExportError;
pub use export::{
    export, ExportConfig, BLOCK_TOPIC, DEFAULT_MAX_STATE_BYTES, DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_STATE_TIMEOUT, EXPORT_CLOCK_SOURCE,
};
pub use manifest::{
    BlockEntry, DigestEntry, ExportManifest, ExportManifestError, ForkEntry, SegmentEntry,
    StateFile, EXPORT_FILE, EXPORT_FORMAT_VERSION, GENESIS_STATE_FILE, MAX_IMAGE_LEN,
    MAX_SOURCE_LEN,
};
pub use open::{diff_root_lists, open_export, Export, RootListDiff, SlotEntry};
