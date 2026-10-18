//! The block/column archiver.
//!
//! A capture ([`Writer`]) stores each gossip payload exactly as the wire delivered it (snappy
//! block-compressed SSZ) at
//!
//! ```text
//! <out>/<network>/<slot_start>-<slot_end>/<topic>/<slot>_0x<root>.ssz_snappy
//! <out>/<network>/<slot_start>-<slot_end>/manifest.toml
//! ```
//!
//! where `root` is the block root (`hash_tree_root` of the `BeaconBlock`, or of the sidecar's
//! block), computed at write time by decoding with the fork of the object's own slot. Each
//! `<slot_start>-<slot_end>` directory is one segment; segments roll every `slots_per_segment`
//! slots and at capture close, and only a sealed segment has a [`Manifest`]: network, preset,
//! slot range, fork digests, subscribed topics (subnets are in the topic names), peer count,
//! capture host, clock source, why it was sealed, and every file's length, slot, root, fork
//! digest and sha256, all covered by the manifest's `archive_sha256`.
//!
//! Replay opens a segment only through [`open_verified`], which recomputes every sha256 and
//! refuses any mismatch, missing file or extra file, an unsealed `.open-*` directory, and a
//! segment not at the `<network>/<slot_start>-<slot_end>` its manifest names.
//!
//! Segments of one capture can overlap: a late payload joins the open segment and lowers its
//! `slot_start`, and a segment that rolls on its manifest's size limit shares its window with
//! the next. A payload can also be in more than one segment (a restarted capture fed the same
//! input, two captures of one network). The archive keeps both and dedups nothing across
//! segments; replay consumers that need one copy per `(topic, slot, root)` dedup by it.
//!
//! Network names come from the operator and topic names from gossip; both become path
//! components, so only `[a-z0-9_-]` and `[a-z0-9_]` are accepted ([`NameError`]).

mod error;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
mod manifest;
mod names;
mod payload;
mod verify;
mod writer;

pub use error::ArchiveError;
pub use manifest::{
    ArchiveFile, ClosedBy, ForkDigest, Manifest, ManifestError, Sha256Digest, FORMAT_VERSION,
    MANIFEST_FILE, MAX_ERROR_LEN, MAX_MANIFEST_LEN,
};
pub use names::{NameError, TopicKind};
pub use payload::{
    decode_payload, decompress, max_compressed_payload_len, ChainParams, Decoded, PayloadError,
};
pub use verify::{open_verified, Archive};
#[cfg(any(test, feature = "test-support"))]
pub use writer::Fault;
pub use writer::{Capture, CaptureConfig, Stored, Writer, OPEN_PREFIX};
