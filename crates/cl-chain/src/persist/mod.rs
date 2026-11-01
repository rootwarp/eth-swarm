//! cl-chain's own durable state outside MDBX.
//!
//! [`durable`] is the C4 file set under `<datadir>/durable/`: the anchor, the latest finalized
//! block and state, and the log of imported blocks, each written atomically (temp file, fsync,
//! rename, fsync dir) and versioned on its own. The bulk tables (blocks, states, columns) are
//! the MDBX env of `store-schema`.

mod atomic;
mod base;
mod crc32c;
pub mod durable;
mod import_log;
