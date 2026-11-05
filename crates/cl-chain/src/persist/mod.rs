//! cl-chain's own durable state outside MDBX.
//!
//! [`durable`] is the C4 file set under `<datadir>/durable/`: the anchor, the latest finalized
//! block and state, and the log of imported blocks, each written atomically (temp file, fsync,
//! rename, fsync dir) and versioned on its own. The bulk tables (blocks, states, columns) are
//! the MDBX env of `store-schema`.
//!
//! [`budget`] is the non-finality disk budget over that env: the caps on unfinalized data, the
//! reserved free-space floor and its import gate, the envelope window and their metrics.

mod atomic;
mod base;
pub mod budget;
mod crc32c;
pub mod durable;
mod import_log;
