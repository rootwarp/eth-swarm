//! Eth2 req/resp wire format (consensus-specs v1.7.0-beta.4), with no libp2p dependency.
//!
//! - [`enr`]: the node-record values `eth2` (SSZ `ENRForkID`), `cgc` and `nfd` as bytes, and
//!   the local values at an epoch of the BPO-aware fork schedule (no `enr`/`discv5` dependency).
//! - [`rpc::codec`]: `ssz_snappy` chunk framing, response result codes and context bytes.
//! - [`rpc::messages`]: the message bodies (`Status` v2, `MetaData` v3, `Ping`, `Goodbye`,
//!   `BeaconBlocksByRange` v2 request, `ErrorMessage`).
//! - [`rpc::protocols`]: the protocol IDs with their payload bounds and response counts.
//!
//! Everything here decodes untrusted peer bytes, so every length is checked against its bound
//! before anything is allocated for it. The transport (`cl-p2p`) drives the sans-IO scanner
//! ([`rpc::codec::scan_response_chunk`]) and adds the deadlines.

pub mod enr;
pub mod rpc;

#[cfg(feature = "testkit")]
pub mod testkit;
