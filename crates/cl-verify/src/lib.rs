//! `cl-verify`: the `ethswarm.verify.v1.VerifyService` gRPC server.
//!
//! cl-chain is the only caller. It sends BLS signature-set batches ([`bls`]) and KZG cell-proof
//! batches ([`kzg`]) and feeds the finalized pubkey registry ([`feed`]) and the finalized builder
//! registry ([`builder_feed`]). The server is gRPC only;
//! there is no in-process fallback, and a verdict that is missing, late or errored is never
//! treated as valid ([`client`] holds the caller-side mapping to gossip verdicts).

pub mod bls;
pub mod builder_feed;
pub mod caps;
pub mod client;
pub mod feed;
pub mod frame;
pub mod handshake;
pub mod kzg;
pub mod metrics;
pub mod notify;
pub mod server;
pub mod startup;
pub mod wire;

/// The `ethswarm.common.v1` and `ethswarm.verify.v1` bindings (generated in `ethswarm-proto`).
pub mod proto {
    pub use ethswarm_proto::ethswarm;
    pub use ethswarm_proto::{common, verify};
}
