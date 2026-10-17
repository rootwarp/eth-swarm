//! `cl-verify`: the `ethswarm.verify.v1.VerifyService` gRPC server.
//!
//! cl-chain is the only caller. It sends BLS signature-set batches ([`bls`]) and KZG cell-proof
//! batches ([`kzg`]) and feeds the finalized pubkey registry ([`feed`]). The server is gRPC only;
//! there is no in-process fallback, and a verdict that is missing, late or errored is never
//! treated as valid ([`client`] holds the caller-side mapping to gossip verdicts).

pub mod bls;
pub mod caps;
pub mod client;
pub mod feed;
pub mod frame;
pub mod handshake;
pub mod kzg;
pub mod notify;
pub mod server;
pub mod startup;
pub mod wire;

/// Generated `ethswarm.*.v1` bindings.
#[allow(clippy::all, clippy::pedantic)] // tonic/prost generated code
pub mod proto {
    pub mod ethswarm {
        pub mod common {
            pub mod v1 {
                tonic::include_proto!("ethswarm.common.v1");
            }
        }
        pub mod verify {
            pub mod v1 {
                tonic::include_proto!("ethswarm.verify.v1");
            }
        }
    }
    pub use ethswarm::common::v1 as common;
    pub use ethswarm::verify::v1 as verify;
}
