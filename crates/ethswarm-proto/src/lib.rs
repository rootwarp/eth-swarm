//! Generated bindings for the `ethswarm.*.v1` service contracts in `proto/`.
//!
//! Each package sits at its proto path (`ethswarm::store::v1`) and under a short alias
//! (`store`). [`FILE_DESCRIPTOR_SET`] is the encoded `google.protobuf.FileDescriptorSet` of every
//! file, for tools that inspect the contract (the contract suite reads RPC shapes from it).
//! `proto/README.md` is normative for the wire rules these types carry.

/// The generated packages, laid out as their proto paths.
#[allow(clippy::all, clippy::pedantic, missing_docs)] // tonic/prost generated code
pub mod ethswarm {
    pub mod common {
        pub mod v1 {
            tonic::include_proto!("ethswarm.common.v1");
        }
    }
    pub mod chain {
        pub mod v1 {
            tonic::include_proto!("ethswarm.chain.v1");
        }
    }
    pub mod store {
        pub mod v1 {
            tonic::include_proto!("ethswarm.store.v1");
        }
    }
    pub mod engine {
        pub mod v1 {
            tonic::include_proto!("ethswarm.engine.v1");
        }
    }
    pub mod p2p {
        pub mod v1 {
            tonic::include_proto!("ethswarm.p2p.v1");
        }
    }
    pub mod discv5 {
        pub mod v1 {
            tonic::include_proto!("ethswarm.discv5.v1");
        }
    }
    pub mod sync {
        pub mod v1 {
            tonic::include_proto!("ethswarm.sync.v1");
        }
    }
    pub mod api {
        pub mod v1 {
            tonic::include_proto!("ethswarm.api.v1");
        }
    }
    pub mod verify {
        pub mod v1 {
            tonic::include_proto!("ethswarm.verify.v1");
        }
    }
}

pub use ethswarm::api::v1 as api;
pub use ethswarm::chain::v1 as chain;
pub use ethswarm::common::v1 as common;
pub use ethswarm::discv5::v1 as discv5;
pub use ethswarm::engine::v1 as engine;
pub use ethswarm::p2p::v1 as p2p;
pub use ethswarm::store::v1 as store;
pub use ethswarm::sync::v1 as sync;
pub use ethswarm::verify::v1 as verify;

/// Encoded `google.protobuf.FileDescriptorSet` of every `ethswarm.*.v1` file.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ethswarm_descriptor.bin"));

/// The proto packages that a service serves, one per service (`common.v1` is shared).
pub const SERVICE_PACKAGES: [&str; 8] = [
    "ethswarm.chain.v1",
    "ethswarm.store.v1",
    "ethswarm.engine.v1",
    "ethswarm.p2p.v1",
    "ethswarm.discv5.v1",
    "ethswarm.sync.v1",
    "ethswarm.api.v1",
    "ethswarm.verify.v1",
];
