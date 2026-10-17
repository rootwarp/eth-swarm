//! Generates the `ethswarm.{common,chain,store,engine,p2p,discv5,sync,api,verify}.v1` bindings
//! (messages, clients and servers) from `proto/`, plus the encoded `FileDescriptorSet`.
//! Needs `protoc` on PATH (or `PROTOC`).

use std::path::PathBuf;

const ROOT: &str = "../../proto";

const PROTOS: [&str; 16] = [
    "ethswarm/common/v1/envelope.proto",
    "ethswarm/common/v1/error.proto",
    "ethswarm/common/v1/fork.proto",
    "ethswarm/common/v1/verdict.proto",
    "ethswarm/chain/v1/events.proto",
    "ethswarm/chain/v1/gossip.proto",
    "ethswarm/chain/v1/import.proto",
    "ethswarm/chain/v1/query.proto",
    "ethswarm/chain/v1/reqresp.proto",
    "ethswarm/store/v1/store.proto",
    "ethswarm/engine/v1/engine.proto",
    "ethswarm/p2p/v1/network.proto",
    "ethswarm/discv5/v1/discovery.proto",
    "ethswarm/sync/v1/sync.proto",
    "ethswarm/api/v1/api.proto",
    "ethswarm/verify/v1/verify.proto",
];

fn main() {
    let protos: Vec<PathBuf> = PROTOS.iter().map(|p| PathBuf::from(ROOT).join(p)).collect();
    for p in &protos {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(out.join("ethswarm_descriptor.bin"))
        .compile_protos(&protos, &[PathBuf::from(ROOT)])
        .expect("compile ethswarm protos");
}
