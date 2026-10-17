//! Generates the `ethswarm.common.v1` and `ethswarm.verify.v1` bindings from `proto/`.
//! Needs `protoc` on PATH (or `PROTOC`).

fn main() {
    let root = "../../proto";
    let protos = [
        "../../proto/ethswarm/common/v1/envelope.proto",
        "../../proto/ethswarm/common/v1/error.proto",
        "../../proto/ethswarm/common/v1/fork.proto",
        "../../proto/ethswarm/common/v1/verdict.proto",
        "../../proto/ethswarm/verify/v1/verify.proto",
    ];
    for p in protos {
        println!("cargo:rerun-if-changed={p}");
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&protos, &[root])
        .expect("compile ethswarm verify protos");
}
