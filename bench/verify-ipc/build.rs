fn main() {
    tonic_prost_build::compile_protos("proto/verify.proto").expect("compile verify.proto");
}
