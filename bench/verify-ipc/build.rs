fn main() {
    tonic_build::compile_protos("proto/verify.proto").expect("compile verify.proto");
}
