//! The embedded descriptor set covers every proto package and every service the bindings expose.

use ethswarm_proto::{FILE_DESCRIPTOR_SET, SERVICE_PACKAGES};
use prost::Message;
use prost_types::FileDescriptorSet;

fn descriptor() -> FileDescriptorSet {
    FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("descriptor set decodes")
}

#[test]
fn every_service_package_has_at_least_one_service() {
    let set = descriptor();
    for package in SERVICE_PACKAGES {
        let services: usize = set
            .file
            .iter()
            .filter(|f| f.package() == package)
            .map(|f| f.service.len())
            .sum();
        assert!(
            services > 0,
            "{package} has no service in the descriptor set"
        );
    }
}

#[test]
fn every_proto_file_is_compiled() {
    let set = descriptor();
    let mut names: Vec<&str> = set.file.iter().map(|f| f.name()).collect();
    names.sort_unstable();
    let mut on_disk: Vec<String> = Vec::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    for pkg in std::fs::read_dir(root.join("ethswarm")).unwrap() {
        let v1 = pkg.unwrap().path().join("v1");
        for file in std::fs::read_dir(&v1).unwrap() {
            let path = file.unwrap().path();
            if path.extension().is_some_and(|e| e == "proto") {
                let rel = path.strip_prefix(&root).unwrap();
                on_disk.push(rel.to_string_lossy().into_owned());
            }
        }
    }
    on_disk.sort_unstable();
    assert_eq!(
        names, on_disk,
        "build.rs PROTOS must list every .proto file"
    );
}

#[test]
fn generated_clients_and_servers_exist_for_each_service() {
    use ethswarm_proto::{api, chain, discv5, engine, p2p, store, sync, verify};
    let names = [
        <api::api_service_server::ApiServiceServer<()> as tonic::server::NamedService>::NAME,
        <chain::import_service_server::ImportServiceServer<()> as tonic::server::NamedService>::NAME,
        <store::store_service_server::StoreServiceServer<()> as tonic::server::NamedService>::NAME,
        <engine::engine_service_server::EngineServiceServer<()> as tonic::server::NamedService>::NAME,
        <p2p::network_service_server::NetworkServiceServer<()> as tonic::server::NamedService>::NAME,
        <discv5::discovery_service_server::DiscoveryServiceServer<()> as tonic::server::NamedService>::NAME,
        <sync::sync_service_server::SyncServiceServer<()> as tonic::server::NamedService>::NAME,
        <verify::verify_service_server::VerifyServiceServer<()> as tonic::server::NamedService>::NAME,
    ];
    assert_eq!(names[0], "ethswarm.api.v1.ApiService");
    assert_eq!(names[7], "ethswarm.verify.v1.VerifyService");
}
