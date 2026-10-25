//! The ipc contract suite against cl-verify: every rule in process and over a Unix socket.
//!
//! cl-verify serves only cl-chain's UID. Over UDS the kernel supplies this process's
//! credentials; in process, where no socket exists, the same credentials (read once from a
//! socket pair) are attached to each request. The UID rule itself is not part of the suite.

use std::sync::{Arc, OnceLock};

use cl_verify::bls::BlstBackend;
use cl_verify::feed::SharedCache;
use cl_verify::handshake::Handshake;
use cl_verify::kzg::{KzgBackend, KzgFailure, PreparedCells, TrustedSetupConfig};
use cl_verify::server::{serve_uds, Limits, ServerConfig, VerifyServer, DEFAULT_SNAPSHOT_INTERVAL};
use ipc::testkit::{probe, Server, Target};
use ipc::Link;
use tokio::net::unix::UCred;
use tonic::service::Routes;
use tonic::transport::server::UdsConnectInfo;

/// The suite never sends KZG work; a verifier that refuses everything keeps the trusted setup
/// out of these tests.
struct NoKzg;

impl KzgBackend for NoKzg {
    fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
        Ok(false)
    }
}

/// This process's credentials, from a connected socket pair.
fn my_cred() -> UCred {
    static CRED: OnceLock<UCred> = OnceLock::new();
    *CRED.get_or_init(|| {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        a.set_nonblocking(true).expect("nonblocking");
        tokio::net::UnixStream::from_std(a)
            .expect("inside the test runtime")
            .peer_cred()
            .expect("peer credentials")
    })
}

/// The one place the suite builds a cl-verify server config. The pubkey snapshot lives in
/// `snapshot_dir`, a temp dir the target keeps alive; the suite never opens PubkeyFeed, so
/// nothing is restored or saved there.
fn server_config(link: &Link, snapshot_dir: &tempfile::TempDir) -> ServerConfig {
    ServerConfig {
        handshake: Handshake::new(link.local(), link.floor()),
        peer_uid: my_cred().uid(),
        // Not loaded: the server gets the backends below.
        trusted_setup: TrustedSetupConfig {
            path: "unused-by-the-contract-suite".into(),
        },
        limits: Limits::default(),
        pubkey_snapshot: snapshot_dir.path().join("pubkeys.bin"),
        snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
    }
}

fn target(link: Link) -> Target {
    let snapshot_dir = Arc::new(tempfile::tempdir().expect("snapshot dir"));
    let server = VerifyServer::with_backends(
        server_config(&link, &snapshot_dir),
        SharedCache::default(),
        Arc::new(BlstBackend),
        Arc::new(NoKzg),
    );
    let (counted, on_uds) = (server.clone(), server.clone());
    let served = Server::new(Routes::new(server.into_service()))
        .with_in_process_extensions(|ext| {
            ext.insert(UdsConnectInfo {
                peer_addr: None,
                peer_cred: Some(my_cred()),
            });
        })
        .with_uds_server(Arc::new(move |listener, stop| {
            let server = on_uds.clone();
            Box::pin(async move {
                let _ = serve_uds(listener, server, async {
                    let _ = stop.await;
                })
                .await;
            })
        }));
    Target::new("ethswarm.verify.v1", served, link)
        .with_probe(probe::verify_bls())
        .with_violation_counter(move || {
            let _keep = &snapshot_dir;
            counted.contract_violations()
        })
}

ipc::contract_suite!(target);
