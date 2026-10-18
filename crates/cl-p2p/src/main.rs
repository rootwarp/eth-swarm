//! `cl-p2p` binary. The service is a stub (see the library), so there is nothing to run yet.
//!
//! It already loads its identity the way the probe unit hands it over
//! (`ops/probe/ethswarm-p2p.service`): the node key only from the systemd credential
//! `$CREDENTIALS_DIRECTORY/nodekey`, never as root ([`cl_p2p::identity`]). Exit 1: the
//! credential is missing or refused. Exit 2: loaded, but the service is not runnable yet.

use std::process::ExitCode;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
    // A refusal is already logged, without key material.
    if cl_p2p::identity::load_from_env().is_err() {
        return ExitCode::from(1);
    }
    eprintln!(
        "cl-p2p {}: stub service, every ethswarm.p2p.v1 RPC answers UNIMPLEMENTED; not runnable yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
