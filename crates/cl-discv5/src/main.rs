//! `cl-discv5` binary. The service is a stub (see the library), so there is nothing to run yet.
//!
//! It already loads its node key the way the probe unit hands it over
//! (`ops/probe/ethswarm-discv5.service`): only from the systemd credential
//! `$CREDENTIALS_DIRECTORY/nodekey`, never as root ([`node_key`]). Exit 1: the credential is
//! missing or refused. Exit 2: loaded, but the service is not runnable yet.

use std::process::ExitCode;

/// The probe unit this service runs as: a root-owned, ACL-granted credential is accepted only
/// from `/run/credentials/<UNIT>`.
const UNIT: &str = "ethswarm-discv5.service";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
    // A load and a refusal are both logged, without key material; the key is wiped on drop.
    if node_key::load_from_env(UNIT).is_err() {
        return ExitCode::from(1);
    }
    eprintln!(
        "cl-discv5 {}: stub service, every ethswarm.discv5.v1 RPC answers UNIMPLEMENTED; not runnable yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
