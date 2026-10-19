//! `cl-discv5` binary. The service is a stub (see the library), so there is nothing to run yet.
//!
//! It already loads its node key the way the probe unit hands it over
//! (`ops/probe/ethswarm-discv5.service`): only from the systemd credential
//! `$CREDENTIALS_DIRECTORY/nodekey`, never as root ([`node_key`]). Exit 1: the credential is
//! missing or refused. Exit 2: loaded, but the service is not runnable yet.
//!
//! Logs are svc-runtime's JSON lines on stderr, at INFO, through its bounded writer: a stderr
//! nobody reads drops lines instead of blocking the binary, and every exit waits for the queue
//! at most [`LOG_FLUSH_DEADLINE`].

use std::process::ExitCode;
use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
use svc_runtime::telemetry::{flush_logs, init_tracing_with, LogQueueBounds};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::Identity;

/// The probe unit this service runs as: a root-owned, ACL-granted credential is accepted only
/// from `/run/credentials/<UNIT>`.
const UNIT: &str = "ethswarm-discv5.service";

fn main() -> ExitCode {
    // `false` only if the writer thread could not start; the binary then runs without logs, as
    // svc-runtime's own `run` does.
    init_tracing_with(
        LevelFilter::INFO,
        LogQueueBounds::default(),
        Identity::new(),
    );
    let code = run();
    flush_logs(LOG_FLUSH_DEADLINE);
    ExitCode::from(code)
}

/// The node-key load and the stub's stop; the exit code.
fn run() -> u8 {
    // A load and a refusal are both logged, without key material; the key is wiped on drop.
    if node_key::load_from_env(UNIT).is_err() {
        return 1;
    }
    tracing::warn!(
        version = env!("CARGO_PKG_VERSION"),
        "cl-discv5: stub service, every ethswarm.discv5.v1 RPC answers UNIMPLEMENTED; not \
         runnable yet"
    );
    2
}
