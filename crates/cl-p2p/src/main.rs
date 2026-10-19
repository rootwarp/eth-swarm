//! `cl-p2p` binary. The service is a stub (see the library), so there is nothing to run yet.
//!
//! It already loads its identity the way the probe unit hands it over
//! (`ops/probe/ethswarm-p2p.service`): the node key only from the systemd credential
//! `$CREDENTIALS_DIRECTORY/nodekey`, never as root ([`cl_p2p::identity`]). Exit 1: the
//! credential is missing or refused. Exit 2: loaded, but the service is not runnable yet.
//!
//! Logs are svc-runtime's JSON lines on stderr, at INFO, through its bounded writer: a stderr
//! nobody reads drops lines instead of blocking the binary, and every exit waits for the queue
//! at most [`LOG_FLUSH_DEADLINE`]. If that writer cannot start, it exits at once with
//! [`EXIT_NO_LOG_WRITER`](svc_runtime::telemetry::EXIT_NO_LOG_WRITER) (71), writing nothing.

use std::process::ExitCode;
use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
use svc_runtime::telemetry::{flush_logs, init_binary_tracing};
use tracing_subscriber::filter::LevelFilter;

fn main() -> ExitCode {
    if let Err(no_log_writer) = init_binary_tracing(LevelFilter::INFO) {
        return no_log_writer;
    }
    let code = run();
    flush_logs(LOG_FLUSH_DEADLINE);
    ExitCode::from(code)
}

/// The identity load and the stub's stop; the exit code.
fn run() -> u8 {
    // A refusal is already logged, without key material.
    if cl_p2p::identity::load_from_env().is_err() {
        return 1;
    }
    tracing::warn!(
        version = env!("CARGO_PKG_VERSION"),
        "cl-p2p: stub service, every ethswarm.p2p.v1 RPC answers UNIMPLEMENTED; not runnable yet"
    );
    2
}
