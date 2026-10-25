//! `cl-p2p` binary: the probe's libp2p side as `ops/probe/ethswarm-p2p.service` runs it. It
//! takes no argument, reads `/etc/ethswarm/cl-p2p.toml` and loads its identity only from the
//! systemd credential `$CREDENTIALS_DIRECTORY/nodekey`, never as root ([`cl_p2p::identity`]).
//! See [`cl_p2p::service`] for the config, the links and the exit codes.
//!
//! Logs are svc-runtime's JSON lines on stderr through its bounded writer: a stderr nobody
//! reads drops lines instead of blocking the binary, and every exit waits for the queue at most
//! `svc_runtime::lifecycle::LOG_FLUSH_DEADLINE`. If that writer cannot start, it exits at once
//! with `EXIT_NO_LOG_WRITER` (71), writing nothing.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cl_p2p::service::main(cl_p2p::service::Build::Deployed))
}
