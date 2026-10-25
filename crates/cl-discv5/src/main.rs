//! `cl-discv5` binary: discv5 peer discovery as `ops/probe/ethswarm-discv5.service` runs it. It
//! takes no argument, reads `/etc/ethswarm/cl-discv5.toml` and loads its node key only from the
//! systemd credential `$CREDENTIALS_DIRECTORY/nodekey`, never as root (`node_key`). See
//! [`cl_discv5::process`] for the config and the exit codes.
//!
//! Logs are svc-runtime's JSON lines on stderr through its bounded writer: a stderr nobody
//! reads drops lines instead of blocking the binary, and every exit waits for the queue at most
//! `svc_runtime::lifecycle::LOG_FLUSH_DEADLINE`. If that writer cannot start, it exits at once
//! with `EXIT_NO_LOG_WRITER` (71), writing nothing.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cl_discv5::process::main(
        cl_discv5::process::Build::Deployed,
    ))
}
