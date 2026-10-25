//! `cl-chain` binary: probe mode as `ops/probe/ethswarm-chain.service` runs it. It takes no
//! argument and reads `/etc/ethswarm/cl-chain.toml`; see [`cl_chain::service`] for the config
//! and the exit codes.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cl_chain::service::main(cl_chain::service::Build::Deployed))
}
