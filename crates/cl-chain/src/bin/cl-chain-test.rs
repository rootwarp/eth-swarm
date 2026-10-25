//! `cl-chain-test`: the `cl-chain` binary built for the integration tests only (cargo feature
//! `test-config`, which only cl-chain's own dev-dependency turns on). It runs the same code
//! ([`cl_chain::service::main`]) with [`cl_chain::service::Build::Test`]: it reads its config
//! from `$CL_CHAIN_TEST_CONFIG`, accepts a config that the test user owns, and lets the OS pick
//! the `/metrics` port. Never deploy it: the deployed binary is `cl-chain`.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cl_chain::service::main(cl_chain::service::Build::Test))
}
