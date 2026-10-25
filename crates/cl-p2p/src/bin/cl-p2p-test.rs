//! `cl-p2p-test`: the `cl-p2p` binary built for the integration tests only (cargo feature
//! `test-config`, which only cl-p2p's own dev-dependency turns on). It runs the same code
//! ([`cl_p2p::service::main`]) with [`cl_p2p::service::Build::Test`]: it reads its config from
//! `$CL_P2P_TEST_CONFIG`, accepts a config and a topic list that the test user owns, and lets
//! the OS pick the `/metrics` port. Never deploy it: the deployed binary is `cl-p2p`.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cl_p2p::service::main(cl_p2p::service::Build::Test))
}
