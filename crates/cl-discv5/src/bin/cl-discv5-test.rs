//! `cl-discv5-test`: the `cl-discv5` binary built for the integration tests only (cargo feature
//! `test-config`, which only cl-discv5's own dev-dependency turns on). It runs the same code
//! ([`cl_discv5::process::main`]) with [`cl_discv5::process::Build::Test`]: it reads its config
//! from `$CL_DISCV5_TEST_CONFIG`, accepts a config that the test user owns, and lets the OS pick
//! the `/metrics` port. Never deploy it: the deployed binary is `cl-discv5`.

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cl_discv5::process::main(cl_discv5::process::Build::Test))
}
