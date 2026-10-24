//! `m2a-session-test`: the `m2a-session` binary built for the integration tests only (cargo
//! feature `test-run-as`, which only cl-p2p's own dev-dependency turns on). It runs the same code
//! (`../m2a-session/app.rs`) with `test_build = true`: it takes a `run_as` other than
//! `m2a-session`, keeps that user's groups, accepts a config the test user owns, and runs on any
//! platform. It says so at startup and in its summary (`"test_build": true`). Never deploy it:
//! the deployed binary is `m2a-session`, which always passes `test_build = false`.

#[path = "../m2a-session/app.rs"]
mod app;
#[path = "../m2a-session/blocks.rs"]
mod blocks;
#[path = "../m2a-session/build_info.rs"]
mod build_info;
#[path = "../m2a-session/enr.rs"]
mod enr;
#[path = "../m2a-session/gate.rs"]
mod gate;
#[path = "../m2a-session/metadata.rs"]
mod metadata;
// The shared unit tests' mock API. `test = false` keeps `cargo test` from running this bin's
// tests, but `cargo clippy --all-targets` still compiles the bin in test mode, and the tests in
// app.rs and reference_api.rs import `crate::mock_api`: without this line that build fails.
#[cfg(test)]
#[path = "../m2a-session/mock_api.rs"]
mod mock_api;
#[path = "../m2a-session/ping.rs"]
mod ping;
#[path = "../m2a-session/probe.rs"]
mod probe;
#[path = "../m2a-session/reference_api.rs"]
mod reference_api;
#[path = "../m2a-session/summary.rs"]
mod summary;

/// The test binary: always a test build.
fn main() -> std::process::ExitCode {
    app::main(true)
}
