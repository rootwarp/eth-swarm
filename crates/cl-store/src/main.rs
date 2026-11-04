//! `cl-store` binary. The service (see the library) is not wired to a service runtime yet, so
//! there is nothing to run.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "cl-store {}: the ethswarm.store.v1 service has no runtime wiring yet; not runnable",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
