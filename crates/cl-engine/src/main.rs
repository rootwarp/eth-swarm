//! `cl-engine` binary. The service is a stub (see the library), so there is nothing to run yet.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "cl-engine {}: stub service, every ethswarm.engine.v1 RPC answers UNIMPLEMENTED; not runnable yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
