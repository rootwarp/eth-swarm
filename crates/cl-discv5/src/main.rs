//! `cl-discv5` binary. The service is a stub (see the library), so there is nothing to run yet.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "cl-discv5 {}: stub service, every ethswarm.discv5.v1 RPC answers UNIMPLEMENTED; not runnable yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
