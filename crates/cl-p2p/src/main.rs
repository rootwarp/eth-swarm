//! `cl-p2p` binary. The service is a stub (see the library), so there is nothing to run yet.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "cl-p2p {}: stub service, every ethswarm.p2p.v1 RPC answers UNIMPLEMENTED; not runnable yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
