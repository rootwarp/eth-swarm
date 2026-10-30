//! `cl-engine` binary.
//!
//! The transport lives in the library ([`cl_engine::server::serve`]). This process entry
//! does not serve: wiring it to the systemd unit is a later change, and a binary that dialed an
//! execution client on startup would need a live host.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "cl-engine {}: engine transport is in the library; this binary does not serve yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}
