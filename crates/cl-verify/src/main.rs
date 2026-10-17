//! The cl-verify process:
//! `cl-verify --trusted-setup <PATH> --socket <PATH> --peer-uid <UID> --pubkey-snapshot <PATH>`.
//!
//! Exit status: 0 after a graceful shutdown on SIGTERM or SIGINT, or `--help`; 2 on a usage error;
//! 1 when startup or serving fails (including a trusted setup whose sha256 is not the pinned one).

use std::process::ExitCode;
use std::time::Duration;

use cl_verify::startup::{run, termination, unwired_network_warning, Args, UsageError, USAGE};

/// After `run` returns, how long blocking jobs still running get before the process exits anyway.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(UsageError::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("cl-verify: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("cl-verify: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(serve(args));
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
    code
}

async fn serve(args: Args) -> ExitCode {
    let config = args.into_config();
    if let Some(warning) = unwired_network_warning(&config.server) {
        eprintln!("cl-verify: warning: {warning}");
    }
    let shutdown = match termination() {
        Ok(shutdown) => shutdown,
        Err(e) => {
            eprintln!("cl-verify: cannot install signal handlers: {e}");
            return ExitCode::FAILURE;
        }
    };
    match run(config, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cl-verify: {e}");
            ExitCode::FAILURE
        }
    }
}
