//! The cl-verify process:
//! `cl-verify --trusted-setup <PATH> --socket <PATH> --peer-uid <UID> --pubkey-snapshot <PATH>
//! --network-dir <DIR>`.
//!
//! Exit status: 0 after a graceful shutdown on SIGTERM or SIGINT, or `--help`; 2 on a usage error
//! (a missing `--network-dir` included); 1 when startup or serving fails (including a network
//! directory that does not read, a trusted setup whose sha256 is not the pinned one, and a pubkey
//! snapshot flush that failed at shutdown); 3 when a second SIGTERM or SIGINT cut the
//! shutdown short (the rest of the drain and the snapshot flush are skipped). Every failure is
//! printed to stderr: no log subscriber is installed.

use std::process::ExitCode;
use std::time::Duration;

use cl_verify::startup::{run, termination, Args, StartupConfig, Stopped, UsageError, USAGE};

/// After `run` returns, how long blocking jobs still running get before the process exits anyway.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(5);

/// The exit status after a second termination signal.
const FORCED_EXIT: u8 = 3;

/// How [`serve`] ended.
enum Outcome {
    /// Exit with this status once the runtime has wound down.
    Exit(ExitCode),
    /// A second signal: exit now, without waiting for blocking jobs.
    Forced,
}

fn main() -> ExitCode {
    let config = match Args::parse(std::env::args_os().skip(1)) {
        Ok(args) => args.into_config(),
        Err(UsageError::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("cl-verify: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let config = match config {
        Ok(config) => config,
        Err(e) => {
            eprintln!("cl-verify: {e}");
            return ExitCode::FAILURE;
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
    match runtime.block_on(serve(config)) {
        Outcome::Exit(code) => {
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
            code
        }
        Outcome::Forced => {
            runtime.shutdown_background();
            ExitCode::from(FORCED_EXIT)
        }
    }
}

async fn serve(config: StartupConfig) -> Outcome {
    let signals = match termination() {
        Ok(signals) => signals,
        Err(e) => {
            eprintln!("cl-verify: cannot install signal handlers: {e}");
            return Outcome::Exit(ExitCode::FAILURE);
        }
    };
    match run(config, signals).await {
        Ok(Stopped::Graceful) => Outcome::Exit(ExitCode::SUCCESS),
        Ok(Stopped::Forced) => {
            eprintln!("cl-verify: second signal; exiting without the pubkey snapshot flush");
            Outcome::Forced
        }
        Err(e) => {
            eprintln!("cl-verify: {e}");
            Outcome::Exit(ExitCode::FAILURE)
        }
    }
}
