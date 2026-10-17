//! `anchor-fetch`: fetch a checkpoint anchor that two providers agree on.
//!
//! ```text
//! anchor-fetch [--config anchor-fetch.toml] [--out DIR] [--quiet]
//! anchor-fetch check-log RUN_LOG
//! ```
//!
//! The first form runs [`cl_sync::checkpoint::fetch::run`] with the mainnet preset (Sepolia,
//! Hoodi and mainnet all use it): on success `DIR/anchor.json` (printed to stdout),
//! `DIR/block.ssz` and `DIR/state.ssz` exist; on any abort the error's name and message go to
//! stderr, no `anchor.json` is written, and the exit code is non-zero (1 check failed, 2
//! config or output refused, 3 provider unreachable, 4 local I/O). Every run appends to
//! `DIR/run.log`, echoed to stderr unless `--quiet`. A run locks `DIR`: a second run into it
//! exits 2 (`out_dir_busy`) at once, and an existing anchor, block or state is never replaced.
//! Provider URLs appear only as `scheme://host:port` (plus `/…` for a base path).
//!
//! `check-log` exits 0 only if the last run in `RUN_LOG` names both providers (name, operator,
//! URL), and 1 otherwise. Usage errors exit 64.

use cl_sync::checkpoint::{fetch, runlog};
use consensus_types::Mainnet;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: anchor-fetch [--config FILE] [--out DIR] [--quiet]\n       anchor-fetch check-log RUN_LOG";
const EXIT_USAGE: u8 = 64;

enum Command {
    Fetch {
        config: PathBuf,
        out: PathBuf,
        echo: bool,
    },
    CheckLog(PathBuf),
}

fn parse(args: &[String]) -> Result<Command, String> {
    if args.first().map(String::as_str) == Some("check-log") {
        return match args {
            [_, path] => Ok(Command::CheckLog(path.into())),
            _ => Err("check-log takes exactly one RUN_LOG".into()),
        };
    }
    let mut config = PathBuf::from("anchor-fetch.toml");
    let mut out = PathBuf::from(".");
    let mut echo = true;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => config = it.next().ok_or("--config needs a FILE")?.into(),
            "--out" => out = it.next().ok_or("--out needs a DIR")?.into(),
            "--quiet" => echo = false,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Command::Fetch { config, out, echo })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("anchor-fetch: {e}\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match command {
        Command::CheckLog(path) => match runlog::verify_file(&path) {
            Ok(()) => {
                eprintln!("anchor-fetch: {} names both providers", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("anchor-fetch: {}: {e}", path.display());
                ExitCode::from(1)
            }
        },
        Command::Fetch { config, out, echo } => {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("anchor-fetch: tokio runtime: {e}");
                    return ExitCode::from(4);
                }
            };
            match runtime.block_on(fetch::run::<Mainnet>(&config, &out, echo)) {
                Ok(anchor) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&anchor).unwrap_or_default()
                    );
                    eprintln!(
                        "anchor-fetch: anchor {} at slot {} written to {}",
                        anchor.block_root,
                        anchor.slot,
                        out.join(fetch::ANCHOR_FILE).display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("anchor-fetch: aborted: {}: {e}", e.name());
                    ExitCode::from(e.exit_code())
                }
            }
        }
    }
}
