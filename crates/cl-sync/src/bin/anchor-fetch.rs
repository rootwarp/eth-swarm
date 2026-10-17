//! `anchor-fetch`: fetch a checkpoint anchor that two providers agree on.
//!
//! ```text
//! anchor-fetch [--config anchor-fetch.toml] [--out DIR] [--quiet]
//! anchor-fetch check-log RUN_LOG
//! anchor-fetch --help
//! ```
//!
//! The first form runs [`cl_sync::checkpoint::fetch::run`] with the mainnet preset (Sepolia,
//! Hoodi and mainnet all use it): on success `DIR/anchor.json` (printed to stdout),
//! `DIR/block.ssz` and `DIR/state.ssz` exist; on any abort the error's name and message go to
//! stderr, no `anchor.json` is written, and the exit code is non-zero (1 check failed, 2
//! config or output refused, 3 provider unreachable, 4 local I/O). Every run appends to
//! `DIR/run.log`, echoed to stderr unless `--quiet`. A run locks `DIR`: a second run into it
//! exits 2 (`out_dir_busy`) at once, and an existing anchor, block or state is never replaced.
//! `DIR` (created 0700 if missing) and `DIR/quarantine` must not be symlinks, must be owned by
//! the effective uid and not writable by group or other, or the run exits 2 (`unsafe_path`).
//! Provider URLs appear only as `scheme://host:port` (plus `/…` for a base path).
//!
//! `anchor.json` is written last and is the commit marker: a killed run can leave
//! `block.ssz` or `state.ssz` without it. Consumers must ignore `block.ssz` and `state.ssz`
//! unless an `anchor.json` next to them names their sha256 values and they match. If a failed
//! publish cannot be rolled back (`publish_rollback_incomplete`, exit 4), stderr and the run
//! log's `abort` line list the files left behind: delete them by hand.
//!
//! `check-log` exits 0 only if the last run in `RUN_LOG` names both providers (name, operator,
//! URL), and 1 otherwise. Usage errors exit 64.

use cl_sync::checkpoint::{fetch, runlog};
use consensus_types::Mainnet;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: anchor-fetch [--config FILE] [--out DIR] [--quiet]\n       anchor-fetch check-log RUN_LOG";
const EXIT_USAGE: u8 = 64;
const HELP: &str = "\
Fetch a checkpoint anchor that two providers run by different operators agree on.

Options:
  --config FILE  provider config (default anchor-fetch.toml)
  --out DIR      output directory (default .; created 0700 if missing)
  --quiet        do not echo the run log to stderr
  -h, --help     print this help

Output: DIR/block.ssz, DIR/state.ssz and DIR/anchor.json, each written only if every check
passes and never replacing an existing file; every run appends to DIR/run.log.

anchor.json is written last and is the commit marker: a killed run can leave block.ssz or
state.ssz without it. Consumers must ignore block.ssz and state.ssz unless an anchor.json next
to them names their sha256 values and they match.

DIR and DIR/quarantine must not be symlinks, must be owned by you and not writable by group or
other (else exit 2, unsafe_path). If a failed publish cannot be rolled back (exit 4,
publish_rollback_incomplete), the error and the run log's abort line list the files left
behind: delete them by hand.

Exit codes: 0 anchor written, 1 check failed, 2 config or output refused, 3 provider
unreachable, 4 local I/O, 64 usage. check-log exits 0 only if the last run in RUN_LOG names
both providers.";

enum Command {
    Help,
    Fetch {
        config: PathBuf,
        out: PathBuf,
        echo: bool,
    },
    CheckLog(PathBuf),
}

fn parse(args: &[String]) -> Result<Command, String> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Command::Help);
    }
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
        Command::Help => {
            println!("{USAGE}\n       anchor-fetch --help\n\n{HELP}");
            ExitCode::SUCCESS
        }
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
