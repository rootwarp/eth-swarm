//! `replay`: replay a pinned devnet export from genesis.
//!
//! ```text
//! replay --manifest PATH --out DIR
//! replay --help
//! ```
//!
//! `--manifest` is a pin file (`testing/replay.manifest.toml`): the export directory, its
//! `export_sha256` and the devnet `config.yaml`, paths relative to the pin file. The replay
//! itself is [`testkit::replay::replay_pin`]. This binary only parses arguments.
//!
//! Exit codes: 0 the post-state root matched every block, 1 the pin, the export or a block
//! failed, 64 usage.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: replay --manifest PATH --out DIR
       replay --help";

const HELP: &str = "\
Replay a pinned devnet export from its genesis state.

Every block is applied with state_transition(validate_result = true) and the in-process BLS
backend. The post-state hash_tree_root must equal the block's state_root, and the block root
must equal the exported root. The export is opened only through open_export_pinned (each
segment through open_verified). A bad pin, a bad manifest or a root-list mismatch stops
before the first block. The first mismatched block writes pre_state.ssz, block.ssz and
post_state.ssz under --out and the process exits 1.

  --manifest PATH    the pin file: export, export_sha256, config (paths relative to the file)
  --out DIR          where the three SSZ files are written on the first mismatch

Exit codes: 0 every block matched, 1 the replay failed, 64 usage.";

struct Args {
    manifest: PathBuf,
    out: PathBuf,
}

fn main() -> ExitCode {
    match parse(env::args().skip(1)) {
        Ok(args) => match testkit::replay::replay_pin(&args.manifest, &args.out) {
            Ok(report) => {
                print!("{report}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("replay: {e}");
                ExitCode::from(1)
            }
        },
        Err(Usage::Help) => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Err(Usage::Bad(message)) => {
            eprintln!("replay: {message}\n{USAGE}");
            ExitCode::from(64)
        }
    }
}

enum Usage {
    Help,
    Bad(String),
}

fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, Usage> {
    let mut manifest = None;
    let mut out = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Err(Usage::Help),
            "--manifest" => manifest = Some(value(&mut args, "--manifest")?),
            "--out" => out = Some(value(&mut args, "--out")?),
            other => return Err(Usage::Bad(format!("unknown argument {other}"))),
        }
    }
    match (manifest, out) {
        (Some(manifest), Some(out)) => Ok(Args {
            manifest: PathBuf::from(manifest),
            out: PathBuf::from(out),
        }),
        _ => Err(Usage::Bad("--manifest and --out are required".into())),
    }
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, Usage> {
    args.next()
        .filter(|v| !v.starts_with("--"))
        .ok_or_else(|| Usage::Bad(format!("{flag} needs a value")))
}
