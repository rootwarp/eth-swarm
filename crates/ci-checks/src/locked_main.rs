//! `check-locked [--repo DIR | FILE|DIR...]`: exits 1 if a workflow `run:` step, a composite
//! action or a repository cargo config can make cargo run without `--locked`.
//!
//! - `--repo DIR` (the default is `--repo .`) checks `DIR/.github/workflows`,
//!   `DIR/.github/actions`, each local action or reusable workflow that a `uses: ./<path>`
//!   names, and each `.cargo/config` and `.cargo/config.toml` below `DIR` (rule 10 of the
//!   module docs of `ci_checks::locked` tells which files count in a git work tree).
//! - `FILE|DIR...` checks only those files. A directory gives its `*.yml` and `*.yaml` files and
//!   each `action.yml` and `action.yaml` below it.
//!
//! See `ci_checks::locked` for the rules.
//! Exit: 0 clean, 1 a cargo call without `--locked`, 2 nothing to check or a usage error,
//! 3 the scan failed.

use ci_checks::locked::{self, PathError};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: check-locked [--repo DIR | FILE|DIR...]";

fn main() -> ExitCode {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let scan = match args.as_slice() {
        [] => locked::check_repo(&PathBuf::from("."), locked::ALLOW),
        [flag, dir] if flag.as_os_str() == "--repo" => locked::check_repo(dir, locked::ALLOW),
        paths if paths.iter().any(|p| p.to_string_lossy().starts_with('-')) => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
        paths => locked::check_paths(paths, locked::ALLOW),
    };
    match scan {
        Err(e @ PathError::Nothing(_)) => {
            eprintln!("ERROR: {e}");
            ExitCode::from(2)
        }
        Err(e @ PathError::Unreadable(_)) => {
            eprintln!("ERROR: scanning workflows failed: {e}");
            ExitCode::from(3)
        }
        Ok(scan) if scan.violations.is_empty() => {
            println!(
                "cargo --locked OK ({} workflow files, {} cargo config files)",
                scan.workflow_files, scan.config_files
            );
            ExitCode::SUCCESS
        }
        Ok(scan) => {
            for v in &scan.violations {
                eprintln!("{v}");
            }
            eprintln!(
                "ERROR: every cargo command in a CI run: step needs --locked \
                 (or a reviewed entry in ci_checks::locked::ALLOW)"
            );
            ExitCode::FAILURE
        }
    }
}
