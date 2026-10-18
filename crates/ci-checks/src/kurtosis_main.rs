//! `check-kurtosis-pins [DIR]`: exits 1 if any ethereum-package args file in DIR (default
//! `testing/kurtosis`) has an image that is not pinned by tag and digest, or leaves one to a
//! package default. See `ci_checks::kurtosis` for the rules.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("testing/kurtosis"));
    if args.next().is_some() {
        eprintln!("usage: check-kurtosis-pins [DIR]");
        return ExitCode::from(2);
    }
    match ci_checks::kurtosis::check_dir(&dir) {
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
        Ok(report) if report.violations.is_empty() => {
            println!("kurtosis image pins OK ({} files)", report.files);
            ExitCode::SUCCESS
        }
        Ok(report) => {
            for v in &report.violations {
                eprintln!("{v}");
            }
            ExitCode::FAILURE
        }
    }
}
