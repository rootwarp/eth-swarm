//! `check-workflows [DIR]`: exits 1 if any workflow in DIR (default `.github/workflows`)
//! breaks a hardening rule. See the library docs for the rules.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let dir = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".github/workflows"));
    if args.next().is_some() {
        eprintln!("usage: check-workflows [DIR]");
        return ExitCode::from(2);
    }
    match ci_checks::check_dir(&dir) {
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
        Ok(report) if report.violations.is_empty() => {
            println!("workflows OK ({} files)", report.files);
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
