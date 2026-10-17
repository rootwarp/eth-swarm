//! One libtest trial per vector case, then the coverage guard.
//!
//! - `SPEC_VECTORS_DIR` overrides the default `target/spec-vectors` of `testing/fetch-vectors.sh`.
//! - `SPEC_SETS` picks the sets to run (space or comma separated, each then required):
//!   `ssz-specs general minimal mainnet comptests cryptography-specs bls12-381-tests`. Unset: ssz-specs
//!   and minimal are required, the others run when extracted.
//! - The coverage guard runs after an unfiltered run and fails it if any vector file was read by
//!   no handler and excused by no `skip.toml` entry. A name filter, `--skip`, `--ignored`,
//!   `--list` or `--bench` turns it off, since those runs do not execute every case. Only reads
//!   made while a trial runs count.
//! - Setup and skip-list errors exit 101 before any trial runs, whatever the filter.

use libtest_mimic::{Arguments, Failed, Trial};
use spec_tests::plan::Date;
use spec_tests::suite::{self, Config, Outcome, SuiteError};
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> Result<String, String> {
    let path = workspace_root().join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
}

fn main() {
    let args = Arguments::from_args();
    // Only a run that executes every case can vouch for coverage.
    let guard_off = if args.bench {
        Some("--bench runs no trial")
    } else if args.list {
        Some("--list runs no trial")
    } else if args.filter.is_some() || !args.skip.is_empty() || args.ignored {
        Some("filtered run")
    } else {
        None
    };
    let root = std::env::var_os("SPEC_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target/spec-vectors"));
    let selection = std::env::var("SPEC_SETS").ok();

    let built = read("testing/vectors.manifest.toml")
        .and_then(|m| read("testing/skip.toml").map(|s| (m, s)))
        .map_err(SuiteError::Setup)
        .and_then(|(manifest, skip)| {
            suite::build(&Config {
                root: &root,
                manifest: &manifest,
                skip: &skip,
                selection: selection.as_deref(),
                today: Date::today_utc(),
            })
        });
    // Reported before libtest runs: as a trial, a name filter could drop it and exit 0.
    let suite = match built {
        Ok(s) => s,
        Err(e) => {
            let (what, msg) = match e {
                SuiteError::Setup(m) => ("setup", m),
                SuiteError::Rules(m) => ("skip list rules", m),
            };
            eprintln!("spec vectors: {what} failed:\n{msg}");
            std::process::exit(101);
        }
    };
    eprintln!("vector sets scanned: {}", suite.scanned.join(" "));

    let trials = suite
        .trials
        .into_iter()
        .map(|t| match t.outcome {
            Outcome::Run(r) => Trial::test(t.name, move || r().map_err(Failed::from)),
            Outcome::Skip(_) => Trial::test(t.name, || Ok(()))
                .with_ignored_flag(true)
                .with_kind("skip"),
            Outcome::Unaccounted => Trial::test(t.name, || {
                Err("unaccounted: no runner for this case and no skip entry".into())
            }),
        })
        .collect();
    let conclusion = libtest_mimic::run(&args, trials);

    if let Some(why) = guard_off {
        eprintln!("coverage guard: off ({why})");
    } else {
        let started = std::time::Instant::now();
        let result = suite.guard.check(&suite.reads);
        eprintln!(
            "coverage guard: checked in {:.2?} (includes the re-walk)",
            started.elapsed()
        );
        match result {
            Ok(covered) => eprintln!("{covered}"),
            Err(unread) => {
                eprintln!("{unread}");
                std::process::exit(101);
            }
        }
    }
    conclusion.exit();
}
