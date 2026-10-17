//! The `vectors` harness binary: setup errors fail the process even when a name filter would
//! drop every trial, and a run that executes no trial reports no coverage.

use std::path::Path;
use std::process::Command;

/// Runs `cargo test -p spec-tests --test vectors -- <args>` with `env`, against an empty
/// vectors directory.
fn vectors(env: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    let empty = tempfile::tempdir().unwrap();
    vectors_in(empty.path(), env, args)
}

/// [`vectors`] against the vectors directory `dir`.
///
/// Under a coverage build the nested binaries are instrumented too; their profiles go to a
/// throwaway directory instead of `default_*.profraw` files in the crate directory.
fn vectors_in(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    let profiles = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args([
        "test",
        "--quiet",
        "-p",
        "spec-tests",
        "--locked",
        "--test",
        "vectors",
        "--",
    ])
    .args(args)
    .env("SPEC_VECTORS_DIR", dir)
    .env("LLVM_PROFILE_FILE", profiles.path().join("%p-%m.profraw"));
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

#[test]
fn filtered_run_with_missing_required_set_fails() {
    for (env, needle) in [
        (&[("SPEC_SETS", "mainnet")][..], "mainnet vectors missing"),
        (&[("SPEC_SETS", "mainnt")][..], "unknown set"),
    ] {
        let out = vectors(env, &["BeaconState"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{env:?} exited 0:\n{stderr}");
        assert!(stderr.contains(needle), "{stderr}");
    }
}

#[test]
fn bench_mode_turns_the_guard_off() {
    let tree = tempfile::tempdir().unwrap();
    let case = tree
        .path()
        .join("ssz-specs/v0.1.0/ssz-test-vectors-v0.1.0/fixtures/ssz/ssz/test_basic_types");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::write(
        case.join("uint8_1.json"),
        br#"{"uint8_1": {"typeName": "Uint8", "serialized": "0x01",
            "root": "0x0100000000000000000000000000000000000000000000000000000000000000"}}"#,
    )
    .unwrap();
    let env = [("SPEC_SETS", "ssz-specs")];

    let full = vectors_in(tree.path(), &env, &[]);
    let stderr = String::from_utf8_lossy(&full.stderr);
    assert!(full.status.success(), "{stderr}");
    assert!(stderr.contains("1 of 1 vector files read"), "{stderr}");

    // --bench ignores every trial: nothing ran, so no coverage may be reported.
    let bench = vectors_in(tree.path(), &env, &["--bench"]);
    let stderr = String::from_utf8_lossy(&bench.stderr);
    assert!(!stderr.contains("vector files read"), "{stderr}");
    assert!(stderr.contains("coverage guard: off"), "{stderr}");
}
