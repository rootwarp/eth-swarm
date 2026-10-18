//! The `check-kurtosis-pins` binary: exit codes, output, and the repository's own args files.

mod common;

use common::{describe, stderr, stdout, workspace_root};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn run(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_check-kurtosis-pins"))
        .args(args)
        .current_dir(workspace_root())
        .output()
        .expect("run check-kurtosis-pins")
}

#[test]
fn repository_args_files_pass() {
    let out = run(&[]);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(
        stdout(&out).contains("kurtosis image pins OK (1 files)"),
        "{}",
        describe(&out)
    );
}

#[test]
fn a_floating_image_fails_with_its_path() {
    let dir = TempDir::new().expect("tempdir");
    let repo_file = workspace_root().join("testing/kurtosis/gloas-genesis.yaml");
    let text = fs::read_to_string(repo_file).expect("read the devnet args file");
    let floating = text.replacen(
        "cl_image: ethpandaops/lodestar:unstable-b3beff2@sha256:",
        "cl_image: ethpandaops/lodestar:unstable # @sha256:",
        1,
    );
    assert_ne!(floating, text, "fixture did not change");
    fs::write(dir.path().join("gloas-genesis.yaml"), floating).expect("write");
    let out = run(&[dir.path()]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(
        stderr(&out).contains(
            "ERROR gloas-genesis.yaml: participants[1].cl_image: image \"ethpandaops/lodestar:unstable\" is not pinned"
        ),
        "{}",
        describe(&out)
    );
}

#[test]
fn an_empty_or_missing_dir_fails() {
    let dir = TempDir::new().expect("tempdir");
    let out = run(&[dir.path()]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(
        stderr(&out).contains("no args files in"),
        "{}",
        describe(&out)
    );
    let missing = dir.path().join("absent");
    let out = run(&[&missing]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
}

#[test]
fn extra_arguments_are_a_usage_error() {
    let out = run(&[Path::new("a"), Path::new("b")]);
    assert_eq!(out.status.code(), Some(2), "{}", describe(&out));
    assert!(stderr(&out).contains("usage: check-kurtosis-pins [DIR]"));
}
