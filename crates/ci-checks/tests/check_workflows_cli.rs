//! The `check-workflows` binary: exit codes, output, and the repository's own workflows.

mod common;

use common::{describe, stderr, stdout, workspace_root};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const GOOD: &str = "on: pull_request\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n";

fn run(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_check-workflows"))
        .args(args)
        .current_dir(workspace_root())
        .output()
        .expect("run check-workflows")
}

fn dir_with(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    for (name, body) in files {
        fs::write(dir.path().join(name), body).expect("write workflow");
    }
    dir
}

#[test]
fn repository_workflows_pass() {
    let out = run(&[]);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(stdout(&out).contains("workflows OK (2 files)"));
}

#[test]
fn hardened_dir_passes() {
    let dir = dir_with(&[("ci.yml", GOOD), ("notes.txt", "ignored")]);
    let out = run(&[dir.path()]);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(stdout(&out).contains("(1 files)"));
}

#[test]
fn every_file_is_checked() {
    let bad = GOOD.replace("@3d3c42e5aac5ba805825da76410c181273ba90b1", "@v7");
    let dir = dir_with(&[("a.yml", GOOD), ("b.yaml", &bad)]);
    let out = run(&[dir.path()]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(stderr(&out).contains("ERROR b.yaml:8: uses: actions/checkout@v7 is not pinned"));
}

#[test]
fn empty_or_missing_directory_fails() {
    let empty = dir_with(&[]);
    let out = run(&[empty.path()]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(stderr(&out).contains("no workflow files"));

    let out = run(&[&empty.path().join("absent")]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
}

#[test]
fn extra_arguments_are_a_usage_error() {
    let dir = dir_with(&[("ci.yml", GOOD)]);
    let out = run(&[dir.path(), dir.path()]);
    assert_eq!(out.status.code(), Some(2), "{}", describe(&out));
}
