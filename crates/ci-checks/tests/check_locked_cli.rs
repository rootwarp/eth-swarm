//! The `check-locked` binary: exit codes, output, the committed negative fixture, and the
//! repository's own workflows.

mod common;

use common::{describe, stderr, stdout, workspace_root};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn run(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_check-locked"))
        .args(args)
        .current_dir(workspace_root())
        .output()
        .expect("run check-locked")
}

const STEP: &str = "jobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: ";

#[test]
fn repository_workflows_pass() {
    let out = run(&[]);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(
        stdout(&out).contains("cargo --locked OK (2 workflow files"),
        "{}",
        describe(&out)
    );
}

#[test]
fn every_reviewed_allow_entry_names_a_line_of_a_repository_workflow() {
    for entry in ci_checks::locked::ALLOW {
        let file = fs::read_to_string(workspace_root().join(entry.file))
            .unwrap_or_else(|e| panic!("{entry:?}: {e}"));
        let first = entry.line.lines().next().unwrap_or_default();
        assert!(file.contains(first), "{entry:?} names no line of its file");
    }
}

#[test]
fn the_negative_fixture_fails_with_its_line() {
    let fixture = workspace_root().join("testing/fixtures/workflow-unlocked.yml");
    let out = run(&[&fixture]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    let err = stderr(&out);
    assert!(
        err.contains(
            "workflow-unlocked.yml:16: cargo test without --locked: cargo test --workspace"
        ),
        "{}",
        describe(&out)
    );
    assert!(
        err.contains("ERROR: every cargo command in a CI run: step needs --locked"),
        "{}",
        describe(&out)
    );
}

#[test]
fn files_and_directories_are_scanned() {
    let dir = TempDir::new().expect("tempdir");
    fs::write(
        dir.path().join("a.yml"),
        format!("{STEP}cargo test --locked\n"),
    )
    .expect("write");
    fs::write(dir.path().join("b.yaml"), format!("{STEP}cargo test\n")).expect("write");
    fs::write(dir.path().join("notes.txt"), format!("{STEP}cargo test\n")).expect("write");
    let out = run(&[dir.path()]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(stderr(&out).contains("b.yaml:5: cargo test without --locked"));

    let good = dir.path().join("a.yml");
    let out = run(&[&good, &good]);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(stdout(&out).contains("cargo --locked OK (2 workflow files"));
}

#[test]
fn nothing_to_check_exits_2() {
    let dir = TempDir::new().expect("tempdir");
    let out = run(&[dir.path()]);
    assert_eq!(out.status.code(), Some(2), "{}", describe(&out));
    assert!(
        stderr(&out).contains("no workflow files in"),
        "{}",
        describe(&out)
    );

    let missing = dir.path().join("absent");
    let out = run(&[&missing]);
    assert_eq!(out.status.code(), Some(2), "{}", describe(&out));
    assert!(
        stderr(&out).contains("absent: no such file or directory"),
        "{}",
        describe(&out)
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_file_exits_3() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("ci.yml");
    fs::write(&file, format!("{STEP}cargo test --locked\n")).expect("write");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).expect("chmod");
    if fs::read(&file).is_ok() {
        return; // root reads any file
    }
    let out = run(&[dir.path()]);
    assert_eq!(out.status.code(), Some(3), "{}", describe(&out));
}

#[test]
fn composite_actions_below_a_directory_are_scanned() {
    let dir = TempDir::new().expect("tempdir");
    let action = dir.path().join("build/action.yml");
    fs::create_dir_all(action.parent().expect("parent")).expect("mkdir");
    fs::write(
        &action,
        "runs:\n  using: composite\n  steps:\n    - run: cargo build\n      shell: bash\n",
    )
    .expect("write");
    let out = run(&[dir.path()]);
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(
        stderr(&out).contains("build/action.yml:4: cargo build without --locked"),
        "{}",
        describe(&out)
    );
}

/// A repository with one clean workflow, for `--repo`.
fn repo_with_workflow() -> TempDir {
    let repo = TempDir::new().expect("tempdir");
    let wf = repo.path().join(".github/workflows");
    fs::create_dir_all(&wf).expect("mkdir");
    fs::write(wf.join("ci.yml"), format!("{STEP}cargo fmt\n")).expect("write");
    repo
}

#[test]
fn repo_mode_scans_workflows_actions_and_cargo_configs() {
    let repo = repo_with_workflow();
    let out = Command::new(env!("CARGO_BIN_EXE_check-locked"))
        .arg("--repo")
        .arg(repo.path())
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", describe(&out));

    let actions = repo.path().join(".github/actions/a");
    fs::create_dir_all(&actions).expect("mkdir");
    fs::write(
        actions.join("action.yaml"),
        "runs:\n  using: composite\n  steps:\n    - run: cargo test\n      shell: bash\n",
    )
    .expect("write");
    let config = repo.path().join("fuzz/.cargo");
    fs::create_dir_all(&config).expect("mkdir");
    fs::write(config.join("config.toml"), "[alias]\nfmt = \"build\"\n").expect("write");
    // Outside a git work tree, every directory counts, a target directory and a nested
    // checkout too: a CACHEDIR.TAG or a .git file can be committed.
    for skipped in ["target/.cargo", "worktrees/x/.cargo"] {
        fs::create_dir_all(repo.path().join(skipped)).expect("mkdir");
        fs::write(
            repo.path().join(skipped).join("config"),
            "[alias]\nfmt = \"b\"\n",
        )
        .expect("write");
    }
    fs::write(repo.path().join("target/CACHEDIR.TAG"), "Signature: x\n").expect("write");
    fs::write(repo.path().join("worktrees/x/.git"), "gitdir: y\n").expect("write");

    let out = Command::new(env!("CARGO_BIN_EXE_check-locked"))
        .arg("--repo")
        .arg(repo.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    let err = stderr(&out);
    assert!(
        err.contains("a/action.yaml:4: cargo test without --locked"),
        "{err}"
    );
    assert!(
        err.contains("fuzz/.cargo/config.toml: alias \"fmt\""),
        "{err}"
    );
    assert!(err.contains("target/.cargo/config: alias"), "{err}");
    assert!(err.contains("worktrees/x/.cargo/config: alias"), "{err}");
}

#[test]
fn repo_mode_without_workflows_exits_2() {
    let repo = TempDir::new().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_check-locked"))
        .arg("--repo")
        .arg(repo.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2), "{}", describe(&out));
}

#[test]
fn a_bad_flag_is_a_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_check-locked"))
        .arg("--repo")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2), "{}", describe(&out));
    assert!(
        stderr(&out).contains("usage: check-locked"),
        "{}",
        describe(&out)
    );
}
