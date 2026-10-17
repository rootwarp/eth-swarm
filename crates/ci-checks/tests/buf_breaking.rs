//! `scripts/buf-breaking.sh`: which commit the breaking check compares against.
//!
//! Runs a copy of the script inside a throwaway repo, with a `buf` shim on `PATH` that
//! records its arguments, so the resolved baseline commit is visible.

mod common;

use common::{checked, describe, stderr, workspace_root};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

struct Repo {
    tmp: TempDir,
    commits: Vec<String>,
}

fn git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ]);
    cmd
}

impl Repo {
    /// A repo with three commits on `main`, no `develop` refs yet.
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("buf-breaking-")
            .tempdir()
            .expect("tempdir");
        let root = tmp.path().join("repo");
        fs::create_dir_all(root.join("scripts")).unwrap();
        fs::create_dir_all(root.join("proto")).unwrap();
        fs::copy(
            workspace_root().join("scripts/buf-breaking.sh"),
            root.join("scripts/buf-breaking.sh"),
        )
        .unwrap();
        checked(git(&root).args(["init", "-q"]));
        let mut commits = Vec::new();
        for n in 0..3 {
            fs::write(root.join("proto/a.proto"), format!("// {n}\n")).unwrap();
            checked(git(&root).args(["add", "-A"]));
            checked(git(&root).args(["commit", "-q", "-m", &format!("c{n}")]));
            commits.push(checked(git(&root).args(["rev-parse", "HEAD"])));
        }
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let shim = bin.join("buf");
        fs::write(&shim, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BUF_LOG\"\n").unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        Self { tmp, commits }
    }

    fn root(&self) -> PathBuf {
        self.tmp.path().join("repo")
    }

    fn update_ref(&self, name: &str, commit: usize) {
        checked(git(&self.root()).args(["update-ref", name, &self.commits[commit]]));
    }

    fn run(&self, args: &[&str]) -> Output {
        let path = format!(
            "{}:{}",
            self.tmp.path().join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new("bash")
            .arg(self.root().join("scripts/buf-breaking.sh"))
            .args(args)
            .env("PATH", path)
            .env("BUF_LOG", self.tmp.path().join("buf.log"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("run buf-breaking.sh")
    }

    fn buf_calls(&self) -> Vec<String> {
        fs::read_to_string(self.tmp.path().join("buf.log"))
            .map(|log| log.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn assert_compared_against(&self, out: &Output, commit: usize) {
        assert!(out.status.success(), "{}", describe(out));
        let calls = self.buf_calls();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(
            calls[0].contains(&format!("#ref={},subdir=proto", self.commits[commit])),
            "want commit {commit}: {calls:?}"
        );
    }
}

#[test]
fn default_prefers_the_develop_branch_over_a_tag_named_develop() {
    let repo = Repo::new();
    repo.update_ref("refs/heads/develop", 0);
    repo.update_ref("refs/tags/develop", 2);

    let out = repo.run(&[]);

    repo.assert_compared_against(&out, 0);
}

#[test]
fn default_falls_back_to_the_remote_tracking_ref_not_a_tag() {
    let repo = Repo::new();
    repo.update_ref("refs/remotes/origin/develop", 1);
    repo.update_ref("refs/tags/origin/develop", 2);

    let out = repo.run(&[]);

    repo.assert_compared_against(&out, 1);
}

#[test]
fn explicit_ref_is_used() {
    let repo = Repo::new();
    repo.update_ref("refs/remotes/origin/develop", 1);
    repo.update_ref("refs/tags/origin/develop", 2);

    let out = repo.run(&["refs/remotes/origin/develop"]);

    repo.assert_compared_against(&out, 1);
}

#[test]
fn unresolvable_ref_fails_without_running_buf() {
    let repo = Repo::new();

    for args in [&[][..], &["refs/remotes/origin/develop"][..]] {
        let out = repo.run(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", describe(&out));
        assert!(
            stderr(&out).contains("does not resolve"),
            "{}",
            describe(&out)
        );
    }
    assert!(repo.buf_calls().is_empty());
}

#[test]
fn baseline_mode_compares_against_the_frozen_image() {
    let repo = Repo::new();

    let out = repo.run(&["--baseline"]);

    assert!(out.status.success(), "{}", describe(&out));
    assert_eq!(repo.buf_calls(), ["breaking --against .baseline/v1.binpb"]);
}

#[test]
fn ci_compares_against_the_remote_tracking_ref() {
    let ci = fs::read_to_string(workspace_root().join(".github/workflows/ci.yml")).unwrap();
    assert!(
        ci.contains("scripts/buf-breaking.sh refs/remotes/origin/develop"),
        "ci.yml must pass the fully qualified remote-tracking ref"
    );
}

#[test]
fn missing_local_branch_does_not_fall_through_to_a_tag_with_its_full_name() {
    let repo = Repo::new();
    repo.update_ref("refs/tags/refs/heads/develop", 2);
    repo.update_ref("refs/remotes/origin/develop", 1);

    let out = repo.run(&[]);

    repo.assert_compared_against(&out, 1);
}

#[test]
fn explicit_ref_must_exist_under_its_full_name() {
    let repo = Repo::new();
    repo.update_ref("refs/tags/refs/remotes/origin/develop", 2);

    let out = repo.run(&["refs/remotes/origin/develop"]);

    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(repo.buf_calls().is_empty());
}

#[test]
fn short_ref_names_are_refused() {
    let repo = Repo::new();
    repo.update_ref("refs/remotes/origin/develop", 1);

    for short in ["origin/develop", "develop", "--bogus"] {
        let out = repo.run(&[short]);
        assert_eq!(out.status.code(), Some(1), "{short}: {}", describe(&out));
        assert!(
            stderr(&out).contains("fully qualified"),
            "{}",
            describe(&out)
        );
    }
    assert!(repo.buf_calls().is_empty());
}
