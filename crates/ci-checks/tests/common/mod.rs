//! Helpers shared by the integration tests that shell out to the repo's CI scripts.
#![allow(dead_code)] // each test crate uses a different subset

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// Runs a repo script with the `bash` on `PATH`.
pub fn bash_script(script: &str) -> Command {
    let mut cmd = Command::new("bash");
    cmd.arg(workspace_root().join(script));
    cmd
}

/// Runs `cmd`, panicking with its output if it fails, and returns trimmed stdout.
pub fn checked(cmd: &mut Command) -> String {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}"));
    assert!(out.status.success(), "{cmd:?} failed:\n{}", describe(&out));
    String::from_utf8(out.stdout)
        .expect("utf-8 stdout")
        .trim()
        .to_owned()
}

pub fn describe(out: &Output) -> String {
    format!(
        "status: {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every regular file under `dir`, relative to it, sorted.
pub fn files_under(dir: &Path) -> Vec<PathBuf> {
    fn walk(base: &Path, dir: &Path, acc: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.map(|e| e.expect("dir entry")) {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, acc);
            } else {
                acc.push(path.strip_prefix(base).expect("under base").to_path_buf());
            }
        }
    }
    let mut acc = Vec::new();
    walk(dir, dir, &mut acc);
    acc.sort();
    acc
}
