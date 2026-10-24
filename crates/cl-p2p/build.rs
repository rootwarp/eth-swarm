//! Embeds what the m2a fuzz gate must say about the decoders this crate is built from.
//!
//! The gate (`fuzz/check-m2a-gate.sh`) vouches for a tree: its decoder key (`git rev-parse
//! HEAD:<path>` of every keyed path and the sha256 of `Cargo.lock` and `fuzz/Cargo.lock`), the
//! libFuzzer limits, the toolchain and cargo-fuzz pins, the seed corpora, and the commits its
//! `head` may name (`heads`: HEAD and its ancestors with HEAD's decoder key). The values are
//! taken here, when the binary is built, not when it runs: a deployed binary has no checkout to
//! look at, and values read at startup from whatever tree is there would describe that tree, not
//! the binary.
//!
//! The values come from the fuzz harness itself, so there is one definition of the key:
//!
//! - `fuzz/check-m2a-gate.sh --print-expected` prints them as one JSON object;
//! - `m2a_dirty_paths` (`fuzz/m2a-common.sh`) lists keyed paths with uncommitted changes
//!   (modified, staged or untracked) or with git's assume-unchanged or skip-worktree flag set
//!   (git would not see an edit). Any makes the values unavailable, as it makes the checker
//!   refuse: HEAD's hashes would not describe the sources being compiled.
//!
//! The checkout must be the one this crate sits in (`<toplevel>/crates/cl-p2p`), found by git
//! with a scrubbed environment (`build_support.rs`): no inherited `GIT_DIR`, `GIT_WORK_TREE`,
//! `GIT_CONFIG*` or `BASH_ENV` can point the scripts at another tree, and no system or global
//! git config or attributes can filter what `git status` sees (so a checkout owned by another
//! user, which would need `safe.directory`, fails closed).
//!
//! Unavailable values (no git checkout, a copy outside its checkout, no harness in the tree, a
//! dirty or missing keyed path, a script failure) are embedded as the reason, and the binary's
//! pre-flight then refuses every gate file. Every other part of the crate builds as usual. The
//! scripts need bash and python3.
//!
//! The values go to the binary as two files in `OUT_DIR`, which it embeds with `include_str!`:
//! `m2a-gate-expected.json` (the JSON, or empty) and `m2a-gate-unavailable.txt` (the reason, or
//! empty). Not as `rustc-env` variables: `heads` grows with the history, and one environment
//! string is capped at 128 KiB on Linux.
//!
//! It also records the build commit and why the build tree was not clean, for the
//! `m2a-summary` line (`src/bin/m2a-session/build_info.rs`): `m2a-build-commit.txt` (git's
//! `HEAD`, or empty) and `m2a-build-unclean.txt` (empty for a clean tree, else the reason). The
//! tree is clean only if `m2a_dirty_paths` finds nothing under [`BUILD_PATHS`], the paths that
//! can change what the binary compiles. A tree without git, or without the harness, is not
//! clean. Cargo reruns this script when a file under a build path changes.
//!
//! Cargo reruns this script when a keyed path or a harness script changes on disk (or, while
//! one is missing, its nearest existing parent below the repository root), when git's `HEAD`,
//! the current branch ref or the index changes (a commit, checkout or `git add`), or when the
//! history depth may have (`build_support::history_watch`: a shallow clone deepened or
//! unshallowed, or a full one made shallow).

mod build_support;

use build_support::{child_env, command, git, history_watch, locate_repo, run, watch_path};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const COMMON: &str = "fuzz/m2a-common.sh";
const CHECKER: &str = "fuzz/check-m2a-gate.sh";
/// The paths that can change what the binary compiles: the workspace manifest and lock file,
/// the toolchain pin, every crate (the binary's path dependencies are among them), and `proto`
/// (ethswarm-proto compiles it). `fuzz/` is not among them: the binary does not compile it,
/// and the gate expectations already refuse a dirty keyed path there.
const BUILD_PATHS: [&str; 5] = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates",
    "proto",
];

type Env = [(OsString, OsString)];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let env = child_env(std::env::vars_os());
    let (gate_file, expected, build) = match locate_repo(&manifest, &env) {
        Ok(repo) => {
            watch_git(&repo, &env);
            (
                repo.join("fuzz/artifacts/m2a-gate.json"),
                expected(&repo, &env),
                build_state(&repo, &env),
            )
        }
        Err(reason) => (
            manifest.join("../../fuzz/artifacts/m2a-gate.json"),
            Err(reason.clone()),
            (String::new(), reason),
        ),
    };
    println!(
        "cargo:rustc-env=M2A_DEFAULT_GATE_FILE={}",
        gate_file.display()
    );
    let (json, reason) = match expected {
        Ok(json) => (json, String::new()),
        Err(reason) => (String::new(), reason.replace(['\n', '\r'], " ")),
    };
    let (commit, unclean) = build;
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("set by cargo"));
    for (name, text) in [
        ("m2a-gate-expected.json", json),
        ("m2a-gate-unavailable.txt", reason),
        ("m2a-build-commit.txt", commit),
        ("m2a-build-unclean.txt", unclean.replace(['\n', '\r'], " ")),
    ] {
        // Rewritten only on a change: the binary embeds the file, so a new mtime rebuilds it.
        let path = out.join(name);
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            std::fs::write(&path, text)
                .unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
        }
    }
}

/// Runs `script` (with `fuzz/m2a-common.sh` as `$1`) in bash, in `repo`.
fn bash(repo: &Path, script: &str, env: &Env) -> Result<String, String> {
    run(
        command("bash", env)
            .current_dir(repo)
            .args(["-c", script, "build.rs", COMMON]),
        &format!("bash -c '{script}'"),
    )
}

fn watch(repo: &Path, rel: &str) {
    if let Some(path) = watch_path(repo, rel) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

/// `rerun-if-changed` for git's HEAD, branch ref, packed refs and index, and for the history
/// depth ([`history_watch`]). Only files that exist are listed: cargo reruns on every build for
/// a missing one.
fn watch_git(repo: &Path, env: &Env) {
    let mut names = vec![
        "HEAD".to_owned(),
        "index".to_owned(),
        "packed-refs".to_owned(),
    ];
    if let Ok(branch) = git(repo, &["symbolic-ref", "-q", "HEAD"], env) {
        names.push(branch.trim().to_owned());
    }
    for name in names {
        if let Ok(p) = git(repo, &["rev-parse", "--git-path", &name], env) {
            let p = repo.join(p.trim());
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
    for p in history_watch(repo, env) {
        println!("cargo:rerun-if-changed={}", p.display());
    }
}

/// `check-m2a-gate.sh --print-expected` of a clean tree, or why there is none.
fn expected(repo: &Path, env: &Env) -> Result<String, String> {
    for script in [COMMON, CHECKER] {
        watch(repo, script);
    }
    for script in [COMMON, CHECKER] {
        if !repo.join(script).is_file() {
            return Err(format!("{script} is not in this tree"));
        }
    }
    let keyed = bash(
        repo,
        r#". "$1" && printf '%s\n' "${M2A_KEY_PATHS[@]}" "${M2A_KEY_FILES[@]}""#,
        env,
    )?;
    for path in keyed.lines().filter(|l| !l.is_empty()) {
        watch(repo, path);
    }
    let dirty = bash(repo, r#". "$1" && m2a_dirty_paths"#, env)?;
    if !dirty.trim().is_empty() {
        let paths: Vec<&str> = dirty.lines().map(str::trim).collect();
        return Err(format!(
            "keyed paths have uncommitted changes: {}",
            paths.join(", ")
        ));
    }
    let json = run(
        command("bash", env)
            .current_dir(repo)
            .args([CHECKER, "--print-expected"]),
        &format!("{CHECKER} --print-expected"),
    )?;
    Ok(json.trim().to_owned())
}

/// The build commit (git's `HEAD`, or empty) and why the build tree was not clean (empty if it
/// was): `m2a_dirty_paths` of the harness over [`BUILD_PATHS`]. At most five paths are named.
fn build_state(repo: &Path, env: &Env) -> (String, String) {
    for path in BUILD_PATHS {
        watch(repo, path);
    }
    let commit = match git(repo, &["rev-parse", "--verify", "HEAD^{commit}"], env) {
        Ok(commit) => commit.trim().to_owned(),
        Err(e) => return (String::new(), format!("no build commit: {e}")),
    };
    if !repo.join(COMMON).is_file() {
        return (commit, format!("{COMMON} is not in this tree"));
    }
    // M2A_KEY_FILES stays non-empty (bash 3.2 under `set -u` refuses an empty array): the lock
    // file is a build path too, and a path named twice is reported once below.
    let script = format!(
        r#". "$1" && GATE_KEY_PATHS=({}) && M2A_KEY_FILES=(Cargo.lock) && m2a_dirty_paths"#,
        BUILD_PATHS.join(" ")
    );
    let unclean = match bash(repo, &script, env) {
        Ok(dirty) => {
            let mut lines: Vec<&str> = Vec::new();
            for line in dirty.lines().map(str::trim).filter(|l| !l.is_empty()) {
                if !lines.contains(&line) {
                    lines.push(line);
                }
            }
            match lines.len() {
                0 => String::new(),
                n if n <= 5 => format!(
                    "uncommitted changes in the build tree: {}",
                    lines.join(", ")
                ),
                n => format!(
                    "uncommitted changes in the build tree: {}, and {} more",
                    lines[..5].join(", "),
                    n - 5
                ),
            }
        }
        Err(e) => format!("cannot check the build tree: {e}"),
    };
    (commit, unclean)
}
