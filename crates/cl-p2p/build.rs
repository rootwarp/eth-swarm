//! Embeds what the m2a fuzz gate must say about the decoders this crate is built from.
//!
//! The gate (`fuzz/check-m2a-gate.sh`) vouches for a tree: its decoder key (`git rev-parse
//! HEAD:<path>` of every keyed path and the sha256 of `Cargo.lock` and `fuzz/Cargo.lock`), the
//! libFuzzer limits, the toolchain and cargo-fuzz pins, and the seed corpora. The values are
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
//! dirty or missing keyed path, a script failure) are embedded as the reason
//! (`M2A_GATE_UNAVAILABLE`), and the binary's pre-flight then refuses every gate file. Every
//! other part of the crate builds as usual. The scripts need bash and python3.
//!
//! Cargo reruns this script when a keyed path or a harness script changes on disk (or, while
//! one is missing, its nearest existing parent below the repository root), or when git's
//! `HEAD`, the current branch ref or the index changes (a commit, checkout or `git add`).

mod build_support;

use build_support::{child_env, command, git, locate_repo, run, watch_path};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const COMMON: &str = "fuzz/m2a-common.sh";
const CHECKER: &str = "fuzz/check-m2a-gate.sh";

type Env = [(OsString, OsString)];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let env = child_env(std::env::vars_os());
    let (gate_file, expected) = match locate_repo(&manifest, &env) {
        Ok(repo) => {
            watch_git(&repo, &env);
            (
                repo.join("fuzz/artifacts/m2a-gate.json"),
                expected(&repo, &env),
            )
        }
        Err(reason) => (
            manifest.join("../../fuzz/artifacts/m2a-gate.json"),
            Err(reason),
        ),
    };
    println!(
        "cargo:rustc-env=M2A_DEFAULT_GATE_FILE={}",
        gate_file.display()
    );
    match expected {
        Ok(json) => {
            println!("cargo:rustc-env=M2A_GATE_EXPECTED={json}");
            println!("cargo:rustc-env=M2A_GATE_UNAVAILABLE=");
        }
        Err(reason) => {
            let reason = reason.replace(['\n', '\r'], " ");
            println!("cargo:rustc-env=M2A_GATE_EXPECTED=");
            println!("cargo:rustc-env=M2A_GATE_UNAVAILABLE={reason}");
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

/// `rerun-if-changed` for git's HEAD, branch ref, packed refs and index. Only files that exist
/// are listed: cargo reruns on every build for a missing one.
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
