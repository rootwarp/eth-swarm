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
//! It also records the build commit and why the build was not clean, for the `m2a-summary`
//! line (`src/bin/m2a-session/build_info.rs`): `m2a-build-commit.txt` (git's `HEAD`, or empty),
//! `m2a-build-rustc.txt` (the compiler's commit hash, or empty) and `m2a-build-unclean.txt`
//! (empty for a clean build, else the reason). The build is clean only if four conditions are
//! true:
//!
//! - `m2a_dirty_paths` finds nothing under [`BUILD_PATHS`] (the paths that can change what the
//!   binaries compile; an ignored file there counts too).
//! - No variable of [`BUILD_FLAG_VARS`] (rustflags, a rustc wrapper, a linker) is set.
//! - No C or proto build variable is set (`CC`, `CFLAGS`, `PROTOC` and the rest:
//!   `build_support::is_c_build_var`).
//! - The compiler's release is the `channel` of `rust-toolchain.toml`, with the official commit
//!   of `build_support::PINNED_RUSTC` (`build_support::compiler_state`), and the compiler is the
//!   `rustc` of that rustup toolchain by its canonical path (`build_support::rustc_location`).
//!
//! A tree without git, or without the harness, is not clean.
//!
//! Cargo reruns this script when a build path, a keyed path or a harness script changes on disk
//! (or, while one is missing, its nearest existing parent below the repository root), when a
//! variable of [`BUILD_FLAG_VARS`], [`COMPILER_VARS`] or a C or proto build variable changes,
//! when git's `HEAD`, the current branch ref or the index changes (a commit, checkout, reset or
//! `git add`), or when the history depth may have (`build_support::history_watch`: a shallow
//! clone deepened or unshallowed, or a full one made shallow). While `git pack-refs` holds the branch ref, the nearest existing
//! directory of its loose file is watched (`build_support::git_watch`). A missing `.cargo` is
//! not watched (the repository root would rerun every build): step 10.2 of the runbook
//! (`ops/ref-node/README.md`) checks the tree again after the build. A new compiler rebuilds
//! every crate, and so reruns this script.

mod build_support;

use build_support::{
    bash, build_flags_unclean, build_state, c_build_watch, child_env, command, compiler_state,
    git_watch, is_c_build_var, locate_repo, run, rustc_location, rustc_version, unclean_reason,
    watch_path, BUILD_FLAG_VARS, BUILD_PATHS, COMMON, COMPILER_VARS,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const CHECKER: &str = "fuzz/check-m2a-gate.sh";

type Env = [(OsString, OsString)];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    for name in BUILD_FLAG_VARS.iter().chain(&COMPILER_VARS) {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let target = std::env::var("TARGET").unwrap_or_default();
    let host = std::env::var("HOST").unwrap_or_default();
    let set_c_vars = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| is_c_build_var(k));
    for name in c_build_watch(&target, &host).into_iter().chain(set_c_vars) {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let env = child_env(std::env::vars_os());
    let (gate_file, expected, build) = match locate_repo(&manifest, &env) {
        Ok(repo) => {
            for p in git_watch(&repo, &env) {
                println!("cargo:rerun-if-changed={}", p.display());
            }
            for path in BUILD_PATHS {
                watch(&repo, path);
            }
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
    let (commit, tree) = build;
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let toolchain = std::fs::read_to_string(manifest.join("../../rust-toolchain.toml"))
        .map_err(|e| format!("rust-toolchain.toml: {e}"));
    let (rustc_commit, compiler) =
        compiler_state(rustc_version(&rustc, &manifest), toolchain.clone());
    let unclean = unclean_reason(
        &tree,
        [
            compiler,
            compiler_location(&rustc, toolchain.as_deref().ok()),
            std::env::var_os("CARGO_BUILD_RUSTC")
                .filter(|v| !v.is_empty())
                .and_then(|other| compiler_location(&other, toolchain.as_deref().ok())),
            build_flags_unclean(std::env::vars_os()),
        ],
    );
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("set by cargo"));
    for (name, text) in [
        ("m2a-gate-expected.json", json),
        ("m2a-gate-unavailable.txt", reason),
        ("m2a-build-commit.txt", commit),
        ("m2a-build-rustc.txt", rustc_commit),
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

/// Why the compiler `rustc` is not the rustc of the pinned rustup toolchain, or `None`
/// ([`rustc_location`]). `RUSTUP_HOME` is rustup's directory, by default `~/.rustup`. With no
/// toolchain file, [`compiler_state`] already gives the reason.
fn compiler_location(rustc: &std::ffi::OsStr, toolchain: Option<&str>) -> Option<String> {
    let toolchain = toolchain?;
    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")));
    let Some(rustup_home) = rustup_home else {
        return Some("compiler: neither RUSTUP_HOME nor HOME is set".to_owned());
    };
    rustc_location(
        rustc,
        std::env::var_os("PATH").as_deref(),
        &rustup_home,
        toolchain,
    )
}

fn watch(repo: &Path, rel: &str) {
    if let Some(path) = watch_path(repo, rel) {
        println!("cargo:rerun-if-changed={}", path.display());
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
