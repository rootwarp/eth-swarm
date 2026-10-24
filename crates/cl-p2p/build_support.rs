//! The parts of `build.rs` that decide which checkout the gate expectations describe. Also
//! compiled into cl-p2p's unit tests (`lib.rs`, `#[path]`), since a build script has none.
//!
//! - [`child_env`]: every git and bash child runs with a cleared environment plus `PATH` only.
//!   `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR`, the `GIT_CONFIG*` family
//!   and the rest would point git at another repository (`git -C` does not override them), and
//!   `BASH_ENV`/`ENV` would run arbitrary code in the bash children. git also reads no system
//!   or global config or attributes (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`,
//!   `GIT_ATTR_NOSYSTEM`), so no clean filter or `core.attributesFile` outside the repository
//!   can make a modified keyed source look clean. Nothing needs `HOME`, so it is dropped too.
//!   One consequence: `safe.directory` is not read, so a checkout owned by another user fails
//!   git's ownership check, and the build embeds "unavailable" (fail closed).
//! - [`locate_repo`]: the checkout must be the one this crate sits in, as
//!   `<toplevel>/crates/cl-p2p`. A copy elsewhere (`cargo package` under `target/package/`, a
//!   vendored tree) would otherwise find the enclosing repository and embed its key.
//! - [`watch_path`]: what to watch for a path that may not exist yet.
//! - [`git_watch`]: the git files that the build commit hangs on.
//! - [`build_state`]: the build commit and the tree check over [`BUILD_PATHS`], and
//!   [`build_flags_unclean`]: the variables that make a build unclean whatever the tree holds.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The fuzz harness that holds the dirty check, relative to the repository root.
pub const COMMON: &str = "fuzz/m2a-common.sh";

/// The paths that can change what the binaries of cl-p2p compile: the workspace manifest and
/// lock file, the toolchain pin, the repository's own cargo config (`.cargo`), `proto`
/// (ethswarm-proto compiles it) and the path packages that cargo
/// compiles for them, cl-p2p with its normal and build dependencies, transitively (a test holds
/// the list to cargo's resolve). Not the other crates: an edit there changes no binary, and a
/// watch on all of `crates` reruns the build script, and so recompiles cl-p2p, after an edit in
/// any crate. `fuzz/` is not among them: the binaries do not compile it, and the gate
/// expectations already refuse a dirty keyed path there.
pub const BUILD_PATHS: [&str; 13] = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo",
    "proto",
    "crates/cl-p2p",
    "crates/consensus-types",
    "crates/ethswarm-proto",
    "crates/ipc",
    "crates/network-config",
    "crates/node-key",
    "crates/p2p-wire",
    "crates/svc-runtime",
];

/// The variables of a build script that change how rustc compiles or links, whatever the tree
/// holds: the rustflags (`CARGO_ENCODED_RUSTFLAGS` holds them from every source: `RUSTFLAGS`,
/// `CARGO_BUILD_RUSTFLAGS` and any cargo config), the rustc wrappers and the linker
/// (`RUSTC_LINKER`: from any cargo config or `CARGO_TARGET_<triple>_LINKER`), and
/// `RUSTC_BOOTSTRAP`, which turns on the unstable features of a stable toolchain (`-Z`,
/// `CARGO_UNSTABLE_*`, and a cfg in the build script of `anyhow`). A cargo config outside the
/// repository (in `$CARGO_HOME` or a parent `.cargo`) is not a build path, so these variables
/// are what the build script sees of it, and step 10.2 of the runbook
/// (`ops/ref-node/README.md`) requires that none exists. A build with any of them set and not
/// empty is not clean.
pub const BUILD_FLAG_VARS: [&str; 6] = [
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_LINKER",
    "RUSTC_BOOTSTRAP",
];

/// The variable that turns incremental compilation on (`1`) or off (`0`) for every profile.
/// The release profile compiles without it, and incremental compilation changes the code
/// generation, so only the value `1` (the only value that cargo reads as on) makes the build
/// unclean. Its reason gives the value.
pub const INCREMENTAL_VAR: &str = "CARGO_INCREMENTAL";

/// The prefixes of cargo's own variables that change the release binary, whatever the tree
/// holds: a profile setting (`CARGO_PROFILE_RELEASE_OPT_LEVEL`, `..._OVERFLOW_CHECKS`,
/// `..._PANIC` and the rest) and an unstable flag (`CARGO_UNSTABLE_BUILD_STD`). A variable with
/// one of them and a name after it, set and not empty, makes the build unclean.
pub const CARGO_FLAG_PREFIXES: [&str; 2] = ["CARGO_PROFILE_", "CARGO_UNSTABLE_"];

/// The profiles and the settings of [`CARGO_FLAG_PREFIXES`] that `build.rs` watches also when
/// they are not set: `CARGO_PROFILE_<profile>_<setting>`. An unstable flag has no fixed list.
pub const WATCHED_PROFILES: [&str; 2] = ["RELEASE", "DEV"];

/// See [`WATCHED_PROFILES`].
pub const PROFILE_SETTINGS: [&str; 11] = [
    "OPT_LEVEL",
    "DEBUG",
    "SPLIT_DEBUGINFO",
    "STRIP",
    "DEBUG_ASSERTIONS",
    "OVERFLOW_CHECKS",
    "LTO",
    "PANIC",
    "INCREMENTAL",
    "CODEGEN_UNITS",
    "RPATH",
];

/// The cargo config keys of the rustc wrappers in the environment (`build.rustc-wrapper` and
/// `build.rustc-workspace-wrapper`). Cargo gives their value to the build script as
/// `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER` ([`BUILD_FLAG_VARS`]), but it reruns the script
/// only when a watched variable of its own environment changes. So `build.rs` watches these
/// too. A wrapper that a cargo config file sets after a clean build does not rerun the script,
/// and a stale "clean" stays: step 10.2 of the runbook refuses such a config before the build.
pub const WRAPPER_CONFIG_VARS: [&str; 2] = [
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
];

/// The variables that select the compiler: cargo's `RUSTC` (also set from a cargo config or by
/// `cargo +<toolchain>` through rustup), `CARGO_BUILD_RUSTC`, and rustup's `RUSTUP_TOOLCHAIN`
/// and `RUSTUP_HOME`.
pub const COMPILER_VARS: [&str; 4] = [
    "RUSTC",
    "CARGO_BUILD_RUSTC",
    "RUSTUP_TOOLCHAIN",
    "RUSTUP_HOME",
];

/// The release and the official commit hash of the compiler that `rust-toolchain.toml` pins
/// (`rustc +1.99.0 -vV` of the rustup distribution). Change it together with the pin: a test
/// fails if the two releases differ.
pub const PINNED_RUSTC: (&str, &str) = ("1.99.0", "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4");

/// The variables of the C builds that cc reads (ring and blst compile C), also with a target
/// suffix (`CC_<target>`, with dashes or underscores) and as `TARGET_<name>` or `HOST_<name>`.
pub const C_BUILD_BASES: [&str; 6] = ["CC", "CXX", "CFLAGS", "CXXFLAGS", "AR", "ARFLAGS"];

/// The other variables that change the C and proto builds: cc's `CRATE_CC_NO_DEFAULTS`, and
/// `PROTOC`, the protobuf compiler of ethswarm-proto.
pub const C_BUILD_VARS: [&str; 2] = ["CRATE_CC_NO_DEFAULTS", "PROTOC"];

/// Whether `name` is a variable of the C or proto build ([`C_BUILD_BASES`], [`C_BUILD_VARS`]).
pub fn is_c_build_var(name: &str) -> bool {
    C_BUILD_VARS.contains(&name)
        || C_BUILD_BASES.iter().any(|base| {
            name == *base
                || name
                    .strip_prefix(base)
                    .and_then(|rest| rest.strip_prefix('_'))
                    .is_some_and(|target| !target.is_empty())
                || ["TARGET_", "HOST_"]
                    .iter()
                    .any(|prefix| name.strip_prefix(prefix) == Some(base))
        })
}

/// Whether `name` is a cargo profile or unstable variable ([`CARGO_FLAG_PREFIXES`]).
pub fn is_cargo_flag_var(name: &str) -> bool {
    CARGO_FLAG_PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty())
    })
}

/// Every variable that `build.rs` watches with `rerun-if-env-changed`, each name once:
/// [`BUILD_FLAG_VARS`], [`COMPILER_VARS`], [`WRAPPER_CONFIG_VARS`], [`INCREMENTAL_VAR`], the
/// profile settings of [`WATCHED_PROFILES`], the C and proto build variables of
/// [`c_build_watch`] for `target` and `host`, and each cargo flag or C build variable of `vars`
/// (the environment now) by name.
/// Cargo cannot watch a prefix, so a prefixed variable that is set only after a clean build
/// does not rerun the script: step 10.2 of the runbook refuses it before the build.
pub fn env_watch(
    target: &str,
    host: &str,
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<String> {
    let mut names: Vec<String> = BUILD_FLAG_VARS
        .iter()
        .chain(&COMPILER_VARS)
        .chain(&WRAPPER_CONFIG_VARS)
        .chain(&[INCREMENTAL_VAR])
        .map(|v| (*v).to_owned())
        .collect();
    for profile in WATCHED_PROFILES {
        for setting in PROFILE_SETTINGS {
            names.push(format!("CARGO_PROFILE_{profile}_{setting}"));
        }
    }
    names.extend(c_build_watch(target, host));
    let mut set: Vec<String> = vars
        .into_iter()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| is_cargo_flag_var(k) || is_c_build_var(k))
        .collect();
    set.sort_unstable();
    names.extend(set);
    let mut unique = Vec::new();
    for name in names {
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    unique
}

/// The C and proto build variables to watch with `rerun-if-env-changed` for `target` and
/// `host`: each form that cc reads.
pub fn c_build_watch(target: &str, host: &str) -> Vec<String> {
    let mut names: Vec<String> = C_BUILD_VARS.iter().map(|v| (*v).to_owned()).collect();
    for base in C_BUILD_BASES {
        names.push(base.to_owned());
        names.push(format!("TARGET_{base}"));
        names.push(format!("HOST_{base}"));
        for triple in [target, host] {
            names.push(format!("{base}_{triple}"));
            names.push(format!("{base}_{}", triple.replace('-', "_")));
        }
    }
    let mut unique = Vec::new();
    for name in names {
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    unique
}

/// How the reason of [`compiler_state`] starts.
pub const COMPILER_REASON: &str = "compiler: ";

/// How the reason of [`build_flags_unclean`] starts.
pub const FLAGS_REASON: &str = "built with ";

/// The only variable a child inherits.
pub const KEPT_VARS: [&str; 1] = ["PATH"];

/// What every child gets on top: no `git status` rewrites the index during a build
/// (`GIT_OPTIONAL_LOCKS=0`), and git reads only the repository's own config and attributes.
pub const SET_VARS: [(&str, &str); 4] = [
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_ATTR_NOSYSTEM", "1"),
];

/// The environment of a git or bash child: `PATH` from `parent`, then [`SET_VARS`].
pub fn child_env(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = parent
        .into_iter()
        .filter(|(k, _)| KEPT_VARS.iter().any(|kept| k == kept))
        .collect();
    env.extend(SET_VARS.iter().map(|(k, v)| ((*k).into(), (*v).into())));
    env
}

/// `program` with exactly `env`.
pub fn command(program: &str, env: &[(OsString, OsString)]) -> Command {
    let mut c = Command::new(program);
    c.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    c
}

/// Runs `command`; its stdout, or why it failed.
pub fn run(command: &mut Command, what: &str) -> Result<String, String> {
    let out = command
        .output()
        .map_err(|e| format!("cannot run {what}: {e}"))?;
    if !out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{what}: {} {}", stderr.trim(), stdout.trim()));
    }
    String::from_utf8(out.stdout).map_err(|_| format!("{what}: output not UTF-8"))
}

/// Runs git in `dir` with `env`.
pub fn git(dir: &Path, args: &[&str], env: &[(OsString, OsString)]) -> Result<String, String> {
    run(
        command("git", env).arg("-C").arg(dir).args(args),
        &format!("git {}", args.join(" ")),
    )
}

/// The checkout whose `crates/cl-p2p` is `manifest_dir`, canonical.
pub fn locate_repo(manifest_dir: &Path, env: &[(OsString, OsString)]) -> Result<PathBuf, String> {
    let top = git(manifest_dir, &["rev-parse", "--show-toplevel"], env)
        .map_err(|e| format!("no git checkout: {e}"))?;
    check_toplevel(manifest_dir, Path::new(top.trim()))
}

/// `toplevel`, canonical, if `manifest_dir` is its `crates/cl-p2p`.
pub fn check_toplevel(manifest_dir: &Path, toplevel: &Path) -> Result<PathBuf, String> {
    let canonical = |p: &Path| {
        p.canonicalize()
            .map_err(|e| format!("{}: {e}", p.display()))
    };
    let manifest = canonical(manifest_dir)?;
    let top = canonical(toplevel)?;
    if manifest == top.join("crates").join("cl-p2p") {
        Ok(top)
    } else {
        Err(format!(
            "{} is not crates/cl-p2p of the git checkout at {}, so that checkout's key would \
             not describe these sources",
            manifest.display(),
            top.display()
        ))
    }
}

/// Runs `script` (with [`COMMON`] as `$1`) in bash, in `repo`.
pub fn bash(repo: &Path, script: &str, env: &[(OsString, OsString)]) -> Result<String, String> {
    run(
        command("bash", env)
            .current_dir(repo)
            .args(["-c", script, "build.rs", COMMON]),
        &format!("bash -c '{script}'"),
    )
}

/// Why the build is not clean because of its variables ([`BUILD_FLAG_VARS`], then
/// [`INCREMENTAL_VAR`] with the value `1`, then the cargo profile and unstable variables of
/// [`is_cargo_flag_var`] and the C and proto build variables of [`is_c_build_var`], each group
/// by name), or `None`. Only the names are given (and the value `1` of [`INCREMENTAL_VAR`]): a
/// flag can hold a path or a secret.
pub fn build_flags_unclean(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Option<String> {
    let vars: Vec<(OsString, OsString)> = vars.into_iter().collect();
    let mut set: Vec<&str> = BUILD_FLAG_VARS
        .iter()
        .copied()
        .filter(|name| vars.iter().any(|(k, v)| k == name && !v.is_empty()))
        .collect();
    let incremental = format!("{INCREMENTAL_VAR}=1");
    if vars.iter().any(|(k, v)| k == INCREMENTAL_VAR && v == "1") {
        set.push(&incremental);
    }
    for is_group in [is_cargo_flag_var, is_c_build_var] {
        let mut group: Vec<&str> = vars
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .filter_map(|(k, _)| k.to_str())
            .filter(|k| is_group(k))
            .collect();
        group.sort_unstable();
        group.dedup();
        set.extend(group);
    }
    (!set.is_empty()).then(|| format!("{FLAGS_REASON}{} set", set.join(", ")))
}

/// The reason that `build.rs` embeds: the tree's reason (empty for a clean tree), then each
/// other reason that is given ([`compiler_state`], [`build_flags_unclean`]), joined by `; `.
pub fn unclean_reason(tree: &str, others: impl IntoIterator<Item = Option<String>>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !tree.is_empty() {
        parts.push(tree.to_owned());
    }
    parts.extend(others.into_iter().flatten());
    parts.join("; ")
}

/// The `channel` of the `[toolchain]` table of a `rust-toolchain.toml`, if there is one.
pub fn pinned_channel(toolchain: &str) -> Option<String> {
    let mut in_toolchain = false;
    for line in toolchain.lines().map(str::trim) {
        if line.starts_with('[') {
            in_toolchain = line == "[toolchain]";
            continue;
        }
        let Some((key, value)) = line.split_once('=').filter(|_| in_toolchain) else {
            continue;
        };
        if key.trim() == "channel" {
            let value = value.trim();
            let unquoted = ['"', '\'']
                .iter()
                .find_map(|q| value.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)));
            return unquoted.map(str::to_owned);
        }
    }
    None
}

/// `<rustc> -vV`, run in `dir` with the environment of this process: the compiler that cargo
/// runs (a rustup proxy resolves it by `RUSTUP_TOOLCHAIN` and the toolchain file of `dir`).
pub fn rustc_version(rustc: &std::ffi::OsStr, dir: &Path) -> Result<String, String> {
    run(
        Command::new(rustc).current_dir(dir).arg("-vV"),
        &format!("{} -vV", Path::new(rustc).display()),
    )
}

/// Why the compiler at `rustc` makes the build unclean, or `None`: it must be, by its canonical
/// path, the `rustc` of the rustup toolchain of the pinned channel for the build host,
/// exactly `<rustup_home>/toolchains/<channel>-<host>/bin/rustc`. A bare name is looked up on
/// `path`. Otherwise a wrapper that prints the real `-vV` would pass [`compiler_state`], and
/// another directory that starts with the channel (`1.99.0-mine`) could hold any compiler.
pub fn rustc_location(
    rustc: &std::ffi::OsStr,
    path: Option<&std::ffi::OsStr>,
    rustup_home: &Path,
    host: &str,
    toolchain: &str,
) -> Option<String> {
    let reason = |why: String| Some(format!("{COMPILER_REASON}{why}"));
    let Some(channel) = pinned_channel(toolchain) else {
        return reason("rust-toolchain.toml pins no channel".to_owned());
    };
    if host.is_empty() {
        return reason("the host triple (HOST) is not set".to_owned());
    }
    let pinned_dir = format!("{channel}-{host}");
    let given = Path::new(rustc);
    let found = if given.components().count() > 1 {
        Some(given.to_path_buf())
    } else {
        path.and_then(|path| {
            std::env::split_paths(path)
                .map(|dir| dir.join(given))
                .find(|candidate| candidate.is_file())
        })
    };
    let Some(canonical) = found.and_then(|f| f.canonicalize().ok()) else {
        return reason(format!("cannot find the rustc {}", given.display()));
    };
    let toolchains = rustup_home.join("toolchains");
    let bin = canonical.parent();
    let toolchain_dir = bin.and_then(Path::parent);
    let pinned = canonical.file_name() == Some("rustc".as_ref())
        && bin.and_then(Path::file_name) == Some("bin".as_ref())
        && toolchain_dir.and_then(Path::file_name) == Some(pinned_dir.as_ref())
        && toolchain_dir.and_then(Path::parent) == toolchains.canonicalize().ok().as_deref();
    if pinned {
        None
    } else {
        reason(format!(
            "{} is not the rustc of the rustup toolchain {pinned_dir} in {}",
            canonical.display(),
            toolchains.display()
        ))
    }
}

/// The compiler's commit hash (from `rustc -vV`, or empty) and why the compiler makes the
/// build unclean, or `None`: its `release` must be the `channel` that `rust-toolchain.toml`
/// pins, and its commit hash the official one of [`PINNED_RUSTC`]. `RUSTC`, `RUSTUP_TOOLCHAIN`,
/// a rustup override or `cargo +<toolchain>` can replace the pin, and the build tree does not
/// show it.
pub fn compiler_state(
    version: Result<String, String>,
    toolchain: Result<String, String>,
) -> (String, Option<String>) {
    let reason = |why: String| Some(format!("{COMPILER_REASON}{why}"));
    let version = match version {
        Ok(version) => version,
        Err(e) => return (String::new(), reason(e)),
    };
    let field = |name: &str| {
        version
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let (Some(hash), Some(release)) = (field("commit-hash:"), field("release:")) else {
        return (
            String::new(),
            reason("rustc -vV gave no commit-hash or no release".to_owned()),
        );
    };
    let pinned = match toolchain {
        Ok(toolchain) => pinned_channel(&toolchain),
        Err(e) => return (hash, reason(e)),
    };
    match pinned {
        None => (
            hash,
            reason("rust-toolchain.toml pins no channel".to_owned()),
        ),
        Some(pinned) if pinned == release && PINNED_RUSTC.0 != release => {
            let why = format!("no official commit of rustc {release} is pinned (PINNED_RUSTC)");
            (hash, reason(why))
        }
        Some(pinned) if pinned == release && hash != PINNED_RUSTC.1 => {
            let why = format!(
                "rustc {release} has commit {hash}, not the official {}",
                PINNED_RUSTC.1
            );
            (hash, reason(why))
        }
        Some(pinned) if pinned == release => (hash, None),
        Some(pinned) => (
            hash,
            reason(format!(
                "rustc {release} is not the release {pinned} that rust-toolchain.toml pins"
            )),
        ),
    }
}

/// The build commit (git's `HEAD`, or empty) and why the build tree was not clean (empty if it
/// was): `m2a_dirty_paths` of the harness over [`BUILD_PATHS`]. That check also lists ignored
/// files. At most five paths are named.
pub fn build_state(repo: &Path, env: &[(OsString, OsString)]) -> (String, String) {
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

/// The git files that the build commit hangs on, for `rerun-if-changed`: HEAD, the index,
/// `packed-refs`, the current branch's ref and the history depth ([`history_watch`]). Only
/// paths that exist are returned: cargo reruns on every build for a missing one.
///
/// The branch ref is a loose file until `git pack-refs` moves it into `packed-refs`. A later
/// update (a `reset --soft`, an `update-ref`) writes the loose file again and changes no other
/// watched file. So while the loose file is missing, its nearest existing ancestor below the
/// common git dir is watched (`refs/heads`, say), never the git dir itself.
pub fn git_watch(repo: &Path, env: &[(OsString, OsString)]) -> Vec<PathBuf> {
    let path = |args: &[&str]| git(repo, args, env).ok().map(|p| repo.join(p.trim()));
    let mut out = Vec::new();
    for name in ["HEAD", "index", "packed-refs"] {
        if let Some(p) = path(&["rev-parse", "--git-path", name]).filter(|p| p.exists()) {
            out.push(p);
        }
    }
    if let Ok(branch) = git(repo, &["symbolic-ref", "-q", "HEAD"], env) {
        let branch = branch.trim();
        if let Some(common) = path(&["rev-parse", "--git-common-dir"]) {
            if let Some(p) = watch_path(&common, branch) {
                out.push(p);
            }
        }
    }
    for p in history_watch(repo, env) {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// What to watch for `rel` under `repo`: the path if it exists, else its nearest existing
/// ancestor below `repo`. `None` when only the repository root exists: watching it would scan
/// `target/` and rerun every build, and a new top-level path arrives either through a commit or
/// checkout (git's HEAD and index are watched) or untracked, which is dirty and refused anyway.
pub fn watch_path(repo: &Path, rel: &str) -> Option<PathBuf> {
    let mut path = repo.join(rel);
    loop {
        if path == repo {
            return None;
        }
        if path.exists() {
            return Some(path);
        }
        if !path.pop() || !path.starts_with(repo) {
            return None;
        }
    }
}

/// What the history depth of `repo` hangs on, for `rerun-if-changed`: the ancestors git lists
/// change when a shallow clone is deepened or unshallowed, with HEAD where it was.
///
/// In a shallow clone that is git's `shallow` file, in the common git dir (`git rev-parse
/// --git-path shallow`, also from a linked worktree): a deepening fetch rewrites it, and
/// `--unshallow` removes it. In a full clone it is missing, and cargo reruns on every build for a
/// missing path, so the watch is then the `FETCH_HEAD` that every fetch writes (the one that
/// makes a clone shallow too), of this worktree's git dir and of the common one, where they
/// exist. Only paths that exist are returned.
pub fn history_watch(repo: &Path, env: &[(OsString, OsString)]) -> Vec<PathBuf> {
    let path = |args: &[&str]| git(repo, args, env).ok().map(|p| repo.join(p.trim()));
    if let Some(shallow) = path(&["rev-parse", "--git-path", "shallow"]).filter(|p| p.exists()) {
        return vec![shallow];
    }
    let mut out = Vec::new();
    for dir in ["--git-dir", "--git-common-dir"] {
        let Some(fetch_head) = path(&["rev-parse", dir]).map(|d| d.join("FETCH_HEAD")) else {
            continue;
        };
        if fetch_head.exists() && !out.contains(&fetch_head) {
            out.push(fetch_head);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    /// The test process's PATH and HOME, for real git runs.
    fn real_env() -> Vec<(OsString, OsString)> {
        child_env(std::env::vars_os())
    }

    fn init_repo(dir: &Path) {
        std::fs::create_dir_all(dir.join("crates/cl-p2p")).unwrap();
        git(dir, &["init", "-q"], &real_env()).unwrap();
    }

    #[test]
    fn child_env_keeps_only_path() {
        let parent = os(&[
            ("PATH", "/usr/bin"),
            ("HOME", "/home/u"),
            ("XDG_CONFIG_HOME", "/home/u/.config"),
            ("GIT_DIR", "/elsewhere/.git"),
            ("GIT_WORK_TREE", "/elsewhere"),
            ("GIT_INDEX_FILE", "/elsewhere/.git/index"),
            ("GIT_COMMON_DIR", "/elsewhere/.git"),
            ("GIT_OBJECT_DIRECTORY", "/x"),
            ("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/x"),
            ("GIT_CEILING_DIRECTORIES", "/"),
            ("GIT_NAMESPACE", "n"),
            ("GIT_CONFIG", "/x"),
            ("GIT_CONFIG_GLOBAL", "/x"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.worktree"),
            ("GIT_CONFIG_VALUE_0", "/elsewhere"),
            ("BASH_ENV", "/tmp/evil.sh"),
            ("ENV", "/tmp/evil.sh"),
            ("CARGO_MANIFEST_DIR", "/m"),
        ]);
        assert_eq!(
            child_env(parent),
            os(&[
                ("PATH", "/usr/bin"),
                ("GIT_OPTIONAL_LOCKS", "0"),
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_ATTR_NOSYSTEM", "1"),
            ])
        );
        let cmd = command("git", &os(&[("PATH", "/usr/bin")]));
        let envs: Vec<_> = cmd.get_envs().collect();
        assert_eq!(envs.len(), 1, "a cleared environment plus the given");
    }

    /// A global git config whose clean filter maps every file back to its committed content
    /// makes a modified file look clean. The child environment reads no global config.
    #[test]
    fn a_global_clean_filter_cannot_hide_a_change() {
        let repo = tempfile::tempdir().unwrap();
        init_repo(repo.path());
        let env = real_env();
        let file = repo.path().join("crates/cl-p2p/src.rs");
        std::fs::write(&file, "committed\n").unwrap();
        git(repo.path(), &["add", "."], &env).unwrap();
        git(
            repo.path(),
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "-m",
                "x",
            ],
            &env,
        )
        .unwrap();
        // Same length: git compares content (through the filter) only when the size matches.
        std::fs::write(&file, "tampered!\n").unwrap();

        let home = tempfile::tempdir().unwrap();
        let attributes = home.path().join("attributes");
        std::fs::write(&attributes, "* filter=hide\n").unwrap();
        let config = format!(
            "[core]\n\tattributesFile = {}\n[filter \"hide\"]\n\tclean = printf 'committed\\\\n'\n",
            attributes.display()
        );
        std::fs::write(home.path().join(".gitconfig"), config).unwrap();
        let status = |env: &[(OsString, OsString)]| {
            git(repo.path(), &["status", "--porcelain", "--", "crates"], env).unwrap()
        };
        // The unscrubbed probes run on a copy of the index, and take no optional lock: a
        // `git status` through the filter would otherwise refresh the real index with the
        // tampered file's stat data, and the scrubbed status below would then trust that stat
        // cache and report the file clean (whether it does depends on timestamp granularity).
        let index_copy = home.path().join("probe-index");
        let probe = |mut env: Vec<(OsString, OsString)>| {
            std::fs::copy(repo.path().join(".git/index"), &index_copy).unwrap();
            env.push(("GIT_INDEX_FILE".into(), index_copy.clone().into()));
            env.push(("GIT_OPTIONAL_LOCKS".into(), "0".into()));
            status(&env)
        };
        let index_before = std::fs::read(repo.path().join(".git/index")).unwrap();
        // With the parent's HOME (or GIT_CONFIG_GLOBAL) pointing at that config, the change hides.
        let mut parent: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(k, _)| k != "GIT_CONFIG_GLOBAL")
            .collect();
        parent.push(("HOME".into(), home.path().into()));
        let mut with_home = parent.clone();
        with_home.retain(|(k, _)| k == "PATH" || k == "HOME");
        assert_eq!(probe(with_home), "", "the filter hides the change");
        let mut with_global = os(&[]);
        with_global.extend(parent.iter().filter(|(k, _)| k == "PATH").cloned());
        with_global.push((
            "GIT_CONFIG_GLOBAL".into(),
            home.path().join(".gitconfig").into(),
        ));
        assert_eq!(probe(with_global), "");
        assert_eq!(
            std::fs::read(repo.path().join(".git/index")).unwrap(),
            index_before,
            "the probes leave the real index alone"
        );
        // Scrubbed, it shows.
        let mut scrubbed_parent = parent;
        scrubbed_parent.push((
            "GIT_CONFIG_GLOBAL".into(),
            home.path().join(".gitconfig").into(),
        ));
        assert_eq!(
            status(&child_env(scrubbed_parent)).trim(),
            "M crates/cl-p2p/src.rs"
        );
    }

    #[test]
    fn a_fake_git_work_tree_is_ignored() {
        let ours = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        init_repo(ours.path());
        init_repo(other.path());
        let manifest = ours.path().join("crates/cl-p2p");
        let mut parent: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        parent.push(("GIT_DIR".into(), other.path().join(".git").into()));
        parent.push(("GIT_WORK_TREE".into(), other.path().into()));
        // Inherited as is, the variables would point git at the other checkout.
        let raw: Vec<(OsString, OsString)> = parent.clone();
        let leaked = git(&manifest, &["rev-parse", "--show-toplevel"], &raw).unwrap();
        assert_eq!(
            Path::new(leaked.trim()).canonicalize().unwrap(),
            other.path().canonicalize().unwrap()
        );
        // Scrubbed, the checkout is the one the crate sits in.
        assert_eq!(
            locate_repo(&manifest, &child_env(parent)).unwrap(),
            ours.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn a_mismatched_toplevel_is_refused() {
        let repo = tempfile::tempdir().unwrap();
        init_repo(repo.path());
        // `cargo package` builds a copy under target/package/, inside the checkout.
        let packaged = repo.path().join("target/package/cl-p2p-0.1.0");
        std::fs::create_dir_all(&packaged).unwrap();
        let err = locate_repo(&packaged, &real_env()).unwrap_err();
        assert!(err.contains("is not crates/cl-p2p"), "{err}");
        let elsewhere = repo.path().join("crates/other");
        std::fs::create_dir_all(&elsewhere).unwrap();
        assert!(check_toplevel(&elsewhere, repo.path()).is_err());
        assert!(check_toplevel(&repo.path().join("missing"), repo.path()).is_err());
        assert_eq!(
            check_toplevel(&repo.path().join("crates/cl-p2p"), repo.path()).unwrap(),
            repo.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn no_git_checkout_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = locate_repo(dir.path(), &real_env()).unwrap_err();
        assert!(err.starts_with("no git checkout"), "{err}");
        let err = locate_repo(dir.path(), &os(&[("PATH", "/nonexistent")])).unwrap_err();
        assert!(err.starts_with("no git checkout: cannot run git"), "{err}");
    }

    /// The history depth hangs on git's shallow file while the clone is shallow (the common git
    /// dir's, also from a linked worktree), and on the fetch that writes FETCH_HEAD otherwise.
    #[test]
    fn the_history_depth_is_watched() {
        let env = real_env();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let origin = root.join("origin");
        init_repo(&origin);
        for n in ["a", "b", "c"] {
            std::fs::write(origin.join(n), n).unwrap();
            git(&origin, &["add", n], &env).unwrap();
            let msg = format!("commit {n}");
            git(
                &origin,
                &[
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                    "commit",
                    "-q",
                    "-m",
                    &msg,
                ],
                &env,
            )
            .unwrap();
        }
        let canonical = |paths: Vec<PathBuf>| -> Vec<PathBuf> {
            paths.iter().map(|p| p.canonicalize().unwrap()).collect()
        };
        // A full clone that never fetched: nothing to watch (a missing path reruns every build).
        assert_eq!(history_watch(&origin, &env), Vec::<PathBuf>::new());
        git(&origin, &["fetch", "-q", ".", "HEAD"], &env).unwrap();
        assert_eq!(
            canonical(history_watch(&origin, &env)),
            vec![origin.join(".git/FETCH_HEAD")]
        );
        let url = format!("file://{}", origin.display());
        let shallow = root.join("shallow");
        git(
            &root,
            &["clone", "-q", "--depth", "1", &url, "shallow"],
            &env,
        )
        .unwrap();
        assert_eq!(
            canonical(history_watch(&shallow, &env)),
            vec![shallow.join(".git/shallow")]
        );
        let linked = root.join("linked");
        git(
            &shallow,
            &["worktree", "add", "-q", "--detach", "../linked"],
            &env,
        )
        .unwrap();
        assert_eq!(
            canonical(history_watch(&linked, &env)),
            vec![shallow.join(".git/shallow")],
            "a linked worktree shares the common dir's shallow file"
        );
        git(&linked, &["fetch", "-q", "--unshallow"], &env).unwrap();
        assert!(!shallow.join(".git/shallow").exists());
        assert_eq!(
            canonical(history_watch(&linked, &env)),
            vec![shallow.join(".git/worktrees/linked/FETCH_HEAD")]
        );
    }

    #[test]
    fn missing_paths_watch_their_nearest_existing_parent() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        std::fs::create_dir_all(root.join("fuzz/src")).unwrap();
        assert_eq!(watch_path(root, "fuzz/src"), Some(root.join("fuzz/src")));
        assert_eq!(
            watch_path(root, "fuzz/m2a-common.sh"),
            Some(root.join("fuzz"))
        );
        assert_eq!(watch_path(root, "fuzz/corpus/a/b"), Some(root.join("fuzz")));
        assert_eq!(
            watch_path(root, "nothing/here"),
            None,
            "never the repo root"
        );
        assert_eq!(watch_path(root, ""), None);
    }

    fn commit_all(repo: &Path, msg: &str) {
        let env = real_env();
        git(repo, &["add", "-A"], &env).unwrap();
        git(
            repo,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "-m",
                msg,
            ],
            &env,
        )
        .unwrap();
    }

    /// The crates of [`BUILD_PATHS`] are exactly the path packages that the binaries of cl-p2p
    /// compile: cl-p2p and its normal and build dependencies, transitively, on every target
    /// (cargo's resolve). A dev-dependency (cl-chain, say) is not among them.
    #[test]
    fn the_build_paths_are_the_closure_of_the_binarys_path_dependencies() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let out = Command::new(env!("CARGO"))
            .args(["metadata", "--locked", "--offline", "--format-version", "1"])
            .arg("--manifest-path")
            .arg(repo.join("Cargo.toml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "cargo metadata: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let packages = meta["packages"].as_array().unwrap();
        let root = packages
            .iter()
            .find(|p| p["name"] == "cl-p2p")
            .map(|p| p["id"].as_str().unwrap())
            .unwrap();
        let nodes: std::collections::HashMap<&str, &serde_json::Value> = meta["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| (n["id"].as_str().unwrap(), n))
            .collect();
        let mut seen = vec![root];
        let mut next = vec![root];
        while let Some(id) = next.pop() {
            for dep in nodes[id]["deps"].as_array().unwrap() {
                let compiled = dep["dep_kinds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|k| k["kind"].is_null() || k["kind"] == "build");
                let pkg = dep["pkg"].as_str().unwrap();
                if compiled && !seen.contains(&pkg) {
                    seen.push(pkg);
                    next.push(pkg);
                }
            }
        }
        let mut closure: Vec<String> = packages
            .iter()
            .filter(|p| p["source"].is_null() && seen.contains(&p["id"].as_str().unwrap()))
            .map(|p| {
                let manifest = Path::new(p["manifest_path"].as_str().unwrap());
                let dir = manifest.parent().unwrap().canonicalize().unwrap();
                dir.strip_prefix(&repo).unwrap().display().to_string()
            })
            .collect();
        closure.sort();
        let mut listed: Vec<String> = BUILD_PATHS
            .iter()
            .filter(|p| p.starts_with("crates/"))
            .map(|p| (*p).to_owned())
            .collect();
        listed.sort();
        assert_eq!(listed, closure);
        assert!(!closure.contains(&"crates/cl-chain".to_owned()));
        for path in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo",
            "proto",
        ] {
            assert!(BUILD_PATHS.contains(&path), "{path}");
        }
    }

    /// After `git pack-refs --all` the branch has no loose ref, and a later reset writes one
    /// again without a change to HEAD, the index or `packed-refs`. A watched path holds it.
    #[test]
    fn a_packed_branch_ref_is_still_watched() {
        let env = real_env();
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().canonicalize().unwrap();
        init_repo(&repo);
        for n in ["a", "b"] {
            std::fs::write(repo.join(n), n).unwrap();
            commit_all(&repo, n);
        }
        let branch = git(&repo, &["symbolic-ref", "-q", "HEAD"], &env).unwrap();
        let loose = repo.join(".git").join(branch.trim());
        assert!(loose.is_file());
        assert!(git_watch(&repo, &env).contains(&loose));
        git(&repo, &["pack-refs", "--all"], &env).unwrap();
        assert!(!loose.exists(), "pack-refs removed the loose ref");
        let watched = git_watch(&repo, &env);
        assert!(watched.iter().all(|p| p.exists()), "{watched:?}");
        git(&repo, &["reset", "-q", "--soft", "HEAD~1"], &env).unwrap();
        assert!(loose.is_file(), "the reset wrote a loose ref");
        assert!(
            watched.iter().any(|w| loose.starts_with(w)),
            "{} is under no watched path: {watched:?}",
            loose.display()
        );
        assert!(
            !watched.contains(&repo.join(".git")),
            "never the whole git dir: {watched:?}"
        );
    }

    /// A rustflags variable or a rustc wrapper that is set makes the build unclean. Cargo
    /// sets `CARGO_ENCODED_RUSTFLAGS` for every build script, empty when there are no flags.
    #[test]
    fn rustflags_and_wrappers_make_the_build_unclean() {
        let none = os(&[("PATH", "/usr/bin"), ("CARGO_ENCODED_RUSTFLAGS", "")]);
        assert_eq!(build_flags_unclean(none), None);
        assert_eq!(build_flags_unclean(os(&[("RUSTFLAGS", "")])), None);
        let flags = os(&[
            ("RUSTFLAGS", "-C target-cpu=native"),
            ("CARGO_ENCODED_RUSTFLAGS", "-C\u{1f}target-cpu=native"),
        ]);
        assert_eq!(
            build_flags_unclean(flags).as_deref(),
            Some("built with RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS set")
        );
        let config = os(&[("CARGO_ENCODED_RUSTFLAGS", "--cfg\u{1f}x")]);
        assert_eq!(
            build_flags_unclean(config).as_deref(),
            Some("built with CARGO_ENCODED_RUSTFLAGS set")
        );
        let wrapper = os(&[
            ("RUSTC_WRAPPER", "sccache"),
            ("RUSTC_WORKSPACE_WRAPPER", "w"),
        ]);
        assert_eq!(
            build_flags_unclean(wrapper).as_deref(),
            Some("built with RUSTC_WRAPPER, RUSTC_WORKSPACE_WRAPPER set")
        );
        // Cargo gives the build script the linker of any cargo config (one outside the
        // repository too) or of CARGO_TARGET_<triple>_LINKER as RUSTC_LINKER.
        let linker = os(&[("RUSTC_LINKER", "/home/u/other-ld")]);
        assert_eq!(
            build_flags_unclean(linker).as_deref(),
            Some("built with RUSTC_LINKER set")
        );
        let flags = || Some("built with RUSTFLAGS set".to_owned());
        let compiler = || Some("compiler: rustc 1.98.0".to_owned());
        assert_eq!(unclean_reason("", [None, None]), "");
        assert_eq!(unclean_reason("tree", [None, None]), "tree");
        assert_eq!(
            unclean_reason("", [None, flags()]),
            "built with RUSTFLAGS set"
        );
        assert_eq!(
            unclean_reason("tree", [compiler(), flags()]),
            "tree; compiler: rustc 1.98.0; built with RUSTFLAGS set"
        );
    }

    const RUSTC_HASH: &str = "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4";

    /// The variables of the C and proto builds (cc for ring and blst, prost for
    /// ethswarm-proto) make the build unclean, in each form that cc reads: plain, with the
    /// target in either spelling, and with TARGET_ or HOST_. Only the names are given.
    #[test]
    fn c_compiler_and_protoc_variables_make_the_build_unclean() {
        let vars = os(&[
            ("PROTOC", "/home/u/protoc"),
            ("CC", "clang"),
            ("CFLAGS", "-O0"),
            ("CXX", "clang++"),
            ("CXXFLAGS", "-O0"),
            ("AR", "llvm-ar"),
            ("CRATE_CC_NO_DEFAULTS", "1"),
            ("CC_x86_64-unknown-linux-gnu", "gcc"),
            ("CFLAGS_x86_64_unknown_linux_gnu", "-g"),
            ("TARGET_CC", "gcc"),
            ("HOST_CXXFLAGS", "-g"),
            ("PATH", "/usr/bin"),
            ("CCACHE_DIR", "/c"),
            ("HOSTNAME", "h"),
            ("TARGET", "x86_64-unknown-linux-gnu"),
            ("ARCH", "x86_64"),
        ]);
        assert_eq!(
            build_flags_unclean(vars).as_deref(),
            Some(
                "built with AR, CC, CC_x86_64-unknown-linux-gnu, CFLAGS, \
                 CFLAGS_x86_64_unknown_linux_gnu, CRATE_CC_NO_DEFAULTS, CXX, CXXFLAGS, \
                 HOST_CXXFLAGS, PROTOC, TARGET_CC set"
            )
        );
        let both = os(&[("RUSTFLAGS", "-g"), ("CC", "clang")]);
        assert_eq!(
            build_flags_unclean(both).as_deref(),
            Some("built with RUSTFLAGS, CC set")
        );
        assert_eq!(build_flags_unclean(os(&[("CC", "")])), None);
        let watched = c_build_watch("x86_64-unknown-linux-gnu", "aarch64-apple-darwin");
        for name in [
            "CC",
            "PROTOC",
            "CRATE_CC_NO_DEFAULTS",
            "TARGET_CC",
            "HOST_CFLAGS",
            "CC_x86_64-unknown-linux-gnu",
            "CC_x86_64_unknown_linux_gnu",
            "CXXFLAGS_aarch64_apple_darwin",
            "AR_aarch64-apple-darwin",
        ] {
            assert!(watched.iter().any(|w| w == name), "{name}: {watched:?}");
        }
    }

    /// A profile setting or an unstable flag of cargo in the environment changes the release
    /// binary (an opt-level, overflow checks, `panic = "abort"`), so it makes the build
    /// unclean. Only the names are given, sorted, after the rustflags and before the C build.
    #[test]
    fn cargo_profile_and_unstable_variables_make_the_build_unclean() {
        let opt = os(&[("CARGO_PROFILE_RELEASE_OPT_LEVEL", "0")]);
        assert_eq!(
            build_flags_unclean(opt).as_deref(),
            Some("built with CARGO_PROFILE_RELEASE_OPT_LEVEL set")
        );
        let vars = os(&[
            ("CC", "clang"),
            ("CARGO_UNSTABLE_BUILD_STD", "std"),
            ("CARGO_PROFILE_RELEASE_PANIC", "abort"),
            ("CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS", "false"),
            ("RUSTFLAGS", "-g"),
            ("CARGO_PROFILE_DEV_DEBUG", ""),
            ("CARGO_PROFILE_", "x"),
            ("CARGO_PKG_NAME", "cl-p2p"),
            ("CARGO_MANIFEST_DIR", "/r/crates/cl-p2p"),
        ]);
        assert_eq!(
            build_flags_unclean(vars).as_deref(),
            Some(
                "built with RUSTFLAGS, CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS, \
                 CARGO_PROFILE_RELEASE_PANIC, CARGO_UNSTABLE_BUILD_STD, CC set"
            )
        );
        for name in ["CARGO_PROFILE_RELEASE_LTO", "CARGO_UNSTABLE_X"] {
            assert!(is_cargo_flag_var(name), "{name}");
        }
        for name in [
            "CARGO_PROFILE_",
            "CARGO_UNSTABLE_",
            "CARGO_PROFILE",
            "CARGO_PKG_NAME",
        ] {
            assert!(!is_cargo_flag_var(name), "{name}");
        }
    }

    /// `RUSTC_BOOTSTRAP` turns on the unstable features of a stable toolchain (`-Z`,
    /// `CARGO_UNSTABLE_*`, and a cfg in the build script of `anyhow`), and `CARGO_INCREMENTAL=1`
    /// changes the code generation of the release build. Each makes the build unclean.
    /// `CARGO_INCREMENTAL=0` turns incremental compilation off, as the release profile does, so
    /// it does not.
    #[test]
    fn rustc_bootstrap_and_incremental_compilation_make_the_build_unclean() {
        let bootstrap = os(&[("RUSTC_BOOTSTRAP", "1")]);
        assert_eq!(
            build_flags_unclean(bootstrap).as_deref(),
            Some("built with RUSTC_BOOTSTRAP set")
        );
        let incremental = os(&[("CARGO_INCREMENTAL", "1")]);
        assert_eq!(
            build_flags_unclean(incremental).as_deref(),
            Some("built with CARGO_INCREMENTAL=1 set")
        );
        for value in ["0", ""] {
            let off = os(&[("CARGO_INCREMENTAL", value), ("CARGO_BUILD_JOBS", "4")]);
            assert_eq!(build_flags_unclean(off), None, "CARGO_INCREMENTAL={value}");
        }
        let all = os(&[
            ("CARGO_UNSTABLE_BUILD_STD", "std"),
            ("CARGO_INCREMENTAL", "1"),
            ("RUSTC_BOOTSTRAP", "1"),
            ("RUSTFLAGS", "-g"),
        ]);
        assert_eq!(
            build_flags_unclean(all).as_deref(),
            Some(
                "built with RUSTFLAGS, RUSTC_BOOTSTRAP, CARGO_INCREMENTAL=1, \
                 CARGO_UNSTABLE_BUILD_STD set"
            )
        );
    }

    /// `build.rs` reruns when a variable that makes the build unclean changes: each fixed name,
    /// the profile settings of the release and dev profiles, the cargo config keys of the
    /// rustc wrappers, and each prefixed variable that is set now. A prefixed variable that is
    /// set only after a clean build is not watched: step 10.2 of the runbook refuses it before
    /// the build.
    #[test]
    fn the_build_script_watches_every_variable_that_makes_the_build_unclean() {
        let set = os(&[
            ("CARGO_UNSTABLE_BUILD_STD", "std"),
            ("CC_wasm32-unknown-unknown", "clang"),
            ("CARGO_PKG_NAME", "cl-p2p"),
        ]);
        let watched = env_watch("x86_64-unknown-linux-gnu", "aarch64-apple-darwin", set);
        for name in BUILD_FLAG_VARS.iter().chain(&COMPILER_VARS).chain(&[
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "RUSTC_BOOTSTRAP",
            "CARGO_INCREMENTAL",
            "CARGO_PROFILE_RELEASE_OPT_LEVEL",
            "CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS",
            "CARGO_PROFILE_RELEASE_PANIC",
            "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS",
            "CARGO_UNSTABLE_BUILD_STD",
            "CC_x86_64_unknown_linux_gnu",
            "CC_wasm32-unknown-unknown",
            "PROTOC",
        ]) {
            assert!(watched.iter().any(|w| w == name), "{name}: {watched:?}");
        }
        assert!(!watched.iter().any(|w| w == "CARGO_PKG_NAME"));
        let mut unique = watched.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), watched.len(), "each name once: {watched:?}");
    }

    /// The compiler must be the `rustc` of the pinned rustup toolchain, by its canonical path:
    /// a `RUSTC` or `CARGO_BUILD_RUSTC` elsewhere (a wrapper that prints the real `-vV`, say)
    /// makes the build unclean. A symlink to the toolchain's own rustc is that rustc. The
    /// toolchain directory must be exactly `<channel>-<host>`: another directory that starts
    /// with the channel (`1.99.0-x`, or the toolchain of another host) is not the pin.
    #[test]
    fn the_compiler_must_be_the_rustc_of_the_pinned_toolchain() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("rustup");
        let file = |p: &Path| {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "").unwrap();
            p.to_path_buf()
        };
        let host = "aarch64-apple-darwin";
        let good = file(&home.join("toolchains/1.99.0-aarch64-apple-darwin/bin/rustc"));
        let old = file(&home.join("toolchains/1.98.0-aarch64-apple-darwin/bin/rustc"));
        let suffixed = file(&home.join("toolchains/1.99.0-aarch64-apple-darwin-x/bin/rustc"));
        let custom = file(&home.join("toolchains/1.99.0-mine/bin/rustc"));
        let other_host = file(&home.join("toolchains/1.99.0-x86_64-apple-darwin/bin/rustc"));
        let other = file(&root.join("wrapper/rustc"));
        let pin = "[toolchain]\nchannel = \"1.99.0\"\n";
        let path = |dirs: &[&Path]| std::env::join_paths(dirs).unwrap();
        assert_eq!(
            rustc_location(good.as_os_str(), None, &home, host, pin),
            None
        );
        let links = root.join("links");
        std::fs::create_dir_all(&links).unwrap();
        std::os::unix::fs::symlink(&good, links.join("rustc")).unwrap();
        assert_eq!(
            rustc_location(links.join("rustc").as_os_str(), None, &home, host, pin),
            None,
            "a symlink to the toolchain's rustc"
        );
        let bare = path(&[&root.join("empty"), &links]);
        assert_eq!(
            rustc_location("rustc".as_ref(), Some(&bare), &home, host, pin),
            None,
            "a bare name is found on PATH"
        );
        for bad in [&old, &suffixed, &custom, &other_host, &other] {
            let why = rustc_location(bad.as_os_str(), None, &home, host, pin).unwrap();
            assert!(
                why.starts_with(COMPILER_REASON)
                    && why.contains(
                        "is not the rustc of the rustup toolchain 1.99.0-aarch64-apple-darwin"
                    ),
                "{why}"
            );
        }
        let wrappers = path(&[other.parent().unwrap()]);
        assert!(rustc_location("rustc".as_ref(), Some(&wrappers), &home, host, pin).is_some());
        let none = root.join("none/rustc");
        let why = rustc_location(none.as_os_str(), None, &home, host, pin).unwrap();
        assert!(why.starts_with("compiler: cannot find"), "{why}");
        let why = rustc_location(good.as_os_str(), None, &home, host, "[toolchain]\n").unwrap();
        assert_eq!(why, "compiler: rust-toolchain.toml pins no channel");
        let why = rustc_location(good.as_os_str(), None, &home, "", pin).unwrap();
        assert_eq!(why, "compiler: the host triple (HOST) is not set");
    }

    /// The official commit of the pinned release is in [`PINNED_RUSTC`], for the release that
    /// rust-toolchain.toml pins: a bump of one without the other fails here.
    #[test]
    fn the_pinned_rustc_commit_is_for_the_toolchain_pin() {
        let toolchain = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rust-toolchain.toml");
        let channel = pinned_channel(&std::fs::read_to_string(toolchain).unwrap());
        assert_eq!(channel.as_deref(), Some(PINNED_RUSTC.0));
        assert_eq!(PINNED_RUSTC.1.len(), 40);
    }

    /// `rustc -vV` of a compiler of `release`.
    fn rustc_vv(release: &str) -> Result<String, String> {
        Ok(format!(
            "rustc {release} (b940084d7 2026-09-28)\nbinary: rustc\n\
             commit-hash: {RUSTC_HASH}\ncommit-date: 2026-09-28\n\
             host: aarch64-apple-darwin\nrelease: {release}\nLLVM version: 23.1.1\n"
        ))
    }

    /// The compiler is recorded by its commit hash, and the build is unclean unless its release
    /// is the channel that rust-toolchain.toml pins: `RUSTC`, `RUSTUP_TOOLCHAIN`, a rustup
    /// override or `cargo +<toolchain>` can replace the pin.
    #[test]
    fn the_compiler_must_be_the_pinned_release() {
        // build.rs reruns when either variable that selects the compiler changes.
        assert_eq!(
            COMPILER_VARS,
            [
                "RUSTC",
                "CARGO_BUILD_RUSTC",
                "RUSTUP_TOOLCHAIN",
                "RUSTUP_HOME"
            ]
        );
        let pin =
            || Ok("[toolchain]\nchannel = \"1.99.0\"\ncomponents = [\"rustfmt\"]\n".to_owned());
        assert_eq!(pinned_channel(&pin().unwrap()).as_deref(), Some("1.99.0"));
        assert_eq!(
            pinned_channel("[toolchain]\nchannel = '1.99.0'\n").as_deref(),
            Some("1.99.0")
        );
        assert_eq!(pinned_channel("[other]\nchannel = \"1.99.0\"\n"), None);
        assert_eq!(pinned_channel("[toolchain]\nprofile = \"minimal\"\n"), None);

        assert_eq!(
            compiler_state(rustc_vv("1.99.0"), pin()),
            (RUSTC_HASH.to_owned(), None)
        );
        for release in ["1.98.0", "1.99.0-nightly", "1.99.1"] {
            assert_eq!(
                compiler_state(rustc_vv(release), pin()),
                (
                    RUSTC_HASH.to_owned(),
                    Some(format!(
                        "compiler: rustc {release} is not the release 1.99.0 that \
                         rust-toolchain.toml pins"
                    ))
                ),
            );
        }
        assert_eq!(
            compiler_state(Err("cannot run rustc -vV: not found".into()), pin()),
            (
                String::new(),
                Some("compiler: cannot run rustc -vV: not found".to_owned())
            )
        );
        assert_eq!(
            compiler_state(Ok("rustc 1.99.0\n".into()), pin()),
            (
                String::new(),
                Some("compiler: rustc -vV gave no commit-hash or no release".to_owned())
            )
        );
        assert_eq!(
            compiler_state(
                rustc_vv("1.99.0"),
                Err("rust-toolchain.toml: missing".into())
            ),
            (
                RUSTC_HASH.to_owned(),
                Some("compiler: rust-toolchain.toml: missing".to_owned())
            )
        );
        // A compiler that says 1.99.0 with another commit is not the official 1.99.0, and a pin
        // with no official commit in PINNED_RUSTC is refused.
        let forged = Ok(rustc_vv("1.99.0")
            .unwrap()
            .replace(RUSTC_HASH, &"0".repeat(40)));
        assert_eq!(
            compiler_state(forged, pin()),
            (
                "0".repeat(40),
                Some(format!(
                    "compiler: rustc 1.99.0 has commit {}, not the official {RUSTC_HASH}",
                    "0".repeat(40)
                ))
            )
        );
        let bumped = || Ok("[toolchain]\nchannel = \"1.100.0\"\n".to_owned());
        assert_eq!(
            compiler_state(rustc_vv("1.100.0"), bumped()).1.as_deref(),
            Some("compiler: no official commit of rustc 1.100.0 is pinned (PINNED_RUSTC)")
        );
        assert_eq!(
            compiler_state(rustc_vv("1.99.0"), Ok("[toolchain]\n".into())),
            (
                RUSTC_HASH.to_owned(),
                Some("compiler: rust-toolchain.toml pins no channel".to_owned())
            )
        );
    }

    /// The tree check of [`build_state`] on a checkout with the real harness: an untracked
    /// `.cargo` config and an ignored file in a build crate make it unclean, and a file in a
    /// crate that the binaries do not compile does not.
    #[test]
    fn the_build_tree_check_sees_cargo_config_and_ignored_files() {
        let env = real_env();
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().canonicalize().unwrap();
        init_repo(&repo);
        let harness = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/m2a-common.sh");
        std::fs::create_dir_all(repo.join("fuzz")).unwrap();
        std::fs::copy(harness, repo.join(COMMON)).unwrap();
        for (path, text) in [
            ("Cargo.toml", "[workspace]\n"),
            ("Cargo.lock", "version = 4\n"),
            (".gitignore", "*.profraw\n"),
            ("crates/cl-p2p/src.rs", "\n"),
            ("crates/cl-chain/src.rs", "\n"),
            ("proto/a.proto", "\n"),
        ] {
            std::fs::create_dir_all(repo.join(path).parent().unwrap()).unwrap();
            std::fs::write(repo.join(path), text).unwrap();
        }
        commit_all(&repo, "tree");
        let head = git(&repo, &["rev-parse", "HEAD"], &env).unwrap();
        assert_eq!(
            build_state(&repo, &env),
            (head.trim().to_owned(), String::new())
        );

        std::fs::write(repo.join("crates/cl-chain/new.rs"), "\n").unwrap();
        assert_eq!(
            build_state(&repo, &env).1,
            "",
            "not a crate of the binaries"
        );

        std::fs::write(repo.join("crates/cl-p2p/default.profraw"), "x").unwrap();
        let unclean = build_state(&repo, &env).1;
        assert!(
            unclean.starts_with("uncommitted changes in the build tree: ")
                && unclean.contains("crates/cl-p2p/default.profraw"),
            "an ignored file is dirty: {unclean}"
        );
        std::fs::remove_file(repo.join("crates/cl-p2p/default.profraw")).unwrap();

        std::fs::create_dir_all(repo.join(".cargo")).unwrap();
        std::fs::write(repo.join(".cargo/config.toml"), "[build]\n").unwrap();
        let unclean = build_state(&repo, &env).1;
        assert!(unclean.contains(".cargo"), "{unclean}");
    }

    /// What `build.rs` embedded for this build is the state of the tree now: the commit is
    /// git's HEAD, and the reason for an unclean tree is the one [`build_state`] gives. A
    /// rustflags reason can follow it ([`unclean_reason`]).
    #[test]
    fn the_embedded_build_state_is_the_trees() {
        let commit = include_str!(concat!(env!("OUT_DIR"), "/m2a-build-commit.txt"));
        let unclean = include_str!(concat!(env!("OUT_DIR"), "/m2a-build-unclean.txt"));
        let env = real_env();
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let (now_commit, now_tree) = match locate_repo(manifest, &env) {
            Ok(repo) => build_state(&repo, &env),
            Err(why) => (String::new(), why),
        };
        assert_eq!(commit, now_commit);
        let (others, tree): (Vec<&str>, Vec<&str>) = unclean
            .split("; ")
            .filter(|part| !part.is_empty())
            .partition(|part| part.starts_with(FLAGS_REASON) || part.starts_with(COMPILER_REASON));
        assert_eq!(
            tree.join("; "),
            now_tree.replace(['\n', '\r'], " "),
            "{unclean}"
        );
        // With no compiler reason, the embedded compiler is the pinned one that cargo runs
        // here (the same RUSTC, the same rust-toolchain.toml).
        let rustc = include_str!(concat!(env!("OUT_DIR"), "/m2a-build-rustc.txt"));
        if !others.iter().any(|part| part.starts_with(COMPILER_REASON)) {
            let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
            let now = compiler_state(
                rustc_version(&compiler, manifest),
                std::fs::read_to_string(manifest.join("../../rust-toolchain.toml"))
                    .map_err(|e| e.to_string()),
            );
            assert_eq!((rustc.to_owned(), None), now, "{unclean}");
        }
    }
}
