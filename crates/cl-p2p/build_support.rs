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

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        // With the parent's HOME (or GIT_CONFIG_GLOBAL) pointing at that config, the change hides.
        let mut parent: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(k, _)| k != "GIT_CONFIG_GLOBAL")
            .collect();
        parent.push(("HOME".into(), home.path().into()));
        let mut with_home = parent.clone();
        with_home.retain(|(k, _)| k == "PATH" || k == "HOME");
        assert_eq!(status(&with_home), "", "the filter hides the change");
        let mut with_global = os(&[]);
        with_global.extend(parent.iter().filter(|(k, _)| k == "PATH").cloned());
        with_global.push((
            "GIT_CONFIG_GLOBAL".into(),
            home.path().join(".gitconfig").into(),
        ));
        assert_eq!(status(&with_global), "");
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
}
