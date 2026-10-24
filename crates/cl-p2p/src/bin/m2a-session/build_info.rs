//! The commit the binary was built from, and whether its build was clean.
//!
//! `build.rs` records both when it builds the crate, because a deployed binary has no checkout
//! to look at. The commit is git's `HEAD`. The build is clean only if four conditions are true:
//!
//! - No build path (`BUILD_PATHS` in `build_support.rs`: the workspace manifests, the toolchain
//!   pin, `.cargo`, `proto` and the crates that the binaries compile) has an uncommitted change,
//!   an untracked or ignored file, or git's assume-unchanged or skip-worktree flag. `build.rs`
//!   reads the tree with `m2a_dirty_paths` of `fuzz/m2a-common.sh`, the same check that voids
//!   the gate expectations for a dirty keyed path.
//! - No rustflags variable, rustc wrapper, linker or `RUSTC_BOOTSTRAP` was set
//!   (`BUILD_FLAG_VARS`).
//! - No cargo profile or unstable variable (`CARGO_PROFILE_*`, `CARGO_UNSTABLE_*`) and no C or
//!   proto build variable was set, and `CARGO_INCREMENTAL` was not `1`.
//! - The compiler's release is the `channel` that `rust-toolchain.toml` pins, with its
//!   official commit, and the compiler is the `rustc` of the rustup toolchain
//!   `<channel>-<host>`. The compiler's commit hash (`rustc -vV`) is recorded too.
//!
//! A test of the library (`build_support::tests::the_embedded_build_state_is_the_trees`) holds
//! the embedded values to the state of the tree.
//!
//! The Status probe refuses to dial with a build that was not clean. The `m2a-summary` line
//! writes the values as `build_commit`, `build_rustc_commit` and `build_dirty`, and its
//! `clean_build` check fails a build that was not clean. A gate file can name an ancestor of the
//! build commit with the same decoder key. The key holds this crate whole, `src/bin` included,
//! but not every build path: `rust-toolchain.toml`, `.cargo` and the files of `proto` outside
//! `proto/ethswarm` can differ at that ancestor. So only `build_commit` ties a posted summary to
//! the commit of the binary that ran.

/// What `build.rs` recorded about the build tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    /// The full `HEAD` commit id of the build tree, if git gave a valid one.
    pub commit: Option<String>,
    /// Why the build was not clean, or `None` if it was.
    pub unclean: Option<String>,
    /// The commit hash of the compiler (`rustc -vV`), if `build.rs` gave a valid one.
    pub rustc_commit: Option<String>,
}

/// Whether `id` is a full lower-case hex id of `lens` characters.
fn full_hex(id: &str, lens: &[usize]) -> bool {
    lens.contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl BuildInfo {
    /// What `build.rs` embedded for this binary.
    pub fn built() -> Self {
        Self::from_build(
            include_str!(concat!(env!("OUT_DIR"), "/m2a-build-commit.txt")),
            include_str!(concat!(env!("OUT_DIR"), "/m2a-build-unclean.txt")),
        )
        .with_rustc(include_str!(concat!(
            env!("OUT_DIR"),
            "/m2a-build-rustc.txt"
        )))
    }

    /// The build from the embedded `commit` (a full commit id, or empty) and `unclean` (empty
    /// for a clean tree, else the reason). A commit that is not a full lower-case hex id
    /// (SHA-1 or SHA-256) counts as no commit, and a build with no commit is never clean.
    pub fn from_build(commit: &str, unclean: &str) -> Self {
        let commit = commit.trim();
        let unclean = unclean.trim();
        let valid = full_hex(commit, &[40, 64]);
        let unclean = match (valid, unclean.is_empty()) {
            (_, false) => Some(unclean.to_owned()),
            (false, true) => Some("no valid build commit was embedded".to_owned()),
            (true, true) => None,
        };
        Self {
            commit: valid.then(|| commit.to_owned()),
            unclean,
            rustc_commit: None,
        }
    }

    /// The build with the embedded compiler commit `rustc` (a full 40-character hex hash, or
    /// empty). Without a valid one the build is not clean.
    pub fn with_rustc(mut self, rustc: &str) -> Self {
        let rustc = rustc.trim();
        if full_hex(rustc, &[40]) {
            self.rustc_commit = Some(rustc.to_owned());
        } else {
            self.rustc_commit = None;
            self.unclean
                .get_or_insert_with(|| "no valid compiler commit was embedded".to_owned());
        }
        self
    }

    /// Whether the binary was built from a known commit and a known compiler, with a clean
    /// build.
    pub fn is_clean(&self) -> bool {
        self.commit.is_some() && self.rustc_commit.is_some() && self.unclean.is_none()
    }

    /// A clean build of a fixed commit, for the tests.
    #[cfg(test)]
    pub fn fixture() -> Self {
        Self::from_build(FIXTURE_COMMIT, "").with_rustc(FIXTURE_RUSTC)
    }
}

/// The commit of [`BuildInfo::fixture`].
#[cfg(test)]
pub const FIXTURE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// The compiler commit of [`BuildInfo::fixture`].
#[cfg(test)]
pub const FIXTURE_RUSTC: &str = "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_commit_with_no_reason_is_clean() {
        let build =
            BuildInfo::from_build(&format!("{FIXTURE_COMMIT}\n"), "\n").with_rustc(FIXTURE_RUSTC);
        assert_eq!(build.commit.as_deref(), Some(FIXTURE_COMMIT));
        assert!(build.is_clean(), "{build:?}");
        let sha256 = "ab".repeat(32);
        assert!(BuildInfo::from_build(&sha256, "")
            .with_rustc(FIXTURE_RUSTC)
            .is_clean());
        // No compiler commit: never clean.
        let no_rustc = BuildInfo::from_build(FIXTURE_COMMIT, "");
        assert_eq!(no_rustc.rustc_commit, None);
        assert!(!no_rustc.is_clean(), "{no_rustc:?}");
    }

    #[test]
    fn a_reason_makes_the_build_unclean() {
        let build = BuildInfo::from_build(FIXTURE_COMMIT, "content differs from HEAD: crates/x");
        assert_eq!(build.commit.as_deref(), Some(FIXTURE_COMMIT));
        assert!(!build.is_clean());
        assert_eq!(
            build.unclean.as_deref(),
            Some("content differs from HEAD: crates/x")
        );
    }

    /// The compiler is recorded by its commit hash. A build without a valid one is not clean,
    /// and a reason that is given stays.
    #[test]
    fn the_compiler_commit_is_recorded() {
        let build = BuildInfo::fixture();
        assert_eq!(build.rustc_commit.as_deref(), Some(FIXTURE_RUSTC));
        assert!(build.is_clean(), "{build:?}");
        for bad in ["", "unknown", "b940084d7", &FIXTURE_RUSTC.to_uppercase()] {
            let build = BuildInfo::from_build(FIXTURE_COMMIT, "").with_rustc(bad);
            assert_eq!(build.rustc_commit, None, "{bad:?}");
            assert!(!build.is_clean(), "{bad:?}");
            assert_eq!(
                build.unclean.as_deref(),
                Some("no valid compiler commit was embedded")
            );
        }
        let why =
            BuildInfo::from_build(FIXTURE_COMMIT, "compiler: cannot run rustc").with_rustc("");
        assert_eq!(why.unclean.as_deref(), Some("compiler: cannot run rustc"));
    }

    #[test]
    fn no_valid_commit_is_never_clean() {
        for commit in [
            "",
            "0123456",
            &FIXTURE_COMMIT.to_uppercase(),
            &format!("{}g", &FIXTURE_COMMIT[..39]),
        ] {
            let build = BuildInfo::from_build(commit, "");
            assert_eq!(build.commit, None, "{commit:?}");
            assert!(!build.is_clean(), "{commit:?}");
            assert_eq!(
                build.unclean.as_deref(),
                Some("no valid build commit was embedded")
            );
        }
        let why = BuildInfo::from_build("", "no git checkout: not a repository");
        assert_eq!(
            why.unclean.as_deref(),
            Some("no git checkout: not a repository")
        );
    }
}
