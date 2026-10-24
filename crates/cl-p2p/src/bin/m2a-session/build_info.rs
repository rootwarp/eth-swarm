//! The commit the binary was built from, and whether its build tree was clean.
//!
//! `build.rs` records both when it builds the crate, because a deployed binary has no checkout
//! to look at. The commit is git's `HEAD`. The tree is clean only if no build path
//! (`BUILD_PATHS` in `build.rs`: the workspace manifests, `crates`, `proto` and the toolchain
//! pin) has an uncommitted change, an untracked file, or git's assume-unchanged or
//! skip-worktree flag. `build.rs` reads that with `m2a_dirty_paths` of `fuzz/m2a-common.sh`,
//! the same check that voids the gate expectations for a dirty keyed path.
//!
//! The `m2a-summary` line writes them as `build_commit` and `build_dirty`, and its
//! `clean_build` check fails a build that was not clean. A gate file can name an ancestor of
//! the build commit, and the decoder key does not hold `src/bin`. So only `build_commit` ties
//! a posted summary to the commit of the binary that ran.

/// What `build.rs` recorded about the build tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    /// The full `HEAD` commit id of the build tree, if git gave a valid one.
    pub commit: Option<String>,
    /// Why the build tree was not clean, or `None` if it was.
    pub unclean: Option<String>,
}

impl BuildInfo {
    /// What `build.rs` embedded for this binary.
    pub fn built() -> Self {
        Self::from_build(
            include_str!(concat!(env!("OUT_DIR"), "/m2a-build-commit.txt")),
            include_str!(concat!(env!("OUT_DIR"), "/m2a-build-unclean.txt")),
        )
    }

    /// The build from the embedded `commit` (a full commit id, or empty) and `unclean` (empty
    /// for a clean tree, else the reason). A commit that is not a full lower-case hex id
    /// (SHA-1 or SHA-256) counts as no commit, and a build with no commit is never clean.
    pub fn from_build(commit: &str, unclean: &str) -> Self {
        let commit = commit.trim();
        let unclean = unclean.trim();
        let valid = matches!(commit.len(), 40 | 64)
            && commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let unclean = match (valid, unclean.is_empty()) {
            (_, false) => Some(unclean.to_owned()),
            (false, true) => Some("no valid build commit was embedded".to_owned()),
            (true, true) => None,
        };
        Self {
            commit: valid.then(|| commit.to_owned()),
            unclean,
        }
    }

    /// Whether the binary was built from a known commit with a clean build tree.
    pub fn is_clean(&self) -> bool {
        self.commit.is_some() && self.unclean.is_none()
    }

    /// A clean build of a fixed commit, for the tests.
    #[cfg(test)]
    pub fn fixture() -> Self {
        Self::from_build(FIXTURE_COMMIT, "")
    }
}

/// The commit of [`BuildInfo::fixture`].
#[cfg(test)]
pub const FIXTURE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_commit_with_no_reason_is_clean() {
        let build = BuildInfo::from_build(&format!("{FIXTURE_COMMIT}\n"), "\n");
        assert_eq!(build.commit.as_deref(), Some(FIXTURE_COMMIT));
        assert!(build.is_clean(), "{build:?}");
        let sha256 = "ab".repeat(32);
        assert!(BuildInfo::from_build(&sha256, "").is_clean());
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

    /// The embedded values parse: a test build from a dirty tree still embeds a reason, and a
    /// clean one a commit.
    #[test]
    fn the_embedded_build_parses() {
        let build = BuildInfo::built();
        assert!(
            build.commit.is_some() || build.unclean.is_some(),
            "{build:?}"
        );
    }
}
