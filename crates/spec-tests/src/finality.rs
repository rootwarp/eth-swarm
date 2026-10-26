//! consensus-spec-tests `tests/<preset>/gloas/finality/finality/pyspec_tests/<case>/`, run
//! through `state_transition::state_transition`.
//!
//! A case has the format of a `sanity/blocks` case: `pre.ssz_snappy`, `meta.yaml` with
//! `blocks_count`, the blocks `blocks_<i>.ssz_snappy`, `post.ssz_snappy` and
//! `manifest.yaml`. [`crate::sanity::run_blocks`] applies the blocks and compares the
//! post-state. The finality cases do not compare the batch verdict of the signature sets
//! with the per-set verdict: the `sanity/blocks` cases do that.

use crate::coverage::Reads;
use crate::plan::Case;
use crate::sanity::{run_blocks, BatchCheck};

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas" && handler == "finality" && matches!(preset, "minimal" | "mainnet")
}

/// Runs one `finality` case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    run_blocks(reads, case, BatchCheck::Skip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanity::tests::{blocks_case, blocks_files, state};

    #[test]
    fn handler_selection() {
        assert!(supported("gloas", "minimal", "finality"));
        assert!(supported("gloas", "mainnet", "finality"));
        assert!(!supported("fulu", "minimal", "finality"));
        assert!(!supported("gloas", "general", "finality"));
        assert!(!supported("gloas", "minimal", "blocks"));
    }

    #[test]
    fn a_case_of_blocks_runs() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        let case = |post| {
            let files = blocks_files(&pre, "{blocks_count: 0}", &[], Some(post));
            let files: Vec<(&str, Vec<u8>)> =
                files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
            blocks_case(dir.path(), "finality", "finality", &files)
        };
        let reads = Reads::default();
        let c = case(&pre);
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        let err = run(&Reads::default(), &case(&state(3))).unwrap_err();
        assert!(err.contains("root mismatch"), "{err}");
    }
}
