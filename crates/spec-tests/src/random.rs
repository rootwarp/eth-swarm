//! consensus-spec-tests `tests/<preset>/gloas/random/random/pyspec_tests/<case>/`, run
//! through `state_transition::state_transition`.
//!
//! A case has the format of a `sanity/blocks` case: `pre.ssz_snappy`, `meta.yaml` with
//! `blocks_count` and `bls_setting`, the blocks `blocks_<i>.ssz_snappy`, `post.ssz_snappy`,
//! `config.yaml` and `manifest.yaml`. [`crate::sanity::run_blocks`] applies the blocks,
//! checks the config, and compares the post-state. The blocks of a random case hold many
//! operations of each kind, so the runner also compares the batch verdict of the signature
//! sets of each block with the per-set verdict ([`BatchCheck::Compare`]).

use crate::coverage::Reads;
use crate::plan::Case;
use crate::sanity::{run_blocks, BatchCheck};

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas" && handler == "random" && matches!(preset, "minimal" | "mainnet")
}

/// Runs one `random` case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    run_blocks(reads, case, BatchCheck::Compare)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::config_yaml;
    use crate::sanity::tests::{blocks_case, blocks_files, state};
    use consensus_types::Minimal;

    #[test]
    fn handler_selection() {
        assert!(supported("gloas", "minimal", "random"));
        assert!(supported("gloas", "mainnet", "random"));
        assert!(!supported("fulu", "minimal", "random"));
        assert!(!supported("gloas", "general", "random"));
        assert!(!supported("gloas", "minimal", "blocks"));
    }

    #[test]
    fn a_case_of_blocks_with_a_config_runs() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        let case = |post, config: String| {
            let mut files =
                blocks_files(&pre, "{blocks_count: 0, bls_setting: 1}", &[], Some(post));
            files.push(("config.yaml".to_owned(), config.into_bytes()));
            let files: Vec<(&str, Vec<u8>)> =
                files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
            blocks_case(dir.path(), "random", "random", &files)
        };
        let config = |replace| config_yaml::<Minimal>("minimal", replace);
        let reads = Reads::default();
        let c = case(&pre, config(&[]));
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        let other_post = state(3);
        let err = run(&Reads::default(), &case(&other_post, config(&[]))).unwrap_err();
        assert!(err.contains("root mismatch"), "{err}");
        let other = config(&[("GLOAS_FORK_EPOCH", Some("1"))]);
        let err = run(&Reads::default(), &case(&pre, other)).unwrap_err();
        assert!(err.contains("GLOAS_FORK_EPOCH"), "{err}");
    }
}
