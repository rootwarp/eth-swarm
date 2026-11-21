//! consensus-spec-tests `tests/<preset>/{fulu,gloas}/networking/<handler>/pyspec_tests/<case>/`.
//!
//! The custody handlers ([`RUNNABLE`]) run through `consensus_types::das`; each case is one
//! `meta.yaml` holding the inputs and the expected `result`, plus the `manifest.yaml` every
//! case carries. The Gloas gossip handlers of [`gossip::RUNNABLE`] run through [`gossip`]. The
//! other `gossip_*` handlers have no runner and are skipped in `skip.toml`.

use crate::coverage::Reads;
use crate::fixture::{self, field};
use crate::gossip;
use crate::plan::Case;
use consensus_types::das;
use consensus_types::primitives::U256;
use std::path::Path;
use yaml_rust2::Yaml;

/// The custody handlers that this runner executes.
pub const RUNNABLE: [&str; 2] = ["compute_columns_for_custody_group", "get_custody_groups"];

/// Forks whose networking custody cases this runner takes (Fulu and Gloas only).
const FORKS: [&str; 2] = ["fulu", "gloas"];

/// Whether this runner runs `handler` of `fork`. A Gloas handler is a custody handler or a
/// gossip handler of [`gossip::RUNNABLE`] or [`gossip::NOT_RUN`], and `Err` for any other: the
/// suite fails setup on it, so a new handler gets a decision.
pub fn handler_runs(fork: &str, handler: &str) -> Result<bool, String> {
    if FORKS.contains(&fork) && RUNNABLE.contains(&handler) {
        Ok(true)
    } else if fork == "gloas" {
        gossip::handler_runs(handler)
    } else {
        Ok(false)
    }
}

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    (FORKS.contains(&fork) && RUNNABLE.contains(&handler))
        || gossip::supported(fork, preset, handler)
}

/// Runs one case: a gossip case through [`gossip::run`], else a custody case from its
/// `meta.yaml`. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    let handler = case.key.handler.as_str();
    if gossip::RUNNABLE.contains(&handler) {
        return gossip::run(reads, case);
    }
    let meta = case.file("meta.yaml").ok_or("case has no meta.yaml")?;
    custody(reads, handler, meta)
}

/// Runs one custody case of `handler` from its `meta.yaml`.
fn custody(reads: &Reads, handler: &str, meta: &Path) -> Result<(), String> {
    let doc = fixture::load(reads, meta)?;
    let want = fixture::u64_list(field(&doc, "result")?)?;
    let got = match handler {
        "get_custody_groups" => das::get_custody_groups(
            node_id(field(&doc, "node_id")?)?,
            uint(field(&doc, "custody_group_count")?)?,
        ),
        "compute_columns_for_custody_group" => {
            das::compute_columns_for_custody_group(uint(field(&doc, "custody_group")?)?)
        }
        other => return Err(format!("networking handler `{other}` has no runner")),
    }
    .map_err(|e| format!("rejected an input the vector expects to succeed: {e}"))?;
    fixture::compare(Some(got), Some(want))
}

/// A `uint64` scalar.
fn uint(y: &Yaml) -> Result<u64, String> {
    y.as_i64()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| format!("expected an unsigned integer, got {y:?}"))
}

/// A `NodeID` (`uint256`) in decimal. The YAML parser keeps a number past `i64` as its source
/// text (`Real`), so the digits are parsed here, never through a float.
fn node_id(y: &Yaml) -> Result<U256, String> {
    let digits = match y {
        Yaml::Integer(i) => {
            return u64::try_from(*i)
                .map(U256::from)
                .map_err(|_| format!("node id {i} is negative"))
        }
        Yaml::Real(s) | Yaml::String(s) => s,
        other => return Err(format!("expected a node id, got {other:?}")),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("node id {digits:?} is not a decimal integer"));
    }
    U256::from_str_radix(digits, 10).map_err(|e| format!("node id {digits:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write(dir: &Path, text: &str) -> PathBuf {
        let p = dir.join("meta.yaml");
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn handler_selection() {
        assert!(supported("fulu", "minimal", "get_custody_groups"));
        assert!(supported(
            "gloas",
            "mainnet",
            "compute_columns_for_custody_group"
        ));
        assert!(!supported("heze", "minimal", "get_custody_groups"));
        assert!(!supported("fulu", "minimal", "gossip_beacon_block"));
        assert!(!supported("gloas", "minimal", "gossip_beacon_block"));
        for handler in gossip::RUNNABLE {
            assert!(supported("gloas", "minimal", handler), "{handler}");
            assert!(!supported("fulu", "minimal", handler), "{handler}");
            assert_eq!(handler_runs("gloas", handler), Ok(true), "{handler}");
            assert_eq!(handler_runs("fulu", handler), Ok(false), "{handler}");
        }
        for handler in gossip::NOT_RUN {
            assert_eq!(handler_runs("gloas", handler), Ok(false), "{handler}");
        }
        assert_eq!(handler_runs("fulu", "get_custody_groups"), Ok(true));
        assert_eq!(handler_runs("gloas", "get_custody_groups"), Ok(true));
        // Only a Gloas handler must be known.
        assert_eq!(handler_runs("fulu", "gossip_new_topic"), Ok(false));
        let err = handler_runs("gloas", "gossip_new_topic").unwrap_err();
        assert!(err.contains("gossip_new_topic"), "{err}");
    }

    /// A custody case dispatches on its handler, and a gossip case goes to the gossip runner.
    #[test]
    fn a_case_runs_through_the_runner_of_its_handler() {
        let dir = tempfile::tempdir().unwrap();
        let meta = write(dir.path(), "custody_group: 55\nresult: [55]\n");
        let case = |handler: &str| Case {
            key: crate::plan::CaseKey {
                source: "consensus-specs".into(),
                fork: "gloas".into(),
                preset: "minimal".into(),
                runner: "networking".into(),
                handler: handler.into(),
                case: "pyspec_tests/case_0".into(),
            },
            files: vec![crate::plan::CaseFile {
                path: meta.clone(),
                name: "meta.yaml".into(),
            }],
        };
        let reads = Reads::default();
        assert_eq!(
            run(&reads, &case("compute_columns_for_custody_group")),
            Ok(())
        );
        // The gossip runner fails closed on the keys of a custody `meta.yaml`.
        let err = run(&reads, &case("gossip_execution_payload_envelope")).unwrap_err();
        assert!(err.contains("unsupported key `custody_group`"), "{err}");
        let no_meta = Case {
            files: Vec::new(),
            ..case("get_custody_groups")
        };
        assert!(run(&reads, &no_meta).unwrap_err().contains("meta.yaml"));
    }

    /// `get_custody_groups_max_node_id_custody_group_count_is_4`, as the vector writes it.
    #[test]
    fn a_large_node_id_case_passes_and_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "node_id: \n  115792089237316195423570985008687907853269984665640564039457584007913129639935\n\
             custody_group_count: 4\nresult: [1, 47, 87, 102]\n",
        );
        let reads = Reads::default();
        assert_eq!(custody(&reads, "get_custody_groups", &p), Ok(()));
        assert!(reads.contains(&p));
        let p = write(
            dir.path(),
            "node_id: 0\ncustody_group_count: 0\nresult: []\n",
        );
        assert_eq!(custody(&Reads::default(), "get_custody_groups", &p), Ok(()));
    }

    #[test]
    fn a_wrong_result_fails() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "custody_group: 55\nresult: [54]\n");
        let err = custody(&Reads::default(), "compute_columns_for_custody_group", &p).unwrap_err();
        assert!(err.contains("differs"), "{err}");
        let p = write(dir.path(), "custody_group: 55\nresult: [55]\n");
        assert_eq!(
            custody(&Reads::default(), "compute_columns_for_custody_group", &p),
            Ok(())
        );
    }

    #[test]
    fn out_of_range_inputs_and_malformed_fixtures_fail() {
        let dir = tempfile::tempdir().unwrap();
        let reads = Reads::default();
        for (handler, text, needle) in [
            (
                "compute_columns_for_custody_group",
                "custody_group: 128\nresult: []\n",
                "expects to succeed",
            ),
            (
                "get_custody_groups",
                "node_id: 1\ncustody_group_count: 129\nresult: []\n",
                "expects to succeed",
            ),
            (
                "get_custody_groups",
                "node_id: '12a'\ncustody_group_count: 1\nresult: []\n",
                "not a decimal",
            ),
            (
                "get_custody_groups",
                "node_id: -1\ncustody_group_count: 1\nresult: []\n",
                "negative",
            ),
            (
                "get_custody_groups",
                "node_id: [1]\ncustody_group_count: 1\nresult: []\n",
                "expected a node id",
            ),
            (
                "get_custody_groups",
                &format!(
                    "node_id: 1{}\ncustody_group_count: 1\nresult: []\n",
                    "0".repeat(80)
                ),
                "node id",
            ),
            (
                "get_custody_groups",
                "node_id: 1\ncustody_group_count: x\nresult: []\n",
                "unsigned integer",
            ),
            ("get_custody_groups", "node_id: 1\nresult: []\n", "missing"),
            ("gossip_beacon_block", "result: []\n", "no runner"),
        ] {
            let err = custody(&reads, handler, &write(dir.path(), text)).unwrap_err();
            assert!(err.contains(needle), "{text}: {err}");
        }
    }
}
