//! consensus-spec-tests `tests/<preset>/gloas/epoch_processing/<handler>/pyspec_tests/<case>/`,
//! run through `state_transition::per_epoch`.
//!
//! Each case holds `pre.ssz_snappy`, `post.ssz_snappy` and `manifest.yaml`. The check is the
//! step of the handler on the pre-state, and then `hash_tree_root` against the post-state. On
//! a mismatch, the error names the top-level fields that differ. A case without
//! `post.ssz_snappy` must fail with an error that proves the input invalid
//! (`StfError::proves_invalid`).
//!
//! [`step`] maps each handler directory to its function in one `match`. A known handler that
//! is not ported yet needs a `skip.toml` entry, and an unknown handler directory fails the run
//! ([`check_handler`]). The `pre_epoch.ssz_snappy` and `post_epoch.ssz_snappy` files of the
//! whole-epoch check are not read until `process_epoch` is complete. A `skip.toml` entry
//! excuses them from the coverage guard.

use crate::check::state_field_diff;
use crate::coverage::Reads;
use crate::fixture;
use crate::plan::{Case, CaseKey};
use consensus_types::gloas::BeaconState;
use consensus_types::{Mainnet, Minimal};
use ssz::Decode;
use state_transition::per_epoch::{
    process_inactivity_updates, process_justification_and_finalization,
    process_rewards_and_penalties,
};
use state_transition::{state_root, Preset, StfError};
use std::path::Path;
use tree_hash::TreeHash;

/// One epoch step: the function of a handler.
pub type Step<E> = fn(&mut BeaconState<E>) -> Result<(), StfError>;

/// The function of a Gloas `epoch_processing` handler directory. `Ok(None)` is a known step
/// that is not ported yet (it needs a `skip.toml` entry), and `Err` is a directory this
/// runner does not know.
pub fn step<E: Preset>(handler: &str) -> Result<Option<Step<E>>, String> {
    match handler {
        "justification_and_finalization" => Ok(Some(process_justification_and_finalization::<E>)),
        "inactivity_updates" => Ok(Some(process_inactivity_updates::<E>)),
        "rewards_and_penalties" => Ok(Some(process_rewards_and_penalties::<E>)),
        "builder_pending_payments"
        | "effective_balance_updates"
        | "eth1_data_reset"
        | "historical_summaries_update"
        | "participation_flag_updates"
        | "pending_consolidations"
        | "pending_deposits"
        | "pending_deposits_churn"
        | "proposer_lookahead"
        | "ptc_window"
        | "randao_mixes_reset"
        | "registry_updates"
        | "slashings"
        | "slashings_reset"
        | "sync_committee_updates" => Ok(None),
        other => Err(format!(
            "unknown epoch_processing handler directory `{other}`: classify it in \
             crates/spec-tests/src/epoch_processing.rs"
        )),
    }
}

/// `Ok(true)` for a handler that runs, `Ok(false)` for a known one that needs a skip entry,
/// `Err` for a handler directory this runner does not know.
pub fn handler_runs(handler: &str) -> Result<bool, String> {
    step::<Minimal>(handler).map(|s| s.is_some())
}

/// Fails on a Gloas `epoch_processing` handler directory that [`step`] does not classify.
/// The message holds the path of the directory below the vector set.
pub fn check_handler(k: &CaseKey) -> Result<(), String> {
    if k.fork != "gloas" || k.runner != "epoch_processing" {
        return Ok(());
    }
    handler_runs(&k.handler).map(drop).map_err(|e| {
        format!(
            "{e} (at tests/{}/{}/{}/{} in {})",
            k.preset, k.fork, k.runner, k.handler, k.source
        )
    })
}

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas" && matches!(preset, "minimal" | "mainnet") && handler_runs(handler) == Ok(true)
}

/// Runs one case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    match case.key.preset.as_str() {
        "minimal" => run_step::<Minimal>(reads, case),
        "mainnet" => run_step::<Mainnet>(reads, case),
        other => Err(format!("no epoch_processing runner for preset {other}")),
    }
}

fn run_step<E: Preset>(reads: &Reads, case: &Case) -> Result<(), String> {
    let handler = &case.key.handler;
    let step = step::<E>(handler)?.ok_or_else(|| {
        format!("epoch_processing handler `{handler}` is not run; it needs a skip.toml entry")
    })?;
    let file = |name: &str| case.file(name).ok_or_else(|| format!("case has no {name}"));
    let mut state = decode_state::<E>(reads, file("pre.ssz_snappy")?)?;
    let post = case
        .file("post.ssz_snappy")
        .map(|p| decode_state::<E>(reads, p))
        .transpose()?;
    match (step(&mut state), post) {
        (Ok(()), Some(post)) => {
            let got = state_root(&mut state).map_err(|e| format!("post-state root: {e}"))?;
            let want = post.tree_hash_root();
            if got == want {
                Ok(())
            } else {
                Err(format!(
                    "post-state root mismatch: got {got:x}, want {want:x}; fields that differ: {}",
                    state_field_diff(&state, &post).join(", ")
                ))
            }
        }
        (Err(e), None) if e.proves_invalid() => {
            // Any proof error passes such a case, so print it: a port defect that happens
            // to give a proof error shows in the trial output.
            eprintln!("{}: expected failure: {handler} failed with {e}", case.key);
            Ok(())
        }
        (Err(e), None) => Err(format!(
            "{handler} failed with {e}, which is not a spec failure"
        )),
        (Ok(()), None) => Err(format!(
            "{handler} passed, but the vector expects it to fail"
        )),
        (Err(e), Some(_)) => Err(format!("{handler} failed: {e}")),
    }
}

/// A `BeaconState` from a `.ssz_snappy` file.
fn decode_state<E: Preset>(reads: &Reads, path: &Path) -> Result<BeaconState<E>, String> {
    let bytes = fixture::ssz_snappy(reads, path)?;
    BeaconState::<E>::from_ssz_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{CaseFile, Date};
    use crate::sanity::tests::state;
    use crate::suite::{self, Config, SuiteError};
    use consensus_types::EthSpec;
    use ssz::Encode;

    const HANDLER: &str = "justification_and_finalization";

    /// A minimal state at the last slot of `epoch` with an empty registry. From epoch 2, its
    /// justification step justifies both epochs: every balance has the floor of one increment.
    fn state_at(epoch: u64) -> BeaconState<Minimal> {
        state(Minimal::start_slot_at_epoch(epoch + 1) - 1)
    }

    fn snappy(s: &BeaconState<Minimal>) -> Vec<u8> {
        snap::raw::Encoder::new()
            .compress_vec(&s.as_ssz_bytes())
            .unwrap()
    }

    /// A case of `handler` in `dir` of `preset`; `post` is left out when `None`.
    fn case(
        dir: &Path,
        preset: &str,
        handler: &str,
        pre: &BeaconState<Minimal>,
        post: Option<&BeaconState<Minimal>>,
    ) -> Case {
        let mut files = Vec::new();
        let mut put = |name: &str, bytes: Vec<u8>| {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            files.push(CaseFile {
                path,
                name: name.into(),
            });
        };
        put("pre.ssz_snappy", snappy(pre));
        if let Some(post) = post {
            put("post.ssz_snappy", snappy(post));
        }
        Case {
            key: CaseKey {
                source: "consensus-specs".into(),
                fork: "gloas".into(),
                preset: preset.into(),
                runner: "epoch_processing".into(),
                handler: handler.into(),
                case: "pyspec_tests/case_0".into(),
            },
            files,
        }
    }

    #[test]
    fn handler_selection() {
        for handler in [
            "justification_and_finalization",
            "inactivity_updates",
            "rewards_and_penalties",
        ] {
            assert!(supported("gloas", "minimal", handler));
            assert!(supported("gloas", "mainnet", handler));
            assert!(!supported("fulu", "minimal", handler));
            assert!(!supported("gloas", "general", handler));
        }
        assert_eq!(handler_runs("registry_updates"), Ok(false));
        assert!(!supported("gloas", "minimal", "registry_updates"));
        assert!(handler_runs("process_new_thing").is_err());
        // Other forks and runners are not checked here.
        let key = |fork: &str, runner: &str| CaseKey {
            source: "consensus-specs".into(),
            fork: fork.into(),
            preset: "minimal".into(),
            runner: runner.into(),
            handler: "historical_roots_update".into(),
            case: "pyspec_tests/case_0".into(),
        };
        assert_eq!(check_handler(&key("phase0", "epoch_processing")), Ok(()));
        assert_eq!(check_handler(&key("gloas", "operations")), Ok(()));
        assert!(check_handler(&key("gloas", "epoch_processing")).is_err());
    }

    #[test]
    fn a_matching_post_state_passes_and_the_case_files_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state_at(2);
        let mut post = pre.clone();
        process_justification_and_finalization(&mut post).unwrap();
        assert_ne!(
            post.current_justified_checkpoint,
            pre.current_justified_checkpoint
        );
        let c = case(dir.path(), "minimal", HANDLER, &pre, Some(&post));
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
    }

    #[test]
    fn a_mismatch_names_the_fields_that_differ() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state_at(2);
        // The pre-state is not the post-state of the step.
        let c = case(dir.path(), "minimal", HANDLER, &pre, Some(&pre));
        let err = run(&Reads::default(), &c).unwrap_err();
        assert!(err.contains("root mismatch"), "{err}");
        assert!(
            err.ends_with("fields that differ: justification_bits, current_justified_checkpoint"),
            "{err}"
        );
        let mut other = pre.clone();
        other.slot += 1;
        other.balances.push(7).unwrap();
        other.apply_updates().unwrap();
        assert_eq!(state_field_diff(&pre, &other), ["slot", "balances"]);
        assert!(state_field_diff(&pre, &pre).is_empty());
    }

    #[test]
    fn a_case_without_a_post_state_must_fail_by_the_spec() {
        let dir = tempfile::tempdir().unwrap();
        // `previous_justified_checkpoint.epoch + 3` overflows once bits 1 to 3 hold.
        let mut invalid = state_at(2);
        for i in 0..3 {
            invalid.justification_bits.set(i, true).unwrap();
        }
        invalid.previous_justified_checkpoint.epoch = u64::MAX;
        let c = case(dir.path(), "minimal", HANDLER, &invalid, None);
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        let c = case(dir.path(), "minimal", HANDLER, &invalid, Some(&invalid));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("failed: arithmetic overflow"));
        let c = case(dir.path(), "minimal", HANDLER, &state_at(2), None);
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("expects it to fail"));
    }

    #[test]
    fn malformed_cases_fail() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state_at(2);
        for (preset, handler, needle) in [
            ("general", HANDLER, "no epoch_processing runner"),
            ("minimal", "registry_updates", "needs a skip.toml entry"),
            (
                "minimal",
                "process_new_thing",
                "unknown epoch_processing handler",
            ),
            // A minimal state does not decode as a mainnet one.
            ("mainnet", HANDLER, "pre.ssz_snappy"),
        ] {
            let c = case(dir.path(), preset, handler, &pre, None);
            let err = run(&Reads::default(), &c).unwrap_err();
            assert!(err.contains(needle), "{handler}: {err}");
        }
        let mut c = case(dir.path(), "minimal", HANDLER, &pre, None);
        c.files.clear();
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("no pre.ssz_snappy"));
    }

    /// An unknown handler directory fails the setup of the run with its path in the message.
    /// A skip entry for it does not help: the directory must be classified in code.
    #[test]
    fn unknown_handler_fails() {
        let tree = tempfile::tempdir().unwrap();
        let rel = "tests/minimal/gloas/epoch_processing/brand_new_step";
        let dir = tree
            .path()
            .join("consensus-specs/v1.7.0-beta.4/minimal")
            .join(rel)
            .join("pyspec_tests/case_0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pre.ssz_snappy"), snappy(&state_at(2))).unwrap();
        let skip = "[[skip]]\nsource = \"consensus-specs\"\nfork = \"gloas\"\n\
                    preset = \"minimal\"\nrunner = \"epoch_processing\"\nhandler = \"*\"\n\
                    reason = \"test\"\nowner = \"ian\"\nissue = \"none\"\n\
                    expires = \"2026-11-30\"\n";
        let built = suite::build(&Config {
            root: tree.path(),
            manifest: "[[source]]\nname = \"consensus-specs\"\ntag = \"v1.7.0-beta.4\"\n",
            skip,
            selection: Some("minimal"),
            today: Date::parse("2026-10-26").unwrap(),
        });
        match built {
            Err(SuiteError::Setup(msg)) => {
                assert!(msg.contains(rel), "{msg}");
                assert!(msg.contains("unknown epoch_processing handler"), "{msg}");
            }
            Err(e) => panic!("expected a setup error, got {e:?}"),
            Ok(_) => panic!("expected a setup error, got a suite"),
        }
    }
}
