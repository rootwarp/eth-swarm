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
//! ([`check_handler`]). The epoch README does not list every Gloas handler, so the map also
//! names `pending_deposits_churn` (the churn cases of `process_pending_deposits`),
//! `proposer_lookahead` and `ptc_window`.
//!
//! The steps get the in-process context of [`crate::bls_backend`]: the deposit verdicts come
//! from `crypto-bls` through [`StateKeys`], and so does the aggregate key of the next sync
//! committee. A case can also hold these files:
//!
//! - `meta.yaml` with `bls_setting`: 0, 1 or no value checks the deposit signatures, and 2
//!   turns BLS off ([`crate::bls_backend::BlsOff`]).
//! - `config.yaml`, which replaces the config of the preset. The transition takes its config
//!   values from the preset, so each value that it reads ([`config_values`]) must be the
//!   value of the case. Another value fails the case.
//!
//! The `pre_epoch.ssz_snappy` and `post_epoch.ssz_snappy` files of the whole-epoch check are
//! not read until `process_epoch` is complete (it stops at the builder payments step). A
//! `skip.toml` entry excuses them from the coverage guard.

use crate::bls_backend::{backend_for, bls_context, bls_setting, StateKeys};
use crate::check::state_field_diff;
use crate::coverage::Reads;
use crate::fixture;
use crate::plan::{Case, CaseKey};
use consensus_types::gloas::BeaconState;
use consensus_types::{Mainnet, Minimal};
use ssz::Decode;
use state_transition::per_epoch::gloas::{process_proposer_lookahead, process_ptc_window};
use state_transition::per_epoch::pending::{
    process_pending_consolidations, process_pending_deposits,
};
use state_transition::per_epoch::registry::{
    process_effective_balance_updates, process_registry_updates, process_slashings,
};
use state_transition::per_epoch::resets::{
    process_eth1_data_reset, process_historical_summaries_update,
    process_participation_flag_updates, process_randao_mixes_reset, process_slashings_reset,
    process_sync_committee_updates,
};
use state_transition::per_epoch::{
    process_inactivity_updates, process_justification_and_finalization,
    process_rewards_and_penalties,
};
use state_transition::preset::{
    EJECTION_BALANCE, INACTIVITY_SCORE_BIAS, INACTIVITY_SCORE_RECOVERY_RATE,
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
};
use state_transition::{state_root, BlsContext, Preset, StfError};
use std::path::Path;
use tree_hash::TreeHash;

/// One epoch step: the function of a handler, with the BLS context of the case.
pub type Step<E> = fn(&mut BeaconState<E>, &BlsContext) -> Result<(), StfError>;

/// The function of a Gloas `epoch_processing` handler directory. `Ok(None)` is a known step
/// that is not ported yet (it needs a `skip.toml` entry), and `Err` is a directory this
/// runner does not know.
pub fn step<E: Preset>(handler: &str) -> Result<Option<Step<E>>, String> {
    let step: Step<E> = match handler {
        "justification_and_finalization" => |s, _| process_justification_and_finalization(s),
        "inactivity_updates" => |s, _| process_inactivity_updates(s),
        "rewards_and_penalties" => |s, _| process_rewards_and_penalties(s),
        "registry_updates" => |s, _| process_registry_updates(s),
        "slashings" => |s, _| process_slashings(s),
        "eth1_data_reset" => |s, _| process_eth1_data_reset(s),
        // `pending_deposits_churn` holds the churn cases of the same step.
        "pending_deposits" | "pending_deposits_churn" => {
            |s, bls| process_pending_deposits(s, bls.genesis_fork_version, bls.backend)
        }
        "pending_consolidations" => |s, _| process_pending_consolidations(s),
        "effective_balance_updates" => |s, _| process_effective_balance_updates(s),
        "slashings_reset" => |s, _| process_slashings_reset(s),
        "randao_mixes_reset" => |s, _| process_randao_mixes_reset(s),
        "historical_summaries_update" => |s, _| process_historical_summaries_update(s),
        "participation_flag_updates" => |s, _| process_participation_flag_updates(s),
        "sync_committee_updates" => |s, bls| process_sync_committee_updates(s, bls.aggregator),
        "proposer_lookahead" => |s, _| process_proposer_lookahead(s),
        "ptc_window" => |s, _| process_ptc_window(s),
        "builder_pending_payments" => return Ok(None),
        other => {
            return Err(format!(
                "unknown epoch_processing handler directory `{other}`: classify it in \
                 crates/spec-tests/src/epoch_processing.rs"
            ))
        }
    };
    Ok(Some(step))
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
    let keys = StateKeys::new(&state);
    let bls = bls_context(
        &case.key.preset,
        backend_for(bls_setting(reads, case)?, &keys),
    )?;
    check_config::<E>(reads, case, &bls)?;
    match (step(&mut state, &bls), post) {
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

/// The config values that the transition reads, with the values of the config of preset
/// `E`, which is also the config of the vectors: `configs/{minimal,mainnet}.yaml`.
pub fn config_values<E: Preset>(bls: &BlsContext) -> [(&'static str, u64); 10] {
    [
        (
            "GENESIS_FORK_VERSION",
            u64::from(u32::from_be_bytes(bls.genesis_fork_version)),
        ),
        ("EJECTION_BALANCE", EJECTION_BALANCE),
        (
            "MIN_VALIDATOR_WITHDRAWABILITY_DELAY",
            MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
        ),
        ("INACTIVITY_SCORE_BIAS", INACTIVITY_SCORE_BIAS),
        (
            "INACTIVITY_SCORE_RECOVERY_RATE",
            INACTIVITY_SCORE_RECOVERY_RATE,
        ),
        (
            "MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA",
            E::MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA,
        ),
        ("CHURN_LIMIT_QUOTIENT_GLOAS", E::CHURN_LIMIT_QUOTIENT_GLOAS),
        (
            "CONSOLIDATION_CHURN_LIMIT_QUOTIENT",
            E::CONSOLIDATION_CHURN_LIMIT_QUOTIENT,
        ),
        (
            "MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS",
            E::MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS,
        ),
        (
            "MIN_BUILDER_WITHDRAWABILITY_DELAY",
            E::MIN_BUILDER_WITHDRAWABILITY_DELAY,
        ),
    ]
}

/// `Err` unless the `config.yaml` of the case (if any) has the [`config_values`] of `E`.
/// The fork versions are hex integers in YAML (`0x00000001`).
fn check_config<E: Preset>(reads: &Reads, case: &Case, bls: &BlsContext) -> Result<(), String> {
    let Some(path) = case.file("config.yaml") else {
        return Ok(());
    };
    let config = fixture::load(reads, path)?;
    for (name, want) in config_values::<E>(bls) {
        let got = fixture::field(&config, name).map_err(|e| format!("config.yaml: {e}"))?;
        if got.as_i64().and_then(|v| u64::try_from(v).ok()) != Some(want) {
            return Err(format!(
                "config.yaml sets {name} to {got:?}, but the runner uses {want}"
            ));
        }
    }
    Ok(())
}

/// A `BeaconState` from a `.ssz_snappy` file.
fn decode_state<E: Preset>(reads: &Reads, path: &Path) -> Result<BeaconState<E>, String> {
    let bytes = fixture::ssz_snappy(reads, path)?;
    BeaconState::<E>::from_ssz_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_backend::BlsOff;
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
            "registry_updates",
            "slashings",
            "eth1_data_reset",
            "pending_deposits",
            "pending_deposits_churn",
            "pending_consolidations",
            "effective_balance_updates",
            "slashings_reset",
            "randao_mixes_reset",
            "historical_summaries_update",
            "participation_flag_updates",
            "sync_committee_updates",
            "proposer_lookahead",
            "ptc_window",
        ] {
            assert!(supported("gloas", "minimal", handler), "{handler}");
            assert!(supported("gloas", "mainnet", handler), "{handler}");
            assert!(!supported("fulu", "minimal", handler));
            assert!(!supported("gloas", "general", handler));
        }
        assert_eq!(handler_runs("builder_pending_payments"), Ok(false));
        assert!(!supported("gloas", "minimal", "builder_pending_payments"));
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
            (
                "minimal",
                "builder_pending_payments",
                "needs a skip.toml entry",
            ),
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

    /// `case` with one more file `name` in `dir`.
    fn with_file(mut case: Case, dir: &Path, name: &str, text: &str) -> Case {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        case.files.push(CaseFile {
            path,
            name: name.into(),
        });
        case
    }

    /// The config values that the transition reads, as `configs/minimal.yaml` writes them.
    const MINIMAL_CONFIG: &str = "GENESIS_FORK_VERSION: 0x00000001\n\
        GLOAS_FORK_EPOCH: 0\n\
        EJECTION_BALANCE: 16000000000\n\
        MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256\n\
        INACTIVITY_SCORE_BIAS: 4\n\
        INACTIVITY_SCORE_RECOVERY_RATE: 16\n\
        MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: 64000000000\n\
        CHURN_LIMIT_QUOTIENT_GLOAS: 16\n\
        CONSOLIDATION_CHURN_LIMIT_QUOTIENT: 32\n\
        MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS: 128000000000\n\
        MIN_BUILDER_WITHDRAWABILITY_DELAY: 2\n";

    #[test]
    fn a_case_config_must_match_the_config_of_the_preset() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state_at(2);
        let mut post = pre.clone();
        process_justification_and_finalization(&mut post).unwrap();
        let c = case(dir.path(), "minimal", HANDLER, &pre, Some(&post));
        let c = with_file(c, dir.path(), "config.yaml", MINIMAL_CONFIG);
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        // Another value of a config field that the transition reads fails the case.
        let other = MINIMAL_CONFIG.replace("EJECTION_BALANCE: 16000000000", "EJECTION_BALANCE: 1");
        let c = case(dir.path(), "minimal", HANDLER, &pre, Some(&post));
        let c = with_file(c, dir.path(), "config.yaml", &other);
        let err = run(&Reads::default(), &c).unwrap_err();
        assert!(err.contains("EJECTION_BALANCE"), "{err}");
        let other = MINIMAL_CONFIG.replace("0x00000001", "0x00000002");
        let c = case(dir.path(), "minimal", HANDLER, &pre, Some(&post));
        let c = with_file(c, dir.path(), "config.yaml", &other);
        let err = run(&Reads::default(), &c).unwrap_err();
        assert!(err.contains("GENESIS_FORK_VERSION"), "{err}");
        // A config without one of the fields fails too.
        let c = case(dir.path(), "minimal", HANDLER, &pre, Some(&post));
        let c = with_file(c, dir.path(), "config.yaml", "PRESET_BASE: 'minimal'\n");
        assert!(run(&Reads::default(), &c).unwrap_err().contains("missing"));
    }

    #[test]
    fn bls_setting_two_turns_the_deposit_signatures_off() {
        use consensus_types::common::PendingDeposit;
        use state_transition::per_epoch::pending::process_pending_deposits;
        let dir = tempfile::tempdir().unwrap();
        // A deposit for a new key with a signature that does not decode.
        let mut pre = state_at(2);
        pre.pending_deposits
            .push(PendingDeposit {
                pubkey: [0xd1; 48],
                withdrawal_credentials: Default::default(),
                amount: 32_000_000_000,
                signature: [0x01; 96],
                slot: 0,
            })
            .unwrap();
        let mut with_bls = pre.clone();
        let mut without_bls = pre.clone();
        let keys = StateKeys::new(&pre);
        let bls = bls_context("minimal", &keys).unwrap();
        process_pending_deposits(&mut with_bls, bls.genesis_fork_version, bls.backend).unwrap();
        process_pending_deposits(&mut without_bls, bls.genesis_fork_version, &BlsOff).unwrap();
        assert_eq!(with_bls.validators.len(), 0);
        assert_eq!(without_bls.validators.len(), 1);
        for (meta, post, passes) in [
            ("{bls_setting: 2}", &without_bls, true),
            ("{bls_setting: 2}", &with_bls, false),
            ("{bls_setting: 1}", &with_bls, true),
            ("{bls_setting: 0}", &with_bls, true),
            ("{}", &with_bls, true),
        ] {
            let c = case(dir.path(), "minimal", "pending_deposits", &pre, Some(post));
            let c = with_file(c, dir.path(), "meta.yaml", meta);
            assert_eq!(run(&Reads::default(), &c).is_ok(), passes, "{meta}");
        }
        let c = case(
            dir.path(),
            "minimal",
            "pending_deposits",
            &pre,
            Some(&with_bls),
        );
        let c = with_file(c, dir.path(), "meta.yaml", "{bls_setting: 3}");
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("bls_setting"));
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
