//! The committed `testing/skip.toml`: it is current, every entry names the plan item that
//! removes it (or `none`), and each skip group is keyed as the test layout assigns it. Whether
//! every entry still matches a file of the pinned vectors is checked by the `vectors` run
//! (stale entries fail it); these checks need no downloaded vectors.

use spec_tests::plan::{CaseKey, Date, SkipList};
use std::path::Path;

fn committed() -> SkipList {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/skip.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    SkipList::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn key(source: &str, fork: &str, preset: &str, runner: &str, handler: &str) -> CaseKey {
    CaseKey {
        source: source.into(),
        fork: fork.into(),
        preset: preset.into(),
        runner: runner.into(),
        handler: handler.into(),
        case: "pyspec_tests/case_0".into(),
    }
}

fn consensus(fork: &str, preset: &str, runner: &str, handler: &str) -> CaseKey {
    key("consensus-specs", fork, preset, runner, handler)
}

/// The issue of the entry that skips `k`; panics if none does.
fn issue_of<'a>(skips: &'a SkipList, k: &CaseKey) -> &'a str {
    skips
        .skipped_by(k)
        .unwrap_or_else(|| panic!("{k} is not skipped"))
        .issue
}

#[test]
fn committed_skip_list_is_current() {
    let skips = committed();
    let errs = skips.expired(Date::today_utc());
    assert!(errs.is_empty(), "expired entries: {errs:?}");
}

#[test]
fn every_entry_names_its_owner_and_removing_issue() {
    for e in committed().entries() {
        assert!(
            !e.reason.trim().is_empty() && !e.owner.trim().is_empty(),
            "{e:?}"
        );
        let plan_id = e.issue.split_once('.').is_some_and(|(major, minor)| {
            // A part of a plan item has one lowercase letter after its number.
            let minor = minor
                .strip_suffix(|c: char| c.is_ascii_lowercase())
                .unwrap_or(minor);
            [major, minor]
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        });
        assert!(
            e.issue == "none" || plan_id,
            "issue must be a plan ID such as \"1.17\" or \"5.11b\", or \"none\": {e:?}"
        );
    }
}

#[test]
fn layout_runners_are_skipped_with_reasons() {
    let skips = committed();
    let both = ["minimal", "mainnet"];
    let fulu_gloas = ["fulu", "gloas"];
    for (runner, forks, presets, handler) in [
        (
            "light_client",
            &fulu_gloas[..],
            &both[..],
            "single_merkle_proof",
        ),
        ("merkle_proof", &["fulu"], &both, "single_merkle_proof"),
        ("fork", &fulu_gloas, &both, "fork"),
        ("transition", &fulu_gloas, &both, "core"),
        ("genesis", &["phase0"], &["minimal"], "initialization"),
        ("sync", &["fulu"], &both, "optimistic"),
    ] {
        for fork in forks {
            for preset in presets {
                let k = consensus(fork, preset, runner, handler);
                let e = skips
                    .skipped_by(&k)
                    .unwrap_or_else(|| panic!("{k} is not skipped"));
                assert!(
                    e.reason.contains(runner) || e.reason.contains(&runner.replace('_', "-")),
                    "{k} is skipped by an entry that does not name {runner}: {e:?}"
                );
            }
        }
    }
}

#[test]
fn state_transition_skips_point_at_their_milestone() {
    let skips = committed();
    for preset in ["minimal", "mainnet"] {
        // No Fulu STF: upgrade_to_fulu and the Electra-to-Fulu transition never run.
        for (runner, handler) in [("fork", "fork"), ("transition", "core")] {
            let k = consensus("fulu", preset, runner, handler);
            assert_eq!(issue_of(&skips, &k), "none", "{k}");
        }
        // upgrade_to_gloas is not ported, and the Fulu-to-Gloas transition needs Fulu
        // processing: neither is work of the state-transition milestone.
        for (runner, handler) in [("fork", "fork"), ("transition", "core")] {
            let k = consensus("gloas", preset, runner, handler);
            assert_eq!(issue_of(&skips, &k), "none", "{k}");
        }
        // The whole-block runners and the rewards run.
        for (runner, handler) in [
            ("sanity", "blocks"),
            ("finality", "finality"),
            ("random", "random"),
            ("rewards", "basic"),
            ("rewards", "leak"),
            ("rewards", "random"),
            ("rewards", "inactivity_scores"),
        ] {
            let k = consensus("gloas", preset, runner, handler);
            assert!(skips.skipped_by(&k).is_none(), "{k} is skipped");
        }
        // Every Gloas epoch step runs, also the three that the epoch README omits
        // (pending_deposits_churn, proposer_lookahead and ptc_window).
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
            "builder_pending_payments",
        ] {
            let k = consensus("gloas", preset, "epoch_processing", handler);
            assert!(skips.skipped_by(&k).is_none(), "{k} is skipped");
        }
    }
}

/// The Gloas operations handlers that the runner executes are not skipped, and no handler of
/// beta.4 waits for its port: a skip entry for one would fail `skip_toml_has_no_m3_entries`.
#[test]
fn gloas_operations_runnable_handlers_are_not_skipped() {
    let skips = committed();
    for preset in ["minimal", "mainnet"] {
        for handler in spec_tests::operations::RUNNABLE {
            let k = consensus("gloas", preset, "operations", handler);
            assert!(skips.skipped_by(&k).is_none(), "{k} is skipped");
        }
    }
    assert_eq!(
        spec_tests::operations::NOT_RUN.len(),
        0,
        "every Gloas operations handler must run: {:?}",
        spec_tests::operations::NOT_RUN
    );
}

/// No Gloas `epoch_processing`, `sanity` or `finality` entry is left: every epoch step is
/// ported, the runner reads the whole-epoch files, the slots that cross an epoch boundary
/// run, and the blocks of `sanity/blocks` and `finality` run.
#[test]
fn no_gloas_epoch_or_slots_entry_is_left() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/skip.toml");
    let doc: toml::Table = std::fs::read_to_string(path).unwrap().parse().unwrap();
    let field =
        |e: &toml::Value, name: &str| e.get(name).and_then(|v| v.as_str()).map(String::from);
    let mut epoch_entries = Vec::new();
    let mut slots_entries = Vec::new();
    for e in doc["skip"].as_array().unwrap() {
        let runner = field(e, "runner");
        let handler = field(e, "handler");
        if field(e, "source").as_deref() != Some("consensus-specs")
            || !matches!(field(e, "fork").as_deref(), Some("gloas" | "*"))
        {
            continue;
        }
        match (runner.as_deref(), handler.as_deref()) {
            (Some("epoch_processing"), _) => epoch_entries.push(e.clone()),
            (Some("sanity" | "finality"), _) => slots_entries.push(e.clone()),
            _ => {}
        }
    }
    assert!(epoch_entries.is_empty(), "{epoch_entries:?}");
    assert!(slots_entries.is_empty(), "{slots_entries:?}");
}

/// The data-column `ssz_static` types, by the forks that define them: consensus-types defines
/// them all, so none may be skipped again.
const COLUMN_TYPES: [(&str, &[&str]); 7] = [
    ("DataColumnSidecar", &["fulu", "gloas"]),
    ("DataColumnsByRootIdentifier", &["fulu", "gloas"]),
    ("MatrixEntry", &["fulu", "gloas"]),
    ("PartialDataColumnGroupID", &["fulu", "gloas"]),
    ("PartialDataColumnPartsMetadata", &["fulu", "gloas"]),
    ("PartialDataColumnSidecar", &["fulu", "gloas"]),
    ("PartialDataColumnHeader", &["fulu"]),
];

/// Each column type's case key that `skips` would skip in any case, as `fork/preset/handler`.
fn skipped_column_types(skips: &SkipList) -> Vec<String> {
    let mut skipped = Vec::new();
    for (handler, forks) in COLUMN_TYPES {
        for fork in forks {
            for preset in ["minimal", "mainnet"] {
                let k = consensus(fork, preset, "ssz_static", handler);
                if let Some(e) = skips.skips_some_case_of(&k) {
                    skipped.push(format!("{fork}/{preset}/{handler}: {}", e.reason));
                }
            }
        }
    }
    skipped
}

#[test]
fn column_types_are_never_skipped() {
    let skipped = skipped_column_types(&committed());
    assert!(
        skipped.is_empty(),
        "testing/skip.toml skips column types: {skipped:?}"
    );
}

/// A handler glob narrowed to one case still skips real column vectors, so the check must
/// catch it.
#[test]
fn column_check_catches_a_handler_glob_narrowed_to_one_case() {
    let skips = SkipList::parse(
        r#"
[[skip]]
source  = "consensus-specs"
fork    = "*"
preset  = "*"
runner  = "ssz_static"
handler = "*DataColumn*"
case    = "ssz_random/case_1"
reason  = "narrow column skip"
owner   = "ian"
issue   = "none"
expires = "2026-11-30"
"#,
    )
    .unwrap();
    let skipped = skipped_column_types(&skips);
    // Every column type but MatrixEntry, in both presets: 5 * 2 forks + 1 Fulu-only, * 2.
    assert_eq!(skipped.len(), 22, "{skipped:?}");
    assert!(skipped.iter().all(|s| !s.contains("MatrixEntry")));
}

#[test]
fn kzg_bls_and_light_client_skips_point_at_their_milestone() {
    let skips = committed();
    let k = consensus("gloas", "mainnet", "ssz_static", "LightClientHeader");
    assert_eq!(issue_of(&skips, &k), "none");

    for handler in [
        "blob_to_kzg_commitment",
        "compute_blob_kzg_proof",
        "compute_challenge",
        "compute_kzg_proof",
        "verify_blob_kzg_proof",
        "verify_blob_kzg_proof_batch",
        "verify_kzg_proof",
        "recover_cells_and_kzg_proofs",
    ] {
        let k = key("cryptography-specs", "none", "none", "kzg", handler);
        assert_eq!(issue_of(&skips, &k), "6.7", "{k}");
    }
    let k = key(
        "cryptography-specs",
        "none",
        "none",
        "kzg",
        "compute_verify_cell_kzg_proof_batch_challenge",
    );
    assert_eq!(issue_of(&skips, &k), "none");
    let k = key("bls12-381-tests", "none", "none", "bls", "hash_to_G2");
    assert_eq!(issue_of(&skips, &k), "none");
}

/// Gloas `sanity/slots` runs, also the cases that cross an epoch boundary. phase0
/// `shuffling/core` runs; every other phase0 runner is out of scope.
#[test]
fn slots_and_shuffling_run() {
    let skips = committed();
    let case = |fork: &str, preset: &str, runner: &str, handler: &str, case: &str| CaseKey {
        case: case.into(),
        ..consensus(fork, preset, runner, handler)
    };
    for preset in ["minimal", "mainnet"] {
        for name in [
            "slots_1",
            "slots_2",
            "execution_payload_availability_reset_from_set",
            "execution_payload_availability_reset_from_unset",
            // The cases that cross an epoch boundary run the whole process_epoch.
            "over_epoch_boundary",
            "empty_epoch",
            "historical_accumulator",
        ] {
            let k = case(
                "gloas",
                preset,
                "sanity",
                "slots",
                &format!("pyspec_tests/{name}"),
            );
            assert!(skips.skipped_by(&k).is_none(), "{k} is skipped");
        }
        let k = case(
            "phase0",
            preset,
            "shuffling",
            "core",
            "shuffle/shuffle_0x00_0",
        );
        assert!(skips.skipped_by(&k).is_none(), "{k} is skipped");
        for runner in ["epoch_processing", "operations", "sanity", "ssz_static"] {
            let k = consensus("phase0", preset, runner, "any");
            assert_eq!(issue_of(&skips, &k), "none", "{k}");
        }
    }
}

/// The runners of the exit of the state-transition milestone (M3), each with the fork of its
/// vectors: every case of them runs, so no skip entry may reach one. The shuffling vectors
/// exist only under phase0, and Gloas shuffles the same way.
const M3_RUNNERS: [(&str, &str); 8] = [
    ("gloas", "sanity"),
    ("gloas", "epoch_processing"),
    ("gloas", "operations"),
    ("gloas", "finality"),
    ("gloas", "rewards"),
    ("gloas", "random"),
    ("gloas", "shuffling"),
    ("phase0", "shuffling"),
];

/// The entries of `skips` that the state-transition milestone must remove:
///
/// - an entry, with a `file` or without, that can match a case of [`M3_RUNNERS`] (its fork
///   and runner), whatever its preset, handler and case globs;
/// - an entry whose `issue` is a plan item of that milestone (`4.x`).
///
/// The out-of-scope runners (`light_client`, `fork`, `transition` and others) keep their
/// entries, with an `issue` of another milestone or `none`.
fn m3_entries(skips: &SkipList) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for (fork, runner) in M3_RUNNERS {
        for (index, summary) in skips.reaching("consensus-specs", fork, runner) {
            found.push(format!(
                "#{index} {summary}: reaches the {fork} {runner} cases"
            ));
        }
    }
    found.extend(
        skips
            .entries()
            .enumerate()
            .filter(|(_, e)| e.issue.starts_with("4."))
            .map(|(index, e)| format!("#{index} issue {}: {}", e.issue, e.reason)),
    );
    found
}

/// The `skip_toml_has_no_m3_entries` check on the skip file at `path`.
fn m3_entries_of(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap();
    let skips = SkipList::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    m3_entries(&skips)
}

fn committed_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/skip.toml")
}

/// Exit 1 of the state-transition milestone: no skip entry is left for its work.
#[test]
fn skip_toml_has_no_m3_entries() {
    let found = m3_entries_of(&committed_path());
    assert!(
        found.is_empty(),
        "testing/skip.toml has entries of the state-transition milestone: {found:#?}"
    );
}

/// The check of [`skip_toml_has_no_m3_entries`] turns red on a temp copy of `skip.toml` with
/// one M3 entry more: a Gloas entry of an M3 runner, also through a fork or runner glob or as
/// a `file` excuse, and an entry of another runner that names a `4.x` plan item.
#[test]
fn skip_toml_has_no_m3_entries_fails_on_an_m3_entry() {
    let committed = std::fs::read_to_string(committed_path()).unwrap();
    let entry = |fork: &str, runner: &str, handler: &str, extra: &str, issue: &str| {
        format!(
            "\n[[skip]]\nsource  = \"consensus-specs\"\nfork    = \"{fork}\"\npreset  = \"*\"\n\
             runner  = \"{runner}\"\nhandler = \"{handler}\"\n{extra}\
             reason  = \"an M3 entry\"\nowner   = \"ian\"\nissue   = \"{issue}\"\n\
             expires = \"2026-11-30\"\n"
        )
    };
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("skip.toml");
    for (added, needle) in [
        (
            entry("gloas", "rewards", "basic", "", "none"),
            "/rewards/basic/",
        ),
        (entry("gloas", "random", "*", "", "none"), "/random/"),
        (
            entry(
                "gloas",
                "sanity",
                "blocks",
                "case    = \"pyspec_tests/x\"\n",
                "none",
            ),
            "/sanity/blocks/pyspec_tests/x",
        ),
        (
            entry("*", "epoch_processing", "*", "", "none"),
            "/epoch_processing/",
        ),
        (
            entry("gloas", "*", "*", "", "none"),
            "consensus-specs/gloas/*/*/*",
        ),
        (
            entry(
                "gloas",
                "operations",
                "*",
                "file    = \"post.ssz_snappy\"\n",
                "none",
            ),
            "file post.ssz_snappy",
        ),
        (entry("gloas", "finality", "*", "", "none"), "/finality/"),
        (entry("gloas", "shuffling", "*", "", "none"), "/shuffling/"),
        // The shuffling vectors exist only under phase0.
        (
            entry(
                "phase0",
                "shuffling",
                "core",
                "case    = \"shuffle/*\"\n",
                "none",
            ),
            "consensus-specs/phase0/*/shuffling/core/shuffle/*",
        ),
        (
            entry("*", "shuffling", "*", "", "none"),
            "consensus-specs/*/*/shuffling/",
        ),
        (entry("gloas", "light_client", "*", "", "4.7"), "issue 4.7"),
    ] {
        std::fs::write(&copy, format!("{committed}{added}")).unwrap();
        let found = m3_entries_of(&copy);
        assert!(
            found.iter().any(|f| f.contains(needle)),
            "{needle}: {found:#?}"
        );
    }
    // An out-of-scope entry with no plan item of the milestone stays green.
    std::fs::write(
        &copy,
        format!(
            "{committed}{}",
            entry("fulu", "rewards", "basic", "", "none")
        ),
    )
    .unwrap();
    assert_eq!(m3_entries_of(&copy), Vec::<String>::new());
}

/// A Gloas `fork_choice` case of `handler`.
fn fork_choice_case(preset: &str, handler: &str, case: &str) -> CaseKey {
    CaseKey {
        case: format!("pyspec_tests/{case}"),
        ..consensus("gloas", preset, "fork_choice", handler)
    }
}

/// The Gloas `fork_choice` cases whose steps are only `tick`, `block` and `checks`, in both
/// presets, by handler (consensus-specs v1.7.0-beta.4 pyspec sources).
const TICK_AND_BLOCK_CASES: [(&str, &[&str]); 3] = [
    (
        "on_block",
        &[
            "basic",
            "on_block_future_block",
            "on_block_bad_parent_root",
            "proposer_boost",
            "proposer_boost_root_same_slot_untimely_block",
            "proposer_boost_is_first_block",
            "on_block_parent_full_rejects_unverified_payload",
        ],
    ),
    (
        "get_head",
        &[
            "genesis",
            "chain_no_attestations",
            "split_tie_breaker_no_attestations",
        ],
    ),
    (
        "get_parent_payload_status",
        &["get_parent_payload_status__genesis_empty_block_hash"],
    ),
];

#[test]
fn gloas_fork_choice_tick_and_block_cases_are_not_skipped() {
    let skips = committed();
    for preset in ["minimal", "mainnet"] {
        for (handler, cases) in TICK_AND_BLOCK_CASES {
            for case in cases {
                let k = fork_choice_case(preset, handler, case);
                let skip = skips.skipped_by(&k);
                assert!(skip.is_none(), "{k} is skipped: {skip:?}");
            }
        }
    }
}

/// The Gloas `fork_choice` cases whose steps are `tick`, `block`, `attestation`,
/// `attester_slashing` and `checks` (with `viable_for_head_roots_and_weights`), by preset and
/// handler (consensus-specs v1.7.0-beta.4 pyspec sources). The blocks of many carry
/// attestations, which the runner gives to `on_attestation`.
const ATTESTATION_CASES: [(&str, &str, &[&str]); 9] = [
    (
        "*",
        "on_attestation",
        &[
            "validate_on_attestation_same_slot_empty_vote",
            "validate_on_attestation_payload_invalid_index",
        ],
    ),
    (
        "*",
        "get_head",
        &[
            "shorter_chain_but_heavier_weight",
            "proposer_boost_excludes_slashed_validators",
            "discard_equivocations_on_attester_slashing",
        ],
    ),
    (
        "minimal",
        "get_head",
        &[
            "filtered_block_tree",
            "discard_equivocations_slashed_validator_censoring",
            "voting_source_within_two_epoch",
            "voting_source_beyond_two_epoch",
        ],
    ),
    (
        "minimal",
        "on_block",
        &[
            "on_block_checkpoints",
            "on_block_before_finalized",
            "on_block_finalized_skip_slots",
            "on_block_finalized_skip_slots_not_in_skip_chain",
            "new_finalized_slot_is_justified_checkpoint_ancestor",
            "justification_withholding",
            "justification_withholding_reverse_order",
            "justification_update_beginning_of_epoch",
            "justification_update_end_of_epoch",
            "incompatible_justification_update_start_of_epoch",
            "incompatible_justification_update_end_of_epoch",
            "justified_update_not_realized_finality",
            "justified_update_monotonic",
            "justified_update_always_if_better",
            "pull_up_past_epoch_block",
            "not_pull_up_current_epoch_block",
            "pull_up_on_tick",
        ],
    ),
    (
        "*",
        "ex_ante",
        &[
            "ex_ante_vanilla",
            "ex_ante_sandwich_without_attestations",
            "ex_ante_sandwich_with_honest_attestation",
        ],
    ),
    (
        "mainnet",
        "ex_ante",
        &[
            "ex_ante_attestations_is_greater_than_proposer_boost_with_boost",
            "ex_ante_sandwich_with_boost_not_sufficient",
        ],
    ),
    (
        "minimal",
        "reorg",
        &[
            "simple_attempted_reorg_without_enough_ffg_votes",
            "simple_attempted_reorg_delayed_justification_current_epoch",
            "include_votes_another_empty_chain_with_enough_ffg_votes_current_epoch",
            "include_votes_another_empty_chain_without_enough_ffg_votes_current_epoch",
            "delayed_justification_current_epoch",
            "delayed_justification_previous_epoch",
            "simple_attempted_reorg_delayed_justification_previous_epoch",
            "include_votes_another_empty_chain_with_enough_ffg_votes_previous_epoch",
        ],
    ),
    (
        "minimal",
        "withholding",
        &[
            "withholding_attack",
            "withholding_attack_unviable_honest_chain",
        ],
    ),
    (
        "minimal",
        "should_apply_proposer_boost",
        &[
            "should_apply_proposer_boost_parent_not_adjacent",
            "should_apply_proposer_boost_parent_not_weak",
            "should_apply_proposer_boost_no_equivocation",
            "should_apply_proposer_boost_withheld",
        ],
    ),
];

#[test]
fn gloas_fork_choice_attestation_cases_are_not_skipped() {
    let skips = committed();
    for (preset, handler, cases) in ATTESTATION_CASES {
        let presets: &[&str] = if preset == "*" {
            &["minimal", "mainnet"]
        } else {
            &[preset]
        };
        for preset in presets {
            for case in cases {
                let k = fork_choice_case(preset, handler, case);
                let skip = skips.skipped_by(&k);
                assert!(skip.is_none(), "{k} is skipped: {skip:?}");
            }
        }
    }
}

/// The cases of the run handlers whose steps are `tick`, `block`, `attestation`,
/// `execution_payload` and `checks`, by preset and handler. The runner gives each envelope to
/// `on_execution_payload_envelope`.
const ENVELOPE_STEP_CASES: [(&str, &str, &[&str]); 3] = [
    (
        "*",
        "on_block",
        &["on_block_parent_full_accepts_verified_payload"],
    ),
    (
        "*",
        "on_attestation",
        &[
            "validate_on_attestation_same_slot_full_vote_rejected",
            "validate_on_attestation_later_slot_full_vote_valid",
            "validate_on_attestation_beacon_root_payload_check",
        ],
    ),
    (
        "minimal",
        "filter_node_tree_variants",
        &[
            "get_head_prunes_childless_unviable_full_variant",
            "get_head_prunes_childless_unviable_empty_variant",
            "get_filtered_node_tree_contains_both_viable_childless_variants",
        ],
    ),
];

#[test]
fn gloas_fork_choice_cases_with_envelope_steps_are_not_skipped() {
    let skips = committed();
    for (preset, handler, cases) in ENVELOPE_STEP_CASES {
        let presets: &[&str] = if preset == "*" {
            &["minimal", "mainnet"]
        } else {
            &[preset]
        };
        for preset in presets {
            for case in cases {
                let k = fork_choice_case(preset, handler, case);
                let skip = skips.skipped_by(&k);
                assert!(skip.is_none(), "{k} is skipped: {skip:?}");
            }
        }
    }
}

/// The cases of the run handlers that also need payload attestations from the wire or payload
/// vote checks, which the runner does not have.
const PAYLOAD_VOTE_CASES: [(&str, &str, &[&str]); 1] = [(
    "*",
    "get_head",
    &[
        "get_head_full_payload_tiebreak",
        "get_head_empty_payload_tiebreak",
    ],
)];

#[test]
fn gloas_fork_choice_cases_with_payload_votes_stay_skipped() {
    let skips = committed();
    for (preset, handler, cases) in PAYLOAD_VOTE_CASES {
        let presets: &[&str] = if preset == "*" {
            &["minimal", "mainnet"]
        } else {
            &[preset]
        };
        for preset in presets {
            for case in cases {
                let k = fork_choice_case(preset, handler, case);
                assert_eq!(issue_of(&skips, &k), "5.14a", "{k}");
            }
        }
    }
}

#[test]
fn other_fork_choice_handlers_and_forks_stay_skipped() {
    let skips = committed();
    for (preset, handler, want) in [
        ("*", "on_payload_attestation_message", "5.14a"),
        ("*", "payload_timeliness", "5.14a"),
        ("*", "payload_data_availability", "5.14a"),
    ] {
        let presets: &[&str] = if preset == "*" {
            &["minimal", "mainnet"]
        } else {
            &[preset]
        };
        for preset in presets {
            let k = consensus("gloas", preset, "fork_choice", handler);
            let e = skips
                .skipped_by(&k)
                .unwrap_or_else(|| panic!("{k} is not skipped"));
            assert_eq!(e.issue, want, "{k}");
            assert!(!e.reason.trim().is_empty(), "{k}");
        }
    }
    // Fork choice is Gloas only: the Fulu cases have no runner, and heze is out of scope.
    for preset in ["minimal", "mainnet"] {
        for handler in ["on_block", "get_head", "ex_ante"] {
            let k = consensus("fulu", preset, "fork_choice", handler);
            assert_eq!(issue_of(&skips, &k), "none", "{k}");
            let k = consensus("heze", preset, "fork_choice", handler);
            let e = skips.skipped_by(&k).unwrap();
            assert!(e.reason.contains("heze"), "{k}: {e:?}");
        }
    }
}

/// No entry may skip a whole run handler of Gloas fork choice, or every handler of the
/// runner: the first matching entry wins, so such an entry hides every case below it. A new
/// case of a run handler is not skipped, so it runs and fails until it gets an entry.
#[test]
fn no_wildcard_entry_reaches_the_run_fork_choice_handlers() {
    let skips = committed();
    for preset in ["minimal", "mainnet"] {
        for handler in [
            "on_block",
            "get_head",
            "get_parent_payload_status",
            "ex_ante",
            "on_attestation",
            "reorg",
            "withholding",
            "should_apply_proposer_boost",
            "filter_node_tree_variants",
            "on_execution_payload_envelope",
            "deposit_with_reorg",
        ] {
            let k = CaseKey {
                case: "pyspec_tests/a_new_case".into(),
                ..consensus("gloas", preset, "fork_choice", handler)
            };
            let skip = skips.skipped_by(&k);
            assert!(skip.is_none(), "{k} is skipped: {skip:?}");
        }
    }
}
