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
            [major, minor]
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        });
        assert!(
            e.issue == "none" || plan_id,
            "issue must be a plan ID such as \"1.17\" or \"none\": {e:?}"
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
        for (runner, handler) in [
            ("operations", "payload_attestation"),
            ("operations", "execution_payload_bid"),
            ("epoch_processing", "builder_pending_payments"),
            ("epoch_processing", "ptc_window"),
            ("fork", "fork"),
            ("sanity", "blocks"),
        ] {
            let k = consensus("gloas", preset, runner, handler);
            assert_eq!(issue_of(&skips, &k), "4.7", "{k}");
        }
        // The reason of each epoch step that is not ported names the item that ports it.
        for (handler, item) in [
            ("builder_pending_payments", "4.6b"),
            ("ptc_window", "4.2b"),
            ("registry_updates", "4.2b"),
        ] {
            let k = consensus("gloas", preset, "epoch_processing", handler);
            let reason = skips.skipped_by(&k).unwrap().reason;
            assert!(
                reason.starts_with(&format!("Ported by {item}:")),
                "{k}: {reason}"
            );
        }
        // The ported epoch steps run.
        for handler in [
            "justification_and_finalization",
            "inactivity_updates",
            "rewards_and_penalties",
        ] {
            let k = consensus("gloas", preset, "epoch_processing", handler);
            assert!(skips.skipped_by(&k).is_none(), "{k} is skipped");
        }
    }
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

/// Gloas `sanity/slots` runs inside one epoch; the cases that cross an epoch boundary wait
/// for `process_epoch`. phase0 `shuffling/core` runs; every other phase0 runner is out of
/// scope.
#[test]
fn slots_inside_one_epoch_and_shuffling_run() {
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
        for name in [
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
            assert_eq!(issue_of(&skips, &k), "4.7", "{k}");
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
