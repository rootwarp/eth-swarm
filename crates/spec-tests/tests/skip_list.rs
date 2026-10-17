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
    }
}

#[test]
fn column_and_kzg_skips_point_at_their_milestone() {
    let skips = committed();
    for fork in ["fulu", "gloas"] {
        for handler in [
            "DataColumnSidecar",
            "DataColumnsByRootIdentifier",
            "MatrixEntry",
            "PartialDataColumnGroupID",
            "PartialDataColumnPartsMetadata",
            "PartialDataColumnSidecar",
        ] {
            let k = consensus(fork, "minimal", "ssz_static", handler);
            assert_eq!(issue_of(&skips, &k), "1.17", "{k}");
        }
    }
    let k = consensus("fulu", "mainnet", "ssz_static", "PartialDataColumnHeader");
    assert_eq!(issue_of(&skips, &k), "1.17");
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
