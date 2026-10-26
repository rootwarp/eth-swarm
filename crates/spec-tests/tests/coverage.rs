//! The coverage guard and the handler-directory check, end to end through `suite::build` on
//! small vector trees laid out like `testing/fetch-vectors.sh` output. No downloaded vectors
//! are needed.

use consensus_types::gloas::Checkpoint;
use network_config::SPEC_PIN;
use spec_tests::plan::Date;
use spec_tests::suite::{self, Config, Outcome, Suite, SuiteError};
use ssz::Decode;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tree_hash::TreeHash;

const MANIFEST: &str = r#"
[[source]]
name = "consensus-specs"
tag = "v1.7.0-beta.4"
[[source]]
name = "ssz-specs"
tag = "v0.1.0"
[[source]]
name = "cryptography-specs"
tag = "v0.1.0"
[[source]]
name = "bls12-381-tests"
tag = "v0.1.2"
"#;

const MINIMAL: &str = "consensus-specs/v1.7.0-beta.4/minimal/tests/minimal";
const CASE_DIR: &str = "consensus-specs/v1.7.0-beta.4/minimal/tests/minimal/gloas/ssz_static/\
                        Checkpoint/ssz_one/case_0";

fn entry(
    source: &str,
    fork: &str,
    preset: &str,
    runner: &str,
    handler: &str,
    extra: &str,
) -> String {
    format!(
        "[[skip]]\nsource = \"{source}\"\nfork = \"{fork}\"\npreset = \"{preset}\"\n\
         runner = \"{runner}\"\nhandler = \"{handler}\"\n{extra}reason = \"test\"\n\
         owner = \"ian\"\nissue = \"TBD\"\nexpires = \"2026-11-30\"\n"
    )
}

fn value_yaml_excused() -> String {
    entry(
        "consensus-specs",
        "*",
        "*",
        "ssz_static",
        "*",
        "file = \"value.yaml\"\n",
    )
}

fn write(root: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap();
    p
}

/// One valid `Checkpoint` case of `fork`: serialized, roots, value and manifest.
fn checkpoint_case(root: &Path, fork: &str) {
    let dir = format!("{MINIMAL}/{fork}/ssz_static/Checkpoint/ssz_one/case_0");
    let bytes = [7u8; 40];
    let htr = Checkpoint::from_ssz_bytes(&bytes).unwrap().tree_hash_root();
    let compressed = snap::raw::Encoder::new().compress_vec(&bytes).unwrap();
    write(root, &format!("{dir}/serialized.ssz_snappy"), &compressed);
    write(
        root,
        &format!("{dir}/roots.yaml"),
        format!("root: '0x{}'\n", hex::encode(htr)).as_bytes(),
    );
    write(
        root,
        &format!("{dir}/value.yaml"),
        b"{epoch: '1', root: '0x07'}\n",
    );
    write(
        root,
        &format!("{dir}/manifest.yaml"),
        format!(
            "preset: minimal\nfork: {fork}\nrunner: ssz_static\nhandler: Checkpoint\n\
             suite: ssz_one\ncase: case_0\n"
        )
        .as_bytes(),
    );
}

/// One phase0 `shuffling/core` case: one index maps to itself.
fn shuffling_case(root: &Path) {
    let dir = format!("{MINIMAL}/phase0/shuffling/core/shuffle/shuffle_0x01_1");
    write(
        root,
        &format!("{dir}/mapping.yaml"),
        format!("seed: '0x{}'\ncount: 1\nmapping: [0]\n", "01".repeat(32)).as_bytes(),
    );
    write(
        root,
        &format!("{dir}/manifest.yaml"),
        b"preset: minimal\nfork: phase0\nrunner: shuffling\nhandler: core\n\
          suite: shuffle\ncase: shuffle_0x01_1\n",
    );
}

/// A minimal tree with one Fulu and one Gloas `Checkpoint` case and one shuffling case: the
/// runnable subtrees.
fn minimal_tree() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    checkpoint_case(dir.path(), "fulu");
    checkpoint_case(dir.path(), "gloas");
    shuffling_case(dir.path());
    dir
}

/// One file in every directory the cryptography-specs and bls12-381-tests sets must hold.
fn crypto_trees(root: &Path) {
    for h in ["bls/eth_aggregate_pubkeys", "kzg/compute_cells"] {
        write(
            root,
            &format!("cryptography-specs/v0.1.0/tests/tests/{h}/case_0/data.yaml"),
            b"input: []\noutput: null\n",
        );
    }
    for h in [
        "aggregate",
        "aggregate_verify",
        "batch_verify",
        "deserialization_G1",
        "deserialization_G2",
        "fast_aggregate_verify",
        "sign",
        "verify",
    ] {
        write(
            root,
            &format!("bls12-381-tests/v0.1.2/bls_tests_yaml/{h}/case_0.yaml"),
            b"input: {}\noutput: null\n",
        );
    }
}

fn build(root: &Path, skip: &str, sets: &str) -> Result<Suite, SuiteError> {
    suite::build(&Config {
        root,
        manifest: MANIFEST,
        skip,
        selection: Some(sets),
        today: Date::parse("2026-10-17").unwrap(),
    })
}

/// Runs every runnable trial; panics on a failing one. Returns the trial names.
fn run_all(suite: &Suite) -> Vec<String> {
    for t in &suite.trials {
        match &t.outcome {
            Outcome::Run(r) => r().unwrap_or_else(|e| panic!("{}: {e}", t.name)),
            Outcome::Skip(_) => {}
            Outcome::Unaccounted => panic!("{} is unaccounted", t.name),
        }
    }
    suite.trials.iter().map(|t| t.name.clone()).collect()
}

#[test]
fn coverage_passes_on_a_fully_read_tree() {
    let tree = minimal_tree();
    let suite = build(tree.path(), &value_yaml_excused(), "minimal").unwrap();
    assert_eq!(
        run_all(&suite),
        [
            "fulu_ssz_static_minimal::Checkpoint::ssz_one::case_0",
            "gloas_ssz_static_minimal::Checkpoint::ssz_one::case_0",
            "phase0_shuffling_minimal::core::shuffle::shuffle_0x01_1"
        ]
    );
    let covered = suite.guard.check(&suite.reads).unwrap();
    assert_eq!((covered.read, covered.total), (8, 10));
}

#[test]
fn coverage_flags_unread_file() {
    let tree = minimal_tree();
    write(tree.path(), &format!("{CASE_DIR}/extra.yaml"), b"planted\n");

    let suite = build(tree.path(), &value_yaml_excused(), "minimal").unwrap();
    run_all(&suite);
    let unread = suite.guard.check(&suite.reads).unwrap_err();
    let planted = PathBuf::from(format!("{CASE_DIR}/extra.yaml"));
    assert_eq!(unread.unread, std::slice::from_ref(&planted));
    assert!(
        unread.to_string().contains(&planted.display().to_string()),
        "{unread}"
    );

    // A matching skip entry excuses it.
    let excuse = entry(
        "consensus-specs",
        "gloas",
        "minimal",
        "ssz_static",
        "Checkpoint",
        "case = \"ssz_one/case_0\"\nfile = \"extra.yaml\"\n",
    );
    let suite = build(tree.path(), &(value_yaml_excused() + &excuse), "minimal").unwrap();
    run_all(&suite);
    assert!(suite.guard.check(&suite.reads).is_ok());
}

#[test]
fn coverage_flags_a_file_without_a_value_yaml_entry() {
    let tree = minimal_tree();
    let suite = build(tree.path(), "", "minimal").unwrap();
    run_all(&suite);
    let unread = suite.guard.check(&suite.reads).unwrap_err();
    assert_eq!(
        unread.unread,
        [
            PathBuf::from(format!(
                "{MINIMAL}/fulu/ssz_static/Checkpoint/ssz_one/case_0/value.yaml"
            )),
            PathBuf::from(format!("{CASE_DIR}/value.yaml")),
        ]
    );
}

#[test]
fn stray_file_outside_any_case_is_unaccounted_until_skipped() {
    let tree = minimal_tree();
    let stray = "consensus-specs/v1.7.0-beta.4/minimal/tests/minimal/gloas/README.md";
    write(tree.path(), stray, b"planted\n");
    let suite = build(tree.path(), &value_yaml_excused(), "minimal").unwrap();
    let unaccounted: Vec<_> = suite
        .trials
        .iter()
        .filter(|t| matches!(t.outcome, Outcome::Unaccounted))
        .map(|t| t.name.clone())
        .collect();
    assert_eq!(unaccounted, ["gloas__minimal::::"]);
    assert!(suite.guard.check(&suite.reads).is_err());

    // The stray file's key has no runner, handler or case; `case = ""` matches only it.
    let skip = value_yaml_excused()
        + &entry(
            "consensus-specs",
            "gloas",
            "minimal",
            "*",
            "*",
            "case = \"\"\n",
        );
    let suite = build(tree.path(), &skip, "minimal").unwrap();
    run_all(&suite);
    assert!(suite.guard.check(&suite.reads).is_ok());
}

#[test]
fn unknown_handler_fails() {
    for (rel, name) in [
        (
            "cryptography-specs/v0.1.0/tests/tests/kzg/compute_cells_v2/case_0/data.yaml",
            "unknown kzg handler directory `compute_cells_v2`",
        ),
        (
            "cryptography-specs/v0.1.0/tests/tests/bls/eth_sign/case_0/data.yaml",
            "unknown bls handler directory `eth_sign`",
        ),
        (
            "bls12-381-tests/v0.1.2/bls_tests_yaml/hash_to_G1/case_0.yaml",
            "unknown bls handler directory `hash_to_G1`",
        ),
    ] {
        let tree = tempfile::tempdir().unwrap();
        crypto_trees(tree.path());
        write(tree.path(), rel, b"input: {}\noutput: null\n");
        let sets = "cryptography-specs bls12-381-tests";
        // Even a skip entry for it does not help: the directory must be classified in code.
        let skip = entry("cryptography-specs", "*", "*", "*", "*", "")
            + &entry("bls12-381-tests", "*", "*", "*", "*", "");
        match build(tree.path(), &skip, sets) {
            Err(SuiteError::Setup(msg)) => assert!(msg.contains(name), "{msg}"),
            other => panic!("{rel}: expected a setup error, got {:?}", other.err()),
        }
    }
}

#[test]
fn known_but_unrun_handler_needs_a_skip_entry() {
    let tree = tempfile::tempdir().unwrap();
    crypto_trees(tree.path());
    write(
        tree.path(),
        "cryptography-specs/v0.1.0/tests/tests/kzg/verify_kzg_proof/case_0/data.yaml",
        b"input: {}\noutput: null\n",
    );
    let name = "cryptography_specs_kzg::verify_kzg_proof::case_0";
    let outcome = |suite: &Suite| {
        let t = suite.trials.iter().find(|t| t.name == name).unwrap();
        match t.outcome {
            Outcome::Run(_) => "run",
            Outcome::Skip(_) => "skip",
            Outcome::Unaccounted => "unaccounted",
        }
    };
    let suite = build(tree.path(), "", "cryptography-specs").unwrap();
    assert_eq!(outcome(&suite), "unaccounted");
    let skip = entry(
        "cryptography-specs",
        "none",
        "none",
        "kzg",
        "verify_kzg_proof",
        "",
    );
    let suite = build(tree.path(), &skip, "cryptography-specs").unwrap();
    assert_eq!(outcome(&suite), "skip");
}

#[test]
fn selected_sets_must_exist_and_be_known() {
    let tree = tempfile::tempdir().unwrap();
    match build(tree.path(), "", "mainnet") {
        Err(SuiteError::Setup(msg)) => assert!(msg.contains("mainnet vectors missing"), "{msg}"),
        other => panic!("{:?}", other.err()),
    }
    match build(tree.path(), "", "minimal mainnt") {
        Err(SuiteError::Setup(msg)) => assert!(msg.contains("unknown set \"mainnt\""), "{msg}"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn stale_entries_fail_only_for_scanned_sets() {
    let tree = minimal_tree();
    let mainnet_only = entry(
        "consensus-specs",
        "gloas",
        "mainnet",
        "ssz_static",
        "Gone",
        "",
    );
    assert!(build(
        tree.path(),
        &(value_yaml_excused() + &mainnet_only),
        "minimal"
    )
    .is_ok());
    let minimal_stale = entry(
        "consensus-specs",
        "gloas",
        "minimal",
        "ssz_static",
        "Gone",
        "",
    );
    match build(
        tree.path(),
        &(value_yaml_excused() + &minimal_stale),
        "minimal",
    ) {
        Err(SuiteError::Rules(msg)) => assert!(msg.contains("stale"), "{msg}"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn manifest_tags_follow_the_spec_pin() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/vectors.manifest.toml"),
    )
    .unwrap();
    let tags = suite::manifest_tags(&text).unwrap();
    assert_eq!(tags["consensus-specs"], SPEC_PIN.consensus_specs);
    assert_eq!(tags["ssz-specs"], SPEC_PIN.ssz_specs);
    for set in &suite::SETS {
        assert!(tags.contains_key(set.source), "{}", set.source);
        assert!(spec_tests::plan::KNOWN_SOURCES.contains(&set.source));
    }
}

const COMPTESTS: &str = "consensus-specs/v1.7.0-beta.4/comptests/tests";

/// A comptests tree with one compliance case, one case of another runner and one file under
/// each Python source tree.
fn comptests_tree() -> TempDir {
    let tree = tempfile::tempdir().unwrap();
    let r = tree.path();
    let fcc =
        format!("{COMPTESTS}/minimal/gloas/fork_choice_compliance/block_tree_test/small/case_0");
    write(r, &format!("{fcc}/steps.yaml"), b"[]\n");
    write(
        r,
        &format!("{COMPTESTS}/core/pyspec/eth_consensus_specs/__init__.py"),
        b"\n",
    );
    write(r, &format!("{COMPTESTS}/formats/bls/README.md"), b"\n");
    write(r, &format!("{COMPTESTS}/generators/__init__.py"), b"\n");
    tree
}

/// The comptests entries of `testing/skip.toml`: compliance vectors plus each Python tree.
fn comptests_skips() -> String {
    entry(
        "comptests",
        "*",
        "minimal",
        "fork_choice_compliance",
        "*",
        "",
    ) + &entry("comptests", "*", "core", "*", "*", "")
        + &entry("comptests", "*", "formats", "*", "*", "")
        + &entry("comptests", "*", "generators", "*", "*", "")
}

#[test]
fn comptests_are_scanned_and_a_narrowed_skip_flags_strays() {
    let tree = comptests_tree();

    // Nothing runs comptests: without an entry every case is unaccounted.
    let suite = build(tree.path(), "", "comptests").unwrap();
    assert_eq!(suite.scanned, ["comptests"]);
    assert!(suite
        .trials
        .iter()
        .all(|t| matches!(t.outcome, Outcome::Unaccounted)));
    assert!(suite.trials.iter().any(|t| t.name
        == "comptests_gloas_fork_choice_compliance_minimal::block_tree_test::small::case_0"));

    // The committed entries skip it all.
    let suite = build(tree.path(), &comptests_skips(), "comptests").unwrap();
    assert!(suite
        .trials
        .iter()
        .all(|t| matches!(t.outcome, Outcome::Skip(_))));
    assert!(suite.guard.check(&suite.reads).is_ok());

    // Without the `core` entry, the Python sources are flagged again.
    let narrow = entry(
        "comptests",
        "*",
        "minimal",
        "fork_choice_compliance",
        "*",
        "",
    ) + &entry("comptests", "*", "formats", "*", "*", "")
        + &entry("comptests", "*", "generators", "*", "*", "");
    let suite = build(tree.path(), &narrow, "comptests").unwrap();
    let unread = suite.guard.check(&suite.reads).unwrap_err();
    assert_eq!(
        unread.unread,
        [PathBuf::from(format!(
            "{COMPTESTS}/core/pyspec/eth_consensus_specs/__init__.py"
        ))]
    );
}

#[test]
fn comptests_case_of_another_runner_stays_unaccounted() {
    let tree = comptests_tree();
    let other = format!("{COMPTESTS}/minimal/gloas/fork_choice/get_head/pyspec_tests/case_0");
    write(tree.path(), &format!("{other}/steps.yaml"), b"[]\n");
    let suite = build(tree.path(), &comptests_skips(), "comptests").unwrap();
    let unaccounted: Vec<_> = suite
        .trials
        .iter()
        .filter(|t| matches!(t.outcome, Outcome::Unaccounted))
        .map(|t| t.name.as_str())
        .collect();
    assert_eq!(
        unaccounted,
        ["comptests_gloas_fork_choice_minimal::get_head::pyspec_tests::case_0"]
    );
}

#[test]
fn comptests_presets_are_valid_only_for_comptests() {
    let tree = minimal_tree();
    match build(
        tree.path(),
        &entry("consensus-specs", "*", "core", "*", "*", ""),
        "minimal",
    ) {
        Err(SuiteError::Rules(msg)) => assert!(msg.contains("`preset` \"core\""), "{msg}"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn comptests_entry_is_not_stale_when_comptests_are_not_extracted() {
    let tree = minimal_tree();
    let skip = value_yaml_excused() + &comptests_skips();
    assert!(build(tree.path(), &skip, "minimal").is_ok());
}

#[test]
fn required_set_without_files_fails() {
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tree.path().join(MINIMAL)).unwrap();
    match build(tree.path(), "", "minimal") {
        Err(SuiteError::Setup(msg)) => {
            assert!(msg.contains("minimal vectors hold no files"), "{msg}")
        }
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn missing_fork_subtree_fails() {
    let tree = tempfile::tempdir().unwrap();
    checkpoint_case(tree.path(), "gloas");
    shuffling_case(tree.path());
    match build(tree.path(), &value_yaml_excused(), "minimal") {
        Err(SuiteError::Setup(msg)) => {
            assert!(msg.contains("tests/minimal/fulu/ssz_static"), "{msg}")
        }
        other => panic!("{:?}", other.err()),
    }
    // The shuffling runner's tree is required too.
    let tree = tempfile::tempdir().unwrap();
    checkpoint_case(tree.path(), "fulu");
    checkpoint_case(tree.path(), "gloas");
    match build(tree.path(), &value_yaml_excused(), "minimal") {
        Err(SuiteError::Setup(msg)) => {
            assert!(msg.contains("tests/minimal/phase0/shuffling"), "{msg}")
        }
        other => panic!("{:?}", other.err()),
    }
    let crypto = tempfile::tempdir().unwrap();
    crypto_trees(crypto.path());
    std::fs::remove_dir_all(
        crypto
            .path()
            .join("cryptography-specs/v0.1.0/tests/tests/kzg"),
    )
    .unwrap();
    match build(crypto.path(), "", "cryptography-specs") {
        Err(SuiteError::Setup(msg)) => assert!(msg.contains("tests/kzg"), "{msg}"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn general_alone_keeps_the_committed_skip_list_valid() {
    let tree = tempfile::tempdir().unwrap();
    let case = "consensus-specs/v1.7.0-beta.4/general/tests/general/altair/bls/\
                eth_aggregate_pubkeys/bls/eth_aggregate_pubkeys_empty_list";
    write(
        tree.path(),
        &format!("{case}/data.yaml"),
        b"input: []\noutput: null\n",
    );
    write(
        tree.path(),
        &format!("{case}/manifest.yaml"),
        b"preset: general\nfork: altair\nrunner: bls\nhandler: eth_aggregate_pubkeys\n\
          suite: bls\ncase: eth_aggregate_pubkeys_empty_list\n",
    );
    let skip = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/skip.toml"),
    )
    .unwrap();
    let suite = build(tree.path(), &skip, "general").unwrap_or_else(|e| panic!("{e:?}"));
    run_all(&suite);
    assert!(suite.guard.check(&suite.reads).is_ok());
}

#[test]
fn files_planted_during_the_run_fail_the_guard() {
    let tree = minimal_tree();
    let suite = build(tree.path(), &value_yaml_excused(), "minimal").unwrap();
    run_all(&suite);
    assert!(suite.guard.check(&suite.reads).is_ok());
    // A file that appears after the walk is reported even inside a skipped or excused place.
    let late = format!("{CASE_DIR}/value.yaml.bak");
    write(tree.path(), &late, b"late\n");
    let err = suite.guard.check(&suite.reads).unwrap_err();
    assert_eq!(err.appeared, [PathBuf::from(&late)]);
    assert!(err.unread.is_empty());
    assert!(err.to_string().contains("appeared during the run"), "{err}");
}

/// One ssz-specs `test_basic_types` case, a valid `Uint8`.
fn ssz_specs_tree() -> TempDir {
    let tree = tempfile::tempdir().unwrap();
    write(
        tree.path(),
        "ssz-specs/v0.1.0/ssz-test-vectors-v0.1.0/fixtures/ssz/ssz/test_basic_types/uint8_1.json",
        br#"{"uint8_1": {"typeName": "Uint8", "serialized": "0x01",
            "root": "0x0100000000000000000000000000000000000000000000000000000000000000"}}"#,
    );
    tree
}

#[test]
fn planning_reads_do_not_count_as_coverage() {
    let tree = ssz_specs_tree();
    let suite = build(tree.path(), "", "ssz-specs").unwrap();
    // Planning opened the fixture to learn its type; no trial has run yet.
    let unread = suite.guard.check(&suite.reads).unwrap_err();
    assert_eq!(unread.unread.len(), 1, "{unread}");
    run_all(&suite);
    assert!(suite.guard.check(&suite.reads).is_ok());
}

#[test]
fn expired_entry_fails_the_suite_and_expiry_day_passes() {
    let tree = minimal_tree();
    let suite_on = |today: &str| {
        suite::build(&Config {
            root: tree.path(),
            manifest: MANIFEST,
            skip: &value_yaml_excused(),
            selection: Some("minimal"),
            today: Date::parse(today).unwrap(),
        })
    };
    // The entry expires on 2026-11-30: valid through that day, expired on the next.
    assert!(suite_on("2026-11-30").is_ok());
    match suite_on("2026-12-01") {
        Err(SuiteError::Rules(msg)) => assert!(msg.contains("expired on 2026-11-30"), "{msg}"),
        other => panic!("{:?}", other.err()),
    }
}
