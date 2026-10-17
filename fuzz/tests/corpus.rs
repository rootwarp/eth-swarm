//! The committed seed corpus: what `seeds::all` builds, and clean under every target.
//!
//! Rebuilding the vector-framed seeds needs the Gloas mainnet `ssz_static` vectors
//! (`SPEC_VECTORS_DIR`, default `target/spec-vectors` of the repo). Without them those seeds are
//! held to their pinned sha256 instead; a vector set that is there but does not load fails.

use ethswarm_fuzz::seeds::{self, VECTOR_PREFIX};
use ethswarm_fuzz::{run, TARGETS};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The vector-framed seeds, pinned so that they hold without the vectors (CI fetches none).
/// `fuzz/gen-seeds.sh` with the vectors rebuilds them; update these with it.
const VECTOR_SEEDS: [(&str, &str); 4] = [
    (
        "gloas-vector-case_0",
        "c759a9912317cd64c16daefe0cce1a971fe8fc36e24776eba34ab0ff89c091b6",
    ),
    (
        "gloas-vector-case_1",
        "738849c45074a96236255e02b73c6d08001c5aee8c5883e9620ce6a856f7e51e",
    ),
    (
        "gloas-vector-case_2",
        "f8a37208e6f9b5adf09200204cafe906d10f436ddeaae1a01b107abf10297efd",
    ),
    (
        "gloas-vectors-all",
        "74d84a84b5250c8035fbe3800c32765c60d398bcba005a001bdb3975cccc4746",
    ),
];

#[path = "../examples/gen-seeds/vectors.rs"]
mod vectors;

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The files of `dir/<target>/` for every target, `(target, name) -> bytes`; nothing if `dir`
/// has no such subdirectory.
fn files_in(dir: &str) -> BTreeMap<(String, String), Vec<u8>> {
    let mut out = BTreeMap::new();
    for target in TARGETS {
        let dir: PathBuf = manifest_dir().join(dir).join(target);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.insert((target.to_string(), name), fs::read(&path).unwrap());
        }
    }
    out
}

/// `(target, name) -> bytes` of every committed seed: the fuzzing corpus (`fuzz/corpus`) and
/// the slow seeds (`fuzz/corpus-slow`).
fn committed() -> BTreeMap<(String, String), Vec<u8>> {
    let mut out = files_in(seeds::SLOW_DIR);
    for (k, v) in files_in(seeds::FUZZ_DIR) {
        assert!(out.insert(k.clone(), v).is_none(), "{k:?} in both corpora");
    }
    out
}

#[test]
fn every_seed_runs_clean() {
    let seeds = committed();
    assert!(!seeds.is_empty());
    for ((target, name), bytes) in &seeds {
        assert!(run(target, bytes), "{target}/{name}: no such target");
    }
}

#[test]
fn committed_corpus_is_what_the_generator_builds() {
    let blocks =
        vectors::load(&vectors::default_dir()).expect("the vector set is there but does not load");
    let built: BTreeMap<(String, String), Vec<u8>> = seeds::all(blocks.as_deref().unwrap_or(&[]))
        .into_iter()
        .map(|s| ((s.target.to_string(), s.name), s.bytes))
        .collect();
    let committed = committed();
    let from_vectors =
        |k: &(String, String)| k.1.starts_with(VECTOR_PREFIX) || k.1 == "gloas-vectors-all";
    if blocks.is_some() {
        assert_eq!(
            committed, built,
            "fuzz/corpus differs from fuzz/gen-seeds.sh output"
        );
    } else {
        let without = |m: &BTreeMap<_, Vec<u8>>| -> BTreeMap<(String, String), Vec<u8>> {
            m.iter()
                .filter(|(k, _)| !from_vectors(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        assert_eq!(without(&committed), without(&built));
        let framed = committed.keys().filter(|k| from_vectors(k)).count();
        assert_eq!(
            framed,
            vectors::CASES.len() + 1,
            "vector-framed seeds missing"
        );
    }
}

#[test]
fn every_target_has_the_required_malformed_seeds() {
    let committed = committed();
    let has = |target: &str, name: &str| committed.contains_key(&(target.into(), name.into()));
    for target in TARGETS {
        for name in [
            "valid",
            "oversize-prefix-10mib-plus-1",
            "snappy-bomb",
            "varint-11-bytes",
            "truncated",
            "trailing-byte",
            "error-code-1",
            "error-code-2",
            "error-code-3",
            "invalid-code-4",
            "invalid-code-255",
            "frame-body-too-large",
            "frame-output-too-large",
            "too-many-empty-frames",
        ] {
            if target == "blocks_by_range_resp" && name == "valid" {
                continue;
            }
            assert!(has(target, name), "{target}/{name}");
        }
    }
    assert!(has("ping_goodbye", "goodbye-valid"));
    assert!(has("ping_goodbye", "goodbye-oversize-prefix-10mib-plus-1"));
    assert!(has("blocks_by_range_resp", "unknown-context-digest"));
    assert!(has("blocks_by_range_resp", "too-many-chunks"));
    assert!(has("blocks_by_range_resp", "data-after-error"));
    assert!(has("blocks_by_range_resp", "response-over-byte-budget"));
}

#[test]
fn vector_seeds_match_their_pinned_sha256() {
    let committed = committed();
    let framed: Vec<&String> = committed
        .keys()
        .filter(|(t, n)| {
            t == "blocks_by_range_resp"
                && (n.starts_with(VECTOR_PREFIX) || n == "gloas-vectors-all")
        })
        .map(|(_, n)| n)
        .collect();
    let pinned: Vec<&str> = VECTOR_SEEDS.iter().map(|(n, _)| *n).collect();
    assert_eq!(framed, pinned, "vector-framed seeds and their pins");
    for (name, sha) in VECTOR_SEEDS {
        let bytes = &committed[&("blocks_by_range_resp".to_string(), name.to_string())];
        let got: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, sha, "blocks_by_range_resp/{name}");
    }
}

#[test]
fn a_vector_set_that_is_there_must_load() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("corpus-vectors");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    assert!(
        vectors::load(&root).unwrap().is_none(),
        "no suite: no vectors"
    );
    let case = vectors::suite_dir(&root).join(vectors::CASES[0]);
    fs::create_dir_all(&case).unwrap();
    fs::write(case.join("serialized.ssz_snappy"), b"not snappy").unwrap();
    assert!(vectors::load(&root).is_err(), "a broken suite is an error");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn slow_seeds_stay_out_of_the_fuzzing_corpus() {
    let fuzzing = files_in(seeds::FUZZ_DIR);
    let slow = files_in(seeds::SLOW_DIR);
    let blocks = vectors::load(&vectors::default_dir()).unwrap();
    for seed in seeds::all(blocks.as_deref().unwrap_or(&[])) {
        let key = (seed.target.to_string(), seed.name.clone());
        let (here, not_there) = if seed.slow {
            (&slow, &fuzzing)
        } else {
            (&fuzzing, &slow)
        };
        assert!(here.contains_key(&key), "{key:?} not in its corpus");
        assert!(!not_there.contains_key(&key), "{key:?} in the other corpus");
    }
    // Seconds per execution: it would slow the fuzzer by orders of magnitude and sit near
    // the -timeout, so it runs under coverage and in the tests only.
    assert!(slow.contains_key(&(
        "blocks_by_range_resp".into(),
        "response-over-byte-budget".into()
    )));
}
