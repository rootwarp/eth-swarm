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

/// The vector-framed seeds, `(target, name, sha256)`, pinned so that they hold without the
/// vectors (CI fetches none). `fuzz/gen-seeds.sh` with the vectors rebuilds them; update these
/// with it.
const VECTOR_SEEDS: [(&str, &str, &str); 7] = [
    (
        "blocks_by_range_resp",
        "gloas-vector-case_0",
        "c759a9912317cd64c16daefe0cce1a971fe8fc36e24776eba34ab0ff89c091b6",
    ),
    (
        "blocks_by_range_resp",
        "gloas-vector-case_1",
        "738849c45074a96236255e02b73c6d08001c5aee8c5883e9620ce6a856f7e51e",
    ),
    (
        "blocks_by_range_resp",
        "gloas-vector-case_2",
        "f8a37208e6f9b5adf09200204cafe906d10f436ddeaae1a01b107abf10297efd",
    ),
    (
        "blocks_by_range_resp",
        "gloas-vectors-all",
        "74d84a84b5250c8035fbe3800c32765c60d398bcba005a001bdb3975cccc4746",
    ),
    (
        "gossip_transform",
        "gloas-vector-case_0",
        "a579cdc043877c62e2a69a7e38dae05807496a08653fc4e2b04fd19bd0425622",
    ),
    (
        "gossip_transform",
        "gloas-vector-case_1",
        "8fafb36a1127dd9412b0781821fecdfdb09a79e1002323c1ea935cde0c2587bd",
    ),
    (
        "gossip_transform",
        "gloas-vector-case_2",
        "6b50382bd86443ef7d89659015129a89c87c8976208bd63157f8159a598bb5d9",
    ),
];

/// Whether a seed is built from a vector case.
fn from_vectors(name: &str) -> bool {
    name.starts_with(VECTOR_PREFIX) || name == "gloas-vectors-all"
}

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
    if blocks.is_some() {
        assert_eq!(
            committed, built,
            "fuzz/corpus differs from fuzz/gen-seeds.sh output"
        );
    } else {
        let without =
            |m: &BTreeMap<(String, String), Vec<u8>>| -> BTreeMap<(String, String), Vec<u8>> {
                m.iter()
                    .filter(|(k, _)| !from_vectors(&k.1))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            };
        assert_eq!(without(&committed), without(&built));
        let framed = committed.keys().filter(|k| from_vectors(&k.1)).count();
        assert_eq!(framed, VECTOR_SEEDS.len(), "vector-framed seeds missing");
    }
}

/// The response-chunk seeds every single-chunk protocol gets, by name.
const CHUNK_SEEDS: [&str; 17] = [
    "valid",
    "oversize-prefix-10mib-plus-1",
    "prefix-over-4gib",
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
    "frame-claims-over-4gib",
    "too-many-empty-frames",
    "prefix-over-type-bound",
];

/// The request seeds every protocol with a request body gets, after `request-`.
const REQUEST_SEEDS: [&str; 13] = [
    "valid",
    "oversize-prefix-10mib-plus-1",
    "prefix-over-4gib",
    "prefix-over-type-bound",
    "prefix-under-type-bound",
    "snappy-bomb",
    "varint-11-bytes",
    "frames-past-the-prefix",
    "frame-body-too-large",
    "frame-output-too-large",
    "frame-claims-over-4gib",
    "truncated",
    "trailing-byte",
];

#[test]
fn every_target_has_the_required_malformed_seeds() {
    let committed = committed();
    let has = |target: &str, name: &str| committed.contains_key(&(target.into(), name.into()));
    let chunks = |target: &str, prefix: &str| {
        for name in CHUNK_SEEDS {
            // These targets name their valid chunks by what they hold.
            if matches!(target, "blocks_by_range_resp" | "data_column_sidecar") && name == "valid" {
                continue;
            }
            assert!(
                has(target, &format!("{prefix}{name}")),
                "{target}/{prefix}{name}"
            );
        }
    };
    let requests = |target: &str, prefix: &str| {
        for name in REQUEST_SEEDS {
            let name = format!("{prefix}request-{name}");
            assert!(has(target, &name), "{target}/{name}");
        }
    };
    for target in [
        "status_v2",
        "metadata_v3",
        "ping_goodbye",
        "blocks_by_range_resp",
    ] {
        chunks(target, "");
    }
    requests("status_v2", "");
    requests("ping_goodbye", "");
    assert!(has("metadata_v3", "request-empty"));
    assert!(has("metadata_v3", "request-trailing-byte"));
    for name in REQUEST_SEEDS {
        assert!(
            has("ping_goodbye", &format!("goodbye-{name}")),
            "goodbye-{name}"
        );
    }
    assert!(has("blocks_by_range_resp", "unknown-context-digest"));
    assert!(has("blocks_by_range_resp", "too-many-chunks"));
    assert!(has("blocks_by_range_resp", "data-after-error"));
    assert!(has("blocks_by_range_resp", "response-over-byte-budget"));

    for prefix in ["status-", "metadata-", "ping-", "goodbye-"] {
        chunks("rpc_chunk", prefix);
    }
    for prefix in ["status-", "ping-", "goodbye-", "blocks-"] {
        requests("rpc_chunk", prefix);
    }
    for name in CHUNK_SEEDS {
        let name = if name == "valid" { "gloas-valid" } else { name };
        assert!(
            has("rpc_chunk", &format!("blocks-{name}")),
            "rpc_chunk/blocks-{name}"
        );
    }
    for name in [
        "metadata-request-empty",
        "goodbye-valid",
        "goodbye-error-code-1",
        "blocks-unknown-context-digest",
        "blocks-context-cut-short",
        "blocks-fulu-bpo-digest-valid",
    ] {
        assert!(has("rpc_chunk", name), "rpc_chunk/{name}");
    }

    for target in ["gossip_transform", "message_id"] {
        for name in [
            "block-gloas-valid",
            "block-declares-over-10mib",
            "block-declares-4gib",
            "block-declares-over-4gib",
            "block-varint-11-bytes",
            "block-truncated",
            "block-trailing-byte",
            "block-snappy-bomb-1mib",
            "block-over-cap",
            "block-not-snappy",
            "aggregate-at-cap",
            "aggregate-over-cap",
            "topic-unknown-name",
            "topic-cut-short",
        ] {
            assert!(has(target, name), "{target}/{name}");
        }
    }

    for name in [
        "sepolia-fulu-fork-epoch-272640",
        "sepolia-before-bpo1-epoch-274175",
        "sepolia-bpo1-epoch-274176",
        "sepolia-before-bpo2-epoch-275711",
        "sepolia-bpo2-epoch-275712",
        "sepolia-before-gloas-epoch-353023",
        "sepolia-gloas-epoch-353024",
        "eth2-15-bytes",
        "cgc-leading-zero",
        "nfd-3-bytes",
        "cgc-rlp-list",
        "ed25519",
        "truncated",
        "trailing-byte",
        "forged-signature",
        "over-300-bytes",
        "regression-structured-ed25519-broken-raw-cgc",
    ] {
        assert!(has("enr_fields", name), "enr_fields/{name}");
        if !matches!(name, "truncated" | "trailing-byte" | "forged-signature")
            && !name.starts_with("regression-")
        {
            let structured = format!("structured-{name}");
            assert!(has("enr_fields", &structured), "enr_fields/{structured}");
        }
    }

    // Gate 2a: the Gloas sidecar as gossip and as a response chunk of both column protocols.
    for name in [
        "valid",
        "at-cap",
        "oversize-column-list",
        "oversize-cells-no-proofs",
        "cells-ne-proofs",
        "index-128",
        "index-u64-max",
        "fulu-slot",
        "declares-cap-plus-1",
        "declares-over-10mib",
        "declares-4gib",
        "declares-over-4gib",
        "snappy-bomb-at-cap",
        "varint-11-bytes",
        "truncated",
        "trailing-byte",
    ] {
        let name = format!("gossip-{name}");
        assert!(
            has("data_column_sidecar", &name),
            "data_column_sidecar/{name}"
        );
    }
    for prefix in ["range-", "root-"] {
        chunks("data_column_sidecar", prefix);
        for name in [
            "gloas-valid",
            "gloas-at-cap",
            "gloas-oversize-column-list",
            "gloas-cells-ne-proofs",
            "gloas-index-128",
            "fulu-valid",
            "fulu-cells-ne-commitments",
            "fulu-index-128",
            "unknown-context-digest",
            "snappy-bomb-within-bound",
            "empty-response",
        ] {
            let name = format!("{prefix}{name}");
            assert!(
                has("data_column_sidecar", &name),
                "data_column_sidecar/{name}"
            );
        }
    }
    // The column requests: no selector byte, so the request seeds carry no `request-` prefix.
    for (target, bounds) in [
        (
            "columns_by_range_req",
            &[
                "at-sidecar-bound",
                "sidecars-past-bound",
                "count-times-columns-overflows",
                "columns-at-list-bound",
                "columns-past-list-bound",
                "index-128",
            ][..],
        ),
        (
            "columns_by_root_req",
            &[
                "at-both-bounds",
                "identifiers-past-bound",
                "identifiers-past-bound-full",
                "identifier-columns-past-bound",
                "index-128",
            ][..],
        ),
    ] {
        for name in REQUEST_SEEDS.iter().chain(bounds) {
            if *name == "prefix-under-type-bound" && target == "columns_by_root_req" {
                continue;
            }
            assert!(has(target, name), "{target}/{name}");
        }
        assert!(
            has(target, "too-many-empty-frames"),
            "{target}/too-many-empty-frames"
        );
    }
}

#[test]
fn vector_seeds_match_their_pinned_sha256() {
    let committed = committed();
    let framed: Vec<(&str, &str)> = committed
        .keys()
        .filter(|(_, n)| from_vectors(n))
        .map(|(t, n)| (t.as_str(), n.as_str()))
        .collect();
    let pinned: Vec<(&str, &str)> = VECTOR_SEEDS.iter().map(|(t, n, _)| (*t, *n)).collect();
    assert_eq!(framed, pinned, "vector-framed seeds and their pins");
    for (target, name, sha) in VECTOR_SEEDS {
        let bytes = &committed[&(target.to_string(), name.to_string())];
        let got: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, sha, "{target}/{name}");
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
