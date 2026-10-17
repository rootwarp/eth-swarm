//! Loading the pinned trusted setup.

mod common;

use std::path::{Path, PathBuf};

use common::{cells_case, setup, setup_sha256, sha256, SETUP_PATH};
use crypto_kzg::{SetupError, TrustedSetup, CELLS_PER_EXT_BLOB, PRECOMPUTE};
use serde_json::Value;

#[test]
fn loads_beta4_json() {
    assert_eq!(
        PRECOMPUTE, 0,
        "cl-verify's memory budget assumes no MSM tables"
    );
    let setup = TrustedSetup::load_pinned(SETUP_PATH, setup_sha256()).expect("beta.4 setup loads");

    let case = cells_case();
    let (cells, proofs) = setup
        .compute_cells_and_kzg_proofs(&case.blob)
        .expect("valid blob");
    assert_eq!(cells.as_slice(), case.cells.as_slice());
    let proofs: Vec<_> = proofs.iter().map(|p| p.to_bytes()).collect();
    assert_eq!(proofs, case.proofs);

    let commitments = vec![case.commitment; CELLS_PER_EXT_BLOB];
    let indices: Vec<u64> = (0..CELLS_PER_EXT_BLOB as u64).collect();
    assert!(setup
        .verify_cell_kzg_proof_batch(&commitments, &indices, cells.as_slice(), &proofs)
        .expect("well-formed batch"));

    // The pairing check is not vacuous: a cell paired with another cell's proof fails.
    let mut swapped = proofs.clone();
    swapped.swap(0, 1);
    assert!(!setup
        .verify_cell_kzg_proof_batch(&commitments, &indices, cells.as_slice(), &swapped)
        .expect("well-formed batch"));
}

/// Writes `bytes` to a fresh temp file and loads it pinned to `digest`.
fn load_bytes(bytes: &[u8], digest: [u8; 32]) -> Result<TrustedSetup, SetupError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("setup.json");
    std::fs::write(&path, bytes).unwrap();
    TrustedSetup::load_pinned(&path, digest)
}

/// Loads `json` pinned to its own digest, so the failure comes from parsing, not the pin.
fn load_json(json: &Value) -> Result<TrustedSetup, SetupError> {
    let bytes = serde_json::to_vec(json).unwrap();
    load_bytes(&bytes, sha256(&bytes))
}

fn beta4_json() -> Value {
    serde_json::from_slice(&std::fs::read(SETUP_PATH).unwrap()).unwrap()
}

fn entries<'a>(json: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    json[key].as_array_mut().unwrap()
}

#[test]
fn rejects_malformed() {
    // Odd-length hex.
    let mut json = beta4_json();
    entries(&mut json, "g1_monomial")[7] = Value::from(format!("0x{}", "a".repeat(95)));
    let err = load_json(&json).map(drop).unwrap_err();
    assert!(
        matches!(
            err,
            SetupError::Hex {
                field: "g1_monomial",
                index: 7,
                source: hex::FromHexError::OddLength
            }
        ),
        "{err:?}"
    );

    // 4,095 Lagrange points.
    let mut json = beta4_json();
    entries(&mut json, "g1_lagrange").pop();
    let err = load_json(&json).map(drop).unwrap_err();
    assert!(
        matches!(
            err,
            SetupError::PointCount {
                field: "g1_lagrange",
                expected: 4096,
                got: 4095
            }
        ),
        "{err:?}"
    );

    // Missing `g2_monomial`.
    let mut json = beta4_json();
    json.as_object_mut().unwrap().remove("g2_monomial");
    let err = load_json(&json).map(drop).unwrap_err();
    assert!(matches!(err, SetupError::Json(_)), "{err:?}");
    assert!(err.to_string().contains("g2_monomial"), "{err}");

    // Digest mismatch: one flipped bit of the pin on the genuine file.
    let mut wrong = setup_sha256();
    wrong[31] ^= 1;
    let err = TrustedSetup::load_pinned(SETUP_PATH, wrong)
        .map(drop)
        .unwrap_err();
    assert!(
        matches!(err, SetupError::DigestMismatch { expected, actual } if expected == wrong && actual == setup_sha256()),
        "{err:?}"
    );

    // The pin is checked before the bytes are even parsed: garbage under a wrong pin is a digest
    // error, not a JSON error, so nothing after the pin (including c-kzg) sees unpinned bytes.
    let err = load_bytes(b"not json", setup_sha256())
        .map(drop)
        .unwrap_err();
    assert!(matches!(err, SetupError::DigestMismatch { .. }), "{err:?}");
}

#[test]
fn rejects_malformed_points() {
    // Missing `0x` prefix.
    let mut json = beta4_json();
    let first = entries(&mut json, "g2_monomial")[0].as_str().unwrap()[2..].to_owned();
    entries(&mut json, "g2_monomial")[0] = Value::from(first);
    let err = load_json(&json).map(drop).unwrap_err();
    assert!(
        matches!(
            err,
            SetupError::MissingPrefix {
                field: "g2_monomial",
                index: 0
            }
        ),
        "{err:?}"
    );

    // Even-length hex of the wrong width (a G1 point where a G2 point belongs).
    let mut json = beta4_json();
    let g1 = entries(&mut json, "g1_monomial")[0].clone();
    entries(&mut json, "g2_monomial")[64] = g1;
    let err = load_json(&json).map(drop).unwrap_err();
    assert!(
        matches!(
            err,
            SetupError::Hex {
                field: "g2_monomial",
                index: 64,
                source: hex::FromHexError::InvalidStringLength
            }
        ),
        "{err:?}"
    );

    // Non-hex characters.
    let mut json = beta4_json();
    entries(&mut json, "g1_lagrange")[4095] = Value::from(format!("0x{}", "z".repeat(96)));
    let err = load_json(&json).map(drop).unwrap_err();
    assert!(
        matches!(
            err,
            SetupError::Hex {
                field: "g1_lagrange",
                index: 4095,
                source: hex::FromHexError::InvalidHexCharacter { .. }
            }
        ),
        "{err:?}"
    );

    // A wrong-typed entry is a JSON error, not a panic.
    let mut json = beta4_json();
    entries(&mut json, "g1_monomial")[0] = Value::from(1);
    assert!(matches!(load_json(&json), Err(SetupError::Json(_))));

    // Unknown top-level keys are refused.
    let mut json = beta4_json();
    json["extra"] = Value::from("x");
    assert!(matches!(load_json(&json), Err(SetupError::Json(_))));

    // Well-formed hex that is not a curve point: c-kzg itself refuses it.
    let mut json = beta4_json();
    entries(&mut json, "g1_monomial")[1] = Value::from(format!("0x{}", "11".repeat(48)));
    let err = load_json(&json).map(drop).unwrap_err();
    assert!(matches!(err, SetupError::Backend(_)), "{err:?}");
}

#[test]
fn rejects_unreadable() {
    let missing = PathBuf::from("/nonexistent/trusted_setup_4096.json");
    let err = TrustedSetup::load_pinned(&missing, setup_sha256())
        .map(drop)
        .unwrap_err();
    assert!(
        matches!(&err, SetupError::Io { path, .. } if path == &missing),
        "{err:?}"
    );

    // A file larger than any trusted setup is refused before it is read in full.
    let huge = vec![b' '; crypto_kzg::MAX_SETUP_BYTES as usize + 1];
    let err = load_bytes(&huge, sha256(&huge)).map(drop).unwrap_err();
    assert!(matches!(err, SetupError::TooLarge { .. }), "{err:?}");
}

#[test]
fn errors_display_their_cause() {
    let err = TrustedSetup::load_pinned(Path::new(SETUP_PATH), [0; 32])
        .map(drop)
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(&"00".repeat(32)) && msg.contains(common::SETUP_SHA256_HEX),
        "{msg}"
    );
}

#[test]
fn shared_setup_is_debug_without_dumping_points() {
    assert_eq!(format!("{:?}", setup()), "TrustedSetup { .. }");
}

/// `TrustedSetup` has no constructor besides `load_pinned`: no public fields, `new`, `Default` or
/// `From`.
#[test]
fn setup_ctor_compile_fail() {
    trybuild::TestCases::new().compile_fail("tests/compile_fail/setup_ctor.rs");
}
