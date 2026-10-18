//! `tests/fixtures/unit_blob_columns.bin`, the KZG cells and proofs the storage-contract tests
//! send to cl-verify, is exactly what the pinned trusted setup computes, and its commitments are
//! the setup's Lagrange points.
//!
//! The fixture blobs are the unit vectors `e_0` and `e_1` (one field element 1, every other 0).
//! In the spec, `blob_to_kzg_commitment(blob)` is
//! `g1_lincomb(bit_reversal_permutation(KZG_SETUP_G1_LAGRANGE), blob)`, so the commitment of
//! `e_i` is `KZG_SETUP_G1_LAGRANGE[bit_reverse(i)]`: entries 0 and 2048 of the setup file. The
//! unit tests read those from the setup file and the cells and proofs from the fixture, so they
//! need no trusted-setup load of their own.
//!
//! Layout, for each column of [`COLUMNS`] in order: the column index (1 byte), then for each blob
//! its cell (2,048 bytes) and its proof (48 bytes).
//!
//! Regenerate with `REGEN_KZG_FIXTURE=1 cargo test -p cl-chain --test kzg_fixture`.

use crypto_kzg::{
    Blob, Bytes48, Cell, TrustedSetup, BETA4_MAINNET_SHA256, BYTES_PER_BLOB, CELLS_PER_EXT_BLOB,
};
use std::path::PathBuf;

/// The columns the unit tests use (custody columns 1, 47, 87, 102 of node `U256::MAX`, and
/// others).
const COLUMNS: [u8; 7] = [0, 1, 5, 47, 87, 102, 127];
/// The field element each blob sets to 1.
const UNIT_POSITIONS: [usize; 2] = [0, 1];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn setup_path() -> PathBuf {
    manifest_dir().join("../crypto-kzg/data/trusted_setup_4096.json")
}

/// The commitment of each fixture blob: its Lagrange point in the setup file.
fn commitments() -> Vec<Bytes48> {
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(setup_path()).unwrap()).unwrap();
    let lagrange = json["g1_lagrange"].as_array().unwrap();
    let bits = (BYTES_PER_BLOB / 32).trailing_zeros();
    UNIT_POSITIONS
        .iter()
        .map(|&i| {
            let reversed = i.reverse_bits() >> (usize::BITS - bits);
            let hex = lagrange[reversed].as_str().unwrap();
            Bytes48::from_bytes(&hex::decode(&hex[2..]).unwrap()).unwrap()
        })
        .collect()
}

#[test]
fn the_fixture_is_what_the_pinned_setup_computes() {
    let setup = TrustedSetup::load_pinned(setup_path(), BETA4_MAINNET_SHA256).unwrap();
    let mut extended = Vec::new();
    for position in UNIT_POSITIONS {
        let mut bytes = vec![0u8; BYTES_PER_BLOB];
        bytes[position * 32 + 31] = 1;
        let blob = Blob::from_bytes(&bytes).unwrap();
        extended.push(setup.compute_cells_and_kzg_proofs(&blob).unwrap());
    }
    let mut fixture = Vec::new();
    for column in COLUMNS {
        fixture.push(column);
        for (cells, proofs) in &extended {
            fixture.extend_from_slice(&cells[usize::from(column)].to_bytes());
            fixture.extend_from_slice(&proofs[usize::from(column)].to_bytes().into_inner());
        }
    }

    // The commitments from the setup file verify every column of both blobs.
    let commitments = commitments();
    for column in 0..CELLS_PER_EXT_BLOB {
        let cells: Vec<Cell> = extended.iter().map(|(c, _)| c[column]).collect();
        let proofs: Vec<Bytes48> = extended.iter().map(|(_, p)| p[column].to_bytes()).collect();
        let indices = vec![column as u64; cells.len()];
        let valid = setup
            .verify_cell_kzg_proof_batch(&commitments, &indices, &cells, &proofs)
            .unwrap();
        assert!(valid, "column {column}");
    }

    let path = manifest_dir().join("tests/fixtures/unit_blob_columns.bin");
    if std::env::var_os("REGEN_KZG_FIXTURE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &fixture).unwrap();
    }
    assert!(
        std::fs::read(&path).unwrap() == fixture,
        "{} is stale: regenerate it (see the module docs)",
        path.display()
    );
}
