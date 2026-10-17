//! Fixtures shared by the integration tests: the vendored beta.4 setup and one vector case.
#![allow(dead_code)] // each test binary uses a different subset

use std::sync::OnceLock;

use crypto_kzg::{Blob, Bytes48, Cell, TrustedSetup, CELLS_PER_EXT_BLOB};
use sha2::{Digest, Sha256};

/// consensus-specs `v1.7.0-beta.4` `presets/mainnet/trusted_setups/trusted_setup_4096.json`.
pub const SETUP_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/trusted_setup_4096.json");
/// sha256 of [`SETUP_PATH`].
pub const SETUP_SHA256_HEX: &str =
    "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f";

/// cryptography-specs `v0.1.0` `tests.zip` (sha256
/// `eeb4893eb544f770810d9499007ebb0b9319431ea412bd54736e1c274da3d037`), member
/// `tests/kzg/compute_cells_and_kzg_proofs/compute_cells_and_kzg_proofs_case_valid_2/data.yaml`.
pub const CASE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/compute_cells_and_kzg_proofs_case_valid_2/data.yaml"
);
/// sha256 of [`CASE_PATH`].
pub const CASE_SHA256_HEX: &str =
    "01b67888b5f232b1e0577b6c39632dc9117cdb39ccdc12b2fe63e7aaa92c4ba4";
/// Commitment to the same blob, the `output` of the same archive's
/// `tests/kzg/blob_to_kzg_commitment/blob_to_kzg_commitment_case_valid_blob_2/data.yaml`.
pub const CASE_COMMITMENT_HEX: &str = "a421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06";

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn digest_from_hex(digest: &str) -> [u8; 32] {
    hex::decode(digest)
        .expect("hex digest")
        .try_into()
        .expect("32-byte digest")
}

pub fn setup_sha256() -> [u8; 32] {
    digest_from_hex(SETUP_SHA256_HEX)
}

/// The vendored setup, loaded once per test binary.
pub fn setup() -> &'static TrustedSetup {
    static SETUP: OnceLock<TrustedSetup> = OnceLock::new();
    SETUP.get_or_init(|| {
        TrustedSetup::load_pinned(SETUP_PATH, setup_sha256()).expect("vendored setup loads")
    })
}

/// One `compute_cells_and_kzg_proofs` case: input blob and the expected cells and proofs.
pub struct CellsCase {
    pub blob: Blob,
    pub commitment: Bytes48,
    pub cells: Vec<Cell>,
    pub proofs: Vec<Bytes48>,
}

/// Parses the vendored case. The file is spec-generated YAML of a fixed shape (`input.blob`, then
/// `output: [cells, proofs]`), so the hex scalars are taken in document order.
pub fn cells_case() -> CellsCase {
    let text = std::fs::read(CASE_PATH).expect("vendored case");
    assert_eq!(
        sha256(&text),
        digest_from_hex(CASE_SHA256_HEX),
        "vendored case digest"
    );
    let text = String::from_utf8(text).expect("utf-8");
    let scalars: Vec<&str> = text
        .split('\'')
        .filter(|s| s.starts_with("0x"))
        .map(|s| &s[2..])
        .collect();
    assert_eq!(
        scalars.len(),
        1 + 2 * CELLS_PER_EXT_BLOB,
        "blob + cells + proofs"
    );
    let (blob, rest) = scalars.split_first().unwrap();
    let (cells, proofs) = rest.split_at(CELLS_PER_EXT_BLOB);
    CellsCase {
        blob: Blob::from_hex(blob).expect("blob"),
        commitment: Bytes48::from_hex(CASE_COMMITMENT_HEX).expect("commitment"),
        cells: cells
            .iter()
            .map(|c| Cell::from_hex(c).expect("cell"))
            .collect(),
        proofs: proofs
            .iter()
            .map(|p| Bytes48::from_hex(p).expect("proof"))
            .collect(),
    }
}
