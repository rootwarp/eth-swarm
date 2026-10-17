//! VerifyKzg over a real tonic server, with cryptography-specs v0.1.0 `verify_cell_kzg_proof_batch`
//! cases (see tests/fixtures/README.md) and the trusted setup loaded only through crypto-kzg's
//! digest-pinned loader.

mod common;

use cl_verify::caps::MAX_KZG_COLUMNS;
use cl_verify::feed::SharedCache;
use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::{KzgCellProof, VerifyKzgRequestBody, VerifyStatus};
use cl_verify::server::{Limits, VerifyServer};
use common::*;

#[test]
fn production_server_loads_only_the_pinned_setup() {
    let good = config(my_uid(), Limits::default());
    assert!(VerifyServer::new(good, SharedCache::default()).is_ok());
    let dir = tempfile::tempdir().unwrap();
    let mut swapped = config(my_uid(), Limits::default());
    swapped.trusted_setup = tampered_setup(dir.path());
    assert!(matches!(
        VerifyServer::new(swapped, SharedCache::default()),
        Err(crypto_kzg::SetupError::DigestMismatch { .. })
    ));
}

fn cells_of(case: &str) -> (Vec<KzgCellProof>, String) {
    let f = read_fixture(&format!(
        "cryptography-specs/verify_cell_kzg_proof_batch/verify_cell_kzg_proof_batch_case_{case}/data.yaml"
    ));
    let commitments = hexes(&f, "commitments");
    let cells = hexes(&f, "cells");
    let proofs = hexes(&f, "proofs");
    let indices: Vec<u64> = f["cell_indices"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(commitments.len(), cells.len());
    assert_eq!(indices.len(), cells.len());
    let out = (0..cells.len())
        .map(|i| KzgCellProof {
            commitment: commitments[i].clone(),
            cell_index: indices[i],
            cell: cells[i].clone(),
            proof: proofs[i].clone(),
        })
        .collect();
    (out, output(&f))
}

#[tokio::test]
async fn verify_cell_kzg_proof_batch_cases() {
    let cases = [
        ("valid_multiple_blobs", VerifyStatus::Valid),
        ("valid_not_sorted", VerifyStatus::Valid),
        ("incorrect_cell", VerifyStatus::Invalid),
        ("incorrect_proof", VerifyStatus::Invalid),
        ("incorrect_commitment", VerifyStatus::Invalid),
        ("invalid_commitment_0", VerifyStatus::DecodeError),
        ("invalid_proof_0", VerifyStatus::DecodeError),
        ("invalid_cell_0", VerifyStatus::DecodeError),
        ("invalid_cell_index", VerifyStatus::DecodeError),
    ];
    let mut h = start().await;
    let mut s = kzg_open(&mut h).await;
    for (id, (case, want)) in cases.iter().enumerate() {
        let (cells, expected) = cells_of(case);
        let spec = match expected.as_str() {
            "true" => VerifyStatus::Valid,
            "false" => VerifyStatus::Invalid,
            _ => VerifyStatus::DecodeError,
        };
        assert_eq!(spec, *want, "{case}: fixture output {expected}");
        s.send(kzg_body(VerifyKzgRequestBody {
            request_id: id as u64,
            cells,
            deadline_unix_ms: far_deadline(),
        }))
        .await;
        let r = kzg_reply(&mut s).await;
        assert_eq!(r.request_id, id as u64);
        assert_eq!(VerifyStatus::try_from(r.status), Ok(*want), "{case}");
        assert_eq!(r.err, None, "{case}");
    }
}

#[tokio::test]
async fn empty_request_is_a_contract_violation_never_valid() {
    // The fixture expects `true` for zero cells; on the wire that would be an ACCEPT with no
    // pairing check, so the server refuses it.
    let (cells, expected) = cells_of("valid_zero_cells");
    assert_eq!((cells.len(), expected.as_str()), (0, "true"));
    let mut h = start().await;
    let mut s = kzg_open(&mut h).await;
    s.send(kzg_body(VerifyKzgRequestBody {
        request_id: 1,
        cells,
        deadline_unix_ms: far_deadline(),
    }))
    .await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn cell_count_over_one_block_is_refused() {
    // hello() schedules at most 21 blobs per block: 128 * 21 cells is the cap.
    let max = MAX_KZG_COLUMNS * 21;
    let cell = |i: usize| KzgCellProof {
        commitment: vec![],
        cell_index: (i % MAX_KZG_COLUMNS) as u64,
        cell: vec![],
        proof: vec![],
    };
    let mut h = start().await;
    let mut s = kzg_open(&mut h).await;
    s.send(kzg_body(VerifyKzgRequestBody {
        request_id: 1,
        cells: (0..max).map(cell).collect(),
        deadline_unix_ms: far_deadline(),
    }))
    .await;
    assert_eq!(
        kzg_reply(&mut s).await.status,
        VerifyStatus::DecodeError as i32
    );
    s.send(kzg_body(VerifyKzgRequestBody {
        request_id: 2,
        cells: (0..=max).map(cell).collect(),
        deadline_unix_ms: far_deadline(),
    }))
    .await;
    let err = s.expect_failure().await;
    assert_eq!(err.code(), ErrorCode::ContractViolation);
    assert!(err.detail.contains("cells"), "{}", err.detail);
}
