//! Cell computation and batch verification.

mod common;

use common::{cells_case, setup};
use crypto_kzg::{Blob, Bytes48, Cell, KzgError, BYTES_PER_BLOB, CELLS_PER_EXT_BLOB};

/// A blob whose first field element is not below the BLS modulus.
fn non_canonical_blob() -> Blob {
    Blob::new([0xff; BYTES_PER_BLOB])
}

#[test]
fn batch_edges() {
    let setup = setup();
    let case = cells_case();
    let c = [case.commitment];
    let cell = [case.cells[3]];
    let proof = [case.proofs[3]];
    let one = [3u64];

    // The single-cell batch is valid, so every failure below comes from the edge itself.
    assert!(setup
        .verify_cell_kzg_proof_batch(&c, &one, &cell, &proof)
        .unwrap());

    let two_c = [c[0], c[0]];
    let two_i = [3u64, 3];
    let two_cell = [cell[0], cell[0]];
    let two_p = [proof[0], proof[0]];
    for (commitments, indices, cells, proofs) in [
        (&two_c[..], &one[..], &cell[..], &proof[..]),
        (&c[..], &two_i[..], &cell[..], &proof[..]),
        (&c[..], &one[..], &two_cell[..], &proof[..]),
        (&c[..], &one[..], &cell[..], &two_p[..]),
        (&[][..], &one[..], &cell[..], &proof[..]),
    ] {
        let err = setup
            .verify_cell_kzg_proof_batch(commitments, indices, cells, proofs)
            .unwrap_err();
        assert!(
            matches!(
                err,
                KzgError::LengthMismatch { commitments: a, cell_indices: b, cells: c, proofs: d }
                    if (a, b, c, d) == (commitments.len(), indices.len(), cells.len(), proofs.len())
            ),
            "{err:?}"
        );
    }

    for bad in [CELLS_PER_EXT_BLOB as u64, u64::MAX] {
        let indices = [3, bad];
        let err = setup
            .verify_cell_kzg_proof_batch(&two_c, &indices, &two_cell, &two_p)
            .unwrap_err();
        assert!(
            matches!(err, KzgError::CellIndexOutOfRange { position: 1, cell_index } if cell_index == bad),
            "{err:?}"
        );
    }

    // Empty batch: true, as in the spec (`verify_cell_kzg_proof_batch_case_valid_zero_cells`).
    assert!(setup
        .verify_cell_kzg_proof_batch(&[], &[], &[], &[])
        .unwrap());
}

#[test]
fn batch_rejects_undecodable_points() {
    let setup = setup();
    let case = cells_case();
    // 0xff.. is not a compressed G1 point: an input error, not a failed check.
    let bogus = [Bytes48::new([0xff; 48])];
    let err = setup
        .verify_cell_kzg_proof_batch(&bogus, &[0], &case.cells[..1], &case.proofs[..1])
        .unwrap_err();
    assert!(matches!(err, KzgError::Backend(_)), "{err:?}");
    assert!(err.to_string().starts_with("c-kzg: "), "{err}");
}

#[test]
fn batch_with_wrong_index_fails() {
    let setup = setup();
    let case = cells_case();
    assert!(!setup
        .verify_cell_kzg_proof_batch(
            &[case.commitment],
            &[4],
            &case.cells[3..4],
            &case.proofs[3..4]
        )
        .unwrap());
}

#[test]
fn compute_cells_matches_vector() {
    let case = cells_case();
    let cells: Box<[Cell; CELLS_PER_EXT_BLOB]> = setup().compute_cells(&case.blob).unwrap();
    assert_eq!(cells.as_slice(), case.cells.as_slice());
}

#[test]
fn non_canonical_blob_is_an_error() {
    let setup = setup();
    assert!(matches!(
        setup.compute_cells(&non_canonical_blob()),
        Err(KzgError::Backend(_))
    ));
    assert!(matches!(
        setup.compute_cells_and_kzg_proofs(&non_canonical_blob()),
        Err(KzgError::Backend(_))
    ));
}
