//! PeerDAS cells: computation and batch proof verification.

use c_kzg::{Blob, Bytes48, Cell, KzgProof, CELLS_PER_EXT_BLOB};

use crate::TrustedSetup;

/// Why a cell operation failed. An `Err` is an invalid *input* (the spec's assertion failure);
/// a well-formed batch whose proofs do not check is `Ok(false)`.
#[derive(Debug, thiserror::Error)]
pub enum KzgError {
    #[error(
        "batch length mismatch: {commitments} commitments, {cell_indices} cell indices, \
         {cells} cells, {proofs} proofs"
    )]
    LengthMismatch {
        commitments: usize,
        cell_indices: usize,
        cells: usize,
        proofs: usize,
    },
    #[error("cell_indices[{position}] = {cell_index} is not below {CELLS_PER_EXT_BLOB}")]
    CellIndexOutOfRange { position: usize, cell_index: u64 },
    /// c-kzg refused the input: a non-canonical blob field element, or bytes that are not a
    /// valid compressed G1 point.
    #[error("c-kzg: {0}")]
    Backend(c_kzg::Error),
}

impl TrustedSetup {
    /// `compute_cells(blob)`: the blob's extension, as `CELLS_PER_EXT_BLOB` cells.
    pub fn compute_cells(&self, blob: &Blob) -> Result<Box<[Cell; CELLS_PER_EXT_BLOB]>, KzgError> {
        self.settings()
            .compute_cells(blob)
            .map_err(KzgError::Backend)
    }

    /// `compute_cells_and_kzg_proofs(blob)`: every cell of the extended blob with its proof.
    #[allow(clippy::type_complexity)]
    pub fn compute_cells_and_kzg_proofs(
        &self,
        blob: &Blob,
    ) -> Result<
        (
            Box<[Cell; CELLS_PER_EXT_BLOB]>,
            Box<[KzgProof; CELLS_PER_EXT_BLOB]>,
        ),
        KzgError,
    > {
        self.settings()
            .compute_cells_and_kzg_proofs(blob)
            .map_err(KzgError::Backend)
    }

    /// `verify_cell_kzg_proof_batch(commitments, cell_indices, cells, proofs)`: checks that
    /// `cells[i]` is cell `cell_indices[i]` of the blob committed to by `commitments[i]`, proven
    /// by `proofs[i]`.
    ///
    /// Before calling c-kzg this checks that all four slices have the same length
    /// ([`KzgError::LengthMismatch`]) and that every cell index is below `CELLS_PER_EXT_BLOB`
    /// ([`KzgError::CellIndexOutOfRange`]). Undecodable commitments or proofs are
    /// [`KzgError::Backend`].
    ///
    /// **An empty batch returns `Ok(true)`**, as in the spec (vector
    /// `verify_cell_kzg_proof_batch_case_valid_zero_cells`). Callers must not read `true` as
    /// "some column was verified".
    ///
    /// The cap on columns per call is the caller's (cl-verify's) policy, not enforced here.
    pub fn verify_cell_kzg_proof_batch(
        &self,
        commitments: &[Bytes48],
        cell_indices: &[u64],
        cells: &[Cell],
        proofs: &[Bytes48],
    ) -> Result<bool, KzgError> {
        let n = cells.len();
        if commitments.len() != n || cell_indices.len() != n || proofs.len() != n {
            return Err(KzgError::LengthMismatch {
                commitments: commitments.len(),
                cell_indices: cell_indices.len(),
                cells: n,
                proofs: proofs.len(),
            });
        }
        if let Some((position, &cell_index)) = cell_indices
            .iter()
            .enumerate()
            .find(|(_, &i)| i >= CELLS_PER_EXT_BLOB as u64)
        {
            return Err(KzgError::CellIndexOutOfRange {
                position,
                cell_index,
            });
        }
        if n == 0 {
            return Ok(true);
        }
        self.settings()
            .verify_cell_kzg_proof_batch(commitments, cell_indices, cells, proofs)
            .map_err(KzgError::Backend)
    }
}
