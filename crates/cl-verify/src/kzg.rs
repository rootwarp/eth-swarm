//! KZG cell-proof batch verification through `crypto-kzg`.
//!
//! The only setup this crate can use is a [`crypto_kzg::TrustedSetup`] from
//! [`TrustedSetup::load_pinned`] under [`BETA4_MAINNET_SHA256`], the consensus-specs
//! `v1.7.0-beta.4` mainnet setup; any other file is refused before it is parsed. The digest is
//! fixed here, not configurable. cl-verify has no c-kzg dependency and no loader of its own.

use std::path::PathBuf;

use crypto_kzg::{
    BackendError, Bytes48, Cell, KzgError, SetupError, TrustedSetup, BETA4_MAINNET_SHA256,
    BYTES_PER_CELL, BYTES_PER_COMMITMENT, BYTES_PER_PROOF,
};

use crate::proto::common::{Error, ErrorCode};
use crate::proto::verify::{KzgCellProof, VerifyStatus};
use crate::wire::wire_error;

/// `NUMBER_OF_COLUMNS` (fulu/das-core.md); a `cell_index` must be below it.
pub const NUMBER_OF_COLUMNS: u64 = 128;

/// Where the trusted setup lives. Its sha256 must be [`BETA4_MAINNET_SHA256`].
#[derive(Clone, Debug)]
pub struct TrustedSetupConfig {
    pub path: PathBuf,
}

/// Why the backend gave no verdict.
#[derive(Debug, PartialEq, Eq)]
pub enum KzgFailure {
    /// A commitment or proof is not a valid point, or an argument is malformed.
    BadInput,
    /// The library failed for a reason unrelated to the input.
    Internal(String),
}

/// Request cells decoded into fixed-size types; parallel arrays, one entry per cell. Built only by
/// [`prepare_cells`], after every length and index has been checked.
pub struct PreparedCells {
    commitments: Vec<Bytes48>,
    cell_indices: Vec<u64>,
    cells: Vec<Cell>,
    proofs: Vec<Bytes48>,
}

impl PreparedCells {
    #[must_use]
    pub fn commitments(&self) -> &[Bytes48] {
        &self.commitments
    }
    #[must_use]
    pub fn cell_indices(&self) -> &[u64] {
        &self.cell_indices
    }
    #[must_use]
    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }
    #[must_use]
    pub fn proofs(&self) -> &[Bytes48] {
        &self.proofs
    }
}

mod backend {
    use super::{KzgFailure, PreparedCells};

    /// The batch check behind [`super::verify_cells`]; injected so tests can stand in a failing
    /// verifier.
    pub trait KzgBackend: Send + Sync + 'static {
        fn verify(&self, cells: &PreparedCells) -> Result<bool, KzgFailure>;
    }
}

/// Nameable (so implementable) outside this crate only with the `test-backends` feature; without
/// it the only implementation is [`PinnedKzgBackend`].
#[cfg(any(test, feature = "test-backends"))]
pub use backend::KzgBackend;
#[cfg(not(any(test, feature = "test-backends")))]
pub(crate) use backend::KzgBackend;

/// `verify_cell_kzg_proof_batch` over the digest-pinned trusted setup.
pub struct PinnedKzgBackend {
    setup: TrustedSetup,
}

impl PinnedKzgBackend {
    /// Loads the setup at `config.path`, refusing it unless its sha256 is
    /// [`BETA4_MAINNET_SHA256`]. On a mismatch nothing is parsed and c-kzg is not called.
    pub fn load(config: &TrustedSetupConfig) -> Result<Self, SetupError> {
        Ok(Self {
            setup: TrustedSetup::load_pinned(&config.path, BETA4_MAINNET_SHA256)?,
        })
    }
}

impl KzgBackend for PinnedKzgBackend {
    fn verify(&self, c: &PreparedCells) -> Result<bool, KzgFailure> {
        self.setup
            .verify_cell_kzg_proof_batch(&c.commitments, &c.cell_indices, &c.cells, &c.proofs)
            .map_err(classify)
    }
}

fn classify(err: KzgError) -> KzgFailure {
    match err {
        KzgError::LengthMismatch { .. } | KzgError::CellIndexOutOfRange { .. } => {
            KzgFailure::BadInput
        }
        KzgError::Backend(e) => classify_backend(e),
    }
}

fn classify_backend(err: BackendError) -> KzgFailure {
    match err {
        BackendError::InvalidBytesLength(_)
        | BackendError::InvalidKzgProof(_)
        | BackendError::InvalidKzgCommitment(_)
        | BackendError::MismatchLength(_) => KzgFailure::BadInput,
        // `C_KZG_RET` is not re-exported by crypto-kzg; its Debug form is the C enum name.
        BackendError::CError(ret) if format!("{ret:?}") == "C_KZG_BADARGS" => KzgFailure::BadInput,
        other => KzgFailure::Internal(other.to_string()),
    }
}

/// Decodes the request cells. Every length and `cell_index` is checked before anything is
/// allocated, so a request of many tiny malformed cells never reserves `BYTES_PER_CELL` per entry.
/// A wrong length or an index `>= NUMBER_OF_COLUMNS` is `DECODE_ERROR`.
pub fn prepare_cells(cells: &[KzgCellProof]) -> Result<PreparedCells, VerifyStatus> {
    let well_formed = cells.iter().all(|c| {
        c.cell_index < NUMBER_OF_COLUMNS
            && c.commitment.len() == BYTES_PER_COMMITMENT
            && c.cell.len() == BYTES_PER_CELL
            && c.proof.len() == BYTES_PER_PROOF
    });
    if !well_formed {
        return Err(VerifyStatus::DecodeError);
    }
    let decode = |_| VerifyStatus::DecodeError;
    let mut out = PreparedCells {
        commitments: Vec::with_capacity(cells.len()),
        cell_indices: Vec::with_capacity(cells.len()),
        cells: Vec::with_capacity(cells.len()),
        proofs: Vec::with_capacity(cells.len()),
    };
    for c in cells {
        out.commitments
            .push(Bytes48::from_bytes(&c.commitment).map_err(decode)?);
        out.cells.push(Cell::from_bytes(&c.cell).map_err(decode)?);
        out.proofs
            .push(Bytes48::from_bytes(&c.proof).map_err(decode)?);
        out.cell_indices.push(c.cell_index);
    }
    Ok(out)
}

/// Batch verdict for `cells`: VALID only if every cell verifies. An `Error` is returned only when
/// there is no verdict; its status is then `OVERLOADED` (core unavailable), never VALID. The
/// server refuses an empty request before it gets here (see [`crate::caps::check_kzg`]).
pub fn verify_cells(
    cells: &[KzgCellProof],
    backend: &dyn KzgBackend,
) -> (VerifyStatus, Option<Error>) {
    let prepared = match prepare_cells(cells) {
        Ok(p) => p,
        Err(status) => return (status, None),
    };
    match backend.verify(&prepared) {
        Ok(true) => (VerifyStatus::Valid, None),
        Ok(false) => (VerifyStatus::Invalid, None),
        Err(KzgFailure::BadInput) => (VerifyStatus::DecodeError, None),
        Err(KzgFailure::Internal(detail)) => unavailable(&detail),
    }
}

/// The no-verdict answer: `OVERLOADED` plus `ERROR_CODE_RESOURCE_UNAVAILABLE`.
#[must_use]
pub fn unavailable(detail: &str) -> (VerifyStatus, Option<Error>) {
    (
        VerifyStatus::Overloaded,
        Some(wire_error(ErrorCode::ResourceUnavailable, detail)),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// crypto-kzg's vendored consensus-specs v1.7.0-beta.4 mainnet setup.
    pub(crate) fn setup_config() -> TrustedSetupConfig {
        TrustedSetupConfig {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../crypto-kzg/data/trusted_setup_4096.json"),
        }
    }

    fn backend() -> &'static PinnedKzgBackend {
        static B: OnceLock<PinnedKzgBackend> = OnceLock::new();
        B.get_or_init(|| PinnedKzgBackend::load(&setup_config()).unwrap())
    }

    fn cell(index: u64) -> KzgCellProof {
        KzgCellProof {
            commitment: [&[0xc0u8][..], &[0u8; 47][..]].concat(),
            cell_index: index,
            cell: vec![0; 2048],
            proof: [&[0xc0u8][..], &[0u8; 47][..]].concat(),
        }
    }

    #[test]
    fn only_the_beta4_mainnet_setup_loads() {
        assert!(PinnedKzgBackend::load(&setup_config()).is_ok());

        let mut bytes = std::fs::read(setup_config().path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x20;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trusted_setup_4096.json");
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            PinnedKzgBackend::load(&TrustedSetupConfig { path }),
            Err(SetupError::DigestMismatch { expected, .. }) if expected == BETA4_MAINNET_SHA256
        ));
    }

    #[test]
    fn zero_polynomial_cell_verifies_against_the_pinned_setup() {
        // Commitment and proof at infinity open the all-zero cell: a valid identity case.
        assert_eq!(
            verify_cells(&[cell(0), cell(127)], backend()),
            (VerifyStatus::Valid, None)
        );
    }

    #[test]
    fn wrong_lengths_and_out_of_range_index_are_decode_errors() {
        let mut short_commitment = cell(0);
        short_commitment.commitment.pop();
        let mut short_cell = cell(0);
        short_cell.cell.pop();
        let mut long_proof = cell(0);
        long_proof.proof.push(0);
        let mut empty_proof = cell(0);
        empty_proof.proof.clear();
        for bad in [
            short_commitment,
            short_cell,
            long_proof,
            empty_proof,
            cell(128),
        ] {
            assert_eq!(
                verify_cells(&[cell(1), bad], backend()),
                (VerifyStatus::DecodeError, None)
            );
        }
    }

    #[test]
    fn invalid_point_is_a_decode_error_and_wrong_proof_is_invalid() {
        let mut not_on_curve = cell(0);
        not_on_curve.commitment = vec![0xff; 48];
        assert_eq!(
            verify_cells(&[not_on_curve], backend()),
            (VerifyStatus::DecodeError, None)
        );
        let mut nonzero_cell = cell(3);
        nonzero_cell.cell[31] = 1;
        assert_eq!(
            verify_cells(&[nonzero_cell], backend()),
            (VerifyStatus::Invalid, None)
        );
    }

    #[test]
    fn internal_failure_is_an_error_never_a_verdict() {
        struct Broken;
        impl KzgBackend for Broken {
            fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
                Err(KzgFailure::Internal("c-kzg malloc".into()))
            }
        }
        let (status, err) = verify_cells(&[cell(0)], &Broken);
        assert_ne!(status, VerifyStatus::Valid);
        assert_ne!(status, VerifyStatus::Unspecified);
        assert_eq!(err.unwrap().code(), ErrorCode::ResourceUnavailable);
    }

    #[test]
    fn crypto_kzg_errors_are_classified() {
        assert_eq!(
            classify(KzgError::CellIndexOutOfRange {
                position: 0,
                cell_index: 128
            }),
            KzgFailure::BadInput
        );
        assert_eq!(
            classify(KzgError::Backend(BackendError::InvalidBytesLength(
                "x".into()
            ))),
            KzgFailure::BadInput
        );
        assert!(matches!(
            classify(KzgError::Backend(BackendError::InvalidTrustedSetup(
                "x".into()
            ))),
            KzgFailure::Internal(_)
        ));
    }
}
