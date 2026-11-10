//! KZG cell-proof batch verification through `crypto-kzg`.
//!
//! The only setup this crate can use is a [`crypto_kzg::TrustedSetup`] from
//! [`TrustedSetup::load_pinned`] under [`BETA4_MAINNET_SHA256`], the consensus-specs
//! `v1.7.0-beta.4` mainnet setup; any other file is refused before it is parsed. The digest is
//! fixed here, not configurable. cl-verify has no c-kzg dependency and no loader of its own.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use crypto_kzg::{
    BackendError, Bytes48, Cell, KzgError, SetupError, TrustedSetup, BETA4_MAINNET_SHA256,
    BYTES_PER_CELL, BYTES_PER_COMMITMENT, BYTES_PER_PROOF,
};

use crate::proto::common::{Error, ErrorCode};
use crate::proto::verify::{KzgCellProof, VerifyStatus};
use crate::wire::{wire_error, Deadline, WallClock};

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

/// What [`verify_columns`] found for one column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnVerdict {
    /// Every cell of the column verifies.
    Valid,
    /// At least one cell of the column does not.
    Invalid,
    /// A cell of the column has a wrong length or a `cell_index >= NUMBER_OF_COLUMNS`; the column
    /// is not verified.
    DecodeError,
}

/// The verdict for one column of a request: the cells that share `cell_index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnResult {
    pub cell_index: u64,
    pub verdict: ColumnVerdict,
}

/// Per-column verdicts for `cells`, one per distinct `cell_index` in order of first appearance.
pub fn verify_columns(
    cells: &[KzgCellProof],
    backend: &dyn KzgBackend,
) -> Result<Vec<ColumnResult>, KzgFailure> {
    let _ = (cells, backend);
    todo!("verify_columns")
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

/// [`verify_cells`] for a job admitted with `deadline`, run on a blocking thread: `None` if its
/// stream closed before it ran (nothing is answered), `DEADLINE_EXCEEDED` with no KZG work if the
/// deadline is no longer open on both clocks (the job may have waited for a thread past it, and a
/// wall clock that steps backwards cannot reopen it).
pub fn verify_cells_gated(
    cells: &[KzgCellProof],
    deadline: &Deadline,
    closed: &AtomicBool,
    clock: &dyn WallClock,
    backend: &dyn KzgBackend,
) -> Option<(VerifyStatus, Option<Error>)> {
    if closed.load(Ordering::SeqCst) {
        return None;
    }
    if !deadline.open(clock) {
        return Some((VerifyStatus::DeadlineExceeded, None));
    }
    Some(verify_cells(cells, backend))
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

    /// Counts the batches it is asked to verify; every one verifies.
    #[derive(Default)]
    struct Counting(std::sync::atomic::AtomicUsize);
    impl KzgBackend for Counting {
        fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }
    }

    /// A wall clock the test sets by hand.
    struct Manual(std::sync::atomic::AtomicU64);
    impl WallClock for Manual {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_monotonic_deadline_past_stops_the_job_though_the_wall_clock_stepped_back() {
        use std::sync::atomic::Ordering;
        let clock = Manual(std::sync::atomic::AtomicU64::new(1_000));
        let deadline = Deadline::new(1_010, &clock).unwrap();
        let open = AtomicBool::new(false);
        let counting = Counting::default();
        assert_eq!(
            verify_cells_gated(&[cell(0)], &deadline, &open, &clock, &counting),
            Some((VerifyStatus::Valid, None))
        );
        // The job then waits for a blocking thread past its monotonic deadline, and the wall
        // clock steps back meanwhile: the wire deadline alone would still look open.
        tokio::time::advance(std::time::Duration::from_millis(20)).await;
        clock.0.store(500, Ordering::SeqCst);
        assert_eq!(
            verify_cells_gated(&[cell(0)], &deadline, &open, &clock, &counting),
            Some((VerifyStatus::DeadlineExceeded, None))
        );
        assert_eq!(counting.0.load(Ordering::SeqCst), 1, "no KZG work after it");
        let closed = AtomicBool::new(true);
        assert_eq!(
            verify_cells_gated(&[cell(0)], &deadline, &closed, &clock, &counting),
            None,
            "a closed stream answers nothing"
        );
    }

    /// A batch verifies unless it holds a cell of a `bad` column. Records the `cell_index` of
    /// every cell of every batch it is asked to verify.
    struct BadColumns {
        bad: Vec<u64>,
        calls: std::sync::Mutex<Vec<Vec<u64>>>,
    }

    impl BadColumns {
        fn new(bad: impl IntoIterator<Item = u64>) -> Self {
            Self {
                bad: bad.into_iter().collect(),
                calls: std::sync::Mutex::default(),
            }
        }
        fn calls(&self) -> Vec<Vec<u64>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl KzgBackend for BadColumns {
        fn verify(&self, c: &PreparedCells) -> Result<bool, KzgFailure> {
            self.calls.lock().unwrap().push(c.cell_indices().to_vec());
            Ok(!c.cell_indices().iter().any(|i| self.bad.contains(i)))
        }
    }

    fn results(order: impl IntoIterator<Item = u64>, invalid: &[u64]) -> Vec<ColumnResult> {
        order
            .into_iter()
            .map(|cell_index| ColumnResult {
                cell_index,
                verdict: if invalid.contains(&cell_index) {
                    ColumnVerdict::Invalid
                } else {
                    ColumnVerdict::Valid
                },
            })
            .collect()
    }

    #[test]
    fn a_valid_request_is_one_batch_call() {
        let cells: Vec<_> = (0..128).rev().chain(0..128).map(cell).collect();
        let backend = BadColumns::new([]);
        assert_eq!(
            verify_columns(&cells, &backend),
            Ok(results((0..128).rev(), &[]))
        );
        let calls = backend.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 256, "every cell, flattened");
    }

    #[test]
    fn every_invalid_column_is_named() {
        // Two blobs per column; the columns first appear in reverse order.
        let cells: Vec<_> = (0..128).rev().chain(0..128).map(cell).collect();
        let bad = [0, 41, 42, 127];
        let backend = BadColumns::new(bad);
        assert_eq!(
            verify_columns(&cells, &backend),
            Ok(results((0..128).rev(), &bad))
        );
        let calls = backend.calls();
        assert_eq!(calls[0].len(), 256, "the whole request first");
        assert!(calls.len() > 1, "then a bisect");
        for call in &calls[1..] {
            assert!(call.len() < 256);
            for index in call {
                let n = call.iter().filter(|i| *i == index).count();
                assert_eq!(n, 2, "column {index} is checked whole: {call:?}");
            }
        }
    }

    #[test]
    fn malformed_columns_are_decode_errors_and_the_rest_are_verified() {
        let mut short = cell(5);
        short.cell.pop();
        let cells = [cell(1), short, cell(5), cell(200), cell(3)];
        let backend = BadColumns::new([3]);
        let mut want = results([1, 5, 200, 3], &[3]);
        want[1].verdict = ColumnVerdict::DecodeError;
        want[2].verdict = ColumnVerdict::DecodeError;
        assert_eq!(verify_columns(&cells, &backend), Ok(want));
        assert_eq!(
            backend.calls()[0],
            [1, 3],
            "one call over the well-formed columns"
        );
        // The batch status does no KZG work for a request with a malformed cell.
        let backend = BadColumns::new([]);
        assert_eq!(
            verify_cells(&cells, &backend),
            (VerifyStatus::DecodeError, None)
        );
        assert!(backend.calls().is_empty());
    }

    #[test]
    fn the_batch_status_is_valid_only_if_every_column_is() {
        let cells: Vec<_> = (0..8).map(cell).collect();
        assert_eq!(
            verify_cells(&cells, &BadColumns::new([])),
            (VerifyStatus::Valid, None)
        );
        assert_eq!(
            verify_cells(&cells, &BadColumns::new([6])),
            (VerifyStatus::Invalid, None)
        );
    }

    #[test]
    fn a_backend_error_in_the_bisect_is_no_verdict() {
        /// The whole batch fails; every later call fails inside the library.
        #[derive(Default)]
        struct FailsThenBreaks(std::sync::atomic::AtomicUsize);
        impl KzgBackend for FailsThenBreaks {
            fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
                match self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                    0 => Ok(false),
                    _ => Err(KzgFailure::Internal("c-kzg malloc".into())),
                }
            }
        }
        let cells: Vec<_> = (0..4).map(cell).collect();
        assert_eq!(
            verify_columns(&cells, &FailsThenBreaks::default()),
            Err(KzgFailure::Internal("c-kzg malloc".into()))
        );
        let (status, err) = verify_cells(&cells, &FailsThenBreaks::default());
        assert_eq!(status, VerifyStatus::Overloaded);
        assert_eq!(err.unwrap().code(), ErrorCode::ResourceUnavailable);
    }

    /// Fails every batch. Its first call steps the wall clock past the deadline or closes the
    /// stream.
    struct FailsAndStops {
        clock: std::sync::Arc<Manual>,
        closed: std::sync::Arc<AtomicBool>,
        close: bool,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl KzgBackend for FailsAndStops {
        fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.close {
                self.closed.store(true, Ordering::SeqCst);
            } else {
                self.clock.0.store(u64::MAX, Ordering::SeqCst);
            }
            Ok(false)
        }
    }

    #[test]
    fn the_bisect_stops_once_the_deadline_passes_or_the_stream_closes() {
        let cells: Vec<_> = (0..16).map(cell).collect();
        for close in [false, true] {
            let backend = FailsAndStops {
                clock: std::sync::Arc::new(Manual(std::sync::atomic::AtomicU64::new(1_000))),
                closed: std::sync::Arc::default(),
                close,
                calls: std::sync::atomic::AtomicUsize::new(0),
            };
            let (clock, closed) = (backend.clock.as_ref(), backend.closed.as_ref());
            let deadline = Deadline::new(60_000, clock).unwrap();
            let got = verify_cells_gated(&cells, &deadline, closed, clock, &backend);
            let want = (!close).then_some((VerifyStatus::DeadlineExceeded, None));
            assert_eq!(got, want, "close: {close}");
            assert_eq!(
                backend.calls.load(Ordering::SeqCst),
                1,
                "no KZG work after the first batch"
            );
        }
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
