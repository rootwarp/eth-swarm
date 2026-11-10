//! kzg: VerifyKzg as per-column batch verification over the pinned trusted setup. A request's
//! cells are flattened into one `verify_cell_kzg_proof_batch` call; only a batch that fails is
//! bisected by column (the cells that share a `cell_index`), so the invalid column is named. A
//! request over 128 columns or 8 MiB is refused before any KZG work.

mod common;

use std::sync::{Arc, Mutex};

use cl_verify::caps::{MAX_KZG_COLUMNS, MAX_KZG_MESSAGE_BYTES, MAX_MESSAGE_BYTES};
use cl_verify::kzg::{
    verify_cells, verify_columns, ColumnResult, ColumnVerdict, KzgBackend, KzgFailure,
    PreparedCells,
};
use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::{KzgCellProof, VerifyStatus};
use common::*;
use prost::Message;

/// The pinned backend, recording the `cell_index` of every cell of every batch it verifies.
#[derive(Default)]
struct Recording(Mutex<Vec<Vec<u64>>>);

impl Recording {
    fn calls(&self) -> Vec<Vec<u64>> {
        self.0.lock().unwrap().clone()
    }
}

impl KzgBackend for Recording {
    fn verify(&self, cells: &PreparedCells) -> Result<bool, KzgFailure> {
        self.0.lock().unwrap().push(cells.cell_indices().to_vec());
        kzg_backend().verify(cells)
    }
}

async fn recorded() -> (Harness, Arc<Recording>) {
    let recording = Arc::new(Recording::default());
    let h = start_with(Options {
        kzg: recording.clone(),
        ..Options::default()
    })
    .await;
    (h, recording)
}

/// `order` as column results, `Invalid` for the columns in `invalid` and `Valid` for the rest.
fn columns(order: impl IntoIterator<Item = u64>, invalid: &[u64]) -> Vec<ColumnResult> {
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

/// One blob's cells at columns 3, 2, 0 and 1, a second blob's cell at column 0, and zero cells
/// at columns `4..last`.
fn fixture_batch(last: u64) -> Vec<KzgCellProof> {
    let (mut cells, out) = kzg_case("valid_not_sorted");
    assert_eq!(out, "true");
    let (more, out) = kzg_case("valid_multiple_blobs");
    assert_eq!(out, "true");
    cells.extend(more);
    cells.extend((4..last).map(zero_cell));
    cells
}

fn sorted(mut v: Vec<u64>) -> Vec<u64> {
    v.sort_unstable();
    v
}

#[test]
fn batch_valid() {
    let cells = fixture_batch(8);
    let backend = Recording::default();
    assert_eq!(
        verify_columns(&cells, &backend),
        Ok(columns([3, 2, 0, 1, 4, 5, 6, 7], &[]))
    );
    let calls = backend.calls();
    assert_eq!(calls.len(), 1, "one batch call, no bisect");
    assert_eq!(
        sorted(calls[0].clone()),
        sorted(cells.iter().map(|c| c.cell_index).collect()),
        "over every cell of the request"
    );
    assert_eq!(verify_cells(&cells, &backend), (VerifyStatus::Valid, None));
    assert_eq!(backend.calls().len(), 2);
}

#[test]
fn one_invalid_named() {
    let mut cells = fixture_batch(16);
    // Column 2 carries the cell of column 3: well-formed, but not the blob's cell at index 2.
    assert_eq!((cells[0].cell_index, cells[1].cell_index), (3, 2));
    cells[1].cell = cells[0].cell.clone();
    let backend = Recording::default();
    let order = [3, 2, 0, 1].into_iter().chain(4..16);
    assert_eq!(
        verify_columns(&cells, &backend),
        Ok(columns(order, &[2])),
        "only the planted column is invalid"
    );
    let calls = backend.calls();
    assert_eq!(calls[0].len(), cells.len(), "the whole request first");
    // 16 columns: at most two calls per halving, four halvings.
    assert!(
        calls.len() > 1 && calls.len() <= 1 + 2 * 4,
        "a bisect by column: {} calls",
        calls.len()
    );
    for call in &calls[1..] {
        for index in call {
            let whole = cells.iter().filter(|c| c.cell_index == *index).count();
            let here = call.iter().filter(|i| *i == index).count();
            assert_eq!(here, whole, "column {index} is checked whole");
        }
    }
    assert_eq!(
        verify_cells(&cells, kzg_backend().as_ref()),
        (VerifyStatus::Invalid, None)
    );
}

#[tokio::test]
async fn over_128_refused() {
    // hello() schedules at most 21 blobs per block. A block of 20 blobs is under the cell cap at
    // 128 and at 129 columns, and over the 4 MiB BLS message cap.
    let (mut h, backend) = recorded().await;
    let mut s = kzg_open(&mut h).await;
    let block = zero_block(MAX_KZG_COLUMNS as u64, 20);
    let at = kzg_cells_request(1, block);
    assert!(kzg_body(at.clone()).encoded_len() > MAX_MESSAGE_BYTES);
    s.send(kzg_body(at)).await;
    let r = kzg_reply(&mut s).await;
    assert_eq!((r.request_id, r.status), (1, VerifyStatus::Valid as i32));
    assert_eq!(backend.calls().len(), 1);

    let over = kzg_cells_request(2, zero_block(MAX_KZG_COLUMNS as u64 + 1, 20));
    s.send(kzg_body(over)).await;
    let err = s.expect_failure().await;
    assert_eq!(err.code(), ErrorCode::ContractViolation);
    assert!(err.detail.contains("129 KZG columns"), "{}", err.detail);
    assert_eq!(backend.calls().len(), 1, "no KZG work for 129 columns");
    assert_eq!(h.server.contract_violations(), 1);
}

#[tokio::test]
async fn over_8mib_refused() {
    let (mut h, backend) = recorded().await;
    let mut s = kzg_open(&mut h).await;
    let at_cap = kzg_request_of_size(1, MAX_KZG_MESSAGE_BYTES, s.generation);
    assert_eq!(
        kzg_body(at_cap.clone()).encoded_len(),
        MAX_KZG_MESSAGE_BYTES
    );
    s.send(kzg_body(at_cap)).await;
    // Exactly 8 MiB is decoded; its one cell is not 2048 bytes, so it is a decode error.
    let r = kzg_reply(&mut s).await;
    assert_eq!(
        (r.request_id, r.status),
        (1, VerifyStatus::DecodeError as i32)
    );

    let over = kzg_request_of_size(2, MAX_KZG_MESSAGE_BYTES + 1, s.generation);
    assert_eq!(
        kzg_body(over.clone()).encoded_len(),
        MAX_KZG_MESSAGE_BYTES + 1
    );
    s.send(kzg_body(over)).await;
    let err = s.expect_failure().await;
    assert_eq!(err.code(), ErrorCode::ContractViolation);
    // tonic refuses it from the gRPC frame header, before the protobuf is decoded.
    assert!(err.detail.contains("message cap"), "{}", err.detail);
    assert!(backend.calls().is_empty(), "no KZG work");
    assert_eq!(h.server.contract_violations(), 1);
}
