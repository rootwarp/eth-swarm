//! caps_before_decode: each server limit (257 BLS sets, a 4 MiB + 1 byte message, 129 KZG
//! columns) refuses the request with a per-call error that fails the stream. No verdict frame is
//! sent and the verifier is never called, so no point, cell or proof is decoded.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use cl_verify::bls::{BlsBackend, BlstBackend, PreparedSet};
use cl_verify::caps::{MAX_BLS_SETS, MAX_KZG_COLUMNS, MAX_MESSAGE_BYTES};
use cl_verify::kzg::{KzgBackend, KzgFailure, PreparedCells};
use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::{
    BlsSet, KzgCellProof, VerifyBlsRequestBody, VerifyKzgRequestBody, VerifyStatus,
};
use common::*;
use prost::Message;

#[derive(Default)]
struct Counting {
    bls_calls: AtomicUsize,
    kzg_calls: AtomicUsize,
}

struct CountingBls(Arc<Counting>);
impl BlsBackend for CountingBls {
    fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
        self.0.bls_calls.fetch_add(1, Ordering::SeqCst);
        BlstBackend.verify(sets)
    }
}

struct CountingKzg(Arc<Counting>);
impl KzgBackend for CountingKzg {
    fn verify(&self, cells: &PreparedCells) -> Result<bool, KzgFailure> {
        self.0.kzg_calls.fetch_add(1, Ordering::SeqCst);
        kzg_backend().verify(cells)
    }
}

async fn counted() -> (Harness, Arc<Counting>) {
    let c = Arc::new(Counting::default());
    let h = start_with(Options {
        bls: Arc::new(CountingBls(Arc::clone(&c))),
        kzg: Arc::new(CountingKzg(Arc::clone(&c))),
        cache: cache_of(4),
        ..Options::default()
    })
    .await;
    (h, c)
}

/// Undecodable set: the signature bytes are not a point.
fn garbage_set() -> BlsSet {
    BlsSet {
        signers: vec![cached(0)],
        signing_root: vec![0; 32],
        signature: vec![0xee; 96],
    }
}

fn garbage_cell(cell_index: u64) -> KzgCellProof {
    KzgCellProof {
        commitment: vec![0xff; 48],
        cell_index,
        cell: vec![0xff; 2048],
        proof: vec![0xff; 48],
    }
}

#[tokio::test]
async fn set_cap_257_fails_the_stream_without_a_verdict() {
    let (mut h, c) = counted().await;
    let mut s = bls_open(&mut h).await;
    let sets = vec![valid_set(0, 1); MAX_BLS_SETS + 1];
    s.send(bls_body(bls_request(1, sets))).await;
    let err = s.expect_failure().await;
    assert_eq!(err.code(), ErrorCode::ContractViolation);
    assert!(err.detail.contains("257"), "{}", err.detail);
    assert_eq!(c.bls_calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.server.contract_violations(), 1);
}

#[tokio::test]
async fn set_cap_is_checked_before_any_set_is_decoded() {
    let (mut h, c) = counted().await;
    // 256 undecodable sets: under the cap, so each gets a DECODE_ERROR verdict.
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(1, vec![garbage_set(); MAX_BLS_SETS])))
        .await;
    let r = bls_reply(&mut s).await;
    assert_eq!(
        outcomes(&r),
        vec![Ok(VerifyStatus::DecodeError); MAX_BLS_SETS]
    );
    // 257 of the same: refused as a whole, not 257 decode errors.
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(
        2,
        vec![garbage_set(); MAX_BLS_SETS + 1],
    )))
    .await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    assert_eq!(
        c.bls_calls.load(Ordering::SeqCst),
        0,
        "nothing decodable reached blst"
    );
}

/// A one-set BLS request padded (through an oversized `signing_root`) to `total` encoded bytes.
fn bls_request_of_size(total: usize) -> VerifyBlsRequestBody {
    let mut body = bls_request(1, vec![garbage_set()]);
    let mut pad = total as i64;
    loop {
        body.sets[0].signing_root = vec![0; pad as usize];
        let len = bls_body(body.clone()).encoded_len() as i64;
        if len == total as i64 {
            return body;
        }
        pad += total as i64 - len;
    }
}

#[tokio::test]
async fn message_cap_refuses_4_mib_plus_one_before_decode() {
    let (mut h, c) = counted().await;
    let at_cap = bls_request_of_size(MAX_MESSAGE_BYTES);
    assert_eq!(bls_body(at_cap.clone()).encoded_len(), MAX_MESSAGE_BYTES);
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(at_cap)).await;
    // Exactly 4 MiB is decoded; the 4 MiB root is not 32 bytes, so the set is a decode error.
    assert_eq!(
        outcomes(&bls_reply(&mut s).await),
        vec![Ok(VerifyStatus::DecodeError)]
    );

    let over = bls_request_of_size(MAX_MESSAGE_BYTES + 1);
    assert_eq!(bls_body(over.clone()).encoded_len(), MAX_MESSAGE_BYTES + 1);
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(over)).await;
    let err = s.expect_failure().await;
    assert_eq!(err.code(), ErrorCode::ContractViolation, "{}", err.detail);
    assert_eq!(c.bls_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn message_cap_applies_to_kzg_requests() {
    let (mut h, c) = counted().await;
    // 1 column, many cells: under the column cap, over the byte cap.
    let n = MAX_MESSAGE_BYTES / 2048 + 1;
    let body = VerifyKzgRequestBody {
        request_id: 1,
        cells: vec![garbage_cell(0); n],
        deadline_unix_ms: far_deadline(),
    };
    assert!(kzg_body(body.clone()).encoded_len() > MAX_MESSAGE_BYTES);
    let mut s = kzg_open(&mut h).await;
    s.send(kzg_body(body)).await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    assert_eq!(c.kzg_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn column_cap_129_fails_the_stream_without_a_verdict() {
    let (mut h, c) = counted().await;
    let mut s = kzg_open(&mut h).await;
    // 128 distinct undecodable columns: under the cap, one DECODE_ERROR verdict.
    s.send(kzg_body(VerifyKzgRequestBody {
        request_id: 1,
        cells: (0..MAX_KZG_COLUMNS as u64).map(garbage_cell).collect(),
        deadline_unix_ms: far_deadline(),
    }))
    .await;
    let r = kzg_reply(&mut s).await;
    assert_eq!(
        (r.request_id, r.status),
        (1, VerifyStatus::DecodeError as i32)
    );
    assert_eq!(c.kzg_calls.load(Ordering::SeqCst), 1);

    s.send(kzg_body(VerifyKzgRequestBody {
        request_id: 2,
        cells: (0..=MAX_KZG_COLUMNS as u64).map(garbage_cell).collect(),
        deadline_unix_ms: far_deadline(),
    }))
    .await;
    let err = s.expect_failure().await;
    assert_eq!(err.code(), ErrorCode::ContractViolation);
    assert!(err.detail.contains("129"), "{}", err.detail);
    assert_eq!(
        c.kzg_calls.load(Ordering::SeqCst),
        1,
        "the 129-column call never reached c-kzg"
    );
}
