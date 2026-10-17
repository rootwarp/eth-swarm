//! VerifyBls over a real tonic server on a Unix socket.
//!
//! "Per-slot verdicts": `results[i]` is the verdict for `sets[i]`. verify.proto's `BlsResult`
//! carries no index field, so the item index is echoed by position ("One per request set, same
//! order"), and the batch is echoed by `request_id`.

mod common;

use cl_verify::client::bls_verdicts;
use cl_verify::proto::common::{ErrorCode, Verdict};
use cl_verify::proto::verify::{BlsSet, VerifyStatus};
use common::*;

#[tokio::test]
async fn batch_echo_returns_the_request_id_and_one_result_per_set() {
    let mut h = start_with(Options {
        cache: cache_of(4),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    for (id, n) in [(41u64, 1usize), (42, 3), (43, 0)] {
        let sets = (0..n as u64).map(|i| valid_set(i, i as u8)).collect();
        s.send(bls_body(bls_request(id, sets))).await;
        let r = bls_reply(&mut s).await;
        assert_eq!(r.request_id, id);
        assert_eq!(outcomes(&r), vec![Ok(VerifyStatus::Valid); n]);
    }
}

#[tokio::test]
async fn per_item_ok_and_error_results_are_independent() {
    let mut h = start_with(Options {
        cache: cache_of(4),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    let mut bad_sig = valid_set(2, 9);
    bad_sig.signature = vec![0x11; 96];
    let sets = vec![
        valid_set(0, 1),
        signed_set(vec![inline(1, pk_bytes(1))], &[1], 9),
        invalid_set(1, 2),
        signed_set(vec![cached(77)], &[77], 3),
        bad_sig,
        valid_set(3, 4),
    ];
    let mut out = s.outstanding();
    let (tag, body) = file_bls(&mut out, bls_request(7, sets));
    s.send(bls_body(body)).await;
    let r = bls_reply(&mut s).await;
    assert_eq!(
        outcomes(&r),
        vec![
            Ok(VerifyStatus::Valid),
            Err(ErrorCode::ContractViolation),
            Ok(VerifyStatus::Invalid),
            Ok(VerifyStatus::UnknownIndex),
            Ok(VerifyStatus::DecodeError),
            Ok(VerifyStatus::Valid),
        ]
    );
    assert_eq!(
        bls_verdicts(Ok(r), &mut out, tag, 6),
        vec![
            Verdict::Accept,
            Verdict::Ignore,
            Verdict::Reject,
            Verdict::Ignore,
            Verdict::Reject,
            Verdict::Accept,
        ]
    );
}

#[tokio::test]
async fn per_slot_verdicts_follow_request_order() {
    let mut h = start_with(Options {
        cache: cache_of(8),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    // Bad sets at positions 0, 3 and 7 of 8; every other position must stay VALID.
    let bad = [0usize, 3, 7];
    let sets: Vec<BlsSet> = (0..8u64)
        .map(|i| {
            if bad.contains(&(i as usize)) {
                invalid_set(i, i as u8)
            } else {
                valid_set(i, i as u8)
            }
        })
        .collect();
    s.send(bls_body(bls_request(99, sets))).await;
    let r = bls_reply(&mut s).await;
    for (i, got) in outcomes(&r).into_iter().enumerate() {
        let want = if bad.contains(&i) {
            VerifyStatus::Invalid
        } else {
            VerifyStatus::Valid
        };
        assert_eq!(got, Ok(want), "slot {i}");
    }
}

#[tokio::test]
async fn full_256_set_batch_is_verified() {
    let mut h = start_with(Options {
        cache: cache_of(16),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    let mut sets: Vec<BlsSet> = (0..256u64).map(|i| valid_set(i % 16, i as u8)).collect();
    sets[200] = invalid_set(200 % 16, 200);
    s.send(bls_body(bls_request(1, sets))).await;
    let r = bls_reply(&mut s).await;
    assert_eq!(r.results.len(), 256);
    let invalid: Vec<usize> = outcomes(&r)
        .iter()
        .enumerate()
        .filter(|(_, o)| **o != Ok(VerifyStatus::Valid))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(invalid, vec![200]);
}

#[tokio::test]
async fn unfinalized_signer_uses_its_inline_key_for_that_call_only() {
    let mut h = start_with(Options {
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    let with_key = signed_set(vec![inline(5, pk_bytes(5))], &[5], 1);
    let without = signed_set(vec![cached(5)], &[5], 1);
    // Mixed aggregate: one finalized signer, one unfinalized with its key inline.
    let mixed = signed_set(vec![cached(0), inline(2, pk_bytes(2))], &[0, 2], 2);
    s.send(bls_body(bls_request(1, vec![with_key, without, mixed])))
        .await;
    let r = bls_reply(&mut s).await;
    assert_eq!(
        outcomes(&r),
        vec![
            Ok(VerifyStatus::Valid),
            Ok(VerifyStatus::UnknownIndex),
            Ok(VerifyStatus::Valid)
        ]
    );
    assert_eq!(h.cache.read().unwrap().high_water(), 2);
}

#[tokio::test]
async fn concurrent_requests_on_one_stream_are_matched_by_request_id() {
    let mut h = start_with(Options {
        cache: cache_of(4),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    for id in 1..=5u64 {
        let sets = if id % 2 == 0 {
            vec![invalid_set(id % 4, id as u8)]
        } else {
            vec![valid_set(id % 4, id as u8)]
        };
        s.send(bls_body(bls_request(id, sets))).await;
    }
    let mut seen = Vec::new();
    for _ in 0..5 {
        let r = bls_reply(&mut s).await;
        let want = if r.request_id % 2 == 0 {
            VerifyStatus::Invalid
        } else {
            VerifyStatus::Valid
        };
        assert_eq!(outcomes(&r), vec![Ok(want)], "request {}", r.request_id);
        seen.push(r.request_id);
    }
    seen.sort_unstable();
    assert_eq!(seen, vec![1, 2, 3, 4, 5]);
    drop(s.tx);
    assert!(s.rx.message().await.unwrap().is_none(), "clean close");
}

#[tokio::test]
async fn far_future_deadline_is_honoured_without_overflow() {
    let mut h = start_with(Options {
        cache: cache_of(1),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    let mut body = bls_request(1, vec![valid_set(0, 1)]);
    body.deadline_unix_ms = u64::MAX;
    s.send(bls_body(body)).await;
    assert_eq!(
        outcomes(&bls_reply(&mut s).await),
        vec![Ok(VerifyStatus::Valid)]
    );
}
