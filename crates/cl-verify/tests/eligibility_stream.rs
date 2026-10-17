//! Signer eligibility through a real server: `VerifyBlsRequestBody.origin` selects the
//! cl-verify-cache rules, and the request-level inline cap applies on import.

mod common;

use cl_verify::caps::MAX_INLINE_KEYS_PER_BATCH;
use cl_verify::client::bls_verdicts;
use cl_verify::proto::common::{ErrorCode, Verdict};
use cl_verify::proto::verify::{BlsSet, VerifyOrigin, VerifyStatus};
use common::*;

async fn harness() -> Harness {
    start_with(Options {
        cache: cache_of(4),
        ..Options::default()
    })
    .await
}

#[tokio::test]
async fn gossip_resolves_cached_signers_and_ignores_unknown_ones() {
    let mut h = harness().await;
    let mut s = bls_open(&mut h).await;
    let sets = vec![valid_set(0, 1), valid_set(9, 4)];
    s.send(bls_body(bls_request_from(1, sets, VerifyOrigin::Gossip)))
        .await;
    let r = bls_reply(&mut s).await;
    assert_eq!(
        outcomes(&r),
        vec![Ok(VerifyStatus::Valid), Ok(VerifyStatus::UnknownIndex)]
    );
    assert_eq!(
        bls_verdicts(Ok(r), 1, 2),
        vec![Verdict::Accept, Verdict::Ignore]
    );
}

#[tokio::test]
async fn gossip_inline_key_fails_the_stream() {
    // Past the cache or for a cached index alike: gossip never carries inline keys.
    for index in [9u64, 1] {
        let mut h = harness().await;
        let mut s = bls_open(&mut h).await;
        let sets = vec![
            valid_set(0, 1),
            signed_set(vec![inline(index, pk_bytes(index))], &[index], 2),
        ];
        s.send(bls_body(bls_request_from(1, sets, VerifyOrigin::Gossip)))
            .await;
        let err = s.expect_failure().await;
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert!(err.detail.contains("gossip"), "{}", err.detail);
    }
}

#[tokio::test]
async fn import_uses_inline_past_high_water_and_refuses_it_for_cached_indices() {
    let mut h = harness().await;
    let mut s = bls_open(&mut h).await;
    let sets = vec![
        signed_set(vec![cached(0), inline(7, pk_bytes(7))], &[0, 7], 1),
        signed_set(vec![inline(2, pk_bytes(2))], &[2], 2),
        valid_set(8, 3),
    ];
    s.send(bls_body(bls_request_from(1, sets, VerifyOrigin::Import)))
        .await;
    assert_eq!(
        outcomes(&bls_reply(&mut s).await),
        vec![
            Ok(VerifyStatus::Valid),
            Err(ErrorCode::ContractViolation),
            Ok(VerifyStatus::UnknownIndex),
        ]
    );
}

#[tokio::test]
async fn unspecified_origin_fails_the_stream() {
    let mut h = harness().await;
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request_from(
        1,
        vec![valid_set(0, 1)],
        VerifyOrigin::Unspecified,
    )))
    .await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn unknown_origin_is_ignored_without_bls_work() {
    let mut h = harness().await;
    let mut s = bls_open(&mut h).await;
    let mut body = bls_request(1, vec![valid_set(0, 1), valid_set(1, 2)]);
    body.origin = 77;
    s.send(bls_body(body)).await;
    let r = bls_reply(&mut s).await;
    assert_eq!(outcomes(&r), vec![Err(ErrorCode::VersionMismatch); 2]);
    assert_eq!(bls_verdicts(Ok(r), 1, 2), vec![Verdict::Ignore; 2]);
    // The stream survives.
    s.send(bls_body(bls_request(2, vec![valid_set(0, 1)])))
        .await;
    assert_eq!(
        outcomes(&bls_reply(&mut s).await),
        vec![Ok(VerifyStatus::Valid)]
    );
}

/// One set of `n` inline signers past the cache, all using validator 100's key (so signing is
/// cheap: the aggregate signature is `n` copies of one signature).
fn many_inline(n: usize, root: u8) -> BlsSet {
    let key = pk_bytes(100);
    let signers = (0..n as u64)
        .map(|i| inline(1_000 + i, key.clone()))
        .collect();
    let keys = vec![100; n];
    signed_set(signers, &keys, root)
}

#[tokio::test]
async fn inline_cap_refuses_a_multi_set_request_but_accepts_one_oversized_set() {
    let mut h = harness().await;
    let mut s = bls_open(&mut h).await;
    let big = MAX_INLINE_KEYS_PER_BATCH + 200;
    s.send(bls_body(bls_request(1, vec![many_inline(big, 1)])))
        .await;
    assert_eq!(
        outcomes(&bls_reply(&mut s).await),
        vec![Ok(VerifyStatus::Valid)],
        "one indivisible set may exceed the packing cap"
    );
    let split = vec![many_inline(MAX_INLINE_KEYS_PER_BATCH, 2), many_inline(1, 3)];
    s.send(bls_body(bls_request(2, split))).await;
    let err = s.expect_failure().await;
    assert_eq!(err.code(), ErrorCode::ContractViolation);
    assert!(err.detail.contains("inline"), "{}", err.detail);
}
