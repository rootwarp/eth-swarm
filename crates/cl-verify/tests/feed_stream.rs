//! PubkeyFeed over a real tonic server.
//!
//! "Feed count check": `PubkeyFeedRequestBody.count` must equal `len(pubkeys)`; a mismatch is
//! `ERROR_CODE_CONTRACT_VIOLATION`, the frame is not applied, and the reply carries the unchanged
//! high-water mark so cl-chain can resend from there.

mod common;

use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::{PubkeyFeedRequestBody, VerifyStatus};
use common::*;

fn frame(start: u64, keys: std::ops::Range<u64>) -> PubkeyFeedRequestBody {
    let pubkeys: Vec<Vec<u8>> = keys.map(pk_bytes).collect();
    PubkeyFeedRequestBody {
        start_index: start,
        count: pubkeys.len() as u64,
        pubkeys,
    }
}

#[tokio::test]
async fn high_water_is_reported_first_then_after_every_append() {
    let mut h = start_with(Options {
        cache: cache_of(3),
        ..Options::default()
    })
    .await;
    let (mut s, first) = feed_open(&mut h).await;
    assert_eq!(first, 3);
    s.send(feed_body(frame(3, 3..6))).await;
    let r = feed_reply(&mut s).await;
    assert_eq!((r.high_water, r.err), (6, None));
    // A restarted feed sees the new mark first.
    let (_s2, again) = feed_open(&mut h).await;
    assert_eq!(again, 6);
}

#[tokio::test]
async fn feed_count_check() {
    let mut h = start().await;
    let (mut s, _) = feed_open(&mut h).await;
    for count in [0u64, 1, 3, u64::MAX] {
        let mut b = frame(0, 0..2);
        b.count = count;
        s.send(feed_body(b)).await;
        let r = feed_reply(&mut s).await;
        assert_eq!(r.high_water, 0, "count {count}");
        assert_eq!(
            r.err.unwrap().code(),
            ErrorCode::ContractViolation,
            "count {count}"
        );
    }
    assert_eq!(h.server.contract_violations(), 4);
    // The stream stays usable: a correct frame is then applied.
    s.send(feed_body(frame(0, 0..2))).await;
    let r = feed_reply(&mut s).await;
    assert_eq!((r.high_water, r.err), (2, None));
}

#[tokio::test]
async fn gap_overlap_and_bad_keys_are_refused_whole() {
    let mut h = start_with(Options {
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    let (mut s, _) = feed_open(&mut h).await;
    let mut bad_key = frame(2, 2..4);
    bad_key.pubkeys[1] = vec![0x01; 48];
    for b in [frame(3, 3..4), frame(1, 1..3), bad_key] {
        s.send(feed_body(b)).await;
        let r = feed_reply(&mut s).await;
        assert_eq!(r.high_water, 2);
        assert_eq!(r.err.unwrap().code(), ErrorCode::ContractViolation);
    }
    assert_eq!(h.cache.read().unwrap().high_water(), 2);
}

#[tokio::test]
async fn fed_keys_serve_bls_by_index_and_the_next_index_stays_unknown() {
    let mut h = start().await;
    let (mut s, _) = feed_open(&mut h).await;
    s.send(feed_body(frame(0, 0..4))).await;
    assert_eq!(feed_reply(&mut s).await.high_water, 4);
    let mut b = bls_open(&mut h).await;
    b.send(bls_body(bls_request(
        1,
        vec![
            signed_set(vec![cached(0), cached(3)], &[0, 3], 1),
            valid_set(4, 2),
        ],
    )))
    .await;
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Ok(VerifyStatus::Valid), Ok(VerifyStatus::UnknownIndex)]
    );
}
