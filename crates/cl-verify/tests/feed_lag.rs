//! The pubkey feed-lag gauges over a real PubkeyFeed stream: the frame that completes the restore
//! and every frame applied after it re-evaluate the lag from the epochs they carry. Frames whose
//! epochs break the rules are refused before they are applied; neither they nor frames refused for
//! other reasons change the gauges.

mod common;

use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::PubkeyFeedRequestBody;
use common::*;
use prometheus_client::encoding::text::encode;

fn at(
    mut frame: PubkeyFeedRequestBody,
    feed_finalized_epoch: u64,
    chain_finalized_epoch: u64,
) -> PubkeyFeedRequestBody {
    frame.feed_finalized_epoch = feed_finalized_epoch;
    frame.chain_finalized_epoch = chain_finalized_epoch;
    frame
}

/// `(verify_pubkey_feed_lag_epochs, verify_pubkey_feed_lag_alert)` of the validator feed
/// (`namespace="validator"`) as scraped from the server.
fn scraped(h: &Harness) -> (u64, u64) {
    let mut text = String::new();
    encode(&mut text, h.server.metrics_registry()).unwrap();
    let gauge = |name: &str| {
        let series = format!("{name}{{namespace=\"validator\"}} ");
        text.lines()
            .find_map(|l| l.strip_prefix(&series)?.parse().ok())
            .unwrap_or_else(|| panic!("{series} missing from\n{text}"))
    };
    (
        gauge("verify_pubkey_feed_lag_epochs"),
        gauge("verify_pubkey_feed_lag_alert"),
    )
}

async fn applied(s: &mut FeedStream, frame: PubkeyFeedRequestBody) -> u64 {
    s.send(feed_body(frame)).await;
    let r = feed_reply(s).await;
    assert_eq!(r.err, None);
    r.high_water
}

/// Sends `frame` and expects it refused as a contract violation at an unchanged high-water mark.
async fn refused(s: &mut FeedStream, frame: PubkeyFeedRequestBody, high_water: u64) {
    s.send(feed_body(frame)).await;
    let r = feed_reply(s).await;
    assert_eq!(
        (r.high_water, r.err.map(|e| e.code())),
        (high_water, Some(ErrorCode::ContractViolation))
    );
}

#[tokio::test]
async fn every_applied_frame_reports_the_feed_lag() {
    let mut h = start().await;
    assert_eq!(scraped(&h), (0, 0));
    // A two-frame rebuild: only the frame whose reply completes the restore is evaluated.
    let (mut s, _) = feed_open(&mut h).await;
    let first = at(announcing(feed_frame(0, 0..2), 3), 95, 99);
    assert_eq!(applied(&mut s, first).await, 2);
    assert_eq!(scraped(&h), (0, 0), "mid-restore frames are not evaluated");
    assert_eq!(applied(&mut s, at(feed_frame(2, 2..3), 95, 100)).await, 3);
    assert_eq!(
        scraped(&h),
        (5, 1),
        "a restore that ends at lag 5 raises the alert"
    );

    assert_eq!(applied(&mut s, at(feed_frame(3, 3..4), 98, 100)).await, 4);
    assert_eq!(scraped(&h), (2, 0));
    assert_eq!(applied(&mut s, at(feed_frame(4, []), 95, 100)).await, 4);
    assert_eq!(scraped(&h), (5, 1), "lag 5 raises the alert");
    // A finality update without new entries: count 0 at the high-water mark.
    assert_eq!(applied(&mut s, at(feed_frame(4, []), 96, 100)).await, 4);
    assert_eq!(scraped(&h), (4, 0), "lag 4 clears it");

    // A frame refused for another reason (a gap) is not evaluated.
    refused(&mut s, at(feed_frame(6, 6..7), 0, 100), 4).await;
    assert_eq!(scraped(&h), (4, 0));

    // On a restored server, the first frame of a new stream is applied and evaluated.
    let (mut next, first) = feed_open(&mut h).await;
    assert_eq!(first, 4);
    let announced = at(announcing(feed_frame(4, 4..5), 5), 90, 100);
    assert_eq!(applied(&mut next, announced).await, 5);
    assert_eq!(scraped(&h), (10, 1));
}

#[tokio::test]
async fn frames_with_impossible_epochs_are_refused_and_keep_the_gauges() {
    let mut h = start().await;
    let mut s = rebuild_over_feed(&mut h, 2, 2).await;
    assert_eq!(applied(&mut s, at(feed_frame(2, []), 95, 100)).await, 2);
    assert_eq!(scraped(&h), (5, 1));
    // Omitted epochs decode as (0, 0): finality cannot move back to 0, so this cannot clear it.
    refused(&mut s, feed_frame(2, 2..3), 2).await;
    // Finality never moves back.
    refused(&mut s, at(feed_frame(2, 2..3), 96, 99), 2).await;
    // The feed cannot be ahead of cl-chain's finality.
    refused(&mut s, at(feed_frame(2, 2..3), 101, 100), 2).await;
    assert_eq!(scraped(&h), (5, 1));
    assert_eq!(h.server.contract_violations(), 3);
    // A zero feed epoch only raises the lag, so it stays allowed.
    assert_eq!(applied(&mut s, at(feed_frame(2, 2..3), 0, 100)).await, 3);
    assert_eq!(scraped(&h), (100, 1));
    assert_eq!(applied(&mut s, at(feed_frame(3, []), 96, 100)).await, 3);
    assert_eq!(scraped(&h), (4, 0));
}
