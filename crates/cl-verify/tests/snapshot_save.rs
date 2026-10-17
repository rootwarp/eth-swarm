//! Keeping the pubkey snapshot current: feed appends after a restore mark it dirty, a saver
//! writes it at most once per `snapshot_interval` off the runtime, a failed save is retried and
//! never breaks the feed, and shutdown flushes a dirty snapshot.

mod common;

use std::time::{Duration, Instant};

use cl_verify::proto::verify::VerifyStatus;
use common::*;

fn saving_every(snapshot: &std::path::Path, interval: Duration) -> Options {
    Options {
        snapshot_interval: Some(interval),
        ..restarted(snapshot)
    }
}

async fn append(s: &mut FeedStream, start: u64, end: u64) {
    s.send(feed_body(feed_frame(start, start..end))).await;
    let r = feed_reply(s).await;
    assert_eq!((r.high_water, r.err), (end, None));
}

#[tokio::test]
async fn appends_after_a_restore_are_saved_and_reloaded_without_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    {
        let mut h = start_with(saving_every(&snapshot, Duration::ZERO)).await;
        let mut s = rebuild_over_feed(&mut h, 5, 5).await;
        append(&mut s, 5, 8).await;
        wait_for(|| snapshot_holds(&snapshot, 8)).await;
    }
    // Restart against a registry of 8: the announcing frame alone loads all of it.
    let mut h = start_with(restarted(&snapshot)).await;
    let (mut s, _) = feed_open(&mut h).await;
    s.send(feed_body(announcing(feed_frame(0, []), 8))).await;
    let r = feed_reply(&mut s).await;
    assert_eq!((r.high_water, r.err), (8, None), "reloaded, no rebuild");
    assert_eq!(bls_outcome(&mut h, 7).await, Ok(VerifyStatus::Valid));
}

#[tokio::test]
async fn a_burst_of_appends_is_saved_at_most_once_per_interval() {
    let interval = Duration::from_secs(1);
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    let mut h = start_with(saving_every(&snapshot, interval)).await;
    let mut s = rebuild_over_feed(&mut h, 2, 2).await;
    // The rebuild is saved at once.
    wait_for(|| h.server.snapshot_saves() == 1).await;
    let first_save = Instant::now();
    for i in 2..12 {
        append(&mut s, i, i + 1).await;
    }
    if first_save.elapsed() < interval * 3 / 4 {
        assert_eq!(
            h.server.snapshot_saves(),
            1,
            "the burst waits for the interval"
        );
    }
    wait_for(|| h.server.snapshot_saves() == 2).await;
    assert!(
        first_save.elapsed() >= interval * 9 / 10,
        "second save no earlier than one interval after the first"
    );
    assert!(
        snapshot_holds(&snapshot, 12),
        "one save covers the whole burst"
    );
    tokio::time::sleep(interval * 3 / 2).await;
    assert_eq!(
        h.server.snapshot_saves(),
        2,
        "nothing dirty, nothing written"
    );
    assert_eq!(h.server.snapshot_save_failures(), 0);
}

#[tokio::test]
async fn a_failing_save_is_retried_and_never_breaks_the_feed() {
    // The snapshot directory does not exist, so every save fails.
    let mut h = start_with(saving_every(&no_snapshot(), Duration::ZERO)).await;
    let mut s = rebuild_over_feed(&mut h, 3, 3).await;
    wait_for(|| h.server.snapshot_save_failures() >= 1).await;
    append(&mut s, 3, 4).await;
    assert_eq!(bls_outcome(&mut h, 3).await, Ok(VerifyStatus::Valid));
    // Still dirty: the saver tries again on a later interval.
    wait_for(|| h.server.snapshot_save_failures() >= 2).await;
    append(&mut s, 4, 5).await;
    assert_eq!(h.server.snapshot_saves(), 0);
    assert_eq!(h.server.contract_violations(), 0);
}

#[tokio::test]
async fn shutdown_flushes_a_dirty_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    let mut h = start_with(saving_every(&snapshot, Duration::from_secs(3_600))).await;
    let mut s = rebuild_over_feed(&mut h, 3, 3).await;
    wait_for(|| h.server.snapshot_saves() == 1).await;
    append(&mut s, 3, 6).await;
    assert!(
        !snapshot_holds(&snapshot, 6),
        "the append waits for the interval"
    );
    drop(s);
    h.shutdown().await;
    assert!(snapshot_holds(&snapshot, 6), "flushed on shutdown");
}

#[tokio::test]
async fn flush_snapshot_writes_only_a_restored_dirty_cache() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    let mut h = start_with(saving_every(&snapshot, Duration::from_secs(3_600))).await;
    // Not restored yet: the empty cache is never written over a snapshot.
    assert!(!h.server.flush_snapshot().await.unwrap());
    assert!(!snapshot.exists());
    let mut s = rebuild_over_feed(&mut h, 3, 3).await;
    wait_for(|| h.server.snapshot_saves() == 1).await;
    assert!(!h.server.flush_snapshot().await.unwrap(), "clean");
    append(&mut s, 3, 4).await;
    assert!(
        h.server.flush_snapshot().await.unwrap(),
        "dirty: written now"
    );
    assert!(snapshot_holds(&snapshot, 4));
    assert_eq!(h.server.snapshot_saves(), 2);
}
