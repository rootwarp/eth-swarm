//! Server shutdown: once the drain is over, live streams are closed and no feed frame is applied
//! or acked after the final snapshot flush, and a failed flush is reported, not just logged.

mod common;

use std::time::Duration;

use cl_verify::server::ServeError;
use common::*;

/// A server that flushes at shutdown only (saves are an hour apart), draining for `drain`.
fn draining(snapshot: &std::path::Path, drain: Duration) -> Options {
    Options {
        snapshot_interval: Some(Duration::from_secs(3_600)),
        drain: Some(drain),
        ..restarted(snapshot)
    }
}

async fn append(s: &mut FeedStream, start: u64, end: u64) {
    s.send(feed_body(feed_frame(start, start..end))).await;
    let r = feed_reply(s).await;
    assert_eq!((r.high_water, r.err), (end, None));
}

#[tokio::test]
async fn an_append_after_shutdown_is_refused_and_one_acked_during_the_drain_is_flushed() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    let mut h = start_with(draining(&snapshot, Duration::from_millis(300))).await;
    let mut s = rebuild_over_feed(&mut h, 3, 3).await;
    wait_for(|| h.server.snapshot_saves() == 1).await;
    append(&mut s, 3, 5).await;

    h.begin_shutdown();
    // The feed stream stays open, so the drain runs its full length. An append during it is
    // applied and acked, and must then be in the flushed snapshot.
    append(&mut s, 5, 6).await;
    h.served().await.expect("clean shutdown");
    assert!(
        snapshot_holds(&snapshot, 6),
        "acked during the drain: flushed"
    );

    // The final flush is done. An append now must not be acked: the stream was closed before
    // the flush, so it can never be applied after it. It is refused: either the stream is gone
    // (the send fails) or it reads the error that ended it.
    if s.tx.send(feed_body(feed_frame(6, 6..8))).await.is_ok() {
        if let Ok(Some(frame)) = s.next().await {
            panic!("append answered after the final flush: {frame:?}");
        }
    }
    assert!(
        snapshot_holds(&snapshot, 6),
        "the snapshot is what was acked"
    );
    assert!(!snapshot_holds(&snapshot, 8));
}

#[tokio::test]
async fn live_streams_are_failed_once_the_drain_is_over() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    let mut h = start_with(Options {
        cache: cache_of(1),
        ..draining(&snapshot, Duration::from_millis(200))
    })
    .await;
    let mut bls = bls_open(&mut h).await;
    let (mut feed, _) = feed_open(&mut h).await;
    h.begin_shutdown();
    h.served().await.expect("clean shutdown");
    for (what, err) in [
        ("bls", bls.expect_failure().await),
        ("feed", feed.expect_failure().await),
    ] {
        assert_eq!(
            err.code(),
            cl_verify::proto::common::ErrorCode::ResourceUnavailable,
            "{what}: {err:?}"
        );
    }
}

#[tokio::test]
async fn a_failed_shutdown_flush_is_returned() {
    // The snapshot directory does not exist: every save fails, so the cache stays dirty.
    let mut h = start_with(draining(&no_snapshot(), Duration::from_millis(200))).await;
    let s = rebuild_over_feed(&mut h, 3, 3).await;
    wait_for(|| h.server.snapshot_save_failures() >= 1).await;
    drop(s);
    h.begin_shutdown();
    match h.served().await {
        Err(ServeError::Flush(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        other => panic!("flush failure not returned: {other:?}"),
    }
}
