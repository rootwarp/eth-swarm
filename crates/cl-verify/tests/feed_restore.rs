//! Pubkey cache restore over a real PubkeyFeed stream: the first frame announces cl-chain's
//! finalized registry; a matching snapshot is reloaded, anything else is rebuilt from index 0 and
//! saved; VerifyBls never sees a partial cache.

mod common;

use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use cl_verify::bls::{BlsBackend, PreparedSet};
use cl_verify::feed::BlstCodec;
use cl_verify::server::Limits;
use cl_verify_cache::persist::save_with;

use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::VerifyStatus;
use cl_verify_cache::persist::effective_uid;
use common::*;

#[tokio::test]
async fn rebuild_is_saved_and_reloaded_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    {
        let mut h = start_with(restarted(&snapshot)).await;
        let _s = rebuild_over_feed(&mut h, 5, 2).await;
        assert_eq!(bls_outcome(&mut h, 4).await, Ok(VerifyStatus::Valid));
        wait_for(|| snapshot_holds(&snapshot, 5)).await;
    }
    // Saved after the rebuild: 0600, ours, exactly the registry.
    let meta = std::fs::metadata(&snapshot).unwrap();
    assert_eq!((meta.mode() & 0o7777, meta.uid()), (0o600, effective_uid()));
    assert!(snapshot_holds(&snapshot, 5));

    // A new process: the announcing frame alone restores the whole cache from the file.
    let mut h = start_with(restarted(&snapshot)).await;
    let (mut s, first) = feed_open(&mut h).await;
    assert_eq!(first, 0);
    s.send(feed_body(announcing(feed_frame(0, []), 5))).await;
    let r = feed_reply(&mut s).await;
    assert_eq!((r.high_water, r.err), (5, None), "loaded, no ranges needed");
    assert_eq!(bls_outcome(&mut h, 4).await, Ok(VerifyStatus::Valid));
    assert_eq!(bls_outcome(&mut h, 5).await, Ok(VerifyStatus::UnknownIndex));
    // The stream continues from the loaded mark.
    s.send(feed_body(feed_frame(5, 5..6))).await;
    assert_eq!(feed_reply(&mut s).await.high_water, 6);
    assert_eq!(h.server.contract_violations(), 0);
}

#[tokio::test]
async fn a_snapshot_that_does_not_match_the_registry_is_rebuilt() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    {
        let mut h = start_with(restarted(&snapshot)).await;
        let _s = rebuild_over_feed(&mut h, 5, 5).await;
        wait_for(|| snapshot_holds(&snapshot, 5)).await;
    }
    // Longer registry: full rebuild from 0 (the first reply asks for index 3, not 5).
    {
        let mut h = start_with(restarted(&snapshot)).await;
        let _s = rebuild_over_feed(&mut h, 7, 3).await;
        assert_eq!(bls_outcome(&mut h, 6).await, Ok(VerifyStatus::Valid));
        wait_for(|| snapshot_holds(&snapshot, 7)).await;
    }

    // Same length, other keys: the file is not used at all.
    let mut h = start_with(restarted(&snapshot)).await;
    let (mut s, _) = feed_open(&mut h).await;
    let mut other = feed_frame(0, 10..17);
    other.finalized_registry = Some(registry_of(10..17));
    s.send(feed_body(other)).await;
    assert_eq!(feed_reply(&mut s).await.high_water, 7);
    // Index 0 now holds validator 10's key: validator 0's signature does not verify.
    assert_eq!(bls_outcome(&mut h, 0).await, Ok(VerifyStatus::Invalid));
}

#[tokio::test]
async fn bls_sees_no_partial_cache_during_a_rebuild() {
    let mut h = start().await;
    let (mut s, _) = feed_open(&mut h).await;
    s.send(feed_body(announcing(feed_frame(0, 0..3), 5))).await;
    assert_eq!(feed_reply(&mut s).await.high_water, 3, "next range wanted");
    assert_eq!(bls_outcome(&mut h, 0).await, Ok(VerifyStatus::UnknownIndex));
    assert_eq!(h.cache.read().unwrap().high_water(), 0);
    s.send(feed_body(feed_frame(3, 3..5))).await;
    assert_eq!(feed_reply(&mut s).await.high_water, 5);
    assert_eq!(bls_outcome(&mut h, 0).await, Ok(VerifyStatus::Valid));
}

#[tokio::test]
async fn a_missing_registry_is_a_contract_violation() {
    let mut h = start().await;
    // A first frame without the registry fails the stream.
    let (mut s, _) = feed_open(&mut h).await;
    s.send(feed_body(feed_frame(0, 0..2))).await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    // So does a stream that ends before its first frame.
    let (Bidi { tx, mut rx, .. }, _) = feed_open(&mut h).await;
    drop(tx);
    let end = tokio::time::timeout(std::time::Duration::from_secs(20), rx.message()).await;
    assert!(matches!(end, Ok(Ok(None) | Err(_))), "the stream ends");
    wait_for(|| h.server.contract_violations() == 2).await;
    assert_eq!(h.cache.read().unwrap().high_water(), 0, "nothing restored");
    // The next stream restores normally.
    let _s = rebuild_over_feed(&mut h, 2, 2).await;
    // Once restored, every stream must still announce the registry first.
    let (mut s, first) = feed_open(&mut h).await;
    assert_eq!(first, 2);
    s.send(feed_body(feed_frame(2, 2..3))).await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    assert_eq!(h.cache.read().unwrap().high_water(), 2);
}

#[tokio::test]
async fn a_feed_that_breaks_its_registry_fails_the_restore() {
    let mut h = start().await;
    let (mut s, _) = feed_open(&mut h).await;
    let mut lying = feed_frame(0, 0..3);
    lying.finalized_registry = Some(registry_of(10..13));
    s.send(feed_body(lying)).await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    assert_eq!(h.cache.read().unwrap().high_water(), 0);
    assert_eq!(bls_outcome(&mut h, 0).await, Ok(VerifyStatus::UnknownIndex));
}

/// A BLS backend that holds each batch until released, so a later request on the same stream
/// stays unread (and its signers unresolved) meanwhile.
struct Gated {
    release: Mutex<std_mpsc::Receiver<()>>,
    entered: AtomicUsize,
}

impl BlsBackend for Gated {
    fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.release.lock().unwrap().recv().unwrap();
        vec![true; sets.len()]
    }
}

#[tokio::test]
async fn inline_signers_wait_for_the_restore_complete_reply() {
    // The snapshot holds 10 keys; cl-chain has sent no range on the new feed stream.
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    save_with(&BlstCodec, &cache_of(10).read().unwrap(), &snapshot).unwrap();
    let (release, rx) = std_mpsc::channel();
    let gate = Arc::new(Gated {
        release: Mutex::new(rx),
        entered: AtomicUsize::new(0),
    });
    let mut h = start_with(Options {
        bls: gate.clone(),
        limits: Limits {
            max_outstanding_per_stream: 1,
            ..Limits::default()
        },
        ..restarted(&snapshot)
    })
    .await;
    let mut b = bls_open(&mut h).await;
    let inline_set = |i: u64, root: u8| signed_set(vec![inline(i, pk_bytes(i))], &[i], root);
    b.send(bls_body(bls_request(1, vec![inline_set(20, 1)])))
        .await;
    wait_for(|| gate.entered.load(Ordering::SeqCst) == 1).await;
    // What the contract forbids: an inline signer sent before the restore-complete reply. Its resolution
    // is delayed (the stream is not read while request 1 is in BLS) past the restore.
    b.send(bls_body(bls_request(2, vec![inline_set(5, 2)])))
        .await;

    let (mut f, first) = feed_open(&mut h).await;
    assert_eq!(
        first, 0,
        "the post-hello status is not the restore-complete reply"
    );
    f.send(feed_body(announcing(feed_frame(0, []), 10))).await;
    let acked = feed_reply(&mut f).await.high_water;
    assert_eq!(
        acked, 10,
        "the restore-complete reply: the whole snapshot is cached"
    );

    release.send(()).unwrap();
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Ok(VerifyStatus::Valid)]
    );
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Err(ErrorCode::ContractViolation)],
        "index 5 is now cached: the early inline signer is a violation"
    );
    // After the reply, cl-chain uses acked = 10: inline only at or past it.
    b.send(bls_body(bls_request(3, vec![inline_set(9, 3)])))
        .await;
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Err(ErrorCode::ContractViolation)]
    );
    release.send(()).unwrap();
    b.send(bls_body(bls_request(4, vec![inline_set(acked, 4)])))
        .await;
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Ok(VerifyStatus::Valid)]
    );
    b.send(bls_body(bls_request(5, vec![valid_set(9, 5)])))
        .await;
    release.send(()).unwrap();
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Ok(VerifyStatus::Valid)]
    );
}

#[tokio::test]
async fn a_multi_frame_rebuild_stays_live_with_imports_pending() {
    // Any BLS work would hang in the gate, and a rebuild frame later than 300 ms fails the restore:
    // the rebuild completing shows nothing held a frame back.
    let (release, rx) = std_mpsc::channel();
    let gate = Arc::new(Gated {
        release: Mutex::new(rx),
        entered: AtomicUsize::new(0),
    });
    let mut h = start_with(Options {
        bls: gate.clone(),
        limits: Limits {
            restore_frame_timeout: Duration::from_millis(300),
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    let mut b = bls_open(&mut h).await;
    let (mut f, _) = feed_open(&mut h).await;
    f.send(feed_body(announcing(feed_frame(0, 0..2), 6))).await;
    let mid = feed_reply(&mut f).await.high_water;
    assert!(
        mid < 6,
        "a mid-rebuild reply is not the restore-complete reply"
    );

    // cl-chain has imports pending for validators 3 and 5. Before the restore-complete reply it
    // sends no inline signers, so they go index-only and are IGNOREd at once (retry later), and
    // no in-flight request holds a rebuild frame back.
    let pending = |id: u64| bls_request(id, vec![valid_set(3, 1), valid_set(5, 2)]);
    b.send(bls_body(pending(1))).await;
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![
            Ok(VerifyStatus::UnknownIndex),
            Ok(VerifyStatus::UnknownIndex)
        ]
    );
    f.send(feed_body(feed_frame(mid, mid..4))).await;
    assert_eq!(feed_reply(&mut f).await.high_water, 4);
    f.send(feed_body(feed_frame(4, 4..6))).await;
    let acked = feed_reply(&mut f).await.high_water;
    assert_eq!(acked, 6, "the restore-complete reply");
    assert_eq!(
        gate.entered.load(Ordering::SeqCst),
        0,
        "no BLS work held up"
    );

    // The retried import resolves from the cache; inline signers resume at acked.
    b.send(bls_body(pending(2))).await;
    release.send(()).unwrap();
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Ok(VerifyStatus::Valid), Ok(VerifyStatus::Valid)]
    );
    let inline_set = signed_set(vec![inline(acked, pk_bytes(acked))], &[acked], 3);
    b.send(bls_body(bls_request(3, vec![inline_set]))).await;
    release.send(()).unwrap();
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Ok(VerifyStatus::Valid)]
    );
    assert_eq!(h.server.contract_violations(), 0);
}

#[tokio::test]
async fn a_stalled_restore_times_out_and_frees_the_feed() {
    let timeout = Duration::from_millis(300);
    let mut h = start_with(Options {
        limits: Limits {
            restore_frame_timeout: timeout,
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    // Stalls before its first frame: the restore gives up and the stream fails.
    let started = Instant::now();
    let (mut stalled, _) = feed_open(&mut h).await;
    assert_eq!(
        stalled.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    assert!(started.elapsed() < timeout * 10);
    // Stalls between rebuild frames: same, and the rebuilt part is not kept.
    let (mut partial, _) = feed_open(&mut h).await;
    partial
        .send(feed_body(announcing(feed_frame(0, 0..2), 4)))
        .await;
    assert_eq!(feed_reply(&mut partial).await.high_water, 2);
    assert_eq!(
        partial.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    assert_eq!(h.cache.read().unwrap().high_water(), 0);
    // A stream waiting behind a stalled restore gets its turn once that one times out.
    let (_blocker, _) = feed_open(&mut h).await;
    let mut next = rebuild_over_feed(&mut h, 4, 2).await;
    next.send(feed_body(feed_frame(4, 4..5))).await;
    assert_eq!(feed_reply(&mut next).await.high_water, 5);
    assert_eq!(h.server.contract_violations(), 3);
}
