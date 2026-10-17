//! Resource limits through a real server: per-stream outstanding requests, the hello timeout, the
//! server-wide stream limit, feed jobs under the verifier permits, and strictly increasing
//! `request_id`s.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cl_verify::bls::{BlsBackend, PreparedSet};
use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::{PubkeyFeedRequestBody, VerifyKzgRequestBody, VerifyStatus};
use cl_verify::server::Limits;
use cl_verify::wire::{error_from_status, now_unix_ms};
use common::*;

/// Answers "valid", but blocks each call until the test releases it.
struct Gated {
    release: Mutex<std_mpsc::Receiver<()>>,
    entered: AtomicUsize,
}

impl Gated {
    fn new() -> (Arc<Self>, std_mpsc::Sender<()>) {
        let (tx, rx) = std_mpsc::channel();
        (
            Arc::new(Self {
                release: Mutex::new(rx),
                entered: AtomicUsize::new(0),
            }),
            tx,
        )
    }
    fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }
}

impl BlsBackend for Gated {
    fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.release.lock().unwrap().recv().unwrap();
        vec![true; sets.len()]
    }
}

async fn wait_for(cond: impl Fn() -> bool) {
    for _ in 0..400 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not reached");
}

fn limits(f: impl FnOnce(&mut Limits)) -> Limits {
    let mut l = Limits::default();
    f(&mut l);
    l
}

#[tokio::test]
async fn stream_stops_reading_at_the_outstanding_limit() {
    let (gate, release) = Gated::new();
    let mut h = start_with(Options {
        bls: gate.clone(),
        limits: limits(|l| l.max_outstanding_per_stream = 2),
        cache: cache_of(4),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    for id in 1..=3 {
        s.send(bls_body(bls_request(id, vec![valid_set(0, id as u8)])))
            .await;
    }
    wait_for(|| gate.entered() == 2).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        gate.entered(),
        2,
        "the third request is not read while two are outstanding"
    );
    release.send(()).unwrap();
    assert_eq!(
        outcomes(&bls_reply(&mut s).await),
        vec![Ok(VerifyStatus::Valid)]
    );
    wait_for(|| gate.entered() == 3).await;
    release.send(()).unwrap();
    release.send(()).unwrap();
    for _ in 0..2 {
        assert_eq!(
            outcomes(&bls_reply(&mut s).await),
            vec![Ok(VerifyStatus::Valid)]
        );
    }
}

#[tokio::test]
async fn missing_hello_times_out_as_a_contract_violation() {
    let mut h = start_with(Options {
        limits: limits(|l| l.hello_timeout = Duration::from_millis(100)),
        ..Options::default()
    })
    .await;
    let mut s = bls_raw(&mut h).await;
    let started = std::time::Instant::now();
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    let mut f = feed_raw(&mut h).await;
    assert_eq!(
        f.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn streams_over_the_server_limit_are_refused_until_one_closes() {
    let mut h = start_with(Options {
        limits: limits(|l| l.max_streams = 1),
        ..Options::default()
    })
    .await;
    let s = bls_open(&mut h).await;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(kzg_hello(hello())).await.unwrap();
    let refused = h
        .client
        .verify_kzg(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap_err();
    assert_eq!(error_from_status(&refused).code(), ErrorCode::Overloaded);
    drop(s);
    let mut opened = None;
    for _ in 0..100 {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send(kzg_hello(hello())).await.unwrap();
        if let Ok(r) = h
            .client
            .verify_kzg(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await
        {
            opened = Some((tx, r));
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        opened.is_some(),
        "a slot frees once the first stream closes"
    );
}

#[tokio::test]
async fn feed_frames_wait_for_a_verifier_permit() {
    let (gate, release) = Gated::new();
    let mut h = start_with(Options {
        bls: gate.clone(),
        limits: limits(|l| l.max_in_flight = 1),
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    let mut b = bls_open(&mut h).await;
    b.send(bls_body(bls_request(1, vec![valid_set(0, 1)])))
        .await;
    wait_for(|| gate.entered() == 1).await;
    let (mut f, _) = feed_open(&mut h).await;
    f.send(feed_body(PubkeyFeedRequestBody {
        start_index: 2,
        count: 1,
        pubkeys: vec![pk_bytes(2)],
        finalized_registry: Some(registry_of(0..3)),
        feed_finalized_epoch: 0,
        chain_finalized_epoch: 0,
    }))
    .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        h.cache.read().unwrap().high_water(),
        2,
        "feed job waits for the permit"
    );
    release.send(()).unwrap();
    assert_eq!(feed_reply(&mut f).await.high_water, 3);
    assert_eq!(
        outcomes(&bls_reply(&mut b).await),
        vec![Ok(VerifyStatus::Valid)]
    );
}

#[tokio::test]
async fn repeated_or_decreasing_request_id_fails_the_stream() {
    let mut h = start_with(Options {
        cache: cache_of(1),
        ..Options::default()
    })
    .await;
    for second in [5u64, 4] {
        let mut s = bls_open(&mut h).await;
        s.send(bls_body(bls_request(5, vec![valid_set(0, 1)])))
            .await;
        assert_eq!(bls_reply(&mut s).await.request_id, 5);
        s.send(bls_body(bls_request(second, vec![valid_set(0, 1)])))
            .await;
        assert_eq!(
            s.expect_failure().await.code(),
            ErrorCode::ContractViolation
        );
    }
    let mut k = kzg_open(&mut h).await;
    let body = |id| VerifyKzgRequestBody {
        request_id: id,
        cells: vec![cl_verify::proto::verify::KzgCellProof::default()],
        deadline_unix_ms: now_unix_ms() + 30_000,
    };
    k.send(kzg_body(body(0))).await;
    assert_eq!(kzg_reply(&mut k).await.request_id, 0);
    k.send(kzg_body(body(0))).await;
    assert_eq!(
        k.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn buffered_request_past_its_deadline_is_never_resolved() {
    // Request 2 carries index 5 inline and waits behind request 1. While it waits, the feed
    // appends index 5 and its deadline passes. Resolving it now would meet a cached index (a
    // contract violation); instead it is DEADLINE_EXCEEDED with no resolution.
    let (gate, release) = Gated::new();
    let mut h = start_with(Options {
        bls: gate.clone(),
        limits: limits(|l| l.max_outstanding_per_stream = 1),
        cache: cache_of(5),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(1, vec![valid_set(0, 1)])))
        .await;
    wait_for(|| gate.entered() == 1).await;
    let mut late = bls_request(2, vec![signed_set(vec![inline(5, pk_bytes(5))], &[5], 2)]);
    late.deadline_unix_ms = now_unix_ms() + 200;
    s.send(bls_body(late)).await;
    let (mut f, _) = feed_open(&mut h).await;
    f.send(feed_body(PubkeyFeedRequestBody {
        start_index: 5,
        count: 1,
        pubkeys: vec![pk_bytes(5)],
        finalized_registry: Some(registry_of(0..6)),
        feed_finalized_epoch: 0,
        chain_finalized_epoch: 0,
    }))
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    release.send(()).unwrap();
    assert_eq!(feed_reply(&mut f).await.high_water, 6);
    assert_eq!(bls_reply(&mut s).await.request_id, 1);
    let r = bls_reply(&mut s).await;
    assert_eq!(r.request_id, 2);
    assert_eq!(outcomes(&r), vec![Ok(VerifyStatus::DeadlineExceeded)]);
    assert_eq!(gate.entered(), 1, "no BLS work for the expired request");
    assert_eq!(h.server.contract_violations(), 0);
}

#[tokio::test]
async fn closed_stream_drops_queued_requests_without_resolving() {
    let (gate, release) = Gated::new();
    let mut h = start_with(Options {
        bls: gate.clone(),
        cache: cache_of(5),
        ..Options::default()
    })
    .await;
    let s = bls_open(&mut h).await;
    // Hold the cache as a feed append would (on its own thread); the request is read and queued
    // behind it.
    let (held_tx, held_rx) = std_mpsc::channel();
    let (go_tx, go_rx) = std_mpsc::channel::<()>();
    let cache = Arc::clone(&h.cache);
    let appender = std::thread::spawn(move || {
        let mut writer = cache.write().unwrap();
        held_tx.send(()).unwrap();
        go_rx.recv().unwrap();
        writer.append(5, pk(5)).unwrap();
    });
    held_rx.recv().unwrap();
    s.send(bls_body(bls_request(
        1,
        vec![
            valid_set(0, 1),
            signed_set(vec![inline(5, pk_bytes(5))], &[5], 2),
        ],
    )))
    .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    drop(s); // cl-chain's stream is gone
    tokio::time::sleep(Duration::from_millis(150)).await;
    go_tx.send(()).unwrap();
    appender.join().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        gate.entered(),
        0,
        "nothing of the closed stream was resolved or verified"
    );
    assert_eq!(h.server.contract_violations(), 0);
    drop(release);
}

#[tokio::test]
async fn zero_or_past_deadline_is_answered_without_resolution() {
    let (gate, _release) = Gated::new();
    let mut h = start_with(Options {
        bls: gate.clone(),
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    // Resolving these would be a contract violation (inline key for cached index 1).
    for (id, deadline) in [(1u64, 0u64), (2, now_unix_ms() - 1)] {
        let mut body = bls_request(id, vec![signed_set(vec![inline(1, pk_bytes(1))], &[1], 1)]);
        body.deadline_unix_ms = deadline;
        s.send(bls_body(body)).await;
        assert_eq!(
            outcomes(&bls_reply(&mut s).await),
            vec![Ok(VerifyStatus::DeadlineExceeded)]
        );
    }
    assert_eq!(gate.entered(), 0);
    assert_eq!(h.server.contract_violations(), 0);
}

#[tokio::test]
async fn per_item_contract_violations_are_counted() {
    let mut h = start_with(Options {
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(
        1,
        vec![
            signed_set(vec![inline(1, pk_bytes(1))], &[1], 1),
            valid_set(0, 2),
        ],
    )))
    .await;
    bls_reply(&mut s).await;
    assert_eq!(h.server.contract_violations(), 1);
}
