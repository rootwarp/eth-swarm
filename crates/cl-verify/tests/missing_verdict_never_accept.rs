//! missing_verdict_never_accept: a deadline miss, an overloaded or failing verifier, or a failed
//! stream yields a non-verdict result that the client maps to IGNORE. No path answers VALID
//! without a successful check, and no result is left unset.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cl_verify::bls::{BlsBackend, PreparedSet};
use cl_verify::client::{bls_verdicts, bls_verdicts_by, kzg_verdict, kzg_verdict_by};
use cl_verify::kzg::{KzgBackend, KzgFailure, PreparedCells};
use cl_verify::proto::common::{ErrorCode, Verdict};
use cl_verify::proto::verify::{
    verify_bls_response, KzgCellProof, VerifyBlsResponseBody, VerifyKzgRequestBody, VerifyStatus,
};
use cl_verify::server::Limits;
use cl_verify::wire::{now_unix_ms, Deadline, SystemClock, WallClock};
use common::*;
use tonic::Status;

/// Answers "valid" for everything, but only after `delay`.
struct Slow(Duration);
impl BlsBackend for Slow {
    fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
        std::thread::sleep(self.0);
        vec![true; sets.len()]
    }
}
impl KzgBackend for Slow {
    fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
        std::thread::sleep(self.0);
        Ok(true)
    }
}

struct Panics;
impl BlsBackend for Panics {
    fn verify(&self, _: &[PreparedSet]) -> Vec<bool> {
        panic!("verifier crashed")
    }
}
impl KzgBackend for Panics {
    fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
        panic!("verifier crashed")
    }
}

/// Answers "valid", but blocks each call until the test releases it.
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

fn zero_cell() -> KzgCellProof {
    KzgCellProof {
        commitment: [&[0xc0u8][..], &[0u8; 47][..]].concat(),
        cell_index: 0,
        cell: vec![0; 2048],
        proof: [&[0xc0u8][..], &[0u8; 47][..]].concat(),
    }
}

fn kzg_request(request_id: u64, deadline_unix_ms: u64) -> VerifyKzgRequestBody {
    VerifyKzgRequestBody {
        request_id,
        cells: vec![zero_cell()],
        deadline_unix_ms,
    }
}

/// Every result is set and none is VALID.
fn assert_no_verdict(b: &VerifyBlsResponseBody) {
    for r in &b.results {
        assert!(r.result.is_some(), "unset result");
        assert_ne!(outcome(r), Ok(VerifyStatus::Valid));
    }
}

#[tokio::test]
async fn server_deadline_miss_is_deadline_exceeded_and_ignore() {
    let slow = Arc::new(Slow(Duration::from_millis(1_500)));
    let mut h = start_with(Options {
        bls: slow.clone(),
        kzg: slow,
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    let mut body = bls_request(5, vec![valid_set(0, 1), valid_set(1, 2)]);
    body.deadline_unix_ms = now_unix_ms() + 150;
    s.send(bls_body(body)).await;
    let r = bls_reply(&mut s).await;
    assert_eq!(outcomes(&r), vec![Ok(VerifyStatus::DeadlineExceeded); 2]);
    assert_no_verdict(&r);
    assert_eq!(bls_verdicts(Ok(r), 5, 2), vec![Verdict::Ignore; 2]);

    let mut k = kzg_open(&mut h).await;
    k.send(kzg_body(kzg_request(6, now_unix_ms() + 150))).await;
    let r = kzg_reply(&mut k).await;
    assert_eq!(r.status, VerifyStatus::DeadlineExceeded as i32);
    assert_eq!(kzg_verdict(Ok(r), 6), Verdict::Ignore);
}

#[tokio::test]
async fn expired_or_unset_deadline_is_never_verified() {
    let gate = Arc::new(Gated {
        release: Mutex::new(std_mpsc::channel().1),
        entered: AtomicUsize::new(0),
    });
    let mut h = start_with(Options {
        bls: gate.clone(),
        cache: cache_of(1),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    for (id, deadline) in [(1u64, 0u64), (2, now_unix_ms() - 1)] {
        let mut body = bls_request(id, vec![valid_set(0, 1)]);
        body.deadline_unix_ms = deadline;
        s.send(bls_body(body)).await;
        let r = bls_reply(&mut s).await;
        assert_eq!(outcomes(&r), vec![Ok(VerifyStatus::DeadlineExceeded)]);
    }
    let mut k = kzg_open(&mut h).await;
    k.send(kzg_body(kzg_request(3, 0))).await;
    assert_eq!(
        kzg_reply(&mut k).await.status,
        VerifyStatus::DeadlineExceeded as i32
    );
    assert_eq!(gate.entered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn verifier_failure_is_an_err_result_and_ignore() {
    let mut h = start_with(Options {
        bls: Arc::new(Panics),
        kzg: Arc::new(Panics),
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(
        9,
        vec![valid_set(0, 1), valid_set(1, 2)],
    )))
    .await;
    let r = bls_reply(&mut s).await;
    assert_eq!(outcomes(&r), vec![Err(ErrorCode::ResourceUnavailable); 2]);
    assert_no_verdict(&r);
    assert_eq!(bls_verdicts(Ok(r), 9, 2), vec![Verdict::Ignore; 2]);

    let mut k = kzg_open(&mut h).await;
    k.send(kzg_body(kzg_request(10, far_deadline()))).await;
    let r = kzg_reply(&mut k).await;
    assert_ne!(r.status, VerifyStatus::Valid as i32);
    assert_ne!(r.status, VerifyStatus::Unspecified as i32);
    assert_eq!(
        r.err.as_ref().unwrap().code(),
        ErrorCode::ResourceUnavailable
    );
    assert_eq!(kzg_verdict(Ok(r), 10), Verdict::Ignore);
    // The stream survives a verifier failure.
    s.send(bls_body(bls_request(11, vec![]))).await;
    assert_eq!(bls_reply(&mut s).await.request_id, 11);
}

#[tokio::test]
async fn no_free_verifier_is_overloaded_and_ignore() {
    let (release, gate_rx) = std_mpsc::channel();
    let gate = Arc::new(Gated {
        release: Mutex::new(gate_rx),
        entered: AtomicUsize::new(0),
    });
    let mut h = start_with(Options {
        bls: gate.clone(),
        limits: Limits {
            max_in_flight: 1,
            ..Limits::default()
        },
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(1, vec![valid_set(0, 1)])))
        .await;
    while gate.entered.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    s.send(bls_body(bls_request(2, vec![valid_set(1, 2)])))
        .await;
    let r = bls_reply(&mut s).await;
    assert_eq!(r.request_id, 2);
    assert_eq!(outcomes(&r), vec![Ok(VerifyStatus::Overloaded)]);
    assert_eq!(bls_verdicts(Ok(r), 2, 1), vec![Verdict::Ignore]);
    release.send(()).unwrap();
    let r = bls_reply(&mut s).await;
    assert_eq!(
        (r.request_id, outcomes(&r)),
        (1, vec![Ok(VerifyStatus::Valid)])
    );
}

#[tokio::test]
async fn caller_deadline_miss_on_a_live_stream_is_ignore() {
    let slow = Arc::new(Slow(Duration::from_millis(1_000)));
    let mut h = start_with(Options {
        bls: slow.clone(),
        kzg: slow,
        cache: cache_of(1),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    // The server would answer VALID after 1 s; the caller gives up after 100 ms.
    s.send(bls_body(bls_request(1, vec![valid_set(0, 1)])))
        .await;
    let deadline = Deadline::new(now_unix_ms() + 100, &SystemClock).unwrap();
    let next = async {
        match s.rx.message().await? {
            Some(m) => match m.frame {
                Some(verify_bls_response::Frame::Body(b)) => Ok(Some(b)),
                _ => Err(Status::internal("unexpected frame")),
            },
            None => Ok(None),
        }
    };
    assert_eq!(
        bls_verdicts_by(&deadline, &SystemClock, 1, 1, next).await,
        vec![Verdict::Ignore]
    );

    let mut k = kzg_open(&mut h).await;
    k.send(kzg_body(kzg_request(2, far_deadline()))).await;
    let deadline = Deadline::new(now_unix_ms() + 100, &SystemClock).unwrap();
    let next = async {
        k.rx.message().await.map(|m| {
            m.and_then(|m| match m.frame {
                Some(cl_verify::proto::verify::verify_kzg_response::Frame::Body(b)) => Some(b),
                _ => None,
            })
        })
    };
    assert_eq!(
        kzg_verdict_by(&deadline, &SystemClock, 2, next).await,
        Verdict::Ignore
    );
}

#[tokio::test]
async fn failed_stream_maps_every_pending_set_to_ignore() {
    let mut h = start_with(Options {
        cache: cache_of(1),
        ..Options::default()
    })
    .await;
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(1, vec![valid_set(0, 1); 257])))
        .await;
    let status = loop {
        match s.next().await {
            Err(status) => break status,
            Ok(Some(_)) => continue,
            Ok(None) => panic!("stream closed without status"),
        }
    };
    assert_eq!(
        bls_verdicts(Err(status), 1, 257),
        vec![Verdict::Ignore; 257]
    );
}

/// Answers "valid", stepping the wall clock an hour forward while it works.
struct JumpsClock(Arc<SteppedClock>);
impl BlsBackend for JumpsClock {
    fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
        self.0.jump(3_600_000);
        vec![true; sets.len()]
    }
}
impl KzgBackend for JumpsClock {
    fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
        self.0.jump(3_600_000);
        Ok(true)
    }
}

#[tokio::test]
async fn wall_clock_jump_during_verification_is_deadline_exceeded_never_valid() {
    let clock = Arc::new(SteppedClock::default());
    let jumps = Arc::new(JumpsClock(Arc::clone(&clock)));
    let mut h = start_with(Options {
        bls: jumps.clone(),
        kzg: jumps,
        cache: cache_of(1),
        clock: clock.clone(),
        ..Options::default()
    })
    .await;
    // The monotonic deadline is 30 s away; only the wall clock passes the wire deadline.
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(1, vec![valid_set(0, 1)])))
        .await;
    let r = bls_reply(&mut s).await;
    assert_eq!(outcomes(&r), vec![Ok(VerifyStatus::DeadlineExceeded)]);
    assert_eq!(bls_verdicts(Ok(r), 1, 1), vec![Verdict::Ignore]);

    let mut k = kzg_open(&mut h).await;
    k.send(kzg_body(kzg_request(2, clock.now_unix_ms() + 30_000)))
        .await;
    let r = kzg_reply(&mut k).await;
    assert_eq!(r.status, VerifyStatus::DeadlineExceeded as i32);
    assert_eq!(kzg_verdict(Ok(r), 2), Verdict::Ignore);
}

#[tokio::test]
async fn kzg_job_that_waited_past_its_deadline_does_no_work() {
    #[derive(Default)]
    struct CountingKzg(AtomicUsize);
    impl KzgBackend for CountingKzg {
        fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
    }
    let kzg = Arc::new(CountingKzg::default());
    let mut h = start_with(Options {
        kzg: kzg.clone(),
        // Admission reads the clock once; by the time the blocking job runs the deadline is gone.
        clock: Arc::new(ExpiresAfterReads {
            reads: AtomicUsize::new(0),
            open_reads: 1,
        }),
        ..Options::default()
    })
    .await;
    let mut k = kzg_open(&mut h).await;
    k.send(kzg_body(kzg_request(1, far_deadline()))).await;
    let r = kzg_reply(&mut k).await;
    assert_eq!(r.status, VerifyStatus::DeadlineExceeded as i32);
    assert_eq!(kzg.0.load(Ordering::SeqCst), 0, "verify_cells never ran");
}
