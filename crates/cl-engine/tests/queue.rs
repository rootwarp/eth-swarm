//! Ordered delivery and reconnect against the in-crate mock EL.

mod common;

use cl_engine::client::{Backoff, CallError, Config, EngineEndpoint, StartError};
use cl_engine::queue::Queue;
use common::{required_methods, test_secret, MockEl};
use serde_json::json;
use std::time::Duration;

const SECRET: [u8; 32] = [0x11; 32];

fn config(url: &str, secret: cl_engine::jwt::JwtSecret) -> Config {
    Config::new(EngineEndpoint::parse(url, false).unwrap(), secret)
        .backoff(Backoff {
            initial: Duration::from_millis(1),
            cap: Duration::from_millis(8),
        })
        .max_reconnect_attempts(4)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn order_kept() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    let mut seqs: Vec<u64> = (1..=100).collect();
    // Deterministic shuffle so submission order is not seq order.
    let mut state = 0xdec0_u64;
    for i in (1..seqs.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (state as usize) % (i + 1);
        seqs.swap(i, j);
    }
    assert_ne!(&seqs[..10], &(1..=10).collect::<Vec<_>>());
    let mut tasks = Vec::with_capacity(seqs.len());
    for seq in seqs {
        let queue = queue.clone();
        tasks.push(tokio::spawn(async move {
            queue
                .call(
                    seq,
                    "engine_newPayloadV5",
                    json!([seq]),
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let got: Vec<u64> = mock
        .seen()
        .into_iter()
        .filter_map(|seen| seen.seq)
        .collect();
    assert_eq!(got, (1..=100).collect::<Vec<_>>());
}

fn payload_seqs(mock: &MockEl) -> Vec<u64> {
    mock.seen()
        .into_iter()
        .filter(|seen| seen.method == "engine_newPayloadV5")
        .filter_map(|seen| seen.seq)
        .collect()
}

/// Index of the `n`th (0-based) capability exchange in what the mock saw.
fn nth_capabilities(mock: &MockEl, n: usize) -> Option<usize> {
    mock.seen()
        .iter()
        .enumerate()
        .filter(|(_, seen)| seen.method == "engine_exchangeCapabilities")
        .nth(n)
        .map(|(index, _)| index)
}

/// Index of the request carrying `seq` in what the mock saw.
fn position_of(mock: &MockEl, seq: u64) -> Option<usize> {
    mock.seen()
        .iter()
        .position(|seen| seen.method == "engine_newPayloadV5" && seen.seq == Some(seq))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_rechecks_capabilities() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    queue
        .call(1, "engine_newPayloadV5", json!([1]), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(mock.capability_calls(), 1);
    let generation = queue.generation();
    // The EL drops the connection while seq 2 is in flight: the caller gets the error, and the
    // call is not sent again.
    mock.fail_next();
    let err = queue
        .call(2, "engine_newPayloadV5", json!([2]), Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(matches!(err, CallError::Transport), "{err:?}");
    assert_eq!(payload_seqs(&mock), [1, 2], "seq 2 was resent");
    // The next call reconnects first: generation bumped, capabilities re-checked, then sent.
    queue
        .call(3, "engine_newPayloadV5", json!([3]), Duration::from_secs(2))
        .await
        .unwrap();
    assert!(queue.generation() > generation);
    assert_eq!(mock.capability_calls(), 2);
    let recheck = nth_capabilities(&mock, 1).expect("a second capability exchange");
    assert!(
        position_of(&mock, 2).unwrap() < recheck && recheck < position_of(&mock, 3).unwrap(),
        "capabilities must be rechecked after the drop and before the next call: {:?}",
        mock.seen()
            .iter()
            .map(|s| s.method.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(payload_seqs(&mock), [1, 2, 3]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_reply_from_earlier_connection_is_dropped() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    mock.push_result(json!({
        "status": "VALID",
        "validationError": "LATE_REPLY_MARKER_9f3a"
    }));
    mock.hold_next();
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    let caller = queue.clone();
    let task = tokio::spawn(async move {
        caller
            .call(1, "engine_newPayloadV5", json!([1]), Duration::from_secs(5))
            .await
    });
    mock.wait_for_method("engine_newPayloadV5").await;
    let generation = queue.generation();
    queue.reconnect().await.unwrap();
    assert!(queue.generation() > generation);
    mock.release();
    let err = task.await.unwrap().unwrap_err();
    assert!(matches!(err, CallError::StaleConnection), "{err:?}");
    assert!(
        !format!("{err} {err:?}").contains("LATE_REPLY_MARKER_9f3a"),
        "a late body was applied"
    );
    assert_eq!(queue.late_dropped(), 1);
    assert_eq!(payload_seqs(&mock), [1], "the in-flight call was resent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_mid_request_keeps_order() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    mock.push_result(json!({"status": "VALID", "validationError": "LATE_9f3a"}));
    mock.hold_next();
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    // seq 1 is held by the EL; 2..=6 are submitted out of order behind it.
    let mut tasks = Vec::new();
    for seq in [1_u64, 5, 3, 6, 2, 4] {
        let queue = queue.clone();
        tasks.push((
            seq,
            tokio::spawn(async move {
                queue
                    .call(
                        seq,
                        "engine_newPayloadV5",
                        json!([seq]),
                        Duration::from_secs(5),
                    )
                    .await
            }),
        ));
        if seq == 1 {
            mock.wait_for_method("engine_newPayloadV5").await;
        }
    }
    // The connection is replaced mid-request, then the EL answers on the old one.
    queue.reconnect().await.unwrap();
    mock.release();
    for (seq, task) in tasks {
        let result = task.await.unwrap();
        if seq == 1 {
            let err = result.unwrap_err();
            assert!(matches!(err, CallError::StaleConnection), "{err:?}");
        } else {
            let value = result.unwrap();
            assert!(!value.to_string().contains("LATE_9f3a"), "{value}");
        }
    }
    assert_eq!(queue.late_dropped(), 1);
    assert_eq!(mock.capability_calls(), 2);
    assert_eq!(payload_seqs(&mock), [1, 2, 3, 4, 5, 6]);
    let recheck = nth_capabilities(&mock, 1).unwrap();
    assert!(recheck < position_of(&mock, 2).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_does_not_wedge_the_queue() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    mock.set_delay(Duration::from_secs(2));
    let err = queue
        .call(
            1,
            "engine_newPayloadV5",
            json!([1]),
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CallError::Timeout), "{err:?}");
    mock.set_delay(Duration::ZERO);
    let started = std::time::Instant::now();
    let value = queue
        .call(2, "engine_newPayloadV5", json!([2]), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(value["status"], "VALID");
    assert!(started.elapsed() < Duration::from_secs(1), "queue was held");
    assert_eq!(payload_seqs(&mock), [1, 2], "the timed-out call was resent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_els_do_not_cross() {
    let secret_a = test_secret([0x11; 32]);
    let secret_b = test_secret([0x22; 32]);
    let mock_a = MockEl::start(secret_a.expose_secret(), required_methods()).await;
    let mock_b = MockEl::start(secret_b.expose_secret(), required_methods()).await;
    let queue_a = Queue::connect(config(&mock_a.url(), secret_a), 1)
        .await
        .unwrap();
    let queue_b = Queue::connect(config(&mock_b.url(), secret_b), 1)
        .await
        .unwrap();
    let mut tasks = Vec::new();
    for seq in (1..=40_u64).rev() {
        for (queue, el) in [(&queue_a, 0_u64), (&queue_b, 1)] {
            let queue = queue.clone();
            tasks.push(tokio::spawn(async move {
                queue
                    .call(
                        seq,
                        "engine_newPayloadV5",
                        json!([seq, el]),
                        Duration::from_secs(5),
                    )
                    .await
                    .unwrap();
            }));
        }
    }
    for task in tasks {
        task.await.unwrap();
    }
    let expected: Vec<u64> = (1..=40).collect();
    assert_eq!(payload_seqs(&mock_a), expected);
    assert_eq!(payload_seqs(&mock_b), expected);
    assert_eq!(mock_a.capability_calls(), 1);
    assert_eq!(mock_b.capability_calls(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_without_capabilities_does_not_resume() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    mock.set_methods(&["engine_newPayloadV4", "engine_forkchoiceUpdatedV3"]);
    let err = queue.reconnect().await.unwrap_err();
    assert!(matches!(err, StartError::MissingCaps(_)), "{err}");
    assert!(!queue.session().is_connected());
}

/// Runs `fut`, failing the test instead of hanging when it takes longer than `within`.
async fn bounded<T>(within: Duration, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(within, fut)
        .await
        .expect("the queue wedged")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_behind_a_gap_that_never_fills_times_out_unsent() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    // seq 1 is never submitted (for example, the server rejected it before the queue).
    let started = std::time::Instant::now();
    let err = bounded(
        Duration::from_secs(3),
        queue.call(
            2,
            "engine_newPayloadV5",
            json!([2]),
            Duration::from_millis(200),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, CallError::Timeout), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(1));
    // The gap was skipped when seq 2 expired: seq 3 runs, and a late seq 1 is refused.
    let value = bounded(
        Duration::from_secs(3),
        queue.call(3, "engine_newPayloadV5", json!([3]), Duration::from_secs(2)),
    )
    .await
    .unwrap();
    assert_eq!(value["status"], "VALID");
    let err = bounded(
        Duration::from_secs(3),
        queue.call(1, "engine_newPayloadV5", json!([1]), Duration::from_secs(2)),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, CallError::Sequence), "{err:?}");
    assert_eq!(payload_seqs(&mock), [3], "an expired or late call was sent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gap_is_skipped_when_a_waiting_call_expires() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    let long = {
        let queue = queue.clone();
        tokio::spawn(async move {
            queue
                .call(2, "engine_newPayloadV5", json!([2]), Duration::from_secs(5))
                .await
        })
    };
    // seq 3 has the earlier deadline. When it passes, the missing seq 1 is skipped, seq 2 runs
    // in order, and seq 3 is answered with a timeout without being sent.
    let short = bounded(
        Duration::from_secs(3),
        queue.call(
            3,
            "engine_newPayloadV5",
            json!([3]),
            Duration::from_millis(200),
        ),
    )
    .await;
    assert!(matches!(short, Err(CallError::Timeout)), "{short:?}");
    let value = bounded(Duration::from_secs(3), long)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(value["status"], "VALID");
    assert_eq!(payload_seqs(&mock), [2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_call_is_never_sent() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    let waiting = {
        let queue = queue.clone();
        tokio::spawn(async move {
            queue
                .call(2, "engine_newPayloadV5", json!([2]), Duration::from_secs(5))
                .await
        })
    };
    // Let seq 2 reach the worker and wait behind seq 1, then drop its caller.
    tokio::time::sleep(Duration::from_millis(50)).await;
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    for seq in [1_u64, 3] {
        bounded(
            Duration::from_secs(3),
            queue.call(
                seq,
                "engine_newPayloadV5",
                json!([seq]),
                Duration::from_secs(2),
            ),
        )
        .await
        .unwrap();
    }
    assert_eq!(payload_seqs(&mock), [1, 3], "the cancelled seq 2 was sent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn released_seq_does_not_hold_later_calls() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    // seq 1 is released now; seq 3 is released before seq 2 has run.
    queue.release(1).await.unwrap();
    queue.release(3).await.unwrap();
    let started = std::time::Instant::now();
    for seq in [2_u64, 4] {
        bounded(
            Duration::from_secs(3),
            queue.call(
                seq,
                "engine_newPayloadV5",
                json!([seq]),
                Duration::from_secs(5),
            ),
        )
        .await
        .unwrap();
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "a release was ignored"
    );
    for seq in [1_u64, 3] {
        let err = queue
            .call(
                seq,
                "engine_newPayloadV5",
                json!([seq]),
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, CallError::Sequence), "{err:?}");
    }
    assert_eq!(payload_seqs(&mock), [2, 4]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reconnects_leave_a_working_connection() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    let mut seq = 1_u64;
    for _ in 0..10 {
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let queue = queue.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                queue.reconnect().await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert!(queue.session().is_connected());
        bounded(
            Duration::from_secs(3),
            queue.call(
                seq,
                "engine_newPayloadV5",
                json!([seq]),
                Duration::from_secs(2),
            ),
        )
        .await
        .unwrap();
        seq += 1;
    }
    assert_eq!(payload_seqs(&mock), (1..seq).collect::<Vec<_>>());
}

/// Seqs 2 and 3 are queued and seq 1 never comes. Seq 2 fails at its own deadline without
/// hanging and is never sent; after the gap is skipped, seq 3 and then seq 4 still go out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gap_expiry_fails_the_waiting_call_at_its_deadline_and_later_seqs_run() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let two = {
        let queue = queue.clone();
        tokio::spawn(async move {
            let result = queue
                .call(
                    2,
                    "engine_newPayloadV5",
                    json!([2]),
                    Duration::from_millis(300),
                )
                .await;
            (result, started.elapsed())
        })
    };
    let three = {
        let queue = queue.clone();
        tokio::spawn(async move {
            queue
                .call(3, "engine_newPayloadV5", json!([3]), Duration::from_secs(3))
                .await
        })
    };
    let (two, two_took) = bounded(Duration::from_secs(3), two).await.unwrap();
    assert!(matches!(two, Err(CallError::Timeout)), "{two:?}");
    assert!(two_took >= Duration::from_millis(290), "{two_took:?}");
    assert!(two_took < Duration::from_secs(1), "{two_took:?}");
    let three = bounded(Duration::from_secs(3), three)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(three["status"], "VALID");
    let four = bounded(
        Duration::from_secs(3),
        queue.call(4, "engine_newPayloadV5", json!([4]), Duration::from_secs(2)),
    )
    .await
    .unwrap();
    assert_eq!(four["status"], "VALID");
    assert_eq!(
        payload_seqs(&mock),
        [3, 4],
        "seq 2 reached the EL after its caller gave up"
    );
}

/// Time spent queued behind a slow call must not come out of the EL's response timeout:
/// the response timeout starts when the request is sent (execution-apis `common.md`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_wait_does_not_shorten_the_el_response_timeout() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    mock.set_delay(Duration::from_millis(400));
    let first = {
        let queue = queue.clone();
        tokio::spawn(async move {
            queue
                .call(1, "engine_newPayloadV5", json!([1]), Duration::from_secs(2))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Queued for about 350 ms, then the EL takes 400 ms: over 600 ms in total, but the EL
    // answered inside its 600 ms timeout counted from the send.
    let second = bounded(
        Duration::from_secs(3),
        queue.call(
            2,
            "engine_newPayloadV5",
            json!([2]),
            Duration::from_millis(600),
        ),
    )
    .await
    .unwrap();
    assert_eq!(second["status"], "VALID");
    assert_eq!(first.await.unwrap().unwrap()["status"], "VALID");
    assert_eq!(payload_seqs(&mock), [1, 2]);
}

/// A call whose queue deadline passes while it waits behind a running call is answered at
/// that deadline and never sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_expiring_while_queued_behind_a_running_call_is_not_sent() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let queue = Queue::connect(config(&mock.url(), secret), 1)
        .await
        .unwrap();
    mock.set_delay(Duration::from_millis(600));
    let first = {
        let queue = queue.clone();
        tokio::spawn(async move {
            queue
                .call(1, "engine_newPayloadV5", json!([1]), Duration::from_secs(2))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let started = std::time::Instant::now();
    let err = bounded(
        Duration::from_secs(3),
        queue.call(
            2,
            "engine_newPayloadV5",
            json!([2]),
            Duration::from_millis(200),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, CallError::Timeout), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_millis(450),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(first.await.unwrap().unwrap()["status"], "VALID");
    mock.set_delay(Duration::ZERO);
    queue
        .call(3, "engine_newPayloadV5", json!([3]), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(payload_seqs(&mock), [1, 3], "the expired call was sent");
}
