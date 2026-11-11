#![cfg(feature = "soak")]

use consensus_types::primitives::Root;
use testkit::head_lag::{analyze, Head, Sample};

fn sample(slot: u64, lag: i64) -> Sample {
    Sample::observed(
        slot,
        Head {
            payload_status: None,
            slot: (1000_i64 - lag).try_into().unwrap(),
            root: Root::from([0x11; 32]),
        },
        Head {
            payload_status: None,
            slot: 1000,
            root: Root::from([0x22; 32]),
        },
    )
    .unwrap()
}

#[test]
fn p99_nearest_rank() {
    let values: Vec<_> = (1..=100).map(|i| sample(i, i as i64)).collect();
    assert_eq!(analyze(&values, 32).unwrap().p99, Some(99));
    let mut values: Vec<_> = (0..99).map(|i| sample(i, 0)).collect();
    values.extend([sample(99, 9), sample(100, 9)]);
    assert_eq!(analyze(&values, 32).unwrap().p99, Some(9));
    assert_eq!(analyze(&[], 32).unwrap().p99, None);
    assert_eq!(
        analyze(&[sample(0, -1)], 32).unwrap().p99,
        Some(-1),
        "ahead is signed, not unsigned underflow"
    );
}

#[test]
fn worst_case() {
    let report = analyze(
        &[sample(0, -1), sample(1, 2), sample(2, 32), sample(3, 33)],
        32,
    )
    .unwrap();
    assert_eq!(report.worst, Some(33));
    assert!(report.exceeds_worst());
    assert!(report.exceeds_p99());
    assert!(
        !analyze(&[sample(0, 32)], 32).unwrap().exceeds_worst(),
        "32 is inclusive"
    );
    assert!(
        !analyze(&[sample(0, 2)], 32).unwrap().exceeds_p99(),
        "2 is inclusive"
    );
    assert_eq!(analyze(&[], 32).unwrap().worst, None);
}

#[test]
fn recovery_within_epoch() {
    let timeline: Vec<_> = (0..=32)
        .map(|slot| sample(slot, if slot == 32 { 2 } else { 3 }))
        .collect();
    let report = analyze(&timeline, 32).unwrap();
    assert_eq!(report.recoveries.len(), 1);
    let recovery = &report.recoveries[0];
    assert_eq!(
        (
            recovery.start_slot,
            recovery.end_slot,
            recovery.elapsed_slots
        ),
        (0, Some(32), 32)
    );
    assert!(
        !recovery.over_epoch,
        "exactly one epoch is within the limit"
    );
    let report = analyze(
        &[sample(0, 3), sample(1, 2), sample(2, 4), sample(3, -1)],
        32,
    )
    .unwrap();
    assert_eq!(report.recoveries.len(), 2);
    assert!(report.recoveries.iter().all(|r| r.elapsed_slots == 1));
}

#[test]
fn recovery_over_epoch_flagged() {
    let timeline: Vec<_> = (0..=33)
        .map(|slot| sample(slot, if slot == 33 { 2 } else { 3 }))
        .collect();
    let report = analyze(&timeline, 32).unwrap();
    assert!(report.recoveries[0].over_epoch);
    assert!(report.exceeds_recovery());
    let ongoing = analyze(&timeline[..33], 8).unwrap();
    assert_eq!(ongoing.recoveries[0].end_slot, None);
    assert!(
        ongoing.recoveries[0].over_epoch,
        "open episodes are not silently discarded"
    );
}

#[test]
fn reference_outage_is_counted_and_excluded() {
    use testkit::head_lag::Gap;
    let timeline = [sample(0, 1), Sample::gap(1, Gap::Reference), sample(2, 2)];
    let report = analyze(&timeline, 32).unwrap();
    assert_eq!(
        (report.samples, report.compared, report.gap_samples),
        (3, 2, 1)
    );
    assert_eq!(report.p99, Some(2));
    assert_eq!(report.worst, Some(2));
    assert_eq!(
        report.exit_code(),
        2,
        "incomplete evidence is not a clean pass"
    );
    let report = analyze(
        &[sample(0, 3), Sample::gap(1, Gap::Reference), sample(2, 2)],
        32,
    )
    .unwrap();
    assert_eq!(report.recoveries[0].elapsed_slots, 2);
    assert!(report.recoveries[0].had_gaps);
    let report = analyze(&[sample(0, 3), sample(3, 2)], 32).unwrap();
    assert_eq!(report.gap_samples, 2, "missing JSONL slots are gaps too");
    assert!(report.recoveries[0].had_gaps);
    let report = analyze(&[Sample::gap(0, Gap::Reference)], 32).unwrap();
    assert_eq!((report.p99, report.worst), (None, None));
    assert_eq!(report.exit_code(), 2);
    assert_eq!(analyze(&[], 32).unwrap().exit_code(), 2);
}

#[test]
fn invalid_timelines_and_forged_lag_are_rejected() {
    let mut forged = sample(0, 3);
    forged.lag = Some(0);
    assert!(
        analyze(&[forged], 32).is_err(),
        "JSONL lag is recomputed from snapshots"
    );
    let mut forged = sample(0, 3);
    forged.gap = Some(testkit::head_lag::Gap::Reference);
    assert!(
        analyze(&[forged], 32).is_err(),
        "gaps cannot carry percentile values"
    );
    assert!(analyze(&[sample(1, 0), sample(0, 0)], 32).is_err());
    assert!(analyze(&[sample(0, 0), sample(0, 0)], 32).is_err());
    assert!(analyze(&[], 0).is_err());
    assert!(analyze(&[sample(0, 0), sample(u64::MAX, 0)], 32).is_err());
    assert!(Sample::observed(
        0,
        Head {
            payload_status: None,
            slot: u64::MAX,
            root: Root::ZERO
        },
        Head {
            payload_status: None,
            slot: 0,
            root: Root::ZERO
        }
    )
    .is_err());
}

#[tokio::test]
async fn samples_query_service_and_reference_head_with_outage_gaps() {
    use std::time::Duration;
    use testkit::collector::testing::{FixtureServer, Reply};
    use testkit::head_lag::{observe, Gap};
    use testkit::query_stub::QueryStub;
    use testkit::root_diff::{QuerySource, Reference};
    let first = FixtureServer::start(|_,path| {
        if path == "/eth/v1/beacon/headers/head" {
            Reply::json(&serde_json::json!({"data":{"root":format!("0x{}","aa".repeat(32)),"header":{"message":{"slot":"97","state_root":format!("0x{}","bb".repeat(32))}}}}).to_string())
        } else if path.ends_with("/finality_checkpoints") {
            Reply::json(include_str!("fixtures/root_diff/matching.json"))
        } else { Reply::status(404) }
    }).await;
    let second = FixtureServer::start(|_,path| {
        assert_eq!(path,"/eth/v1/beacon/headers/head");
        Reply::json(&serde_json::json!({"data":{"root":format!("0x{}","cc".repeat(32)),"header":{"message":{"slot":"100"}}}}).to_string())
    }).await;
    let down = FixtureServer::start(|_, _| Reply::status(503)).await;
    let directory = tempfile::tempdir().unwrap();
    let socket = ipc::uds::SocketDir::under(directory.path(), "query-stub").unwrap();
    let timeout = Duration::from_secs(2);
    let server = QueryStub::start(&socket, first.url(""), timeout).unwrap();
    let ours = QuerySource::new(
        socket.socket_path(),
        ipc::peercred::effective_uid(),
        timeout,
    );
    let reference = Reference::new(second.url(""), timeout);
    let value = observe(101, &ours, &reference).await;
    assert_eq!(value.lag, Some(3));
    assert_eq!(value.ours.as_ref().unwrap().slot, 97);
    assert_eq!(
        hex::encode(value.reference.as_ref().unwrap().root),
        "cc".repeat(32)
    );
    let value = observe(102, &ours, &Reference::new(down.url(""), timeout)).await;
    assert_eq!(value.gap, Some(Gap::Reference));
    assert_eq!(value.lag, None);
    assert!(value.ours.is_some());
    server.shutdown().await.unwrap();
}

struct ConstantHead {
    slot: u64,
    calls: std::sync::atomic::AtomicU64,
}
impl ConstantHead {
    fn new(slot: u64) -> Self {
        Self {
            slot,
            calls: 0.into(),
        }
    }
}
impl testkit::head_lag::HeadSource for ConstantHead {
    async fn read_head(&self) -> Result<Head, testkit::head_lag::Error> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Head {
            payload_status: None,
            slot: self.slot,
            root: Root::ZERO,
        })
    }
}

#[tokio::test]
async fn slot_offset_sampler_writes_shared_jsonl_without_drift() {
    use std::time::Duration;
    use testkit::collector::{
        testing::{ManualClock, ManualPause},
        Clock,
    };
    use testkit::head_lag::{run, RunConfig, SlotSchedule};
    let schedule = SlotSchedule::new(1000, 12, Duration::from_secs(4)).unwrap();
    assert_eq!(schedule.due(10).unwrap(), Duration::from_secs(1124));
    assert_eq!(schedule.next_slot(Duration::from_secs(1124)).unwrap(), 10);
    assert_eq!(
        schedule
            .next_slot(Duration::from_secs(1124) + Duration::from_nanos(1))
            .unwrap(),
        11
    );
    assert!(SlotSchedule::new(1000, 12, Duration::from_secs(12)).is_err());
    assert!(SlotSchedule::new(1000, 0, Duration::ZERO).is_err());
    assert!(schedule.due(u64::MAX).is_err());
    let clock = ManualClock::at(1_000_000_000_000);
    let ours = ConstantHead::new(999);
    let reference = ConstantHead::new(1000);
    let mut output = Vec::new();
    let report = run(
        RunConfig {
            schedule,
            first_slot: 10,
            slots: 3,
            slots_per_epoch: 32,
        },
        &ours,
        &reference,
        &*clock,
        &ManualPause(clock.clone()),
        &mut output,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            report.samples,
            report.compared,
            report.gap_samples,
            report.exit_code()
        ),
        (3, 3, 0, 0)
    );
    let records: Vec<Sample> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records.iter().map(|value| value.slot).collect::<Vec<_>>(),
        [10, 11, 12]
    );
    assert!(records
        .iter()
        .all(|value| value.lag == Some(1) && value.ours.is_some() && value.reference.is_some()));
    assert_eq!(
        Duration::from_nanos(clock.now().wall_ns),
        schedule.due(12).unwrap()
    );
}

#[tokio::test]
async fn missed_and_overrun_slots_are_gaps_not_late_matches() {
    use std::time::Duration;
    use testkit::collector::testing::{ManualClock, ManualPause};
    use testkit::head_lag::{run, Gap, RunConfig, SlotSchedule};
    let schedule = SlotSchedule::new(1000, 12, Duration::from_secs(4)).unwrap();
    let clock = ManualClock::at(schedule.due(12).unwrap().as_nanos().try_into().unwrap());
    let ours = ConstantHead::new(999);
    let reference = ConstantHead::new(1000);
    let mut output = Vec::new();
    let report = run(
        RunConfig {
            schedule,
            first_slot: 10,
            slots: 3,
            slots_per_epoch: 32,
        },
        &ours,
        &reference,
        &*clock,
        &ManualPause(clock.clone()),
        &mut output,
    )
    .await
    .unwrap();
    assert_eq!((report.compared, report.gap_samples), (1, 2));
    assert_eq!(ours.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    let values: Vec<Sample> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(values[0].gap, Some(Gap::MissedSample));
    assert_eq!(values[1].lag, None);
    struct Slow {
        clock: std::sync::Arc<ManualClock>,
    }
    impl testkit::head_lag::HeadSource for Slow {
        async fn read_head(&self) -> Result<Head, testkit::head_lag::Error> {
            self.clock.advance(Duration::from_secs(13));
            Ok(Head {
                payload_status: None,
                slot: 1000,
                root: Root::ZERO,
            })
        }
    }
    let clock = ManualClock::at(schedule.due(10).unwrap().as_nanos().try_into().unwrap());
    let report = run(
        RunConfig {
            schedule,
            first_slot: 10,
            slots: 1,
            slots_per_epoch: 32,
        },
        &ours,
        &Slow {
            clock: clock.clone(),
        },
        &*clock,
        &ManualPause(clock.clone()),
        &mut Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        (report.compared, report.gap_samples),
        (0, 1),
        "late responses cannot be assigned to an earlier sample slot"
    );
}

#[tokio::test]
async fn jsonl_analysis_is_bounded_and_validates_records() {
    use testkit::head_lag::analyze_jsonl;
    let mut bytes = serde_json::to_vec(&sample(0, 2)).unwrap();
    bytes.push(b'\n');
    bytes.extend(serde_json::to_vec(&Sample::gap(1, testkit::head_lag::Gap::Reference)).unwrap());
    let report = analyze_jsonl(bytes.as_slice(), 32).await.unwrap();
    assert_eq!((report.p99, report.gap_samples), (Some(2), 1));
    let error = analyze_jsonl(b"private-response-data".as_slice(), 32)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("private-response-data"));
    assert!(analyze_jsonl(vec![b'x'; 4097].as_slice(), 32)
        .await
        .is_err());
    let mut forged = sample(0, 3);
    forged.lag = Some(0);
    assert!(
        analyze_jsonl(serde_json::to_vec(&forged).unwrap().as_slice(), 32)
            .await
            .is_err()
    );
}

#[test]
fn alert_p99() {
    use testkit::head_lag::{AlertKind, Monitor};
    let mut monitor = Monitor::new(12, 32).unwrap();
    for slot in 0..300 {
        assert!(monitor.observe(&sample(slot, 1)).unwrap().is_empty());
    }
    let mut alerts = Vec::new();
    for slot in 300..305 {
        alerts.extend(monitor.observe(&sample(slot, 3)).unwrap());
    }
    let alerts: Vec<_> = alerts
        .iter()
        .filter(|alert| alert.kind == AlertKind::P99)
        .collect();
    assert_eq!(
        alerts.len(),
        1,
        "alert on the rising edge, not every bad sample"
    );
    assert_eq!(alerts[0].slot, 303);
    assert_eq!(alerts[0].window_samples, 300);
    assert_eq!(alerts[0].head_ours, Root::from([0x11; 32]));
    assert_eq!(alerts[0].head_ref, Root::from([0x22; 32]));
    assert!(monitor.observe(&sample(604, 1)).unwrap().is_empty());
    assert!(
        monitor
            .observe(&sample(605, 3))
            .unwrap()
            .iter()
            .any(|alert| alert.kind == AlertKind::P99),
        "old breaches expire after the sliding hour"
    );
}

#[test]
fn alert_worst() {
    use testkit::head_lag::{AlertKind, Monitor};
    let mut monitor = Monitor::new(12, 32).unwrap();
    assert!(!monitor
        .observe(&sample(0, 32))
        .unwrap()
        .iter()
        .any(|a| a.kind == AlertKind::Worst));
    assert_eq!(
        monitor
            .observe(&sample(1, 33))
            .unwrap()
            .iter()
            .filter(|a| a.kind == AlertKind::Worst)
            .count(),
        1
    );
    assert!(!monitor
        .observe(&sample(2, 34))
        .unwrap()
        .iter()
        .any(|a| a.kind == AlertKind::Worst));
    monitor.observe(&sample(3, 2)).unwrap();
    assert!(monitor
        .observe(&sample(4, 33))
        .unwrap()
        .iter()
        .any(|a| a.kind == AlertKind::Worst));
}

#[test]
fn alert_recovery() {
    use testkit::head_lag::{AlertKind, Gap, Monitor};
    let mut monitor = Monitor::new(12, 32).unwrap();
    monitor.observe(&sample(0, 3)).unwrap();
    for slot in 1..=32 {
        assert!(!monitor
            .observe(&Sample::gap(slot, Gap::Reference))
            .unwrap()
            .iter()
            .any(|a| a.kind == AlertKind::Recovery));
    }
    let alerts = monitor.observe(&Sample::gap(33, Gap::Reference)).unwrap();
    let alert = alerts
        .iter()
        .find(|alert| alert.kind == AlertKind::Recovery)
        .unwrap();
    assert_eq!(
        (alert.slot, alert.context_slot, alert.recovery_slots),
        (33, 0, Some(33))
    );
    assert!(alert.had_gaps);
    assert_eq!(alert.head_ours, Root::from([0x11; 32]));
    monitor.observe(&sample(34, 2)).unwrap();
    let mut monitor = Monitor::new(12, 400).unwrap();
    let mut recoveries = Vec::new();
    for slot in 0..=402 {
        recoveries.extend(
            monitor
                .observe(&sample(slot, 3))
                .unwrap()
                .into_iter()
                .filter(|a| a.kind == AlertKind::Recovery),
        );
    }
    assert_eq!(
        recoveries.len(),
        1,
        "ongoing recovery must outlive the sliding-hour buffer"
    );
    assert_eq!(recoveries[0].recovery_slots, Some(401));
}

#[test]
fn no_alert_clean() {
    use testkit::head_lag::{Gap, Monitor};
    let mut monitor = Monitor::new(12, 32).unwrap();
    for slot in 0..400 {
        let record = if slot == 12 {
            Sample::gap(slot, Gap::Reference)
        } else {
            sample(slot, 2)
        };
        assert!(monitor.observe(&record).unwrap().is_empty());
    }
    let metrics = monitor.metrics().unwrap();
    assert!(metrics.contains("# TYPE head_lag_slots gauge"));
    assert!(metrics.contains("head_lag_slots 2\n"));
    assert!(metrics.contains("head_lag_available 1\n"));
    assert!(monitor
        .observe(&Sample::gap(400, Gap::Reference))
        .unwrap()
        .is_empty());
    let metrics = monitor.metrics().unwrap();
    assert!(metrics.contains("head_lag_available 0\n"));
    assert!(
        metrics.contains("head_lag_slots 2\n"),
        "a gap must not fabricate healthy zero lag"
    );
    assert!(monitor.observe(&sample(400, 1)).is_err());
    assert!(Monitor::new(0, 32).is_err());
}

#[tokio::test]
async fn report_golden() {
    use testkit::head_lag::report_jsonl;
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/head_lag/report-timeline.json")).unwrap();
    let mut input = Vec::new();
    let mut slot = 0;
    for entry in fixture.as_array().unwrap() {
        for _ in 0..entry["repeat"].as_u64().unwrap() {
            serde_json::to_writer(&mut input, &sample(slot, entry["lag"].as_i64().unwrap()))
                .unwrap();
            input.push(b'\n');
            slot += 1;
        }
    }
    let report = report_jsonl(input.as_slice(), 12, 32, None).await.unwrap();
    assert_eq!(
        report.markdown(),
        include_str!("fixtures/head_lag/report.md")
    );
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn report_window_preserves_carry_in_and_missing_tail() {
    use testkit::head_lag::window_report;
    let samples: Vec<_> = (0..=7205)
        .map(|slot| sample(slot, if slot < 35 { 3 } else { 1 }))
        .collect();
    let report = window_report(&samples, 12, 32, None).unwrap();
    assert_eq!(report.start_slot, 6);
    assert_eq!(report.summary.p99, Some(1));
    assert_eq!(
        report.summary.recoveries[0].start_slot, 0,
        "recovery must not restart at the report boundary"
    );
    assert_eq!(report.exit_code(), 1);
    let samples: Vec<_> = (0..7200)
        .map(|slot| sample(slot, if slot == 7199 { 3 } else { 1 }))
        .collect();
    assert_eq!(
        window_report(&samples, 12, 32, None).unwrap().exit_code(),
        2,
        "an open recovery is not a completed pass"
    );
    let tail = window_report(&samples, 12, 32, Some(7232)).unwrap();
    assert!(tail.summary.recoveries[0].over_epoch);
    assert!(tail.summary.recoveries[0].had_gaps);
    assert_eq!(tail.exit_code(), 1);
    let missing = window_report(&[sample(10000, 1)], 12, 32, Some(10001)).unwrap();
    assert_eq!(
        (
            missing.summary.samples,
            missing.summary.gap_samples,
            missing.gap_seconds
        ),
        (7200, 7199, 86388)
    );
    assert_eq!(missing.exit_code(), 2);
    assert!(!missing.markdown().contains("Overall: PASS"));
    assert!(window_report(&samples, 7, 32, None).is_err());
}

#[tokio::test]
async fn live_alerts_are_written_during_sampling_with_atomic_metrics() {
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };
    use testkit::collector::{
        testing::{ManualClock, ManualPause},
        Clock,
    };
    use testkit::head_lag::{run_live, RunConfig, SlotSchedule};
    struct LiveWriter {
        clock: Arc<ManualClock>,
        due: u64,
        bytes: Vec<u8>,
    }
    impl tokio::io::AsyncWrite for LiveWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            assert_eq!(
                this.clock.now().wall_ns,
                this.due,
                "alerts must not be deferred until run completion"
            );
            this.bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let schedule = SlotSchedule::new(1000, 12, Duration::from_secs(4)).unwrap();
    let due = schedule.due(10).unwrap().as_nanos().try_into().unwrap();
    let clock = ManualClock::at(due);
    let mut alerts = LiveWriter {
        clock: clock.clone(),
        due,
        bytes: Vec::new(),
    };
    let directory = tempfile::tempdir().unwrap();
    let metrics = directory.path().join("lag.prom");
    std::fs::write(&metrics, "initial").unwrap();
    let summary = run_live(
        RunConfig {
            schedule,
            first_slot: 10,
            slots: 3,
            slots_per_epoch: 32,
        },
        &ConstantHead::new(966),
        &ConstantHead::new(1000),
        &*clock,
        &ManualPause(clock.clone()),
        (&mut Vec::new(), &mut alerts, Some(metrics.as_path())),
    )
    .await
    .unwrap();
    assert_eq!(summary.exit_code(), 1);
    let text = String::from_utf8(alerts.bytes).unwrap();
    assert_eq!(text.lines().count(), 2);
    for line in text.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["slot"], 10);
        assert!(value["head_ours"].is_string());
        assert!(value["head_ref"].is_string());
    }
    assert!(std::fs::read_to_string(&metrics)
        .unwrap()
        .contains("head_lag_slots 34\n"));
    assert!(std::fs::read_to_string(&metrics)
        .unwrap()
        .contains("head_lag_updated_at_seconds 1148\n"));
    assert_eq!(
        std::fs::read_dir(directory.path()).unwrap().count(),
        1,
        "atomic publication must not leave scratch files"
    );
}

#[test]
fn report_is_causal_and_empty_windows_never_pass() {
    use testkit::head_lag::window_report;
    let samples: Vec<_> = (0..=10035)
        .map(|slot| sample(slot, if (10000..10035).contains(&slot) { 3 } else { 1 }))
        .collect();
    assert_eq!(
        window_report(&samples, 12, 32, Some(9999))
            .unwrap()
            .exit_code(),
        0
    );
    let report = window_report(&samples, 12, 32, Some(10000)).unwrap();
    assert_eq!(report.exit_code(), 2);
    assert_eq!(report.summary.recoveries[0].end_slot, None);
    assert_eq!(
        report.summary.recoveries[0].elapsed_slots, 0,
        "future observations cannot resolve or age an earlier report"
    );
    assert_eq!(
        window_report(&samples, 12, 32, None).unwrap().exit_code(),
        1
    );
    let empty = window_report(&[], 12, 32, Some(7199)).unwrap();
    assert_eq!((empty.gap_seconds, empty.exit_code()), (86400, 2));
}

#[test]
fn uncertain_recovery_is_not_proven_but_prior_breaches_stay_sticky() {
    use testkit::head_lag::Gap;
    for explicit in [false, true] {
        let mut timeline: Vec<_> = (0..10_000).map(|slot| sample(slot, 0)).collect();
        timeline.push(sample(10_000, 3));
        if explicit {
            timeline.extend((10_001..10_041).map(|slot| Sample::gap(slot, Gap::Reference)));
        }
        timeline.push(sample(10_041, 0));
        let report = analyze(&timeline, 32).unwrap();
        assert_eq!(report.p99, Some(0));
        assert_eq!(report.recoveries[0].elapsed_slots, 41);
        assert!(report.recoveries[0].had_gaps);
        assert!(
            !report.exceeds_recovery(),
            "missing observations cannot establish a breach"
        );
        assert_eq!(report.exit_code(), 2);
    }
    for proven in [false, true] {
        let mut timeline: Vec<_> = (0..10_000).map(|slot| sample(slot, 0)).collect();
        let end = if proven { 10_034 } else { 10_033 };
        timeline.extend((10_000..end).map(|slot| sample(slot, 3)));
        timeline.push(Sample::gap(end, Gap::Reference));
        let open = analyze(&timeline, 32).unwrap();
        assert_eq!(
            open.exceeds_recovery(),
            proven,
            "a gap itself must not cross the proof boundary"
        );
        timeline.push(sample(end + 1, 0));
        let closed = analyze(&timeline, 32).unwrap();
        assert_eq!(closed.exceeds_recovery(), proven);
        assert_eq!(closed.exit_code(), if proven { 1 } else { 2 });
    }
}

#[tokio::test]
async fn sampled_slot_end_is_exclusive_before_and_after_reads() {
    use std::time::Duration;
    use testkit::collector::testing::{ManualClock, ManualPause};
    use testkit::head_lag::{run, RunConfig, SlotSchedule};
    struct AdvancingHead {
        clock: std::sync::Arc<ManualClock>,
        delay: Duration,
    }
    impl testkit::head_lag::HeadSource for AdvancingHead {
        async fn read_head(&self) -> Result<Head, testkit::head_lag::Error> {
            self.clock.advance(self.delay);
            Ok(Head {
                slot: 10,
                root: Root::ZERO,
                payload_status: None,
            })
        }
    }
    let schedule = SlotSchedule::new(1000, 12, Duration::from_secs(4)).unwrap();
    for (now, delay, compared, calls) in [
        (1131, 0, 1, 1),
        (1132, 0, 0, 0),
        (1133, 0, 0, 0),
        (1124, 7, 1, 1),
        (1124, 8, 0, 1),
        (1124, 9, 0, 1),
    ] {
        let clock = ManualClock::at(now * 1_000_000_000);
        let ours = ConstantHead::new(10);
        let reference = AdvancingHead {
            clock: clock.clone(),
            delay: Duration::from_secs(delay),
        };
        let report = run(
            RunConfig {
                schedule,
                first_slot: 10,
                slots: 1,
                slots_per_epoch: 32,
            },
            &ours,
            &reference,
            &*clock,
            &ManualPause(clock.clone()),
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.compared, compared, "now={now}, delay={delay}");
        assert_eq!(report.gap_samples, 1 - compared);
        assert_eq!(ours.calls.load(std::sync::atomic::Ordering::Relaxed), calls);
    }
}

#[tokio::test]
async fn reference_head_accepts_mixed_case_api_roots() {
    use std::time::Duration;
    use testkit::collector::testing::{FixtureServer, Reply};
    use testkit::head_lag::HeadSource;
    use testkit::root_diff::Reference;
    let api = FixtureServer::start(|_, _| {
        Reply::json(include_str!("fixtures/root_diff/mixed-case-header.json"))
    })
    .await;
    let head = Reference::new(api.url(""), Duration::from_secs(2))
        .read_head()
        .await
        .unwrap();
    assert_eq!(head.slot, 321);
    assert_eq!(head.root, Root::from([0xab; 32]));
}
