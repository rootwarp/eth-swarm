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
