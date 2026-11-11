#![cfg(feature = "soak")]

use testkit::root_diff::{compare, parse_finality, Record};
const MATCHING: &[u8] = include_bytes!("fixtures/root_diff/matching.json");
const FINALIZED_MISMATCH: &[u8] = include_bytes!("fixtures/root_diff/finalized-mismatch.json");
const JUSTIFIED_MISMATCH: &[u8] = include_bytes!("fixtures/root_diff/justified-mismatch.json");

fn record(reference: Option<&[u8]>) -> Record {
    compare(
        10,
        Some(parse_finality(MATCHING).unwrap()),
        reference.map(|body| parse_finality(body).unwrap()),
    )
}

#[test]
fn match_no_flag() {
    let record = record(Some(MATCHING));
    assert_eq!(record.r#match, Some(true));
    assert!(!record.is_mismatch());
    assert!(record.gap.is_none());
    let value = serde_json::to_value(record).unwrap();
    assert_eq!(value["epoch"], 10);
    assert_eq!(value["match"], true);
    assert_eq!(value["ours"], value["reference"]);
}

#[test]
fn finalized_mismatch_flags() {
    let record = record(Some(FINALIZED_MISMATCH));
    assert!(record.is_mismatch());
    assert_eq!(record.r#match, Some(false));
    assert!(record.gap.is_none());
}

#[test]
fn justified_mismatch_flags() {
    assert!(record(Some(JUSTIFIED_MISMATCH)).is_mismatch());
    let ours = parse_finality(MATCHING).unwrap();
    let mut reference = ours.clone();
    reference.justified.epoch += 1; // Equal roots with unequal checkpoint epochs still diverge.
    assert!(compare(10, Some(ours), Some(reference)).is_mismatch());
}

#[test]
fn reference_down_is_gap() {
    let record = record(None);
    assert_eq!(record.r#match, None);
    assert_eq!(record.gap, Some(testkit::root_diff::Gap::Reference));
    assert!(!record.is_mismatch());
    let json = serde_json::to_value(record).unwrap();
    assert!(json["match"].is_null());
    assert_eq!(json["gap"], "reference");
    assert_eq!(
        compare(10, None, None).gap,
        Some(testkit::root_diff::Gap::Both)
    );
    assert_eq!(
        compare(10, None, Some(parse_finality(MATCHING).unwrap())).gap,
        Some(testkit::root_diff::Gap::Ours)
    );
}

#[tokio::test]
async fn http_failure_is_gap() {
    use std::time::Duration;
    use testkit::collector::testing::{FixtureServer, Reply};
    use testkit::root_diff::{sample, Reference};
    let good =
        FixtureServer::start(|_, _| Reply::json(std::str::from_utf8(MATCHING).unwrap())).await;
    let down = FixtureServer::start(|_, _| Reply::status(503)).await;
    let ours = Reference::new(good.url(""), Duration::from_secs(2));
    let reference = Reference::new(down.url(""), Duration::from_secs(2));
    let record = sample(10, 321, &ours, &reference).await;
    assert_eq!(record.gap, Some(testkit::root_diff::Gap::Reference));
    assert_eq!(record.r#match, None);
    assert_eq!(
        down.seen()[0].0,
        "/eth/v1/beacon/states/321/finality_checkpoints"
    );
}

#[tokio::test]
async fn query_stub_roundtrip_over_peer_checked_uds() {
    use std::time::Duration;
    use testkit::collector::testing::{FixtureServer, Reply};
    use testkit::query_stub::QueryStub;
    use testkit::root_diff::{sample, QuerySource, Reference};
    let api = FixtureServer::start(|_, path| {
        if path == "/eth/v1/beacon/headers/321" {
            Reply::json(&serde_json::json!({"execution_optimistic":false,"finalized":false,"data":{"root":format!("0x{}", "aa".repeat(32)),"header":{"message":{"slot":"321","state_root":format!("0x{}", "bb".repeat(32))}}}}).to_string())
        } else if path.ends_with("/finality_checkpoints") {
            Reply::json(std::str::from_utf8(MATCHING).unwrap())
        } else { Reply::status(404) }
    }).await;
    let dir = tempfile::tempdir().unwrap();
    let socket = ipc::uds::SocketDir::under(dir.path(), "query-stub").unwrap();
    let timeout = Duration::from_secs(2);
    let server = QueryStub::start(&socket, api.url(""), timeout).unwrap();
    let ours = QuerySource::new(
        socket.socket_path(),
        ipc::peercred::effective_uid(),
        timeout,
    );
    let reference = Reference::new(api.url(""), timeout);
    let record = sample(10, 321, &ours, &reference).await;
    assert_eq!(record.r#match, Some(true), "{record:?}");
    assert!(
        api.seen().iter().any(|(path, _)| path
            == &format!(
                "/eth/v1/beacon/states/0x{}/finality_checkpoints",
                "bb".repeat(32)
            )),
        "stub must pin checkpoints to the header's state root"
    );
    let wrong_uid = QuerySource::new(
        socket.socket_path(),
        ipc::peercred::effective_uid() + 1,
        timeout,
    );
    assert_eq!(
        sample(10, 321, &wrong_uid, &reference).await.gap,
        Some(testkit::root_diff::Gap::Ours)
    );
    server.shutdown().await.unwrap();
    assert!(!socket.socket_path().exists());
}

#[test]
fn epoch_boundary_plus_one_slot_and_checked_arithmetic() {
    use std::time::Duration;
    use testkit::root_diff::Schedule;
    let schedule = Schedule::new(1000, 12, 32).unwrap();
    assert_eq!(schedule.sample_slot(10).unwrap(), 320);
    let due = Duration::from_secs(4852);
    assert_eq!(schedule.due(10).unwrap(), due);
    assert_eq!(schedule.next_epoch(due).unwrap(), 10);
    assert_eq!(
        schedule.next_epoch(due + Duration::from_nanos(1)).unwrap(),
        11
    );
    assert_eq!(schedule.next_epoch(Duration::ZERO).unwrap(), 0);
    assert!(Schedule::new(1000, 0, 32).is_err());
    assert!(Schedule::new(1000, 12, 1).is_err());
    assert!(schedule.due(u64::MAX).is_err());
}

struct Timeline {
    calls: std::sync::Mutex<Vec<u64>>,
    mismatch: Option<u64>,
    down: Option<u64>,
}
impl Timeline {
    fn matching() -> Self {
        Self {
            calls: Default::default(),
            mismatch: None,
            down: None,
        }
    }
}
impl testkit::root_diff::CheckpointSource for Timeline {
    async fn read(
        &self,
        slot: u64,
    ) -> Result<testkit::root_diff::Checkpoints, testkit::root_diff::Error> {
        self.calls.lock().unwrap().push(slot);
        if self.down == Some(slot) {
            return Err(testkit::root_diff::Error::Reference);
        }
        let mut value = parse_finality(MATCHING).unwrap();
        if self.mismatch == Some(slot) {
            value.finalized.epoch += 1;
        }
        Ok(value)
    }
}

#[tokio::test]
async fn scheduled_jsonl_keeps_mismatches_and_gaps() {
    use std::time::Duration;
    use testkit::collector::testing::{ManualClock, ManualPause};
    use testkit::collector::Clock;
    use testkit::root_diff::{run, RunConfig, Schedule};
    let schedule = Schedule::new(1000, 12, 32).unwrap();
    let clock = ManualClock::at(1_000_000_000_000);
    let ours = Timeline::matching();
    let reference = Timeline {
        mismatch: Some(352),
        down: Some(384),
        ..Timeline::matching()
    };
    let mut output = Vec::new();
    let report = run(
        RunConfig {
            schedule,
            first_epoch: 10,
            epochs: 3,
        },
        &ours,
        &reference,
        &*clock,
        &ManualPause(clock.clone()),
        &mut output,
    )
    .await
    .unwrap();
    assert_eq!((report.samples, report.mismatches, report.gaps), (3, 1, 1));
    assert_eq!(
        report.exit_code(),
        1,
        "a later gap must not erase an earlier mismatch"
    );
    let records: Vec<Record> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records.iter().map(|r| r.epoch).collect::<Vec<_>>(),
        [10, 11, 12]
    );
    assert_eq!(records[0].r#match, Some(true));
    assert_eq!(records[1].r#match, Some(false));
    assert_eq!(records[2].r#match, None);
    assert_eq!(*ours.calls.lock().unwrap(), [320, 352, 384]);
    assert_eq!(
        Duration::from_nanos(clock.now().wall_ns),
        schedule.due(12).unwrap()
    );
}

#[tokio::test]
async fn missed_poll_slot_is_gap_without_late_reads() {
    use testkit::collector::testing::{ManualClock, ManualPause};
    use testkit::root_diff::{run, Gap, RunConfig, Schedule};
    let schedule = Schedule::new(1000, 12, 32).unwrap();
    let late = schedule.due(10).unwrap() + std::time::Duration::from_secs(12);
    let clock = ManualClock::at(late.as_nanos().try_into().unwrap());
    let source = Timeline::matching();
    let mut output = Vec::new();
    let report = run(
        RunConfig {
            schedule,
            first_epoch: 10,
            epochs: 1,
        },
        &source,
        &source,
        &*clock,
        &ManualPause(clock.clone()),
        &mut output,
    )
    .await
    .unwrap();
    assert_eq!(report.exit_code(), 2);
    assert!(source.calls.lock().unwrap().is_empty());
    let record: Record = serde_json::from_slice(&output).unwrap();
    assert_eq!(record.gap, Some(Gap::MissedSample));
    assert_eq!(record.r#match, None);
}

#[test]
fn sampling_waits_one_slot_after_the_state_being_compared() {
    let schedule = testkit::root_diff::Schedule::new(1000, 12, 32).unwrap();
    assert_eq!(
        schedule.sample_slot(10).unwrap(),
        320,
        "at the +1-slot poll, compare the completed boundary slot, not a block not produced yet"
    );
    assert_eq!(schedule.due(10).unwrap().as_secs(), 1000 + (320 + 1) * 12);
    assert!(
        testkit::root_diff::Schedule::new(u64::MAX / 1_000_000_000, 12, 32).is_err(),
        "schedule must fit the injected clock's nanosecond range"
    );
}

#[test]
fn malformed_finality_is_rejected_without_echoing_response_data() {
    let original: serde_json::Value = serde_json::from_slice(MATCHING).unwrap();
    for field in ["finalized", "current_justified"] {
        for (key, bad) in [
            ("epoch", serde_json::json!(9)),
            ("epoch", serde_json::json!("+9")),
            ("epoch", serde_json::json!("18446744073709551616")),
            ("root", serde_json::json!("private-response-data")),
            ("root", serde_json::json!(format!("0x{}", "AG".repeat(32)))),
            ("root", serde_json::json!(format!("0x{}", "ab".repeat(31)))),
            ("root", serde_json::json!(format!("0x{}", "ab".repeat(33)))),
            ("root", serde_json::json!(format!("0X{}", "ab".repeat(32)))),
        ] {
            let mut value = original.clone();
            value["data"][field][key] = bad;
            let error = parse_finality(&serde_json::to_vec(&value).unwrap()).unwrap_err();
            assert_eq!(error.to_string(), "invalid finality checkpoint response");
        }
    }
    let parsed = parse_finality(MATCHING).unwrap();
    assert_eq!(parsed.justified.epoch, 9);
    assert_eq!(hex::encode(parsed.justified.root), "22".repeat(32));
}

#[tokio::test]
async fn simulated_hour_two_fixture_cls_one_record_per_epoch() {
    use std::time::Duration;
    use testkit::collector::testing::{FixtureServer, ManualClock, ManualPause, Reply};
    use testkit::query_stub::QueryStub;
    use testkit::root_diff::{run, QuerySource, Reference, RunConfig, Schedule};
    let first = FixtureServer::start(|_,path| {
        if let Some(slot) = path.strip_prefix("/eth/v1/beacon/headers/") {
            Reply::json(&serde_json::json!({"data":{"root":format!("0x{}", "aa".repeat(32)),"header":{"message":{"slot":slot,"state_root":format!("0x{}", "bb".repeat(32))}}}}).to_string())
        } else if path.ends_with("/finality_checkpoints") { Reply::json(std::str::from_utf8(MATCHING).unwrap()) }
        else { Reply::status(404) }
    }).await;
    let second =
        FixtureServer::start(|_, _| Reply::json(std::str::from_utf8(MATCHING).unwrap())).await;
    let dir = tempfile::tempdir().unwrap();
    let socket = ipc::uds::SocketDir::under(dir.path(), "query-stub").unwrap();
    let timeout = Duration::from_secs(2);
    let server = QueryStub::start(&socket, first.url(""), timeout).unwrap();
    let ours = QuerySource::new(
        socket.socket_path(),
        ipc::peercred::effective_uid(),
        timeout,
    );
    let reference = Reference::new(second.url(""), timeout);
    let clock = ManualClock::at(1_000_000_000_000);
    let mut output = Vec::new();
    let report = run(
        RunConfig {
            schedule: Schedule::new(1000, 12, 32).unwrap(),
            first_epoch: 10,
            epochs: 10,
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
            report.mismatches,
            report.gaps,
            report.exit_code()
        ),
        (10, 0, 0, 0)
    );
    let records: Vec<Record> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records
            .iter()
            .map(|record| record.epoch)
            .collect::<Vec<_>>(),
        (10..20).collect::<Vec<_>>()
    );
    assert!(records.iter().all(|record| record.r#match == Some(true)));
    assert_eq!(second.seen().len(), 10);
    server.shutdown().await.unwrap();
}

#[test]
fn mixed_case_finality_roots_are_equivalent() {
    let mixed = include_bytes!("fixtures/root_diff/mixed-case-finality.json");
    let canonical = String::from_utf8(mixed.to_vec())
        .unwrap()
        .to_ascii_lowercase();
    assert_eq!(
        parse_finality(mixed).unwrap(),
        parse_finality(canonical.as_bytes()).unwrap()
    );
}

#[tokio::test]
async fn mixed_case_headers_roundtrip_through_query_stub() {
    use std::time::Duration;
    use testkit::collector::testing::{FixtureServer, Reply};
    use testkit::query_stub::QueryStub;
    use testkit::root_diff::{sample, QuerySource, Reference};
    let api = FixtureServer::start(|_, path| {
        if path == "/eth/v1/beacon/headers/321" {
            Reply::json(include_str!("fixtures/root_diff/mixed-case-header.json"))
        } else if path.ends_with("/finality_checkpoints") {
            Reply::json(include_str!("fixtures/root_diff/mixed-case-finality.json"))
        } else {
            Reply::status(404)
        }
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let socket = ipc::uds::SocketDir::under(dir.path(), "mixed-case").unwrap();
    let timeout = Duration::from_secs(2);
    let server = QueryStub::start(&socket, api.url(""), timeout).unwrap();
    let ours = QuerySource::new(
        socket.socket_path(),
        ipc::peercred::effective_uid(),
        timeout,
    );
    let reference = Reference::new(api.url(""), timeout);
    let record = sample(10, 321, &ours, &reference).await;
    server.shutdown().await.unwrap();
    assert_eq!(record.r#match, Some(true), "{record:?}");
    assert!(api.seen().iter().any(|(path, _)| path
        == &format!(
            "/eth/v1/beacon/states/0x{}/finality_checkpoints",
            "cd".repeat(32)
        )));
}
