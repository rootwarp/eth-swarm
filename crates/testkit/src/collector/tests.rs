//! The collector's acceptance tests: slot-relative and envelope-relative offsets on fixtures,
//! and an SSE disconnect recorded as a missing interval.

use super::*;
use consensus_types::primitives::Root;
use testing;

const MS: u64 = 1_000_000;
/// Hoodi's `genesis_time` (2025-03-17 12:10:00 UTC); any value works.
const GENESIS: u64 = 1_742_213_400;
const SLOT_MS: u64 = 12_000;

fn record(slot: Option<u64>, wall_ns: u64) -> ArrivalRecord {
    ArrivalRecord {
        source: Source::Gossip,
        topic: "beacon_block".into(),
        subnet: None,
        msg_id: None,
        block_root: None,
        slot,
        recv_mono_ns: 0,
        recv_wall_ns: wall_ns,
        peer: None,
    }
}

#[test]
fn slot_offset_fixture() {
    let clock = SlotClock::new(GENESIS, SLOT_MS).unwrap();
    let wall = GENESIS * 1_000 * MS + 3 * SLOT_MS * MS + 1_500 * MS;
    let want = SlotOffset {
        slot: 3,
        offset_ns: 1_500 * MS as i64,
    };
    // The record's own slot, and the wall-clock slot when the record has none.
    assert_eq!(clock.offset(&record(Some(3), wall)), Some(want));
    assert_eq!(clock.offset(&record(None, wall)), Some(want));
    assert_eq!(want.offset_ms(), 1_500.0);
}

fn arrival(source: Source, topic: &str, root: Option<u8>, mono_ms: u64) -> ArrivalRecord {
    ArrivalRecord {
        source,
        topic: topic.into(),
        subnet: None,
        msg_id: None,
        block_root: root.map(Root::repeat_byte),
        slot: Some(9),
        recv_mono_ns: mono_ms * MS,
        recv_wall_ns: GENESIS * 1_000 * MS + mono_ms * MS,
        peer: None,
    }
}

#[test]
fn envelope_relative_fixture() {
    let records = [
        arrival(Source::Gossip, "beacon_block", Some(1), 900),
        arrival(Source::Gossip, "execution_payload", Some(1), 1_000),
        // 800 ms after its envelope.
        arrival(Source::Gossip, "data_column_sidecar_3", Some(1), 1_800),
        // No envelope for this root.
        arrival(Source::Gossip, "data_column_sidecar_4", Some(2), 1_900),
    ];
    let got = envelope_relative(&records);
    assert_eq!(
        got.columns,
        vec![ColumnOffset {
            record: 2,
            block_root: Root::repeat_byte(1),
            offset_ns: 800 * MS as i64,
        }]
    );
    assert_eq!(got.columns[0].offset_ms(), 800.0);
    assert_eq!(got.unmatched_columns, 1);
}

const FIXTURE: &str = include_str!("fixtures/hoodi-events.sse");
const DROP_MARKER: &str = ": fixture: the reference node drops the stream here\n";

fn info(sources: Vec<Source>) -> CaptureInfo {
    CaptureInfo {
        network: "hoodi".into(),
        genesis_time: GENESIS,
        slot_duration_ms: SLOT_MS,
        column_subnet_count: 128,
        sources,
        sse_topics: DEFAULT_TOPICS.iter().map(|t| (*t).to_owned()).collect(),
        host: "test".into(),
        time_daemon: "none".into(),
        started_mono_ns: 0,
        started_wall_ns: GENESIS * 1_000 * MS,
    }
}

#[tokio::test]
async fn sse_gap_recorded() {
    use crate::archive::fixtures::{chain, Spec};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use testing::{FixtureServer, ManualClock, ManualPause, Reply};
    use tokio::sync::watch;

    const DOWN: Duration = Duration::from_secs(30);
    let (before, after) = FIXTURE
        .split_once(DROP_MARKER)
        .expect("the fixture's drop marker");
    let want_events = SseParser::default().feed(FIXTURE.as_bytes()).unwrap().len();
    assert_eq!(want_events, 10);

    // The node streams the first half and drops the connection, answers 503 for 30 s, then
    // streams the second half.
    let start = (GENESIS * 1_000 + 100 * SLOT_MS + 500) * MS;
    let clock = ManualClock::at(start);
    let dropped_at = Arc::new(Mutex::new(0u64));
    let server = FixtureServer::start({
        let (clock, dropped_at) = (Arc::clone(&clock), Arc::clone(&dropped_at));
        move |n, _| {
            let now = clock.now().mono_ns;
            let mut dropped_at = dropped_at.lock().unwrap();
            if n == 0 {
                *dropped_at = now;
                Reply::stream(vec![before], false)
            } else if now - *dropped_at < DOWN.as_nanos() as u64 {
                Reply::status(503)
            } else {
                Reply::stream(vec![after], true)
            }
        }
    })
    .await;
    let mut config = SseConfig::new(server.url(""), &DEFAULT_TOPICS).unwrap();
    config.backoff = Backoff {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(1),
    };

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("capture");
    let mut collector =
        Collector::<Spec>::create(&out, info(vec![Source::Sse]), chain(), None).unwrap();
    let (arrivals, mut rx) = Arrivals::channel(64);
    let (stop_tx, stop) = watch::channel(false);
    let client = tokio::spawn({
        let (clock, arrivals) = (Arc::clone(&clock), arrivals.clone());
        async move {
            let pause = ManualPause(Arc::clone(&clock));
            run_sse(&config, &*clock, &pause, &arrivals, stop).await
        }
    });
    let mut events = 0;
    let mut logged = Vec::new();
    while events < want_events {
        let arrival = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("an arrival within 10 s")
            .unwrap();
        events += usize::from(matches!(arrival, Arrival::Sse(_)));
        logged.extend(collector.handle(arrival).unwrap());
    }
    stop_tx.send(true).unwrap();
    let stats = client.await.unwrap();
    drop(arrivals);
    while let Some(arrival) = rx.recv().await {
        logged.extend(collector.handle(arrival).unwrap());
    }
    let summary = collector.finish(0).unwrap();

    // One missing interval: the 30 s the node was down, from the last bytes of the first stream
    // to the response of the second, after 29 refused reconnects.
    assert_eq!(stats.gaps, 1);
    assert_eq!(summary.missing.len(), 1, "{summary:?}");
    let gap = &summary.missing[0];
    assert_eq!(gap.source, Source::Sse);
    assert_eq!(gap.duration_ns(), DOWN.as_nanos() as u64);
    assert_eq!(
        (gap.start_wall_ns, gap.end_wall_ns),
        (start, start + 30_000 * MS)
    );
    assert_eq!(gap.failed_attempts, 29);
    assert_eq!(gap.reason, "/eth/v1/events: the stream ended");
    assert!(!gap.open_at_shutdown);
    assert!(
        logged.iter().any(|l| l.contains("missing interval")),
        "{logged:?}"
    );

    // On disk: gaps.jsonl and the summary carry it; the records sit on either side of it.
    let gaps = std::fs::read_to_string(out.join(GAPS_FILE)).unwrap();
    let on_disk: Vec<MissingInterval> = gaps
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(on_disk, summary.missing);
    let toml_summary: Summary =
        toml::from_str(&std::fs::read_to_string(out.join(SUMMARY_FILE)).unwrap()).unwrap();
    assert_eq!(toml_summary, summary);
    let (read_info, records) = read_capture(&out).unwrap();
    assert_eq!(read_info, info(vec![Source::Sse]));
    assert_eq!(records.len(), want_events);
    let (early, late): (Vec<_>, Vec<_>) = records
        .iter()
        .partition(|r| r.recv_wall_ns <= gap.start_wall_ns);
    assert_eq!((early.len(), late.len()), (6, 4));
    assert!(late.iter().all(|r| r.recv_wall_ns >= gap.end_wall_ns));
    assert!(early.iter().all(|r| r.slot == Some(100)));
    assert!(late.iter().all(|r| r.slot == Some(103)));
}
