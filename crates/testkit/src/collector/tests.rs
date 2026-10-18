//! The collector's acceptance tests: slot-relative and envelope-relative offsets on fixtures,
//! an SSE disconnect recorded as a missing interval, the topic-set manifest, and per-topic
//! rates against a hand-counted fixture.

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
        bytes: 0,
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
        bytes: 0,
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
        ..CaptureInfo::default()
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
    let (arrivals, mut rx) = Arrivals::channel(64, usize::MAX);
    let (stop_tx, stop) = watch::channel(false);
    let client = tokio::spawn({
        let (clock, arrivals) = (Arc::clone(&clock), arrivals.clone());
        async move {
            let pause = ManualPause(Arc::clone(&clock));
            let started = clock.now();
            run_sse(&config, &*clock, &pause, &arrivals, started, stop).await
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

    // Two missing intervals: the moment before the first stream (none on a clock that stood
    // still), and the 30 s the node was down, from the last bytes of the first stream to the
    // response of the second, after 29 refused reconnects.
    assert_eq!(stats.gaps, 2);
    assert_eq!(summary.missing_intervals, 2, "{summary:?}");
    assert_eq!(summary.missing_ns, DOWN.as_nanos() as u64);
    assert_eq!(summary.missing_open_at_shutdown, 0);
    assert!(
        logged.iter().any(|l| l.contains("missing interval")),
        "{logged:?}"
    );

    // On disk: gaps.jsonl lists them, the summary counts them and points to it; the records sit
    // on either side of the outage.
    let gaps = std::fs::read_to_string(out.join(&summary.gaps_file)).unwrap();
    let on_disk: Vec<MissingInterval> = gaps
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(on_disk.len(), 2);
    assert_eq!(
        (on_disk[0].start_wall_ns, on_disk[0].duration_ns()),
        (start, 0)
    );
    assert_eq!(on_disk[0].reason, "/eth/v1/events: not connected yet");
    let gap = &on_disk[1];
    assert_eq!(gap.source, Source::Sse);
    assert_eq!(gap.duration_ns(), DOWN.as_nanos() as u64);
    assert_eq!(
        (gap.start_wall_ns, gap.end_wall_ns),
        (start, start + 30_000 * MS)
    );
    assert_eq!(gap.failed_attempts, 29);
    assert_eq!(gap.reason, "/eth/v1/events: the stream ended");
    assert!(!gap.open_at_shutdown);
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

/// An SSE arrival of `event` with `data`, `bytes` long on the wire, at `wall_ms` into the
/// capture.
fn sse_at(event: &str, data: &str, wall_ms: u64) -> Arrival {
    Arrival::Sse(StampedEvent {
        stamp: Stamp {
            mono_ns: wall_ms * MS,
            wall_ns: GENESIS * 1_000 * MS + wall_ms * MS,
        },
        event: SseEvent {
            event: event.into(),
            data: data.into(),
        },
    })
}

fn single_attestation(slot: u64, committee_index: u64) -> String {
    format!(
        r#"{{"committee_index":"{committee_index}","attester_index":"9","data":{{"slot":"{slot}","index":"0","beacon_block_root":"0x{}"}},"signature":"0x00"}}"#,
        "cd".repeat(32)
    )
}

#[test]
fn topic_set_manifest() {
    use crate::archive::fixtures::{chain, Spec};
    let configured: Vec<String> = EXIT14_SSE_EVENTS
        .iter()
        .map(|(e, _)| (*e).to_owned())
        .filter(|e| e != "execution_payload_bid")
        .collect();
    let info = CaptureInfo {
        sse_topics: configured.clone(),
        // The node refused the bid topic at start: a gap, never subscribed.
        sse_topics_unsupported: vec!["execution_payload_bid".into()],
        attestation_subnets: vec![3, 5],
        committees_per_slot: Some(64),
        slots_per_epoch: Some(32),
        ..info(vec![Source::Sse])
    };
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("capture");
    let mut c = Collector::<Spec>::create(&out, info.clone(), chain(), None).unwrap();
    let block = format!(r#"{{"slot":"7","block":"0x{}"}}"#, "ab".repeat(32));
    let column = format!(
        r#"{{"block_root":"0x{}","index":"5","slot":"7"}}"#,
        "ab".repeat(32)
    );
    for (i, (event, data)) in [
        ("block_gossip", block.clone()),
        ("data_column_sidecar", column.clone()),
        ("data_column_sidecar", column.clone()),
        // Subnet 3 twice, subnet 5 never; subnet 9 is not sampled: counted, not recorded.
        ("single_attestation", single_attestation(7, 3)),
        ("single_attestation", single_attestation(7, 3)),
        ("single_attestation", single_attestation(7, 9)),
        ("attestation", single_attestation(7, 0)),
    ]
    .into_iter()
    .enumerate()
    {
        c.handle(sse_at(event, &data, 100 + i as u64)).unwrap();
    }
    let summary = c.finish(0).unwrap();

    // capture.toml carries the configured topics and sampled subnets.
    let read = read_info(&out).unwrap();
    assert_eq!(read, info);

    // summary.toml lists every configured topic with its n, zeros included (the refused one
    // too), and every sampled subnet; the zeros are the gaps, the refused topic among them.
    let on_disk: Summary =
        toml::from_str(&std::fs::read_to_string(out.join(SUMMARY_FILE)).unwrap()).unwrap();
    assert_eq!(on_disk, summary);
    let n: Vec<(&str, u64)> = summary
        .topics
        .iter()
        .map(|t| {
            assert_eq!(t.source, Source::Sse);
            (t.topic.as_str(), t.n)
        })
        .collect();
    assert_eq!(
        n,
        [
            ("attestation", 1),
            ("block_gossip", 1),
            ("data_column_sidecar", 2),
            ("execution_payload_bid", 0),
            ("execution_payload_gossip", 0),
            ("payload_attestation_message", 0),
            ("single_attestation", 2),
        ]
    );
    let block_bytes = summary
        .topics
        .iter()
        .find(|t| t.topic == "block_gossip")
        .unwrap()
        .bytes;
    assert_eq!(block_bytes, block.len() as u64);
    let subnets: Vec<(u64, u64)> = summary
        .attestation_subnets
        .iter()
        .map(|s| (s.subnet, s.n))
        .collect();
    assert_eq!(subnets, [(3, 2), (5, 0)]);
    assert_eq!(summary.outside_sampled_subnets, 1);
    assert_eq!(
        summary.missing_topics,
        [
            "sse:execution_payload_bid",
            "sse:execution_payload_gossip",
            "sse:payload_attestation_message",
            "sse:attestation_subnet_5",
        ]
    );
    assert_eq!(summary.unsupported_topics, ["sse:execution_payload_bid"]);
    // The gaps line names each gap once, the refused topic marked.
    assert_eq!(
        summary.topic_gaps(),
        [
            "sse:execution_payload_bid (refused)",
            "sse:execution_payload_gossip",
            "sse:payload_attestation_message",
            "sse:attestation_subnet_5",
        ]
    );
    // A summary written before refused topics had rows lists them on the line all the same.
    let earlier = Summary {
        missing_topics: vec!["sse:attestation_subnet_5".into()],
        ..summary.clone()
    };
    assert_eq!(
        earlier.topic_gaps(),
        [
            "sse:execution_payload_bid (refused)",
            "sse:attestation_subnet_5"
        ]
    );
    // The records: every arrival but the unsampled attestation, with its size.
    let (_, records) = read_capture(&out).unwrap();
    assert_eq!(records.len(), 6);
    assert_eq!(records[3].subnet, Some(3));
    assert_eq!(records[0].bytes, block.len() as u64);
}

fn sized(topic: &str, subnet: Option<u64>, slot: u64, bytes: u64) -> ArrivalRecord {
    ArrivalRecord {
        source: Source::Sse,
        topic: topic.into(),
        subnet,
        msg_id: None,
        block_root: None,
        slot: Some(slot),
        recv_mono_ns: 0,
        // 2 s into the slot.
        recv_wall_ns: (GENESIS * 1_000 + slot * SLOT_MS + 2_000) * MS,
        peer: None,
        bytes,
    }
}

/// One rate as hand-counted: topic, subnet, n, bytes, msgs/slot, bytes/slot, peak msgs, peak
/// bytes.
type Row<'a> = (&'a str, Option<u64>, u64, u64, f64, f64, u64, u64);

#[test]
fn rates_fixture() {
    let (att, agg, ptc) = (
        "single_attestation",
        "attestation",
        "payload_attestation_message",
    );
    let records = [
        // Slot 10: 3 attestations (subnets 3, 3, 5), 2 aggregates, 4 PTC messages, a block.
        sized("block_gossip", None, 10, 100),
        sized(att, Some(3), 10, 240),
        sized(att, Some(3), 10, 240),
        sized(att, Some(5), 10, 240),
        sized(agg, None, 10, 500),
        sized(agg, None, 10, 500),
        sized(ptc, None, 10, 150),
        sized(ptc, None, 10, 150),
        sized(ptc, None, 10, 150),
        sized(ptc, None, 10, 150),
        // Slot 11: 1 attestation (subnet 5), 1 aggregate, no PTC message, no block.
        sized(att, Some(5), 11, 240),
        sized(agg, None, 11, 500),
        // Slot 12: 2 attestations (subnets 3, 5), 3 aggregates, 2 PTC messages, a block.
        sized("block_gossip", None, 12, 100),
        sized(att, Some(3), 12, 240),
        sized(att, Some(5), 12, 240),
        sized(agg, None, 12, 500),
        sized(agg, None, 12, 500),
        sized(agg, None, 12, 500),
        sized(ptc, None, 12, 150),
        sized(ptc, None, 12, 150),
    ];
    let clock = SlotClock::new(GENESIS, SLOT_MS).unwrap();
    let mut counter = RateCounter::new(clock);
    records.iter().for_each(|r| counter.add(r));
    let rates = counter.finish();
    // Hand-counted over the 3 slots the SSE source was seen in:
    // (topic, subnet, n, bytes, msgs/slot, bytes/slot, peak msgs, peak bytes)
    let want: [Row; 6] = [
        (agg, None, 6, 3_000, 2.0, 1_000.0, 3, 1_500),
        ("block_gossip", None, 2, 200, 2.0 / 3.0, 200.0 / 3.0, 1, 100),
        (ptc, None, 6, 900, 2.0, 300.0, 4, 600),
        (att, None, 6, 1_440, 2.0, 480.0, 3, 720),
        (att, Some(3), 3, 720, 1.0, 240.0, 2, 480),
        (att, Some(5), 3, 720, 1.0, 240.0, 1, 240),
    ];
    let got: Vec<Row> = rates
        .topics
        .iter()
        .map(|r| {
            assert_eq!((r.source, r.slots), (Source::Sse, 3), "{r:?}");
            (
                r.topic.as_str(),
                r.subnet,
                r.n,
                r.bytes,
                r.msgs_per_slot,
                r.bytes_per_slot,
                r.peak_msgs_per_slot,
                r.peak_bytes_per_slot,
            )
        })
        .collect();
    assert_eq!(got, want);
    assert_eq!(rates.before_genesis, 0);

    // A record before genesis has no slot: left out, and counted.
    let mut counter = RateCounter::new(clock);
    counter.add(&ArrivalRecord {
        recv_wall_ns: 0,
        ..sized(att, Some(3), 0, 240)
    });
    let rates = counter.finish();
    assert_eq!((rates.topics.len(), rates.before_genesis), (0, 1));
}
