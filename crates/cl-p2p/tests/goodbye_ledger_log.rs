//! The Goodbye ledger's log lines: one `goodbye3_hourly` line per closed hour, and next to a
//! Goodbye 3 one `goodbye3_received` line with one `goodbye3_context` line per context entry,
//! the rate-limit entry filled by the rate limiter's own debug event through the context layer.
//!
//! Its own test binary with a single test, like `goodbye_log.rs`: `tracing` caches each
//! callsite's interest process-wide, so a thread-scoped subscriber in a unit test can miss lines
//! whose callsites another test registered first.

use cl_p2p::peers::context::{self, GoodbyeContext};
use cl_p2p::peers::manager::{
    GoodbyeLedger, GoodbyeLedgerConfig, ReceivedGoodbye, Verdict, HOUR_SECS,
};
use cl_p2p::rpc::limits::{shared_limiter, ChunkPacer, RateLimits};
use cl_p2p::rpc::metrics::StatusValidity;
use cl_p2p::transport::Direction;
use libp2p::PeerId;
use p2p_wire::rpc::protocols::Protocol;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::Layer as _;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn lines_with(&self, needle: &str) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter(|l| l.contains(needle))
            .map(str::to_owned)
            .collect()
    }
}

fn has_all(line: &str, fields: &[String]) {
    for field in fields {
        assert!(line.contains(field.as_str()), "{field} missing from {line}");
    }
}

#[test]
fn goodbye3_lines_and_context() {
    // First, before any callsite is hit: the one subscriber of this process, an INFO
    // formatting layer and the context layer.
    let log = Captured::default();
    let writer = log.clone();
    let goodbye_context = GoodbyeContext::new();
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .with_filter(tracing::level_filters::LevelFilter::INFO),
        )
        .with(context::layer(goodbye_context.clone()));
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

    let peer = PeerId::random();
    // The rate limiter withholds the third Ping answer chunk in a row (a burst of 2): its own
    // debug event fills the context.
    let pacer = ChunkPacer::new(
        shared_limiter(RateLimits::default()),
        peer,
        Protocol::PingV1,
        None,
    );
    for _ in 0..3 {
        pacer.reserve().sent();
    }
    // The shape of the pinned gossipsub's PRUNE event.
    tracing::debug!(
        target: "libp2p_gossipsub::behaviour",
        peer = %peer,
        "Handling PRUNE message for peer"
    );

    // A monotonic clock that moves with the test's wall times, so no hour reads as a step.
    let hour = 491_000 * HOUR_SECS;
    let start = Instant::now();
    let mono = Arc::new(Mutex::new(start));
    let clock = {
        let mono = mono.clone();
        move || *mono.lock().unwrap()
    };
    let mut ledger = GoodbyeLedger::new(GoodbyeLedgerConfig::default())
        .unwrap()
        .with_context(goodbye_context.clone())
        .with_monotonic_clock(clock);
    let at = |secs: u64| {
        *mono.lock().unwrap() = start + Duration::from_secs(secs - hour);
        UNIX_EPOCH + Duration::from_secs(secs)
    };
    ledger.status(peer, true, at(hour));
    ledger.identified(peer, "Lighthouse/v8.0.0\nforged line");
    let others: Vec<PeerId> = (0..9).map(|_| PeerId::random()).collect();
    for other in &others {
        ledger.status(*other, true, at(hour + 1));
    }
    let goodbye_at: SystemTime = at(hour + 60);
    ledger.goodbye(&ReceivedGoodbye {
        peer,
        reason: 3,
        status_valid: StatusValidity::Valid,
        direction: Direction::Inbound,
        at: goodbye_at,
    });
    // Ticked every minute, as the owner does, so every hour is observed.
    let tick_to = |ledger: &mut GoodbyeLedger, from: u64, to: u64| {
        let mut closed = None;
        for secs in (from..=to).step_by(60) {
            closed = ledger.tick(at(secs)).or(closed);
        }
        closed.expect("an hour closed")
    };
    // 1 of 10 is 10 %, above the default 2 %.
    let closed = tick_to(&mut ledger, hour + 120, hour + HOUR_SECS);
    assert_eq!(closed.verdict, Verdict::Fail);
    // The next hour: the 9 still connected, no Goodbye 3.
    let closed = tick_to(&mut ledger, hour + HOUR_SECS + 60, hour + 2 * HOUR_SECS);
    assert_eq!(closed.verdict, Verdict::Pass);

    let received = log.lines_with("goodbye3_received");
    assert_eq!(received.len(), 1, "{received:?}");
    has_all(
        &received[0],
        &[
            format!("peer={peer}"),
            // Escaped: a peer's agent string cannot start a line of its own.
            "agent=\"Lighthouse/v8.0.0\\nforged line\"".to_owned(),
            "status_valid=\"true\"".to_owned(),
            "direction=\"inbound\"".to_owned(),
            format!("unix_ms={}", (hour + 60) * 1000),
            "counted=true".to_owned(),
            "rate_limited=1".to_owned(),
            "prunes_received=1".to_owned(),
        ],
    );
    let context = log.lines_with("goodbye3_context");
    assert_eq!(context.len(), 2, "{context:?}");
    has_all(
        &context[0],
        &[
            format!("peer={peer}"),
            "kind=\"rate_limited\"".to_owned(),
            "protocol=\"ping\"".to_owned(),
            "count=1".to_owned(),
            "first_unix_ms=".to_owned(),
        ],
    );
    has_all(
        &context[1],
        &["kind=\"prune_received\"".to_owned(), "count=1".to_owned()],
    );

    let hourly = log.lines_with("goodbye3_hourly");
    assert_eq!(hourly.len(), 2, "{hourly:?}");
    has_all(
        &hourly[0],
        &[
            "WARN".to_owned(),
            format!("hour_start_unix={hour}"),
            "status_valid_peers=10".to_owned(),
            "goodbye3_senders=1".to_owned(),
            "rate_pct=10.0".to_owned(),
            "threshold_pct=2.0".to_owned(),
            "capped=false".to_owned(),
            "clock_stepped=false".to_owned(),
            "unobserved=false".to_owned(),
            "verdict=\"fail\"".to_owned(),
        ],
    );
    has_all(
        &hourly[1],
        &[
            "INFO".to_owned(),
            format!("hour_start_unix={}", hour + HOUR_SECS),
            "status_valid_peers=9".to_owned(),
            "goodbye3_senders=0".to_owned(),
            "rate_pct=0.0".to_owned(),
            "verdict=\"pass\"".to_owned(),
        ],
    );
    // The debug events themselves stay out of the INFO log.
    assert!(log.lines_with("over quota").is_empty());
    assert!(log.lines_with("Handling PRUNE").is_empty());
}
