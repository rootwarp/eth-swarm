//! The feed-lag alert logs one line per transition, not one per update.
//!
//! This binary holds a single test: tracing caches callsite interest process-wide, so a scoped
//! subscriber can miss events that other tests' threads hit concurrently.

use std::sync::{Arc, Mutex};

use cl_verify::metrics::FeedLagMetrics;
use prometheus_client::registry::Registry;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// Collects every event as `LEVEL message`.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut message = Message(String::new());
        event.record(&mut message);
        let line = format!("{} {}", event.metadata().level(), message.0);
        self.0.lock().unwrap().push(line);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[test]
fn alert_clears() {
    let capture = Capture::default();
    let metrics = FeedLagMetrics::register(&mut Registry::default());
    tracing::subscriber::with_default(capture.clone(), || {
        // Lag 4 (at the bound), 5 twice, a frame without epochs (refused, so it logs nothing),
        // 5 again at a later finality, then 4, 3 and 4.
        let updates = [
            (96, 100),
            (95, 100),
            (95, 100),
            (0, 0),
            (96, 101),
            (97, 101),
            (98, 101),
            (97, 101),
        ];
        let refused = updates
            .into_iter()
            .filter(|&(feed, chain)| metrics.update(feed, chain).is_err())
            .count();
        assert_eq!(refused, 1);
    });
    assert_eq!(metrics.alert(), 0);
    assert_eq!(
        *capture.0.lock().unwrap(),
        [
            "WARN pubkey feed lag alert raised",
            "INFO pubkey feed lag alert cleared",
        ]
    );
}
