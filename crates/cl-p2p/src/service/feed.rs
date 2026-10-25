//! The Goodbye ledger's feed ([`run_feed`]): the owner loop of the swarm hands it what
//! [`GoodbyeLedger`] reads ([`FeedEvent`]: judged Statuses and received Goodbyes, identify
//! answers, last disconnects), and it ticks the ledger every [`LEDGER_TICK`] with the wall
//! clock, so each hour closes on time with or without events.
//!
//! The owner loop sends through a [`FeedSender`]: only the events that the ledger reads, and
//! never a wait. A burst that does not fit in [`FEED_CAPACITY`] is dropped and counted on
//! `p2p_ledger_feed_dropped_total`, except a disconnect: the ledger keeps a peer as Status-valid
//! until its disconnect, so a lost one would count the peer in every later hour. A disconnect
//! that does not fit is held, in order, and nothing goes ahead of it. At most [`MAX_HELD`]
//! disconnects are held: past them a disconnect is dropped and counted too, and only the first
//! drop of a stall is logged, until the held ones drain.
//!
//! The ledger's own monotonic clock is tokio's ([`tokio::time::Instant`]), so a paused test
//! clock drives both the ticks and the ledger's check for unobserved gaps.

use crate::peers::manager::GoodbyeLedger;
use crate::rpc::inbound::ControlEvent;
use libp2p::PeerId;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};

/// How often the ledger is ticked: about once a minute, well within its [`MAX_CALL_GAP`]
/// (five minutes) of an observed hour.
///
/// [`MAX_CALL_GAP`]: crate::peers::manager::MAX_CALL_GAP
pub const LEDGER_TICK: Duration = Duration::from_secs(60);

/// The events the feed waits for at most \[est\]: a burst of Status and Goodbye events; past
/// it the owner loop drops and counts them.
pub const FEED_CAPACITY: usize = 4096;

/// The disconnects a [`FeedSender`] holds at most while the feed is full: one per peer, as many
/// as the feed's queue. Past it a disconnect is dropped and counted.
pub const MAX_HELD: usize = FEED_CAPACITY;

/// What the owner loop hands the feed.
#[derive(Debug, Clone)]
pub enum FeedEvent {
    /// A req/resp event: a judged Status or a received Goodbye count; the others are not read.
    Control(ControlEvent),
    /// A peer identified itself with this agent version.
    Identified {
        /// The peer.
        peer: PeerId,
        /// Its agent version, as it sent it (the ledger cuts it).
        agent: String,
    },
    /// The last connection of a peer closed.
    Disconnected(PeerId),
}

/// The owner loop's side of the feed (see the module docs).
#[derive(Debug)]
pub struct FeedSender {
    tx: mpsc::Sender<FeedEvent>,
    /// Disconnects that did not fit, oldest first, each peer once.
    held: VecDeque<PeerId>,
    dropped: Counter,
    /// Whether the warning of the current stall went out: only its first dropped disconnect is
    /// logged, until the held disconnects drain.
    stall_logged: bool,
    /// Stall warnings logged so far.
    stall_warnings: u64,
}

impl FeedSender {
    /// A sender into `tx`, its `p2p_ledger_feed_dropped_total` registered in `registry` at 0.
    pub fn new(tx: mpsc::Sender<FeedEvent>, registry: &mut Registry) -> Self {
        let dropped = Counter::default();
        registry.register(
            "p2p_ledger_feed_dropped",
            "Events for the Goodbye ledger dropped because its feed was full",
            dropped.clone(),
        );
        Self {
            tx,
            held: VecDeque::new(),
            dropped,
            stall_logged: false,
            stall_warnings: 0,
        }
    }

    /// A req/resp event: only a judged Status and a received Goodbye go; the ledger reads no
    /// other.
    pub fn control(&mut self, event: ControlEvent) {
        if matches!(
            event,
            ControlEvent::Status { .. } | ControlEvent::GoodbyeReceived { .. }
        ) {
            self.send(FeedEvent::Control(event));
        }
    }

    /// `peer` identified itself with `agent`.
    pub fn identified(&mut self, peer: PeerId, agent: String) {
        self.send(FeedEvent::Identified { peer, agent });
    }

    /// The last connection of `peer` closed: sent, or held until it fits.
    pub fn disconnected(&mut self, peer: PeerId) {
        if self.flush() {
            match self.tx.try_send(FeedEvent::Disconnected(peer)) {
                Ok(()) | Err(TrySendError::Closed(_)) => return,
                Err(TrySendError::Full(_)) => {}
            }
        }
        // Nothing of `peer` went after its held disconnect: one is enough.
        if self.held.contains(&peer) {
            return;
        }
        if self.held.len() < MAX_HELD {
            self.held.push_back(peer);
        } else {
            self.dropped.inc();
            // One line per stall: a stalled feed would log every disconnect.
            if !self.stall_logged {
                self.stall_logged = true;
                self.stall_warnings += 1;
                tracing::warn!(
                    held = MAX_HELD,
                    "the Goodbye ledger's feed is stalled: disconnects past the held ones are \
                     dropped and counted (p2p_ledger_feed_dropped_total) until it drains"
                );
            }
        }
    }

    /// Sends the held disconnects that fit now, oldest first; `true` when none is held. A feed
    /// that is gone (the stop) holds nothing.
    pub fn flush(&mut self) -> bool {
        while let Some(&peer) = self.held.front() {
            match self.tx.try_send(FeedEvent::Disconnected(peer)) {
                Ok(()) => {
                    self.held.pop_front();
                }
                Err(TrySendError::Closed(_)) => self.held.clear(),
                Err(TrySendError::Full(_)) => return false,
            }
        }
        self.stall_logged = false;
        true
    }

    /// `event` unless it does not fit or a held disconnect is ahead of it: then dropped and
    /// counted.
    fn send(&mut self, event: FeedEvent) {
        let sent = self.flush()
            && match self.tx.try_send(event) {
                Ok(()) | Err(TrySendError::Closed(_)) => true,
                Err(TrySendError::Full(_)) => false,
            };
        if !sent {
            self.dropped.inc();
            tracing::debug!("the Goodbye ledger's feed is full: an event dropped");
        }
    }
}

/// The wall clock the hours are counted by.
pub type Wall = Box<dyn Fn() -> SystemTime + Send>;

/// Runs `ledger` on `events` until `stop` turns true or both the events' sender and the stop's
/// go; returns the ledger. A tick goes first at the start, then every [`LEDGER_TICK`].
pub async fn run_feed(
    ledger: GoodbyeLedger,
    mut events: mpsc::Receiver<FeedEvent>,
    mut stop: watch::Receiver<bool>,
    wall: Wall,
) -> GoodbyeLedger {
    let mut ledger = ledger.with_monotonic_clock(|| tokio::time::Instant::now().into_std());
    let mut ticks = tokio::time::interval(LEDGER_TICK);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    // What is queued still counts; nothing more is waited for.
                    while let Ok(event) = events.try_recv() {
                        feed(&mut ledger, &event, &wall);
                    }
                    break;
                }
            }
            event = events.recv() => match event {
                Some(event) => feed(&mut ledger, &event, &wall),
                None => break,
            },
            _ = ticks.tick() => {
                ledger.tick(wall());
            }
        }
    }
    ledger
}

/// One event into the ledger.
fn feed(ledger: &mut GoodbyeLedger, event: &FeedEvent, wall: &Wall) {
    match event {
        // Judged now, by the feed's wall clock: the hours of every call are of one clock.
        FeedEvent::Control(ControlEvent::Status {
            peer, relevance, ..
        }) => ledger.status(*peer, relevance.is_relevant(), wall()),
        FeedEvent::Control(event) => ledger.observe(event),
        FeedEvent::Identified { peer, agent } => ledger.identified(*peer, agent),
        FeedEvent::Disconnected(peer) => ledger.disconnected(peer, wall()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::manager::{GoodbyeLedgerConfig, Verdict, HOUR_SECS};
    use crate::rpc::inbound::{Relevance, StatusVia};
    use crate::rpc::metrics::StatusValidity;
    use crate::transport::Direction;
    use prometheus_client::registry::Registry;
    use std::sync::{Arc, Mutex};
    use std::time::UNIX_EPOCH;

    /// The start of an hour, in Unix seconds.
    const HOUR: u64 = 491_000 * HOUR_SECS;

    /// A wall clock at `HOUR` plus tokio's time since the test started.
    fn wall() -> (Wall, Arc<Mutex<SystemTime>>) {
        let start = tokio::time::Instant::now();
        let last = Arc::new(Mutex::new(UNIX_EPOCH));
        let seen = Arc::clone(&last);
        let wall: Wall = Box::new(move || {
            let now = UNIX_EPOCH + Duration::from_secs(HOUR) + start.elapsed();
            *seen.lock().unwrap() = now;
            now
        });
        (wall, last)
    }

    fn peer() -> PeerId {
        PeerId::random()
    }

    fn status(peer: PeerId) -> FeedEvent {
        FeedEvent::Control(ControlEvent::Status {
            peer,
            status: p2p_wire::testkit::status(),
            relevance: Relevance::Relevant,
            via: StatusVia::Response,
        })
    }

    /// The feed's ticks close the hour on time without any event after it: two Status-valid
    /// peers, one Goodbye 3, and the hour's line has 50 %.
    #[tokio::test(start_paused = true)]
    async fn the_tick_closes_each_hour_on_time() {
        let (tx, rx) = mpsc::channel(16);
        let (stop, stopped) = watch::channel(false);
        let (wall, last) = wall();
        let ledger = GoodbyeLedger::new(GoodbyeLedgerConfig::default()).unwrap();
        let feeding = tokio::spawn(run_feed(ledger, rx, stopped, wall));
        let (a, b) = (peer(), peer());
        tx.send(status(a)).await.unwrap();
        tx.send(status(b)).await.unwrap();
        tx.send(FeedEvent::Identified {
            peer: a,
            agent: "Lighthouse/v8".into(),
        })
        .await
        .unwrap();
        tx.send(FeedEvent::Control(ControlEvent::GoodbyeReceived {
            peer: a,
            reason: 3,
            status_valid: StatusValidity::Valid,
            direction: Direction::Outbound,
            at: UNIX_EPOCH + Duration::from_secs(HOUR + 60),
        }))
        .await
        .unwrap();
        tx.send(FeedEvent::Disconnected(b)).await.unwrap();
        // Past the hour, with no event: only the ticks run.
        tokio::time::sleep(Duration::from_secs(HOUR_SECS + 120)).await;
        assert!(
            *last.lock().unwrap() >= UNIX_EPOCH + Duration::from_secs(HOUR + HOUR_SECS),
            "a tick read the wall clock past the hour"
        );
        stop.send_replace(true);
        let ledger = feeding.await.unwrap();
        let closed: Vec<_> = ledger.closed_hours().collect();
        assert_eq!(closed.len(), 1, "{closed:?}");
        let hour = closed[0];
        assert_eq!(hour.rate.hour, HOUR / HOUR_SECS);
        assert_eq!(
            (hour.rate.status_valid_peers, hour.rate.goodbye3_senders),
            (2, 1)
        );
        assert!(!hour.rate.unobserved, "ticked every minute: observed");
        assert_eq!(hour.verdict, Verdict::Fail);
    }

    fn kind(event: &FeedEvent) -> String {
        match event {
            FeedEvent::Control(ControlEvent::Status { peer, .. }) => format!("status {peer}"),
            FeedEvent::Control(ControlEvent::GoodbyeReceived { peer, .. }) => {
                format!("goodbye {peer}")
            }
            FeedEvent::Control(other) => format!("other {other:?}"),
            FeedEvent::Identified { peer, .. } => format!("identified {peer}"),
            FeedEvent::Disconnected(peer) => format!("disconnected {peer}"),
        }
    }

    fn dropped(registry: &Registry) -> String {
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, registry).unwrap();
        text.lines()
            .find(|l| l.starts_with("p2p_ledger_feed_dropped_total "))
            .unwrap_or_default()
            .to_owned()
    }

    /// The sender hands the ledger only what it reads, drops and counts the rest of a burst
    /// that does not fit, and never drops a disconnect: one that does not fit is held, in order,
    /// and goes before any later event.
    #[tokio::test]
    async fn the_sender_holds_every_disconnect_in_order() {
        let (tx, mut rx) = mpsc::channel(2);
        let mut registry = Registry::default();
        let mut sender = FeedSender::new(tx, &mut registry);
        let (a, b, c) = (peer(), peer(), peer());
        // Not read by the ledger: never sent, not a drop.
        sender.control(ControlEvent::Pong {
            peer: a,
            seq_number: 1,
        });
        sender.control(ControlEvent::StatusAnswered { peer: a });
        let FeedEvent::Control(goodbye) = goodbye(a) else {
            unreachable!()
        };
        sender.control(goodbye);
        let FeedEvent::Control(first) = status(b) else {
            unreachable!()
        };
        sender.control(first);
        // Full: a Status and an identify answer are dropped and counted.
        let FeedEvent::Control(late) = status(c) else {
            unreachable!()
        };
        sender.control(late);
        sender.identified(c, "Lighthouse/v8".into());
        assert_eq!(dropped(&registry), "p2p_ledger_feed_dropped_total 2");
        // Full: the disconnects are held, each peer once, in order.
        sender.disconnected(a);
        sender.disconnected(b);
        sender.disconnected(a);
        // Nothing goes ahead of a held disconnect: dropped and counted.
        let FeedEvent::Control(behind) = status(c) else {
            unreachable!()
        };
        sender.control(behind);
        assert_eq!(dropped(&registry), "p2p_ledger_feed_dropped_total 3");
        assert!(!sender.flush(), "still full");
        let mut got = vec![kind(&rx.recv().await.unwrap())];
        assert!(!sender.flush(), "one of two fits");
        got.push(kind(&rx.recv().await.unwrap()));
        got.push(kind(&rx.recv().await.unwrap()));
        // A later event sends the rest first.
        let FeedEvent::Control(after) = status(c) else {
            unreachable!()
        };
        sender.control(after);
        got.push(kind(&rx.recv().await.unwrap()));
        got.push(kind(&rx.recv().await.unwrap()));
        assert!(sender.flush());
        assert_eq!(
            got,
            [
                format!("goodbye {a}"),
                format!("status {b}"),
                format!("disconnected {a}"),
                format!("disconnected {b}"),
                format!("status {c}"),
            ]
        );
        assert_eq!(dropped(&registry), "p2p_ledger_feed_dropped_total 3");
        // The feed gone (the stop): nothing is held.
        drop(rx);
        sender.disconnected(c);
        assert!(sender.flush());
    }

    fn goodbye(peer: PeerId) -> FeedEvent {
        FeedEvent::Control(ControlEvent::GoodbyeReceived {
            peer,
            reason: 3,
            status_valid: StatusValidity::Valid,
            direction: Direction::Outbound,
            at: UNIX_EPOCH,
        })
    }

    /// The held disconnects are bounded: past [`MAX_HELD`] one is dropped and counted.
    #[tokio::test]
    async fn the_held_disconnects_are_bounded() {
        let (tx, _rx) = mpsc::channel(1);
        let mut registry = Registry::default();
        let mut sender = FeedSender::new(tx, &mut registry);
        sender.identified(peer(), String::new());
        for _ in 0..=MAX_HELD {
            sender.disconnected(peer());
        }
        assert_eq!(sender.held.len(), MAX_HELD);
        assert_eq!(dropped(&registry), "p2p_ledger_feed_dropped_total 1");
    }

    /// A stalled feed logs its first dropped disconnect only, and logs again only after it
    /// drained and stalled anew; every drop is counted.
    #[tokio::test]
    async fn a_stall_is_logged_once() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut registry = Registry::default();
        let mut sender = FeedSender::new(tx, &mut registry);
        sender.identified(peer(), String::new());
        for _ in 0..MAX_HELD + 3 {
            sender.disconnected(peer());
        }
        assert_eq!(dropped(&registry), "p2p_ledger_feed_dropped_total 3");
        assert_eq!(sender.stall_warnings, 1);
        // Drained: every held disconnect goes, then a new stall logs again.
        while !sender.flush() {
            rx.recv().await.unwrap();
        }
        rx.recv().await.unwrap();
        for _ in 0..=MAX_HELD + 1 {
            sender.disconnected(peer());
        }
        assert_eq!(sender.stall_warnings, 2);
    }

    /// The feed ends when the stop turns true, with the events already queued counted, and when
    /// its sender goes.
    #[tokio::test(start_paused = true)]
    async fn the_feed_ends_at_the_stop() {
        let (tx, rx) = mpsc::channel(16);
        let (stop, stopped) = watch::channel(false);
        let ledger = GoodbyeLedger::new(GoodbyeLedgerConfig::default()).unwrap();
        tx.send(status(peer())).await.unwrap();
        stop.send_replace(true);
        let ledger = run_feed(ledger, rx, stopped, wall().0).await;
        assert_eq!(ledger.current().map(|h| h.status_valid_peers), Some(1));
        drop(tx);
        let (tx, rx) = mpsc::channel::<FeedEvent>(1);
        let (_stop, stopped) = watch::channel(false);
        drop(tx);
        let ledger = run_feed(
            GoodbyeLedger::new(GoodbyeLedgerConfig::default()).unwrap(),
            rx,
            stopped,
            wall().0,
        )
        .await;
        assert_eq!(ledger.closed_hours().count(), 0);
    }
}
