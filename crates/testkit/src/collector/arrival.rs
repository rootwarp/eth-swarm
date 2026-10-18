//! [`Arrival`]: what the sources hand the collector, stamped and not yet decoded, and the
//! bounded channel that carries it ([`Arrivals`]).
//!
//! A source stamps a message and offers it without waiting ([`Arrivals::offer`]); a full
//! channel drops it and counts the drop, so a slow disk never delays a later stamp. Gaps and
//! NTP samples are rare and must not be lost, so they wait for room ([`Arrivals::deliver`]).

use super::clock::Stamp;
use super::ntp::NtpSample;
use super::record::Source;
use super::sse::SseEvent;
use super::tap::TapRecord;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// One stamped, undecoded arrival, or an event about the capture itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arrival {
    /// A gossip message from the probe's tap.
    Tap(TapRecord),
    /// An SSE event from the reference node.
    Sse(StampedEvent),
    /// A source was down: nothing it would have delivered in the interval was seen.
    Gap(MissingInterval),
    /// A sample of the host clock's offset from its time daemon.
    Ntp(NtpSample),
}

/// An SSE event, stamped when the chunk that completed it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedEvent {
    /// The receive time.
    pub stamp: Stamp,
    /// The event.
    pub event: SseEvent,
}

/// An interval in which a source delivered nothing because it was disconnected: a manifest's
/// missing interval. It runs from the last moment the source was known to be alive (its last
/// received bytes, or the collector's start if it never connected) to the moment it was back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingInterval {
    /// The source that was down.
    pub source: Source,
    /// The start, monotonic nanoseconds.
    pub start_mono_ns: u64,
    /// The start, Unix nanoseconds.
    pub start_wall_ns: u64,
    /// The end, monotonic nanoseconds.
    pub end_mono_ns: u64,
    /// The end, Unix nanoseconds.
    pub end_wall_ns: u64,
    /// Why the source went down (the first failure), never a URL.
    pub reason: String,
    /// Failed reconnect attempts in the interval.
    pub failed_attempts: u32,
    /// The collector stopped before the source was back: the end is the stop time.
    pub open_at_shutdown: bool,
}

impl MissingInterval {
    /// The interval's length on the monotonic clock.
    pub fn duration_ns(&self) -> u64 {
        self.end_mono_ns.saturating_sub(self.start_mono_ns)
    }
}

/// The sending side of the arrival channel. Cheap to clone; every clone shares the drop count.
#[derive(Debug, Clone)]
pub struct Arrivals {
    tx: mpsc::Sender<Arrival>,
    dropped: Drops,
}

/// The count of arrivals [`Arrivals::offer`] dropped, readable without holding a sender (which
/// would keep the channel open).
#[derive(Debug, Clone, Default)]
pub struct Drops(Arc<AtomicU64>);

impl Drops {
    /// Arrivals dropped so far.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// The channel is closed: the collector has stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the collector has stopped")]
pub struct Closed;

impl Arrivals {
    /// A channel holding up to `capacity` arrivals (at least 1).
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<Arrival>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let dropped = Drops::default();
        (Self { tx, dropped }, rx)
    }

    /// Hands over `arrival` without waiting; `false` (and one more drop counted) if the
    /// channel is full or closed.
    pub fn offer(&self, arrival: Arrival) -> bool {
        let sent = self.tx.try_send(arrival).is_ok();
        if !sent {
            self.dropped.0.fetch_add(1, Ordering::Relaxed);
        }
        sent
    }

    /// Hands over `arrival`, waiting for room.
    pub async fn deliver(&self, arrival: Arrival) -> Result<(), Closed> {
        self.tx.send(arrival).await.map_err(|_| Closed)
    }

    /// Arrivals [`Arrivals::offer`] dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.get()
    }

    /// The shared drop count.
    pub fn drops(&self) -> Drops {
        self.dropped.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gap() -> Arrival {
        Arrival::Gap(MissingInterval {
            source: Source::Sse,
            start_mono_ns: 5,
            start_wall_ns: 6,
            end_mono_ns: 3,
            end_wall_ns: 4,
            reason: "eof".into(),
            failed_attempts: 0,
            open_at_shutdown: false,
        })
    }

    #[tokio::test]
    async fn a_full_channel_drops_and_counts() {
        let (arrivals, mut rx) = Arrivals::channel(0);
        assert!(arrivals.offer(gap()));
        assert!(!arrivals.clone().offer(gap()));
        assert_eq!(arrivals.dropped(), 1);
        assert_eq!(rx.recv().await, Some(gap()));
        arrivals.deliver(gap()).await.unwrap();
        drop(rx);
        assert_eq!(arrivals.deliver(gap()).await, Err(Closed));
        assert!(!arrivals.offer(gap()));
        assert_eq!(arrivals.dropped(), 2);
        assert_eq!(arrivals.drops().get(), 2);
    }

    #[test]
    fn duration_never_underflows() {
        let Arrival::Gap(g) = gap() else {
            unreachable!()
        };
        assert_eq!(g.duration_ns(), 0);
    }
}
