//! [`Arrival`]: what the sources hand the collector, stamped and not yet decoded, and the
//! bounded channel that carries it ([`Arrivals`], [`ArrivalReceiver`]).
//!
//! A source stamps a message and offers it without waiting ([`Arrivals::offer`]); a channel
//! that is full, by entries or by queued bytes, drops it and counts the drop, so a slow disk
//! never delays a later stamp and a flood of large events cannot grow the queue past its byte
//! budget. A closed channel is not a full one: the collector has stopped, and the source is told
//! so ([`Closed`]). Gaps and NTP samples are rare and must not be lost, so they wait for room
//! ([`Arrivals::deliver`]); their bytes are counted but never refused.

use super::clock::Stamp;
use super::ntp::NtpSample;
use super::record::Source;
use super::sse::SseEvent;
use super::tap::TapRecord;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

impl Arrival {
    /// What it holds while queued, for the byte budget: the enum itself and the allocations of
    /// its strings and buffers. Capacity, not length: a buffer built by appending (an SSE
    /// event's data) can hold up to twice what it uses, and holds all of it while queued.
    pub fn weight(&self) -> usize {
        let heap = match self {
            Arrival::Tap(t) => {
                t.topic.capacity() + t.msg_id.capacity() + t.peer.capacity() + t.payload.capacity()
            }
            Arrival::Sse(e) => e.event.event.capacity() + e.event.data.capacity(),
            Arrival::Gap(g) => g.reason.capacity(),
            Arrival::Ntp(n) => n.daemon.capacity() + n.error.as_ref().map_or(0, String::capacity),
        };
        std::mem::size_of::<Arrival>() + heap
    }
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

/// The sending side of the arrival channel. Cheap to clone; every clone shares the drop count
/// and the byte budget.
#[derive(Debug, Clone)]
pub struct Arrivals {
    tx: mpsc::Sender<Arrival>,
    dropped: Drops,
    budget: Arc<Budget>,
}

/// The receiving side: [`Arrival`]s in the order they were handed over. Receiving one frees
/// its bytes in the budget.
#[derive(Debug)]
pub struct ArrivalReceiver {
    rx: mpsc::Receiver<Arrival>,
    budget: Arc<Budget>,
}

/// The bytes queued ([`Arrival::weight`]) and the most [`Arrivals::offer`] lets in.
#[derive(Debug)]
struct Budget {
    queued: AtomicUsize,
    max: usize,
}

impl Budget {
    /// Counts `weight` in if it fits under `max`.
    fn take(&self, weight: usize) -> bool {
        let mut queued = self.queued.load(Ordering::Acquire);
        loop {
            let Some(total) = queued.checked_add(weight).filter(|t| *t <= self.max) else {
                return false;
            };
            match self.queued.compare_exchange_weak(
                queued,
                total,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(now) => queued = now,
            }
        }
    }

    /// Counts `weight` in, over `max` or not.
    fn force(&self, weight: usize) {
        self.queued.fetch_add(weight, Ordering::AcqRel);
    }

    fn release(&self, weight: usize) {
        self.queued.fetch_sub(weight, Ordering::AcqRel);
    }
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

    fn count(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// The channel is closed: the collector has stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the collector has stopped")]
pub struct Closed;

impl Arrivals {
    /// A channel holding up to `capacity` arrivals (at least 1) and, of offered ones, up to
    /// `max_bytes` queued ([`Arrival::weight`]).
    pub fn channel(capacity: usize, max_bytes: usize) -> (Self, ArrivalReceiver) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let budget = Arc::new(Budget {
            queued: AtomicUsize::new(0),
            max: max_bytes,
        });
        let arrivals = Self {
            tx,
            dropped: Drops::default(),
            budget: Arc::clone(&budget),
        };
        (arrivals, ArrivalReceiver { rx, budget })
    }

    /// Hands over `arrival` without waiting: `Ok(true)` if queued, `Ok(false)` (and one more
    /// drop counted) if the channel is full by entries or by bytes, [`Closed`] if the collector
    /// has stopped.
    pub fn offer(&self, arrival: Arrival) -> Result<bool, Closed> {
        if self.tx.is_closed() {
            return Err(Closed);
        }
        let weight = arrival.weight();
        if !self.budget.take(weight) {
            self.dropped.count();
            return Ok(false);
        }
        match self.tx.try_send(arrival) {
            Ok(()) => Ok(true),
            Err(e) => {
                self.budget.release(weight);
                match e {
                    mpsc::error::TrySendError::Full(_) => {
                        self.dropped.count();
                        Ok(false)
                    }
                    mpsc::error::TrySendError::Closed(_) => Err(Closed),
                }
            }
        }
    }

    /// Hands over `arrival`, waiting for an entry; its bytes are counted, never refused.
    pub async fn deliver(&self, arrival: Arrival) -> Result<(), Closed> {
        let weight = arrival.weight();
        self.budget.force(weight);
        self.tx.send(arrival).await.map_err(|_| {
            self.budget.release(weight);
            Closed
        })
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

impl ArrivalReceiver {
    /// The next arrival, waiting for one; `None` once every sender is gone and it is drained.
    pub async fn recv(&mut self) -> Option<Arrival> {
        let arrival = self.rx.recv().await;
        self.received(arrival)
    }

    /// [`ArrivalReceiver::recv`], blocking the thread: for the collector's blocking thread.
    pub fn blocking_recv(&mut self) -> Option<Arrival> {
        let arrival = self.rx.blocking_recv();
        self.received(arrival)
    }

    /// The next arrival if one is queued.
    pub fn try_recv(&mut self) -> Option<Arrival> {
        let arrival = self.rx.try_recv().ok();
        self.received(arrival)
    }

    /// The bytes queued now.
    pub fn queued_bytes(&self) -> usize {
        self.budget.queued.load(Ordering::Acquire)
    }

    fn received(&self, arrival: Option<Arrival>) -> Option<Arrival> {
        if let Some(a) = &arrival {
            self.budget.release(a.weight());
        }
        arrival
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

    fn sse(data_len: usize) -> Arrival {
        Arrival::Sse(StampedEvent {
            stamp: Stamp::default(),
            event: SseEvent {
                event: "block_gossip".into(),
                data: "x".repeat(data_len),
            },
        })
    }

    #[tokio::test]
    async fn a_full_channel_drops_and_counts() {
        let (arrivals, mut rx) = Arrivals::channel(0, usize::MAX);
        assert_eq!(arrivals.offer(gap()), Ok(true));
        assert_eq!(arrivals.clone().offer(gap()), Ok(false));
        assert_eq!(arrivals.dropped(), 1);
        assert_eq!(rx.recv().await, Some(gap()));
        arrivals.deliver(gap()).await.unwrap();
        drop(rx);
        assert_eq!(arrivals.deliver(gap()).await, Err(Closed));
        // Closed is not full: the collector has stopped, and the source is told so.
        assert_eq!(arrivals.offer(gap()), Err(Closed));
        assert_eq!(arrivals.dropped(), 1);
        assert_eq!(arrivals.drops().get(), 1);
    }

    #[tokio::test]
    async fn queued_bytes_are_bounded() {
        let weight = sse(1_000).weight();
        assert!(weight > 1_000, "{weight}");
        // Room for two such events by bytes, though the channel holds 16.
        let (arrivals, mut rx) = Arrivals::channel(16, 2 * weight + weight / 2);
        assert_eq!(arrivals.offer(sse(1_000)), Ok(true));
        assert_eq!(arrivals.offer(sse(1_000)), Ok(true));
        assert_eq!(rx.queued_bytes(), 2 * weight);
        assert_eq!(arrivals.offer(sse(1_000)), Ok(false));
        // An event larger than the whole budget never fits.
        assert_eq!(arrivals.offer(sse(10 * weight)), Ok(false));
        assert_eq!(arrivals.dropped(), 2);
        // Gaps and NTP samples are not dropped: they are counted, and wait only for an entry.
        arrivals.deliver(gap()).await.unwrap();
        assert_eq!(rx.queued_bytes(), 2 * weight + gap().weight());
        // A received arrival frees its bytes.
        assert_eq!(rx.try_recv(), Some(sse(1_000)));
        assert_eq!(rx.queued_bytes(), weight + gap().weight());
        assert_eq!(arrivals.offer(sse(1_000)), Ok(true));
        let mut rest = Vec::new();
        drop(arrivals);
        while let Some(a) = rx.recv().await {
            rest.push(a);
        }
        assert_eq!(rest, vec![sse(1_000), gap(), sse(1_000)]);
        assert_eq!(rx.queued_bytes(), 0);
        assert_eq!(rx.try_recv(), None);
    }

    #[test]
    fn an_arrival_is_charged_its_capacity_not_its_length() {
        // A buffer grown large and cut short still holds its allocation while queued.
        let mut data = "x".repeat(4_096);
        data.truncate(10);
        let mut name = String::with_capacity(256);
        name.push_str("block_gossip");
        let arrival = Arrival::Sse(StampedEvent {
            stamp: Stamp::default(),
            event: SseEvent { event: name, data },
        });
        let base = std::mem::size_of::<Arrival>();
        assert_eq!(arrival.weight(), base + 256 + 4_096);
        let mut payload = Vec::with_capacity(1 << 16);
        payload.push(1u8);
        let tap = Arrival::Tap(TapRecord {
            stamp: Stamp::default(),
            topic: String::new(),
            msg_id: Vec::new(),
            peer: String::new(),
            payload,
        });
        assert_eq!(tap.weight(), base + (1 << 16));
    }

    #[test]
    fn every_arrival_weighs_its_heap_bytes() {
        let base = std::mem::size_of::<Arrival>();
        assert_eq!(sse(10).weight(), base + "block_gossip".len() + 10);
        assert_eq!(gap().weight(), base + "eof".len());
        let tap = Arrival::Tap(TapRecord {
            stamp: Stamp::default(),
            topic: "t".repeat(3),
            msg_id: vec![0; 4],
            peer: "p".repeat(5),
            payload: vec![0; 6],
        });
        assert_eq!(tap.weight(), base + 18);
        let ntp = Arrival::Ntp(NtpSample {
            mono_ns: 0,
            wall_ns: 0,
            daemon: "chrony".into(),
            clock_error_ns: None,
            error: Some("exit 1".into()),
        });
        assert_eq!(ntp.weight(), base + 12);
    }

    #[test]
    fn duration_never_underflows() {
        let Arrival::Gap(g) = gap() else {
            unreachable!()
        };
        assert_eq!(g.duration_ns(), 0);
    }
}
