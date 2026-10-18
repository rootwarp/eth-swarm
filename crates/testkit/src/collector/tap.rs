//! [`TapRecord`]: what our probe's gossipsub tap hands the collector.
//!
//! The probe stamps a message the moment gossipsub delivers it, before it decodes or copies
//! anything ([`Tap::now`]), and offers it without waiting ([`Tap::offer`]). The slot and block
//! root are decoded later, off the gossip hot path, by the collector.

use super::arrival::{Arrival, Arrivals, Closed};
use super::clock::{Clock, Stamp};
use std::sync::Arc;

/// One gossip message as gossipsub delivered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapRecord {
    /// The receive time, taken at delivery.
    pub stamp: Stamp,
    /// The full topic: `/eth2/<fork_digest>/<name>/ssz_snappy`.
    pub topic: String,
    /// The gossipsub message-id.
    pub msg_id: Vec<u8>,
    /// The propagation source's peer ID, as text.
    pub peer: String,
    /// The message data: snappy block-compressed SSZ, as received.
    pub payload: Vec<u8>,
}

/// The probe's handle on the collector.
#[derive(Clone)]
pub struct Tap {
    clock: Arc<dyn Clock>,
    arrivals: Arrivals,
}

impl std::fmt::Debug for Tap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tap").finish_non_exhaustive()
    }
}

impl Tap {
    /// A tap stamping with `clock` and offering to `arrivals`.
    pub fn new(clock: Arc<dyn Clock>, arrivals: Arrivals) -> Self {
        Self { clock, arrivals }
    }

    /// The receive time: call it first when gossipsub delivers a message.
    pub fn now(&self) -> Stamp {
        self.clock.now()
    }

    /// Offers `record` without waiting: `Ok(false)` if the collector is behind and it was
    /// dropped (counted in [`Arrivals::dropped`]), [`Closed`] if the collector has stopped (stop
    /// tapping).
    pub fn offer(&self, record: TapRecord) -> Result<bool, Closed> {
        self.arrivals.offer(Arrival::Tap(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::clock::SystemClock;

    #[tokio::test]
    async fn stamps_then_offers() {
        let (arrivals, mut rx) = Arrivals::channel(1, usize::MAX);
        let tap = Tap::new(Arc::new(SystemClock::new()), arrivals.clone());
        let stamp = tap.now();
        let record = TapRecord {
            stamp,
            topic: "/eth2/00000000/beacon_block/ssz_snappy".into(),
            msg_id: vec![1],
            peer: "p".into(),
            payload: vec![2],
        };
        assert_eq!(tap.offer(record.clone()), Ok(true));
        assert_eq!(tap.offer(record.clone()), Ok(false));
        assert_eq!(arrivals.dropped(), 1);
        assert_eq!(rx.recv().await, Some(Arrival::Tap(record.clone())));
        drop(rx);
        assert_eq!(tap.offer(record), Err(Closed));
        assert!(format!("{tap:?}").starts_with("Tap"));
    }
}
