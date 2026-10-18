//! Per-topic rates: messages and bytes per slot, from a capture's records.
//!
//! A record's slot is the wall-clock slot of its arrival ([`SlotClock::wall_slot`]), not the
//! slot it names: rates measure the traffic a slot carries. A source's slots are the slots in
//! which it recorded anything, so a missing interval adds no empty slot. Each topic's rate is
//! its count over its source's slots, with the busiest slot's count beside it; an SSE
//! `single_attestation` has a row per subnet as well. Bytes are [`ArrivalRecord::bytes`]: the
//! message data for gossip, the event's JSON for SSE.
//!
//! Records are read in arrival order, so a slot's count is closed when the next slot starts; a
//! wall clock stepped back opens a new run of the slot rather than reopening the old one.

use super::offsets::SlotClock;
use super::record::{ArrivalRecord, Source};
use super::topics::SINGLE_ATTESTATION;
use consensus_types::primitives::Slot;
use std::collections::{BTreeMap, BTreeSet};

/// One topic's rate.
#[derive(Debug, Clone, PartialEq)]
pub struct TopicRate {
    /// The source.
    pub source: Source,
    /// The topic: a gossip topic name, or an SSE event name.
    pub topic: String,
    /// The subnet, for a per-subnet row of SSE `single_attestation`.
    pub subnet: Option<u64>,
    /// Records.
    pub n: u64,
    /// Their bytes.
    pub bytes: u64,
    /// The slots the source recorded anything in.
    pub slots: u64,
    /// `n / slots`.
    pub msgs_per_slot: f64,
    /// `bytes / slots`.
    pub bytes_per_slot: f64,
    /// The most records in one slot.
    pub peak_msgs_per_slot: u64,
    /// The most bytes in one slot.
    pub peak_bytes_per_slot: u64,
}

/// Every topic's rate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rates {
    /// By source, topic and subnet (the topic's own row first).
    pub topics: Vec<TopicRate>,
    /// Records received before genesis: no slot, left out.
    pub before_genesis: u64,
}

/// Counts records one at a time ([`RateCounter::add`]), so a capture of any length fits.
#[derive(Debug)]
pub struct RateCounter {
    clock: SlotClock,
    slots: BTreeMap<Source, BTreeSet<Slot>>,
    rows: BTreeMap<(Source, String, Option<u64>), Row>,
    before_genesis: u64,
}

#[derive(Debug, Default)]
struct Row {
    n: u64,
    bytes: u64,
    /// The slot being counted, and its count so far.
    current: Option<(Slot, u64, u64)>,
    peak_msgs: u64,
    peak_bytes: u64,
}

impl Row {
    fn add(&mut self, slot: Slot, bytes: u64) {
        self.n += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        match &mut self.current {
            Some((at, n, b)) if *at == slot => {
                *n += 1;
                *b = b.saturating_add(bytes);
            }
            _ => {
                self.close();
                self.current = Some((slot, 1, bytes));
            }
        }
    }

    fn close(&mut self) {
        if let Some((_, n, b)) = self.current.take() {
            self.peak_msgs = self.peak_msgs.max(n);
            self.peak_bytes = self.peak_bytes.max(b);
        }
    }
}

impl RateCounter {
    /// Rates on `clock`'s slots.
    pub fn new(clock: SlotClock) -> Self {
        Self {
            clock,
            slots: BTreeMap::new(),
            rows: BTreeMap::new(),
            before_genesis: 0,
        }
    }

    /// Counts `record` in.
    pub fn add(&mut self, record: &ArrivalRecord) {
        let Some(slot) = self.clock.wall_slot(record.recv_wall_ns) else {
            self.before_genesis += 1;
            return;
        };
        self.slots.entry(record.source).or_default().insert(slot);
        let mut add = |subnet| {
            let key = (record.source, record.topic.clone(), subnet);
            self.rows.entry(key).or_default().add(slot, record.bytes);
        };
        add(None);
        if record.source == Source::Sse && record.topic == SINGLE_ATTESTATION {
            if let Some(subnet) = record.subnet {
                add(Some(subnet));
            }
        }
    }

    /// The rates of every record counted in.
    pub fn finish(mut self) -> Rates {
        let topics = (self.rows.iter_mut())
            .map(|((source, topic, subnet), row)| {
                row.close();
                let slots = self.slots.get(source).map_or(0, |s| s.len() as u64);
                let per_slot = |v: u64| {
                    if slots == 0 {
                        0.0
                    } else {
                        v as f64 / slots as f64
                    }
                };
                TopicRate {
                    source: *source,
                    topic: topic.clone(),
                    subnet: *subnet,
                    n: row.n,
                    bytes: row.bytes,
                    slots,
                    msgs_per_slot: per_slot(row.n),
                    bytes_per_slot: per_slot(row.bytes),
                    peak_msgs_per_slot: row.peak_msgs,
                    peak_bytes_per_slot: row.peak_bytes,
                }
            })
            .collect();
        Rates {
            topics,
            before_genesis: self.before_genesis,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(source: Source, topic: &str, wall_s: u64) -> ArrivalRecord {
        ArrivalRecord {
            source,
            topic: topic.into(),
            subnet: None,
            msg_id: None,
            block_root: None,
            slot: None,
            recv_mono_ns: 0,
            recv_wall_ns: wall_s * 1_000_000_000,
            peer: None,
            bytes: 10,
        }
    }

    #[test]
    fn each_source_has_its_own_slots_and_a_stepped_clock_opens_a_new_run() {
        let clock = SlotClock::new(0, 12_000).unwrap();
        let mut c = RateCounter::new(clock);
        for r in [
            at(Source::Gossip, "beacon_block", 1),
            at(Source::Gossip, "beacon_block", 13),
            at(Source::Gossip, "beacon_block", 14),
            // The wall clock stepped back into slot 0: a new run, not slot 0's again.
            at(Source::Gossip, "beacon_block", 2),
            at(Source::Sse, "block_gossip", 30),
        ] {
            c.add(&r);
        }
        let rates = c.finish();
        let gossip = &rates.topics[0];
        assert_eq!(
            (gossip.slots, gossip.n, gossip.peak_msgs_per_slot),
            (2, 4, 2)
        );
        assert_eq!(gossip.msgs_per_slot, 2.0);
        let sse = &rates.topics[1];
        assert_eq!(
            (sse.source, sse.slots, sse.bytes_per_slot),
            (Source::Sse, 1, 10.0)
        );
        assert_eq!(RateCounter::new(clock).finish(), Rates::default());
    }
}
