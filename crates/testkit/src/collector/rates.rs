//! Per-topic rates: messages and bytes per slot, from a capture's records.
//!
//! A record's slot is the wall-clock slot of its arrival ([`SlotClock::wall_slot`]), not the
//! slot it names: rates measure the traffic a slot carries. A source's slots are the slots in
//! which it recorded anything, so a missing interval adds no empty slot. Each topic's rate is
//! its count over its source's slots, with the busiest slot's count beside it; an SSE
//! `single_attestation` has a row per subnet as well. Bytes are [`ArrivalRecord::bytes`]: the
//! message data for gossip, the event's JSON for SSE. [`RateCounter::configure`] gives every
//! configured topic and sampled subnet of a `summary.toml` its row, so one with no records is a
//! 0 row rather than absent.
//!
//! A row counts each of its slots apart, so the busiest slot is the true maximum: a wall clock
//! stepped back into an earlier slot adds to that slot's count. Memory grows with the slots
//! seen in the capture (at most one entry per record per row), not with the records.

use super::offsets::SlotClock;
use super::record::{ArrivalRecord, Source};
use super::sink::Summary;
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

/// Counts records one at a time ([`RateCounter::add`]): records are never held, only a count
/// per row and slot seen.
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
    /// `(n, bytes)` of each slot the row recorded anything in.
    per_slot: BTreeMap<Slot, (u64, u64)>,
}

impl Row {
    fn add(&mut self, slot: Slot, bytes: u64) {
        self.n += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        let (n, b) = self.per_slot.entry(slot).or_default();
        *n += 1;
        *b = b.saturating_add(bytes);
    }

    /// The most records, and the most bytes, in one slot.
    fn peaks(&self) -> (u64, u64) {
        (self.per_slot.values()).fold((0, 0), |(n, b), (sn, sb)| (n.max(*sn), b.max(*sb)))
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

    /// Gives every topic of `summary` (a capture's `summary.toml`: each configured topic, the
    /// refused ones included) a row, and every sampled SSE subnet a `single_attestation` one
    /// when that topic has a row, so a configured topic with no records is a 0 row. A gossip
    /// subnet is a topic (`beacon_attestation_<n>`) of its own.
    pub fn configure(&mut self, summary: &Summary) {
        for t in &summary.topics {
            self.rows
                .entry((t.source, t.topic.clone(), None))
                .or_default();
        }
        let attestations = (Source::Sse, SINGLE_ATTESTATION.to_owned(), None);
        if !self.rows.contains_key(&attestations) {
            return;
        }
        for s in &summary.attestation_subnets {
            if s.source == Source::Sse {
                let key = (Source::Sse, SINGLE_ATTESTATION.to_owned(), Some(s.subnet));
                self.rows.entry(key).or_default();
            }
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
    pub fn finish(self) -> Rates {
        let topics = (self.rows.iter())
            .map(|((source, topic, subnet), row)| {
                let (peak_msgs, peak_bytes) = row.peaks();
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
                    peak_msgs_per_slot: peak_msgs,
                    peak_bytes_per_slot: peak_bytes,
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
    fn a_clock_stepped_back_adds_to_the_earlier_slot_count() {
        let clock = SlotClock::new(0, 12_000).unwrap();
        let mut c = RateCounter::new(clock);
        // Slots 0, 1, then 0 again: slot 0 holds two records, not two runs of one.
        for wall_s in [1, 13, 2] {
            c.add(&at(Source::Gossip, "beacon_block", wall_s));
        }
        let rates = c.finish();
        let row = &rates.topics[0];
        assert_eq!(
            (
                row.slots,
                row.n,
                row.peak_msgs_per_slot,
                row.peak_bytes_per_slot
            ),
            (2, 3, 2, 20)
        );
    }

    #[test]
    fn configured_topics_without_records_are_zero_rows() {
        use crate::collector::sink::{SubnetCount, Summary, TopicCount};
        let topic = |source, topic: &str, n| TopicCount {
            source,
            topic: topic.into(),
            n,
            bytes: n * 10,
        };
        let subnet = |source, subnet| SubnetCount {
            source,
            subnet,
            n: 0,
            bytes: 0,
        };
        let summary = Summary {
            topics: vec![
                topic(Source::Sse, "block_gossip", 1),
                topic(Source::Sse, "execution_payload_bid", 0),
                topic(Source::Sse, SINGLE_ATTESTATION, 0),
                topic(Source::Gossip, "beacon_block", 0),
            ],
            // An SSE subnet is a single_attestation row; a gossip one is a topic of its own.
            attestation_subnets: vec![subnet(Source::Sse, 3), subnet(Source::Gossip, 4)],
            ..Summary::default()
        };
        let mut c = RateCounter::new(SlotClock::new(0, 12_000).unwrap());
        c.configure(&summary);
        c.add(&at(Source::Sse, "block_gossip", 1));
        let rates = c.finish();
        // (topic, subnet, n, slots, msgs/slot, peak msgs): the gossip row has no slot of its own.
        let rows: Vec<_> = (rates.topics.iter())
            .map(|r| {
                let t = r.topic.as_str();
                (
                    t,
                    r.subnet,
                    r.n,
                    r.slots,
                    r.msgs_per_slot,
                    r.peak_msgs_per_slot,
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("beacon_block", None, 0, 0, 0.0, 0),
                ("block_gossip", None, 1, 1, 1.0, 1),
                ("execution_payload_bid", None, 0, 1, 0.0, 0),
                (SINGLE_ATTESTATION, None, 0, 1, 0.0, 0),
                (SINGLE_ATTESTATION, Some(3), 0, 1, 0.0, 0),
            ]
        );
        assert_eq!(rates.topics[0].source, Source::Gossip);
        assert_eq!(rates.topics[2].peak_bytes_per_slot, 0);
        // Without a single_attestation row, an SSE subnet gets none either.
        let mut c = RateCounter::new(SlotClock::new(0, 12_000).unwrap());
        c.configure(&Summary {
            attestation_subnets: vec![subnet(Source::Sse, 3)],
            ..Summary::default()
        });
        assert_eq!(c.finish().topics, []);
    }

    #[test]
    fn each_source_has_its_own_slots() {
        let clock = SlotClock::new(0, 12_000).unwrap();
        let mut c = RateCounter::new(clock);
        for r in [
            at(Source::Gossip, "beacon_block", 1),
            at(Source::Gossip, "beacon_block", 13),
            at(Source::Gossip, "beacon_block", 14),
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
