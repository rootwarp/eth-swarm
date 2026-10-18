//! Slot-relative offsets: `recv_wall − (genesis_time + slot × SLOT_DURATION_MS)`.

use super::record::ArrivalRecord;
use consensus_types::primitives::Slot;
use network_config::ChainConfig;

const NS_PER_MS: u64 = 1_000_000;
const NS_PER_S: u64 = 1_000_000_000;

/// The slot schedule: `genesis_time` and `SLOT_DURATION_MS` of [`ChainConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotClock {
    genesis_ns: u64,
    slot_ns: u64,
}

/// An arrival against the start of its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotOffset {
    /// The record's slot, or the wall-clock slot of its arrival when it has none.
    pub slot: Slot,
    /// `recv_wall − slot start`, in nanoseconds: negative for an arrival before its slot.
    pub offset_ns: i64,
}

impl SlotOffset {
    /// [`SlotOffset::offset_ns`] in milliseconds.
    pub fn offset_ms(&self) -> f64 {
        self.offset_ns as f64 / NS_PER_MS as f64
    }
}

impl SlotClock {
    /// A schedule from `genesis_time` (Unix seconds) and the slot duration in milliseconds.
    /// `None` for a zero duration or a genesis that nanoseconds cannot hold.
    pub fn new(genesis_time: u64, slot_duration_ms: u64) -> Option<Self> {
        if slot_duration_ms == 0 {
            return None;
        }
        Some(Self {
            genesis_ns: genesis_time.checked_mul(NS_PER_S)?,
            slot_ns: slot_duration_ms.checked_mul(NS_PER_MS)?,
        })
    }

    /// The schedule of `config` (`SLOT_DURATION_MS`) from `genesis_time`.
    pub fn from_config(config: &ChainConfig, genesis_time: u64) -> Option<Self> {
        Self::new(genesis_time, config.slot_duration_ms())
    }

    /// The start of `slot`, Unix nanoseconds; `None` past `u64`.
    pub fn slot_start_ns(&self, slot: Slot) -> Option<u64> {
        slot.checked_mul(self.slot_ns)?.checked_add(self.genesis_ns)
    }

    /// The slot `wall_ns` falls in; `None` before genesis.
    pub fn wall_slot(&self, wall_ns: u64) -> Option<Slot> {
        Some(wall_ns.checked_sub(self.genesis_ns)? / self.slot_ns)
    }

    /// `record`'s arrival against the start of its slot (its wall-clock slot when it carries
    /// none). `None` if there is no slot (before genesis) or the offset does not fit.
    pub fn offset(&self, record: &ArrivalRecord) -> Option<SlotOffset> {
        let slot = match record.slot {
            Some(slot) => slot,
            None => self.wall_slot(record.recv_wall_ns)?,
        };
        let start = self.slot_start_ns(slot)?;
        let offset = i128::from(record.recv_wall_ns) - i128::from(start);
        Some(SlotOffset {
            slot,
            offset_ns: i64::try_from(offset).ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::record::Source;
    use network_config::Network;

    fn at(slot: Option<Slot>, wall_ns: u64) -> ArrivalRecord {
        ArrivalRecord {
            source: Source::Sse,
            topic: "block_gossip".into(),
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
    fn early_and_late_arrivals() {
        let clock = SlotClock::new(100, 12_000).unwrap();
        let slot_5 = clock.slot_start_ns(5).unwrap();
        assert_eq!(slot_5, 100 * NS_PER_S + 60 * NS_PER_S);
        // 200 ms before slot 5 starts: still slot 4 on the wall, -200 ms against slot 5.
        let early = at(Some(5), slot_5 - 200 * NS_PER_MS);
        let got = clock.offset(&early).unwrap();
        assert_eq!((got.slot, got.offset_ns), (5, -200_000_000));
        assert_eq!(clock.wall_slot(early.recv_wall_ns), Some(4));
        // A block 2 slots late.
        let late = clock.offset(&at(Some(5), slot_5 + 24 * NS_PER_S)).unwrap();
        assert_eq!(late.offset_ms(), 24_000.0);
    }

    #[test]
    fn before_genesis_and_out_of_range() {
        let clock = SlotClock::new(100, 12_000).unwrap();
        assert_eq!(clock.wall_slot(99 * NS_PER_S), None);
        assert_eq!(clock.offset(&at(None, 0)), None);
        assert_eq!(clock.slot_start_ns(u64::MAX), None);
        assert_eq!(clock.offset(&at(Some(u64::MAX), 0)), None);
        // A wall time i64 nanoseconds cannot hold relative to genesis.
        let far = SlotClock::new(0, 1).unwrap();
        assert_eq!(far.offset(&at(Some(0), u64::MAX)), None);
        assert_eq!(SlotClock::new(100, 0), None);
        assert_eq!(SlotClock::new(u64::MAX, 12_000), None);
        assert_eq!(SlotClock::new(0, u64::MAX), None);
    }

    #[test]
    fn the_pinned_config_names_the_slot_duration() {
        let config = ChainConfig::load(Network::Hoodi).unwrap();
        let clock = SlotClock::from_config(&config, 1_000).unwrap();
        assert_eq!(clock.slot_start_ns(1), Some(1_012 * NS_PER_S));
    }
}
