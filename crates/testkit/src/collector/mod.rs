//! The gossip/SSE arrival collector: when each block, envelope and column arrived, on a
//! monotonic and a wall clock, and how far into its slot and after its envelope.
//!
//! Two sources feed one [`Collector`] through a bounded [`Arrivals`] channel:
//!
//! - **gossip**: our probe's gossipsub tap ([`Tap`]). The probe stamps a message the moment
//!   gossipsub delivers it ([`Tap::now`]) and offers the undecoded [`TapRecord`]; it never waits.
//! - **SSE**: a reference node's `/eth/v1/events` ([`run_sse`]; beacon-APIs `01e99a6`
//!   eventstream), plain `http://` to a loopback [`ReferenceApiUrl`] (SSH tunnel for a remote
//!   node). Each body chunk is stamped as it arrives, before it is parsed. Disconnects are
//!   reconnected with backoff and recorded as [`MissingInterval`]s for the manifest.
//!
//! Stamps come from a [`Clock`] (`Instant` and `SystemTime`, [`SystemClock`]) and are taken
//! before any decode. The collector then decodes off the hot path: the slot and block root of a
//! gossip payload (by the fork of the object's own slot) or of an SSE event's JSON, writes one
//! [`ArrivalRecord`] per arrival, and hands gossip payloads to the archive
//! ([`crate::archive::Writer`]) as received. The host clock's NTP offset is sampled every
//! [`NTP_INTERVAL`] from its time daemon ([`TimeDaemon`]) and logged.
//!
//! Offsets are computed from the records afterwards:
//!
//! - slot-relative ([`SlotClock::offset`]): `recv_wall − (genesis_time + slot ×
//!   SLOT_DURATION_MS)`, from [`network_config::ChainConfig`];
//! - envelope-relative ([`envelope_relative`]): a column's arrival minus the arrival of the
//!   `execution_payload` envelope of the same `beacon_block_root`, on the monotonic clock;
//!   columns without one are counted as unmatched.

mod arrival;
mod clock;
mod decode;
mod envelope;
mod ntp;
mod offsets;
mod record;
mod sink;
mod sse;
mod tap;
mod url;

pub use arrival::{Arrival, Arrivals, Closed, Drops, MissingInterval, StampedEvent};
pub use clock::{Clock, Stamp, SystemClock};
pub use decode::{
    decode_gossip, decode_sse, parse_gossip_topic, topic_subnet, Decoded, GossipTopic,
};
pub use envelope::{envelope_relative, ArrivalKind, ColumnOffset, EnvelopeRelative};
pub use ntp::{
    parse_chrony_tracking, parse_timesyncd_status, sample, CommandDaemon, NtpSample, TimeDaemon,
    COMMAND_TIMEOUT, NTP_INTERVAL,
};
pub use offsets::{SlotClock, SlotOffset};
pub use record::{ArrivalRecord, Source};
pub use sink::{
    collect, read_capture, CaptureInfo, Collector, CollectorError, Summary, CAPTURE_FILE,
    GAPS_FILE, NTP_FILE, RECORDS_FILE, SUMMARY_FILE,
};
pub use sse::{
    genesis_time, run as run_sse, ApiError, Backoff, Pause, SseConfig, SseConfigError, SseEvent,
    SseParser, SseStats, TokioPause, TooLarge, DEFAULT_TOPICS, EVENTS_PATH, GENESIS_PATH,
    MAX_EVENT_BYTES, MAX_JSON_BYTES,
};
pub use tap::{Tap, TapRecord};
pub use url::{ReferenceApiUrl, UrlError};

#[cfg(any(test, feature = "test-support"))]
pub mod testing;
#[cfg(test)]
mod tests;
