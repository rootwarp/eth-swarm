//! The gossip/SSE arrival collector: when each block, envelope and column arrived, on a
//! monotonic and a wall clock, and how far into its slot and after its envelope.
//!
//! Two sources feed one [`Collector`] through a bounded [`Arrivals`] channel (by entries and by
//! queued bytes):
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
//! What a capture subscribes is configuration ([`TopicConfig`], a topics file read as data): the
//! SSE events of the exit-14 topic set and the attestation subnets sampled. Both go into
//! `capture.toml` with the events the node refused at start, and `summary.toml` gives each
//! topic and sampled subnet its count, listing those with none as gaps ([`Summary`]).
//!
//! Offsets and rates are computed from the records afterwards:
//!
//! - slot-relative ([`SlotClock::offset`]): `recv_wall − (genesis_time + slot ×
//!   SLOT_DURATION_MS)`, from [`network_config::ChainConfig`];
//! - envelope-relative ([`envelope_relative`]): a column's arrival minus the arrival of the
//!   `execution_payload` envelope of the same `beacon_block_root`, on the monotonic clock;
//!   columns without one are counted as unmatched;
//! - per-topic rates ([`RateCounter`]): messages and bytes per slot, and the busiest slot's.

mod arrival;
mod clock;
mod decode;
mod envelope;
mod ntp;
mod offsets;
mod rates;
mod record;
mod sink;
mod sse;
mod tap;
mod topics;
mod url;

pub use arrival::{
    Arrival, ArrivalReceiver, Arrivals, Closed, Drops, MissingInterval, StampedEvent,
};
pub use clock::{Clock, Stamp, SystemClock};
pub use decode::{
    decode_gossip, decode_sse, parse_gossip_topic, topic_subnet, Decoded, GossipTopic, SseSubnets,
};
pub use envelope::{
    envelope_relative, ArrivalKind, ColumnMatch, ColumnOffset, EnvelopeIndex, EnvelopeRelative,
};
pub use ntp::{
    parse_chrony_tracking, parse_timesyncd_status, sample, CommandDaemon, NtpSample, TimeDaemon,
    COMMAND_TIMEOUT, NTP_INTERVAL,
};
pub use offsets::{SlotClock, SlotOffset};
pub use rates::{RateCounter, Rates, TopicRate};
pub use record::{ArrivalRecord, Source};
pub use sink::{
    collect, read_capture, read_info, read_summary, records, CaptureInfo, Collector,
    CollectorError, Records, SubnetCount, Summary, TopicCount, CAPTURE_FILE, GAPS_FILE,
    MAX_RECORD_LINE_BYTES, NTP_FILE, RECORDS_FILE, SUMMARY_FILE,
};
pub(crate) use sse::get as api_get;
pub use sse::{
    committees_per_slot, config_name, genesis_time, node_attnets, run as run_sse, supported_topics,
    ApiError, Backoff, Pause, SseConfig, SseConfigError, SseEvent, SseParser, SseStats, TokioPause,
    TooLarge, COMMITTEES_PATH, DEFAULT_TOPICS, EVENTS_PATH, GENESIS_PATH, IDENTITY_PATH,
    MAX_COMMITTEES_BYTES, MAX_COMMITTEES_PER_SLOT, MAX_EVENT_BYTES, MAX_EVENT_NAME_BYTES,
    MAX_IDENTITY_BYTES, MAX_JSON_BYTES, MAX_SPEC_BYTES, SPEC_PATH,
};
pub use tap::{Tap, TapRecord};
pub use topics::{
    TopicConfig, TopicsFileError, EXIT14_SSE_EVENTS, FALLBACK_SSE_EVENTS, KNOWN_SSE_EVENTS,
    MAX_TOPICS_FILE_BYTES, SINGLE_ATTESTATION,
};
pub use url::{ReferenceApiUrl, UrlError, UrlFileError, MAX_URL_FILE_BYTES};

#[cfg(any(test, feature = "test-support"))]
pub mod testing;
#[cfg(test)]
mod tests;
