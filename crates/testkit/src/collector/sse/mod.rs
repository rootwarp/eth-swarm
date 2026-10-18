//! The reference node's `/eth/v1/events` stream (beacon-APIs eventstream).

mod client;
mod node;
mod parse;
mod spec;

pub(crate) use client::get;
pub use client::{
    genesis_time, run, supported_topics, ApiError, Backoff, Pause, SseConfig, SseConfigError,
    SseStats, TokioPause, DEFAULT_TOPICS, EVENTS_PATH, GENESIS_PATH, MAX_JSON_BYTES,
};
pub use node::{
    committees_per_slot, node_attnets, COMMITTEES_PATH, IDENTITY_PATH, MAX_COMMITTEES_BYTES,
    MAX_COMMITTEES_PER_SLOT, MAX_IDENTITY_BYTES,
};
pub use parse::{SseEvent, SseParser, TooLarge, MAX_EVENT_BYTES, MAX_EVENT_NAME_BYTES};
pub use spec::{config_name, MAX_SPEC_BYTES, SPEC_PATH};
