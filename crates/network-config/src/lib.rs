//! Network configuration for the Fulu/Gloas beacon node.
//!
//! - [`ChainConfig`]: a network's flat eth-clients `config.yaml`, embedded at a pinned commit and
//!   checked against its pinned sha256 on every load.
//! - [`ForkSchedule`]: which fork ([`ForkName`]) is active at an epoch.
//! - [`ChainConfig::get_blob_parameters`]: the EIP-7892 blob schedule lookup.
//! - [`digest`]: `compute_fork_digest` with the Fulu blob-parameter rule, and the wall-clock
//!   epoch.
//! - [`Network::genesis`]: the pinned genesis time and validators root.
//! - [`MAX_SEED_LOOKAHEAD`]: the preset activation lookahead.
//! - [`SPEC_PIN`]: the spec releases every type and vector in the workspace follows.

mod chain_config;
pub mod digest;
mod flat_yaml;
mod fork_schedule;
mod preset;

pub use chain_config::{
    BlobParameters, ChainConfig, ConfigError, Genesis, Network, PinnedSource,
    MAX_BLOB_COMMITMENTS_PER_BLOCK,
};
pub use fork_schedule::{
    Epoch, ForkName, ForkSchedule, ScheduleOrderError, ScheduledFork, UnknownFork, Version,
    FAR_FUTURE_EPOCH,
};
pub use preset::MAX_SEED_LOOKAHEAD;

/// The spec releases the workspace is pinned to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecPin {
    /// ethereum/consensus-specs tag.
    pub consensus_specs: &'static str,
    /// ethereum/ssz-specs tag (SSZ left consensus-specs).
    pub ssz_specs: &'static str,
}

/// consensus-specs `v1.7.0-beta.4` and ssz-specs `v0.1.0`.
pub const SPEC_PIN: SpecPin = SpecPin {
    consensus_specs: "v1.7.0-beta.4",
    ssz_specs: "v0.1.0",
};
