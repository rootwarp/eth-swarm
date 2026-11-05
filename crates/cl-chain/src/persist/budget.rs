//! The non-finality disk budget (stub).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use network_config::{ChainConfig, ConfigError};
use prometheus_client::registry::Registry;
use serde::Deserialize;

pub use store_schema::budget::{
    decide, stored, Branch, Budget, Caps, Decision, Kind, Observer, Usage, KINDS,
};

/// A mebibyte.
pub const MIB: u64 = 1 << 20;
/// A gibibyte.
pub const GIB: u64 = 1 << 30;

/// The `[chain.disk_budget]` table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DiskBudget {
    pub aggregate_mib: u64,
    pub columns_mib: u64,
    pub states_mib: u64,
    pub fc_snapshots_mib: u64,
    pub envelopes_mib: u64,
    pub pending_mib: u64,
    pub pending_items: u64,
    pub fc_snapshots_kept: u64,
    pub states_kept_per_epoch: u64,
    pub canonical_headroom_percent: u64,
    pub floor_min_mib: u64,
    pub floor_percent: u64,
    pub floor_hysteresis_mib: u64,
    pub sync_check_over_mib: u64,
}

impl DiskBudget {
    /// Why the table is refused at startup, if it is.
    ///
    /// # Errors
    ///
    /// The first value refused.
    pub fn check(&self) -> Result<(), String> {
        todo!()
    }

    /// The budget's caps.
    #[must_use]
    pub fn caps(&self) -> Caps {
        todo!()
    }

    /// The free-space floor.
    #[must_use]
    pub fn floor(&self) -> Floor {
        todo!()
    }
}

/// The reserved free-space floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Floor {
    pub min_bytes: u64,
    pub percent: u64,
    pub hysteresis_bytes: u64,
    pub sync_over_bytes: u64,
}

impl Floor {
    /// The floor on a volume of `total` bytes.
    #[must_use]
    pub fn bytes(&self, total: u64) -> u64 {
        let _ = total;
        todo!()
    }
}

/// A volume's space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsSpace {
    pub free: u64,
    pub total: u64,
}

/// Where the free space comes from.
pub trait FsStats: Send + Sync + std::fmt::Debug {
    /// The space of the volume `path` is on.
    ///
    /// # Errors
    ///
    /// The call failed.
    fn space(&self, path: &Path) -> io::Result<FsSpace>;
}

/// `statvfs(3)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Statvfs;

impl FsStats for Statvfs {
    fn space(&self, path: &Path) -> io::Result<FsSpace> {
        let _ = path;
        todo!()
    }
}

/// Why a write may not go ahead.
#[derive(Debug, thiserror::Error)]
pub enum FloorError {
    #[error("free space is below the reserved floor: import is stopped")]
    Closed,
    #[error("statvfs: {0}")]
    Stats(io::Error),
}

/// What the import core consults before it imports.
#[derive(Debug, Default)]
pub struct ImportGate {
    closed: std::sync::atomic::AtomicBool,
}

impl ImportGate {
    /// Whether import may go on.
    #[must_use]
    pub fn is_open(&self) -> bool {
        let _ = &self.closed;
        todo!()
    }

    /// `Ok` while the gate is open.
    ///
    /// # Errors
    ///
    /// [`FloorError::Closed`].
    pub fn check(&self) -> Result<(), FloorError> {
        todo!()
    }
}

/// The free-space floor's watcher.
#[derive(Debug)]
pub struct FloorWatcher {
    _dir: PathBuf,
}

impl FloorWatcher {
    /// A watcher of the volume of `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>, fs: Box<dyn FsStats>, floor: Floor) -> Self {
        let _ = (dir.into(), fs, floor);
        todo!()
    }

    /// The gate it opens and closes.
    #[must_use]
    pub fn gate(&self) -> Arc<ImportGate> {
        todo!()
    }

    /// The free bytes it last saw.
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        todo!()
    }

    /// One look at the free space; whether the gate is open after it.
    ///
    /// # Errors
    ///
    /// The look failed: the gate stays as it was.
    pub fn tick(&self) -> io::Result<bool> {
        todo!()
    }

    /// Before a write of `bytes`.
    ///
    /// # Errors
    ///
    /// [`FloorError`].
    pub fn before_write(&self, bytes: u64) -> Result<(), FloorError> {
        let _ = bytes;
        todo!()
    }

    /// Ticks every `every` until dropped.
    pub async fn run(self: Arc<Self>, every: Duration) {
        let _ = every;
        todo!()
    }
}

/// The envelope window's inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeWindow {
    pub gloas_fork_epoch: u64,
    pub min_epochs: u64,
    pub slots_per_epoch: u64,
    pub anchor_slot: u64,
}

impl EnvelopeWindow {
    /// The window of `config`.
    ///
    /// # Errors
    ///
    /// A config value it reads is missing or invalid.
    pub fn new(
        config: &ChainConfig,
        slots_per_epoch: u64,
        anchor_slot: u64,
    ) -> Result<Self, ConfigError> {
        let _ = (config, slots_per_epoch, anchor_slot);
        todo!()
    }
}

/// Whether the envelope at `slot` is kept.
#[must_use]
pub fn keep_envelope(
    slot: u64,
    finalized_slot: u64,
    current_epoch: u64,
    window: &EnvelopeWindow,
) -> bool {
    let _ = (slot, finalized_slot, current_epoch, window);
    todo!()
}

/// The budget's metrics.
#[derive(Debug)]
pub struct BudgetMetrics;

impl BudgetMetrics {
    /// Registers them in `registry`.
    pub fn register(
        registry: &mut Registry,
        budget: Arc<Budget>,
        floor: Option<Arc<FloorWatcher>>,
    ) {
        let _ = (registry, budget, floor);
        todo!()
    }
}
