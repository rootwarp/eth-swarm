//! The non-finality disk budget: how much unfinalized data cl-chain keeps while finality
//! stalls, and the free space it never eats into.
//!
//! - **Admission and accounting** are [`store_schema::budget`]'s, re-exported here: the per-kind
//!   counters ([`Kind`]) as `meta` rows written in the transaction of the write they count, and
//!   the decision at the budget ([`decide`], [`Budget::admit`]): over a cap a side-branch write
//!   is IGNOREd, a canonical one admitted up to the canonical headroom. The column writer
//!   (`cl_chain_columns::ColumnWriter::open_with_budget`) enforces it for columns; blocks,
//!   states, pending queues and fork-choice snapshots call [`Budget::admit`],
//!   [`Budget::charge`] and [`Budget::release`] in their own write transactions. Finalized data
//!   ([`Branch::Finalized`]) is never charged, never refused, and the budget never deletes.
//! - **Config** ([`DiskBudget`]): the `[chain.disk_budget]` table of `/etc/ethswarm/cl-chain.toml`
//!   (a table of `[chain]`, cl-chain's own). A missing key is its compiled-in default; an
//!   unknown key, or a per-type cap above the aggregate, fails the start.
//! - **The floor** ([`FloorWatcher`]): `statvfs` of the data directory once per slot
//!   ([`FloorWatcher::run`]) and before any write over the sync threshold
//!   ([`FloorWatcher::before_write`]). Below the reserved floor the [`ImportGate`] closes:
//!   import stops, finalized serving (cl-store, read-only) goes on. It opens again once free
//!   space is the hysteresis above the floor. `statvfs` is behind [`FsStats`], so tests use a
//!   fake.
//! - **Envelopes** ([`keep_envelope`]): every unfinalized one is kept, a finalized one inside
//!   `[max(GLOAS_FORK_EPOCH, current - compute_min_epochs_for_block_requests()), current]`; older
//!   ones are prunable, the anchor's never. It binds once the `envelopes` table has a writer.
//! - **Metrics** ([`BudgetMetrics`]): `chain_disk_budget_bytes{kind}`,
//!   `chain_disk_budget_cap_bytes{kind}`, `chain_disk_budget_refusals_total{kind,branch}`,
//!   `chain_disk_budget_reached`, `chain_disk_free_bytes`, `chain_disk_floor_reached`. Reaching
//!   the budget or the floor, and leaving it, is logged once per transition.
//!
//! # Proposed values
//!
//! All **proposed, pending Vera's review**; `crates/cl-chain/README.md` ("Non-finality disk
//! budget (proposed values)") records them with their reasoning, and
//! `tests/fixtures/budget.toml` holds them as a config table.
//!
//! | value | proposed |
//! |---|---|
//! | aggregate unfinalized | 48 GiB |
//! | columns / states / fc_snapshots / envelopes / pending | 32 GiB / 8 GiB / 512 MiB / 4 GiB / 1 GiB |
//! | item caps | states: last 2 per epoch per branch head, plus finalized; fc_snapshots: last 2; pending: 4,096 |
//! | canonical headroom | 10% over the aggregate |
//! | reserved free floor | max(10 GiB, 5% of the volume), reopening 1 GiB above it |
//! | synchronous `statvfs` | before writes over 16 MiB, else once per slot |

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use network_config::{window, ChainConfig, ConfigError, ForkName};
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::{counter::ConstCounter, gauge::ConstGauge, MetricType};
use prometheus_client::registry::Registry;
use serde::Deserialize;

pub use store_schema::budget::{
    decide, stored, Branch, Budget, Caps, Decision, Kind, Observer, Usage, KINDS,
};

/// A mebibyte.
pub const MIB: u64 = 1 << 20;
/// A gibibyte.
pub const GIB: u64 = 1 << 30;

/// The `[chain.disk_budget]` table; sizes in MiB. Its default is the proposed values (see the
/// module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DiskBudget {
    /// All kinds' unfinalized bytes together.
    pub aggregate_mib: u64,
    pub columns_mib: u64,
    pub states_mib: u64,
    pub fc_snapshots_mib: u64,
    pub envelopes_mib: u64,
    pub pending_mib: u64,
    /// Rows in the pending queues.
    pub pending_items: u64,
    /// Fork-choice snapshots kept.
    pub fc_snapshots_kept: u64,
    /// States kept per epoch per branch head, besides the finalized one: the states writer's
    /// retention, not a counter cap.
    pub states_kept_per_epoch: u64,
    /// How far over the aggregate canonical writes are still admitted.
    pub canonical_headroom_percent: u64,
    /// The reserved free floor is the larger of this and `floor_percent` of the volume.
    pub floor_min_mib: u64,
    pub floor_percent: u64,
    /// The gate opens again this far above the floor.
    pub floor_hysteresis_mib: u64,
    /// A write over this looks at the free space first.
    pub sync_check_over_mib: u64,
}

impl Default for DiskBudget {
    fn default() -> Self {
        Self {
            aggregate_mib: 48 * 1024,
            columns_mib: 32 * 1024,
            states_mib: 8 * 1024,
            fc_snapshots_mib: 512,
            envelopes_mib: 4 * 1024,
            pending_mib: 1024,
            pending_items: 4096,
            fc_snapshots_kept: 2,
            states_kept_per_epoch: 2,
            canonical_headroom_percent: 10,
            floor_min_mib: 10 * 1024,
            floor_percent: 5,
            floor_hysteresis_mib: 1024,
            sync_check_over_mib: 16,
        }
    }
}

impl DiskBudget {
    /// Why the table is refused at startup, if it is: a per-type cap above the aggregate, an
    /// aggregate of zero, a percentage over 100, or a size over `u64::MAX` bytes. Names the
    /// keys, never the values.
    ///
    /// # Errors
    ///
    /// The first value refused.
    pub fn check(&self) -> Result<(), String> {
        let sizes = [
            ("aggregate_mib", self.aggregate_mib),
            ("columns_mib", self.columns_mib),
            ("states_mib", self.states_mib),
            ("fc_snapshots_mib", self.fc_snapshots_mib),
            ("envelopes_mib", self.envelopes_mib),
            ("pending_mib", self.pending_mib),
            ("floor_min_mib", self.floor_min_mib),
            ("floor_hysteresis_mib", self.floor_hysteresis_mib),
            ("sync_check_over_mib", self.sync_check_over_mib),
        ];
        if let Some((key, _)) = sizes.iter().find(|(_, mib)| mib.checked_mul(MIB).is_none()) {
            return Err(format!("{key} is over u64::MAX bytes"));
        }
        if self.aggregate_mib == 0 {
            return Err("aggregate_mib must be positive".into());
        }
        if let Some((key, _)) = sizes[1..6]
            .iter()
            .find(|(_, mib)| *mib > self.aggregate_mib)
        {
            return Err(format!("{key} is above aggregate_mib"));
        }
        for (key, percent) in [
            ("floor_percent", self.floor_percent),
            (
                "canonical_headroom_percent",
                self.canonical_headroom_percent,
            ),
        ] {
            if percent > 100 {
                return Err(format!("{key} is over 100"));
            }
        }
        Ok(())
    }

    /// The budget's caps, in bytes.
    #[must_use]
    pub fn caps(&self) -> Caps {
        let mut caps = Caps {
            aggregate: self.aggregate_mib.saturating_mul(MIB),
            headroom_percent: self.canonical_headroom_percent,
            ..Caps::unlimited()
        };
        for (kind, mib) in [
            (Kind::Columns, self.columns_mib),
            (Kind::States, self.states_mib),
            (Kind::FcSnapshots, self.fc_snapshots_mib),
            (Kind::Envelopes, self.envelopes_mib),
            (Kind::Pending, self.pending_mib),
        ] {
            caps.bytes[kind as usize] = Some(mib.saturating_mul(MIB));
        }
        caps.items[Kind::Pending as usize] = Some(self.pending_items);
        caps.items[Kind::FcSnapshots as usize] = Some(self.fc_snapshots_kept);
        caps
    }

    /// The free-space floor, in bytes.
    #[must_use]
    pub fn floor(&self) -> Floor {
        Floor {
            min_bytes: self.floor_min_mib.saturating_mul(MIB),
            percent: self.floor_percent,
            hysteresis_bytes: self.floor_hysteresis_mib.saturating_mul(MIB),
            sync_over_bytes: self.sync_check_over_mib.saturating_mul(MIB),
        }
    }
}

/// The reserved free-space floor ([`DiskBudget::floor`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Floor {
    pub min_bytes: u64,
    pub percent: u64,
    pub hysteresis_bytes: u64,
    pub sync_over_bytes: u64,
}

impl Floor {
    /// The floor on a volume of `total` bytes: the larger of the minimum and the percentage.
    #[must_use]
    pub fn bytes(&self, total: u64) -> u64 {
        let share = u128::from(total) * u128::from(self.percent) / 100;
        self.min_bytes.max(u64::try_from(share).unwrap_or(u64::MAX))
    }
}

/// A volume's space, as an unprivileged process may use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsSpace {
    /// Bytes free to unprivileged users (`f_bavail`).
    pub free: u64,
    /// The volume's size.
    pub total: u64,
}

/// Where the free space comes from: [`Statvfs`], or a test's fake.
pub trait FsStats: Send + Sync + std::fmt::Debug {
    /// The space of the volume `path` is on.
    ///
    /// # Errors
    ///
    /// The call failed.
    fn space(&self, path: &Path) -> io::Result<FsSpace>;
}

/// `statvfs(3)` through rustix.
#[derive(Clone, Copy, Debug, Default)]
pub struct Statvfs;

impl FsStats for Statvfs {
    fn space(&self, path: &Path) -> io::Result<FsSpace> {
        let stat = rustix::fs::statvfs(path)?;
        Ok(FsSpace {
            free: stat.f_bavail.saturating_mul(stat.f_frsize),
            total: stat.f_blocks.saturating_mul(stat.f_frsize),
        })
    }
}

/// Why a write may not go ahead for the floor.
#[derive(Debug, thiserror::Error)]
pub enum FloorError {
    /// The import gate is closed.
    #[error("free space is below the reserved floor: import is stopped")]
    Closed,
    /// The synchronous look at the free space failed.
    #[error("statvfs: {0}")]
    Stats(io::Error),
}

/// What the import core consults before it imports: closed below the floor. Readers never
/// consult it.
#[derive(Debug, Default)]
pub struct ImportGate {
    closed: AtomicBool,
}

impl ImportGate {
    /// Whether import may go on.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    /// `Ok` while the gate is open.
    ///
    /// # Errors
    ///
    /// [`FloorError::Closed`].
    pub fn check(&self) -> Result<(), FloorError> {
        self.is_open().then_some(()).ok_or(FloorError::Closed)
    }
}

/// The free-space floor's watcher: opens and closes its [`ImportGate`].
#[derive(Debug)]
pub struct FloorWatcher {
    dir: PathBuf,
    fs: Box<dyn FsStats>,
    floor: Floor,
    gate: Arc<ImportGate>,
    free: AtomicU64,
}

impl FloorWatcher {
    /// A watcher of the volume of `dir`, its gate open until its first look.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>, fs: Box<dyn FsStats>, floor: Floor) -> Self {
        Self {
            dir: dir.into(),
            fs,
            floor,
            gate: Arc::default(),
            free: AtomicU64::new(0),
        }
    }

    /// The gate it opens and closes.
    #[must_use]
    pub fn gate(&self) -> Arc<ImportGate> {
        Arc::clone(&self.gate)
    }

    /// The free bytes it last saw.
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        self.free.load(Ordering::Relaxed)
    }

    /// One look at the free space: the gate closes below the floor and opens at the floor plus
    /// the hysteresis. Whether it is open after the look.
    ///
    /// # Errors
    ///
    /// The look failed: the gate stays as it was.
    pub fn tick(&self) -> io::Result<bool> {
        let space = self.fs.space(&self.dir)?;
        self.free.store(space.free, Ordering::Relaxed);
        let floor = self.floor.bytes(space.total);
        let open = self.gate.is_open();
        let now = if open {
            space.free >= floor
        } else {
            space.free >= floor.saturating_add(self.floor.hysteresis_bytes)
        };
        if now != open {
            self.gate.closed.store(!now, Ordering::Release);
            if now {
                tracing::info!(
                    free = space.free,
                    floor,
                    "disk_floor_reached cleared: import resumes"
                );
            } else {
                tracing::warn!(free = space.free, floor, "disk_floor_reached: import stops");
            }
        }
        Ok(now)
    }

    /// Before a write of `bytes`: over the sync threshold it looks at the free space first;
    /// then the gate must be open.
    ///
    /// # Errors
    ///
    /// [`FloorError::Stats`] if that look failed, [`FloorError::Closed`] below the floor.
    pub fn before_write(&self, bytes: u64) -> Result<(), FloorError> {
        if bytes > self.floor.sync_over_bytes {
            self.tick().map_err(FloorError::Stats)?;
        }
        self.gate.check()
    }

    /// Looks once every `every` (a slot) until the future is dropped. A failed look is logged
    /// and leaves the gate as it was.
    pub async fn run(self: Arc<Self>, every: Duration) {
        let mut ticks = tokio::time::interval(every);
        loop {
            ticks.tick().await;
            if let Err(e) = self.tick() {
                tracing::warn!(error = %e, dir = %self.dir.display(), "statvfs failed");
            }
        }
    }
}

/// The envelope window's inputs ([`keep_envelope`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeWindow {
    /// `GLOAS_FORK_EPOCH`; `u64::MAX` if Gloas is not scheduled.
    pub gloas_fork_epoch: u64,
    /// `compute_min_epochs_for_block_requests()` from Gloas on.
    pub min_epochs: u64,
    pub slots_per_epoch: u64,
    /// The anchor's slot: its envelope is never pruned.
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
        let gloas_fork_epoch = config
            .fork_schedule()
            .fork_epoch(ForkName::Gloas)
            .unwrap_or(u64::MAX);
        Ok(Self {
            gloas_fork_epoch,
            min_epochs: window::min_epochs_for_block_requests(config, gloas_fork_epoch)?,
            slots_per_epoch,
            anchor_slot,
        })
    }
}

/// Whether the envelope at `slot` is kept: unfinalized (above `finalized_slot`), the anchor's,
/// or in an epoch from `max(GLOAS_FORK_EPOCH, current_epoch - min_epochs)` on. Any other is
/// prunable by the envelopes table's finality prune.
#[must_use]
pub fn keep_envelope(
    slot: u64,
    finalized_slot: u64,
    current_epoch: u64,
    window: &EnvelopeWindow,
) -> bool {
    let start = window
        .gloas_fork_epoch
        .max(current_epoch.saturating_sub(window.min_epochs));
    slot > finalized_slot
        || slot == window.anchor_slot
        || slot / window.slots_per_epoch.max(1) >= start
}

/// The budget's and the floor's metrics, read at each scrape ([`Collector`]).
#[derive(Debug)]
pub struct BudgetMetrics {
    budget: Arc<Budget>,
    floor: Option<Arc<FloorWatcher>>,
}

impl BudgetMetrics {
    /// Registers them in `registry`, and logs the budget's transitions.
    pub fn register(
        registry: &mut Registry,
        budget: Arc<Budget>,
        floor: Option<Arc<FloorWatcher>>,
    ) {
        budget.on_transition(Box::new(|reached, kind, branch| {
            let (kind, branch) = (kind.name(), branch.name());
            if reached {
                tracing::warn!(
                    kind,
                    branch,
                    "disk_budget_reached: unfinalized writes ignored"
                );
            } else {
                tracing::info!(kind, branch, "disk_budget_reached cleared");
            }
        }));
        registry.register_collector(Box::new(Self { budget, floor }));
    }
}

/// One gauge with no label.
fn gauge(encoder: &mut DescriptorEncoder, name: &str, help: &str, value: u64) -> std::fmt::Result {
    ConstGauge::new(value).encode(encoder.encode_descriptor(name, help, None, MetricType::Gauge)?)
}

/// One gauge per label set.
fn gauges<const N: usize>(
    encoder: &mut DescriptorEncoder,
    name: &str,
    help: &str,
    series: &[([(&'static str, &'static str); N], u64)],
) -> std::fmt::Result {
    let mut metric = encoder.encode_descriptor(name, help, None, MetricType::Gauge)?;
    for (labels, value) in series {
        ConstGauge::new(*value).encode(metric.encode_family(labels)?)?;
    }
    Ok(())
}

impl Collector for BudgetMetrics {
    fn encode(&self, mut encoder: DescriptorEncoder) -> std::fmt::Result {
        let budget = &self.budget;
        let caps = budget.caps();
        let mut used = vec![([("kind", "aggregate")], budget.total())];
        let mut capped = vec![([("kind", "aggregate")], caps.aggregate)];
        let mut refusals = Vec::new();
        for kind in Kind::ALL {
            used.push(([("kind", kind.name())], budget.used(kind).bytes));
            if let Some(cap) = caps.bytes[kind as usize] {
                capped.push(([("kind", kind.name())], cap));
            }
            for branch in [Branch::Canonical, Branch::Side] {
                let labels = [("kind", kind.name()), ("branch", branch.name())];
                refusals.push((labels, budget.refusals(kind, branch)));
            }
        }
        let e = &mut encoder;
        gauges(
            e,
            "chain_disk_budget_bytes",
            "Unfinalized bytes stored, by kind",
            &used,
        )?;
        gauges(
            e,
            "chain_disk_budget_cap_bytes",
            "Disk budget caps, by kind",
            &capped,
        )?;
        let help = "Unfinalized writes the disk budget ignored, by kind and branch";
        let mut metric = e.encode_descriptor(
            "chain_disk_budget_refusals",
            help,
            None,
            MetricType::Counter,
        )?;
        for (labels, value) in &refusals {
            ConstCounter::new(*value).encode(metric.encode_family(labels)?)?;
        }
        let reached = u64::from(budget.reached());
        gauge(
            e,
            "chain_disk_budget_reached",
            "1 while the disk budget refuses",
            reached,
        )?;
        if let Some(floor) = &self.floor {
            let free = floor.free_bytes();
            gauge(
                e,
                "chain_disk_free_bytes",
                "Free bytes on the data volume",
                free,
            )?;
            let closed = u64::from(!floor.gate().is_open());
            gauge(
                e,
                "chain_disk_floor_reached",
                "1 while import is stopped",
                closed,
            )?;
        }
        Ok(())
    }
}
