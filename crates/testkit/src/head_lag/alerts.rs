//! Live sliding-window decisions. Alerts are local records, not external notifications.
use super::{analyze, Error, Sample};
use consensus_types::primitives::Root;
use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use serde::Serialize;
use std::collections::VecDeque;
#[derive(Default)]
struct Metrics {
    lag: Gauge,
    available: Gauge,
    p99: Gauge,
    count: Gauge,
    recovery: Gauge,
    active: Gauge,
    epoch: Gauge,
    uncertain: Gauge,
    updated: Gauge,
    period: Gauge,
}
impl Metrics {
    fn register(registry: &mut Registry) -> Self {
        let metrics = Self::default();
        for (name,help,gauge) in [
            ("head_lag_slots","Last available signed head lag; meaningful as current only when head_lag_available is one",metrics.lag.clone()),
            ("head_lag_available","One when this slot has both heads, zero for a gap",metrics.available.clone()),
            ("head_lag_p99_slots","Nearest-rank p99 of available samples in the trailing hour",metrics.p99.clone()),
            ("head_lag_window_samples","Available samples contributing to the trailing-hour p99",metrics.count.clone()),
            ("head_lag_recovery_slots","Elapsed sampling slots in the current observed recovery",metrics.recovery.clone()),
            ("head_lag_recovery_active","One while an observed recovery is still open",metrics.active.clone()),
            ("head_lag_slots_per_epoch","Configured inclusive recovery limit in slots",metrics.epoch.clone()),
            ("head_lag_updated_at_seconds","Unix time of the last observed polling slot, for scrape freshness",metrics.updated.clone()),
            ("head_lag_sample_period_seconds","Configured sample period for freshness checks",metrics.period.clone()),
            ("head_lag_recovery_uncertain","One if the open recovery crosses missing observations",metrics.uncertain.clone()),
        ] {registry.register(name,help,gauge);}
        metrics
    }
}

/// An exit-one threshold that became active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// Nearest-rank p99 exceeds two slots in the trailing hour.
    P99,
    /// A current sample exceeds thirty-two slots.
    Worst,
    /// An observed recovery has lasted longer than one epoch.
    Recovery,
}
/// A rising-edge alert, with explicit root-diff correlation context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// The threshold crossed.
    pub kind: AlertKind,
    /// Polling slot where the condition became active.
    pub slot: u64,
    /// The successful sample supplying both roots (can precede a gap-triggered alert).
    pub context_slot: u64,
    /// Our head root at context_slot.
    pub head_ours: Root,
    /// Reference head root at context_slot.
    pub head_ref: Root,
    /// Signed lag at context_slot.
    pub lag: i64,
    /// Trailing-hour nearest-rank p99, excluding gaps.
    pub p99: Option<i64>,
    /// Successful samples in the trailing hour; makes partial startup coverage explicit.
    pub window_samples: u64,
    /// Current recovery duration in sampling slots, if an episode is open.
    pub recovery_slots: Option<u64>,
    /// A recovery crossed gaps; its exact recovery time is uncertain.
    pub had_gaps: bool,
}
/// Bounded per-slot alert computation; a partial startup hour uses its available samples.
pub struct Monitor {
    seconds_per_slot: u64,
    window: VecDeque<Sample>,
    previous: Option<u64>,
    context: Option<Sample>,
    p99_active: bool,
    worst_active: bool,
    slots_per_epoch: u64,
    recovery: Option<(u64, bool)>,
    recovery_active: bool,
    metrics: Metrics,
    registry: Registry,
}
impl Monitor {
    /// Configure the sampling grid and recovery epoch length.
    pub fn new(seconds_per_slot: u64, slots_per_epoch: u64) -> Result<Self, Error> {
        if seconds_per_slot == 0 || slots_per_epoch == 0 {
            return Err(Error::Config);
        }
        let epoch = i64::try_from(slots_per_epoch).map_err(|_| Error::Config)?;
        let period = i64::try_from(seconds_per_slot).map_err(|_| Error::Config)?;
        let mut registry = Registry::default();
        let metrics = Metrics::register(&mut registry);
        metrics.epoch.set(epoch);
        metrics.period.set(period);
        Ok(Self {
            metrics,
            registry,
            seconds_per_slot,
            window: VecDeque::new(),
            previous: None,
            context: None,
            p99_active: false,
            worst_active: false,
            slots_per_epoch,
            recovery: None,
            recovery_active: false,
        })
    }
    /// Encode registered prometheus-client gauges. Availability/count disambiguate gaps
    /// and an empty percentile window; roots stay in alert records, never metric labels.
    pub fn metrics(&self) -> Result<String, Error> {
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &self.registry)
            .map_err(|_| Error::Record)?;
        Ok(text)
    }
    /// Observe each strictly increasing sample exactly once; reject forged evidence.
    pub fn observe(&mut self, sample: &Sample) -> Result<Vec<Alert>, Error> {
        analyze(std::slice::from_ref(sample), 1)?;
        if self.previous.is_some_and(|slot| slot >= sample.slot) {
            return Err(Error::Timeline);
        }
        if let Some((_, had_gaps)) = &mut self.recovery {
            *had_gaps |=
                sample.lag.is_none() || self.previous.is_some_and(|old| sample.slot - old > 1);
        }
        match sample.lag {
            Some(lag) if lag > 2 => {
                self.recovery.get_or_insert((sample.slot, false));
            }
            Some(_) => self.recovery = None,
            None => {}
        }
        let recovery_slots = self.recovery.map(|(start, _)| sample.slot - start);
        let had_gaps = self.recovery.is_some_and(|(_, gaps)| gaps);
        let recovering = recovery_slots.is_some_and(|slots| slots > self.slots_per_epoch);
        self.previous = Some(sample.slot);
        if sample.lag.is_some() {
            self.context = Some(sample.clone());
        }
        while self.window.front().is_some_and(|old| {
            u128::from(sample.slot - old.slot) * u128::from(self.seconds_per_slot) >= 3600
        }) {
            self.window.pop_front();
        }
        self.window.push_back(sample.clone());
        let mut lags: Vec<_> = self.window.iter().filter_map(|sample| sample.lag).collect();
        lags.sort_unstable();
        let rank = (lags.len() as u128 * 99).div_ceil(100) as usize;
        let p99 = lags.get(rank.saturating_sub(1)).copied();
        if let Some(lag) = sample.lag {
            self.metrics.lag.set(lag);
        }
        self.metrics.available.set(i64::from(sample.lag.is_some()));
        self.metrics.p99.set(p99.unwrap_or(0));
        self.metrics.count.set(lags.len() as i64);
        self.metrics.recovery.set(
            recovery_slots
                .map(|value| i64::try_from(value).unwrap_or(i64::MAX))
                .unwrap_or(0),
        );
        self.metrics.active.set(i64::from(self.recovery.is_some()));
        self.metrics.uncertain.set(i64::from(had_gaps));
        let active = p99.is_some_and(|lag| lag > 2);
        let mut alerts = Vec::new();
        let worst = sample.lag.is_some_and(|lag| lag > 32);
        for (kind, firing, previous) in [
            (AlertKind::P99, active, self.p99_active),
            (AlertKind::Worst, worst, self.worst_active),
            (AlertKind::Recovery, recovering, self.recovery_active),
        ] {
            if !firing || previous {
                continue;
            }
            let Some(context) = &self.context else {
                continue;
            };
            let (ours, reference) = context
                .ours
                .as_ref()
                .zip(context.reference.as_ref())
                .ok_or(Error::Sample)?;
            alerts.push(Alert {
                kind,
                slot: sample.slot,
                context_slot: context.slot,
                head_ours: ours.root,
                head_ref: reference.root,
                lag: context.lag.ok_or(Error::Sample)?,
                p99,
                window_samples: lags.len() as u64,
                recovery_slots,
                had_gaps,
            });
        }
        self.p99_active = active;
        self.worst_active = worst;
        self.recovery_active = recovering;
        Ok(alerts)
    }
}

struct LiveSink<'a, S, A> {
    monitor: Monitor,
    samples: &'a mut S,
    alerts: &'a mut A,
    metrics: Option<&'a std::path::Path>,
    clock: &'a dyn crate::collector::Clock,
}
impl<S: tokio::io::AsyncWrite + Unpin, A: tokio::io::AsyncWrite + Unpin> super::SampleSink
    for LiveSink<'_, S, A>
{
    async fn record(&mut self, sample: &Sample) -> Result<(), Error> {
        let alerts = self.monitor.observe(sample)?;
        self.monitor
            .metrics
            .updated
            .set((self.clock.now().wall_ns / 1_000_000_000) as i64);
        super::write_jsonl(self.samples, sample).await?;
        for alert in alerts {
            super::write_jsonl(self.alerts, &alert).await?;
        }
        if let Some(path) = self.metrics {
            publish_metrics(path, self.monitor.metrics()?).await?;
        }
        Ok(())
    }
}

async fn publish_metrics(path: &std::path::Path, text: String) -> Result<(), Error> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let temp = path.with_file_name(format!(
            ".head-lag-metrics.{}.{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // create_new establishes ownership: a collision must never be removed as our temp.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let result = (|| {
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, &path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    })
    .await
    .map_err(|_| Error::Io(std::io::Error::other("metrics publisher stopped")))?
    .map_err(Error::Io)
}

/// Sample and emit local alerts before advancing to the next slot. The output tuple is
/// `(samples_jsonl, alerts_jsonl, optional_metrics_path)`. The caller must exclusively own
/// that metrics path; publication replaces it atomically. Rule freshness checks prevent
/// an ended/cancelled run's last file snapshot from remaining a live alert forever.
pub async fn run_live(
    config: super::RunConfig,
    ours: &impl super::HeadSource,
    reference: &impl super::HeadSource,
    clock: &impl crate::collector::Clock,
    pause: &impl crate::collector::Pause,
    outputs: (
        &mut (impl tokio::io::AsyncWrite + Unpin),
        &mut (impl tokio::io::AsyncWrite + Unpin),
        Option<&std::path::Path>,
    ),
) -> Result<super::Summary, Error> {
    let monitor = Monitor::new(config.schedule.seconds_per_slot, config.slots_per_epoch)?;
    let mut sink = LiveSink {
        monitor,
        samples: outputs.0,
        alerts: outputs.1,
        metrics: outputs.2,
        clock,
    };
    super::run_with_sink(config, ours, reference, clock, pause, &mut sink).await
}

/// Prometheus rule document in JSON-compatible YAML syntax. Freshness gates exclude stale
/// textfile snapshots; detailed root context is in the companion local alert JSONL.
pub const ALERT_RULES: &str = include_str!("../../alerts/head-lag.rules.json");
