//! Head lag is reference head slot minus our head slot; ahead observations remain signed.
//! Gaps are missing evidence, never zero lag. Live alerting/24-hour presentation is separate.

use consensus_types::primitives::Root;
use serde::{Deserialize, Serialize};

/// A head snapshot, including its root for downstream root-diff correlation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// Beacon head slot.
    pub slot: u64,
    /// Beacon block root.
    pub root: Root,
    /// Optional atomic chain.v1 head selection; absent on header-only or older observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_status: Option<crate::root_diff::PayloadStatus>,
}

/// Why a slot has no usable head comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gap {
    /// Our QueryService read failed.
    Ours,
    /// Reference header read failed.
    Reference,
    /// Both reads failed.
    Both,
    /// Polling slot was missed; no late read was substituted.
    MissedSample,
    /// Slot difference cannot be represented as a signed 64-bit lag.
    LagOverflow,
}

/// One shared JSONL observation. `slot` is the sampling slot, not either node's head slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    /// Wall-clock slot being sampled.
    pub slot: u64,
    /// Our head if available.
    pub ours: Option<Head>,
    /// Reference head if available.
    pub reference: Option<Head>,
    /// Signed reference-minus-ours lag; null on gaps.
    pub lag: Option<i64>,
    /// Missing evidence, if any.
    pub gap: Option<Gap>,
}

/// Sanitized errors; remote URLs and response bodies are never included.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid timing/epoch configuration.
    #[error("invalid head-lag configuration")]
    Config,
    /// Unrepresentable signed lag.
    #[error("head-slot difference exceeds signed lag range")]
    LagOverflow,
    /// Duplicate, reversed or unrepresentable timeline slots.
    #[error("head-lag timeline slots are not strictly increasing or overflow")]
    Timeline,

    /// A gap has a lag, or the recorded lag disagrees with its snapshots.
    #[error("inconsistent head-lag sample")]
    Sample,

    /// Transport, deadline or response-contract failure.
    #[error("head snapshot read failed")]
    Read,

    /// Output record serialization failed.
    #[error("head-lag record encoding failed")]
    Record,
    /// Input/output failed; a partial run is never a success.
    #[error("head-lag I/O: {0}")]
    Io(#[source] std::io::Error),

    /// Malformed or oversized shared JSONL input; response content is redacted.
    #[error("invalid or oversized head-lag JSONL record")]
    Input,
}

impl Sample {
    /// A completed comparison; signed subtraction never wraps.
    pub fn observed(slot: u64, ours: Head, reference: Head) -> Result<Self, Error> {
        let lag = i64::try_from(i128::from(reference.slot) - i128::from(ours.slot))
            .map_err(|_| Error::LagOverflow)?;
        Ok(Self {
            slot,
            ours: Some(ours),
            reference: Some(reference),
            lag: Some(lag),
            gap: None,
        })
    }

    /// Missing evidence; it cannot contribute a zero-lag value to percentiles.
    pub fn gap(slot: u64, reason: Gap) -> Self {
        Self {
            slot,
            ours: None,
            reference: None,
            lag: None,
            gap: Some(reason),
        }
    }
}

/// An observed recovery interval from lag >2 until the first subsequent lag <=2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Recovery {
    /// First above-target observation.
    pub start_slot: u64,
    /// First recovered observation, or null while still open at the run boundary.
    pub end_slot: Option<u64>,
    /// Sampling-slot distance; slot duration is supplied by the network configuration.
    pub elapsed_slots: u64,
    /// Whether the observed interval is longer than one epoch (inclusive limit).
    pub over_epoch: bool,
    /// Missing observations inside this interval make its exact recovery time uncertain.
    pub had_gaps: bool,
}

/// Run-wide computation, not a live alert or a time-windowed report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Nearest-rank 99th percentile; no value when no comparisons succeeded.
    pub p99: Option<i64>,
    /// Covered sampling slots (including explicit and missing-record gaps).
    pub samples: u64,
    /// Successful head comparisons contributing to percentile and worst.
    pub compared: u64,
    /// Covered slots with missing evidence, excluded from percentile/worst.
    pub gap_samples: u64,
    /// Maximum observed lag, excluding gaps.
    pub worst: Option<i64>,
    /// Completed and still-open recovery intervals in observation order.
    pub recoveries: Vec<Recovery>,
}

impl Summary {
    /// Whether nearest-rank p99 exceeds the inclusive two-slot target.
    pub fn exceeds_p99(&self) -> bool {
        self.p99.is_some_and(|lag| lag > 2)
    }
    /// Whether any observed lag exceeds the inclusive worst-case target.
    pub fn exceeds_worst(&self) -> bool {
        self.worst.is_some_and(|lag| lag > 32)
    }
    /// Whether any completed or open observed recovery exceeded an epoch.
    pub fn exceeds_recovery(&self) -> bool {
        self.recoveries.iter().any(|recovery| recovery.over_epoch)
    }
    /// Computed breach = 1; gaps/no data = 2; complete observations within thresholds = 0.
    pub fn exit_code(&self) -> u8 {
        if self.exceeds_p99() || self.exceeds_worst() || self.exceeds_recovery() {
            1
        } else if self.gap_samples > 0 || self.compared == 0 {
            2
        } else {
            0
        }
    }
}

/// Compute statistics from a synthetic or recorded timeline.
pub fn analyze(samples: &[Sample], slots_per_epoch: u64) -> Result<Summary, Error> {
    if slots_per_epoch == 0 {
        return Err(Error::Config);
    }
    if samples.windows(2).any(|pair| pair[0].slot >= pair[1].slot) {
        return Err(Error::Timeline);
    }
    for sample in samples {
        match (sample.lag, sample.gap) {
            (None, Some(_)) => {}
            (Some(lag), None) => {
                let Some((ours, reference)) = sample.ours.as_ref().zip(sample.reference.as_ref())
                else {
                    return Err(Error::Sample);
                };
                if i128::from(lag) != i128::from(reference.slot) - i128::from(ours.slot) {
                    return Err(Error::Sample);
                }
            }
            _ => return Err(Error::Sample),
        }
    }
    let covered = match samples.first().zip(samples.last()) {
        Some((first, last)) => last
            .slot
            .checked_sub(first.slot)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(Error::Timeline)?,
        None => 0,
    };
    let mut lags: Vec<_> = samples.iter().filter_map(|sample| sample.lag).collect();
    lags.sort_unstable();
    let rank = (lags.len() as u128 * 99).div_ceil(100) as usize;
    let mut recoveries = Vec::new();
    let mut active: Option<Recovery> = None;
    let mut previous = None;
    for sample in samples {
        if let Some(recovery) = &mut active {
            recovery.elapsed_slots = sample.slot - recovery.start_slot;
            recovery.over_epoch = recovery.elapsed_slots > slots_per_epoch;
            recovery.had_gaps |= previous.is_some_and(|previous| sample.slot - previous > 1);
        }
        match sample.lag {
            Some(lag) if lag > 2 => {
                if active.is_none() {
                    active = Some(Recovery {
                        start_slot: sample.slot,
                        end_slot: None,
                        elapsed_slots: 0,
                        over_epoch: false,
                        had_gaps: false,
                    });
                }
            }
            Some(_) => {
                if let Some(mut recovery) = active.take() {
                    recovery.end_slot = Some(sample.slot);
                    recoveries.push(recovery);
                }
            }
            None => {
                if let Some(recovery) = &mut active {
                    recovery.had_gaps = true;
                }
            }
        }
        previous = Some(sample.slot);
    }
    if let Some(recovery) = active {
        recoveries.push(recovery);
    }
    Ok(Summary {
        p99: lags.get(rank.saturating_sub(1)).copied(),
        worst: lags.last().copied(),
        samples: covered,
        compared: lags.len() as u64,
        gap_samples: covered - lags.len() as u64,
        recoveries,
    })
}

/// A real head transport or a deterministic synthetic timeline source.
pub trait HeadSource: Sync {
    /// Read the current head, with transport deadlines supplied by the implementation.
    fn read_head(&self) -> impl std::future::Future<Output = Result<Head, Error>> + Send;
}

impl HeadSource for crate::root_diff::Reference {
    async fn read_head(&self) -> Result<Head, Error> {
        let header = self.head_header().await.map_err(|_| Error::Read)?;
        let slot = header["data"]["header"]["message"]["slot"]
            .as_str()
            .ok_or(Error::Read)?;
        if slot.is_empty() || !slot.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Read);
        }
        let slot = slot.parse().map_err(|_| Error::Read)?;
        let root = header["data"]["root"]
            .as_str()
            .and_then(|root| root.strip_prefix("0x"))
            .and_then(crate::archive::canonical_hex::<32>)
            .ok_or(Error::Read)?;
        Ok(Head {
            payload_status: None,
            slot,
            root: Root::from(root),
        })
    }
}

impl HeadSource for crate::root_diff::QuerySource {
    async fn read_head(&self) -> Result<Head, Error> {
        let response = self
            .summary(ethswarm_proto::chain::hot_state_id::Id::Named(
                "head".to_owned(),
            ))
            .await
            .map_err(|_| Error::Read)?;
        let root: [u8; 32] = response.block_root.try_into().map_err(|_| Error::Read)?;
        let payload_status = response
            .payload_status
            .map(crate::root_diff::PayloadStatus::from_wire)
            .transpose()
            .map_err(|_| Error::Read)?;
        Ok(Head {
            payload_status,
            slot: response.slot,
            root: Root::from(root),
        })
    }
}

/// Read both heads concurrently. A failed side is retained as a gap, not a zero lag.
pub async fn observe(slot: u64, ours: &impl HeadSource, reference: &impl HeadSource) -> Sample {
    let (ours, reference) = tokio::join!(ours.read_head(), reference.read_head());
    let (ours, reference) = (ours.ok(), reference.ok());
    let (lag, gap) = match (&ours, &reference) {
        (Some(a), Some(b)) => match i64::try_from(i128::from(b.slot) - i128::from(a.slot)) {
            Ok(lag) => (Some(lag), None),
            Err(_) => (None, Some(Gap::LagOverflow)),
        },
        (Some(_), None) => (None, Some(Gap::Reference)),
        (None, Some(_)) => (None, Some(Gap::Ours)),
        (None, None) => (None, Some(Gap::Both)),
    };
    Sample {
        slot,
        ours,
        reference,
        lag,
        gap,
    }
}

/// Operational cap for a finite run (over four months at mainnet slot duration).
pub const MAX_SAMPLES: u64 = 1_000_000;

/// Slot sampling times, with a configurable offset (normally +4 seconds).
#[derive(Clone, Copy, Debug)]
pub struct SlotSchedule {
    genesis: u64,
    seconds_per_slot: u64,
    offset: std::time::Duration,
}

impl SlotSchedule {
    /// Validate nonzero slots and an offset strictly inside each slot.
    pub fn new(
        genesis: u64,
        seconds_per_slot: u64,
        offset: std::time::Duration,
    ) -> Result<Self, Error> {
        if seconds_per_slot == 0 || offset >= std::time::Duration::from_secs(seconds_per_slot) {
            return Err(Error::Config);
        }
        let value = Self {
            genesis,
            seconds_per_slot,
            offset,
        };
        value.due(0)?;
        Ok(value)
    }

    /// Poll timestamp since the Unix epoch, checked against the injected clock's range.
    pub fn due(&self, slot: u64) -> Result<std::time::Duration, Error> {
        let seconds = slot
            .checked_mul(self.seconds_per_slot)
            .and_then(|delta| self.genesis.checked_add(delta))
            .ok_or(Error::Config)?;
        let due = std::time::Duration::from_secs(seconds)
            .checked_add(self.offset)
            .ok_or(Error::Config)?;
        if due.as_nanos() > u128::from(u64::MAX) {
            return Err(Error::Config);
        }
        Ok(due)
    }

    /// First poll at or after now, preserving subsecond boundary precision.
    pub fn next_slot(&self, now: std::time::Duration) -> Result<u64, Error> {
        let Some(delta) = now.checked_sub(self.due(0)?) else {
            return Ok(0);
        };
        let slot = delta.as_secs() / self.seconds_per_slot;
        if self.due(slot)? < now {
            slot.checked_add(1).ok_or(Error::Config)
        } else {
            Ok(slot)
        }
    }
}

/// A finite collection window; no unbounded background polling task is spawned.
#[derive(Clone, Copy, Debug)]
pub struct RunConfig {
    /// Slot timing and configured sample offset.
    pub schedule: SlotSchedule,
    /// First wall-clock sampling slot.
    pub first_slot: u64,
    /// Number of consecutive slots (1 through MAX_SAMPLES).
    pub slots: u64,
    /// Network epoch length used by recovery computation.
    pub slots_per_epoch: u64,
}

/// Poll on fixed slot timestamps, flushing shared JSONL before computing the summary.
/// Clock/pause injection makes timing tests deterministic. Cancellation drops current reads.
pub async fn run(
    config: RunConfig,
    ours: &impl HeadSource,
    reference: &impl HeadSource,
    clock: &impl crate::collector::Clock,
    pause: &impl crate::collector::Pause,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<Summary, Error> {
    run_with_sink(
        config,
        ours,
        reference,
        clock,
        pause,
        &mut JsonlSink { output },
    )
    .await
}

/// A per-slot consumer, sharing the exact sampling cadence across lag and head comparisons.
pub trait SampleSink {
    /// Persist or process a completed sample; failure stops the finite run.
    fn record(&mut self, sample: &Sample) -> impl std::future::Future<Output = Result<(), Error>>;
}
struct JsonlSink<'a, W> {
    output: &'a mut W,
}
impl<W: tokio::io::AsyncWrite + Unpin> SampleSink for JsonlSink<'_, W> {
    async fn record(&mut self, sample: &Sample) -> Result<(), Error> {
        write_jsonl(self.output, sample).await
    }
}
pub(crate) async fn write_jsonl(
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    value: &impl Serialize,
) -> Result<(), Error> {
    use tokio::io::AsyncWriteExt;
    let mut line = serde_json::to_vec(value).map_err(|_| Error::Record)?;
    line.push(b'\n');
    output.write_all(&line).await.map_err(Error::Io)?;
    output.flush().await.map_err(Error::Io)
}

/// Poll fixed timestamps and deliver each gap/comparison once to a bounded consumer.
pub async fn run_with_sink(
    config: RunConfig,
    ours: &impl HeadSource,
    reference: &impl HeadSource,
    clock: &impl crate::collector::Clock,
    pause: &impl crate::collector::Pause,
    sink: &mut impl SampleSink,
) -> Result<Summary, Error> {
    use std::time::Duration;
    if config.slots == 0 || config.slots > MAX_SAMPLES || config.slots_per_epoch == 0 {
        return Err(Error::Config);
    }
    let end = config
        .first_slot
        .checked_add(config.slots)
        .ok_or(Error::Config)?;
    config.schedule.due(end - 1)?;
    let mut samples = Vec::new();
    for slot in config.first_slot..end {
        let due = config.schedule.due(slot)?;
        loop {
            let now = Duration::from_nanos(clock.now().wall_ns);
            let Some(wait) = due.checked_sub(now).filter(|wait| !wait.is_zero()) else {
                break;
            };
            pause.pause(wait).await;
        }
        let window = Duration::from_secs(config.schedule.seconds_per_slot);
        let mut sample = if Duration::from_nanos(clock.now().wall_ns).saturating_sub(due) >= window
        {
            Sample::gap(slot, Gap::MissedSample)
        } else {
            observe(slot, ours, reference).await
        };
        if Duration::from_nanos(clock.now().wall_ns).saturating_sub(due) >= window {
            sample = Sample::gap(slot, Gap::MissedSample);
        }
        sink.record(&sample).await?;
        samples.push(sample);
    }
    analyze(&samples, config.slots_per_epoch)
}

/// Read bounded shared JSONL samples and compute run-wide statistics.
/// Each line is at most 4 KiB; at most MAX_SAMPLES records are retained for the finite window.
/// Invalid records/order fail closed rather than silently lowering the percentile denominator.
pub async fn analyze_jsonl(
    input: impl tokio::io::AsyncRead + Unpin,
    slots_per_epoch: u64,
) -> Result<Summary, Error> {
    let samples = read_samples(input).await?;
    analyze(&samples, slots_per_epoch)
}

pub(crate) async fn read_samples(
    input: impl tokio::io::AsyncRead + Unpin,
) -> Result<Vec<Sample>, Error> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    fn append(line: &[u8], samples: &mut Vec<Sample>) -> Result<(), Error> {
        if samples.len() as u64 >= MAX_SAMPLES {
            return Err(Error::Config);
        }
        samples.push(serde_json::from_slice(line).map_err(|_| Error::Input)?);
        Ok(())
    }
    let mut reader = BufReader::new(input);
    let mut samples = Vec::new();
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(Error::Io)?;
        if available.is_empty() {
            if !line.is_empty() {
                append(&line, &mut samples)?;
            }
            break;
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |n| n + 1);
        if line.len() + count > 4096 {
            return Err(Error::Input);
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if line.last() == Some(&b'\n') {
            append(&line, &mut samples)?;
            line.clear();
        }
    }
    Ok(samples)
}

mod alerts;
pub use alerts::{run_live, Alert, AlertKind, Monitor, ALERT_RULES};

mod report;
pub use report::{report_jsonl, window_report, Report};
