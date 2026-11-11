//! Deterministic 24-hour reports: missing evidence must never qualify an exit.
use super::{analyze, Error, Sample, Summary};

/// A trailing, slot-aligned 24-hour result, including unobserved leading/trailing slots.
#[derive(Debug)]
pub struct Report {
    /// First representable sampling slot in the requested window.
    pub start_slot: u64,
    /// Inclusive final sampling slot.
    pub end_slot: u64,
    /// Configured slot duration.
    pub seconds_per_slot: u64,
    /// Inclusive recovery target.
    pub slots_per_epoch: u64,
    /// Statistics of observed values, with coverage normalized to the full requested window.
    pub summary: Summary,
    /// Time without a successful head comparison (includes missing JSONL records).
    pub gap_seconds: u64,
}
impl Report {
    fn complete(&self) -> bool {
        self.summary.gap_samples == 0 && self.summary.compared > 0
    }
    fn recovery_pass(&self) -> bool {
        self.complete()
            && !self.summary.exceeds_recovery()
            && self.summary.recoveries.iter().all(|r| r.end_slot.is_some())
    }
    /// Observed breach=1; incomplete coverage/open recovery=2; qualified report=0.
    pub fn exit_code(&self) -> u8 {
        if self.summary.exceeds_p99()
            || self.summary.exceeds_worst()
            || self.summary.exceeds_recovery()
        {
            1
        } else if !self.complete() || !self.recovery_pass() {
            2
        } else {
            0
        }
    }
    /// Stable Markdown. PASS requires complete evidence, not merely low observed lag.
    pub fn markdown(&self) -> String {
        let verdict = |pass| if pass { "PASS" } else { "FAIL" };
        let value = |lag: Option<i64>| {
            lag.map(|lag| lag.to_string())
                .unwrap_or_else(|| "unavailable".into())
        };
        let mut text = format!(
            "# Head-lag report\n\n\
Window: 24h; slots {start}..={end} ({expected} expected).\n\
Slot duration: {period} s; epoch: {epoch} slots.\n\
Samples: {compared} compared, {gaps} gaps ({gap_seconds} s).\n\n\
Overall: {overall}\n\n\
## Exit-one thresholds\n\
- p99 <= 2 slots: {p99_result} (observed: {p99}).\n\
- worst <= 32 slots: {worst_result} (observed: {worst}).\n\
- recovery <= 1 epoch: {recovery}.\n\
- complete evidence: {coverage}.\n\n\
## Recoveries\n",
            start = self.start_slot,
            end = self.end_slot,
            expected = self.summary.samples,
            period = self.seconds_per_slot,
            epoch = self.slots_per_epoch,
            compared = self.summary.compared,
            gaps = self.summary.gap_samples,
            gap_seconds = self.gap_seconds,
            overall = verdict(self.exit_code() == 0),
            p99_result = verdict(self.complete() && self.summary.p99.is_some_and(|v| v <= 2)),
            p99 = value(self.summary.p99),
            worst_result = verdict(self.complete() && self.summary.worst.is_some_and(|v| v <= 32)),
            worst = value(self.summary.worst),
            recovery = verdict(self.recovery_pass()),
            coverage = verdict(self.complete()),
        );
        if self.summary.recoveries.is_empty() {
            text.push_str("None observed.\n");
        } else {
            text.push_str("| Start slot | End slot | Elapsed slots | Seconds | Over epoch | Gaps |\n| --- | --- | --- | --- | --- | --- |\n");
            for recovery in &self.summary.recoveries {
                text.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    recovery.start_slot,
                    recovery
                        .end_slot
                        .map(|slot| slot.to_string())
                        .unwrap_or_else(|| "open".into()),
                    recovery.elapsed_slots,
                    u128::from(recovery.elapsed_slots) * u128::from(self.seconds_per_slot),
                    if recovery.over_epoch { "yes" } else { "no" },
                    if recovery.had_gaps { "yes" } else { "no" }
                ));
            }
        }
        text.push_str(
            "\nThreshold PASS requires complete coverage; open recoveries are incomplete.\n",
        );
        text
    }
}

/// Compute a whole-slot 24-hour window ending at `end_slot` (or the final input slot).
/// The slot duration must divide 24 hours. A short/empty capture cannot qualify a full day.
pub fn window_report(
    samples: &[Sample],
    seconds_per_slot: u64,
    slots_per_epoch: u64,
    end_slot: Option<u64>,
) -> Result<Report, Error> {
    if seconds_per_slot == 0 || 86400 % seconds_per_slot != 0 {
        return Err(Error::Config);
    }
    let all = analyze(samples, slots_per_epoch)?;
    let expected = 86400 / seconds_per_slot;
    let end = end_slot
        .or_else(|| samples.last().map(|sample| sample.slot))
        .ok_or(Error::Input)?;
    let start = end
        .checked_add(1)
        .ok_or(Error::Config)?
        .saturating_sub(expected);
    let selected: Vec<_> = samples
        .iter()
        .filter(|sample| sample.slot >= start && sample.slot <= end)
        .cloned()
        .collect();
    let mut summary = analyze(&selected, slots_per_epoch)?;
    summary.recoveries = all
        .recoveries
        .into_iter()
        .filter(|r| r.start_slot <= end && r.end_slot.unwrap_or(end) >= start)
        .map(|mut recovery| {
            let finish = recovery.end_slot.unwrap_or(end).min(end);
            recovery.elapsed_slots = finish - recovery.start_slot;
            recovery.end_slot = recovery.end_slot.filter(|slot| *slot <= end);
            // Clipping may discard proof, but missing tail evidence cannot create it.
            recovery.over_epoch &= recovery.elapsed_slots > slots_per_epoch;
            recovery.had_gaps |= samples.last().is_none_or(|sample| sample.slot < finish);
            recovery
        })
        .collect();
    summary.samples = expected;
    summary.gap_samples = expected - summary.compared;
    Ok(Report {
        start_slot: start,
        end_slot: end,
        seconds_per_slot,
        slots_per_epoch,
        gap_seconds: summary.gap_samples * seconds_per_slot,
        summary,
    })
}
/// Read the shared bounded JSONL, then render a full-day decision (no live reads).
pub async fn report_jsonl(
    input: impl tokio::io::AsyncRead + Unpin,
    seconds_per_slot: u64,
    slots_per_epoch: u64,
    end_slot: Option<u64>,
) -> Result<Report, Error> {
    let samples = super::read_samples(input).await?;
    window_report(&samples, seconds_per_slot, slots_per_epoch, end_slot)
}
