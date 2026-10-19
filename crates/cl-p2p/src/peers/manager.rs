//! The Goodbye ledger: Goodbye reason 3 (`phase0/p2p-interface.md` §Goodbye, L1457–1483:
//! "Fault/error") received from Status-valid peers, per hour, against a threshold N.
//!
//! # The rate
//!
//! The owner's event loop feeds [`GoodbyeLedger`] what [`crate::rpc::inbound::Control`] and
//! identify report ([`GoodbyeLedger::observe`], [`GoodbyeLedger::observe_identify`]; each
//! received Goodbye is already counted in `p2p_goodbye_received_total{reason, status_valid}`
//! and logged as one `goodbye_received` line) and tells it when a peer disconnects, and when
//! ([`GoodbyeLedger::disconnected`]). Hours are wall-clock UTC hours. For each hour:
//!
//! - **Seen**: the distinct peers that were Status-valid at some point in the hour: a peer
//!   whose Status passed the relevance check in it, or one still connected and Status-valid
//!   from an earlier hour (each new hour starts with those).
//! - **Senders**: the distinct seen peers that sent Goodbye 3 in the hour while Status-valid. A
//!   Goodbye 3 from a peer whose Status failed or was never judged is logged but not counted,
//!   and a peer that sends two counts once.
//! - **Rate** = senders ÷ seen, in percent ([`HourlyRate`]).
//!
//! # The threshold
//!
//! Exit 10 (a): the rate is at most N in every hour, N = max(2 %, 2 × the hourly p95 of the
//! Sepolia baseline run) ([`Threshold::from_baseline_p95`]). Until that baseline exists N is
//! 2 % \[est, provisional\]. N is configuration: `goodbye3_threshold_pct`
//! ([`GoodbyeLedgerConfig`]), set from the baseline report.
//!
//! # The verdict
//!
//! When an hour ends (the first event or [`GoodbyeLedger::tick`] in a later hour), the ledger
//! logs one `goodbye3_hourly` line: the hour's start, `status_valid_peers`, `goodbye3_senders`,
//! `rate_pct`, `threshold_pct`, `capped`, `clock_stepped`, `unobserved` and `verdict`
//! ([`Verdict`]: `pass`, `fail`, `no_peers` for an hour with no Status-valid peer,
//! `inconclusive` for an hour whose peer set reached its cap, whose wall clock stepped or that
//! nobody observed). A `fail` is logged at WARN, the
//! others at INFO. Hours skipped with no event and no tick are closed too, each with the
//! Status-valid peers connected throughout (the last `hours_kept` of them); the owner still
//! ticks the ledger every minute or so, so each line comes on time.
//!
//! # Clock steps
//!
//! Hours are wall-clock hours, so the ledger checks the wall clock against a monotonic one
//! ([`Instant`], or [`GoodbyeLedger::with_monotonic_clock`]). When the two have moved more than
//! [`MAX_CLOCK_SKEW`] apart since they last agreed, the wall clock stepped: the open hour is
//! closed `inconclusive` (`clock_stepped`), the hour the new time is in opens `inconclusive`
//! too, nothing is filled in between, and a step back leaves the future hour instead of
//! staying in it. The hours after are judged again. Each hour close that found no step
//! re-anchors the check, so a slow drift between the two clocks never adds up over a long run.
//!
//! The monotonic clock also shows whether the hours were observed: more than [`MAX_CALL_GAP`]
//! (5 min \[est\], five of the owner's minute ticks) between two calls means the probe was
//! paused or its event loop blocked while the host ran on. The open hour, every hour skipped
//! and the hour it resumes in are then `inconclusive` (`unobserved`); the peers still count in
//! each, but none of them is a `pass` or enters [`GoodbyeLedger::baseline_p95_pct`].
//!
//! Next to each Goodbye 3, counted or not, the ledger logs one `goodbye3_received` line (peer,
//! its identify agent version, `status_valid`, `direction`, `unix_ms`, whether it was counted,
//! and its totals of rate-limit and PRUNE events) and one `goodbye3_context` line per
//! [`super::context::ContextEntry`] of that peer. That is context only: nothing infers from it
//! why the peer said Goodbye.
//!
//! # Memory
//!
//! One hour is open at a time. Its two peer sets hold at most `max_peers_per_hour` peers
//! (2,048 by default \[est\]): the probe holds at most 160 connections, so 2,048 distinct
//! Status-valid peers in an hour is every connection replaced about 13 times, past any churn
//! the probe sees. A peer ID takes about 80 bytes, so the two sets stay under about 400 KiB. A
//! peer past the cap is not recorded and the hour is `inconclusive`, never a `pass` on a
//! sample. The Status-valid connected peers and the agent versions are held to the same cap; a
//! Status-valid peer turned away because that set is full may still be connected, so each
//! hour after one that turned a peer away starts capped too, until an hour turns none away
//! (CLs re-send their Status every few minutes, so a peer still connected is turned away again
//! within the hour).
//! When an hour closes its sets are dropped and only its [`ClosedHour`] (a few words) is kept,
//! for the last `hours_kept` hours (168, a week, by default).

use super::context::{unix_ms, ContextKind, GoodbyeContext};
use crate::behaviour::capped;
use crate::rpc::inbound::ControlEvent;
use crate::rpc::metrics::StatusValidity;
use crate::transport::Direction;
use libp2p::{identify, PeerId};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Goodbye reason 3, "Fault/error" (`phase0/p2p-interface.md` L1474).
pub const GOODBYE_FAULT: u64 = 3;

/// The lowest N, in percent, and N until a baseline exists \[est, provisional\].
pub const THRESHOLD_FLOOR_PCT: f64 = 2.0;

/// N is this many times the baseline's hourly p95.
pub const BASELINE_FACTOR: f64 = 2.0;

/// Seconds in an hour.
pub const HOUR_SECS: u64 = 3600;

/// The default cap on each hour's peer sets \[est\] (see the module docs).
pub const DEFAULT_MAX_PEERS_PER_HOUR: usize = 2048;

/// The highest `max_peers_per_hour` a config may set: 16,384 peers, about 3 MiB in the two
/// sets.
pub const MAX_PEERS_PER_HOUR_LIMIT: usize = 16_384;

/// How far the wall clock may move away from the monotonic clock before the ledger takes it
/// as a step \[est\]: well past NTP slewing, well under an hour.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// The longest monotonic time between two ledger calls (events or ticks) that still counts as
/// observed \[est\]: five ticks of the minute the owner ticks at. A longer gap (the probe
/// paused or its event loop blocked while the host ran on) leaves the hours it spans
/// unobserved.
pub const MAX_CALL_GAP: Duration = Duration::from_secs(300);

/// Closed hours kept by default: a week.
pub const DEFAULT_HOURS_KEPT: usize = 168;

/// The highest `hours_kept` a config may set: 30 days.
pub const MAX_HOURS_KEPT: usize = 720;

/// The ledger's configuration, a `[goodbye_ledger]` table in a TOML config. Every key is
/// optional; an unknown key is refused, so a typo fails startup instead of falling back to a
/// default.
///
/// ```toml
/// [goodbye_ledger]
/// goodbye3_threshold_pct = 2.0   # N; from the baseline report: max(2, 2 × hourly p95)
/// max_peers_per_hour = 2048      # the cap on each hour's peer sets
/// hours_kept = 168               # closed hours kept
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GoodbyeLedgerConfig {
    /// N, in percent: 2 to 100.
    pub goodbye3_threshold_pct: f64,
    /// The cap on each hour's peer sets: 1 to [`MAX_PEERS_PER_HOUR_LIMIT`].
    pub max_peers_per_hour: usize,
    /// Closed hours kept: 1 to [`MAX_HOURS_KEPT`].
    pub hours_kept: usize,
}

impl Default for GoodbyeLedgerConfig {
    fn default() -> Self {
        Self {
            goodbye3_threshold_pct: THRESHOLD_FLOOR_PCT,
            max_peers_per_hour: DEFAULT_MAX_PEERS_PER_HOUR,
            hours_kept: DEFAULT_HOURS_KEPT,
        }
    }
}

/// Why a ledger configuration, or a baseline, was refused.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum LedgerConfigError {
    /// N is not a number from the 2 % floor to 100.
    #[error("goodbye3_threshold_pct {0}: want a number from {THRESHOLD_FLOOR_PCT} to 100")]
    Threshold(f64),
    /// A baseline p95 is not a number from 0 to 100.
    #[error("goodbye3 hourly p95 {0}: want a number from 0 to 100")]
    Baseline(f64),
    /// `max_peers_per_hour` is out of range.
    #[error("max_peers_per_hour {0}: want 1 to {MAX_PEERS_PER_HOUR_LIMIT}")]
    MaxPeers(usize),
    /// `hours_kept` is out of range.
    #[error("hours_kept {0}: want 1 to {MAX_HOURS_KEPT}")]
    HoursKept(usize),
}

/// N, in percent: the highest hourly rate that passes.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Threshold(f64);

impl Threshold {
    /// N until a baseline exists: [`THRESHOLD_FLOOR_PCT`].
    pub const DEFAULT: Self = Self(THRESHOLD_FLOOR_PCT);

    /// N = `pct`.
    ///
    /// # Errors
    ///
    /// `pct` is not a number from [`THRESHOLD_FLOOR_PCT`] to 100.
    pub fn new(pct: f64) -> Result<Self, LedgerConfigError> {
        if pct.is_finite() && (THRESHOLD_FLOOR_PCT..=100.0).contains(&pct) {
            Ok(Self(pct))
        } else {
            Err(LedgerConfigError::Threshold(pct))
        }
    }

    /// N = max([`THRESHOLD_FLOOR_PCT`], [`BASELINE_FACTOR`] × `p95_pct`), at most 100, from the
    /// baseline's hourly p95 in percent.
    ///
    /// # Errors
    ///
    /// `p95_pct` is not a number from 0 to 100.
    pub fn from_baseline_p95(p95_pct: f64) -> Result<Self, LedgerConfigError> {
        if !(p95_pct.is_finite() && (0.0..=100.0).contains(&p95_pct)) {
            return Err(LedgerConfigError::Baseline(p95_pct));
        }
        Ok(Self(
            (BASELINE_FACTOR * p95_pct).clamp(THRESHOLD_FLOOR_PCT, 100.0),
        ))
    }

    /// N, in percent.
    #[must_use]
    pub fn pct(self) -> f64 {
        self.0
    }

    /// Whether `senders` of `seen` peers is at most N.
    #[must_use]
    pub fn admits(self, senders: usize, seen: usize) -> bool {
        // Both counts are at most MAX_PEERS_PER_HOUR_LIMIT, exact in an f64.
        senders as f64 * 100.0 <= self.0 * seen as f64
    }
}

/// The verdict on one hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The rate is at most N.
    Pass,
    /// The rate is above N.
    Fail,
    /// No Status-valid peer was seen: nothing to judge.
    NoPeers,
    /// The peer sets reached their cap, so the rate is over a sample; or the wall clock
    /// stepped, so the hour is not an hour of observation.
    Inconclusive,
}

impl Verdict {
    /// The `verdict` value logged.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NoPeers => "no_peers",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// One hour's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HourlyRate {
    /// The hour: Unix seconds ÷ [`HOUR_SECS`].
    pub hour: u64,
    /// Distinct peers Status-valid in the hour.
    pub status_valid_peers: usize,
    /// Distinct ones of them that sent Goodbye 3 while Status-valid.
    pub goodbye3_senders: usize,
    /// Whether a peer was left out because the sets were full.
    pub capped: bool,
    /// Whether the wall clock stepped (moved more than [`MAX_CLOCK_SKEW`] away from the
    /// monotonic clock) in the hour or into it.
    pub clock_stepped: bool,
    /// Whether the ledger went more than [`MAX_CALL_GAP`] of monotonic time without a call
    /// (an event or a tick) in the hour or into it: the probe was paused or blocked, so the
    /// hour was not observed.
    pub unobserved: bool,
}

impl HourlyRate {
    /// Senders ÷ seen, in percent; `None` with no peer seen.
    #[must_use]
    pub fn pct(&self) -> Option<f64> {
        (self.status_valid_peers > 0)
            .then(|| self.goodbye3_senders as f64 * 100.0 / self.status_valid_peers as f64)
    }

    /// The hour's start, in Unix seconds.
    #[must_use]
    pub fn start_unix_secs(&self) -> u64 {
        self.hour.saturating_mul(HOUR_SECS)
    }

    /// The verdict under N = `threshold`.
    #[must_use]
    pub fn verdict(&self, threshold: Threshold) -> Verdict {
        if self.capped || self.clock_stepped || self.unobserved {
            Verdict::Inconclusive
        } else if self.status_valid_peers == 0 {
            Verdict::NoPeers
        } else if threshold.admits(self.goodbye3_senders, self.status_valid_peers) {
            Verdict::Pass
        } else {
            Verdict::Fail
        }
    }
}

/// A closed hour: its counts, the N it was judged under and the verdict.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClosedHour {
    pub rate: HourlyRate,
    pub threshold: Threshold,
    pub verdict: Verdict,
}

/// A received Goodbye, as [`ControlEvent::GoodbyeReceived`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedGoodbye {
    pub peer: PeerId,
    pub reason: u64,
    /// The peer's Status validity when it said Goodbye.
    pub status_valid: StatusValidity,
    pub direction: Direction,
    pub at: SystemTime,
}

/// The open hour.
#[derive(Debug)]
struct Hour {
    index: u64,
    seen: HashSet<PeerId>,
    senders: HashSet<PeerId>,
    capped: bool,
    clock_stepped: bool,
    unobserved: bool,
}

impl Hour {
    /// Records `peer` as seen, unless the set is full (then the hour is capped); whether it is
    /// in the set.
    fn see(&mut self, peer: PeerId, cap: usize) -> bool {
        if self.seen.contains(&peer) {
            return true;
        }
        if self.seen.len() >= cap {
            self.capped = true;
            return false;
        }
        self.seen.insert(peer)
    }

    fn rate(&self) -> HourlyRate {
        HourlyRate {
            hour: self.index,
            status_valid_peers: self.seen.len(),
            goodbye3_senders: self.senders.len(),
            capped: self.capped,
            clock_stepped: self.clock_stepped,
            unobserved: self.unobserved,
        }
    }
}

/// The hour `at` is in.
fn hour_of(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) / HOUR_SECS
}

/// The nearest-rank 95th percentile of `values`; `None` for none.
#[must_use]
pub fn p95(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    // ceil(0.95 × n), 1-based: exact in integers.
    let rank = (sorted.len() * 95).div_ceil(100);
    Some(sorted[rank.max(1) - 1])
}

/// What the clocks said at one ledger call.
#[derive(Debug, Clone, Copy, Default)]
struct Reading {
    /// The wall clock moved more than [`MAX_CLOCK_SKEW`] away from the monotonic one.
    stepped: bool,
    /// More than [`MAX_CALL_GAP`] passed since the last call.
    unobserved: bool,
    /// The monotonic time read; `None` without a clock check.
    now: Option<Instant>,
}

/// The monotonic clock the wall clock is checked against.
#[derive(Clone)]
struct MonoClock(Arc<dyn Fn() -> Instant + Send + Sync>);

impl fmt::Debug for MonoClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MonoClock")
    }
}

/// The ledger (see the module docs).
#[derive(Debug)]
pub struct GoodbyeLedger {
    cfg: GoodbyeLedgerConfig,
    threshold: Threshold,
    open: Option<Hour>,
    closed: VecDeque<ClosedHour>,
    /// Connected peers whose last Status was valid: the next hour starts with them.
    valid_now: HashSet<PeerId>,
    /// Whether `valid_now` was full and turned a Status-valid peer away in the open hour: such
    /// a peer may still be connected, so the next hour starts incomplete.
    turned_away: bool,
    /// Each identified peer's agent version, cut at [`crate::behaviour::MAX_LOGGED_CHARS`].
    agents: HashMap<PeerId, String>,
    context: Option<GoodbyeContext>,
    /// The monotonic clock; `None` checks no step (unit tests that step the wall clock alone).
    mono: Option<MonoClock>,
    /// A wall time and the monotonic time read with it: at the last step or the last hour
    /// close, whichever came later.
    anchor: Option<(SystemTime, Instant)>,
    /// The monotonic time of the last call (an event or a tick).
    last_call: Option<Instant>,
}

impl GoodbyeLedger {
    /// A ledger under `cfg`.
    ///
    /// # Errors
    ///
    /// A value of `cfg` is out of range.
    pub fn new(cfg: GoodbyeLedgerConfig) -> Result<Self, LedgerConfigError> {
        let threshold = Threshold::new(cfg.goodbye3_threshold_pct)?;
        if !(1..=MAX_PEERS_PER_HOUR_LIMIT).contains(&cfg.max_peers_per_hour) {
            return Err(LedgerConfigError::MaxPeers(cfg.max_peers_per_hour));
        }
        if !(1..=MAX_HOURS_KEPT).contains(&cfg.hours_kept) {
            return Err(LedgerConfigError::HoursKept(cfg.hours_kept));
        }
        Ok(Self {
            cfg,
            threshold,
            open: None,
            closed: VecDeque::new(),
            valid_now: HashSet::new(),
            turned_away: false,
            agents: HashMap::new(),
            context: None,
            mono: Some(MonoClock(Arc::new(Instant::now))),
            anchor: None,
            last_call: None,
        })
    }

    /// The same ledger, logging `context` next to each Goodbye 3 and forgetting a peer's
    /// context when it disconnects.
    #[must_use]
    pub fn with_context(mut self, context: GoodbyeContext) -> Self {
        self.context = Some(context);
        self
    }

    /// The same ledger, checking the wall clock against `clock` instead of [`Instant::now`].
    #[must_use]
    pub fn with_monotonic_clock(
        mut self,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        self.mono = Some(MonoClock(Arc::new(clock)));
        self.anchor = None;
        self.last_call = None;
        self
    }

    /// The same ledger, checking no clock step.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn without_clock_check(mut self) -> Self {
        self.mono = None;
        self
    }

    /// N.
    #[must_use]
    pub fn threshold(&self) -> Threshold {
        self.threshold
    }

    /// The open hour's counts so far.
    #[must_use]
    pub fn current(&self) -> Option<HourlyRate> {
        self.open.as_ref().map(Hour::rate)
    }

    /// The closed hours kept, oldest first.
    pub fn closed_hours(&self) -> impl Iterator<Item = &ClosedHour> {
        self.closed.iter()
    }

    /// The hourly p95 of the closed hours kept that were judged (`pass` or `fail`), in
    /// percent: the baseline a run like this one gives ([`Threshold::from_baseline_p95`]).
    #[must_use]
    pub fn baseline_p95_pct(&self) -> Option<f64> {
        let rates: Vec<f64> = self
            .closed
            .iter()
            .filter(|h| matches!(h.verdict, Verdict::Pass | Verdict::Fail))
            .filter_map(|h| h.rate.pct())
            .collect();
        p95(&rates)
    }

    /// Closes the open hour if `now` is in a later one; the hour it closed.
    ///
    /// The owner calls this with the current wall time about once a minute, events or not:
    /// more than [`MAX_CALL_GAP`] of monotonic time between two calls (ticks or events) leaves
    /// the hours it spans `unobserved`, so they are never judged.
    pub fn tick(&mut self, now: SystemTime) -> Option<ClosedHour> {
        self.advance(now)
    }

    /// Reads the monotonic clock for a call at `at` (see [`Reading`]).
    fn read_clocks(&mut self, at: SystemTime) -> Reading {
        let Some(mono) = &self.mono else {
            return Reading::default();
        };
        let now = (mono.0)();
        let unobserved = self
            .last_call
            .is_some_and(|last| now.saturating_duration_since(last) > MAX_CALL_GAP);
        self.last_call = Some(now);
        let Some((wall0, mono0)) = self.anchor else {
            self.anchor = Some((at, now));
            return Reading {
                now: Some(now),
                ..Reading::default()
            };
        };
        let wall = match at.duration_since(wall0) {
            Ok(ahead) => ahead.as_secs_f64(),
            Err(back) => -back.duration().as_secs_f64(),
        };
        let mono = now.saturating_duration_since(mono0).as_secs_f64();
        let stepped = (wall - mono).abs() > MAX_CLOCK_SKEW.as_secs_f64();
        if stepped {
            self.anchor = Some((at, now));
        }
        Reading {
            stepped,
            unobserved,
            now: Some(now),
        }
    }

    /// A new hour `index`, starting with the Status-valid connected peers.
    fn start_hour(&self, index: u64, capped: bool, reading: Reading) -> Hour {
        let mut hour = Hour {
            index,
            seen: HashSet::new(),
            senders: HashSet::new(),
            capped,
            clock_stepped: reading.stepped,
            unobserved: reading.unobserved,
        };
        for peer in &self.valid_now {
            hour.see(*peer, self.cfg.max_peers_per_hour);
        }
        hour
    }

    /// Makes the hour of `at` the open one, closing the one before; the last hour it closed.
    ///
    /// - Hours skipped with no event and no tick are closed too, the last `hours_kept` of
    ///   them, each with the Status-valid peers connected throughout.
    /// - A peer turned away by a full `valid_now` may still be connected: each hour after the
    ///   one it was turned away in starts capped, until an hour turns none away.
    /// - A time in an earlier hour (a clock that went back within [`MAX_CLOCK_SKEW`]) stays in
    ///   the open hour. A clock step, either way, closes the open hour as stepped and opens the
    ///   hour of `at` as stepped, filling nothing in between.
    /// - More than [`MAX_CALL_GAP`] since the last call marks the open hour, every skipped
    ///   hour and the hour of `at` unobserved; the peers still count in each.
    /// - An hour close that found no step re-anchors the clock check, so the drift between the
    ///   two clocks is measured over an hour at most, never summed over the run.
    fn advance(&mut self, at: SystemTime) -> Option<ClosedHour> {
        let index = hour_of(at);
        let reading = self.read_clocks(at);
        let Some(open) = self.open.as_mut() else {
            self.open = Some(self.start_hour(index, false, reading));
            return None;
        };
        open.clock_stepped |= reading.stepped;
        open.unobserved |= reading.unobserved;
        if index == open.index || (index < open.index && !reading.stepped) {
            return None;
        }
        let open = self.open.take()?;
        let carry = std::mem::take(&mut self.turned_away);
        let mut last = self.close(&open);
        if !reading.stepped {
            let skipped = index - open.index - 1;
            let kept = u64::try_from(self.cfg.hours_kept).unwrap_or(u64::MAX);
            for gap in (index - skipped.min(kept))..index {
                let hour = self.start_hour(gap, carry, reading);
                last = self.close(&hour);
            }
            if let Some(now) = reading.now {
                self.anchor = Some((at, now));
            }
        }
        self.open = Some(self.start_hour(index, carry, reading));
        Some(last)
    }

    fn close(&mut self, hour: &Hour) -> ClosedHour {
        let rate = hour.rate();
        let closed = ClosedHour {
            rate,
            threshold: self.threshold,
            verdict: rate.verdict(self.threshold),
        };
        log_hour(&closed);
        if self.closed.len() >= self.cfg.hours_kept {
            self.closed.pop_front();
        }
        self.closed.push_back(closed);
        closed
    }

    /// `peer`'s Status was judged at `at`: valid (it passed the relevance check) or not.
    pub fn status(&mut self, peer: PeerId, valid: bool, at: SystemTime) {
        self.advance(at);
        if !valid {
            self.valid_now.remove(&peer);
            return;
        }
        let cap = self.cfg.max_peers_per_hour;
        if let Some(hour) = self.open.as_mut() {
            hour.see(peer, cap);
        }
        if self.valid_now.len() < cap || self.valid_now.contains(&peer) {
            self.valid_now.insert(peer);
        } else {
            self.turned_away = true;
            if let Some(hour) = self.open.as_mut() {
                hour.capped = true;
            }
        }
    }

    /// `peer` identified itself with `agent_version`.
    pub fn identified(&mut self, peer: PeerId, agent_version: &str) {
        if self.agents.len() < self.cfg.max_peers_per_hour || self.agents.contains_key(&peer) {
            self.agents.insert(peer, capped(agent_version).to_owned());
        }
    }

    /// `peer` disconnected at `at`: every hour up to that one counts it if it was Status-valid,
    /// the next does not start with it, and its agent version and context are dropped.
    pub fn disconnected(&mut self, peer: &PeerId, at: SystemTime) {
        self.advance(at);
        self.valid_now.remove(peer);
        self.agents.remove(peer);
        if let Some(context) = &self.context {
            context.forget(peer);
        }
    }

    /// A peer said Goodbye: a Status-valid one is seen in the hour, and a Goodbye 3 from it is
    /// counted; every Goodbye 3 is logged with its context. The peer is leaving, so the next
    /// hour does not start with it.
    pub fn goodbye(&mut self, goodbye: &ReceivedGoodbye) {
        self.advance(goodbye.at);
        let valid = goodbye.status_valid == StatusValidity::Valid;
        let cap = self.cfg.max_peers_per_hour;
        let mut counted = false;
        if let Some(hour) = self.open.as_mut() {
            if valid && hour.see(goodbye.peer, cap) && goodbye.reason == GOODBYE_FAULT {
                hour.senders.insert(goodbye.peer);
                counted = true;
            }
        }
        self.valid_now.remove(&goodbye.peer);
        if goodbye.reason == GOODBYE_FAULT {
            self.log_fault(goodbye, counted);
        }
    }

    /// Feeds `event`: a judged Status (at the time it is fed) or a received Goodbye.
    pub fn observe(&mut self, event: &ControlEvent) {
        match event {
            ControlEvent::Status {
                peer, relevance, ..
            } => self.status(*peer, relevance.is_relevant(), SystemTime::now()),
            ControlEvent::GoodbyeReceived {
                peer,
                reason,
                status_valid,
                direction,
                at,
            } => self.goodbye(&ReceivedGoodbye {
                peer: *peer,
                reason: *reason,
                status_valid: *status_valid,
                direction: *direction,
                at: *at,
            }),
            _ => {}
        }
    }

    /// Feeds an identify event: a received one gives the peer's agent version.
    pub fn observe_identify(&mut self, event: &identify::Event) {
        if let identify::Event::Received { peer_id, info, .. } = event {
            self.identified(*peer_id, &info.agent_version);
        }
    }

    /// The `goodbye3_received` line and one `goodbye3_context` line per context entry.
    fn log_fault(&self, goodbye: &ReceivedGoodbye, counted: bool) {
        let entries = self
            .context
            .as_ref()
            .map(|c| c.entries(&goodbye.peer))
            .unwrap_or_default();
        let total = |kind: ContextKind| -> u64 {
            entries
                .iter()
                .filter(|e| e.kind == kind)
                .map(|e| e.count)
                .fold(0, u64::saturating_add)
        };
        let agent = self.agents.get(&goodbye.peer).map_or("", String::as_str);
        tracing::info!(
            peer = %goodbye.peer,
            // Peer-supplied: logged escaped, as `log_identify` does.
            agent = ?agent,
            status_valid = goodbye.status_valid.as_str(),
            direction = goodbye.direction.as_str(),
            unix_ms = unix_ms(goodbye.at),
            counted,
            rate_limited = total(ContextKind::RateLimited),
            prunes_received = total(ContextKind::PruneReceived),
            "goodbye3_received"
        );
        for entry in &entries {
            tracing::info!(
                peer = %goodbye.peer,
                kind = entry.kind.as_str(),
                protocol = entry.detail,
                count = entry.count,
                first_unix_ms = entry.first_unix_ms,
                last_unix_ms = entry.last_unix_ms,
                "goodbye3_context"
            );
        }
    }
}

/// The `goodbye3_hourly` line of `hour`.
fn log_hour(hour: &ClosedHour) {
    let rate = &hour.rate;
    let rate_pct = rate.pct().unwrap_or(0.0);
    if hour.verdict == Verdict::Fail {
        tracing::warn!(
            hour_start_unix = rate.start_unix_secs(),
            status_valid_peers = rate.status_valid_peers,
            goodbye3_senders = rate.goodbye3_senders,
            rate_pct,
            threshold_pct = hour.threshold.pct(),
            capped = rate.capped,
            clock_stepped = rate.clock_stepped,
            unobserved = rate.unobserved,
            verdict = hour.verdict.as_str(),
            "goodbye3_hourly"
        );
    } else {
        tracing::info!(
            hour_start_unix = rate.start_unix_secs(),
            status_valid_peers = rate.status_valid_peers,
            goodbye3_senders = rate.goodbye3_senders,
            rate_pct,
            threshold_pct = hour.threshold.pct(),
            capped = rate.capped,
            clock_stepped = rate.clock_stepped,
            unobserved = rate.unobserved,
            verdict = hour.verdict.as_str(),
            "goodbye3_hourly"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::inbound::{Relevance, StatusVia};
    use libp2p::swarm::ConnectionId;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// The start of an hour, in Unix seconds.
    const HOUR: u64 = 491_000 * HOUR_SECS;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// A monotonic clock the test moves by hand.
    #[derive(Clone)]
    struct FakeMono(Arc<Mutex<Instant>>);

    impl FakeMono {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }

        fn clock(&self) -> impl Fn() -> Instant + Send + Sync + 'static {
            let now = self.0.clone();
            move || *now.lock().unwrap()
        }
    }

    /// A ledger whose monotonic clock never moves: these tests step the wall clock alone,
    /// so the step check is off (`clock_steps` tests it).
    fn ledger() -> GoodbyeLedger {
        GoodbyeLedger::new(GoodbyeLedgerConfig::default())
            .unwrap()
            .without_clock_check()
    }

    fn capped_ledger(max_peers_per_hour: usize) -> GoodbyeLedger {
        GoodbyeLedger::new(GoodbyeLedgerConfig {
            max_peers_per_hour,
            ..GoodbyeLedgerConfig::default()
        })
        .unwrap()
        .without_clock_check()
    }

    fn peers(n: usize) -> Vec<PeerId> {
        (0..n).map(|_| PeerId::random()).collect()
    }

    fn goodbye(
        peer: PeerId,
        reason: u64,
        status_valid: StatusValidity,
        secs: u64,
    ) -> ReceivedGoodbye {
        ReceivedGoodbye {
            peer,
            reason,
            status_valid,
            direction: Direction::Outbound,
            at: at(secs),
        }
    }

    /// `n` peers made Status-valid in the hour starting at `start`.
    fn valid_peers(ledger: &mut GoodbyeLedger, n: usize, start: u64) -> Vec<PeerId> {
        let peers = peers(n);
        for (i, peer) in (0u64..).zip(&peers) {
            ledger.status(*peer, true, at(start + i));
        }
        peers
    }

    #[test]
    fn hourly_rate() {
        let mut ledger = ledger();
        let peers = valid_peers(&mut ledger, 50, HOUR);
        for peer in &peers[..3] {
            ledger.goodbye(&goodbye(*peer, 3, StatusValidity::Valid, HOUR + 600));
        }
        // Not Status-valid: one whose Status failed, one never judged.
        let invalid = PeerId::random();
        ledger.status(invalid, false, at(HOUR + 10));
        ledger.goodbye(&goodbye(invalid, 3, StatusValidity::Invalid, HOUR + 700));
        ledger.goodbye(&goodbye(
            PeerId::random(),
            3,
            StatusValidity::Unknown,
            HOUR + 800,
        ));
        let rate = ledger.current().expect("an open hour");
        assert_eq!(rate.status_valid_peers, 50);
        assert_eq!(rate.goodbye3_senders, 3);
        assert_eq!(rate.pct(), Some(6.0));
        assert!(!rate.capped);
        // Above the default N of 2 %, at or below an N of 6 %.
        assert_eq!(rate.verdict(ledger.threshold()), Verdict::Fail);
        assert_eq!(rate.verdict(Threshold::new(6.0).unwrap()), Verdict::Pass);
        // The hour closes with the first event of the next one.
        let closed = ledger.tick(at(HOUR + HOUR_SECS)).expect("closed");
        assert_eq!(closed.rate, rate);
        assert_eq!(closed.verdict, Verdict::Fail);
        assert_eq!(closed.threshold, Threshold::DEFAULT);
        assert_eq!(rate.start_unix_secs(), HOUR);
    }

    #[test]
    fn threshold() {
        assert_eq!(Threshold::from_baseline_p95(0.5).unwrap().pct(), 2.0);
        assert_eq!(Threshold::from_baseline_p95(3.0).unwrap().pct(), 6.0);
        // 2 % until a baseline exists.
        assert_eq!(GoodbyeLedgerConfig::default().goodbye3_threshold_pct, 2.0);
        assert_eq!(ledger().threshold(), Threshold::DEFAULT);
        assert_eq!(Threshold::DEFAULT.pct(), THRESHOLD_FLOOR_PCT);
        // Exactly 1 % and none: the floor.
        assert_eq!(Threshold::from_baseline_p95(1.0).unwrap().pct(), 2.0);
        assert_eq!(Threshold::from_baseline_p95(0.0).unwrap().pct(), 2.0);
        // Never above 100 %.
        assert_eq!(Threshold::from_baseline_p95(80.0).unwrap().pct(), 100.0);
        // N passes a rate at it, not above.
        let n = Threshold::from_baseline_p95(3.0).unwrap();
        assert!(n.admits(3, 50));
        assert!(!n.admits(4, 50));
        for bad in [-0.1, 100.1, f64::INFINITY] {
            assert_eq!(
                Threshold::from_baseline_p95(bad),
                Err(LedgerConfigError::Baseline(bad))
            );
        }
    }

    #[test]
    fn a_nan_baseline_is_refused() {
        assert!(matches!(
            Threshold::from_baseline_p95(f64::NAN),
            Err(LedgerConfigError::Baseline(_))
        ));
        assert!(matches!(
            Threshold::new(f64::NAN),
            Err(LedgerConfigError::Threshold(_))
        ));
    }

    #[test]
    fn a_duplicate_sender_counts_once() {
        let mut ledger = ledger();
        let peers = valid_peers(&mut ledger, 10, HOUR);
        for secs in [100, 200, 300] {
            ledger.goodbye(&goodbye(peers[0], 3, StatusValidity::Valid, HOUR + secs));
        }
        let rate = ledger.current().unwrap();
        assert_eq!((rate.goodbye3_senders, rate.status_valid_peers), (1, 10));
        assert_eq!(rate.pct(), Some(10.0));
    }

    #[test]
    fn other_reasons_are_not_counted() {
        let mut ledger = ledger();
        let peers = valid_peers(&mut ledger, 4, HOUR);
        ledger.goodbye(&goodbye(peers[0], 1, StatusValidity::Valid, HOUR + 5));
        ledger.goodbye(&goodbye(peers[1], 2, StatusValidity::Valid, HOUR + 5));
        ledger.goodbye(&goodbye(peers[2], 129, StatusValidity::Valid, HOUR + 5));
        let rate = ledger.current().unwrap();
        assert_eq!((rate.goodbye3_senders, rate.status_valid_peers), (0, 4));
        assert_eq!(rate.verdict(ledger.threshold()), Verdict::Pass);
    }

    #[test]
    fn a_valid_goodbye_counts_its_sender_as_seen() {
        // The ledger missed the Status (fed late), the Goodbye says the peer was valid.
        let mut ledger = ledger();
        ledger.goodbye(&goodbye(PeerId::random(), 3, StatusValidity::Valid, HOUR));
        let rate = ledger.current().unwrap();
        assert_eq!((rate.goodbye3_senders, rate.status_valid_peers), (1, 1));
    }

    #[test]
    fn an_empty_hour_has_no_rate() {
        let mut ledger = ledger();
        assert_eq!(ledger.current(), None);
        assert_eq!(ledger.tick(at(HOUR)), None);
        let rate = ledger.current().unwrap();
        assert_eq!(rate.pct(), None);
        assert_eq!(rate.verdict(ledger.threshold()), Verdict::NoPeers);
        let closed = ledger.tick(at(HOUR + HOUR_SECS)).unwrap();
        assert_eq!(closed.verdict, Verdict::NoPeers);
        assert_eq!(ledger.baseline_p95_pct(), None);
    }

    #[test]
    fn hour_rollover_starts_with_the_peers_still_valid() {
        let mut ledger = ledger();
        let peers = valid_peers(&mut ledger, 5, HOUR);
        ledger.goodbye(&goodbye(peers[0], 3, StatusValidity::Valid, HOUR + 60));
        ledger.disconnected(&peers[1], at(HOUR + 90));
        ledger.status(peers[2], false, at(HOUR + 120));
        assert_eq!(ledger.tick(at(HOUR + HOUR_SECS - 1)), None, "same hour");
        // Next hour: a new peer's Status closes the old one.
        let late = PeerId::random();
        ledger.status(late, true, at(HOUR + HOUR_SECS + 5));
        let first = ledger.closed_hours().next().copied().unwrap();
        assert_eq!(first.rate.hour, HOUR / HOUR_SECS);
        assert_eq!(
            (first.rate.goodbye3_senders, first.rate.status_valid_peers),
            (1, 5)
        );
        // The sender left, peers[1] disconnected, peers[2]'s Status failed: 2 carried + 1 new.
        let rate = ledger.current().unwrap();
        assert_eq!(rate.hour, HOUR / HOUR_SECS + 1);
        assert_eq!((rate.goodbye3_senders, rate.status_valid_peers), (0, 3));
        // A skipped hour (no event, no tick) is closed too, with the connected valid peers.
        let closed = ledger.tick(at(HOUR + 3 * HOUR_SECS)).unwrap();
        assert_eq!(closed.rate.hour, HOUR / HOUR_SECS + 2);
        assert_eq!(closed.rate.status_valid_peers, 3);
        assert_eq!(ledger.current().unwrap().status_valid_peers, 3);
        let hours: Vec<u64> = ledger
            .closed_hours()
            .map(|h| h.rate.hour - HOUR / HOUR_SECS)
            .collect();
        assert_eq!(hours, [0, 1, 2]);
    }

    #[test]
    fn a_clock_that_goes_back_stays_in_the_open_hour() {
        let mut ledger = ledger();
        let peers = valid_peers(&mut ledger, 2, HOUR + HOUR_SECS);
        ledger.goodbye(&goodbye(peers[0], 3, StatusValidity::Valid, HOUR + 10));
        let rate = ledger.current().unwrap();
        assert_eq!(rate.hour, HOUR / HOUR_SECS + 1);
        assert_eq!(rate.goodbye3_senders, 1);
        assert_eq!(ledger.closed_hours().count(), 0);
    }

    #[test]
    fn a_full_hour_is_inconclusive_and_bounded() {
        let mut ledger = capped_ledger(4);
        let peers = valid_peers(&mut ledger, 6, HOUR);
        // Past the cap: neither seen nor counted.
        ledger.goodbye(&goodbye(peers[5], 3, StatusValidity::Valid, HOUR + 30));
        ledger.goodbye(&goodbye(peers[0], 3, StatusValidity::Valid, HOUR + 30));
        let rate = ledger.current().unwrap();
        assert_eq!((rate.goodbye3_senders, rate.status_valid_peers), (1, 4));
        assert!(rate.capped);
        assert_eq!(rate.verdict(ledger.threshold()), Verdict::Inconclusive);
        // The carried set is capped too: the next hour starts with at most the cap.
        ledger.tick(at(HOUR + HOUR_SECS));
        let next = ledger.current().unwrap();
        assert!(next.status_valid_peers <= 4, "{next:?}");
        // Agents too.
        for peer in &peers {
            ledger.identified(*peer, "lighthouse");
        }
        assert_eq!(ledger.agents.len(), 4);
        ledger.identified(peers[0], "lighthouse/v2");
        assert_eq!(ledger.agents[&peers[0]], "lighthouse/v2");
    }

    #[test]
    fn old_hours_are_dropped() {
        let mut ledger = GoodbyeLedger::new(GoodbyeLedgerConfig {
            hours_kept: 3,
            ..GoodbyeLedgerConfig::default()
        })
        .unwrap();
        for h in 0..6 {
            ledger.tick(at(HOUR + h * HOUR_SECS));
        }
        let kept: Vec<u64> = ledger.closed_hours().map(|h| h.rate.hour).collect();
        let first = HOUR / HOUR_SECS;
        assert_eq!(kept, [first + 2, first + 3, first + 4]);
    }

    #[test]
    fn baseline_p95_of_the_judged_hours() {
        assert_eq!(p95(&[]), None);
        assert_eq!(p95(&[4.0]), Some(4.0));
        // 20 values 1..=20: rank ceil(19) = 19.
        let values: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(p95(&values), Some(19.0));
        // 21 values: rank ceil(19.95) = 20.
        let values: Vec<f64> = (1..=21).map(f64::from).collect();
        assert_eq!(p95(&values), Some(20.0));

        let mut ledger = ledger();
        // Hour 0: 1 of 100 (1 %); hour 1: no peers (skipped); hour 2: 2 of 50 (4 %).
        let peers = valid_peers(&mut ledger, 100, HOUR);
        ledger.goodbye(&goodbye(peers[0], 3, StatusValidity::Valid, HOUR + 200));
        for peer in &peers {
            ledger.disconnected(peer, at(HOUR + 300));
        }
        ledger.tick(at(HOUR + HOUR_SECS));
        let later = valid_peers(&mut ledger, 50, HOUR + 2 * HOUR_SECS);
        for peer in &later[..2] {
            ledger.goodbye(&goodbye(
                *peer,
                3,
                StatusValidity::Valid,
                HOUR + 2 * HOUR_SECS + 9,
            ));
        }
        ledger.tick(at(HOUR + 3 * HOUR_SECS));
        let verdicts: Vec<Verdict> = ledger.closed_hours().map(|h| h.verdict).collect();
        assert_eq!(verdicts, [Verdict::Pass, Verdict::NoPeers, Verdict::Fail]);
        assert_eq!(ledger.baseline_p95_pct(), Some(4.0));
        assert_eq!(
            Threshold::from_baseline_p95(ledger.baseline_p95_pct().unwrap())
                .unwrap()
                .pct(),
            8.0
        );
    }

    #[test]
    fn config_from_toml() {
        #[derive(Deserialize)]
        struct File {
            goodbye_ledger: GoodbyeLedgerConfig,
        }
        let file: File =
            toml::from_str("[goodbye_ledger]\ngoodbye3_threshold_pct = 6.0\n").unwrap();
        assert_eq!(
            file.goodbye_ledger,
            GoodbyeLedgerConfig {
                goodbye3_threshold_pct: 6.0,
                ..GoodbyeLedgerConfig::default()
            }
        );
        let ledger = GoodbyeLedger::new(file.goodbye_ledger).unwrap();
        assert_eq!(ledger.threshold().pct(), 6.0);
        let empty: File = toml::from_str("[goodbye_ledger]\n").unwrap();
        assert_eq!(empty.goodbye_ledger, GoodbyeLedgerConfig::default());
        // A typo fails instead of falling back to the default.
        let typo = toml::from_str::<File>("[goodbye_ledger]\ngoodbye3_treshold_pct = 6.0\n");
        assert!(typo.is_err());
    }

    #[test]
    fn config_out_of_range_is_refused() {
        let with = |f: fn(&mut GoodbyeLedgerConfig)| {
            let mut cfg = GoodbyeLedgerConfig::default();
            f(&mut cfg);
            GoodbyeLedger::new(cfg).unwrap_err()
        };
        assert_eq!(
            with(|c| c.goodbye3_threshold_pct = 1.5),
            LedgerConfigError::Threshold(1.5)
        );
        assert_eq!(
            with(|c| c.goodbye3_threshold_pct = 101.0),
            LedgerConfigError::Threshold(101.0)
        );
        assert_eq!(
            with(|c| c.max_peers_per_hour = 0),
            LedgerConfigError::MaxPeers(0)
        );
        assert_eq!(
            with(|c| c.max_peers_per_hour = MAX_PEERS_PER_HOUR_LIMIT + 1),
            LedgerConfigError::MaxPeers(MAX_PEERS_PER_HOUR_LIMIT + 1)
        );
        assert_eq!(with(|c| c.hours_kept = 0), LedgerConfigError::HoursKept(0));
        assert_eq!(
            with(|c| c.hours_kept = MAX_HOURS_KEPT + 1),
            LedgerConfigError::HoursKept(MAX_HOURS_KEPT + 1)
        );
        assert!(LedgerConfigError::Threshold(1.5)
            .to_string()
            .contains("goodbye3_threshold_pct"));
        assert!(Threshold::new(100.0).is_ok());
        assert!(Threshold::new(THRESHOLD_FLOOR_PCT).is_ok());
    }

    #[test]
    fn observe_feeds_status_and_goodbye_events() {
        let mut ledger = ledger();
        let valid = PeerId::random();
        let wrong = PeerId::random();
        let status = p2p_wire::testkit::status();
        for (peer, relevance) in [
            (valid, Relevance::Relevant),
            (wrong, Relevance::WrongForkDigest),
        ] {
            ledger.observe(&ControlEvent::Status {
                peer,
                status: status.clone(),
                relevance,
                via: StatusVia::Response,
            });
        }
        ledger.observe(&ControlEvent::Pong {
            peer: valid,
            seq_number: 1,
        });
        let rate = ledger.current().unwrap();
        assert_eq!(rate.status_valid_peers, 1);
        let now = SystemTime::now();
        ledger.observe(&ControlEvent::GoodbyeReceived {
            peer: valid,
            reason: 3,
            status_valid: StatusValidity::Valid,
            direction: Direction::Inbound,
            at: now,
        });
        let rate = ledger.current().unwrap();
        assert_eq!((rate.goodbye3_senders, rate.status_valid_peers), (1, 1));
        assert_eq!(rate.hour, hour_of(now));
    }

    #[test]
    fn observe_identify_keeps_the_agent_capped() {
        let mut ledger = ledger();
        let key = libp2p::identity::Keypair::generate_secp256k1();
        let peer = key.public().to_peer_id();
        let long = "x".repeat(crate::behaviour::MAX_LOGGED_CHARS + 10);
        let info = identify::Info {
            public_key: key.public(),
            protocol_version: "eth2/1.0.0".to_owned(),
            agent_version: long,
            listen_addrs: Vec::new(),
            protocols: Vec::new(),
            observed_addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            signed_peer_record: None,
        };
        ledger.observe_identify(&identify::Event::Received {
            connection_id: ConnectionId::new_unchecked(0),
            peer_id: peer,
            info,
        });
        assert_eq!(
            ledger.agents[&peer].chars().count(),
            crate::behaviour::MAX_LOGGED_CHARS
        );
        ledger.observe_identify(&identify::Event::Sent {
            connection_id: ConnectionId::new_unchecked(0),
            peer_id: PeerId::random(),
        });
        assert_eq!(ledger.agents.len(), 1);
        ledger.disconnected(&peer, SystemTime::now());
        assert!(ledger.agents.is_empty());
    }

    #[test]
    fn disconnect_forgets_the_context() {
        let context = GoodbyeContext::new();
        let mut ledger = ledger().with_context(context.clone());
        let peer = PeerId::random();
        context.prune_received(peer, at(HOUR));
        ledger.goodbye(&goodbye(peer, 3, StatusValidity::Valid, HOUR + 1));
        assert_eq!(
            context.entries(&peer).len(),
            1,
            "kept until the peer leaves"
        );
        ledger.disconnected(&peer, at(HOUR + 2));
        assert!(context.entries(&peer).is_empty());
    }

    #[test]
    fn a_disconnect_in_a_later_hour_counts_the_peer_in_every_hour_it_was_valid() {
        let mut ledger = ledger();
        let peer = PeerId::random();
        // Status-valid at 12:59:59, so still at 13:00:00; it leaves at 14:00:05, and nothing
        // else happens until 15:00.
        ledger.status(peer, true, at(HOUR - 1));
        ledger.disconnected(&peer, at(HOUR + HOUR_SECS + 5));
        ledger.tick(at(HOUR + 2 * HOUR_SECS));
        let hours: Vec<(u64, usize)> = ledger
            .closed_hours()
            .map(|h| {
                (
                    h.rate.hour + 1 - HOUR / HOUR_SECS,
                    h.rate.status_valid_peers,
                )
            })
            .collect();
        // 12:00, 13:00 and 14:00 each saw it; 15:00 starts without it.
        assert_eq!(hours, [(0, 1), (1, 1), (2, 1)]);
        assert_eq!(ledger.current().unwrap().status_valid_peers, 0);
    }

    #[test]
    fn a_gap_longer_than_the_hours_kept_fills_only_those() {
        let mut ledger = GoodbyeLedger::new(GoodbyeLedgerConfig {
            hours_kept: 3,
            ..GoodbyeLedgerConfig::default()
        })
        .unwrap()
        .without_clock_check();
        ledger.status(PeerId::random(), true, at(HOUR));
        ledger.tick(at(HOUR + 1000 * HOUR_SECS));
        let hours: Vec<u64> = ledger
            .closed_hours()
            .map(|h| h.rate.hour - HOUR / HOUR_SECS)
            .collect();
        assert_eq!(hours, [997, 998, 999]);
        assert!(ledger
            .closed_hours()
            .all(|h| h.rate.status_valid_peers == 1));
    }

    #[test]
    fn an_overflow_keeps_the_next_hour_inconclusive_until_it_clears() {
        let mut ledger = capped_ledger(4);
        // Six valid peers: two are turned away.
        let peers = valid_peers(&mut ledger, 6, HOUR);
        assert!(ledger.current().unwrap().capped);
        // The next hour starts with the four held, and the two turned away may still be
        // connected: it is inconclusive, not a pass on four.
        ledger.disconnected(&peers[0], at(HOUR + HOUR_SECS + 10));
        let next = ledger.current().unwrap();
        assert_eq!(next.hour, HOUR / HOUR_SECS + 1);
        assert!(next.capped, "{next:?}");
        assert_eq!(next.verdict(ledger.threshold()), Verdict::Inconclusive);
        // No peer turned away in that hour: the one after is judged again.
        ledger.tick(at(HOUR + 2 * HOUR_SECS));
        let after = ledger.current().unwrap();
        assert!(!after.capped, "{after:?}");
        assert_eq!(after.status_valid_peers, 3);
        assert_eq!(after.verdict(ledger.threshold()), Verdict::Pass);
        // Turned away again (a re-Status while full): the hour after is inconclusive again.
        valid_peers(&mut ledger, 2, HOUR + 2 * HOUR_SECS + 5);
        ledger.tick(at(HOUR + 3 * HOUR_SECS));
        assert!(ledger.current().unwrap().capped);
    }

    #[test]
    fn clock_steps() {
        let mono = FakeMono::new();
        let mut ledger = GoodbyeLedger::new(GoodbyeLedgerConfig::default())
            .unwrap()
            .with_monotonic_clock(mono.clock());
        let peers = valid_peers(&mut ledger, 10, HOUR);
        // Wall and monotonic time agree within 60 s: no step.
        mono.advance(Duration::from_secs(200));
        ledger.status(peers[0], true, at(HOUR + 240));
        assert!(!ledger.current().unwrap().clock_stepped);
        // The wall clock jumps two hours ahead while 10 s pass: the open hour is cut short
        // and the hour it lands in is not a real hour of observation.
        mono.advance(Duration::from_secs(10));
        ledger.status(peers[0], true, at(HOUR + 2 * HOUR_SECS + 250));
        let cut = *ledger.closed_hours().last().unwrap();
        assert_eq!(cut.rate.hour, HOUR / HOUR_SECS);
        assert!(cut.rate.clock_stepped);
        assert_eq!(cut.verdict, Verdict::Inconclusive);
        assert_eq!(
            ledger.closed_hours().count(),
            1,
            "no hours filled across a step"
        );
        let future = ledger.current().unwrap();
        assert_eq!(future.hour, HOUR / HOUR_SECS + 2);
        assert!(future.clock_stepped);
        // And back: the ledger leaves the future hour instead of staying in it.
        mono.advance(Duration::from_secs(10));
        ledger.status(peers[1], true, at(HOUR + 260));
        let left = *ledger.closed_hours().last().unwrap();
        assert_eq!(left.rate.hour, HOUR / HOUR_SECS + 2);
        assert_eq!(left.verdict, Verdict::Inconclusive);
        let back = ledger.current().unwrap();
        assert_eq!(back.hour, HOUR / HOUR_SECS);
        assert!(back.clock_stepped);
        assert_eq!(back.verdict(ledger.threshold()), Verdict::Inconclusive);
        // From there on the clocks agree again: the next hour is judged.
        tick_minutes(&mut ledger, &mono, HOUR + 260, 60);
        let closed = *ledger.closed_hours().last().unwrap();
        assert_eq!(closed.rate.hour, HOUR / HOUR_SECS);
        assert_eq!(closed.verdict, Verdict::Inconclusive);
        let next = ledger.current().unwrap();
        assert!(!next.clock_stepped);
        assert_eq!(next.verdict(ledger.threshold()), Verdict::Pass);
    }

    /// Ticks `ledger` once a minute for `minutes`, both clocks moving together from the wall
    /// time `from`; the wall time it ends at.
    fn tick_minutes(ledger: &mut GoodbyeLedger, mono: &FakeMono, from: u64, minutes: u64) -> u64 {
        let mut secs = from;
        for _ in 0..minutes {
            mono.advance(Duration::from_secs(60));
            secs += 60;
            ledger.tick(at(secs));
        }
        secs
    }

    fn checked_ledger(mono: &FakeMono) -> GoodbyeLedger {
        GoodbyeLedger::new(GoodbyeLedgerConfig::default())
            .unwrap()
            .with_monotonic_clock(mono.clock())
    }

    #[test]
    fn hours_nobody_observed_are_inconclusive() {
        let mono = FakeMono::new();
        let mut ledger = checked_ledger(&mono);
        let peers = valid_peers(&mut ledger, 10, HOUR);
        // A normal hour, ticked every minute: judged, and it passes.
        let end = tick_minutes(&mut ledger, &mono, HOUR, 61);
        let first = *ledger.closed_hours().last().unwrap();
        assert_eq!(first.rate.hour, HOUR / HOUR_SECS);
        assert!(!first.rate.unobserved);
        assert_eq!(first.verdict, Verdict::Pass);
        // The probe is paused for 3 h while the host runs on: both clocks move together, so
        // no step, but nobody observed those hours.
        mono.advance(Duration::from_secs(3 * HOUR_SECS));
        ledger.tick(at(end + 3 * HOUR_SECS));
        let after: Vec<ClosedHour> = ledger.closed_hours().skip(1).copied().collect();
        let hours: Vec<u64> = after
            .iter()
            .map(|h| h.rate.hour - HOUR / HOUR_SECS)
            .collect();
        assert_eq!(hours, [1, 2, 3], "the open hour and the two skipped ones");
        for hour in &after {
            assert!(hour.rate.unobserved, "{hour:?}");
            assert!(!hour.rate.clock_stepped, "{hour:?}");
            assert_eq!(hour.verdict, Verdict::Inconclusive, "{hour:?}");
            // The peers still count in every hour they were valid.
            assert_eq!(hour.rate.status_valid_peers, 10);
        }
        // The hour it resumes in is unobserved too.
        let resumed = ledger.current().unwrap();
        assert!(resumed.unobserved);
        assert_eq!(resumed.verdict(ledger.threshold()), Verdict::Inconclusive);
        // The next hour, ticked again, is judged: 1 of 10 sends Goodbye 3.
        let end = tick_minutes(&mut ledger, &mono, end + 3 * HOUR_SECS, 60);
        mono.advance(Duration::from_secs(1));
        ledger.goodbye(&goodbye(peers[0], 3, StatusValidity::Valid, end + 1));
        tick_minutes(&mut ledger, &mono, end + 1, 61);
        let judged: Vec<(u64, Verdict)> = ledger
            .closed_hours()
            .filter(|h| matches!(h.verdict, Verdict::Pass | Verdict::Fail))
            .map(|h| (h.rate.hour - HOUR / HOUR_SECS, h.verdict))
            .collect();
        assert_eq!(judged, [(0, Verdict::Pass), (5, Verdict::Fail)]);
        // Only those enter the baseline: 0 % and 10 %.
        assert_eq!(ledger.baseline_p95_pct(), Some(10.0));
    }

    #[test]
    fn a_pause_within_the_hour_leaves_it_unobserved() {
        let mono = FakeMono::new();
        let mut ledger = checked_ledger(&mono);
        valid_peers(&mut ledger, 3, HOUR);
        let end = tick_minutes(&mut ledger, &mono, HOUR, 10);
        // 5 min between calls is still observed; 6 is not.
        mono.advance(MAX_CALL_GAP);
        ledger.tick(at(end + MAX_CALL_GAP.as_secs()));
        assert!(!ledger.current().unwrap().unobserved);
        mono.advance(MAX_CALL_GAP + Duration::from_secs(60));
        ledger.tick(at(end + 2 * MAX_CALL_GAP.as_secs() + 60));
        let rate = ledger.current().unwrap();
        assert_eq!(rate.hour, HOUR / HOUR_SECS);
        assert!(rate.unobserved);
        assert_eq!(rate.verdict(ledger.threshold()), Verdict::Inconclusive);
    }

    #[test]
    fn slow_drift_is_no_step() {
        // The monotonic clock runs 10 s an hour slow against the wall clock: 100 s over ten
        // hours, but never 60 s within one, so every hour is judged.
        let mono = FakeMono::new();
        let mut ledger = checked_ledger(&mono);
        valid_peers(&mut ledger, 5, HOUR);
        let mut secs = HOUR;
        for _ in 0..10 * 60 {
            mono.advance(Duration::from_millis(59_833));
            secs += 60;
            ledger.tick(at(secs));
        }
        assert_eq!(ledger.closed_hours().count(), 10);
        for hour in ledger.closed_hours() {
            assert!(!hour.rate.clock_stepped, "{hour:?}");
            assert_eq!(hour.verdict, Verdict::Pass, "{hour:?}");
        }
    }

    #[test]
    fn the_default_clock_is_the_real_one() {
        // Wall time now and the real monotonic clock agree: no step.
        let mut ledger = ledger_with_real_clock();
        ledger.status(PeerId::random(), true, SystemTime::now());
        ledger.tick(SystemTime::now());
        assert!(!ledger.current().unwrap().clock_stepped);
        assert!(format!("{ledger:?}").contains("GoodbyeLedger"));
    }

    fn ledger_with_real_clock() -> GoodbyeLedger {
        GoodbyeLedger::new(GoodbyeLedgerConfig::default()).unwrap()
    }

    #[test]
    fn verdict_names() {
        let names: Vec<_> = [
            Verdict::Pass,
            Verdict::Fail,
            Verdict::NoPeers,
            Verdict::Inconclusive,
        ]
        .map(Verdict::as_str)
        .to_vec();
        assert_eq!(names, ["pass", "fail", "no_peers", "inconclusive"]);
    }
}
