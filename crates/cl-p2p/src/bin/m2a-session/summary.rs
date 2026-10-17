//! The session summary: one `m2a-summary` JSON line after every step's own line, with one
//! verdict per check ([`CHECKS`]), the pinned peer's ID, the spec pin, the start and end time
//! and the exit code. The exit code is 0 only if every check passed.
//!
//! - `status`, `metadata`, `ping`, `blocks_by_range`: the step passed (its own line has the
//!   field verdicts); `status` covers the fork digest.
//! - `pinned_peer_only`: at the end, the swarm is connected to no peer but the pinned one and
//!   listens nowhere.
//! - `decode_limits`: the BlocksByRange request asked for at most `MAX_REQUEST_BLOCKS_DENEB`
//!   blocks and the response held at most `count` of them, read under the codec's byte budget.
//! - `blocks_dropped`: the BlocksByRange response arrived and its blocks were hashed and
//!   dropped (the step keeps roots only, and the binary links no store crate).
//! - `fuzz_gate`, `own_os_user`, `key_handling`: what the pre-flight established before the
//!   dial (a passing m2a fuzz gate, a non-root effective UID, a checked node key).

use crate::blocks::BlocksReport;
use crate::probe::{verdicts_json, Report, Verdict};
use cl_p2p::rpc::codec::MAX_RESPONSE_BYTES;
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use libp2p::PeerId;
use network_config::SPEC_PIN;
use p2p_wire::rpc::protocols::MAX_REQUEST_BLOCKS_DENEB;
use serde_json::json;

/// Every check of the summary, in order.
pub const CHECKS: [&str; 10] = [
    "status",
    "metadata",
    "ping",
    "blocks_by_range",
    "pinned_peer_only",
    "decode_limits",
    "blocks_dropped",
    "fuzz_gate",
    "own_os_user",
    "key_handling",
];

/// What the run knows besides the steps' report.
#[derive(Debug, Clone)]
pub struct Facts {
    /// The pinned peer.
    pub peer_id: PeerId,
    /// Unix milliseconds at the start of the run.
    pub started_at_ms: u128,
    /// Unix milliseconds once the steps ended.
    pub ended_at_ms: u128,
    /// The peers the swarm is connected to at the end.
    pub connected: Vec<PeerId>,
    /// How many listen addresses the swarm has at the end.
    pub listeners: usize,
    /// The fuzz-gate pre-flight.
    pub fuzz_gate: Verdict,
    /// The effective UID the run passed the pre-flight as.
    pub euid: u32,
    /// How the node key was checked.
    pub key_handling: Verdict,
}

/// The summary of one session.
#[derive(Debug, Clone)]
pub struct Summary {
    facts: Facts,
    checks: Vec<(&'static str, Verdict)>,
}

fn verdict(pass: bool, detail: impl Into<String>) -> Verdict {
    Verdict {
        pass,
        detail: detail.into(),
    }
}

/// Which step's line says why a step did not run.
struct Step {
    /// The step's own log line.
    line: &'static str,
    /// The line of the step whose outcome decides whether it runs.
    gate: &'static str,
}

/// A step's verdict: passed, failed with its error, or not run, because the session stopped
/// early (`stopped`) or the step before it decided so.
fn step(ran: Option<(bool, Option<&String>)>, s: Step, stopped: Option<&String>) -> Verdict {
    let line = s.line;
    match ran {
        None => match stopped {
            Some(e) => verdict(false, format!("not run: {e}")),
            None => verdict(false, format!("not run (see {})", s.gate)),
        },
        Some((true, _)) => verdict(true, format!("passed (see {line})")),
        Some((false, Some(e))) => verdict(false, format!("failed: {e}")),
        Some((false, None)) => verdict(false, format!("a verdict failed (see {line})")),
    }
}

fn status_check(report: &Report) -> Verdict {
    if report.status_passed() {
        return verdict(true, "passed, the fork digest included (see m2a-status)");
    }
    if let Some(e) = &report.error {
        return verdict(false, format!("failed: {e}"));
    }
    let failed: Vec<&str> = report
        .verdicts
        .iter()
        .filter(|(_, v)| !v.pass)
        .map(|(name, _)| *name)
        .collect();
    verdict(false, format!("failed: {}", failed.join(", ")))
}

fn decode_limits(blocks: Option<&BlocksReport>) -> Verdict {
    let limits = format!(
        "chunks at most count, at most {MAX_RESPONSE_BYTES} bytes per response, at most \
         {MAX_PAYLOAD_SIZE} bytes per chunk"
    );
    let Some(b) = blocks else {
        return verdict(
            false,
            format!("no BlocksByRange step; codec limits: {limits}"),
        );
    };
    match (b.request, b.blocks_dropped()) {
        (Some(r), Some(n)) => verdict(
            r.count <= MAX_REQUEST_BLOCKS_DENEB && n as u64 <= r.count,
            format!(
                "requested {} blocks (at most {MAX_REQUEST_BLOCKS_DENEB}), received {n}; {limits}",
                r.count
            ),
        ),
        _ => verdict(
            false,
            format!("no BlocksByRange response; codec limits: {limits}"),
        ),
    }
}

fn blocks_dropped(blocks: Option<&BlocksReport>) -> Verdict {
    match blocks.and_then(BlocksReport::blocks_dropped) {
        Some(n) => verdict(
            true,
            format!("{n} blocks hashed and dropped; roots kept only, nothing stored"),
        ),
        None => verdict(false, "no BlocksByRange response to drop"),
    }
}

impl Summary {
    /// The summary of `report`, with `facts`.
    pub fn new(report: &Report, facts: Facts) -> Self {
        let blocks = report.blocks.as_ref();
        let pinned = facts.peer_id;
        let others: Vec<String> = facts
            .connected
            .iter()
            .filter(|p| **p != pinned)
            .map(ToString::to_string)
            .collect();
        let pinned_only = verdict(
            others.is_empty() && facts.listeners == 0,
            format!(
                "connected to {} peer(s), {} not pinned{}; {} listen address(es)",
                facts.connected.len(),
                others.len(),
                if others.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", others.join(", "))
                },
                facts.listeners
            ),
        );
        let checks = vec![
            ("status", status_check(report)),
            (
                "metadata",
                step(
                    report
                        .metadata
                        .as_ref()
                        .map(|m| (m.passed(), m.error.as_ref())),
                    Step {
                        line: "m2a-metadata",
                        gate: "m2a-status",
                    },
                    report.error.as_ref(),
                ),
            ),
            (
                "ping",
                step(
                    report.ping.as_ref().map(|p| (p.passed(), p.error.as_ref())),
                    Step {
                        line: "m2a-ping",
                        gate: "m2a-metadata",
                    },
                    report.error.as_ref(),
                ),
            ),
            (
                "blocks_by_range",
                step(
                    blocks.map(|b| (b.passed(), b.error.as_ref())),
                    Step {
                        line: "m2a-blocks-by-range",
                        gate: "m2a-status",
                    },
                    report.error.as_ref(),
                ),
            ),
            ("pinned_peer_only", pinned_only),
            ("decode_limits", decode_limits(blocks)),
            ("blocks_dropped", blocks_dropped(blocks)),
            ("fuzz_gate", facts.fuzz_gate.clone()),
            (
                "own_os_user",
                verdict(
                    facts.euid != 0,
                    format!("effective UID {} (root refused)", facts.euid),
                ),
            ),
            ("key_handling", facts.key_handling.clone()),
        ];
        Self { facts, checks }
    }

    /// Whether every check in [`CHECKS`] has a passing verdict.
    pub fn passed(&self) -> bool {
        CHECKS
            .iter()
            .all(|c| self.checks.iter().any(|(name, v)| name == c && v.pass))
    }

    /// 0 if every check passed, else 1.
    pub fn exit_code(&self) -> u8 {
        u8::from(!self.passed())
    }

    /// The checks, in [`CHECKS`] order.
    pub fn checks(&self) -> &[(&'static str, Verdict)] {
        &self.checks
    }

    /// The summary line: one JSON object, no newline inside.
    pub fn json_line(&self) -> String {
        let checks = verdicts_json(&self.checks);
        let ms = |t: u128| u64::try_from(t).unwrap_or(u64::MAX);
        json!({
            "event": "m2a-summary",
            "pass": self.passed(),
            "exit_code": self.exit_code(),
            "peer_id": self.facts.peer_id.to_string(),
            "consensus_specs": SPEC_PIN.consensus_specs,
            "started_at_ms": ms(self.facts.started_at_ms),
            "ended_at_ms": ms(self.facts.ended_at_ms),
            "checks": checks,
        })
        .to_string()
    }
}
