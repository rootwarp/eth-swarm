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
//! - `production_build`: the deployed binary `m2a-session` ran; the test binary
//!   `m2a-session-test` fails it.
//! - `fuzz_gate`, `own_os_user`, `key_handling`: what the pre-flight established before the
//!   dial (a passing m2a fuzz gate, the effective UID of the session user `run_as`, never
//!   root, with equal real and saved UIDs, a checked node key). `own_os_user` passes only when
//!   `run_as` is the session account `m2a-session`. The top-level `os_user` and `euid` name the
//!   user and its UID.

use crate::blocks::BlocksReport;
use crate::probe::{verdicts_json, Report, Verdict};
use cl_p2p::m2a_session::config::DEFAULT_RUN_AS;
use cl_p2p::rpc::codec::MAX_RESPONSE_BYTES;
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use libp2p::PeerId;
use network_config::SPEC_PIN;
use p2p_wire::rpc::protocols::MAX_REQUEST_BLOCKS_DENEB;
use serde_json::json;

/// Every check of the summary, in order.
pub const CHECKS: [&str; 11] = [
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
    "production_build",
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
    /// The session user (`run_as`) the pre-flight held that UID to.
    pub user: String,
    /// How the node key was checked.
    pub key_handling: Verdict,
    /// Whether the test binary `m2a-session-test` ran: a summary from it is never evidence.
    pub test_build: bool,
}

/// The summary of one session.
#[derive(Debug, Clone)]
pub struct Summary {
    facts: Facts,
    checks: Vec<(&'static str, Verdict)>,
}

/// `own_os_user`: the pre-flight held the run to its `run_as` user, and that user is the
/// session's own account [`DEFAULT_RUN_AS`]. A config can name another `run_as` (a login user's
/// own name, say); that run passes the pre-flight but not this check.
fn own_os_user(facts: &Facts) -> Verdict {
    let base = format!(
        "effective UID {}, the session user {:?} (root, mixed UIDs and every other UID refused)",
        facts.euid, facts.user
    );
    if facts.user != DEFAULT_RUN_AS {
        return verdict(
            false,
            format!(
                "{base}; run_as {:?} is not the session account {DEFAULT_RUN_AS:?}",
                facts.user
            ),
        );
    }
    verdict(facts.euid != 0, base)
}

/// `production_build`: the deployed binary `m2a-session` ran, not the test binary
/// `m2a-session-test`, whose run is never evidence.
fn production_build(test_build: bool) -> Verdict {
    if test_build {
        verdict(
            false,
            "the test binary m2a-session-test ran: it takes any run_as and the test user's \
             config; run m2a-session",
        )
    } else {
        verdict(
            true,
            "the deployed binary m2a-session ran (test_build = false)",
        )
    }
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
            ("own_os_user", own_os_user(&facts)),
            ("key_handling", facts.key_handling.clone()),
            ("production_build", production_build(facts.test_build)),
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
            "os_user": self.facts.user,
            "euid": self.facts.euid,
            "test_build": self.facts.test_build,
            "consensus_specs": SPEC_PIN.consensus_specs,
            "started_at_ms": ms(self.facts.started_at_ms),
            "ended_at_ms": ms(self.facts.ended_at_ms),
            "checks": checks,
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(user: &str, euid: u32) -> Facts {
        Facts {
            peer_id: PeerId::random(),
            started_at_ms: 1,
            ended_at_ms: 2,
            connected: Vec::new(),
            listeners: 0,
            fuzz_gate: verdict(true, "gate"),
            euid,
            user: user.to_owned(),
            key_handling: verdict(true, "key"),
            test_build: false,
        }
    }

    fn own_os_user(user: &str, euid: u32) -> Verdict {
        let summary = Summary::new(&Report::default(), facts(user, euid));
        summary
            .checks()
            .iter()
            .find(|(name, _)| *name == "own_os_user")
            .map(|(_, v)| v.clone())
            .unwrap()
    }

    /// `own_os_user` passes only for the session's own account, `m2a-session`: a config that
    /// names another `run_as` (a login user's own name, say) passed the pre-flight, but the
    /// run is not the session's own user.
    #[test]
    fn own_os_user_passes_only_as_the_default_run_as() {
        let ok = own_os_user("m2a-session", 1000);
        assert!(ok.pass, "{ok:?}");
        assert!(ok.detail.contains("effective UID 1000"), "{ok:?}");
        let other = own_os_user("alice", 1000);
        assert!(!other.pass, "{other:?}");
        assert!(
            other
                .detail
                .contains("run_as \"alice\" is not the session account \"m2a-session\""),
            "{other:?}"
        );
        assert!(!own_os_user("m2a-session", 0).pass);
        let line: serde_json::Value =
            serde_json::from_str(&Summary::new(&Report::default(), facts("alice", 7)).json_line())
                .unwrap();
        assert_eq!(line["os_user"], "alice");
        assert_eq!(line["euid"], 7);
        assert_eq!(line["test_build"], false);
    }

    /// A summary of the test binary fails its `production_build` check, so a gate that reads
    /// the summary fails the run.
    #[test]
    fn a_test_build_fails_the_production_build_check() {
        let check = |test_build: bool| {
            let summary = Summary::new(
                &Report::default(),
                Facts {
                    test_build,
                    ..facts("m2a-session", 1000)
                },
            );
            summary
                .checks()
                .iter()
                .find(|(name, _)| *name == "production_build")
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert!(check(false).pass);
        let test = check(true);
        assert!(!test.pass, "{test:?}");
        assert!(test.detail.contains("m2a-session-test"), "{test:?}");
    }
}
