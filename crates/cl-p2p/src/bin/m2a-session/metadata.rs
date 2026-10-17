//! The MetaData step: the peer's MetaData v3, judged field by field against the reference
//! node's own MetaData from `/eth/v1/node/identity`, and the JSON line that records it.
//!
//! It runs after the Status exchange, on the same connection
//! ([`cl_p2p::m2a_session::Session::request_metadata`], which keeps the peer's MetaData in the
//! session), and the Ping step ([`crate::ping`]) compares its answer with this `seq_number`. `fulu/p2p-interface.md` L778–794 defines the request, L269–288 the type;
//! `attnets` and `syncnets` are `altair/p2p-interface.md` L141–149.
//!
//! **Order**: sample the identity; request; sample again. `seq_number` increments on every
//! change to the other fields (`phase0/p2p-interface.md` L456–477), so if it moved between the
//! samples (a subnet rotation), the request runs once more, sampled against the newer one; if it
//! moves again, every field fails. The match is never relaxed.
//!
//! **Verdicts** ([`FIELDS`], all must pass): each field of the peer's MetaData equals the API's
//! (the sample after the request, whose `seq_number` equals the one before it), compared as
//! typed values.

use crate::probe::{hex, Verdict};
use crate::reference_api::ReferenceApi;
use cl_p2p::m2a_session::Session;
use consensus_types::EthSpec;
use p2p_wire::rpc::messages::MetaDataV3;
use serde_json::{json, Value};

/// How often the request is re-run when the node's `seq_number` moves during it.
pub const MAX_RERUNS: u32 = 1;
/// Every verdict a passing step has: the fields of MetaData v3.
pub const FIELDS: [&str; 4] = ["seq_number", "attnets", "syncnets", "custody_group_count"];

/// Everything the step saw.
#[derive(Debug, Clone, Default)]
pub struct MetaDataReport {
    /// The peer's MetaData (of the last attempt, the one judged).
    pub peer: Option<MetaDataV3>,
    /// The API's MetaData before the last attempt's request.
    pub api_before: Option<MetaDataV3>,
    /// The API's MetaData after it; `None` if the attempt stopped before.
    pub api_after: Option<MetaDataV3>,
    /// Re-runs because `seq_number` moved.
    pub reruns: u32,
    /// The verdicts, in order.
    pub verdicts: Vec<(&'static str, Verdict)>,
    /// Why the step stopped early.
    pub error: Option<String>,
}

/// A MetaData in the beacon API's encoding: decimal strings, `0x` hex bitvectors.
pub fn metadata_json(m: &MetaDataV3) -> Value {
    json!({
        "seq_number": m.seq_number.to_string(),
        "attnets": hex(m.attnets.as_slice()),
        "syncnets": hex(m.syncnets.as_slice()),
        "custody_group_count": m.custody_group_count.to_string(),
    })
}

impl MetaDataReport {
    /// Whether every field in [`FIELDS`] has a passing verdict and nothing failed early.
    pub fn passed(&self) -> bool {
        self.error.is_none()
            && FIELDS
                .iter()
                .all(|f| self.verdicts.iter().any(|(name, v)| name == f && v.pass))
    }

    fn verdict(&mut self, name: &'static str, pass: bool, detail: String) {
        self.verdicts.push((name, Verdict { pass, detail }));
    }

    /// The step's log line: one JSON object, no newline inside.
    pub fn json_line(&self) -> String {
        let verdicts: serde_json::Map<String, Value> = self
            .verdicts
            .iter()
            .map(|(name, v)| {
                (
                    (*name).to_owned(),
                    json!({"pass": v.pass, "detail": v.detail}),
                )
            })
            .collect();
        json!({
            "event": "m2a-metadata",
            "pass": self.passed(),
            "error": self.error,
            "peer": self.peer.as_ref().map(metadata_json),
            "api_before": self.api_before.as_ref().map(metadata_json),
            "api_after": self.api_after.as_ref().map(metadata_json),
            "seq_number_reruns": self.reruns,
            "verdicts": verdicts,
        })
        .to_string()
    }
}

/// The reference node's MetaData.
pub async fn sample(api: &ReferenceApi) -> Result<MetaDataV3, String> {
    api.node_identity()
        .await
        .map(|id| id.metadata)
        .map_err(|e| format!("MetaData sample: {e}"))
}

/// Runs the step on a session connected to the pinned peer.
pub async fn run<E: EthSpec>(session: &mut Session<E>, api: &ReferenceApi) -> MetaDataReport {
    let mut report = MetaDataReport::default();
    if let Err(e) = steps(session, api, &mut report).await {
        report.error = Some(e);
    }
    report
}

async fn steps<E: EthSpec>(
    session: &mut Session<E>,
    api: &ReferenceApi,
    report: &mut MetaDataReport,
) -> Result<(), String> {
    let mut before = sample(api).await?;
    let moved_again = loop {
        // One attempt's observations only: a re-run that fails part-way must not leave the
        // previous attempt's answer or sample next to its own.
        report.api_before = Some(before.clone());
        report.peer = None;
        report.api_after = None;
        let theirs = session
            .request_metadata()
            .await
            .map_err(|e| format!("metadata request: {e}"))?;
        report.peer = Some(theirs);
        let after = sample(api).await?;
        report.api_after = Some(after.clone());
        if after.seq_number == before.seq_number {
            break false;
        }
        if report.reruns == MAX_RERUNS {
            break true;
        }
        report.reruns += 1;
        tracing::info!(
            before = %metadata_json(&before),
            after = %metadata_json(&after),
            "the reference node's seq_number moved during the MetaData request; requesting once more"
        );
        before = after;
    };
    let theirs = report.peer.clone().expect("set by the request");
    let after = report.api_after.clone().expect("sampled");
    let moved = if moved_again {
        "; seq_number moved again during the re-run"
    } else {
        ""
    };
    // Typed comparisons, in FIELDS order; the details show the API's encoding.
    let equal = [
        theirs.seq_number == after.seq_number,
        theirs.attnets == after.attnets,
        theirs.syncnets == after.syncnets,
        theirs.custody_group_count == after.custody_group_count,
    ];
    let (peer_json, api_json) = (metadata_json(&theirs), metadata_json(&after));
    for (name, equal) in FIELDS.into_iter().zip(equal) {
        let detail = format!(
            "{name}: peer {}, API {}{moved}",
            peer_json[name].as_str().unwrap_or_default(),
            api_json[name].as_str().unwrap_or_default()
        );
        report.verdict(name, !moved_again && equal, detail);
    }
    Ok(())
}
