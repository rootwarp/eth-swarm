//! The Ping step: one Ping v1 exchange with the pinned peer, its answer judged against the
//! `seq_number` the MetaData step decoded, and the JSON line that records it.
//!
//! It runs after the MetaData step, on the same connection, and only if that step decoded a
//! MetaData. `phase0/p2p-interface.md` L1628–1682 defines Ping: we send our MetaData
//! `seq_number` ([`OUR_SEQ_NUMBER`]) and the peer answers with its own.
//!
//! **Order and verdicts** (`p` the Ping answer, `s` the MetaData step's `seq_number`):
//! - `p == s`: `seq_number` passes.
//! - `p < s`: `seq_number` fails; a `seq_number` never decreases.
//! - `p > s`: the peer's MetaData changed since the step, and a changed `seq_number` means
//!   "request MetaData" (`phase0/p2p-interface.md` L456–477). The MetaData is re-fetched once
//!   ([`MAX_REFETCHES`]), then the identity re-sampled: `seq_number` passes if the re-fetched
//!   `seq_number` equals `p`, and `refetch_identity` if every field of the re-fetched MetaData
//!   equals the identity's. It is never re-fetched twice, and the match is never relaxed.
//!
//! No Goodbye is sent; the session closes the connection.

use crate::metadata::{self, metadata_json};
use crate::probe::{verdicts_json, Verdict};
use crate::reference_api::ReferenceApi;
use cl_p2p::m2a_session::Session;
use cl_p2p::rpc::outbound;
use consensus_types::EthSpec;
use p2p_wire::rpc::messages::MetaDataV3;
use serde_json::json;

/// Our MetaData `seq_number`: the session advertises no subnets and answers no MetaData
/// requests, so its MetaData never changes from the initial 0.
pub const OUR_SEQ_NUMBER: u64 = 0;
/// How often MetaData is re-fetched when the Ping answer is above the MetaData step's.
pub const MAX_REFETCHES: u32 = 1;
/// Every verdict a passing step has; a re-fetch adds `refetch_identity`, which must pass too.
pub const FIELDS: [&str; 1] = ["seq_number"];

/// Everything the step saw.
#[derive(Debug, Clone, Default)]
pub struct PingReport {
    /// The `seq_number` we sent.
    pub ours: u64,
    /// The peer's Ping answer.
    pub peer: Option<u64>,
    /// The `seq_number` of the MetaData step's MetaData.
    pub metadata_seq_number: u64,
    /// MetaData re-fetches because the Ping answer was above `metadata_seq_number`.
    pub refetches: u32,
    /// The re-fetched MetaData.
    pub refetched: Option<MetaDataV3>,
    /// The reference node's MetaData, sampled after the re-fetch.
    pub refetched_api: Option<MetaDataV3>,
    /// The verdicts, in order.
    pub verdicts: Vec<(&'static str, Verdict)>,
    /// Why the step stopped early.
    pub error: Option<String>,
}

impl PingReport {
    /// Whether every field in [`FIELDS`] has a passing verdict, every other verdict passed
    /// and nothing failed early.
    pub fn passed(&self) -> bool {
        self.error.is_none()
            && FIELDS
                .iter()
                .all(|f| self.verdicts.iter().any(|(name, _)| name == f))
            && self.verdicts.iter().all(|(_, v)| v.pass)
    }

    fn verdict(&mut self, name: &'static str, pass: bool, detail: String) {
        self.verdicts.push((name, Verdict { pass, detail }));
    }

    /// The step's log line: one JSON object, no newline inside. The `seq_number`s are decimal
    /// strings, as the beacon API encodes a `uint64`.
    pub fn json_line(&self) -> String {
        let verdicts = verdicts_json(&self.verdicts);
        let refetched = (self.refetches > 0).then(|| {
            json!({
                "peer": self.refetched.as_ref().map(metadata_json),
                "api": self.refetched_api.as_ref().map(metadata_json),
            })
        });
        json!({
            "event": "m2a-ping",
            "pass": self.passed(),
            "error": self.error,
            "our_seq_number": self.ours.to_string(),
            "peer_seq_number": self.peer.map(|p| p.to_string()),
            "metadata_seq_number": self.metadata_seq_number.to_string(),
            "metadata_refetches": self.refetches,
            "refetched": refetched,
            "verdicts": verdicts,
        })
        .to_string()
    }
}

/// Runs the step on a session connected to the pinned peer, against `metadata_seq_number`, the
/// `seq_number` the MetaData step decoded.
pub async fn run<E: EthSpec>(
    session: &mut Session<E>,
    api: &ReferenceApi,
    metadata_seq_number: u64,
) -> PingReport {
    let mut report = PingReport {
        ours: OUR_SEQ_NUMBER,
        metadata_seq_number,
        ..PingReport::default()
    };
    if let Err(e) = steps(session, api, &mut report).await {
        report.error = Some(e);
    }
    report
}

async fn steps<E: EthSpec>(
    session: &mut Session<E>,
    api: &ReferenceApi,
    report: &mut PingReport,
) -> Result<(), String> {
    let peer = session.pinned().peer_id;
    let theirs = outbound::ping(session.swarm(), peer, report.ours)
        .await
        .map_err(|e| format!("ping: {e}"))?;
    report.peer = Some(theirs);
    let step = report.metadata_seq_number;
    if theirs <= step {
        let (pass, why) = if theirs == step {
            (true, "")
        } else {
            (false, ": below it, and a seq_number never decreases")
        };
        report.verdict(
            "seq_number",
            pass,
            format!("Ping {theirs}, MetaData {step}{why}"),
        );
        return Ok(());
    }
    report.refetches = MAX_REFETCHES;
    tracing::info!(
        ping = theirs,
        metadata = step,
        "the peer's Ping seq_number is above its MetaData's; requesting MetaData once more"
    );
    let refetched = session
        .request_metadata()
        .await
        .map_err(|e| format!("metadata re-fetch: {e}"))?;
    report.refetched = Some(refetched.clone());
    let identity = api
        .node_identity()
        .await
        .map(|id| id.metadata)
        .map_err(|e| format!("identity re-sample: {e}"))?;
    report.refetched_api = Some(identity.clone());
    report.verdict(
        "seq_number",
        refetched.seq_number == theirs,
        format!(
            "Ping {theirs}, MetaData {step}, re-fetched MetaData {}",
            refetched.seq_number
        ),
    );
    let (peer_json, api_json) = (metadata_json(&refetched), metadata_json(&identity));
    let differ: Vec<&str> = metadata::FIELDS
        .into_iter()
        .filter(|f| peer_json[f] != api_json[f])
        .collect();
    let detail = if differ.is_empty() {
        format!("re-fetched MetaData equals the API's: {api_json}")
    } else {
        format!(
            "re-fetched MetaData {peer_json}, API {api_json}: {} differ",
            differ.join(", ")
        )
    };
    report.verdict("refetch_identity", refetched == identity, detail);
    Ok(())
}
