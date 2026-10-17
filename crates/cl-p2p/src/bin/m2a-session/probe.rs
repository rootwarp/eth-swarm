//! The Status probe: one Status v2 exchange with the pinned peer, judged against the reference
//! beacon API, and the JSON line that records it.
//!
//! **Our Status** (probe mode): `fork_digest` is `compute_fork_digest(genesis_validators_root,
//! current_epoch)` for the pinned Sepolia config and the wall clock; `finalized_*` are the
//! reference API's finalized checkpoint (`/eth/v1/beacon/states/head/finality_checkpoints`);
//! `head_root`/`head_slot` are that finalized block (`/eth/v1/beacon/headers/{root}`); and
//! `earliest_available_slot` is our `head_slot` (there is no value for "serves nothing").
//!
//! **Order**: connect; check the API's genesis against the pinned one (a wrong genesis root
//! would make every digest wrong); read the node's ENR; sample the API; exchange; sample
//! again. If the finalized checkpoint moved between the two samples, the exchange runs once
//! more (with a Status built from the newer sample); if it moves again, the finalized check
//! fails. The match is never relaxed.
//!
//! **Verdicts** ([`FIELDS`], all must pass):
//! - `genesis`: the API's genesis time, validators root and fork version equal the pinned ones;
//! - `fork_digest`: the peer's digest equals ours (`phase0/p2p-interface.md` handshake);
//! - `enr_fork_digest`: the `eth2` digest of the node's ENR equals ours;
//! - `finalized_root`, `finalized_epoch`: exactly the API's finalized checkpoint (the sample
//!   after the exchange, equal to the one before it);
//! - `head_slot`: within [`HEAD_TOLERANCE_SLOTS`] of the API's head in either sample;
//! - `head_root`: the API knows the block, on its canonical chain, at the peer's `head_slot`;
//! - `earliest_available_slot`: the peer's, from its Status v2, at most its `head_slot`;
//! - `connection`: the peer accepted us: the connection is still up [`HOLD`] after the
//!   exchange and a second Status on it succeeds.

use crate::enr;
use crate::reference_api::{Checkpoint, Header, ReferenceApi};
use cl_p2p::m2a_session::{Session, SessionError};
use cl_p2p::rpc::outbound::{self, OutboundError};
use consensus_types::EthSpec;
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use network_config::digest::{current_epoch, fork_digest_inputs, DigestInputs};
use network_config::{ChainConfig, Genesis};
use p2p_wire::rpc::messages::StatusV2;
use serde_json::{json, Value};
use std::time::Duration;

/// How far the peer's head may be from the API's [est].
pub const HEAD_TOLERANCE_SLOTS: u64 = 2;
/// How long the connection must stay up after the exchange [est].
pub const HOLD: Duration = Duration::from_secs(10);
/// How often the exchange is re-run when finality moves during it.
pub const MAX_RERUNS: u32 = 1;
/// Every verdict a passing probe has.
pub const FIELDS: [&str; 9] = [
    "genesis",
    "fork_digest",
    "enr_fork_digest",
    "finalized_root",
    "finalized_epoch",
    "head_root",
    "head_slot",
    "earliest_available_slot",
    "connection",
];

/// The pinned chain the session runs on.
#[derive(Debug, Clone)]
pub struct Chain {
    /// The pinned config.
    pub config: ChainConfig,
    /// The pinned genesis.
    pub genesis: Genesis,
    /// `SLOTS_PER_EPOCH` of the config's preset.
    pub slots_per_epoch: u64,
}

/// What the probe needs besides the session and the API.
pub struct Probe<'a> {
    /// The chain.
    pub chain: &'a Chain,
    /// Unix milliseconds now.
    pub now_ms: &'a (dyn Fn() -> u128 + Sync),
    /// How long to connect.
    pub connect_timeout: Duration,
    /// [`HOLD`] in production.
    pub hold: Duration,
}

/// One reading of the reference API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiSample {
    /// The finalized checkpoint.
    pub finalized: Checkpoint,
    /// The finalized block's header.
    pub finalized_header: Header,
    /// The head block's header.
    pub head: Header,
}

/// One field's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Whether it passed.
    pub pass: bool,
    /// What was compared.
    pub detail: String,
}

/// Everything the probe saw.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Our Status (of the exchange judged).
    pub ours: Option<StatusV2>,
    /// The peer's Status.
    pub peer: Option<StatusV2>,
    /// The digest inputs of our Status.
    pub inputs: Option<DigestInputs>,
    /// The `eth2` digest of the reference node's ENR.
    pub enr_fork_digest: Option<[u8; 4]>,
    /// The API sample before the exchange judged.
    pub api_before: Option<ApiSample>,
    /// The API sample after it.
    pub api_after: Option<ApiSample>,
    /// Re-runs because finality moved.
    pub reruns: u32,
    /// The verdicts, in order.
    pub verdicts: Vec<(&'static str, Verdict)>,
    /// Why the probe stopped early.
    pub error: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    let digits: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{digits}")
}

fn status_json(s: &StatusV2) -> Value {
    json!({
        "fork_digest": hex(&s.fork_digest),
        "finalized_root": hex(s.finalized_root.as_slice()),
        "finalized_epoch": s.finalized_epoch.to_string(),
        "head_root": hex(s.head_root.as_slice()),
        "head_slot": s.head_slot.to_string(),
        "earliest_available_slot": s.earliest_available_slot.to_string(),
    })
}

fn header_json(h: &Header) -> Value {
    json!({"root": hex(h.root.as_slice()), "slot": h.slot.to_string(), "canonical": h.canonical})
}

fn sample_json(s: &ApiSample) -> Value {
    json!({
        "finalized": {"epoch": s.finalized.epoch.to_string(), "root": hex(s.finalized.root.as_slice())},
        "finalized_header": header_json(&s.finalized_header),
        "head": header_json(&s.head),
    })
}

fn inputs_json(i: &DigestInputs) -> Value {
    json!({
        "epoch": i.epoch.to_string(),
        "fork": i.fork.as_str(),
        "fork_version": hex(&i.fork_version),
        "blob_parameters": {
            "epoch": i.blob_parameters.epoch.to_string(),
            "max_blobs_per_block": i.blob_parameters.max_blobs_per_block.to_string(),
        },
        "genesis_validators_root": hex(&i.genesis_validators_root),
        "fork_digest": hex(&i.fork_digest),
    })
}

impl Report {
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

    /// The session log line: one JSON object, no newline inside.
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
            "event": "m2a-status",
            "pass": self.passed(),
            "error": self.error,
            "ours": self.ours.as_ref().map(status_json),
            "peer": self.peer.as_ref().map(status_json),
            "digest_inputs": self.inputs.as_ref().map(inputs_json),
            "enr_fork_digest": self.enr_fork_digest.map(|d| hex(&d)),
            "api_before": self.api_before.as_ref().map(sample_json),
            "api_after": self.api_after.as_ref().map(sample_json),
            "finality_reruns": self.reruns,
            "earliest_available_slot": self.peer.as_ref().map(|p| p.earliest_available_slot.to_string()),
            "verdicts": verdicts,
        })
        .to_string()
    }
}

/// Reads the finalized checkpoint, its block and the head.
async fn sample(api: &ReferenceApi) -> Result<ApiSample, String> {
    let finalized = api
        .finality_checkpoints()
        .await
        .map_err(|e| e.to_string())?;
    let finalized_header = api
        .header(finalized.root)
        .await
        .map_err(|e| e.to_string())?;
    let head = api.head_header().await.map_err(|e| e.to_string())?;
    Ok(ApiSample {
        finalized,
        finalized_header,
        head,
    })
}

/// Our Status for `sample` at the wall clock.
fn our_status(
    chain: &Chain,
    now_ms: u128,
    sample: &ApiSample,
) -> Result<(DigestInputs, StatusV2), String> {
    let epoch = current_epoch(
        chain.genesis.genesis_time,
        chain.config.slot_duration_ms(),
        chain.slots_per_epoch,
        now_ms,
    )
    .map_err(|e| e.to_string())?;
    let inputs = fork_digest_inputs(&chain.config, &chain.genesis.genesis_validators_root, epoch)
        .map_err(|e| e.to_string())?;
    let head = sample.finalized_header;
    let status = StatusV2 {
        fork_digest: inputs.fork_digest,
        finalized_root: sample.finalized.root,
        finalized_epoch: sample.finalized.epoch,
        head_root: head.root,
        head_slot: head.slot,
        earliest_available_slot: head.slot,
    };
    Ok((inputs, status))
}

/// Runs the probe on a started, not yet connected session.
pub async fn run<E: EthSpec>(
    session: &mut Session<E>,
    api: &ReferenceApi,
    probe: &Probe<'_>,
) -> Report {
    let mut report = Report::default();
    if let Err(e) = steps(session, api, probe, &mut report).await {
        report.error = Some(e);
    }
    report
}

async fn steps<E: EthSpec>(
    session: &mut Session<E>,
    api: &ReferenceApi,
    probe: &Probe<'_>,
    report: &mut Report,
) -> Result<(), String> {
    match tokio::time::timeout(probe.connect_timeout, session.connect()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("connect: {e}")),
        Err(_) => {
            return Err(format!(
                "connect: timed out after {:?}",
                probe.connect_timeout
            ))
        }
    }
    check_genesis(api, probe.chain, report).await?;
    let enr = api.identity_enr().await.map_err(|e| e.to_string())?;
    let enr_digest = enr::eth2_fork_id(&enr).map(|id| id.fork_digest);
    report.enr_fork_digest = enr_digest.as_ref().ok().copied();

    let peer = session.pinned().peer_id;
    let mut before = sample(api).await?;
    let mut mismatch = false;
    let mut moved_again = false;
    let ours = loop {
        let (inputs, ours) = our_status(probe.chain, (probe.now_ms)(), &before)?;
        report.inputs = Some(inputs);
        report.ours = Some(ours.clone());
        let result = outbound::status(session.swarm(), peer, &ours).await;
        let theirs = match result {
            Ok(s) => s,
            Err(OutboundError::ForkDigestMismatch { peer, .. }) => {
                mismatch = true;
                *peer
            }
            Err(e) => return Err(format!("status exchange: {e}")),
        };
        report.peer = Some(theirs);
        let after = sample(api).await?;
        report.api_before = Some(before);
        report.api_after = Some(after);
        if after.finalized != before.finalized && !mismatch {
            if report.reruns < MAX_RERUNS {
                report.reruns += 1;
                tracing::info!("finality moved during the exchange; running it once more");
                before = after;
                continue;
            }
            moved_again = true;
        }
        break ours;
    };
    let theirs = report.peer.clone().expect("set by the exchange");
    let (before, after) = (
        report.api_before.expect("sampled"),
        report.api_after.expect("sampled"),
    );

    report.verdict(
        "fork_digest",
        !mismatch,
        format!(
            "ours {} (epoch {}), the peer's {}",
            hex(&ours.fork_digest),
            report.inputs.map_or(0, |i| i.epoch),
            hex(&theirs.fork_digest)
        ),
    );
    match enr_digest {
        Ok(d) => report.verdict(
            "enr_fork_digest",
            d == ours.fork_digest,
            format!("ENR eth2 {}, ours {}", hex(&d), hex(&ours.fork_digest)),
        ),
        Err(e) => report.verdict("enr_fork_digest", false, format!("ENR: {e}")),
    }
    let moved = if moved_again {
        "; finality moved again during the re-run"
    } else {
        ""
    };
    report.verdict(
        "finalized_root",
        !moved_again && theirs.finalized_root == after.finalized.root,
        format!(
            "peer {}, API {}{moved}",
            hex(theirs.finalized_root.as_slice()),
            hex(after.finalized.root.as_slice())
        ),
    );
    report.verdict(
        "finalized_epoch",
        !moved_again && theirs.finalized_epoch == after.finalized.epoch,
        format!(
            "peer {}, API {}{moved}",
            theirs.finalized_epoch, after.finalized.epoch
        ),
    );
    let off = theirs
        .head_slot
        .abs_diff(before.head.slot)
        .min(theirs.head_slot.abs_diff(after.head.slot));
    report.verdict(
        "head_slot",
        off <= HEAD_TOLERANCE_SLOTS,
        format!(
            "peer {}, API {} before and {} after: {off} slot(s) off, at most {HEAD_TOLERANCE_SLOTS}",
            theirs.head_slot, before.head.slot, after.head.slot
        ),
    );
    match api.header(theirs.head_root).await {
        Ok(h) => report.verdict(
            "head_root",
            h.canonical && h.slot == theirs.head_slot,
            format!(
                "API has {} at slot {} (canonical: {}), the peer's head_slot {}",
                hex(h.root.as_slice()),
                h.slot,
                h.canonical,
                theirs.head_slot
            ),
        ),
        Err(e) => report.verdict("head_root", false, format!("API: {e}")),
    }
    report.verdict(
        "earliest_available_slot",
        theirs.earliest_available_slot <= theirs.head_slot,
        format!(
            "{} against head_slot {}",
            theirs.earliest_available_slot, theirs.head_slot
        ),
    );
    if mismatch {
        report.verdict(
            "connection",
            false,
            "not checked: the handshake failed".to_owned(),
        );
        return Ok(());
    }
    let connection = match hold(session, probe.hold).await {
        Err(e) => Err(e),
        Ok(()) => second_status(session, probe, &after).await,
    };
    match connection {
        Ok(digest) => report.verdict(
            "connection",
            true,
            format!(
                "still connected after {:?}; a second Status at {} succeeded",
                probe.hold,
                hex(&digest)
            ),
        ),
        Err(e) => report.verdict("connection", false, e),
    }
    Ok(())
}

/// A second Status on the held connection, built afresh: the hold may have crossed a BPO or
/// fork boundary, after which the old digest is wrong. Returns the digest sent.
async fn second_status<E: EthSpec>(
    session: &mut Session<E>,
    probe: &Probe<'_>,
    sample: &ApiSample,
) -> Result<[u8; 4], String> {
    let (_, ours) = our_status(probe.chain, (probe.now_ms)(), sample)?;
    let peer = session.pinned().peer_id;
    outbound::status(session.swarm(), peer, &ours)
        .await
        .map(|_| ours.fork_digest)
        .map_err(|e| format!("second Status: {e}"))
}

/// The API's genesis must be the pinned one; anything else stops the probe.
async fn check_genesis(
    api: &ReferenceApi,
    chain: &Chain,
    report: &mut Report,
) -> Result<(), String> {
    let g = api.genesis().await.map_err(|e| e.to_string())?;
    let pinned = chain.genesis;
    let pass = g.genesis_time == pinned.genesis_time
        && g.genesis_validators_root.0 == pinned.genesis_validators_root
        && g.genesis_fork_version == chain.config.genesis_fork_version();
    let detail = format!(
        "API time {} root {} version {}; pinned time {} root {} version {}",
        g.genesis_time,
        hex(g.genesis_validators_root.as_slice()),
        hex(&g.genesis_fork_version),
        pinned.genesis_time,
        hex(&pinned.genesis_validators_root),
        hex(&chain.config.genesis_fork_version())
    );
    report.verdict("genesis", pass, detail);
    if pass {
        Ok(())
    } else {
        Err("the reference node's genesis differs from the pinned one".to_owned())
    }
}

/// Drives the swarm for `d`; fails if the last connection to the pinned peer closes.
async fn hold<E: EthSpec>(session: &mut Session<E>, d: Duration) -> Result<(), String> {
    let peer = session.pinned().peer_id;
    let deadline = tokio::time::Instant::now() + d;
    loop {
        match tokio::time::timeout_at(deadline, session.swarm().select_next_some()).await {
            Err(_) => break,
            Ok(SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                cause,
                ..
            }) if peer_id == peer => {
                let cause = cause.map_or_else(|| "no cause".to_owned(), |c| c.to_string());
                return Err(format!(
                    "the peer closed the connection within {d:?}: {cause}"
                ));
            }
            Ok(SwarmEvent::NewListenAddr { address, .. }) => {
                return Err(SessionError::Listening(address).to_string());
            }
            Ok(_) => {}
        }
    }
    if session.swarm().is_connected(&peer) {
        Ok(())
    } else {
        Err(format!("not connected after {d:?}"))
    }
}
