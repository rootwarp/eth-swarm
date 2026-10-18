//! The BlocksByRange step: one `BeaconBlocksByRange` v2 request for the peer's last finalized
//! slots, every returned block hashed and compared root by root with the reference API, then
//! dropped; and the JSON line that records it.
//!
//! It runs after the Ping step, on the same connection, once the Status handshake passed (it
//! needs the peer's Status). `phase0/p2p-interface.md` L1485–1575 defines the request,
//! `gloas/p2p-interface.md` L1356–1374 its Gloas context bytes, and `MAX_REQUEST_BLOCKS_DENEB`
//! (128, `deneb/p2p-interface.md` L68) its size.
//!
//! **Range** ([`range`]): `finalized_slot` is the first slot of the peer's `finalized_epoch`,
//! `start_slot = max(earliest_available_slot, finalized_slot - 127)` (saturating), `count =
//! finalized_slot - start_slot + 1` and `step = 1`. Every slot of it is at or before the
//! finalized checkpoint, so no root in it can reorg. A peer whose `earliest_available_slot` is
//! after `finalized_slot` has no finalized block to serve: the step fails without a request.
//!
//! **Roots** ([`compare`]), in both directions, for every slot of the range: a block's
//! `hash_tree_root(block.message)` must equal the API's `/eth/v1/beacon/blocks/{slot}/root`; a
//! slot the API has a block for must have one; a slot the API calls empty (404) must have
//! none. A count-only match fails.
//!
//! **Order**: the API's roots of the whole range are read first, [`ROOT_READS_IN_FLIGHT`] at a
//! time, then the request is sent. No stream to the peer is open while the API is read, so
//! that phase must end before our idle connection timeout closes the connection; with every
//! read bounded by `REQUEST_TIMEOUT`, it does (a compile-time check). The BlocksByRange
//! exchange, the hold and the second Status then follow back to back.
//!
//! **Blocks are dropped**: [`outbound::blocks_by_range`] hands back the decoded blocks, which
//! live only in this step's local `Vec` until [`hash_and_drop`] has their roots. The report
//! holds slots and roots, never a block, and nothing is stored: the binary links no store
//! crate (`scripts/check-m2a-deps.sh`).
//!
//! **Verdicts** ([`FIELDS`], all must pass):
//! - `request`: `start_slot` at or after the peer's `earliest_available_slot`, `count` in
//!   `1..=MAX_REQUEST_BLOCKS_DENEB`, `step` 1, the range ending at `finalized_slot`;
//! - `roots`: no [`Mismatch`] over the range.

use crate::probe::{hex, verdicts_json, Chain, Verdict};
use crate::reference_api::ReferenceApi;
use crate::reference_api::REQUEST_TIMEOUT;
use cl_p2p::m2a_session::{Session, IDLE_CONNECTION_TIMEOUT};
use cl_p2p::rpc::outbound;
use consensus_types::primitives::{Epoch, Root, Slot};
use consensus_types::{forked, EthSpec};
use futures::{StreamExt, TryStreamExt};
use network_config::digest::compute_fork_digest;
use p2p_wire::rpc::messages::{BlocksByRangeV2Request, StatusV2};
use p2p_wire::rpc::protocols::MAX_REQUEST_BLOCKS_DENEB;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Every verdict a passing step has.
pub const FIELDS: [&str; 2] = ["request", "roots"];
/// How many block-root reads are in flight at once \[est\].
pub const ROOT_READS_IN_FLIGHT: usize = 16;

// Every read ends within `REQUEST_TIMEOUT`, so all of a range's roots arrive (or the first
// failure does) well before an idle connection to the peer closes.
const _: () = assert!(
    MAX_REQUEST_BLOCKS_DENEB.div_ceil(ROOT_READS_IN_FLIGHT as u64) * REQUEST_TIMEOUT.as_secs()
        < IDLE_CONNECTION_TIMEOUT.as_secs()
);

/// The request for the peer's last finalized slots, or why there is none.
pub fn range(
    finalized_epoch: Epoch,
    earliest_available_slot: Slot,
    slots_per_epoch: u64,
) -> Result<BlocksByRangeV2Request, String> {
    let finalized_slot = finalized_epoch
        .checked_mul(slots_per_epoch)
        .ok_or_else(|| format!("finalized epoch {finalized_epoch} has no slot in u64"))?;
    if earliest_available_slot > finalized_slot {
        return Err(format!(
            "precondition failed: earliest_available_slot {earliest_available_slot} is after the \
             finalized slot {finalized_slot}: the peer serves no finalized block"
        ));
    }
    let start_slot =
        earliest_available_slot.max(finalized_slot.saturating_sub(MAX_REQUEST_BLOCKS_DENEB - 1));
    Ok(BlocksByRangeV2Request {
        start_slot,
        count: finalized_slot - start_slot + 1,
        step: 1,
    })
}

/// `hash_tree_root(block.message)`: the block root the beacon API reports.
pub use cl_p2p::rpc::outbound::block_root;

/// What the step reads of a block before it drops it.
pub trait Rooted {
    /// The block's slot.
    fn slot(&self) -> Slot;
    /// Its root.
    fn root(&self) -> Root;
}

impl<E: EthSpec> Rooted for forked::SignedBeaconBlock<E> {
    fn slot(&self) -> Slot {
        forked::SignedBeaconBlock::slot(self)
    }

    fn root(&self) -> Root {
        block_root(self)
    }
}

/// The slot and root of every block, in order. It takes the blocks by value and drops each
/// one before it returns.
pub fn hash_and_drop<B: Rooted>(blocks: Vec<B>) -> Vec<(Slot, Root)> {
    blocks.into_iter().map(|b| (b.slot(), b.root())).collect()
}

/// How one slot of the range failed the comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchKind {
    /// Both have a block, with different roots.
    RootDiffers,
    /// The peer sent a block for a slot the API calls empty.
    BlockForEmptySlot,
    /// The peer sent no block for a slot the API has one for.
    MissingBlock,
    /// The API was not asked about the slot.
    NoApiAnswer,
}

impl MismatchKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::RootDiffers => "root differs",
            Self::BlockForEmptySlot => "a block for a slot the API calls empty",
            Self::MissingBlock => "no block for a slot the API has",
            Self::NoApiAnswer => "no API answer for the slot",
        }
    }
}

/// One slot whose block and API root disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mismatch {
    /// The slot.
    pub slot: Slot,
    /// The peer's block root at the slot.
    pub peer: Option<Root>,
    /// The API's root at the slot (`None`: empty).
    pub api: Option<Root>,
    /// What disagrees.
    pub kind: MismatchKind,
}

/// Compares the peer's `(slot, root)`s with the API's root (`None`: empty) of every slot of
/// `request`, in both directions. `peer` comes from [`outbound::blocks_by_range`], so its
/// slots are inside the range and strictly increasing.
pub fn compare(
    request: &BlocksByRangeV2Request,
    peer: &[(Slot, Root)],
    api: &BTreeMap<Slot, Option<Root>>,
) -> Vec<Mismatch> {
    let blocks: BTreeMap<Slot, Root> = peer.iter().copied().collect();
    let end = request.start_slot.saturating_add(request.count);
    (request.start_slot..end)
        .filter_map(|slot| {
            let peer = blocks.get(&slot).copied();
            let Some(&api) = api.get(&slot) else {
                return Some((slot, peer, None, MismatchKind::NoApiAnswer));
            };
            let kind = match (peer, api) {
                (Some(p), Some(a)) if p == a => return None,
                (None, None) => return None,
                (Some(_), Some(_)) => MismatchKind::RootDiffers,
                (Some(_), None) => MismatchKind::BlockForEmptySlot,
                (None, Some(_)) => MismatchKind::MissingBlock,
            };
            Some((slot, peer, api, kind))
        })
        .map(|(slot, peer, api, kind)| Mismatch {
            slot,
            peer,
            api,
            kind,
        })
        .collect()
}

/// Everything the step saw. It holds slots and roots, never a block.
#[derive(Debug, Clone, Default)]
pub struct BlocksReport {
    /// The peer's `finalized_epoch`.
    pub finalized_epoch: Epoch,
    /// The first slot of `finalized_epoch`.
    pub finalized_slot: Option<Slot>,
    /// The peer's `earliest_available_slot`.
    pub earliest_available_slot: Slot,
    /// The request sent.
    pub request: Option<BlocksByRangeV2Request>,
    /// The slot and root of every block received, once they were hashed and dropped.
    pub peer_roots: Option<Vec<(Slot, Root)>>,
    /// The API's root (`None`: empty) of every slot of the range.
    pub api_roots: BTreeMap<Slot, Option<Root>>,
    /// Every slot that failed the comparison.
    pub mismatches: Vec<Mismatch>,
    /// The verdicts, in order.
    pub verdicts: Vec<(&'static str, Verdict)>,
    /// Why the step stopped early.
    pub error: Option<String>,
}

fn root_text(root: Option<Root>) -> Value {
    root.map_or(Value::Null, |r| Value::from(hex(r.as_slice())))
}

impl BlocksReport {
    /// Whether every field in [`FIELDS`] has a passing verdict and nothing failed early.
    pub fn passed(&self) -> bool {
        self.error.is_none()
            && FIELDS
                .iter()
                .all(|f| self.verdicts.iter().any(|(name, v)| name == f && v.pass))
    }

    /// How many blocks were received, hashed and dropped; `None` if no response arrived.
    pub fn blocks_dropped(&self) -> Option<usize> {
        self.peer_roots.as_ref().map(Vec::len)
    }

    fn verdict(&mut self, name: &'static str, pass: bool, detail: String) {
        self.verdicts.push((name, Verdict { pass, detail }));
    }

    /// The step's log line: one JSON object, no newline inside. Slots are decimal strings, as
    /// the beacon API encodes a `uint64`.
    pub fn json_line(&self) -> String {
        let verdicts = verdicts_json(&self.verdicts);
        let request = self.request.map(|r| {
            json!({
                "start_slot": r.start_slot.to_string(),
                "count": r.count.to_string(),
                "step": r.step.to_string(),
            })
        });
        let blocks = self.peer_roots.as_ref().map(|roots| {
            roots
                .iter()
                .map(|(slot, root)| json!({"slot": slot.to_string(), "root": hex(root.as_slice())}))
                .collect::<Vec<_>>()
        });
        let mismatches: Vec<Value> = self
            .mismatches
            .iter()
            .map(|m| {
                json!({
                    "slot": m.slot.to_string(),
                    "kind": m.kind.as_str(),
                    "peer": root_text(m.peer),
                    "api": root_text(m.api),
                })
            })
            .collect();
        let api_blocks = self.api_roots.values().filter(|r| r.is_some()).count();
        json!({
            "event": "m2a-blocks-by-range",
            "pass": self.passed(),
            "error": self.error,
            "finalized_epoch": self.finalized_epoch.to_string(),
            "finalized_slot": self.finalized_slot.map(|s| s.to_string()),
            "earliest_available_slot": self.earliest_available_slot.to_string(),
            "request": request,
            "blocks": blocks,
            "blocks_dropped": self.blocks_dropped(),
            "api_slots_checked": self.api_roots.len(),
            "api_blocks": api_blocks,
            "mismatches": mismatches,
            "verdicts": verdicts,
        })
        .to_string()
    }
}

/// The API's root (`None`: empty) of every slot of `request`, [`ROOT_READS_IN_FLIGHT`] reads at a
/// time; the first failed read fails them all.
async fn api_roots(
    api: &ReferenceApi,
    request: &BlocksByRangeV2Request,
) -> Result<BTreeMap<Slot, Option<Root>>, String> {
    let end = request.start_slot.saturating_add(request.count);
    futures::stream::iter(request.start_slot..end)
        .map(|slot| async move { api.block_root(slot).await.map(|root| (slot, root)) })
        .buffered(ROOT_READS_IN_FLIGHT)
        .map_err(|e| e.to_string())
        .try_collect()
        .await
}

/// Runs the step on a session connected to the pinned peer, for the peer's Status `theirs`.
pub async fn run<E: EthSpec>(
    session: &mut Session<E>,
    api: &ReferenceApi,
    chain: &Chain,
    theirs: &StatusV2,
) -> BlocksReport {
    let mut report = BlocksReport {
        finalized_epoch: theirs.finalized_epoch,
        finalized_slot: theirs.finalized_epoch.checked_mul(chain.slots_per_epoch),
        earliest_available_slot: theirs.earliest_available_slot,
        ..BlocksReport::default()
    };
    if let Err(e) = steps(session, api, chain, &mut report).await {
        report.error = Some(e);
    }
    report
}

async fn steps<E: EthSpec>(
    session: &mut Session<E>,
    api: &ReferenceApi,
    chain: &Chain,
    report: &mut BlocksReport,
) -> Result<(), String> {
    let eas = report.earliest_available_slot;
    let request = match range(report.finalized_epoch, eas, chain.slots_per_epoch) {
        Ok(r) => r,
        Err(e) => {
            report.verdict("request", false, e);
            return Ok(());
        }
    };
    report.request = Some(request);
    let last = request.start_slot + request.count - 1;
    report.verdict(
        "request",
        request.start_slot >= eas
            && (1..=MAX_REQUEST_BLOCKS_DENEB).contains(&request.count)
            && request.step == 1
            && Some(last) == report.finalized_slot,
        format!(
            "slots {}..={last} (count {}, at most {MAX_REQUEST_BLOCKS_DENEB}; step {}), from \
             earliest_available_slot {eas} or later, to the finalized slot",
            request.start_slot, request.count, request.step
        ),
    );
    report.api_roots = api_roots(api, &request).await?;
    let gvr = chain.genesis.genesis_validators_root;
    let digest_at = |epoch| compute_fork_digest(&chain.config, &gvr, epoch).ok();
    let peer = session.pinned().peer_id;
    let blocks = outbound::blocks_by_range::<E, _>(session.swarm(), peer, request, &digest_at)
        .await
        .map_err(|e| format!("blocks_by_range: {e}"))?;
    let roots = hash_and_drop(blocks);
    report.peer_roots = Some(roots.clone());
    report.mismatches = compare(&request, &roots, &report.api_roots);
    let api_blocks = report.api_roots.values().filter(|r| r.is_some()).count();
    let detail = if report.mismatches.is_empty() {
        format!(
            "all {} slots agree: {} blocks, each root equal to the API's, {} empty on both sides",
            request.count,
            roots.len(),
            request.count as usize - api_blocks
        )
    } else {
        let first = report.mismatches[0];
        format!(
            "{} of {} slots disagree (peer {} blocks, API {}); first at slot {}: {}",
            report.mismatches.len(),
            request.count,
            roots.len(),
            api_blocks,
            first.slot,
            first.kind.as_str()
        )
    };
    report.verdict("roots", report.mismatches.is_empty(), detail);
    Ok(())
}
