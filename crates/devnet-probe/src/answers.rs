//! `answers`: asks a running probe (the `cl-p2p` unit, `testing/kurtosis/run-units.sh`) for its
//! custody columns by `DataColumnSidecarsByRange` v1 and `DataColumnSidecarsByRoot` v1, as any
//! peer would, and judges every answer against the column store that it serves from
//! ([`crate::serve::judge_answers`], the checks of `serve`'s own self-check).
//!
//! The store is cl-chain's (`columns_dir`), opened read-only while the units run. The probe
//! keeps storing meanwhile, so the range ends [`DEFAULT_BEHIND_EPOCHS`] epochs before the wall
//! clock (`--behind-slots`): the columns of those blocks have arrived. The range starts at the
//! `earliest_available_slot` of the probe's Status. The custody columns are the ones of
//! `node_id` for `CUSTODY_REQUIREMENT` groups, which the probe advertises.

use crate::devnet::Devnet;
use crate::report::Check;
use crate::serve::{judge_answers, Answers, ColumnRequester};
use cl_chain_columns::ColumnReader;
use consensus_types::das::{custody_columns, CUSTODY_REQUIREMENT};
use consensus_types::primitives::U256;
use consensus_types::EthSpec;
use libp2p::Multiaddr;
use std::path::PathBuf;

/// The check's name, as the subcommand.
pub const NAME: &str = "answers";

/// How many epochs before the wall clock the range ends by default.
pub const DEFAULT_BEHIND_EPOCHS: u64 = 2;

/// What `answers` asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswersPlan {
    /// The probe's libp2p address, without a peer ID (Noise proves whichever it is).
    pub probe: Multiaddr,
    /// The probe's column store.
    pub columns_dir: PathBuf,
    /// The probe's node ID: its custody columns.
    pub node_id: U256,
    /// How many slots before the wall clock the range ends; `None`:
    /// [`DEFAULT_BEHIND_EPOCHS`] epochs.
    pub behind_slots: Option<u64>,
}

/// The `answers` check (see the module docs) at the wall clock `now_ms`, with the store of
/// `plan.columns_dir` opened read-only.
pub async fn answers<E: EthSpec>(devnet: &Devnet, plan: &AnswersPlan, now_ms: u128) -> Check {
    match ColumnReader::open(&plan.columns_dir) {
        Ok(store) => answers_with::<E>(devnet, plan, &store, now_ms).await,
        Err(e) => Check::failed(
            NAME,
            format!("the column store {}: {e}", plan.columns_dir.display()),
        ),
    }
}

/// [`answers`] against `store`, which must be the store of `plan.columns_dir`.
pub async fn answers_with<E: EthSpec>(
    devnet: &Devnet,
    plan: &AnswersPlan,
    store: &ColumnReader,
    now_ms: u128,
) -> Check {
    let mut check = Check::new(NAME);
    let custody = match custody_columns(plan.node_id, CUSTODY_REQUIREMENT) {
        Ok(custody) => custody,
        Err(e) => return Check::failed(NAME, format!("the custody columns: {e}")),
    };
    let Some(now_slot) = devnet.probe_network().slot_at(now_ms) else {
        return Check::failed(NAME, "the clock is before genesis");
    };
    let behind = plan
        .behind_slots
        .unwrap_or(DEFAULT_BEHIND_EPOCHS * devnet.slots_per_epoch());
    let last_slot = now_slot.saturating_sub(behind);
    let digest = match devnet.fork_digest(now_ms) {
        Ok(digest) => digest,
        Err(e) => return Check::failed(NAME, format!("our fork digest: {e}")),
    };
    let mut requester = match ColumnRequester::<E>::new(devnet) {
        Ok(requester) => requester,
        Err(e) => return Check::failed(NAME, e),
    };
    let peer = match requester.connect_any(plan.probe.clone()).await {
        Ok(peer) => peer,
        Err(e) => return Check::failed(NAME, format!("the probe at {}: {e}", plan.probe)),
    };
    let earliest = match requester.status(peer, digest).await {
        Ok(theirs) => {
            check.pass(format!(
                "the probe {peer} at {}: its Status advertises earliest_available_slot {}",
                plan.probe, theirs.earliest_available_slot
            ));
            theirs.earliest_available_slot
        }
        Err(e) => {
            check.fail(format!("the probe's Status: {e}"));
            return check;
        }
    };
    if earliest > last_slot {
        check.fail(format!(
            "nothing to ask yet: served from slot {earliest}, the range ends at {last_slot} \
             ({behind} slots before the clock)"
        ));
        return check;
    }
    let answers = Answers {
        store,
        custody: &custody,
        earliest,
        last_slot,
    };
    judge_answers(&mut check, &mut requester, devnet, peer, &answers).await;
    check
}
