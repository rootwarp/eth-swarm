//! `ReqRespService/BlocksByRange`: the blocks cl-p2p serves a peer's BeaconBlocksByRange v2
//! request above cl-store's finalized slot from (#146; `phase0/p2p-interface.md` L1485–1575,
//! `gloas/p2p-interface.md` L1356–1374).
//!
//! cl-chain runs no fork choice yet, so the canonical chain is its stamp's: one read
//! transaction of its own env reads the stamp, then walks the parents down from the stamp's head
//! to the range's start ([`store_schema::blocks::walk`], the walker cl-store reads by too). The
//! answer is the blocks of that chain in the range, ascending (skipped slots have none, a block
//! off the head's chain is never served), one `PAYLOAD_TYPE_SIGNED_BEACON_BLOCK` envelope per
//! block: its root, the stored SSZ and the fork digest of its slot's epoch. With no stamp there
//! is nothing to serve: `ERROR_CODE_RESOURCE_UNAVAILABLE`. cl-p2p asks only for slots above
//! cl-store's finalized slot, so the walk is bounded by non-finality (and one write of the
//! store's lag). It shares the column reads' places ([`super::DEFAULT_MAX_READS`]) and stops at
//! [`super::READ_DEADLINE`]. When fork choice lands, the walk becomes its canonical chain.
//!
//! `ReqRespService/BlocksByRoot` ([`unfinalized_blocks`]): the requested blocks cl-p2p serves a
//! peer's BeaconBlocksByRoot v2 request from before it asks cl-store for the rest. Every block
//! stored above the stamp's finalized slot is served, on any branch (an orphan the env still
//! holds included), in request order and each once: a point lookup in `block_index` per root,
//! in one read transaction. A root not stored, or stored at or below the finalized slot, gets
//! nothing: cl-store serves the finalized chain.

use super::{Refusal, MAX_REQUEST_BLOCKS_DENEB};
use cl_chain_columns::{ColumnReader, ColumnWriter};
use ethswarm_proto::common::{Envelope, PayloadType};
use ipc::Link;
use std::ops::ControlFlow;
use std::time::Instant;
use store_schema::env::RoTxn;
use store_schema::keys::Root;

/// The blocks env as the req/resp server reads it: cl-chain's own, the column store's.
pub trait BlockStore: Send + Sync + 'static {
    /// One read transaction of the env.
    ///
    /// # Errors
    ///
    /// The transaction did not begin.
    fn read_txn(&self) -> Result<RoTxn<'_>, String>;
}

impl BlockStore for ColumnWriter {
    fn read_txn(&self) -> Result<RoTxn<'_>, String> {
        self.reader().read_txn().map_err(|e| e.to_string())
    }
}

impl BlockStore for ColumnReader {
    fn read_txn(&self) -> Result<RoTxn<'_>, String> {
        ColumnReader::read_txn(self).map_err(|e| e.to_string())
    }
}

impl From<store_schema::Error> for Refusal {
    fn from(e: store_schema::Error) -> Self {
        Self::Store(e.to_string())
    }
}

/// One block of an answer, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBlock {
    /// Its slot.
    pub slot: u64,
    /// `hash_tree_root(block.message)`.
    pub root: Root,
    /// The `SignedBeaconBlock` SSZ, as stored.
    pub ssz: Vec<u8>,
}

/// How many blocks a walk reads between two looks at its deadline.
const DEADLINE_EVERY: usize = 64;

/// The canonical blocks of `[start, start + count)`, ascending: those on the parent walk down
/// from the stamp's head, read in one transaction, stopping at `deadline`.
///
/// # Errors
///
/// [`Refusal::Invalid`] for a `count` over `MAX_REQUEST_BLOCKS_DENEB`;
/// [`Refusal::Unavailable`] with no stamp; [`Refusal::Store`] for a failed read or one past
/// `deadline`.
pub fn canonical_blocks(
    store: &dyn BlockStore,
    start: u64,
    count: u64,
    deadline: Instant,
) -> Result<Vec<StoredBlock>, Refusal> {
    if count > MAX_REQUEST_BLOCKS_DENEB as u64 {
        return Err(Refusal::Invalid(format!("count {count} is over 128")));
    }
    let late = || Refusal::Store("the block read passed its deadline".into());
    let txn = store.read_txn().map_err(Refusal::Store)?;
    let stamp = store_schema::stamp::read(&txn)?
        .ok_or_else(|| Refusal::Unavailable("nothing is stamped yet".into()))?;
    let end = start
        .saturating_add(count)
        .min(stamp.head_slot.saturating_add(1));
    let (mut blocks, mut walked) = (Vec::new(), 0usize);
    if start < end {
        store_schema::blocks::walk(&txn, stamp.head_root, start, |slot, root, ssz| {
            walked += 1;
            if walked.is_multiple_of(DEADLINE_EVERY) && Instant::now() >= deadline {
                return Err(late());
            }
            if slot < end {
                blocks.push(StoredBlock {
                    slot,
                    root,
                    ssz: ssz.to_vec(),
                });
            }
            Ok(ControlFlow::Continue(()))
        })?;
    }
    if Instant::now() >= deadline {
        return Err(late());
    }
    blocks.reverse();
    Ok(blocks)
}

/// The blocks of `roots` stored above the stamp's finalized slot, in request order, each once,
/// read in one transaction, stopping at `deadline`.
///
/// # Errors
///
/// [`Refusal::Invalid`] for more than `MAX_REQUEST_BLOCKS_DENEB` roots;
/// [`Refusal::Unavailable`] with no stamp; [`Refusal::Store`] for a failed read or one past
/// `deadline`.
pub fn unfinalized_blocks(
    store: &dyn BlockStore,
    roots: &[Root],
    deadline: Instant,
) -> Result<Vec<StoredBlock>, Refusal> {
    if roots.len() > MAX_REQUEST_BLOCKS_DENEB {
        return Err(Refusal::Invalid(format!("{} roots, over 128", roots.len())));
    }
    let txn = store.read_txn().map_err(Refusal::Store)?;
    let stamp = store_schema::stamp::read(&txn)?
        .ok_or_else(|| Refusal::Unavailable("nothing is stamped yet".into()))?;
    let mut blocks: Vec<StoredBlock> = Vec::new();
    for root in roots {
        if blocks.iter().any(|b| b.root == *root) {
            continue;
        }
        if let Some(b) = store_schema::blocks::stored(&txn, root)? {
            if b.slot > stamp.finalized_slot {
                let ssz = b.ssz.into_owned();
                blocks.push(StoredBlock {
                    slot: b.slot,
                    root: *root,
                    ssz,
                });
            }
        }
    }
    if Instant::now() >= deadline {
        return Err(Refusal::Store("the block read passed its deadline".into()));
    }
    Ok(blocks)
}

/// `blocks` as the envelopes of a chain.v1 response, `seq` from 1, each with the digest of its
/// slot's epoch on `link`.
pub(super) fn envelopes(link: &Link, blocks: Vec<StoredBlock>) -> Result<Vec<Envelope>, Refusal> {
    (1u64..)
        .zip(blocks)
        .map(|(seq, b)| {
            let digest = link
                .fork_digest_at_slot(b.slot)
                .ok_or_else(|| Refusal::Store(format!("no fork digest for slot {}", b.slot)))?;
            Ok(Envelope {
                fork_digest: digest.to_vec(),
                slot: b.slot,
                root: b.root.to_vec(),
                ssz: b.ssz,
                payload_type: PayloadType::SignedBeaconBlock as i32,
                trace_id: Vec::new(),
                seq,
            })
        })
        .collect()
}
