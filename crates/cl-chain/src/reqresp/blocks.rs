//! `ReqRespService/BlocksByRange`: the canonical blocks of a slot range, read from cl-chain's
//! own env (#146).

use super::Refusal;
use cl_chain_columns::{ColumnReader, ColumnWriter};
use std::time::Instant;
use store_schema::env::RoTxn;
use store_schema::keys::Root;

/// The blocks env as the req/resp server reads it.
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
        todo!("#146 step 4")
    }
}

impl BlockStore for ColumnReader {
    fn read_txn(&self) -> Result<RoTxn<'_>, String> {
        todo!("#146 step 4")
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

/// The canonical blocks of `[start, start + count)`, ascending, read in one transaction.
///
/// # Errors
///
/// [`Refusal`].
pub fn canonical_blocks(
    _store: &dyn BlockStore,
    _start: u64,
    _count: u64,
    _deadline: Instant,
) -> Result<Vec<StoredBlock>, Refusal> {
    todo!("#146 step 4")
}
