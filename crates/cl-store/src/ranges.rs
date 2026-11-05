//! Finalized block ranges: the blocks of a slot range at or below the stamp's finalized slot,
//! in one read transaction with its stamp, under the call's deadline.
//!
//! The blocks are the stamp's finalized chain, found in the finalized slot index that cl-chain
//! writes with the stamp that finalizes them ([`store_schema::finalized`]): a fork block the
//! writer still holds at a finalized slot is never served. A range costs one seek and a row per
//! block, at any depth below the finalized slot. One that starts below the index's floor (what
//! cl-chain's backfill has not reached yet) is [`ReadError::Unavailable`], unread.

use crate::reader::{Block, Deadline, ReadError, Reader, Stamped};

impl Reader {
    /// The canonical blocks with a slot in `start..start + count` and at or below the stamp's
    /// finalized slot, ascending; skipped slots have none.
    ///
    /// # Errors
    ///
    /// [`ReadError`]: [`ReadError::Unavailable`] too for a range that starts below the floor of
    /// the finalized slot index, before any block is read.
    pub fn finalized_blocks(
        &self,
        start: u64,
        count: u64,
        deadline: &Deadline,
    ) -> Result<Stamped<Vec<Block>>, ReadError> {
        self.read(deadline, |snap, stamp| {
            let end = start
                .saturating_add(count)
                .min(stamp.finalized_slot.saturating_add(1));
            let mut blocks = Vec::new();
            if start < end {
                if !snap.indexed(start)? {
                    return Err(ReadError::Unavailable);
                }
                snap.finalized_range(start, end, |slot, root, ssz| {
                    blocks.push(Block {
                        slot,
                        root,
                        ssz: ssz.to_vec(),
                        finalized: true,
                    });
                })?;
            }
            Ok(blocks)
        })
    }
}

#[cfg(test)]
#[path = "ranges_tests.rs"]
mod tests;
