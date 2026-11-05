//! Finalized block ranges: the blocks of a slot range at or below the stamp's finalized slot,
//! in one read transaction with its stamp, under the call's deadline.
//!
//! The blocks are the stamp's finalized chain, found in the finalized slot index that cl-chain
//! writes with the stamp that finalizes them ([`store_schema::finalized`]): a fork block the
//! writer still holds at a finalized slot is never served. A range costs one seek and a row per
//! block, at any depth below the finalized slot. One that starts below the index's floor (what
//! cl-chain's backfill has not reached yet) is [`ReadError::Unavailable`], unread.
//!
//! By root ([`Reader::blocks_by_root`], `GetBlocksByRoot`): a point lookup per root in
//! `block_index` and one in the index, in one read transaction; only a finalized block is
//! served.

use crate::reader::{Block, Deadline, ReadError, Reader, Root, Stamped};

/// What the store holds at one requested root ([`Reader::blocks_by_root`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtRoot {
    /// The block, finalized by the stamp.
    Finalized(Block),
    /// A block above the stamp's finalized slot: not served.
    Unfinalized,
    /// No block, or one off the finalized chain at or below the finalized slot.
    Missing,
}

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

    /// What the stamp's snapshot holds at each of `roots`, in order: a block at or below the
    /// stamp's finalized slot is served only if it is the index's block at its slot (below the
    /// index's floor: not proven, [`AtRoot::Missing`]).
    ///
    /// # Errors
    ///
    /// [`ReadError`].
    pub fn blocks_by_root(
        &self,
        roots: &[Root],
        deadline: &Deadline,
    ) -> Result<Stamped<Vec<AtRoot>>, ReadError> {
        self.read(deadline, |snap, stamp| {
            roots
                .iter()
                .map(|root| {
                    snap.step()?;
                    let Some(stored) = snap.stored(root)? else {
                        return Ok(AtRoot::Missing);
                    };
                    if stored.slot > stamp.finalized_slot {
                        return Ok(AtRoot::Unfinalized);
                    }
                    if !snap.finalized(stamp, stored.slot, *root)? {
                        return Ok(AtRoot::Missing);
                    }
                    Ok(AtRoot::Finalized(Block {
                        slot: stored.slot,
                        root: *root,
                        ssz: stored.ssz.into_owned(),
                        finalized: true,
                    }))
                })
                .collect()
        })
    }
}

#[cfg(test)]
#[path = "ranges_tests.rs"]
mod tests;
