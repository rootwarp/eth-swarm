//! Finalized block ranges: the blocks of a slot range at or below the stamp's finalized slot,
//! in one read transaction with its stamp, under the call's deadline.
//!
//! The blocks are the stamp's finalized chain, read by walking the parents down from its
//! finalized block: a fork block the writer still holds at a finalized slot is never served.
//! The walk costs one block per stored block between the finalized block and the range, so a
//! range far below finality can run into the deadline.

use std::ops::ControlFlow;

use crate::reader::{Block, Deadline, ReadError, Reader, Stamped};

impl Reader {
    /// The canonical blocks with a slot in `start..start + count` and at or below the stamp's
    /// finalized slot, ascending; skipped slots have none.
    ///
    /// # Errors
    ///
    /// [`ReadError`].
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
                snap.walk(stamp.finalized_root, start, |slot, root, ssz| {
                    if slot < end {
                        blocks.push(Block {
                            slot,
                            root,
                            ssz: ssz.to_vec(),
                            finalized: true,
                        });
                    }
                    ControlFlow::Continue(())
                })?;
            }
            blocks.reverse();
            Ok(blocks)
        })
    }
}
