//! Finalized block ranges: the blocks of a slot range at or below the stamp's finalized slot,
//! in one read transaction with its stamp, under the call's deadline.
//!
//! The blocks are the stamp's finalized chain, read by walking the parents down from its
//! finalized block: a fork block the writer still holds at a finalized slot is never served.
//! The walk costs one block per stored block between the finalized block and the range, so a
//! range is served only from at most [`MAX_FINALIZED_DEPTH`] slots below the finalized slot.

use std::ops::ControlFlow;

use crate::reader::{Block, Deadline, ReadError, Reader, Stamped};

/// How far below the stamp's finalized slot a range may start \[est\]: 2,048 slots (64 epochs
/// of 32 slots, about 6.8 hours). The walk down from the finalized block reads one stored block
/// per slot between it and the range, whatever `count` is, so a one-block range deep in history
/// would walk all of it. A range that starts deeper is [`ReadError::Unavailable`] before any
/// block is read, so a read walks at most this many blocks above its range: bounded work per
/// request until a finalized slot index (slot to root) lands, which reaches any depth in one
/// lookup. cl-p2p refuses the same depth before it asks
/// (`cl_p2p::rpc::blocks::MAX_FINALIZED_DEPTH`).
pub const MAX_FINALIZED_DEPTH: u64 = 2_048;

impl Reader {
    /// The canonical blocks with a slot in `start..start + count` and at or below the stamp's
    /// finalized slot, ascending; skipped slots have none.
    ///
    /// # Errors
    ///
    /// [`ReadError`]: [`ReadError::Unavailable`] too for a range that starts more than
    /// [`MAX_FINALIZED_DEPTH`] below the stamp's finalized slot, before any block is read.
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
                if start < stamp.finalized_slot.saturating_sub(MAX_FINALIZED_DEPTH) {
                    return Err(ReadError::Unavailable);
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{block, deadline, stamp, Store};

    /// Cole B1, Vera N1: a range is read by walking down from the finalized block, one block per
    /// slot walked, whatever `count` is. One that starts more than [`MAX_FINALIZED_DEPTH`] below
    /// the finalized slot is `Unavailable` before any block is read, even when its end reaches
    /// into what is served (never a part of it); one that starts at that depth is served.
    #[test]
    fn deep_range_unavailable() {
        let store = Store::new();
        let finalized = MAX_FINALIZED_DEPTH + 10;
        let edge = finalized - MAX_FINALIZED_DEPTH;
        let (mut blocks, mut parent) = (Vec::new(), [0; 32]);
        for slot in [1, edge - 1, edge, edge + 1, finalized] {
            let (ssz, root) = block(slot, parent, 0);
            blocks.push(ssz);
            parent = root;
        }
        let at = (finalized, parent);
        store.import(
            &blocks.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            stamp(1, at, at),
        );
        let reader = store.reader();
        let dl = deadline();
        let slots = |start, count| {
            reader
                .finalized_blocks(start, count, &dl)
                .map(|read| read.value.iter().map(|b| b.slot).collect::<Vec<_>>())
        };
        assert_eq!(slots(edge, 1), Ok(vec![edge]), "at the cap");
        assert_eq!(slots(edge, 128), Ok(vec![edge, edge + 1]));
        assert_eq!(slots(finalized, 1), Ok(vec![finalized]));
        assert_eq!(
            slots(edge - 1, 1),
            Err(ReadError::Unavailable),
            "one past it"
        );
        assert_eq!(slots(1, 128), Err(ReadError::Unavailable), "never a part");
    }
}
