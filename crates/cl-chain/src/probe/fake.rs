//! Test fixtures of the probe: [`Silent`], a reference node in memory, and [`Clock`], a wall
//! clock the test sets.

use super::{ApiError, BlockApi, Checkpoint, Header, ReferenceApi, Root};
use consensus_types::primitives::Slot;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A reference node from a table of blocks: a root it knows is answered at once, any other
/// never, so the reference view's timeout ends its lookup. Counts the header requests.
#[derive(Default)]
pub(crate) struct Silent {
    pub(crate) blocks: Mutex<HashMap<Root, (Slot, Vec<u8>)>>,
    asked: Mutex<Vec<Root>>,
}

impl Silent {
    /// Serves a Gloas block at `slot`; returns its root.
    pub(crate) fn serve(&self, slot: Slot) -> Root {
        let (_, ssz, root) = crate::testing::gloas_block(slot, &[[1; 48]]);
        self.blocks.lock().unwrap().insert(root, (slot, ssz));
        root
    }

    /// Serves a Gloas block at `slot` whose parent is `parent`; returns its root.
    pub(crate) fn serve_on(&self, slot: Slot, parent: Root) -> Root {
        let (_, ssz, root) = crate::testing::gloas_block_on(slot, &[[1; 48]], parent);
        self.blocks.lock().unwrap().insert(root, (slot, ssz));
        root
    }

    /// [`Self::serve_on`], a block of another bid: another root at the same slot and parent.
    pub(crate) fn serve_fork(&self, slot: Slot, parent: Root) -> Root {
        let (_, ssz, root) = crate::testing::gloas_block_on(slot, &[[2; 48]], parent);
        self.blocks.lock().unwrap().insert(root, (slot, ssz));
        root
    }

    /// The header requests for `root` so far.
    pub(crate) fn asked(&self, root: Root) -> usize {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|r| **r == root)
            .count()
    }
}

impl ReferenceApi for Arc<Silent> {
    async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
        Err(ApiError("not used".into()))
    }

    async fn header(&self, root: Root) -> Result<Header, ApiError> {
        self.asked.lock().unwrap().push(root);
        let known = self
            .blocks
            .lock()
            .unwrap()
            .get(&root)
            .map(|(slot, _)| *slot);
        match known {
            Some(slot) => Ok(Header { root, slot }),
            None => std::future::pending().await,
        }
    }
}

impl BlockApi for Arc<Silent> {
    async fn block(&self, root: Root) -> Result<Vec<u8>, ApiError> {
        let known = self
            .blocks
            .lock()
            .unwrap()
            .get(&root)
            .map(|(_, ssz)| ssz.clone());
        match known {
            Some(ssz) => Ok(ssz),
            None => std::future::pending().await,
        }
    }
}

/// A wall clock whose `data_column_serve_range` the test sets: `None` (before Fulu) by
/// default. Every slot has one digest.
#[derive(Debug, Default)]
pub(crate) struct Clock(Mutex<Option<(Slot, Slot)>>);

impl Clock {
    /// A clock whose serve range is `first` to `last`.
    pub(crate) fn at(first: Slot, last: Slot) -> Self {
        Self(Mutex::new(Some((first, last))))
    }

    /// Moves the serve range to `range`.
    pub(crate) fn set(&self, range: Option<(Slot, Slot)>) {
        *self.0.lock().unwrap() = range;
    }
}

impl crate::reqresp::ServeClock for Clock {
    fn serve_range(&self) -> Option<(Slot, Slot)> {
        *self.0.lock().unwrap()
    }

    fn fork_digest(&self, _: Slot) -> Option<[u8; 4]> {
        Some([1, 2, 3, 4])
    }
}
