//! Test fixtures of the probe: [`Silent`], a reference node in memory.

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
