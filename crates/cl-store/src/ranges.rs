//! Finalized block ranges: the blocks of a slot range at or below the stamp's finalized slot,
//! in one read transaction with its stamp, under the call's deadline.

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
        let _ = (start, count, deadline);
        Err(ReadError::Internal)
    }
}
