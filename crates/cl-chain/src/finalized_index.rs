//! The finalized slot index on reopen ([`store_schema::finalized`]): every stamp that moves the
//! finalized block indexes it in its own transaction, and when cl-chain opens a store an older
//! cl-chain left unindexed (schema version 2) it backfills the index down to the start of the
//! block serve window, in bounded batches ([`backfill`]). cl-store serves ranges from the
//! index's floor up meanwhile, and refuses below it.

use cl_chain_columns::ColumnWriter;
use network_config::{digest::current_epoch, window::block_serve_window};

use crate::probe::ProbeChain;

pub use store_schema::finalized::BACKFILL_BATCH;

/// Backfills the index of `writer`'s store down to `floor`, one write transaction per batch of
/// at most `batch` slots ([`ColumnWriter::index_finalized_batch`]), each with the stamp carried,
/// until none is due: the batches committed. A crash between two loses no committed batch.
///
/// # Errors
///
/// The store's; the batches committed before it stay.
pub fn backfill(writer: &ColumnWriter, floor: u64, batch: u64) -> cl_chain_columns::Result<u64> {
    let mut batches = 0;
    while writer.index_finalized_batch(floor, batch)?.is_some() {
        batches += 1;
    }
    Ok(batches)
}

/// The first slot of the block serve window (`network_config::window`, consensus-specs
/// `MIN_EPOCHS_FOR_BLOCK_REQUESTS`, the Gloas formula from `GLOAS_FORK_EPOCH` on) at `now_ms`
/// (Unix milliseconds) on `chain`; genesis before genesis or for a config without the
/// window's values.
#[must_use]
pub fn window_floor(chain: &ProbeChain, now_ms: u128) -> u64 {
    let (genesis, spe) = (chain.genesis.genesis_time, chain.slots_per_epoch);
    current_epoch(genesis, chain.config.slot_duration_ms(), spe, now_ms)
        .ok()
        .and_then(|epoch| block_serve_window(&chain.config, epoch).ok())
        .map_or(0, |start| start.saturating_mul(spe))
}
