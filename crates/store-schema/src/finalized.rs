//! The finalized slot index: `finalized_slots` holds, for each slot from the `meta` row
//! [`FINALIZED_INDEX_FROM_KEY`] up to the stamp's finalized slot, the root of the block of the
//! stamp's finalized chain at that slot, if stored; a skipped slot has no row. The from slot is
//! 0 once the index reaches the bottom of the stored chain (genesis, or a block whose parent is
//! not stored: a checkpoint anchor). Only those rows prove anything: below the from slot (a
//! part no backfill has reached yet, or all of it with no row) a reader refuses, never guesses.
//!
//! - [`txn::commit`](crate::txn::commit) writes it with every [`Update::New`] that moves the
//!   finalized block, in the same transaction ([`advance`]): the new finalized block and its
//!   parents down to the one before it. A store's first stamp indexes its chain down to its
//!   bottom: only its own transaction's blocks, since nothing commits before it. A new
//!   finalized block whose chain does not lead to the one before (no writer path does that)
//!   raises the from slot to its own lowest row, so no row of the other chain is trusted.
//! - [`backfill`] lowers the from slot by one bounded batch per write transaction: what the
//!   writer runs after it opens a store the index came after (version 2).
//! - [`indexed_from`], [`root_at`] and [`range`] read it (cl-store): a point lookup, and a range
//!   in one seek and a row per block, at any depth below the finalized slot.
//!
//! [`Update::New`]: crate::txn::Update::New

use std::borrow::Cow;

use libmdbx::WriteFlags;

use crate::{
    blocks,
    keys::{slot_root_key, Root, FINALIZED_INDEX_FROM_KEY},
    stamp::{self, Stamp},
    tables::{BLOCKS, BLOCK_INDEX, FINALIZED_SLOTS, META},
    txn::{ReadTxn, RwTxn},
    Error, Result,
};

/// Slots one [`backfill`] batch covers at most \[est\]: 8,192 (256 epochs of 32), so its write
/// transaction reads and writes at most that many blocks and rows.
pub const BACKFILL_BATCH: u64 = 8_192;

/// The lowest slot the index covers without gaps, up to the stamp's finalized slot; `None`
/// while it covers nothing.
pub fn indexed_from(txn: &impl ReadTxn) -> Result<Option<u64>> {
    let meta = txn.open_table(Some(META))?;
    Ok(txn
        .get::<[u8; 8]>(&meta, FINALIZED_INDEX_FROM_KEY)?
        .map(u64::from_be_bytes))
}

/// The root the index holds at `slot`, `None` for none: proof only from [`indexed_from`] up to
/// the stamp's finalized slot.
pub fn root_at(txn: &impl ReadTxn, slot: u64) -> Result<Option<Root>> {
    let table = txn.open_table(Some(FINALIZED_SLOTS))?;
    Ok(txn.get::<Root>(&table, &slot.to_be_bytes())?)
}

/// The indexed blocks of `start..end`, ascending: `visit` sees each `(slot, root, ssz)`. One
/// seek, then a row and its block per block, however far below the finalized slot `start` is.
/// A row whose block is not stored is [`Error::Corrupt`].
///
/// # Errors
///
/// The env's, as `E`, or `visit`'s.
pub fn range<T: ReadTxn, E: From<Error>>(
    txn: &T,
    start: u64,
    end: u64,
    mut visit: impl FnMut(u64, Root, &[u8]) -> std::result::Result<(), E>,
) -> std::result::Result<(), E> {
    let table = txn.open_table(Some(FINALIZED_SLOTS)).map_err(Error::from)?;
    let blocks = txn.open_table(Some(BLOCKS)).map_err(Error::from)?;
    let mut cursor = txn.cursor(&table).map_err(Error::from)?;
    for row in cursor.iter_from::<[u8; 8], Root>(&start.to_be_bytes()) {
        let (slot, root) = row.map_err(Error::from)?;
        let slot = u64::from_be_bytes(slot);
        if slot >= end {
            break;
        }
        let key = slot_root_key(slot, &root);
        let ssz = txn
            .get::<Cow<'_, [u8]>>(&blocks, &key)
            .map_err(Error::from)?;
        visit(slot, root, &ssz.ok_or(Error::Corrupt { table: BLOCKS })?)?;
    }
    Ok(())
}

/// Indexes `new`'s finalized block in `txn`, `stored` the stamp before it (`None` for a store's
/// first): the block and its parents down to `stored`'s finalized block, whose own row stays
/// (or is written, with no from row yet); else down to the bottom of the stored chain (from
/// slot 0), or to a parent below `stored`'s finalized slot (from the lowest row written).
/// Nothing if the finalized block did not move.
pub(crate) fn advance(txn: &RwTxn<'_>, stored: Option<&Stamp>, new: &Stamp) -> Result<()> {
    let top = (new.finalized_slot, new.finalized_root);
    let old = stored.map(|stamp| (stamp.finalized_slot, stamp.finalized_root));
    if old == Some(top) {
        return Ok(());
    }
    let (lowest, end) = index_down(txn, top, old.map_or(0, |o| o.0), old.map(|o| o.1))?;
    let from = match (end, old, indexed_from(txn)?) {
        (End::Joined, _, Some(from)) => from,
        (End::Joined, Some(old), None) => {
            put(txn, old)?;
            old.0
        }
        (End::Bottom, ..) => bottom(txn, lowest)?,
        _ => lowest,
    };
    set_from(txn, from)
}

/// One batch of the backfill, in `txn`: the index lowered from [`indexed_from`] (from the stamp's
/// finalized block, with no from row) by at most `batch` slots and never below `floor`, any row
/// the batch's slots held before cleared first, and the from row written. The new from slot; or
/// `None` with no batch due: no stamp yet, the from slot at `floor` or below (0 once the bottom
/// of the stored chain is reached), or `batch` 0. Drop `txn` then: it holds no progress.
///
/// # Errors
///
/// The env's; [`Error::Corrupt`] for a from row with no row at or above it.
pub fn backfill(txn: &RwTxn<'_>, floor: u64, batch: u64) -> Result<Option<u64>> {
    let Some(stamp) = stamp::read(txn)?.filter(|_| batch > 0) else {
        return Ok(None);
    };
    let from = indexed_from(txn)?;
    let (top, high) = match from {
        None => {
            let top = (stamp.finalized_slot, stamp.finalized_root);
            (top, top.0.saturating_add(1))
        }
        Some(from) if from <= floor => return Ok(None),
        Some(from) => {
            let table = txn.open_table(Some(FINALIZED_SLOTS))?;
            let at = txn
                .cursor(&table)?
                .set_range::<[u8; 8], Root>(&from.to_be_bytes())?;
            let at = at.ok_or(Error::Corrupt {
                table: FINALIZED_SLOTS,
            })?;
            ((u64::from_be_bytes(at.0), at.1), from)
        }
    };
    let low = high.saturating_sub(batch).max(floor).min(top.0);
    clear(txn, low, high)?;
    let (lowest, end) = index_down(txn, top, low, None)?;
    let new = match end {
        End::Below => low,
        End::Joined | End::Bottom => bottom(txn, lowest)?,
    };
    if from.is_some_and(|from| new >= from) {
        return Ok(None);
    }
    set_from(txn, new)?;
    Ok(Some(new))
}

/// Why [`index_down`] stopped.
enum End {
    /// The next parent is the one it was to stop at.
    Joined,
    /// The next parent is below the lowest slot it was to index.
    Below,
    /// There is no next parent: slot 0, or a parent that is not stored.
    Bottom,
}

/// Writes the rows of `top` and its parents, while stored, down to `low`, and stops before the
/// parent `stop`: the lowest slot written and why it stopped. A parent at or above its child's
/// slot is [`Error::Corrupt`].
fn index_down(
    txn: &RwTxn<'_>,
    top: (u64, Root),
    low: u64,
    stop: Option<Root>,
) -> Result<(u64, End)> {
    let index = txn.open_table(Some(BLOCK_INDEX))?;
    let (mut slot, mut root) = top;
    loop {
        put(txn, (slot, root))?;
        if slot == 0 {
            return Ok((slot, End::Bottom));
        }
        let Some(block) = blocks::stored(txn, &root)? else {
            return Ok((slot, End::Bottom));
        };
        let parent = block.parent;
        if stop == Some(parent) {
            return Ok((slot, End::Joined));
        }
        let Some(at) = txn.get::<[u8; 8]>(&index, &parent)?.map(u64::from_be_bytes) else {
            return Ok((slot, End::Bottom));
        };
        if at >= slot {
            return Err(Error::Corrupt { table: BLOCKS });
        }
        if at < low {
            return Ok((slot, End::Below));
        }
        (slot, root) = (at, parent);
    }
}

/// The from slot at the bottom of the stored chain, `lowest` its lowest row: 0, every row below
/// `lowest` cleared (none of them is of this chain).
fn bottom(txn: &RwTxn<'_>, lowest: u64) -> Result<u64> {
    clear(txn, 0, lowest)?;
    Ok(0)
}

/// Deletes the rows of `low..high`.
fn clear(txn: &RwTxn<'_>, low: u64, high: u64) -> Result<()> {
    let table = txn.open_table(Some(FINALIZED_SLOTS))?;
    let mut stale = Vec::new();
    for row in txn
        .cursor(&table)?
        .iter_from::<[u8; 8], ()>(&low.to_be_bytes())
    {
        let (slot, ()) = row?;
        if u64::from_be_bytes(slot) >= high {
            break;
        }
        stale.push(slot);
    }
    for slot in stale {
        txn.del(&table, slot, None)?;
    }
    Ok(())
}

fn put(txn: &RwTxn<'_>, (slot, root): (u64, Root)) -> Result<()> {
    let table = txn.open_table(Some(FINALIZED_SLOTS))?;
    txn.put(&table, slot.to_be_bytes(), root, WriteFlags::UPSERT)?;
    Ok(())
}

fn set_from(txn: &RwTxn<'_>, from: u64) -> Result<()> {
    let meta = txn.open_table(Some(META))?;
    let row = from.to_be_bytes();
    txn.put(&meta, FINALIZED_INDEX_FROM_KEY, row, WriteFlags::UPSERT)?;
    Ok(())
}
