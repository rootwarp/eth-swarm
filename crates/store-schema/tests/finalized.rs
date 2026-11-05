//! The finalized slot index: `finalized_slots` (slot to the root of the stamp's finalized chain
//! there) and the `meta` row `finalized_index_from` (the lowest slot it covers without gaps, up
//! to the finalized slot). The writer writes it in the transaction that moves the stamp's
//! finalized block ([`txn::commit`]), and backfills it downward in bounded batches on reopen
//! ([`finalized::backfill`]), each batch its own stamped commit.

mod common;

use std::collections::BTreeMap;

use libmdbx::WriteFlags;
use store_schema::{
    env::{self, WriterEnv, WriterOptions, MIN_MAX_SIZE},
    finalized,
    keys::{Root, FINALIZED_INDEX_FROM_KEY, SCHEMA_VERSION_KEY},
    stamp::{self, Stamp},
    tables::{FINALIZED_SLOTS, META},
    txn::{self, Update},
    version::SCHEMA_VERSION,
    Error,
};

fn opts() -> WriterOptions {
    WriterOptions {
        max_size: MIN_MAX_SIZE,
    }
}

/// A block as the tests hold it: slot, root, SSZ.
type Block = (u64, Root, Vec<u8>);

/// Blocks at `slots`, each on the one before, the first on `parent`.
fn chain(parent: Root, slots: impl IntoIterator<Item = u64>, salt: u64) -> Vec<Block> {
    let mut parent = parent;
    slots
        .into_iter()
        .map(|slot| {
            let (ssz, root) = common::fulu_block_ssz(slot, parent, salt);
            parent = root;
            (slot, root, ssz)
        })
        .collect()
}

/// Slots 1 to 40 but 5, 12 and 17.
fn canonical() -> Vec<Block> {
    chain([0; 32], (1..=40).filter(|s| ![5, 12, 17].contains(s)), 0)
}

fn at(blocks: &[Block], slot: u64) -> (u64, Root) {
    let (slot, root, _) = blocks.iter().find(|b| b.0 == slot).unwrap();
    (*slot, *root)
}

fn stamp(seq: u64, head: (u64, Root), finalized: (u64, Root)) -> Stamp {
    Stamp {
        head_seq: seq,
        head_root: head.1,
        head_slot: head.0,
        finalized_root: finalized.1,
        finalized_slot: finalized.0,
    }
}

/// `blocks` and `stamp` in one write transaction, through the stamped commit.
fn import(writer: &WriterEnv, blocks: &[Block], stamp: Stamp) -> store_schema::Result<()> {
    let txn = txn::begin(writer)?;
    for (_, _, ssz) in blocks {
        store_schema::blocks::put::<common::E>(&txn, &common::schedule(), ssz)?;
    }
    txn::commit(txn, Update::New(stamp)).map(drop)
}

/// The index as a read transaction sees it: its rows, slot to root, and its from row.
fn index(writer: &WriterEnv) -> (BTreeMap<u64, Root>, Option<u64>) {
    let txn = writer.begin_ro_txn().unwrap();
    let table = txn.open_table(Some(FINALIZED_SLOTS)).unwrap();
    let rows = txn
        .cursor(&table)
        .unwrap()
        .iter::<[u8; 8], [u8; 32]>()
        .map(|row| {
            let (slot, root) = row.unwrap();
            (u64::from_be_bytes(slot), root)
        })
        .collect();
    let from = finalized::indexed_from(&txn).unwrap();
    (rows, from)
}

/// The rows the index must hold: `blocks` with a slot in `from..=to`.
fn want(blocks: &[Block], from: u64, to: u64) -> BTreeMap<u64, Root> {
    blocks
        .iter()
        .filter(|b| (from..=to).contains(&b.0))
        .map(|b| (b.0, b.1))
        .collect()
}

fn stored_stamp(writer: &WriterEnv) -> Option<Stamp> {
    stamp::read(&writer.begin_ro_txn().unwrap()).unwrap()
}

/// The index moves with the stamp's finalized block, in the same transaction: the first stamp
/// indexes the chain below its finalized block down to its bottom (from 0), each later one
/// the blocks from the finalized block before it up, never a fork block, never above the
/// finalized slot. A commit that carries the stamp, or is refused, changes nothing; so does a
/// transaction dropped before its commit.
#[test]
fn the_index_moves_with_the_finalized_stamp() {
    let dir = tempfile::tempdir().unwrap();
    let writer = env::open_writer(dir.path(), opts()).unwrap();
    assert_eq!(
        index(&writer),
        (BTreeMap::new(), None),
        "nothing before a stamp"
    );
    let blocks = canonical();
    // A fork block at 8, on the block at 7.
    let fork = chain(at(&blocks, 7).1, [8], 9);
    let all: Vec<Block> = blocks.iter().chain(&fork).cloned().collect();
    import(&writer, &all, stamp(1, at(&blocks, 20), at(&blocks, 10))).unwrap();
    assert_eq!(index(&writer), (want(&blocks, 1, 10), Some(0)));

    let read = |slot| finalized::root_at(&writer.begin_ro_txn().unwrap(), slot).unwrap();
    assert_eq!(
        read(8),
        Some(at(&blocks, 8).1),
        "the canonical block, not the fork's"
    );
    assert_eq!(read(5), None, "a skipped slot");
    assert_eq!(read(11), None, "above the finalized slot");

    // Carried: nothing moves.
    txn::commit(txn::begin(&writer).unwrap(), Update::Carry).unwrap();
    assert_eq!(index(&writer), (want(&blocks, 1, 10), Some(0)));

    // Dropped before its commit, and refused at it: nothing is written.
    let txn = txn::begin(&writer).unwrap();
    let missing = stamp(2, at(&blocks, 40), (30, [0xee; 32]));
    let err = txn::commit(txn, Update::New(missing)).unwrap_err();
    assert!(matches!(err, Error::StampBlockMissing { .. }), "{err:?}");
    let txn = txn::begin(&writer).unwrap();
    let table = txn.open_table(Some(FINALIZED_SLOTS)).unwrap();
    txn.put(&table, 30u64.to_be_bytes(), [0xee; 32], WriteFlags::UPSERT)
        .unwrap();
    drop(txn);
    assert_eq!(index(&writer), (want(&blocks, 1, 10), Some(0)));

    // Finality moves to 30 (12 and 17 skipped): the rows from 11 up, in that commit.
    import(&writer, &[], stamp(2, at(&blocks, 40), at(&blocks, 30))).unwrap();
    assert_eq!(index(&writer), (want(&blocks, 1, 30), Some(0)));
    assert_eq!(
        stored_stamp(&writer),
        Some(stamp(2, at(&blocks, 40), at(&blocks, 30)))
    );
    // A new head alone moves nothing.
    import(&writer, &[], stamp(3, at(&blocks, 39), at(&blocks, 30))).unwrap();
    assert_eq!(index(&writer), (want(&blocks, 1, 30), Some(0)));
}

/// A first stamp whose chain does not reach genesis (a checkpoint anchor) indexes down to its
/// lowest stored block: the bottom, from 0 (nothing below is stored). A finalized block whose chain does not lead to the one before it (no
/// writer path does that) restarts the index at its own lowest row, so a reader never trusts a
/// row of the other chain.
#[test]
fn the_index_starts_at_the_lowest_stored_block() {
    let dir = tempfile::tempdir().unwrap();
    let writer = env::open_writer(dir.path(), opts()).unwrap();
    let blocks = chain([0x77; 32], 100..=110, 0);
    import(
        &writer,
        &blocks,
        stamp(1, at(&blocks, 110), at(&blocks, 104)),
    )
    .unwrap();
    assert_eq!(index(&writer), (want(&blocks, 100, 104), Some(0)));

    // 107' and 108' on 103, around the finalized block at 104.
    let other = chain(at(&blocks, 103).1, [107, 108], 5);
    let s = stamp(2, at(&other, 108), at(&other, 108));
    import(&writer, &other, s).unwrap();
    let (rows, from) = index(&writer);
    assert_eq!(from, Some(107));
    let above: BTreeMap<u64, Root> = rows.range(107..).map(|(s, r)| (*s, *r)).collect();
    assert_eq!(above, want(&other, 107, 108));
}

/// Turns the env at `path` into the version-2 layout this index came with: no
/// `finalized_slots` table, no from row, version 2. Raw, as no writer path may.
fn downgrade_to_v2(writer: WriterEnv) {
    let db = writer.raw_env();
    let txn = db.begin_rw_txn().unwrap();
    let table = txn.open_table(Some(FINALIZED_SLOTS)).unwrap();
    // SAFETY: the table handle is not used after the drop, and no other handle is open.
    unsafe { txn.drop_table(table).unwrap() };
    let meta = txn.open_table(Some(META)).unwrap();
    txn.del(&meta, FINALIZED_INDEX_FROM_KEY, None).unwrap();
    txn.put(
        &meta,
        SCHEMA_VERSION_KEY,
        2u64.to_be_bytes(),
        WriteFlags::UPSERT,
    )
    .unwrap();
    txn.commit().unwrap();
}

/// A version-2 env holding [`canonical`], head 40, finalized 30.
fn v2_env(path: &std::path::Path) -> Vec<Block> {
    let writer = env::open_writer(path, opts()).unwrap();
    let blocks = canonical();
    import(&writer, &blocks, stamp(4, at(&blocks, 40), at(&blocks, 30))).unwrap();
    downgrade_to_v2(writer);
    blocks
}

/// One backfill batch in its own write transaction, committed with the stamp carried; `None`
/// (nothing committed) once there is nothing left to index.
fn batch(writer: &WriterEnv, floor: u64, slots: u64) -> Option<u64> {
    let txn = txn::begin(writer).unwrap();
    let from = finalized::backfill(&txn, floor, slots).unwrap()?;
    txn::commit(txn, Update::Carry).unwrap();
    Some(from)
}

/// Upgrading a version-2 env creates the empty table and writes version 3, nothing else; a
/// reader waits for that. Backfill then indexes it down from the finalized block, at most
/// `slots` slots per batch, each batch its own commit with the stamp carried unchanged, and
/// stops at the bottom of the stored chain (from 0).
#[test]
fn backfill_on_reopen_of_a_v2_env() {
    let dir = tempfile::tempdir().unwrap();
    let blocks = v2_env(dir.path());
    let err = env::open_reader(dir.path()).unwrap_err();
    assert!(matches!(err, Error::NeedsUpgrade { found: 2 }), "{err:?}");

    let mut created = Vec::new();
    let writer = env::open_writer_with(dir.path(), opts(), |_, new: &[&'static str]| {
        created = new.to_vec();
        Ok::<_, Error>(())
    })
    .unwrap();
    assert_eq!(SCHEMA_VERSION, 3);
    assert_eq!(created, [FINALIZED_SLOTS]);
    assert_eq!(
        index(&writer),
        (BTreeMap::new(), None),
        "nothing indexed yet"
    );
    let stamped = stored_stamp(&writer).unwrap();
    assert_eq!(stamped, stamp(4, at(&blocks, 40), at(&blocks, 30)));

    let mut froms = Vec::new();
    while let Some(from) = batch(&writer, 0, 8) {
        froms.push(from);
        let (rows, indexed) = index(&writer);
        assert_eq!((&rows, indexed), (&want(&blocks, from, 30), Some(from)));
        assert_eq!(stored_stamp(&writer), Some(stamped), "carried");
    }
    assert_eq!(froms, [23, 15, 7, 0]);
    assert_eq!(index(&writer), (want(&blocks, 0, 30), Some(0)));
    drop(writer);
    env::open_reader(dir.path()).expect("a v3 env opens");
}

/// A crash between batches loses nothing committed and writes nothing uncommitted: the next
/// open goes on from the last committed batch and ends where an uninterrupted run ends.
#[test]
fn backfill_resumes_after_a_crash_between_batches() {
    let dir = tempfile::tempdir().unwrap();
    let blocks = v2_env(dir.path());
    {
        let writer = env::open_writer(dir.path(), opts()).unwrap();
        assert_eq!(batch(&writer, 0, 8), Some(23));
        // The next batch dies before its commit.
        let txn = txn::begin(&writer).unwrap();
        assert_eq!(finalized::backfill(&txn, 0, 8).unwrap(), Some(15));
        drop(txn);
        assert_eq!(index(&writer), (want(&blocks, 23, 30), Some(23)));
    }
    let writer = env::open_writer(dir.path(), opts()).unwrap();
    assert_eq!(index(&writer), (want(&blocks, 23, 30), Some(23)));
    let froms: Vec<u64> = std::iter::from_fn(|| batch(&writer, 0, 8)).collect();
    assert_eq!(froms, [15, 7, 0]);
    assert_eq!(index(&writer), (want(&blocks, 0, 30), Some(0)));
}

/// Backfill stops at the floor it is given (the block serve window's start): the index covers
/// the floor and up, nothing below it; and finality moving meanwhile keeps both ends.
#[test]
fn backfill_stops_at_the_floor() {
    let dir = tempfile::tempdir().unwrap();
    let blocks = v2_env(dir.path());
    let writer = env::open_writer(dir.path(), opts()).unwrap();
    assert_eq!(batch(&writer, 12, 8), Some(23));
    // Finality moves between two batches.
    import(&writer, &[], stamp(5, at(&blocks, 40), at(&blocks, 36))).unwrap();
    assert_eq!(index(&writer), (want(&blocks, 23, 36), Some(23)));
    let froms: Vec<u64> = std::iter::from_fn(|| batch(&writer, 12, 8)).collect();
    assert_eq!(froms, [15, 12]);
    assert_eq!(index(&writer), (want(&blocks, 12, 36), Some(12)));
    assert_eq!(
        batch(&writer, 0, 0),
        None,
        "a batch of no slot writes nothing"
    );
}

/// Before the first stamp there is nothing to index: backfill writes nothing.
#[test]
fn no_backfill_before_the_first_stamp() {
    let dir = tempfile::tempdir().unwrap();
    let writer = env::open_writer(dir.path(), opts()).unwrap();
    let txn = txn::begin(&writer).unwrap();
    assert_eq!(finalized::backfill(&txn, 0, 8).unwrap(), None);
}
