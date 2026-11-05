//! Finalized ranges and the parent walk's `finalized` flag over the finalized slot index: any
//! depth below the finalized slot in one seek, refused below the index's floor.

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use store_schema::{tables::META, txn::seed_unstamped};

use crate::{
    reader::{Clock, Deadline, ParentWalk, Root},
    testkit::{block, deadline, stamp, Store},
    BlockRef, ReadError, Reader,
};

/// The `meta` row of the lowest slot the index covers without gaps.
const INDEX_FROM: &[u8] = b"finalized_index_from";

/// Blocks at `slots`, each on the one before, the first on `parent`: their SSZ and roots.
fn chain(parent: Root, slots: &[u64], salt: u64) -> Vec<(u64, Root, Vec<u8>)> {
    let mut parent = parent;
    slots
        .iter()
        .map(|&slot| {
            let (ssz, root) = block(slot, parent, salt);
            parent = root;
            (slot, root, ssz)
        })
        .collect()
}

/// `blocks`, the last one head and finalized, in one stamped import.
fn import(store: &Store, blocks: &[(u64, Root, Vec<u8>)]) {
    let ssz: Vec<&[u8]> = blocks.iter().map(|b| b.2.as_slice()).collect();
    let (slot, root, _) = blocks.last().unwrap();
    store.import(&ssz, stamp(1, (*slot, *root), (*slot, *root)));
}

/// The index's floor raised to `slot`, as a backfill still under way leaves it: the row alone,
/// committed raw (the stamp is unchanged).
fn index_from(store: &Store, slot: u64) {
    seed_unstamped(
        store.writer(),
        META,
        &[(INDEX_FROM, &slot.to_be_bytes()[..])],
    )
    .unwrap();
}

fn slots(reader: &Reader, start: u64, count: u64) -> Result<Vec<u64>, ReadError> {
    let read = reader.finalized_blocks(start, count, &deadline())?;
    Ok(read.value.iter().map(|b| b.slot).collect())
}

const F: u64 = 100_000;

/// Cole B1, Vera N1: a range is found in the finalized slot index, at any depth below the
/// finalized slot: a one-block range 99,999 slots down is served (the 2,048-slot cap is gone).
/// One that starts below the index's floor (the part a backfill has not reached yet) is
/// `Unavailable` before any block is read, even when its end reaches into what is served
/// (never a part of it); one that starts at the floor is served.
#[test]
fn deep_range_unavailable() {
    let store = Store::new();
    let blocks = chain([0; 32], &[1, 2, 3, 100, 101, 102, F], 0);
    import(&store, &blocks);
    let reader = store.reader();
    assert_eq!(slots(&reader, 1, 1), Ok(vec![1]), "99,999 slots down");
    assert_eq!(slots(&reader, 1, 50), Ok(vec![1, 2, 3]));
    assert_eq!(slots(&reader, 1, 128), Ok(vec![1, 2, 3, 100, 101, 102]));
    assert_eq!(slots(&reader, 99, 4), Ok(vec![100, 101, 102]));
    assert_eq!(slots(&reader, F, 1), Ok(vec![F]));
    assert_eq!(
        slots(&reader, F + 1, 1),
        Ok(vec![]),
        "above the finalized slot"
    );

    index_from(&store, 100);
    assert_eq!(slots(&reader, 100, 1), Ok(vec![100]), "at the floor");
    assert_eq!(
        slots(&reader, 99, 2),
        Err(ReadError::Unavailable),
        "one below"
    );
    assert_eq!(
        slots(&reader, 1, 128),
        Err(ReadError::Unavailable),
        "never a part"
    );
}

/// The work of a range read is the same at any depth: the rows (an index row and its block
/// each) touched by a 4-block range at 10, 10,000 and 999,990 slots below the finalized slot
/// are its 4 rows, though 1,000 and 2,000 stored blocks lie between the finalized block and the
/// two deeper ranges. One seek, then `count` rows at most: no walk.
#[test]
fn range_work_is_flat_across_depth() {
    const TOP: u64 = 1_000_100;
    let starts = [TOP - 10, TOP - 10_000, TOP - 999_990];
    let mut slots_of: Vec<u64> = Vec::new();
    for start in [starts[2], 500_000, starts[1], 995_000, starts[0]] {
        let n = if start % 1_000 == 0 { 1_000 } else { 4 };
        slots_of.extend(start..start + n);
    }
    slots_of.push(TOP);
    let store = Store::new();
    let blocks = chain([0; 32], &slots_of, 0);
    import(&store, &blocks);
    let reader = store.reader();
    let above = |start: u64| blocks.iter().filter(|b| b.0 > start + 3).count();
    assert_eq!(starts.map(above), [1, 1_005, 2_009]);

    let work: Vec<usize> = starts
        .iter()
        .map(|&start| {
            let before = reader.touched.load(Ordering::SeqCst);
            let read = reader.finalized_blocks(start, 4, &deadline()).unwrap();
            let got: Vec<u64> = read.value.iter().map(|b| b.slot).collect();
            assert_eq!(got, (start..start + 4).collect::<Vec<_>>());
            reader.touched.load(Ordering::SeqCst) - before
        })
        .collect();
    assert_eq!(work, [4, 4, 4], "rows touched at depth 10, 10,000, 999,990");
}

/// D3a: a parent walk's `finalized` is a point lookup in the index, at any depth: a
/// canonical block 99,998 slots below the finalized slot reads `true`, its sibling at the same
/// slot `false` (and so do the blocks below it), each after a few looks at the clock (no walk).
/// A block below the index's floor reads `false`: not proven, never a false `true`.
#[test]
fn blocks_by_head_deep_canonical_and_sibling() {
    let store = Store::new();
    let blocks = chain([0; 32], &[1, 2, 3, F], 0);
    let sibling = chain(blocks[0].1, &[2], 7);
    let all: Vec<_> = sibling.iter().chain(&blocks).cloned().collect();
    import(&store, &all);
    let reader = Arc::new(store.reader());
    let looks = Arc::new(AtomicUsize::new(0));
    let clock: Clock = {
        let (looks, t0) = (Arc::clone(&looks), Instant::now());
        Arc::new(move || {
            looks.fetch_add(1, Ordering::SeqCst);
            t0
        })
    };
    let walk = |root: Root| {
        looks.store(0, Ordering::SeqCst);
        let deadline = Deadline::after(Arc::clone(&clock), Duration::from_secs(600));
        let read: Vec<(u64, bool)> = ParentWalk::new(Arc::clone(&reader), root, 3, deadline)
            .map(|b| b.map(|b| (b.value.slot, b.value.finalized)))
            .collect::<Result<_, _>>()
            .unwrap();
        (read, looks.load(Ordering::SeqCst))
    };
    let (read, canonical_looks) = walk(blocks[2].1);
    assert_eq!(read, [(3, true), (2, true), (1, true)]);
    let (read, sibling_looks) = walk(sibling[0].1);
    assert_eq!(read, [(2, false), (1, false)], "off the finalized chain");
    assert!(
        canonical_looks <= 7 && sibling_looks <= 7,
        "{canonical_looks}, {sibling_looks} looks: no walk to the finalized block"
    );
    let by_root = |root| {
        let read = reader.block(BlockRef::Root(root), &deadline()).unwrap();
        read.value.finalized
    };
    assert!(by_root(blocks[1].1));
    assert!(!by_root(sibling[0].1));
    let at_2 = reader.block(BlockRef::Slot(2), &deadline()).unwrap();
    assert_eq!(at_2.value.root, blocks[1].1);

    index_from(&store, 3);
    let (read, _) = walk(blocks[1].1);
    assert_eq!(
        read,
        [(2, false), (1, false)],
        "below the floor: not proven"
    );
    let (read, _) = walk(blocks[2].1);
    assert_eq!(
        read,
        [(3, true), (2, true), (1, true)],
        "decided once, at 3"
    );
}

/// `GetBlocksByRoot`'s read: in one transaction under one stamp (head 14, finalized 11), a
/// point lookup per root, in request order. A finalized root is served as stored, the
/// finalized slot's own included; a root not stored is missing; a block above the finalized
/// slot is held but not served, the head's and a fork's alike; a fork block at or below the
/// finalized slot is missing, never served, and so is a finalized block below the index's
/// floor (not proven). A read past its deadline serves nothing.
#[test]
fn blocks_by_root_finalized_only() {
    use crate::ranges::AtRoot;
    let store = Store::new();
    let main = chain([0; 32], &[10, 11, 12, 14], 0);
    let fork = chain(main[0].1, &[11, 13], 9);
    let mut all = main.clone();
    all.extend(fork.iter().cloned());
    let ssz: Vec<&[u8]> = all.iter().map(|b| b.2.as_slice()).collect();
    let head = (main[3].0, main[3].1);
    store.import(&ssz, stamp(4, head, (main[1].0, main[1].1)));
    let reader = store.reader();
    let roots = [
        main[1].1, [0xee; 32], main[3].1, fork[0].1, fork[1].1, main[0].1,
    ];
    let read = reader.blocks_by_root(&roots, &deadline()).unwrap();
    assert_eq!(read.stamp, stamp(4, head, (11, main[1].1)));
    let served = |b: &(u64, Root, Vec<u8>)| {
        AtRoot::Finalized(crate::reader::Block {
            slot: b.0,
            root: b.1,
            ssz: b.2.clone(),
            finalized: true,
        })
    };
    assert_eq!(
        read.value,
        [
            served(&main[1]),
            AtRoot::Missing,
            AtRoot::Unfinalized,
            AtRoot::Missing,
            AtRoot::Unfinalized,
            served(&main[0]),
        ]
    );
    index_from(&store, 11);
    let read = reader.blocks_by_root(&[main[0].1, main[1].1], &deadline());
    assert_eq!(read.unwrap().value, [AtRoot::Missing, served(&main[1])]);
    let gone = Deadline::after(Arc::new(Instant::now), Duration::ZERO);
    assert_eq!(
        reader.blocks_by_root(&roots, &gone).map(|r| r.value.len()),
        Err(ReadError::DeadlineExceeded)
    );
}
