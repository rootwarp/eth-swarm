use super::*;
use crate::probe::{CanonicalChain, ChainView};
use cl_chain_columns::Column;
use std::sync::OnceLock;

/// The custody columns of node `U256::MAX` (`get_custody_groups(U256::MAX, 4)`).
const CUSTODY: [u64; 4] = [1, 47, 87, 102];

fn store() -> (tempfile::TempDir, ColumnWriter) {
    let dir = tempfile::tempdir().unwrap();
    let writer = ColumnWriter::open(dir.path()).unwrap();
    (dir, writer)
}

/// Distinct bytes per (slot, index), so a test sees which sidecar it got.
fn ssz(slot: u64, index: u64) -> Vec<u8> {
    let mut out = slot.to_le_bytes().to_vec();
    out.extend(index.to_le_bytes());
    out
}

fn root(slot: u64) -> Root {
    let mut root = [0xb0; 32];
    root[..8].copy_from_slice(&slot.to_be_bytes());
    root
}

/// The root of a block at `slot` on another branch.
fn fork(slot: u64) -> Root {
    let mut root = [0xf0; 32];
    root[..8].copy_from_slice(&slot.to_be_bytes());
    root
}

/// Stores `indices` of the block `root` at `slot`, linked by `link`.
fn put_root(writer: &ColumnWriter, slot: u64, root: Root, link: BlockLink, indices: &[u64]) {
    let bytes: Vec<_> = indices.iter().map(|&i| (i, ssz(slot, i))).collect();
    let columns: Vec<_> = bytes
        .iter()
        .map(|(index, ssz)| Column { index: *index, ssz })
        .collect();
    writer
        .write_block_columns(slot, &root, link, &columns)
        .unwrap();
}

/// Stores one linked chain of blocks at `slots` (roots [`root`]), each with `indices`; the
/// first a start.
fn chain(writer: &ColumnWriter, slots: &[u64], indices: &[u64]) {
    let mut link = BlockLink::Start;
    for &slot in slots {
        put_root(writer, slot, root(slot), link, indices);
        link = BlockLink::Parent(root(slot));
    }
}

fn snap(writer: &ColumnWriter) -> cl_chain_columns::Snapshot<'_> {
    writer.reader().snapshot().unwrap()
}

/// A chain that holds every block these tests store, [`root`] and [`fork`] alike, at slots 0 to
/// 1000: the tests of the store's own chain rules, which hold under the reference's chain too.
fn every_block() -> Arc<ChainView> {
    static VIEW: OnceLock<Arc<ChainView>> = OnceLock::new();
    let view = VIEW.get_or_init(|| {
        let blocks = (0..=1000).flat_map(|slot| [(slot, root(slot)), (slot, fork(slot))]);
        Arc::new(ChainView::new(blocks).unwrap())
    });
    Arc::clone(view)
}

/// [`every_block`] as the column server follows it.
fn following_every_block() -> Arc<CanonicalChain> {
    Arc::new(CanonicalChain::fixed((*every_block()).clone()))
}

fn view(earliest: Option<Slot>) -> ServeView {
    ServeView {
        custody: CUSTODY.to_vec(),
        earliest,
        serve_range: Some((0, 1000)),
        budget: ServeBudget::default(),
        deadline: None,
        chain: Some(every_block()),
    }
}

/// [`view`] on the reference's chain of `blocks` (slots of [`root`]s).
fn on_chain(earliest: Option<Slot>, blocks: &[u64]) -> ServeView {
    let chain = ChainView::new(blocks.iter().map(|&slot| (slot, root(slot))));
    ServeView {
        chain: chain.map(Arc::new),
        ..view(earliest)
    }
}

/// A block off the reference's chain is never served, even alone in its range
/// (`fulu/p2p-interface.md`, `DataColumnSidecarsByRange v1`: "data column sidecars as included
/// by blocks from the single chain defined by the current head"): the chain 10 to 12, and an
/// orphan at 11 whose parent is 10, which the store's links alone would serve.
#[test]
fn an_orphan_alone_in_its_range_is_never_served() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 12], &CUSTODY);
    put_root(&writer, 11, fork(11), BlockLink::Parent(root(10)), &CUSTODY);
    let v = on_chain(Some(10), &[10, 12]);
    let snapshot = snap(&writer);
    let served = columns_by_range(&snapshot, 11, 1, &CUSTODY, &v).unwrap();
    assert!(
        served.iter().all(|s| s.block_root != fork(11)),
        "{served:?}"
    );
    // The reference's chain has no block at 11: nothing to serve there.
    assert_eq!(served, Vec::new());
    // Around it, the chain's blocks, and never the orphan.
    let served = columns_by_range(&snapshot, 10, 3, &[1], &v).unwrap();
    assert_eq!(keys(&served), [(10, 1), (12, 1)]);
    assert!(served.iter().all(|s| s.block_root == root(s.slot)));
    drop(snapshot);
    // The same through the column server, which follows the reference's chain.
    let writer = Arc::new(writer);
    open_custody(&writer, 10);
    let server = ColumnServer::new(
        Arc::clone(&writer) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Fixed),
        ServeBudget::default(),
    )
    .following(Arc::new(CanonicalChain::fixed(
        ChainView::new([(10, root(10)), (12, root(12))]).unwrap(),
    )));
    assert_eq!(server.by_range(11, 1, &CUSTODY, None).unwrap(), Vec::new());
    let served = server.by_range(10, 3, &[1], None).unwrap();
    assert_eq!(keys(&served), [(10, 1), (12, 1)]);
}

/// While the reference's chain is not known, a range with a stored block is
/// `3: ResourceUnavailable`, never a possible orphan; and a block past either end of the known
/// chain ends the answer before it.
#[test]
fn an_unknown_chain_serves_no_block() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 12], &CUSTODY);
    put_root(&writer, 11, fork(11), BlockLink::Parent(root(10)), &CUSTODY);
    let snapshot = snap(&writer);
    let unknown = ServeView {
        chain: None,
        ..view(Some(10))
    };
    for (start, count) in [(11, 1), (10, 3), (12, 1)] {
        let why = unavailable(columns_by_range(&snapshot, start, count, &[1], &unknown));
        assert!(why.contains("not known"), "{start}+{count}: {why}");
    }
    // A range with no stored block needs no chain: nothing to serve, as before.
    assert_eq!(
        columns_by_range(&snapshot, 13, 2, &[1], &unknown).unwrap(),
        Vec::new()
    );
    // The chain is known up to 10: 12 may be on it or not, so the answer ends before it.
    let to_10 = on_chain(Some(10), &[10]);
    let served = columns_by_range(&snapshot, 10, 3, &[1], &to_10).unwrap();
    assert_eq!(keys(&served), [(10, 1)]);
    let why = unavailable(columns_by_range(&snapshot, 12, 1, &[1], &to_10));
    assert!(why.contains("slot 12"), "{why}");
    // Known from 12 on: 10 is before it, so a range from 10 has no block to start with.
    let from_12 = on_chain(Some(10), &[12]);
    let why = unavailable(columns_by_range(&snapshot, 10, 3, &[1], &from_12));
    assert!(why.contains("slot 10"), "{why}");
    assert_eq!(
        keys(&columns_by_range(&snapshot, 12, 1, &[1], &from_12).unwrap()),
        [(12, 1)]
    );
    // A column server that follows no chain serves no range.
    drop(snapshot);
    let writer = Arc::new(writer);
    open_custody(&writer, 10);
    let server = ColumnServer::new(
        Arc::clone(&writer) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Fixed),
        ServeBudget::default(),
    );
    assert!(matches!(
        server.by_range(10, 3, &[1], None),
        Err(Refusal::Unavailable(_))
    ));
    // Before its first view it claims nothing unfinalized, so by root leaves its blocks out
    // too; with a chain known, by root answers what it holds: a root names its block.
    assert_eq!(
        server.by_root(&[(fork(11), vec![1])], None).unwrap(),
        Vec::new()
    );
    let server = server.following(following_every_block());
    let served = server.by_root(&[(fork(11), vec![1])], None).unwrap();
    assert_eq!(keys(&served), [(11, 1)]);
}

/// The column server never claims a slot before the first block of the reference's chain it
/// knows above the store's finalized slot: a range from there would be refused. Once finality
/// covers those slots, the store serves them without the chain.
#[test]
fn earliest_available_slot_never_claims_a_slot_before_the_known_chain() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 11, 12], &CUSTODY);
    let writer = Arc::new(writer);
    open_custody(&writer, 10);
    let server = ColumnServer::new(
        Arc::clone(&writer) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Fixed),
        ServeBudget::default(),
    )
    .following(Arc::new(CanonicalChain::fixed(
        ChainView::new([(11, root(11)), (12, root(12))]).unwrap(),
    )));
    assert_eq!(server.earliest_available_slot(), Some(11));
    assert_eq!(server.status_floor(), Ok(11));
    let served = server.by_range(11, 2, &[1], None).unwrap();
    assert_eq!(keys(&served), [(11, 1), (12, 1)]);
    let why = unavailable(server.by_range(10, 3, &[1], None));
    assert!(why.contains("below earliest_available_slot 11"), "{why}");
    writer
        .finalize(10, &std::collections::HashSet::from([root(10)]), 11)
        .unwrap();
    assert_eq!(server.earliest_available_slot(), Some(10));
    let served = server.by_range(10, 3, &[1], None).unwrap();
    assert_eq!(keys(&served), [(10, 1), (11, 1), (12, 1)]);
}

/// While the chain is not known (the stream down, a walk waiting), the first slot of the last
/// view still bounds the claim: a range from below it would be refused once the chain is known
/// again, so it is never claimed.
#[test]
fn the_last_known_chain_bounds_the_claim_while_the_chain_is_unknown() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 11, 12], &CUSTODY);
    let writer = Arc::new(writer);
    open_custody(&writer, 10);
    let canonical = Arc::new(CanonicalChain::fixed(
        ChainView::new([(11, root(11)), (12, root(12))]).unwrap(),
    ));
    let server = ColumnServer::new(
        Arc::clone(&writer) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Fixed),
        ServeBudget::default(),
    )
    .following(Arc::clone(&canonical));
    assert_eq!(server.earliest_available_slot(), Some(11));
    canonical.set(None);
    assert_eq!(server.earliest_available_slot(), Some(11));
    assert_eq!(canonical.known_from(), Some(11));
}

/// Before the first view of the reference's chain (a start with the event stream down), no
/// stored block above the finalized slot has a known place: a store with nothing finalized
/// claims nothing it holds, and a range from what it claims is never refused. Once finality
/// covers its first blocks, it claims them.
#[test]
fn before_the_first_view_nothing_unfinalized_is_claimed() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 11, 12], &CUSTODY);
    let writer = Arc::new(writer);
    open_custody(&writer, 10);
    let canonical = Arc::new(CanonicalChain::default());
    let server = ColumnServer::new(
        Arc::clone(&writer) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Fixed),
        ServeBudget::default(),
    )
    .following(Arc::clone(&canonical));
    assert_eq!(server.earliest_available_slot(), Some(13));
    assert_eq!(server.status_floor(), Ok(13));
    assert_eq!(server.by_range(13, 2, &[1], None), Ok(Vec::new()));
    writer
        .finalize(
            11,
            &std::collections::HashSet::from([root(10), root(11)]),
            12,
        )
        .unwrap();
    assert_eq!(server.earliest_available_slot(), Some(10));
    let served = server.by_range(10, 3, &[1], None).unwrap();
    assert_eq!(keys(&served), [(10, 1), (11, 1)]);
    canonical.set(ChainView::new([(12, root(12))]));
    assert_eq!(server.earliest_available_slot(), Some(10));
}

/// Every block at or below the store's finalized slot is on the finalized chain: those blocks
/// are served while the reference's chain is not known, and the answer ends before the first
/// block above it.
#[test]
fn finalized_blocks_are_served_without_the_chain() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 11, 12], &CUSTODY);
    put_root(&writer, 11, fork(11), BlockLink::Parent(root(10)), &CUSTODY);
    let canonical = std::collections::HashSet::from([root(10), root(11)]);
    writer.finalize(11, &canonical, 12).unwrap();
    assert_eq!(writer.reader().slot_of(&fork(11)).unwrap(), None);
    let unknown = ServeView {
        chain: None,
        ..view(Some(10))
    };
    let snapshot = snap(&writer);
    for count in [2, 3] {
        let served = columns_by_range(&snapshot, 10, count, &[1], &unknown).unwrap();
        assert_eq!(keys(&served), [(10, 1), (11, 1)], "10+{count}");
    }
    let why = unavailable(columns_by_range(&snapshot, 12, 1, &[1], &unknown));
    assert!(why.contains("not known"), "{why}");
}

/// The custody record of node `U256::MAX` in `writer`, set at `slot`.
fn open_custody(writer: &Arc<ColumnWriter>, slot: Slot) {
    use crate::da::custody::{Advertise, Custody, EnrCgc, EnrError};
    struct NoEnr;
    impl EnrCgc for NoEnr {
        fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
            Ok(())
        }
    }
    Custody::open(
        Arc::clone(writer),
        NoEnr,
        U256::MAX,
        Advertise::Custody,
        slot,
    )
    .unwrap();
}

fn keys(served: &[Served]) -> Vec<(u64, u64)> {
    served.iter().map(|s| (s.slot, s.index)).collect()
}

fn unavailable(r: Result<Vec<Served>, Refusal>) -> String {
    match r {
        Err(Refusal::Unavailable(why)) => why,
        other => panic!("{other:?}"),
    }
}

#[test]
fn by_range_order() {
    let (_dir, writer) = store();
    // Slot 12 skipped (no blobs): 13 links to 11 through it.
    chain(&writer, &[10, 11, 13], &CUSTODY);
    let served = columns_by_range(&snap(&writer), 10, 4, &[102, 1, 47], &view(Some(10))).unwrap();
    assert_eq!(
        keys(&served),
        [
            (10, 1),
            (10, 47),
            (10, 102),
            (11, 1),
            (11, 47),
            (11, 102),
            (13, 1),
            (13, 47),
            (13, 102),
        ]
    );
    // Every included block holds every requested custody column, as stored.
    for s in &served {
        assert_eq!(s.ssz, ssz(s.slot, s.index));
        assert_eq!(s.block_root, root(s.slot));
    }
    // All four custody columns, duplicates asked for once.
    let served =
        columns_by_range(&snap(&writer), 10, 2, &CUSTODY.repeat(2), &view(Some(10))).unwrap();
    assert_eq!(served.len(), 8);
    assert!(served
        .windows(2)
        .all(|w| (w[0].slot, w[0].index) < (w[1].slot, w[1].index)));
}

/// A block of the chain without a requested column ends the answer before it: the complete
/// blocks before it go out ("Clients MAY limit the number of data column sidecars in the
/// response", `fulu/p2p-interface.md` L682), never the block in part and never the blocks after
/// it; with no complete block before it the range is unavailable, never an empty answer.
#[test]
fn by_range_serves_the_complete_blocks_before_one_it_cannot_serve_whole() {
    let (_dir, writer) = store();
    put_root(&writer, 10, root(10), BlockLink::Start, &CUSTODY);
    put_root(
        &writer,
        11,
        root(11),
        BlockLink::Parent(root(10)),
        &[1, 47, 87],
    ); // 102 missed
    put_root(&writer, 12, root(12), BlockLink::Parent(root(11)), &CUSTODY);
    let v = view(Some(10));
    let block_10: Vec<_> = CUSTODY.iter().map(|&i| (10, i)).collect();
    for count in [2, 3] {
        let served = columns_by_range(&snap(&writer), 10, count, &CUSTODY, &v).unwrap();
        assert_eq!(keys(&served), block_10, "10+{count}");
    }
    // First: nothing complete before it.
    for count in [1, 2] {
        let why = unavailable(columns_by_range(&snap(&writer), 11, count, &CUSTODY, &v));
        assert!(why.contains("slot 11"), "11+{count}: {why}");
    }
    // Asking for the columns it has, it goes on.
    let served = columns_by_range(&snap(&writer), 10, 3, &[1, 47], &v).unwrap();
    assert_eq!(keys(&served).len(), 6);
    // A block that holds none of the requested columns counts too: first, or last.
    put_root(&writer, 20, root(20), BlockLink::Start, &[87]);
    put_root(&writer, 21, root(21), BlockLink::Parent(root(20)), &CUSTODY);
    put_root(&writer, 22, root(22), BlockLink::Parent(root(21)), &[87]);
    let why = unavailable(columns_by_range(&snap(&writer), 20, 2, &[1], &v));
    assert!(why.contains("slot 20"), "{why}");
    assert_eq!(
        keys(&columns_by_range(&snap(&writer), 21, 2, &[47], &v).unwrap()),
        [(21, 47)]
    );
    assert_eq!(
        keys(&columns_by_range(&snap(&writer), 21, 1, &[1], &v).unwrap()),
        [(21, 1)]
    );
}

/// A block past the chain that does not link to it may be on it: the answer ends before it.
#[test]
fn by_range_ends_before_a_block_that_does_not_link() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 11], &CUSTODY);
    put_root(&writer, 13, root(13), BlockLink::Gap, &CUSTODY);
    let v = view(Some(10));
    let served = columns_by_range(&snap(&writer), 10, 5, &[1], &v).unwrap();
    assert_eq!(keys(&served), [(10, 1), (11, 1)]);
    // From the gap on, it starts the chain; before it, the range may lack a block.
    assert_eq!(
        keys(&columns_by_range(&snap(&writer), 13, 1, &[1], &v).unwrap()),
        [(13, 1)]
    );
    let why = unavailable(columns_by_range(&snap(&writer), 12, 2, &[1], &v));
    assert!(why.contains("before slot 13"), "{why}");
    // One at the tip's own slot that does not link may be the chain's block there instead.
    put_root(&writer, 11, fork(11), BlockLink::Gap, &CUSTODY);
    assert_eq!(
        keys(&columns_by_range(&snap(&writer), 10, 2, &[1], &v).unwrap()),
        [(10, 1)]
    );
    // From 11, the two tie with nothing shared.
    unavailable(columns_by_range(&snap(&writer), 11, 1, &[1], &v));
}

/// SEC-007, BUG-010: a block waiting for an ancestor the store lacks names its slot. A range
/// over that slot is never an empty success, even with no block of it stored, and the answer
/// ends before it; a pending block whose ancestor is before the range starts the chain.
#[test]
fn a_pending_ancestors_slot_is_never_answered_as_empty() {
    let (_dir, writer) = store();
    put_root(&writer, 10, root(10), BlockLink::Start, &CUSTODY);
    // 12 carries blobs but none of its columns arrived (yet): 14 waits for it.
    put_root(
        &writer,
        14,
        root(14),
        BlockLink::Pending(root(12), 12),
        &CUSTODY,
    );
    put_root(&writer, 15, root(15), BlockLink::Parent(root(14)), &CUSTODY);
    let v = view(Some(10));
    for (start, count) in [(12, 1), (11, 2), (11, 5), (12, 4)] {
        let why = unavailable(columns_by_range(&snap(&writer), start, count, &[1], &v));
        assert!(why.contains("slot 12"), "{start}+{count}: {why}");
    }
    // The complete blocks before it go out.
    assert_eq!(
        keys(&columns_by_range(&snap(&writer), 10, 6, &[1], &v).unwrap()),
        [(10, 1)]
    );
    // Past it, the pending block starts the chain: its ancestor is before the range.
    assert_eq!(
        keys(&columns_by_range(&snap(&writer), 13, 3, &[1], &v).unwrap()),
        [(14, 1), (15, 1)]
    );
    assert_eq!(
        columns_by_range(&snap(&writer), 13, 1, &[1], &v).unwrap(),
        Vec::new()
    );
    // Once the ancestor is written, the chain runs through it.
    put_root(&writer, 12, root(12), BlockLink::Parent(root(10)), &CUSTODY);
    assert_eq!(
        keys(&columns_by_range(&snap(&writer), 10, 6, &[1], &v).unwrap()),
        [(10, 1), (12, 1), (14, 1), (15, 1)]
    );
}

/// A store no writer has migrated yet, read by a read-only reader (cl-store's, or a probe's
/// before its writer opened): a pending link stored without its target's slot names no slot, so
/// every slot below its block may be the one the store lacks. A range below that block is
/// `3: ResourceUnavailable`, never an empty success; from the block on, it is served.
#[test]
fn an_unmigrated_pending_link_is_never_answered_as_empty() {
    let dir = tempfile::tempdir().unwrap();
    {
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer
            .set_custody(&cl_chain_columns::CustodyRecord {
                cgc: 4,
                cgc_set_slot: 0,
                metadata_seq: 1,
                advertised_cgc: 4,
            })
            .unwrap();
        put_root(&writer, 10, root(10), BlockLink::Start, &CUSTODY);
        // 14 waits for 12, written as the store wrote a pending link before.
        put_root(&writer, 14, root(14), BlockLink::Start, &CUSTODY);
        writer
            .put_legacy_pending_link(&root(14), &root(12))
            .unwrap();
        put_root(&writer, 15, root(15), BlockLink::Parent(root(14)), &CUSTODY);
    }
    let reader = Arc::new(ColumnReader::open(dir.path()).unwrap());
    assert_eq!(reader.contiguous_from().unwrap(), None, "not migrated");
    let server = ColumnServer::new(
        reader as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Fixed),
        ServeBudget::default(),
    )
    .following(following_every_block());
    assert_eq!(server.earliest_available_slot(), Some(10));
    for (start, count) in [(12, 1), (10, 1), (11, 2), (10, 4), (13, 1), (10, 6)] {
        assert!(
            matches!(
                server.by_range(start, count, &[1], None),
                Err(Refusal::Unavailable(_))
            ),
            "{start}+{count}"
        );
    }
    // From the block on, its missing ancestor is before the range.
    let served = server.by_range(14, 2, &[1], None).unwrap();
    assert_eq!(keys(&served), [(14, 1), (15, 1)]);
    assert_eq!(server.by_range(16, 4, &[1], None).unwrap(), Vec::new());
}

/// CR-003: only the block the budget cut is spared the completeness check; a block before it
/// that lacks a requested column still ends the answer, as any such block does.
#[test]
fn only_the_block_the_budget_cut_is_spared() {
    let (_dir, writer) = store();
    chain(&writer, &[10], &CUSTODY);
    put_root(&writer, 11, root(11), BlockLink::Parent(root(10)), &[1, 47]);
    put_root(&writer, 12, root(12), BlockLink::Parent(root(11)), &CUSTODY);
    put_root(&writer, 13, root(13), BlockLink::Parent(root(12)), &CUSTODY);
    let at = |max_sidecars| ServeView {
        budget: ServeBudget {
            max_bytes: usize::MAX,
            max_sidecars,
        },
        ..view(Some(10))
    };
    // Cut inside 12: 11 lacks a column and ends the answer, 12 is the budget's.
    let served = columns_by_range(&snap(&writer), 10, 4, &CUSTODY, &at(8)).unwrap();
    assert_eq!(keys(&served).len(), 4);
    // Cut before 13 (not read at all): 12 is whole and goes out.
    let served = columns_by_range(&snap(&writer), 11, 3, &[1, 47], &at(4)).unwrap();
    assert_eq!(keys(&served), [(11, 1), (11, 47), (12, 1), (12, 47)]);
    let served = columns_by_range(&snap(&writer), 12, 2, &CUSTODY, &at(6)).unwrap();
    assert_eq!(keys(&served), CUSTODY.map(|i| (12, i)));
    // The block read whole is off the chain, and the chain's first is the one cut: nothing
    // whole to send, never an empty answer.
    let (_dir, writer) = store();
    put_root(&writer, 10, fork(10), BlockLink::Start, &CUSTODY);
    put_root(&writer, 11, root(11), BlockLink::Start, &CUSTODY);
    let why = unavailable(columns_by_range(&snap(&writer), 10, 2, &CUSTODY, &at(5)));
    assert!(
        why.contains("budget cut the first block, at slot 11"),
        "{why}"
    );
}

/// BUG-003: two blocks at one slot that share no stored ancestor leave no chain to serve:
/// unavailable, not an empty success.
#[test]
fn a_tie_with_nothing_shared_is_unavailable() {
    let (_dir, writer) = store();
    put_root(&writer, 10, root(10), BlockLink::Start, &CUSTODY);
    put_root(&writer, 10, fork(10), BlockLink::Start, &CUSTODY);
    let why = unavailable(columns_by_range(
        &snap(&writer),
        10,
        1,
        &[1],
        &view(Some(10)),
    ));
    assert!(why.contains("chain"), "{why}");
    // A pending block ties to nothing either: with its ancestor in the range, the range up
    // to that ancestor is all there is; without, it is the higher tip.
    let (_dir, writer) = store();
    put_root(&writer, 10, root(10), BlockLink::Start, &CUSTODY);
    put_root(
        &writer,
        12,
        root(12),
        BlockLink::Pending([0x77; 32], 11),
        &CUSTODY,
    );
    let v = view(Some(10));
    let served = columns_by_range(&snap(&writer), 10, 3, &[1], &v).unwrap();
    assert_eq!(keys(&served), [(10, 1)]);
    let why = unavailable(columns_by_range(&snap(&writer), 11, 2, &[1], &v));
    assert!(why.contains("slot 11"), "{why}");
}

/// BUG-003, BUG-007: a range answer is one chain of linked blocks, whatever other branches
/// the store still holds, and a budget cut never mixes them.
#[test]
fn by_range_follows_one_linked_chain() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 12, 13, 14], &CUSTODY);
    // An orphaned branch off 10 at 11 and 12, never pruned.
    put_root(&writer, 11, fork(11), BlockLink::Parent(root(10)), &CUSTODY);
    put_root(&writer, 12, fork(12), BlockLink::Parent(fork(11)), &CUSTODY);
    let v = view(Some(10));
    let served = columns_by_range(&snap(&writer), 10, 5, &[1], &v).unwrap();
    assert_eq!(keys(&served), [(10, 1), (12, 1), (13, 1), (14, 1)]);
    assert!(served.iter().all(|s| s.block_root == root(s.slot)));
    // Two blocks at slot 12 no longer stop a range through it.
    let served = columns_by_range(&snap(&writer), 12, 3, &[1, 47], &v).unwrap();
    assert_eq!(
        keys(&served),
        [(12, 1), (12, 47), (13, 1), (13, 47), (14, 1), (14, 47)]
    );
    // A budget cut at a whole block: the chain of what was read, never the other branch.
    let cut = ServeView {
        budget: ServeBudget {
            max_sidecars: 3,
            ..ServeBudget::default()
        },
        ..v.clone()
    };
    let served = columns_by_range(&snap(&writer), 10, 5, &[1], &cut).unwrap();
    assert!(
        served.iter().all(|s| s.block_root == root(s.slot)),
        "{served:?}"
    );
    // Two tips of one length and slot: only what they share.
    put_root(&writer, 15, root(15), BlockLink::Parent(root(14)), &[1]);
    put_root(&writer, 15, fork(15), BlockLink::Parent(root(14)), &[1]);
    let served = columns_by_range(&snap(&writer), 13, 3, &[1], &v).unwrap();
    assert_eq!(keys(&served), [(13, 1), (14, 1)]);
}

/// BUG-002: the answer holds at most the budget's sidecars, cut at a whole block, and its bytes
/// too; the first block always goes.
#[test]
fn by_range_cuts_at_a_whole_block_by_count_and_bytes() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 11, 12], &CUSTODY);
    let at = |max_sidecars, max_bytes| ServeView {
        budget: ServeBudget {
            max_bytes,
            max_sidecars,
        },
        ..view(Some(10))
    };
    let one = ssz(10, 1).len();
    let served = columns_by_range(&snap(&writer), 10, 3, &CUSTODY, &at(9, usize::MAX)).unwrap();
    assert_eq!(served.len(), 8, "two whole blocks of four");
    let served = columns_by_range(&snap(&writer), 10, 3, &CUSTODY, &at(100, 5 * one)).unwrap();
    assert_eq!(served.len(), 4);
    // CR budget: a first block past the budget goes whole, as cl-p2p and by-root send it.
    let served = columns_by_range(&snap(&writer), 10, 3, &CUSTODY, &at(3, usize::MAX)).unwrap();
    assert_eq!(keys(&served), [(10, 1), (10, 47), (10, 87), (10, 102)]);
    let served = columns_by_range(&snap(&writer), 10, 3, &CUSTODY, &at(100, 1)).unwrap();
    assert_eq!(served.len(), 4);
}

/// Lead-b: after a gap the store claims nothing before it, so a range over the gap is
/// unavailable instead of silently skipping the block it never held.
#[test]
fn a_gap_moves_earliest_available_slot_past_it() {
    use crate::da::custody::{Advertise, Custody, EnrCgc, EnrError};
    struct NoEnr;
    impl EnrCgc for NoEnr {
        fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
            Ok(())
        }
    }
    let (_dir, writer) = store();
    let writer = Arc::new(writer);
    Custody::open(
        Arc::clone(&writer),
        NoEnr,
        U256::MAX,
        Advertise::Custody,
        10,
    )
    .unwrap();
    let server = ColumnServer::new(
        Arc::clone(&writer) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Fixed),
        ServeBudget::default(),
    )
    .following(following_every_block());
    chain(&writer, &[10, 11], &CUSTODY);
    assert_eq!(server.earliest_available_slot(), Some(10));
    // 12 was never held (downtime): 13 is stored as a gap.
    put_root(&writer, 13, root(13), BlockLink::Gap, &CUSTODY);
    put_root(&writer, 14, root(14), BlockLink::Parent(root(13)), &CUSTODY);
    assert_eq!(server.earliest_available_slot(), Some(13));
    let why = unavailable(server.by_range(10, 5, &CUSTODY, None));
    assert!(why.contains("below earliest_available_slot 13"), "{why}");
    let served = server.by_range(13, 2, &[1], None).unwrap();
    assert_eq!(keys(&served), [(13, 1), (14, 1)]);
    // By root still answers what it holds from 13 on, and leaves the rest out.
    let served = server
        .by_root(&[(root(11), vec![1]), (root(14), vec![1])], None)
        .unwrap();
    assert_eq!(keys(&served), [(14, 1)]);
}

#[test]
fn below_earliest_or_outside_the_serve_range_is_unavailable_never_empty() {
    let (_dir, writer) = store();
    chain(&writer, &[20], &CUSTODY);
    // Nothing stored yet.
    let why = unavailable(columns_by_range(&snap(&writer), 20, 1, &[1], &view(None)));
    assert!(why.contains("no columns stored"));
    // Below earliest_available_slot, even where the range reaches it.
    let why = unavailable(columns_by_range(
        &snap(&writer),
        19,
        2,
        &[1],
        &view(Some(20)),
    ));
    assert!(why.contains("below earliest_available_slot 20"), "{why}");
    // Before data_column_serve_range, or no range before Fulu.
    for range in [Some((21, 100)), None] {
        let v = ServeView {
            serve_range: range,
            ..view(Some(5))
        };
        unavailable(columns_by_range(&snap(&writer), 20, 1, &[1], &v));
    }
    // A column the node does not custody.
    let why = unavailable(columns_by_range(
        &snap(&writer),
        20,
        1,
        &[5],
        &view(Some(20)),
    ));
    assert!(why.contains("not a custody column"));
    // At earliest_available_slot: served.
    let served = columns_by_range(&snap(&writer), 20, 1, &[1], &view(Some(20))).unwrap();
    assert_eq!(keys(&served), [(20, 1)]);
}

/// A range after the current epoch holds no column yet: an empty answer, as slots without
/// known data columns are skipped (`fulu/p2p-interface.md` L678–680).
#[test]
fn a_range_in_the_future_is_empty() {
    let (_dir, writer) = store();
    chain(&writer, &[20], &CUSTODY);
    let v = ServeView {
        serve_range: Some((0, 30)),
        ..view(Some(20))
    };
    assert_eq!(
        columns_by_range(&snap(&writer), 31, 10, &[1], &v).unwrap(),
        Vec::new()
    );
    // Starting inside the range and reaching past it: what is held.
    assert_eq!(
        keys(&columns_by_range(&snap(&writer), 20, 100, &[1], &v).unwrap()),
        [(20, 1)]
    );
}

#[test]
fn by_root_mixed() {
    let (_dir, writer) = store();
    chain(&writer, &[10], &CUSTODY);
    put_root(&writer, 11, root(11), BlockLink::Parent(root(10)), &[1, 47]);
    let v = view(Some(10));
    let ids = [
        (root(11), vec![102, 47, 1]),
        ([0x5a; 32], vec![1, 47]), // unknown: omitted
        (root(10), vec![87, 5]),   // 5 is not stored: omitted
    ];
    let served = columns_by_root(&snap(&writer), &ids, &v).unwrap();
    assert_eq!(keys(&served), [(11, 1), (11, 47), (10, 87)]);
    assert!(served.iter().all(|s| s.ssz == ssz(s.slot, s.index)));
    assert_eq!(served[0].block_root, root(11));
    // Only unknown roots: an empty answer.
    let served = columns_by_root(&snap(&writer), &[([1; 32], vec![1])], &v).unwrap();
    assert!(served.is_empty());
    // Over the request bound: invalid.
    let many: Vec<_> = (0..129).map(|i| ([i as u8; 32], vec![1])).collect();
    assert!(matches!(
        columns_by_root(&snap(&writer), &many, &v),
        Err(Refusal::Invalid(_))
    ));
    let wide: Vec<_> = (0..128)
        .map(|i| ([i as u8; 32], (0..129).collect()))
        .collect();
    assert!(matches!(
        columns_by_root(&snap(&writer), &wide, &v),
        Err(Refusal::Invalid(_))
    ));
    assert!(matches!(
        columns_by_root(&snap(&writer), &[(root(10), vec![128])], &v),
        Err(Refusal::Invalid(_))
    ));
}

/// SEC-005, BUG-006, the budget: by root, each `(root, index)` once, a root below
/// `earliest_available_slot` or outside the range left out (not the whole request), and the
/// budget cut at a whole identifier with the first always in.
#[test]
fn by_root_dedupes_skips_and_cuts() {
    let (_dir, writer) = store();
    chain(&writer, &[10, 11, 12], &CUSTODY);
    let v = view(Some(11));
    // One root named over and over fills nothing twice.
    let flood: Vec<_> = (0..128).map(|_| (root(11), CUSTODY.to_vec())).collect();
    let served = columns_by_root(&snap(&writer), &flood, &v).unwrap();
    assert_eq!(keys(&served), [(11, 1), (11, 47), (11, 87), (11, 102)]);
    let served = columns_by_root(
        &snap(&writer),
        &[(root(12), vec![1, 1, 47]), (root(12), vec![47, 87])],
        &v,
    )
    .unwrap();
    assert_eq!(keys(&served), [(12, 1), (12, 47), (12, 87)]);
    // 10 is below earliest: left out; the rest still answered.
    let served = columns_by_root(
        &snap(&writer),
        &[(root(10), vec![1]), (root(12), vec![1])],
        &v,
    )
    .unwrap();
    assert_eq!(keys(&served), [(12, 1)]);
    // Outside the serve range: left out.
    let outside = ServeView {
        serve_range: Some((12, 100)),
        ..v.clone()
    };
    let served = columns_by_root(
        &snap(&writer),
        &[(root(11), vec![1]), (root(12), vec![1])],
        &outside,
    )
    .unwrap();
    assert_eq!(keys(&served), [(12, 1)]);
    // The budget: whole identifiers, the first always.
    let small = ServeView {
        budget: ServeBudget {
            max_bytes: 3 * ssz(11, 1).len(),
            max_sidecars: 100,
        },
        ..v.clone()
    };
    let ids = [(root(11), CUSTODY.to_vec()), (root(12), vec![1])];
    let served = columns_by_root(&snap(&writer), &ids, &small).unwrap();
    assert_eq!(keys(&served), [(11, 1), (11, 47), (11, 87), (11, 102)]);
    let few = ServeView {
        budget: ServeBudget {
            max_bytes: usize::MAX,
            max_sidecars: 5,
        },
        ..v
    };
    let served = columns_by_root(&snap(&writer), &ids, &few).unwrap();
    assert_eq!(served.len(), 5);
    let served = columns_by_root(
        &snap(&writer),
        &[(root(11), CUSTODY.to_vec()), (root(12), CUSTODY.to_vec())],
        &few,
    )
    .unwrap();
    assert_eq!(
        served.len(),
        4,
        "the second identifier would pass the budget"
    );
}

#[test]
fn range_bounds_are_invalid() {
    let (_dir, writer) = store();
    let v = view(Some(0));
    let all: Vec<u64> = (0..128).collect();
    for (count, columns) in [(1, vec![128]), (129, all.clone()), (u64::MAX, vec![1])] {
        assert!(matches!(
            columns_by_range(&snap(&writer), 0, count, &columns, &v),
            Err(Refusal::Invalid(_))
        ));
    }
    // Naming nothing is an empty answer, even with nothing stored.
    assert!(columns_by_range(&snap(&writer), 0, 0, &[1], &view(None))
        .unwrap()
        .is_empty());
    assert!(columns_by_range(&snap(&writer), 0, 5, &[], &view(None))
        .unwrap()
        .is_empty());
}

/// The request bounds need no store: every index below `NUMBER_OF_COLUMNS`, and at most
/// `MAX_REQUEST_DATA_COLUMN_SIDECARS` sidecars counted as named, duplicates included; by root
/// also at most `MAX_REQUEST_BLOCKS_DENEB` identifiers. A request within them gets the number of
/// sidecars it names.
#[test]
fn request_bounds_hold_without_a_store() {
    let all: Vec<u64> = (0..128).collect();
    assert_eq!(range_request_bounds(128, &all), Ok(16_384));
    assert_eq!(range_request_bounds(8_192, &[1, 1]), Ok(16_384));
    assert_eq!(range_request_bounds(u64::MAX, &[]), Ok(0));
    assert_eq!(range_request_bounds(0, &[127]), Ok(0));
    for (count, columns) in [
        (1, vec![128]),
        (0, vec![u64::MAX]),
        (129, all.clone()),
        (8_193, vec![1, 1]),
        (u64::MAX, vec![1]),
    ] {
        assert!(
            matches!(
                range_request_bounds(count, &columns),
                Err(Refusal::Invalid(_))
            ),
            "{count} x {columns:?}"
        );
    }

    let ids = |n: usize, columns: Vec<u64>| -> Vec<(Root, Vec<u64>)> {
        (0..n).map(|i| ([i as u8; 32], columns.clone())).collect()
    };
    assert_eq!(root_request_bounds(&[]), Ok(0));
    assert_eq!(root_request_bounds(&ids(128, all.clone())), Ok(16_384));
    assert_eq!(root_request_bounds(&ids(128, vec![5; 128])), Ok(16_384));
    assert_eq!(root_request_bounds(&ids(3, vec![])), Ok(0));
    for bad in [
        ids(129, vec![1]),
        ids(128, (0..129).map(|i| i % 128).collect()),
        ids(1, vec![1, 128]),
        ids(1, vec![u64::MAX]),
    ] {
        assert!(
            matches!(root_request_bounds(&bad), Err(Refusal::Invalid(_))),
            "{} identifiers",
            bad.len()
        );
    }
}

/// A clock with every slot in range and one Gloas digest.
struct Fixed;

impl ServeClock for Fixed {
    fn serve_range(&self) -> Option<(Slot, Slot)> {
        Some((0, 1000))
    }

    fn fork_digest(&self, _: Slot) -> Option<[u8; 4]> {
        Some([0x61, 0x0a, 0x50, 0x01])
    }
}

#[test]
fn the_server_reads_its_view_from_the_store() {
    use crate::da::custody::{Advertise, Custody, EnrCgc, EnrError};
    struct NoEnr;
    impl EnrCgc for NoEnr {
        fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
            Ok(())
        }
    }
    let (_dir, writer) = store();
    let writer = Arc::new(writer);
    let server = ColumnServer::new(
        Arc::clone(&writer) as Arc<dyn ColumnStore>,
        U256::MAX,
        Arc::new(Fixed),
        ServeBudget::default(),
    )
    .following(following_every_block());
    // No custody record yet: nothing to serve.
    assert_eq!(server.earliest_available_slot(), None);
    Custody::open(
        Arc::clone(&writer),
        NoEnr,
        U256::MAX,
        Advertise::Custody,
        16,
    )
    .unwrap();
    let v = server.view().unwrap();
    assert_eq!(v.custody, CUSTODY);
    assert_eq!(v.earliest, None, "nothing stored yet");
    chain(&writer, &[17, 30], &CUSTODY);
    assert_eq!(server.earliest_available_slot(), Some(17));
    // Finality prunes past the first stored slot: earliest moves after the watermark.
    writer.prune_finalized(20).unwrap();
    assert_eq!(server.earliest_available_slot(), Some(21));
    assert!(matches!(
        server.by_range(17, 1, &[1], None),
        Err(Refusal::Unavailable(_))
    ));
    let served = server.by_range(21, 10, &CUSTODY, None).unwrap();
    let envelopes = server.envelopes(served).unwrap();
    let seqs: Vec<_> = envelopes.iter().map(|e| (e.seq, e.slot)).collect();
    assert_eq!(seqs, [(1, 30), (2, 30), (3, 30), (4, 30)]);
    assert!(envelopes
        .iter()
        .all(|e| e.fork_digest == [0x61, 0x0a, 0x50, 0x01]
            && e.payload_type == PayloadType::DataColumnSidecar as i32
            && e.root == root(30)));
    assert_eq!(
        server.by_root(&[(root(30), vec![47])], None).unwrap().len(),
        1
    );
    // A read past its deadline stops.
    let past = Some(Instant::now());
    assert!(matches!(
        server.by_range(21, 10, &CUSTODY, past),
        Err(Refusal::Store(_))
    ));
    assert!(matches!(
        server.by_root(&[(root(30), vec![47])], past),
        Err(Refusal::Store(_))
    ));
}

/// SEC-004: the stream carries a fixed message per code, never the refusal's detail.
#[test]
fn refusals_map_to_fixed_messages_per_code() {
    let chunk = |r: Refusal| match refusal_chunk(&r).unwrap().result {
        Some(pb::response_chunk::Result::Error(e)) => (e.code, e.detail),
        other => panic!("{other:?}"),
    };
    let secret = "MDBX_PANIC at 0xdeadbeef";
    assert_eq!(
        chunk(Refusal::Invalid(secret.into())),
        (ErrorCode::Invalid as i32, INVALID_MESSAGE.into())
    );
    assert_eq!(
        chunk(Refusal::Unavailable(secret.into())),
        (
            ErrorCode::ResourceUnavailable as i32,
            UNAVAILABLE_MESSAGE.into()
        )
    );
    assert_eq!(
        chunk(Refusal::Overloaded),
        (ErrorCode::Overloaded as i32, OVERLOADED_MESSAGE.into())
    );
    let status = refusal_chunk(&Refusal::Store(secret.into())).unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
    assert!(!status.message().contains("MDBX"));
    let bad = pb::DataColumnsByRootRequest {
        ids: vec![pb::DataColumnsByRootIdentifier {
            block_root: vec![1; 31],
            columns: vec![1],
        }],
        hello: None,
    };
    assert!(matches!(identifiers(&bad), Err(Refusal::Invalid(_))));
}

/// SEC-003: reads past the server's places are refused as overloaded at once; a read's place
/// is held until the read ends.
#[tokio::test]
async fn reads_past_the_places_are_overloaded() {
    use ipc::envelope::DigestTable;
    use network_config::{ForkSchedule, ScheduledFork};
    use tokio_stream::StreamExt;
    let at = |epoch| ScheduledFork {
        version: [7, 0, 0, 0],
        epoch,
    };
    let hello = common::Hello {
        api_version: 1,
        min_api_version: 1,
        max_api_version: 1,
        ..Default::default()
    };
    let digests = DigestTable::new(vec![(0, ForkName::Gloas, [0x61, 0x0a, 0x50, 0x01])]).unwrap();
    let link = Link::new::<consensus_types::Mainnet>(
        hello.clone(),
        1,
        ForkSchedule::new(at(0), at(0)).unwrap(),
        digests,
    );
    let (_dir, writer) = store();
    let columns = Arc::new(
        ColumnServer::new(
            Arc::new(writer) as Arc<dyn ColumnStore>,
            U256::MAX,
            Arc::new(Fixed),
            ServeBudget::default(),
        )
        .following(following_every_block()),
    );
    let codes = |server: ReqRespServer| {
        let hello = hello.clone();
        async move {
            let request = pb::DataColumnsByRangeRequest {
                start_slot: 0,
                count: 1,
                columns: vec![1],
                hello: Some(hello.clone()),
            };
            let mut stream = server
                .data_columns_by_range(Request::new(request))
                .await
                .unwrap()
                .into_inner();
            let mut codes = Vec::new();
            while let Some(frame) = stream.next().await {
                if let Some(pb::data_columns_by_range_response::Frame::Body(body)) =
                    frame.unwrap().frame
                {
                    if let Some(pb::response_chunk::Result::Error(e)) =
                        body.item.and_then(|i| i.result)
                    {
                        codes.push(e.code);
                    }
                }
            }
            codes
        }
    };
    let full = ReqRespServer::with_max_reads(link.clone(), Arc::clone(&columns), 0);
    assert_eq!(codes(full).await, [ErrorCode::Overloaded as i32]);
    // With a place: read, and refused for what it is (nothing stored).
    let open = ReqRespServer::with_max_reads(link, columns, 1);
    assert_eq!(
        codes(open.clone()).await,
        [ErrorCode::ResourceUnavailable as i32]
    );
    assert_eq!(open.reads.available_permits(), 1, "given back");
}

#[test]
fn the_wall_clock_serve_range() {
    use network_config::{ChainConfig, Network};
    let chain = ProbeChain {
        config: ChainConfig::load(Network::Sepolia).unwrap(),
        genesis: Network::Sepolia.genesis().unwrap(),
        slots_per_epoch: 32,
    };
    let clock = WallClock::new(chain.clone()).unwrap();
    assert_eq!(clock.min_epochs, 4096);
    let fulu = chain
        .config
        .fork_schedule()
        .fork_epoch(ForkName::Fulu)
        .unwrap();
    let ms_per_epoch = u128::from(chain.config.slot_duration_ms() * 32);
    let at = |epoch: u64| {
        u128::from(chain.genesis.genesis_time) * 1000 + u128::from(epoch) * ms_per_epoch
    };
    // Before Fulu: no range.
    assert_eq!(clock.serve_range_at(at(fulu - 1)), None);
    // Within MIN_EPOCHS of Fulu: from Fulu to the end of the current epoch.
    assert_eq!(
        clock.serve_range_at(at(fulu + 10)),
        Some((fulu * 32, (fulu + 11) * 32 - 1))
    );
    // Later: the last MIN_EPOCHS epochs.
    let now = fulu + 5000;
    assert_eq!(
        clock.serve_range_at(at(now)),
        Some(((now - 4096) * 32, (now + 1) * 32 - 1))
    );
    assert_eq!(
        clock.fork_digest(fulu * 32).map(|d| d.to_vec()),
        Some(
            compute_fork_digest(&chain.config, &chain.genesis.genesis_validators_root, fulu)
                .unwrap()
                .to_vec()
        )
    );
    assert!(clock.serve_range().is_some(), "Sepolia is past Fulu");
    let mut hoodi = chain;
    hoodi.config = ChainConfig::load(Network::Hoodi).unwrap();
    assert!(WallClock::new(hoodi).is_ok());
}

/// `ReqRespService` refuses a column request as `1: InvalidRequest` exactly when
/// [`range_request_bounds`] or [`root_request_bounds`] refuses it, with a store or without one:
/// the bounds are the service's, not a copy of them.
#[tokio::test]
async fn the_service_refuses_exactly_what_the_bounds_refuse() {
    use ipc::envelope::DigestTable;
    use network_config::{ForkSchedule, ScheduledFork};
    use tokio_stream::StreamExt;
    let at = |epoch| ScheduledFork {
        version: [7, 0, 0, 0],
        epoch,
    };
    let hello = common::Hello {
        api_version: 1,
        min_api_version: 1,
        max_api_version: 1,
        ..Default::default()
    };
    let digests = DigestTable::new(vec![(0, ForkName::Gloas, [0x61, 0x0a, 0x50, 0x01])]).unwrap();
    let link = Link::new::<consensus_types::Mainnet>(
        hello.clone(),
        1,
        ForkSchedule::new(at(0), at(0)).unwrap(),
        digests,
    );
    /// The error codes of a response's chunks.
    fn codes(item: Option<pb::ResponseChunk>) -> Option<i32> {
        match item.and_then(|i| i.result) {
            Some(pb::response_chunk::Result::Error(e)) => Some(e.code),
            _ => None,
        }
    }
    let all: Vec<u64> = (0..128).collect();
    let ranges = [
        (0, vec![1]),
        (5, vec![]),
        (128, all.clone()),
        (8_192, vec![47, 47]),
        (1, vec![128]),
        (129, all.clone()),
        (8_193, vec![47, 47]),
        (u64::MAX, vec![1]),
        (u64::MAX, vec![]),
    ];
    let ids = |n: usize, columns: Vec<u64>| -> Vec<(Root, Vec<u64>)> {
        (0..n).map(|i| ([i as u8; 32], columns.clone())).collect()
    };
    let roots = [
        vec![],
        ids(1, vec![1, 1]),
        ids(128, all.clone()),
        ids(129, vec![1]),
        ids(128, (0..129).map(|i| i % 128).collect()),
        ids(1, vec![128]),
    ];
    for stored in [false, true] {
        let (_dir, writer) = store();
        if stored {
            chain(&writer, &[10, 11], &CUSTODY);
        }
        let server = ReqRespServer::new(
            link.clone(),
            Arc::new(
                ColumnServer::new(
                    Arc::new(writer) as Arc<dyn ColumnStore>,
                    U256::MAX,
                    Arc::new(Fixed),
                    ServeBudget::default(),
                )
                .following(following_every_block()),
            ),
        );
        for (count, columns) in &ranges {
            let request = pb::DataColumnsByRangeRequest {
                start_slot: 10,
                count: *count,
                columns: columns.clone(),
                hello: Some(hello.clone()),
            };
            let mut stream = server
                .data_columns_by_range(Request::new(request))
                .await
                .unwrap()
                .into_inner();
            let mut refused = Vec::new();
            while let Some(frame) = stream.next().await {
                if let Some(pb::data_columns_by_range_response::Frame::Body(body)) =
                    frame.unwrap().frame
                {
                    refused.extend(codes(body.item));
                }
            }
            let invalid = refused == [ErrorCode::Invalid as i32];
            assert_eq!(
                invalid,
                range_request_bounds(*count, columns).is_err(),
                "stored {stored}: {count} x {columns:?} refused with {refused:?}"
            );
        }
        for ids in &roots {
            let request = pb::DataColumnsByRootRequest {
                ids: ids
                    .iter()
                    .map(|(root, columns)| pb::DataColumnsByRootIdentifier {
                        block_root: root.to_vec(),
                        columns: columns.clone(),
                    })
                    .collect(),
                hello: Some(hello.clone()),
            };
            let mut stream = server
                .data_columns_by_root(Request::new(request))
                .await
                .unwrap()
                .into_inner();
            let mut refused = Vec::new();
            while let Some(frame) = stream.next().await {
                if let Some(pb::data_columns_by_root_response::Frame::Body(body)) =
                    frame.unwrap().frame
                {
                    refused.extend(codes(body.item));
                }
            }
            let invalid = refused == [ErrorCode::Invalid as i32];
            assert_eq!(
                invalid,
                root_request_bounds(ids).is_err(),
                "stored {stored}: {} identifiers refused with {refused:?}",
                ids.len()
            );
        }
    }
}

/// The link of the GetStatus tests: one Gloas digest from genesis.
fn status_link() -> Link {
    use ipc::envelope::DigestTable;
    use network_config::{ForkSchedule, ScheduledFork};
    let at = |epoch| ScheduledFork {
        version: [7, 0, 0, 0],
        epoch,
    };
    let hello = common::Hello {
        api_version: 1,
        min_api_version: 1,
        max_api_version: 1,
        ..Default::default()
    };
    let digests = DigestTable::new(vec![(0, ForkName::Gloas, [0x61, 0x0a, 0x50, 0x01])]).unwrap();
    Link::new::<consensus_types::Mainnet>(
        hello,
        1,
        ForkSchedule::new(at(0), at(0)).unwrap(),
        digests,
    )
}

/// A Status source answering from its list, one entry per call.
struct ScriptedStatus(
    std::sync::Mutex<Vec<Result<pb::GetStatusResponse, crate::probe::ProbeError>>>,
);

impl ChainStatus for ScriptedStatus {
    fn status(&self) -> StatusLookup<'_> {
        let next = self.0.lock().unwrap().remove(0);
        Box::pin(async move { next })
    }
}

fn a_status() -> pb::GetStatusResponse {
    pb::GetStatusResponse {
        fork_digest: vec![0x61, 0x0a, 0x50, 0x01],
        finalized: Some(common::Checkpoint {
            epoch: 3,
            root: vec![0xaa; 32],
        }),
        head_root: vec![0xaa; 32],
        head_slot: 96,
        earliest_available_slot: 120,
    }
}

/// `GetStatus` serves the Status source it is given (the probe's `StatusProvider`, its
/// `earliest_available_slot` the column server's), `UNAVAILABLE` while the source has none,
/// and is the stub (`UNIMPLEMENTED`) without a source.
#[tokio::test]
async fn get_status_serves_the_status_source() {
    let (_dir, writer) = store();
    let columns = Arc::new(
        ColumnServer::new(
            Arc::new(writer) as Arc<dyn ColumnStore>,
            U256::MAX,
            Arc::new(Fixed),
            ServeBudget::default(),
        )
        .following(following_every_block()),
    );
    let stub = ReqRespServer::new(status_link(), Arc::clone(&columns));
    let err = stub
        .get_status(Request::new(pb::GetStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);

    let source = ScriptedStatus(std::sync::Mutex::new(vec![
        Ok(a_status()),
        Err(crate::probe::ProbeError::Unavailable(
            "no sample yet".into(),
        )),
    ]));
    let served = ReqRespServer::new(status_link(), columns).serving_status(Arc::new(source));
    assert!(format!("{stub:?}").contains("serves_status: false"));
    assert!(format!("{served:?}").contains("serves_status: true"));
    let got = served
        .get_status(Request::new(pb::GetStatusRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got, a_status());
    let err = served
        .get_status(Request::new(pb::GetStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
}
