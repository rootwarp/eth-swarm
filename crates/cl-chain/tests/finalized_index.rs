//! cl-chain's side of the finalized slot index: the backfill it runs when it opens the store
//! again ([`finalized_index::backfill`]), through its one writer, [`ColumnWriter`]: bounded
//! batches, each its own write transaction with the stamp carried, down to the block serve
//! window's start ([`finalized_index::window_floor`]) or the lowest stored block.

use std::path::Path;

use cl_chain::finalized_index;
use cl_chain::probe::ProbeChain;
use cl_chain_columns::ColumnWriter;
use consensus_types::{ForkSchedule, Minimal};
use libmdbx::WriteFlags;
use network_config::{
    window::block_serve_window, ChainConfig, Network, ScheduledFork, FAR_FUTURE_EPOCH,
};
use ssz::Encode as _;
use store_schema::{
    env::{self, test_writer},
    finalized,
    keys::{Root, FINALIZED_INDEX_FROM_KEY, SCHEMA_VERSION_KEY},
    stamp::{self, Stamp},
    tables::{FINALIZED_SLOTS, META},
    txn::{self, Update},
};
use tree_hash::TreeHash as _;

/// Fulu from genesis, Gloas never.
fn schedule() -> ForkSchedule {
    let at = |version, epoch| ScheduledFork { version, epoch };
    ForkSchedule::new(at([6, 0, 0, 1], 0), at([7, 0, 0, 1], FAR_FUTURE_EPOCH)).unwrap()
}

/// Slots 1 to 40 but 5, 12 and 17, each on the one before: `(slot, root, ssz)`.
fn canonical() -> Vec<(u64, Root, Vec<u8>)> {
    let mut parent = [0; 32];
    (1..=40u64)
        .filter(|s| ![5, 12, 17].contains(s))
        .map(|slot| {
            let mut block = p2p_wire::testkit::fulu_block::<Minimal>(slot);
            block.message.parent_root = parent.into();
            parent = block.message.tree_hash_root().0;
            (slot, parent, block.as_ssz_bytes())
        })
        .collect()
}

fn stamp() -> Stamp {
    let blocks = canonical();
    let at = |slot: u64| blocks.iter().find(|b| b.0 == slot).unwrap().1;
    Stamp {
        head_seq: 4,
        head_root: at(40),
        head_slot: 40,
        finalized_root: at(30),
        finalized_slot: 30,
    }
}

/// A store as a version-2 cl-chain left it: [`canonical`], head 40, finalized 30, and no
/// finalized slot index (no table, no from row; raw, as no writer path may).
fn v2_env(path: &Path) {
    let writer = test_writer(path).unwrap();
    let txn = txn::begin(&writer).unwrap();
    for (_, _, ssz) in canonical() {
        store_schema::blocks::put::<Minimal>(&txn, &schedule(), &ssz).unwrap();
    }
    txn::commit(txn, Update::New(stamp())).unwrap();
    let txn = writer.raw_env().begin_rw_txn().unwrap();
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

/// The store's stamp, index rows and from row, read once no writer has it open.
fn read(path: &Path) -> (Option<Stamp>, Vec<(u64, Root)>, Option<u64>) {
    let env = env::open_reader(path).unwrap();
    let txn = env::begin_reader_txn(&env).unwrap();
    let rows = (0..=40)
        .filter_map(|slot| {
            finalized::root_at(&txn, slot)
                .unwrap()
                .map(|root| (slot, root))
        })
        .collect();
    (
        stamp::read(&txn).unwrap(),
        rows,
        finalized::indexed_from(&txn).unwrap(),
    )
}

fn want(from: u64) -> Vec<(u64, Root)> {
    canonical()
        .into_iter()
        .filter(|b| (from..=30).contains(&b.0))
        .map(|b| (b.0, b.1))
        .collect()
}

/// A version-2 store is upgraded by the writer's open with nothing indexed, then backfilled
/// from its finalized block down in batches of at most 8 slots, one stamped commit each, the
/// stamp carried unchanged. A crash between two batches keeps the first: the next open goes on
/// from it, and ends with the index of an uninterrupted run. Once done, a further open commits
/// nothing.
#[test]
fn reopen_backfills_a_v2_env_in_bounded_batches() {
    let dir = tempfile::tempdir().unwrap();
    v2_env(dir.path());
    {
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(writer.index_finalized_batch(0, 8).unwrap(), Some(23));
        assert_eq!(writer.stamped_txns_committed(), 1);
    }
    assert_eq!(read(dir.path()), (Some(stamp()), want(23), Some(23)));

    {
        let writer = ColumnWriter::open(dir.path()).unwrap();
        assert_eq!(finalized_index::backfill(&writer, 0, 8).unwrap(), 3);
        assert_eq!(writer.stamped_txns_committed(), 3);
    }
    assert_eq!(read(dir.path()), (Some(stamp()), want(1), Some(1)));

    let writer = ColumnWriter::open(dir.path()).unwrap();
    assert_eq!(finalized_index::backfill(&writer, 0, 8).unwrap(), 0);
    assert_eq!(writer.rw_txns_committed(), 0, "nothing left to index");
}

/// The backfill stops at the floor it is given, the start of the block serve window.
#[test]
fn backfill_stops_at_the_window_floor() {
    let dir = tempfile::tempdir().unwrap();
    v2_env(dir.path());
    {
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let batches = finalized_index::backfill(&writer, 14, finalized_index::BACKFILL_BATCH);
        assert_eq!(batches.unwrap(), 1, "one batch of 8,192 slots");
    }
    assert_eq!(read(dir.path()), (Some(stamp()), want(14), Some(14)));
}

/// The floor is the first slot of the block serve window at the wall clock
/// (`network_config::window`), genesis before the window has a start.
#[test]
fn the_window_floor_follows_the_clock() {
    let chain = ProbeChain {
        config: ChainConfig::load(Network::Sepolia).unwrap(),
        genesis: Network::Sepolia.genesis().unwrap(),
        slots_per_epoch: 32,
    };
    let ms_per_epoch = u128::from(chain.config.slot_duration_ms() * 32);
    let at = |epoch: u64| {
        u128::from(chain.genesis.genesis_time) * 1000 + u128::from(epoch) * ms_per_epoch
    };
    assert_eq!(
        finalized_index::window_floor(&chain, 0),
        0,
        "before genesis"
    );
    assert_eq!(finalized_index::window_floor(&chain, at(100)), 0);
    for epoch in [40_000, 400_000] {
        let start = block_serve_window(&chain.config, epoch).unwrap();
        assert!(start > 0);
        assert_eq!(finalized_index::window_floor(&chain, at(epoch)), start * 32);
    }
}
