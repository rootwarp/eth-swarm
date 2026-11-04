//! Fills a store env with real data for `scripts/mdbx-chk-envs.sh`, which runs `mdbx_chk` on it.
//!
//! Usage: `cargo run --locked -p cl-chain-columns --example fill_env -- <env-dir>`
//!
//! Through the production writer paths only. First store-schema's: [`env::open_writer`], then
//! 256 Fulu blocks (Minimal preset, built and SSZ-encoded in code) stored with [`blocks::put`],
//! each committed with a new stamp ([`Update::New`]). That writer is dropped and a
//! [`ColumnWriter`] opens the same env: the 128 SSZ `DataColumnSidecar`s of every fourth block
//! go through [`ColumnWriter::write_block_columns`] (16 per write txn, each carrying the
//! stamp), each block linked to the one written before it. Then
//! [`ColumnWriter::prune_finalized`] deletes the columns of the first 16 slots, so the env also
//! holds freed pages.

#[path = "../../store-schema/tests/common/mod.rs"]
mod common;

use std::error::Error;

use cl_chain_columns::{
    BlockLink, Column, ColumnWriter, WriterOptions, MIN_MAX_SIZE, NUMBER_OF_COLUMNS,
};
use store_schema::{
    blocks, env,
    keys::Root,
    stamp::{self, Stamp},
    txn::{self, Update},
};

const BLOCKS: u64 = 256;
const FINALIZED_PRUNE_SLOT: u64 = 16;

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::args_os()
        .nth(1)
        .ok_or("usage: fill_env <env-dir>")?;
    let opts = WriterOptions {
        max_size: MIN_MAX_SIZE,
    };
    let schedule = common::schedule();
    let mut chain: Vec<(u64, Root)> = Vec::new();
    let mut with_columns = Vec::new();
    {
        let writer = env::open_writer(dir.as_ref(), opts)?;
        let mut parent = [0; 32];
        for i in 0..BLOCKS {
            let block = common::fulu_block(i + 1, parent, i);
            let (ssz, _) = common::fulu_block_ssz(i + 1, parent, i);
            let txn = writer.begin_rw_txn()?;
            let (slot, root) = blocks::put::<common::E>(&txn, &schedule, &ssz)?;
            chain.push((slot, root));
            let (finalized_slot, finalized_root) = chain[chain.len().saturating_sub(65)];
            let stamp = Stamp {
                head_seq: i + 1,
                head_root: root,
                head_slot: slot,
                finalized_root,
                finalized_slot,
            };
            txn::commit(txn, Update::New(stamp))?;
            if i % 4 == 0 {
                with_columns.push((slot, root, block));
            }
            parent = root;
        }
    }

    let writer = ColumnWriter::open_with(&dir, opts)?;
    let mut link = BlockLink::Start;
    let mut written = 0;
    for (slot, root, block) in &with_columns {
        let sidecars: Vec<Vec<u8>> = (0..NUMBER_OF_COLUMNS)
            .map(|index| common::fulu_sidecar(block, index))
            .collect();
        let columns: Vec<Column<'_>> = sidecars
            .iter()
            .zip(0..)
            .map(|(ssz, index)| Column { index, ssz })
            .collect();
        written += writer
            .write_block_columns(*slot, root, link, &columns)?
            .columns;
        link = BlockLink::Parent(*root);
    }
    let pruned = writer.prune_finalized(FINALIZED_PRUNE_SLOT)?;
    if pruned.columns == 0 {
        return Err("the prune removed no column".into());
    }
    if writer.stamped_txns_committed() != writer.rw_txns_committed() {
        return Err("a column txn did not carry the stamp".into());
    }
    let columns = writer.reader().column_count()?;
    if columns != written as u64 - pruned.columns {
        return Err(format!("{columns} columns stored, {written} written").into());
    }
    drop(writer);

    let reader = env::open_reader(dir.as_ref())?;
    let head = stamp::read(&reader.begin_ro_txn()?)?.ok_or("no stamp")?;
    println!(
        "filled {}: {BLOCKS} blocks, {columns} columns, head slot {}, finalized slot {}",
        dir.to_string_lossy(),
        head.head_slot,
        head.finalized_slot
    );
    Ok(())
}
