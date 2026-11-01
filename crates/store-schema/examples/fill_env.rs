//! Fills a store env with real data for `scripts/mdbx-chk-envs.sh`, which runs `mdbx_chk` on it.
//!
//! Usage: `cargo run --locked -p store-schema --example fill_env -- <env-dir>`
//!
//! Through the production writer paths: [`env::open_writer`], then 256 Fulu blocks (Minimal
//! preset, built and SSZ-encoded in code) stored with [`blocks::put`], each committed with a new
//! stamp ([`Update::New`]). Every fourth block gets 128 SSZ `DataColumnSidecar`s in 8 column
//! txns of 16 that carry the stamp ([`Update::Carry`]), as cl-chain-columns writes them. Then
//! one prune txn deletes the columns of the first 16 slots, so the env also holds freed pages.

#[path = "../tests/common/mod.rs"]
mod common;

use std::error::Error;

use libmdbx::WriteFlags;
use store_schema::{
    blocks,
    env::{self, WriterOptions, MIN_MAX_SIZE},
    keys::{slot_root_key, Root},
    stamp::{self, Stamp},
    tables::{COLUMNS, COLUMN_ROOTS},
    txn::{self, Update},
};

const BLOCKS: u64 = 256;
const COLUMNS_PER_BLOCK: u64 = 128;
const COLUMNS_PER_TXN: u64 = 16;
const PRUNED_BELOW_SLOT: u64 = 17;

fn column_key(slot: u64, root: &Root, index: u64) -> Vec<u8> {
    [&slot_root_key(slot, root)[..], &index.to_be_bytes()].concat()
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::args_os()
        .nth(1)
        .ok_or("usage: fill_env <env-dir>")?;
    let writer = env::open_writer(
        dir.as_ref(),
        WriterOptions {
            max_size: MIN_MAX_SIZE,
        },
    )?;
    let db = writer.env();
    let schedule = common::schedule();
    let mut chain: Vec<(u64, Root)> = Vec::new();
    let (mut parent, mut columns) = ([0; 32], 0u64);
    for i in 0..BLOCKS {
        let block = common::fulu_block(i + 1, parent, i);
        let (ssz, _) = common::fulu_block_ssz(i + 1, parent, i);
        let txn = db.begin_rw_txn()?;
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
        parent = root;
        if i % 4 != 0 {
            continue;
        }
        for chunk in 0..COLUMNS_PER_BLOCK / COLUMNS_PER_TXN {
            let txn = db.begin_rw_txn()?;
            let table = txn.open_table(Some(COLUMNS))?;
            for index in chunk * COLUMNS_PER_TXN..(chunk + 1) * COLUMNS_PER_TXN {
                let sidecar = common::fulu_sidecar(&block, index);
                txn.put(
                    &table,
                    column_key(slot, &root, index),
                    sidecar,
                    WriteFlags::UPSERT,
                )?;
                columns += 1;
            }
            let roots = txn.open_table(Some(COLUMN_ROOTS))?;
            txn.put(&roots, root, slot.to_be_bytes(), WriteFlags::UPSERT)?;
            if txn::commit(txn, Update::Carry)? != Some(stamp) {
                return Err("a column txn did not carry the stamp".into());
            }
        }
    }
    let txn = db.begin_rw_txn()?;
    let table = txn.open_table(Some(COLUMNS))?;
    let roots = txn.open_table(Some(COLUMN_ROOTS))?;
    let mut pruned = 0u64;
    for (slot, root) in chain.iter().filter(|(slot, _)| *slot < PRUNED_BELOW_SLOT) {
        for index in 0..COLUMNS_PER_BLOCK {
            pruned += u64::from(txn.del(&table, column_key(*slot, root, index), None)?);
        }
        txn.del(&roots, root, None)?;
    }
    txn::commit(txn, Update::Carry)?;
    let head = stamp::read(&db.begin_ro_txn()?)?.ok_or("no stamp")?;
    println!(
        "filled {}: {BLOCKS} blocks, {} columns, head slot {}, finalized slot {}",
        dir.to_string_lossy(),
        columns - pruned,
        head.head_slot,
        head.finalized_slot
    );
    Ok(())
}
