//! Import latency while the low-priority task writes columns.
//!
//! Three runs on fresh Durable envs, same data, same key layout, columns written back to back
//! (the catch-up worst case):
//! - `chunked`: [`ColumnWriter::write_columns`], at most 16 columns per write txn, import
//!   priority between txns. This is the store.
//! - `single-locked`: one 128-column txn per block behind an import-first lock like the
//!   store's (raw libmdbx); isolates the effect of the chunk size.
//! - `single-raw`: one 128-column txn per block and no lock, so import races libmdbx's own
//!   write-txn begin, which sleeps 250 ms on `MDBX_BUSY`.
//!
//! While the column thread runs, an "import" thread commits one tiny write txn about every
//! millisecond and records how long each took from the call to commit return (waiting for the
//! write lock included). The p99 of that is the number the chunk size exists for.
//!
//! ```text
//! cargo run --release -p cl-chain-columns --example write_bench
//! BENCH_BLOCKS=1024 BENCH_BLOBS=21 cargo run --release -p cl-chain-columns --example write_bench
//! ```

use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};

use cl_chain_columns::{
    keys::{column_key, BlockRoot, CGC_KEY, COLUMNS_TABLE, META_TABLE, ROOTS_TABLE, TABLES},
    Column, ColumnWriter, MAX_COLUMNS_PER_TXN, NUMBER_OF_COLUMNS,
};
use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ReadWriteOptions, SyncMode, TableFlags, WriteFlags,
};

const IMPORT_INTERVAL: Duration = Duration::from_millis(1);
/// Blocks rotate over this many slots and overwrite older rows, so the env (and the disk it
/// takes) stays bounded however many blocks a run writes.
const SLOT_WINDOW: u64 = 64;

/// Serialized size of a Fulu `DataColumnSidecar` with `blobs` blobs: fixed part (index, three
/// offsets, signed header, inclusion proof) plus one cell, commitment and proof per blob.
fn sidecar_len(blobs: usize) -> usize {
    8 + 3 * 4 + 208 + 4 * 32 + blobs * (2048 + 48 + 48)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .map(|v| {
            v.parse()
                .unwrap_or_else(|_| panic!("{name} must be an integer"))
        })
        .unwrap_or(default)
}

fn block_root(slot: u64) -> BlockRoot {
    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&slot.to_be_bytes());
    root
}

/// Stand-in for block import: anything that needs the env's single write lock.
trait Store: Send + Sync {
    fn write_block(&self, slot: u64, columns: &[Vec<u8>]);
    fn import_txn(&self);
}

struct Chunked(ColumnWriter);

impl Store for Chunked {
    fn write_block(&self, slot: u64, columns: &[Vec<u8>]) {
        let columns: Vec<Column<'_>> = (0..)
            .zip(columns)
            .map(|(index, ssz)| Column { index, ssz })
            .collect();
        self.0
            .write_columns(slot, &block_root(slot), &columns)
            .unwrap();
    }

    fn import_txn(&self) {
        self.0.set_cgc(4).unwrap();
    }
}

/// Baseline: one write txn per block. With `locked`, txns take the same import-priority lock
/// as [`ColumnWriter`]; without it, threads race for MDBX's write lock directly.
struct SingleTxn {
    db: Database<NoWriteMap>,
    locked: bool,
    txn_lock: Mutex<()>,
    import_waiting: AtomicUsize,
}

impl SingleTxn {
    fn open(path: &Path, locked: bool) -> Self {
        let db = Database::<NoWriteMap>::open_with_options(
            path,
            DatabaseOptions {
                max_tables: Some(TABLES.len() as u64),
                mode: Mode::ReadWrite(ReadWriteOptions {
                    sync_mode: SyncMode::Durable,
                    max_size: Some(256 << 30),
                    growth_step: Some(256 << 20),
                    ..ReadWriteOptions::default()
                }),
                ..DatabaseOptions::default()
            },
        )
        .unwrap();
        let txn = db.begin_rw_txn().unwrap();
        for table in TABLES {
            txn.create_table(Some(table), TableFlags::empty()).unwrap();
        }
        txn.commit().unwrap();
        Self {
            db,
            locked,
            txn_lock: Mutex::new(()),
            import_waiting: AtomicUsize::new(0),
        }
    }

    fn lock(&self, import: bool) -> Option<MutexGuard<'_, ()>> {
        if !self.locked {
            return None;
        }
        if import {
            self.import_waiting.fetch_add(1, Ordering::SeqCst);
            let guard = self.txn_lock.lock().unwrap();
            self.import_waiting.fetch_sub(1, Ordering::SeqCst);
            return Some(guard);
        }
        loop {
            while self.import_waiting.load(Ordering::SeqCst) > 0 {
                thread::yield_now();
            }
            let guard = self.txn_lock.lock().unwrap();
            if self.import_waiting.load(Ordering::SeqCst) == 0 {
                return Some(guard);
            }
        }
    }
}

impl Store for SingleTxn {
    fn write_block(&self, slot: u64, columns: &[Vec<u8>]) {
        let root = block_root(slot);
        let _lock = self.lock(false);
        let txn = self.db.begin_rw_txn().unwrap();
        {
            let roots = txn.open_table(Some(ROOTS_TABLE)).unwrap();
            txn.put(&roots, root, slot.to_be_bytes(), WriteFlags::UPSERT)
                .unwrap();
            let table = txn.open_table(Some(COLUMNS_TABLE)).unwrap();
            for (index, ssz) in (0..).zip(columns) {
                txn.put(
                    &table,
                    column_key(slot, &root, index),
                    ssz,
                    WriteFlags::UPSERT,
                )
                .unwrap();
            }
        }
        txn.commit().unwrap();
    }

    fn import_txn(&self) {
        let _lock = self.lock(true);
        let txn = self.db.begin_rw_txn().unwrap();
        {
            let meta = txn.open_table(Some(META_TABLE)).unwrap();
            txn.put(&meta, CGC_KEY, 4u64.to_be_bytes(), WriteFlags::UPSERT)
                .unwrap();
        }
        txn.commit().unwrap();
    }
}

struct Run {
    write_time: Duration,
    import_ms: Vec<f64>,
}

fn run(store: Arc<dyn Store>, blocks: u64, columns: &[Vec<u8>]) -> Run {
    let done = Arc::new(AtomicBool::new(false));
    let importer = {
        let (store, done) = (Arc::clone(&store), Arc::clone(&done));
        thread::spawn(move || {
            let mut import_ms = Vec::new();
            while !done.load(Ordering::Relaxed) {
                let start = Instant::now();
                store.import_txn();
                import_ms.push(start.elapsed().as_secs_f64() * 1e3);
                thread::sleep(IMPORT_INTERVAL);
            }
            import_ms
        })
    };
    let start = Instant::now();
    for block in 0..blocks {
        store.write_block(block % SLOT_WINDOW, columns);
    }
    let write_time = start.elapsed();
    done.store(true, Ordering::Relaxed);
    Run {
        write_time,
        import_ms: importer.join().unwrap(),
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn report(name: &str, txns_per_block: u64, blocks: u64, column_bytes: usize, mut run: Run) {
    run.import_ms.sort_by(f64::total_cmp);
    let ms = &run.import_ms;
    let mib =
        (blocks as usize * NUMBER_OF_COLUMNS as usize * column_bytes) as f64 / (1 << 20) as f64;
    let secs = run.write_time.as_secs_f64();
    println!(
        "{name:<13} | {txns_per_block:>4} | {:>8.1} | {:>7.1} | {:>6} | {:>7.2} | {:>7.2} | {:>7.2}",
        secs * 1e3 / blocks as f64,
        mib / secs,
        ms.len(),
        percentile(ms, 0.50),
        percentile(ms, 0.99),
        ms[ms.len() - 1],
    );
}

fn main() {
    let blocks = env_u64("BENCH_BLOCKS", 1024);
    let blobs = env_u64("BENCH_BLOBS", 21) as usize;
    let column_bytes = sidecar_len(blobs);
    let columns: Vec<Vec<u8>> = (0..NUMBER_OF_COLUMNS)
        .map(|i| (0..column_bytes).map(|b| (b as u64 ^ i) as u8).collect())
        .collect();

    println!(
        "write_bench: {} {}, SyncMode::Durable, {blocks} blocks x {NUMBER_OF_COLUMNS} columns x \
         {column_bytes} B ({blobs} blobs), import txn every {IMPORT_INTERVAL:?}",
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    println!("mode          | txn/ | ms/block | MiB/s   | import | p50 ms  | p99 ms  | max ms");
    println!("              | blk  |          |         | txns   |         |         |");

    let chunked_dir = tempfile::tempdir().unwrap();
    let chunked = Arc::new(Chunked(ColumnWriter::open(chunked_dir.path()).unwrap()));
    let chunk_txns = NUMBER_OF_COLUMNS.div_ceil(MAX_COLUMNS_PER_TXN as u64);
    report(
        "chunked",
        chunk_txns,
        blocks,
        column_bytes,
        run(chunked, blocks, &columns),
    );

    for (name, locked) in [("single-locked", true), ("single-raw", false)] {
        let dir = tempfile::tempdir().unwrap();
        let single = Arc::new(SingleTxn::open(dir.path(), locked));
        report(name, 1, blocks, column_bytes, run(single, blocks, &columns));
    }
}
