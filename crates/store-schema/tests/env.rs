//! The store-schema env: shared options, every table, the single writer and the schema version.
//!
//! Cross-process cases re-run this test binary as a child, selected by `CHILD_MODE`. Every test
//! runs under [`serial`]: MDBX locks with open-file-description locks, and a child spawned by
//! one test must not inherit another test's lock fds between fork and exec (see
//! cl-chain-columns' `tests/sole_writer.rs`).

mod common;

use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex, MutexGuard, PoisonError,
    },
    thread,
    time::Duration,
};

use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ReadWriteOptions, SyncMode, Transaction,
    TransactionKind, WriteFlags,
};
use store_schema::{
    blocks,
    env::{self, WriterOptions, DEFAULT_MAX_SIZE},
    keys::{decode_slot_root_key, slot_root_key, Root, SCHEMA_VERSION_KEY, STAMP_KEY},
    stamp::{self, Stamp},
    tables::{
        BLOCKS, BLOCK_INDEX, COLUMNS, COLUMN_LINKS, COLUMN_ROOTS, ENVELOPES, FC_SNAPSHOT,
        MAX_TABLES, META, STATES, TABLES,
    },
    txn::{self, Update},
    version::SCHEMA_VERSION,
    Error,
};

const CHILD_MODE: &str = "STORE_SCHEMA_CHILD_MODE";
const CHILD_PATH: &str = "STORE_SCHEMA_CHILD_PATH";
const READY: &str = "STORE_SCHEMA_CHILD_READY";
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn opts() -> WriterOptions {
    WriterOptions::default()
}

fn child(mode: &str, path: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env(CHILD_MODE, mode)
        .env(CHILD_PATH, path);
    command
}

/// A child that has opened something and holds it until its stdin closes.
struct Holder(std::process::Child);

impl Holder {
    /// Spawns `mode` and waits (at most [`CHILD_DEADLINE`]) until it prints [`READY`].
    fn start(mode: &str, path: &Path) -> Self {
        let mut process = child(mode, path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = process.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            let _ = tx.send(lines.any(|l| l.is_ok_and(|l| l.contains(READY))));
            lines.for_each(drop);
        });
        let mut holder = Self(process);
        if rx.recv_timeout(CHILD_DEADLINE) != Ok(true) {
            holder.kill();
            panic!("{mode} child never got ready");
        }
        holder
    }

    /// Closes the child's stdin and waits for it.
    fn release(mut self) -> ExitStatus {
        drop(self.0.stdin.take());
        self.0.wait().unwrap()
    }

    fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            self.kill();
        }
    }
}

fn run_child(mode: &str, path: &Path) -> ExitStatus {
    child(mode, path).status().unwrap()
}

/// Runs only when spawned by a test of this binary; a normal run passes straight through.
#[test]
fn child_entry() {
    let (Ok(mode), Ok(path)) = (std::env::var(CHILD_MODE), std::env::var(CHILD_PATH)) else {
        return;
    };
    let hold = || {
        println!("{READY}");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
    };
    match mode.as_str() {
        "second-writer" => {
            let err = env::open_writer(Path::new(&path), opts()).unwrap_err();
            assert!(matches!(err, Error::WriterHeld { .. }), "{err:?}");
        }
        "hold-writer" => {
            let _writer = env::open_writer(Path::new(&path), opts()).unwrap();
            hold();
        }
        "hold-safe-nosync" => {
            let _env = raw_open(Path::new(&path), SyncMode::SafeNoSync).unwrap();
            hold();
        }
        // cl-store's side of `meta_row_in_commit`: RO txns in another process until stdin
        // closes, each checked with `stamp_agrees_with_blocks`.
        "stamp-reader" => {
            let reader = env::open_reader(Path::new(&path)).unwrap();
            let done = Arc::new(AtomicBool::new(false));
            let stdin_closed = Arc::clone(&done);
            thread::spawn(move || {
                let _ = std::io::stdin().read_to_end(&mut Vec::new());
                stdin_closed.store(true, Ordering::SeqCst);
            });
            println!("{READY}");
            std::io::stdout().flush().unwrap();
            let mut stamped = 0u64;
            while !done.load(Ordering::SeqCst) {
                let txn = reader.begin_ro_txn().unwrap();
                stamped += u64::from(stamp_agrees_with_blocks(&txn).is_some());
            }
            assert!(stamped > 0, "the reader never saw a stamp");
        }
        other => panic!("unknown child mode {other}"),
    }
}

/// `(max_tables, flags)` of an open env, from the C API.
fn env_settings(db: &Database<NoWriteMap>) -> (u64, u32) {
    let ptr = db.ptr().0;
    let mut max_tables = 0;
    let mut flags = 0;
    // SAFETY: `ptr` is the live env of `db`; both calls only read its options.
    unsafe {
        assert_eq!(
            mdbx_sys::mdbx_env_get_option(ptr, mdbx_sys::MDBX_opt_max_db, &mut max_tables),
            0
        );
        assert_eq!(mdbx_sys::mdbx_env_get_flags(ptr, &mut flags), 0);
    }
    (max_tables, flags)
}

/// A meta row, read through a fresh writer env.
fn meta_row(db: &Database<NoWriteMap>, key: &[u8]) -> Option<Vec<u8>> {
    let txn = db.begin_ro_txn().unwrap();
    let meta = txn.open_table(Some(META)).unwrap();
    txn.get::<Vec<u8>>(&meta, key).unwrap()
}

fn put_meta(db: &Database<NoWriteMap>, key: &[u8], value: &[u8]) {
    let txn = db.begin_rw_txn().unwrap();
    let meta = txn.open_table(Some(META)).unwrap();
    txn.put(&meta, key, value, WriteFlags::UPSERT).unwrap();
    txn.commit().unwrap();
}

/// The env opened read-write with `sync_mode` and the writer's other options, bypassing
/// store-schema (and its writer guard): an older layout, or a foreign opener.
fn raw_open(path: &Path, sync_mode: SyncMode) -> libmdbx::Result<Database<NoWriteMap>> {
    Database::<NoWriteMap>::open_with_options(
        path,
        DatabaseOptions {
            max_tables: Some(MAX_TABLES),
            mode: Mode::ReadWrite(ReadWriteOptions {
                sync_mode,
                max_size: Some(DEFAULT_MAX_SIZE as isize),
                growth_step: Some(256 << 20),
                ..ReadWriteOptions::default()
            }),
            ..DatabaseOptions::default()
        },
    )
}

/// The env opened read-only without store-schema's checks.
fn raw_reader(path: &Path) -> Database<NoWriteMap> {
    Database::<NoWriteMap>::open_with_options(
        path,
        DatabaseOptions {
            max_tables: Some(MAX_TABLES),
            mode: Mode::ReadOnly,
            ..DatabaseOptions::default()
        },
    )
    .unwrap()
}

/// The names in the main DB: every named table of the env.
fn table_names(db: &Database<NoWriteMap>) -> BTreeSet<String> {
    let txn = db.begin_ro_txn().unwrap();
    let main = txn.open_table(None).unwrap();
    let mut cursor = txn.cursor(&main).unwrap();
    let mut names = BTreeSet::new();
    let mut row = cursor.first::<Vec<u8>, ()>().unwrap();
    while let Some((name, ())) = row {
        names.insert(String::from_utf8(name).unwrap());
        row = cursor.next::<Vec<u8>, ()>().unwrap();
    }
    names
}

/// Every row of `table`, in key order.
fn rows(db: &Database<NoWriteMap>, table: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let txn = db.begin_ro_txn().unwrap();
    let handle = txn.open_table(Some(table)).unwrap();
    txn.cursor(&handle)
        .unwrap()
        .iter::<Vec<u8>, Vec<u8>>()
        .map(Result::unwrap)
        .collect()
}

/// A `columns` key: `slot BE ‖ root ‖ index BE`.
fn column_key(slot: u64, root: &Root, index: u64) -> Vec<u8> {
    [&slot_root_key(slot, root)[..], &index.to_be_bytes()].concat()
}

/// The #291 (schema version 1) layout, built by hand: its six tables, the version row 1 and
/// the tables in `extra`.
fn v1_env(path: &Path, extra: &[&str]) -> Database<NoWriteMap> {
    let db = raw_open(path, SyncMode::Durable).unwrap();
    let txn = db.begin_rw_txn().unwrap();
    for table in [COLUMNS, COLUMN_ROOTS, META, COLUMN_LINKS, BLOCKS, STATES]
        .iter()
        .chain(extra)
    {
        txn.create_table(Some(table), libmdbx::TableFlags::empty())
            .unwrap();
    }
    let meta = txn.open_table(Some(META)).unwrap();
    txn.put(
        &meta,
        SCHEMA_VERSION_KEY,
        1u64.to_be_bytes(),
        WriteFlags::UPSERT,
    )
    .unwrap();
    txn.commit().unwrap();
    db
}

/// What every reader asserts in one RO txn: the stamp row is valid ([`stamp::read`]: its head
/// and finalized blocks are stored), its head block is there, and no block is newer than its
/// head; with no stamp, no block at all.
fn stamp_agrees_with_blocks<K: TransactionKind>(
    txn: &Transaction<'_, K, NoWriteMap>,
) -> Option<Stamp> {
    let blocks = txn.open_table(Some(BLOCKS)).unwrap();
    let newest = txn
        .cursor(&blocks)
        .unwrap()
        .last::<Vec<u8>, ()>()
        .unwrap()
        .map(|(key, ())| decode_slot_root_key(&key).unwrap());
    let stamp = stamp::read(txn).expect("every snapshot holds a valid stamp or none");
    match stamp {
        None => assert_eq!(newest, None, "blocks committed without a stamp"),
        Some(stamp) => {
            let head = slot_root_key(stamp.head_slot, &stamp.head_root);
            assert!(
                txn.get::<()>(&blocks, &head).unwrap().is_some(),
                "the stamp's head block is missing"
            );
            let (slot, _) = newest.expect("a stamp without its blocks");
            assert!(
                slot <= stamp.head_slot,
                "a block at {slot} is newer than the stamp's head at {}",
                stamp.head_slot
            );
        }
    }
    stamp
}

#[test]
fn max_tables_before_create() {
    let _serial = serial();
    // Without `max_tables`, MDBX has no slot for a named table: why it is set before any create.
    let raw = tempfile::tempdir().unwrap();
    {
        let db = Database::<NoWriteMap>::open_with_options(raw.path(), DatabaseOptions::default())
            .unwrap();
        let txn = db.begin_rw_txn().unwrap();
        let err = txn
            .create_table(Some(BLOCKS), libmdbx::TableFlags::empty())
            .unwrap_err();
        assert!(matches!(err, libmdbx::Error::DbsFull), "{err:?}");
    }

    // The table names are the on-disk format: pinned.
    assert_eq!(
        TABLES,
        [
            "columns",
            "column_roots",
            "meta",
            "column_links",
            "blocks",
            "states",
            "block_index",
            "envelopes",
            "fc_snapshot"
        ]
    );
    assert_eq!(
        [
            COLUMNS,
            COLUMN_ROOTS,
            META,
            COLUMN_LINKS,
            BLOCKS,
            STATES,
            BLOCK_INDEX,
            ENVELOPES,
            FC_SNAPSHOT
        ],
        TABLES
    );
    // Headroom: later tables need no new max_tables.
    assert_eq!(MAX_TABLES, 16);
    assert!(TABLES.len() as u64 + 4 <= MAX_TABLES);

    let dir = tempfile::tempdir().unwrap();
    let writer = env::open_writer(dir.path(), opts()).unwrap();
    let (max_tables, flags) = env_settings(writer.env());
    assert_eq!(max_tables, MAX_TABLES);
    let no_sync =
        mdbx_sys::MDBX_NOMETASYNC | mdbx_sys::MDBX_SAFE_NOSYNC | mdbx_sys::MDBX_UTTERLY_NOSYNC;
    assert_eq!(
        flags & no_sync,
        0,
        "the writer env must be SyncMode::Durable"
    );
    assert_eq!(flags & mdbx_sys::MDBX_RDONLY, 0);
    {
        let txn = writer.env().begin_ro_txn().unwrap();
        for table in TABLES {
            txn.open_table(Some(table))
                .unwrap_or_else(|e| panic!("table {table} missing after the first open: {e}"));
        }
    }
    assert_eq!(
        meta_row(writer.env(), SCHEMA_VERSION_KEY),
        Some(SCHEMA_VERSION.to_be_bytes().to_vec())
    );
    drop(writer);

    // The reader shares the options: same max_tables, read-only, durable.
    let reader = env::open_reader(dir.path()).unwrap();
    let (max_tables, flags) = env_settings(&reader);
    assert_eq!(max_tables, MAX_TABLES);
    assert_ne!(
        flags & mdbx_sys::MDBX_RDONLY,
        0,
        "the reader is MDBX_RDONLY"
    );
    assert_eq!(flags & no_sync, 0);
}

#[test]
fn second_writer_refused() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let writer = env::open_writer(dir.path(), opts()).unwrap();

    // In this process.
    let err = env::open_writer(dir.path(), opts()).unwrap_err();
    assert!(
        matches!(err, Error::WriterHeld { ref path } if path == dir.path()),
        "{err:?}"
    );
    // In another process.
    assert!(run_child("second-writer", dir.path()).success());

    drop(writer);
    env::open_writer(dir.path(), opts()).expect("the guard goes with the writer");
}

#[test]
fn version_mismatch_refuses() {
    let _serial = serial();
    // Newer, and unknown (no version 0 was ever written).
    for stored in [SCHEMA_VERSION + 1, 0, u64::MAX] {
        let dir = tempfile::tempdir().unwrap();
        {
            let writer = env::open_writer(dir.path(), opts()).unwrap();
            put_meta(writer.env(), SCHEMA_VERSION_KEY, &stored.to_be_bytes());
        }
        let err = env::open_writer(dir.path(), opts()).unwrap_err();
        assert!(
            matches!(err, Error::SchemaVersion { found, supported }
                if found == stored && supported == SCHEMA_VERSION),
            "{err:?}"
        );
        let err = env::open_reader(dir.path()).unwrap_err();
        assert!(
            matches!(err, Error::SchemaVersion { found, .. } if found == stored),
            "{err:?}"
        );
        // The refused writer wrote nothing.
        let reader = Database::<NoWriteMap>::open_with_options(
            dir.path(),
            DatabaseOptions {
                max_tables: Some(MAX_TABLES),
                mode: Mode::ReadOnly,
                ..DatabaseOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            meta_row(&reader, SCHEMA_VERSION_KEY),
            Some(stored.to_be_bytes().to_vec())
        );
    }

    // A row that is no u64 at all.
    let dir = tempfile::tempdir().unwrap();
    {
        let writer = env::open_writer(dir.path(), opts()).unwrap();
        put_meta(writer.env(), SCHEMA_VERSION_KEY, b"\x01");
    }
    let err = env::open_writer(dir.path(), opts()).unwrap_err();
    assert!(
        matches!(err, Error::MalformedSchemaVersion { len: 1 }),
        "{err:?}"
    );
    let err = env::open_reader(dir.path()).unwrap_err();
    assert!(
        matches!(err, Error::MalformedSchemaVersion { len: 1 }),
        "{err:?}"
    );
}

/// cl-store's read-only open never opens `writer.guard`: it opens next to a live writer in
/// another process, and it never creates the guard.
#[test]
fn a_reader_never_takes_the_writer_guard() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    drop(env::open_writer(dir.path(), opts()).unwrap());

    let holder = Holder::start("hold-writer", dir.path());
    let reader = env::open_reader(dir.path()).expect("a reader opens next to a live writer");
    assert_eq!(
        meta_row(&reader, SCHEMA_VERSION_KEY),
        Some(SCHEMA_VERSION.to_be_bytes().to_vec())
    );
    drop(reader);
    assert!(holder.release().success());

    let guard_files = || {
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with("writer.guard"))
            .collect::<Vec<_>>()
    };
    assert!(!guard_files().is_empty(), "the writer made its guard");
    for name in guard_files() {
        std::fs::remove_file(dir.path().join(name)).unwrap();
    }
    let reader = env::open_reader(dir.path()).unwrap();
    drop(reader.begin_ro_txn().unwrap());
    drop(reader);
    assert_eq!(
        guard_files(),
        Vec::<String>::new(),
        "the RO path made a guard"
    );
}

/// An env cl-chain-columns wrote before store-schema (its four tables, no version row) is
/// upgraded in place by the first writer open: the new tables and the version row are added,
/// nothing is rewritten. A reader opens it before that, as it is.
#[test]
fn a_legacy_column_env_is_upgraded_in_place() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let legacy = [COLUMNS, COLUMN_ROOTS, META, COLUMN_LINKS];
    {
        let db = Database::<NoWriteMap>::open_with_options(
            dir.path(),
            DatabaseOptions {
                max_tables: Some(legacy.len() as u64),
                mode: Mode::ReadWrite(ReadWriteOptions {
                    sync_mode: SyncMode::Durable,
                    max_size: Some(DEFAULT_MAX_SIZE as isize),
                    growth_step: Some(256 << 20),
                    ..ReadWriteOptions::default()
                }),
                ..DatabaseOptions::default()
            },
        )
        .unwrap();
        let txn = db.begin_rw_txn().unwrap();
        for table in legacy {
            txn.create_table(Some(table), libmdbx::TableFlags::empty())
                .unwrap();
        }
        let meta = txn.open_table(Some(META)).unwrap();
        txn.put(&meta, b"cgc", 8u64.to_be_bytes(), WriteFlags::UPSERT)
            .unwrap();
        let columns = txn.open_table(Some(COLUMNS)).unwrap();
        txn.put(&columns, [7u8; 48], b"col", WriteFlags::UPSERT)
            .unwrap();
        txn.commit().unwrap();
    }

    let reader = env::open_reader(dir.path()).expect("no version row is no refusal");
    assert_eq!(meta_row(&reader, SCHEMA_VERSION_KEY), None);
    drop(reader);

    let mut created = Vec::new();
    let writer = env::open_writer_with(dir.path(), opts(), |_, new: &[&'static str]| {
        created = new.to_vec();
        Ok::<_, Error>(())
    })
    .unwrap();
    assert_eq!(
        created,
        [BLOCKS, STATES, BLOCK_INDEX, ENVELOPES, FC_SNAPSHOT]
    );
    assert_eq!(
        meta_row(writer.env(), SCHEMA_VERSION_KEY),
        Some(SCHEMA_VERSION.to_be_bytes().to_vec())
    );
    assert_eq!(
        meta_row(writer.env(), b"cgc"),
        Some(8u64.to_be_bytes().to_vec())
    );
    {
        let txn = writer.env().begin_ro_txn().unwrap();
        let columns = txn.open_table(Some(COLUMNS)).unwrap();
        assert_eq!(
            txn.get::<Vec<u8>>(&columns, &[7u8; 48]).unwrap(),
            Some(b"col".to_vec())
        );
    }
    drop(writer);

    let mut created = vec!["sentinel"];
    drop(
        env::open_writer_with(dir.path(), opts(), |_, new: &[&'static str]| {
            created = new.to_vec();
            Ok::<_, Error>(())
        })
        .unwrap(),
    );
    assert_eq!(
        created,
        Vec::<&str>::new(),
        "the second open creates nothing"
    );

    // A fresh env: every table is new.
    let fresh = tempfile::tempdir().unwrap();
    drop(
        env::open_writer_with(fresh.path(), opts(), |_, new: &[&'static str]| {
            created = new.to_vec();
            Ok::<_, Error>(())
        })
        .unwrap(),
    );
    assert_eq!(created, TABLES);
}

/// An error from the upgrade hook aborts the whole open: no table and no version row is
/// written, so the next open runs the hook again.
#[test]
fn a_failed_upgrade_writes_nothing() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let err = env::open_writer_with(dir.path(), opts(), |_, _| {
        Err(Error::Io(std::io::Error::other("upgrade failed")))
    })
    .unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    let mut created = Vec::new();
    drop(
        env::open_writer_with(dir.path(), opts(), |_, new: &[&'static str]| {
            created = new.to_vec();
            Ok::<_, Error>(())
        })
        .unwrap(),
    );
    assert_eq!(created, TABLES);
}

/// The version check reads only its own row: any other meta row opens. The stamp row is not
/// free-form any more (#130): the writer's open carries it ([`Update::Carry`]), so a stamp row
/// that is not a valid stamp refuses the writer and writes nothing.
#[test]
fn the_meta_table_has_room_for_the_stamp_row() {
    let _serial = serial();
    assert_eq!(STAMP_KEY, b"stamp");
    assert_eq!(SCHEMA_VERSION_KEY, b"schema_version");
    let dir = tempfile::tempdir().unwrap();
    {
        let writer = env::open_writer(dir.path(), opts()).unwrap();
        put_meta(writer.env(), b"a_row_of_some_later_version", b"?");
    }
    let writer = env::open_writer(dir.path(), opts()).expect("other meta rows are no version");
    assert_eq!(meta_row(writer.env(), STAMP_KEY), None);
    put_meta(writer.env(), STAMP_KEY, &[0xab; 80]);
    drop(writer);
    let err = env::open_writer(dir.path(), opts()).unwrap_err();
    assert!(matches!(err, Error::MalformedStamp { len: 80 }), "{err:?}");
    let reader = env::open_reader(dir.path()).expect("the reader ignores other rows");
    assert_eq!(meta_row(&reader, STAMP_KEY), Some(vec![0xab; 80]));
    let err = stamp::read(&reader.begin_ro_txn().unwrap()).unwrap_err();
    assert!(matches!(err, Error::MalformedStamp { len: 80 }), "{err:?}");
}

/// A2: a fresh env holds exactly the schema's tables, and the reader opens each of them.
#[test]
fn all_tables_created() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let writer = env::open_writer(dir.path(), opts()).unwrap();
    let want: BTreeSet<String> = [
        META,
        BLOCKS,
        BLOCK_INDEX,
        ENVELOPES,
        STATES,
        FC_SNAPSHOT,
        COLUMNS,
        COLUMN_ROOTS,
        COLUMN_LINKS,
    ]
    .map(String::from)
    .into();
    assert_eq!(table_names(writer.env()), want);
    assert_eq!(
        TABLES
            .map(String::from)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        want
    );
    drop(writer);
    let reader = env::open_reader(dir.path()).unwrap();
    let txn = reader.begin_ro_txn().unwrap();
    for table in &want {
        txn.open_table(Some(table)).unwrap();
    }
}

/// A4: every write txn commits exactly one stamp row with its data, and a concurrent reader,
/// in this process and in another, never sees blocks without their stamp or the reverse.
/// The writer thread commits 1,000 blocks, each with a new stamp, interleaved with column
/// chunk txns that carry the stamp.
#[test]
fn meta_row_in_commit() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let writer = env::open_writer(dir.path(), opts()).unwrap();
    let other_process = Holder::start("stamp-reader", dir.path());
    let db = writer.env();
    let done = AtomicBool::new(false);
    let seen = AtomicU64::new(0);
    thread::scope(|scope| {
        let reader = scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                let txn = db.begin_ro_txn().unwrap();
                seen.fetch_add(
                    u64::from(stamp_agrees_with_blocks(&txn).is_some()),
                    Ordering::SeqCst,
                );
            }
        });
        let schedule = common::schedule();
        let mut chain: Vec<(u64, Root)> = Vec::new();
        let mut parent = [0; 32];
        for i in 0..1000u64 {
            // A column chunk of the block before: carries that block's stamp, or none yet.
            if let Some(&(slot, root)) = chain.last() {
                let txn = db.begin_rw_txn().unwrap();
                let before = stamp::read(&txn).unwrap();
                let columns = txn.open_table(Some(COLUMNS)).unwrap();
                for index in (i % 8) * 16..(i % 8 + 1) * 16 {
                    let key = column_key(slot, &root, index);
                    txn.put(&columns, key, b"column", WriteFlags::UPSERT)
                        .unwrap();
                }
                assert_eq!(txn::commit(txn, Update::Carry).unwrap(), before);
            }
            let (ssz, _) = common::fulu_block_ssz(i + 1, parent, i);
            let txn = db.begin_rw_txn().unwrap();
            let (slot, root) = blocks::put::<common::E>(&txn, &schedule, &ssz).unwrap();
            chain.push((slot, root));
            let (finalized_slot, finalized_root) = chain[chain.len().saturating_sub(65)];
            let stamp = Stamp {
                head_seq: i + 1,
                head_root: root,
                head_slot: slot,
                finalized_root,
                finalized_slot,
            };
            assert_eq!(txn::commit(txn, Update::New(stamp)).unwrap(), Some(stamp));
            parent = root;
        }
        done.store(true, Ordering::SeqCst);
        reader.join().unwrap();
    });
    assert!(
        seen.load(Ordering::SeqCst) > 0,
        "the reader never saw a stamp"
    );
    assert!(
        other_process.release().success(),
        "the reader in another process failed"
    );
    let last = stamp::read(&db.begin_ro_txn().unwrap()).unwrap().unwrap();
    assert_eq!((last.head_seq, last.head_slot), (1000, 1000));
    assert_eq!(rows(db, BLOCKS).len(), 1000);
    assert_eq!(rows(db, BLOCK_INDEX).len(), 1000);
}

/// C1: a #291-era env (schema version 1, rows in every table) is upgraded in place by the
/// first writer open: the new tables are created, `block_index` is filled from `blocks` in
/// the same txn, the version row goes 1 → 2, the stamp is carried, and every old row reads
/// back byte-identical. A reader refuses the env until then.
#[test]
fn a_v1_env_is_upgraded_in_place_rows_identical() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let mut chain = Vec::new();
    {
        let db = v1_env(dir.path(), &[]);
        let txn = db.begin_rw_txn().unwrap();
        let table = |name| txn.open_table(Some(name)).unwrap();
        let (blocks_t, states, columns, roots, links, meta) = (
            table(BLOCKS),
            table(STATES),
            table(COLUMNS),
            table(COLUMN_ROOTS),
            table(COLUMN_LINKS),
            table(META),
        );
        let mut parent = [0; 32];
        for slot in [3u64, 4, 9] {
            let block = common::fulu_block(slot, parent, slot);
            let (ssz, root) = common::fulu_block_ssz(slot, parent, slot);
            txn.put(
                &blocks_t,
                slot_root_key(slot, &root),
                &ssz,
                WriteFlags::UPSERT,
            )
            .unwrap();
            txn.put(
                &states,
                slot_root_key(slot, &root),
                b"state",
                WriteFlags::UPSERT,
            )
            .unwrap();
            for index in [0u64, 5] {
                let sidecar = common::fulu_sidecar(&block, index);
                txn.put(
                    &columns,
                    column_key(slot, &root, index),
                    sidecar,
                    WriteFlags::UPSERT,
                )
                .unwrap();
            }
            txn.put(&roots, root, slot.to_be_bytes(), WriteFlags::UPSERT)
                .unwrap();
            txn.put(
                &links,
                root,
                [[1u8].as_slice(), &parent].concat(),
                WriteFlags::UPSERT,
            )
            .unwrap();
            chain.push((slot, root));
            parent = root;
        }
        let stamp = Stamp {
            head_seq: 3,
            head_root: chain[2].1,
            head_slot: 9,
            finalized_root: chain[0].1,
            finalized_slot: 3,
        };
        txn.put(&meta, STAMP_KEY, stamp.encode(), WriteFlags::UPSERT)
            .unwrap();
        txn.put(&meta, b"cgc", 8u64.to_be_bytes(), WriteFlags::UPSERT)
            .unwrap();
        txn.commit().unwrap();
    }
    let v1_tables = [COLUMNS, COLUMN_ROOTS, META, COLUMN_LINKS, BLOCKS, STATES];
    let before: Vec<_> = {
        let db = raw_reader(dir.path());
        v1_tables.iter().map(|t| rows(&db, t)).collect()
    };

    let err = env::open_reader(dir.path()).unwrap_err();
    assert!(matches!(err, Error::NeedsUpgrade { found: 1 }), "{err:?}");

    let mut created = Vec::new();
    let writer = env::open_writer_with(dir.path(), opts(), |_, new: &[&'static str]| {
        created = new.to_vec();
        Ok::<_, Error>(())
    })
    .unwrap();
    assert_eq!(created, [BLOCK_INDEX, ENVELOPES, FC_SNAPSHOT]);
    let db = writer.env();
    assert_eq!(
        meta_row(db, SCHEMA_VERSION_KEY),
        Some(SCHEMA_VERSION.to_be_bytes().to_vec())
    );
    assert_eq!(SCHEMA_VERSION, 2);
    for (table, old) in v1_tables.iter().zip(&before) {
        let mut new = rows(db, table);
        let mut old = old.clone();
        if *table == META {
            // The version row is the one row the upgrade rewrites.
            old.retain(|(k, _)| k != SCHEMA_VERSION_KEY);
            new.retain(|(k, _)| k != SCHEMA_VERSION_KEY);
        }
        assert_eq!(new, old, "table {table} changed");
    }
    let index: Vec<_> = chain
        .iter()
        .map(|(slot, root)| (root.to_vec(), slot.to_be_bytes().to_vec()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(rows(db, BLOCK_INDEX), index);
    assert_eq!(rows(db, ENVELOPES), vec![]);
    assert_eq!(rows(db, FC_SNAPSHOT), vec![]);
    let stamp = stamp::read(&db.begin_ro_txn().unwrap()).unwrap().unwrap();
    assert_eq!((stamp.head_slot, stamp.finalized_slot), (9, 3));
    drop(writer);

    let reader = env::open_reader(dir.path()).expect("a v2 env opens");
    drop(reader);
    let mut created = vec!["sentinel"];
    let writer = env::open_writer_with(dir.path(), opts(), |_, new: &[&'static str]| {
        created = new.to_vec();
        Ok::<_, Error>(())
    })
    .unwrap();
    assert_eq!(
        created,
        Vec::<&str>::new(),
        "the second open creates nothing"
    );
    assert_eq!(rows(writer.env(), BLOCK_INDEX), index);
}

/// A `blocks` key that is not `slot ‖ root` cannot be indexed: the upgrade refuses it and
/// writes nothing, so the env stays at version 1.
#[test]
fn a_v1_env_with_a_malformed_block_key_is_not_upgraded() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    {
        let db = v1_env(dir.path(), &[]);
        let txn = db.begin_rw_txn().unwrap();
        let blocks = txn.open_table(Some(BLOCKS)).unwrap();
        txn.put(&blocks, [7u8; 39], b"block", WriteFlags::UPSERT)
            .unwrap();
        txn.commit().unwrap();
    }
    let err = env::open_writer(dir.path(), opts()).unwrap_err();
    assert!(
        matches!(err, Error::Corrupt { table } if table == BLOCKS),
        "{err:?}"
    );
    let db = raw_reader(dir.path());
    assert!(!table_names(&db).contains(BLOCK_INDEX));
    assert_eq!(
        meta_row(&db, SCHEMA_VERSION_KEY),
        Some(1u64.to_be_bytes().to_vec())
    );
}

/// V1: a newer schema version refuses the writer and the reader, and the refused writer
/// neither upgrades nor downgrades anything: no table is created, the version row stays.
#[test]
fn newer_version_refused() {
    let _serial = serial();
    for stored in [SCHEMA_VERSION + 1, u64::MAX] {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = v1_env(dir.path(), &[]);
            put_meta(&db, SCHEMA_VERSION_KEY, &stored.to_be_bytes());
        }
        let names = table_names(&raw_reader(dir.path()));
        let err = env::open_writer(dir.path(), opts()).unwrap_err();
        assert!(
            matches!(err, Error::SchemaVersion { found, supported }
                if found == stored && supported == SCHEMA_VERSION),
            "{err:?}"
        );
        let err = env::open_reader(dir.path()).unwrap_err();
        assert!(
            matches!(err, Error::SchemaVersion { found, .. } if found == stored),
            "{err:?}"
        );
        let db = raw_reader(dir.path());
        assert_eq!(
            table_names(&db),
            names,
            "the refused writer created a table"
        );
        assert!(!names.contains(BLOCK_INDEX));
        assert_eq!(
            meta_row(&db, SCHEMA_VERSION_KEY),
            Some(stored.to_be_bytes().to_vec())
        );
    }
}

/// V1: a named table the schema does not know refuses the writer and the reader, and the
/// refused writer writes nothing (a v1 env stays v1, without the new tables).
#[test]
fn unknown_table_refused() {
    let _serial = serial();
    let unknown = |err: &Error| matches!(err, Error::UnknownTable { name } if name == "mystery");

    let dir = tempfile::tempdir().unwrap();
    drop(v1_env(dir.path(), &["mystery"]));
    let names = table_names(&raw_reader(dir.path()));
    let err = env::open_writer(dir.path(), opts()).unwrap_err();
    assert!(unknown(&err), "{err:?}");
    let db = raw_reader(dir.path());
    assert_eq!(table_names(&db), names);
    assert_eq!(
        meta_row(&db, SCHEMA_VERSION_KEY),
        Some(1u64.to_be_bytes().to_vec())
    );
    drop(db);

    let dir = tempfile::tempdir().unwrap();
    drop(env::open_writer(dir.path(), opts()).unwrap());
    {
        let db = raw_open(dir.path(), SyncMode::Durable).unwrap();
        let txn = db.begin_rw_txn().unwrap();
        txn.create_table(Some("mystery"), libmdbx::TableFlags::empty())
            .unwrap();
        txn.commit().unwrap();
    }
    let err = env::open_writer(dir.path(), opts()).unwrap_err();
    assert!(unknown(&err), "{err:?}");
    let err = env::open_reader(dir.path()).unwrap_err();
    assert!(unknown(&err), "{err:?}");
}

/// C4: no opener may mix sync modes on the env. While the writer (`Durable`) has it open in
/// another process, a `SafeNoSync` or `UtterlyNoSync` open is `MDBX_INCOMPATIBLE`; and while a
/// `SafeNoSync` opener holds it, the writer refuses the same way.
#[test]
fn mixed_sync_mode_refused() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    drop(env::open_writer(dir.path(), opts()).unwrap());

    let holder = Holder::start("hold-writer", dir.path());
    for mode in [SyncMode::SafeNoSync, SyncMode::UtterlyNoSync] {
        let err = raw_open(dir.path(), mode).unwrap_err();
        assert!(
            matches!(err, libmdbx::Error::Incompatible),
            "{mode:?}: {err:?}"
        );
    }
    assert!(holder.release().success());

    let holder = Holder::start("hold-safe-nosync", dir.path());
    let err = env::open_writer(dir.path(), opts()).unwrap_err();
    assert!(
        matches!(err, Error::Mdbx(libmdbx::Error::Incompatible)),
        "{err:?}"
    );
    assert!(holder.release().success());
    drop(env::open_writer(dir.path(), opts()).expect("a durable writer alone opens"));
}
