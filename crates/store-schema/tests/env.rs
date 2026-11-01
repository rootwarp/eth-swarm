//! The store-schema env: shared options, every table, the single writer and the schema version.
//!
//! Cross-process cases re-run this test binary as a child, selected by `CHILD_MODE`. Every test
//! runs under [`serial`]: MDBX locks with open-file-description locks, and a child spawned by
//! one test must not inherit another test's lock fds between fork and exec (see
//! cl-chain-columns' `tests/sole_writer.rs`).

use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    sync::{mpsc, Mutex, MutexGuard, PoisonError},
    thread,
    time::Duration,
};

use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ReadWriteOptions, SyncMode, WriteFlags,
};
use store_schema::{
    env::{self, WriterOptions, DEFAULT_MAX_SIZE},
    keys::{SCHEMA_VERSION_KEY, STAMP_KEY},
    tables::{BLOCKS, COLUMNS, COLUMN_LINKS, COLUMN_ROOTS, MAX_TABLES, META, STATES, TABLES},
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
            "states"
        ]
    );
    assert_eq!(
        [COLUMNS, COLUMN_ROOTS, META, COLUMN_LINKS, BLOCKS, STATES],
        TABLES
    );
    // Headroom: #130's tables (block_index, envelopes, ...) need no new max_tables.
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
    assert_eq!(created, [BLOCKS, STATES]);
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

/// #130 adds a head/finalized stamp row to every commit under [`STAMP_KEY`], with no
/// migration: the version check reads only its own row, so any other meta row, of any length,
/// opens.
#[test]
fn the_meta_table_has_room_for_the_stamp_row() {
    let _serial = serial();
    assert_eq!(STAMP_KEY, b"stamp");
    assert_eq!(SCHEMA_VERSION_KEY, b"schema_version");
    let dir = tempfile::tempdir().unwrap();
    {
        let writer = env::open_writer(dir.path(), opts()).unwrap();
        put_meta(writer.env(), STAMP_KEY, &[0xab; 80]);
        put_meta(writer.env(), b"a_row_of_some_later_version", b"?");
    }
    let writer = env::open_writer(dir.path(), opts()).expect("other meta rows are no version");
    assert_eq!(meta_row(writer.env(), STAMP_KEY), Some(vec![0xab; 80]));
    drop(writer);
    let reader = env::open_reader(dir.path()).expect("the reader ignores them too");
    assert_eq!(meta_row(&reader, STAMP_KEY), Some(vec![0xab; 80]));
}
