//! cl-chain is the only writer of the column env: one `ColumnWriter` per env across every
//! process, and readers (cl-store) open it read-only.
//!
//! Cross-process cases re-run this test binary as a child, selected by `CHILD_MODE`.
//!
//! Every test here runs under [`serial`]. MDBX locks its files with open-file-description
//! (OFD) locks, and a child spawned by one test briefly holds a copy of every fd of this
//! process (from the fork until exec closes the `O_CLOEXEC` ones), the open file descriptions
//! and their locks included. A test that closes an env and reopens it while another test spawns
//! a child can then find its own released lock still held, and fail with
//! `WriterAlreadyOpen` (seen under full-workspace load). Spawning and reopening never overlap
//! once the tests are serialized.

use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    sync::{mpsc, Mutex, MutexGuard, PoisonError},
    thread,
    time::{Duration, Instant},
};

use cl_chain_columns::{BlockLink, Column, ColumnReader, ColumnWriter, Error, WriterOptions};

const CHILD_MODE: &str = "CL_CHAIN_COLUMNS_CHILD_MODE";
const CHILD_PATH: &str = "CL_CHAIN_COLUMNS_CHILD_PATH";
const ROOT: [u8; 32] = [0x11; 32];

const READY: &str = "CL_CHAIN_COLUMNS_CHILD_READY";

/// A block the `migrate-and-link` child stores linked to [`ROOT`].
const LINKED: [u8; 32] = [0x22; 32];

/// How long a child may take to get ready, or to exit, before it is killed.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);

static SERIAL: Mutex<()> = Mutex::new(());

/// Serializes the tests of this binary (see the module docs); a failed test does not poison it.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A spawned child, killed and reaped if it is still running when dropped (a failed assertion
/// never leaves it behind).
struct Child(std::process::Child);

impl Child {
    fn spawn(command: &mut Command) -> Self {
        Self(command.spawn().unwrap())
    }

    /// Waits until the child prints [`READY`] on its piped stdout; kills it if it has not
    /// within `timeout`, or exits first.
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), String> {
        let stdout = self.0.stdout.take().expect("stdout is piped");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            // libtest may print "test child_entry ... " on the same line first.
            let ready = lines.any(|line| line.is_ok_and(|l| l.contains(READY)));
            let _ = tx.send(ready);
            // Keep draining, so the child's later output never meets a closed pipe.
            lines.for_each(drop);
        });
        match rx.recv_timeout(timeout) {
            Ok(true) => Ok(()),
            outcome => {
                self.kill();
                Err(match outcome {
                    Ok(_) => "child exited before it was ready".to_owned(),
                    Err(_) => format!("child not ready within {timeout:?}; killed"),
                })
            }
        }
    }

    /// The child's exit status; kills it if it has not exited within `timeout`.
    fn wait(&mut self, timeout: Duration) -> Result<ExitStatus, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.kill();
                return Err(format!("child did not exit within {timeout:?}; killed"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn has_exited(&mut self) -> bool {
        self.0.try_wait().unwrap().is_some()
    }

    fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.has_exited() {
            self.kill();
        }
    }
}

fn child(mode: &str, path: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env(CHILD_MODE, mode)
        .env(CHILD_PATH, path);
    command
}

fn run_child(mode: &str, path: &Path) -> ExitStatus {
    Child::spawn(&mut child(mode, path))
        .wait(CHILD_DEADLINE)
        .unwrap()
}

/// Runs only when spawned by `run_child`; a normal test run passes it straight through.
#[test]
fn child_entry() {
    let (Ok(mode), Ok(path)) = (std::env::var(CHILD_MODE), std::env::var(CHILD_PATH)) else {
        return;
    };
    match mode.as_str() {
        "second-writer" => {
            let err = ColumnWriter::open(&path).unwrap_err();
            assert!(matches!(err, Error::WriterAlreadyOpen { .. }), "{err:?}");
        }
        "reader" => {
            let reader = ColumnReader::open(&path).unwrap();
            assert_eq!(reader.get(&ROOT, 3).unwrap(), Some(b"col-3".to_vec()));
            assert_eq!(reader.cgc().unwrap(), Some(8));
        }
        "hold-reader" => {
            let _reader = ColumnReader::open(&path).unwrap();
            println!("{READY}");
            std::io::stdout().flush().unwrap();
            // Hold the env open until the parent closes stdin.
            std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
        }
        "hang" => loop {
            std::thread::park();
        },
        "migrate-and-link" => {
            let writer = ColumnWriter::open(&path).unwrap();
            writer
                .write_block_columns(
                    11,
                    &LINKED,
                    BlockLink::Parent(ROOT),
                    &[Column {
                        index: 3,
                        ssz: b"linked",
                    }],
                )
                .unwrap();
        }
        "writer-then-crash" => {
            let _writer = ColumnWriter::open(&path).unwrap();
            std::process::abort();
        }
        other => panic!("unknown child mode {other}"),
    }
}

#[test]
fn second_writer_in_the_same_process_is_refused() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let writer = ColumnWriter::open(dir.path()).unwrap();
    let err = ColumnWriter::open(dir.path()).unwrap_err();
    assert!(matches!(err, Error::WriterAlreadyOpen { .. }), "{err:?}");

    drop(writer);
    ColumnWriter::open(dir.path()).expect("the guard is released when the writer drops");
}

#[test]
fn writers_of_different_envs_do_not_conflict() {
    let _serial = serial();
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let _wa = ColumnWriter::open(a.path()).unwrap();
    let _wb = ColumnWriter::open(b.path()).unwrap();
}

#[test]
fn second_writer_in_another_process_is_refused_while_readers_read() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let writer = ColumnWriter::open(dir.path()).unwrap();
    writer
        .write_columns(
            9,
            &ROOT,
            &[Column {
                index: 3,
                ssz: b"col-3",
            }],
        )
        .unwrap();
    writer.set_cgc(8).unwrap();

    assert!(run_child("second-writer", dir.path()).success());
    assert!(run_child("reader", dir.path()).success());
}

#[test]
fn a_crashed_writer_leaves_no_stale_lock() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    assert!(!run_child("writer-then-crash", dir.path()).success());
    ColumnWriter::open(dir.path()).expect("the OS released the dead writer's guard");
}

#[test]
fn a_map_size_change_blocked_by_an_open_reader_is_an_error() {
    let _serial = serial();
    const MIB_256: usize = 256 << 20;
    let dir = tempfile::tempdir().unwrap();
    let small = WriterOptions { max_size: MIB_256 };
    let large = WriterOptions {
        max_size: 2 * MIB_256,
    };
    drop(ColumnWriter::open_with(dir.path(), small).unwrap());

    let mut reader = Child::spawn(
        child("hold-reader", dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    );
    reader
        .wait_ready(CHILD_DEADLINE)
        .expect("reader child opens the env");

    // With cl-store attached, MDBX keeps the env's geometry: say so instead of ignoring it.
    let err = ColumnWriter::open_with(dir.path(), large).unwrap_err();
    assert!(
        matches!(
            err,
            Error::GeometryMismatch { requested, effective }
                if requested == 2 * MIB_256 && effective == MIB_256
        ),
        "{err:?}"
    );
    ColumnWriter::open_with(dir.path(), small).expect("the current geometry still opens");

    drop(reader.0.stdin.take());
    assert!(reader.wait(CHILD_DEADLINE).unwrap().success());
    ColumnWriter::open_with(dir.path(), large).expect("alone, the writer applies the new size");
}

#[test]
fn a_child_that_never_gets_ready_is_killed_at_the_deadline() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let mut hung = Child::spawn(child("hang", dir.path()).stdout(Stdio::piped()));
    let err = hung.wait_ready(Duration::from_millis(300)).unwrap_err();
    assert!(err.contains("not ready"), "{err}");
    assert!(hung.has_exited(), "the hung child was killed");
}

#[test]
fn a_child_that_never_exits_is_killed_at_the_deadline() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let mut hung = Child::spawn(&mut child("hang", dir.path()));
    let err = hung.wait(Duration::from_millis(300)).unwrap_err();
    assert!(err.contains("did not exit"), "{err}");
    assert!(hung.has_exited(), "the hung child was killed");
}

/// Makes the env at `path` look as one written before the links table existed: drops the table
/// and the contiguous-from slot, through MDBX itself.
fn make_legacy(path: &Path) {
    use cl_chain_columns::keys::{CONTIGUOUS_FROM_KEY, LINKS_TABLE, META_TABLE, TABLES};
    use libmdbx::{Database, DatabaseOptions, Mode, NoWriteMap, ReadWriteOptions, SyncMode};
    let db = Database::<NoWriteMap>::open_with_options(
        path,
        DatabaseOptions {
            max_tables: Some(TABLES.len() as u64),
            mode: Mode::ReadWrite(ReadWriteOptions {
                sync_mode: SyncMode::Durable,
                // The writer's geometry, so this open leaves it as it is.
                max_size: Some(cl_chain_columns::DEFAULT_MAX_SIZE as isize),
                growth_step: Some(256 << 20),
                ..ReadWriteOptions::default()
            }),
            ..DatabaseOptions::default()
        },
    )
    .unwrap();
    let txn = db.begin_rw_txn().unwrap();
    let links = txn.open_table(Some(LINKS_TABLE)).unwrap();
    // SAFETY: no other handle of the table is open in this process.
    unsafe { txn.drop_table(links).unwrap() };
    let meta = txn.open_table(Some(META_TABLE)).unwrap();
    let _ = txn.del(&meta, CONTIGUOUS_FROM_KEY, None);
    txn.commit().unwrap();
}

/// CR-005: a reader (cl-store) opened on an env without the links table reads the links a
/// writer in another process migrated and wrote after it opened, from its next snapshot on.
#[test]
fn a_reader_opened_before_the_migration_reads_links_after_it() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    {
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer
            .write_block_columns(
                9,
                &ROOT,
                BlockLink::Start,
                &[Column {
                    index: 3,
                    ssz: b"col-3",
                }],
            )
            .unwrap();
    }
    make_legacy(dir.path());
    let reader = ColumnReader::open(dir.path()).unwrap();
    assert_eq!(reader.link_of(&ROOT).unwrap(), Some(BlockLink::Gap));
    assert_eq!(reader.contiguous_from().unwrap(), Some(10));
    assert!(run_child("migrate-and-link", dir.path()).success());
    // The old block stays claimed past; the new one reads its link, not a legacy gap.
    assert_eq!(reader.contiguous_from().unwrap(), Some(10));
    assert_eq!(reader.link_of(&ROOT).unwrap(), Some(BlockLink::Gap));
    assert_eq!(
        reader.link_of(&LINKED).unwrap(),
        Some(BlockLink::Parent(ROOT))
    );
}
