//! The custody group count survives a killed cl-chain: a child process (this test binary,
//! selected by `CHILD_MODE`) opens the custody on a temp column env, changes it, says it is
//! ready and is then killed with SIGKILL; the parent reopens the same env.
//!
//! The tests run under [`serial`]: MDBX locks its files with open-file-description locks, and a
//! child spawned by one test briefly holds copies of this process's fds, so a reopen in another
//! test could find its own released lock still held (see `cl-chain-columns/tests/sole_writer.rs`).

use cl_chain::da::custody::{Advertise, Custody, CustodyError, EnrCgc, EnrError};
use cl_chain_columns::ColumnWriter;
use consensus_types::primitives::U256;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

const CHILD_MODE: &str = "CL_CHAIN_CUSTODY_CHILD_MODE";
const CHILD_PATH: &str = "CL_CHAIN_CUSTODY_CHILD_PATH";
const READY: &str = "CL_CHAIN_CUSTODY_CHILD_READY";
const CHILD_DEADLINE: Duration = Duration::from_secs(60);
/// A node id whose four custody groups are `[1, 47, 87, 102]`.
const NODE: U256 = U256::MAX;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The ENR `cgc` values the custody set, in order.
#[derive(Debug, Default)]
struct RecordedEnr(Vec<u64>);

impl EnrCgc for RecordedEnr {
    fn set_cgc(&mut self, cgc: u64) -> Result<(), EnrError> {
        self.0.push(cgc);
        Ok(())
    }
}

fn open(path: &Path, slot: u64) -> Custody<ColumnWriter, RecordedEnr> {
    let writer = ColumnWriter::open(path).unwrap();
    Custody::open(
        writer,
        RecordedEnr::default(),
        NODE,
        Advertise::Custody,
        slot,
    )
    .unwrap()
}

/// Runs the child in `mode` on `path` until it is ready, then kills it with SIGKILL.
fn run_and_kill(mode: &str, path: &Path) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env(CHILD_MODE, mode)
        .env(CHILD_PATH, path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        let ready = lines.any(|l| l.is_ok_and(|l| l.contains(READY)));
        let _ = tx.send(ready);
        lines.for_each(drop);
    });
    let ready = rx.recv_timeout(CHILD_DEADLINE);
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(ready, Ok(true), "the child never got ready");
}

/// Runs only when spawned by [`run_and_kill`]; a normal run passes straight through.
#[test]
fn child_entry() {
    let (Ok(mode), Ok(path)) = (std::env::var(CHILD_MODE), std::env::var(CHILD_PATH)) else {
        return;
    };
    let mut custody = open(Path::new(&path), 100);
    match mode.as_str() {
        "first-start" => {}
        "raise-to-8" => assert!(custody.set_cgc(8, 200).unwrap()),
        other => panic!("unknown child mode {other}"),
    }
    println!("{READY}");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn the_first_count_survives_a_kill() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    run_and_kill("first-start", dir.path());
    let custody = open(dir.path(), 500);
    assert_eq!((custody.cgc(), custody.cgc_set_slot()), (4, 100));
    assert_eq!(custody.enr().0, vec![4], "the ENR cgc is 4");
    assert_eq!(custody.custody_columns(), vec![1, 47, 87, 102]);
}

#[test]
fn a_raised_count_survives_a_kill_and_never_decreases() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    run_and_kill("raise-to-8", dir.path());

    let mut custody = open(dir.path(), 500);
    assert_eq!((custody.cgc(), custody.cgc_set_slot()), (8, 200));
    let seq = custody.metadata().seq_number;
    assert_eq!(seq, 1, "one raise, one MetaData bump; a restart adds none");
    let err = custody.set_cgc(4, 600).unwrap_err();
    assert!(
        matches!(
            err,
            CustodyError::Decrease {
                stored: 8,
                requested: 4
            }
        ),
        "{err:?}"
    );
    drop(custody);

    // The refused decrease left the stored count alone.
    let custody = open(dir.path(), 700);
    assert_eq!((custody.cgc(), custody.cgc_set_slot()), (8, 200));
    assert_eq!(custody.metadata().seq_number, seq);
    assert_eq!(custody.enr().0, vec![8]);
}
