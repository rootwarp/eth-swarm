//! cl-chain is the only writer of the column env: one `ColumnWriter` per env across every
//! process, and readers (cl-store) open it read-only.
//!
//! Cross-process cases re-run this test binary as a child, selected by `CHILD_MODE`.

use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Command, ExitStatus, Stdio},
};

use cl_chain_columns::{Column, ColumnReader, ColumnWriter, Error, WriterOptions};

const CHILD_MODE: &str = "CL_CHAIN_COLUMNS_CHILD_MODE";
const CHILD_PATH: &str = "CL_CHAIN_COLUMNS_CHILD_PATH";
const ROOT: [u8; 32] = [0x11; 32];

const READY: &str = "CL_CHAIN_COLUMNS_CHILD_READY";

fn child(mode: &str, path: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env(CHILD_MODE, mode)
        .env(CHILD_PATH, path);
    command
}

fn run_child(mode: &str, path: &Path) -> ExitStatus {
    child(mode, path).status().unwrap()
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
        "writer-then-crash" => {
            let _writer = ColumnWriter::open(&path).unwrap();
            std::process::abort();
        }
        other => panic!("unknown child mode {other}"),
    }
}

#[test]
fn second_writer_in_the_same_process_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let writer = ColumnWriter::open(dir.path()).unwrap();
    let err = ColumnWriter::open(dir.path()).unwrap_err();
    assert!(matches!(err, Error::WriterAlreadyOpen { .. }), "{err:?}");

    drop(writer);
    ColumnWriter::open(dir.path()).expect("the guard is released when the writer drops");
}

#[test]
fn writers_of_different_envs_do_not_conflict() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let _wa = ColumnWriter::open(a.path()).unwrap();
    let _wb = ColumnWriter::open(b.path()).unwrap();
}

#[test]
fn second_writer_in_another_process_is_refused_while_readers_read() {
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
    let dir = tempfile::tempdir().unwrap();
    assert!(!run_child("writer-then-crash", dir.path()).success());
    ColumnWriter::open(dir.path()).expect("the OS released the dead writer's guard");
}

#[test]
fn a_map_size_change_blocked_by_an_open_reader_is_an_error() {
    const MIB_256: usize = 256 << 20;
    let dir = tempfile::tempdir().unwrap();
    let small = WriterOptions { max_size: MIB_256 };
    let large = WriterOptions {
        max_size: 2 * MIB_256,
    };
    drop(ColumnWriter::open_with(dir.path(), small).unwrap());

    let mut reader = child("hold-reader", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(reader.stdout.take().unwrap()).lines();
    assert!(
        // libtest may print "test child_entry ... " on the same line first.
        lines.any(|line| line.unwrap().contains(READY)),
        "reader child never opened the env"
    );

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

    drop(reader.stdin.take());
    assert!(reader.wait().unwrap().success());
    ColumnWriter::open_with(dir.path(), large).expect("alone, the writer applies the new size");
}
