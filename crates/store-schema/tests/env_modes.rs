//! The env layout the writer owns: the env directory 0750 (a setgid bit there kept), `mdbx.dat`
//! 0640 and `mdbx.lck` 0660 (group-writable: a reader registers its read slots there), whatever
//! the umask. The writer sets it when it creates the env and again on every open; it never
//! changes a group, so the files take the directory's (setgid, as cl-node provisions it).
//!
//! Only mode bits are asserted, never a refused open, so these hold as any user, root included;
//! scripts/store-two-users.sh checks the same layout across two users.
//!
//! The umask is per process, so the open under umask 0077 (the units' `UMask=`) runs in a
//! child: this test binary again, through `sh -c 'umask 0077 && exec ...'`, its ignored
//! `umask_child` test only. Every test here runs under [`serial`]: a child spawned by one test
//! must not inherit another test's MDBX lock fds between fork and exec.

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
    sync::{Mutex, MutexGuard, PoisonError},
};

use store_schema::env::{self, WriterOptions, MIN_MAX_SIZE};

/// The env path the child opens.
const CHILD_PATH: &str = "STORE_SCHEMA_MODES_CHILD_PATH";

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn opts() -> WriterOptions {
    WriterOptions {
        max_size: MIN_MAX_SIZE,
    }
}

/// The modes of the env directory, `mdbx.dat` and `mdbx.lck` in octal, special bits included.
fn modes(path: &Path) -> String {
    [".", "mdbx.dat", "mdbx.lck"]
        .map(|name| format!("{:o}", mode(&path.join(name))))
        .join(" ")
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o7777
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// This process's umask, if `/proc/self/status` says (Linux 4.7 and later).
fn umask() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let mask = status.lines().find_map(|l| l.strip_prefix("Umask:"))?;
    u32::from_str_radix(mask.trim(), 8).ok()
}

/// The child [`open_under_umask_0077`] spawns: one writer open of [`CHILD_PATH`], closed.
#[test]
#[ignore = "the child of the umask tests: runs only when one of them spawns it"]
fn umask_child() {
    let path = std::env::var_os(CHILD_PATH).expect("spawned with the env path");
    if let Some(mask) = umask() {
        assert_eq!(mask, 0o077, "the child's umask: {mask:o}");
    }
    drop(env::open_writer(Path::new(&path), opts()).unwrap());
}

/// Opens the writer at `path`, then closes it, in a child process whose umask is 0077.
fn open_under_umask_0077(path: &Path) {
    let status = Command::new("sh")
        .args(["-c", r#"umask 0077 && exec "$@""#, "sh"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "umask_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_PATH, path)
        .status()
        .unwrap();
    assert!(status.success(), "the writer under umask 0077: {status}");
}

/// A writer that creates the env under umask 0077, the units' `UMask=`, still lays it out
/// 0750, 0640 and 0660, and a reader opens it read-only. In a directory provisioned setgid
/// (2700 here, its group bits wrong) the bit is kept, 2750, and the files are in the
/// directory's group.
#[test]
fn writer_creates_the_layout_under_umask_0077() {
    let _serial = serial();
    let base = tempfile::tempdir().unwrap();

    let fresh = base.path().join("fresh");
    open_under_umask_0077(&fresh);
    assert_eq!(modes(&fresh), "750 640 660", "a directory it made");
    drop(env::open_reader(&fresh).expect("a reader opens it read-only"));

    let provisioned = base.path().join("provisioned");
    fs::create_dir(&provisioned).unwrap();
    chmod(&provisioned, 0o2700);
    open_under_umask_0077(&provisioned);
    assert_eq!(
        modes(&provisioned),
        "2750 640 660",
        "a setgid directory provisioned for it"
    );
    let group = fs::metadata(&provisioned).unwrap().gid();
    for name in ["mdbx.dat", "mdbx.lck"] {
        let gid = fs::metadata(provisioned.join(name)).unwrap().gid();
        assert_eq!(gid, group, "{name} is in the directory's group");
    }
    drop(env::open_reader(&provisioned).expect("a reader opens it read-only"));
}

/// Every writer open brings an existing env back to the layout: files left 0644, 0600 or 0666
/// and a directory left 0755, 0700, 0777 or sticky (a hand-made env, or one an older writer
/// left) are 0640, 0660 and 0750 again, a setgid bit on the directory kept. An env already
/// laid out stays as it is, and a reader opens it read-only each time.
#[test]
fn every_writer_open_restores_the_layout() {
    let _serial = serial();
    let base = tempfile::tempdir().unwrap();
    let path = base.path().join("env");
    drop(env::open_writer(&path, opts()).unwrap());
    assert_eq!(modes(&path), "750 640 660", "as created");
    for (dir, dat, lck, want) in [
        (0o755, 0o644, 0o644, 0o750),
        (0o700, 0o600, 0o600, 0o750),
        (0o777, 0o666, 0o666, 0o750),
        (0o1750, 0o600, 0o644, 0o750),
        (0o2777, 0o644, 0o600, 0o2750),
        (0o2750, 0o640, 0o660, 0o2750),
    ] {
        chmod(&path, dir);
        chmod(&path.join("mdbx.dat"), dat);
        chmod(&path.join("mdbx.lck"), lck);
        drop(env::open_writer(&path, opts()).unwrap());
        assert_eq!(
            modes(&path),
            format!("{want:o} 640 660"),
            "reopened from {dir:o}, {dat:o}, {lck:o}"
        );
        drop(env::open_reader(&path).expect("a reader opens it read-only"));
    }
}
