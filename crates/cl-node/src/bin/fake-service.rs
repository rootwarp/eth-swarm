//! `cl-node-fake-service`: a stand-in for a service binary, for `tests/launch.rs` only (cargo
//! feature `test-fake-service`). Never deploy it.
//!
//! The test links `<bin>/cl-<svc>` to this binary, so the service is the name it was run as
//! (`argv[0]`), and writes `<bin>/fake.conf`: a `log <path>` line and one `<svc> <mode>` line per
//! scripted service (others are `ready`). Nothing comes through the environment, which cl-node
//! clears. It appends its events to the log: `start <svc> <pid>`, `env <svc> <names>`,
//! `creds <svc> ...`, `runtime <svc> <dir> <mode>`, `signals <svc> blk=<SigBlk> ign=<SigIgn>`, `ready <svc>` (before READY=1 is sent),
//! `grandchild <svc> <pid>`, `term <svc>` and `exit <svc>`.
//!
//! Modes: `ready`; `slow-ready` (READY=1 after 300 ms); `never-ready`; `die-before-ready` (exit
//! 3); `die-after-ready` (exit 4 once the log has `ready api`); `ignore-sigterm` (logs SIGTERM,
//! keeps running); `grandchild` (ready, then a child that sleeps in its process group);
//! `grandchild-die` (that child, then exit 3 before READY=1); `grandchild-ready` (a child of its
//! own sends READY=1, the service itself never does).

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Duration;

fn log(path: &Path, line: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .expect("open the log");
    file.write_all(format!("{line}\n").as_bytes())
        .expect("write the log");
}

fn mode_of(path: &Path) -> String {
    format!(
        "{:o}",
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    )
}

/// A grandchild in this process's group that outlives it unless cl-node kills the group: never
/// waited for, on purpose (`no_orphans_left`).
#[allow(clippy::zombie_processes)]
fn sleeper() -> u32 {
    let exe = std::env::current_exe().unwrap();
    let child = std::process::Command::new(exe)
        .arg("sleeper")
        .spawn()
        .unwrap();
    child.id()
}

fn main() {
    let argv0 = PathBuf::from(std::env::args_os().next().unwrap());
    match std::env::args().nth(1).as_deref() {
        Some("sleeper") => {
            // It inherits our blocked SIGTERM: unblock it, so the group's SIGTERM kills it.
            unsafe {
                let mut empty: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut empty);
                libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            }
            std::thread::sleep(Duration::from_secs(600));
            exit(0);
        }
        Some("notify") => {
            let socket = std::env::args_os().nth(2).unwrap();
            UnixDatagram::unbound()
                .unwrap()
                .send_to(b"READY=1", socket)
                .unwrap();
            exit(0);
        }
        _ => {}
    }
    // The signal state cl-node gave us, before we change it.
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let sig = |key: &str| {
        let line = status.lines().find(|l| l.starts_with(key)).unwrap();
        line[key.len()..].trim().to_owned()
    };
    let signals = format!("blk={} ign={}", sig("SigBlk:"), sig("SigIgn:"));
    // Block SIGTERM and SIGINT first, so neither kills us before it is logged.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let svc = argv0
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("cl-")
        .expect("run as cl-<svc>")
        .to_owned();
    let conf = fs::read_to_string(argv0.parent().unwrap().join("fake.conf")).unwrap();
    let mut log_path = None;
    let mut mode = "ready".to_owned();
    for line in conf.lines() {
        match line.split_once(' ') {
            Some(("log", path)) => log_path = Some(PathBuf::from(path)),
            Some((s, m)) if s == svc => mode = m.to_owned(),
            _ => {}
        }
    }
    let log_path = log_path.expect("fake.conf names the log");
    let log = |line: String| log(&log_path, &line);

    log(format!("start {svc} {}", std::process::id()));
    log(format!("signals {svc} {signals}"));
    let mut names: Vec<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    names.sort();
    log(format!("env {svc} {}", names.join(",")));
    match std::env::var_os("CREDENTIALS_DIRECTORY") {
        None => log(format!("creds {svc} none")),
        Some(dir) => {
            let dir = PathBuf::from(dir);
            let mut files: Vec<String> = fs::read_dir(&dir)
                .unwrap()
                .map(|e| {
                    let path = e.unwrap().path();
                    let content = fs::read_to_string(&path).unwrap();
                    let name = path.file_name().unwrap().to_string_lossy().into_owned();
                    format!("{name}={}:{content}", mode_of(&path))
                })
                .collect();
            files.sort();
            log(format!(
                "creds {svc} dir={} {}",
                mode_of(&dir),
                files.join(" ")
            ));
        }
    }
    if let Some(dir) = std::env::var_os("RUNTIME_DIRECTORY") {
        let dir = PathBuf::from(dir);
        log(format!("runtime {svc} {} {}", dir.display(), mode_of(&dir)));
    }
    let ready = || {
        log(format!("ready {svc}"));
        let socket = std::env::var_os("NOTIFY_SOCKET").expect("NOTIFY_SOCKET");
        UnixDatagram::unbound()
            .unwrap()
            .send_to(b"READY=1", socket)
            .expect("send READY=1");
    };
    match mode.as_str() {
        "die-before-ready" => exit(3),
        "grandchild-die" => {
            log(format!("grandchild {svc} {}", sleeper()));
            exit(3);
        }
        "never-ready" => {}
        "grandchild-ready" => {
            let socket = std::env::var_os("NOTIFY_SOCKET").unwrap();
            let exe = std::env::current_exe().unwrap();
            let sent = std::process::Command::new(exe)
                .arg("notify")
                .arg(socket)
                .status()
                .unwrap();
            assert!(sent.success());
            log(format!("notified-by-grandchild {svc}"));
        }
        "slow-ready" => {
            std::thread::sleep(Duration::from_millis(300));
            ready();
        }
        _ => ready(),
    }
    if mode == "grandchild" {
        log(format!("grandchild {svc} {}", sleeper()));
    }
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    loop {
        let sig = unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &timeout) };
        if sig == libc::SIGTERM || sig == libc::SIGINT {
            log(format!("term {svc}"));
            if mode != "ignore-sigterm" {
                exit(0);
            }
        }
        if mode == "die-after-ready"
            && fs::read_to_string(&log_path)
                .unwrap()
                .lines()
                .any(|l| l == "ready api")
        {
            log(format!("exit {svc}"));
            exit(4);
        }
    }
}
