//! `cl-node launch --foreground` against `cl-node-fake-service` (src/bin/fake-service.rs): each
//! test links `<bin>/cl-<svc>` to the fake, scripts some services through `<bin>/fake.conf`, and
//! reads the order of what happened from the log the fakes append to.
//!
//! As root, cl-node drops every child to its unit user, which a test host does not have: only
//! `root_without_unit_users_refuses` runs as root (CI's root-tests job), the others skip there.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const SERVICES: [&str; 8] = [
    "verify", "engine", "chain", "store", "discv5", "p2p", "sync", "api",
];

/// Credentials as the test plants them, and as an owner must see them.
const JWT: &str = "test-jwt-secret";
const NODEKEY: &str = "test-nodekey";

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Whether a non-root test can run; prints why not.
fn non_root(test: &str) -> bool {
    if is_root() {
        eprintln!("{test}: skipped as root (children would drop to unit users this host lacks)");
    }
    !is_root()
}

struct Harness {
    _dir: tempfile::TempDir,
    bin: PathBuf,
    creds: PathBuf,
    runtime: PathBuf,
    log: PathBuf,
    stderr: PathBuf,
}

impl Harness {
    /// Every service `ready`, except the `(svc, mode)` given.
    fn new(modes: &[(&str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        let bin = root.join("bin");
        let creds = root.join("creds");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&creds).unwrap();
        let fake = env!("CARGO_BIN_EXE_cl-node-fake-service");
        for svc in SERVICES {
            std::os::unix::fs::symlink(fake, bin.join(format!("cl-{svc}"))).unwrap();
        }
        let log = root.join("events.log");
        let mut conf = format!("log {}\n", log.display());
        for (svc, mode) in modes {
            conf.push_str(&format!("{svc} {mode}\n"));
        }
        fs::write(bin.join("fake.conf"), conf).unwrap();
        for (name, content) in [("jwt", JWT), ("nodekey", NODEKEY)] {
            fs::write(creds.join(name), content).unwrap();
            fs::set_permissions(creds.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        Harness {
            bin,
            creds,
            runtime: root.join("run"),
            log,
            stderr: root.join("stderr"),
            _dir: dir,
        }
    }

    fn command(&self, ready_timeout: u64, stop_grace: u64) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cl-node"));
        cmd.args([
            "launch",
            "--foreground",
            "--network",
            "mainnet",
            "--bin-dir",
        ])
        .arg(&self.bin)
        .arg("--credentials-dir")
        .arg(&self.creds)
        .arg("--runtime-dir")
        .arg(&self.runtime)
        .args(["--ready-timeout", &ready_timeout.to_string()])
        .args(["--stop-grace", &stop_grace.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&self.stderr).unwrap());
        cmd
    }

    fn spawn(&self, ready_timeout: u64, stop_grace: u64) -> Child {
        self.command(ready_timeout, stop_grace).spawn().unwrap()
    }

    fn lines(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The `start`, `ready`, `term` and `exit` events, without pids.
    fn events(&self) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter_map(|l| {
                let mut words = l.split(' ');
                let (kind, svc) = (words.next()?, words.next()?);
                ["start", "ready", "term", "exit"]
                    .contains(&kind)
                    .then(|| format!("{kind} {svc}"))
            })
            .collect()
    }

    /// The rest of the line after `<kind> <svc> ` for each service that logged one.
    fn field(&self, kind: &str, svc: &str) -> Option<String> {
        let prefix = format!("{kind} {svc} ");
        self.lines()
            .into_iter()
            .find_map(|l| l.strip_prefix(&prefix).map(str::to_owned))
    }

    fn pids(&self, kind: &str) -> Vec<i32> {
        self.lines()
            .iter()
            .filter(|l| l.starts_with(&format!("{kind} ")))
            .map(|l| l.rsplit(' ').next().unwrap().parse().unwrap())
            .collect()
    }

    fn wait_for_line(&self, line: &str) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !self.lines().iter().any(|l| l == line) {
            assert!(
                Instant::now() < deadline,
                "no {line:?} in {:?}",
                self.lines()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap_or_default()
    }
}

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("cl-node did not exit");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn signal(child: &Child, sig: rustix::process::Signal) {
    let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
    rustix::process::kill_process(pid, sig).unwrap();
}

/// `start`/`ready` for each service in `services`.
fn started(services: &[&str]) -> Vec<String> {
    services
        .iter()
        .flat_map(|s| [format!("start {s}"), format!("ready {s}")])
        .collect()
}

fn terms(services: &[&str]) -> Vec<String> {
    services.iter().map(|s| format!("term {s}")).collect()
}

fn reversed(services: &[&str]) -> Vec<&'static str> {
    SERVICES
        .iter()
        .rev()
        .filter(|s| services.contains(s))
        .copied()
        .collect()
}

/// Whether `pid` is gone (or a zombie no one has reaped yet), within 5 s.
fn gone(pid: i32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
        let alive = match stat {
            Err(_) => false,
            // The state is the first field after the parenthesised command.
            Ok(stat) => !stat
                .rsplit_once(") ")
                .is_some_and(|(_, r)| r.starts_with('Z')),
        };
        if !alive {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn starts_in_order_and_waits_for_ready() {
    if !non_root("starts_in_order_and_waits_for_ready") {
        return;
    }
    // A slow READY=1 must hold back the next start.
    let h = Harness::new(&[("verify", "slow-ready"), ("chain", "slow-ready")]);
    let mut child = h.spawn(10, 5);
    h.wait_for_line("ready api");
    signal(&child, rustix::process::Signal::TERM);
    assert!(wait(&mut child).success(), "{}", h.stderr());
    let events = h.events();
    assert_eq!(events[..16], started(&SERVICES)[..], "{events:?}");
}

#[test]
fn sigterm_stops_in_reverse_order() {
    if !non_root("sigterm_stops_in_reverse_order") {
        return;
    }
    for sig in [rustix::process::Signal::TERM, rustix::process::Signal::INT] {
        let h = Harness::new(&[]);
        let mut child = h.spawn(10, 5);
        h.wait_for_line("ready api");
        signal(&child, sig);
        let status = wait(&mut child);
        assert_eq!(status.code(), Some(0), "{sig:?}: {}", h.stderr());
        let mut want = started(&SERVICES);
        want.extend(terms(&reversed(&SERVICES)));
        assert_eq!(h.events(), want, "{sig:?}");
    }
}

#[test]
fn death_before_ready_stops_started_in_reverse() {
    if !non_root("death_before_ready_stops_started_in_reverse") {
        return;
    }
    let h = Harness::new(&[("store", "die-before-ready")]);
    let mut child = h.spawn(10, 5);
    let status = wait(&mut child);
    assert_eq!(status.code(), Some(1), "{}", h.stderr());
    let mut want = started(&["verify", "engine", "chain"]);
    want.push("start store".into());
    want.extend(terms(&["chain", "engine", "verify"]));
    assert_eq!(h.events(), want);
    assert!(h.stderr().contains("cl-store exited"), "{}", h.stderr());
}

#[test]
fn start_failure_stops_started_in_reverse() {
    if !non_root("start_failure_stops_started_in_reverse") {
        return;
    }
    let h = Harness::new(&[]);
    fs::remove_file(h.bin.join("cl-store")).unwrap();
    let mut child = h.spawn(10, 5);
    assert_eq!(wait(&mut child).code(), Some(1), "{}", h.stderr());
    let mut want = started(&["verify", "engine", "chain"]);
    want.extend(terms(&["chain", "engine", "verify"]));
    assert_eq!(h.events(), want);
    assert!(
        h.stderr().contains("cannot start cl-store"),
        "{}",
        h.stderr()
    );
}

#[test]
fn death_after_ready_stops_others_in_reverse() {
    if !non_root("death_after_ready_stops_others_in_reverse") {
        return;
    }
    let h = Harness::new(&[("p2p", "die-after-ready")]);
    let mut child = h.spawn(10, 5);
    let status = wait(&mut child);
    assert_eq!(status.code(), Some(1), "{}", h.stderr());
    let mut want = started(&SERVICES);
    want.push("exit p2p".into());
    let others: Vec<&str> = SERVICES.iter().copied().filter(|s| *s != "p2p").collect();
    want.extend(terms(&reversed(&others)));
    assert_eq!(h.events(), want);
    assert!(h.stderr().contains("cl-p2p exited"), "{}", h.stderr());
}

#[test]
fn ready_timeout_fails() {
    if !non_root("ready_timeout_fails") {
        return;
    }
    let h = Harness::new(&[("chain", "never-ready")]);
    let begun = Instant::now();
    let mut child = h.spawn(1, 5);
    let status = wait(&mut child);
    assert!(begun.elapsed() >= Duration::from_secs(1));
    assert_eq!(status.code(), Some(1), "{}", h.stderr());
    let mut want = started(&["verify", "engine"]);
    want.push("start chain".into());
    // The one that missed its deadline is stopped too, first.
    want.extend(terms(&["chain", "engine", "verify"]));
    assert_eq!(h.events(), want);
    assert!(
        h.stderr().contains("cl-chain sent no READY=1"),
        "{}",
        h.stderr()
    );
}

#[test]
fn ready_only_from_the_main_pid() {
    if !non_root("ready_only_from_the_main_pid") {
        return;
    }
    // READY=1 from another process of the service does not count (the units' NotifyAccess=main).
    let h = Harness::new(&[("engine", "grandchild-ready")]);
    let mut child = h.spawn(1, 5);
    assert_eq!(wait(&mut child).code(), Some(1), "{}", h.stderr());
    let notified = h
        .lines()
        .iter()
        .any(|l| l == "notified-by-grandchild engine");
    assert!(notified, "the grandchild sent no READY=1: {:?}", h.lines());
    let mut want = started(&["verify"]);
    want.push("start engine".into());
    want.extend(terms(&["engine", "verify"]));
    assert_eq!(h.events(), want);
    assert!(
        h.stderr().contains("cl-engine sent no READY=1"),
        "{}",
        h.stderr()
    );
}

#[test]
fn sigkill_after_grace() {
    if !non_root("sigkill_after_grace") {
        return;
    }
    let h = Harness::new(&[("engine", "ignore-sigterm")]);
    let mut child = h.spawn(10, 1);
    h.wait_for_line("ready api");
    let begun = Instant::now();
    signal(&child, rustix::process::Signal::TERM);
    let status = wait(&mut child);
    assert!(
        begun.elapsed() >= Duration::from_secs(1),
        "the grace was not waited"
    );
    assert_eq!(status.code(), Some(0), "{}", h.stderr());
    let mut want = started(&SERVICES);
    want.extend(terms(&reversed(&SERVICES)));
    assert_eq!(h.events(), want);
    let engine: i32 = h.field("start", "engine").unwrap().parse().unwrap();
    assert!(gone(engine), "cl-engine survived");
    assert!(h.stderr().contains("SIGKILL"), "{}", h.stderr());
}

#[test]
fn no_orphans_left() {
    if !non_root("no_orphans_left") {
        return;
    }
    // A grandchild in a running child's group, stopped by SIGTERM to cl-node.
    let h = Harness::new(&[("sync", "grandchild")]);
    let mut child = h.spawn(10, 5);
    h.wait_for_line("ready api");
    signal(&child, rustix::process::Signal::TERM);
    assert!(wait(&mut child).success(), "{}", h.stderr());
    let pids = [h.pids("start"), h.pids("grandchild")].concat();
    assert_eq!(pids.len(), 9, "{:?}", h.lines());
    for pid in pids {
        assert!(gone(pid), "pid {pid} survived cl-node");
    }
    // A child that dies before READY=1 and leaves a grandchild behind in its group.
    let h = Harness::new(&[("store", "grandchild-die")]);
    let mut child = h.spawn(10, 5);
    assert_eq!(wait(&mut child).code(), Some(1), "{}", h.stderr());
    let pids = [h.pids("start"), h.pids("grandchild")].concat();
    assert_eq!(pids.len(), 5, "{:?}", h.lines());
    for pid in pids {
        assert!(gone(pid), "pid {pid} survived cl-node");
    }
    // cl-node killed outright: its children die with it (parent-death signal).
    let h = Harness::new(&[]);
    let mut child = h.spawn(10, 5);
    h.wait_for_line("ready api");
    signal(&child, rustix::process::Signal::KILL);
    wait(&mut child);
    let pids = h.pids("start");
    assert_eq!(pids.len(), 8, "{:?}", h.lines());
    for pid in pids {
        assert!(gone(pid), "pid {pid} survived a SIGKILLed cl-node");
    }
}

#[test]
fn credentials_only_for_owners() {
    if !non_root("credentials_only_for_owners") {
        return;
    }
    let h = Harness::new(&[]);
    let mut child = h.spawn(10, 5);
    h.wait_for_line("ready api");
    signal(&child, rustix::process::Signal::TERM);
    assert!(wait(&mut child).success(), "{}", h.stderr());
    for svc in SERVICES {
        let want = match svc {
            "engine" => format!("dir=700 jwt=400:{JWT}"),
            "p2p" | "discv5" => format!("dir=700 nodekey=400:{NODEKEY}"),
            _ => "none".into(),
        };
        assert_eq!(
            h.field("creds", svc).as_deref(),
            Some(want.as_str()),
            "{svc}"
        );
    }
    // The copies are gone with cl-node; only the services' runtime directories stay.
    let mut left: Vec<String> = fs::read_dir(&h.runtime)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    let mut want: Vec<String> = SERVICES.iter().map(|s| format!("cl-{s}")).collect();
    want.sort();
    assert_eq!(left, want);

    // A missing credential refuses the start before any service runs.
    let h = Harness::new(&[]);
    fs::remove_file(h.creds.join("nodekey")).unwrap();
    let mut child = h.spawn(10, 5);
    assert_eq!(wait(&mut child).code(), Some(1));
    assert_eq!(h.events(), Vec::<String>::new());
    assert!(h.stderr().contains("nodekey"), "{}", h.stderr());
}

#[test]
fn env_is_cleared() {
    if !non_root("env_is_cleared") {
        return;
    }
    let h = Harness::new(&[]);
    let mut child = h
        .command(10, 5)
        .env("ETHSWARM_JWT_SECRET", "leak")
        .env("CREDENTIALS_DIRECTORY", "/leak")
        .env("HOME", "/leak")
        .spawn()
        .unwrap();
    h.wait_for_line("ready api");
    signal(&child, rustix::process::Signal::TERM);
    assert!(wait(&mut child).success(), "{}", h.stderr());
    for svc in SERVICES {
        let want = match svc {
            "engine" | "p2p" | "discv5" => {
                "CREDENTIALS_DIRECTORY,NOTIFY_SOCKET,PATH,RUNTIME_DIRECTORY"
            }
            _ => "NOTIFY_SOCKET,PATH,RUNTIME_DIRECTORY",
        };
        assert_eq!(h.field("env", svc).as_deref(), Some(want), "{svc}");
        let runtime = h.runtime.join(format!("cl-{svc}"));
        assert_eq!(
            h.field("runtime", svc),
            Some(format!("{} 750", runtime.display())),
            "{svc}"
        );
    }
}

#[test]
fn children_start_with_default_signals() {
    if !non_root("children_start_with_default_signals") {
        return;
    }
    // cl-node started with SIGTERM and SIGUSR1 blocked and SIGHUP ignored: it still stops on
    // SIGTERM, and every child starts as systemd starts a service: nothing blocked, only
    // SIGPIPE ignored (IgnoreSIGPIPE=yes).
    let h = Harness::new(&[]);
    let mut cmd = h.command(10, 5);
    // SAFETY: only signal-mask and disposition syscalls between fork and exec.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    h.wait_for_line("ready api");
    signal(&child, rustix::process::Signal::TERM);
    assert_eq!(wait(&mut child).code(), Some(0), "{}", h.stderr());
    let mut want = started(&SERVICES);
    want.extend(terms(&reversed(&SERVICES)));
    assert_eq!(h.events(), want);
    for svc in SERVICES {
        assert_eq!(
            h.field("signals", svc).as_deref(),
            Some("blk=0000000000000000 ign=0000000000001000"),
            "{svc}"
        );
    }
}

#[test]
fn root_without_unit_users_refuses() {
    let required = std::env::var("ETHSWARM_ROOT_TESTS").is_ok_and(|v| v == "1");
    if !is_root() {
        assert!(!required, "needs root with ETHSWARM_ROOT_TESTS=1");
        eprintln!("root_without_unit_users_refuses: skipped (not root)");
        return;
    }
    let present = Command::new("getent")
        .args(["passwd", "ethswarm-verify"])
        .status()
        .unwrap()
        .success();
    if present {
        assert!(
            !required,
            "this host has ethswarm-verify: the refusal cannot be tested"
        );
        eprintln!("root_without_unit_users_refuses: skipped (ethswarm-verify exists)");
        return;
    }
    let h = Harness::new(&[]);
    let mut child = h.spawn(10, 5);
    assert_eq!(wait(&mut child).code(), Some(1), "{}", h.stderr());
    assert!(h.stderr().contains("ethswarm-verify"), "{}", h.stderr());
    assert_eq!(h.events(), Vec::<String>::new(), "a child started");
    assert!(
        !h.runtime.exists(),
        "created runtime directories before refusing"
    );
}

#[test]
fn launch_usage_errors() {
    for args in [
        &["launch"][..],
        &["launch", "--network", "mainnet"][..],
        &["launch", "--foreground"][..],
        &[
            "launch",
            "--foreground",
            "--network",
            "mainnet",
            "--ready-timeout",
            "0",
        ][..],
        &[
            "launch",
            "--foreground",
            "--network",
            "mainnet",
            "--stop-grace",
            "x",
        ][..],
        &[
            "launch",
            "--foreground",
            "--network",
            "mainnet",
            "--bin-dir",
            "rel",
        ][..],
        &[
            "launch",
            "--foreground",
            "--network",
            "mainnet",
            "--runtime-dir",
            "rel",
        ][..],
        &[
            "launch",
            "--foreground",
            "--network",
            "mainnet",
            "--credentials-dir",
            "rel",
        ][..],
    ] {
        let run = Command::new(env!("CARGO_BIN_EXE_cl-node"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(run.status.code(), Some(2), "{args:?}: {run:?}");
    }
    let help = Command::new(env!("CARGO_BIN_EXE_cl-node"))
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("cl-node launch --foreground"), "{help}");
}
