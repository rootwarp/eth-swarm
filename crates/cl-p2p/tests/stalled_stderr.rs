//! The `cl-p2p` and `m2a-session` binaries keep going, and exit within their deadlines, when
//! their stderr is a pipe nobody reads.
//!
//! Each child's stderr is a pipe filled to capacity before the child starts, its read end held
//! open by the test and never read, so the child's first write to stderr would block. A log
//! line written from the logging thread itself (a synchronous writer) would freeze the binary
//! there: no dial, no exit. Every log line goes through the bounded stderr writer instead, and
//! the exit waits for it at most `LOG_FLUSH_DEADLINE`.

use futures::StreamExt;
use libp2p::identity::{secp256k1, Keypair};
use libp2p::swarm::{dummy, SwarmEvent};
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, SwarmBuilder};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::io::{PipeReader, PipeWriter, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
use svc_runtime::telemetry::EXIT_NO_LOG_WRITER;
use tokio::time::Instant;

/// What an exit may take past its own deadlines: process start-up and teardown on a loaded
/// host.
const SLACK: Duration = Duration::from_secs(10);
/// How often [`Stalled::wait_until`] looks again.
const POLL: Duration = Duration::from_millis(20);
/// The most a pipe is written while filling it: far past any pipe's capacity.
const FILL_CAP: usize = 16 << 20;
/// A minimum thread stack (1 PiB, `RUST_MIN_STACK`) that no address space holds: in a child
/// given it, every thread spawn fails, the log writer's included.
const NO_THREAD_STACK: &str = "1125899906842624";
/// The session's dial deadline (`--connect-timeout-secs`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// The node key the session's key file holds.
const SECRET: [u8; 32] = [7; 32];

/// Writes `chunk` to `writer` (non-blocking) until the pipe takes no more of it.
fn fill_with(writer: &PipeWriter, chunk: &[u8], written: &mut usize) {
    loop {
        assert!(
            *written <= FILL_CAP,
            "the pipe took {written} bytes, still not full"
        );
        match (&*writer).write(chunk) {
            Ok(n) => *written += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("filling the pipe: {e}"),
        }
    }
}

/// A pipe with a full buffer and a blocking write end: the next write to it blocks until the
/// read end is read, which the test never does. Large chunks first, then single bytes, so no
/// room is left (a write of up to `PIPE_BUF` bytes waits for room for all of it).
fn full_pipe() -> (PipeReader, PipeWriter) {
    let (reader, writer) = std::io::pipe().unwrap();
    let blocking = fcntl_getfl(&writer).unwrap();
    fcntl_setfl(&writer, blocking | OFlags::NONBLOCK).unwrap();
    let mut written = 0;
    fill_with(&writer, &[b'\n'; 64 << 10], &mut written);
    fill_with(&writer, b"\n", &mut written);
    fcntl_setfl(&writer, blocking).unwrap();
    (reader, writer)
}

/// A child whose stderr is a [`full_pipe`] the test holds and never reads, or a file. Killed
/// and reaped on every way out of the test: a pass, a failed assertion, a deadline.
struct Stalled {
    child: Child,
    _stderr: Option<PipeReader>,
}

impl Stalled {
    /// Spawns `command` with stdin and stdout closed and stderr full.
    fn spawn(command: Command) -> Self {
        let (reader, writer) = full_pipe();
        Self::spawn_with_stderr(command, writer.into(), Some(reader))
    }

    /// Spawns `command` with stdin and stdout closed and stderr written to `file`.
    fn spawn_to_file(command: Command, file: &Path) -> Self {
        let file = std::fs::File::create(file).unwrap();
        Self::spawn_with_stderr(command, file.into(), None)
    }

    fn spawn_with_stderr(mut command: Command, stderr: Stdio, held: Option<PipeReader>) -> Self {
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .unwrap();
        Self {
            child,
            _stderr: held,
        }
    }

    /// The exit status, or `None` if the child still runs at `deadline`. Polls `try_wait`, so
    /// no thread is left waiting on the child.
    async fn wait_until(&mut self, deadline: Instant) -> Option<ExitStatus> {
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait on the child") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// The exit code, panicking if the child has not exited by `deadline`.
    async fn exit_code_by(&mut self, deadline: Instant, what: &str) -> Option<i32> {
        match self.wait_until(deadline).await {
            Some(status) => status.code(),
            None => panic!("{what}: still running at its deadline; stuck writing stderr?"),
        }
    }
}

impl Drop for Stalled {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The deadline of a binary that exits at once: the log flush, plus [`SLACK`].
fn flush_deadline() -> Instant {
    Instant::now() + LOG_FLUSH_DEADLINE + SLACK
}

// cl-p2p: a stub that loads its identity and exits.

fn cl_p2p(credentials: Option<&Path>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cl-p2p"));
    command.env_remove(node_key::CREDENTIALS_DIRECTORY);
    if let Some(dir) = credentials {
        command.env(node_key::CREDENTIALS_DIRECTORY, dir);
    }
    command
}

#[tokio::test]
async fn cl_p2p_refuses_and_exits_with_a_full_stderr() {
    let mut child = Stalled::spawn(cl_p2p(None));
    let code = child.exit_code_by(flush_deadline(), "cl-p2p").await;
    assert_eq!(code, Some(1), "no credential");
}

#[tokio::test]
async fn cl_p2p_loads_its_identity_and_exits_with_a_full_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(node_key::CREDENTIAL);
    std::fs::write(&path, [0x42; 32]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let mut child = Stalled::spawn(cl_p2p(Some(dir.path())));
    let code = child.exit_code_by(flush_deadline(), "cl-p2p").await;
    assert_eq!(code, Some(2), "loaded, not runnable yet");
}

/// `command` exits [`EXIT_NO_LOG_WRITER`] at once, with stderr full and with stderr a file it
/// writes nothing to, when no thread can start (`what` names it).
async fn exits_silently_without_a_log_writer(command: impl Fn() -> Command, what: &str) {
    let no_writer = || {
        let mut command = command();
        command.env("RUST_MIN_STACK", NO_THREAD_STACK);
        command
    };
    let mut child = Stalled::spawn(no_writer());
    let code = child.exit_code_by(flush_deadline(), what).await;
    assert_eq!(code, Some(i32::from(EXIT_NO_LOG_WRITER)), "{what}");
    let dir = tempfile::tempdir().unwrap();
    let stderr = dir.path().join("stderr");
    let mut child = Stalled::spawn_to_file(no_writer(), &stderr);
    let code = child.exit_code_by(flush_deadline(), what).await;
    assert_eq!(code, Some(i32::from(EXIT_NO_LOG_WRITER)), "{what}");
    assert_eq!(std::fs::read_to_string(&stderr).unwrap(), "", "{what}");
}

#[tokio::test]
async fn cl_p2p_exits_at_once_writing_nothing_when_its_log_writer_cannot_start() {
    exits_silently_without_a_log_writer(|| cl_p2p(None), "cl-p2p").await;
}

// m2a-session: a dial of the pinned peer, and refusals.

/// A loopback TCP peer (Noise XX, yamux) serving nothing; the peers that connected to it.
async fn loopback_peer() -> (PeerId, Multiaddr, Arc<Mutex<Vec<PeerId>>>) {
    let mut swarm = SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| dummy::Behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    let id = *swarm.local_peer_id();
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            break address;
        }
    };
    let connected = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&connected);
    tokio::spawn(async move {
        loop {
            if let SwarmEvent::ConnectionEstablished { peer_id, .. } =
                swarm.select_next_some().await
            {
                record.lock().unwrap().push(peer_id);
            }
        }
    });
    (id, addr, connected)
}

/// The peer ID of [`SECRET`].
fn secret_peer_id() -> PeerId {
    let mut secret = SECRET;
    let secret = secp256k1::SecretKey::try_from_bytes(&mut secret).unwrap();
    Keypair::from(secp256k1::Keypair::from(secret))
        .public()
        .to_peer_id()
}

/// A config pinning `peer_id` at `addr`, with a 0600 key file holding [`SECRET`], for the session
/// user the tests run as; `None` (and `test` is skipped, with the reason printed) if that user has
/// no portable passwd entry ([`cl_p2p::testkit::os_user_name`]).
/// A config directory the real binary takes: under [`cl_p2p::testkit::config_root`] (no symlink
/// on the path), and read-only while it lives, because the test user owns it and the session
/// refuses a config in a directory its own user can write.
struct ConfigDir {
    // Dropped first: the directory is writable again before it is removed.
    _sealed: cl_p2p::testkit::Sealed,
    dir: tempfile::TempDir,
}

impl ConfigDir {
    fn path(&self) -> &Path {
        self.dir.path()
    }
}

fn config_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .tempdir_in(cl_p2p::testkit::config_root())
        .unwrap()
}

fn session_config(addr: &Multiaddr, peer_id: PeerId, test: &str) -> Option<ConfigDir> {
    let run_as = cl_p2p::testkit::os_user_name(test)?;
    let dir = config_tempdir();
    let key = dir.path().join("node.key");
    std::fs::write(&key, SECRET).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let text = format!(
        "network = \"sepolia\"\npeer = \"{addr}/p2p/{peer_id}\"\n\
         reference_api_url = \"http://127.0.0.1:5052\"\nnode_key = \"{}\"\nrun_as = \"{run_as}\"\n",
        key.display()
    );
    let config = dir.path().join("m2a-session.toml");
    std::fs::write(&config, text).unwrap();
    // Read-only: the session refuses a config its own effective UID can write.
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o444)).unwrap();
    Some(ConfigDir {
        _sealed: cl_p2p::testkit::Sealed::new(dir.path()),
        dir,
    })
}

fn m2a_session(config: &Path, args: &[&str]) -> Command {
    // The test binary: it takes the test user's config and run_as (`test_build = true`).
    let mut command = Command::new(env!("CARGO_BIN_EXE_m2a-session-test"));
    command.arg("--config").arg(config).args(args);
    command
}

#[tokio::test]
async fn m2a_session_dials_and_exits_with_a_full_stderr() {
    let (id, addr, connected) = loopback_peer().await;
    let Some(dir) = session_config(&addr, id, "m2a_session_dials_and_exits_with_a_full_stderr")
    else {
        return;
    };
    let secs = CONNECT_TIMEOUT.as_secs().to_string();
    let mut child = Stalled::spawn(m2a_session(
        &dir.path().join("m2a-session.toml"),
        &["--dial-only", "--connect-timeout-secs", &secs],
    ));
    let deadline = Instant::now() + CONNECT_TIMEOUT + LOG_FLUSH_DEADLINE + SLACK;
    let code = child
        .exit_code_by(deadline, "m2a-session --dial-only")
        .await;
    if euid() == 0 {
        assert_eq!(code, Some(2), "root is refused");
        return;
    }
    assert_eq!(code, Some(0), "the dial and the disconnect succeeded");
    // The session made progress past its first log lines: it reached the peer as itself.
    assert_eq!(*connected.lock().unwrap(), vec![secret_peer_id()]);
}

#[tokio::test]
async fn m2a_session_refusals_exit_with_a_full_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    for args in [&["--bogus"][..], &[]] {
        let mut child = Stalled::spawn(m2a_session(&missing, args));
        let code = child.exit_code_by(flush_deadline(), "m2a-session").await;
        assert_eq!(code, Some(2), "{args:?}: refused");
    }
}

#[tokio::test]
async fn m2a_session_exits_at_once_writing_nothing_when_its_log_writer_cannot_start() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    exits_silently_without_a_log_writer(|| m2a_session(&missing, &[]), "m2a-session").await;
}
