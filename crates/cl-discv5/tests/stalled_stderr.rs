//! The `cl-discv5` binary exits within its deadline when its stderr is a pipe nobody reads.
//!
//! The child's stderr is a pipe filled to capacity before the child starts, its read end held
//! open by the test and never read, so the child's first write to stderr would block. A log
//! line written from the logging thread itself (a synchronous writer) would freeze the binary
//! there for good. Every log line goes through the bounded stderr writer instead, and the exit
//! waits for it at most `LOG_FLUSH_DEADLINE`.

use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::io::{PipeReader, PipeWriter, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
use svc_runtime::telemetry::EXIT_NO_LOG_WRITER;

/// What an exit may take past the log flush: process start-up and teardown on a loaded host.
const SLACK: Duration = Duration::from_secs(10);
/// How often [`Stalled::wait_until`] looks again.
const POLL: Duration = Duration::from_millis(20);
/// The most a pipe is written while filling it: far past any pipe's capacity.
const FILL_CAP: usize = 16 << 20;
/// A minimum thread stack (1 PiB, `RUST_MIN_STACK`) that no address space holds: in a child
/// given it, every thread spawn fails, the log writer's included.
const NO_THREAD_STACK: &str = "1125899906842624";

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
    fn wait_until(&mut self, deadline: Instant) -> Option<ExitStatus> {
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait on the child") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(POLL);
        }
    }

    /// The exit code, panicking if the child has not exited by the log flush plus [`SLACK`].
    fn exit_code(&mut self) -> Option<i32> {
        match self.wait_until(Instant::now() + LOG_FLUSH_DEADLINE + SLACK) {
            Some(status) => status.code(),
            None => panic!("cl-discv5: still running at its deadline; stuck writing stderr?"),
        }
    }
}

impl Drop for Stalled {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn cl_discv5(credentials: Option<&Path>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cl-discv5"));
    command.env_remove(node_key::CREDENTIALS_DIRECTORY);
    if let Some(dir) = credentials {
        command.env(node_key::CREDENTIALS_DIRECTORY, dir);
    }
    command
}

#[test]
fn refuses_and_exits_with_a_full_stderr() {
    let mut child = Stalled::spawn(cl_discv5(None));
    assert_eq!(child.exit_code(), Some(1), "no credential");
}

#[test]
fn loads_its_node_key_and_exits_with_a_full_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(node_key::CREDENTIAL);
    std::fs::write(&path, [0x42; 32]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let mut child = Stalled::spawn(cl_discv5(Some(dir.path())));
    assert_eq!(child.exit_code(), Some(2), "loaded, not runnable yet");
}

#[test]
fn exits_at_once_writing_nothing_when_its_log_writer_cannot_start() {
    let no_writer = || {
        let mut command = cl_discv5(None);
        command.env("RUST_MIN_STACK", NO_THREAD_STACK);
        command
    };
    let mut child = Stalled::spawn(no_writer());
    assert_eq!(child.exit_code(), Some(i32::from(EXIT_NO_LOG_WRITER)));
    let dir = tempfile::tempdir().unwrap();
    let stderr = dir.path().join("stderr");
    let mut child = Stalled::spawn_to_file(no_writer(), &stderr);
    assert_eq!(child.exit_code(), Some(i32::from(EXIT_NO_LOG_WRITER)));
    assert_eq!(std::fs::read_to_string(&stderr).unwrap(), "");
}
