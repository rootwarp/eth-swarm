//! The `devnet-probe` binary exits within its deadline when its stderr is a pipe nobody reads,
//! and still writes its usage errors to stderr unchanged when one does.
//!
//! The child's stderr is a pipe filled to capacity before the child starts, its read end held
//! open by the test and never read, so the child's first write to stderr would block. A usage
//! error written straight to stderr, or a log line from a synchronous writer, would freeze the
//! probe there for good. Both go through the bounded stderr writer instead, and the exit waits
//! for it at most `LOG_FLUSH_DEADLINE`.

use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::io::{PipeReader, PipeWriter, Write as _};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
use svc_runtime::telemetry::EXIT_NO_LOG_WRITER;

/// What an exit may take past the log flush: process start-up and teardown on a loaded host.
const SLACK: Duration = Duration::from_secs(10);
/// How often [`Owned::wait_until`] looks again.
const POLL: Duration = Duration::from_millis(20);
/// The most a pipe is written while filling it: far past any pipe's capacity.
const FILL_CAP: usize = 16 << 20;
/// A minimum thread stack (1 PiB, `RUST_MIN_STACK`) that no address space holds: in a child
/// given it, every thread spawn fails, the log writer's included.
const NO_THREAD_STACK: &str = "1125899906842624";
/// The probe's usage exit.
const EXIT_USAGE: i32 = 2;

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
struct Owned {
    child: Child,
    _stderr: Option<PipeReader>,
}

impl Owned {
    /// Spawns `command` with stdin closed, stdout to `stdout` and stderr full.
    fn stalled(command: Command, stdout: &Path) -> Self {
        let (reader, writer) = full_pipe();
        Self::spawn(command, stdout, writer.into(), Some(reader))
    }

    /// Spawns `command` with stdin closed, stdout to `stdout` and stderr to `stderr`.
    fn to_files(command: Command, stdout: &Path, stderr: &Path) -> Self {
        let stderr = std::fs::File::create(stderr).unwrap();
        Self::spawn(command, stdout, stderr.into(), None)
    }

    fn spawn(mut command: Command, stdout: &Path, stderr: Stdio, held: Option<PipeReader>) -> Self {
        let child = command
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(stdout).unwrap())
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
            None => panic!("devnet-probe: still running at its deadline; stuck writing stderr?"),
        }
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `devnet-probe connect`: a usage error, no `--config` or `--network-dir`.
fn usage_error() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_devnet-probe"));
    command.arg("connect");
    command
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn a_usage_error_exits_with_a_full_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let stdout = dir.path().join("stdout");
    let mut child = Owned::stalled(usage_error(), &stdout);
    assert_eq!(child.exit_code(), Some(EXIT_USAGE));
    assert_eq!(read(&stdout), "", "a usage error prints no report");
}

#[test]
fn a_usage_error_reaches_stderr_as_plain_text() {
    let dir = tempfile::tempdir().unwrap();
    let (stdout, stderr) = (dir.path().join("stdout"), dir.path().join("stderr"));
    let mut child = Owned::to_files(usage_error(), &stdout, &stderr);
    assert_eq!(child.exit_code(), Some(EXIT_USAGE));
    let text = read(&stderr);
    assert!(
        text.starts_with("devnet-probe: ") && text.contains("--config or --network-dir"),
        "{text}"
    );
    assert!(
        text.contains("\nusage: devnet-probe <discover|connect|status|fetch-epoch|all>\n"),
        "{text}"
    );
    assert!(text.ends_with("       devnet-probe --help\n"), "{text}");
    assert_eq!(read(&stdout), "");
}

#[test]
fn the_help_is_still_printed_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let (stdout, stderr) = (dir.path().join("stdout"), dir.path().join("stderr"));
    let mut command = Command::new(env!("CARGO_BIN_EXE_devnet-probe"));
    command.arg("--help");
    let mut child = Owned::to_files(command, &stdout, &stderr);
    assert_eq!(child.exit_code(), Some(0));
    assert!(read(&stdout).starts_with("usage: devnet-probe"));
    assert_eq!(read(&stderr), "");
}

#[test]
fn exits_at_once_writing_nothing_when_its_log_writer_cannot_start() {
    let no_writer = || {
        let mut command = usage_error();
        command.env("RUST_MIN_STACK", NO_THREAD_STACK);
        command
    };
    let dir = tempfile::tempdir().unwrap();
    let (stdout, stderr) = (dir.path().join("stdout"), dir.path().join("stderr"));
    let mut child = Owned::stalled(no_writer(), &stdout);
    assert_eq!(child.exit_code(), Some(i32::from(EXIT_NO_LOG_WRITER)));
    let mut child = Owned::to_files(no_writer(), &stdout, &stderr);
    assert_eq!(child.exit_code(), Some(i32::from(EXIT_NO_LOG_WRITER)));
    assert_eq!(read(&stderr), "");
    assert_eq!(read(&stdout), "");
}
