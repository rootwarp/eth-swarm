//! A child process a test owns, so a stuck child can never hang the test run.

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::time::Instant;

/// How often [`OwnedChild::wait_until`] and [`OwnedChild::wait_for_handshake`] look again.
const POLL: Duration = Duration::from_millis(20);

/// The most of a child's stderr that is kept: its first 256 KiB. The rest is still read, so the
/// child never blocks, but only counted.
pub const STDERR_CAP: usize = 256 << 10;

/// The body of a child's stderr reader, for the function that starts its thread.
pub type Reader = Box<dyn FnOnce() + Send + 'static>;

/// Starts `body` on its own thread, or returns why the OS could not create one.
pub fn reader_thread(body: Reader) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("child-stderr".to_owned())
        .spawn(body)
}

/// A readiness line looked for in stderr as it is read, so no poll copies or rescans the log,
/// and a line past [`STDERR_CAP`] is still seen.
pub struct Handshake {
    needle: Vec<u8>,
    /// The bytes since the last read that may start a match: at most `needle.len() - 1`.
    carry: Vec<u8>,
    seen: bool,
}

impl Handshake {
    pub fn new(needle: &str) -> Self {
        assert!(!needle.is_empty(), "an empty handshake matches nothing");
        Self {
            needle: needle.as_bytes().to_vec(),
            carry: Vec::new(),
            seen: false,
        }
    }

    /// Looks for the needle in the next `bytes` of the stream, a match split across reads
    /// included.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.seen {
            return;
        }
        self.carry.extend_from_slice(bytes);
        self.seen = self
            .carry
            .windows(self.needle.len())
            .any(|w| w == self.needle);
        let start = self.carry.len().saturating_sub(self.needle.len() - 1);
        self.carry.drain(..start);
    }

    pub fn seen(&self) -> bool {
        self.seen
    }
}

/// What the reader has taken from a child's stderr.
#[derive(Default)]
struct Log {
    /// The first [`STDERR_CAP`] bytes.
    kept: Vec<u8>,
    /// Every byte read, kept or not.
    read: u64,
    handshake: Option<Handshake>,
}

impl Log {
    fn record(&mut self, bytes: &[u8]) {
        self.read += bytes.len() as u64;
        let take = bytes.len().min(STDERR_CAP - self.kept.len());
        if self.kept.capacity() - self.kept.len() < take {
            // Grow as `Vec` would, but never past the cap.
            let grown = (self.kept.capacity() * 2).clamp(self.kept.len() + take, STDERR_CAP);
            self.kept.reserve_exact(grown - self.kept.len());
        }
        self.kept.extend_from_slice(&bytes[..take]);
        if let Some(handshake) = &mut self.handshake {
            handshake.feed(bytes);
        }
    }
}

/// A spawned child process. Its stderr is read on a thread as it arrives, so a child that
/// logs more than a pipe holds never blocks in `write` (a tokio worker blocked there stops the
/// child's whole runtime: timers, I/O and signal delivery).
pub struct OwnedChild {
    child: Reaped,
    log: Arc<Mutex<Log>>,
    /// Ends at the pipe's end of file, once the child has exited.
    reader: JoinHandle<()>,
}

impl OwnedChild {
    /// Spawns `command` with stdin closed and stderr captured.
    pub fn spawn(command: Command) -> std::io::Result<Self> {
        Self::spawn_with(command, None, reader_thread)
    }

    /// [`Self::spawn`], looking for `handshake` in stderr from its first byte on (see
    /// [`Self::wait_for_handshake`]).
    pub fn spawn_with_handshake(command: Command, handshake: &str) -> std::io::Result<Self> {
        Self::spawn_with(command, Some(handshake), reader_thread)
    }

    /// [`Self::spawn`], with an optional `handshake`, and `start_reader` starting the stderr
    /// reader. If that fails, the child is killed and reaped and its error returned.
    pub fn spawn_with(
        mut command: Command,
        handshake: Option<&str>,
        start_reader: impl FnOnce(Reader) -> std::io::Result<JoinHandle<()>>,
    ) -> std::io::Result<Self> {
        let child = command
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        // Guarded from here on: if the reader cannot start, the `?` below kills and reaps it.
        let mut child = Reaped(child);
        let mut pipe = child.0.stderr.take().expect("stderr is piped");
        let log = Arc::new(Mutex::new(Log {
            handshake: handshake.map(Handshake::new),
            ..Log::default()
        }));
        let sink = Arc::clone(&log);
        let reader = start_reader(Box::new(move || {
            let mut buf = [0u8; 8192];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => sink.lock().unwrap().record(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        }))?;
        Ok(Self { child, log, reader })
    }

    pub fn pid(&self) -> rustix::process::Pid {
        rustix::process::Pid::from_child(&self.child.0)
    }

    /// What the child wrote to stderr so far: at most its first [`STDERR_CAP`] bytes, then a
    /// line saying how much more there was.
    pub fn stderr(&self) -> String {
        let log = self.log.lock().unwrap();
        let mut text = String::from_utf8_lossy(&log.kept).into_owned();
        if log.read > log.kept.len() as u64 {
            text.push_str(&format!(
                "\n[stderr truncated: kept the first {} of {} bytes]",
                log.kept.len(),
                log.read
            ));
        }
        text
    }

    /// How many bytes of stderr have been read, kept or not.
    pub fn stderr_read(&self) -> u64 {
        self.log.lock().unwrap().read
    }

    /// How much memory the kept stderr holds, in bytes.
    pub fn stderr_held(&self) -> usize {
        self.log.lock().unwrap().kept.capacity()
    }

    /// Whether stderr shows the spawn's handshake by `deadline`: a readiness handshake, not a
    /// sleep. `false` as soon as stderr ends without it.
    pub async fn wait_for_handshake(&self, deadline: Instant) -> bool {
        loop {
            // Taken first: once the reader has finished, its last read is already recorded.
            let ended = self.reader.is_finished();
            let seen = self
                .log
                .lock()
                .unwrap()
                .handshake
                .as_ref()
                .expect("spawned with a handshake")
                .seen();
            if seen {
                return true;
            }
            if ended || Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// The child's exit status, or `None` if it is still running at `deadline`. Polls
    /// `try_wait` rather than blocking in `wait`, so no thread is left waiting on the child.
    /// After the exit it also waits (to the same deadline) for the rest of stderr.
    pub async fn wait_until(&mut self, deadline: Instant) -> Option<ExitStatus> {
        let status = loop {
            if let Some(status) = self.child.0.try_wait().expect("try_wait on the child") {
                break status;
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(POLL).await;
        };
        while !self.reader.is_finished() && Instant::now() < deadline {
            tokio::time::sleep(POLL).await;
        }
        Some(status)
    }
}

/// A child that is killed and reaped when dropped, from the moment it is spawned.
struct Reaped(Child);

/// SIGKILL and reap on every way out of the test: a pass, a failed assertion (the panic
/// unwinds through here), a deadline, or a reader that could not start. Killing a child that
/// already exited is harmless.
impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
