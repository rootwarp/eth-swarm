//! A child process a test owns, so a stuck child can never hang the test run.

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::time::Instant;

/// How often [`OwnedChild::wait_until`] looks for the exit.
const POLL: Duration = Duration::from_millis(20);

/// A spawned child process. Its stderr is read on a thread as it arrives, so a child that
/// logs more than a pipe holds never blocks in `write` (a tokio worker blocked there stops the
/// child's whole runtime: timers, I/O and signal delivery).
pub struct OwnedChild {
    child: Child,
    stderr: Arc<Mutex<Vec<u8>>>,
    /// Ends at the pipe's end of file, once the child has exited.
    reader: JoinHandle<()>,
}

impl OwnedChild {
    /// Spawns `command` with stdin closed and stderr captured.
    pub fn spawn(mut command: Command) -> std::io::Result<Self> {
        let mut child = command
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut pipe = child.stderr.take().expect("stderr is piped");
        let stderr = Arc::<Mutex<Vec<u8>>>::default();
        let sink = Arc::clone(&stderr);
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            child,
            stderr,
            reader,
        })
    }

    pub fn pid(&self) -> rustix::process::Pid {
        rustix::process::Pid::from_child(&self.child)
    }

    /// What the child wrote to stderr so far.
    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }

    /// Whether stderr shows `needle` by `deadline`: a readiness handshake, not a sleep.
    pub async fn wait_for_stderr(&self, needle: &str, deadline: Instant) -> bool {
        loop {
            if self.stderr().contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
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
            if let Some(status) = self.child.try_wait().expect("try_wait on the child") {
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

/// SIGKILL and reap on every way out of the test: a pass, a failed assertion (the panic
/// unwinds through here), or a deadline. Killing a child that already exited is harmless.
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
