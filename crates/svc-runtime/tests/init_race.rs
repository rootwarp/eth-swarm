//! Two threads that race through the first tracing init both find the bounded panic hook in
//! place once their call returns, the one that loses the race (`AlreadyInitialized`) too: a
//! panic right after it never blocks on a full stderr.
//!
//! The race runs in a child, this test binary re-executed to run `init_race_child` (ignored,
//! and a no-op without its environment), with its stderr a full pipe nobody reads, so the
//! default hook would block the panicking thread for good. The winner's `extra` layer holds
//! its init open, between starting the log writer and installing the hook, until the loser's
//! call has returned and its panic is over, or [`HOLD`] has passed. Its stdout is a file the
//! test reads for the child's own diagnostics.

mod common;

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use common::child::Stalled;
use svc_runtime::telemetry::{try_init_tracing, try_init_tracing_with, LogQueueBounds};
use tokio::time::Instant;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::Layer;

/// Set, `init_race_child` runs the race.
const CHILD_MODE: &str = "SVC_RUNTIME_INIT_RACE";
/// The exit status of a child whose two threads both got through their panic.
const SURVIVED: i32 = 0;
/// How long the winner's init waits for the loser: far past the loser's own init and panic
/// when nothing blocks them.
const HOLD: Duration = Duration::from_secs(2);
/// Every wait on the child is bounded by this.
const STEP: Duration = Duration::from_secs(30);

/// The arguments that run [`init_race_child`] in this test binary.
const CHILD_ARGS: [&str; 4] = ["--exact", "init_race_child", "--ignored", "--nocapture"];

/// The winner's extra layer: once layered onto the registry, inside the winner's init, it
/// says so on `entered` and waits up to [`HOLD`] on `released`.
struct Hold {
    entered: Mutex<Option<Sender<()>>>,
    released: Mutex<Receiver<()>>,
}

impl<S: tracing::Subscriber> Layer<S> for Hold {
    fn on_layer(&mut self, _: &mut S) {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        let _ = self.released.lock().unwrap().recv_timeout(HOLD);
    }
}

/// The process side of the test.
#[test]
#[ignore = "run by the test of this file in a child process"]
fn init_race_child() {
    if std::env::var_os(CHILD_MODE).is_none() {
        return;
    }
    let start = Arc::new(Barrier::new(2));
    let (entered, inside) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let winner = {
        let start = Arc::clone(&start);
        std::thread::spawn(move || {
            start.wait();
            let hold = Hold {
                entered: Mutex::new(Some(entered)),
                released: Mutex::new(released),
            };
            let init = try_init_tracing_with(LevelFilter::INFO, LogQueueBounds::default(), hold);
            println!("winner: {init:?}");
            assert!(init.is_ok(), "{init:?}");
            panic_bounded("the winner")
        })
    };
    let loser = std::thread::spawn(move || {
        start.wait();
        // The winner is inside its init, the log writer started.
        inside.recv().unwrap();
        let init = try_init_tracing(LevelFilter::INFO);
        println!("loser: {init:?}");
        assert!(init.is_err(), "{init:?}");
        let survived = panic_bounded("the loser");
        let _ = release.send(());
        survived
    });
    let survived = [loser.join(), winner.join()];
    println!("survived: {survived:?}");
    let all = survived.iter().all(|s| matches!(s, Ok(true)));
    std::process::exit(if all { SURVIVED } else { 1 });
}

/// Panics on this thread and catches it: the default hook would write to the full stderr and
/// block here. `true` once the panic is over.
fn panic_bounded(who: &str) -> bool {
    let caught = std::panic::catch_unwind(|| panic!("{who} panics after its init"));
    println!("{who} survived its panic");
    caught.is_err()
}

/// This binary, to run [`init_race_child`], its stdout written to `stdout`.
fn child(stdout: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(CHILD_ARGS)
        .env(CHILD_MODE, "1")
        .env_remove("RUST_BACKTRACE")
        .stdout(Stdio::from(std::fs::File::create(stdout).unwrap()));
    command
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[tokio::test]
async fn both_racers_see_the_bounded_panic_hook_once_their_init_returns() {
    let tmp = tempfile::tempdir().unwrap();
    let stdout = tmp.path().join("stdout");
    let mut stalled = Stalled::spawn(child(&stdout)).unwrap();
    let status = stalled
        .wait_until(Instant::now() + STEP)
        .await
        .unwrap_or_else(|| {
            panic!(
                "still running after {STEP:?}: a panic blocked on stderr?\n{}",
                read(&stdout)
            )
        });
    assert_eq!(status.code(), Some(SURVIVED), "{}", read(&stdout));
}
