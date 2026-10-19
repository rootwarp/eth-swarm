//! An owner's layer that calls the init from inside it (its `on_layer`, which runs under the
//! init's lock) is refused at once with `Reentrant` instead of deadlocking on that lock, and
//! the outer init goes on to settle the logging.
//!
//! The only test in this file, so the first init of its process is the one it makes.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use svc_runtime::telemetry::{
    init_binary_tracing, try_init_tracing, try_init_tracing_with, LogQueueBounds, TracingInitError,
};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::Layer;

/// Far past an init that does not deadlock.
const STEP: Duration = Duration::from_secs(30);

/// What the re-entrant calls returned, as `Debug` text.
type Seen = Arc<Mutex<Vec<String>>>;

/// An owner's layer that calls the init again once layered onto the registry.
struct Reenters(Seen);

impl<S: tracing::Subscriber> Layer<S> for Reenters {
    fn on_layer(&mut self, _: &mut S) {
        let again = try_init_tracing(LevelFilter::INFO);
        let binary = init_binary_tracing(LevelFilter::INFO);
        let mut seen = self.0.lock().unwrap();
        seen.push(format!("{again:?}"));
        seen.push(format!("{binary:?}"));
    }
}

#[test]
fn an_init_called_from_inside_the_init_is_refused_not_deadlocked() {
    let seen = Seen::default();
    let layer = Reenters(Arc::clone(&seen));
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let outer = try_init_tracing_with(LevelFilter::INFO, LogQueueBounds::default(), layer);
        let after = try_init_tracing(LevelFilter::INFO);
        let _ = done.send((format!("{outer:?}"), after));
    });
    let (outer, after) = finished
        .recv_timeout(STEP)
        .unwrap_or_else(|_| panic!("the init did not return within {STEP:?}: deadlocked?"));
    assert_eq!(outer, "Ok(())");
    assert_eq!(
        *seen.lock().unwrap(),
        ["Err(Reentrant)", "Ok(())"],
        "the re-entrant calls are refused; a binary's goes on, the outer init settles it"
    );
    assert!(
        matches!(after, Err(TracingInitError::AlreadyInitialized)),
        "once the outer init is over, the thread is not inside it: {after:?}"
    );
}
