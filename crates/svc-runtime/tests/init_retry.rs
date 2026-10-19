//! An owner's layer that panics under the init, after the log writer started, leaves that
//! writer for the next call: a retry once the panic is caught starts no second writer thread,
//! and its logging works.
//!
//! The only test in this file, so the first init of its process is the one it makes.

use std::time::Duration;

use svc_runtime::telemetry::{
    flush_logs, queue_stderr, try_init_tracing, try_init_tracing_with, LogQueueBounds,
};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::Layer;

/// An owner's layer that panics once layered onto the registry.
struct Panics;

impl<S: tracing::Subscriber> Layer<S> for Panics {
    fn on_layer(&mut self, _: &mut S) {
        panic!("the owner's layer panics under the init");
    }
}

/// The threads of this process.
fn threads() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc/self/task").unwrap().count()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // One line per thread, under a header.
        let out = std::process::Command::new("ps")
            .args(["-M", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap().lines().count() - 1
    }
}

#[test]
fn a_retry_after_an_owners_layer_panicked_reuses_the_log_writer() {
    let before = threads();
    for attempt in 0..3 {
        let caught = std::panic::catch_unwind(|| {
            try_init_tracing_with(LevelFilter::INFO, LogQueueBounds::default(), Panics)
        });
        assert!(caught.is_err(), "attempt {attempt}: the layer panicked");
    }
    let retry = try_init_tracing(LevelFilter::INFO);
    assert!(retry.is_ok(), "{retry:?}");
    assert_eq!(
        threads(),
        before + 1,
        "one log-writer thread, never one per attempt"
    );
    assert!(queue_stderr(b"queued after the retry\n"));
    assert!(flush_logs(Duration::from_secs(10)));
}
