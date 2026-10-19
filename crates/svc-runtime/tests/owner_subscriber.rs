//! An embedding owner that installed its own subscriber and panic hook first keeps both: the
//! init starts the log writer, for queued stderr text, and leaves the hook alone.
//!
//! The only test in this file, so the first init of its process is the one it makes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use svc_runtime::telemetry::{
    flush_logs, init_binary_tracing, queue_stderr, try_init_tracing, TracingInitError,
};
use tracing_subscriber::filter::LevelFilter;

/// Set by the owner's panic hook.
static OWNER_HOOK_RAN: AtomicBool = AtomicBool::new(false);

#[test]
fn an_owners_subscriber_keeps_its_panic_hook_and_gets_the_writer() {
    tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
    std::panic::set_hook(Box::new(|_| OWNER_HOOK_RAN.store(true, Ordering::SeqCst)));

    let init = try_init_tracing(LevelFilter::INFO);
    assert!(
        matches!(init, Err(TracingInitError::AlreadyInitialized)),
        "{init:?}"
    );
    assert!(
        matches!(
            try_init_tracing(LevelFilter::INFO),
            Err(TracingInitError::AlreadyInitialized)
        ),
        "the first call settled it"
    );
    assert_eq!(init_binary_tracing(LevelFilter::INFO), Ok(()));

    let caught = std::panic::catch_unwind(|| panic!("with the owner's hook in place"));
    assert!(caught.is_err());
    assert!(
        OWNER_HOOK_RAN.load(Ordering::SeqCst),
        "the owner's hook ran"
    );

    assert!(queue_stderr(
        b"plain text queued with an owner's subscriber\n"
    ));
    assert!(flush_logs(Duration::from_secs(10)));
}
