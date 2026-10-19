//! A process whose log-writer thread cannot start never blocks on stderr, and `run` stops at
//! once with `EXIT_NO_LOG_WRITER`, writing nothing.
//!
//! The thread fails to start for real: each child is this test binary re-executed to run
//! `no_log_writer_child` (ignored, and a no-op without its environment) with `RUST_MIN_STACK`
//! past any address space, so every thread spawn fails (the harness then runs the test on its
//! main thread). Its stdout is a file the test reads for the child's own diagnostics.

mod common;

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use common::child::{OwnedChild, Stalled, NO_THREAD_STACK};
use common::*;
use ethswarm_proto::engine::engine_service_server::EngineServiceServer;
use svc_runtime::telemetry::{
    init_binary_tracing, try_init_tracing, try_init_tracing_with, LogQueueBounds, TracingInitError,
    EXIT_NO_LOG_WRITER,
};
use svc_runtime::{exit_code, Config, RuntimeError, Services};
use tokio::time::Instant;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::Identity;

/// What `no_log_writer_child` does: [`PANIC`] or [`RUN`].
const CHILD_MODE: &str = "SVC_RUNTIME_NO_LOG_WRITER_MODE";
/// The config `run` loads in [`RUN`] mode.
const CHILD_CONFIG: &str = "SVC_RUNTIME_NO_LOG_WRITER_CONFIG";
/// Carry on without logs past the failed start, then panic with stderr full.
const PANIC: &str = "panic";
/// `svc_runtime::run`, which must stop on the failed start.
const RUN: &str = "run";
/// The exit status of a [`PANIC`] child that got through.
const PANIC_SURVIVED: i32 = 0;
/// Every wait on a child is bounded by this.
const STEP: Duration = Duration::from_secs(30);

/// The arguments that run [`no_log_writer_child`] in this test binary.
const CHILD_ARGS: [&str; 4] = ["--exact", "no_log_writer_child", "--ignored", "--nocapture"];

/// The process side of every test here.
#[test]
#[ignore = "run by the tests of this file in a child process"]
fn no_log_writer_child() {
    let Some(mode) = std::env::var(CHILD_MODE).ok() else {
        return;
    };
    match mode.as_str() {
        PANIC => panic_child(),
        RUN => run_child(),
        other => panic!("unknown mode {other}"),
    }
}

fn panic_child() {
    let first = try_init_tracing_with(
        LevelFilter::INFO,
        LogQueueBounds::default(),
        Identity::new(),
    );
    println!("first: {first:?}");
    assert!(
        matches!(first, Err(TracingInitError::WriterUnavailable(_))),
        "{first:?}"
    );
    // The first call settled it: an owner that carries on is not refused by a later call.
    let again = try_init_tracing(LevelFilter::INFO);
    println!("again: {again:?}");
    assert!(
        matches!(again, Err(TracingInitError::AlreadyInitialized)),
        "{again:?}"
    );
    assert!(init_binary_tracing(LevelFilter::INFO).is_ok());
    tracing::error!("no subscriber: goes nowhere");
    // The default hook would write this to the full stderr and block here for good.
    let caught = std::panic::catch_unwind(|| panic!("after the log writer failed to start"));
    assert!(caught.is_err());
    println!("survived the panic");
    std::process::exit(PANIC_SURVIVED);
}

fn run_child() {
    let path = std::env::var_os(CHILD_CONFIG).expect("a config");
    let config = Config::load("cl-engine", path.as_ref()).unwrap();
    // A current-thread runtime starts no thread, so it builds without any.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(svc_runtime::run(
        config,
        // Never served: `run` must stop before it binds anything.
        Services::new().add_service(EngineServiceServer::new(cl_engine::EngineStub::new(
            ipc::testkit::fixture::v1_link(),
        ))),
    ));
    println!("run: {result:?}");
    assert!(
        matches!(result, Err(RuntimeError::LogWriter(_))),
        "{result:?}"
    );
    assert_eq!(exit_code(&result), ExitCode::from(EXIT_NO_LOG_WRITER));
    std::process::exit(EXIT_NO_LOG_WRITER.into());
}

/// This binary, to run [`no_log_writer_child`] in `mode` with no thread able to start, its
/// stdout written to `stdout`.
fn child(mode: &str, stdout: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(CHILD_ARGS)
        .env(CHILD_MODE, mode)
        .env("RUST_MIN_STACK", NO_THREAD_STACK)
        .env_remove("NOTIFY_SOCKET")
        .stdout(Stdio::from(std::fs::File::create(stdout).unwrap()));
    command
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[tokio::test]
async fn a_panic_after_the_writer_failed_to_start_does_not_block_on_a_full_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let stdout = tmp.path().join("stdout");
    let mut stalled = Stalled::spawn(child(PANIC, &stdout)).unwrap();
    let status = stalled
        .wait_until(Instant::now() + STEP)
        .await
        .unwrap_or_else(|| {
            panic!(
                "still running after {STEP:?}: blocked on stderr?\n{}",
                read(&stdout)
            )
        });
    assert_eq!(status.code(), Some(PANIC_SURVIVED), "{}", read(&stdout));
}

#[tokio::test]
async fn run_stops_without_a_log_writer_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let config = tmp.path().join("cl-engine.toml");
    let text = engine_toml(
        &root,
        ipc::peercred::effective_gid(),
        me(),
        &ENGINE_METHODS,
        r#"["cl-chain"]"#,
        1000,
    );
    std::fs::write(&config, text).unwrap();
    let stdout = tmp.path().join("stdout");
    let mut command = child(RUN, &stdout);
    command.env(CHILD_CONFIG, &config);
    let mut child = OwnedChild::spawn(command).unwrap();
    let status = child
        .wait_until(Instant::now() + STEP)
        .await
        .unwrap_or_else(|| panic!("still running after {STEP:?}\n{}", read(&stdout)));
    assert_eq!(
        status.code(),
        Some(i32::from(EXIT_NO_LOG_WRITER)),
        "{}",
        read(&stdout)
    );
    assert_eq!(child.stderr(), "", "nothing reaches stderr");
    // `run` stopped before binding the socket.
    let socket = ipc::uds::SocketDir::under(&root, "cl-engine").unwrap();
    assert!(!socket.socket_path().exists());
}
