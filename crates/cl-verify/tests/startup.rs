//! Process startup: the trusted setup is loaded and its sha256 checked against the beta.4 mainnet
//! pin before the socket is bound, and READY is sent only once the server is serving.
//!
//! "Never calls c-kzg" is observed through the error: `DigestMismatch` is returned by
//! `crypto_kzg::TrustedSetup::load_pinned` before the file is parsed, and crypto-kzg's own tests
//! count the c-kzg builder calls on that path (zero).

mod common;

use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use cl_verify::caps::MAX_KZG_COLUMNS;
use cl_verify::notify;
use cl_verify::proto::common::Hello;
use cl_verify::proto::verify::verify_service_client::VerifyServiceClient;
use cl_verify::proto::verify::{
    verify_kzg_response, KzgCellProof, VerifyKzgRequestBody, VerifyStatus,
};
use cl_verify::server::Limits;
use cl_verify::startup::{
    run_with, run_with_signals, Readiness, StartupConfig, StartupError, Stopped, Termination,
};
use common::*;
use crypto_kzg::{SetupError, BETA4_MAINNET_SHA256};
use ipc::testkit::devnet::{
    devnet_genesis_state, kurtosis_hello, write_network_file, KURTOSIS_CONFIG, KURTOSIS_MAX_BLOBS,
};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

/// Records READY and wakes the test when it arrives.
#[derive(Default)]
struct Recorder {
    calls: AtomicUsize,
    /// At each READY, whether `socket` accepted a connection: the path also exists between
    /// `bind` and `listen`, when a connect is refused.
    socket_accepted: Mutex<Vec<bool>>,
    socket: Option<std::path::PathBuf>,
    woken: Mutex<Option<oneshot::Sender<()>>>,
}

impl Readiness for Recorder {
    fn ready(&self) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(path) = &self.socket {
            let accepted = std::os::unix::net::UnixStream::connect(path).is_ok();
            self.socket_accepted.lock().unwrap().push(accepted);
        }
        if let Some(tx) = self.woken.lock().unwrap().take() {
            let _ = tx.send(());
        }
        Ok(())
    }
}

fn startup_config(setup: cl_verify::kzg::TrustedSetupConfig, socket: &Path) -> StartupConfig {
    let mut server = config(my_uid(), Limits::default());
    server.trusted_setup = setup;
    StartupConfig {
        server,
        socket_path: socket.to_path_buf(),
        drain_timeout: Duration::from_secs(10),
    }
}

/// A feed stream on `socket` (hello `ours`) that rebuilds validators `0..saved`, waits until that
/// is saved to `snapshot`, then appends `saved..total`. The append lands within the snapshot
/// interval, so only a shutdown flush can write it.
async fn feed_dirty_snapshot(
    socket: &Path,
    ours: Hello,
    snapshot: &Path,
    saved: u64,
    total: u64,
) -> (VerifyServiceClient<tonic::transport::Channel>, FeedStream) {
    let mut client = VerifyServiceClient::new(connect(socket).await);
    let (tx, rx) = mpsc::channel(8);
    let rx = client
        .pubkey_feed(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let mut feed = Bidi {
        tx,
        rx,
        generation: 0,
    };
    feed.send(feed_hello(ours)).await;
    assert!(feed.next().await.unwrap().is_some(), "server hello");
    assert_eq!(feed_reply(&mut feed).await.high_water, 0);
    feed.send(feed_body(announcing(feed_frame(0, 0..saved), saved)))
        .await;
    assert_eq!(feed_reply(&mut feed).await.high_water, saved);
    wait_for(|| snapshot_holds(snapshot, saved)).await;
    feed.send(feed_body(feed_frame(saved, saved..total))).await;
    assert_eq!(feed_reply(&mut feed).await.high_water, total);
    assert!(!snapshot_holds(snapshot, total), "saved before shutdown");
    (client, feed)
}

#[tokio::test]
async fn startup_refuses_bad_setup() {
    let dir = tempfile::tempdir().unwrap();
    let setup = tampered_setup(dir.path());
    let actual: [u8; 32] = Sha256::digest(std::fs::read(&setup.path).unwrap()).into();
    let socket = dir.path().join("verify.sock");
    let readiness = Recorder::default();

    let err = run_with(startup_config(setup, &socket), &readiness, async {})
        .await
        .unwrap_err();

    assert!(
        matches!(&err, StartupError::Setup(SetupError::DigestMismatch { expected, actual: got })
            if *expected == BETA4_MAINNET_SHA256 && *got == actual),
        "{err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains(&hex::encode(BETA4_MAINNET_SHA256)), "{msg}");
    assert!(msg.contains(&hex::encode(actual)), "{msg}");
    assert!(!socket.exists(), "socket bound despite a refused setup");
    assert_eq!(readiness.calls.load(Ordering::SeqCst), 0, "READY sent");
}

#[tokio::test]
async fn missing_setup_fails_before_bind() {
    let dir = tempfile::tempdir().unwrap();
    let setup = cl_verify::kzg::TrustedSetupConfig {
        path: dir.path().join("absent.json"),
    };
    let socket = dir.path().join("verify.sock");
    let readiness = Recorder::default();
    let err = run_with(startup_config(setup, &socket), &readiness, async {})
        .await
        .unwrap_err();
    assert!(
        matches!(err, StartupError::Setup(SetupError::Io { .. })),
        "{err:?}"
    );
    assert!(!socket.exists());
    assert_eq!(readiness.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pinned_setup_binds_serves_then_reports_ready() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let (woken_tx, woken) = oneshot::channel();
    let readiness = std::sync::Arc::new(Recorder {
        socket: Some(socket.clone()),
        woken: Mutex::new(Some(woken_tx)),
        ..Recorder::default()
    });
    let (stop, stopped) = oneshot::channel::<()>();
    let cfg = startup_config(setup_config(), &socket);
    let task = {
        let readiness = std::sync::Arc::clone(&readiness);
        tokio::spawn(async move {
            run_with(cfg, readiness.as_ref(), async {
                let _ = stopped.await;
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(30), woken)
        .await
        .expect("READY within 30 s")
        .expect("READY sent");
    assert_eq!(*readiness.socket_accepted.lock().unwrap(), [true]);

    // The server answers a real stream on the socket it reported ready on.
    let mut client = VerifyServiceClient::new(connect(&socket).await);
    let (tx, rx) = mpsc::channel(8);
    let rx = client
        .pubkey_feed(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let mut feed = Bidi {
        tx,
        rx,
        generation: 0,
    };
    feed.send(feed_hello(hello())).await;
    assert!(feed.next().await.unwrap().is_some(), "server hello");
    assert_eq!(feed_reply(&mut feed).await.high_water, 0);

    // Graceful shutdown waits for open connections, so close ours first.
    drop((feed, client));
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("clean shutdown within 30 s")
        .unwrap()
        .unwrap();
    assert_eq!(readiness.calls.load(Ordering::SeqCst), 1);
    assert!(
        !socket.exists(),
        "socket left behind after a clean shutdown"
    );
}

#[tokio::test]
async fn socket_replaced_while_serving_is_left_alone() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let (woken_tx, woken) = oneshot::channel();
    let readiness = std::sync::Arc::new(Recorder {
        woken: Mutex::new(Some(woken_tx)),
        ..Recorder::default()
    });
    let (stop, stopped) = oneshot::channel::<()>();
    let cfg = startup_config(setup_config(), &socket);
    let task = {
        let readiness = std::sync::Arc::clone(&readiness);
        tokio::spawn(async move {
            run_with(cfg, readiness.as_ref(), async {
                let _ = stopped.await;
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(30), woken)
        .await
        .expect("READY within 30 s")
        .unwrap();

    // Someone else now owns the path: shutdown must not unlink their socket.
    std::fs::remove_file(&socket).unwrap();
    let theirs = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let ino = std::fs::symlink_metadata(&socket).unwrap().ino();
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("clean shutdown within 30 s")
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::symlink_metadata(&socket).unwrap().ino(), ino);
    drop(theirs);
}

#[tokio::test]
async fn failed_ready_notification_fails_startup() {
    struct NoManager;
    impl Readiness for NoManager {
        fn ready(&self) -> io::Result<()> {
            Err(io::Error::other("manager gone"))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let err = run_with(
        startup_config(setup_config(), &socket),
        &NoManager,
        std::future::pending(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StartupError::Notify(_)), "{err:?}");
    assert!(!socket.exists(), "socket left behind after a failed READY");
}

#[tokio::test]
async fn occupied_socket_path_is_a_bind_error() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    std::fs::write(&socket, b"not a socket").unwrap();
    let readiness = Recorder::default();
    let err = run_with(
        startup_config(setup_config(), &socket),
        &readiness,
        std::future::pending(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StartupError::Bind { .. }), "{err:?}");
    assert_eq!(std::fs::read(&socket).unwrap(), b"not a socket");
    assert_eq!(readiness.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stale_socket_from_a_previous_run_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());
    let (woken_tx, woken) = oneshot::channel();
    let readiness = Recorder {
        woken: Mutex::new(Some(woken_tx)),
        ..Recorder::default()
    };
    // Shut down as soon as READY is sent.
    run_with(startup_config(setup_config(), &socket), &readiness, async {
        let _ = woken.await;
    })
    .await
    .unwrap();
    assert_eq!(readiness.calls.load(Ordering::SeqCst), 1);
    assert!(!socket.exists(), "our socket is removed on exit");
}

#[tokio::test]
async fn a_shutdown_during_setup_binds_nothing_and_sends_no_ready() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let readiness = Recorder::default();
    // The signal arrived while the trusted setup was loading: shutdown has already happened.
    run_with(startup_config(setup_config(), &socket), &readiness, async {
    })
    .await
    .expect("a clean exit");
    assert!(
        !socket.exists(),
        "socket bound after shutdown was requested"
    );
    assert_eq!(readiness.calls.load(Ordering::SeqCst), 0, "READY sent");

    let (signals, sender) = Termination::channel();
    sender.signal();
    let readiness = Recorder::default();
    let stopped = run_with_signals(startup_config(setup_config(), &socket), &readiness, signals)
        .await
        .unwrap();
    assert_eq!(stopped, Stopped::Graceful);
    assert!(!socket.exists());
    assert_eq!(readiness.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_second_signal_during_the_drain_returns_at_once_without_the_flush() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let snapshot = dir.path().join("pubkeys.bin");
    let mut cfg = startup_config(setup_config(), &socket);
    cfg.server.pubkey_snapshot = snapshot.clone();
    cfg.drain_timeout = Duration::from_secs(60);
    let (woken_tx, woken) = oneshot::channel();
    let readiness = std::sync::Arc::new(Recorder {
        woken: Mutex::new(Some(woken_tx)),
        ..Recorder::default()
    });
    let (signals, sender) = Termination::channel();
    let task = {
        let readiness = std::sync::Arc::clone(&readiness);
        tokio::spawn(async move { run_with_signals(cfg, readiness.as_ref(), signals).await })
    };
    tokio::time::timeout(Duration::from_secs(30), woken)
        .await
        .expect("READY within 30 s")
        .unwrap();
    // The open feed stream holds the drain for its full minute.
    let (_client, _feed) = feed_dirty_snapshot(&socket, hello(), &snapshot, 3, 5).await;
    sender.signal();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!task.is_finished(), "draining");
    sender.signal();
    let stopped = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the second signal ends it at once")
        .unwrap()
        .unwrap();
    assert_eq!(stopped, Stopped::Forced);
    assert!(!snapshot_holds(&snapshot, 5), "the flush was skipped");
    assert!(snapshot_holds(&snapshot, 3), "the last save is intact");
    assert!(!socket.exists(), "socket removed");
}

#[tokio::test]
async fn shutdown_flushes_a_dirty_snapshot_within_the_drain_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let snapshot = dir.path().join("pubkeys.bin");
    let mut cfg = startup_config(setup_config(), &socket);
    cfg.server.pubkey_snapshot = snapshot.clone();
    cfg.drain_timeout = Duration::from_millis(300);
    let (woken_tx, woken) = oneshot::channel();
    let readiness = std::sync::Arc::new(Recorder {
        woken: Mutex::new(Some(woken_tx)),
        ..Recorder::default()
    });
    let (stop, stopped) = oneshot::channel::<()>();
    let task = {
        let readiness = std::sync::Arc::clone(&readiness);
        tokio::spawn(async move {
            run_with(cfg, readiness.as_ref(), async {
                let _ = stopped.await;
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(30), woken)
        .await
        .expect("READY within 30 s")
        .unwrap();
    // The feed stream stays open: graceful shutdown cannot finish on its own, the drain bound
    // ends it.
    let (_client, _feed) = feed_dirty_snapshot(&socket, hello(), &snapshot, 3, 5).await;
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("shutdown bounded by the drain timeout")
        .unwrap()
        .unwrap();
    assert!(snapshot_holds(&snapshot, 5), "dirty snapshot flushed");
    assert!(!socket.exists(), "socket removed");
}

// ---- the real binary ----

/// Writes the `config.yaml` (the shape of our Kurtosis devnet: Fulu and Gloas at epoch 0) and
/// `genesis.ssz` of the devnet to `dir/net`, mode 0644, and returns that directory.
fn network_dir(dir: &Path) -> std::path::PathBuf {
    let net = dir.join("net");
    std::fs::create_dir_all(&net).unwrap();
    write_network_file(net.join("config.yaml"), KURTOSIS_CONFIG);
    write_network_file(net.join("genesis.ssz"), devnet_genesis_state(256));
    net
}

/// The hello cl-chain's side of the verify.v1 link sends for the devnet now: the network hello
/// of the same files, the way the probe builds it.
fn chain_hello() -> Hello {
    kurtosis_hello("devnet-probe/test")
        .at(u128::from(cl_verify::wire::now_unix_ms()))
        .unwrap()
}

fn cl_verify() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cl-verify"));
    cmd.env_remove("NOTIFY_SOCKET");
    cmd
}

#[test]
fn binary_exits_nonzero_on_a_tampered_setup_without_binding() {
    let dir = tempfile::tempdir().unwrap();
    let setup = tampered_setup(dir.path());
    let actual: [u8; 32] = Sha256::digest(std::fs::read(&setup.path).unwrap()).into();
    let socket = dir.path().join("verify.sock");
    // A manager socket that would receive READY if it were (wrongly) sent.
    let notify_path = dir.path().join("notify.sock");
    let manager = std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();
    manager.set_nonblocking(true).unwrap();

    let out = cl_verify()
        .env("NOTIFY_SOCKET", &notify_path)
        .arg("--trusted-setup")
        .arg(&setup.path)
        .arg("--socket")
        .arg(&socket)
        .args(["--peer-uid", &my_uid().to_string()])
        .arg("--pubkey-snapshot")
        .arg(dir.path().join("pubkeys.bin"))
        .arg("--network-dir")
        .arg(network_dir(dir.path()))
        .output()
        .unwrap();

    assert!(!out.status.success(), "{out:?}");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&hex::encode(BETA4_MAINNET_SHA256)),
        "{stderr}"
    );
    assert!(stderr.contains(&hex::encode(actual)), "{stderr}");
    assert!(!stderr.contains("network config is not wired"), "{stderr}");
    assert!(!socket.exists(), "socket bound despite a refused setup");
    let mut buf = [0u8; 64];
    assert_eq!(
        manager.recv(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "READY sent"
    );
}

/// Starts the binary on a fresh dir and waits for its READY.
fn spawn_binary(dir: &Path) -> std::process::Child {
    spawn_binary_with(dir, &dir.join("pubkeys.bin"), std::process::Stdio::null())
}

/// [`spawn_binary`] with the given snapshot path and stderr.
fn spawn_binary_with(
    dir: &Path,
    snapshot: &Path,
    stderr: std::process::Stdio,
) -> std::process::Child {
    let socket = dir.join("verify.sock");
    // The socket file appears at bind(), before listen(): a connect in between is refused. READY
    // comes only once the socket accepts connections, so wait for that instead.
    let notify_path = dir.join("notify.sock");
    let manager = std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();
    manager
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut child = cl_verify()
        .env("NOTIFY_SOCKET", &notify_path)
        .arg("--trusted-setup")
        .arg(setup_config().path)
        .arg("--socket")
        .arg(&socket)
        .args(["--peer-uid", &my_uid().to_string()])
        .arg("--pubkey-snapshot")
        .arg(snapshot)
        .arg("--network-dir")
        .arg(network_dir(dir))
        .stderr(stderr)
        .spawn()
        .unwrap();
    match await_ready(&manager, &mut child) {
        Ok(()) => child,
        Err(why) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cl-verify on {}: {why}", socket.display());
        }
    }
}

/// Waits up to 30 s for `child` to send READY to `manager` (read timeout 100 ms).
fn await_ready(
    manager: &std::os::unix::net::UnixDatagram,
    child: &mut std::process::Child,
) -> Result<(), String> {
    let mut buf = [0u8; 64];
    for _ in 0..300 {
        match manager.recv(&mut buf) {
            Ok(n) if &buf[..n] == notify::READY.as_bytes() => return Ok(()),
            Ok(n) => {
                let got = String::from_utf8_lossy(&buf[..n]);
                return Err(format!("unexpected notification {got:?}"));
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(format!("cannot read the notify socket: {e}")),
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("exited before READY: {status:?}"));
        }
    }
    Err("no READY within 30 s".into())
}

/// Sends `signal` to `child`.
fn send_signal(child: &std::process::Child, signal: &str) {
    let sent = Command::new("kill")
        .args([signal, &child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
}

/// Sends `signal` to `child` and returns its exit status, within 30 s.
fn signal_and_wait(child: &mut std::process::Child, signal: &str) -> std::process::ExitStatus {
    send_signal(child, signal);
    for _ in 0..300 {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("cl-verify did not exit within 30 s of {signal}");
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_sigterm_flushes_the_snapshot_removes_the_socket_and_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let snapshot = dir.path().join("pubkeys.bin");
    let mut child = spawn_binary(dir.path());
    let (client, feed) = feed_dirty_snapshot(&socket, chain_hello(), &snapshot, 3, 5).await;
    drop((feed, client));

    let status = tokio::task::block_in_place(|| signal_and_wait(&mut child, "-TERM"));
    assert_eq!(status.code(), Some(0), "{status:?}");
    assert!(snapshot_holds(&snapshot, 5), "dirty snapshot flushed");
    assert!(!socket.exists(), "socket removed");
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_second_sigterm_exits_3_at_once_without_the_flush() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let snapshot = dir.path().join("pubkeys.bin");
    let mut child = spawn_binary(dir.path());
    // The feed stream stays open, so the first SIGTERM drains for the default 10 s.
    let (_client, _feed) = feed_dirty_snapshot(&socket, chain_hello(), &snapshot, 3, 5).await;
    send_signal(&child, "-TERM");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(child.try_wait().unwrap().is_none(), "draining");
    let started = std::time::Instant::now();
    let status = tokio::task::block_in_place(|| signal_and_wait(&mut child, "-TERM"));
    assert_eq!(status.code(), Some(3), "{status:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "exited promptly, not after the drain"
    );
    assert!(!snapshot_holds(&snapshot, 5), "the flush was skipped");
    assert!(!socket.exists(), "socket removed");
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_reports_a_failed_shutdown_flush_and_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    // The snapshot's directory does not exist: every save, the shutdown flush included, fails.
    let snapshot = dir.path().join("missing").join("pubkeys.bin");
    let mut child = spawn_binary_with(dir.path(), &snapshot, std::process::Stdio::piped());
    {
        let mut client = VerifyServiceClient::new(connect(&socket).await);
        let (tx, rx) = mpsc::channel(8);
        let rx = client
            .pubkey_feed(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        let mut feed = Bidi {
            tx,
            rx,
            generation: 0,
        };
        feed.send(feed_hello(chain_hello())).await;
        assert!(feed.next().await.unwrap().is_some(), "server hello");
        assert_eq!(feed_reply(&mut feed).await.high_water, 0);
        feed.send(feed_body(announcing(feed_frame(0, 0..3), 3)))
            .await;
        assert_eq!(feed_reply(&mut feed).await.high_water, 3);
    }
    let status = tokio::task::block_in_place(|| signal_and_wait(&mut child, "-TERM"));
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    assert_eq!(status.code(), Some(1), "{status:?}: {stderr}");
    assert!(stderr.contains("pubkey snapshot not flushed"), "{stderr}");
    assert!(!socket.exists(), "socket removed");
}

#[test]
fn binary_sigint_exits_0_and_removes_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = spawn_binary(dir.path());
    let status = signal_and_wait(&mut child, "-INT");
    assert_eq!(status.code(), Some(0), "{status:?}");
    assert!(!dir.path().join("verify.sock").exists(), "socket removed");
}

/// The binary's hello from `--network-dir` is what cl-chain's side sends for the same files:
/// the handshake passes (no `VERSION_MISMATCH`), and the KZG cell cap is one block at the
/// devnet's largest blob count (21), not 0. The devnet has the shape of our Kurtosis devnet:
/// Fulu and Gloas at epoch 0.
#[tokio::test(flavor = "multi_thread")]
async fn binary_hello_from_the_network_dir_matches_cl_chain_and_caps_kzg_by_its_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let mut child = spawn_binary(dir.path());
    let mut client = VerifyServiceClient::new(connect(&socket).await);
    let (tx, rx) = mpsc::channel(8);
    let rx = client
        .verify_kzg(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let mut kzg = Bidi {
        tx,
        rx,
        generation: 0,
    };
    let ours = chain_hello();
    kzg.send(kzg_hello(ours.clone())).await;
    let server = match kzg.next().await {
        Ok(Some(r)) => match r.frame {
            Some(verify_kzg_response::Frame::Hello(server)) => server,
            other => panic!("first server frame is not hello: {other:?}"),
        },
        other => panic!("no server hello: {other:?}"),
    };
    assert!(server.build.starts_with("cl-verify/"), "{}", server.build);
    assert_ne!(server.generation, 0);
    assert_eq!(
        Hello {
            build: ours.build.clone(),
            generation: 0,
            ..server.clone()
        },
        ours
    );
    kzg.generation = server.generation;

    let cell = |i: usize| KzgCellProof {
        commitment: vec![],
        cell_index: (i % MAX_KZG_COLUMNS) as u64,
        cell: vec![],
        proof: vec![],
    };
    let max = MAX_KZG_COLUMNS * KURTOSIS_MAX_BLOBS as usize;
    kzg.send(kzg_body(VerifyKzgRequestBody {
        request_id: 1,
        cells: (0..max).map(cell).collect(),
        deadline_unix_ms: far_deadline(),
        generation: 0,
    }))
    .await;
    let reply = kzg_reply(&mut kzg).await;
    assert_eq!(reply.err, None);
    assert_eq!(reply.status, VerifyStatus::DecodeError as i32);
    kzg.send(kzg_body(VerifyKzgRequestBody {
        request_id: 2,
        cells: (0..=max).map(cell).collect(),
        deadline_unix_ms: far_deadline(),
        generation: 0,
    }))
    .await;
    let err = kzg.expect_failure().await;
    assert_eq!(
        err.code(),
        cl_verify::proto::common::ErrorCode::ContractViolation
    );
    assert!(
        err.detail.contains(&format!("cap of {max}")),
        "{}",
        err.detail
    );
    drop((kzg, client));

    let status = tokio::task::block_in_place(|| signal_and_wait(&mut child, "-TERM"));
    assert_eq!(status.code(), Some(0), "{status:?}");
}

#[test]
fn binary_without_a_network_dir_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = cl_verify()
        .arg("--trusted-setup")
        .arg(setup_config().path)
        .arg("--socket")
        .arg(dir.path().join("verify.sock"))
        .args(["--peer-uid", &my_uid().to_string()])
        .arg("--pubkey-snapshot")
        .arg(dir.path().join("pubkeys.bin"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--network-dir is required"), "{stderr}");
    assert!(!dir.path().join("verify.sock").exists());
}

#[test]
fn binary_exits_1_on_a_network_dir_that_does_not_read_without_binding() {
    let dir = tempfile::tempdir().unwrap();
    let net = network_dir(dir.path());
    std::fs::remove_file(net.join("genesis.ssz")).unwrap();
    let out = cl_verify()
        .arg("--trusted-setup")
        .arg(setup_config().path)
        .arg("--socket")
        .arg(dir.path().join("verify.sock"))
        .args(["--peer-uid", &my_uid().to_string()])
        .arg("--pubkey-snapshot")
        .arg(dir.path().join("pubkeys.bin"))
        .arg("--network-dir")
        .arg(&net)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("network config refused"), "{stderr}");
    assert!(stderr.contains("genesis.ssz"), "{stderr}");
    assert!(!dir.path().join("verify.sock").exists());
}

#[test]
fn binary_usage_error_exits_2() {
    let out = cl_verify().arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--trusted-setup"));
}

#[test]
fn binary_help_exits_0() {
    let out = cl_verify().arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("--trusted-setup"));
}
