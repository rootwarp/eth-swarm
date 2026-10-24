//! Process startup, in this order: read the network ([`Args::into_config`]: `--network-dir`
//! gives the hello of every stream), load the KZG trusted setup and check its sha256 against
//! [`crypto_kzg::BETA4_MAINNET_SHA256`], bind the Unix socket, start serving, then report READY to
//! the service manager.
//!
//! A refused setup ends startup before anything else happens: no socket is bound, c-kzg is never
//! called (the digest is checked before the file is parsed) and READY is never sent. The error
//! names the expected and actual digests.
//!
//! A shutdown requested before the bind (a signal that arrived while the setup was loading) ends
//! startup there: nothing is bound and READY is never sent. One requested after the bind, before
//! READY, unbinds and ends it likewise.
//!
//! Shutdown (SIGTERM or SIGINT, see [`termination`]) is graceful and bounded: open connections get
//! [`StartupConfig::drain_timeout`] to finish, then their streams are closed and feed work stops,
//! a dirty pubkey snapshot is flushed once (a failure is returned), and the socket file this
//! process bound is removed. A second signal during the drain or the flush cuts it short
//! ([`run_with_signals`], [`Stopped::Forced`]): the flush is skipped and the socket file removed.

use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use crypto_kzg::SetupError;
use ipc::hello::{NetworkHello, UnknownPreset};
use network_config::network_dir::{NetworkDir, NetworkDirError};
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::feed::SharedCache;
use crate::handshake::Handshake;
use crate::kzg::TrustedSetupConfig;
use crate::notify;
use crate::proto::common::{Hello, SpecPin};
use crate::server::{
    serve_uds_draining, Limits, ServeError, ServerConfig, VerifyServer, DEFAULT_SNAPSHOT_INTERVAL,
};

/// The `api_version` this build speaks, and the lowest one it accepts.
pub const API_VERSION: u32 = 1;

/// The `build` of every hello this binary sends.
pub const BUILD: &str = concat!("cl-verify/", env!("CARGO_PKG_VERSION"));

/// Command-line usage.
pub const USAGE: &str = "\
usage: cl-verify --trusted-setup <PATH> --socket <PATH> --peer-uid <UID> --pubkey-snapshot <PATH>
                 --network-dir <DIR>

  --trusted-setup    consensus-specs v1.7.0-beta.4
                     presets/mainnet/trusted_setups/trusted_setup_4096.json
  --socket           Unix socket to serve ethswarm.verify.v1 on
  --peer-uid         the only peer UID served (cl-chain's)
  --pubkey-snapshot  pubkey cache snapshot file (pubkeys.bin); its directory must be writable
                     only by the cl-verify user (e.g. the service's state directory)
  --network-dir      the network's genesis data: DIR/config.yaml and DIR/genesis.ssz, the same
                     files cl-chain reads; every hello carries their genesis validators root,
                     fork and blob schedules, and the KZG cell cap follows the blob schedule";

/// How long open connections get to finish once shutdown begins.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything [`run`] needs.
#[derive(Clone, Debug)]
pub struct StartupConfig {
    pub server: ServerConfig,
    pub socket_path: PathBuf,
    /// Once shutdown begins, the longest wait for open connections (cl-chain keeps its streams
    /// open) before their streams are closed; the snapshot flush follows either way.
    pub drain_timeout: Duration,
}

/// Why the network of `--network-dir` was refused.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error(transparent)]
    Dir(#[from] NetworkDirError),
    #[error(transparent)]
    Preset(#[from] UnknownPreset),
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// `--network-dir` cannot be read, or its config is not valid.
    #[error("network config refused: {0}")]
    Network(#[from] NetworkError),
    /// The trusted setup is missing, unreadable, or not the pinned file.
    #[error("trusted setup refused: {0}")]
    Setup(#[from] SetupError),
    #[error("cannot bind {}: {source}", path.display())]
    Bind {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot notify the service manager: {0}")]
    Notify(#[source] io::Error),
    #[error("serving failed: {0}")]
    Serve(#[source] tonic::transport::Error),
    /// The shutdown snapshot flush failed: the appends since the last save are rebuilt on the
    /// next start.
    #[error("pubkey snapshot not flushed at shutdown: {0}")]
    Flush(#[source] io::Error),
    #[error("server task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

impl From<ServeError> for StartupError {
    fn from(err: ServeError) -> Self {
        match err {
            ServeError::Transport(e) => Self::Serve(e),
            ServeError::Flush(e) => Self::Flush(e),
        }
    }
}

/// How startup reports that it is serving (the READY seam).
pub trait Readiness: Send + Sync {
    fn ready(&self) -> io::Result<()>;
}

/// `READY=1` to `$NOTIFY_SOCKET`; nothing when it is unset.
pub struct SystemdReadiness;

impl Readiness for SystemdReadiness {
    fn ready(&self) -> io::Result<()> {
        notify::notify_ready().map(drop)
    }
}

/// The termination signals received so far, counted from 0 ([`termination`]). Clones share the
/// count.
#[derive(Clone, Debug)]
pub struct Termination {
    count: watch::Receiver<u32>,
}

/// Delivers signals to the [`Termination`] made with it ([`Termination::channel`]).
#[derive(Debug)]
pub struct SignalSender(watch::Sender<u32>);

impl SignalSender {
    /// One more signal; returns how many have arrived.
    pub fn signal(&self) -> u32 {
        self.0.send_modify(|n| *n = n.saturating_add(1));
        *self.0.borrow()
    }
}

impl Termination {
    /// A termination fed by the returned sender instead of the process's signals.
    #[must_use]
    pub fn channel() -> (Self, SignalSender) {
        let (tx, count) = watch::channel(0);
        (Self { count }, SignalSender(tx))
    }

    /// Resolves once `n` signals have arrived (at once if they already have), or never if the
    /// source is gone before that.
    pub fn after(&self, n: u32) -> impl Future<Output = ()> + Send + 'static {
        let mut count = self.count.clone();
        async move {
            if count.wait_for(|got| *got >= n).await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Counts SIGTERM and SIGINT: the first starts the shutdown, a second forces the exit
/// ([`run_with_signals`]). The handlers are installed when this is called (inside a runtime), so a
/// signal that arrives before anything waits on the result is not lost.
pub fn termination() -> io::Result<Termination> {
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let (termination, sender) = Termination::channel();
    tokio::spawn(async move {
        loop {
            let name = tokio::select! {
                Some(()) = term.recv() => "SIGTERM",
                Some(()) = int.recv() => "SIGINT",
                else => return,
            };
            if sender.signal() == 1 {
                tracing::info!(signal = name, "shutting down");
            } else {
                tracing::warn!(
                    signal = name,
                    "second signal: exiting now, without the flush"
                );
            }
        }
    });
    Ok(termination)
}

/// How [`run_with_signals`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stopped {
    /// After the first signal: drained, flushed, socket removed.
    Graceful,
    /// A second signal arrived during the drain or the flush: stopped at once, the flush skipped,
    /// the socket removed.
    Forced,
}

/// [`run_with_signals`] reporting readiness to systemd.
pub async fn run(config: StartupConfig, signals: Termination) -> Result<Stopped, StartupError> {
    run_with_signals(config, &SystemdReadiness, signals).await
}

/// [`run_with`] that shuts down on the first of `signals` and gives up on the second: the server
/// task is aborted at once, so the rest of the drain and the snapshot flush are skipped.
pub async fn run_with_signals(
    config: StartupConfig,
    readiness: &dyn Readiness,
    signals: Termination,
) -> Result<Stopped, StartupError> {
    tokio::select! {
        biased;
        () = signals.after(2) => Ok(Stopped::Forced),
        run = run_with(config, readiness, signals.after(1)) => run.map(|()| Stopped::Graceful),
    }
}

/// Loads the pinned setup, binds `config.socket_path`, serves until `shutdown` resolves, and calls
/// `readiness` once the server is running. If `shutdown` has already resolved after the setup is
/// loaded, or right after the bind, it returns `Ok` there: nothing stays bound and READY is not
/// sent. After `shutdown`, connections get `config.drain_timeout`, their streams are closed, the
/// pubkey snapshot is flushed once if dirty (a failure is [`StartupError::Flush`]), and the socket
/// file is removed. Dropping the returned future aborts the server task.
pub async fn run_with(
    config: StartupConfig,
    readiness: &dyn Readiness,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), StartupError> {
    if let Some(warning) = unwired_network_warning(&config.server) {
        tracing::warn!("{warning}");
    }
    let mut shutdown = Box::pin(shutdown);
    let server = VerifyServer::new(config.server, SharedCache::default()).map_err(setup_refused)?;
    if has_resolved(&mut shutdown).await {
        tracing::info!("shutdown requested during startup; not serving");
        return Ok(());
    }
    let (listener, _socket_file) = bind(&config.socket_path)?;
    if has_resolved(&mut shutdown).await {
        tracing::info!("shutdown requested during startup; not serving");
        return Ok(());
    }
    let mut serving = AbortOnDrop(tokio::spawn(serve_uds_draining(
        listener,
        server,
        shutdown,
        config.drain_timeout,
    )));
    if let Err(e) = readiness.ready() {
        tracing::error!(error = %e, "cannot notify the service manager");
        return Err(StartupError::Notify(e));
    }
    tracing::info!(socket = %config.socket_path.display(), "cl-verify ready");
    (&mut serving.0).await??;
    Ok(())
}

/// Polls `fut` once: whether it has already resolved. A resolved future is not polled again.
async fn has_resolved<F: Future + ?Sized>(fut: &mut Pin<Box<F>>) -> bool {
    std::future::poll_fn(|cx| Poll::Ready(fut.as_mut().poll(cx).is_ready())).await
}

/// Aborts the task when dropped (the caller gave up on it).
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn setup_refused(err: SetupError) -> StartupError {
    match &err {
        SetupError::DigestMismatch { expected, actual } => tracing::error!(
            expected = %hex::encode(expected),
            actual = %hex::encode(actual),
            "trusted setup sha256 mismatch; refusing to start"
        ),
        other => tracing::error!(error = %other, "trusted setup refused; refusing to start"),
    }
    StartupError::Setup(err)
}

/// Binds `path`, first removing a socket file left by a previous run. Anything else at `path` is
/// left alone and fails the bind. The returned guard removes the socket file again on every exit
/// path after the bind.
fn bind(path: &Path) -> Result<(UnixListener, BoundSocket), StartupError> {
    let bind_err = |source| StartupError::Bind {
        path: path.to_owned(),
        source,
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path).map_err(bind_err)?,
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(bind_err(e)),
    }
    let listener = UnixListener::bind(path).map_err(bind_err)?;
    let socket = BoundSocket::of(path, std::fs::symlink_metadata(path)).map_err(bind_err)?;
    Ok((listener, socket))
}

/// The socket file this process created. Dropping it unlinks the path only while it is still that
/// file (same device and inode); a socket someone else has since put there is left alone.
struct BoundSocket {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl BoundSocket {
    /// The guard for the socket just bound at `path`, given its metadata. Without the metadata the
    /// guard could not tell the file apart later, so the path (bound a moment ago) is unlinked now
    /// and the error returned: no socket file is left behind.
    fn of(path: &Path, meta: io::Result<std::fs::Metadata>) -> io::Result<Self> {
        match meta {
            Ok(meta) => Ok(Self {
                path: path.to_owned(),
                dev: meta.dev(),
                ino: meta.ino(),
            }),
            Err(e) => {
                if let Err(rm) = std::fs::remove_file(path) {
                    tracing::warn!(socket = %path.display(), error = %rm, "cannot remove our socket");
                }
                Err(e)
            }
        }
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        let ours = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && m.dev() == self.dev && m.ino() == self.ino);
        if !ours {
            return;
        }
        if let Err(e) = std::fs::remove_file(&self.path) {
            tracing::warn!(socket = %self.path.display(), error = %e, "cannot remove our socket");
        }
    }
}

/// The startup warning for a hello without network configuration (see [`local_hello`]), or `None`
/// once the genesis root and fork schedule are set.
#[must_use]
pub fn unwired_network_warning(config: &ServerConfig) -> Option<&'static str> {
    let ours = config.handshake.ours();
    (ours.genesis_validators_root.is_empty() || ours.fork_schedule.is_empty()).then_some(
        "network config is not wired into cl-verify: every cl-chain hello will fail with \
         VERSION_MISMATCH and the KZG cell cap is 0, so all KZG batches are refused",
    )
}

/// Parsed command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub trusted_setup: PathBuf,
    pub socket: PathBuf,
    pub peer_uid: u32,
    pub pubkey_snapshot: PathBuf,
    pub network_dir: PathBuf,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("help requested")]
    Help,
    #[error("unknown argument {0:?}")]
    Unknown(OsString),
    #[error("{0} needs a value")]
    MissingValue(&'static str),
    #[error("{0} given twice")]
    Duplicate(&'static str),
    #[error("{0} is required")]
    Required(&'static str),
    #[error("--peer-uid: not a UID: {0:?}")]
    BadUid(OsString),
}

impl Args {
    /// Parses `--trusted-setup <PATH> --socket <PATH> --peer-uid <UID> --pubkey-snapshot <PATH>
    /// --network-dir <DIR>` (any order, all required), or `--help`.
    ///
    /// `--network-dir` is required: without the network, every cl-chain hello fails with
    /// `VERSION_MISMATCH` and the KZG cell cap is 0, so a process that started would serve
    /// nothing.
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, UsageError> {
        let mut setup = None;
        let mut socket = None;
        let mut uid = None;
        let mut snapshot = None;
        let mut network = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let (name, slot) = match arg.to_str() {
                Some("--help" | "-h") => return Err(UsageError::Help),
                Some("--trusted-setup") => ("--trusted-setup", &mut setup),
                Some("--socket") => ("--socket", &mut socket),
                Some("--peer-uid") => ("--peer-uid", &mut uid),
                Some("--pubkey-snapshot") => ("--pubkey-snapshot", &mut snapshot),
                Some("--network-dir") => ("--network-dir", &mut network),
                _ => return Err(UsageError::Unknown(arg)),
            };
            let value = args.next().ok_or(UsageError::MissingValue(name))?;
            if slot.replace(value).is_some() {
                return Err(UsageError::Duplicate(name));
            }
        }
        let uid = uid.ok_or(UsageError::Required("--peer-uid"))?;
        Ok(Self {
            trusted_setup: setup.ok_or(UsageError::Required("--trusted-setup"))?.into(),
            socket: socket.ok_or(UsageError::Required("--socket"))?.into(),
            pubkey_snapshot: snapshot
                .ok_or(UsageError::Required("--pubkey-snapshot"))?
                .into(),
            network_dir: network.ok_or(UsageError::Required("--network-dir"))?.into(),
            peer_uid: uid
                .to_str()
                .and_then(|s| s.parse().ok())
                .ok_or(UsageError::BadUid(uid))?,
        })
    }

    /// The startup configuration, with default limits, the default snapshot interval and the
    /// hello of `--network-dir` ([`network_hello`]). This is the one place a production
    /// [`ServerConfig`] is built.
    ///
    /// # Errors
    ///
    /// The network directory cannot be read or its config is not valid
    /// ([`StartupError::Network`]).
    pub fn into_config(self) -> Result<StartupConfig, StartupError> {
        let network = network_hello(&self.network_dir)?;
        Ok(StartupConfig {
            server: ServerConfig {
                handshake: Handshake::network(network, API_VERSION),
                peer_uid: self.peer_uid,
                trusted_setup: TrustedSetupConfig {
                    path: self.trusted_setup,
                },
                limits: Limits::default(),
                pubkey_snapshot: self.pubkey_snapshot,
                snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
            },
            socket_path: self.socket,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        })
    }
}

/// The hello of the network in `dir` (`config.yaml` and `genesis.ssz`, read by
/// [`NetworkDir::read`]), sent with [`BUILD`]. cl-chain's side builds its verify.v1 hello the
/// same way from the same files ([`NetworkHello`]), so the two are equal apart from `build`.
///
/// # Errors
///
/// A file cannot be read, the config is not valid, or its `PRESET_BASE` is neither `minimal`
/// nor `mainnet`.
pub fn network_hello(dir: &Path) -> Result<NetworkHello, NetworkError> {
    let network = NetworkDir::read(dir)?;
    Ok(NetworkHello::new(BUILD, &network.config, network.genesis)?)
}

/// A hello without a network: API version, build and spec pin only.
///
/// The binary never sends it (`--network-dir` is required). It fails closed for a
/// [`StartupConfig`] built with it: the hello of a real cl-chain, which carries the network, is
/// refused with `VERSION_MISMATCH`, and with no blob schedule the KZG cell cap
/// ([`crate::caps::max_kzg_cells`]) is 0, so every KZG batch is refused before it is verified.
/// [`run_with`] warns about it ([`unwired_network_warning`]).
#[must_use]
pub fn local_hello() -> Hello {
    Hello {
        api_version: API_VERSION,
        build: BUILD.into(),
        spec_pin: Some(SpecPin {
            consensus_specs_tag: network_config::SPEC_PIN.consensus_specs.into(),
            ssz_specs_tag: network_config::SPEC_PIN.ssz_specs.into(),
        }),
        min_api_version: API_VERSION,
        max_api_version: API_VERSION,
        ..Hello::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete command line.
    const OK: [&str; 10] = [
        "--trusted-setup",
        "s",
        "--socket",
        "k",
        "--peer-uid",
        "1",
        "--pubkey-snapshot",
        "p",
        "--network-dir",
        "n",
    ];

    fn parse(args: &[&str]) -> Result<Args, UsageError> {
        Args::parse(args.iter().map(OsString::from))
    }

    #[test]
    fn parses_the_five_flags_in_any_order() {
        let want = Args {
            trusted_setup: "/etc/setup.json".into(),
            socket: "/run/verify.sock".into(),
            peer_uid: 990,
            pubkey_snapshot: "/var/lib/cl-verify/pubkeys.bin".into(),
            network_dir: "/etc/ethswarm/network".into(),
        };
        let a = [
            "--trusted-setup",
            "/etc/setup.json",
            "--socket",
            "/run/verify.sock",
            "--peer-uid",
            "990",
            "--pubkey-snapshot",
            "/var/lib/cl-verify/pubkeys.bin",
            "--network-dir",
            "/etc/ethswarm/network",
        ];
        assert_eq!(parse(&a), Ok(want.clone()));
        let b = [a[8], a[9], a[6], a[7], a[4], a[5], a[2], a[3], a[0], a[1]];
        assert_eq!(parse(&b), Ok(want));
    }

    #[test]
    fn refuses_bad_command_lines() {
        let ok = OK;
        assert_eq!(parse(&["--help"]), Err(UsageError::Help));
        assert_eq!(parse(&["-h"]), Err(UsageError::Help));
        assert_eq!(
            parse(&["--bogus"]),
            Err(UsageError::Unknown("--bogus".into()))
        );
        assert_eq!(
            parse(&["--socket"]),
            Err(UsageError::MissingValue("--socket"))
        );
        assert_eq!(
            parse(&[&ok[..], &["--socket", "x"]].concat()),
            Err(UsageError::Duplicate("--socket"))
        );
        assert_eq!(
            parse(&ok[2..]),
            Err(UsageError::Required("--trusted-setup"))
        );
        assert_eq!(
            parse(&[&ok[..2], &ok[4..]].concat()),
            Err(UsageError::Required("--socket"))
        );
        assert_eq!(
            parse(&[&ok[..4], &ok[6..]].concat()),
            Err(UsageError::Required("--peer-uid"))
        );
        assert_eq!(
            parse(&[&ok[..6], &ok[8..]].concat()),
            Err(UsageError::Required("--pubkey-snapshot"))
        );
        // Without a network, no cl-chain hello can match and the KZG cell cap is 0.
        assert_eq!(parse(&ok[..8]), Err(UsageError::Required("--network-dir")));
        assert_eq!(
            parse(&[&ok[..8], &["--network-dir"]].concat()),
            Err(UsageError::MissingValue("--network-dir"))
        );
        assert_eq!(
            parse(&[&ok[..], &["--network-dir", "m"]].concat()),
            Err(UsageError::Duplicate("--network-dir"))
        );
        assert_eq!(
            parse(&[&ok[..4], &["--peer-uid", "-1"], &ok[6..]].concat()),
            Err(UsageError::BadUid("-1".into()))
        );
    }

    /// A network directory with the devnet of [`crate::handshake::tests::DEVNET_CONFIG`].
    fn devnet_dir() -> tempfile::TempDir {
        use crate::handshake::tests::{DEVNET_CONFIG, DEVNET_GENESIS};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.yaml"), DEVNET_CONFIG).unwrap();
        let mut state = DEVNET_GENESIS.genesis_time.to_le_bytes().to_vec();
        state.extend_from_slice(&DEVNET_GENESIS.genesis_validators_root);
        state.extend_from_slice(&[0xee; 64]);
        std::fs::write(dir.path().join("genesis.ssz"), state).unwrap();
        dir
    }

    /// [`OK`] with `dir` as the network directory.
    fn with_network(dir: &Path) -> Args {
        let mut argv = OK.to_vec();
        argv[9] = dir.to_str().unwrap();
        parse(&argv).unwrap()
    }

    #[test]
    fn config_uses_the_given_paths_and_uid() {
        let dir = devnet_dir();
        let cfg = with_network(dir.path()).into_config().unwrap();
        assert_eq!(cfg.socket_path, PathBuf::from("k"));
        assert_eq!(cfg.server.peer_uid, 1);
        assert_eq!(cfg.server.pubkey_snapshot, PathBuf::from("p"));
        assert_eq!(cfg.server.snapshot_interval, DEFAULT_SNAPSHOT_INTERVAL);
        assert_eq!(cfg.server.trusted_setup.path, PathBuf::from("s"));
    }

    /// The hello of `--network-dir` is the network's: what cl-chain's side of the link sends
    /// for the same directory, so the handshake passes, and the KZG cell cap is one block at the
    /// network's largest blob count.
    #[test]
    fn the_network_dir_gives_the_hello_of_the_network() {
        use crate::handshake::tests::{devnet, devnet_ms, At};
        let dir = devnet_dir();
        let cfg = with_network(dir.path()).into_config().unwrap();
        let ours = cfg.server.handshake.ours();
        assert_eq!(ours, network_hello(dir.path()).unwrap().schedule());
        assert_eq!(ours.genesis_validators_root, [0x42; 32]);
        assert_eq!(ours.fork_schedule.len(), 3);
        assert_eq!(ours.build, BUILD);
        assert_eq!(unwired_network_warning(&cfg.server), None);
        assert_eq!(crate::caps::max_kzg_cells(ours), 128 * 12);

        let chain = devnet("cl-chain/test");
        for slot in [0, 8, 16, 1_000] {
            let now = devnet_ms(slot);
            let theirs = chain.at(u128::from(now)).unwrap();
            let (_, sent) = cfg.server.handshake.accept(&theirs, &At(now)).unwrap();
            assert_eq!(
                Hello {
                    build: theirs.build.clone(),
                    ..sent
                },
                theirs
            );
        }
    }

    #[test]
    fn a_network_dir_that_does_not_read_fails_the_config() {
        let dir = tempfile::tempdir().unwrap();
        let err = with_network(dir.path()).into_config().unwrap_err();
        assert!(matches!(err, StartupError::Network(_)), "{err:?}");
        assert!(err.to_string().contains("config.yaml"), "{err}");

        let devnet = devnet_dir();
        let yaml = crate::handshake::tests::DEVNET_CONFIG.replace("'minimal'", "'gnosis'");
        std::fs::write(devnet.path().join("config.yaml"), yaml).unwrap();
        let err = with_network(devnet.path()).into_config().unwrap_err();
        assert!(err.to_string().contains("gnosis"), "{err}");
    }

    /// Until network config reaches cl-verify, the unwired hello fails closed: a real cl-chain
    /// hello is a VERSION_MISMATCH and the KZG cell cap is 0, so every KZG batch is refused.
    #[test]
    fn unwired_hello_fails_closed() {
        let ours = local_hello();
        assert_eq!(crate::caps::max_kzg_cells(&ours), 0);
        let one_cell = crate::proto::verify::VerifyKzgRequestBody {
            cells: vec![crate::proto::verify::KzgCellProof::default()],
            ..Default::default()
        };
        assert!(crate::caps::check_kzg(&one_cell, 0).is_err());

        let chain = Hello {
            genesis_validators_root: vec![0x4b; 32],
            current_fork_digest: vec![0xaa, 0xbb, 0xcc, 0xdd],
            fork_schedule: vec![crate::proto::common::ForkScheduleEntry {
                epoch: 0,
                fork_digest: vec![0xaa, 0xbb, 0xcc, 0xdd],
                fork: crate::proto::common::ForkName::Fulu as i32,
                fork_version: vec![0x06, 0, 0, 0],
                max_blobs_per_block: 9,
            }],
            ..ours.clone()
        };
        let err = Handshake::new(ours, API_VERSION)
            .accept(&chain, &crate::wire::SystemClock)
            .unwrap_err();
        assert_eq!(err.code(), crate::proto::common::ErrorCode::VersionMismatch);
    }

    #[test]
    fn unwired_network_config_is_warned_about() {
        let dir = devnet_dir();
        let mut unwired = with_network(dir.path()).into_config().unwrap();
        unwired.server.handshake = Handshake::new(local_hello(), API_VERSION);
        let warning = unwired_network_warning(&unwired.server).expect("a warning");
        assert!(warning.contains("not wired"), "{warning}");

        let mut wired = unwired.server;
        let mut hello = local_hello();
        hello.genesis_validators_root = vec![1; 32];
        hello.fork_schedule = vec![crate::proto::common::ForkScheduleEntry {
            max_blobs_per_block: 9,
            ..Default::default()
        }];
        wired.handshake = Handshake::new(hello, API_VERSION);
        assert_eq!(unwired_network_warning(&wired), None);
    }

    #[test]
    fn a_socket_whose_metadata_cannot_be_read_after_the_bind_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let err = BoundSocket::of(&path, Err(io::Error::other("stat failed"))).err();
        assert_eq!(err.map(|e| e.to_string()).as_deref(), Some("stat failed"));
        assert!(!path.exists(), "socket file left behind");
        drop(listener);

        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let guard = BoundSocket::of(&path, std::fs::symlink_metadata(&path)).unwrap();
        assert!(path.exists());
        drop(guard);
        assert!(!path.exists(), "the guard removes our socket");
        drop(listener);
    }

    #[tokio::test]
    async fn termination_counts_signals_and_resolves_at_each_count() {
        let (signals, sender) = Termination::channel();
        let first = tokio::spawn(signals.after(1));
        let second = tokio::spawn(signals.after(2));
        tokio::task::yield_now().await;
        assert!(!first.is_finished());
        assert_eq!(sender.signal(), 1);
        first.await.unwrap();
        assert!(!second.is_finished());
        assert_eq!(sender.signal(), 2);
        second.await.unwrap();
        signals.after(1).await;

        // A source that is gone before the count is reached never resolves.
        let (signals, sender) = Termination::channel();
        drop(sender);
        let never = tokio::time::timeout(Duration::from_millis(20), signals.after(1)).await;
        assert!(never.is_err());
    }

    #[tokio::test]
    async fn the_process_signal_source_installs_its_handlers() {
        assert!(termination().is_ok());
    }

    #[test]
    fn local_hello_carries_the_spec_pin() {
        let pin = local_hello().spec_pin.unwrap();
        assert_eq!(pin.consensus_specs_tag, "v1.7.0-beta.4");
        assert_eq!(pin.ssz_specs_tag, "v0.1.0");
    }
}
