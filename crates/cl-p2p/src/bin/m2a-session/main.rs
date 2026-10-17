//! `m2a-session`: dial the pinned reference node (see `cl_p2p::m2a_session`).
//!
//! ```text
//! m2a-session [--config <path>] [--dial-only | --print-peer-id] [--connect-timeout-secs <n>]
//! ```
//!
//! The config (`cl_p2p::m2a_session::config`, default `/etc/ethswarm/m2a-session.toml`) pins the
//! peer, the deadlines and the node key. The pre-flight runs before anything else.
//!
//! - default: dial the pinned peer and exit once it is connected.
//! - `--dial-only`: dial, check the pinned peer ID (Noise XX, then yamux), disconnect, exit.
//!   No req/resp traffic.
//! - `--print-peer-id`: print the node key's peer ID on stdout and exit, without dialling, so
//!   the operator can list it as a trusted peer on the reference node. Needs `node_key`.
//!
//! Exit 0 on success, 1 if the dial fails or times out, 2 on bad arguments, a refused config or
//! a failed pre-flight.

use cl_p2p::m2a_session::config::{M2aConfig, DEFAULT_CONFIG_PATH};
use cl_p2p::m2a_session::{preflight, KeySource, Preflight, Session, SessionError, Transport};
use consensus_types::Mainnet;
use p2p_wire::rpc::codec::ContextTable;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage: m2a-session [--config <path>] [--dial-only | --print-peer-id] \
                     [--connect-timeout-secs <n>]";
const EXIT_CONNECTED: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_REFUSED: u8 = 2;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// What the run does once the pre-flight passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Dial and stay connected (the req/resp work follows in later sessions).
    Session,
    /// Dial, check the pinned ID, disconnect.
    DialOnly,
    /// Print the node key's peer ID; no network.
    PrintPeerId,
}

#[derive(Debug)]
struct Args {
    config: PathBuf,
    mode: Mode,
    connect_timeout: Duration,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut config, mut mode, mut connect_timeout) = (
        PathBuf::from(DEFAULT_CONFIG_PATH),
        Mode::Session,
        DEFAULT_CONNECT_TIMEOUT,
    );
    let mut set_mode = |flag: &str, new| match mode {
        Mode::Session => {
            mode = new;
            Ok(())
        }
        _ => Err(format!(
            "{flag}: --dial-only and --print-peer-id are exclusive"
        )),
    };
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--config" => config = PathBuf::from(value()?),
            "--dial-only" => set_mode(&flag, Mode::DialOnly)?,
            "--print-peer-id" => set_mode(&flag, Mode::PrintPeerId)?,
            "--connect-timeout-secs" => {
                let secs = value()?
                    .parse::<u64>()
                    .map_err(|e| format!("--connect-timeout-secs: {e}"))?;
                connect_timeout = Duration::from_secs(secs);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        config,
        mode,
        connect_timeout,
    })
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
    let euid = rustix::process::geteuid().as_raw();
    ExitCode::from(run(std::env::args().skip(1), euid, &mut std::io::stdout()))
}

/// The whole run for `argv`, as effective UID `euid`, printing to `out`; returns the exit code.
fn run(argv: impl Iterator<Item = String>, euid: u32, out: &mut dyn Write) -> u8 {
    let args = match parse_args(argv) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("m2a-session: {e}\n{USAGE}");
            return EXIT_REFUSED;
        }
    };
    let config = match M2aConfig::load(&args.config) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(config = %args.config.display(), error = %e, "config refused");
            return EXIT_REFUSED;
        }
    };
    if args.mode == Mode::PrintPeerId && config.node_key == KeySource::Ephemeral {
        tracing::error!(
            "--print-peer-id needs node_key: an ephemeral key has a new peer ID each run"
        );
        return EXIT_REFUSED;
    }
    let key = match preflight(&Preflight {
        euid,
        key: config.node_key.clone(),
    }) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "pre-flight refused");
            return EXIT_REFUSED;
        }
    };
    if args.mode == Mode::PrintPeerId {
        return match writeln!(out, "{}", key.peer_id()) {
            Ok(()) => EXIT_CONNECTED,
            Err(e) => {
                tracing::error!(error = %e, "cannot print the peer ID");
                EXIT_FAILED
            }
        };
    }
    tracing::info!(
        network = ?config.network,
        reference_api = ?config.reference_api_url,
        trusted_by_reference = config.trusted_by_reference,
        "config loaded"
    );
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "tokio runtime");
            return EXIT_FAILED;
        }
    };
    // No fork digests yet: the live table comes from compute_fork_digest in later work, and no
    // request that needs context bytes is sent before then.
    let contexts = Arc::new(ContextTable::new());
    runtime.block_on(async {
        let mut session = match Session::<Mainnet>::start(
            key,
            config.peer,
            contexts,
            config.deadlines,
            Transport::Tcp,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "session start");
                return EXIT_FAILED;
            }
        };
        let dial = async {
            session.connect().await?;
            if args.mode == Mode::DialOnly {
                session.disconnect().await?;
                tracing::info!(
                    "dial-only: the pinned peer proved its ID (Noise XX, yamux); disconnected"
                );
            }
            Ok::<(), SessionError>(())
        };
        match tokio::time::timeout(args.connect_timeout, dial).await {
            Ok(Ok(())) => EXIT_CONNECTED,
            Ok(Err(e)) => {
                tracing::error!(error = %e, "session");
                EXIT_FAILED
            }
            Err(_) => {
                tracing::error!(timeout = ?args.connect_timeout, "connect timed out");
                EXIT_FAILED
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn args() {
        let a = parse(&[]).unwrap();
        assert_eq!(a.config, PathBuf::from("/etc/ethswarm/m2a-session.toml"));
        assert_eq!(a.mode, Mode::Session);
        assert_eq!(a.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        let a = parse(&[
            "--config",
            "/c.toml",
            "--dial-only",
            "--connect-timeout-secs",
            "3",
        ])
        .unwrap();
        assert_eq!(a.config, PathBuf::from("/c.toml"));
        assert_eq!(a.mode, Mode::DialOnly);
        assert_eq!(a.connect_timeout, Duration::from_secs(3));
        assert_eq!(parse(&["--print-peer-id"]).unwrap().mode, Mode::PrintPeerId);
        for bad in [
            &["--config"][..],
            &["--connect-timeout-secs", "x"],
            &["--listen", "x"],
            &["--peer", "/ip4/127.0.0.1/tcp/1"],
            &["--key-file", "/k"],
            &["--dial-only", "--print-peer-id"],
            &["--print-peer-id", "--dial-only"],
            &["--dial-only", "--dial-only"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    fn argv(args: &[&str]) -> impl Iterator<Item = String> {
        args.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// A loopback address nothing listens on: bound once, then released.
    fn closed_port_peer() -> String {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", libp2p::PeerId::random())
    }

    /// A config dir pinning `peer`, plus `extra` config lines.
    fn config(peer: &str, extra: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m2a-session.toml");
        let text = format!(
            "network = \"sepolia\"\npeer = \"{peer}\"\n\
             reference_api_url = \"http://127.0.0.1:5052\"\n{extra}\n"
        );
        std::fs::write(&path, text).unwrap();
        let path = path.to_str().unwrap().to_owned();
        (dir, path)
    }

    /// A 0600 key file in `dir`.
    fn key_file(dir: &tempfile::TempDir) -> String {
        let path = dir.path().join("node.key");
        std::fs::write(&path, [7; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn run_quiet(args: &[&str], euid: u32) -> (u8, String) {
        let mut out = Vec::new();
        let code = run(argv(args), euid, &mut out);
        (code, String::from_utf8(out).unwrap())
    }

    #[test]
    fn bad_arguments_config_and_preflight_are_refused() {
        assert_eq!(run_quiet(&["--bogus"], 1000).0, EXIT_REFUSED);
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.toml");
        let missing = ["--config", missing.to_str().unwrap()];
        assert_eq!(run_quiet(&missing, 1000).0, EXIT_REFUSED, "no config");
        let (_dir, bad) = config("/ip4/127.0.0.1/tcp/9000", "");
        assert_eq!(
            run_quiet(&["--config", &bad], 1000).0,
            EXIT_REFUSED,
            "no /p2p/"
        );
        let (_dir, path) = config(&closed_port_peer(), "");
        assert_eq!(run_quiet(&["--config", &path], 0).0, EXIT_REFUSED, "root");
        let (_dir, path) = config(&closed_port_peer(), "node_key = \"/nonexistent/m2a-key\"");
        assert_eq!(
            run_quiet(&["--config", &path], 1000).0,
            EXIT_REFUSED,
            "no key file"
        );
    }

    #[test]
    fn failed_dial_exits_1() {
        // Loopback only, to a port nothing listens on: no network contact.
        let (_dir, path) = config(&closed_port_peer(), "");
        assert_eq!(run_quiet(&["--config", &path], 1000).0, EXIT_FAILED);
        let dial_only = ["--config", &path, "--dial-only"];
        assert_eq!(run_quiet(&dial_only, 1000).0, EXIT_FAILED);
        let timeout = ["--config", &path, "--connect-timeout-secs", "0"];
        assert_eq!(run_quiet(&timeout, 1000).0, EXIT_FAILED);
    }

    #[test]
    fn print_peer_id() {
        let (dir, _) = config(&closed_port_peer(), "");
        let key = key_file(&dir);
        let (_keep, path) = config(&closed_port_peer(), &format!("node_key = \"{key}\""));
        let (code, out) = run_quiet(&["--config", &path, "--print-peer-id"], euid());
        assert_eq!(code, EXIT_CONNECTED);
        let mut secret = [7; 32];
        let secret = libp2p::identity::secp256k1::SecretKey::try_from_bytes(&mut secret).unwrap();
        let want =
            libp2p::identity::Keypair::from(libp2p::identity::secp256k1::Keypair::from(secret))
                .public()
                .to_peer_id();
        assert_eq!(out, format!("{want}\n"));

        let print = ["--config", &path, "--print-peer-id"];
        assert_eq!(run_quiet(&print, 0).0, EXIT_REFUSED, "root");
        let (_dir, ephemeral) = config(&closed_port_peer(), "");
        let print = ["--config", &ephemeral, "--print-peer-id"];
        assert_eq!(
            run_quiet(&print, 1000),
            (EXIT_REFUSED, String::new()),
            "ephemeral"
        );
    }

    /// A writer that always fails.
    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn print_peer_id_to_a_closed_stdout_exits_1() {
        let (dir, _) = config(&closed_port_peer(), "");
        let key = key_file(&dir);
        let (_keep, path) = config(&closed_port_peer(), &format!("node_key = \"{key}\""));
        let print = ["--config", &path, "--print-peer-id"];
        assert_eq!(run(argv(&print), euid(), &mut Broken), EXIT_FAILED);
    }
}
