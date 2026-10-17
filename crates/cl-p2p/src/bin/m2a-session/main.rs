//! `m2a-session`: dial one pinned peer and exit (see `cl_p2p::m2a_session`).
//!
//! ```text
//! m2a-session --peer <multiaddr>/p2p/<peer id> [--key-file <path>] [--connect-timeout-secs <n>]
//! ```
//!
//! Without `--key-file` the node key is ephemeral. Exit 0 once the pinned peer is connected, 1
//! if the dial fails or times out, 2 on bad arguments or a failed pre-flight.

use cl_p2p::m2a_session::{preflight, KeySource, PinnedPeer, Preflight, Session, Transport};
use consensus_types::Mainnet;
use p2p_wire::rpc::codec::ContextTable;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str =
    "usage: m2a-session --peer <multiaddr>/p2p/<peer id> [--key-file <path>] [--connect-timeout-secs <n>]";
const EXIT_CONNECTED: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_REFUSED: u8 = 2;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

struct Args {
    pinned: PinnedPeer,
    key: KeySource,
    connect_timeout: Duration,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut pinned, mut key, mut connect_timeout) =
        (None, KeySource::Ephemeral, DEFAULT_CONNECT_TIMEOUT);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--peer" => pinned = Some(value()?.parse::<PinnedPeer>().map_err(|e| e.to_string())?),
            "--key-file" => key = KeySource::File(PathBuf::from(value()?)),
            "--connect-timeout-secs" => {
                let secs = value()?
                    .parse::<u64>()
                    .map_err(|e| format!("--connect-timeout-secs: {e}"))?;
                connect_timeout = Duration::from_secs(secs);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let pinned = pinned.ok_or("--peer is required")?;
    Ok(Args {
        pinned,
        key,
        connect_timeout,
    })
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
    let euid = rustix::process::geteuid().as_raw();
    ExitCode::from(run(std::env::args().skip(1), euid))
}

/// The whole session for `argv`, as effective UID `euid`; returns the exit code.
fn run(argv: impl Iterator<Item = String>, euid: u32) -> u8 {
    let args = match parse_args(argv) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("m2a-session: {e}\n{USAGE}");
            return EXIT_REFUSED;
        }
    };
    let key = match preflight(&Preflight {
        euid,
        key: args.key,
    }) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "pre-flight refused");
            return EXIT_REFUSED;
        }
    };
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
        let mut session =
            match Session::<Mainnet>::start(key, args.pinned, contexts, Transport::Tcp) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "session start");
                    return EXIT_FAILED;
                }
            };
        match tokio::time::timeout(args.connect_timeout, session.connect()).await {
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

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn args() {
        let id = libp2p::PeerId::random();
        let peer = format!("/ip4/127.0.0.1/tcp/9000/p2p/{id}");
        let a = parse(&["--peer", &peer]).unwrap();
        assert_eq!(a.pinned.peer_id, id);
        assert_eq!(a.key, KeySource::Ephemeral);
        assert_eq!(a.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        let a = parse(&[
            "--peer",
            &peer,
            "--key-file",
            "/k",
            "--connect-timeout-secs",
            "3",
        ])
        .unwrap();
        assert_eq!(a.key, KeySource::File("/k".into()));
        assert_eq!(a.connect_timeout, Duration::from_secs(3));
        assert!(parse(&[]).is_err());
        assert!(parse(&["--peer"]).is_err());
        assert!(parse(&["--listen", "x"]).is_err());
        assert!(parse(&["--peer", "/ip4/127.0.0.1/tcp/1"]).is_err());
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

    #[test]
    fn bad_arguments_and_preflight_are_refused() {
        assert_eq!(run(argv(&[]), 1000), EXIT_REFUSED);
        let peer = closed_port_peer();
        assert_eq!(run(argv(&["--peer", &peer]), 0), EXIT_REFUSED, "root");
        let missing = ["--peer", &peer, "--key-file", "/nonexistent/m2a-key"];
        assert_eq!(run(argv(&missing), 1000), EXIT_REFUSED);
    }

    #[test]
    fn failed_dial_exits_1() {
        // Loopback only, to a port nothing listens on: no network contact.
        let peer = closed_port_peer();
        assert_eq!(run(argv(&["--peer", &peer]), 1000), EXIT_FAILED);
        let timeout = ["--peer", &peer, "--connect-timeout-secs", "0"];
        assert_eq!(run(argv(&timeout), 1000), EXIT_FAILED);
    }
}
