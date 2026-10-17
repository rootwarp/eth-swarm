//! `m2a-session`: the pinned reference node's Status v2, MetaData v3 and Ping v1 probe (see
//! `cl_p2p::m2a_session`).
//!
//! ```text
//! m2a-session [--config <path>] [--dial-only | --print-peer-id] [--connect-timeout-secs <n>]
//!             [--gate-file <path>]
//! ```
//!
//! The config (`cl_p2p::m2a_session::config`, default `/etc/ethswarm/m2a-session.toml`) pins the
//! peer, the reference API, the deadlines and the node key. The pre-flight runs before anything
//! else.
//!
//! - default: the Status probe ([`probe`]). The pre-flight also requires a passing m2a fuzz
//!   gate for the decoders this binary was built from ([`gate`]; `--gate-file`, default the
//!   checkout's `fuzz/artifacts/m2a-gate.json`), and refuses before dialling without one. Then:
//!   dial, send our Status v2 at the pinned Sepolia fork digest, judge the peer's against the
//!   reference beacon API ([`reference_api`]); request the peer's MetaData v3 on the same
//!   connection and judge it against the node's `/eth/v1/node/identity` ([`metadata`]); Ping
//!   it with our `seq_number` 0 and check its answer against that MetaData ([`ping`]); hold
//!   the connection and send a second Status. One JSON line per step on stdout records it all.
//! - `--dial-only`: dial, check the pinned peer ID (Noise XX, then yamux), disconnect, exit.
//!   No req/resp traffic, so no response decoder runs and no fuzz gate is needed.
//! - `--print-peer-id`: print the node key's peer ID on stdout and exit, without dialling, so
//!   the operator can list it as a trusted peer on the reference node. Needs `node_key`.
//!
//! Exit 0 on success (every verdict of every step passed), 1 if the dial, an exchange or a verdict
//! fails, 2 on bad arguments, a refused config or a failed pre-flight.

mod enr;
mod gate;
mod metadata;
#[cfg(test)]
mod mock_api;
mod ping;
mod probe;
mod reference_api;

use cl_p2p::m2a_session::config::{M2aConfig, Network as SessionNetwork, DEFAULT_CONFIG_PATH};
use cl_p2p::m2a_session::{preflight, KeySource, Preflight, Session, SessionError, Transport};
use consensus_types::{EthSpec, Mainnet};
use gate::Expected;
use network_config::digest::digest_schedule;
use network_config::{ChainConfig, Network};
use p2p_wire::rpc::codec::ContextTable;
use probe::{Chain, Probe};
use reference_api::ReferenceApi;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage: m2a-session [--config <path>] [--dial-only | --print-peer-id] \
                     [--connect-timeout-secs <n>] [--gate-file <path>]";
const EXIT_CONNECTED: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_REFUSED: u8 = 2;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// What the run does once the pre-flight passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The Status probe.
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
    gate_file: PathBuf,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut config, mut mode, mut connect_timeout, mut gate_file) = (
        PathBuf::from(DEFAULT_CONFIG_PATH),
        Mode::Session,
        DEFAULT_CONNECT_TIMEOUT,
        PathBuf::from(gate::DEFAULT_GATE_FILE),
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
            "--gate-file" => gate_file = PathBuf::from(value()?),
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
        gate_file,
    })
}

/// What a run takes from its environment, injected so tests can fix it.
struct RunEnv {
    /// What the fuzz gate file must hold for this build.
    gate: Expected,
    /// Unix milliseconds now.
    now_ms: Box<dyn Fn() -> u128 + Send + Sync>,
    /// How long the probe holds the connection.
    hold: Duration,
}

impl RunEnv {
    /// The embedded gate expectations, the system clock, [`probe::HOLD`].
    fn production() -> Self {
        Self {
            gate: Expected::built(),
            now_ms: Box::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis())
            }),
            hold: probe::HOLD,
        }
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
    let euid = rustix::process::geteuid().as_raw();
    let env = RunEnv::production();
    ExitCode::from(run(
        std::env::args().skip(1),
        euid,
        &mut std::io::stdout(),
        &env,
    ))
}

/// The pinned chain of `network`, checked against the session's preset.
fn chain(network: SessionNetwork) -> Result<Chain, String> {
    let network = match network {
        SessionNetwork::Sepolia => Network::Sepolia,
    };
    let config = ChainConfig::load(network).map_err(|e| format!("{network} config: {e}"))?;
    if config.preset_base() != Mainnet::NAME {
        return Err(format!(
            "{network} is preset {}, the session runs {}",
            config.preset_base(),
            Mainnet::NAME
        ));
    }
    let genesis = network
        .genesis()
        .ok_or_else(|| format!("no pinned genesis for {network}"))?;
    Ok(Chain {
        config,
        genesis,
        slots_per_epoch: Mainnet::slots_per_epoch(),
    })
}

/// Every digest of the schedule, from Fulu on.
fn context_table(chain: &Chain) -> ContextTable {
    let mut table = ContextTable::new();
    for entry in digest_schedule(&chain.config, &chain.genesis.genesis_validators_root) {
        table.insert(entry.fork_digest, entry.fork);
    }
    table
}

/// The whole run for `argv`, as effective UID `euid`, printing to `out`; returns the exit code.
fn run(argv: impl Iterator<Item = String>, euid: u32, out: &mut dyn Write, env: &RunEnv) -> u8 {
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
    let probe_api = if args.mode == Mode::Session {
        if let Err(e) = gate::check(&args.gate_file, &env.gate) {
            tracing::error!(error = %e, "pre-flight refused: no passing m2a fuzz gate");
            return EXIT_REFUSED;
        }
        let Some(url) = &config.reference_api_url else {
            tracing::error!("config refused: the Status probe needs reference_api_url");
            return EXIT_REFUSED;
        };
        Some(ReferenceApi::new(url, reference_api::REQUEST_TIMEOUT))
    } else {
        None
    };
    let chain = match chain(config.network) {
        Ok(chain) => chain,
        Err(e) => {
            tracing::error!(error = %e, "pinned chain");
            return EXIT_REFUSED;
        }
    };
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
    let contexts = Arc::new(context_table(&chain));
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
        if let Some(api) = probe_api {
            let probe = Probe {
                chain: &chain,
                now_ms: env.now_ms.as_ref(),
                connect_timeout: args.connect_timeout,
                hold: env.hold,
            };
            let report = probe::run(&mut session, &api, &probe).await;
            for line in report.json_lines() {
                if let Err(e) = writeln!(out, "{line}") {
                    tracing::error!(error = %e, "cannot write the session log line");
                    return EXIT_FAILED;
                }
            }
            return if report.passed() {
                tracing::info!("status, metadata and ping probes passed");
                EXIT_CONNECTED
            } else {
                let metadata_error = report.metadata.as_ref().and_then(|m| m.error.as_ref());
                let ping_error = report.ping.as_ref().and_then(|p| p.error.as_ref());
                tracing::error!(error = ?report.error, ?metadata_error, ?ping_error, "probe failed");
                EXIT_FAILED
            };
        }
        let dial = async {
            session.connect().await?;
            session.disconnect().await?;
            tracing::info!(
                "dial-only: the pinned peer proved its ID (Noise XX, yamux); disconnected"
            );
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
    use crate::gate::tests::{fixture_expected, passing_gate};
    use crate::mock_api::{MockApi, Route};
    use cl_p2p::testkit::{MetaDataReply, PingReply, StatusPeer, StatusReply};
    use consensus_types::primitives::{Root, Slot};
    use p2p_wire::rpc::messages::{MetaDataV3, StatusV2};
    use p2p_wire::rpc::protocols::ResultCode;
    use serde_json::Value;
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
        assert_eq!(a.gate_file, PathBuf::from(gate::DEFAULT_GATE_FILE));
        assert!(a.gate_file.ends_with("fuzz/artifacts/m2a-gate.json"));
        let a = parse(&[
            "--config",
            "/c.toml",
            "--dial-only",
            "--connect-timeout-secs",
            "3",
            "--gate-file",
            "/g.json",
        ])
        .unwrap();
        assert_eq!(a.config, PathBuf::from("/c.toml"));
        assert_eq!(a.mode, Mode::DialOnly);
        assert_eq!(a.connect_timeout, Duration::from_secs(3));
        assert_eq!(a.gate_file, PathBuf::from("/g.json"));
        assert_eq!(parse(&["--print-peer-id"]).unwrap().mode, Mode::PrintPeerId);
        for bad in [
            &["--config"][..],
            &["--gate-file"],
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

    /// A config dir pinning `peer` and the reference API at `api`, plus `extra` config lines.
    fn config_with_api(peer: &str, api: &str, extra: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m2a-session.toml");
        let text = format!(
            "network = \"sepolia\"\npeer = \"{peer}\"\nreference_api_url = \"{api}\"\n{extra}\n"
        );
        std::fs::write(&path, text).unwrap();
        let path = path.to_str().unwrap().to_owned();
        (dir, path)
    }

    fn config(peer: &str, extra: &str) -> (tempfile::TempDir, String) {
        config_with_api(peer, "http://127.0.0.1:5052", extra)
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

    /// Epoch 353100: Gloas on the pinned Sepolia schedule, digest 0x669e6c11.
    const EPOCH: u64 = 353_100;
    const DIGEST: [u8; 4] = [0x66, 0x9e, 0x6c, 0x11];

    /// 5 s into `epoch`.
    fn ms_at(epoch: u64) -> u128 {
        let genesis = Network::Sepolia.genesis().unwrap().genesis_time;
        u128::from(genesis + epoch * 384) * 1000 + 5_000
    }

    fn now_ms() -> u128 {
        ms_at(EPOCH)
    }

    /// A clock at `epochs[n]` on its `n`th reading; the last repeats.
    fn clock(epochs: Vec<u64>) -> Box<dyn Fn() -> u128 + Send + Sync> {
        let readings = std::sync::atomic::AtomicUsize::new(0);
        Box::new(move || {
            let n = readings.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ms_at(epochs[n.min(epochs.len() - 1)])
        })
    }

    fn test_env() -> RunEnv {
        RunEnv {
            gate: Expected::Known(fixture_expected()),
            now_ms: Box::new(now_ms),
            hold: Duration::from_millis(300),
        }
    }

    /// A passing gate file for the test key, in `dir`.
    fn gate_file(dir: &tempfile::TempDir, gate: &Value) -> String {
        let path = dir.path().join("m2a-gate.json");
        std::fs::write(&path, gate.to_string()).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn run_quiet(args: &[&str], euid: u32) -> (u8, String) {
        let mut out = Vec::new();
        let code = run(argv(args), euid, &mut out, &test_env());
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
        // The gate passes, but the reference API is not on loopback, or not plain HTTP.
        let gate = gate_file(&dir, &passing_gate(&fixture_expected()));
        for url in ["https://127.0.0.1:5052", "http://192.0.2.10:5052"] {
            let (_dir, path) = config_with_api(&closed_port_peer(), url, "");
            assert_eq!(
                run_quiet(&["--config", &path, "--gate-file", &gate], 1000).0,
                EXIT_REFUSED,
                "{url}"
            );
        }
    }

    #[test]
    fn failed_dial_exits_1() {
        // Loopback only, to a port nothing listens on: no network contact.
        let (dir, path) = config(&closed_port_peer(), "");
        let gate = gate_file(&dir, &passing_gate(&fixture_expected()));
        let (code, line) = run_quiet(&["--config", &path, "--gate-file", &gate], 1000);
        assert_eq!(code, EXIT_FAILED);
        let line: Value = serde_json::from_str(line.trim()).unwrap();
        assert!(
            line["error"].as_str().unwrap().starts_with("connect:"),
            "{line}"
        );
        assert_eq!(line["pass"], false);
        let dial_only = ["--config", &path, "--dial-only"];
        assert_eq!(run_quiet(&dial_only, 1000).0, EXIT_FAILED);
        let timeout = [
            "--config",
            &path,
            "--connect-timeout-secs",
            "0",
            "--dial-only",
        ];
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
        assert_eq!(
            run(argv(&print), euid(), &mut Broken, &test_env()),
            EXIT_FAILED
        );
    }

    #[test]
    fn context_table_has_every_schedule_digest() {
        let chain = chain(SessionNetwork::Sepolia).unwrap();
        let table = context_table(&chain);
        use network_config::ForkName::{Fulu, Gloas};
        for (digest, fork) in [
            ([0x7e, 0x0d, 0x34, 0x47], Fulu),
            ([0xfd, 0x32, 0xb6, 0x22], Fulu),
            ([0x74, 0xd0, 0x14, 0x59], Fulu),
            (DIGEST, Gloas),
        ] {
            assert_eq!(table.fork(&digest), Some(fork), "{digest:02x?}");
        }
        assert_eq!(table.fork(&[0; 4]), None);
    }

    // The Status probe against a loopback peer and a mock reference API.

    fn root(b: u8) -> Root {
        Root::repeat_byte(b)
    }

    /// The finalized checkpoints of the scenarios.
    const F1: (u64, u8) = (353_000, 0xf1);
    const F2: (u64, u8) = (353_001, 0xf2);
    const F3: (u64, u8) = (353_002, 0xf3);
    /// The API's head.
    const HEAD_SLOT: Slot = 353_098 * 32 + 5;
    const HEAD_ROOT: u8 = 0xaa;

    fn finalized_slot(epoch: u64) -> Slot {
        epoch * 32
    }

    /// A peer Status at `finalized` with its head `off` slots from the API's.
    fn peer_status(finalized: (u64, u8), off: i64, eas: Slot) -> StatusV2 {
        let head_slot = HEAD_SLOT.checked_add_signed(off).unwrap();
        StatusV2 {
            fork_digest: [0; 4],
            finalized_root: root(finalized.1),
            finalized_epoch: finalized.0,
            head_root: root(head_byte(off)),
            head_slot,
            earliest_available_slot: eas,
        }
    }

    fn head_byte(off: i64) -> u8 {
        HEAD_ROOT.wrapping_add(off as u8)
    }

    struct Scenario {
        /// The API's finalized checkpoint, per request.
        finality: Vec<(u64, u8)>,
        /// The peer's Status, per request (the digest is echoed).
        peer: Vec<StatusV2>,
        /// Close the connection after this many answers.
        disconnect_after: Option<usize>,
        /// The ENR the identity endpoint serves.
        enr: &'static str,
        /// The MetaData the identity endpoint serves, per request (the first is the ENR read).
        identity: Vec<MetaDataV3>,
        /// Raw identity bodies, per request, instead of `identity`.
        identity_bodies: Option<Vec<String>>,
        /// The peer's MetaData answer, per request.
        metadata: Vec<MetaDataReply>,
        /// The peer's Ping answer, per request.
        ping: Vec<PingReply>,
        /// The gate file.
        gate: Value,
        /// The epoch of the clock at each reading; the last repeats.
        clock: Vec<u64>,
    }

    impl Scenario {
        fn new(peer: StatusV2) -> Self {
            Self {
                finality: vec![F1],
                peer: vec![peer],
                disconnect_after: None,
                enr: crate::enr::tests::ENR_GLOAS,
                identity: vec![md(7)],
                identity_bodies: None,
                metadata: vec![MetaDataReply::MetaData(md(7))],
                ping: vec![PingReply::Ping(7)],
                gate: passing_gate(&fixture_expected()),
                clock: vec![EPOCH],
            }
        }
    }

    /// The fixture MetaData at `seq_number`.
    fn md(seq_number: u64) -> MetaDataV3 {
        MetaDataV3 {
            seq_number,
            ..p2p_wire::testkit::metadata()
        }
    }

    struct Outcome {
        code: u8,
        lines: Vec<Value>,
        peer: StatusPeer,
        api: MockApi,
    }

    impl Outcome {
        fn event(&self, event: &str) -> Option<&Value> {
            self.lines.iter().find(|l| l["event"] == event)
        }

        fn verdict(&self, field: &str) -> bool {
            verdict_of(self.line(), field)
        }

        fn line(&self) -> &Value {
            self.event("m2a-status").expect("a Status log line")
        }

        fn metadata_line(&self) -> &Value {
            self.event("m2a-metadata").expect("a MetaData log line")
        }

        fn metadata_verdict(&self, field: &str) -> bool {
            verdict_of(self.metadata_line(), field)
        }

        fn ping_line(&self) -> &Value {
            self.event("m2a-ping").expect("a Ping log line")
        }

        fn ping_verdict(&self, field: &str) -> bool {
            verdict_of(self.ping_line(), field)
        }
    }

    fn verdict_of(line: &Value, field: &str) -> bool {
        line["verdicts"][field]["pass"]
            .as_bool()
            .unwrap_or_else(|| panic!("no verdict {field}: {line}"))
    }

    async fn api_for(s: &Scenario) -> MockApi {
        let pinned = Network::Sepolia.genesis().unwrap();
        let mut routes = vec![
            (
                "/eth/v1/beacon/genesis".to_owned(),
                Route::json(MockApi::genesis_json(
                    pinned.genesis_time,
                    Root::from(pinned.genesis_validators_root),
                    [0x90, 0, 0, 0x69],
                )),
            ),
            (
                "/eth/v1/node/identity".to_owned(),
                Route::sequence(s.identity_bodies.clone().unwrap_or_else(|| {
                    s.identity
                        .iter()
                        .map(|m| MockApi::identity_json(s.enr, m))
                        .collect()
                })),
            ),
            (
                "/eth/v1/beacon/states/head/finality_checkpoints".to_owned(),
                Route::sequence(
                    s.finality
                        .iter()
                        .map(|(e, r)| MockApi::finality_json(*e, root(*r)))
                        .collect(),
                ),
            ),
            (
                "/eth/v1/beacon/headers/head".to_owned(),
                Route::json(MockApi::header_json(root(HEAD_ROOT), HEAD_SLOT, true)),
            ),
        ];
        for (epoch, r) in [F1, F2, F3] {
            routes.push((
                format!("/eth/v1/beacon/headers/{}", root(r)),
                Route::json(MockApi::header_json(root(r), finalized_slot(epoch), true)),
            ));
        }
        // The blocks the peers name as their head: canonical, at HEAD_SLOT + off.
        for off in -3i64..=3 {
            let slot = HEAD_SLOT.checked_add_signed(off).unwrap();
            routes.push((
                format!("/eth/v1/beacon/headers/{}", root(head_byte(off))),
                Route::json(MockApi::header_json(root(head_byte(off)), slot, true)),
            ));
        }
        MockApi::start(
            routes
                .iter()
                .map(|(p, r)| (p.as_str(), r.clone()))
                .collect(),
        )
        .await
    }

    /// Runs the binary's `run` against the scenario's peer and API.
    async fn probe(s: Scenario) -> Outcome {
        let statuses = s.peer.clone();
        let metadata = s.metadata.clone();
        let pings = s.ping.clone();
        let peer = StatusPeer::spawn_with_ping(
            Box::new(move |req, n| {
                StatusReply::Status(StatusV2 {
                    fork_digest: req.fork_digest,
                    ..statuses[n.min(statuses.len() - 1)].clone()
                })
            }),
            Some(Box::new(move |n| {
                metadata[n.min(metadata.len() - 1)].clone()
            })),
            Some(Box::new(move |_, n| pings[n.min(pings.len() - 1)].clone())),
            s.disconnect_after,
        )
        .await;
        probe_with_peer(s, peer).await
    }

    /// Runs the binary's `run` against `peer` and the scenario's API.
    async fn probe_with_peer(s: Scenario, peer: StatusPeer) -> Outcome {
        let api = api_for(&s).await;
        let addr = format!("{}/p2p/{}", peer.addr, peer.id);
        let (dir, path) = config_with_api(&addr, &api.url(), "");
        let gate = gate_file(&dir, &s.gate);
        let env = RunEnv {
            now_ms: clock(s.clock.clone()),
            ..test_env()
        };
        let (code, out) = tokio::task::spawn_blocking(move || {
            std::thread::spawn(move || {
                let _dir = dir;
                let mut out = Vec::new();
                let args = ["--config", &path, "--gate-file", &gate];
                let code = run(argv(&args), 1000, &mut out, &env);
                (code, String::from_utf8(out).unwrap())
            })
            .join()
            .unwrap()
        })
        .await
        .unwrap();
        let lines: Vec<Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(lines.len() <= 3, "one JSON line per step at most: {out}");
        Outcome {
            code,
            lines,
            peer,
            api,
        }
    }

    const FINALITY_PATH: &str = "/eth/v1/beacon/states/head/finality_checkpoints";
    const IDENTITY_PATH: &str = "/eth/v1/node/identity";

    #[tokio::test(flavor = "multi_thread")]
    async fn matching_peer_passes() {
        let eas = HEAD_SLOT - 100;
        let out = probe(Scenario::new(peer_status(F1, 0, eas))).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.line());
        assert_eq!(out.line()["pass"], true);
        for field in probe::FIELDS {
            assert!(out.verdict(field), "{field}: {}", out.line());
        }
        // Our Status: the computed digest, the API's finalized checkpoint and block.
        let ours = &out.peer.requests()[0];
        assert_eq!(ours.fork_digest, DIGEST);
        assert_eq!(ours.finalized_root, root(F1.1));
        assert_eq!(ours.finalized_epoch, F1.0);
        assert_eq!(ours.head_root, root(F1.1));
        assert_eq!(ours.head_slot, finalized_slot(F1.0));
        assert_eq!(ours.earliest_available_slot, ours.head_slot);
        // The first Status, the MetaData, the Ping with our seq_number 0, then the second
        // Status, all on one connection.
        assert_eq!(out.peer.requests().len(), 2);
        assert_eq!(out.peer.metadata_requests(), 1);
        assert_eq!(out.peer.pings(), vec![ping::OUR_SEQ_NUMBER]);
        assert_eq!(ping::OUR_SEQ_NUMBER, 0);
        assert_eq!(out.peer.connections(), 1);
        assert_eq!(out.api.hits(FINALITY_PATH), 2, "sampled before and after");
        assert_eq!(out.lines.len(), 3, "one line per step");
        let events: Vec<&Value> = out.lines.iter().map(|l| &l["event"]).collect();
        assert_eq!(events, ["m2a-status", "m2a-metadata", "m2a-ping"]);
        assert_eq!(out.ping_line()["pass"], true);
        for field in ping::FIELDS {
            assert!(out.ping_verdict(field), "{field}: {}", out.ping_line());
        }
        assert_eq!(out.metadata_line()["pass"], true);
        for field in metadata::FIELDS {
            assert!(
                out.metadata_verdict(field),
                "{field}: {}",
                out.metadata_line()
            );
        }
        // The ENR read, then the MetaData sampled before and after the request.
        assert_eq!(out.api.hits(IDENTITY_PATH), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_log_line_has_the_peers_metadata_both_samples_and_verdicts() {
        let out = probe(Scenario::new(peer_status(F1, 0, 0))).await;
        let line = out.metadata_line();
        assert_eq!(line["event"], "m2a-metadata");
        assert_eq!(line["error"], Value::Null);
        // The beacon API's encodings: decimal strings, 0x hex bitvectors.
        let want = serde_json::json!({
            "seq_number": "7",
            "attnets": "0x0100000000000080",
            "syncnets": "0x04",
            "custody_group_count": "4",
        });
        for key in ["peer", "api_before", "api_after"] {
            assert_eq!(line[key], want, "{key}");
        }
        assert_eq!(line["seq_number_reruns"], 0);
        let verdicts = line["verdicts"].as_object().unwrap();
        let mut names: Vec<&str> = verdicts.keys().map(String::as_str).collect();
        names.sort_unstable();
        let mut fields = metadata::FIELDS.to_vec();
        fields.sort_unstable();
        assert_eq!(names, fields);
        for v in verdicts.values() {
            assert!(v["pass"].is_boolean() && v["detail"].is_string(), "{v}");
        }
        assert!(!line.to_string().contains('\n'));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_mismatch_fails() {
        // The peer reports sync subnet 3 as well: one syncnets bit differs from the API's.
        let mut theirs = md(7);
        theirs.syncnets.set(3, true).unwrap();
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.metadata = vec![MetaDataReply::MetaData(theirs)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert_eq!(out.line()["pass"], true, "the Status step itself passed");
        let line = out.metadata_line();
        assert_eq!(line["pass"], false);
        assert!(!out.metadata_verdict("syncnets"));
        for field in ["seq_number", "attnets", "custody_group_count"] {
            assert!(out.metadata_verdict(field), "{field}: {line}");
        }
        let detail = line["verdicts"]["syncnets"]["detail"].as_str().unwrap();
        assert!(detail.contains("syncnets"), "{detail}");
        assert!(
            detail.contains("0x0c") && detail.contains("0x04"),
            "{detail}"
        );
        assert_eq!(line["peer"]["syncnets"], "0x0c");
        assert_eq!(line["api_after"]["syncnets"], "0x04");
        // Every other field on its own, too.
        for (field, theirs) in [
            ("seq_number", md(8)),
            (
                "custody_group_count",
                MetaDataV3 {
                    custody_group_count: 8,
                    ..md(7)
                },
            ),
            ("attnets", {
                let mut m = md(7);
                m.attnets.set(1, true).unwrap();
                m
            }),
        ] {
            let mut s = Scenario::new(peer_status(F1, 0, 0));
            s.metadata = vec![MetaDataReply::MetaData(theirs)];
            let out = probe(s).await;
            assert_eq!(out.code, EXIT_FAILED, "{field}");
            assert!(!out.metadata_verdict(field), "{field}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_seq_moved_reruns_once() {
        // The node's seq_number moves between the samples (a subnet rotation): the request runs
        // again, sampled after the newer one, and the peer (now at 8) matches it.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.identity = vec![md(7), md(7), md(8), md(8)];
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::MetaData(md(8)),
        ];
        s.ping = vec![PingReply::Ping(8)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.metadata_line());
        let line = out.metadata_line();
        assert_eq!(line["seq_number_reruns"], 1);
        assert_eq!(line["api_before"]["seq_number"], "8");
        assert_eq!(line["api_after"]["seq_number"], "8");
        assert_eq!(line["peer"]["seq_number"], "8");
        assert_eq!(out.peer.metadata_requests(), 2);
        assert_eq!(out.api.hits(IDENTITY_PATH), 4);

        // It moves again during the re-run: every field fails, no third request.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.identity = vec![md(7), md(7), md(8), md(9)];
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::MetaData(md(8)),
        ];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let line = out.metadata_line();
        assert_eq!(line["seq_number_reruns"], 1);
        for field in metadata::FIELDS {
            assert!(!out.metadata_verdict(field), "{field}");
            let detail = line["verdicts"][field]["detail"].as_str().unwrap();
            assert!(detail.contains("moved again"), "{detail}");
        }
        assert_eq!(line["api_before"]["seq_number"], "8");
        assert_eq!(line["api_after"]["seq_number"], "9");
        assert_eq!(out.peer.metadata_requests(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_rerun_request_failure_logs_only_the_rerun() {
        // seq_number moves (7 -> 8), and the re-run's request fails: the line holds the re-run's
        // sample before it and nothing from the first attempt.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.identity = vec![md(7), md(7), md(8)];
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::Error(ResultCode::ServerError, b"busy".to_vec()),
        ];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let line = out.metadata_line();
        assert_eq!(line["seq_number_reruns"], 1);
        let error = line["error"].as_str().unwrap();
        assert!(error.starts_with("metadata request:"), "{error}");
        assert_eq!(line["api_before"]["seq_number"], "8");
        assert_eq!(line["peer"], Value::Null, "not the first attempt's: {line}");
        assert_eq!(
            line["api_after"],
            Value::Null,
            "not the first attempt's: {line}"
        );
        assert_eq!(out.peer.metadata_requests(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_rerun_sample_failure_logs_only_the_rerun() {
        // seq_number moves (7 -> 8), and the re-run's sample after the request is malformed: the
        // line holds the re-run's sample before and its peer MetaData, and no sample after.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        let body = |m: &MetaDataV3| MockApi::identity_json(s.enr, m);
        let bad = body(&md(9)).replace("0x0100000000000080", "0x01");
        s.identity_bodies = Some(vec![body(&md(7)), body(&md(7)), body(&md(8)), bad]);
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::MetaData(md(8)),
        ];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let line = out.metadata_line();
        assert_eq!(line["seq_number_reruns"], 1);
        let error = line["error"].as_str().unwrap();
        assert!(
            error.starts_with("MetaData sample:") && error.contains("attnets"),
            "{error}"
        );
        assert_eq!(line["api_before"]["seq_number"], "8");
        assert_eq!(
            line["peer"]["seq_number"], "8",
            "the re-run's answer: {line}"
        );
        assert_eq!(
            line["api_after"],
            Value::Null,
            "not the first attempt's: {line}"
        );
        assert_eq!(out.api.hits(IDENTITY_PATH), 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_request_failure_fails_the_step_only() {
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.metadata = vec![MetaDataReply::Error(
            ResultCode::ServerError,
            b"busy".to_vec(),
        )];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let line = out.metadata_line();
        assert_eq!(line["pass"], false);
        let error = line["error"].as_str().unwrap();
        assert!(
            error.starts_with("metadata request:") && error.contains("busy"),
            "{error}"
        );
        assert_eq!(
            line["api_before"]["seq_number"], "7",
            "sampled before the request"
        );
        assert_eq!(line["peer"], Value::Null);
        // No MetaData seq_number to compare a Ping answer with: no Ping.
        assert!(out.event("m2a-ping").is_none());
        assert!(out.peer.pings().is_empty());
        // The connection check still ran, on the same connection.
        assert_eq!(out.line()["pass"], true);
        assert!(out.verdict("connection"));
        assert_eq!(out.peer.connections(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_identity_metadata_fails_the_step() {
        // The ENR read is lenient; the MetaData sample is not: attnets is one byte, not eight.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        let valid = MockApi::identity_json(s.enr, &md(7));
        s.identity_bodies = Some(vec![
            valid.clone(),
            valid.replace("0x0100000000000080", "0x01"),
        ]);
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert_eq!(out.line()["pass"], true);
        let error = out.metadata_line()["error"].as_str().unwrap();
        assert!(error.contains("attnets"), "{error}");
        assert_eq!(
            out.peer.metadata_requests(),
            0,
            "no request without a sample"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ping_log_line_has_our_seq_the_peers_and_the_metadata_steps() {
        let out = probe(Scenario::new(peer_status(F1, 0, 0))).await;
        let line = out.ping_line();
        assert_eq!(line["event"], "m2a-ping");
        assert_eq!(line["pass"], true);
        assert_eq!(line["error"], Value::Null);
        // Decimal strings, as the beacon API encodes a uint64.
        assert_eq!(line["our_seq_number"], "0");
        assert_eq!(line["peer_seq_number"], "7");
        assert_eq!(line["metadata_seq_number"], "7");
        assert_eq!(line["metadata_refetches"], 0);
        assert_eq!(line["refetched"], Value::Null);
        let verdicts = line["verdicts"].as_object().unwrap();
        let names: Vec<&str> = verdicts.keys().map(String::as_str).collect();
        assert_eq!(names, ping::FIELDS);
        let detail = verdicts["seq_number"]["detail"].as_str().unwrap();
        assert!(
            detail.contains("Ping 7") && detail.contains("MetaData 7"),
            "{detail}"
        );
        assert!(!line.to_string().contains('\n'));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ping_seq_lower_fails() {
        // The MetaData step decoded 7; a Ping answer of 6 went backwards.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.ping = vec![PingReply::Ping(6)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert_eq!(out.line()["pass"], true, "the Status step itself passed");
        assert_eq!(out.metadata_line()["pass"], true);
        let line = out.ping_line();
        assert_eq!(line["pass"], false);
        assert!(!out.ping_verdict("seq_number"));
        assert_eq!(line["peer_seq_number"], "6");
        assert_eq!(line["metadata_seq_number"], "7");
        let detail = line["verdicts"]["seq_number"]["detail"].as_str().unwrap();
        assert!(detail.contains("below"), "{detail}");
        // No re-fetch for a lower answer.
        assert_eq!(line["metadata_refetches"], 0);
        assert_eq!(out.peer.metadata_requests(), 1);
        assert_eq!(out.api.hits(IDENTITY_PATH), 3);
        // The connection check still ran.
        assert!(out.verdict("connection"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ping_seq_higher_refetches_metadata() {
        // The peer's MetaData moved to 8 after the step (a subnet rotation): one re-fetch, and
        // the new MetaData matches the Ping answer and the re-sampled identity.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.identity = vec![md(7), md(7), md(7), md(8)];
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::MetaData(md(8)),
        ];
        s.ping = vec![PingReply::Ping(8)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.ping_line());
        let line = out.ping_line();
        assert_eq!(line["pass"], true);
        assert_eq!(line["metadata_refetches"], 1);
        assert_eq!(line["peer_seq_number"], "8");
        assert_eq!(line["metadata_seq_number"], "7");
        // Both MetaData results are logged: the step's and the re-fetched one.
        assert_eq!(out.metadata_line()["peer"]["seq_number"], "7");
        assert_eq!(line["refetched"]["peer"]["seq_number"], "8");
        assert_eq!(line["refetched"]["api"]["seq_number"], "8");
        assert!(out.ping_verdict("seq_number") && out.ping_verdict("refetch_identity"));
        assert_eq!(out.peer.metadata_requests(), 2, "exactly one re-fetch");
        assert_eq!(out.peer.pings(), vec![0], "one Ping");
        // The ENR read, the step's two samples, the re-sample.
        assert_eq!(out.api.hits(IDENTITY_PATH), 4);
        assert_eq!(out.peer.connections(), 1);

        // The re-fetched MetaData is at 9, not the Ping's 8: fail, and no second re-fetch.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.identity = vec![md(7), md(7), md(7), md(9)];
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::MetaData(md(9)),
        ];
        s.ping = vec![PingReply::Ping(8)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let line = out.ping_line();
        assert_eq!(line["pass"], false);
        assert!(!out.ping_verdict("seq_number"));
        assert!(out.ping_verdict("refetch_identity"), "{line}");
        assert_eq!(line["refetched"]["peer"]["seq_number"], "9");
        assert_eq!(line["metadata_refetches"], 1);
        assert_eq!(out.peer.metadata_requests(), 2, "never a second re-fetch");

        // The re-fetched MetaData matches the Ping, but the reference identity is still at 7.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::MetaData(md(8)),
        ];
        s.ping = vec![PingReply::Ping(8)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert!(out.ping_verdict("seq_number"));
        assert!(!out.ping_verdict("refetch_identity"));
        let line = out.ping_line();
        let detail = line["verdicts"]["refetch_identity"]["detail"]
            .as_str()
            .unwrap();
        assert!(detail.contains("seq_number"), "{detail}");
        assert_eq!(line["refetched"]["api"]["seq_number"], "7");
        assert_eq!(out.peer.metadata_requests(), 2);

        // The re-fetch itself fails: the step fails with the error.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::Error(ResultCode::ServerError, b"busy".to_vec()),
        ];
        s.ping = vec![PingReply::Ping(8)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let error = out.ping_line()["error"].as_str().unwrap();
        assert!(
            error.starts_with("metadata re-fetch:") && error.contains("busy"),
            "{error}"
        );
        assert_eq!(out.peer.metadata_requests(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ping_failure_fails_the_step_only() {
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.ping = vec![PingReply::Chunks(vec![7, 7])];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert_eq!(out.line()["pass"], true);
        assert_eq!(out.metadata_line()["pass"], true);
        let line = out.ping_line();
        assert_eq!(line["pass"], false);
        assert_eq!(line["peer_seq_number"], Value::Null);
        assert_eq!(line["metadata_seq_number"], "7");
        let error = line["error"].as_str().unwrap();
        assert!(
            error.starts_with("ping:") && error.contains("chunks"),
            "{error}"
        );
        assert!(out.verdict("connection"));
        assert_eq!(out.peer.connections(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finalized_mismatch_fails() {
        let out = probe(Scenario::new(peer_status(F2, 0, HEAD_SLOT))).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert!(!out.verdict("finalized_root"));
        assert!(!out.verdict("finalized_epoch"));
        assert!(out.verdict("head_slot") && out.verdict("fork_digest"));
        assert_eq!(out.line()["pass"], false);
        // Only the epoch differs: still a failure, exact match only.
        let wrong_epoch = StatusV2 {
            finalized_epoch: F1.0 + 1,
            ..peer_status(F1, 0, HEAD_SLOT)
        };
        let out = probe(Scenario::new(wrong_epoch)).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert!(out.verdict("finalized_root"));
        assert!(!out.verdict("finalized_epoch"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn head_2_slots_off_passes() {
        for off in [-2, 2] {
            let out = probe(Scenario::new(peer_status(F1, off, HEAD_SLOT - 10))).await;
            assert_eq!(out.code, EXIT_CONNECTED, "{off}: {}", out.line());
            assert!(out.verdict("head_slot") && out.verdict("head_root"));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn head_3_slots_off_fails() {
        for off in [-3, 3] {
            let out = probe(Scenario::new(peer_status(F1, off, 0))).await;
            assert_eq!(out.code, EXIT_FAILED, "{off}");
            assert!(!out.verdict("head_slot"));
            assert!(out.verdict("head_root"), "the block itself is known");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn head_root_unknown_or_at_another_slot_fails() {
        let unknown = StatusV2 {
            head_root: root(0x01),
            ..peer_status(F1, 0, 0)
        };
        let out = probe(Scenario::new(unknown)).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert!(!out.verdict("head_root"));
        assert!(out.verdict("head_slot"));
        // The head root of HEAD_SLOT + 1, claimed at HEAD_SLOT.
        let elsewhere = StatusV2 {
            head_root: root(head_byte(1)),
            ..peer_status(F1, 0, 0)
        };
        let out = probe(Scenario::new(elsewhere)).await;
        assert!(!out.verdict("head_root"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn finality_moved_reruns_once() {
        // Finality moves between the first two samples: the exchange runs again with a Status
        // built from the newer checkpoint, and the peer (now at F2) matches it.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.finality = vec![F1, F2, F2];
        s.peer = vec![peer_status(F1, 0, 0), peer_status(F2, 0, 0)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.line());
        assert_eq!(out.line()["finality_reruns"], 1);
        let requests = out.peer.requests();
        assert_eq!(requests[0].finalized_root, root(F1.1));
        assert_eq!(requests[1].finalized_root, root(F2.1));
        assert_eq!(requests[1].finalized_epoch, F2.0);
        // First, re-run, then the second Status of the connection check.
        assert_eq!(requests.len(), 3);
        assert_eq!(out.api.hits(FINALITY_PATH), 3);
        assert_eq!(
            out.line()["api_before"]["finalized"]["epoch"],
            F2.0.to_string()
        );

        // Finality moves again during the re-run: the check fails, no third exchange.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.finality = vec![F1, F2, F3];
        s.peer = vec![peer_status(F1, 0, 0), peer_status(F2, 0, 0)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert_eq!(out.line()["finality_reruns"], 1);
        assert!(!out.verdict("finalized_root") && !out.verdict("finalized_epoch"));
        let detail = out.line()["verdicts"]["finalized_root"]["detail"]
            .as_str()
            .unwrap();
        assert!(detail.contains("moved again"), "{detail}");
        assert_eq!(out.api.hits(FINALITY_PATH), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn eas_equal_head_passes() {
        let out = probe(Scenario::new(peer_status(F1, 1, HEAD_SLOT + 1))).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.line());
        assert!(out.verdict("earliest_available_slot"));
        assert_eq!(
            out.line()["earliest_available_slot"],
            (HEAD_SLOT + 1).to_string()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn eas_above_head_fails() {
        let out = probe(Scenario::new(peer_status(F1, 0, HEAD_SLOT + 1))).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert!(!out.verdict("earliest_available_slot"));
        assert_eq!(
            out.line()["earliest_available_slot"],
            (HEAD_SLOT + 1).to_string()
        );
        for field in ["fork_digest", "finalized_root", "head_slot", "connection"] {
            assert!(out.verdict(field), "{field}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn status_then_disconnect_fails() {
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        // Answers the Status, the MetaData and the Ping, then closes the connection.
        s.disconnect_after = Some(3);
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert!(!out.verdict("connection"));
        for field in ["fork_digest", "finalized_root", "head_slot", "head_root"] {
            assert!(out.verdict(field), "{field}");
        }
        assert_eq!(
            out.peer.requests().len(),
            1,
            "no second Status reached the peer"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn second_status_after_a_digest_boundary_sends_the_new_digest() {
        // The exchange runs in the last Fulu epoch; the hold crosses GLOAS_FORK_EPOCH. A peer
        // on the new fork answers the second Status with the Gloas digest, which is only ours
        // if the second Status is built afresh.
        const BPO2: [u8; 4] = [0x74, 0xd0, 0x14, 0x59];
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.clock = vec![353_023, 353_024];
        s.enr = crate::enr::tests::ENR_BPO2;
        let statuses = [
            StatusV2 {
                fork_digest: BPO2,
                ..peer_status(F1, 0, 0)
            },
            StatusV2 {
                fork_digest: DIGEST,
                ..peer_status(F1, 0, 0)
            },
        ];
        // It serves MetaData and Ping too: both steps run between the two Status exchanges.
        let metadata = s.metadata[0].clone();
        let ping = s.ping[0].clone();
        let peer = StatusPeer::spawn_with_ping(
            Box::new(move |_, n| StatusReply::Status(statuses[n.min(1)].clone())),
            Some(Box::new(move |_| metadata.clone())),
            Some(Box::new(move |_, _| ping.clone())),
            None,
        )
        .await;
        let out = probe_with_peer(s, peer).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.line());
        assert!(out.verdict("connection"));
        assert_eq!(out.metadata_line()["pass"], true);
        assert_eq!(out.peer.metadata_requests(), 1);
        assert_eq!(out.ping_line()["pass"], true);
        assert_eq!(out.peer.pings(), vec![ping::OUR_SEQ_NUMBER]);
        let requests = out.peer.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].fork_digest, BPO2);
        assert_eq!(
            requests[1].fork_digest, DIGEST,
            "the second Status is rebuilt"
        );
        assert_eq!(out.line()["digest_inputs"]["epoch"], "353023");
    }

    /// Runs `args` (after `--config <config>`) on a runtime-free thread.
    async fn run_off_runtime(config: String, args: Vec<String>, env: RunEnv) -> (u8, String) {
        tokio::task::spawn_blocking(move || {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let mut all = vec!["--config".to_owned(), config];
                all.extend(args);
                let code = run(all.into_iter(), 1000, &mut out, &env);
                (code, String::from_utf8(out).unwrap())
            })
            .join()
            .unwrap()
        })
        .await
        .unwrap()
    }

    /// A config pinning `peer` with no `reference_api_url`.
    fn config_without_api(peer: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m2a-session.toml");
        std::fs::write(&path, format!("network = \"sepolia\"\npeer = \"{peer}\"\n")).unwrap();
        let path = path.to_str().unwrap().to_owned();
        (dir, path)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dial_only_needs_no_reference_api_url() {
        let peer = StatusPeer::echoing(peer_status(F1, 0, 0)).await;
        let (_dir, path) = config_without_api(&format!("{}/p2p/{}", peer.addr, peer.id));
        let (code, _) = run_off_runtime(path, vec!["--dial-only".into()], test_env()).await;
        assert_eq!(code, EXIT_CONNECTED);
        assert_eq!(peer.connections(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_without_reference_api_url_is_refused() {
        let peer = StatusPeer::echoing(peer_status(F1, 0, 0)).await;
        let (dir, path) = config_without_api(&format!("{}/p2p/{}", peer.addr, peer.id));
        let gate = gate_file(&dir, &passing_gate(&fixture_expected()));
        let (code, out) = run_off_runtime(path, vec!["--gate-file".into(), gate], test_env()).await;
        assert_eq!(code, EXIT_REFUSED);
        assert!(out.is_empty(), "refused before the session: {out}");
        assert_eq!(peer.connections(), 0, "refused before dialling");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enr_digest_mismatch_fails() {
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.enr = crate::enr::tests::ENR_BPO2;
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert!(!out.verdict("enr_fork_digest"));
        assert!(out.verdict("fork_digest"));
        assert_eq!(out.line()["enr_fork_digest"], "0x74d01459");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gate_file_required() {
        let missing = Scenario::new(peer_status(F1, 0, 0));
        let mut stale = Scenario::new(peer_status(F1, 0, 0));
        stale.gate["decoder_key"]["git"]["crates/p2p-wire"] = Value::from("0".repeat(40));
        let mut short = Scenario::new(peer_status(F1, 0, 0));
        short.gate["targets"][2]["seconds"] = Value::from(3599);
        let mut crashed = Scenario::new(peer_status(F1, 0, 0));
        crashed.gate["targets"][0]["crashes"] = Value::from(1);
        missing_gate_refused(missing).await;
        for s in [stale, short, crashed] {
            let out = probe(s).await;
            assert_eq!(out.code, EXIT_REFUSED);
            assert!(out.lines.is_empty(), "refused before the session");
            assert_eq!(out.peer.connections(), 0, "refused before dialling");
            assert!(out.api.seen().is_empty(), "and before the API");
        }
    }

    async fn missing_gate_refused(s: Scenario) {
        let peer = StatusPeer::echoing(s.peer[0].clone()).await;
        let addr = format!("{}/p2p/{}", peer.addr, peer.id);
        let (dir, path) = config(&addr, "");
        let gate = dir.path().join("no-gate.json");
        let gate = gate.to_str().unwrap().to_owned();
        let code = tokio::task::spawn_blocking(move || {
            std::thread::spawn(move || {
                let args = ["--config", path.as_str(), "--gate-file", gate.as_str()];
                run(argv(&args), 1000, &mut Vec::new(), &test_env())
            })
            .join()
            .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(peer.connections(), 0);
        // A build without a decoder key refuses even a passing gate file.
        let (dir, path) = config(&addr, "");
        let gate = gate_file(&dir, &passing_gate(&fixture_expected()));
        let env = RunEnv {
            gate: Expected::Unavailable("fuzz/src is not in HEAD".into()),
            ..test_env()
        };
        let code = tokio::task::spawn_blocking(move || {
            std::thread::spawn(move || {
                let args = ["--config", path.as_str(), "--gate-file", gate.as_str()];
                run(argv(&args), 1000, &mut Vec::new(), &env)
            })
            .join()
            .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(peer.connections(), 0);
        drop(dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn genesis_mismatch_stops_before_the_exchange() {
        let s = Scenario::new(peer_status(F1, 0, 0));
        let peer = StatusPeer::echoing(s.peer[0].clone()).await;
        let api = MockApi::start(vec![(
            "/eth/v1/beacon/genesis",
            Route::json(MockApi::genesis_json(1, root(9), [0x90, 0, 0, 0x69])),
        )])
        .await;
        let addr = format!("{}/p2p/{}", peer.addr, peer.id);
        let (dir, path) = config_with_api(&addr, &api.url(), "");
        let gate = gate_file(&dir, &passing_gate(&fixture_expected()));
        let (code, out) = tokio::task::spawn_blocking(move || {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let args = ["--config", path.as_str(), "--gate-file", gate.as_str()];
                (run(argv(&args), 1000, &mut out, &test_env()), out)
            })
            .join()
            .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(code, EXIT_FAILED);
        let line: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(line["verdicts"]["genesis"]["pass"], false);
        assert!(line["error"].as_str().unwrap().contains("genesis"));
        assert!(peer.requests().is_empty(), "no Status sent");
        drop(dir);
    }
}
