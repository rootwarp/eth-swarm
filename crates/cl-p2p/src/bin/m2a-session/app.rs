//! The whole `m2a-session` run, shared by the two binaries: `m2a-session` calls
//! [`main`] with `test_build = false`, the test binary `m2a-session-test` with `true` (see the
//! crate docs of `main.rs`). Nothing else differs between them.

use crate::build_info::BuildInfo;
use crate::gate::Expected;
use crate::probe::{Chain, Probe, Verdict};
use crate::reference_api::ReferenceApi;
use crate::{gate, probe, reference_api, summary};
use cl_p2p::m2a_session::config::{M2aConfig, Network as SessionNetwork, DEFAULT_CONFIG_PATH};
use cl_p2p::m2a_session::os_user::{self, ProcessGids, ProcessUids, UserEntry, UserError};
use cl_p2p::m2a_session::{
    check_platform, check_process, check_run_as, preflight, KeySource, Preflight, PreflightError,
    Session, SessionError, SessionUser, Transport, IDLE_CONNECTION_TIMEOUT,
};
use consensus_types::{EthSpec, Mainnet};
use network_config::{ChainConfig, Network};
use p2p_wire::rpc::codec::ContextTable;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
use svc_runtime::telemetry::{flush_logs, init_binary_tracing};
use tracing_subscriber::filter::LevelFilter;

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
    /// Unix milliseconds now, for the fork digests.
    now_ms: Box<dyn Fn() -> u128 + Send + Sync>,
    /// Unix milliseconds now, for the summary's start and end time.
    wall_ms: Box<dyn Fn() -> u128 + Send + Sync>,
    /// How long the probe holds the connection.
    hold: Duration,
    /// How long the connection may go without a stream before our side closes it.
    idle_timeout: Duration,
    /// Builds the runtime the session runs on.
    runtime: fn() -> std::io::Result<tokio::runtime::Runtime>,
    /// The UID and primary GID of an OS user: `getpwnam_r` ([`os_user::user_of`]) in
    /// production.
    user_of: fn(&str) -> Result<UserEntry, UserError>,
    /// Whether this is the test binary `m2a-session-test`: `false` in `m2a-session`. It goes to
    /// the pre-flight as `test_build`.
    test_build: bool,
    /// The platform: [`Preflight::os_of_this_build`] in production.
    os: String,
    /// The owner the config's path may have besides root: 0 (root only) in `m2a-session`, the
    /// process's own UID in the test binary.
    config_owner: u32,
    /// The build commit and state: [`BuildInfo::built`] in production.
    build: BuildInfo,
}

/// A current-thread tokio runtime with I/O and timers.
fn current_thread_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// Unix milliseconds of the system clock.
fn system_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

impl RunEnv {
    /// The embedded gate expectations, the system clock, [`probe::HOLD`]; `test_build` as the
    /// binary passes it.
    fn production(test_build: bool) -> Self {
        Self {
            test_build,
            os: Preflight::os_of_this_build().into(),
            config_owner: if test_build {
                rustix::process::geteuid().as_raw()
            } else {
                0
            },
            gate: Expected::built(),
            build: BuildInfo::built(),
            now_ms: Box::new(system_ms),
            wall_ms: Box::new(system_ms),
            hold: probe::HOLD,
            idle_timeout: IDLE_CONNECTION_TIMEOUT,
            runtime: current_thread_runtime,
            user_of: os_user::user_of,
        }
    }
}

/// How the pre-flight checked the node key, for the summary.
fn key_handling(key: &KeySource, euid: u32) -> Verdict {
    let detail = match key {
        KeySource::Ephemeral => "ephemeral secp256k1 key: never written, never logged".to_owned(),
        KeySource::File(path) => format!(
            "key file {}: a regular file of mode 0600 owned by UID {euid}; its bytes wiped \
             after loading, never logged",
            path.display()
        ),
    };
    Verdict { pass: true, detail }
}

/// The process's own UIDs, GIDs and supplementary groups.
#[derive(Debug, Clone)]
struct ProcessIds {
    uids: ProcessUids,
    gids: ProcessGids,
}

/// The binary's `main`: `test_build` is `false` in `m2a-session` and `true` only in the test
/// binary `m2a-session-test`, which then says so first.
pub fn main(test_build: bool) -> ExitCode {
    if let Err(no_log_writer) = init_binary_tracing(LevelFilter::INFO) {
        return no_log_writer;
    }
    if test_build {
        tracing::warn!(
            test_build,
            "TEST BUILD m2a-session-test: it takes any run_as, that user's groups and a config \
             that user owns; never deploy it, deploy m2a-session"
        );
    }
    let gids = match os_user::process_gids() {
        Ok(gids) => gids,
        Err(e) => {
            tracing::error!(error = %e, "pre-flight refused: cannot read the process's groups");
            flush_logs(LOG_FLUSH_DEADLINE);
            return ExitCode::from(EXIT_REFUSED);
        }
    };
    let process = ProcessIds {
        uids: os_user::process_uids(),
        gids,
    };
    let env = RunEnv::production(test_build);
    let code = run(
        std::env::args().skip(1),
        process,
        &mut std::io::stdout(),
        &env,
    );
    flush_logs(LOG_FLUSH_DEADLINE);
    ExitCode::from(code)
}

/// The checks that need neither the config nor a lookup, first: the process's IDs
/// ([`check_process`]), then, outside the test binary, the platform (Linux only), so that the
/// error on another platform says so before any other check can fail there.
fn process_checks(process: &ProcessIds, env: &RunEnv) -> Result<(), PreflightError> {
    check_process(&process.uids, &process.gids)?;
    check_platform(&env.os, env.test_build)
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

/// Every digest of the schedule, from Fulu on, and the network's caps.
fn context_table(chain: &Chain) -> ContextTable {
    cl_p2p::rpc::network_context_table(&chain.config, &chain.genesis.genesis_validators_root)
}

/// What the session summary needs besides the report, fixed once the pre-flight passed.
struct SummaryInputs {
    peer_id: libp2p::PeerId,
    started_at_ms: u128,
    fuzz_gate: Verdict,
    euid: u32,
    user: String,
    key_handling: Verdict,
    test_build: bool,
    build: BuildInfo,
}

/// Writes the steps' lines and the summary to `out` and returns the exit code: 0 only if
/// every check passed. `session` is `None` if setup failed before there was one.
fn finish<E: EthSpec>(
    out: &mut dyn Write,
    env: &RunEnv,
    inputs: SummaryInputs,
    report: &probe::Report,
    session: Option<&mut Session<E>>,
) -> u8 {
    let (connected, listeners) = session.map_or((Vec::new(), 0), |s| {
        let swarm = s.swarm();
        (
            swarm.connected_peers().copied().collect(),
            swarm.listeners().count(),
        )
    });
    let summary = summary::Summary::new(
        report,
        summary::Facts {
            peer_id: inputs.peer_id,
            started_at_ms: inputs.started_at_ms,
            ended_at_ms: (env.wall_ms)(),
            connected,
            listeners,
            fuzz_gate: inputs.fuzz_gate,
            euid: inputs.euid,
            user: inputs.user,
            key_handling: inputs.key_handling,
            test_build: inputs.test_build,
            build: inputs.build,
        },
    );
    for line in report.json_lines().iter().chain([&summary.json_line()]) {
        if let Err(e) = writeln!(out, "{line}") {
            tracing::error!(error = %e, "cannot write the session log line");
            return EXIT_FAILED;
        }
    }
    if summary.passed() && report.passed() {
        tracing::info!("every check of the session passed");
        EXIT_CONNECTED
    } else {
        let failed: Vec<&str> = summary
            .checks()
            .iter()
            .filter(|(_, v)| !v.pass)
            .map(|(name, _)| *name)
            .collect();
        tracing::error!(error = ?report.error, ?failed, "probe failed");
        EXIT_FAILED
    }
}

/// A report of a session whose setup failed: no step ran.
fn setup_failed(why: String) -> probe::Report {
    probe::Report {
        error: Some(format!("session setup: {why}")),
        ..probe::Report::default()
    }
}

/// The whole run for `argv`, as a process with the IDs `process`, printing to `out`; returns
/// the exit code.
fn run(
    argv: impl Iterator<Item = String>,
    process: ProcessIds,
    out: &mut dyn Write,
    env: &RunEnv,
) -> u8 {
    let started_at_ms = (env.wall_ms)();
    let args = match parse_args(argv) {
        Ok(args) => args,
        Err(e) => {
            tracing::error!(error = %e, usage = USAGE, "bad arguments");
            return EXIT_REFUSED;
        }
    };
    // Root, mixed UIDs, GID 0 and mixed GIDs first, then the platform (Linux only, outside a
    // test build), before the config is read or the name service is asked.
    if let Err(e) = process_checks(&process, env) {
        tracing::error!(error = %e, "pre-flight refused");
        return EXIT_REFUSED;
    }
    let ProcessIds { uids, gids } = process;
    let euid = uids.effective;
    let config = match M2aConfig::load_for(&args.config, euid, env.config_owner) {
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
    let key_check = key_handling(&config.node_key, euid);
    // Only the session account, before the name service is asked (a test build takes others).
    if let Err(e) = check_run_as(&config.run_as, env.test_build) {
        tracing::error!(error = %e, "pre-flight refused");
        return EXIT_REFUSED;
    }
    let entry = match (env.user_of)(&config.run_as) {
        Ok(entry) => entry,
        Err(e) => {
            tracing::error!(error = %e, "pre-flight refused");
            return EXIT_REFUSED;
        }
    };
    let key = match preflight(
        &Preflight {
            uids,
            gids,
            user: SessionUser {
                name: config.run_as.clone(),
                uid: entry.uid,
                gid: entry.gid,
            },
            os: env.os.clone(),
            key: config.node_key.clone(),
        },
        env.test_build,
    ) {
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
        // A build that was not clean fails `clean_build`, so the session would give no
        // evidence: refuse it before the dial, not after the whole run.
        if !env.build.is_clean() {
            tracing::error!(
                commit = ?env.build.commit,
                error = env.build.unclean.as_deref().unwrap_or_default(),
                "pre-flight refused: the Status probe needs a clean build"
            );
            return EXIT_REFUSED;
        }
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
    // In probe mode, from here on every exit goes through the summary.
    let inputs = probe_api.as_ref().map(|_| SummaryInputs {
        peer_id: config.peer.peer_id,
        started_at_ms,
        // The probe runs only after the gate check passed.
        fuzz_gate: Verdict {
            pass: true,
            detail: format!(
                "the gate file {} passed for this build's decoders",
                args.gate_file.display()
            ),
        },
        euid,
        user: config.run_as.clone(),
        key_handling: key_check,
        test_build: env.test_build,
        build: env.build.clone(),
    });
    let runtime = match (env.runtime)() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "tokio runtime");
            return match inputs {
                Some(inputs) => finish::<Mainnet>(
                    out,
                    env,
                    inputs,
                    &setup_failed(format!("tokio runtime: {e}")),
                    None,
                ),
                None => EXIT_FAILED,
            };
        }
    };
    let contexts = Arc::new(context_table(&chain));
    runtime.block_on(async {
        let mut session = match Session::<Mainnet>::start_with_idle_timeout(
            key,
            config.peer,
            contexts,
            config.deadlines,
            Transport::Tcp,
            env.idle_timeout,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "session start");
                return match inputs {
                    Some(inputs) => finish::<Mainnet>(
                        out,
                        env,
                        inputs,
                        &setup_failed(format!("session start: {e}")),
                        None,
                    ),
                    None => EXIT_FAILED,
                };
            }
        };
        if let (Some(api), Some(inputs)) = (probe_api, inputs) {
            let probe = Probe {
                chain: &chain,
                now_ms: env.now_ms.as_ref(),
                connect_timeout: args.connect_timeout,
                hold: env.hold,
            };
            let report = probe::run(&mut session, &api, &probe).await;
            return finish(out, env, inputs, &report, Some(&mut session));
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
    use crate::{blocks, metadata, ping};
    use cl_p2p::testkit::{
        BlocksReply, BlocksResponder, MetaDataReply, PingReply, StatusPeer, StatusReply,
    };
    use consensus_types::forked;
    use consensus_types::primitives::{Root, Slot};
    use p2p_wire::rpc::messages::{BlocksByRangeV2Request, ForkDigest, MetaDataV3, StatusV2};
    use p2p_wire::rpc::protocols::{ResultCode, MAX_REQUEST_BLOCKS_DENEB};
    use serde_json::Value;
    use ssz::Encode;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;

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

    /// A loopback address that refuses every dial ([`cl_p2p::testkit::refused_tcp_addr`]).
    fn closed_port_peer() -> String {
        let addr = cl_p2p::testkit::refused_tcp_addr(std::net::Ipv4Addr::LOCALHOST.into());
        format!(
            "/ip4/{}/tcp/{}/p2p/{}",
            addr.ip(),
            addr.port(),
            libp2p::PeerId::random()
        )
    }

    /// A config dir pinning `peer` and the reference API at `api`, plus `extra` config lines.
    /// The directory is under [`cl_p2p::testkit::config_root`]: the session walks the config's
    /// path and refuses a symlink on it (macOS's `$TMPDIR` is under the `/var` symlink).
    fn config_with_api(peer: &str, api: &str, extra: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::Builder::new()
            .tempdir_in(cl_p2p::testkit::config_root())
            .unwrap();
        let path = dir.path().join("m2a-session.toml");
        let text = format!(
            "network = \"sepolia\"\npeer = \"{peer}\"\nreference_api_url = \"{api}\"\n{extra}\n"
        );
        std::fs::write(&path, text).unwrap();
        // Read-only: the session refuses a config its own effective UID can write.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
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

    /// The summary's clock: [`WALL_MS`], then one millisecond later per reading.
    const WALL_MS: u128 = 1_790_000_000_000;

    fn test_env() -> RunEnv {
        let readings = std::sync::atomic::AtomicU64::new(0);
        RunEnv {
            gate: Expected::Known(fixture_expected()),
            now_ms: Box::new(now_ms),
            wall_ms: Box::new(move || {
                WALL_MS + u128::from(readings.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
            }),
            hold: Duration::from_millis(300),
            idle_timeout: IDLE_CONNECTION_TIMEOUT,
            runtime: current_thread_runtime,
            user_of: test_user_of,
            // The production path (what `m2a-session` runs), on the platform it is for. The
            // tests that need the test binary's path use `test_build_env`.
            test_build: false,
            os: "linux".into(),
            config_owner: euid(),
            build: BuildInfo::fixture(),
        }
    }

    /// The test's users: `m2a-session` (the default `run_as`) is UID and GID 1000, `test-user`
    /// the effective UID and GID (for a key file the test owns), and no other user exists.
    fn test_user_of(name: &str) -> Result<UserEntry, UserError> {
        match name {
            "m2a-session" => Ok(UserEntry {
                uid: 1000,
                gid: 1000,
            }),
            "test-user" => Ok(UserEntry {
                uid: euid(),
                gid: egid(),
            }),
            other => Err(UserError::NotFound(other.to_owned())),
        }
    }

    fn egid() -> u32 {
        rustix::process::getegid().as_raw()
    }

    /// The IDs of a process running as `uid`, all equal: GID 1000 for the test's `m2a-session`
    /// (and 1001, a login user in its group), 0 for root, else the test's own effective GID.
    ///
    /// GitHub-hosted runners are uid 1001. `ids(euid())` is that process, not the synthetic
    /// login user, so it keeps the real gid. Otherwise `run_as = "test-user"` fails the
    /// group check before a dial.
    fn ids(uid: u32) -> ProcessIds {
        let gid = if uid == euid() && uid != 1000 {
            egid()
        } else {
            match uid {
                0 => 0,
                1000 | 1001 => 1000,
                _ => egid(),
            }
        };
        ProcessIds {
            uids: ProcessUids::same(uid),
            gids: ProcessGids::same(gid),
        }
    }

    /// A passing gate file for the test key, in `dir`.
    fn gate_file(dir: &tempfile::TempDir, gate: &Value) -> String {
        let path = dir.path().join("m2a-gate.json");
        std::fs::write(&path, gate.to_string()).unwrap();
        path.to_str().unwrap().to_owned()
    }

    /// [`test_env`] with the test binary's `test_build = true`: another `run_as`, its groups.
    fn test_build_env() -> RunEnv {
        RunEnv {
            test_build: true,
            ..test_env()
        }
    }

    /// `run` with [`test_build_env`].
    fn run_quiet_test_build(args: &[&str], euid: u32) -> (u8, String) {
        let mut out = Vec::new();
        let code = run(argv(args), ids(euid), &mut out, &test_build_env());
        (code, String::from_utf8(out).unwrap())
    }

    /// The production run refuses a platform other than Linux right after the process checks:
    /// before the config is read and before any lookup, so the error says so.
    #[test]
    fn the_platform_is_checked_before_the_config_and_the_lookup() {
        let macos = || RunEnv {
            os: "macos".into(),
            user_of: no_lookup,
            ..test_env()
        };
        assert_eq!(
            process_checks(&ids(1000), &macos()),
            Err(PreflightError::NotLinux("macos".into()))
        );
        // Root is refused first, as before.
        assert_eq!(process_checks(&ids(0), &macos()), Err(PreflightError::Root));
        assert_eq!(process_checks(&ids(1000), &test_env()), Ok(()));
        let test_build = RunEnv {
            test_build: true,
            ..macos()
        };
        assert_eq!(process_checks(&ids(1000), &test_build), Ok(()));
        // A config path that does not exist: if `run` read the config before the platform
        // check (or had no platform check), it would refuse the config, not the platform.
        let mut out = Vec::new();
        let missing = ["--config", "/nonexistent/m2a-session.toml", "--dial-only"];
        let (code, logs) = logs_of(|| run(argv(&missing), ids(1000), &mut out, &macos()));
        assert_eq!(code, EXIT_REFUSED);
        assert!(out.is_empty());
        assert!(
            logs.contains("pre-flight refused") && logs.contains("refusing to run on macos"),
            "{logs}"
        );
        assert!(!logs.contains("config refused"), "{logs}");
    }

    /// What `f` returns, and the log lines that it writes (the fmt layer, without colours).
    fn logs_of<R>(f: impl FnOnce() -> R) -> (R, String) {
        #[derive(Clone, Default)]
        struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lines = Lines::default();
        let writer = lines.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let result = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8_lossy(&lines.0.lock().unwrap()).into_owned();
        (result, text)
    }

    fn run_quiet(args: &[&str], euid: u32) -> (u8, String) {
        let mut out = Vec::new();
        let code = run(argv(args), ids(euid), &mut out, &test_env());
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

    /// A lookup that must not run: the process checks come first.
    fn no_lookup(name: &str) -> Result<UserEntry, UserError> {
        panic!("a name-service lookup of {name:?} before the process checks")
    }

    /// Root, and mixed real, effective and saved UIDs, are refused before the config is read and
    /// before any name-service lookup, in every mode.
    #[test]
    fn the_process_uids_are_checked_before_any_lookup() {
        let env = RunEnv {
            user_of: no_lookup,
            ..test_env()
        };
        let (_dir, path) = config(&closed_port_peer(), "");
        let same = ProcessGids::same(1000);
        let mixed = [
            (ProcessUids::same(0), ProcessGids::same(0)),
            (
                ProcessUids {
                    real: 0,
                    effective: 1000,
                    saved: Some(1000),
                },
                same.clone(),
            ),
            (
                ProcessUids {
                    real: 1000,
                    effective: 1000,
                    saved: Some(0),
                },
                same.clone(),
            ),
            (
                ProcessUids {
                    real: 1001,
                    effective: 1000,
                    saved: None,
                },
                same.clone(),
            ),
            (ProcessUids::same(1000), ProcessGids::same(0)),
            (
                ProcessUids::same(1000),
                ProcessGids {
                    real: 0,
                    ..same.clone()
                },
            ),
            (
                ProcessUids::same(1000),
                ProcessGids {
                    real: 1001,
                    ..same.clone()
                },
            ),
        ];
        for (uids, gids) in mixed {
            let process = ProcessIds { uids, gids };
            for args in [
                &["--config", path.as_str(), "--dial-only"][..],
                &["--config", path.as_str(), "--print-peer-id"],
                &["--config", "/nonexistent/m2a-session.toml"],
            ] {
                let mut out = Vec::new();
                assert_eq!(
                    run(argv(args), process.clone(), &mut out, &env),
                    EXIT_REFUSED,
                    "{process:?}"
                );
                assert!(out.is_empty());
            }
        }
    }

    /// The production run (`test_build = false`, what `m2a-session` passes) refuses a `run_as`
    /// other than `m2a-session` before any lookup, in every mode, even inside this test build.
    #[test]
    fn the_production_run_refuses_a_run_as_other_than_the_session_account() {
        let env = RunEnv {
            test_build: false,
            user_of: no_lookup,
            ..test_env()
        };
        let (dir, path) = config(&closed_port_peer(), "run_as = \"test-user\"");
        let _sealed = cl_p2p::testkit::Sealed::new(dir.path());
        for mode in [&["--dial-only"][..], &["--print-peer-id"], &[]] {
            let args: Vec<&str> = ["--config", path.as_str()]
                .into_iter()
                .chain(mode.iter().copied())
                .collect();
            let mut out = Vec::new();
            assert_eq!(
                run(argv(&args), ids(euid()), &mut out, &env),
                EXIT_REFUSED,
                "{mode:?}"
            );
            assert!(out.is_empty());
        }
        // The same config in the test build passes the pre-flight and dials.
        let dial_only = ["--config", path.as_str(), "--dial-only"];
        assert_eq!(run_quiet_test_build(&dial_only, euid()).0, EXIT_FAILED);
    }

    /// The production run accepts a config owned by root only: the test user's is refused.
    #[test]
    fn the_production_run_refuses_a_config_its_user_owns() {
        if euid() == 0 {
            // As root the temp directory is root's: nothing to refuse.
            eprintln!("the_production_run_refuses_a_config_its_user_owns: skipped as root");
            return;
        }
        let env = RunEnv {
            test_build: false,
            config_owner: 0,
            ..test_env()
        };
        let (_dir, path) = config(&closed_port_peer(), "");
        let dial_only = ["--config", path.as_str(), "--dial-only"];
        let mut out = Vec::new();
        assert_eq!(
            run(argv(&dial_only), ids(1000), &mut out, &env),
            EXIT_REFUSED
        );
        assert!(out.is_empty());
        // The test build accepts the test user as the config's owner.
        assert_eq!(run_quiet(&dial_only, 1000).0, EXIT_FAILED);
    }

    /// A process whose effective GID is not the session user's primary GID, or with groups
    /// besides it, is refused before it dials.
    #[test]
    fn a_group_other_than_the_session_users_is_refused() {
        let (_dir, path) = config(&closed_port_peer(), "");
        let dial_only = ["--config", path.as_str(), "--dial-only"];
        let env = test_env();
        for gids in [
            ProcessGids::same(1001),
            ProcessGids {
                groups: vec![1000, 0],
                ..ProcessGids::same(1000)
            },
        ] {
            let process = ProcessIds {
                uids: ProcessUids::same(1000),
                gids,
            };
            let mut out = Vec::new();
            assert_eq!(run(argv(&dial_only), process, &mut out, &env), EXIT_REFUSED);
        }
        // Its own group, as a supplementary group too: it dials (and fails, nothing listens).
        let own = ProcessIds {
            uids: ProcessUids::same(1000),
            gids: ProcessGids {
                groups: vec![1000],
                ..ProcessGids::same(1000)
            },
        };
        assert_eq!(
            run(argv(&dial_only), own, &mut Vec::new(), &env),
            EXIT_FAILED
        );
    }

    /// A config the session's effective UID can write is refused; the same config read-only
    /// passes to the dial.
    #[test]
    fn a_config_the_session_user_can_write_is_refused() {
        let (dir, path) = config(&closed_port_peer(), "run_as = \"test-user\"");
        let _sealed = cl_p2p::testkit::Sealed::new(dir.path());
        let dial_only = ["--config", path.as_str(), "--dial-only"];
        assert_eq!(
            run_quiet_test_build(&dial_only, euid()).0,
            EXIT_FAILED,
            "read-only: dials"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            run_quiet_test_build(&dial_only, euid()),
            (EXIT_REFUSED, String::new())
        );
    }

    /// A login user that is not `run_as` is refused before anything else, in every mode, and
    /// so is a `run_as` the system does not know.
    #[test]
    fn a_user_other_than_run_as_is_refused() {
        let (dir, path) = config(&closed_port_peer(), "");
        let gate = gate_file(&dir, &passing_gate(&fixture_expected()));
        for mode in [&["--gate-file", gate.as_str()][..], &["--dial-only"]] {
            let args: Vec<&str> = ["--config", path.as_str()]
                .into_iter()
                .chain(mode.iter().copied())
                .collect();
            assert_eq!(
                run_quiet(&args, 1001),
                (EXIT_REFUSED, String::new()),
                "{mode:?}"
            );
        }
        let (_dir, unknown) = config(&closed_port_peer(), "run_as = \"no-such-user\"");
        assert_eq!(
            run_quiet(&["--config", &unknown, "--dial-only"], 1000),
            (EXIT_REFUSED, String::new())
        );
    }

    #[test]
    fn failed_dial_exits_1() {
        // Loopback only, to a port nothing listens on: no network contact.
        let (dir, path) = config(&closed_port_peer(), "");
        let gate = gate_file(&dir, &passing_gate(&fixture_expected()));
        let (code, out) = run_quiet(&["--config", &path, "--gate-file", &gate], 1000);
        assert_eq!(code, EXIT_FAILED);
        let lines: Vec<Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let line = &lines[0];
        assert!(
            line["error"].as_str().unwrap().starts_with("connect:"),
            "{line}"
        );
        assert_eq!(line["pass"], false);
        // No other step ran; the summary records it.
        assert_eq!(lines.len(), 2, "{out}");
        assert_eq!(lines[1]["event"], "m2a-summary");
        assert_eq!(lines[1]["pass"], false);
        assert_eq!(lines[1]["exit_code"], 1);
        assert_eq!(lines[1]["checks"]["blocks_by_range"]["pass"], false);
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
        let (keep, path) = config(
            &closed_port_peer(),
            &format!("node_key = \"{key}\"\nrun_as = \"test-user\""),
        );
        // The test user owns the directory: read-only, as the session requires.
        let _sealed = cl_p2p::testkit::Sealed::new(keep.path());
        let (code, out) = run_quiet_test_build(&["--config", &path, "--print-peer-id"], euid());
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
        let (keep, path) = config(
            &closed_port_peer(),
            &format!("node_key = \"{key}\"\nrun_as = \"test-user\""),
        );
        let _sealed = cl_p2p::testkit::Sealed::new(keep.path());
        let print = ["--config", &path, "--print-peer-id"];
        assert_eq!(
            run(argv(&print), ids(euid()), &mut Broken, &test_build_env()),
            EXIT_FAILED
        );
    }

    #[test]
    fn setup_failure_after_the_preflight_writes_the_summary() {
        let (dir, path) = config(&closed_port_peer(), "");
        let gate = gate_file(&dir, &passing_gate(&fixture_expected()));
        let env = RunEnv {
            runtime: || Err(std::io::Error::other("no threads")),
            ..test_env()
        };
        let mut out = Vec::new();
        let args = ["--config", &path, "--gate-file", &gate];
        assert_eq!(run(argv(&args), ids(1000), &mut out, &env), EXIT_FAILED);
        let out = String::from_utf8(out).unwrap();
        let lines: Vec<Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2, "{out}");
        let error = lines[0]["error"].as_str().unwrap();
        assert!(error.contains("tokio runtime: no threads"), "{error}");
        let summary = &lines[1];
        assert_eq!(summary["event"], "m2a-summary");
        assert_eq!(summary["pass"], false);
        assert_eq!(summary["exit_code"], 1);
        let check = |name: &str| summary["checks"][name].clone();
        for step in ["metadata", "ping", "blocks_by_range"] {
            assert_eq!(check(step)["pass"], false, "{step}");
            let detail = check(step)["detail"].as_str().unwrap().to_owned();
            assert!(
                detail.starts_with("not run: ") && detail.contains("no threads"),
                "{step}: {detail}"
            );
        }
        assert_eq!(check("status")["pass"], false);
        // What the pre-flight established still holds.
        for passed in ["fuzz_gate", "own_os_user", "key_handling"] {
            assert_eq!(check(passed)["pass"], true, "{passed}");
        }
        // Dial-only has no summary: it prints nothing either way.
        let mut out = Vec::new();
        let dial_only = ["--config", &path, "--dial-only"];
        assert_eq!(
            run(argv(&dial_only), ids(1000), &mut out, &env),
            EXIT_FAILED
        );
        assert!(out.is_empty());
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
        // The network's caps: without them every column chunk would be refused.
        assert_eq!(
            table.network_caps(),
            Some(&consensus_types::caps::NetworkCaps::from_config(
                &chain.config
            ))
        );
    }

    // The Status probe against a loopback peer and a mock reference API.

    fn root(b: u8) -> Root {
        Root::repeat_byte(b)
    }

    /// The finalized checkpoints of the scenarios, in Gloas (from epoch 353024).
    const F1: (u64, u8) = (353_050, 0xf1);
    const F2: (u64, u8) = (353_051, 0xf2);
    const F3: (u64, u8) = (353_052, 0xf3);
    /// A finalized checkpoint whose 128 slots cross the Fulu/Gloas boundary.
    const FB: (u64, u8) = (353_025, 0xfb);
    /// `GLOAS_FORK_EPOCH` of the pinned Sepolia config.
    const GLOAS_EPOCH: u64 = 353_024;
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
        /// The peer's BlocksByRange answer, instead of its blocks of the requested range.
        blocks: Option<BlocksReply>,
        /// The API's root of these slots (`None`: 404), instead of its blocks'.
        api_roots: Vec<(Slot, Option<Root>)>,
        /// How long the API takes to answer each block-root read of a block.
        root_delay: Duration,
        /// Slots whose block-root read the API answers with HTTP 500.
        root_failures: Vec<Slot>,
        /// Our side's idle connection timeout.
        idle_timeout: Duration,
        /// What `build.rs` recorded about the build.
        build: BuildInfo,
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
                blocks: None,
                api_roots: Vec::new(),
                root_delay: Duration::ZERO,
                root_failures: Vec::new(),
                idle_timeout: IDLE_CONNECTION_TIMEOUT,
                build: BuildInfo::fixture(),
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

        fn blocks_line(&self) -> &Value {
            self.event("m2a-blocks-by-range")
                .expect("a BlocksByRange log line")
        }

        fn blocks_verdict(&self, field: &str) -> bool {
            verdict_of(self.blocks_line(), field)
        }

        fn summary(&self) -> &Value {
            self.event("m2a-summary").expect("a summary line")
        }

        fn check(&self, name: &str) -> bool {
            self.summary()["checks"][name]["pass"]
                .as_bool()
                .unwrap_or_else(|| panic!("no check {name}: {}", self.summary()))
        }
    }

    /// The pinned Sepolia chain, loaded once.
    fn sepolia() -> &'static Chain {
        static CHAIN: OnceLock<Chain> = OnceLock::new();
        CHAIN.get_or_init(|| chain(SessionNetwork::Sepolia).unwrap())
    }

    /// The slots of the scenarios with no block, on both sides.
    fn empty(slot: Slot) -> bool {
        slot % 7 == 3
    }

    /// The block the fixture chain has at `slot`: in the fork of its epoch, distinct per slot.
    fn chain_block(slot: Slot) -> forked::SignedBeaconBlock<Mainnet> {
        if slot / 32 >= GLOAS_EPOCH {
            forked::SignedBeaconBlock::Gloas(p2p_wire::testkit::gloas_block(slot))
        } else {
            forked::SignedBeaconBlock::Fulu(p2p_wire::testkit::fulu_block(slot))
        }
    }

    /// `chain_block(slot)` on the wire: its epoch's digest and its SSZ.
    fn wire_block(slot: Slot) -> (ForkDigest, Vec<u8>) {
        let chain = sepolia();
        let digest = network_config::digest::compute_fork_digest(
            &chain.config,
            &chain.genesis.genesis_validators_root,
            slot / 32,
        )
        .unwrap();
        (digest, chain_block(slot).as_ssz_bytes())
    }

    /// The fixture chain's blocks in `request`'s range.
    fn chain_blocks(request: &BlocksByRangeV2Request) -> BlocksReply {
        let slots = request.start_slot..request.start_slot + request.count;
        BlocksReply::Blocks(slots.filter(|s| !empty(*s)).map(wire_block).collect())
    }

    /// Serves the scenario's BlocksByRange answer, or the chain's blocks of the range.
    fn blocks_responder(reply: Option<BlocksReply>) -> BlocksResponder {
        Box::new(move |req, _| reply.clone().unwrap_or_else(|| chain_blocks(req)))
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
        for (epoch, r) in [F1, F2, F3, FB] {
            routes.push((
                format!("/eth/v1/beacon/headers/{}", root(r)),
                Route::json(MockApi::header_json(root(r), finalized_slot(epoch), true)),
            ));
            // The block roots of the 128 slots up to the finalized slot; empty slots are 404.
            let last = finalized_slot(epoch);
            for slot in (last - 127..=last).filter(|s| !empty(*s)) {
                let r = blocks::block_root(&chain_block(slot));
                routes.push((
                    format!("/eth/v1/beacon/blocks/{slot}/root"),
                    Route::json(MockApi::block_root_json(r)).delayed(s.root_delay),
                ));
            }
        }
        for slot in &s.root_failures {
            routes.push((
                format!("/eth/v1/beacon/blocks/{slot}/root"),
                Route::status(500),
            ));
        }
        for (slot, r) in &s.api_roots {
            let route = r.map_or_else(
                || Route::status(404),
                |r| Route::json(MockApi::block_root_json(r)),
            );
            routes.push((format!("/eth/v1/beacon/blocks/{slot}/root"), route));
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
        let peer = StatusPeer::spawn_with_blocks(
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
            Some(blocks_responder(s.blocks.clone())),
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
            idle_timeout: s.idle_timeout,
            build: s.build.clone(),
            ..test_env()
        };
        let (code, out) = tokio::task::spawn_blocking(move || {
            std::thread::spawn(move || {
                let _dir = dir;
                let mut out = Vec::new();
                let args = ["--config", &path, "--gate-file", &gate];
                let code = run(argv(&args), ids(1000), &mut out, &env);
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
        assert!(
            lines.len() <= 5,
            "one JSON line per step and the summary at most: {out}"
        );
        // A refused run prints nothing; any other ends with the summary.
        if let Some(summary) = lines.last() {
            assert_eq!(
                summary["event"], "m2a-summary",
                "the summary comes last: {out}"
            );
            assert_eq!(
                summary["exit_code"],
                u8::from(code != EXIT_CONNECTED),
                "{out}"
            );
        }
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
        let eas = finalized_slot(F1.0) - 100;
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
        assert_eq!(out.peer.wait_connections(1).await, 1);
        assert_eq!(out.api.hits(FINALITY_PATH), 2, "sampled before and after");
        assert_eq!(out.lines.len(), 5, "one line per step and the summary");
        let events: Vec<&Value> = out.lines.iter().map(|l| &l["event"]).collect();
        assert_eq!(
            events,
            [
                "m2a-status",
                "m2a-metadata",
                "m2a-ping",
                "m2a-blocks-by-range",
                "m2a-summary"
            ]
        );
        // One BlocksByRange, from the peer's earliest_available_slot to the finalized slot,
        // on the same connection.
        let request = BlocksByRangeV2Request {
            start_slot: eas,
            count: 101,
            step: 1,
        };
        assert_eq!(out.peer.blocks_requests(), vec![request]);
        assert_eq!(out.blocks_line()["pass"], true);
        for field in blocks::FIELDS {
            assert!(out.blocks_verdict(field), "{field}: {}", out.blocks_line());
        }
        assert_eq!(out.summary()["pass"], true);
        for check in summary::CHECKS {
            assert!(out.check(check), "{check}: {}", out.summary());
        }
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
        assert_eq!(
            out.summary()["checks"]["ping"]["detail"],
            "not run (see m2a-metadata)"
        );
        // The connection check still ran, on the same connection.
        assert_eq!(out.line()["pass"], true);
        assert!(out.verdict("connection"));
        assert_eq!(out.peer.wait_connections(1).await, 1);
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
        assert_eq!(out.peer.wait_connections(1).await, 1);

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
    async fn ping_refetch_identity_resample_failure_names_the_resample() {
        // The re-fetch succeeds, but the identity sampled after it is malformed.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        let body = |m: &MetaDataV3| MockApi::identity_json(s.enr, m);
        let bad = body(&md(8)).replace("0x0100000000000080", "0x01");
        s.identity_bodies = Some(vec![body(&md(7)), body(&md(7)), body(&md(7)), bad]);
        s.metadata = vec![
            MetaDataReply::MetaData(md(7)),
            MetaDataReply::MetaData(md(8)),
        ];
        s.ping = vec![PingReply::Ping(8)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let line = out.ping_line();
        let error = line["error"].as_str().unwrap();
        assert!(
            error.starts_with("identity re-sample: ") && error.contains("attnets"),
            "{error}"
        );
        assert!(!error.contains("MetaData sample"), "{error}");
        assert_eq!(line["refetched"]["peer"]["seq_number"], "8");
        assert_eq!(line["refetched"]["api"], Value::Null);
        assert_eq!(out.api.hits(IDENTITY_PATH), 4);
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
        assert_eq!(out.peer.wait_connections(1).await, 1);
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
            let out = probe(Scenario::new(peer_status(F1, off, finalized_slot(F1.0)))).await;
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
        assert_eq!(out.line()["pass"], true, "{}", out.line());
        assert!(out.verdict("earliest_available_slot"));
        // Its earliest_available_slot is after its finalized slot: it serves no finalized
        // block, so the BlocksByRange precondition fails without a request.
        assert_eq!(out.code, EXIT_FAILED);
        assert!(!out.blocks_verdict("request"));
        assert!(out.peer.blocks_requests().is_empty());
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
        // Answers the Status, the MetaData, the Ping and the BlocksByRange, then closes the
        // connection.
        s.disconnect_after = Some(4);
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
        let peer = StatusPeer::spawn_with_blocks(
            Box::new(move |_, n| StatusReply::Status(statuses[n.min(1)].clone())),
            Some(Box::new(move |_| metadata.clone())),
            Some(Box::new(move |_, _| ping.clone())),
            Some(blocks_responder(None)),
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
                let code = run(all.into_iter(), ids(1000), &mut out, &env);
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
        let dir = tempfile::Builder::new()
            .tempdir_in(cl_p2p::testkit::config_root())
            .unwrap();
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
        assert_eq!(peer.wait_connections(1).await, 1);
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

    /// The probe refuses to dial with a build that was not clean (an ignored file in a build
    /// crate, say, or no build commit): the session would only fail its `clean_build` check
    /// at the end. The pre-check `--dial-only` gives no evidence, and still dials.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unclean_build_is_refused_before_the_probe() {
        for build in [
            BuildInfo::from_build(
                crate::build_info::FIXTURE_COMMIT,
                "uncommitted changes in the build tree: not in HEAD: crates/cl-p2p/a.profraw",
            ),
            BuildInfo::from_build(
                crate::build_info::FIXTURE_COMMIT,
                "built with RUSTFLAGS set",
            ),
            BuildInfo::from_build("", ""),
        ] {
            let mut s = Scenario::new(peer_status(F1, 0, 0));
            s.build = build.clone();
            let out = probe(s).await;
            assert_eq!(out.code, EXIT_REFUSED, "{build:?}");
            assert!(out.lines.is_empty(), "refused before the session");
            assert_eq!(out.peer.connections(), 0, "refused before dialling");
            assert!(out.api.seen().is_empty(), "and before the API");
        }
        let peer = StatusPeer::echoing(peer_status(F1, 0, 0)).await;
        let (_dir, path) = config_without_api(&format!("{}/p2p/{}", peer.addr, peer.id));
        let env = RunEnv {
            build: BuildInfo::from_build("", ""),
            ..test_env()
        };
        let (code, _) = run_off_runtime(path, vec!["--dial-only".into()], env).await;
        assert_eq!(code, EXIT_CONNECTED);
        assert_eq!(peer.wait_connections(1).await, 1);
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
                run(argv(&args), ids(1000), &mut Vec::new(), &test_env())
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
                run(argv(&args), ids(1000), &mut Vec::new(), &env)
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

    // The BlocksByRange step.

    #[test]
    fn start_slot_respects_eas() {
        let last = finalized_slot(F1.0);
        // (earliest_available_slot, start_slot, count)
        for (eas, start, count) in [
            (0, last - 127, 128),
            (last - 127, last - 127, 128),
            (last - 128, last - 127, 128),
            (last - 10, last - 10, 11),
            (last, last, 1),
        ] {
            let r = blocks::range(F1.0, eas, 32).unwrap();
            assert_eq!(
                r,
                BlocksByRangeV2Request {
                    start_slot: start,
                    count,
                    step: 1
                },
                "eas {eas}"
            );
            assert!(r.start_slot >= eas);
            assert!(r.count <= MAX_REQUEST_BLOCKS_DENEB);
            assert_eq!(
                r.start_slot + r.count - 1,
                last,
                "ends at the finalized slot"
            );
        }
        // Fewer than 128 slots since genesis: no underflow.
        for (epoch, count) in [(0, 1), (1, 33), (3, 97), (4, 128)] {
            let r = blocks::range(epoch, 0, 32).unwrap();
            assert_eq!(r.start_slot + r.count - 1, epoch * 32);
            assert_eq!(r.count, count, "epoch {epoch}");
        }
    }

    #[test]
    fn eas_after_finalized_fails_precondition() {
        let last = finalized_slot(F1.0);
        let err = blocks::range(F1.0, last + 1, 32).unwrap_err();
        assert!(
            err.contains("precondition") && err.contains("earliest_available_slot"),
            "{err}"
        );
        assert!(blocks::range(u64::MAX, 0, 32).is_err(), "no slot in u64");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn eas_after_finalized_sends_no_request() {
        let out = probe(Scenario::new(peer_status(F1, 0, finalized_slot(F1.0) + 1))).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert_eq!(out.line()["pass"], true, "the Status step itself passed");
        let line = out.blocks_line();
        assert_eq!(line["request"], Value::Null);
        let detail = line["verdicts"]["request"]["detail"].as_str().unwrap();
        assert!(detail.contains("precondition"), "{detail}");
        assert!(out.peer.blocks_requests().is_empty(), "no request");
        assert!(!out.check("blocks_by_range") && !out.check("blocks_dropped"));
        // The connection check still ran.
        assert!(out.verdict("connection"));
    }

    #[test]
    fn root_compare() {
        let r = |b: u8| Some(root(b));
        let request = BlocksByRangeV2Request {
            start_slot: 100,
            count: 6,
            step: 1,
        };
        // Slots 101 and 104 are empty.
        let api: BTreeMap<Slot, Option<Root>> = [
            (100, r(1)),
            (101, None),
            (102, r(2)),
            (103, r(3)),
            (104, None),
            (105, r(5)),
        ]
        .into();
        let all = vec![
            (100, root(1)),
            (102, root(2)),
            (103, root(3)),
            (105, root(5)),
        ];
        // (a) Every block matches, and every empty slot is empty on both sides.
        assert_eq!(blocks::compare(&request, &all, &api), []);

        let kinds = |peer: &[(Slot, Root)]| -> Vec<(Slot, blocks::MismatchKind)> {
            blocks::compare(&request, peer, &api)
                .iter()
                .map(|m| (m.slot, m.kind))
                .collect()
        };
        use blocks::MismatchKind::{BlockForEmptySlot, MissingBlock, NoApiAnswer, RootDiffers};
        // (b) One root differs.
        let mut b = all.clone();
        b[2].1 = root(9);
        assert_eq!(kinds(&b), [(103, RootDiffers)]);
        let m = blocks::compare(&request, &b, &api)[0];
        assert_eq!((m.peer, m.api), (r(9), r(3)));
        // (c) A block for a slot the API calls empty.
        let mut c = all.clone();
        c.insert(1, (101, root(7)));
        assert_eq!(kinds(&c), [(101, BlockForEmptySlot)]);
        // (d) No block for a slot the API has.
        assert_eq!(kinds(&all[..3]), [(105, MissingBlock)]);
        // As many blocks as the API has, at the wrong slots: a count-only match fails.
        let shifted = vec![
            (100, root(1)),
            (101, root(2)),
            (102, root(3)),
            (105, root(5)),
        ];
        assert_eq!(
            kinds(&shifted),
            [
                (101, BlockForEmptySlot),
                (102, RootDiffers),
                (103, MissingBlock)
            ]
        );
        // A slot the API was not asked about never passes.
        let mut partial = api.clone();
        partial.remove(&104);
        assert_eq!(
            blocks::compare(&request, &all, &partial)
                .iter()
                .map(|m| (m.slot, m.kind))
                .collect::<Vec<_>>(),
            [(104, NoApiAnswer)]
        );
    }

    #[test]
    fn block_root_is_the_message_root() {
        use tree_hash::TreeHash;
        let gloas = p2p_wire::testkit::gloas_block::<Mainnet>(5);
        let block = forked::SignedBeaconBlock::Gloas(gloas.clone());
        assert_eq!(blocks::block_root(&block), gloas.message.tree_hash_root());
        assert_ne!(
            blocks::block_root(&block),
            block.tree_hash_root(),
            "not the signed block's"
        );
        let fulu = p2p_wire::testkit::fulu_block::<Mainnet>(5);
        let block = forked::SignedBeaconBlock::Fulu(fulu.clone());
        assert_eq!(blocks::block_root(&block), fulu.message.tree_hash_root());
        let roots = blocks::hash_and_drop(vec![chain_block(1), chain_block(2)]);
        assert_eq!(roots.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [1, 2]);
        assert_ne!(roots[0].1, roots[1].1);
    }

    /// A block that counts its drops.
    struct Counted {
        slot: Slot,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl blocks::Rooted for Counted {
        fn slot(&self) -> Slot {
            self.slot
        }
        fn root(&self) -> Root {
            root(self.slot as u8)
        }
    }

    /// The "dropped" half of the evidence: `hash_and_drop`, which the step hands every block
    /// it receives, has dropped each one by the time it returns their roots. The "nothing
    /// stored" half is `scripts/check-m2a-deps.sh`: the binary links no store crate.
    #[test]
    fn hash_and_drop_drops_every_block() {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let blocks: Vec<Counted> = [3, 5, 8]
            .map(|slot| Counted {
                slot,
                drops: Arc::clone(&drops),
            })
            .into();
        let roots = blocks::hash_and_drop(blocks);
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(roots, [(3, root(3)), (5, root(5)), (8, root(8))]);
        assert_eq!(Arc::strong_count(&drops), 1, "no block is left anywhere");
    }

    /// The session-level half: the step's line keeps a slot and a root per block and nothing
    /// else ([`hash_and_drop_drops_every_block`] proves the drop itself).
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_are_dropped_after_comparison() {
        let out = probe(Scenario::new(peer_status(F1, 0, 0))).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.blocks_line());
        let line = out.blocks_line();
        let last = finalized_slot(F1.0);
        assert_eq!(line["request"]["start_slot"], (last - 127).to_string());
        assert_eq!(line["request"]["count"], "128");
        assert_eq!(line["request"]["step"], "1");
        assert_eq!(line["finalized_slot"], last.to_string());
        let served = (last - 127..=last).filter(|s| !empty(*s)).count();
        assert_eq!(line["blocks_dropped"], served);
        assert_eq!(line["api_slots_checked"], 128);
        assert_eq!(line["api_blocks"], served);
        // The step keeps a slot and a root per block, nothing of the block itself.
        let kept = line["blocks"].as_array().unwrap();
        assert_eq!(kept.len(), served);
        for b in kept {
            let mut keys: Vec<&String> = b.as_object().unwrap().keys().collect();
            keys.sort();
            assert_eq!(keys, ["root", "slot"], "{b}");
        }
        assert_eq!(line["mismatches"], serde_json::json!([]));
        assert!(out.check("blocks_dropped") && out.check("decode_limits"));
        // Every slot of the range was asked of the API, once.
        for slot in last - 127..=last {
            assert_eq!(
                out.api.hits(&format!("/eth/v1/beacon/blocks/{slot}/root")),
                1
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn slow_api_reads_do_not_idle_out_the_connection() {
        // Each block-root read takes 40 ms: one after another, the ~110 reads take over 4 s, far
        // past our 1 s idle timeout. The peer is correct, so the connection check must pass.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.root_delay = Duration::from_millis(40);
        s.idle_timeout = Duration::from_secs(1);
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.summary());
        assert!(out.verdict("connection"), "{}", out.line());
        assert!(out.blocks_verdict("roots"), "{}", out.blocks_line());
        assert_eq!(out.peer.wait_connections(1).await, 1);
        assert_eq!(
            out.peer.requests().len(),
            2,
            "the second Status reached the peer"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_root_failure_sends_no_blocks_request() {
        // The API's roots are read before the request: a failed read stops the step first.
        let last = finalized_slot(F1.0);
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.root_failures = vec![last - 5];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let line = out.blocks_line();
        let error = line["error"].as_str().unwrap();
        assert!(
            error.contains(&format!("/eth/v1/beacon/blocks/{}/root", last - 5))
                && error.contains("500"),
            "{error}"
        );
        assert!(out.peer.blocks_requests().is_empty(), "no request");
        assert!(out.blocks_verdict("request"));
        assert!(out.verdict("connection"), "the connection check still ran");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn root_mismatch_fails_the_session() {
        let last = finalized_slot(F1.0);
        // (b) One root differs at the API; (c) the API calls a served slot empty; (d) the API
        // has a block at a slot the peer leaves empty.
        let differs = last - 1;
        let called_empty = last - 2;
        let unserved = (last - 127..=last).find(|s| empty(*s)).unwrap();
        for (slot, api, kind) in [
            (differs, Some(root(0x99)), "root differs"),
            (called_empty, None, "a block for a slot the API calls empty"),
            (
                unserved,
                Some(root(0x98)),
                "no block for a slot the API has",
            ),
        ] {
            assert!(!empty(differs) && !empty(called_empty));
            let mut s = Scenario::new(peer_status(F1, 0, 0));
            s.api_roots = vec![(slot, api)];
            let out = probe(s).await;
            assert_eq!(out.code, EXIT_FAILED, "{kind}");
            assert!(out.blocks_verdict("request"));
            assert!(!out.blocks_verdict("roots"), "{kind}");
            let mismatches = out.blocks_line()["mismatches"].as_array().unwrap().clone();
            assert_eq!(mismatches.len(), 1, "{kind}: {mismatches:?}");
            assert_eq!(mismatches[0]["slot"], slot.to_string());
            assert_eq!(mismatches[0]["kind"], kind);
            assert!(!out.check("blocks_by_range"));
            for check in [
                "status",
                "metadata",
                "ping",
                "blocks_dropped",
                "decode_limits",
            ] {
                assert!(out.check(check), "{kind}: {check}");
            }
            assert_eq!(out.summary()["exit_code"], 1);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn range_across_the_gloas_fork_passes() {
        // Epochs 353021..=353025: Fulu blocks under the BPO digest of their epoch, then Gloas
        // blocks under the Gloas digest, each chunk decoded in its own fork.
        let mut s = Scenario::new(peer_status(FB, 0, 0));
        s.finality = vec![FB];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_CONNECTED, "{}", out.blocks_line());
        let first = finalized_slot(FB.0) - 127;
        assert!(first / 32 < GLOAS_EPOCH);
        assert_eq!(
            out.blocks_line()["request"]["start_slot"],
            first.to_string()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_request_failure_fails_the_step_only() {
        // The peer serves a block under the wrong digest: the response is refused whole.
        let last = finalized_slot(F1.0);
        let (_, ssz) = wire_block(last);
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.blocks = Some(BlocksReply::Blocks(vec![([0x7e, 0x0d, 0x34, 0x47], ssz)]));
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let line = out.blocks_line();
        let error = line["error"].as_str().unwrap();
        assert!(error.starts_with("blocks_by_range:"), "{error}");
        assert_eq!(line["blocks"], Value::Null);
        assert!(!out.check("blocks_by_range") && !out.check("blocks_dropped"));
        assert!(out.check("status") && out.check("ping"));
        assert!(out.verdict("connection"), "the connection check still ran");
        // An error chunk.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.blocks = Some(BlocksReply::Error(
            ResultCode::ResourceUnavailable,
            b"pruned".to_vec(),
        ));
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        let error = out.blocks_line()["error"].as_str().unwrap();
        assert!(error.contains("pruned"), "{error}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn summary_line_format() {
        let out = probe(Scenario::new(peer_status(F1, 0, 0))).await;
        assert_eq!(out.code, EXIT_CONNECTED);
        let line = out.summary();
        assert_eq!(line["event"], "m2a-summary");
        assert_eq!(line["pass"], true);
        assert_eq!(line["exit_code"], 0);
        assert_eq!(line["peer_id"], out.peer.id.to_string());
        assert_eq!(line["consensus_specs"], "v1.7.0-beta.4");
        let started = line["started_at_ms"].as_u64().unwrap();
        let ended = line["ended_at_ms"].as_u64().unwrap();
        assert_eq!(u128::from(started), WALL_MS);
        assert!(ended > started, "{line}");
        let checks = line["checks"].as_object().unwrap();
        let names: Vec<&str> = checks.keys().map(String::as_str).collect();
        let mut want = summary::CHECKS.to_vec();
        want.sort_unstable();
        let mut names_sorted = names.clone();
        names_sorted.sort_unstable();
        assert_eq!(names_sorted, want);
        for (name, v) in checks {
            assert_eq!(v["pass"], true, "{name}: {v}");
            assert!(v["detail"].is_string(), "{name}: {v}");
        }
        let detail = |name: &str| line["checks"][name]["detail"].as_str().unwrap().to_owned();
        assert!(detail("own_os_user").contains("1000"));
        assert!(detail("own_os_user").contains("\"m2a-session\""));
        assert_eq!(line["os_user"], "m2a-session");
        assert_eq!(line["euid"], 1000);
        assert_eq!(line["test_build"], false);
        assert!(detail("production_build").contains("m2a-session"));
        assert_eq!(line["build_commit"], crate::build_info::FIXTURE_COMMIT);
        assert_eq!(line["build_dirty"], false);
        assert!(detail("clean_build").contains(crate::build_info::FIXTURE_COMMIT));
        assert!(detail("key_handling").contains("ephemeral"));
        assert_eq!(
            detail("pinned_peer_only"),
            "connected to 1 peer(s), 0 not pinned; 0 listen address(es)"
        );
        assert!(detail("fuzz_gate").contains("m2a-gate.json"));
        assert!(!line.to_string().contains('\n'));
        // Any failed step fails the summary and the exit code.
        let mut s = Scenario::new(peer_status(F1, 0, 0));
        s.ping = vec![PingReply::Ping(6)];
        let out = probe(s).await;
        assert_eq!(out.code, EXIT_FAILED);
        assert_eq!(out.summary()["pass"], false);
        assert_eq!(out.summary()["exit_code"], 1);
        assert!(!out.check("ping"));
        assert!(out.check("blocks_by_range") && out.check("metadata"));
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
                (run(argv(&args), ids(1000), &mut out, &test_env()), out)
            })
            .join()
            .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(code, EXIT_FAILED);
        let out = String::from_utf8(out).unwrap();
        let line: Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
        assert_eq!(line["verdicts"]["genesis"]["pass"], false);
        assert!(line["error"].as_str().unwrap().contains("genesis"));
        assert!(peer.requests().is_empty(), "no Status sent");
        drop(dir);
    }
}
