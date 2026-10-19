//! `devnet-probe`: the probe's discovery, transport, Status and range checks against the
//! reference CLs of a local Kurtosis devnet.
//!
//! ```text
//! devnet-probe <discover|connect|status|fetch-epoch|all>
//!              (--network-dir DIR | --config PATH [--genesis PATH])
//!              [--api URL]... [--peer MULTIADDR]... [--enr ENR]... [--bootnode ENR]...
//!              [--discv5-listen IP:PORT] [--discover-secs N] [--connect-secs N]
//!              [--status-secs N] [--hold-secs N] [--ping-secs N] [--fetch-secs N] [--epoch N]
//! devnet-probe --help
//! ```
//!
//! Each check prints one `PASS` or `FAIL` line per thing it judged and a summary line, and the
//! run ends with one `verdict:` line (`devnet_probe::report`). The checks are in
//! `devnet_probe`: `discover`, `connect`, `status` and `fetch-epoch`; `all` runs the
//! four in that order. A `setup` check runs first: the config parses, and the genesis (from the
//! genesis state and every `--api`) is one, and for the checks that dial, every `--api`'s node
//! is one of the `--peer`s.
//!
//! Exit codes: 0 every check passed, 1 a check failed, 2 usage (an `--api` node no `--peer`
//! names included), 3 diagnostic: every check passed, but `status` held less than
//! [`status::ACCEPTANCE_HOLD`], so it printed `DIAGNOSTIC` instead of `PASS`.
//!
//! A recorded deviation (a `connect` peer on mplex, which offers no yamux) is still a pass and
//! exits 0, but the check's summary and the verdict name it:
//! `verdict: PASS (2/2 checks; 1 recorded deviation: connect mplex)`.
//!
//! The report lines go to stdout. Logs are svc-runtime's JSON lines on stderr, at INFO,
//! through its bounded writer, and a usage error's plain text goes through the same queue: a
//! stderr nobody reads drops lines instead of blocking the probe, and every exit waits for the
//! queue at most [`LOG_FLUSH_DEADLINE`]. If that writer cannot start, the probe exits at once
//! with [`EXIT_NO_LOG_WRITER`](svc_runtime::telemetry::EXIT_NO_LOG_WRITER) (71), writing
//! nothing.

use cl_discv5::enr::{Enr, EnrFields};
use cl_p2p::m2a_session::PinnedPeer;
use consensus_types::{EthSpec, Mainnet, Minimal};
use devnet_probe::api::{ProbeApi, DEFAULT_API_TIMEOUT};
use devnet_probe::connect::{self, ConnectPlan};
use devnet_probe::devnet::{is_devnet_ip, parse_peer, read_config, read_genesis, Devnet, Preset};
use devnet_probe::discover::{self, DiscoverPlan};
use devnet_probe::fetch::{self, FetchPlan};
use devnet_probe::ours::{Clock, DEFAULT_REFRESH_INTERVAL};
use devnet_probe::report::{verdict, Check, Outcome};
use devnet_probe::status::{self, StatusPlan};
use libp2p::PeerId;
use network_config::{Epoch, Genesis};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
use svc_runtime::telemetry::{flush_logs, init_binary_tracing, queue_stderr};
use testkit::collector::ReferenceApiUrl;
use tracing::level_filters::LevelFilter;

const USAGE: &str = "\
usage: devnet-probe <discover|connect|status|fetch-epoch|all>
                    (--network-dir DIR | --config PATH [--genesis PATH])
                    [--api URL]... [--peer MULTIADDR]... [--enr ENR]... [--bootnode ENR]...
                    [--discv5-listen IP:PORT] [--discover-secs N] [--connect-secs N]
                    [--status-secs N] [--hold-secs N] [--ping-secs N] [--fetch-secs N]
                    [--epoch N]
       devnet-probe --help";
const HELP: &str = "\
Check our probe against the reference CLs of a local devnet. Every address must be local
(loopback, private, link-local, CGNAT, IPv6 unique-local): the probe talks to a local devnet
only.

  discover      our discv5 (local mode: it queries local addresses only), seeded with
                --bootnode, must find every reference CL's record (--enr, and the ENR of
                every --api's /eth/v1/node/identity)
  connect       each --peer: TCP, Noise XX (the peer ID) and the muxer, which must be yamux
                (mplex passes, as a recorded deviation, for a peer that refuses yamux and
                then answers our identify over mplex)
  status        each --peer: our Status v2 answered, its Status answered, then the
                connection held --hold-secs with a Ping every --ping-secs and no Goodbye
  fetch-epoch   a finalized epoch by BlocksByRange v2 from the --peers; every slot's root
                must equal the first --api's /eth/v1/beacon/blocks/{slot}/root (404: empty)
  all           the four, in that order

  --network-dir DIR      the devnet's genesis data: DIR/config.yaml and DIR/genesis.ssz
  --config PATH          the devnet's config.yaml (PRESET_BASE picks the preset)
  --genesis PATH         the genesis state (genesis.ssz): genesis time and validators root
  --api URL              a reference CL's beacon API, http:// to a loopback host; repeatable.
                         The first is the reference: our Status, finality and the roots.
                         For connect, status and fetch-epoch, every --api's node must be
                         one of the --peers (exit 2 otherwise)
  --peer MULTIADDR       a reference CL, /ip4/<ip>/tcp/<port>/p2p/<peer id>; repeatable
  --enr ENR              a reference CL's record (enr:...), to be found; repeatable
  --bootnode ENR         a record our discv5 starts from; repeatable
  --discv5-listen IP:PORT  our discv5 UDP address (default 0.0.0.0:9000)
  --discover-secs N      how long discover looks (default 60)
  --connect-secs N       how long each connect dial may take (default 30)
  --status-secs N        how long the peers have to answer our Status (default 30)
  --hold-secs N          how long status holds each connection (default 600); under 600
                         the status check is diagnostic only, never an acceptance pass
  --ping-secs N          our Ping cadence while holding (default 15)
  --fetch-secs N         how long fetch-epoch's range fetch may take (default 120)
  --epoch N              the epoch fetch-epoch fetches (default: finalized epoch - 1)

Every -secs flag takes 1 to 86400.

Exit codes: 0 every check passed (an acceptance pass), 1 a check failed, 2 usage (including an
--api node no --peer names), 3 diagnostic: every check passed but one ran outside the
acceptance rules (a hold under 600 s), so it prints DIAGNOSTIC, never PASS.

A recorded deviation (connect mplex) is still a pass, with exit 0, but the verdict names every
recorded deviation, as each check's summary does:
  verdict: PASS (2/2 checks; 1 recorded deviation: connect mplex)";

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
/// Every check passed, but one ran outside the acceptance rules (a hold under
/// [`status::ACCEPTANCE_HOLD`]): never an acceptance pass.
const EXIT_DIAGNOSTIC: u8 = 3;

/// Which checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Discover,
    Connect,
    Status,
    FetchEpoch,
    All,
}

impl Command {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "discover" => Self::Discover,
            "connect" => Self::Connect,
            "status" => Self::Status,
            "fetch-epoch" => Self::FetchEpoch,
            "all" => Self::All,
            _ => return None,
        })
    }

    fn runs(self, check: Self) -> bool {
        self == check || self == Self::All
    }

    /// Whether it dials the `--peer`s.
    fn dials(self) -> bool {
        [Self::Connect, Self::Status, Self::FetchEpoch]
            .into_iter()
            .any(|c| self.runs(c))
    }
}

/// A parsed command line.
#[derive(Debug, PartialEq)]
enum Parsed {
    Help,
    Run(Box<Args>),
}

#[derive(Debug, PartialEq)]
struct Args {
    command: Command,
    config: PathBuf,
    genesis: Option<PathBuf>,
    apis: Vec<ReferenceApiUrl>,
    peers: Vec<PinnedPeer>,
    enrs: Vec<Enr>,
    bootnodes: Vec<Enr>,
    discv5_listen: SocketAddr,
    discover: Duration,
    connect: Duration,
    status_deadline: Duration,
    hold: Duration,
    ping: Duration,
    fetch: Duration,
    epoch: Option<Epoch>,
}

/// The error for an argument the probe does not take: only a flag's key is named, never a
/// value, which may be a URL with a key in it.
fn unknown_argument(arg: &str) -> String {
    let key = arg.split_once('=').map_or(arg, |(key, _)| key);
    let flag_like = key.len() <= 32
        && key.strip_prefix("--").is_some_and(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if flag_like {
        format!("unknown argument {key} (a flag and its value are two arguments)")
    } else {
        "unknown argument (not shown: it may hold a URL)".into()
    }
}

/// The longest duration a flag takes: one day.
const MAX_SECONDS: u64 = 86_400;

fn seconds(flag: &str, value: &str) -> Result<Duration, String> {
    let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    match digits.then(|| value.parse::<u64>().ok()).flatten() {
        None => Err(format!("{flag}: not a number")),
        Some(0) => Err(format!("{flag} must be at least 1")),
        Some(s) if s > MAX_SECONDS => Err(format!("{flag} must be at most {MAX_SECONDS}")),
        Some(s) => Ok(Duration::from_secs(s)),
    }
}

/// A record given on the command line: `enr:` text with a secp256k1 key and an `eth2` field.
fn parse_enr(flag: &str, text: &str) -> Result<Enr, String> {
    let enr: Enr = text
        .parse()
        .map_err(|e: String| format!("{flag}: not a node record: {e}"))?;
    EnrFields::read(&enr).map_err(|e| format!("{flag}: {e}"))?;
    Ok(enr)
}

/// A bootnode: a record at local addresses only ([`is_devnet_ip`]).
fn parse_bootnode(text: &str) -> Result<Enr, String> {
    let enr = parse_enr("--bootnode", text)?;
    let ips: Vec<IpAddr> = enr
        .ip4()
        .map(IpAddr::V4)
        .into_iter()
        .chain(enr.ip6().map(IpAddr::V6))
        .collect();
    if ips.is_empty() || !ips.iter().all(|ip| is_devnet_ip(*ip)) {
        return Err(format!(
            "--bootnode {}: not at a local address (loopback, private, link-local, CGNAT, IPv6 \
             unique-local): the probe talks to a local devnet only",
            devnet_probe::api::hex0x(&enr.node_id().raw())
        ));
    }
    Ok(enr)
}

fn parse(argv: &[String]) -> Result<Parsed, String> {
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Parsed::Help);
    }
    let command = match argv.first() {
        None => return Err("no command".into()),
        Some(c) => Command::parse(c).ok_or_else(|| {
            "unknown command (want discover, connect, status, fetch-epoch or all)".to_owned()
        })?,
    };
    let (mut network_dir, mut config, mut genesis) = (None, None, None);
    let mut args = Args {
        command,
        config: PathBuf::new(),
        genesis: None,
        apis: Vec::new(),
        peers: Vec::new(),
        enrs: Vec::new(),
        bootnodes: Vec::new(),
        discv5_listen: discover::DEFAULT_LISTEN,
        discover: discover::DEFAULT_DEADLINE,
        connect: connect::DEFAULT_TIMEOUT,
        status_deadline: status::DEFAULT_STATUS_DEADLINE,
        hold: status::DEFAULT_HOLD,
        ping: status::DEFAULT_PING_INTERVAL,
        fetch: fetch::DEFAULT_FETCH_TIMEOUT,
        epoch: None,
    };
    let mut it = argv[1..].iter();
    while let Some(flag) = it.next() {
        if !flag.starts_with("--") {
            return Err(unknown_argument(flag));
        }
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))
            .map(String::as_str);
        match flag.as_str() {
            "--network-dir" => network_dir = Some(PathBuf::from(value?)),
            "--config" => config = Some(PathBuf::from(value?)),
            "--genesis" => genesis = Some(PathBuf::from(value?)),
            "--api" => args
                .apis
                .push(ReferenceApiUrl::parse(value?).map_err(|e| format!("--api: {e}"))?),
            "--peer" => args
                .peers
                .push(parse_peer(value?).map_err(|e| format!("--peer: {e}"))?),
            "--enr" => args.enrs.push(parse_enr("--enr", value?)?),
            "--bootnode" => args.bootnodes.push(parse_bootnode(value?)?),
            "--discv5-listen" => {
                args.discv5_listen = value?
                    .parse()
                    .map_err(|_| "--discv5-listen: want IP:PORT".to_owned())?;
            }
            "--discover-secs" => args.discover = seconds(flag, value?)?,
            "--connect-secs" => args.connect = seconds(flag, value?)?,
            "--status-secs" => args.status_deadline = seconds(flag, value?)?,
            "--hold-secs" => args.hold = seconds(flag, value?)?,
            "--ping-secs" => args.ping = seconds(flag, value?)?,
            "--fetch-secs" => args.fetch = seconds(flag, value?)?,
            "--epoch" => {
                let v = value?;
                let epoch = v
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| v.parse().ok())
                    .flatten()
                    .ok_or("--epoch: not a number")?;
                args.epoch = Some(epoch);
            }
            other => return Err(unknown_argument(other)),
        }
    }
    match (network_dir, config) {
        (Some(_), Some(_)) => return Err("give --network-dir or --config, not both".into()),
        (Some(dir), None) => {
            args.config = dir.join("config.yaml");
            args.genesis = Some(genesis.unwrap_or_else(|| dir.join("genesis.ssz")));
        }
        (None, Some(path)) => {
            args.config = path;
            args.genesis = genesis;
        }
        (None, None) => return Err("give --config or --network-dir".into()),
    }
    if args.genesis.is_none() && args.apis.is_empty() {
        return Err("the genesis comes from --genesis or --api: give one".into());
    }
    let cmd = args.command;
    if cmd.runs(Command::Discover) {
        if args.bootnodes.is_empty() {
            return Err("discover needs --bootnode".into());
        }
        if args.enrs.is_empty() && args.apis.is_empty() {
            return Err("discover needs the records to find: --enr or --api".into());
        }
    }
    let wants_peers = [Command::Connect, Command::Status, Command::FetchEpoch];
    if wants_peers.iter().any(|c| cmd.runs(*c)) && args.peers.is_empty() {
        return Err("connect, status and fetch-epoch need --peer".into());
    }
    if (cmd.runs(Command::Status) || cmd.runs(Command::FetchEpoch)) && args.apis.is_empty() {
        return Err("status and fetch-epoch need the reference --api".into());
    }
    Ok(Parsed::Run(Box::new(args)))
}

/// Unix milliseconds of the system clock.
fn system_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// The `setup` check: the devnet from the config and the one genesis every source names.
async fn setup(args: &Args) -> (Check, Option<Devnet>) {
    let mut check = Check::new("setup");
    let yaml = match read_config(&args.config) {
        Ok(yaml) => yaml,
        Err(e) => return (Check::failed("setup", format!("config: {e}")), None),
    };
    let mut genesis: Option<(Genesis, String)> = None;
    if let Some(path) = &args.genesis {
        match read_genesis(path) {
            Ok(g) => genesis = Some((g, format!("the genesis state {}", path.display()))),
            Err(e) => return (Check::failed("setup", format!("genesis: {e}")), None),
        }
    }
    let mut api_genesis = Vec::new();
    for (n, url) in args.apis.iter().enumerate() {
        let api = ProbeApi::new(url.clone(), DEFAULT_API_TIMEOUT);
        match api.genesis().await {
            Ok(g) => api_genesis.push((n, g)),
            Err(e) => check.fail(format!("api {n} ({url:?}): {e}")),
        }
    }
    if genesis.is_none() {
        genesis = api_genesis
            .first()
            .map(|(n, g)| (g.genesis, format!("api {n}")));
    }
    let Some((genesis, source)) = genesis else {
        check.fail("no genesis: neither a genesis state nor an API answered");
        return (check, None);
    };
    let devnet = match Devnet::new(&yaml, genesis) {
        Ok(devnet) => devnet,
        Err(e) => {
            check.fail(format!("config {}: {e}", args.config.display()));
            return (check, None);
        }
    };
    let hex = |b: &[u8]| devnet_probe::api::hex0x(b);
    check.pass(format!(
        "config {} ({}, preset {}), genesis time {} and validators root {} from {source}",
        args.config.display(),
        devnet.config().config_name(),
        devnet.config().preset_base(),
        genesis.genesis_time,
        hex(&genesis.genesis_validators_root)
    ));
    for (n, g) in api_genesis {
        let fork_version = devnet.config().genesis_fork_version();
        check.record(
            g.genesis == genesis && g.fork_version == fork_version,
            format!(
                "api {n}: genesis time {}, validators root {}, fork version {} (want {}, {}, {})",
                g.genesis.genesis_time,
                hex(&g.genesis.genesis_validators_root),
                hex(&g.fork_version),
                genesis.genesis_time,
                hex(&genesis.genesis_validators_root),
                hex(&fork_version)
            ),
        );
    }
    let ok = check.passed();
    (check, ok.then_some(devnet))
}

/// The records `discover` must find: every `--enr` and every `--api`'s node identity.
async fn expected_records(args: &Args, check: &mut Check) -> Vec<Enr> {
    let mut expected = args.enrs.clone();
    for (n, url) in args.apis.iter().enumerate() {
        let api = ProbeApi::new(url.clone(), DEFAULT_API_TIMEOUT);
        match api.identity().await {
            Ok(identity) => match parse_enr("identity", &identity.enr) {
                Ok(enr) if expected.iter().all(|e| e.node_id() != enr.node_id()) => {
                    expected.push(enr);
                }
                Ok(_) => {}
                Err(e) => check.fail(format!("api {n}: its identity's ENR: {e}")),
            },
            Err(e) => check.fail(format!("api {n}: {e}")),
        }
    }
    expected
}

/// Runs the checks of `args` under the preset `E`, writing each one's lines as it ends.
async fn checks<E: EthSpec>(args: &Args, devnet: &Devnet, out: &mut dyn Write) -> Vec<Check> {
    let clock: Clock = Arc::new(system_ms);
    let reference = || ProbeApi::new(args.apis[0].clone(), DEFAULT_API_TIMEOUT);
    let mut done = Vec::new();
    let mut emit = |check: Check, out: &mut dyn Write| {
        for line in check.render() {
            let _ = writeln!(out, "{line}");
        }
        let _ = out.flush();
        done.push(check);
    };
    if args.command.runs(Command::Discover) {
        let check = match devnet.fork_fields(system_ms()) {
            Ok(fork) => {
                let mut sources = Check::new(discover::NAME);
                let expected = expected_records(args, &mut sources).await;
                let plan = DiscoverPlan {
                    fork,
                    listen: args.discv5_listen,
                    bootnodes: args.bootnodes.clone(),
                    expected,
                    deadline: args.discover,
                };
                let mut check = discover::discover(&plan).await;
                for line in sources.lines() {
                    check.record(line.pass, line.detail.clone());
                }
                check
            }
            Err(e) => Check::failed(discover::NAME, format!("our record's fork fields: {e}")),
        };
        emit(check, out);
    }
    if args.command.runs(Command::Connect) {
        let plan = ConnectPlan {
            peers: args.peers.clone(),
            timeout: args.connect,
        };
        emit(connect::connect::<E>(devnet, &plan).await, out);
    }
    if args.command.runs(Command::Status) {
        let plan = StatusPlan {
            peers: args.peers.clone(),
            hold: args.hold,
            ping_interval: args.ping,
            status_deadline: args.status_deadline,
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            listen: Vec::new(),
        };
        let mut check = status::status::<E>(devnet, reference(), Arc::clone(&clock), &plan).await;
        if args.hold < status::ACCEPTANCE_HOLD {
            check.mark_diagnostic(format!(
                "hold {} s < {} s",
                args.hold.as_secs(),
                status::ACCEPTANCE_HOLD.as_secs()
            ));
        }
        emit(check, out);
    }
    if args.command.runs(Command::FetchEpoch) {
        let plan = FetchPlan {
            peers: args.peers.clone(),
            epoch: args.epoch,
            status_deadline: args.status_deadline,
            fetch_timeout: args.fetch,
        };
        emit(
            fetch::fetch_epoch::<E>(devnet, reference(), Arc::clone(&clock), &plan).await,
            out,
        );
    }
    done
}

/// The whole run for `argv`; returns the exit code.
fn run(argv: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let args = match parse(argv) {
        Ok(Parsed::Run(args)) => args,
        Ok(Parsed::Help) => {
            let _ = writeln!(out, "{USAGE}\n\n{HELP}");
            return 0;
        }
        Err(e) => {
            let _ = writeln!(err, "devnet-probe: {e}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "devnet-probe: tokio runtime: {e}");
            return EXIT_FAILED;
        }
    };
    let ran = runtime.block_on(async {
        let (mut setup, devnet) = setup(&args).await;
        let mut missing = Vec::new();
        if devnet.is_some() && args.command.dials() {
            for (n, node) in api_nodes(&args, &mut setup).await {
                if !args.peers.iter().any(|p| p.peer_id == node) {
                    missing.push(format!("api {n} is node {node}, which no --peer names"));
                }
            }
        }
        for line in setup.render() {
            let _ = writeln!(out, "{line}");
        }
        if !missing.is_empty() {
            return Err(missing);
        }
        let ok = setup.passed();
        let mut all = vec![setup];
        if let (Some(devnet), true) = (devnet, ok) {
            let ran = match devnet.preset() {
                Preset::Minimal => checks::<Minimal>(&args, &devnet, out).await,
                Preset::Mainnet => checks::<Mainnet>(&args, &devnet, out).await,
            };
            all.extend(ran);
        }
        Ok(all)
    });
    let all = match ran {
        Ok(all) => all,
        Err(missing) => {
            let _ = writeln!(
                err,
                "devnet-probe: {}: every reference CL must be dialled: give its --peer",
                missing.join("; ")
            );
            return EXIT_USAGE;
        }
    };
    let (outcome, line) = verdict(&all);
    let _ = writeln!(out, "{line}");
    match outcome {
        Outcome::Pass => 0,
        Outcome::Fail => EXIT_FAILED,
        Outcome::Diagnostic => EXIT_DIAGNOSTIC,
    }
}

/// The libp2p peer ID of every `--api`'s node (`/eth/v1/node/identity`), by `--api` index; a
/// read that fails, or an ID that does not parse, is a failed line of `check`.
async fn api_nodes(args: &Args, check: &mut Check) -> Vec<(usize, PeerId)> {
    let mut nodes = Vec::new();
    for (n, url) in args.apis.iter().enumerate() {
        let api = ProbeApi::new(url.clone(), DEFAULT_API_TIMEOUT);
        match api.identity().await.map(|i| i.peer_id.parse::<PeerId>()) {
            Ok(Ok(node)) => {
                check.pass(format!("api {n}: node {node}"));
                nodes.push((n, node));
            }
            Ok(Err(e)) => check.fail(format!("api {n}: identity: peer_id: {e}")),
            Err(e) => check.fail(format!("api {n}: identity: {e}")),
        }
    }
    nodes
}

fn main() -> ExitCode {
    if let Err(no_log_writer) = init_binary_tracing(LevelFilter::INFO) {
        return no_log_writer;
    }
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // `run` writes its usage errors here just before it returns; they reach stderr unchanged,
    // queued behind the logs, so a stderr nobody reads cannot block the exit either.
    let mut err = Vec::new();
    let code = run(&argv, &mut std::io::stdout(), &mut err);
    if !err.is_empty() {
        queue_stderr(&err);
    }
    flush_logs(LOG_FLUSH_DEADLINE);
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use devnet_probe::fixtures;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A record at `ip` with the fixture devnet's fork fields now, as `enr:` text.
    fn enr_at(ip: std::net::Ipv4Addr) -> String {
        let key = cl_discv5::enr::CombinedKey::generate_secp256k1();
        let fork = fixtures::devnet().fork_fields(fixtures::now_ms()).unwrap();
        let addr = cl_discv5::enr::LocalAddr::new(ip);
        cl_discv5::enr::build_local_enr(&key, &fork, 4, &addr)
            .unwrap()
            .to_base64()
    }

    const PEER: &str =
        "/ip4/127.0.0.1/tcp/4000/p2p/16Uiu2HAmUoDUVzvvH5ZJwz3o6z2ZRQb2hR1LwVV3ZLfxgy8pskqk";

    #[test]
    fn arguments() {
        let enr = enr_at(std::net::Ipv4Addr::LOCALHOST);
        let public_enr = enr_at(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let (good, public) = (enr.as_str(), public_enr.as_str());
        let a = parse(&args(&["connect", "--network-dir", "/net", "--peer", PEER])).unwrap();
        let Parsed::Run(a) = a else { panic!("{a:?}") };
        assert_eq!(a.command, Command::Connect);
        assert_eq!(a.config, PathBuf::from("/net/config.yaml"));
        assert_eq!(a.genesis, Some(PathBuf::from("/net/genesis.ssz")));
        assert_eq!(a.peers.len(), 1);
        assert_eq!(a.hold, status::DEFAULT_HOLD);
        assert_eq!(a.ping, status::DEFAULT_PING_INTERVAL);
        assert_eq!(a.discv5_listen, discover::DEFAULT_LISTEN);
        let full = args(&[
            "all",
            "--config",
            "/c.yaml",
            "--api",
            "http://127.0.0.1:5052",
            "--api",
            "http://localhost:4000",
            "--peer",
            PEER,
            "--enr",
            good,
            "--bootnode",
            good,
            "--discv5-listen",
            "127.0.0.1:9100",
            "--discover-secs",
            "5",
            "--connect-secs",
            "6",
            "--status-secs",
            "7",
            "--hold-secs",
            "8",
            "--ping-secs",
            "9",
            "--fetch-secs",
            "10",
            "--epoch",
            "3",
        ]);
        let Parsed::Run(a) = parse(&full).unwrap() else {
            panic!()
        };
        assert_eq!(a.command, Command::All);
        assert_eq!(a.config, PathBuf::from("/c.yaml"));
        assert_eq!(a.genesis, None);
        assert_eq!(a.apis.len(), 2);
        assert_eq!(a.enrs.len(), 1);
        assert_eq!(a.bootnodes.len(), 1);
        assert_eq!(a.discv5_listen, "127.0.0.1:9100".parse().unwrap());
        assert_eq!(
            [
                a.discover,
                a.connect,
                a.status_deadline,
                a.hold,
                a.ping,
                a.fetch
            ],
            [5, 6, 7, 8, 9, 10].map(Duration::from_secs)
        );
        assert_eq!(a.epoch, Some(3));
        assert_eq!(parse(&args(&["--help"])).unwrap(), Parsed::Help);
        for (bad, why) in [
            (&["bogus"][..], "unknown command"),
            (&[], "no command"),
            (&["connect", "--peer", PEER], "--config or --network-dir"),
            (
                &["connect", "--network-dir", "/n", "--config", "/c"],
                "not both",
            ),
            (&["connect", "--network-dir", "/n"], "--peer"),
            (&["status", "--network-dir", "/n", "--peer", PEER], "--api"),
            (
                &["fetch-epoch", "--network-dir", "/n", "--peer", PEER],
                "--api",
            ),
            (
                &["discover", "--network-dir", "/n", "--enr", good],
                "--bootnode",
            ),
            (
                &["discover", "--network-dir", "/n", "--bootnode", good],
                "--enr or --api",
            ),
            (
                &["connect", "--config", "/c", "--peer", PEER],
                "--genesis or --api",
            ),
            (
                &["connect", "--network-dir", "/n", "--peer"],
                "needs a value",
            ),
            (
                &[
                    "connect",
                    "--network-dir",
                    "/n",
                    "--peer",
                    "/ip4/8.8.8.8/tcp/1/p2p/16Uiu2HAmUoDUVzvvH5ZJwz3o6z2ZRQb2hR1LwVV3ZLfxgy8pskqk",
                ],
                "not a local address",
            ),
            (
                &[
                    "connect",
                    "--network-dir",
                    "/n",
                    "--peer",
                    PEER,
                    "--api",
                    "https://127.0.0.1",
                ],
                "--api",
            ),
            (
                &[
                    "connect",
                    "--network-dir",
                    "/n",
                    "--peer",
                    PEER,
                    "--hold-secs",
                    "x",
                ],
                "not a number",
            ),
            (
                &[
                    "connect",
                    "--network-dir",
                    "/n",
                    "--peer",
                    PEER,
                    "--ping-secs",
                    "0",
                ],
                "at least 1",
            ),
            (
                &[
                    "connect",
                    "--network-dir",
                    "/n",
                    "--peer",
                    PEER,
                    "--hold-secs",
                    "86401",
                ],
                "at most 86400",
            ),
            (
                &[
                    "discover",
                    "--network-dir",
                    "/n",
                    "--bootnode",
                    good,
                    "--enr",
                    good,
                    "--discover-secs",
                    "18446744073709551615",
                ],
                "at most 86400",
            ),
            (
                &[
                    "connect",
                    "--network-dir",
                    "/n",
                    "--peer",
                    PEER,
                    "--discv5-listen",
                    "x",
                ],
                "--discv5-listen",
            ),
            (
                &[
                    "discover",
                    "--network-dir",
                    "/n",
                    "--bootnode",
                    "enr:-x",
                    "--enr",
                    good,
                ],
                "--bootnode",
            ),
            (
                &[
                    "discover",
                    "--network-dir",
                    "/n",
                    "--bootnode",
                    public,
                    "--enr",
                    good,
                ],
                "not at a local address",
            ),
            (
                &[
                    "connect",
                    "--network-dir",
                    "/n",
                    "--peer",
                    PEER,
                    "--frobnicate",
                    "1",
                ],
                "unknown argument --frobnicate",
            ),
            (
                &[
                    "connect",
                    "--network-dir",
                    "/n",
                    "--peer",
                    PEER,
                    "http://key@x",
                ],
                "not shown",
            ),
        ] {
            let err = parse(&args(bad)).unwrap_err();
            assert!(err.contains(why), "{bad:?}: {err}");
        }
    }

    /// A devnet directory: the fixture config and a genesis state prefix.
    fn network_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.yaml"),
            testkit::export_blocks::fixtures::CONFIG,
        )
        .unwrap();
        let genesis = fixtures::devnet().genesis();
        let mut state = genesis.genesis_time.to_le_bytes().to_vec();
        state.extend_from_slice(&genesis.genesis_validators_root);
        state.extend_from_slice(&[0xee; 64]);
        std::fs::write(dir.path().join("genesis.ssz"), state).unwrap();
        dir
    }

    fn run_args(list: &[&str]) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args(list), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn peer_arg(p: &PinnedPeer) -> String {
        format!("{}/p2p/{}", p.addr, p.peer_id)
    }

    #[test]
    fn help_and_usage() {
        let (code, out, _) = run_args(&["--help"]);
        assert_eq!(code, 0);
        assert!(out.starts_with("usage: devnet-probe"), "{out}");
        assert!(out.contains("fetch-epoch"), "{out}");
        assert!(
            out.contains("the verdict names every\nrecorded deviation"),
            "{out}"
        );
        let (code, _, err) = run_args(&["connect"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("--config or --network-dir"), "{err}");
    }

    #[test]
    fn connect_against_a_stand_in() {
        let rt = runtime();
        let devnet = fixtures::devnet();
        let cl = rt.block_on(fixtures::StandIn::spawn::<Minimal>(&devnet, None));
        let dir = network_dir();
        let dir_arg = dir.path().to_str().unwrap();
        let good = peer_arg(&cl.pinned());
        let (code, out, _) = run_args(&["connect", "--network-dir", dir_arg, "--peer", &good]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("setup: PASS config"), "{out}");
        assert!(out.contains("connect: PASS peer"), "{out}");
        assert!(out.contains("/yamux/1.0.0"), "{out}");
        assert!(out.ends_with("verdict: PASS (2/2 checks)\n"), "{out}");
        // A peer offering mplex only passes, exit 0, its deviation recorded in the PASS line,
        // the check's summary and the verdict.
        let mplex = peer_arg(&rt.block_on(fixtures::mplex_only_peer()));
        let (code, out, _) = run_args(&[
            "connect",
            "--network-dir",
            dir_arg,
            "--peer",
            &good,
            "--peer",
            &mplex,
        ]);
        assert_eq!(code, 0, "{out}");
        assert!(
            out.contains("muxer=/mplex/6.7.0 (peer offers no yamux: recorded deviation)"),
            "{out}"
        );
        assert!(
            out.contains("\nconnect: PASS (2/2; 1 recorded deviation: mplex)\n"),
            "{out}"
        );
        assert!(
            out.ends_with("verdict: PASS (2/2 checks; 1 recorded deviation: connect mplex)\n"),
            "{out}"
        );
        let closed = peer_arg(&fixtures::closed_port_peer());
        let (code, out, _) = run_args(&[
            "connect",
            "--network-dir",
            dir_arg,
            "--peer",
            &good,
            "--peer",
            &closed,
        ]);
        assert_eq!(code, EXIT_FAILED, "{out}");
        assert!(
            out.ends_with("verdict: FAIL (1/2 checks; failed: connect)\n"),
            "{out}"
        );
        // A preset this probe has no spec for is a failed setup.
        std::fs::write(
            dir.path().join("config.yaml"),
            testkit::export_blocks::fixtures::CONFIG.replace("'minimal'", "'gnosis'"),
        )
        .unwrap();
        let (code, out, _) = run_args(&["connect", "--network-dir", dir_arg, "--peer", &good]);
        assert_eq!(code, EXIT_FAILED);
        assert!(out.contains("setup: FAIL config"), "{out}");
        assert!(!out.contains("connect:"), "{out}");
    }

    #[test]
    fn setup_refuses_a_second_genesis() {
        let rt = runtime();
        let chain = fixtures::FixtureChain::default();
        let other = Genesis {
            genesis_validators_root: [0x43; 32],
            ..fixtures::devnet().genesis()
        };
        chain.with(|s| s.genesis = Some((other, [0, 0, 0, 1])));
        let server = rt.block_on(chain.serve());
        let api = format!("http://{}", server.addr);
        let dir = network_dir();
        let peer = peer_arg(&fixtures::closed_port_peer());
        let dir_arg = dir.path().to_str().unwrap();
        let (code, out, _) = run_args(&[
            "connect",
            "--network-dir",
            dir_arg,
            "--peer",
            &peer,
            "--api",
            &api,
        ]);
        assert_eq!(code, EXIT_FAILED);
        assert!(out.contains("setup: FAIL api 0: genesis time"), "{out}");
        assert!(!out.contains("connect:"), "{out}");
        // Unreadable inputs, and an API that does not answer while no genesis state is given.
        let missing = dir.path().join("none.yaml");
        let (code, out, _) = run_args(&[
            "connect",
            "--config",
            missing.to_str().unwrap(),
            "--api",
            &api,
            "--peer",
            &peer,
        ]);
        assert_eq!(code, EXIT_FAILED);
        assert!(out.contains("setup: FAIL config"), "{out}");
        let bad_genesis = dir.path().join("short.ssz");
        std::fs::write(&bad_genesis, [1, 2, 3]).unwrap();
        let config = dir.path().join("config.yaml");
        let (code, out, _) = run_args(&[
            "connect",
            "--config",
            config.to_str().unwrap(),
            "--genesis",
            bad_genesis.to_str().unwrap(),
            "--peer",
            &peer,
        ]);
        assert_eq!(code, EXIT_FAILED);
        assert!(out.contains("setup: FAIL genesis"), "{out}");
        chain.with(|s| s.down = true);
        let (code, out, _) = run_args(&[
            "connect",
            "--config",
            config.to_str().unwrap(),
            "--api",
            &api,
            "--peer",
            &peer,
        ]);
        assert_eq!(code, EXIT_FAILED);
        assert!(out.contains("no genesis"), "{out}");
    }

    /// A reference API answering `devnet`'s genesis, finalized at epoch 4 (slot 32, root
    /// `0xf4…`), whose node is `peer`.
    fn reference_api(
        rt: &tokio::runtime::Runtime,
        peer: libp2p::PeerId,
    ) -> (
        fixtures::FixtureChain,
        testkit::collector::testing::FixtureServer,
    ) {
        let chain = fixtures::FixtureChain::default();
        chain.finalize(4, consensus_types::primitives::Root::repeat_byte(0xf4), 32);
        chain.with(|s| {
            s.genesis = Some((fixtures::devnet().genesis(), [0, 0, 0, 1]));
            s.identity = Some((peer.to_string(), "enr:-unused".into()));
        });
        let server = rt.block_on(chain.serve());
        (chain, server)
    }

    /// The Status of a CL that matches ours against [`reference_api`].
    fn matching_status(devnet: &Devnet) -> p2p_wire::rpc::messages::StatusV2 {
        let finalized = consensus_types::primitives::Root::repeat_byte(0xf4);
        p2p_wire::rpc::messages::StatusV2 {
            fork_digest: devnet.fork_digest(fixtures::now_ms()).unwrap(),
            finalized_root: finalized,
            finalized_epoch: 4,
            head_root: finalized,
            head_slot: 32,
            earliest_available_slot: 0,
        }
    }

    /// A hold shorter than the acceptance hold prints no PASS for status, and the run exits 3,
    /// never 0.
    #[test]
    fn a_short_hold_is_diagnostic_only() {
        let rt = runtime();
        let devnet = fixtures::devnet();
        let script = fixtures::Script {
            restatus_after: Some(Duration::from_millis(200)),
            ..fixtures::Script::default()
        };
        let cl = rt.block_on(fixtures::StandIn::scripted::<Minimal>(
            &devnet,
            Some(matching_status(&devnet)),
            script,
        ));
        let (_chain, server) = reference_api(&rt, cl.id);
        let api = format!("http://{}", server.addr);
        let dir = network_dir();
        let peer = peer_arg(&cl.pinned());
        let (code, out, _) = run_args(&[
            "status",
            "--network-dir",
            dir.path().to_str().unwrap(),
            "--api",
            &api,
            "--peer",
            &peer,
            "--hold-secs",
            "1",
            "--ping-secs",
            "1",
        ]);
        assert_eq!(code, EXIT_DIAGNOSTIC, "{out}");
        assert!(!out.contains("status: PASS"), "{out}");
        assert!(
            out.contains("status: DIAGNOSTIC (1/1; hold 1 s < 600 s)"),
            "{out}"
        );
        assert!(out.contains("verdict: DIAGNOSTIC ("), "{out}");
    }

    /// Every reference API's node must be among the `--peer`s: leaving one out is a usage
    /// error, not a pass over the rest.
    #[test]
    fn every_api_node_needs_its_peer() {
        let rt = runtime();
        let devnet = fixtures::devnet();
        let cl = rt.block_on(fixtures::StandIn::spawn::<Minimal>(&devnet, None));
        let other = libp2p::PeerId::random();
        let (chain, server) = reference_api(&rt, other);
        let api = format!("http://{}", server.addr);
        let dir = network_dir();
        let dir_arg = dir.path().to_str().unwrap();
        let peer = peer_arg(&cl.pinned());
        let (code, out, err) = run_args(&[
            "connect",
            "--network-dir",
            dir_arg,
            "--api",
            &api,
            "--peer",
            &peer,
        ]);
        assert_eq!(code, EXIT_USAGE, "{out}");
        assert!(
            err.contains(&other.to_string()) && err.contains("no --peer"),
            "{err}"
        );
        assert!(!out.contains("connect:"), "{out}");
        // Its own peer given, the run goes on; an identity the API does not serve fails setup.
        chain.with(|s| s.identity = Some((cl.id.to_string(), "enr:-unused".into())));
        let (code, out, _) = run_args(&[
            "connect",
            "--network-dir",
            dir_arg,
            "--api",
            &api,
            "--peer",
            &peer,
        ]);
        assert_eq!(code, 0, "{out}");
        chain.with(|s| s.identity = None);
        let (code, out, _) = run_args(&[
            "connect",
            "--network-dir",
            dir_arg,
            "--api",
            &api,
            "--peer",
            &peer,
        ]);
        assert_eq!(code, EXIT_FAILED, "{out}");
        assert!(out.contains("setup: FAIL api 0: identity"), "{out}");
    }

    /// What an `all` run against the fixture reference CL reports, check by check.
    const ALL_EXPECTED: [&str; 5] = [
        "setup: PASS",
        "discover: PASS",
        "connect: PASS",
        // A 1 s hold is no acceptance hold.
        "status: DIAGNOSTIC",
        // The stand-in stores no blocks: it answers 3: ResourceUnavailable.
        "fetch-epoch: FAIL",
    ];

    /// The summary line of each check in `out`, in order.
    fn summaries(out: &str) -> Vec<&str> {
        out.lines()
            .filter(|l| l.ends_with(')') && !l.starts_with("verdict"))
            .filter(|l| {
                [": PASS (", ": FAIL (", ": DIAGNOSTIC ("]
                    .iter()
                    .any(|w| l.contains(w))
            })
            .collect()
    }

    /// Whether an `all` run with `--discv5-listen listen` lost nothing but its port: our node
    /// found `listen` itself taken, and every check other than discover reported what
    /// [`ALL_EXPECTED`] says. Only such a run is run again; any other is a result.
    fn only_the_port_was_taken(out: &str, listen: &str) -> bool {
        let ours = format!("discover: FAIL discv5 on {listen}: ");
        let taken = out
            .lines()
            .any(|l| l.starts_with(&ours) && fixtures::port_taken(l));
        let summaries = summaries(out);
        let rest_as_expected = summaries.len() == ALL_EXPECTED.len()
            && summaries
                .iter()
                .zip(ALL_EXPECTED)
                .all(|(line, want)| want.starts_with("discover:") || line.starts_with(want));
        taken && rest_as_expected
    }

    /// An `all` run's output: `discover` is its discover lines, and every other check reports
    /// `connect` for connect and what [`ALL_EXPECTED`] says for the rest.
    fn all_output(discover: &[&str], connect: &str) -> String {
        let (line, summary) = (
            format!("connect: {connect} peer 0: yamux"),
            format!("connect: {connect} (1/1)"),
        );
        let mut out = vec!["setup: PASS api 0: identity", "setup: PASS (1/1)"];
        out.extend_from_slice(discover);
        out.extend([
            line.as_str(),
            summary.as_str(),
            "status: DIAGNOSTIC peer 0: held 1.0 s",
            "status: DIAGNOSTIC (1/1; hold under the acceptance hold)",
            "fetch-epoch: FAIL peer 0: 3: ResourceUnavailable",
            "fetch-epoch: FAIL (0/1)",
            "verdict: FAIL (3/5 checks; failed: discover, fetch-epoch)",
        ]);
        out.iter().map(|l| format!("{l}\n")).collect()
    }

    /// Our node's start on 127.0.0.1:9100 finding the port taken, as the discover check
    /// reports it.
    const TAKEN: &str = "discover: FAIL discv5 on 127.0.0.1:9100: discv5 did not start: \
                         Io(Os { code: 48, kind: AddrInUse, message: \"Address already in use\" })";

    #[test]
    fn an_all_run_that_lost_only_its_port_is_run_again() {
        let out = all_output(&[TAKEN, "discover: FAIL (0/1)"], "PASS");
        assert!(only_the_port_was_taken(&out, "127.0.0.1:9100"), "{out}");
    }

    /// A taken port must not hide a real failure elsewhere in the same run.
    #[test]
    fn an_all_run_with_a_taken_port_and_another_failure_is_a_result() {
        let out = all_output(&[TAKEN, "discover: FAIL (0/1)"], "FAIL");
        assert!(!only_the_port_was_taken(&out, "127.0.0.1:9100"), "{out}");
        // A check that never reported is no match either.
        let short: String = out.lines().take(4).map(|l| format!("{l}\n")).collect();
        assert!(
            !only_the_port_was_taken(&short, "127.0.0.1:9100"),
            "{short}"
        );
    }

    /// The taken port must be this run's own listen address.
    #[test]
    fn an_all_run_whose_taken_port_is_not_its_own_is_a_result() {
        let out = all_output(&[TAKEN, "discover: FAIL (0/1)"], "PASS");
        assert!(!only_the_port_was_taken(&out, "127.0.0.1:9101"), "{out}");
        assert!(!only_the_port_was_taken(&out, "127.0.0.1:910"), "{out}");
        // A discover failure that is not a taken port is a result.
        let other = "discover: FAIL discv5 on 127.0.0.1:9100: discv5 did not start: refused";
        let out = all_output(&[other, "discover: FAIL (0/1)"], "PASS");
        assert!(!only_the_port_was_taken(&out, "127.0.0.1:9100"), "{out}");
        // AddrInUse from another check, with discover passing, is a result.
        let elsewhere = "discover: PASS kind: AddrInUse";
        let out = all_output(&[elsewhere, "discover: PASS (1/1)"], "PASS");
        assert!(!only_the_port_was_taken(&out, "127.0.0.1:9100"), "{out}");
    }

    #[test]
    fn all_runs_every_check_in_order() {
        let rt = runtime();
        let devnet = fixtures::devnet();
        // A reference CL: its discv5 node (found through itself as the bootnode), its probe
        // swarm (which re-Statuses us and holds the connection, but serves no blocks), and its
        // beacon API.
        let fork = devnet.fork_fields(fixtures::now_ms()).unwrap();
        let (node, _events) = rt.block_on(fixtures::discv5_node(&fork));
        let record = node.local_enr();
        let finalized = consensus_types::primitives::Root::repeat_byte(0xf4);
        let ours = p2p_wire::rpc::messages::StatusV2 {
            fork_digest: devnet.fork_digest(fixtures::now_ms()).unwrap(),
            finalized_root: finalized,
            finalized_epoch: 4,
            head_root: finalized,
            head_slot: 32,
            earliest_available_slot: 0,
        };
        let script = fixtures::Script {
            restatus_after: Some(Duration::from_millis(200)),
            ..fixtures::Script::default()
        };
        let cl = rt.block_on(fixtures::StandIn::scripted::<Minimal>(
            &devnet,
            Some(ours),
            script,
        ));
        let chain = fixtures::FixtureChain::default();
        chain.finalize(4, finalized, 32);
        chain.with(|s| {
            s.genesis = Some((devnet.genesis(), [0, 0, 0, 1]));
            s.identity = Some((cl.id.to_string(), record.to_base64()));
        });
        let server = rt.block_on(chain.serve());
        let api = format!("http://{}", server.addr);
        let dir = network_dir();
        let peer = peer_arg(&cl.pinned());
        let boot = record.to_base64();
        // `run` builds its own runtime, so the retry runs off any tokio runtime; our discv5
        // node moves to a fresh port while it finds that very port taken and every other
        // check reported what it should (`only_the_port_was_taken`). Any other run is the
        // result, so a race on the port never hides a failure elsewhere in the same run.
        let all = |port: u16| {
            let listen = format!("127.0.0.1:{port}");
            let (code, out, _) = run_args(&[
                "all",
                "--network-dir",
                dir.path().to_str().unwrap(),
                "--api",
                &api,
                "--peer",
                &peer,
                "--bootnode",
                &boot,
                "--discv5-listen",
                &listen,
                "--discover-secs",
                "5",
                "--hold-secs",
                "1",
                "--ping-secs",
                "1",
                "--status-secs",
                "5",
                "--fetch-secs",
                "5",
            ]);
            if only_the_port_was_taken(&out, &listen) {
                Err(out)
            } else {
                Ok((code, out))
            }
        };
        let (code, out) = futures::executor::block_on(fixtures::on_free_udp_port(|port| {
            std::future::ready(all(port))
        }));
        assert_eq!(code, EXIT_FAILED, "{out}");
        let summaries = summaries(&out);
        assert_eq!(summaries.len(), ALL_EXPECTED.len(), "{out}");
        for (line, want) in summaries.iter().zip(ALL_EXPECTED) {
            assert!(line.starts_with(want), "{want}: {out}");
        }
        assert!(
            out.ends_with("verdict: FAIL (4/5 checks; failed: fetch-epoch)\n"),
            "{out}"
        );
    }
}
