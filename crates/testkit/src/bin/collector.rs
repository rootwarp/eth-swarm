//! `collector`: record gossip/SSE arrival times, and compute their offsets afterwards.
//!
//! ```text
//! collector sse --network hoodi|sepolia (--url URL | --url-file PATH) --out DIR --host HOST
//!               [--topic EVENT... | --topics-file PATH] [--ntp chrony|timesyncd|none]
//!               [--max-backoff-secs N]
//! collector offsets CAPTURE_DIR
//! collector rates CAPTURE_DIR
//! collector --help
//! ```
//!
//! `sse` reads `genesis_time` from the reference node (checked against the pinned genesis where
//! one is pinned) and refuses a node whose `CONFIG_NAME` is not `--network`, then streams its
//! `/eth/v1/events` into a new capture directory `OUT/<network>-<unix start seconds>/`
//! ([`testkit::collector::Collector`]) until SIGTERM or SIGINT, reconnecting with backoff and
//! recording every disconnect as a missing interval. The host clock's NTP offset is sampled
//! every 60 s from the time daemon and logged. The URL must be plain `http://` to a loopback
//! host; reach a remote node through an SSH tunnel. A URL that carries a key comes from
//! `--url-file` (a 0600 file), never `--url`, so it stays out of `/proc/<pid>/cmdline`. Our
//! probe's gossip tap feeds the same collector through [`testkit::collector::Tap`].
//!
//! The topic set comes from `--topics-file` ([`testkit::collector::TopicConfig`], read as data):
//! the SSE events and the sampled attestation subnets, both copied into `capture.toml`. At the
//! start the node is asked for each event alone; one it refuses is not subscribed and is listed
//! as unsupported, a gap. Blocks and columns are always subscribed (the fallback), and a node
//! that refuses them is refused. With `single_attestation` subscribed, the committees per slot
//! are read from the node (an attestation's subnet is computed from them), and its `attnets`
//! too: a sampled subnet it does not subscribe is logged.
//!
//! `rates` prints one JSON line per topic with its messages and bytes per slot (and the busiest
//! slot's), and per sampled subnet for `single_attestation`; then a summary line. A slot is one
//! the topic's source recorded anything in: a slot with nothing from the source (a missing
//! interval, say) is not in the divisor. Every configured topic and sampled subnet of
//! `summary.toml` has its line, a 0 line when nothing was recorded (a refused topic included);
//! a capture without `summary.toml` yet (still running) lists the recorded topics only.
//!
//! `offsets` prints one JSON line per record with its slot-relative offset and, for a column,
//! its envelope-relative offset, then a summary line with the unmatched column count. It reads
//! the records twice, one at a time, so a capture of any length fits.
//!
//! Exit codes: 0 done, 1 the node, the genesis check or the capture failed, 64 usage.

use consensus_types::caps::NetworkCaps;
use consensus_types::EthSpec;
use consensus_types::Mainnet;
use network_config::{ChainConfig, Network};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use testkit::archive::ChainParams;
use testkit::collector::{
    collect, committees_per_slot, config_name, genesis_time, node_attnets, read_info, read_summary,
    records, run_sse, sample, supported_topics, Arrival, ArrivalReceiver, Arrivals, Backoff,
    CaptureInfo, Clock, Collector, CollectorError, ColumnMatch, CommandDaemon, Drops,
    EnvelopeIndex, RateCounter, ReferenceApiUrl, SlotClock, Source, SseConfig, Summary,
    SystemClock, TimeDaemon, TokioPause, TopicConfig, DEFAULT_TOPICS, FALLBACK_SSE_EVENTS,
    NTP_INTERVAL, SINGLE_ATTESTATION,
};
use tokio::sync::watch;

/// What writes the capture: [`collect`], or a fault in tests.
type WriteCapture = fn(
    Collector<Mainnet>,
    ArrivalReceiver,
    &Drops,
    &mut dyn FnMut(&str),
) -> Result<Summary, CollectorError>;

const USAGE: &str = "\
usage: collector sse --network hoodi|sepolia (--url URL | --url-file PATH) --out DIR --host HOST
                     [--topic EVENT... | --topics-file PATH] [--ntp chrony|timesyncd|none]
                     [--max-backoff-secs N]
       collector offsets CAPTURE_DIR
       collector rates CAPTURE_DIR
       collector --help";
const HELP: &str = "\
Record gossip/SSE arrival times (monotonic and wall clock), or print their offsets.

sse streams a reference node's /eth/v1/events into OUT/<network>-<unix start seconds>/
(capture.toml, records.jsonl, gaps.jsonl, ntp.jsonl, and summary.toml at the end) until
SIGTERM or SIGINT. Disconnects are reconnected with backoff and recorded as missing intervals.

  --network NAME          hoodi or sepolia (the embedded config); the node's CONFIG_NAME
                          (/eth/v1/config/spec) must be the same
  --url URL               the node's beacon API: http:// to a loopback host only (tunnel to a
                          remote node over SSH); its genesis_time is read from it
  --url-file PATH         the same URL read from PATH instead (one line; a regular file only
                          its owner may access, mode 0600), so a key in it stays out of argv
  --out DIR               where the capture directory is created
  --host HOST             the capture host, for capture.toml
  --topic EVENT           an event to subscribe, repeatable (default: block_gossip,
                          execution_payload_gossip, data_column_sidecar)
  --topics-file PATH      the events and sampled attestation subnets instead, from a TOML file
                          (sse_events, attestation_subnets; a regular file only its owner, root
                          or this user, may write); events the node refuses are listed as gaps
  --ntp DAEMON            chrony (chronyc tracking), timesyncd (timedatectl timesync-status)
                          or none; sampled every 60 s (default chrony)
  --max-backoff-secs N    the longest reconnect wait (default 30)

offsets prints one JSON line per record of CAPTURE_DIR: its slot-relative offset
(recv_wall - (genesis_time + slot * SLOT_DURATION_MS)) and, for a column, its offset from the
execution_payload envelope of the same block root; then a summary with the unmatched columns.

rates prints one JSON line per topic of CAPTURE_DIR: messages and bytes per slot, and the
busiest slot's; per subnet too for single_attestation. The divisor counts only the slots the
topic's source recorded anything in: a slot with nothing from that source (a missing interval)
is left out, not counted as empty. Every configured topic and sampled subnet of summary.toml
gets a line, 0 when nothing was recorded (a topic the node refused included); without
summary.toml (a capture still running) only the recorded topics are listed.

Exit codes: 0 done, 1 the node, the genesis check or the capture failed, 64 usage.";

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 64;
/// Arrivals the channel holds while the collector writes: about ten minutes of a busy stream.
const CHANNEL_CAPACITY: usize = 1 << 16;
/// Bytes the queued arrivals may hold: 64 MiB. Beacon API events are a few hundred bytes, so
/// the entry cap binds first; this one binds on events near `MAX_EVENT_BYTES`, which would
/// otherwise let the queue grow to 64 GiB.
const CHANNEL_BYTES: usize = 64 << 20;
const GENESIS_TIMEOUT: Duration = Duration::from_secs(10);
const SPEC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ntp {
    Chrony,
    Timesyncd,
    None,
}

impl Ntp {
    fn name(self) -> &'static str {
        match self {
            Ntp::Chrony => "chrony",
            Ntp::Timesyncd => "timesyncd",
            Ntp::None => "none",
        }
    }

    fn daemon(self) -> Option<Arc<dyn TimeDaemon>> {
        match self {
            Ntp::Chrony => Some(Arc::new(CommandDaemon::chrony())),
            Ntp::Timesyncd => Some(Arc::new(CommandDaemon::timesyncd())),
            Ntp::None => None,
        }
    }
}

#[derive(Debug)]
struct SseArgs {
    network: Network,
    url: ReferenceApiUrl,
    out: PathBuf,
    host: String,
    topics: Vec<String>,
    attestation_subnets: Vec<u64>,
    ntp: Ntp,
    max_backoff: Duration,
}

#[derive(Debug)]
enum Command {
    Help,
    Sse(Box<SseArgs>),
    Offsets(PathBuf),
    Rates(PathBuf),
}

fn parse(args: &[String]) -> Result<Command, String> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Command::Help);
    }
    match args.first().map(String::as_str) {
        Some("offsets") => match &args[1..] {
            [dir] => Ok(Command::Offsets(dir.into())),
            _ => Err("offsets takes exactly one CAPTURE_DIR".into()),
        },
        Some("rates") => match &args[1..] {
            [dir] => Ok(Command::Rates(dir.into())),
            _ => Err("rates takes exactly one CAPTURE_DIR".into()),
        },
        Some("sse") => parse_sse(&args[1..]).map(|a| Command::Sse(Box::new(a))),
        Some(_) => Err("unknown command (want sse, offsets or rates)".into()),
        None => Err("no command".into()),
    }
}

/// The flags `sse` takes, each followed by its value.
const SSE_FLAGS: [&str; 9] = [
    "--network",
    "--url",
    "--url-file",
    "--out",
    "--host",
    "--topic",
    "--topics-file",
    "--ntp",
    "--max-backoff-secs",
];

/// The error for an argument `sse` does not take. Arguments can hold a keyed URL
/// (`--url=http://…/<key>`, or a URL where a flag was due), so only a flag's key is named, and
/// only when it looks like one; never a value.
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

fn parse_sse(args: &[String]) -> Result<SseArgs, String> {
    let (mut network, mut url, mut out, mut host) = (None, None, None, None);
    let mut topics = Vec::new();
    let mut topic_file: Option<TopicConfig> = None;
    let mut ntp = Ntp::Chrony;
    let mut max_backoff = Backoff::default().max;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        // Matched before anything is said about it: only a known flag is ever quoted.
        let Some(flag) = SSE_FLAGS.into_iter().find(|f| f == arg) else {
            return Err(unknown_argument(arg));
        };
        // A value is never quoted either: a misplaced URL can land in any flag's value.
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?
            .as_str();
        match flag {
            "--network" => {
                let found = Network::ALL.into_iter().find(|n| n.name() == value);
                network = Some(found.ok_or("--network: want hoodi or sepolia")?);
            }
            // The error says why, never the URL (its path may hold a key).
            "--url" | "--url-file" if url.is_some() => {
                return Err("give one --url or --url-file".into())
            }
            "--url" => url = Some(ReferenceApiUrl::parse(value).map_err(|e| e.to_string())?),
            // The URL stays out of argv; the error names the file, never what it holds.
            "--url-file" => {
                let read = ReferenceApiUrl::read_file(Path::new(value));
                url = Some(read.map_err(|e| format!("--url-file: {e}"))?);
            }
            "--out" => out = Some(PathBuf::from(value)),
            "--host" => host = Some(value.to_owned()),
            "--topic" | "--topics-file" if topic_file.is_some() => {
                return Err("give --topic or one --topics-file, not both".into())
            }
            "--topic" => topics.push(value.to_owned()),
            "--topics-file" if !topics.is_empty() => {
                return Err("give --topic or one --topics-file, not both".into())
            }
            "--topics-file" => {
                let read = TopicConfig::read_file(Path::new(value));
                topic_file = Some(read.map_err(|e| format!("--topics-file: {e}"))?);
            }
            "--ntp" => {
                ntp = match value {
                    "chrony" => Ntp::Chrony,
                    "timesyncd" => Ntp::Timesyncd,
                    "none" => Ntp::None,
                    _ => return Err("--ntp: want chrony, timesyncd or none".into()),
                }
            }
            _ => {
                let secs: u64 = value
                    .parse()
                    .ok()
                    .filter(|s| *s > 0)
                    .ok_or_else(|| format!("{flag}: want a positive number of seconds"))?;
                max_backoff = Duration::from_secs(secs);
            }
        }
    }
    fn required<T>(value: Option<T>, flag: &str) -> Result<T, String> {
        value.ok_or_else(|| format!("{flag} is required"))
    }
    let attestation_subnets = match topic_file {
        Some(file) => {
            topics = file.sse_events;
            file.attestation_subnets
        }
        None => Vec::new(),
    };
    if topics.is_empty() {
        topics = DEFAULT_TOPICS.iter().map(|t| (*t).to_owned()).collect();
    }
    let checked: Vec<&str> = topics.iter().map(String::as_str).collect();
    SseConfig::checked_topics(&checked).map_err(|e| format!("--topic: {e}"))?;
    let host = required(host, "--host")?;
    if host.is_empty() {
        return Err("--host must not be empty".into());
    }
    Ok(SseArgs {
        network: required(network, "--network")?,
        url: required(url, "--url or --url-file")?,
        out: required(out, "--out")?,
        host,
        topics,
        attestation_subnets,
        ntp,
        max_backoff,
    })
}

/// Where the collector's log lines go: stderr, or a buffer in tests.
type Log = Arc<Mutex<dyn Write + Send>>;

fn log(to: &Log, line: &str) {
    let _ = writeln!(to.lock().expect("log lock"), "collector: {line}");
}

fn run(args: &[String], out: &mut dyn Write, err: &Log) -> u8 {
    let command = match parse(args) {
        Ok(c) => c,
        Err(e) => {
            log(err, &format!("{e}\n{USAGE}"));
            return EXIT_USAGE;
        }
    };
    match command {
        Command::Help => {
            let _ = writeln!(out, "{USAGE}\n\n{HELP}");
            0
        }
        Command::Offsets(dir) => offsets(&dir, out, err),
        Command::Rates(dir) => rates(&dir, out, err),
        Command::Sse(args) => {
            let args = *args;
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log(err, &format!("tokio runtime: {e}"));
                    return EXIT_FAILED;
                }
            };
            runtime.block_on(async {
                let (stop_tx, stop) = watch::channel(false);
                tokio::spawn(async move {
                    wait_for_signal().await;
                    let _ = stop_tx.send(true);
                });
                let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
                let write: WriteCapture = collect::<Mainnet>;
                capture_sse(&args, clock, args.ntp.daemon(), stop, write, out, err).await
            })
        }
    }
}

/// SIGTERM (systemd stop) or SIGINT.
async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// The SSE capture, until `stop`.
async fn capture_sse(
    args: &SseArgs,
    clock: Arc<dyn Clock>,
    daemon: Option<Arc<dyn TimeDaemon>>,
    stop: watch::Receiver<bool>,
    write: WriteCapture,
    out: &mut dyn Write,
    err: &Log,
) -> u8 {
    let fail = |message: String| {
        log(err, &message);
        EXIT_FAILED
    };
    let network = args.network.name();
    let config = match ChainConfig::load(args.network) {
        Ok(config) => config,
        Err(e) => return fail(format!("{network} config: {e}")),
    };
    let Some(column_subnet_count) = config
        .get("DATA_COLUMN_SIDECAR_SUBNET_COUNT")
        .and_then(|v| v.parse::<u64>().ok())
    else {
        return fail(format!(
            "{network} config: no DATA_COLUMN_SIDECAR_SUBNET_COUNT"
        ));
    };
    let genesis = match genesis_time(&args.url, GENESIS_TIMEOUT).await {
        Ok(t) => t,
        Err(e) => return fail(format!("genesis: {e}")),
    };
    if let Some(pinned) = args.network.genesis() {
        if pinned.genesis_time != genesis {
            // The node's value is not quoted: nothing from a response goes into a message.
            return fail(format!(
                "the node's genesis_time is not {network}'s pinned {}",
                pinned.genesis_time
            ));
        }
    }
    // Hoodi pins no genesis: on a host that runs both networks, a URL with the other node's
    // port is caught here. Only a network of ours is ever named, never the node's text.
    match config_name(&args.url, SPEC_TIMEOUT).await {
        Ok(name) if name == network => {}
        Ok(name) => {
            let refusal = match Network::ALL.into_iter().find(|n| n.name() == name) {
                Some(other) => format!(
                    "the node's CONFIG_NAME is {}, not {network}: the URL reaches another \
                     network's node",
                    other.name()
                ),
                None => format!("the node's CONFIG_NAME is not {network}"),
            };
            return fail(refusal);
        }
        Err(e) => return fail(format!("spec: {e}")),
    }
    let (subscribed, unsupported) =
        match supported_topics(&args.url, &args.topics, SPEC_TIMEOUT).await {
            Ok(found) => found,
            Err(e) => return fail(format!("events: {e}")),
        };
    if let Some(fallback) = FALLBACK_SSE_EVENTS
        .iter()
        .find(|f| unsupported.iter().any(|u| u == *f))
    {
        return fail(format!(
            "the node does not emit {fallback}: no beacon_block and column fallback"
        ));
    }
    if subscribed.is_empty() {
        return fail("the node emits none of the configured events".into());
    }
    if !unsupported.is_empty() {
        log(
            err,
            &format!(
                "the node does not emit {}: not subscribed, listed as unsupported (gaps)",
                unsupported.join(",")
            ),
        );
    }
    let slots_per_epoch = Mainnet::slots_per_epoch();
    let (mut committees, mut attnets) = (None, None);
    if subscribed.iter().any(|t| t == SINGLE_ATTESTATION) {
        let now = SlotClock::new(genesis, config.slot_duration_ms())
            .and_then(|c| c.wall_slot(clock.now().wall_ns));
        let Some(slot) = now else {
            return fail("committees: the wall clock is before genesis".into());
        };
        if args.attestation_subnets.is_empty() {
            log(
                err,
                &format!(
                    "no attestation subnet is sampled: every {SINGLE_ATTESTATION} is counted, \
                     none recorded (name them in --topics-file)"
                ),
            );
        }
        match committees_per_slot(&args.url, slot, slots_per_epoch, SPEC_TIMEOUT).await {
            Ok(n) => committees = Some(n),
            Err(e) => return fail(format!("committees: {e}")),
        }
        // Only for the log and capture.toml: a node without its identity is still captured.
        match node_attnets(&args.url, SPEC_TIMEOUT).await {
            Ok(subnets) => {
                let unsubscribed: Vec<String> = (args.attestation_subnets.iter())
                    .filter(|s| !subnets.contains(s))
                    .map(u64::to_string)
                    .collect();
                if !unsubscribed.is_empty() {
                    log(
                        err,
                        &format!(
                            "the node does not subscribe attestation subnet {} (its attnets): \
                             expect no {SINGLE_ATTESTATION} there",
                            unsubscribed.join(",")
                        ),
                    );
                }
                attnets = Some(subnets);
            }
            Err(e) => log(err, &format!("identity: {e}")),
        }
    }
    let topics: Vec<&str> = subscribed.iter().map(String::as_str).collect();
    let mut sse = match SseConfig::new(args.url.clone(), &topics) {
        Ok(c) => c,
        Err(e) => return fail(e.to_string()),
    };
    sse.backoff.max = args.max_backoff.max(sse.backoff.initial);
    let started = clock.now();
    let info = CaptureInfo {
        network: network.to_owned(),
        genesis_time: genesis,
        slot_duration_ms: config.slot_duration_ms(),
        column_subnet_count,
        sources: vec![Source::Sse],
        sse_topics: sse.topics.clone(),
        host: args.host.clone(),
        time_daemon: args.ntp.name().to_owned(),
        started_mono_ns: started.mono_ns,
        started_wall_ns: started.wall_ns,
        sse_topics_unsupported: unsupported,
        gossip_topics: Vec::new(),
        attestation_subnets: args.attestation_subnets.clone(),
        node_attnets: attnets,
        committees_per_slot: committees,
        slots_per_epoch: Some(slots_per_epoch),
    };
    let dir = args
        .out
        .join(format!("{network}-{}", started.wall_ns / 1_000_000_000));
    let chain = ChainParams {
        schedule: *config.fork_schedule(),
        caps: NetworkCaps::from_config(&config),
    };
    let collector = match Collector::<Mainnet>::create(&dir, info, chain, None) {
        Ok(c) => c,
        Err(e) => return fail(e.to_string()),
    };
    let _ = writeln!(out, "{}", dir.display());
    log(
        err,
        &format!(
            "capturing {network} SSE ({}) into {}; NTP from {}",
            sse.topics.join(","),
            dir.display(),
            args.ntp.name()
        ),
    );

    let (arrivals, rx) = Arrivals::channel(CHANNEL_CAPACITY, CHANNEL_BYTES);
    let drops = arrivals.drops();
    let writer_log = Arc::clone(err);
    let mut writer = tokio::task::spawn_blocking(move || {
        write(collector, rx, &drops, &mut |line| log(&writer_log, line))
    });
    // The producers stop on `stop`, or when the writer fails: `halt` carries both.
    let (halt_tx, halt) = watch::channel(false);
    let halt_tx = Arc::new(halt_tx);
    let forward = tokio::spawn({
        let (halt_tx, mut stop) = (Arc::clone(&halt_tx), stop);
        async move {
            let _ = stop.wait_for(|s| *s).await;
            let _ = halt_tx.send(true);
        }
    });
    let ntp = daemon.map(|daemon| {
        let (clock, arrivals, halt) = (Arc::clone(&clock), arrivals.clone(), halt.clone());
        tokio::spawn(sample_ntp(clock, daemon, arrivals, halt))
    });
    // The writer runs until every producer is gone; if it ends first it failed, and the
    // capture stops with it rather than drop every event until a signal. The SSE client also
    // returns on its own once the writer is gone (the channel closed).
    let early = {
        let sse_run = run_sse(&sse, &*clock, &TokioPause, &arrivals, started, halt);
        tokio::pin!(sse_run);
        tokio::select! {
            stats = &mut sse_run => Ok(stats),
            written = &mut writer => {
                let _ = halt_tx.send(true);
                let _ = sse_run.await;
                Err(written)
            }
        }
    };
    // However the SSE client ended, the NTP sampler stops with it.
    let _ = halt_tx.send(true);
    if let Some(ntp) = ntp {
        let _ = ntp.await;
    }
    forward.abort();
    drop(arrivals);
    let stats = match early {
        Ok(stats) => stats,
        Err(Ok(Ok(_))) => return fail("capture: the writer stopped before the producers".into()),
        Err(Ok(Err(e))) => return fail(format!("capture: {e}")),
        Err(Err(e)) => return fail(format!("capture: {e}")),
    };
    let summary = match writer.await {
        Ok(Ok(summary)) => summary,
        Ok(Err(e)) => return fail(format!("capture: {e}")),
        Err(e) => return fail(format!("capture: {e}")),
    };
    let _ = writeln!(
        out,
        "{}: {} records, {} undecoded, {} dropped, {} unsubscribed, {} connections, {} missing \
         intervals, {} outside the sampled subnets",
        dir.display(),
        summary.records,
        summary.undecoded,
        summary.dropped,
        stats.unsubscribed,
        stats.connections,
        summary.missing_intervals,
        summary.outside_sampled_subnets
    );
    let gaps = summary.topic_gaps();
    if !gaps.is_empty() {
        let _ = writeln!(out, "{}: topic gaps: {}", dir.display(), gaps.join(", "));
    }
    0
}

/// Samples the clock offset every [`NTP_INTERVAL`], the first at once, until `stop`.
async fn sample_ntp(
    clock: Arc<dyn Clock>,
    daemon: Arc<dyn TimeDaemon>,
    arrivals: Arrivals,
    mut stop: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(NTP_INTERVAL);
    loop {
        tokio::select! {
            biased;
            _ = stop.wait_for(|s| *s) => return,
            _ = tick.tick() => {}
        }
        let (clock, daemon) = (Arc::clone(&clock), Arc::clone(&daemon));
        let Ok(taken) = tokio::task::spawn_blocking(move || sample(&*clock, &*daemon)).await else {
            return;
        };
        if arrivals.deliver(Arrival::Ntp(taken)).await.is_err() {
            return;
        }
    }
}

/// Two passes over `records.jsonl`, one record in memory at a time: the envelopes first, then
/// every record's offsets. Records appended after the first pass (a capture still being
/// written) are left out of the second.
fn offsets(dir: &Path, out: &mut dyn Write, err: &Log) -> u8 {
    let fail = |message: String| {
        log(err, &message);
        EXIT_FAILED
    };
    let info = match read_info(dir) {
        Ok(info) => info,
        Err(e) => return fail(e.to_string()),
    };
    let Some(clock) = SlotClock::new(info.genesis_time, info.slot_duration_ms) else {
        return fail(format!(
            "{}: slot_duration_ms must be positive",
            dir.display()
        ));
    };
    let mut envelopes = EnvelopeIndex::default();
    let mut count = 0usize;
    let first_pass = records(dir).and_then(|mut all| {
        all.try_for_each(|record| {
            envelopes.add(&record?);
            count += 1;
            Ok::<_, CollectorError>(())
        })
    });
    if let Err(e) = first_pass {
        return fail(e.to_string());
    }
    let second = match records(dir) {
        Ok(all) => all,
        Err(e) => return fail(e.to_string()),
    };
    let (mut with_offset, mut matched, mut unmatched) = (0u64, 0u64, 0u64);
    for (i, record) in second.take(count).enumerate() {
        let record = match record {
            Ok(record) => record,
            Err(e) => return fail(e.to_string()),
        };
        let offset = clock.offset(&record);
        with_offset += u64::from(offset.is_some());
        let envelope_offset_ms = match envelopes.column(&record) {
            ColumnMatch::Matched { offset_ns, .. } => {
                matched += 1;
                Some(offset_ns as f64 / 1e6)
            }
            ColumnMatch::Unmatched => {
                unmatched += 1;
                None
            }
            ColumnMatch::NotAColumn => None,
        };
        let line = serde_json::json!({
            "index": i,
            "source": record.source,
            "topic": record.topic,
            "slot": offset.map(|o| o.slot),
            "slot_offset_ms": offset.map(|o| o.offset_ms()),
            "envelope_offset_ms": envelope_offset_ms,
        });
        let _ = writeln!(out, "{line}");
    }
    let summary = serde_json::json!({
        "summary": {
            "records": count,
            "slot_offsets": with_offset,
            "columns_matched": matched,
            "unmatched_columns": unmatched,
        }
    });
    let _ = writeln!(out, "{summary}");
    0
}

/// One pass over `records.jsonl`, one record in memory at a time, with a 0 row for every
/// configured topic and sampled subnet of `summary.toml` that has no record.
fn rates(dir: &Path, out: &mut dyn Write, err: &Log) -> u8 {
    let fail = |message: String| {
        log(err, &message);
        EXIT_FAILED
    };
    let info = match read_info(dir) {
        Ok(info) => info,
        Err(e) => return fail(e.to_string()),
    };
    let Some(clock) = SlotClock::new(info.genesis_time, info.slot_duration_ms) else {
        return fail(format!(
            "{}: slot_duration_ms must be positive",
            dir.display()
        ));
    };
    let mut counter = RateCounter::new(clock);
    match read_summary(dir) {
        Ok(Some(summary)) => counter.configure(&summary),
        Ok(None) => log(
            err,
            &format!(
                "{}: no summary.toml yet: topics with no records are not listed",
                dir.display()
            ),
        ),
        Err(e) => return fail(e.to_string()),
    }
    let counted = records(dir).and_then(|mut all| {
        all.try_for_each(|record| {
            counter.add(&record?);
            Ok::<_, CollectorError>(())
        })
    });
    if let Err(e) = counted {
        return fail(e.to_string());
    }
    let rates = counter.finish();
    for r in &rates.topics {
        let line = serde_json::json!({
            "source": r.source,
            "topic": r.topic,
            "subnet": r.subnet,
            "n": r.n,
            "bytes": r.bytes,
            "slots": r.slots,
            "msgs_per_slot": r.msgs_per_slot,
            "bytes_per_slot": r.bytes_per_slot,
            "peak_msgs_per_slot": r.peak_msgs_per_slot,
            "peak_bytes_per_slot": r.peak_bytes_per_slot,
        });
        let _ = writeln!(out, "{line}");
    }
    let summary = serde_json::json!({
        "summary": {
            "topics": rates.topics.iter().filter(|r| r.subnet.is_none()).count(),
            "before_genesis": rates.before_genesis,
        }
    });
    let _ = writeln!(out, "{summary}");
    0
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let err: Log = Arc::new(Mutex::new(std::io::stderr()));
    ExitCode::from(run(&args, &mut std::io::stdout(), &err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use testkit::archive::fixtures;
    use testkit::collector::testing::{FixtureServer, HangUp, Reply};
    use testkit::collector::{
        read_capture, ArrivalRecord, NtpSample, MAX_RECORD_LINE_BYTES, NTP_FILE, SUMMARY_FILE,
    };

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn buffer() -> (Log, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (Arc::clone(&buf) as Log, buf)
    }

    fn text(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    fn run_args(list: &[&str]) -> (u8, String, String) {
        let (err, buf) = buffer();
        let mut out = Vec::new();
        let code = run(&args(list), &mut out, &err);
        (code, String::from_utf8(out).unwrap(), text(&buf))
    }

    fn sse_args(url: &str, out: &Path) -> Vec<String> {
        args(&[
            "sse",
            "--network",
            "hoodi",
            "--url",
            url,
            "--out",
            out.to_str().unwrap(),
            "--host",
            "ref-host",
        ])
    }

    #[test]
    fn usage_and_help() {
        let (code, out, _) = run_args(&["--help"]);
        assert_eq!(code, 0);
        assert!(out.contains("SLOT_DURATION_MS"), "{out}");
        for bad in [
            &[][..],
            &["capture"],
            &["offsets"],
            &["offsets", "a", "b"],
            &["sse", "--network"],
            &["sse", "--network", "mainnet"],
            &["sse", "--ntp", "ntpd"],
            &["sse", "--max-backoff-secs", "0"],
            &["sse", "--bogus", "1"],
            &[
                "sse",
                "--network",
                "hoodi",
                "--url",
                "http://127.0.0.1:5052",
            ],
            &[
                "sse",
                "--network",
                "hoodi",
                "--url",
                "http://127.0.0.1",
                "--out",
                "/x",
                "--host",
                "",
            ],
        ] {
            let (code, _, err) = run_args(bad);
            assert_eq!(code, EXIT_USAGE, "{bad:?}: {err}");
            assert!(err.contains("usage:"), "{err}");
        }
        // A remote or keyed URL is refused without being quoted.
        let (code, _, err) = run_args(&["sse", "--url", "http://ref.example/hunter2"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(
            err.contains("loopback") && !err.contains("hunter2"),
            "{err}"
        );
    }

    #[test]
    fn the_url_can_come_from_a_file_and_never_from_both() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("collector-hoodi.url");
        std::fs::write(&file, "http://127.0.0.1:5053/key-hunter2\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let file_arg = file.to_str().unwrap();
        let with = |url_flags: &[&str]| {
            let mut list = vec!["sse", "--network", "hoodi", "--out", "/x", "--host", "h"];
            list.extend_from_slice(url_flags);
            parse(&args(&list))
        };
        let Ok(Command::Sse(a)) = with(&["--url-file", file_arg]) else {
            panic!("--url-file refused")
        };
        assert_eq!(format!("{:?}", a.url), "http://127.0.0.1:5053/…");
        assert_eq!(a.url.base_path(), "/key-hunter2");

        let both = with(&["--url-file", file_arg, "--url", "http://127.0.0.1:5053"]);
        assert!(both.unwrap_err().contains("--url or --url-file"));
        let twice = with(&["--url-file", file_arg, "--url-file", file_arg]);
        assert!(twice.unwrap_err().contains("--url or --url-file"));
        let neither = with(&[]).unwrap_err();
        assert!(
            neither.contains("--url or --url-file is required"),
            "{neither}"
        );

        // A file others may read is refused, naming the file and never the URL in it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (code, _, err) = run_args(&[
            "sse",
            "--network",
            "hoodi",
            "--url-file",
            file_arg,
            "--out",
            "/x",
            "--host",
            "h",
        ]);
        assert_eq!(code, EXIT_USAGE);
        assert!(
            err.contains(&format!("--url-file: {file_arg}: group or others")),
            "{err}"
        );
        assert!(!err.contains("hunter2"), "{err}");
    }

    #[test]
    fn a_keyed_path_never_appears_in_stderr() {
        const KEYED: &str = "http://127.0.0.1:5052/hunter2";
        let flag = format!("--url={KEYED}");
        for (list, named) in [
            // `--url=…` is not `--url …`: an unknown argument, named by its key only.
            (vec!["sse", "--network", "hoodi", &flag], Some("--url")),
            (vec!["sse", &flag, "--network", "hoodi"], Some("--url")),
            (vec!["sse", "--network", "hoodi", KEYED], None),
            (vec![KEYED], None),
            (vec!["sse", "--network", KEYED], None),
            (vec!["sse", "--ntp", KEYED], None),
            (vec!["sse", "--max-backoff-secs", KEYED], None),
            (vec!["sse", "--topic", KEYED], None),
        ] {
            let (code, _, err) = run_args(&list);
            assert_eq!(code, EXIT_USAGE, "{list:?}: {err}");
            assert!(!err.contains("hunter2"), "{list:?}: {err}");
            if let Some(key) = named {
                assert!(err.contains(&format!("unknown argument {key}")), "{err}");
            }
        }
    }

    #[test]
    fn sse_defaults() {
        let Command::Sse(a) = parse(&sse_args("http://127.0.0.1:5052", Path::new("/out"))).unwrap()
        else {
            panic!("not sse");
        };
        assert_eq!(a.topics, DEFAULT_TOPICS);
        assert_eq!(
            (a.ntp, a.max_backoff),
            (Ntp::Chrony, Duration::from_secs(30))
        );
        assert_eq!(a.network, Network::Hoodi);
        let mut more = sse_args("http://127.0.0.1:5052", Path::new("/out"));
        more.extend(args(&[
            "--topic",
            "head",
            "--ntp",
            "timesyncd",
            "--max-backoff-secs",
            "5",
        ]));
        let Command::Sse(a) = parse(&more).unwrap() else {
            panic!("not sse");
        };
        assert_eq!(a.topics, ["head"]);
        assert_eq!(
            (a.ntp, a.max_backoff),
            (Ntp::Timesyncd, Duration::from_secs(5))
        );
        assert_eq!(Ntp::None.daemon().map(|_| ()), None);
        assert_eq!(Ntp::Chrony.daemon().unwrap().name(), "chrony");
        assert_eq!(Ntp::Timesyncd.daemon().unwrap().name(), "timesyncd");
    }

    struct FixedDaemon;

    impl TimeDaemon for FixedDaemon {
        fn name(&self) -> &str {
            "fixed"
        }
        fn clock_error_ns(&self) -> Result<i64, String> {
            Ok(250_000)
        }
    }

    const STREAM: &str = "event: block_gossip\ndata: {\"slot\":\"3\",\"block\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}\n\n";

    async fn node(genesis: &'static str) -> FixtureServer {
        node_on(genesis, "hoodi").await
    }

    /// A node whose spec says `CONFIG_NAME: config_name`.
    async fn node_on(genesis: &'static str, config_name: &'static str) -> FixtureServer {
        FixtureServer::start(move |_, path| match path {
            "/eth/v1/beacon/genesis" => {
                Reply::json(&format!(r#"{{"data":{{"genesis_time":"{genesis}"}}}}"#))
            }
            "/eth/v1/config/spec" => {
                Reply::json(&format!(r#"{{"data":{{"CONFIG_NAME":"{config_name}"}}}}"#))
            }
            "/eth/v1/events" => Reply::stream(vec![STREAM], true),
            _ => Reply::status(404),
        })
        .await
    }

    /// Runs `sse` until 500 ms after the first record is on disk.
    async fn capture(args: &SseArgs) -> (u8, String, String) {
        capture_on(args, Arc::new(SystemClock::new())).await
    }

    /// [`capture`] on `clock`.
    async fn capture_on(args: &SseArgs, clock: Arc<dyn Clock>) -> (u8, String, String) {
        let (err, buf) = buffer();
        let (stop_tx, stop) = watch::channel(false);
        let out_dir = args.out.clone();
        let stopper = tokio::spawn(async move {
            for _ in 0..200 {
                tokio::time::sleep(Duration::from_millis(25)).await;
                let has_records = std::fs::read_dir(&out_dir)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .any(|e| std::fs::metadata(e.path().join("records.jsonl")).is_ok());
                if has_records {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            stop_tx.send(true).unwrap();
        });
        let mut out = Vec::new();
        let code = capture_sse(
            args,
            clock,
            Some(Arc::new(FixedDaemon)),
            stop,
            collect::<Mainnet>,
            &mut out,
            &err,
        )
        .await;
        stopper.abort();
        (code, String::from_utf8(out).unwrap(), text(&buf))
    }

    fn parsed(url: &str, out: &Path) -> SseArgs {
        match parse(&sse_args(url, out)).unwrap() {
            Command::Sse(a) => *a,
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn sse_refuses_a_node_on_another_network() {
        let dir = tempfile::tempdir().unwrap();
        // Hoodi pins no genesis, so on a host that runs both, the Sepolia node's port is caught
        // by its CONFIG_NAME only.
        let server = node_on("1655733600", "sepolia").await;
        let (code, out, err) =
            capture(&parsed(&format!("http://{}", server.addr), dir.path())).await;
        assert_eq!(code, EXIT_FAILED);
        assert!(out.is_empty(), "{out}");
        assert!(
            err.contains("the node's CONFIG_NAME is sepolia, not hoodi"),
            "{err}"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // A name that is no network of ours is refused without being quoted.
        let server = node_on("1742213400", "devnet7").await;
        let (code, _, err) = capture(&parsed(&format!("http://{}", server.addr), dir.path())).await;
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("the node's CONFIG_NAME is not hoodi"), "{err}");
        assert!(!err.contains("devnet7"), "{err}");

        // A node without the spec endpoint is refused too: fail closed.
        let server = FixtureServer::start(|_, path| match path {
            "/eth/v1/beacon/genesis" => Reply::json(r#"{"data":{"genesis_time":"1742213400"}}"#),
            _ => Reply::status(404),
        })
        .await;
        let (code, _, err) = capture(&parsed(&format!("http://{}", server.addr), dir.path())).await;
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("spec: /eth/v1/config/spec: HTTP 404"), "{err}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn sse_captures_until_stopped() {
        let server = node("1742213400").await;
        let dir = tempfile::tempdir().unwrap();
        let args = parsed(&format!("http://{}", server.addr), dir.path());
        let (code, out, err) = capture(&args).await;
        assert_eq!(code, 0, "{err}");
        let capture_dir = PathBuf::from(out.lines().next().unwrap());
        assert!(capture_dir.starts_with(dir.path()), "{out}");
        assert!(out.lines().nth(1).unwrap().contains("1 records"), "{out}");
        assert!(err.contains("capturing hoodi SSE"), "{err}");
        assert!(err.contains("ntp: fixed clock error +0.250 ms"), "{err}");

        let (info, records) = read_capture(&capture_dir).unwrap();
        assert_eq!(info.genesis_time, 1_742_213_400);
        assert_eq!(
            (info.slot_duration_ms, info.column_subnet_count),
            (12_000, 128)
        );
        assert_eq!(info.host, "ref-host");
        let r: &ArrivalRecord = &records[0];
        assert_eq!(
            (r.source, r.topic.as_str(), r.slot),
            (Source::Sse, "block_gossip", Some(3))
        );
        let summary: Summary =
            toml::from_str(&std::fs::read_to_string(capture_dir.join(SUMMARY_FILE)).unwrap())
                .unwrap();
        assert_eq!(summary.records, 1);
        // Only the moment before the first stream is missing.
        assert_eq!(summary.missing_intervals, 1, "{summary:?}");
        assert_eq!(summary.missing_open_at_shutdown, 0, "{summary:?}");
        let ntp = std::fs::read_to_string(capture_dir.join(NTP_FILE)).unwrap();
        let first: NtpSample = serde_json::from_str(ntp.lines().next().unwrap()).unwrap();
        assert_eq!(first.clock_error_ns, Some(250_000));

        // offsets over the capture: one record at slot 3, no columns.
        let (code, out, _) = run_args(&["offsets", capture_dir.to_str().unwrap()]);
        assert_eq!(code, 0);
        let last: serde_json::Value = serde_json::from_str(out.lines().last().unwrap()).unwrap();
        assert_eq!(last["summary"]["records"], 1);
        assert_eq!(last["summary"]["unmatched_columns"], 0);
    }

    /// A clock that moves 1 s forward each time it is read: whatever the capture does between
    /// two readings (creating and syncing its files, logging) takes time.
    struct StepClock {
        wall_ns: u64,
        reads: std::sync::atomic::AtomicU64,
    }

    impl Clock for StepClock {
        fn now(&self) -> testkit::collector::Stamp {
            let n = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            testkit::collector::Stamp {
                mono_ns: n * 1_000_000_000,
                wall_ns: self.wall_ns + n * 1_000_000_000,
            }
        }
    }

    #[tokio::test]
    async fn the_setup_before_the_first_stream_is_missing_time() {
        let server = node("1742213400").await;
        let dir = tempfile::tempdir().unwrap();
        let args = parsed(&format!("http://{}", server.addr), dir.path());
        let clock = Arc::new(StepClock {
            wall_ns: SystemClock::new().now().wall_ns,
            reads: Default::default(),
        });
        let (code, out, err) = capture_on(&args, clock).await;
        assert_eq!(code, 0, "{err}");
        let capture_dir = PathBuf::from(out.lines().next().unwrap());
        let info = read_info(&capture_dir).unwrap();
        let gaps = std::fs::read_to_string(capture_dir.join("gaps.jsonl")).unwrap();
        let first: testkit::collector::MissingInterval =
            serde_json::from_str(gaps.lines().next().unwrap()).unwrap();
        // The first gap opens at the start capture.toml records, not when the client runs.
        assert_eq!(
            (first.start_mono_ns, first.start_wall_ns),
            (info.started_mono_ns, info.started_wall_ns)
        );
        assert!(first.duration_ns() >= 1_000_000_000, "{first:?}");
        let summary: Summary =
            toml::from_str(&std::fs::read_to_string(capture_dir.join(SUMMARY_FILE)).unwrap())
                .unwrap();
        assert_eq!(summary.missing_intervals, 1, "{summary:?}");
        assert_eq!(summary.missing_ns, first.duration_ns());
    }

    #[tokio::test]
    async fn sse_refuses_a_node_it_cannot_trust_or_reach() {
        let dir = tempfile::tempdir().unwrap();
        // Sepolia pins its genesis: a node on another chain is refused.
        let server = node("1").await;
        let mut args = parsed(&format!("http://{}", server.addr), dir.path());
        args.network = Network::Sepolia;
        let (code, _, err) = capture(&args).await;
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("not sepolia's pinned 1655733600"), "{err}");
        // The node's own value is a response value: not quoted.
        assert!(!err.contains("genesis_time 1 "), "{err}");

        let server = HangUp::start().await;
        let url = format!("http://{}/hunter2", server.addr);
        let (code, _, err) = capture(&parsed(&url, dir.path())).await;
        assert_eq!(code, EXIT_FAILED);
        assert!(
            err.contains("genesis: /eth/v1/beacon/genesis: http"),
            "{err}"
        );
        assert!(!err.contains("hunter2"), "{err}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// A writer that takes one arrival, then fails as a full disk would.
    fn full_disk(
        collector: Collector<Mainnet>,
        mut rx: ArrivalReceiver,
        _: &Drops,
        _: &mut dyn FnMut(&str),
    ) -> Result<Summary, CollectorError> {
        let _ = rx.blocking_recv();
        drop(collector);
        Err(CollectorError::Io {
            path: "records.jsonl".into(),
            source: std::io::Error::other("No space left on device"),
        })
    }

    #[tokio::test]
    async fn a_writer_failure_stops_the_capture() {
        // The node streams an event every 10 ms and never stops; nothing sends a stop.
        let server = FixtureServer::start(move |_, path| match path {
            "/eth/v1/beacon/genesis" => Reply::json(r#"{"data":{"genesis_time":"1742213400"}}"#),
            "/eth/v1/config/spec" => Reply::json(r#"{"data":{"CONFIG_NAME":"hoodi"}}"#),
            _ => Reply::stream(vec![STREAM; 10_000], true).paced(Duration::from_millis(10)),
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let args = parsed(&format!("http://{}", server.addr), dir.path());
        let (err, buf) = buffer();
        let (_stop_tx, stop) = watch::channel(false);
        let mut out = Vec::new();
        let started = std::time::Instant::now();
        let capture = capture_sse(
            &args,
            Arc::new(SystemClock::new()),
            Some(Arc::new(FixedDaemon)),
            stop,
            full_disk,
            &mut out,
            &err,
        );
        let code = tokio::time::timeout(Duration::from_secs(10), capture)
            .await
            .expect("the capture stops on its own once the writer fails");
        assert_eq!(code, EXIT_FAILED);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        let err = text(&buf);
        assert!(
            err.contains("capture: records.jsonl: No space left on device"),
            "{err}"
        );
    }

    /// `body` as a 0644 topics file in `dir`.
    fn topics_file(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("collector-hoodi.topics.toml");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    const EXIT14: &str = "sse_events = [\"block_gossip\", \"execution_payload_bid\", \
        \"single_attestation\", \"attestation\", \"data_column_sidecar\"]\n\
        attestation_subnets = [0, 1]\n";

    #[test]
    fn the_topic_set_comes_from_a_topics_file_or_from_topic_flags() {
        let dir = tempfile::tempdir().unwrap();
        let file = topics_file(dir.path(), EXIT14);
        let file_arg = file.to_str().unwrap();
        let with = |extra: &[&str]| {
            let mut list = sse_args("http://127.0.0.1:5053", Path::new("/out"));
            list.extend(args(extra));
            parse(&list)
        };
        let Ok(Command::Sse(a)) = with(&["--topics-file", file_arg]) else {
            panic!("--topics-file refused");
        };
        assert_eq!(
            a.topics,
            [
                "block_gossip",
                "execution_payload_bid",
                "single_attestation",
                "attestation",
                "data_column_sidecar"
            ]
        );
        assert_eq!(a.attestation_subnets, [0, 1]);
        for both in [
            &["--topics-file", file_arg, "--topic", "head"][..],
            &["--topic", "head", "--topics-file", file_arg],
            &["--topics-file", file_arg, "--topics-file", file_arg],
        ] {
            let err = with(both).unwrap_err();
            assert!(err.contains("not both"), "{both:?}: {err}");
        }
        // A file that is not a config is refused, naming it and why.
        let bad = topics_file(dir.path(), "sse_events = [\"weather\"]\n");
        let (code, _, err) = run_args(&[
            "sse",
            "--network",
            "hoodi",
            "--url",
            "http://127.0.0.1:5053",
            "--out",
            "/x",
            "--host",
            "h",
            "--topics-file",
            bad.to_str().unwrap(),
        ]);
        assert_eq!(code, EXIT_USAGE);
        assert!(
            err.contains(&format!("--topics-file: {}: sse_events", bad.display())),
            "{err}"
        );
    }

    const EXIT14_STREAM: [&str; 5] = [
        "event: block_gossip\ndata: {\"slot\":\"3\",\"block\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}\n\n",
        // Committee 0 and 5 of 64: subnets 0 (sampled) and 5 (not).
        "event: single_attestation\ndata: {\"committee_index\":\"0\",\"attester_index\":\"1\",\"data\":{\"slot\":\"3\",\"index\":\"0\",\"beacon_block_root\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}}\n\n",
        "event: single_attestation\ndata: {\"committee_index\":\"5\",\"attester_index\":\"2\",\"data\":{\"slot\":\"3\",\"index\":\"0\",\"beacon_block_root\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}}\n\n",
        "event: attestation\ndata: {\"aggregation_bits\":\"0x01\",\"data\":{\"slot\":\"3\",\"index\":\"0\",\"beacon_block_root\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}}\n\n",
        "event: data_column_sidecar\ndata: {\"block_root\":\"0x1111111111111111111111111111111111111111111111111111111111111111\",\"index\":\"7\",\"slot\":\"3\"}\n\n",
    ];

    /// How the fixture node answers the committees of a slot.
    #[derive(Clone, Copy)]
    enum Committees {
        /// This many, of the slot asked for.
        Count(usize),
        /// One, of another slot.
        OtherSlot,
        /// This status.
        Status(u16),
    }

    impl Committees {
        fn reply(self, query: &str) -> Reply {
            let slot = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("slot="))
                .unwrap_or("0");
            let (slot, n) = match self {
                Committees::Count(n) => (slot.to_owned(), n),
                Committees::OtherSlot => (format!("{slot}1"), 1),
                Committees::Status(code) => return Reply::status(code),
            };
            let one = format!(r#"{{"index":"0","slot":"{slot}","validators":["1"]}}"#);
            Reply::json(&format!(r#"{{"data":[{}]}}"#, vec![one; n].join(",")))
        }
    }

    /// A Hoodi node at Lighthouse's topic set without the bid one, with attestation subnet 0
    /// subscribed; `refuse` names a further topic it refuses.
    async fn exit14_node(refuse: &'static str, committees: Committees) -> FixtureServer {
        FixtureServer::start_with_query(move |_, asked| {
            let (path, query) = asked.split_once('?').unwrap_or((asked, ""));
            match path {
                "/eth/v1/beacon/genesis" => {
                    Reply::json(r#"{"data":{"genesis_time":"1742213400"}}"#)
                }
                "/eth/v1/config/spec" => Reply::json(r#"{"data":{"CONFIG_NAME":"hoodi"}}"#),
                "/eth/v1/beacon/states/head/committees" => committees.reply(query),
                "/eth/v1/node/identity" => Reply::json(
                    r#"{"data":{"metadata":{"seq_number":"1","attnets":"0x0100000000000000"}}}"#,
                ),
                "/eth/v1/events" if query == "topics=execution_payload_bid" => Reply::status(400),
                "/eth/v1/events" if query == format!("topics={refuse}") => Reply::status(400),
                "/eth/v1/events" => Reply::stream(EXIT14_STREAM.to_vec(), true),
                _ => Reply::status(404),
            }
        })
        .await
    }

    #[tokio::test]
    async fn sse_captures_the_exit14_set_and_lists_its_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let server = exit14_node("none", Committees::Count(64)).await;
        let mut args = parsed(&format!("http://{}", server.addr), dir.path());
        args.topics = [
            "block_gossip",
            "execution_payload_bid",
            "single_attestation",
            "attestation",
            "data_column_sidecar",
        ]
        .map(String::from)
        .into();
        args.attestation_subnets = vec![0, 1];
        let (code, out, err) = capture(&args).await;
        assert_eq!(code, 0, "{err}");
        assert!(
            err.contains("the node does not emit execution_payload_bid: not subscribed"),
            "{err}"
        );
        assert!(
            err.contains("the node does not subscribe attestation subnet 1 (its attnets)"),
            "{err}"
        );
        let capture_dir = PathBuf::from(out.lines().next().unwrap());
        let info = read_info(&capture_dir).unwrap();
        assert_eq!(
            info.sse_topics,
            [
                "attestation",
                "block_gossip",
                "data_column_sidecar",
                "single_attestation"
            ]
        );
        assert_eq!(info.sse_topics_unsupported, ["execution_payload_bid"]);
        assert_eq!(info.attestation_subnets, [0, 1]);
        assert_eq!(info.node_attnets, Some(vec![0]));
        assert_eq!(
            (info.committees_per_slot, info.slots_per_epoch),
            (Some(64), Some(32))
        );
        let summary: Summary =
            toml::from_str(&std::fs::read_to_string(capture_dir.join(SUMMARY_FILE)).unwrap())
                .unwrap();
        assert_eq!(summary.records, 4, "{summary:?}");
        assert_eq!(summary.outside_sampled_subnets, 1);
        assert_eq!(summary.unsupported_topics, ["sse:execution_payload_bid"]);
        // The refused topic has its n = 0 row, so it is a missing topic too, and the gaps
        // line names it once.
        assert_eq!(
            summary.missing_topics,
            ["sse:execution_payload_bid", "sse:attestation_subnet_1"]
        );
        let bid = summary
            .topics
            .iter()
            .find(|t| t.topic == "execution_payload_bid");
        assert_eq!(bid.map(|t| (t.n, t.bytes)), Some((0, 0)), "{summary:?}");
        let gaps = out.lines().find(|l| l.contains("topic gaps: ")).unwrap();
        assert!(
            gaps.ends_with(
                "topic gaps: sse:execution_payload_bid (refused), sse:attestation_subnet_1"
            ),
            "{out}"
        );
        // Every recorded event got its subnet and size.
        let (_, records) = read_capture(&capture_dir).unwrap();
        let attestation = records
            .iter()
            .find(|r| r.topic == "single_attestation")
            .unwrap();
        assert_eq!(attestation.subnet, Some(0));
        assert!(records.iter().all(|r| r.bytes > 0), "{records:?}");

        // rates over the capture: one slot, one line per configured topic (the refused one at
        // 0) and one per sampled subnet (subnet 1 at 0).
        let (code, out, err) = run_args(&["rates", capture_dir.to_str().unwrap()]);
        assert_eq!(code, 0, "{err}");
        let lines: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let rows: Vec<(String, serde_json::Value, u64, f64)> = lines[..lines.len() - 1]
            .iter()
            .map(|l| {
                (
                    l["topic"].as_str().unwrap().to_owned(),
                    l["subnet"].clone(),
                    l["n"].as_u64().unwrap(),
                    l["msgs_per_slot"].as_f64().unwrap(),
                )
            })
            .collect();
        let none = serde_json::Value::Null;
        assert_eq!(rows.len(), 7, "{out}");
        assert_eq!(rows[3], ("execution_payload_bid".into(), none, 0, 0.0));
        assert_eq!(
            rows[5],
            ("single_attestation".into(), serde_json::json!(0), 1, 1.0)
        );
        assert_eq!(
            rows[6],
            ("single_attestation".into(), serde_json::json!(1), 0, 0.0)
        );
        assert_eq!(lines.last().unwrap()["summary"]["topics"], 5);
    }

    #[tokio::test]
    async fn sse_refuses_a_node_without_the_fallback_or_its_committees() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = parsed("http://127.0.0.1:1", dir.path());
        args.topics = ["block_gossip", "single_attestation", "data_column_sidecar"]
            .map(String::from)
            .into();
        args.attestation_subnets = vec![0];
        for (refuse, committees, want) in [
            (
                "block_gossip",
                Committees::Count(1),
                "the node does not emit block_gossip: no beacon_block and column fallback",
            ),
            (
                "none",
                Committees::Status(500),
                "committees: /eth/v1/beacon/states/head/committees: HTTP 500",
            ),
            (
                "none",
                Committees::OtherSlot,
                "committees: /eth/v1/beacon/states/head/committees: bad response",
            ),
        ] {
            let server = exit14_node(refuse, committees).await;
            args.url = ReferenceApiUrl::parse(&format!("http://{}", server.addr)).unwrap();
            let (code, _, err) = capture(&args).await;
            assert_eq!(code, EXIT_FAILED, "{want}: {err}");
            assert!(err.contains(want), "{err} (want {want})");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
        // --topic single_attestation samples no subnet: said, and the capture runs.
        let server = exit14_node("none", Committees::Count(1)).await;
        let mut unsampled = parsed(&format!("http://{}", server.addr), dir.path());
        unsampled.topics = ["block_gossip", "single_attestation", "data_column_sidecar"]
            .map(String::from)
            .into();
        let (code, _, err) = capture(&unsampled).await;
        assert_eq!(code, 0, "{err}");
        assert!(
            err.contains("no attestation subnet is sampled: every single_attestation is counted"),
            "{err}"
        );
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            std::fs::remove_dir_all(entry.unwrap().path()).unwrap();
        }
        // A node that refuses every configured event.
        let server = exit14_node("none", Committees::Count(1)).await;
        args.url = ReferenceApiUrl::parse(&format!("http://{}", server.addr)).unwrap();
        args.topics = vec!["execution_payload_bid".into()];
        let (code, _, err) = capture(&args).await;
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("emits none of the configured events"), "{err}");
        // A node that answers neither 200 nor 400 for a topic.
        let server = FixtureServer::start(|_, path| match path {
            "/eth/v1/beacon/genesis" => Reply::json(r#"{"data":{"genesis_time":"1742213400"}}"#),
            "/eth/v1/config/spec" => Reply::json(r#"{"data":{"CONFIG_NAME":"hoodi"}}"#),
            _ => Reply::status(503),
        })
        .await;
        args.url = ReferenceApiUrl::parse(&format!("http://{}", server.addr)).unwrap();
        let (code, _, err) = capture(&args).await;
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("events: /eth/v1/events: HTTP 503"), "{err}");
    }

    #[test]
    fn rates_of_a_capture_that_cannot_be_read() {
        let (code, _, err) = run_args(&["rates", "/nonexistent/capture"]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("/nonexistent/capture"), "{err}");
        let (code, _, err) = run_args(&["rates"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("rates takes exactly one CAPTURE_DIR"), "{err}");
    }

    #[test]
    fn rates_without_a_summary_list_the_recorded_topics() {
        let dir = tempfile::tempdir().unwrap();
        let info = CaptureInfo {
            network: "sepolia".into(),
            genesis_time: 100,
            slot_duration_ms: 12_000,
            sources: vec![Source::Sse],
            sse_topics: vec!["block_gossip".into(), "data_column_sidecar".into()],
            ..CaptureInfo::default()
        };
        // A capture still being written: no summary.toml yet.
        drop(Collector::<Mainnet>::create(dir.path(), info, fixtures::chain(), None).unwrap());
        let line = r#"{"source":"sse","topic":"block_gossip","subnet":null,"msg_id":null,"block_root":null,"slot":2,"recv_mono_ns":0,"recv_wall_ns":124000000000,"peer":null,"bytes":5}"#;
        std::fs::write(dir.path().join("records.jsonl"), format!("{line}\n")).unwrap();
        let (code, out, err) = run_args(&["rates", dir.path().to_str().unwrap()]);
        assert_eq!(code, 0, "{err}");
        assert!(
            err.contains("no summary.toml yet: topics with no records are not listed"),
            "{err}"
        );
        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(out.contains(r#""topic":"block_gossip""#), "{out}");
        // A summary.toml that does not parse is refused.
        std::fs::write(dir.path().join(SUMMARY_FILE), "records = 1\n").unwrap();
        let (code, out, err) = run_args(&["rates", dir.path().to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("summary.toml"), "{err}");
        assert!(out.is_empty(), "{out}");
    }

    #[test]
    fn offsets_of_a_capture() {
        let dir = tempfile::tempdir().unwrap();
        let info = CaptureInfo {
            network: "sepolia".into(),
            genesis_time: 100,
            slot_duration_ms: 12_000,
            column_subnet_count: 128,
            sources: vec![Source::Gossip],
            sse_topics: vec![],
            host: "h".into(),
            time_daemon: "none".into(),
            started_mono_ns: 0,
            started_wall_ns: 0,
            ..CaptureInfo::default()
        };
        let collector =
            Collector::<Mainnet>::create(dir.path(), info, fixtures::chain(), None).unwrap();
        collector.finish(0).unwrap();
        let root = format!("0x{}", "22".repeat(32));
        let line = |topic: &str, mono_ms: u64| {
            format!(
                r#"{{"source":"gossip","topic":"{topic}","subnet":null,"msg_id":null,"block_root":"{root}","slot":2,"recv_mono_ns":{},"recv_wall_ns":{},"peer":null}}"#,
                mono_ms * 1_000_000,
                (100_000 + 24_000 + mono_ms) * 1_000_000
            )
        };
        let records = [
            line("execution_payload", 1_000),
            line("data_column_sidecar_1", 1_800),
            line("data_column_sidecar_2", 2_000).replace(&root, &format!("0x{}", "33".repeat(32))),
        ];
        std::fs::write(dir.path().join("records.jsonl"), records.join("\n") + "\n").unwrap();
        let (code, out, err) = run_args(&["offsets", dir.path().to_str().unwrap()]);
        assert_eq!(code, 0, "{err}");
        let lines: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[1]["slot"], 2);
        assert_eq!(lines[1]["slot_offset_ms"], 1_800.0);
        assert_eq!(lines[1]["envelope_offset_ms"], 800.0);
        assert_eq!(lines[2]["envelope_offset_ms"], serde_json::Value::Null);
        assert_eq!(lines[3]["summary"]["columns_matched"], 1);
        assert_eq!(lines[3]["summary"]["unmatched_columns"], 1);

        // A line no record is that long: refused, with where, not read whole.
        let long = format!("{{\"topic\":\"{}\"}}", "x".repeat(MAX_RECORD_LINE_BYTES));
        let mut text = std::fs::read_to_string(dir.path().join("records.jsonl")).unwrap();
        text.push_str(&long);
        std::fs::write(dir.path().join("records.jsonl"), &text).unwrap();
        let (code, out, err) = run_args(&["offsets", dir.path().to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
        assert!(
            err.contains("records.jsonl: line 4: over 65536 bytes"),
            "{err}"
        );
        assert!(out.is_empty(), "{out}");

        let (code, _, err) = run_args(&["offsets", "/nonexistent/capture"]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("/nonexistent/capture"), "{err}");

        let text = std::fs::read_to_string(dir.path().join("capture.toml")).unwrap();
        let zero = text.replace("slot_duration_ms = 12000", "slot_duration_ms = 0");
        std::fs::remove_file(dir.path().join("capture.toml")).unwrap();
        std::fs::write(dir.path().join("capture.toml"), zero).unwrap();
        let (code, _, err) = run_args(&["offsets", dir.path().to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("slot_duration_ms"), "{err}");
    }
}
