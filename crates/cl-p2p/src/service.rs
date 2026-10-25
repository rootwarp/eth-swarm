//! The `cl-p2p` process: what `ops/probe/ethswarm-p2p.service` runs.
//!
//! The unit passes no argument. The binary reads `/etc/ethswarm/cl-p2p.toml` ([`CONFIG_PATH`])
//! through the owner walk (`svc_runtime::Config::load_root_owned`), loads the node key from its
//! systemd credential ([`crate::identity`]), and runs until SIGTERM:
//!
//! - **cl-chain** (its socket, its server's UID checked): our Status from `GetStatus`
//!   ([`ChainStatusSource`]), the column answers from `DataColumnsByRange`/`ByRoot`
//!   ([`ChainColumns`]), and the custody subnets from `WatchSubscriptions`. The start waits for
//!   cl-chain up to `chain_wait_ms`, and for its first subscriptions. Then it refuses a key whose
//!   custody columns are not the ones cl-chain names ([`check_custody`]): cl-chain's `node_id`
//!   is then another key's. Each later body is held to the same key and group count.
//! - **The swarm** ([`swarm::serving_swarm`]): the ignore-all gossipsub on the topic list
//!   (`gossip_topics`) and the custody column subnets, under the fork digests that cl-chain's
//!   subscriptions name ([`digests::DigestTopics`]): a superseded digest's topics leave one
//!   epoch after its change, so the topic set stays within its bound across every change. And
//!   the req/resp responders.
//! - **cl-discv5** ([`peers::watch_peers`]): its record's `cgc` (`GetLocalEnr`) must be our
//!   custody group count. The candidates it finds, their addresses held to the `mode`'s IP
//!   rule, are dialled by the [`peers::Dialer`] up to `target_peers` of our own dials (inbound
//!   peers come in addition), with the static peers first and always. A dial waits for our
//!   first Status: a reference CL drops a peer that sends none.
//! - **The owner loop** ([`Owner`]): `p2p_peers{direction}` and `p2p_dial_failures_total`
//!   ([`PeerMetrics`]), identify logs, and the Goodbye ledger's feed ([`feed::run_feed`]), whose
//!   dropped events count on `p2p_ledger_feed_dropped_total` ([`feed::FeedSender`]).
//! - **Its own socket**: `ethswarm.p2p.v1` (still the stub), behind the method ACL of its
//!   config, with `/metrics`. The swarm's metrics keep their names (`Hooks::unprefixed`):
//!   `topic_msg_*`, `p2p_peers`, `p2p_goodbye_received_total`, and the rest.
//!
//! On SIGTERM the swarm sends Goodbye 1 (client shutdown) to every peer and gives the Goodbyes
//! [`GOODBYE_FLUSH`], the socket drains, and the process exits 0. A task that finds a fault of
//! the run stops the process the same way, with that fault's exit code.
//!
//! Exit codes, which `RestartPreventExitStatus=1 2 64` reads: 0 a clean stop; 1 a refused
//! credential or a start that a restart cannot fix (the swarm, the socket's bind, an ACL of
//! unserved methods, a cl-chain server of another user); 2 a refused config, custody columns
//! that are not our key's (at the start or later), or a cl-discv5 record of another `cgc`; 64
//! an argument; 69 cl-chain (its directory included) not there within `chain_wait_ms`, or a
//! clock before genesis (restarted); 70 a fault of the run that a restart can fix, such as a
//! topic set that cannot follow the fork digests (restarted); 71 no log writer (restarted).

pub mod backoff;
pub mod config;
pub mod digests;
pub mod feed;
pub mod peers;
pub mod swarm;

use crate::behaviour::{log_identify, SpecBehaviour, SpecBehaviourEvent};
use crate::custody::CustodySubscriptions;
use crate::peers::manager::GoodbyeLedger;
use crate::rpc::chain_status::{ChainStatus, ChainStatusSource, DEFAULT_STATUS_REFRESH};
use crate::rpc::columns::ChainColumns;
use crate::rpc::inbound::StatusSource;
use crate::rpc::limits::{RpcLimits, MAX_COLUMN_RESPONSE_BYTES};
use crate::transport::PeerMetrics;
use crate::P2pStub;
use config::P2pSettings;
use consensus_types::das::{
    custody_columns, CUSTODY_REQUIREMENT, NUMBER_OF_COLUMNS, NUMBER_OF_CUSTODY_GROUPS,
};
use consensus_types::primitives::{keccak256, U256};
use consensus_types::{EthSpec, Mainnet, Minimal};
use ethswarm_proto::chain as pb;
use feed::{FeedSender, FEED_CAPACITY};
use futures::StreamExt as _;
use ipc::frame::Inbound;
use ipc::hello::{NetworkHello, Preset};
use ipc::Link;
use libp2p::identity::Keypair;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, Swarm};
use pb::gossip_service_client::GossipServiceClient;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use svc_runtime::{Config, Hooks, Services};
use tokio::sync::{mpsc, watch};
use tonic::transport::Channel;

/// The config file of the deployed binary.
pub const CONFIG_PATH: &str = "/etc/ethswarm/cl-p2p.toml";

/// The environment variable that names the config of the test binary `cl-p2p-test`. The
/// `cl-p2p` binary never reads it.
pub const TEST_CONFIG_ENV: &str = "CL_P2P_TEST_CONFIG";

/// The service's name: its socket directory and its config table.
pub const SERVICE: &str = "cl-p2p";

/// The build string of our hellos and of identify.
pub const BUILD: &str = concat!("cl-p2p/", env!("CARGO_PKG_VERSION"));

/// A refused credential, or a start or run that a restart cannot fix.
pub const EXIT_FAILED: u8 = 1;
/// A refused config, or custody columns that are not our key's.
pub const EXIT_CONFIG: u8 = 2;
/// A command-line argument (`EX_USAGE`).
pub const EXIT_USAGE: u8 = 64;
/// A peer that the start needs is not there yet (`EX_UNAVAILABLE`): restarted.
pub const EXIT_UNAVAILABLE: u8 = 69;
/// A fault of the run that a restart can fix (`EX_SOFTWARE`): restarted.
pub const EXIT_SOFTWARE: u8 = 70;

/// Goodbye reason 1, "Client shut down" (`phase0/p2p-interface.md` §Goodbye).
pub const GOODBYE_SHUTDOWN: u64 = 1;

/// How long the Goodbyes of a shutdown get to go out.
pub const GOODBYE_FLUSH: Duration = Duration::from_secs(1);

/// How often the dialer looks for peers to dial.
pub const DIAL_EVERY: Duration = Duration::from_secs(2);

/// How long a connection with no open stream stays up.
pub const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// The discv5 node ID of `key`: keccak256 of its uncompressed secp256k1 public key, as the
/// spec's `uint256` (what `get_custody_groups` takes). `None` for a key of another type.
#[must_use]
pub fn node_id(key: &Keypair) -> Option<U256> {
    let public = key.public().try_into_secp256k1().ok()?;
    let point = public.to_bytes_uncompressed();
    Some(U256::from_be_bytes(keccak256(&point[1..]).0))
}

/// Why the custody columns that cl-chain names are refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    /// They are not the columns of our key.
    #[error(
        "cl-chain custodies columns {chain:?}, but our node key's are {ours:?}: set cl-chain's \
         node_id to this key's"
    )]
    NotOurs {
        /// The columns cl-chain names.
        chain: Vec<u64>,
        /// The columns of our key, for as many groups.
        ours: Vec<u64>,
    },
    /// They are fewer groups than `CUSTODY_REQUIREMENT`.
    #[error(
        "cl-chain custodies {groups} custody groups, fewer than CUSTODY_REQUIREMENT \
         ({CUSTODY_REQUIREMENT})"
    )]
    TooFew {
        /// The groups cl-chain names.
        groups: u64,
    },
}

/// Fails unless `subscriptions` names exactly the custody columns of `node_id` for its group
/// count (decision D4: cl-chain's `node_id` is ours), and at least `CUSTODY_REQUIREMENT` groups.
///
/// # Errors
///
/// [`CustodyError`].
pub fn check_custody(
    node_id: U256,
    subscriptions: &CustodySubscriptions,
) -> Result<u64, CustodyError> {
    let chain: Vec<u64> = subscriptions.columns().collect();
    let per_group = (NUMBER_OF_COLUMNS / NUMBER_OF_CUSTODY_GROUPS).max(1);
    let groups = chain.len() as u64 / per_group;
    let ours = custody_columns(node_id, groups).unwrap_or_default();
    if ours != chain || chain.len() as u64 != groups * per_group {
        return Err(CustodyError::NotOurs { chain, ours });
    }
    if groups < CUSTODY_REQUIREMENT {
        return Err(CustodyError::TooFew { groups });
    }
    Ok(groups)
}

/// Why [`serve`] stopped other than cleanly.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// cl-chain is not there yet, or the clock is before genesis: a restart can fix it.
    #[error("{0}")]
    Unavailable(String),
    /// The config does not fit this key or this cl-chain.
    #[error("{0}")]
    Config(String),
    /// The start failed in a way that a restart cannot fix.
    #[error("{0}")]
    Failed(String),
    /// A fault of the run that a restart can fix: the swarm's tasks did not end in time.
    #[error("{0}")]
    Software(String),
    /// The runtime stopped on an error.
    #[error("{0}")]
    Runtime(#[from] svc_runtime::RuntimeError),
}

impl ServeError {
    /// The exit code (see the module docs).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        use svc_runtime::RuntimeError;
        match self {
            Self::Unavailable(_) => EXIT_UNAVAILABLE,
            Self::Config(_) => EXIT_CONFIG,
            Self::Failed(_) => EXIT_FAILED,
            Self::Software(_) => EXIT_SOFTWARE,
            // The socket and the ACL do not fix themselves; every other fault of the run may.
            Self::Runtime(RuntimeError::Bind(_) | RuntimeError::UnservedMethods(_)) => EXIT_FAILED,
            Self::Runtime(RuntimeError::LogWriter(_)) => svc_runtime::telemetry::EXIT_NO_LOG_WRITER,
            Self::Runtime(_) => EXIT_SOFTWARE,
        }
    }
}

/// Why cl-chain at `socket` did not accept: a server of another user is a refusal that a restart
/// cannot fix ([`ServeError::Failed`]); a socket that is not there (its directory included) or
/// that nobody listens on is [`ServeError::Unavailable`].
#[must_use]
pub fn chain_unreachable(socket: &Path, err: &tonic::transport::Error) -> ServeError {
    let shown = format!("cl-chain at {}: {}", socket.display(), error_chain(err));
    if ipc::uds::peer_refusal(err).is_some() {
        ServeError::Failed(format!("{shown}: the server is not cl-chain's user"))
    } else {
        ServeError::Unavailable(shown)
    }
}

/// What cl-p2p runs with: its config, its `[p2p]` table and its network.
#[derive(Debug)]
pub struct Loaded {
    /// The config.
    pub config: Config,
    /// The `[p2p]` table.
    pub settings: P2pSettings,
    /// The network's hello.
    pub network: Arc<NetworkHello>,
}

/// Which binary runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Build {
    /// `cl-p2p`: [`CONFIG_PATH`], owned by root.
    Deployed,
    /// `cl-p2p-test`: the config at [`TEST_CONFIG_ENV`], which the test user may own, and a
    /// `/metrics` port that the OS picks.
    Test,
}

/// Loads the config of `build` for this process's effective UID.
///
/// # Errors
///
/// The config, its `[p2p]` table or its topic list is refused; the text names why.
pub fn load(build: Build) -> Result<Loaded, String> {
    let euid = ipc::peercred::effective_uid();
    let (config, accepted) = match build {
        Build::Deployed => (
            Config::load_root_owned(SERVICE, Path::new(CONFIG_PATH), euid, 0)
                .map_err(|e| e.to_string())?,
            0,
        ),
        Build::Test => {
            let path = std::env::var_os(TEST_CONFIG_ENV)
                .ok_or_else(|| format!("{TEST_CONFIG_ENV} is not set"))?;
            let config = Config::load_root_owned(SERVICE, Path::new(&path), euid, euid)
                .map_err(|e| e.to_string())?
                .with_ephemeral_metrics_port();
            (config, euid)
        }
    };
    let table: toml::Table = config.section().map_err(|e| e.to_string())?;
    let settings = P2pSettings::from_table(table, euid, accepted).map_err(|e| e.to_string())?;
    let genesis = config.genesis.ok_or_else(|| {
        format!(
            "the network {} has no pinned genesis: give network_dir",
            config.network.name()
        )
    })?;
    let network = NetworkHello::new(BUILD, &config.chain, genesis)
        .map(Arc::new)
        .map_err(|e| format!("the network: {e}"))?;
    Ok(Loaded {
        config,
        settings,
        network,
    })
}

/// The process: no argument, the config of `build`, the logs, the node key, the runtime; the
/// exit code.
#[must_use]
pub fn main(build: Build) -> u8 {
    use svc_runtime::lifecycle::LOG_FLUSH_DEADLINE;
    use svc_runtime::telemetry::{flush_logs, init_binary_tracing, EXIT_NO_LOG_WRITER};
    use tracing::level_filters::LevelFilter;
    let arguments = std::env::args_os().len().saturating_sub(1);
    let loaded = (arguments == 0).then(|| load(build));
    let level = match &loaded {
        Some(Ok(loaded)) => loaded.config.log_level,
        _ => LevelFilter::INFO,
    };
    if init_binary_tracing(level).is_err() {
        return EXIT_NO_LOG_WRITER;
    }
    let code = match loaded {
        None => {
            tracing::error!(
                arguments,
                config = CONFIG_PATH,
                "cl-p2p takes no argument: it reads its config file only"
            );
            EXIT_USAGE
        }
        // The credential first, as the unit's exit codes say: 1 before 2. A refusal is already
        // logged, without key material.
        Some(loaded) => match (crate::identity::load_from_env(), loaded) {
            (Err(_), _) => EXIT_FAILED,
            (Ok(_), Err(e)) => {
                tracing::error!(error = %e, "config refused");
                EXIT_CONFIG
            }
            (Ok(key), Ok(loaded)) => run_runtime(loaded, key.into_keypair()),
        },
    };
    flush_logs(LOG_FLUSH_DEADLINE);
    code
}

/// How long the swarm's tasks get to end after the runtime's drain.
const TASKS_END: Duration = Duration::from_secs(5);

/// [`run`] on a new multi-threaded runtime; the exit code.
fn run_runtime(loaded: Loaded, key: Keypair) -> u8 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return EXIT_FAILED;
        }
    };
    let code = match runtime.block_on(run(loaded, key)) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = %e, code = e.exit_code(), "cl-p2p stopped");
            e.exit_code()
        }
    };
    runtime.shutdown_timeout(TASKS_END);
    code
}

/// [`serve`] under the preset of the network, with systemd's notification and SIGTERM/SIGINT.
///
/// # Errors
///
/// As [`serve`].
pub async fn run(loaded: Loaded, key: Keypair) -> Result<(), ServeError> {
    let hooks = Hooks::systemd().map_err(|e| ServeError::Failed(format!("signals: {e}")))?;
    match loaded.network.preset() {
        Preset::Minimal => serve::<Minimal>(loaded, key, hooks).await,
        Preset::Mainnet => serve::<Mainnet>(loaded, key, hooks).await,
    }
}

/// Runs the service of `loaded` with `key` (see the module docs) until `hooks.shutdown`. Its
/// metrics go to `hooks.unprefixed`. A stop during the start is a clean stop.
///
/// # Errors
///
/// cl-chain did not accept or send its subscriptions within `chain_wait_ms`
/// ([`ServeError::Unavailable`]), the custody columns are not our key's or cl-discv5's record
/// has another `cgc` ([`ServeError::Config`]), the swarm could not be built, a task of the run
/// found a fault, or the runtime stopped on an error.
pub async fn serve<E: EthSpec>(
    loaded: Loaded,
    key: Keypair,
    mut hooks: Hooks,
) -> Result<(), ServeError> {
    let Loaded {
        config,
        settings,
        network,
    } = loaded;
    if let Err(e) = network.at(ipc::hello::system_ms()) {
        return Err(ServeError::Unavailable(format!("our fork digest: {e}")));
    }
    let link = Link::network(Arc::clone(&network), 1)
        .map_err(|e| ServeError::Failed(format!("the digest schedule: {e}")))?;
    let node = node_id(&key).ok_or_else(|| ServeError::Failed("not a secp256k1 key".into()))?;
    let (stop_tx, stop) = watch::channel(false);

    // cl-chain first: our Status, our custody, our column answers.
    let wait = settings.chain_wait;
    let socket = settings.chain_socket.clone();
    let connect = ipc::uds::connect_path_waiting(&socket, settings.chain_uid, wait, || {
        tracing::info!(socket = %socket.display(), wait_ms = wait.as_millis() as u64,
            "cl-chain is not accepting yet; trying again until the wait is over");
    });
    let chain = tokio::select! {
        () = &mut hooks.shutdown => {
            tracing::info!("stopped before cl-chain accepted");
            return Ok(());
        }
        chain = connect => chain.map_err(|e| chain_unreachable(&settings.chain_socket, &e))?,
    };
    let (subs_tx, mut subs_rx) = mpsc::channel(4);
    let watching_subs = tokio::spawn(watch_subscriptions(
        chain.clone(),
        link.clone(),
        subs_tx,
        stop.clone(),
    ));
    let first = tokio::select! {
        () = &mut hooks.shutdown => {
            watching_subs.abort();
            return Ok(());
        }
        first = tokio::time::timeout(wait, subs_rx.recv()) => first,
    };
    let Ok(Some(first)) = first else {
        watching_subs.abort();
        return Err(ServeError::Unavailable(
            "no custody subscriptions from cl-chain within chain_wait_ms".into(),
        ));
    };
    let groups = match check_custody(node, &first) {
        Ok(groups) => groups,
        Err(e) => {
            watching_subs.abort();
            return Err(ServeError::Config(e.to_string()));
        }
    };
    let status = ChainStatusSource::new(ChainStatus::new(chain.clone()));
    let refresh = status.keep_current(DEFAULT_STATUS_REFRESH);
    // One epoch: how long the topics of a superseded digest stay.
    let grace = Duration::from_millis(
        network
            .config()
            .slot_duration_ms()
            .saturating_mul(E::slots_per_epoch()),
    );
    let mut digest_topics =
        digests::DigestTopics::new(settings.topics.clone(), grace, first.clone());
    let topics = digest_topics.start_topics();
    tracing::info!(
        peer_id = %key.public().to_peer_id(),
        columns = ?first.columns().collect::<Vec<_>>(),
        topics = topics.len(),
        "custody columns are our key's"
    );
    let sources = swarm::Sources {
        status: Arc::new(status.clone()) as Arc<dyn StatusSource>,
        custody_group_count: groups,
        columns: Some(Arc::new(ChainColumns::new(
            chain,
            link.clone(),
            MAX_COLUMN_RESPONSE_BYTES,
        ))),
    };
    let plan = swarm::SwarmPlan {
        listen: settings.listen.clone(),
        idle: IDLE_CONNECTION_TIMEOUT,
        bypass: settings.static_peers.iter().map(|p| p.peer_id).collect(),
        muxer_observer: None,
        ping_interval: crate::rpc::inbound::PING_INTERVAL,
        gossip: None,
        limits: RpcLimits {
            column_answer_prefixes: settings.answer_prefixes,
            ..RpcLimits::default()
        },
    };
    let gossip = swarm::Gossip { topics, tap: None };
    let genesis = network.genesis();
    let swarm = swarm::serving_swarm::<E>(
        network.config(),
        &genesis,
        key,
        sources,
        plan,
        Some(gossip),
        &mut hooks.unprefixed,
    )
    .map_err(ServeError::Failed)?;
    let peer_metrics = PeerMetrics::register(&mut hooks.unprefixed);
    let ledger = GoodbyeLedger::new(settings.goodbye_ledger)
        .map_err(|e| ServeError::Config(format!("goodbye_ledger: {e}")))?;
    let (feed_tx, feed_rx) = mpsc::channel(FEED_CAPACITY);
    let feeding = tokio::spawn(feed::run_feed(
        ledger,
        feed_rx,
        stop.clone(),
        Box::new(SystemTime::now),
    ));
    let (fatal, mut faults) = mpsc::channel::<ServeError>(1);
    let (candidates_tx, candidates) = mpsc::channel(peers::MAX_CANDIDATES);
    let watching_peers = tokio::spawn(fail_on(
        fatal.clone(),
        peers::watch_peers(
            peers::Discv5Peer {
                socket: settings.discv5_socket.clone(),
                uid: settings.discv5_uid,
                mode: settings.mode,
                groups,
            },
            link.clone(),
            candidates_tx,
            stop.clone(),
        ),
    ));
    let owner = Owner {
        swarm,
        peer_metrics,
        dialer: peers::Dialer::new(settings.target_peers, settings.static_peers.clone()),
        feed: FeedSender::new(feed_tx, &mut hooks.unprefixed),
        status: Arc::new(status),
        topics: digest_topics,
        node,
        groups,
    };
    let driving = tokio::spawn(fail_on(fatal, owner.drive(candidates, subs_rx, stop)));

    let services = Services::new().add_service(
        ethswarm_proto::p2p::network_service_server::NetworkServiceServer::new(P2pStub::new(link)),
    );
    // The stop: SIGTERM, or the first fault of a task that must stop the process.
    let (failed_tx, mut failed) = tokio::sync::oneshot::channel::<ServeError>();
    let shutdown = std::mem::replace(&mut hooks.shutdown, Box::pin(std::future::pending()));
    hooks.shutdown = Box::pin(async move {
        tokio::select! {
            () = shutdown => {}
            Some(e) = faults.recv() => {
                tracing::error!(error = %e, code = e.exit_code(), "stopping on a fault of the run");
                let _ = failed_tx.send(e);
            }
        }
        stop_tx.send_replace(true);
    });
    let result = svc_runtime::run_with(config, services, hooks).await;
    // The swarm says Goodbye, the feed and the streams end (the stop, or its sender gone),
    // within a limit. Tasks that do not end in time are 70, unless the run itself failed.
    let ended = tasks_end(
        async {
            let _ = driving.await;
            let _ = feeding.await;
            let _ = watching_peers.await;
            let _ = watching_subs.await;
        },
        TASKS_END,
    )
    .await;
    refresh.abort();
    if let Ok(e) = failed.try_recv() {
        return Err(e);
    }
    result.map_err(ServeError::from)?;
    ended
}

/// Runs `task`; its fault goes to `fatal`, which stops the process (the first fault wins).
async fn fail_on(
    fatal: mpsc::Sender<ServeError>,
    task: impl std::future::Future<Output = Result<(), ServeError>>,
) {
    if let Err(e) = task.await {
        let _ = fatal.try_send(e);
    }
}

/// A fork digest as 8 lowercase hex digits, as in a topic.
fn hex4(digest: &[u8; 4]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Waits for `tasks` to end, `limit` at most.
///
/// # Errors
///
/// [`ServeError::Software`] (70) if they did not end in time.
pub async fn tasks_end(
    tasks: impl std::future::Future<Output = ()>,
    limit: Duration,
) -> Result<(), ServeError> {
    if tokio::time::timeout(limit, tasks).await.is_ok() {
        return Ok(());
    }
    tracing::warn!(
        limit_ms = limit.as_millis() as u64,
        "the swarm's tasks did not end in time"
    );
    Err(ServeError::Software(format!(
        "the swarm's tasks did not end within {limit:?} of the drain"
    )))
}

/// `err` and each error in its source chain, joined by `": "`.
fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut shown = err.to_string();
    let mut next = err.source();
    while let Some(e) = next {
        shown.push_str(": ");
        shown.push_str(&e.to_string());
        next = e.source();
    }
    shown
}

/// Reads cl-chain's `WatchSubscriptions` over `chain` into `bodies` (each checked,
/// [`CustodySubscriptions::from_chain`]; a body that breaks the contract fails the stream)
/// until `stop` turns true or its sender goes, or `bodies` closes, opening it again after
/// each end or failure ([`backoff::Backoff`]: 1 s, doubled to 30 s, and 1 s again after a
/// stream that delivered a body).
pub async fn watch_subscriptions(
    chain: Channel,
    link: Link,
    bodies: mpsc::Sender<CustodySubscriptions>,
    mut stop: watch::Receiver<bool>,
) {
    let mut backoff = backoff::Backoff::default();
    loop {
        if *stop.borrow_and_update() {
            return;
        }
        let mut delivered = 0usize;
        let read = read_subscriptions(&chain, &link, &bodies, &mut delivered);
        let ended = tokio::select! {
            ended = read => ended,
            _ = stop.changed() => return,
        };
        match ended {
            Ok(()) => tracing::info!(
                bodies = delivered,
                "cl-chain's WatchSubscriptions stream ended"
            ),
            Err(e) => tracing::warn!(error = %e, bodies = delivered,
                "cl-chain's WatchSubscriptions stream failed"),
        }
        if bodies.is_closed() {
            return;
        }
        tokio::select! {
            () = tokio::time::sleep(backoff.after(delivered > 0)) => {}
            _ = stop.changed() => return,
        }
    }
}

/// One `WatchSubscriptions` stream into `bodies`, counting the bodies it `delivered`, until it
/// ends or `bodies` closes.
async fn read_subscriptions(
    chain: &Channel,
    link: &Link,
    bodies: &mpsc::Sender<CustodySubscriptions>,
    delivered: &mut usize,
) -> Result<(), String> {
    let stream = GossipServiceClient::new(chain.clone())
        .watch_subscriptions(pb::WatchSubscriptionsRequest {
            hello: Some(link.local()),
        })
        .await
        .map_err(|e| format!("WatchSubscriptions: {}", e.message()))?
        .into_inner();
    let mut guarded = link
        .open(Inbound::from_server(stream))
        .await
        .map_err(|e| format!("WatchSubscriptions: {e}"))?;
    while let Some(accepted) = guarded
        .body()
        .await
        .map_err(|e| format!("WatchSubscriptions: {e}"))?
    {
        let checked = CustodySubscriptions::from_chain(&accepted.body)
            .map_err(|e| format!("WatchSubscriptions body: {e}"))?;
        if bodies.send(checked).await.is_err() {
            return Ok(());
        }
        *delivered += 1;
    }
    Ok(())
}

/// The owner of the swarm: it drives it and keeps what it learns (see the module docs).
pub struct Owner<E: EthSpec> {
    swarm: Swarm<SpecBehaviour<E>>,
    peer_metrics: PeerMetrics,
    dialer: peers::Dialer,
    feed: FeedSender,
    /// Our Status: no dial goes out before there is one.
    status: Arc<dyn StatusSource>,
    /// The fork digests whose topics are subscribed.
    topics: digests::DigestTopics,
    /// Our discv5 node ID: each subscriptions body must name its custody columns.
    node: U256,
    /// The custody group count of our MetaData: each body must name as many groups.
    groups: u64,
}

impl<E: EthSpec> Owner<E> {
    /// Drives the swarm until `stop`: its events, the candidates, the subscriptions and the
    /// dials. Then it says Goodbye to every peer and gives that [`GOODBYE_FLUSH`].
    ///
    /// # Errors
    ///
    /// A subscriptions body that is not our custody (`Owner::check`, exit 2), or a topic set
    /// that cannot follow the fork digests (exit 70): the owner says Goodbye and stops, and so
    /// must the process.
    pub async fn drive(
        mut self,
        mut candidates: mpsc::Receiver<peers::Candidate>,
        mut subscriptions: mpsc::Receiver<CustodySubscriptions>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), ServeError> {
        let mut dials = tokio::time::interval(DIAL_EVERY);
        dials.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let ended = loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break Ok(());
                    }
                }
                event = self.swarm.select_next_some() => self.on_event(event),
                Some(candidate) = candidates.recv() => self.dialer.add(candidate),
                Some(body) = subscriptions.recv() => {
                    if let Err(e) = self.check(&body) {
                        break Err(e);
                    }
                    self.topics.set_body(body);
                    if let Err(e) = self.follow_digests() {
                        break Err(e);
                    }
                }
                _ = dials.tick() => {
                    self.feed.flush();
                    if let Err(e) = self.follow_digests() {
                        break Err(e);
                    }
                    self.dial();
                }
            }
        };
        self.goodbye().await;
        ended
    }

    /// Holds a subscriptions body to our key ([`check_custody`]) and to the group count of our
    /// MetaData, as the first body was at the start (decision D4).
    ///
    /// # Errors
    ///
    /// [`ServeError::Config`]: cl-chain's `node_id` or custody group count changed under us.
    fn check(&self, body: &CustodySubscriptions) -> Result<(), ServeError> {
        let groups =
            check_custody(self.node, body).map_err(|e| ServeError::Config(e.to_string()))?;
        if groups != self.groups {
            return Err(ServeError::Config(format!(
                "cl-chain changed its custody group count from {} to {groups}: our MetaData and \
                 record carry {}; restart cl-chain, cl-discv5 and cl-p2p on one cgc",
                self.groups, self.groups
            )));
        }
        Ok(())
    }

    fn on_event(&mut self, event: SwarmEvent<SpecBehaviourEvent<E>>) {
        self.peer_metrics.observe(&event);
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => self.dialer.connected(peer_id, endpoint.is_dialer()),
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                self.dialer.disconnected(&peer_id);
                self.feed.disconnected(peer_id);
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                ..
            } => self.dialer.failed(&peer),
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(%address, "listening");
            }
            SwarmEvent::Behaviour(SpecBehaviourEvent::ReqResp(event)) => self.feed.control(event),
            SwarmEvent::Behaviour(SpecBehaviourEvent::Identify(event)) => {
                log_identify(&event);
                if let identify::Event::Received { peer_id, info, .. } = event {
                    self.feed.identified(peer_id, info.agent_version);
                }
            }
            _ => {}
        }
    }

    /// Brings the gossip topics to the last subscriptions body ([`digests::DigestTopics`]):
    /// the digests past their grace retire, the new ones are subscribed.
    ///
    /// # Errors
    ///
    /// [`ServeError::Software`]: the topics of the current digest do not fit, or gossipsub
    /// refused a topic. The topic set would no longer follow the chain.
    fn follow_digests(&mut self) -> Result<(), ServeError> {
        let Some(gossip) = self.swarm.behaviour_mut().gossipsub.as_mut() else {
            return Ok(());
        };
        let followed = self
            .topics
            .follow(gossip, tokio::time::Instant::now())
            .map_err(|e| ServeError::Software(format!("the gossip topics: {e}")))?;
        if !followed.retired.is_empty() || followed.subscribed > 0 {
            tracing::info!(
                retired = ?followed.retired.iter().map(hex4).collect::<Vec<_>>(),
                subscribed = followed.subscribed,
                topics = gossip.subscribed_len(),
                whitelist = gossip.whitelist_len(),
                "the gossip topics follow the fork digests"
            );
        }
        if !followed.deferred.is_empty() {
            tracing::debug!(
                deferred = ?followed.deferred.iter().map(hex4).collect::<Vec<_>>(),
                "a fork digest waits for room in the topic set"
            );
        }
        Ok(())
    }

    /// Dials the peers the dialer says are due, once we have a Status.
    fn dial(&mut self) {
        if self.status.status().is_none() {
            return;
        }
        for (peer, addrs) in self.dialer.due(tokio::time::Instant::now()) {
            let opts = DialOpts::peer_id(peer).addresses(addrs).build();
            if let Err(e) = self.swarm.dial(opts) {
                self.peer_metrics.observe_dial_error(&e);
                self.dialer.failed(&peer);
            }
        }
    }

    /// Goodbye 1 to every connected peer, then the swarm runs [`GOODBYE_FLUSH`] more.
    async fn goodbye(&mut self) {
        let peers: Vec<_> = self.swarm.connected_peers().copied().collect();
        for peer in &peers {
            self.swarm
                .behaviour_mut()
                .req_resp
                .goodbye(*peer, GOODBYE_SHUTDOWN);
        }
        tracing::info!(peers = peers.len(), "stopping: Goodbye sent to every peer");
        let flush = tokio::time::sleep(GOODBYE_FLUSH);
        tokio::pin!(flush);
        loop {
            tokio::select! {
                () = &mut flush => break,
                event = self.swarm.select_next_some() => self.peer_metrics.observe(&event),
            }
        }
    }
}

#[cfg(test)]
mod tests;
