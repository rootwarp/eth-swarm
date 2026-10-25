//! cl-chain in probe mode as one service: the column store, the column server over it, our
//! Status and the custody subscriptions, all on `ethswarm.chain.v1`.
//!
//! - **The network** ([`ProbeNetwork`]): the config, the genesis and the network hello
//!   (`ipc::hello::NetworkHello`) of the network that the probe runs on.
//! - **The service** ([`ProbeService`]):
//!   - the column store ([`ColumnIngest`]): the reference node vouches for each block root,
//!     cl-verify checks the cells by KZG, and only custody columns are kept;
//!   - the reference follower ([`ColumnIngest::follow_head`]): the reference's `block` events
//!     announce its roots ahead of their columns, and its `head`, `chain_reorg` and
//!     `finalized_checkpoint` events keep its canonical chain, which range answers follow.
//!     With the wall clock they prune the store of the blocks off the finalized chain and of
//!     the columns out of retention;
//!   - the column server ([`ColumnServer`]) and our Status ([`StatusProvider`], its
//!     `earliest_available_slot` the column server's), on `ReqRespService`
//!     ([`ReqRespServer`]);
//!   - the custody subscriptions on `GossipService/WatchSubscriptions` ([`GossipServer`]).
//!
//!   The store is opened in its directory, and opened again after a restart: the custody
//!   record in it keeps the custody group count and `cgc_set_slot` of the first start.
//! - **The method ACL** ([`chain_acl`]): only the caller `cl-p2p`, by its UID, may call
//!   [`CHAIN_METHODS`], and nothing else.
//! - **The KZG link** ([`connect_verify`], [`verify_client`]): cl-verify's socket, whose
//!   directory other users cannot change ([`check_verify_socket_dir`]) and whose server must run
//!   as cl-verify's UID.
//!
//! The service itself binds no socket: [`ProbeService::routes`] are served by the caller (the
//! `cl-chain` binary through `svc_runtime::run_with`, `devnet-probe serve` on a socket of its
//! own), behind [`chain_acl`].

use crate::da::custody::{Advertise, Custody, EnrCgc, EnrError};
use crate::probe::{
    BeaconApi, ColumnContract, ColumnIngest, ColumnMetrics, GossipColumn, HeadFollow, IngestLimits,
    ProbeChain, QueueMetrics, RefLimits, RefView, ServedColumns, StatusProvider,
    DEFAULT_API_TIMEOUT,
};
use crate::reqresp::{
    ChainStatus, ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock, WallClock,
};
use crate::verify::client::{KzgClient, KzgVerifier};
use crate::ChainStub;
use cl_chain_columns::{ColumnReader, ColumnWriter};
use consensus_types::caps::NetworkCaps;
use consensus_types::primitives::U256;
use consensus_types::{forked, EthSpec};
use ethswarm_proto::chain as pb;
use ethswarm_proto::verify::verify_service_client::VerifyServiceClient;
use ipc::acl::{AclTables, MethodAcl};
use ipc::envelope::DigestTable;
use ipc::frame::OutFrame;
use ipc::hello::{stream_hello, NetworkHello, NetworkHelloError, Preset};
use ipc::stub::StubStream;
use ipc::Link;
use network_config::digest::{compute_fork_digest, current_epoch, digest_schedule, DigestError};
use network_config::{ChainConfig, Epoch, Genesis};
use pb::gossip_service_server::{GossipService, GossipServiceServer};
use prometheus_client::registry::Registry;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::service::Routes;
use tonic::{Request, Response, Status, Streaming};

/// The service that serves `ethswarm.chain.v1`, and its socket directory's name.
pub const CHAIN_SERVICE: &str = "cl-chain";

/// The one caller of cl-chain's socket: cl-p2p.
pub const P2P_CALLER: &str = "cl-p2p";

/// The `ethswarm.chain.v1` methods that cl-p2p calls, and only those: our Status, the custody
/// columns by range and by root, and the custody subscriptions.
pub const CHAIN_METHODS: [&str; 4] = [
    "/ethswarm.chain.v1.ReqRespService/GetStatus",
    "/ethswarm.chain.v1.ReqRespService/DataColumnsByRange",
    "/ethswarm.chain.v1.ReqRespService/DataColumnsByRoot",
    "/ethswarm.chain.v1.GossipService/WatchSubscriptions",
];

/// The file in the store's directory that holds the node ID the store's custody follows: written
/// on the store's first open (mode 0600), compared on every open after it.
pub const NODE_ID_FILE: &str = "node-id";

/// The `WatchSubscriptions` streams open at once at most \[est\]: cl-p2p holds one, and a
/// reconnect may briefly hold a second.
pub const MAX_WATCHERS: usize = 4;

/// How long cl-verify may take for one column's cells \[est\].
pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long cl-chain waits for cl-verify's socket to accept a connection \[est\]: a cl-verify
/// started a moment before loads its trusted setup before it binds.
pub const VERIFY_SOCKET_WAIT: Duration = Duration::from_secs(30);

/// The pause between two connection attempts to cl-verify's socket.
const VERIFY_SOCKET_RETRY: Duration = Duration::from_millis(200);

/// How long a reference sample is reused for our Status \[est\]: every Status that goes out
/// reads the store again, the reference API at most every 2 s.
pub const STATUS_SAMPLE_REUSE: Duration = Duration::from_secs(2);

/// The `api_version` of the chain.v1 and verify.v1 links.
pub const API_VERSION: u32 = 1;

/// How many epochs before a fork digest change the subscriptions name the next digest
/// \[est\]: cl-p2p joins the column subnets under it before the change, so it misses no column
/// of the first slots after it.
pub const SUBSCRIBE_AHEAD: Epoch = 2;

/// Unix milliseconds of the system clock.
#[must_use]
pub fn system_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// The network the probe runs on: its config, its genesis and its network hello, which gives
/// its preset.
#[derive(Debug, Clone)]
pub struct ProbeNetwork {
    config: ChainConfig,
    genesis: Genesis,
    hello: Arc<NetworkHello>,
}

impl ProbeNetwork {
    /// The network of `config` and `genesis`, whose hellos carry `build`.
    ///
    /// # Errors
    ///
    /// The config gives no network hello ([`NetworkHello::new`]): its `PRESET_BASE` is
    /// neither `minimal` nor `mainnet`, its `SLOT_DURATION_MS` is 0, or it schedules no Fulu.
    pub fn new(
        build: &str,
        config: ChainConfig,
        genesis: Genesis,
    ) -> Result<Self, NetworkHelloError> {
        let hello = Arc::new(NetworkHello::new(build, &config, genesis)?);
        Ok(Self {
            config,
            genesis,
            hello,
        })
    }

    /// The config.
    #[must_use]
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// The genesis time and validators root.
    #[must_use]
    pub fn genesis(&self) -> Genesis {
        self.genesis
    }

    /// The network hello: the hello of the chain.v1 and verify.v1 links. cl-verify builds its
    /// own from the same files in the same way, so the two differ only in `build`.
    #[must_use]
    pub fn hello(&self) -> &Arc<NetworkHello> {
        &self.hello
    }

    /// The preset that `PRESET_BASE` names.
    #[must_use]
    pub fn preset(&self) -> Preset {
        self.hello.preset()
    }

    /// `SLOTS_PER_EPOCH` of the preset.
    #[must_use]
    pub fn slots_per_epoch(&self) -> u64 {
        self.hello.slots_per_epoch()
    }

    /// The wall-clock epoch at `now_ms` (Unix milliseconds).
    ///
    /// # Errors
    ///
    /// The clock is before genesis.
    pub fn epoch_at(&self, now_ms: u128) -> Result<Epoch, DigestError> {
        current_epoch(
            self.genesis.genesis_time,
            self.config.slot_duration_ms(),
            self.slots_per_epoch(),
            now_ms,
        )
    }

    /// The wall-clock slot at `now_ms`; `None` before genesis.
    #[must_use]
    pub fn slot_at(&self, now_ms: u128) -> Option<u64> {
        let since = now_ms.checked_sub(u128::from(self.genesis.genesis_time) * 1000)?;
        let slot_ms = u128::from(self.config.slot_duration_ms().max(1));
        u64::try_from(since / slot_ms).ok()
    }

    /// When `epoch` starts, as Unix milliseconds.
    #[must_use]
    pub fn epoch_start_ms(&self, epoch: Epoch) -> u128 {
        u128::from(self.genesis.genesis_time) * 1000
            + u128::from(epoch)
                * u128::from(self.slots_per_epoch())
                * u128::from(self.config.slot_duration_ms())
    }

    /// `compute_fork_digest(epoch)` on the BPO-aware schedule; `None` before Fulu.
    #[must_use]
    pub fn digest_at(&self, epoch: Epoch) -> Option<[u8; 4]> {
        compute_fork_digest(&self.config, &self.genesis.genesis_validators_root, epoch).ok()
    }

    /// The network for our Status ([`StatusProvider`]) and the serve clock ([`WallClock`]).
    #[must_use]
    pub fn probe_chain(&self) -> ProbeChain {
        ProbeChain {
            config: self.config.clone(),
            genesis: self.genesis,
            slots_per_epoch: self.slots_per_epoch(),
        }
    }
}

/// The chain.v1 link that both ends of cl-chain's socket hold: the network hello at `now_ms`
/// and every digest of the schedule.
///
/// # Errors
///
/// The clock is before genesis or Fulu, or the schedule has no digest.
pub fn chain_link<E: EthSpec>(net: &ProbeNetwork, now_ms: u128) -> Result<Link, String> {
    let hello = net
        .hello()
        .at(now_ms)
        .map_err(|e| format!("our fork digest: {e}"))?;
    let digests = DigestTable::new(
        digest_schedule(net.config(), &net.genesis().genesis_validators_root)
            .iter()
            .map(|e| (e.epoch, e.fork, e.fork_digest))
            .collect(),
    )
    .map_err(|e| format!("the digest schedule: {e}"))?;
    Ok(Link::new::<E>(
        hello,
        API_VERSION,
        *net.config().fork_schedule(),
        digests,
    ))
}

/// cl-chain's side of the verify.v1 link on `channel`: a KZG client that opens each stream
/// with the network hello at the time of the stream open ([`KzgClient::network`]). That hello
/// equals the one that cl-verify sends for `--network-dir` of the same network, apart from
/// `build`, before and after each fork or BPO digest change.
#[must_use]
pub fn verify_client(net: &ProbeNetwork, channel: tonic::transport::Channel) -> KzgClient {
    KzgClient::network(VerifyServiceClient::new(channel), Arc::clone(net.hello()))
}

/// cl-chain's method ACL: [`CHAIN_METHODS`] to [`P2P_CALLER`] at `caller_uid`, nothing else.
///
/// # Errors
///
/// The ACL does not load (it always does).
pub fn chain_acl(caller_uid: u32) -> Result<MethodAcl, String> {
    let tables = AclTables {
        callers: [(P2P_CALLER.to_owned(), caller_uid)].into(),
        methods: CHAIN_METHODS
            .iter()
            .map(|m| ((*m).to_owned(), vec![P2P_CALLER.to_owned()]))
            .collect(),
    };
    MethodAcl::from_tables(CHAIN_SERVICE, &tables).map_err(|e| e.to_string())
}

/// Refuses a verify socket whose directory other users could change, or the way to it
/// ([`ipc::uds::open_closed_dir`], as for the socket root and the store's parent): walked from
/// `/` without following a symlink, it and every directory above it must be owned by `uid`
/// (cl-verify's user) or root, and not group or world writable unless sticky. The directory
/// itself must be writable only by its owner, also when it is sticky, as the socket root.
/// Otherwise another user could put a socket of their own in its place. The connector refuses a
/// server of another user anyway, so such a socket could only stop the run. A relative
/// `socket` is taken from the working directory.
///
/// # Errors
///
/// The directory is not closed, cannot be opened, or `socket` names no file in it.
pub fn check_verify_socket_dir(socket: &Path, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let shown = socket.display();
    let path = std::env::current_dir()
        .map_err(|e| format!("verify socket {shown}: the working directory: {e}"))?
        .join(socket);
    let (Some(dir), Some(_)) = (path.parent(), path.file_name()) else {
        return Err(format!("verify socket {shown} names no file"));
    };
    let fd =
        ipc::uds::open_closed_dir(dir, uid).map_err(|e| format!("verify socket directory {e}"))?;
    // The directory itself, as the socket root ([`ipc::uds::bind`]): writable only by its
    // owner, sticky or not. In a sticky directory that others can write (`/tmp`), another
    // user could create the socket name first.
    let meta = std::fs::File::from(fd)
        .metadata()
        .map_err(|e| format!("verify socket directory {}: {e}", dir.display()))?;
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "verify socket directory {} must be writable only by its owner (mode {mode:o})",
            dir.display()
        ));
    }
    Ok(())
}

/// A channel to cl-verify at `path`, which must run as `uid` ([`ipc::uds::connect_path`]). While
/// the socket is not there yet or refuses connections ([`is_not_ready`]), the connection is
/// tried again every 200 ms until `wait` is over, and the wait is logged once. Any other error
/// (a server of another user included) is returned at once.
///
/// # Errors
///
/// The last connection error. [`error_chain`] shows it with its causes.
pub async fn connect_verify(
    path: &Path,
    uid: u32,
    wait: Duration,
) -> Result<tonic::transport::Channel, tonic::transport::Error> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut logged = false;
    loop {
        match ipc::uds::connect_path(path, uid).await {
            Ok(channel) => return Ok(channel),
            Err(e)
                if is_not_ready(&e)
                    && tokio::time::Instant::now() + VERIFY_SOCKET_RETRY <= deadline =>
            {
                if !logged {
                    tracing::info!(
                        socket = %path.display(),
                        wait_ms = wait.as_millis() as u64,
                        retry_ms = VERIFY_SOCKET_RETRY.as_millis() as u64,
                        "cl-verify is not accepting yet; trying again until the wait is over"
                    );
                    logged = true;
                }
                tokio::time::sleep(VERIFY_SOCKET_RETRY).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Whether `err` is a socket that is not there yet (`NotFound`) or that nobody listens on yet
/// (`ConnectionRefused`), anywhere in its source chain. A peer check that failed
/// ([`ipc::uds::peer_refusal`]) is never "not ready", whatever I/O error it carries.
#[must_use]
pub fn is_not_ready(err: &(dyn std::error::Error + 'static)) -> bool {
    if ipc::uds::peer_refusal(err).is_some() {
        return false;
    }
    let mut next = Some(err);
    while let Some(e) = next {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) {
                return true;
            }
        }
        next = e.source();
    }
    false
}

/// `err` and each error in its source chain, joined by `": "`. A tonic transport error alone
/// shows only "transport error".
#[must_use]
pub fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut shown = err.to_string();
    let mut next = err.source();
    while let Some(e) = next {
        shown.push_str(": ");
        shown.push_str(&e.to_string());
        next = e.source();
    }
    shown
}

/// Opens the column store's directory at `path`, mode 0700, for the user `uid`: created if it
/// is not there, used again if it is (a restart). Its parent and every directory above it must
/// be closed to other users ([`ipc::uds::open_closed_dir`]: owned by `uid` or root, not group
/// or world writable unless sticky). An existing `path` must be a directory, not a symlink,
/// owned by `uid`, that the group and others cannot write.
///
/// # Errors
///
/// The path is relative or names no directory, its parent is not closed, or `path` is not
/// such a directory.
pub fn open_store_dir(path: &Path, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let shown = path.display();
    if !path.is_absolute() {
        return Err(format!("column store {shown} must be an absolute path"));
    }
    let (Some(parent), Some(_)) = (path.parent(), path.file_name()) else {
        return Err(format!("column store {shown} names no directory"));
    };
    ipc::uds::open_closed_dir(parent, uid).map_err(|e| format!("column store parent {e}"))?;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => tracing::info!(path = %shown, "column store created"),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("column store {shown}: {e}")),
    }
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("column store {shown}: {e}"))?;
    let mode = meta.mode() & 0o7777;
    if !meta.is_dir() || meta.uid() != uid || mode & 0o022 != 0 {
        return Err(format!(
            "column store {shown} must be a directory owned by UID {uid} that only it can \
             write (found: {}, owner UID {}, mode {mode:04o})",
            if meta.is_dir() {
                "a directory"
            } else {
                "not a directory"
            },
            meta.uid()
        ));
    }
    Ok(())
}

/// The probe publishes no ENR from cl-chain: the custody group count reaches cl-discv5 another
/// way.
pub struct NoEnr;

impl EnrCgc for NoEnr {
    fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
        Ok(())
    }
}

/// What [`ProbeService::open`] needs.
pub struct ProbePlan<V> {
    /// The link both ends of the socket hold ([`chain_link`]).
    pub link: Link,
    /// Our node ID: the custody columns.
    pub node_id: U256,
    /// The column store's directory. It must exist ([`open_store_dir`]).
    pub columns_dir: PathBuf,
    /// The reference node's beacon API: the block roots it vouches for, and our Status.
    pub reference: BeaconApi,
    /// cl-verify's KZG checks.
    pub kzg: V,
    /// How long one KZG check may take.
    pub verify_timeout: Duration,
    /// The slot custody is set at on a new store: columns are stored from there on. A store
    /// opened again keeps the slot of its first start.
    pub cgc_set_slot: u64,
}

/// The column store of cl-chain's probe mode.
type Ingest<E, V> = ColumnIngest<BeaconApi, E, V, Arc<ColumnWriter>, NoEnr>;

/// Why [`ProbeService::open`] failed.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The store holds the custody of another node ID: its columns are another key's.
    #[error(
        "the column store {} is of node ID {stored}, not {configured}: the custody columns \
         follow the node ID, so clear the store (remove the directory) to start with this one, \
         or set node_id back",
        dir.display()
    )]
    NodeIdChanged {
        /// The store's directory.
        dir: PathBuf,
        /// The node ID the store was opened with first.
        stored: String,
        /// The node ID given now.
        configured: String,
    },
    /// Any other failure.
    #[error("{0}")]
    Failed(String),
}

impl From<String> for OpenError {
    fn from(why: String) -> Self {
        Self::Failed(why)
    }
}

impl From<OpenError> for String {
    fn from(e: OpenError) -> Self {
        e.to_string()
    }
}

/// `0x` and the 64 hex digits of `node_id`.
fn node_id_text(node_id: U256) -> String {
    format!("0x{}", hex::encode(node_id.to_be_bytes::<32>()))
}

/// Holds the store in `dir` to `node_id`: the first open writes it to [`NODE_ID_FILE`] (a
/// temporary file, synced, then renamed, mode 0600); every later open reads it back (a regular
/// file, the one looked at and not a symlink, at most 128 bytes) and refuses another node ID.
fn claim_node_id(dir: &Path, node_id: U256) -> Result<(), OpenError> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = dir.join(NODE_ID_FILE);
    let want = node_id_text(node_id);
    let failed = |why: String| OpenError::Failed(format!("{}: {why}", path.display()));
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if !meta.file_type().is_file() => Err(failed("not a regular file".into())),
        Ok(seen) => {
            use std::os::unix::fs::MetadataExt as _;
            let file = std::fs::File::open(&path).map_err(|e| failed(e.to_string()))?;
            // The file opened is the regular file looked at, not one put in its place since.
            let opened = file.metadata().map_err(|e| failed(e.to_string()))?;
            if (opened.dev(), opened.ino()) != (seen.dev(), seen.ino()) {
                return Err(failed("replaced while it was opened".into()));
            }
            let mut text = String::new();
            file.take(128)
                .read_to_string(&mut text)
                .map_err(|e| failed(e.to_string()))?;
            let stored = text.trim();
            let parsed = stored
                .strip_prefix("0x")
                .and_then(|h| hex::decode(h).ok())
                .filter(|b| b.len() == 32);
            if parsed.is_none() {
                return Err(failed("not a node ID".into()));
            }
            if stored != want {
                return Err(OpenError::NodeIdChanged {
                    dir: dir.to_owned(),
                    stored: stored.to_owned(),
                    configured: want,
                });
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let tmp = dir.join(format!("{NODE_ID_FILE}.tmp"));
            let _ = std::fs::remove_file(&tmp);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| failed(e.to_string()))?;
            file.write_all(format!("{want}\n").as_bytes())
                .and_then(|()| file.sync_all())
                .and_then(|()| std::fs::rename(&tmp, &path))
                .map_err(|e| failed(e.to_string()))?;
            tracing::info!(node_id = %want, store = %dir.display(), "the column store is this node ID's");
            Ok(())
        }
        Err(e) => Err(failed(e.to_string())),
    }
}

/// cl-chain in probe mode (see the module docs).
pub struct ProbeService<E: EthSpec, V> {
    ingest: Ingest<E, V>,
    writer: Arc<ColumnWriter>,
    columns: Arc<ColumnServer>,
    status: Arc<StatusProvider<BeaconApi>>,
    custody: Vec<u64>,
    cgc: u64,
    caps: NetworkCaps,
    net: ProbeNetwork,
    link: Link,
    /// Tells every `WatchSubscriptions` stream to end; dropped with the service.
    stop: Arc<watch::Sender<bool>>,
}

impl<E: EthSpec, V: KzgVerifier + 'static> ProbeService<E, V> {
    /// Opens the store (again, after a restart), starts the ingest and the reference follower.
    /// Must be called within a tokio runtime. The store's metrics go to `registry`.
    ///
    /// # Errors
    ///
    /// [`OpenError::NodeIdChanged`] for a store of another node ID ([`NODE_ID_FILE`]);
    /// [`OpenError::Failed`] if the clock, the store, the custody record or the ingest failed.
    pub fn open(
        net: &ProbeNetwork,
        plan: ProbePlan<V>,
        registry: &mut Registry,
    ) -> Result<Self, OpenError> {
        let clock: Arc<dyn ServeClock> = Arc::new(WallClock::new(net.probe_chain())?);
        let writer = Arc::new(
            ColumnWriter::open(&plan.columns_dir)
                .map_err(|e| format!("column store {}: {e}", plan.columns_dir.display()))?,
        );
        // Under the writer's lock: no other start compares or writes it meanwhile.
        claim_node_id(&plan.columns_dir, plan.node_id)?;
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            plan.node_id,
            Advertise::Custody,
            plan.cgc_set_slot,
        )
        .map_err(|e| format!("custody: {e}"))?;
        let columns_of = custody.custody_columns();
        let cgc = custody.advertised_cgc();
        let contract = ColumnContract {
            kzg: plan.kzg,
            verify_timeout: plan.verify_timeout,
            metrics: ColumnMetrics::register(registry),
        };
        let refs = RefView::<_, E>::new(
            plan.reference.clone(),
            *net.config().fork_schedule(),
            RefLimits::default(),
        );
        let ingest = ColumnIngest::start(
            refs,
            custody,
            contract,
            Arc::clone(&writer),
            IngestLimits::default(),
            QueueMetrics::register(registry),
        )
        .map_err(|e| format!("column ingest: {e}"))?;
        // The reference's block events seed its view: a root it imports is looked up before its
        // columns arrive, so a flood of made-up roots cannot delay them. Its head, re-org and
        // finality events keep its chain, which range answers follow, and with the wall clock
        // they prune the store of the blocks off the finalized chain and out of retention.
        ingest.follow_head(
            plan.reference.clone(),
            HeadFollow::default(),
            Arc::clone(&clock),
        );
        let columns = Arc::new(
            ColumnServer::new(
                Arc::clone(&writer) as Arc<dyn ColumnStore>,
                plan.node_id,
                clock,
                ServeBudget::default(),
            )
            .following(ingest.canonical()),
        );
        let status = Arc::new(
            StatusProvider::new(plan.reference, net.probe_chain(), DEFAULT_API_TIMEOUT)
                .serving_columns(Arc::clone(&columns) as Arc<dyn ServedColumns>)
                .reusing_samples(STATUS_SAMPLE_REUSE),
        );
        let (stop, _) = watch::channel(false);
        Ok(Self {
            ingest,
            writer,
            columns,
            status,
            custody: columns_of,
            cgc,
            caps: NetworkCaps::from_config(net.config()),
            net: net.clone(),
            link: plan.link,
            stop: Arc::new(stop),
        })
    }

    /// Takes one column sidecar from gossip, its topic's fork digest `fork_digest` and its
    /// subnet `subnet_id`: decoded by the fork of its slot, and stored if the storage contract
    /// passes it. A `fork_digest` that is not the digest of its slot's epoch is dropped without
    /// decoding (`proto/README.md`). Returns whether it was handed to the store. Every column
    /// is IGNOREd: none is forwarded.
    pub fn accept_column(&self, fork_digest: [u8; 4], subnet_id: u64, data: &[u8]) -> bool {
        let Ok(slot) = forked::DataColumnSidecar::<E>::peek_slot(data) else {
            tracing::debug!("a column sidecar without a slot: dropped");
            return false;
        };
        let epoch = slot / self.net.slots_per_epoch().max(1);
        if self.net.digest_at(epoch) != Some(fork_digest) {
            tracing::debug!(
                slot,
                "a column sidecar on another fork digest's topic: dropped"
            );
            return false;
        }
        let schedule = self.net.config().fork_schedule();
        match forked::DataColumnSidecar::<E>::from_ssz_bytes_by_slot(data, schedule, &self.caps) {
            Ok(forked::DataColumnSidecar::Gloas(sidecar)) => {
                let _ = self.ingest.on_column(GossipColumn { sidecar, subnet_id });
                true
            }
            Ok(other) => {
                tracing::debug!(
                    slot = other.slot(),
                    "a column sidecar before Gloas: not stored"
                );
                false
            }
            Err(e) => {
                tracing::debug!(error = ?e, "a column sidecar that does not decode: dropped");
                false
            }
        }
    }
}

impl<E: EthSpec, V> ProbeService<E, V> {
    /// Every `ethswarm.chain.v1` service: `ReqRespService` from the column server and our
    /// Status, `GossipService/WatchSubscriptions` from the custody, the rest stubs. Serve them
    /// behind [`chain_acl`].
    #[must_use]
    pub fn routes(&self) -> Routes {
        ChainStub::new(self.link.clone())
            .serving(self.req_resp_server())
            .serving_gossip(self.gossip_server())
            .routes()
    }

    /// `ReqRespService`: the column server and our Status.
    #[must_use]
    pub fn req_resp_server(&self) -> ReqRespServer {
        ReqRespServer::new(self.link.clone(), Arc::clone(&self.columns))
            .serving_status(Arc::clone(&self.status) as Arc<dyn ChainStatus>)
    }

    /// `GossipService`: the custody subscriptions on the wall clock, its streams ended by
    /// [`Self::stream_stop`].
    #[must_use]
    pub fn gossip_server(&self) -> GossipServer {
        GossipServer::new(
            self.link.clone(),
            Subscriptions::new(&self.net, self.custody.clone()),
            Arc::new(system_ms),
            self.stop.subscribe(),
        )
    }

    /// The handle that ends every `WatchSubscriptions` stream ([`StreamStop::end_streams`]), for
    /// a shutdown future that does not hold the service.
    #[must_use]
    pub fn stream_stop(&self) -> StreamStop {
        StreamStop(Arc::clone(&self.stop))
    }

    /// The chain.v1 link of the service.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Our custody columns, sorted.
    #[must_use]
    pub fn custody_columns(&self) -> &[u64] {
        &self.custody
    }

    /// The custody group count we advertise.
    #[must_use]
    pub fn custody_group_count(&self) -> u64 {
        self.cgc
    }

    /// The slot custody was set at: the one of the store's first start.
    #[must_use]
    pub fn cgc_set_slot(&self) -> u64 {
        self.ingest.custody().cgc_set_slot()
    }

    /// The store, read only.
    #[must_use]
    pub fn reader(&self) -> &ColumnReader {
        self.writer.reader()
    }

    /// The slot the columns are served from (the Status `earliest_available_slot`); `None`
    /// while nothing is.
    #[must_use]
    pub fn earliest_available_slot(&self) -> Option<u64> {
        self.columns.earliest_available_slot()
    }

    /// What our Status must advertise at least: the slot a range request is served from
    /// ([`ColumnServer::status_floor`]).
    ///
    /// # Errors
    ///
    /// The store cannot be read.
    pub fn status_floor(&self) -> Result<u64, String> {
        self.columns.status_floor()
    }

    /// Columns on their way into the store.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.ingest.pending()
    }

    /// Waits until the store's writer has done everything handed to it so far, the settle of
    /// pending links after it included ([`ColumnIngest::settled`]); `false` if it is gone.
    pub async fn settled(&self) -> bool {
        self.ingest.settled().await
    }

    /// Samples the reference API for our Status now, so the first `GetStatus` has one: a
    /// Status never waits on the API, and before its first good sample is `UNAVAILABLE`.
    ///
    /// # Errors
    ///
    /// The sample failed or timed out; a later Status refreshes it in the background.
    pub async fn sample_reference(&self) -> Result<(), String> {
        self.status.refresh().await.map_err(|e| e.to_string())
    }
}

/// Ends the `WatchSubscriptions` streams of a [`ProbeService`] ([`ProbeService::stream_stop`]).
#[derive(Clone, Debug)]
pub struct StreamStop(Arc<watch::Sender<bool>>);

impl StreamStop {
    /// Ends every stream now, with `UNAVAILABLE`: a stream that stays open would hold the
    /// shutdown's drain to its deadline. Streams opened after this end at once. Called at the
    /// start of a shutdown.
    pub fn end_streams(&self) {
        self.0.send_replace(true);
    }
}

/// What `WatchSubscriptions` tells cl-p2p: our custody columns, under the fork digest of the
/// wall clock and, from [`SUBSCRIBE_AHEAD`] epochs before a digest change, the next digest too.
#[derive(Debug, Clone)]
pub struct Subscriptions {
    columns: Vec<u64>,
    net: ProbeNetwork,
    /// Every digest change of the schedule: its first epoch and its digest, ascending.
    changes: Vec<(Epoch, [u8; 4])>,
}

impl Subscriptions {
    /// The subscriptions of `columns` on `net`.
    #[must_use]
    pub fn new(net: &ProbeNetwork, columns: Vec<u64>) -> Self {
        let changes = digest_schedule(net.config(), &net.genesis().genesis_validators_root)
            .iter()
            .map(|e| (e.epoch, e.fork_digest))
            .collect();
        Self {
            columns,
            net: net.clone(),
            changes,
        }
    }

    /// The body at `now_ms`; `None` before genesis or Fulu.
    #[must_use]
    pub fn body_at(&self, now_ms: u128) -> Option<pb::WatchSubscriptionsResponseBody> {
        let epoch = self.net.epoch_at(now_ms).ok()?;
        let current = self.net.digest_at(epoch)?;
        let mut fork_digests = vec![current.to_vec()];
        // Each change within the lead, so two changes close together each get all of it.
        let ahead = epoch.saturating_add(SUBSCRIBE_AHEAD);
        for (at, digest) in &self.changes {
            let digest = digest.to_vec();
            if *at > epoch && *at <= ahead && !fork_digests.contains(&digest) {
                fork_digests.push(digest);
            }
        }
        Some(pb::WatchSubscriptionsResponseBody {
            attnets: Vec::new(),
            syncnets: Vec::new(),
            custody_columns: self.columns.clone(),
            fork_digests,
        })
    }

    /// How long from `now_ms` to the start of the next epoch, when the body can change next;
    /// before genesis, to genesis.
    #[must_use]
    pub fn wait_from(&self, now_ms: u128) -> Duration {
        let next = match self.net.epoch_at(now_ms) {
            Ok(epoch) => self.net.epoch_start_ms(epoch.saturating_add(1)),
            Err(_) => self.net.epoch_start_ms(0),
        };
        let ms = u64::try_from(next.saturating_sub(now_ms)).unwrap_or(u64::MAX);
        Duration::from_millis(ms.max(1))
    }
}

/// Unix milliseconds now.
pub type WallMs = Arc<dyn Fn() -> u128 + Send + Sync>;

/// `ethswarm.chain.v1.GossipService` with `WatchSubscriptions` served from [`Subscriptions`];
/// the rest are stubs (contract checks, then `UNIMPLEMENTED`).
///
/// A `WatchSubscriptions` stream sends our hello, then the body, then a new body each time it
/// changes (checked at each epoch start of the wall clock `clock`). It ends with `UNAVAILABLE`
/// when `stop` turns true or its sender is dropped (the service stops), and ends when the
/// client goes.
#[derive(Clone)]
pub struct GossipServer {
    link: Link,
    subscriptions: Arc<Subscriptions>,
    clock: WallMs,
    stop: watch::Receiver<bool>,
    /// A place per open `WatchSubscriptions` stream ([`MAX_WATCHERS`]).
    watchers: Arc<tokio::sync::Semaphore>,
}

impl std::fmt::Debug for GossipServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipServer")
            .field("link", &self.link)
            .field("subscriptions", &self.subscriptions)
            .finish_non_exhaustive()
    }
}

impl GossipServer {
    /// A server of `subscriptions` holding every stream to `link`.
    #[must_use]
    pub fn new(
        link: Link,
        subscriptions: Subscriptions,
        clock: WallMs,
        stop: watch::Receiver<bool>,
    ) -> Self {
        Self {
            link,
            subscriptions: Arc::new(subscriptions),
            clock,
            stop,
            watchers: Arc::new(tokio::sync::Semaphore::new(MAX_WATCHERS)),
        }
    }

    /// The tonic service.
    #[must_use]
    pub fn into_service(self) -> GossipServiceServer<Self> {
        GossipServiceServer::new(self)
    }
}

/// The status a `WatchSubscriptions` stream ends with when cl-chain stops.
fn stopping() -> Status {
    Status::unavailable("cl-chain is stopping")
}

#[tonic::async_trait]
impl GossipService for GossipServer {
    async fn get_fork_schedule(
        &self,
        _: Request<pb::GetForkScheduleRequest>,
    ) -> Result<Response<pb::GetForkScheduleResponse>, Status> {
        ipc::stub::unary(&self.link, "get_fork_schedule", &[])
    }

    type WatchPublishStream = StubStream<pb::WatchPublishResponse>;

    async fn watch_publish(
        &self,
        request: Request<pb::WatchPublishRequest>,
    ) -> Result<Response<Self::WatchPublishStream>, Status> {
        ipc::stub::server_stream(&self.link, "watch_publish", request.get_ref())
    }

    type WatchSubscriptionsStream = StubStream<pb::WatchSubscriptionsResponse>;

    async fn watch_subscriptions(
        &self,
        request: Request<pb::WatchSubscriptionsRequest>,
    ) -> Result<Response<Self::WatchSubscriptionsStream>, Status> {
        self.link
            .accept_hello_field(request.get_ref().hello.as_ref())
            .map_err(|e| e.to_status())?;
        let (_, ours) = stream_hello(self.link.local()).map_err(|e| e.to_status())?;
        // Held by the stream's task until the stream ends.
        let place = Arc::clone(&self.watchers)
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted(format!(
                    "{MAX_WATCHERS} WatchSubscriptions streams are open already"
                ))
            })?;
        let (tx, rx) = mpsc::channel(2);
        let subscriptions = Arc::clone(&self.subscriptions);
        let clock = Arc::clone(&self.clock);
        let mut stop = self.stop.clone();
        ipc::spawn_in_span(async move {
            let _place = place;
            if tx
                .send(Ok(pb::WatchSubscriptionsResponse::hello(ours)))
                .await
                .is_err()
            {
                return;
            }
            let mut sent = None;
            loop {
                if *stop.borrow_and_update() {
                    let _ = tx.send(Err(stopping())).await;
                    return;
                }
                let now = clock();
                if let Some(body) = subscriptions.body_at(now) {
                    if sent.as_ref() != Some(&body) {
                        let frame = pb::WatchSubscriptionsResponse::body(body.clone());
                        if tx.send(Ok(frame)).await.is_err() {
                            return;
                        }
                        sent = Some(body);
                    }
                }
                tokio::select! {
                    () = tokio::time::sleep(subscriptions.wait_from(now)) => {}
                    changed = stop.changed() => if changed.is_err() {
                        let _ = tx.send(Err(stopping())).await;
                        return;
                    },
                    () = tx.closed() => return,
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    type ValidateStream = StubStream<pb::ValidateResponse>;

    async fn validate(
        &self,
        request: Request<Streaming<pb::ValidateRequest>>,
    ) -> Result<Response<Self::ValidateStream>, Status> {
        ipc::stub::bidi(&self.link, "validate", request)
    }
}

#[cfg(test)]
mod tests;
