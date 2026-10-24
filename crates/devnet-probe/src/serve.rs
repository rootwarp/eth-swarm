//! `serve`: the probe stores its custody columns from gossip and serves them by
//! `DataColumnSidecarsByRange` v1 and `DataColumnSidecarsByRoot` v1 (`fulu/p2p-interface.md`
//! L605–790), the way the services split it, then checks its own answers against its store.
//!
//! - **cl-chain** ([`ChainSide`]): probe mode's column store ([`ColumnIngest`]: the reference
//!   node vouches for each block root, cl-verify checks the cells by KZG, only custody columns
//!   are kept, and the reference's `block` events announce its roots ahead of their columns,
//!   [`ColumnIngest::follow_head`]), the column server over it ([`ColumnServer`], its range
//!   answers on the reference's canonical chain from the same events, and the store pruned of
//!   the blocks off its finalized chain and of the columns out of retention by the wall clock:
//!   `cl_chain::probe::CanonicalChain`) and our Status
//!   ([`StatusProvider`], its `earliest_available_slot` the column server's), all on
//!   `ethswarm.chain.v1.ReqRespService` ([`ReqRespServer`] mounted by [`ChainStub::serving`]).
//!   It is served on a Unix socket of its own, `<socket root>/cl-chain/cl-chain.sock`, bound by
//!   [`ipc::uds::bind`] (directory 0750, socket 0660) behind the method ACL ([`chain_acl`]):
//!   only the caller `cl-p2p` (our own UID) may call `GetStatus`, `DataColumnsByRange` and
//!   `DataColumnsByRoot`, and nothing else.
//! - **cl-p2p** ([`p2p_swarm`]): the probe swarm, connected to that socket through the
//!   peer-checked connector ([`ipc::uds::connect_path`]: the server must run as cl-chain's
//!   UID): its column responders answer from [`ChainColumns`], every Status it sends or
//!   answers is read from `GetStatus` afresh ([`ChainStatusSource`]: never below what the
//!   store serves from, none at all if the read fails), and its ignore-all gossipsub
//!   subscribes to our custody column subnets (and `beacon_block`) with a capture tap.
//! - **The gossip hand-off** ([`ChainSide::hand_over`]): each captured column sidecar whose
//!   topic carries the fork digest of its slot's epoch is decoded by the fork of its slot and
//!   given to cl-chain's [`ColumnIngest::on_column`] in process; another digest is dropped
//!   undecoded. `ethswarm.chain.v1.GossipService/Validate`, its wire form, is still a stub.
//!
//! [`serve`] runs it all for a while on the devnet, dialling the reference CLs so their column
//! gossip reaches us, never across a fork digest change ([`clip_until`]: the subscriptions are
//! of the digest at its start, and every deadline is counted back from its end, again once the
//! start is done), then stops the hand-off, lets the store settle ([`settle`]: the queue empty
//! and the writer's confirmation that it is done, links included; a store still changing is
//! reported, never checked), asks the probe what it stored, as a peer would
//! ([`ColumnRequester`] over libp2p), and compares every answer with the store
//! ([`self_check`]), all by [`AFTER_SERVING`] after serving and before the digest change.

use super::devnet::Devnet;
use super::report::Check;
use super::swarm::{serving_swarm, Gossip, Sources, SwarmPlan};
use cl_chain::da::custody::{Advertise, Custody, EnrCgc, EnrError};
use cl_chain::probe::{
    BeaconApi, ColumnContract, ColumnIngest, ColumnMetrics, GossipColumn, HeadFollow, IngestLimits,
    QueueMetrics, RefLimits, RefView, StatusProvider, DEFAULT_API_TIMEOUT,
};
use cl_chain::reqresp::{ColumnServer, ColumnStore, ReqRespServer, ServeBudget, WallClock};
use cl_chain::verify::client::KzgVerifier;
use cl_chain::ChainStub;
use cl_chain_columns::{ColumnReader, ColumnWriter, RangeBudget};
use cl_p2p::behaviour::{SpecBehaviour, SpecBehaviourEvent};
use cl_p2p::gossip::{CaptureReader, CaptureTap, Captured};
use cl_p2p::m2a_session::PinnedPeer;
use cl_p2p::rpc::answer_bucket::AnswerPrefixes;
use cl_p2p::rpc::chain_status::{ChainStatus, ChainStatusSource, DEFAULT_STATUS_REFRESH};
use cl_p2p::rpc::codec::{Deadlines, ReceivedChunk, RpcCodec, RpcRequest};
use cl_p2p::rpc::columns::ChainColumns;
use cl_p2p::rpc::inbound::StatusSource;
use cl_p2p::rpc::limits::{RpcLimits, MAX_COLUMN_RESPONSE_BYTES};
use consensus_types::caps::NetworkCaps;
use consensus_types::das::NUMBER_OF_COLUMNS;
use consensus_types::primitives::U256;
use consensus_types::{forked, EthSpec};
use ethswarm_proto::common::{
    BlobScheduleEntry, ForkName as WireForkName, ForkScheduleEntry, Hello, SpecPin,
};
use futures::StreamExt;
use ipc::acl::{AclLayer, AclTables, MethodAcl};
use ipc::envelope::DigestTable;
use ipc::uds::{Ownership, SocketDir, SocketGuard};
use ipc::Link;
use libp2p::identity::Keypair;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmEvent};
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use network_config::digest::digest_schedule;
use network_config::ForkName;
use p2p_wire::gossip::{GossipKind, GossipTopic};
use p2p_wire::rpc::messages::{
    DataColumnsByRangeV1Request, DataColumnsByRootIdentifier, DataColumnsByRootV1Request,
    ForkDigest, StatusV2,
};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// The check's name, as the subcommand.
pub const NAME: &str = "serve";

/// The service that serves `ethswarm.chain.v1`, and its socket directory's name.
pub const CHAIN_SERVICE: &str = "cl-chain";

/// The one caller of cl-chain's socket: cl-p2p.
pub const P2P_CALLER: &str = "cl-p2p";

/// The `ethswarm.chain.v1` methods cl-p2p calls to serve columns, and only those.
pub const CHAIN_METHODS: [&str; 3] = [
    "/ethswarm.chain.v1.ReqRespService/GetStatus",
    "/ethswarm.chain.v1.ReqRespService/DataColumnsByRange",
    "/ethswarm.chain.v1.ReqRespService/DataColumnsByRoot",
];

/// How long the probe serves by default before it checks its answers.
pub const DEFAULT_SERVE: Duration = Duration::from_secs(300);

/// How long cl-verify may take for one column's cells \[est\].
pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// How many captured gossip messages wait for the hand-off at most \[est\]: a few slots of
/// the custody subnets' columns; past it the tap drops and counts them.
pub const TAP_CAPACITY: usize = 1024;

/// How often the hand-off drains the tap.
const PUMP_EVERY: Duration = Duration::from_millis(20);

/// How long the columns still on their way into the store get once serving ends ([`settle`]):
/// a store still changing after it is not checked.
const SETTLE_WAIT: Duration = Duration::from_secs(10);

/// How long `serve` keeps after serving for the settle wait and its own check \[est\]: both
/// end by then ([`check_by`]), and serving ends at least this before the next fork digest
/// ([`clip_until`]).
pub const AFTER_SERVING: Duration = Duration::from_secs(30);

/// How long a reference sample is reused for our Status \[est\]: every Status that goes out
/// reads the store afresh, the reference API at most every 2 s.
const STATUS_SAMPLE_REUSE: Duration = Duration::from_secs(2);

/// How long one of our requests to the probe may take.
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// The roots a by-root check names at most.
const BY_ROOT_BLOCKS: usize = 4;

/// The `api_version` of the probe's chain.v1 and verify.v1 links.
const API_VERSION: u32 = 1;

/// The spec pin every hello carries.
fn spec_pin() -> SpecPin {
    SpecPin {
        consensus_specs_tag: network_config::SPEC_PIN.consensus_specs.into(),
        ssz_specs_tag: network_config::SPEC_PIN.ssz_specs.into(),
    }
}

/// The chain.v1 link both ends of cl-chain's socket hold: our hello (the devnet's genesis
/// validators root, the digest of the wall clock at `now_ms`, every fork and blob-schedule
/// entry) and every digest of the schedule.
///
/// # Errors
///
/// The clock is before genesis or Fulu, or the schedule has no digest.
pub fn chain_link<E: EthSpec>(devnet: &Devnet, now_ms: u128) -> Result<Link, String> {
    let config = devnet.config();
    let gvr = devnet.genesis().genesis_validators_root;
    let current = devnet
        .fork_digest(now_ms)
        .map_err(|e| format!("our fork digest: {e}"))?;
    let schedule = digest_schedule(config, &gvr);
    let wire = |fork: ForkName| match fork {
        ForkName::Fulu => WireForkName::Fulu,
        ForkName::Gloas => WireForkName::Gloas,
    };
    let hello = Hello {
        api_version: API_VERSION,
        build: concat!("devnet-probe/", env!("CARGO_PKG_VERSION")).into(),
        genesis_validators_root: gvr.to_vec(),
        current_fork_digest: current.to_vec(),
        spec_pin: Some(spec_pin()),
        fork_schedule: schedule
            .iter()
            .map(|e| ForkScheduleEntry {
                epoch: e.epoch,
                fork_digest: e.fork_digest.to_vec(),
                fork: wire(e.fork) as i32,
                fork_version: e.fork_version.to_vec(),
                max_blobs_per_block: e.blob_parameters.max_blobs_per_block,
            })
            .collect(),
        blob_schedule: config
            .blob_schedule()
            .iter()
            .map(|b| BlobScheduleEntry {
                epoch: b.epoch,
                max_blobs_per_block: b.max_blobs_per_block,
            })
            .collect(),
        min_api_version: API_VERSION,
        max_api_version: API_VERSION,
        generation: 0,
    };
    let digests = DigestTable::new(
        schedule
            .iter()
            .map(|e| (e.epoch, e.fork, e.fork_digest))
            .collect(),
    )
    .map_err(|e| format!("the digest schedule: {e}"))?;
    Ok(Link::new::<E>(
        hello,
        API_VERSION,
        *config.fork_schedule(),
        digests,
    ))
}

/// The hello of cl-chain's side of the verify.v1 link, as cl-verify's own: the spec pin and
/// the API version, nothing of the network.
#[must_use]
pub fn verify_hello() -> Hello {
    Hello {
        api_version: API_VERSION,
        build: concat!("devnet-probe/", env!("CARGO_PKG_VERSION")).into(),
        spec_pin: Some(spec_pin()),
        min_api_version: API_VERSION,
        max_api_version: API_VERSION,
        ..Hello::default()
    }
}

/// The discv5 node ID of `key` as the spec's `uint256`: what the custody columns are drawn
/// from (`get_custody_groups`).
///
/// # Errors
///
/// `key` is not a secp256k1 key.
pub fn node_id(key: &Keypair) -> Result<U256, String> {
    let secp = key
        .clone()
        .try_into_secp256k1()
        .map_err(|_| "the node key is not a secp256k1 key".to_owned())?;
    let mut secret = secp.secret().to_bytes();
    let combined = cl_discv5::enr::CombinedKey::secp256k1_from_bytes(&mut secret)
        .map_err(|_| "the node key is not a secp256k1 key".to_owned());
    secret.fill(0);
    // The node ID is the record's: keccak256 of the uncompressed public key.
    let record = cl_discv5::enr::Enr::builder()
        .build(&combined?)
        .map_err(|e| format!("a record of the node key: {e}"))?;
    Ok(U256::from_be_bytes(record.node_id().raw()))
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

/// The slot of the wall clock at `now_ms`; `None` before genesis.
#[must_use]
pub fn slot_at(devnet: &Devnet, now_ms: u128) -> Option<u64> {
    let since = now_ms.checked_sub(u128::from(devnet.genesis().genesis_time) * 1000)?;
    let slot_ms = u128::from(devnet.config().slot_duration_ms().max(1));
    u64::try_from(since / slot_ms).ok()
}

/// The probe publishes no ENR while it serves: peers reach it by its own dials.
struct NoEnr;

impl EnrCgc for NoEnr {
    fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
        Ok(())
    }
}

/// What [`ChainSide::start`] needs.
pub struct ChainPlan<V> {
    /// The link both ends of the socket hold ([`chain_link`]).
    pub link: Link,
    /// Our node ID ([`node_id`]): the custody columns.
    pub node_id: U256,
    /// The column store's directory.
    pub columns_dir: PathBuf,
    /// The socket root: cl-chain's socket is `<root>/cl-chain/cl-chain.sock`.
    pub socket_root: PathBuf,
    /// cl-p2p's UID, the one caller the ACL lets in.
    pub caller_uid: u32,
    /// The reference node's beacon API: the block roots it vouches for, and our Status.
    pub reference: BeaconApi,
    /// cl-verify's KZG checks.
    pub kzg: V,
    /// How long one KZG check may take.
    pub verify_timeout: Duration,
    /// The slot custody is set at on a new store: columns are stored from there on.
    pub cgc_set_slot: u64,
}

/// The column store of cl-chain's probe mode.
type Ingest<E, V> = ColumnIngest<BeaconApi, E, V, Arc<ColumnWriter>, NoEnr>;

/// cl-chain in probe mode: the column store, its column server and our Status, served on its
/// socket behind the ACL until dropped.
pub struct ChainSide<E: EthSpec, V> {
    ingest: Ingest<E, V>,
    writer: Arc<ColumnWriter>,
    columns: Arc<ColumnServer>,
    status: Arc<StatusProvider<BeaconApi>>,
    custody: Vec<u64>,
    cgc: u64,
    socket: PathBuf,
    caps: NetworkCaps,
    devnet: Devnet,
    server: JoinHandle<()>,
    _guard: SocketGuard,
}

impl<E: EthSpec, V: KzgVerifier + 'static> ChainSide<E, V> {
    /// Opens the store, starts the ingest and serves chain.v1 on the socket.
    ///
    /// # Errors
    ///
    /// The store, the custody record, the ingest, the clock or the socket failed.
    pub fn start(
        devnet: &Devnet,
        plan: ChainPlan<V>,
        registry: &mut Registry,
    ) -> Result<Self, String> {
        // Everything that can be checked first is, so a refused start leaves no store behind.
        let clock: Arc<dyn cl_chain::reqresp::ServeClock> =
            Arc::new(WallClock::new(devnet.probe_chain())?);
        let acl = chain_acl(plan.caller_uid)?;
        let dir = SocketDir::under(&plan.socket_root, CHAIN_SERVICE).map_err(|e| e.to_string())?;
        let (listener, guard) = ipc::uds::bind(&dir, Ownership::current())
            .map_err(|e| format!("cl-chain socket: {e}"))?
            .into_tokio()
            .map_err(|e| format!("cl-chain socket: {e}"))?;
        let writer = Arc::new(
            ColumnWriter::open(&plan.columns_dir)
                .map_err(|e| format!("column store {}: {e}", plan.columns_dir.display()))?,
        );
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
            *devnet.config().fork_schedule(),
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
            StatusProvider::new(plan.reference, devnet.probe_chain(), DEFAULT_API_TIMEOUT)
                .serving_columns(Arc::clone(&columns) as Arc<dyn cl_chain::probe::ServedColumns>)
                .reusing_samples(STATUS_SAMPLE_REUSE),
        );
        let req_resp = ReqRespServer::new(plan.link.clone(), Arc::clone(&columns))
            .serving_status(Arc::clone(&status) as Arc<dyn cl_chain::reqresp::ChainStatus>);
        let routes = ChainStub::new(plan.link).serving(req_resp).routes();
        let server = tokio::spawn(async move {
            let served = tonic::transport::Server::builder()
                .layer(AclLayer::new(Arc::new(acl)))
                .add_routes(routes)
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await;
            if let Err(e) = served {
                tracing::error!(error = %e, "cl-chain's socket stopped serving");
            }
        });
        Ok(Self {
            ingest,
            writer,
            columns,
            status,
            custody: columns_of,
            cgc,
            socket: dir.socket_path(),
            caps: NetworkCaps::from_config(devnet.config()),
            devnet: devnet.clone(),
            server,
            _guard: guard,
        })
    }
}

impl<E: EthSpec, V> ChainSide<E, V> {
    /// cl-chain's socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
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

impl<E: EthSpec, V: KzgVerifier + 'static> ChainSide<E, V> {
    /// Hands one captured gossip message to the column store, if it is a Gloas column sidecar
    /// on a column subnet whose topic carries the fork digest of the sidecar's slot's epoch:
    /// decoded by the fork of its slot, as cl-p2p's gossip path does. A digest mismatch is
    /// dropped without decoding (`proto/README.md`). Returns whether it was handed over.
    pub fn hand_over(&self, captured: &Captured) -> bool {
        let Some(topic) = GossipTopic::parse(&captured.topic).ok() else {
            return false;
        };
        let GossipKind::DataColumnSidecar { subnet_id } = topic.kind else {
            return false;
        };
        let Ok(slot) = forked::DataColumnSidecar::<E>::peek_slot(&captured.data) else {
            tracing::debug!("a column sidecar without a slot: dropped");
            return false;
        };
        let epoch = slot / self.devnet.slots_per_epoch().max(1);
        if self.devnet.digest_at(epoch) != Some(topic.fork_digest) {
            tracing::debug!(
                slot,
                "a column sidecar on another fork digest's topic: dropped"
            );
            return false;
        }
        let schedule = self.devnet.config().fork_schedule();
        match forked::DataColumnSidecar::<E>::from_ssz_bytes_by_slot(
            &captured.data,
            schedule,
            &self.caps,
        ) {
            Ok(forked::DataColumnSidecar::Gloas(sidecar)) => {
                // Every column is reported IGNORE: none is forwarded.
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

    /// Hands over every message queued in `tap`; returns how many were column sidecars.
    pub fn pump(&self, tap: &CaptureReader) -> usize {
        let mut handed = 0;
        while let Some(captured) = tap.try_next() {
            handed += usize::from(self.hand_over(&captured));
        }
        handed
    }
}

impl<E: EthSpec, V> Drop for ChainSide<E, V> {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// The task that keeps our Status current from cl-chain's `GetStatus`; stopped when dropped.
#[derive(Debug)]
pub struct StatusTask(JoinHandle<()>);

impl Drop for StatusTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// cl-p2p in the probe: its swarm, and its Status source.
pub struct P2pSide<E: EthSpec> {
    /// The probe swarm.
    pub swarm: Swarm<SpecBehaviour<E>>,
    /// Our Status: the last good one from cl-chain for judging, read fresh for every Status
    /// the swarm sends or answers ([`ChainStatusSource`]).
    pub status: ChainStatusSource,
    /// Keeps the last good Status current.
    pub refresh: StatusTask,
}

/// The probe swarm serving the custody columns `custody` from cl-chain at `chain_socket`
/// (whose server must run as `chain_uid`), its Status cl-chain's `GetStatus`, gossiping on
/// `beacon_block` and our custody column subnets at `digest`, each message to `tap`.
///
/// # Errors
///
/// cl-chain cannot be reached, or the swarm cannot be built.
#[allow(clippy::too_many_arguments)]
pub async fn p2p_swarm<E: EthSpec>(
    devnet: &Devnet,
    link: Link,
    chain_socket: &Path,
    chain_uid: u32,
    key: Keypair,
    plan: SwarmPlan,
    custody: &[u64],
    custody_group_count: u64,
    digest: ForkDigest,
    tap: CaptureTap,
) -> Result<P2pSide<E>, String> {
    let channel = ipc::uds::connect_path(chain_socket, chain_uid)
        .await
        .map_err(|e| format!("cl-chain at {}: {e}", chain_socket.display()))?;
    let status = ChainStatusSource::new(ChainStatus::new(channel.clone()));
    let refresh = StatusTask(status.keep_current(DEFAULT_STATUS_REFRESH));
    let sources = Sources {
        status: Arc::new(status.clone()) as Arc<dyn StatusSource>,
        custody_group_count,
        columns: Some(Arc::new(ChainColumns::new(
            channel,
            link,
            MAX_COLUMN_RESPONSE_BYTES,
        ))),
    };
    let mut topics = vec![GossipTopic::new(digest, GossipKind::BeaconBlock)];
    topics.extend(custody.iter().map(|&column| {
        GossipTopic::new(
            digest,
            GossipKind::DataColumnSidecar {
                subnet_id: consensus_types::das::compute_subnet_for_data_column_sidecar(column),
            },
        )
    }));
    topics.dedup();
    let gossip = Gossip {
        topics,
        tap: Some(tap),
    };
    let swarm = serving_swarm(devnet, key, sources, plan, Some(gossip))?;
    Ok(P2pSide {
        swarm,
        status,
        refresh,
    })
}

/// The two column protocols and Status, ours to request on.
#[derive(NetworkBehaviour)]
pub struct Requests<E: EthSpec> {
    range: request_response::Behaviour<RpcCodec<E>>,
    root: request_response::Behaviour<RpcCodec<E>>,
    status: request_response::Behaviour<RpcCodec<E>>,
}

/// What one column request got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnAnswer {
    /// A success: each sidecar's context bytes and SSZ, in order.
    Sidecars(Vec<(ForkDigest, Vec<u8>)>),
    /// One error chunk with this code.
    Refused(ResultCode),
}

/// A peer of our own that asks the probe for columns, as any peer would.
pub struct ColumnRequester<E: EthSpec> {
    swarm: Swarm<Requests<E>>,
}

impl<E: EthSpec> ColumnRequester<E> {
    /// A requester reading answers under `devnet`'s context table and caps.
    ///
    /// # Errors
    ///
    /// The swarm cannot be built.
    pub fn new(devnet: &Devnet) -> Result<Self, String> {
        let codec = RpcCodec::<E>::new(Arc::new(devnet.context_table()), Deadlines::default());
        let behaviour = Requests {
            range: cl_p2p::rpc::outbound_behaviour(Protocol::DataColumnsByRangeV1, codec.clone()),
            root: cl_p2p::rpc::outbound_behaviour(Protocol::DataColumnsByRootV1, codec.clone()),
            status: cl_p2p::rpc::outbound_behaviour(Protocol::StatusV2, codec),
        };
        let swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| format!("requester transport: {e}"))?
            .with_behaviour(|_| behaviour)
            .map_err(|e| format!("requester: {e}"))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(REQUEST_DEADLINE))
            .build();
        Ok(Self { swarm })
    }

    /// Connects to `peer` at `addr`.
    ///
    /// # Errors
    ///
    /// The dial failed or took longer than the request deadline.
    pub async fn connect(&mut self, peer: PeerId, addr: Multiaddr) -> Result<(), String> {
        let opts = DialOpts::peer_id(peer).addresses(vec![addr]).build();
        self.swarm.dial(opts).map_err(|e| format!("dial: {e}"))?;
        let connected = async {
            loop {
                match self.swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer => {
                        return Ok(());
                    }
                    SwarmEvent::OutgoingConnectionError { error, .. } => {
                        return Err(format!("dial: {error}"));
                    }
                    _ => {}
                }
            }
        };
        tokio::time::timeout(REQUEST_DEADLINE, connected)
            .await
            .map_err(|_| "dial: no connection in time".to_owned())?
    }

    /// `DataColumnSidecarsByRange` v1 of `count` slots from `start_slot` for `columns`.
    ///
    /// # Errors
    ///
    /// The request is out of bounds, or the exchange failed.
    pub async fn by_range(
        &mut self,
        peer: PeerId,
        start_slot: u64,
        count: u64,
        columns: &[u64],
    ) -> Result<ColumnAnswer, String> {
        let columns = columns
            .to_vec()
            .try_into()
            .map_err(|_| "too many columns".to_owned())?;
        let request = Request::DataColumnsByRange(DataColumnsByRangeV1Request {
            start_slot,
            count,
            columns,
        });
        let id = self
            .swarm
            .behaviour_mut()
            .range
            .send_request(&peer, RpcRequest::from(request));
        self.answer(id).await
    }

    /// `DataColumnSidecarsByRoot` v1 of `ids`.
    ///
    /// # Errors
    ///
    /// The request is out of bounds, or the exchange failed.
    pub async fn by_root(
        &mut self,
        peer: PeerId,
        ids: &[([u8; 32], Vec<u64>)],
    ) -> Result<ColumnAnswer, String> {
        let ids = ids
            .iter()
            .map(|(root, columns)| {
                Ok(DataColumnsByRootIdentifier {
                    block_root: (*root).into(),
                    columns: columns
                        .clone()
                        .try_into()
                        .map_err(|_| "too many columns".to_owned())?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let request = Request::DataColumnsByRoot(DataColumnsByRootV1Request(
            ids.try_into()
                .map_err(|_| "too many identifiers".to_owned())?,
        ));
        let id = self
            .swarm
            .behaviour_mut()
            .root
            .send_request(&peer, RpcRequest::from(request));
        self.answer(id).await
    }

    /// The probe's Status, asked with a Status of our own on `fork_digest` that claims nothing
    /// (finalized epoch 0), so it is judged relevant.
    ///
    /// # Errors
    ///
    /// The exchange failed, or the answer is not one Status.
    pub async fn status(
        &mut self,
        peer: PeerId,
        fork_digest: ForkDigest,
    ) -> Result<StatusV2, String> {
        let ours = StatusV2 {
            fork_digest,
            finalized_root: [0; 32].into(),
            finalized_epoch: 0,
            head_root: [0; 32].into(),
            head_slot: 0,
            earliest_available_slot: 0,
        };
        let id = self
            .swarm
            .behaviour_mut()
            .status
            .send_request(&peer, RpcRequest::from(Request::Status(ours)));
        let chunks = self.response(id).await?;
        match chunks.as_slice() {
            [ReceivedChunk {
                chunk: ResponseChunk::Success(Response::Status(theirs)),
                ..
            }] => Ok(theirs.clone()),
            other => Err(format!("not one Status: {other:?}")),
        }
    }

    async fn answer(&mut self, id: OutboundRequestId) -> Result<ColumnAnswer, String> {
        answer_of(self.response(id).await?)
    }

    /// The chunks of our request `id`'s response.
    async fn response(&mut self, id: OutboundRequestId) -> Result<Vec<ReceivedChunk<E>>, String> {
        let wait = async {
            loop {
                let event = match self.swarm.select_next_some().await {
                    SwarmEvent::Behaviour(
                        RequestsEvent::Range(e) | RequestsEvent::Root(e) | RequestsEvent::Status(e),
                    ) => e,
                    _ => continue,
                };
                match event {
                    request_response::Event::Message {
                        message:
                            request_response::Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    } if request_id == id => return Ok(response),
                    request_response::Event::OutboundFailure {
                        request_id, error, ..
                    } if request_id == id => return Err(format!("request failed: {error}")),
                    _ => {}
                }
            }
        };
        tokio::time::timeout(REQUEST_DEADLINE, wait)
            .await
            .map_err(|_| "no answer in time".to_owned())?
    }
}

/// The answer the chunks of one response make.
fn answer_of<E: EthSpec>(chunks: Vec<ReceivedChunk<E>>) -> Result<ColumnAnswer, String> {
    let mut sidecars = Vec::new();
    for (n, chunk) in chunks.into_iter().enumerate() {
        match chunk {
            ReceivedChunk {
                context: Some(context),
                chunk: ResponseChunk::Success(Response::DataColumn(sidecar)),
            } => sidecars.push((context, sidecar.as_ssz_bytes())),
            ReceivedChunk {
                chunk: ResponseChunk::Error { code, .. },
                ..
            } if sidecars.is_empty() => return Ok(ColumnAnswer::Refused(code)),
            other => return Err(format!("chunk {n} is not a column sidecar: {other:?}")),
        }
    }
    Ok(ColumnAnswer::Sidecars(sidecars))
}

/// One stored block of a range: its slot, its root and its `(column, SSZ)` in index order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlock {
    /// Its slot.
    pub slot: u64,
    /// Its root.
    pub root: [u8; 32],
    /// Its stored columns, in index order.
    pub columns: Vec<(u64, Vec<u8>)>,
}

/// The stored sidecars of `slots` (inclusive) for `columns`, block by block in slot order.
///
/// # Errors
///
/// The store failed.
pub fn stored_blocks(
    store: &ColumnReader,
    slots: (u64, u64),
    columns: &[u64],
) -> Result<Vec<StoredBlock>, String> {
    let read = store
        .columns_in_range(
            slots.0,
            slots.1.saturating_add(1),
            |i| columns.contains(&i),
            RangeBudget::unbounded(),
        )
        .map_err(|e| format!("the store: {e}"))?;
    let mut blocks: Vec<StoredBlock> = Vec::new();
    // The columns come in key order: slot, then root, then index.
    for column in read.columns {
        match blocks.last_mut() {
            Some(b) if (b.slot, b.root) == (column.slot, column.block_root) => {
                b.columns.push((column.index, column.ssz));
            }
            _ => blocks.push(StoredBlock {
                slot: column.slot,
                root: column.block_root,
                columns: vec![(column.index, column.ssz)],
            }),
        }
    }
    Ok(blocks)
}

/// Asks the probe `peer` at `addr` for its custody columns as a peer would, and judges every
/// answer against `chain`'s store, into `check`:
///
/// - **by range**, from `earliest_available_slot` to `last_slot`, every custody column: a
///   non-empty answer of stored sidecars only, each the stored bytes of its block and column,
///   in `(slot, column_index)` order, with the context bytes of its slot's epoch;
/// - **by root**, up to [`BY_ROOT_BLOCKS`] stored blocks' custody columns and a root nobody
///   stored: exactly the stored sidecars of the stored blocks, in request order, the unknown
///   root left out;
/// - **a column we do not custody**, by range: `3: ResourceUnavailable`, never an empty answer;
/// - **our Status**: its `earliest_available_slot` at or above the slot the store serves from.
///
/// Nothing may enter the store while it runs (see [`drive`]'s `pumping`), so the answers are
/// judged against the store they were read from.
#[allow(clippy::too_many_arguments)]
pub async fn self_check<E: EthSpec, V: KzgVerifier + 'static>(
    check: &mut Check,
    chain: &ChainSide<E, V>,
    devnet: &Devnet,
    peer: PeerId,
    addr: Multiaddr,
    fork_digest: ForkDigest,
    last_slot: u64,
) {
    let mut requester = match ColumnRequester::<E>::new(devnet) {
        Ok(r) => r,
        Err(e) => return check.fail(e),
    };
    if let Err(e) = requester.connect(peer, addr.clone()).await {
        return check.fail(format!("our requester at {addr}: {e}"));
    }
    // Our Status, as a peer gets it: never below the slot a range request is served from.
    match (
        requester.status(peer, fork_digest).await,
        chain.status_floor(),
    ) {
        (Ok(ours), Ok(floor)) => check.record(
            ours.earliest_available_slot >= floor,
            format!(
                "our Status advertises earliest_available_slot {}, served from {floor}",
                ours.earliest_available_slot
            ),
        ),
        (Err(e), _) => check.fail(format!("our Status: {e}")),
        (_, Err(e)) => check.fail(format!("the store's floor: {e}")),
    }
    let custody = chain.custody_columns().to_vec();
    let Some(earliest) = chain.earliest_available_slot() else {
        let stored = chain.reader().column_count().unwrap_or(0);
        return check.fail(format!(
            "nothing to serve: no earliest_available_slot ({stored} columns stored)"
        ));
    };
    let blocks = match stored_blocks(chain.reader(), (earliest, last_slot), &custody) {
        Ok(blocks) => blocks,
        Err(e) => return check.fail(e),
    };
    // Every stored sidecar of the range in `(slot, column_index)` order: its place, slot and
    // root, by its bytes (each `(root, index)` has bytes of its own).
    let order: std::collections::HashMap<&[u8], (usize, u64, [u8; 32])> = blocks
        .iter()
        .flat_map(|b| b.columns.iter().map(move |(_, ssz)| (b.slot, b.root, ssz)))
        .enumerate()
        .map(|(n, (slot, root, ssz))| (ssz.as_slice(), (n, slot, root)))
        .collect();
    let epoch_digest = |slot: u64| devnet.digest_at(slot / devnet.slots_per_epoch().max(1));

    // By range: stored sidecars only, as stored, in order, whole blocks.
    let count = last_slot
        .saturating_sub(earliest)
        .saturating_add(1)
        .min(cl_chain::reqresp::MAX_REQUEST_DATA_COLUMN_SIDECARS / custody.len().max(1) as u64);
    match requester.by_range(peer, earliest, count, &custody).await {
        Ok(ColumnAnswer::Sidecars(got)) => {
            let judged = judge_range(&got, &order, custody.len(), epoch_digest);
            check.record(
                !got.is_empty() && judged.is_ok(),
                format!(
                    "by range [{earliest}, {}] x {custody:?}: {} sidecars of {} stored blocks: {}",
                    earliest + count - 1,
                    got.len(),
                    blocks.len(),
                    judged
                        .err()
                        .unwrap_or_else(|| "each as stored, in order, whole blocks".into())
                ),
            );
        }
        Ok(ColumnAnswer::Refused(code)) => check.fail(format!(
            "by range [{earliest}, {last_slot}] x {custody:?}: refused {code:?} with {} blocks \
             stored",
            blocks.len()
        )),
        Err(e) => check.fail(format!("by range: {e}")),
    }

    // By root: exactly the stored sidecars, the unknown root left out.
    let named: Vec<_> = blocks.iter().rev().take(BY_ROOT_BLOCKS).rev().collect();
    let mut ids: Vec<([u8; 32], Vec<u64>)> =
        named.iter().map(|b| (b.root, custody.clone())).collect();
    let unknown = [0x5a; 32];
    ids.push((unknown, custody.clone()));
    let want: Vec<(Option<ForkDigest>, Vec<u8>)> = named
        .iter()
        .flat_map(|b| {
            b.columns
                .iter()
                .map(move |(_, ssz)| (epoch_digest(b.slot), ssz.clone()))
        })
        .collect();
    match requester.by_root(peer, &ids).await {
        Ok(ColumnAnswer::Sidecars(got)) => {
            let got: Vec<_> = got.into_iter().map(|(c, s)| (Some(c), s)).collect();
            check.record(
                got == want,
                format!(
                    "by root, {} stored blocks and an unknown root: {} sidecars, {} stored \
                     (equal: {})",
                    named.len(),
                    got.len(),
                    want.len(),
                    got == want
                ),
            );
        }
        Ok(ColumnAnswer::Refused(code)) => check.fail(format!("by root: refused {code:?}")),
        Err(e) => check.fail(format!("by root: {e}")),
    }

    // A column we do not custody: unavailable, never an empty answer.
    let other = (0..NUMBER_OF_COLUMNS).find(|c| !custody.contains(c));
    if let Some(other) = other {
        let answer = requester.by_range(peer, earliest, 1, &[other]).await;
        check.record(
            answer == Ok(ColumnAnswer::Refused(ResultCode::ResourceUnavailable)),
            format!("by range of column {other}, not ours: {answer:?}"),
        );
    }
}

/// Whether a range answer `got` holds stored sidecars only (`order`: each stored sidecar's
/// place in `(slot, column_index)` order, slot and root), each with the context of its slot's
/// epoch, in that order, and only whole blocks of `per_block` sidecars.
fn judge_range(
    got: &[(ForkDigest, Vec<u8>)],
    order: &std::collections::HashMap<&[u8], (usize, u64, [u8; 32])>,
    per_block: usize,
    digest_of: impl Fn(u64) -> Option<ForkDigest>,
) -> Result<(), String> {
    let mut last = None;
    let mut per_root: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for (n, (context, ssz)) in got.iter().enumerate() {
        let Some(&(place, slot, root)) = order.get(ssz.as_slice()) else {
            return Err(format!("sidecar {n} is not one the store holds"));
        };
        if digest_of(slot) != Some(*context) {
            return Err(format!(
                "sidecar {n} (slot {slot}) has context {context:02x?}"
            ));
        }
        if last.is_some_and(|l| place <= l) {
            return Err(format!("sidecar {n} is out of order"));
        }
        last = Some(place);
        *per_root.entry(root).or_default() += 1;
    }
    match per_root.values().find(|&&n| n != per_block) {
        Some(n) => Err(format!("a block with {n} of its {per_block} sidecars")),
        None => Ok(()),
    }
}

/// The non-zero `probe_column_dropped_total{reason}` counts of `registry`, `reason=n`
/// comma-separated, or `none`.
fn drops(registry: &Registry) -> String {
    let mut text = String::new();
    if prometheus_client::encoding::text::encode(&mut text, registry).is_err() {
        return "unknown".into();
    }
    let counts: Vec<String> = text
        .lines()
        .filter_map(|line| line.strip_prefix("probe_column_dropped_total{reason=\""))
        .filter_map(|rest| rest.split_once("\"} "))
        .filter(|(_, n)| *n != "0")
        .map(|(reason, n)| format!("{reason}={n}"))
        .collect();
    if counts.is_empty() {
        "none".into()
    } else {
        counts.join(", ")
    }
}

/// What `serve` runs.
#[derive(Debug, Clone)]
pub struct ServePlan {
    /// Where the probe swarm listens.
    pub listen: Vec<Multiaddr>,
    /// The reference CLs it dials, so their column gossip reaches it.
    pub peers: Vec<PinnedPeer>,
    /// How long it serves before it checks its answers.
    pub serve_for: Duration,
    /// The column store's directory.
    pub columns_dir: PathBuf,
    /// The socket root cl-chain's socket goes under.
    pub socket_root: PathBuf,
    /// How long one KZG check may take.
    pub verify_timeout: Duration,
    /// The address blocks the column answer places are counted per.
    pub answer_prefixes: AnswerPrefixes,
}

/// The probe swarm's listen address our requester dials: a loopback one if it listens there,
/// else the first.
fn requester_target(listening: &[Multiaddr]) -> Option<Multiaddr> {
    let loopback = listening.iter().find(|a| {
        a.iter().any(|p| {
            matches!(p, libp2p::multiaddr::Protocol::Ip4(ip) if ip.is_loopback())
                || matches!(p, libp2p::multiaddr::Protocol::Ip6(ip) if ip.is_loopback())
        })
    });
    loopback.or_else(|| listening.first()).cloned()
}

/// Drives `swarm` until `stop` fires, handing its captured column sidecars to `chain` while
/// `pumping` is set; while it is not, they wait in the tap (and past its capacity are
/// dropped and counted).
pub async fn drive<E: EthSpec, V: KzgVerifier + 'static>(
    mut swarm: Swarm<SpecBehaviour<E>>,
    chain: Arc<ChainSide<E, V>>,
    tap: CaptureReader,
    pumping: Arc<AtomicBool>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    let mut pump = tokio::time::interval(PUMP_EVERY);
    let mut handed = 0usize;
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = pump.tick() => if pumping.load(Ordering::SeqCst) {
                handed += chain.pump(&tap);
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    tracing::info!(peer = %peer_id, addr = %endpoint.get_remote_address(), "connected");
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    tracing::info!(peer = %peer_id, cause = ?cause, "disconnected");
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    tracing::warn!(peer = ?peer_id, error = %error, "dial failed");
                }
                SwarmEvent::Behaviour(SpecBehaviourEvent::ReqResp(event)) => {
                    tracing::debug!(event = ?event, "req/resp");
                }
                _ => {}
            },
        }
    }
    tracing::info!(
        handed,
        dropped = tap.dropped(),
        "column sidecars handed to the store"
    );
}

/// When `epoch` starts, as Unix milliseconds.
fn epoch_start_ms(devnet: &Devnet, epoch: u64) -> u128 {
    let slot_ms = u128::from(devnet.config().slot_duration_ms());
    u128::from(devnet.genesis().genesis_time) * 1000
        + u128::from(epoch) * u128::from(devnet.slots_per_epoch()) * slot_ms
}

/// The next fork digest change after `now_ms`: the epoch it starts at, and when, as Unix
/// milliseconds; `None` if no digest follows.
#[must_use]
pub fn next_digest_change(devnet: &Devnet, now_ms: u128) -> Option<(u64, u128)> {
    let gvr = devnet.genesis().genesis_validators_root;
    digest_schedule(devnet.config(), &gvr)
        .into_iter()
        .map(|e| (e.epoch, epoch_start_ms(devnet, e.epoch)))
        .find(|&(_, at)| at > now_ms)
}

/// How long a run started at `now_ms` may serve: [`clip_until`] the next fork digest change
/// after `now_ms`.
///
/// # Errors
///
/// The next digest starts too soon to serve one slot and check before it.
pub fn clip_serve(
    devnet: &Devnet,
    now_ms: u128,
    serve_for: Duration,
) -> Result<(Duration, Option<u64>), String> {
    clip_until(
        devnet,
        next_digest_change(devnet, now_ms),
        now_ms,
        serve_for,
    )
}

/// How long a run may serve from `now_ms` when the digest it subscribed to ends at `change`
/// (the epoch and its start, [`next_digest_change`] of the run's start): `serve_for`, unless
/// serving and its [`AFTER_SERVING`] check would not end before `change`. The probe subscribes
/// to the column subnets of one digest, so it does not run across a digest change: it serves
/// until [`AFTER_SERVING`] before it, and says so (`Some` of the epoch). The deadline is
/// absolute, counted back from `change`, so `now_ms` can be after a slow start and the run
/// still ends before the same change.
///
/// # Errors
///
/// `change` is too soon (or past) to serve one slot and check before it.
pub fn clip_until(
    devnet: &Devnet,
    change: Option<(u64, u128)>,
    now_ms: u128,
    serve_for: Duration,
) -> Result<(Duration, Option<u64>), String> {
    let Some((epoch, at_ms)) = change else {
        return Ok((serve_for, None));
    };
    let until =
        Duration::from_millis(u64::try_from(at_ms.saturating_sub(now_ms)).unwrap_or(u64::MAX));
    if serve_for + AFTER_SERVING <= until {
        return Ok((serve_for, None));
    }
    let slot = Duration::from_millis(devnet.config().slot_duration_ms());
    match until.checked_sub(AFTER_SERVING) {
        Some(left) if left >= slot => Ok((left, Some(epoch))),
        _ => Err(format!(
            "the fork digest changes at epoch {epoch}, in {} s: too soon to serve and check \
             before it; start after it",
            until.as_secs()
        )),
    }
}

/// When the digest change `change` comes on the monotonic clock, given that `started` was at
/// `started_ms` on the wall clock.
fn boundary_at(
    started: tokio::time::Instant,
    started_ms: u128,
    change: Option<(u64, u128)>,
) -> Option<tokio::time::Instant> {
    change.map(|(_, at_ms)| {
        let ahead = u64::try_from(at_ms.saturating_sub(started_ms)).unwrap_or(u64::MAX);
        started + Duration::from_millis(ahead)
    })
}

/// When the settle wait and the self-check must have ended, serving having ended at `ended`:
/// [`AFTER_SERVING`] later, and before the digest change at `boundary`.
fn check_by(
    ended: tokio::time::Instant,
    boundary: Option<tokio::time::Instant>,
) -> tokio::time::Instant {
    let by = ended + AFTER_SERVING;
    boundary.map_or(by, |b| by.min(b))
}

/// Why the store did not settle ([`settle`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsettled {
    /// Columns still on their way into the store at the end of the wait: the last count.
    Queued(usize),
    /// The queue was empty, but the writer did not confirm within the wait that it was done
    /// (or is gone): it may still be settling the links of what it wrote.
    Writing,
}

/// Waits for the store to settle within `wait`: `pending` (the columns on their way into it)
/// 0, polled every [`PUMP_EVERY`], then the writer's `barrier` confirmed
/// ([`ColumnIngest::settled`]: everything handed to it written and its pending links settled
/// after that), then `pending` still 0. A column gives its queue place back once written,
/// before the writer settles the links after it, so an empty queue alone does not show that
/// the store stopped changing. `Err` if it did not settle: nothing may be compared against it.
///
/// # Errors
///
/// [`Unsettled`]: columns still queued, or no confirmation from the writer, by the end of
/// `wait`.
pub async fn settle<B>(
    pending: impl Fn() -> usize,
    barrier: impl Fn() -> B,
    wait: Duration,
) -> Result<(), Unsettled>
where
    B: std::future::Future<Output = bool>,
{
    let by = tokio::time::Instant::now() + wait;
    loop {
        let mut left = pending();
        if left == 0 {
            match tokio::time::timeout_at(by, barrier()).await {
                Ok(true) => {
                    left = pending();
                    if left == 0 {
                        return Ok(());
                    }
                }
                Ok(false) | Err(_) => return Err(Unsettled::Writing),
            }
        }
        if tokio::time::Instant::now() >= by {
            return Err(Unsettled::Queued(left));
        }
        tokio::time::sleep(PUMP_EVERY.min(by - tokio::time::Instant::now())).await;
    }
}

/// Refuses a parent directory of the new store that other users could change, or the way to
/// it ([`ipc::uds::open_closed_dir`], as for the socket root): walked from `/` without
/// following a symlink, it and every directory above it must be owned by `uid` or root and
/// not group or world writable unless sticky. The store is created here and opened again by
/// path ([`ColumnWriter::open`]); with any such directory on the way another user could
/// rename one away and put theirs in its place in between, or point the failed start's
/// cleanup elsewhere.
fn check_store_parent(parent: &Path, uid: u32) -> Result<(), String> {
    ipc::uds::open_closed_dir(parent, uid)
        .map(drop)
        .map_err(|e| format!("column store parent {e}"))
}

/// The column store's directory this run created ([`create_store_dir`]).
#[derive(Debug)]
struct NewStore {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl NewStore {
    /// Removes the store after a failed start, but only while its path still names the
    /// directory this run created (same device and inode, not followed through a symlink):
    /// whatever is in its place by then is left alone.
    fn remove(self) {
        use std::os::unix::fs::MetadataExt;
        let ours = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.is_dir() && (m.dev(), m.ino()) == (self.dev, self.ino));
        if !ours {
            tracing::warn!(
                path = %self.path.display(),
                "the new column store is no longer there: nothing removed"
            );
            return;
        }
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            tracing::warn!(error = %e, "the new column store is left behind");
        }
    }
}

/// Creates the column store's directory, mode 0700, under a parent no other user can change
/// ([`check_store_parent`]); a relative path is taken from the working directory. It must not
/// exist yet, not even as a symlink: every run serves under a fresh node key, whose custody
/// columns are its own.
fn create_store_dir(path: &Path) -> Result<NewStore, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let shown = path.display();
    let path = std::env::current_dir()
        .map_err(|e| format!("column store {shown}: the working directory: {e}"))?
        .join(path);
    let (Some(parent), Some(_)) = (path.parent(), path.file_name()) else {
        return Err(format!("column store {shown} names no new directory"));
    };
    check_store_parent(parent, Ownership::current().uid)?;
    match std::fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(format!(
                "{shown} exists: every run serves under a fresh node key, whose custody \
                 columns are its own, so its column store must be new"
            ))
        }
        Err(e) => return Err(format!("column store {shown}: {e}")),
    }
    let created =
        std::fs::symlink_metadata(&path).map_err(|e| format!("column store {shown}: {e}"))?;
    Ok(NewStore {
        path,
        dev: created.dev(),
        ino: created.ino(),
    })
}

/// The `serve` check: cl-chain and cl-p2p as [`ChainSide`] and [`p2p_swarm`], connected over
/// cl-chain's socket, the reference CLs `plan.peers` dialled, served for `plan.serve_for`
/// (clipped before the next fork digest change after `now_ms`, [`clip_until`], again once the
/// start is done), then [`self_check`]ed with the hand-off to the store stopped, once the store
/// settled ([`settle`]), and by [`check_by`]. `reference` is the first reference CL's beacon API, `kzg`
/// cl-verify, and `tap` the capture queue between the swarm and the store. `now_ms` is the
/// wall clock. The column store's directory is created here, and removed again if the run
/// ends before serving: the start fails, the swarm listens nowhere, or the clip after the start
/// fails.
pub async fn serve<E: EthSpec, V: KzgVerifier + 'static>(
    devnet: &Devnet,
    reference: BeaconApi,
    kzg: V,
    plan: &ServePlan,
    tap: (CaptureTap, CaptureReader),
    now_ms: u128,
) -> Check {
    let mut check = Check::new(NAME);
    let started_at = tokio::time::Instant::now();
    // The digest whose column subnets the run subscribes to ends here: every deadline of the
    // run is counted back from it.
    let change = next_digest_change(devnet, now_ms);
    if let Err(e) = clip_until(devnet, change, now_ms, plan.serve_for) {
        return Check::failed(NAME, e);
    }
    let store = match create_store_dir(&plan.columns_dir) {
        Ok(store) => store,
        Err(e) => return Check::failed(NAME, e),
    };
    let key = Keypair::generate_secp256k1();
    let mut registry = Registry::default();
    let started = async {
        let id = node_id(&key)?;
        let link = chain_link::<E>(devnet, now_ms)?;
        let digest = devnet
            .fork_digest(now_ms)
            .map_err(|e| format!("our fork digest: {e}"))?;
        let cgc_set_slot = slot_at(devnet, now_ms).ok_or("the clock is before genesis")?;
        let uid = Ownership::current().uid;
        let chain = ChainSide::<E, V>::start(
            devnet,
            ChainPlan {
                link: link.clone(),
                node_id: id,
                columns_dir: plan.columns_dir.clone(),
                socket_root: plan.socket_root.clone(),
                caller_uid: uid,
                reference,
                kzg,
                verify_timeout: plan.verify_timeout,
                cgc_set_slot,
            },
            &mut registry,
        )?;
        // A Status never waits on the reference API: sampled now, so the first has one.
        if let Err(e) = chain.sample_reference().await {
            tracing::warn!(error = %e, "no reference sample for our Status yet");
        }
        let swarm_plan = SwarmPlan {
            listen: plan.listen.clone(),
            idle: Duration::from_secs(60),
            bypass: plan.peers.iter().map(|p| p.peer_id).collect(),
            muxer_observer: None,
            ping_interval: cl_p2p::rpc::inbound::PING_INTERVAL,
            gossip: None,
            limits: RpcLimits {
                column_answer_prefixes: plan.answer_prefixes,
                ..RpcLimits::default()
            },
        };
        let p2p = p2p_swarm::<E>(
            devnet,
            link,
            chain.socket(),
            uid,
            key.clone(),
            swarm_plan,
            chain.custody_columns(),
            chain.custody_group_count(),
            digest,
            tap.0,
        )
        .await?;
        Ok::<_, String>((chain, p2p, digest))
    };
    let (chain, p2p, digest) = match started.await {
        Ok(started) => started,
        Err(e) => {
            store.remove();
            return Check::failed(NAME, e);
        }
    };
    let P2pSide {
        mut swarm,
        status,
        refresh: _refresh,
    } = p2p;
    let peer = *swarm.local_peer_id();
    check.pass(format!(
        "serving custody columns {:?} (cgc {}) as {peer}, cl-chain on {}",
        chain.custody_columns(),
        chain.custody_group_count(),
        chain.socket().display()
    ));
    // Where it listens, before anything else.
    let mut listening = Vec::new();
    let deadline = tokio::time::Instant::now() + REQUEST_DEADLINE;
    while listening.len() < plan.listen.len().max(1) {
        match tokio::time::timeout_at(deadline, swarm.select_next_some()).await {
            Ok(SwarmEvent::NewListenAddr { address, .. }) => listening.push(address),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let Some(target) = requester_target(&listening) else {
        check.fail("the probe swarm listens nowhere");
        // Nothing served: the store goes, as after a failed start, once nothing holds it.
        drop((swarm, status, chain));
        store.remove();
        return check;
    };
    // Our Status first: a reference CL we dial without one would drop us.
    let deadline = tokio::time::Instant::now() + REQUEST_DEADLINE;
    while status.status().is_none() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(PUMP_EVERY).await;
    }
    match status.status() {
        Some(ours) => check.pass(format!(
            "our Status from cl-chain's GetStatus: head slot {}, earliest_available_slot {}",
            ours.head_slot, ours.earliest_available_slot
        )),
        None => check.fail("no Status of ours from cl-chain's GetStatus"),
    }
    for p in &plan.peers {
        let opts = DialOpts::peer_id(p.peer_id)
            .addresses(vec![p.addr.clone()])
            .build();
        if let Err(e) = swarm.dial(opts) {
            check.fail(format!("dial {}: {e}", p.peer_id));
        }
    }
    // The start took its time: clipped again from the clock now, before the same change.
    let serving_from = now_ms + started_at.elapsed().as_millis();
    let (serve_for, clipped) = match clip_until(devnet, change, serving_from, plan.serve_for) {
        Ok(clip) => clip,
        Err(e) => {
            check.fail(format!(
                "after a start of {} s: {e}",
                started_at.elapsed().as_secs()
            ));
            drop((swarm, status, chain));
            store.remove();
            return check;
        }
    };
    if let Some(epoch) = clipped {
        check.pass(format!(
            "serving for {} s, not {} s: the fork digest changes at epoch {epoch}",
            serve_for.as_secs(),
            plan.serve_for.as_secs()
        ));
    }
    let chain = Arc::new(chain);
    let pumping = Arc::new(AtomicBool::new(true));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let driver = tokio::spawn(drive(
        swarm,
        Arc::clone(&chain),
        tap.1,
        Arc::clone(&pumping),
        stopped,
    ));
    tokio::time::sleep(serve_for).await;
    // The hand-off stops, and what is on its way in settles: the check reads one store. Both
    // end by `check_by`, before the digest change.
    pumping.store(false, Ordering::SeqCst);
    let by = check_by(
        tokio::time::Instant::now(),
        boundary_at(started_at, now_ms, change),
    );
    let wait = SETTLE_WAIT.min(by.saturating_duration_since(tokio::time::Instant::now()));
    let settled = settle(|| chain.pending(), || chain.settled(), wait).await;
    let stored = chain.reader().column_count().unwrap_or(0);
    check.record(
        stored > 0,
        format!(
            "{stored} custody columns stored in {} s, earliest_available_slot {:?}; dropped: {}",
            serve_for.as_secs(),
            chain.earliest_available_slot(),
            drops(&registry)
        ),
    );
    // To the end of the epoch serving ended in: the serve range ends there.
    let last_slot = slot_at(devnet, serving_from + serve_for.as_millis())
        .unwrap_or(u64::MAX)
        .saturating_add(devnet.slots_per_epoch());
    match settled {
        Err(Unsettled::Queued(left)) => check.fail(format!(
            "ingest did not settle: {left} columns still on their way into the store after {} \
             s, so no answer is checked against it",
            wait.as_secs()
        )),
        Err(Unsettled::Writing) => check.fail(format!(
            "ingest did not settle: the store's writer did not confirm it was done within {} s, \
             so no answer is checked against it",
            wait.as_secs()
        )),
        Ok(()) => {
            let checked = self_check(&mut check, &chain, devnet, peer, target, digest, last_slot);
            if tokio::time::timeout_at(by, checked).await.is_err() {
                check.fail(format!(
                    "the self-check did not end within {} s of serving{}",
                    AFTER_SERVING.as_secs(),
                    change.map_or_else(String::new, |(epoch, _)| format!(
                        " and before the fork digest changes at epoch {epoch}"
                    ))
                ));
            }
        }
    }
    let _ = stop.send(());
    let _ = driver.await;
    check
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::devnet;
    use consensus_types::Minimal;

    #[test]
    fn the_node_id_is_the_records() {
        let key = Keypair::generate_secp256k1();
        let secp = key.clone().try_into_secp256k1().unwrap();
        let mut secret = secp.secret().to_bytes();
        let combined = cl_discv5::enr::CombinedKey::secp256k1_from_bytes(&mut secret).unwrap();
        let fork = devnet().fork_fields(crate::fixtures::now_ms()).unwrap();
        let addr = cl_discv5::enr::LocalAddr::new(std::net::Ipv4Addr::LOCALHOST);
        let enr = cl_discv5::enr::build_local_enr(&combined, &fork, 4, &addr).unwrap();
        assert_eq!(
            node_id(&key).unwrap(),
            U256::from_be_bytes(enr.node_id().raw())
        );
        assert!(node_id(&Keypair::generate_ed25519()).is_err());
    }

    #[test]
    fn the_acl_lets_cl_p2p_call_the_serving_methods_only() {
        let acl = chain_acl(990).unwrap();
        for method in CHAIN_METHODS {
            assert!(acl.allows(method, 990), "{method}");
            assert!(!acl.allows(method, 991), "{method}");
        }
        assert!(!acl.allows("/ethswarm.chain.v1.ReqRespService/GetMetadata", 990));
        assert!(!acl.allows("/ethswarm.chain.v1.GossipService/Validate", 990));
    }

    #[test]
    fn the_link_holds_every_digest_and_our_pin() {
        let devnet = devnet();
        let now = crate::fixtures::now_ms();
        let link = chain_link::<Minimal>(&devnet, now).unwrap();
        let hello = link.local();
        assert_eq!(hello.genesis_validators_root, [0x42; 32]);
        assert_eq!(hello.current_fork_digest, devnet.fork_digest(now).unwrap());
        assert_eq!(hello.fork_schedule.len(), 3);
        assert_eq!(hello.blob_schedule.len(), 1);
        assert_eq!(hello.spec_pin, Some(spec_pin()));
        assert_eq!(verify_hello().spec_pin, Some(spec_pin()));
        assert!(verify_hello().genesis_validators_root.is_empty());
        let before = u128::from(devnet.genesis().genesis_time) * 1000 - 1;
        assert!(chain_link::<Minimal>(&devnet, before).is_err());
    }

    /// A run ends before the next fork digest, by [`AFTER_SERVING`]: cut short when it would
    /// cross it, refused when too close to it, as asked when no digest follows in time.
    #[test]
    fn a_run_is_cut_before_the_next_fork_digest() {
        let devnet = devnet();
        // The fixture: Fulu at 0, a blob change at 1, Gloas at 2; 6 s slots, 8 per epoch.
        let at = |epoch: u64, slot: u64| {
            u128::from(devnet.genesis().genesis_time) * 1000 + u128::from(epoch * 8 + slot) * 6_000
        };
        let five = Duration::from_secs(5);
        // In epoch 1, Gloas (epoch 2) 48 s away: 5 s and the check fit before it.
        assert_eq!(clip_serve(&devnet, at(1, 0), five), Ok((five, None)));
        // 300 s would cross it: cut to 48 - 30 s.
        assert_eq!(
            clip_serve(&devnet, at(1, 0), Duration::from_secs(300)),
            Ok((Duration::from_secs(18), Some(2)))
        );
        // One slot before it: refused.
        let refused = clip_serve(&devnet, at(1, 7), five).unwrap_err();
        assert!(refused.contains("epoch 2"), "{refused}");
        // Past every digest change: as asked.
        let long = Duration::from_secs(86_400);
        assert_eq!(clip_serve(&devnet, at(5, 0), long), Ok((long, None)));
    }

    /// After startup the run is clipped again from where the clock is, against the digest it
    /// subscribed to at its start: never against a later change once startup ran past it.
    #[test]
    fn the_clip_counts_from_the_digest_boundary_after_startup() {
        let devnet = devnet();
        // The fixture: Fulu at 0, a blob change at 1, Gloas at 2; 6 s slots, 8 per epoch.
        let at = |epoch: u64, slot: u64| {
            u128::from(devnet.genesis().genesis_time) * 1000 + u128::from(epoch * 8 + slot) * 6_000
        };
        let long = Duration::from_secs(300);
        let change = next_digest_change(&devnet, at(1, 0));
        assert_eq!(change, Some((2, at(2, 0))));
        assert_eq!(
            clip_until(&devnet, change, at(1, 0), long),
            clip_serve(&devnet, at(1, 0), long)
        );
        // A 10 s start: 10 s less to serve, the same boundary.
        assert_eq!(
            clip_until(&devnet, change, at(1, 0) + 10_000, long),
            Ok((Duration::from_secs(8), Some(2)))
        );
        // A start that leaves less than a slot to serve before the check: refused.
        let late = clip_until(&devnet, change, at(1, 0) + 13_000, long).unwrap_err();
        assert!(late.contains("epoch 2"), "{late}");
        // A start that ran past the boundary: refused, where a clip from the clock alone
        // would find no later change and serve as asked.
        let past = at(2, 0) + 1_000;
        let five = Duration::from_secs(5);
        assert!(clip_until(&devnet, change, past, five)
            .unwrap_err()
            .contains("epoch 2"));
        assert_eq!(clip_serve(&devnet, past, five), Ok((five, None)));
        // No change ahead: as asked.
        assert_eq!(clip_until(&devnet, None, past, long), Ok((long, None)));
    }

    /// The settle wait and the self-check end by [`AFTER_SERVING`] after serving, and before
    /// the digest the run subscribed to ends.
    #[test]
    fn the_check_ends_before_the_digest_boundary() {
        let start = tokio::time::Instant::now();
        let boundary = boundary_at(start, 1_000, Some((2, 49_000)));
        assert_eq!(boundary, Some(start + Duration::from_secs(48)));
        assert_eq!(boundary_at(start, 1_000, None), None);
        let ended = start + Duration::from_secs(10);
        assert_eq!(check_by(ended, None), ended + AFTER_SERVING);
        assert_eq!(check_by(ended, boundary), ended + AFTER_SERVING);
        let late = start + Duration::from_secs(40);
        assert_eq!(check_by(late, boundary), boundary.unwrap());
    }

    /// The self-check runs only on a store that settled: nothing pending, the writer's
    /// barrier confirmed after that, and still nothing pending. One still changing at the end
    /// of the wait is reported, never compared.
    #[tokio::test(start_paused = true)]
    async fn the_store_settles_or_the_check_does_not_run() {
        use std::sync::atomic::AtomicUsize;
        let confirmed = || async { true };
        let left = Arc::new(AtomicUsize::new(5));
        let draining = Arc::clone(&left);
        tokio::spawn(async move {
            while draining.load(Ordering::SeqCst) > 0 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                draining.fetch_sub(1, Ordering::SeqCst);
            }
        });
        let start = tokio::time::Instant::now();
        assert_eq!(
            settle(|| left.load(Ordering::SeqCst), confirmed, SETTLE_WAIT).await,
            Ok(())
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        // Never drained: not settled, at the end of the wait.
        let start = tokio::time::Instant::now();
        assert_eq!(
            settle(|| 2, confirmed, SETTLE_WAIT).await,
            Err(Unsettled::Queued(2))
        );
        assert!(start.elapsed() >= SETTLE_WAIT);
        assert!(start.elapsed() <= SETTLE_WAIT + PUMP_EVERY);
        // Empty while the barrier went through, then not: not settled either.
        let polls = AtomicUsize::new(0);
        let flapping = || usize::from(polls.fetch_add(1, Ordering::SeqCst) % 2 == 1);
        assert!(settle(flapping, confirmed, SETTLE_WAIT).await.is_err());
        // No wait left: one look.
        assert_eq!(
            settle(|| 1, confirmed, Duration::ZERO).await,
            Err(Unsettled::Queued(1))
        );
    }

    /// A writer still settling links once the queue is empty does not let the self-check
    /// start: the settle waits for its barrier, and one that never comes fails the wait.
    #[tokio::test(start_paused = true)]
    async fn the_settle_waits_for_the_writers_barrier() {
        let settling_until = tokio::time::Instant::now() + Duration::from_millis(700);
        let barrier = || async move {
            tokio::time::sleep_until(settling_until).await;
            true
        };
        let start = tokio::time::Instant::now();
        assert_eq!(settle(|| 0, barrier, SETTLE_WAIT).await, Ok(()));
        assert_eq!(start.elapsed(), Duration::from_millis(700), "not before it");
        // A writer that never confirms, or is gone.
        let never = || std::future::pending::<bool>();
        let start = tokio::time::Instant::now();
        assert_eq!(
            settle(|| 0, never, SETTLE_WAIT).await,
            Err(Unsettled::Writing)
        );
        assert_eq!(start.elapsed(), SETTLE_WAIT);
        let gone = || async { false };
        assert_eq!(
            settle(|| 0, gone, SETTLE_WAIT).await,
            Err(Unsettled::Writing)
        );
    }

    /// A temporary directory named without symlinks (macOS's `/var` is one).
    fn real_tempdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path()).unwrap();
        (dir, path)
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The new store's parent must not let other users swap the store between its creation
    /// and its opening by path: owned by us or root, and writable by no one else unless
    /// sticky.
    #[test]
    fn the_store_parent_is_closed_to_other_users() {
        let uid = Ownership::current().uid;
        let (_tmp, dir) = real_tempdir();
        for (mode, ok) in [
            (0o700, true),
            (0o755, true),
            (0o1777, true),
            (0o1770, true),
            (0o777, false),
            (0o770, false),
            (0o702, false),
        ] {
            set_mode(&dir, mode);
            let checked = check_store_parent(&dir, uid);
            assert_eq!(checked.is_ok(), ok, "{mode:o}: {checked:?}");
            if let Err(e) = checked {
                assert!(e.contains("not writable by others"), "{e}");
            }
        }
        // Under such a parent nothing is created.
        set_mode(&dir, 0o777);
        let columns = dir.join("columns");
        let refused = create_store_dir(&columns).unwrap_err();
        assert!(refused.starts_with("column store"), "{refused}");
        assert!(!columns.exists());
        set_mode(&dir, 0o700);
        create_store_dir(&columns).unwrap();
        // Owned by another user than us (and not root): refused.
        if uid != 0 {
            let other = check_store_parent(&dir, uid + 1).unwrap_err();
            assert!(other.contains("owned by"), "{other}");
        }
        // A parent that is not a directory.
        let file = dir.join("file");
        std::fs::write(&file, b"").unwrap();
        let not_dir = check_store_parent(&file, uid).unwrap_err();
        assert!(not_dir.contains("not a directory"), "{not_dir}");
    }

    /// Every directory on the way to the store is checked, not only its parent: under a
    /// directory others can write, the next one down could be renamed away and replaced.
    #[test]
    fn every_ancestor_of_the_store_is_closed_to_other_users() {
        let (_tmp, dir) = real_tempdir();
        // `shared` (0777, no sticky bit) / `mine` (0700) / `columns`.
        let shared = dir.join("shared");
        let mine = shared.join("mine");
        std::fs::create_dir_all(&mine).unwrap();
        set_mode(&mine, 0o700);
        set_mode(&shared, 0o777);
        let columns = mine.join("columns");
        let refused = create_store_dir(&columns).unwrap_err();
        assert!(refused.contains("not writable by others"), "{refused}");
        assert!(refused.contains("shared"), "names the ancestor: {refused}");
        assert!(!columns.exists(), "nothing created under it");
        // Sticky, as /tmp is: nobody else can rename `mine`.
        set_mode(&shared, 0o1777);
        create_store_dir(&columns).unwrap();
        set_mode(&shared, 0o755);
    }

    /// A symlink anywhere on the way to the store is refused, not followed, even one only we
    /// can change: the path is checked as it is named.
    #[test]
    fn a_symlinked_ancestor_of_the_store_is_refused() {
        let (_tmp, dir) = real_tempdir();
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        set_mode(&real, 0o700);
        std::os::unix::fs::symlink(&real, dir.join("link")).unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("up")).unwrap();
        for via in [dir.join("link/columns"), dir.join("up/real/columns")] {
            let refused = create_store_dir(&via).unwrap_err();
            assert!(refused.contains("symlink"), "{}: {refused}", via.display());
            assert!(!real.join("columns").exists(), "nothing created through it");
        }
        // A relative path or one with `..` is not walked from `/`.
        let odd = create_store_dir(&real.join("../real/columns")).unwrap_err();
        assert!(odd.contains(".."), "{odd}");
    }

    /// A root-owned sticky ancestor, such as /tmp, is closed enough: nobody else can rename
    /// or replace what we create in it.
    #[test]
    fn a_root_owned_sticky_ancestor_is_accepted() {
        use std::os::unix::fs::MetadataExt;
        let sticky = ["/tmp", "/private/tmp", "/var/tmp"].into_iter().find(|p| {
            std::fs::symlink_metadata(p)
                .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o1002 == 0o1002)
        });
        let Some(sticky) = sticky else {
            eprintln!("a_root_owned_sticky_ancestor_is_accepted: no root-owned sticky /tmp here");
            return;
        };
        let uid = Ownership::current().uid;
        assert_eq!(check_store_parent(Path::new(sticky), uid), Ok(()));
        let dir = tempfile::Builder::new()
            .prefix("store-")
            .tempdir_in(sticky)
            .unwrap();
        let columns = dir.path().join("columns");
        create_store_dir(&columns).unwrap();
        assert!(columns.is_dir());
    }

    /// The cleanup of a failed start removes the directory this run created and nothing
    /// else: whatever is in its place by then, a directory or a symlink, is left alone.
    #[test]
    fn the_cleanup_removes_only_the_store_this_run_created() {
        let (_tmp, dir) = real_tempdir();
        let columns = dir.join("columns");
        // The store, with something in it: removed whole.
        let store = create_store_dir(&columns).unwrap();
        std::fs::write(columns.join("data.mdb"), b"x").unwrap();
        store.remove();
        assert!(!columns.exists());
        // Another directory in its place: left alone, with what it holds.
        let store = create_store_dir(&columns).unwrap();
        let moved = dir.join("moved");
        std::fs::rename(&columns, &moved).unwrap();
        std::fs::create_dir(&columns).unwrap();
        std::fs::write(columns.join("theirs"), b"x").unwrap();
        store.remove();
        assert!(
            columns.join("theirs").exists(),
            "another directory is not removed"
        );
        assert!(moved.is_dir(), "nor the moved store, by another name");
        // A symlink in its place: neither it nor its target is touched.
        std::fs::remove_dir_all(&columns).unwrap();
        let store = create_store_dir(&columns).unwrap();
        std::fs::remove_dir(&columns).unwrap();
        std::os::unix::fs::symlink(&moved, &columns).unwrap();
        store.remove();
        assert!(std::fs::symlink_metadata(&columns)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(moved.is_dir());
    }

    #[test]
    fn the_wall_clock_slot() {
        let devnet = devnet();
        let genesis_ms = u128::from(devnet.genesis().genesis_time) * 1000;
        assert_eq!(slot_at(&devnet, genesis_ms - 1), None);
        assert_eq!(slot_at(&devnet, genesis_ms), Some(0));
        assert_eq!(slot_at(&devnet, genesis_ms + 6_000 * 9 + 5), Some(9));
    }

    #[test]
    fn the_requester_dials_a_loopback_listen_address() {
        let addr = |s: &str| s.parse::<Multiaddr>().unwrap();
        let listening = [
            addr("/ip4/10.0.0.2/tcp/9000"),
            addr("/ip4/127.0.0.1/tcp/9000"),
        ];
        assert_eq!(requester_target(&listening), Some(listening[1].clone()));
        let v6 = [addr("/ip6/fd00::2/tcp/9000"), addr("/ip6/::1/tcp/9000")];
        assert_eq!(requester_target(&v6), Some(v6[1].clone()));
        assert_eq!(
            requester_target(&listening[..1]),
            Some(listening[0].clone())
        );
        assert_eq!(requester_target(&[]), None);
    }

    #[test]
    fn a_range_answer_is_judged_against_the_store() {
        let (a, b, c, d) = (vec![1u8], vec![2u8], vec![3u8], vec![4u8]);
        let order: std::collections::HashMap<&[u8], (usize, u64, [u8; 32])> = [
            (a.as_slice(), (0, 10, [1; 32])),
            (b.as_slice(), (1, 10, [1; 32])),
            (c.as_slice(), (2, 11, [2; 32])),
            (d.as_slice(), (3, 11, [2; 32])),
        ]
        .into();
        let digest = |slot: u64| Some([slot as u8; 4]);
        let ok = [([10; 4], a.clone()), ([10; 4], b.clone())];
        assert_eq!(judge_range(&ok, &order, 2, digest), Ok(()));
        let unknown = [([10; 4], vec![9u8])];
        assert!(judge_range(&unknown, &order, 2, digest)
            .unwrap_err()
            .contains("not one"));
        let context = [([0; 4], a.clone())];
        assert!(judge_range(&context, &order, 1, digest)
            .unwrap_err()
            .contains("context"));
        let backwards = [([10; 4], b.clone()), ([10; 4], a.clone())];
        assert!(judge_range(&backwards, &order, 2, digest)
            .unwrap_err()
            .contains("order"));
        let partial = [
            ([10; 4], a.clone()),
            ([10; 4], b.clone()),
            ([11; 4], c.clone()),
        ];
        assert!(judge_range(&partial, &order, 2, digest)
            .unwrap_err()
            .contains("1 of its 2"));
    }

    #[test]
    fn the_chunks_of_an_answer() {
        let error = ReceivedChunk::<Minimal> {
            context: None,
            chunk: ResponseChunk::Error {
                code: ResultCode::ResourceUnavailable,
                message: b"resource unavailable".to_vec().try_into().unwrap(),
            },
        };
        assert_eq!(
            answer_of(vec![error.clone()]),
            Ok(ColumnAnswer::Refused(ResultCode::ResourceUnavailable))
        );
        assert_eq!(
            answer_of::<Minimal>(Vec::new()),
            Ok(ColumnAnswer::Sidecars(Vec::new()))
        );
        let sidecar = p2p_wire::testkit::gloas_sidecar::<Minimal>(9, 1);
        let chunk = ReceivedChunk::<Minimal> {
            context: Some([1; 4]),
            chunk: ResponseChunk::Success(Response::DataColumn(Box::new(
                forked::DataColumnSidecar::Gloas(sidecar.clone()),
            ))),
        };
        assert_eq!(
            answer_of(vec![chunk.clone()]),
            Ok(ColumnAnswer::Sidecars(vec![(
                [1; 4],
                sidecar.as_ssz_bytes()
            )]))
        );
        assert!(answer_of(vec![chunk, error])
            .unwrap_err()
            .contains("chunk 1"));
    }

    #[tokio::test]
    async fn the_requester_reports_a_failed_dial() {
        let mut requester = ColumnRequester::<Minimal>::new(&devnet()).unwrap();
        let closed = cl_p2p::testkit::refused_tcp_addr(std::net::Ipv4Addr::LOCALHOST.into());
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", closed.port())
            .parse()
            .unwrap();
        let err = requester.connect(PeerId::random(), addr).await.unwrap_err();
        assert!(err.starts_with("dial"), "{err}");
    }

    #[test]
    fn drops_name_every_reason_counted() {
        let mut registry = Registry::default();
        assert_eq!(drops(&registry), "none");
        // The family the store counts its drops in, as it registers it.
        let dropped = prometheus_client::metrics::family::Family::<
            Vec<(&str, &str)>,
            prometheus_client::metrics::counter::Counter,
        >::default();
        registry.register("probe_column_dropped", "drops", dropped.clone());
        assert_eq!(drops(&registry), "none", "no series yet");
        let _ = dropped.get_or_create(&vec![("reason", "wrong_subnet")]);
        dropped
            .get_or_create(&vec![("reason", "not_custody")])
            .inc_by(2);
        dropped
            .get_or_create(&vec![("reason", "kzg_invalid")])
            .inc();
        let text = drops(&registry);
        assert!(!text.contains("wrong_subnet"), "{text}");
        assert!(text.contains("not_custody=2"), "{text}");
        assert!(text.contains("kzg_invalid=1"), "{text}");
    }
}
