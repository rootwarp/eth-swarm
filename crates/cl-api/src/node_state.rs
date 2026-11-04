//! What `node/health` and `node/syncing` report: cl-chain's last chain status, set against the
//! wall clock.
//!
//! cl-chain is the single writer of the head, optimistic status and the engine's state
//! (ARCH §8a). cl-api polls chain.v1 `ImportService.GetChainStatus` ([`poll_chain`], one call
//! per poll interval). From each `SyncStatus` it keeps `head_slot`, `optimistic` and
//! `el_offline` ([`ChainHead`]).
//!
//! - **Not initialised.** Until the first status arrives, health is 503. `syncing` then reports
//!   head slot 0 and `is_syncing=true`.
//! - **`sync_distance`** is the wall-clock slot ([`SlotClock`]) minus the head slot. sync.v1 has
//!   no status RPC yet. `is_syncing` is a distance above the tolerance ([`SYNC_TOLERANCE_SLOTS`]).
//! - **Chain unreachable** (the AC8 case). A poll that fails, times out or gets no status marks
//!   cl-chain unreachable at once. `syncing` then reports `is_syncing=true` from the last cached
//!   head, and health is 206, never 200. The next good status clears it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ethswarm_proto::chain as pb;
use pb::import_service_client::ImportServiceClient;
use tonic::codegen::{Body, Bytes, StdError};

/// The largest `sync_distance` that still counts as synced. A slot or two without a block is
/// normal, so the tolerance allows 8 of them before the node reports syncing.
pub const SYNC_TOLERANCE_SLOTS: u64 = 8;

type Now = Arc<dyn Fn() -> Duration + Send + Sync>;

/// The wall-clock slot of the network.
#[derive(Clone)]
pub struct SlotClock {
    genesis_time: u64,
    slot_duration_ms: u64,
    now: Now,
}

impl std::fmt::Debug for SlotClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotClock")
            .field("genesis_time", &self.genesis_time)
            .field("slot_duration_ms", &self.slot_duration_ms)
            .finish_non_exhaustive()
    }
}

impl SlotClock {
    /// The slots of a network with `genesis_time` (Unix seconds) and `slot_duration_ms`, on the
    /// system clock.
    #[must_use]
    pub fn new(genesis_time: u64, slot_duration_ms: u64) -> Self {
        Self::with_now(genesis_time, slot_duration_ms, || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
        })
    }

    /// [`Self::new`] on `now` (the time since the Unix epoch).
    #[must_use]
    pub fn with_now(
        genesis_time: u64,
        slot_duration_ms: u64,
        now: impl Fn() -> Duration + Send + Sync + 'static,
    ) -> Self {
        let _ = (genesis_time, slot_duration_ms, now);
        todo!()
    }

    /// The current slot: 0 before genesis.
    #[must_use]
    pub fn current_slot(&self) -> u64 {
        todo!()
    }
}

/// What one chain status says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub head_slot: u64,
    /// cl-chain is tracking the head optimistically.
    pub optimistic: bool,
    /// cl-chain cannot reach the execution engine.
    pub el_offline: bool,
}

impl From<&pb::SyncStatus> for ChainHead {
    fn from(status: &pb::SyncStatus) -> Self {
        let _ = status;
        todo!()
    }
}

/// `node/syncing`'s data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syncing {
    pub head_slot: u64,
    pub sync_distance: u64,
    pub is_syncing: bool,
    pub is_optimistic: bool,
    pub el_offline: bool,
}

/// `node/health`'s answer, before any `syncing_status` override.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    /// 200: synced, not optimistic, the engine online and cl-chain reachable.
    Ready,
    /// 206: syncing, optimistic, the engine offline, or cl-chain unreachable since its last
    /// status.
    Degraded,
    /// 503: no chain status yet.
    NotInitialised,
}

/// The node's state, shared by the poller and the handlers.
#[derive(Clone, Debug)]
pub struct NodeState {
    clock: SlotClock,
    sync_tolerance: u64,
    last: Arc<Mutex<Last>>,
}

/// The last poll's outcome.
#[derive(Clone, Copy, Debug, Default)]
struct Last {
    /// The last status cl-chain sent.
    head: Option<ChainHead>,
    /// Whether the last poll got a status.
    reachable: bool,
}

impl NodeState {
    /// No status yet, a tolerance of [`SYNC_TOLERANCE_SLOTS`].
    #[must_use]
    pub fn new(clock: SlotClock) -> Self {
        let _ = clock;
        todo!()
    }

    /// Records a status cl-chain sent.
    pub fn record_head(&self, head: ChainHead) {
        let _ = head;
        todo!()
    }

    /// Records a poll that got no status. The last head stays cached.
    pub fn record_unreachable(&self) {
        todo!()
    }

    /// Whether the last poll got a status.
    #[must_use]
    pub fn chain_reachable(&self) -> bool {
        todo!()
    }

    /// `node/syncing`'s data now.
    #[must_use]
    pub fn syncing(&self) -> Syncing {
        todo!()
    }

    /// `node/health`'s answer now.
    #[must_use]
    pub fn health(&self) -> Health {
        todo!()
    }
}

/// One poll: a `GetChainStatus` call, given at most `timeout`, recorded in `state`.
pub async fn poll_once<T>(client: &mut ImportServiceClient<T>, state: &NodeState, timeout: Duration)
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    let _ = (client, state, timeout);
    todo!()
}

/// Polls every `interval` until `shutdown`. Each call gets `interval` at most.
pub async fn poll_chain(
    client: ImportServiceClient<tonic::transport::Channel>,
    state: NodeState,
    interval: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let _ = (client, state, interval, shutdown);
    todo!()
}
