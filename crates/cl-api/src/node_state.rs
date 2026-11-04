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

use std::sync::{Arc, Mutex, PoisonError};
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
        Self {
            genesis_time,
            slot_duration_ms: slot_duration_ms.max(1),
            now: Arc::new(now),
        }
    }

    /// The current slot: 0 before genesis.
    #[must_use]
    pub fn current_slot(&self) -> u64 {
        let now_ms = u64::try_from((self.now)().as_millis()).unwrap_or(u64::MAX);
        now_ms.saturating_sub(self.genesis_time.saturating_mul(1000)) / self.slot_duration_ms
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
        Self {
            head_slot: status.head_slot,
            optimistic: status.optimistic,
            el_offline: status.el_offline,
        }
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
    /// No status yet.
    #[must_use]
    pub fn new(clock: SlotClock) -> Self {
        Self {
            clock,
            last: Arc::default(),
        }
    }

    fn last(&self) -> Last {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a status cl-chain sent; returns whether the poll before got one too.
    pub fn record_head(&self, head: ChainHead) -> bool {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let was = last.reachable;
        *last = Last {
            head: Some(head),
            reachable: true,
        };
        was
    }

    /// Records a poll that got no status, keeping the last head; returns whether the poll
    /// before got one.
    pub fn record_unreachable(&self) -> bool {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut last.reachable, false)
    }

    /// Whether the last poll got a status.
    #[must_use]
    pub fn chain_reachable(&self) -> bool {
        self.last().reachable
    }

    /// `node/syncing`'s data now.
    #[must_use]
    pub fn syncing(&self) -> Syncing {
        self.view(self.last())
    }

    /// `node/health`'s answer now.
    #[must_use]
    pub fn health(&self) -> Health {
        let last = self.last();
        if last.head.is_none() {
            return Health::NotInitialised;
        }
        let s = self.view(last);
        if s.is_syncing || s.is_optimistic || s.el_offline {
            Health::Degraded
        } else {
            Health::Ready
        }
    }

    fn view(&self, last: Last) -> Syncing {
        let wall = self.clock.current_slot();
        let Some(head) = last.head else {
            return Syncing {
                head_slot: 0,
                sync_distance: wall,
                is_syncing: true,
                is_optimistic: false,
                el_offline: false,
            };
        };
        let sync_distance = wall.saturating_sub(head.head_slot);
        Syncing {
            head_slot: head.head_slot,
            sync_distance,
            is_syncing: !last.reachable || sync_distance > SYNC_TOLERANCE_SLOTS,
            is_optimistic: head.optimistic,
            el_offline: head.el_offline,
        }
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
    let call = client.get_chain_status(pb::GetChainStatusRequest {});
    let failure = match tokio::time::timeout(timeout, call).await {
        Ok(Ok(response)) => match response.into_inner().status {
            Some(status) => {
                if !state.record_head(ChainHead::from(&status)) {
                    tracing::info!(head_slot = status.head_slot, "cl-chain reachable");
                }
                return;
            }
            None => "GetChainStatus answered without a status".to_owned(),
        },
        Ok(Err(status)) => format!("GetChainStatus failed: {status}"),
        Err(_) => format!("GetChainStatus took longer than {timeout:?}"),
    };
    if state.record_unreachable() {
        tracing::warn!(error = %failure, "cl-chain unreachable: node/syncing reports syncing");
    } else {
        tracing::debug!(error = %failure, "cl-chain still unreachable");
    }
}

/// Polls every `interval` until `shutdown`. Each call gets `interval` at most.
pub async fn poll_chain(
    client: ImportServiceClient<tonic::transport::Channel>,
    state: NodeState,
    interval: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let mut client = client;
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        let poll = async {
            ticks.tick().await;
            poll_once(&mut client, &state, interval).await;
        };
        tokio::select! {
            () = &mut shutdown => return,
            () = poll => {}
        }
    }
}
