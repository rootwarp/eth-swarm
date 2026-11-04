//! `chain.v1` `EventsService`: cl-chain's sequenced events, the source of cl-api's
//! `/eth/v1/events` and of the head and finality cl-store follows.
//!
//! [`ChainEvents`] is the publisher. cl-chain is the single writer, and each of its event
//! sources calls one method of it:
//!
//! - fork choice, at every new head: [`ChainEvents::head`] with the head node and the block tree
//!   it holds ([`BlockTree`]). A head node that changed is a HEAD event, after a CHAIN_REORG if
//!   the old head block is not an ancestor of the new one. The same node again is nothing.
//! - block import, after `on_block`: [`ChainEvents::block`], a BLOCK event.
//! - finality, at a new finalized checkpoint: [`ChainEvents::finalized`], a FINALIZED_CHECKPOINT
//!   event.
//!
//! [`EventsServer`] serves `EventsService/Subscribe` from it: each event goes to every stream
//! whose request named its kind, through a `tokio::sync::broadcast`, so a publisher never waits
//! on a subscriber. A stream that falls behind ends, and nothing is replayed (its docs have the
//! request checks and every way a stream ends).
//!
//! # Frames
//!
//! Every event is one `SubscribeResponseBody`. `seq` is cl-chain's, not the stream's: it starts
//! at 1 and goes up by one per event of any kind, so a stream sees a strictly increasing
//! subsequence of it (`proto/ethswarm/chain/v1/events.proto`). `slot`, `root` and `optimistic`
//! are those of the event's block (FINALIZED_CHECKPOINT: the start slot of the checkpoint's
//! epoch and its root; CHAIN_REORG: the new head). `data_json` is the event as the beacon APIs
//! write it (`apis/eventstream/index.yaml` at `01e99a6`): integers as quoted decimals, roots and
//! hashes as `0x` hex.
//!
//! - HEAD: `head`'s `slot`, `block`, `state`, `epoch_transition`,
//!   `previous_duty_dependent_root`, `current_duty_dependent_root` and `execution_optimistic`,
//!   and the head node's `payload_status` (`"empty"`, `"full"`; `"pending"` never heads a Gloas
//!   fork choice; a Fulu head is `"full"`). `head` and `head_v2` share this kind: `head` is the
//!   frame without `payload_status`, `head_v2` names the two dependent roots
//!   `current_epoch_dependent_root` and `next_epoch_dependent_root` (the same roots). Gloas
//!   asks for a second head event when the head block's payload turns from empty to full; the
//!   payload status is part of the node, so that change is a HEAD here.
//! - BLOCK: `slot`, `block`, `execution_optimistic` and, from Gloas, the `builder_index` and
//!   `block_hash` of the block's `signed_execution_payload_bid.message` ([`Bid`]).
//! - FINALIZED_CHECKPOINT: `block`, `state`, `epoch`, `execution_optimistic`.
//! - CHAIN_REORG: `slot` (the new head's), `depth`, `old_head_block`, `new_head_block`,
//!   `old_head_state`, `new_head_state`, `epoch` (the new head's), `execution_optimistic` (the
//!   new head's). `depth` is the old head's slot less the slot of the common ancestor.
//!
//! Every `data_json` is a fixed set of short fields, well under 1 KiB, so none can reach the
//! proto's 64 KiB cap.

use crate::persist::durable::PayloadStatus;
use consensus_types::gloas;
use consensus_types::primitives::{BuilderIndex, Epoch, Hash32, Root, Slot};
use consensus_types::EthSpec;
use ethswarm_proto::chain as pb;
use ipc::frame::OutFrame;
use ipc::hello::stream_hello;
use ipc::stub::StubStream;
use ipc::{ContractError, Link};
use pb::events_service_server::{EventsService, EventsServiceServer};
use pb::EventKind;
use serde::Serialize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// Events the bus keeps for its slowest subscriber. A subscriber further behind than this has
/// lost events.
pub const EVENT_CAPACITY: usize = 1024;

/// Frames one stream holds ahead of its client.
const STREAM_BUFFER: usize = 16;

/// The fork-choice head: the node `get_head` returned (its block and, from Gloas, its payload
/// status) and what the head state says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The head block's slot.
    pub slot: Slot,
    /// The head block's root.
    pub block: Root,
    /// The head block's state root.
    pub state: Root,
    /// The head node's payload status (Gloas `ForkChoiceNode.payload_status`); a Fulu head is
    /// [`PayloadStatus::Full`].
    pub payload_status: PayloadStatus,
    /// `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch - 1) - 1)` of the head
    /// state at the head's epoch, the genesis block root on underflow.
    pub previous_duty_dependent_root: Root,
    /// `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)`, the genesis
    /// block root on underflow.
    pub current_duty_dependent_root: Root,
    /// The head is optimistic: its execution payload is not known to be valid yet.
    pub execution_optimistic: bool,
}

/// A block fork choice's `on_block` imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedBlock {
    pub slot: Slot,
    pub block: Root,
    pub execution_optimistic: bool,
    /// Gloas: the block's bid. `None` for a Fulu block, whose event names no bid.
    pub bid: Option<Bid>,
}

/// What a Gloas block's event names of its `signed_execution_payload_bid.message`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bid {
    /// `BUILDER_INDEX_SELF_BUILD` for a block its proposer built.
    pub builder_index: BuilderIndex,
    /// The committed execution block hash.
    pub block_hash: Hash32,
}

impl<E: EthSpec> From<&gloas::ExecutionPayloadBid<E>> for Bid {
    fn from(bid: &gloas::ExecutionPayloadBid<E>) -> Self {
        Self {
            builder_index: bid.builder_index,
            block_hash: bid.block_hash,
        }
    }
}

/// A new finalized checkpoint, with the state of its block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finalized {
    pub epoch: Epoch,
    pub block: Root,
    pub state: Root,
    pub execution_optimistic: bool,
}

/// The block tree fork choice holds, which [`ChainEvents::head`] walks back to the common
/// ancestor of the old and the new head.
pub trait BlockTree {
    /// The root and slot of the parent of block `root`; `None` if the tree does not hold
    /// `root` or its parent.
    fn parent(&self, root: &Root) -> Option<(Root, Slot)>;
}

/// The publisher of cl-chain's events (see the module docs). Clones publish to the same bus.
#[derive(Clone, Debug)]
pub struct ChainEvents {
    bus: Arc<Bus>,
}

#[derive(Debug)]
struct Bus {
    slots_per_epoch: u64,
    sender: broadcast::Sender<pb::SubscribeResponseBody>,
    /// Held while an event is numbered and sent, so the bus sends in `seq` order.
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// The `seq` of the last event; 0 before the first.
    seq: u64,
    /// The last head published.
    head: Option<Head>,
}

impl ChainEvents {
    /// A bus keeping [`EVENT_CAPACITY`] events, its epochs `slots_per_epoch` slots long.
    #[must_use]
    pub fn new(slots_per_epoch: u64) -> Self {
        Self::with_capacity(slots_per_epoch, EVENT_CAPACITY)
    }

    /// A bus keeping `capacity` events (at least one) for its slowest subscriber.
    #[must_use]
    pub fn with_capacity(slots_per_epoch: u64, capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self {
            bus: Arc::new(Bus {
                slots_per_epoch: slots_per_epoch.max(1),
                sender,
                state: Mutex::default(),
            }),
        }
    }

    /// Fork choice has a new head. A head node other than the last one is a HEAD event, after
    /// a CHAIN_REORG if the old head block is not an ancestor of `head`'s. `tree` must still
    /// hold both heads: call this before pruning it at a new finality. If it cannot tell
    /// where the two heads meet, no CHAIN_REORG is sent.
    pub fn head(&self, head: Head, tree: &dyn BlockTree) {
        let bus = &*self.bus;
        let mut state = bus.lock();
        let epoch_transition = match state.head.replace(head) {
            None => false,
            Some(old) if old.block == head.block && old.payload_status == head.payload_status => {
                return;
            }
            Some(old) => {
                match common_ancestor(tree, (old.block, old.slot), (head.block, head.slot)) {
                    Some((root, _)) if root == old.block => {}
                    Some((_, slot)) => bus.reorg(&mut state, &old, &head, old.slot - slot),
                    None => tracing::warn!(
                        old_slot = old.slot,
                        new_slot = head.slot,
                        "the block tree has no common ancestor of the old and new head: no CHAIN_REORG"
                    ),
                }
                bus.epoch(old.slot) < bus.epoch(head.slot)
            }
        };
        let data = HeadData {
            slot: head.slot.to_string(),
            block: hex0x(head.block),
            state: hex0x(head.state),
            epoch_transition,
            previous_duty_dependent_root: hex0x(head.previous_duty_dependent_root),
            current_duty_dependent_root: hex0x(head.current_duty_dependent_root),
            execution_optimistic: head.execution_optimistic,
            payload_status: payload_status_name(head.payload_status),
        };
        let at = (head.slot, head.block, head.execution_optimistic);
        bus.send(&mut state, EventKind::Head, at, &data);
    }

    /// Block import: `on_block` imported `block`. A BLOCK event.
    pub fn block(&self, block: &ImportedBlock) {
        let data = BlockData {
            slot: block.slot.to_string(),
            block: hex0x(block.block),
            execution_optimistic: block.execution_optimistic,
            builder_index: block.bid.map(|b| b.builder_index.to_string()),
            block_hash: block.bid.map(|b| hex0x(b.block_hash)),
        };
        let at = (block.slot, block.block, block.execution_optimistic);
        let bus = &*self.bus;
        bus.send(&mut bus.lock(), EventKind::Block, at, &data);
    }

    /// Finality: `checkpoint` is the new finalized checkpoint. A FINALIZED_CHECKPOINT event, at
    /// the start slot of its epoch.
    pub fn finalized(&self, checkpoint: &Finalized) {
        let data = FinalizedData {
            block: hex0x(checkpoint.block),
            state: hex0x(checkpoint.state),
            epoch: checkpoint.epoch.to_string(),
            execution_optimistic: checkpoint.execution_optimistic,
        };
        let bus = &*self.bus;
        let slot = checkpoint.epoch.saturating_mul(bus.slots_per_epoch);
        let at = (slot, checkpoint.block, checkpoint.execution_optimistic);
        bus.send(&mut bus.lock(), EventKind::FinalizedCheckpoint, at, &data);
    }
}

/// Where an event is: its slot, root and execution optimism.
type At = (Slot, Root, bool);

impl Bus {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn epoch(&self, slot: Slot) -> Epoch {
        slot / self.slots_per_epoch
    }

    fn reorg(&self, state: &mut State, old: &Head, new: &Head, depth: u64) {
        let data = ReorgData {
            slot: new.slot.to_string(),
            depth: depth.to_string(),
            old_head_block: hex0x(old.block),
            new_head_block: hex0x(new.block),
            old_head_state: hex0x(old.state),
            new_head_state: hex0x(new.state),
            epoch: self.epoch(new.slot).to_string(),
            execution_optimistic: new.execution_optimistic,
        };
        let at = (new.slot, new.block, new.execution_optimistic);
        self.send(state, EventKind::ChainReorg, at, &data);
    }

    /// Numbers the event and sends it to every subscriber. With none, it is gone, its `seq`
    /// spent all the same.
    fn send(&self, state: &mut State, kind: EventKind, at: At, data: &impl Serialize) {
        let (slot, root, optimistic) = at;
        state.seq += 1;
        let body = pb::SubscribeResponseBody {
            seq: state.seq,
            kind: kind as i32,
            slot,
            root: root.to_vec(),
            // Strings and booleans only: serializing cannot fail.
            data_json: serde_json::to_vec(data).unwrap_or_default(),
            optimistic,
        };
        let _ = self.sender.send(body);
    }
}

/// The block where the chains of `a` and `b` (root, slot) meet: the later of the two steps back
/// to its parent until both are one block. `None` if the tree misses a block on the way, or
/// names a parent that is not earlier than its child.
fn common_ancestor(
    tree: &dyn BlockTree,
    mut a: (Root, Slot),
    mut b: (Root, Slot),
) -> Option<(Root, Slot)> {
    while a.0 != b.0 {
        let later = if a.1 >= b.1 { &mut a } else { &mut b };
        *later = tree.parent(&later.0).filter(|parent| parent.1 < later.1)?;
    }
    Some(a)
}

fn hex0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// The beacon API's name of a payload status (`head_v2`).
fn payload_status_name(status: PayloadStatus) -> &'static str {
    match status {
        PayloadStatus::Empty => "empty",
        PayloadStatus::Full => "full",
        PayloadStatus::Pending => "pending",
    }
}

#[derive(Serialize)]
struct HeadData {
    slot: String,
    block: String,
    state: String,
    epoch_transition: bool,
    previous_duty_dependent_root: String,
    current_duty_dependent_root: String,
    execution_optimistic: bool,
    payload_status: &'static str,
}

#[derive(Serialize)]
struct BlockData {
    slot: String,
    block: String,
    execution_optimistic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    builder_index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,
}

#[derive(Serialize)]
struct FinalizedData {
    block: String,
    state: String,
    epoch: String,
    execution_optimistic: bool,
}

#[derive(Serialize)]
struct ReorgData {
    slot: String,
    depth: String,
    old_head_block: String,
    new_head_block: String,
    old_head_state: String,
    new_head_state: String,
    epoch: String,
    execution_optimistic: bool,
}

/// The v1 kinds one stream subscribes, as bits `1 << kind`.
#[derive(Clone, Copy, Debug)]
struct Kinds(u8);

impl Kinds {
    /// The kinds `SubscribeRequest.kinds` names. `EVENT_KIND_UNSPECIFIED` is a contract
    /// violation, a kind that v1 does not serve (5–8) or a request without a v1 kind
    /// `INVALID_ARGUMENT`; an unknown non-zero kind is ignored (`proto/README.md` rule 3).
    fn of(link: &Link, kinds: &[i32]) -> Result<Self, Status> {
        let mut bits = 0;
        for &kind in kinds {
            match EventKind::try_from(kind) {
                Ok(EventKind::Unspecified) => {
                    return Err(link.fail(&ContractError::violation(
                        "SubscribeRequest.kinds holds EVENT_KIND_UNSPECIFIED",
                    )));
                }
                Ok(
                    v1 @ (EventKind::Head
                    | EventKind::Block
                    | EventKind::FinalizedCheckpoint
                    | EventKind::ChainReorg),
                ) => bits |= Self::bit(v1),
                Ok(later) => {
                    return Err(Status::invalid_argument(format!(
                        "{} is not a chain.v1 event yet",
                        later.as_str_name()
                    )));
                }
                Err(_) => {}
            }
        }
        if bits == 0 {
            return Err(Status::invalid_argument(
                "SubscribeRequest.kinds names no chain.v1 event kind",
            ));
        }
        Ok(Self(bits))
    }

    fn bit(kind: EventKind) -> u8 {
        1 << (kind as u8)
    }

    /// Whether the stream asked for `kind`, one the bus sends (1–4).
    fn has(self, kind: i32) -> bool {
        (1..=4).contains(&kind) && self.0 & (1 << kind) != 0
    }
}

/// `EventsService` over a [`ChainEvents`] bus, every stream held to `link`.
///
/// `Subscribe` checks the request's hello (none is a contract violation), then its kinds
/// (`EVENT_KIND_UNSPECIFIED` is a contract violation; a kind v1 does not serve, 5–8, or no v1
/// kind at all is `INVALID_ARGUMENT`; an unknown non-zero kind is ignored). The stream then
/// sends our hello and every later event of its kinds, in `seq` order.
///
/// Nothing is replayed: cl-chain keeps no past events, so `resume_from_seq` is ignored and a
/// stream starts at the bus's next event. A client that resumes compares the first `seq` it
/// gets with `resume_from_seq + 1` and, on a gap, resyncs through `QueryService` or `store.v1`
/// (`events.proto`). A stream ends:
///
/// - when its client goes, without waiting for an event;
/// - with `RESOURCE_EXHAUSTED` once it is more than the bus's capacity behind: the bus never
///   waits on a slow stream, and the stream sends nothing past the gap;
/// - with `UNAVAILABLE` when the stop ([`Self::stopping`]) turns true or its sender goes, or
///   when the bus closes (every [`ChainEvents`] dropped).
#[derive(Clone, Debug)]
pub struct EventsServer {
    link: Link,
    events: ChainEvents,
    stop: Option<watch::Receiver<bool>>,
}

impl EventsServer {
    #[must_use]
    pub fn new(link: Link, events: ChainEvents) -> Self {
        Self {
            link,
            events,
            stop: None,
        }
    }

    /// The same server, every stream ended with `UNAVAILABLE` when `stop` turns true or its
    /// sender goes. Open streams would otherwise hold a drain to its deadline.
    #[must_use]
    pub fn stopping(mut self, stop: watch::Receiver<bool>) -> Self {
        self.stop = Some(stop);
        self
    }

    /// The bus the streams are served from.
    #[must_use]
    pub fn events(&self) -> &ChainEvents {
        &self.events
    }

    /// The tonic service.
    #[must_use]
    pub fn into_service(self) -> EventsServiceServer<Self> {
        EventsServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl EventsService for EventsServer {
    type SubscribeStream = StubStream<pb::SubscribeResponse>;

    async fn subscribe(
        &self,
        request: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let request = request.into_inner();
        self.link
            .accept_hello_field(request.hello.as_ref())
            .map_err(|e| e.to_status())?;
        let kinds = Kinds::of(&self.link, &request.kinds)?;
        let (_, ours) = stream_hello(&self.link.local()).map_err(|e| e.to_status())?;
        let mut events = self.events.bus.sender.subscribe();
        let mut stop = self.stop.clone();
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        ipc::spawn_in_span(async move {
            if tx
                .send(Ok(pb::SubscribeResponse::hello(ours)))
                .await
                .is_err()
            {
                return;
            }
            let end = loop {
                let body = tokio::select! {
                    received = events.recv() => match received {
                        Ok(body) => body,
                        Err(RecvError::Lagged(missed)) => break lagged(missed),
                        Err(RecvError::Closed) => {
                            break Status::unavailable("cl-chain's event bus is closed");
                        }
                    },
                    () = stopped(stop.as_mut()) => break Status::unavailable("cl-chain is stopping"),
                    () = tx.closed() => return,
                };
                if kinds.has(body.kind)
                    && tx
                        .send(Ok(pb::SubscribeResponse::body(body)))
                        .await
                        .is_err()
                {
                    return;
                }
            };
            let _ = tx.send(Err(end)).await;
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// The end of a stream `missed` events behind the bus.
fn lagged(missed: u64) -> Status {
    tracing::warn!(missed, "an EventsService stream fell behind the bus: ended");
    Status::resource_exhausted(format!(
        "the stream fell {missed} events behind; nothing is replayed: subscribe again and resync"
    ))
}

/// Resolves once `stop` is true or its sender is gone; never without a stop.
async fn stopped(stop: Option<&mut watch::Receiver<bool>>) {
    match stop {
        Some(stop) => {
            let _ = stop.wait_for(|stop| *stop).await;
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::primitives::{Address, B256};
    use consensus_types::Minimal;
    use ethswarm_proto::common::{ErrorCode, Hello};
    use ipc::envelope::DigestTable;
    use ipc::hello::Generation;
    use ipc::ContractError;
    use network_config::{ForkName, ForkSchedule, ScheduledFork};
    use pb::subscribe_response::Frame;
    use pb::EventKind;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio_stream::StreamExt;

    /// `SLOTS_PER_EPOCH` of the minimal preset.
    const SLOTS: u64 = 8;

    const ALL: [EventKind; 4] = [
        EventKind::Head,
        EventKind::Block,
        EventKind::FinalizedCheckpoint,
        EventKind::ChainReorg,
    ];

    type Frames = StubStream<pb::SubscribeResponse>;

    fn link() -> Link {
        let at = |epoch| ScheduledFork {
            version: [7, 0, 0, 0],
            epoch,
        };
        let hello = Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 1,
            ..Default::default()
        };
        let digests = DigestTable::new(vec![(0, ForkName::Gloas, [1, 2, 3, 4])]).unwrap();
        Link::new::<Minimal>(hello, 1, ForkSchedule::new(at(0), at(0)).unwrap(), digests)
    }

    fn root(n: u8) -> Root {
        B256::repeat_byte(n)
    }

    /// The state root of block `n` in these tests.
    fn state(n: u8) -> Root {
        root(n | 0x80)
    }

    /// `root(n)` as the beacon API writes it.
    fn hex_of(root: Root) -> String {
        format!("0x{}", hex::encode(root))
    }

    /// The head on block `n` at `slot`.
    fn head(n: u8, slot: Slot, payload_status: PayloadStatus) -> Head {
        Head {
            slot,
            block: root(n),
            state: state(n),
            payload_status,
            previous_duty_dependent_root: root(0x71),
            current_duty_dependent_root: root(0x72),
            execution_optimistic: false,
        }
    }

    /// A block tree of `(block, slot, parent)`.
    struct Tree(HashMap<Root, (Slot, Root)>);

    fn tree(blocks: &[(u8, Slot, u8)]) -> Tree {
        Tree(
            blocks
                .iter()
                .map(|&(n, slot, parent)| (root(n), (slot, root(parent))))
                .collect(),
        )
    }

    impl BlockTree for Tree {
        fn parent(&self, root: &Root) -> Option<(Root, Slot)> {
            let (_, parent) = self.0.get(root)?;
            let (slot, _) = self.0.get(parent)?;
            Some((*parent, *slot))
        }
    }

    fn finalized(epoch: Epoch, n: u8) -> Finalized {
        Finalized {
            epoch,
            block: root(n),
            state: state(n),
            execution_optimistic: false,
        }
    }

    fn fulu_block(n: u8, slot: Slot) -> ImportedBlock {
        ImportedBlock {
            slot,
            block: root(n),
            execution_optimistic: false,
            bid: None,
        }
    }

    fn raw(kinds: &[EventKind]) -> Vec<i32> {
        kinds.iter().map(|k| *k as i32).collect()
    }

    fn request(kinds: Vec<i32>) -> pb::SubscribeRequest {
        pb::SubscribeRequest {
            kinds,
            resume_from_seq: 0,
            hello: Some(link().local()),
        }
    }

    async fn call(server: &EventsServer, request: pb::SubscribeRequest) -> Result<Frames, Status> {
        server
            .subscribe(Request::new(request))
            .await
            .map(Response::into_inner)
    }

    /// The next frame, within a few seconds.
    async fn next(frames: &mut Frames) -> Option<Result<pb::SubscribeResponse, Status>> {
        tokio::time::timeout(Duration::from_secs(5), frames.next())
            .await
            .expect("a frame in time")
    }

    /// A subscription to `kinds`, its hello (with a server generation) read.
    async fn open(server: &EventsServer, kinds: &[EventKind]) -> Frames {
        let mut frames = call(server, request(raw(kinds))).await.expect("subscribed");
        match next(&mut frames)
            .await
            .expect("a first frame")
            .unwrap()
            .frame
        {
            Some(Frame::Hello(hello)) => assert!(Generation::from_hello(&hello).is_ok()),
            other => panic!("first frame {other:?}"),
        }
        frames
    }

    async fn body(frames: &mut Frames) -> pb::SubscribeResponseBody {
        match next(frames).await.expect("a frame").unwrap().frame {
            Some(Frame::Body(body)) => body,
            other => panic!("not a body: {other:?}"),
        }
    }

    async fn bodies(frames: &mut Frames, n: usize) -> Vec<pb::SubscribeResponseBody> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(body(frames).await);
        }
        out
    }

    fn data(body: &pb::SubscribeResponseBody) -> Value {
        serde_json::from_slice(&body.data_json).expect("data_json is JSON")
    }

    fn kinds_of(bodies: &[pb::SubscribeResponseBody]) -> Vec<i32> {
        bodies.iter().map(|b| b.kind).collect()
    }

    fn bus() -> (ChainEvents, EventsServer) {
        let events = ChainEvents::new(SLOTS);
        let server = EventsServer::new(link(), events.clone());
        (events, server)
    }

    /// A head change is one HEAD frame: the head block's slot and root, and in `data_json` the
    /// beacon-API `head` fields with the fork-choice node's `payload_status`. Gloas: the same
    /// block turning full is a second HEAD (`head_v2`), and no re-org; the same node again is no
    /// event.
    #[tokio::test]
    async fn head_frame_carries_payload_status() {
        let (events, server) = bus();
        let mut frames = open(&server, &ALL).await;
        let tree = tree(&[(1, 9, 0), (2, 16, 1)]);

        events.head(head(1, 9, PayloadStatus::Empty), &tree);
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.slot, b.root.as_slice(), b.optimistic),
            (EventKind::Head as i32, 9, root(1).as_slice(), false)
        );
        assert_eq!(
            data(&b),
            json!({
                "slot": "9",
                "block": hex_of(root(1)),
                "state": hex_of(state(1)),
                "epoch_transition": false,
                "previous_duty_dependent_root": hex_of(root(0x71)),
                "current_duty_dependent_root": hex_of(root(0x72)),
                "execution_optimistic": false,
                "payload_status": "empty",
            })
        );

        events.head(head(1, 9, PayloadStatus::Full), &tree);
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.root.as_slice()),
            (EventKind::Head as i32, root(1).as_slice())
        );
        assert_eq!(data(&b)["payload_status"], "full");

        // The same node again: nothing. The next head, in the next epoch, optimistic.
        events.head(head(1, 9, PayloadStatus::Full), &tree);
        let next_head = Head {
            execution_optimistic: true,
            ..head(2, 16, PayloadStatus::Empty)
        };
        events.head(next_head, &tree);
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.slot, b.optimistic),
            (EventKind::Head as i32, 16, true)
        );
        let d = data(&b);
        assert_eq!(d["epoch_transition"], json!(true));
        assert_eq!(d["execution_optimistic"], json!(true));
        assert_eq!(d["payload_status"], "empty");
    }

    /// An imported Gloas block is a BLOCK frame whose `data_json` names its bid's
    /// `builder_index` and `block_hash` (quoted decimal, 0x hex); a Fulu block has neither.
    #[tokio::test]
    async fn block_frame_gloas_fields() {
        let (events, server) = bus();
        let mut frames = open(&server, &[EventKind::Block]).await;
        let bid = gloas::ExecutionPayloadBid::<Minimal> {
            parent_block_hash: B256::ZERO,
            parent_block_root: B256::ZERO,
            block_hash: B256::repeat_byte(0x12),
            prev_randao: B256::ZERO,
            fee_recipient: Address::ZERO,
            gas_limit: 0,
            builder_index: 42,
            slot: 10,
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: Default::default(),
            execution_requests_root: B256::ZERO,
        };
        events.block(&ImportedBlock {
            slot: 10,
            block: root(3),
            execution_optimistic: true,
            bid: Some(Bid::from(&bid)),
        });
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.slot, b.root.as_slice(), b.optimistic),
            (EventKind::Block as i32, 10, root(3).as_slice(), true)
        );
        assert_eq!(
            data(&b),
            json!({
                "slot": "10",
                "block": hex_of(root(3)),
                "execution_optimistic": true,
                "builder_index": "42",
                "block_hash": format!("0x{}", "12".repeat(32)),
            })
        );

        // A self-built block: BUILDER_INDEX_SELF_BUILD, quoted in full.
        let self_built = gloas::ExecutionPayloadBid {
            builder_index: consensus_types::signing::BUILDER_INDEX_SELF_BUILD,
            ..bid
        };
        events.block(&ImportedBlock {
            slot: 11,
            block: root(4),
            execution_optimistic: false,
            bid: Some(Bid::from(&self_built)),
        });
        assert_eq!(
            data(&body(&mut frames).await)["builder_index"],
            "18446744073709551615"
        );

        events.block(&fulu_block(5, 12));
        assert_eq!(
            data(&body(&mut frames).await),
            json!({"slot": "12", "block": hex_of(root(5)), "execution_optimistic": false})
        );
    }

    /// A new finalized checkpoint is a FINALIZED_CHECKPOINT frame at its epoch's start slot.
    #[tokio::test]
    async fn finalized_checkpoint_frame() {
        let (events, server) = bus();
        let mut frames = open(&server, &[EventKind::FinalizedCheckpoint]).await;
        events.finalized(&Finalized {
            execution_optimistic: true,
            ..finalized(3, 5)
        });
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.slot, b.root.as_slice(), b.optimistic),
            (
                EventKind::FinalizedCheckpoint as i32,
                3 * SLOTS,
                root(5).as_slice(),
                true
            )
        );
        assert_eq!(
            data(&b),
            json!({
                "block": hex_of(root(5)),
                "state": hex_of(state(5)),
                "epoch": "3",
                "execution_optimistic": true,
            })
        );
    }

    /// The new head is on another branch: CHAIN_REORG, then HEAD. `depth` is the old head's
    /// slot less the common ancestor's, both ways.
    #[tokio::test]
    async fn reorg_when_old_head_not_ancestor() {
        let (events, server) = bus();
        let mut frames = open(&server, &ALL).await;
        // 0 ← 1 ← 2 ← 3, and 1 ← 4 ← 5.
        let tree = tree(&[(1, 1, 0), (2, 2, 1), (3, 3, 2), (4, 4, 1), (5, 9, 4)]);

        events.head(head(3, 3, PayloadStatus::Full), &tree);
        assert_eq!(body(&mut frames).await.kind, EventKind::Head as i32);

        let new_head = Head {
            execution_optimistic: true,
            ..head(5, 9, PayloadStatus::Empty)
        };
        events.head(new_head, &tree);
        let [reorg, head_frame] = <[_; 2]>::try_from(bodies(&mut frames, 2).await).unwrap();
        assert_eq!(
            (
                reorg.kind,
                reorg.slot,
                reorg.root.as_slice(),
                reorg.optimistic
            ),
            (EventKind::ChainReorg as i32, 9, root(5).as_slice(), true)
        );
        assert_eq!(
            data(&reorg),
            json!({
                "slot": "9",
                "depth": "2",
                "old_head_block": hex_of(root(3)),
                "new_head_block": hex_of(root(5)),
                "old_head_state": hex_of(state(3)),
                "new_head_state": hex_of(state(5)),
                "epoch": "1",
                "execution_optimistic": true,
            })
        );
        assert_eq!(
            (head_frame.kind, head_frame.root.as_slice()),
            (EventKind::Head as i32, root(5).as_slice())
        );

        // Back to the shorter branch: the old head (slot 9) is 8 slots past block 1.
        events.head(head(3, 3, PayloadStatus::Full), &tree);
        let [reorg, head_frame] = <[_; 2]>::try_from(bodies(&mut frames, 2).await).unwrap();
        assert_eq!(reorg.kind, EventKind::ChainReorg as i32);
        let d = data(&reorg);
        assert_eq!(
            (&d["slot"], &d["depth"], &d["epoch"]),
            (&json!("3"), &json!("8"), &json!("0"))
        );
        assert_eq!(
            (&d["old_head_block"], &d["new_head_block"]),
            (&json!(hex_of(root(5))), &json!(hex_of(root(3))))
        );
        assert_eq!(d["execution_optimistic"], json!(false));
        assert_eq!(head_frame.kind, EventKind::Head as i32);
    }

    /// A head that extends the old one, even past a block, is HEAD only.
    #[tokio::test]
    async fn no_reorg_on_extension() {
        let (events, server) = bus();
        let mut frames = open(&server, &ALL).await;
        let tree = tree(&[(1, 1, 0), (2, 2, 1), (3, 3, 2)]);
        events.head(head(1, 1, PayloadStatus::Full), &tree);
        events.head(head(3, 3, PayloadStatus::Full), &tree);
        events.finalized(&finalized(0, 1));
        let got = bodies(&mut frames, 3).await;
        assert_eq!(
            kinds_of(&got),
            raw(&[
                EventKind::Head,
                EventKind::Head,
                EventKind::FinalizedCheckpoint
            ])
        );
        assert_eq!(got[1].root.as_slice(), root(3).as_slice());
    }

    /// A subscriber gets only the kinds it asked for (a kind named twice once, an unknown
    /// non-zero kind ignored); a request that names no v1 kind is refused.
    #[tokio::test]
    async fn kinds_filter() {
        let (events, server) = bus();
        let mut blocks = call(
            &server,
            request(vec![EventKind::Block as i32, EventKind::Block as i32, 99]),
        )
        .await
        .expect("subscribed");
        assert!(matches!(
            next(&mut blocks).await.unwrap().unwrap().frame,
            Some(Frame::Hello(_))
        ));
        let mut heads = open(&server, &[EventKind::Head, EventKind::FinalizedCheckpoint]).await;

        let tree = tree(&[]);
        events.head(head(1, 1, PayloadStatus::Full), &tree);
        events.block(&fulu_block(2, 2));
        events.finalized(&finalized(1, 1));
        events.block(&fulu_block(3, 3));
        events.finalized(&finalized(2, 3));

        let got = bodies(&mut blocks, 2).await;
        assert_eq!(kinds_of(&got), raw(&[EventKind::Block, EventKind::Block]));
        assert_eq!(
            (got[0].slot, got[1].slot),
            (2, 3),
            "each block once, in order"
        );
        let got = bodies(&mut heads, 3).await;
        assert_eq!(
            kinds_of(&got),
            raw(&[
                EventKind::Head,
                EventKind::FinalizedCheckpoint,
                EventKind::FinalizedCheckpoint
            ])
        );

        for kinds in [vec![], vec![99]] {
            let refused = call(&server, request(kinds.clone())).await.err();
            assert_eq!(
                refused.map(|s| s.code()),
                Some(tonic::Code::InvalidArgument),
                "{kinds:?}"
            );
        }
    }

    /// `seq` is cl-chain's, not the stream's: from 1, gap-free across every kind, so a
    /// filtered stream sees a strictly increasing subsequence and a later stream goes on from
    /// where the bus is.
    #[tokio::test]
    async fn seq_monotonic() {
        let (events, server) = bus();
        let mut all = open(&server, &ALL).await;
        let mut finality = open(&server, &[EventKind::FinalizedCheckpoint]).await;
        let tree = tree(&[(0, 0, 0xff), (1, 1, 0), (2, 2, 0)]);

        events.head(head(1, 1, PayloadStatus::Full), &tree);
        events.block(&fulu_block(2, 2));
        events.finalized(&finalized(0, 0));
        // A re-org: CHAIN_REORG and HEAD, two seqs.
        events.head(head(2, 2, PayloadStatus::Full), &tree);
        events.finalized(&finalized(1, 2));

        let seqs: Vec<u64> = bodies(&mut all, 6).await.iter().map(|b| b.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5, 6]);
        let seqs: Vec<u64> = bodies(&mut finality, 2)
            .await
            .iter()
            .map(|b| b.seq)
            .collect();
        assert_eq!(seqs, [3, 6]);

        let mut later = open(&server, &[EventKind::Block]).await;
        events.block(&fulu_block(3, 3));
        assert_eq!(body(&mut later).await.seq, 7);
        assert_eq!(body(&mut all).await.seq, 7);
    }

    /// Kinds outside v1 (5–8) are refused with INVALID_ARGUMENT, alone or beside a v1 kind;
    /// `EVENT_KIND_UNSPECIFIED` too, as the contract violation it is.
    #[tokio::test]
    async fn out_of_v1_kind_rejected() {
        let link = link();
        let server = EventsServer::new(link.clone(), ChainEvents::new(SLOTS));
        for kind in [
            EventKind::ExecutionPayload,
            EventKind::PayloadAttestation,
            EventKind::DataColumnSidecar,
            EventKind::ForkSchedule,
        ] {
            for kinds in [vec![kind as i32], vec![EventKind::Head as i32, kind as i32]] {
                let refused = call(&server, request(kinds)).await.err();
                assert_eq!(
                    refused.map(|s| s.code()),
                    Some(tonic::Code::InvalidArgument),
                    "{kind:?}"
                );
            }
        }
        assert_eq!(link.metrics().counts().contract_violations, 0);

        let refused = call(&server, request(vec![EventKind::Head as i32, 0]))
            .await
            .err()
            .expect("UNSPECIFIED refused");
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            ContractError::from_status(&refused).code(),
            ErrorCode::ContractViolation
        );
        assert_eq!(link.metrics().counts().contract_violations, 1);
    }

    /// The request is the client's only frame, so it carries its hello: one without is a
    /// contract violation, before the kinds are looked at.
    #[tokio::test]
    async fn missing_hello_is_a_contract_violation() {
        let link = link();
        let server = EventsServer::new(link.clone(), ChainEvents::new(SLOTS));
        let request = pb::SubscribeRequest {
            hello: None,
            ..request(raw(&ALL))
        };
        let refused = call(&server, request).await.err().expect("refused");
        assert_eq!(
            ContractError::from_status(&refused).code(),
            ErrorCode::ContractViolation
        );
        assert_eq!(link.metrics().counts().contract_violations, 1);
    }

    /// A stream that fell further behind than the bus keeps ends with RESOURCE_EXHAUSTED: no
    /// replay, and no later event after the gap.
    #[tokio::test]
    async fn a_lagged_stream_ends() {
        let events = ChainEvents::with_capacity(SLOTS, 2);
        let server = EventsServer::new(link(), events.clone());
        let mut frames = open(&server, &[EventKind::Block]).await;
        for n in 0..5 {
            events.block(&fulu_block(n, u64::from(n)));
        }
        let end = next(&mut frames).await.expect("an end").unwrap_err();
        assert_eq!(end.code(), tonic::Code::ResourceExhausted, "{end:?}");
        assert!(next(&mut frames).await.is_none());
    }

    /// A stream whose client is gone lets go of the bus without waiting for an event.
    #[tokio::test]
    async fn a_gone_client_frees_its_stream() {
        let (events, server) = bus();
        let frames = open(&server, &ALL).await;
        assert_eq!(events.bus.sender.receiver_count(), 1);
        drop(frames);
        tokio::time::timeout(Duration::from_secs(5), async {
            while events.bus.sender.receiver_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the stream let go of the bus");
    }

    /// A stopping server ends every stream with UNAVAILABLE, when the stop turns true or its
    /// sender goes.
    #[tokio::test]
    async fn stopping_ends_the_streams() {
        for drop_sender in [false, true] {
            let (stop, stopped) = tokio::sync::watch::channel(false);
            let server = EventsServer::new(link(), ChainEvents::new(SLOTS)).stopping(stopped);
            let mut frames = open(&server, &ALL).await;
            if drop_sender {
                drop(stop);
            } else {
                stop.send_replace(true);
            }
            let end = next(&mut frames).await.expect("an end").unwrap_err();
            assert_eq!(end.code(), tonic::Code::Unavailable, "{end:?}");
        }
    }

    /// `resume_from_seq` replays nothing: the stream starts at the bus's next event, and the
    /// client tells the gap from its `seq`.
    #[tokio::test]
    async fn resume_from_seq_is_not_replayed() {
        let (events, server) = bus();
        events.block(&fulu_block(1, 1));
        events.block(&fulu_block(2, 2));
        let resume = pb::SubscribeRequest {
            resume_from_seq: 1,
            ..request(raw(&[EventKind::Block]))
        };
        let mut frames = call(&server, resume).await.expect("subscribed");
        assert!(matches!(
            next(&mut frames).await.unwrap().unwrap().frame,
            Some(Frame::Hello(_))
        ));
        events.block(&fulu_block(3, 3));
        assert_eq!(body(&mut frames).await.seq, 3);
    }
}
