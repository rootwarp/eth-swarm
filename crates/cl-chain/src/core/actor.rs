//! The chain core: the single writer of the chain state.
//!
//! [`ChainCore`] holds the head, the pre-states ([`Snapshots`]), the states of its walks over
//! empty slots ([`Advanced`]), the blocks whose payload is verified and the EL's verdicts
//! ([`ExecutionStatuses`]). [`ChainCore::spawn`] moves
//! it onto one dedicated OS thread, the only mutator of that state. The thread serves the
//! queues of [`queue`] until each sender is gone, and then returns the core. Each queue is
//! bounded: an item for a full queue is refused at once ([`SubmitError::Full`]), and the caller
//! IGNOREs it. When more than one queue holds an item, the thread serves block import first,
//! then envelope, then gossip commit.
//!
//! A block import first takes its deadline: the time of [`ChainCore::with_verify_timeout`]
//! ([`DEFAULT_VERIFY_TIMEOUT`] if not set) from the start of the import. Then the core checks
//! the block before any state processing, because the slot loop of the transition costs one
//! `process_slot` for each slot and the queue senders have no clock and no pre-states. A check
//! marked *kept* keeps its refusal of the block root (see [Seen roots](#seen-roots)):
//!
//! - the EL contradicted itself: IGNORE (see [Envelope import](#envelope-import));
//! - the table records the bid's `block_hash` or `parent_block_hash` `Invalid`: IGNORE;
//! - no [`PayloadImportGate`] is set: IGNORE. [`ChainCore::from_anchor`] sets none, so a core
//!   that misses [`ChainCore::with_payload_gate`] commits nothing
//!   ([`PermitAll`](crate::import::block::PermitAll) is an explicit opt-in);
//! - the block slot is more than [`MAX_FUTURE_SLOTS`] ahead of the slot of the wall clock
//!   ([`ChainCore::with_clock`], the system clock if not set), or the wall clock is before
//!   genesis: IGNORE;
//! - the core committed the block, or it is the anchor: IGNORE;
//! - the core refused the block before and kept the refusal: the same answer again;
//! - the parent has no pre-state: IGNORE;
//! - the block builds on the FULL payload of its parent (`get_parent_payload_status`: the bid's
//!   `parent_block_hash` is the `block_hash` of the bid of the parent pre-state) and that payload
//!   is not verified: IGNORE;
//! - the block slot is more than [`PRE_STATE_EPOCHS`] epochs of slots after the slot of the
//!   parent pre-state: the far-parent path below, in place of the checks that follow here;
//! - `proposer_index` is past the registry of the pre-state: INVALID, kept;
//! - the caller of the import dropped the receiver of the answer: IGNORE. The core checks this
//!   here, again at the end of the VerifyBls call of the proposer set, and at the end of
//!   [`import_block`]. A drop before a check stops the import at that check: no later VerifyBls
//!   call, no commit, and no kept refusal, also of an INVALID verdict;
//! - the proposer signature ([`check_proposer_signature`]), with the key and the domain of the
//!   pre-state: INVALID on an INVALID verdict (kept for that signature only), IGNORE on no
//!   verdict.
//!
//! The far-parent path first walks the empty slots between the parent pre-state and the block
//! on a copy, to the slot before the block ([`advance`](super::advance)). The wall-clock bound
//! does not stop a block at the slot of the wall clock on an old pre-state (the anchor stays
//! for good), so the walk has its own bounds, and a block that its proposer did not sign must
//! not cost a walk. In order:
//!
//! - a start more than [`MAX_ADVANCE_EPOCHS`](super::advance::MAX_ADVANCE_EPOCHS) epochs of
//!   slots before the block: IGNORE, with no VerifyBls call;
//! - `proposer_index` is past the registry of the parent pre-state: IGNORE, with no VerifyBls
//!   call. The walk can add an index, so this is no proof;
//! - the parent pre-state shows `proposer_index` slashed, or exited or withdrawable at the
//!   epoch of the block: IGNORE, with no VerifyBls call. The walk cannot change that, but it is
//!   no proof about the block. A validator that is not active yet goes on: the walk can
//!   activate it;
//! - the network schedule has no fork at the epoch of the block, or `get_domain` on the parent
//!   pre-state does not give the proposer domain of that fork for that epoch: IGNORE, with no
//!   VerifyBls call;
//! - the caller stopped waiting, before and at the end of the VerifyBls call of the proposer
//!   set: IGNORE, with no kept refusal;
//! - the proposer signature ([`check_proposer_signature_in`]), with the key of the parent
//!   pre-state and the proposer domain of the fork that the network schedule gives for the
//!   epoch of the block ([`schedule_proposer_domain`]): INVALID on an INVALID verdict (kept for
//!   that signature only), IGNORE on no verdict;
//! - the wall clock again, after that VerifyBls call: the block slot is more than
//!   [`MAX_FUTURE_SLOTS`] ahead of its slot, or it is before genesis: IGNORE;
//! - the walk does not fit in the admission budget of that slot of the wall clock
//!   ([`AdvanceBudget`]): at most
//!   [`MAX_ADVANCE_EPOCHS_PER_SLOT`](super::advance::MAX_ADVANCE_EPOCHS_PER_SLOT) epochs of walk
//!   in each slot for all proposers, and one walk in each slot for the proposer of the block.
//!   Charged to both in full before the walk: IGNORE, with no walk and no charge;
//! - the walk: the deadline, a caller that stopped waiting, no deposit verdict, or an error in
//!   the walk is IGNORE;
//! - the caller stopped waiting: IGNORE;
//! - `proposer_index` is not the proposer of the block slot in the lookahead of the advanced
//!   state: INVALID [`StfError::WrongProposer`], kept; a lookahead without that entry is
//!   IGNORE;
//! - `get_domain` on the advanced state does not give the proposer domain of the signature
//!   check for the epoch of the block: IGNORE, with no second VerifyBls call and no kept
//!   refusal;
//! - the key of `proposer_index` on the advanced state is not the one of the signature check:
//!   the proposer set goes to cl-verify again with it, with the same answers as above. Else the
//!   verdict holds, and there is no second VerifyBls call for it.
//!
//! Then it runs [`import_block`] on the pre-state: the pre-state of the parent, or the advanced
//! state. The core sends the signature sets to cl-verify through a [`BlsVerifier`], on the
//! Tokio runtime of the caller, with the deadline of the import: the proposer set in a first
//! VerifyBls call, the block sets in a later one during the transition. The deposit sets of
//! a walk go in calls between them. Each VerifyBls call of one import gets the same deadline,
//! and no verdict by then is IGNORE. The core commits only on a VALID verdict, a post-state
//! root equal to `block.state_root` and a gate that permits the payload: it makes the parent
//! pre-state the most recently used, keeps the post-state as a pre-state, drops the kept walk
//! states and the verified payload of each block whose pre-state left the LRU, and the block
//! becomes the head. There is no fork choice yet, so the head is the last block the core
//! committed. There is no prune of pre-states at finality yet; when one comes, it must also
//! drop the kept walk states and the verified payloads of the parents that it prunes. On any
//! other outcome the head and the pre-states do not change, their order of use included. An
//! INVALID outcome of the transition is kept.
//!
//! # Seen roots
//!
//! The core keeps the root of each block it committed, and of the anchor, apart from the
//! pre-states: a block whose pre-state left the LRU is still IGNORE, and the head does not go
//! back to it. These roots are not bounded until a prune at finality exists: 32 bytes for each
//! committed block, and the overhead of the set.
//!
//! It also keeps the refusals marked *kept*, at most [`MAX_REFUSED_ROOTS`], the first refused
//! going first. Such a refusal does not change when the block comes again: it depends only on
//! the block and on the pre-state of its parent. A refusal for the proposer signature holds
//! only for that signature, as the block root does not commit to it. The core does not keep no
//! verdict (the block can come again and get a verdict in time), a parent without a pre-state
//! (it can come), a refused payload, a refusal from the EL's verdicts, the wall-clock bound (the
//! same block is in that bound once its slot comes, and that check costs no slot loop and no
//! VerifyBls call), a caller that stopped waiting, a far-parent proposer past the registry of
//! the parent pre-state or one that it shows slashed, exited or withdrawable, a fork of the
//! parent pre-state or of the advanced state that is not the schedule fork, the admission
//! budget, or a refusal of the walk: a later walk can start from a nearer state, or have more
//! time or budget.
//!
//! # Envelope import
//!
//! An envelope verifies the payload of a committed block (`on_execution_payload_envelope`, with
//! no fork choice store). In order:
//!
//! - the EL contradicted itself: IGNORE;
//! - the payload of `beacon_block_root` is verified, or that block is not committed with a
//!   pre-state: IGNORE;
//! - no data availability check ([`ChainCore::with_data_availability`]) is set, or the data is
//!   not available: IGNORE;
//! - no engine ([`ChainCore::with_engine`]) is set: IGNORE;
//! - `verify_execution_payload_envelope` on the post-state of the block. The signature goes to
//!   cl-verify with the deadline of a block import; a failed check is REJECT, no verdict IGNORE.
//!   Last, the newPayload call runs on the runtime of the core, which waits up to
//!   [`ChainCore::with_engine_timeout`] ([`DEFAULT_ENGINE_TIMEOUT`]). The core records the
//!   verdict in its [`ExecutionStatuses`], the only writer of it. If the EL has now contradicted
//!   itself, the envelope is IGNORE. Else only the table's permit
//!   ([`ExecutionStatuses::permits_payload_import`]) imports it: INVALID is REJECT, and another
//!   refusal or no verdict is IGNORE.
//!
//! An imported envelope makes its block's payload verified (VALID, or SYNCING or ACCEPTED: the
//! table keeps which). A refused one changes nothing but the record of a verdict the EL gave.
//!
//! An EL contradiction (a VALID payload called INVALID, or the other way round) stays: the spec
//! asks for manual intervention. From the answer that sets it, that envelope included, each
//! envelope and block import is IGNORE before any state processing, VerifyBls or newPayload call.
//!
//! Gossip commit is a queue kind only: the core answers each item IGNORE and changes nothing.

use super::advance::{
    advance, block_proposer, walk_slots, AdvanceBudget, Advanced, MAX_ADVANCED_STATES,
};
use super::envelope::EnvelopeHooks;
use super::seen::Refused;
use super::snapshot::{max_pre_states, Snapshots, PRE_STATE_EPOCHS};
use crate::engine::client::{NewPayload, CALL_TIMEOUT};
use crate::engine::verdict::{ElVerdict, ExecutionStatus, ExecutionStatuses};
use crate::import::block::{
    check_proposer_signature, check_proposer_signature_in, import_block, process_empty_slots,
    schedule_proposer_domain, NotImported, PayloadImportGate,
};
use crate::verify::client::{BlsOutcome, BlsVerifier, UnixClock};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock, SignedExecutionPayloadEnvelope};
use consensus_types::primitives::{BLSPubkey, Epoch, Root, Slot, ValidatorIndex};
use consensus_types::signing::DOMAIN_BEACON_PROPOSER;
use ethswarm_proto::verify::BlsSet;
use fork_choice::{verify_execution_payload_envelope, DataAvailability, DataAvailabilityCheck};
use network_config::ChainConfig;
use state_transition::accessors::get_domain;
use state_transition::{state_root, Preset, StfError};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Handle;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tree_hash::TreeHash;

/// The time a block import has for its VerifyBls verdicts, from the start of the import
/// \[est\]: well inside a slot, so a block that has no verdict by then is IGNOREd and can come
/// again.
pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(4);

/// The time an envelope import gives the EL's newPayload verdict, from the start of the call
/// \[est\]: the wait of [`NewPayloadClient`](crate::engine::client::NewPayloadClient) for
/// cl-engine's answer. The core thread waits for it.
pub const DEFAULT_ENGINE_TIMEOUT: Duration = CALL_TIMEOUT;

/// The most slots a block can be ahead of the slot of the wall clock: one slot of clock skew
/// between the core and the proposer. The gossip rule (`MAXIMUM_GOSSIP_CLOCK_DISPARITY`) is
/// tighter, but it is for gossip validation, and no code reads that config value yet.
pub const MAX_FUTURE_SLOTS: u64 = 1;

/// The most roots of refused blocks that the core keeps \[est\]. Past it, the root refused
/// first goes.
pub const MAX_REFUSED_ROOTS: usize = 1024;

/// The last block the core committed, or the anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// `hash_tree_root(block.message)`.
    pub block_root: Root,
    /// `block.slot`.
    pub slot: Slot,
    /// `block.state_root`, equal to the root of the post-state the core holds.
    pub state_root: Root,
}

/// What the core did with an item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The block is committed: its post-state is a pre-state of the core, and it is the head.
    Committed {
        /// `hash_tree_root(block.message)`.
        block_root: Root,
        /// The root of the post-state, equal to `block.state_root`.
        state_root: Root,
    },
    /// The payload of the envelope's block is verified: VALID, or SYNCING or ACCEPTED
    /// (optimistic).
    PayloadVerified {
        /// `envelope.beacon_block_root`.
        block_root: Root,
    },
    /// A proven invalid block (REJECT); see [`NotImported::Invalid`]. Nothing is committed.
    Invalid(StfError),
    /// A proven invalid envelope (REJECT): a failed check of `verify_execution_payload_envelope`,
    /// or an EL verdict of INVALID. Why, for the log. Nothing is verified.
    InvalidEnvelope(String),
    /// No verdict and no proof (IGNORE): why, for the log. Nothing is committed.
    Ignored(String),
}

/// The answer to an item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    /// The place of the item in the order the core served its items, from 1.
    pub turn: u64,
    /// What the core did.
    pub outcome: Outcome,
}

/// Why the core did not take an item. The caller IGNOREs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SubmitError {
    /// The queue of the item is full.
    #[error("the chain core queue is full")]
    Full,
    /// The core stopped.
    #[error("the chain core stopped")]
    Stopped,
}

/// Why an anchor did not install: the state root cannot be computed, or it is not
/// `block.state_root` ([`StfError::StateRootMismatch`]), or the network config lacks a value
/// that the transition reads.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// The anchor state does not hash, or not to `block.state_root`.
    #[error("anchor state: {0}")]
    State(StfError),
    /// The network config lacks `CAPELLA_FORK_VERSION`.
    #[error("network config: {0}")]
    Config(String),
}

/// The answer channel of an item.
type Reply = oneshot::Sender<Served>;

/// A hook that the core thread runs in a walk over empty slots, with the slot of the walk state
/// ([`ChainCore::with_walk_hook`]).
#[cfg(feature = "test-hooks")]
type WalkHook = Box<dyn Fn(Slot) + Send + Sync>;

/// The test hooks of a [`ChainCore`]: none in a build without the `test-hooks` feature.
#[derive(Default)]
struct Hooks {
    #[cfg(feature = "test-hooks")]
    walk: Option<WalkHook>,
}

impl Hooks {
    /// Runs the walk hook, if one is set.
    fn walk(&self, _slot: Slot) {
        #[cfg(feature = "test-hooks")]
        if let Some(hook) = &self.walk {
            hook(_slot);
        }
    }
}

/// A block to import, and where its answer goes.
struct ImportItem<E: Preset> {
    block: Box<SignedBeaconBlock<E>>,
    reply: Reply,
}

/// An envelope to import, and where its answer goes.
struct EnvelopeItem<E: Preset> {
    envelope: Box<SignedExecutionPayloadEnvelope<E>>,
    reply: Reply,
}

/// The sending side of the queues of the core.
#[derive(Clone)]
pub struct CoreSender<E: Preset> {
    import: mpsc::Sender<ImportItem<E>>,
    envelope: mpsc::Sender<EnvelopeItem<E>>,
    gossip: mpsc::Sender<Reply>,
}

/// The receiving side of the queues of the core, for [`ChainCore::spawn`].
pub struct CoreQueue<E: Preset> {
    import: mpsc::Receiver<ImportItem<E>>,
    envelope: mpsc::Receiver<EnvelopeItem<E>>,
    gossip: mpsc::Receiver<Reply>,
}

/// The queues of the core, each with room for `capacity` items (at least 1).
pub fn queue<E: Preset>(capacity: usize) -> (CoreSender<E>, CoreQueue<E>) {
    let capacity = capacity.max(1);
    let (import, import_rx) = mpsc::channel(capacity);
    let (envelope, envelope_rx) = mpsc::channel(capacity);
    let (gossip, gossip_rx) = mpsc::channel(capacity);
    (
        CoreSender {
            import,
            envelope,
            gossip,
        },
        CoreQueue {
            import: import_rx,
            envelope: envelope_rx,
            gossip: gossip_rx,
        },
    )
}

impl<E: Preset> CoreSender<E> {
    /// Queues `block` for import. The answer comes on the receiver; a receiver that closes
    /// without one means the core stopped (IGNORE). The core checks the slot of the block
    /// against the wall clock before the slot loop (see the module docs). If the caller drops
    /// the receiver, the core stops the import at its next check of the caller (IGNORE).
    pub fn import(
        &self,
        block: SignedBeaconBlock<E>,
    ) -> Result<oneshot::Receiver<Served>, SubmitError> {
        submit(&self.import, |reply| ImportItem {
            block: Box::new(block),
            reply,
        })
    }

    /// Queues `envelope` for import (see the module docs). The answer comes on the receiver; a
    /// receiver that closes without one means the core stopped (IGNORE).
    pub fn envelope(
        &self,
        envelope: SignedExecutionPayloadEnvelope<E>,
    ) -> Result<oneshot::Receiver<Served>, SubmitError> {
        submit(&self.envelope, |reply| EnvelopeItem {
            envelope: Box::new(envelope),
            reply,
        })
    }

    /// Queues a gossip commit item. Gossip commit is not implemented: the answer is IGNORE.
    pub fn gossip(&self) -> Result<oneshot::Receiver<Served>, SubmitError> {
        submit(&self.gossip, |reply| reply)
    }
}

/// Puts the item that `item` makes for its reply channel into `queue`, without a wait.
fn submit<T>(
    queue: &mpsc::Sender<T>,
    item: impl FnOnce(Reply) -> T,
) -> Result<oneshot::Receiver<Served>, SubmitError> {
    let (reply, answer) = oneshot::channel();
    queue.try_send(item(reply)).map_err(|e| match e {
        TrySendError::Full(_) => SubmitError::Full,
        TrySendError::Closed(_) => SubmitError::Stopped,
    })?;
    Ok(answer)
}

/// An item of one of the queues.
enum Item<E: Preset> {
    Import(ImportItem<E>),
    Envelope(EnvelopeItem<E>),
    Gossip(Reply),
}

impl<E: Preset> CoreQueue<E> {
    /// The next item: import first, then envelope, then gossip. `None` once each queue is
    /// closed and empty.
    async fn next(&mut self) -> Option<Item<E>> {
        tokio::select! {
            biased;
            Some(item) = self.import.recv() => Some(Item::Import(item)),
            Some(item) = self.envelope.recv() => Some(Item::Envelope(item)),
            Some(reply) = self.gossip.recv() => Some(Item::Gossip(reply)),
            else => None,
        }
    }
}

/// The single writer of the chain state (see the module docs).
pub struct ChainCore<E: Preset> {
    config: ChainConfig,
    /// `genesis_time` of the anchor state, Unix seconds: the start of slot 0.
    genesis_time: u64,
    snapshots: Snapshots<BeaconState<E>>,
    /// The states of the walks over empty slots (see [`advance`](super::advance)).
    advanced: Advanced<BeaconState<E>>,
    /// The admission budget of those walks, on the slots of `clock`.
    budget: AdvanceBudget,
    /// The root of each block the core committed, and of the anchor (see the module docs).
    committed: HashSet<Root>,
    /// The kept refusals, by block root (see the module docs).
    refused: Refused<Outcome>,
    /// The EL's verdicts on the payloads of the imported envelopes (see the module docs).
    statuses: ExecutionStatuses,
    /// The blocks whose payload is verified, among those with a pre-state.
    payload_verified: HashSet<Root>,
    head: Head,
    verify_timeout: Duration,
    engine_timeout: Duration,
    /// `None` until [`Self::with_payload_gate`]: no block commits without a gate.
    gate: Option<Box<dyn PayloadImportGate>>,
    /// `None` until [`Self::with_data_availability`]: no envelope imports without it.
    data: Option<Box<dyn DataAvailabilityCheck + Send>>,
    /// `None` until [`Self::with_engine`]: no envelope imports without it.
    engine: Option<Box<dyn NewPayload<E>>>,
    clock: UnixClock,
    turns: u64,
    hooks: Hooks,
}

impl<E: Preset> ChainCore<E> {
    /// A core on the anchor `state` and `block` of `config`'s network. The roots are computed
    /// again here: the state must have the root `block.state_root`. This is not the Bootstrap
    /// RPC; the caller checks where the anchor comes from.
    ///
    /// The core has no payload gate: it IGNOREs each block until [`Self::with_payload_gate`]
    /// sets one.
    pub fn from_anchor(
        mut state: BeaconState<E>,
        block: SignedBeaconBlock<E>,
        config: ChainConfig,
    ) -> Result<Self, AnchorError> {
        config
            .capella_fork_version()
            .map_err(|e| AnchorError::Config(e.to_string()))?;
        if config.slot_duration_ms() == 0 {
            return Err(AnchorError::Config("SLOT_DURATION_MS is 0".into()));
        }
        let computed = state_root(&mut state).map_err(AnchorError::State)?;
        if computed != block.message.state_root {
            return Err(AnchorError::State(StfError::StateRootMismatch {
                block: block.message.state_root,
                computed,
            }));
        }
        let head = Head {
            block_root: block.message.tree_hash_root(),
            slot: block.message.slot,
            state_root: computed,
        };
        Ok(Self {
            config,
            genesis_time: state.genesis_time,
            snapshots: Snapshots::new(head.block_root, state, max_pre_states::<E>()),
            advanced: Advanced::new(MAX_ADVANCED_STATES),
            budget: AdvanceBudget::new(),
            committed: HashSet::from([head.block_root]),
            refused: Refused::new(MAX_REFUSED_ROOTS),
            statuses: ExecutionStatuses::new(),
            payload_verified: HashSet::new(),
            head,
            verify_timeout: DEFAULT_VERIFY_TIMEOUT,
            engine_timeout: DEFAULT_ENGINE_TIMEOUT,
            gate: None,
            data: None,
            engine: None,
            clock: Arc::new(system_clock),
            turns: 0,
            hooks: Hooks::default(),
        })
    }

    /// The same core where each import has `timeout` for its VerifyBls verdicts: one deadline,
    /// taken at the start of the import, for each VerifyBls call of that import.
    #[must_use]
    pub fn with_verify_timeout(mut self, timeout: Duration) -> Self {
        self.verify_timeout = timeout;
        self
    }

    /// The same core with `gate` as the payload gate of each import.
    #[must_use]
    pub fn with_payload_gate(mut self, gate: impl PayloadImportGate + 'static) -> Self {
        self.gate = Some(Box::new(gate));
        self
    }

    /// The same core with `check` as the data availability check of each envelope import.
    #[must_use]
    pub fn with_data_availability(
        mut self,
        check: impl DataAvailabilityCheck + Send + 'static,
    ) -> Self {
        self.data = Some(Box::new(check));
        self
    }

    /// The same core with `engine` as the newPayload call of each envelope import.
    #[must_use]
    pub fn with_engine(mut self, engine: impl NewPayload<E> + 'static) -> Self {
        self.engine = Some(Box::new(engine));
        self
    }

    /// The same core where each newPayload call has `timeout` for the EL's verdict.
    #[must_use]
    pub fn with_engine_timeout(mut self, timeout: Duration) -> Self {
        self.engine_timeout = timeout;
        self
    }

    /// The same core with the payload of block `block_root` verified, as if its envelope
    /// imported. A test seam, for an anchor whose envelope cannot verify.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn with_payload_verified(mut self, block_root: Root) -> Self {
        self.payload_verified.insert(block_root);
        self
    }

    /// The same core with `clock` (Unix milliseconds) as its wall clock, in place of the system
    /// clock.
    #[must_use]
    pub fn with_clock(mut self, clock: UnixClock) -> Self {
        self.clock = clock;
        self
    }

    /// The same core with `hook` as its walk hook, in place of an earlier one. A test seam: in
    /// a walk over empty slots (see [`advance`](super::advance)), the core thread runs `hook`
    /// with the slot of the walk state before each check of the deadline and of the caller,
    /// and once after the walk. So it runs before the walk, at each epoch boundary after the
    /// walk keeps its state, and before the check of the proposer.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn with_walk_hook(mut self, hook: impl Fn(Slot) + Send + Sync + 'static) -> Self {
        self.hooks.walk = Some(Box::new(hook));
        self
    }

    /// The same core that keeps `state` as the state of a walk from the parent `parent_root` at
    /// the last slot of epoch `epoch - 1` (see [`advance`](super::advance)), in place of an
    /// earlier one. A test seam: a later walk from that parent can start from `state`, as from a
    /// state that a walk kept.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn with_advanced_state(
        mut self,
        parent_root: Root,
        epoch: Epoch,
        state: BeaconState<E>,
    ) -> Self {
        self.advanced.insert(parent_root, epoch, state);
        self
    }

    /// The last block the core committed, or the anchor.
    pub fn head(&self) -> Head {
        self.head
    }

    /// The post-state of block `block_root`, if the core holds it as a pre-state.
    pub fn state(&self, block_root: &Root) -> Option<&BeaconState<E>> {
        self.snapshots.peek(block_root)
    }

    /// The number of pre-states the core holds, the anchor included.
    pub fn pre_states(&self) -> usize {
        self.snapshots.len()
    }

    /// `true` if the core keeps a refusal of block `block_root`, for one signature or for each
    /// (see [Seen roots](#seen-roots)).
    pub fn is_refused(&self, block_root: &Root) -> bool {
        self.refused.contains(block_root)
    }

    /// `true` if the core committed block `block_root`, or it is the anchor.
    pub fn is_committed(&self, block_root: &Root) -> bool {
        self.committed.contains(block_root)
    }

    /// `true` if the payload of block `block_root` is verified (see the module docs).
    pub fn payload_verified(&self, block_root: &Root) -> bool {
        self.payload_verified.contains(block_root)
    }

    /// The EL's verdicts that the core recorded, and whether the EL contradicted itself.
    pub fn execution_statuses(&self) -> &ExecutionStatuses {
        &self.statuses
    }

    /// The post-state of block `parent_root` advanced to the last slot of epoch `epoch - 1`, if
    /// the core keeps it (see [`advance`](super::advance)).
    pub fn advanced_state(&self, parent_root: &Root, epoch: Epoch) -> Option<&BeaconState<E>> {
        self.advanced.peek(parent_root, epoch)
    }

    /// Moves the core onto a new OS thread that serves `queue` (see the module docs). Each
    /// VerifyBls call runs on `runtime`, and the core thread waits for it: the runtime must
    /// keep running (a current-thread runtime must not block its own thread on the core). The
    /// thread returns the core once each sender of `queue` is gone and the queues are empty.
    pub fn spawn<V: BlsVerifier + 'static>(
        self,
        queue: CoreQueue<E>,
        verifier: Arc<V>,
        runtime: Handle,
    ) -> std::io::Result<JoinHandle<Self>> {
        std::thread::Builder::new()
            .name("chain-core".into())
            .spawn(move || self.run(queue, &verifier, &runtime))
    }

    fn run<V: BlsVerifier + 'static>(
        mut self,
        mut queue: CoreQueue<E>,
        verifier: &Arc<V>,
        runtime: &Handle,
    ) -> Self {
        while let Some(item) = runtime.block_on(queue.next()) {
            self.turns += 1;
            let turn = self.turns;
            let (outcome, reply) = match item {
                Item::Import(item) => (
                    self.import(&item.block, &item.reply, verifier, runtime),
                    item.reply,
                ),
                Item::Envelope(item) => (
                    self.import_envelope(&item.envelope, verifier, runtime),
                    item.reply,
                ),
                Item::Gossip(reply) => (Outcome::Ignored("no gossip commit yet".into()), reply),
            };
            // A caller that stopped waiting has nothing to answer.
            let _ = reply.send(Served { turn, outcome });
        }
        self
    }

    /// Imports `block` and commits it only if it imports (see the module docs). `reply` is the
    /// answer channel of the import: once it is closed, the import stops at the next check.
    fn import<V: BlsVerifier + 'static>(
        &mut self,
        block: &SignedBeaconBlock<E>,
        reply: &Reply,
        verifier: &Arc<V>,
        runtime: &Handle,
    ) -> Outcome {
        let deadline = self.deadline(runtime);
        if self.statuses.el_contradiction() {
            return Outcome::Ignored(EL_CONTRADICTION.into());
        }
        let bid = &block.message.body.signed_execution_payload_bid.message;
        for hash in [bid.block_hash, bid.parent_block_hash] {
            if self.statuses.status(&hash) == Some(ExecutionStatus::Invalid) {
                return Outcome::Ignored(format!("the EL found payload {hash} of the bid INVALID"));
            }
        }
        let Some(gate) = self.gate.as_deref() else {
            return Outcome::Ignored("no payload gate is set".into());
        };
        if let Err(why) = self.check_slot(block.message.slot) {
            return Outcome::Ignored(why);
        }
        let block_root = block.message.tree_hash_root();
        if self.committed.contains(&block_root) {
            return Outcome::Ignored(format!("block {block_root} is already committed"));
        }
        if let Some(refused) = self.refused.get(&block_root, &block.signature) {
            return refused.clone();
        }
        let parent = block.message.parent_root;
        // A peek: the parent becomes the most recently used only if its child commits, so a
        // failed import does not change the order of use.
        let Some(parent_state) = self.snapshots.peek(&parent) else {
            return Outcome::Ignored(format!("no pre-state for the parent {parent}"));
        };
        if bid.parent_block_hash == parent_state.latest_execution_payload_bid.block_hash
            && !self.payload_verified.contains(&parent)
        {
            return Outcome::Ignored(format!(
                "the payload of the parent {parent} is not verified"
            ));
        }
        let verdict = |sets: Vec<BlsSet>| verify(runtime, verifier, sets, deadline);
        let slot = block.message.slot;
        let proposer = block.message.proposer_index;
        let window = PRE_STATE_EPOCHS * E::slots_per_epoch();
        let advanced;
        let pre = if slot.saturating_sub(parent_state.slot) <= window {
            // The slot loop can add a validator, but not an active one: its activation waits
            // for the finality of a later epoch than the one that added it, and the loop has no
            // new attestations to finalize that epoch. So an index past the registry of the
            // pre-state is never the proposer, and `process_block_header` refuses it after the
            // slot loop. Refused here, it costs no slot loop.
            if !in_registry(parent_state, proposer) {
                let invalid = Outcome::Invalid(StfError::UnknownValidator(proposer));
                return self.refused.refuse(block_root, None, invalid);
            }
            // A caller that stopped waiting gets no answer: no VerifyBls call and no commit for
            // it. This is no proof about the block, so the refusal is not kept.
            if reply.is_closed() {
                return Outcome::Ignored(CALLER_GONE.into());
            }
            // The gossip order: the signature of the proposer before the slot loop, so that a
            // block that its proposer did not sign costs one VerifyBls call and no slot loop.
            let checked = check_proposer_signature(parent_state, block, &verdict);
            if let Some(stop) = signature_stop(&mut self.refused, block_root, block, reply, checked)
            {
                return stop;
            }
            parent_state
        } else {
            // A block far after its parent: the checks before the walk cost no `process_slots`.
            let gap = match walk_slots(&self.advanced, parent, parent_state, slot) {
                Ok(gap) => gap,
                // Past the cap: no proof about the block, so the refusal is not kept.
                Err(why) => return Outcome::Ignored(why),
            };
            // The walk can add an index to the registry, so an index past the registry of the
            // parent state is no proof here. It is not kept, and it costs no VerifyBls call.
            if !in_registry(parent_state, proposer) {
                return Outcome::Ignored(format!(
                    "proposer {proposer} is past the registry of the state of the parent {parent}"
                ));
            }
            // The walk does not unslash a validator, or move a set exit or withdrawable epoch
            // later, so such a proposer cannot propose at the block epoch. The walk can activate
            // a validator, so one that is not active yet goes on. No proof: it is not kept.
            let epoch = E::epoch_at_slot(slot);
            if let Some(why) = cannot_propose(parent_state, proposer, epoch) {
                return Outcome::Ignored(format!(
                    "proposer {proposer} {why} in the state of the parent {parent}"
                ));
            }
            // The domain of the network schedule at the block epoch. `get_domain` on the parent
            // state must give it too: else an INVALID verdict with it is no proof. The walk has
            // no fork upgrade yet, so a block that needs one can come again when it has.
            let gvr = parent_state.genesis_validators_root;
            let Some(domain) = schedule_proposer_domain(&self.config, epoch, gvr) else {
                return Outcome::Ignored(format!("the network schedule has no fork at {epoch}"));
            };
            if get_domain(parent_state, DOMAIN_BEACON_PROPOSER, Some(epoch)) != domain {
                return Outcome::Ignored(format!(
                    "the fork of the state of the parent {parent} at epoch {epoch} is not the \
                     fork of the network schedule"
                ));
            }
            if reply.is_closed() {
                return Outcome::Ignored(CALLER_GONE.into());
            }
            // A validator key does not change, so the key of the parent state is the key of
            // the block slot. A block that its proposer did not sign costs no walk.
            let checked = check_proposer_signature_in(parent_state, block, domain, &verdict);
            if let Some(stop) = signature_stop(&mut self.refused, block_root, block, reply, checked)
            {
                return stop;
            }
            // The VerifyBls call can take up to the deadline: the slot of the walk is the slot of
            // the clock after it, so the block slot is checked again against that slot.
            let wall_slot = match self.check_slot(slot) {
                Ok(wall_slot) => wall_slot,
                Err(why) => return Outcome::Ignored(why),
            };
            // The walk is charged in full before it starts, to the budget of all proposers and
            // to the budget of its proposer, and gives nothing back if it stops early. A block
            // over the budget can come again in a later slot, or from a nearer kept state.
            let epochs = gap.div_ceil(E::slots_per_epoch());
            if !self.budget.take(wall_slot, proposer, epochs) {
                return Outcome::Ignored(format!(
                    "the walk of {epochs} epochs of proposer {proposer} is over the admission \
                     budget of slot {wall_slot}"
                ));
            }
            let hooks = &self.hooks;
            // On the clock of the runtime, as the deadline.
            let stop = |at: Slot| {
                hooks.walk(at);
                let _context = runtime.enter();
                if Instant::now() >= deadline {
                    Some("no time left")
                } else if reply.is_closed() {
                    Some(CALLER_GONE)
                } else {
                    None
                }
            };
            let config = &self.config;
            let walk = |state: &mut BeaconState<E>, to: Slot| {
                process_empty_slots(state, to, parent_state, config, &verdict)
            };
            let walked = advance(&mut self.advanced, parent, parent_state, slot, &stop, &walk);
            advanced = match walked {
                Ok(state) => state,
                // No proof about the block, so the refusal is not kept.
                Err(why) => return Outcome::Ignored(why),
            };
            self.hooks.walk(advanced.slot);
            if reply.is_closed() {
                return Outcome::Ignored(CALLER_GONE.into());
            }
            let expected = match block_proposer(&advanced, slot) {
                Ok(expected) => expected,
                // The lookahead of the state is at fault, not the block.
                Err(why) => return Outcome::Ignored(why),
            };
            // This check comes before the domain check below, so a block that fails both is
            // refused here and kept INVALID: `process_block_header` refuses another proposer on
            // the advanced state, and that check reads no domain.
            if proposer != expected {
                // The signature is valid, so the refusal holds for the message.
                let invalid = Outcome::Invalid(StfError::WrongProposer {
                    block: proposer,
                    expected,
                });
                return self.refused.refuse(block_root, None, invalid);
            }
            // The verdict holds for the domain that it checked. A walk with a fork upgrade can
            // give the advanced state another fork at the block epoch: no proof about the block,
            // so no second VerifyBls call and no kept refusal.
            if get_domain(&advanced, DOMAIN_BEACON_PROPOSER, Some(epoch)) != domain {
                return Outcome::Ignored(format!(
                    "the fork of the advanced state of the parent {parent} at epoch {epoch} is \
                     not the fork of the network schedule"
                ));
            }
            // The verdict holds for the key that it checked. If the advanced state gives
            // another one, the signature goes to cl-verify again with it.
            if registry_key(&advanced, proposer) != registry_key(parent_state, proposer) {
                let checked = check_proposer_signature_in(&advanced, block, domain, &verdict);
                if let Some(stop) =
                    signature_stop(&mut self.refused, block_root, block, reply, checked)
                {
                    return stop;
                }
            }
            &advanced
        };
        let imported = import_block(pre, block, &self.config, &verdict, gate);
        // The same for the VerifyBls call of the block sets, before any change of the core: no
        // commit and no kept refusal.
        if reply.is_closed() {
            return Outcome::Ignored(CALLER_GONE.into());
        }
        match imported {
            Ok(imported) => {
                self.head = Head {
                    block_root: imported.block_root,
                    slot: block.message.slot,
                    state_root: imported.state_root,
                };
                self.snapshots.promote(&parent);
                self.snapshots.insert(imported.block_root, imported.post);
                // The insert can drop the pre-state of a parent. Its kept walk states then
                // cannot serve an import, as an import needs that pre-state first.
                let snapshots = &self.snapshots;
                self.advanced.retain(|parent| snapshots.contains(parent));
                self.payload_verified
                    .retain(|root| snapshots.contains(root));
                self.committed.insert(imported.block_root);
                Outcome::Committed {
                    block_root: imported.block_root,
                    state_root: imported.state_root,
                }
            }
            // The proposer signature is valid, so the refusal holds for the message.
            Err(NotImported::Invalid(e)) => {
                self.refused.refuse(block_root, None, Outcome::Invalid(e))
            }
            Err(NotImported::Ignored(why)) => Outcome::Ignored(why),
        }
    }

    /// Imports `signed` and verifies its block's payload only if it imports (see the module
    /// docs).
    fn import_envelope<V: BlsVerifier + 'static>(
        &mut self,
        signed: &SignedExecutionPayloadEnvelope<E>,
        verifier: &Arc<V>,
        runtime: &Handle,
    ) -> Outcome {
        let deadline = self.deadline(runtime);
        if self.statuses.el_contradiction() {
            return Outcome::Ignored(EL_CONTRADICTION.into());
        }
        let root = signed.message.beacon_block_root;
        if self.payload_verified.contains(&root) {
            return Outcome::Ignored(format!("the payload of block {root} is already verified"));
        }
        let committed = self.committed.contains(&root);
        let Some(state) = self.snapshots.peek(&root).filter(|_| committed) else {
            return Outcome::Ignored(format!("block {root} is not committed with a pre-state"));
        };
        let Some(data) = self.data.as_deref() else {
            return Outcome::Ignored("no data availability check is set".into());
        };
        if data.is_data_available(root) != DataAvailability::Available {
            return Outcome::Ignored(format!("the data of block {root} is not available"));
        }
        let Some(engine) = self.engine.as_deref() else {
            return Outcome::Ignored("no newPayload engine is set".into());
        };
        // `from_anchor` refuses a zero SLOT_DURATION_MS.
        let Some(slot_ms) = NonZeroU64::new(self.config.slot_duration_ms()) else {
            return Outcome::Ignored("SLOT_DURATION_MS is 0".into());
        };
        let verdict = |sets: Vec<BlsSet>| verify(runtime, verifier, sets, deadline);
        let hooks = EnvelopeHooks {
            verdict: &verdict,
            engine,
            runtime,
            timeout: self.engine_timeout,
            envelope: &signed.message,
            bid: &state.latest_execution_payload_bid,
            statuses: RefCell::new(&mut self.statuses),
            el: Cell::new(None),
        };
        let checked = verify_execution_payload_envelope(state, signed, slot_ms, &hooks);
        let el = hooks.el.get();
        // The answer that set it is refused too.
        if self.statuses.el_contradiction() {
            return Outcome::Ignored(EL_CONTRADICTION.into());
        }
        match checked {
            Ok(()) => {
                self.payload_verified.insert(root);
                Outcome::PayloadVerified { block_root: root }
            }
            Err(fork_choice::Error::InvalidEnvelope(e)) => Outcome::InvalidEnvelope(e.to_string()),
            Err(e) if matches!(el, Some(ElVerdict::Invalid { .. })) => {
                Outcome::InvalidEnvelope(format!("the EL answered INVALID: {e}"))
            }
            Err(e) => Outcome::Ignored(e.to_string()),
        }
    }

    /// The deadline of the VerifyBls calls of an import that starts now: on the clock of the
    /// timers of `runtime`. A timeout past the range of `Instant` gives no time at all.
    fn deadline(&self, runtime: &Handle) -> Instant {
        let _context = runtime.enter();
        let now = Instant::now();
        now.checked_add(self.verify_timeout).unwrap_or(now)
    }

    /// The slot of the wall clock. `Err` (why, for the log) if `slot` is more than
    /// [`MAX_FUTURE_SLOTS`] ahead of it, or if the wall clock is before genesis.
    fn check_slot(&self, slot: Slot) -> Result<Slot, String> {
        let now_ms = (self.clock)();
        let wall_slot = now_ms
            .checked_sub(u128::from(self.genesis_time) * 1000)
            .and_then(|since| since.checked_div(u128::from(self.config.slot_duration_ms())))
            .ok_or_else(|| format!("the wall clock {now_ms} ms is before genesis"))?;
        if u128::from(slot) > wall_slot + u128::from(MAX_FUTURE_SLOTS) {
            return Err(format!(
                "block slot {slot} is more than {MAX_FUTURE_SLOTS} slot ahead of the wall-clock \
                 slot {wall_slot}"
            ));
        }
        Ok(Slot::try_from(wall_slot).unwrap_or(Slot::MAX))
    }
}

/// `true` if validator `index` is in the registry of `state`.
fn in_registry<E: Preset>(state: &BeaconState<E>, index: ValidatorIndex) -> bool {
    registry_key(state, index).is_some()
}

/// Why validator `index` of `state` cannot propose a block at `epoch`, a later epoch than the
/// state, or `None`: it is slashed, or exited or withdrawable at `epoch`. Slots without a block
/// do not unslash a validator, or move a set exit or withdrawable epoch later. `None` for a
/// validator that is not active yet, and for an index past the registry.
fn cannot_propose<E: Preset>(
    state: &BeaconState<E>,
    index: ValidatorIndex,
    epoch: Epoch,
) -> Option<String> {
    let validator = state.validators.get(usize::try_from(index).ok()?)?;
    if validator.slashed {
        Some("is slashed".into())
    } else if validator.exit_epoch <= epoch {
        Some(format!(
            "exits at epoch {}, not after the block epoch {epoch}",
            validator.exit_epoch
        ))
    } else if validator.withdrawable_epoch <= epoch {
        Some(format!(
            "is withdrawable at epoch {}, not after the block epoch {epoch}",
            validator.withdrawable_epoch
        ))
    } else {
        None
    }
}

/// The registry key of validator `index` in `state`.
fn registry_key<E: Preset>(state: &BeaconState<E>, index: ValidatorIndex) -> Option<BLSPubkey> {
    let index = usize::try_from(index).ok()?;
    state
        .validators
        .get(index)
        .map(|validator| validator.pubkey)
}

/// The answer to an import after the VerifyBls call of its proposer set gave `checked`, or
/// `None` if the import goes on. A caller that stopped waiting during the call gets IGNORE, and
/// the core keeps no refusal, also of an INVALID verdict. An INVALID verdict is kept in
/// `refused` for that signature only, as the block root does not commit to it. No verdict is
/// IGNORE.
fn signature_stop<E: Preset>(
    refused: &mut Refused<Outcome>,
    block_root: Root,
    block: &SignedBeaconBlock<E>,
    reply: &Reply,
    checked: Result<(), NotImported>,
) -> Option<Outcome> {
    if reply.is_closed() {
        return Some(Outcome::Ignored(CALLER_GONE.into()));
    }
    match checked {
        Ok(()) => None,
        Err(NotImported::Invalid(e)) => {
            Some(refused.refuse(block_root, Some(block.signature), Outcome::Invalid(e)))
        }
        Err(NotImported::Ignored(why)) => Some(Outcome::Ignored(why)),
    }
}

/// The system clock in Unix milliseconds, 0 before 1970 (before any genesis).
fn system_clock() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}

/// The verdict of `verifier` on `sets`, or none by `deadline`. The call runs on `runtime`; the
/// core thread waits for it. A deadline that passed sends nothing, and a verdict that comes at
/// or after the deadline is no verdict: a late VALID never commits.
fn verify<V: BlsVerifier + 'static>(
    runtime: &Handle,
    verifier: &Arc<V>,
    sets: Vec<BlsSet>,
    deadline: Instant,
) -> BlsOutcome {
    let verifier = Arc::clone(verifier);
    let call = runtime.spawn(async move {
        if Instant::now() >= deadline {
            return BlsOutcome::NoVerdict(format!("{NO_VERDICT_IN_TIME}: no time left"));
        }
        // The deadline of the verifier, not a second timer: it stops only a verifier that does
        // not keep its deadline. `BlsClient` closes its stream when a call that sent its
        // request is dropped, so this cannot leave a request in its window.
        let outcome = tokio::time::timeout_at(deadline, verifier.verify_sets(sets, deadline))
            .await
            .unwrap_or_else(|_| BlsOutcome::NoVerdict(NO_VERDICT_IN_TIME.into()));
        // `timeout_at` polls the call before its timer, so a verdict that is ready at the
        // deadline gets through it.
        match outcome {
            BlsOutcome::Valid | BlsOutcome::Invalid if Instant::now() >= deadline => {
                BlsOutcome::NoVerdict(format!("{NO_VERDICT_IN_TIME}: the verdict came at it"))
            }
            outcome => outcome,
        }
    });
    runtime
        .block_on(call)
        .unwrap_or_else(|e| BlsOutcome::NoVerdict(format!("the VerifyBls call failed: {e}")))
}

/// The no-verdict reason of a VerifyBls call without a verdict before its deadline.
const NO_VERDICT_IN_TIME: &str = "no verdict by the deadline";

/// The IGNORE reason of each import once the EL contradicted itself.
const EL_CONTRADICTION: &str = "the EL contradicted itself: no import until manual intervention";

/// The IGNORE reason of an import whose caller dropped the receiver of the answer.
const CALLER_GONE: &str = "the caller stopped waiting for the answer";
