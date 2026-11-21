//! The chain core: the single writer of the chain state.
//!
//! [`ChainCore`] holds the head and the pre-states ([`Snapshots`]). [`ChainCore::spawn`] moves
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
//! - no [`PayloadImportGate`] is set: IGNORE. [`ChainCore::from_anchor`] sets none, so a core
//!   that misses [`ChainCore::with_payload_gate`] commits nothing
//!   ([`PermitAll`](crate::import::block::PermitAll) is an explicit opt-in);
//! - the block slot is more than [`MAX_FUTURE_SLOTS`] ahead of the slot of the wall clock
//!   ([`ChainCore::with_clock`], the system clock if not set), or the wall clock is before
//!   genesis: IGNORE;
//! - the core committed the block, or it is the anchor: IGNORE;
//! - the core refused the block before and kept the refusal: the same answer again;
//! - the parent has no pre-state: IGNORE;
//! - the block slot is more than [`PRE_STATE_EPOCHS`] epochs of slots after the slot of the
//!   parent pre-state: IGNORE, kept. The wall-clock bound does not stop a block at the slot of
//!   the wall clock on an old pre-state (the anchor stays for good), and the walk from that
//!   pre-state costs one `process_slot` for each slot;
//! - `proposer_index` is past the registry of the parent pre-state: INVALID, kept;
//! - the proposer signature ([`check_proposer_signature`]), with the key of the parent
//!   pre-state: INVALID on an INVALID verdict (kept for that signature only), IGNORE on no
//!   verdict.
//!
//! Then it runs [`import_block`] on the pre-state of the parent. The core sends the signature
//! sets to cl-verify through a [`BlsVerifier`], on the Tokio runtime of the caller, with the
//! deadline of the import: the proposer set in a first VerifyBls call, the block sets in a
//! second one during the transition. Each VerifyBls call of one import gets the same deadline,
//! and no verdict by then is IGNORE. The core commits only on a VALID verdict, a post-state
//! root equal to `block.state_root` and a gate that permits the payload: it makes the parent
//! pre-state the most recently used, keeps the post-state as a pre-state, and the block
//! becomes the head. There is no fork choice yet, so the head is the last block the core
//! committed. On any other outcome the head and the pre-states do not change, their order of
//! use included. An INVALID outcome of the transition is kept.
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
//! (it can come), a refused payload, or the wall-clock bound: the same block is in that bound
//! once its slot comes, and that check costs no slot loop and no VerifyBls call.
//!
//! Envelope import and gossip commit are queue kinds only: the core answers each such item
//! IGNORE and changes nothing.

use super::seen::Refused;
use super::snapshot::{max_pre_states, Snapshots, PRE_STATE_EPOCHS};
use crate::import::block::{
    check_proposer_signature, import_block, NotImported, PayloadImportGate,
};
use crate::verify::client::{BlsOutcome, BlsVerifier, UnixClock};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{Epoch, Root, Slot};
use ethswarm_proto::verify::BlsSet;
use network_config::ChainConfig;
use state_transition::{state_root, Preset, StfError};
use std::collections::HashSet;
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
    /// A proven invalid block (REJECT); see [`NotImported::Invalid`]. Nothing is committed.
    Invalid(StfError),
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

/// A block to import, and where its answer goes.
struct ImportItem<E: Preset> {
    block: Box<SignedBeaconBlock<E>>,
    reply: Reply,
}

/// The sending side of the queues of the core.
#[derive(Clone)]
pub struct CoreSender<E: Preset> {
    import: mpsc::Sender<ImportItem<E>>,
    envelope: mpsc::Sender<Reply>,
    gossip: mpsc::Sender<Reply>,
}

/// The receiving side of the queues of the core, for [`ChainCore::spawn`].
pub struct CoreQueue<E: Preset> {
    import: mpsc::Receiver<ImportItem<E>>,
    envelope: mpsc::Receiver<Reply>,
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
    /// against the wall clock before the slot loop (see the module docs).
    pub fn import(
        &self,
        block: SignedBeaconBlock<E>,
    ) -> Result<oneshot::Receiver<Served>, SubmitError> {
        submit(&self.import, |reply| ImportItem {
            block: Box::new(block),
            reply,
        })
    }

    /// Queues an envelope item. Envelope import is not implemented: the answer is IGNORE.
    pub fn envelope(&self) -> Result<oneshot::Receiver<Served>, SubmitError> {
        submit(&self.envelope, |reply| reply)
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
    Envelope(Reply),
    Gossip(Reply),
}

impl<E: Preset> CoreQueue<E> {
    /// The next item: import first, then envelope, then gossip. `None` once each queue is
    /// closed and empty.
    async fn next(&mut self) -> Option<Item<E>> {
        tokio::select! {
            biased;
            Some(item) = self.import.recv() => Some(Item::Import(item)),
            Some(reply) = self.envelope.recv() => Some(Item::Envelope(reply)),
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
    /// The root of each block the core committed, and of the anchor (see the module docs).
    committed: HashSet<Root>,
    /// The kept refusals, by block root (see the module docs).
    refused: Refused<Outcome>,
    head: Head,
    verify_timeout: Duration,
    /// `None` until [`Self::with_payload_gate`]: no block commits without a gate.
    gate: Option<Box<dyn PayloadImportGate>>,
    clock: UnixClock,
    turns: u64,
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
            committed: HashSet::from([head.block_root]),
            refused: Refused::new(MAX_REFUSED_ROOTS),
            head,
            verify_timeout: DEFAULT_VERIFY_TIMEOUT,
            gate: None,
            clock: Arc::new(system_clock),
            turns: 0,
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

    /// The same core with `clock` (Unix milliseconds) as its wall clock, in place of the system
    /// clock.
    #[must_use]
    pub fn with_clock(mut self, clock: UnixClock) -> Self {
        self.clock = clock;
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

    /// The post-state of block `parent_root` advanced to the last slot of epoch `epoch - 1`, if
    /// the core keeps it.
    pub fn advanced_state(&self, parent_root: &Root, epoch: Epoch) -> Option<&BeaconState<E>> {
        // The core advances no state yet.
        let _ = (parent_root, epoch);
        None
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
                Item::Import(item) => (self.import(&item.block, verifier, runtime), item.reply),
                Item::Envelope(reply) => (Outcome::Ignored("no envelope import yet".into()), reply),
                Item::Gossip(reply) => (Outcome::Ignored("no gossip commit yet".into()), reply),
            };
            // A caller that stopped waiting has nothing to answer.
            let _ = reply.send(Served { turn, outcome });
        }
        self
    }

    /// Imports `block` and commits it only if it imports (see the module docs).
    fn import<V: BlsVerifier + 'static>(
        &mut self,
        block: &SignedBeaconBlock<E>,
        verifier: &Arc<V>,
        runtime: &Handle,
    ) -> Outcome {
        // In the context of the runtime, so that the deadline is on the clock of its timers. A
        // timeout past the range of `Instant` gives no time at all: no verdict is IGNORE.
        let deadline = {
            let _context = runtime.enter();
            let now = Instant::now();
            now.checked_add(self.verify_timeout).unwrap_or(now)
        };
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
        let Some(pre) = self.snapshots.peek(&parent) else {
            return Outcome::Ignored(format!("no pre-state for the parent {parent}"));
        };
        let window = PRE_STATE_EPOCHS * E::slots_per_epoch();
        if block.message.slot.saturating_sub(pre.slot) > window {
            let why = format!(
                "block slot {} is more than {window} slots after the parent state slot {}",
                block.message.slot, pre.slot
            );
            return self.refused.refuse(block_root, None, Outcome::Ignored(why));
        }
        // The slot loop can add a validator, but not an active one: its activation waits for
        // the finality of a later epoch than the one that added it, and the loop has no new
        // attestations to finalize that epoch. So an index past the registry of the parent is
        // never the proposer, and `process_block_header` refuses it after the slot loop.
        // Refused here, it costs no slot loop.
        let proposer = block.message.proposer_index;
        if !usize::try_from(proposer).is_ok_and(|index| index < pre.validators.len()) {
            let invalid = Outcome::Invalid(StfError::UnknownValidator(proposer));
            return self.refused.refuse(block_root, None, invalid);
        }
        let verdict = |sets: Vec<BlsSet>| verify(runtime, verifier, sets, deadline);
        // The gossip order: the signature of the proposer before the slot loop, so that a
        // block that its proposer did not sign costs one VerifyBls call and no slot loop.
        match check_proposer_signature(pre, block, &verdict) {
            Ok(()) => {}
            Err(NotImported::Invalid(e)) => {
                let signature = Some(block.signature);
                return self
                    .refused
                    .refuse(block_root, signature, Outcome::Invalid(e));
            }
            Err(NotImported::Ignored(why)) => return Outcome::Ignored(why),
        }
        match import_block(pre, block, &self.config, &verdict, gate) {
            Ok(imported) => {
                self.head = Head {
                    block_root: imported.block_root,
                    slot: block.message.slot,
                    state_root: imported.state_root,
                };
                self.snapshots.promote(&parent);
                self.snapshots.insert(imported.block_root, imported.post);
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

    /// `Err` (why, for the log) if `slot` is more than [`MAX_FUTURE_SLOTS`] ahead of the slot
    /// of the wall clock, or if the wall clock is before genesis.
    fn check_slot(&self, slot: Slot) -> Result<(), String> {
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
        Ok(())
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
