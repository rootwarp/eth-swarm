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
//! ([`DEFAULT_VERIFY_TIMEOUT`] if not set) from the start of the import. Then it runs
//! [`import_block`] on the pre-state of the parent of the block. The core sends the signature
//! sets to cl-verify through a [`BlsVerifier`], on the Tokio runtime of the caller, with the
//! deadline of the import: each VerifyBls call of one import gets the same deadline, and no
//! verdict by then is IGNORE. The core commits only on a VALID verdict and a
//! post-state root equal to `block.state_root`: it keeps the post-state as a pre-state, and the
//! block becomes the head. There is no fork choice yet, so the head is the last block the core
//! committed. On any other outcome the head and the pre-states do not change. The
//! [`PayloadImportGate`] of [`ChainCore::with_payload_gate`] ([`PermitAll`] if not set) can
//! refuse a block that would commit: that is IGNORE.
//!
//! Envelope import and gossip commit are queue kinds only: the core answers each such item
//! IGNORE and changes nothing.

use super::snapshot::{max_pre_states, Snapshots};
use crate::import::block::{import_block, NotImported, PayloadImportGate, PermitAll};
use crate::verify::client::{BlsOutcome, BlsVerifier};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{Root, Slot};
use ethswarm_proto::verify::BlsSet;
use network_config::ChainConfig;
use state_transition::{state_root, Preset, StfError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tree_hash::TreeHash;

/// The time a block import has for its VerifyBls verdicts, from the start of the import
/// \[est\]: well inside a slot, so a block that has no verdict by then is IGNOREd and can come
/// again.
pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(4);

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
    /// without one means the core stopped (IGNORE). Bound `block.slot` against the wall clock
    /// first: the slot loop of the transition costs one `process_slot` for each slot, and the
    /// core does not bound it.
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
    snapshots: Snapshots<BeaconState<E>>,
    head: Head,
    verify_timeout: Duration,
    gate: Box<dyn PayloadImportGate>,
    turns: u64,
}

impl<E: Preset> ChainCore<E> {
    /// A core on the anchor `state` and `block` of `config`'s network. The roots are computed
    /// again here: the state must have the root `block.state_root`. This is not the Bootstrap
    /// RPC; the caller checks where the anchor comes from.
    pub fn from_anchor(
        mut state: BeaconState<E>,
        block: SignedBeaconBlock<E>,
        config: ChainConfig,
    ) -> Result<Self, AnchorError> {
        config
            .capella_fork_version()
            .map_err(|e| AnchorError::Config(e.to_string()))?;
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
            snapshots: Snapshots::new(head.block_root, state, max_pre_states::<E>()),
            head,
            verify_timeout: DEFAULT_VERIFY_TIMEOUT,
            gate: Box::new(PermitAll),
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
        self.gate = Box::new(gate);
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
        let parent = block.message.parent_root;
        let Some(pre) = self.snapshots.get(&parent) else {
            return Outcome::Ignored(format!("no pre-state for the parent {parent}"));
        };
        let verdict = |sets: Vec<BlsSet>| verify(runtime, verifier, sets, deadline);
        match import_block(pre, block, &self.config, &verdict, self.gate.as_ref()) {
            Ok(imported) => {
                self.head = Head {
                    block_root: imported.block_root,
                    slot: block.message.slot,
                    state_root: imported.state_root,
                };
                self.snapshots.insert(imported.block_root, imported.post);
                Outcome::Committed {
                    block_root: imported.block_root,
                    state_root: imported.state_root,
                }
            }
            Err(NotImported::Invalid(e)) => Outcome::Invalid(e),
            Err(NotImported::Ignored(why)) => Outcome::Ignored(why),
        }
    }
}

/// The verdict of `verifier` on `sets`, or none by `deadline`. The call runs on `runtime`; the
/// core thread waits for it.
fn verify<V: BlsVerifier + 'static>(
    runtime: &Handle,
    verifier: &Arc<V>,
    sets: Vec<BlsSet>,
    deadline: Instant,
) -> BlsOutcome {
    let verifier = Arc::clone(verifier);
    let call = runtime.spawn(async move {
        // The deadline of the verifier, not a second timer: it stops only a verifier that does
        // not keep its deadline, so that a late VALID never commits. `BlsClient` closes its
        // stream when its call is dropped, so this cannot leave a request in its window.
        tokio::time::timeout_at(deadline, verifier.verify_sets(sets, deadline))
            .await
            .unwrap_or_else(|_| BlsOutcome::NoVerdict("no verdict by the deadline".into()))
    });
    runtime
        .block_on(call)
        .unwrap_or_else(|e| BlsOutcome::NoVerdict(format!("the VerifyBls call failed: {e}")))
}
