//! The reference node's canonical chain, as its event stream tells it ([`CanonicalChain`]), and
//! the prunes of the column store it drives ([`Prune`]).
//!
//! A range answer comes "from the single chain defined by the current head", and "blocks from
//! slots before the finalization MUST lead to the finalized block reported in the `Status`
//! handshake" (`fulu/p2p-interface.md`, `DataColumnSidecarsByRange v1`). The probe runs no fork
//! choice, so the chain is the reference's: [`track_chain`] keeps a bounded record of it from
//! the reference's `head`, `chain_reorg` and `finalized_checkpoint` events (`probe::head`), and
//! publishes it as a [`ChainView`] that the column server reads
//! ([`crate::reqresp::ColumnServer::following`]). The reference is trusted for block roots only
//! (`probe::ref_view`), and its stream is plain `http://`: no event alone removes a column.
//!
//! - **A new head** (`head`, or the `new_head_block` of a `chain_reorg`): the record is walked
//!   from the head back through the parent roots of the blocks the reference vouches for
//!   ([`RefView::lookup`]: header and block, decoded and hashed), until a block the record
//!   holds, a block at or below the finalized slot (the store's watermark when the tracker
//!   starts, so a restart walks no further down than the store needs), or [`MAX_CANON_WALK`]
//!   blocks. The walked blocks replace what the record held above the block it met; a walk
//!   that met nothing (at the finalized slot, or at its bound) replaces the whole record, which
//!   then starts at the lowest walked block. The chain is not known while a walk waits on a block the reference
//!   view has not cached, so the old head is not served meanwhile. A walk that fails (a lookup
//!   without an answer, a parent not below its child) keeps the record as it was, leaves the
//!   chain unknown, and runs again after [`CANON_RETRY`] or at the next head. Only with no
//!   record at all is the part walked kept as the record: there is nothing to keep. A head
//!   change prunes nothing: the blocks off the chain are left out of every answer, and a head
//!   that comes back finds its blocks still stored.
//! - **A new finalized checkpoint** (`finalized_checkpoint`): its epoch's start slot is the
//!   finalized slot, which only rises. It is taken only if its epoch is at least two epochs
//!   before the current epoch by the wall clock ([`crate::reqresp::ServeClock`]; FFG finalizes
//!   no later epoch), at most the epoch of the record's head, and if the record holds the
//!   checkpoint block as its last block at or before that slot. If the record starts after
//!   that slot, it is first walked down from its first block to reach it, at most
//!   [`MAX_CANON_WALK`] blocks, and the chain is unknown meanwhile, since heads wait for that
//!   walk: the next head publishes it again. Anything else prunes nothing. Taken, the column
//!   store removes the blocks at or below the finalized slot that are off the finalized chain
//!   ([`Finality`], `ColumnWriter::finalize`): the record places every block from its first
//!   slot on, and below it the store follows its own links down from the record's blocks to
//!   its watermark, so a record that starts above the watermark loses no canonical block, and
//!   a block it cannot place stays. The finalized chain's blocks stay, served from
//!   the store's watermark on without the record. The prune runs while heads are followed, and
//!   once the store is done, the record keeps the checkpoint block and its descendants.
//! - **Retention**: every column below the first slot of `data_column_serve_range` by the wall
//!   clock is pruned ([`Prune::retain_from`], `ColumnWriter::prune_before`), and the store's
//!   `earliest_available_slot` rises past it ([`super::earliest_servable_slot`]). A retention
//!   prune that failed is tried again after a pause that doubles up to
//!   [`MAX_RETENTION_BACKOFF`], and a checkpoint that is due goes first. Once the store's
//!   writer is gone ([`Pruned::Gone`]), the tracker ends and the chain is unknown.
//! - **The stream is down** (it ended, failed or went quiet): the chain is unknown until the next
//!   head, since the reference may have moved meanwhile. The record is kept, so the walk of
//!   that head usually meets it at once.
//!
//! [`ChainView::status`] says whether a block is on the chain, off it, or unknown: a slot below
//! the record's first block or above its head, or no record. The column server serves a block
//! above the store's finalized slot only while it is on the chain, and a range without one to
//! serve is `3: ResourceUnavailable`, never a possible orphan.
//!
//! Bounds: at most [`MAX_CANON_WALK`] lookups per head or checkpoint and [`MAX_CANON_BLOCKS`]
//! blocks in the record (the lowest go first). The event stream's own bounds are in
//! `probe::head`. Errors are logged without a URL or a value from the reference.

use super::{BlockApi, ReferenceApi};
use super::{Checkpoint, RefView, Root};
use crate::reqresp::ServeClock;
use consensus_types::primitives::Slot;
use consensus_types::EthSpec;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::watch;

/// Lookups one head or checkpoint may cost \[est\]: four mainnet epochs, past the two to three
/// epochs between the head and finality on a healthy chain. A deeper walk stops there, and the
/// record starts at its lowest block.
pub const MAX_CANON_WALK: usize = 128;

/// Blocks the record holds at most \[est\]: about 34 hours of mainnet slots without finality.
/// Past it the lowest blocks go first.
pub const MAX_CANON_BLOCKS: usize = 8192;

/// How long after a failed walk the head is walked again \[est\]: a twelfth of a mainnet slot,
/// so a reference that answers again is followed well before its next head.
pub const CANON_RETRY: Duration = Duration::from_secs(1);

/// Whether a block is on the reference's canonical chain, as a [`ChainView`] knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canonical {
    /// On the chain.
    Yes,
    /// Off it: an orphan.
    No,
    /// Not known: below the first block of the view, above its head, or no view.
    Unknown,
}

/// The reference's canonical chain from its first block to its head (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainView {
    floor: Slot,
    head: Slot,
    roots: HashMap<Root, Slot>,
}

impl ChainView {
    /// The chain of `blocks`, `(slot, root)` each, from the lowest slot to the highest: every
    /// other block in between is off it. `None` without a block.
    pub fn new(blocks: impl IntoIterator<Item = (Slot, Root)>) -> Option<Self> {
        let roots: HashMap<Root, Slot> = blocks
            .into_iter()
            .map(|(slot, root)| (root, slot))
            .collect();
        let floor = roots.values().copied().min()?;
        let head = roots.values().copied().max()?;
        Some(Self { floor, head, roots })
    }

    /// The slot of its first block.
    #[must_use]
    pub fn floor(&self) -> Slot {
        self.floor
    }

    /// The slot of its head.
    #[must_use]
    pub fn head_slot(&self) -> Slot {
        self.head
    }

    /// Its blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether it has no block (never: [`Self::new`] needs one).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Whether the block `root` at `slot` is on the chain.
    #[must_use]
    pub fn status(&self, slot: Slot, root: &Root) -> Canonical {
        if self.roots.get(root) == Some(&slot) {
            Canonical::Yes
        } else if (self.floor..=self.head).contains(&slot) {
            Canonical::No
        } else {
            Canonical::Unknown
        }
    }
}

/// The [`ChainView`] the follower publishes and the column server reads; `None` while the
/// chain is unknown, as it is from [`Self::default`] on.
#[derive(Debug, Default)]
pub struct CanonicalChain {
    view: Mutex<Published>,
}

/// What [`CanonicalChain`] holds.
#[derive(Debug, Default)]
struct Published {
    view: Option<Arc<ChainView>>,
    /// The first slot of the last view published, kept while the chain is unknown.
    known_from: Option<Slot>,
}

impl CanonicalChain {
    /// A chain that stays `view` unless [`Self::set`] changes it: for a store whose chain is
    /// known some other way.
    #[must_use]
    pub fn fixed(view: ChainView) -> Self {
        let chain = Self::default();
        chain.set(Some(view));
        chain
    }

    /// The view now; `None` while the chain is unknown.
    #[must_use]
    pub fn view(&self) -> Option<Arc<ChainView>> {
        self.lock().view.clone()
    }

    /// The first slot of the view now, or of the last one published while the chain is
    /// unknown; `None` before the first view. A block between the store's finalized slot and
    /// this slot has no known place, now or once the chain is known again.
    #[must_use]
    pub fn known_from(&self) -> Option<Slot> {
        self.lock().known_from
    }

    /// Publishes `view`; `None` makes the chain unknown.
    pub fn set(&self, view: Option<ChainView>) {
        let mut published = self.lock();
        if let Some(view) = &view {
            published.known_from = Some(view.floor());
        }
        published.view = view.map(Arc::new);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Published> {
        self.view.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the column store prunes for the reference's chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prune {
    /// The finalized chain to keep (`ColumnWriter::finalize`).
    pub finalized: Option<Finality>,
    /// Every column below this slot, out of the retention window (`ColumnWriter::prune_before`).
    pub retain_from: Option<Slot>,
}

/// A finalized checkpoint the record holds, as the column store finalizes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finality {
    /// The start slot of the finalized epoch.
    pub slot: Slot,
    /// The record's blocks, the checkpoint block among them: the finalized chain up to `slot`,
    /// and its descendants. The store follows its own links down from them to its watermark
    /// (`ColumnWriter::finalize`).
    pub canonical: Vec<Root>,
    /// The record's first slot: from it on, a stored block not in `canonical` is off the chain.
    pub known_from: Slot,
}

impl Prune {
    /// Whether there is nothing to prune.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.finalized.is_none() && self.retain_from.is_none()
    }
}

/// How a prune ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pruned {
    /// Every part of it is done.
    Done,
    /// A part failed: it is tried again later.
    Failed,
    /// The store's writer is gone: nothing is pruned any more.
    Gone,
}

/// Where the follower's prunes go: the column store's writer
/// ([`super::ColumnIngest::follow_head`]), or nowhere (`()`).
pub trait PruneSink: Send + Sync {
    /// Prunes `prune`, or hands it to the one who does, and says how it ended.
    fn prune(&self, prune: Prune) -> impl Future<Output = Pruned> + Send;
}

impl PruneSink for () {
    async fn prune(&self, _: Prune) -> Pruned {
        Pruned::Done
    }
}

/// How a walk of a head ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Walk {
    /// The chain is published.
    Done,
    /// It failed: the chain is unknown, and the head is to be walked again.
    Retry,
}

/// The reference's chain as the follower last saw it, and its record (see the module docs).
pub(super) struct Tracker<A, E> {
    refs: Arc<RefView<A, E>>,
    chain: Arc<CanonicalChain>,
    clock: Arc<dyn ServeClock>,
    /// The record: the chain's blocks by slot, from its first block to its head.
    by_slot: BTreeMap<Slot, Root>,
    /// `by_slot` the other way round.
    slots: HashMap<Root, Slot>,
    /// The start slot of the finalized epoch the column store finalized.
    finalized: Option<Slot>,
    /// The slot the column store keeps columns from.
    retained: Option<Slot>,
    /// Set while a checkpoint's walk left the chain unknown: whether a view was published
    /// before it.
    hidden: Option<bool>,
}

/// How a walk down from a head stopped.
enum End {
    /// At a block of the record, at this slot.
    Met(Slot),
    /// At the finalized slot, or at [`MAX_CANON_WALK`].
    Bound,
    /// Without an answer, or at a parent not below its child.
    Failed,
}

impl<A, E> Tracker<A, E>
where
    A: ReferenceApi + BlockApi,
    E: EthSpec,
{
    /// A tracker with no record yet, of a column store finalized at `finalized` (its
    /// watermark), so the first walk stops there.
    pub(super) fn new(
        refs: Arc<RefView<A, E>>,
        chain: Arc<CanonicalChain>,
        clock: Arc<dyn ServeClock>,
        finalized: Option<Slot>,
    ) -> Self {
        Self {
            refs,
            chain,
            clock,
            by_slot: BTreeMap::new(),
            slots: HashMap::new(),
            finalized,
            retained: None,
            hidden: None,
        }
    }

    /// The stream is down: the chain is unknown until the next head.
    pub(super) fn down(&self) {
        self.chain.set(None);
    }

    /// The reference's head is now `head`: walks to the record and publishes the chain (see the
    /// module docs).
    pub(super) async fn on_head(&mut self, head: Root) -> Walk {
        let mut walked: Vec<(Slot, Root)> = Vec::new();
        let mut next = head;
        let mut hidden = false;
        let end = loop {
            if let Some(&slot) = self.slots.get(&next) {
                break End::Met(slot);
            }
            if walked.len() >= MAX_CANON_WALK {
                break End::Bound;
            }
            // A lookup may take the whole lookup timeout: the old head is not served meanwhile.
            if !hidden && self.refs.cached_block(&next).is_none() {
                self.chain.set(None);
                hidden = true;
            }
            let block = match self.refs.lookup(next).await {
                Ok(block) => block,
                Err(e) => {
                    tracing::debug!(error = %e, "the reference's chain: a block not looked up");
                    break End::Failed;
                }
            };
            if walked.last().is_some_and(|&(child, _)| block.slot >= child) {
                tracing::warn!("the reference's chain: a parent is not below its child");
                break End::Failed;
            }
            walked.push((block.slot, next));
            if self.finalized.is_some_and(|f| block.slot <= f) {
                break End::Bound;
            }
            next = block.parent_root;
        };
        let lowest = walked.last().map(|&(slot, _)| slot);
        let end = match end {
            End::Met(met) if lowest.is_some_and(|lowest| met >= lowest) => {
                tracing::warn!("the reference's chain: the walk met its record above itself");
                End::Failed
            }
            // With no record there is nothing to keep: the part walked is the record.
            End::Failed if self.by_slot.is_empty() && !walked.is_empty() => End::Bound,
            end => end,
        };
        match end {
            End::Failed => {
                self.chain.set(None);
                return Walk::Retry;
            }
            End::Met(met) => {
                let above = self.by_slot.split_off(&met.saturating_add(1));
                for root in above.values() {
                    self.slots.remove(root);
                }
            }
            End::Bound => {
                self.by_slot.clear();
                self.slots.clear();
            }
        }
        for (slot, root) in walked {
            self.by_slot.insert(slot, root);
            self.slots.insert(root, slot);
        }
        while self.by_slot.len() > MAX_CANON_BLOCKS {
            if let Some((_, root)) = self.by_slot.pop_first() {
                self.slots.remove(&root);
            }
        }
        self.publish();
        Walk::Done
    }

    /// The reference finalized `checkpoint`: the prune that finalizes the column store, the
    /// finalized slot and the checkpoint block's slot, if the checkpoint is taken (see the
    /// module docs); else `None`, and nothing is pruned.
    pub(super) async fn on_finalized(
        &mut self,
        checkpoint: Checkpoint,
    ) -> Option<(Prune, Slot, Slot)> {
        let spe = E::slots_per_epoch().max(1);
        let slot = checkpoint.epoch.checked_mul(spe)?;
        if self.finalized.is_some_and(|f| slot <= f) {
            return None;
        }
        // FFG finalizes an epoch two epochs after it at the earliest.
        let current = self.clock.serve_range().map(|(_, last)| last / spe);
        if current.is_none_or(|current| checkpoint.epoch.saturating_add(2) > current) {
            tracing::warn!(
                "the reference's finalized checkpoint is not two epochs behind the wall clock: \
                 not taken"
            );
            return None;
        }
        let (&head, _) = self.by_slot.last_key_value()?;
        if checkpoint.epoch > head / spe.max(1) {
            tracing::warn!("the reference's finalized checkpoint is past its head: not taken");
            return None;
        }
        let block = match self.by_slot.range(..=slot).next_back() {
            Some((&block, root)) if *root == checkpoint.root => block,
            Some(_) => {
                tracing::warn!("the reference's finalized checkpoint is off its chain: not taken");
                return None;
            }
            None => {
                // The walk down may wait on lookups, and heads wait meanwhile: the chain is
                // unknown until a view is computed again (`track_chain`).
                self.hidden = Some(self.chain.view().is_some());
                self.chain.set(None);
                self.extend_to(checkpoint.root, slot).await?
            }
        };
        let canonical = self.by_slot.values().copied().collect();
        let (&known_from, _) = self.by_slot.first_key_value()?;
        let prune = Prune {
            finalized: Some(Finality {
                slot,
                canonical,
                known_from,
            }),
            retain_from: None,
        };
        Some((prune, slot, block))
    }

    /// Walks the record down from its first block to `root`, the last block at or before
    /// `slot`; its slot once the record holds it. `None` if the walk meets another block at or
    /// before `slot`, fails or passes [`MAX_CANON_WALK`].
    async fn extend_to(&mut self, root: Root, slot: Slot) -> Option<Slot> {
        let (&floor, &first) = self.by_slot.first_key_value()?;
        let mut next = self.refs.lookup(first).await.ok()?.parent_root;
        let mut child = floor;
        let mut walked = Vec::new();
        for _ in 0..MAX_CANON_WALK {
            let block = self.refs.lookup(next).await.ok()?;
            if block.slot >= child {
                return None;
            }
            walked.push((block.slot, next));
            if block.slot <= slot {
                if next != root {
                    tracing::warn!("the reference's finalized checkpoint is off its chain");
                    return None;
                }
                for (slot, root) in walked {
                    self.by_slot.insert(slot, root);
                    self.slots.insert(root, slot);
                }
                return Some(block.slot);
            }
            child = block.slot;
            next = block.parent_root;
        }
        None
    }

    /// The column store finalized `slot`, the checkpoint block at `block`: the record keeps
    /// that block and its descendants, published only now, so no block below it was unknown
    /// while the store still held it unfinalized.
    pub(super) fn finalized_applied(&mut self, slot: Slot, block: Slot) {
        self.finalized = Some(slot);
        let kept = self.by_slot.split_off(&block);
        for root in self.by_slot.values() {
            self.slots.remove(root);
        }
        self.by_slot = kept;
        if self.chain.view().is_some() {
            self.publish();
        }
    }

    /// Whether a checkpoint's walk left the chain unknown that was published before it; clears
    /// the mark.
    pub(super) fn take_hidden(&mut self) -> bool {
        self.hidden.take().unwrap_or(false)
    }

    /// Publishes the record again, after a checkpoint's walk that no new head followed.
    pub(super) fn republish(&self) {
        self.publish();
    }

    /// The first slot of `data_column_serve_range` by the wall clock, once it is past the slot
    /// the column store keeps columns from.
    pub(super) fn retention_due(&self) -> Option<Slot> {
        let (first, _) = self.clock.serve_range()?;
        (first > 0 && self.retained.is_none_or(|kept| first > kept)).then_some(first)
    }

    /// The column store keeps columns from `slot` now.
    pub(super) fn retention_applied(&mut self, slot: Slot) {
        self.retained = Some(slot);
    }

    fn publish(&self) {
        let view = ChainView::new(self.by_slot.iter().map(|(&slot, &root)| (slot, root)));
        self.chain.set(view);
    }
}

/// What the event reader tells [`track_chain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChainEvent {
    /// The stream is down.
    Down,
    /// The reference's head is now this root.
    Head(Root),
}

/// What the record does once a prune is done.
enum Done {
    /// The store finalized this slot, the checkpoint block at the second.
    Finality(Slot, Slot),
    /// The store keeps columns from this slot.
    Retention(Slot),
}

/// A prune in flight.
type InFlight<'a> = Pin<Box<dyn Future<Output = Pruned> + Send + 'a>>;

/// The longest pause before a failed retention prune is tried again \[est\]: a minute, so a
/// store that keeps failing costs a prune and a warning a minute.
pub const MAX_RETENTION_BACKOFF: Duration = Duration::from_secs(60);

/// Waits for `prune`, if there is one.
async fn finished(prune: &mut Option<InFlight<'_>>) -> Pruned {
    match prune {
        Some(prune) => prune.await,
        None => std::future::pending().await,
    }
}

/// Waits until `at`, if it is set.
async fn until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Keeps `tracker` on the reference's chain from the latest `heads` and `finalized` (the
/// reader sends them), walks a failed head again [`CANON_RETRY`] after it failed, and hands
/// each prune to `prunes`, until both senders are gone, or until the store's writer is (the
/// chain is unknown then). A prune runs while heads are followed: the record changes for it
/// only once the store is done. One prune runs at a time; a checkpoint waits for its turn, and
/// goes before a retention prune. A retention prune that failed is tried again after
/// [`CANON_RETRY`], doubled after each failure in a row up to [`MAX_RETENTION_BACKOFF`].
pub(super) async fn track_chain<A, E, P>(
    mut tracker: Tracker<A, E>,
    mut heads: watch::Receiver<Option<ChainEvent>>,
    mut finalized: watch::Receiver<Option<Checkpoint>>,
    prunes: P,
) where
    A: ReferenceApi + BlockApi,
    E: EthSpec,
    P: PruneSink,
{
    let (mut heads_open, mut finalized_open) = (true, true);
    // The head to walk again, and when.
    let mut retry: Option<(Root, tokio::time::Instant)> = None;
    let mut prune: Option<InFlight<'_>> = None;
    let mut then: Option<Done> = None;
    // No retention prune before this, and the pause after the next failure.
    let mut retention_at: Option<tokio::time::Instant> = None;
    let mut backoff = CANON_RETRY;
    let walk_again = |root, walk| {
        (walk == Walk::Retry).then(|| (root, tokio::time::Instant::now() + CANON_RETRY))
    };
    while heads_open || finalized_open || prune.is_some() {
        tokio::select! {
            done = finished(&mut prune), if prune.is_some() => {
                prune = None;
                match (then.take(), done) {
                    (_, Pruned::Gone) => {
                        tracing::warn!("the column store's writer is gone: the chain is not followed");
                        tracker.down();
                        return;
                    }
                    (Some(Done::Finality(slot, block)), Pruned::Done) => {
                        tracker.finalized_applied(slot, block);
                    }
                    (Some(Done::Retention(slot)), Pruned::Done) => {
                        tracker.retention_applied(slot);
                        (retention_at, backoff) = (None, CANON_RETRY);
                    }
                    (Some(Done::Retention(_)), Pruned::Failed) => {
                        retention_at = Some(tokio::time::Instant::now() + backoff);
                        backoff = backoff.saturating_mul(2).min(MAX_RETENTION_BACKOFF);
                    }
                    (Some(Done::Finality(..)) | None, Pruned::Failed) | (None, Pruned::Done) => {}
                }
            }
            changed = finalized.changed(), if finalized_open && prune.is_none() => {
                if changed.is_err() {
                    finalized_open = false;
                    continue;
                }
                let checkpoint = *finalized.borrow_and_update();
                if let Some(checkpoint) = checkpoint {
                    if let Some((next, slot, block)) = tracker.on_finalized(checkpoint).await {
                        prune = Some(Box::pin(prunes.prune(next)));
                        then = Some(Done::Finality(slot, block));
                    }
                    // A head that came during the walk is walked next, and publishes then.
                    if tracker.take_hidden() && !heads.has_changed().unwrap_or(true) {
                        tracker.republish();
                    }
                }
            }
            changed = heads.changed(), if heads_open => {
                if changed.is_err() {
                    heads_open = false;
                    continue;
                }
                let event = *heads.borrow_and_update();
                match event {
                    Some(ChainEvent::Head(root)) => {
                        retry = walk_again(root, tracker.on_head(root).await);
                    }
                    Some(ChainEvent::Down) => {
                        tracker.down();
                        retry = None;
                    }
                    None => {}
                }
            }
            () = until(retry.map(|(_, at)| at)), if retry.is_some() => {
                if let Some((root, _)) = retry {
                    retry = walk_again(root, tracker.on_head(root).await);
                }
            }
            () = until(retention_at), if retention_at.is_some() && prune.is_none() => {
                retention_at = None;
            }
        }
        // Retention waits for a checkpoint that is due, and for its pause after a failure; it
        // ends with the senders.
        let checkpoint_due = finalized_open && finalized.has_changed().unwrap_or(false);
        let paused = retention_at.is_some_and(|at| tokio::time::Instant::now() < at);
        if prune.is_none() && !checkpoint_due && !paused && (heads_open || finalized_open) {
            if let Some(slot) = tracker.retention_due() {
                let next = Prune {
                    finalized: None,
                    retain_from: Some(slot),
                };
                prune = Some(Box::pin(prunes.prune(next)));
                then = Some(Done::Retention(slot));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake::{Clock, Silent};
    use super::super::RefLimits;
    use super::*;
    use crate::testing::{gloas_block_on, schedule, Spec};
    use tokio::sync::Semaphore;

    type View = RefView<Arc<Silent>, Spec>;

    fn tracker(
        reference: &Arc<Silent>,
        clock: &Arc<Clock>,
    ) -> (Tracker<Arc<Silent>, Spec>, Arc<CanonicalChain>) {
        let refs = Arc::new(View::new(
            Arc::clone(reference),
            schedule(),
            RefLimits::default(),
        ));
        let chain = Arc::new(CanonicalChain::default());
        let clock = Arc::clone(clock) as Arc<dyn ServeClock>;
        (Tracker::new(refs, Arc::clone(&chain), clock, None), chain)
    }

    fn status(chain: &CanonicalChain, slot: Slot, root: &Root) -> Canonical {
        chain
            .view()
            .map_or(Canonical::Unknown, |view| view.status(slot, root))
    }

    /// A block at `slot` on `parent` that `reference` does not serve yet: its root, and how to
    /// serve it.
    fn later(slot: Slot, parent: Root) -> (Root, impl FnOnce(&Silent)) {
        let (_, ssz, root) = gloas_block_on(slot, &[[1; 48]], parent);
        let serve = move |reference: &Silent| {
            reference.blocks.lock().unwrap().insert(root, (slot, ssz));
        };
        (root, serve)
    }

    #[test]
    fn a_view_knows_its_blocks_and_nothing_past_its_ends() {
        assert_eq!(ChainView::new(std::iter::empty()), None);
        let view = ChainView::new([(12, [12; 32]), (10, [10; 32])]).unwrap();
        assert_eq!((view.floor(), view.head_slot(), view.len()), (10, 12, 2));
        assert!(!view.is_empty());
        assert_eq!(view.status(10, &[10; 32]), Canonical::Yes);
        // Another block between the ends is off the chain, and so is a known root at
        // another slot.
        assert_eq!(view.status(11, &[11; 32]), Canonical::No);
        assert_eq!(view.status(11, &[10; 32]), Canonical::No);
        // Past the ends nothing is known.
        assert_eq!(view.status(9, &[9; 32]), Canonical::Unknown);
        assert_eq!(view.status(13, &[13; 32]), Canonical::Unknown);
        let chain = CanonicalChain::fixed(view.clone());
        assert_eq!(chain.view().as_deref(), Some(&view));
        chain.set(None);
        assert_eq!(chain.view(), None);
        assert_eq!(CanonicalChain::default().view(), None);
    }

    /// A re-org leaves the old branch off the chain, and a head that comes back puts it on the
    /// chain again: a head change prunes nothing.
    #[tokio::test(start_paused = true)]
    async fn a_head_is_walked_to_the_record_and_a_head_that_comes_back_is_on_it_again() {
        let reference = Arc::new(Silent::default());
        let b10 = reference.serve(10);
        let b11 = reference.serve_on(11, b10);
        let b12 = reference.serve_on(12, b10);
        let b13 = reference.serve_on(13, b11);
        let (mut tracker, chain) = tracker(&reference, &Arc::default());
        // b10's parent is not known: with no record, the part walked is the record.
        assert_eq!(tracker.on_head(b11).await, Walk::Done);
        assert_eq!(status(&chain, 10, &b10), Canonical::Yes);
        assert_eq!(status(&chain, 11, &b11), Canonical::Yes);
        assert_eq!(status(&chain, 9, &[9; 32]), Canonical::Unknown);
        // b12 builds on b10: b11 is off the chain; only b12's lookup is new.
        assert_eq!(tracker.on_head(b12).await, Walk::Done);
        assert_eq!(status(&chain, 11, &b11), Canonical::No);
        assert_eq!(status(&chain, 12, &b12), Canonical::Yes);
        // Back to b11, then on to its child b13.
        assert_eq!(tracker.on_head(b11).await, Walk::Done);
        assert_eq!(status(&chain, 11, &b11), Canonical::Yes);
        assert_eq!(status(&chain, 12, &b12), Canonical::Unknown);
        assert_eq!(tracker.on_head(b13).await, Walk::Done);
        assert_eq!(status(&chain, 12, &b12), Canonical::No);
        assert_eq!(status(&chain, 13, &b13), Canonical::Yes);
        assert_eq!(chain.view().unwrap().floor(), 10);
    }

    /// A walk that fails keeps the record: the chain is unknown until a walk succeeds, and its
    /// first block stays where it was.
    #[tokio::test(start_paused = true)]
    async fn a_failed_walk_keeps_the_record_and_leaves_the_chain_unknown() {
        let reference = Arc::new(Silent::default());
        let b10 = reference.serve(10);
        let b11 = reference.serve_on(11, b10);
        let (mut tracker, chain) = tracker(&reference, &Arc::default());
        tracker.on_head(b11).await;
        // A head whose parent the reference does not know (its lookup times out).
        let b12 = reference.serve_on(12, [0x77; 32]);
        assert_eq!(tracker.on_head(b12).await, Walk::Retry);
        assert_eq!(chain.view(), None);
        // A head the reference does not vouch for at all.
        assert_eq!(tracker.on_head([0x66; 32]).await, Walk::Retry);
        assert_eq!(chain.view(), None);
        // The next head meets the record kept meanwhile, its first block where it was.
        let b13 = reference.serve_on(13, b11);
        assert_eq!(tracker.on_head(b13).await, Walk::Done);
        let view = chain.view().unwrap();
        assert_eq!((view.floor(), view.head_slot()), (10, 13));
        assert_eq!(view.status(12, &b12), Canonical::No);
        tracker.down();
        assert_eq!(chain.view(), None);
    }

    /// While a walk waits on a block the reference view has not cached, the chain is unknown:
    /// the old head is never served after a re-org that the walk has not followed yet.
    #[tokio::test(start_paused = true)]
    async fn a_walk_that_waits_on_a_lookup_leaves_the_chain_unknown_meanwhile() {
        let reference = Arc::new(Silent::default());
        let b10 = reference.serve(10);
        let b11 = reference.serve_on(11, b10);
        let (mut tracker, chain) = tracker(&reference, &Arc::default());
        tracker.on_head(b11).await;
        let (b12, serve_b12) = later(12, b10);
        let watch = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(chain.view(), None, "the old head is not served");
        };
        let (walk, ()) = tokio::join!(tracker.on_head(b12), watch);
        assert_eq!(walk, Walk::Retry, "b12's lookup timed out");
        serve_b12(&reference);
        assert_eq!(tracker.on_head(b12).await, Walk::Done);
        assert_eq!(status(&chain, 11, &b11), Canonical::No);
        // A walk on cached blocks only keeps the view published throughout.
        assert_eq!(tracker.on_head(b11).await, Walk::Done);
        assert_eq!(status(&chain, 11, &b11), Canonical::Yes);
    }

    /// A checkpoint is taken only within the wall clock, at most the epoch of the record's
    /// head, and only if the record holds it: anything else prunes nothing.
    #[tokio::test(start_paused = true)]
    async fn a_finalized_checkpoint_is_taken_only_within_the_clock_and_on_the_record() {
        // Blocks from epoch 2 on: the fixture's Gloas starts at epoch 1. The wall clock is in
        // epoch 4.
        let spe = Spec::slots_per_epoch();
        let clock = Arc::new(Clock::at(0, 5 * spe - 1));
        let reference = Arc::new(Silent::default());
        let b15 = reference.serve(2 * spe - 1);
        let b16 = reference.serve_on(2 * spe, b15);
        let b17 = reference.serve_on(2 * spe + 1, b16);
        let (mut tracker, chain) = tracker(&reference, &clock);
        // No record yet: nothing to take it on.
        let at = |epoch, root| Checkpoint { epoch, root };
        assert_eq!(tracker.on_finalized(at(2, b16)).await, None);
        tracker.on_head(b17).await;
        for (epoch, root, why) in [
            (u64::MAX, b16, "an epoch whose slot overflows"),
            (1000, b16, "past the wall clock"),
            (3, b17, "not two epochs behind the wall clock"),
            (2, [0x55; 32], "a root off the record"),
        ] {
            assert_eq!(tracker.on_finalized(at(epoch, root)).await, None, "{why}");
        }
        // Two epochs behind a later wall clock, but past the record's head.
        clock.set(Some((0, 11 * spe - 1)));
        assert_eq!(tracker.on_finalized(at(3, b17)).await, None);
        // In epoch 3 of the wall clock, epoch 2 is not two epochs behind yet.
        clock.set(Some((0, 4 * spe - 1)));
        assert_eq!(tracker.on_finalized(at(2, b16)).await, None);
        clock.set(Some((0, 5 * spe - 1)));
        let (prune, slot, block) = tracker.on_finalized(at(2, b16)).await.unwrap();
        assert_eq!((slot, block), (2 * spe, 2 * spe));
        assert_eq!(
            prune,
            Prune {
                finalized: Some(Finality {
                    slot: 2 * spe,
                    canonical: vec![b15, b16, b17],
                    known_from: 2 * spe - 1,
                }),
                retain_from: None,
            }
        );
        // Nothing moves until the store is done.
        assert_eq!(chain.view().unwrap().floor(), 2 * spe - 1);
        tracker.finalized_applied(slot, block);
        assert_eq!(chain.view().unwrap().floor(), 2 * spe);
        assert_eq!(status(&chain, 2 * spe - 1, &b15), Canonical::Unknown);
        // Finality never goes back.
        assert_eq!(tracker.on_finalized(at(2, b16)).await, None);
    }

    /// A record whose first block is past the checkpoint is walked down to it.
    #[tokio::test(start_paused = true)]
    async fn the_record_is_walked_down_to_a_checkpoint_before_it() {
        let spe = Spec::slots_per_epoch();
        let clock = Arc::new(Clock::at(0, 5 * spe - 1));
        let reference = Arc::new(Silent::default());
        let b15 = reference.serve(2 * spe - 1);
        let (b16, serve_b16) = later(2 * spe, b15);
        let b17 = reference.serve_on(2 * spe + 1, b16);
        let b18 = reference.serve_on(2 * spe + 2, b17);
        let (mut tracker, chain) = tracker(&reference, &clock);
        // b16 is not served yet: the first walk keeps b17 and b18.
        tracker.on_head(b18).await;
        assert_eq!(chain.view().unwrap().floor(), 2 * spe + 1);
        serve_b16(&reference);
        let checkpoint = Checkpoint {
            epoch: 2,
            root: b16,
        };
        let (prune, _, block) = tracker.on_finalized(checkpoint).await.unwrap();
        assert_eq!(block, 2 * spe);
        let finality = prune.finalized.unwrap();
        assert_eq!(finality.canonical, vec![b16, b17, b18]);
        // The walk down left the chain unknown, until a view is computed again.
        assert!(tracker.take_hidden());
        assert_eq!(chain.view(), None);
        tracker.republish();
        assert_eq!(status(&chain, 2 * spe, &b16), Canonical::Yes);
    }

    /// A re-org that comes while a checkpoint's walk down waits on a lookup is never answered
    /// with the old head: the chain is unknown from the walk's start until the re-org is
    /// walked.
    #[tokio::test(start_paused = true)]
    async fn a_reorg_during_a_checkpoint_walk_never_serves_the_old_head() {
        let spe = Spec::slots_per_epoch();
        let clock = Arc::new(Clock::at(0, 5 * spe - 1));
        let reference = Arc::new(Silent::default());
        let b15 = reference.serve(2 * spe - 1);
        let (b16, _) = later(2 * spe, b15);
        let b17 = reference.serve_on(2 * spe + 1, b16);
        let b18 = reference.serve_on(2 * spe + 2, b17);
        let c18 = reference.serve_fork(2 * spe + 2, b17);
        let (tracker, chain) = tracker(&reference, &clock);
        let (heads, heads_seen) = watch::channel(None);
        let (finalized, finalized_seen) = watch::channel(None);
        let task = tokio::spawn(track_chain(tracker, heads_seen, finalized_seen, ()));
        // b16 is never served: the first walk keeps b17 and b18, and the walk down to the
        // checkpoint waits out b16's lookup.
        heads.send_replace(Some(ChainEvent::Head(b18)));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(status(&chain, 2 * spe + 2, &b18), Canonical::Yes);
        finalized.send_replace(Some(Checkpoint {
            epoch: 2,
            root: b16,
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        heads.send_replace(Some(ChainEvent::Head(c18)));
        for _ in 0..30 {
            assert_ne!(
                status(&chain, 2 * spe + 2, &b18),
                Canonical::Yes,
                "the old head after the re-org"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(status(&chain, 2 * spe + 2, &c18), Canonical::Yes);
        assert_eq!(status(&chain, 2 * spe + 2, &b18), Canonical::No);
        task.abort();
    }

    /// A tracker of a store finalized at slot 16 stops its first walk there, though the
    /// reference knows the blocks before it.
    #[tokio::test(start_paused = true)]
    async fn a_tracker_of_a_finalized_store_stops_its_first_walk_at_the_watermark() {
        let reference = Arc::new(Silent::default());
        let b14 = reference.serve(14);
        let b15 = reference.serve_on(15, b14);
        let b16 = reference.serve_on(16, b15);
        let b17 = reference.serve_on(17, b16);
        let refs = Arc::new(View::new(
            Arc::clone(&reference),
            schedule(),
            RefLimits::default(),
        ));
        let chain = Arc::new(CanonicalChain::default());
        let clock = Arc::new(Clock::default()) as Arc<dyn ServeClock>;
        let mut tracker = Tracker::new(refs, Arc::clone(&chain), clock, Some(16));
        assert_eq!(tracker.on_head(b17).await, Walk::Done);
        assert_eq!(chain.view().unwrap().floor(), 16);
        assert_eq!(reference.asked(b15), 0, "never walked past the watermark");
    }

    /// The prunes of one checkpoint, held until the test lets them go.
    struct Held {
        seen: Mutex<Vec<Prune>>,
        go: Semaphore,
    }

    impl Default for Held {
        fn default() -> Self {
            Self {
                seen: Mutex::default(),
                go: Semaphore::new(0),
            }
        }
    }

    impl PruneSink for Arc<Held> {
        async fn prune(&self, prune: Prune) -> Pruned {
            let finality = prune.finalized.is_some();
            self.seen.lock().unwrap().push(prune);
            if finality {
                self.go.acquire().await.unwrap().forget();
            }
            Pruned::Done
        }
    }

    /// The record is trimmed to the checkpoint block only once the store finalized: until then
    /// the blocks below it are still on the chain, not unknown.
    #[tokio::test(start_paused = true)]
    async fn the_finality_trim_is_published_after_the_prune() {
        let spe = Spec::slots_per_epoch();
        let clock = Arc::new(Clock::at(0, 5 * spe - 1));
        let reference = Arc::new(Silent::default());
        let b15 = reference.serve(2 * spe - 1);
        let b16 = reference.serve_on(2 * spe, b15);
        let b17 = reference.serve_on(2 * spe + 1, b16);
        let c17 = reference.serve_fork(2 * spe + 1, b16);
        let (tracker, chain) = tracker(&reference, &clock);
        let (heads, heads_seen) = watch::channel(None);
        let (finalized, finalized_seen) = watch::channel(None);
        let held = Arc::new(Held::default());
        let task = tokio::spawn(track_chain(
            tracker,
            heads_seen,
            finalized_seen,
            Arc::clone(&held),
        ));
        heads.send_replace(Some(ChainEvent::Head(b17)));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(status(&chain, 2 * spe - 1, &b15), Canonical::Yes);
        finalized.send_replace(Some(Checkpoint {
            epoch: 2,
            root: b16,
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            held.seen.lock().unwrap().len(),
            1,
            "the prune is with the store"
        );
        assert_eq!(status(&chain, 2 * spe - 1, &b15), Canonical::Yes);
        // Heads are followed while the store prunes: a re-org to c17 is walked at once.
        heads.send_replace(Some(ChainEvent::Head(c17)));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(status(&chain, 2 * spe + 1, &b17), Canonical::No);
        assert_eq!(status(&chain, 2 * spe + 1, &c17), Canonical::Yes);
        held.go.add_permits(1);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(status(&chain, 2 * spe - 1, &b15), Canonical::Unknown);
        assert_eq!(chain.view().unwrap().floor(), 2 * spe);
        assert_eq!(status(&chain, 2 * spe + 1, &c17), Canonical::Yes);
        task.abort();
    }

    /// A failed walk is walked again after the retry interval, without a new head.
    #[tokio::test(start_paused = true)]
    async fn a_failed_walk_is_walked_again() {
        let reference = Arc::new(Silent::default());
        let b10 = reference.serve(10);
        let (b11, serve_b11) = later(11, b10);
        let (tracker, chain) = tracker(&reference, &Arc::default());
        let (heads, heads_seen) = watch::channel(None);
        let (_finalized, finalized_seen) = watch::channel(None);
        let task = tokio::spawn(track_chain(tracker, heads_seen, finalized_seen, ()));
        heads.send_replace(Some(ChainEvent::Head(b11)));
        // b11's lookup times out after 2 s: unknown.
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert_eq!(chain.view(), None);
        serve_b11(&reference);
        tokio::time::sleep(CANON_RETRY * 4).await;
        assert_eq!(status(&chain, 11, &b11), Canonical::Yes);
        task.abort();
    }

    /// A sink whose retention prunes fail (or every prune, once the writer is gone), a
    /// millisecond after each call, and that keeps what it was asked: whether it was a
    /// finality prune, and when.
    struct FailingRetention {
        calls: Mutex<Vec<(bool, tokio::time::Instant)>>,
        gone: bool,
    }

    impl PruneSink for Arc<FailingRetention> {
        async fn prune(&self, prune: Prune) -> Pruned {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let finality = prune.finalized.is_some();
            let now = tokio::time::Instant::now();
            self.calls.lock().unwrap().push((finality, now));
            match (self.gone, finality) {
                (true, _) => Pruned::Gone,
                (false, true) => Pruned::Done,
                (false, false) => Pruned::Failed,
            }
        }
    }

    impl FailingRetention {
        fn retention_calls(&self) -> Vec<tokio::time::Instant> {
            let calls = self.calls.lock().unwrap();
            calls
                .iter()
                .filter(|(f, _)| !f)
                .map(|(_, at)| *at)
                .collect()
        }

        fn finality_calls(&self) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(f, _)| *f)
                .count()
        }
    }

    /// A retention prune that keeps failing is tried again after a growing pause, never at
    /// once: a checkpoint still reaches the store, a failed head walk still runs again, and the
    /// tracker ends once both senders are gone.
    #[tokio::test(start_paused = true)]
    async fn a_retention_prune_that_keeps_failing_is_paced_and_holds_nothing_up() {
        let spe = Spec::slots_per_epoch();
        // The serve range starts at slot 8: retention is due from the start.
        let clock = Arc::new(Clock::at(8, 5 * spe - 1));
        let reference = Arc::new(Silent::default());
        let b15 = reference.serve(2 * spe - 1);
        let b16 = reference.serve_on(2 * spe, b15);
        let b17 = reference.serve_on(2 * spe + 1, b16);
        let (tracker, chain) = tracker(&reference, &clock);
        let (heads, heads_seen) = watch::channel(None);
        let (finalized, finalized_seen) = watch::channel(None);
        let sink = Arc::new(FailingRetention {
            calls: Mutex::default(),
            gone: false,
        });
        let task = tokio::spawn(track_chain(
            tracker,
            heads_seen,
            finalized_seen,
            Arc::clone(&sink),
        ));
        heads.send_replace(Some(ChainEvent::Head(b17)));
        tokio::time::sleep(Duration::from_secs(3)).await;
        finalized.send_replace(Some(Checkpoint {
            epoch: 2,
            root: b16,
        }));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(sink.finality_calls(), 1, "the checkpoint reached the store");
        // A head walk that fails runs again, while retention keeps failing.
        let (b18, serve_b18) = later(2 * spe + 2, b17);
        heads.send_replace(Some(ChainEvent::Head(b18)));
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(chain.view(), None);
        serve_b18(&reference);
        tokio::time::sleep(CANON_RETRY * 2).await;
        assert_eq!(status(&chain, 2 * spe + 2, &b18), Canonical::Yes);
        tokio::time::sleep(Duration::from_secs(60)).await;
        let tries = sink.retention_calls();
        assert!((3..=10).contains(&tries.len()), "{} tries", tries.len());
        for pair in tries.windows(2) {
            assert!(pair[1] - pair[0] >= CANON_RETRY, "{:?}", pair[1] - pair[0]);
        }
        // Both senders gone: the tracker ends, retention or not.
        drop((heads, finalized));
        let ended = tokio::time::timeout(Duration::from_secs(120), task).await;
        assert!(ended.is_ok(), "the tracker did not end");
    }

    /// Once the writer is gone, the tracker ends, and the chain is unknown.
    #[tokio::test(start_paused = true)]
    async fn the_tracker_ends_once_the_writer_is_gone() {
        let reference = Arc::new(Silent::default());
        let b10 = reference.serve(10);
        let b11 = reference.serve_on(11, b10);
        let clock = Arc::new(Clock::at(8, 100));
        let (tracker, chain) = tracker(&reference, &clock);
        let (heads, heads_seen) = watch::channel(None);
        let (_finalized, finalized_seen) = watch::channel(None);
        let sink = Arc::new(FailingRetention {
            calls: Mutex::default(),
            gone: true,
        });
        let task = tokio::spawn(track_chain(
            tracker,
            heads_seen,
            finalized_seen,
            Arc::clone(&sink),
        ));
        heads.send_replace(Some(ChainEvent::Head(b11)));
        let ended = tokio::time::timeout(Duration::from_secs(10), task).await;
        assert!(ended.is_ok(), "the tracker did not end");
        assert_eq!(sink.retention_calls().len(), 1);
        assert_eq!(chain.view(), None);
    }

    /// Retention is due each time the first slot of the serve range moves past the slot the
    /// store keeps from.
    #[test]
    fn retention_is_due_once_the_serve_range_moves() {
        let reference = Arc::new(Silent::default());
        let clock = Arc::new(Clock::at(0, 100));
        let (mut tracker, _) = tracker(&reference, &clock);
        assert_eq!(tracker.retention_due(), None, "nothing before slot 0");
        clock.set(Some((64, 200)));
        assert_eq!(tracker.retention_due(), Some(64));
        assert_eq!(tracker.retention_due(), Some(64), "until the store is done");
        tracker.retention_applied(64);
        assert_eq!(tracker.retention_due(), None);
        clock.set(Some((96, 232)));
        assert_eq!(tracker.retention_due(), Some(96));
        clock.set(None);
        assert_eq!(tracker.retention_due(), None, "before Fulu");
    }

    #[tokio::test(start_paused = true)]
    async fn a_walk_is_bounded() {
        let reference = Arc::new(Silent::default());
        // From slot 8, the fixture's first Gloas slot.
        let mut parent = reference.serve(8);
        let head = MAX_CANON_WALK as u64 + 20;
        for slot in 9..=head {
            parent = reference.serve_on(slot, parent);
        }
        let (mut tracker, chain) = tracker(&reference, &Arc::default());
        tracker.on_head(parent).await;
        let view = chain.view().unwrap();
        assert_eq!(view.len(), MAX_CANON_WALK);
        assert_eq!(view.head_slot(), head);
        assert_eq!(view.floor(), head + 1 - MAX_CANON_WALK as u64);
    }
}
