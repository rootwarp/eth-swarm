//! [`RefView`]: which block roots the reference node vouches for, and their bids' commitments.
//!
//! The reference Beacon API is trusted for **roots only**. A root is known once the reference
//! answers `/eth/v1/beacon/headers/{root}` with a header that names that root. The commitments
//! are not taken on its word: the block comes from `/eth/v2/beacon/blocks/{root}` as SSZ, is
//! decoded by the fork of its own slot, and is used only if it is Gloas, its `hash_tree_root` is
//! the root and its slot is the header's. Its bid's `blob_kzg_commitments` are then what the
//! columns of that root verify against (`gloas/p2p-interface.md`, `data_column_sidecar_{subnet_id}`).
//!
//! Bounds ([`RefLimits`]):
//! - every lookup gets its answer within `timeout`, header and block together, or
//!   [`RefError::Timeout`]. A lookup of a root asks in rounds: one header and block request,
//!   within the timeout, at a time;
//! - at most `max_in_flight` roots are being looked up at once in the general places, and
//!   `max_announced_in_flight` more in the announced roots' places (below), and at most that
//!   many requests run against the reference. Lookups of a root already in flight share its
//!   round; a new root while its places are full is [`RefError::Busy`] at once, never queued.
//!   A root leaves the set when a round gives an answer that it keeps, or when the last caller
//!   waiting on it is gone (its error, its timeout, or it dropped the lookup), so abandoned
//!   lookups never hold a place. A general round keeps only a block or a refusal: after no
//!   answer (an error or a timeout), the callers still waiting on the root ask again in turn,
//!   and a new lookup of the root joins them rather than asking again;
//! - at most `max_cached` resolved roots are kept, the oldest evicted first. A root the reference
//!   does not know is not cached: it may know it a moment later;
//! - a root the reference announced on its event stream ([`RefView::announce`], `probe::head`)
//!   is a hint, at most `max_announced` of them, the oldest forgotten first; a second
//!   announcement of a root leaves its hint as it is. While the hint is live, its lookup takes
//!   one of `max_announced_in_flight` places of its own, which lookups of other roots never
//!   take, so a flood of made-up roots in the general places cannot keep it out
//!   ([`RefView::lookup_announced`]). A round in those places keeps any answer, so all its
//!   callers share its one request. The hint is spent once a round resolves its root (it is
//!   cached) or the reference refuses it ([`RefError::Block`]). Each round without an answer
//!   (a timeout, an API error, or cut short) counts a failure: the first starts the hint's last
//!   `announced_ttl`, and [`MAX_ANNOUNCED_FAILURES`] of them end it. So a slow reference does
//!   not cost the root its places, and one that fails at once costs a few requests, not one per
//!   column. It is only a hint: the root is established as any other.
//!   [`RefView::until_cached`] tells a waiting column once its root is cached.
//!
//! [`RefView::seed`] puts a block the node already holds (the checkpoint anchor that two
//! providers agreed on) into the cache without asking the reference.

use super::{ApiError, ReferenceApi, Root, DEFAULT_API_TIMEOUT};
use consensus_types::primitives::{KZGCommitment, Slot};
use consensus_types::{forked, gloas, EthSpec, ForkSchedule};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{watch, OnceCell, Semaphore};
use tokio::time::Instant;
use tree_hash::TreeHash;

/// The reference Beacon API's blocks.
pub trait BlockApi: Send + Sync {
    /// The SSZ of the signed block `root` (`/eth/v2/beacon/blocks/{root}`).
    fn block(&self, root: Root) -> impl Future<Output = Result<Vec<u8>, ApiError>> + Send;
}

/// What the reference vouches for about one block root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefBlock {
    pub root: Root,
    pub slot: Slot,
    /// The block's `parent_root`.
    pub parent_root: Root,
    /// The bid's `blob_kzg_commitments`.
    pub commitments: Vec<KZGCommitment>,
}

impl RefBlock {
    fn of<E: EthSpec>(root: Root, block: &gloas::BeaconBlock<E>) -> Self {
        let bid = &block.body.signed_execution_payload_bid.message;
        Self {
            root,
            slot: block.slot,
            parent_root: block.parent_root.0,
            commitments: bid.blob_kzg_commitments.iter().copied().collect(),
        }
    }
}

/// Roots a [`RefView`] looks up at once by default \[est\]. With the column store's defaults,
/// [`IngestLimits::validate_for`](super::IngestLimits::validate_for) needs 96: a retry of each
/// of the 16 seats, and the first asks that can hang together on a slow reference within the
/// 2 s timeout (16 at once, then 32 a second: 80). The 8 past that are for the chain-link walks
/// of known roots (the column links, and the walk of the reference's chain, `probe::canon`),
/// which ask outside the root wait's budgets one root at a time, and for timers that fire late.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 104;

/// Lookups of announced roots at once by default \[est\]: the reference imports about a block a
/// slot, so one is usually enough; the rest is for a reorg's few blocks and a slow reference.
pub const DEFAULT_MAX_ANNOUNCED_IN_FLIGHT: usize = 4;

/// Announced roots remembered by default \[est\]: a hint is spent by its first lookup that
/// ends, so only roots announced while every announced place is taken wait here.
pub const DEFAULT_MAX_ANNOUNCED: usize = 32;

/// Lookups of an announced root that may fail without an answer before its announcement is
/// spent \[est\]: a reference that is slow or late gets a few more tries, one that answers
/// errors at once costs no more than this many requests for it.
pub const MAX_ANNOUNCED_FAILURES: u8 = 4;

/// The bounds of a [`RefView`] (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefLimits {
    /// The most one lookup may take, header and block together.
    pub timeout: Duration,
    /// Roots looked up at once in the general places. Requests running against the reference
    /// are at most this and `max_announced_in_flight` together.
    pub max_in_flight: usize,
    /// Resolved roots kept.
    pub max_cached: usize,
    /// Announced roots looked up at once, in places of their own.
    pub max_announced_in_flight: usize,
    /// Announced roots remembered, until a lookup resolves each one.
    pub max_announced: usize,
    /// How long an announced root stays announced after its first lookup that failed without
    /// an answer (a timeout or an API error).
    pub announced_ttl: Duration,
}

impl Default for RefLimits {
    /// [`DEFAULT_API_TIMEOUT`], [`DEFAULT_MAX_IN_FLIGHT`] in flight, 64 cached (two mainnet
    /// epochs of blocks), and [`DEFAULT_MAX_ANNOUNCED_IN_FLIGHT`] and
    /// [`DEFAULT_MAX_ANNOUNCED`] for announced roots \[est\].
    fn default() -> Self {
        Self {
            timeout: DEFAULT_API_TIMEOUT,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            max_cached: 64,
            max_announced_in_flight: DEFAULT_MAX_ANNOUNCED_IN_FLIGHT,
            max_announced: DEFAULT_MAX_ANNOUNCED,
            announced_ttl: super::ingest::DEFAULT_ROOT_WAIT,
        }
    }
}

/// Why a root has no [`RefBlock`]. Every one means "not vouched for": the column is dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefError {
    /// The reference refused, failed or does not know the root.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// No answer within the lookup timeout.
    #[error("no answer within {0:?}")]
    Timeout(Duration),
    /// This many roots are already in flight.
    #[error("{0} lookups in flight")]
    Busy(usize),
    /// The reference's header or block does not establish the root.
    #[error("block: {0}")]
    Block(String),
}

/// One round of a root's lookup: its answer once there is one to keep. A general round keeps
/// only a block or a refusal, so after no answer the callers still waiting ask again in turn.
/// A round in the announced places keeps any answer, so its callers share one request.
type Lookup = Arc<OnceCell<Result<Arc<RefBlock>, RefError>>>;

/// One root being looked up, and how many callers are waiting on it.
struct InFlight {
    lookup: Lookup,
    waiters: usize,
    /// Whether it holds one of the announced roots' places.
    announced: bool,
}

#[derive(Default)]
struct State {
    cached: HashMap<Root, Arc<RefBlock>>,
    /// Insertion order of `cached`, oldest first.
    order: VecDeque<Root>,
    in_flight: HashMap<Root, InFlight>,
    /// The entries of `in_flight` in the announced roots' places.
    announced_in_flight: usize,
    /// Announced roots not resolved yet.
    hints: HashMap<Root, Hint>,
    /// Announcement order of `hints`, oldest first.
    hint_order: VecDeque<Root>,
}

/// One announced root.
#[derive(Debug, Clone, Copy, Default)]
struct Hint {
    /// Its lookups that ended without an answer (a timeout or an API error).
    failures: u8,
    /// Set by the first of them: the hint lives until then.
    until: Option<Instant>,
}

impl Hint {
    fn live(&self, now: Instant) -> bool {
        self.failures < MAX_ANNOUNCED_FAILURES && self.until.is_none_or(|until| now < until)
    }
}

/// A round in progress: one cut short (its caller gave up, or timed out first) counts as a
/// round without an answer in the root's hint.
struct CutRound<'a, A, E> {
    view: &'a RefView<A, E>,
    root: Root,
    done: bool,
}

impl<A, E> std::ops::Drop for CutRound<'_, A, E> {
    fn drop(&mut self) {
        if !self.done {
            let ttl = self.view.limits.announced_ttl;
            let mut state = self
                .view
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.note(self.root, None, ttl);
        }
    }
}

/// How a lookup begins: answered at once, or waiting on a lookup in flight, in the announced
/// places or not.
enum Begin {
    Answered(Result<Arc<RefBlock>, RefError>),
    Waits(Lookup, bool),
}

/// One caller's share of an in-flight lookup. Dropping it, when the lookup ends for this caller
/// or the caller gives up first, releases the share ([`State::leave`]).
struct Waiter<'a> {
    state: &'a Mutex<State>,
    /// Told of every root cached ([`RefView::until_cached`]).
    cached: &'a watch::Sender<u64>,
    max_cached: usize,
    root: Root,
    lookup: Lookup,
    /// Set once the lookup resolved the root for this caller.
    resolved: Option<Arc<RefBlock>>,
    /// Set once the lookup's round has an answer that it keeps: the root leaves the set.
    settled: bool,
}

impl std::ops::Drop for Waiter<'_> {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.leave(
            self.root,
            &self.lookup,
            self.settled,
            self.resolved.is_some(),
        );
        if let Some(block) = self.resolved.take() {
            state.cache(block, self.max_cached);
            drop(state);
            self.cached.send_modify(|generation| *generation += 1);
        }
    }
}

/// The reference node's view of block roots (see the module docs).
pub struct RefView<A, E> {
    api: A,
    schedule: ForkSchedule,
    limits: RefLimits,
    requests: Semaphore,
    state: Mutex<State>,
    /// Lookups refused as [`RefError::Busy`] so far.
    busy: AtomicU64,
    /// Bumped whenever a root is cached.
    cached: watch::Sender<u64>,
    spec: PhantomData<fn() -> E>,
}

impl<A: ReferenceApi + BlockApi, E: EthSpec> RefView<A, E> {
    /// A view of `api`, decoding blocks by `schedule`.
    pub fn new(api: A, schedule: ForkSchedule, limits: RefLimits) -> Self {
        Self {
            api,
            schedule,
            limits,
            requests: Semaphore::new(
                limits
                    .max_in_flight
                    .saturating_add(limits.max_announced_in_flight),
            ),
            state: Mutex::default(),
            busy: AtomicU64::new(0),
            cached: watch::Sender::new(0),
            spec: PhantomData,
        }
    }

    /// The block `root` as the reference vouches for it.
    ///
    /// # Errors
    ///
    /// [`RefError`]: the root is not vouched for, or not within the bounds.
    pub async fn lookup(&self, root: Root) -> Result<Arc<RefBlock>, RefError> {
        let begin = self.begin(&mut self.state(), root, false);
        self.finish(root, begin).await
    }

    /// Records `root` as announced by the reference ([`Self::lookup_announced`]), unless it is
    /// cached; the oldest announced root is forgotten past `max_announced`. Only a hint: the
    /// root is still established by its header and block.
    pub fn announce(&self, root: Root) {
        let mut state = self.state();
        if state.cached.contains_key(&root) {
            return;
        }
        // Announced again: the hint stays as it is, its failures and its life too.
        if state.hints.contains_key(&root) {
            return;
        }
        // Hints past their life give their room back first.
        let now = Instant::now();
        let State {
            hints, hint_order, ..
        } = &mut *state;
        hints.retain(|_, hint| hint.live(now));
        hint_order.retain(|hint| hints.contains_key(hint));
        state.hints.insert(root, Hint::default());
        state.hint_order.push_back(root);
        while state.hints.len() > self.limits.max_announced {
            let Some(oldest) = state.hint_order.pop_front() else {
                break;
            };
            state.hints.remove(&oldest);
        }
    }

    /// [`Self::lookup`] of a root the reference announced ([`Self::announce`]) while its hint
    /// is live: cached, or sharing its lookup in flight, or a new round in the announced roots'
    /// own places (`max_announced_in_flight`), which lookups of other roots never take. `None`
    /// for a root not cached and without a live hint, which takes the general path.
    ///
    /// # Errors
    ///
    /// [`RefError`], as [`Self::lookup`]; [`RefError::Busy`] once every announced place is
    /// taken.
    pub async fn lookup_announced(&self, root: Root) -> Option<Result<Arc<RefBlock>, RefError>> {
        let begin = {
            let mut state = self.state();
            let known = state.cached.contains_key(&root);
            if !known && !state.live_hint(&root) {
                return None;
            }
            self.begin(&mut state, root, true)
        };
        Some(self.finish(root, begin).await)
    }

    /// [`Self::lookup`] of `root` in the announced roots' places, whether or not its
    /// announcement is still remembered: for the follower of the reference's own stream, which
    /// may announce more roots at once than `max_announced` keeps.
    ///
    /// # Errors
    ///
    /// As [`Self::lookup_announced`].
    pub async fn lookup_as_announced(&self, root: Root) -> Result<Arc<RefBlock>, RefError> {
        let begin = self.begin(&mut self.state(), root, true);
        self.finish(root, begin).await
    }

    async fn finish(&self, root: Root, begin: Begin) -> Result<Arc<RefBlock>, RefError> {
        match begin {
            Begin::Waits(lookup, announced) => self.wait(root, lookup, announced).await,
            Begin::Answered(result) => result,
        }
    }

    /// Whether `root` has a live hint ([`Self::lookup_announced`] takes it).
    #[must_use]
    pub fn is_announced(&self, root: &Root) -> bool {
        self.state().live_hint(root)
    }

    /// Joins or opens the lookup of `root` under `state`, a new one in the announced places if
    /// `announced`, else in the general ones.
    fn begin(&self, state: &mut State, root: Root, announced: bool) -> Begin {
        if let Some(block) = state.cached.get(&root) {
            return Begin::Answered(Ok(Arc::clone(block)));
        }
        if let Some(entry) = state.in_flight.get_mut(&root) {
            entry.waiters += 1;
            return Begin::Waits(Arc::clone(&entry.lookup), entry.announced);
        }
        let (used, max) = if announced {
            let used = state.announced_in_flight;
            (used, self.limits.max_announced_in_flight)
        } else {
            let used = state.in_flight.len() - state.announced_in_flight;
            (used, self.limits.max_in_flight)
        };
        if used >= max {
            self.busy.fetch_add(1, Ordering::Relaxed);
            return Begin::Answered(Err(RefError::Busy(used)));
        }
        let lookup = Lookup::default();
        let entry = InFlight {
            lookup: Arc::clone(&lookup),
            waiters: 1,
            announced,
        };
        state.in_flight.insert(root, entry);
        state.announced_in_flight += usize::from(announced);
        Begin::Waits(lookup, announced)
    }

    /// One caller's wait on `lookup` of `root`, within the timeout. In the announced places
    /// the round's own timeout bounds it, and every caller gets the round's answer.
    async fn wait(
        &self,
        root: Root,
        lookup: Lookup,
        announced: bool,
    ) -> Result<Arc<RefBlock>, RefError> {
        // From here on, however this future ends, the waiter releases its share.
        let mut waiter = Waiter {
            state: &self.state,
            cached: &self.cached,
            max_cached: self.limits.max_cached,
            root,
            lookup,
            resolved: None,
            settled: false,
        };
        let timeout = self.limits.timeout;
        let round = waiter
            .lookup
            .get_or_try_init(|| self.round(root, announced));
        let kept = if announced {
            round.await
        } else {
            tokio::time::timeout(timeout, round)
                .await
                .unwrap_or(Err(RefError::Timeout(timeout)))
        };
        waiter.settled = kept.is_ok();
        let result = match kept {
            Ok(kept) => kept.clone(),
            Err(e) => Err(e),
        };
        waiter.resolved = result.as_ref().ok().cloned();
        result
    }

    /// One round: the header and the block within the timeout, its answer noted in the root's
    /// hint ([`State::note`]). The answer to keep in the round, or an error that leaves the
    /// round to the next caller ([`Lookup`]).
    async fn round(
        &self,
        root: Root,
        announced: bool,
    ) -> Result<Result<Arc<RefBlock>, RefError>, RefError> {
        let mut cut = CutRound {
            view: self,
            root,
            done: false,
        };
        let timeout = self.limits.timeout;
        let answer = tokio::time::timeout(timeout, self.fetch(root))
            .await
            .unwrap_or(Err(RefError::Timeout(timeout)));
        cut.done = true;
        self.note(root, Some(&answer));
        match answer {
            Err(e) if !announced && !matches!(e, RefError::Block(_)) => Err(e),
            kept => Ok(kept),
        }
    }

    /// Notes a round of `root` in its hint: its `answer`, or `None` for a round cut short.
    fn note(&self, root: Root, answer: Option<&Result<Arc<RefBlock>, RefError>>) {
        let ttl = self.limits.announced_ttl;
        self.state().note(root, answer, ttl);
    }

    /// Announced roots remembered now, their hints still live.
    #[must_use]
    pub fn announced(&self) -> usize {
        let now = Instant::now();
        let state = self.state();
        state.hints.values().filter(|hint| hint.live(now)).count()
    }

    /// Caches `block`, which the node already holds and trusts, without asking the reference;
    /// returns its root.
    pub fn seed(&self, block: &gloas::SignedBeaconBlock<E>) -> Root {
        let root = block.message.tree_hash_root().0;
        let block = Arc::new(RefBlock::of(root, &block.message));
        self.state().cache(block, self.limits.max_cached);
        self.cached.send_modify(|generation| *generation += 1);
        root
    }

    /// Resolves once `root` is cached (at once if it is).
    pub async fn until_cached(&self, root: Root) {
        // Subscribed before the check, so a root cached in between still wakes it.
        let mut changes = self.cached.subscribe();
        while self.cached_block(&root).is_none() {
            if changes.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }

    /// The block `root` if it is cached, without asking the reference.
    #[must_use]
    pub fn cached_block(&self, root: &Root) -> Option<Arc<RefBlock>> {
        self.state().cached.get(root).cloned()
    }

    /// The bounds this view was made with.
    #[must_use]
    pub fn limits(&self) -> RefLimits {
        self.limits
    }

    /// Roots being looked up now.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.state().in_flight.len()
    }

    /// Lookups refused so far because every place was taken ([`RefError::Busy`]).
    #[must_use]
    pub fn busy(&self) -> u64 {
        self.busy.load(Ordering::Relaxed)
    }

    /// Resolved roots kept.
    #[must_use]
    pub fn cached(&self) -> usize {
        self.state().cached.len()
    }

    /// The header, then the block, both checked against `root`.
    async fn fetch(&self, root: Root) -> Result<Arc<RefBlock>, RefError> {
        let _request = self
            .requests
            .acquire()
            .await
            .map_err(|_| RefError::Busy(self.limits.max_in_flight))?;
        let header = self.api.header(root).await?;
        if header.root != root {
            return Err(RefError::Block(format!(
                "the header of 0x{} names 0x{}",
                hex::encode(root),
                hex::encode(header.root)
            )));
        }
        let ssz = self.api.block(root).await?;
        let block = forked::SignedBeaconBlock::<E>::from_ssz_bytes_by_slot(&ssz, &self.schedule)
            .map_err(|e| RefError::Block(format!("decode: {e}")))?;
        let forked::SignedBeaconBlock::Gloas(block) = block else {
            return Err(RefError::Block(format!(
                "slot {} is before Gloas: no bid",
                block.slot()
            )));
        };
        let actual = block.message.tree_hash_root().0;
        if actual != root {
            return Err(RefError::Block(format!(
                "hash_tree_root 0x{} is not 0x{}",
                hex::encode(actual),
                hex::encode(root)
            )));
        }
        if block.message.slot != header.slot {
            return Err(RefError::Block(format!(
                "block slot {} is not the header slot {}",
                block.message.slot, header.slot
            )));
        }
        Ok(Arc::new(RefBlock::of(root, &block.message)))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl State {
    /// One waiter on `lookup` of `root` is gone: the root leaves the in-flight set if the
    /// waiter's round `settled` it (an answer the round keeps) or that waiter was the last
    /// one. After no answer in a general round, the waiters still there ask again in turn, so
    /// the root stays theirs. A newer lookup of the same root is left alone. A root `resolved`
    /// is cached, so its hint is spent.
    fn leave(&mut self, root: Root, lookup: &Lookup, settled: bool, resolved: bool) {
        if resolved {
            self.spend(&root);
        }
        let Some(entry) = self
            .in_flight
            .get_mut(&root)
            .filter(|entry| Arc::ptr_eq(&entry.lookup, lookup))
        else {
            return;
        };
        entry.waiters = entry.waiters.saturating_sub(1);
        if !settled && entry.waiters > 0 {
            return;
        }
        if let Some(entry) = self.in_flight.remove(&root) {
            self.announced_in_flight -= usize::from(entry.announced);
        }
    }

    /// Notes a round of `root` in its hint, if it has one: a refusal spends it, and a round
    /// without an answer (a timeout, an API error, or cut short: `None`) counts a failure,
    /// the first of them starting the hint's last `ttl`. A block resolves the root, which
    /// spends the hint once it is cached ([`Self::leave`]).
    fn note(
        &mut self,
        root: Root,
        answer: Option<&Result<Arc<RefBlock>, RefError>>,
        ttl: Duration,
    ) {
        match answer {
            Some(Ok(_)) => {}
            Some(Err(RefError::Block(_))) => self.spend(&root),
            Some(Err(_)) | None => {
                if let Some(hint) = self.hints.get_mut(&root) {
                    hint.failures = hint.failures.saturating_add(1);
                    hint.until.get_or_insert_with(|| Instant::now() + ttl);
                }
            }
        }
    }

    fn spend(&mut self, root: &Root) {
        if self.hints.remove(root).is_some() {
            self.hint_order.retain(|hint| hint != root);
        }
    }

    fn live_hint(&self, root: &Root) -> bool {
        let now = Instant::now();
        self.hints.get(root).is_some_and(|hint| hint.live(now))
    }

    fn cache(&mut self, block: Arc<RefBlock>, max: usize) {
        if max == 0 || self.cached.contains_key(&block.root) {
            return;
        }
        while self.cached.len() >= max {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.cached.remove(&oldest);
        }
        self.order.push_back(block.root);
        self.cached.insert(block.root, block);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Checkpoint, Header};
    use super::*;
    use crate::testing::{gloas_block, schedule, Spec};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::sync::watch;

    /// A reference node from tables: headers and block SSZ by root. While `hang` is set, every
    /// request waits until it is cleared or takes one of the `passes` handed out.
    struct Reference {
        headers: Mutex<HashMap<Root, Header>>,
        blocks: Mutex<HashMap<Root, Vec<u8>>>,
        hang: watch::Sender<bool>,
        passes: Semaphore,
        requests: AtomicUsize,
    }

    impl Default for Reference {
        fn default() -> Self {
            Self {
                headers: Mutex::default(),
                blocks: Mutex::default(),
                hang: watch::Sender::default(),
                passes: Semaphore::new(0),
                requests: AtomicUsize::default(),
            }
        }
    }

    impl Reference {
        /// Serves the Gloas block at `slot` with `n` commitments; returns its root.
        fn serve(&self, slot: Slot, n: u8) -> Root {
            let commitments: Vec<_> = (0..n).map(|i| [0xc0 | i; 48]).collect();
            let (_, ssz, root) = gloas_block(slot, &commitments);
            self.serve_as(root, slot, ssz);
            root
        }

        fn serve_as(&self, root: Root, slot: Slot, ssz: Vec<u8>) {
            self.headers
                .lock()
                .unwrap()
                .insert(root, Header { root, slot });
            self.blocks.lock().unwrap().insert(root, ssz);
        }

        async fn gate(&self) {
            self.requests.fetch_add(1, Ordering::SeqCst);
            let mut hang = self.hang.subscribe();
            // The sender lives as long as the fixture, so this ends only when `hang` clears or
            // a pass is handed out.
            tokio::select! {
                _ = hang.wait_for(|hang| !hang) => {}
                pass = self.passes.acquire() => pass.unwrap().forget(),
            }
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    impl ReferenceApi for &Reference {
        async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
            Err(ApiError("not used".into()))
        }

        async fn header(&self, root: Root) -> Result<Header, ApiError> {
            self.gate().await;
            let found = self.headers.lock().unwrap().get(&root).copied();
            found.ok_or_else(|| ApiError("404".into()))
        }
    }

    impl BlockApi for &Reference {
        async fn block(&self, root: Root) -> Result<Vec<u8>, ApiError> {
            self.gate().await;
            let found = self.blocks.lock().unwrap().get(&root).cloned();
            found.ok_or_else(|| ApiError("404".into()))
        }
    }

    fn view(api: &Reference, limits: RefLimits) -> RefView<&Reference, Spec> {
        RefView::new(api, schedule(), limits)
    }

    #[tokio::test]
    async fn a_vouched_root_gives_its_bids_commitments_once() {
        let api = Reference::default();
        let root = api.serve(9, 2);
        let refs = view(&api, RefLimits::default());
        assert_eq!(refs.cached_block(&root), None);
        let block = refs.lookup(root).await.unwrap();
        assert_eq!(refs.cached_block(&root), Some(Arc::clone(&block)));
        assert_eq!(
            *block,
            RefBlock {
                root,
                slot: 9,
                parent_root: block.parent_root,
                commitments: vec![[0xc0; 48], [0xc1; 48]],
            }
        );
        let asked = api.requests();
        assert_eq!(asked, 2, "one header, one block");
        assert_eq!(refs.lookup(root).await.unwrap(), block);
        assert_eq!(api.requests(), asked, "the second lookup is cached");
    }

    #[tokio::test]
    async fn an_unknown_root_is_not_cached() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        let (_, ssz, root) = gloas_block(10, &[[1; 48]]);
        assert!(matches!(refs.lookup(root).await, Err(RefError::Api(_))));
        // The reference learns the block: the next lookup asks again and finds it.
        api.serve_as(root, 10, ssz);
        assert_eq!(refs.lookup(root).await.unwrap().slot, 10);
    }

    #[tokio::test]
    async fn the_block_must_be_the_root() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        // The reference vouches for a root but serves another block for it.
        let (_, other, _) = gloas_block(11, &[[1; 48]]);
        api.serve_as([0x77; 32], 11, other);
        let err = refs.lookup([0x77; 32]).await.unwrap_err();
        assert!(err.to_string().contains("hash_tree_root"), "{err}");
        // A header that names another root.
        let root = api.serve(12, 1);
        let header = Header {
            root: [0x55; 32],
            slot: 12,
        };
        api.headers.lock().unwrap().insert(root, header);
        let err = refs.lookup(root).await.unwrap_err();
        assert!(err.to_string().contains("names"), "{err}");
        // A header at another slot than the block's.
        let root = api.serve(13, 1);
        let header = Header { root, slot: 14 };
        api.headers.lock().unwrap().insert(root, header);
        let err = refs.lookup(root).await.unwrap_err();
        assert!(err.to_string().contains("slot"), "{err}");
    }

    #[tokio::test]
    async fn a_block_before_gloas_has_no_bid() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        use ssz::Encode;
        use tree_hash::TreeHash;
        let fulu = p2p_wire::testkit::fulu_block::<Spec>(3);
        let root = fulu.message.tree_hash_root().0;
        api.serve_as(root, 3, fulu.as_ssz_bytes());
        let err = refs.lookup(root).await.unwrap_err();
        assert!(err.to_string().contains("Gloas"), "{err}");
        // Bytes that are no block at all.
        api.serve_as([0x66; 32], 9, vec![1, 2, 3]);
        assert!(matches!(
            refs.lookup([0x66; 32]).await,
            Err(RefError::Block(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_reference_times_out() {
        let api = Reference::default();
        let root = api.serve(9, 1);
        api.hang.send_replace(true);
        let limits = RefLimits {
            timeout: Duration::from_millis(500),
            ..RefLimits::default()
        };
        let refs = view(&api, limits);
        let start = tokio::time::Instant::now();
        let err = refs.lookup(root).await.unwrap_err();
        assert_eq!(err, RefError::Timeout(Duration::from_millis(500)));
        assert_eq!(start.elapsed(), Duration::from_millis(500));
        assert_eq!(
            refs.in_flight(),
            0,
            "a timed-out lookup leaves nothing in flight"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lookups_in_flight_are_bounded_and_shared() {
        let api = Reference::default();
        let first = api.serve(9, 1);
        let second = api.serve(10, 1);
        api.hang.send_replace(true);
        let limits = RefLimits {
            max_in_flight: 1,
            ..RefLimits::default()
        };
        let refs = view(&api, limits);
        let hung = async {
            // Two lookups of one root share one request.
            let (a, b) = tokio::join!(refs.lookup(first), refs.lookup(first));
            assert!(a.is_err() && b.is_err());
        };
        let refused = async {
            tokio::task::yield_now().await;
            assert_eq!(refs.in_flight(), 1);
            // Another root while the set is full: refused at once, never queued.
            assert_eq!(refs.lookup(second).await, Err(RefError::Busy(1)));
            assert_eq!(api.requests(), 1, "one request for both lookups of `first`");
        };
        tokio::join!(hung, refused);
    }

    #[tokio::test]
    async fn the_cache_is_bounded() {
        let api = Reference::default();
        let roots: Vec<_> = (0..3).map(|i| api.serve(9 + i, 1)).collect();
        let limits = RefLimits {
            max_cached: 2,
            ..RefLimits::default()
        };
        let refs = view(&api, limits);
        for root in &roots {
            refs.lookup(*root).await.unwrap();
        }
        assert_eq!(refs.cached(), 2);
        let asked = api.requests();
        // The oldest was evicted and is asked for again; the newest is still cached.
        refs.lookup(roots[2]).await.unwrap();
        assert_eq!(api.requests(), asked);
        refs.lookup(roots[0]).await.unwrap();
        assert_eq!(api.requests(), asked + 2);
        assert_eq!(refs.cached(), 2);
    }

    #[tokio::test]
    async fn a_seeded_anchor_needs_no_request() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        let (block, _, root) = gloas_block(16, &[[3; 48]]);
        assert_eq!(refs.seed(&block), root);
        let found = refs.lookup(root).await.unwrap();
        assert_eq!((found.slot, found.commitments.clone()), (16, vec![[3; 48]]));
        assert_eq!(api.requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_lookups_free_their_place() {
        let api = Reference::default();
        let limits = RefLimits::default();
        let roots: Vec<_> = (0..=u64::try_from(limits.max_in_flight).unwrap())
            .map(|i| api.serve(9 + i, 1))
            .collect();
        let (last, cancelled) = roots.split_last().unwrap();
        api.hang.send_replace(true);
        let refs = view(&api, limits);
        // Every caller gives up long before the lookup's own timeout.
        for root in cancelled {
            let gave_up = tokio::time::timeout(Duration::from_millis(100), refs.lookup(*root));
            assert!(gave_up.await.is_err(), "the reference is hanging");
        }
        assert_eq!(
            refs.in_flight(),
            0,
            "a dropped lookup leaves nothing in flight"
        );
        // A new root is looked up, not refused as busy.
        api.hang.send_replace(false);
        assert_eq!(refs.lookup(*last).await.unwrap().root, *last);
    }

    #[tokio::test(start_paused = true)]
    async fn a_shared_lookup_outlives_a_waiter_that_gives_up() {
        let api = Reference::default();
        let root = api.serve(9, 1);
        api.hang.send_replace(true);
        let refs = view(&api, RefLimits::default());
        let gives_up = async {
            let gave_up = tokio::time::timeout(Duration::from_millis(100), refs.lookup(root));
            assert!(gave_up.await.is_err(), "the reference is hanging");
            assert_eq!(
                refs.in_flight(),
                1,
                "the other waiter still holds the lookup"
            );
            // A third lookup of the root shares it rather than adding a root.
            let shared = tokio::time::timeout(Duration::from_millis(100), refs.lookup(root));
            assert!(shared.await.is_err());
            assert_eq!(refs.in_flight(), 1);
            api.hang.send_replace(false);
        };
        // The waiter that gives up asks first, so it is the one running the request.
        let stays = async {
            tokio::task::yield_now().await;
            refs.lookup(root).await
        };
        let ((), block) = tokio::join!(gives_up, stays);
        assert_eq!(
            block.unwrap().root,
            root,
            "the remaining waiter gets the answer"
        );
        assert_eq!(refs.in_flight(), 0);
        assert_eq!(refs.cached(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_announced_root_is_looked_up_in_places_of_its_own() {
        let api = Reference::default();
        let (flood, real, other) = (api.serve(9, 1), api.serve(10, 1), api.serve(11, 1));
        api.hang.send_replace(true);
        let limits = RefLimits {
            max_in_flight: 1,
            max_announced_in_flight: 1,
            ..RefLimits::default()
        };
        let refs = view(&api, limits);
        // A root never announced does not take the announced path.
        assert_eq!(refs.lookup_announced(flood).await, None);
        refs.announce(real);
        refs.announce(other);
        assert_eq!(refs.announced(), 2);
        let hung = async {
            let (a, b, c) = tokio::join!(
                refs.lookup(flood),
                refs.lookup_announced(real),
                refs.lookup_announced(real)
            );
            assert!(a.is_ok());
            assert_eq!(b.unwrap().unwrap().root, real);
            assert_eq!(c.unwrap().unwrap().root, real);
        };
        let full = async {
            tokio::task::yield_now().await;
            // The general place is taken, and the announced root has a place of its own,
            // which its second lookup shares.
            assert_eq!(refs.in_flight(), 2);
            assert_eq!(api.requests(), 2, "one request per root");
            assert_eq!(refs.lookup(other).await, Err(RefError::Busy(1)));
            // The announced places are full too: busy, never queued.
            let busy = refs.lookup_announced(other).await;
            assert_eq!(busy, Some(Err(RefError::Busy(1))));
            assert_eq!(refs.busy(), 2);
            api.hang.send_replace(false);
        };
        tokio::join!(hung, full);
        assert_eq!(refs.in_flight(), 0);
        assert_eq!(refs.cached(), 2);
        // Still announced, never looked up: its lookup starts once a place is free.
        assert_eq!(
            refs.lookup_announced(other).await.unwrap().unwrap().root,
            other
        );
        assert_eq!(refs.announced(), 0, "every hint spent");
    }

    #[tokio::test(start_paused = true)]
    async fn a_hint_outlives_a_failed_lookup_for_its_ttl() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        let ttl = refs.limits().announced_ttl;
        // The reference announces a root its API does not serve yet: the lookup fails, and
        // the hint stays, so the next column of the root still takes the announced path.
        let (_, ssz, root) = gloas_block(9, &[[1; 48]]);
        refs.announce(root);
        let failed = refs.lookup_announced(root).await.unwrap();
        assert!(matches!(failed, Err(RefError::Api(_))), "{failed:?}");
        assert_eq!(refs.announced(), 1, "kept after an error");
        // A later failure does not make the hint live longer than one ttl from the first.
        tokio::time::sleep(ttl / 2).await;
        assert!(refs.lookup_announced(root).await.unwrap().is_err());
        tokio::time::sleep(ttl / 2).await;
        assert_eq!(refs.lookup_announced(root).await, None, "past its ttl");
        assert_eq!(refs.announced(), 0);
        // Announced again, the hint stays as it was: past its ttl.
        api.serve_as(root, 9, ssz);
        refs.announce(root);
        assert_eq!(refs.lookup_announced(root).await, None);
        // Another root announced and served: the block is cached, and the hint spent.
        let root = api.serve(9, 1);
        refs.announce(root);
        assert_eq!(refs.lookup_announced(root).await.unwrap().unwrap().slot, 9);
        assert_eq!(refs.announced(), 0);
        let asked = api.requests();
        assert_eq!(refs.lookup_announced(root).await.unwrap().unwrap().slot, 9);
        assert_eq!(api.requests(), asked, "cached");
        // A cached root is not announced again.
        refs.announce(root);
        assert_eq!(refs.announced(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_hint_whose_lookups_keep_failing_is_spent_after_a_few() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        // A reference that answers 404 at once: each column of the root would ask again.
        let (_, _, root) = gloas_block(9, &[[1; 48]]);
        refs.announce(root);
        for _ in 0..MAX_ANNOUNCED_FAILURES {
            assert!(refs.lookup_announced(root).await.unwrap().is_err());
        }
        assert_eq!(refs.lookup_announced(root).await, None, "spent");
        assert_eq!(api.requests(), usize::from(MAX_ANNOUNCED_FAILURES));
    }

    #[tokio::test]
    async fn a_hint_whose_block_does_not_establish_the_root_is_spent() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        let (_, other, _) = gloas_block(11, &[[1; 48]]);
        api.serve_as([0x77; 32], 11, other);
        refs.announce([0x77; 32]);
        let refused = refs.lookup_announced([0x77; 32]).await.unwrap();
        assert!(matches!(refused, Err(RefError::Block(_))), "{refused:?}");
        assert_eq!(refs.lookup_announced([0x77; 32]).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_announced_lookup_keeps_the_hint() {
        let api = Reference::default();
        let root = api.serve(9, 1);
        api.hang.send_replace(true);
        let refs = view(&api, RefLimits::default());
        refs.announce(root);
        let gave_up = tokio::time::timeout(Duration::from_millis(100), refs.lookup_announced(root));
        assert!(gave_up.await.is_err());
        assert_eq!(refs.announced(), 1);
        api.hang.send_replace(false);
        assert_eq!(
            refs.lookup_announced(root).await.unwrap().unwrap().root,
            root
        );
    }

    #[tokio::test]
    async fn announced_roots_are_bounded_and_the_oldest_is_forgotten() {
        let api = Reference::default();
        let limits = RefLimits {
            max_announced: 2,
            ..RefLimits::default()
        };
        let refs = view(&api, limits);
        let roots: Vec<_> = (0..3).map(|i| api.serve(9 + i, 1)).collect();
        for root in &roots {
            refs.announce(*root);
        }
        refs.announce(roots[2]);
        assert_eq!(refs.announced(), 2, "an announcement again adds nothing");
        assert_eq!(refs.lookup_announced(roots[0]).await, None, "forgotten");
        for root in &roots[1..] {
            assert_eq!(
                refs.lookup_announced(*root).await.unwrap().unwrap().root,
                *root
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_column_joins_an_announced_lookup_only_while_its_hint_is_live() {
        let api = Reference::default();
        let roots: Vec<_> = (0..2).map(|i| api.serve(9 + i, 1)).collect();
        api.hang.send_replace(true);
        let limits = RefLimits {
            max_announced: 1,
            ..RefLimits::default()
        };
        let refs = view(&api, limits);
        refs.announce(roots[0]);
        let first = refs.lookup_announced(roots[0]);
        let later = async {
            tokio::task::yield_now().await;
            // A newer announcement pushes the hint out: the lookup in flight is not the
            // announced path's any more.
            refs.announce(roots[1]);
            assert_eq!(refs.lookup_announced(roots[0]).await, None);
            api.hang.send_replace(false);
        };
        let (first, ()) = tokio::join!(first, later);
        assert_eq!(first.unwrap().unwrap().root, roots[0]);
        assert_eq!(api.requests(), 2, "one header, one block");
    }

    #[tokio::test(start_paused = true)]
    async fn waiters_on_an_announced_root_that_always_fails_ask_at_most_the_failure_cap() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        // The reference announced the root, but its API answers 404 at once, every time.
        let (_, _, root) = gloas_block(9, &[[1; 48]]);
        refs.announce(root);
        api.hang.send_replace(true);
        let ten = async {
            tokio::join!(
                refs.lookup_announced(root),
                refs.lookup_announced(root),
                refs.lookup_announced(root),
                refs.lookup_announced(root),
                refs.lookup_announced(root),
                refs.lookup_announced(root),
                refs.lookup_announced(root),
                refs.lookup_announced(root),
                refs.lookup_announced(root),
                refs.lookup_announced(root),
            )
        };
        let release = async {
            tokio::task::yield_now().await;
            api.hang.send_replace(false);
        };
        let (outcomes, ()) = tokio::join!(ten, release);
        let outcomes = [
            outcomes.0, outcomes.1, outcomes.2, outcomes.3, outcomes.4, outcomes.5, outcomes.6,
            outcomes.7, outcomes.8, outcomes.9,
        ];
        assert!(outcomes.iter().all(|o| !matches!(o, Some(Ok(_)))));
        assert_eq!(api.requests(), 1, "ten waiters, one round");
        // Asked again and again, as columns of the root keep coming: the hint ends.
        let mut asks = 0;
        while refs.lookup_announced(root).await.is_some() {
            asks += 1;
            assert!(asks < 100, "the hint never ends");
        }
        assert!(
            api.requests() <= usize::from(MAX_ANNOUNCED_FAILURES),
            "{} requests",
            api.requests()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_waiters_of_a_refused_round_share_its_answer() {
        let api = Reference::default();
        let (_, other, _) = gloas_block(11, &[[1; 48]]);
        api.serve_as([0x77; 32], 11, other);
        api.hang.send_replace(true);
        let refs = view(&api, RefLimits::default());
        let three = async {
            tokio::join!(
                refs.lookup([0x77; 32]),
                refs.lookup([0x77; 32]),
                refs.lookup([0x77; 32])
            )
        };
        let release = async {
            tokio::task::yield_now().await;
            api.hang.send_replace(false);
        };
        let ((a, b, c), ()) = tokio::join!(three, release);
        for refused in [a, b, c] {
            assert!(matches!(refused, Err(RefError::Block(_))), "{refused:?}");
        }
        assert_eq!(api.requests(), 2, "one header, one block, for all three");
    }

    #[tokio::test]
    async fn a_repeated_announcement_keeps_the_hint() {
        let api = Reference::default();
        let refs = view(&api, RefLimits::default());
        let (_, _, root) = gloas_block(9, &[[1; 48]]);
        refs.announce(root);
        for _ in 1..MAX_ANNOUNCED_FAILURES {
            assert!(refs.lookup_announced(root).await.unwrap().is_err());
        }
        // The block event again: the failures so far still count.
        refs.announce(root);
        assert!(refs.lookup_announced(root).await.unwrap().is_err());
        assert_eq!(refs.lookup_announced(root).await, None, "spent");
    }

    /// Polls until `done`, within a deadline of (paused) time.
    async fn until(done: impl Fn() -> bool) {
        let polled = tokio::time::timeout(Duration::from_secs(5), async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        polled
            .await
            .expect("the condition held before the deadline");
    }

    #[tokio::test(start_paused = true)]
    async fn a_shared_lookup_that_fails_keeps_its_root_for_the_waiters_retrying_it() {
        let api = Reference::default();
        let (_, ssz, root) = gloas_block(9, &[[1; 48]]);
        api.hang.send_replace(true);
        let refs = view(&api, RefLimits::default());
        // The first waiter runs the request; the reference does not know the root yet.
        let fails = refs.lookup(root);
        let retries = async {
            tokio::task::yield_now().await;
            refs.lookup(root).await
        };
        let drive = async {
            until(|| api.requests() == 1).await;
            api.passes.add_permits(1);
            // The first waiter's error; the second retries through the same lookup.
            until(|| api.requests() == 2).await;
            assert_eq!(
                refs.in_flight(),
                1,
                "the retrying waiter still holds the root"
            );
            // A new lookup of the root shares the retry rather than asking again.
            let joins = refs.lookup(root);
            let release = async {
                tokio::task::yield_now().await;
                assert_eq!(refs.in_flight(), 1);
                assert_eq!(api.requests(), 2, "one request in flight for the root");
                api.serve_as(root, 9, ssz);
                api.hang.send_replace(false);
            };
            tokio::join!(joins, release).0
        };
        let (failed, retried, joined) = tokio::join!(fails, retries, drive);
        assert!(matches!(failed, Err(RefError::Api(_))), "{failed:?}");
        assert_eq!(retried.unwrap().root, root);
        assert_eq!(joined.unwrap().root, root);
        assert_eq!(api.requests(), 3, "the retry's header, then its block");
        assert_eq!(refs.in_flight(), 0);
        assert_eq!(refs.cached(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_shared_lookup_that_times_out_keeps_its_root_for_the_waiters_retrying_it() {
        let api = Reference::default();
        let root = api.serve(9, 1);
        api.hang.send_replace(true);
        let limits = RefLimits {
            timeout: Duration::from_millis(500),
            ..RefLimits::default()
        };
        let refs = view(&api, limits);
        let times_out = refs.lookup(root);
        let retries = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            refs.lookup(root).await
        };
        let drive = async {
            // The first waiter timed out; the second retries through the same lookup.
            tokio::time::sleep(Duration::from_millis(550)).await;
            assert_eq!(api.requests(), 2);
            assert_eq!(
                refs.in_flight(),
                1,
                "the retrying waiter still holds the root"
            );
            let joins = refs.lookup(root);
            let release = async {
                tokio::task::yield_now().await;
                assert_eq!(refs.in_flight(), 1);
                assert_eq!(api.requests(), 2, "one request in flight for the root");
                api.hang.send_replace(false);
            };
            tokio::join!(joins, release).0
        };
        let (timed_out, retried, joined) = tokio::join!(times_out, retries, drive);
        assert_eq!(
            timed_out,
            Err(RefError::Timeout(Duration::from_millis(500)))
        );
        assert_eq!(retried.unwrap().root, root);
        assert_eq!(joined.unwrap().root, root);
        assert_eq!(refs.in_flight(), 0);
        assert_eq!(refs.cached(), 1);
    }
}
