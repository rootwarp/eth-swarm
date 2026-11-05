//! `BeaconBlocksByRange` v2 answers (#146; `phase0/p2p-interface.md` L1485–1575,
//! `gloas/p2p-interface.md` L1356–1374): [`ByRangeResponder`], the production [`Responder`],
//! over a [`BlockSource`] ([`super::blocks_ipc::IpcBlocks`] in the service). cl-p2p opens no
//! database: the finalized blocks come from cl-store (store.v1), the rest from cl-chain
//! (chain.v1, ADR-006).
//!
//! # An answer
//!
//! [`super::inbound::Control`] has checked the request already: `step` 0 or `count` over 128
//! is `1: InvalidRequest`, never clamped, and `count` 0 is never served. Then, on the answer's
//! own task:
//!
//! 1. **The floor**: a `start_slot` below our Status's `earliest_available_slot` (the cached
//!    Status peers pick us by) is `3: ResourceUnavailable` before any IPC call (L1538–1541);
//!    with no Status of ours it is `2: ServerError`. When the floor is above the start of the
//!    block serve window (`network_config::window`, L1527–1530: the node is not compliant
//!    until it backfilled), that is logged once and shown in `rpc_block_window_gap_slots`.
//! 2. **A lookup slot**: at most [`super::limits::RpcLimits::max_block_lookups`] answers hold
//!    IPC calls at once; one past them waits for a slot up to [`BLOCK_LOOKUP_TIMEOUT`], then
//!    is `2`.
//! 3. **The split**: the store's finalized slot `F0`, read first ([`BlockSource::finalized_slot`],
//!    cl-store's `GetChainHead.finalized_slot`). The blocks of `[start, min(end, F0 + 1))` come
//!    from cl-store, then those of `[max(start, F0 + 1), end)` from cl-chain, each half asked
//!    for only if it is not empty. Finality only advances and cl-store is never ahead of
//!    cl-chain, so a later store read still holds every finalized block up to `F0`, and
//!    cl-chain's head descends from `F0`'s block: no gap and no duplicate, whatever finality
//!    does meanwhile. A start more than [`MAX_FINALIZED_DEPTH`] below `F0` is
//!    `3: ResourceUnavailable` before cl-store is asked (counted as `{store, depth}`): its walk
//!    down from `F0` costs a block per slot whatever `count` is.
//! 4. **One chain**: blocks go out in ascending slot order inside the range, each block's
//!    `parent_root` the root of the block before it (L1558–1572). A block that breaks that ends
//!    the answer at the last whole chunk (L1574–1575: the view changed), counted, never an
//!    error chunk mid-stream; before the first chunk such a block breaks the contract: `2`.
//! 5. **Bytes as stored**: each block is decoded by the fork of its slot (the envelope's, checked
//!    by the source) and handed to the sink, which re-encodes it and picks its context bytes,
//!    the digest of its own epoch ([`super::responder`]): codec only, no state transition.
//!
//! `step` above 1 is answered with at most the block at `start_slot` (L1514–1515), and costs
//! one token. A failed lookup ([`Failed`]: cl-store's `UNAVAILABLE` and cl-chain's
//! `RESOURCE_UNAVAILABLE` are `3`, any other failure, a contract break or a step past its
//! timeout `2`) ends the answer with its code before the first chunk, and cleanly at the last
//! whole chunk after it; each is counted in `rpc_block_lookup_failures_total{half, kind}`.

use super::columns::fixed_message;
use super::inbound::StatusSource;
use super::metrics::RpcMetrics;
use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::{forked, EthSpec};
use futures::{Stream, StreamExt as _};
use libp2p::PeerId;
use network_config::ForkName;
use p2p_wire::rpc::messages::BlocksByRangeV2Request;
use p2p_wire::rpc::protocols::{Request, Response, ResultCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// How long one IPC step of a block answer may take \[est\]: 2 s, as a column lookup
/// ([`super::inbound::COLUMN_LOOKUP_TIMEOUT`]) and cl-chain's read deadline. Each step (the
/// head read, opening a half's stream, each block of it) has its own; the stream's writer cuts
/// the whole answer at the first-byte and total deadlines.
pub const BLOCK_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// How far below the store's finalized slot `F0` a range may start \[est\]: 2,048 slots (64
/// epochs of 32 slots, about 6.8 hours). An answer costs `count` tokens, but cl-store reads the
/// finalized half by walking the parents down from its finalized block, one stored block per
/// slot between `F0` and `start_slot` whatever `count` is, so uncapped a one-token request
/// deep in history walks all of it. A start below `F0 - MAX_FINALIZED_DEPTH` is
/// `3: ResourceUnavailable` before cl-store is asked: bounded work per request until a
/// finalized slot index (slot to root) lands, which reaches any depth in one lookup. cl-store
/// refuses the same depth itself (`cl_store::MAX_FINALIZED_DEPTH`; `tests/byrange_serve.rs`
/// pins the two together).
pub const MAX_FINALIZED_DEPTH: u64 = 2_048;

/// Which half of an answer a block comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Half {
    /// The finalized blocks, and the split point: cl-store.
    Store,
    /// The blocks above the store's finalized slot: cl-chain.
    Chain,
}

impl Half {
    /// The metric's `half` label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Chain => "chain",
        }
    }
}

/// Why a block lookup failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    /// The result code the answer ends with if nothing went out yet.
    pub code: ResultCode,
    /// The metric's `kind` label: `status` (the call failed), `refused` (an error chunk),
    /// `contract`, `timeout`, `order`, `link`, `decode` or `depth` (a start too far below `F0`).
    pub kind: &'static str,
    /// What happened, for the log.
    pub why: String,
}

impl Failed {
    /// `2: ServerError` of `kind`.
    #[must_use]
    pub fn server_error(kind: &'static str, why: impl Into<String>) -> Self {
        Self {
            code: ResultCode::ServerError,
            kind,
            why: why.into(),
        }
    }
}

/// One stored block as a source hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedBlock {
    /// Its slot.
    pub slot: u64,
    /// `hash_tree_root(block.message)`.
    pub root: [u8; 32],
    /// The fork of its slot: the shape it is decoded with.
    pub fork: ForkName,
    /// Its SSZ, as stored.
    pub ssz: Vec<u8>,
}

/// One IPC step in flight.
pub type Lookup<T> = Pin<Box<dyn Future<Output = Result<T, Failed>> + Send>>;

/// The blocks of one half, read one at a time as the answer goes out (never collected), so a
/// slow reader holds the IPC stream back through the sink. Dropping it cancels the call.
pub type Blocks = Pin<Box<dyn Stream<Item = Result<ServedBlock, Failed>> + Send>>;

/// Where the blocks of an answer come from (see the module docs).
pub trait BlockSource: Send + Sync + 'static {
    /// The store's finalized slot `F0`.
    fn finalized_slot(&self) -> Lookup<u64>;

    /// The canonical blocks of `[start, start + count)` from `half`, ascending.
    fn blocks(&self, half: Half, start: u64, count: u64) -> Lookup<Blocks>;

    /// The block at `root` and its ancestors, newest first, at most `count` (#230).
    fn by_head(&self, root: [u8; 32], count: u64) -> Lookup<Blocks>;
}

/// The start slot of the block serve window now, if known.
pub type WindowStart = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// Serves BeaconBlocksByRange v2 from a [`BlockSource`] (see the module docs).
#[derive(Clone)]
pub struct ByRangeResponder {
    source: Arc<dyn BlockSource>,
    status: Arc<dyn StatusSource>,
    lookups: Arc<Semaphore>,
    metrics: Option<RpcMetrics>,
    window: Option<WindowStart>,
    /// Whether the floor above the window's start was logged.
    warned: Arc<AtomicBool>,
    /// The deepest start below `F0` served ([`MAX_FINALIZED_DEPTH`]).
    max_depth: u64,
}

impl ByRangeResponder {
    /// Answers from `source`, its floor our Status's from `status`, at most `max_lookups`
    /// answers holding IPC calls at once, its failures counted in `metrics`.
    #[must_use]
    pub fn new(
        source: Arc<dyn BlockSource>,
        status: Arc<dyn StatusSource>,
        max_lookups: usize,
        metrics: Option<RpcMetrics>,
    ) -> Self {
        Self {
            source,
            status,
            lookups: Arc::new(Semaphore::new(max_lookups.min(Semaphore::MAX_PERMITS))),
            metrics,
            window: None,
            warned: Arc::default(),
            max_depth: MAX_FINALIZED_DEPTH,
        }
    }

    /// The same responder, serving starts at most `depth` slots below `F0`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_max_depth(mut self, depth: u64) -> Self {
        self.max_depth = depth;
        self
    }

    /// The same responder, comparing its floor with `window`'s start (see the module docs).
    #[must_use]
    pub fn with_window(mut self, window: WindowStart) -> Self {
        self.window = Some(window);
        self
    }

    /// The BeaconBlocksByHead responder (#230): not yet.
    #[must_use]
    pub fn head_responder(&self) -> super::blocks_head::ByHeadResponder {
        todo!("#230")
    }

    /// Lookup slots free now.
    #[must_use]
    pub fn free_lookups(&self) -> usize {
        self.lookups.available_permits()
    }

    /// Counts and logs `failed` of `half`, and hands it back.
    fn failed(&self, half: Half, failed: Failed) -> Failed {
        tracing::debug!(half = half.label(), kind = failed.kind, why = %failed.why,
            "block lookup failed");
        if let Some(metrics) = &self.metrics {
            metrics.block_lookup_failed(half.label(), failed.kind);
        }
        failed
    }

    /// Compares the floor `eas` with the serve window's start.
    fn check_window(&self, eas: u64) {
        let Some(start) = self.window.as_ref().and_then(|window| window()) else {
            return;
        };
        if let Some(metrics) = &self.metrics {
            metrics.set_block_window_gap(eas.saturating_sub(start));
        }
        if eas > start && !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                earliest_available_slot = eas,
                window_start = start,
                "blocks are served from above the start of the block serve window: ranges \
                 below earliest_available_slot get 3: ResourceUnavailable until backfill"
            );
        }
    }

    /// The answer to `range` into `out` (see the module docs).
    async fn answer<E: EthSpec>(
        &self,
        range: BlocksByRangeV2Request,
        out: &mut Out<E>,
    ) -> Result<(), Failed> {
        let eas = self
            .status
            .status()
            .ok_or_else(|| Failed::server_error("status", "no Status of ours"))?
            .earliest_available_slot;
        if range.start_slot < eas {
            return Err(Failed {
                code: ResultCode::ResourceUnavailable,
                kind: "floor",
                why: format!(
                    "start_slot {} below earliest_available_slot {eas}",
                    range.start_slot
                ),
            });
        }
        self.check_window(eas);
        let count = if range.step > 1 {
            range.count.min(1)
        } else {
            range.count
        };
        let (start, end) = (range.start_slot, range.start_slot.saturating_add(count));
        let slot = Arc::clone(&self.lookups).acquire_owned();
        let Ok(Ok(_slot)) = tokio::time::timeout(BLOCK_LOOKUP_TIMEOUT, slot).await else {
            return Err(Failed::server_error("busy", "no lookup slot in time"));
        };
        let finalized = self.source.finalized_slot().await;
        let finalized = finalized.map_err(|f| self.failed(Half::Store, f))?;
        if start < finalized.saturating_sub(self.max_depth) {
            let why = format!(
                "start_slot {start} more than {} slots below F0 {finalized}",
                self.max_depth
            );
            let deep = Failed {
                code: ResultCode::ResourceUnavailable,
                kind: "depth",
                why,
            };
            return Err(self.failed(Half::Store, deep));
        }
        let split = finalized.saturating_add(1);
        if start < split {
            self.half(out, Half::Store, start, end.min(split)).await?;
        }
        if end > split {
            self.half(out, Half::Chain, start.max(split), end).await?;
        }
        Ok(())
    }

    /// The blocks of `[start, end)` from `half`, sent as they come.
    async fn half<E: EthSpec>(
        &self,
        out: &mut Out<E>,
        half: Half,
        start: u64,
        end: u64,
    ) -> Result<(), Failed> {
        let opened = self.source.blocks(half, start, end - start).await;
        let mut blocks = opened.map_err(|f| self.failed(half, f))?;
        while let Some(next) = blocks.next().await {
            let block = next.and_then(|b| out.check(b, start, end));
            let response = block.map_err(|f| self.failed(half, f))?;
            if out.sink.send(response).await.is_err() {
                return Err(Failed::server_error("closed", "the answer has ended"));
            }
            out.sent += 1;
        }
        Ok(())
    }
}

/// One answer on its way out.
struct Out<E: EthSpec> {
    sink: ChunkSink<E>,
    /// Chunks sent.
    sent: usize,
    /// The slot and root of the block sent last.
    last: Option<(u64, [u8; 32])>,
}

impl<E: EthSpec> Out<E> {
    /// `block` as the next chunk of `[start, end)`, if it is: after the last block, inside the
    /// range, on the last block, decoded in its fork.
    fn check(&mut self, block: ServedBlock, start: u64, end: u64) -> Result<Response<E>, Failed> {
        let after = self.last.is_none_or(|(slot, _)| block.slot > slot);
        if !after || !(start..end).contains(&block.slot) {
            let why = format!(
                "slot {} out of order or outside [{start}, {end})",
                block.slot
            );
            return Err(Failed::server_error("order", why));
        }
        let decoded =
            forked::SignedBeaconBlock::<E>::from_ssz_bytes_for_fork(&block.ssz, block.fork)
                .map_err(|e| {
                    Failed::server_error("decode", format!("slot {}: {e:?}", block.slot))
                })?;
        let parent = match &decoded {
            forked::SignedBeaconBlock::Fulu(b) => b.message.parent_root.0,
            forked::SignedBeaconBlock::Gloas(b) => b.message.parent_root.0,
        };
        if decoded.slot() != block.slot {
            return Err(Failed::server_error("decode", "a block of another slot"));
        }
        if self.last.is_some_and(|(_, root)| root != parent) {
            let why = format!("slot {}: parent_root is not the block before", block.slot);
            return Err(Failed::server_error("link", why));
        }
        self.last = Some((block.slot, block.root));
        Ok(Response::Block(Box::new(decoded)))
    }

    /// Ends the answer on `failed`: its error chunk if nothing went out, else at the last whole
    /// chunk.
    async fn end(&mut self, failed: Failed) {
        if self.sent == 0 {
            let _ = self
                .sink
                .error(failed.code, fixed_message(failed.code).as_bytes())
                .await;
        }
    }
}

impl<E: EthSpec> Responder<E> for ByRangeResponder {
    /// `count`, or one token for `step` above 1 (one block at most).
    fn cost(&self, request: &Request) -> u64 {
        match request {
            Request::BlocksByRange(range) if range.step > 1 => range.count.min(1),
            other => other.max_response_chunks(),
        }
    }

    fn serve(&self, _: PeerId, request: Request, sink: ChunkSink<E>) -> Serving {
        let this = self.clone();
        Box::pin(async move {
            let Request::BlocksByRange(range) = request else {
                return;
            };
            let mut out = Out {
                sink,
                sent: 0,
                last: None,
            };
            if let Err(failed) = this.answer(range, &mut out).await {
                out.end(failed).await;
            }
        })
    }
}

/// The #146 fixture: a linked Fulu→Gloas chain on the minimal preset, matching
/// [`super::responder::testing::serving_table`] (Fulu from epoch 0, its BPO digest from 2,
/// Gloas from 4), and a [`BlockSource`] over it that counts its calls per half.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use consensus_types::{forked, Minimal};
    use ssz::Encode;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// The skipped slots, the fork block's slot among them (off the head's chain).
    pub(crate) const SKIPPED: [u64; 4] = [5, 17, 33, 36];
    /// The head's slot.
    pub(crate) const HEAD: u64 = 40;
    /// The store's finalized slot.
    pub(crate) const FINALIZED: u64 = 20;

    /// A block at `slot` on `parent`: Fulu before epoch 4, Gloas from it; `salt` makes
    /// siblings differ.
    pub(crate) fn block(slot: u64, parent: [u8; 32], salt: u64) -> ServedBlock {
        let block = if slot < 32 {
            let mut b = p2p_wire::testkit::fulu_block::<Minimal>(slot);
            b.message.parent_root = parent.into();
            b.message.proposer_index = salt;
            forked::SignedBeaconBlock::Fulu(b)
        } else {
            let mut b = p2p_wire::testkit::gloas_block::<Minimal>(slot);
            b.message.parent_root = parent.into();
            b.message.proposer_index = salt;
            forked::SignedBeaconBlock::Gloas(b)
        };
        ServedBlock {
            slot,
            root: block.message_root().0,
            fork: block.fork_name(),
            ssz: block.as_ssz_bytes(),
        }
    }

    /// The canonical chain: slots 1 to [`HEAD`] but [`SKIPPED`], each on the one before.
    pub(crate) fn chain() -> Vec<ServedBlock> {
        let mut chain: Vec<ServedBlock> = Vec::new();
        for slot in (1..=HEAD).filter(|s| !SKIPPED.contains(s)) {
            let parent = chain.last().map_or([0; 32], |b| b.root);
            chain.push(block(slot, parent, 0));
        }
        chain
    }

    /// The `parent_root` of `block`, decoded in its fork.
    pub(crate) fn parent_of(block: &ServedBlock) -> [u8; 32] {
        let decoded =
            forked::SignedBeaconBlock::<Minimal>::from_ssz_bytes_for_fork(&block.ssz, block.fork)
                .unwrap();
        match decoded {
            forked::SignedBeaconBlock::Fulu(b) => b.message.parent_root.0,
            forked::SignedBeaconBlock::Gloas(b) => b.message.parent_root.0,
        }
    }

    /// The canonical block at `slot`.
    pub(crate) fn at(slot: u64) -> ServedBlock {
        chain().into_iter().find(|b| b.slot == slot).unwrap()
    }

    /// The slots of the canonical blocks of `[start, end)`.
    pub(crate) fn canonical(start: u64, end: u64) -> Vec<u64> {
        chain()
            .iter()
            .map(|b| b.slot)
            .filter(|s| (start..end).contains(s))
            .collect()
    }

    /// Where a scripted act happens.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) enum Step {
        /// The finalized slot's read.
        Head,
        /// Opening a half's stream.
        Open(Half),
        /// The `n`th block of a half's stream.
        Item(Half, usize),
    }

    /// What happens there.
    #[derive(Debug, Clone)]
    pub(crate) enum Act {
        /// Nothing, for good.
        Stall,
        /// This failure.
        Fail(Failed),
    }

    /// One call of the source.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Call {
        Head,
        Range(Half, u64, u64),
        /// A parent walk from a root, of at most `count` blocks (#230).
        ByHead([u8; 32], u64),
    }

    #[derive(Default)]
    struct State {
        finalized: AtomicU64,
        /// After a head read, the finalized slot moves here.
        advance_to: Mutex<Option<u64>>,
        calls: Mutex<Vec<Call>>,
        /// Streams (and lookups) alive.
        open: AtomicUsize,
        script: Mutex<HashMap<Step, Act>>,
        /// Blocks the chain half serves in place of the canonical one at a slot.
        replaced: Mutex<Vec<(u64, ServedBlock)>>,
        /// What the store half takes per slot walked before it opens.
        walk_cost: Mutex<Option<Duration>>,
        /// Blocks the store holds besides [`chain`]'s (fork blocks), found by root.
        known: Mutex<Vec<ServedBlock>>,
        /// Blocks a parent walk sends in place of its `n`th.
        walk_replaced: Mutex<Vec<(usize, ServedBlock)>>,
        /// How many blocks past its `count` a parent walk sends.
        overserve: AtomicU64,
        /// The blocks parent walks handed over so far.
        walk_reads: AtomicUsize,
    }

    /// A [`BlockSource`] over [`chain`]: the store half holds the blocks at or below its
    /// finalized slot, the chain half every canonical block.
    #[derive(Clone)]
    pub(crate) struct Fake(Arc<State>);

    /// Held by whatever of the fake is alive.
    struct Open(Arc<State>);

    impl Drop for Open {
        fn drop(&mut self) {
            self.0.open.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Fake {
        /// The fixture with the store finalized at [`FINALIZED`].
        pub(crate) fn new() -> Self {
            let fake = Self(Arc::default());
            fake.0.finalized.store(FINALIZED, Ordering::SeqCst);
            fake
        }

        /// From the next head read on, the finalized slot moves to `slot` once it was read.
        pub(crate) fn advance_after_head(&self, slot: u64) {
            *self.0.advance_to.lock().unwrap() = Some(slot);
        }

        /// `act` at `step`, from now on.
        pub(crate) fn script(&self, step: Step, act: Act) {
            self.0.script.lock().unwrap().insert(step, act);
        }

        /// The chain half serves `block` in place of the canonical block at slot `at`.
        pub(crate) fn replace(&self, at: u64, block: ServedBlock) {
            self.0.replaced.lock().unwrap().push((at, block));
        }

        /// From now on the store half takes `per_slot` for each slot from its finalized slot
        /// down to the range's start before it opens, as cl-store's parent walk does.
        pub(crate) fn walk_cost(&self, per_slot: Duration) {
            *self.0.walk_cost.lock().unwrap() = Some(per_slot);
        }

        /// The store holds `block` too (off [`chain`]), found by its root.
        pub(crate) fn add(&self, block: ServedBlock) {
            self.0.known.lock().unwrap().push(block);
        }

        /// Parent walks send `block` in place of their `n`th block.
        pub(crate) fn replace_in_walk(&self, n: usize, block: ServedBlock) {
            self.0.walk_replaced.lock().unwrap().push((n, block));
        }

        /// Parent walks go on `extra` blocks past their `count`, as far as the parents reach.
        pub(crate) fn overserve(&self, extra: u64) {
            self.0.overserve.store(extra, Ordering::SeqCst);
        }

        /// The blocks parent walks handed over so far.
        pub(crate) fn walk_reads(&self) -> usize {
            self.0.walk_reads.load(Ordering::SeqCst)
        }

        /// The calls so far, and forgets them.
        pub(crate) fn calls(&self) -> Vec<Call> {
            std::mem::take(&mut *self.0.calls.lock().unwrap())
        }

        /// The range calls so far, and forgets every call.
        pub(crate) fn ranges(&self) -> Vec<(Half, u64, u64)> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Range(half, start, count) => Some((half, start, count)),
                    Call::Head | Call::ByHead(..) => None,
                })
                .collect()
        }

        /// Lookups and streams alive now.
        pub(crate) fn open(&self) -> usize {
            self.0.open.load(Ordering::SeqCst)
        }

        fn enter(&self) -> Open {
            self.0.open.fetch_add(1, Ordering::SeqCst);
            Open(Arc::clone(&self.0))
        }

        fn act(&self, step: Step) -> Option<Act> {
            self.0.script.lock().unwrap().get(&step).cloned()
        }
    }

    /// `act` as the result of a step, stalling for good on [`Act::Stall`].
    async fn acted<T>(act: Option<Act>) -> Option<Result<T, Failed>> {
        match act {
            None => None,
            Some(Act::Stall) => futures::future::pending().await,
            Some(Act::Fail(failed)) => Some(Err(failed)),
        }
    }

    impl BlockSource for Fake {
        fn finalized_slot(&self) -> Lookup<u64> {
            let (fake, live) = (self.clone(), self.enter());
            fake.0.calls.lock().unwrap().push(Call::Head);
            Box::pin(async move {
                let _live = live;
                if let Some(failed) = acted(fake.act(Step::Head)).await {
                    return failed;
                }
                let read = fake.0.finalized.load(Ordering::SeqCst);
                if let Some(to) = *fake.0.advance_to.lock().unwrap() {
                    fake.0.finalized.store(to, Ordering::SeqCst);
                }
                Ok(read)
            })
        }

        fn blocks(&self, half: Half, start: u64, count: u64) -> Lookup<Blocks> {
            let (fake, live) = (self.clone(), self.enter());
            fake.0
                .calls
                .lock()
                .unwrap()
                .push(Call::Range(half, start, count));
            Box::pin(async move {
                if let Some(failed) = acted(fake.act(Step::Open(half))).await {
                    return failed;
                }
                let end = start.saturating_add(count);
                let finalized = fake.0.finalized.load(Ordering::SeqCst);
                let cost = *fake.0.walk_cost.lock().unwrap();
                if let Some(per_slot) = cost.filter(|_| half == Half::Store) {
                    let walked = finalized.saturating_sub(start);
                    let walked = u32::try_from(walked).unwrap_or(u32::MAX);
                    tokio::time::sleep(per_slot.saturating_mul(walked)).await;
                }
                let replaced = fake.0.replaced.lock().unwrap().clone();
                let blocks: Vec<ServedBlock> = chain()
                    .into_iter()
                    .filter(|b| (start..end).contains(&b.slot))
                    .filter(|b| half == Half::Chain || b.slot <= finalized)
                    .map(|b| match replaced.iter().find(|(at, _)| *at == b.slot) {
                        Some((_, r)) if half == Half::Chain => r.clone(),
                        _ => b,
                    })
                    .collect();
                let items = futures::stream::unfold(
                    (0usize, blocks.into_iter(), fake, live),
                    move |(i, mut blocks, fake, live)| async move {
                        if let Some(failed) = acted(fake.act(Step::Item(half, i))).await {
                            return Some((failed, (i + 1, Vec::new().into_iter(), fake, live)));
                        }
                        let next = blocks.next()?;
                        Some((Ok(next), (i + 1, blocks, fake, live)))
                    },
                );
                Ok(Box::pin(items) as Blocks)
            })
        }

        /// The store's parent walk: the block at `root`, then its parent, while stored, ending
        /// after slot 0 or `count` blocks (plus [`Fake::overserve`]); scripted at
        /// `Open(Store)` and `Item(Store, n)`.
        fn by_head(&self, root: [u8; 32], count: u64) -> Lookup<Blocks> {
            let (fake, live) = (self.clone(), self.enter());
            fake.0.calls.lock().unwrap().push(Call::ByHead(root, count));
            Box::pin(async move {
                if let Some(failed) = acted(fake.act(Step::Open(Half::Store))).await {
                    return failed;
                }
                let mut known = chain();
                known.extend(fake.0.known.lock().unwrap().iter().cloned());
                let take = count.saturating_add(fake.0.overserve.load(Ordering::SeqCst));
                let mut walk = Vec::new();
                let mut next = Some(root);
                while let Some(at) = next.filter(|_| (walk.len() as u64) < take) {
                    let Some(block) = known.iter().find(|b| b.root == at).cloned() else {
                        break;
                    };
                    next = (block.slot > 0).then(|| parent_of(&block));
                    walk.push(block);
                }
                for (n, block) in fake.0.walk_replaced.lock().unwrap().iter() {
                    if let Some(item) = walk.get_mut(*n) {
                        *item = block.clone();
                    }
                }
                let items = futures::stream::unfold(
                    (0usize, walk.into_iter(), fake, live),
                    move |(i, mut walk, fake, live)| async move {
                        let step = Step::Item(Half::Store, i);
                        if let Some(failed) = acted(fake.act(step)).await {
                            return Some((failed, (i + 1, Vec::new().into_iter(), fake, live)));
                        }
                        let next = walk.next()?;
                        fake.0.walk_reads.fetch_add(1, Ordering::SeqCst);
                        Some((Ok(next), (i + 1, walk, fake, live)))
                    },
                );
                Ok(Box::pin(items) as Blocks)
            })
        }
    }

    /// A failure of `code`, `kind`.
    pub(crate) fn failed(code: ResultCode, kind: &'static str) -> Failed {
        Failed {
            code,
            kind,
            why: format!("scripted {kind}"),
        }
    }
}
