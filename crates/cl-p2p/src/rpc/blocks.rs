//! `BeaconBlocksByRange` v2 answers (#146; `phase0/p2p-interface.md` L1485–1575,
//! `gloas/p2p-interface.md` L1356–1374): [`ByRangeResponder`], the production [`Responder`],
//! over a [`BlockSource`] ([`super::blocks_ipc::IpcBlocks`] in the service). cl-p2p opens no
//! database: the finalized blocks come from cl-store (store.v1), the rest from cl-chain
//! (chain.v1, ADR-006). [`ByRangeResponder::head_responder`] builds the BeaconBlocksByHead
//! responder over the same source, lookup slots and window ([`super::blocks_head`], #230), and
//! [`ByRangeResponder::root_responder`] the BeaconBlocksByRoot one ([`super::blocks_root`]).
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
//!    A start below the window's start and at or below the highest `F0` read so far (finality
//!    only advances, so that is still finalized) is `3` too, at once (counted as
//!    `{store, window}`): expired finalized history.
//! 2. **A lookup slot**: at most [`super::limits::RpcLimits::max_block_lookups`] answers hold
//!    IPC calls at once; one past them waits for a slot up to [`BLOCK_LOOKUP_TIMEOUT`], then
//!    is `2`.
//! 3. **The split**: the store's finalized slot `F0`, read first ([`BlockSource::finalized_slot`],
//!    cl-store's `GetChainHead.finalized_slot`). A start below the window's start and at or
//!    below `F0` is `3` (`{store, window}`), the whole request, whatever of it reaches into the
//!    window: cl-store finds any range inside the window in its finalized slot index in one
//!    seek, so the window is the only floor below `F0`, and finalized history deeper than it is
//!    never asked for. The window does not account for finality (L1532–1536): a start above
//!    `F0` is served even below the window's start. The blocks of `[start, min(end, F0 + 1))`
//!    come from cl-store, then those of `[max(start, F0 + 1), end)` from cl-chain, each half
//!    asked for only if it is not empty. Finality only advances and cl-store is never ahead of
//!    cl-chain, so a later store read still holds every finalized block up to `F0`, and
//!    cl-chain's head descends from `F0`'s block: no gap and no duplicate, whatever finality
//!    does meanwhile. A start inside the window that cl-store has not indexed yet (its backfill
//!    still under way) is its `UNAVAILABLE`: `3`.
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

use super::blocks_head::{
    ByHeadResponder, StoreStreams, MAX_BYHEAD_STORE_STREAMS, MAX_BYHEAD_STORE_STREAMS_PER_IP,
};
use super::blocks_root::ByRootResponder;
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// How long one IPC step of a block answer may take \[est\]: 2 s, as a column lookup
/// ([`super::inbound::COLUMN_LOOKUP_TIMEOUT`]) and cl-chain's read deadline. Each step (the
/// head read, opening a half's stream, each block of it) has its own; the stream's writer cuts
/// the whole answer at the first-byte and total deadlines.
pub const BLOCK_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Which half of an answer a block comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Half {
    /// The finalized blocks, the split point and every parent walk: cl-store.
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
    /// `contract`, `timeout`, `order`, `link`, `decode` or `window` (a start in finalized
    /// history below the serve window).
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

    /// The block at `root` and its ancestors, newest first, at most `count`, from cl-store's
    /// parent walk (#230): none for a root it does not hold.
    fn by_head(&self, root: [u8; 32], count: u64) -> Lookup<Blocks>;

    /// What `half` serves of `roots`, in their order: cl-chain every block above its finalized
    /// slot, cl-store the finalized ones and the roots it holds above its own ([`RootItem`]).
    fn by_root(&self, half: Half, roots: Vec<[u8; 32]>) -> Lookup<RootItems>;
}

/// One item of a half's answer to a by-root lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootItem {
    /// A block it serves.
    Block(ServedBlock),
    /// A root cl-store holds above its finalized slot, not served (never cl-chain's).
    Unfinalized([u8; 32]),
}

/// One half's answer to a by-root lookup, read one item at a time (never collected): the
/// answer reads it only as far as the peer's send budget reaches, then drops it
/// ([`super::blocks_root`]), which cancels the call.
pub type RootItems = Pin<Box<dyn Stream<Item = Result<RootItem, Failed>> + Send>>;

/// The start slot of the block serve window now, if known; both block responders read it.
pub type WindowStart = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// `block` decoded by the fork of its slot, and its `parent_root`; one that does not decode,
/// or decodes to a block of another slot, is `2` (`decode`).
pub(super) fn decode<E: EthSpec>(
    block: &ServedBlock,
) -> Result<(forked::SignedBeaconBlock<E>, [u8; 32]), Failed> {
    let decoded =
        forked::SignedBeaconBlock::<E>::from_ssz_bytes_for_fork(&block.ssz, block.fork)
            .map_err(|e| Failed::server_error("decode", format!("slot {}: {e:?}", block.slot)))?;
    if decoded.slot() != block.slot {
        return Err(Failed::server_error("decode", "a block of another slot"));
    }
    let parent = match &decoded {
        forked::SignedBeaconBlock::Fulu(b) => b.message.parent_root.0,
        forked::SignedBeaconBlock::Gloas(b) => b.message.parent_root.0,
    };
    Ok((decoded, parent))
}

/// Serves BeaconBlocksByRange v2 from a [`BlockSource`] (see the module docs).
#[derive(Clone)]
pub struct ByRangeResponder {
    source: Arc<dyn BlockSource>,
    status: Arc<dyn StatusSource>,
    lookups: Arc<Semaphore>,
    metrics: Option<RpcMetrics>,
    window: Option<WindowStart>,
    /// The highest `F0` read so far: never above the store's finalized slot now, finality only
    /// advancing (0 before the first read: slot 0 is final whatever `F0` is).
    finalized: Arc<AtomicU64>,
    /// Whether the floor above the window's start was logged.
    warned: Arc<AtomicBool>,
    /// The store streams of the ByHead answers it builds ([`Self::head_responder`]).
    head_streams: StoreStreams,
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
            finalized: Arc::default(),
            warned: Arc::default(),
            head_streams: StoreStreams::new(
                MAX_BYHEAD_STORE_STREAMS,
                MAX_BYHEAD_STORE_STREAMS_PER_IP,
            ),
        }
    }

    /// The same responder, refusing starts in finalized history below `window`'s start and
    /// comparing its floor with it (see the module docs).
    #[must_use]
    pub fn with_window(mut self, window: WindowStart) -> Self {
        self.window = Some(window);
        self
    }

    /// The BeaconBlocksByHead responder over the same source, taking its lookup slots from
    /// this responder's pool, counting its failures in the same metrics and reading the same
    /// window (#230, D5, D7). Every one it builds shares one pool of store streams.
    #[must_use]
    pub fn head_responder(&self) -> ByHeadResponder {
        ByHeadResponder::new(
            Arc::clone(&self.source),
            Arc::clone(&self.lookups),
            self.head_streams.clone(),
            self.metrics.clone(),
            self.window.clone(),
        )
    }

    /// The BeaconBlocksByRoot responder over the same source, lookup slots, metrics and pool of
    /// store streams as [`Self::head_responder`]'s.
    #[must_use]
    pub fn root_responder(&self) -> ByRootResponder {
        ByRootResponder::new(
            Arc::clone(&self.source),
            Arc::clone(&self.lookups),
            self.head_streams.clone(),
            self.metrics.clone(),
        )
    }

    /// Lookup slots free now.
    #[must_use]
    pub fn free_lookups(&self) -> usize {
        self.lookups.available_permits()
    }

    /// The store streams its ByHead answers hold now.
    #[cfg(test)]
    pub(crate) fn held_store_streams(&self) -> usize {
        self.head_streams.held()
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

    /// Compares the floor `eas` with the serve window's start, if known.
    fn check_window(&self, eas: u64, start: Option<u64>) {
        let Some(start) = start else {
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

    /// `3` for `start`, below the serve window's start `window` and at or below the finalized
    /// slot `finalized`: expired finalized history, counted as `{store, window}`.
    fn expired(&self, start: u64, window: u64, finalized: u64) -> Failed {
        let why = format!(
            "start_slot {start} below the serve window's start {window}, at or below F0 \
             {finalized}"
        );
        let expired = Failed {
            code: ResultCode::ResourceUnavailable,
            kind: "window",
            why,
        };
        self.failed(Half::Store, expired)
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
        let window = self.window.as_ref().and_then(|window| window());
        self.check_window(eas, window);
        // Below the window only finalized history is refused: at once when an `F0` read before
        // proves the start finalized, else once `F0` is read.
        let below = window.filter(|start| range.start_slot < *start);
        let known = self.finalized.load(Ordering::Relaxed);
        if let Some(window) = below.filter(|_| range.start_slot <= known) {
            return Err(self.expired(range.start_slot, window, known));
        }
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
        self.finalized.fetch_max(finalized, Ordering::Relaxed);
        if let Some(window) = below.filter(|_| start <= finalized) {
            return Err(self.expired(start, window, finalized));
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
pub(super) struct Out<E: EthSpec> {
    pub(super) sink: ChunkSink<E>,
    /// Chunks sent.
    pub(super) sent: usize,
    /// The slot and root of the block sent last.
    last: Option<(u64, [u8; 32])>,
}

impl<E: EthSpec> Out<E> {
    pub(super) fn new(sink: ChunkSink<E>) -> Self {
        Self {
            sink,
            sent: 0,
            last: None,
        }
    }

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
        let (decoded, parent) = decode::<E>(&block)?;
        if self.last.is_some_and(|(_, root)| root != parent) {
            let why = format!("slot {}: parent_root is not the block before", block.slot);
            return Err(Failed::server_error("link", why));
        }
        self.last = Some((block.slot, block.root));
        Ok(Response::Block(Box::new(decoded)))
    }

    /// Ends the answer on `failed`: its error chunk if nothing went out, else at the last whole
    /// chunk.
    pub(super) async fn end(&mut self, failed: Failed) {
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
            let mut out = Out::new(sink);
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
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Call {
        Head,
        Range(Half, u64, u64),
        /// A parent walk from a root, of at most `count` blocks (#230).
        ByHead([u8; 32], u64),
        /// A by-root lookup of one half.
        ByRoot(Half, Vec<[u8; 32]>),
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
        /// Blocks the store holds besides [`chain`]'s (fork blocks), found by root.
        known: Mutex<Vec<ServedBlock>>,
        /// Blocks the store holds as finalized besides [`chain`]'s, found by root.
        finalized_known: Mutex<Vec<ServedBlock>>,
        /// The roots of the blocks by-root lookups handed over, in order.
        root_reads: Mutex<Vec<[u8; 32]>>,
        /// Blocks a parent walk sends in place of its `n`th.
        walk_replaced: Mutex<Vec<(usize, ServedBlock)>>,
        /// How many blocks past its `count` a parent walk sends.
        overserve: AtomicU64,
        /// The blocks parent walks handed over so far.
        walk_reads: AtomicUsize,
        /// The finalized slots the store's next by-root lookups read, one each, before
        /// `finalized` again: a store behind the chain.
        store_lags: Mutex<std::collections::VecDeque<u64>>,
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

        /// The store's finalized slot is `slot` from now on.
        pub(crate) fn finalize_at(&self, slot: u64) {
            self.0.finalized.store(slot, Ordering::SeqCst);
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

        /// The store holds `block` too (off [`chain`]), found by its root.
        pub(crate) fn add(&self, block: ServedBlock) {
            self.0.known.lock().unwrap().push(block);
        }

        /// The store holds `block` as a finalized one (off [`chain`]), found by its root: its
        /// by-root lookups serve it at or below the finalized slot.
        pub(crate) fn add_finalized(&self, block: ServedBlock) {
            self.0.finalized_known.lock().unwrap().push(block);
        }

        /// The roots of the blocks by-root lookups handed over so far, in order, and forgets
        /// them.
        pub(crate) fn root_reads(&self) -> Vec<[u8; 32]> {
            std::mem::take(&mut *self.0.root_reads.lock().unwrap())
        }

        /// Parent walks send `block` in place of their `n`th block.
        pub(crate) fn replace_in_walk(&self, n: usize, block: ServedBlock) {
            self.0.walk_replaced.lock().unwrap().push((n, block));
        }

        /// Parent walks go on `extra` blocks past their `count`, as far as the parents reach.
        pub(crate) fn overserve(&self, extra: u64) {
            self.0.overserve.store(extra, Ordering::SeqCst);
        }

        /// The store's next by-root lookups read these finalized slots, one each.
        pub(crate) fn lag_store(&self, slots: impl IntoIterator<Item = u64>) {
            self.0.store_lags.lock().unwrap().extend(slots);
        }

        /// The by-root calls so far, and forgets every call.
        pub(crate) fn root_calls(&self) -> Vec<(Half, Vec<[u8; 32]>)> {
            self.calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::ByRoot(half, roots) => Some((half, roots)),
                    _ => None,
                })
                .collect()
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
                    Call::Head | Call::ByHead(..) | Call::ByRoot(..) => None,
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

        /// [`Fake::root_lookup`]'s items one at a time, each block counted in
        /// [`Fake::root_reads`] as it is handed over; scripted at `Open(half)` and
        /// `Item(half, n)`.
        fn by_root(&self, half: Half, roots: Vec<[u8; 32]>) -> Lookup<RootItems> {
            let (fake, live) = (self.clone(), self.enter());
            let call = Call::ByRoot(half, roots.clone());
            fake.0.calls.lock().unwrap().push(call);
            Box::pin(async move {
                if let Some(failed) = acted(fake.act(Step::Open(half))).await {
                    return failed;
                }
                let found = fake.root_lookup(half, &roots);
                let items = futures::stream::unfold(
                    (0usize, found.into_iter(), fake, live),
                    move |(i, mut found, fake, live)| async move {
                        if let Some(failed) = acted(fake.act(Step::Item(half, i))).await {
                            return Some((failed, (i + 1, Vec::new().into_iter(), fake, live)));
                        }
                        let next = found.next()?;
                        if let RootItem::Block(block) = &next {
                            fake.0.root_reads.lock().unwrap().push(block.root);
                        }
                        Some((Ok(next), (i + 1, found, fake, live)))
                    },
                );
                Ok(Box::pin(items) as RootItems)
            })
        }
    }

    impl Fake {
        /// The chain half: every block of `roots` held above the finalized slot (any branch,
        /// [`Fake::replace`]d); the store half: the canonical ones (or
        /// [`Fake::add_finalized`]) at or below its finalized slot, and the roots held above
        /// it. In the order of `roots`.
        fn root_lookup(&self, half: Half, roots: &[[u8; 32]]) -> Vec<RootItem> {
            let mut known = chain();
            known.extend(self.0.known.lock().unwrap().iter().cloned());
            let held_final = self.0.finalized_known.lock().unwrap().clone();
            known.extend(held_final.iter().cloned());
            let lag = match half {
                Half::Store => self.0.store_lags.lock().unwrap().pop_front(),
                Half::Chain => None,
            };
            let finalized = lag.unwrap_or_else(|| self.0.finalized.load(Ordering::SeqCst));
            let (canonical, replaced) = (chain(), self.0.replaced.lock().unwrap().clone());
            let mut answer = Vec::new();
            for root in roots {
                let Some(block) = known.iter().find(|b| b.root == *root).cloned() else {
                    continue;
                };
                let swap = replaced.iter().find(|(at, _)| *at == block.slot);
                match half {
                    Half::Chain if block.slot > finalized => {
                        answer.push(RootItem::Block(swap.map_or(block, |(_, r)| r.clone())));
                    }
                    Half::Store if block.slot > finalized => {
                        answer.push(RootItem::Unfinalized(*root));
                    }
                    Half::Store if canonical.contains(&block) || held_final.contains(&block) => {
                        answer.push(RootItem::Block(block));
                    }
                    _ => {}
                }
            }
            answer
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
