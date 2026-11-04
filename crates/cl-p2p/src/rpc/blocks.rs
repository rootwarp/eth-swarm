//! `BeaconBlocksByRange` v2 answers (#146): [`ByRangeResponder`] over a [`BlockSource`].

use super::inbound::StatusSource;
use super::metrics::RpcMetrics;
use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::EthSpec;
use futures::Stream;
use libp2p::PeerId;
use network_config::ForkName;
use p2p_wire::rpc::protocols::{Request, ResultCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// How long one IPC step of a block answer may take \[est\].
pub const BLOCK_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Which half of an answer a block comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Half {
    /// The finalized blocks: cl-store.
    Store,
    /// The blocks above the store's finalized slot: cl-chain.
    Chain,
}

/// Why a block lookup failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    /// The result code the answer ends with if nothing went out yet.
    pub code: ResultCode,
    /// The metric's `kind` label.
    pub kind: &'static str,
    /// What happened, for the log.
    pub why: String,
}

/// One stored block as a source hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedBlock {
    /// Its slot.
    pub slot: u64,
    /// `hash_tree_root(block.message)`.
    pub root: [u8; 32],
    /// The fork of its slot.
    pub fork: ForkName,
    /// Its SSZ, as stored.
    pub ssz: Vec<u8>,
}

/// One IPC step in flight.
pub type Lookup<T> = Pin<Box<dyn Future<Output = Result<T, Failed>> + Send>>;

/// The blocks of one half, read one at a time.
pub type Blocks = Pin<Box<dyn Stream<Item = Result<ServedBlock, Failed>> + Send>>;

/// Where the blocks of an answer come from.
pub trait BlockSource: Send + Sync + 'static {
    /// The store's finalized slot.
    fn finalized_slot(&self) -> Lookup<u64>;

    /// The canonical blocks of `[start, start + count)` from `half`, ascending.
    fn blocks(&self, half: Half, start: u64, count: u64) -> Lookup<Blocks>;
}

/// The start slot of the block serve window now, if known.
pub type WindowStart = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// Serves BeaconBlocksByRange v2 from a [`BlockSource`].
#[derive(Clone)]
pub struct ByRangeResponder {
    #[allow(dead_code)]
    source: Arc<dyn BlockSource>,
    #[allow(dead_code)]
    status: Arc<dyn StatusSource>,
    lookups: Arc<Semaphore>,
    #[allow(dead_code)]
    metrics: Option<RpcMetrics>,
    #[allow(dead_code)]
    window: Option<WindowStart>,
}

impl ByRangeResponder {
    /// Answers from `source`, its floor from `status`, at most `max_lookups` at once.
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
            lookups: Arc::new(Semaphore::new(max_lookups)),
            metrics,
            window: None,
        }
    }

    /// The same responder, warning when `earliest_available_slot` is above `window`'s start.
    #[must_use]
    pub fn with_window(mut self, window: WindowStart) -> Self {
        self.window = Some(window);
        self
    }

    /// Lookup slots free now.
    #[must_use]
    pub fn free_lookups(&self) -> usize {
        self.lookups.available_permits()
    }
}

impl<E: EthSpec> Responder<E> for ByRangeResponder {
    fn serve(&self, _: PeerId, _: Request, _: ChunkSink<E>) -> Serving {
        Box::pin(async { todo!("#146 step 6") })
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
                    Call::Head => None,
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
