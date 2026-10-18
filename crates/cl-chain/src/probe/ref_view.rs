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
//!   [`RefError::Timeout`];
//! - at most `max_in_flight` roots are being looked up at once, and at most that many requests
//!   run against the reference. Lookups of a root already in flight share its request; a new root
//!   while the set is full is [`RefError::Busy`] at once, never queued;
//! - at most `max_cached` resolved roots are kept, the oldest evicted first. A root the reference
//!   does not know is not cached: it may know it a moment later.
//!
//! [`RefView::seed`] puts a block the node already holds (the checkpoint anchor that two
//! providers agreed on) into the cache without asking the reference.

use super::{ApiError, ReferenceApi, Root, DEFAULT_API_TIMEOUT};
use consensus_types::primitives::{KZGCommitment, Slot};
use consensus_types::{forked, gloas, EthSpec, ForkSchedule};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{OnceCell, Semaphore};
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
    /// The bid's `blob_kzg_commitments`.
    pub commitments: Vec<KZGCommitment>,
}

impl RefBlock {
    fn of<E: EthSpec>(root: Root, block: &gloas::BeaconBlock<E>) -> Self {
        let bid = &block.body.signed_execution_payload_bid.message;
        Self {
            root,
            slot: block.slot,
            commitments: bid.blob_kzg_commitments.iter().copied().collect(),
        }
    }
}

/// The bounds of a [`RefView`] (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefLimits {
    /// The most one lookup may take, header and block together.
    pub timeout: Duration,
    /// Roots looked up at once, and requests running against the reference.
    pub max_in_flight: usize,
    /// Resolved roots kept.
    pub max_cached: usize,
}

impl Default for RefLimits {
    /// [`DEFAULT_API_TIMEOUT`], 16 in flight, 64 cached (two mainnet epochs of blocks) \[est\].
    fn default() -> Self {
        Self {
            timeout: DEFAULT_API_TIMEOUT,
            max_in_flight: 16,
            max_cached: 64,
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

type Lookup = Arc<OnceCell<Arc<RefBlock>>>;

#[derive(Default)]
struct State {
    cached: HashMap<Root, Arc<RefBlock>>,
    /// Insertion order of `cached`, oldest first.
    order: VecDeque<Root>,
    in_flight: HashMap<Root, Lookup>,
}

/// The reference node's view of block roots (see the module docs).
pub struct RefView<A, E> {
    api: A,
    schedule: ForkSchedule,
    limits: RefLimits,
    requests: Semaphore,
    state: Mutex<State>,
    spec: PhantomData<fn() -> E>,
}

impl<A: ReferenceApi + BlockApi, E: EthSpec> RefView<A, E> {
    /// A view of `api`, decoding blocks by `schedule`.
    pub fn new(api: A, schedule: ForkSchedule, limits: RefLimits) -> Self {
        Self {
            api,
            schedule,
            limits,
            requests: Semaphore::new(limits.max_in_flight),
            state: Mutex::default(),
            spec: PhantomData,
        }
    }

    /// The block `root` as the reference vouches for it.
    ///
    /// # Errors
    ///
    /// [`RefError`]: the root is not vouched for, or not within the bounds.
    pub async fn lookup(&self, root: Root) -> Result<Arc<RefBlock>, RefError> {
        let lookup = {
            let mut state = self.state();
            if let Some(block) = state.cached.get(&root) {
                return Ok(Arc::clone(block));
            }
            match state.in_flight.get(&root) {
                Some(lookup) => Arc::clone(lookup),
                None if state.in_flight.len() >= self.limits.max_in_flight => {
                    return Err(RefError::Busy(state.in_flight.len()));
                }
                None => Arc::clone(state.in_flight.entry(root).or_default()),
            }
        };
        let timeout = self.limits.timeout;
        let result = tokio::time::timeout(timeout, lookup.get_or_try_init(|| self.fetch(root)))
            .await
            .unwrap_or(Err(RefError::Timeout(timeout)))
            .cloned();
        let mut state = self.state();
        if state
            .in_flight
            .get(&root)
            .is_some_and(|l| Arc::ptr_eq(l, &lookup))
        {
            state.in_flight.remove(&root);
        }
        if let Ok(block) = &result {
            state.cache(Arc::clone(block), self.limits.max_cached);
        }
        result
    }

    /// Caches `block`, which the node already holds and trusts, without asking the reference;
    /// returns its root.
    pub fn seed(&self, block: &gloas::SignedBeaconBlock<E>) -> Root {
        let root = block.message.tree_hash_root().0;
        let block = Arc::new(RefBlock::of(root, &block.message));
        self.state().cache(block, self.limits.max_cached);
        root
    }

    /// Roots being looked up now.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.state().in_flight.len()
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A reference node from tables: headers and block SSZ by root. `hang` makes every request
    /// wait forever.
    #[derive(Default)]
    struct Reference {
        headers: Mutex<HashMap<Root, Header>>,
        blocks: Mutex<HashMap<Root, Vec<u8>>>,
        hang: AtomicBool,
        requests: AtomicUsize,
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
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
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
        let block = refs.lookup(root).await.unwrap();
        assert_eq!(
            *block,
            RefBlock {
                root,
                slot: 9,
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
        api.hang.store(true, Ordering::SeqCst);
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
        api.hang.store(true, Ordering::SeqCst);
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
}
