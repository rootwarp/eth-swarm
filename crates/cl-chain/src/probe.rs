//! Probe mode: what cl-chain does while it imports nothing of its own. It vouches for nothing
//! itself; the reference node's Beacon API ([`BeaconApi`]) is trusted for block roots only.
//!
//! - **Status** ([`StatusProvider`]): what cl-chain hands cl-p2p over
//!   `ethswarm.chain.v1.ReqRespService/GetStatus` (below).
//! - **Storage contract** ([`storage_contract`]): a gossip column sidecar is stored only if the
//!   reference vouches for its block root ([`RefView`]), its cells verify by KZG through
//!   cl-verify against the bid's `blob_kzg_commitments`, and its index and subnet are a custody
//!   column. Anything else is dropped and counted (`probe_column_dropped_total{reason}`); see
//!   [`column`] for the order of the checks and the reasons.
//! - **Column store** ([`ColumnIngest`]): gossip column sidecars from cl-p2p, through a
//!   bounded pending queue and a bounded wait for their block root, then the storage contract,
//!   written on the `columns-writer` thread. Forward only, from `cgc_set_slot`; the first stored
//!   slot ([`first_stored_column_slot`]) is persisted with the columns. Every column is reported
//!   IGNORE, so nothing is re-broadcast; see [`ingest`].
//!
//! # Status
//!
//! - `fork_digest`: `compute_fork_digest(genesis_validators_root, epoch)` at the **wall-clock**
//!   epoch of the pinned network config (`phase0/p2p-interface.md` Status: "the node's current
//!   epoch defined by the wall-clock time"), BPO epochs included. It never comes from the
//!   reference API, so it moves with the clock even while the API is down.
//! - `finalized`: the reference Beacon API's finalized checkpoint
//!   (`/eth/v1/beacon/states/head/finality_checkpoints`).
//! - `head_root`, `head_slot`: the finalized block's header (`/eth/v1/beacon/headers/{root}`).
//!   The probe advertises the newest block it can vouch for, not the reference node's head: it
//!   imports nothing past finality, so a later head would claim blocks it cannot serve.
//! - `earliest_available_slot`: once the probe serves its custody columns
//!   ([`StatusProvider::serving_columns`]), the slot it serves them from
//!   ([`crate::reqresp::ColumnServer::earliest_available_slot`]): [`earliest_servable_slot`],
//!   the highest of the first stored column slot, the slot after the finalized-slot watermark,
//!   `cgc_set_slot` and the store's contiguous-from slot, never the first stored slot alone (a
//!   historical minimum that pruning leaves below the data). A node storing forward from the
//!   slot its `cgc` was set at advertises that slot (`fulu/p2p-interface.md` L552–561,
//!   `fulu/validator.md` L173–175). Until a column is stored, and without a column store,
//!   `head_slot`.
//!
//!   **Deviation: it may sit above `head_slot`.** The probe's head is its finalized block, two
//!   to three epochs behind the wall clock, while it stores columns from the slot it started
//!   at, so for those epochs after a first start `earliest_available_slot > head_slot`. The spec
//!   defines it as "The slot of earliest available block" (L558–559) and states no relation to
//!   `head_slot`; clamping it to `head_slot + 1` would claim slots the probe cannot serve, so it
//!   is not clamped.
//!
//! Each [`StatusProvider::status`] samples the API under a bounded timeout. A sample that fails
//! or times out (an outage) keeps the last good one; with none yet, the Status is
//! [`ProbeError::Unavailable`], which the RPC answers `UNAVAILABLE` and cl-p2p treats as "no
//! Status": it sends none and judges none, never a guessed one.
//!
//! The kept sample only moves forward: a sample whose finalized epoch or head slot is below the
//! kept one's is ignored (and the kept one answered). Overlapping calls can finish out of order,
//! a slow one with an older answer after a fast one with a newer answer, and the Status we
//! advertise must never move back.

mod beacon_api;
pub mod column;
pub mod ingest;
mod ref_view;
mod root_wait;

pub use beacon_api::BeaconApi;
pub use column::{
    storage_contract, store_verified, ColumnContract, ColumnMetrics, Drop, GossipColumn, Verified,
};
pub use ingest::{
    earliest_servable_slot, first_stored_column_slot, ColumnIngest, IngestLimits, LimitsError,
    QueueMetrics, COLUMN_BUFFER_ALERT_BYTES, DEFAULT_FIRST_ASKS_PER_SEC, DEFAULT_FIRST_ASK_BURST,
    DEFAULT_MAX_ASKING_COLUMNS, DEFAULT_MAX_WAITING_COLUMNS, DEFAULT_MAX_WAITING_ROOTS,
    DEFAULT_RETRIES_PER_SEC, DEFAULT_ROOT_RETRY, DEFAULT_ROOT_WAIT, DEFAULT_UNKNOWN_ROOT_TTL,
};
pub use ref_view::{BlockApi, RefBlock, RefError, RefLimits, RefView, DEFAULT_MAX_IN_FLIGHT};
pub use root_wait::{MAX_CANDIDATES_PER_INDEX, MAX_UNKNOWN_ROOTS};

use ethswarm_proto::chain as pb;
use ethswarm_proto::common;
use network_config::digest::{compute_fork_digest, current_epoch, DigestError};
use network_config::{ChainConfig, Epoch, Genesis};
use std::future::Future;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// A block root.
pub type Root = [u8; 32];

/// How long one sample of the reference API may take \[est\].
pub const DEFAULT_API_TIMEOUT: Duration = Duration::from_secs(2);

/// A finalized checkpoint, as the reference API reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Root,
}

/// A block header's root and slot, as the reference API reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub root: Root,
    pub slot: u64,
}

/// Why the reference API gave no answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("reference API: {0}")]
pub struct ApiError(pub String);

/// The reference Beacon API, as far as the Status needs it.
pub trait ReferenceApi: Send + Sync {
    /// The finalized checkpoint of the head state.
    fn finalized_checkpoint(&self) -> impl Future<Output = Result<Checkpoint, ApiError>> + Send;

    /// The header of the block `root`.
    fn header(&self, root: Root) -> impl Future<Output = Result<Header, ApiError>> + Send;
}

/// The network the probe runs on.
#[derive(Debug, Clone)]
pub struct ProbeChain {
    /// The pinned network config.
    pub config: ChainConfig,
    /// The pinned genesis.
    pub genesis: Genesis,
    /// `SLOTS_PER_EPOCH` of the config's preset.
    pub slots_per_epoch: u64,
}

/// Why there is no Status.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// The wall clock has no epoch with a digest (before genesis or Fulu).
    #[error("no fork digest at the wall clock: {0}")]
    Clock(#[from] DigestError),
    /// The reference API has not given one good sample yet.
    #[error("no reference sample yet: {0}")]
    Unavailable(String),
}

impl From<ProbeError> for tonic::Status {
    /// `UNAVAILABLE`: the caller retries, and judges nothing meanwhile.
    fn from(e: ProbeError) -> Self {
        tonic::Status::unavailable(e.to_string())
    }
}

/// One good sample of the reference API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sample {
    finalized: Checkpoint,
    head: Header,
}

impl Sample {
    /// Whether `self` is behind `kept` in its finalized epoch or its head slot.
    fn is_older_than(&self, kept: &Sample) -> bool {
        self.finalized.epoch < kept.finalized.epoch || self.head.slot < kept.head.slot
    }
}

/// The slot the probe serves its custody columns from, for the Status.
pub trait ServedColumns: Send + Sync {
    /// `earliest_available_slot` while columns are served; `None` while none is.
    fn earliest_available_slot(&self) -> Option<u64>;
}

/// Builds the probe's Status from the wall clock and the reference API (see the module docs).
pub struct StatusProvider<A> {
    api: A,
    chain: ProbeChain,
    timeout: Duration,
    last_good: Mutex<Option<Sample>>,
    columns: Option<std::sync::Arc<dyn ServedColumns>>,
}

impl<A: ReferenceApi> StatusProvider<A> {
    /// A provider sampling `api` for `chain`, each sample within `timeout`.
    pub fn new(api: A, chain: ProbeChain, timeout: Duration) -> Self {
        Self {
            api,
            chain,
            timeout,
            last_good: Mutex::new(None),
            columns: None,
        }
    }

    /// The same provider, its `earliest_available_slot` the slot `columns` serves from.
    #[must_use]
    pub fn serving_columns(mut self, columns: std::sync::Arc<dyn ServedColumns>) -> Self {
        self.columns = Some(columns);
        self
    }

    /// The finalized checkpoint and its block, if the API gives both in time and they agree.
    async fn sample(&self) -> Result<Sample, ApiError> {
        let read = async {
            let finalized = self.api.finalized_checkpoint().await?;
            let head = self.api.header(finalized.root).await?;
            if head.root != finalized.root {
                return Err(ApiError(format!(
                    "header of {:02x?} names root {:02x?}",
                    finalized.root, head.root
                )));
            }
            Ok(Sample { finalized, head })
        };
        tokio::time::timeout(self.timeout, read)
            .await
            .map_err(|_| ApiError(format!("no answer within {:?}", self.timeout)))?
    }

    /// The Status at `now_ms` (Unix milliseconds) as `GetStatusResponse`.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Clock`] if the wall clock has no digest; [`ProbeError::Unavailable`] while
    /// the API has never given a good sample.
    pub async fn status(&self, now_ms: u128) -> Result<pb::GetStatusResponse, ProbeError> {
        let chain = &self.chain;
        let epoch = current_epoch(
            chain.genesis.genesis_time,
            chain.config.slot_duration_ms(),
            chain.slots_per_epoch,
            now_ms,
        )?;
        let fork_digest =
            compute_fork_digest(&chain.config, &chain.genesis.genesis_validators_root, epoch)?;
        let fresh = self.sample().await;
        let sample = {
            let mut last = self
                .last_good
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match fresh {
                Ok(sample) => match *last {
                    Some(kept) if sample.is_older_than(&kept) => tracing::debug!(
                        finalized_epoch = sample.finalized.epoch,
                        head_slot = sample.head.slot,
                        kept_epoch = kept.finalized.epoch,
                        kept_slot = kept.head.slot,
                        "an older reference sample than the kept one: ignored"
                    ),
                    _ => *last = Some(sample),
                },
                Err(e) => match *last {
                    Some(_) => {
                        tracing::warn!(%e, "reference API outage: keeping the last good sample")
                    }
                    None => return Err(ProbeError::Unavailable(e.to_string())),
                },
            }
            last.expect("set or kept above")
        };
        Ok(pb::GetStatusResponse {
            fork_digest: fork_digest.to_vec(),
            finalized: Some(common::Checkpoint {
                epoch: sample.finalized.epoch,
                root: sample.finalized.root.to_vec(),
            }),
            head_root: sample.head.root.to_vec(),
            head_slot: sample.head.slot,
            earliest_available_slot: self
                .columns
                .as_ref()
                .and_then(|c| c.earliest_available_slot())
                .unwrap_or(sample.head.slot),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_config::Network;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU8, Ordering};

    const UP: u8 = 0;
    const FAILING: u8 = 1;
    const HANGING: u8 = 2;

    /// A reference API that answers from its tables, fails, or never answers.
    #[derive(Default)]
    struct Fixture {
        mode: AtomicU8,
        finalized: Mutex<Option<Checkpoint>>,
        headers: Mutex<HashMap<Root, Header>>,
    }

    impl Fixture {
        fn finalize(&self, epoch: Epoch, root: Root, slot: u64) {
            *self.finalized.lock().unwrap() = Some(Checkpoint { epoch, root });
            self.headers
                .lock()
                .unwrap()
                .insert(root, Header { root, slot });
        }

        async fn gate(&self) -> Result<(), ApiError> {
            match self.mode.load(Ordering::SeqCst) {
                FAILING => Err(ApiError("connection refused".into())),
                HANGING => std::future::pending().await,
                _ => Ok(()),
            }
        }
    }

    impl ReferenceApi for &Fixture {
        async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
            self.gate().await?;
            self.finalized
                .lock()
                .unwrap()
                .ok_or_else(|| ApiError("no finality".into()))
        }

        async fn header(&self, root: Root) -> Result<Header, ApiError> {
            self.gate().await?;
            self.headers
                .lock()
                .unwrap()
                .get(&root)
                .copied()
                .ok_or_else(|| ApiError("404".into()))
        }
    }

    fn sepolia() -> ProbeChain {
        ProbeChain {
            config: ChainConfig::load(Network::Sepolia).unwrap(),
            genesis: Network::Sepolia.genesis().unwrap(),
            slots_per_epoch: 32,
        }
    }

    /// Unix ms at the start of `epoch` on `chain`.
    fn at_epoch(chain: &ProbeChain, epoch: Epoch) -> u128 {
        let ms_per_epoch = u128::from(chain.config.slot_duration_ms() * chain.slots_per_epoch);
        u128::from(chain.genesis.genesis_time) * 1000 + u128::from(epoch) * ms_per_epoch
    }

    fn digest_at(chain: &ProbeChain, epoch: Epoch) -> Vec<u8> {
        compute_fork_digest(&chain.config, &chain.genesis.genesis_validators_root, epoch)
            .unwrap()
            .to_vec()
    }

    /// The first epoch after Fulu at which the digest changes (a BPO epoch), and the one before.
    fn digest_boundary(chain: &ProbeChain) -> (Epoch, Epoch) {
        let schedule = network_config::digest::digest_schedule(
            &chain.config,
            &chain.genesis.genesis_validators_root,
        );
        let next = schedule[1].epoch;
        (next - 1, next)
    }

    #[tokio::test(start_paused = true)]
    async fn status_provider() {
        let chain = sepolia();
        let (before, after) = digest_boundary(&chain);
        let api = Fixture::default();
        api.finalize(before - 2, [0xaa; 32], (before - 2) * 32);
        let provider = StatusProvider::new(&api, chain.clone(), DEFAULT_API_TIMEOUT);

        // The fixture's finalized checkpoint and its block, the wall-clock digest.
        let status = provider.status(at_epoch(&chain, before)).await.unwrap();
        let want = pb::GetStatusResponse {
            fork_digest: digest_at(&chain, before),
            finalized: Some(common::Checkpoint {
                epoch: before - 2,
                root: vec![0xaa; 32],
            }),
            head_root: vec![0xaa; 32],
            head_slot: (before - 2) * 32,
            earliest_available_slot: (before - 2) * 32,
        };
        assert_eq!(status, want);

        // Finality moves: the next Status follows it.
        api.finalize(before - 1, [0xbb; 32], (before - 1) * 32);
        let status = provider.status(at_epoch(&chain, before)).await.unwrap();
        assert_eq!(status.finalized.as_ref().unwrap().root, vec![0xbb; 32]);
        assert_eq!(status.head_slot, (before - 1) * 32);
        let good = status;

        // An outage (refused, then silent past the timeout) keeps the last good sample, and the
        // digest still follows the clock across the BPO epoch.
        api.mode.store(FAILING, Ordering::SeqCst);
        let status = provider.status(at_epoch(&chain, after)).await.unwrap();
        assert_ne!(digest_at(&chain, after), digest_at(&chain, before));
        assert_eq!(status.fork_digest, digest_at(&chain, after));
        assert_eq!(status.finalized, good.finalized);
        assert_eq!(status.head_root, good.head_root);
        api.mode.store(HANGING, Ordering::SeqCst);
        let start = tokio::time::Instant::now();
        let status = provider.status(at_epoch(&chain, after)).await.unwrap();
        assert_eq!(start.elapsed(), DEFAULT_API_TIMEOUT);
        assert_eq!(status.finalized, good.finalized);

        // Back up: fresh values again.
        api.mode.store(UP, Ordering::SeqCst);
        api.finalize(after, [0xcc; 32], after * 32);
        let status = provider.status(at_epoch(&chain, after)).await.unwrap();
        assert_eq!(status.finalized.unwrap().epoch, after);
    }

    /// A reference API whose `header` answers take the next scripted delay each.
    struct Slow<'a> {
        api: &'a Fixture,
        delays: Mutex<std::collections::VecDeque<Duration>>,
    }

    impl ReferenceApi for &Slow<'_> {
        async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
            (&self.api).finalized_checkpoint().await
        }

        async fn header(&self, root: Root) -> Result<Header, ApiError> {
            let delay = self.delays.lock().unwrap().pop_front().unwrap_or_default();
            tokio::time::sleep(delay).await;
            (&self.api).header(root).await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn status_never_moves_backwards() {
        let chain = sepolia();
        let (before, _) = digest_boundary(&chain);
        let now = at_epoch(&chain, before);
        let api = Fixture::default();
        let (old, new) = (before - 3, before - 2);
        api.finalize(old, [0xaa; 32], old * 32);
        let slow = Slow {
            api: &api,
            delays: Mutex::new([Duration::from_secs(1), Duration::ZERO].into()),
        };
        let provider = StatusProvider::new(&slow, chain.clone(), DEFAULT_API_TIMEOUT);

        // A slow refresh reads the old checkpoint, then a fast one reads the newer one and
        // finishes first: the slow one's older answer must not replace it.
        let (stale, fresh) = tokio::join!(provider.status(now), async {
            tokio::task::yield_now().await;
            api.finalize(new, [0xbb; 32], new * 32);
            provider.status(now).await
        });
        let epoch = |s: &pb::GetStatusResponse| s.finalized.as_ref().unwrap().epoch;
        assert_eq!(epoch(&fresh.unwrap()), new);
        let stale = stale.unwrap();
        assert_eq!(
            epoch(&stale),
            new,
            "the late, older sample is not advertised"
        );
        assert_eq!(stale.head_slot, new * 32);

        // An outage keeps the newest sample, not the last one to arrive.
        api.mode.store(FAILING, Ordering::SeqCst);
        let kept = provider.status(now).await.unwrap();
        assert_eq!(epoch(&kept), new);
        assert_eq!(kept.head_root, vec![0xbb; 32]);

        // An answer older in either field is refused too, one after the other.
        api.mode.store(UP, Ordering::SeqCst);
        api.finalize(old, [0xcc; 32], (new + 5) * 32);
        assert_eq!(epoch(&provider.status(now).await.unwrap()), new);
        api.finalize(new, [0xdd; 32], new * 32 - 1);
        let status = provider.status(now).await.unwrap();
        assert_eq!(status.head_root, vec![0xbb; 32]);
        // The same epoch and slot, or newer: taken.
        api.finalize(new + 1, [0xee; 32], (new + 1) * 32);
        let status = provider.status(now).await.unwrap();
        assert_eq!(epoch(&status), new + 1);
        assert_eq!(status.head_root, vec![0xee; 32]);
    }

    #[tokio::test]
    async fn no_status_before_one_good_sample() {
        let chain = sepolia();
        let (before, _) = digest_boundary(&chain);
        let api = Fixture::default();
        api.mode.store(FAILING, Ordering::SeqCst);
        let provider = StatusProvider::new(&api, chain.clone(), DEFAULT_API_TIMEOUT);
        let err = provider.status(at_epoch(&chain, before)).await.unwrap_err();
        assert!(matches!(err, ProbeError::Unavailable(_)), "{err}");
        assert_eq!(tonic::Status::from(err).code(), tonic::Code::Unavailable);
        // A finalized root the API has no header for is no good sample either.
        api.mode.store(UP, Ordering::SeqCst);
        *api.finalized.lock().unwrap() = Some(Checkpoint {
            epoch: 1,
            root: [1; 32],
        });
        assert!(matches!(
            provider.status(at_epoch(&chain, before)).await,
            Err(ProbeError::Unavailable(_))
        ));
        // Nor is a header that names another root.
        api.headers.lock().unwrap().insert(
            [1; 32],
            Header {
                root: [2; 32],
                slot: 32,
            },
        );
        let err = provider.status(at_epoch(&chain, before)).await.unwrap_err();
        assert!(err.to_string().contains("names root"), "{err}");
    }

    #[tokio::test]
    async fn the_clock_must_have_a_digest() {
        let chain = sepolia();
        let api = Fixture::default();
        api.finalize(1, [1; 32], 32);
        let provider = StatusProvider::new(&api, chain.clone(), DEFAULT_API_TIMEOUT);
        // Before genesis, and after genesis but before Fulu.
        let before_genesis = u128::from(chain.genesis.genesis_time) * 1000 - 1;
        assert!(matches!(
            provider.status(before_genesis).await,
            Err(ProbeError::Clock(DigestError::BeforeGenesis { .. }))
        ));
        assert!(matches!(
            provider.status(at_epoch(&chain, 0)).await,
            Err(ProbeError::Clock(DigestError::BeforeFulu { .. }))
        ));
    }

    /// Exit 9c: with the custody columns served, Status v2 `earliest_available_slot` is the first
    /// stored column slot, which for a node storing forward from its `cgc` is the slot `cgc` was
    /// set at (`fulu/p2p-interface.md` L552–561, `fulu/validator.md` L173–175).
    #[tokio::test(start_paused = true)]
    async fn earliest_available_slot_is_the_first_stored_column_slot() {
        use crate::da::custody::{Advertise, Custody, EnrCgc, EnrError};
        use crate::reqresp::{ColumnServer, ColumnStore, ServeBudget, ServeClock};
        use cl_chain_columns::{BlockLink, Column, ColumnWriter};
        use consensus_types::primitives::U256;
        use std::sync::Arc;
        struct NoEnr;
        impl EnrCgc for NoEnr {
            fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
                Ok(())
            }
        }
        struct Always;
        impl ServeClock for Always {
            fn serve_range(&self) -> Option<(u64, u64)> {
                Some((0, u64::MAX))
            }
            fn fork_digest(&self, _: u64) -> Option<[u8; 4]> {
                Some([1, 2, 3, 4])
            }
        }
        let chain = sepolia();
        let (before, _) = digest_boundary(&chain);
        let api = Fixture::default();
        let head = (before - 2) * 32;
        api.finalize(before - 2, [0xaa; 32], head);
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let cgc_set_slot = head + 40;
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            U256::MAX,
            Advertise::Custody,
            cgc_set_slot,
        )
        .unwrap();
        let server = Arc::new(ColumnServer::new(
            Arc::clone(&writer) as Arc<dyn ColumnStore>,
            U256::MAX,
            Arc::new(Always),
            ServeBudget::default(),
        ));
        let provider =
            StatusProvider::new(&api, chain.clone(), DEFAULT_API_TIMEOUT).serving_columns(server);
        let now = at_epoch(&chain, before);
        // No column stored yet: the head slot, as before.
        assert_eq!(
            provider.status(now).await.unwrap().earliest_available_slot,
            head
        );
        // Forward from cgc_set_slot: the first stored column slot is the slot cgc was set at.
        let store = |slot: u64, root: u8, link: BlockLink| {
            let columns: Vec<_> = custody
                .custody_columns()
                .into_iter()
                .map(|index| Column {
                    index,
                    ssz: b"sidecar",
                })
                .collect();
            writer
                .write_block_columns(slot, &[root; 32], link, &columns)
                .unwrap();
        };
        store(cgc_set_slot + 3, 2, BlockLink::Parent([1; 32]));
        store(cgc_set_slot, 1, BlockLink::Start);
        let first = first_stored_column_slot(writer.reader()).unwrap();
        assert_eq!(first, Some(cgc_set_slot));
        let status = provider.status(now).await.unwrap();
        assert_eq!(status.earliest_available_slot, cgc_set_slot);
        assert_eq!(Some(status.earliest_available_slot), first);
        assert_eq!(custody.cgc_set_slot(), status.earliest_available_slot);
        // Above the head the probe advertises (its finalized block): see the module docs.
        assert!(status.earliest_available_slot > status.head_slot);
        // Finality prunes the first block: the first stored slot stays, the Status moves on to
        // the slot after the watermark, which the store can still serve.
        writer.prune_finalized(cgc_set_slot + 1).unwrap();
        assert_eq!(first_stored_column_slot(writer.reader()).unwrap(), first);
        let status = provider.status(now).await.unwrap();
        assert_eq!(status.earliest_available_slot, cgc_set_slot + 2);
    }

    // The storage contract (`storage_contract`), end to end: a reference-API fixture server
    // over HTTP, the in-process cl-verify with the pinned setup, the column env, and the
    // custody of node `U256::MAX` (columns 1, 47, 87 and 102).

    use crate::da::custody::{Advertise, Custody, EnrCgc, EnrError};
    use crate::testing::{blobs, gloas_block, schedule, ClVerify, Served, Spec, Stub, StubVerify};
    use crate::verify::client::KzgClient;
    use cl_chain_columns::ColumnWriter;
    use consensus_types::gloas::DataColumnSidecar;
    use consensus_types::primitives::U256;
    use prometheus_client::registry::Registry;
    use std::sync::Arc;
    use testkit::collector::testing::{FixtureServer, Reply};

    /// The slot of the fixture block.
    const SLOT: u64 = 9;
    /// A custody column of `U256::MAX`.
    const CUSTODY_COLUMN: u64 = 47;

    /// The ENR is not under test here.
    struct NoEnr;

    impl EnrCgc for NoEnr {
        fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
            Ok(())
        }
    }

    struct Contract {
        refs: RefView<BeaconApi, Spec>,
        custody: Custody<Arc<ColumnWriter>, NoEnr>,
        contract: ColumnContract<KzgClient>,
        registry: Registry,
        writer: Arc<ColumnWriter>,
        /// The root of the block the reference serves, which commits to both fixture blobs.
        root: Root,
        /// The root of a block that commits to the first fixture blob only.
        one_blob_root: Root,
        _verify: Served,
        _reference: Reference,
        _dir: tempfile::TempDir,
    }

    /// A reference node over HTTP: the headers and blocks it serves, 404 for any other.
    struct Reference {
        server: FixtureServer,
        replies: Arc<Mutex<HashMap<String, Reply>>>,
    }

    impl Reference {
        async fn start() -> Self {
            let replies = Arc::<Mutex<HashMap<String, Reply>>>::default();
            let served = Arc::clone(&replies);
            let server = FixtureServer::start(move |_, path| {
                served
                    .lock()
                    .unwrap()
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| Reply::status(404))
            })
            .await;
            Self { server, replies }
        }

        /// From now on, serves the header (at `slot`) and the block `ssz` of `root`.
        fn serve(&self, root: Root, slot: u64, ssz: Vec<u8>) {
            let id = format!("0x{}", hex::encode(root));
            let header = format!(
                r#"{{"data":{{"root":"{id}","canonical":true,"header":{{"message":{{"slot":"{slot}"}}}}}}}}"#
            );
            let mut replies = self.replies.lock().unwrap();
            replies.insert(format!("/eth/v1/beacon/headers/{id}"), Reply::json(&header));
            replies.insert(format!("/eth/v2/beacon/blocks/{id}"), Reply::ssz(ssz));
        }

        fn api(&self) -> BeaconApi {
            BeaconApi::new(&format!("http://{}", self.server.addr), DEFAULT_API_TIMEOUT).unwrap()
        }
    }

    async fn contract_with(verify: Served, verify_timeout: Duration) -> Contract {
        let b = blobs();
        let (_, ssz, root) = gloas_block(SLOT, &b.commitments);
        let (_, one_ssz, one_blob_root) = gloas_block(SLOT, &b.commitments[..1]);
        let server = Reference::start().await;
        server.serve(root, SLOT, ssz);
        server.serve(one_blob_root, SLOT, one_ssz);
        let api = server.api();
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            U256::MAX,
            Advertise::Withheld,
            0,
        )
        .unwrap();
        assert!(custody.custody_columns().contains(&CUSTODY_COLUMN));
        let mut registry = Registry::default();
        let contract = ColumnContract {
            kzg: verify.kzg_client().await,
            verify_timeout,
            metrics: ColumnMetrics::register(&mut registry),
        };
        Contract {
            refs: RefView::new(api, schedule(), RefLimits::default()),
            custody,
            contract,
            registry,
            writer,
            root,
            one_blob_root,
            _verify: verify,
            _reference: server,
            _dir: dir,
        }
    }

    async fn contract() -> Contract {
        contract_with(ClVerify::start(), Duration::from_secs(10)).await
    }

    /// Column `index` of both fixture blobs for block `root`, arriving on its own subnet.
    fn column(root: Root, index: u64) -> GossipColumn<Spec> {
        let b = blobs();
        let blobs = 0..b.commitments.len();
        let cells: Vec<_> = blobs
            .clone()
            .map(|blob| b.cell(blob, index % 128).to_vec().try_into().unwrap())
            .collect();
        let proofs: Vec<_> = blobs.map(|blob| b.proof(blob, index % 128)).collect();
        GossipColumn {
            sidecar: DataColumnSidecar {
                index,
                column: cells.try_into().unwrap(),
                kzg_proofs: proofs.try_into().unwrap(),
                slot: SLOT,
                beacon_block_root: root.into(),
            },
            subnet_id: index % 128,
        }
    }

    impl Contract {
        /// The contract, then the store if it held: what gossip ingestion does.
        async fn ingest(&self, column: &GossipColumn<Spec>) -> Result<(), Drop> {
            let verified =
                storage_contract(column, &self.refs, &self.custody, &self.contract).await?;
            store_verified(&verified, &self.writer).unwrap();
            Ok(())
        }

        fn stored(&self, column: &GossipColumn<Spec>) -> Option<Vec<u8>> {
            let root = column.sidecar.beacon_block_root.0;
            self.writer
                .reader()
                .get(&root, column.sidecar.index)
                .unwrap()
        }

        /// `probe_column_dropped_total{reason}` as exposed, for every reason.
        fn exposed(&self) -> HashMap<&'static str, u64> {
            let mut text = String::new();
            prometheus_client::encoding::text::encode(&mut text, &self.registry).unwrap();
            Drop::ALL
                .iter()
                .map(|d| {
                    let series =
                        format!("probe_column_dropped_total{{reason=\"{}\"}} ", d.reason());
                    let value = text
                        .lines()
                        .find_map(|l| l.strip_prefix(&series))
                        .map_or(0, |v| v.parse().unwrap());
                    assert_eq!(value, self.contract.metrics.dropped(*d), "{}", d.reason());
                    (d.reason(), value)
                })
                .collect()
        }

        /// `column` is dropped for `reason`, nothing of it is stored, and the drop is counted
        /// under that reason only, `count` times so far.
        async fn assert_dropped(&self, column: &GossipColumn<Spec>, reason: Drop, count: u64) {
            assert_eq!(self.ingest(column).await, Err(reason));
            assert_eq!(
                self.stored(column),
                None,
                "a dropped column is never stored"
            );
            let exposed = self.exposed();
            for (label, value) in exposed {
                let want = if label == reason.reason() { count } else { 0 };
                assert_eq!(value, want, "probe_column_dropped_total{{reason={label}}}");
            }
        }
    }

    #[tokio::test]
    async fn contract_valid_stores() {
        let c = contract().await;
        let column = column(c.root, CUSTODY_COLUMN);
        assert_eq!(c.ingest(&column).await, Ok(()));
        use ssz::Encode;
        assert_eq!(c.stored(&column), Some(column.sidecar.as_ssz_bytes()));
        assert!(c.exposed().values().all(|&n| n == 0), "nothing dropped");
        // Every custody column of the block is stored.
        for index in c.custody.custody_columns() {
            let column = self::column(c.root, index);
            assert_eq!(c.ingest(&column).await, Ok(()), "column {index}");
        }
        let stored = c.writer.reader().columns_for_root(&c.root).unwrap();
        assert_eq!(stored.len(), 4);
    }

    #[tokio::test]
    async fn contract_unknown_root() {
        let c = contract().await;
        // A root the reference has never heard of (404).
        c.assert_dropped(&column([0x5a; 32], CUSTODY_COLUMN), Drop::UnknownRoot, 1)
            .await;
        // A vouched root at another slot than the reference's block.
        let mut other_slot = column(c.root, CUSTODY_COLUMN);
        other_slot.sidecar.slot = SLOT + 1;
        c.assert_dropped(&other_slot, Drop::UnknownRoot, 2).await;
    }

    #[tokio::test]
    async fn contract_kzg_invalid() {
        let c = contract().await;
        // One flipped cell byte (the low byte of a field element: still canonical).
        let mut flipped = column(c.root, CUSTODY_COLUMN);
        flipped.sidecar.column[1][31] ^= 1;
        c.assert_dropped(&flipped, Drop::KzgInvalid, 1).await;
        // A proof of another column.
        let mut wrong_proof = column(c.root, CUSTODY_COLUMN);
        wrong_proof.sidecar.kzg_proofs[0] = blobs().proof(0, 0);
        c.assert_dropped(&wrong_proof, Drop::KzgInvalid, 2).await;
        // One proof short: structurally invalid, never sent to cl-verify.
        let mut short = column(c.root, CUSTODY_COLUMN);
        short.sidecar.kzg_proofs = vec![blobs().proof(0, 47)].try_into().unwrap();
        c.assert_dropped(&short, Drop::KzgInvalid, 3).await;
        // The unchanged column still stores.
        assert_eq!(c.ingest(&column(c.root, CUSTODY_COLUMN)).await, Ok(()));
    }

    #[tokio::test]
    async fn contract_commitments_mismatch() {
        let c = contract().await;
        // Two cells for a bid that commits to one blob.
        c.assert_dropped(
            &column(c.one_blob_root, CUSTODY_COLUMN),
            Drop::CommitmentsMismatch,
            1,
        )
        .await;
        // One cell for a bid of two.
        let mut one = column(c.root, CUSTODY_COLUMN);
        one.sidecar.column = vec![one.sidecar.column[0].clone()].try_into().unwrap();
        one.sidecar.kzg_proofs = vec![one.sidecar.kzg_proofs[0]].try_into().unwrap();
        c.assert_dropped(&one, Drop::CommitmentsMismatch, 2).await;
        // No cells at all: a sidecar for zero blobs.
        let mut empty = column(c.root, CUSTODY_COLUMN);
        empty.sidecar.column = Vec::new().try_into().unwrap();
        empty.sidecar.kzg_proofs = Vec::new().try_into().unwrap();
        c.assert_dropped(&empty, Drop::CommitmentsMismatch, 3).await;
        // The first blob's column against the one-blob bid verifies.
        let mut first = column(c.one_blob_root, CUSTODY_COLUMN);
        first.sidecar.column = vec![first.sidecar.column[0].clone()].try_into().unwrap();
        first.sidecar.kzg_proofs = vec![first.sidecar.kzg_proofs[0]].try_into().unwrap();
        assert_eq!(c.ingest(&first).await, Ok(()));
    }

    #[tokio::test]
    async fn contract_not_custody() {
        let c = contract().await;
        // A valid column on its own subnet that this node does not custody.
        assert!(!c.custody.custody_columns().contains(&5));
        c.assert_dropped(&column(c.root, 5), Drop::NotCustody, 1)
            .await;
        // An index past NUMBER_OF_COLUMNS, on the subnet of its index modulo 128.
        let mut past = column(c.root, CUSTODY_COLUMN);
        past.sidecar.index = 128 + CUSTODY_COLUMN;
        c.assert_dropped(&past, Drop::NotCustody, 2).await;
    }

    #[tokio::test]
    async fn contract_wrong_subnet() {
        let c = contract().await;
        // A custody column on another column's subnet.
        let mut moved = column(c.root, CUSTODY_COLUMN);
        moved.subnet_id = CUSTODY_COLUMN + 1;
        c.assert_dropped(&moved, Drop::WrongSubnet, 1).await;
        // On a subnet past DATA_COLUMN_SIDECAR_SUBNET_COUNT.
        moved.subnet_id = 128 + CUSTODY_COLUMN;
        c.assert_dropped(&moved, Drop::WrongSubnet, 2).await;
    }

    #[tokio::test]
    async fn verify_timeout_drops() {
        let deadline = Duration::from_millis(300);
        let c = contract_with(StubVerify::start(Stub::Silent), deadline).await;
        let column = column(c.root, CUSTODY_COLUMN);
        // The reference lookup is cached first, so the time below is cl-verify's alone.
        c.refs.lookup(c.root).await.unwrap();
        let start = std::time::Instant::now();
        c.assert_dropped(&column, Drop::VerifyTimeout, 1).await;
        let took = start.elapsed();
        assert!(took >= deadline, "{took:?}");
        assert!(took < deadline + Duration::from_millis(250), "{took:?}");
        // cl-verify that is not there at all: dropped the same way.
        let gone = contract_with(StubVerify::start(Stub::Mute), deadline).await;
        gone.assert_dropped(&column, Drop::VerifyTimeout, 1).await;
    }

    // The forward-only column store (`ColumnIngest`): gossip columns queue, wait for their root,
    // pass the storage contract and are written on the columns-writer thread; every one is
    // reported IGNORE.

    use ethswarm_proto::common::Verdict;
    use ethswarm_proto::verify::KzgCellProof;
    use root_wait::MAX_CANDIDATES_PER_INDEX;
    use ssz::Encode as _;

    /// How long a test waits for the store to settle before it fails.
    const SETTLE: Duration = Duration::from_secs(20);

    type Ingest = ColumnIngest<BeaconApi, Spec, KzgClient, Arc<ColumnWriter>, NoEnr>;

    /// A column store on a fresh env, its custody set at `cgc_set_slot`, and a reference that
    /// serves a block of both fixture blobs at each of `slots`.
    struct Store {
        ingest: Ingest,
        writer: Arc<ColumnWriter>,
        registry: Registry,
        /// The reference's blocks, as (root, slot).
        blocks: Vec<(Root, u64)>,
        reference: Reference,
        _verify: Served,
        _dir: tempfile::TempDir,
    }

    async fn store_with(cgc_set_slot: u64, slots: &[u64], limits: IngestLimits) -> Store {
        let reference = Reference::start().await;
        let blocks = slots
            .iter()
            .map(|&slot| {
                let (_, ssz, root) = gloas_block(slot, &blobs().commitments);
                reference.serve(root, slot, ssz);
                (root, slot)
            })
            .collect();
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            U256::MAX,
            Advertise::Withheld,
            cgc_set_slot,
        )
        .unwrap();
        assert_eq!(custody.cgc_set_slot(), cgc_set_slot);
        let verify = ClVerify::start();
        let mut registry = Registry::default();
        let contract = ColumnContract {
            kzg: verify.kzg_client().await,
            verify_timeout: Duration::from_secs(10),
            metrics: ColumnMetrics::register(&mut registry),
        };
        let refs = RefView::new(reference.api(), schedule(), RefLimits::default());
        let ingest = ColumnIngest::start(
            refs,
            custody,
            contract,
            Arc::clone(&writer),
            limits,
            QueueMetrics::register(&mut registry),
        )
        .unwrap();
        Store {
            ingest,
            writer,
            registry,
            blocks,
            reference,
            _verify: verify,
            _dir: dir,
        }
    }

    /// Column `index` of both fixture blobs for the block `root` at `slot`.
    fn column_at(root: Root, slot: u64, index: u64) -> GossipColumn<Spec> {
        let mut column = column(root, index);
        column.sidecar.slot = slot;
        column
    }

    /// Polls `done` until it holds; fails after [`SETTLE`].
    async fn settle(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + SETTLE;
        while !done() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    impl Store {
        fn stored(&self, column: &GossipColumn<Spec>) -> Option<Vec<u8>> {
            let root = column.sidecar.beacon_block_root.0;
            let stored = self.writer.reader().get(&root, column.sidecar.index);
            stored.unwrap()
        }

        fn dropped(&self, reason: Drop) -> u64 {
            self.ingest.contract().metrics.dropped(reason)
        }

        /// `name` as exposed in the registry; 0 if absent.
        fn exposed(&self, name: &str) -> u64 {
            let mut text = String::new();
            prometheus_client::encoding::text::encode(&mut text, &self.registry).unwrap();
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{name} ")))
                .map_or(0, |v| v.parse().unwrap())
        }

        /// Hands `column` over as gossip does; the verdict is IGNORE whatever happens next.
        fn gossip(&self, column: &GossipColumn<Spec>) {
            assert_eq!(self.ingest.on_column(column.clone()), Verdict::Ignore);
        }

        /// Gossips `column` and waits until it is stored as its SSZ and the queue is empty
        /// (so the write is counted too).
        async fn store(&self, column: &GossipColumn<Spec>) {
            self.gossip(column);
            let want = column.sidecar.as_ssz_bytes();
            settle("the column to be stored", || {
                self.ingest.pending() == 0 && self.stored(column).as_ref() == Some(&want)
            })
            .await;
        }
    }

    /// A cl-verify that never answers, holding every batch of cells it was handed.
    #[derive(Clone, Default)]
    struct Stalled(Arc<Mutex<Vec<Vec<KzgCellProof>>>>);

    impl crate::verify::client::KzgVerifier for Stalled {
        async fn verify_cells(
            &self,
            cells: Vec<KzgCellProof>,
            _: Duration,
        ) -> crate::verify::client::KzgOutcome {
            self.0.lock().unwrap().push(cells);
            std::future::pending().await
        }
    }

    impl Stalled {
        /// The batches held now, and the heap bytes of their copies.
        fn held(&self) -> (usize, usize) {
            let held = self.0.lock().unwrap();
            let bytes = held
                .iter()
                .map(|cells| {
                    cells.capacity() * std::mem::size_of::<KzgCellProof>()
                        + cells
                            .iter()
                            .map(|c| {
                                c.commitment.capacity() + c.cell.capacity() + c.proof.capacity()
                            })
                            .sum::<usize>()
                })
                .sum();
            (held.len(), bytes)
        }
    }

    /// A cl-verify client whose calls run out of time at once with their frames still queued:
    /// it keeps what each call held charged until [`QueuedFrames::send`].
    #[derive(Clone, Default)]
    struct QueuedFrames(Arc<Mutex<Vec<crate::verify::client::Held>>>);

    impl crate::verify::client::KzgVerifier for QueuedFrames {
        async fn verify_cells(
            &self,
            _: Vec<KzgCellProof>,
            _: Duration,
        ) -> crate::verify::client::KzgOutcome {
            unreachable!("the store hands its charge over")
        }

        async fn verify_cells_holding(
            &self,
            _: Vec<KzgCellProof>,
            _: Duration,
            held: crate::verify::client::Held,
        ) -> crate::verify::client::KzgOutcome {
            self.0.lock().unwrap().push(held);
            crate::verify::client::KzgOutcome::NoVerdict("no verdict by the deadline".into())
        }
    }

    impl QueuedFrames {
        /// The queued frames leave for the wire.
        fn send(&self) {
            self.0.lock().unwrap().clear();
        }
    }

    #[tokio::test]
    async fn a_timed_out_check_keeps_its_copies_charged_while_its_frame_is_queued() {
        let reference = Reference::start().await;
        let (_, ssz, root) = gloas_block(SLOT, &blobs().commitments);
        reference.serve(root, SLOT, ssz);
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            U256::MAX,
            Advertise::Withheld,
            0,
        )
        .unwrap();
        let queued = QueuedFrames::default();
        let contract = ColumnContract {
            kzg: queued.clone(),
            verify_timeout: Duration::from_secs(1),
            metrics: ColumnMetrics::default(),
        };
        let refs = RefView::new(reference.api(), schedule(), RefLimits::default());
        let ingest = ColumnIngest::start(
            refs,
            custody,
            contract,
            Arc::clone(&writer),
            IngestLimits::default(),
            QueueMetrics::default(),
        )
        .unwrap();
        let column = column_at(root, SLOT, CUSTODY_COLUMN);
        assert_eq!(ingest.on_column(column), Verdict::Ignore);
        settle("the check to run out of time", || {
            ingest.contract().metrics.dropped(Drop::VerifyTimeout) == 1 && ingest.pending() == 0
        })
        .await;
        // The column is gone, but its cells still sit in the outbound queue: still charged.
        let charged = ingest.copy_bytes();
        assert!(charged > 0, "the queued cells are charged");
        assert_eq!(queued.0.lock().unwrap().len(), 1);
        queued.send();
        assert_eq!(
            ingest.copy_bytes(),
            0,
            "released as the frame left the queue"
        );
    }

    #[tokio::test]
    async fn copies_for_the_kzg_check_are_charged() {
        let slots = [9, 10];
        let reference = Reference::start().await;
        let roots: Vec<_> = slots
            .iter()
            .map(|&slot| {
                let (_, ssz, root) = gloas_block(slot, &blobs().commitments);
                reference.serve(root, slot, ssz);
                root
            })
            .collect();
        let one = column_at(roots[0], slots[0], CUSTODY_COLUMN)
            .sidecar
            .ssz_bytes_len();
        let limits = IngestLimits {
            max_copy_bytes: 8 * one,
            ..IngestLimits::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            U256::MAX,
            Advertise::Withheld,
            0,
        )
        .unwrap();
        let mut registry = Registry::default();
        let stalled = Stalled::default();
        let contract = ColumnContract {
            kzg: stalled.clone(),
            verify_timeout: Duration::from_secs(600),
            metrics: ColumnMetrics::register(&mut registry),
        };
        let refs = RefView::new(reference.api(), schedule(), RefLimits::default());
        let ingest = ColumnIngest::start(
            refs,
            custody,
            contract,
            Arc::clone(&writer),
            limits,
            QueueMetrics::register(&mut registry),
        )
        .unwrap();
        let exposed = |name: &str| {
            let mut text = String::new();
            prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{name} ")))
                .map_or(0, |v| v.parse::<u64>().unwrap())
        };
        // cl-verify stalls: each column holds its copies until the copy budget is full.
        let mut columns = slots.iter().zip(&roots).flat_map(|(&slot, &root)| {
            ingest
                .custody()
                .custody_columns()
                .into_iter()
                .map(move |index| column_at(root, slot, index))
        });
        let mut sent = 0;
        while exposed("probe_column_queue_dropped_total") == 0 {
            let column = columns
                .next()
                .expect("the copy budget fills before the columns run out");
            assert_eq!(ingest.on_column(column), Verdict::Ignore);
            sent += 1;
            settle("the column to reach cl-verify or be dropped", || {
                stalled.held().0 + exposed("probe_column_queue_dropped_total") as usize == sent
            })
            .await;
        }
        let (held, copies) = stalled.held();
        assert!(held >= 1, "at least one column fits");
        assert_eq!(
            ingest.pending(),
            held,
            "the dropped column gave its place back"
        );
        // What is charged bounds what is held: the queued sidecars and their copies.
        assert!(
            copies <= ingest.copy_bytes(),
            "{copies} > {}",
            ingest.copy_bytes()
        );
        assert!(ingest.copy_bytes() <= limits.max_copy_bytes);
        assert_eq!(ingest.pending_bytes(), held * one);
        assert_eq!(
            exposed("probe_column_buffer_bytes"),
            (ingest.pending_bytes() + ingest.copy_bytes()) as u64,
            "the gauge reports both budgets"
        );
        assert!(Drop::ALL
            .iter()
            .all(|&d| ingest.contract().metrics.dropped(d) == 0));
        assert_eq!(writer.reader().column_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn queue_full_drops() {
        let one = column_at([0; 32], 9, CUSTODY_COLUMN)
            .sidecar
            .ssz_bytes_len();
        let limits = IngestLimits {
            max_items: 8,
            max_bytes: 3 * one + one / 2,
            root_wait: Duration::from_secs(1),
            alert_bytes: 2 * one,
            max_waiting_columns: 3,
            max_asking_columns: 4,
            ..IngestLimits::default()
        };
        let s = store_with(0, &[9], limits).await;
        let (root, slot) = s.blocks[0];
        // Three columns of roots the reference does not know wait for them, each holding its
        // place in the queue.
        for i in 0..3 {
            s.gossip(&column_at([0x50 + i; 32], slot, CUSTODY_COLUMN));
        }
        assert_eq!((s.ingest.pending(), s.ingest.pending_bytes()), (3, 3 * one));
        assert_eq!(s.exposed("probe_column_buffer_bytes"), 3 * one as u64);
        assert_eq!(
            s.exposed("probe_column_buffer_alert"),
            1,
            "past alert_bytes"
        );
        // A fourth column would pass the byte cap: dropped and counted, never queued.
        let valid = column_at(root, slot, CUSTODY_COLUMN);
        s.gossip(&valid);
        assert_eq!(s.exposed("probe_column_queue_dropped_total"), 1);
        assert_eq!(s.ingest.pending_bytes(), 3 * one);
        assert!(s.ingest.pending_bytes() <= limits.max_bytes);
        // The waiting three time out (root_timeout) and give their places back; the valid
        // column then stores.
        settle("the root wait to end", || s.ingest.pending() == 0).await;
        assert_eq!(s.dropped(Drop::RootTimeout), 3);
        assert_eq!(s.exposed("probe_column_buffer_bytes"), 0);
        assert_eq!(s.exposed("probe_column_buffer_alert"), 0);
        assert_eq!(s.stored(&valid), None, "the dropped column was not stored");
        s.store(&valid).await;
        assert_eq!(s.exposed("probe_column_stored_total"), 1);
        assert_eq!(s.exposed("probe_column_queue_dropped_total"), 1);
    }

    #[tokio::test]
    async fn queue_item_cap_drops() {
        let limits = IngestLimits {
            max_items: 2,
            root_wait: Duration::from_secs(1),
            max_waiting_columns: 0,
            max_asking_columns: 1,
            ..IngestLimits::default()
        };
        let s = store_with(0, &[9], limits).await;
        for i in 0..5 {
            s.gossip(&column_at([0x60 + i; 32], 9, CUSTODY_COLUMN));
            assert!(s.ingest.pending() <= 2);
        }
        assert_eq!(s.ingest.pending(), 2);
        assert_eq!(s.exposed("probe_column_queue_dropped_total"), 3);
        // The two queued find their roots unknown, with no seat to wait in.
        settle("the root wait to end", || s.ingest.pending() == 0).await;
        assert_eq!(s.dropped(Drop::RootWaitFull), 2);
    }

    #[tokio::test]
    async fn forward_only() {
        let cgc_set_slot = 16;
        let s = store_with(cgc_set_slot, &[9, 17, 18], IngestLimits::default()).await;
        assert_eq!(s.ingest.first_stored_column_slot().unwrap(), None);
        // A valid column of a block the reference vouches for, below cgc_set_slot.
        let (root, slot) = s.blocks[0];
        let below = column_at(root, slot, CUSTODY_COLUMN);
        s.gossip(&below);
        settle("the column below to be dropped", || {
            s.dropped(Drop::BeforeCustodySlot) == 1
        })
        .await;
        assert_eq!(s.ingest.pending(), 0);
        assert_eq!(s.stored(&below), None);
        // At and after it: stored, the later slot first.
        for &(root, slot) in s.blocks[1..].iter().rev() {
            s.store(&column_at(root, slot, CUSTODY_COLUMN)).await;
        }
        let first = s.ingest.first_stored_column_slot().unwrap().unwrap();
        assert!(first >= cgc_set_slot, "{first}");
        assert_eq!(first, 17);
        assert_eq!(
            first_stored_column_slot(s.writer.reader()).unwrap(),
            Some(17)
        );
        assert_eq!(s.writer.reader().slot_of(&root).unwrap(), None);
    }

    /// Each stored block is linked to the stored blob-carrying block before it on its chain,
    /// through blocks without blobs, and a blob-carrying block that is not held is a gap that
    /// raises the contiguous-from slot.
    #[tokio::test]
    async fn blocks_are_stored_with_their_chain_link() {
        use crate::testing::gloas_block_on;
        use cl_chain_columns::BlockLink;
        let cgc_set_slot = 16;
        let s = store_with(cgc_set_slot, &[], IngestLimits::default()).await;
        let b = blobs();
        let serve = |slot, commitments: &[[u8; 48]], parent| {
            let (_, ssz, root) = gloas_block_on(slot, commitments, parent);
            s.reference.serve(root, slot, ssz);
            root
        };
        // Below cgc_set_slot: nothing before it is to be held.
        let old = serve(15, &b.commitments, [0x0f; 32]);
        let b17 = serve(17, &b.commitments, old);
        let b18 = serve(18, &b.commitments, b17);
        // 19 carries no blobs: 20 links to 18 through it.
        let e19 = serve(19, &[], b18);
        let b20 = serve(20, &b.commitments, e19);
        // 21 carries blobs but none of its columns arrive: 22 is a gap.
        let m21 = serve(21, &b.commitments, b20);
        let b22 = serve(22, &b.commitments, m21);
        for (root, slot) in [(b17, 17), (b18, 18), (b20, 20), (b22, 22)] {
            s.store(&column_at(root, slot, CUSTODY_COLUMN)).await;
        }
        let reader = s.writer.reader();
        assert_eq!(reader.link_of(&b17).unwrap(), Some(BlockLink::Start));
        assert_eq!(reader.link_of(&b18).unwrap(), Some(BlockLink::Parent(b17)));
        assert_eq!(reader.link_of(&b20).unwrap(), Some(BlockLink::Parent(b18)));
        // 21's columns may still come: 22 waits for it, and raises nothing yet.
        assert_eq!(reader.link_of(&b22).unwrap(), Some(BlockLink::Pending(m21)));
        assert_eq!(reader.contiguous_from().unwrap(), None);
        // A parent the reference does not know: a gap at once. Once the store is past 22 by
        // the pending wait, 22 is settled as a gap too.
        let lost = serve(30, &b.commitments, [0x5e; 32]);
        s.store(&column_at(lost, 30, CUSTODY_COLUMN)).await;
        assert_eq!(reader.link_of(&lost).unwrap(), Some(BlockLink::Gap));
        assert_eq!(reader.link_of(&b22).unwrap(), Some(BlockLink::Gap));
        assert_eq!(reader.contiguous_from().unwrap(), Some(30));
    }

    /// A child checked or written before its parent still links to it, whichever comes first:
    /// the link is decided on the writer thread, and a child waits for a parent on its way.
    #[tokio::test]
    async fn a_parent_and_child_released_together_link_in_either_order() {
        use crate::testing::gloas_block_on;
        use cl_chain_columns::BlockLink;
        let b = blobs();
        for order in ["parent-first", "child-first", "together"] {
            let limits = IngestLimits {
                root_wait: Duration::from_secs(10),
                root_retry: Duration::from_millis(20),
                retries_per_sec: 1000,
                ..IngestLimits::default()
            };
            let s = store_with(16, &[], limits).await;
            let (_, old_ssz, old) = gloas_block_on(15, &b.commitments, [0x0f; 32]);
            let (_, parent_ssz, parent) = gloas_block_on(17, &b.commitments, old);
            let (_, child_ssz, child) = gloas_block_on(18, &b.commitments, parent);
            s.reference.serve(old, 15, old_ssz);
            let parent_column = column_at(parent, 17, CUSTODY_COLUMN);
            let child_column = column_at(child, 18, CUSTODY_COLUMN);
            match order {
                "parent-first" => {
                    s.reference.serve(parent, 17, parent_ssz);
                    s.reference.serve(child, 18, child_ssz);
                    s.store(&parent_column).await;
                    s.store(&child_column).await;
                }
                "child-first" => {
                    s.reference.serve(parent, 17, parent_ssz);
                    s.reference.serve(child, 18, child_ssz);
                    s.store(&child_column).await;
                    assert_eq!(
                        s.writer.reader().link_of(&child).unwrap(),
                        Some(BlockLink::Pending(parent))
                    );
                    s.store(&parent_column).await;
                }
                _ => {
                    // Both wait for their roots, and are released at once.
                    s.gossip(&child_column);
                    s.gossip(&parent_column);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    s.reference.serve(child, 18, child_ssz);
                    s.reference.serve(parent, 17, parent_ssz);
                    let want = [
                        child_column.sidecar.as_ssz_bytes(),
                        parent_column.sidecar.as_ssz_bytes(),
                    ];
                    settle("both columns to be stored", || {
                        s.stored(&child_column).as_ref() == Some(&want[0])
                            && s.stored(&parent_column).as_ref() == Some(&want[1])
                            && s.ingest.pending() == 0
                    })
                    .await;
                }
            }
            let reader = s.writer.reader();
            assert_eq!(
                reader.link_of(&parent).unwrap(),
                Some(BlockLink::Start),
                "{order}"
            );
            assert_eq!(
                reader.link_of(&child).unwrap(),
                Some(BlockLink::Parent(parent)),
                "{order}"
            );
            assert_eq!(reader.contiguous_from().unwrap(), None, "{order}");
        }
    }

    #[tokio::test]
    async fn a_late_root_is_waited_for() {
        let limits = IngestLimits {
            root_wait: Duration::from_secs(10),
            root_retry: Duration::from_millis(20),
            retries_per_sec: 1000,
            ..IngestLimits::default()
        };
        let s = store_with(0, &[], limits).await;
        // The column arrives before the reference has its block.
        let (_, ssz, root) = gloas_block(SLOT, &blobs().commitments);
        let column = column_at(root, SLOT, CUSTODY_COLUMN);
        s.gossip(&column);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(s.ingest.pending(), 1, "waiting for its root");
        assert_eq!(s.stored(&column), None);
        s.reference.serve(root, SLOT, ssz);
        let want = column.sidecar.as_ssz_bytes();
        settle("the column to be stored", || {
            s.stored(&column).as_ref() == Some(&want)
        })
        .await;
        assert!(Drop::ALL.iter().all(|&d| s.dropped(d) == 0));
    }

    /// A made-up block root: `i` in its first bytes.
    fn fake_root(i: u32) -> Root {
        let mut root = [0xf0; 32];
        root[..4].copy_from_slice(&i.to_be_bytes());
        root
    }

    /// The custody columns of the block `root` at [`SLOT`].
    fn custody_columns(s: &Store, root: Root) -> Vec<GossipColumn<Spec>> {
        s.ingest
            .custody()
            .custody_columns()
            .into_iter()
            .map(|index| column_at(root, SLOT, index))
            .collect()
    }

    /// Waits until every column of `columns` is stored as its SSZ.
    async fn all_stored(s: &Store, columns: &[GossipColumn<Spec>]) {
        for column in columns {
            let want = column.sidecar.as_ssz_bytes();
            settle("the real column to be stored", || {
                s.stored(column).as_ref() == Some(&want)
            })
            .await;
        }
    }

    /// The header requests the reference has seen for `root`.
    fn header_requests(s: &Store, root: Root) -> usize {
        let path = format!("/eth/v1/beacon/headers/0x{}", hex::encode(root));
        s.reference
            .server
            .seen()
            .iter()
            .filter(|(seen, _)| *seen == path)
            .count()
    }

    #[tokio::test]
    async fn made_up_roots_cannot_crowd_out_a_waiting_real_one() {
        let limits = IngestLimits {
            root_wait: Duration::from_secs(1),
            root_retry: Duration::from_millis(100),
            max_waiting_roots: 4,
            retries_per_sec: 40,
            ..IngestLimits::default()
        };
        let s = store_with(0, &[], limits).await;
        let start = tokio::time::Instant::now();
        // The real block's custody columns arrive before the reference has the block, and
        // wait for it.
        let (_, ssz, root) = gloas_block(SLOT, &blobs().commitments);
        let real = custody_columns(&s, root);
        for column in &real {
            s.gossip(column);
        }
        settle("the real root to wait", || s.ingest.waiting_roots() == 1).await;
        // A flood of columns of made-up roots: three more roots get a seat in the wait, and
        // every other column is dropped, at once or after its first ask.
        let flood = 200;
        for i in 0..flood {
            s.gossip(&column_at(fake_root(i), SLOT, CUSTODY_COLUMN));
        }
        settle("the made-up roots to take the other seats", || {
            s.ingest.waiting_roots() == 4
        })
        .await;
        // The reference learns the real block within the wait: every real column is stored.
        s.reference.serve(root, SLOT, ssz);
        all_stored(&s, &real).await;
        settle("the flood's waits to end", || s.ingest.pending() == 0).await;
        // Every made-up root is dropped: the three seated, and one more that took the real
        // root's seat once it was known, time out; the rest find no seat.
        let timed_out = s.dropped(Drop::RootTimeout);
        assert!((3..=4).contains(&timed_out), "{timed_out}");
        assert_eq!(timed_out + s.dropped(Drop::RootWaitFull), u64::from(flood));
        assert_eq!(s.exposed("probe_column_queue_dropped_total"), 0);
        // Requests stay within the two budgets, however many roots: the headers of the roots
        // asked about, and the real block once (it is cached from then on).
        let asked = s.reference.server.seen().len() as f64;
        let elapsed = start.elapsed().as_secs_f64();
        let budget = f64::from(limits.first_ask_burst)
            + f64::from(limits.first_asks_per_sec) * elapsed
            + 2.0 * 4.0
            + f64::from(limits.retries_per_sec) * elapsed
            + 1.0;
        assert!(asked <= budget, "{asked} requests, budget {budget}");
        assert!(asked < f64::from(flood), "not one request per made-up root");
    }

    /// A reference node from a table of blocks that answers a root it does not know only after
    /// `slow`, and one it knows at once.
    struct SlowReference {
        blocks: HashMap<Root, (u64, Vec<u8>)>,
        slow: Duration,
        asked: Mutex<Vec<Root>>,
    }

    impl ReferenceApi for Arc<SlowReference> {
        async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
            Err(ApiError("not used".into()))
        }

        async fn header(&self, root: Root) -> Result<Header, ApiError> {
            self.asked.lock().unwrap().push(root);
            match self.blocks.get(&root) {
                Some(&(slot, _)) => Ok(Header { root, slot }),
                None => {
                    tokio::time::sleep(self.slow).await;
                    Err(ApiError("404".into()))
                }
            }
        }
    }

    impl BlockApi for Arc<SlowReference> {
        async fn block(&self, root: Root) -> Result<Vec<u8>, ApiError> {
            let block = self.blocks.get(&root).map(|(_, ssz)| ssz.clone());
            block.ok_or_else(|| ApiError("404".into()))
        }
    }

    #[tokio::test]
    async fn a_known_root_is_asked_about_while_every_seat_retries_against_a_slow_reference() {
        // The default limits, the reference view's included.
        let limits = IngestLimits::default();
        let (_, ssz, root) = gloas_block(SLOT, &blobs().commitments);
        let reference = Arc::new(SlowReference {
            blocks: HashMap::from([(root, (SLOT, ssz))]),
            slow: Duration::from_millis(1500),
            asked: Mutex::default(),
        });
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            U256::MAX,
            Advertise::Withheld,
            0,
        )
        .unwrap();
        let verify = ClVerify::start();
        let contract = ColumnContract {
            kzg: verify.kzg_client().await,
            verify_timeout: Duration::from_secs(10),
            metrics: ColumnMetrics::default(),
        };
        let refs = RefView::new(Arc::clone(&reference), schedule(), RefLimits::default());
        let ingest = ColumnIngest::start(
            refs,
            custody,
            contract,
            Arc::clone(&writer),
            limits,
            QueueMetrics::default(),
        )
        .unwrap();
        // Made-up roots take every seat, and their retries hang on the slow reference together.
        let seats = u32::try_from(limits.max_waiting_roots).unwrap();
        for i in 0..seats {
            ingest.on_column(column_at(fake_root(i), SLOT, CUSTODY_COLUMN));
        }
        settle("every seat to retry at once", || {
            ingest.waiting_roots() == limits.max_waiting_roots
                && ingest.refs_in_flight() == limits.max_waiting_roots
        })
        .await;
        // A root the reference knows: its first ask still finds a place, and every one of its
        // custody columns is stored.
        let real: Vec<_> = ingest
            .custody()
            .custody_columns()
            .into_iter()
            .map(|index| column_at(root, SLOT, index))
            .collect();
        for column in &real {
            ingest.on_column(column.clone());
        }
        for column in &real {
            let want = column.sidecar.as_ssz_bytes();
            settle("the known root's column to be stored", || {
                writer.reader().get(&root, column.sidecar.index).unwrap() == Some(want.clone())
            })
            .await;
        }
        let metrics = &ingest.contract().metrics;
        assert_eq!(metrics.dropped(Drop::RootWaitFull), 0);
        let asked = reference.asked.lock().unwrap();
        assert_eq!(asked.iter().filter(|r| **r == root).count(), 1);
    }

    #[tokio::test]
    async fn a_known_root_is_stored_behind_full_seats_and_a_resent_root() {
        // The defaults, and no pause for the budgets to refill.
        let limits = IngestLimits::default();
        let s = store_with(0, &[SLOT], limits).await;
        let (root, _) = s.blocks[0];
        let start = tokio::time::Instant::now();
        // Made-up roots come first and take every seat in the root wait.
        let seats = u32::try_from(limits.max_waiting_roots).unwrap();
        for i in 0..seats {
            s.gossip(&column_at(fake_root(i), SLOT, CUSTODY_COLUMN));
        }
        // One more made-up root, resent at a high rate: past its first ask it finds no seat, and
        // is remembered until it would be asked again.
        let resent = fake_root(seats);
        // Thousands a second: 20 resends, then a millisecond for the store to take them.
        let store = &s;
        let resend = |n| async move {
            for i in 0..n {
                store.gossip(&column_at(resent, SLOT, [1, 47, 87, 102][i % 4]));
                if i % 20 == 19 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        };
        resend(400).await;
        // The reference already knows the real root: asked about at its turn, it needs no seat,
        // and every one of its custody columns is stored.
        let real = custody_columns(&s, root);
        for column in &real {
            s.gossip(column);
            resend(100).await;
        }
        all_stored(&s, &real).await;
        assert_eq!(s.dropped(Drop::RootTimeout), 0);
        settle("the made-up roots to hold every seat", || {
            s.ingest.waiting_roots() == limits.max_waiting_roots
        })
        .await;
        // The resent root cost a first ask per retry interval at most, not one per resend.
        let resent_asks = header_requests(&s, resent);
        let intervals = start.elapsed().as_secs_f64() / limits.root_retry.as_secs_f64();
        assert!(resent_asks as f64 <= intervals + 1.0, "{resent_asks} asks");
        assert_eq!(header_requests(&s, root), 1, "the real root asked once");
    }

    #[tokio::test]
    async fn a_forged_column_first_cannot_keep_the_real_one_out() {
        let limits = IngestLimits {
            root_wait: Duration::from_secs(10),
            root_retry: Duration::from_millis(20),
            retries_per_sec: 1000,
            ..IngestLimits::default()
        };
        let s = store_with(0, &[], limits).await;
        let (_, ssz, root) = gloas_block(SLOT, &blobs().commitments);
        // A forged column of a real root still waiting for the reference: other bytes, so
        // gossip does not deduplicate it against the real one, which comes second.
        let mut forged = column_at(root, SLOT, CUSTODY_COLUMN);
        forged.sidecar.column[0][31] ^= 1;
        s.gossip(&forged);
        settle("the forged column to wait", || {
            s.ingest.waiting_roots() == 1
        })
        .await;
        let real = column_at(root, SLOT, CUSTODY_COLUMN);
        s.gossip(&real);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(s.ingest.pending(), 2, "both candidates wait");
        assert_eq!(s.dropped(Drop::RootWaitFull), 0);
        // The block becomes known: the forgery fails KZG, the real column is stored.
        s.reference.serve(root, SLOT, ssz);
        all_stored(&s, std::slice::from_ref(&real)).await;
        settle("the forgery to be dropped", || {
            s.dropped(Drop::KzgInvalid) == 1
        })
        .await;
    }

    #[tokio::test]
    async fn four_forgeries_first_cost_the_real_column_of_their_index() {
        let limits = IngestLimits {
            root_wait: Duration::from_secs(10),
            root_retry: Duration::from_millis(20),
            retries_per_sec: 1000,
            ..IngestLimits::default()
        };
        let s = store_with(0, &[], limits).await;
        let (_, ssz, root) = gloas_block(SLOT, &blobs().commitments);
        // MAX_CANDIDATES_PER_INDEX forgeries of one index, before the real column.
        for byte in 0..usize::from(MAX_CANDIDATES_PER_INDEX) {
            let mut forged = column_at(root, SLOT, CUSTODY_COLUMN);
            forged.sidecar.column[0][byte] ^= 1;
            s.gossip(&forged);
        }
        settle("the forgeries to wait", || s.ingest.waiting_roots() == 1).await;
        // The real column, fifth, finds the index full: dropped and counted, the documented
        // limit of the cap. Gossip delivers each message id once, so no later copy comes.
        let real = column_at(root, SLOT, CUSTODY_COLUMN);
        s.gossip(&real);
        settle("the real column to be refused", || {
            s.dropped(Drop::RootWaitFull) == 1
        })
        .await;
        // The root becomes known: the forgeries fail KZG, and the index stays empty.
        s.reference.serve(root, SLOT, ssz);
        settle("the forgeries to be dropped", || {
            s.dropped(Drop::KzgInvalid) == u64::from(MAX_CANDIDATES_PER_INDEX)
        })
        .await;
        settle("the queue to drain", || s.ingest.pending() == 0).await;
        assert_eq!(s.stored(&real), None, "the real column is lost");
        assert_eq!(s.writer.reader().column_count().unwrap(), 0);
        assert_eq!(s.dropped(Drop::RootWaitFull), 1);
    }

    #[tokio::test]
    async fn limits_that_cannot_bound_a_store_are_refused_at_start() {
        let defaults = IngestLimits::default();
        let refused = [
            (
                IngestLimits {
                    first_ask_burst: 0,
                    ..defaults
                },
                RefLimits::default(),
            ),
            (
                IngestLimits {
                    root_retry: Duration::ZERO,
                    ..defaults
                },
                RefLimits::default(),
            ),
            (
                IngestLimits {
                    retries_per_sec: 31,
                    ..defaults
                },
                RefLimits::default(),
            ),
            // A reference view with no more lookup places than seats.
            (
                defaults,
                RefLimits {
                    max_in_flight: defaults.max_waiting_roots,
                    ..RefLimits::default()
                },
            ),
        ];
        for (limits, ref_limits) in refused {
            let reference = Reference::start().await;
            let dir = tempfile::tempdir().unwrap();
            let writer = Arc::new(ColumnWriter::open(dir.path()).unwrap());
            let custody = Custody::open(
                Arc::clone(&writer),
                NoEnr,
                U256::MAX,
                Advertise::Withheld,
                0,
            )
            .unwrap();
            let contract = ColumnContract {
                kzg: Stalled::default(),
                verify_timeout: Duration::from_secs(1),
                metrics: ColumnMetrics::default(),
            };
            let refs = RefView::<_, Spec>::new(reference.api(), schedule(), ref_limits);
            let started = ColumnIngest::start(
                refs,
                custody,
                contract,
                writer,
                limits,
                QueueMetrics::default(),
            );
            let err = started.err().expect("refused");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        }
    }

    #[tokio::test]
    async fn only_contract_columns_are_stored() {
        let s = store_with(0, &[SLOT], IngestLimits::default()).await;
        let (root, slot) = s.blocks[0];
        // Not custody: dropped before any root wait or reference request.
        s.gossip(&column_at(root, slot, 5));
        // A flipped cell: the contract's KZG check drops it.
        let mut flipped = column_at(root, slot, 87);
        flipped.sidecar.column[0][31] ^= 1;
        s.gossip(&flipped);
        settle("both drops", || {
            s.dropped(Drop::NotCustody) == 1 && s.dropped(Drop::KzgInvalid) == 1
        })
        .await;
        settle("the queue to drain", || s.ingest.pending() == 0).await;
        assert_eq!(s.writer.reader().column_count().unwrap(), 0);
        // Every custody column of the block stores.
        for index in s.ingest.custody().custody_columns() {
            s.store(&column_at(root, slot, index)).await;
        }
        assert_eq!(s.writer.reader().column_count().unwrap(), 4);
        assert_eq!(s.exposed("probe_column_stored_total"), 4);
    }
}
