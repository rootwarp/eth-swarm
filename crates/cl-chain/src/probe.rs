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
//! - `earliest_available_slot`: `head_slot` until the probe serves a range of its own.
//!
//! Each [`StatusProvider::status`] samples the API under a bounded timeout. A sample that fails
//! or times out (an outage) keeps the last good one; with none yet, the Status is
//! [`ProbeError::Unavailable`], which the RPC answers `UNAVAILABLE` and cl-p2p treats as "no
//! Status": it sends none and judges none, never a guessed one.

mod beacon_api;
pub mod column;
mod ref_view;

pub use beacon_api::BeaconApi;
pub use column::{
    storage_contract, store_verified, ColumnContract, ColumnMetrics, Drop, GossipColumn, Verified,
};
pub use ref_view::{BlockApi, RefBlock, RefError, RefLimits, RefView};

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

/// Builds the probe's Status from the wall clock and the reference API (see the module docs).
pub struct StatusProvider<A> {
    api: A,
    chain: ProbeChain,
    timeout: Duration,
    last_good: Mutex<Option<Sample>>,
}

impl<A: ReferenceApi> StatusProvider<A> {
    /// A provider sampling `api` for `chain`, each sample within `timeout`.
    pub fn new(api: A, chain: ProbeChain, timeout: Duration) -> Self {
        Self {
            api,
            chain,
            timeout,
            last_good: Mutex::new(None),
        }
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
                Ok(sample) => *last = Some(sample),
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
            earliest_available_slot: sample.head.slot,
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
        _reference: FixtureServer,
        _dir: tempfile::TempDir,
    }

    /// The reference serves the headers and blocks of `blocks` (root, SSZ), 404 for any other.
    async fn reference(blocks: Vec<(Root, Vec<u8>)>) -> FixtureServer {
        let mut replies = HashMap::new();
        for (root, ssz) in blocks {
            let id = format!("0x{}", hex::encode(root));
            let header = format!(
                r#"{{"data":{{"root":"{id}","canonical":true,"header":{{"message":{{"slot":"{SLOT}"}}}}}}}}"#
            );
            replies.insert(format!("/eth/v1/beacon/headers/{id}"), Reply::json(&header));
            replies.insert(format!("/eth/v2/beacon/blocks/{id}"), Reply::ssz(ssz));
        }
        FixtureServer::start(move |_, path| {
            replies
                .get(path)
                .cloned()
                .unwrap_or_else(|| Reply::status(404))
        })
        .await
    }

    async fn contract_with(verify: Served, verify_timeout: Duration) -> Contract {
        let b = blobs();
        let (_, ssz, root) = gloas_block(SLOT, &b.commitments);
        let (_, one_ssz, one_blob_root) = gloas_block(SLOT, &b.commitments[..1]);
        let server = reference(vec![(root, ssz), (one_blob_root, one_ssz)]).await;
        let api = BeaconApi::new(&format!("http://{}", server.addr), DEFAULT_API_TIMEOUT).unwrap();
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
}
