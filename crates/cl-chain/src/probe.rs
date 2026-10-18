//! Probe mode: the Status cl-chain hands cl-p2p over `ethswarm.chain.v1.ReqRespService/
//! GetStatus` while it imports nothing of its own.
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
}
