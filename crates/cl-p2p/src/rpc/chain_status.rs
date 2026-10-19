//! Our Status from cl-chain: `ethswarm.chain.v1.ReqRespService/GetStatus` over its Unix socket
//! ([`ChainStatus`]), kept in the [`SharedStatus`] the swarm sends and answers from.
//!
//! cl-chain builds the Status (in probe mode `cl_chain::probe::StatusProvider`: the wall-clock
//! fork digest, the reference node's finalized checkpoint and block, and the slot the custody
//! columns are served from as `earliest_available_slot`); cl-p2p only maps it
//! ([`status_from_chain`]). Every call has a deadline ([`DEFAULT_CALL_DEADLINE`]), so a
//! cl-chain that never answers one costs that call only. cl-chain answers at once, from its
//! last good reference sample and a fresh read of its store, never waiting on the reference
//! API, so a stalled reference node does not run this deadline out.
//!
//! [`ChainStatusSource`] is the swarm's [`StatusSource`]: a peer's Status is judged against
//! the last good Status ([`ChainStatus::keep_current`] refreshes it), and every Status that
//! goes out (sent on a dial, or answered) is read fresh from cl-chain
//! ([`StatusSource::fresh`]), so its `earliest_available_slot` is what the column store serves
//! from at that moment, never a cached value the store has since passed (a first stored
//! column, a finality prune or a detected gap raises it). A fresh read that fails or passes its
//! deadline gives no Status: the peer's request is answered `2: ServerError` and nothing is
//! sent, rather than the cached value, which may be below what the store serves from.

use super::inbound::{
    status_from_chain, ChainStatusError, SharedStatus, StatusLookup, StatusSource,
};
use ethswarm_proto::chain as pb;
use p2p_wire::rpc::messages::StatusV2;
use pb::req_resp_service_client::ReqRespServiceClient;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Channel;

/// How often our Status is asked of cl-chain again by default \[est\]: 12 s, a mainnet slot,
/// often enough to follow finality, which moves once an epoch (the devnet probe's own refresh,
/// `devnet_probe::ours`, is the same).
pub const DEFAULT_STATUS_REFRESH: Duration = Duration::from_secs(12);

/// How long one `GetStatus` call may take by default \[est\]: 2 s, well within the refresh
/// interval and a peer's 5 s first-byte deadline for our answer.
pub const DEFAULT_CALL_DEADLINE: Duration = Duration::from_secs(2);

/// Why a `GetStatus` call gave no Status.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusCallError {
    /// The call failed: cl-chain is down, refused it, or has no Status yet.
    #[error("GetStatus failed: {0}")]
    Call(String),
    /// No answer within the call's deadline.
    #[error("GetStatus: no answer within its deadline")]
    Deadline,
    /// The response breaks the contract.
    #[error("GetStatus response: {0}")]
    Contract(#[from] ChainStatusError),
}

/// The `ethswarm.chain.v1.ReqRespService/GetStatus` client.
#[derive(Clone, Debug)]
pub struct ChainStatus {
    client: ReqRespServiceClient<Channel>,
    deadline: Duration,
}

impl ChainStatus {
    /// A client asking cl-chain over `channel` (a unary call: no hello), each call within
    /// [`DEFAULT_CALL_DEADLINE`].
    #[must_use]
    pub fn new(channel: Channel) -> Self {
        Self {
            client: ReqRespServiceClient::new(channel),
            deadline: DEFAULT_CALL_DEADLINE,
        }
    }

    /// The same client, each call within `deadline`.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// The Status cl-chain serves now.
    ///
    /// # Errors
    ///
    /// [`StatusCallError`].
    pub async fn status(&self) -> Result<StatusV2, StatusCallError> {
        let mut client = self.client.clone();
        let response =
            tokio::time::timeout(self.deadline, client.get_status(pb::GetStatusRequest {}))
                .await
                .map_err(|_| StatusCallError::Deadline)?
                .map_err(|status| StatusCallError::Call(status.code().to_string()))?;
        Ok(status_from_chain(response.get_ref())?)
    }

    /// Asks once now and then every `every`, each good answer replacing the Status in
    /// `shared`; a failed one is logged and the last good Status kept. Runs until the returned
    /// task is aborted.
    #[must_use]
    pub fn keep_current(
        self,
        shared: Arc<SharedStatus>,
        every: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(every);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                match self.status().await {
                    Ok(status) => shared.set(status),
                    Err(e) => tracing::warn!(error = %e, "our Status: keeping the last good one"),
                }
            }
        })
    }
}

/// The swarm's Status from cl-chain (see the module docs): the last good one for judging, a
/// fresh read for every Status that goes out.
#[derive(Clone, Debug)]
pub struct ChainStatusSource {
    client: ChainStatus,
    cached: Arc<SharedStatus>,
}

impl ChainStatusSource {
    /// A source reading from `client`, nothing cached yet.
    #[must_use]
    pub fn new(client: ChainStatus) -> Self {
        Self {
            client,
            cached: Arc::new(SharedStatus::new(None)),
        }
    }

    /// The last good Status, which [`Self::keep_current`] refreshes.
    #[must_use]
    pub fn cached(&self) -> Arc<SharedStatus> {
        Arc::clone(&self.cached)
    }

    /// Refreshes the cached Status every `every` ([`ChainStatus::keep_current`]).
    #[must_use]
    pub fn keep_current(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        self.client.clone().keep_current(self.cached(), every)
    }
}

impl StatusSource for ChainStatusSource {
    fn status(&self) -> Option<StatusV2> {
        self.cached.status()
    }

    fn fresh(&self) -> Option<StatusLookup> {
        let (client, cached) = (self.client.clone(), self.cached());
        Some(Box::pin(async move {
            match client.status().await {
                Ok(status) => {
                    cached.set(status.clone());
                    Some(status)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "no fresh Status of ours: none goes out");
                    None
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_chain::probe::ProbeError;
    use cl_chain::reqresp::{
        ChainStatus as Served, ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock,
        StatusLookup,
    };
    use cl_chain_columns::ColumnWriter;
    use consensus_types::primitives::U256;
    use ethswarm_proto::common::{Checkpoint, Hello};
    use ipc::envelope::DigestTable;
    use ipc::Link;
    use network_config::{ForkName, ForkSchedule, ScheduledFork};
    use std::sync::Mutex;

    struct Always;

    impl ServeClock for Always {
        fn serve_range(&self) -> Option<(u64, u64)> {
            Some((0, 1000))
        }

        fn fork_digest(&self, _: u64) -> Option<[u8; 4]> {
            Some([1, 2, 3, 4])
        }
    }

    /// cl-chain's Status, scripted: the next answer per call (`None`: a call that never
    /// ends), the last one again once drawn.
    struct Scripted(Mutex<Vec<Option<Result<pb::GetStatusResponse, ProbeError>>>>);

    impl Served for Scripted {
        fn status(&self) -> StatusLookup<'_> {
            let mut answers = self.0.lock().unwrap();
            let next = if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone()
            };
            Box::pin(async move {
                match next {
                    Some(answer) => answer,
                    None => std::future::pending().await,
                }
            })
        }
    }

    fn response(head_slot: u64) -> pb::GetStatusResponse {
        pb::GetStatusResponse {
            fork_digest: vec![1, 2, 3, 4],
            finalized: Some(Checkpoint {
                epoch: 2,
                root: vec![0xaa; 32],
            }),
            head_root: vec![0xaa; 32],
            head_slot,
            earliest_available_slot: 100,
        }
    }

    fn link() -> Link {
        let at = |epoch| ScheduledFork {
            version: [7, 0, 0, 0],
            epoch,
        };
        let hello = Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 1,
            ..Default::default()
        };
        let digests = DigestTable::new(vec![(0, ForkName::Gloas, [1, 2, 3, 4])]).unwrap();
        Link::new::<consensus_types::Mainnet>(
            hello,
            1,
            ForkSchedule::new(at(0), at(0)).unwrap(),
            digests,
        )
    }

    /// cl-chain's `ReqRespService` on a Unix socket, serving `answers` as its Status.
    async fn chain(
        answers: Vec<Result<pb::GetStatusResponse, ProbeError>>,
    ) -> (Channel, tempfile::TempDir, tokio::sync::oneshot::Sender<()>) {
        chain_steps(answers.into_iter().map(Some).collect()).await
    }

    /// [`chain`], `None` a call that never ends.
    async fn chain_steps(
        answers: Vec<Option<Result<pb::GetStatusResponse, ProbeError>>>,
    ) -> (Channel, tempfile::TempDir, tokio::sync::oneshot::Sender<()>) {
        let dir = tempfile::tempdir().unwrap();
        let writer = std::sync::Arc::new(ColumnWriter::open(dir.path().join("columns")).unwrap());
        let columns = std::sync::Arc::new(ColumnServer::new(
            writer as std::sync::Arc<dyn ColumnStore>,
            U256::MAX,
            std::sync::Arc::new(Always),
            ServeBudget::default(),
        ));
        let server = ReqRespServer::new(link(), columns)
            .serving_status(std::sync::Arc::new(Scripted(Mutex::new(answers))));
        let socket = dir.path().join("chain.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(ipc::stub::serve_uds(
            listener,
            tonic::service::Routes::new(server.into_service()),
            async {
                let _ = stopped.await;
            },
        ));
        let uid = ipc::uds::Ownership::current().uid;
        let channel = ipc::uds::connect_path(&socket, uid).await.unwrap();
        (channel, dir, stop)
    }

    #[tokio::test]
    async fn the_status_is_cl_chains_mapped() {
        let (channel, _dir, _stop) = chain(vec![
            Ok(response(64)),
            Err(ProbeError::Unavailable("no sample".into())),
            Ok(pb::GetStatusResponse {
                head_root: vec![1; 31],
                ..response(64)
            }),
        ])
        .await;
        let client = ChainStatus::new(channel);
        let status = client.status().await.unwrap();
        assert_eq!(status, status_from_chain(&response(64)).unwrap());
        assert_eq!(status.earliest_available_slot, 100);
        assert_eq!(
            client.status().await.unwrap_err(),
            StatusCallError::Call(tonic::Code::Unavailable.to_string())
        );
        assert!(matches!(
            client.status().await.unwrap_err(),
            StatusCallError::Contract(ChainStatusError::Length {
                field: "head_root",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn the_shared_status_follows_cl_chain_and_keeps_the_last_good_one() {
        let (channel, _dir, _stop) = chain(vec![
            Err(ProbeError::Unavailable("no sample".into())),
            Ok(response(64)),
            Err(ProbeError::Unavailable("outage".into())),
            Ok(response(72)),
        ])
        .await;
        let shared = Arc::new(SharedStatus::new(None));
        let task =
            ChainStatus::new(channel).keep_current(Arc::clone(&shared), Duration::from_millis(30));
        let mut seen = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while seen.last() != Some(&Some(72)) {
            assert!(tokio::time::Instant::now() < deadline, "{seen:?}");
            let head = shared.status().map(|s| s.head_slot);
            if seen.last() != Some(&head) {
                seen.push(head);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // None until cl-chain had a Status, then 64 through the outage, then 72.
        assert_eq!(seen, [None, Some(64), Some(72)]);
        task.abort();
    }

    /// A call that never ends is cut at its deadline, and the next refresh still runs.
    #[tokio::test]
    async fn a_stalled_call_does_not_stop_the_refresh() {
        let (channel, _dir, _stop) = chain_steps(vec![None, Some(Ok(response(64)))]).await;
        let shared = Arc::new(SharedStatus::new(None));
        let client = ChainStatus::new(channel).with_deadline(Duration::from_millis(100));
        let task = client.keep_current(Arc::clone(&shared), Duration::from_millis(30));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while shared.status().is_none() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the refresh stopped"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(shared.status().unwrap().head_slot, 64);
        task.abort();
    }

    #[tokio::test]
    async fn a_call_past_its_deadline_is_an_error() {
        let (channel, _dir, _stop) = chain_steps(vec![None]).await;
        let client = ChainStatus::new(channel).with_deadline(Duration::from_millis(50));
        assert_eq!(client.status().await, Err(StatusCallError::Deadline));
    }

    /// The service's Status source: the last good Status for judging, a fresh `GetStatus` for
    /// each Status that goes out, and no Status at all when that read fails, never the cached
    /// one (which may be below what the store serves from by now).
    #[tokio::test]
    async fn the_source_reads_fresh_and_refuses_on_a_failed_read() {
        let (channel, _dir, _stop) = chain_steps(vec![
            Some(Ok(response(64))),
            Some(Err(ProbeError::Unavailable("store".into()))),
            None,
            Some(Ok(response(72))),
        ])
        .await;
        let source = ChainStatusSource::new(
            ChainStatus::new(channel).with_deadline(Duration::from_millis(100)),
        );
        assert_eq!(source.status(), None);
        let fresh = |s: &ChainStatusSource| s.fresh().expect("reads fresh");
        assert_eq!(fresh(&source).await.map(|s| s.head_slot), Some(64));
        assert_eq!(source.status().map(|s| s.head_slot), Some(64), "kept");
        assert_eq!(fresh(&source).await, None, "a refused read");
        assert_eq!(fresh(&source).await, None, "a stalled read");
        assert_eq!(source.status().map(|s| s.head_slot), Some(64));
        assert_eq!(fresh(&source).await.map(|s| s.head_slot), Some(72));
        assert!(Arc::ptr_eq(&source.cached(), &source.cached()));
    }
}
