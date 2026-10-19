//! Our Status: probe mode's [`StatusProvider`] (cl-chain) over the reference CL's beacon API,
//! sampled once before the first dial and then every refresh interval, kept in the
//! [`SharedStatus`] the probe swarm answers and sends from.
//!
//! The fork digest is `compute_fork_digest` of the wall-clock epoch on the devnet's config; the
//! finalized checkpoint and head are the reference API's finalized checkpoint and its block. A
//! failed sample keeps the last good one (the provider's rule); with none at the start there is
//! no Status of ours, and the probe dials nobody.

use super::api::ProbeApi;
use super::devnet::Devnet;
use cl_chain::probe::{StatusProvider, DEFAULT_API_TIMEOUT};
use cl_p2p::rpc::inbound::{status_from_chain, SharedStatus, StatusSource};
use p2p_wire::rpc::messages::StatusV2;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::AbortHandle;

/// Unix milliseconds now.
pub type Clock = Arc<dyn Fn() -> u128 + Send + Sync>;

/// How often our Status is sampled again by default \[est\].
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(12);

/// Our Status, kept current by a task that ends when this is dropped.
pub struct OurStatus {
    shared: Arc<SharedStatus>,
    task: AbortHandle,
}

/// One sample of `provider` as a Status: the reference API sampled now (a failed sample keeps
/// the last good one), then the Status from it.
async fn sample(provider: &StatusProvider<ProbeApi>, clock: &Clock) -> Result<StatusV2, String> {
    if let Err(e) = provider.refresh().await {
        tracing::debug!(error = %e, "our Status: no new reference sample");
    }
    let response = provider.status(clock()).map_err(|e| e.to_string())?;
    status_from_chain(&response).map_err(|e| e.to_string())
}

impl OurStatus {
    /// Samples our Status once, then every `every`.
    ///
    /// # Errors
    ///
    /// The first sample failed: no Status of ours.
    pub async fn start(
        devnet: &Devnet,
        api: ProbeApi,
        clock: Clock,
        every: Duration,
    ) -> Result<(Self, StatusV2), String> {
        let provider = StatusProvider::new(api, devnet.probe_chain(), DEFAULT_API_TIMEOUT);
        let first = sample(&provider, &clock)
            .await
            .map_err(|e| format!("no Status of ours: {e}"))?;
        let shared = Arc::new(SharedStatus::new(Some(first.clone())));
        let keep = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            let mut ticks = tokio::time::interval(every);
            ticks.tick().await;
            loop {
                ticks.tick().await;
                match sample(&provider, &clock).await {
                    Ok(status) => keep.set(status),
                    Err(e) => tracing::warn!(error = %e, "our Status: keeping the last good one"),
                }
            }
        })
        .abort_handle();
        Ok((Self { shared, task }, first))
    }

    /// The source the probe swarm reads our Status from.
    #[must_use]
    pub fn source(&self) -> Arc<dyn StatusSource> {
        Arc::clone(&self.shared) as Arc<dyn StatusSource>
    }

    /// Our Status now.
    #[must_use]
    pub fn current(&self) -> Option<StatusV2> {
        self.shared.status()
    }
}

impl Drop for OurStatus {
    fn drop(&mut self) {
        self.task.abort();
    }
}
