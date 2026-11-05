//! `BeaconBlocksByHead` v1 answers (#230; `fulu/p2p-interface.md` L796–863):
//! [`ByHeadResponder`], built from the range responder
//! ([`super::blocks::ByRangeResponder::head_responder`]) over the same [`BlockSource`], and
//! [`NoBlocks`] for a node with no block source.
//!
//! # An answer
//!
//! [`super::inbound::Control`] books `min(count, MAX_REQUEST_BLOCKS_DENEB)` tokens (a larger
//! `count` is served as 128, never `1`: L820–821, Ezra's ruling of 2026-11-01) and starts the
//! answer at the peer's first token; `count` 0 is an empty success, never served. Then, on the
//! answer's own task:
//!
//! 1. **The window**: its start is read once ([`WindowStart`], the range responder's:
//!    `network_config::window`, the Gloas formula from `GLOAS_FORK_EPOCH` on). When it is
//!    unknown (before genesis, or a config without its values) no window applies: every block
//!    held is served, and that is logged once.
//! 2. **A lookup slot** from the range responder's pool: at most
//!    [`super::limits::RpcLimits::max_block_lookups`] answers of either protocol hold IPC calls
//!    at once; one past them waits up to [`BLOCK_LOOKUP_TIMEOUT`], then is `2` (`busy`).
//! 3. **One store walk** ([`BlockSource::by_head`], cl-store's `GetBlocksByHead`) for finalized
//!    and unfinalized blocks alike: a walk addressed by a root asks no fork choice question, so
//!    it is never split at the finalized slot. A root the store does not hold is a success of
//!    zero chunks (L832: "zero or more"; the ≥ 1 block of L840–841 is for a root we hold).
//! 4. **The walk's shape**: the first block is the one at `beacon_root`, each next one the
//!    parent of the block before, at a lower slot (L819–820), each decoded by the fork of its
//!    slot to a block of that slot. A break is `2` before the first chunk, a clean end after it.
//! 5. **The window again**: the block at `beacon_root` below the window's start is
//!    `3: ResourceUnavailable` (L836–838; ruling), and a later ancestor below it ends the answer
//!    with success before it.
//! 6. **The count**: the walk stops at `min(count, 128)` blocks whatever the store sends and
//!    drops the store's stream, which cancels the call. Blocks go out one at a time as the sink
//!    takes them, never collected: a slow reader holds the store back.
//!
//! Rate limiting never empties an answer (L842–843; ruling): the walk starts at the peer's first
//! token, so a held root's block goes out whole at that token. A failed lookup ends the answer
//! with its code before the first chunk (cl-store's `UNAVAILABLE` is `3`, any other failure
//! `2`), else cleanly at the last whole chunk, counted in
//! `rpc_block_lookup_failures_total{half="store", kind}`.

use super::blocks::{decode, BlockSource, Failed, Half, Out, WindowStart, BLOCK_LOOKUP_TIMEOUT};
use super::metrics::RpcMetrics;
use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::EthSpec;
use futures::StreamExt as _;
use libp2p::PeerId;
use p2p_wire::rpc::messages::BlocksByHeadV1Request;
use p2p_wire::rpc::protocols::{Request, Response, ResultCode, MAX_REQUEST_BLOCKS_DENEB};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Serves BeaconBlocksByHead v1 from a [`BlockSource`] (see the module docs).
#[derive(Clone)]
pub struct ByHeadResponder {
    source: Arc<dyn BlockSource>,
    lookups: Arc<Semaphore>,
    metrics: Option<RpcMetrics>,
    window: Option<WindowStart>,
    /// Whether an unknown window was logged.
    warned: Arc<AtomicBool>,
}

impl ByHeadResponder {
    /// Answers from `source`, holding one of `lookups` while it reads, its failures counted in
    /// `metrics`, below `window`'s start refused.
    pub(super) fn new(
        source: Arc<dyn BlockSource>,
        lookups: Arc<Semaphore>,
        metrics: Option<RpcMetrics>,
        window: Option<WindowStart>,
    ) -> Self {
        Self {
            source,
            lookups,
            metrics,
            window,
            warned: Arc::default(),
        }
    }

    /// The start slot of the serve window now; `None` (logged once) when it is unknown.
    fn window_start(&self) -> Option<u64> {
        let start = self.window.as_ref().and_then(|window| window());
        if start.is_none() && !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "the block serve window is unknown: BeaconBlocksByHead serves every block held"
            );
        }
        start
    }

    /// Counts and logs `failed`, and hands it back.
    fn failed(&self, failed: Failed) -> Failed {
        tracing::debug!(kind = failed.kind, why = %failed.why, "block walk failed");
        if let Some(metrics) = &self.metrics {
            metrics.block_lookup_failed(Half::Store.label(), failed.kind);
        }
        failed
    }

    /// The answer to `head` into `out` (see the module docs).
    async fn answer<E: EthSpec>(
        &self,
        head: BlocksByHeadV1Request,
        out: &mut Out<E>,
    ) -> Result<(), Failed> {
        let count = head.count.min(MAX_REQUEST_BLOCKS_DENEB);
        let floor = self.window_start();
        let slot = Arc::clone(&self.lookups).acquire_owned();
        let Ok(Ok(_slot)) = tokio::time::timeout(BLOCK_LOOKUP_TIMEOUT, slot).await else {
            return Err(Failed::server_error("busy", "no lookup slot in time"));
        };
        let opened = self.source.by_head(head.beacon_root.0, count).await;
        let mut blocks = opened.map_err(|f| self.failed(f))?;
        // The root the next block must have, and the slot it must be below.
        let (mut want, mut above) = (head.beacon_root.0, None);
        while (out.sent as u64) < count {
            let Some(next) = blocks.next().await else {
                break;
            };
            let block = next.map_err(|f| self.failed(f))?;
            if block.root != want || above.is_some_and(|slot| block.slot >= slot) {
                let why = format!("slot {}: not the block the walk asked for", block.slot);
                return Err(self.failed(Failed::server_error("link", why)));
            }
            if floor.is_some_and(|start| block.slot < start) {
                if out.sent > 0 {
                    return Ok(());
                }
                return Err(Failed {
                    code: ResultCode::ResourceUnavailable,
                    kind: "window",
                    why: format!("slot {} below the serve window", block.slot),
                });
            }
            let (decoded, parent) = decode::<E>(&block).map_err(|f| self.failed(f))?;
            if out
                .sink
                .send(Response::Block(Box::new(decoded)))
                .await
                .is_err()
            {
                return Err(Failed::server_error("closed", "the answer has ended"));
            }
            out.sent += 1;
            (want, above) = (parent, Some(block.slot));
        }
        Ok(())
    }
}

impl<E: EthSpec> Responder<E> for ByHeadResponder {
    fn serve(&self, _: PeerId, request: Request, sink: ChunkSink<E>) -> Serving {
        let this = self.clone();
        Box::pin(async move {
            let Request::BlocksByHead(head) = request else {
                return;
            };
            let mut out = Out::new(sink);
            if let Err(failed) = this.answer(head, &mut out).await {
                out.end(failed).await;
            }
        })
    }
}

/// The BeaconBlocksByHead responder of a node with no block source: every request is an empty
/// success at the peer's token, since we hold nothing we can reach.
pub(crate) struct NoBlocks;

impl<E: EthSpec> Responder<E> for NoBlocks {
    fn serve(&self, _: PeerId, _: Request, _: ChunkSink<E>) -> Serving {
        Box::pin(async {})
    }
}
