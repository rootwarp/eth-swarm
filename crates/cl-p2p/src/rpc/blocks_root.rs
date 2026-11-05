//! `BeaconBlocksByRoot` v2 answers (`phase0/p2p-interface.md` L1577–1626, `deneb` L878–911,
//! `gloas` L1376–1394): [`ByRootResponder`], built from the range responder
//! ([`super::blocks::ByRangeResponder::root_responder`]) over the same [`BlockSource`], lookup
//! slots and metrics, and the BlocksByHead pool of store streams ([`super::blocks_head`]).
//!
//! [`super::inbound::Control`] dispatches it ([`super::inbound::Control::with_root_responder`]):
//! a request naming more than `MAX_REQUEST_BLOCKS_DENEB` (128) roots is past its SSZ bound and
//! gets `1: InvalidRequest` from the codec; one naming none is an empty success. It books one
//! token per root named, of its own bucket; a duplicate's goes back once the answer ended.
//!
//! # An answer
//!
//! On the answer's own task:
//!
//! 1. **The roots**: each once, in request order.
//! 2. **A lookup slot** from the range responder's pool, held to the answer's end as a range
//!    answer's is (its blocks are held until they went out); one past them waits up to
//!    [`BLOCK_LOOKUP_TIMEOUT`], then is `2` (`busy`).
//! 3. **cl-chain first**: one call for every root ([`BlockSource::by_root`], chain.v1
//!    `BlocksByRoot`), the blocks it stores above its finalized slot on any branch, orphans it
//!    still holds included.
//! 4. **cl-store for the rest**: one call (store.v1 `GetBlocksByRoot`) under a store-stream
//!    permit (`3` past the pool or the IP's share, counted as kind `streams` or `ip_streams`),
//!    the finalized blocks. A root cl-store holds above its own finalized slot that cl-chain
//!    answered without was finalized by cl-chain meanwhile: cl-store is asked once more for
//!    those roots.
//! 5. **Request order**: the blocks go out in the order of their roots in the request, each
//!    decoded by the fork of its slot and sent with the digest of its own epoch. A root neither
//!    half serves gets no chunk (L1598–1600).
//!
//! A half whose call fails (cl-store's `UNAVAILABLE` and cl-chain's `RESOURCE_UNAVAILABLE` are
//! `3`, any other failure `2`), or that answers a root it was not asked for, one twice, or a
//! block that does not decode by the fork of its slot, adds nothing and is counted in
//! `rpc_block_lookup_failures_total{half, kind}`: the answer is what the other half found, or
//! the first failure's code if neither found anything. Each IPC step runs under
//! [`BLOCK_LOOKUP_TIMEOUT`], and the stream's writer cuts the answer at its deadlines.

use super::blocks::{decode, BlockSource, ByRoot, Failed, Half, Out, BLOCK_LOOKUP_TIMEOUT};
use super::blocks_head::StoreStreams;
use super::metrics::RpcMetrics;
use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::{forked, EthSpec};
use libp2p::PeerId;
use p2p_wire::rpc::protocols::{Request, Response};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// The blocks found so far, by root.
type Found<E> = HashMap<[u8; 32], forked::SignedBeaconBlock<E>>;

/// Serves BeaconBlocksByRoot v2 from a [`BlockSource`] (see the module docs).
#[derive(Clone)]
pub struct ByRootResponder {
    source: Arc<dyn BlockSource>,
    lookups: Arc<Semaphore>,
    streams: StoreStreams,
    metrics: Option<RpcMetrics>,
}

impl ByRootResponder {
    /// Answers from `source`, holding one of `lookups` and, for its cl-store call, one of
    /// `streams`, its failures counted in `metrics`.
    pub(super) fn new(
        source: Arc<dyn BlockSource>,
        lookups: Arc<Semaphore>,
        streams: StoreStreams,
        metrics: Option<RpcMetrics>,
    ) -> Self {
        Self {
            source,
            lookups,
            streams,
            metrics,
        }
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

    /// `half`'s blocks of `roots` into `found`, all or none; the roots it holds unfinalized.
    async fn ask<E: EthSpec>(
        &self,
        half: Half,
        roots: Vec<[u8; 32]>,
        found: &mut Found<E>,
    ) -> Result<Vec<[u8; 32]>, Failed> {
        let answer = self.source.by_root(half, roots.clone()).await;
        let ByRoot {
            blocks,
            unfinalized,
        } = answer.map_err(|f| self.failed(half, f))?;
        let mut new = Found::new();
        for block in blocks {
            let decoded = decode::<E>(&block).map_err(|f| self.failed(half, f))?.0;
            if !roots.contains(&block.root) || new.insert(block.root, decoded).is_some() {
                let why = "a block of a root not asked for, or twice";
                return Err(self.failed(half, Failed::server_error("contract", why)));
            }
        }
        found.extend(new);
        Ok(unfinalized
            .into_iter()
            .filter(|root| roots.contains(root))
            .collect())
    }

    /// cl-store's blocks of `misses` into `found`, under a store-stream permit for a peer at
    /// `ip`: once more for the roots it holds unfinalized if `retry`.
    async fn ask_store<E: EthSpec>(
        &self,
        misses: Vec<[u8; 32]>,
        ip: Option<IpAddr>,
        retry: bool,
        found: &mut Found<E>,
    ) -> Result<(), Failed> {
        let _permit = self
            .streams
            .take(ip)
            .map_err(|f| self.failed(Half::Store, f))?;
        let unfinalized = self.ask(Half::Store, misses, found).await?;
        if !retry || unfinalized.is_empty() {
            return Ok(());
        }
        tracing::debug!(
            roots = unfinalized.len(),
            "finality moved during a by-root answer: cl-store asked once more"
        );
        self.ask(Half::Store, unfinalized, found).await.map(drop)
    }

    /// The answer to `roots` from a peer at `ip` into `out` (see the module docs).
    async fn answer<E: EthSpec>(
        &self,
        roots: Vec<[u8; 32]>,
        ip: Option<IpAddr>,
        out: &mut Out<E>,
    ) -> Result<(), Failed> {
        let mut wanted: Vec<[u8; 32]> = Vec::with_capacity(roots.len());
        for root in roots {
            if !wanted.contains(&root) {
                wanted.push(root);
            }
        }
        let slot = Arc::clone(&self.lookups).acquire_owned();
        let Ok(Ok(_slot)) = tokio::time::timeout(BLOCK_LOOKUP_TIMEOUT, slot).await else {
            return Err(Failed::server_error("busy", "no lookup slot in time"));
        };
        let mut found = Found::new();
        let chain = self.ask(Half::Chain, wanted.clone(), &mut found).await;
        let misses: Vec<[u8; 32]> = wanted
            .iter()
            .filter(|root| !found.contains_key(*root))
            .copied()
            .collect();
        let mut failure = chain.as_ref().err().cloned();
        if !misses.is_empty() {
            let store = self.ask_store(misses, ip, chain.is_ok(), &mut found);
            failure = failure.or(store.await.err());
        }
        if let Some(failed) = failure.filter(|_| found.is_empty()) {
            return Err(failed);
        }
        for root in &wanted {
            let Some(block) = found.remove(root) else {
                continue;
            };
            if out
                .sink
                .send(Response::Block(Box::new(block)))
                .await
                .is_err()
            {
                return Err(Failed::server_error("closed", "the answer has ended"));
            }
            out.sent += 1;
        }
        Ok(())
    }
}

impl<E: EthSpec> Responder<E> for ByRootResponder {
    /// The answer to a peer whose IP is not known: not counted per IP.
    fn serve(&self, peer: PeerId, request: Request, sink: ChunkSink<E>) -> Serving {
        self.serve_from(peer, None, request, sink)
    }

    fn serve_from(
        &self,
        _: PeerId,
        ip: Option<IpAddr>,
        request: Request,
        sink: ChunkSink<E>,
    ) -> Serving {
        let this = self.clone();
        Box::pin(async move {
            let Request::BlocksByRoot(roots) = request else {
                return;
            };
            let roots = roots.0.iter().map(|root| root.0).collect();
            let mut out = Out::new(sink);
            if let Err(failed) = this.answer(roots, ip, &mut out).await {
                out.end(failed).await;
            }
        })
    }
}

#[cfg(test)]
#[path = "blocks_root_tests.rs"]
mod tests;
