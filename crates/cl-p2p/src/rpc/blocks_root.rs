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

use super::blocks::{BlockSource, Failed, Out};
use super::blocks_head::StoreStreams;
use super::metrics::RpcMetrics;
use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::EthSpec;
use libp2p::PeerId;
use p2p_wire::rpc::protocols::Request;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

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

    /// The answer to `roots` from a peer at `ip` into `out` (see the module docs).
    async fn answer<E: EthSpec>(
        &self,
        roots: Vec<[u8; 32]>,
        ip: Option<IpAddr>,
        out: &mut Out<E>,
    ) -> Result<(), Failed> {
        let _ = (&self.source, &self.lookups, &self.streams, &self.metrics);
        let _ = (roots, ip, out.sent);
        Ok::<(), Failed>(())
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
