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
//!
//! # The send budget
//!
//! A block read later can go out first (cl-store's are read after cl-chain's), so the answer
//! holds its blocks until the last one is read. It holds at most the peer's send budget of
//! them ([`ChunkSink::budget`], `RpcLimits::max_queued_bytes_per_peer`), each counted as the
//! largest chunk it can go out as (`max_response_chunk_len`), and holds them as stored, raw
//! SSZ: each is decoded once to check it as it is read and again as it goes out, never held
//! decoded. A block is let go as its chunk is queued, which takes no more of the budget than
//! it was counted at, so what an answer holds plus what it has queued stays within the budget,
//! as a range answer's queued chunks do ([`super::responder`]).
//!
//! The answer is the request-order prefix of the blocks found that fits ("Clients MAY limit
//! the number of blocks in the response"): a block that does not fit cuts the answer at its
//! root, and so does one pushed out by a block read later for an earlier root; a full budget
//! cuts it after its last block. Nothing from the cut on is served or read: each half's
//! stream, in request order, is dropped at its first block past the cut, which cancels the
//! call, and cl-store is asked, and asked again, only for roots before the cut. A block whose
//! chunk alone is over the budget is held alone, as the sink queues it alone, so the first
//! block found always goes out ("MUST respond with at least one block, if they have it"). A
//! half that fails takes back the blocks it added, not the cut they made.

use super::blocks::{
    decode, BlockSource, Failed, Half, Out, RootItem, ServedBlock, BLOCK_LOOKUP_TIMEOUT,
};
use super::blocks_head::StoreStreams;
use super::metrics::RpcMetrics;
use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::EthSpec;
use futures::StreamExt as _;
use libp2p::PeerId;
use p2p_wire::rpc::codec::max_response_chunk_len;
use p2p_wire::rpc::protocols::{Request, Response};
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// The blocks an answer holds until they go out (see "The send budget"): as stored, by the
/// place of their root in the request, those of the request-order prefix that fits `budget`.
struct Held {
    /// The roots asked for, each once, in request order.
    wanted: Vec<[u8; 32]>,
    blocks: BTreeMap<usize, ServedBlock>,
    /// The chunk bytes the blocks held go out as, at most ([`cost`]).
    bytes: usize,
    budget: usize,
    /// The place of the first root not served: its block, or one before it, did not fit.
    cut: usize,
}

/// The most bytes `block` goes out as: one chunk, its context bytes and framing included.
fn cost(block: &ServedBlock) -> usize {
    max_response_chunk_len(block.ssz.len())
}

impl Held {
    /// Nothing held yet of `wanted`, within `budget` chunk bytes.
    fn new(wanted: Vec<[u8; 32]>, budget: usize) -> Self {
        Self {
            cut: wanted.len(),
            wanted,
            blocks: BTreeMap::new(),
            bytes: 0,
            budget,
        }
    }

    fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The place of `root` in the request.
    fn place(&self, root: &[u8; 32]) -> Option<usize> {
        self.wanted.iter().position(|r| r == root)
    }

    /// Whether `root` is asked for before the cut.
    fn before_cut(&self, root: &[u8; 32]) -> bool {
        self.place(root).is_some_and(|at| at < self.cut)
    }

    /// The roots before the cut with no block held, in request order.
    fn misses(&self) -> Vec<[u8; 32]> {
        (0..self.cut)
            .filter(|at| !self.blocks.contains_key(at))
            .map(|at| self.wanted[at])
            .collect()
    }

    /// Holds `block` if its root is before the cut, then lets go of the blocks of the latest
    /// roots, moving the cut to them, while the budget is over (a block alone is held whatever
    /// its size); its place if it is still held.
    fn hold(&mut self, block: ServedBlock) -> Option<usize> {
        let at = self.place(&block.root).filter(|at| *at < self.cut)?;
        self.bytes += cost(&block);
        if let Some(old) = self.blocks.insert(at, block) {
            self.bytes -= cost(&old);
        }
        while self.bytes > self.budget && self.blocks.len() > 1 {
            let Some((last, out)) = self.blocks.pop_last() else {
                break;
            };
            self.bytes -= cost(&out);
            self.cut = last;
        }
        if self.bytes >= self.budget {
            // No block after the last one held fits any more.
            let after = self.blocks.last_key_value().map_or(0, |(last, _)| last + 1);
            self.cut = self.cut.min(after);
        }
        self.blocks.contains_key(&at).then_some(at)
    }

    /// Lets go of the blocks held at `places`.
    fn take_back(&mut self, places: &[usize]) {
        for at in places {
            if let Some(block) = self.blocks.remove(at) {
                self.bytes -= cost(&block);
            }
        }
    }

    /// Lets go of the block of the first root held, and hands it over.
    fn next(&mut self) -> Option<ServedBlock> {
        let (_, block) = self.blocks.pop_first()?;
        self.bytes -= cost(&block);
        Some(block)
    }
}

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

    /// `half`'s blocks of `roots` into `held` while they fit, all or none: a failure takes back
    /// what it added. Its stream is read a block at a time and dropped at the first block past
    /// the cut (see "The send budget"). The roots before the cut it holds unfinalized.
    async fn ask<E: EthSpec>(
        &self,
        half: Half,
        roots: Vec<[u8; 32]>,
        held: &mut Held,
    ) -> Result<Vec<[u8; 32]>, Failed> {
        let opened = self.source.by_root(half, roots.clone()).await;
        let mut items = opened.map_err(|f| self.failed(half, f))?;
        let (mut added, mut seen, mut unfinalized) = (Vec::new(), HashSet::new(), Vec::new());
        let read = loop {
            let block = match items.next().await {
                None => break Ok(()),
                Some(Err(failed)) => break Err(failed),
                Some(Ok(RootItem::Unfinalized(root))) => {
                    if roots.contains(&root) {
                        unfinalized.push(root);
                    }
                    continue;
                }
                Some(Ok(RootItem::Block(block))) => block,
            };
            if let Err(failed) = decode::<E>(&block) {
                break Err(failed);
            }
            if !roots.contains(&block.root) || !seen.insert(block.root) {
                let why = "a block of a root not asked for, or twice";
                break Err(Failed::server_error("contract", why));
            }
            match held.hold(block) {
                Some(at) => added.push(at),
                // Past the cut: so is every block after it.
                None => break Ok(()),
            }
        };
        drop(items);
        if let Err(failed) = read {
            held.take_back(&added);
            return Err(self.failed(half, failed));
        }
        unfinalized.retain(|root| held.before_cut(root));
        Ok(unfinalized)
    }

    /// cl-store's blocks of `misses` into `held`, under a store-stream permit for a peer at
    /// `ip`: once more for the roots it holds unfinalized if `retry`.
    async fn ask_store<E: EthSpec>(
        &self,
        misses: Vec<[u8; 32]>,
        ip: Option<IpAddr>,
        retry: bool,
        held: &mut Held,
    ) -> Result<(), Failed> {
        let _permit = self
            .streams
            .take(ip)
            .map_err(|f| self.failed(Half::Store, f))?;
        let unfinalized = self.ask::<E>(Half::Store, misses, held).await?;
        if !retry || unfinalized.is_empty() {
            return Ok(());
        }
        tracing::debug!(
            roots = unfinalized.len(),
            "finality moved during a by-root answer: cl-store asked once more"
        );
        self.ask::<E>(Half::Store, unfinalized, held)
            .await
            .map(drop)
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
        let mut held = Held::new(wanted, out.sink.budget());
        let chain = self
            .ask::<E>(Half::Chain, held.wanted.clone(), &mut held)
            .await;
        let misses = held.misses();
        let mut failure = chain.as_ref().err().cloned();
        if !misses.is_empty() {
            let store = self.ask_store::<E>(misses, ip, chain.is_ok(), &mut held);
            failure = failure.or(store.await.err());
        }
        if let Some(failed) = failure.filter(|_| held.is_empty()) {
            return Err(failed);
        }
        while let Some(block) = held.next() {
            // Checked as it was read: decoded again only as it goes out, one at a time.
            let decoded = decode::<E>(&block)?.0;
            drop(block);
            if out
                .sink
                .send(Response::Block(Box::new(decoded)))
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
