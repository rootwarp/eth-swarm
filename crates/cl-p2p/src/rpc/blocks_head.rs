//! `BeaconBlocksByHead` v1 answers (#230; `fulu/p2p-interface.md` L796–863):
//! [`ByHeadResponder`], built from the range responder
//! ([`super::blocks::ByRangeResponder::head_responder`]) over the same [`BlockSource`], and
//! [`NoBlocks`] for a node with no block source.
//!
//! [`super::inbound::Control`] dispatches it ([`super::inbound::Control::with_head_responder`]).
//! It is a [`Responder`] for a streamed answer ([`super::responder`]), which books
//! `min(count, MAX_REQUEST_BLOCKS_DENEB)` tokens ([`Request::max_response_chunks`]: a larger
//! `count` is served as 128, never `1`, L820–821; Ezra's ruling of 2026-11-01), runs it from the
//! peer's first token, and never runs it for `count` 0, an empty success.
//!
//! # An answer
//!
//! On the answer's own task:
//!
//! 1. **The window**: its start is read once ([`WindowStart`], the range responder's:
//!    `network_config::window`, the Gloas formula from `GLOAS_FORK_EPOCH` on). When it is
//!    unknown (before genesis, or a config without its values) no window applies: every block
//!    held is served, and that is logged once.
//! 2. **A store-stream permit** ([`StoreStreams`], the range responder's), taken at once or not
//!    at all, before the lookup slot: at most [`MAX_BYHEAD_STORE_STREAMS`] (24) answers hold a
//!    cl-store stream at once, at most [`MAX_BYHEAD_STORE_STREAMS_PER_IP`] (4) of them for the
//!    peers of one IP (an IPv4 address or an IPv6 /58, [`BYHEAD_IP_PREFIXES`]). One past either is
//!    `3: ResourceUnavailable` before any chunk, as cl-store answers a walk past its own cap,
//!    reading nothing and holding nothing (counted, kind `streams` or `ip_streams`). The
//!    permit goes with the store stream, dropped with it: at the count, an end or a reset.
//! 3. **A lookup slot** from the range responder's pool, for each store read: at most
//!    [`super::limits::RpcLimits::max_block_lookups`] answers of either protocol hold IPC calls
//!    at once; one past them waits up to [`BLOCK_LOOKUP_TIMEOUT`], then is `2` (`busy`) before
//!    the first chunk and a clean end after it. The slot goes back while the sink waits on the
//!    peer, so a slow reader holds none (only its store stream and its permit).
//! 4. **One store walk** ([`BlockSource::by_head`], cl-store's `GetBlocksByHead`) for finalized
//!    and unfinalized blocks alike: a walk addressed by a root asks no fork choice question, so
//!    it is never split at the finalized slot. A root the store does not hold is a success of
//!    zero chunks (L832: "zero or more"; the ≥ 1 block of L840–841 is for a root we hold).
//! 5. **The walk's shape**: the first block is the one at `beacon_root`, each next one the
//!    parent of the block before, at a lower slot (L819–820), each decoded by the fork of its
//!    slot to a block of that slot. A break is `2` before the first chunk, a clean end after it.
//! 6. **The window again**: the block at `beacon_root` below the window's start is
//!    `3: ResourceUnavailable` (L836–838; ruling; counted as a failure of kind `window`), and a
//!    later ancestor below it ends the answer with success before it.
//! 7. **The count**: the walk stops at `min(count, 128)` blocks whatever the store sends and
//!    drops the store's stream, which cancels the call, before its last block goes out. Blocks
//!    go out one at a time as the sink takes them, never collected: a slow reader holds the
//!    store back.
//!
//! A failed lookup ends the answer with its code before the first chunk (cl-store's
//! `UNAVAILABLE` is `3`, any other failure `2`), else cleanly at the last whole chunk, counted in
//! `rpc_block_lookup_failures_total{half="store", kind}`.

use super::answer_bucket::{AnswerBucket, AnswerPrefixes};
use super::blocks::{decode, BlockSource, Failed, Half, Out, WindowStart, BLOCK_LOOKUP_TIMEOUT};
use super::metrics::RpcMetrics;
use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::EthSpec;
use futures::StreamExt as _;
use libp2p::PeerId;
use p2p_wire::rpc::messages::BlocksByHeadV1Request;
use p2p_wire::rpc::protocols::{Request, Response, ResultCode, MAX_REQUEST_BLOCKS_DENEB};
use std::collections::hash_map::{Entry, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// `GetBlocksByHead` store streams cl-p2p's answers hold at once \[est\]: 24, below cl-store's
/// `MAX_HEAD_STREAMS` (32, `cl_store::server`; cl-p2p links no cl-store, so its tests check
/// this is below it when they compile). A stalled reader holds its stream up to cl-store's 10 s
/// walk; were cl-p2p's answers to fill cl-store's cap, every other walk would be refused there,
/// a root we hold included, and cl-store's other callers (cl-api, cl-sync) with it. Below it,
/// cl-p2p refuses first, by its own pool and per-IP cap, and those callers keep 8.
pub const MAX_BYHEAD_STORE_STREAMS: usize = 24;

/// Of those, the ones answers to the peers of one IP ([`BYHEAD_IP_PREFIXES`]) hold at once
/// \[est\]: 4. One IP may open 16 ByHead streams (8 inbound connections, `peer_caps`'
/// `max_established_incoming_per_ip`, of 2 streams each, `MAX_CONCURRENT_REQUESTS`); at 4,
/// filling the pool takes 6 IPs, and one peer still has both its streams on each of two
/// connections.
pub const MAX_BYHEAD_STORE_STREAMS_PER_IP: usize = 4;

/// What one IP is for [`MAX_BYHEAD_STORE_STREAMS_PER_IP`]: an IPv4 address or an IPv6 /58, the
/// buckets of the per-IP connection cap (`peer_caps`), with an IPv4-mapped IPv6 address counted
/// as its IPv4 address ([`AnswerPrefixes::bucket`]).
pub const BYHEAD_IP_PREFIXES: AnswerPrefixes = AnswerPrefixes { ipv4: 32, ipv6: 58 };

/// The store streams ByHead answers hold (see the module docs): at most `max`, at most
/// `max_per_ip` for the peers of one IP. Every clone is the same pool.
#[derive(Clone)]
pub(crate) struct StoreStreams(Arc<Streams>);

struct Streams {
    max: usize,
    max_per_ip: usize,
    held: Mutex<Held>,
}

/// The permits out, in all and per IP.
#[derive(Default)]
struct Held {
    total: usize,
    per_ip: HashMap<AnswerBucket, usize>,
}

impl StoreStreams {
    /// A pool of `max` permits, at most `max_per_ip` of them for the peers of one IP.
    pub(crate) fn new(max: usize, max_per_ip: usize) -> Self {
        let held = Mutex::default();
        Self(Arc::new(Streams {
            max,
            max_per_ip,
            held,
        }))
    }

    fn lock(&self) -> MutexGuard<'_, Held> {
        self.0.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The permits out now.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.lock().total
    }

    /// A permit for the store stream of an answer to a peer at `ip` (`None`: not counted per
    /// IP), at once; `3: ResourceUnavailable` if the pool or `ip`'s share of it is full.
    pub(super) fn take(&self, ip: Option<IpAddr>) -> Result<StreamPermit, Failed> {
        let bucket = ip.map(|ip| BYHEAD_IP_PREFIXES.bucket(ip));
        let mut held = self.lock();
        let of_ip = bucket.map_or(0, |b| held.per_ip.get(&b).copied().unwrap_or(0));
        let kind = if held.total >= self.0.max {
            "streams"
        } else if of_ip >= self.0.max_per_ip {
            "ip_streams"
        } else {
            held.total += 1;
            if let Some(bucket) = bucket {
                *held.per_ip.entry(bucket).or_default() += 1;
            }
            let streams = self.clone();
            return Ok(StreamPermit { streams, bucket });
        };
        Err(Failed {
            code: ResultCode::ResourceUnavailable,
            kind,
            why: format!("no store stream free ({kind})"),
        })
    }
}

/// One store stream's permit ([`StoreStreams::take`]), given back on drop.
pub(super) struct StreamPermit {
    streams: StoreStreams,
    bucket: Option<AnswerBucket>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut held = self.streams.lock();
        held.total = held.total.saturating_sub(1);
        if let Some(Entry::Occupied(mut n)) = self.bucket.map(|b| held.per_ip.entry(b)) {
            *n.get_mut() -= 1;
            if *n.get() == 0 {
                n.remove();
            }
        }
    }
}

/// Serves BeaconBlocksByHead v1 from a [`BlockSource`] (see the module docs).
#[derive(Clone)]
pub struct ByHeadResponder {
    source: Arc<dyn BlockSource>,
    lookups: Arc<Semaphore>,
    streams: StoreStreams,
    metrics: Option<RpcMetrics>,
    window: Option<WindowStart>,
    /// Whether an unknown window was logged.
    warned: Arc<AtomicBool>,
}

impl ByHeadResponder {
    /// Answers from `source`, holding one of `lookups` while it reads and one of `streams`
    /// while its store stream lives, its failures counted in `metrics`, below `window`'s start
    /// refused.
    pub(super) fn new(
        source: Arc<dyn BlockSource>,
        lookups: Arc<Semaphore>,
        streams: StoreStreams,
        metrics: Option<RpcMetrics>,
        window: Option<WindowStart>,
    ) -> Self {
        Self {
            source,
            lookups,
            streams,
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

    /// One of the shared lookup slots, waited for up to [`BLOCK_LOOKUP_TIMEOUT`].
    async fn lookup(&self) -> Result<OwnedSemaphorePermit, Failed> {
        let slot = Arc::clone(&self.lookups).acquire_owned();
        match tokio::time::timeout(BLOCK_LOOKUP_TIMEOUT, slot).await {
            Ok(Ok(slot)) => Ok(slot),
            _ => Err(Failed::server_error("busy", "no lookup slot in time")),
        }
    }

    /// The answer to `head` from a peer at `ip` into `out` (see the module docs).
    async fn answer<E: EthSpec>(
        &self,
        head: BlocksByHeadV1Request,
        ip: Option<IpAddr>,
        out: &mut Out<E>,
    ) -> Result<(), Failed> {
        let count = head.count.min(MAX_REQUEST_BLOCKS_DENEB);
        let floor = self.window_start();
        let permit = self.streams.take(ip).map_err(|f| self.failed(f))?;
        let mut slot = Some(self.lookup().await?);
        let opened = self.source.by_head(head.beacon_root.0, count).await;
        // The permit goes with the store stream: dropped with it, never before.
        let mut walk = Some((opened.map_err(|f| self.failed(f))?, permit));
        // The root the next block must have, and the slot it must be below.
        let (mut want, mut above) = (head.beacon_root.0, None);
        while (out.sent as u64) < count {
            let Some((blocks, _)) = walk.as_mut() else {
                break;
            };
            // A slot for each read, none while the sink below waits on the peer.
            let held = match slot.take() {
                Some(held) => held,
                None => self.lookup().await?,
            };
            let Some(next) = blocks.next().await else {
                break;
            };
            drop(held);
            let block = next.map_err(|f| self.failed(f))?;
            if block.root != want || above.is_some_and(|slot| block.slot >= slot) {
                let why = format!("slot {}: not the block the walk asked for", block.slot);
                return Err(self.failed(Failed::server_error("link", why)));
            }
            if floor.is_some_and(|start| block.slot < start) {
                if out.sent > 0 {
                    return Ok(());
                }
                return Err(self.failed(Failed {
                    code: ResultCode::ResourceUnavailable,
                    kind: "window",
                    why: format!("slot {} below the serve window", block.slot),
                }));
            }
            let (decoded, parent) = decode::<E>(&block).map_err(|f| self.failed(f))?;
            if out.sent as u64 + 1 == count {
                // The walk is read: its stream (and permit) go before the last block waits on
                // the sink.
                walk = None;
            }
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

/// The BeaconBlocksByHead responder of a node with no block source: every request is an empty
/// success at the peer's token, since we hold nothing we can reach.
pub(crate) struct NoBlocks;

impl<E: EthSpec> Responder<E> for NoBlocks {
    fn serve(&self, _: PeerId, _: Request, _: ChunkSink<E>) -> Serving {
        Box::pin(async {})
    }
}

impl<E: EthSpec> Responder<E> for ByHeadResponder {
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
            let Request::BlocksByHead(head) = request else {
                return;
            };
            let mut out = Out::new(sink);
            if let Err(failed) = this.answer(head, ip, &mut out).await {
                out.end(failed).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_BYHEAD_STORE_STREAMS, MAX_BYHEAD_STORE_STREAMS_PER_IP};
    use crate::rpc::blocks::testing::{self as fixture, failed, Act, Call, Fake, Step};
    use crate::rpc::blocks::{ByRangeResponder, Half, ServedBlock, BLOCK_LOOKUP_TIMEOUT};
    use crate::rpc::codec::{Answer, Deadlines, InboundCodec, ReceivedChunk, RpcCodec, RpcRequest};
    use crate::rpc::inbound::SharedStatus;
    use crate::rpc::metrics::RpcMetrics;
    use crate::rpc::responder::{testing, Queued, Responder, StreamedAnswer, STREAM_QUEUE_LEN};
    use consensus_types::caps::NetworkCaps;
    use consensus_types::{forked, ForkName, Minimal};
    use libp2p::request_response::Codec as _;
    use p2p_wire::rpc::messages::{BlocksByHeadV1Request, BlocksByRangeV2Request, StatusV2};
    use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
    use p2p_wire::testkit::{self as wire, FULU_BPO_DIGEST, FULU_DIGEST, GLOAS_DIGEST};
    use prometheus_client::registry::Registry;
    use ssz::Encode as _;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::Instant;

    type E = Minimal;
    const HEAD: Protocol = Protocol::BlocksByHeadV1;
    /// The lookup slots of every responder here.
    const LOOKUPS: usize = 16;
    /// A peer's byte budget no answer here fills: only the stream's queue holds a walk back.
    const ROOMY: usize = 1 << 20;

    fn head(root: [u8; 32], count: u64) -> Request {
        Request::BlocksByHead(BlocksByHeadV1Request {
            beacon_root: root.into(),
            count,
        })
    }

    fn by_range(start_slot: u64, count: u64) -> Request {
        Request::BlocksByRange(BlocksByRangeV2Request {
            start_slot,
            count,
            step: 1,
        })
    }

    fn metrics() -> RpcMetrics {
        RpcMetrics::register(&mut Registry::default())
    }

    /// The production range responder over `fake` (our Status's `earliest_available_slot` 0,
    /// [`LOOKUPS`] slots, failures counted in `metrics`, the serve window starting at slot
    /// `window` if given), and the ByHead responder it builds (D5: the same lookup slots,
    /// metrics and window).
    fn responders(
        fake: &Fake,
        window: Option<u64>,
        metrics: &RpcMetrics,
    ) -> (Arc<dyn Responder<E>>, ByRangeResponder) {
        let status = StatusV2 {
            earliest_available_slot: 0,
            ..wire::status()
        };
        let mut range = ByRangeResponder::new(
            Arc::new(fake.clone()),
            Arc::new(SharedStatus::new(Some(status))),
            LOOKUPS,
            Some(metrics.clone()),
        );
        if let Some(start) = window {
            range = range.with_window(Arc::new(move || Some(start)));
        }
        (Arc::new(range.head_responder()), range)
    }

    /// Writes `stream` as the stream's writer does, unpaced, to a requester that takes every
    /// write at once: the bytes it got.
    async fn write(stream: StreamedAnswer) -> Vec<u8> {
        let contexts = testing::serving_table(NetworkCaps::PRESET_BOUND);
        let mut writer = InboundCodec::new(RpcCodec::<E>::new(contexts, Deadlines::default()));
        let mut sent = futures::io::Cursor::new(Vec::new());
        let answer = Answer::streamed(stream, None, None);
        writer
            .write_response(&HEAD, &mut sent, answer)
            .await
            .unwrap();
        sent.into_inner()
    }

    /// The chunks a requester of `request` reads from `wire`, context bytes included.
    async fn received(wire: &[u8], request: &Request) -> Vec<ReceivedChunk<E>> {
        let contexts = Arc::new(wire::context_table());
        let mut codec = RpcCodec::<E>::new(contexts, Deadlines::default());
        let valid = RpcRequest::Valid(request.clone());
        let mut sent = futures::io::sink();
        codec.write_request(&HEAD, &mut sent, valid).await.unwrap();
        codec.read_response(&HEAD, &mut &wire[..]).await.unwrap()
    }

    /// `responder`'s answer to `request` from a fresh peer, as the requester reads it, and how
    /// long it took.
    async fn serve(
        responder: &Arc<dyn Responder<E>>,
        request: Request,
    ) -> (Vec<ReceivedChunk<E>>, Duration) {
        serve_from(responder, None, request).await
    }

    /// [`serve`] for a fresh peer at `ip`.
    async fn serve_from(
        responder: &Arc<dyn Responder<E>>,
        ip: Option<IpAddr>,
        request: Request,
    ) -> (Vec<ReceivedChunk<E>>, Duration) {
        let start = Instant::now();
        let (stream, _, _) = testing::start_from(responder, ip, request.clone(), ROOMY);
        let wire = write(stream).await;
        (received(&wire, &request).await, Instant::now() - start)
    }

    /// The blocks of `chunks`, which must all be blocks.
    fn blocks_of(chunks: &[ReceivedChunk<E>]) -> Vec<&forked::SignedBeaconBlock<E>> {
        chunks
            .iter()
            .map(|c| match &c.chunk {
                ResponseChunk::Success(Response::Block(b)) => &**b,
                other => panic!("not a block: {other:?}"),
            })
            .collect()
    }

    /// The (slot, root) of each block of `chunks`.
    fn walked(chunks: &[ReceivedChunk<E>]) -> Vec<(u64, [u8; 32])> {
        blocks_of(chunks)
            .iter()
            .map(|b| (b.slot(), b.message_root().0))
            .collect()
    }

    /// The (slot, root) of the canonical ancestry of the block at `from`: at most `n`, newest
    /// first.
    fn ancestry(from: u64, n: usize) -> Vec<(u64, [u8; 32])> {
        fixture::chain()
            .iter()
            .rev()
            .filter(|b| b.slot <= from)
            .take(n)
            .map(|b| (b.slot, b.root))
            .collect()
    }

    /// The code of the one error chunk `chunks` are, if they are.
    fn only_error(chunks: &[ReceivedChunk<E>]) -> Option<ResultCode> {
        match chunks {
            [ReceivedChunk {
                context: None,
                chunk: ResponseChunk::Error { code, .. },
            }] => Some(*code),
            _ => None,
        }
    }

    /// Each block is the parent of the one before it (`fulu` L819–820), at a lower slot.
    fn assert_descending(chunks: &[ReceivedChunk<E>]) {
        for pair in blocks_of(chunks).windows(2) {
            let parent = match pair[0] {
                forked::SignedBeaconBlock::Fulu(b) => b.message.parent_root,
                forked::SignedBeaconBlock::Gloas(b) => b.message.parent_root,
            };
            assert_eq!(parent, pair[1].message_root(), "slot {}", pair[0].slot());
            assert!(pair[1].slot() < pair[0].slot());
        }
    }

    /// The IPv4 address `10.0.x.y` numbered `i`.
    fn ipv4(i: usize) -> IpAddr {
        let [.., x, y] = u32::try_from(i).unwrap().to_be_bytes();
        IpAddr::V4(Ipv4Addr::new(10, 0, x, y))
    }

    /// Waits (yielding, never sleeping) until nothing of `fake` is alive: an aborted answer
    /// drops its walk when the runtime next runs its task.
    async fn closed(fake: &Fake) {
        for _ in 0..64 {
            if fake.open() == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("{} lookups or streams still open", fake.open());
    }

    /// #230 AC `byhead_ancestry` (`fulu/p2p-interface.md` L819–820): a known head returns its
    /// ancestry, the block at `beacon_root` included, in descending slot order, up to `count`
    /// blocks: exact (slot, root) pairs, skipped slots skipped. One store walk per answer
    /// (D1: no finalized-slot read, no chain half), so the walk crosses the store's finalized
    /// slot (20) with no gap and no duplicate. Across the epoch-2 BPO digest and the epoch-4
    /// Gloas switch each chunk carries its own epoch's digest, decodes in that fork and is the
    /// block as stored (Cole).
    #[tokio::test(start_paused = true)]
    async fn byhead_ancestry() {
        let fake = Fake::new();
        let (responder, _) = responders(&fake, None, &metrics());
        for (from, count, n) in [
            (40, 128, 36),
            (40, 10, 10),
            (24, 8, 8),
            (21, 2, 2),
            (20, 1, 1),
            (2, 128, 2),
        ] {
            let root = fixture::at(from).root;
            let (chunks, _) = serve(&responder, head(root, count)).await;
            assert_eq!(
                walked(&chunks),
                ancestry(from, n),
                "from {from}, count {count}"
            );
            assert_descending(&chunks);
            assert_eq!(fake.calls(), [Call::ByHead(root, count)], "one store walk");
        }
        let (chunks, _) = serve(&responder, head(fixture::at(40).root, 128)).await;
        let mut seen = HashSet::new();
        for (chunk, block) in chunks.iter().zip(blocks_of(&chunks)) {
            let slot = block.slot();
            let (digest, fork) = match slot / 8 {
                0..=1 => (FULU_DIGEST, ForkName::Fulu),
                2..=3 => (FULU_BPO_DIGEST, ForkName::Fulu),
                _ => (GLOAS_DIGEST, ForkName::Gloas),
            };
            assert_eq!(chunk.context, Some(digest), "slot {slot}");
            assert_eq!(block.fork_name(), fork, "slot {slot}");
            assert_eq!(block.as_ssz_bytes(), fixture::at(slot).ssz, "slot {slot}");
            seen.insert(digest);
        }
        assert_eq!(seen.len(), 3, "every digest of the fixture");
    }

    /// #230 AC `byhead_limits` (Ezra, 2026-11-01): a `count` over 128 (129, `u64::MAX`) is
    /// served as `min(count, MAX_REQUEST_BLOCKS_DENEB)` = 128 (`fulu` L820–821), never `1`: the
    /// store is asked for 128 and every block it holds goes out. `count` 0 is an empty success
    /// that reads nothing: the streamed answer runs no responder for it.
    #[tokio::test(start_paused = true)]
    async fn byhead_count_clamped() {
        let fake = Fake::new();
        let (responder, _) = responders(&fake, None, &metrics());
        let root = fixture::at(40).root;
        for count in [129, u64::MAX] {
            let (chunks, _) = serve(&responder, head(root, count)).await;
            assert_eq!(
                walked(&chunks),
                ancestry(40, 36),
                "{count}: served, never 1"
            );
            assert_eq!(fake.calls(), [Call::ByHead(root, 128)], "{count}: clamped");
        }
        let (chunks, _) = serve(&responder, head(root, 0)).await;
        assert!(chunks.is_empty(), "count 0: an empty success, {chunks:?}");
        assert_eq!(fake.calls(), [], "count 0: nothing read");
    }

    /// #230 AC `byhead_limits`: a root we do not hold is a success of zero chunks, no error
    /// code (L832: "zero or more"; the ≥ 1 MUST of L840–841 is for a root we hold), and its
    /// lookup slot goes back. A held root below the start of the serve window is
    /// `3: ResourceUnavailable` before any chunk (L836–838); one at the start is served.
    #[tokio::test(start_paused = true)]
    async fn byhead_unknown_root_and_window() {
        let fake = Fake::new();
        let (responder, range) = responders(&fake, None, &metrics());
        let unknown = [0xee; 32];
        let (chunks, _) = serve(&responder, head(unknown, 8)).await;
        assert!(
            chunks.is_empty(),
            "an unknown root: zero chunks, {chunks:?}"
        );
        assert_eq!(fake.calls(), [Call::ByHead(unknown, 8)]);
        closed(&fake).await;
        assert_eq!(range.free_lookups(), LOOKUPS);

        let metrics = metrics();
        let (windowed, _) = responders(&fake, Some(24), &metrics);
        let (chunks, _) = serve(&windowed, head(fixture::at(23).root, 4)).await;
        assert_eq!(only_error(&chunks), Some(ResultCode::ResourceUnavailable));
        assert_eq!(
            metrics.block_lookup_failures("store", "window"),
            1,
            "counted"
        );
        let (chunks, _) = serve(&windowed, head(fixture::at(24).root, 4)).await;
        assert_eq!(
            walked(&chunks),
            ancestry(24, 1),
            "served, and stops below the window"
        );
    }

    /// #230 (the rulings' second window case): a walk that reaches an ancestor below the start
    /// of the serve window stops before it and ends with success, never an error chunk. The
    /// window's start is read once per answer, and the store walk is dropped at the stop.
    #[tokio::test(start_paused = true)]
    async fn byhead_window_stop() {
        let fake = Fake::new();
        let reads = Arc::new(AtomicUsize::new(0));
        let window = {
            let reads = Arc::clone(&reads);
            Arc::new(move || {
                reads.fetch_add(1, Ordering::SeqCst);
                Some(18)
            })
        };
        let (_, range) = responders(&fake, None, &metrics());
        let responder: Arc<dyn Responder<E>> = Arc::new(range.with_window(window).head_responder());
        let (chunks, _) = serve(&responder, head(fixture::at(40).root, 128)).await;
        let want: Vec<(u64, [u8; 32])> = ancestry(40, 36)
            .into_iter()
            .filter(|(slot, _)| *slot >= 18)
            .collect();
        assert_eq!(walked(&chunks), want, "a clean end before slot 16");
        assert_eq!(reads.load(Ordering::SeqCst), 1, "the window read once");
        closed(&fake).await;
        assert_eq!(
            fake.walk_reads(),
            want.len() + 1,
            "the block below read, not sent"
        );
    }

    /// #230 D9: a walk ends cleanly where the store's walk ends (a parent it does not hold,
    /// after slot 0); a failed store step after `k` chunks ends the answer at those `k`,
    /// counted; one before the first chunk ends it with its code (cl-store's `UNAVAILABLE` is
    /// `3`, anything else `2`). Each gives its lookup slot back.
    #[tokio::test(start_paused = true)]
    async fn byhead_stops_cleanly() {
        let metrics = metrics();
        let fake = Fake::new();
        let orphan = fixture::block(45, [0xaa; 32], 3);
        fake.add(orphan.clone());
        let genesis = fixture::block(0, [0; 32], 0);
        let child = fixture::block(3, genesis.root, 5);
        fake.add(genesis.clone());
        fake.add(child.clone());
        let (responder, _) = responders(&fake, None, &metrics);
        let (chunks, _) = serve(&responder, head(orphan.root, 8)).await;
        assert_eq!(walked(&chunks), [(45, orphan.root)], "a parent not stored");
        let (chunks, _) = serve(&responder, head(child.root, 8)).await;
        assert_eq!(
            walked(&chunks),
            [(3, child.root), (0, genesis.root)],
            "slot 0 reached"
        );

        let root = fixture::at(40).root;
        for (step, code) in [
            (Step::Open(Half::Store), ResultCode::ResourceUnavailable),
            (Step::Open(Half::Store), ResultCode::ServerError),
            (Step::Item(Half::Store, 0), ResultCode::ServerError),
        ] {
            let fake = Fake::new();
            fake.script(step, Act::Fail(failed(code, "status")));
            let (responder, range) = responders(&fake, None, &metrics);
            let (chunks, _) = serve(&responder, head(root, 8)).await;
            assert_eq!(only_error(&chunks), Some(code), "{step:?}");
            closed(&fake).await;
            assert_eq!(range.free_lookups(), LOOKUPS);
        }
        let fake = Fake::new();
        let timeout = failed(ResultCode::ServerError, "timeout");
        fake.script(Step::Item(Half::Store, 3), Act::Fail(timeout));
        let (responder, range) = responders(&fake, None, &metrics);
        let (chunks, _) = serve(&responder, head(root, 8)).await;
        assert_eq!(walked(&chunks), ancestry(40, 3), "a clean end after 3");
        assert_eq!(metrics.block_lookup_failures("store", "status"), 3);
        assert_eq!(metrics.block_lookup_failures("store", "timeout"), 1);
        closed(&fake).await;
        assert_eq!(range.free_lookups(), LOOKUPS);
    }

    /// #230 D9: the store's blocks are held to the walk: the first is the block at
    /// `beacon_root`, each next one the parent of the block before, at a lower slot, and each
    /// decodes in the fork of its slot to a block of that slot. A break before the first chunk
    /// is `2`; after it the answer ends cleanly at its last whole chunk.
    #[tokio::test(start_paused = true)]
    async fn byhead_contract_breaks() {
        let metrics = metrics();
        let root = fixture::at(40).root;
        let garbage = ServedBlock {
            ssz: vec![0; 200],
            ..fixture::at(40)
        };
        let another_slot = ServedBlock {
            slot: 41,
            ..fixture::at(40)
        };
        for (case, first) in [
            ("a wrong first root", fixture::at(39)),
            ("a decode failure", garbage),
            ("another slot", another_slot),
        ] {
            let fake = Fake::new();
            fake.replace_in_walk(0, first);
            let (responder, _) = responders(&fake, None, &metrics);
            let (chunks, _) = serve(&responder, head(root, 8)).await;
            assert_eq!(only_error(&chunks), Some(ResultCode::ServerError), "{case}");
            closed(&fake).await;
        }
        let sibling = fixture::block(39, [0xee; 32], 7);
        let not_lower = ServedBlock {
            slot: 39,
            ..fixture::at(38)
        };
        for (case, n, block, sent) in [
            ("a broken parent link", 1, sibling, 1),
            ("a slot that does not descend", 2, fixture::at(39), 2),
            ("a block of another slot", 2, not_lower, 2),
        ] {
            let fake = Fake::new();
            fake.replace_in_walk(n, block);
            let (responder, _) = responders(&fake, None, &metrics);
            let (chunks, _) = serve(&responder, head(root, 8)).await;
            assert_eq!(walked(&chunks), ancestry(40, sent), "{case}: a clean end");
            closed(&fake).await;
        }
    }

    /// #230 (Vera): the walk stops at `min(count, 128)` blocks whatever the store sends: no
    /// block past it is read, and the store's stream is dropped.
    #[tokio::test(start_paused = true)]
    async fn byhead_hard_stop_at_count() {
        let fake = Fake::new();
        fake.overserve(10);
        let (responder, _) = responders(&fake, None, &metrics());
        let (chunks, _) = serve(&responder, head(fixture::at(40).root, 4)).await;
        assert_eq!(walked(&chunks), ancestry(40, 4));
        closed(&fake).await;
        assert_eq!(fake.walk_reads(), 4, "nothing read past the count");
    }

    /// #230 (Vera): the walk streams block by block, never collected: with nothing taken from
    /// the stream's queue the store is read no further than the queue and the block in hand,
    /// and each chunk taken lets about one more block be read.
    #[tokio::test(start_paused = true)]
    async fn byhead_bounded_memory() {
        let fake = Fake::new();
        let (responder, _) = responders(&fake, None, &metrics());
        let request = head(fixture::at(40).root, 128);
        let (mut stream, _, _) = testing::start(&responder, request, ROOMY);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let read = fake.walk_reads();
        assert!(
            (STREAM_QUEUE_LEN..=STREAM_QUEUE_LEN + 1).contains(&read),
            "{read} read, none taken"
        );
        for taken in 1..=2 {
            let chunk = stream.next().await;
            assert!(matches!(chunk, Some(Queued::Chunk { last: false, .. })));
            tokio::time::sleep(Duration::from_secs(1)).await;
            let read = fake.walk_reads();
            assert!(
                read <= taken + STREAM_QUEUE_LEN + 1,
                "{read} read, {taken} taken"
            );
        }
    }

    /// #230 AC (Vera): an answer dropped mid-walk (the requester reset the stream) frees the
    /// walk task, the stream slot, the lookup slot it held while reading and the peer's bytes,
    /// and drops the store stream, which cancels the call: no read runs after it.
    #[tokio::test(start_paused = true)]
    async fn byhead_cancel_mid_walk() {
        let fake = Fake::new();
        let (responder, range) = responders(&fake, None, &metrics());
        let request = head(fixture::at(40).root, 128);
        let (mut stream, slots, bytes) = testing::start(&responder, request, ROOMY);
        for _ in 0..3 {
            assert!(matches!(stream.next().await, Some(Queued::Chunk { .. })));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            range.free_lookups(),
            LOOKUPS,
            "none held while the sink waits (#326)"
        );
        assert_eq!(fake.open(), 1, "the store stream open");
        drop(stream);
        closed(&fake).await;
        let read = fake.walk_reads();
        assert!((3..=3 + STREAM_QUEUE_LEN + 1).contains(&read), "{read}");
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(fake.walk_reads(), read, "no read after the drop");
        assert_eq!(range.free_lookups(), LOOKUPS);
        assert_eq!(slots.available_permits(), 1, "the stream slot is back");
        assert_eq!(bytes.available(), ROOMY, "the peer's bytes are back");
    }

    /// #230 (Cole NIT 1, Vera N2 of part B1): an answer holds its lookup slot while it reads the
    /// store, never while its sink waits on the peer. More stalled ByHead requesters than there
    /// are slots (their answers read until the stream's queue is full, then wait) hold none, so
    /// a range answer gets one at once and is served whole, never `2` (busy) after a slot wait;
    /// their store streams stay open until their answers go.
    #[tokio::test(start_paused = true)]
    async fn byhead_stalled_readers_free_lookup_slots() {
        let fake = Fake::new();
        let (responder, range) = responders(&fake, None, &metrics());
        let stalled: Vec<_> = (0..LOOKUPS + 4)
            .map(|_| testing::start(&responder, head(fixture::at(40).root, 128), ROOMY))
            .collect();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let read = fake.walk_reads();
        assert!(
            read >= stalled.len() * STREAM_QUEUE_LEN,
            "each queue full: {read}"
        );
        assert_eq!(
            range.free_lookups(),
            LOOKUPS,
            "no slot held by a stalled answer"
        );
        assert_eq!(fake.open(), stalled.len(), "every store stream open");

        let ranges: Arc<dyn Responder<E>> = Arc::new(range.clone());
        let start = Instant::now();
        let (mut answer, _, _) = testing::start(&ranges, by_range(1, 4), ROOMY);
        let mut sent = 0;
        loop {
            match answer.next().await {
                Some(Queued::Chunk { last: false, .. }) => sent += 1,
                Some(Queued::Done) => break,
                other => panic!("not a block: {other:?}"),
            }
        }
        assert_eq!(sent, fixture::canonical(1, 5).len(), "served whole");
        assert!(
            Instant::now() - start < BLOCK_LOOKUP_TIMEOUT,
            "no wait for a slot"
        );
        drop(stalled);
        closed(&fake).await;
        assert_eq!(range.free_lookups(), LOOKUPS);
    }

    /// #230 D5: ByHead answers take their lookup slot from the range responder's pool: with
    /// every slot held by range answers, a ByHead answer waits one IPC step for one, then is
    /// `2: ServerError` (busy) without reaching the store; once the slots are back it is
    /// served.
    #[tokio::test(start_paused = true)]
    async fn byhead_shares_lookup_slots() {
        let fake = Fake::new();
        fake.script(Step::Head, Act::Stall);
        let (responder, range) = responders(&fake, None, &metrics());
        let ranges: Arc<dyn Responder<E>> = Arc::new(range.clone());
        let held: Vec<_> = (0..LOOKUPS)
            .map(|_| testing::start(&ranges, by_range(1, 4), ROOMY))
            .collect();
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(range.free_lookups(), 0, "every slot held by a range answer");
        let root = fixture::at(40).root;
        let (chunks, took) = serve(&responder, head(root, 4)).await;
        assert_eq!(only_error(&chunks), Some(ResultCode::ServerError));
        assert_eq!(took, BLOCK_LOOKUP_TIMEOUT, "waited one IPC step for a slot");
        assert!(
            !fake.calls().contains(&Call::ByHead(root, 4)),
            "never reached the store"
        );
        drop(held);
        closed(&fake).await;
        assert_eq!(range.free_lookups(), LOOKUPS);
        let (chunks, _) = serve(&responder, head(root, 4)).await;
        assert_eq!(walked(&chunks), ancestry(40, 4));
    }

    /// #230 B1 (Vera; Ezra's ruling): cl-p2p holds at most [`MAX_BYHEAD_STORE_STREAMS`] (24)
    /// store streams, below cl-store's `MAX_HEAD_STREAMS` (32, checked when this compiles), so
    /// stalled answers can never take the stream cl-store has for another peer's walk.
    /// Stalled answers (128 blocks, none read) from 12 IPs, two each so none is at its per-IP
    /// cap, hold all 24; one more, from an IP of its own, is `3: ResourceUnavailable` before
    /// any chunk, never reaching the store, and counted. Once a stalled answer goes, its
    /// permit is back and the next peer is served whole.
    #[tokio::test(start_paused = true)]
    async fn byhead_store_stream_pool() {
        const _: () = assert!(MAX_BYHEAD_STORE_STREAMS < cl_store::server::MAX_HEAD_STREAMS);
        const _: () = assert!(2 <= MAX_BYHEAD_STORE_STREAMS_PER_IP);
        let metrics = metrics();
        let fake = Fake::new();
        let (responder, range) = responders(&fake, None, &metrics);
        let root = fixture::at(40).root;
        let mut stalled: Vec<_> = (0..MAX_BYHEAD_STORE_STREAMS)
            .map(|i| testing::start_from(&responder, Some(ipv4(i / 2)), head(root, 128), ROOMY))
            .collect();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(fake.open(), MAX_BYHEAD_STORE_STREAMS, "a store stream each");
        assert_eq!(range.held_store_streams(), MAX_BYHEAD_STORE_STREAMS);
        assert_eq!(fake.calls().len(), MAX_BYHEAD_STORE_STREAMS);

        let late = Some(ipv4(1000));
        let (chunks, _) = serve_from(&responder, late, head(root, 4)).await;
        assert_eq!(only_error(&chunks), Some(ResultCode::ResourceUnavailable));
        assert_eq!(fake.calls(), [], "never reached the store");
        assert_eq!(
            fake.open(),
            MAX_BYHEAD_STORE_STREAMS,
            "no store stream more"
        );
        assert_eq!(metrics.block_lookup_failures("store", "streams"), 1);
        assert_eq!(range.free_lookups(), LOOKUPS);

        drop(stalled.pop());
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(range.held_store_streams(), MAX_BYHEAD_STORE_STREAMS - 1);
        let (chunks, _) = serve_from(&responder, late, head(root, 4)).await;
        assert_eq!(
            walked(&chunks),
            ancestry(40, 4),
            "served once a permit is back"
        );
        drop(stalled);
        closed(&fake).await;
        assert_eq!(range.held_store_streams(), 0);
    }

    /// #230 B1 (Ezra's ruling): an answer's store-stream permit is taken before cl-store's
    /// `GetBlocksByHead` opens and goes with the store stream. It is held while the open
    /// waits and while a stalled reader holds the walk back; it goes back with the stream once
    /// the walk has read its `count` blocks, though the last still waits on the sink; when the
    /// answer is dropped mid-walk (a reset); and when the stream fails to open.
    #[tokio::test(start_paused = true)]
    async fn byhead_permit_lives_with_the_store_stream() {
        let fake = Fake::new();
        let (responder, range) = responders(&fake, None, &metrics());
        let root = fixture::at(40).root;
        let ip = Some(ipv4(1));
        let count = STREAM_QUEUE_LEN + 2;
        let request = head(root, count as u64);
        let (mut stream, _, _) = testing::start_from(&responder, ip, request, ROOMY);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(fake.open(), 1, "the store stream open");
        assert_eq!(
            range.held_store_streams(),
            1,
            "held while the reader stalls"
        );
        // One taken: the walk reads its last block and drops its stream, then that block
        // waits on the full queue.
        assert!(matches!(stream.next().await, Some(Queued::Chunk { .. })));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(fake.walk_reads(), count, "every block read");
        assert_eq!(fake.open(), 0, "the store stream dropped");
        assert_eq!(range.held_store_streams(), 0, "the permit with it");
        let mut rest = 0;
        while let Some(Queued::Chunk { last: false, .. }) = stream.next().await {
            rest += 1;
        }
        assert_eq!(rest, count - 1, "the answer went on without it");

        let (stream, _, _) = testing::start_from(&responder, ip, head(root, 128), ROOMY);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(range.held_store_streams(), 1);
        drop(stream);
        closed(&fake).await;
        assert_eq!(
            range.held_store_streams(),
            0,
            "back when the answer is dropped"
        );

        let _ = fake.calls();
        fake.script(Step::Open(Half::Store), Act::Stall);
        let (stream, _, _) = testing::start_from(&responder, ip, head(root, 4), ROOMY);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(fake.calls(), [Call::ByHead(root, 4)], "opening");
        assert_eq!(
            range.held_store_streams(),
            1,
            "taken before the stream opens"
        );
        drop(stream);
        closed(&fake).await;
        assert_eq!(range.held_store_streams(), 0);

        let refused = failed(ResultCode::ResourceUnavailable, "status");
        fake.script(Step::Open(Half::Store), Act::Fail(refused));
        let (chunks, _) = serve_from(&responder, ip, head(root, 4)).await;
        assert_eq!(only_error(&chunks), Some(ResultCode::ResourceUnavailable));
        assert_eq!(range.held_store_streams(), 0, "back when the open fails");
    }
}
