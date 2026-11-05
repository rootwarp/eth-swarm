//! `BeaconBlocksByHead` v1 answers (#230; `fulu/p2p-interface.md` L796–863). Not served yet.

use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::EthSpec;
use libp2p::PeerId;
use p2p_wire::rpc::protocols::Request;

/// Serves BeaconBlocksByHead v1 (not yet).
#[derive(Clone)]
pub struct ByHeadResponder;

impl<E: EthSpec> Responder<E> for ByHeadResponder {
    fn serve(&self, _: PeerId, _: Request, _: ChunkSink<E>) -> Serving {
        todo!("#230")
    }
}

#[cfg(test)]
mod tests {
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
        let start = Instant::now();
        let (stream, _, _) = testing::start(responder, request.clone(), ROOMY);
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

        let (windowed, _) = responders(&fake, Some(24), &metrics());
        let (chunks, _) = serve(&windowed, head(fixture::at(23).root, 4)).await;
        assert_eq!(only_error(&chunks), Some(ResultCode::ResourceUnavailable));
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
        assert_eq!(range.free_lookups(), LOOKUPS - 1, "a lookup slot held");
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
}
