//! Streamed answers: a [`Responder`] produces the chunks of one inbound request on its own
//! task, through a [`ChunkSink`], and the stream's writer ([`super::codec::InboundCodec`])
//! sends them as they come (see the codec's "Answers").
//!
//! # The sink
//!
//! The responder hands the sink decoded objects; the sink makes the wire chunk itself, so a
//! responder cannot get the framing, the context or the bounds wrong:
//!
//! - Context bytes (only where the protocol has them) are the digest of the epoch of the
//!   object's own slot, `compute_epoch_at_slot(slot)` (`fulu/p2p-interface.md` L700–702,
//!   L766–768, L847–848), from the serving [`ContextTable`]'s schedule
//!   ([`ContextTable::at_epoch`]), never the current epoch's. An object of another fork than
//!   its epoch's is refused.
//! - A payload is checked against its type's SSZ bound at that fork, which is capped at
//!   `MAX_PAYLOAD_SIZE` (`phase0/p2p-interface.md` L1203–1213), before it is encoded; so is
//!   whether it answers the protocol at all.
//! - An error chunk ([`ChunkSink::error`]) is code 1, 2 or 3, `3` only where the protocol
//!   specifies it (L1291), with no context bytes and its message cut at 256 bytes (L1303). It
//!   ends the answer.
//! - No more chunks than the request allows (`count`, or 1; [`Request::max_response_chunks`]),
//!   an error chunk included.
//! - A refused object ends the answer too: the writer sends `2: ServerError` if nothing went
//!   out yet, else ends at the last whole chunk. Every `send` after the end is
//!   [`SinkError::Closed`], as is every `send` once the stream is gone, so the responder stops.
//!
//! # Backpressure
//!
//! Each chunk is queued encoded on its stream's queue of [`STREAM_QUEUE_LEN`] chunks and holds
//! its bytes of the peer's budget ([`super::limits::RpcLimits::max_queued_bytes_per_peer`],
//! shared by all its streams) until the writer wrote it: [`ChunkSink::send`] waits for both, so
//! a slow reader holds back the responder, and with it the store reads behind the chunks. A
//! chunk larger than the whole budget is queued alone.

use consensus_types::EthSpec;
use libp2p::PeerId;
use p2p_wire::rpc::codec::{encode_error_chunk, encode_success_chunk, ContextTable};
use p2p_wire::rpc::messages::MAX_ERROR_MESSAGE_LEN;
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResultCode};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::AbortHandle;
use tokio::time::Instant;

/// The chunks one stream's queue holds \[est\]: a slow reader holds back its responder after
/// this many, besides the peer's byte budget.
pub const STREAM_QUEUE_LEN: usize = 4;

/// One responder's work on one request ([`Responder::serve`]).
pub type Serving = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Serves the requests of one protocol as streamed answers (see the module docs).
///
/// [`super::inbound::Control`] checks a request before it reaches the responder (a count over
/// its cap is `1: InvalidRequest`, never clamped), books [`Self::cost`] tokens of the peer's
/// quota for it, and runs [`Self::serve`]'s future on its own task until it returns or the
/// stream ends (written, reset, timed out), whichever is first.
pub trait Responder<E: EthSpec>: Send + Sync + 'static {
    /// The tokens of the peer's (peer, protocol) quota `request` is charged when it is
    /// admitted: by default the items it asks for (BlocksByRange `count`; a column range
    /// `count × len(columns)`; by root, the items it names; 1 on a single-response protocol).
    /// Its chunks go out at those tokens, and those it did not use, past one for its read, go
    /// back once it ended (not after a reset).
    fn cost(&self, request: &Request) -> u64 {
        request.max_response_chunks()
    }

    /// Answers `peer`'s `request` through `sink`. Called on the swarm's task: the work belongs
    /// in the returned future, which stops when a [`ChunkSink`] call fails or is dropped when
    /// the stream ends. Returning ends the answer; a panic ends it as a failure.
    fn serve(&self, peer: PeerId, request: Request, sink: ChunkSink<E>) -> Serving;
}

/// One peer's budget of queued response bytes
/// ([`super::limits::RpcLimits::max_queued_bytes_per_peer`]), shared by its streams.
#[derive(Debug, Clone)]
pub(crate) struct PeerBytes {
    semaphore: Arc<Semaphore>,
    len: usize,
}

impl PeerBytes {
    /// A budget of `len` bytes.
    pub(crate) fn new(len: usize) -> Self {
        let len = len.min(Semaphore::MAX_PERMITS);
        Self {
            semaphore: Arc::new(Semaphore::new(len)),
            len,
        }
    }

    /// The bytes not held by a queued chunk.
    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Holds `n` bytes (at most the whole budget) once they are free.
    async fn hold(&self, n: usize) -> Option<OwnedSemaphorePermit> {
        let n = u32::try_from(n.min(self.len)).unwrap_or(u32::MAX);
        Arc::clone(&self.semaphore).acquire_many_owned(n).await.ok()
    }
}

/// Why a [`ChunkSink`] took no chunk.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SinkError {
    /// The answer has ended (an error chunk, a refusal) or its stream is gone: stop.
    #[error("the answer has ended")]
    Closed,
    /// The object breaks the protocol (see the module docs); the answer ends with it.
    #[error("refused: {0}")]
    Refused(String),
}

/// What a stream's queue carries to its writer.
#[derive(Debug)]
pub(crate) enum Queued {
    /// One encoded chunk, holding its bytes of the peer's budget until it was written; `last`
    /// for an error chunk, which ends the answer.
    Chunk {
        bytes: Vec<u8>,
        held: OwnedSemaphorePermit,
        last: bool,
    },
    /// The responder returned: the answer is complete.
    Done,
    /// The sink refused an object: the answer ends.
    Failed,
}

/// Where a [`Responder`] puts the chunks of one answer (see the module docs).
pub struct ChunkSink<E: EthSpec> {
    protocol: Protocol,
    /// The chunks the request allows ([`Request::max_response_chunks`]) not yet queued.
    allowed: u64,
    contexts: Arc<ContextTable>,
    queue: mpsc::Sender<Queued>,
    budget: PeerBytes,
    ended: bool,
    _spec: PhantomData<fn() -> E>,
}

impl<E: EthSpec> ChunkSink<E> {
    /// A sink of at most `max_chunks` of `protocol`'s chunks, contexts from `contexts`, into
    /// `queue`, each chunk holding its bytes of `budget` while queued.
    fn new(
        protocol: Protocol,
        max_chunks: u64,
        contexts: Arc<ContextTable>,
        queue: mpsc::Sender<Queued>,
        budget: PeerBytes,
    ) -> Self {
        Self {
            protocol,
            allowed: max_chunks,
            contexts,
            queue,
            budget,
            ended: false,
            _spec: PhantomData,
        }
    }

    /// Queues `response` as the next success chunk, once the queue and the peer's byte budget
    /// have room.
    ///
    /// # Errors
    ///
    /// [`SinkError::Refused`] for an object the protocol does not allow, which ends the answer;
    /// [`SinkError::Closed`] once the answer has ended or its stream is gone.
    pub async fn send(&mut self, response: Response<E>) -> Result<(), SinkError> {
        if self.ended {
            return Err(SinkError::Closed);
        }
        match self.encode(&response) {
            Ok(bytes) => {
                drop(response);
                self.push(bytes, false).await
            }
            Err(why) => self.fail(why).await,
        }
    }

    /// Queues the error chunk of `code` with `message` (cut at 256 bytes), which ends the
    /// answer.
    ///
    /// # Errors
    ///
    /// [`SinkError::Refused`] for `0`, or `3` on a protocol that does not specify it, which
    /// ends the answer; [`SinkError::Closed`] once the answer has ended or its stream is gone.
    pub async fn error(&mut self, code: ResultCode, message: &[u8]) -> Result<(), SinkError> {
        if self.ended {
            return Err(SinkError::Closed);
        }
        if code == ResultCode::ResourceUnavailable && !self.protocol.permits_resource_unavailable()
        {
            return self
                .fail(format!("{} does not specify 3", self.protocol))
                .await;
        }
        if self.allowed == 0 {
            return self
                .fail("more chunks than the request allows".into())
                .await;
        }
        let message = &message[..message.len().min(MAX_ERROR_MESSAGE_LEN)];
        match encode_error_chunk(code, message) {
            Ok(bytes) => {
                let pushed = self.push(bytes, true).await;
                self.ended = true;
                pushed
            }
            Err(e) => self.fail(e.to_string()).await,
        }
    }

    /// The wire chunk of `response` (see the module docs), or why it is refused.
    fn encode(&self, response: &Response<E>) -> Result<Vec<u8>, String> {
        if self.allowed == 0 {
            return Err("more chunks than the request allows".into());
        }
        if !response.answers(self.protocol) {
            return Err(format!("not a response of {}", self.protocol));
        }
        let (context, fork) = if self.protocol.has_context_bytes() {
            let (slot, fork) = match response {
                Response::Block(block) => (block.slot(), block.fork_name()),
                Response::DataColumn(sidecar) => (sidecar.slot(), sidecar.fork_name()),
                _ => return Err(format!("no slot in a response of {}", self.protocol)),
            };
            let epoch = E::epoch_at_slot(slot);
            match self.contexts.at_epoch(epoch) {
                Some((digest, at)) if at == fork => (Some(digest), Some(fork)),
                Some((_, at)) => return Err(format!("a {fork:?} object at a {at:?} epoch")),
                None => return Err(format!("no fork digest for epoch {epoch}")),
            }
        } else {
            (None, None)
        };
        let len = response.ssz_bytes_len();
        let network = self.contexts.network_caps();
        match self.protocol.response_bounds_with::<E>(fork, network) {
            Some(b) if (b.min..=b.max).contains(&len) => {}
            bounds => return Err(format!("{len} SSZ bytes, outside {bounds:?}")),
        }
        encode_success_chunk(context, &response.ssz_bytes()).map_err(|e| e.to_string())
    }

    /// Queues `bytes` once the peer's budget and the queue have room.
    async fn push(&mut self, bytes: Vec<u8>, last: bool) -> Result<(), SinkError> {
        self.allowed -= 1;
        let held = self
            .budget
            .hold(bytes.len())
            .await
            .ok_or(SinkError::Closed)?;
        let chunk = Queued::Chunk { bytes, held, last };
        self.queue.send(chunk).await.map_err(|_| {
            self.ended = true;
            SinkError::Closed
        })
    }

    /// Ends the answer on a refused object.
    async fn fail(&mut self, why: String) -> Result<(), SinkError> {
        tracing::warn!(protocol = %self.protocol, %why, "a responder's chunk refused");
        self.ended = true;
        // A writer already gone ends nothing more.
        let _ = self.queue.send(Queued::Failed).await;
        Err(SinkError::Refused(why))
    }
}

/// A streamed answer (`Answer::streamed`): the queue its responder's task
/// fills, chunk by chunk, for the stream's writer. It holds one of the global inbound-stream
/// slots ([`super::limits::RpcLimits::max_inbound_streams`]); dropping it (the writer returned
/// or was dropped: written, reset, timed out) gives the slot back and aborts the task, so
/// neither depends on the responder finishing.
#[derive(Debug)]
pub struct StreamedAnswer {
    queue: mpsc::Receiver<Queued>,
    started: Instant,
    task: AbortHandle,
    _slot: OwnedSemaphorePermit,
}

impl StreamedAnswer {
    /// Runs `responder` on `peer`'s `request` on its own task, its chunks' context bytes from
    /// `contexts`, each holding its bytes of `budget` while queued, the answer holding `slot`;
    /// `None` outside a tokio runtime.
    pub(crate) fn start<E: EthSpec>(
        responder: &dyn Responder<E>,
        peer: PeerId,
        request: Request,
        contexts: Arc<ContextTable>,
        budget: PeerBytes,
        slot: OwnedSemaphorePermit,
    ) -> Option<Self> {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let (done, queue) = mpsc::channel(STREAM_QUEUE_LEN);
        let max_chunks = request.max_response_chunks();
        let sink = ChunkSink::new(
            request.protocol(),
            max_chunks,
            contexts,
            done.clone(),
            budget,
        );
        let serving = responder.serve(peer, request, sink);
        let task = runtime.spawn(async move {
            serving.await;
            // Only a responder that returned says so: one that panicked or was aborted drops
            // its sink, which ends the answer as a failure.
            let _ = done.send(Queued::Done).await;
        });
        Some(Self {
            queue,
            started: Instant::now(),
            task: task.abort_handle(),
            _slot: slot,
        })
    }

    /// When the answer started: its deadlines run from here.
    pub(crate) fn started(&self) -> Instant {
        self.started
    }

    /// The next item; `None` once the responder's task is gone without saying it was done.
    pub(crate) async fn next(&mut self) -> Option<Queued> {
        self.queue.recv().await
    }
}

impl Drop for StreamedAnswer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Fakes for the tests of streamed answers: a scripted [`Responder`] and a count of its futures
/// still alive.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use consensus_types::caps::NetworkCaps;
    use consensus_types::{forked, ForkName};
    use p2p_wire::testkit::{FULU_BPO_DIGEST, FULU_DIGEST, GLOAS_DIGEST};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A responder that runs a closure on each request.
    pub(crate) struct Script<E: EthSpec>(
        Box<dyn Fn(Request, ChunkSink<E>) -> Serving + Send + Sync>,
    );

    impl<E: EthSpec> Responder<E> for Script<E> {
        fn serve(&self, _: PeerId, request: Request, sink: ChunkSink<E>) -> Serving {
            (self.0)(request, sink)
        }
    }

    /// The responder running `f` on each request.
    pub(crate) fn script<E, F, Fut>(f: F) -> Arc<dyn Responder<E>>
    where
        E: EthSpec,
        F: Fn(Request, ChunkSink<E>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        Arc::new(Script(Box::new(move |request, sink| {
            Box::pin(f(request, sink))
        })))
    }

    /// Fulu from epoch 0, its BPO digest from epoch 2 and Gloas from epoch 4 (8 slots an
    /// epoch on the minimal preset), under `caps`.
    pub(crate) fn serving_table(caps: NetworkCaps) -> Arc<ContextTable> {
        let mut table = ContextTable::new().with_network_caps(caps);
        table.insert_from(0, FULU_DIGEST, ForkName::Fulu);
        table.insert_from(2, FULU_BPO_DIGEST, ForkName::Fulu);
        table.insert_from(4, GLOAS_DIGEST, ForkName::Gloas);
        Arc::new(table)
    }

    /// The fixture Fulu block at `slot`.
    pub(crate) fn fulu_block<E: EthSpec>(slot: u64) -> Response<E> {
        Response::Block(Box::new(forked::SignedBeaconBlock::Fulu(
            p2p_wire::testkit::fulu_block(slot),
        )))
    }

    /// The fixture block at `slot` in the fork [`serving_table`] gives its epoch: Fulu before
    /// epoch 4, Gloas from it.
    pub(crate) fn block<E: EthSpec>(slot: u64) -> Response<E> {
        if E::epoch_at_slot(slot) < 4 {
            fulu_block(slot)
        } else {
            Response::Block(Box::new(forked::SignedBeaconBlock::Gloas(
                p2p_wire::testkit::gloas_block(slot),
            )))
        }
    }

    /// The streamed answer of `responder` to `request` from a fresh peer over
    /// [`serving_table`], holding the one slot of a fresh global cap and a fresh budget of
    /// `budget` bytes: the answer, the cap and the budget.
    pub(crate) fn start<E: EthSpec>(
        responder: &dyn Responder<E>,
        request: Request,
        budget: usize,
    ) -> (StreamedAnswer, Arc<Semaphore>, PeerBytes) {
        let slots = Arc::new(Semaphore::new(1));
        let bytes = PeerBytes::new(budget);
        let slot = Arc::clone(&slots).try_acquire_owned().expect("a free slot");
        let contexts = serving_table(NetworkCaps::PRESET_BOUND);
        let peer = PeerId::random();
        let answer = StreamedAnswer::start(responder, peer, request, contexts, bytes.clone(), slot)
            .expect("a runtime");
        (answer, slots, bytes)
    }

    /// Counts the responder futures alive: each holds a [`Live`] from [`Lives::enter`].
    #[derive(Clone, Default)]
    pub(crate) struct Lives(Arc<AtomicUsize>);

    /// One responder future alive.
    pub(crate) struct Live(Arc<AtomicUsize>);

    impl Drop for Live {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Lives {
        /// A future starts.
        pub(crate) fn enter(&self) -> Live {
            self.0.fetch_add(1, Ordering::SeqCst);
            Live(Arc::clone(&self.0))
        }

        /// Futures alive.
        pub(crate) fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }

        /// Waits (yielding to the runtime, never sleeping) until every future was dropped:
        /// an aborted task drops its future when the runtime next runs it.
        pub(crate) async fn gone(&self) {
            for _ in 0..64 {
                if self.count() == 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("{} responder futures still alive", self.count());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::serving_table;
    use super::*;
    use crate::rpc::codec::read_response_chunks;
    use consensus_types::caps::{NetworkCaps, MAX_PAYLOAD_SIZE};
    use consensus_types::{forked, Minimal};
    use p2p_wire::rpc::codec::encode_chunk;
    use p2p_wire::rpc::messages::Ping;
    use p2p_wire::rpc::protocols::ResponseChunk;
    use p2p_wire::testkit::{self as wire, FULU_BPO_DIGEST, FULU_DIGEST, GLOAS_DIGEST};

    type E = Minimal;
    const BLOCKS: Protocol = Protocol::BlocksByRangeV2;
    const COLUMNS: Protocol = Protocol::DataColumnsByRangeV1;
    const ROOMY: usize = 1 << 20;

    type Parts = (ChunkSink<E>, mpsc::Receiver<Queued>, PeerBytes);

    /// A sink of `protocol` over `contexts`, the receiving end of its queue, and its peer's
    /// budget of `budget` bytes.
    fn sink_on(protocol: Protocol, budget: usize, contexts: Arc<ContextTable>) -> Parts {
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_LEN);
        let bytes = PeerBytes::new(budget);
        let sink = ChunkSink::new(protocol, u64::MAX, contexts, tx, bytes.clone());
        (sink, rx, bytes)
    }

    fn open(protocol: Protocol, budget: usize) -> Parts {
        sink_on(protocol, budget, serving_table(NetworkCaps::PRESET_BOUND))
    }

    /// A sink of `protocol` for a request allowing `max_chunks` chunks.
    fn open_for(protocol: Protocol, max_chunks: u64) -> Parts {
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_LEN);
        let bytes = PeerBytes::new(ROOMY);
        let contexts = serving_table(NetworkCaps::PRESET_BOUND);
        let sink = ChunkSink::new(protocol, max_chunks, contexts, tx, bytes.clone());
        (sink, rx, bytes)
    }

    fn fulu_block(slot: u64) -> Response<E> {
        testing::fulu_block(slot)
    }

    fn gloas_block(slot: u64) -> Response<E> {
        Response::Block(Box::new(forked::SignedBeaconBlock::Gloas(
            wire::gloas_block(slot),
        )))
    }

    /// The next queued item, which must be a chunk: its bytes and whether it ends the answer.
    fn chunk(rx: &mut mpsc::Receiver<Queued>) -> (Vec<u8>, bool) {
        match rx.try_recv() {
            Ok(Queued::Chunk { bytes, last, .. }) => (bytes, last),
            other => panic!("not a chunk: {other:?}"),
        }
    }

    fn refused(got: Result<(), SinkError>) -> bool {
        matches!(got, Err(SinkError::Refused(_)))
    }

    /// #4 (Cole): the result byte, then the context bytes where the protocol has them, then the
    /// varint SSZ length and the snappy frames (`phase0/p2p-interface.md` L1343–1370), which the
    /// requester's reader reads back.
    #[tokio::test]
    async fn sink_chunk_layout() {
        let (mut sink, mut rx, _) = open(BLOCKS, ROOMY);
        let block = fulu_block(3);
        let ssz = block.ssz_bytes();
        sink.send(block.clone()).await.unwrap();
        let (bytes, last) = chunk(&mut rx);
        assert!(!last);
        assert_eq!(bytes[0], 0, "result: success");
        assert_eq!(bytes[1..5], FULU_DIGEST, "context bytes");
        assert_eq!(
            bytes[5..],
            encode_chunk(&ssz).unwrap(),
            "varint, then frames"
        );
        let read = read_response_chunks::<E, _>(&mut &bytes[..], BLOCKS, 1, &wire::context_table())
            .await
            .unwrap();
        assert_eq!(read, [ResponseChunk::Success(block)]);
        // No context bytes on a protocol without them.
        let (mut sink, mut rx, _) = open(Protocol::PingV1, ROOMY);
        sink.send(Response::Ping(Ping(7))).await.unwrap();
        let ping = [&[0u8][..], &encode_chunk(&7u64.to_le_bytes()).unwrap()].concat();
        assert_eq!(chunk(&mut rx).0, ping);
    }

    /// #5 (Cole): each object's context bytes are the digest of the epoch of its own slot
    /// (`fulu/p2p-interface.md` L700–702, L766–768, L847–848): the last slot before a digest
    /// change and the first after it carry their own. An object of another fork than its
    /// epoch's is refused and ends the answer.
    #[tokio::test]
    async fn sink_context_at_fork_boundary() {
        let (mut sink, mut rx, _) = open(BLOCKS, ROOMY);
        for (response, digest) in [
            (fulu_block(15), FULU_DIGEST),
            (fulu_block(16), FULU_BPO_DIGEST),
            (fulu_block(31), FULU_BPO_DIGEST),
            (gloas_block(32), GLOAS_DIGEST),
        ] {
            sink.send(response).await.unwrap();
            assert_eq!(chunk(&mut rx).0[1..5], digest);
        }
        let (mut sink, mut rx, _) = open(COLUMNS, ROOMY);
        for (slot, digest) in [(15, FULU_DIGEST), (16, FULU_BPO_DIGEST)] {
            let sidecar = forked::DataColumnSidecar::Fulu(wire::fulu_sidecar(slot, 1));
            sink.send(Response::DataColumn(Box::new(sidecar)))
                .await
                .unwrap();
            assert_eq!(chunk(&mut rx).0[1..5], digest);
        }
        let (mut sink, mut rx, _) = open(BLOCKS, ROOMY);
        assert!(
            refused(sink.send(fulu_block(32)).await),
            "a Fulu block at a Gloas epoch"
        );
        assert!(matches!(rx.try_recv(), Ok(Queued::Failed)));
        assert_eq!(sink.send(gloas_block(32)).await, Err(SinkError::Closed));
    }

    /// #6 (Cole): an error chunk is code 1, 2 or 3 with no context bytes, `3` only where the
    /// protocol specifies it (`phase0/p2p-interface.md` L1291); an `ErrorMessage` over 256
    /// bytes is cut at 256 (L1303). The error chunk ends the answer.
    #[tokio::test]
    async fn sink_error_chunk_codes() {
        for code in [
            ResultCode::InvalidRequest,
            ResultCode::ServerError,
            ResultCode::ResourceUnavailable,
        ] {
            let (mut sink, mut rx, _) = open(BLOCKS, ROOMY);
            sink.error(code, b"why").await.unwrap();
            let (bytes, last) = chunk(&mut rx);
            assert!(last);
            let want = [&[code.as_byte()][..], &encode_chunk(b"why").unwrap()].concat();
            assert_eq!(bytes, want, "no context bytes");
            assert_eq!(sink.send(fulu_block(1)).await, Err(SinkError::Closed));
        }
        let (mut sink, mut rx, _) = open(Protocol::PingV1, ROOMY);
        let unspecified = sink.error(ResultCode::ResourceUnavailable, b"x").await;
        assert!(refused(unspecified), "Ping does not specify 3");
        assert!(matches!(rx.try_recv(), Ok(Queued::Failed)));
        let (mut sink, _rx, _) = open(BLOCKS, ROOMY);
        assert!(refused(sink.error(ResultCode::Success, b"x").await));
        let (mut sink, mut rx, _) = open(BLOCKS, ROOMY);
        sink.error(ResultCode::ServerError, &[b'x'; 300])
            .await
            .unwrap();
        let (bytes, _) = chunk(&mut rx);
        let read = read_response_chunks::<E, _>(&mut &bytes[..], BLOCKS, 1, &wire::context_table())
            .await
            .unwrap();
        let [ResponseChunk::Error { message, .. }] = &read[..] else {
            panic!("{read:?}")
        };
        assert_eq!(message.len(), 256);
    }

    /// #7 (Cole): a payload over `MAX_PAYLOAD_SIZE` (`phase0/p2p-interface.md` L1203–1213),
    /// over its type's bound at its fork, or not of the protocol, is refused before it is
    /// encoded and ends the answer (the writer then sends `2: ServerError` if nothing went out,
    /// else ends at the last whole chunk: `codec::tests`).
    #[tokio::test]
    async fn sink_refuses_over_max_payload_and_type_bound() {
        let mut big = wire::fulu_block::<E>(1);
        let tx = vec![0u8; MAX_PAYLOAD_SIZE].try_into().unwrap();
        big.message
            .body
            .execution_payload
            .transactions
            .push(tx)
            .unwrap();
        let big = Response::Block(Box::new(forked::SignedBeaconBlock::Fulu(big)));
        assert!(big.ssz_bytes_len() > MAX_PAYLOAD_SIZE);
        // Two cells, on a network of at most one blob per block.
        let mut wide = wire::gloas_sidecar::<E>(32, 0);
        wide.column.push(wide.column[0].clone()).unwrap();
        wide.kzg_proofs.push(wide.kzg_proofs[0]).unwrap();
        let wide = Response::DataColumn(Box::new(forked::DataColumnSidecar::Gloas(wide)));
        let preset = || serving_table(NetworkCaps::PRESET_BOUND);
        let one_blob = serving_table(NetworkCaps::from_blob_schedule(1, &[]));
        for (protocol, response, contexts) in [
            (BLOCKS, big, preset()),
            (COLUMNS, wide, one_blob),
            (BLOCKS, Response::Ping(Ping(1)), preset()),
        ] {
            let (mut sink, mut rx, _) = sink_on(protocol, ROOMY, contexts);
            assert!(refused(sink.send(response).await));
            assert!(matches!(rx.try_recv(), Ok(Queued::Failed)));
            assert_eq!(sink.send(fulu_block(1)).await, Err(SinkError::Closed));
        }
    }

    /// A response holds at most the chunks its request allows (`count`, or 1): one past them,
    /// an error chunk included, is refused, and the answer ends at the last whole chunk.
    #[tokio::test]
    async fn sink_refuses_chunks_past_the_request() {
        let (mut sink, mut rx, _) = open_for(BLOCKS, 2);
        for slot in 1..=2 {
            sink.send(fulu_block(slot)).await.unwrap();
            chunk(&mut rx);
        }
        assert!(refused(sink.send(fulu_block(3)).await));
        assert!(matches!(rx.try_recv(), Ok(Queued::Failed)));
        let (mut sink, mut rx, _) = open_for(Protocol::PingV1, 1);
        sink.send(Response::Ping(Ping(1))).await.unwrap();
        chunk(&mut rx);
        assert!(refused(sink.error(ResultCode::ServerError, b"late").await));
        assert!(matches!(rx.try_recv(), Ok(Queued::Failed)));
    }

    /// #15 (Cole, Vera): a full queue or a spent byte budget holds the producer in `send` until
    /// the writer took (and wrote) enough, so a slow reader slows the responder and its reads,
    /// and the bytes queued for a peer stay within its budget. A chunk larger than the whole
    /// budget goes alone.
    #[tokio::test(start_paused = true)]
    async fn slow_reader_backpressure() {
        let one = {
            let (mut sink, mut rx, _) = open(BLOCKS, ROOMY);
            sink.send(fulu_block(1)).await.unwrap();
            chunk(&mut rx).0.len()
        };
        let budget = 2 * one + one / 2;
        let (mut sink, mut rx, bytes) = open(BLOCKS, budget);
        sink.send(fulu_block(1)).await.unwrap();
        sink.send(fulu_block(2)).await.unwrap();
        assert_eq!(budget - bytes.available(), 2 * one);
        {
            let third = sink.send(fulu_block(3));
            tokio::pin!(third);
            assert!(
                futures::poll!(&mut third).is_pending(),
                "the queue has room"
            );
            let taken = rx.recv().await;
            assert!(
                futures::poll!(&mut third).is_pending(),
                "taken, not yet written"
            );
            drop(taken);
            third.await.unwrap();
        }
        assert!(budget - bytes.available() <= budget);
        // The queue holds STREAM_QUEUE_LEN chunks, whatever the budget.
        let (mut sink, mut rx, _) = open(BLOCKS, ROOMY);
        for slot in 0..STREAM_QUEUE_LEN as u64 {
            sink.send(fulu_block(slot)).await.unwrap();
        }
        {
            let next = sink.send(fulu_block(9));
            tokio::pin!(next);
            assert!(futures::poll!(&mut next).is_pending(), "the queue is full");
            drop(rx.recv().await);
            next.await.unwrap();
        }
        // Over the whole budget: alone.
        let (mut sink, mut rx, bytes) = open(BLOCKS, one / 2);
        sink.send(fulu_block(1)).await.unwrap();
        assert_eq!(bytes.available(), 0);
        let next = sink.send(fulu_block(2));
        tokio::pin!(next);
        assert!(futures::poll!(&mut next).is_pending());
        drop(rx.recv().await);
        next.await.unwrap();
    }
}
