//! The outbound half of the req/resp codec: `write_request` and `read_response` of
//! [`request_response::Codec`], over the `p2p-wire` framing.
//!
//! # Deadlines
//!
//! `request_response` has one deadline per exchange (`with_request_timeout`). The spec's
//! response timing needs three, all local \[est\] values because consensus-specs v1.7.0-beta.4
//! defines no `TTFB_TIMEOUT` or `RESP_TIMEOUT`; [`Deadlines`] holds them and [`read_response`]
//! runs them with `tokio::time::timeout`:
//!
//! - `ttfb` (5 s): from the start of the read to the first response byte;
//! - `per_chunk` (5 s): for each response chunk, from its first read to its last byte;
//! - `total` (10 s): for the whole response.
//!
//! [`read_response_chunks`] is the deadline-free chunk loop under them, `pub` so that it can be
//! fuzzed on its own.
//!
//! [`read_response`]: request_response::Codec::read_response
//!
//! # Reads
//!
//! Each chunk is read through one [`ResponseChunkScanner`], which parses every frame once and
//! says exactly how many more bytes the chunk needs, so no read goes past a chunk. The receive
//! buffer grows by doubling but never past the chunk's own bound (`max_len`), so a peer cannot
//! make it larger than the declared length allows. After every read the loop spends one unit of
//! the task's tokio budget, so a peer whose data is always ready cannot keep the deadlines (or
//! the other tasks of a `current_thread` runtime) from running.
//!
//! A chunk count above the request's (`count`, or 1) is an error, data after an error chunk is
//! an error, and so is an empty response on a single-response protocol. A response holds at
//! most [`MAX_RESPONSE_BYTES`] of wire bytes and estimated decoded size.
//!
//! # Context bytes
//!
//! [`RpcCodec`] returns each chunk as a [`ReceivedChunk`], with the fork digest its context
//! bytes named. The [`ContextTable`] only picks the fork to decode with, and several digests
//! name one fork (one per blob-parameter epoch), so whether the digest is the one of the
//! block's own epoch is for the caller to check
//! ([`blocks_by_range`](super::outbound::blocks_by_range)).

use consensus_types::EthSpec;
use consensus_types::{caps, forked};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use p2p_wire::rpc::codec::{
    decode_response_chunk, encode_request, CodecError, ContextTable, ResponseChunkScanner, Scan,
    CONTEXT_BYTES_LEN,
};
use p2p_wire::rpc::messages::ForkDigest;
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk};
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

/// The local \[est\] deadlines of one outbound exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadlines {
    /// From the start of the read to the first response byte.
    pub ttfb: Duration,
    /// For the whole response.
    pub total: Duration,
    /// For each response chunk.
    pub per_chunk: Duration,
}

impl Default for Deadlines {
    /// 5 s first byte, 10 s total, 5 s per chunk \[est\].
    fn default() -> Self {
        Self {
            ttfb: Duration::from_secs(5),
            total: Duration::from_secs(10),
            per_chunk: Duration::from_secs(5),
        }
    }
}

/// Which deadline passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    /// [`Deadlines::ttfb`].
    Ttfb,
    /// [`Deadlines::total`].
    Total,
    /// [`Deadlines::per_chunk`].
    PerChunk,
}

/// Why a response was refused.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// A chunk broke the wire format.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// The stream failed.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// The peer sent more chunks than the request allows.
    #[error("more than {max} response chunks")]
    TooManyChunks {
        /// The most the request allows.
        max: u64,
    },
    /// Data followed an error chunk, which must end the response.
    #[error("data after an error chunk")]
    DataAfterError,
    /// The response holds more than its byte budget ([`MAX_RESPONSE_BYTES`]).
    #[error("response exceeds its {budget}-byte budget")]
    ResponseTooLarge {
        /// The budget.
        budget: usize,
    },
    /// A single-response protocol's stream ended without a chunk.
    #[error("the stream ended without a response chunk")]
    NoResponse,
    /// A deadline passed.
    #[error("{0:?} deadline passed")]
    Deadline(Deadline),
}

impl From<ReadError> for io::Error {
    fn from(e: ReadError) -> Self {
        let kind = match &e {
            ReadError::Deadline(_) => io::ErrorKind::TimedOut,
            ReadError::Io(inner) => inner.kind(),
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, e)
    }
}

/// Runs `fut` under `limit`, if any, failing with `which` when it passes.
async fn within<F, T>(limit: Option<Duration>, which: Deadline, fut: F) -> Result<T, ReadError>
where
    F: Future<Output = Result<T, ReadError>>,
{
    match limit {
        None => fut.await,
        Some(d) => tokio::time::timeout(d, fut)
            .await
            .map_err(|_| ReadError::Deadline(which))?,
    }
}

/// The most bytes one response may hold: the wire bytes of its chunks plus their estimated
/// decoded size (the SSZ bytes, plus [`PER_TRANSACTION_HEAP`] per Fulu transaction; twice the
/// SSZ bytes for a Gloas block). 256 MiB \[est\]: 128 typical blocks fit many times over,
/// while a peer cannot make one exchange hold more. Exceeding it is
/// [`ReadError::ResponseTooLarge`].
///
/// Across streams: only `BeaconBlocksByRange` responses hold more than one small chunk, and its
/// behaviour opens at most [`MAX_CONCURRENT_REQUESTS`](super::MAX_CONCURRENT_REQUESTS) streams
/// per peer, so one peer can make the session hold at most 2 × 256 MiB of responses, plus one
/// chunk being decoded per stream (`consensus_types::caps` bounds its decode heap).
pub const MAX_RESPONSE_BYTES: usize = 256 << 20;

/// Heap one transaction of a Fulu block adds once decoded beyond its SSZ bytes: a 24-byte list
/// header, doubled for list growth, and an allocation of at least
/// [`MIN_ALLOCATION_BYTES`](caps::MIN_ALLOCATION_BYTES). An empty transaction is 4 bytes on the
/// wire and this many in memory.
pub const PER_TRANSACTION_HEAP: usize = 2 * 24 + caps::MIN_ALLOCATION_BYTES;

/// The estimated heap a kept chunk holds once decoded, from its SSZ length `ssz_len`.
///
/// - Fulu block: its SSZ bytes plus [`PER_TRANSACTION_HEAP`] per transaction, the one list
///   whose decoded size can grow far past its wire size (`consensus_types::caps`).
/// - Gloas block: [`BLOCK_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE`](caps::BLOCK_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE)
///   per SSZ byte, the budget `consensus_types::caps` derives for it.
/// - Anything else: fixed-size or at most 256 bytes, so its SSZ length.
fn decoded_size<E: EthSpec>(chunk: &ResponseChunk<E>, ssz_len: usize) -> usize {
    let held = match chunk {
        ResponseChunk::Success(Response::Block(block)) => {
            let heap = match &**block {
                forked::SignedBeaconBlock::Fulu(b) => {
                    let transactions = b.message.body.execution_payload.transactions.len();
                    ssz_len.saturating_add(transactions.saturating_mul(PER_TRANSACTION_HEAP))
                }
                forked::SignedBeaconBlock::Gloas(_) => {
                    ssz_len.saturating_mul(caps::BLOCK_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE)
                }
            };
            heap.saturating_add(size_of::<forked::SignedBeaconBlock<E>>())
        }
        _ => ssz_len,
    };
    held.saturating_add(size_of::<ResponseChunk<E>>())
}

/// One decoded response chunk and the context bytes it arrived with.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceivedChunk<E: EthSpec> {
    /// The fork digest of a success chunk on a protocol with context bytes; `None` for an
    /// error chunk or a protocol without them.
    pub context: Option<ForkDigest>,
    /// The chunk.
    pub chunk: ResponseChunk<E>,
}

/// What a response may still hold.
#[derive(Debug, Clone, Copy)]
struct Budget {
    total: usize,
    used: usize,
}

impl Budget {
    fn new(total: usize) -> Self {
        Self { total, used: 0 }
    }

    /// Fails unless `cost` more bytes fit.
    fn check(&self, cost: usize) -> Result<(), ReadError> {
        match self.used.checked_add(cost) {
            Some(used) if used <= self.total => Ok(()),
            _ => Err(ReadError::ResponseTooLarge { budget: self.total }),
        }
    }

    fn charge(&mut self, cost: usize) -> Result<(), ReadError> {
        self.check(cost)?;
        self.used += cost;
        Ok(())
    }
}

/// Reads one response chunk and charges it to `budget`; `None` if the stream ended cleanly
/// before it.
///
/// One [`ResponseChunkScanner`] lives across the reads, so each frame is parsed once. After
/// every read the task spends one unit of its tokio budget, so a peer whose data is always
/// ready still lets the executor run timers (the deadlines) and other tasks.
async fn read_chunk<E: EthSpec, T: AsyncRead + Unpin>(
    io: &mut T,
    protocol: Protocol,
    contexts: &ContextTable,
    budget: &mut Budget,
) -> Result<Option<ReceivedChunk<E>>, ReadError> {
    let mut scanner = ResponseChunkScanner::<E>::new(protocol, contexts);
    let mut buf = Vec::new();
    loop {
        let (need, max_len) = match scanner.scan(&buf)? {
            Scan::Complete { .. } => {
                let ssz_len = scanner.declared_len().unwrap_or(0);
                // The wire bytes and the SSZ length are a floor of the cost: refuse before
                // decoding if even that does not fit.
                budget.check(buf.len().saturating_add(ssz_len))?;
                let chunk = decode_response_chunk(&buf, protocol, contexts)?;
                budget.charge(buf.len().saturating_add(decoded_size(&chunk, ssz_len)))?;
                // The scanner names a fork only after reading a success chunk's context bytes,
                // which follow the result byte.
                let context = scanner.fork().and_then(|_| {
                    buf.get(1..=CONTEXT_BYTES_LEN)
                        .and_then(|raw| ForkDigest::try_from(raw).ok())
                });
                return Ok(Some(ReceivedChunk { context, chunk }));
            }
            Scan::Incomplete { need, max_len } => (need, max_len),
        };
        let start = buf.len();
        let end = start + need;
        if end > buf.capacity() {
            let target = buf
                .capacity()
                .saturating_mul(2)
                .clamp(end, max_len.max(end));
            buf.reserve_exact(target - start);
        }
        buf.resize(end, 0);
        let mut filled = start;
        while filled < end {
            match io.read(&mut buf[filled..end]).await? {
                0 if filled == 0 => return Ok(None),
                0 => return Err(CodecError::Truncated.into()),
                n => filled += n,
            }
            tokio::task::consume_budget().await;
        }
    }
}

/// Reads one byte where the stream must end: `true` if it did.
async fn at_end<T: AsyncRead + Unpin>(
    io: &mut T,
    per_chunk: Option<Duration>,
) -> Result<bool, ReadError> {
    let mut probe = [0u8; 1];
    let n = within(per_chunk, Deadline::PerChunk, async {
        Ok(io.read(&mut probe).await?)
    })
    .await?;
    Ok(n == 0)
}

/// The chunk loop, with `per_chunk` around each chunk if given and at most `budget` bytes.
async fn read_chunks<E: EthSpec, T: AsyncRead + Unpin>(
    io: &mut T,
    protocol: Protocol,
    max_chunks: u64,
    contexts: &ContextTable,
    per_chunk: Option<Duration>,
    budget: usize,
) -> Result<Vec<ReceivedChunk<E>>, ReadError> {
    let mut budget = Budget::new(budget);
    let mut chunks = Vec::new();
    loop {
        if chunks.len() as u64 == max_chunks {
            // Anything after the last allowed chunk is an extra chunk.
            if !at_end(io, per_chunk).await? {
                return Err(ReadError::TooManyChunks { max: max_chunks });
            }
            break;
        }
        let chunk = within(
            per_chunk,
            Deadline::PerChunk,
            read_chunk(io, protocol, contexts, &mut budget),
        );
        match chunk.await? {
            None => break,
            Some(
                c @ ReceivedChunk {
                    chunk: ResponseChunk::Error { .. },
                    ..
                },
            ) => {
                // An error chunk ends the response: nothing may follow it.
                if !at_end(io, per_chunk).await? {
                    return Err(ReadError::DataAfterError);
                }
                chunks.push(c);
                break;
            }
            Some(c) => chunks.push(c),
        }
    }
    if chunks.is_empty() && protocol.single_response() {
        return Err(ReadError::NoResponse);
    }
    Ok(chunks)
}

/// Reads the response of `protocol` from `io`: at most `max_chunks` chunks, the last of which
/// may be an error chunk, until the stream ends. No deadlines (see [`Deadlines`]).
pub async fn read_response_chunks<E: EthSpec, T: AsyncRead + Unpin>(
    io: &mut T,
    protocol: Protocol,
    max_chunks: u64,
    contexts: &ContextTable,
) -> Result<Vec<ResponseChunk<E>>, ReadError> {
    let chunks = read_chunks(io, protocol, max_chunks, contexts, None, MAX_RESPONSE_BYTES).await?;
    Ok(chunks.into_iter().map(|c| c.chunk).collect())
}

/// [`read_response_chunks`] under `deadlines`.
async fn read_response_within<E: EthSpec, T: AsyncRead + Unpin>(
    io: &mut T,
    protocol: Protocol,
    max_chunks: u64,
    contexts: &ContextTable,
    deadlines: Deadlines,
    budget: usize,
) -> Result<Vec<ReceivedChunk<E>>, ReadError> {
    let exchange = async {
        let mut first = [0u8; 1];
        let n = within(Some(deadlines.ttfb), Deadline::Ttfb, async {
            Ok(io.read(&mut first).await?)
        })
        .await?;
        let mut stream = (&first[..n]).chain(&mut *io);
        read_chunks(
            &mut stream,
            protocol,
            max_chunks,
            contexts,
            Some(deadlines.per_chunk),
            budget,
        )
        .await
    };
    within(Some(deadlines.total), Deadline::Total, exchange).await
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "cl-p2p serves no inbound req/resp yet",
    )
}

/// The req/resp codec of one outbound stream.
///
/// `request_response` clones the codec for every outbound stream and calls `write_request`
/// then `read_response` on that clone, so the clone carries the written request's chunk limit
/// into the read.
#[derive(Debug)]
pub struct RpcCodec<E: EthSpec> {
    contexts: Arc<ContextTable>,
    deadlines: Deadlines,
    expected_chunks: Option<u64>,
    _spec: PhantomData<fn() -> E>,
}

impl<E: EthSpec> Clone for RpcCodec<E> {
    fn clone(&self) -> Self {
        Self {
            contexts: Arc::clone(&self.contexts),
            deadlines: self.deadlines,
            expected_chunks: self.expected_chunks,
            _spec: PhantomData,
        }
    }
}

impl<E: EthSpec> RpcCodec<E> {
    /// A codec that looks context bytes up in `contexts`.
    pub fn new(contexts: Arc<ContextTable>, deadlines: Deadlines) -> Self {
        Self {
            contexts,
            deadlines,
            expected_chunks: None,
            _spec: PhantomData,
        }
    }
}

impl<E: EthSpec> request_response::Codec for RpcCodec<E> {
    type Protocol = Protocol;
    type Request = Request;
    type Response = Vec<ReceivedChunk<E>>;

    async fn read_request<T>(&mut self, _: &Protocol, _: &mut T) -> io::Result<Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(unsupported())
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let max_chunks = self
            .expected_chunks
            .take()
            .ok_or_else(|| io::Error::other("read_response before write_request"))?;
        let contexts = Arc::clone(&self.contexts);
        Ok(read_response_within(
            io,
            *protocol,
            max_chunks,
            &contexts,
            self.deadlines,
            MAX_RESPONSE_BYTES,
        )
        .await?)
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Protocol,
        io: &mut T,
        req: Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if req.protocol() != *protocol {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a {} request on {protocol}", req.protocol()),
            ));
        }
        let bytes =
            encode_request(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        io.write_all(&bytes).await?;
        io.flush().await?;
        self.expected_chunks = Some(req.max_response_chunks());
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Protocol,
        _: &mut T,
        _: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::{forked, Minimal};
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;
    use p2p_wire::rpc::codec::{encode_error_chunk, encode_success_chunk, CodecError};
    use p2p_wire::rpc::messages::{BlocksByRangeV2Request, Ping};
    use p2p_wire::rpc::protocols::{Response, ResultCode};
    use p2p_wire::testkit;
    use ssz::Encode;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::time::{Instant, Sleep};

    type E = Minimal;

    fn block_chunk(slot: u64) -> Vec<u8> {
        let ssz = testkit::fulu_block::<E>(slot).as_ssz_bytes();
        encode_success_chunk(Some(testkit::FULU_DIGEST), &ssz).unwrap()
    }

    fn ping_chunk(n: u64) -> Vec<u8> {
        encode_success_chunk(None, &Ping(n).as_ssz_bytes()).unwrap()
    }

    fn range(count: u64) -> Request {
        Request::BlocksByRange(BlocksByRangeV2Request {
            start_slot: 1,
            count,
            step: 1,
        })
    }

    fn codec() -> RpcCodec<E> {
        RpcCodec::new(Arc::new(testkit::context_table()), Deadlines::default())
    }

    /// The codec after it wrote `request`, as `request_response` drives it on one stream.
    async fn codec_after(request: Request) -> RpcCodec<E> {
        let mut codec = codec();
        let protocol = request.protocol();
        let mut sink = Cursor::new(Vec::new());
        codec
            .write_request(&protocol, &mut sink, request)
            .await
            .unwrap();
        codec
    }

    fn read_error(err: &io::Error) -> &ReadError {
        err.get_ref()
            .and_then(|e| e.downcast_ref::<ReadError>())
            .expect("a ReadError inside")
    }

    /// Delivers scripted byte runs, each after its delay, then stalls or ends.
    struct Script {
        steps: VecDeque<(Duration, Vec<u8>)>,
        sleep: Option<Pin<Box<Sleep>>>,
        ready: VecDeque<u8>,
        stall_at_end: bool,
    }

    impl Script {
        fn new(steps: Vec<(Duration, Vec<u8>)>, stall_at_end: bool) -> Self {
            Self {
                steps: steps.into(),
                sleep: None,
                ready: VecDeque::new(),
                stall_at_end,
            }
        }
    }

    impl AsyncRead for Script {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            loop {
                if !self.ready.is_empty() {
                    let n = buf.len().min(self.ready.len());
                    for (slot, byte) in buf.iter_mut().zip(self.ready.drain(..n)) {
                        *slot = byte;
                    }
                    return Poll::Ready(Ok(n));
                }
                let Some((delay, _)) = self.steps.front() else {
                    return if self.stall_at_end {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(0))
                    };
                };
                let delay = *delay;
                let sleep = self
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.sleep = None;
                let (_, bytes) = self.steps.pop_front().expect("front exists");
                self.ready.extend(bytes);
            }
        }
    }

    #[test]
    fn default_deadlines() {
        let d = Deadlines::default();
        assert_eq!(d.ttfb, Duration::from_secs(5));
        assert_eq!(d.total, Duration::from_secs(10));
        assert_eq!(d.per_chunk, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn extra_chunk_rejected() {
        // count = 2, the peer sends 3: the first two decode, the third is an error.
        let wire: Vec<u8> = [block_chunk(1), block_chunk(2), block_chunk(3)].concat();
        let contexts = testkit::context_table();
        let err = read_response_chunks::<E, _>(
            &mut Cursor::new(wire.clone()),
            Protocol::BlocksByRangeV2,
            2,
            &contexts,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ReadError::TooManyChunks { max: 2 }), "{err}");

        // Through the codec: the count comes from the request it wrote.
        let mut codec = codec_after(range(2)).await;
        let err = codec
            .read_response(&Protocol::BlocksByRangeV2, &mut Cursor::new(wire))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            read_error(&err),
            ReadError::TooManyChunks { max: 2 }
        ));
    }

    #[tokio::test]
    async fn blocks_up_to_count_are_read() {
        let bpo = testkit::fulu_block::<E>(2).as_ssz_bytes();
        let bpo = encode_success_chunk(Some(testkit::FULU_BPO_DIGEST), &bpo).unwrap();
        let wire: Vec<u8> = [block_chunk(1), bpo].concat();
        let mut codec = codec_after(range(2)).await;
        let chunks = codec
            .read_response(&Protocol::BlocksByRangeV2, &mut Cursor::new(wire))
            .await
            .unwrap();
        // Each block keeps the context bytes it arrived with.
        let want: Vec<ReceivedChunk<E>> =
            [(1, testkit::FULU_DIGEST), (2, testkit::FULU_BPO_DIGEST)]
                .map(|(s, digest)| ReceivedChunk {
                    context: Some(digest),
                    chunk: ResponseChunk::Success(Response::Block(Box::new(
                        forked::SignedBeaconBlock::Fulu(testkit::fulu_block(s)),
                    ))),
                })
                .into();
        assert_eq!(chunks, want);
        // Fewer blocks than requested, or none, end the response cleanly.
        let one = read_response_chunks::<E, _>(
            &mut Cursor::new(block_chunk(1)),
            Protocol::BlocksByRangeV2,
            2,
            &testkit::context_table(),
        )
        .await
        .unwrap();
        assert_eq!(one.len(), 1);
        let none = read_response_chunks::<E, _>(
            &mut Cursor::new(Vec::new()),
            Protocol::BlocksByRangeV2,
            2,
            &testkit::context_table(),
        )
        .await
        .unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn error_chunk_ends_the_response() {
        let wire: Vec<u8> = [
            block_chunk(1),
            encode_error_chunk(ResultCode::ResourceUnavailable, b"pruned").unwrap(),
        ]
        .concat();
        let chunks = read_response_chunks::<E, _>(
            &mut Cursor::new(wire),
            Protocol::BlocksByRangeV2,
            4,
            &testkit::context_table(),
        )
        .await
        .unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(matches!(
            &chunks[1],
            ResponseChunk::Error { code: ResultCode::ResourceUnavailable, message } if &message[..] == b"pruned"
        ));
    }

    #[tokio::test]
    async fn single_response_protocols() {
        let contexts = testkit::context_table();
        let got = read_response_chunks::<E, _>(
            &mut Cursor::new(ping_chunk(5)),
            Protocol::PingV1,
            1,
            &contexts,
        )
        .await
        .unwrap();
        assert_eq!(got, vec![ResponseChunk::Success(Response::Ping(Ping(5)))]);
        let err = read_response_chunks::<E, _>(
            &mut Cursor::new(Vec::new()),
            Protocol::PingV1,
            1,
            &contexts,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ReadError::NoResponse), "{err}");
        let two = [ping_chunk(5), ping_chunk(6)].concat();
        let err =
            read_response_chunks::<E, _>(&mut Cursor::new(two), Protocol::PingV1, 1, &contexts)
                .await
                .unwrap_err();
        assert!(matches!(err, ReadError::TooManyChunks { max: 1 }), "{err}");
    }

    #[tokio::test]
    async fn stream_ending_inside_a_chunk_is_truncated() {
        let chunk = block_chunk(1);
        let err = read_response_chunks::<E, _>(
            &mut Cursor::new(chunk[..chunk.len() - 1].to_vec()),
            Protocol::BlocksByRangeV2,
            1,
            &testkit::context_table(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ReadError::Codec(CodecError::Truncated)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn codec_errors_surface_typed() {
        let contexts = testkit::context_table();
        let err = read_response_chunks::<E, _>(
            &mut Cursor::new(vec![4, 0]),
            Protocol::PingV1,
            1,
            &contexts,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ReadError::Codec(CodecError::InvalidResultCode(4))),
            "{err}"
        );
    }

    #[tokio::test]
    async fn write_request_encodes_and_checks_the_protocol() {
        let mut codec = codec();
        let mut sink = Cursor::new(Vec::new());
        let request = Request::Ping(Ping(3));
        codec
            .write_request(&Protocol::PingV1, &mut sink, request.clone())
            .await
            .unwrap();
        let written = sink.into_inner();
        assert_eq!(
            written,
            p2p_wire::rpc::codec::encode_request(&request).unwrap()
        );

        let mut sink = Cursor::new(Vec::new());
        let err = codec
            .write_request(&Protocol::StatusV2, &mut sink, request)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            sink.into_inner().is_empty(),
            "nothing written on the wrong protocol"
        );

        // MetaData writes nothing at all.
        let mut sink = Cursor::new(Vec::new());
        codec
            .write_request(&Protocol::MetaDataV3, &mut sink, Request::MetaData)
            .await
            .unwrap();
        assert!(sink.into_inner().is_empty());
    }

    #[tokio::test]
    async fn chunks_without_context_bytes_have_none() {
        let mut codec = codec_after(Request::Ping(Ping(1))).await;
        let got = codec
            .read_response(&Protocol::PingV1, &mut Cursor::new(ping_chunk(5)))
            .await
            .unwrap();
        assert_eq!(
            got,
            vec![ReceivedChunk {
                context: None,
                chunk: ResponseChunk::Success(Response::Ping(Ping(5))),
            }]
        );
        // An error chunk of a protocol with context bytes carries none.
        let wire = [
            block_chunk(1),
            encode_error_chunk(ResultCode::ResourceUnavailable, b"pruned").unwrap(),
        ]
        .concat();
        let mut codec = codec_after(range(4)).await;
        let got = codec
            .read_response(&Protocol::BlocksByRangeV2, &mut Cursor::new(wire))
            .await
            .unwrap();
        let contexts: Vec<_> = got.iter().map(|c| c.context).collect();
        assert_eq!(contexts, [Some(testkit::FULU_DIGEST), None]);
    }

    #[tokio::test]
    async fn read_response_without_a_request_fails() {
        let err = codec()
            .read_response(&Protocol::PingV1, &mut Cursor::new(ping_chunk(1)))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn inbound_half_is_not_served() {
        let mut codec = codec();
        let err = codec
            .read_request(&Protocol::PingV1, &mut Cursor::new(Vec::new()))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let err = codec
            .write_response(&Protocol::PingV1, &mut Cursor::new(Vec::new()), Vec::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    async fn timed_read(request: Request, mut io: Script) -> (io::Error, Duration) {
        let protocol = request.protocol();
        let mut codec = codec_after(request).await;
        let start = Instant::now();
        let err = codec.read_response(&protocol, &mut io).await.unwrap_err();
        (err, start.elapsed())
    }

    #[tokio::test(start_paused = true)]
    async fn ttfb_deadline_fires() {
        let (err, elapsed) = timed_read(Request::Ping(Ping(1)), Script::new(vec![], true)).await;
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(matches!(
            read_error(&err),
            ReadError::Deadline(Deadline::Ttfb)
        ));
        assert_eq!(elapsed, Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn total_deadline_fires() {
        // Every chunk comes 4 s after the one before: inside the 5 s first-byte and per-chunk
        // deadlines, but the third lands at 12 s, past the 10 s total.
        let steps = (1..=4)
            .map(|s| {
                (
                    Duration::from_secs(if s == 1 { 0 } else { 4 }),
                    block_chunk(s),
                )
            })
            .collect();
        let (err, elapsed) = timed_read(range(4), Script::new(steps, true)).await;
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(matches!(
            read_error(&err),
            ReadError::Deadline(Deadline::Total)
        ));
        assert_eq!(elapsed, Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn per_chunk_deadline_fires() {
        // The first chunk arrives at once; the second sends half its bytes and stalls.
        let second = block_chunk(2);
        let steps = vec![
            (Duration::ZERO, block_chunk(1)),
            (Duration::from_secs(1), second[..second.len() / 2].to_vec()),
        ];
        let (err, elapsed) = timed_read(range(2), Script::new(steps, true)).await;
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(matches!(
            read_error(&err),
            ReadError::Deadline(Deadline::PerChunk)
        ));
        assert_eq!(elapsed, Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_but_timely_response_passes() {
        let steps = vec![(Duration::from_secs(4), ping_chunk(2))];
        let mut codec = codec_after(Request::Ping(Ping(1))).await;
        let got = codec
            .read_response(&Protocol::PingV1, &mut Script::new(steps, false))
            .await
            .unwrap();
        let chunks: Vec<_> = got.into_iter().map(|c| c.chunk).collect();
        assert_eq!(
            chunks,
            vec![ResponseChunk::Success(Response::Ping(Ping(2)))]
        );
    }

    /// Always ready: `head` once, then `unit` repeated forever.
    struct Endless {
        head: VecDeque<u8>,
        unit: Vec<u8>,
        at: usize,
    }

    impl Endless {
        fn new(head: Vec<u8>, unit: Vec<u8>) -> Self {
            Self {
                head: head.into(),
                unit,
                at: 0,
            }
        }
    }

    impl AsyncRead for Endless {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let this = &mut *self;
            if !this.head.is_empty() {
                let n = buf.len().min(this.head.len());
                for (slot, byte) in buf.iter_mut().zip(this.head.drain(..n)) {
                    *slot = byte;
                }
                return Poll::Ready(Ok(n));
            }
            for slot in buf.iter_mut() {
                *slot = this.unit[this.at];
                this.at = (this.at + 1) % this.unit.len();
            }
            Poll::Ready(Ok(buf.len()))
        }
    }

    /// A BlocksByRange success head with a known digest and a 10 MiB prefix, then the snappy
    /// stream identifier.
    fn ten_mib_block_head() -> Vec<u8> {
        let mut head = vec![0];
        head.extend_from_slice(&testkit::FULU_DIGEST);
        p2p_wire::rpc::codec::encode_varint(10 * (1 << 20), &mut head);
        head.extend_from_slice(b"\xff\x06\x00\x00sNaPpY");
        head
    }

    #[tokio::test]
    async fn endless_padding_is_refused_quickly() {
        let mut io = Endless::new(ten_mib_block_head(), vec![0xfe, 0, 0, 0]);
        let start = std::time::Instant::now();
        let err = read_response_chunks::<E, _>(
            &mut io,
            Protocol::BlocksByRangeV2,
            1,
            &testkit::context_table(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ReadError::Codec(CodecError::TooManyEmptyFrames { .. })),
            "{err}"
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn always_ready_stream_hits_the_total_deadline() {
        // Valid 64-byte data frames forever: never an error before the 10 MiB is reached, and
        // never Pending. The chunk loop yields to the executor, so the total deadline fires in
        // real time.
        let unit = {
            let chunk = p2p_wire::rpc::codec::encode_chunk(&[7u8; 64]).unwrap();
            chunk[1 + 10..].to_vec() // drop the prefix and the stream identifier
        };
        let mut io = Endless::new(ten_mib_block_head(), unit);
        let deadlines = Deadlines {
            ttfb: Duration::from_secs(5),
            total: Duration::from_millis(50),
            per_chunk: Duration::from_secs(5),
        };
        let start = std::time::Instant::now();
        let err = read_response_within::<E, _>(
            &mut io,
            Protocol::BlocksByRangeV2,
            1,
            &testkit::context_table(),
            deadlines,
            MAX_RESPONSE_BYTES,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ReadError::Deadline(Deadline::Total)), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn data_after_an_error_chunk_rejected() {
        let contexts = testkit::context_table();
        let error = encode_error_chunk(ResultCode::ServerError, b"busy").unwrap();
        // Single-response protocol: an error chunk, then another chunk.
        let wire = [error.clone(), ping_chunk(1)].concat();
        let err =
            read_response_chunks::<E, _>(&mut Cursor::new(wire), Protocol::PingV1, 1, &contexts)
                .await
                .unwrap_err();
        assert!(matches!(err, ReadError::DataAfterError), "{err}");
        // Multi-chunk protocol, below its count: still an error.
        let wire = [block_chunk(1), error.clone(), block_chunk(2)].concat();
        let err = read_response_chunks::<E, _>(
            &mut Cursor::new(wire),
            Protocol::BlocksByRangeV2,
            4,
            &contexts,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ReadError::DataAfterError), "{err}");
        // An error chunk that ends the stream is the response.
        let got =
            read_response_chunks::<E, _>(&mut Cursor::new(error), Protocol::PingV1, 1, &contexts)
                .await
                .unwrap();
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn response_over_its_byte_budget_rejected() {
        let contexts = testkit::context_table();
        let one = block_chunk(1);
        let cost = one.len() + chunk_cost_estimate(&testkit::fulu_block::<E>(1));
        let wire = [block_chunk(1), block_chunk(2), block_chunk(3)].concat();
        // Room for exactly two blocks: the third is refused.
        let budget = 2 * cost + cost / 2;
        let err = read_chunks::<E, _>(
            &mut Cursor::new(wire.clone()),
            Protocol::BlocksByRangeV2,
            3,
            &contexts,
            None,
            budget,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ReadError::ResponseTooLarge { budget: b } if b == budget),
            "{err}"
        );
        // Room for three: all pass.
        let got = read_chunks::<E, _>(
            &mut Cursor::new(wire),
            Protocol::BlocksByRangeV2,
            3,
            &contexts,
            None,
            3 * cost,
        )
        .await
        .unwrap();
        assert_eq!(got.len(), 3);
        // A chunk whose wire bytes and SSZ length alone are over budget is refused before decode.
        let err = read_chunks::<E, _>(
            &mut Cursor::new(one.clone()),
            Protocol::BlocksByRangeV2,
            1,
            &contexts,
            None,
            one.len(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ReadError::ResponseTooLarge { .. }), "{err}");
        assert_eq!(MAX_RESPONSE_BYTES, 256 << 20);
    }

    /// The decoded estimate of a block chunk, for the budget tests.
    fn chunk_cost_estimate(block: &consensus_types::fulu::SignedBeaconBlock<E>) -> usize {
        let ssz = block.as_ssz_bytes();
        let chunk: ResponseChunk<E> = ResponseChunk::Success(Response::Block(Box::new(
            forked::SignedBeaconBlock::Fulu(block.clone()),
        )));
        decoded_size(&chunk, ssz.len())
    }

    #[test]
    fn decoded_size_counts_transactions() {
        // 4 bytes on the wire per empty transaction, but a list header and an allocation each
        // once decoded.
        let plain = testkit::fulu_block::<E>(1);
        let mut many = plain.clone();
        many.message.body.execution_payload.transactions =
            vec![Default::default(); 1000].try_into().unwrap();
        let wire_growth = many.as_ssz_bytes().len() - plain.as_ssz_bytes().len();
        assert_eq!(wire_growth, 4000);
        let growth = chunk_cost_estimate(&many) - chunk_cost_estimate(&plain);
        assert!(growth >= 1000 * PER_TRANSACTION_HEAP, "{growth}");
        // A Gloas block is charged twice its SSZ length.
        let gloas = testkit::gloas_block::<E>(2);
        let len = gloas.as_ssz_bytes().len();
        let chunk: ResponseChunk<E> = ResponseChunk::Success(Response::Block(Box::new(
            forked::SignedBeaconBlock::Gloas(gloas),
        )));
        assert!(decoded_size(&chunk, len) >= 2 * len);
        let ping: ResponseChunk<E> = ResponseChunk::Success(Response::Ping(Ping(1)));
        assert!(decoded_size(&ping, 8) >= 8);
    }
}
