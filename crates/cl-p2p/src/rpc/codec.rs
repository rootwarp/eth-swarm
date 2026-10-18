//! The req/resp codec: [`request_response::Codec`] over the `p2p-wire` framing, both halves.
//!
//! - Outbound: `write_request` writes one [`Request`], `read_response` reads its chunks.
//! - Inbound: `read_request` reads one request and `write_response` writes our chunks. A
//!   request that breaks the wire format (a wrong length, bad snappy, an early end, bytes after
//!   it) is not an I/O error: it is returned as [`RpcRequest::Malformed`], so the responder can
//!   answer `1: InvalidRequest` (`phase0/p2p-interface.md` L1383–1386) instead of dropping the
//!   stream. `write_response` refuses `3: ResourceUnavailable` on a protocol that does not
//!   specify it ([`Protocol::permits_resource_unavailable`]), and an error chunk carries no
//!   context bytes (`altair/p2p-interface.md` L463–465).
//!
//! # Deadlines
//!
//! `request_response` has one deadline per exchange (`with_request_timeout`). The spec's
//! response timing needs three, all local \[est\] values because consensus-specs v1.7.0-beta.4
//! defines no `TTFB_TIMEOUT` or `RESP_TIMEOUT`; [`Deadlines`] holds them and [`read_response`]
//! and [`read_request`] run them with `tokio::time::timeout`:
//!
//! - `ttfb` (5 s): from the start of the read to the first byte (for an empty MetaData
//!   request, to the end of the stream);
//! - `per_chunk` (5 s): for each chunk, from its first read to its last byte, and for the end
//!   of the stream after the last chunk;
//! - `total` (10 s): for the whole response or request.
//!
//! An inbound stream that stays silent therefore fails at 5 s and is dropped; until then it
//! holds one of the behaviour's `max_concurrent_streams` slots.
//!
//! [`read_response_chunks`] is the deadline-free chunk loop under them, `pub` so that it can be
//! fuzzed on its own.
//!
//! [`read_response`]: request_response::Codec::read_response
//! [`read_request`]: request_response::Codec::read_request
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
//!
//! # Answers
//!
//! The probe's inbound streams run [`InboundCodec`]: [`RpcCodec`]'s request reader, and a
//! writer of [`Answer`]s that sends one chunk at a time, each whole and flushed, once the
//! peer's [`ChunkPacer`] has a token for it (`phase0/p2p-interface.md` L1269–1274). A stream
//! that goes away before a chunk was written whole refunds what is still ahead of that chunk's
//! token.

use super::limits::ChunkPacer;
use super::metrics::RpcMetrics;
use consensus_types::EthSpec;
use consensus_types::{caps, forked};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use p2p_wire::rpc::codec::{
    decode_request, decode_response_chunk, encode_error_chunk, encode_request,
    encode_success_chunk, ChunkScanner, CodecError, ContextTable, ResponseChunkScanner, Scan,
    CONTEXT_BYTES_LEN,
};
use p2p_wire::rpc::messages::ForkDigest;
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// One request as the codec carries it: what we send, or what a peer sent.
#[derive(Debug, Clone, PartialEq)]
pub enum RpcRequest {
    /// A request that decoded.
    Valid(Request),
    /// A peer's request that broke the wire format; the responder answers `1: InvalidRequest`.
    /// Never written.
    Malformed(CodecError),
}

impl From<Request> for RpcRequest {
    fn from(request: Request) -> Self {
        Self::Valid(request)
    }
}

/// Appends exactly `len` more bytes to `buf`; a stream that ends before them is truncated.
async fn read_exact_more<T: AsyncRead + Unpin>(
    io: &mut T,
    buf: &mut Vec<u8>,
    len: usize,
) -> Result<(), ReadError> {
    let start = buf.len();
    buf.resize(start + len, 0);
    let mut filled = start;
    while filled < buf.len() {
        match io.read(&mut buf[filled..]).await? {
            0 => return Err(CodecError::Truncated.into()),
            n => filled += n,
        }
        tokio::task::consume_budget().await;
    }
    Ok(())
}

/// Reads the one request of `protocol` and the end of the stream after it, with `per_chunk`
/// around each if given. The request's payload is read through one [`ChunkScanner`], so no
/// read goes past it and the buffer never holds more than its bound allows.
async fn read_request_bytes<T: AsyncRead + Unpin>(
    io: &mut T,
    protocol: Protocol,
    per_chunk: Option<Duration>,
) -> Result<Request, ReadError> {
    let mut buf = Vec::new();
    if let Some(bounds) = protocol.request_bounds() {
        within(per_chunk, Deadline::PerChunk, async {
            let mut scanner = ChunkScanner::with_bounds(bounds);
            while let Scan::Incomplete { need, .. } = scanner.scan(&buf)? {
                read_exact_more(io, &mut buf, need).await?;
            }
            Ok(())
        })
        .await?;
    }
    // The request ends the stream: whatever follows is a malformed request.
    let mut rest = [0u8; 1];
    let n = within(per_chunk, Deadline::PerChunk, async {
        Ok(io.read(&mut rest).await?)
    })
    .await?;
    if n > 0 {
        return Err(CodecError::TrailingBytes(n).into());
    }
    Ok(decode_request(protocol, &buf)?)
}

/// [`read_request_bytes`] under `deadlines`: the first byte (or the end of an empty request)
/// within `ttfb`, the rest within `per_chunk`, all of it within `total`.
async fn read_request_within<T: AsyncRead + Unpin>(
    io: &mut T,
    protocol: Protocol,
    deadlines: Deadlines,
) -> Result<Request, ReadError> {
    let exchange = async {
        let mut first = [0u8; 1];
        let n = within(Some(deadlines.ttfb), Deadline::Ttfb, async {
            Ok(io.read(&mut first).await?)
        })
        .await?;
        let mut stream = (&first[..n]).chain(&mut *io);
        read_request_bytes(&mut stream, protocol, Some(deadlines.per_chunk)).await
    };
    within(Some(deadlines.total), Deadline::Total, exchange).await
}

/// Why a response cannot be written: our own mistake, never the peer's.
fn invalid_response(why: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

/// The wire bytes of `chunks` as the response on `protocol`: each a success chunk of the
/// protocol's type (with context bytes exactly where the protocol has them) or an error chunk
/// with a code the protocol allows, and only the last an error.
///
/// # Errors
///
/// `InvalidInput` for anything the protocol does not allow; nothing is written then.
pub fn encode_response<E: EthSpec>(
    protocol: Protocol,
    chunks: &[ReceivedChunk<E>],
) -> io::Result<Vec<u8>> {
    Ok(encode_response_chunks(protocol, chunks)?.concat())
}

/// [`encode_response`], one buffer per chunk, so a writer can send each chunk on its own.
///
/// # Errors
///
/// `InvalidInput` for anything the protocol does not allow; nothing is encoded then.
pub fn encode_response_chunks<E: EthSpec>(
    protocol: Protocol,
    chunks: &[ReceivedChunk<E>],
) -> io::Result<Vec<Vec<u8>>> {
    let max = match protocol {
        Protocol::BlocksByRangeV2 => usize::MAX,
        // Goodbye too: its response is one chunk (`phase0/p2p-interface.md` L1483).
        _ => 1,
    };
    if chunks.len() > max {
        return Err(invalid_response(format!(
            "{} chunks on {protocol}, at most {max}",
            chunks.len()
        )));
    }
    let mut out = Vec::new();
    for (i, ReceivedChunk { context, chunk }) in chunks.iter().enumerate() {
        let bytes = match chunk {
            ResponseChunk::Success(response) => {
                if response.protocol() != protocol {
                    return Err(invalid_response(format!("{response:?} on {protocol}")));
                }
                if context.is_some() != protocol.has_context_bytes() {
                    return Err(invalid_response(format!(
                        "context bytes {context:?} on {protocol}"
                    )));
                }
                encode_success_chunk(*context, &response.ssz_bytes())
            }
            ResponseChunk::Error { code, message } => {
                if i + 1 != chunks.len() {
                    return Err(invalid_response("an error chunk before the last".into()));
                }
                if context.is_some() {
                    return Err(invalid_response("an error chunk with context bytes".into()));
                }
                if *code == ResultCode::ResourceUnavailable
                    && !protocol.permits_resource_unavailable()
                {
                    return Err(invalid_response(format!(
                        "{protocol} does not specify 3: ResourceUnavailable"
                    )));
                }
                encode_error_chunk(*code, message)
            }
        };
        out.push(bytes.map_err(|e| invalid_response(e.to_string()))?);
    }
    Ok(out)
}

/// The req/resp codec of one stream.
///
/// `request_response` clones the codec for every stream. On an outbound stream it calls
/// `write_request` then `read_response` on that clone, so the clone carries the written
/// request's chunk limit into the read; on an inbound stream `read_request`, then
/// `write_response` once the behaviour answered.
#[derive(Debug)]
pub struct RpcCodec<E: EthSpec> {
    contexts: Arc<ContextTable>,
    deadlines: Deadlines,
    expected_chunks: Option<u64>,
    metrics: Option<RpcMetrics>,
    _spec: PhantomData<fn() -> E>,
}

impl<E: EthSpec> Clone for RpcCodec<E> {
    fn clone(&self) -> Self {
        Self {
            contexts: Arc::clone(&self.contexts),
            deadlines: self.deadlines,
            expected_chunks: self.expected_chunks,
            metrics: self.metrics.clone(),
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
            metrics: None,
            _spec: PhantomData,
        }
    }

    /// The codec, counting every deadline that passes in `rpc_timeouts_total{kind}`.
    ///
    /// The count is taken here because `request_response` reports nothing for an inbound
    /// stream whose `read_request` failed: a silent inbound stream would go uncounted.
    #[must_use]
    pub fn with_metrics(mut self, metrics: RpcMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Counts `result`'s deadline, if one passed.
    fn count<T>(&self, result: &Result<T, ReadError>) {
        if let (Err(ReadError::Deadline(kind)), Some(metrics)) = (result, &self.metrics) {
            metrics.timed_out(*kind);
        }
    }
}

/// Our answer to one inbound request: its chunks and, if they are rate limited, the pacer of
/// the requester's bucket.
#[derive(Debug, Clone)]
pub struct Answer<E: EthSpec> {
    /// The chunks, in order.
    pub chunks: Vec<ReceivedChunk<E>>,
    /// Paces the chunks; `None` sends them at once.
    pub pacer: Option<ChunkPacer>,
}

impl<E: EthSpec> From<Vec<ReceivedChunk<E>>> for Answer<E> {
    /// `chunks`, unpaced.
    fn from(chunks: Vec<ReceivedChunk<E>>) -> Self {
        Self {
            chunks,
            pacer: None,
        }
    }
}

/// The codec of an inbound-only behaviour: reads requests as [`RpcCodec`] does and writes
/// [`Answer`]s chunk by chunk (see the module docs). It never sends a request.
#[derive(Debug)]
pub struct InboundCodec<E: EthSpec> {
    inner: RpcCodec<E>,
}

impl<E: EthSpec> Clone for InboundCodec<E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<E: EthSpec> InboundCodec<E> {
    /// Requests read by `inner`.
    pub fn new(inner: RpcCodec<E>) -> Self {
        Self { inner }
    }
}

fn inbound_only() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "an inbound-only codec sends no request",
    )
}

impl<E: EthSpec> request_response::Codec for InboundCodec<E> {
    type Protocol = Protocol;
    type Request = RpcRequest;
    type Response = Answer<E>;

    async fn read_request<T>(&mut self, protocol: &Protocol, io: &mut T) -> io::Result<RpcRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.inner.read_request(protocol, io).await
    }

    async fn read_response<T>(&mut self, _: &Protocol, _: &mut T) -> io::Result<Answer<E>>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(inbound_only())
    }

    async fn write_request<T>(&mut self, _: &Protocol, _: &mut T, _: RpcRequest) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(inbound_only())
    }

    /// Checks the whole answer ([`encode_response`]), then writes each chunk whole once its
    /// token is due. A chunk whose write never completed (the future was dropped, or the write
    /// failed) gets back the part of its token still ahead; one written whole stays charged
    /// even if the flush after it fails, since the peer may have it all.
    async fn write_response<T>(
        &mut self,
        protocol: &Protocol,
        io: &mut T,
        answer: Answer<E>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        for bytes in encode_response_chunks(*protocol, &answer.chunks)? {
            let reservation = answer.pacer.as_ref().map(ChunkPacer::reserve);
            if let Some(due) = reservation.as_ref().map(|r| r.due()) {
                if due > tokio::time::Instant::now() {
                    tokio::time::sleep_until(due).await;
                }
            }
            io.write_all(&bytes).await?;
            if let Some(reservation) = reservation {
                reservation.sent();
            }
            io.flush().await?;
        }
        Ok(())
    }
}

impl<E: EthSpec> request_response::Codec for RpcCodec<E> {
    type Protocol = Protocol;
    type Request = RpcRequest;
    type Response = Vec<ReceivedChunk<E>>;

    /// One request, under [`Deadlines`]. A passed deadline or a failed stream is an error (the
    /// stream is dropped unanswered); a request that broke the wire format is
    /// [`RpcRequest::Malformed`].
    async fn read_request<T>(&mut self, protocol: &Protocol, io: &mut T) -> io::Result<RpcRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let read = read_request_within(io, *protocol, self.deadlines).await;
        self.count(&read);
        // `decode_request` decodes the request type of `protocol` only.
        match read {
            Ok(request) => Ok(RpcRequest::Valid(request)),
            Err(ReadError::Codec(e)) => Ok(RpcRequest::Malformed(e)),
            Err(e) => Err(e.into()),
        }
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
        let read = read_response_within(
            io,
            *protocol,
            max_chunks,
            &contexts,
            self.deadlines,
            MAX_RESPONSE_BYTES,
        )
        .await;
        self.count(&read);
        Ok(read?)
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Protocol,
        io: &mut T,
        req: RpcRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let RpcRequest::Valid(req) = req else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a malformed request is never sent",
            ));
        };
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
        protocol: &Protocol,
        io: &mut T,
        chunks: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_response(*protocol, &chunks)?;
        io.write_all(&bytes).await?;
        io.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::limits::{shared_limiter, ChunkPacer, Quota, RateLimits};
    use consensus_types::{forked, Minimal};
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;
    use p2p_wire::rpc::codec::{encode_error_chunk, encode_success_chunk, CodecError};
    use p2p_wire::rpc::messages::{BlocksByRangeV2Request, Goodbye, Ping};
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
            .write_request(&protocol, &mut sink, request.into())
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
            .write_request(&Protocol::PingV1, &mut sink, request.clone().into())
            .await
            .unwrap();
        let written = sink.into_inner();
        assert_eq!(
            written,
            p2p_wire::rpc::codec::encode_request(&request).unwrap()
        );

        let mut sink = Cursor::new(Vec::new());
        let err = codec
            .write_request(&Protocol::StatusV2, &mut sink, request.into())
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
            .write_request(&Protocol::MetaDataV3, &mut sink, Request::MetaData.into())
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

    // --- the inbound half: read_request and write_response ---

    /// `read_request` of `wire` on `protocol`, the stream ending after it.
    async fn read_req(protocol: Protocol, wire: Vec<u8>) -> io::Result<RpcRequest> {
        codec()
            .read_request(&protocol, &mut Cursor::new(wire))
            .await
    }

    fn malformed(got: io::Result<RpcRequest>) -> CodecError {
        match got {
            Ok(RpcRequest::Malformed(e)) => e,
            other => panic!("not refused as malformed: {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_request_decodes_every_request() {
        let requests = [
            Request::Status(testkit::status()),
            Request::Ping(Ping(7)),
            Request::Goodbye(Goodbye(2)),
            Request::MetaData,
            range(4),
        ];
        for request in requests {
            let wire = p2p_wire::rpc::codec::encode_request(&request).unwrap();
            let got = read_req(request.protocol(), wire).await.unwrap();
            assert_eq!(got, RpcRequest::Valid(request));
        }
    }

    #[tokio::test]
    async fn malformed_requests_are_answered_not_dropped() {
        // A declared length over the type's: refused from the prefix.
        let long = p2p_wire::rpc::codec::encode_chunk(&[0u8; 16]).unwrap();
        assert!(matches!(
            malformed(read_req(Protocol::PingV1, long).await),
            CodecError::PayloadTooLarge { len: 16, max: 8 }
        ));
        // Bytes after the request.
        let mut extra = p2p_wire::rpc::codec::encode_request(&Request::Ping(Ping(1))).unwrap();
        extra.push(0);
        assert_eq!(
            malformed(read_req(Protocol::PingV1, extra).await),
            CodecError::TrailingBytes(1)
        );
        // The stream ends inside the request, or before it.
        let ping = p2p_wire::rpc::codec::encode_request(&Request::Ping(Ping(1))).unwrap();
        let cut = ping[..ping.len() - 1].to_vec();
        assert_eq!(
            malformed(read_req(Protocol::PingV1, cut).await),
            CodecError::Truncated
        );
        assert_eq!(
            malformed(read_req(Protocol::StatusV2, Vec::new()).await),
            CodecError::Truncated
        );
        // A MetaData request is empty.
        assert_eq!(
            malformed(read_req(Protocol::MetaDataV3, vec![0]).await),
            CodecError::TrailingBytes(1)
        );
        // A 7-byte Ping: below the type's one length, refused at the prefix before any SSZ.
        let short = p2p_wire::rpc::codec::encode_chunk(&[0u8; 7]).unwrap();
        assert_eq!(
            malformed(read_req(Protocol::PingV1, short).await),
            CodecError::PayloadTooSmall { len: 7, min: 8 }
        );
    }

    #[tokio::test]
    async fn write_request_refuses_a_malformed_request() {
        let mut sink = Cursor::new(Vec::new());
        let err = codec()
            .write_request(
                &Protocol::PingV1,
                &mut sink,
                RpcRequest::Malformed(CodecError::Truncated),
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(sink.into_inner().is_empty());
    }

    /// `read_request` of `request` on `io`, timed.
    async fn timed_request(protocol: Protocol, mut io: Script) -> (io::Error, Duration) {
        let start = Instant::now();
        let err = codec().read_request(&protocol, &mut io).await.unwrap_err();
        (err, start.elapsed())
    }

    #[tokio::test(start_paused = true)]
    async fn silent_request_stream_hits_the_first_byte_deadline() {
        for protocol in [Protocol::StatusV2, Protocol::MetaDataV3, Protocol::PingV1] {
            let (err, elapsed) = timed_request(protocol, Script::new(vec![], true)).await;
            assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{protocol}");
            assert!(matches!(
                read_error(&err),
                ReadError::Deadline(Deadline::Ttfb)
            ));
            assert_eq!(elapsed, Duration::from_secs(5), "{protocol}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_request_hits_the_per_chunk_deadline() {
        // The first bytes at 1 s, then nothing: 5 s after the first byte.
        let wire =
            p2p_wire::rpc::codec::encode_request(&Request::Status(testkit::status())).unwrap();
        let steps = vec![(Duration::from_secs(1), wire[..wire.len() / 2].to_vec())];
        let (err, elapsed) = timed_request(Protocol::StatusV2, Script::new(steps, true)).await;
        assert!(matches!(
            read_error(&err),
            ReadError::Deadline(Deadline::PerChunk)
        ));
        assert_eq!(elapsed, Duration::from_secs(6));
        // The whole request, but the stream never ends: the end is waited for per chunk too.
        let steps = vec![(Duration::ZERO, wire)];
        let (err, elapsed) = timed_request(Protocol::StatusV2, Script::new(steps, true)).await;
        assert!(matches!(
            read_error(&err),
            ReadError::Deadline(Deadline::PerChunk)
        ));
        assert_eq!(elapsed, Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_request_inside_the_deadlines_is_read() {
        let wire = p2p_wire::rpc::codec::encode_request(&Request::Ping(Ping(4))).unwrap();
        let (head, tail) = wire.split_at(2);
        let steps = vec![
            (Duration::from_secs(4), head.to_vec()),
            (Duration::from_secs(4), tail.to_vec()),
        ];
        let got = codec()
            .read_request(&Protocol::PingV1, &mut Script::new(steps, false))
            .await
            .unwrap();
        assert_eq!(got, RpcRequest::Valid(Request::Ping(Ping(4))));
    }

    fn success(response: Response<E>) -> ReceivedChunk<E> {
        ReceivedChunk {
            context: None,
            chunk: ResponseChunk::Success(response),
        }
    }

    fn error(code: ResultCode, message: &[u8]) -> ReceivedChunk<E> {
        ReceivedChunk {
            context: None,
            chunk: ResponseChunk::Error {
                code,
                message: message.to_vec().try_into().unwrap(),
            },
        }
    }

    async fn write_resp(protocol: Protocol, chunks: Vec<ReceivedChunk<E>>) -> io::Result<Vec<u8>> {
        let mut sink = Cursor::new(Vec::new());
        codec()
            .write_response(&protocol, &mut sink, chunks)
            .await
            .map(|()| sink.into_inner())
    }

    #[tokio::test]
    async fn write_response_round_trips_through_read_response() {
        let cases: Vec<(Request, Vec<ReceivedChunk<E>>)> = vec![
            (
                Request::Status(testkit::status()),
                vec![success(Response::Status(testkit::status()))],
            ),
            (
                Request::MetaData,
                vec![success(Response::MetaData(testkit::metadata()))],
            ),
            (
                Request::Ping(Ping(1)),
                vec![success(Response::Ping(Ping(9)))],
            ),
            (
                Request::Ping(Ping(1)),
                vec![error(ResultCode::InvalidRequest, b"bad")],
            ),
            (
                range(2),
                vec![
                    ReceivedChunk {
                        context: Some(testkit::FULU_DIGEST),
                        chunk: ResponseChunk::Success(Response::Block(Box::new(
                            forked::SignedBeaconBlock::Fulu(testkit::fulu_block(1)),
                        ))),
                    },
                    error(ResultCode::ResourceUnavailable, b"pruned"),
                ],
            ),
        ];
        for (request, chunks) in cases {
            let protocol = request.protocol();
            let wire = write_resp(protocol, chunks.clone()).await.unwrap();
            let mut codec = codec_after(request).await;
            let back = codec
                .read_response(&protocol, &mut Cursor::new(wire))
                .await
                .unwrap();
            assert_eq!(back, chunks, "{protocol}");
        }
    }

    #[tokio::test]
    async fn write_response_refuses_what_the_protocol_does_not_allow() {
        let refused = |r: io::Result<Vec<u8>>| match r {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}"),
            Ok(bytes) => panic!("wrote {bytes:?}"),
        };
        // 3: ResourceUnavailable only where the protocol specifies it.
        for protocol in [Protocol::StatusV2, Protocol::MetaDataV3, Protocol::PingV1] {
            refused(write_resp(protocol, vec![error(ResultCode::ResourceUnavailable, b"")]).await);
        }
        // A response of another protocol.
        refused(
            write_resp(
                Protocol::PingV1,
                vec![success(Response::Status(testkit::status()))],
            )
            .await,
        );
        // Context bytes where the protocol has none, and none where it has them.
        let mut ping = success(Response::Ping(Ping(1)));
        ping.context = Some(testkit::FULU_DIGEST);
        refused(write_resp(Protocol::PingV1, vec![ping]).await);
        let block = success(Response::Block(Box::new(forked::SignedBeaconBlock::Fulu(
            testkit::fulu_block(1),
        ))));
        refused(write_resp(Protocol::BlocksByRangeV2, vec![block]).await);
        // An error chunk ends the response, and carries no context bytes.
        let block = || ReceivedChunk {
            context: Some(testkit::FULU_DIGEST),
            chunk: ResponseChunk::Success(Response::Block(Box::new(
                forked::SignedBeaconBlock::Fulu(testkit::fulu_block(1)),
            ))),
        };
        let unavailable = error(ResultCode::ResourceUnavailable, b"");
        refused(
            write_resp(
                Protocol::BlocksByRangeV2,
                vec![unavailable.clone(), block()],
            )
            .await,
        );
        let mut with_context = unavailable;
        with_context.context = Some(testkit::FULU_DIGEST);
        refused(write_resp(Protocol::BlocksByRangeV2, vec![block(), with_context]).await);
        // Goodbye's response is one chunk (`phase0` L1483): one Goodbye or one error chunk,
        // never two; an empty one writes nothing.
        let bye = success(Response::Goodbye(Goodbye(1)));
        assert_eq!(
            write_resp(Protocol::GoodbyeV1, vec![bye.clone()])
                .await
                .unwrap(),
            encode_success_chunk(None, &1u64.to_le_bytes()).unwrap()
        );
        assert!(!write_resp(
            Protocol::GoodbyeV1,
            vec![error(ResultCode::InvalidRequest, b"")]
        )
        .await
        .unwrap()
        .is_empty());
        refused(write_resp(Protocol::GoodbyeV1, vec![bye.clone(), bye]).await);
        assert_eq!(
            write_resp(Protocol::GoodbyeV1, Vec::new()).await.unwrap(),
            Vec::<u8>::new()
        );
    }

    #[tokio::test]
    async fn goodbye_response_is_one_chunk_or_none() {
        let read = |wire: Vec<u8>| async move {
            let mut codec = codec_after(Request::Goodbye(Goodbye(1))).await;
            codec
                .read_response(&Protocol::GoodbyeV1, &mut Cursor::new(wire))
                .await
        };
        assert!(read(Vec::new()).await.unwrap().is_empty());
        let chunk = encode_success_chunk(None, &3u64.to_le_bytes()).unwrap();
        let got = read(chunk.clone()).await.unwrap();
        assert_eq!(
            got,
            [ReceivedChunk {
                context: None,
                chunk: ResponseChunk::Success(Response::Goodbye(Goodbye(3))),
            }]
        );
        let err = read([chunk.clone(), chunk].concat()).await.unwrap_err();
        assert!(matches!(
            read_error(&err),
            ReadError::TooManyChunks { max: 1 }
        ));
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
    async fn deadlines_are_counted_by_kind() {
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let mut codec = codec_after(Request::Ping(Ping(1)))
            .await
            .with_metrics(metrics.clone());
        let err = codec
            .read_response(&Protocol::PingV1, &mut Script::new(vec![], true))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let mut inbound = codec.clone();
        inbound
            .read_request(&Protocol::PingV1, &mut Script::new(vec![], true))
            .await
            .unwrap_err();
        assert_eq!(metrics.timeouts(Deadline::Ttfb), 2);
        // A refused response is not a timeout.
        let mut codec = codec_after(Request::Ping(Ping(1)))
            .await
            .with_metrics(metrics.clone());
        codec
            .read_response(&Protocol::PingV1, &mut Cursor::new(vec![4, 0]))
            .await
            .unwrap_err();
        for kind in [Deadline::Ttfb, Deadline::PerChunk, Deadline::Total] {
            let want = u64::from(kind == Deadline::Ttfb) * 2;
            assert_eq!(metrics.timeouts(kind), want, "{kind:?}");
        }
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

    // --- paced answers ---

    /// Records when each write happened and how long it was; takes every byte at once.
    #[derive(Default)]
    struct Timed {
        writes: Vec<(Instant, usize)>,
    }

    impl AsyncWrite for Timed {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.push((Instant::now(), buf.len()));
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    const BLOCKS: Protocol = Protocol::BlocksByRangeV2;

    fn blocks(n: u64) -> Vec<ReceivedChunk<E>> {
        (1..=n)
            .map(|slot| ReceivedChunk {
                context: Some(testkit::FULU_DIGEST),
                chunk: ResponseChunk::Success(Response::Block(Box::new(
                    forked::SignedBeaconBlock::Fulu(testkit::fulu_block::<E>(slot)),
                ))),
            })
            .collect()
    }

    fn inbound_codec() -> InboundCodec<E> {
        InboundCodec::new(codec())
    }

    #[tokio::test(start_paused = true)]
    async fn paced_answer_streams_each_chunk_on_its_token() {
        // Two blocks at once, then one per 500 ms; the burst is already spent.
        let limiter = shared_limiter(RateLimits {
            blocks_by_range: Quota::new(2, Duration::from_millis(500)),
            ..RateLimits::default()
        });
        let peer = libp2p::PeerId::random();
        let start = Instant::now();
        for _ in 0..2 {
            limiter.lock().unwrap().schedule(peer, BLOCKS, start);
        }
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let pacer = ChunkPacer::new(limiter, peer, BLOCKS, Some(metrics.clone()));
        let chunks = blocks(4);
        let whole: Vec<usize> = chunks
            .iter()
            .map(|c| {
                encode_response(BLOCKS, std::slice::from_ref(c))
                    .unwrap()
                    .len()
            })
            .collect();
        let answer = Answer {
            chunks,
            pacer: Some(pacer),
        };
        let mut io = Timed::default();
        inbound_codec()
            .write_response(&BLOCKS, &mut io, answer)
            .await
            .unwrap();
        // The first chunk leaves when its own token is back, not the last one's; each chunk
        // goes out whole, one period after the one before it.
        let at: Vec<u128> = io
            .writes
            .iter()
            .map(|(t, _)| (*t - start).as_millis())
            .collect();
        assert_eq!(at, [500, 1000, 1500, 2000]);
        let lens: Vec<usize> = io.writes.iter().map(|(_, n)| *n).collect();
        assert_eq!(lens, whole);
        assert_eq!(metrics.rate_limited_count(BLOCKS), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unpaced_answer_goes_out_at_once() {
        let mut io = Timed::default();
        let start = Instant::now();
        let answer: Answer<E> = blocks(3).into();
        inbound_codec()
            .write_response(&BLOCKS, &mut io, answer)
            .await
            .unwrap();
        assert_eq!(io.writes.len(), 3);
        assert!(io.writes.iter().all(|(t, _)| *t == start));
        // A malformed answer is refused before any chunk is written.
        let mut io = Timed::default();
        let two_pings: Answer<E> = vec![
            ReceivedChunk {
                context: None,
                chunk: ResponseChunk::Success(Response::Ping(Ping(1))),
            };
            2
        ]
        .into();
        let err = inbound_codec()
            .write_response(&Protocol::PingV1, &mut io, two_pings)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(io.writes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_paced_write_refunds_its_unsent_chunk() {
        // One block a second, the token spent: the first chunk waits a second.
        let limiter = shared_limiter(RateLimits {
            blocks_by_range: Quota::new(1, Duration::from_secs(1)),
            ..RateLimits::default()
        });
        let peer = libp2p::PeerId::random();
        let start = Instant::now();
        limiter.lock().unwrap().schedule(peer, BLOCKS, start);
        let answer = Answer {
            chunks: blocks(3),
            pacer: Some(ChunkPacer::new(limiter.clone(), peer, BLOCKS, None)),
        };
        let mut io = Timed::default();
        let mut codec = inbound_codec();
        // The stream goes away (the connection closed) before the chunk is due.
        let write = codec.write_response(&BLOCKS, &mut io, answer);
        assert!(tokio::time::timeout(Duration::from_millis(100), write)
            .await
            .is_err());
        assert!(io.writes.is_empty());
        // The chunk was never sent, so it is not charged: the next one is due when the spent
        // token is back, not a period later.
        let now = Instant::now();
        let due = limiter.lock().unwrap().schedule(peer, BLOCKS, now);
        assert_eq!(due - start, Duration::from_secs(1));
    }

    /// Takes every byte, then fails to flush.
    #[derive(Default)]
    struct FlushFails {
        written: usize,
    }

    impl AsyncWrite for FlushFails {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written += buf.len();
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_chunk_written_whole_stays_charged_when_the_flush_fails() {
        // One block a second, the bucket full.
        let limiter = shared_limiter(RateLimits {
            blocks_by_range: Quota::new(1, Duration::from_secs(1)),
            ..RateLimits::default()
        });
        let peer = libp2p::PeerId::random();
        let start = Instant::now();
        let answer = Answer {
            chunks: blocks(2),
            pacer: Some(ChunkPacer::new(limiter.clone(), peer, BLOCKS, None)),
        };
        let mut io = FlushFails::default();
        let err = inbound_codec()
            .write_response(&BLOCKS, &mut io, answer)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        // The first chunk went to the stream whole, so the peer may have it: it stays charged,
        // and the next chunk waits for its token. The second was never written.
        assert!(io.written > 0);
        let due = limiter.lock().unwrap().schedule(peer, BLOCKS, start);
        assert_eq!(due - start, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn the_inbound_codec_only_reads_requests_and_writes_answers() {
        let mut codec = inbound_codec();
        let bytes = p2p_wire::rpc::codec::encode_request(&Request::Ping(Ping(3))).unwrap();
        let read = codec
            .read_request(&Protocol::PingV1, &mut Cursor::new(bytes))
            .await
            .unwrap();
        assert_eq!(read, RpcRequest::Valid(Request::Ping(Ping(3))));
        let mut sink = Cursor::new(Vec::new());
        assert!(codec
            .write_request(&Protocol::PingV1, &mut sink, Request::Ping(Ping(3)).into())
            .await
            .is_err());
        assert!(codec
            .read_response(&Protocol::PingV1, &mut Cursor::new(Vec::new()))
            .await
            .is_err());
    }
}
