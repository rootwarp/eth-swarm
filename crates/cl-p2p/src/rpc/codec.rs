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
//! - `ttfb` ([`super::TTFB_TIMEOUT`], 5 s): from the start of the read to the first byte (for an
//!   empty MetaData request, to the end of the stream);
//! - `per_chunk` ([`super::PER_CHUNK_TIMEOUT`], 5 s): for each chunk, from its first read to its
//!   last byte, and for the end of the stream after the last chunk;
//! - `total` ([`super::RESP_TIMEOUT`], 10 s): for the whole response or request.
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
//! token. A column answer goes out at the tokens booked for it instead ([`BookedChunks`]): cut
//! again when writing starts, and settled once, when its first chunk was written whole.
//!
//! A streamed answer (`Answer::streamed`) is written as its responder produces it
//! ([`super::responder`]): each chunk comes encoded and checked from the responder's queue and
//! goes out whole at its token (those booked for the answer, then the pacer's), and gives its
//! bytes of the peer's budget back once written. Its deadlines run from when the answer was
//! made, each less [`super::inbound::STATUS_ANSWER_SLACK`]: no chunk produced by `ttfb` is
//! `2: ServerError`, and at `total` the answer ends at its last whole chunk (one whose token
//! comes later is not sent). The first chunk waits for its token whatever the deadline: rate
//! limiting never answers an error (`phase0/p2p-interface.md` L1269–1274), and
//! `request_response`'s own exchange timeout bounds that wait. When the responder returns, the writer returns and
//! `request_response` closes the write side; an empty answer is valid on a list protocol and
//! `2: ServerError` on a single-response one, and a responder that failed (panicked, or had a
//! chunk refused) gets `2: ServerError` if nothing went out, else a clean end. The unused
//! booked tokens go back when the writer returns `Ok`; a failed write refunds nothing.

use super::columns::{block_lengths, error_answer, fixed_message};
use super::inbound::STATUS_ANSWER_SLACK;
use super::limits::{AnswerPermit, BookedChunks, ChunkPacer, Reservation};
use super::metrics::RpcMetrics;
use super::responder::{Queued, StreamedAnswer};
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
use p2p_wire::rpc::protocols::{
    Protocol, Request, Response, ResponseChunk, ResultCode, MAX_REQUEST_DATA_COLUMN_SIDECARS,
};
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
    /// [`super::TTFB_TIMEOUT`], [`super::RESP_TIMEOUT`] and [`super::PER_CHUNK_TIMEOUT`] \[est\].
    fn default() -> Self {
        Self {
            ttfb: super::TTFB_TIMEOUT,
            total: super::RESP_TIMEOUT,
            per_chunk: super::PER_CHUNK_TIMEOUT,
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
/// - Anything else: fixed-size, at most 256 bytes, or a column sidecar, whose cells and proofs
///   are fixed-size items of its lists: its SSZ length.
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
    check_response(protocol, chunks)?;
    chunks.iter().map(encode_checked_chunk).collect()
}

/// Whether `chunks` may be the response on `protocol` ([`encode_response`]'s rules), without
/// encoding them.
///
/// # Errors
///
/// `InvalidInput` for anything the protocol does not allow.
fn check_response<E: EthSpec>(protocol: Protocol, chunks: &[ReceivedChunk<E>]) -> io::Result<()> {
    let max = match protocol {
        Protocol::BlocksByRangeV2 => usize::MAX,
        // No more than `compute_max_request_data_column_sidecars()` (`fulu/p2p-interface.md`
        // L667–670, L746–747).
        Protocol::DataColumnsByRangeV1 | Protocol::DataColumnsByRootV1 => {
            MAX_REQUEST_DATA_COLUMN_SIDECARS as usize
        }
        // Goodbye too: its response is one chunk (`phase0/p2p-interface.md` L1483).
        _ => 1,
    };
    if chunks.len() > max {
        return Err(invalid_response(format!(
            "{} chunks on {protocol}, at most {max}",
            chunks.len()
        )));
    }
    for (i, ReceivedChunk { context, chunk }) in chunks.iter().enumerate() {
        match chunk {
            ResponseChunk::Success(response) => {
                if !response.answers(protocol) {
                    return Err(invalid_response(format!("{response:?} on {protocol}")));
                }
                if context.is_some() != protocol.has_context_bytes() {
                    return Err(invalid_response(format!(
                        "context bytes {context:?} on {protocol}"
                    )));
                }
            }
            ResponseChunk::Error { code, .. } => {
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
            }
        }
    }
    Ok(())
}

/// The wire bytes of one chunk [`check_response`] passed.
/// The SSZ bytes of a success chunk's payload; 0 for an error chunk, which ends the answer, so
/// no share of the answer's window follows from it ([`super::limits::WriteSchedule`]).
fn ssz_len<E: EthSpec>(chunk: &ReceivedChunk<E>) -> usize {
    match &chunk.chunk {
        ResponseChunk::Success(response) => response.ssz_bytes_len(),
        ResponseChunk::Error { .. } => 0,
    }
}

fn encode_checked_chunk<E: EthSpec>(chunk: &ReceivedChunk<E>) -> io::Result<Vec<u8>> {
    match &chunk.chunk {
        ResponseChunk::Success(response) => {
            encode_success_chunk(chunk.context, &response.ssz_bytes())
        }
        ResponseChunk::Error { code, message } => encode_error_chunk(*code, message),
    }
    .map_err(|e| invalid_response(e.to_string()))
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

/// Our answer to one inbound request: its chunks and how they are paced, by the pacer of the
/// requester's bucket (each chunk charged as it goes) or by the tokens booked for a column
/// answer, and the place a column answer holds until the writer returns.
#[derive(Debug)]
pub struct Answer<E: EthSpec> {
    /// The chunks, in order.
    pub chunks: Vec<ReceivedChunk<E>>,
    /// Paces the chunks, each charged as it is next to go; `None` with `booked` and `token`
    /// neither sends them at once.
    pub pacer: Option<ChunkPacer>,
    /// The first chunk's token, reserved before the answer was made (our Status, read once
    /// the token is due): that chunk goes out at it instead of a token of `pacer`, and gets
    /// back what is still ahead of it if never written whole.
    pub token: Option<Box<Reservation>>,
    /// The tokens booked for the chunks when the request was admitted, settled by the writer;
    /// used before `pacer`.
    pub booked: Option<Box<BookedChunks>>,
    /// The column answer's place, given back when the writer returns or is dropped.
    pub permit: Option<Box<AnswerPermit>>,
    /// A streamed answer: its chunks come from its responder's task instead of `chunks`
    /// (`Answer::streamed`).
    pub stream: Option<Box<StreamedAnswer>>,
}

impl<E: EthSpec> From<Vec<ReceivedChunk<E>>> for Answer<E> {
    /// `chunks`, unpaced.
    fn from(chunks: Vec<ReceivedChunk<E>>) -> Self {
        Self {
            chunks,
            pacer: None,
            token: None,
            booked: None,
            permit: None,
            stream: None,
        }
    }
}

impl<E: EthSpec> Answer<E> {
    /// The answer `stream`'s responder produces, its chunks going out at the tokens `booked`
    /// for it, then at `pacer`'s.
    #[must_use]
    pub(crate) fn streamed(
        stream: StreamedAnswer,
        pacer: Option<ChunkPacer>,
        booked: Option<BookedChunks>,
    ) -> Self {
        Self {
            chunks: Vec::new(),
            pacer,
            token: None,
            booked: booked.map(Box::new),
            permit: None,
            stream: Some(Box::new(stream)),
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

    /// Writes `stream`'s chunks as its responder produces them (see the module docs), each at
    /// its token: one of `booked`, then of `pacer`.
    async fn write_streamed<T: AsyncWrite + Unpin>(
        &self,
        protocol: Protocol,
        io: &mut T,
        mut stream: Box<StreamedAnswer>,
        pacer: Option<ChunkPacer>,
        mut booked: Option<Box<BookedChunks>>,
    ) -> io::Result<()> {
        let deadlines = self.inner.deadlines;
        let end_by = stream.started() + deadlines.total.saturating_sub(STATUS_ANSWER_SLACK);
        let first_by =
            (stream.started() + deadlines.ttfb.saturating_sub(STATUS_ANSWER_SLACK)).min(end_by);
        let mut sent = 0u64;
        let mut produced = false;
        let failed = loop {
            let by = if produced { end_by } else { first_by };
            let Ok(next) = tokio::time::timeout_at(by, stream.next()).await else {
                let deadline = if produced {
                    Deadline::Total
                } else {
                    Deadline::Ttfb
                };
                if let Some(metrics) = &self.inner.metrics {
                    metrics.timed_out(deadline);
                }
                // Nothing produced in time is our failure; a short answer is a valid one.
                break sent == 0;
            };
            produced = true;
            let (bytes, held, last) = match next {
                Some(Queued::Chunk { bytes, held, last }) => (bytes, held, last),
                Some(Queued::Done) => break sent == 0 && protocol.single_response(),
                Some(Queued::Failed) | None => break sent == 0,
            };
            let (due, reservation) = match booked.as_deref() {
                Some(booked) if sent < booked.tokens() => (Some(booked.due(sent)), None),
                _ => {
                    let reservation = pacer.as_ref().map(ChunkPacer::reserve);
                    (reservation.as_ref().map(Reservation::due), reservation)
                }
            };
            if let Some(due) = due {
                if due >= end_by && sent > 0 {
                    // Its token comes past the end: the answer ends at the last whole chunk.
                    break false;
                }
                tokio::time::sleep_until(due).await;
            }
            io.write_all(&bytes).await?;
            if let Some(reservation) = reservation {
                reservation.sent();
            }
            sent += 1;
            drop(held);
            io.flush().await?;
            if last {
                break false;
            }
        };
        if failed {
            let message = fixed_message(ResultCode::ServerError).as_bytes();
            let bytes = encode_error_chunk(ResultCode::ServerError, message)
                .map_err(|e| invalid_response(e.to_string()))?;
            io.write_all(&bytes).await?;
            io.flush().await?;
        }
        if let Some(booked) = booked.as_mut() {
            booked.settle_answer(sent);
        }
        Ok(())
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

    /// Checks the whole answer ([`encode_response`]'s rules), then encodes and writes each chunk
    /// whole once its token is due, dropping each decoded chunk as it is encoded, so the answer
    /// never holds more than its decoded chunks and one encoded one. With a pacer (or the first
    /// chunk's token reserved before, [`Answer::token`]), a chunk whose write never completed
    /// (the future was dropped, or the write failed) gets back the part of its token still
    /// ahead, and one written whole stays charged even if the flush after it fails, since the
    /// peer may have it all. A booked answer is first cut again, at a whole
    /// block, to what a requester reading at the answer's pace from now reads by the end of its
    /// window ([`BookedChunks::cut`]), and an answer of sidecars is refused with
    /// `3: ResourceUnavailable` if not even its first block reaches that requester before the
    /// place goes back (an error answer goes out with its own code); its unused tokens go back
    /// once its first chunk (a refusal's error chunk too) was written and flushed (an empty
    /// one's at once, [`BookedChunks::settle_answer`]), so a stream reset before that (the
    /// request-response handler waits on the answer, not the stream) gets nothing back. A
    /// booked chunk not written by its place in the answer's schedule
    /// ([`super::limits::WriteSchedule`]) ends the write with `TimedOut`. The answer's place
    /// goes back when this returns or is dropped. A streamed answer (`Answer::streamed`) is
    /// written as its responder produces it instead (see the module docs).
    async fn write_response<T>(
        &mut self,
        protocol: &Protocol,
        io: &mut T,
        answer: Answer<E>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if let Some(stream) = answer.stream {
            return self
                .write_streamed(*protocol, io, stream, answer.pacer, answer.booked)
                .await;
        }
        check_response(*protocol, &answer.chunks)?;
        let Answer {
            mut chunks,
            pacer,
            mut token,
            mut booked,
            mut permit,
            stream: _,
        } = answer;
        let now = tokio::time::Instant::now();
        let schedule = booked.as_deref().map(|booked| {
            // Cut again from when writing starts, at a whole block: what is left of the window
            // from here is what the requester has to read in.
            let held_since = permit.as_ref().map_or(now, |p| p.held_since());
            let mut sizes: Vec<usize> = chunks.iter().map(ssz_len).collect();
            let (keep, bytes) = booked.cut(&sizes, &block_lengths(&chunks), held_since, now);
            let sidecars = chunks
                .first()
                .is_some_and(|c| matches!(c.chunk, ResponseChunk::Success(_)));
            if keep == 0 && sidecars {
                // Not even the first block reaches the requester before the place goes back:
                // refused whole, never sent in part and then reset.
                chunks = error_answer(ResultCode::ResourceUnavailable);
                sizes = chunks.iter().map(ssz_len).collect();
            } else if keep > 0 {
                chunks.truncate(keep);
                sizes.truncate(keep);
            }
            // Else an error answer: it holds no block to send in part, and keeps its own code.
            if let Some(permit) = permit.as_mut() {
                permit.hold_bytes(bytes);
            }
            booked.write_schedule(sizes, held_since, now)
        });
        let _place = permit;
        let kept = chunks.len() as u64;
        if kept == 0 {
            if let Some(booked) = booked.as_mut() {
                booked.settle_answer(0);
            }
        }
        for (i, chunk) in (0u64..).zip(chunks) {
            let bytes = encode_checked_chunk(&chunk)?;
            drop(chunk);
            let reservation = match &booked {
                Some(_) => None,
                None => token
                    .take()
                    .map(|token| *token)
                    .or_else(|| pacer.as_ref().map(ChunkPacer::reserve)),
            };
            let due = match &booked {
                Some(booked) => Some(booked.due(i)),
                None => reservation.as_ref().map(|r| r.due()),
            };
            if let (Some(due), Some(schedule)) = (due, &schedule) {
                // A column chunk: written and flushed by its place in the answer's schedule, or
                // the stream is reset and the answer's place goes back.
                let by = schedule.written_by(i, due, tokio::time::Instant::now());
                let written = if due < by {
                    tokio::time::sleep_until(due).await;
                    let write = async {
                        io.write_all(&bytes).await?;
                        io.flush().await
                    };
                    tokio::time::timeout_at(by, write).await.ok()
                } else {
                    None
                };
                match written {
                    Some(written) => {
                        written?;
                        if i == 0 {
                            // The stream took a whole chunk: it is still there.
                            if let Some(booked) = booked.as_mut() {
                                booked.settle_answer(kept);
                            }
                        }
                    }
                    None => {
                        if let Some(metrics) = &self.inner.metrics {
                            metrics.timed_out(Deadline::PerChunk);
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "a column chunk was not written within its deadline",
                        ));
                    }
                }
                continue;
            }
            if let Some(due) = due {
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
            token: None,
            booked: None,
            permit: None,
            stream: None,
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

    /// Deadlines long enough that no test write here meets them.
    const LONG: crate::rpc::limits::ColumnDeadlines = crate::rpc::limits::ColumnDeadlines {
        answer_window: Duration::from_secs(10),
        write: Duration::from_secs(10),
        answer_bytes: crate::rpc::limits::MAX_COLUMN_RESPONSE_BYTES,
    };

    /// BUG-001, SEC-001: a column answer goes out at the tokens booked for it, holds its place
    /// until the writer returns, written or not, and a write dropped midway refunds nothing.
    #[tokio::test(start_paused = true)]
    async fn a_booked_answer_paces_holds_its_place_and_never_refunds() {
        use crate::rpc::limits::{BookedChunks, ColumnPlaces};
        let limiter = shared_limiter(RateLimits {
            blocks_by_range: Quota::new(1, Duration::from_secs(1)),
            ..RateLimits::default()
        });
        let peer = libp2p::PeerId::random();
        let places = ColumnPlaces::new(1, 1, None);
        let start = Instant::now();
        let booked = BookedChunks::book(&limiter, peer, BLOCKS, 3, None, LONG);
        let answer = Answer {
            chunks: blocks(3),
            pacer: None,
            token: None,
            booked: Some(Box::new(booked)),
            permit: places.try_take(peer, None).map(Box::new),
            stream: None,
        };
        assert_eq!(places.held(), 1);
        let mut io = Timed::default();
        inbound_codec()
            .write_response(&BLOCKS, &mut io, answer)
            .await
            .unwrap();
        let at: Vec<u128> = io
            .writes
            .iter()
            .map(|(t, _)| (*t - start).as_millis())
            .collect();
        assert_eq!(at, [0, 1000, 2000]);
        assert_eq!(places.held(), 0, "given back once written");
        // A write dropped before its second chunk: the place goes back, the tokens do not.
        let start = Instant::now();
        let booked = BookedChunks::book(&limiter, peer, BLOCKS, 3, None, LONG);
        let answer = Answer {
            chunks: blocks(3),
            pacer: None,
            token: None,
            booked: Some(Box::new(booked)),
            permit: places.try_take(peer, None).map(Box::new),
            stream: None,
        };
        let mut io = Timed::default();
        let mut codec = inbound_codec();
        let write = codec.write_response(&BLOCKS, &mut io, answer);
        assert!(tokio::time::timeout(Duration::from_millis(1500), write)
            .await
            .is_err());
        assert_eq!(places.held(), 0, "given back when the write is dropped");
        let due = limiter
            .lock()
            .unwrap()
            .schedule(peer, BLOCKS, Instant::now());
        assert!(
            due - start >= Duration::from_secs(3),
            "refunded: {:?}",
            due - start
        );
    }

    /// Accepts nothing: a requester that stopped reading, its window full.
    struct NeverWrites;

    impl AsyncWrite for NeverWrites {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// How long `chunk`'s SSZ bytes take at the default answer pace
    /// ([`crate::rpc::limits::PacedReader::transfer`]).
    fn transfer_at_the_answer_pace(chunk: &ReceivedChunk<E>) -> Duration {
        let window = crate::rpc::limits::COLUMN_ANSWER_WINDOW.as_nanos();
        let bytes = crate::rpc::limits::MAX_COLUMN_RESPONSE_BYTES as u128;
        Duration::from_nanos((window * ssz_len(chunk) as u128 / bytes) as u64)
    }

    /// SEC-001: a due column chunk that cannot be written within the write deadline, after
    /// its own bytes' time at the answer's pace, ends the write, so the answer's place goes back
    /// long before the exchange timeout.
    #[tokio::test(start_paused = true)]
    async fn a_booked_chunk_not_written_in_time_gives_its_place_back() {
        use crate::rpc::limits::{BookedChunks, ColumnDeadlines, ColumnPlaces};
        let limiter = shared_limiter(RateLimits::default());
        let peer = libp2p::PeerId::random();
        let places = ColumnPlaces::new(1, 1, None);
        let deadline = Duration::from_secs(1);
        let answer = Answer {
            chunks: blocks(2),
            pacer: None,
            token: None,
            booked: Some(Box::new(BookedChunks::book(
                &limiter,
                peer,
                BLOCKS,
                2,
                None,
                ColumnDeadlines {
                    write: deadline,
                    ..ColumnDeadlines::default()
                },
            ))),
            permit: places.try_take(peer, None).map(Box::new),
            stream: None,
        };
        let start = Instant::now();
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = RpcMetrics::register(&mut registry);
        let mut codec = InboundCodec::new(codec().with_metrics(metrics.clone()));
        let err = codec
            .write_response(&BLOCKS, &mut NeverWrites, answer)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // The timer's millisecond resolution aside.
        let cut = deadline + transfer_at_the_answer_pace(&blocks(1)[0]);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= cut && elapsed - cut < Duration::from_millis(1),
            "{elapsed:?}"
        );
        assert_eq!(places.held(), 0);
        assert_eq!(metrics.timeouts(Deadline::PerChunk), 1);
    }

    /// A requester that reads a chunk every `every`, after a first `window` of chunks: the
    /// muxer's window, then its own pace; it stops reading for good after `limit` bytes.
    struct SlowReader {
        every: Duration,
        chunk: usize,
        window: usize,
        since: Instant,
        taken: usize,
        limit: usize,
        /// When it stopped reading, at `limit`.
        stopped: Option<Instant>,
        wake: Pin<Box<tokio::time::Sleep>>,
    }

    impl SlowReader {
        fn new(every: Duration, chunk: usize, window: usize) -> Self {
            let since = Instant::now();
            Self {
                every,
                chunk,
                window,
                since,
                taken: 0,
                limit: usize::MAX,
                stopped: None,
                wake: Box::pin(tokio::time::sleep_until(since)),
            }
        }

        /// The same reader, which stops reading after `limit` bytes.
        fn stopping_after(self, limit: usize) -> Self {
            Self { limit, ..self }
        }
    }

    impl AsyncWrite for SlowReader {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.taken >= self.limit {
                self.stopped.get_or_insert_with(Instant::now);
                return Poll::Pending;
            }
            loop {
                let read = (Instant::now() - self.since).as_nanos() / self.every.as_nanos();
                let room = (self.window + self.chunk * read as usize)
                    .saturating_sub(self.taken)
                    .min(self.limit - self.taken);
                if room > 0 {
                    let n = room.min(buf.len());
                    self.taken += n;
                    return Poll::Ready(Ok(n));
                }
                let next = self.since + self.every * (read as u32 + 1);
                self.wake.as_mut().reset(next);
                if self.wake.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// SEC-001: a booked answer keeps to its schedule, not to a deadline per write. Requesters
    /// reading a chunk every 0.9 s, each within the 1 s write deadline, two per /24 on four,
    /// take all eight places and still give every one back before an honest requester's wait
    /// for a place runs out ([`crate::rpc::limits::COLUMN_QUEUE_WAIT`]), so it is served; one
    /// that reads at the answer's own pace is never cut.
    #[tokio::test(start_paused = true)]
    async fn slow_readers_on_many_ips_cannot_keep_every_place() {
        use crate::rpc::answer_bucket::AnswerBucket;
        use crate::rpc::limits::{BookedChunks, ColumnDeadlines, ColumnPlaces};
        use std::net::Ipv4Addr;
        let limiter = shared_limiter(RateLimits::default());
        let places = ColumnPlaces::new(8, 2, None);
        let deadlines = ColumnDeadlines::default();
        let chunk = encode_response(BLOCKS, &blocks(1)).unwrap().len();
        let answer = |peer, ip: u8| Answer {
            chunks: blocks(40),
            pacer: None,
            token: None,
            booked: Some(Box::new(BookedChunks::book(
                &limiter, peer, BLOCKS, 40, None, deadlines,
            ))),
            permit: places
                .try_take(peer, Some(AnswerBucket::V4(Ipv4Addr::new(10, 0, ip, 0))))
                .map(Box::new),
            stream: None,
        };
        let start = Instant::now();
        let slow: Vec<_> = (0..8)
            .map(|i| {
                let answer = answer(libp2p::PeerId::random(), i / 2);
                assert!(answer.permit.is_some(), "place {i}");
                async move {
                    let mut io = SlowReader::new(Duration::from_millis(900), chunk, 2 * chunk);
                    inbound_codec()
                        .write_response(&BLOCKS, &mut io, answer)
                        .await
                }
            })
            .collect();
        assert_eq!(places.held(), 8);
        let honest = libp2p::PeerId::random();
        let mut io = Timed::default();
        let served = async {
            let wait = crate::rpc::limits::COLUMN_QUEUE_WAIT;
            let mut answer = answer(honest, 9);
            while answer.permit.is_none() {
                assert!(start.elapsed() <= wait, "every place still held");
                tokio::time::sleep(Duration::from_millis(50)).await;
                answer = answer_again(answer, &places, honest);
            }
            inbound_codec()
                .write_response(&BLOCKS, &mut io, answer)
                .await
        };
        let (slow, served) = tokio::join!(futures::future::join_all(slow), served);
        served.expect("the honest requester is served");
        assert_eq!(io.writes.len(), 40);
        for written in slow {
            assert_eq!(written.unwrap_err().kind(), io::ErrorKind::TimedOut);
        }
        assert!(start.elapsed() < crate::rpc::limits::COLUMN_QUEUE_WAIT);
        assert_eq!(places.held(), 0);
        // A requester that keeps up with the answer's share of the window is never cut.
        let peer = libp2p::PeerId::random();
        let answer = answer(peer, 1);
        let mut io = SlowReader::new(Duration::from_millis(100), chunk, chunk);
        inbound_codec()
            .write_response(&BLOCKS, &mut io, answer)
            .await
            .expect("read at the answer's pace");
    }

    /// `answer` with a place for `peer`, if one is free now.
    fn answer_again(
        mut answer: Answer<E>,
        places: &crate::rpc::limits::ColumnPlaces,
        peer: libp2p::PeerId,
    ) -> Answer<E> {
        answer.permit = places.try_take(peer, None).map(Box::new);
        answer
    }

    /// SEC-001: a place is held at most the answer window and the write deadline, counted from
    /// when it was taken: a lookup that took long leaves less of the window to write in.
    #[tokio::test(start_paused = true)]
    async fn a_place_is_held_at_most_the_window_and_the_write_deadline() {
        use crate::rpc::limits::{BookedChunks, ColumnDeadlines, ColumnPlaces};
        let limiter = shared_limiter(RateLimits::default());
        let places = ColumnPlaces::new(1, 1, None);
        let deadlines = ColumnDeadlines::default();
        let peer = libp2p::PeerId::random();
        let chunk = encode_response(BLOCKS, &blocks(1)).unwrap().len();
        let taken = Instant::now();
        let answer = Answer {
            chunks: blocks(40),
            pacer: None,
            token: None,
            booked: Some(Box::new(BookedChunks::book(
                &limiter, peer, BLOCKS, 40, None, deadlines,
            ))),
            permit: places.try_take(peer, None).map(Box::new),
            stream: None,
        };
        // The lookup took 3 s; then a requester reading a chunk every 100 ms needs 4 s more.
        tokio::time::advance(Duration::from_secs(3)).await;
        let mut io = SlowReader::new(Duration::from_millis(100), chunk, chunk);
        let err = inbound_codec()
            .write_response(&BLOCKS, &mut io, answer)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(taken.elapsed() <= deadlines.answer_window + deadlines.write);
        assert_eq!(places.held(), 0);
    }

    const COLUMNS: Protocol = Protocol::DataColumnsByRangeV1;

    /// A Gloas sidecar of column `index` at `slot` with `blobs` incompressible cells, so its
    /// encoded size is about its SSZ size (2 KiB a blob).
    fn big_sidecar(
        slot: u64,
        index: u64,
        blobs: usize,
    ) -> consensus_types::gloas::DataColumnSidecar<E> {
        let mut sidecar = testkit::gloas_sidecar::<E>(slot, index);
        let mut x = (slot * 128 + index).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let cells: Vec<_> = (0..blobs)
            .map(|_| {
                let bytes: Vec<u8> = (0..2048)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        x as u8
                    })
                    .collect();
                consensus_types::fulu::Cell::<E>::new(bytes).unwrap()
            })
            .collect();
        sidecar.kzg_proofs = vec![[0xbb; 48]; cells.len()].try_into().unwrap();
        sidecar.column = cells.try_into().unwrap();
        sidecar
    }

    /// A chunk of [`big_sidecar`].
    fn sidecar_chunk(slot: u64, blobs: usize) -> ReceivedChunk<E> {
        ReceivedChunk {
            context: Some(testkit::GLOAS_DIGEST),
            chunk: ResponseChunk::Success(Response::DataColumn(Box::new(
                forked::DataColumnSidecar::Gloas(big_sidecar(slot, 1, blobs)),
            ))),
        }
    }

    /// An answer of 150 sidecars of 21-blob blocks (6.5 MB) and then 600 of 1-blob blocks
    /// (1.3 MB): under the 8 MiB budget and within the tokens it books, its bytes front-loaded.
    fn large_first() -> Vec<ReceivedChunk<E>> {
        (0..750)
            .map(|i| sidecar_chunk(i, if i < 150 { 21 } else { 1 }))
            .collect()
    }

    /// Bytes every 10 ms that read `MAX_COLUMN_RESPONSE_BYTES` in `COLUMN_ANSWER_WINDOW`: the
    /// answer's documented pace, about 1.7 MB/s.
    fn at_the_answer_pace() -> usize {
        let window = crate::rpc::limits::COLUMN_ANSWER_WINDOW.as_millis() as usize;
        crate::rpc::limits::MAX_COLUMN_RESPONSE_BYTES * 10 / window
    }

    /// A booked column answer of `chunks`, with a place taken now.
    fn booked_columns(
        chunks: Vec<ReceivedChunk<E>>,
        places: &crate::rpc::limits::ColumnPlaces,
    ) -> Answer<E> {
        use crate::rpc::limits::{BookedChunks, ColumnDeadlines};
        let limiter = shared_limiter(RateLimits::default());
        let peer = libp2p::PeerId::random();
        let n = chunks.len() as u64;
        Answer {
            chunks,
            pacer: None,
            token: None,
            booked: Some(Box::new(BookedChunks::book(
                &limiter,
                peer,
                COLUMNS,
                n,
                None,
                ColumnDeadlines::default(),
            ))),
            permit: places.try_take(peer, None).map(Box::new),
            stream: None,
        }
    }

    /// The schedule shares the window by bytes: a requester that reads at the answer's pace is
    /// never cut, even when the large sidecars come first, and one that stops reading is still
    /// cut a write deadline and its chunk's bytes' time after it stopped.
    #[tokio::test(start_paused = true)]
    async fn a_reader_at_the_answer_pace_is_never_cut_by_large_chunks_first() {
        let places = crate::rpc::limits::ColumnPlaces::new(1, 1, None);
        let pace = at_the_answer_pace();
        let start = Instant::now();
        let mut io = SlowReader::new(Duration::from_millis(10), pace, pace);
        inbound_codec()
            .write_response(&COLUMNS, &mut io, booked_columns(large_first(), &places))
            .await
            .expect("read at the answer's pace");
        assert!(start.elapsed() <= crate::rpc::limits::COLUMN_ANSWER_WINDOW);
        assert_eq!(places.held(), 0);
        // The same reader, stopping after 2 MB: cut within a write deadline of stopping.
        let mut io = SlowReader::new(Duration::from_millis(10), pace, pace).stopping_after(2 << 20);
        let err = inbound_codec()
            .write_response(&COLUMNS, &mut io, booked_columns(large_first(), &places))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let stopped = io.stopped.expect("stopped reading");
        let cut = Instant::now();
        let largest = transfer_at_the_answer_pace(&sidecar_chunk(0, 21));
        assert!(cut - stopped <= crate::rpc::limits::COLUMN_WRITE_DEADLINE + largest);
        assert!(cut - stopped >= crate::rpc::limits::COLUMN_WRITE_DEADLINE / 2);
        assert_eq!(places.held(), 0);
    }

    /// A slow lookup leaves less of the answer window to write in, though the answer keeps its
    /// byte budget: the answer is cut to the whole blocks a requester reading at the answer's
    /// pace reads in what is left of the window, so it gets a shorter answer, never a reset.
    #[tokio::test(start_paused = true)]
    async fn a_slow_lookup_shortens_the_answer_and_never_resets_it() {
        use crate::rpc::columns::ServedColumn;
        use crate::rpc::columns::{AnswerBudget, ColumnLookup, ColumnReply, Requested};
        use crate::rpc::inbound::{answer_columns, COLUMN_LOOKUP_TIMEOUT};
        use crate::rpc::limits::{
            BookedChunks, ColumnDeadlines, ColumnPlaces, MAX_COLUMN_RESPONSE_BYTES,
        };
        use p2p_wire::rpc::messages::DataColumnsByRangeV1Request;
        const CUSTODY: [u64; 4] = [1, 47, 87, 102];
        // 50 blocks of four 21-blob sidecars: 8.8 MB, past the byte budget.
        let root = |slot: u64| [slot as u8; 32];
        let stored: Vec<ServedColumn> = (0..50u64)
            .flat_map(|slot| {
                CUSTODY.map(|index| {
                    let mut sidecar = big_sidecar(slot, index, 21);
                    sidecar.beacon_block_root = root(slot).into();
                    ServedColumn {
                        context: testkit::GLOAS_DIGEST,
                        fork: network_config::ForkName::Gloas,
                        slot,
                        block_root: root(slot),
                        ssz: sidecar.as_ssz_bytes(),
                    }
                })
            })
            .collect();
        let requested = Requested::of(&Request::DataColumnsByRange(DataColumnsByRangeV1Request {
            start_slot: 0,
            count: 50,
            columns: CUSTODY.to_vec().try_into().unwrap(),
        }))
        .unwrap();
        let contexts = testkit::column_context_table();
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let limiter = shared_limiter(RateLimits::default());
        let places = ColumnPlaces::new(1, 1, None);
        let pace = at_the_answer_pace();
        let mut served = Vec::new();
        for lookup_takes in [
            Duration::ZERO,
            COLUMN_LOOKUP_TIMEOUT - Duration::from_millis(100),
        ] {
            let peer = libp2p::PeerId::random();
            let deadlines = ColumnDeadlines::default();
            let booked = BookedChunks::book(&limiter, peer, COLUMNS, 200, None, deadlines);
            let mut permit = places.try_take(peer, None).unwrap();
            let reply = ColumnReply::Sidecars(stored.clone());
            let lookup: ColumnLookup = Box::pin(async move {
                tokio::time::sleep(lookup_takes).await;
                reply
            });
            let budget = AnswerBudget {
                max_sidecars: booked.tokens(),
                max_bytes: MAX_COLUMN_RESPONSE_BYTES,
            };
            let (chunks, bytes) = answer_columns::<E>(
                lookup, &requested, &contexts, budget, &metrics, &permit, &booked,
            )
            .await;
            permit.hold_bytes(bytes);
            served.push(chunks.len());
            assert_eq!(chunks.len() % CUSTODY.len(), 0, "whole blocks");
            let answer = Answer {
                chunks,
                pacer: None,
                token: None,
                booked: Some(Box::new(booked)),
                permit: Some(Box::new(permit)),
                stream: None,
            };
            let mut io = SlowReader::new(Duration::from_millis(10), pace, pace);
            inbound_codec()
                .write_response(&COLUMNS, &mut io, answer)
                .await
                .unwrap_or_else(|e| panic!("after a {lookup_takes:?} lookup: {e}"));
        }
        // The byte budget cut the answer of the quick lookup; the slow one's is shorter still.
        assert!(served[0] < stored.len(), "{served:?}");
        assert!(served[1] < served[0], "{served:?}");
        assert!(served[1] > 0, "{served:?}");
    }

    /// A requester that reads `bytes` every `every` whenever there is something to read, with
    /// no window to buffer into: it banks no read time while it waits for a chunk (one withheld
    /// for its token), so a chunk takes its own bytes' time from when it is offered.
    struct SteadyReader {
        bytes: usize,
        every: Duration,
        /// When it has read every byte taken so far.
        read_by: Instant,
        wake: Pin<Box<Sleep>>,
        /// Every byte taken.
        taken: Vec<u8>,
        /// Reading from then on with no gap ([`Self::from_now`]).
        from: Option<Instant>,
    }

    impl SteadyReader {
        fn new(bytes: usize, every: Duration) -> Self {
            let now = Instant::now();
            Self {
                bytes,
                every,
                read_by: now,
                wake: Box::pin(tokio::time::sleep_until(now)),
                taken: Vec::new(),
                from: None,
            }
        }

        /// One that reads `bytes` every `every` from now on with no gap, its `n`th byte read
        /// `n` bytes' time after now however late the timer wakes it: for an answer whose
        /// tokens are all due, so it never waits for one.
        fn from_now(bytes: usize, every: Duration) -> Self {
            Self {
                from: Some(Instant::now()),
                ..Self::new(bytes, every)
            }
        }

        /// The SSZ of every sidecar it read, decoded from the wire as a requester does.
        async fn sidecars(&self) -> Vec<Vec<u8>> {
            let contexts = testkit::column_context_table();
            let mut wire = Cursor::new(self.taken.clone());
            read_response_within::<E, _>(
                &mut wire,
                COLUMNS,
                u64::MAX,
                &contexts,
                Deadlines::default(),
                usize::MAX,
            )
            .await
            .unwrap()
            .into_iter()
            .map(|chunk| match chunk.chunk {
                ResponseChunk::Success(Response::DataColumn(sidecar)) => sidecar.as_ssz_bytes(),
                other => panic!("not a sidecar: {other:?}"),
            })
            .collect()
        }

        /// Ready once every byte taken so far is read.
        fn poll_read_up(&mut self, cx: &mut Context<'_>) -> Poll<()> {
            if self.read_by <= Instant::now() {
                return Poll::Ready(());
            }
            let at = self.read_by;
            self.wake.as_mut().reset(at);
            self.wake.as_mut().poll(cx)
        }
    }

    impl AsyncWrite for SteadyReader {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.poll_read_up(cx).is_pending() {
                return Poll::Pending;
            }
            let n = buf.len().min(self.bytes);
            self.taken.extend_from_slice(&buf[..n]);
            let (from, read) = match self.from {
                Some(from) => (from, self.taken.len()),
                None => (Instant::now(), n),
            };
            let nanos = self.every.as_nanos() * read as u128 / self.bytes as u128;
            self.read_by = from + Duration::from_nanos(nanos as u64);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_read_up(cx).map(Ok)
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A stored Gloas sidecar of column `index` at `slot` with `blobs` cells ([`big_sidecar`]).
    fn stored_sidecar(slot: u64, index: u64, blobs: usize) -> crate::rpc::columns::ServedColumn {
        let mut root = [0x5a; 32];
        root[..8].copy_from_slice(&slot.to_be_bytes());
        let mut sidecar = big_sidecar(slot, index, blobs);
        sidecar.beacon_block_root = root.into();
        crate::rpc::columns::ServedColumn {
            context: testkit::GLOAS_DIGEST,
            fork: network_config::ForkName::Gloas,
            slot,
            block_root: root,
            ssz: sidecar.as_ssz_bytes(),
        }
    }

    /// BUG-001: a chunk that waits for its token gives the requester nothing to read meanwhile.
    /// With the burst spent, 500 one-blob sidecars before 165 of 21 blobs take 2.5 s at the
    /// token rate, and a requester reading at the answer's pace from when each byte is offered
    /// then needs 4.3 s more for the large ones. The answer is cut, at a whole block, to what it
    /// reads in the window given when each token is due: a shorter, valid answer, never a reset.
    #[tokio::test(start_paused = true)]
    async fn a_spent_bucket_cuts_a_small_first_answer_to_what_a_steady_reader_reads() {
        use crate::rpc::columns::{AnswerBudget, ColumnLookup, ColumnReply, Requested};
        use crate::rpc::inbound::answer_columns;
        use crate::rpc::limits::{
            BookedChunks, ColumnDeadlines, ColumnPlaces, COLUMN_ANSWER_WINDOW,
            COLUMN_WRITE_DEADLINE, MAX_COLUMN_RESPONSE_BYTES,
        };
        use p2p_wire::rpc::messages::DataColumnsByRangeV1Request;
        let stored: Vec<_> = (0..665u64)
            .map(|slot| stored_sidecar(slot, 1, if slot < 500 { 1 } else { 21 }))
            .collect();
        let total: usize = stored.iter().map(|s| s.ssz.len()).sum();
        assert!(
            total <= MAX_COLUMN_RESPONSE_BYTES,
            "within the byte budget: {total}"
        );
        let requested = Requested::of(&Request::DataColumnsByRange(DataColumnsByRangeV1Request {
            start_slot: 0,
            count: 665,
            columns: vec![1].try_into().unwrap(),
        }))
        .unwrap();
        let contexts = testkit::column_context_table();
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let limiter = shared_limiter(RateLimits::default());
        let places = ColumnPlaces::new(1, 1, None);
        let peer = libp2p::PeerId::random();
        // The burst went on an earlier answer.
        let _spent = limiter
            .lock()
            .unwrap()
            .charge_block(peer, COLUMNS, 512, Instant::now());
        let deadlines = ColumnDeadlines::default();
        let booked = BookedChunks::book(&limiter, peer, COLUMNS, 665, None, deadlines);
        assert_eq!(booked.tokens(), 665);
        let mut permit = places.try_take(peer, None).unwrap();
        let taken = Instant::now();
        let reply = ColumnReply::Sidecars(stored.clone());
        let lookup: ColumnLookup = Box::pin(async move { reply });
        let budget = AnswerBudget {
            max_sidecars: booked.tokens(),
            max_bytes: MAX_COLUMN_RESPONSE_BYTES,
        };
        let (chunks, bytes) = answer_columns::<E>(
            lookup, &requested, &contexts, budget, &metrics, &permit, &booked,
        )
        .await;
        permit.hold_bytes(bytes);
        let sent: Vec<Vec<u8>> = chunks
            .iter()
            .map(|chunk| match &chunk.chunk {
                ResponseChunk::Success(Response::DataColumn(sidecar)) => sidecar.as_ssz_bytes(),
                other => panic!("not a sidecar: {other:?}"),
            })
            .collect();
        let answer = Answer {
            chunks,
            pacer: None,
            token: None,
            booked: Some(Box::new(booked)),
            permit: Some(Box::new(permit)),
            stream: None,
        };
        let mut io = SteadyReader::new(at_the_answer_pace(), Duration::from_millis(10));
        inbound_codec()
            .write_response(&COLUMNS, &mut io, answer)
            .await
            .expect("a steady reader at the answer's pace is never reset");
        assert!(taken.elapsed() <= COLUMN_ANSWER_WINDOW + COLUMN_WRITE_DEADLINE);
        assert_eq!(places.held(), 0);
        // A valid prefix of the stored answer: every small sidecar, cut among the large ones.
        let prefix: Vec<_> = stored[..sent.len()].iter().map(|s| s.ssz.clone()).collect();
        assert_eq!(sent, prefix);
        assert!(sent.len() > 500, "{} sent", sent.len());
        assert!(sent.len() < stored.len(), "{} sent", sent.len());
    }

    /// BUG-005: the writer may start well after the lookup ended. The answer is cut again, at
    /// a whole block, to what a requester reading at the answer's pace from the write's start
    /// reads by the end of the window, while the place's hold stays tied to when it was taken.
    /// 190 sidecars of 21 blobs (8,373,680 bytes) take 4.99 s at that pace: with a 1.1 s delay
    /// before writing they no longer fit, and the honest requester gets a shorter valid prefix,
    /// never a reset.
    #[tokio::test(start_paused = true)]
    async fn a_delay_before_writing_cuts_the_answer_and_never_resets_it() {
        use crate::rpc::columns::{AnswerBudget, ColumnLookup, ColumnReply, Requested};
        use crate::rpc::inbound::answer_columns;
        use crate::rpc::limits::{
            BookedChunks, ColumnDeadlines, ColumnPlaces, COLUMN_ANSWER_WINDOW,
            COLUMN_WRITE_DEADLINE, MAX_COLUMN_RESPONSE_BYTES,
        };
        use p2p_wire::rpc::messages::DataColumnsByRangeV1Request;
        let stored: Vec<_> = (0..190u64)
            .map(|slot| stored_sidecar(slot, 1, 21))
            .collect();
        let total: usize = stored.iter().map(|s| s.ssz.len()).sum();
        assert_eq!(total, 8_373_680);
        let requested = Requested::of(&Request::DataColumnsByRange(DataColumnsByRangeV1Request {
            start_slot: 0,
            count: 190,
            columns: vec![1].try_into().unwrap(),
        }))
        .unwrap();
        let contexts = testkit::column_context_table();
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let limiter = shared_limiter(RateLimits::default());
        let places = ColumnPlaces::new(1, 1, None);
        let peer = libp2p::PeerId::random();
        let booked = BookedChunks::book(
            &limiter,
            peer,
            COLUMNS,
            190,
            None,
            ColumnDeadlines::default(),
        );
        let mut permit = places.try_take(peer, None).unwrap();
        let taken = Instant::now();
        let reply = ColumnReply::Sidecars(stored.clone());
        let lookup: ColumnLookup = Box::pin(async move { reply });
        let budget = AnswerBudget {
            max_sidecars: booked.tokens(),
            max_bytes: MAX_COLUMN_RESPONSE_BYTES,
        };
        let (chunks, bytes) = answer_columns::<E>(
            lookup, &requested, &contexts, budget, &metrics, &permit, &booked,
        )
        .await;
        assert_eq!(
            chunks.len(),
            190,
            "read in the window from the lookup's end"
        );
        permit.hold_bytes(bytes);
        // The writer starts 1.1 s after the lookup ended.
        tokio::time::advance(Duration::from_millis(1_100)).await;
        let mut io = SteadyReader::new(at_the_answer_pace(), Duration::from_millis(10));
        let answer = Answer {
            chunks,
            pacer: None,
            token: None,
            booked: Some(Box::new(booked)),
            permit: Some(Box::new(permit)),
            stream: None,
        };
        inbound_codec()
            .write_response(&COLUMNS, &mut io, answer)
            .await
            .expect("a steady reader at the answer's pace is never reset");
        assert!(taken.elapsed() <= COLUMN_ANSWER_WINDOW + COLUMN_WRITE_DEADLINE);
        assert_eq!(places.held(), 0);
        // A valid prefix of whole blocks, shorter than the lookup's answer.
        let sent = io.sidecars().await;
        let prefix: Vec<_> = stored[..sent.len()].iter().map(|s| s.ssz.clone()).collect();
        assert_eq!(sent, prefix);
        assert!(!sent.is_empty() && sent.len() < 190, "{} sent", sent.len());
    }

    /// The chunks a [`SteadyReader`] read, decoded from the wire as a requester does.
    async fn steadily_read(io: &SteadyReader) -> Vec<ResponseChunk<E>> {
        let contexts = testkit::column_context_table();
        let mut wire = Cursor::new(io.taken.clone());
        read_response_within::<E, _>(
            &mut wire,
            ROOTS,
            u64::MAX,
            &contexts,
            Deadlines::default(),
            usize::MAX,
        )
        .await
        .unwrap()
        .into_iter()
        .map(|chunk| chunk.chunk)
        .collect()
    }

    const ROOTS: Protocol = Protocol::DataColumnsByRootV1;

    /// All 128 columns of one 21-blob Gloas block, by root: 5.64 MB, 3.36 s at the answer's pace.
    fn one_full_block() -> (Vec<crate::rpc::columns::ServedColumn>, Request) {
        use p2p_wire::rpc::messages::{DataColumnsByRootIdentifier, DataColumnsByRootV1Request};
        let stored: Vec<_> = (0..128u64)
            .map(|index| stored_sidecar(7, index, 21))
            .collect();
        let id = DataColumnsByRootIdentifier {
            block_root: stored[0].block_root.into(),
            columns: (0..128u64).collect::<Vec<_>>().try_into().unwrap(),
        };
        let request =
            Request::DataColumnsByRoot(DataColumnsByRootV1Request(vec![id].try_into().unwrap()));
        (stored, request)
    }

    /// All 128 columns of one 21-blob Fulu block, by root: the largest sidecars of a network of
    /// at most 21 blobs a block (45,380 bytes each), their cells random so nothing compresses.
    fn one_full_fulu_block() -> (Vec<crate::rpc::columns::ServedColumn>, Request) {
        use p2p_wire::rpc::messages::{DataColumnsByRootIdentifier, DataColumnsByRootV1Request};
        use tree_hash::TreeHash;
        let slot = 7;
        let stored: Vec<_> = (0..128u64)
            .map(|index| {
                let cells: Vec<_> = big_sidecar(slot, index, 21)
                    .column
                    .iter()
                    .cloned()
                    .collect();
                let mut sidecar = testkit::fulu_sidecar::<E>(slot, index);
                sidecar.column = cells.try_into().unwrap();
                sidecar.kzg_commitments = vec![[0xcc; 48]; 21].try_into().unwrap();
                sidecar.kzg_proofs = vec![[0xbb; 48]; 21].try_into().unwrap();
                crate::rpc::columns::ServedColumn {
                    context: testkit::FULU_DIGEST,
                    fork: network_config::ForkName::Fulu,
                    slot,
                    block_root: sidecar.signed_block_header.message.tree_hash_root().0,
                    ssz: sidecar.as_ssz_bytes(),
                }
            })
            .collect();
        let id = DataColumnsByRootIdentifier {
            block_root: stored[0].block_root.into(),
            columns: (0..128u64).collect::<Vec<_>>().try_into().unwrap(),
        };
        let request =
            Request::DataColumnsByRoot(DataColumnsByRootV1Request(vec![id].try_into().unwrap()));
        (stored, request)
    }

    /// Serves [`one_full_block`] to `peer` from `limiter` as [`crate::rpc::inbound::Control`]
    /// does, its lookup taking `lookup_takes` and its writer starting `delay` after that, to a
    /// requester reading at the answer's pace. The lookup's chunks and the requester's.
    async fn serve_one_full_block(
        limiter: &crate::rpc::limits::SharedLimiter,
        peer: libp2p::PeerId,
        lookup_takes: Duration,
        delay: Duration,
    ) -> (Vec<ResponseChunk<E>>, Vec<ResponseChunk<E>>) {
        let steady = || SteadyReader::new(at_the_answer_pace(), Duration::from_millis(10));
        serve_one_full_block_to(limiter, peer, lookup_takes, delay, steady).await
    }

    /// [`serve_one_full_block`] to the requester `reader` makes when the writer starts.
    async fn serve_one_full_block_to(
        limiter: &crate::rpc::limits::SharedLimiter,
        peer: libp2p::PeerId,
        lookup_takes: Duration,
        delay: Duration,
        reader: impl FnOnce() -> SteadyReader,
    ) -> (Vec<ResponseChunk<E>>, Vec<ResponseChunk<E>>) {
        serve_full_block_to(limiter, peer, lookup_takes, delay, reader, one_full_block()).await
    }

    /// [`serve_one_full_block_to`] with the sidecars and the request of `block`.
    async fn serve_full_block_to(
        limiter: &crate::rpc::limits::SharedLimiter,
        peer: libp2p::PeerId,
        lookup_takes: Duration,
        delay: Duration,
        reader: impl FnOnce() -> SteadyReader,
        block: (Vec<crate::rpc::columns::ServedColumn>, Request),
    ) -> (Vec<ResponseChunk<E>>, Vec<ResponseChunk<E>>) {
        use crate::rpc::columns::{
            lookup_cost, AnswerBudget, ColumnLookup, ColumnReply, Requested,
        };
        use crate::rpc::inbound::answer_columns;
        use crate::rpc::limits::{
            BookedChunks, ColumnDeadlines, ColumnPlaces, COLUMN_ANSWER_WINDOW,
            COLUMN_WRITE_DEADLINE, MAX_COLUMN_RESPONSE_BYTES,
        };
        let (stored, request) = block;
        let requested = Requested::of(&request).unwrap();
        let contexts = testkit::column_context_table();
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let places = ColumnPlaces::new(1, 1, None);
        let booked =
            BookedChunks::book(limiter, peer, ROOTS, 128, None, ColumnDeadlines::default())
                .with_lookup_cost(lookup_cost(&request));
        tokio::time::sleep_until(booked.ready_at()).await;
        let mut permit = places.try_take(peer, None).unwrap();
        let taken = Instant::now();
        let reply = ColumnReply::Sidecars(stored);
        let lookup: ColumnLookup = Box::pin(async move {
            tokio::time::sleep(lookup_takes).await;
            reply
        });
        let budget = AnswerBudget {
            max_sidecars: booked.tokens(),
            max_bytes: MAX_COLUMN_RESPONSE_BYTES,
        };
        let (chunks, bytes) = answer_columns::<E>(
            lookup, &requested, &contexts, budget, &metrics, &permit, &booked,
        )
        .await;
        let looked_up = chunks.iter().map(|c| c.chunk.clone()).collect();
        permit.hold_bytes(bytes);
        tokio::time::advance(delay).await;
        let mut io = reader();
        let answer = Answer {
            chunks,
            pacer: None,
            token: None,
            booked: Some(Box::new(booked)),
            permit: Some(Box::new(permit)),
            stream: None,
        };
        inbound_codec()
            .write_response(&ROOTS, &mut io, answer)
            .await
            .expect("a steady reader at the answer's pace is never reset");
        assert!(taken.elapsed() <= COLUMN_ANSWER_WINDOW + COLUMN_WRITE_DEADLINE);
        assert_eq!(places.held(), 0);
        (looked_up, steadily_read(&io).await)
    }

    /// Whether `chunks` is the one `3: ResourceUnavailable` chunk.
    fn unavailable(chunks: &[ResponseChunk<E>]) -> bool {
        matches!(
            chunks,
            [ResponseChunk::Error {
                code: ResultCode::ResourceUnavailable,
                ..
            }]
        )
    }

    /// The first block of an answer goes whole or not at all: one too large to reach a requester
    /// reading at the answer's pace before the place's hold ends is refused with
    /// `3: ResourceUnavailable`, never sent in part and then reset. All 128 columns of a 21-blob
    /// block take 3.36 s at that pace: after a 1.9 s lookup the block still reaches the requester
    /// within the window and the write deadline (5.26 s of 6 s), but a writer starting 1.2 s
    /// later would need until 6.46 s.
    #[tokio::test(start_paused = true)]
    async fn a_first_block_past_the_hold_is_refused_and_never_sent_in_part() {
        let limiter = shared_limiter(RateLimits::default());
        let (lookup_takes, delay) = (Duration::from_millis(1_900), Duration::from_millis(1_200));
        // Without the delay the whole block goes out.
        let (looked_up, read) = serve_one_full_block(
            &limiter,
            libp2p::PeerId::random(),
            lookup_takes,
            Duration::ZERO,
        )
        .await;
        assert_eq!(
            looked_up.len(),
            128,
            "read in the window from the lookup's end"
        );
        assert_eq!(read, looked_up);
        // With it, the writer refuses the block whole.
        let (looked_up, read) =
            serve_one_full_block(&limiter, libp2p::PeerId::random(), lookup_takes, delay).await;
        assert_eq!(
            looked_up.len(),
            128,
            "read in the window from the lookup's end"
        );
        assert!(unavailable(&read), "{read:?}");
    }

    /// The same holds from the lookup's end: a block whose tokens come too late for a requester
    /// reading at the answer's pace to have it before the place's hold ends (one token per
    /// 50 ms, the last of 128 due 6.35 s after the lookup started) is refused there, never an
    /// empty success, and the refusal is charged as any other: the tokens past the lookup's
    /// cost go back once it was written.
    #[tokio::test(start_paused = true)]
    async fn a_first_block_whose_tokens_come_past_the_hold_is_refused() {
        let period = Duration::from_millis(50);
        let limiter = shared_limiter(RateLimits {
            data_columns_by_root: Quota::new(1, period),
            ..RateLimits::default()
        });
        let peer = libp2p::PeerId::random();
        let start = Instant::now();
        let (looked_up, read) =
            serve_one_full_block(&limiter, peer, Duration::ZERO, Duration::ZERO).await;
        assert!(unavailable(&looked_up), "{looked_up:?}");
        assert!(unavailable(&read), "{read:?}");
        let next = limiter
            .lock()
            .unwrap()
            .clone()
            .schedule(peer, ROOTS, Instant::now());
        assert_eq!(
            next,
            start + period,
            "the lookup's one token kept, the rest back"
        );
    }

    /// A column quota the load check accepts serves the largest first block whole with an
    /// instant lookup, with no burst to spend: a period 100 µs shorter than the longest it
    /// accepts (about 47.03 ms, so the 128th token comes 5.96 s after the first) and the
    /// block's 128 Fulu 21-blob sidecars reach a requester reading at the answer's pace 13 ms
    /// before the 6 s hold ends. One token per 47.2 ms, which a check of the token times alone accepted,
    /// is refused at load, and its block is refused `3: ResourceUnavailable` at the hold.
    #[tokio::test(start_paused = true)]
    async fn a_quota_the_load_check_accepts_serves_a_full_first_block_after_an_instant_lookup() {
        use crate::rpc::limits::{
            largest_column_sidecar, RpcLimits, COLUMN_ANSWER_WINDOW, COLUMN_WRITE_DEADLINE,
            MAX_COLUMN_RESPONSE_BYTES,
        };
        use consensus_types::caps::NetworkCaps;
        use p2p_wire::rpc::codec::max_response_chunk_len;
        let network = NetworkCaps::from_blob_schedule(21, &[]);
        let largest = largest_column_sidecar::<E>(&network);
        let block = one_full_fulu_block();
        assert!(block.0.iter().all(|s| s.ssz.len() == largest));
        let on_wire = {
            let window = COLUMN_ANSWER_WINDOW.as_nanos();
            let bytes = max_response_chunk_len(largest) as u128;
            Duration::from_nanos((window * bytes / MAX_COLUMN_RESPONSE_BYTES as u128) as u64)
        };
        let slowest = (COLUMN_ANSWER_WINDOW + COLUMN_WRITE_DEADLINE - on_wire) / 127;
        let by_root = |period| RpcLimits {
            rate: RateLimits {
                data_columns_by_root: Quota::new(1, period),
                ..RateLimits::default()
            },
            ..RpcLimits::default()
        };
        let steady = || SteadyReader::new(at_the_answer_pace(), Duration::from_millis(10));
        let inside = by_root(slowest - Duration::from_micros(100));
        assert_eq!(inside.validate::<E>(&network), Ok(()));
        let limiter = shared_limiter(inside.rate);
        let peer = libp2p::PeerId::random();
        let (looked_up, read) = serve_full_block_to(
            &limiter,
            peer,
            Duration::ZERO,
            Duration::ZERO,
            steady,
            block.clone(),
        )
        .await;
        assert_eq!(looked_up.len(), 128);
        assert_eq!(read, looked_up);
        let past = by_root(Duration::from_micros(47_200));
        assert!(past.validate::<E>(&network).is_err());
        let limiter = shared_limiter(past.rate);
        let peer = libp2p::PeerId::random();
        let (looked_up, read) = serve_full_block_to(
            &limiter,
            peer,
            Duration::ZERO,
            Duration::ZERO,
            steady,
            block,
        )
        .await;
        assert!(
            unavailable(&looked_up),
            "{} chunks looked up",
            looked_up.len()
        );
        assert!(unavailable(&read), "{} chunks read", read.len());
    }

    /// Only an answer of sidecars is refused past the hold: an error answer (the lookup's
    /// `2: ServerError` here) whose writer starts after the place's hold ended goes out with its
    /// own code, never replaced by `3: ResourceUnavailable`.
    #[tokio::test(start_paused = true)]
    async fn an_error_answer_written_past_the_hold_keeps_its_code() {
        use crate::rpc::columns::error_answer;
        use crate::rpc::limits::{ColumnPlaces, COLUMN_ANSWER_WINDOW, COLUMN_WRITE_DEADLINE};
        let places = ColumnPlaces::new(1, 1, None);
        for code in [ResultCode::ServerError, ResultCode::InvalidRequest] {
            let answer = booked_columns(error_answer(code), &places);
            tokio::time::advance(COLUMN_ANSWER_WINDOW + COLUMN_WRITE_DEADLINE * 2).await;
            let mut io = SteadyReader::new(1 << 20, Duration::ZERO);
            inbound_codec()
                .write_response(&COLUMNS, &mut io, answer)
                .await
                .unwrap();
            let read = read_response_within::<E, _>(
                &mut Cursor::new(io.taken.clone()),
                COLUMNS,
                u64::MAX,
                &testkit::column_context_table(),
                Deadlines::default(),
                usize::MAX,
            )
            .await
            .unwrap();
            assert!(
                matches!(&read[..], [chunk] if matches!(chunk.chunk, ResponseChunk::Error { code: c, .. } if c == code)),
                "{code:?}: {read:?}"
            );
            assert_eq!(places.held(), 0);
        }
    }

    /// The hold check sizes the first block by what goes on the wire, not by its SSZ: each
    /// chunk's result byte, context bytes, length prefix and snappy frames add 26 bytes to a
    /// 21-blob sidecar, 3,328 bytes and about 2 ms at the answer's pace for all 128 columns. A
    /// writer that starts when the block's SSZ would be read just before the hold ends refuses
    /// it, where a requester reading its framed bytes at that pace would be reset partway;
    /// one that starts when its framed bytes would be read just before then serves it whole.
    #[tokio::test(start_paused = true)]
    async fn the_hold_check_counts_the_framed_bytes_of_the_first_block() {
        use crate::rpc::limits::{
            COLUMN_ANSWER_WINDOW, COLUMN_WRITE_DEADLINE, MAX_COLUMN_RESPONSE_BYTES,
        };
        use p2p_wire::rpc::codec::max_response_chunk_len;
        let at_pace = |bytes: usize| {
            let window = COLUMN_ANSWER_WINDOW.as_nanos();
            let nanos = window * bytes as u128 / MAX_COLUMN_RESPONSE_BYTES as u128;
            Duration::from_nanos(nanos as u64)
        };
        let (stored, _) = one_full_block();
        let ssz: Duration = stored.iter().map(|s| at_pace(s.ssz.len())).sum();
        let framed: Duration = stored
            .iter()
            .map(|s| at_pace(max_response_chunk_len(s.ssz.len())))
            .sum();
        assert!(
            framed - ssz > Duration::from_millis(1),
            "{ssz:?} {framed:?}"
        );
        let limiter = shared_limiter(RateLimits::default());
        let lookup_takes = Duration::from_millis(1_900);
        let hold = COLUMN_ANSWER_WINDOW + COLUMN_WRITE_DEADLINE;
        let exact = || SteadyReader::from_now(MAX_COLUMN_RESPONSE_BYTES, COLUMN_ANSWER_WINDOW);
        let serve = |delay| {
            let peer = libp2p::PeerId::random();
            serve_one_full_block_to(&limiter, peer, lookup_takes, delay, exact)
        };
        // The timer wakes the lookup and the requester up to 1 ms late each, so the writer
        // starts up to 1 ms after `delay` and the requester's last read lands up to 1 ms late.
        // Its SSZ is read 1.5 ms before the hold ends, its framed bytes after it: refused.
        let (looked_up, read) =
            serve(hold - lookup_takes - ssz - Duration::from_micros(1_500)).await;
        assert_eq!(looked_up.len(), 128);
        assert!(unavailable(&read), "{} chunks read", read.len());
        // Its framed bytes are read 3 ms before the hold ends: served whole.
        let (looked_up, read) =
            serve(hold - lookup_takes - framed - Duration::from_millis(3)).await;
        assert_eq!(read, looked_up);
        assert_eq!(read.len(), 128);
    }

    /// Fails every write: a stream the requester reset.
    struct ResetStream;

    impl AsyncWrite for ResetStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// When `peer`'s next column chunk would go at `now`, without charging it.
    fn next_column(
        limiter: &crate::rpc::limits::SharedLimiter,
        peer: libp2p::PeerId,
        now: Instant,
    ) -> Instant {
        limiter.lock().unwrap().clone().schedule(peer, COLUMNS, now)
    }

    /// BUG-004: an answer's unused tokens go back once its first chunk is written whole, so the
    /// stream is known to be there; a stream the requester reset during the lookup (the
    /// request-response handler waits on its response channel and never sees the stream until
    /// it writes) fails that write and gets nothing back.
    #[tokio::test(start_paused = true)]
    async fn unused_tokens_go_back_once_the_first_chunk_is_written_never_on_a_reset() {
        use crate::rpc::limits::{BookedChunks, ColumnDeadlines, ColumnPlaces};
        let period = Duration::from_millis(100);
        let limiter = shared_limiter(RateLimits {
            data_columns_by_range: Quota::new(1, period),
            ..RateLimits::default()
        });
        let places = ColumnPlaces::new(2, 2, None);
        let answer = |peer| Answer {
            chunks: vec![sidecar_chunk(0, 1), sidecar_chunk(1, 1)],
            pacer: None,
            token: None,
            booked: Some(Box::new(BookedChunks::book(
                &limiter,
                peer,
                COLUMNS,
                10,
                None,
                ColumnDeadlines::default(),
            ))),
            permit: places.try_take(peer, None).map(Box::new),
            stream: None,
        };
        let start = Instant::now();
        // Written: the two chunks stay charged, the eight past them go back.
        let read = libp2p::PeerId::random();
        let mut io = Timed::default();
        inbound_codec()
            .write_response(&COLUMNS, &mut io, answer(read))
            .await
            .unwrap();
        assert_eq!(io.writes.len(), 2);
        assert_eq!(
            next_column(&limiter, read, Instant::now()),
            start + period * 2
        );
        // Reset: nothing went out, and all ten stay spent.
        let reset = libp2p::PeerId::random();
        let start = Instant::now();
        let err = inbound_codec()
            .write_response(&COLUMNS, &mut ResetStream, answer(reset))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(
            next_column(&limiter, reset, Instant::now()),
            start + period * 10
        );
        assert_eq!(places.held(), 0);
    }

    /// SEC-002: the first block of an answer always goes out, so the booking holds it whole:
    /// a by-root request naming one root's four columns in four identifiers, from a spent
    /// bucket, books and is charged for all four sidecars it gets, not the one an identifier
    /// names. An answer whose first block is past its booking is refused, never sent uncharged.
    #[tokio::test(start_paused = true)]
    async fn a_split_root_request_is_charged_for_every_chunk_it_gets() {
        use crate::rpc::columns::{AnswerBudget, ColumnLookup, ColumnReply, Requested};
        use crate::rpc::inbound::{answer_columns, column_tokens};
        use crate::rpc::limits::{BookedChunks, ColumnDeadlines, ColumnPlaces, RpcLimits};
        use p2p_wire::rpc::messages::{DataColumnsByRootIdentifier, DataColumnsByRootV1Request};
        let period = Duration::from_millis(100);
        let limits = RpcLimits {
            rate: RateLimits {
                data_columns_by_root: Quota::new(1, period),
                ..RateLimits::default()
            },
            ..RpcLimits::default()
        };
        let limiter = shared_limiter(limits.rate);
        let peer = libp2p::PeerId::random();
        let start = Instant::now();
        let _spent = limiter
            .lock()
            .unwrap()
            .charge_block(peer, ROOTS, 100, start);
        let stored: Vec<_> = (0..4).map(|index| stored_sidecar(7, index, 1)).collect();
        let root = stored[0].block_root;
        let ids: Vec<_> = (0..4u64)
            .map(|index| DataColumnsByRootIdentifier {
                block_root: root.into(),
                columns: vec![index].try_into().unwrap(),
            })
            .collect();
        let request =
            Request::DataColumnsByRoot(DataColumnsByRootV1Request(ids.try_into().unwrap()));
        let requested = Requested::of(&request).unwrap();
        let deliverable =
            limiter
                .lock()
                .unwrap()
                .deliverable(peer, ROOTS, limits.column_answer_window, start);
        assert_eq!(deliverable, 0, "the bucket is spent");
        let tokens = column_tokens(
            &request,
            &requested,
            limits.column_answer_sidecars(ROOTS),
            deliverable,
        );
        assert_eq!(tokens, 4);
        let booked = BookedChunks::book(
            &limiter,
            peer,
            ROOTS,
            tokens,
            None,
            ColumnDeadlines::default(),
        );
        // The lookup runs once the first token is due.
        tokio::time::sleep_until(booked.ready_at()).await;
        let places = ColumnPlaces::new(1, 1, None);
        let mut permit = places.try_take(peer, None).unwrap();
        let contexts = testkit::column_context_table();
        let metrics = RpcMetrics::register(&mut prometheus_client::registry::Registry::default());
        let budget = AnswerBudget {
            max_sidecars: booked.tokens(),
            max_bytes: crate::rpc::limits::MAX_COLUMN_RESPONSE_BYTES,
        };
        let reply = ColumnReply::Sidecars(stored.clone());
        let lookup: ColumnLookup = Box::pin(async move { reply });
        let (chunks, bytes) = answer_columns::<E>(
            lookup, &requested, &contexts, budget, &metrics, &permit, &booked,
        )
        .await;
        permit.hold_bytes(bytes);
        let mut io = Timed::default();
        let answer = Answer {
            chunks,
            pacer: None,
            token: None,
            booked: Some(Box::new(booked)),
            permit: Some(Box::new(permit)),
            stream: None,
        };
        inbound_codec()
            .write_response(&ROOTS, &mut io, answer)
            .await
            .unwrap();
        assert_eq!(io.writes.len(), 4, "the whole block");
        let next = limiter
            .lock()
            .unwrap()
            .clone()
            .schedule(peer, ROOTS, Instant::now());
        assert_eq!(next, start + period * (100 + 4), "every chunk charged");

        // Booked for fewer than its first block holds: refused, nothing of the block sent.
        let booked = BookedChunks::book(&limiter, peer, ROOTS, 1, None, ColumnDeadlines::default());
        let permit = places.try_take(peer, None).unwrap();
        let reply = ColumnReply::Sidecars(stored);
        let lookup: ColumnLookup = Box::pin(async move { reply });
        let budget = AnswerBudget {
            max_sidecars: booked.tokens(),
            ..budget
        };
        let (chunks, _) = answer_columns::<E>(
            lookup, &requested, &contexts, budget, &metrics, &permit, &booked,
        )
        .await;
        assert!(
            matches!(
                chunks.as_slice(),
                [ReceivedChunk {
                    chunk: ResponseChunk::Error {
                        code: ResultCode::ServerError,
                        ..
                    },
                    ..
                }]
            ),
            "{chunks:?}"
        );
    }

    /// Serves `request` from `peer` from a store that holds none of what it names, as
    /// [`crate::rpc::inbound::Control`] does: books its tokens on admission, runs the lookup once
    /// the first is due, and writes the empty answer. How long the lookup waited for its tokens.
    async fn serve_unknown(
        limiter: &crate::rpc::limits::SharedLimiter,
        limits: &crate::rpc::limits::RpcLimits,
        peer: libp2p::PeerId,
        request: &Request,
    ) -> Duration {
        use crate::rpc::columns::{lookup_cost, Requested};
        use crate::rpc::inbound::column_tokens;
        use crate::rpc::limits::BookedChunks;
        let protocol = request.protocol();
        let now = Instant::now();
        let requested = Requested::of(request).unwrap();
        let deliverable =
            limiter
                .lock()
                .unwrap()
                .deliverable(peer, protocol, limits.column_answer_window, now);
        let tokens = column_tokens(
            request,
            &requested,
            limits.column_answer_sidecars(protocol),
            deliverable,
        );
        let booked = BookedChunks::book(
            limiter,
            peer,
            protocol,
            tokens,
            None,
            limits.column_deadlines(),
        )
        .with_lookup_cost(lookup_cost(request));
        let ready = booked.ready_at();
        tokio::time::sleep_until(ready).await;
        let answer = Answer {
            chunks: Vec::new(),
            pacer: None,
            token: None,
            booked: Some(Box::new(booked)),
            permit: None,
            stream: None,
        };
        inbound_codec()
            .write_response(&protocol, &mut Timed::default(), answer)
            .await
            .unwrap();
        ready.saturating_duration_since(now)
    }

    /// `n` by-root identifiers of roots no store holds, each naming `columns`.
    fn unknown_roots(n: u8, columns: &[u64]) -> Request {
        use p2p_wire::rpc::messages::{DataColumnsByRootIdentifier, DataColumnsByRootV1Request};
        let ids: Vec<_> = (0..n)
            .map(|i| DataColumnsByRootIdentifier {
                block_root: [i; 32].into(),
                columns: columns.to_vec().try_into().unwrap(),
            })
            .collect();
        Request::DataColumnsByRoot(DataColumnsByRootV1Request(ids.try_into().unwrap()))
    }

    /// SEC-001: a lookup that finds nothing still costs its peer one token per root it named
    /// (per identifier naming a column; one per range), so empty lookups drain the quota like any other answer: past the burst
    /// (512) a peer naming 128 unknown roots a time waits 128 tokens (640 ms) per lookup. An
    /// honest peer is never charged more than the same request answered in full, so a pattern
    /// within its quota never waits for its tokens: a syncing peer asking every 100 ms for 8
    /// roots of 8 columns each we do not hold, and every 200 ms for 32 empty slots of them.
    #[tokio::test(start_paused = true)]
    async fn empty_lookups_drain_the_quota_and_an_honest_pattern_never_waits() {
        use crate::rpc::limits::RpcLimits;
        use p2p_wire::rpc::messages::DataColumnsByRangeV1Request;
        let limits = RpcLimits::default();
        let limiter = shared_limiter(limits.rate);
        let flooding = libp2p::PeerId::random();
        let flood = unknown_roots(128, &[0]);
        let start = Instant::now();
        let mut waited = Duration::ZERO;
        for _ in 0..12 {
            waited += serve_unknown(&limiter, &limits, flooding, &flood).await;
        }
        // 12 × 128 lookups, 512 of them in the burst, the rest at one per 5 ms.
        let period = limits.rate.data_columns_by_root.period;
        assert!(waited >= period * (12 * 128 - 512 - 128), "{waited:?}");
        assert!(start.elapsed() >= period * (12 * 128 - 512 - 128));

        let honest = libp2p::PeerId::random();
        let custody: Vec<u64> = (0..8).collect();
        let by_root = unknown_roots(8, &custody);
        let by_range = Request::DataColumnsByRange(DataColumnsByRangeV1Request {
            start_slot: 0,
            count: 32,
            columns: custody.clone().try_into().unwrap(),
        });
        for step in 0..600u32 {
            let at = Instant::now();
            assert_eq!(
                serve_unknown(&limiter, &limits, honest, &by_root).await,
                Duration::ZERO,
                "by root, step {step}"
            );
            if step % 2 == 0 {
                assert_eq!(
                    serve_unknown(&limiter, &limits, honest, &by_range).await,
                    Duration::ZERO,
                    "by range, step {step}"
                );
            }
            tokio::time::sleep_until(at + Duration::from_millis(100)).await;
        }
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
            token: None,
            booked: None,
            permit: None,
            stream: None,
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
            token: None,
            booked: None,
            permit: None,
            stream: None,
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

    // --- streamed answers (#234) ---

    use crate::rpc::responder::testing::{self, Lives};
    use crate::rpc::responder::{PeerBytes, Responder};
    use p2p_wire::rpc::protocols::MAX_REQUEST_BLOCKS_DENEB;

    /// Takes every write whole, at once, recording when and what.
    #[derive(Default)]
    struct Wire {
        writes: Vec<(Instant, Vec<u8>)>,
    }

    impl Wire {
        fn bytes(&self) -> Vec<u8> {
            self.writes.iter().flat_map(|(_, w)| w.clone()).collect()
        }

        fn at_ms(&self, start: Instant) -> Vec<u128> {
            self.writes
                .iter()
                .map(|(t, _)| (*t - start).as_millis())
                .collect()
        }
    }

    impl AsyncWrite for Wire {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.push((Instant::now(), buf.to_vec()));
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// The unpaced streamed answer of `responder` to `request` (a 1 MiB peer budget), with the
    /// global stream slots and the byte budget it holds.
    fn streamed(
        responder: &dyn Responder<E>,
        request: Request,
    ) -> (Answer<E>, Arc<tokio::sync::Semaphore>, PeerBytes) {
        let (stream, slots, bytes) = testing::start(responder, request, 1 << 20);
        (Answer::streamed(stream, None, None), slots, bytes)
    }

    /// What a requester reads from `wire`, to its end.
    async fn read_back(protocol: Protocol, wire: &[u8]) -> Vec<ResponseChunk<E>> {
        let contexts = testkit::context_table();
        read_response_chunks::<E, _>(
            &mut &wire[..],
            protocol,
            MAX_REQUEST_BLOCKS_DENEB,
            &contexts,
        )
        .await
        .unwrap()
    }

    fn is_server_error(read: &[ResponseChunk<E>]) -> bool {
        matches!(
            read,
            [ResponseChunk::Error {
                code: ResultCode::ServerError,
                ..
            }]
        )
    }

    /// Sends the blocks of slots `1..=n`.
    fn sends(n: u64) -> Arc<dyn Responder<E>> {
        testing::script(move |_, mut sink| async move {
            for slot in 1..=n {
                sink.send(testing::fulu_block(slot)).await.unwrap();
            }
        })
    }

    /// #9: a responder that sends nothing: an empty answer on a list protocol, at once (zero
    /// chunks are a valid response, `phase0/p2p-interface.md` L1203).
    #[tokio::test(start_paused = true)]
    async fn streamed_zero_chunks_closes_cleanly() {
        let (answer, slots, _) = streamed(&*sends(0), range(4));
        let mut wire = Wire::default();
        let start = Instant::now();
        inbound_codec()
            .write_response(&BLOCKS, &mut wire, answer)
            .await
            .unwrap();
        assert!(wire.writes.is_empty());
        assert_eq!(Instant::now(), start, "ended at once");
        assert_eq!(slots.available_permits(), 1);
    }

    /// #9: on a single-response protocol no chunk is `2: ServerError`.
    #[tokio::test(start_paused = true)]
    async fn streamed_zero_chunks_single_response_is_server_error() {
        let (answer, ..) = streamed(&*sends(0), Request::Ping(Ping(1)));
        let mut wire = Wire::default();
        inbound_codec()
            .write_response(&Protocol::PingV1, &mut wire, answer)
            .await
            .unwrap();
        assert!(is_server_error(
            &read_back(Protocol::PingV1, &wire.bytes()).await
        ));
    }

    /// #10: the writer returns as soon as the responder's last chunk is written, not at a
    /// deadline, and `request_response` then closes the write side (`phase0` L1262–1263): the
    /// requester reads every chunk to the end. The task, its slot and its bytes are gone.
    #[tokio::test(start_paused = true)]
    async fn write_side_closed_after_last_chunk() {
        let lives = Lives::default();
        let three = {
            let lives = lives.clone();
            testing::script(move |_, mut sink| {
                let live = lives.enter();
                async move {
                    let _live = live;
                    for slot in 1..=3 {
                        sink.send(testing::fulu_block(slot)).await.unwrap();
                    }
                }
            })
        };
        let (answer, slots, bytes) = streamed(&*three, range(3));
        let mut wire = Wire::default();
        let start = Instant::now();
        inbound_codec()
            .write_response(&BLOCKS, &mut wire, answer)
            .await
            .unwrap();
        assert_eq!(Instant::now(), start, "ended at the last chunk");
        wire.close().await.unwrap();
        assert_eq!(read_back(BLOCKS, &wire.bytes()).await.len(), 3);
        lives.gone().await;
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(bytes.available(), 1 << 20);
    }

    /// #13: no chunk by the first-byte deadline less the slack (4.5 s): `2: ServerError` at
    /// that instant, and the responder's task is aborted.
    #[tokio::test(start_paused = true)]
    async fn ttfb_fires_paused() {
        let lives = Lives::default();
        let slow = {
            let lives = lives.clone();
            testing::script(move |_, mut sink| {
                let live = lives.enter();
                async move {
                    let _live = live;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    let _ = sink.send(testing::fulu_block(1)).await;
                }
            })
        };
        let (answer, slots, _) = streamed(&*slow, range(1));
        let mut wire = Wire::default();
        let start = Instant::now();
        inbound_codec()
            .write_response(&BLOCKS, &mut wire, answer)
            .await
            .unwrap();
        assert_eq!(Instant::now() - start, Duration::from_millis(4_500));
        assert!(is_server_error(&read_back(BLOCKS, &wire.bytes()).await));
        lives.gone().await;
        assert_eq!(slots.available_permits(), 1);
    }

    /// #13: past the total less the slack (9.5 s) after a chunk went out: the answer ends
    /// there, at a whole chunk, with no error chunk.
    #[tokio::test(start_paused = true)]
    async fn total_fires_paused() {
        let lives = Lives::default();
        let stalls = {
            let lives = lives.clone();
            testing::script(move |_, mut sink| {
                let live = lives.enter();
                async move {
                    let _live = live;
                    sink.send(testing::fulu_block(1)).await.unwrap();
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    let _ = sink.send(testing::fulu_block(2)).await;
                }
            })
        };
        let (answer, ..) = streamed(&*stalls, range(2));
        let mut wire = Wire::default();
        let start = Instant::now();
        inbound_codec()
            .write_response(&BLOCKS, &mut wire, answer)
            .await
            .unwrap();
        assert_eq!(Instant::now() - start, Duration::from_millis(9_500));
        let read = read_back(BLOCKS, &wire.bytes()).await;
        assert!(matches!(read[..], [ResponseChunk::Success(_)]), "{read:?}");
        lives.gone().await;
    }

    /// #16 (Cole): a chunk over the quota is withheld until its token (the tokens booked at
    /// admission, then the pacer's) and then sent whole: never split, never an error chunk,
    /// never an early end (`phase0` L1269–1274).
    #[tokio::test(start_paused = true)]
    async fn withheld_chunks_are_whole() {
        use crate::rpc::limits::BookedChunks;
        let limiter = shared_limiter(RateLimits {
            blocks_by_range: Quota::new(1, Duration::from_secs(1)),
            ..RateLimits::default()
        });
        let peer = libp2p::PeerId::random();
        let start = Instant::now();
        let booked = BookedChunks::book(&limiter, peer, BLOCKS, 3, None, LONG);
        let pacer = ChunkPacer::new(Arc::clone(&limiter), peer, BLOCKS, None);
        let (stream, ..) = testing::start(&*sends(4), range(4), 1 << 20);
        let answer = Answer::streamed(stream, Some(pacer), Some(booked));
        let mut wire = Wire::default();
        inbound_codec()
            .write_response(&BLOCKS, &mut wire, answer)
            .await
            .unwrap();
        assert_eq!(wire.at_ms(start), [0, 1000, 2000, 3000]);
        for (_, write) in &wire.writes {
            let one = read_back(BLOCKS, write).await;
            assert!(
                matches!(one[..], [ResponseChunk::Success(_)]),
                "a whole chunk"
            );
        }
    }

    /// #7 (Cole): an object the sink refuses ends the answer: `2: ServerError` if nothing went
    /// out, else the chunks before it and a clean end.
    #[tokio::test(start_paused = true)]
    async fn a_refused_chunk_ends_the_answer() {
        for before in [0u64, 2] {
            let bad = testing::script(move |_, mut sink| async move {
                for slot in 1..=before {
                    sink.send(testing::fulu_block(slot)).await.unwrap();
                }
                let _ = sink.send(Response::Ping(Ping(1))).await;
            });
            let (answer, ..) = streamed(&*bad, range(3));
            let mut wire = Wire::default();
            inbound_codec()
                .write_response(&BLOCKS, &mut wire, answer)
                .await
                .unwrap();
            let read = read_back(BLOCKS, &wire.bytes()).await;
            match before {
                0 => assert!(is_server_error(&read), "{read:?}"),
                _ => assert!(matches!(
                    read[..],
                    [ResponseChunk::Success(_), ResponseChunk::Success(_)]
                )),
            }
        }
    }

    /// #21: a responder that panics ends its answer: `2: ServerError` before any chunk, else a
    /// clean end after the chunks it sent; its slot and bytes come back either way.
    #[tokio::test(start_paused = true)]
    async fn a_panicking_responder_ends_the_answer() {
        for before in [0u64, 1] {
            let buggy = testing::script(move |_, mut sink| async move {
                for slot in 1..=before {
                    sink.send(testing::fulu_block(slot)).await.unwrap();
                }
                panic!("a responder bug");
            });
            let (answer, slots, bytes) = streamed(&*buggy, range(2));
            let mut wire = Wire::default();
            inbound_codec()
                .write_response(&BLOCKS, &mut wire, answer)
                .await
                .unwrap();
            let read = read_back(BLOCKS, &wire.bytes()).await;
            match before {
                0 => assert!(is_server_error(&read), "{read:?}"),
                _ => assert!(matches!(read[..], [ResponseChunk::Success(_)])),
            }
            assert_eq!(slots.available_permits(), 1);
            assert_eq!(bytes.available(), 1 << 20);
        }
    }
}
