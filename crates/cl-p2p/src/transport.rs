//! The TCP muxers: yamux first, then mplex under three caps.
//!
//! TCP clients MUST support mplex and MAY support yamux, and yamux takes precedence when both
//! are offered (`phase0/p2p-interface.md`). [`muxers`] is that pair for
//! `SwarmBuilder::with_tcp`, yamux first, so every dial we make proposes yamux before mplex.
//!
//! mplex has no flow control: a peer may send on every stream as fast as it likes, and what the
//! application has not read yet sits in memory. Three caps bound it:
//!
//! 1. **Streams** ([`mplex_config`]): at most [`MPLEX_MAX_STREAMS`] at once. mplex resets every
//!    further inbound stream, and delays further outbound ones.
//! 2. **Per stream** (`MaxBufferBehaviour::ResetStream`): mplex resets a stream once
//!    [`MPLEX_MAX_BUFFERED_FRAMES`] frames wait inside mplex for it, and [`BudgetedMuxer`]
//!    resets a stream that holds more than [`MuxerBudget::stream_bytes`] unread bytes.
//! 3. **Per connection** ([`BudgetedMuxer`]): once a connection's streams together hold more
//!    than [`MuxerBudget::connection_bytes`] unread bytes, the connection is closed and
//!    `p2p_conn_budget_exceeded_total` counts it.
//!
//! A [`StreamMuxer`] does not say how much it buffers, so [`BudgetedMuxer`] does the buffering
//! itself: each time the connection task polls it, it reads every open stream into that
//! stream's own buffer until the stream has nothing more, and the application reads from that
//! buffer first. The bytes in those buffers are exactly the bytes the muxer delivered and the
//! application has not read, and their sum is what the budget counts. Beyond them, mplex holds
//! frames only for a stream it read past while reading another one; it wakes the connection
//! task for them, so the next poll moves them into the counted buffers.
//!
//! Wrap only a muxer without flow control. yamux credits its window as data is read, so reading
//! it eagerly would let the peer send without limit; yamux bounds its own buffers by its
//! windows.

#[cfg(test)]
mod tests;

use bytes::{Buf, Bytes, BytesMut};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use futures::{ready, AsyncRead, AsyncWrite, FutureExt as _};
use libp2p::core::muxing::{StreamMuxer, StreamMuxerEvent, StreamMuxerExt as _};
use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use libp2p::yamux;
use libp2p_mplex::MaxBufferBehaviour;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};

/// Streams one mplex connection may have open at once (inbound and outbound together).
pub const MPLEX_MAX_STREAMS: usize = 64;

/// Frames mplex holds for one stream before it resets the stream.
///
/// [`BudgetedMuxer`] reads every stream each time the connection is polled, so frames wait
/// inside mplex only for a stream mplex read past while reading another, until the next poll.
/// 256 frames is 2 MiB of rust-libp2p's 8 KiB frames: enough that a burst on one stream is not
/// reset just because it arrived while another stream was being read. Memory is bounded by
/// [`MuxerBudget`], not by this count.
pub const MPLEX_MAX_BUFFERED_FRAMES: usize = 256;

/// Unread bytes one stream may hold before it is reset: one `MAX_PAYLOAD_SIZE` message at its
/// snappy worst case, `max_compressed_len(MAX_PAYLOAD_SIZE)` = `32 + n + n / 6`
/// (`phase0/p2p-interface.md`), about 11.7 MiB. A peer may send a message that large; a stream
/// holding more than that unread is no longer one message the application is behind on.
pub const DEFAULT_STREAM_BYTES: usize = MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE / 6 + 32;

/// Unread bytes one connection's streams may hold together before it is closed: 32 MiB.
///
/// Two streams can each hold a full [`DEFAULT_STREAM_BYTES`] message (a gossip message and a
/// req/resp chunk the application is behind on at the same time), with about 8.7 MiB to spare. At
/// 100 mplex peers that is at most 3.2 GiB, against the 1 GiB per connection yamux's default
/// receive window would allow.
pub const DEFAULT_CONNECTION_BYTES: usize = 32 << 20;

/// What [`BudgetedMuxer`] reads from a stream at a time, and the size of its buffer's chunks.
const RECV_CHUNK: usize = 16 * 1024;

/// mplex with the stream and per-stream caps: [`MPLEX_MAX_STREAMS`] streams, and
/// [`MaxBufferBehaviour::ResetStream`] after [`MPLEX_MAX_BUFFERED_FRAMES`] frames (the library
/// defaults are 128 streams and blocking the whole connection after 32 frames). Meant to run
/// under [`BudgetedMuxer`], as [`muxers`] does.
#[must_use]
pub fn mplex_config() -> libp2p_mplex::Config {
    let mut config = libp2p_mplex::Config::new();
    config
        .set_max_num_streams(MPLEX_MAX_STREAMS)
        .set_max_buffer_size(MPLEX_MAX_BUFFERED_FRAMES)
        .set_max_buffer_behaviour(MaxBufferBehaviour::ResetStream);
    config
}

/// The muxers for `SwarmBuilder::with_tcp(tcp, noise::Config::new, muxers(budget))`: yamux
/// first, then [`mplex_config`] under `budget`.
pub fn muxers(
    budget: MuxerBudget,
) -> (
    fn() -> yamux::Config,
    impl FnOnce() -> Budgeted<libp2p_mplex::Config>,
) {
    (yamux::Config::default, move || {
        Budgeted::new(mplex_config(), budget)
    })
}

/// The transport metrics, on the service's prometheus-client [`Registry`].
#[derive(Clone, Debug)]
pub struct TransportMetrics {
    conn_budget_exceeded: Counter,
}

impl TransportMetrics {
    /// Creates `p2p_conn_budget_exceeded_total` at 0 and registers it in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self {
            conn_budget_exceeded: Counter::default(),
        };
        registry.register(
            "p2p_conn_budget_exceeded",
            "Connections closed because their streams held more unread bytes than the budget",
            metrics.conn_budget_exceeded.clone(),
        );
        metrics
    }

    /// The current `p2p_conn_budget_exceeded_total` value.
    #[must_use]
    pub fn conn_budget_exceeded(&self) -> u64 {
        self.conn_budget_exceeded.get()
    }
}

/// Why a [`MuxerBudget`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// Every stream would be reset by its first byte.
    #[error("stream_bytes must be at least 1")]
    ZeroStreamBytes,
    /// One stream could hold more than the whole connection may.
    #[error("stream_bytes {stream_bytes} is above connection_bytes {connection_bytes}")]
    StreamAboveConnection {
        stream_bytes: usize,
        connection_bytes: usize,
    },
}

/// The unread bytes a [`BudgetedMuxer`] lets one connection hold, and the counter it bumps when
/// a connection holds more.
#[derive(Clone, Debug)]
pub struct MuxerBudget {
    connection_bytes: usize,
    stream_bytes: usize,
    exceeded: Counter,
}

impl MuxerBudget {
    /// A connection is closed once its streams hold more than `connection_bytes` unread bytes
    /// together, and a stream is reset once it holds more than `stream_bytes`.
    pub fn new(
        connection_bytes: usize,
        stream_bytes: usize,
        metrics: &TransportMetrics,
    ) -> Result<Self, BudgetError> {
        if stream_bytes == 0 {
            return Err(BudgetError::ZeroStreamBytes);
        }
        if stream_bytes > connection_bytes {
            return Err(BudgetError::StreamAboveConnection {
                stream_bytes,
                connection_bytes,
            });
        }
        Ok(Self {
            connection_bytes,
            stream_bytes,
            exceeded: metrics.conn_budget_exceeded.clone(),
        })
    }

    /// [`DEFAULT_CONNECTION_BYTES`] and [`DEFAULT_STREAM_BYTES`].
    #[must_use]
    pub fn with_defaults(metrics: &TransportMetrics) -> Self {
        Self {
            connection_bytes: DEFAULT_CONNECTION_BYTES,
            stream_bytes: DEFAULT_STREAM_BYTES,
            exceeded: metrics.conn_budget_exceeded.clone(),
        }
    }

    /// Unread bytes one connection's streams may hold together.
    #[must_use]
    pub fn connection_bytes(&self) -> usize {
        self.connection_bytes
    }

    /// Unread bytes one stream may hold.
    #[must_use]
    pub fn stream_bytes(&self) -> usize {
        self.stream_bytes
    }
}

/// A muxer upgrade whose muxer runs under a [`MuxerBudget`]: [`BudgetedMuxer`], one per
/// connection.
#[derive(Clone, Debug)]
pub struct Budgeted<U> {
    inner: U,
    budget: MuxerBudget,
}

impl<U> Budgeted<U> {
    /// `inner`, each of whose muxers runs under `budget`.
    pub fn new(inner: U, budget: MuxerBudget) -> Self {
        Self { inner, budget }
    }
}

impl<U: UpgradeInfo> UpgradeInfo for Budgeted<U> {
    type Info = U::Info;
    type InfoIter = U::InfoIter;

    fn protocol_info(&self) -> Self::InfoIter {
        self.inner.protocol_info()
    }
}

impl<C, U> InboundConnectionUpgrade<C> for Budgeted<U>
where
    U: InboundConnectionUpgrade<C>,
    U::Output: StreamMuxer,
    U::Future: Unpin,
{
    type Output = BudgetedMuxer<U::Output>;
    type Error = U::Error;
    type Future = Budgeting<U::Future>;

    fn upgrade_inbound(self, socket: C, info: Self::Info) -> Self::Future {
        Budgeting::new(self.inner.upgrade_inbound(socket, info), self.budget)
    }
}

impl<C, U> OutboundConnectionUpgrade<C> for Budgeted<U>
where
    U: OutboundConnectionUpgrade<C>,
    U::Output: StreamMuxer,
    U::Future: Unpin,
{
    type Output = BudgetedMuxer<U::Output>;
    type Error = U::Error;
    type Future = Budgeting<U::Future>;

    fn upgrade_outbound(self, socket: C, info: Self::Info) -> Self::Future {
        Budgeting::new(self.inner.upgrade_outbound(socket, info), self.budget)
    }
}

/// The upgrade of [`Budgeted`]: the inner upgrade, then its muxer wrapped in a
/// [`BudgetedMuxer`].
#[derive(Debug)]
pub struct Budgeting<F> {
    inner: F,
    /// Taken when the muxer is ready.
    budget: Option<MuxerBudget>,
}

impl<F> Budgeting<F> {
    fn new(inner: F, budget: MuxerBudget) -> Self {
        Self {
            inner,
            budget: Some(budget),
        }
    }
}

impl<F, M, E> Future for Budgeting<F>
where
    F: Future<Output = Result<M, E>> + Unpin,
    M: StreamMuxer,
{
    type Output = Result<BudgetedMuxer<M>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let muxer = ready!(this.inner.poll_unpin(cx))?;
        let budget = this
            .budget
            .take()
            .expect("Budgeting polled after it completed");
        Poll::Ready(Ok(BudgetedMuxer::new(muxer, budget)))
    }
}

/// Why a [`BudgetedMuxer`] closed its connection.
#[derive(Debug, thiserror::Error)]
pub enum BudgetedMuxerError<E> {
    /// The wrapped muxer failed.
    #[error(transparent)]
    Muxer(E),
    /// The connection's streams held more unread bytes than the budget.
    #[error("the connection's streams hold {buffered} unread bytes, over its budget of {budget}")]
    BudgetExceeded { buffered: usize, budget: usize },
}

/// A [`StreamMuxer`] whose streams' unread bytes are counted against a [`MuxerBudget`]; see
/// the [module docs](self).
pub struct BudgetedMuxer<M: StreamMuxer> {
    inner: M,
    budget: MuxerBudget,
    /// The unread bytes every stream holds, together.
    buffered: Arc<AtomicUsize>,
    /// Every stream handed out; a dropped one is pruned on the next poll.
    streams: Vec<Weak<Mutex<Held<M::Substream>>>>,
    /// Where a stream is read into before its buffer.
    scratch: Box<[u8]>,
    /// The unread bytes when the budget was exceeded; the connection is closed from then on.
    exceeded: Option<usize>,
    /// A stream was reset and the connection not flushed since. mplex queues the reset frame
    /// when the stream is dropped but sends it only with the next flush, which it makes only
    /// when writing; so the muxer flushes through another open stream. With no other stream,
    /// the reset leaves with the next stream's flush or the connection's next write, and
    /// meanwhile mplex discards what the peer sends on the reset stream.
    flush_owed: bool,
}

impl<M: StreamMuxer> BudgetedMuxer<M> {
    /// `inner`, with every stream it opens or accepts from now on counted against `budget`.
    pub fn new(inner: M, budget: MuxerBudget) -> Self {
        Self {
            inner,
            budget,
            buffered: Arc::default(),
            streams: Vec::new(),
            scratch: vec![0; RECV_CHUNK].into_boxed_slice(),
            exceeded: None,
            flush_owed: false,
        }
    }

    /// The unread bytes this connection's streams hold.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffered.load(Ordering::Relaxed)
    }

    fn closed(&self) -> Result<(), BudgetedMuxerError<M::Error>> {
        match self.exceeded {
            Some(buffered) => Err(BudgetedMuxerError::BudgetExceeded {
                buffered,
                budget: self.budget.connection_bytes,
            }),
            None => Ok(()),
        }
    }

    fn adopt(&mut self, inner: M::Substream) -> BudgetedStream<M::Substream> {
        let held = Arc::new(Mutex::new(Held::new(inner)));
        self.streams.push(Arc::downgrade(&held));
        BudgetedStream {
            held,
            buffered: Arc::clone(&self.buffered),
        }
    }
}

impl<M> BudgetedMuxer<M>
where
    M: StreamMuxer,
    M::Substream: Unpin,
{
    /// Reads every open stream into its buffer, then closes the connection if they hold more
    /// than the budget.
    fn drain(&mut self, cx: &mut Context<'_>) -> Result<(), BudgetedMuxerError<M::Error>> {
        self.streams.retain(|held| held.strong_count() > 0);
        let limits = Limits {
            stream_bytes: self.budget.stream_bytes,
            connection_bytes: self.budget.connection_bytes,
        };
        for held in self.streams.iter().filter_map(Weak::upgrade) {
            let reset = lock(&held).drain(cx, &mut self.scratch, limits, &self.buffered);
            self.flush_owed |= reset;
            let buffered = self.buffered.load(Ordering::Relaxed);
            if buffered > limits.connection_bytes {
                self.exceeded = Some(buffered);
                self.budget.exceeded.inc();
                tracing::warn!(
                    buffered,
                    budget = limits.connection_bytes,
                    "closing a connection whose streams hold more unread bytes than its budget"
                );
                return self.closed();
            }
        }
        if self.flush_owed {
            self.flush_owed = !self.flush(cx);
        }
        Ok(())
    }

    /// Flushes the connection through the first open stream; whether that finished.
    fn flush(&mut self, cx: &mut Context<'_>) -> bool {
        for held in self.streams.iter().filter_map(Weak::upgrade) {
            if let Some(inner) = lock(&held).inner.as_mut() {
                // An error is the connection's, and the connection reports it.
                return Pin::new(inner).poll_flush(cx).is_ready();
            }
        }
        false
    }
}

impl<M> StreamMuxer for BudgetedMuxer<M>
where
    M: StreamMuxer + Unpin,
    M::Substream: Unpin,
    M::Error: 'static,
{
    type Substream = BudgetedStream<M::Substream>;
    type Error = BudgetedMuxerError<M::Error>;

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        this.closed()?;
        let stream =
            ready!(this.inner.poll_inbound_unpin(cx)).map_err(BudgetedMuxerError::Muxer)?;
        Poll::Ready(Ok(this.adopt(stream)))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        this.closed()?;
        let stream =
            ready!(this.inner.poll_outbound_unpin(cx)).map_err(BudgetedMuxerError::Muxer)?;
        Poll::Ready(Ok(this.adopt(stream)))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .inner
            .poll_close_unpin(cx)
            .map_err(BudgetedMuxerError::Muxer)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        let this = self.get_mut();
        this.closed()?;
        this.drain(cx)?;
        this.inner.poll_unpin(cx).map_err(BudgetedMuxerError::Muxer)
    }
}

/// A stream of a [`BudgetedMuxer`]: reads come from what the muxer drained first, then from
/// the stream itself; writes go straight through. Dropping it frees its bytes and drops the
/// inner stream, which resets it.
pub struct BudgetedStream<S> {
    held: Arc<Mutex<Held<S>>>,
    buffered: Arc<AtomicUsize>,
}

impl<S: AsyncRead + Unpin> AsyncRead for BudgetedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let mut guard = lock(&this.held);
        let held = &mut *guard;
        if !held.buf.is_empty() {
            let n = held.buf.pop_into(out);
            this.buffered.fetch_sub(n, Ordering::Relaxed);
            return Poll::Ready(Ok(n));
        }
        if let Some(e) = held.error.take() {
            return Poll::Ready(Err(e));
        }
        let inner = match (&held.read, held.inner.as_mut()) {
            (ReadState::Open, Some(inner)) => inner,
            (ReadState::Eof, _) => return Poll::Ready(Ok(0)),
            (ReadState::Failed(kind), _) => return Poll::Ready(Err((*kind).into())),
            (ReadState::Open | ReadState::Reset, _) => return Poll::Ready(Err(reset_error())),
        };
        match Pin::new(inner).poll_read(cx, out) {
            Poll::Pending => {
                held.reader = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(0)) => {
                held.read = ReadState::Eof;
                Poll::Ready(Ok(0))
            }
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => {
                held.read = ReadState::Failed(e.kind());
                Poll::Ready(Err(e))
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BudgetedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match lock(&self.held).inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_write(cx, buf),
            None => Poll::Ready(Err(reset_error())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match lock(&self.held).inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_flush(cx),
            None => Poll::Ready(Err(reset_error())),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match lock(&self.held).inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_close(cx),
            None => Poll::Ready(Err(reset_error())),
        }
    }
}

impl<S> Drop for BudgetedStream<S> {
    fn drop(&mut self) {
        let mut held = lock(&self.held);
        self.buffered.fetch_sub(held.buf.len(), Ordering::Relaxed);
        held.buf = RecvBuf::default();
        held.inner = None;
    }
}

/// What a read of a stream may still return once its buffer is empty.
#[derive(Debug)]
enum ReadState {
    /// More data: read the stream.
    Open,
    /// The end of the stream.
    Eof,
    /// The stream failed; every further read fails the same way.
    Failed(io::ErrorKind),
    /// Reset for holding more than its budget.
    Reset,
}

/// One stream, shared by the [`BudgetedStream`] and the muxer that drains it.
struct Held<S> {
    /// `None` once the stream is reset or its [`BudgetedStream`] dropped.
    inner: Option<S>,
    buf: RecvBuf,
    read: ReadState,
    /// A read error the drain hit, for the application's next read after the buffer.
    error: Option<io::Error>,
    /// The task last left waiting on a read.
    reader: Option<Waker>,
}

#[derive(Clone, Copy)]
struct Limits {
    stream_bytes: usize,
    connection_bytes: usize,
}

impl<S> Held<S> {
    fn new(inner: S) -> Self {
        Self {
            inner: Some(inner),
            buf: RecvBuf::default(),
            read: ReadState::Open,
            error: None,
            reader: None,
        }
    }
}

impl<S: AsyncRead + Unpin> Held<S> {
    /// Reads the stream into its buffer until it has nothing more, ends, fails, passes its
    /// budget (reset), or the connection passes its budget (left for the muxer to close).
    /// Whether it reset the stream.
    fn drain(
        &mut self,
        cx: &mut Context<'_>,
        scratch: &mut [u8],
        limits: Limits,
        buffered: &AtomicUsize,
    ) -> bool {
        let mut changed = false;
        let mut reset = false;
        while let (ReadState::Open, Some(inner)) = (&self.read, self.inner.as_mut()) {
            match Pin::new(inner).poll_read(cx, scratch) {
                Poll::Pending => break,
                Poll::Ready(Ok(0)) => self.read = ReadState::Eof,
                Poll::Ready(Ok(n)) => {
                    self.buf.push(&scratch[..n]);
                    let total = buffered.fetch_add(n, Ordering::Relaxed) + n;
                    if self.buf.len() > limits.stream_bytes {
                        self.reset(buffered, limits.stream_bytes);
                        reset = true;
                    } else if total > limits.connection_bytes {
                        changed = true;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.read = ReadState::Failed(e.kind());
                    self.error = Some(e);
                }
            }
            changed = true;
        }
        if changed {
            if let Some(reader) = self.reader.take() {
                reader.wake();
            }
        }
        reset
    }

    /// Frees the buffer and drops the inner stream, which resets it.
    fn reset(&mut self, buffered: &AtomicUsize, stream_bytes: usize) {
        tracing::debug!(
            held = self.buf.len(),
            budget = stream_bytes,
            "resetting a stream that holds more unread bytes than its budget"
        );
        buffered.fetch_sub(self.buf.len(), Ordering::Relaxed);
        self.buf = RecvBuf::default();
        self.inner = None;
        self.read = ReadState::Reset;
    }
}

/// A stream's unread bytes, in chunks of at most [`RECV_CHUNK`], so the memory held stays
/// within two chunks of [`len`](Self::len) however the bytes arrive and are read.
#[derive(Default)]
struct RecvBuf {
    full: VecDeque<Bytes>,
    tail: BytesMut,
    len: usize,
}

impl RecvBuf {
    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, mut data: &[u8]) {
        self.len += data.len();
        while !data.is_empty() {
            if self.tail.len() == RECV_CHUNK {
                self.full.push_back(self.tail.split().freeze());
            }
            let n = (RECV_CHUNK - self.tail.len()).min(data.len());
            self.tail.extend_from_slice(&data[..n]);
            data = &data[n..];
        }
    }

    /// Moves up to `out.len()` of the oldest bytes into `out`; how many.
    fn pop_into(&mut self, out: &mut [u8]) -> usize {
        let n = match self.full.front_mut() {
            Some(front) => {
                let n = out.len().min(front.len());
                out[..n].copy_from_slice(&front[..n]);
                front.advance(n);
                if front.is_empty() {
                    self.full.pop_front();
                }
                n
            }
            None => {
                let n = out.len().min(self.tail.len());
                out[..n].copy_from_slice(&self.tail[..n]);
                self.tail.advance(n);
                n
            }
        };
        self.len -= n;
        n
    }
}

fn reset_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        "stream reset: it held more unread bytes than its budget",
    )
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A stream's state is valid whatever a panicking holder did, so poisoning is ignored.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
