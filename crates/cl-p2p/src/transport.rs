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
//! itself: each time the connection task polls it (a *pass*), it reads every open stream into
//! that stream's own buffer until the stream has nothing more, and the application reads from
//! that buffer first. The bytes in those buffers are exactly the bytes the muxer delivered and
//! the application has not read, and their sum is what the budget counts.
//!
//! Beyond them, mplex holds the frames it read for one stream while reading another, and a
//! peer may send frames of up to 1 MiB. [`Budgeted`] therefore puts a [`QuotaSocket`] under
//! mplex, which hands it at most [`PASS_BYTES`] and [`PASS_FRAMES`] per pass, and each pass
//! moves what mplex holds before it lets an idle stream read on. Uncounted, mplex holds at most
//! one pass plus the one frame it is decoding, and never the 257 frames at which it resets a
//! healthy stream. Inbound streams mplex has queued are taken into the muxer's own queue,
//! drained and counted until the swarm takes them. A swarm over these muxers must take them at
//! once: see [`MIN_NEGOTIATING_INBOUND_STREAMS`].
//!
//! mplex's own stream cap counts the streams it holds an entry for, and it forgets a stream the
//! peer resets twice while that stream's handle lives on. [`BudgetedMuxer`] therefore counts
//! every live stream itself, queued or handed out, until its handle is dropped
//! ([`BudgetedMuxer::live_streams`]). An inbound stream that would make more than
//! [`MPLEX_MAX_STREAMS`] live closes the connection, and `p2p_conn_budget_exceeded_total` counts
//! it; an outbound open waits while that many are live, since it is ours, until a handle is
//! dropped.
//!
//! mplex resets a stream only by dropping it, and sends that Reset frame only with a flush
//! through another stream; and it sends none for a stream whose write side we closed. A stream
//! over its budget that mplex therefore cannot reset (closed for writing, or with no other
//! stream to flush through) closes the connection instead, so the peer stops sending.
//!
//! Closing a connection fails every stream on it at once: its bytes are freed and a waiting
//! reader or writer is woken to an error.
//!
//! Wrap only a muxer without flow control. yamux credits its window as data is read, so reading
//! it eagerly would let the peer send without limit; yamux bounds its own buffers by its
//! windows.

mod quota;
#[cfg(test)]
mod tests;

use quota::Pass;
pub use quota::{QuotaSocket, EMPTY_FRAME_WINDOW, MAX_EMPTY_FRAMES, PASS_BYTES, PASS_FRAMES};

use bytes::{Buf, Bytes, BytesMut};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use futures::task::AtomicWaker;
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

/// The least `max_negotiating_inbound_streams` a swarm over [`muxers`] may run with:
/// [`MPLEX_MAX_STREAMS`].
///
/// [`BudgetedMuxer`] takes every inbound stream mplex accepts and drains and counts it until
/// the swarm takes it. A stream the swarm leaves waiting has no reader, so what its peer sends
/// piles up against the budget until the connection is closed. The swarm takes inbound streams
/// only while fewer than `max_negotiating_inbound_streams` are negotiating; at
/// [`MPLEX_MAX_STREAMS`] or more it always takes them, since mplex never holds more. The libp2p
/// default is 128. Build the swarm config with [`with_negotiating_inbound_streams`].
pub const MIN_NEGOTIATING_INBOUND_STREAMS: usize = MPLEX_MAX_STREAMS;

/// `config` letting `streams` inbound streams negotiate at once, for a swarm over [`muxers`].
///
/// # Panics
///
/// In debug builds, if `streams` is below [`MIN_NEGOTIATING_INBOUND_STREAMS`]; release builds
/// raise it to that.
#[must_use]
pub fn with_negotiating_inbound_streams(
    config: libp2p::swarm::Config,
    streams: usize,
) -> libp2p::swarm::Config {
    debug_assert!(
        streams >= MIN_NEGOTIATING_INBOUND_STREAMS,
        "max_negotiating_inbound_streams {streams} is below {MIN_NEGOTIATING_INBOUND_STREAMS}: \
         mplex would hold frames for streams the budget does not see"
    );
    config.with_max_negotiating_inbound_streams(streams.max(MIN_NEGOTIATING_INBOUND_STREAMS))
}

/// Frames mplex holds for one stream before it resets the stream.
///
/// mplex holds frames for a stream it read past while reading another. A frame may be up to
/// 1 MiB, so this count bounds nothing in bytes: 256 frames can be 256 MiB. Bytes are bounded by
/// [`PASS_BYTES`] per pass and by [`MuxerBudget`]. A stream gets at most two passes of
/// [`PASS_FRAMES`] frames before it is drained, so a healthy stream never reaches this count.
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
            "Connections closed because their streams held more unread bytes than the budget, \
             a stream over its budget could not be reset, or the peer opened more streams than \
             mplex may hold open",
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
    U: InboundConnectionUpgrade<QuotaSocket<C>>,
    U::Output: StreamMuxer,
    U::Future: Unpin,
{
    type Output = BudgetedMuxer<U::Output>;
    type Error = U::Error;
    type Future = Budgeting<U::Future>;

    fn upgrade_inbound(self, socket: C, info: Self::Info) -> Self::Future {
        let pass = Arc::<Pass>::default();
        let socket = QuotaSocket::new(socket, Arc::clone(&pass));
        Budgeting::new(self.inner.upgrade_inbound(socket, info), self.budget, pass)
    }
}

impl<C, U> OutboundConnectionUpgrade<C> for Budgeted<U>
where
    U: OutboundConnectionUpgrade<QuotaSocket<C>>,
    U::Output: StreamMuxer,
    U::Future: Unpin,
{
    type Output = BudgetedMuxer<U::Output>;
    type Error = U::Error;
    type Future = Budgeting<U::Future>;

    fn upgrade_outbound(self, socket: C, info: Self::Info) -> Self::Future {
        let pass = Arc::<Pass>::default();
        let socket = QuotaSocket::new(socket, Arc::clone(&pass));
        Budgeting::new(self.inner.upgrade_outbound(socket, info), self.budget, pass)
    }
}

/// The upgrade of [`Budgeted`]: the inner upgrade, then its muxer wrapped in a
/// [`BudgetedMuxer`].
#[derive(Debug)]
pub struct Budgeting<F> {
    inner: F,
    /// Taken when the muxer is ready.
    budget: Option<(MuxerBudget, Arc<Pass>)>,
}

impl<F> Budgeting<F> {
    fn new(inner: F, budget: MuxerBudget, pass: Arc<Pass>) -> Self {
        Self {
            inner,
            budget: Some((budget, pass)),
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
        let (budget, pass) = this
            .budget
            .take()
            .expect("Budgeting polled after it completed");
        Poll::Ready(Ok(BudgetedMuxer::with_pass(muxer, budget, pass)))
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
    /// A stream held more unread bytes than its budget, and mplex could not tell the peer to
    /// stop: it sends no Reset for a stream whose write side we closed, and sends a Reset only
    /// with a flush through another stream, of which there was none.
    #[error(
        "a stream holds {held} unread bytes, over its budget of {budget}, and mplex cannot reset it"
    )]
    StreamUnresettable { held: usize, budget: usize },
    /// The peer sent more than [`MAX_EMPTY_FRAMES`] empty data frames in [`EMPTY_FRAME_WINDOW`].
    #[error(
        "the peer sent more than {max} empty data frames in {window}",
        max = MAX_EMPTY_FRAMES,
        window = EMPTY_FRAME_WINDOW
    )]
    EmptyFrameFlood,
    /// A new stream would have made more streams live, queued for the swarm or handed out,
    /// than mplex may hold open.
    #[error("a new stream would make {live} streams live, over the cap of {max}")]
    TooManyStreams { live: usize, max: usize },
}

/// Why a [`BudgetedMuxer`] closed its connection, kept to answer every later call with.
#[derive(Clone, Copy, Debug)]
enum Closed {
    Budget { buffered: usize },
    Unresettable { held: usize },
    EmptyFrames,
    Streams { live: usize },
}

/// A [`StreamMuxer`] whose streams' unread bytes are counted against a [`MuxerBudget`]; see
/// the [module docs](self).
pub struct BudgetedMuxer<M: StreamMuxer> {
    inner: M,
    budget: MuxerBudget,
    /// The read quota, which only a [`Budgeted`] upgrade puts under the muxer.
    pass: Arc<Pass>,
    /// The unread bytes every stream holds, together.
    buffered: Arc<AtomicUsize>,
    /// Every stream whose [`BudgetedStream`] is not yet dropped, queued or handed out; see
    /// [`LiveSlot`].
    live: Arc<Live>,
    /// Every stream handed out or queued; a dropped one is pruned on the next poll. Pruning is
    /// lazy, so [`live`](Self::live), not its length, is the count of live streams.
    streams: Vec<Weak<Mutex<Held<M::Substream>>>>,
    /// Inbound streams taken from the muxer and not yet by the swarm.
    inbound: VecDeque<BudgetedStream<M::Substream>>,
    /// Where a stream is read into before its buffer.
    scratch: Box<[u8]>,
    /// Where the next pass starts, so that no stream is always read first.
    rotation: usize,
    /// Set once the connection is closed for good.
    closed: Option<Closed>,
    /// The bytes held by a stream reset since the connection was last flushed. mplex queues
    /// the Reset frame when the stream is dropped but sends it only with the next flush, which
    /// it makes only through a stream; so the muxer flushes through another open stream, and
    /// with none left it closes the connection (`StreamMuxer::poll` of mplex does nothing and
    /// its connection flush is crate-private).
    flush_owed: Option<usize>,
}

impl<M: StreamMuxer> BudgetedMuxer<M> {
    /// `inner`, with every stream it opens or accepts from now on counted against `budget`.
    ///
    /// Without the socket under it, which only [`Budgeted`] wraps, there is no read quota: a
    /// pass reads each stream for as long as it has data, and frames for one stream that the
    /// read of another pulls in wait inside `inner` until that stream is read.
    pub fn new(inner: M, budget: MuxerBudget) -> Self {
        Self::with_pass(inner, budget, Arc::default())
    }

    fn with_pass(inner: M, budget: MuxerBudget, pass: Arc<Pass>) -> Self {
        Self {
            inner,
            budget,
            pass,
            buffered: Arc::default(),
            live: Arc::default(),
            streams: Vec::new(),
            inbound: VecDeque::new(),
            scratch: vec![0; RECV_CHUNK].into_boxed_slice(),
            rotation: 0,
            closed: None,
            flush_owed: None,
        }
    }

    /// The unread bytes this connection's streams hold.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffered.load(Ordering::Relaxed)
    }

    /// The streams of this connection still alive: queued for the swarm or handed out, and not
    /// yet dropped. A stream reset or failed still counts while its handle is kept.
    #[must_use]
    pub fn live_streams(&self) -> usize {
        self.live.count()
    }

    /// Whether [`MPLEX_MAX_STREAMS`] streams are live, so that an outbound open must wait; if so,
    /// `opener` is woken once one is given back.
    fn at_stream_cap(&self, opener: &Waker) -> bool {
        // Registered before the count is read, so a stream given back in between still wakes it.
        self.live.opener.register(opener);
        self.live.count() >= MPLEX_MAX_STREAMS
    }

    fn closed(&self) -> Result<(), BudgetedMuxerError<M::Error>> {
        self.closed.map_or(Ok(()), |why| Err(self.error(why)))
    }

    /// The error every call answers with once the connection is closed for `why`.
    fn error(&self, why: Closed) -> BudgetedMuxerError<M::Error> {
        match why {
            Closed::Budget { buffered } => BudgetedMuxerError::BudgetExceeded {
                buffered,
                budget: self.budget.connection_bytes,
            },
            Closed::Unresettable { held } => BudgetedMuxerError::StreamUnresettable {
                held,
                budget: self.budget.stream_bytes,
            },
            Closed::EmptyFrames => BudgetedMuxerError::EmptyFrameFlood,
            Closed::Streams { live } => BudgetedMuxerError::TooManyStreams {
                live,
                max: MPLEX_MAX_STREAMS,
            },
        }
    }

    /// The error for `e` from the wrapped muxer: the empty-frame flood when the quota socket
    /// failed it for one, which closes the connection.
    fn muxer_failed(&mut self, e: M::Error) -> BudgetedMuxerError<M::Error> {
        if self.pass.flooded() {
            return self.close(Closed::EmptyFrames);
        }
        BudgetedMuxerError::Muxer(e)
    }

    /// Closes the connection for good: every stream fails from now on, its bytes are freed and
    /// its waiting reader and writer are woken. Returns the error the connection fails with.
    fn close(&mut self, why: Closed) -> BudgetedMuxerError<M::Error> {
        match why {
            Closed::Budget { buffered } => {
                self.budget.exceeded.inc();
                tracing::warn!(
                    buffered,
                    budget = self.budget.connection_bytes,
                    "closing a connection whose streams hold more unread bytes than its budget"
                );
            }
            Closed::Unresettable { held } => {
                self.budget.exceeded.inc();
                tracing::warn!(
                    held,
                    budget = self.budget.stream_bytes,
                    "closing a connection with a stream over its budget that mplex cannot reset"
                );
            }
            // The quota socket logs the flood it found.
            Closed::EmptyFrames => {}
            Closed::Streams { live } => {
                self.budget.exceeded.inc();
                tracing::warn!(
                    live,
                    max = MPLEX_MAX_STREAMS,
                    "closing a connection with more live streams than mplex may hold open"
                );
            }
        }
        self.closed = Some(why);
        self.inbound.clear();
        for held in self.streams.drain(..).filter_map(|held| held.upgrade()) {
            lock(&held).shut(&self.buffered);
        }
        self.error(why)
    }

    /// Adopts `inner` as one more live stream, unless that would make more than
    /// [`MPLEX_MAX_STREAMS`] live, which closes the connection. Only an inbound stream can: an
    /// outbound open waits at the cap ([`at_stream_cap`](Self::at_stream_cap)).
    ///
    /// mplex drops its entry for a stream when the stream is dropped, and holds at most
    /// [`MPLEX_MAX_STREAMS`] entries, so a peer within mplex's cap stays within this one. Two
    /// handles outlive their entry: one whose stream the peer reset twice (mplex forgets the
    /// stream at the second Reset), and one whose stream the budget reset. A peer repeating
    /// either frees an mplex slot each time while the application may keep the handle; only
    /// this count sees those handles pile up.
    fn admit(
        &mut self,
        inner: M::Substream,
    ) -> Result<BudgetedStream<M::Substream>, BudgetedMuxerError<M::Error>> {
        let live = self.live_streams() + 1;
        if live > MPLEX_MAX_STREAMS {
            drop(inner);
            return Err(self.close(Closed::Streams { live }));
        }
        let slot = LiveSlot::take(&self.live);
        let held = Arc::new(Mutex::new(Held::new(inner, slot)));
        self.streams.push(Arc::downgrade(&held));
        Ok(BudgetedStream {
            held,
            buffered: Arc::clone(&self.buffered),
        })
    }
}

impl<M> BudgetedMuxer<M>
where
    M: StreamMuxer + Unpin,
    M::Substream: Unpin,
{
    /// One pass: moves what the streams hold into their buffers, then closes the connection if
    /// they hold more than the budget.
    ///
    /// The pass first sweeps every stream with the socket shut, which moves the frames mplex
    /// already holds; then it lets one stream at a time read the socket, starting at
    /// `rotation`, and sweeps again after each read that took anything. A
    /// burst mplex pulled in for one stream while another read is thereby moved before any
    /// idle stream reads further, and the quota holds what one read can pull in for the others
    /// to [`PASS_FRAMES`].
    fn drain(&mut self, cx: &mut Context<'_>) -> Result<(), BudgetedMuxerError<M::Error>> {
        self.streams.retain(|held| held.strong_count() > 0);
        self.pass.begin(cx.waker());
        let rotation = self.rotation;
        self.rotation = self.rotation.wrapping_add(1);
        self.sweep(cx, rotation)?;
        let streams = self.streams.len();
        for k in 0..streams {
            if self.pass.exhausted() || self.pass.flooded() {
                break;
            }
            let before = self.pass.left();
            self.drain_stream((rotation + k) % streams, cx)?;
            if self.pass.left() != before {
                self.sweep(cx, rotation)?;
            }
        }
        if self.pass.flooded() {
            return Err(self.close(Closed::EmptyFrames));
        }
        if let Some(held) = self.flush_owed {
            match self.flush(cx) {
                Flush::Done => self.flush_owed = None,
                Flush::Pending => {}
                Flush::NoStream => return Err(self.close(Closed::Unresettable { held })),
            }
        }
        Ok(())
    }

    /// With the socket shut, takes the inbound streams the muxer has queued, then drains every
    /// stream, starting at `rotation`.
    fn sweep(
        &mut self,
        cx: &mut Context<'_>,
        rotation: usize,
    ) -> Result<(), BudgetedMuxerError<M::Error>> {
        self.pass.set_open(false);
        let swept = self.take_inbound(cx).and_then(|()| {
            let streams = self.streams.len();
            (0..streams).try_for_each(|k| self.drain_stream((rotation + k) % streams, cx))
        });
        self.pass.set_open(true);
        swept
    }

    /// Takes every inbound stream the muxer has queued into [`inbound`](Self::inbound), where
    /// it is drained and counted until the swarm takes it. mplex queues an inbound stream as
    /// soon as it reads its Open frame, and the swarm takes one per loop of its connection task,
    /// each of which begins a pass; a queued stream left inside mplex would collect a pass of
    /// frames per loop, uncounted, and be reset at its 257th. Each one taken counts as live, so
    /// one past [`MPLEX_MAX_STREAMS`] live closes the connection (see
    /// [`admit`](Self::admit)).
    fn take_inbound(&mut self, cx: &mut Context<'_>) -> Result<(), BudgetedMuxerError<M::Error>> {
        loop {
            match self.inner.poll_inbound_unpin(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(Err(e)) => return Err(self.muxer_failed(e)),
                Poll::Ready(Ok(inner)) => {
                    let stream = self.admit(inner)?;
                    self.inbound.push_back(stream);
                }
            }
        }
    }

    /// Drains stream `index`, then closes the connection if it is over budget.
    fn drain_stream(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
    ) -> Result<(), BudgetedMuxerError<M::Error>> {
        let Some(held) = self.streams[index].upgrade() else {
            return Ok(());
        };
        let limits = Limits {
            stream_bytes: self.budget.stream_bytes,
            connection_bytes: self.budget.connection_bytes,
        };
        let drained = lock(&held).drain(cx, &mut self.scratch, limits, &self.buffered);
        match drained {
            Drained::Kept => {}
            Drained::Reset { held } => {
                self.flush_owed = Some(self.flush_owed.map_or(held, |owed| owed.max(held)));
            }
            Drained::Unresettable { held } => {
                return Err(self.close(Closed::Unresettable { held }));
            }
        }
        let buffered = self.buffered.load(Ordering::Relaxed);
        if buffered > limits.connection_bytes {
            return Err(self.close(Closed::Budget { buffered }));
        }
        Ok(())
    }

    /// Flushes the connection through the first open stream.
    fn flush(&mut self, cx: &mut Context<'_>) -> Flush {
        for held in self.streams.iter().filter_map(Weak::upgrade) {
            if let Some(inner) = lock(&held).inner.as_mut() {
                // An error is the connection's, and the connection reports it.
                return match Pin::new(inner).poll_flush(cx) {
                    Poll::Ready(_) => Flush::Done,
                    Poll::Pending => Flush::Pending,
                };
            }
        }
        Flush::NoStream
    }
}

/// How [`BudgetedMuxer::flush`] went.
enum Flush {
    Done,
    /// The socket is not writable yet; mplex wakes the connection task when it is.
    Pending,
    /// No open stream is left to flush through.
    NoStream,
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
        this.pass.register(cx.waker());
        if let Some(stream) = this.inbound.pop_front() {
            return Poll::Ready(Ok(stream));
        }
        let stream = match ready!(this.inner.poll_inbound_unpin(cx)) {
            Ok(stream) => stream,
            Err(e) => return Poll::Ready(Err(this.muxer_failed(e))),
        };
        Poll::Ready(this.admit(stream))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        this.closed()?;
        this.pass.register(cx.waker());
        // mplex may have room while the cap is reached: a stream the budget reset is gone from
        // mplex, but stays live while its handle is kept. Our own open must not close the
        // connection for that, so it waits before mplex opens anything.
        if this.at_stream_cap(cx.waker()) {
            return Poll::Pending;
        }
        let stream = match ready!(this.inner.poll_outbound_unpin(cx)) {
            Ok(stream) => stream,
            Err(e) => return Poll::Ready(Err(this.muxer_failed(e))),
        };
        Poll::Ready(this.admit(stream))
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
/// the stream itself; writes go straight through. Dropping it frees its bytes, gives back its
/// live slot and drops the inner stream, which resets it.
pub struct BudgetedStream<S> {
    held: Arc<Mutex<Held<S>>>,
    buffered: Arc<AtomicUsize>,
}

impl<S> BudgetedStream<S> {
    /// Runs a write-side `op` on the inner stream, remembering the task it leaves waiting so
    /// that a reset can wake it.
    fn write_side<T>(
        &self,
        cx: &mut Context<'_>,
        op: impl FnOnce(&mut S, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let mut held = lock(&self.held);
        let Some(inner) = held.inner.as_mut() else {
            return Poll::Ready(Err(match held.read {
                ReadState::Closed => closed_error(),
                _ => reset_error(),
            }));
        };
        let poll = op(inner, cx);
        if poll.is_pending() {
            held.writer = Some(cx.waker().clone());
        }
        poll
    }
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
            (ReadState::Closed, _) => return Poll::Ready(Err(closed_error())),
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
        self.write_side(cx, |inner, cx| Pin::new(inner).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_side(cx, |inner, cx| Pin::new(inner).poll_flush(cx))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // mplex sends the Close frame before it flushes, so the stream counts as closed for
        // writing from the first call, finished or not.
        lock(&self.held).write_closed = true;
        self.write_side(cx, |inner, cx| Pin::new(inner).poll_close(cx))
    }
}

impl<S> Drop for BudgetedStream<S> {
    fn drop(&mut self) {
        let mut held = lock(&self.held);
        self.buffered.fetch_sub(held.buf.len(), Ordering::Relaxed);
        held.buf = RecvBuf::default();
        // The slot goes first: mplex may hand out a replacement as soon as the inner stream frees
        // its entry, and that one must not count this one as still live.
        drop(held.slot.take());
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
    /// The connection was closed.
    Closed,
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
    /// The task last left waiting on a write, flush or close; mplex wakes writers only when the
    /// socket is writable, so a reset must wake it.
    writer: Option<Waker>,
    /// The application has closed, or begun to close, its side. mplex sends no Reset for such a
    /// stream when it is dropped, so it cannot be reset.
    write_closed: bool,
    /// The stream's place in its muxer's live count, taken by [`BudgetedStream`]'s drop before
    /// it drops [`inner`](Self::inner).
    slot: Option<LiveSlot>,
}

/// One live stream in its muxer's count of them: taken when the muxer adopts the stream, given
/// back when its [`BudgetedStream`] is dropped, before the inner stream. Tying the count to that
/// drop gives it back on every path a handle ends by: dropped by the swarm or the application,
/// whether its stream was open, reset or failed, or freed from the queue, also when the
/// connection closes. Giving it back wakes an outbound open waiting at the cap.
struct LiveSlot(Arc<Live>);

impl LiveSlot {
    fn take(live: &Arc<Live>) -> Self {
        live.streams.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(live))
    }
}

impl Drop for LiveSlot {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::Relaxed);
        self.0.opener.wake();
    }
}

/// A muxer's count of its live streams; see [`LiveSlot`].
#[derive(Debug, Default)]
struct Live {
    streams: AtomicUsize,
    /// The outbound open waiting at [`MPLEX_MAX_STREAMS`], woken when a stream is given back.
    opener: AtomicWaker,
}

impl Live {
    fn count(&self) -> usize {
        self.streams.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy)]
struct Limits {
    stream_bytes: usize,
    connection_bytes: usize,
}

/// What [`Held::drain`] did to the stream.
enum Drained {
    Kept,
    /// Reset for holding `held` bytes, over its budget.
    Reset {
        held: usize,
    },
    /// Over its budget with `held` bytes, but closed for writing, so not resettable.
    Unresettable {
        held: usize,
    },
}

impl<S> Held<S> {
    fn new(inner: S, slot: LiveSlot) -> Self {
        Self {
            inner: Some(inner),
            buf: RecvBuf::default(),
            read: ReadState::Open,
            error: None,
            reader: None,
            writer: None,
            write_closed: false,
            slot: Some(slot),
        }
    }

    /// Fails the stream for good once its connection is closed: frees its bytes, drops the
    /// inner stream and wakes whoever waits on it.
    fn shut(&mut self, buffered: &AtomicUsize) {
        buffered.fetch_sub(self.buf.len(), Ordering::Relaxed);
        self.buf = RecvBuf::default();
        self.inner = None;
        self.read = ReadState::Closed;
        self.error = None;
        for waiter in [self.reader.take(), self.writer.take()]
            .into_iter()
            .flatten()
        {
            waiter.wake();
        }
    }
}

impl<S: AsyncRead + Unpin> Held<S> {
    /// Reads the stream into its buffer until it has nothing more, ends, fails, passes its
    /// budget (reset, or left for the muxer to close the connection if it cannot be reset), or
    /// the connection passes its budget (left for the muxer to close).
    fn drain(
        &mut self,
        cx: &mut Context<'_>,
        scratch: &mut [u8],
        limits: Limits,
        buffered: &AtomicUsize,
    ) -> Drained {
        let mut changed = false;
        let mut drained = Drained::Kept;
        while let (ReadState::Open, Some(inner)) = (&self.read, self.inner.as_mut()) {
            match Pin::new(inner).poll_read(cx, scratch) {
                Poll::Pending => break,
                Poll::Ready(Ok(0)) => self.read = ReadState::Eof,
                Poll::Ready(Ok(n)) => {
                    self.buf.push(&scratch[..n]);
                    let total = buffered.fetch_add(n, Ordering::Relaxed) + n;
                    let held = self.buf.len();
                    if held > limits.stream_bytes && self.write_closed {
                        drained = Drained::Unresettable { held };
                        changed = true;
                        break;
                    } else if held > limits.stream_bytes {
                        self.reset(buffered, limits.stream_bytes);
                        drained = Drained::Reset { held };
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
        drained
    }

    /// Frees the buffer and drops the inner stream, which resets it, and wakes a waiting
    /// writer to see the reset.
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
        if let Some(writer) = self.writer.take() {
            writer.wake();
        }
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

fn closed_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the connection was closed: it broke its budget",
    )
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A stream's state is valid whatever a panicking holder did, so poisoning is ignored.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// The probe swarm over these muxers lives in its own module.
mod swarm;
pub use swarm::{
    build_swarm, build_swarm_with_gossip, BuildError, DialFailure, Direction, LogNegotiated,
    PeerMetrics, SwarmConfig, DEFAULT_CONNECTION_TIMEOUT, DEFAULT_IDLE_CONNECTION_TIMEOUT,
    DEFAULT_TCP_PORT, MAX_NEGOTIATING_INBOUND_STREAMS,
};
