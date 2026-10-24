//! [`Capped`]: a muxer upgrade whose muxer ([`CappedMuxer`]) makes our own opens wait below
//! yamux's stream cap, so they never close the connection.
//!
//! yamux 0.14 counts the streams of both peers together against its cap
//! ([`YAMUX_MAX_STREAMS`](super::YAMUX_MAX_STREAMS)). A peer's stream past it ends the
//! connection with a `GoAway`, and our open past it fails with `TooManyStreams`, which the swarm
//! takes as a failed connection. [`CappedMuxer`] counts every live stream itself, inbound and
//! outbound, from the muxer's answer until its handle is dropped, and holds an open of ours
//! while either is true:
//!
//! - [`YAMUX_MAX_OPENS`](super::YAMUX_MAX_OPENS) of our own streams are live. So a peer always
//!   has room for the rest of the cap, its own streams.
//! - The connection's live streams are within
//!   [`YAMUX_OPEN_MARGIN`](super::YAMUX_OPEN_MARGIN) of the cap. The margin is room for the
//!   streams yamux still counts after their handles are dropped, in the usual case.
//!
//! A held open is woken when a stream goes. The swarm's own substream timeout still bounds it:
//! an open held past that fails as that one open, and the connection stays.
//!
//! **Limit: the count is ours, not yamux's.** yamux 0.14 forgets a stream whose handle was
//! dropped only when it polls its stream receivers, and it does that only while no frame waits
//! to be written (`Connection::poll_next_inbound`). libp2p-yamux can also hold an inbound
//! stream that the swarm has not taken yet. Neither is visible through their API, and a stream
//! here stops counting as soon as its handle is dropped. So the margin is not a bound: while
//! the TCP send side is full, yamux can count more streams than [`CappedMuxer`] does, and one
//! of our opens can still meet `TooManyStreams`, which closes the connection. That needs a peer
//! that holds about 28 streams of its own (the cap less our 32 and the margin) and does not
//! read what we send it. Our own use stays far below the cap, so that peer only loses its own
//! connection.

use futures::task::AtomicWaker;
use futures::{ready, AsyncRead, AsyncWrite};
use libp2p::core::muxing::{StreamMuxer, StreamMuxerEvent, StreamMuxerExt as _};
use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use super::{YAMUX_MAX_OPENS, YAMUX_MAX_STREAMS, YAMUX_OPEN_MARGIN};

/// `U`, each of whose muxers is a [`CappedMuxer`].
#[derive(Clone, Debug)]
pub struct Capped<U>(pub U);

impl<U: UpgradeInfo> UpgradeInfo for Capped<U> {
    type Info = U::Info;
    type InfoIter = U::InfoIter;

    fn protocol_info(&self) -> Self::InfoIter {
        self.0.protocol_info()
    }
}

impl<C, U> InboundConnectionUpgrade<C> for Capped<U>
where
    U: InboundConnectionUpgrade<C>,
    U::Future: Unpin,
{
    type Output = CappedMuxer<U::Output>;
    type Error = U::Error;
    type Future = Capping<U::Future>;

    fn upgrade_inbound(self, socket: C, info: Self::Info) -> Self::Future {
        Capping(self.0.upgrade_inbound(socket, info))
    }
}

impl<C, U> OutboundConnectionUpgrade<C> for Capped<U>
where
    U: OutboundConnectionUpgrade<C>,
    U::Future: Unpin,
{
    type Output = CappedMuxer<U::Output>;
    type Error = U::Error;
    type Future = Capping<U::Future>;

    fn upgrade_outbound(self, socket: C, info: Self::Info) -> Self::Future {
        Capping(self.0.upgrade_outbound(socket, info))
    }
}

/// The upgrade of [`Capped`]: the inner upgrade, then its muxer wrapped in a [`CappedMuxer`].
#[derive(Debug)]
pub struct Capping<F>(F);

impl<F, M, E> Future for Capping<F>
where
    F: Future<Output = Result<M, E>> + Unpin,
{
    type Output = Result<CappedMuxer<M>, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let muxer = ready!(Pin::new(&mut self.0).poll(cx))?;
        Poll::Ready(Ok(CappedMuxer::new(muxer)))
    }
}

/// The live streams of one connection.
#[derive(Debug, Default)]
struct Live {
    all: AtomicUsize,
    ours: AtomicUsize,
    /// The held open, woken when a stream goes.
    held: AtomicWaker,
}

impl Live {
    /// Whether an open of ours waits now.
    fn full(&self) -> bool {
        self.ours.load(Ordering::Acquire) >= YAMUX_MAX_OPENS
            || self.all.load(Ordering::Acquire) >= YAMUX_MAX_STREAMS - YAMUX_OPEN_MARGIN
    }
}

/// A muxer whose opens wait below the stream cap (see the module docs).
#[derive(Debug)]
pub struct CappedMuxer<M> {
    inner: M,
    live: Arc<Live>,
}

impl<M> CappedMuxer<M> {
    /// `inner`, its streams counted from now on.
    pub fn new(inner: M) -> Self {
        Self {
            inner,
            live: Arc::default(),
        }
    }

    /// The streams live now, the peer's and ours, from the muxer's answer until their handles
    /// are dropped.
    #[must_use]
    pub fn live_streams(&self) -> usize {
        self.live.all.load(Ordering::Acquire)
    }
}

impl<M> StreamMuxer for CappedMuxer<M>
where
    M: StreamMuxer + Unpin,
    M::Substream: Unpin,
{
    type Substream = CappedStream<M::Substream>;
    type Error = M::Error;

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let stream = ready!(this.inner.poll_inbound_unpin(cx))?;
        Poll::Ready(Ok(CappedStream::new(stream, &this.live, false)))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        if this.live.full() {
            this.live.held.register(cx.waker());
            // A stream that went between the check and the register woke no one.
            if this.live.full() {
                return Poll::Pending;
            }
        }
        let stream = ready!(this.inner.poll_outbound_unpin(cx))?;
        Poll::Ready(Ok(CappedStream::new(stream, &this.live, true)))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.poll_close_unpin(cx)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        self.get_mut().inner.poll_unpin(cx)
    }
}

/// A stream of a [`CappedMuxer`], counted live until it is dropped.
#[derive(Debug)]
pub struct CappedStream<S> {
    inner: S,
    live: Arc<Live>,
    ours: bool,
}

impl<S> CappedStream<S> {
    fn new(inner: S, live: &Arc<Live>, ours: bool) -> Self {
        live.all.fetch_add(1, Ordering::AcqRel);
        if ours {
            live.ours.fetch_add(1, Ordering::AcqRel);
        }
        Self {
            inner,
            live: Arc::clone(live),
            ours,
        }
    }
}

impl<S> Drop for CappedStream<S> {
    fn drop(&mut self) {
        self.live.all.fetch_sub(1, Ordering::AcqRel);
        if self.ours {
            self.live.ours.fetch_sub(1, Ordering::AcqRel);
        }
        self.live.held.wake();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CappedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read_vectored(cx, bufs)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CappedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
