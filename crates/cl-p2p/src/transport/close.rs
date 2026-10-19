//! A deadline on the graceful close of a connection.
//!
//! When the swarm closes a connection gracefully, its task waits for the muxer's close with no
//! deadline of its own. That close writes what the muxer still holds, then its close frames,
//! and flushes them; a peer that stopped reading, with our send buffer full, holds it up for
//! good, and the connection keeps its slot. [`DeadlineMuxer`] fails a close still unfinished
//! its deadline after it began, so the swarm drops the connection; [`CloseDeadline`] is the
//! muxer upgrade that puts it on every connection.

use futures::{ready, FutureExt as _};
use libp2p::core::muxing::{StreamMuxer, StreamMuxerEvent, StreamMuxerExt as _};
use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Sleep;

/// A muxer upgrade whose muxers fail a graceful close still unfinished `deadline` after it
/// began: [`DeadlineMuxer`].
#[derive(Clone, Debug)]
pub struct CloseDeadline<U> {
    inner: U,
    deadline: Duration,
}

impl<U> CloseDeadline<U> {
    /// `inner`, each of whose muxers has `deadline` to close.
    pub fn new(inner: U, deadline: Duration) -> Self {
        Self { inner, deadline }
    }
}

impl<U: UpgradeInfo> UpgradeInfo for CloseDeadline<U> {
    type Info = U::Info;
    type InfoIter = U::InfoIter;

    fn protocol_info(&self) -> Self::InfoIter {
        self.inner.protocol_info()
    }
}

impl<C, U> InboundConnectionUpgrade<C> for CloseDeadline<U>
where
    U: InboundConnectionUpgrade<C>,
    U::Output: StreamMuxer,
    U::Future: Unpin,
{
    type Output = DeadlineMuxer<U::Output>;
    type Error = U::Error;
    type Future = WithDeadline<U::Future>;

    fn upgrade_inbound(self, socket: C, info: Self::Info) -> Self::Future {
        WithDeadline::new(self.inner.upgrade_inbound(socket, info), self.deadline)
    }
}

impl<C, U> OutboundConnectionUpgrade<C> for CloseDeadline<U>
where
    U: OutboundConnectionUpgrade<C>,
    U::Output: StreamMuxer,
    U::Future: Unpin,
{
    type Output = DeadlineMuxer<U::Output>;
    type Error = U::Error;
    type Future = WithDeadline<U::Future>;

    fn upgrade_outbound(self, socket: C, info: Self::Info) -> Self::Future {
        WithDeadline::new(self.inner.upgrade_outbound(socket, info), self.deadline)
    }
}

/// The upgrade of [`CloseDeadline`]: the inner upgrade, then its muxer wrapped in a
/// [`DeadlineMuxer`].
#[derive(Debug)]
pub struct WithDeadline<F> {
    inner: F,
    deadline: Duration,
}

impl<F> WithDeadline<F> {
    fn new(inner: F, deadline: Duration) -> Self {
        Self { inner, deadline }
    }
}

impl<F, M, E> Future for WithDeadline<F>
where
    F: Future<Output = Result<M, E>> + Unpin,
    M: StreamMuxer,
{
    type Output = Result<DeadlineMuxer<M>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let muxer = ready!(this.inner.poll_unpin(cx))?;
        Poll::Ready(Ok(DeadlineMuxer::new(muxer, this.deadline)))
    }
}

/// Why a [`DeadlineMuxer`] failed.
#[derive(Debug, thiserror::Error)]
pub enum CloseDeadlineError<E> {
    /// The wrapped muxer failed.
    #[error(transparent)]
    Muxer(E),
    /// The graceful close had not finished its deadline after it began.
    #[error("the graceful close had not finished after {0:?}: the connection is dropped")]
    Expired(Duration),
}

/// A [`StreamMuxer`] whose graceful close fails once its deadline passed, which
/// [`CloseDeadline`] builds. Everything else goes straight to the wrapped muxer.
#[derive(Debug)]
pub struct DeadlineMuxer<M> {
    inner: M,
    deadline: Duration,
    /// Set when the close begins.
    expires: Option<Pin<Box<Sleep>>>,
}

impl<M> DeadlineMuxer<M> {
    /// `inner`, whose close fails `deadline` after it began.
    pub fn new(inner: M, deadline: Duration) -> Self {
        Self {
            inner,
            deadline,
            expires: None,
        }
    }
}

impl<M> StreamMuxer for DeadlineMuxer<M>
where
    M: StreamMuxer + Unpin,
{
    type Substream = M::Substream;
    type Error = CloseDeadlineError<M::Error>;

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        self.get_mut()
            .inner
            .poll_inbound_unpin(cx)
            .map_err(CloseDeadlineError::Muxer)
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        self.get_mut()
            .inner
            .poll_outbound_unpin(cx)
            .map_err(CloseDeadlineError::Muxer)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if let Poll::Ready(closed) = this.inner.poll_close_unpin(cx) {
            return Poll::Ready(closed.map_err(CloseDeadlineError::Muxer));
        }
        let deadline = this.deadline;
        let expires = this
            .expires
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(deadline)));
        ready!(expires.as_mut().poll(cx));
        Poll::Ready(Err(CloseDeadlineError::Expired(deadline)))
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        self.get_mut()
            .inner
            .poll_unpin(cx)
            .map_err(CloseDeadlineError::Muxer)
    }
}
