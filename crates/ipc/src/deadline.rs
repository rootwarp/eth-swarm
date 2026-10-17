//! A client's calls over one fenced stream: deadlines, reconnects and late results.
//!
//! [`Calls`] wraps the stream's [`Outstanding`] table. [`Calls::start`] files a request and
//! returns its [`Pending`] result; the stream's reader hands every response to
//! [`Calls::deliver`] (or [`Calls::deliver_body`]), which settles it through its fences and
//! completes the call. A fence violation is returned as `ERROR_CODE_CONTRACT_VIOLATION` (the
//! reader fails the stream with it) and never completes a call.
//!
//! Every call fails locally as IGNORE ([`Ignored`], never ACCEPT) when its deadline passes
//! ([`Pending::wait_until`]) or when the client replaces the stream ([`Calls::close`],
//! [`Calls::reconnect`], which also starts the new stream's table with the new server
//! generation). A result that arrives for such a call later is late: [`Calls::deliver`] drops it
//! and counts it in [`FenceMetrics`], which the tables of successive streams share.
//!
//! Unary links (`engine.v1`) exchange no hello, so there is no server generation to echo. The
//! client fences their calls the same way, locally: a [`Calls`] per connection with a generation
//! it draws itself ([`Generation::random`]) at every (re)connect, and a call's result is
//! delivered with the fence of its own request (`Fence::new(tag, 0, hash)`) when the RPC
//! returns. A call still running when the connection is replaced has already failed as IGNORE,
//! and its result is dropped as late.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ethswarm_proto::common::Verdict;
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::error::ContractError;
use crate::fence::{Fence, FenceError, FencedResult, ItemHash, Outstanding, RequestTag};
use crate::hello::Generation;

/// Why a call ended without a result. Both are IGNORE, never ACCEPT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Ignored {
    /// Its deadline passed.
    #[error("deadline passed before the result")]
    Deadline,
    /// The stream was replaced (reconnect) or failed before the result.
    #[error("stream replaced before the result")]
    Reconnect,
}

impl Ignored {
    /// The verdict a call that ended this way yields.
    #[must_use]
    pub fn verdict(self) -> Verdict {
        Verdict::Ignore
    }
}

/// What [`Calls::deliver`] did with a response that passed (or was exempt from) the checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// It settled its request and completed the call.
    Accepted,
    /// Its call had already failed as IGNORE: dropped and counted.
    LateDropped,
}

/// Fencing counters, shared by the successive streams of one link.
#[derive(Debug, Default)]
pub struct FenceMetrics {
    late_dropped: AtomicU64,
    violations: AtomicU64,
    ignored: AtomicU64,
}

/// A point-in-time copy of [`FenceMetrics`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FenceCounts {
    /// Late results dropped (their call had failed as IGNORE).
    pub late_dropped: u64,
    /// Responses refused as fence violations.
    pub violations: u64,
    /// Calls failed locally as IGNORE (deadline or reconnect).
    pub ignored: u64,
}

impl FenceMetrics {
    #[must_use]
    pub fn counts(&self) -> FenceCounts {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        FenceCounts {
            late_dropped: get(&self.late_dropped),
            violations: get(&self.violations),
            ignored: get(&self.ignored),
        }
    }

    fn bump(counter: &AtomicU64, by: u64) {
        counter.fetch_add(by, Ordering::Relaxed);
    }
}

/// A delivered result and when it was delivered, judged against the waiter's deadline.
type Delivered<T> = (T, Instant);

struct State<T> {
    outstanding: Outstanding,
    waiters: HashMap<u64, oneshot::Sender<Delivered<T>>>,
}

type Shared<T> = Arc<Mutex<State<T>>>;

fn lock<T>(shared: &Shared<T>) -> std::sync::MutexGuard<'_, State<T>> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The calls of one stream. Cloning shares them.
pub struct Calls<T> {
    shared: Shared<T>,
    metrics: Arc<FenceMetrics>,
    capacity: usize,
}

impl<T> Clone for Calls<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            metrics: Arc::clone(&self.metrics),
            capacity: self.capacity,
        }
    }
}

impl<T> std::fmt::Debug for Calls<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Calls")
            .field("outstanding", &lock(&self.shared).outstanding)
            .field("metrics", &self.metrics.counts())
            .finish_non_exhaustive()
    }
}

impl<T> Calls<T> {
    /// The calls of a stream whose server hello announced `generation`, with at most
    /// `capacity` requests pending (see [`Outstanding::new`]).
    #[must_use]
    pub fn new(generation: Generation, capacity: usize) -> Self {
        Self::with_metrics(generation, capacity, Arc::default())
    }

    /// [`Calls::new`] counting into `metrics`.
    #[must_use]
    pub fn with_metrics(
        generation: Generation,
        capacity: usize,
        metrics: Arc<FenceMetrics>,
    ) -> Self {
        Self {
            shared: Arc::new(Mutex::new(State {
                outstanding: Outstanding::new(generation, capacity),
                waiters: HashMap::new(),
            })),
            metrics,
            capacity,
        }
    }

    #[must_use]
    pub fn generation(&self) -> Generation {
        lock(&self.shared).outstanding.generation()
    }

    #[must_use]
    pub fn metrics(&self) -> &Arc<FenceMetrics> {
        &self.metrics
    }

    /// Calls waiting for their result.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        lock(&self.shared).outstanding.len()
    }

    /// Files the next request ([`Outstanding::issue`]): `build` makes it for its tag and returns
    /// it with its item hashes. Send the returned request, then wait on the [`Pending`].
    pub fn start<R>(
        &self,
        build: impl FnOnce(RequestTag) -> (R, Vec<ItemHash>),
    ) -> Result<(R, Pending<T>), ContractError> {
        let mut state = lock(&self.shared);
        let (tag, request) = state.outstanding.issue(build)?;
        let (tx, rx) = oneshot::channel();
        state.waiters.insert(tag.request_id, tx);
        Ok((
            request,
            Pending {
                tag,
                rx,
                shared: Arc::clone(&self.shared),
                metrics: Arc::clone(&self.metrics),
            },
        ))
    }

    /// Settles a response whose results carry `fences` and completes its call with `result`.
    /// A late response is dropped and counted; a fence violation is counted and returned as
    /// `ERROR_CODE_CONTRACT_VIOLATION`, and `result` is dropped.
    ///
    /// The waiter judges the delivery time against its own deadline: a result delivered after
    /// it is late there ([`Pending::wait_until`]), even if the waiter is polled only later.
    pub fn deliver(&self, fences: &[Fence], result: T) -> Result<Delivery, ContractError> {
        let mut state = lock(&self.shared);
        let settled = state.outstanding.settle(fences);
        self.complete(&mut state, settled, result)
    }

    /// [`Calls::deliver`] for a response body that carries its own fences. On a replaced
    /// stream it is late before its fences are read ([`Outstanding::settle_body`]).
    pub fn deliver_body(&self, body: T) -> Result<Delivery, ContractError>
    where
        T: FencedResult,
    {
        let mut state = lock(&self.shared);
        let settled = state.outstanding.settle_body(&body);
        self.complete(&mut state, settled, body)
    }

    fn complete(
        &self,
        state: &mut State<T>,
        settled: Result<u64, FenceError>,
        result: T,
    ) -> Result<Delivery, ContractError> {
        match settled {
            Ok(request_id) => {
                if let Some(waiter) = state.waiters.remove(&request_id) {
                    // A waiter that gave up has nothing left to complete.
                    let _ = waiter.send((result, Instant::now()));
                }
                Ok(Delivery::Accepted)
            }
            Err(e) => self.refused(&e),
        }
    }

    fn refused(&self, e: &FenceError) -> Result<Delivery, ContractError> {
        match e.to_contract_error() {
            None => {
                FenceMetrics::bump(&self.metrics.late_dropped, 1);
                tracing::debug!(reason = %e, "late result dropped");
                Ok(Delivery::LateDropped)
            }
            Some(err) => {
                FenceMetrics::bump(&self.metrics.violations, 1);
                tracing::warn!(detail = err.detail(), "fence violation");
                Err(err)
            }
        }
    }

    /// The stream was replaced or failed: every outstanding call ends as
    /// [`Ignored::Reconnect`], and every result that still arrives on it is late. Returns the
    /// number of calls failed.
    pub fn close(&self) -> usize {
        let mut state = lock(&self.shared);
        let failed = state.outstanding.close().len();
        state.waiters.clear();
        FenceMetrics::bump(&self.metrics.ignored, failed as u64);
        failed
    }

    /// Closes this stream ([`Calls::close`]) and returns the calls of the new one, whose server
    /// hello announced `generation`, with the same capacity and shared metrics.
    #[must_use]
    pub fn reconnect(&self, generation: Generation) -> Self {
        self.close();
        Self::with_metrics(generation, self.capacity, Arc::clone(&self.metrics))
    }
}

/// One call's result, still to come.
pub struct Pending<T> {
    tag: RequestTag,
    rx: oneshot::Receiver<Delivered<T>>,
    shared: Shared<T>,
    metrics: Arc<FenceMetrics>,
}

impl<T> std::fmt::Debug for Pending<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl<T> Pending<T> {
    /// The tag the request was sent with.
    #[must_use]
    pub fn tag(&self) -> RequestTag {
        self.tag
    }

    /// [`Pending::wait_until`] `timeout` from now.
    pub async fn wait(self, timeout: Duration) -> Result<T, Ignored> {
        self.wait_until(Instant::now() + timeout).await
    }

    /// The result, or IGNORE once `deadline` passes (the request then expires: a result that
    /// comes later is late) or the stream is replaced. A result delivered at or after
    /// `deadline` is late too, even when this waiter is polled only afterwards: it is dropped
    /// and counted once, and the call is IGNORE.
    pub async fn wait_until(mut self, deadline: Instant) -> Result<T, Ignored> {
        let delivered = tokio::select! {
            biased;
            delivered = &mut self.rx => delivered,
            () = tokio::time::sleep_until(deadline) => return self.expire(deadline),
        };
        self.judge(delivered.map_err(|_| Ignored::Reconnect)?, deadline)
    }

    fn expire(mut self, deadline: Instant) -> Result<T, Ignored> {
        let mut state = lock(&self.shared);
        let id = self.tag.request_id;
        if state.outstanding.expire(id) {
            state.waiters.remove(&id);
            FenceMetrics::bump(&self.metrics.ignored, 1);
            return Err(Ignored::Deadline);
        }
        drop(state);
        // Settled just before the deadline check, or the stream was replaced meanwhile.
        let delivered = self.rx.try_recv().map_err(|_| Ignored::Reconnect)?;
        self.judge(delivered, deadline)
    }

    /// A settled result counts only if it was delivered before `deadline`.
    fn judge(&self, (result, at): Delivered<T>, deadline: Instant) -> Result<T, Ignored> {
        if at < deadline {
            return Ok(result);
        }
        FenceMetrics::bump(&self.metrics.late_dropped, 1);
        FenceMetrics::bump(&self.metrics.ignored, 1);
        tracing::debug!(
            request_id = self.tag.request_id,
            "result delivered after its deadline"
        );
        Err(Ignored::Deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fence::item_hash;
    use ethswarm_proto::common::{ErrorCode, Verdict};

    fn generation(g: u64) -> Generation {
        Generation::new(g).unwrap()
    }

    fn calls() -> Calls<&'static str> {
        Calls::new(generation(11), 8)
    }

    /// Starts a one-item call and returns its pending result and the fence that answers it.
    fn start(c: &Calls<&'static str>) -> (Pending<&'static str>, Fence) {
        let ((), pending) = c.start(|_| ((), vec![item_hash(b"item")])).unwrap();
        let fence = Fence::new(pending.tag(), 0, item_hash(b"item"));
        (pending, fence)
    }

    #[tokio::test]
    async fn a_fenced_result_completes_its_call() {
        let c = calls();
        let (pending, fence) = start(&c);
        assert_eq!(c.outstanding(), 1);
        assert_eq!(c.deliver(&[fence], "verdict"), Ok(Delivery::Accepted));
        assert_eq!(pending.wait(Duration::from_secs(5)).await, Ok("verdict"));
        assert_eq!(c.outstanding(), 0);
        assert_eq!(c.metrics().counts(), FenceCounts::default());
    }

    #[tokio::test]
    async fn a_violation_fails_at_the_seam_and_never_completes_the_call() {
        let c = calls();
        let (pending, fence) = start(&c);
        let stale = Fence {
            generation: 12,
            ..fence
        };
        let err = c.deliver(&[stale], "forged").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert_eq!(c.metrics().counts().violations, 1);
        // The client fails the stream; the call then ends as IGNORE, never with the forgery.
        assert_eq!(c.close(), 1);
        let ignored = pending.wait(Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(ignored, Ignored::Reconnect);
        assert_eq!(ignored.verdict(), Verdict::Ignore);
        assert_eq!(c.metrics().counts().ignored, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_fails_the_call_as_ignore_and_the_late_result_is_counted() {
        let c = calls();
        let (pending, fence) = start(&c);
        let ignored = pending.wait(Duration::from_millis(50)).await.unwrap_err();
        assert_eq!(ignored, Ignored::Deadline);
        assert_eq!(c.outstanding(), 0);
        assert_eq!(c.deliver(&[fence], "late"), Ok(Delivery::LateDropped));
        let counts = c.metrics().counts();
        assert_eq!(
            (counts.late_dropped, counts.ignored, counts.violations),
            (1, 1, 0)
        );
        // A second copy is a duplicate.
        assert_eq!(
            c.deliver(&[fence], "again").unwrap_err().code(),
            ErrorCode::ContractViolation
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_result_that_beats_the_deadline_check_is_still_returned() {
        let c = calls();
        let (pending, fence) = start(&c);
        let deadline = Instant::now() + Duration::from_millis(10);
        c.deliver(&[fence], "just in time").unwrap();
        tokio::time::advance(Duration::from_millis(20)).await;
        assert_eq!(pending.wait_until(deadline).await, Ok("just in time"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_result_delivered_after_the_deadline_is_late_even_if_the_waiter_polls_later() {
        let c = calls();
        let (pending, fence) = start(&c);
        let deadline = Instant::now() + Duration::from_millis(10);
        tokio::time::advance(Duration::from_millis(20)).await;
        // Delivered past the deadline, before the waiter is polled at all.
        c.deliver(&[fence], "too late").unwrap();
        assert_eq!(pending.wait_until(deadline).await, Err(Ignored::Deadline));
        let counts = c.metrics().counts();
        assert_eq!(
            (counts.late_dropped, counts.ignored, counts.violations),
            (1, 1, 0)
        );
    }

    #[test]
    fn anything_on_a_replaced_stream_is_late_even_a_malformed_fence() {
        use ethswarm_proto::verify::{BlsResult, VerifyBlsResponseBody};
        let c: Calls<VerifyBlsResponseBody> = Calls::new(generation(3), 4);
        c.close();
        let bodies = [
            // No fence at all, no results, and results of two requests.
            VerifyBlsResponseBody {
                request_id: 1,
                results: vec![BlsResult::default()],
            },
            VerifyBlsResponseBody {
                request_id: 1,
                results: Vec::new(),
            },
        ];
        for body in bodies {
            assert_eq!(c.deliver_body(body), Ok(Delivery::LateDropped));
        }
        let counts = c.metrics().counts();
        assert_eq!((counts.late_dropped, counts.violations), (2, 0));
    }

    #[tokio::test]
    async fn a_body_whose_outer_id_is_not_its_fences_is_a_violation() {
        use crate::fence::FencedRequest;
        use ethswarm_proto::verify::{BlsSet, VerifyBlsRequestBody, VerifyBlsResponseBody};
        let c: Calls<VerifyBlsResponseBody> = Calls::new(generation(3), 4);
        let (request, pending) = c
            .start(|tag| {
                let r = VerifyBlsRequestBody {
                    request_id: tag.request_id,
                    generation: tag.generation.get(),
                    sets: vec![BlsSet::default()],
                    ..Default::default()
                };
                let h = r.item_hashes();
                (r, h)
            })
            .unwrap();
        let mut body = VerifyBlsResponseBody {
            request_id: 99,
            results: vec![Default::default()],
        };
        body.stamp(&request.result_fences());
        let err = c.deliver_body(body).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert_eq!(c.outstanding(), 1, "nothing settled");
        drop(pending);
    }

    #[tokio::test]
    async fn reconnect_fails_every_call_and_old_results_are_late() {
        let c = calls();
        let (first, f1) = start(&c);
        let (second, f2) = start(&c);
        let next = c.reconnect(generation(12));
        assert_eq!(next.generation(), generation(12));
        assert_eq!(
            first.wait(Duration::from_secs(5)).await,
            Err(Ignored::Reconnect)
        );
        assert_eq!(
            second.wait(Duration::from_secs(5)).await,
            Err(Ignored::Reconnect)
        );
        // Late results of the old stream are dropped and counted, on the shared metrics.
        assert_eq!(c.deliver(&[f1], "late"), Ok(Delivery::LateDropped));
        assert_eq!(c.deliver(&[f2], "late"), Ok(Delivery::LateDropped));
        assert_eq!(next.metrics().counts().late_dropped, 2);
        assert_eq!(next.metrics().counts().ignored, 2);
        // The old stream takes no new calls; the new one does, from id 1.
        assert_eq!(
            c.start(|_| ((), vec![item_hash(b"x")])).unwrap_err().code(),
            ErrorCode::ResourceUnavailable
        );
        let (pending, fence) = start(&next);
        assert_eq!(pending.tag().request_id, 1);
        // An old-generation result for the new stream's id is stale: a violation.
        let old = Fence {
            generation: 11,
            ..fence
        };
        assert_eq!(
            next.deliver(&[old], "replayed").unwrap_err().code(),
            ErrorCode::ContractViolation
        );
        assert_eq!(next.deliver(&[fence], "fresh"), Ok(Delivery::Accepted));
        assert_eq!(pending.wait(Duration::from_secs(5)).await, Ok("fresh"));
    }

    #[tokio::test]
    async fn bodies_are_delivered_through_their_fences() {
        use crate::fence::FencedRequest;
        use ethswarm_proto::verify::{BlsSet, VerifyBlsRequestBody, VerifyBlsResponseBody};
        let c: Calls<VerifyBlsResponseBody> = Calls::new(generation(3), 4);
        let (request, pending) = c
            .start(|tag| {
                let r = VerifyBlsRequestBody {
                    request_id: tag.request_id,
                    generation: tag.generation.get(),
                    sets: vec![BlsSet::default()],
                    ..Default::default()
                };
                let h = r.item_hashes();
                (r, h)
            })
            .unwrap();
        let unfenced = VerifyBlsResponseBody {
            request_id: 1,
            results: vec![Default::default()],
        };
        let err = c.deliver_body(unfenced.clone()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        let mut reply = unfenced;
        reply.stamp(&request.result_fences());
        assert_eq!(c.deliver_body(reply.clone()), Ok(Delivery::Accepted));
        assert_eq!(pending.wait(Duration::from_secs(5)).await, Ok(reply));
    }

    #[tokio::test]
    async fn a_dropped_waiter_does_not_fail_delivery() {
        let c = calls();
        let (pending, fence) = start(&c);
        drop(pending);
        assert_eq!(c.deliver(&[fence], "nobody waits"), Ok(Delivery::Accepted));
    }

    #[test]
    fn capacity_overload_is_local_and_ignorable() {
        let c: Calls<()> = Calls::new(generation(1), 1);
        let _held = c.start(|_| ((), vec![item_hash(b"a")])).unwrap();
        let err = c.start(|_| ((), vec![item_hash(b"b")])).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Overloaded);
    }
}
