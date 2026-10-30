//! One ordered worker per execution layer.
//!
//! Calls are run in `seq` order, one at a time, so a later `forkchoiceUpdated` cannot overtake
//! an earlier `newPayload`. Each connection has a generation ([`crate::client::Session::generation`]).
//! Reconnect bumps it before the capability re-check. A result that belongs to an earlier
//! generation is dropped and never applied.
//!
//! A call that was sent when its connection failed, timed out or was replaced resolves as an
//! error to its caller; it is not sent again, because the EL may already have applied it. The
//! connection is dropped, and the next call reconnects (capability check included) inside its
//! own deadline before it is sent, so one failure does not wedge the queue.
//!
//! The queue is bounded: [`Queue::call`] waits for room in a channel of [`QUEUE_DEPTH`] jobs
//! (backpressure), and at most [`QUEUE_DEPTH`] jobs wait for an earlier `seq`; past that a
//! call fails with [`CallError::Overloaded`].
//!
//! Every job has a deadline for being sent, including while it waits for an earlier `seq`. A
//! job is never sent after that deadline or after its caller has gone (the [`Queue::call`]
//! future was dropped); it is checked right before it is sent. Its `seq` is still used up, so
//! later jobs do not wait for it. Once a job is sent, the EL gets its full response timeout,
//! counted from the send: time spent queued never shortens it (execution-apis `common.md`).
//! Whether the caller gives up first or the worker sends first is settled by one
//! compare-and-swap on the job's [`Claim`], so a job is either answered unsent or sent.
//!
//! Gaps. A `seq` that will never be called (its request was rejected before reaching the
//! queue) should be given back with [`Queue::release`]; later jobs then run without waiting.
//! If a gap is never filled or released, it is skipped when any job waiting behind it reaches
//! its deadline: that job is answered [`CallError::Timeout`] without being sent, and the queue
//! advances to the lowest `seq` it holds. A missing `seq` that turns up after it was skipped
//! fails with [`CallError::Sequence`] and is not sent, so nothing reaches the EL out of order.

use crate::client::{CallError, Config, Session, StartError};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// Jobs waiting to be taken by the worker, and separately jobs waiting for an earlier `seq`.
/// Large enough for the ordering test's 100 calls with room to spare.
pub const QUEUE_DEPTH: usize = 256;

/// Who got to a job first: its caller giving up at the deadline, or the worker sending it.
#[derive(Clone, Default)]
struct Claim(Arc<AtomicU8>);

const PENDING: u8 = 0;
const SENT: u8 = 1;
const ABANDONED: u8 = 2;

impl Claim {
    /// The worker is about to send: false if the caller already gave up.
    fn send(&self) -> bool {
        self.swap_from_pending(SENT)
    }

    /// The caller reached its deadline: false if the request is already on the wire.
    fn abandon(&self) -> bool {
        self.swap_from_pending(ABANDONED)
    }

    fn swap_from_pending(&self, to: u8) -> bool {
        self.0
            .compare_exchange(PENDING, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

struct Job {
    seq: u64,
    method: String,
    params: Value,
    /// Last moment the job may be sent.
    deadline: Instant,
    /// The EL's response timeout, counted from the send.
    timeout: Duration,
    claim: Claim,
    reply: oneshot::Sender<Result<Value, CallError>>,
}

/// What waits in the buffer for an earlier `seq`.
enum Entry {
    /// A call still to run.
    Job(Job),
    /// A `seq` given back by [`Queue::release`]; nothing is sent for it.
    Released,
}

enum Msg {
    Job(Job),
    Release(u64),
}

struct Immediate {
    method: String,
    params: Value,
    deadline: Instant,
    timeout: Duration,
    claim: Claim,
    reply: oneshot::Sender<Result<Value, CallError>>,
}

/// The ordered engine queue.
#[derive(Clone)]
pub struct Queue {
    tx: mpsc::Sender<Msg>,
    immediate: mpsc::Sender<Immediate>,
    session: Session,
}

impl Queue {
    /// Connects, checks capabilities, and starts the worker at `initial_seq`.
    pub async fn connect(config: Config, initial_seq: u64) -> Result<Self, StartError> {
        let session = Session::connect(config).await?;
        Ok(Self::spawn(session, initial_seq))
    }

    /// A worker in front of an already connected session.
    #[must_use]
    pub fn spawn(session: Session, initial_seq: u64) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
        let (immediate_tx, immediate_rx) = mpsc::channel(8);
        let worker = session.clone();
        tokio::spawn(async move { run(rx, immediate_rx, worker, initial_seq).await });
        Self {
            tx,
            immediate: immediate_tx,
            session,
        }
    }

    /// Runs `method` when every lower `seq` since the queue's start has finished, been
    /// released, or been skipped (see the module docs). A job not sent within `timeout` is
    /// answered [`CallError::Timeout`] and never sent. A sent job gets the full `timeout` for
    /// the EL's response, counted from the send, so the whole call can take up to twice
    /// `timeout`. Dropping the returned future cancels the job if it has not been sent yet.
    pub async fn call(
        &self,
        seq: u64,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, CallError> {
        let deadline = Instant::now() + timeout;
        let (reply, rx) = oneshot::channel();
        let claim = Claim::default();
        let job = Job {
            seq,
            method: method.to_owned(),
            params,
            deadline,
            timeout,
            claim: claim.clone(),
            reply,
        };
        match tokio::time::timeout_at(deadline.into(), self.tx.send(Msg::Job(job))).await {
            // The job never reached the worker, so it cannot be sent.
            Err(_) => return Err(CallError::Timeout),
            Ok(Err(_)) => return Err(CallError::Stopped),
            Ok(Ok(())) => {}
        }
        await_reply(rx, deadline, &claim).await
    }

    /// Gives back `seq` without running anything for it, so later calls do not wait for it.
    /// Call it when a request was refused before [`Queue::call`]. A `seq` that has already
    /// run, been released or been skipped is ignored; a later `call` with a released `seq`
    /// fails with [`CallError::Sequence`].
    pub async fn release(&self, seq: u64) -> Result<(), CallError> {
        self.tx
            .send(Msg::Release(seq))
            .await
            .map_err(|_| CallError::Stopped)
    }

    /// Runs `method` when the worker is between ordered calls. It does not take a `seq` and
    /// does not run while an ordered call is in flight.
    pub async fn call_now(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, CallError> {
        let deadline = Instant::now() + timeout;
        let (reply, rx) = oneshot::channel();
        let claim = Claim::default();
        let job = Immediate {
            method: method.to_owned(),
            params,
            deadline,
            timeout,
            claim: claim.clone(),
            reply,
        };
        match tokio::time::timeout_at(deadline.into(), self.immediate.send(job)).await {
            Err(_) => return Err(CallError::Timeout),
            Ok(Err(_)) => return Err(CallError::Stopped),
            Ok(Ok(())) => {}
        }
        await_reply(rx, deadline, &claim).await
    }

    /// Bumps the connection generation and re-checks capabilities before returning. Safe to
    /// call while the worker runs and concurrently with other reconnects
    /// ([`Session::reconnect`]).
    pub async fn reconnect(&self) -> Result<(), StartError> {
        self.session.reconnect().await
    }

    /// The connection generation the worker stamps on calls it sends from now.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.session.generation()
    }

    /// Results dropped because their connection generation was no longer current.
    #[must_use]
    pub fn late_dropped(&self) -> u64 {
        self.session.late_dropped()
    }

    /// The session, for tests that read the same counters.
    #[must_use]
    pub fn session(&self) -> &Session {
        &self.session
    }
}

/// Waits for the worker's answer. At `deadline`, a job that has not been sent is abandoned
/// (the worker will not send it); one already sent keeps waiting for its response, which the
/// worker bounds by the job's response timeout.
async fn await_reply(
    mut rx: oneshot::Receiver<Result<Value, CallError>>,
    deadline: Instant,
    claim: &Claim,
) -> Result<Value, CallError> {
    tokio::select! {
        result = &mut rx => return result.map_err(|_| CallError::Stopped)?,
        () = tokio::time::sleep_until(deadline.into()) => {}
    }
    if claim.abandon() {
        return Err(CallError::Timeout);
    }
    rx.await.map_err(|_| CallError::Stopped)?
}

async fn run(
    mut rx: mpsc::Receiver<Msg>,
    mut immediate: mpsc::Receiver<Immediate>,
    session: Session,
    mut next: u64,
) {
    let mut buffered: BTreeMap<u64, Entry> = BTreeMap::new();
    let mut immediate_open = true;
    loop {
        if let Some(entry) = buffered.remove(&next) {
            if let Entry::Job(job) = entry {
                execute(&session, job).await;
            }
            next = next.saturating_add(1);
            continue;
        }
        // Waiting for a gap: wake at the earliest deadline of a job behind it.
        let earliest = buffered
            .values()
            .filter_map(|entry| match entry {
                Entry::Job(job) => Some(job.deadline),
                Entry::Released => None,
            })
            .min();
        tokio::select! {
            biased;
            msg = rx.recv() => {
                let Some(msg) = msg else {
                    break;
                };
                match msg {
                    Msg::Release(seq) => {
                        if seq == next {
                            next = next.saturating_add(1);
                        } else if seq > next
                            && !buffered.contains_key(&seq)
                            && buffered.len() < QUEUE_DEPTH
                        {
                            buffered.insert(seq, Entry::Released);
                        }
                    }
                    Msg::Job(job) => {
                        if job.seq < next || buffered.contains_key(&job.seq) {
                            let _ = job.reply.send(Err(CallError::Sequence));
                        } else if job.seq == next {
                            execute(&session, job).await;
                            next = next.saturating_add(1);
                        } else if buffered.len() >= QUEUE_DEPTH {
                            let _ = job.reply.send(Err(CallError::Overloaded));
                        } else {
                            buffered.insert(job.seq, Entry::Job(job));
                        }
                    }
                }
            }
            now = immediate.recv(), if immediate_open => {
                let Some(now) = now else {
                    immediate_open = false;
                    continue;
                };
                if now.reply.is_closed() {
                    continue;
                }
                let result = dispatch_at(
                    &session,
                    &now.method,
                    &now.params,
                    now.deadline,
                    now.timeout,
                    &now.claim,
                    || now.reply.is_closed(),
                )
                .await;
                let _ = now.reply.send(result);
            }
            () = sleep_until(earliest), if earliest.is_some() => {
                // A job waited behind the gap until its deadline. Answer every expired job
                // (its `seq` stays used up, so nothing is sent for it), then skip the gap:
                // continue from the lowest `seq` held.
                let now = Instant::now();
                for entry in buffered.values_mut() {
                    if matches!(entry, Entry::Job(job) if job.deadline <= now) {
                        if let Entry::Job(job) = std::mem::replace(entry, Entry::Released) {
                            let _ = job.reply.send(Err(CallError::Timeout));
                        }
                    }
                }
                if let Some(&lowest) = buffered.keys().next() {
                    tracing::warn!(from = next, to = lowest, "engine queue skipped a seq gap");
                    next = lowest;
                }
            }
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline.into()).await;
    }
}

async fn execute(session: &Session, job: Job) {
    // The caller gave up: send nothing.
    if job.reply.is_closed() {
        return;
    }
    let result = dispatch_at(
        session,
        &job.method,
        &job.params,
        job.deadline,
        job.timeout,
        &job.claim,
        || job.reply.is_closed(),
    )
    .await;
    let _ = job.reply.send(result);
}

async fn dispatch_at(
    session: &Session,
    method: &str,
    params: &Value,
    deadline: Instant,
    timeout: Duration,
    claim: &Claim,
    cancelled: impl Fn() -> bool,
) -> Result<Value, CallError> {
    if Instant::now() >= deadline {
        return Err(CallError::Timeout);
    }
    // Nothing has been sent for this call yet, so reconnecting first is safe. The reconnect
    // (generation bump, then the capability check) is bounded by this call's deadline.
    if !session.is_connected() {
        match tokio::time::timeout_at(deadline.into(), session.reconnect()).await {
            Err(_) => return Err(CallError::Timeout),
            Ok(Err(err)) => return Err(err.into()),
            Ok(Ok(())) => {}
        }
    }
    // The reconnect may have taken a while: check again right before sending, and claim the
    // job so its caller can no longer abandon it.
    if cancelled() || Instant::now() >= deadline || !claim.send() {
        return Err(CallError::Timeout);
    }
    // Sent at most once, with the full response timeout from now: a failure after this point
    // is the caller's result.
    session.call(method, params, timeout).await
}
