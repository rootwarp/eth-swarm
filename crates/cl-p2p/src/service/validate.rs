//! The column hand-off to cl-chain: `ethswarm.chain.v1.GossipService/Validate`, fed by the
//! gossip capture tap.
//!
//! The ignore-all gossipsub reports every message IGNORE in the poll that delivers it, before
//! anything else sees it, and gives the capture tap a copy ([`crate::gossip::IgnoreAll`]). This
//! module sends the copies of the `data_column_sidecar_{subnet_id}` messages to cl-chain, which
//! stores its custody columns from them. The verdicts change nothing: each message was
//! reported IGNORE already, so no verdict can make it travel on. They are read for their fences
//! and counted.
//!
//! - **The tap** keeps only the `data_column_sidecar_*` topics ([`is_column_topic`]), so it
//!   holds at most [`crate::service::TAP_CAPACITY`] column sidecars, each within its topic's
//!   cap. When it is full, it drops and counts (it never slows the swarm).
//! - **The bridge** ([`bridge_tap`]): a thread of its own blocks on the tap, makes each column
//!   sidecar a gossip message ([`column_message`]: the topic's fork digest, the sidecar's slot,
//!   read without decoding, and its subnet) and passes it to a bounded queue of
//!   [`COLUMN_QUEUE`] messages. When the queue is full (cl-chain stalls or restarts), the bridge
//!   drops and counts the message: it never waits, so the tap behind it does not fill.
//! - **The batches** ([`Batcher`]): up to [`MAX_BATCH_MESSAGES`] messages or [`BATCH_WINDOW`]
//!   after the first one, whichever comes first, and at most [`MAX_BATCH_SSZ_BYTES`] of SSZ (a
//!   larger sidecar goes alone).
//! - **The stream** ([`hand_off_columns`]): our hello, then cl-chain's, compared in full and
//!   with its server generation ([`Link::open`]). Then fenced batches ([`Outstanding`]): each
//!   carries its `request_id` and the generation, its envelopes carry `seq` from 1, and its
//!   verdicts settle only through their fences. At most [`MAX_OUTSTANDING`] batches are open;
//!   one more is not sent. A batch with no verdicts by [`VALIDATE_DEADLINE`] fails locally as
//!   IGNORE, and keeps its place until its late verdicts come, which are dropped and counted.
//!   Once every place is held so, cl-chain holds the stream but answers nothing, and the stream
//!   fails. A verdict batch that breaks its fence fails the stream too. A stream that ends or
//!   fails is opened again after a wait (1 s, doubled up to 30 s), and its open batches fail as
//!   IGNORE.
//! - **The metric** `p2p_column_handoff_total{result}`: the column sidecars that cl-chain
//!   answered (`answered`), that failed as IGNORE at their deadline or with their stream
//!   (`ignored`), whose verdicts came after that and were dropped (`late`), that were not sent
//!   (`unsent`: no stream, too many open batches), and that the tap (`tap_dropped`) or the
//!   queue (`queue_dropped`) had no room for.

use crate::gossip::{CaptureReader, Captured};
use consensus_types::{forked, EthSpec};
use ethswarm_proto::chain as pb;
use ethswarm_proto::common::{Envelope, PayloadType, PeerId as WirePeerId, Verdict};
use ipc::fence::{FenceError, FencedRequest, Outstanding};
use ipc::frame::{Inbound, OutFrame, SeqCounter};
use ipc::hello::Generation;
use ipc::Link;
use p2p_wire::gossip::{GossipKind, GossipTopic};
use pb::gossip_service_client::GossipServiceClient;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tonic::transport::Channel;

/// The most messages in one batch: `ValidateBatch.messages`, as cl-chain caps it.
pub const MAX_BATCH_MESSAGES: usize = 256;

/// How long a batch waits for more messages after its first one (`ValidateRequest`: "up to
/// 256 messages or 2 ms, whichever first").
pub const BATCH_WINDOW: Duration = Duration::from_millis(2);

/// The SSZ bytes one batch carries at most \[est\]: well within the request frame that cl-chain
/// decodes (`MAX_GOSSIP_REQUEST_BYTES`, 12 MiB). One sidecar that is larger goes alone.
pub const MAX_BATCH_SSZ_BYTES: usize = 2 * 1024 * 1024;

/// How long a batch waits for its verdicts (`GossipService.Validate`: "missed deadline (default
/// 500 ms) => p2p applies VERDICT_IGNORE").
pub const VALIDATE_DEADLINE: Duration = Duration::from_millis(500);

/// Batches open on one stream at most \[est\]: a deadline's worth of batches at a high rate.
pub const MAX_OUTSTANDING: usize = 16;

/// Column sidecars that wait between the bridge and the stream at most \[est\]: a few slots of
/// the custody subnets' columns.
pub const COLUMN_QUEUE: usize = 1024;

/// The first wait before a stream is opened again.
const FIRST_BACKOFF: Duration = Duration::from_secs(1);

/// The longest wait before a stream is opened again.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// The thread name of the bridge.
pub const BRIDGE_THREAD: &str = "column-tap";

/// Whether `topic` is a `data_column_sidecar_{subnet_id}` topic: the topics the tap keeps.
#[must_use]
pub fn is_column_topic(topic: &str) -> bool {
    GossipTopic::parse(topic).is_ok_and(|t| matches!(t.kind, GossipKind::DataColumnSidecar { .. }))
}

/// The `data_column_sidecar_{subnet_id}` message of `captured`, as cl-chain takes it: its
/// envelope carries the topic's fork digest and the sidecar's slot, read without decoding
/// (`peek_slot`), and its `seq` is set when it is sent. `None` for another topic, a topic that
/// does not parse, or bytes that hold no slot.
#[must_use]
pub fn column_message<E: EthSpec>(captured: &Captured) -> Option<pb::GossipMessage> {
    let topic = GossipTopic::parse(&captured.topic).ok()?;
    let GossipKind::DataColumnSidecar { subnet_id } = topic.kind else {
        return None;
    };
    let slot = forked::DataColumnSidecar::<E>::peek_slot(&captured.data).ok()?;
    Some(pb::GossipMessage {
        message_id: captured.message_id.clone(),
        topic: pb::Topic::DataColumnSidecar as i32,
        subnet_id: u32::try_from(subnet_id).ok()?,
        propagation_source: Some(WirePeerId {
            id: captured.source.to_string(),
        }),
        payload: Some(Envelope {
            fork_digest: topic.fork_digest.to_vec(),
            slot,
            ssz: captured.data.clone(),
            payload_type: PayloadType::DataColumnSidecar as i32,
            ..Default::default()
        }),
        received_unix_ms: unix_ms(captured.recv_wall),
    })
}

/// Starts the bridge (see the module docs): a thread named [`BRIDGE_THREAD`] that reads `tap`
/// and passes its column sidecars ([`column_message`]) to `columns`, or drops and counts one
/// (`queue_dropped` in `metrics`) while `columns` is full. It ends once every tap of the queue
/// is gone or `columns` is closed.
///
/// # Errors
///
/// The thread could not be spawned.
pub fn bridge_tap<E: EthSpec>(
    tap: CaptureReader,
    columns: mpsc::Sender<pb::GossipMessage>,
    metrics: HandOffMetrics,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(BRIDGE_THREAD.into())
        .spawn(move || {
            while let Some(captured) = tap.recv() {
                let Some(message) = column_message::<E>(&captured) else {
                    continue;
                };
                match columns.try_send(message) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => metrics.add(QUEUE_DROPPED, 1),
                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
        })
}

/// One batch that fills up: the messages, the SSZ bytes they carry, and when the first came.
#[derive(Debug, Default)]
pub struct Batcher {
    messages: Vec<pb::GossipMessage>,
    bytes: usize,
    opened: Option<Instant>,
}

impl Batcher {
    /// Adds `message`, received at `now`. Returns a batch that is due because of it: the one
    /// before, if `message` does not fit in it, or this one, once it holds
    /// [`MAX_BATCH_MESSAGES`] messages or [`MAX_BATCH_SSZ_BYTES`].
    pub fn push(
        &mut self,
        message: pb::GossipMessage,
        now: Instant,
    ) -> Option<Vec<pb::GossipMessage>> {
        let size = message.payload.as_ref().map_or(0, |p| p.ssz.len());
        let earlier = if !self.messages.is_empty() && self.bytes + size > MAX_BATCH_SSZ_BYTES {
            self.take()
        } else {
            None
        };
        if self.messages.is_empty() {
            self.opened = Some(now);
        }
        self.messages.push(message);
        self.bytes += size;
        if earlier.is_some() {
            return earlier;
        }
        let full = self.messages.len() >= MAX_BATCH_MESSAGES || self.bytes >= MAX_BATCH_SSZ_BYTES;
        if full {
            self.take()
        } else {
            None
        }
    }

    /// When the batch is due by its window; `None` while it is empty.
    #[must_use]
    pub fn due_at(&self) -> Option<Instant> {
        self.opened.map(|opened| opened + BATCH_WINDOW)
    }

    /// Takes the batch, if it holds a message.
    pub fn take(&mut self) -> Option<Vec<pb::GossipMessage>> {
        self.opened = None;
        self.bytes = 0;
        (!self.messages.is_empty()).then(|| std::mem::take(&mut self.messages))
    }

    /// Messages in the batch now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// `p2p_column_handoff_total{result}` (see the module docs).
#[derive(Clone, Debug, Default)]
pub struct HandOffMetrics {
    handoff: Family<ResultLabel, Counter>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
struct ResultLabel {
    result: &'static str,
}

/// cl-chain answered the batch.
const ANSWERED: &str = "answered";
/// The batch failed as IGNORE: its deadline passed, or its stream was replaced.
const IGNORED: &str = "ignored";
/// The batch's verdicts came after it failed as IGNORE, and were dropped.
const LATE: &str = "late";
/// The batch was not sent.
const UNSENT: &str = "unsent";
/// The tap was full.
const TAP_DROPPED: &str = "tap_dropped";
/// The column queue was full.
const QUEUE_DROPPED: &str = "queue_dropped";

/// Every result, the label set of `p2p_column_handoff_total`.
const RESULTS: [&str; 6] = [ANSWERED, IGNORED, LATE, UNSENT, TAP_DROPPED, QUEUE_DROPPED];

impl HandOffMetrics {
    /// The family on `registry`, each result at 0.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self::default();
        for result in RESULTS {
            drop(metrics.handoff.get_or_create(&ResultLabel { result }));
        }
        registry.register(
            "p2p_column_handoff",
            "Column sidecars handed to cl-chain's Validate, by result: answered, ignored (no \
             verdict by the deadline, or the stream replaced), late (verdicts after that, \
             dropped), unsent, tap_dropped or queue_dropped (no room)",
            metrics.handoff.clone(),
        );
        metrics
    }

    /// The counter of `tap_dropped`, for the capture tap to count its drops on
    /// ([`crate::gossip::capture_tap_counted`]).
    #[must_use]
    pub fn tap_counter(&self) -> Counter {
        self.handoff
            .get_or_create(&ResultLabel {
                result: TAP_DROPPED,
            })
            .clone()
    }

    fn add(&self, result: &'static str, n: usize) {
        self.handoff
            .get_or_create(&ResultLabel { result })
            .inc_by(u64::try_from(n).unwrap_or(u64::MAX));
    }

    /// The count of `result` now.
    #[must_use]
    pub fn count(&self, result: &'static str) -> u64 {
        self.handoff.get_or_create(&ResultLabel { result }).get()
    }

    /// Column sidecars cl-chain answered.
    #[must_use]
    pub fn answered(&self) -> u64 {
        self.count(ANSWERED)
    }

    /// Column sidecars that failed as IGNORE.
    #[must_use]
    pub fn ignored(&self) -> u64 {
        self.count(IGNORED)
    }

    /// Column sidecars that were not sent.
    #[must_use]
    pub fn unsent(&self) -> u64 {
        self.count(UNSENT)
    }

    /// Column sidecars whose verdicts came late.
    #[must_use]
    pub fn late(&self) -> u64 {
        self.count(LATE)
    }

    /// Column sidecars the tap had no room for.
    #[must_use]
    pub fn tap_dropped(&self) -> u64 {
        self.count(TAP_DROPPED)
    }

    /// Column sidecars the column queue had no room for.
    #[must_use]
    pub fn queue_dropped(&self) -> u64 {
        self.count(QUEUE_DROPPED)
    }
}

/// The bounds of the hand-off: the constants above, apart from tests.
#[derive(Debug, Clone, Copy)]
pub struct HandOffLimits {
    /// [`VALIDATE_DEADLINE`].
    pub deadline: Duration,
    /// [`MAX_OUTSTANDING`].
    pub max_outstanding: usize,
    /// The first wait before a stream is opened again.
    pub first_backoff: Duration,
}

impl Default for HandOffLimits {
    fn default() -> Self {
        Self {
            deadline: VALIDATE_DEADLINE,
            max_outstanding: MAX_OUTSTANDING,
            first_backoff: FIRST_BACKOFF,
        }
    }
}

/// Hands the column sidecars of `columns` to cl-chain over `chain` (see the module docs) until
/// `stop` turns true or its sender goes, or `columns` closes. A stream that ends or fails is
/// opened again after a wait.
pub async fn hand_off_columns(
    chain: Channel,
    link: Link,
    mut columns: mpsc::Receiver<pb::GossipMessage>,
    metrics: HandOffMetrics,
    limits: HandOffLimits,
    mut stop: watch::Receiver<bool>,
) {
    let mut backoff = limits.first_backoff;
    loop {
        if *stop.borrow_and_update() {
            return;
        }
        let mut stream = OpenStream::new(&metrics, limits);
        let ended = tokio::select! {
            ended = stream.run(&chain, &link, &mut columns) => ended,
            _ = stop.changed() => Ended::Stopped,
        };
        stream.close();
        match ended {
            Ended::Stopped | Ended::Closed => return,
            Ended::Failed { why, answered } => {
                tracing::warn!(error = %why, "cl-chain's Validate stream failed");
                if answered {
                    backoff = limits.first_backoff;
                }
            }
        }
        // While no stream is open, the queue fills and then the tap drops.
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            _ = stop.changed() => return,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// How a stream ended.
enum Ended {
    /// The stop came.
    Stopped,
    /// The column queue closed: the bridge is gone.
    Closed,
    /// The stream ended or failed; whether cl-chain answered a batch on it first.
    Failed { why: String, answered: bool },
}

/// One batch sent and not settled: its id, its deadline and its message count.
struct Open {
    id: u64,
    deadline: Instant,
    messages: usize,
}

/// One `Validate` stream: its open batches, its counts.
struct OpenStream<'a> {
    metrics: &'a HandOffMetrics,
    limits: HandOffLimits,
    /// In the order sent, so in the order of their deadlines.
    open: VecDeque<Open>,
    outstanding: Option<Outstanding>,
    /// The batch that fills up; what it holds when the stream ends is not sent.
    batcher: Batcher,
    /// Batches past their deadline whose late verdicts have not come: each holds a place.
    expired: usize,
    answered: bool,
}

impl<'a> OpenStream<'a> {
    fn new(metrics: &'a HandOffMetrics, limits: HandOffLimits) -> Self {
        Self {
            metrics,
            limits,
            open: VecDeque::new(),
            outstanding: None,
            batcher: Batcher::default(),
            expired: 0,
            answered: false,
        }
    }

    fn failed(&self, why: impl Into<String>) -> Ended {
        Ended::Failed {
            why: why.into(),
            answered: self.answered,
        }
    }

    /// Opens the stream and runs it until it ends.
    async fn run(
        &mut self,
        chain: &Channel,
        link: &Link,
        columns: &mut mpsc::Receiver<pb::GossipMessage>,
    ) -> Ended {
        // The hello and every batch the table lets out fit, so a send never waits.
        let (requests, outbound) = mpsc::channel(self.limits.max_outstanding + 1);
        if requests
            .try_send(pb::ValidateRequest::hello(link.local()))
            .is_err()
        {
            return self.failed("the request queue is closed");
        }
        let responses = match GossipServiceClient::new(chain.clone())
            .validate(Frames(outbound))
            .await
        {
            Ok(responses) => responses.into_inner(),
            Err(status) => return self.failed(format!("Validate: {}", status.message())),
        };
        let mut guarded = match link.open(Inbound::from_server(responses)).await {
            Ok(guarded) => guarded,
            Err(e) => return self.failed(format!("Validate: {e}")),
        };
        let generation = match Generation::from_hello(guarded.peer()) {
            Ok(generation) => generation,
            Err(e) => return self.failed(format!("Validate: {e}")),
        };
        self.outstanding = Some(Outstanding::new(generation, self.limits.max_outstanding));
        let mut seq = SeqCounter::new();
        loop {
            let due = self.batcher.due_at();
            let deadline = self.open.front().map(|o| o.deadline);
            tokio::select! {
                message = columns.recv() => match message {
                    Some(message) => {
                        if let Some(batch) = self.batcher.push(message, Instant::now()) {
                            if let Err(e) = self.send(&requests, &mut seq, batch) {
                                return e;
                            }
                        }
                    }
                    None => return Ended::Closed,
                },
                () = sleep_until(due), if due.is_some() => {
                    if let Some(batch) = self.batcher.take() {
                        if let Err(e) = self.send(&requests, &mut seq, batch) {
                            return e;
                        }
                    }
                }
                () = sleep_until(deadline), if deadline.is_some() => {
                    if let Err(e) = self.expire_due() {
                        return e;
                    }
                }
                body = guarded.body() => match body {
                    Ok(Some(accepted)) => {
                        if let Err(e) = self.settle(link, &accepted.body) {
                            return e;
                        }
                    }
                    Ok(None) => return self.failed("cl-chain ended the stream"),
                    Err(e) => return self.failed(format!("Validate: {e}")),
                },
            }
        }
    }

    /// Sends `batch` with the next request id and envelope seqs, or counts it unsent.
    fn send(
        &mut self,
        requests: &mpsc::Sender<pb::ValidateRequest>,
        seq: &mut SeqCounter,
        batch: Vec<pb::GossipMessage>,
    ) -> Result<(), Ended> {
        let n = batch.len();
        // The place first: a batch that took its id and seqs must go out, or the stream breaks.
        let permit = match requests.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                self.metrics.add(UNSENT, n);
                return Ok(());
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                self.metrics.add(UNSENT, n);
                return Err(self.failed("the Validate stream is closed"));
            }
        };
        let Some(outstanding) = self.outstanding.as_mut() else {
            self.metrics.add(UNSENT, n);
            return Ok(());
        };
        let issued = outstanding.issue(|tag| {
            let messages = batch
                .into_iter()
                .map(|mut message| {
                    if let Some(payload) = message.payload.as_mut() {
                        payload.seq = seq.next_seq();
                    }
                    message
                })
                .collect();
            let body = pb::ValidateBatch {
                messages,
                request_id: tag.request_id,
                generation: tag.generation.get(),
            };
            let hashes = body.item_hashes();
            (body, hashes)
        });
        match issued {
            Ok((tag, body)) => {
                permit.send(pb::ValidateRequest::body(body));
                self.open.push_back(Open {
                    id: tag.request_id,
                    deadline: Instant::now() + self.limits.deadline,
                    messages: n,
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "a column batch not sent");
                self.metrics.add(UNSENT, n);
            }
        }
        Ok(())
    }

    /// Fails every open batch past its deadline as IGNORE. Fails the stream once every place
    /// of it is held by such a batch: cl-chain answers nothing on it.
    fn expire_due(&mut self) -> Result<(), Ended> {
        let now = Instant::now();
        while self.open.front().is_some_and(|o| o.deadline <= now) {
            let Some(open) = self.open.pop_front() else {
                break;
            };
            if self
                .outstanding
                .as_mut()
                .is_some_and(|outstanding| outstanding.expire(open.id))
            {
                self.expired += 1;
            }
            self.metrics.add(IGNORED, open.messages);
        }
        if self.expired >= self.limits.max_outstanding.max(1) {
            return Err(self.failed(format!(
                "cl-chain answered none of the last {} batches by their deadline",
                self.expired
            )));
        }
        Ok(())
    }

    /// Settles a verdict batch through its fences. A late one is dropped; one that breaks its
    /// fence fails the stream.
    fn settle(&mut self, link: &Link, verdicts: &pb::VerdictBatch) -> Result<(), Ended> {
        let Some(outstanding) = self.outstanding.as_mut() else {
            return Err(self.failed("verdicts before the stream opened"));
        };
        match outstanding.settle_body(verdicts) {
            Ok(id) => {
                let messages = self
                    .open
                    .iter()
                    .position(|o| o.id == id)
                    .and_then(|at| self.open.remove(at))
                    .map_or(0, |o| o.messages);
                self.metrics.add(ANSWERED, messages);
                self.answered = true;
                if let Some(v) = verdicts
                    .verdicts
                    .iter()
                    .find(|v| v.verdict != Verdict::Ignore as i32)
                {
                    tracing::warn!(
                        verdict = v.verdict,
                        reason = %v.reason,
                        "cl-chain answered a column with another verdict than IGNORE; the \
                         probe reported IGNORE to gossipsub already"
                    );
                }
                Ok(())
            }
            Err(FenceError::Late { request_id }) => {
                tracing::debug!(request_id, "late verdicts of a column batch: dropped");
                self.metrics.add(LATE, verdicts.verdicts.len());
                self.expired = self.expired.saturating_sub(1);
                Ok(())
            }
            Err(e) => {
                if let Some(err) = e.to_contract_error() {
                    link.record(&err);
                }
                Err(self.failed(format!("Validate verdicts: {e}")))
            }
        }
    }

    /// The stream is gone: every open batch fails as IGNORE, and the batch that was filling
    /// up is not sent.
    fn close(&mut self) {
        if let Some(outstanding) = self.outstanding.as_mut() {
            outstanding.close();
        }
        for open in self.open.drain(..) {
            self.metrics.add(IGNORED, open.messages);
        }
        if let Some(left) = self.batcher.take() {
            self.metrics.add(UNSENT, left.len());
        }
    }
}

/// The request frames of a stream, as tonic sends them: what the queue holds, until it closes.
struct Frames(mpsc::Receiver<pb::ValidateRequest>);

impl futures::Stream for Frames {
    type Item = pb::ValidateRequest;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

/// Sleeps until `at`; never returns for `None`.
async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Unix milliseconds of `at`, 0 before the epoch.
fn unix_ms(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests;
