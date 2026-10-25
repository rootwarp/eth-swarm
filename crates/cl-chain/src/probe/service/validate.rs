//! `GossipService/Validate` in probe mode: cl-p2p hands over the column sidecars that its
//! gossipsub captured, and cl-chain stores its custody columns from them.
//!
//! The probe has no state transition, so it validates nothing: every verdict is IGNORE, never
//! ACCEPT and never REJECT. cl-p2p reports every message IGNORE to gossipsub before it hands it
//! over, so no verdict can make a message travel on. One stream goes like this:
//!
//! 1. **The hellos.** cl-p2p's hello is checked against ours ([`Link::open`]). Then ours goes
//!    out with a fresh server generation for the stream ([`stream_hello`]).
//! 2. **Each batch.** The contract layer checks the frame, `Envelope.seq`, and the payload type
//!    and fork digest of each envelope ([`ipc::link::Guarded::body`]). Then the batch must hold
//!    1 to [`MAX_BATCH_MESSAGES`] messages, a `request_id` above the one before it, and the
//!    stream's generation ([`check_request`]). A topic of `TOPIC_UNSPECIFIED` is a contract
//!    violation too. Each of these fails the stream with `ERROR_CODE_CONTRACT_VIOLATION`, and
//!    nothing of the batch is handed over.
//! 3. **Each message**, in order:
//!    - an envelope that the contract layer dropped (an unknown payload type, or a fork digest
//!      that is not the digest of its slot's epoch): IGNORE, never decoded;
//!    - an unknown topic, a topic other than `data_column_sidecar`, or a payload that is not a
//!      `DataColumnSidecar`: IGNORE, never decoded;
//!    - a column sidecar: handed to the store ([`ColumnHandOff`]), which decodes it by the fork
//!      of its slot; IGNORE.
//! 4. **The verdicts.** One [`pb::GossipVerdict`] per message, in order, each stamped with the
//!    fence of its message ([`FencedRequest::result_fences`]).
//!
//! The stream ends with `UNAVAILABLE` when cl-chain stops, as `WatchSubscriptions` does, and ends
//! when cl-p2p closes its side.

use ethswarm_proto::chain as pb;
use ethswarm_proto::common::{Envelope, PayloadType, Verdict};
use ipc::fence::{check_request, FencedRequest, FencedResult};
use ipc::frame::{Inbound, OutFrame};
use ipc::hello::stream_hello;
use ipc::{ContractError, Link};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit};
use tonic::{Status, Streaming};

/// The most messages one batch may hold (`ValidateBatch.messages`).
pub const MAX_BATCH_MESSAGES: usize = 256;

/// Verdict batches queued for cl-p2p on one stream.
const VERDICT_BUFFER: usize = 8;

/// One column sidecar of a batch, as its gossip message names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipColumnBytes<'a> {
    /// The fork digest of its topic, which the envelope carries.
    pub fork_digest: [u8; 4],
    /// The slot that its envelope names.
    pub slot: u64,
    /// The subnet of its `data_column_sidecar_{subnet_id}` topic.
    pub subnet_id: u64,
    /// The sidecar's SSZ.
    pub ssz: &'a [u8],
}

/// What happened to a column sidecar that [`ColumnHandOff::hand_over`] took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandOff {
    /// It was decoded and given to the store, which checks it against its storage contract.
    Stored,
    /// It was dropped before the store, for this reason.
    Dropped(&'static str),
}

impl HandOff {
    /// The reason of an IGNORE verdict for this outcome.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Stored => "probe: IGNORE: handed to the column store",
            Self::Dropped(why) => why,
        }
    }
}

/// Where `Validate` hands the gossip column sidecars: the column store of probe mode.
pub trait ColumnHandOff: Send + Sync {
    /// Takes one column sidecar. The implementation must drop a sidecar whose own slot is not
    /// its envelope's, or whose fork digest is not the digest of its slot's epoch, without
    /// decoding it, and must decode the rest by the fork of their slot.
    fn hand_over(&self, column: GossipColumnBytes<'_>) -> HandOff;
}

/// The reason of an IGNORE verdict for a message that the contract layer dropped.
const DROPPED: &str = "probe: IGNORE: the envelope was dropped undecoded (payload type or digest)";

/// The reason of an IGNORE verdict for a message that is not a column sidecar.
const NOT_A_COLUMN: &str = "probe: IGNORE: not a data column sidecar";

/// The status a `Validate` stream ends with when cl-chain stops.
fn stopping() -> Status {
    Status::unavailable("cl-chain is stopping")
}

/// Serves one `Validate` stream (see the module docs) on its own task, which holds `place` until
/// the stream ends; returns the receiver of the response frames.
pub(crate) fn serve_stream(
    link: Link,
    columns: Arc<dyn ColumnHandOff>,
    requests: Streaming<pb::ValidateRequest>,
    mut stop: watch::Receiver<bool>,
    place: OwnedSemaphorePermit,
) -> mpsc::Receiver<Result<pb::ValidateResponse, Status>> {
    let (tx, rx) = mpsc::channel(VERDICT_BUFFER);
    ipc::spawn_in_span(async move {
        let _place = place;
        let opened = async {
            let guarded = link.open(Inbound::new(requests)).await?;
            let (generation, ours) = stream_hello(&link.local())?;
            Ok::<_, ContractError>((guarded, generation, ours))
        };
        let (mut guarded, generation, ours) = tokio::select! {
            opened = opened => match opened {
                Ok(opened) => opened,
                Err(e) => {
                    let _ = tx.send(Err(e.to_status())).await;
                    return;
                }
            },
            () = async { drop(stop.wait_for(|stopped| *stopped).await) } => {
                let _ = tx.send(Err(stopping())).await;
                return;
            }
        };
        if tx
            .send(Ok(pb::ValidateResponse::hello(ours)))
            .await
            .is_err()
        {
            return;
        }
        let mut last_id = 0;
        loop {
            let next = tokio::select! {
                next = guarded.body() => next,
                changed = stop.changed() => {
                    let stopped = changed.is_err() || *stop.borrow();
                    if stopped {
                        let _ = tx.send(Err(stopping())).await;
                        return;
                    }
                    continue;
                }
                () = tx.closed() => return,
            };
            let accepted = match next {
                Ok(Some(accepted)) => accepted,
                Ok(None) => return,
                Err(e) => {
                    let _ = tx.send(Err(e.to_status())).await;
                    return;
                }
            };
            let dropped: BTreeSet<usize> = accepted.dropped.iter().map(|(i, _)| *i).collect();
            let batch = accepted.body;
            let checked =
                check_batch(&batch, last_id).and_then(|()| check_request(&batch, generation));
            if let Err(e) = checked {
                let _ = tx.send(Err(link.fail(&e))).await;
                return;
            }
            last_id = batch.request_id;
            let verdicts = judge(&batch, &dropped, columns.as_ref());
            if tx
                .send(Ok(pb::ValidateResponse::body(verdicts)))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    rx
}

/// The checks of a batch that fail the stream (see the module docs, step 2), apart from the
/// generation.
fn check_batch(batch: &pb::ValidateBatch, last_id: u64) -> Result<(), ContractError> {
    let n = batch.messages.len();
    if n == 0 || n > MAX_BATCH_MESSAGES {
        return Err(ContractError::violation(format!(
            "request {}: {n} messages, want 1 to {MAX_BATCH_MESSAGES}",
            batch.request_id
        )));
    }
    if batch.request_id <= last_id {
        return Err(ContractError::violation(format!(
            "request_id {} does not increase on {last_id}",
            batch.request_id
        )));
    }
    if let Some(i) = batch
        .messages
        .iter()
        .position(|m| m.topic == pb::Topic::Unspecified as i32)
    {
        return Err(ContractError::violation(format!(
            "request {}: message {i} has TOPIC_UNSPECIFIED",
            batch.request_id
        )));
    }
    Ok(())
}

/// The verdicts of `batch`, every one IGNORE and fenced; the column sidecars in it go to
/// `columns`, except those at the `dropped` indexes.
fn judge(
    batch: &pb::ValidateBatch,
    dropped: &BTreeSet<usize>,
    columns: &dyn ColumnHandOff,
) -> pb::VerdictBatch {
    let verdicts = batch
        .messages
        .iter()
        .enumerate()
        .map(|(i, message)| {
            let reason = if dropped.contains(&i) {
                DROPPED
            } else {
                column_of(message).map_or(NOT_A_COLUMN, |column| columns.hand_over(column).reason())
            };
            pb::GossipVerdict {
                message_id: message.message_id.clone(),
                verdict: Verdict::Ignore as i32,
                reason: reason.to_owned(),
                fence: None,
            }
        })
        .collect();
    let mut answer = pb::VerdictBatch {
        verdicts,
        request_id: batch.request_id,
    };
    answer.stamp(&batch.result_fences());
    answer
}

/// The column sidecar that `message` carries, if its topic and its payload are both a data
/// column sidecar's and its envelope has a 4-byte digest.
fn column_of(message: &pb::GossipMessage) -> Option<GossipColumnBytes<'_>> {
    if message.topic != pb::Topic::DataColumnSidecar as i32 {
        return None;
    }
    let Envelope {
        fork_digest,
        slot,
        ssz,
        payload_type,
        ..
    } = message.payload.as_ref()?;
    if *payload_type != PayloadType::DataColumnSidecar as i32 {
        return None;
    }
    Some(GossipColumnBytes {
        fork_digest: fork_digest.as_slice().try_into().ok()?,
        slot: *slot,
        subnet_id: u64::from(message.subnet_id),
        ssz,
    })
}

#[cfg(test)]
mod tests;
