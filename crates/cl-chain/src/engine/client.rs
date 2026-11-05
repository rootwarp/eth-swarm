//! [`FcuSender`]: cl-chain's `ForkchoiceUpdated` client of cl-engine (`ethswarm.engine.v1`).
//!
//! - **Latest wins.** One task sends; [`FcuSender::send`] only puts the arguments in a
//!   one-value slot. A value that is replaced before the task took it is never sent, and is
//!   counted in `chain_fcu_coalesced_total`. So after a stall (a slow EL, cl-engine away) only
//!   the latest arguments go out.
//! - **`seq`.** Every call takes the next value of the process's one [`EngineSeq`], which
//!   cl-engine's queue orders calls by. It never resets in the process, a reconnect included,
//!   and a retry takes a new one.
//! - **Retries.** A failure on the way to the EL is retried with the latest arguments (the
//!   failed ones, unless newer ones came), after a backoff that doubles from [`BACKOFF_MIN`] to
//!   [`BACKOFF_MAX`] and resets after an answer. Those failures are: cl-engine's socket refuses
//!   the connection or the server's UID; the call fails in transport (`UNAVAILABLE`,
//!   `CANCELLED`, `UNKNOWN`, `DEADLINE_EXCEEDED`, or no answer within [`CALL_TIMEOUT`]), after
//!   which the connection is opened again; or cl-engine answers that the EL is unreachable or
//!   timed out. Any other gRPC status (a contract violation) is not retried: the same arguments
//!   would be refused again.
//! - **Answers.** The response, `PayloadStatus` included, goes to the caller as it is
//!   ([`FcuSender::outcomes`]), an `EngineError` other than the retried ones too. This module
//!   reads no verdict from it.
//! - **Metrics.** `chain_fcu_sent_total` (calls sent), `chain_fcu_coalesced_total`, and
//!   `chain_fcu_errors_total{kind}` ([`FcuErrorKind`]).

use super::fcu::ForkchoiceArgs;
use ethswarm_proto::engine as pb;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// The first pause before a retry.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// The longest pause before a retry.
pub const BACKOFF_MAX: Duration = Duration::from_secs(8);
/// How long one call may take before it counts as lost in transport: above cl-engine's 10 s
/// request deadline, so cl-engine's own answer comes first.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(12);

/// The `seq` of cl-chain's engine.v1 calls: one counter per process, shared by every caller,
/// from 1 and strictly increasing.
#[derive(Clone, Debug)]
pub struct EngineSeq(Arc<AtomicU64>);

impl EngineSeq {
    /// A counter whose first `seq` is 1.
    #[must_use]
    pub fn new() -> Self {
        todo!()
    }

    /// The next `seq`.
    #[must_use]
    pub fn next(&self) -> u64 {
        todo!()
    }
}

impl Default for EngineSeq {
    fn default() -> Self {
        Self::new()
    }
}

/// The `kind` of `chain_fcu_errors_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FcuErrorKind {
    /// cl-engine's socket refused the connection, or its server is not the expected user.
    Connect,
    /// The call failed with a gRPC status or timed out.
    Rpc,
    /// cl-engine answered with an `EngineError`.
    Engine,
}

impl FcuErrorKind {
    /// The `kind` label.
    #[must_use]
    pub fn label(self) -> &'static str {
        todo!()
    }
}

type KindLabel = [(&'static str, &'static str); 1];

/// `chain_fcu_sent_total`, `chain_fcu_coalesced_total` and `chain_fcu_errors_total{kind}`.
#[derive(Clone, Debug, Default)]
pub struct FcuMetrics {
    sent: Counter,
    coalesced: Counter,
    errors: Family<KindLabel, Counter>,
}

impl FcuMetrics {
    /// Registers the counters in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let _ = registry;
        todo!()
    }

    /// Calls sent so far.
    #[must_use]
    pub fn sent(&self) -> u64 {
        todo!()
    }

    /// Arguments replaced before they were sent, so far.
    #[must_use]
    pub fn coalesced(&self) -> u64 {
        todo!()
    }

    /// Errors of `kind` so far.
    #[must_use]
    pub fn errors(&self, kind: FcuErrorKind) -> u64 {
        let _ = kind;
        todo!()
    }
}

/// One answered call.
#[derive(Clone, Debug, PartialEq)]
pub struct FcuOutcome {
    /// The call's `seq`.
    pub seq: u64,
    /// What was sent.
    pub args: ForkchoiceArgs,
    /// cl-engine's response, as it is.
    pub response: pb::ForkchoiceUpdatedResponse,
}

/// The one-value slot between [`FcuSender::send`] and the task.
#[derive(Default)]
struct Slot {}

/// The `ForkchoiceUpdated` sender (see the module docs). Dropping it stops its task.
pub struct FcuSender {
    slot: Arc<Slot>,
    metrics: FcuMetrics,
    outcomes: watch::Receiver<Option<FcuOutcome>>,
    task: JoinHandle<()>,
}

impl FcuSender {
    /// Starts the task that sends to cl-engine's socket at `socket`, served by `expected_uid`,
    /// with `seq` from `seq`. It connects at the first send. Must be called within a Tokio
    /// runtime.
    #[must_use]
    pub fn spawn(
        socket: impl Into<PathBuf>,
        expected_uid: u32,
        seq: EngineSeq,
        metrics: FcuMetrics,
    ) -> Self {
        let _ = (socket.into(), expected_uid, seq, metrics);
        todo!()
    }

    /// Makes `args` the next arguments to send, in place of any not sent yet.
    pub fn send(&self, args: ForkchoiceArgs) {
        let _ = (&self.slot, &self.metrics, args);
        todo!()
    }

    /// The latest answered call, `None` before the first.
    #[must_use]
    pub fn outcomes(&self) -> watch::Receiver<Option<FcuOutcome>> {
        self.outcomes.clone()
    }
}

impl Drop for FcuSender {
    fn drop(&mut self) {
        self.task.abort();
    }
}
