//! cl-chain's clients of cl-engine (`ethswarm.engine.v1`): [`FcuSender`] for
//! `ForkchoiceUpdated` (below), and [`NewPayloadClient`] for `NewPayload` (see its docs), whose
//! answers become an [`ElVerdict`]. Both take `seq` from the process's one [`EngineSeq`].
//!
//! The `ForkchoiceUpdated` sender:
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
//!   [`BACKOFF_MAX`] and resets after an answer. Those failures are: no connection to
//!   cl-engine's socket within [`CALL_TIMEOUT`], or a server that is not the expected user; the
//!   call fails in transport (`UNAVAILABLE`,
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
use super::verdict::{self, ElVerdict, Reason};
use consensus_types::gloas::{ExecutionPayloadBid, ExecutionPayloadEnvelope};
use consensus_types::EthSpec;
use engine_api::new_payload_v5_params;
use ethswarm_proto::engine as pb;
use pb::engine_service_client::EngineServiceClient;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use tonic::transport::Channel;
use tonic::Code;

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
        Self(Arc::new(AtomicU64::new(1)))
    }

    /// The next `seq`.
    #[must_use]
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
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
    const ALL: [Self; 3] = [Self::Connect, Self::Rpc, Self::Engine];

    /// The `kind` label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Rpc => "rpc",
            Self::Engine => "engine",
        }
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
        let metrics = Self::default();
        registry.register(
            "chain_fcu_sent",
            "forkchoiceUpdated calls sent to cl-engine",
            metrics.sent.clone(),
        );
        registry.register(
            "chain_fcu_coalesced",
            "forkchoiceUpdated arguments replaced by newer ones before they were sent",
            metrics.coalesced.clone(),
        );
        registry.register(
            "chain_fcu_errors",
            "forkchoiceUpdated calls that failed, by kind",
            metrics.errors.clone(),
        );
        // Every kind is there from the start, at 0.
        for kind in FcuErrorKind::ALL {
            drop(metrics.errors.get_or_create(&[("kind", kind.label())]));
        }
        metrics
    }

    /// Calls sent so far.
    #[must_use]
    pub fn sent(&self) -> u64 {
        self.sent.get()
    }

    /// Arguments replaced before they were sent, so far.
    #[must_use]
    pub fn coalesced(&self) -> u64 {
        self.coalesced.get()
    }

    /// Errors of `kind` so far.
    #[must_use]
    pub fn errors(&self, kind: FcuErrorKind) -> u64 {
        self.errors.get_or_create(&[("kind", kind.label())]).get()
    }

    fn error(&self, kind: FcuErrorKind) {
        self.errors.get_or_create(&[("kind", kind.label())]).inc();
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
struct Slot {
    latest: Mutex<Option<ForkchoiceArgs>>,
    ready: Notify,
}

impl Slot {
    /// Puts `args` in the slot: true if they replaced arguments not taken yet.
    fn put(&self, args: ForkchoiceArgs) -> bool {
        let replaced = self.lock().replace(args).is_some();
        self.ready.notify_one();
        replaced
    }

    /// Puts back `args` whose call failed, unless newer ones came meanwhile.
    fn put_back(&self, args: ForkchoiceArgs) {
        self.lock().get_or_insert(args);
    }

    /// Takes the latest arguments, waiting until there are some.
    async fn take(&self) -> ForkchoiceArgs {
        loop {
            let taken = self.lock().take();
            if let Some(args) = taken {
                return args;
            }
            self.ready.notified().await;
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<ForkchoiceArgs>> {
        self.latest.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Why a call has no outcome for the caller.
enum Failed {
    /// Lost on the way to the EL: retried after the backoff.
    Lost,
    /// Refused by cl-engine: not retried.
    Refused,
}

/// The sending task.
struct Task {
    socket: PathBuf,
    expected_uid: u32,
    seq: EngineSeq,
    slot: Arc<Slot>,
    metrics: FcuMetrics,
    outcomes: watch::Sender<Option<FcuOutcome>>,
    client: Option<EngineServiceClient<Channel>>,
}

impl Task {
    async fn run(mut self) {
        let mut backoff = BACKOFF_MIN;
        loop {
            let args = self.slot.take().await;
            match self.call(args).await {
                Ok(outcome) => {
                    backoff = BACKOFF_MIN;
                    self.outcomes.send_replace(Some(outcome));
                }
                Err(Failed::Refused) => backoff = BACKOFF_MIN,
                Err(Failed::Lost) => {
                    self.slot.put_back(args);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
            }
        }
    }

    /// One call with `args` and the next `seq`, on the open connection or a new one. A
    /// connection whose call was lost is dropped.
    async fn call(&mut self, args: ForkchoiceArgs) -> Result<FcuOutcome, Failed> {
        let mut client = match self.client.take() {
            Some(client) => client,
            None => {
                let connect = ipc::uds::connect_path(&self.socket, self.expected_uid);
                match tokio::time::timeout(CALL_TIMEOUT, connect).await {
                    Ok(Ok(channel)) => EngineServiceClient::new(channel),
                    failed => {
                        self.metrics.error(FcuErrorKind::Connect);
                        let error = match failed {
                            Ok(Err(err)) => err.to_string(),
                            _ => "timed out".to_owned(),
                        };
                        tracing::warn!(
                            socket = %self.socket.display(),
                            error,
                            "forkchoiceUpdated: cl-engine did not accept"
                        );
                        return Err(Failed::Lost);
                    }
                }
            }
        };
        let seq = self.seq.next();
        self.metrics.sent.inc();
        let call = client.forkchoice_updated(args.request(seq));
        let response = match tokio::time::timeout(CALL_TIMEOUT, call).await {
            Ok(Ok(response)) => response.into_inner(),
            Ok(Err(status)) => {
                self.metrics.error(FcuErrorKind::Rpc);
                let lost = lost_in_transport(status.code());
                tracing::warn!(seq, code = ?status.code(), retry = lost, "forkchoiceUpdated failed");
                if lost {
                    return Err(Failed::Lost);
                }
                self.client = Some(client);
                return Err(Failed::Refused);
            }
            Err(_) => {
                self.metrics.error(FcuErrorKind::Rpc);
                tracing::warn!(seq, "forkchoiceUpdated: no answer from cl-engine in time");
                return Err(Failed::Lost);
            }
        };
        self.client = Some(client);
        if let Some(error) = &response.error {
            self.metrics.error(FcuErrorKind::Engine);
            let lost = matches!(
                pb::EngineErrorKind::try_from(error.kind),
                Ok(pb::EngineErrorKind::ElUnreachable | pb::EngineErrorKind::Timeout)
            );
            tracing::warn!(
                seq,
                kind = error.kind,
                rpc_code = error.rpc_code,
                retry = lost,
                "forkchoiceUpdated: cl-engine answered an error"
            );
            if lost {
                return Err(Failed::Lost);
            }
        }
        Ok(FcuOutcome {
            seq,
            args,
            response,
        })
    }
}

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
        let slot = Arc::new(Slot::default());
        let (outcomes_tx, outcomes) = watch::channel(None);
        let task = Task {
            socket: socket.into(),
            expected_uid,
            seq,
            slot: Arc::clone(&slot),
            metrics: metrics.clone(),
            outcomes: outcomes_tx,
            client: None,
        };
        Self {
            slot,
            metrics,
            outcomes,
            task: tokio::spawn(task.run()),
        }
    }

    /// Makes `args` the next arguments to send, in place of any not sent yet.
    pub fn send(&self, args: ForkchoiceArgs) {
        if self.slot.put(args) {
            self.metrics.coalesced.inc();
        }
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

/// `engine_newPayloadV5`'s timeout (execution-apis `amsterdam.md`): the wait cl-engine gives
/// the EL before it answers `EngineError` `TIMEOUT`. The request asks for no other
/// (`timeout_ms` 0, which never shortens it), and [`NewPayloadClient`] waits [`CALL_TIMEOUT`],
/// longer, for cl-engine's answer.
pub const NEW_PAYLOAD_V5_TIMEOUT: Duration = Duration::from_secs(6);

// The client never gives up before cl-engine's wait for the EL is over.
const _: () = assert!(CALL_TIMEOUT.as_secs() > NEW_PAYLOAD_V5_TIMEOUT.as_secs());

/// `chain_new_payload_verdicts_total{verdict}`, by [`ElVerdict::label`].
#[derive(Clone, Debug, Default)]
pub struct NewPayloadMetrics {
    verdicts: Family<KindLabel, Counter>,
}

impl NewPayloadMetrics {
    /// Registers the counter in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self::default();
        registry.register(
            "chain_new_payload_verdicts",
            "newPayload calls, by the verdict they gave",
            metrics.verdicts.clone(),
        );
        // Every verdict is there from the start, at 0.
        for verdict in ElVerdict::LABELS {
            drop(metrics.verdicts.get_or_create(&[("verdict", verdict)]));
        }
        metrics
    }

    /// Verdicts labelled `verdict` so far: 0 for a label that is not one of
    /// [`ElVerdict::LABELS`].
    #[must_use]
    pub fn verdicts(&self, verdict: &str) -> u64 {
        ElVerdict::LABELS
            .into_iter()
            .find(|label| *label == verdict)
            .map_or(0, |label| {
                self.verdicts.get_or_create(&[("verdict", label)]).get()
            })
    }

    fn count(&self, verdict: &ElVerdict) {
        self.verdicts
            .get_or_create(&[("verdict", verdict.label())])
            .inc();
    }
}

/// cl-chain's `NewPayload` client of cl-engine: one `engine_newPayloadV5` call per envelope,
/// whose answer is an [`ElVerdict`].
///
/// - **One call, no retry.** Each call takes the next `seq` of the process's [`EngineSeq`], the
///   one the [`FcuSender`] uses, once it has a connection. A failed call is
///   [`ElVerdict::NotVerified`]; calling again is the caller's choice.
/// - **The wait.** `timeout_ms` is 0, so cl-engine gives the EL the spec's 6 s
///   ([`NEW_PAYLOAD_V5_TIMEOUT`]) and answers `EngineError` `TIMEOUT` after it. The client gives
///   cl-engine [`CALL_TIMEOUT`] to connect and as much to answer; no answer by then is
///   [`Reason::Timeout`].
/// - **Fail closed.** Only a status, read by [`verdict::map_proto`], gives a verdict. An
///   `EngineError` (also beside a status), a failed call, an answer for another `seq`, no
///   status, no connection and a timeout are `NotVerified`, never `Valid`.
/// - **Connection.** One, opened at the first call and shared by concurrent calls. A call
///   lost in transport (a timeout, `UNAVAILABLE`, `CANCELLED`, `UNKNOWN`, `DEADLINE_EXCEEDED`)
///   drops it, and the next call opens another.
/// - **Metrics.** `chain_new_payload_verdicts_total{verdict}` ([`NewPayloadMetrics`]).
pub struct NewPayloadClient {
    socket: PathBuf,
    expected_uid: u32,
    seq: EngineSeq,
    metrics: NewPayloadMetrics,
    client: Mutex<Option<EngineServiceClient<Channel>>>,
}

impl NewPayloadClient {
    /// A client of cl-engine's socket at `socket`, served by `expected_uid`, with `seq` from
    /// `seq`. It connects at the first call.
    #[must_use]
    pub fn new(
        socket: impl Into<PathBuf>,
        expected_uid: u32,
        seq: EngineSeq,
        metrics: NewPayloadMetrics,
    ) -> Self {
        Self {
            socket: socket.into(),
            expected_uid,
            seq,
            metrics,
            client: Mutex::new(None),
        }
    }

    /// Sends `envelope`, whose committed bid is `bid`, to the EL, and gives its verdict (see
    /// the type docs). Must be called within a Tokio runtime.
    pub async fn new_payload<E: EthSpec>(
        &self,
        envelope: &ExecutionPayloadEnvelope<E>,
        bid: &ExecutionPayloadBid<E>,
    ) -> ElVerdict {
        let verdict = self.call(envelope, bid).await;
        self.metrics.count(&verdict);
        if let ElVerdict::NotVerified(reason) = verdict {
            tracing::warn!(
                block_hash = %envelope.payload.block_hash,
                ?reason,
                "newPayload: no verdict"
            );
        }
        verdict
    }

    async fn call<E: EthSpec>(
        &self,
        envelope: &ExecutionPayloadEnvelope<E>,
        bid: &ExecutionPayloadBid<E>,
    ) -> ElVerdict {
        let not_verified = ElVerdict::NotVerified;
        let Ok(data) = serde_json::to_vec(&new_payload_v5_params(envelope, bid)) else {
            return not_verified(Reason::Malformed);
        };
        let Some(mut client) = self.connection().await else {
            return not_verified(Reason::Connect);
        };
        let seq = self.seq.next();
        let request = pb::NewPayloadRequest {
            seq,
            params: Some(pb::VersionedData {
                version: pb::EngineMethodVersion::GloasAmsterdam as i32,
                encoding: pb::PayloadEncoding::Json as i32,
                data,
            }),
            timeout_ms: 0,
        };
        let response = match tokio::time::timeout(CALL_TIMEOUT, client.new_payload(request)).await {
            Ok(Ok(response)) => response.into_inner(),
            Ok(Err(status)) => {
                if lost_in_transport(status.code()) {
                    self.disconnect();
                }
                return not_verified(Reason::Rpc(status.code()));
            }
            Err(_) => {
                self.disconnect();
                return not_verified(Reason::Timeout);
            }
        };
        if response.seq != seq {
            return not_verified(Reason::Malformed);
        }
        if let Some(error) = &response.error {
            return not_verified(Reason::Engine(error.kind));
        }
        response
            .status
            .as_ref()
            .map_or(not_verified(Reason::Malformed), verdict::map_proto)
    }

    /// The open connection, or a new one.
    async fn connection(&self) -> Option<EngineServiceClient<Channel>> {
        let open = self.lock().clone();
        if open.is_some() {
            return open;
        }
        let connect = ipc::uds::connect_path(&self.socket, self.expected_uid);
        match tokio::time::timeout(CALL_TIMEOUT, connect).await {
            Ok(Ok(channel)) => {
                let client = EngineServiceClient::new(channel);
                *self.lock() = Some(client.clone());
                Some(client)
            }
            failed => {
                let error = match failed {
                    Ok(Err(err)) => err.to_string(),
                    _ => "timed out".to_owned(),
                };
                tracing::warn!(
                    socket = %self.socket.display(),
                    error,
                    "newPayload: cl-engine did not accept"
                );
                None
            }
        }
    }

    fn disconnect(&self) {
        *self.lock() = None;
    }

    fn lock(&self) -> MutexGuard<'_, Option<EngineServiceClient<Channel>>> {
        self.client.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A gRPC status of a call lost on the way, after which the connection is opened again.
fn lost_in_transport(code: Code) -> bool {
    matches!(
        code,
        Code::Unavailable | Code::Cancelled | Code::Unknown | Code::DeadlineExceeded
    )
}
