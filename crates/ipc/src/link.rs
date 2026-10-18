//! One service's side of its links: our hello, the API-version floor, the fork schedule and
//! digests envelopes are checked against, and the contract metrics.
//!
//! [`Link::open`] reads the peer's hello within the hello timeout and negotiates; the returned
//! [`Guarded`] stream then yields bodies whose envelopes have been checked: `seq` strictly
//! increasing from 1 across every envelope of the direction, and each envelope opened as far as
//! [`crate::envelope::check_envelope`]. A zero `payload_type` or a bad `seq` fails the stream
//! (`ERROR_CODE_CONTRACT_VIOLATION`); an unknown type (IGNORE) or a mismatched fork digest
//! (`ERROR_CODE_FORK_DIGEST_MISMATCH`, logged) drops that envelope and the stream goes on.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use consensus_types::EthSpec;
use ethswarm_proto::common::{Envelope, ErrorCode, Hello};
use network_config::ForkSchedule;
use tokio_stream::Stream;
use tonic::Status;

use crate::envelope::{check_envelope_at, Checked, EnvelopeError, Envelopes, ForkDigests};
use crate::error::ContractError;
use crate::frame::{check_unary_seq, InFrame, Inbound, SeqChecker};
use crate::hello::negotiate;

/// Time from stream open to the peer's hello unless configured otherwise.
pub const DEFAULT_HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Contract counters of one service (the contract-violation metric and its neighbours).
#[derive(Debug, Default)]
pub struct ContractMetrics {
    contract_violations: AtomicU64,
    version_mismatches: AtomicU64,
    digest_mismatches: AtomicU64,
    ignored: AtomicU64,
    accepted: AtomicU64,
}

/// A point-in-time copy of [`ContractMetrics`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub contract_violations: u64,
    pub version_mismatches: u64,
    pub digest_mismatches: u64,
    /// Envelopes dropped as IGNORE (unknown `payload_type`).
    pub ignored: u64,
    /// Envelopes that passed the type, digest and seq checks.
    pub accepted: u64,
}

impl ContractMetrics {
    #[must_use]
    pub fn counts(&self) -> Counts {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        Counts {
            contract_violations: get(&self.contract_violations),
            version_mismatches: get(&self.version_mismatches),
            digest_mismatches: get(&self.digest_mismatches),
            ignored: get(&self.ignored),
            accepted: get(&self.accepted),
        }
    }

    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

struct Inner {
    local: Hello,
    floor: u32,
    schedule: ForkSchedule,
    digests: Box<dyn ForkDigests + Send + Sync>,
    slots_per_epoch: u64,
    metrics: ContractMetrics,
}

/// A service's contract configuration. Cloning shares the metrics.
#[derive(Clone)]
pub struct Link {
    inner: Arc<Inner>,
    hello_timeout: Duration,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("local", &self.inner.local)
            .field("floor", &self.inner.floor)
            .field("hello_timeout", &self.hello_timeout)
            .finish_non_exhaustive()
    }
}

impl Link {
    /// `local` is the hello this side sends first on every stream; `floor` the lowest API
    /// version it accepts. Envelope epochs use `E::slots_per_epoch()`.
    pub fn new<E: EthSpec>(
        local: Hello,
        floor: u32,
        schedule: ForkSchedule,
        digests: impl ForkDigests + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                local,
                floor,
                schedule,
                digests: Box::new(digests),
                slots_per_epoch: E::slots_per_epoch(),
                metrics: ContractMetrics::default(),
            }),
            hello_timeout: DEFAULT_HELLO_TIMEOUT,
        }
    }

    /// Whether `other` is this link or a clone of it (same configuration and metrics).
    #[must_use]
    pub fn is_same(&self, other: &Link) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// The same link with another hello timeout.
    #[must_use]
    pub fn with_hello_timeout(mut self, timeout: Duration) -> Self {
        self.hello_timeout = timeout;
        self
    }

    #[must_use]
    pub fn local(&self) -> &Hello {
        &self.inner.local
    }

    #[must_use]
    pub fn floor(&self) -> u32 {
        self.inner.floor
    }

    #[must_use]
    pub fn schedule(&self) -> &ForkSchedule {
        &self.inner.schedule
    }

    #[must_use]
    pub fn metrics(&self) -> &ContractMetrics {
        &self.inner.metrics
    }

    #[must_use]
    pub fn hello_timeout(&self) -> Duration {
        self.hello_timeout
    }

    /// Logs `err` and counts it in the metrics.
    pub fn record(&self, err: &ContractError) {
        let m = &self.inner.metrics;
        match err.code() {
            ErrorCode::ContractViolation => ContractMetrics::bump(&m.contract_violations),
            ErrorCode::VersionMismatch => ContractMetrics::bump(&m.version_mismatches),
            ErrorCode::ForkDigestMismatch => ContractMetrics::bump(&m.digest_mismatches),
            _ => {}
        }
        let (code, name) = logged_code(err);
        tracing::warn!(code, name, detail = err.detail(), "contract error");
    }

    /// `err` recorded, as the status that fails the call or stream.
    #[must_use]
    pub fn fail(&self, err: &ContractError) -> Status {
        self.record(err);
        err.to_status()
    }

    fn recorded<T>(&self, r: Result<T, ContractError>) -> Result<T, ContractError> {
        if let Err(e) = &r {
            self.record(e);
        }
        r
    }

    /// Negotiates with the peer's hello ([`negotiate`] against our hello and floor).
    pub fn negotiate(&self, remote: &Hello) -> Result<u32, ContractError> {
        self.recorded(negotiate(&self.inner.local, remote, self.inner.floor))
    }

    /// The in-line hello of a server-streaming request, which is required.
    pub fn accept_hello_field(&self, hello: Option<&Hello>) -> Result<u32, ContractError> {
        match hello {
            Some(h) => self.negotiate(h),
            None => self.recorded(Err(ContractError::violation(
                "server-streaming request has no hello",
            ))),
        }
    }

    /// The type and digest checks of one envelope (no seq, no decode, no metrics).
    pub fn check_envelope<'a>(&self, envelope: &'a Envelope) -> Result<Checked<'a>, EnvelopeError> {
        check_envelope_at(
            envelope,
            self.inner.slots_per_epoch,
            &self.inner.schedule,
            &self.inner.digests.as_ref(),
        )
    }

    /// Checks one envelope at its place in a stream or call: a zero type fails it, anything
    /// else that does not pass is counted and returned as the reason it is dropped.
    fn admit_envelope(&self, envelope: &Envelope) -> Result<Option<EnvelopeError>, ContractError> {
        let m = &self.inner.metrics;
        match self.check_envelope(envelope) {
            Ok(_) => {
                ContractMetrics::bump(&m.accepted);
                Ok(None)
            }
            Err(EnvelopeError::UnspecifiedType) => {
                self.recorded(Err(ContractError::violation(format!(
                    "envelope seq {}: {}",
                    envelope.seq,
                    EnvelopeError::UnspecifiedType
                ))))
            }
            Err(e) => {
                match e.to_contract_error() {
                    Some(err) => self.record(&err),
                    None => {
                        ContractMetrics::bump(&m.ignored);
                        tracing::debug!(reason = %e, "envelope ignored");
                    }
                }
                Ok(Some(e))
            }
        }
    }

    /// The envelopes of a unary call: `seq` must be 0 on each. Returns, per envelope, why it is
    /// dropped (`None`: passed).
    pub fn check_unary(
        &self,
        envelopes: &[&Envelope],
    ) -> Result<Vec<Option<EnvelopeError>>, ContractError> {
        envelopes
            .iter()
            .map(|e| {
                self.recorded(check_unary_seq(e.seq))?;
                self.admit_envelope(e)
            })
            .collect()
    }

    /// Reads the peer's hello from `inbound` within the hello timeout and negotiates.
    pub async fn open<S, T>(&self, mut inbound: Inbound<S>) -> Result<Guarded<S>, ContractError>
    where
        S: Stream<Item = Result<T, Status>> + Unpin,
        T: InFrame,
    {
        let hello = tokio::time::timeout(self.hello_timeout, inbound.hello())
            .await
            .unwrap_or_else(|_| {
                Err(ContractError::violation(format!(
                    "no hello within {:?}",
                    self.hello_timeout
                )))
            });
        let peer = self.recorded(hello)?;
        let version = self.negotiate(&peer)?;
        Ok(Guarded {
            inbound,
            seq: SeqChecker::new(),
            link: self.clone(),
            version,
            peer,
        })
    }
}

/// The code [`Link::record`] logs: as on the wire, with its name. An unknown peer code maps to
/// `ERROR_CODE_UNSPECIFIED` in [`ContractError::code`], so it is logged by number only.
fn logged_code(err: &ContractError) -> (i32, &'static str) {
    let name = if err.is_ignore() {
        "unknown"
    } else {
        err.code().as_str_name()
    };
    (err.raw_code(), name)
}

/// A body whose envelopes were checked, with the ones to drop.
#[derive(Clone, Debug, PartialEq)]
pub struct Accepted<B> {
    pub body: B,
    /// `(index in Envelopes::envelopes order, reason)` of every envelope not to use.
    pub dropped: Vec<(usize, EnvelopeError)>,
}

/// An inbound stream after a successful handshake.
pub struct Guarded<S> {
    inbound: Inbound<S>,
    seq: SeqChecker,
    link: Link,
    version: u32,
    peer: Hello,
}

impl<S, T> Guarded<S>
where
    S: Stream<Item = Result<T, Status>> + Unpin,
    T: InFrame,
    T::Body: Envelopes,
{
    /// The negotiated API version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The peer's hello.
    #[must_use]
    pub fn peer(&self) -> &Hello {
        &self.peer
    }

    /// The next body, or `None` once the peer closes its side.
    pub async fn body(&mut self) -> Result<Option<Accepted<T::Body>>, ContractError> {
        let Some(body) = self.link.recorded(self.inbound.body().await)? else {
            return Ok(None);
        };
        self.link.recorded(body.check_shape())?;
        let mut dropped = Vec::new();
        for (i, envelope) in body.envelopes().into_iter().enumerate() {
            self.link.recorded(self.seq.check(envelope.seq))?;
            if let Some(reason) = self.link.admit_envelope(envelope)? {
                dropped.push((i, reason));
            }
        }
        Ok(Some(Accepted { body, dropped }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::DigestTable;
    use crate::frame::OutFrame;
    use consensus_types::Mainnet;
    use ethswarm_proto::chain::{ImportBatchRequest, ImportBatchRequestBody};
    use ethswarm_proto::common::PayloadType;
    use network_config::{ForkName, ScheduledFork};

    const DIGEST: [u8; 4] = [1, 2, 3, 4];

    fn link(floor: u32) -> Link {
        let schedule = ForkSchedule::new(
            ScheduledFork {
                version: [0; 4],
                epoch: 0,
            },
            ScheduledFork {
                version: [1; 4],
                epoch: 100,
            },
        )
        .unwrap();
        let digests = DigestTable::new(vec![
            (0, ForkName::Fulu, DIGEST),
            (100, ForkName::Gloas, [9; 4]),
        ])
        .unwrap();
        let hello = Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 2,
            ..Default::default()
        };
        Link::new::<Mainnet>(hello, floor, schedule, digests)
    }

    fn env(seq: u64, payload_type: i32, digest: [u8; 4]) -> Envelope {
        Envelope {
            seq,
            slot: 1,
            payload_type,
            fork_digest: digest.to_vec(),
            ..Default::default()
        }
    }

    fn block(seq: u64) -> Envelope {
        env(seq, PayloadType::SignedBeaconBlock as i32, DIGEST)
    }

    fn batch(blocks: Vec<Envelope>) -> ImportBatchRequest {
        ImportBatchRequest::body(ImportBatchRequestBody {
            blocks,
            ..Default::default()
        })
    }

    fn peer() -> Hello {
        let mut h = link(1).local().clone();
        h.max_api_version = 1;
        h
    }

    async fn opened(
        frames: Vec<ImportBatchRequest>,
    ) -> Result<
        Guarded<impl Stream<Item = Result<ImportBatchRequest, Status>> + Unpin>,
        ContractError,
    > {
        let mut all = vec![ImportBatchRequest::hello(peer())];
        all.extend(frames);
        link(1)
            .open(Inbound::new(tokio_stream::iter(all.into_iter().map(Ok))))
            .await
    }

    #[tokio::test]
    async fn open_negotiates_and_bodies_check_seq_across_envelopes() {
        let mut g = opened(vec![batch(vec![block(1), block(2)]), batch(vec![block(3)])])
            .await
            .unwrap();
        assert_eq!(g.version(), 1);
        assert_eq!(g.peer().max_api_version, 1);
        assert!(g.body().await.unwrap().unwrap().dropped.is_empty());
        assert!(g.body().await.unwrap().unwrap().dropped.is_empty());
        assert_eq!(g.body().await, Ok(None));
    }

    #[tokio::test]
    async fn repeated_seq_fails_the_stream() {
        let mut g = opened(vec![batch(vec![block(1), block(1)])]).await.unwrap();
        let err = g.body().await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert_eq!(g.link.metrics().counts().contract_violations, 1);
    }

    #[tokio::test]
    async fn zero_type_fails_unknown_type_and_bad_digest_drop() {
        let mut g = opened(vec![
            batch(vec![env(1, 99, DIGEST), env(2, 1, [7; 4]), block(3)]),
            batch(vec![env(4, 0, DIGEST)]),
        ])
        .await
        .unwrap();
        let first = g.body().await.unwrap().unwrap();
        assert_eq!(first.dropped.len(), 2);
        assert_eq!(first.dropped[0], (0, EnvelopeError::UnknownType(99)));
        assert!(matches!(
            first.dropped[1],
            (1, EnvelopeError::DigestMismatch { .. })
        ));
        assert_eq!(
            g.body().await.unwrap_err().code(),
            ErrorCode::ContractViolation
        );
        let c = g.link.metrics().counts();
        assert_eq!(
            c,
            Counts {
                contract_violations: 1,
                version_mismatches: 0,
                digest_mismatches: 1,
                ignored: 1,
                accepted: 1,
            }
        );
    }

    #[tokio::test]
    async fn gossip_message_without_payload_fails_the_stream() {
        use ethswarm_proto::chain::{GossipMessage, ValidateBatch, ValidateRequest};
        let msg = |payload| GossipMessage {
            payload,
            ..Default::default()
        };
        let l = link(1);
        let frames = vec![
            Ok(ValidateRequest::hello(peer())),
            Ok(ValidateRequest::body(ValidateBatch {
                messages: vec![msg(Some(block(1))), msg(None)],
            })),
        ];
        let mut g = l
            .open(Inbound::new(tokio_stream::iter(frames)))
            .await
            .unwrap();
        let err = g.body().await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert!(err.detail().contains("payload"), "{err}");
        assert_eq!(l.metrics().counts().contract_violations, 1);
        assert_eq!(
            l.metrics().counts().accepted,
            0,
            "nothing in the batch is admitted"
        );
    }

    #[tokio::test]
    async fn empty_response_chunk_fails_the_stream() {
        use ethswarm_proto::p2p::{
            response_chunk, RequestBlocksByRangeResponse as Resp,
            RequestBlocksByRangeResponseBody as Body, ResponseChunk,
        };
        let chunk = |result| {
            Resp::body(Body {
                item: Some(ResponseChunk { peer: None, result }),
            })
        };
        let l = link(1);
        let frames = vec![
            Ok(Resp::hello(peer())),
            Ok(chunk(Some(response_chunk::Result::Chunk(block(1))))),
            Ok(chunk(None)),
        ];
        let mut g = l
            .open(Inbound::from_server(tokio_stream::iter(frames)))
            .await
            .unwrap();
        assert!(g.body().await.unwrap().unwrap().dropped.is_empty());
        let err = g.body().await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert!(err.detail().contains("neither chunk nor error"), "{err}");
        let c = l.metrics().counts();
        assert_eq!((c.contract_violations, c.accepted), (1, 1));
    }

    #[tokio::test]
    async fn missing_or_mismatched_hello_fails_open() {
        let l = link(1);
        let body_first = Inbound::new(tokio_stream::iter(vec![Ok(batch(vec![]))]));
        assert_eq!(
            l.open(body_first).await.err().unwrap().code(),
            ErrorCode::ContractViolation
        );
        let mut other = peer();
        other.genesis_validators_root = vec![1; 32];
        let wrong = Inbound::new(tokio_stream::iter(vec![Ok(ImportBatchRequest::hello(
            other,
        ))]));
        assert_eq!(
            l.open(wrong).await.err().unwrap().code(),
            ErrorCode::VersionMismatch
        );
        let c = l.metrics().counts();
        assert_eq!((c.contract_violations, c.version_mismatches), (1, 1));
    }

    #[tokio::test]
    async fn floor_above_the_common_version_fails_open() {
        let l = link(2);
        let s = Inbound::new(tokio_stream::iter(vec![Ok(ImportBatchRequest::hello(
            peer(),
        ))]));
        assert_eq!(
            l.open(s).await.err().unwrap().code(),
            ErrorCode::VersionMismatch
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_hello_within_the_timeout_is_a_contract_violation() {
        let l = link(1).with_hello_timeout(Duration::from_millis(10));
        assert_eq!(l.hello_timeout(), Duration::from_millis(10));
        let silent = Inbound::new(tokio_stream::pending::<Result<ImportBatchRequest, Status>>());
        let err = l.open(silent).await.err().unwrap();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert!(err.detail().contains("no hello"));
    }

    #[test]
    fn hello_field_is_required() {
        let l = link(1);
        assert!(l.is_same(&l.clone().with_hello_timeout(Duration::from_secs(1))));
        assert!(!l.is_same(&link(1)));
        assert_eq!(
            l.accept_hello_field(None).unwrap_err().code(),
            ErrorCode::ContractViolation
        );
        assert_eq!(l.accept_hello_field(Some(&peer())), Ok(1));
        assert_eq!(l.floor(), 1);
        assert!(l.schedule().fork_at(0).is_some());
        assert!(format!("{l:?}").contains("floor"));
    }

    #[test]
    fn unary_envelopes_carry_seq_zero() {
        let l = link(1);
        assert_eq!(l.check_unary(&[&block(0)]), Ok(vec![None]));
        assert_eq!(
            l.check_unary(&[&block(1)]).unwrap_err().code(),
            ErrorCode::ContractViolation
        );
        let dropped = l.check_unary(&[&env(0, 42, DIGEST)]).unwrap();
        assert_eq!(dropped, vec![Some(EnvelopeError::UnknownType(42))]);
        assert_eq!(
            l.check_unary(&[&env(0, 0, DIGEST)]).unwrap_err().code(),
            ErrorCode::ContractViolation
        );
    }

    #[test]
    fn record_logs_the_code_as_on_the_wire() {
        let unknown = ContractError::from(ethswarm_proto::common::Error {
            code: 999,
            detail: "newer".into(),
        });
        assert_eq!(logged_code(&unknown), (999, "unknown"));
        assert_eq!(
            logged_code(&ContractError::violation("x")),
            (
                ErrorCode::ContractViolation as i32,
                "ERROR_CODE_CONTRACT_VIOLATION"
            )
        );
    }

    #[test]
    fn fail_records_and_maps_to_a_status() {
        let l = link(1);
        let status = l.fail(&ContractError::violation("x"));
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        l.record(&ContractError::new(ErrorCode::NotFound, "not counted"));
        assert_eq!(l.metrics().counts().contract_violations, 1);
    }
}
