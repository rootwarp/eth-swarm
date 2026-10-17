//! The `ethswarm.verify.v1.VerifyService` tonic server.
//!
//! Every RPC first checks the Unix-socket peer's UID against the configured cl-chain UID and takes
//! a slot from the server-wide stream limit; then the stream must open with the hello exchange
//! ([`crate::handshake`], [`crate::frame`]) within the hello timeout. BLS and KZG request bodies
//! must carry strictly increasing `request_id`s, are checked against [`crate::caps`], and are then
//! verified concurrently on the blocking pool, with at most `max_outstanding_per_stream` requests
//! per stream between being read and having their response queued. Responses carry the request's
//! `request_id` and may arrive out of order.
//!
//! A request whose deadline has passed is answered `DEADLINE_EXCEEDED` without being verified, one
//! that finds no free verifier slot is answered `OVERLOADED`, and work that finishes at or after
//! its deadline or fails inside the verifier is answered `DEADLINE_EXCEEDED` or with an `err`,
//! never VALID. Contract violations (peer, framing, handshake, ordering, caps) fail the stream
//! with a status that carries the `common.v1.Error`; PubkeyFeed frame errors are answered in-band
//! so the sender can resync.
//!
//! The pubkey cache starts empty and is restored on the first PubkeyFeed frame, from the snapshot
//! at [`ServerConfig::pubkey_snapshot`] or by a rebuild over that stream ([`crate::feed`]); errors
//! during the restore fail the stream. VerifyBls reads the empty cache (`UNKNOWN_INDEX`) until then.
//!
//! The frame that completes the restore, and every PubkeyFeed frame applied after it, re-evaluate
//! the feed-lag gauges from the finalized epochs they carry ([`crate::metrics`]); a frame whose
//! epochs break the epoch rules is refused before it is applied. The metrics live on the registry
//! from [`VerifyServer::metrics_registry`].

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use crypto_kzg::SetupError;
use prometheus_client::registry::Registry as MetricsRegistry;
use tokio::net::UnixListener;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tokio_stream::Stream;
use tonic::transport::server::UdsConnectInfo;
use tonic::{Code, Request, Response, Status, Streaming};

use crate::bls::{self, BlsBackend, BlstBackend};
use crate::caps::{self, CapError, MAX_MESSAGE_BYTES};
use crate::feed::{self, FrameEpochs, Restored, SharedCache, SnapshotWriter};
use crate::frame::{InFrame, Inbound, OutFrame};
use crate::handshake::Handshake;
use crate::kzg::{self, KzgBackend, PinnedKzgBackend, TrustedSetupConfig};
use crate::metrics::FeedLagMetrics;
use crate::proto::common::{Error, ErrorCode};
use crate::proto::verify::verify_service_server::{VerifyService, VerifyServiceServer};
use crate::proto::verify::{
    bls_result, PubkeyFeedRequest, PubkeyFeedResponse, PubkeyFeedResponseBody, VerifyBlsRequest,
    VerifyBlsRequestBody, VerifyBlsResponse, VerifyBlsResponseBody, VerifyKzgRequest,
    VerifyKzgRequestBody, VerifyKzgResponse, VerifyKzgResponseBody, VerifyStatus,
};
use crate::wire::{by_deadline, to_status, wire_error, Deadline, SystemClock, WallClock};

/// Response frames buffered per stream before senders wait.
const RESPONSE_BUFFER: usize = 64;

/// Resource limits. All of them are configurable; [`Limits::default`] is a starting point.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Verification and feed jobs running at once across all streams (at least 1). A BLS or KZG
    /// request that finds none free is answered `OVERLOADED`; a feed frame waits for one.
    pub max_in_flight: usize,
    /// Requests per stream (at least 1) that have been read but whose response is not yet queued. The server
    /// stops reading the stream until one completes, so a peer that stops reading cannot pile up
    /// work.
    pub max_outstanding_per_stream: usize,
    /// Open RPC streams across all connections; more are refused with `OVERLOADED`.
    pub max_streams: usize,
    /// HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` per connection.
    pub max_concurrent_streams_per_connection: u32,
    /// Time from stream open to the peer's hello; longer is a contract violation.
    pub hello_timeout: Duration,
    /// During a pubkey cache restore, the longest wait for the next PubkeyFeed frame (and for
    /// the peer to take a reply). Longer is a contract violation that fails the stream and frees
    /// the restore for the next stream.
    pub restore_frame_timeout: Duration,
    pub http2_keepalive_interval: Duration,
    pub http2_keepalive_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_in_flight: 64,
            max_outstanding_per_stream: 32,
            max_streams: 16,
            max_concurrent_streams_per_connection: 16,
            hello_timeout: Duration::from_secs(5),
            restore_frame_timeout: Duration::from_secs(30),
            http2_keepalive_interval: Duration::from_secs(10),
            http2_keepalive_timeout: Duration::from_secs(20),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Our hello and API-version floor.
    pub handshake: Handshake,
    /// The only Unix-socket peer UID served (cl-chain's).
    pub peer_uid: u32,
    /// The digest-pinned KZG trusted setup.
    pub trusted_setup: TrustedSetupConfig,
    pub limits: Limits,
    /// The on-disk pubkey cache snapshot (`pubkeys.bin`), in a directory only cl-verify can
    /// write. Loaded or rebuilt on the first PubkeyFeed frame, then kept current (see
    /// `snapshot_interval`).
    pub pubkey_snapshot: PathBuf,
    /// Least time between two snapshot saves after a restore ([`DEFAULT_SNAPSHOT_INTERVAL`]).
    /// A rebuild or feed append marks the snapshot dirty; zero saves after every change.
    pub snapshot_interval: Duration,
}

/// One mainnet epoch (32 slots of 12 s): at most one snapshot save per epoch of feed appends.
pub const DEFAULT_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(384);

/// The service implementation. Cloning shares the cache, backends and counters.
#[derive(Clone)]
pub struct VerifyServer {
    inner: Arc<Inner>,
}

struct Inner {
    handshake: Handshake,
    peer_uid: u32,
    limits: Limits,
    max_kzg_cells: usize,
    cache: SharedCache,
    /// Whether `cache` has been restored (see [`crate::feed`]). Held across a restore, so a
    /// second feed stream waits for it instead of restoring again.
    restored: Mutex<bool>,
    snapshot: Arc<SnapshotWriter>,
    bls: Arc<dyn BlsBackend>,
    kzg: Arc<dyn KzgBackend>,
    permits: Arc<Semaphore>,
    streams: Arc<Semaphore>,
    clock: Arc<dyn WallClock>,
    contract_violations: AtomicU64,
    /// Holds every metric below; served by the service runtime.
    metrics: MetricsRegistry,
    feed_lag: FeedLagMetrics,
}

impl VerifyServer {
    /// The production server: blst for BLS and the pinned trusted setup for KZG. Fails if the
    /// setup file is missing or its sha256 is not [`crypto_kzg::BETA4_MAINNET_SHA256`].
    ///
    /// Pass an empty `cache`: it is restored from `config.pubkey_snapshot` or rebuilt from the
    /// feed on the first PubkeyFeed frame, and VerifyBls sees it empty until then. A non-empty
    /// `cache` counts as already restored by the caller.
    ///
    /// This is the only constructor outside tests: the `with_backends*` seams exist only with the
    /// `test-backends` feature, so no other crate can serve over an unpinned KZG backend.
    pub fn new(config: ServerConfig, cache: SharedCache) -> Result<Self, SetupError> {
        let kzg = Arc::new(PinnedKzgBackend::load(&config.trusted_setup)?);
        Ok(Self::build(
            config,
            cache,
            Arc::new(BlstBackend),
            kzg,
            Arc::new(SystemClock),
        ))
    }

    /// A server over the given verifiers (tests inject slow or failing ones). `trusted_setup` in
    /// `config` is not loaded here.
    #[cfg(any(test, feature = "test-backends"))]
    #[must_use]
    pub fn with_backends(
        config: ServerConfig,
        cache: SharedCache,
        bls: Arc<dyn BlsBackend>,
        kzg: Arc<dyn KzgBackend>,
    ) -> Self {
        Self::build(config, cache, bls, kzg, Arc::new(SystemClock))
    }

    /// [`Self::with_backends`] with the wall clock deadlines are judged against (tests step it).
    #[cfg(any(test, feature = "test-backends"))]
    #[must_use]
    pub fn with_backends_and_clock(
        config: ServerConfig,
        cache: SharedCache,
        bls: Arc<dyn BlsBackend>,
        kzg: Arc<dyn KzgBackend>,
        clock: Arc<dyn WallClock>,
    ) -> Self {
        Self::build(config, cache, bls, kzg, clock)
    }

    fn build(
        config: ServerConfig,
        cache: SharedCache,
        bls: Arc<dyn BlsBackend>,
        kzg: Arc<dyn KzgBackend>,
        clock: Arc<dyn WallClock>,
    ) -> Self {
        let max_kzg_cells = caps::max_kzg_cells(config.handshake.ours());
        let restored = cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .high_water()
            > 0;
        let mut metrics = MetricsRegistry::default();
        let feed_lag = FeedLagMetrics::register(&mut metrics);
        Self {
            inner: Arc::new(Inner {
                handshake: config.handshake,
                peer_uid: config.peer_uid,
                permits: Arc::new(Semaphore::new(config.limits.max_in_flight.max(1))),
                streams: Arc::new(Semaphore::new(config.limits.max_streams)),
                limits: config.limits,
                max_kzg_cells,
                cache,
                restored: Mutex::new(restored),
                snapshot: Arc::new(SnapshotWriter::new(
                    config.pubkey_snapshot,
                    config.snapshot_interval,
                )),
                bls,
                kzg,
                clock,
                contract_violations: AtomicU64::new(0),
                metrics,
                feed_lag,
            }),
        }
    }

    /// Contract violations seen so far (the contract-violation metric).
    #[must_use]
    pub fn contract_violations(&self) -> u64 {
        self.inner.contract_violations.load(Ordering::Relaxed)
    }

    /// The prometheus-client registry with cl-verify's metrics ([`crate::metrics`]), for the
    /// service runtime to serve.
    #[must_use]
    pub fn metrics_registry(&self) -> &MetricsRegistry {
        &self.inner.metrics
    }

    /// Snapshots written since start (the snapshot-save metric).
    #[must_use]
    pub fn snapshot_saves(&self) -> u64 {
        self.inner.snapshot.saves()
    }

    /// Snapshot saves that failed since start; each is retried on a later interval.
    #[must_use]
    pub fn snapshot_save_failures(&self) -> u64 {
        self.inner.snapshot.failures()
    }

    /// Writes the pubkey snapshot now if the cache has changed since the last save, ignoring the
    /// interval: `Ok(true)` if written. Before the cache is restored there is nothing to write.
    /// [`serve_uds`] calls this after a graceful shutdown; process start-up code that serves
    /// another way must call it before exiting.
    pub async fn flush_snapshot(&self) -> std::io::Result<bool> {
        self.inner.snapshot.save_if_dirty(&self.inner.cache).await
    }

    /// The tonic service, with the message cap enforced from the frame header before decode.
    #[must_use]
    pub fn into_service(self) -> VerifyServiceServer<Self> {
        VerifyServiceServer::new(self)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
    }
}

/// Serves `server` on a Unix socket until `shutdown` resolves, with the configured HTTP/2
/// keepalive and per-connection stream limit, then flushes a dirty pubkey snapshot
/// ([`VerifyServer::flush_snapshot`]; a failure is logged).
pub async fn serve_uds(
    listener: UnixListener,
    server: VerifyServer,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), tonic::transport::Error> {
    serve(listener, server, shutdown, None).await
}

/// [`serve_uds`] with a bounded shutdown: once `shutdown` resolves, open connections get `drain`
/// to finish before they are dropped. The snapshot is flushed once either way.
pub async fn serve_uds_draining(
    listener: UnixListener,
    server: VerifyServer,
    shutdown: impl Future<Output = ()> + Send,
    drain: Duration,
) -> Result<(), tonic::transport::Error> {
    serve(listener, server, shutdown, Some(drain)).await
}

async fn serve(
    listener: UnixListener,
    server: VerifyServer,
    shutdown: impl Future<Output = ()> + Send,
    drain: Option<Duration>,
) -> Result<(), tonic::transport::Error> {
    let limits = server.inner.limits.clone();
    let (begun, begun_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async move {
        shutdown.await;
        let _ = begun.send(());
    };
    let serving = tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(limits.http2_keepalive_interval))
        .http2_keepalive_timeout(Some(limits.http2_keepalive_timeout))
        .max_concurrent_streams(limits.max_concurrent_streams_per_connection)
        .add_service(server.clone().into_service())
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), shutdown);
    let drained = async move {
        match (drain, begun_rx.await) {
            (Some(drain), Ok(())) => tokio::time::sleep(drain).await,
            _ => std::future::pending().await,
        }
    };
    let served = tokio::select! {
        served = serving => served,
        () = drained => {
            tracing::warn!(?drain, "connections still open after the drain timeout; dropping them");
            Ok(())
        }
    };
    if let Err(e) = server.flush_snapshot().await {
        tracing::error!(error = %e, "pubkey snapshot not flushed at shutdown");
    }
    served
}

/// The UID of the Unix-socket peer, if the connection is a Unix socket with credentials.
fn peer_uid<T>(request: &Request<T>) -> Option<u32> {
    request
        .extensions()
        .get::<UdsConnectInfo>()
        .and_then(|info| info.peer_cred)
        .map(|cred| cred.uid())
}

/// `PERMISSION_DENIED` unless the peer is the configured UID. A peer without credentials (not a
/// Unix socket) is refused too.
#[allow(clippy::result_large_err)] // the handler returns this Status as is
fn authorize(allowed: u32, peer: Option<u32>) -> Result<(), Status> {
    match peer {
        Some(uid) if uid == allowed => Ok(()),
        other => {
            let who =
                other.map_or_else(|| "no peer credentials".to_string(), |u| format!("uid {u}"));
            let err = wire_error(
                ErrorCode::ContractViolation,
                format!("{who}: only cl-chain (uid {allowed}) may call cl-verify"),
            );
            Err(Status::with_details(
                Code::PermissionDenied,
                err.detail.clone(),
                prost::Message::encode_to_vec(&err).into(),
            ))
        }
    }
}

type Tx<T> = mpsc::Sender<Result<T, Status>>;

/// A request body with a per-stream `request_id`.
trait Numbered {
    fn request_id(&self) -> u64;
}

impl Numbered for VerifyBlsRequestBody {
    fn request_id(&self) -> u64 {
        self.request_id
    }
}

impl Numbered for VerifyKzgRequestBody {
    fn request_id(&self) -> u64 {
        self.request_id
    }
}

impl Inner {
    /// Peer check and a stream slot, before anything is read from the stream.
    #[allow(clippy::result_large_err)] // the handler returns this Status as is
    fn admit_stream<T>(&self, request: &Request<T>) -> Result<OwnedSemaphorePermit, Status> {
        if let Err(denied) = authorize(self.peer_uid, peer_uid(request)) {
            self.contract_violations.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(message = denied.message(), "verify peer refused");
            return Err(denied);
        }
        Arc::clone(&self.streams).try_acquire_owned().map_err(|_| {
            to_status(&wire_error(
                ErrorCode::Overloaded,
                format!("stream limit of {} reached", self.limits.max_streams),
            ))
        })
    }

    /// Logs, counts and sends the error that ends the stream.
    async fn fail<T>(&self, tx: &Tx<T>, err: Error) {
        self.record_failure(&err);
        let _ = tx.send(Err(to_status(&err))).await;
    }

    /// [`Self::fail`], giving up on the send after `limit`: for a peer that may have stopped
    /// reading, whose full response queue would otherwise hold the task forever.
    async fn fail_within<T>(&self, tx: &Tx<T>, err: Error, limit: Duration) {
        self.record_failure(&err);
        let _ = timeout(limit, tx.send(Err(to_status(&err)))).await;
    }

    fn record_failure(&self, err: &Error) {
        if err.code() == ErrorCode::ContractViolation {
            self.contract_violations.fetch_add(1, Ordering::Relaxed);
        }
        tracing::warn!(code = ?err.code(), detail = %err.detail, "verify stream failed");
    }

    /// Reads and checks the peer's hello within the hello timeout, then sends ours. `false` if
    /// the stream already failed.
    async fn open<S, Req, Resp>(&self, inbound: &mut Inbound<S>, tx: &Tx<Resp>) -> bool
    where
        S: Stream<Item = Result<Req, Status>> + Unpin,
        Req: InFrame,
        Resp: OutFrame,
    {
        let hello = timeout(self.limits.hello_timeout, inbound.hello())
            .await
            .unwrap_or_else(|_| {
                Err(wire_error(
                    ErrorCode::ContractViolation,
                    format!("no hello within {:?}", self.limits.hello_timeout),
                ))
            });
        match hello.and_then(|theirs| self.handshake.accept(&theirs)) {
            Ok(_) => tx
                .send(Ok(Resp::hello(self.handshake.ours().clone())))
                .await
                .is_ok(),
            Err(e) => {
                self.fail(tx, e).await;
                false
            }
        }
    }

    /// Restores the cache from this stream's first frame on a blocking thread (see
    /// [`feed::restore`]) and returns the stream with the epochs of the frame that completed the
    /// restore, or the error that fails it. The caller sends that error once it has released the
    /// restore lock.
    async fn restore_cache<S>(
        &self,
        inbound: Inbound<S>,
        tx: &Tx<PubkeyFeedResponse>,
    ) -> Result<(Inbound<S>, FrameEpochs), Error>
    where
        S: FeedInbound,
    {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| wire_error(ErrorCode::ResourceUnavailable, "verify server closed"))?;
        let mut link = feed::StreamLink::new(
            inbound,
            tx.clone(),
            Handle::current(),
            self.limits.restore_frame_timeout,
        );
        let (cache, snapshot) = (Arc::clone(&self.cache), self.snapshot.path().to_path_buf());
        let job = spawn_blocking(move || {
            let _permit = permit;
            let outcome = feed::restore(&cache, &snapshot, &mut link);
            (outcome, link)
        });
        let err = match job.await {
            Ok((Ok((outcome, epochs)), link)) => {
                match &outcome {
                    Restored::Rebuilt(_) => self.snapshot.mark_dirty(),
                    Restored::Loaded => self.snapshot.note_committed(
                        self.cache
                            .read()
                            .unwrap_or_else(PoisonError::into_inner)
                            .high_water(),
                    ),
                }
                self.snapshot.start(&self.cache);
                tracing::info!(
                    ?outcome,
                    high_water = self
                        .cache
                        .read()
                        .unwrap_or_else(PoisonError::into_inner)
                        .high_water(),
                    "pubkey cache restored"
                );
                return Ok((link.into_inbound(), epochs));
            }
            Ok((Err(err), _)) => err,
            Err(join) => wire_error(
                ErrorCode::ResourceUnavailable,
                format!("pubkey cache restore failed: {join}"),
            ),
        };
        Err(err)
    }

    /// Publishes the lag for an applied frame's (or a completed restore's) epochs. They passed
    /// the check before; an update that a higher chain epoch from another stream has overtaken
    /// since is dropped, so the gauges never move back.
    fn publish_feed_lag(&self, epochs: FrameEpochs) {
        let FrameEpochs {
            feed_finalized_epoch,
            chain_finalized_epoch,
        } = epochs;
        if let Err(e) = self
            .feed_lag
            .update(feed_finalized_epoch, chain_finalized_epoch)
        {
            tracing::debug!(error = %e, "feed-lag update overtaken; not published");
        }
    }

    /// A verifier slot for a request with `deadline_unix_ms`, or the status to answer instead.
    fn admit(
        &self,
        deadline_unix_ms: u64,
    ) -> Result<(Deadline, OwnedSemaphorePermit), VerifyStatus> {
        let deadline = Deadline::new(deadline_unix_ms, self.clock.as_ref())
            .ok_or(VerifyStatus::DeadlineExceeded)?;
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| VerifyStatus::Overloaded)?;
        Ok((deadline, permit))
    }

    /// `None` if the stream closed before the request's signers were resolved.
    async fn verify_bls(
        self: Arc<Self>,
        body: VerifyBlsRequestBody,
        closed: Arc<AtomicBool>,
    ) -> Option<VerifyBlsResponseBody> {
        let request_id = body.request_id;
        let n = body.sets.len();
        let results = match self.admit(body.deadline_unix_ms) {
            Err(status) => bls::all_status(n, status),
            Ok((deadline, permit)) => {
                let inner = Arc::clone(&self);
                let work = spawn_blocking(move || {
                    let _permit = permit;
                    bls::verify_request_gated(
                        &body,
                        &closed,
                        inner.clock.as_ref(),
                        &inner.cache,
                        inner.bls.as_ref(),
                    )
                });
                match by_deadline(&deadline, self.clock.as_ref(), work).await {
                    Some(Ok(Some(results))) => results,
                    Some(Ok(None)) => return None,
                    Some(Err(join)) => {
                        tracing::error!(error = %join, "BLS verifier failed");
                        (0..n)
                            .map(|_| {
                                bls::error(ErrorCode::ResourceUnavailable, "BLS verifier failed")
                            })
                            .collect()
                    }
                    None => bls::all_status(n, VerifyStatus::DeadlineExceeded),
                }
            }
        };
        let violations = results
            .iter()
            .filter(|r| matches!(&r.result, Some(bls_result::Result::Err(e)) if e.code() == ErrorCode::ContractViolation))
            .count();
        if violations > 0 {
            self.contract_violations
                .fetch_add(violations as u64, Ordering::Relaxed);
            tracing::warn!(
                request_id,
                violations,
                "BLS sets refused as contract violations"
            );
        }
        Some(VerifyBlsResponseBody {
            request_id,
            results,
        })
    }

    /// `None` if the stream closed before the cells were verified.
    async fn verify_kzg(
        self: Arc<Self>,
        body: VerifyKzgRequestBody,
        closed: Arc<AtomicBool>,
    ) -> Option<VerifyKzgResponseBody> {
        let request_id = body.request_id;
        let (status, err) = match self.admit(body.deadline_unix_ms) {
            Err(status) => (status, None),
            Ok((deadline, permit)) => {
                let inner = Arc::clone(&self);
                let work = spawn_blocking(move || {
                    let _permit = permit;
                    if closed.load(Ordering::SeqCst) {
                        return None;
                    }
                    // The job may have waited for a blocking thread past its deadline.
                    if !bls::deadline_open(body.deadline_unix_ms, inner.clock.now_unix_ms()) {
                        return Some((VerifyStatus::DeadlineExceeded, None));
                    }
                    Some(kzg::verify_cells(&body.cells, inner.kzg.as_ref()))
                });
                match by_deadline(&deadline, self.clock.as_ref(), work).await {
                    Some(Ok(Some(verdict))) => verdict,
                    Some(Ok(None)) => return None,
                    Some(Err(join)) => {
                        tracing::error!(error = %join, "KZG verifier failed");
                        kzg::unavailable("KZG verifier failed")
                    }
                    None => (VerifyStatus::DeadlineExceeded, None),
                }
            }
        };
        Some(VerifyKzgResponseBody {
            request_id,
            status: status as i32,
            err,
        })
    }
}

/// Shared loop for the two verification RPCs: hello, then for each body a per-stream slot is
/// taken before it is read, its `request_id` must exceed the previous one, it is cap-checked, and
/// it is handed to `verify` on its own task, which frees the slot once the response is queued.
///
/// The stream counts as closed once the peer's side breaks, the server fails the stream, or the
/// peer stops listening for responses; queued requests then resolve nothing and are dropped
/// unanswered. A clean end of the request side (half-close) is not a close: requests already read
/// are still answered.
fn spawn_verify_stream<Req, Resp, Cap, Run, Fut>(
    inner: Arc<Inner>,
    stream_slot: OwnedSemaphorePermit,
    inbound: Streaming<Req>,
    cap: Cap,
    verify: Run,
) -> ReceiverStream<Result<Resp, Status>>
where
    Req: InFrame + Send + 'static,
    Req::Body: Numbered + Send + 'static,
    Resp: OutFrame + Send + 'static,
    Resp::Body: Send,
    Cap: Fn(&Inner, &Req::Body) -> Result<(), CapError> + Send + 'static,
    Run: Fn(Arc<Inner>, Req::Body, Arc<AtomicBool>) -> Fut + Send + 'static,
    Fut: Future<Output = Option<Resp::Body>> + Send + 'static,
{
    let (tx, rx) = mpsc::channel(RESPONSE_BUFFER);
    tokio::spawn(async move {
        let _stream_slot = stream_slot;
        let mut inbound = Inbound::new(inbound);
        if !inner.open(&mut inbound, &tx).await {
            return;
        }
        let closed = Arc::new(AtomicBool::new(false));
        let watch = {
            let (tx, closed) = (tx.clone(), Arc::clone(&closed));
            tokio::spawn(async move {
                tx.closed().await;
                closed.store(true, Ordering::SeqCst);
            })
        };
        let close = |closed: &AtomicBool| closed.store(true, Ordering::SeqCst);
        let outstanding_max = inner.limits.max_outstanding_per_stream.max(1);
        let outstanding = Arc::new(Semaphore::new(outstanding_max));
        let mut last_id: Option<u64> = None;
        loop {
            let Ok(slot) = Arc::clone(&outstanding).acquire_owned().await else {
                return;
            };
            let body = match inbound.body().await {
                Ok(Some(body)) => body,
                Ok(None) => break,
                Err(e) => {
                    close(&closed);
                    inner.fail(&tx, e).await;
                    break;
                }
            };
            let id = body.request_id();
            if let Some(last) = last_id.filter(|last| id <= *last) {
                let err = wire_error(
                    ErrorCode::ContractViolation,
                    format!("request_id {id} does not increase on {last}"),
                );
                close(&closed);
                inner.fail(&tx, err).await;
                break;
            }
            last_id = Some(id);
            if let Err(breach) = cap(&inner, &body) {
                close(&closed);
                inner.fail(&tx, breach.to_wire()).await;
                break;
            }
            let tx = tx.clone();
            let job = verify(Arc::clone(&inner), body, Arc::clone(&closed));
            tokio::spawn(async move {
                if let Some(reply) = job.await {
                    let _ = tx.send(Ok(Resp::body(reply))).await;
                }
                drop(slot);
            });
        }
        // Keep watching for the peer going away until every queued job has finished, then end
        // the response stream.
        let all = u32::try_from(outstanding_max).unwrap_or(u32::MAX);
        let _ = outstanding.acquire_many(all).await;
        watch.abort();
    });
    ReceiverStream::new(rx)
}

/// A PubkeyFeed request stream (tonic's `Streaming` in production).
trait FeedInbound: Stream<Item = Result<PubkeyFeedRequest, Status>> + Unpin + Send + 'static {}

impl<S> FeedInbound for S where
    S: Stream<Item = Result<PubkeyFeedRequest, Status>> + Unpin + Send + 'static
{
}

/// One PubkeyFeed stream: hello, the restore (or the first-frame check on a restored server),
/// then one reply per frame.
async fn run_feed<S: FeedInbound>(
    inner: Arc<Inner>,
    mut inbound: Inbound<S>,
    tx: Tx<PubkeyFeedResponse>,
) {
    if !inner.open(&mut inbound, &tx).await {
        return;
    }
    // One restore at a time; a stream that finds it done goes straight on.
    let mut restored = inner.restored.lock().await;
    // The high-water mark goes first so the sender knows where to start.
    let first = PubkeyFeedResponse::body(feed::status(&inner.cache));
    if tx.send(Ok(first)).await.is_err() {
        return;
    }
    let mut check_first = *restored;
    if *restored {
        drop(restored);
    } else {
        let epochs;
        (inbound, epochs) = match inner.restore_cache(inbound, &tx).await {
            Ok(back) => back,
            Err(err) => {
                // Release the restore first: the peer may have stopped reading, and the next
                // stream must not wait behind this one's last send.
                drop(restored);
                let limit = inner.limits.restore_frame_timeout;
                return inner.fail_within(&tx, err, limit).await;
            }
        };
        *restored = true;
        drop(restored);
        // The restored cache holds the announced registry: evaluate the lag once now, since a
        // stalled finality may send no further frame for a long time.
        inner.publish_feed_lag(epochs);
        let reply = PubkeyFeedResponse::body(feed::status(&inner.cache));
        if tx.send(Ok(reply)).await.is_err() {
            return;
        }
    }
    loop {
        let body = match inbound.body().await {
            Ok(Some(body)) => body,
            Ok(None) if check_first => {
                let err = wire_error(
                    ErrorCode::ContractViolation,
                    "pubkey feed closed before its first frame",
                );
                return inner.fail(&tx, err).await;
            }
            Ok(None) => return,
            Err(e) => return inner.fail(&tx, e).await,
        };
        if std::mem::take(&mut check_first) {
            if let Err(e) = feed::check_first_frame(&inner.cache, &body) {
                return inner.fail(&tx, e).await;
            }
        }
        let cache = Arc::clone(&inner.cache);
        let appends = !body.pubkeys.is_empty();
        let epochs = FrameEpochs::of(&body);
        let reply = match inner
            .feed_lag
            .check(epochs.feed_finalized_epoch, epochs.chain_finalized_epoch)
        {
            // Refused before it is applied: the gauges keep their values.
            Err(e) => PubkeyFeedResponseBody {
                high_water: feed::status(&cache).high_water,
                err: Some(wire_error(ErrorCode::ContractViolation, e.to_string())),
            },
            Ok(()) => {
                // Feed frames wait for a verifier slot like any other blocking job.
                let Ok(permit) = Arc::clone(&inner.permits).acquire_owned().await else {
                    return;
                };
                let job = spawn_blocking(move || {
                    let _permit = permit;
                    feed::apply(&cache, &body)
                });
                match job.await {
                    Ok(reply) => reply,
                    Err(join) => {
                        let err = wire_error(
                            ErrorCode::ResourceUnavailable,
                            format!("pubkey feed failed: {join}"),
                        );
                        return inner.fail(&tx, err).await;
                    }
                }
            }
        };
        if reply.err.is_none() {
            // Applied: its epochs describe the cache as it now is.
            inner.publish_feed_lag(epochs);
        }
        if appends && reply.err.is_none() {
            // high_water advanced: the snapshot is behind the cache.
            inner.snapshot.mark_dirty();
            inner.snapshot.start(&inner.cache);
        }
        if let Some(err) = &reply.err {
            if err.code() == ErrorCode::ContractViolation {
                inner.contract_violations.fetch_add(1, Ordering::Relaxed);
            }
            tracing::warn!(code = ?err.code(), detail = %err.detail, "pubkey feed frame refused");
        }
        if tx.send(Ok(PubkeyFeedResponse::body(reply))).await.is_err() {
            return;
        }
    }
}

#[tonic::async_trait]
impl VerifyService for VerifyServer {
    type VerifyBlsStream = ReceiverStream<Result<VerifyBlsResponse, Status>>;
    type VerifyKzgStream = ReceiverStream<Result<VerifyKzgResponse, Status>>;
    type PubkeyFeedStream = ReceiverStream<Result<PubkeyFeedResponse, Status>>;

    async fn verify_bls(
        &self,
        request: Request<Streaming<VerifyBlsRequest>>,
    ) -> Result<Response<Self::VerifyBlsStream>, Status> {
        let slot = self.inner.admit_stream(&request)?;
        Ok(Response::new(spawn_verify_stream(
            Arc::clone(&self.inner),
            slot,
            request.into_inner(),
            |_, body| caps::check_bls(body),
            Inner::verify_bls,
        )))
    }

    async fn verify_kzg(
        &self,
        request: Request<Streaming<VerifyKzgRequest>>,
    ) -> Result<Response<Self::VerifyKzgStream>, Status> {
        let slot = self.inner.admit_stream(&request)?;
        Ok(Response::new(spawn_verify_stream(
            Arc::clone(&self.inner),
            slot,
            request.into_inner(),
            |inner, body| caps::check_kzg(body, inner.max_kzg_cells),
            Inner::verify_kzg,
        )))
    }

    async fn pubkey_feed(
        &self,
        request: Request<Streaming<PubkeyFeedRequest>>,
    ) -> Result<Response<Self::PubkeyFeedStream>, Status> {
        let slot = self.inner.admit_stream(&request)?;
        let inner = Arc::clone(&self.inner);
        let (tx, rx) = mpsc::channel(RESPONSE_BUFFER);
        let inbound = Inbound::new(request.into_inner());
        tokio::spawn(async move {
            let _stream_slot = slot;
            run_feed(inner, inbound, tx).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::error_from_status;

    #[test]
    fn only_the_configured_uid_is_authorized() {
        assert!(authorize(501, Some(501)).is_ok());
        for peer in [Some(0), Some(502), None] {
            let status = authorize(501, peer).unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied);
            assert_eq!(
                error_from_status(&status).code(),
                ErrorCode::ContractViolation
            );
        }
    }

    #[test]
    fn request_without_uds_info_has_no_peer_uid() {
        assert_eq!(peer_uid(&Request::new(())), None);
    }
}

#[cfg(test)]
mod feed_tests {
    //! PubkeyFeed streams driven directly, so a test controls each response queue.

    use super::*;
    use crate::kzg::{KzgFailure, PreparedCells};
    use crate::proto::common::Hello;
    use crate::proto::verify::{
        pubkey_feed_request, pubkey_feed_response, FinalizedRegistry, PubkeyFeedRequestBody,
    };
    use blst::min_pk::SecretKey;
    use cl_verify_cache::persist::Registry;

    struct NoKzg;

    impl KzgBackend for NoKzg {
        fn verify(&self, _: &PreparedCells) -> Result<bool, KzgFailure> {
            Ok(true)
        }
    }

    fn hello() -> Hello {
        Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 1,
            ..Hello::default()
        }
    }

    fn server(dir: &tempfile::TempDir, restore_frame_timeout: Duration) -> Arc<Inner> {
        let config = ServerConfig {
            handshake: Handshake::new(hello(), 1),
            peer_uid: 0,
            trusted_setup: TrustedSetupConfig {
                path: PathBuf::from("/unused"),
            },
            limits: Limits {
                restore_frame_timeout,
                ..Limits::default()
            },
            pubkey_snapshot: dir.path().join("pubkeys.bin"),
            snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
        };
        let cache = SharedCache::default();
        VerifyServer::with_backends(config, cache, Arc::new(BlstBackend), Arc::new(NoKzg)).inner
    }

    fn key(i: u64) -> Vec<u8> {
        let mut ikm = [5u8; 32];
        ikm[..8].copy_from_slice(&i.to_le_bytes());
        SecretKey::key_gen(&ikm, &[])
            .unwrap()
            .sk_to_pk()
            .compress()
            .to_vec()
    }

    /// The first frame of a rebuild of `0..n`, carrying index 0 only.
    fn announcing(n: u64) -> PubkeyFeedRequest {
        let keys: Vec<_> = (0..n)
            .map(|i| blst::min_pk::PublicKey::key_validate(&key(i)).unwrap())
            .collect();
        let registry = Registry::of(&feed::BlstCodec, &keys);
        PubkeyFeedRequest {
            frame: Some(pubkey_feed_request::Frame::Body(PubkeyFeedRequestBody {
                start_index: 0,
                count: 1,
                pubkeys: vec![key(0)],
                finalized_registry: Some(FinalizedRegistry {
                    len: registry.len,
                    sha256: registry.sha256.to_vec(),
                }),
                feed_finalized_epoch: 0,
                chain_finalized_epoch: 0,
            })),
        }
    }

    fn hello_frame() -> PubkeyFeedRequest {
        PubkeyFeedRequest {
            frame: Some(pubkey_feed_request::Frame::Hello(hello())),
        }
    }

    /// A request stream that delivers `frames`, then stays open.
    fn inbound(
        frames: Vec<PubkeyFeedRequest>,
    ) -> Inbound<impl Stream<Item = Result<PubkeyFeedRequest, Status>> + Unpin + Send + 'static>
    {
        let frames = tokio_stream::iter(frames.into_iter().map(Ok));
        Inbound::new(tokio_stream::StreamExt::chain(
            frames,
            tokio_stream::pending(),
        ))
    }

    fn high_water(frame: Option<Result<PubkeyFeedResponse, Status>>) -> u64 {
        match frame {
            Some(Ok(PubkeyFeedResponse {
                frame: Some(pubkey_feed_response::Frame::Body(b)),
            })) => b.high_water,
            other => panic!("expected a feed reply, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_that_stops_reading_during_a_restore_does_not_block_the_next_restore() {
        let dir = tempfile::tempdir().unwrap();
        let inner = server(&dir, Duration::from_millis(200));
        // Stream A never reads: its queue holds the hello and the status, so the rebuild's first
        // reply times out and the restore fails while the queue is still full.
        let (a_tx, _a_rx) = mpsc::channel(2);
        let full = a_tx.clone();
        let a = tokio::spawn(run_feed(
            Arc::clone(&inner),
            inbound(vec![hello_frame(), announcing(2)]),
            a_tx,
        ));
        for _ in 0..500 {
            if full.capacity() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(full.capacity(), 0, "stream A holds the restore");

        // Stream B restores a one-entry registry once A has given up.
        let (b_tx, mut b_rx) = mpsc::channel(RESPONSE_BUFFER);
        tokio::spawn(run_feed(
            Arc::clone(&inner),
            inbound(vec![hello_frame(), announcing(1)]),
            b_tx,
        ));
        let restored = tokio::time::timeout(Duration::from_secs(5), async {
            let _hello = b_rx.recv().await;
            (high_water(b_rx.recv().await), high_water(b_rx.recv().await))
        })
        .await
        .expect("stream B restored within 5 s");
        assert_eq!(restored, (0, 1));
        tokio::time::timeout(Duration::from_secs(5), a)
            .await
            .expect("stream A ended")
            .unwrap();
        assert_eq!(inner.contract_violations.load(Ordering::Relaxed), 1);
    }
}
