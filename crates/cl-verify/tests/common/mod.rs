//! Test harness: a real tonic `VerifyService` on a Unix socket in a temp dir, a client channel over
//! it, stream helpers that do the hello exchange, and a tiny reader for the YAML fixtures.
#![allow(dead_code, clippy::result_large_err)] // tonic::Status is large; shared by several test crates

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use blst::min_pk::{PublicKey, SecretKey, Signature};
use cl_verify::bls::{BlsBackend, BlstBackend, DST};
use cl_verify::feed::SharedCache;
use cl_verify::handshake::Handshake;
use cl_verify::kzg::{KzgBackend, PinnedKzgBackend, TrustedSetupConfig};
use cl_verify::proto::common::{
    BlobScheduleEntry, Error, ErrorCode, ForkName, ForkScheduleEntry, Hello, SpecPin,
};
use cl_verify::proto::verify::verify_service_client::VerifyServiceClient;
use cl_verify::proto::verify::*;
use cl_verify::server::{
    serve_uds, serve_uds_draining, Limits, ServeError, ServerConfig, VerifyServer,
    DEFAULT_SNAPSHOT_INTERVAL,
};
use cl_verify::wire::{error_from_status, now_unix_ms, SystemClock, WallClock};
use hyper_util::rt::TokioIo;
use ipc::fence::{FencedRequest, Outstanding, RequestTag};
use ipc::hello::Generation;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Status, Streaming};

pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn hello() -> Hello {
    Hello {
        api_version: 1,
        build: "cl-chain/test".into(),
        genesis_validators_root: vec![0x4b; 32],
        current_fork_digest: vec![0xaa, 0xbb, 0xcc, 0xdd],
        spec_pin: Some(SpecPin {
            consensus_specs_tag: "v1.7.0-beta.4".into(),
            ssz_specs_tag: "v0.1.0".into(),
        }),
        fork_schedule: vec![
            ForkScheduleEntry {
                epoch: 0,
                fork_digest: vec![0xaa, 0xbb, 0xcc, 0xdd],
                fork: ForkName::Fulu as i32,
                fork_version: vec![0x06, 0, 0, 0],
                max_blobs_per_block: 9,
            },
            ForkScheduleEntry {
                epoch: 1000,
                fork_digest: vec![0x11, 0x22, 0x33, 0x44],
                fork: ForkName::Gloas as i32,
                fork_version: vec![0x07, 0, 0, 0],
                max_blobs_per_block: 21,
            },
        ],
        blob_schedule: vec![BlobScheduleEntry {
            epoch: 500,
            max_blobs_per_block: 15,
        }],
        min_api_version: 1,
        max_api_version: 1,
        generation: 0,
    }
}

/// crypto-kzg's vendored consensus-specs v1.7.0-beta.4 mainnet setup (the pinned one).
pub fn setup_config() -> TrustedSetupConfig {
    TrustedSetupConfig {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../crypto-kzg/data/trusted_setup_4096.json"),
    }
}

/// A copy of the pinned setup with one byte changed, in `dir`. It is still well-formed JSON with
/// valid points, so only the digest pin can refuse it.
pub fn tampered_setup(dir: &Path) -> TrustedSetupConfig {
    let mut bytes = std::fs::read(setup_config().path).unwrap();
    let at = bytes.windows(2).position(|w| w == b"0x").unwrap() + 2;
    bytes[at] = if bytes[at] == b'a' { b'b' } else { b'a' };
    let path = dir.join("trusted_setup_4096.json");
    std::fs::write(&path, &bytes).unwrap();
    TrustedSetupConfig { path }
}

pub fn kzg_backend() -> Arc<PinnedKzgBackend> {
    static B: OnceLock<Arc<PinnedKzgBackend>> = OnceLock::new();
    B.get_or_init(|| Arc::new(PinnedKzgBackend::load(&setup_config()).unwrap()))
        .clone()
}

/// This process's UID (the owner of a file it just created).
pub fn my_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::metadata(dir.path()).unwrap().uid()
}

/// A snapshot path that is never written (its directory does not exist): every restore rebuilds.
pub fn no_snapshot() -> PathBuf {
    PathBuf::from("/nonexistent/cl-verify-test/pubkeys.bin")
}

pub fn config(peer_uid: u32, limits: Limits) -> ServerConfig {
    ServerConfig {
        handshake: Handshake::new(hello(), 1),
        peer_uid,
        trusted_setup: setup_config(),
        limits,
        pubkey_snapshot: no_snapshot(),
        snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
    }
}

pub struct Options {
    pub bls: Arc<dyn BlsBackend>,
    pub kzg: Arc<dyn KzgBackend>,
    pub limits: Limits,
    /// UID the server accepts; `None` means this process's.
    pub peer_uid: Option<u32>,
    pub cache: SharedCache,
    pub clock: Arc<dyn WallClock>,
    /// The pubkey snapshot path; `None` means `pubkeys.bin` in the harness's temp dir.
    pub snapshot: Option<PathBuf>,
    /// The snapshot save interval; `None` means the default.
    pub snapshot_interval: Option<Duration>,
    /// Serve with `serve_uds_draining` and this drain timeout; `None` means `serve_uds`.
    pub drain: Option<Duration>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            bls: Arc::new(BlstBackend),
            kzg: kzg_backend(),
            limits: Limits::default(),
            peer_uid: None,
            cache: SharedCache::default(),
            clock: Arc::new(SystemClock),
            snapshot: None,
            snapshot_interval: None,
            drain: None,
        }
    }
}

pub struct Harness {
    pub server: VerifyServer,
    pub client: VerifyServiceClient<Channel>,
    pub cache: SharedCache,
    /// The Unix socket the server listens on.
    pub socket: PathBuf,
    _dir: tempfile::TempDir,
    shutdown: Option<oneshot::Sender<()>>,
    serving: tokio::task::JoinHandle<Result<(), ServeError>>,
}

impl Harness {
    /// Graceful shutdown: closes the client, signals the server and waits for `serve_uds` to
    /// return (after its snapshot flush).
    pub async fn shutdown(self) {
        let Harness {
            client,
            shutdown,
            serving,
            ..
        } = self;
        drop(client);
        if let Some(tx) = shutdown {
            let _ = tx.send(());
        }
        served(serving).await.unwrap();
    }

    /// Signals the server to shut down; returns at once.
    pub fn begin_shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }

    /// Waits up to 20 s for the server to return, and returns what it returned.
    pub async fn served(self) -> Result<(), ServeError> {
        served(self.serving).await
    }
}

async fn served(
    serving: tokio::task::JoinHandle<Result<(), ServeError>>,
) -> Result<(), ServeError> {
    tokio::time::timeout(Duration::from_secs(20), serving)
        .await
        .expect("server shut down within 20 s")
        .unwrap()
}

pub async fn start() -> Harness {
    start_with(Options::default()).await
}

pub async fn start_with(o: Options) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verify.sock");
    let mut config = config(o.peer_uid.unwrap_or_else(my_uid), o.limits);
    config.pubkey_snapshot = o.snapshot.unwrap_or_else(|| dir.path().join("pubkeys.bin"));
    if let Some(interval) = o.snapshot_interval {
        config.snapshot_interval = interval;
    }
    let server =
        VerifyServer::with_backends_and_clock(config, o.cache.clone(), o.bls, o.kzg, o.clock);
    serve_on(&path, server.clone(), dir, o.cache, o.drain).await
}

/// Serves `server` on a Unix socket at `path` (draining for `drain` at shutdown, if given) and
/// connects a client.
pub async fn serve_on(
    path: &Path,
    server: VerifyServer,
    dir: tempfile::TempDir,
    cache: SharedCache,
    drain: Option<Duration>,
) -> Harness {
    let listener = UnixListener::bind(path).unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let stop = async {
        let _ = rx.await;
    };
    let serving = match drain {
        Some(drain) => tokio::spawn(serve_uds_draining(listener, server.clone(), stop, drain)),
        None => tokio::spawn(serve_uds(listener, server.clone(), stop)),
    };
    let client = VerifyServiceClient::new(connect(path).await);
    Harness {
        server,
        client,
        cache,
        socket: path.to_path_buf(),
        _dir: dir,
        shutdown: Some(tx),
        serving,
    }
}

pub async fn connect(path: &Path) -> Channel {
    let path = path.to_path_buf();
    Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap()
}

/// Client end of one bidi stream, before or after the hello exchange.
pub struct Bidi<Req, Resp> {
    pub tx: mpsc::Sender<Req>,
    pub rx: Streaming<Resp>,
    /// The server generation the server's hello announced; 0 before the hello exchange.
    pub generation: u64,
}

/// A request that carries the stream's server generation in its body.
pub trait Stamp {
    /// Sets the body's `generation` to `generation` unless the test set one itself.
    fn stamp(&mut self, generation: u64);
}

impl Stamp for VerifyBlsRequest {
    fn stamp(&mut self, generation: u64) {
        if let Some(verify_bls_request::Frame::Body(b)) = &mut self.frame {
            if b.generation == 0 {
                b.generation = generation;
            }
        }
    }
}

impl Stamp for VerifyKzgRequest {
    fn stamp(&mut self, generation: u64) {
        if let Some(verify_kzg_request::Frame::Body(b)) = &mut self.frame {
            if b.generation == 0 {
                b.generation = generation;
            }
        }
    }
}

impl Stamp for PubkeyFeedRequest {
    fn stamp(&mut self, _: u64) {}
}

impl<Req: Stamp, Resp> Bidi<Req, Resp> {
    /// Sends `req`, its body stamped with the stream's server generation (see [`Stamp`]).
    pub async fn send(&self, mut req: Req) {
        req.stamp(self.generation);
        self.send_unstamped(req).await;
    }

    /// Sends `req` exactly as given.
    pub async fn send_unstamped(&self, req: Req) {
        self.tx.send(req).await.unwrap();
    }
}

impl<Req, Resp> Bidi<Req, Resp> {
    /// The client's table of outstanding requests for this stream, after the hello exchange.
    pub fn outstanding(&self) -> Outstanding {
        Outstanding::new(
            Generation::new(self.generation).expect("hello exchange done"),
            64,
        )
    }

    pub async fn next(&mut self) -> Result<Option<Resp>, Status> {
        tokio::time::timeout(Duration::from_secs(20), self.rx.message())
            .await
            .expect("server answered within 20 s")
    }

    /// The stream must fail; returns the wire error it failed with.
    pub async fn expect_failure(&mut self) -> Error {
        loop {
            match self.next().await {
                Err(status) => return error_from_status(&status),
                Ok(Some(_)) => continue,
                Ok(None) => panic!("stream ended without an error"),
            }
        }
    }
}

pub type BlsStream = Bidi<VerifyBlsRequest, VerifyBlsResponse>;
pub type KzgStream = Bidi<VerifyKzgRequest, VerifyKzgResponse>;
pub type FeedStream = Bidi<PubkeyFeedRequest, PubkeyFeedResponse>;

pub fn bls_hello(h: Hello) -> VerifyBlsRequest {
    VerifyBlsRequest {
        frame: Some(verify_bls_request::Frame::Hello(h)),
    }
}
pub fn bls_body(b: VerifyBlsRequestBody) -> VerifyBlsRequest {
    VerifyBlsRequest {
        frame: Some(verify_bls_request::Frame::Body(b)),
    }
}
pub fn kzg_hello(h: Hello) -> VerifyKzgRequest {
    VerifyKzgRequest {
        frame: Some(verify_kzg_request::Frame::Hello(h)),
    }
}
pub fn kzg_body(b: VerifyKzgRequestBody) -> VerifyKzgRequest {
    VerifyKzgRequest {
        frame: Some(verify_kzg_request::Frame::Body(b)),
    }
}
pub fn feed_hello(h: Hello) -> PubkeyFeedRequest {
    PubkeyFeedRequest {
        frame: Some(pubkey_feed_request::Frame::Hello(h)),
    }
}
pub fn feed_body(b: PubkeyFeedRequestBody) -> PubkeyFeedRequest {
    PubkeyFeedRequest {
        frame: Some(pubkey_feed_request::Frame::Body(b)),
    }
}

/// Opens a BLS stream without sending anything.
pub async fn bls_raw(h: &mut Harness) -> BlsStream {
    let (tx, rx) = mpsc::channel(8);
    let rx = h
        .client
        .verify_bls(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    Bidi {
        tx,
        rx,
        generation: 0,
    }
}

/// Opens a BLS stream and completes the hello exchange.
pub async fn bls_open(h: &mut Harness) -> BlsStream {
    let mut s = bls_raw(h).await;
    s.send(bls_hello(hello())).await;
    match s.next().await.unwrap().unwrap().frame {
        Some(verify_bls_response::Frame::Hello(server)) => s.generation = server_generation(server),
        other => panic!("first server frame is not hello: {other:?}"),
    }
    s
}

/// The generation of the server's hello, which must be ours in every other field.
pub fn server_generation(server: Hello) -> u64 {
    assert_ne!(server.generation, 0, "server hello has generation 0");
    let generation = server.generation;
    assert_eq!(
        Hello {
            generation: 0,
            ..server
        },
        hello()
    );
    generation
}

pub async fn kzg_raw(h: &mut Harness) -> KzgStream {
    let (tx, rx) = mpsc::channel(8);
    let rx = h
        .client
        .verify_kzg(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    Bidi {
        tx,
        rx,
        generation: 0,
    }
}

pub async fn kzg_open(h: &mut Harness) -> KzgStream {
    let mut s = kzg_raw(h).await;
    s.send(kzg_hello(hello())).await;
    match s.next().await.unwrap().unwrap().frame {
        Some(verify_kzg_response::Frame::Hello(server)) => s.generation = server_generation(server),
        other => panic!("first server frame is not hello: {other:?}"),
    }
    s
}

pub async fn feed_raw(h: &mut Harness) -> FeedStream {
    let (tx, rx) = mpsc::channel(8);
    let rx = h
        .client
        .pubkey_feed(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    Bidi {
        tx,
        rx,
        generation: 0,
    }
}

/// Opens a feed stream, completes the hello exchange and returns the first high-water report.
pub async fn feed_open(h: &mut Harness) -> (FeedStream, u64) {
    let mut s = feed_raw(h).await;
    s.send(feed_hello(hello())).await;
    match s.next().await.unwrap().unwrap().frame {
        Some(pubkey_feed_response::Frame::Hello(server)) => {
            s.generation = server_generation(server)
        }
        other => panic!("first server frame is not hello: {other:?}"),
    }
    let first = feed_reply(&mut s).await;
    assert_eq!(first.err, None);
    (s, first.high_water)
}

pub async fn bls_reply(s: &mut BlsStream) -> VerifyBlsResponseBody {
    match s.next().await.unwrap().unwrap().frame {
        Some(verify_bls_response::Frame::Body(b)) => b,
        other => panic!("expected a body frame: {other:?}"),
    }
}

pub async fn kzg_reply(s: &mut KzgStream) -> VerifyKzgResponseBody {
    match s.next().await.unwrap().unwrap().frame {
        Some(verify_kzg_response::Frame::Body(b)) => b,
        other => panic!("expected a body frame: {other:?}"),
    }
}

pub async fn feed_reply(s: &mut FeedStream) -> PubkeyFeedResponseBody {
    match s.next().await.unwrap().unwrap().frame {
        Some(pubkey_feed_response::Frame::Body(b)) => b,
        other => panic!("expected a body frame: {other:?}"),
    }
}

pub fn far_deadline() -> u64 {
    now_unix_ms() + 30_000
}

/// An import request (inline keys allowed past the high-water mark).
pub fn bls_request(request_id: u64, sets: Vec<BlsSet>) -> VerifyBlsRequestBody {
    bls_request_from(request_id, sets, VerifyOrigin::Import)
}

pub fn bls_request_from(
    request_id: u64,
    sets: Vec<BlsSet>,
    origin: VerifyOrigin,
) -> VerifyBlsRequestBody {
    VerifyBlsRequestBody {
        request_id,
        sets,
        deadline_unix_ms: far_deadline(),
        origin: origin as i32,
        generation: 0,
    }
}

/// Files `body` as the next request in `out`: its `request_id` and `generation` become the
/// issued tag's.
pub fn file_bls(
    out: &mut Outstanding,
    body: VerifyBlsRequestBody,
) -> (RequestTag, VerifyBlsRequestBody) {
    out.issue(|tag| {
        let body = VerifyBlsRequestBody {
            request_id: tag.request_id,
            generation: tag.generation.get(),
            ..body
        };
        let hashes = body.item_hashes();
        (body, hashes)
    })
    .expect("room for a request")
}

/// [`file_bls`] for a KZG request.
pub fn file_kzg(
    out: &mut Outstanding,
    body: VerifyKzgRequestBody,
) -> (RequestTag, VerifyKzgRequestBody) {
    out.issue(|tag| {
        let body = VerifyKzgRequestBody {
            request_id: tag.request_id,
            generation: tag.generation.get(),
            ..body
        };
        let hashes = body.item_hashes();
        (body, hashes)
    })
    .expect("room for a request")
}

/// `VerifyStatus` of a result, or the error code of an `err` result.
pub fn outcome(r: &BlsResult) -> Result<VerifyStatus, ErrorCode> {
    match r.result.as_ref().expect("result oneof is set") {
        bls_result::Result::Status(s) => Ok(VerifyStatus::try_from(*s).unwrap()),
        bls_result::Result::Err(e) => Err(e.code()),
    }
}

pub fn outcomes(b: &VerifyBlsResponseBody) -> Vec<Result<VerifyStatus, ErrorCode>> {
    b.results.iter().map(outcome).collect()
}

// ---- deterministic keys ----

pub fn sk(i: u64) -> SecretKey {
    let mut ikm = [0x5au8; 32];
    ikm[..8].copy_from_slice(&i.to_le_bytes());
    SecretKey::key_gen(&ikm, &[]).unwrap()
}

pub fn pk(i: u64) -> PublicKey {
    sk(i).sk_to_pk()
}

pub fn pk_bytes(i: u64) -> Vec<u8> {
    pk(i).compress().to_vec()
}

/// cl-chain's finalized registry made of the keys of validators `keys`, in order.
pub fn registry_of(keys: impl IntoIterator<Item = u64>) -> FinalizedRegistry {
    let compressed: Vec<[u8; 48]> = keys.into_iter().map(|i| pk(i).compress()).collect();
    FinalizedRegistry {
        len: compressed.len() as u64,
        sha256: cl_verify_cache::persist::root_of(&compressed).to_vec(),
    }
}

/// Feed frame `start .. start + len(keys)` carrying the keys of validators `keys`.
pub fn feed_frame(start: u64, keys: impl IntoIterator<Item = u64>) -> PubkeyFeedRequestBody {
    let pubkeys: Vec<Vec<u8>> = keys.into_iter().map(pk_bytes).collect();
    PubkeyFeedRequestBody {
        start_index: start,
        count: pubkeys.len() as u64,
        pubkeys,
        finalized_registry: None,
        feed_finalized_epoch: 0,
        chain_finalized_epoch: 0,
    }
}

/// `frame` as the first frame of a stream, announcing the registry of validators `0..n`.
pub fn announcing(mut frame: PubkeyFeedRequestBody, n: u64) -> PubkeyFeedRequestBody {
    frame.finalized_registry = Some(registry_of(0..n));
    frame
}

/// Cache holding validators `0..n`.
pub fn cache_of(n: u64) -> SharedCache {
    let cache = SharedCache::default();
    cache
        .write()
        .unwrap()
        .append_range(0, (0..n).map(pk).collect())
        .unwrap();
    cache
}

pub fn cached(i: u64) -> Signer {
    Signer {
        validator_index: i,
        inline_pubkey: vec![],
    }
}

pub fn inline(i: u64, key: Vec<u8>) -> Signer {
    Signer {
        validator_index: i,
        inline_pubkey: key,
    }
}

/// A set signed by every validator in `signers` over `[root; 32]`.
pub fn signed_set(signers: Vec<Signer>, keys: &[u64], root: u8) -> BlsSet {
    let msg = [root; 32];
    let sigs: Vec<Signature> = keys.iter().map(|i| sk(*i).sign(&msg, DST, &[])).collect();
    let refs: Vec<&Signature> = sigs.iter().collect();
    let agg = blst::min_pk::AggregateSignature::aggregate(&refs, false).unwrap();
    BlsSet {
        signers,
        signing_root: msg.to_vec(),
        signature: agg.to_signature().compress().to_vec(),
    }
}

pub fn valid_set(i: u64, root: u8) -> BlsSet {
    signed_set(vec![cached(i)], &[i], root)
}

pub fn invalid_set(i: u64, root: u8) -> BlsSet {
    let mut s = valid_set(i, root);
    s.signing_root[0] ^= 0xff;
    s
}

// ---- fixture YAML ----

/// Minimal reader for the flat fixture files: each `key:` maps to the scalars that follow it
/// (quotes, brackets, braces, commas and list dashes are dropped).
pub fn yaml_fields(text: &str) -> HashMap<String, Vec<String>> {
    let cleaned: String = text
        .chars()
        .map(|c| if "{}[],'".contains(c) { ' ' } else { c })
        .collect();
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut key: Option<String> = None;
    for tok in cleaned.split_whitespace() {
        if tok == "-" {
            continue;
        }
        if let Some(k) = tok.strip_suffix(':') {
            out.entry(k.to_string()).or_default();
            key = Some(k.to_string());
        } else if let Some(k) = &key {
            out.get_mut(k).unwrap().push(tok.to_string());
        }
    }
    out
}

pub fn read_fixture(rel: &str) -> HashMap<String, Vec<String>> {
    yaml_fields(&std::fs::read_to_string(fixtures().join(rel)).unwrap())
}

pub fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap()
}

pub fn hexes(f: &HashMap<String, Vec<String>>, key: &str) -> Vec<Vec<u8>> {
    f[key].iter().map(|s| unhex(s)).collect()
}

pub fn output(f: &HashMap<String, Vec<String>>) -> String {
    f["output"][0].clone()
}

// ---- test wall clocks ----

/// The system clock plus an offset the test can step forward at any moment.
#[derive(Default)]
pub struct SteppedClock(std::sync::atomic::AtomicU64);

impl SteppedClock {
    pub fn jump(&self, ms: u64) {
        self.0.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }
}

impl WallClock for SteppedClock {
    fn now_unix_ms(&self) -> u64 {
        now_unix_ms() + self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The system clock for the first `open_reads` reads, then an hour ahead: a job that waited after
/// admission finds its deadline gone.
pub struct ExpiresAfterReads {
    pub reads: std::sync::atomic::AtomicUsize,
    pub open_reads: usize,
}

impl WallClock for ExpiresAfterReads {
    fn now_unix_ms(&self) -> u64 {
        let n = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n < self.open_reads {
            now_unix_ms()
        } else {
            now_unix_ms() + 3_600_000
        }
    }
}

/// Waits up to 5 s for `cond`.
pub async fn wait_for(cond: impl Fn() -> bool) {
    for _ in 0..500 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not met within 5 s");
}

/// Options for a server whose snapshot lives at `snapshot` (shared across restarts).
pub fn restarted(snapshot: &Path) -> Options {
    Options {
        snapshot: Some(snapshot.to_path_buf()),
        ..Options::default()
    }
}

/// Feeds validators `0..n` to a fresh server in frames of `chunk`, following its replies.
pub async fn rebuild_over_feed(h: &mut Harness, n: u64, chunk: u64) -> FeedStream {
    let (mut s, first) = feed_open(h).await;
    assert_eq!(first, 0, "nothing served before the restore");
    let mut start = 0;
    while start < n {
        let end = (start + chunk).min(n);
        let frame = feed_frame(start, start..end);
        s.send(feed_body(if start == 0 {
            announcing(frame, n)
        } else {
            frame
        }))
        .await;
        let r = feed_reply(&mut s).await;
        assert_eq!((r.high_water, r.err), (end, None));
        start = end;
    }
    s
}

/// The verdict for one valid set signed by validator `index`, resolved from the cache.
pub async fn bls_outcome(h: &mut Harness, index: u64) -> Result<VerifyStatus, ErrorCode> {
    let mut b = bls_open(h).await;
    b.send(bls_body(bls_request(1, vec![valid_set(index, 7)])))
        .await;
    outcomes(&bls_reply(&mut b).await).remove(0)
}

/// Whether the snapshot at `path` loads as exactly validators `0..n`.
pub fn snapshot_holds(path: &Path, n: u64) -> bool {
    use cl_verify_cache::persist::{load_with, Registry, Startup};
    let keys: Vec<_> = (0..n).map(pk).collect();
    let registry = Registry::of(&cl_verify::feed::BlstCodec, &keys);
    matches!(
        load_with(&cl_verify::feed::BlstCodec, path, &registry),
        Startup::Use(c) if c.high_water() == n
    )
}
