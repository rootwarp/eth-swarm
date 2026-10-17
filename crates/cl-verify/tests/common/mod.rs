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
use cl_verify::server::{serve_uds, Limits, ServerConfig, VerifyServer};
use cl_verify::wire::{error_from_status, now_unix_ms, SystemClock, WallClock};
use hyper_util::rt::TokioIo;
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
    }
}

/// crypto-kzg's vendored consensus-specs v1.7.0-beta.4 mainnet setup and its pinned sha256.
pub fn setup_config() -> TrustedSetupConfig {
    TrustedSetupConfig {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../crypto-kzg/data/trusted_setup_4096.json"),
        sha256: hex::decode("f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f")
            .unwrap()
            .try_into()
            .unwrap(),
    }
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

pub fn config(peer_uid: u32, limits: Limits) -> ServerConfig {
    ServerConfig {
        handshake: Handshake::new(hello(), 1),
        peer_uid,
        trusted_setup: setup_config(),
        limits,
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
        }
    }
}

pub struct Harness {
    pub server: VerifyServer,
    pub client: VerifyServiceClient<Channel>,
    pub cache: SharedCache,
    _dir: tempfile::TempDir,
    _shutdown: oneshot::Sender<()>,
}

pub async fn start() -> Harness {
    start_with(Options::default()).await
}

pub async fn start_with(o: Options) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verify.sock");
    let server = VerifyServer::with_backends_and_clock(
        config(o.peer_uid.unwrap_or_else(my_uid), o.limits),
        o.cache.clone(),
        o.bls,
        o.kzg,
        o.clock,
    );
    serve_on(&path, server.clone(), dir, o.cache).await
}

/// Serves `server` on a Unix socket at `path` and connects a client.
pub async fn serve_on(
    path: &Path,
    server: VerifyServer,
    dir: tempfile::TempDir,
    cache: SharedCache,
) -> Harness {
    let listener = UnixListener::bind(path).unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve_uds(listener, server.clone(), async {
        let _ = rx.await;
    }));
    let client = VerifyServiceClient::new(connect(path).await);
    Harness {
        server,
        client,
        cache,
        _dir: dir,
        _shutdown: tx,
    }
}

async fn connect(path: &Path) -> Channel {
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
}

impl<Req, Resp> Bidi<Req, Resp> {
    pub async fn send(&self, req: Req) {
        self.tx.send(req).await.unwrap();
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
    Bidi { tx, rx }
}

/// Opens a BLS stream and completes the hello exchange.
pub async fn bls_open(h: &mut Harness) -> BlsStream {
    let mut s = bls_raw(h).await;
    s.send(bls_hello(hello())).await;
    match s.next().await.unwrap().unwrap().frame {
        Some(verify_bls_response::Frame::Hello(server)) => assert_eq!(server, hello()),
        other => panic!("first server frame is not hello: {other:?}"),
    }
    s
}

pub async fn kzg_raw(h: &mut Harness) -> KzgStream {
    let (tx, rx) = mpsc::channel(8);
    let rx = h
        .client
        .verify_kzg(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    Bidi { tx, rx }
}

pub async fn kzg_open(h: &mut Harness) -> KzgStream {
    let mut s = kzg_raw(h).await;
    s.send(kzg_hello(hello())).await;
    match s.next().await.unwrap().unwrap().frame {
        Some(verify_kzg_response::Frame::Hello(_)) => {}
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
    Bidi { tx, rx }
}

/// Opens a feed stream, completes the hello exchange and returns the first high-water report.
pub async fn feed_open(h: &mut Harness) -> (FeedStream, u64) {
    let mut s = feed_raw(h).await;
    s.send(feed_hello(hello())).await;
    match s.next().await.unwrap().unwrap().frame {
        Some(pubkey_feed_response::Frame::Hello(_)) => {}
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
    }
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
