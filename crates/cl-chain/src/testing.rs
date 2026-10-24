//! Test fixtures shared by [`crate::verify`] and [`crate::probe`] tests, and by
//! `tests/v2_serving.rs`, which includes this file as a module of its own.
//!
//! - [`Blobs`]: two deterministic blobs (the unit vectors `e_0` and `e_1`), their KZG
//!   commitments, and the cells and proofs of some of their columns. The commitments are the
//!   pinned setup's Lagrange points of those blobs, read from the setup file; the cells and proofs
//!   come from `tests/fixtures/unit_blob_columns.bin`, which `tests/kzg_fixture.rs` checks
//!   against what the pinned setup computes (the trusted setup is loaded only there). The valid
//!   tests then check the result end to end: cl-verify accepts these cells against these
//!   commitments only if all three agree.
//! - [`ClVerify`]: an in-process cl-verify (`VerifyServer::new`: the pinned trusted setup) on a
//!   Unix socket in a temp dir.
//! - [`StubVerify`]: a VerifyKzg server that misbehaves on purpose (silent, mute, hangs up).
//!   [`StubVerify::start_network`] checks each client hello as cl-verify does, with the
//!   network hello at the time of a [`ManualClock`] ([`Handshake::accept`]).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::verify::client::KzgClient;
use cl_verify::feed::SharedCache;
use cl_verify::handshake::Handshake;
use cl_verify::kzg::TrustedSetupConfig;
use cl_verify::server::{serve_uds, Limits, ServerConfig, VerifyServer, DEFAULT_SNAPSHOT_INTERVAL};
use cl_verify::wire::WallClock;
use ethswarm_proto::common::{
    BlobScheduleEntry, ErrorCode, ForkName, ForkScheduleEntry, Hello, SpecPin,
};
use ethswarm_proto::verify::verify_service_client::VerifyServiceClient;
use ethswarm_proto::verify::verify_service_server::{VerifyService, VerifyServiceServer};
use ethswarm_proto::verify::{
    verify_kzg_request, verify_kzg_response, PubkeyFeedRequest, PubkeyFeedResponse,
    VerifyBlsRequest, VerifyBlsResponse, VerifyKzgRequest, VerifyKzgResponse,
    VerifyKzgResponseBody, VerifyStatus,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::{Request, Response, Status, Streaming};

/// The pinned trusted setup crypto-kzg vendors (consensus-specs v1.7.0-beta.4, mainnet).
pub fn setup_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../crypto-kzg/data/trusted_setup_4096.json")
}

/// The field element each fixture blob sets to 1.
const UNIT_POSITIONS: [usize; 2] = [0, 1];
/// `log2(FIELD_ELEMENTS_PER_BLOB)`.
const BLOB_BITS: u32 = 12;
const BYTES_PER_CELL: usize = 2048;
const BYTES_PER_PROOF: usize = 48;
/// See `tests/kzg_fixture.rs` for the layout.
const COLUMNS: &[u8] = include_bytes!("../tests/fixtures/unit_blob_columns.bin");

/// One column of both fixture blobs.
struct Column {
    cells: Vec<Vec<u8>>,
    proofs: Vec<[u8; 48]>,
}

/// The fixture blobs' commitments and, for the columns in the fixture, their cells and proofs.
pub struct Blobs {
    /// One 48-byte commitment per blob.
    pub commitments: Vec<[u8; 48]>,
    columns: BTreeMap<u64, Column>,
}

impl Blobs {
    /// Cell `column` of blob `blob`, 2,048 bytes. Panics for a column not in the fixture.
    pub fn cell(&self, blob: usize, column: u64) -> &[u8] {
        &self.columns[&column].cells[blob]
    }

    /// The proof of [`Blobs::cell`].
    pub fn proof(&self, blob: usize, column: u64) -> [u8; 48] {
        self.columns[&column].proofs[blob]
    }
}

/// The fixture blobs, read once per test binary.
pub fn blobs() -> &'static Blobs {
    static BLOBS: OnceLock<Blobs> = OnceLock::new();
    BLOBS.get_or_init(|| {
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(setup_path()).unwrap()).unwrap();
        let lagrange = json["g1_lagrange"].as_array().unwrap();
        let commitments = UNIT_POSITIONS
            .iter()
            .map(|i| {
                let reversed = i.reverse_bits() >> (usize::BITS - BLOB_BITS);
                let hex = lagrange[reversed].as_str().unwrap();
                hex::decode(&hex[2..]).unwrap().try_into().unwrap()
            })
            .collect();
        let per_column = 1 + UNIT_POSITIONS.len() * (BYTES_PER_CELL + BYTES_PER_PROOF);
        assert_eq!(COLUMNS.len() % per_column, 0);
        let columns = COLUMNS
            .chunks(per_column)
            .map(|chunk| {
                let (cells, proofs) = chunk[1..]
                    .chunks(BYTES_PER_CELL + BYTES_PER_PROOF)
                    .map(|b| {
                        let (cell, proof) = b.split_at(BYTES_PER_CELL);
                        (cell.to_vec(), <[u8; 48]>::try_from(proof).unwrap())
                    })
                    .unzip();
                (u64::from(chunk[0]), Column { cells, proofs })
            })
            .collect();
        Blobs {
            commitments,
            columns,
        }
    })
}

/// The hello both ends of a test link send (generation 0: the server draws its own).
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
                fork_digest: vec![0x99, 0x88, 0x77, 0x66],
                fork: ForkName::Fulu as i32,
                fork_version: vec![0x06, 0, 0, 0],
                max_blobs_per_block: 9,
            },
            ForkScheduleEntry {
                epoch: 0,
                fork_digest: vec![0xaa, 0xbb, 0xcc, 0xdd],
                fork: ForkName::Gloas as i32,
                fork_version: vec![0x07, 0, 0, 0],
                max_blobs_per_block: 21,
            },
        ],
        blob_schedule: vec![BlobScheduleEntry {
            epoch: 0,
            max_blobs_per_block: 21,
        }],
        min_api_version: 1,
        max_api_version: 1,
        generation: 0,
    }
}

/// This process's effective UID: the peer both ends of a test socket expect.
pub fn my_uid() -> u32 {
    ipc::uds::Ownership::current().uid
}

/// A wall clock that the test sets by hand, in Unix milliseconds.
#[derive(Debug, Default)]
pub struct ManualClock(pub AtomicU64);

impl ManualClock {
    /// A clock that reads `unix_ms`.
    pub fn at(unix_ms: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(unix_ms)))
    }

    /// Sets the clock to `unix_ms`.
    pub fn set(&self, unix_ms: u64) {
        self.0.store(unix_ms, Ordering::SeqCst);
    }
}

impl WallClock for ManualClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// What a network stub ([`StubVerify::start_network`]) found in each client hello, in stream
/// order: the accepted `current_fork_digest`, or the error code of the refusal.
pub type Handshakes = Arc<Mutex<Vec<Result<Vec<u8>, ErrorCode>>>>;

/// A server task on a Unix socket in its own temp dir, stopped when this is dropped.
pub struct Served {
    pub socket: PathBuf,
    /// VerifyKzg streams the server has answered (counted by [`StubVerify`] only).
    opened: Arc<AtomicUsize>,
    /// The client hellos a network stub checked.
    handshakes: Handshakes,
    _dir: tempfile::TempDir,
    _stop: oneshot::Sender<()>,
}

impl Served {
    /// A verify.v1 client to this server, cl-chain's side of the link.
    pub async fn kzg_client(&self) -> KzgClient {
        let channel = ipc::uds::connect_path(&self.socket, my_uid())
            .await
            .unwrap();
        KzgClient::new(VerifyServiceClient::new(channel), hello())
    }

    /// A verify.v1 client to this server that opens each stream with `network`'s hello at the
    /// time of `clock`.
    pub async fn network_kzg_client(
        &self,
        network: ipc::hello::NetworkHello,
        clock: Arc<ManualClock>,
    ) -> KzgClient {
        let channel = ipc::uds::connect_path(&self.socket, my_uid())
            .await
            .unwrap();
        KzgClient::network_with_clock(
            VerifyServiceClient::new(channel),
            Arc::new(network),
            Arc::new(move || u128::from(clock.now_unix_ms())),
        )
    }

    /// A verify.v1 client to this server that opens each stream with `network`'s hello at the
    /// time of `clock` (Unix milliseconds).
    pub async fn network_kzg_client_on(
        &self,
        network: ipc::hello::NetworkHello,
        clock: crate::verify::client::UnixClock,
    ) -> KzgClient {
        let channel = ipc::uds::connect_path(&self.socket, my_uid())
            .await
            .unwrap();
        KzgClient::network_with_clock(VerifyServiceClient::new(channel), Arc::new(network), clock)
    }

    /// VerifyKzg streams opened so far.
    pub fn streams_opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }

    /// What a network stub found in each client hello so far, in stream order.
    pub fn handshakes(&self) -> Vec<Result<Vec<u8>, ErrorCode>> {
        self.handshakes.lock().unwrap().clone()
    }
}

fn socket() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("verify.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    (dir, socket, listener)
}

/// The real cl-verify, in process: `VerifyServer::new` loads the pinned trusted setup.
pub struct ClVerify;

impl ClVerify {
    pub fn start() -> Served {
        let (dir, socket, listener) = socket();
        let config = ServerConfig {
            handshake: Handshake::new(hello(), 1),
            peer_uid: my_uid(),
            trusted_setup: TrustedSetupConfig { path: setup_path() },
            limits: Limits::default(),
            pubkey_snapshot: dir.path().join("pubkeys.bin"),
            snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
        };
        let server = VerifyServer::new(config, SharedCache::default()).unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(serve_uds(listener, server, async {
            let _ = stopped.await;
        }));
        Served {
            socket,
            opened: Arc::default(),
            handshakes: Arc::default(),
            _dir: dir,
            _stop: stop,
        }
    }
}

/// How [`StubVerify`] answers a VerifyKzg stream.
#[derive(Clone, Copy, Debug)]
pub enum Stub {
    /// Sends its hello, reads every request, never answers one.
    Silent,
    /// Sends nothing at all, not even a hello.
    Mute,
    /// Sends a hello with generation 0, which no request can be fenced with.
    ZeroGeneration,
    /// Sends its hello, then ends the stream at the first request.
    HangsUp,
    /// Answers every request `VERIFY_STATUS_VALID`, without the fence that binds the answer to
    /// it.
    Unfenced,
    /// Answers the first request with a second hello.
    HelloTwice,
}

/// A VerifyKzg server scripted by [`Stub`]. Its senders live as long as the server, so a silent
/// stream stays open.
pub struct StubVerify {
    mode: Stub,
    opened: Arc<AtomicUsize>,
    open: Mutex<Vec<mpsc::Sender<Result<VerifyKzgResponse, Status>>>>,
    /// cl-verify's side of the handshake and its clock: each client hello is checked against
    /// it before the stub answers ([`Self::start_network`]).
    network: Option<(Handshake, Arc<ManualClock>)>,
    handshakes: Handshakes,
}

type Frames<T> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl VerifyService for StubVerify {
    type VerifyBlsStream = Frames<VerifyBlsResponse>;
    type VerifyKzgStream = ReceiverStream<Result<VerifyKzgResponse, Status>>;
    type PubkeyFeedStream = Frames<PubkeyFeedResponse>;

    async fn verify_bls(
        &self,
        _: Request<Streaming<VerifyBlsRequest>>,
    ) -> Result<Response<Self::VerifyBlsStream>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn verify_kzg(
        &self,
        request: Request<Streaming<VerifyKzgRequest>>,
    ) -> Result<Response<Self::VerifyKzgStream>, Status> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        let mut inbound = request.into_inner();
        // A network stub reads and checks the client's hello first, as cl-verify does.
        let ours = match &self.network {
            Some((handshake, clock)) => {
                let theirs = match inbound.message().await {
                    Ok(Some(VerifyKzgRequest {
                        frame: Some(verify_kzg_request::Frame::Hello(theirs)),
                    })) => theirs,
                    _ => return Err(Status::invalid_argument("no client hello")),
                };
                match handshake.accept(&theirs, clock.as_ref()) {
                    Ok((_, ours)) => {
                        let digest = ours.current_fork_digest.clone();
                        self.handshakes.lock().unwrap().push(Ok(digest));
                        ours
                    }
                    Err(e) => {
                        // As cl-verify fails a stream: the error is its first response.
                        self.handshakes.lock().unwrap().push(Err(e.code()));
                        let (tx, rx) = mpsc::channel(1);
                        tx.send(Err(cl_verify::wire::to_status(&e))).await.unwrap();
                        return Ok(Response::new(ReceiverStream::new(rx)));
                    }
                }
            }
            None => hello(),
        };
        let hello_read = self.network.is_some();
        let (tx, rx) = mpsc::channel(16);
        let server_hello = move |generation| VerifyKzgResponse {
            frame: Some(verify_kzg_response::Frame::Hello(Hello {
                generation,
                ..ours.clone()
            })),
        };
        match self.mode {
            Stub::Mute => {}
            Stub::ZeroGeneration => tx.send(Ok(server_hello(0))).await.unwrap(),
            _ => tx.send(Ok(server_hello(0x5eed))).await.unwrap(),
        }
        let mode = self.mode;
        match mode {
            Stub::HangsUp => {
                tokio::spawn(async move {
                    // The client's hello, then its first request: end the stream there.
                    if !hello_read {
                        let _ = inbound.message().await;
                    }
                    let _ = inbound.message().await;
                    drop(tx);
                });
            }
            Stub::Unfenced | Stub::HelloTwice => {
                let answers = tx.clone();
                tokio::spawn(async move {
                    while let Ok(Some(frame)) = inbound.message().await {
                        let Some(verify_kzg_request::Frame::Body(body)) = frame.frame else {
                            continue;
                        };
                        let answer = match mode {
                            Stub::HelloTwice => server_hello(0x5eed),
                            _ => VerifyKzgResponse {
                                frame: Some(verify_kzg_response::Frame::Body(
                                    VerifyKzgResponseBody {
                                        request_id: body.request_id,
                                        status: VerifyStatus::Valid as i32,
                                        err: None,
                                        fence: None,
                                    },
                                )),
                            },
                        };
                        let _ = answers.send(Ok(answer)).await;
                    }
                });
                self.open.lock().unwrap().push(tx);
            }
            _ => {
                tokio::spawn(async move { while let Ok(Some(_)) = inbound.message().await {} });
                self.open.lock().unwrap().push(tx);
            }
        }
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn pubkey_feed(
        &self,
        _: Request<Streaming<PubkeyFeedRequest>>,
    ) -> Result<Response<Self::PubkeyFeedStream>, Status> {
        Err(Status::unimplemented("stub"))
    }
}

impl StubVerify {
    pub fn start(mode: Stub) -> Served {
        Self::serve(mode, None)
    }

    /// A stub that checks each client hello against `handshake` at the time of `clock`, as
    /// cl-verify does at each stream open, and answers by `mode` after a hello it accepts. A
    /// refused hello fails the stream. [`Served::handshakes`] records each outcome.
    pub fn start_network(mode: Stub, handshake: Handshake, clock: Arc<ManualClock>) -> Served {
        Self::serve(mode, Some((handshake, clock)))
    }

    fn serve(mode: Stub, network: Option<(Handshake, Arc<ManualClock>)>) -> Served {
        let (dir, socket, listener) = socket();
        let opened = Arc::<AtomicUsize>::default();
        let handshakes = Handshakes::default();
        let stub = StubVerify {
            mode,
            opened: Arc::clone(&opened),
            open: Mutex::default(),
            network,
            handshakes: Arc::clone(&handshakes),
        };
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(VerifyServiceServer::new(stub))
                .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                    let _ = stopped.await;
                }),
        );
        Served {
            socket,
            opened,
            handshakes,
            _dir: dir,
            _stop: stop,
        }
    }
}

/// The test preset.
pub type Spec = consensus_types::Minimal;

/// Gloas from epoch 1 (slot 8 in the minimal preset), Fulu before.
pub fn schedule() -> consensus_types::ForkSchedule {
    use network_config::ScheduledFork;
    consensus_types::ForkSchedule::new(
        ScheduledFork {
            version: [0x06, 0, 0, 0],
            epoch: 0,
        },
        ScheduledFork {
            version: [0x07, 0, 0, 0],
            epoch: 1,
        },
    )
    .unwrap()
}

/// A Gloas block, its SSZ and its root.
pub type FixtureBlock = (
    consensus_types::gloas::SignedBeaconBlock<Spec>,
    Vec<u8>,
    [u8; 32],
);

/// A Gloas block at `slot` whose bid commits to `commitments`, its SSZ and its root.
pub fn gloas_block(slot: u64, commitments: &[[u8; 48]]) -> FixtureBlock {
    gloas_block_on(
        slot,
        commitments,
        p2p_wire::testkit::gloas_block::<Spec>(slot)
            .message
            .parent_root
            .0,
    )
}

/// [`gloas_block`] whose parent is `parent`.
pub fn gloas_block_on(slot: u64, commitments: &[[u8; 48]], parent: [u8; 32]) -> FixtureBlock {
    use ssz::Encode;
    use tree_hash::TreeHash;
    let mut block = p2p_wire::testkit::gloas_block::<Spec>(slot);
    block.message.parent_root = parent.into();
    block
        .message
        .body
        .signed_execution_payload_bid
        .message
        .blob_kzg_commitments = commitments.to_vec().try_into().unwrap();
    let root = block.message.tree_hash_root().0;
    let ssz = block.as_ssz_bytes();
    (block, ssz, root)
}
