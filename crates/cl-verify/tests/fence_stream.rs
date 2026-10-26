//! Request fencing through the real cl-verify server, in process and over a Unix socket.
//!
//! The server draws a fresh generation for every stream, refuses a request with another one,
//! and stamps every result with the fence of the item it answers; its own responses settle in
//! the client's `Outstanding` table. The four rejected cases (reordered, duplicated,
//! stale-generation and substituted results) cannot come from an honest server, so a test-only
//! proxy between the client and the real server rewrites the real server's responses on the
//! wire, and the client helpers must refuse each one as a contract violation and IGNORE.

mod common;

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use cl_verify::bls::BlstBackend;
use cl_verify::client::{bls_verdicts, kzg_verdict, settle_bls, settle_kzg};
use cl_verify::proto::common::{ErrorCode, Verdict};
use cl_verify::proto::verify::verify_service_client::VerifyServiceClient;
use cl_verify::proto::verify::verify_service_server::{VerifyService, VerifyServiceServer};
use cl_verify::proto::verify::*;
use cl_verify::server::{serve_uds, Limits, VerifyServer};
use common::*;
use ipc::fence::{message_hash, Fence, FenceError, FencedRequest};
use ipc::testkit::{Connection, Mode, Server, Transport};
use tokio::net::unix::UCred;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::service::Routes;
use tonic::transport::server::UdsConnectInfo;
use tonic::{Request, Response, Status, Streaming};

/// This process's credentials (cl-verify serves only its configured UID), from a socket pair.
fn my_cred() -> UCred {
    static CRED: OnceLock<UCred> = OnceLock::new();
    *CRED.get_or_init(|| {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        a.set_nonblocking(true).expect("nonblocking");
        tokio::net::UnixStream::from_std(a)
            .expect("inside the test runtime")
            .peer_cred()
            .expect("peer credentials")
    })
}

/// One start of the real server, validators 0..4 cached.
fn real_server() -> Server {
    let mut config = config(my_cred().uid(), Limits::default());
    config.pubkey_snapshot = no_snapshot();
    let server =
        VerifyServer::with_backends(config, cache_of(4), Arc::new(BlstBackend), kzg_backend());
    let on_uds = server.clone();
    Server::new(Routes::new(server.into_service()))
        .with_in_process_extensions(|ext| {
            ext.insert(UdsConnectInfo {
                peer_addr: None,
                peer_cred: Some(my_cred()),
            });
        })
        .with_uds_server(Arc::new(move |listener, stop| {
            let server = on_uds.clone();
            Box::pin(async move {
                let _ = serve_uds(listener, server, async {
                    let _ = stop.await;
                })
                .await;
            })
        }))
}

/// Opens a BLS stream over `transport` and completes the hello exchange.
async fn open_bls(transport: &Transport) -> BlsStream {
    let (tx, rx) = mpsc::channel(8);
    let rx = VerifyServiceClient::new(transport.clone())
        .verify_bls(ReceiverStream::new(rx))
        .await
        .expect("stream opens")
        .into_inner();
    let mut s = Bidi {
        tx,
        rx,
        generation: 0,
    };
    s.send(bls_hello(hello())).await;
    match s.next().await.unwrap().unwrap().frame {
        Some(verify_bls_response::Frame::Hello(server)) => s.generation = server_generation(server),
        other => panic!("first server frame is not hello: {other:?}"),
    }
    s
}

async fn open_kzg(transport: &Transport) -> KzgStream {
    let (tx, rx) = mpsc::channel(8);
    let rx = VerifyServiceClient::new(transport.clone())
        .verify_kzg(ReceiverStream::new(rx))
        .await
        .expect("stream opens")
        .into_inner();
    let mut s = Bidi {
        tx,
        rx,
        generation: 0,
    };
    s.send(kzg_hello(hello())).await;
    match s.next().await.unwrap().unwrap().frame {
        Some(verify_kzg_response::Frame::Hello(server)) => s.generation = server_generation(server),
        other => panic!("first server frame is not hello: {other:?}"),
    }
    s
}

fn two_sets() -> Vec<BlsSet> {
    vec![valid_set(0, 1), valid_set(1, 2)]
}

/// How the proxy rewrites the real server's VerifyBls responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rewrite {
    /// Swaps the first two results.
    Reorder,
    /// Forwards every response twice.
    Duplicate,
    /// Replaces a response with the one an earlier stream got for the same request id.
    Replay,
    /// Puts the result of item 1 into item 0's slot, claiming index 0.
    Substitute,
}

/// Responses recorded per stream, for replays.
#[derive(Default)]
struct Tape {
    streams: Mutex<Vec<Vec<VerifyBlsResponseBody>>>,
}

/// A VerifyService in front of the real server that rewrites its responses. Test-only: it is
/// never built into cl-verify.
#[derive(Clone)]
struct RewritingProxy {
    upstream: Transport,
    rewrite: Rewrite,
    tape: Arc<Tape>,
}

impl RewritingProxy {
    /// What the client gets instead of `body`, the real server's response on stream `stream`.
    fn rewrite(
        &self,
        stream: usize,
        mut body: VerifyBlsResponseBody,
    ) -> Vec<VerifyBlsResponseBody> {
        match self.rewrite {
            Rewrite::Reorder => {
                body.results.swap(0, 1);
                vec![body]
            }
            Rewrite::Duplicate => vec![body.clone(), body],
            Rewrite::Replay => {
                let mut streams = self
                    .tape
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let earlier = streams[..stream]
                    .iter()
                    .flatten()
                    .find(|old| old.request_id == body.request_id)
                    .cloned();
                streams[stream].push(body.clone());
                vec![earlier.unwrap_or(body)]
            }
            Rewrite::Substitute => {
                let mut swapped = body.results[1].clone();
                if let Some(fence) = swapped.fence.as_mut() {
                    fence.index = 0;
                }
                body.results[0] = swapped;
                vec![body]
            }
        }
    }
}

#[tonic::async_trait]
impl VerifyService for RewritingProxy {
    type VerifyBlsStream = ReceiverStream<Result<VerifyBlsResponse, Status>>;
    type VerifyKzgStream = Streaming<VerifyKzgResponse>;
    type PubkeyFeedStream = Streaming<PubkeyFeedResponse>;
    type BuilderKeyFeedStream = Streaming<BuilderKeyFeedResponse>;

    async fn verify_bls(
        &self,
        request: Request<Streaming<VerifyBlsRequest>>,
    ) -> Result<Response<Self::VerifyBlsStream>, Status> {
        let requests = request.into_inner().filter_map(Result::ok);
        let mut upstream = VerifyServiceClient::new(self.upstream.clone())
            .verify_bls(requests)
            .await?
            .into_inner();
        let stream = {
            let mut streams = self
                .tape
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            streams.push(Vec::new());
            streams.len() - 1
        };
        let (tx, rx) = mpsc::channel(16);
        let proxy = self.clone();
        tokio::spawn(async move {
            while let Some(item) = upstream.next().await {
                let frames = match item {
                    Ok(VerifyBlsResponse {
                        frame: Some(verify_bls_response::Frame::Body(body)),
                    }) => proxy
                        .rewrite(stream, body)
                        .into_iter()
                        .map(|b| {
                            Ok(VerifyBlsResponse {
                                frame: Some(verify_bls_response::Frame::Body(b)),
                            })
                        })
                        .collect(),
                    other => vec![other],
                };
                for frame in frames {
                    if tx.send(frame).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn verify_kzg(
        &self,
        request: Request<Streaming<VerifyKzgRequest>>,
    ) -> Result<Response<Self::VerifyKzgStream>, Status> {
        let requests = request.into_inner().filter_map(Result::ok);
        VerifyServiceClient::new(self.upstream.clone())
            .verify_kzg(requests)
            .await
    }

    async fn pubkey_feed(
        &self,
        request: Request<Streaming<PubkeyFeedRequest>>,
    ) -> Result<Response<Self::PubkeyFeedStream>, Status> {
        let requests = request.into_inner().filter_map(Result::ok);
        VerifyServiceClient::new(self.upstream.clone())
            .pubkey_feed(requests)
            .await
    }

    async fn builder_key_feed(
        &self,
        request: Request<Streaming<BuilderKeyFeedRequest>>,
    ) -> Result<Response<Self::BuilderKeyFeedStream>, Status> {
        let requests = request.into_inner().filter_map(Result::ok);
        VerifyServiceClient::new(self.upstream.clone())
            .builder_key_feed(requests)
            .await
    }
}

/// The real server behind a rewriting proxy; the client talks to the proxy.
struct Rewired {
    _real: Connection,
    proxy: Connection,
    tape: Arc<Tape>,
}

async fn rewired(mode: &Mode, rewrite: Rewrite) -> Rewired {
    let real = mode.connect(real_server()).await;
    let tape = Arc::new(Tape::default());
    let proxy = RewritingProxy {
        upstream: real.transport.clone(),
        rewrite,
        tape: Arc::clone(&tape),
    };
    let proxy = mode
        .connect(Server::new(Routes::new(VerifyServiceServer::new(proxy))))
        .await;
    Rewired {
        _real: real,
        proxy,
        tape,
    }
}

/// One two-set gossip request of valid sets through the proxy. Returns what the client helpers
/// made of every response that came back for it: the settle result and the verdicts.
async fn rewritten_call(
    s: &mut BlsStream,
    responses: usize,
) -> Vec<(Result<(), FenceError>, Vec<Verdict>)> {
    let mut out = s.outstanding();
    let (tag, body) = file_bls(&mut out, bls_request(1, two_sets()));
    s.send(bls_body(body)).await;
    let mut seen = Vec::new();
    for _ in 0..responses {
        let reply = bls_reply(s).await;
        let settled = settle_bls(&mut out.clone(), tag, reply.clone()).map(|_| ());
        let verdicts = bls_verdicts(Ok(reply), &mut out, tag, 2);
        seen.push((settled, verdicts));
    }
    seen
}

fn assert_refused(seen: &(Result<(), FenceError>, Vec<Verdict>), what: &str) -> FenceError {
    let (settled, verdicts) = seen;
    let err = settled.clone().expect_err(what);
    assert_eq!(
        err.code(),
        Some(ErrorCode::ContractViolation),
        "{what}: {err}"
    );
    assert_eq!(verdicts, &vec![Verdict::Ignore; 2], "{what}: never ACCEPT");
    err
}

async fn real_server_results_settle(mode: Mode) {
    let conn = mode.connect(real_server()).await;
    let mut s = open_bls(&conn.transport).await;
    let mut out = s.outstanding();
    // Two requests in flight; each response settles its own request.
    let (first, a) = file_bls(&mut out, bls_request(1, two_sets()));
    let (second, b) = file_bls(&mut out, bls_request(2, vec![valid_set(2, 3)]));
    s.send(bls_body(a.clone())).await;
    s.send(bls_body(b.clone())).await;
    for _ in 0..2 {
        let reply = bls_reply(&mut s).await;
        let (tag, n, request) = if reply.request_id == first.request_id {
            (first, 2, &a)
        } else {
            (second, 1, &b)
        };
        // Every result carries exactly the fence of the item it answers.
        let fences: Vec<Fence> = reply
            .results
            .iter()
            .map(|r| Fence::from_wire(r.fence.as_ref()).unwrap())
            .collect();
        assert_eq!(fences, request.result_fences());
        assert_eq!(
            bls_verdicts(Ok(reply), &mut out, tag, n),
            vec![Verdict::Accept; n]
        );
    }
    assert!(out.is_empty());

    // A request answered DEADLINE_EXCEEDED without any work is fenced too.
    let mut expired = bls_request(3, vec![valid_set(0, 1)]);
    expired.deadline_unix_ms = 0;
    let (tag, body) = file_bls(&mut out, expired);
    s.send(bls_body(body)).await;
    let reply = bls_reply(&mut s).await;
    assert_eq!(outcomes(&reply), vec![Ok(VerifyStatus::DeadlineExceeded)]);
    assert_eq!(settle_bls(&mut out, tag, reply).map(|_| ()), Ok(()));

    // KZG: one item, the whole request body as sent.
    let mut k = open_kzg(&conn.transport).await;
    assert_ne!(
        k.generation, s.generation,
        "each stream has its own generation"
    );
    let mut kout = k.outstanding();
    let cells = VerifyKzgRequestBody {
        cells: vec![KzgCellProof {
            commitment: vec![0; 48],
            cell_index: 0,
            cell: vec![0; 2048],
            proof: vec![0; 48],
        }],
        deadline_unix_ms: far_deadline(),
        ..Default::default()
    };
    let (ktag, kbody) = file_kzg(&mut kout, cells);
    k.send(kzg_body(kbody.clone())).await;
    let reply = kzg_reply(&mut k).await;
    let fence = Fence::from_wire(reply.fence.as_ref()).unwrap();
    assert_eq!(fence.index, 0);
    assert_eq!(fence.item_hash, message_hash(&kbody));
    assert_eq!(
        settle_kzg(&mut kout.clone(), ktag, reply.clone()).map(|_| ()),
        Ok(())
    );
    assert_ne!(kzg_verdict(Ok(reply), &mut kout, ktag), Verdict::Accept);
}

async fn server_generation_is_fresh_per_stream_and_start(mode: Mode) {
    let first = mode.connect(real_server()).await;
    let a = open_bls(&first.transport).await.generation;
    let b = open_bls(&first.transport).await.generation;
    let restarted = mode.connect(real_server()).await;
    let c = open_bls(&restarted.transport).await.generation;
    for g in [a, b, c] {
        assert_ne!(g, 0);
    }
    assert!(a != b && b != c && a != c, "{a:#x} {b:#x} {c:#x}");
}

async fn request_with_another_generation_fails_the_stream(mode: Mode) {
    let conn = mode.connect(real_server()).await;
    let old = open_bls(&conn.transport).await;
    for (what, generation) in [
        ("zero", 0),
        ("another stream's", old.generation),
        ("made up", old.generation ^ 0x5a5a),
    ] {
        let mut s = open_bls(&conn.transport).await;
        let mut body = bls_request(1, vec![valid_set(0, 1)]);
        body.generation = generation;
        s.send_unstamped(bls_body(body)).await;
        let err = s.expect_failure().await;
        assert_eq!(err.code(), ErrorCode::ContractViolation, "{what}");
        assert!(err.detail.contains("generation"), "{what}: {}", err.detail);
    }
    let mut k = open_kzg(&conn.transport).await;
    let body = VerifyKzgRequestBody {
        request_id: 1,
        generation: k.generation ^ 1,
        deadline_unix_ms: far_deadline(),
        ..Default::default()
    };
    k.send_unstamped(kzg_body(body)).await;
    assert_eq!(
        k.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

async fn reordered_results_rejected(mode: Mode) {
    let r = rewired(&mode, Rewrite::Reorder).await;
    let mut s = open_bls(&r.proxy.transport).await;
    let seen = rewritten_call(&mut s, 1).await;
    let err = assert_refused(&seen[0], "reordered");
    assert!(matches!(err, FenceError::Reordered { .. }), "{err}");
}

async fn duplicated_results_rejected(mode: Mode) {
    let r = rewired(&mode, Rewrite::Duplicate).await;
    let mut s = open_bls(&r.proxy.transport).await;
    let seen = rewritten_call(&mut s, 2).await;
    assert_eq!(
        seen[0],
        (Ok(()), vec![Verdict::Accept; 2]),
        "the first copy"
    );
    let err = assert_refused(&seen[1], "duplicated");
    assert_eq!(err, FenceError::Duplicate { request_id: 1 });
}

async fn stale_generation_results_rejected(mode: Mode) {
    let r = rewired(&mode, Rewrite::Replay).await;
    let mut first = open_bls(&r.proxy.transport).await;
    let seen = rewritten_call(&mut first, 1).await;
    assert_eq!(seen[0], (Ok(()), vec![Verdict::Accept; 2]), "first stream");
    // The second stream's request 1 gets the first stream's answer, with its old generation.
    let mut second = open_bls(&r.proxy.transport).await;
    assert_ne!(second.generation, first.generation);
    let seen = rewritten_call(&mut second, 1).await;
    let err = assert_refused(&seen[0], "stale generation");
    assert!(matches!(err, FenceError::StaleGeneration { .. }), "{err}");
    assert_eq!(r.tape.streams.lock().unwrap().len(), 2);
}

async fn substituted_results_rejected(mode: Mode) {
    let r = rewired(&mode, Rewrite::Substitute).await;
    let mut s = open_bls(&r.proxy.transport).await;
    let seen = rewritten_call(&mut s, 1).await;
    let err = assert_refused(&seen[0], "substituted");
    assert!(matches!(err, FenceError::Substituted { .. }), "{err}");
}

macro_rules! both_transports {
    ($($name:ident),* $(,)?) => {
        mod in_process {
            $(
                #[test]
                fn $name() {
                    ipc::testkit::block_on(super::$name(ipc::testkit::Mode::InProcess));
                }
            )*
        }
        mod uds {
            $(
                #[test]
                fn $name() {
                    let dir = ipc::testkit::tempdir();
                    ipc::testkit::block_on(super::$name(ipc::testkit::Mode::over_uds(dir.path())));
                }
            )*
        }
    };
}

both_transports!(
    real_server_results_settle,
    server_generation_is_fresh_per_stream_and_start,
    request_with_another_generation_fails_the_stream,
    reordered_results_rejected,
    duplicated_results_rejected,
    stale_generation_results_rejected,
    substituted_results_rejected,
);
