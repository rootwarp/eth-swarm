//! Engine transport faults against the scriptable mock EL (`testkit::mock_el`).
//!
//! The timing tests run on paused Tokio time with auto-advance held off ([`freeze`]): waiting
//! on loopback I/O never moves the clock, only `tokio::time::advance` does, so a scripted
//! `Reply::Delay` lands exactly where the test puts it.

use cl_engine::capabilities::{FORKCHOICE_UPDATED_V4, NEW_PAYLOAD_V5};
use cl_engine::client::{
    health_status, Backoff, CallError, Clock, Config, EngineEndpoint, Session, StartError,
    EXCHANGE_CAPABILITIES, FORKCHOICE_UPDATED_TIMEOUT, NEW_PAYLOAD_V5_TIMEOUT,
};
use cl_engine::jwt::{self, JwtSecret};
use cl_engine::queue::Queue;
use cl_engine::server::{serve, EngineServer, Limits};
use data_encoding::HEXLOWER;
use ethswarm_proto::engine as pb;
use http::StatusCode;
use hyper_util::rt::TokioIo;
use ipc::acl::{AclTables, MethodAcl};
use pb::engine_service_client::EngineServiceClient;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use testkit::mock_el::{self, MockEl, Reply};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tonic::transport::{Channel, Endpoint, Uri};

const KEY: [u8; 32] = [0x5a; 32];
const NEW_PAYLOAD_V4: &str = "engine_newPayloadV4";
const GET_PAYLOAD_V5: &str = "engine_getPayloadV5";
const FORKCHOICE_UPDATED_V3: &str = "engine_forkchoiceUpdatedV3";
const GET_BLOBS_V3: &str = "engine_getBlobsV3";
const GET_PAYLOAD_BODIES_BY_HASH_V1: &str = "engine_getPayloadBodiesByHashV1";
/// JSON-RPC "Method not found".
const METHOD_NOT_FOUND: i64 = -32601;
const NEW_PAYLOAD_PATH: &str = "/ethswarm.engine.v1.EngineService/NewPayload";
const FORKCHOICE_UPDATED_PATH: &str = "/ethswarm.engine.v1.EngineService/ForkchoiceUpdated";

/// The mock EL's clock.
fn el_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// The mock EL with `key`, accepting `iat` within 60 s of [`el_now`] (`authentication.md`).
async fn start_el(key: [u8; 32]) -> MockEl {
    MockEl::start(mock_el::Config {
        key,
        skew: Duration::from_secs(60),
        now: el_now,
    })
    .await
    .unwrap()
}

/// The client's clock: [`el_now`] shifted by a settable number of seconds.
#[derive(Default)]
struct Skew(AtomicI64);

impl Skew {
    fn set(&self, secs: i64) {
        self.0.store(secs, Ordering::Relaxed);
    }
}

impl Clock for Skew {
    fn now(&self) -> SystemTime {
        let secs = self.0.load(Ordering::Relaxed);
        let by = Duration::from_secs(secs.unsigned_abs());
        if secs < 0 {
            el_now() - by
        } else {
            el_now() + by
        }
    }
}

fn skewed(secs: i64) -> Arc<Skew> {
    let clock = Arc::new(Skew::default());
    clock.set(secs);
    clock
}

/// `key` loaded as production loads it: an owner-only `jwtsecret` credential file.
fn secret(key: [u8; 32]) -> JwtSecret {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(jwt::CREDENTIAL);
    std::fs::write(&path, HEXLOWER.encode(&key)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    // A root-owned credential is read as an ACL grant; as root, own it as another UID.
    let euid = match rustix::process::geteuid().as_raw() {
        0 => {
            rustix::fs::chown(&path, Some(rustix::process::Uid::from_raw(4242)), None).unwrap();
            4242
        }
        uid => uid,
    };
    jwt::load(
        Some(dir.path().as_os_str()),
        euid,
        "ethswarm-engine.service",
    )
    .unwrap()
}

fn endpoint(mock: &MockEl) -> EngineEndpoint {
    EngineEndpoint::parse(&mock.url(), false).unwrap()
}

fn config(mock: &MockEl, clock: Arc<dyn Clock>) -> Config {
    Config::new(endpoint(mock), secret(KEY)).clock(clock)
}

fn hex(hash: [u8; 32]) -> String {
    format!("0x{}", HEXLOWER.encode(&hash))
}

/// `engine_newPayload` params holding only `blockHash`, the field the mock EL reads.
fn payload(hash: [u8; 32]) -> Value {
    json!([{ "blockHash": hex(hash) }])
}

fn forkchoice_state(head: [u8; 32]) -> Value {
    json!({
        "headBlockHash": hex(head),
        "safeBlockHash": hex(head),
        "finalizedBlockHash": hex(head),
    })
}

/// The methods the mock EL received, in order.
fn sent(mock: &MockEl) -> Vec<String> {
    mock.requests().into_iter().map(|r| r.method).collect()
}

/// Waits until `mock` has received `method` for block or head `hash`.
async fn arrived(mock: &MockEl, method: &str, hash: [u8; 32]) {
    let want = hex(hash);
    let mut seen = 0;
    loop {
        mock.wait_for_requests(seen + 1).await;
        let requests = mock.requests();
        if requests.iter().any(|r| {
            r.method == method
                && (r.params[0]["blockHash"] == want || r.params[0]["headBlockHash"] == want)
        }) {
            return;
        }
        seen = requests.len();
    }
}

/// Holds the paused clock still until dropped. Tokio does not auto-advance paused time while a
/// blocking task runs (`tokio::time::pause`, "Preventing auto-advance"); without this, waiting
/// on loopback I/O would jump the clock to the next pending deadline.
struct Frozen {
    _release: std::sync::mpsc::Sender<()>,
}

fn freeze() -> Frozen {
    let (release, released) = std::sync::mpsc::channel::<()>();
    tokio::task::spawn_blocking(move || {
        // Returns once the sender is dropped.
        let _ = released.recv();
    });
    Frozen { _release: release }
}

/// cl-engine's `ethswarm.engine.v1` server on a Unix socket, in front of a queue to the mock
/// EL, with this process as cl-chain.
struct Served {
    client: EngineServiceClient<Channel>,
    _dir: tempfile::TempDir,
    _stop: oneshot::Sender<()>,
}

async fn serve_engine(mock: &MockEl) -> Served {
    let queue = Queue::connect(config(mock, skewed(0)), 1)
        .await
        .unwrap_or_else(|err| panic!("{err}"));
    let mut tables = AclTables::default();
    tables
        .callers
        .insert("cl-chain".into(), ipc::testkit::own_cred().uid());
    for path in [NEW_PAYLOAD_PATH, FORKCHOICE_UPDATED_PATH] {
        tables.methods.insert(path.into(), vec!["cl-chain".into()]);
    }
    let acl = Arc::new(MethodAcl::from_tables("cl-engine", &tables).unwrap());
    let server = EngineServer::new(ipc::testkit::fixture::v1_link(), acl, queue);
    let dir = ipc::testkit::tempdir();
    let path = dir.path().join("engine.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (stop, stopped) = oneshot::channel();
    tokio::spawn(serve(listener, server, Limits::default(), async {
        let _ = stopped.await;
    }));
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .unwrap();
    Served {
        client: EngineServiceClient::new(channel),
        _dir: dir,
        _stop: stop,
    }
}

fn new_payload_request(
    seq: u64,
    version: pb::EngineMethodVersion,
    hash: [u8; 32],
    timeout_ms: u32,
) -> pb::NewPayloadRequest {
    pb::NewPayloadRequest {
        seq,
        params: Some(pb::VersionedData {
            version: version as i32,
            encoding: pb::PayloadEncoding::Json as i32,
            data: serde_json::to_vec(&payload(hash)).unwrap(),
        }),
        timeout_ms,
    }
}

fn forkchoice_request(seq: u64, head: [u8; 32], timeout_ms: u32) -> pb::ForkchoiceUpdatedRequest {
    pb::ForkchoiceUpdatedRequest {
        seq,
        head_block_hash: head.to_vec(),
        safe_block_hash: head.to_vec(),
        finalized_block_hash: head.to_vec(),
        timeout_ms,
        ..Default::default()
    }
}

/// `-38005` is `UnsupportedFork`, not a generic RPC error, it costs no reconnect, and nothing
/// is retried with another method version, not after `-38005` and not after any other failure.
/// `-32601` from the methods the fork did not replace stays an RPC error. On the wire, the
/// server reports it as `ENGINE_ERROR_KIND_UNSUPPORTED_FORK` with its code.
#[tokio::test]
async fn minus_38005_no_downgrade() {
    let mock = start_el(KEY).await;
    mock.set_capabilities(
        [
            NEW_PAYLOAD_V5,
            FORKCHOICE_UPDATED_V4,
            NEW_PAYLOAD_V4,
            GET_PAYLOAD_V5,
            FORKCHOICE_UPDATED_V3,
            GET_BLOBS_V3,
            GET_PAYLOAD_BODIES_BY_HASH_V1,
        ]
        .map(str::to_owned)
        .to_vec(),
    );
    let queue = Queue::connect(config(&mock, skewed(0)), 1)
        .await
        .unwrap_or_else(|err| panic!("{err}"));
    let head = [0x0f; 32];
    let calls = [
        (NEW_PAYLOAD_V4, payload(head), CallError::UnsupportedFork),
        (
            GET_PAYLOAD_V5,
            json!(["0x0000000000000001"]),
            CallError::UnsupportedFork,
        ),
        (
            FORKCHOICE_UPDATED_V3,
            json!([forkchoice_state(head), null]),
            CallError::UnsupportedFork,
        ),
        (
            GET_BLOBS_V3,
            json!([[]]),
            CallError::Rpc {
                code: METHOD_NOT_FOUND,
            },
        ),
        (
            GET_PAYLOAD_BODIES_BY_HASH_V1,
            json!([[]]),
            CallError::Rpc {
                code: METHOD_NOT_FOUND,
            },
        ),
    ];
    for (seq, (method, params, want)) in (1..).zip(calls) {
        let err = queue
            .call(seq, method, params, FORKCHOICE_UPDATED_TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(err, want, "{method}");
        assert!(!err.reconnects(), "{method}");
    }
    assert_eq!(queue.generation(), 1);
    assert!(queue.session().is_connected());

    // A connection the EL drops is a transport failure: it reconnects, and is not retried.
    let dropped = [0x0d; 32];
    mock.on_new_payload(dropped, Reply::Drop);
    let err = queue
        .call(6, NEW_PAYLOAD_V5, payload(dropped), NEW_PAYLOAD_V5_TIMEOUT)
        .await
        .unwrap_err();
    assert_eq!(err, CallError::Transport);
    assert!(err.reconnects());

    let mut served = serve_engine(&mock).await;
    let reply = served
        .client
        .new_payload(new_payload_request(
            1,
            pb::EngineMethodVersion::FuluOsaka,
            head,
            0,
        ))
        .await
        .unwrap()
        .into_inner();
    let error = reply.error.expect("an engine error");
    assert_eq!(error.kind, pb::EngineErrorKind::UnsupportedFork as i32);
    assert_eq!(error.rpc_code, -38005);

    assert_eq!(
        sent(&mock),
        [
            EXCHANGE_CAPABILITIES,
            NEW_PAYLOAD_V4,
            GET_PAYLOAD_V5,
            FORKCHOICE_UPDATED_V3,
            GET_BLOBS_V3,
            GET_PAYLOAD_BODIES_BY_HASH_V1,
            NEW_PAYLOAD_V5,
            EXCHANGE_CAPABILITIES,
            NEW_PAYLOAD_V4,
        ]
    );
}

/// The EL accepts `iat` within 60 s of its clock. A client clock 59 s off either way gets
/// through and 61 s is refused, at start and on each call (every call mints a fresh token).
#[tokio::test]
async fn jwt_skew_59s_ok_61s_rejected() {
    let mock = start_el(KEY).await;
    for secs in [-61, 61] {
        let err = Session::connect(config(&mock, skewed(secs)))
            .await
            .unwrap_err();
        assert!(matches!(err, StartError::Unauthorized), "{secs} s: {err}");
    }
    assert!(mock.requests().is_empty(), "a stale token was served");
    for secs in [-59, 59] {
        Session::connect(config(&mock, skewed(secs)))
            .await
            .unwrap_or_else(|err| panic!("{secs} s: {err}"));
    }
    let clock = skewed(0);
    let session = Session::connect(config(&mock, Arc::clone(&clock) as Arc<dyn Clock>))
        .await
        .unwrap();
    for (secs, accepted) in [(59, true), (61, false), (-59, true), (-61, false)] {
        clock.set(secs);
        let result = session
            .call(NEW_PAYLOAD_V5, &payload([0x04; 32]), NEW_PAYLOAD_V5_TIMEOUT)
            .await;
        if accepted {
            assert_eq!(result.unwrap()["status"], "VALID", "{secs} s");
        } else {
            assert_eq!(result, Err(CallError::Unauthorized), "{secs} s");
        }
    }
}

/// A token signed with another key is refused at start, and the EL serves nothing for it.
#[tokio::test]
async fn jwt_bad_key_fails() {
    let mock = start_el(KEY).await;
    let wrong = || Config::new(endpoint(&mock), secret([0xa5; 32])).clock(skewed(0));
    let err = Session::connect(wrong()).await.unwrap_err();
    assert!(matches!(err, StartError::Unauthorized), "{err}");
    let shown = err.to_string();
    assert!(!shown.contains(&HEXLOWER.encode(&[0xa5; 32])), "{shown}");
    let err = Queue::connect(wrong(), 1).await.err();
    assert!(matches!(err, Some(StartError::Unauthorized)), "{err:?}");
    assert!(
        mock.requests().is_empty(),
        "a request with a bad key was served"
    );
    // The right key with the same clock gets through: the key is what failed.
    Session::connect(config(&mock, skewed(0))).await.unwrap();
    assert_eq!(sent(&mock), [EXCHANGE_CAPABILITIES]);
}

/// The spec waits are floors (`common.md`: the CL MUST wait the method's timeout). Through the
/// server, a `timeout_ms` below the 6 s newPayload / 8 s forkchoiceUpdated wait does not
/// shorten it, a larger one raises it, and a reply after the wait is a timeout.
#[tokio::test(start_paused = true)]
async fn timeout_waits_full() {
    let _frozen = freeze();
    let mock = start_el(KEY).await;
    let served = serve_engine(&mock).await;
    let ms = Duration::from_millis;
    // (method, timeout_ms, when the EL replies, the wait the server must give it)
    let cases = [
        (NEW_PAYLOAD_V5, 1, ms(5_900), NEW_PAYLOAD_V5_TIMEOUT),
        (
            FORKCHOICE_UPDATED_V4,
            1,
            ms(7_900),
            FORKCHOICE_UPDATED_TIMEOUT,
        ),
        (NEW_PAYLOAD_V5, 0, ms(6_100), NEW_PAYLOAD_V5_TIMEOUT),
        (
            FORKCHOICE_UPDATED_V4,
            0,
            ms(8_100),
            FORKCHOICE_UPDATED_TIMEOUT,
        ),
        (NEW_PAYLOAD_V5, 9_000, ms(8_900), ms(9_000)),
    ];
    for (seq, (method, timeout_ms, delay, wait)) in (1u8..).zip(cases) {
        let hash = [seq; 32];
        let seq = u64::from(seq);
        let mut client = served.client.clone();
        let call = if method == NEW_PAYLOAD_V5 {
            mock.on_new_payload(hash, Reply::Delay(delay));
            let request = new_payload_request(
                seq,
                pb::EngineMethodVersion::GloasAmsterdam,
                hash,
                timeout_ms,
            );
            tokio::spawn(async move {
                let reply = client.new_payload(request).await.unwrap().into_inner();
                (reply.status, reply.error)
            })
        } else {
            mock.on_forkchoice_updated(hash, Reply::Delay(delay));
            let request = forkchoice_request(seq, hash, timeout_ms);
            tokio::spawn(async move {
                let reply = client
                    .forkchoice_updated(request)
                    .await
                    .unwrap()
                    .into_inner();
                (reply.status, reply.error)
            })
        };
        arrived(&mock, method, hash).await;
        tokio::time::advance(delay.min(wait)).await;
        let (status, error) = call.await.unwrap();
        let case = format!("{method}, timeout_ms {timeout_ms}, reply at {delay:?}");
        if delay < wait {
            assert_eq!(
                status.map(|status| status.status),
                Some(pb::PayloadStatusKind::Valid as i32),
                "{case}: {error:?}"
            );
        } else {
            assert_eq!(
                error.map(|error| error.kind),
                Some(pb::EngineErrorKind::Timeout as i32),
                "{case}: {status:?}"
            );
        }
    }
}

/// `el_offline` turns on when no call has succeeded for `el_offline_after` (30 s by default)
/// and at once when a dial is refused; a successful call on the current generation clears it.
/// The beacon health code it implies is 206 while it is on, 200 once it clears.
#[tokio::test(start_paused = true)]
async fn el_offline_sets_flag_and_206() {
    let _frozen = freeze();
    let mock = start_el(KEY).await;
    let window = Duration::from_secs(30);
    let late = [0x01; 32];
    mock.on_new_payload(late, Reply::Delay(window + Duration::from_secs(1)));
    // One dial per reconnect and no backoff, so the refused dial below ends its reconnect.
    let config = config(&mock, skewed(0))
        .max_reconnect_attempts(1)
        .backoff(Backoff {
            initial: Duration::ZERO,
            cap: Duration::ZERO,
        });
    assert_eq!(config.el_offline_after, window);
    let queue = Queue::connect(config, 1)
        .await
        .unwrap_or_else(|err| panic!("{err}"));
    assert!(!queue.el_offline());
    assert_eq!(health_status(queue.el_offline()), StatusCode::OK);

    // Seq 1 is in flight on generation 1 when a reconnect replaces it.
    let in_flight = {
        let queue = queue.clone();
        tokio::spawn(async move {
            queue
                .call(1, NEW_PAYLOAD_V5, payload(late), Duration::from_secs(60))
                .await
        })
    };
    arrived(&mock, NEW_PAYLOAD_V5, late).await;
    queue.reconnect().await.unwrap();

    // Nothing succeeds for the whole window.
    tokio::time::advance(window - Duration::from_millis(1)).await;
    assert!(!queue.el_offline());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(queue.el_offline());
    assert!(queue.session().el_offline());
    assert_eq!(
        health_status(queue.el_offline()),
        StatusCode::PARTIAL_CONTENT
    );

    // The reply for generation 1 is dropped and does not clear the flag.
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(in_flight.await.unwrap(), Err(CallError::StaleConnection));
    assert!(queue.el_offline());

    // A successful call on the current generation does.
    queue
        .call(
            2,
            NEW_PAYLOAD_V5,
            payload([0x02; 32]),
            NEW_PAYLOAD_V5_TIMEOUT,
        )
        .await
        .unwrap();
    assert!(!queue.el_offline());
    assert_eq!(health_status(queue.el_offline()), StatusCode::OK);

    // The EL goes away: the refused dial turns the flag on at once, well inside the window.
    drop(mock);
    // Lets the runtime drop the mock's cancelled listener task, closing its port.
    tokio::task::yield_now().await;
    let refused = queue.reconnect().await;
    assert!(
        matches!(refused, Err(StartError::Unavailable)),
        "{refused:?}"
    );
    assert!(queue.el_offline());
    assert_eq!(
        health_status(queue.el_offline()),
        StatusCode::PARTIAL_CONTENT
    );
}

/// A reply that arrives after a reconnect belongs to the replaced generation: the caller gets
/// `StaleConnection`, `late_dropped` counts it, and the call is not sent again.
#[tokio::test(start_paused = true)]
async fn stale_generation_dropped() {
    let _frozen = freeze();
    let mock = start_el(KEY).await;
    let late = [0x06; 32];
    mock.on_new_payload(late, Reply::Delay(Duration::from_secs(2)));
    let queue = Queue::connect(config(&mock, skewed(0)), 1)
        .await
        .unwrap_or_else(|err| panic!("{err}"));
    let in_flight = {
        let queue = queue.clone();
        tokio::spawn(async move {
            queue
                .call(1, NEW_PAYLOAD_V5, payload(late), NEW_PAYLOAD_V5_TIMEOUT)
                .await
        })
    };
    arrived(&mock, NEW_PAYLOAD_V5, late).await;
    queue.reconnect().await.unwrap();
    assert_eq!(queue.generation(), 2);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(in_flight.await.unwrap(), Err(CallError::StaleConnection));
    assert_eq!(queue.late_dropped(), 1);

    let fresh = [0x07; 32];
    let value = queue
        .call(2, NEW_PAYLOAD_V5, payload(fresh), NEW_PAYLOAD_V5_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(value["status"], "VALID");
    assert_eq!(queue.late_dropped(), 1);
    let blocks: Vec<Value> = mock
        .requests()
        .into_iter()
        .filter(|r| r.method == NEW_PAYLOAD_V5)
        .map(|r| r.params[0]["blockHash"].clone())
        .collect();
    assert_eq!(blocks, [json!(hex(late)), json!(hex(fresh))]);
}

/// Start and reconnect need `engine_newPayloadV5` and `engine_forkchoiceUpdatedV4`; the
/// previous-fork versions do not stand in, and nothing but the capability exchange is sent.
#[tokio::test]
async fn capability_gate_refuses_missing_methods() {
    let mock = start_el(KEY).await;
    let list = |methods: &[&str]| {
        mock.set_capabilities(methods.iter().map(|method| (*method).to_owned()).collect());
    };
    let both = [NEW_PAYLOAD_V5, FORKCHOICE_UPDATED_V4];
    let cases: [(&[&str], &[&str]); 4] = [
        (&[FORKCHOICE_UPDATED_V4], &[NEW_PAYLOAD_V5]),
        (&[NEW_PAYLOAD_V5], &[FORKCHOICE_UPDATED_V4]),
        (
            &[NEW_PAYLOAD_V4, FORKCHOICE_UPDATED_V3, GET_PAYLOAD_V5],
            &both,
        ),
        (&[], &both),
    ];
    for (listed, missing) in cases {
        list(listed);
        match Session::connect(config(&mock, skewed(0))).await {
            Err(StartError::MissingCaps(caps)) => {
                assert_eq!(caps.missing(), missing, "{listed:?}");
            }
            other => panic!("{listed:?}: {other:?}"),
        }
    }
    // A reconnect checks again, and so does the reconnect before the next call.
    list(&both);
    let queue = Queue::connect(config(&mock, skewed(0)), 1)
        .await
        .unwrap_or_else(|err| panic!("{err}"));
    list(&[NEW_PAYLOAD_V4, FORKCHOICE_UPDATED_V3]);
    let err = queue.reconnect().await;
    assert!(matches!(err, Err(StartError::MissingCaps(_))), "{err:?}");
    let err = queue
        .call(
            1,
            NEW_PAYLOAD_V5,
            payload([0x03; 32]),
            NEW_PAYLOAD_V5_TIMEOUT,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CallError::MissingCaps(_)), "{err:?}");
    assert_eq!(sent(&mock), [EXCHANGE_CAPABILITIES; 7]);
}
