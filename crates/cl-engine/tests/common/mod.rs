//! In-crate hyper mock execution layer. No live host.
//!
//! Each integration-test binary compiles this module and uses a different subset of it.

#![allow(dead_code)]

use bytes::Bytes;
use cl_engine::jwt::{self, JwtSecret, CREDENTIAL};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

pub struct Seen {
    pub method: String,
    pub seq: Option<u64>,
}

struct State {
    secret: [u8; 32],
    methods: Mutex<Vec<String>>,
    seen: Mutex<Vec<Seen>>,
    iats: Mutex<Vec<i64>>,
    results: Mutex<VecDeque<Value>>,
    fail_remaining: AtomicU32,
    hold_remaining: AtomicU32,
    hold: watch::Receiver<bool>,
    delay: Mutex<Duration>,
    chunked: AtomicU32,
    capability_calls: AtomicU64,
}

pub struct MockEl {
    addr: SocketAddr,
    state: Arc<State>,
    release: watch::Sender<bool>,
    _shutdown: oneshot::Sender<()>,
}

impl MockEl {
    pub async fn start(secret: &[u8; 32], methods: Vec<String>) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (release, hold) = watch::channel(false);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let state = Arc::new(State {
            secret: *secret,
            methods: Mutex::new(methods),
            seen: Mutex::new(Vec::new()),
            iats: Mutex::new(Vec::new()),
            results: Mutex::new(VecDeque::new()),
            fail_remaining: AtomicU32::new(0),
            hold_remaining: AtomicU32::new(0),
            hold,
            delay: Mutex::new(Duration::ZERO),
            chunked: AtomicU32::new(0),
            capability_calls: AtomicU64::new(0),
        });
        let serve = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let state = Arc::clone(&serve);
                        tokio::spawn(async move {
                            let conn = hyper::server::conn::http1::Builder::new().serve_connection(
                                TokioIo::new(stream),
                                service_fn(move |req| {
                                    let state = Arc::clone(&state);
                                    async move { handle(state, req).await }
                                }),
                            );
                            let _ = conn.await;
                        });
                    }
                }
            }
        });
        Self {
            addr,
            state,
            release,
            _shutdown: shutdown_tx,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set_methods(&self, methods: &[&str]) {
        *self.state.methods.lock().unwrap() = methods.iter().map(|m| (*m).to_owned()).collect();
    }

    pub fn push_result(&self, result: Value) {
        self.state.results.lock().unwrap().push_back(result);
    }

    pub fn fail_next(&self) {
        self.state.fail_remaining.fetch_add(1, Ordering::Relaxed);
    }

    pub fn hold_next(&self) {
        self.state.hold_remaining.fetch_add(1, Ordering::Relaxed);
    }

    pub fn release(&self) {
        self.release.send(true).unwrap();
    }

    pub fn set_delay(&self, delay: Duration) {
        *self.state.delay.lock().unwrap() = delay;
    }

    /// The next engine call (not the capability exchange) answers with `bytes` of chunked body
    /// and no `Content-Length`.
    pub fn chunked_next(&self, bytes: u32) {
        self.state.chunked.store(bytes, Ordering::Relaxed);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|seen| Seen {
                method: seen.method.clone(),
                seq: seen.seq,
            })
            .collect()
    }

    pub fn iats(&self) -> Vec<i64> {
        self.state.iats.lock().unwrap().clone()
    }

    pub fn capability_calls(&self) -> u64 {
        self.state.capability_calls.load(Ordering::Relaxed)
    }

    pub async fn wait_for_method(&self, method: &str) {
        for _ in 0..400 {
            if self.seen().iter().any(|seen| seen.method == method) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {method}");
    }
}

async fn handle(
    state: Arc<State>,
    req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<http_body_util::combinators::BoxBody<Bytes, Infallible>>, std::io::Error>
{
    let authorized = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    let bytes = req
        .into_body()
        .collect()
        .await
        .map_err(std::io::Error::other)?
        .to_bytes();
    let Some(token) = authorized else {
        return Ok(status(401, Bytes::from_static(b"missing jwt")));
    };
    let claims = match jwt::verify(&state.secret, &token, std::time::SystemTime::now()) {
        Ok(claims) => claims,
        Err(_) => return Ok(status(401, Bytes::from_static(b"rejected jwt"))),
    };
    state.iats.lock().unwrap().push(claims.iat);
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let seq = body
        .get("params")
        .and_then(Value::as_array)
        .and_then(|params| params.first())
        .and_then(Value::as_u64);
    state.seen.lock().unwrap().push(Seen {
        method: method.clone(),
        seq,
    });
    if decrement(&state.fail_remaining) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "el restart",
        ));
    }
    if method == "engine_exchangeCapabilities" {
        state.capability_calls.fetch_add(1, Ordering::Relaxed);
        let methods = state.methods.lock().unwrap().clone();
        return Ok(json_response(
            &serde_json::json!({"jsonrpc":"2.0","id":id,"result":methods}),
        ));
    }
    let chunked = state.chunked.swap(0, Ordering::Relaxed);
    if chunked > 0 {
        return Ok(chunked_response(chunked));
    }
    let delay = *state.delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let hold = decrement(&state.hold_remaining);
    let result = state
        .results
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or_else(default_status);
    if hold {
        let mut rx = state.hold.clone();
        if tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|ready| *ready))
            .await
            .is_err()
        {
            return Ok(json_response(
                &serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"hold expired"}}),
            ));
        }
    }
    Ok(json_response(
        &serde_json::json!({"jsonrpc":"2.0","id":id,"result":result}),
    ))
}

fn decrement(counter: &AtomicU32) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current == 0 {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn default_status() -> Value {
    serde_json::json!({"status":"VALID","latestValidHash":null,"validationError":null})
}

fn json_response(
    value: &Value,
) -> hyper::Response<http_body_util::combinators::BoxBody<Bytes, Infallible>> {
    status(200, Bytes::from(serde_json::to_vec(value).unwrap()))
}

fn status(
    code: u16,
    body: Bytes,
) -> hyper::Response<http_body_util::combinators::BoxBody<Bytes, Infallible>> {
    hyper::Response::builder()
        .status(code)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(body).map_err(|err| match err {}).boxed())
        .unwrap()
}

fn chunked_response(
    total: u32,
) -> hyper::Response<http_body_util::combinators::BoxBody<Bytes, Infallible>> {
    let chunk = Bytes::from(vec![b'x'; 32]);
    let n = usize::try_from(total)
        .unwrap_or(0)
        .div_ceil(chunk.len())
        .max(1);
    let stream =
        tokio_stream::iter((0..n).map(move |_| Ok::<_, Infallible>(Frame::data(chunk.clone()))));
    hyper::Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(StreamBody::new(stream).boxed())
        .unwrap()
}

pub fn required_methods() -> Vec<String> {
    cl_engine::capabilities::REQUIRED
        .into_iter()
        .map(str::to_owned)
        .collect()
}

pub fn test_secret(bytes: [u8; 32]) -> JwtSecret {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CREDENTIAL);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(hex_encode(&bytes).as_bytes())
        .unwrap();
    let uid = match rustix::process::geteuid().as_raw() {
        0 => 4242,
        uid => uid,
    };
    if rustix::process::geteuid().is_root() {
        rustix::fs::chown(&path, Some(rustix::process::Uid::from_raw(uid)), None).unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    jwt::load(Some(dir.path().as_os_str()), uid, "ethswarm-engine.service").unwrap()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
