//! Loopback-only Engine API fixture. Enable `mock-el` from a dev-dependency.
//!
//! Scripts are persistent per block hash and method; unscripted hashes return VALID.
//! Responses reuse `engine-api`'s codec, except deliberate malformed/contradictory faults.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use engine_api::{FixedData, PayloadStatusV1, ValidationStatus};
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt, Full, Limited};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use sha2_hmac::Sha256;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};

/// Authentication settings. No Debug implementation: never print the key.
pub struct Config {
    /// A test-only HS256 key, not a production credential.
    pub key: [u8; 32],
    /// Maximum accepted absolute `iat` difference (normally 60 seconds).
    pub skew: Duration,
    /// Wall clock; injectable for deterministic JWT boundary tests.
    pub now: fn() -> SystemTime,
}

/// A persistent reply for a payload/head hash.
#[derive(Clone, Debug)]
pub enum Reply {
    /// VALID with the requested hash as latestValidHash.
    Valid,
    /// INVALID with a chosen latestValidHash (including null).
    Invalid {
        /// Latest valid ancestor, or unknown.
        lvh: Option<[u8; 32]>,
    },
    /// SYNCING with null latestValidHash.
    Syncing,
    /// ACCEPTED with null latestValidHash.
    Accepted,
    /// Return VALID after this duration (Tokio clock, controllable with paused time).
    Delay(Duration),
    /// Close the connection without an HTTP or JSON-RPC reply.
    Drop,
    /// HTTP 200 with an incomplete JSON document.
    Malformed,
    /// VALID with a mismatched latestValidHash and non-null validationError.
    Contradictory,
}

/// An authenticated request, recorded before any scripted delay/drop. No JWT is retained.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    /// JSON-RPC request id, preserved verbatim.
    pub id: Value,
    /// Engine method name.
    pub method: String,
    /// Original parameters for independent encoding and ordering assertions.
    pub params: Value,
}

struct State {
    requests: Vec<Request>,
    changed: Arc<Notify>,
    config: Config,
    capabilities: Vec<String>,
    // One lock protects method/hash scripts. Never held across I/O or await.
    scripts: HashMap<(String, [u8; 32]), Reply>,
}

/// A running fixture. Dropping it cancels the listener and every active connection.
pub struct MockEl {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    server: JoinHandle<()>,
}

impl MockEl {
    /// Binds an ephemeral IPv4 loopback port; never listens on a public interface.
    pub async fn start(config: Config) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            config,
            capabilities: vec![
                "engine_newPayloadV5".to_owned(),
                "engine_forkchoiceUpdatedV4".to_owned(),
            ],
            scripts: HashMap::new(),
            requests: Vec::new(),
            changed: Arc::new(Notify::new()),
        }));
        let shared = Arc::clone(&state);
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    Some(_) = connections.join_next() => {},
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        // Bound in-flight tasks, including stalled clients and delayed responses.
                        if connections.len() >= 64 { continue; }
                        let state = Arc::clone(&shared);
                        connections.spawn(async move {
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(
                                TokioIo::new(stream),
                                service_fn(move |req| handle(Arc::clone(&state), req)),
                            ).await;
                        });
                    }
                }
            }
        });
        Ok(Self {
            addr,
            state,
            server,
        })
    }

    /// The bound loopback endpoint.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// HTTP endpoint suitable for an Engine client configuration.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Sets/replaces the reply for this block in `engine_newPayloadV5`.
    pub fn on_new_payload(&self, block_hash: [u8; 32], reply: Reply) {
        self.script("engine_newPayloadV5", block_hash, reply);
    }

    /// Sets/replaces the reply for this head in `engine_forkchoiceUpdatedV4`.
    pub fn on_forkchoice_updated(&self, head_hash: [u8; 32], reply: Reply) {
        self.script("engine_forkchoiceUpdatedV4", head_hash, reply);
    }

    /// Overrides capability negotiation, including missing/old versions for startup-gate tests.
    pub fn set_capabilities(&self, methods: Vec<String>) {
        self.state.lock().expect("mock state poisoned").capabilities = methods;
    }

    /// Snapshot in server receive order, not response completion order.
    pub fn requests(&self) -> Vec<Request> {
        self.state
            .lock()
            .expect("mock state poisoned")
            .requests
            .clone()
    }

    /// Waits for at least `count` authenticated requests; cancellable, with no polling sleeps.
    pub async fn wait_for_requests(&self, count: usize) {
        let changed = Arc::clone(&self.state.lock().expect("mock state poisoned").changed);
        loop {
            let notified = changed.notified();
            // Register before checking the condition so no notification is lost.
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .state
                .lock()
                .expect("mock state poisoned")
                .requests
                .len()
                >= count
            {
                return;
            }
            notified.await;
        }
    }

    fn script(&self, method: &str, hash: [u8; 32], reply: Reply) {
        self.state
            .lock()
            .expect("mock state poisoned")
            .scripts
            .insert((method.to_owned(), hash), reply);
    }
}

impl Drop for MockEl {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn handle(
    state: Arc<Mutex<State>>,
    req: hyper::Request<hyper::body::Incoming>,
) -> io::Result<hyper::Response<Full<Bytes>>> {
    let authorized = req
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| {
            authenticated(&state.lock().expect("mock state poisoned").config, token)
        });
    if !authorized {
        return response(401, &json!({"error":"JWT rejected"}));
    }
    // This fixture intentionally accepts only small test payloads, not live blocks.
    let bytes = Limited::new(req.into_body(), 1024 * 1024)
        .collect()
        .await
        .map_err(io::Error::other)?
        .to_bytes();
    let body: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body["method"].as_str().unwrap_or("");
    {
        let mut state = state.lock().expect("mock state poisoned");
        // Bound retained fixture data. A runaway client fails instead of growing without limit.
        if state.requests.len() >= 4096 {
            return Err(io::Error::other("mock request log full"));
        }
        state.requests.push(Request {
            id: id.clone(),
            method: method.to_owned(),
            params: body["params"].clone(),
        });
        state.changed.notify_waiters();
    }
    match method {
        "engine_exchangeCapabilities" => {
            return response(
                200,
                &json!({"jsonrpc":"2.0", "id":id, "result":state.lock().expect("mock state poisoned").capabilities}),
            )
        }
        "engine_newPayloadV4" | "engine_getPayloadV5" | "engine_forkchoiceUpdatedV3" => {
            return rpc_error(id, -38005, "Unsupported fork")
        }
        "engine_newPayloadV5" | "engine_forkchoiceUpdatedV4" => {}
        _ => return rpc_error(id, -32601, "Method not found"),
    }
    let fcu = method == "engine_forkchoiceUpdatedV4";
    let hash: FixedData<32> = serde_json::from_value(
        body["params"][0][if fcu { "headBlockHash" } else { "blockHash" }].clone(),
    )
    .map_err(io::Error::other)?;
    let reply = state
        .lock()
        .expect("mock state poisoned")
        .scripts
        .get(&(method.to_owned(), hash.0))
        .cloned()
        .unwrap_or(Reply::Valid);
    let (status, latest_valid_hash, validation_error) = match reply {
        Reply::Drop => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "scripted EL drop",
            ))
        }
        Reply::Malformed => return raw_response(200, Bytes::from_static(b"{\"jsonrpc\":")),
        Reply::Contradictory => {
            let mut wrong = hash.0;
            wrong[0] ^= 1;
            (
                ValidationStatus::Valid,
                Some(FixedData(wrong)),
                Some("scripted contradiction".to_owned()),
            )
        }
        Reply::Delay(duration) => {
            tokio::time::sleep(duration).await;
            (ValidationStatus::Valid, Some(hash), None)
        }
        Reply::Valid => (ValidationStatus::Valid, Some(hash), None),
        Reply::Invalid { lvh } => (
            ValidationStatus::Invalid,
            lvh.map(FixedData),
            Some("scripted invalid payload".to_owned()),
        ),
        Reply::Syncing => (ValidationStatus::Syncing, None, None),
        Reply::Accepted => (ValidationStatus::Accepted, None, None),
    };
    let payload_status = PayloadStatusV1 {
        status,
        latest_valid_hash,
        validation_error,
    };
    let result = if fcu {
        json!({"payloadStatus":payload_status,"payloadId":null})
    } else {
        serde_json::to_value(payload_status).map_err(io::Error::other)?
    };
    response(200, &json!({"jsonrpc":"2.0","id":id,"result":result}))
}

fn response(code: u16, body: &Value) -> io::Result<hyper::Response<Full<Bytes>>> {
    raw_response(
        code,
        Bytes::from(serde_json::to_vec(body).map_err(io::Error::other)?),
    )
}

fn raw_response(code: u16, body: Bytes) -> io::Result<hyper::Response<Full<Bytes>>> {
    hyper::Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Full::new(body))
        .map_err(io::Error::other)
}

fn authenticated(config: &Config, token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let decode = |part| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    };
    let (Some(header_json), Some(claims)) = (decode(header), decode(payload)) else {
        return false;
    };
    if header_json["alg"] != "HS256" {
        return false;
    }
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&config.key) else {
        return false;
    };
    mac.update(format!("{header}.{payload}").as_bytes());
    if mac.verify_slice(&signature).is_err() {
        return false;
    }
    let Some(iat) = claims["iat"].as_u64() else {
        return false;
    };
    let Ok(now) = (config.now)().duration_since(UNIX_EPOCH) else {
        return false;
    };
    iat.abs_diff(now.as_secs()) <= config.skew.as_secs()
}

fn rpc_error(id: Value, code: i64, message: &str) -> io::Result<hyper::Response<Full<Bytes>>> {
    response(
        200,
        &json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}}),
    )
}
