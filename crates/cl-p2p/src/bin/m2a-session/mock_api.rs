//! A mock reference beacon API for the tests: plain HTTP/1.1 on 127.0.0.1. Each path has a
//! scripted list of replies (the `n`th request gets the `n`th, the last repeats), unknown
//! paths are 404, and every request is recorded.

use bytes::Bytes;
use consensus_types::primitives::{Root, Slot};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use p2p_wire::rpc::messages::MetaDataV3;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// The replies of one path, in order.
#[derive(Clone, Debug)]
pub struct Route(Vec<String>);

impl Route {
    /// Always this JSON.
    pub fn json(body: impl Into<String>) -> Self {
        Self(vec![body.into()])
    }

    /// These JSON bodies, one per request; the last repeats.
    pub fn sequence(bodies: Vec<String>) -> Self {
        assert!(!bodies.is_empty());
        Self(bodies)
    }
}

type Seen = Arc<Mutex<Vec<(String, HashMap<String, String>)>>>;

/// A running mock.
pub struct MockApi {
    /// Where it listens.
    pub addr: SocketAddr,
    seen: Seen,
}

impl MockApi {
    /// Serves `routes` on 127.0.0.1 until the test ends.
    pub async fn start(routes: Vec<(&str, Route)>) -> Self {
        Self::start_on("127.0.0.1:0", routes)
            .await
            .expect("127.0.0.1 is available")
    }

    /// Serves `routes` on `bind`, or `None` if it cannot be bound.
    pub async fn start_on(bind: &str, routes: Vec<(&str, Route)>) -> Option<Self> {
        let routes: HashMap<String, Route> =
            routes.into_iter().map(|(p, r)| (p.to_owned(), r)).collect();
        let routes = Arc::new(routes);
        let counts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let seen = Seen::default();
        let listener = TcpListener::bind(bind).await.ok()?;
        let addr = listener.local_addr().unwrap();
        let record = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (routes, counts, record) = (
                    Arc::clone(&routes),
                    Arc::clone(&counts),
                    Arc::clone(&record),
                );
                let service = service_fn(move |req: Request<Incoming>| {
                    let path = req.uri().path().to_owned();
                    let headers = req
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
                        .collect();
                    record.lock().unwrap().push((path.clone(), headers));
                    let body = routes.get(&path).map(|r| {
                        let mut counts = counts.lock().unwrap();
                        let n = counts.entry(path.clone()).or_insert(0);
                        let body = r.0[(*n).min(r.0.len() - 1)].clone();
                        *n += 1;
                        body
                    });
                    async move {
                        let response = match body {
                            Some(b) => Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(b))),
                            None => Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::new(Bytes::new())),
                        };
                        Ok::<_, Infallible>(response.unwrap())
                    }
                });
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Some(Self { addr, seen })
    }

    /// `http://<addr>`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request: its path and headers.
    pub fn seen(&self) -> Vec<(String, HashMap<String, String>)> {
        self.seen.lock().unwrap().clone()
    }

    /// How many requests hit `path`.
    pub fn hits(&self, path: &str) -> usize {
        self.seen().iter().filter(|(p, _)| p == path).count()
    }

    /// A `/eth/v1/beacon/headers/{id}` body.
    pub fn header_json(root: Root, slot: Slot, canonical: bool) -> String {
        format!(
            r#"{{"execution_optimistic":false,"finalized":false,"data":{{"root":"{root}",
            "canonical":{canonical},"header":{{"message":{{"slot":"{slot}","proposer_index":"4",
            "parent_root":"{root}","state_root":"{root}","body_root":"{root}"}},
            "signature":"0x00"}}}}}}"#
        )
    }

    /// A `/eth/v1/beacon/states/head/finality_checkpoints` body.
    pub fn finality_json(epoch: u64, root: Root) -> String {
        format!(
            r#"{{"execution_optimistic":false,"finalized":false,"data":{{
            "previous_justified":{{"epoch":"{e0}","root":"{root}"}},
            "current_justified":{{"epoch":"{e1}","root":"{root}"}},
            "finalized":{{"epoch":"{epoch}","root":"{root}"}}}}}}"#,
            e0 = epoch + 1,
            e1 = epoch + 2,
        )
    }

    /// A `/eth/v1/beacon/genesis` body.
    pub fn genesis_json(time: u64, gvr: Root, version: [u8; 4]) -> String {
        let v: String = version.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            r#"{{"data":{{"genesis_time":"{time}","genesis_validators_root":"{gvr}",
            "genesis_fork_version":"0x{v}"}}}}"#
        )
    }

    /// A `/eth/v1/node/identity` body with `metadata`, encoded as the beacon API does.
    pub fn identity_json(enr: &str, metadata: &MetaDataV3) -> String {
        let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
        format!(
            r#"{{"data":{{"peer_id":"16Uiu2HAm","enr":"{enr}","p2p_addresses":[],
            "discovery_addresses":[],"metadata":{{"seq_number":"{seq}","attnets":"0x{att}",
            "syncnets":"0x{sync}","custody_group_count":"{cgc}"}}}}}}"#,
            seq = metadata.seq_number,
            att = hex(metadata.attnets.as_slice()),
            sync = hex(metadata.syncnets.as_slice()),
            cgc = metadata.custody_group_count,
        )
    }
}
