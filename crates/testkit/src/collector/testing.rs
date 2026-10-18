//! Test doubles (feature `test-support`): a scripted clock, a pause that advances it instead of
//! sleeping, a fixture beacon node serving scripted HTTP/1.1 replies on 127.0.0.1, and a
//! server that hangs up on every connection.

use super::clock::{Clock, Stamp};
use super::sse::Pause;
use super::url::ReferenceApiUrl;
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;

/// A clock that moves only when told to.
#[derive(Debug, Default)]
pub struct ManualClock(Mutex<Stamp>);

impl ManualClock {
    /// A clock at `wall_ns` on the wall and 0 on the monotonic clock.
    pub fn at(wall_ns: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Stamp {
            mono_ns: 0,
            wall_ns,
        })))
    }

    /// Moves both clocks forward by `d`.
    pub fn advance(&self, d: Duration) {
        let ns = u64::try_from(d.as_nanos()).unwrap();
        let mut now = self.0.lock().unwrap();
        now.mono_ns += ns;
        now.wall_ns += ns;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Stamp {
        *self.0.lock().unwrap()
    }
}

/// A pause that advances a [`ManualClock`] and returns at once.
#[derive(Debug, Clone)]
pub struct ManualPause(pub Arc<ManualClock>);

impl Pause for ManualPause {
    async fn pause(&self, d: Duration) {
        self.0.advance(d);
        tokio::task::yield_now().await;
    }
}

/// One scripted reply.
#[derive(Debug, Clone)]
pub struct Reply {
    status: StatusCode,
    content_type: &'static str,
    chunks: Vec<Bytes>,
    hold: bool,
    pace: Option<Duration>,
}

impl Reply {
    /// A 200 `text/event-stream` body of `chunks`, one write each; `hold` keeps the stream
    /// open after them, otherwise it ends.
    pub fn stream(chunks: Vec<&str>, hold: bool) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "text/event-stream",
            chunks: chunks
                .into_iter()
                .map(|c| Bytes::copy_from_slice(c.as_bytes()))
                .collect(),
            hold,
            pace: None,
        }
    }

    /// This reply with `every` between its chunks (real time), the first after `every` too.
    pub fn paced(self, every: Duration) -> Self {
        Self {
            pace: Some(every),
            ..self
        }
    }

    /// A 200 JSON body.
    pub fn json(body: &str) -> Self {
        Self {
            content_type: "application/json",
            ..Self::stream(vec![body], false)
        }
    }

    /// A 200 `application/octet-stream` body: SSZ, as the beacon API serves it.
    pub fn ssz(body: Vec<u8>) -> Self {
        Self {
            content_type: "application/octet-stream",
            chunks: vec![Bytes::from(body)],
            ..Self::stream(vec![], false)
        }
    }

    /// `status` with an empty body.
    pub fn status(status: u16) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap(),
            ..Self::stream(vec![], false)
        }
    }

    /// This reply with another content type.
    pub fn content_type(self, content_type: &'static str) -> Self {
        Self {
            content_type,
            ..self
        }
    }
}

/// A body that writes its chunks, `pace` apart if set, then ends or stays open.
struct ChunkBody {
    chunks: VecDeque<Bytes>,
    hold: bool,
    pace: Option<Duration>,
    wait: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Body for ChunkBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let (Some(pace), false) = (self.pace, self.chunks.is_empty()) {
            let wait = self
                .wait
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(pace)));
            if wait.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.wait = None;
        }
        match self.chunks.pop_front() {
            Some(chunk) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            // Never woken: the client ends it by closing the connection.
            None if self.hold => Poll::Pending,
            None => Poll::Ready(None),
        }
    }
}

type Seen = Arc<Mutex<Vec<(String, HeaderMap)>>>;

/// A fixture beacon node on 127.0.0.1: the `n`th request (from 0), for path `path` (without
/// the query), gets `reply(n, path)`.
pub struct FixtureServer {
    /// Where it listens.
    pub addr: SocketAddr,
    seen: Seen,
}

impl FixtureServer {
    /// Serves until the test ends.
    pub async fn start(reply: impl Fn(usize, &str) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Seen::default();
        let record = Arc::clone(&seen);
        let reply = Arc::new(reply);
        let count = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (reply, count, record) =
                    (Arc::clone(&reply), Arc::clone(&count), Arc::clone(&record));
                let service = service_fn(move |req: Request<Incoming>| {
                    let path = req.uri().path_and_query().unwrap().to_string();
                    record
                        .lock()
                        .unwrap()
                        .push((path.clone(), req.headers().clone()));
                    let r = reply(count.fetch_add(1, Ordering::SeqCst), req.uri().path());
                    async move {
                        let body = ChunkBody {
                            chunks: r.chunks.into(),
                            hold: r.hold,
                            pace: r.pace,
                            wait: None,
                        };
                        Response::builder()
                            .status(r.status)
                            .header("content-type", r.content_type)
                            .body(body)
                    }
                });
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { addr, seen }
    }

    /// The server's URL with base path `base` (`""` or `/…`).
    pub fn url(&self, base: &str) -> ReferenceApiUrl {
        ReferenceApiUrl::parse(&format!("http://{}{base}", self.addr)).unwrap()
    }

    /// Every request so far: path and query, headers.
    pub fn seen(&self) -> Vec<(String, HeaderMap)> {
        self.seen.lock().unwrap().clone()
    }
}

/// A loopback server that accepts every connection and closes it at once, before reading a
/// byte: every request to it fails. It holds its port until the test's runtime ends, so no
/// other socket can take the port meanwhile; freeing a port and hoping nothing listens there
/// does not hold under load.
#[derive(Debug)]
pub struct HangUp {
    /// Where it listens.
    pub addr: SocketAddr,
}

impl HangUp {
    /// Listens on a fresh port on 127.0.0.1.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        Self { addr }
    }

    /// Its URL with base path `base` (`""` or `/…`).
    pub fn url(&self, base: &str) -> ReferenceApiUrl {
        ReferenceApiUrl::parse(&format!("http://{}{base}", self.addr)).unwrap()
    }
}

/// A `SignedExecutionPayloadEnvelope` for `block_root` whose payload is at `slot`, snappy
/// block-compressed as gossip carries it.
pub fn envelope(slot: u64, block_root: consensus_types::primitives::Root) -> Vec<u8> {
    use crate::archive::fixtures::{snappy, Spec};
    use consensus_types::gloas;
    use ssz::Encode;
    let block = p2p_wire::testkit::fulu_block::<Spec>(slot);
    let f = &block.message.body.execution_payload;
    let envelope = gloas::SignedExecutionPayloadEnvelope::<Spec> {
        message: gloas::ExecutionPayloadEnvelope {
            payload: gloas::ExecutionPayload {
                parent_hash: f.parent_hash,
                fee_recipient: f.fee_recipient,
                state_root: f.state_root,
                receipts_root: f.receipts_root,
                logs_bloom: f.logs_bloom.clone(),
                prev_randao: f.prev_randao,
                block_number: f.block_number,
                gas_limit: f.gas_limit,
                gas_used: f.gas_used,
                timestamp: f.timestamp,
                extra_data: f.extra_data.clone(),
                base_fee_per_gas: f.base_fee_per_gas,
                block_hash: f.block_hash,
                transactions: Default::default(),
                withdrawals: Default::default(),
                blob_gas_used: f.blob_gas_used,
                excess_blob_gas: f.excess_blob_gas,
                block_access_list: Default::default(),
                slot_number: slot,
            },
            execution_requests: gloas::ExecutionRequests {
                deposits: Default::default(),
                withdrawals: Default::default(),
                consolidations: Default::default(),
                builder_deposits: Default::default(),
                builder_exits: Default::default(),
            },
            builder_index: 7,
            beacon_block_root: block_root,
            parent_beacon_block_root: block.message.parent_root,
        },
        signature: block.signature,
    };
    snappy(&envelope.as_ssz_bytes())
}
