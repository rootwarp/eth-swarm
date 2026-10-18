//! The `/eth/v1/events` client: one long-lived GET per connection, reconnected with backoff.
//!
//! hyper 1 over plain TCP to a loopback [`ReferenceApiUrl`], HTTP/1.1, no redirects (anything
//! but `200 text/event-stream` is a failure). Each body chunk is stamped the moment it arrives,
//! before the parser reads it, and every event it completes carries that stamp. A stream that
//! ends, fails, sends an oversized event or stays silent for [`SseConfig::idle_timeout`] is
//! reconnected; the time without a stream becomes a [`MissingInterval`], from the last chunk
//! received to the next stream's response, with the first failure's reason and the failed
//! attempts. Beacon nodes do not replay missed events, so every disconnect is a gap, however
//! short. Errors name the API path only, never the base URL or the query.

use super::parse::{SseParser, TooLarge};
use crate::collector::arrival::{Arrival, Arrivals, MissingInterval, StampedEvent};
use crate::collector::clock::{Clock, Stamp};
use crate::collector::record::Source;
use crate::collector::url::ReferenceApiUrl;
use bytes::Bytes;
use http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, HOST, USER_AGENT};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::watch;

/// The event stream's API path.
pub const EVENTS_PATH: &str = "/eth/v1/events";
/// The genesis API path.
pub const GENESIS_PATH: &str = "/eth/v1/beacon/genesis";
/// The events subscribed by default: the gossip-validation events of blocks, envelopes and
/// columns (beacon-APIs eventstream), the closest the API gets to gossip arrival.
pub const DEFAULT_TOPICS: [&str; 3] = [
    "block_gossip",
    "execution_payload_gossip",
    "data_column_sidecar",
];
/// Cap on a JSON response: 64 KiB.
pub const MAX_JSON_BYTES: usize = 64 << 10;

/// Waiting between reconnects. Injectable, so tests advance a scripted clock instead.
pub trait Pause: Sync {
    /// Waits `d`.
    fn pause(&self, d: Duration) -> impl Future<Output = ()> + Send;
}

/// [`Pause`] on the tokio timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioPause;

impl Pause for TokioPause {
    async fn pause(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

/// Reconnect backoff: `initial`, doubling up to `max`, back to `initial` once a stream
/// delivered an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The first wait.
    pub initial: Duration,
    /// The longest wait.
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
        }
    }
}

/// What the client connects to and how.
#[derive(Debug, Clone)]
pub struct SseConfig {
    /// The reference node's beacon API.
    pub url: ReferenceApiUrl,
    /// The subscribed event names (`topics=`).
    pub topics: Vec<String>,
    /// Reconnect backoff.
    pub backoff: Backoff,
    /// Deadline of connect plus response headers.
    pub request_timeout: Duration,
    /// A stream silent this long is dropped: five slots without a block event or keep-alive.
    pub idle_timeout: Duration,
}

/// A refused [`SseConfig`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SseConfigError {
    /// No topic.
    #[error("no SSE topic to subscribe")]
    NoTopic,
    /// A topic that is not `[a-z0-9_]+`.
    #[error("SSE topic {0:?} may only use [a-z0-9_]")]
    Topic(String),
}

impl SseConfig {
    /// `url` with `topics` (sorted, deduplicated), 1 s to 30 s backoff, a 10 s request and a
    /// 60 s idle deadline.
    pub fn new(url: ReferenceApiUrl, topics: &[&str]) -> Result<Self, SseConfigError> {
        let mut topics: Vec<String> = topics.iter().map(|t| (*t).to_owned()).collect();
        topics.sort();
        topics.dedup();
        if topics.is_empty() {
            return Err(SseConfigError::NoTopic);
        }
        let allowed = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_';
        if let Some(bad) = topics
            .iter()
            .find(|t| t.is_empty() || !t.bytes().all(allowed))
        {
            return Err(SseConfigError::Topic(bad.clone()));
        }
        Ok(Self {
            url,
            topics,
            backoff: Backoff::default(),
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
        })
    }

    fn path_and_query(&self) -> String {
        format!("{EVENTS_PATH}?topics={}", self.topics.join(","))
    }
}

/// Why a request or a stream failed. Names the API path, never the base URL or the query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// Connect or HTTP failure.
    #[error("{path}: {reason}")]
    Transport {
        /// The API path.
        path: &'static str,
        /// Why.
        reason: String,
    },
    /// A status other than 200.
    #[error("{path}: HTTP {status}")]
    Status {
        /// The API path.
        path: &'static str,
        /// The status code.
        status: u16,
    },
    /// The deadline passed.
    #[error("{path}: no answer within {timeout:?}")]
    Timeout {
        /// The API path.
        path: &'static str,
        /// The deadline.
        timeout: Duration,
    },
    /// The response is not what the API specifies.
    #[error("{path}: bad response: {reason}")]
    BadResponse {
        /// The API path.
        path: &'static str,
        /// Why.
        reason: String,
    },
}

/// What [`run`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SseStats {
    /// Streams opened.
    pub connections: u64,
    /// Events handed over (offered; drops are counted by [`Arrivals`]).
    pub events: u64,
    /// Missing intervals recorded.
    pub gaps: u64,
}

/// Streams events into `arrivals` until `stop` turns true (or its sender is dropped),
/// reconnecting with backoff and recording every gap. An interval still open at the stop is
/// recorded as [`MissingInterval::open_at_shutdown`]. Returns early if the collector has
/// stopped (the channel is closed).
pub async fn run<P: Pause>(
    config: &SseConfig,
    clock: &dyn Clock,
    pause: &P,
    arrivals: &Arrivals,
    mut stop: watch::Receiver<bool>,
) -> SseStats {
    let mut stats = SseStats::default();
    let started = clock.now();
    let mut gap: Option<OpenGap> = None;
    let mut delay = config.backoff.initial;
    loop {
        let attempt = tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            attempt = open(config) => attempt,
        };
        match attempt {
            Err(e) => {
                let open = gap.get_or_insert_with(|| OpenGap::new(started, e.to_string()));
                open.failed_attempts += 1;
            }
            Ok(body) => {
                let connected = clock.now();
                stats.connections += 1;
                if let Some(open) = gap.take() {
                    let interval = open.close(connected, false);
                    if arrivals.deliver(Arrival::Gap(interval)).await.is_err() {
                        return stats;
                    }
                    stats.gaps += 1;
                }
                let streamed = stream(config, body, clock, arrivals, connected, &mut stop).await;
                stats.events += streamed.events;
                match streamed.end {
                    StreamEnd::Stopped => break,
                    StreamEnd::Failed(reason) => {
                        gap = Some(OpenGap::new(streamed.last_alive, reason));
                    }
                }
                if streamed.events > 0 {
                    delay = config.backoff.initial;
                }
            }
        }
        tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            () = pause.pause(delay) => {}
        }
        delay = delay.saturating_mul(2).min(config.backoff.max);
    }
    if let Some(open) = gap {
        let interval = open.close(clock.now(), true);
        if arrivals.deliver(Arrival::Gap(interval)).await.is_ok() {
            stats.gaps += 1;
        }
    }
    stats
}

/// Resolves once `stop` is true or its sender is gone.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stop| *stop).await;
}

/// A gap that has not ended yet.
struct OpenGap {
    start: Stamp,
    reason: String,
    failed_attempts: u32,
}

impl OpenGap {
    fn new(start: Stamp, reason: String) -> Self {
        Self {
            start,
            reason,
            failed_attempts: 0,
        }
    }

    fn close(self, end: Stamp, open_at_shutdown: bool) -> MissingInterval {
        MissingInterval {
            source: Source::Sse,
            start_mono_ns: self.start.mono_ns,
            start_wall_ns: self.start.wall_ns,
            end_mono_ns: end.mono_ns,
            end_wall_ns: end.wall_ns,
            reason: self.reason,
            failed_attempts: self.failed_attempts,
            open_at_shutdown,
        }
    }
}

enum StreamEnd {
    Stopped,
    Failed(String),
}

struct Streamed {
    end: StreamEnd,
    /// The last chunk's stamp, or the connection's if none came.
    last_alive: Stamp,
    events: u64,
}

/// Reads one stream until it ends, fails, goes idle or `stop`.
async fn stream(
    config: &SseConfig,
    mut body: Incoming,
    clock: &dyn Clock,
    arrivals: &Arrivals,
    connected: Stamp,
    stop: &mut watch::Receiver<bool>,
) -> Streamed {
    let mut parser = SseParser::default();
    let mut out = Streamed {
        end: StreamEnd::Stopped,
        last_alive: connected,
        events: 0,
    };
    let failed = |reason: String| StreamEnd::Failed(format!("{EVENTS_PATH}: {reason}"));
    out.end = loop {
        let frame = tokio::select! {
            biased;
            () = stopped(stop) => break StreamEnd::Stopped,
            frame = tokio::time::timeout(config.idle_timeout, body.frame()) => frame,
        };
        let frame = match frame {
            Err(_) => break failed(format!("no bytes within {:?}", config.idle_timeout)),
            Ok(None) => break failed("the stream ended".into()),
            Ok(Some(Err(e))) => break failed(format!("body: {e}")),
            Ok(Some(Ok(frame))) => frame,
        };
        // The receive time, before the parser reads a byte.
        let stamp = clock.now();
        let Ok(chunk) = frame.into_data() else {
            continue; // trailers
        };
        out.last_alive = stamp;
        match parser.feed(&chunk) {
            Ok(events) => {
                for event in events {
                    arrivals.offer(Arrival::Sse(StampedEvent { stamp, event }));
                    out.events += 1;
                }
            }
            Err(e @ TooLarge) => break failed(e.to_string()),
        }
    };
    out
}

/// Opens the event stream: connect, `200 text/event-stream`, within the request deadline.
async fn open(config: &SseConfig) -> Result<Incoming, ApiError> {
    let path_and_query = config.path_and_query();
    let request = get(
        &config.url,
        EVENTS_PATH,
        &path_and_query,
        "text/event-stream",
    );
    let response = tokio::time::timeout(config.request_timeout, request)
        .await
        .map_err(|_| ApiError::Timeout {
            path: EVENTS_PATH,
            timeout: config.request_timeout,
        })??;
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .to_ascii_lowercase()
        .starts_with("text/event-stream")
    {
        return Err(ApiError::BadResponse {
            path: EVENTS_PATH,
            reason: "the content type is not text/event-stream".into(),
        });
    }
    Ok(response.into_body())
}

/// `GET <base><path_and_query>` on a fresh HTTP/1.1 connection; anything but 200 is an error.
async fn get(
    url: &ReferenceApiUrl,
    path: &'static str,
    path_and_query: &str,
    accept: &str,
) -> Result<http::Response<Incoming>, ApiError> {
    let transport = |reason: String| ApiError::Transport { path, reason };
    let request = Request::get(format!("{}{path_and_query}", url.base_path()))
        .header(HOST, url.authority())
        .header(ACCEPT, accept)
        .header(CACHE_CONTROL, "no-cache")
        .header(
            USER_AGENT,
            concat!("ethswarm-collector/", env!("CARGO_PKG_VERSION")),
        )
        .body(Empty::<Bytes>::new())
        .map_err(|e| transport(format!("request: {e}")))?;
    let tcp = TcpStream::connect(&url.addrs()[..])
        .await
        .map_err(|e| transport(format!("connect: {e}")))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .map_err(|e| transport(format!("http: {e}")))?;
    tokio::spawn(async move {
        // Ends when the body is read or dropped; its errors surface on the body.
        let _ = connection.await;
    });
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| transport(format!("http: {e}")))?;
    if response.status() != StatusCode::OK {
        return Err(ApiError::Status {
            path,
            status: response.status().as_u16(),
        });
    }
    Ok(response)
}

/// `GET /eth/v1/beacon/genesis`: `genesis_time`, Unix seconds (a decimal string, as the API
/// specifies; anything else is refused).
pub async fn genesis_time(url: &ReferenceApiUrl, timeout: Duration) -> Result<u64, ApiError> {
    #[derive(serde::Deserialize)]
    struct Data {
        data: Genesis,
    }
    #[derive(serde::Deserialize)]
    struct Genesis {
        genesis_time: String,
    }
    let bad = |reason: String| ApiError::BadResponse {
        path: GENESIS_PATH,
        reason,
    };
    let fetch = async {
        let response = get(url, GENESIS_PATH, GENESIS_PATH, "application/json").await?;
        match Limited::new(response.into_body(), MAX_JSON_BYTES)
            .collect()
            .await
        {
            Ok(body) => Ok(body.to_bytes()),
            Err(e) if e.is::<http_body_util::LengthLimitError>() => {
                Err(bad(format!("body over {MAX_JSON_BYTES} bytes")))
            }
            Err(e) => Err(ApiError::Transport {
                path: GENESIS_PATH,
                reason: format!("body: {e}"),
            }),
        }
    };
    let body = tokio::time::timeout(timeout, fetch)
        .await
        .map_err(|_| ApiError::Timeout {
            path: GENESIS_PATH,
            timeout,
        })??;
    let d: Data = serde_json::from_slice(&body).map_err(|e| bad(format!("json: {e}")))?;
    let text = d.data.genesis_time;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!("genesis_time {text:?} is not a decimal u64")));
    }
    text.parse()
        .map_err(|e| bad(format!("genesis_time {text:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::testing::{FixtureServer, ManualClock, ManualPause, Reply};
    use crate::collector::SseEvent;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    const KEY: &str = "/key-hunter2";
    const BLOCK: &str = "event: block_gossip\ndata: {\"slot\":\"1\",\"block\":\"0x01\"}\n\n";

    fn config(server: &FixtureServer, topics: &[&str]) -> SseConfig {
        let mut c = SseConfig::new(server.url(KEY), topics).unwrap();
        c.backoff = Backoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(4),
        };
        c.idle_timeout = Duration::from_millis(300);
        c.request_timeout = Duration::from_secs(5);
        c
    }

    /// Runs the client until `until` holds for the arrivals so far, then stops it.
    async fn run_until(
        config: SseConfig,
        clock: Arc<ManualClock>,
        until: impl Fn(&[Arrival]) -> bool,
    ) -> (Vec<Arrival>, SseStats) {
        let (arrivals, mut rx) = Arrivals::channel(1024);
        let (stop_tx, stop) = watch::channel(false);
        let pause = ManualPause(Arc::clone(&clock));
        let client = tokio::spawn(async move {
            let stats = run(&config, &*clock, &pause, &arrivals, stop).await;
            drop(arrivals);
            stats
        });
        let mut seen = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !until(&seen) {
            assert!(
                std::time::Instant::now() < deadline,
                "not done in 10 s: {seen:?}"
            );
            if let Ok(next) = tokio::time::timeout(Duration::from_millis(10), rx.recv()).await {
                seen.push(next.expect("the client runs"));
            }
        }
        stop_tx.send(true).unwrap();
        let stats = client.await.unwrap();
        seen.extend(drain(&mut rx).await);
        (seen, stats)
    }

    async fn drain(rx: &mut mpsc::Receiver<Arrival>) -> Vec<Arrival> {
        let mut out = Vec::new();
        while let Some(a) = rx.recv().await {
            out.push(a);
        }
        out
    }

    fn events(arrivals: &[Arrival]) -> Vec<&StampedEvent> {
        arrivals
            .iter()
            .filter_map(|a| match a {
                Arrival::Sse(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    fn gaps(arrivals: &[Arrival]) -> Vec<&MissingInterval> {
        arrivals
            .iter()
            .filter_map(|a| match a {
                Arrival::Gap(g) => Some(g),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn config_topics_are_checked() {
        let url = ReferenceApiUrl::parse("http://127.0.0.1:5052").unwrap();
        let c = SseConfig::new(url.clone(), &["head", "block_gossip", "head"]).unwrap();
        assert_eq!(c.topics, ["block_gossip", "head"]);
        assert_eq!(
            c.path_and_query(),
            "/eth/v1/events?topics=block_gossip,head"
        );
        assert_eq!(
            SseConfig::new(url.clone(), &[]).unwrap_err(),
            SseConfigError::NoTopic
        );
        for bad in ["", "Head", "a&b", "a,b", "a b"] {
            assert_eq!(
                SseConfig::new(url.clone(), &[bad]).unwrap_err(),
                SseConfigError::Topic(bad.into())
            );
        }
    }

    #[tokio::test]
    async fn events_carry_the_stamp_of_the_chunk_that_completed_them() {
        let server = FixtureServer::start(|_, _| {
            Reply::stream(
                vec![": hi\n\nevent: block_gossip\ndata: {}\n", "\n", BLOCK],
                true,
            )
        })
        .await;
        let clock = ManualClock::at(1_000);
        let (seen, stats) = run_until(config(&server, &DEFAULT_TOPICS), clock, |s| {
            events(s).len() == 2
        })
        .await;
        let got = events(&seen);
        assert_eq!(
            got[0].event,
            SseEvent {
                event: "block_gossip".into(),
                data: "{}".into()
            }
        );
        assert_eq!(got[0].stamp.wall_ns, 1_000);
        assert!(gaps(&seen).is_empty(), "{seen:?}");
        assert_eq!((stats.connections, stats.events, stats.gaps), (1, 2, 0));

        let (path, headers) = &server.seen()[0];
        assert_eq!(
            path,
            &format!(
                "{KEY}/eth/v1/events?topics=block_gossip,data_column_sidecar,\
                 execution_payload_gossip"
            )
        );
        assert_eq!(headers[ACCEPT], "text/event-stream");
        assert_eq!(headers[HOST], server.addr.to_string());
    }

    #[tokio::test]
    async fn a_refused_reply_is_a_gap_that_never_shows_the_url() {
        let server = FixtureServer::start(|n, _| match n {
            0 => Reply::status(503),
            1 => Reply::stream(vec![BLOCK], true).content_type("application/json"),
            _ => Reply::stream(vec![BLOCK], true),
        })
        .await;
        let clock = ManualClock::at(0);
        let (seen, stats) = run_until(config(&server, &["block_gossip"]), clock, |s| {
            !events(s).is_empty()
        })
        .await;
        let gaps = gaps(&seen);
        assert_eq!(gaps.len(), 1, "{seen:?}");
        let g = gaps[0];
        // From the start (it never connected) to the third request, after a 1 s and a 2 s wait.
        assert_eq!((g.start_mono_ns, g.end_mono_ns), (0, 3_000_000_000));
        assert_eq!(g.failed_attempts, 2);
        assert_eq!(g.reason, "/eth/v1/events: HTTP 503");
        assert!(!g.open_at_shutdown);
        assert_eq!((stats.connections, stats.gaps), (1, 1));
        for a in &seen {
            assert!(!format!("{a:?}").contains("hunter2"), "{a:?}");
        }
    }

    #[tokio::test]
    async fn a_dropped_stream_reconnects_and_backs_off() {
        // An event, then the stream ends; the next one sends an oversized event; then one that
        // stays silent past the idle deadline; then a good one.
        let huge = format!("data: {}\n\n", "x".repeat(super::super::MAX_EVENT_BYTES));
        let server = FixtureServer::start(move |n, _| match n {
            0 => Reply::stream(vec![BLOCK], false),
            1 => Reply::stream(vec![&huge], true),
            2 => Reply::stream(vec![], true),
            _ => Reply::stream(vec![BLOCK], true),
        })
        .await;
        let clock = ManualClock::at(0);
        let (seen, stats) = run_until(config(&server, &["block_gossip"]), clock, |s| {
            events(s).len() == 2
        })
        .await;
        let gaps = gaps(&seen);
        assert_eq!(gaps.len(), 3, "{seen:?}");
        assert_eq!(gaps[0].reason, "/eth/v1/events: the stream ended");
        assert!(gaps[1].reason.contains("over"), "{}", gaps[1].reason);
        assert!(
            gaps[2].reason.contains("no bytes within"),
            "{}",
            gaps[2].reason
        );
        // A stream that delivered an event resets the backoff: 1 s; the empty ones double it.
        let waits: Vec<u64> = gaps
            .iter()
            .map(|g| g.duration_ns() / 1_000_000_000)
            .collect();
        assert_eq!(waits, [1, 2, 4]);
        assert!(gaps.iter().all(|g| g.failed_attempts == 0));
        assert_eq!(stats.connections, 4);
    }

    #[tokio::test]
    async fn a_stop_while_down_closes_the_gap_as_open() {
        // Nothing listens on the port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = ReferenceApiUrl::parse(&format!("http://{}", listener.local_addr().unwrap()));
        drop(listener);
        let mut c = SseConfig::new(url.unwrap(), &["head"]).unwrap();
        c.backoff.max = Duration::from_secs(1);
        let clock = ManualClock::at(0);
        let (seen, stats) = run_until(c, Arc::clone(&clock), |_| {
            clock.now().mono_ns >= 3_000_000_000
        })
        .await;
        let gaps = gaps(&seen);
        assert_eq!(gaps.len(), 1, "{seen:?}");
        assert!(gaps[0].open_at_shutdown);
        assert!(gaps[0].failed_attempts >= 3);
        assert!(
            gaps[0].reason.starts_with("/eth/v1/events: connect"),
            "{}",
            gaps[0].reason
        );
        assert_eq!(stats.connections, 0);
    }

    #[tokio::test]
    async fn genesis_time_is_read_strictly() {
        let server = FixtureServer::start(|n, _| match n {
            0 => Reply::json(r#"{"data":{"genesis_time":"1742213400","genesis_validators_root":"0x00","genesis_fork_version":"0x10000910"}}"#),
            1 => Reply::json(r#"{"data":{"genesis_time":1742213400}}"#),
            2 => Reply::json(&format!("{{\"data\":{{\"genesis_time\":\"{}\"}}}}", "9".repeat(MAX_JSON_BYTES))),
            3 => Reply::json(r#"{"data":{"genesis_time":"+1"}}"#),
            _ => Reply::status(404),
        })
        .await;
        let url = server.url(KEY);
        let t = Duration::from_secs(5);
        assert_eq!(genesis_time(&url, t).await, Ok(1_742_213_400));
        for _ in 0..3 {
            let err = genesis_time(&url, t).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    ApiError::BadResponse {
                        path: GENESIS_PATH,
                        ..
                    }
                ),
                "{err}"
            );
        }
        let err = genesis_time(&url, t).await.unwrap_err();
        assert_eq!(
            err,
            ApiError::Status {
                path: GENESIS_PATH,
                status: 404
            }
        );
        assert_eq!(server.seen()[0].0, format!("{KEY}{GENESIS_PATH}"));
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = ReferenceApiUrl::parse(&format!("http://{}", listener.local_addr().unwrap()));
        // Accepts and never answers.
        let _held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let err = genesis_time(&url.unwrap(), Duration::from_millis(200)).await;
        assert!(
            matches!(
                err,
                Err(ApiError::Timeout {
                    path: GENESIS_PATH,
                    ..
                })
            ),
            "{err:?}"
        );
    }
}
