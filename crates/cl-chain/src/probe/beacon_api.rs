//! [`BeaconApi`]: the reference node's Beacon API over HTTP.
//!
//! Plain `http://` to the reference node, reached on loopback or through an SSH tunnel, as the
//! collector and the export reach theirs: HTTP/1.1, a fresh connection per request, no redirects
//! (anything but 200 is an error). Every request, connect to last body byte, runs within the
//! client's timeout. JSON bodies are capped at [`MAX_JSON_BYTES`], a block's SSZ at
//! `MAX_PAYLOAD_SIZE` unless set lower ([`BeaconApi::with_max_block_bytes`]); a declared length
//! over the cap is refused before the body is read. The response's content type must be the one
//! asked for. Errors name the API path template, never the base URL or a value from the
//! response.
//!
//! - `/eth/v1/beacon/states/head/finality_checkpoints` ([`ReferenceApi::finalized_checkpoint`]).
//! - `/eth/v1/beacon/headers/{block_id}`, the root as block id ([`ReferenceApi::header`]).
//! - `/eth/v2/beacon/blocks/{block_id}` as SSZ ([`BlockApi::block`]).
//! - `/eth/v1/events?topics=block` as `text/event-stream` ([`HeadSource::open`]): only the
//!   connect and the response's head run within the timeout, and the stream's lines and events
//!   are capped (`probe::head`).

use super::head::{block_event_root, HeadSource, HeadStream, SseParser, BLOCK_EVENT, EVENTS_PATH};
use super::{ApiError, BlockApi, Checkpoint, Header, ReferenceApi, Root};
use bytes::Bytes;
use consensus_types::caps::ObjectKind;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use http::uri::{Authority, Scheme};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::net::TcpStream;

/// Cap on a JSON response (finality checkpoints, a header): 1 MiB.
pub const MAX_JSON_BYTES: usize = 1 << 20;

const JSON: &str = "application/json";
const SSZ: &str = "application/octet-stream";
const EVENT_STREAM: &str = "text/event-stream";
const FINALITY_PATH: &str = "/eth/v1/beacon/states/head/finality_checkpoints";
const HEADER_PATH: &str = "/eth/v1/beacon/headers/{block_id}";
const BLOCK_PATH: &str = "/eth/v2/beacon/blocks/{block_id}";

/// The reference Beacon API at one `http://` base URL (see the module docs).
#[derive(Debug, Clone)]
pub struct BeaconApi {
    authority: Authority,
    timeout: Duration,
    max_block_bytes: usize,
}

impl BeaconApi {
    /// A client for `url` (`http://host[:port]`, no path, query or user info), every request
    /// within `timeout`.
    ///
    /// # Errors
    ///
    /// [`ApiError`] for any other URL.
    pub fn new(url: &str, timeout: Duration) -> Result<Self, ApiError> {
        let refuse = |why: &str| ApiError(format!("reference API URL: {why}"));
        let uri: Uri = url.parse().map_err(|_| refuse("not a URL"))?;
        if uri.scheme() != Some(&Scheme::HTTP) {
            return Err(refuse("the scheme must be http://"));
        }
        let authority = uri.authority().ok_or_else(|| refuse("no host"))?.clone();
        if authority.as_str().contains('@') {
            return Err(refuse("user info is not taken"));
        }
        let bare = uri.path_and_query().is_none_or(|p| p.as_str() == "/");
        if !bare {
            return Err(refuse("a base path or query is not taken"));
        }
        Ok(Self {
            authority,
            timeout,
            max_block_bytes: ObjectKind::SignedBeaconBlock.transport_limit(),
        })
    }

    /// This client with `max` as the cap on a block's SSZ.
    #[must_use]
    pub fn with_max_block_bytes(self, max: usize) -> Self {
        Self {
            max_block_bytes: max,
            ..self
        }
    }

    /// `GET path` on a fresh connection: a 200 of content type `accept`, its body not read yet,
    /// and the connection's task, which ends when dropped. `fail` names the request in errors.
    async fn send(
        &self,
        path: &str,
        accept: &'static str,
        fail: impl Fn(String) -> ApiError,
    ) -> Result<(Response<Incoming>, AbortOnDrop<hyper::Result<()>>), ApiError> {
        let host = self.authority.host().trim_matches(|c| c == '[' || c == ']');
        let port = self.authority.port_u16().unwrap_or(80);
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| fail(format!("connect: {}", e.kind())))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| fail(format!("handshake: {e}")))?;
        let connection = AbortOnDrop(tokio::spawn(connection));
        let request = Request::get(path)
            .header(HOST, self.authority.as_str())
            .header(ACCEPT, accept)
            .body(Empty::<Bytes>::new())
            .map_err(|e| fail(format!("request: {e}")))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| fail(format!("request: {e}")))?;
        if response.status() != StatusCode::OK {
            return Err(fail(format!("HTTP {}", response.status().as_u16())));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !content_type.to_ascii_lowercase().starts_with(accept) {
            return Err(fail(format!("the content type is not {accept}")));
        }
        Ok((response, connection))
    }

    /// `GET path`: a 200 of content type `accept` with at most `max` body bytes, all within the
    /// timeout. `template` names the request in errors.
    async fn get(
        &self,
        template: &'static str,
        path: &str,
        accept: &'static str,
        max: usize,
    ) -> Result<Bytes, ApiError> {
        let fail = |why: String| ApiError(format!("{template}: {why}"));
        let get = async {
            let (response, connection) = self.send(path, accept, fail).await?;
            let declared = response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
            if declared.is_some_and(|n| n > max as u64) {
                return Err(fail(format!("the body is over {max} bytes")));
            }
            let body = Limited::new(response.into_body(), max)
                .collect()
                .await
                .map_err(|e| {
                    if e.is::<http_body_util::LengthLimitError>() {
                        fail(format!("the body is over {max} bytes"))
                    } else {
                        fail(format!("body: {e}"))
                    }
                })?
                .to_bytes();
            drop(connection);
            Ok(body)
        };
        tokio::time::timeout(self.timeout, get)
            .await
            .map_err(|_| fail(format!("no answer within {:?}", self.timeout)))?
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        template: &'static str,
        path: &str,
    ) -> Result<T, ApiError> {
        let body = self.get(template, path, JSON, MAX_JSON_BYTES).await?;
        serde_json::from_slice(&body).map_err(|e| {
            ApiError(format!(
                "{template}: json: {:?} error at line {} column {}",
                e.classify(),
                e.line(),
                e.column()
            ))
        })
    }
}

/// Aborts the connection task when the request is done or cancelled.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> std::ops::Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

#[derive(Deserialize)]
struct Finality {
    finalized: CheckpointJson,
}

#[derive(Deserialize)]
struct CheckpointJson {
    epoch: String,
    root: String,
}

#[derive(Deserialize)]
struct HeaderData {
    root: String,
    header: SignedHeader,
}

#[derive(Deserialize)]
struct SignedHeader {
    message: HeaderMessage,
}

#[derive(Deserialize)]
struct HeaderMessage {
    slot: String,
}

/// `0x` and 64 hex digits.
pub(super) fn root(template: &'static str, text: &str) -> Result<Root, ApiError> {
    text.strip_prefix("0x")
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| Root::try_from(b).ok())
        .ok_or_else(|| ApiError(format!("{template}: a root is not 0x and 64 hex digits")))
}

/// A decimal `u64` without sign or other characters, as the API writes integers.
pub(super) fn decimal(template: &'static str, text: &str) -> Result<u64, ApiError> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    digits
        .then(|| text.parse().ok())
        .flatten()
        .ok_or_else(|| ApiError(format!("{template}: an integer is not a decimal u64")))
}

fn block_id(root: Root) -> String {
    format!("0x{}", hex::encode(root))
}

impl ReferenceApi for BeaconApi {
    async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
        let d: Data<Finality> = self.get_json(FINALITY_PATH, FINALITY_PATH).await?;
        Ok(Checkpoint {
            epoch: decimal(FINALITY_PATH, &d.data.finalized.epoch)?,
            root: root(FINALITY_PATH, &d.data.finalized.root)?,
        })
    }

    async fn header(&self, block: Root) -> Result<Header, ApiError> {
        let path = format!("/eth/v1/beacon/headers/{}", block_id(block));
        let d: Data<HeaderData> = self.get_json(HEADER_PATH, &path).await?;
        Ok(Header {
            root: root(HEADER_PATH, &d.data.root)?,
            slot: decimal(HEADER_PATH, &d.data.header.message.slot)?,
        })
    }
}

/// The reference's `block` events, one stream ([`HeadSource`] of [`BeaconApi`]).
pub struct BlockEvents {
    body: Incoming,
    parser: SseParser,
    /// Roots of a chunk's events not handed over yet.
    ready: VecDeque<Root>,
    /// The fault that ends the stream, given once `ready` is empty.
    failed: Option<ApiError>,
    _connection: AbortOnDrop<hyper::Result<()>>,
}

fn events_error(why: impl std::fmt::Display) -> ApiError {
    ApiError(format!("{EVENTS_PATH}: {why}"))
}

impl HeadSource for BeaconApi {
    type Stream = BlockEvents;

    /// `GET /eth/v1/events?topics=block`: connect and the response's head within the timeout;
    /// the stream itself has no deadline here (see [`super::HeadFollow::idle_timeout`]).
    async fn open(&self) -> Result<BlockEvents, ApiError> {
        let path = format!("{EVENTS_PATH}?topics={BLOCK_EVENT}");
        let send = self.send(&path, EVENT_STREAM, events_error);
        let (response, connection) = tokio::time::timeout(self.timeout, send)
            .await
            .map_err(|_| events_error(format!("no answer within {:?}", self.timeout)))??;
        Ok(BlockEvents {
            body: response.into_body(),
            parser: SseParser::default(),
            ready: VecDeque::new(),
            failed: None,
            _connection: connection,
        })
    }
}

impl HeadStream for BlockEvents {
    /// The next `block` event's root, or `None` after a chunk with none. A chunk's events are
    /// bounded by the parser's caps on a line and an event; its roots wait in `ready`, and a
    /// fault in the chunk is given after the roots before it.
    async fn next_root(&mut self) -> Result<Option<Root>, ApiError> {
        if let Some(root) = self.ready.pop_front() {
            return Ok(Some(root));
        }
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let frame = match self.body.frame().await {
            None => return Err(events_error("the stream ended")),
            Some(Err(e)) => return Err(events_error(format!("body: {e}"))),
            Some(Ok(frame)) => frame,
        };
        // Trailers carry no events.
        let Ok(chunk) = frame.into_data() else {
            return Ok(None);
        };
        let mut events = Vec::new();
        let fed = self.parser.feed_into(&chunk, &mut events);
        for event in events.iter().filter(|event| event.name == BLOCK_EVENT) {
            match block_event_root(&event.data) {
                Ok(root) => self.ready.push_back(root),
                Err(e) => {
                    self.failed = Some(e);
                    break;
                }
            }
        }
        if let (None, Err(e)) = (&self.failed, fed) {
            self.failed = Some(events_error(e));
        }
        match (self.ready.pop_front(), &self.failed) {
            (Some(root), _) => Ok(Some(root)),
            (None, Some(e)) => Err(e.clone()),
            (None, None) => Ok(None),
        }
    }
}

impl BlockApi for BeaconApi {
    async fn block(&self, block: Root) -> Result<Vec<u8>, ApiError> {
        let path = format!("/eth/v2/beacon/blocks/{}", block_id(block));
        let body = self
            .get(BLOCK_PATH, &path, SSZ, self.max_block_bytes)
            .await?;
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::super::head::{HeadSource, HeadStream, MAX_EVENT_BYTES};
    use super::*;
    use testkit::collector::testing::{FixtureServer, HangUp, Reply};

    const ROOT: Root = [0xab; 32];

    fn header_json(root: &str, slot: &str) -> String {
        format!(
            r#"{{"execution_optimistic":false,"finalized":true,"data":{{"root":"{root}","canonical":true,"header":{{"message":{{"slot":"{slot}","proposer_index":"1","parent_root":"0x{z}","state_root":"0x{z}","body_root":"0x{z}"}},"signature":"0x{s}"}}}}}}"#,
            z = "00".repeat(32),
            s = "00".repeat(96),
        )
    }

    fn api(server: &FixtureServer) -> BeaconApi {
        BeaconApi::new(&format!("http://{}", server.addr), Duration::from_secs(5)).unwrap()
    }

    #[tokio::test]
    async fn header_reads_root_and_slot() {
        let hex = format!("0x{}", "ab".repeat(32));
        let body = header_json(&hex, "12345");
        let server = FixtureServer::start(move |_, _| Reply::json(&body)).await;
        let header = api(&server).header(ROOT).await.unwrap();
        assert_eq!(
            header,
            Header {
                root: ROOT,
                slot: 12345
            }
        );
        let (path, headers) = server.seen().remove(0);
        assert_eq!(path, format!("/eth/v1/beacon/headers/{hex}"));
        assert_eq!(headers["accept"], "application/json");
    }

    #[tokio::test]
    async fn finalized_checkpoint_reads_epoch_and_root() {
        let body = format!(
            r#"{{"data":{{"previous_justified":{{"epoch":"1","root":"0x{z}"}},"current_justified":{{"epoch":"2","root":"0x{z}"}},"finalized":{{"epoch":"7","root":"0x{r}"}}}}}}"#,
            z = "00".repeat(32),
            r = "ab".repeat(32)
        );
        let server = FixtureServer::start(move |_, _| Reply::json(&body)).await;
        let checkpoint = api(&server).finalized_checkpoint().await.unwrap();
        assert_eq!(
            checkpoint,
            Checkpoint {
                epoch: 7,
                root: ROOT
            }
        );
        assert_eq!(
            server.seen()[0].0,
            "/eth/v1/beacon/states/head/finality_checkpoints"
        );
    }

    #[tokio::test]
    async fn block_is_ssz_by_root() {
        let server = FixtureServer::start(|_, _| Reply::ssz(vec![1, 2, 3])).await;
        assert_eq!(api(&server).block(ROOT).await.unwrap(), vec![1, 2, 3]);
        let (path, headers) = server.seen().remove(0);
        assert_eq!(path, format!("/eth/v2/beacon/blocks/0x{}", "ab".repeat(32)));
        assert_eq!(headers["accept"], "application/octet-stream");
    }

    #[tokio::test]
    async fn a_404_is_an_error_naming_the_path_not_the_host() {
        let server = FixtureServer::start(|_, _| Reply::status(404)).await;
        let err = api(&server).header(ROOT).await.unwrap_err();
        assert!(err.0.contains("404"), "{err}");
        assert!(err.0.contains("/eth/v1/beacon/headers/{block_id}"), "{err}");
        assert!(!err.0.contains("127.0.0.1"), "{err}");
    }

    #[tokio::test]
    async fn bad_bodies_are_errors() {
        let cases: Vec<(&str, Reply)> = vec![
            ("not json", Reply::json("{")),
            ("short root", Reply::json(&header_json("0xab", "1"))),
            ("no 0x", Reply::json(&header_json(&"ab".repeat(32), "1"))),
            (
                "signed slot",
                Reply::json(&header_json(&format!("0x{}", "ab".repeat(32)), "-1")),
            ),
            (
                "wrong type",
                Reply::json(&header_json(&format!("0x{}", "ab".repeat(32)), "1"))
                    .content_type("text/plain"),
            ),
        ];
        for (what, reply) in cases {
            let server = FixtureServer::start(move |_, _| reply.clone()).await;
            assert!(api(&server).header(ROOT).await.is_err(), "{what}");
        }
        // An SSZ body where a JSON one was asked for, and the other way round.
        let server = FixtureServer::start(|_, _| Reply::json("{}")).await;
        assert!(api(&server).block(ROOT).await.is_err());
    }

    #[tokio::test]
    async fn a_block_over_the_cap_is_refused() {
        let server = FixtureServer::start(|_, _| Reply::ssz(vec![0; 1025])).await;
        let err = api(&server)
            .with_max_block_bytes(1024)
            .block(ROOT)
            .await
            .unwrap_err();
        assert!(err.0.contains("1024"), "{err}");
        let server = FixtureServer::start(|_, _| Reply::ssz(vec![0; 1024])).await;
        let small = api(&server).with_max_block_bytes(1024);
        assert_eq!(small.block(ROOT).await.unwrap().len(), 1024);
    }

    #[tokio::test]
    async fn a_silent_or_gone_reference_is_an_error_within_the_timeout() {
        // Headers sent, then the body never ends.
        let silent = Reply::stream(vec!["{"], true).content_type("application/json");
        let server = FixtureServer::start(move |_, _| silent.clone()).await;
        let timeout = Duration::from_millis(300);
        let api = BeaconApi::new(&format!("http://{}", server.addr), timeout).unwrap();
        let start = std::time::Instant::now();
        let err = api.header(ROOT).await.unwrap_err();
        assert!(start.elapsed() < timeout + Duration::from_millis(250));
        assert!(err.0.contains("within"), "{err}");
        let gone = HangUp::start().await;
        let api = BeaconApi::new(&format!("http://{}", gone.addr), timeout).unwrap();
        assert!(api.block(ROOT).await.is_err());
    }

    fn block_event(root: &str, slot: &str) -> String {
        format!(
            "event: block\ndata: {{\"slot\":\"{slot}\",\"block\":\"{root}\",\"execution_optimistic\":false}}\n\n"
        )
    }

    #[tokio::test]
    async fn block_events_announce_each_root() {
        let first = format!("0x{}", "ab".repeat(32));
        let second = format!("0x{}", "cd".repeat(32));
        let chunks = [
            ": keep-alive\n\n".to_owned(),
            block_event(&first, "10"),
            // Another event name is skipped; an event split over two chunks is whole.
            "event: head\ndata: {}\n\n".to_owned(),
            block_event(&second, "11")[..20].to_owned(),
            block_event(&second, "11")[20..].to_owned(),
        ];
        let server = FixtureServer::start_with_query(move |_, _| {
            Reply::stream(chunks.iter().map(String::as_str).collect(), false)
        })
        .await;
        let mut events = api(&server).open().await.unwrap();
        // The keep-alive alone: bytes, no root.
        assert_eq!(events.next_root().await, Ok(None));
        assert_eq!(events.next_root().await, Ok(Some(ROOT)));
        assert_eq!(next_root(&mut events).await, Ok([0xcd; 32]));
        let end = next_root(&mut events).await.unwrap_err();
        assert!(end.0.contains("ended"), "{end}");
        let (path, headers) = server.seen().remove(0);
        assert_eq!(path, "/eth/v1/events?topics=block");
        assert_eq!(headers["accept"], "text/event-stream");
    }

    #[tokio::test]
    async fn a_bad_event_ends_the_stream_and_quotes_nothing() {
        let host = |server: &FixtureServer| server.addr.to_string();
        let long_line = format!("data: {}\n", "x".repeat(MAX_EVENT_BYTES + 1));
        let long_event = format!("data: {}\n", "y".repeat(MAX_EVENT_BYTES / 2)).repeat(2);
        let cases = [
            (
                "malformed json",
                "event: block\ndata: {\"slot\":\n\n".to_owned(),
                "json",
            ),
            ("wrong-length root", block_event("0xabcdef", "10"), "64 hex"),
            ("oversize line", long_line, "line"),
            ("oversize event", long_event, "event is over"),
        ];
        for (what, body, says) in cases {
            let server = FixtureServer::start_with_query(move |_, _| {
                Reply::stream(vec![body.as_str()], true)
            })
            .await;
            let mut events = api(&server).open().await.unwrap();
            let err = next_root(&mut events).await.unwrap_err();
            assert!(err.0.contains(says), "{what}: {err}");
            assert!(err.0.starts_with("/eth/v1/events"), "{what}: {err}");
            assert!(!err.0.contains(&host(&server)), "{what}: {err}");
            assert!(!err.0.contains("abcdef"), "{what}: {err}");
        }
    }

    #[tokio::test]
    async fn an_events_stream_that_is_not_one_is_refused() {
        let server = FixtureServer::start(|_, _| Reply::status(503)).await;
        let err = api(&server).open().await.err().unwrap();
        assert!(err.0.contains("503"), "{err}");
        assert!(!err.0.contains("127.0.0.1"), "{err}");
        let server = FixtureServer::start(|_, _| Reply::json("{}")).await;
        let err = api(&server).open().await.err().unwrap();
        assert!(err.0.contains("text/event-stream"), "{err}");
        let gone = HangUp::start().await;
        let api = BeaconApi::new(&format!("http://{}", gone.addr), Duration::from_secs(1));
        assert!(api.unwrap().open().await.is_err());
    }

    #[tokio::test]
    async fn an_events_stream_outlives_the_request_timeout() {
        // Events paced past the request timeout: only opening the stream is timed.
        let event = block_event(&format!("0x{}", "ab".repeat(32)), "10");
        let server = FixtureServer::start_with_query(move |_, _| {
            Reply::stream(vec![event.as_str(), event.as_str()], true)
                .paced(Duration::from_millis(150))
        })
        .await;
        let api = BeaconApi::new(
            &format!("http://{}", server.addr),
            Duration::from_millis(100),
        );
        let mut events = api.unwrap().open().await.unwrap();
        assert_eq!(next_root(&mut events).await, Ok(ROOT));
        assert_eq!(next_root(&mut events).await, Ok(ROOT));
    }

    /// The next root of `events`, past the chunks with none.
    async fn next_root(events: &mut BlockEvents) -> Result<Root, ApiError> {
        loop {
            if let Some(root) = events.next_root().await? {
                return Ok(root);
            }
        }
    }

    #[tokio::test]
    async fn the_roots_before_a_bad_event_in_a_chunk_are_announced_first() {
        let good = block_event(&format!("0x{}", "ab".repeat(32)), "10");
        let long_line = format!("data: {}\n", "x".repeat(MAX_EVENT_BYTES + 1));
        let bad_json = "event: block\ndata: {\"slot\":\n\n".to_owned();
        for (what, bad, says) in [("json", bad_json, "json"), ("line", long_line, "line")] {
            let chunk = format!("{good}{good}{bad}");
            let server = FixtureServer::start_with_query(move |_, _| {
                Reply::stream(vec![chunk.as_str()], true)
            })
            .await;
            let mut events = api(&server).open().await.unwrap();
            assert_eq!(events.next_root().await, Ok(Some(ROOT)), "{what}");
            assert_eq!(events.next_root().await, Ok(Some(ROOT)), "{what}");
            let err = events.next_root().await.unwrap_err();
            assert!(err.0.contains(says), "{what}: {err}");
        }
    }

    #[test]
    fn only_a_plain_http_base_is_taken() {
        let timeout = Duration::from_secs(1);
        for bad in [
            "https://127.0.0.1:5052",
            "127.0.0.1:5052",
            "http://127.0.0.1:5052/eth",
            "http://127.0.0.1:5052/?x=1",
            "http://user@127.0.0.1:5052",
            "",
        ] {
            assert!(BeaconApi::new(bad, timeout).is_err(), "{bad}");
        }
        for good in [
            "http://127.0.0.1:5052",
            "http://localhost:5052/",
            "http://[::1]:80",
        ] {
            assert!(BeaconApi::new(good, timeout).is_ok(), "{good}");
        }
    }
}
