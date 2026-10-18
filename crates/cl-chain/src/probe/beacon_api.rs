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

use super::{ApiError, BlockApi, Checkpoint, Header, ReferenceApi, Root};
use bytes::Bytes;
use consensus_types::caps::ObjectKind;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use http::uri::{Authority, Scheme};
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::time::Duration;
use tokio::net::TcpStream;

/// Cap on a JSON response (finality checkpoints, a header): 1 MiB.
pub const MAX_JSON_BYTES: usize = 1 << 20;

const JSON: &str = "application/json";
const SSZ: &str = "application/octet-stream";
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
            let host = self.authority.host().trim_matches(|c| c == '[' || c == ']');
            let port = self.authority.port_u16().unwrap_or(80);
            let stream = TcpStream::connect((host, port))
                .await
                .map_err(|e| fail(format!("connect: {}", e.kind())))?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
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
fn root(template: &'static str, text: &str) -> Result<Root, ApiError> {
    text.strip_prefix("0x")
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| Root::try_from(b).ok())
        .ok_or_else(|| ApiError(format!("{template}: a root is not 0x and 64 hex digits")))
}

/// A decimal `u64` without sign or other characters, as the API writes integers.
fn decimal(template: &'static str, text: &str) -> Result<u64, ApiError> {
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
