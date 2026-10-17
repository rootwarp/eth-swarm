//! The reference node's beacon API: a hyper 1 client for localhost or an SSH tunnel.
//!
//! Plain `http://` to a loopback host only: the API is reached on the host itself or through an
//! SSH tunnel, and the session has no TLS stack. The config enforces it, with no credentials,
//! query or fragment ([`ReferenceApiUrl`] exists only once that passed), so the client takes
//! the URL as it is. The base path may still carry a key, so no error or log line here shows
//! it (errors name the API path only).
//!
//! One connection per request, HTTP/1.1, no redirects (anything but 200 is an error), JSON
//! bodies buffered under [`MAX_JSON_BYTES`], one deadline per request. Integers are decimal
//! strings and roots `0x` + 64 hex digits, as the beacon API specifies; anything else is
//! refused.

use bytes::Bytes;
use cl_p2p::m2a_session::config::ReferenceApiUrl;
use consensus_types::primitives::{Epoch, Root, Slot};
use http::header::{ACCEPT, HOST, USER_AGENT};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

/// Cap on a JSON response: 1 MiB.
pub const MAX_JSON_BYTES: usize = 1 << 20;
/// Deadline of one request: connect, response and body [est].
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a request failed. Never shows the base URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// Connect or HTTP failure.
    #[error("{path}: {reason}")]
    Transport {
        /// The API path.
        path: String,
        /// Why.
        reason: String,
    },
    /// A status other than 200.
    #[error("{path}: HTTP {status}")]
    Status {
        /// The API path.
        path: String,
        /// The status code.
        status: u16,
    },
    /// The deadline passed.
    #[error("{path}: no answer within {REQUEST_TIMEOUT:?}")]
    Timeout {
        /// The API path.
        path: String,
    },
    /// The body is over [`MAX_JSON_BYTES`] or not the expected JSON.
    #[error("{path}: bad response: {reason}")]
    BadResponse {
        /// The API path.
        path: String,
        /// Why.
        reason: String,
    },
}

/// A checkpoint (`finalized` of `finality_checkpoints`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Checkpoint {
    /// The epoch.
    #[serde(deserialize_with = "quoted_u64")]
    pub epoch: Epoch,
    /// The block root.
    #[serde(deserialize_with = "root")]
    pub root: Root,
}

/// A block header as the API reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The block root.
    pub root: Root,
    /// The block's slot.
    pub slot: Slot,
    /// Whether the block is on the node's canonical chain.
    pub canonical: bool,
}

/// `/eth/v1/beacon/genesis`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct GenesisInfo {
    /// Unix seconds.
    #[serde(deserialize_with = "quoted_u64")]
    pub genesis_time: u64,
    /// The genesis validators root.
    #[serde(deserialize_with = "root")]
    pub genesis_validators_root: Root,
    /// `GENESIS_FORK_VERSION`.
    #[serde(deserialize_with = "version")]
    pub genesis_fork_version: [u8; 4],
}

#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

#[derive(Deserialize)]
struct FinalityData {
    finalized: Checkpoint,
}

#[derive(Deserialize)]
struct HeaderData {
    #[serde(deserialize_with = "root")]
    root: Root,
    canonical: bool,
    header: SignedHeader,
}

#[derive(Deserialize)]
struct SignedHeader {
    message: HeaderMessage,
}

#[derive(Deserialize)]
struct HeaderMessage {
    #[serde(deserialize_with = "quoted_u64")]
    slot: Slot,
}

#[derive(Deserialize)]
struct IdentityData {
    enr: String,
}

fn quoted_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let s = String::deserialize(d)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(serde::de::Error::custom(format!(
            "{s:?} is not a decimal u64"
        )));
    }
    s.parse().map_err(serde::de::Error::custom)
}

/// `0x` and exactly `2 * N` hex digits.
pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let digits = s.strip_prefix("0x")?;
    if digits.len() != 2 * N || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn root<'de, D: Deserializer<'de>>(d: D) -> Result<Root, D::Error> {
    let s = String::deserialize(d)?;
    parse_hex::<32>(&s)
        .map(Root::from)
        .ok_or_else(|| serde::de::Error::custom(format!("{s:?} is not a 0x root")))
}

fn version<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 4], D::Error> {
    let s = String::deserialize(d)?;
    parse_hex::<4>(&s).ok_or_else(|| serde::de::Error::custom(format!("{s:?} is not a version")))
}

/// The addresses of a loopback `host` as the config accepts it, without a lookup: `localhost`
/// is `127.0.0.1` then `::1` (the system resolver could map it anywhere), an IP literal is
/// itself. Anything else (which the config refuses) has none, and every request fails.
fn loopback_addrs(host: &str) -> Vec<IpAddr> {
    if host.eq_ignore_ascii_case("localhost") {
        return vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
    }
    let literal = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    let ip = match literal {
        Some(v6) => v6.parse::<Ipv6Addr>().map(IpAddr::from).ok(),
        None => host.parse::<Ipv4Addr>().map(IpAddr::from).ok(),
    };
    ip.filter(IpAddr::is_loopback).into_iter().collect()
}

/// The client.
#[derive(Clone)]
pub struct ReferenceApi {
    /// The literal loopback addresses to connect to, in order. Names are never resolved.
    addrs: Vec<SocketAddr>,
    /// `Host:` header value.
    authority: String,
    /// The base path without a trailing `/`. May hold a key: never shown.
    base: String,
    timeout: Duration,
}

impl std::fmt::Debug for ReferenceApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReferenceApi")
            .field("addrs", &self.addrs)
            .finish_non_exhaustive()
    }
}

impl ReferenceApi {
    /// A client for `url` (plain HTTP to a loopback host, as the config checked).
    pub fn new(url: &ReferenceApiUrl, timeout: Duration) -> Self {
        let uri = url.uri();
        let host = uri.host().unwrap_or_default();
        let port = url.port();
        Self {
            addrs: loopback_addrs(host)
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
            authority: uri
                .authority()
                .map_or_else(|| host.to_owned(), |a| a.as_str().to_owned()),
            base: uri.path().trim_end_matches('/').to_owned(),
            timeout,
        }
    }

    /// `GET /eth/v1/beacon/genesis`.
    pub async fn genesis(&self) -> Result<GenesisInfo, ApiError> {
        let d: Data<GenesisInfo> = self.get_json("/eth/v1/beacon/genesis").await?;
        Ok(d.data)
    }

    /// `GET /eth/v1/node/identity`: the node's ENR, as text.
    pub async fn identity_enr(&self) -> Result<String, ApiError> {
        let d: Data<IdentityData> = self.get_json("/eth/v1/node/identity").await?;
        Ok(d.data.enr)
    }

    /// `GET /eth/v1/beacon/states/head/finality_checkpoints`: the finalized checkpoint.
    pub async fn finality_checkpoints(&self) -> Result<Checkpoint, ApiError> {
        let d: Data<FinalityData> = self
            .get_json("/eth/v1/beacon/states/head/finality_checkpoints")
            .await?;
        Ok(d.data.finalized)
    }

    /// `GET /eth/v1/beacon/headers/head`.
    pub async fn head_header(&self) -> Result<Header, ApiError> {
        self.header_at("/eth/v1/beacon/headers/head".to_owned())
            .await
    }

    /// `GET /eth/v1/beacon/headers/{root}`; the reported root must be `root`.
    pub async fn header(&self, root: Root) -> Result<Header, ApiError> {
        let path = format!("/eth/v1/beacon/headers/{root}");
        let header = self.header_at(path.clone()).await?;
        if header.root != root {
            return Err(ApiError::BadResponse {
                path,
                reason: format!("asked for {root}, got {}", header.root),
            });
        }
        Ok(header)
    }

    async fn header_at(&self, path: String) -> Result<Header, ApiError> {
        let d: Data<HeaderData> = self.get_json(&path).await?;
        Ok(Header {
            root: d.data.root,
            slot: d.data.header.message.slot,
            canonical: d.data.canonical,
        })
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        match tokio::time::timeout(self.timeout, self.fetch(path)).await {
            Ok(Ok(bytes)) => serde_json::from_slice(&bytes).map_err(|e| ApiError::BadResponse {
                path: path.to_owned(),
                reason: format!("json: {e}"),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ApiError::Timeout {
                path: path.to_owned(),
            }),
        }
    }

    async fn fetch(&self, path: &str) -> Result<Bytes, ApiError> {
        let transport = |reason: String| ApiError::Transport {
            path: path.to_owned(),
            reason,
        };
        let request = Request::get(format!("{}{path}", self.base))
            .header(HOST, &self.authority)
            .header(ACCEPT, "application/json")
            .header(
                USER_AGENT,
                concat!("ethswarm-m2a-session/", env!("CARGO_PKG_VERSION")),
            )
            .body(Empty::<Bytes>::new())
            .map_err(|e| transport(format!("request: {e}")))?;
        let tcp = TcpStream::connect(&self.addrs[..])
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
                path: path.to_owned(),
                status: response.status().as_u16(),
            });
        }
        match Limited::new(response.into_body(), MAX_JSON_BYTES)
            .collect()
            .await
        {
            Ok(body) => Ok(body.to_bytes()),
            Err(e) if e.is::<http_body_util::LengthLimitError>() => Err(ApiError::BadResponse {
                path: path.to_owned(),
                reason: format!("body over {MAX_JSON_BYTES} bytes"),
            }),
            Err(e) => Err(transport(format!("body: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_api::{MockApi, Route};
    use cl_p2p::m2a_session::config::M2aConfig;

    fn url(text: &str) -> ReferenceApiUrl {
        let config = format!(
            "network = \"sepolia\"\npeer = \"/ip4/127.0.0.1/tcp/9000/p2p/{}\"\n\
             reference_api_url = \"{text}\"\n",
            libp2p::PeerId::random()
        );
        M2aConfig::from_toml(&config)
            .unwrap()
            .reference_api_url
            .unwrap()
    }

    fn client(api: &MockApi) -> ReferenceApi {
        ReferenceApi::new(&url(&api.url()), Duration::from_secs(2))
    }

    const R1: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    #[tokio::test]
    async fn reads_the_four_endpoints() {
        let api = MockApi::start(vec![
            (
                "/eth/v1/beacon/states/head/finality_checkpoints",
                Route::json(format!(
                    r#"{{"execution_optimistic":false,"finalized":true,"data":{{
                    "previous_justified":{{"epoch":"1","root":"{R1}"}},
                    "current_justified":{{"epoch":"2","root":"{R1}"}},
                    "finalized":{{"epoch":"3","root":"{R1}"}}}}}}"#
                )),
            ),
            (
                "/eth/v1/beacon/headers/head",
                Route::json(MockApi::header_json(Root::repeat_byte(2), 99, true)),
            ),
            (
                "/eth/v1/beacon/genesis",
                Route::json(MockApi::genesis_json(
                    5,
                    Root::repeat_byte(3),
                    [0x90, 0, 0, 0x69],
                )),
            ),
            (
                "/eth/v1/node/identity",
                Route::json(r#"{"data":{"peer_id":"16U","enr":"enr:abc","p2p_addresses":[]}}"#),
            ),
        ])
        .await;
        let c = client(&api);
        let f = c.finality_checkpoints().await.unwrap();
        assert_eq!((f.epoch, f.root), (3, Root::repeat_byte(0x11)));
        let h = c.head_header().await.unwrap();
        assert_eq!(
            h,
            Header {
                root: Root::repeat_byte(2),
                slot: 99,
                canonical: true
            }
        );
        let g = c.genesis().await.unwrap();
        assert_eq!(g.genesis_time, 5);
        assert_eq!(g.genesis_validators_root, Root::repeat_byte(3));
        assert_eq!(g.genesis_fork_version, [0x90, 0, 0, 0x69]);
        assert_eq!(c.identity_enr().await.unwrap(), "enr:abc");
        let seen = api.seen();
        assert_eq!(seen[0].1["accept"], "application/json");
        assert_eq!(seen[0].1["host"], api.addr.to_string());
    }

    #[tokio::test]
    async fn header_by_root_must_name_that_root() {
        let r = Root::repeat_byte(4);
        let api = MockApi::start(vec![
            (
                &format!("/eth/v1/beacon/headers/{r}"),
                Route::json(MockApi::header_json(r, 7, false)),
            ),
            (
                &format!("/eth/v1/beacon/headers/{}", Root::repeat_byte(5)),
                Route::json(MockApi::header_json(r, 7, true)),
            ),
        ])
        .await;
        let c = client(&api);
        assert_eq!(c.header(r).await.unwrap().slot, 7);
        assert!(!c.header(r).await.unwrap().canonical);
        let err = c.header(Root::repeat_byte(5)).await.unwrap_err();
        assert!(matches!(err, ApiError::BadResponse { .. }), "{err}");
        let err = c.header(Root::repeat_byte(6)).await.unwrap_err();
        assert!(matches!(err, ApiError::Status { status: 404, .. }), "{err}");
    }

    #[tokio::test]
    async fn refuses_malformed_json_and_huge_bodies() {
        let bad_values = [
            r#"{"data":{"finalized":{"epoch":3,"root":"0x11"}}}"#.to_owned(),
            format!(r#"{{"data":{{"finalized":{{"epoch":"-3","root":"{R1}"}}}}}}"#),
            format!(r#"{{"data":{{"finalized":{{"epoch":"","root":"{R1}"}}}}}}"#),
            format!(
                r#"{{"data":{{"finalized":{{"epoch":"3","root":"{}"}}}}}}"#,
                &R1[2..]
            ),
            r#"{"data":{"finalized":{"epoch":"3","root":"0xgg"}}}"#.to_owned(),
            "not json".to_owned(),
        ];
        for body in bad_values {
            let api = MockApi::start(vec![(
                "/eth/v1/beacon/states/head/finality_checkpoints",
                Route::json(body.clone()),
            )])
            .await;
            let err = client(&api).finality_checkpoints().await.unwrap_err();
            assert!(matches!(err, ApiError::BadResponse { .. }), "{body}: {err}");
        }
        let api = MockApi::start(vec![(
            "/eth/v1/beacon/genesis",
            Route::json("x".repeat(MAX_JSON_BYTES + 1)),
        )])
        .await;
        let err = client(&api).genesis().await.unwrap_err();
        assert!(err.to_string().contains("body over"), "{err}");
        let api = MockApi::start(vec![(
            "/eth/v1/beacon/genesis",
            Route::json(r#"{"data":{"genesis_time":"1","genesis_validators_root":"0x00","genesis_fork_version":"0x01"}}"#),
        )])
        .await;
        assert!(client(&api).genesis().await.is_err());
    }

    #[tokio::test]
    async fn base_path_is_prefixed_and_never_shown() {
        let api = MockApi::start(vec![(
            "/secret-key/eth/v1/beacon/headers/head",
            Route::json(MockApi::header_json(Root::repeat_byte(2), 1, true)),
        )])
        .await;
        let c = ReferenceApi::new(&url(&format!("{}/secret-key/", api.url())), REQUEST_TIMEOUT);
        assert_eq!(c.head_header().await.unwrap().slot, 1);
        let err = c.finality_checkpoints().await.unwrap_err();
        assert!(!err.to_string().contains("secret-key"), "{err}");
        assert!(!format!("{c:?}").contains("secret-key"));
    }

    #[tokio::test]
    async fn failures_are_typed() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let c = ReferenceApi::new(&url(&format!("http://{addr}")), REQUEST_TIMEOUT);
        assert!(matches!(
            c.genesis().await.unwrap_err(),
            ApiError::Transport { .. }
        ));
        // A server that accepts and never answers.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = silent.accept().await {
                held.push(s);
            }
        });
        let c = ReferenceApi::new(&url(&format!("http://{addr}")), Duration::from_millis(200));
        assert!(matches!(
            c.genesis().await.unwrap_err(),
            ApiError::Timeout { .. }
        ));
    }

    fn addrs(text: &str) -> Vec<std::net::SocketAddr> {
        ReferenceApi::new(&url(text), REQUEST_TIMEOUT).addrs
    }

    #[test]
    fn connects_only_to_literal_loopback_addresses() {
        // localhost is never looked up: it is 127.0.0.1, then ::1.
        assert_eq!(
            addrs("http://localhost:5052"),
            [
                "127.0.0.1:5052".parse().unwrap(),
                "[::1]:5052".parse().unwrap()
            ]
        );
        assert_eq!(addrs("http://LocalHost").len(), 2);
        assert_eq!(addrs("http://localhost")[0].port(), 80);
        assert_eq!(
            addrs("http://127.0.0.2:1"),
            ["127.0.0.2:1".parse().unwrap()]
        );
        assert_eq!(addrs("http://[::1]:1"), ["[::1]:1".parse().unwrap()]);
        let c = ReferenceApi::new(&url("http://[::1]:1"), REQUEST_TIMEOUT);
        assert_eq!(
            c.authority, "[::1]:1",
            "the Host header keeps the URL's form"
        );
    }

    #[tokio::test]
    async fn localhost_reaches_127_0_0_1_then_falls_back_to_ipv6() {
        let api = MockApi::start(vec![(
            "/eth/v1/beacon/headers/head",
            Route::json(MockApi::header_json(Root::repeat_byte(2), 3, true)),
        )])
        .await;
        let c = ReferenceApi::new(
            &url(&format!("http://localhost:{}", api.addr.port())),
            REQUEST_TIMEOUT,
        );
        assert_eq!(c.head_header().await.unwrap().slot, 3);
        assert_eq!(
            api.seen()[0].1["host"],
            format!("localhost:{}", api.addr.port())
        );
        // Only ::1 listens: 127.0.0.1 refuses, and the fallback answers.
        let Some(v6) = MockApi::start_on(
            "[::1]:0",
            vec![(
                "/eth/v1/beacon/headers/head",
                Route::json(MockApi::header_json(Root::repeat_byte(2), 4, true)),
            )],
        )
        .await
        else {
            eprintln!("skipping the IPv6 fallback: no ::1 on this host");
            return;
        };
        if std::net::TcpListener::bind(("127.0.0.1", v6.addr.port())).is_err() {
            eprintln!(
                "skipping the IPv6 fallback: 127.0.0.1:{} is taken",
                v6.addr.port()
            );
            return;
        }
        let c = ReferenceApi::new(
            &url(&format!("http://localhost:{}", v6.addr.port())),
            REQUEST_TIMEOUT,
        );
        assert_eq!(c.head_header().await.unwrap().slot, 4);
    }
}
