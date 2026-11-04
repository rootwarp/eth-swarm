//! The Beacon API's HTTP core, at beacon-APIs `01e99a6`.
//!
//! - **Bind.** [`HttpBind`]: `127.0.0.1:5052` by default (ARCH §2b). A non-loopback address is
//!   refused before anything listens, unless the operator flag `http_allow_non_loopback` is set.
//! - **Errors.** [`ApiError`]: the beacon-APIs body `{"code", "message"}` (`types/http.yaml`
//!   `ErrorMessage`; `stacktraces` is never sent). An unknown route answers 404 and a known route
//!   with another method 405 (with `Allow`). A bad parameter answers 400.
//! - **Content negotiation** ([`negotiate`]). Without `Accept`, the answer is JSON. A route that
//!   can produce none of the accepted types answers 406. Part 1 has no SSZ route, so each route
//!   takes [`JsonOnly`].
//! - **`Eth-Consensus-Version`** ([`with_consensus_version`]): set on fork-versioned responses.
//!   No part 1 route is fork-versioned.

use std::borrow::Cow;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use axum::Router;
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use network_config::ForkName;
use tokio::net::TcpListener;

use crate::node_state::NodeState;
use crate::routes::config::ConfigData;

/// `127.0.0.1:5052`: the Beacon API's default address.
pub const DEFAULT_HTTP_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5052));

/// `Eth-Consensus-Version`: the fork of the data in a fork-versioned response.
pub const CONSENSUS_VERSION: HeaderName = HeaderName::from_static("eth-consensus-version");

const JSON: &str = "application/json";
const SSZ: &str = "application/octet-stream";

/// Where the Beacon API listens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpBind {
    pub addr: SocketAddr,
    /// The operator flag. Without it, only a loopback address is accepted.
    pub allow_non_loopback: bool,
}

impl Default for HttpBind {
    fn default() -> Self {
        Self {
            addr: DEFAULT_HTTP_ADDR,
            allow_non_loopback: false,
        }
    }
}

/// Why the Beacon API does not listen.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("{0} is not a loopback address; set http_allow_non_loopback to listen on it")]
    NotLoopback(SocketAddr),
    #[error("cannot listen on {addr}: {source}")]
    Io {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

impl HttpBind {
    /// The address to listen on, if the policy allows it. An IPv4-mapped IPv6 address
    /// (`::ffff:127.0.0.1`) is not loopback here.
    ///
    /// # Errors
    ///
    /// [`BindError::NotLoopback`] for a non-loopback address without the operator flag.
    pub fn check(&self) -> Result<SocketAddr, BindError> {
        if self.addr.ip().is_loopback() || self.allow_non_loopback {
            Ok(self.addr)
        } else {
            Err(BindError::NotLoopback(self.addr))
        }
    }

    /// Listens on [`Self::check`]'s address. A refused address opens no socket.
    ///
    /// # Errors
    ///
    /// The address is refused, or the bind fails.
    pub async fn bind(&self) -> Result<TcpListener, BindError> {
        let addr = self.check()?;
        TcpListener::bind(addr)
            .await
            .map_err(|source| BindError::Io { addr, source })
    }
}

/// A beacon-APIs error response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: Cow<'static, str>,
}

impl ApiError {
    #[must_use]
    pub fn new(status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// 400: a bad parameter.
    #[must_use]
    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "code": self.status.as_u16(), "message": self.message });
        json_response(self.status, &body)
    }
}

/// A JSON response with `body`.
#[must_use]
pub fn json_response(status: StatusCode, body: &serde_json::Value) -> Response {
    json_bytes(status, Bytes::from(body.to_string()))
}

/// A JSON response with a body that is already encoded.
#[must_use]
pub fn json_bytes(status: StatusCode, body: Bytes) -> Response {
    (
        status,
        [(CONTENT_TYPE, HeaderValue::from_static(JSON))],
        body,
    )
        .into_response()
}

/// A response encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// `application/json`.
    Json,
    /// `application/octet-stream`.
    Ssz,
}

/// The encoding to answer with, for the request's `Accept` headers and whether the route can
/// produce SSZ. Each type gets the q of the most specific range that matches it (RFC 9110
/// §12.5.1). The higher q wins, then the type the client named over a wildcard, then JSON. A
/// range that does not parse is ignored, and no usable range at all means JSON.
///
/// # Errors
///
/// 406 when the route can produce none of the accepted types.
pub fn negotiate(headers: &HeaderMap, ssz: bool) -> Result<Encoding, ApiError> {
    let ranges: Vec<(String, u16)> = headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(media_range)
        .collect();
    if ranges.is_empty() {
        return Ok(Encoding::Json);
    }
    let json = preference(&ranges, JSON);
    let ssz = if ssz {
        preference(&ranges, SSZ)
    } else {
        (0, 0)
    };
    match (json, ssz) {
        (json, ssz) if ssz.0 > 0 && ssz > json => Ok(Encoding::Ssz),
        ((q, _), _) if q > 0 => Ok(Encoding::Json),
        _ => Err(ApiError::new(
            StatusCode::NOT_ACCEPTABLE,
            "Accepted media type not supported",
        )),
    }
}

/// One `type/subtype; q=...` range: the lowercase type and q in thousandths.
fn media_range(range: &str) -> Option<(String, u16)> {
    let mut parts = range.split(';');
    let media = parts.next()?.trim().to_ascii_lowercase();
    if !media.contains('/') {
        return None;
    }
    let mut q = 1000;
    for param in parts {
        if let Some((name, value)) = param.split_once('=') {
            if name.trim().eq_ignore_ascii_case("q") {
                let value: f32 = value.trim().parse().ok()?;
                if !(0.0..=1.0).contains(&value) {
                    return None;
                }
                q = (value * 1000.0).round() as u16;
            }
        }
    }
    Some((media, q))
}

/// `(q, specificity)` of `media` under `ranges`: specificity 2 for the exact type, 1 for
/// `type/*`, 0 for `*/*`; `(0, 0)` when nothing matches.
fn preference(ranges: &[(String, u16)], media: &str) -> (u16, u8) {
    let wildcard = format!("{}/*", media.split('/').next().unwrap_or_default());
    let specificity = |range: &str| match range {
        r if r == media => Some(2),
        r if r == wildcard => Some(1),
        "*/*" => Some(0),
        _ => None,
    };
    ranges
        .iter()
        .filter_map(|(range, q)| specificity(range).map(|s| (s, *q)))
        .max()
        .map_or((0, 0), |(s, q)| (q, s))
}

/// The extractor of a JSON-only route: it rejects a request that does not accept JSON with 406.
#[derive(Clone, Copy, Debug)]
pub struct JsonOnly;

impl<S: Send + Sync> FromRequestParts<S> for JsonOnly {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        negotiate(&parts.headers, false).map(|_| Self)
    }
}

/// `response` with `Eth-Consensus-Version: <fork>`, replacing any earlier value.
#[must_use]
pub fn with_consensus_version(mut response: Response, fork: ForkName) -> Response {
    response
        .headers_mut()
        .insert(CONSENSUS_VERSION, HeaderValue::from_static(fork.as_str()));
    response
}

/// What the handlers read.
#[derive(Clone)]
pub struct ApiState {
    pub node: NodeState,
    pub config: Arc<ConfigData>,
}

/// Every route, with the 404 and 405 fallbacks.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .merge(crate::routes::node::routes())
        .merge(crate::routes::config::routes())
        .fallback(|| async { ApiError::new(StatusCode::NOT_FOUND, "Route not found") })
        // After every route: it applies to the routes added before it.
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")
        })
        .with_state(state)
}

/// Serves `router` on `listener` until `shutdown`, then lets the open requests finish.
///
/// # Errors
///
/// The server stopped on an I/O error.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_state::NodeState;
    use crate::testing::{self, get, json, request};
    use http::header::{ACCEPT, ALLOW, CONTENT_TYPE};
    use http::{HeaderValue, Method, Request};

    fn bind(addr: &str, allow_non_loopback: bool) -> HttpBind {
        HttpBind {
            addr: addr.parse().unwrap(),
            allow_non_loopback,
        }
    }

    fn app() -> Router {
        router(testing::api_state(NodeState::new(testing::clock())))
    }

    /// The error body: JSON `{"code": <status>, "message": <text>}` and nothing else.
    fn assert_error(status: StatusCode, headers: &HeaderMap, body: &[u8], code: u16) {
        assert_eq!(status.as_u16(), code);
        assert_eq!(headers[CONTENT_TYPE], "application/json");
        let body = json(body);
        let object = body.as_object().unwrap();
        assert_eq!(object.len(), 2, "{body}");
        assert_eq!(object["code"], code);
        assert!(!object["message"].as_str().unwrap().is_empty(), "{body}");
    }

    #[tokio::test]
    async fn loopback_only() {
        // The default bind is 127.0.0.1:5052, without the flag.
        let default = HttpBind::default();
        assert_eq!(default.addr, "127.0.0.1:5052".parse().unwrap());
        assert_eq!(default.addr, DEFAULT_HTTP_ADDR);
        assert!(!default.allow_non_loopback);
        assert_eq!(default.check().unwrap(), DEFAULT_HTTP_ADDR);
        // Loopback, IPv4 or IPv6, needs no flag.
        for addr in ["127.0.0.1:5052", "127.8.9.10:9000", "[::1]:5052"] {
            assert_eq!(bind(addr, false).check().unwrap(), addr.parse().unwrap());
        }
        // Anything else needs the operator flag. An IPv4-mapped loopback is not loopback.
        for addr in [
            "0.0.0.0:5052",
            "[::]:5052",
            "192.168.1.10:5052",
            "10.0.0.1:5052",
            "[::ffff:127.0.0.1]:5052",
        ] {
            let parsed: SocketAddr = addr.parse().unwrap();
            let err = bind(addr, false).check().unwrap_err();
            assert!(
                matches!(err, BindError::NotLoopback(a) if a == parsed),
                "{err}"
            );
            assert_eq!(bind(addr, true).check().unwrap(), parsed);
        }
        // A refused address opens no socket; a loopback one listens.
        let err = bind("0.0.0.0:0", false).bind().await.unwrap_err();
        assert!(matches!(err, BindError::NotLoopback(_)), "{err}");
        let listener = bind("127.0.0.1:0", false).bind().await.unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn error_shape() {
        let app = app();
        // An unknown route: 404.
        for uri in ["/eth/v1/node/nope", "/", "/eth/v2/node/syncing"] {
            let (status, headers, body) = get(&app, uri).await;
            assert_error(status, &headers, &body, 404);
        }
        // A known route with another method: 405, naming the allowed ones.
        for method in [Method::POST, Method::PUT, Method::DELETE] {
            let req = Request::builder()
                .method(method)
                .uri("/eth/v1/node/syncing")
                .body(axum::body::Body::empty())
                .unwrap();
            let (status, headers, body) = request(&app, req).await;
            assert_error(status, &headers, &body, 405);
            assert!(headers[ALLOW].to_str().unwrap().contains("GET"));
        }
        // A bad parameter: 400.
        let (status, headers, body) = get(&app, "/eth/v1/node/health?syncing_status=x").await;
        assert_error(status, &headers, &body, 400);
        // The type itself.
        let response = ApiError::bad_request("bad slot").into_response();
        let (status, headers) = (response.status(), response.headers().clone());
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        assert_error(status, &headers, &body, 400);
        assert_eq!(json(&body)["message"], "bad slot");
    }

    fn accept(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[tokio::test]
    async fn content_negotiation() {
        let app = app();
        let version = |accept: Option<&'static str>| {
            let mut req = Request::builder().uri("/eth/v1/node/version");
            if let Some(value) = accept {
                req = req.header(ACCEPT, value);
            }
            request(&app, req.body(axum::body::Body::empty()).unwrap())
        };
        // JSON by default, and whenever JSON is acceptable.
        for value in [
            None,
            Some("application/json"),
            Some("application/json; charset=utf-8"),
            Some("*/*"),
            Some("application/*"),
            Some("application/octet-stream;q=1.0,application/json;q=0.9"),
            Some("text/html, application/json;q=0.5"),
        ] {
            let (status, headers, body) = version(value).await;
            assert_eq!(status, StatusCode::OK, "{value:?}");
            assert_eq!(headers[CONTENT_TYPE], "application/json", "{value:?}");
            assert!(json(&body)["data"]["version"].is_string());
            // No part 1 route is fork-versioned.
            assert!(headers.get(CONSENSUS_VERSION).is_none());
        }
        // SSZ only, on a route without SSZ, or nothing this server produces: 406.
        for value in [
            "application/octet-stream",
            "application/octet-stream, application/json;q=0",
            "text/plain",
            "application/json;q=0",
        ] {
            let (status, headers, body) = version(Some(value)).await;
            assert_error(status, &headers, &body, 406);
        }
        // A route that can produce SSZ follows the client's preference: the higher q, then the
        // type the client named over a wildcard; JSON wins a full tie.
        let ssz = |value: &str| negotiate(&accept(value), true);
        assert_eq!(negotiate(&HeaderMap::new(), true), Ok(Encoding::Json));
        assert_eq!(ssz("application/octet-stream"), Ok(Encoding::Ssz));
        assert_eq!(
            ssz("application/octet-stream;q=1.0,application/json;q=0.9"),
            Ok(Encoding::Ssz)
        );
        assert_eq!(
            ssz("application/json,application/octet-stream;q=0.5"),
            Ok(Encoding::Json)
        );
        assert_eq!(ssz("*/*"), Ok(Encoding::Json));
        assert_eq!(ssz("application/octet-stream, */*"), Ok(Encoding::Ssz));
        assert_eq!(
            ssz("application/json, application/octet-stream"),
            Ok(Encoding::Json)
        );
        assert_eq!(
            ssz("text/plain").unwrap_err().status,
            StatusCode::NOT_ACCEPTABLE
        );
        assert_eq!(
            negotiate(&accept("application/octet-stream"), false)
                .unwrap_err()
                .status,
            StatusCode::NOT_ACCEPTABLE
        );
        // The Eth-Consensus-Version helper.
        for fork in ForkName::ALL {
            let response = with_consensus_version(StatusCode::OK.into_response(), fork);
            assert_eq!(response.headers()[CONSENSUS_VERSION], fork.as_str());
            assert_eq!(
                response.headers().get_all(CONSENSUS_VERSION).iter().count(),
                1
            );
        }
        let twice = with_consensus_version(
            with_consensus_version(StatusCode::OK.into_response(), ForkName::Fulu),
            ForkName::Gloas,
        );
        assert_eq!(twice.headers()[CONSENSUS_VERSION], "gloas");
        assert_eq!(twice.headers().get_all(CONSENSUS_VERSION).iter().count(), 1);
    }
}
