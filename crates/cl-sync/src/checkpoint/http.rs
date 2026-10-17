//! Beacon API client: hyper 1 over TCP, TLS through rustls.
//!
//! `https://` providers go through rustls on the `ring` provider (ring is already in the tree
//! through `ethereum_hashing`, and aws-lc would add a C build and a second crypto stack),
//! verified against the Mozilla roots of `webpki-roots` (CDLA-Permissive-2.0, allowed in
//! `deny.toml`), with ALPN `http/1.1`. The platform verifier is not used: it would make the
//! trust anchors depend on the host. `http://` needs the explicit `allow_insecure_http` flag
//! (see [`crate::checkpoint::config`]) and exists for local fixtures.
//!
//! One connection per request, HTTP/1.1, no redirects (a 3xx is an error). JSON bodies are
//! buffered under [`MAX_JSON_BYTES`]. SSZ bodies are streamed into a quarantine file under the
//! caller's cap: a `Content-Length` over the cap is refused before anything is read, and the
//! running count is checked on every chunk, so an endless body is cut at the cap. On any
//! failure the partial file is deleted.

use crate::checkpoint::config::{Provider, Scheme};
use crate::checkpoint::fetch::AnchorError;
use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Body, Incoming};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Cap on a JSON response (finality checkpoints, headers): 1 MiB.
pub const MAX_JSON_BYTES: u64 = 1 << 20;
/// The beacon API's SSZ media type.
pub const OCTET_STREAM: &str = "application/octet-stream";
/// The fork header of the beacon API.
pub const CONSENSUS_VERSION: &str = "eth-consensus-version";

/// A downloaded SSZ body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Download {
    /// Bytes written.
    pub len: u64,
    /// sha256 of those bytes.
    pub sha256: [u8; 32],
    /// The response's `Eth-Consensus-Version`, if it sent one.
    pub consensus_version: Option<String>,
}

/// The beacon API client.
#[derive(Clone)]
pub struct Client {
    tls: TlsConnector,
    request_timeout: Duration,
    body_timeout: Duration,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("request_timeout", &self.request_timeout)
            .field("body_timeout", &self.body_timeout)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client with `request_timeout` for connect, response headers and JSON bodies, and
    /// `body_timeout` for one SSZ body.
    pub fn new(request_timeout: Duration, body_timeout: Duration) -> Result<Self, AnchorError> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| AnchorError::Config(format!("tls: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: TlsConnector::from(Arc::new(tls)),
            request_timeout,
            body_timeout,
        })
    }

    /// GETs `path` as JSON and parses it as `T`.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        provider: &Provider,
        path: &str,
    ) -> Result<T, AnchorError> {
        let response = self.get(provider, path, "application/json", None).await?;
        let declared = content_length(&response);
        if declared.is_some_and(|n| n > MAX_JSON_BYTES) {
            return Err(too_large(provider, path, MAX_JSON_BYTES, declared));
        }
        let limit = usize::try_from(MAX_JSON_BYTES).unwrap_or(usize::MAX);
        let body = Limited::new(response.into_body(), limit).collect();
        let bytes = match tokio::time::timeout(self.request_timeout, body).await {
            Err(_) => return Err(timeout(provider, path)),
            Ok(Err(e)) if e.is::<http_body_util::LengthLimitError>() => {
                return Err(too_large(provider, path, MAX_JSON_BYTES, None))
            }
            Ok(Err(e)) => return Err(transport(provider, path, e)),
            Ok(Ok(collected)) => collected.to_bytes(),
        };
        serde_json::from_slice(&bytes).map_err(|e| AnchorError::BadResponse {
            provider: provider.name.clone(),
            path: path.to_owned(),
            reason: format!("json: {e}"),
        })
    }

    /// GETs `path` as SSZ of `expected_version` and streams the body into `dest` (created
    /// new, mode 0600) under `cap` bytes. A response whose `Eth-Consensus-Version` names
    /// another fork is refused before its body is read. Deletes `dest` on any failure.
    pub async fn download_ssz(
        &self,
        provider: &Provider,
        path: &str,
        expected_version: &str,
        dest: &Path,
        cap: u64,
    ) -> Result<Download, AnchorError> {
        let response = self
            .get(provider, path, OCTET_STREAM, Some(expected_version))
            .await?;
        let content_type = header(&response, CONTENT_TYPE.as_str());
        if !content_type
            .as_deref()
            .is_some_and(|t| t.trim().starts_with(OCTET_STREAM))
        {
            return Err(AnchorError::BadResponse {
                provider: provider.name.clone(),
                path: path.to_owned(),
                reason: format!("content type {content_type:?}, expected {OCTET_STREAM}"),
            });
        }
        let declared = content_length(&response);
        if declared.is_some_and(|n| n > cap) {
            return Err(too_large(provider, path, cap, declared));
        }
        let consensus_version = header(&response, CONSENSUS_VERSION);
        if let Some(got) = consensus_version.as_deref() {
            if !got.trim().eq_ignore_ascii_case(expected_version) {
                return Err(AnchorError::WrongFork {
                    provider: provider.name.clone(),
                    path: path.to_owned(),
                    expected: expected_version.to_owned(),
                    got: got.to_owned(),
                });
            }
        }
        let copy = stream_to_file(response.into_body(), dest, cap, provider, path);
        let result = match tokio::time::timeout(self.body_timeout, copy).await {
            Ok(result) => result,
            Err(_) => Err(timeout(provider, path)),
        };
        match result {
            Ok((len, sha256)) => Ok(Download {
                len,
                sha256,
                consensus_version,
            }),
            Err(e) => {
                // The file may not exist (refused before creation); either way it is gone.
                let _ = tokio::fs::remove_file(dest).await;
                Err(e)
            }
        }
    }

    /// GETs `path`, requiring a 200.
    async fn get(
        &self,
        provider: &Provider,
        path: &str,
        accept: &str,
        consensus_version: Option<&str>,
    ) -> Result<Response<Incoming>, AnchorError> {
        let mut request = Request::get(provider.path(path))
            .header(HOST, provider.authority())
            .header(ACCEPT, accept)
            .header(
                USER_AGENT,
                concat!("ethswarm-anchor-fetch/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(v) = consensus_version {
            request = request.header(CONSENSUS_VERSION, v);
        }
        let request = request
            .body(Empty::<Bytes>::new())
            .map_err(|e| transport(provider, path, e))?;
        let exchange = self.exchange(provider, path, request);
        let response = tokio::time::timeout(self.request_timeout, exchange)
            .await
            .map_err(|_| timeout(provider, path))??;
        if response.status() != StatusCode::OK {
            return Err(AnchorError::HttpStatus {
                provider: provider.name.clone(),
                path: path.to_owned(),
                status: response.status().as_u16(),
            });
        }
        Ok(response)
    }

    async fn exchange(
        &self,
        provider: &Provider,
        path: &str,
        request: Request<Empty<Bytes>>,
    ) -> Result<Response<Incoming>, AnchorError> {
        let tcp = TcpStream::connect((provider.host.as_str(), provider.port))
            .await
            .map_err(|e| transport(provider, path, format!("connect: {e}")))?;
        match provider.scheme {
            Scheme::Http => send(tcp, request).await,
            Scheme::Https => {
                let name = ServerName::try_from(provider.host.clone())
                    .map_err(|e| transport(provider, path, format!("tls: server name: {e}")))?;
                let tls = self
                    .tls
                    .connect(name, tcp)
                    .await
                    .map_err(|e| transport(provider, path, format!("tls: {e}")))?;
                send(tls, request).await
            }
        }
        .map_err(|e| transport(provider, path, format!("http: {e}")))
    }
}

/// One HTTP/1.1 exchange over `io`.
async fn send<S>(io: S, request: Request<Empty<Bytes>>) -> Result<Response<Incoming>, hyper::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        // Ends when the response body is read or dropped; its errors surface on the body.
        let _ = connection.await;
    });
    sender.send_request(request).await
}

/// Streams `body` into a new file at `dest`, failing as soon as more than `cap` bytes arrive.
/// Returns the length and sha256. The caller deletes `dest` on failure.
async fn stream_to_file<B>(
    mut body: B,
    dest: &Path,
    cap: u64,
    provider: &Provider,
    path: &str,
) -> Result<(u64, [u8; 32]), AnchorError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Display,
{
    let io = |what: &str, source| AnchorError::Io {
        context: format!("{what} {}", dest.display()),
        source,
    };
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dest)
        .await
        .map_err(|e| io("create", e))?;
    let mut hasher = Sha256::new();
    let mut len: u64 = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| transport(provider, path, format!("body: {e}")))?;
        let Ok(data) = frame.into_data() else {
            continue; // trailers
        };
        len = len.saturating_add(data.len() as u64);
        if len > cap {
            return Err(too_large(provider, path, cap, None));
        }
        hasher.update(&data);
        file.write_all(&data).await.map_err(|e| io("write", e))?;
    }
    file.sync_all().await.map_err(|e| io("fsync", e))?;
    Ok((len, hasher.finalize().into()))
}

fn header<B>(response: &Response<B>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn content_length<B>(response: &Response<B>) -> Option<u64> {
    header(response, CONTENT_LENGTH.as_str()).and_then(|v| v.trim().parse().ok())
}

fn transport(provider: &Provider, path: &str, reason: impl Display) -> AnchorError {
    AnchorError::Transport {
        provider: provider.name.clone(),
        path: path.to_owned(),
        reason: reason.to_string(),
    }
}

fn timeout(provider: &Provider, path: &str) -> AnchorError {
    AnchorError::Timeout {
        provider: provider.name.clone(),
        path: path.to_owned(),
    }
}

fn too_large(
    provider: &Provider,
    path: &str,
    limit: u64,
    content_length: Option<u64>,
) -> AnchorError {
    AnchorError::BodyTooLarge {
        provider: provider.name.clone(),
        path: path.to_owned(),
        limit,
        content_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::config::{Provider, Scheme};
    use crate::checkpoint::fetch::AnchorError;
    use crate::checkpoint::testkit::{Reply, Server};
    use bytes::Bytes;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn provider(addr: SocketAddr, scheme: Scheme) -> Provider {
        Provider {
            name: "fixture".into(),
            operator: "op".into(),
            scheme,
            host: addr.ip().to_string(),
            port: addr.port(),
            base_path: String::new(),
        }
    }

    fn client() -> Client {
        Client::new(Duration::from_secs(5), Duration::from_secs(5)).unwrap()
    }

    async fn serve(path: &str, reply: Reply) -> Server {
        Server::start(HashMap::from([(path.to_owned(), reply)])).await
    }

    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct Small {
        x: u32,
    }

    #[tokio::test]
    async fn get_json_parses_and_asks_for_json() {
        let s = serve("/j", Reply::Json(r#"{"x":7}"#.into())).await;
        let got: Small = client()
            .get_json(&provider(s.addr, Scheme::Http), "/j")
            .await
            .unwrap();
        assert_eq!(got, Small { x: 7 });
        let seen = s.seen();
        assert_eq!(seen[0].headers["accept"], "application/json");
        assert_eq!(seen[0].headers["host"], s.addr.to_string());
    }

    #[tokio::test]
    async fn get_json_maps_status_parse_and_size_failures() {
        let s = Server::start(HashMap::from([
            ("/missing".to_owned(), Reply::Status(404)),
            ("/garbage".to_owned(), Reply::Json("not json".into())),
            ("/huge".to_owned(), Reply::Declared(MAX_JSON_BYTES + 1)),
            ("/endless".to_owned(), Reply::Endless),
        ]))
        .await;
        let p = provider(s.addr, Scheme::Http);
        let c = client();
        let err = c.get_json::<Small>(&p, "/missing").await.unwrap_err();
        assert!(
            matches!(err, AnchorError::HttpStatus { status: 404, .. }),
            "{err:?}"
        );
        let err = c.get_json::<Small>(&p, "/garbage").await.unwrap_err();
        assert!(matches!(err, AnchorError::BadResponse { .. }), "{err:?}");
        let err = c.get_json::<Small>(&p, "/huge").await.unwrap_err();
        assert!(
            matches!(
                err,
                AnchorError::BodyTooLarge {
                    content_length: Some(_),
                    ..
                }
            ),
            "{err:?}"
        );
        let err = c.get_json::<Small>(&p, "/endless").await.unwrap_err();
        assert!(
            matches!(
                err,
                AnchorError::BodyTooLarge {
                    content_length: None,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn download_streams_to_the_file_and_hashes_it() {
        let body = Bytes::from(vec![7u8; 300_000]);
        let s = serve(
            "/ssz",
            Reply::Ssz {
                body: body.clone(),
                version: Some("gloas"),
            },
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x.ssz");
        let got = client()
            .download_ssz(
                &provider(s.addr, Scheme::Http),
                "/ssz",
                "gloas",
                &dest,
                300_000,
            )
            .await
            .unwrap();
        assert_eq!(got.len, 300_000);
        assert_eq!(got.sha256, <[u8; 32]>::from(Sha256::digest(&body)));
        assert_eq!(got.consensus_version.as_deref(), Some("gloas"));
        assert_eq!(std::fs::read(&dest).unwrap(), body);
        let h = &s.seen()[0].headers;
        assert_eq!(h["accept"], "application/octet-stream");
        assert_eq!(h["eth-consensus-version"], "gloas");
    }

    #[tokio::test]
    async fn download_refuses_a_declared_length_over_the_cap_before_reading() {
        let s = serve("/ssz", Reply::Declared(1025)).await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x.ssz");
        let err = client()
            .download_ssz(
                &provider(s.addr, Scheme::Http),
                "/ssz",
                "gloas",
                &dest,
                1024,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                AnchorError::BodyTooLarge {
                    limit: 1024,
                    content_length: Some(1025),
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn download_aborts_an_endless_body_at_the_cap_and_deletes_the_file() {
        let s = serve("/ssz", Reply::Endless).await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x.ssz");
        let err = client()
            .download_ssz(
                &provider(s.addr, Scheme::Http),
                "/ssz",
                "gloas",
                &dest,
                1 << 20,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                AnchorError::BodyTooLarge {
                    content_length: None,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn download_refuses_a_non_ssz_content_type_and_bad_status() {
        let s = Server::start(HashMap::from([
            (
                "/json".to_owned(),
                Reply::Typed {
                    body: Bytes::from_static(b"{}"),
                    content_type: "application/json",
                },
            ),
            ("/gone".to_owned(), Reply::Status(500)),
        ]))
        .await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x.ssz");
        let p = provider(s.addr, Scheme::Http);
        let err = client()
            .download_ssz(&p, "/json", "gloas", &dest, 1024)
            .await
            .unwrap_err();
        assert!(matches!(err, AnchorError::BadResponse { .. }), "{err:?}");
        let err = client()
            .download_ssz(&p, "/gone", "gloas", &dest, 1024)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AnchorError::HttpStatus { status: 500, .. }),
            "{err:?}"
        );
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn download_refuses_another_fork_before_reading_the_body() {
        let s = serve(
            "/ssz",
            Reply::Ssz {
                body: Bytes::from_static(b"x"),
                version: Some("fulu"),
            },
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x.ssz");
        let err = client()
            .download_ssz(
                &provider(s.addr, Scheme::Http),
                "/ssz",
                "gloas",
                &dest,
                1024,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, AnchorError::WrongFork { ref got, .. } if got == "fulu"),
            "{err:?}"
        );
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn download_times_out_and_deletes_the_file() {
        let s = serve("/ssz", Reply::Endless).await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x.ssz");
        let c = Client::new(Duration::from_secs(5), Duration::from_millis(200)).unwrap();
        let err = c
            .download_ssz(
                &provider(s.addr, Scheme::Http),
                "/ssz",
                "gloas",
                &dest,
                u64::MAX,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AnchorError::Timeout { .. }), "{err:?}");
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let c = Client::new(Duration::from_millis(200), Duration::from_secs(5)).unwrap();
        let err = c
            .get_json::<Small>(&provider(addr, Scheme::Http), "/j")
            .await
            .unwrap_err();
        assert!(matches!(err, AnchorError::Timeout { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn connection_refused_is_a_transport_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = client()
            .get_json::<Small>(&provider(addr, Scheme::Http), "/j")
            .await
            .unwrap_err();
        assert!(matches!(err, AnchorError::Transport { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn https_to_a_plain_http_server_fails_the_tls_handshake() {
        let s = serve("/j", Reply::Json(r#"{"x":7}"#.into())).await;
        let err = client()
            .get_json::<Small>(&provider(s.addr, Scheme::Https), "/j")
            .await
            .unwrap_err();
        assert!(
            matches!(err, AnchorError::Transport { ref reason, .. } if reason.contains("tls")),
            "{err:?}"
        );
    }
}
