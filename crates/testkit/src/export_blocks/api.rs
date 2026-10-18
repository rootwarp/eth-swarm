//! The beacon API reads an export makes: SSZ blocks and the genesis state, block roots and the
//! finalized header, each bounded in size and time.
//!
//! Every request goes through the collector's HTTP/1.1 client ([`crate::collector::api_get`]):
//! plain `http://` to a loopback [`ReferenceApiUrl`], a fresh connection per request, no
//! redirects. Errors name the API path template and the slot, never the base URL or a value
//! from the response.

use super::ExportError;
use crate::archive::canonical_hex;
use crate::collector::{api_get, ApiError, ReferenceApiUrl, MAX_JSON_BYTES};
use bytes::Bytes;
use consensus_types::primitives::{Root, Slot};
use http::header::CONTENT_TYPE;
use http_body_util::{BodyExt, Limited};
use std::time::Duration;

/// `GET /eth/v2/beacon/blocks/{slot}` (SSZ).
pub const BLOCK_PATH: &str = "/eth/v2/beacon/blocks/{slot}";
/// `GET /eth/v1/beacon/blocks/{slot}/root`.
pub const BLOCK_ROOT_PATH: &str = "/eth/v1/beacon/blocks/{slot}/root";
/// `GET /eth/v2/debug/beacon/states/{state_root}` (SSZ): the genesis state, by the genesis
/// block's `state_root`. Every CL serves a state by its root; not every one serves the
/// `genesis` id (Lodestar without `--serveHistoricalState` answers 500).
pub const GENESIS_STATE_PATH: &str = "/eth/v2/debug/beacon/states/{state_root}";
/// `GET /eth/v1/beacon/headers/finalized`.
pub const FINALIZED_HEADER_PATH: &str = "/eth/v1/beacon/headers/finalized";

const SSZ: &str = "application/octet-stream";
const JSON: &str = "application/json";

/// A beacon API, read with one deadline per request.
#[derive(Debug, Clone)]
pub(crate) struct BeaconApi<'a> {
    url: &'a ReferenceApiUrl,
    timeout: Duration,
}

impl<'a> BeaconApi<'a> {
    pub(crate) fn new(url: &'a ReferenceApiUrl, timeout: Duration) -> Self {
        Self { url, timeout }
    }

    /// The finalized block header's slot and root.
    pub(crate) async fn finalized(&self) -> Result<(Slot, Root), ExportError> {
        #[derive(serde::Deserialize)]
        struct Data {
            data: Header,
        }
        #[derive(serde::Deserialize)]
        struct Header {
            root: String,
            header: Signed,
        }
        #[derive(serde::Deserialize)]
        struct Signed {
            message: Message,
        }
        #[derive(serde::Deserialize)]
        struct Message {
            slot: String,
        }
        let path = FINALIZED_HEADER_PATH;
        let body = self.fetch(path, path, JSON, MAX_JSON_BYTES, None).await?;
        let d: Data = json(path, None, &body)?;
        let slot = decimal(&d.data.header.message.slot)
            .ok_or_else(|| bad(path, None, "the header slot is not a decimal u64"))?;
        let root = root_hex(&d.data.root).ok_or_else(|| bad(path, None, NOT_A_ROOT))?;
        Ok((slot, root))
    }

    /// The SSZ of the state with root `state_root`, at most `max` bytes, within `timeout`;
    /// `None` when the API answers 404.
    pub(crate) async fn state_by_root(
        &self,
        state_root: Root,
        max: usize,
        timeout: Duration,
    ) -> Result<Option<Bytes>, ExportError> {
        let path = GENESIS_STATE_PATH;
        let path_and_query = format!("/eth/v2/debug/beacon/states/{state_root}");
        let api = Self {
            timeout,
            ..self.clone()
        };
        match api.fetch(path, &path_and_query, SSZ, max, None).await {
            Ok(body) => Ok(Some(body)),
            Err(ExportError::Api {
                source: ApiError::Status { status: 404, .. },
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The block at `slot` as SSZ, at most `max` bytes; `None` when the API answers 404 (an
    /// empty slot).
    pub(crate) async fn block(&self, slot: Slot, max: usize) -> Result<Option<Bytes>, ExportError> {
        let path_and_query = format!("/eth/v2/beacon/blocks/{slot}");
        match self
            .fetch(BLOCK_PATH, &path_and_query, SSZ, max, Some(slot))
            .await
        {
            Ok(body) => Ok(Some(body)),
            Err(ExportError::Api {
                source: ApiError::Status { status: 404, .. },
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The API's root of the block at `slot`; `None` when the API answers 404 (no block).
    pub(crate) async fn block_root(&self, slot: Slot) -> Result<Option<Root>, ExportError> {
        #[derive(serde::Deserialize)]
        struct Data {
            data: RootData,
        }
        #[derive(serde::Deserialize)]
        struct RootData {
            root: String,
        }
        let path = BLOCK_ROOT_PATH;
        let path_and_query = format!("/eth/v1/beacon/blocks/{slot}/root");
        let body = match self
            .fetch(path, &path_and_query, JSON, MAX_JSON_BYTES, Some(slot))
            .await
        {
            Ok(body) => body,
            Err(ExportError::Api {
                source: ApiError::Status { status: 404, .. },
                ..
            }) => return Ok(None),
            Err(e) => return Err(e),
        };
        let d: Data = json(path, Some(slot), &body)?;
        root_hex(&d.data.root)
            .map(Some)
            .ok_or_else(|| bad(path, Some(slot), NOT_A_ROOT))
    }

    /// `GET`, a 200 of content type `accept`, and at most `max` body bytes, all within the
    /// deadline.
    async fn fetch(
        &self,
        path: &'static str,
        path_and_query: &str,
        accept: &'static str,
        max: usize,
        slot: Option<Slot>,
    ) -> Result<Bytes, ExportError> {
        let api = |source: ApiError| ExportError::Api { slot, source };
        let fetch = async {
            let response = api_get(self.url, path, path_and_query, accept)
                .await
                .map_err(api)?;
            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            if !content_type.to_ascii_lowercase().starts_with(accept) {
                return Err(bad(
                    path,
                    slot,
                    &format!("the content type is not {accept}"),
                ));
            }
            match Limited::new(response.into_body(), max).collect().await {
                Ok(body) => Ok(body.to_bytes()),
                Err(e) if e.is::<http_body_util::LengthLimitError>() => {
                    Err(ExportError::TooLarge { path, slot, max })
                }
                Err(e) => Err(api(ApiError::Transport {
                    path,
                    reason: format!("body: {e}"),
                })),
            }
        };
        tokio::time::timeout(self.timeout, fetch)
            .await
            .map_err(|_| {
                api(ApiError::Timeout {
                    path,
                    timeout: self.timeout,
                })
            })?
    }
}

const NOT_A_ROOT: &str = "the root is not 0x and 64 lowercase hex";

/// A root as the API writes it: `0x` and 64 lowercase hex digits.
fn root_hex(text: &str) -> Option<Root> {
    text.strip_prefix("0x")
        .and_then(canonical_hex::<32>)
        .map(Root::from)
}

fn bad(path: &'static str, slot: Option<Slot>, reason: &str) -> ExportError {
    ExportError::Api {
        slot,
        source: ApiError::BadResponse {
            path,
            reason: reason.to_owned(),
        },
    }
}

/// Parses a JSON body; serde's message quotes what it found, so only the kind and place of
/// the error are kept.
fn json<T: serde::de::DeserializeOwned>(
    path: &'static str,
    slot: Option<Slot>,
    body: &[u8],
) -> Result<T, ExportError> {
    serde_json::from_slice(body).map_err(|e| {
        let reason = format!(
            "json: {:?} error at line {} column {}",
            e.classify(),
            e.line(),
            e.column()
        );
        bad(path, slot, &reason)
    })
}

/// A decimal `u64` without sign or other characters, as the API writes integers.
fn decimal(text: &str) -> Option<u64> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    digits.then(|| text.parse().ok()).flatten()
}
