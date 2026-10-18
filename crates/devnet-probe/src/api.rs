//! The reference CL's beacon API, as far as the probe reads it: the genesis, the node's identity
//! (its peer ID and ENR), the finalized checkpoint and its header (probe mode's Status, through
//! [`cl_chain::probe::ReferenceApi`]) and each slot's block root.
//!
//! Plain `http://` to a loopback [`ReferenceApiUrl`] (`kurtosis port print <enclave> <service>
//! http`), through the collector's client: a fresh connection per request, bounded bodies, one
//! deadline per request. Errors name the API path, never the URL or a response value.

use cl_chain::probe::{self, Checkpoint, Header};
use consensus_types::primitives::{Root, Slot};
use network_config::Genesis;
use serde::Deserialize;
use std::time::Duration;
use testkit::collector::get_json_at as api_get_json;

pub use testkit::collector::{
    ApiError, ReferenceApiUrl, GENESIS_PATH, IDENTITY_PATH, MAX_IDENTITY_BYTES, MAX_JSON_BYTES,
};

/// `GET /eth/v1/beacon/blocks/{block_id}/root`.
pub const BLOCK_ROOT_PATH: &str = "/eth/v1/beacon/blocks/{block_id}/root";

/// `GET /eth/v1/beacon/states/head/finality_checkpoints`.
pub const FINALITY_PATH: &str = "/eth/v1/beacon/states/head/finality_checkpoints";
/// `GET /eth/v1/beacon/headers/{block_id}`.
pub const HEADER_PATH: &str = "/eth/v1/beacon/headers/{block_id}";

/// How long one beacon API request may take \[est\].
pub const DEFAULT_API_TIMEOUT: Duration = Duration::from_secs(5);

/// What `/eth/v1/beacon/genesis` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiGenesis {
    /// `genesis_time` and `genesis_validators_root`.
    pub genesis: Genesis,
    /// `genesis_fork_version`.
    pub fork_version: [u8; 4],
}

/// What `/eth/v1/node/identity` says of the node's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `peer_id`, the libp2p peer ID.
    pub peer_id: String,
    /// `enr`, the node's record (`enr:` and base64url).
    pub enr: String,
}

/// One reference CL's beacon API.
#[derive(Debug, Clone)]
pub struct ProbeApi {
    url: ReferenceApiUrl,
    timeout: Duration,
}

/// `0x` and the lowercase hex of `bytes`, as the beacon API writes roots and versions.
#[must_use]
pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// `0x` and `2 * N` lowercase hex digits, as the beacon API writes roots and versions.
fn prefixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.strip_prefix("0x")?;
    let lower = digits
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut out = [0u8; N];
    (lower && hex::decode_to_slice(digits, &mut out).is_ok()).then_some(out)
}

/// A decimal `u64`, as the beacon API writes integers.
fn decimal(text: &str) -> Option<u64> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    digits.then(|| text.parse().ok()).flatten()
}

fn bad(path: &'static str, field: &str) -> ApiError {
    ApiError::BadResponse {
        path,
        reason: format!("{field} is not what the API specifies"),
    }
}

impl ProbeApi {
    /// The API at `url`, each request within `timeout`.
    #[must_use]
    pub fn new(url: ReferenceApiUrl, timeout: Duration) -> Self {
        Self { url, timeout }
    }

    /// `/eth/v1/beacon/genesis`.
    ///
    /// # Errors
    ///
    /// The request failed or a field is malformed.
    pub async fn genesis(&self) -> Result<ApiGenesis, ApiError> {
        #[derive(Deserialize)]
        struct Data {
            data: Fields,
        }
        #[derive(Deserialize)]
        struct Fields {
            genesis_time: String,
            genesis_validators_root: String,
            genesis_fork_version: String,
        }
        let path = GENESIS_PATH;
        let d: Data = api_get_json(&self.url, path, path, MAX_JSON_BYTES, self.timeout).await?;
        let genesis_time =
            decimal(&d.data.genesis_time).ok_or_else(|| bad(path, "genesis_time"))?;
        let genesis_validators_root = prefixed::<32>(&d.data.genesis_validators_root)
            .ok_or_else(|| bad(path, "genesis_validators_root"))?;
        let fork_version = prefixed::<4>(&d.data.genesis_fork_version)
            .ok_or_else(|| bad(path, "genesis_fork_version"))?;
        Ok(ApiGenesis {
            genesis: Genesis {
                genesis_time,
                genesis_validators_root,
            },
            fork_version,
        })
    }

    /// `/eth/v1/node/identity`: the node's peer ID and ENR, as text.
    ///
    /// # Errors
    ///
    /// The request failed.
    pub async fn identity(&self) -> Result<Identity, ApiError> {
        #[derive(Deserialize)]
        struct Data {
            data: Identity,
        }
        #[derive(Deserialize)]
        struct Identity {
            peer_id: String,
            enr: String,
        }
        let path = IDENTITY_PATH;
        let d: Data = api_get_json(&self.url, path, path, MAX_IDENTITY_BYTES, self.timeout).await?;
        Ok(self::Identity {
            peer_id: d.data.peer_id,
            enr: d.data.enr,
        })
    }

    /// The head state's finalized checkpoint.
    ///
    /// # Errors
    ///
    /// The request failed or a field is malformed.
    pub async fn finalized(&self) -> Result<Checkpoint, ApiError> {
        #[derive(Deserialize)]
        struct Data {
            data: Checkpoints,
        }
        #[derive(Deserialize)]
        struct Checkpoints {
            finalized: Raw,
        }
        #[derive(Deserialize)]
        struct Raw {
            epoch: String,
            root: String,
        }
        let path = FINALITY_PATH;
        let d: Data = api_get_json(&self.url, path, path, MAX_JSON_BYTES, self.timeout).await?;
        let epoch = decimal(&d.data.finalized.epoch).ok_or_else(|| bad(path, "epoch"))?;
        let root = prefixed::<32>(&d.data.finalized.root).ok_or_else(|| bad(path, "root"))?;
        Ok(Checkpoint { epoch, root })
    }

    /// The header of the block `root`: its root and slot.
    ///
    /// # Errors
    ///
    /// The request failed (a 404 for an unknown root) or a field is malformed.
    pub async fn header(&self, root: [u8; 32]) -> Result<Header, ApiError> {
        #[derive(Deserialize)]
        struct Data {
            data: Signed,
        }
        #[derive(Deserialize)]
        struct Signed {
            root: String,
            header: Outer,
        }
        #[derive(Deserialize)]
        struct Outer {
            message: Message,
        }
        #[derive(Deserialize)]
        struct Message {
            slot: String,
        }
        let path = HEADER_PATH;
        let query = format!("/eth/v1/beacon/headers/0x{}", hex::encode(root));
        let d: Data = api_get_json(&self.url, path, &query, MAX_JSON_BYTES, self.timeout).await?;
        Ok(Header {
            root: prefixed::<32>(&d.data.root).ok_or_else(|| bad(path, "root"))?,
            slot: decimal(&d.data.header.message.slot).ok_or_else(|| bad(path, "slot"))?,
        })
    }

    /// The root of the block at `slot` (`/eth/v1/beacon/blocks/{slot}/root`); `None` when the
    /// API answers 404, an empty slot.
    ///
    /// # Errors
    ///
    /// The request failed otherwise, or the root is malformed.
    pub async fn block_root(&self, slot: Slot) -> Result<Option<Root>, String> {
        #[derive(Deserialize)]
        struct Data {
            data: RootData,
        }
        #[derive(Deserialize)]
        struct RootData {
            root: String,
        }
        let path = BLOCK_ROOT_PATH;
        let query = format!("/eth/v1/beacon/blocks/{slot}/root");
        match api_get_json::<Data>(&self.url, path, &query, MAX_JSON_BYTES, self.timeout).await {
            Ok(d) => prefixed::<32>(&d.data.root)
                .map(|r| Some(Root::from(r)))
                .ok_or_else(|| format!("slot {slot}: {}", bad(path, "root"))),
            Err(ApiError::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(format!("slot {slot}: {e}")),
        }
    }
}

impl probe::ReferenceApi for ProbeApi {
    async fn finalized_checkpoint(&self) -> Result<Checkpoint, probe::ApiError> {
        self.finalized()
            .await
            .map_err(|e| probe::ApiError(e.to_string()))
    }

    async fn header(&self, root: [u8; 32]) -> Result<Header, probe::ApiError> {
        ProbeApi::header(self, root)
            .await
            .map_err(|e| probe::ApiError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::FixtureChain;
    use cl_chain::probe::ReferenceApi as _;
    use testkit::collector::testing::Reply;

    const T: Duration = Duration::from_secs(5);

    fn genesis() -> Genesis {
        Genesis {
            genesis_time: 1_760_800_000,
            genesis_validators_root: [0x42; 32],
        }
    }

    #[tokio::test]
    async fn reads_the_genesis_and_the_identity() {
        let chain = FixtureChain::default();
        let server = chain.serve().await;
        let api = ProbeApi::new(server.url(""), T);
        assert!(matches!(
            api.genesis().await,
            Err(ApiError::Status { status: 404, .. })
        ));
        chain.with(|s| {
            s.genesis = Some((genesis(), [0, 0, 0, 1]));
            s.identity = Some(("16Uiu2HAmPeer".into(), "enr:-abc".into()));
        });
        assert_eq!(
            api.genesis().await.unwrap(),
            ApiGenesis {
                genesis: genesis(),
                fork_version: [0, 0, 0, 1]
            }
        );
        assert_eq!(
            api.identity().await.unwrap(),
            Identity {
                peer_id: "16Uiu2HAmPeer".into(),
                enr: "enr:-abc".into()
            }
        );
        chain.with(|s| s.down = true);
        assert!(matches!(
            api.identity().await,
            Err(ApiError::Status { status: 503, .. })
        ));
    }

    #[tokio::test]
    async fn malformed_genesis_fields_are_refused() {
        let replies = [
            r#"{"data":{"genesis_time":"x","genesis_validators_root":"0x00","genesis_fork_version":"0x00000001"}}"#.to_owned(),
            format!(r#"{{"data":{{"genesis_time":"1","genesis_validators_root":"0x{}","genesis_fork_version":"0x0001"}}}}"#, "42".repeat(32)),
            format!(r#"{{"data":{{"genesis_time":"1","genesis_validators_root":"0x{}","genesis_fork_version":"0x00000001"}}}}"#, "4G".repeat(32)),
        ];
        let server =
            testkit::collector::testing::FixtureServer::start(move |n, _| Reply::json(&replies[n]))
                .await;
        let api = ProbeApi::new(server.url(""), T);
        for want in [
            "genesis_time",
            "genesis_fork_version",
            "genesis_validators_root",
        ] {
            let err = api.genesis().await.unwrap_err().to_string();
            assert!(err.contains(want), "{err}");
        }
    }

    #[tokio::test]
    async fn the_status_reads_go_through_the_chain_trait() {
        let chain = FixtureChain::default();
        let server = chain.serve().await;
        let api = ProbeApi::new(server.url(""), T);
        assert!(api.finalized_checkpoint().await.is_err());
        let root = Root::repeat_byte(0xab);
        chain.finalize(3, root, 24);
        let checkpoint = api.finalized_checkpoint().await.unwrap();
        assert_eq!(checkpoint.epoch, 3);
        assert_eq!(checkpoint.root, root.0);
        let header = api.header(root.0).await.unwrap();
        assert_eq!(header.root, root.0);
        assert_eq!(header.slot, 24);
        let err = api.header([0xcd; 32]).await.unwrap_err();
        assert!(err.to_string().contains("404"), "{err}");
    }

    #[tokio::test]
    async fn block_roots_and_empty_slots() {
        let chain = FixtureChain::default();
        let server = chain.serve().await;
        let api = ProbeApi::new(server.url(""), T);
        chain.with(|s| {
            s.roots.insert(17, Root::repeat_byte(0x17));
        });
        assert_eq!(
            api.block_root(17).await.unwrap(),
            Some(Root::repeat_byte(0x17))
        );
        assert_eq!(
            api.block_root(18).await.unwrap(),
            None,
            "404: an empty slot"
        );
        chain.with(|s| s.down = true);
        assert!(api.block_root(17).await.unwrap_err().contains("503"));
    }
}
