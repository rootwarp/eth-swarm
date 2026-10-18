//! `GET /eth/v1/config/spec`: the reference node's `CONFIG_NAME`, so a collector pointed at
//! another network's node (Sepolia's port on a host that also runs Hoodi) refuses to start.

use super::client::{get_json, ApiError};
use crate::collector::url::ReferenceApiUrl;
use std::time::Duration;

/// The spec API path.
pub const SPEC_PATH: &str = "/eth/v1/config/spec";
/// Cap on the spec response: 256 KiB. It is the node's whole config, every value a string; a
/// few tens of KiB today, and it grows with each fork's keys and the blob schedule.
pub const MAX_SPEC_BYTES: usize = 256 << 10;
/// The longest `CONFIG_NAME` accepted. Network names are short; anything longer is not one.
const MAX_CONFIG_NAME_BYTES: usize = 64;

/// The node's `CONFIG_NAME` from `GET /eth/v1/config/spec`: a plain name (ASCII letters,
/// digits, `-` and `_`, at most 64 bytes), compared by the caller against the network it was
/// configured for. Nothing from the response goes into an error: a refused name is not quoted.
pub async fn config_name(url: &ReferenceApiUrl, timeout: Duration) -> Result<String, ApiError> {
    #[derive(serde::Deserialize)]
    struct Data {
        data: Spec,
    }
    #[derive(serde::Deserialize)]
    struct Spec {
        #[serde(rename = "CONFIG_NAME")]
        config_name: String,
    }
    let d: Data = get_json(url, SPEC_PATH, MAX_SPEC_BYTES, timeout).await?;
    let name = d.data.config_name;
    let plain = !name.is_empty()
        && name.len() <= MAX_CONFIG_NAME_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !plain {
        return Err(ApiError::BadResponse {
            path: SPEC_PATH,
            reason: "CONFIG_NAME is not a plain network name".into(),
        });
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::testing::{FixtureServer, Reply};
    use std::time::Duration;

    const KEY: &str = "/key-hunter2";

    #[tokio::test]
    async fn config_name_is_read_from_the_spec() {
        let server = FixtureServer::start(|_, _| {
            Reply::json(
                r#"{"data":{"CONFIG_NAME":"hoodi","PRESET_BASE":"mainnet","BLOB_SCHEDULE":[{"EPOCH":"1","MAX_BLOBS_PER_BLOCK":"9"}]}}"#,
            )
        })
        .await;
        let name = config_name(&server.url(KEY), Duration::from_secs(5)).await;
        assert_eq!(name.as_deref(), Ok("hoodi"));
        assert_eq!(server.seen()[0].0, format!("{KEY}{SPEC_PATH}"));
    }

    #[tokio::test]
    async fn a_spec_without_a_plain_config_name_is_refused_unquoted() {
        let bodies = [
            r#"{"data":{"PRESET_BASE":"mainnet"}}"#.to_owned(),
            r#"{"data":{"CONFIG_NAME":4242}}"#.to_owned(),
            r#"{"data":{"CONFIG_NAME":"hoodi","CONFIG_NAME":"sepolia"}}"#.to_owned(),
            r#"{"data":{"CONFIG_NAME":""}}"#.to_owned(),
            r#"{"data":{"CONFIG_NAME":"hunter2 secret"}}"#.to_owned(),
            format!(r#"{{"data":{{"CONFIG_NAME":"{}"}}}}"#, "h".repeat(65)),
            format!(
                r#"{{"data":{{"CONFIG_NAME":"hoodi","PAD":"{}"}}}}"#,
                "9".repeat(MAX_SPEC_BYTES)
            ),
        ];
        let count = bodies.len();
        let server = FixtureServer::start(move |n, _| Reply::json(&bodies[n])).await;
        let url = server.url(KEY);
        for _ in 0..count {
            let err = config_name(&url, Duration::from_secs(5)).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    ApiError::BadResponse {
                        path: SPEC_PATH,
                        ..
                    }
                ),
                "{err}"
            );
            let text = err.to_string();
            assert!(
                !text.contains("4242") && !text.contains("hunter2"),
                "{text}"
            );
            assert!(
                !text.contains("sepolia") && !text.contains("hhhh"),
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn a_failed_request_names_the_path_only() {
        let server = FixtureServer::start(|_, _| Reply::status(404)).await;
        let err = config_name(&server.url(KEY), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            ApiError::Status {
                path: SPEC_PATH,
                status: 404
            }
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = ReferenceApiUrl::parse(&format!("http://{}", listener.local_addr().unwrap()));
        // Accepts and never answers.
        let _held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let err = config_name(&url.unwrap(), Duration::from_millis(200)).await;
        assert!(
            matches!(
                err,
                Err(ApiError::Timeout {
                    path: SPEC_PATH,
                    ..
                })
            ),
            "{err:?}"
        );
    }
}
