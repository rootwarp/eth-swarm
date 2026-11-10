#![cfg(feature = "mock-el")]

use bytes::Bytes;
use engine_api::{PayloadStatusV1, ValidationStatus};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use testkit::mock_el::{Config, MockEl, Reply};

const KEY: [u8; 32] = [0x11; 32];
const HASH: [u8; 32] = [0x22; 32];
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}
fn config() -> Config {
    Config {
        key: KEY,
        skew: Duration::from_secs(60),
        now,
    }
}
// Independently computed known-answer JWT (Python HMAC-SHA256).
const TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMDB9.Hb09lNHg9IiC1UttHzXRW1voUqjM97m4oEuKWkSux5g";

async fn call(
    el: &MockEl,
    method: &str,
    hash: [u8; 32],
    id: u64,
    token: Option<&str>,
) -> Result<(u16, Bytes), Box<dyn std::error::Error + Send + Sync>> {
    let stream = tokio::net::TcpStream::connect(el.addr()).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    let task = tokio::spawn(conn);
    let field = if method == "engine_forkchoiceUpdatedV4" {
        "headBlockHash"
    } else {
        "blockHash"
    };
    let mut request = http::Request::post("/").header("host", el.addr().to_string());
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let body = json!({"jsonrpc":"2.0", "id":id, "method":method, "params":[{field:format!("0x{}", hex::encode(hash))}]});
    let result = async {
        let response = sender
            .send_request(request.body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))?)
            .await?;
        let status = response.status().as_u16();
        Ok((status, response.into_body().collect().await?.to_bytes()))
    }
    .await;
    task.abort();
    result
}
async fn rpc(el: &MockEl, method: &str, id: u64) -> Value {
    let (status, body) = call(el, method, HASH, id, Some(TOKEN)).await.unwrap();
    assert_eq!(status, 200);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["id"], id);
    value
}

#[tokio::test]
async fn each_status() {
    let el = MockEl::start(config()).await.unwrap();
    for method in ["engine_newPayloadV5", "engine_forkchoiceUpdatedV4"] {
        for (reply, status) in [
            (Reply::Valid, ValidationStatus::Valid),
            (
                Reply::Invalid {
                    lvh: Some([0x33; 32]),
                },
                ValidationStatus::Invalid,
            ),
            (Reply::Syncing, ValidationStatus::Syncing),
            (Reply::Accepted, ValidationStatus::Accepted),
        ] {
            if method == "engine_newPayloadV5" {
                el.on_new_payload(HASH, reply);
            } else {
                el.on_forkchoice_updated(HASH, reply);
            }
            let response = rpc(&el, method, 42).await;
            let result = if method == "engine_newPayloadV5" {
                &response["result"]
            } else {
                &response["result"]["payloadStatus"]
            };
            let result: PayloadStatusV1 = serde_json::from_value(result.clone()).unwrap();
            assert_eq!(result.status, status);
            assert_eq!(
                result.latest_valid_hash.map(|h| h.0),
                match status {
                    ValidationStatus::Valid => Some(HASH),
                    ValidationStatus::Invalid => Some([0x33; 32]),
                    _ => None,
                }
            );
        }
    }
}

fn sign(key: &[u8; 32], claims: Value, algorithm: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let header = json!({"alg":algorithm,"typ":"JWT"});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(input.as_bytes());
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

#[tokio::test]
async fn jwt_enforced() {
    let el = MockEl::start(config()).await.unwrap();
    for offset in [-61_i64, -60, -59, 0, 59, 60, 61] {
        let token = sign(&KEY, json!({"iat":1_700_000_000_i64 + offset}), "HS256");
        let (status, _) = call(&el, "engine_newPayloadV5", HASH, 1, Some(&token))
            .await
            .unwrap();
        assert_eq!(
            status,
            if offset.abs() <= 60 { 200 } else { 401 },
            "offset {offset}"
        );
    }
    let bad_tokens = [
        None,
        Some("nonsense".to_owned()),
        Some(sign(&[0x44; 32], json!({"iat":1_700_000_000}), "HS256")),
        Some(sign(&KEY, json!({"iat":1_700_000_000}), "none")),
        Some(sign(&KEY, json!({}), "HS256")),
        Some(sign(&KEY, json!({"iat":"1700000000"}), "HS256")),
    ];
    for token in bad_tokens {
        let (status, body) = call(&el, "engine_newPayloadV5", HASH, 1, token.as_deref())
            .await
            .unwrap();
        assert_eq!(status, 401);
        assert!(!String::from_utf8_lossy(&body).contains(&hex::encode(KEY)));
    }
    let el = MockEl::start(Config {
        skew: Duration::from_secs(10),
        ..config()
    })
    .await
    .unwrap();
    let token = sign(&KEY, json!({"iat":1_700_000_011}), "HS256");
    assert_eq!(
        call(&el, "engine_newPayloadV5", HASH, 1, Some(&token))
            .await
            .unwrap()
            .0,
        401
    );
}

#[tokio::test]
async fn request_log_order() {
    let el = MockEl::start(config()).await.unwrap();
    assert_eq!(
        call(&el, "engine_newPayloadV5", HASH, 0, None)
            .await
            .unwrap()
            .0,
        401
    );
    for (id, method) in [
        "engine_newPayloadV5",
        "engine_forkchoiceUpdatedV4",
        "engine_newPayloadV5",
    ]
    .into_iter()
    .enumerate()
    {
        rpc(&el, method, id as u64).await;
    }
    el.wait_for_requests(3).await;
    let seen = el.requests();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        [json!(0), json!(1), json!(2)]
    );
    assert_eq!(seen[0].method, "engine_newPayloadV5");
    assert_eq!(seen[1].method, "engine_forkchoiceUpdatedV4");
    assert_eq!(
        seen[2].params[0]["blockHash"],
        format!("0x{}", hex::encode(HASH))
    );
}

#[tokio::test]
async fn delay_and_drop() {
    let el = std::sync::Arc::new(MockEl::start(config()).await.unwrap());
    for (index, method) in ["engine_newPayloadV5", "engine_forkchoiceUpdatedV4"]
        .into_iter()
        .enumerate()
    {
        if index == 0 {
            el.on_new_payload(HASH, Reply::Delay(Duration::from_secs(3600)));
        } else {
            el.on_forkchoice_updated(HASH, Reply::Delay(Duration::from_secs(3600)));
        }
        let shared = std::sync::Arc::clone(&el);
        let task = tokio::spawn(async move { rpc(&shared, method, 5).await });
        el.wait_for_requests(index * 2 + 1).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(3599)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "response must wait the scripted delay");
        tokio::time::advance(Duration::from_secs(2)).await;
        let result = task.await.unwrap();
        let status = if index == 0 {
            &result["result"]["status"]
        } else {
            &result["result"]["payloadStatus"]["status"]
        };
        assert_eq!(status, "VALID");
        tokio::time::resume();
        if index == 0 {
            el.on_new_payload(HASH, Reply::Drop);
        } else {
            el.on_forkchoice_updated(HASH, Reply::Drop);
        }
        assert!(call(&el, method, HASH, 6, Some(TOKEN)).await.is_err());
    }
    assert_eq!(el.requests().len(), 4, "drops are logged too");
}

#[tokio::test]
async fn malformed_and_contradictory() {
    let el = MockEl::start(config()).await.unwrap();
    for method in ["engine_newPayloadV5", "engine_forkchoiceUpdatedV4"] {
        if method == "engine_newPayloadV5" {
            el.on_new_payload(HASH, Reply::Malformed);
        } else {
            el.on_forkchoice_updated(HASH, Reply::Malformed);
        }
        let (status, body) = call(&el, method, HASH, 7, Some(TOKEN)).await.unwrap();
        assert_eq!(status, 200);
        assert!(serde_json::from_slice::<Value>(&body).is_err());
        if method == "engine_newPayloadV5" {
            el.on_new_payload(HASH, Reply::Contradictory);
        } else {
            el.on_forkchoice_updated(HASH, Reply::Contradictory);
        }
        let result = rpc(&el, method, 8).await;
        let result = if method == "engine_newPayloadV5" {
            &result["result"]
        } else {
            &result["result"]["payloadStatus"]
        };
        assert_eq!(result["status"], "VALID");
        assert_ne!(
            result["latestValidHash"],
            format!("0x{}", hex::encode(HASH))
        );
        assert!(result["validationError"].is_string());
    }
}

#[tokio::test]
async fn capabilities_and_rec24() {
    let el = MockEl::start(config()).await.unwrap();
    let caps = rpc(&el, "engine_exchangeCapabilities", 9).await;
    assert_eq!(
        caps["result"],
        json!(["engine_newPayloadV5", "engine_forkchoiceUpdatedV4"])
    );
    for method in [
        "engine_newPayloadV4",
        "engine_getPayloadV5",
        "engine_forkchoiceUpdatedV3",
    ] {
        let reply = rpc(&el, method, 10).await;
        assert_eq!(reply["error"]["code"], -38005, "{method}");
        assert!(reply.get("result").is_none());
    }
    for method in [
        "engine_getBlobsV3",
        "engine_getPayloadBodiesByHashV1",
        "unknown",
    ] {
        let reply = rpc(&el, method, 11).await;
        assert_eq!(
            reply["error"]["code"], -32601,
            "not a Rec 24 method: {method}"
        );
    }
}

#[tokio::test]
async fn capabilities_are_scriptable() {
    let el = MockEl::start(config()).await.unwrap();
    el.set_capabilities(vec!["engine_newPayloadV4".to_owned()]);
    assert_eq!(
        rpc(&el, "engine_exchangeCapabilities", 12).await["result"],
        json!(["engine_newPayloadV4"])
    );
    el.set_capabilities(Vec::new());
    assert_eq!(
        rpc(&el, "engine_exchangeCapabilities", 13).await["result"],
        json!([])
    );
}

#[tokio::test]
async fn scripts_are_hash_and_method_scoped() {
    let el = MockEl::start(config()).await.unwrap();
    el.on_new_payload(HASH, Reply::Syncing);
    el.on_forkchoice_updated([0x44; 32], Reply::Invalid { lvh: None });
    for _ in 0..2 {
        assert_eq!(
            rpc(&el, "engine_newPayloadV5", 14).await["result"]["status"],
            "SYNCING"
        );
        assert_eq!(
            rpc(&el, "engine_forkchoiceUpdatedV4", 15).await["result"]["payloadStatus"]["status"],
            "VALID"
        );
    }
    let (_, body) = call(&el, "engine_newPayloadV5", [0x44; 32], 16, Some(TOKEN))
        .await
        .unwrap();
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["result"]["status"], "VALID");
    let (_, body) = call(
        &el,
        "engine_forkchoiceUpdatedV4",
        [0x44; 32],
        17,
        Some(TOKEN),
    )
    .await
    .unwrap();
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["result"]["payloadStatus"]["status"], "INVALID");
    assert!(response["result"]["payloadStatus"]["latestValidHash"].is_null());
    el.on_new_payload(HASH, Reply::Accepted);
    assert_eq!(
        rpc(&el, "engine_newPayloadV5", 18).await["result"]["status"],
        "ACCEPTED"
    );
}
