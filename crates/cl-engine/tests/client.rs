//! Engine client against the in-crate mock EL.

mod common;

use cl_engine::capabilities::{FORKCHOICE_UPDATED_V4, NEW_PAYLOAD_V5};
use cl_engine::client::{
    Backoff, CallError, Clock, Config, EndpointError, EngineEndpoint, Session, StartError,
};
use cl_engine::jwt;
use common::{required_methods, test_secret, MockEl};
use data_encoding::BASE64URL_NOPAD;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: [u8; 32] = [0x11; 32];

fn config(url: &str, secret: cl_engine::jwt::JwtSecret) -> Config {
    Config::new(EngineEndpoint::parse(url, false).unwrap(), secret).backoff(Backoff {
        initial: Duration::from_millis(1),
        cap: Duration::from_millis(8),
    })
}

struct ScriptClock(Mutex<VecDeque<SystemTime>>);

impl Clock for ScriptClock {
    fn now(&self) -> SystemTime {
        self.0.lock().unwrap().pop_front().expect("a scripted time")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_capabilities_refuse_start() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(
        secret.expose_secret(),
        vec![
            "engine_newPayloadV4".into(),
            "engine_forkchoiceUpdatedV3".into(),
        ],
    )
    .await;
    let err = Session::connect(config(&mock.url(), secret))
        .await
        .unwrap_err();
    let StartError::MissingCaps(missing) = err else {
        panic!("{err}");
    };
    assert_eq!(missing.missing(), &[NEW_PAYLOAD_V5, FORKCHOICE_UPDATED_V4]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_capability_error_names_the_method() {
    let secret = test_secret(SECRET);
    for (offered, absent) in [
        (
            ["engine_newPayloadV4", FORKCHOICE_UPDATED_V4],
            NEW_PAYLOAD_V5,
        ),
        (
            [NEW_PAYLOAD_V5, "engine_forkchoiceUpdatedV3"],
            FORKCHOICE_UPDATED_V4,
        ),
    ] {
        let mock = MockEl::start(
            secret.expose_secret(),
            offered.iter().map(|m| (*m).to_owned()).collect(),
        )
        .await;
        let err = Session::connect(config(&mock.url(), test_secret(SECRET)))
            .await
            .unwrap_err();
        assert!(matches!(err, StartError::MissingCaps(_)), "{err}");
        let shown = err.to_string();
        assert!(shown.contains(absent), "{shown}");
        // The call path reports the same name.
        let call: CallError = err.into();
        assert!(call.to_string().contains(absent), "{call}");
    }
}

/// A clock a fixed distance from the real one.
struct Skewed(i64);

impl Clock for Skewed {
    fn now(&self) -> SystemTime {
        let now = SystemTime::now();
        let by = Duration::from_secs(self.0.unsigned_abs());
        if self.0 < 0 {
            now - by
        } else {
            now + by
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_rejects_iat_outside_sixty_seconds() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    // iat and the verifier's clock are whole seconds, so 61 s can read as 60 across a tick.
    for skew in [-62_i64, 62, -3600, 3600] {
        let err = Session::connect(
            config(&mock.url(), test_secret(SECRET)).clock(std::sync::Arc::new(Skewed(skew))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, StartError::Unauthorized),
            "skew {skew}: {err}"
        );
    }
    assert_eq!(mock.capability_calls(), 0, "a stale token was served");
    for skew in [-50_i64, 50] {
        Session::connect(
            config(&mock.url(), test_secret(SECRET)).clock(std::sync::Arc::new(Skewed(skew))),
        )
        .await
        .unwrap_or_else(|err| panic!("skew {skew}: {err}"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_jwt_fails_the_call() {
    let el = test_secret(SECRET);
    let client = test_secret([0x22; 32]);
    let mock = MockEl::start(el.expose_secret(), required_methods()).await;
    let err = Session::connect(config(&mock.url(), client))
        .await
        .unwrap_err();
    assert!(matches!(err, StartError::Unauthorized), "{err}");
    let shown = err.to_string();
    assert!(!shown.contains("2222"), "{shown}");
    assert!(!shown.contains(&hex(&SECRET)), "{shown}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_use_fresh_iat() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let t0 = SystemTime::now();
    let clock = ScriptClock(Mutex::new(VecDeque::from([
        t0,
        t0 + Duration::from_secs(5),
        t0 + Duration::from_secs(10),
    ])));
    let session = Session::connect(config(&mock.url(), secret).clock(std::sync::Arc::new(clock)))
        .await
        .unwrap();
    session
        .call("engine_newPayloadV5", &json!([1]), Duration::from_secs(2))
        .await
        .unwrap();
    session
        .call("engine_newPayloadV5", &json!([2]), Duration::from_secs(2))
        .await
        .unwrap();
    let iats = mock.iats();
    assert!(iats.len() >= 3, "{iats:?}");
    let call_iats = &iats[iats.len() - 2..];
    assert_ne!(call_iats[0], call_iats[1], "{iats:?}");
    assert_eq!(call_iats[1] - call_iats[0], 5, "{iats:?}");
    let shown = format!("{session:?}");
    assert!(!shown.contains(&hex(&SECRET)), "{shown}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_over_the_declared_cap_fails() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    mock.push_result(json!({"status":"VALID","validationError":"x".repeat(800)}));
    let session = Session::connect(config(&mock.url(), secret).max_body_bytes(256))
        .await
        .unwrap();
    let err = session
        .call("engine_newPayloadV5", &json!([1]), Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        matches!(err, CallError::BodyTooLarge { limit: 256 }),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_response_over_the_cap_fails() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    mock.chunked_next(4_000);
    let session = Session::connect(config(&mock.url(), secret).max_body_bytes(256))
        .await
        .unwrap();
    let err = session
        .call("engine_newPayloadV5", &json!([1]), Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        matches!(err, CallError::BodyTooLarge { limit: 256 }),
        "{err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_timeout_fails() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    mock.set_delay(Duration::from_secs(2));
    let session = Session::connect(config(&mock.url(), secret)).await.unwrap();
    let started = std::time::Instant::now();
    let err = session
        .call(
            "engine_newPayloadV5",
            &json!([1]),
            Duration::from_millis(80),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CallError::Timeout), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_millis(800),
        "timeout did not fire"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_rejects_alg_none() {
    let secret = test_secret(SECRET);
    let mock = MockEl::start(secret.expose_secret(), required_methods()).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header = BASE64URL_NOPAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = BASE64URL_NOPAD.encode(format!(r#"{{"iat":{now}}}"#).as_bytes());
    let token = format!("{header}.{payload}.");
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"engine_exchangeCapabilities","params":[[]]}"#;
    let status = post(&mock, &token, body).await;
    assert_eq!(status, 401);
    // A token our client produces is HS256 and is what `verify` accepts.
    let produced = jwt::token(secret.expose_secret(), std::time::SystemTime::now());
    assert!(jwt::verify(
        secret.expose_secret(),
        &produced,
        std::time::SystemTime::now()
    )
    .is_ok());
    assert!(!produced.contains("none"));
}

#[test]
fn non_loopback_is_rejected_unless_the_operator_opts_out() {
    assert_eq!(
        EngineEndpoint::parse("http://10.1.2.3:8551", false).unwrap_err(),
        EndpointError::NotLoopback
    );
    assert!(EngineEndpoint::parse("http://10.1.2.3:8551", true).is_ok());
    assert!(EngineEndpoint::parse("http://127.0.0.1:8551", false).is_ok());
}

async fn post(mock: &MockEl, token: &str, body: &str) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(mock.url().trim_start_matches("http://"))
        .await
        .unwrap();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        mock.url().trim_start_matches("http://"),
        body.len(),
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    let code = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    code
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
