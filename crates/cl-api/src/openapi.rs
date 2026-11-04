//! The part 1 routes against the beacon-APIs `01e99a6` OpenAPI schemas.
//!
//! `tests/fixtures/beacon-apis-01e99a6.json` is a pinned copy of the response schemas these
//! routes need, so nothing is fetched at test time. [`Spec::check`] checks the JSON Schema
//! keywords those schemas use. A keyword, type or pattern it does not know fails the test, so
//! the fixture cannot gain a rule that is silently skipped.

use serde_json::Value;

const FIXTURE: &str = include_str!("../tests/fixtures/beacon-apis-01e99a6.json");

/// The beacon-APIs commit the fixture was copied from.
const COMMIT: &str = "01e99a6530b22941f619bde525cbf8bb61991d42";

/// The fixture: `paths` and the `components` their `$ref`s point at.
struct Spec {
    root: Value,
}

impl Spec {
    fn load() -> Self {
        Self {
            root: serde_json::from_str(FIXTURE).expect("the fixture is JSON"),
        }
    }

    /// `value`, with any chain of `$ref` (`#/a/b`) followed.
    fn resolve<'a>(&'a self, mut value: &'a Value) -> &'a Value {
        while let Some(target) = value.get("$ref").and_then(Value::as_str) {
            let pointer = target
                .strip_prefix('#')
                .unwrap_or_else(|| panic!("{target}: only local references"));
            value = self
                .root
                .pointer(pointer)
                .unwrap_or_else(|| panic!("{target}: not in the fixture"));
        }
        value
    }

    /// The documented response of `GET path` with `status`.
    fn response(&self, path: &str, status: u16) -> Option<&Value> {
        let operation = self.root["paths"].get(path)?.get("get")?;
        operation["responses"]
            .get(status.to_string())
            .map(|r| self.resolve(r))
    }

    /// The JSON schema of a response, `None` for a response without content.
    fn json_schema<'a>(&'a self, response: &'a Value) -> Option<&'a Value> {
        response
            .get("content")
            .map(|c| &c["application/json"]["schema"])
    }

    fn schema(&self, name: &str) -> &Value {
        &self.root["components"]["schemas"][name]
    }

    /// Every way `value` breaks `schema`.
    fn errors(&self, schema: &Value, value: &Value) -> Vec<String> {
        let mut errors = Vec::new();
        self.check(schema, value, "$", &mut errors);
        errors
    }

    fn check(&self, schema: &Value, value: &Value, at: &str, errors: &mut Vec<String>) {
        let schema = self.resolve(schema);
        let rules = schema
            .as_object()
            .unwrap_or_else(|| panic!("{at}: a schema is an object, not {schema}"));
        let mut failures = Vec::new();
        let mut fail = |what: String| failures.push(format!("{at}: {what}, got {value}"));
        for (keyword, rule) in rules {
            match keyword.as_str() {
                "title" => {}
                "type" => {
                    let ok = match rule.as_str() {
                        Some("object") => value.is_object(),
                        Some("array") => value.is_array(),
                        Some("string") => value.is_string(),
                        Some("boolean") => value.is_boolean(),
                        Some("number") => value.is_number(),
                        Some("integer") => value.is_i64() || value.is_u64(),
                        _ => panic!("{at}: unknown type {rule}"),
                    };
                    if !ok {
                        fail(format!("expected type {rule}"));
                    }
                }
                "format" => {
                    assert_eq!(rule, "hex", "{at}: unknown format");
                    let hex = value.as_str().and_then(|s| s.strip_prefix("0x"));
                    if value.is_string()
                        && !hex.is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
                    {
                        fail("expected 0x-prefixed hex".into());
                    }
                }
                "pattern" => {
                    // The only pattern the fixture has: `^0x[a-fA-F0-9]{N}$`.
                    let pattern = rule.as_str().unwrap();
                    let digits: usize = pattern
                        .strip_prefix("^0x[a-fA-F0-9]{")
                        .and_then(|rest| rest.strip_suffix("}$"))
                        .and_then(|n| n.parse().ok())
                        .unwrap_or_else(|| panic!("{at}: unsupported pattern {pattern}"));
                    if let Some(s) = value.as_str() {
                        let hex = s.strip_prefix("0x").unwrap_or("");
                        if !s.starts_with("0x")
                            || hex.len() != digits
                            || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            fail(format!("expected {pattern}"));
                        }
                    }
                }
                "minimum" | "maximum" => {
                    let bound = rule.as_f64().unwrap();
                    if let Some(n) = value.as_f64() {
                        let ok = if keyword == "minimum" {
                            n >= bound
                        } else {
                            n <= bound
                        };
                        if !ok {
                            fail(format!("{keyword} {bound}"));
                        }
                    }
                }
                "required" => {
                    if let Some(object) = value.as_object() {
                        for name in rule.as_array().unwrap() {
                            if !object.contains_key(name.as_str().unwrap()) {
                                fail(format!("missing required {name}"));
                            }
                        }
                    }
                }
                "properties" => {
                    if let Some(object) = value.as_object() {
                        for (name, sub) in rule.as_object().unwrap() {
                            if let Some(v) = object.get(name) {
                                self.check(sub, v, &format!("{at}.{name}"), errors);
                            }
                        }
                    }
                }
                "items" => {
                    if let Some(items) = value.as_array() {
                        for (i, v) in items.iter().enumerate() {
                            self.check(rule, v, &format!("{at}[{i}]"), errors);
                        }
                    }
                }
                other => panic!("{at}: the checker does not know the keyword {other:?}"),
            }
        }
        errors.extend(failures);
    }

    /// The checker catches what it should, so a pass means something.
    fn self_check(&self) {
        use serde_json::json;
        let fork = json!({"$ref": "#/components/schemas/Fork"});
        let good = json!({"previous_version": "0x00000001", "current_version": "0x0000000A", "epoch": "1"});
        assert_eq!(self.errors(&fork, &good), Vec::<String>::new());
        for bad in [
            json!({"previous_version": "0x00000001", "current_version": "0x00000002"}),
            json!({"previous_version": "0x00000001", "current_version": "0x00000002", "epoch": 1}),
            json!({"previous_version": "0x0001", "current_version": "0x00000002", "epoch": "1"}),
            json!({"previous_version": "0x0000000g", "current_version": "0x00000002", "epoch": "1"}),
            json!({"previous_version": "000000001", "current_version": "0x00000002", "epoch": "1"}),
            json!([good]),
        ] {
            assert!(!self.errors(&fork, &bad).is_empty(), "{bad}");
        }
        let syncing = self
            .json_schema(self.response("/eth/v1/node/syncing", 200).unwrap())
            .unwrap();
        let data = json!({"head_slot": "1", "sync_distance": "0", "is_syncing": false,
                          "is_optimistic": false, "el_offline": false});
        assert!(self.errors(syncing, &json!({ "data": data })).is_empty());
        let mut wrong = data.clone();
        wrong["is_syncing"] = json!("false");
        assert!(!self.errors(syncing, &json!({ "data": wrong })).is_empty());
        assert!(!self.errors(syncing, &data).is_empty());
        let error = self.schema("ErrorMessage");
        assert!(self
            .errors(error, &json!({"code": 404, "message": "x"}))
            .is_empty());
        assert!(!self
            .errors(error, &json!({"code": "404", "message": "x"}))
            .is_empty());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::Router;
    use http::header::{ACCEPT, CONTENT_TYPE};
    use http::{Method, Request, StatusCode};
    use network_config::{ChainConfig, Network};

    use super::*;
    use crate::node_state::{ChainHead, NodeState};
    use crate::routes::config::ConfigData;
    use crate::server::{router, ApiState};
    use crate::testing::{self, json, request, WALL_SLOT};

    /// Checks one response against the fixture; returns its status.
    async fn check(
        spec: &Spec,
        app: &Router,
        path: &str,
        req: Request<Body>,
        seen: &mut BTreeSet<String>,
    ) -> StatusCode {
        let uri = req.uri().to_string();
        let (status, headers, body) = request(app, req).await;
        seen.insert(path.to_owned());
        let response = spec.response(path, status.as_u16());
        assert!(
            response.is_some() || !status.is_success(),
            "{uri}: {status} is not a response of {path}"
        );
        let schema = match response.and_then(|r| spec.json_schema(r)) {
            Some(schema) => schema,
            // A documented response without content has no body (`node/health`).
            None if response.is_some() && body.is_empty() => return status,
            None if status.is_success() => panic!("{uri}: {status} has no content: {body:?}"),
            // Any other error carries the beacon-APIs error body.
            None => spec.schema("ErrorMessage"),
        };
        assert_eq!(headers[CONTENT_TYPE], "application/json", "{uri}");
        let errors = spec.errors(schema, &json(&body));
        assert!(
            errors.is_empty(),
            "{uri} ({status}) breaks the schema: {errors:#?}"
        );
        status
    }

    fn get(uri: &str) -> Request<Body> {
        Request::get(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn part1_routes_match_schema() {
        let spec = Spec::load();
        assert_eq!(spec.root["source"]["commit"], COMMIT);
        spec.self_check();
        let mut seen = BTreeSet::new();
        let node = NodeState::new(testing::clock());
        let app = router(testing::api_state(node.clone()));
        let (health, syncing) = ("/eth/v1/node/health", "/eth/v1/node/syncing");

        // Every node state: not initialised, ready, syncing, optimistic, EL offline, unreachable.
        let mut codes = BTreeSet::new();
        let heads = [
            None,
            Some((WALL_SLOT, false, false)),
            Some((WALL_SLOT - 100, false, false)),
            Some((WALL_SLOT, true, false)),
            Some((WALL_SLOT, false, true)),
        ];
        for head in heads {
            if let Some((head_slot, optimistic, el_offline)) = head {
                node.record_head(ChainHead {
                    head_slot,
                    optimistic,
                    el_offline,
                });
            }
            for uri in [health, "/eth/v1/node/health?syncing_status=200"] {
                codes.insert(
                    check(&spec, &app, health, get(uri), &mut seen)
                        .await
                        .as_u16(),
                );
            }
            check(&spec, &app, syncing, get(syncing), &mut seen).await;
        }
        node.record_unreachable();
        check(&spec, &app, health, get(health), &mut seen).await;
        check(&spec, &app, syncing, get(syncing), &mut seen).await;
        assert_eq!(codes, BTreeSet::from([200, 206, 503]));

        // `syncing_status` follows the parameter's schema: in range is used, out of range is 400.
        let parameter = &spec.root["paths"][health]["get"]["parameters"][0];
        assert_eq!(parameter["name"], "syncing_status");
        node.record_head(ChainHead {
            head_slot: WALL_SLOT - 100,
            optimistic: false,
            el_offline: false,
        });
        for value in [99, 100, 200, 599, 600, 1000] {
            let valid = spec
                .errors(&parameter["schema"], &serde_json::json!(value))
                .is_empty();
            let uri = format!("{health}?syncing_status={value}");
            if valid {
                // The client's own code, listed in the schema or not, and no body.
                let (status, _, body) = request(&app, get(&uri)).await;
                assert_eq!(status.as_u16(), value, "{uri}");
                assert!(body.is_empty(), "{uri}");
            } else {
                let status = check(&spec, &app, health, get(&uri), &mut seen).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            }
        }

        check(
            &spec,
            &app,
            "/eth/v1/node/version",
            get("/eth/v1/node/version"),
            &mut seen,
        )
        .await;

        // The config routes, for each pinned network.
        for network in Network::ALL {
            let state = ApiState {
                node: node.clone(),
                config: Arc::new(ConfigData::new(&ChainConfig::load(network).unwrap()).unwrap()),
            };
            let app = router(state);
            for path in [
                "/eth/v1/config/spec",
                "/eth/v1/config/fork_schedule",
                "/eth/v1/config/deposit_contract",
            ] {
                let status = check(&spec, &app, path, get(path), &mut seen).await;
                assert_eq!(status, StatusCode::OK, "{network} {path}");
            }
        }

        // Errors: an unknown route, another method, an unacceptable type.
        let not_found = check(&spec, &app, "/eth/v1/nope", get("/eth/v1/nope"), &mut seen).await;
        assert_eq!(not_found, StatusCode::NOT_FOUND);
        let post = Request::builder()
            .method(Method::POST)
            .uri(syncing)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            check(&spec, &app, syncing, post, &mut seen).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        let ssz = Request::get(syncing)
            .header(ACCEPT, "application/octet-stream")
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = request(&app, ssz).await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
        let not_acceptable = spec.resolve(&spec.root["components"]["responses"]["NotAcceptable"]);
        let errors = spec.errors(spec.json_schema(not_acceptable).unwrap(), &json(&body));
        assert!(errors.is_empty(), "406: {errors:#?}");

        // Every route of the fixture was checked.
        let paths: BTreeSet<String> = spec.root["paths"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        seen.remove("/eth/v1/nope");
        assert_eq!(seen, paths);
    }
}
