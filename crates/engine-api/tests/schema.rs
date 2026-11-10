//! The emitted JSON against the OpenRPC schema and example vendored from execution-apis
//! (`tests/fixtures/engine_newPayloadV5.json`), and a mock EL that consumes it.

mod common;

use common::*;
use consensus_types::ForkName;
use engine_api::*;
use serde_json::{json, Value};

fn params() -> NewPayloadV5Params {
    new_payload_v5_params(
        &envelope(all_requests()),
        &bid(vec![[0x01; 48], [0x02; 48]]),
    )
}

#[test]
fn fixture_is_the_pinned_method() {
    let pinned = Pinned::load();
    assert_eq!(
        pinned.pin(),
        "ethereum/execution-apis fd2ba6a6139406d13cf28bb97d88008b2f597db3"
    );
    assert_eq!(pinned.method()["name"], methods::NEW_PAYLOAD_V5);
    assert_eq!(
        pinned.method()["name"],
        engine_methods(ForkName::Gloas).new_payload
    );
}

#[test]
fn params_match_pinned_schema() {
    let pinned = Pinned::load();
    let value = serde_json::to_value(params()).unwrap();
    pinned.check_params(&value).unwrap();

    // Exactly the pinned fields, none missing and none extra.
    let schema = pinned.schema("ExecutionPayloadV4");
    let mut want: Vec<&str> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut got: Vec<&str> = value[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    want.sort_unstable();
    got.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(schema["required"].as_array().unwrap().len(), want.len());

    // Empty lists and zero quantities fit too.
    let sparse = new_payload_v5_params(&envelope(no_requests()), &bid(vec![]));
    pinned
        .check_params(&serde_json::to_value(sparse).unwrap())
        .unwrap();
}

#[test]
fn validator_rejects_off_schema_json() {
    let pinned = Pinned::load();
    let good = serde_json::to_value(params()).unwrap();
    let mut cases: Vec<(&str, Value)> = Vec::new();
    let mut v = good.clone();
    v[0]["blockNumber"] = json!("0x0102");
    cases.push(("leading zero", v));
    let mut v = good.clone();
    v[0]["blockHash"] = json!(format!("0x{}", "AB".repeat(32)));
    cases.push(("uppercase hash32", v));
    let mut v = good.clone();
    v[0].as_object_mut().unwrap().remove("slotNumber");
    cases.push(("missing slotNumber", v));
    let mut v = good.clone();
    v[0]["blobsBundle"] = json!(null);
    cases.push(("extra field", v));
    let mut v = good.clone();
    v.as_array_mut().unwrap().pop();
    cases.push(("three params", v));
    for (what, v) in cases {
        assert!(pinned.check_params(&v).is_err(), "{what}");
    }
}

#[test]
fn pinned_example_round_trips() {
    let pinned = Pinned::load();
    let pinned_example = &pinned.example()["params"];

    // The pinned example is not a valid request as written, in two ways the decoder catches:
    // 1. It omits `slotNumber`, which its own schema requires (an EL answers `-32602`).
    let err = pinned.check_params(pinned_example).unwrap_err();
    assert!(err.contains("missing required slotNumber"), "{err}");
    // 2. Its `blockAccessList` has an odd number of hex digits (1091), which `DATA` forbids
    //    (common.md); the OpenRPC `bytes` pattern does not check it.
    let block_access_list = &pinned_example[0]["blockAccessList"];
    assert_eq!(block_access_list.as_str().unwrap().len(), 2 + 1091);
    assert!(serde_json::from_value::<Data>(block_access_list.clone()).is_err());
    let mut example = pinned_example.clone();
    example[0]["blockAccessList"] = json!("0xc0");
    let err = serde_json::from_value::<NewPayloadV5Params>(example.clone()).unwrap_err();
    assert!(err.to_string().contains("slotNumber"), "{err}");

    // With both fixed, every other pinned value fits the schema and re-encodes as pinned.
    example[0]["slotNumber"] = json!("0x1");
    pinned.check_params(&example).unwrap();
    let decoded: NewPayloadV5Params = serde_json::from_value(example.clone()).unwrap();
    assert_eq!(decoded.execution_payload.slot_number, Quantity(1));
    assert_eq!(decoded.execution_payload.block_number, Quantity(0x112720f));
    assert_eq!(decoded.execution_payload.transactions.len(), 3);
    assert_eq!(decoded.execution_payload.withdrawals.len(), 2);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), example);
}

#[test]
fn pinned_example_result_decodes() {
    let pinned = Pinned::load();
    let result = &pinned.example()["result"];
    pinned.check_result(result).unwrap();
    let status: PayloadStatusV1 = serde_json::from_value(result.clone()).unwrap();
    assert_eq!(status.status, ValidationStatus::Valid);
    assert_eq!(status.latest_valid_hash.unwrap().0[..2], [0x35, 0x59]);
    assert_eq!(status.validation_error, None);
    assert_eq!(serde_json::to_value(&status).unwrap(), *result);
}

fn call(el: &mut MockEl, method: &str, params: &NewPayloadV5Params) -> Value {
    let request = serde_json::to_vec(&rpc_request(7, method, params)).unwrap();
    let response: Value = serde_json::from_slice(&el.handle(&request)).unwrap();
    assert_eq!(response["id"], 7);
    response
}

#[test]
fn mock_el_consumes_params_and_answers_scripted_status() {
    let block_hash = format!("0x{}", "77".repeat(32));
    let parent_hash = format!("0x{}", "11".repeat(32));
    let mut el = MockEl::new(vec![
        json!({"status": "VALID", "latestValidHash": block_hash, "validationError": null}),
        json!({"status": "SYNCING", "latestValidHash": null, "validationError": null}),
        json!({"status": "INVALID", "latestValidHash": parent_hash, "validationError": "bad"}),
    ]);
    let method = engine_methods(ForkName::Gloas).new_payload;
    let sent = [
        params(),
        new_payload_v5_params(&envelope(no_requests()), &bid(vec![])),
        params(),
    ];
    let mut statuses = Vec::new();
    for params in &sent {
        let response = call(&mut el, method, params);
        assert!(response.get("error").is_none(), "{response}");
        let status: PayloadStatusV1 = serde_json::from_value(response["result"].clone()).unwrap();
        statuses.push(status);
    }
    assert_eq!(el.received, sent, "the EL decoded what the crate emitted");
    assert_eq!(
        statuses[0],
        PayloadStatusV1 {
            status: ValidationStatus::Valid,
            latest_valid_hash: Some(FixedData([0x77; 32])),
            validation_error: None,
        }
    );
    assert_eq!(statuses[1].status, ValidationStatus::Syncing);
    assert_eq!(statuses[1].latest_valid_hash, None);
    assert_eq!(statuses[2].status, ValidationStatus::Invalid);
    assert_eq!(statuses[2].latest_valid_hash, Some(FixedData([0x11; 32])));
    assert_eq!(statuses[2].validation_error.as_deref(), Some("bad"));
}

#[test]
fn mock_el_refuses_what_the_pin_refuses() {
    let mut el = MockEl::new(vec![]);
    let response = call(&mut el, methods::NEW_PAYLOAD_V4, &params());
    assert_eq!(response["error"]["code"], METHOD_NOT_FOUND);

    // Requests out of type order: `-32602`, before any status is consumed.
    let mut reordered = params();
    reordered.execution_requests.swap(0, 1);
    let response = call(&mut el, methods::NEW_PAYLOAD_V5, &reordered);
    assert_eq!(response["error"]["code"], INVALID_PARAMS, "{response}");

    // A one-byte request (a type with no data).
    let mut bare = params();
    bare.execution_requests = vec![Data(vec![0x00])];
    let response = call(&mut el, methods::NEW_PAYLOAD_V5, &bare);
    assert_eq!(response["error"]["code"], INVALID_PARAMS, "{response}");
    assert!(el.received.is_empty());
}
