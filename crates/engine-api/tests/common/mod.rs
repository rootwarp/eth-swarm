//! Shared test support: hand-built `Minimal` envelopes and bids, a validator for the vendored
//! OpenRPC fixture, and a mock EL that answers `engine_newPayloadV5` over JSON-RPC bytes.
#![allow(dead_code)]

use consensus_types::gloas::{
    BuilderDepositRequest, BuilderExitRequest, ConsolidationRequest, DepositRequest,
    ExecutionPayload, ExecutionPayloadBid, ExecutionPayloadEnvelope, ExecutionRequests,
    WithdrawalRequest,
};
use consensus_types::primitives::{Address, KZGCommitment, B256, U256};
use consensus_types::Minimal;
use consensus_types::{common::Withdrawal, gloas::Transaction};
use engine_api::{methods, NewPayloadV5Params};
use regex::Regex;
use serde_json::{json, Value};
use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};
use std::collections::VecDeque;

pub type E = Minimal;

/// The envelope's `parent_beacon_block_root`.
pub const PARENT_BEACON_BLOCK_ROOT: u8 = 0xaa;

fn list<T, N: typenum::Unsigned>(items: Vec<T>) -> ProgressiveVariableList<T, N> {
    ProgressiveVariableList::new(items).expect("within the list bound")
}

/// A payload with a distinct value in every field.
pub fn payload() -> ExecutionPayload<E> {
    ExecutionPayload {
        parent_hash: B256::repeat_byte(0x11),
        fee_recipient: Address::repeat_byte(0xab),
        state_root: B256::repeat_byte(0x33),
        receipts_root: B256::repeat_byte(0x44),
        logs_bloom: FixedVector::from_elem(0x55),
        prev_randao: B256::repeat_byte(0x66),
        block_number: 0x0102,
        gas_limit: 30_000_000,
        gas_used: 0,
        timestamp: 0x6553_f100,
        extra_data: VariableList::new(b"ethswarm".to_vec()).unwrap(),
        base_fee_per_gas: U256::from(7u64),
        block_hash: B256::repeat_byte(0x77),
        transactions: list(vec![
            Transaction::new(vec![0x02, 0xf8, 0x6c]).unwrap(),
            Transaction::new(vec![0x03, 0x00]).unwrap(),
        ]),
        withdrawals: list(vec![Withdrawal {
            index: 0xf0,
            validator_index: 0x10,
            address: Address::repeat_byte(0x88),
            amount: 1,
        }]),
        blob_gas_used: 0x20000,
        excess_blob_gas: 0,
        // The RLP encoding of an empty list.
        block_access_list: list(vec![0xc0]),
        slot_number: 9,
    }
}

pub fn no_requests() -> ExecutionRequests<E> {
    ExecutionRequests {
        deposits: list(vec![]),
        withdrawals: list(vec![]),
        consolidations: list(vec![]),
        builder_deposits: list(vec![]),
        builder_exits: list(vec![]),
    }
}

pub fn deposit(i: u8) -> DepositRequest {
    DepositRequest {
        pubkey: [i; 48],
        withdrawal_credentials: B256::repeat_byte(i),
        amount: 32_000_000_000,
        signature: [i; 96],
        index: u64::from(i),
    }
}

pub fn withdrawal_request(i: u8) -> WithdrawalRequest {
    WithdrawalRequest {
        source_address: Address::repeat_byte(i),
        validator_pubkey: [i; 48],
        amount: u64::from(i),
    }
}

pub fn consolidation(i: u8) -> ConsolidationRequest {
    ConsolidationRequest {
        source_address: Address::repeat_byte(i),
        source_pubkey: [i; 48],
        target_pubkey: [i ^ 0xff; 48],
    }
}

pub fn builder_deposit(i: u8) -> BuilderDepositRequest {
    BuilderDepositRequest {
        pubkey: [i; 48],
        withdrawal_credentials: B256::repeat_byte(i),
        amount: 1_000_000_000,
        signature: [i; 96],
    }
}

pub fn builder_exit(i: u8) -> BuilderExitRequest {
    BuilderExitRequest {
        source_address: Address::repeat_byte(i),
        pubkey: [i; 48],
    }
}

/// One request of every type.
pub fn all_requests() -> ExecutionRequests<E> {
    ExecutionRequests {
        deposits: list(vec![deposit(1)]),
        withdrawals: list(vec![withdrawal_request(2)]),
        consolidations: list(vec![consolidation(3)]),
        builder_deposits: list(vec![builder_deposit(4)]),
        builder_exits: list(vec![builder_exit(5)]),
    }
}

pub fn envelope(execution_requests: ExecutionRequests<E>) -> ExecutionPayloadEnvelope<E> {
    ExecutionPayloadEnvelope {
        payload: payload(),
        execution_requests,
        builder_index: 3,
        beacon_block_root: B256::repeat_byte(0xbb),
        parent_beacon_block_root: B256::repeat_byte(PARENT_BEACON_BLOCK_ROOT),
    }
}

/// The bid `envelope` commits to. Its `parent_block_root` differs from the envelope's
/// `parent_beacon_block_root`, so a test can tell which one the params use.
pub fn bid(commitments: Vec<KZGCommitment>) -> ExecutionPayloadBid<E> {
    let payload = payload();
    ExecutionPayloadBid {
        parent_block_hash: payload.parent_hash,
        parent_block_root: B256::repeat_byte(0xcc),
        block_hash: payload.block_hash,
        prev_randao: payload.prev_randao,
        fee_recipient: payload.fee_recipient,
        gas_limit: payload.gas_limit,
        builder_index: 3,
        slot: payload.slot_number,
        value: 0,
        execution_payment: 0,
        blob_kzg_commitments: list(commitments),
        execution_requests_root: B256::ZERO,
    }
}

/// A JSON-RPC request for `params`, as cl-engine sends it.
pub fn rpc_request(id: u64, method: &str, params: &NewPayloadV5Params) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// The vendored execution-apis fixture (`tests/fixtures/engine_newPayloadV5.json`), with a
/// validator for the subset of JSON Schema it uses: `$ref`, `type`, `required`, `properties`,
/// `items`, `pattern` and `enum`.
///
/// It is stricter than JSON Schema in one way: an object property the schema does not define
/// is an error, so an encoder cannot emit a field the pin lacks. A `null` passes for an optional
/// property: `PayloadStatusV1` sends `latestValidHash` and `validationError` as `null`
/// (`paris.md`), which the OpenRPC schema writes as an optional string.
pub struct Pinned {
    doc: Value,
}

impl Pinned {
    pub fn load() -> Self {
        let doc = serde_json::from_str(include_str!("../fixtures/engine_newPayloadV5.json"))
            .expect("fixture is JSON");
        Self { doc }
    }

    pub fn pin(&self) -> &str {
        self.doc["pin"].as_str().unwrap()
    }

    pub fn method(&self) -> &Value {
        &self.doc["method"]
    }

    pub fn example(&self) -> &Value {
        &self.doc["method"]["examples"][0]
    }

    pub fn schema(&self, name: &str) -> &Value {
        &self.doc["components"]["schemas"][name]
    }

    /// Checks a whole `params` array against the method's param schemas.
    pub fn check_params(&self, params: &Value) -> Result<(), String> {
        let specs = self.method()["params"].as_array().unwrap();
        let params = params.as_array().ok_or("params: not an array")?;
        if params.len() != specs.len() {
            return Err(format!(
                "params: {} items, want {}",
                params.len(),
                specs.len()
            ));
        }
        for (spec, param) in specs.iter().zip(params) {
            self.check(&spec["schema"], param, spec["name"].as_str().unwrap())?;
        }
        Ok(())
    }

    pub fn check_result(&self, result: &Value) -> Result<(), String> {
        self.check(&self.method()["result"]["schema"], result, "result")
    }

    pub fn check(&self, schema: &Value, value: &Value, at: &str) -> Result<(), String> {
        if let Some(target) = schema.get("$ref") {
            let name = target.as_str().unwrap();
            let name = name
                .strip_prefix("#/components/schemas/")
                .expect("local ref");
            let resolved = self.schema(name);
            assert!(!resolved.is_null(), "fixture lacks schema {name}");
            return self.check(resolved, value, &format!("{at} ({name})"));
        }
        match schema["type"].as_str() {
            Some("object") => {
                let object = value.as_object().ok_or(format!("{at}: not an object"))?;
                let required: Vec<&str> = schema["required"]
                    .as_array()
                    .map(|r| r.iter().map(|k| k.as_str().unwrap()).collect())
                    .unwrap_or_default();
                for key in &required {
                    if !object.contains_key(*key) {
                        return Err(format!("{at}: missing required {key}"));
                    }
                }
                for (key, item) in object {
                    let property = schema["properties"]
                        .get(key)
                        .ok_or(format!("{at}: {key} is not in the schema"))?;
                    if item.is_null() && !required.contains(&key.as_str()) {
                        continue;
                    }
                    self.check(property, item, &format!("{at}.{key}"))?;
                }
                Ok(())
            }
            Some("array") => {
                let items = value.as_array().ok_or(format!("{at}: not an array"))?;
                for (i, item) in items.iter().enumerate() {
                    self.check(&schema["items"], item, &format!("{at}[{i}]"))?;
                }
                Ok(())
            }
            Some("string") => {
                let s = value.as_str().ok_or(format!("{at}: not a string"))?;
                if let Some(pattern) = schema["pattern"].as_str() {
                    if !Regex::new(pattern).unwrap().is_match(s) {
                        return Err(format!("{at}: {s:?} does not match {pattern}"));
                    }
                }
                if let Some(allowed) = schema["enum"].as_array() {
                    if !allowed.iter().any(|a| a == value) {
                        return Err(format!("{at}: {s:?} is not one of {allowed:?}"));
                    }
                }
                Ok(())
            }
            other => panic!("{at}: schema type {other:?} is not used by the fixture"),
        }
    }
}

/// `-32601: Method not found`.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// `-32602: Invalid params`.
pub const INVALID_PARAMS: i64 = -32602;

/// A mock EL serving `engine_newPayloadV5` over JSON-RPC bytes. It checks each request against
/// the pinned schema and the `executionRequests` rules of `prague.md` (one element per type,
/// types ascending, each longer than one byte), records the params it decoded, and answers with
/// the next scripted `PayloadStatusV1`.
pub struct MockEl {
    pinned: Pinned,
    script: VecDeque<Value>,
    pub received: Vec<NewPayloadV5Params>,
}

impl MockEl {
    pub fn new(script: Vec<Value>) -> Self {
        Self {
            pinned: Pinned::load(),
            script: script.into(),
            received: Vec::new(),
        }
    }

    pub fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        let request: Value = serde_json::from_slice(request).expect("request is JSON");
        let outcome = self.serve(&request);
        let mut response = json!({"jsonrpc": "2.0", "id": request["id"]});
        match outcome {
            Ok(result) => response["result"] = result,
            Err((code, message)) => response["error"] = json!({"code": code, "message": message}),
        }
        serde_json::to_vec(&response).unwrap()
    }

    fn serve(&mut self, request: &Value) -> Result<Value, (i64, String)> {
        assert_eq!(request["jsonrpc"], "2.0");
        if request["method"] != methods::NEW_PAYLOAD_V5 {
            return Err((METHOD_NOT_FOUND, format!("{}", request["method"])));
        }
        let params = &request["params"];
        let invalid = |e: String| (INVALID_PARAMS, e);
        self.pinned.check_params(params).map_err(invalid)?;
        check_request_order(&params[3]).map_err(invalid)?;
        let decoded = serde_json::from_value(params.clone()).map_err(|e| invalid(e.to_string()))?;
        self.received.push(decoded);
        let result = self.script.pop_front().expect("a scripted status per call");
        self.pinned
            .check_result(&result)
            .expect("scripted status fits the pin");
        Ok(result)
    }
}

/// `prague.md` `executionRequests`: each element longer than one byte, types strictly
/// ascending. Read off the hex string, independently of the crate's decoder.
fn check_request_order(requests: &Value) -> Result<(), String> {
    let mut last: Option<u8> = None;
    for request in requests.as_array().unwrap() {
        let s = request.as_str().unwrap();
        if s.len() <= 4 {
            return Err(format!("request {s} is one byte or shorter"));
        }
        let request_type = u8::from_str_radix(&s[2..4], 16).map_err(|e| e.to_string())?;
        if last.is_some_and(|l| l >= request_type) {
            return Err(format!("request type {request_type:#04x} out of order"));
        }
        last = Some(request_type);
    }
    Ok(())
}
