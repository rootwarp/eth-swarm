//! `new_payload_v5_params` on hand-built `Minimal` envelopes and bids, and the fork table.

mod common;

use common::*;
use consensus_types::primitives::{KZGCommitment, U256};
use consensus_types::ForkName;
use engine_api::methods::{
    FORKCHOICE_UPDATED_V3, FORKCHOICE_UPDATED_V4, NEW_PAYLOAD_V4, NEW_PAYLOAD_V5,
};
use engine_api::new_payload::{
    BUILDER_DEPOSIT_REQUEST_TYPE, BUILDER_EXIT_REQUEST_TYPE, CONSOLIDATION_REQUEST_TYPE,
    DEPOSIT_REQUEST_TYPE, WITHDRAWAL_REQUEST_TYPE,
};
use engine_api::*;
use serde_json::json;
use ssz_types::ProgressiveVariableList;

/// The compressed G1 point at infinity.
fn infinity() -> KZGCommitment {
    let mut c = [0; 48];
    c[0] = 0xc0;
    c
}

#[test]
fn versioned_hash_known_answer() {
    // sha256(0xc0 || 47 zero bytes) = 5f0657f3...3c444014; the version byte replaces 0x5f.
    let hash = kzg_commitment_to_versioned_hash(&infinity());
    assert_eq!(
        format!("{hash:x}"),
        "010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"
    );
}

#[test]
fn versioned_hashes_from_bid() {
    let commitments = vec![[0x01; 48], infinity(), [0x7f; 48]];
    let params = new_payload_v5_params(&envelope(no_requests()), &bid(commitments.clone()));
    let want: Vec<FixedData<32>> = commitments
        .iter()
        .map(|c| kzg_commitment_to_versioned_hash(c).into())
        .collect();
    assert_eq!(params.expected_blob_versioned_hashes, want);
    for hash in &params.expected_blob_versioned_hashes {
        assert_eq!(hash.0[0], 0x01, "VERSIONED_HASH_VERSION_KZG");
    }

    // Same order as the bid: reversing the commitments reverses the hashes.
    let reversed: Vec<_> = commitments.into_iter().rev().collect();
    let params = new_payload_v5_params(&envelope(no_requests()), &bid(reversed));
    let mut want = want;
    want.reverse();
    assert_eq!(params.expected_blob_versioned_hashes, want);

    let params = new_payload_v5_params(&envelope(no_requests()), &bid(vec![]));
    assert!(params.expected_blob_versioned_hashes.is_empty());
    assert_eq!(serde_json::to_value(&params).unwrap()[1], json!([]));
}

#[test]
fn parent_beacon_block_root_from_envelope() {
    let params = new_payload_v5_params(&envelope(no_requests()), &bid(vec![]));
    assert_eq!(
        params.parent_beacon_block_root,
        FixedData([PARENT_BEACON_BLOCK_ROOT; 32])
    );
}

#[test]
fn payload_fields_carried_over() {
    let params = new_payload_v5_params(&envelope(no_requests()), &bid(vec![]));
    let want = ExecutionPayloadV4 {
        parent_hash: FixedData([0x11; 32]),
        fee_recipient: FixedData([0xab; 20]),
        state_root: FixedData([0x33; 32]),
        receipts_root: FixedData([0x44; 32]),
        logs_bloom: FixedData([0x55; 256]),
        prev_randao: FixedData([0x66; 32]),
        block_number: Quantity(0x0102),
        gas_limit: Quantity(30_000_000),
        gas_used: Quantity(0),
        timestamp: Quantity(0x6553_f100),
        extra_data: Data(b"ethswarm".to_vec()),
        base_fee_per_gas: Quantity256(U256::from(7u64)),
        block_hash: FixedData([0x77; 32]),
        transactions: vec![Data(vec![0x02, 0xf8, 0x6c]), Data(vec![0x03, 0x00])],
        withdrawals: vec![WithdrawalV1 {
            index: Quantity(0xf0),
            validator_index: Quantity(0x10),
            address: FixedData([0x88; 20]),
            amount: Quantity(1),
        }],
        blob_gas_used: Quantity(0x20000),
        excess_blob_gas: Quantity(0),
        block_access_list: Data(vec![0xc0]),
        slot_number: Quantity(9),
    };
    assert_eq!(params.execution_payload, want);
}

#[test]
fn params_serialize_as_four_element_array() {
    let params = new_payload_v5_params(&envelope(all_requests()), &bid(vec![infinity()]));
    let value = serde_json::to_value(&params).unwrap();
    let items = value.as_array().expect("a JSON array");
    assert_eq!(items.len(), 4);
    let payload = &items[0];
    assert_eq!(payload["parentHash"], format!("0x{}", "11".repeat(32)));
    assert_eq!(payload["feeRecipient"], format!("0x{}", "ab".repeat(20)));
    assert_eq!(payload["logsBloom"], format!("0x{}", "55".repeat(256)));
    assert_eq!(payload["blockNumber"], "0x102");
    assert_eq!(payload["gasLimit"], "0x1c9c380");
    assert_eq!(payload["gasUsed"], "0x0");
    assert_eq!(payload["timestamp"], "0x6553f100");
    assert_eq!(payload["extraData"], "0x657468737761726d");
    assert_eq!(payload["baseFeePerGas"], "0x7");
    assert_eq!(payload["transactions"], json!(["0x02f86c", "0x0300"]));
    assert_eq!(
        payload["withdrawals"],
        json!([{
            "index": "0xf0",
            "validatorIndex": "0x10",
            "address": format!("0x{}", "88".repeat(20)),
            "amount": "0x1",
        }])
    );
    assert_eq!(payload["blobGasUsed"], "0x20000");
    assert_eq!(payload["excessBlobGas"], "0x0");
    assert_eq!(payload["blockAccessList"], "0xc0");
    assert_eq!(payload["slotNumber"], "0x9");
    assert_eq!(
        items[1],
        json!(["0x010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"])
    );
    assert_eq!(items[2], format!("0x{}", "aa".repeat(32)));
    assert_eq!(items[3].as_array().unwrap().len(), 5);
}

#[test]
fn empty_requests_omitted() {
    let params = new_payload_v5_params(&envelope(no_requests()), &bid(vec![]));
    assert!(params.execution_requests.is_empty());
    assert_eq!(serde_json::to_value(&params).unwrap()[3], json!([]));
    assert!(get_execution_requests_list(&no_requests()).is_empty());

    // Only the non-empty groups appear, still in type order.
    let mut requests = no_requests();
    requests.withdrawals = ProgressiveVariableList::new(vec![withdrawal_request(2)]).unwrap();
    requests.builder_exits = ProgressiveVariableList::new(vec![builder_exit(5)]).unwrap();
    let list = get_execution_requests_list(&requests);
    let types: Vec<u8> = list.iter().map(|r| r[0]).collect();
    assert_eq!(types, [WITHDRAWAL_REQUEST_TYPE, BUILDER_EXIT_REQUEST_TYPE]);
}

/// `Address::repeat_byte(i)`, `[i; 48]` and friends, as the fixtures build them.
fn rep(byte: u8, n: usize) -> Vec<u8> {
    vec![byte; n]
}

#[test]
fn builder_requests_encoded() {
    let mut requests = no_requests();
    requests.builder_deposits =
        ProgressiveVariableList::new(vec![builder_deposit(4), builder_deposit(6)]).unwrap();
    requests.builder_exits = ProgressiveVariableList::new(vec![builder_exit(5)]).unwrap();
    let params = new_payload_v5_params(&envelope(requests), &bid(vec![]));

    // BuilderDepositRequest: pubkey, withdrawal_credentials, amount (u64 LE), signature.
    let mut deposits = vec![BUILDER_DEPOSIT_REQUEST_TYPE];
    for i in [4, 6] {
        deposits.extend(rep(i, 48));
        deposits.extend(rep(i, 32));
        deposits.extend(1_000_000_000u64.to_le_bytes());
        deposits.extend(rep(i, 96));
    }
    // BuilderExitRequest: source_address, pubkey.
    let mut exits = vec![BUILDER_EXIT_REQUEST_TYPE];
    exits.extend(rep(5, 20));
    exits.extend(rep(5, 48));

    assert_eq!(params.execution_requests, [Data(deposits), Data(exits)]);
    assert_eq!(BUILDER_DEPOSIT_REQUEST_TYPE, 0x03);
    assert_eq!(BUILDER_EXIT_REQUEST_TYPE, 0x04);
}

#[test]
fn every_request_group_in_type_order() {
    let list = get_execution_requests_list(&all_requests());

    let mut deposit = vec![DEPOSIT_REQUEST_TYPE];
    deposit.extend(rep(1, 48));
    deposit.extend(rep(1, 32));
    deposit.extend(32_000_000_000u64.to_le_bytes());
    deposit.extend(rep(1, 96));
    deposit.extend(1u64.to_le_bytes());

    let mut withdrawal = vec![WITHDRAWAL_REQUEST_TYPE];
    withdrawal.extend(rep(2, 20));
    withdrawal.extend(rep(2, 48));
    withdrawal.extend(2u64.to_le_bytes());

    let mut consolidation = vec![CONSOLIDATION_REQUEST_TYPE];
    consolidation.extend(rep(3, 20));
    consolidation.extend(rep(3, 48));
    consolidation.extend(rep(3 ^ 0xff, 48));

    let types: Vec<u8> = list.iter().map(|r| r[0]).collect();
    assert_eq!(types, [0x00, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(list[0], deposit);
    assert_eq!(list[1], withdrawal);
    assert_eq!(list[2], consolidation);
    assert_eq!(list[3].len(), 1 + 48 + 32 + 8 + 96);
    assert_eq!(list[4].len(), 1 + 20 + 48);
}

#[test]
fn gloas_selects_new_payload_v5_and_forkchoice_updated_v4() {
    let gloas = engine_methods(ForkName::Gloas);
    assert_eq!(gloas.new_payload, "engine_newPayloadV5");
    assert_eq!(gloas.forkchoice_updated, "engine_forkchoiceUpdatedV4");
    assert_eq!(gloas.new_payload, NEW_PAYLOAD_V5);
    assert_eq!(gloas.forkchoice_updated, FORKCHOICE_UPDATED_V4);

    // Only Gloas uses the Amsterdam methods, and Gloas uses nothing else.
    for fork in ForkName::ALL {
        let methods = engine_methods(fork);
        let amsterdam = methods.new_payload == NEW_PAYLOAD_V5;
        assert_eq!(amsterdam, fork == ForkName::Gloas, "{fork:?}");
        assert_eq!(
            methods.forkchoice_updated == FORKCHOICE_UPDATED_V4,
            fork == ForkName::Gloas
        );
    }
    let fulu = engine_methods(ForkName::Fulu);
    assert_eq!(fulu.new_payload, NEW_PAYLOAD_V4);
    assert_eq!(fulu.forkchoice_updated, FORKCHOICE_UPDATED_V3);
}
