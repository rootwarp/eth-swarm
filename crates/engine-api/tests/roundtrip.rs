//! Serializing then deserializing is the identity.

use consensus_types::primitives::U256;
use engine_api::*;
use proptest::collection::vec;
use proptest::prelude::*;

fn fixed<const N: usize>() -> impl Strategy<Value = FixedData<N>> {
    vec(any::<u8>(), N).prop_map(|b| FixedData(b.try_into().unwrap()))
}

fn data(max: usize) -> impl Strategy<Value = Data> {
    vec(any::<u8>(), 0..=max).prop_map(Data)
}

/// Shifted right by a random amount, so short encodings (and zero) come up often.
fn quantity() -> impl Strategy<Value = Quantity> {
    (any::<u64>(), 0..=64u32).prop_map(|(v, shift)| Quantity(v.checked_shr(shift).unwrap_or(0)))
}

fn quantity256() -> impl Strategy<Value = Quantity256> {
    (any::<[u8; 32]>(), 0..256usize)
        .prop_map(|(b, shift)| Quantity256(U256::from_be_bytes(b) >> shift))
}

fn withdrawal() -> impl Strategy<Value = WithdrawalV1> {
    (quantity(), quantity(), fixed::<20>(), quantity()).prop_map(
        |(index, validator_index, address, amount)| WithdrawalV1 {
            index,
            validator_index,
            address,
            amount,
        },
    )
}

fn payload() -> impl Strategy<Value = ExecutionPayloadV4> {
    let head = (
        fixed::<32>(),
        fixed::<20>(),
        fixed::<32>(),
        fixed::<32>(),
        fixed::<256>(),
        fixed::<32>(),
        quantity(),
        quantity(),
        quantity(),
        quantity(),
    );
    let tail = (
        data(32),
        quantity256(),
        fixed::<32>(),
        vec(data(64), 0..4),
        vec(withdrawal(), 0..4),
        quantity(),
        quantity(),
        data(96),
        quantity(),
    );
    (head, tail).prop_map(|(h, t)| ExecutionPayloadV4 {
        parent_hash: h.0,
        fee_recipient: h.1,
        state_root: h.2,
        receipts_root: h.3,
        logs_bloom: h.4,
        prev_randao: h.5,
        block_number: h.6,
        gas_limit: h.7,
        gas_used: h.8,
        timestamp: h.9,
        extra_data: t.0,
        base_fee_per_gas: t.1,
        block_hash: t.2,
        transactions: t.3,
        withdrawals: t.4,
        blob_gas_used: t.5,
        excess_blob_gas: t.6,
        block_access_list: t.7,
        slot_number: t.8,
    })
}

proptest! {
    #[test]
    fn roundtrip_execution_payload_v4(payload in payload()) {
        let json = serde_json::to_string(&payload).unwrap();
        let back: ExecutionPayloadV4 = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, payload);
    }

    #[test]
    fn roundtrip_new_payload_v5_params(
        execution_payload in payload(),
        expected_blob_versioned_hashes in vec(fixed::<32>(), 0..4),
        parent_beacon_block_root in fixed::<32>(),
        execution_requests in vec(data(64), 0..4),
    ) {
        let params = NewPayloadV5Params {
            execution_payload,
            expected_blob_versioned_hashes,
            parent_beacon_block_root,
            execution_requests,
        };
        let json = serde_json::to_vec(&params).unwrap();
        let back: NewPayloadV5Params = serde_json::from_slice(&json).unwrap();
        prop_assert_eq!(back, params);
    }

    #[test]
    fn roundtrip_payload_status_v1(
        status in prop::sample::select(vec![
            ValidationStatus::Valid,
            ValidationStatus::Invalid,
            ValidationStatus::Syncing,
            ValidationStatus::Accepted,
            ValidationStatus::InvalidBlockHash,
        ]),
        latest_valid_hash in proptest::option::of(fixed::<32>()),
        validation_error in proptest::option::of(".{0,16}"),
    ) {
        let status = PayloadStatusV1 { status, latest_valid_hash, validation_error };
        let json = serde_json::to_string(&status).unwrap();
        let back: PayloadStatusV1 = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, status);
    }
}
