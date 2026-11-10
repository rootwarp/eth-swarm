//! The Engine API encodings, written out by hand from execution-apis `src/engine/common.md`
//! ("Encoding") and the `PayloadStatusV1` structure of `paris.md`.

use consensus_types::primitives::U256;
use engine_api::*;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

fn decodes<T: DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_value(Value::from(s)).ok()
}

#[test]
fn quantity_strips_leading_zeros() {
    let enc = |v: u64| serde_json::to_value(Quantity(v)).unwrap();
    assert_eq!(enc(0), "0x0");
    assert_eq!(enc(1), "0x1");
    assert_eq!(enc(0x10), "0x10");
    assert_eq!(enc(0x0400), "0x400");
    assert_eq!(enc(u64::MAX), "0xffffffffffffffff");

    let enc = |v: U256| serde_json::to_value(Quantity256(v)).unwrap();
    assert_eq!(enc(U256::ZERO), "0x0");
    assert_eq!(enc(U256::from(7u64)), "0x7");
    assert_eq!(
        enc(U256::from(1u64) << 255),
        format!("0x8{}", "0".repeat(63))
    );
    assert_eq!(enc(U256::MAX), format!("0x{}", "f".repeat(64)));
}

#[test]
fn quantity_decoding_is_canonical() {
    assert_eq!(decodes("0x0"), Some(Quantity(0)));
    assert_eq!(decodes("0x400"), Some(Quantity(0x400)));
    // common.md allows either case.
    assert_eq!(decodes("0xAbC"), Some(Quantity(0xabc)));
    assert_eq!(decodes("0xffffffffffffffff"), Some(Quantity(u64::MAX)));
    for bad in [
        "",
        "0",
        "1",
        "0x",
        "0X1",
        "0x00",
        "0x01",
        "0x+1",
        "0x-1",
        "0x 1",
        "0xg",
        "0x10000000000000000",
    ] {
        assert_eq!(decodes::<Quantity>(bad), None, "{bad:?}");
    }
    assert_eq!(
        decodes(&format!("0x1{}", "0".repeat(63))),
        Some(Quantity256(U256::from(1u64) << 252))
    );
    assert_eq!(
        decodes::<Quantity256>(&format!("0x1{}", "0".repeat(64))),
        None
    );
    assert_eq!(decodes::<Quantity256>("0x007"), None);
    // A QUANTITY is a string, never a JSON number.
    assert!(serde_json::from_value::<Quantity>(json!(1)).is_err());
}

#[test]
fn data_is_two_digits_per_byte() {
    assert_eq!(serde_json::to_value(Data(vec![])).unwrap(), "0x");
    assert_eq!(
        serde_json::to_value(Data(vec![0x00, 0xab])).unwrap(),
        "0x00ab"
    );
    assert_eq!(
        serde_json::to_value(FixedData([0xde, 0xad])).unwrap(),
        "0xdead"
    );
    assert_eq!(
        serde_json::to_value(FixedData([0xAB; 20])).unwrap(),
        format!("0x{}", "ab".repeat(20)),
        "lowercase, never checksummed"
    );

    assert_eq!(decodes("0x"), Some(Data(vec![])));
    assert_eq!(decodes("0x00AB"), Some(Data(vec![0x00, 0xab])));
    assert_eq!(decodes("0xdead"), Some(FixedData([0xde, 0xad])));
    for bad in ["", "00", "0x0", "0x123", "0x0x12", "0xzz", "0X00", "0x 0"] {
        assert_eq!(decodes::<Data>(bad), None, "{bad:?}");
    }
    assert_eq!(decodes::<FixedData<2>>("0xde"), None);
    assert_eq!(decodes::<FixedData<2>>("0xdeadbe"), None);
    assert_eq!(decodes::<FixedData<0>>("0x"), Some(FixedData([])));
}

#[test]
fn payload_status_v1_decodes() {
    let hash = format!("0x{}", "77".repeat(32));
    let status: PayloadStatusV1 = serde_json::from_value(
        json!({"status": "VALID", "latestValidHash": hash, "validationError": null}),
    )
    .unwrap();
    assert_eq!(
        status,
        PayloadStatusV1 {
            status: ValidationStatus::Valid,
            latest_valid_hash: Some(FixedData([0x77; 32])),
            validation_error: None,
        }
    );

    let status: PayloadStatusV1 = serde_json::from_value(json!({
        "status": "INVALID", "latestValidHash": null, "validationError": "bad block access list",
    }))
    .unwrap();
    assert_eq!(status.status, ValidationStatus::Invalid);
    assert_eq!(status.latest_valid_hash, None);
    assert_eq!(
        status.validation_error.as_deref(),
        Some("bad block access list")
    );

    // Missing optional fields read as null; a field this version lacks is ignored.
    let status: PayloadStatusV1 =
        serde_json::from_value(json!({"status": "SYNCING", "inclusionListSatisfied": null}))
            .unwrap();
    assert_eq!(status.status, ValidationStatus::Syncing);
    assert_eq!(status.latest_valid_hash, None);

    for (s, want) in [
        ("ACCEPTED", ValidationStatus::Accepted),
        ("INVALID_BLOCK_HASH", ValidationStatus::InvalidBlockHash),
    ] {
        let status: PayloadStatusV1 = serde_json::from_value(json!({ "status": s })).unwrap();
        assert_eq!(status.status, want);
    }
    for bad in [
        json!({"status": "valid"}),
        json!({"status": "UNKNOWN"}),
        json!({"latestValidHash": hash}),
        json!({"status": "VALID", "latestValidHash": "0x77"}),
    ] {
        assert!(
            serde_json::from_value::<PayloadStatusV1>(bad.clone()).is_err(),
            "{bad}"
        );
    }

    // Encoding writes both optional fields, as null when absent.
    let status = PayloadStatusV1 {
        status: ValidationStatus::Syncing,
        latest_valid_hash: None,
        validation_error: None,
    };
    assert_eq!(
        serde_json::to_value(&status).unwrap(),
        json!({"status": "SYNCING", "latestValidHash": null, "validationError": null})
    );
}
