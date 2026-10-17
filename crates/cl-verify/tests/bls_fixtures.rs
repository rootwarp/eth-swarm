//! bls12-381-tests v0.1.2 cases (see tests/fixtures/README.md) through the VerifyBls stream.
//! Pubkeys travel inline for indices past the (empty) cache high-water mark.

mod common;

use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::{BlsSet, Signer, VerifyStatus};
use common::*;

const FIRST_INDEX: u64 = 1_000;

fn inline_signers(keys: &[Vec<u8>]) -> Vec<Signer> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| inline(FIRST_INDEX + i as u64, k.clone()))
        .collect()
}

async fn verify(sets: Vec<BlsSet>) -> Vec<Result<VerifyStatus, ErrorCode>> {
    let mut h = start().await;
    let mut s = bls_open(&mut h).await;
    let n = sets.len();
    s.send(bls_body(bls_request(1, sets))).await;
    let r = bls_reply(&mut s).await;
    assert_eq!(r.results.len(), n);
    outcomes(&r)
}

#[tokio::test]
async fn verify_cases() {
    let cases = [
        (
            "verify_valid_case_195246ee3bd3b6ec",
            Ok(VerifyStatus::Valid),
        ),
        // The tampered bytes are not a G2 point, so they fail decoding.
        (
            "verify_tampered_signature_case_195246ee3bd3b6ec",
            Ok(VerifyStatus::DecodeError),
        ),
        (
            "verify_wrong_pubkey_case_195246ee3bd3b6ec",
            Ok(VerifyStatus::Invalid),
        ),
        // The infinity pubkey fails KeyValidate and the infinity signature fails decoding.
        (
            "verify_infinity_pubkey_and_infinity_signature",
            Ok(VerifyStatus::DecodeError),
        ),
    ];
    for (name, want) in cases {
        let f = read_fixture(&format!("bls12-381-tests/verify/{name}.yaml"));
        let set = BlsSet {
            signers: inline_signers(&hexes(&f, "pubkey")),
            signing_root: hexes(&f, "message")[0].clone(),
            signature: hexes(&f, "signature")[0].clone(),
        };
        let got = verify(vec![set]).await;
        assert_eq!(got, vec![want], "{name}");
        assert_eq!(
            got[0] == Ok(VerifyStatus::Valid),
            output(&f) == "true",
            "{name}"
        );
    }
}

#[tokio::test]
async fn fast_aggregate_verify_cases() {
    let cases = [
        (
            "fast_aggregate_verify_valid_3d7576f3c0e3570a",
            Ok(VerifyStatus::Valid),
        ),
        (
            "fast_aggregate_verify_extra_pubkey_4f079f946446fabf",
            Ok(VerifyStatus::Invalid),
        ),
        (
            "fast_aggregate_verify_tampered_signature_3d7576f3c0e3570a",
            Ok(VerifyStatus::DecodeError),
        ),
        (
            // Inline keys come from cl-chain: an invalid one is its contract violation.
            "fast_aggregate_verify_infinity_pubkey",
            Err(ErrorCode::ContractViolation),
        ),
    ];
    for (name, want) in cases {
        let f = read_fixture(&format!(
            "bls12-381-tests/fast_aggregate_verify/{name}.yaml"
        ));
        let set = BlsSet {
            signers: inline_signers(&hexes(&f, "pubkeys")),
            signing_root: hexes(&f, "message")[0].clone(),
            signature: hexes(&f, "signature")[0].clone(),
        };
        let got = verify(vec![set]).await;
        assert_eq!(got, vec![want], "{name}");
        assert_eq!(
            got[0] == Ok(VerifyStatus::Valid),
            output(&f) == "true",
            "{name}"
        );
    }
}

#[tokio::test]
async fn batch_verify_cases() {
    for name in [
        "batch_verify_valid_multiple_signature_set",
        "batch_verify_invalid_forged_signature_set",
        "batch_verify_invalid_infinity_signature_set",
    ] {
        let f = read_fixture(&format!("bls12-381-tests/batch_verify/{name}.yaml"));
        let (pks, msgs, sigs) = (
            hexes(&f, "pubkeys"),
            hexes(&f, "messages"),
            hexes(&f, "signatures"),
        );
        assert_eq!(pks.len(), msgs.len());
        let sets: Vec<BlsSet> = (0..pks.len())
            .map(|i| BlsSet {
                signers: vec![inline(FIRST_INDEX + i as u64, pks[i].clone())],
                signing_root: msgs[i].clone(),
                signature: sigs[i].clone(),
            })
            .collect();
        let got = verify(sets).await;
        let all_valid = got.iter().all(|o| *o == Ok(VerifyStatus::Valid));
        assert_eq!(all_valid, output(&f) == "true", "{name}: {got:?}");
    }
}

#[tokio::test]
async fn forged_pair_fails_both_sets_even_though_their_sum_verifies() {
    // The two forged signatures cancel when summed with equal weights; non-zero random scalars
    // catch that, and the per-set fallback marks each set on its own.
    let f =
        read_fixture("bls12-381-tests/batch_verify/batch_verify_invalid_forged_signature_set.yaml");
    let (pks, msgs, sigs) = (
        hexes(&f, "pubkeys"),
        hexes(&f, "messages"),
        hexes(&f, "signatures"),
    );
    let sets: Vec<BlsSet> = (0..2)
        .map(|i| BlsSet {
            signers: vec![inline(FIRST_INDEX + i as u64, pks[i].clone())],
            signing_root: msgs[i].clone(),
            signature: sigs[i].clone(),
        })
        .collect();
    assert_eq!(verify(sets).await, vec![Ok(VerifyStatus::Invalid); 2]);
}

#[tokio::test]
async fn fast_aggregate_with_no_pubkeys_fails_the_stream() {
    // eth_fast_aggregate_verify accepts zero pubkeys with the infinity signature; on the wire a
    // set with no signers is a request-shape violation, never a verdict.
    let f = read_fixture(
        "bls12-381-tests/fast_aggregate_verify/fast_aggregate_verify_na_pubkeys_and_infinity_signature.yaml",
    );
    assert!(f["pubkeys"].is_empty());
    let set = BlsSet {
        signers: vec![],
        signing_root: hexes(&f, "message")[0].clone(),
        signature: hexes(&f, "signature")[0].clone(),
    };
    let mut h = start().await;
    let mut s = bls_open(&mut h).await;
    s.send(bls_body(bls_request(1, vec![set]))).await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}
