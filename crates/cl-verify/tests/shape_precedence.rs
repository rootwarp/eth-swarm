//! Request-shape violations fail the stream with CONTRACT_VIOLATION, and they are checked before
//! the deadline: a malformed request with a zero or expired deadline is still a contract
//! violation, never DEADLINE_EXCEEDED, so a cl-chain bug is not hidden.

mod common;

use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::{BlsSet, VerifyBlsRequestBody, VerifyKzgRequestBody, VerifyOrigin};
use cl_verify::wire::now_unix_ms;
use common::*;

fn shapes() -> Vec<(&'static str, VerifyBlsRequestBody)> {
    let mut no_signers = valid_set(0, 1);
    no_signers.signers.clear();
    let gossip_inline = signed_set(vec![inline(9, pk_bytes(9))], &[9], 2);
    let many_inline = |root| -> BlsSet {
        signed_set(
            (0..600u64)
                .map(|i| inline(1_000 + i, pk_bytes(100)))
                .collect(),
            &[100; 600],
            root,
        )
    };
    vec![
        (
            "zero signers",
            bls_request(1, vec![valid_set(0, 1), no_signers]),
        ),
        (
            "gossip inline",
            bls_request_from(1, vec![gossip_inline], VerifyOrigin::Gossip),
        ),
        (
            "unspecified origin",
            bls_request_from(1, vec![valid_set(0, 1)], VerifyOrigin::Unspecified),
        ),
        ("257 sets", bls_request(1, vec![valid_set(0, 1); 257])),
        (
            "inline cap across sets",
            bls_request(1, vec![many_inline(3), many_inline(4)]),
        ),
    ]
}

#[tokio::test]
async fn bls_shape_violation_wins_over_a_zero_or_expired_deadline() {
    let mut h = start_with(Options {
        cache: cache_of(2),
        ..Options::default()
    })
    .await;
    for deadline in [0, now_unix_ms() - 1] {
        for (name, mut body) in shapes() {
            body.deadline_unix_ms = deadline;
            let mut s = bls_open(&mut h).await;
            s.send(bls_body(body)).await;
            let err = s.expect_failure().await;
            assert_eq!(
                err.code(),
                ErrorCode::ContractViolation,
                "{name} @ {deadline}"
            );
        }
    }
}

#[tokio::test]
async fn empty_kzg_request_wins_over_a_zero_deadline() {
    let mut h = start().await;
    let mut s = kzg_open(&mut h).await;
    s.send(kzg_body(VerifyKzgRequestBody {
        request_id: 1,
        cells: vec![],
        deadline_unix_ms: 0,
        generation: 0,
    }))
    .await;
    assert_eq!(
        s.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}
