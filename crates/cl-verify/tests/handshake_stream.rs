//! Stream handshake rules on all three RPCs, through a real tonic server: exactly one hello from
//! each side, first; any other opening, a hello mid-stream, or an empty frame is
//! `ERROR_CODE_CONTRACT_VIOLATION`; a handshake that differs is `ERROR_CODE_VERSION_MISMATCH`.

mod common;

use cl_verify::proto::common::{ErrorCode, ForkName};
use cl_verify::proto::verify::{
    PubkeyFeedRequestBody, VerifyBlsRequest, VerifyKzgRequest, VerifyKzgRequestBody,
};
use common::*;

#[tokio::test]
async fn body_before_hello_is_a_contract_violation_on_every_rpc() {
    let mut h = start().await;
    let mut b = bls_raw(&mut h).await;
    b.send(bls_body(bls_request(1, vec![]))).await;
    assert_eq!(
        b.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );

    let mut k = kzg_raw(&mut h).await;
    k.send(kzg_body(VerifyKzgRequestBody::default())).await;
    assert_eq!(
        k.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );

    let mut f = feed_raw(&mut h).await;
    f.send(feed_body(PubkeyFeedRequestBody::default())).await;
    assert_eq!(
        f.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    assert_eq!(h.server.contract_violations(), 3);
}

#[tokio::test]
async fn empty_frame_is_a_contract_violation() {
    let mut h = start().await;
    let mut b = bls_raw(&mut h).await;
    b.send(VerifyBlsRequest { frame: None }).await;
    assert_eq!(
        b.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    let mut k = kzg_open(&mut h).await;
    k.send(VerifyKzgRequest { frame: None }).await;
    assert_eq!(
        k.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn hello_mid_stream_is_a_contract_violation() {
    let mut h = start().await;
    let mut b = bls_open(&mut h).await;
    b.send(bls_hello(hello())).await;
    assert_eq!(
        b.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    let (mut f, _) = feed_open(&mut h).await;
    f.send(feed_hello(hello())).await;
    assert_eq!(
        f.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn closing_before_hello_is_a_contract_violation() {
    let mut h = start().await;
    let mut b = bls_raw(&mut h).await;
    drop(b.tx);
    let status = b.rx.message().await.unwrap_err();
    assert_eq!(
        cl_verify::wire::error_from_status(&status).code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn differing_handshake_is_a_version_mismatch_and_no_hello_is_sent() {
    let mut h = start().await;
    let mut theirs = hello();
    theirs.genesis_validators_root[0] ^= 1;
    let mut b = bls_raw(&mut h).await;
    b.send(bls_hello(theirs)).await;
    let first = b.next().await;
    let status = first.expect_err("no hello frame before the failure");
    assert_eq!(
        cl_verify::wire::error_from_status(&status).code(),
        ErrorCode::VersionMismatch
    );

    let mut future_fork = hello();
    future_fork.fork_schedule[1].epoch += 1;
    let mut k = kzg_raw(&mut h).await;
    k.send(kzg_hello(future_fork)).await;
    assert_eq!(k.expect_failure().await.code(), ErrorCode::VersionMismatch);

    let mut unspecified = hello();
    unspecified.fork_schedule[0].fork = ForkName::Unspecified as i32;
    let mut f = feed_raw(&mut h).await;
    f.send(feed_hello(unspecified)).await;
    assert_eq!(
        f.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}
