//! Tests of the VerifyBls side of the verify.v1 client: the caps of each request, the verdict
//! of an answer, and the stream of a call without an answer.

use super::*;
use crate::testing::{Stub, StubVerify};
use ethswarm_proto::common::Error as WireError;
use ethswarm_proto::verify::{
    bls_result, BlsResult, BlsSet, KeyNamespace, Signer, VerifyBlsResponseBody,
};

/// A set of `signers` validator signers. Each signer carries a key inline if `inline` is true.
fn set(signers: u64, inline: bool) -> BlsSet {
    BlsSet {
        signers: (0..signers)
            .map(|validator_index| Signer {
                validator_index,
                inline_pubkey: if inline { vec![0xa0; 48] } else { Vec::new() },
                namespace: KeyNamespace::Validator as i32,
                builder: None,
            })
            .collect(),
        signing_root: vec![0; 32],
        signature: vec![0; 96],
    }
}

/// The number of sets in each request.
fn sizes(requests: &[Vec<BlsSet>]) -> Vec<usize> {
    requests.iter().map(Vec::len).collect()
}

/// A response with one result of each status.
fn answer(statuses: &[VerifyStatus]) -> VerifyBlsResponseBody {
    VerifyBlsResponseBody {
        request_id: 1,
        results: statuses
            .iter()
            .map(|status| BlsResult {
                result: Some(bls_result::Result::Status(*status as i32)),
                fence: None,
            })
            .collect(),
    }
}

#[test]
fn the_caps_are_the_caps_of_cl_verify() {
    assert_eq!(MAX_BLS_SETS, cl_verify::caps::MAX_BLS_SETS);
    assert_eq!(MAX_BLS_SIGNERS, cl_verify::caps::MAX_SIGNERS_PER_REQUEST);
    assert_eq!(MAX_INLINE_KEYS, cl_verify::caps::MAX_INLINE_KEYS_PER_BATCH);
    assert_eq!(MAX_BLS_MESSAGE_BYTES, cl_verify::caps::MAX_MESSAGE_BYTES);
}

#[test]
fn a_batch_over_256_sets_splits_in_order() {
    let sets: Vec<BlsSet> = (0..600)
        .map(|index| {
            let mut one = set(1, false);
            one.signers[0].validator_index = index;
            one
        })
        .collect();
    let requests = bls_requests(sets.clone()).unwrap();
    assert_eq!(sizes(&requests), vec![256, 256, 88]);
    assert_eq!(
        requests.concat(),
        sets,
        "the split must keep each set in order"
    );
}

#[test]
fn inline_keys_split_at_1024_and_a_lone_set_can_carry_more() {
    let sets = vec![
        set(500, true),
        set(500, true),
        set(500, true),
        set(2_000, true),
        set(1, true),
    ];
    assert_eq!(sizes(&bls_requests(sets).unwrap()), vec![2, 1, 1, 1]);
}

#[test]
fn signers_split_at_131072() {
    let sets = vec![set(100_000, false), set(40_000, false), set(1, false)];
    assert_eq!(sizes(&bls_requests(sets).unwrap()), vec![1, 2]);
}

#[test]
fn a_set_over_the_message_cap_refuses_the_whole_batch() {
    // 80,000 inline keys do not fit in 4 MiB.
    let refused = bls_requests(vec![set(1, true), set(80_000, true)]);
    assert!(refused.is_err(), "no part of the batch must go out");
}

#[test]
fn an_empty_batch_is_no_request() {
    assert!(bls_requests(Vec::new()).is_err());
}

#[test]
fn only_valid_for_each_set_is_valid() {
    use VerifyStatus::{
        DeadlineExceeded, DecodeError, Invalid, Overloaded, UnknownIndex, Unspecified, Valid,
    };
    assert_eq!(bls_outcome(&answer(&[Valid, Valid])), BlsOutcome::Valid);
    assert_eq!(bls_outcome(&answer(&[Valid, Invalid])), BlsOutcome::Invalid);
    assert_eq!(
        bls_outcome(&answer(&[UnknownIndex, DecodeError])),
        BlsOutcome::Invalid,
        "a proof in one set must win over no verdict in another"
    );
    for status in [UnknownIndex, DeadlineExceeded, Overloaded, Unspecified] {
        assert!(
            matches!(
                bls_outcome(&answer(&[Valid, status])),
                BlsOutcome::NoVerdict(_)
            ),
            "{status:?}"
        );
    }
    let mut unknown = answer(&[Valid]);
    unknown.results[0].result = Some(bls_result::Result::Status(99));
    assert!(matches!(bls_outcome(&unknown), BlsOutcome::NoVerdict(_)));
    let mut err = answer(&[Valid]);
    err.results[0].result = Some(bls_result::Result::Err(WireError::default()));
    assert!(matches!(bls_outcome(&err), BlsOutcome::NoVerdict(_)));
    let mut empty = answer(&[Valid]);
    empty.results[0].result = None;
    assert!(matches!(bls_outcome(&empty), BlsOutcome::NoVerdict(_)));
    assert!(matches!(
        bls_outcome(&answer(&[])),
        BlsOutcome::NoVerdict(_)
    ));
}

#[tokio::test]
async fn a_silent_cl_verify_is_no_verdict_and_its_stream_closes() {
    let served = StubVerify::start(Stub::Silent);
    let client = served.bls_client().await;
    let timeout = Duration::from_millis(50);
    let outcome = client.verify_sets(vec![set(1, true)], timeout).await;
    assert_eq!(
        outcome,
        BlsOutcome::NoVerdict("no verdict by the deadline".into())
    );
    assert_eq!(served.streams_opened(), 1);
    // The stream of the late call is gone: the next call opens a new one.
    let outcome = client.verify_sets(vec![set(1, true)], timeout).await;
    assert!(matches!(outcome, BlsOutcome::NoVerdict(_)), "{outcome:?}");
    assert_eq!(
        served.streams_opened(),
        2,
        "a VerifyBls stream without an answer by the deadline must close"
    );
}
