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
    let outcome = client
        .verify_sets(vec![set(1, true)], Instant::now() + timeout)
        .await;
    assert_eq!(
        outcome,
        BlsOutcome::NoVerdict("no verdict by the deadline".into())
    );
    assert_eq!(served.streams_opened(), 1);
    // The stream of the late call is gone: the next call opens a new one.
    let outcome = client
        .verify_sets(vec![set(1, true)], Instant::now() + timeout)
        .await;
    assert!(matches!(outcome, BlsOutcome::NoVerdict(_)), "{outcome:?}");
    assert_eq!(
        served.streams_opened(),
        2,
        "a VerifyBls stream without an answer by the deadline must close"
    );
}

/// Polls `call` until its request is in the outstanding table of `link`, then drops it.
async fn drop_after_send<F: Future>(link: &StreamLink<Bls>, call: F)
where
    F::Output: std::fmt::Debug,
{
    let mut call = std::pin::pin!(call);
    let sent = async {
        while link.calls.outstanding() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::select! {
        outcome = &mut call => panic!("the call must wait for its verdict: {outcome:?}"),
        () = sent => {}
    }
}

#[tokio::test]
async fn a_call_dropped_after_its_send_closes_its_stream_and_frees_its_slot() {
    let served = StubVerify::start(Stub::Silent);
    let client = served.bls_client().await;
    let long = Duration::from_secs(60);
    for dropped in 1..=DEFAULT_MAX_OUTSTANDING + 1 {
        let link = client.streams.live().await.unwrap();
        let call = client.verify_sets(vec![set(1, true)], Instant::now() + long);
        drop_after_send(&link, call).await;
        assert_eq!(
            link.calls.outstanding(),
            0,
            "call {dropped}: a dropped call must not keep its slot"
        );
        assert!(
            link.requests.is_closed(),
            "call {dropped}: a dropped call must close its stream"
        );
    }
    assert_eq!(served.streams_opened(), DEFAULT_MAX_OUTSTANDING + 1);
    let outcome = client
        .verify_sets(
            vec![set(1, true)],
            Instant::now() + Duration::from_millis(50),
        )
        .await;
    assert_eq!(
        outcome,
        BlsOutcome::NoVerdict(LATE.into()),
        "the next call must have room in the window"
    );
}

#[tokio::test]
async fn the_requests_of_one_batch_share_its_deadline() {
    // 600 sets go out as three requests (256, 256 and 88 sets), one after the other. The stub
    // answers each one after `wait`.
    let wait = Duration::from_millis(200);
    let served = StubVerify::start(Stub::ValidAfter(wait));
    let client = served.bls_client().await;
    let sets: Vec<BlsSet> = (0..600)
        .map(|index| {
            let mut one = set(1, false);
            one.signers[0].validator_index = index;
            one
        })
        .collect();
    // The third answer comes after the deadline: a request must not get a new deadline.
    let outcome = client
        .verify_sets(sets.clone(), Instant::now() + wait * 5 / 2)
        .await;
    assert_eq!(outcome, BlsOutcome::NoVerdict(LATE.into()));
    // With room for the three answers, the batch is valid.
    let outcome = client.verify_sets(sets, Instant::now() + wait * 6).await;
    assert_eq!(outcome, BlsOutcome::Valid);
    assert_eq!(
        served.bls_requests(),
        6,
        "each batch must go out as three requests"
    );
}

#[tokio::test]
async fn an_expired_deadline_sends_nothing_and_keeps_the_stream() {
    let served = StubVerify::start(Stub::ValidAfter(Duration::from_millis(1)));
    let client = served.bls_client().await;
    let long = Duration::from_secs(10);
    let outcome = client
        .verify_sets(vec![set(1, true)], Instant::now() + long)
        .await;
    assert_eq!(outcome, BlsOutcome::Valid);
    let link = client.streams.live().await.unwrap();
    let now = Instant::now();
    tokio::time::sleep(Duration::from_millis(2)).await;
    for deadline in [Instant::now(), now] {
        let outcome = client.verify_sets(vec![set(1, true)], deadline).await;
        assert_eq!(
            outcome,
            BlsOutcome::NoVerdict(LATE.into()),
            "a call out of time must be no verdict"
        );
    }
    assert!(
        !link.requests.is_closed(),
        "a call out of time must not close a healthy stream"
    );
    let outcome = client
        .verify_sets(vec![set(1, true)], Instant::now() + long)
        .await;
    assert_eq!(outcome, BlsOutcome::Valid, "the stream must still serve");
    assert_eq!(served.streams_opened(), 1);
    assert_eq!(
        served.bls_requests(),
        2,
        "a call out of time must send no request"
    );
}

/// Polls `call` `polls` times, each time finding it still waiting, then drops it.
async fn drop_while_pending<F: Future>(call: F, polls: usize)
where
    F::Output: std::fmt::Debug,
{
    let mut call = std::pin::pin!(call);
    for poll in 0..polls {
        tokio::select! {
            biased;
            outcome = &mut call => panic!("the call finished at poll {poll}: {outcome:?}"),
            () = std::future::ready(()) => {}
        }
    }
}

/// One request is in flight. Other calls wait for the send lock, or stop at the seam after
/// their place in the queue, and go before they take an id. None of them sent a request, so
/// none may close the stream under the request in flight.
#[tokio::test]
async fn a_call_cancelled_before_its_send_keeps_the_stream_of_another_call() {
    let served = StubVerify::start(Stub::ValidAfter(Duration::from_millis(200)));
    let client = served.bls_client().await;
    let long = Duration::from_secs(10);
    let link = client.streams.live().await.unwrap();
    let first = client.verify_sets(vec![set(1, true)], Instant::now() + long);
    let mut first = std::pin::pin!(first);
    let sent = async {
        while link.calls.outstanding() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::select! {
        outcome = &mut first => panic!("the first call must wait for its verdict: {outcome:?}"),
        () = sent => {}
    }
    // Polled once with a free lock, a call stops at the seam after its place in the queue.
    drop_while_pending(
        client.verify_sets(vec![set(1, true)], Instant::now() + long),
        1,
    )
    .await;
    {
        let _send = link.send.lock().await;
        drop_while_pending(
            client.verify_sets(vec![set(1, true)], Instant::now() + long),
            2,
        )
        .await;
        let outcome = client
            .verify_sets(
                vec![set(1, true)],
                Instant::now() + Duration::from_millis(20),
            )
            .await;
        assert_eq!(
            outcome,
            BlsOutcome::NoVerdict(LATE.into()),
            "a call out of time at the send lock must be no verdict"
        );
    }
    assert!(
        !link.requests.is_closed(),
        "a call that sent nothing must not close the stream"
    );
    assert_eq!(
        first.await,
        BlsOutcome::Valid,
        "the request in flight must get its verdict"
    );
    assert_eq!(link.calls.outstanding(), 0);
    assert_eq!(served.streams_opened(), 1);
    assert_eq!(
        served.bls_requests(),
        1,
        "only the first call sent a request"
    );
}
