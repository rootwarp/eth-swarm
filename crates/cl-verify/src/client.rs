//! Caller-side mapping from verify.v1 results to gossip verdicts (cl-chain uses this).
//!
//! Only `VERIFY_STATUS_VALID` is ever ACCEPT. Everything that is not a verdict (a stream error, a
//! missed deadline, a missing or mismatched response, an `err` result, `UNSPECIFIED`, or a status
//! this build does not know) is IGNORE. REJECT is kept for a proven bad object: an invalid
//! signature or proof, or bytes that are not a valid point.

use std::future::Future;

use tonic::Status;

use crate::proto::common::Verdict;
use crate::proto::verify::{bls_result, BlsResult, VerifyBlsResponseBody, VerifyKzgResponseBody};
use crate::wire::{by_deadline, Deadline, WallClock};

/// Verdict for one `VerifyStatus` value as received (an `i32`, so unknown values survive).
#[must_use]
pub fn status_verdict(status: i32) -> Verdict {
    use crate::proto::verify::VerifyStatus;
    match VerifyStatus::try_from(status) {
        Ok(VerifyStatus::Valid) => Verdict::Accept,
        Ok(VerifyStatus::Invalid | VerifyStatus::DecodeError) => Verdict::Reject,
        Ok(
            VerifyStatus::UnknownIndex | VerifyStatus::DeadlineExceeded | VerifyStatus::Overloaded,
        ) => Verdict::Ignore,
        Ok(VerifyStatus::Unspecified) => {
            tracing::warn!("contract violation: VERIFY_STATUS_UNSPECIFIED from cl-verify");
            Verdict::Ignore
        }
        Err(_) => Verdict::Ignore,
    }
}

/// Verdict for one BLS set. A missing result, an `err` result or an empty `oneof` is IGNORE.
#[must_use]
pub fn bls_result_verdict(result: Option<&BlsResult>) -> Verdict {
    match result.and_then(|r| r.result.as_ref()) {
        Some(bls_result::Result::Status(s)) => status_verdict(*s),
        Some(bls_result::Result::Err(_)) => Verdict::Ignore,
        None => {
            if result.is_some() {
                tracing::warn!("contract violation: BlsResult with neither status nor err");
            }
            Verdict::Ignore
        }
    }
}

/// One verdict per request set, in request order. A stream error, a response for another
/// `request_id`, or a result count other than `n_sets` makes every set IGNORE: results are matched
/// to sets by position, so a missing one would shift every later verdict.
#[must_use]
pub fn bls_verdicts(
    response: Result<VerifyBlsResponseBody, Status>,
    request_id: u64,
    n_sets: usize,
) -> Vec<Verdict> {
    let body = match response {
        Ok(body) if body.request_id == request_id && body.results.len() == n_sets => body,
        _ => return vec![Verdict::Ignore; n_sets],
    };
    body.results
        .iter()
        .map(|r| bls_result_verdict(Some(r)))
        .collect()
}

/// Batch verdict for a KZG request. An `err` wins over any status.
#[must_use]
pub fn kzg_verdict(response: Result<VerifyKzgResponseBody, Status>, request_id: u64) -> Verdict {
    match response {
        Ok(body) if body.request_id == request_id && body.err.is_none() => {
            status_verdict(body.status)
        }
        _ => Verdict::Ignore,
    }
}

/// [`bls_verdicts`] for the next response body, IGNORE for every set unless it arrives while
/// `deadline` is still open on both the monotonic clock and `clock` (the wall clock the wire
/// `deadline_unix_ms` is judged against). A body that is ready only after either has passed is
/// IGNORE too.
pub async fn bls_verdicts_by<F>(
    deadline: &Deadline,
    clock: &dyn WallClock,
    request_id: u64,
    n_sets: usize,
    next_body: F,
) -> Vec<Verdict>
where
    F: Future<Output = Result<Option<VerifyBlsResponseBody>, Status>>,
{
    match by_deadline(deadline, clock, next_body).await {
        Some(Ok(Some(body))) => bls_verdicts(Ok(body), request_id, n_sets),
        _ => vec![Verdict::Ignore; n_sets],
    }
}

/// [`kzg_verdict`] for the next response body, IGNORE unless it arrives while `deadline` is open
/// on both clocks.
pub async fn kzg_verdict_by<F>(
    deadline: &Deadline,
    clock: &dyn WallClock,
    request_id: u64,
    next_body: F,
) -> Verdict
where
    F: Future<Output = Result<Option<VerifyKzgResponseBody>, Status>>,
{
    match by_deadline(deadline, clock, next_body).await {
        Some(Ok(Some(body))) => kzg_verdict(Ok(body), request_id),
        _ => Verdict::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::{Error, ErrorCode};
    use crate::proto::verify::VerifyStatus;
    use crate::wire::SystemClock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    fn status(s: VerifyStatus) -> BlsResult {
        BlsResult {
            result: Some(bls_result::Result::Status(s as i32)),
        }
    }

    fn err() -> BlsResult {
        BlsResult {
            result: Some(bls_result::Result::Err(Error {
                code: ErrorCode::ResourceUnavailable as i32,
                detail: String::new(),
            })),
        }
    }

    #[test]
    fn only_valid_is_accept() {
        let cases = [
            (VerifyStatus::Valid as i32, Verdict::Accept),
            (VerifyStatus::Invalid as i32, Verdict::Reject),
            (VerifyStatus::DecodeError as i32, Verdict::Reject),
            (VerifyStatus::UnknownIndex as i32, Verdict::Ignore),
            (VerifyStatus::DeadlineExceeded as i32, Verdict::Ignore),
            (VerifyStatus::Overloaded as i32, Verdict::Ignore),
            (VerifyStatus::Unspecified as i32, Verdict::Ignore),
            (99, Verdict::Ignore),
            (-1, Verdict::Ignore),
        ];
        for (s, want) in cases {
            assert_eq!(status_verdict(s), want, "status {s}");
        }
    }

    #[test]
    fn err_or_empty_bls_result_is_ignore() {
        assert_eq!(bls_result_verdict(Some(&err())), Verdict::Ignore);
        assert_eq!(
            bls_result_verdict(Some(&BlsResult { result: None })),
            Verdict::Ignore
        );
        assert_eq!(bls_result_verdict(None), Verdict::Ignore);
        assert_eq!(
            bls_result_verdict(Some(&status(VerifyStatus::Valid))),
            Verdict::Accept
        );
    }

    #[test]
    fn bls_response_maps_each_set_in_order() {
        let body = VerifyBlsResponseBody {
            request_id: 7,
            results: vec![status(VerifyStatus::Valid), status(VerifyStatus::Invalid)],
        };
        assert_eq!(
            bls_verdicts(Ok(body), 7, 2),
            vec![Verdict::Accept, Verdict::Reject]
        );
    }

    #[test]
    fn short_bls_response_is_ignore_for_every_set() {
        // A dropped result must not shift another set's VALID onto the wrong position.
        let body = VerifyBlsResponseBody {
            request_id: 7,
            results: vec![status(VerifyStatus::Valid), status(VerifyStatus::Invalid)],
        };
        assert_eq!(bls_verdicts(Ok(body), 7, 3), vec![Verdict::Ignore; 3]);
    }

    #[test]
    fn bls_response_with_extra_results_is_ignore() {
        let body = VerifyBlsResponseBody {
            request_id: 7,
            results: vec![status(VerifyStatus::Valid); 3],
        };
        assert_eq!(bls_verdicts(Ok(body), 7, 2), vec![Verdict::Ignore; 2]);
    }

    #[test]
    fn bls_response_for_another_request_is_ignore() {
        let body = VerifyBlsResponseBody {
            request_id: 8,
            results: vec![status(VerifyStatus::Valid)],
        };
        assert_eq!(bls_verdicts(Ok(body), 7, 1), vec![Verdict::Ignore]);
    }

    #[test]
    fn stream_error_is_ignore_for_every_set() {
        let got = bls_verdicts(Err(Status::internal("boom")), 1, 2);
        assert_eq!(got, vec![Verdict::Ignore; 2]);
        assert_eq!(
            kzg_verdict(Err(Status::deadline_exceeded("late")), 1),
            Verdict::Ignore
        );
    }

    #[test]
    fn kzg_err_wins_over_a_valid_status() {
        let mut body = VerifyKzgResponseBody {
            request_id: 3,
            status: VerifyStatus::Valid as i32,
            err: None,
        };
        assert_eq!(kzg_verdict(Ok(body.clone()), 3), Verdict::Accept);
        assert_eq!(kzg_verdict(Ok(body.clone()), 4), Verdict::Ignore);
        body.err = Some(Error {
            code: ErrorCode::ResourceUnavailable as i32,
            detail: String::new(),
        });
        assert_eq!(kzg_verdict(Ok(body), 3), Verdict::Ignore);
    }

    struct Manual(AtomicU64);
    impl WallClock for Manual {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn deadline_in(ms: u64, clock: &dyn WallClock) -> Deadline {
        Deadline::new(clock.now_unix_ms() + ms, clock).unwrap()
    }

    fn valid_bls() -> VerifyBlsResponseBody {
        VerifyBlsResponseBody {
            request_id: 1,
            results: vec![status(VerifyStatus::Valid)],
        }
    }

    fn valid_kzg() -> VerifyKzgResponseBody {
        VerifyKzgResponseBody {
            request_id: 1,
            status: VerifyStatus::Valid as i32,
            err: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn caller_deadline_miss_is_ignore() {
        let deadline = deadline_in(50, &SystemClock);
        let never = std::future::pending::<Result<Option<VerifyBlsResponseBody>, Status>>();
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, 1, 2, never).await,
            vec![Verdict::Ignore; 2]
        );
        let kzg_never = std::future::pending::<Result<Option<VerifyKzgResponseBody>, Status>>();
        assert_eq!(
            kzg_verdict_by(&deadline, &SystemClock, 1, kzg_never).await,
            Verdict::Ignore
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ready_valid_after_deadline_is_ignore() {
        let deadline = deadline_in(1, &SystemClock);
        tokio::time::advance(Duration::from_millis(2)).await;
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, 1, 1, async {
                Ok(Some(valid_bls()))
            })
            .await,
            vec![Verdict::Ignore]
        );
        assert_eq!(
            kzg_verdict_by(&deadline, &SystemClock, 1, async { Ok(Some(valid_kzg())) }).await,
            Verdict::Ignore
        );
    }

    #[tokio::test(start_paused = true)]
    async fn valid_after_a_wall_clock_jump_past_the_deadline_is_ignore() {
        let clock = Manual(AtomicU64::new(1_000));
        let deadline = deadline_in(5_000, &clock);
        let bls = async {
            clock.0.store(6_001, Ordering::SeqCst);
            Ok(Some(valid_bls()))
        };
        assert_eq!(
            bls_verdicts_by(&deadline, &clock, 1, 1, bls).await,
            vec![Verdict::Ignore]
        );
        clock.0.store(1_000, Ordering::SeqCst);
        let kzg = async {
            clock.0.store(6_001, Ordering::SeqCst);
            Ok(Some(valid_kzg()))
        };
        assert_eq!(
            kzg_verdict_by(&deadline, &clock, 1, kzg).await,
            Verdict::Ignore
        );
    }

    #[tokio::test]
    async fn closed_stream_is_ignore_and_answer_in_time_is_mapped() {
        let deadline = deadline_in(5_000, &SystemClock);
        let closed = async { Ok(None) };
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, 1, 1, closed).await,
            vec![Verdict::Ignore]
        );
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, 1, 1, async {
                Ok(Some(valid_bls()))
            })
            .await,
            vec![Verdict::Accept]
        );
        let kzg = VerifyKzgResponseBody {
            request_id: 1,
            status: VerifyStatus::Invalid as i32,
            err: None,
        };
        assert_eq!(
            kzg_verdict_by(&deadline, &SystemClock, 1, async { Ok(Some(kzg)) }).await,
            Verdict::Reject
        );
    }
}
