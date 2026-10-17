//! Caller-side mapping from verify.v1 results to gossip verdicts (cl-chain uses this).
//!
//! Only `VERIFY_STATUS_VALID` is ever ACCEPT. Everything that is not a verdict (a stream error, a
//! missed deadline, a missing or mismatched response, an `err` result, `UNSPECIFIED`, or a status
//! this build does not know) is IGNORE. REJECT is kept for a proven bad object: an invalid
//! signature or proof, or bytes that are not a valid point.
//!
//! Every response is first settled against the caller's [`Outstanding`] table of the stream
//! ([`settle_bls`], [`settle_kzg`]): its results must carry the fences of the request it answers
//! (`request_id`, the stream's server generation, item index, item hash). A reordered, duplicated,
//! stale-generation or substituted response, or one without fences, is
//! `ERROR_CODE_CONTRACT_VIOLATION` (logged) and IGNORE for every set, never ACCEPT. It fails the
//! stream: the table is closed, as it is on a stream error or end, so nothing that still arrives
//! on it is ACCEPT. A response for a request whose deadline already passed, or presented with a
//! tag of another stream, is late: IGNORE.

use std::future::Future;

use ipc::fence::{FenceError, FencedResult, Outstanding, RequestTag};
use tonic::Status;

use crate::proto::common::Verdict;
use crate::proto::verify::{bls_result, BlsResult, VerifyBlsResponseBody, VerifyKzgResponseBody};
use crate::wire::{race_deadline, Deadline, Timed, WallClock};

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

/// Settles a VerifyBls response for the request tagged `tag` ([`Outstanding::settle_body`]),
/// which then forgets that request. The response must name that request in its body and in
/// every fence. A tag of another stream (another generation; request ids restart at 1 on every
/// stream) and anything on a closed table is late. On an error nothing is settled (a late
/// response consumes its expired entry).
pub fn settle_bls(
    outstanding: &mut Outstanding,
    tag: RequestTag,
    body: VerifyBlsResponseBody,
) -> Result<VerifyBlsResponseBody, FenceError> {
    settle(outstanding, tag, body)
}

/// [`settle_bls`] for a VerifyKzg response.
pub fn settle_kzg(
    outstanding: &mut Outstanding,
    tag: RequestTag,
    body: VerifyKzgResponseBody,
) -> Result<VerifyKzgResponseBody, FenceError> {
    settle(outstanding, tag, body)
}

fn settle<B: FencedResult>(
    outstanding: &mut Outstanding,
    tag: RequestTag,
    body: B,
) -> Result<B, FenceError> {
    if tag.generation != outstanding.generation() {
        return Err(FenceError::Late {
            request_id: tag.request_id,
        });
    }
    if !outstanding.is_closed() && body.request_id() != tag.request_id {
        return Err(FenceError::Substituted {
            request_id: tag.request_id,
            detail: format!("response names request {}", body.request_id()),
        });
    }
    outstanding.settle_body(&body)?;
    Ok(body)
}

/// Logs why a response was refused. A contract violation is a cl-verify bug: the client fails
/// the stream, so `outstanding` is closed and nothing that still arrives on it is ACCEPT.
fn refused(outstanding: &mut Outstanding, e: &FenceError) {
    if e.is_ignore() {
        tracing::debug!(reason = %e, "late cl-verify response dropped");
    } else {
        tracing::warn!(reason = %e, "contract violation: cl-verify response fence");
        outstanding.close();
    }
}

/// The stream errored or ended: every outstanding request fails as IGNORE, and the table takes
/// nothing more as a verdict.
fn ended(outstanding: &mut Outstanding) {
    outstanding.close();
}

/// One verdict per request set, in request order, for the request tagged `tag` with `n_sets`
/// sets. A stream error, a response that does not settle ([`settle_bls`]), or a result count
/// other than `n_sets` makes every set IGNORE: results are matched to sets by position, so a
/// missing one would shift every later verdict.
///
/// A stream error or a fence violation also closes `outstanding` (the stream is failed), so a
/// later response on it, however well fenced, is IGNORE too. Check
/// [`Outstanding::is_closed`] to know the stream must be replaced. Responses may arrive out of
/// order: pass each one with the tag of the request its `request_id` names.
#[must_use]
pub fn bls_verdicts(
    response: Result<VerifyBlsResponseBody, Status>,
    outstanding: &mut Outstanding,
    tag: RequestTag,
    n_sets: usize,
) -> Vec<Verdict> {
    let ignore = || vec![Verdict::Ignore; n_sets];
    let Ok(body) = response else {
        ended(outstanding);
        return ignore();
    };
    match settle_bls(outstanding, tag, body) {
        Ok(body) if body.results.len() == n_sets => body
            .results
            .iter()
            .map(|r| bls_result_verdict(Some(r)))
            .collect(),
        Ok(_) => ignore(),
        Err(e) => {
            refused(outstanding, &e);
            ignore()
        }
    }
}

/// Batch verdict for the KZG request tagged `tag`. A response that does not settle
/// ([`settle_kzg`]) is IGNORE, and an `err` wins over any status. A stream error or a fence
/// violation closes `outstanding`, as in [`bls_verdicts`].
#[must_use]
pub fn kzg_verdict(
    response: Result<VerifyKzgResponseBody, Status>,
    outstanding: &mut Outstanding,
    tag: RequestTag,
) -> Verdict {
    let Ok(body) = response else {
        ended(outstanding);
        return Verdict::Ignore;
    };
    match settle_kzg(outstanding, tag, body) {
        Ok(body) if body.err.is_none() => status_verdict(body.status),
        Ok(_) => Verdict::Ignore,
        Err(e) => {
            refused(outstanding, &e);
            Verdict::Ignore
        }
    }
}

/// What the next response body did by the deadline: the body to map, or `None` once it is
/// accounted for as IGNORE.
fn by_deadline_body<B: FencedResult>(
    raced: Timed<Result<Option<B>, Status>>,
    outstanding: &mut Outstanding,
    tag: RequestTag,
) -> Option<B> {
    match raced {
        Timed::InTime(Ok(Some(body))) => Some(body),
        // Nothing yet: the request expires, and its response, if it still comes, is late.
        Timed::TimedOut => {
            outstanding.expire(tag.request_id);
            None
        }
        // Read only after the deadline: late now. It frees its entry and is counted.
        Timed::Late(Ok(Some(body))) => {
            outstanding.expire(tag.request_id);
            if let Err(e) = settle(outstanding, tag, body) {
                refused(outstanding, &e);
            }
            None
        }
        Timed::InTime(Ok(None) | Err(_)) | Timed::Late(Ok(None) | Err(_)) => {
            ended(outstanding);
            None
        }
    }
}

/// [`bls_verdicts`] for the next response body, IGNORE for every set unless it arrives while
/// `deadline` is still open on both the monotonic clock and `clock` (the wall clock the wire
/// `deadline_unix_ms` is judged against). With no body by then the request expires: its
/// response, if it still comes, is late. A body that is ready only after the deadline is late
/// at once: it is dropped, counted ([`Outstanding::late_dropped`]) and frees its entry. A
/// stream error or end closes `outstanding`.
pub async fn bls_verdicts_by<F>(
    deadline: &Deadline,
    clock: &dyn WallClock,
    outstanding: &mut Outstanding,
    tag: RequestTag,
    n_sets: usize,
    next_body: F,
) -> Vec<Verdict>
where
    F: Future<Output = Result<Option<VerifyBlsResponseBody>, Status>>,
{
    let raced = race_deadline(deadline, clock, next_body).await;
    match by_deadline_body(raced, outstanding, tag) {
        Some(body) => bls_verdicts(Ok(body), outstanding, tag, n_sets),
        None => vec![Verdict::Ignore; n_sets],
    }
}

/// [`kzg_verdict`] for the next response body, IGNORE unless it arrives while `deadline` is open
/// on both clocks (a late body and a stream end are handled as in [`bls_verdicts_by`]).
pub async fn kzg_verdict_by<F>(
    deadline: &Deadline,
    clock: &dyn WallClock,
    outstanding: &mut Outstanding,
    tag: RequestTag,
    next_body: F,
) -> Verdict
where
    F: Future<Output = Result<Option<VerifyKzgResponseBody>, Status>>,
{
    let raced = race_deadline(deadline, clock, next_body).await;
    match by_deadline_body(raced, outstanding, tag) {
        Some(body) => kzg_verdict(Ok(body), outstanding, tag),
        None => Verdict::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::{Error, ErrorCode};
    use crate::proto::verify::{BlsSet, VerifyBlsRequestBody, VerifyKzgRequestBody, VerifyStatus};
    use crate::wire::SystemClock;
    use ipc::fence::FencedRequest;
    use ipc::hello::Generation;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    fn status(s: VerifyStatus) -> BlsResult {
        BlsResult {
            result: Some(bls_result::Result::Status(s as i32)),
            fence: None,
        }
    }

    fn err() -> BlsResult {
        BlsResult {
            result: Some(bls_result::Result::Err(Error {
                code: ErrorCode::ResourceUnavailable as i32,
                detail: String::new(),
            })),
            fence: None,
        }
    }

    fn outstanding() -> Outstanding {
        Outstanding::new(Generation::new(0x9e).unwrap(), 8)
    }

    /// Files a BLS request of `n` distinct sets.
    fn bls_request(out: &mut Outstanding, n: u8) -> (RequestTag, VerifyBlsRequestBody) {
        out.issue(|tag| {
            let body = VerifyBlsRequestBody {
                request_id: tag.request_id,
                generation: tag.generation.get(),
                sets: (0..n)
                    .map(|i| BlsSet {
                        signing_root: vec![i; 32],
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            };
            let hashes = body.item_hashes();
            (body, hashes)
        })
        .unwrap()
    }

    /// The response an honest server sends for `request` with `results`.
    fn bls_answer(
        request: &VerifyBlsRequestBody,
        results: Vec<BlsResult>,
    ) -> VerifyBlsResponseBody {
        let mut body = VerifyBlsResponseBody {
            request_id: request.request_id,
            results,
        };
        body.stamp(&request.result_fences());
        body
    }

    fn kzg_request(out: &mut Outstanding) -> (RequestTag, VerifyKzgRequestBody) {
        out.issue(|tag| {
            let body = VerifyKzgRequestBody {
                request_id: tag.request_id,
                generation: tag.generation.get(),
                deadline_unix_ms: 1,
                ..Default::default()
            };
            let hashes = body.item_hashes();
            (body, hashes)
        })
        .unwrap()
    }

    fn kzg_answer(request: &VerifyKzgRequestBody, s: VerifyStatus) -> VerifyKzgResponseBody {
        let mut body = VerifyKzgResponseBody {
            request_id: request.request_id,
            status: s as i32,
            err: None,
            fence: None,
        };
        body.stamp(&request.result_fences());
        body
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
            bls_result_verdict(Some(&BlsResult {
                result: None,
                fence: None,
            })),
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
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 2);
        let body = bls_answer(
            &request,
            vec![status(VerifyStatus::Valid), status(VerifyStatus::Invalid)],
        );
        assert_eq!(
            bls_verdicts(Ok(body), &mut out, tag, 2),
            vec![Verdict::Accept, Verdict::Reject]
        );
        assert!(out.is_empty(), "the request is settled");
    }

    #[test]
    fn short_or_long_bls_response_is_ignore_for_every_set() {
        // A dropped result must not shift another set's VALID onto the wrong position.
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 3);
        let mut short = bls_answer(&request, vec![status(VerifyStatus::Valid); 3]);
        short.results.pop();
        assert_eq!(
            bls_verdicts(Ok(short), &mut out, tag, 3),
            vec![Verdict::Ignore; 3]
        );
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 3);
        let mut long = bls_answer(&request, vec![status(VerifyStatus::Valid); 3]);
        long.results.push(long.results[0].clone());
        assert_eq!(
            bls_verdicts(Ok(long), &mut out, tag, 3),
            vec![Verdict::Ignore; 3]
        );
        // A caller that expects another set count gets IGNORE even for a well-fenced answer.
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 1);
        let body = bls_answer(&request, vec![status(VerifyStatus::Valid)]);
        assert_eq!(
            bls_verdicts(Ok(body), &mut out, tag, 2),
            vec![Verdict::Ignore; 2]
        );
    }

    #[test]
    fn bls_response_for_another_request_is_a_violation_and_ignore() {
        let mut out = outstanding();
        let (first, _) = bls_request(&mut out, 1);
        let (_, second) = bls_request(&mut out, 1);
        let body = bls_answer(&second, vec![status(VerifyStatus::Valid)]);
        let refused = settle_bls(&mut out.clone(), first, body.clone()).unwrap_err();
        assert_eq!(refused.code(), Some(ErrorCode::ContractViolation));
        assert_eq!(
            bls_verdicts(Ok(body), &mut out, first, 1),
            vec![Verdict::Ignore]
        );
        assert!(out.is_closed(), "a violation fails the stream");
    }

    #[test]
    fn every_fence_mismatch_is_a_contract_violation_and_ignore() {
        type Mutation = fn(&mut VerifyBlsResponseBody);
        let mutations: Vec<(&str, Mutation)> = vec![
            ("reordered", |b| b.results.swap(0, 1)),
            ("stale generation", |b| {
                for r in &mut b.results {
                    r.fence.as_mut().unwrap().generation ^= 1;
                }
            }),
            ("substituted", |b| {
                b.results[0].fence.as_mut().unwrap().item_hash = vec![0xee; 32];
            }),
            ("missing fence", |b| b.results[1].fence = None),
            ("short item hash", |b| {
                b.results[1].fence.as_mut().unwrap().item_hash.pop();
            }),
        ];
        for (what, mutate) in mutations {
            let mut out = outstanding();
            let (tag, request) = bls_request(&mut out, 2);
            let honest = bls_answer(&request, vec![status(VerifyStatus::Valid); 2]);
            let mut body = honest.clone();
            mutate(&mut body);
            let e = settle_bls(&mut out.clone(), tag, body.clone()).unwrap_err();
            assert_eq!(e.code(), Some(ErrorCode::ContractViolation), "{what}: {e}");
            assert_eq!(
                bls_verdicts(Ok(body), &mut out, tag, 2),
                vec![Verdict::Ignore; 2],
                "{what}"
            );
            assert!(out.is_closed(), "{what}: the stream is failed");
            // The honest answer that follows on the failed stream is never ACCEPT.
            assert_eq!(
                bls_verdicts(Ok(honest), &mut out, tag, 2),
                vec![Verdict::Ignore; 2],
                "{what}: after the violation"
            );
        }
    }

    #[test]
    fn a_duplicated_response_is_a_contract_violation_and_ignore() {
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 1);
        let body = bls_answer(&request, vec![status(VerifyStatus::Valid)]);
        assert_eq!(
            bls_verdicts(Ok(body.clone()), &mut out, tag, 1),
            vec![Verdict::Accept]
        );
        let e = settle_bls(&mut out.clone(), tag, body.clone()).unwrap_err();
        assert_eq!(e, FenceError::Duplicate { request_id: 1 });
        assert_eq!(
            bls_verdicts(Ok(body), &mut out, tag, 1),
            vec![Verdict::Ignore]
        );
        assert!(out.is_closed());
    }

    #[test]
    fn a_stream_error_fails_the_stream_and_nothing_later_accepts() {
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 2);
        let got = bls_verdicts(Err(Status::internal("boom")), &mut out, tag, 2);
        assert_eq!(got, vec![Verdict::Ignore; 2]);
        assert!(out.is_closed());
        let valid = bls_answer(&request, vec![status(VerifyStatus::Valid); 2]);
        assert_eq!(
            bls_verdicts(Ok(valid), &mut out, tag, 2),
            vec![Verdict::Ignore; 2]
        );

        let mut kout = outstanding();
        let (ktag, krequest) = kzg_request(&mut kout);
        assert_eq!(
            kzg_verdict(Err(Status::deadline_exceeded("late")), &mut kout, ktag),
            Verdict::Ignore
        );
        assert!(kout.is_closed());
        let valid = kzg_answer(&krequest, VerifyStatus::Valid);
        assert_eq!(kzg_verdict(Ok(valid), &mut kout, ktag), Verdict::Ignore);
    }

    #[test]
    fn an_old_streams_tag_is_late_against_the_new_table() {
        // Request ids restart at 1 on every stream; the generation tells the tags apart.
        let mut old = outstanding();
        let (old_tag, _) = bls_request(&mut old, 1);
        let mut new = Outstanding::new(Generation::new(0x9f).unwrap(), 8);
        let (new_tag, new_request) = bls_request(&mut new, 1);
        assert_eq!(old_tag.request_id, new_tag.request_id);
        let body = bls_answer(&new_request, vec![status(VerifyStatus::Valid)]);
        let e = settle_bls(&mut new.clone(), old_tag, body.clone()).unwrap_err();
        assert!(e.is_ignore(), "{e}");
        assert_eq!(
            bls_verdicts(Ok(body.clone()), &mut new, old_tag, 1),
            vec![Verdict::Ignore]
        );
        assert_eq!((new.len(), new.is_closed()), (1, false), "nothing settled");
        assert_eq!(
            bls_verdicts(Ok(body), &mut new, new_tag, 1),
            vec![Verdict::Accept]
        );

        let (old_ktag, _) = kzg_request(&mut old);
        let (_, new_krequest) = kzg_request(&mut new);
        let kbody = kzg_answer(&new_krequest, VerifyStatus::Valid);
        assert!(settle_kzg(&mut new.clone(), old_ktag, kbody.clone())
            .unwrap_err()
            .is_ignore());
        assert_eq!(kzg_verdict(Ok(kbody), &mut new, old_ktag), Verdict::Ignore);
    }

    #[test]
    fn kzg_err_wins_over_a_valid_status_and_fences_are_checked() {
        let mut out = outstanding();
        let (tag, request) = kzg_request(&mut out);
        let body = kzg_answer(&request, VerifyStatus::Valid);
        assert_eq!(
            kzg_verdict(Ok(body.clone()), &mut out, tag),
            Verdict::Accept
        );
        // The answer presented for another request is refused and fails the stream.
        let mut other_out = outstanding();
        let (_, _) = kzg_request(&mut other_out);
        let (other, _) = kzg_request(&mut other_out);
        assert_eq!(
            kzg_verdict(Ok(body), &mut other_out, other),
            Verdict::Ignore
        );
        assert!(other_out.is_closed());

        let (tag, request) = kzg_request(&mut out);
        let mut failed = kzg_answer(&request, VerifyStatus::Valid);
        failed.err = Some(Error {
            code: ErrorCode::ResourceUnavailable as i32,
            detail: String::new(),
        });
        assert_eq!(kzg_verdict(Ok(failed), &mut out, tag), Verdict::Ignore);

        let (tag, request) = kzg_request(&mut out);
        let mut unfenced = kzg_answer(&request, VerifyStatus::Valid);
        unfenced.fence = None;
        let e = settle_kzg(&mut out.clone(), tag, unfenced.clone()).unwrap_err();
        assert_eq!(e.code(), Some(ErrorCode::ContractViolation));
        assert_eq!(kzg_verdict(Ok(unfenced), &mut out, tag), Verdict::Ignore);
        assert!(out.is_closed());
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

    #[tokio::test(start_paused = true)]
    async fn caller_deadline_miss_is_ignore_and_the_late_response_too() {
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 2);
        let deadline = deadline_in(50, &SystemClock);
        let never = std::future::pending::<Result<Option<VerifyBlsResponseBody>, Status>>();
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, &mut out, tag, 2, never).await,
            vec![Verdict::Ignore; 2]
        );
        // The VALID answer that arrives afterwards is late: dropped, not a violation.
        let late = bls_answer(&request, vec![status(VerifyStatus::Valid); 2]);
        let e = settle_bls(&mut out.clone(), tag, late.clone()).unwrap_err();
        assert!(e.is_ignore(), "{e}");
        assert_eq!(
            bls_verdicts(Ok(late), &mut out, tag, 2),
            vec![Verdict::Ignore; 2]
        );

        let (ktag, krequest) = kzg_request(&mut out);
        let kzg_never = std::future::pending::<Result<Option<VerifyKzgResponseBody>, Status>>();
        assert_eq!(
            kzg_verdict_by(&deadline, &SystemClock, &mut out, ktag, kzg_never).await,
            Verdict::Ignore
        );
        let late = kzg_answer(&krequest, VerifyStatus::Valid);
        assert!(settle_kzg(&mut out, ktag, late).unwrap_err().is_ignore());
    }

    #[tokio::test(start_paused = true)]
    async fn ready_valid_after_deadline_is_ignore() {
        let mut out = outstanding();
        let deadline = deadline_in(1, &SystemClock);
        tokio::time::advance(Duration::from_millis(2)).await;
        let (tag, request) = bls_request(&mut out, 1);
        let body = bls_answer(&request, vec![status(VerifyStatus::Valid)]);
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, &mut out, tag, 1, async {
                Ok(Some(body))
            })
            .await,
            vec![Verdict::Ignore]
        );
        let (ktag, krequest) = kzg_request(&mut out);
        let kbody = kzg_answer(&krequest, VerifyStatus::Valid);
        assert_eq!(
            kzg_verdict_by(&deadline, &SystemClock, &mut out, ktag, async {
                Ok(Some(kbody))
            })
            .await,
            Verdict::Ignore
        );
    }

    #[tokio::test(start_paused = true)]
    async fn valid_after_a_wall_clock_jump_past_the_deadline_is_ignore() {
        let clock = Manual(AtomicU64::new(1_000));
        let deadline = deadline_in(5_000, &clock);
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 1);
        let body = bls_answer(&request, vec![status(VerifyStatus::Valid)]);
        let bls = async {
            clock.0.store(6_001, Ordering::SeqCst);
            Ok(Some(body))
        };
        assert_eq!(
            bls_verdicts_by(&deadline, &clock, &mut out, tag, 1, bls).await,
            vec![Verdict::Ignore]
        );
        clock.0.store(1_000, Ordering::SeqCst);
        let (ktag, krequest) = kzg_request(&mut out);
        let kbody = kzg_answer(&krequest, VerifyStatus::Valid);
        let kzg = async {
            clock.0.store(6_001, Ordering::SeqCst);
            Ok(Some(kbody))
        };
        assert_eq!(
            kzg_verdict_by(&deadline, &clock, &mut out, ktag, kzg).await,
            Verdict::Ignore
        );
    }

    #[tokio::test]
    async fn closed_stream_fails_the_table_and_answer_in_time_is_mapped() {
        let deadline = deadline_in(5_000, &SystemClock);
        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 1);
        let closed = async { Ok(None) };
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, &mut out, tag, 1, closed).await,
            vec![Verdict::Ignore]
        );
        assert!(out.is_closed(), "EOF ends the stream");
        // A VALID body for the same tag afterwards is never ACCEPT.
        let body = bls_answer(&request, vec![status(VerifyStatus::Valid)]);
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, &mut out, tag, 1, async {
                Ok(Some(body))
            })
            .await,
            vec![Verdict::Ignore]
        );

        let mut out = outstanding();
        let (tag, request) = bls_request(&mut out, 1);
        let body = bls_answer(&request, vec![status(VerifyStatus::Valid)]);
        assert_eq!(
            bls_verdicts_by(&deadline, &SystemClock, &mut out, tag, 1, async {
                Ok(Some(body))
            })
            .await,
            vec![Verdict::Accept]
        );
        let (ktag, krequest) = kzg_request(&mut out);
        let kzg = kzg_answer(&krequest, VerifyStatus::Invalid);
        assert_eq!(
            kzg_verdict_by(&deadline, &SystemClock, &mut out, ktag, async {
                Ok(Some(kzg))
            })
            .await,
            Verdict::Reject
        );
        let (ktag, _) = kzg_request(&mut out);
        let kzg_closed = async { Ok(None) };
        assert_eq!(
            kzg_verdict_by(&deadline, &SystemClock, &mut out, ktag, kzg_closed).await,
            Verdict::Ignore
        );
        assert!(out.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn bodies_read_after_the_deadline_are_late_and_free_their_slot() {
        const CAPACITY: usize = 2;
        let mut out = Outstanding::new(Generation::new(0x9e).unwrap(), CAPACITY);
        let races = CAPACITY as u64 + 1;
        for _ in 0..races {
            let (tag, request) = bls_request(&mut out, 1);
            let deadline = deadline_in(1, &SystemClock);
            let body = bls_answer(&request, vec![status(VerifyStatus::Valid)]);
            // The body is read only once the deadline has passed.
            tokio::time::advance(Duration::from_millis(2)).await;
            let after = async { Ok(Some(body)) };
            assert_eq!(
                bls_verdicts_by(&deadline, &SystemClock, &mut out, tag, 1, after).await,
                vec![Verdict::Ignore]
            );
        }
        assert_eq!(out.late_dropped(), races);
        assert!(out.is_empty());
        assert!(!out.is_closed());
        // The stream still takes requests: no expired entry was left behind.
        let (tag, request) = kzg_request(&mut out);
        let deadline = deadline_in(1, &SystemClock);
        let kbody = kzg_answer(&request, VerifyStatus::Valid);
        tokio::time::advance(Duration::from_millis(2)).await;
        let after = async { Ok(Some(kbody)) };
        assert_eq!(
            kzg_verdict_by(&deadline, &SystemClock, &mut out, tag, after).await,
            Verdict::Ignore
        );
        assert_eq!(out.late_dropped(), races + 1);
        bls_request(&mut out, 1);
    }
}
