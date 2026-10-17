//! Wire helpers shared by the server and the client mapping: `common.v1.Error` construction,
//! `Error` <-> `tonic::Status`, and deadline arithmetic.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::{timeout_at, Instant};

use prost::Message;
use tonic::{Code, Status};

use crate::proto::common::{Error, ErrorCode};

/// `common.v1.Error.detail` max length in bytes (error.proto).
pub const MAX_DETAIL_BYTES: usize = 1024;

/// Builds a wire error, truncating `detail` to [`MAX_DETAIL_BYTES`] on a char boundary.
#[must_use]
pub fn wire_error(code: ErrorCode, detail: impl Into<String>) -> Error {
    let mut detail = detail.into();
    if detail.len() > MAX_DETAIL_BYTES {
        let mut cut = MAX_DETAIL_BYTES;
        while !detail.is_char_boundary(cut) {
            cut -= 1;
        }
        detail.truncate(cut);
    }
    Error {
        code: code as i32,
        detail,
    }
}

/// Status that fails a stream. The `common.v1.Error` travels prost-encoded in the status details.
#[must_use]
pub fn to_status(err: &Error) -> Status {
    let code = match err.code() {
        ErrorCode::ContractViolation | ErrorCode::ForkDigestMismatch | ErrorCode::SszDecode => {
            Code::InvalidArgument
        }
        ErrorCode::VersionMismatch => Code::FailedPrecondition,
        ErrorCode::DeadlineExceeded => Code::DeadlineExceeded,
        ErrorCode::Overloaded => Code::ResourceExhausted,
        _ => Code::Unavailable,
    };
    Status::with_details(code, err.detail.clone(), err.encode_to_vec().into())
}

/// The `common.v1.Error` a stream failed with. A status without (valid) details, such as one
/// raised by the transport itself, is mapped from its gRPC code.
#[must_use]
pub fn error_from_status(status: &Status) -> Error {
    if let Ok(err) = Error::decode(status.details()) {
        if err.code != ErrorCode::Unspecified as i32 {
            return err;
        }
    }
    let code = match status.code() {
        Code::DeadlineExceeded | Code::Cancelled => ErrorCode::DeadlineExceeded,
        Code::ResourceExhausted => ErrorCode::Overloaded,
        Code::InvalidArgument | Code::OutOfRange | Code::PermissionDenied => {
            ErrorCode::ContractViolation
        }
        Code::FailedPrecondition => ErrorCode::VersionMismatch,
        _ => ErrorCode::ResourceUnavailable,
    };
    wire_error(code, status.message())
}

/// Maps an error tonic raised while receiving a request frame. tonic reports a message over the
/// decoding limit as `OutOfRange` from the frame header, before decoding it: a cap breach.
#[must_use]
pub fn inbound_error(status: &Status) -> Error {
    match status.code() {
        Code::OutOfRange => wire_error(
            ErrorCode::ContractViolation,
            format!("request over the message cap: {}", status.message()),
        ),
        _ => wire_error(
            ErrorCode::ResourceUnavailable,
            format!("receive failed: {}", status.message()),
        ),
    }
}

/// The wall clock deadlines are judged against. Injected so tests can step it.
pub trait WallClock: Send + Sync + 'static {
    /// Milliseconds since the Unix epoch.
    fn now_unix_ms(&self) -> u64;
}

/// The system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl WallClock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        now_unix_ms()
    }
}

/// Stand-in for a monotonic deadline too far ahead to represent.
const FAR_DEADLINE: Duration = Duration::from_secs(365 * 24 * 3600);

/// A wire deadline (`deadline_unix_ms`) plus the monotonic instant derived from it when the
/// request was read. It is open only while both hold: the monotonic check covers a wall clock
/// that steps backwards, the wall check one that steps forwards.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    at: Instant,
    unix_ms: u64,
}

impl Deadline {
    /// `None` if `unix_ms` is unset (0) or leaves no time on `clock`.
    #[must_use]
    pub fn new(unix_ms: u64, clock: &dyn WallClock) -> Option<Self> {
        let left = time_left(unix_ms, clock.now_unix_ms())?;
        let now = Instant::now();
        let at = now.checked_add(left).unwrap_or_else(|| now + FAR_DEADLINE);
        Some(Self { at, unix_ms })
    }

    #[must_use]
    pub fn instant(&self) -> Instant {
        self.at
    }

    #[must_use]
    pub fn unix_ms(&self) -> u64 {
        self.unix_ms
    }

    /// `Instant::now() < instant` and `clock <= unix_ms`.
    #[must_use]
    pub fn open(&self, clock: &dyn WallClock) -> bool {
        Instant::now() < self.at && clock.now_unix_ms() <= self.unix_ms
    }
}

/// `fut`'s output if it is ready while `deadline` is still open, else `None`.
///
/// `timeout_at` polls the future before its timer, so a result that becomes ready after the
/// deadline would otherwise still be returned; both clocks are checked again after it resolves.
pub async fn by_deadline<F: Future>(
    deadline: &Deadline,
    clock: &dyn WallClock,
    fut: F,
) -> Option<F::Output> {
    let out = timeout_at(deadline.at, fut).await.ok()?;
    deadline.open(clock).then_some(out)
}

/// Milliseconds since the Unix epoch (0 if the clock is before it).
#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Time left until `deadline_unix_ms`, or `None` if it has passed. An unset (0) deadline has
/// always passed: work is never started without one.
#[must_use]
pub fn time_left(deadline_unix_ms: u64, now_unix_ms: u64) -> Option<Duration> {
    deadline_unix_ms
        .checked_sub(now_unix_ms)
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn detail_is_truncated_on_a_char_boundary() {
        let err = wire_error(ErrorCode::Invalid, "é".repeat(600));
        assert!(err.detail.len() <= MAX_DETAIL_BYTES);
        assert_eq!(err.detail.len(), 1024);
        let short = wire_error(ErrorCode::Invalid, "x");
        assert_eq!(short.detail, "x");
    }

    #[test]
    fn status_round_trips_the_wire_error() {
        for code in [
            ErrorCode::ContractViolation,
            ErrorCode::VersionMismatch,
            ErrorCode::DeadlineExceeded,
            ErrorCode::Overloaded,
            ErrorCode::ResourceUnavailable,
        ] {
            let err = wire_error(code, "why");
            assert_eq!(error_from_status(&to_status(&err)), err);
        }
    }

    #[test]
    fn status_without_details_maps_from_the_grpc_code() {
        let cases = [
            (Code::DeadlineExceeded, ErrorCode::DeadlineExceeded),
            (Code::Cancelled, ErrorCode::DeadlineExceeded),
            (Code::ResourceExhausted, ErrorCode::Overloaded),
            (Code::OutOfRange, ErrorCode::ContractViolation),
            (Code::InvalidArgument, ErrorCode::ContractViolation),
            (Code::PermissionDenied, ErrorCode::ContractViolation),
            (Code::FailedPrecondition, ErrorCode::VersionMismatch),
            (Code::Internal, ErrorCode::ResourceUnavailable),
            (Code::Unknown, ErrorCode::ResourceUnavailable),
        ];
        for (grpc, want) in cases {
            assert_eq!(error_from_status(&Status::new(grpc, "m")).code(), want);
        }
    }

    #[test]
    fn inbound_size_limit_is_a_contract_violation() {
        let over = Status::new(Code::OutOfRange, "decoded message length too large");
        assert_eq!(inbound_error(&over).code(), ErrorCode::ContractViolation);
        let other = Status::new(Code::Unknown, "h2 reset");
        assert_eq!(inbound_error(&other).code(), ErrorCode::ResourceUnavailable);
    }

    /// A wall clock the test sets by hand.
    struct Manual(AtomicU64);
    impl WallClock for Manual {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ready_result_after_the_monotonic_deadline_is_dropped() {
        let clock = Manual(AtomicU64::new(1_000));
        let deadline = Deadline::new(1_010, &clock).unwrap();
        tokio::time::advance(Duration::from_millis(11)).await;
        assert_eq!(by_deadline(&deadline, &clock, async { 7 }).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn result_before_deadline_is_kept_and_late_one_dropped() {
        let clock = Manual(AtomicU64::new(1_000));
        let deadline = Deadline::new(1_010, &clock).unwrap();
        assert_eq!(by_deadline(&deadline, &clock, async { 7 }).await, Some(7));
        let late = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            7
        };
        assert_eq!(by_deadline(&deadline, &clock, late).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn wall_clock_jump_past_the_deadline_drops_the_result() {
        // The monotonic deadline is still ahead, but the wall clock stepped past the wire deadline
        // while the work ran.
        let clock = Manual(AtomicU64::new(1_000));
        let deadline = Deadline::new(5_000, &clock).unwrap();
        let work = async {
            clock.0.store(5_001, Ordering::SeqCst);
            7
        };
        assert_eq!(by_deadline(&deadline, &clock, work).await, None);
        assert!(!deadline.open(&clock));
        clock.0.store(5_000, Ordering::SeqCst);
        assert!(
            deadline.open(&clock),
            "the deadline millisecond itself is still open"
        );
    }

    #[test]
    fn deadline_needs_time_left_on_the_wall_clock() {
        let clock = Manual(AtomicU64::new(1_000));
        assert!(Deadline::new(0, &clock).is_none());
        assert!(Deadline::new(1_000, &clock).is_none());
        let d = Deadline::new(u64::MAX, &clock).expect("far deadlines do not overflow");
        assert_eq!(d.unix_ms(), u64::MAX);
        assert!(SystemClock.now_unix_ms() > 1_700_000_000_000);
    }

    #[test]
    fn deadline_in_the_past_or_unset_has_no_time_left() {
        assert_eq!(time_left(0, 1_000), None);
        assert_eq!(time_left(999, 1_000), None);
        assert_eq!(time_left(1_000, 1_000), None);
        assert_eq!(time_left(1_250, 1_000), Some(Duration::from_millis(250)));
        assert!(now_unix_ms() > 1_700_000_000_000);
    }
}
