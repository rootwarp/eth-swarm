//! Wire helpers shared by the server and the client mapping: `common.v1.Error` construction and
//! `Error` <-> `tonic::Status` (from [`ipc::error`]), and deadline arithmetic.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::{timeout_at, Instant};

pub use ipc::error::{error_from_status, inbound_error, to_status, wire_error, MAX_DETAIL_BYTES};

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
///
/// The deadline millisecond itself is open, everywhere: `verify.proto` answers a request
/// `DEADLINE_EXCEEDED` once it is *past* its deadline and resolves signers while
/// `now <= deadline_unix_ms`. So a request read at exactly `unix_ms` is admitted
/// ([`Deadline::new`]), [`Deadline::open`] holds while the wall clock reads at most `unix_ms`, and
/// the monotonic instant is the end of that millisecond (`unix_ms + 1` as read on admission).
/// An unset (0) deadline is never open.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    at: Instant,
    unix_ms: u64,
}

impl Deadline {
    /// `None` if `unix_ms` is unset (0) or already past on `clock` (`now > unix_ms`).
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
    match race_deadline(deadline, clock, fut).await {
        Timed::InTime(out) => Some(out),
        Timed::Late(_) | Timed::TimedOut => None,
    }
}

/// What became of a future raced against a [`Deadline`].
#[derive(Debug, PartialEq, Eq)]
pub enum Timed<T> {
    /// Ready while the deadline was still open.
    InTime(T),
    /// Ready, but only once the deadline had passed on either clock.
    Late(T),
    /// Not ready by the deadline; the future was dropped.
    TimedOut,
}

/// [`by_deadline`] that keeps a result which became ready after the deadline, so the caller
/// can account for it ([`Timed::Late`]) instead of losing it.
pub async fn race_deadline<F: Future>(
    deadline: &Deadline,
    clock: &dyn WallClock,
    fut: F,
) -> Timed<F::Output> {
    match timeout_at(deadline.at, fut).await {
        Err(_) => Timed::TimedOut,
        Ok(out) if deadline.open(clock) => Timed::InTime(out),
        Ok(out) => Timed::Late(out),
    }
}

/// Milliseconds since the Unix epoch (0 if the clock is before it).
#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Time left until the end of the deadline millisecond (see [`Deadline`]), or `None` if the
/// deadline is past (`now > deadline`). An unset (0) deadline has always passed: work is never
/// started without one.
#[must_use]
pub fn time_left(deadline_unix_ms: u64, now_unix_ms: u64) -> Option<Duration> {
    if deadline_unix_ms == 0 {
        return None;
    }
    deadline_unix_ms
        .checked_sub(now_unix_ms)
        .map(|ms| Duration::from_millis(ms.saturating_add(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::ErrorCode;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tonic::{Code, Status};

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
    fn deadline_needs_a_set_deadline_not_yet_past_on_the_wall_clock() {
        let clock = Manual(AtomicU64::new(1_000));
        assert!(Deadline::new(0, &clock).is_none());
        assert!(Deadline::new(999, &clock).is_none());
        let d = Deadline::new(u64::MAX, &clock).expect("far deadlines do not overflow");
        assert_eq!(d.unix_ms(), u64::MAX);
        assert!(SystemClock.now_unix_ms() > 1_700_000_000_000);
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_millisecond_itself_is_open_on_admission_and_after() {
        // Read at exactly unix_ms: not yet past, so admitted, and open for that whole millisecond.
        let clock = Manual(AtomicU64::new(1_000));
        let d = Deadline::new(1_000, &clock).expect("now == unix_ms is not past");
        assert!(d.open(&clock));
        assert_eq!(by_deadline(&d, &clock, async { 7 }).await, Some(7));
        tokio::time::advance(Duration::from_micros(999)).await;
        assert!(d.open(&clock), "still inside the deadline millisecond");
        tokio::time::advance(Duration::from_micros(1)).await;
        assert!(
            !d.open(&clock),
            "the next millisecond is past on the monotonic clock"
        );
        clock.0.store(1_001, Ordering::SeqCst);
        assert!(
            Deadline::new(1_000, &clock).is_none(),
            "one ms later is past"
        );
    }

    #[test]
    fn deadline_in_the_past_or_unset_has_no_time_left() {
        assert_eq!(time_left(0, 1_000), None);
        assert_eq!(time_left(999, 1_000), None);
        assert_eq!(
            time_left(1_000, 1_000),
            Some(Duration::from_millis(1)),
            "the deadline millisecond itself is left"
        );
        assert_eq!(time_left(1_250, 1_000), Some(Duration::from_millis(251)));
        assert_eq!(
            time_left(u64::MAX, 0),
            Some(Duration::from_millis(u64::MAX))
        );
        assert!(now_unix_ms() > 1_700_000_000_000);
    }
}
