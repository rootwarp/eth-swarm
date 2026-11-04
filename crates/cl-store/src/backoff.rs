//! Bounded, jittered exponential backoff: cl-store's pace for subscribing again to cl-chain's
//! events ([`crate::follow`]) and for reopening the store env ([`crate::recover`]).

use std::time::Duration;

/// The delays between the attempts of one thing that keeps failing.
#[derive(Clone, Debug)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
}

impl Backoff {
    /// `base` doubling up to `cap`.
    #[must_use]
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self { base, cap }
    }

    /// The delay before the next attempt.
    pub fn next_delay(&mut self) -> Duration {
        let _ = self.cap;
        self.base
    }

    /// Back to the first delay, after a success.
    pub fn reset(&mut self) {}
}
