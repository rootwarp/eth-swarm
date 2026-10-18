//! The two receive clocks: monotonic and wall.
//!
//! [`Clock::now`] is the first thing done with an arrival, before any decode. The monotonic
//! clock orders arrivals and measures intervals between them (envelope-relative offsets, gaps)
//! immune to wall-clock steps; the wall clock places them against the slot schedule
//! (slot-relative offsets), so it is only as good as the host's time sync, whose offset the
//! collector samples ([`super::ntp`]).

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// One receive time on both clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stamp {
    /// Nanoseconds since the clock's origin (`Instant`).
    pub mono_ns: u64,
    /// Unix nanoseconds (`SystemTime`); 0 if the host clock is before 1970.
    pub wall_ns: u64,
}

/// A source of [`Stamp`]s. Injectable, so tests run on a scripted clock.
pub trait Clock: Send + Sync {
    /// Now, on both clocks.
    fn now(&self) -> Stamp;
}

/// The host's clocks: `Instant` since construction and `SystemTime`.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose monotonic origin is now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Stamp {
        let mono = self.origin.elapsed();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Stamp {
            mono_ns: saturating_ns(mono.as_nanos()),
            wall_ns: saturating_ns(wall.as_nanos()),
        }
    }
}

fn saturating_ns(ns: u128) -> u64 {
    u64::try_from(ns).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_monotonic_and_near_system_time() {
        let clock = SystemClock::new();
        let a = clock.now();
        let b = clock.now();
        assert!(b.mono_ns >= a.mono_ns);
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let diff = (wall.as_nanos() as i128 - b.wall_ns as i128).abs();
        assert!(diff < 5_000_000_000, "{diff} ns from SystemTime");
        assert_eq!(saturating_ns(u128::MAX), u64::MAX);
        let _ = SystemClock::default().now();
    }
}
