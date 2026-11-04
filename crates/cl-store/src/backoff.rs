//! Bounded, jittered exponential backoff: cl-store's pace for subscribing again to cl-chain's
//! events ([`crate::follow`]) and for reopening the store env ([`crate::recover`]).
//!
//! The `n`th delay (from 0) is drawn from `[c/2, c]`, with `c = min(base * 2^n, cap)` ("equal
//! jitter"). Many clients restarting together therefore spread out, and no delay is below half
//! its ceiling or above the cap. When the cap is `base * 2^k` (both users' constants are), each
//! delay is at least the one before, until they all fall in `[cap/2, cap]`.

use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    time::Duration,
};

/// The delays between the attempts of one thing that keeps failing.
#[derive(Clone, Debug)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    /// Doublings so far; it stops growing at the cap.
    step: u32,
    /// SplitMix64 state, seeded per backoff from the process's random hasher keys.
    rng: u64,
}

impl Backoff {
    /// `base` doubling up to `cap` (at least `base`).
    #[must_use]
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap: cap.max(base),
            step: 0,
            rng: RandomState::new().build_hasher().finish(),
        }
    }

    /// The delay before the next attempt.
    pub fn next_delay(&mut self) -> Duration {
        let ceiling = 1u32
            .checked_shl(self.step)
            .and_then(|factor| self.base.checked_mul(factor))
            .map_or(self.cap, |c| c.min(self.cap));
        if ceiling < self.cap {
            self.step += 1;
        }
        let half = ceiling / 2;
        let span = u64::try_from((ceiling - half).as_nanos()).unwrap_or(u64::MAX);
        half + Duration::from_nanos(self.draw() % span.saturating_add(1))
    }

    /// Back to the first delay, after a success.
    pub fn reset(&mut self) {
        self.step = 0;
    }

    /// SplitMix64: a jitter, not a secret.
    fn draw(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
