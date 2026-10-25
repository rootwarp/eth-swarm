//! The wait before a stream from a peer service is opened again ([`Backoff`]).

use std::time::Duration;

/// The first wait before a stream is opened again.
pub const FIRST_BACKOFF: Duration = Duration::from_secs(1);

/// The longest wait before a stream is opened again.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// The wait before a stream is opened again: [`FIRST_BACKOFF`], doubled after each try to
/// [`MAX_BACKOFF`], and [`FIRST_BACKOFF`] again after a stream that delivered a message. Thus a
/// peer that restarts after a long run is read again within a second, and a peer that fails at
/// each try is not tried more than once per [`MAX_BACKOFF`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            next: FIRST_BACKOFF,
        }
    }
}

impl Backoff {
    /// The wait after a stream that ended or failed, which `delivered` a message or not.
    pub fn after(&mut self, delivered: bool) -> Duration {
        if delivered {
            self.next = FIRST_BACKOFF;
        }
        let wait = self.next;
        self.next = (self.next * 2).min(MAX_BACKOFF);
        wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_to_its_cap_and_resets_after_a_delivery() {
        let mut backoff = Backoff::default();
        let waits: Vec<u64> = (0..7).map(|_| backoff.after(false).as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30]);
        // A stream that delivered: the next wait is the first again, then it doubles.
        assert_eq!(backoff.after(true), FIRST_BACKOFF);
        assert_eq!(backoff.after(false), FIRST_BACKOFF * 2);
        assert_eq!(backoff.after(true), FIRST_BACKOFF);
    }
}
