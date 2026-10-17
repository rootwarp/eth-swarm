//! Pubkey feed lag behind finality.
//!
//! The feed's finalized epoch is the finalized checkpoint whose registry the cache holds in full;
//! the chain's finalized epoch is cl-chain's current one. Their difference is the lag. A feed
//! ahead of the chain has lag 0 here (cl-verify refuses such epochs before they reach this).
//!
//! The bound: a validator is activated only once the finality that covers its deposit is reached
//! (`is_eligible_for_activation`), and its activation epoch is then
//! `compute_activation_exit_epoch(epoch) = epoch + 1 + MAX_SEED_LOOKAHEAD` (`phase0/beacon-chain.md`).
//! While finality advances normally, it therefore cannot sign until 1 + `MAX_SEED_LOOKAHEAD` (5)
//! epochs after that finality, so a lag of up to `MAX_SEED_LOOKAHEAD` (4) epochs cannot hide a
//! usable signer, and the alert is for a lag past it.
//!
//! While finality stalls, that does not hold: `epoch` is the current epoch, not the finalized one,
//! so a validator eligible at 96 and activated during 98 signs from 103, while finality stuck at 99
//! leaves the feed at `(95, 99)`, a lag of 4 with no alert and the signer missing. Such signers'
//! gossip is IGNOREd (`UnknownIndex`) until the feed catches up: lost coverage, never a wrong key.
//! Callers pass `MAX_SEED_LOOKAHEAD` as `max_lag`, so this crate needs no preset.

/// Epochs the feed trails the chain's finalized epoch; 0 when the feed is level or ahead.
#[must_use]
pub const fn feed_lag_epochs(feed_finalized_epoch: u64, chain_finalized_epoch: u64) -> u64 {
    chain_finalized_epoch.saturating_sub(feed_finalized_epoch)
}

/// Whether the feed trails the chain's finalized epoch by more than `max_lag` epochs.
#[must_use]
pub const fn feed_lag_exceeded(
    feed_finalized_epoch: u64,
    chain_finalized_epoch: u64,
    max_lag: u64,
) -> bool {
    feed_lag_epochs(feed_finalized_epoch, chain_finalized_epoch) > max_lag
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// `MAX_SEED_LOOKAHEAD` in both presets; the real bound comes from `network-config`.
    const MAX_LAG: u64 = 4;

    #[test]
    fn lag_at_bound_does_not_alert_and_one_past_does() {
        assert_eq!(feed_lag_epochs(96, 100), 4);
        assert!(!feed_lag_exceeded(96, 100, MAX_LAG));
        assert_eq!(feed_lag_epochs(95, 100), 5);
        assert!(feed_lag_exceeded(95, 100, MAX_LAG));
    }

    #[test]
    fn lag_no_underflow() {
        assert_eq!(feed_lag_epochs(105, 100), 0);
        assert!(!feed_lag_exceeded(105, 100, MAX_LAG));
        assert_eq!(feed_lag_epochs(u64::MAX, 0), 0);
        assert!(!feed_lag_exceeded(u64::MAX, 0, 0));
    }

    #[test]
    fn level_feed_has_no_lag() {
        assert_eq!(feed_lag_epochs(100, 100), 0);
        assert!(!feed_lag_exceeded(100, 100, 0));
    }

    #[test]
    fn lag_spans_the_whole_epoch_range() {
        assert_eq!(feed_lag_epochs(0, u64::MAX), u64::MAX);
        assert!(feed_lag_exceeded(0, u64::MAX, MAX_LAG));
        assert!(!feed_lag_exceeded(0, u64::MAX, u64::MAX));
    }

    proptest! {
        #[test]
        fn alert_iff_chain_is_more_than_max_lag_ahead(
            feed in any::<u64>(),
            chain in any::<u64>(),
            max_lag in 0u64..16,
        ) {
            let expected = chain > feed && chain - feed > max_lag;
            prop_assert_eq!(feed_lag_exceeded(feed, chain, max_lag), expected);
        }
    }
}
