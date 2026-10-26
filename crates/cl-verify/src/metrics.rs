//! cl-verify metrics on a prometheus-client [`Registry`], served by the service runtime.
//!
//! Pubkey feed lag ([`FeedLagMetrics`]): how many epochs a cache's finalized registry trails
//! cl-chain's finalized epoch, and an alert once that passes [`MAX_FEED_LAG_EPOCHS`]. The bound,
//! and when it holds, are in [`cl_verify_cache::lag`]. Each key feed has its own series, by the
//! `namespace` label ([`FeedNamespace`]): `validator` for PubkeyFeed and `builder` for
//! BuilderKeyFeed. The two series never share a value or a finality history.
//!
//! The epochs come from cl-chain's feed frames and are checked before use ([`check_epochs`]):
//! finality only moves forward, so a chain epoch below the highest one already evaluated is
//! refused, and so is a feed epoch past the chain epoch. A frame that omits both fields decodes as
//! `(0, 0)` and is therefore refused once any non-zero chain epoch has been seen.

use std::sync::atomic::AtomicU64;
use std::sync::{Mutex, MutexGuard, PoisonError};

use cl_verify_cache::lag::{feed_lag_epochs, feed_lag_exceeded};
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

/// Largest feed lag, in epochs, that raises no alert: `MAX_SEED_LOOKAHEAD` from the preset. While
/// finality advances normally, a deposit activates 1 + `MAX_SEED_LOOKAHEAD` epochs after the
/// finality that covers it; while finality stalls, a smaller lag can still miss recent signers.
pub const MAX_FEED_LAG_EPOCHS: u64 = network_config::MAX_SEED_LOOKAHEAD;

/// Why a frame's finalized epochs are refused (a contract violation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LagEpochError {
    /// The chain epoch is below one already evaluated: finality never moves back.
    #[error("chain_finalized_epoch {chain} is below {highest}, already reported")]
    ChainEpochBackwards { chain: u64, highest: u64 },
    /// The feed claims a finalized registry newer than cl-chain's finality.
    #[error("feed_finalized_epoch {feed} is past chain_finalized_epoch {chain}")]
    FeedAheadOfChain { feed: u64, chain: u64 },
}

/// Checks one frame's epochs against the highest chain epoch already accepted, if any.
pub fn check_epochs(
    feed_finalized_epoch: u64,
    chain_finalized_epoch: u64,
    highest_chain_epoch: Option<u64>,
) -> Result<(), LagEpochError> {
    if let Some(highest) = highest_chain_epoch.filter(|h| chain_finalized_epoch < *h) {
        return Err(LagEpochError::ChainEpochBackwards {
            chain: chain_finalized_epoch,
            highest,
        });
    }
    if feed_finalized_epoch > chain_finalized_epoch {
        return Err(LagEpochError::FeedAheadOfChain {
            feed: feed_finalized_epoch,
            chain: chain_finalized_epoch,
        });
    }
    Ok(())
}

/// A change of the feed-lag alert, returned by [`NamespaceLag::update`] and logged once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedLagTransition {
    /// The lag passed [`MAX_FEED_LAG_EPOCHS`].
    Raised { lag_epochs: u64 },
    /// The lag fell back to [`MAX_FEED_LAG_EPOCHS`] or below.
    Cleared { lag_epochs: u64 },
}

/// The key feed that a lag series describes: the `namespace` label of the gauges.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum FeedNamespace {
    /// PubkeyFeed: the validator registry.
    Validator,
    /// BuilderKeyFeed: the builder registry.
    Builder,
}

impl FeedNamespace {
    /// Every namespace, in label order.
    pub const ALL: [Self; 2] = [Self::Validator, Self::Builder];

    /// The label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::Builder => "builder",
        }
    }
}

impl EncodeLabelValue for FeedNamespace {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> std::fmt::Result {
        std::fmt::Write::write_str(encoder, self.as_str())
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct NamespaceLabel {
    namespace: FeedNamespace,
}

/// The `verify_pubkey_feed_lag_epochs{namespace}` and `verify_pubkey_feed_lag_alert{namespace}`
/// (0/1) gauges, one series per [`FeedNamespace`], each at 0 from the start.
#[derive(Debug)]
pub struct FeedLagMetrics {
    validator: NamespaceLag,
    builder: NamespaceLag,
}

impl FeedLagMetrics {
    /// Creates both gauge families with every namespace at 0 (no lag, no alert) and registers
    /// them in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let lag_epochs = Family::<NamespaceLabel, Gauge<u64, AtomicU64>>::default();
        let alert = Family::<NamespaceLabel, Gauge>::default();
        registry.register(
            "verify_pubkey_feed_lag_epochs",
            "Epochs a key feed's finalized registry trails cl-chain's finalized epoch",
            lag_epochs.clone(),
        );
        registry.register(
            "verify_pubkey_feed_lag_alert",
            "1 while a key feed trails finality by more than MAX_SEED_LOOKAHEAD epochs",
            alert.clone(),
        );
        let series = |namespace| {
            let label = NamespaceLabel { namespace };
            NamespaceLag {
                namespace,
                lag_epochs: lag_epochs.get_or_create(&label).clone(),
                alert: alert.get_or_create(&label).clone(),
                state: Mutex::new(LagState::default()),
            }
        };
        Self {
            validator: series(FeedNamespace::Validator),
            builder: series(FeedNamespace::Builder),
        }
    }

    /// The PubkeyFeed series (`namespace="validator"`).
    #[must_use]
    pub fn validator(&self) -> &NamespaceLag {
        &self.validator
    }

    /// The BuilderKeyFeed series (`namespace="builder"`).
    #[must_use]
    pub fn builder(&self) -> &NamespaceLag {
        &self.builder
    }

    /// The series of `namespace`.
    #[must_use]
    pub fn namespace(&self, namespace: FeedNamespace) -> &NamespaceLag {
        match namespace {
            FeedNamespace::Validator => &self.validator,
            FeedNamespace::Builder => &self.builder,
        }
    }
}

/// The lag series of one [`FeedNamespace`].
///
/// The server [`check`](Self::check)s a feed frame's epochs before applying it, refusing the
/// frame on an error, and calls [`update`](Self::update) once the frame is applied (and, for
/// PubkeyFeed, once when the restore completes). cl-chain sends a frame on every finality update,
/// so both inputs are re-evaluated. The gauges change only on an accepted update; the alert logs
/// only when it changes.
#[derive(Debug)]
pub struct NamespaceLag {
    namespace: FeedNamespace,
    lag_epochs: Gauge<u64, AtomicU64>,
    alert: Gauge,
    /// Held across the check and the gauge writes, so concurrent updates publish in chain-epoch
    /// order and log their transitions in that order too.
    state: Mutex<LagState>,
}

#[derive(Debug, Default)]
struct LagState {
    alerting: bool,
    /// The highest chain epoch accepted by [`NamespaceLag::update`].
    highest_chain_epoch: Option<u64>,
}

impl NamespaceLag {
    /// Whether a frame with these epochs may be applied ([`check_epochs`] against the highest
    /// chain epoch accepted so far). Changes nothing.
    pub fn check(
        &self,
        feed_finalized_epoch: u64,
        chain_finalized_epoch: u64,
    ) -> Result<(), LagEpochError> {
        let state = self.state();
        check_epochs(
            feed_finalized_epoch,
            chain_finalized_epoch,
            state.highest_chain_epoch,
        )
    }

    /// Re-evaluates the lag of the feed at `feed_finalized_epoch` behind cl-chain at
    /// `chain_finalized_epoch`, sets both gauges and returns the alert transition, if any. The
    /// epochs are checked again under the same lock: an update that a higher chain epoch has
    /// overtaken since its [`check`](Self::check) is refused and changes nothing. Each
    /// transition is logged once: a warning when raised, info when cleared.
    pub fn update(
        &self,
        feed_finalized_epoch: u64,
        chain_finalized_epoch: u64,
    ) -> Result<Option<FeedLagTransition>, LagEpochError> {
        let mut state = self.state();
        check_epochs(
            feed_finalized_epoch,
            chain_finalized_epoch,
            state.highest_chain_epoch,
        )?;
        state.highest_chain_epoch = Some(chain_finalized_epoch);
        let lag_epochs = feed_lag_epochs(feed_finalized_epoch, chain_finalized_epoch);
        let exceeded = feed_lag_exceeded(
            feed_finalized_epoch,
            chain_finalized_epoch,
            MAX_FEED_LAG_EPOCHS,
        );
        self.lag_epochs.set(lag_epochs);
        self.alert.set(i64::from(exceeded));
        if state.alerting == exceeded {
            return Ok(None);
        }
        state.alerting = exceeded;
        if exceeded {
            tracing::warn!(
                lag_epochs,
                max_lag_epochs = MAX_FEED_LAG_EPOCHS,
                feed_finalized_epoch,
                chain_finalized_epoch,
                namespace = self.namespace.as_str(),
                "pubkey feed lag alert raised"
            );
            Ok(Some(FeedLagTransition::Raised { lag_epochs }))
        } else {
            tracing::info!(
                lag_epochs,
                max_lag_epochs = MAX_FEED_LAG_EPOCHS,
                feed_finalized_epoch,
                chain_finalized_epoch,
                namespace = self.namespace.as_str(),
                "pubkey feed lag alert cleared"
            );
            Ok(Some(FeedLagTransition::Cleared { lag_epochs }))
        }
    }

    /// The current `verify_pubkey_feed_lag_epochs` value of this namespace.
    pub fn lag_epochs(&self) -> u64 {
        self.lag_epochs.get()
    }

    /// The current `verify_pubkey_feed_lag_alert` value of this namespace: 1 while raised, else 0.
    pub fn alert(&self) -> i64 {
        self.alert.get()
    }

    fn state(&self) -> MutexGuard<'_, LagState> {
        // The state is valid whatever a panicking holder did, so poisoning is ignored.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::encoding::text::encode;

    fn registered() -> (Registry, FeedLagMetrics) {
        let mut registry = Registry::default();
        let metrics = FeedLagMetrics::register(&mut registry);
        (registry, metrics)
    }

    fn scrape(registry: &Registry) -> String {
        let mut text = String::new();
        encode(&mut text, registry).unwrap();
        text
    }

    #[test]
    fn bound_is_max_seed_lookahead() {
        assert_eq!(MAX_FEED_LAG_EPOCHS, network_config::MAX_SEED_LOOKAHEAD);
        // compute_activation_exit_epoch: a deposit activates 1 + MAX_SEED_LOOKAHEAD = 5 epochs on.
        assert_eq!(1 + MAX_FEED_LAG_EPOCHS, 5);
    }

    #[test]
    fn lag_of_four_does_not_alert_and_five_does() {
        let (_, all) = registered();
        let metrics = all.validator();
        assert_eq!(metrics.update(96, 100), Ok(None));
        assert_eq!((metrics.lag_epochs(), metrics.alert()), (4, 0));
        assert_eq!(
            metrics.update(95, 100),
            Ok(Some(FeedLagTransition::Raised { lag_epochs: 5 }))
        );
        assert_eq!((metrics.lag_epochs(), metrics.alert()), (5, 1));
    }

    #[test]
    fn a_feed_ahead_of_the_chain_is_refused_and_keeps_the_gauges() {
        let (_, all) = registered();
        let metrics = all.validator();
        metrics.update(95, 100).unwrap();
        let ahead = LagEpochError::FeedAheadOfChain {
            feed: 105,
            chain: 100,
        };
        assert_eq!(metrics.check(105, 100), Err(ahead));
        assert_eq!(metrics.update(105, 100), Err(ahead));
        assert_eq!((metrics.lag_epochs(), metrics.alert()), (5, 1));
    }

    #[test]
    fn finality_never_moves_back() {
        let (_, all) = registered();
        let metrics = all.validator();
        metrics.update(95, 100).unwrap();
        // A frame that omits both epochs decodes as (0, 0).
        for (feed, chain) in [(0, 0), (95, 99)] {
            let back = LagEpochError::ChainEpochBackwards {
                chain,
                highest: 100,
            };
            assert_eq!(metrics.check(feed, chain), Err(back));
            assert_eq!(metrics.update(feed, chain), Err(back));
        }
        assert_eq!((metrics.lag_epochs(), metrics.alert()), (5, 1));
        // The same chain epoch again, and a zero feed epoch, are fine.
        assert_eq!(metrics.check(95, 100), Ok(()));
        assert_eq!(metrics.update(0, 100), Ok(None));
        assert_eq!((metrics.lag_epochs(), metrics.alert()), (100, 1));
    }

    #[test]
    fn an_overtaken_update_is_not_published() {
        let (_, all) = registered();
        let metrics = all.validator();
        // Two streams pass the check in one order and publish in the other.
        assert_eq!(metrics.check(97, 100), Ok(()));
        assert_eq!(metrics.check(95, 101), Ok(()));
        assert_eq!(
            metrics.update(95, 101),
            Ok(Some(FeedLagTransition::Raised { lag_epochs: 6 }))
        );
        assert_eq!(
            metrics.update(97, 100),
            Err(LagEpochError::ChainEpochBackwards {
                chain: 100,
                highest: 101
            })
        );
        assert_eq!((metrics.lag_epochs(), metrics.alert()), (6, 1));
    }

    #[test]
    fn epochs_are_checked_against_the_highest_chain_epoch() {
        assert_eq!(check_epochs(4, 9, None), Ok(()));
        assert_eq!(check_epochs(9, 9, Some(9)), Ok(()));
        assert_eq!(
            check_epochs(10, 9, None),
            Err(LagEpochError::FeedAheadOfChain { feed: 10, chain: 9 })
        );
        assert_eq!(
            check_epochs(0, 8, Some(9)),
            Err(LagEpochError::ChainEpochBackwards {
                chain: 8,
                highest: 9
            })
        );
        assert!(LagEpochError::FeedAheadOfChain { feed: 10, chain: 9 }
            .to_string()
            .contains("10"));
    }

    #[test]
    fn feed_lag_namespace() {
        let (registry, metrics) = registered();
        let text = scrape(&registry);
        for ns in ["validator", "builder"] {
            for gauge in [
                "verify_pubkey_feed_lag_epochs",
                "verify_pubkey_feed_lag_alert",
            ] {
                assert!(
                    text.contains(&format!("\n{gauge}{{namespace=\"{ns}\"}} 0\n")),
                    "{text}"
                );
            }
        }
        // A builder feed 5 epochs behind finality raises the builder alert only.
        assert_eq!(
            metrics.builder().update(95, 100),
            Ok(Some(FeedLagTransition::Raised { lag_epochs: 5 }))
        );
        let text = scrape(&registry);
        assert!(
            text.contains("\nverify_pubkey_feed_lag_alert{namespace=\"builder\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("\nverify_pubkey_feed_lag_epochs{namespace=\"builder\"} 5\n"),
            "{text}"
        );
        assert!(
            text.contains("\nverify_pubkey_feed_lag_alert{namespace=\"validator\"} 0\n"),
            "{text}"
        );
        assert_eq!(
            (
                metrics.validator().lag_epochs(),
                metrics.validator().alert()
            ),
            (0, 0)
        );
        // Lag 4 clears it.
        assert_eq!(
            metrics.builder().update(96, 100),
            Ok(Some(FeedLagTransition::Cleared { lag_epochs: 4 }))
        );
        let text = scrape(&registry);
        assert!(
            text.contains("\nverify_pubkey_feed_lag_alert{namespace=\"builder\"} 0\n"),
            "{text}"
        );
        // Each namespace checks finality against its own history.
        metrics.validator().update(90, 120).unwrap();
        assert_eq!(metrics.builder().check(96, 100), Ok(()));
        assert_eq!(
            metrics.namespace(FeedNamespace::Builder).alert(),
            metrics.builder().alert()
        );
        assert_eq!(metrics.namespace(FeedNamespace::Validator).lag_epochs(), 30);
    }

    /// The log lines per transition are checked in `tests/feed_lag_log.rs`, alone in its binary:
    /// tracing caches callsite interest globally, so a scoped subscriber races parallel tests.
    #[test]
    fn alert_clears() {
        let (_, all) = registered();
        let metrics = all.validator();
        let transitions = [(95, 100), (95, 100), (96, 101), (97, 101), (98, 101)]
            .map(|(feed, chain)| metrics.update(feed, chain).unwrap());
        assert_eq!(
            transitions,
            [
                Some(FeedLagTransition::Raised { lag_epochs: 5 }),
                None,
                None,
                Some(FeedLagTransition::Cleared { lag_epochs: 4 }),
                None,
            ]
        );
        assert_eq!((metrics.lag_epochs(), metrics.alert()), (3, 0));
    }

    #[test]
    fn metrics_expose_feed_lag() {
        let (registry, all) = registered();
        let metrics = all.validator();
        metrics.update(95, 100).unwrap();
        let text = scrape(&registry);
        assert!(
            text.contains("# TYPE verify_pubkey_feed_lag_epochs gauge\n"),
            "{text}"
        );
        assert!(
            text.contains("\nverify_pubkey_feed_lag_epochs{namespace=\"validator\"} 5\n"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE verify_pubkey_feed_lag_alert gauge\n"),
            "{text}"
        );
        assert!(
            text.contains("\nverify_pubkey_feed_lag_alert{namespace=\"validator\"} 1\n"),
            "{text}"
        );

        metrics.update(96, 100).unwrap();
        let text = scrape(&registry);
        assert!(
            text.contains("\nverify_pubkey_feed_lag_epochs{namespace=\"validator\"} 4\n"),
            "{text}"
        );
        assert!(
            text.contains("\nverify_pubkey_feed_lag_alert{namespace=\"validator\"} 0\n"),
            "{text}"
        );
    }

    #[test]
    fn gauges_start_at_zero() {
        let (registry, _) = registered();
        let text = scrape(&registry);
        assert!(
            text.contains("\nverify_pubkey_feed_lag_epochs{namespace=\"validator\"} 0\n"),
            "{text}"
        );
        assert!(
            text.contains("\nverify_pubkey_feed_lag_alert{namespace=\"validator\"} 0\n"),
            "{text}"
        );
    }
}
