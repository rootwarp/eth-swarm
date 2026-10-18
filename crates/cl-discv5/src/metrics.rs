//! cl-discv5 metrics, on the service's prometheus-client [`Registry`].
//!
//! - `discv5_table_evictions_total{reason}`: records [`Discovery`](crate::service::Discovery)
//!   removed from discv5's routing table because they fail the rules discv5 0.12 does not
//!   apply on every insertion: `ip_rule` (an address outside the IP rules of the mode, the
//!   `table_filter`) or `fork_digest` (another fork digest, or none). Counted once per removal,
//!   whether the event stream or the periodic sweep found the record.

pub use crate::service::EvictionReason;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::fmt::Write as _;

impl EncodeLabelValue for EvictionReason {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> std::fmt::Result {
        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReasonLabel {
    reason: EvictionReason,
}

/// The routing-table eviction counter (see the module docs). Clones share the counts; the
/// default is unregistered and still counts.
#[derive(Clone, Debug, Default)]
pub struct EvictionMetrics {
    evictions: Family<ReasonLabel, Counter>,
}

impl EvictionMetrics {
    /// Creates the counter with every reason at 0 and registers it in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self::default();
        for reason in EvictionReason::ALL {
            drop(metrics.evictions.get_or_create(&ReasonLabel { reason }));
        }
        registry.register(
            "discv5_table_evictions",
            "Routing-table records removed for failing the IP rules or the fork digest, by reason",
            metrics.evictions.clone(),
        );
        metrics
    }

    /// Counts one record removed for `reason`.
    pub fn record(&self, reason: EvictionReason) {
        self.evictions.get_or_create(&ReasonLabel { reason }).inc();
    }

    /// The records removed for `reason` so far.
    #[must_use]
    pub fn evictions(&self, reason: EvictionReason) -> u64 {
        self.evictions.get_or_create(&ReasonLabel { reason }).get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::encoding::text::encode;

    fn text(registry: &Registry) -> String {
        let mut text = String::new();
        encode(&mut text, registry).unwrap();
        text
    }

    #[test]
    fn evictions_are_counted_by_reason_and_exported() {
        let mut registry = Registry::default();
        let metrics = EvictionMetrics::register(&mut registry);
        let exported = text(&registry);
        assert!(
            exported.contains(r#"discv5_table_evictions_total{reason="ip_rule"} 0"#),
            "{exported}"
        );
        assert!(
            exported.contains(r#"discv5_table_evictions_total{reason="fork_digest"} 0"#),
            "{exported}"
        );

        metrics.record(EvictionReason::IpRule);
        metrics.record(EvictionReason::IpRule);
        metrics.clone().record(EvictionReason::ForkDigest);
        assert_eq!(metrics.evictions(EvictionReason::IpRule), 2);
        assert_eq!(metrics.evictions(EvictionReason::ForkDigest), 1);
        let exported = text(&registry);
        assert!(
            exported.contains(r#"discv5_table_evictions_total{reason="ip_rule"} 2"#),
            "{exported}"
        );
        assert!(
            exported.contains(r#"discv5_table_evictions_total{reason="fork_digest"} 1"#),
            "{exported}"
        );

        // Unregistered metrics still count.
        let unregistered = EvictionMetrics::default();
        unregistered.record(EvictionReason::ForkDigest);
        assert_eq!(unregistered.evictions(EvictionReason::ForkDigest), 1);
        assert_eq!(unregistered.evictions(EvictionReason::IpRule), 0);
    }
}
