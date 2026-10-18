//! The req/resp protocols the spec makes MUST-support that the probe does not register:
//! `BeaconBlocksByHead` v1 (`fulu/p2p-interface.md` L796–863) and
//! `ExecutionPayloadEnvelopesByRange` v1 and `ExecutionPayloadEnvelopesByRoot` v1
//! (`gloas/p2p-interface.md` L1396, L1446). Written probe deviations (the README's
//! §Deviations), closed by [6.42] and [6.19b].
//!
//! # Rejection
//!
//! No behaviour of the probe swarm offers these ids, so multistream-select answers the
//! peer's proposal `na` and the negotiation fails (`phase0/p2p-interface.md` L187–196): no
//! handler sees a stream, nothing is read or written past the negotiation, and the connection
//! stays up. No error chunk goes out: `3: ResourceUnavailable` is valid only where a protocol
//! specifies it, never as a generic "unsupported" answer.
//!
//! # Counting
//!
//! Every refused proposal of one of these ids counts in
//! `rpc_inbound_unsupported_total{protocol}` ([`RpcMetrics`]), so the probe shows how often
//! peers ask. The pinned rust-libp2p reports a failed inbound negotiation to no behaviour and
//! no handler (the connection only logs that no protocol was agreed), and the one place it names
//! the refused protocol is `multistream_select`'s `Listener: rejecting protocol` debug event,
//! with the proposal in its `protocol` field. [`layer`] counts from that event: a `tracing`
//! layer the owner adds to its subscriber (`tracing_subscriber::registry().with(...)`, next to
//! its formatting layer); without it the counter stays at 0. It enables that one debug event for
//! itself only, so the other layers' levels are unchanged, and reads both fields into fixed
//! buffers, so a peer's proposal costs no allocation and only the three [`Unsupported`] names
//! ever become label values.
//!
//! `tracing` caches each callsite's interest process-wide: install the subscriber before the
//! swarm runs, as the process's default.

use crate::rpc::metrics::RpcMetrics;
use std::fmt::{self, Write as _};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// The `tracing` target of multistream-select's listener: the module that answers proposals.
const LISTENER_TARGET: &str = "multistream_select::listener_select";

/// The message of the listener's event for a refused proposal.
const REJECTING: &str = "Listener: rejecting protocol";

/// The longest field value read, in bytes: past the longest [`Unsupported`] ID and the
/// message, so a longer value cannot be one of them.
const MAX_FIELD_LEN: usize = 96;

/// A protocol the probe leaves unregistered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unsupported {
    /// `/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy` (Fulu).
    BlocksByHeadV1,
    /// `/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy` (Gloas).
    EnvelopesByRangeV1,
    /// `/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy` (Gloas).
    EnvelopesByRootV1,
}

impl Unsupported {
    /// Every protocol the probe leaves unregistered.
    pub const ALL: [Self; 3] = [
        Self::BlocksByHeadV1,
        Self::EnvelopesByRangeV1,
        Self::EnvelopesByRootV1,
    ];

    /// The multistream protocol ID.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::BlocksByHeadV1 => "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy",
            Self::EnvelopesByRangeV1 => {
                "/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy"
            }
            Self::EnvelopesByRootV1 => {
                "/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy"
            }
        }
    }

    /// The `protocol` label value: the message name of the protocol ID.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BlocksByHeadV1 => "beacon_blocks_by_head",
            Self::EnvelopesByRangeV1 => "execution_payload_envelopes_by_range",
            Self::EnvelopesByRootV1 => "execution_payload_envelopes_by_root",
        }
    }

    /// The protocol whose ID is exactly `id` (`phase0` L189: exact equality).
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.id() == id)
    }
}

/// The layer counting refused proposals of the [`Unsupported`] ids in `metrics` (see the
/// module docs), filtered to the listener's debug events.
pub fn layer<S>(metrics: RpcMetrics) -> impl Layer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let listener = filter_fn(|meta: &Metadata<'_>| {
        meta.is_event() && meta.target() == LISTENER_TARGET && *meta.level() == Level::DEBUG
    })
    .with_max_level_hint(LevelFilter::DEBUG);
    RefusedProposals { metrics }.with_filter(listener)
}

/// Counts each refused proposal of an [`Unsupported`] id.
struct RefusedProposals {
    metrics: RpcMetrics,
}

impl<S: Subscriber> Layer<S> for RefusedProposals {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut fields = ListenerFields::default();
        event.record(&mut fields);
        if fields.message.as_str() != Some(REJECTING) {
            return;
        }
        if let Some(protocol) = fields.protocol.as_str().and_then(Unsupported::from_id) {
            self.metrics.inbound_unsupported(protocol);
        }
    }
}

/// The two fields of a listener event the count reads.
#[derive(Default)]
struct ListenerFields {
    message: Capped,
    protocol: Capped,
}

impl ListenerFields {
    fn slot(&mut self, field: &Field) -> Option<&mut Capped> {
        match field.name() {
            "message" => Some(&mut self.message),
            "protocol" => Some(&mut self.protocol),
            _ => None,
        }
    }
}

impl Visit for ListenerFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if let Some(slot) = self.slot(field) {
            slot.set(format_args!("{value}"));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `%value` fields and the message arrive here, formatting as their `Display`.
        if let Some(slot) = self.slot(field) {
            slot.set(format_args!("{value:?}"));
        }
    }
}

/// A field value of at most [`MAX_FIELD_LEN`] bytes; a longer one is no value at all.
struct Capped {
    buf: [u8; MAX_FIELD_LEN],
    len: usize,
    overflow: bool,
}

impl Default for Capped {
    fn default() -> Self {
        Self {
            buf: [0; MAX_FIELD_LEN],
            len: 0,
            overflow: false,
        }
    }
}

impl Capped {
    fn set(&mut self, value: fmt::Arguments<'_>) {
        self.len = 0;
        self.overflow = false;
        // An overflow is recorded in `overflow`; the error only stops the formatting.
        let _ = self.write_fmt(value);
    }

    /// The value, unless it overflowed.
    fn as_str(&self) -> Option<&str> {
        if self.overflow {
            return None;
        }
        std::str::from_utf8(&self.buf[..self.len]).ok()
    }
}

impl fmt::Write for Capped {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        if end > MAX_FIELD_LEN {
            self.overflow = true;
            return Err(fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::registry::Registry;
    use tracing_subscriber::layer::SubscriberExt as _;

    /// The counts after `emit` ran under a subscriber holding only [`layer`].
    fn counted(emit: impl FnOnce()) -> [u64; 3] {
        let metrics = RpcMetrics::register(&mut Registry::default());
        let subscriber = tracing_subscriber::registry().with(layer(metrics.clone()));
        tracing::subscriber::with_default(subscriber, emit);
        Unsupported::ALL.map(|p| metrics.inbound_unsupported_count(p))
    }

    #[test]
    fn counts_each_refused_proposal_by_protocol() {
        let counts = counted(|| {
            for (n, protocol) in Unsupported::ALL.into_iter().enumerate() {
                for _ in 0..=n {
                    // The shape of multistream-select's own event: a `Display` field.
                    tracing::debug!(
                        target: "multistream_select::listener_select",
                        protocol = %protocol.id(),
                        "Listener: rejecting protocol"
                    );
                }
            }
            // A plain `&str` field counts the same.
            tracing::debug!(
                target: "multistream_select::listener_select",
                protocol = Unsupported::BlocksByHeadV1.id(),
                "Listener: rejecting protocol"
            );
        });
        assert_eq!(counts, [2, 2, 3]);
    }

    #[test]
    fn counts_nothing_else() {
        let head = Unsupported::BlocksByHeadV1.id();
        let longer = format!("{head}{}", "x".repeat(MAX_FIELD_LEN));
        let counts = counted(|| {
            // Confirmed, not refused.
            tracing::debug!(
                target: "multistream_select::listener_select",
                protocol = %head,
                "Listener: confirming protocol"
            );
            // A refused id the probe does not name, and one it does serve.
            for id in [
                "/eth2/beacon_chain/req/beacon_blocks_by_head/2/ssz_snappy",
                "/eth2/beacon_chain/req/status/2/ssz_snappy",
                &longer,
            ] {
                tracing::debug!(
                    target: "multistream_select::listener_select",
                    protocol = %id,
                    "Listener: rejecting protocol"
                );
            }
            // Another target, another level, no protocol field.
            tracing::debug!(target: "cl_p2p", protocol = %head, "Listener: rejecting protocol");
            tracing::info!(
                target: "multistream_select::listener_select",
                protocol = %head,
                "Listener: rejecting protocol"
            );
            tracing::debug!(
                target: "multistream_select::listener_select",
                "Listener: rejecting protocol"
            );
            // The message overflowing the buffer.
            tracing::debug!(
                target: "multistream_select::listener_select",
                protocol = %head,
                "Listener: rejecting protocol{}",
                "!".repeat(MAX_FIELD_LEN)
            );
        });
        assert_eq!(counts, [0, 0, 0]);
    }

    #[derive(Clone, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn leaves_the_other_layers_levels_alone() {
        use tracing_subscriber::Layer as _;
        let metrics = RpcMetrics::register(&mut Registry::default());
        let out = Captured::default();
        let writer = out.clone();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(move || writer.clone())
                    .with_filter(LevelFilter::INFO),
            )
            .with(layer(metrics.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(
                target: "multistream_select::listener_select",
                protocol = %Unsupported::EnvelopesByRangeV1.id(),
                "Listener: rejecting protocol"
            );
            tracing::info!("an info line");
        });
        assert_eq!(
            metrics.inbound_unsupported_count(Unsupported::EnvelopesByRangeV1),
            1
        );
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("an info line"), "{text}");
        assert!(!text.contains("rejecting"), "{text}");
    }
}
