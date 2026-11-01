//! The req/resp metrics, on the service's prometheus-client [`Registry`] (the one the swarm's
//! [`PeerMetrics`](crate::transport::PeerMetrics) is on).
//!
//! - `rpc_timeouts_total{kind}`: exchanges that failed on a deadline, inbound or outbound:
//!   `ttfb` (first byte), `per_chunk`, `total` (the codec's or `request_response`'s own).
//! - `rpc_invalid_data_total{direction}`: requests (`inbound`) or responses (`outbound`) that
//!   broke the wire format or the request's limits. A timeout is never counted here.
//! - `p2p_goodbye_sent_total{reason, status_valid}` and `p2p_goodbye_received_total{reason,
//!   status_valid}`: Goodbye messages by reason code and by whether the peer's Status was valid
//!   (`true`, `false`, or `unknown` before a Status was judged).
//! - `p2p_status_valid_peers`: connected peers whose last Status passed the relevance check.
//! - `rpc_outbound_inflight{protocol}`: our requests in flight per protocol, at most
//!   `MAX_CONCURRENT_REQUESTS` ([`crate::rpc::limits::OutboundSemaphore`]); for Ping, which
//!   takes no shared slot, up to one per connected peer
//!   ([`Control::ping`](crate::rpc::inbound::Control::ping)).
//! - `rpc_rate_limited_total{protocol}`: response chunks withheld because the peer was over its
//!   quota ([`crate::rpc::limits::ChunkPacer`]).
//! - `rpc_inbound_unsupported_total{protocol}`: peers' proposals of a protocol the probe leaves
//!   unregistered, refused at multistream-select ([`super::unsupported`]), by protocol: only
//!   the three [`Unsupported`] names, whatever a peer proposes.
//! - `rpc_column_answers` and `rpc_column_answer_bytes`: the column answers held now (lookup to
//!   the end of the write) and the SSZ bytes they hold ([`crate::rpc::limits::ColumnPlaces`]).
//! - `rpc_column_unrequested_total`: sidecars a column source handed over that the request did
//!   not name (or named once and got twice), dropped, never sent.
//! - `rpc_column_sidecars_answered_total{protocol}`: column sidecars of our answers to peers'
//!   `DataColumnSidecarsByRange` and `DataColumnSidecarsByRoot` requests, counted as each answer
//!   goes to its stream.
//! - `rpc_inbound_streams_refused_total`: inbound streams answered `2: ServerError` because
//!   `max_inbound_streams` streamed answers were open ([`crate::rpc::limits::RpcLimits`]).
//! - `queue_dropped_total{queue}`: items a bounded queue IGNOREd ([`QueueMetrics`]), shared with
//!   the other queues of the service through [`RpcMetrics::queues`].
//!
//! The `reason` label is the decimal code for 0 to 255 (1–3 and the client-specific codes from
//! 128 that clients use) and `other` above, so a peer cannot grow the label set past 257 values.

use super::codec::Deadline;
use super::limits::QueueMetrics;
use super::unsupported::Unsupported;
use crate::transport::Direction;
use p2p_wire::rpc::protocols::Protocol;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::fmt::Write as _;

/// The highest reason code that keeps its own `reason` label value.
pub const MAX_REASON_LABEL: u64 = 255;

impl Deadline {
    /// Every deadline.
    pub const ALL: [Self; 3] = [Self::Ttfb, Self::PerChunk, Self::Total];

    /// The `kind` label value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ttfb => "ttfb",
            Self::PerChunk => "per_chunk",
            Self::Total => "total",
        }
    }
}

impl EncodeLabelValue for Deadline {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> std::fmt::Result {
        encoder.write_str(self.as_str())
    }
}

/// Whether a peer's Status passed the relevance check: the `status_valid` label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum StatusValidity {
    /// It passed.
    Valid,
    /// It failed (another fork digest, a conflicting finalized checkpoint).
    Invalid,
    /// No Status of the peer was judged yet.
    Unknown,
}

impl StatusValidity {
    pub const ALL: [Self; 3] = [Self::Valid, Self::Invalid, Self::Unknown];

    /// The `status_valid` label value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "true",
            Self::Invalid => "false",
            Self::Unknown => "unknown",
        }
    }
}

impl From<Option<bool>> for StatusValidity {
    fn from(valid: Option<bool>) -> Self {
        match valid {
            Some(true) => Self::Valid,
            Some(false) => Self::Invalid,
            None => Self::Unknown,
        }
    }
}

impl EncodeLabelValue for StatusValidity {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> std::fmt::Result {
        encoder.write_str(self.as_str())
    }
}

/// A Goodbye reason as a label value: the code up to [`MAX_REASON_LABEL`], `other` above.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ReasonLabel(Option<u8>);

impl ReasonLabel {
    /// The label of reason code `reason`.
    #[must_use]
    pub fn of(reason: u64) -> Self {
        Self(u8::try_from(reason).ok())
    }
}

impl EncodeLabelValue for ReasonLabel {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> std::fmt::Result {
        match self.0 {
            Some(code) => write!(encoder, "{code}"),
            None => encoder.write_str("other"),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct KindLabel {
    kind: Deadline,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DirectionLabel {
    direction: Direction,
}

/// The `protocol` label value: the message name of the protocol ID.
#[must_use]
pub fn protocol_label(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::StatusV2 => "status",
        Protocol::MetaDataV3 => "metadata",
        Protocol::PingV1 => "ping",
        Protocol::BlocksByRangeV2 => "beacon_blocks_by_range",
        Protocol::GoodbyeV1 => "goodbye",
        Protocol::DataColumnsByRangeV1 => "data_column_sidecars_by_range",
        Protocol::DataColumnsByRootV1 => "data_column_sidecars_by_root",
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ProtocolLabel {
    protocol: &'static str,
}

impl ProtocolLabel {
    fn of(protocol: Protocol) -> Self {
        Self {
            protocol: protocol_label(protocol),
        }
    }

    fn unsupported(protocol: Unsupported) -> Self {
        Self {
            protocol: protocol.label(),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct GoodbyeLabels {
    reason: ReasonLabel,
    status_valid: StatusValidity,
}

/// The req/resp metrics (see the module docs).
#[derive(Clone, Debug)]
pub struct RpcMetrics {
    timeouts: Family<KindLabel, Counter>,
    invalid_data: Family<DirectionLabel, Counter>,
    goodbye_sent: Family<GoodbyeLabels, Counter>,
    goodbye_received: Family<GoodbyeLabels, Counter>,
    status_valid_peers: Gauge,
    outbound_inflight: Family<ProtocolLabel, Gauge>,
    rate_limited: Family<ProtocolLabel, Counter>,
    inbound_unsupported: Family<ProtocolLabel, Counter>,
    column_answers: Gauge,
    column_answer_bytes: Gauge,
    column_unrequested: Counter,
    column_sidecars_answered: Family<ProtocolLabel, Counter>,
    inbound_streams_refused: Counter,
    queues: QueueMetrics,
}

impl RpcMetrics {
    /// Creates every metric, the fixed label values at 0 (for Goodbye, the three spec reasons),
    /// and registers them in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self {
            timeouts: Family::default(),
            invalid_data: Family::default(),
            goodbye_sent: Family::default(),
            goodbye_received: Family::default(),
            status_valid_peers: Gauge::default(),
            outbound_inflight: Family::default(),
            rate_limited: Family::default(),
            inbound_unsupported: Family::default(),
            column_answers: Gauge::default(),
            column_answer_bytes: Gauge::default(),
            column_unrequested: Counter::default(),
            column_sidecars_answered: Family::default(),
            inbound_streams_refused: Counter::default(),
            queues: QueueMetrics::register(registry),
        };
        for protocol in [
            Protocol::DataColumnsByRangeV1,
            Protocol::DataColumnsByRootV1,
        ] {
            drop(
                metrics
                    .column_sidecars_answered
                    .get_or_create(&ProtocolLabel::of(protocol)),
            );
        }
        for protocol in Protocol::ALL {
            let label = ProtocolLabel::of(protocol);
            drop(metrics.outbound_inflight.get_or_create(&label));
            drop(metrics.rate_limited.get_or_create(&label));
        }
        for protocol in Unsupported::ALL {
            drop(
                metrics
                    .inbound_unsupported
                    .get_or_create(&ProtocolLabel::unsupported(protocol)),
            );
        }
        for kind in Deadline::ALL {
            drop(metrics.timeouts.get_or_create(&KindLabel { kind }));
        }
        for direction in Direction::ALL {
            drop(
                metrics
                    .invalid_data
                    .get_or_create(&DirectionLabel { direction }),
            );
        }
        for reason in 1..=3 {
            for status_valid in StatusValidity::ALL {
                let labels = GoodbyeLabels {
                    reason: ReasonLabel::of(reason),
                    status_valid,
                };
                drop(metrics.goodbye_sent.get_or_create(&labels));
                drop(metrics.goodbye_received.get_or_create(&labels));
            }
        }
        registry.register(
            "rpc_timeouts",
            "Req/resp exchanges that failed on a deadline, by deadline",
            metrics.timeouts.clone(),
        );
        registry.register(
            "rpc_invalid_data",
            "Req/resp requests (inbound) or responses (outbound) that broke the wire format",
            metrics.invalid_data.clone(),
        );
        registry.register(
            "p2p_goodbye_sent",
            "Goodbye messages sent, by reason and the peer's Status validity",
            metrics.goodbye_sent.clone(),
        );
        registry.register(
            "p2p_goodbye_received",
            "Goodbye messages received, by reason and the peer's Status validity",
            metrics.goodbye_received.clone(),
        );
        registry.register(
            "p2p_status_valid_peers",
            "Connected peers whose Status passed the relevance check",
            metrics.status_valid_peers.clone(),
        );
        registry.register(
            "rpc_outbound_inflight",
            "Our req/resp requests in flight, by protocol",
            metrics.outbound_inflight.clone(),
        );
        registry.register(
            "rpc_rate_limited",
            "Req/resp response chunks withheld because the peer was over its quota, by protocol",
            metrics.rate_limited.clone(),
        );
        registry.register(
            "rpc_inbound_unsupported",
            "Peers' proposals of a req/resp protocol we leave unregistered, refused at \
             multistream-select, by protocol",
            metrics.inbound_unsupported.clone(),
        );
        registry.register(
            "rpc_column_answers",
            "Column answers held now, from the lookup until the stream's writer returns",
            metrics.column_answers.clone(),
        );
        registry.register(
            "rpc_column_answer_bytes",
            "SSZ bytes of the column answers held now",
            metrics.column_answer_bytes.clone(),
        );
        registry.register(
            "rpc_column_sidecars_answered",
            "Column sidecars of our answers to peers' column requests, by protocol",
            metrics.column_sidecars_answered.clone(),
        );
        registry.register(
            "rpc_column_unrequested",
            "Column sidecars a source handed over that the request did not name, dropped",
            metrics.column_unrequested.clone(),
        );
        registry.register(
            "rpc_inbound_streams_refused",
            "Inbound streams answered 2: ServerError because the streamed answers were at their cap",
            metrics.inbound_streams_refused.clone(),
        );
        metrics
    }

    /// Counts an inbound stream refused at the global cap.
    pub(crate) fn inbound_stream_refused(&self) {
        self.inbound_streams_refused.inc();
    }

    /// The current `rpc_inbound_streams_refused_total`.
    #[must_use]
    pub fn inbound_streams_refused(&self) -> u64 {
        self.inbound_streams_refused.get()
    }

    /// Sets `rpc_column_answers` and `rpc_column_answer_bytes`.
    pub(crate) fn set_column_answers(&self, held: usize, bytes: usize) {
        self.column_answers
            .set(i64::try_from(held).unwrap_or(i64::MAX));
        self.column_answer_bytes
            .set(i64::try_from(bytes).unwrap_or(i64::MAX));
    }

    /// Counts `n` sidecars dropped as unrequested.
    pub(crate) fn unrequested(&self, n: u64) {
        self.column_unrequested.inc_by(n);
    }

    /// The current `rpc_column_answers`.
    #[must_use]
    pub fn column_answers_held(&self) -> u64 {
        u64::try_from(self.column_answers.get()).unwrap_or(0)
    }

    /// The current `rpc_column_answer_bytes`.
    #[must_use]
    pub fn column_answer_bytes_held(&self) -> u64 {
        u64::try_from(self.column_answer_bytes.get()).unwrap_or(0)
    }

    /// Counts `n` column sidecars of an answer to a `protocol` request.
    pub(crate) fn column_sidecars_answered(&self, protocol: Protocol, n: usize) {
        self.column_sidecars_answered
            .get_or_create(&ProtocolLabel::of(protocol))
            .inc_by(u64::try_from(n).unwrap_or(u64::MAX));
    }

    /// The current `rpc_column_sidecars_answered_total{protocol}`.
    #[must_use]
    pub fn column_sidecars_answered_count(&self, protocol: Protocol) -> u64 {
        self.column_sidecars_answered
            .get_or_create(&ProtocolLabel::of(protocol))
            .get()
    }

    /// The current `rpc_column_unrequested_total`.
    #[must_use]
    pub fn column_unrequested(&self) -> u64 {
        self.column_unrequested.get()
    }

    /// Sets `rpc_outbound_inflight{protocol}`.
    pub(crate) fn set_outbound_inflight(&self, protocol: Protocol, in_flight: usize) {
        let value = i64::try_from(in_flight).unwrap_or(i64::MAX);
        self.outbound_inflight
            .get_or_create(&ProtocolLabel::of(protocol))
            .set(value);
    }

    /// Counts a response chunk withheld on `protocol`.
    pub(crate) fn rate_limited(&self, protocol: Protocol) {
        self.rate_limited
            .get_or_create(&ProtocolLabel::of(protocol))
            .inc();
    }

    /// Counts a peer's proposal of `protocol` that multistream-select refused.
    pub(crate) fn inbound_unsupported(&self, protocol: Unsupported) {
        self.inbound_unsupported
            .get_or_create(&ProtocolLabel::unsupported(protocol))
            .inc();
    }

    /// The current `rpc_inbound_unsupported_total{protocol}`.
    #[must_use]
    pub fn inbound_unsupported_count(&self, protocol: Unsupported) -> u64 {
        self.inbound_unsupported
            .get_or_create(&ProtocolLabel::unsupported(protocol))
            .get()
    }

    /// `queue_dropped_total{queue}`, for every bounded queue of the service.
    #[must_use]
    pub fn queues(&self) -> &QueueMetrics {
        &self.queues
    }

    /// The current `rpc_outbound_inflight{protocol}`.
    #[must_use]
    pub fn outbound_inflight(&self, protocol: Protocol) -> i64 {
        self.outbound_inflight
            .get_or_create(&ProtocolLabel::of(protocol))
            .get()
    }

    /// The current `rpc_rate_limited_total{protocol}`.
    #[must_use]
    pub fn rate_limited_count(&self, protocol: Protocol) -> u64 {
        self.rate_limited
            .get_or_create(&ProtocolLabel::of(protocol))
            .get()
    }

    /// Counts an exchange that failed on `kind`.
    pub fn timed_out(&self, kind: Deadline) {
        self.timeouts.get_or_create(&KindLabel { kind }).inc();
    }

    /// Counts a request (`Inbound`) or response (`Outbound`) that broke the wire format.
    pub fn invalid_data(&self, direction: Direction) {
        self.invalid_data
            .get_or_create(&DirectionLabel { direction })
            .inc();
    }

    /// Counts a Goodbye sent.
    pub fn goodbye_sent(&self, reason: u64, status_valid: StatusValidity) {
        let labels = GoodbyeLabels {
            reason: ReasonLabel::of(reason),
            status_valid,
        };
        self.goodbye_sent.get_or_create(&labels).inc();
    }

    /// Counts a Goodbye received.
    pub fn goodbye_received(&self, reason: u64, status_valid: StatusValidity) {
        let labels = GoodbyeLabels {
            reason: ReasonLabel::of(reason),
            status_valid,
        };
        self.goodbye_received.get_or_create(&labels).inc();
    }

    /// A peer's Status became valid (`true`) or stopped being valid.
    pub(crate) fn status_valid_peer(&self, valid: bool) {
        if valid {
            self.status_valid_peers.inc();
        } else {
            self.status_valid_peers.dec();
        }
    }

    /// The current `rpc_timeouts_total{kind}`.
    #[must_use]
    pub fn timeouts(&self, kind: Deadline) -> u64 {
        self.timeouts.get_or_create(&KindLabel { kind }).get()
    }

    /// The current `rpc_invalid_data_total{direction}`.
    #[must_use]
    pub fn invalid_data_count(&self, direction: Direction) -> u64 {
        self.invalid_data
            .get_or_create(&DirectionLabel { direction })
            .get()
    }

    /// The current `p2p_goodbye_sent_total{reason, status_valid}`.
    #[must_use]
    pub fn goodbye_sent_count(&self, reason: u64, status_valid: StatusValidity) -> u64 {
        let labels = GoodbyeLabels {
            reason: ReasonLabel::of(reason),
            status_valid,
        };
        self.goodbye_sent.get_or_create(&labels).get()
    }

    /// The current `p2p_goodbye_received_total{reason, status_valid}`.
    #[must_use]
    pub fn goodbye_received_count(&self, reason: u64, status_valid: StatusValidity) -> u64 {
        let labels = GoodbyeLabels {
            reason: ReasonLabel::of(reason),
            status_valid,
        };
        self.goodbye_received.get_or_create(&labels).get()
    }

    /// The current `p2p_status_valid_peers`.
    #[must_use]
    pub fn status_valid_peers(&self) -> i64 {
        self.status_valid_peers.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::encoding::text::encode;

    fn text(registry: &Registry) -> String {
        let mut out = String::new();
        encode(&mut out, registry).unwrap();
        out
    }

    #[test]
    fn every_fixed_label_starts_at_zero() {
        let mut registry = Registry::default();
        let _metrics = RpcMetrics::register(&mut registry);
        let text = text(&registry);
        for line in [
            "rpc_timeouts_total{kind=\"ttfb\"} 0",
            "rpc_timeouts_total{kind=\"per_chunk\"} 0",
            "rpc_timeouts_total{kind=\"total\"} 0",
            "rpc_invalid_data_total{direction=\"inbound\"} 0",
            "rpc_invalid_data_total{direction=\"outbound\"} 0",
            "p2p_goodbye_sent_total{reason=\"2\",status_valid=\"true\"} 0",
            "p2p_goodbye_received_total{reason=\"3\",status_valid=\"unknown\"} 0",
            "p2p_status_valid_peers 0",
            "rpc_outbound_inflight{protocol=\"status\"} 0",
            "rpc_outbound_inflight{protocol=\"beacon_blocks_by_range\"} 0",
            "rpc_rate_limited_total{protocol=\"ping\"} 0",
            "rpc_rate_limited_total{protocol=\"goodbye\"} 0",
            "rpc_inbound_unsupported_total{protocol=\"beacon_blocks_by_head\"} 0",
            "rpc_inbound_unsupported_total{protocol=\"execution_payload_envelopes_by_range\"} 0",
            "rpc_inbound_unsupported_total{protocol=\"execution_payload_envelopes_by_root\"} 0",
        ] {
            assert!(text.contains(line), "{line} missing from\n{text}");
        }
    }

    #[test]
    fn counters_count_by_label() {
        let mut registry = Registry::default();
        let metrics = RpcMetrics::register(&mut registry);
        metrics.timed_out(Deadline::Ttfb);
        metrics.invalid_data(Direction::Outbound);
        metrics.goodbye_sent(2, StatusValidity::Invalid);
        metrics.goodbye_received(129, StatusValidity::Valid);
        metrics.goodbye_received(1 << 40, StatusValidity::Unknown);
        metrics.status_valid_peer(true);
        metrics.status_valid_peer(true);
        metrics.status_valid_peer(false);
        assert_eq!(metrics.timeouts(Deadline::Ttfb), 1);
        assert_eq!(metrics.timeouts(Deadline::Total), 0);
        assert_eq!(metrics.invalid_data_count(Direction::Outbound), 1);
        assert_eq!(metrics.invalid_data_count(Direction::Inbound), 0);
        assert_eq!(metrics.goodbye_sent_count(2, StatusValidity::Invalid), 1);
        assert_eq!(metrics.goodbye_sent_count(2, StatusValidity::Valid), 0);
        assert_eq!(
            metrics.goodbye_received_count(129, StatusValidity::Valid),
            1
        );
        assert_eq!(metrics.status_valid_peers(), 1);
        metrics.set_outbound_inflight(Protocol::MetaDataV3, 2);
        metrics.rate_limited(Protocol::PingV1);
        assert_eq!(metrics.outbound_inflight(Protocol::MetaDataV3), 2);
        assert_eq!(metrics.outbound_inflight(Protocol::PingV1), 0);
        assert_eq!(metrics.rate_limited_count(Protocol::PingV1), 1);
        assert_eq!(metrics.queues().dropped("nothing"), 0);
        metrics.inbound_unsupported(Unsupported::EnvelopesByRootV1);
        metrics.inbound_unsupported(Unsupported::EnvelopesByRootV1);
        assert_eq!(
            metrics.inbound_unsupported_count(Unsupported::EnvelopesByRootV1),
            2
        );
        assert_eq!(
            metrics.inbound_unsupported_count(Unsupported::BlocksByHeadV1),
            0
        );
        let text = text(&registry);
        assert!(
            text.contains(
                "rpc_inbound_unsupported_total{protocol=\"execution_payload_envelopes_by_root\"} 2"
            ),
            "{text}"
        );
        assert!(
            text.contains("rpc_outbound_inflight{protocol=\"metadata\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("p2p_goodbye_received_total{reason=\"129\",status_valid=\"true\"} 1"),
            "{text}"
        );
        // Every code past 255 shares one label value.
        assert!(
            text.contains(
                "p2p_goodbye_received_total{reason=\"other\",status_valid=\"unknown\"} 1"
            ),
            "{text}"
        );
        assert_eq!(ReasonLabel::of(256), ReasonLabel::of(u64::MAX));
    }

    #[test]
    fn validity_from_the_peer_state() {
        assert_eq!(StatusValidity::from(Some(true)), StatusValidity::Valid);
        assert_eq!(StatusValidity::from(Some(false)), StatusValidity::Invalid);
        assert_eq!(StatusValidity::from(None), StatusValidity::Unknown);
        let kinds: Vec<_> = Deadline::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(kinds, ["ttfb", "per_chunk", "total"]);
    }
}
