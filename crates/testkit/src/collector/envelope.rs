//! Envelope-relative column offsets: a column's arrival minus the arrival of the
//! `execution_payload` envelope of the same `beacon_block_root`, on the monotonic clock.
//!
//! Gloas columns and envelopes travel independently; this offset is what the B9 captures
//! measure. Each source is matched on its own (gossip columns with gossip envelopes, SSE with
//! SSE): the two see the network from different places. The envelope's arrival is the first
//! one seen for its root. A column whose root has no envelope, or which has no root (it did not
//! decode), is counted as unmatched.

use super::record::{ArrivalRecord, Source};
use consensus_types::primitives::Root;
use std::collections::HashMap;

/// What an arrival is, for matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrivalKind {
    /// A `SignedExecutionPayloadEnvelope`: gossip `execution_payload`, SSE
    /// `execution_payload_gossip` (the gossip-validation event, not the import one).
    Envelope,
    /// A `DataColumnSidecar`: gossip `data_column_sidecar_<subnet>`, SSE `data_column_sidecar`.
    Column,
}

impl ArrivalKind {
    /// The kind of an arrival on `topic` from `source`, if it is one that is matched.
    pub fn of(source: Source, topic: &str) -> Option<Self> {
        match (source, topic) {
            (Source::Gossip, "execution_payload") | (Source::Sse, "execution_payload_gossip") => {
                Some(Self::Envelope)
            }
            (Source::Sse, "data_column_sidecar") => Some(Self::Column),
            (Source::Gossip, t) if t.starts_with("data_column_sidecar_") => Some(Self::Column),
            _ => None,
        }
    }
}

/// One column matched to its envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnOffset {
    /// The column's index in the records.
    pub record: usize,
    /// The block root both carry.
    pub block_root: Root,
    /// Column arrival − envelope arrival (monotonic), nanoseconds: negative for a column
    /// ahead of its envelope.
    pub offset_ns: i64,
}

impl ColumnOffset {
    /// [`ColumnOffset::offset_ns`] in milliseconds.
    pub fn offset_ms(&self) -> f64 {
        self.offset_ns as f64 / 1e6
    }
}

/// Every column's envelope-relative offset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvelopeRelative {
    /// Matched columns, in record order.
    pub columns: Vec<ColumnOffset>,
    /// Columns with no envelope of the same source and root.
    pub unmatched_columns: u64,
}

/// Matches every column in `records` to its envelope.
pub fn envelope_relative(records: &[ArrivalRecord]) -> EnvelopeRelative {
    let mut envelopes: HashMap<(Source, Root), u64> = HashMap::new();
    for r in records {
        if let (Some(ArrivalKind::Envelope), Some(root)) =
            (ArrivalKind::of(r.source, &r.topic), r.block_root)
        {
            let first = envelopes.entry((r.source, root)).or_insert(r.recv_mono_ns);
            *first = (*first).min(r.recv_mono_ns);
        }
    }
    let mut out = EnvelopeRelative::default();
    for (i, r) in records.iter().enumerate() {
        if ArrivalKind::of(r.source, &r.topic) != Some(ArrivalKind::Column) {
            continue;
        }
        let envelope = r
            .block_root
            .and_then(|root| Some((root, *envelopes.get(&(r.source, root))?)));
        let offset = envelope.and_then(|(root, at)| {
            let ns = i128::from(r.recv_mono_ns) - i128::from(at);
            Some((root, i64::try_from(ns).ok()?))
        });
        match offset {
            Some((block_root, offset_ns)) => out.columns.push(ColumnOffset {
                record: i,
                block_root,
                offset_ns,
            }),
            None => out.unmatched_columns += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(source: Source, topic: &str, root: Option<u8>, mono_ns: u64) -> ArrivalRecord {
        ArrivalRecord {
            source,
            topic: topic.into(),
            subnet: None,
            msg_id: None,
            block_root: root.map(Root::repeat_byte),
            slot: None,
            recv_mono_ns: mono_ns,
            recv_wall_ns: 0,
            peer: None,
        }
    }

    #[test]
    fn kinds() {
        use ArrivalKind::*;
        assert_eq!(
            ArrivalKind::of(Source::Gossip, "execution_payload"),
            Some(Envelope)
        );
        assert_eq!(
            ArrivalKind::of(Source::Sse, "execution_payload_gossip"),
            Some(Envelope)
        );
        assert_eq!(ArrivalKind::of(Source::Sse, "execution_payload"), None);
        assert_eq!(
            ArrivalKind::of(Source::Gossip, "execution_payload_gossip"),
            None
        );
        assert_eq!(
            ArrivalKind::of(Source::Gossip, "data_column_sidecar_0"),
            Some(Column)
        );
        assert_eq!(
            ArrivalKind::of(Source::Sse, "data_column_sidecar"),
            Some(Column)
        );
        assert_eq!(ArrivalKind::of(Source::Gossip, "data_column_sidecar"), None);
        assert_eq!(ArrivalKind::of(Source::Gossip, "beacon_block"), None);
    }

    #[test]
    fn sources_match_separately_and_the_first_envelope_counts() {
        let records = [
            at(Source::Sse, "data_column_sidecar", Some(1), 50),
            at(Source::Gossip, "execution_payload", Some(1), 300),
            at(Source::Gossip, "execution_payload", Some(1), 100),
            at(Source::Gossip, "data_column_sidecar_7", Some(1), 40),
            at(Source::Sse, "execution_payload_gossip", Some(1), 10),
            at(Source::Gossip, "data_column_sidecar_8", None, 500),
        ];
        let got = envelope_relative(&records);
        let offsets: Vec<_> = got
            .columns
            .iter()
            .map(|c| (c.record, c.offset_ns))
            .collect();
        // The SSE column is 40 ns after the SSE envelope; the gossip column 60 ns ahead of the
        // first gossip envelope. The rootless column is unmatched.
        assert_eq!(offsets, vec![(0, 40), (3, -60)]);
        assert_eq!(got.unmatched_columns, 1);
    }

    #[test]
    fn an_offset_i64_cannot_hold_is_unmatched() {
        let records = [
            at(Source::Gossip, "execution_payload", Some(1), 0),
            at(Source::Gossip, "data_column_sidecar_1", Some(1), u64::MAX),
        ];
        assert_eq!(envelope_relative(&records).unmatched_columns, 1);
    }
}
