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

/// The first envelope arrival of each source and block root, from one pass over the records:
/// what a column is matched against. It holds one entry per envelope root, not the records, so
/// a capture of any length is matched in two passes over its file.
#[derive(Debug, Clone, Default)]
pub struct EnvelopeIndex {
    first: HashMap<(Source, Root), u64>,
}

/// How a record matched ([`EnvelopeIndex::column`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnMatch {
    /// Not a column.
    NotAColumn,
    /// A column with no envelope of the same source and root (or no root, or an offset `i64`
    /// cannot hold).
    Unmatched,
    /// A column and its envelope.
    Matched {
        /// The block root both carry.
        block_root: Root,
        /// Column arrival − envelope arrival (monotonic), nanoseconds.
        offset_ns: i64,
    },
}

impl EnvelopeIndex {
    /// Counts `record` in if it is an envelope with a root.
    pub fn add(&mut self, record: &ArrivalRecord) {
        if let (Some(ArrivalKind::Envelope), Some(root)) = (
            ArrivalKind::of(record.source, &record.topic),
            record.block_root,
        ) {
            let first = self
                .first
                .entry((record.source, root))
                .or_insert(record.recv_mono_ns);
            *first = (*first).min(record.recv_mono_ns);
        }
    }

    /// `record` matched against the envelopes counted in.
    pub fn column(&self, record: &ArrivalRecord) -> ColumnMatch {
        if ArrivalKind::of(record.source, &record.topic) != Some(ArrivalKind::Column) {
            return ColumnMatch::NotAColumn;
        }
        let matched = record.block_root.and_then(|root| {
            let at = *self.first.get(&(record.source, root))?;
            let ns = i128::from(record.recv_mono_ns) - i128::from(at);
            Some(ColumnMatch::Matched {
                block_root: root,
                offset_ns: i64::try_from(ns).ok()?,
            })
        });
        matched.unwrap_or(ColumnMatch::Unmatched)
    }
}

/// Matches every column in `records` to its envelope.
pub fn envelope_relative(records: &[ArrivalRecord]) -> EnvelopeRelative {
    let mut index = EnvelopeIndex::default();
    records.iter().for_each(|r| index.add(r));
    let mut out = EnvelopeRelative::default();
    for (i, r) in records.iter().enumerate() {
        match index.column(r) {
            ColumnMatch::NotAColumn => {}
            ColumnMatch::Unmatched => out.unmatched_columns += 1,
            ColumnMatch::Matched {
                block_root,
                offset_ns,
            } => out.columns.push(ColumnOffset {
                record: i,
                block_root,
                offset_ns,
            }),
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
            bytes: 0,
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
