//! [`ArrivalRecord`]: one arrival, as `records.jsonl` stores it.

use consensus_types::primitives::{Root, Slot};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Where an arrival was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Our probe's gossipsub tap, at delivery.
    Gossip,
    /// A reference node's `/eth/v1/events` stream.
    Sse,
}

/// One arrival.
///
/// `recv_mono_ns` and `recv_wall_ns` are taken before anything decodes the message; `slot` and
/// `block_root` are decoded afterwards and are `None` when the message does not carry them or
/// does not decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArrivalRecord {
    /// Gossip or SSE.
    pub source: Source,
    /// Gossip: the topic name without fork digest and encoding (`beacon_block`,
    /// `data_column_sidecar_3`, `execution_payload`). SSE: the event name (`block_gossip`,
    /// `data_column_sidecar`, `execution_payload_gossip`).
    pub topic: String,
    /// The subnet: from the topic name (gossip), or the column's subnet (SSE
    /// `data_column_sidecar`, `index % DATA_COLUMN_SIDECAR_SUBNET_COUNT`).
    pub subnet: Option<u64>,
    /// The gossipsub message-id, `0x` and hex (gossip only).
    pub msg_id: Option<String>,
    /// The block root the message belongs to.
    #[serde(serialize_with = "ser_root", deserialize_with = "de_root")]
    pub block_root: Option<Root>,
    /// The message's slot.
    pub slot: Option<Slot>,
    /// Monotonic receive time: nanoseconds since the collector's clock origin.
    pub recv_mono_ns: u64,
    /// Wall-clock receive time: Unix nanoseconds.
    pub recv_wall_ns: u64,
    /// The peer that delivered it (gossip only: the propagation source's peer ID).
    pub peer: Option<String>,
}

fn ser_root<S: Serializer>(root: &Option<Root>, s: S) -> Result<S::Ok, S::Error> {
    match root {
        Some(r) => s.serialize_str(&format!("{r}")),
        None => s.serialize_none(),
    }
}

fn de_root<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Root>, D::Error> {
    let Some(text) = Option::<String>::deserialize(d)? else {
        return Ok(None);
    };
    parse_root(&text)
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom(format!("{text:?} is not 0x and 64 hex digits")))
}

/// `0x` and exactly 64 hex digits.
pub(crate) fn parse_root(text: &str) -> Option<Root> {
    let digits = text.strip_prefix("0x")?;
    let mut out = [0u8; 32];
    if digits.len() != 64 {
        return None;
    }
    hex::decode_to_slice(digits, &mut out).ok()?;
    Some(Root::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_with_and_without_a_root() {
        let mut record = ArrivalRecord {
            source: Source::Sse,
            topic: "data_column_sidecar".into(),
            subnet: Some(5),
            msg_id: None,
            block_root: Some(Root::repeat_byte(0xab)),
            slot: Some(7),
            recv_mono_ns: 11,
            recv_wall_ns: 12,
            peer: None,
        };
        let text = serde_json::to_string(&record).unwrap();
        assert!(text.contains(r#""source":"sse""#), "{text}");
        assert!(text.contains(&format!(r#""block_root":"0x{}""#, "ab".repeat(32))));
        assert_eq!(
            serde_json::from_str::<ArrivalRecord>(&text).unwrap(),
            record
        );

        record.block_root = None;
        let text = serde_json::to_string(&record).unwrap();
        assert!(text.contains(r#""block_root":null"#), "{text}");
        assert_eq!(
            serde_json::from_str::<ArrivalRecord>(&text).unwrap(),
            record
        );
    }

    #[test]
    fn a_malformed_root_is_refused() {
        for root in [
            "0x12",
            "ab".repeat(32).as_str(),
            &format!("0x{}", "zz".repeat(32)),
        ] {
            let text = format!(
                r#"{{"source":"gossip","topic":"t","subnet":null,"msg_id":null,"block_root":"{root}","slot":null,"recv_mono_ns":0,"recv_wall_ns":0,"peer":null}}"#
            );
            assert!(
                serde_json::from_str::<ArrivalRecord>(&text).is_err(),
                "{root}"
            );
        }
    }
}
