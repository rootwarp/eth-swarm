//! The beacon API JSON responses the fetcher reads (`/eth/v1/beacon/states/{id}/
//! finality_checkpoints`, `/eth/v1/beacon/headers/{id}`). Integers are decimal strings and
//! roots `0x` + 64 hex digits, as the beacon API specifies; anything else is refused.

use consensus_types::common::BeaconBlockHeader;
use consensus_types::primitives::{Epoch, Root};
use serde::{Deserialize, Deserializer};

/// `GET /eth/v1/beacon/states/finalized/finality_checkpoints`.
#[derive(Debug, Deserialize)]
pub(crate) struct FinalityResponse {
    pub data: FinalityData,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FinalityData {
    pub finalized: Checkpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct Checkpoint {
    #[serde(deserialize_with = "quoted_u64")]
    pub epoch: Epoch,
    #[serde(deserialize_with = "root")]
    pub root: Root,
}

/// `GET /eth/v1/beacon/headers/{block_id}`.
#[derive(Debug, Deserialize)]
pub(crate) struct HeaderResponse {
    pub data: HeaderData,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HeaderData {
    #[serde(deserialize_with = "root")]
    pub root: Root,
    pub canonical: bool,
    pub header: SignedHeader,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SignedHeader {
    pub message: HeaderMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct HeaderMessage {
    #[serde(deserialize_with = "quoted_u64")]
    pub slot: u64,
    #[serde(deserialize_with = "quoted_u64")]
    pub proposer_index: u64,
    #[serde(deserialize_with = "root")]
    pub parent_root: Root,
    #[serde(deserialize_with = "root")]
    pub state_root: Root,
    #[serde(deserialize_with = "root")]
    pub body_root: Root,
}

impl From<HeaderMessage> for BeaconBlockHeader {
    fn from(h: HeaderMessage) -> Self {
        BeaconBlockHeader {
            slot: h.slot,
            proposer_index: h.proposer_index,
            parent_root: h.parent_root,
            state_root: h.state_root,
            body_root: h.body_root,
        }
    }
}

fn quoted_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let s = String::deserialize(d)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(serde::de::Error::custom(format!(
            "{s:?} is not a decimal u64"
        )));
    }
    s.parse().map_err(serde::de::Error::custom)
}

fn root<'de, D: Deserializer<'de>>(d: D) -> Result<Root, D::Error> {
    let s = String::deserialize(d)?;
    parse_root(&s).ok_or_else(|| serde::de::Error::custom(format!("{s:?} is not a 0x root")))
}

/// `0x` followed by exactly 64 hex digits.
pub(crate) fn parse_root(s: &str) -> Option<Root> {
    let hex = s.strip_prefix("0x")?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn parses_finality_and_headers() {
        let f: FinalityResponse = serde_json::from_str(&format!(
            r#"{{"execution_optimistic":false,"finalized":true,"data":{{
                "previous_justified":{{"epoch":"1","root":"{R1}"}},
                "current_justified":{{"epoch":"2","root":"{R1}"}},
                "finalized":{{"epoch":"3","root":"{R1}"}}}}}}"#
        ))
        .unwrap();
        assert_eq!(f.data.finalized.epoch, 3);
        assert_eq!(f.data.finalized.root, Root::repeat_byte(0x11));
        let h: HeaderResponse = serde_json::from_str(&format!(
            r#"{{"data":{{"root":"{R1}","canonical":true,"header":{{"message":{{
                "slot":"9","proposer_index":"4","parent_root":"{R1}","state_root":"{R1}",
                "body_root":"{R1}"}},"signature":"0x00"}}}}}}"#
        ))
        .unwrap();
        assert!(h.data.canonical);
        let header = BeaconBlockHeader::from(h.data.header.message);
        assert_eq!((header.slot, header.proposer_index), (9, 4));
    }

    #[test]
    fn refuses_unquoted_or_malformed_values() {
        let bad = [
            format!(r#"{{"epoch":3,"root":"{R1}"}}"#),
            format!(r#"{{"epoch":"-3","root":"{R1}"}}"#),
            format!(r#"{{"epoch":"","root":"{R1}"}}"#),
            r#"{"epoch":"3","root":"0x11"}"#.to_owned(),
            format!(r#"{{"epoch":"3","root":"{}"}}"#, &R1[2..]),
            format!(r#"{{"epoch":"3","root":"0x{}"}}"#, "g".repeat(64)),
        ];
        for text in bad {
            assert!(serde_json::from_str::<Checkpoint>(&text).is_err(), "{text}");
        }
    }
}
