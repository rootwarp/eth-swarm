//! What the reference node says about its attestation subnets, for the sampled ones: the
//! committees per slot (`GET /eth/v1/beacon/states/head/committees`), which an unaggregated
//! attestation's subnet is computed from, and the subnets it subscribes (`GET
//! /eth/v1/node/identity`, its metadata `attnets`). Both are read once at the start and kept in
//! `capture.toml`. Nothing from a response goes into an error.

use super::client::{get_json, get_json_at, ApiError};
use crate::collector::url::ReferenceApiUrl;
use p2p_wire::gossip::topic::ATTESTATION_SUBNET_COUNT;
use serde::de::IgnoredAny;
use serde::Deserialize;
use std::time::Duration;

/// The committees API path.
pub const COMMITTEES_PATH: &str = "/eth/v1/beacon/states/head/committees";
/// The node identity API path.
pub const IDENTITY_PATH: &str = "/eth/v1/node/identity";
/// Cap on the committees of one slot: 4 MiB. 64 committees of a million validators' slot share
/// are about 400 KB of JSON; the validator lists are skipped, never held.
pub const MAX_COMMITTEES_BYTES: usize = 4 << 20;
/// Cap on the identity response: 64 KiB (an ENR, a few addresses and the metadata).
pub const MAX_IDENTITY_BYTES: usize = 64 << 10;
/// `MAX_COMMITTEES_PER_SLOT` (mainnet and minimal presets).
pub const MAX_COMMITTEES_PER_SLOT: u64 = 64;

/// The committees per slot at `slot` (`get_committee_count_per_slot` of its epoch): the
/// committees the head state lists for that slot, 1 to [`MAX_COMMITTEES_PER_SLOT`].
pub async fn committees_per_slot(
    url: &ReferenceApiUrl,
    slot: u64,
    slots_per_epoch: u64,
    timeout: Duration,
) -> Result<u64, ApiError> {
    #[derive(Deserialize)]
    struct Data {
        data: Vec<Committee>,
    }
    #[derive(Deserialize)]
    struct Committee {
        slot: String,
        #[allow(dead_code)]
        validators: IgnoredAny,
    }
    let bad = |reason: &str| ApiError::BadResponse {
        path: COMMITTEES_PATH,
        reason: reason.into(),
    };
    let epoch = slot
        .checked_div(slots_per_epoch)
        .ok_or(bad("no SLOTS_PER_EPOCH"))?;
    let query = format!("{COMMITTEES_PATH}?epoch={epoch}&slot={slot}");
    let d: Data = get_json_at(url, COMMITTEES_PATH, &query, MAX_COMMITTEES_BYTES, timeout).await?;
    let want = slot.to_string();
    if d.data.iter().any(|c| c.slot != want) {
        return Err(bad("a committee of another slot"));
    }
    let count = d.data.len() as u64;
    if !(1..=MAX_COMMITTEES_PER_SLOT).contains(&count) {
        return Err(bad("not 1 to 64 committees"));
    }
    Ok(count)
}

/// The attestation subnets the node subscribes: the bits set in its metadata `attnets`
/// (`Bitvector[ATTESTATION_SUBNET_COUNT]`, `0x` and 16 hex digits, bit `i` in byte `i / 8`).
pub async fn node_attnets(url: &ReferenceApiUrl, timeout: Duration) -> Result<Vec<u64>, ApiError> {
    #[derive(Deserialize)]
    struct Data {
        data: Identity,
    }
    #[derive(Deserialize)]
    struct Identity {
        metadata: Metadata,
    }
    #[derive(Deserialize)]
    struct Metadata {
        attnets: String,
    }
    let d: Data = get_json(url, IDENTITY_PATH, MAX_IDENTITY_BYTES, timeout).await?;
    parse_attnets(&d.data.metadata.attnets).ok_or(ApiError::BadResponse {
        path: IDENTITY_PATH,
        reason: "attnets is not 0x and 16 hex digits".into(),
    })
}

fn parse_attnets(text: &str) -> Option<Vec<u64>> {
    let digits = text.strip_prefix("0x")?;
    let mut bytes = [0u8; (ATTESTATION_SUBNET_COUNT / 8) as usize];
    if digits.len() != 2 * bytes.len() {
        return None;
    }
    hex::decode_to_slice(digits, &mut bytes).ok()?;
    let set = |i: &u64| bytes[(*i / 8) as usize] >> (*i % 8) & 1 == 1;
    Some((0..ATTESTATION_SUBNET_COUNT).filter(set).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::testing::{FixtureServer, Reply};

    const KEY: &str = "/key-hunter2";

    fn committees(slot: &str, count: usize) -> String {
        let one = format!(r#"{{"index":"0","slot":"{slot}","validators":["1","2","3"]}}"#);
        format!(
            r#"{{"execution_optimistic":false,"finalized":false,"data":[{}]}}"#,
            vec![one; count].join(",")
        )
    }

    #[tokio::test]
    async fn the_committees_of_the_slot_are_counted() {
        let replies = [
            committees("70", 64),
            committees("70", 1),
            committees("70", 0),
            committees("70", 65),
            committees("71", 2),
            r#"{"data":[{"slot":70}]}"#.to_owned(),
        ];
        let server = FixtureServer::start(move |n, _| Reply::json(&replies[n])).await;
        let url = server.url(KEY);
        let t = Duration::from_secs(5);
        assert_eq!(committees_per_slot(&url, 70, 32, t).await, Ok(64));
        assert_eq!(committees_per_slot(&url, 70, 32, t).await, Ok(1));
        for _ in 0..4 {
            let err = committees_per_slot(&url, 70, 32, t).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    ApiError::BadResponse {
                        path: COMMITTEES_PATH,
                        ..
                    }
                ),
                "{err}"
            );
        }
        assert_eq!(
            server.seen()[0].0,
            format!("{KEY}{COMMITTEES_PATH}?epoch=2&slot=70")
        );
        assert!(committees_per_slot(&url, 70, 0, t).await.is_err());
    }

    #[tokio::test]
    async fn attnets_are_the_subnets_the_node_subscribes() {
        let identity = |attnets: &str| {
            format!(
                r#"{{"data":{{"peer_id":"16Uiu2","enr":"enr:-","metadata":{{"seq_number":"1","attnets":"{attnets}","syncnets":"0x00"}}}}}}"#
            )
        };
        let replies = [
            identity("0x0300000000000080"),
            identity("0x0000000000000000"),
            identity("0x03"),
            identity("0xzz00000000000000"),
        ];
        let server = FixtureServer::start(move |n, _| Reply::json(&replies[n])).await;
        let url = server.url(KEY);
        let t = Duration::from_secs(5);
        assert_eq!(node_attnets(&url, t).await, Ok(vec![0, 1, 63]));
        assert_eq!(node_attnets(&url, t).await, Ok(vec![]));
        for _ in 0..2 {
            let err = node_attnets(&url, t).await.unwrap_err();
            assert_eq!(
                err,
                ApiError::BadResponse {
                    path: IDENTITY_PATH,
                    reason: "attnets is not 0x and 16 hex digits".into()
                }
            );
        }
        assert_eq!(server.seen()[0].0, format!("{KEY}{IDENTITY_PATH}"));
    }
}
