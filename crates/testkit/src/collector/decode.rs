//! Decoding an arrival after it was stamped: the gossip topic's name, fork digest and subnet,
//! and the slot and block root of the payload (decoded by the fork of the object's own slot);
//! the slot, block root and column subnet of an SSE event's JSON.

use super::record::parse_root;
use super::sse::SseEvent;
use crate::archive::{
    decode_payload, decompress, ChainParams, ForkDigest, PayloadError, TopicKind,
};
use consensus_types::caps::ObjectKind;
use consensus_types::codec::{decode, DecodeError, Object};
use consensus_types::primitives::{Root, Slot};
use consensus_types::{EthSpec, ForkName};
use p2p_wire::gossip::topic::ATTESTATION_SUBNET_COUNT;

/// A gossip topic, `/eth2/<fork_digest>/<name>/ssz_snappy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipTopic<'a> {
    /// The fork digest.
    pub fork_digest: ForkDigest,
    /// The topic name (`beacon_block`, `data_column_sidecar_3`, …).
    pub name: &'a str,
}

/// Parses a full gossip topic; `None` if it is not `/eth2/<8 lowercase hex>/<name>/ssz_snappy`.
pub fn parse_gossip_topic(topic: &str) -> Option<GossipTopic<'_>> {
    let rest = topic.strip_prefix("/eth2/")?.strip_suffix("/ssz_snappy")?;
    let (digest, name) = rest.split_once('/')?;
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if digest.len() != 8 || !digest.bytes().all(lower_hex) || name.is_empty() || name.contains('/')
    {
        return None;
    }
    let mut fork_digest = [0u8; 4];
    hex::decode_to_slice(digest, &mut fork_digest).ok()?;
    Some(GossipTopic { fork_digest, name })
}

/// The subnet in a topic name: `data_column_sidecar_<n>`, `beacon_attestation_<n>`,
/// `sync_committee_<n>`, with `n` canonical decimal.
pub fn topic_subnet(name: &str) -> Option<u64> {
    [
        "data_column_sidecar_",
        "beacon_attestation_",
        "sync_committee_",
    ]
    .iter()
    .find_map(|prefix| name.strip_prefix(prefix))
    .and_then(canonical_decimal)
}

/// A decimal `u64` without sign or leading zero.
fn canonical_decimal(digits: &str) -> Option<u64> {
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    canonical.then(|| digits.parse().ok()).flatten()
}

/// What decoding found: the object's slot and the block root it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// The slot.
    pub slot: Slot,
    /// The block root.
    pub root: Root,
}

/// The slot and block root of a gossip payload on topic `name`: blocks and columns as the
/// archive files them, `execution_payload` envelopes by their `beacon_block_root` and payload
/// `slot_number` (Gloas only). `Ok(None)` for a topic not decoded here.
pub fn decode_gossip<E: EthSpec>(
    name: &str,
    payload: &[u8],
    chain: &ChainParams,
) -> Result<Option<Decoded>, PayloadError> {
    if name == "execution_payload" {
        return decode_envelope::<E>(payload, chain).map(Some);
    }
    let Ok(kind) = TopicKind::of(name) else {
        return Ok(None);
    };
    let d = decode_payload::<E>(kind, payload, chain)?;
    Ok(Some(Decoded {
        slot: d.slot,
        root: d.root,
    }))
}

/// A `SignedExecutionPayloadEnvelope`: Gloas-shaped, and its payload's slot must be a Gloas
/// slot.
fn decode_envelope<E: EthSpec>(
    payload: &[u8],
    chain: &ChainParams,
) -> Result<Decoded, PayloadError> {
    const KIND: ObjectKind = ObjectKind::SignedExecutionPayloadEnvelope;
    let ssz = decompress(payload)?;
    let Object::SignedExecutionPayloadEnvelope(envelope) =
        decode::<E>(KIND, ForkName::Gloas, &ssz)?
    else {
        unreachable!("decode returns the kind it was asked for");
    };
    let slot = envelope.message.payload.slot_number;
    let fork = consensus_types::forked::fork_at_slot::<E>(&chain.schedule, slot)?;
    if fork != ForkName::Gloas {
        return Err(DecodeError::NotInFork { kind: KIND, fork }.into());
    }
    Ok(Decoded {
        slot,
        root: envelope.message.beacon_block_root,
    })
}

/// What the subnet of an SSE event is computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseSubnets {
    /// `DATA_COLUMN_SIDECAR_SUBNET_COUNT`: a column's subnet is `index % count`.
    pub column_subnet_count: u64,
    /// The committees per slot (`get_committee_count_per_slot`), if known: without it an
    /// unaggregated attestation has no subnet.
    pub committees_per_slot: Option<u64>,
    /// `SLOTS_PER_EPOCH`.
    pub slots_per_epoch: Option<u64>,
}

/// The slot, block root and subnet of an SSE event, from its JSON, under a `data` wrapper when
/// the event is versioned. The slot and root are the event's own (`slot`, and `block_root` or
/// `block`), else those of its `data` (an attestation's `AttestationData`, a PTC message's
/// `PayloadAttestationData`: `beacon_block_root`), else of its `message` (a bid's slot). The
/// subnet of a `data_column_sidecar` is `index % column_subnet_count`; that of a
/// `single_attestation` is `compute_subnet_for_attestation(committees_per_slot, slot,
/// committee_index)`. Missing or malformed fields are `None`.
pub fn decode_sse(
    event: &SseEvent,
    subnets: &SseSubnets,
) -> (Option<Slot>, Option<Root>, Option<u64>) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.data) else {
        return (None, None, None);
    };
    let body = match (json.get("version"), json.get("data")) {
        (Some(_), Some(data)) => data,
        _ => &json,
    };
    let decimal = |object: &serde_json::Value, key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|s| {
                (!s.starts_with('+'))
                    .then(|| s.parse::<u64>().ok())
                    .flatten()
            })
    };
    // The first of the event, its data and its message that carries a slot.
    let inner = [Some(body), body.get("data"), body.get("message")]
        .into_iter()
        .flatten()
        .find(|o| o.get("slot").is_some())
        .unwrap_or(body);
    let slot = decimal(inner, "slot");
    let root = ["block_root", "block", "beacon_block_root"]
        .iter()
        .find_map(|key| inner.get(*key)?.as_str().and_then(parse_root));
    let subnet = match event.event.as_str() {
        "data_column_sidecar" => {
            decimal(body, "index").and_then(|i| i.checked_rem(subnets.column_subnet_count))
        }
        "single_attestation" => attestation_subnet(subnets, slot, decimal(body, "committee_index")),
        _ => None,
    };
    (slot, root, subnet)
}

/// `compute_subnet_for_attestation`: `(committees_per_slot * (slot % SLOTS_PER_EPOCH) +
/// committee_index) % ATTESTATION_SUBNET_COUNT`.
fn attestation_subnet(
    subnets: &SseSubnets,
    slot: Option<Slot>,
    committee_index: Option<u64>,
) -> Option<u64> {
    let since_epoch_start = slot?.checked_rem(subnets.slots_per_epoch?)?;
    let committees = subnets
        .committees_per_slot?
        .checked_mul(since_epoch_start)?
        .checked_add(committee_index?)?;
    Some(committees % ATTESTATION_SUBNET_COUNT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::fixtures::{self, Spec, GLOAS_SLOT};
    use crate::collector::testing;

    #[test]
    fn gossip_topics() {
        let t = parse_gossip_topic("/eth2/0a1b2c3d/data_column_sidecar_12/ssz_snappy").unwrap();
        assert_eq!(
            t,
            GossipTopic {
                fork_digest: [0x0a, 0x1b, 0x2c, 0x3d],
                name: "data_column_sidecar_12"
            }
        );
        for bad in [
            "/eth2/0A1B2C3D/beacon_block/ssz_snappy",
            "/eth2/0a1b2c/beacon_block/ssz_snappy",
            "/eth2/0a1b2c3d/beacon_block/ssz",
            "/eth2/0a1b2c3d//ssz_snappy",
            "/eth2/0a1b2c3d/a/b/ssz_snappy",
            "eth2/0a1b2c3d/beacon_block/ssz_snappy",
            "beacon_block",
        ] {
            assert_eq!(parse_gossip_topic(bad), None, "{bad}");
        }
    }

    #[test]
    fn subnets() {
        assert_eq!(topic_subnet("data_column_sidecar_0"), Some(0));
        assert_eq!(topic_subnet("data_column_sidecar_127"), Some(127));
        assert_eq!(topic_subnet("beacon_attestation_63"), Some(63));
        assert_eq!(topic_subnet("sync_committee_3"), Some(3));
        for none in [
            "beacon_block",
            "data_column_sidecar_",
            "data_column_sidecar_01",
            "data_column_sidecar_+1",
            "sync_committee_contribution_and_proof",
            "execution_payload",
        ] {
            assert_eq!(topic_subnet(none), None, "{none}");
        }
    }

    #[test]
    fn gossip_payloads() {
        let chain = fixtures::chain();
        let (block, root) = fixtures::block(GLOAS_SLOT, 1);
        let got = decode_gossip::<Spec>("beacon_block", &block, &chain).unwrap();
        assert_eq!(
            got,
            Some(Decoded {
                slot: GLOAS_SLOT,
                root
            })
        );

        let (column, root) = fixtures::column(GLOAS_SLOT + 1, 1, 4);
        let got = decode_gossip::<Spec>("data_column_sidecar_4", &column, &chain).unwrap();
        assert_eq!(
            got,
            Some(Decoded {
                slot: GLOAS_SLOT + 1,
                root
            })
        );

        let envelope = testing::envelope(GLOAS_SLOT + 2, Root::repeat_byte(9));
        let got = decode_gossip::<Spec>("execution_payload", &envelope, &chain).unwrap();
        assert_eq!(
            got,
            Some(Decoded {
                slot: GLOAS_SLOT + 2,
                root: Root::repeat_byte(9)
            })
        );

        assert_eq!(
            decode_gossip::<Spec>("voluntary_exit", &block, &chain).unwrap(),
            None
        );
    }

    #[test]
    fn gossip_payloads_that_do_not_decode() {
        let chain = fixtures::chain();
        // An envelope at a Fulu slot: envelopes exist from Gloas only.
        let early = testing::envelope(GLOAS_SLOT - 1, Root::repeat_byte(9));
        let err = decode_gossip::<Spec>("execution_payload", &early, &chain).unwrap_err();
        assert!(matches!(err, PayloadError::Decode(_)), "{err}");
        let (block, _) = fixtures::block(3, 0);
        assert!(decode_gossip::<Spec>("execution_payload", &block, &chain).is_err());
        assert!(decode_gossip::<Spec>("beacon_block", &[0xff; 8], &chain).is_err());
        assert!(matches!(
            decode_gossip::<Spec>("execution_payload", &[0xff; 8], &chain),
            Err(PayloadError::Snappy(_))
        ));
    }

    fn sse(event: &str, data: &str) -> SseEvent {
        SseEvent {
            event: event.into(),
            data: data.into(),
        }
    }

    /// Hoodi's parameters: 128 column subnets, 64 committees a slot, 32 slots an epoch.
    const HOODI: SseSubnets = SseSubnets {
        column_subnet_count: 128,
        committees_per_slot: Some(64),
        slots_per_epoch: Some(32),
    };

    #[test]
    fn exit14_sse_events() {
        let r = format!("0x{}", "ab".repeat(32));
        let root = Some(Root::repeat_byte(0xab));
        // An aggregate (`attestation`): the slot and root are in its data.
        let aggregate = sse(
            "attestation",
            &format!(
                r#"{{"aggregation_bits":"0x01","data":{{"slot":"12","index":"0","beacon_block_root":"{r}"}},"signature":"0x00","committee_bits":"0x01"}}"#
            ),
        );
        assert_eq!(decode_sse(&aggregate, &HOODI), (Some(12), root, None));
        // An unaggregated attestation: its subnet is compute_subnet_for_attestation.
        let single = |slot: u64, committee: u64| {
            sse(
                "single_attestation",
                &format!(
                    r#"{{"committee_index":"{committee}","attester_index":"1","data":{{"slot":"{slot}","index":"0","beacon_block_root":"{r}"}},"signature":"0x00"}}"#
                ),
            )
        };
        assert_eq!(
            decode_sse(&single(12, 5), &HOODI),
            (Some(12), root, Some(5))
        );
        // One committee a slot: (1 * (slot % 32) + 0) % 64.
        let sepolia = SseSubnets {
            committees_per_slot: Some(1),
            ..HOODI
        };
        assert_eq!(decode_sse(&single(45, 0), &sepolia).2, Some(13));
        // 3 committees a slot: (3 * 30 + 2) % 64 = 28.
        let three = SseSubnets {
            committees_per_slot: Some(3),
            ..HOODI
        };
        assert_eq!(decode_sse(&single(30, 2), &three).2, Some(28));
        // Without the committee count there is no subnet.
        let unknown = SseSubnets {
            committees_per_slot: None,
            ..HOODI
        };
        assert_eq!(decode_sse(&single(12, 5), &unknown), (Some(12), root, None));
        // A PTC message: versioned, the slot and root under its data.
        let ptc = sse(
            "payload_attestation_message",
            &format!(
                r#"{{"version":"gloas","data":{{"validator_index":"123","data":{{"beacon_block_root":"{r}","slot":"10","payload_present":true,"blob_data_available":true}},"signature":"0x00"}}}}"#
            ),
        );
        assert_eq!(decode_sse(&ptc, &HOODI), (Some(10), root, None));
        // A bid: versioned, the slot in its message; it names no block root of its own.
        let bid = sse(
            "execution_payload_bid",
            &format!(
                r#"{{"version":"gloas","data":{{"message":{{"parent_block_root":"{r}","slot":"10","builder_index":"42"}},"signature":"0x00"}}}}"#
            ),
        );
        assert_eq!(decode_sse(&bid, &HOODI), (Some(10), None, None));
    }

    #[test]
    fn sse_events() {
        let r = format!("0x{}", "ab".repeat(32));
        let root = Some(Root::repeat_byte(0xab));
        let block = sse("block_gossip", &format!(r#"{{"slot":"10","block":"{r}"}}"#));
        assert_eq!(decode_sse(&block, &HOODI), (Some(10), root, None));
        let column = sse(
            "data_column_sidecar",
            &format!(r#"{{"block_root":"{r}","index":"130","slot":"1"}}"#),
        );
        assert_eq!(decode_sse(&column, &HOODI), (Some(1), root, Some(2)));
        let envelope = sse(
            "execution_payload_gossip",
            &format!(
                r#"{{"slot":"10","builder_index":"42","block_hash":"0x12","block_root":"{r}"}}"#
            ),
        );
        assert_eq!(decode_sse(&envelope, &HOODI), (Some(10), root, None));
        let versioned = sse(
            "head_v2",
            &format!(r#"{{"version":"gloas","data":{{"slot":"10","block":"{r}"}}}}"#),
        );
        assert_eq!(decode_sse(&versioned, &HOODI), (Some(10), root, None));

        for (event, data) in [
            ("block_gossip", r#"{"slot":10,"block":"0x01"}"#),
            ("block_gossip", "not json"),
            ("block_gossip", r#"["slot"]"#),
            ("data_column_sidecar", r#"{"index":"x","slot":"+1"}"#),
        ] {
            assert_eq!(
                decode_sse(&sse(event, data), &HOODI),
                (None, None, None),
                "{data}"
            );
        }
        // A zero subnet count gives no subnet rather than a division by zero.
        let column = sse("data_column_sidecar", r#"{"index":"3"}"#);
        let zero = SseSubnets {
            column_subnet_count: 0,
            ..HOODI
        };
        assert_eq!(decode_sse(&column, &zero), (None, None, None));
    }
}
