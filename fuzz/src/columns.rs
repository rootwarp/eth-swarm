//! The column targets of gate 2a: a Gloas `DataColumnSidecar` as gossip and as a req/resp
//! response chunk (`data_column_sidecar`), and the two column requests (`columns_by_range_req`,
//! `columns_by_root_req`).
//!
//! Every bound is the production one on the pinned Sepolia blob schedule: the Gloas sidecar cap is
//! `compute_max_data_column_sidecar_size()` (`gloas/p2p-interface.md` L324–341) of the schedule's
//! largest `MAX_BLOBS_PER_BLOCK` ([`column_network`]), computed once; no network-config code runs
//! on the input. The response chunks read their context bytes from the fixture digests of
//! [`column_contexts`], which carries those caps: without them a column success chunk is refused
//! before its payload is read, and the success path is never reached.
//!
//! - `data_column_sidecar`: the first byte selects the entry point. With [`CHUNK_BIT`] clear the
//!   rest is the `data` of a gossip message on `data_column_sidecar_{subnet}` (the subnet is the
//!   byte's upper seven bits) under the Gloas digest: `SnappyTransform::inbound` (`p2p_wire::gossip`)
//!   bounds and decompresses it, then `consensus_types::codec::decode_for` decodes the Gloas
//!   sidecar on the network's caps. With [`CHUNK_BIT`] set the rest is one response chunk of
//!   `DataColumnSidecarsByRange` v1 (or, with [`ROOT_BIT`], `DataColumnSidecarsByRoot` v1):
//!   `decode_response_chunk` decodes it by the fork its context bytes name, the incremental
//!   scanners run on the same bytes as for `rpc_chunk`, and the timed codec reads it as the
//!   response to a request naming one sidecar.
//! - `columns_by_range_req` / `columns_by_root_req`: the input is one inbound request, read by
//!   the timed codec and `decode_request` (held to each other as for the control targets), then
//!   judged by `column_request_error`, the check cl-p2p admits a column request with
//!   (`fulu/p2p-interface.md` L746–747), and its chunk limit `max_response_chunks`.
//!
//! The invariants, past those the shared harness holds every chunk and request to:
//!
//! - a gossip message the transform accepts is at most the column topic's cap, which is the
//!   spec's sidecar size formula, written out here on its own ([`spec_max_sidecar_size`]); the
//!   decoder never refuses it as too large, and never for want of network caps or of the kind
//!   at Gloas;
//! - a decoded sidecar re-encodes to exactly its SSZ bytes, is at most its fork's cap, and agrees
//!   with the decode by the fork of its own slot (`from_ssz_bytes_by_slot` on the Sepolia
//!   schedule): the same sidecar where that fork is the one the transport named, a refusal where
//!   it is not (the two shapes differ in their first offset);
//! - the chunk decoder and the timed codec accept the same chunk (the codec also accepts the
//!   empty response), and the codec records the chunk's context digest;
//! - a request's verdict is the spec rule's ([`spec_request_rule`]: every index below
//!   `NUMBER_OF_COLUMNS`, at most `MAX_REQUEST_DATA_COLUMN_SIDECARS` sidecars, counted without
//!   saturation), its chunk limit is the sidecars it names (at most the bound), and its lists are
//!   within their SSZ limits. cl-chain's `ReqRespService` holds the same bounds on what cl-p2p
//!   forwards (`cl_chain::reqresp`), so the rule is cl-chain's too.
//!
//! The decoders do not check that a sidecar's cells, proofs and commitments line up, or that its
//! index is below `NUMBER_OF_COLUMNS`: those are `verify_data_column_sidecar` rules, which gossip
//! validation and the column store apply to a decoded sidecar. The seeds hold such sidecars, so
//! the fuzzer starts next to them.

use crate::chunk::{agree, feed};
use crate::{check_chunk_in, timed, E};
use consensus_types::caps::{
    compute_max_data_column_sidecar_size, NetworkCaps, ObjectKind, MAX_PAYLOAD_SIZE,
};
use consensus_types::codec::{decode_for, DecodeError, Object};
use consensus_types::{forked, EthSpec, ForkName, ForkSchedule};
use network_config::{ChainConfig, Network};
use p2p_wire::gossip::{GossipKind, GossipTopic, SnappyTransform, TopicCaps};
use p2p_wire::rpc::codec::{
    decode_response_chunk, max_compressed_len, scan_response_chunk, ContextTable,
    ResponseChunkScanner, Scan, CONTEXT_BYTES_LEN,
};
use p2p_wire::rpc::messages::{DataColumnsByRangeV1Request, DataColumnsByRootIdentifier};
use p2p_wire::rpc::protocols::{
    column_request_error, Protocol, Request, Response, ResponseChunk, MAX_REQUEST_BLOCKS_DENEB,
    MAX_REQUEST_DATA_COLUMN_SIDECARS, NUMBER_OF_COLUMNS,
};
use p2p_wire::testkit;
use ssz::Encode;
use ssz_types::typenum::Unsigned;
use std::io;
use std::sync::{Arc, OnceLock};

/// `data_column_sidecar`: a first byte with this bit set selects a response chunk, clear a gossip
/// message.
pub const CHUNK_BIT: u8 = 0x01;
/// `data_column_sidecar`, response chunk: with this bit set the chunk is a
/// `DataColumnSidecarsByRoot` v1 one, clear a `DataColumnSidecarsByRange` v1 one.
pub const ROOT_BIT: u8 = 0x02;

/// The column targets' setup: the Sepolia caps and schedule, the context table with those caps
/// (shared with the timed codec) and the gossip transform.
struct Columns {
    network: NetworkCaps,
    schedule: ForkSchedule,
    contexts: Arc<ContextTable>,
    snappy: SnappyTransform,
}

fn columns() -> &'static Columns {
    static COLUMNS: OnceLock<Columns> = OnceLock::new();
    COLUMNS.get_or_init(|| {
        let config = ChainConfig::load(Network::Sepolia).expect("the pinned Sepolia config");
        let network = NetworkCaps::from_config(&config);
        Columns {
            network,
            schedule: *config.fork_schedule(),
            contexts: Arc::new(testkit::context_table().with_network_caps(network)),
            snappy: SnappyTransform::new(TopicCaps::gloas::<E>(&network)),
        }
    })
}

/// The network caps of the column targets: the pinned Sepolia blob schedule's.
pub fn column_network() -> &'static NetworkCaps {
    &columns().network
}

/// The fork schedule a sidecar's slot is mapped through: the pinned Sepolia one.
pub fn column_schedule() -> &'static ForkSchedule {
    &columns().schedule
}

/// The fixture context table (Fulu, a Fulu BPO digest, Gloas) with [`column_network`]'s caps.
pub fn column_contexts() -> &'static ContextTable {
    &columns().contexts
}

/// The gossip topic of `data_column_sidecar` for `subnet`, under the fixture Gloas digest.
pub fn column_topic(subnet: u8) -> String {
    GossipTopic::new(
        testkit::GLOAS_DIGEST,
        GossipKind::DataColumnSidecar {
            subnet_id: u64::from(subnet),
        },
    )
    .to_string()
}

/// The serialized length of a Gloas `DataColumnSidecar` holding `max_blobs` cells and proofs,
/// the spec's `compute_max_data_column_sidecar_size()` (`gloas/p2p-interface.md` L324–341):
/// `index` (8), the `column` and `kzg_proofs` offsets (4 each), `slot` (8) and
/// `beacon_block_root` (32), then `BYTES_PER_CELL` and a 48-byte `KZGProof` per blob.
pub fn spec_max_sidecar_size(max_blobs: u64) -> u64 {
    let fixed = 8 + 4 + 4 + 8 + 32;
    let per_blob = <E as EthSpec>::BytesPerCell::to_u64() + 48;
    fixed + max_blobs * per_blob
}

/// `data_column_sidecar`: see the module docs.
pub fn data_column_sidecar(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if selector & CHUNK_BIT == 0 {
        gossip(selector >> 1, rest);
    } else if selector & ROOT_BIT == 0 {
        chunk(Protocol::DataColumnsByRangeV1, rest);
    } else {
        chunk(Protocol::DataColumnsByRootV1, rest);
    }
}

/// One gossip message's `data` on the column topic of `subnet`.
fn gossip(subnet: u8, data: &[u8]) {
    let c = columns();
    let topic = column_topic(subnet);
    let Ok(ssz) = c.snappy.inbound(&topic, data) else {
        return;
    };
    let cap = c.snappy.caps().cap(GossipKind::DataColumnSidecar {
        subnet_id: u64::from(subnet),
    });
    let spec_cap = spec_max_sidecar_size(c.network.max_blobs_per_block());
    assert_eq!(
        cap as u64,
        spec_cap.min(MAX_PAYLOAD_SIZE as u64),
        "the column topic's cap is not compute_max_data_column_sidecar_size()"
    );
    assert!(
        ssz.len() <= cap,
        "{} bytes accepted under a {cap}-byte cap",
        ssz.len()
    );
    assert!(
        data.len() <= max_compressed_len(MAX_PAYLOAD_SIZE),
        "{} compressed bytes accepted",
        data.len()
    );
    assert_eq!(
        snap::raw::decompress_len(data).ok(),
        Some(ssz.len()),
        "decompressed to another length than the header declares"
    );
    match decode_for::<E>(
        ObjectKind::DataColumnSidecar,
        ForkName::Gloas,
        &c.network,
        &ssz,
    ) {
        Ok(Object::DataColumnSidecar(sidecar)) => {
            assert_eq!(
                sidecar.fork_name(),
                ForkName::Gloas,
                "a Gloas decode of another fork"
            );
            check_sidecar(&sidecar, &ssz, ForkName::Gloas);
        }
        Ok(other) => panic!("a DataColumnSidecar decode returned {:?}", other.kind()),
        Err(e) => {
            assert!(
                matches!(e, DecodeError::Ssz(_)),
                "a message within the topic cap refused before decoding: {e}"
            );
            by_slot(&ssz, None, ForkName::Gloas);
        }
    }
}

/// The invariants of a decoded sidecar `sidecar` of `ssz`, decoded by `named`, the fork the
/// topic or the context bytes named.
fn check_sidecar(sidecar: &forked::DataColumnSidecar<E>, ssz: &[u8], named: ForkName) {
    assert!(
        sidecar.as_ssz_bytes() == ssz,
        "the sidecar re-encodes to other bytes"
    );
    let network = column_network();
    let cap =
        consensus_types::caps::max_size_for::<E>(ObjectKind::DataColumnSidecar, named, network)
            .expect("a sidecar exists at every supported fork");
    assert!(
        ssz.len() <= cap,
        "{} bytes over the {cap}-byte cap",
        ssz.len()
    );
    if named == ForkName::Gloas {
        assert_eq!(
            compute_max_data_column_sidecar_size::<E>(network),
            spec_max_sidecar_size(network.max_blobs_per_block()),
            "compute_max_data_column_sidecar_size() breaks the spec formula"
        );
    }
    by_slot(ssz, Some(sidecar), named);
}

/// `ssz` decoded by the fork of its own slot agrees with `shaped`, its decode by `named` (`None`
/// if that refused it): both are the same sidecar, or the slot's fork is another (the shapes
/// differ in their first offset, so only one of the two can accept).
fn by_slot(ssz: &[u8], shaped: Option<&forked::DataColumnSidecar<E>>, named: ForkName) {
    let by_slot = forked::DataColumnSidecar::<E>::from_ssz_bytes_by_slot(
        ssz,
        column_schedule(),
        column_network(),
    );
    match (shaped, by_slot) {
        (Some(shaped), Ok(by_slot)) => {
            assert!(
                *shaped == by_slot,
                "the decode by the slot's fork differs from the decode by {named}"
            );
            let fork = forked::fork_at_slot::<E>(column_schedule(), by_slot.slot());
            assert_eq!(fork, Ok(named), "decoded by slot with another fork");
        }
        (Some(shaped), Err(_)) => {
            let fork = forked::fork_at_slot::<E>(column_schedule(), shaped.slot());
            assert_ne!(
                fork,
                Ok(named),
                "a {named} sidecar at a {named} slot refused by its slot's fork"
            );
        }
        (None, Ok(by_slot)) => assert_ne!(
            by_slot.fork_name(),
            named,
            "refused by {named}, accepted by the same fork through its slot"
        ),
        (None, Err(_)) => {}
    }
}

/// The request we send on `protocol` for one sidecar: the response is at most one chunk.
fn one_sidecar_request(protocol: Protocol) -> Request {
    match protocol {
        Protocol::DataColumnsByRangeV1 => {
            Request::DataColumnsByRange(DataColumnsByRangeV1Request {
                start_slot: 0,
                count: 1,
                columns: vec![0].try_into().expect("one column"),
            })
        }
        Protocol::DataColumnsByRootV1 => {
            Request::DataColumnsByRoot(p2p_wire::rpc::messages::DataColumnsByRootV1Request(
                vec![DataColumnsByRootIdentifier {
                    block_root: Default::default(),
                    columns: vec![0].try_into().expect("one column"),
                }]
                .try_into()
                .expect("one identifier"),
            ))
        }
        other => panic!("{other} is not a column protocol"),
    }
}

/// One response chunk of a column protocol.
fn chunk(protocol: Protocol, wire: &[u8]) {
    let contexts = column_contexts();
    let mut scanner = ResponseChunkScanner::<E>::new(protocol, contexts);
    let fed = feed(wire, |buf| scanner.scan(buf));
    let whole = scan_response_chunk::<E>(wire, protocol, contexts);
    agree(&fed, wire.len(), &whole);
    let direct = decode_response_chunk::<E>(wire, protocol, contexts);
    if let Ok(decoded) = &direct {
        assert_eq!(
            whole,
            Ok(Scan::Complete { len: wire.len() }),
            "an accepted chunk does not scan as complete at its length"
        );
        check_chunk_in(contexts, wire, protocol, decoded);
        if let ResponseChunk::Success(Response::DataColumn(sidecar)) = decoded {
            let named = sidecar.fork_name();
            check_sidecar(sidecar, &sidecar.as_ssz_bytes(), named);
        }
    }
    let request = one_sidecar_request(protocol);
    let read = timed::read_response_in(&columns().contexts, request, wire);
    match (read, direct) {
        (Ok(chunks), Ok(decoded)) => {
            let [received] = chunks.as_slice() else {
                panic!("one chunk read as {} chunks", chunks.len());
            };
            assert!(
                received.chunk == decoded,
                "the codec and the chunk decoder disagree"
            );
            let context = matches!(decoded, ResponseChunk::Success(_))
                .then(|| wire[1..1 + CONTEXT_BYTES_LEN].try_into().expect("4 bytes"));
            assert_eq!(received.context, context, "the codec's context digest");
        }
        (Ok(chunks), Err(e)) => assert!(
            chunks.is_empty() && wire.is_empty(),
            "the codec accepted {} chunks the chunk decoder refuses: {e}",
            chunks.len()
        ),
        (Err(e), Ok(_)) => panic!("the codec refused a chunk the chunk decoder accepts: {e}"),
        (Err(e), Err(_)) => assert_ne!(
            e.kind(),
            io::ErrorKind::TimedOut,
            "a deadline passed on an in-memory stream: {e}"
        ),
    }
}

/// `columns_by_range_req`: one inbound `DataColumnSidecarsByRange` v1 request.
pub fn columns_by_range_req(wire: &[u8]) {
    column_request(Protocol::DataColumnsByRangeV1, wire);
}

/// `columns_by_root_req`: one inbound `DataColumnSidecarsByRoot` v1 request.
pub fn columns_by_root_req(wire: &[u8]) {
    column_request(Protocol::DataColumnsByRootV1, wire);
}

/// Why the spec refuses a decoded column request (`1: InvalidRequest`), else how many sidecars it
/// names (`fulu/p2p-interface.md` L684–685, L728–730, L746–747): every index must be below
/// `NUMBER_OF_COLUMNS`, and the sidecars (a range's `count × len(columns)`, the sum of the
/// identifiers' columns) at most `MAX_REQUEST_DATA_COLUMN_SIDECARS`. Counted in `u128`, so no
/// count saturates or wraps.
pub fn spec_request_rule(request: &Request) -> Result<u64, &'static str> {
    let (indices, sidecars): (Vec<u64>, u128) = match request {
        Request::DataColumnsByRange(r) => (
            r.columns.to_vec(),
            u128::from(r.count) * r.columns.len() as u128,
        ),
        Request::DataColumnsByRoot(r) => {
            let indices: Vec<u64> = r.0.iter().flat_map(|id| id.columns.to_vec()).collect();
            let sidecars = indices.len() as u128;
            (indices, sidecars)
        }
        _ => return Err("not a column request"),
    };
    if indices.iter().any(|&i| i >= NUMBER_OF_COLUMNS) {
        return Err("an index at or past NUMBER_OF_COLUMNS");
    }
    u64::try_from(sidecars)
        .ok()
        .filter(|&n| n <= MAX_REQUEST_DATA_COLUMN_SIDECARS)
        .ok_or("more sidecars than MAX_REQUEST_DATA_COLUMN_SIDECARS")
}

/// A column request through the timed codec and the request decoder, then its verdict.
fn column_request(protocol: Protocol, wire: &[u8]) {
    let Some(request) = crate::request(protocol, wire) else {
        return;
    };
    match &request {
        Request::DataColumnsByRange(r) => assert!(
            r.columns.len() as u64 <= NUMBER_OF_COLUMNS,
            "{} columns decoded",
            r.columns.len()
        ),
        Request::DataColumnsByRoot(r) => {
            assert!(
                r.0.len() as u64 <= MAX_REQUEST_BLOCKS_DENEB,
                "{} identifiers decoded",
                r.0.len()
            );
            for id in r.0.iter() {
                assert!(
                    id.columns.len() as u64 <= NUMBER_OF_COLUMNS,
                    "{} columns decoded in one identifier",
                    id.columns.len()
                );
            }
            // The two list limits bound the sidecars by themselves.
            assert!(
                r.requested_sidecars() <= MAX_REQUEST_DATA_COLUMN_SIDECARS,
                "a decoded by-root request names {} sidecars",
                r.requested_sidecars()
            );
        }
        other => panic!("a {protocol} request decoded to {other:?}"),
    }
    let rule = spec_request_rule(&request);
    let error = column_request_error(&request);
    match (&rule, &error) {
        (Ok(_), Some(why)) => panic!("a request the spec allows refused: {why}"),
        (Err(why), None) => panic!("a request the spec refuses ({why}) admitted"),
        _ => {}
    }
    let chunks = request.max_response_chunks();
    assert!(
        chunks <= MAX_REQUEST_DATA_COLUMN_SIDECARS,
        "a chunk limit of {chunks}"
    );
    if let Ok(sidecars) = rule {
        assert_eq!(
            chunks, sidecars,
            "the chunk limit is not the sidecars named"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_column_caps_are_the_sepolia_schedule() {
        let network = column_network();
        assert!(network.max_blobs_per_block() > 0);
        let cap = spec_max_sidecar_size(network.max_blobs_per_block());
        assert_eq!(compute_max_data_column_sidecar_size::<E>(network), cap);
        assert_eq!(column_contexts().network_caps(), Some(network));
        for digest in [
            testkit::FULU_DIGEST,
            testkit::FULU_BPO_DIGEST,
            testkit::GLOAS_DIGEST,
        ] {
            assert!(column_contexts().fork(&digest).is_some());
        }
        assert_eq!(
            column_schedule().fork_at(353_024),
            Some(ForkName::Gloas),
            "Sepolia's Gloas epoch"
        );
    }

    #[test]
    fn the_spec_rule_counts_without_saturating() {
        let range = |count, columns: Vec<u64>| {
            Request::DataColumnsByRange(DataColumnsByRangeV1Request {
                start_slot: 0,
                count,
                columns: columns.try_into().unwrap(),
            })
        };
        assert_eq!(
            spec_request_rule(&range(128, (0..128).collect())),
            Ok(16_384)
        );
        assert!(spec_request_rule(&range(129, (0..128).collect())).is_err());
        assert!(spec_request_rule(&range(u64::MAX, vec![1, 2])).is_err());
        assert_eq!(spec_request_rule(&range(u64::MAX, vec![])), Ok(0));
        assert!(spec_request_rule(&range(1, vec![128])).is_err());
        assert!(spec_request_rule(&Request::MetaData).is_err());
    }

    #[test]
    fn the_selector_picks_the_entry_point() {
        // An empty gossip message, an empty response on either protocol: nothing to check, but
        // each reaches its entry point without a panic.
        data_column_sidecar(&[0]);
        data_column_sidecar(&[CHUNK_BIT]);
        data_column_sidecar(&[CHUNK_BIT | ROOT_BIT]);
        assert_eq!(
            column_topic(127),
            "/eth2/610a5001/data_column_sidecar_127/ssz_snappy"
        );
    }
}
