//! The gate-2a seeds: `data_column_sidecar` (gossip messages and response chunks of both column
//! protocols) and the two column requests, `columns_by_range_req` and `columns_by_root_req`.
//!
//! The sidecars hold the shapes a peer may send and the decoder must not trip on: valid Gloas
//! and Fulu sidecars, a Gloas sidecar at exactly the Sepolia cap and one blob past it (an
//! oversize column list, refused from its declared length), a column list past the cap with no
//! proofs, cell counts that are not the proof or commitment counts, an index at and far past
//! `NUMBER_OF_COLUMNS`, sidecars at slots of another fork than the one the transport named and
//! before Fulu, hand-broken offsets, snappy bombs (headers declaring one byte past the cap,
//! past `MAX_PAYLOAD_SIZE`, 4 GiB and more; zeros at the cap), and the framing refusals of the
//! response chunk. The requests hold the bounds: 128 columns and 128 × 128 sidecars exactly at
//! their limits and one past them, a `count × len(columns)` that overflows `u64`, identifier
//! lists at `MAX_REQUEST_BLOCKS_DENEB` and one past it (as an empty and as a full list), an
//! identifier with one column too many, indices at and past `NUMBER_OF_COLUMNS`, empty
//! requests, broken offsets and the framing refusals.

use super::{cat, framed, Seed, Sink, OVER_4GIB};
use crate::{column_network, spec_max_sidecar_size, CHUNK_BIT, E, ROOT_BIT};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use consensus_types::{fulu, EthSpec};
use p2p_wire::rpc::codec::{encode_chunk, encode_success_chunk};
use p2p_wire::rpc::messages::{
    DataColumnsByRangeV1Request, DataColumnsByRootIdentifier, DataColumnsByRootV1Request,
    ForkDigest,
};
use p2p_wire::rpc::protocols::{Protocol, ResultCode};
use p2p_wire::testkit;
use ssz::Encode;
use ssz_types::typenum::Unsigned;

const SIDECAR: &str = "data_column_sidecar";
const RANGE: &str = "columns_by_range_req";
const ROOT: &str = "columns_by_root_req";

/// Sepolia's Fulu and Gloas fork epochs (`network-config`'s pinned config), as slots of the
/// mainnet preset: the seeds' sidecars sit at a slot of the fork that names them.
const FULU_SLOT: u64 = 272_640 * 32;
/// See [`FULU_SLOT`].
const GLOAS_SLOT: u64 = 353_024 * 32;

/// A Gloas sidecar's fixed part: `index`, the two offsets, `slot` and `beacon_block_root`.
const GLOAS_FIXED: usize = 8 + 4 + 4 + 8 + 32;

/// The largest blob count of the Sepolia schedule: the Gloas cap holds this many cells and proofs.
fn max_blobs() -> usize {
    usize::try_from(column_network().max_blobs_per_block()).expect("a small blob count")
}

/// A Gloas sidecar of column `index` at `slot` with `cells` cells and `proofs` proofs.
fn gloas_sidecar(index: u64, slot: u64, cells: usize, proofs: usize) -> Vec<u8> {
    let mut sidecar = testkit::gloas_sidecar::<E>(slot, index);
    let cell = sidecar.column[0].clone();
    let proof = sidecar.kzg_proofs[0];
    sidecar.column = vec![cell; cells].try_into().expect("an unbounded list");
    sidecar.kzg_proofs = vec![proof; proofs].try_into().expect("an unbounded list");
    sidecar.as_ssz_bytes()
}

/// A Fulu sidecar of column `index` at `slot` with `cells` cells, `commitments` commitments and
/// `proofs` proofs.
fn fulu_sidecar(index: u64, slot: u64, cells: usize, commitments: usize, proofs: usize) -> Vec<u8> {
    let mut sidecar: fulu::DataColumnSidecar<E> = testkit::fulu_sidecar::<E>(slot, index);
    let cell = sidecar.column[0].clone();
    let key = sidecar.kzg_proofs[0];
    sidecar.column = vec![cell; cells].try_into().expect("within the Fulu bound");
    sidecar.kzg_commitments = vec![key; commitments]
        .try_into()
        .expect("within the Fulu bound");
    sidecar.kzg_proofs = vec![key; proofs].try_into().expect("within the Fulu bound");
    sidecar.as_ssz_bytes()
}

/// Every gate-2a seed.
pub fn all(seeds: &mut Vec<Seed>) {
    gossip(seeds);
    for (lead, prefix) in [(CHUNK_BIT, "range-"), (CHUNK_BIT | ROOT_BIT, "root-")] {
        chunks(seeds, lead, prefix);
    }
    range_requests(seeds);
    root_requests(seeds);
}

fn compress(ssz: &[u8]) -> Vec<u8> {
    snap::raw::Encoder::new()
        .compress_vec(ssz)
        .expect("within snappy's limit")
}

/// A snappy block header declaring `declared` bytes, then 16 zero bytes of body.
fn declaring(declared: u64) -> Vec<u8> {
    cat(&[&varint_u64(declared), &[0; 16]])
}

fn varint_u64(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    p2p_wire::rpc::codec::encode_varint(n, &mut out);
    out
}

/// The raw Gloas sidecar layout with the given offsets and variable part, at the Gloas slot.
fn gloas_raw(column_offset: u32, proofs_offset: u32, variable: &[u8]) -> Vec<u8> {
    cat(&[
        &47u64.to_le_bytes(),
        &column_offset.to_le_bytes(),
        &proofs_offset.to_le_bytes(),
        &GLOAS_SLOT.to_le_bytes(),
        &[0x40; 32],
        variable,
    ])
}

/// `data_column_sidecar` gossip messages, named `gossip-*`, after the selector of their subnet.
fn gossip(seeds: &mut Vec<Seed>) {
    let cell_len = <E as EthSpec>::BytesPerCell::to_usize();
    let cap = usize::try_from(spec_max_sidecar_size(max_blobs() as u64)).expect("a small cap");
    let blobs = max_blobs();
    let valid = gloas_sidecar(47, GLOAS_SLOT + 1, 1, 1);
    let valid_message = compress(&valid);
    let column = |subnet: u8| subnet << 1;
    let mut add = |subnet: u8, name: &str, data: Vec<u8>| {
        seeds.push(Seed {
            target: SIDECAR,
            slow: false,
            name: format!("gossip-{name}"),
            bytes: cat(&[&[column(subnet)], &data]),
        });
    };
    add(47, "valid", valid_message.clone());
    add(
        0,
        "valid-subnet-0",
        compress(&gloas_sidecar(0, GLOAS_SLOT, 1, 1)),
    );
    add(
        127,
        "valid-subnet-127",
        compress(&gloas_sidecar(127, GLOAS_SLOT, 1, 1)),
    );
    add(
        47,
        "no-cells",
        compress(&gloas_sidecar(47, GLOAS_SLOT, 0, 0)),
    );
    add(
        47,
        "at-cap",
        compress(&gloas_sidecar(47, GLOAS_SLOT, blobs, blobs)),
    );
    add(
        47,
        "oversize-column-list",
        compress(&gloas_sidecar(47, GLOAS_SLOT, blobs + 1, blobs + 1)),
    );
    add(
        47,
        "oversize-cells-no-proofs",
        compress(&gloas_sidecar(47, GLOAS_SLOT, blobs + 1, 0)),
    );
    add(
        47,
        "cells-ne-proofs",
        compress(&gloas_sidecar(47, GLOAS_SLOT, 2, 1)),
    );
    // Proofs far past the cells, within the cap: (cap - fixed - cell) / 48 proofs.
    let proofs = (cap - GLOAS_FIXED - cell_len) / 48;
    add(
        47,
        "proofs-far-past-cells",
        compress(&gloas_sidecar(47, GLOAS_SLOT, 1, proofs)),
    );
    add(
        0,
        "index-128",
        compress(&gloas_sidecar(128, GLOAS_SLOT, 1, 1)),
    );
    add(
        127,
        "index-u64-max",
        compress(&gloas_sidecar(u64::MAX, GLOAS_SLOT, 1, 1)),
    );
    add(
        47,
        "fulu-slot",
        compress(&gloas_sidecar(47, FULU_SLOT, 1, 1)),
    );
    add(47, "pre-fulu-slot", compress(&gloas_sidecar(47, 9, 1, 1)));
    add(
        47,
        "fulu-sidecar",
        compress(&fulu_sidecar(47, FULU_SLOT, 1, 1, 1)),
    );
    // Hand-broken layouts.
    let cell = vec![47u8; cell_len];
    let proof = [0xbb; 48];
    let fixed = GLOAS_FIXED as u32;
    add(
        47,
        "proofs-offset-before-column",
        compress(&gloas_raw(fixed, fixed - 4, &cat(&[&cell, &proof]))),
    );
    add(
        47,
        "column-not-whole-cells",
        compress(&gloas_raw(
            fixed,
            fixed + 2047,
            &cat(&[&cell[..2047], &proof]),
        )),
    );
    add(
        47,
        "first-offset-of-fulu",
        compress(&gloas_raw(356, 356 + 2048, &cat(&[&cell, &proof]))),
    );
    add(
        47,
        "proofs-offset-past-end",
        compress(&gloas_raw(fixed, fixed + 4096, &cat(&[&cell, &proof]))),
    );
    // Snappy bombs and broken blocks.
    add(47, "declares-cap-plus-1", declaring(cap as u64 + 1));
    add(
        47,
        "declares-over-10mib",
        declaring(MAX_PAYLOAD_SIZE as u64 + 1),
    );
    add(47, "declares-4gib", declaring(u64::from(u32::MAX)));
    add(47, "declares-over-4gib", declaring(OVER_4GIB as u64));
    add(47, "snappy-bomb-at-cap", compress(&vec![0; cap]));
    add(47, "varint-11-bytes", cat(&[&[0x80; 10], &[0x01]]));
    add(
        47,
        "truncated",
        valid_message[..valid_message.len() - 1].to_vec(),
    );
    add(47, "trailing-byte", cat(&[&valid_message, &[0]]));
    add(47, "not-snappy", vec![0xff, 0x00, 0x01]);
    add(47, "empty-data", Vec::new());
}

fn sidecar_chunk(digest: ForkDigest, ssz: &[u8]) -> Vec<u8> {
    encode_success_chunk(Some(digest), ssz).expect("a sidecar within MAX_PAYLOAD_SIZE")
}

/// `data_column_sidecar` response chunks after the selector `lead`, named `{prefix}*`.
fn chunks(seeds: &mut Vec<Seed>, lead: u8, prefix: &str) {
    let blobs = max_blobs();
    let gloas = gloas_sidecar(47, GLOAS_SLOT + 1, 1, 1);
    let fulu = fulu_sidecar(47, FULU_SLOT + 1, 1, 1, 1);
    let gloas_chunk = sidecar_chunk(testkit::GLOAS_DIGEST, &gloas);
    let mut sink = Sink {
        seeds,
        target: SIDECAR,
        lead: &[lead],
        prefix,
    };
    sink.add("gloas-valid", &gloas_chunk);
    sink.add(
        "gloas-at-cap",
        &sidecar_chunk(
            testkit::GLOAS_DIGEST,
            &gloas_sidecar(47, GLOAS_SLOT, blobs, blobs),
        ),
    );
    sink.add(
        "gloas-oversize-column-list",
        &sidecar_chunk(
            testkit::GLOAS_DIGEST,
            &gloas_sidecar(47, GLOAS_SLOT, blobs + 1, blobs + 1),
        ),
    );
    sink.add(
        "gloas-cells-ne-proofs",
        &sidecar_chunk(testkit::GLOAS_DIGEST, &gloas_sidecar(47, GLOAS_SLOT, 3, 1)),
    );
    sink.add(
        "gloas-index-128",
        &sidecar_chunk(testkit::GLOAS_DIGEST, &gloas_sidecar(128, GLOAS_SLOT, 1, 1)),
    );
    sink.add(
        "gloas-fulu-slot",
        &sidecar_chunk(testkit::GLOAS_DIGEST, &gloas_sidecar(47, FULU_SLOT, 1, 1)),
    );
    sink.add("fulu-valid", &sidecar_chunk(testkit::FULU_DIGEST, &fulu));
    sink.add(
        "fulu-bpo-digest-valid",
        &sidecar_chunk(testkit::FULU_BPO_DIGEST, &fulu),
    );
    sink.add(
        "fulu-cells-ne-commitments",
        &sidecar_chunk(testkit::FULU_DIGEST, &fulu_sidecar(47, FULU_SLOT, 2, 1, 3)),
    );
    sink.add(
        "fulu-index-128",
        &sidecar_chunk(testkit::FULU_DIGEST, &fulu_sidecar(128, FULU_SLOT, 1, 1, 1)),
    );
    sink.add(
        "fulu-gloas-slot",
        &sidecar_chunk(testkit::FULU_DIGEST, &fulu_sidecar(47, GLOAS_SLOT, 1, 1, 1)),
    );
    sink.add(
        "gloas-sidecar-under-fulu-digest",
        &sidecar_chunk(testkit::FULU_DIGEST, &gloas),
    );
    sink.add(
        "fulu-sidecar-under-gloas-digest",
        &sidecar_chunk(testkit::GLOAS_DIGEST, &fulu),
    );
    sink.add(
        "unknown-context-digest",
        &sidecar_chunk(testkit::UNKNOWN_DIGEST, &gloas),
    );
    sink.add(
        "context-cut-short",
        &[ResultCode::Success.as_byte(), testkit::GLOAS_DIGEST[0]],
    );
    sink.add("empty-response", &[]);
    sink.result_codes();
    let head = cat(&[&[ResultCode::Success.as_byte()], &testkit::GLOAS_DIGEST]);
    let cap = usize::try_from(spec_max_sidecar_size(blobs as u64)).expect("a small cap");
    sink.bad_payloads(&head, cap, 1000);
    sink.bad_frames(&head, 1000, Some((&head, 1000)));
    sink.add(
        "prefix-under-sidecar-minimum",
        &cat(&[&head, &framed(10, &[0; 10])]),
    );
    sink.add(
        "snappy-bomb-within-bound",
        &cat(&[&head, &framed(cap, &vec![0; cap])]),
    );
    sink.truncated_and_trailing(&gloas_chunk);
}

/// The framing refusals of a request whose valid encoding is `valid`, named as `rpc_chunk`'s:
/// prefixes past `MAX_PAYLOAD_SIZE`, 4 GiB and the request's bound (and under its minimum, if it
/// has one), a snappy bomb and frames past a small prefix, an 11-byte varint, the frame caps,
/// and the request cut short and with a byte after it.
fn request_framing(sink: &mut Sink<'_>, protocol: Protocol, valid: &[u8], ssz_len: usize) {
    let bounds = protocol
        .request_bounds()
        .expect("a column request has a body");
    sink.bad_payloads(&[], bounds.max, ssz_len);
    if bounds.min > 0 {
        sink.add("prefix-under-type-bound", &framed(bounds.min - 1, &[0; 16]));
    }
    sink.bad_frames(&[], ssz_len, Some((&[], bounds.max)));
    sink.truncated_and_trailing(valid);
}

fn range_request(count: u64, columns: Vec<u64>) -> Vec<u8> {
    DataColumnsByRangeV1Request {
        start_slot: GLOAS_SLOT,
        count,
        columns: columns.try_into().expect("within NUMBER_OF_COLUMNS"),
    }
    .as_ssz_bytes()
}

/// `columns_by_range_req`: one request, no selector.
fn range_requests(seeds: &mut Vec<Seed>) {
    let mut sink = Sink {
        seeds,
        target: RANGE,
        lead: &[],
        prefix: "",
    };
    let ssz = range_request(32, vec![1, 47, 87, 102]);
    let valid = encode_chunk(&ssz).expect("a small request");
    sink.add("valid", &valid);
    let mut add = |name: &str, ssz: &[u8]| sink.add(name, &encode_chunk(ssz).expect("small"));
    add("at-sidecar-bound", &range_request(128, (0..128).collect()));
    add(
        "sidecars-past-bound",
        &range_request(129, (0..128).collect()),
    );
    add(
        "count-times-columns-overflows",
        &range_request(u64::MAX, vec![0, 1]),
    );
    add("count-u64-max-no-columns", &range_request(u64::MAX, vec![]));
    add("count-0", &range_request(0, vec![1, 2]));
    add("no-columns", &range_request(32, vec![]));
    add("index-128", &range_request(1, vec![1, 128]));
    add("index-u64-max", &range_request(1, vec![u64::MAX]));
    add("duplicate-columns", &range_request(2, vec![5, 5, 5]));
    add(
        "columns-at-list-bound",
        &range_request(1, (0..128).collect()),
    );
    let head = cat(&[&GLOAS_SLOT.to_le_bytes(), &1u64.to_le_bytes()]);
    let indices: Vec<u8> = (0..129u64).flat_map(u64::to_le_bytes).collect();
    add(
        "columns-past-list-bound",
        &cat(&[&head, &20u32.to_le_bytes(), &indices]),
    );
    add(
        "columns-offset-not-20",
        &cat(&[&head, &24u32.to_le_bytes(), &[0; 4], &1u64.to_le_bytes()]),
    );
    add(
        "columns-not-whole-indices",
        &cat(&[&head, &20u32.to_le_bytes(), &[1; 7]]),
    );
    request_framing(&mut sink, Protocol::DataColumnsByRangeV1, &valid, ssz.len());
}

fn identifier(byte: u8, columns: Vec<u64>) -> DataColumnsByRootIdentifier {
    DataColumnsByRootIdentifier {
        block_root: [byte; 32].into(),
        columns: columns.try_into().expect("within NUMBER_OF_COLUMNS"),
    }
}

fn root_request(ids: Vec<DataColumnsByRootIdentifier>) -> Vec<u8> {
    DataColumnsByRootV1Request(ids.try_into().expect("within MAX_REQUEST_BLOCKS_DENEB"))
        .as_ssz_bytes()
}

/// The SSZ of `ids` (any count) as a list of identifiers: one offset each, then the identifiers.
fn raw_identifier_list(ids: &[Vec<u8>]) -> Vec<u8> {
    let mut offset = ids.len() * 4;
    let mut out = Vec::new();
    for id in ids {
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += id.len();
    }
    for id in ids {
        out.extend_from_slice(id);
    }
    out
}

/// `columns_by_root_req`: one request, no selector.
fn root_requests(seeds: &mut Vec<Seed>) {
    let mut sink = Sink {
        seeds,
        target: ROOT,
        lead: &[],
        prefix: "",
    };
    let ssz = root_request(vec![
        identifier(1, vec![1, 47]),
        identifier(2, vec![87, 102]),
    ]);
    let valid = encode_chunk(&ssz).expect("a small request");
    sink.add("valid", &valid);
    let mut add = |name: &str, ssz: &[u8]| sink.add(name, &encode_chunk(ssz).expect("small"));
    let full = |n: usize| -> Vec<DataColumnsByRootIdentifier> {
        (0..n)
            .map(|i| identifier(i as u8, (0..128).collect()))
            .collect()
    };
    add("at-both-bounds", &root_request(full(128)));
    add("empty-list", &root_request(vec![]));
    add(
        "identifier-no-columns",
        &root_request(vec![identifier(1, vec![])]),
    );
    add(
        "index-128",
        &root_request(vec![identifier(1, vec![2]), identifier(2, vec![128])]),
    );
    add(
        "index-u64-max",
        &root_request(vec![identifier(1, vec![u64::MAX])]),
    );
    add(
        "duplicate-pairs",
        &root_request(vec![identifier(1, vec![5, 5]), identifier(1, vec![5])]),
    );
    // Identifier lists one past MAX_REQUEST_BLOCKS_DENEB: empty identifiers (within the byte
    // bound, refused by the list limit) and full ones (past the byte bound).
    let empty_id = identifier(3, vec![]).as_ssz_bytes();
    add(
        "identifiers-past-bound",
        &raw_identifier_list(&vec![empty_id.clone(); 129]),
    );
    let full_id = identifier(4, (0..128).collect()).as_ssz_bytes();
    add(
        "identifiers-past-bound-full",
        &raw_identifier_list(&vec![full_id; 129]),
    );
    let past: Vec<u8> = (0..129u64).flat_map(u64::to_le_bytes).collect();
    let wide = cat(&[&[5; 32], &36u32.to_le_bytes(), &past]);
    add(
        "identifier-columns-past-bound",
        &raw_identifier_list(&[wide]),
    );
    let id = identifier(6, vec![1]).as_ssz_bytes();
    add(
        "identifier-columns-offset-not-36",
        &raw_identifier_list(&[cat(&[
            &[6; 32],
            &40u32.to_le_bytes(),
            &[0; 4],
            &1u64.to_le_bytes(),
        ])]),
    );
    let two = raw_identifier_list(&[id.clone(), id.clone()]);
    let mut misaligned = two.clone();
    misaligned[..4].copy_from_slice(&5u32.to_le_bytes());
    add("first-offset-not-a-multiple-of-4", &misaligned);
    let mut decreasing = two.clone();
    decreasing[4..8].copy_from_slice(&4u32.to_le_bytes());
    add("offsets-decreasing", &decreasing);
    let mut past_end = two;
    past_end[4..8].copy_from_slice(&4096u32.to_le_bytes());
    add("offset-past-end", &past_end);
    add(
        "identifier-cut-short",
        &raw_identifier_list(&[empty_id[..35].to_vec()]),
    );
    request_framing(&mut sink, Protocol::DataColumnsByRootV1, &valid, ssz.len());
}
