//! The seed corpus (`fuzz/corpus/<target>/`), built from the production encoders.
//!
//! Valid chunks are the round-trip fixtures of `p2p-wire`'s tests, plus Gloas
//! `SignedBeaconBlock`s from the beta.4 mainnet `ssz_static` vectors, which the caller reads
//! (`fuzz/examples/gen-seeds.rs`) and passes in as SSZ. Malformed seeds put the fuzzer next to
//! every refusal: a length prefix over `MAX_PAYLOAD_SIZE` and one over 4 GiB, snappy bombs, an
//! 11-byte varint, a truncated chunk, trailing bytes, error chunks with result codes 1-3 and
//! 4-255, an unknown context digest, more chunks than the request allows, the frame caps (an
//! oversize frame body, a frame claiming more than 64 KiB and one claiming more than 4 GiB, too
//! many empty frames), data after an error chunk and a response over its byte budget. The
//! control targets get the same for the inbound requests, `rpc_chunk` for every protocol in both
//! directions (the column protocols' sidecars of both forks and their requests among them); the gossip and ENR seeds are in [`gossip`] and [`record`], and the gate-2a column
//! seeds (sidecars over gossip and req/resp, the two column requests) in [`columns`].
//!
//! Everything here is deterministic, so `tests/corpus.rs` can check the committed corpus is
//! exactly what this module builds.

mod columns;
mod gossip;
mod record;

use crate::{E, GOODBYE_BIT, REQUEST_BIT, REQUEST_SELECTOR};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use consensus_types::EthSpec;
use consensus_types::ForkName;
use p2p_wire::rpc::codec::{
    decode_varint, encode_chunk, encode_error_chunk, encode_success_chunk, encode_varint,
    MAX_EMPTY_FRAMES, MAX_FRAME_BODY_LEN,
};
use p2p_wire::rpc::messages::{
    BlocksByRangeV2Request, DataColumnsByRangeV1Request, DataColumnsByRootIdentifier,
    DataColumnsByRootV1Request, ForkDigest, Goodbye, Ping, MAX_ERROR_MESSAGE_LEN,
};
use p2p_wire::rpc::protocols::{Protocol, ResultCode};
use p2p_wire::testkit;
use ssz::Encode;
use ssz_types::typenum::Unsigned;
use ssz_types::VariableList;

/// Seed names built from a vector case start with this.
pub const VECTOR_PREFIX: &str = "gloas-vector-";

/// The fuzzing corpus, under `fuzz/`: what `fuzz/run-m2a-gate.sh` starts libFuzzer from.
pub const FUZZ_DIR: &str = "corpus";
/// Seeds too slow to fuzz from (seconds per execution), under `fuzz/`: run by
/// `fuzz/coverage-m2a.sh` and the tests, never handed to libFuzzer.
pub const SLOW_DIR: &str = "corpus-slow";

/// One seed file: `fuzz/<FUZZ_DIR or SLOW_DIR>/<target>/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    /// The fuzz target.
    pub target: &'static str,
    /// Whether it belongs in [`SLOW_DIR`].
    pub slow: bool,
    /// The file name.
    pub name: String,
    /// The file contents.
    pub bytes: Vec<u8>,
}

/// A Gloas mainnet `SignedBeaconBlock` from an `ssz_static` case, as SSZ.
#[derive(Debug, Clone)]
pub struct VectorBlock {
    /// The case directory name (`case_0`).
    pub case: String,
    /// The block's SSZ bytes.
    pub ssz: Vec<u8>,
}

const ERROR_MESSAGE: &[u8] = b"seed error";
/// The snappy framing stream identifier.
const STREAM_IDENTIFIER: &[u8] = b"\xff\x06\x00\x00sNaPpY";
/// A snappy padding frame's chunk type.
const PADDING: u8 = 0xfe;
/// Result bytes outside 0-3: the first, a middle and the last refused value.
const INVALID_CODES: [u8; 3] = [4, 128, 255];
const ERROR_CODES: [ResultCode; 3] = [
    ResultCode::InvalidRequest,
    ResultCode::ServerError,
    ResultCode::ResourceUnavailable,
];
/// 64 KiB of zeros: about 3 KiB of snappy frames, far past `max_compressed_len` of a small
/// declared length.
const BOMB_LEN: usize = 1 << 16;
/// 1 MiB of zeros under a 1 MiB prefix: within a block's bound, about 48 KiB compressed.
const BLOCK_BOMB_LEN: usize = 1 << 20;
/// A length past 4 GiB: 2^32 + 1, a 5-byte varint.
const OVER_4GIB: usize = (1 << 32) + 1;

/// Every seed, for every target.
pub fn all(vector_blocks: &[VectorBlock]) -> Vec<Seed> {
    let mut seeds = Vec::new();
    let status = testkit::status().as_ssz_bytes();
    let metadata = testkit::metadata().as_ssz_bytes();
    let ping = Ping(9).as_ssz_bytes();
    single_chunk(&mut seeds, "status_v2", &[0], "", &status);
    requests(&mut seeds, "status_v2", REQUEST_BIT, "", Some(&status));
    single_chunk(&mut seeds, "metadata_v3", &[0], "", &metadata);
    requests(&mut seeds, "metadata_v3", REQUEST_BIT, "", None);
    single_chunk(&mut seeds, "ping_goodbye", &[0], "", &ping);
    requests(&mut seeds, "ping_goodbye", REQUEST_BIT, "", Some(&ping));
    goodbye(&mut seeds);
    blocks_by_range(&mut seeds, vector_blocks);
    rpc_chunk(&mut seeds, &status, &metadata, &ping);
    gossip::all(&mut seeds, vector_blocks);
    record::all(&mut seeds);
    columns::all(&mut seeds);
    seeds
}

/// `declared` as the length prefix, then the snappy frames of `data`.
fn framed(declared: usize, data: &[u8]) -> Vec<u8> {
    let chunk = encode_chunk(data).expect("seed payload within MAX_PAYLOAD_SIZE");
    let (_, prefix) = decode_varint(&chunk).expect("encode_chunk writes a prefix");
    let mut out = Vec::new();
    encode_varint(declared as u64, &mut out);
    out.extend_from_slice(&chunk[prefix..]);
    out
}

fn varint(n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    encode_varint(n as u64, &mut out);
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

struct Sink<'a> {
    seeds: &'a mut Vec<Seed>,
    target: &'static str,
    /// Bytes before every seed: the selector or `count` byte of the target.
    lead: &'a [u8],
    /// Before every seed name.
    prefix: &'a str,
}

impl Sink<'_> {
    fn add(&mut self, name: impl AsRef<str>, body: &[u8]) {
        self.seeds.push(Seed {
            target: self.target,
            slow: false,
            name: format!("{}{}", self.prefix, name.as_ref()),
            bytes: cat(&[self.lead, body]),
        });
    }

    /// Error chunks with codes 1-3, and result bytes 4 and up before a valid payload.
    fn result_codes(&mut self) {
        for code in ERROR_CODES {
            let chunk = encode_error_chunk(code, ERROR_MESSAGE).expect("valid error chunk");
            self.add(format!("error-code-{}", code.as_byte()), &chunk);
        }
        let payload = encode_chunk(ERROR_MESSAGE).expect("small payload");
        for code in INVALID_CODES {
            self.add(format!("invalid-code-{code}"), &cat(&[&[code], &payload]));
        }
    }

    /// The malformed payloads after `head` (result and context bytes, or nothing): a prefix of
    /// `MAX_PAYLOAD_SIZE + 1` and one over 4 GiB, a prefix one past `bound`, a snappy bomb under
    /// a `small` prefix and an 11-byte varint.
    fn bad_payloads(&mut self, head: &[u8], bound: usize, small: usize) {
        let oversize = framed(MAX_PAYLOAD_SIZE + 1, &[0; 16]);
        self.add("oversize-prefix-10mib-plus-1", &cat(&[head, &oversize]));
        let over_4gib = framed(OVER_4GIB, &[0; 16]);
        self.add("prefix-over-4gib", &cat(&[head, &over_4gib]));
        let over = framed(bound + 1, &[0; 16]);
        self.add("prefix-over-type-bound", &cat(&[head, &over]));
        let bomb = framed(small, &[0; BOMB_LEN]);
        self.add("snappy-bomb", &cat(&[head, &bomb]));
        let overrun = framed(small, &vec![0; small + 16]);
        self.add("frames-past-the-prefix", &cat(&[head, &overrun]));
        let varint = [0x80u8; 10];
        self.add("varint-11-bytes", &cat(&[head, &varint, &[0x01]]));
    }

    /// The frame caps after `head`, under a `declared` prefix: a frame body one past
    /// `MAX_FRAME_BODY_LEN`, a frame claiming 65,537 decompressed bytes, one claiming more than
    /// 4 GiB and, after `empty` (a
    /// head and a prefix whose `max_compressed_len` has room for 17 empty frames), more than
    /// `MAX_EMPTY_FRAMES` frames without data.
    fn bad_frames(&mut self, head: &[u8], declared: usize, empty: Option<(&[u8], usize)>) {
        let prefix = varint(declared);
        let body_len = (MAX_FRAME_BODY_LEN + 1) as u32;
        let header = [
            0x00,
            body_len as u8,
            (body_len >> 8) as u8,
            (body_len >> 16) as u8,
        ];
        self.add(
            "frame-body-too-large",
            &cat(&[head, &prefix, STREAM_IDENTIFIER, &header]),
        );
        // A compressed frame: CRC, then the snappy length varint of 65,537.
        let body = [0, 0, 0, 0, 0x81, 0x80, 0x04];
        let frame = cat(&[&[0x00, body.len() as u8, 0, 0], &body]);
        self.add(
            "frame-output-too-large",
            &cat(&[head, &prefix, STREAM_IDENTIFIER, &frame]),
        );
        // The same, its snappy length varint claiming 2^32 + 1 bytes.
        let body = cat(&[&[0, 0, 0, 0], &varint(OVER_4GIB)]);
        let frame = cat(&[&[0x00, body.len() as u8, 0, 0], &body]);
        self.add(
            "frame-claims-over-4gib",
            &cat(&[head, &prefix, STREAM_IDENTIFIER, &frame]),
        );
        // The stream identifier and 16 padding frames: 17 frames without data.
        if let Some((head, declared)) = empty {
            let padding = [PADDING, 0, 0, 0].repeat(MAX_EMPTY_FRAMES);
            self.add(
                "too-many-empty-frames",
                &cat(&[head, &varint(declared), STREAM_IDENTIFIER, &padding]),
            );
        }
    }

    /// The valid `chunk`, cut one byte short and with a trailing byte.
    fn truncated_and_trailing(&mut self, chunk: &[u8]) {
        self.add("truncated", &chunk[..chunk.len() - 1]);
        self.add("trailing-byte", &cat(&[chunk, &[0]]));
    }
}

/// A single-response protocol whose success payload is `ssz`.
fn single_chunk(
    seeds: &mut Vec<Seed>,
    target: &'static str,
    lead: &[u8],
    prefix: &str,
    ssz: &[u8],
) {
    let mut sink = Sink {
        seeds,
        target,
        lead,
        prefix,
    };
    let valid = encode_success_chunk(None, ssz).expect("valid chunk");
    sink.add("valid", &valid);
    sink.result_codes();
    sink.bad_payloads(&[ResultCode::Success.as_byte()], ssz.len(), ssz.len());
    // The empty-frame cap needs a bound with room for 17 frames: an error chunk's 256 bytes.
    let error_head = [ResultCode::InvalidRequest.as_byte()];
    sink.bad_frames(
        &[ResultCode::Success.as_byte()],
        ssz.len(),
        Some((&error_head, MAX_ERROR_MESSAGE_LEN)),
    );
    sink.truncated_and_trailing(&valid);
}

/// The inbound requests of a protocol whose request body is `ssz` (`None`: an empty request),
/// after the `lead` selector byte, named `{prefix}request-*`: the valid request, and for a body
/// the malformed payloads and frames under its exact length, a prefix one under it, and the
/// request cut short and with a byte after it.
fn requests(
    seeds: &mut Vec<Seed>,
    target: &'static str,
    lead: u8,
    prefix: &str,
    ssz: Option<&[u8]>,
) {
    let prefix = format!("{prefix}request-");
    let mut sink = Sink {
        seeds,
        target,
        lead: &[lead],
        prefix: &prefix,
    };
    let Some(ssz) = ssz else {
        sink.add("empty", &[]);
        sink.add("trailing-byte", &[0]);
        sink.add(
            "with-a-payload",
            &encode_chunk(&[]).expect("an empty payload"),
        );
        return;
    };
    let valid = encode_chunk(ssz).expect("valid request");
    sink.add("valid", &valid);
    sink.bad_payloads(&[], ssz.len(), ssz.len());
    sink.add("prefix-under-type-bound", &framed(ssz.len() - 1, &[0; 16]));
    sink.bad_frames(&[], ssz.len(), None);
    sink.truncated_and_trailing(&valid);
}

/// `ping_goodbye` with the Goodbye selector: an inbound `Goodbye` request (a bare payload, no
/// result byte), named `goodbye-*`.
fn goodbye(seeds: &mut Vec<Seed>) {
    let mut sink = Sink {
        seeds,
        target: "ping_goodbye",
        lead: &[GOODBYE_BIT],
        prefix: "goodbye-",
    };
    let ssz = Goodbye(3).as_ssz_bytes();
    let valid = encode_chunk(&ssz).expect("valid payload");
    sink.add("valid", &valid);
    let bound = ssz.len();
    sink.add(
        "oversize-prefix-10mib-plus-1",
        &framed(MAX_PAYLOAD_SIZE + 1, &[0; 16]),
    );
    sink.add("prefix-over-4gib", &framed(OVER_4GIB, &[0; 16]));
    sink.add("prefix-over-type-bound", &framed(bound + 1, &[0; 16]));
    sink.add("prefix-under-type-bound", &framed(bound - 1, &[0; 16]));
    sink.add("snappy-bomb", &framed(bound, &[0; BOMB_LEN]));
    sink.add("frames-past-the-prefix", &framed(bound, &[0; 8 + 16]));
    sink.add("varint-11-bytes", &cat(&[&[0x80; 10], &[0x01]]));
    // A Goodbye's 8-byte bound leaves no room for 17 empty frames: the cut-off comes first.
    sink.bad_frames(&[], bound, None);
    sink.truncated_and_trailing(&valid);
}

/// A Fulu block whose payload holds the most (empty) transactions a block may.
fn max_transactions_block(slot: u64) -> Vec<u8> {
    let mut block = testkit::fulu_block::<E>(slot);
    let max = <<E as EthSpec>::MaxTransactionsPerPayload as Unsigned>::to_usize();
    block.message.body.execution_payload.transactions =
        VariableList::new(vec![VariableList::empty(); max]).expect("at the list bound");
    block.as_ssz_bytes()
}

fn block_chunk(digest: ForkDigest, ssz: &[u8]) -> Vec<u8> {
    encode_success_chunk(Some(digest), ssz).expect("block within MAX_PAYLOAD_SIZE")
}

/// `blocks_by_range_resp`: the first byte is `count`, then the response chunks.
fn blocks_by_range(seeds: &mut Vec<Seed>, vector_blocks: &[VectorBlock]) {
    let target = "blocks_by_range_resp";
    let fulu = block_chunk(
        testkit::FULU_DIGEST,
        &testkit::fulu_block::<E>(1).as_ssz_bytes(),
    );
    let fulu_bpo = block_chunk(
        testkit::FULU_BPO_DIGEST,
        &testkit::fulu_block::<E>(2).as_ssz_bytes(),
    );
    let gloas = block_chunk(
        testkit::GLOAS_DIGEST,
        &testkit::gloas_block::<E>(3).as_ssz_bytes(),
    );
    let vectors: Vec<Vec<u8>> = vector_blocks
        .iter()
        .map(|b| block_chunk(testkit::GLOAS_DIGEST, &b.ssz))
        .collect();
    let error = encode_error_chunk(ResultCode::ResourceUnavailable, ERROR_MESSAGE)
        .expect("valid error chunk");

    let mut add = |slow: bool, count: u8, name: String, body: &[u8]| {
        seeds.push(Seed {
            target,
            slow,
            name,
            bytes: cat(&[&[count], body]),
        });
    };
    for (block, chunk) in vector_blocks.iter().zip(&vectors) {
        add(false, 1, format!("{VECTOR_PREFIX}{}", block.case), chunk);
    }
    if !vectors.is_empty() {
        add(
            false,
            vectors.len() as u8,
            "gloas-vectors-all".into(),
            &vectors.concat(),
        );
    }
    add(
        false,
        3,
        "fulu-bpo-gloas".into(),
        &cat(&[&fulu, &fulu_bpo, &gloas]),
    );
    add(false, 4, "empty-response".into(), &[]);
    add(false, 4, "block-then-error".into(), &cat(&[&fulu, &error]));
    add(
        false,
        4,
        "data-after-error".into(),
        &cat(&[&fulu, &error, &fulu_bpo]),
    );
    // Four Fulu blocks of 2^20 empty transactions: each about 84 MiB against the 256 MiB budget
    // (4 MiB of SSZ, PER_TRANSACTION_HEAP per transaction), about 200 KiB on the wire each.
    let budget_block = block_chunk(testkit::FULU_DIGEST, &max_transactions_block(5));
    let budget = budget_block.repeat(4);
    add(true, 4, "response-over-byte-budget".into(), &budget);
    add(false, 1, "too-many-chunks".into(), &cat(&[&fulu, &gloas]));
    add(false, 0, "count-0-one-chunk".into(), &fulu);
    add(false, 200, "count-200-clamped-to-128".into(), &gloas);
    let fulu_ssz = testkit::fulu_block::<E>(4).as_ssz_bytes();
    add(
        false,
        1,
        "fulu-block-under-gloas-digest".into(),
        &block_chunk(testkit::GLOAS_DIGEST, &fulu_ssz),
    );
    let unknown = cat(&[
        &[ResultCode::Success.as_byte()],
        &testkit::UNKNOWN_DIGEST,
        &encode_chunk(&fulu_ssz).expect("small block"),
    ]);
    add(false, 1, "unknown-context-digest".into(), &unknown);

    let mut sink = Sink {
        seeds,
        target,
        lead: &[1],
        prefix: "",
    };
    sink.result_codes();
    let head = cat(&[&[ResultCode::Success.as_byte()], &testkit::GLOAS_DIGEST]);
    let bound = Protocol::BlocksByRangeV2
        .response_max_len::<E>(Some(ForkName::Gloas))
        .expect("a Gloas block has a bound");
    sink.bad_payloads(&head, bound, 1000);
    sink.bad_frames(&head, 1000, Some((&head, 1000)));
    let bomb = framed(BLOCK_BOMB_LEN, &vec![0; BLOCK_BOMB_LEN]);
    sink.add("snappy-bomb-1mib-within-bound", &cat(&[&head, &bomb]));
    sink.truncated_and_trailing(&gloas);
}

/// `rpc_chunk`: for every protocol, its response chunks after the protocol's index and its
/// request payloads after the index with [`REQUEST_SELECTOR`], named `{protocol}-*` and
/// `{protocol}-request-*`.
fn rpc_chunk(seeds: &mut Vec<Seed>, status: &[u8], metadata: &[u8], ping: &[u8]) {
    let target = "rpc_chunk";
    let index = |protocol: Protocol| {
        let i = Protocol::ALL
            .iter()
            .position(|p| *p == protocol)
            .expect("every protocol is in ALL");
        u8::try_from(i).expect("seven protocols")
    };
    let range = BlocksByRangeV2Request {
        start_slot: 7,
        count: 4,
        step: 1,
    }
    .as_ssz_bytes();
    let goodbye = Goodbye(1).as_ssz_bytes();
    for (protocol, name, response, request) in [
        (Protocol::StatusV2, "status", status, Some(status)),
        (Protocol::MetaDataV3, "metadata", metadata, None),
        (Protocol::PingV1, "ping", ping, Some(ping)),
        // Goodbye's response is one chunk with a reason, like its request
        // (`phase0/p2p-interface.md` L1461, L1483).
        (Protocol::GoodbyeV1, "goodbye", &goodbye[..], Some(&goodbye[..])),
    ] {
        let prefix = format!("{name}-");
        let i = index(protocol);
        single_chunk(seeds, target, &[i], &prefix, response);
        requests(seeds, target, i | REQUEST_SELECTOR, &prefix, request);
    }

    let i = index(Protocol::BlocksByRangeV2);
    requests(seeds, target, i | REQUEST_SELECTOR, "blocks-", Some(&range));
    let mut sink = Sink {
        seeds,
        target,
        lead: &[i],
        prefix: "blocks-",
    };
    let fulu = block_chunk(
        testkit::FULU_DIGEST,
        &testkit::fulu_block::<E>(1).as_ssz_bytes(),
    );
    let fulu_bpo = block_chunk(
        testkit::FULU_BPO_DIGEST,
        &testkit::fulu_block::<E>(2).as_ssz_bytes(),
    );
    let gloas = block_chunk(
        testkit::GLOAS_DIGEST,
        &testkit::gloas_block::<E>(3).as_ssz_bytes(),
    );
    sink.add("fulu-valid", &fulu);
    sink.add("fulu-bpo-digest-valid", &fulu_bpo);
    sink.add("gloas-valid", &gloas);
    let fulu_ssz = testkit::fulu_block::<E>(4).as_ssz_bytes();
    sink.add(
        "fulu-block-under-gloas-digest",
        &block_chunk(testkit::GLOAS_DIGEST, &fulu_ssz),
    );
    let unknown = cat(&[
        &[ResultCode::Success.as_byte()],
        &testkit::UNKNOWN_DIGEST,
        &encode_chunk(&fulu_ssz).expect("small block"),
    ]);
    sink.add("unknown-context-digest", &unknown);
    sink.add(
        "context-cut-short",
        &[ResultCode::Success.as_byte(), testkit::GLOAS_DIGEST[0]],
    );
    sink.result_codes();
    let head = cat(&[&[ResultCode::Success.as_byte()], &testkit::GLOAS_DIGEST]);
    let bound = Protocol::BlocksByRangeV2
        .response_max_len::<E>(Some(ForkName::Gloas))
        .expect("a Gloas block has a bound");
    sink.bad_payloads(&head, bound, 1000);
    sink.add(
        "prefix-under-block-minimum",
        &cat(&[&head, &framed(10, &[0; 10])]),
    );
    sink.bad_frames(&head, 1000, Some((&head, 1000)));
    let bomb = framed(BLOCK_BOMB_LEN, &vec![0; BLOCK_BOMB_LEN]);
    sink.add("snappy-bomb-1mib-within-bound", &cat(&[&head, &bomb]));
    sink.truncated_and_trailing(&gloas);

    for (protocol, name) in [
        (Protocol::DataColumnsByRangeV1, "columns-range-"),
        (Protocol::DataColumnsByRootV1, "columns-root-"),
    ] {
        columns(seeds, target, index(protocol), protocol, name);
    }
}

/// `rpc_chunk` for a column protocol, after its index `i`: its request (valid, past its lists'
/// limits, cut short, with a byte after it, over its bound) and its sidecar chunks (Gloas and
/// Fulu, a sidecar under another fork's digest, an unknown digest, the result codes and the
/// malformed payloads), named `{prefix}*`.
fn columns(seeds: &mut Vec<Seed>, target: &'static str, i: u8, protocol: Protocol, prefix: &str) {
    let id = |byte: u8, columns: Vec<u64>| DataColumnsByRootIdentifier {
        block_root: [byte; 32].into(),
        columns: columns.try_into().expect("within NUMBER_OF_COLUMNS"),
    };
    let request = match protocol {
        Protocol::DataColumnsByRangeV1 => DataColumnsByRangeV1Request {
            start_slot: 64,
            count: 32,
            columns: vec![1, 47, 87, 102].try_into().expect("four columns"),
        }
        .as_ssz_bytes(),
        _ => DataColumnsByRootV1Request(
            vec![id(1, vec![1, 47]), id(2, vec![87, 102])]
                .try_into()
                .expect("two identifiers"),
        )
        .as_ssz_bytes(),
    };
    let bounds = protocol
        .request_bounds()
        .expect("a column request has a body");
    let request_prefix = format!("{prefix}request-");
    let mut sink = Sink {
        seeds,
        target,
        lead: &[i | REQUEST_SELECTOR],
        prefix: &request_prefix,
    };
    let valid = encode_chunk(&request).expect("valid request");
    sink.add("valid", &valid);
    sink.add("prefix-over-type-bound", &framed(bounds.max + 1, &[0; 16]));
    // A list one past its limit.
    let past = match protocol {
        Protocol::DataColumnsByRangeV1 => {
            let mut ssz = cat(&[
                &64u64.to_le_bytes(),
                &1u64.to_le_bytes(),
                &20u32.to_le_bytes(),
            ]);
            ssz.extend(std::iter::repeat_n(0u8, 129 * 8));
            ssz
        }
        _ => {
            let mut ssz: Vec<u8> = (0..129u32)
                .flat_map(|n| (129 * 4 + n * 40).to_le_bytes())
                .collect();
            for _ in 0..129 {
                ssz.extend(cat(&[&[0; 32], &36u32.to_le_bytes(), &[0; 4]]));
            }
            ssz
        }
    };
    sink.add(
        "list-past-its-limit",
        &encode_chunk(&past).expect("within MAX_PAYLOAD_SIZE"),
    );
    sink.bad_frames(&[], request.len(), None);
    sink.truncated_and_trailing(&valid);

    let mut sink = Sink {
        seeds,
        target,
        lead: &[i],
        prefix,
    };
    let gloas = testkit::gloas_sidecar::<E>(9, 47).as_ssz_bytes();
    let fulu = testkit::fulu_sidecar::<E>(9, 47).as_ssz_bytes();
    let gloas_chunk = block_chunk(testkit::GLOAS_DIGEST, &gloas);
    sink.add("gloas-valid", &gloas_chunk);
    sink.add("fulu-valid", &block_chunk(testkit::FULU_DIGEST, &fulu));
    sink.add(
        "fulu-bpo-digest-valid",
        &block_chunk(testkit::FULU_BPO_DIGEST, &fulu),
    );
    sink.add(
        "gloas-sidecar-under-fulu-digest",
        &block_chunk(testkit::FULU_DIGEST, &gloas),
    );
    sink.add(
        "unknown-context-digest",
        &block_chunk(testkit::UNKNOWN_DIGEST, &gloas),
    );
    sink.result_codes();
    let head = cat(&[&[ResultCode::Success.as_byte()], &testkit::GLOAS_DIGEST]);
    let bound = protocol
        .response_max_len_with::<E>(Some(ForkName::Gloas), crate::contexts().network_caps())
        .expect("a Gloas sidecar has a bound under the preset caps");
    sink.bad_payloads(&head, bound, 1000);
    sink.add(
        "prefix-under-sidecar-minimum",
        &cat(&[&head, &framed(10, &[0; 10])]),
    );
    sink.truncated_and_trailing(&gloas_chunk);
}
