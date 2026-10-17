//! The seed corpus (`fuzz/corpus/<target>/`), built from the `p2p-wire` encoder.
//!
//! Valid chunks are the round-trip fixtures of `p2p-wire`'s tests, plus Gloas
//! `SignedBeaconBlock`s from the beta.4 mainnet `ssz_static` vectors, which the caller reads
//! (`fuzz/examples/gen-seeds.rs`) and passes in as SSZ. Malformed seeds put the fuzzer next to
//! every refusal: a length prefix over `MAX_PAYLOAD_SIZE`, snappy bombs, an 11-byte varint, a
//! truncated chunk, trailing bytes, error chunks with result codes 1-3 and 4-255, an unknown
//! context digest, more chunks than the request allows, the frame caps (an oversize frame body,
//! a frame claiming more than 64 KiB, too many empty frames), data after an error chunk and a
//! response over its byte budget.
//!
//! Everything here is deterministic, so `tests/corpus.rs` can check the committed corpus is
//! exactly what this module builds.

use crate::E;
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use consensus_types::EthSpec;
use consensus_types::ForkName;
use p2p_wire::rpc::codec::{
    decode_varint, encode_chunk, encode_error_chunk, encode_success_chunk, encode_varint,
    MAX_EMPTY_FRAMES, MAX_FRAME_BODY_LEN,
};
use p2p_wire::rpc::messages::{ForkDigest, Goodbye, Ping, MAX_ERROR_MESSAGE_LEN};
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

/// Every seed, for every target.
pub fn all(vector_blocks: &[VectorBlock]) -> Vec<Seed> {
    let mut seeds = Vec::new();
    single_chunk(
        &mut seeds,
        "status_v2",
        &[],
        &testkit::status().as_ssz_bytes(),
    );
    single_chunk(
        &mut seeds,
        "metadata_v3",
        &[],
        &testkit::metadata().as_ssz_bytes(),
    );
    single_chunk(&mut seeds, "ping_goodbye", &[0], &Ping(9).as_ssz_bytes());
    goodbye(&mut seeds);
    blocks_by_range(&mut seeds, vector_blocks);
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
}

impl Sink<'_> {
    fn add(&mut self, name: impl Into<String>, body: &[u8]) {
        self.seeds.push(Seed {
            target: self.target,
            slow: false,
            name: name.into(),
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
    /// `MAX_PAYLOAD_SIZE + 1`, a prefix one past `bound`, a snappy bomb under a `small` prefix
    /// and an 11-byte varint.
    fn bad_payloads(&mut self, head: &[u8], bound: usize, small: usize) {
        let oversize = framed(MAX_PAYLOAD_SIZE + 1, &[0; 16]);
        self.add("oversize-prefix-10mib-plus-1", &cat(&[head, &oversize]));
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
    /// `MAX_FRAME_BODY_LEN`, a frame claiming 65,537 decompressed bytes and, after `empty` (a
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
fn single_chunk(seeds: &mut Vec<Seed>, target: &'static str, lead: &[u8], ssz: &[u8]) {
    let mut sink = Sink {
        seeds,
        target,
        lead,
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

/// `ping_goodbye` with the Goodbye selector: a bare payload, no result byte.
fn goodbye(seeds: &mut Vec<Seed>) {
    let mut sink = Sink {
        seeds,
        target: "ping_goodbye",
        lead: &[crate::GOODBYE_BIT],
    };
    let ssz = Goodbye(3).as_ssz_bytes();
    let valid = encode_chunk(&ssz).expect("valid payload");
    sink.add("goodbye-valid", &valid);
    let bound = ssz.len();
    let named = |name: &str| format!("goodbye-{name}");
    let oversize = framed(MAX_PAYLOAD_SIZE + 1, &[0; 16]);
    sink.add(named("oversize-prefix-10mib-plus-1"), &oversize);
    sink.add(named("snappy-bomb"), &framed(bound, &[0; BOMB_LEN]));
    sink.add(named("varint-11-bytes"), &cat(&[&[0x80; 10], &[0x01]]));
    let mut frames = Sink {
        seeds: &mut *sink.seeds,
        target: "ping_goodbye",
        lead: &[crate::GOODBYE_BIT],
    };
    let before = frames.seeds.len();
    // A Goodbye's 8-byte bound leaves no room for 17 empty frames: the cut-off comes first.
    frames.bad_frames(&[], bound, None);
    for seed in &mut frames.seeds[before..] {
        seed.name = named(&seed.name);
    }
    sink.add(named("truncated"), &valid[..valid.len() - 1]);
    sink.add(named("trailing-byte"), &cat(&[&valid, &[0]]));
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
