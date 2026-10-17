//! Each named seed reaches the check it is named for, so the corpus starts the fuzzer next to
//! every refusal (and the valid seeds reach the re-encode invariants).

use cl_p2p::rpc::codec::{read_response_chunks, ReadError, MAX_RESPONSE_BYTES};
use ethswarm_fuzz::seeds::{self, Seed};
use ethswarm_fuzz::{contexts, E};
use futures::executor::block_on;
use futures::io::Cursor;
use p2p_wire::rpc::codec::{
    decode_chunk, decode_response_chunk, CodecError, MAX_EMPTY_FRAMES, MAX_FRAME_BODY_LEN,
};
use p2p_wire::rpc::protocols::{Protocol, Response, ResponseChunk};
use std::sync::OnceLock;

/// What a seed's decode error must look like.
type Expect = fn(&CodecError) -> bool;

fn seed(target: &str, name: &str) -> Vec<u8> {
    static ALL: OnceLock<Vec<Seed>> = OnceLock::new();
    ALL.get_or_init(|| seeds::all(&[]))
        .iter()
        .find(|s| s.target == target && s.name == name)
        .unwrap_or_else(|| panic!("no seed {target}/{name}"))
        .bytes
        .clone()
}

fn single(target: &str, name: &str) -> Result<ResponseChunk<E>, CodecError> {
    let (protocol, skip) = match target {
        "status_v2" => (Protocol::StatusV2, 0),
        "metadata_v3" => (Protocol::MetaDataV3, 0),
        "ping_goodbye" => (Protocol::PingV1, 1),
        other => panic!("{other} is not a single-chunk target"),
    };
    decode_response_chunk::<E>(&seed(target, name)[skip..], protocol, contexts())
}

fn range(name: &str) -> Result<Vec<ResponseChunk<E>>, ReadError> {
    let bytes = seed("blocks_by_range_resp", name);
    let request_count = u64::from(bytes[0]).min(128);
    block_on(read_response_chunks::<E, _>(
        &mut Cursor::new(&bytes[1..]),
        Protocol::BlocksByRangeV2,
        request_count,
        contexts(),
    ))
}

fn range_codec_error(name: &str) -> CodecError {
    match range(name) {
        Err(ReadError::Codec(e)) => e,
        other => panic!("{name}: {other:?}"),
    }
}

#[test]
fn single_chunk_seeds() {
    for target in ["status_v2", "metadata_v3", "ping_goodbye"] {
        assert!(
            matches!(single(target, "valid"), Ok(ResponseChunk::Success(_))),
            "{target}"
        );
        for code in 1..=3 {
            let got = single(target, &format!("error-code-{code}"));
            assert!(matches!(got, Ok(ResponseChunk::Error { .. })), "{target}");
        }
        for code in [4, 128, 255] {
            let got = single(target, &format!("invalid-code-{code}"));
            assert_eq!(got, Err(CodecError::InvalidResultCode(code)), "{target}");
        }
        let cases: [(&str, Expect); 10] = [
            ("frame-body-too-large", |e| {
                *e == CodecError::FrameTooLarge {
                    len: MAX_FRAME_BODY_LEN + 1,
                }
            }),
            ("frame-output-too-large", |e| {
                *e == CodecError::FrameTooLarge { len: 65_537 }
            }),
            ("too-many-empty-frames", |e| {
                *e == CodecError::TooManyEmptyFrames {
                    max: MAX_EMPTY_FRAMES,
                }
            }),
            (
                "oversize-prefix-10mib-plus-1",
                |e| matches!(e, CodecError::PayloadTooLarge { len, .. } if *len == 10 * (1 << 20) + 1),
            ),
            ("prefix-over-type-bound", |e| {
                matches!(e, CodecError::PayloadTooLarge { .. })
            }),
            ("snappy-bomb", |e| {
                matches!(e, CodecError::CompressedTooLarge { .. })
            }),
            ("frames-past-the-prefix", |e| {
                matches!(e, CodecError::PayloadOverrun { .. })
            }),
            ("varint-11-bytes", |e| *e == CodecError::VarintTooLong),
            ("truncated", |e| *e == CodecError::Truncated),
            ("trailing-byte", |e| *e == CodecError::TrailingBytes(1)),
        ];
        for (name, want) in cases {
            let err = single(target, name).unwrap_err();
            assert!(want(&err), "{target}/{name}: {err:?}");
        }
    }
}

#[test]
fn goodbye_seeds() {
    let payload = |name: &str| seed("ping_goodbye", &format!("goodbye-{name}"))[1..].to_vec();
    assert_eq!(
        decode_chunk(&payload("valid"), 8).unwrap(),
        3u64.to_le_bytes()
    );
    assert!(matches!(
        decode_chunk(&payload("oversize-prefix-10mib-plus-1"), 8),
        Err(CodecError::PayloadTooLarge { .. })
    ));
    assert!(matches!(
        decode_chunk(&payload("snappy-bomb"), 8),
        Err(CodecError::CompressedTooLarge { .. })
    ));
    assert_eq!(
        decode_chunk(&payload("varint-11-bytes"), 8),
        Err(CodecError::VarintTooLong)
    );
    assert_eq!(
        decode_chunk(&payload("frame-body-too-large"), 8),
        Err(CodecError::FrameTooLarge {
            len: MAX_FRAME_BODY_LEN + 1
        })
    );
    assert_eq!(
        decode_chunk(&payload("frame-output-too-large"), 8),
        Err(CodecError::FrameTooLarge { len: 65_537 })
    );
    assert_eq!(
        decode_chunk(&payload("truncated"), 8),
        Err(CodecError::Truncated)
    );
    assert_eq!(
        decode_chunk(&payload("trailing-byte"), 8),
        Err(CodecError::TrailingBytes(1))
    );
}

#[test]
fn blocks_by_range_seeds() {
    let blocks = |name| -> Vec<ResponseChunk<E>> { range(name).unwrap() };
    let forks = |chunks: &[ResponseChunk<E>]| -> Vec<String> {
        chunks
            .iter()
            .map(|c| match c {
                ResponseChunk::Success(Response::Block(b)) => b.fork_name().to_string(),
                other => format!("{other:?}"),
            })
            .collect()
    };
    assert_eq!(forks(&blocks("fulu-bpo-gloas")), ["fulu", "fulu", "gloas"]);
    assert!(blocks("empty-response").is_empty());
    let ended = blocks("block-then-error");
    assert!(matches!(ended[1], ResponseChunk::Error { .. }));
    assert_eq!(blocks("count-200-clamped-to-128").len(), 1);
    assert!(matches!(
        range("too-many-chunks"),
        Err(ReadError::TooManyChunks { max: 1 })
    ));
    assert!(matches!(
        range("count-0-one-chunk"),
        Err(ReadError::TooManyChunks { max: 0 })
    ));
    assert!(matches!(
        range_codec_error("unknown-context-digest"),
        CodecError::UnknownContext(_)
    ));
    assert!(matches!(
        range_codec_error("fulu-block-under-gloas-digest"),
        CodecError::Decode(_)
    ));
    assert!(matches!(
        range_codec_error("oversize-prefix-10mib-plus-1"),
        CodecError::PayloadTooLarge { .. }
    ));
    assert!(matches!(
        range_codec_error("snappy-bomb"),
        CodecError::CompressedTooLarge { len: 1000, .. }
    ));
    assert!(matches!(
        range_codec_error("snappy-bomb-1mib-within-bound"),
        CodecError::Decode(_)
    ));
    assert_eq!(
        range_codec_error("varint-11-bytes"),
        CodecError::VarintTooLong
    );
    assert_eq!(range_codec_error("truncated"), CodecError::Truncated);
    // One byte past the one chunk the request allows is an extra chunk.
    assert!(matches!(
        range("trailing-byte"),
        Err(ReadError::TooManyChunks { max: 1 })
    ));
    assert_eq!(
        range_codec_error("frame-body-too-large"),
        CodecError::FrameTooLarge {
            len: MAX_FRAME_BODY_LEN + 1
        }
    );
    assert_eq!(
        range_codec_error("frame-output-too-large"),
        CodecError::FrameTooLarge { len: 65_537 }
    );
    assert_eq!(
        range_codec_error("too-many-empty-frames"),
        CodecError::TooManyEmptyFrames {
            max: MAX_EMPTY_FRAMES
        }
    );
    assert!(matches!(
        range("data-after-error"),
        Err(ReadError::DataAfterError)
    ));
    assert!(matches!(
        range("response-over-byte-budget"),
        Err(ReadError::ResponseTooLarge { budget }) if budget == MAX_RESPONSE_BYTES
    ));
    for code in [4, 128, 255] {
        assert_eq!(
            range_codec_error(&format!("invalid-code-{code}")),
            CodecError::InvalidResultCode(code)
        );
    }
}

#[test]
fn vector_seeds_decode_as_gloas_blocks() {
    // The committed seed: the vectors are not needed to read it back.
    let corpus =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/blocks_by_range_resp");
    let all = std::fs::read(corpus.join("gloas-vectors-all")).expect("committed seed");
    let chunks = block_on(read_response_chunks::<E, _>(
        &mut Cursor::new(&all[1..]),
        Protocol::BlocksByRangeV2,
        u64::from(all[0]),
        contexts(),
    ))
    .unwrap();
    assert_eq!(chunks.len(), 3);
    for chunk in chunks {
        let ResponseChunk::Success(Response::Block(block)) = chunk else {
            panic!("not a block")
        };
        assert_eq!(block.fork_name().to_string(), "gloas");
    }
}
