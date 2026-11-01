//! Each named seed reaches the check it is named for, so the corpus starts the fuzzer next to
//! every refusal (and the valid seeds reach the re-encode invariants).

use cl_discv5::enr::{parse_enr_fields, EnrFields, FieldError};
use cl_p2p::rpc::codec::{read_response_chunks, ReadError, MAX_RESPONSE_BYTES};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use ethswarm_fuzz::seeds::{self, Seed};
use ethswarm_fuzz::{contexts, gossip_digests, split_message, structured_record, topic_caps, E};
use futures::executor::block_on;
use futures::io::Cursor;
use network_config::{ChainConfig, Network};
use p2p_wire::enr::{EnrFieldError, ForkFields};
use p2p_wire::gossip::{
    compute_message_id, message_id_of_decompressed, GossipKind, GossipTopic, SnappyTransform,
    TopicError, TransformError,
};
use p2p_wire::rpc::codec::{
    decode_request, decode_response_chunk, CodecError, MAX_EMPTY_FRAMES, MAX_FRAME_BODY_LEN,
};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk};
use std::sync::OnceLock;

/// What a seed's decode error must look like.
type Expect = fn(&CodecError) -> bool;

fn try_seed(target: &str, name: &str) -> Option<Vec<u8>> {
    static ALL: OnceLock<Vec<Seed>> = OnceLock::new();
    ALL.get_or_init(|| seeds::all(&[]))
        .iter()
        .find(|s| s.target == target && s.name == name)
        .map(|s| s.bytes.clone())
}

fn seed(target: &str, name: &str) -> Vec<u8> {
    try_seed(target, name).unwrap_or_else(|| panic!("no seed {target}/{name}"))
}

/// A seed's bytes after its selector byte.
fn body(target: &str, name: &str) -> Vec<u8> {
    seed(target, name)[1..].to_vec()
}

/// The control target of a single-response protocol, or `rpc_chunk` with the protocol's prefix.
fn control(protocol: Protocol) -> (&'static str, &'static str) {
    match protocol {
        Protocol::StatusV2 => ("status_v2", "status-"),
        Protocol::MetaDataV3 => ("metadata_v3", "metadata-"),
        Protocol::PingV1 => ("ping_goodbye", "ping-"),
        other => panic!("{other} is not a single-response protocol"),
    }
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

/// What each malformed single-chunk seed must be refused with.
fn chunk_cases() -> [(&'static str, Expect); 12] {
    [
        ("frame-body-too-large", |e| {
            *e == CodecError::FrameTooLarge {
                len: MAX_FRAME_BODY_LEN + 1,
            }
        }),
        ("frame-output-too-large", |e| {
            *e == CodecError::FrameTooLarge { len: 65_537 }
        }),
        ("frame-claims-over-4gib", |e| {
            matches!(e, CodecError::Snappy(_))
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
        (
            "prefix-over-4gib",
            |e| matches!(e, CodecError::PayloadTooLarge { len, .. } if *len == (1 << 32) + 1),
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
    ]
}

/// What each malformed request seed must be refused with: the chunk refusals, and a prefix
/// under the request's exact length.
fn request_cases() -> Vec<(&'static str, Expect)> {
    let mut cases: Vec<(&str, Expect)> = chunk_cases()
        .into_iter()
        .filter(|(name, _)| *name != "too-many-empty-frames")
        .collect();
    cases.push(("prefix-under-type-bound", |e| {
        matches!(e, CodecError::PayloadTooSmall { .. })
    }));
    cases
}

/// The single-response chunk seeds of `protocol`: `bytes(name)` is the chunk.
fn check_single_chunks(protocol: Protocol, what: &str, bytes: impl Fn(&str) -> Vec<u8>) {
    let decode = |name: &str| decode_response_chunk::<E>(&bytes(name), protocol, contexts());
    assert!(
        matches!(decode("valid"), Ok(ResponseChunk::Success(_))),
        "{what}"
    );
    for code in 1..=3 {
        let got = decode(&format!("error-code-{code}"));
        assert!(matches!(got, Ok(ResponseChunk::Error { .. })), "{what}");
    }
    for code in [4, 128, 255] {
        let got = decode(&format!("invalid-code-{code}"));
        assert_eq!(got, Err(CodecError::InvalidResultCode(code)), "{what}");
    }
    for (name, want) in chunk_cases() {
        let err = decode(name).unwrap_err();
        assert!(want(&err), "{what}/{name}: {err:?}");
    }
}

/// The request seeds of `protocol` whose body is `valid`: `bytes(name)` is the payload.
fn check_requests(protocol: Protocol, what: &str, valid: Request, bytes: impl Fn(&str) -> Vec<u8>) {
    let decode = |name: &str| decode_request(protocol, &bytes(name));
    assert_eq!(decode("valid"), Ok(valid), "{what}");
    for (name, want) in request_cases() {
        let err = decode(name).unwrap_err();
        assert!(want(&err), "{what}/{name}: {err:?}");
    }
}

#[test]
fn single_chunk_seeds() {
    for protocol in [Protocol::StatusV2, Protocol::MetaDataV3, Protocol::PingV1] {
        let (target, prefix) = control(protocol);
        check_single_chunks(protocol, target, |name| body(target, name));
        check_single_chunks(protocol, "rpc_chunk", |name| {
            body("rpc_chunk", &format!("{prefix}{name}"))
        });
    }
}

#[test]
fn request_seeds() {
    let status = Request::Status(p2p_wire::testkit::status());
    let ping = Request::Ping(p2p_wire::rpc::messages::Ping(9));
    check_requests(Protocol::StatusV2, "status_v2", status.clone(), |n| {
        body("status_v2", &format!("request-{n}"))
    });
    check_requests(Protocol::PingV1, "ping_goodbye", ping.clone(), |n| {
        body("ping_goodbye", &format!("request-{n}"))
    });
    check_requests(Protocol::StatusV2, "rpc_chunk", status, |n| {
        body("rpc_chunk", &format!("status-request-{n}"))
    });
    check_requests(Protocol::PingV1, "rpc_chunk", ping, |n| {
        body("rpc_chunk", &format!("ping-request-{n}"))
    });
    let goodbye = Request::Goodbye(p2p_wire::rpc::messages::Goodbye(1));
    check_requests(Protocol::GoodbyeV1, "rpc_chunk", goodbye, |n| {
        body("rpc_chunk", &format!("goodbye-request-{n}"))
    });
    let range = Request::BlocksByRange(p2p_wire::rpc::messages::BlocksByRangeV2Request {
        start_slot: 7,
        count: 4,
        step: 1,
    });
    check_requests(Protocol::BlocksByRangeV2, "rpc_chunk", range, |n| {
        body("rpc_chunk", &format!("blocks-request-{n}"))
    });
    for (target, prefix) in [("metadata_v3", ""), ("rpc_chunk", "metadata-")] {
        let decode = |name: &str| {
            decode_request(
                Protocol::MetaDataV3,
                &body(target, &format!("{prefix}request-{name}")),
            )
        };
        assert_eq!(decode("empty"), Ok(Request::MetaData));
        assert_eq!(decode("trailing-byte"), Err(CodecError::TrailingBytes(1)));
        assert!(matches!(
            decode("with-a-payload"),
            Err(CodecError::TrailingBytes(_))
        ));
    }
}

#[test]
fn rpc_chunk_block_and_goodbye_seeds() {
    let block = |name: &str| {
        decode_response_chunk::<E>(
            &body("rpc_chunk", &format!("blocks-{name}")),
            Protocol::BlocksByRangeV2,
            contexts(),
        )
    };
    let fork = |name: &str| match block(name) {
        Ok(ResponseChunk::Success(Response::Block(b))) => b.fork_name().to_string(),
        other => format!("{other:?}"),
    };
    assert_eq!(fork("fulu-valid"), "fulu");
    assert_eq!(fork("fulu-bpo-digest-valid"), "fulu");
    assert_eq!(fork("gloas-valid"), "gloas");
    assert!(matches!(
        block("unknown-context-digest"),
        Err(CodecError::UnknownContext(_))
    ));
    assert_eq!(block("context-cut-short"), Err(CodecError::Truncated));
    assert!(matches!(
        block("fulu-block-under-gloas-digest"),
        Err(CodecError::Decode(_))
    ));
    assert!(matches!(
        block("prefix-under-block-minimum"),
        Err(CodecError::PayloadTooSmall { .. })
    ));
    assert!(matches!(
        block("snappy-bomb"),
        Err(CodecError::CompressedTooLarge { len: 1000, .. })
    ));
    assert!(matches!(
        block("snappy-bomb-1mib-within-bound"),
        Err(CodecError::Decode(_))
    ));
    let goodbye = |name: &str| {
        decode_response_chunk::<E>(
            &body("rpc_chunk", &format!("goodbye-{name}")),
            Protocol::GoodbyeV1,
            contexts(),
        )
    };
    // Goodbye's response is one chunk with a reason (`phase0/p2p-interface.md` L1461, L1483).
    assert_eq!(
        goodbye("valid"),
        Ok(ResponseChunk::Success(Response::Goodbye(
            p2p_wire::rpc::messages::Goodbye(1)
        )))
    );
    assert!(matches!(
        goodbye("error-code-2"),
        Ok(ResponseChunk::Error { .. })
    ));
    // The selector names the protocol and the direction.
    assert_eq!(seed("rpc_chunk", "blocks-gloas-valid")[0], 3);
    assert_eq!(seed("rpc_chunk", "goodbye-request-valid")[0], 4 | 8);
}

/// The column protocols' seeds reach the sidecar decoder under the fixture caps, and each
/// refusal it is named for.
#[test]
fn rpc_chunk_column_seeds() {
    use consensus_types::forked;
    for (protocol, prefix) in [
        (Protocol::DataColumnsByRangeV1, "columns-range-"),
        (Protocol::DataColumnsByRootV1, "columns-root-"),
    ] {
        let chunk = |name: &str| {
            decode_response_chunk::<E>(
                &body("rpc_chunk", &format!("{prefix}{name}")),
                protocol,
                contexts(),
            )
        };
        assert!(matches!(
            chunk("gloas-valid"),
            Ok(ResponseChunk::Success(Response::DataColumn(s))) if matches!(*s, forked::DataColumnSidecar::Gloas(_))
        ));
        for name in ["fulu-valid", "fulu-bpo-digest-valid"] {
            assert!(
                matches!(
                    chunk(name),
                    Ok(ResponseChunk::Success(Response::DataColumn(s))) if matches!(*s, forked::DataColumnSidecar::Fulu(_))
                ),
                "{name}"
            );
        }
        assert!(matches!(
            chunk("gloas-sidecar-under-fulu-digest"),
            Err(CodecError::Decode(_))
        ));
        assert!(matches!(
            chunk("unknown-context-digest"),
            Err(CodecError::UnknownContext(_))
        ));
        assert!(matches!(
            chunk("prefix-under-sidecar-minimum"),
            Err(CodecError::PayloadTooSmall { .. })
        ));
        assert!(matches!(
            chunk("prefix-over-type-bound"),
            Err(CodecError::PayloadTooLarge { .. })
        ));
        let request = |name: &str| {
            decode_request(
                protocol,
                &body("rpc_chunk", &format!("{prefix}request-{name}")),
            )
        };
        assert!(request("valid").is_ok());
        assert!(matches!(
            request("list-past-its-limit"),
            Err(CodecError::Decode(_)) | Err(CodecError::PayloadTooLarge { .. })
        ));
        assert!(matches!(
            request("prefix-over-type-bound"),
            Err(CodecError::PayloadTooLarge { .. })
        ));
        assert!(request("truncated").is_err());
        assert!(request("trailing-byte").is_err());
    }
}

#[test]
fn goodbye_seeds() {
    let goodbye = Request::Goodbye(p2p_wire::rpc::messages::Goodbye(3));
    check_requests(Protocol::GoodbyeV1, "ping_goodbye", goodbye, |n| {
        body("ping_goodbye", &format!("goodbye-{n}"))
    });
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

fn transform() -> SnappyTransform {
    SnappyTransform::new(topic_caps())
}

/// A gossip seed's topic and the snappy transform's answer on it.
fn inbound(target: &str, name: &str) -> (String, Result<Vec<u8>, TransformError>) {
    let bytes = seed(target, name);
    let (topic, data) = split_message(&bytes).unwrap_or_else(|| panic!("{target}/{name}"));
    (topic.to_owned(), transform().inbound(topic, data))
}

#[test]
fn gossip_seeds() {
    let caps = topic_caps();
    let block_cap = caps.cap(GossipKind::BeaconBlock);
    assert_eq!(
        caps.cap(GossipKind::DataColumnSidecar { subnet_id: 0 }),
        45_380
    );
    for target in ["gossip_transform", "message_id"] {
        let got = |name: &str| inbound(target, name).1;
        let declared = |name: &str| match got(name) {
            Err(TransformError::DeclaredTooLarge { declared, cap }) => (declared, cap),
            other => panic!("{target}/{name}: {other:?}"),
        };
        let gloas = got("block-gloas-valid").unwrap();
        consensus_types::forked::SignedBeaconBlock::<E>::from_ssz_bytes_for_fork(
            &gloas,
            consensus_types::ForkName::Gloas,
        )
        .expect("a Gloas block");
        // One valid block under each digest of the Sepolia schedule, held to that digest's
        // caps (`TopicCaps::from_config`).
        let digests = gossip_digests();
        assert_eq!(digests.len(), 4);
        for (name, (digest, _, _)) in [
            "block-fulu-digest-valid",
            "block-fulu-bpo1-digest-valid",
            "block-fulu-bpo2-digest-valid",
            "block-gloas-valid",
        ]
        .into_iter()
        .zip(digests)
        {
            let (topic, ssz) = inbound(target, name);
            assert_eq!(
                GossipTopic::parse(&topic).unwrap().fork_digest,
                *digest,
                "{name}"
            );
            assert!(ssz.is_ok(), "{target}/{name}");
        }
        // No cap: a digest off the schedule, and a Gloas topic under a Fulu digest.
        for name in ["block-unsubscribed-digest", "bid-on-fulu-digest"] {
            assert!(
                matches!(got(name), Err(TransformError::NoCap(_))),
                "{target}/{name}: {:?}",
                got(name)
            );
        }
        // The column sidecar under each Fulu digest: its blob limit's sidecar passes, a byte
        // more is refused (Sepolia: 9, 15 and 21 blobs).
        for (n, cap) in [(1, 19_652), (2, 32_516), (3, 45_380)] {
            let at = format!("column-0-fulu-{n}-at-cap");
            assert_eq!(got(&at).map(|d| d.len()), Ok(cap), "{target}/{at}");
            let over = format!("column-0-fulu-{n}-over-cap");
            assert_eq!(declared(&over), (cap + 1, cap), "{target}/{over}");
        }
        assert_eq!(
            declared("block-declares-over-10mib"),
            (MAX_PAYLOAD_SIZE + 1, block_cap)
        );
        assert_eq!(
            declared("block-declares-4gib"),
            (u32::MAX as usize, block_cap)
        );
        assert_eq!(declared("block-over-cap"), (block_cap + 1, block_cap));
        for name in [
            "block-declares-over-4gib",
            "block-declares-u64-max",
            "block-varint-11-bytes",
            "block-truncated",
            "block-trailing-byte",
            "block-framing-format",
            "block-empty-data",
            "block-not-snappy",
        ] {
            assert!(
                matches!(got(name), Err(TransformError::Snappy(_))),
                "{target}/{name}: {:?}",
                got(name)
            );
        }
        assert_eq!(got("block-snappy-bomb-1mib").unwrap().len(), 1 << 20);
        assert!(matches!(
            got("topic-unknown-name"),
            Err(TransformError::Topic(TopicError::UnknownName(_)))
        ));
        assert!(matches!(
            got("topic-upper-case-digest"),
            Err(TransformError::Topic(TopicError::ForkDigest(_)))
        ));
        assert!(matches!(got("topic-empty"), Err(TransformError::Topic(_))));
        assert_eq!(split_message(&seed(target, "topic-cut-short")), None);
        for name in [
            "aggregate",
            "attestation-0",
            "attestation-63",
            "column-0",
            "column-127",
            "bid",
            "payload",
            "payload-attestation",
        ] {
            let (topic, empty) = inbound(target, &format!("{name}-empty"));
            assert_eq!(empty, Ok(Vec::new()), "{target}/{name}-empty");
            let topic = GossipTopic::parse(&topic).unwrap();
            let cap = caps.cap_at(topic.fork_digest, topic.kind).unwrap();
            assert_eq!(
                declared(&format!("{name}-over-cap")),
                (cap + 1, cap),
                "{name}"
            );
            let at_cap = format!("{name}-at-cap");
            if try_seed(target, &at_cap).is_some() {
                assert_eq!(
                    inbound(target, &at_cap).1.map(|d| d.len()),
                    Ok(cap),
                    "{at_cap}"
                );
            }
        }
        assert_eq!(
            got("aggregate-at-cap").unwrap().len(),
            caps.cap(GossipKind::BeaconAggregateAndProof)
        );
    }
}

#[test]
fn message_id_seeds_take_both_branches() {
    let id = |name: &str| {
        let bytes = seed("message_id", name);
        let (topic, data) = split_message(&bytes).unwrap();
        let decompressed = transform().inbound(topic, data).ok();
        (
            compute_message_id(topic, data),
            decompressed.map(|d| message_id_of_decompressed(topic, &d)),
        )
    };
    for valid in [
        "block-gloas-valid",
        "block-snappy-bomb-1mib",
        "aggregate-at-cap",
    ] {
        let (got, want) = id(valid);
        assert_eq!(Some(got), want, "{valid}: the valid-snappy branch");
    }
    for invalid in [
        "block-not-snappy",
        "block-declares-over-10mib",
        "block-truncated",
    ] {
        let (got, want) = id(invalid);
        assert_eq!(want, None, "{invalid}");
        let bytes = seed("message_id", invalid);
        let (topic, data) = split_message(&bytes).unwrap();
        assert_ne!(
            got,
            message_id_of_decompressed(topic, data),
            "{invalid}: the invalid-snappy branch"
        );
    }
}

fn sepolia(epoch: u64) -> ForkFields {
    let config = ChainConfig::load(Network::Sepolia).unwrap();
    let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
    ForkFields::from_schedule(&config, &gvr, epoch).unwrap()
}

#[test]
fn enr_seeds() {
    let raw = |name: &str| body("enr_fields", name);
    let parse = |name: &str| parse_enr_fields(&raw(name));
    // Each digest change from Fulu on: the epoch before it names the next digest in `nfd`, the
    // epoch of it carries that digest in `eth2`.
    let boundaries = [
        ("fulu-fork", 272_640),
        ("before-bpo1", 274_175),
        ("bpo1", 274_176),
        ("before-bpo2", 275_711),
        ("bpo2", 275_712),
        ("before-gloas", 353_023),
        ("gloas", 353_024),
    ];
    let mut digests = Vec::new();
    for (label, epoch) in boundaries {
        let fields = parse(&format!("sepolia-{label}-epoch-{epoch}")).unwrap();
        let want = sepolia(epoch);
        assert_eq!(
            fields,
            EnrFields {
                eth2: want.eth2,
                cgc: Some(4),
                nfd: Some(want.nfd),
                attnets: 0,
                syncnets: 0,
            },
            "{label}"
        );
        digests.push((fields.eth2.fork_digest, fields.nfd.unwrap()));
    }
    for pair in [(1, 2), (3, 4), (5, 6)] {
        let (before, at) = (digests[pair.0], digests[pair.1]);
        assert_ne!(before.0, at.0, "the digest changes at the boundary");
        assert_eq!(before.1, at.0, "nfd names the next digest");
    }
    assert_eq!(digests[6].1, [0; 4], "nothing scheduled after Gloas");
    let value = |name: &str| match parse(name) {
        Err(FieldError::Value(e)) => e,
        other => panic!("{name}: {other:?}"),
    };
    assert_eq!(value("eth2-15-bytes"), EnrFieldError::Eth2Len(15));
    assert_eq!(value("eth2-17-bytes"), EnrFieldError::Eth2Len(17));
    assert_eq!(value("cgc-leading-zero"), EnrFieldError::CgcLeadingZero);
    assert_eq!(value("cgc-9-bytes"), EnrFieldError::CgcTooLong(9));
    assert_eq!(value("nfd-3-bytes"), EnrFieldError::NfdLen(3));
    assert_eq!(value("nfd-5-bytes"), EnrFieldError::NfdLen(5));
    assert_eq!(parse("cgc-rlp-list"), Err(FieldError::Rlp { key: "cgc" }));
    assert_eq!(parse("no-eth2"), Err(FieldError::NoEth2));
    assert_eq!(parse("ed25519"), Err(FieldError::NotSecp256k1));
    assert_eq!(parse("cgc-zero").unwrap().cgc, Some(0));
    assert_eq!(parse("cgc-max").unwrap().cgc, Some(u64::MAX));
    let only = parse("eth2-only").unwrap();
    assert_eq!((only.cgc, only.nfd), (None, None));
    for name in [
        "truncated",
        "trailing-byte",
        "forged-signature",
        "over-300-bytes",
        "empty",
        "empty-list",
        "not-rlp",
    ] {
        assert!(
            matches!(parse(name), Err(FieldError::Record(_))),
            "{name}: {:?}",
            parse(name)
        );
    }
    // The ed25519 record the fuzzer found, whose raw cgc breaks it: refused as a record.
    let found = structured_record(&body(
        "enr_fields",
        "regression-structured-ed25519-broken-raw-cgc",
    ));
    assert!(matches!(
        parse_enr_fields(&found.unwrap()),
        Err(FieldError::Record(_))
    ));
    // A structured seed signs to exactly the record of the raw seed of its name.
    let mut structured = 0;
    for (target, name) in seeds::all(&[]).into_iter().map(|s| (s.target, s.name)) {
        let Some(base) = name.strip_prefix("structured-") else {
            continue;
        };
        if target != "enr_fields" || base == "no-values" {
            continue;
        }
        let record = structured_record(&body("enr_fields", &name)).unwrap();
        assert_eq!(record, raw(base), "{name}");
        structured += 1;
    }
    assert_eq!(structured, 20);
}

/// The Sepolia sidecar cap the column seeds are built around.
fn column_cap() -> usize {
    ethswarm_fuzz::spec_max_sidecar_size(ethswarm_fuzz::column_network().max_blobs_per_block())
        as usize
}

/// A decoded column sidecar, or why not.
type SidecarDecode =
    Result<consensus_types::forked::DataColumnSidecar<E>, consensus_types::codec::DecodeError>;

/// A `data_column_sidecar` gossip seed's transform and Gloas decode.
fn column_gossip(name: &str) -> (Result<Vec<u8>, TransformError>, Option<SidecarDecode>) {
    use consensus_types::caps::ObjectKind;
    use consensus_types::codec::{decode_for, Object};
    let bytes = seed("data_column_sidecar", &format!("gossip-{name}"));
    assert_eq!(
        bytes[0] & ethswarm_fuzz::CHUNK_BIT,
        0,
        "{name}: a gossip selector"
    );
    let topic = ethswarm_fuzz::column_topic(bytes[0] >> 1);
    let transform = SnappyTransform::new(topic_caps_on_sepolia());
    let inbound = transform.inbound(&topic, &bytes[1..]);
    let decoded = inbound.as_ref().ok().map(|ssz| {
        decode_for::<E>(
            ObjectKind::DataColumnSidecar,
            consensus_types::ForkName::Gloas,
            ethswarm_fuzz::column_network(),
            ssz,
        )
        .map(|o| match o {
            Object::DataColumnSidecar(s) => s,
            other => panic!("{name}: {:?}", other.kind()),
        })
    });
    (inbound, decoded)
}

fn topic_caps_on_sepolia() -> p2p_wire::gossip::TopicCaps {
    p2p_wire::gossip::TopicCaps::gloas::<E>(ethswarm_fuzz::column_network())
}

fn by_slot(sidecar: &consensus_types::forked::DataColumnSidecar<E>) -> SidecarDecode {
    use ssz::Encode;
    consensus_types::forked::DataColumnSidecar::from_ssz_bytes_by_slot(
        &sidecar.as_ssz_bytes(),
        ethswarm_fuzz::column_schedule(),
        ethswarm_fuzz::column_network(),
    )
}

/// The column gossip seeds reach the Gloas sidecar decode on the Sepolia caps, or the refusal
/// each is named for; the decoder takes counts and indices that verification refuses later.
#[test]
fn data_column_sidecar_gossip_seeds() {
    use consensus_types::codec::DecodeError;
    use consensus_types::forked::DataColumnSidecar;
    let cap = column_cap();
    assert_eq!(
        topic_caps_on_sepolia().cap(GossipKind::DataColumnSidecar { subnet_id: 0 }),
        cap
    );
    let gloas = |name: &str| match column_gossip(name) {
        (Ok(_), Some(Ok(DataColumnSidecar::Gloas(s)))) => s,
        other => panic!("{name}: {other:?}"),
    };
    for name in ["valid", "valid-subnet-0", "valid-subnet-127", "no-cells"] {
        let s = gloas(name);
        assert!(
            by_slot(&DataColumnSidecar::Gloas(s)).is_ok(),
            "{name}: a Gloas slot"
        );
    }
    assert_eq!(gloas("valid-subnet-127").index, 127);
    let at_cap = column_gossip("at-cap").0.unwrap();
    assert_eq!(at_cap.len(), cap, "exactly at the cap");
    assert_eq!(
        gloas("at-cap").column.len() as u64,
        ethswarm_fuzz::column_network().max_blobs_per_block()
    );
    let s = gloas("cells-ne-proofs");
    assert_ne!(s.column.len(), s.kzg_proofs.len());
    let s = gloas("proofs-far-past-cells");
    assert!(s.kzg_proofs.len() > 100 * s.column.len());
    assert_eq!(gloas("index-128").index, 128);
    assert_eq!(gloas("index-u64-max").index, u64::MAX);
    let s = DataColumnSidecar::Gloas(gloas("fulu-slot"));
    assert!(
        matches!(by_slot(&s), Err(DecodeError::Ssz(_))),
        "a Fulu slot decodes as Fulu"
    );
    let s = DataColumnSidecar::Gloas(gloas("pre-fulu-slot"));
    assert!(matches!(by_slot(&s), Err(DecodeError::PreFulu { slot: 9 })));
    for name in [
        "oversize-column-list",
        "oversize-cells-no-proofs",
        "declares-cap-plus-1",
    ] {
        match column_gossip(name).0 {
            Err(TransformError::DeclaredTooLarge { declared, cap: c }) => {
                assert_eq!(c, cap, "{name}");
                assert!(declared > cap, "{name}");
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    for name in ["declares-over-10mib", "declares-4gib"] {
        assert!(
            matches!(
                column_gossip(name).0,
                Err(TransformError::DeclaredTooLarge { .. })
            ),
            "{name}"
        );
    }
    for name in [
        "declares-over-4gib",
        "varint-11-bytes",
        "truncated",
        "trailing-byte",
        "not-snappy",
        "empty-data",
    ] {
        assert!(
            matches!(column_gossip(name).0, Err(TransformError::Snappy(_))),
            "{name}"
        );
    }
    for name in [
        "snappy-bomb-at-cap",
        "fulu-sidecar",
        "proofs-offset-before-column",
        "column-not-whole-cells",
        "first-offset-of-fulu",
        "proofs-offset-past-end",
    ] {
        match column_gossip(name) {
            (Ok(_), Some(Err(DecodeError::Ssz(_)))) => {}
            other => panic!("{name}: {other:?}"),
        }
    }
    assert_eq!(column_gossip("snappy-bomb-at-cap").0.unwrap().len(), cap);
}

/// The column response-chunk seeds of both protocols reach the sidecar decoder through the
/// context table with the Sepolia caps, and each refusal they are named for.
#[test]
fn data_column_sidecar_chunk_seeds() {
    use consensus_types::forked::DataColumnSidecar;
    use ethswarm_fuzz::{column_contexts, CHUNK_BIT, ROOT_BIT};
    for (lead, prefix, protocol) in [
        (CHUNK_BIT, "range-", Protocol::DataColumnsByRangeV1),
        (CHUNK_BIT | ROOT_BIT, "root-", Protocol::DataColumnsByRootV1),
    ] {
        let bytes = |name: &str| {
            let seed = seed("data_column_sidecar", &format!("{prefix}{name}"));
            assert_eq!(seed[0], lead, "{prefix}{name}: the selector");
            seed[1..].to_vec()
        };
        let decode =
            |name: &str| decode_response_chunk::<E>(&bytes(name), protocol, column_contexts());
        let fork = |name: &str| match decode(name) {
            Ok(ResponseChunk::Success(Response::DataColumn(s))) => match *s {
                DataColumnSidecar::Fulu(_) => "fulu",
                DataColumnSidecar::Gloas(_) => "gloas",
            },
            other => panic!("{prefix}{name}: {other:?}"),
        };
        for name in [
            "gloas-valid",
            "gloas-at-cap",
            "gloas-cells-ne-proofs",
            "gloas-index-128",
            "gloas-fulu-slot",
        ] {
            assert_eq!(fork(name), "gloas", "{prefix}{name}");
        }
        for name in [
            "fulu-valid",
            "fulu-bpo-digest-valid",
            "fulu-cells-ne-commitments",
            "fulu-index-128",
            "fulu-gloas-slot",
        ] {
            assert_eq!(fork(name), "fulu", "{prefix}{name}");
        }
        let err = |name: &str| decode(name).expect_err(name);
        assert!(matches!(
            err("gloas-oversize-column-list"),
            CodecError::PayloadTooLarge { .. }
        ));
        assert!(matches!(
            err("gloas-sidecar-under-fulu-digest"),
            CodecError::Decode(_)
        ));
        assert!(matches!(
            err("fulu-sidecar-under-gloas-digest"),
            CodecError::Decode(_)
        ));
        assert!(matches!(
            err("unknown-context-digest"),
            CodecError::UnknownContext(_)
        ));
        assert_eq!(err("context-cut-short"), CodecError::Truncated);
        assert!(matches!(
            err("prefix-under-sidecar-minimum"),
            CodecError::PayloadTooSmall { .. }
        ));
        assert!(matches!(
            err("snappy-bomb-within-bound"),
            CodecError::Decode(_)
        ));
        assert_eq!(err("empty-response"), CodecError::Truncated);
        // The empty response is a valid (empty) column answer to the codec.
        let empty = block_on(read_response_chunks::<E, _>(
            &mut Cursor::new(&bytes("empty-response")[..]),
            protocol,
            1,
            column_contexts(),
        ));
        assert!(
            matches!(empty.map(|c| c.len()), Ok(0)),
            "{prefix}empty-response"
        );
        for code in 1..=3 {
            assert!(
                matches!(
                    decode(&format!("error-code-{code}")),
                    Ok(ResponseChunk::Error { .. })
                ),
                "{prefix}error-code-{code}"
            );
        }
        for code in [4, 128, 255] {
            assert_eq!(
                decode(&format!("invalid-code-{code}")),
                Err(CodecError::InvalidResultCode(code))
            );
        }
        for (name, want) in chunk_cases() {
            let got = err(name);
            assert!(want(&got), "{prefix}{name}: {got:?}");
        }
    }
}

/// What each column request seed decodes to and how cl-p2p's admission check and the spec rule
/// judge it: `Ok(n)` admitted for `n` sidecars, `Err(())` refused as `1: InvalidRequest`.
fn column_request_verdicts(target: &str, protocol: Protocol, cases: &[(&str, Result<u64, ()>)]) {
    use p2p_wire::rpc::protocols::column_request_error;
    for (name, want) in cases {
        let request = decode_request(protocol, &seed(target, name))
            .unwrap_or_else(|e| panic!("{target}/{name}: {e}"));
        let admitted = column_request_error(&request).is_none();
        let rule = ethswarm_fuzz::spec_request_rule(&request);
        match want {
            Ok(n) => {
                assert!(admitted, "{target}/{name}: refused");
                assert_eq!(rule, Ok(*n), "{target}/{name}");
                assert_eq!(request.max_response_chunks(), *n, "{target}/{name}");
            }
            Err(()) => {
                assert!(!admitted, "{target}/{name}: admitted");
                assert!(rule.is_err(), "{target}/{name}");
            }
        }
    }
}

/// The framing refusals every column request target holds, by name.
fn column_request_framing(target: &str, protocol: Protocol, has_minimum: bool) {
    let decode = |name: &str| decode_request(protocol, &seed(target, name));
    for (name, want) in request_cases() {
        if name == "prefix-under-type-bound" && !has_minimum {
            assert!(
                try_seed(target, name).is_none(),
                "{target}/{name}: no minimum"
            );
            continue;
        }
        let err = decode(name).unwrap_err();
        assert!(want(&err), "{target}/{name}: {err:?}");
    }
    assert_eq!(
        decode("too-many-empty-frames"),
        Err(CodecError::TooManyEmptyFrames {
            max: MAX_EMPTY_FRAMES
        })
    );
}

#[test]
fn columns_by_range_req_seeds() {
    let target = "columns_by_range_req";
    let protocol = Protocol::DataColumnsByRangeV1;
    column_request_verdicts(
        target,
        protocol,
        &[
            ("valid", Ok(128)),
            ("at-sidecar-bound", Ok(16_384)),
            ("sidecars-past-bound", Err(())),
            ("count-times-columns-overflows", Err(())),
            ("count-u64-max-no-columns", Ok(0)),
            ("count-0", Ok(0)),
            ("no-columns", Ok(0)),
            ("index-128", Err(())),
            ("index-u64-max", Err(())),
            ("duplicate-columns", Ok(6)),
            ("columns-at-list-bound", Ok(128)),
        ],
    );
    let decode = |name: &str| decode_request(protocol, &seed(target, name));
    assert!(matches!(
        decode("columns-past-list-bound"),
        Err(CodecError::PayloadTooLarge { .. })
    ));
    assert!(matches!(
        decode("columns-offset-not-20"),
        Err(CodecError::Decode(_))
    ));
    assert!(matches!(
        decode("columns-not-whole-indices"),
        Err(CodecError::Decode(_))
    ));
    column_request_framing(target, protocol, true);
}

#[test]
fn columns_by_root_req_seeds() {
    let target = "columns_by_root_req";
    let protocol = Protocol::DataColumnsByRootV1;
    column_request_verdicts(
        target,
        protocol,
        &[
            ("valid", Ok(4)),
            ("at-both-bounds", Ok(16_384)),
            ("empty-list", Ok(0)),
            ("identifier-no-columns", Ok(0)),
            ("index-128", Err(())),
            ("index-u64-max", Err(())),
            ("duplicate-pairs", Ok(3)),
        ],
    );
    let decode = |name: &str| decode_request(protocol, &seed(target, name));
    assert!(matches!(
        decode("identifiers-past-bound-full"),
        Err(CodecError::PayloadTooLarge { .. })
    ));
    for name in [
        "identifiers-past-bound",
        "identifier-columns-past-bound",
        "identifier-columns-offset-not-36",
        "first-offset-not-a-multiple-of-4",
        "offsets-decreasing",
        "offset-past-end",
        "identifier-cut-short",
    ] {
        assert!(
            matches!(decode(name), Err(CodecError::Decode(_))),
            "{name}: {:?}",
            decode(name)
        );
    }
    column_request_framing(target, protocol, false);
}
