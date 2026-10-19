//! The harness behind the fuzz targets, shared with the corpus tests and the seed generator.
//!
//! Each target feeds peer bytes to the exact entry point the binaries run on them, with the
//! mainnet preset (the session's and the probe's) and the fixture [`ContextTable`] with the
//! preset's column-sidecar caps (no network config runs on peer bytes, so none runs here
//! either; the caps let the column protocols' sidecars decode, `from_ssz_bytes_for_fork_with`). A decode error is the expected outcome
//! for most inputs; what must never happen is a panic, an allocation past the libFuzzer limits
//! the gates set, or an accepted input that breaks one of the invariants below.
//!
//! The req/resp control targets (`status_v2`, `metadata_v3`, `ping_goodbye`) run the timed codec
//! (the `timed` module: `cl_p2p::rpc::codec`'s `RpcCodec` and `InboundCodec`, under the
//! production deadlines), both directions: the first byte selects a response read on an outbound stream or,
//! with [`REQUEST_BIT`] (or, for `ping_goodbye`, [`GOODBYE_BIT`]), a request read on an inbound
//! one. Each result is held to the stateless decoder's (`decode_response_chunk`,
//! `decode_request`) on the same bytes:
//!
//! - an accepted chunk's payload decodes on its own through `decode_chunk` (with the bound of
//!   its result code and context), and the decoded value re-encodes to exactly those SSZ bytes;
//! - the scanner agrees with the decoder: an accepted chunk scans as complete at its full length;
//! - a success chunk decodes to the protocol's own response type, a block or a column sidecar
//!   in the fork its context bytes name, and an error chunk carries the result byte it was sent
//!   with;
//! - the codec accepts a response exactly when the chunk decoder accepts it (and returns that
//!   chunk), and a request exactly when the request decoder does (and returns that request);
//! - a `BeaconBlocksByRange` response holds at most the request's chunk limit, an error chunk
//!   only last, and every input byte was consumed (nothing may follow an error chunk); every chunk
//!   the reader decoded meets the chunk invariants, also when it then refuses the stream.
//!
//! The other targets: [`rpc_chunk`] (one chunk or request payload of any protocol, and the
//! incremental scanners), [`gossip_transform`] and [`message_id`] (the gossip transform, the Gloas
//! block decode and the message-id), [`enr_fields`] (a node record's `eth2`, `cgc` and `nfd`),
//! the column targets of gate 2a, [`data_column_sidecar`], [`columns_by_range_req`] and
//! [`columns_by_root_req`] (the `columns` module: the Gloas sidecar over gossip and req/resp on
//! the Sepolia blob schedule's caps, and the two column requests with their admission check and
//! cl-chain's bounds), and gate 2b's [`column_contract`] (the `contract` module: cl-chain's
//! storage contract, column store and column RPCs, driven with sequences of sidecars and
//! requests).

mod chunk;
mod columns;
mod contract;
mod gossip;
mod record;
pub mod seeds;
mod timed;

pub use chunk::{rpc_chunk, REQUEST_SELECTOR};
pub(crate) use columns::column_transform;
pub use columns::{
    chain_request_bounds, column_contexts, column_network, column_schedule, column_topic,
    columns_by_range_req, columns_by_root_req, data_column_sidecar, spec_max_sidecar_size,
    spec_request_rule, CHUNK_BIT, ROOT_BIT,
};
pub use contract::{
    cgc_set_slot, column_contract, column_contract_events, gloas_slot, known_blocks, kzg_verdict,
    raw_gossip, raw_request, Answer, Event, GossipSpec, KnownBlock, RangeSpec, RootSpec, CHAIN,
    CUSTODY, EXTRA_CELL, INPUT_DEADLINE, KZG_INVALID, KZG_NO_VERDICT, KZG_VALID, MAX_GOSSIP,
    MAX_REQUESTS, MISSING_CELL, MISSING_PROOF, OPS, OP_GOSSIP, OP_RANGE, OP_RAW_GOSSIP,
    OP_RAW_RANGE, OP_RAW_ROOT, OP_ROOT, SLOT_AFTER, UNKNOWN_ROOT, WRONG_SUBNET,
};
pub use gossip::{gossip_transform, message_id, message_input, split_message, topic_caps};
pub use record::{
    enr_fields, signed_record, structured_input, structured_record, RecordSpec, RecordValue,
    MAX_RECORD_LEN, STRUCTURED_BIT,
};

use cl_p2p::rpc::codec::{read_response_chunks, ReadError, ReceivedChunk, RpcRequest};
use consensus_types::Mainnet;
use futures::executor::block_on;
use futures::io::Cursor;
use p2p_wire::rpc::codec::{
    decode_chunk, decode_chunk_within, decode_request, decode_response_chunk, scan_response_chunk,
    ContextTable, Scan, CONTEXT_BYTES_LEN,
};
use p2p_wire::rpc::messages::{BlocksByRangeV2Request, ForkDigest, Ping};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
use ssz::Encode;
use std::io;
use std::sync::OnceLock;

/// The preset the `m2a-session` binary and the probe decode with.
pub type E = Mainnet;

/// Every target, by name: the four of the m2a gate (`fuzz/run-m2a-gate.sh`), the four
/// `fuzz/run-gate1.sh` adds to its three control targets, then the three of gate 2a
/// (`fuzz/run-gate2a.sh`) and the one of gate 2b (`fuzz/run-gate2b.sh`).
pub const TARGETS: [&str; 12] = [
    "status_v2",
    "metadata_v3",
    "ping_goodbye",
    "blocks_by_range_resp",
    "rpc_chunk",
    "gossip_transform",
    "message_id",
    "enr_fields",
    "data_column_sidecar",
    "columns_by_range_req",
    "columns_by_root_req",
    "column_contract",
];

/// `ping_goodbye`: a first byte with this bit set selects a `Goodbye` request (the body a
/// disconnecting peer sends); clear, a `Ping` (see [`REQUEST_BIT`]).
pub const GOODBYE_BIT: u8 = 1;

/// The control targets: a first byte with this bit set selects an inbound request of the
/// protocol, clear the response to our request.
pub const REQUEST_BIT: u8 = 2;

/// The fixture context table: Fulu (two digests) and Gloas, with the preset's column caps.
pub fn contexts() -> &'static ContextTable {
    static TABLE: OnceLock<ContextTable> = OnceLock::new();
    TABLE.get_or_init(p2p_wire::testkit::column_context_table)
}

/// Runs target `name` on `data`; `false` if there is no such target.
pub fn run(name: &str, data: &[u8]) -> bool {
    match name {
        "status_v2" => status_v2(data),
        "metadata_v3" => metadata_v3(data),
        "ping_goodbye" => ping_goodbye(data),
        "blocks_by_range_resp" => {
            blocks_by_range_resp(data);
        }
        "rpc_chunk" => rpc_chunk(data),
        "gossip_transform" => gossip_transform(data),
        "message_id" => message_id(data),
        "enr_fields" => enr_fields(data),
        "data_column_sidecar" => data_column_sidecar(data),
        "columns_by_range_req" => columns_by_range_req(data),
        "columns_by_root_req" => columns_by_root_req(data),
        "column_contract" => column_contract(data),
        _ => return false,
    }
    true
}

/// `status_v2`: after the selector byte, one `Status` v2 response chunk, or with
/// [`REQUEST_BIT`] an inbound `Status` request.
pub fn status_v2(data: &[u8]) {
    control(Protocol::StatusV2, data);
}

/// `metadata_v3`: after the selector byte, one `MetaData` v3 response chunk, or with
/// [`REQUEST_BIT`] an inbound `GetMetaData` request (which must be empty).
pub fn metadata_v3(data: &[u8]) {
    control(Protocol::MetaDataV3, data);
}

/// `ping_goodbye`: after the selector byte, an inbound `Goodbye` request ([`GOODBYE_BIT`]), else
/// an inbound `Ping` request ([`REQUEST_BIT`]) or one `Ping` response chunk.
pub fn ping_goodbye(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if selector & GOODBYE_BIT != 0 {
        request(Protocol::GoodbyeV1, rest);
    } else {
        control(Protocol::PingV1, data);
    }
}

/// The selector byte's [`REQUEST_BIT`] picks the direction of `protocol` for the rest.
fn control(protocol: Protocol, data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if selector & REQUEST_BIT != 0 {
        request(protocol, rest);
    } else {
        response(protocol, rest);
    }
}

/// The request we send on `protocol`, whose response the timed codec then reads.
fn our_request(protocol: Protocol) -> Request {
    match protocol {
        Protocol::StatusV2 => Request::Status(p2p_wire::testkit::status()),
        Protocol::MetaDataV3 => Request::MetaData,
        Protocol::PingV1 => Request::Ping(Ping(1)),
        other => panic!("{other} is not a single-response control protocol"),
    }
}

/// `wire` as the response to our request on `protocol`, through the timed codec, held to the
/// stateless chunk decoder.
fn response(protocol: Protocol, wire: &[u8]) {
    let read = timed::read_response(our_request(protocol), wire);
    let direct = decode_response_chunk::<E>(wire, protocol, contexts());
    match (read, direct) {
        (Ok(chunks), Ok(chunk)) => {
            let [ReceivedChunk {
                context: None,
                chunk: read,
            }] = chunks.as_slice()
            else {
                panic!("a single-response read returned {chunks:?}");
            };
            assert!(*read == chunk, "the codec and the chunk decoder disagree");
            assert_eq!(
                complete_len(wire, protocol),
                wire.len(),
                "scan and decode disagree"
            );
            check_chunk(wire, protocol, &chunk);
        }
        (Err(e), Ok(_)) => panic!("the codec refused a chunk the chunk decoder accepts: {e}"),
        (Ok(_), Err(e)) => panic!("the codec accepted a chunk the chunk decoder refuses: {e}"),
        (Err(e), Err(_)) => assert_ne!(
            e.kind(),
            io::ErrorKind::TimedOut,
            "a deadline passed on an in-memory stream: {e}"
        ),
    }
}

/// `wire` as an inbound request of `protocol`, through the timed codec, held to the stateless
/// request decoder; the request, if both accepted it.
pub(crate) fn request(protocol: Protocol, wire: &[u8]) -> Option<Request> {
    let read = timed::read_request(protocol, wire)
        .unwrap_or_else(|e| panic!("an in-memory request stream failed: {e}"));
    let direct = decode_request(protocol, wire);
    match read {
        RpcRequest::Valid(request) => {
            assert_eq!(
                direct.as_ref(),
                Ok(&request),
                "the codec and the request decoder disagree"
            );
            assert_eq!(
                request.protocol(),
                protocol,
                "a request of another protocol"
            );
            match protocol.request_bounds() {
                Some(bounds) => {
                    let ssz = decode_chunk_within(wire, bounds)
                        .expect("an accepted request's payload decodes on its own");
                    assert!(
                        request.ssz_body() == Some(ssz),
                        "the request re-encodes to other SSZ bytes"
                    );
                }
                None => assert!(wire.is_empty(), "an empty request with bytes"),
            }
            Some(request)
        }
        RpcRequest::Malformed(e) => {
            assert!(
                direct.is_err(),
                "the codec refused ({e}) a request the request decoder accepts"
            );
            None
        }
    }
}

/// `blocks_by_range_resp`: the first byte is the request's `count`, the rest the response
/// stream, read by `read_response_chunks` with the chunk limit the request allows.
///
/// The same bytes are also walked chunk by chunk, as the reader reads them: every chunk the
/// reader decoded is checked, also when it then refuses the stream (an extra chunk, a broken
/// one), and an accepted response must be exactly the walked chunks. Returns how many chunks
/// were checked.
pub fn blocks_by_range_resp(data: &[u8]) -> usize {
    let Some((&count, wire)) = data.split_first() else {
        return 0;
    };
    let request = Request::BlocksByRange(BlocksByRangeV2Request {
        start_slot: 0,
        count: u64::from(count),
        step: 1,
    });
    let max_chunks = request.max_response_chunks();
    let protocol = Protocol::BlocksByRangeV2;
    let read = block_on(read_response_chunks::<E, _>(
        &mut Cursor::new(wire),
        protocol,
        max_chunks,
        contexts(),
    ));

    let mut walked = Vec::new();
    let mut rest = wire;
    while (walked.len() as u64) < max_chunks {
        let Ok(Scan::Complete { len }) = scan_response_chunk::<E>(rest, protocol, contexts())
        else {
            break;
        };
        let Ok(chunk) = decode_response_chunk::<E>(&rest[..len], protocol, contexts()) else {
            break;
        };
        check_chunk(&rest[..len], protocol, &chunk);
        rest = &rest[len..];
        let last = matches!(chunk, ResponseChunk::Error { .. });
        walked.push(chunk);
        if last {
            break;
        }
    }

    match read {
        Ok(chunks) => {
            assert!(
                chunks.len() as u64 <= max_chunks,
                "{} chunks accepted for a limit of {max_chunks}",
                chunks.len()
            );
            assert!(chunks == walked, "the reader and the chunk walk disagree");
            // Nothing follows the last chunk, an error chunk included.
            assert!(
                rest.is_empty(),
                "{} bytes left after the response",
                rest.len()
            );
        }
        Err(ReadError::DataAfterError) => {
            assert!(
                matches!(walked.last(), Some(ResponseChunk::Error { .. })),
                "data after an error chunk, with no error chunk"
            );
            assert!(
                !rest.is_empty(),
                "refused with nothing after the error chunk"
            );
        }
        Err(ReadError::TooManyChunks { max }) => {
            assert_eq!(max, max_chunks, "chunk limit reported wrong");
            assert_eq!(walked.len() as u64, max_chunks, "refused before the limit");
            assert!(!rest.is_empty(), "refused with nothing past the limit");
        }
        Err(ReadError::NoResponse) => panic!("an empty BlocksByRange response is valid"),
        Err(_) => {}
    }
    walked.len()
}

/// The length of the complete response chunk at the start of `buf`, which the decoder accepted.
fn complete_len(buf: &[u8], protocol: Protocol) -> usize {
    match scan_response_chunk::<E>(buf, protocol, contexts()) {
        Ok(Scan::Complete { len }) => len,
        other => panic!("an accepted chunk scans as {other:?}"),
    }
}

/// The context digest of a success chunk of a protocol with context bytes.
fn digest(chunk: &[u8]) -> ForkDigest {
    chunk[1..1 + CONTEXT_BYTES_LEN]
        .try_into()
        .expect("an accepted chunk holds its context bytes")
}

/// The SSZ payload of an accepted `chunk`, read with `contexts`, through the payload decoder
/// alone.
fn payload(contexts: &ContextTable, chunk: &[u8], protocol: Protocol) -> Vec<u8> {
    let (head, max) = if chunk[0] != ResultCode::Success.as_byte() {
        (1, protocol.error_max_len())
    } else if protocol.has_context_bytes() {
        let fork = contexts.fork(&digest(chunk));
        let max = protocol.response_max_len_with::<E>(fork, contexts.network_caps());
        (1 + CONTEXT_BYTES_LEN, max.expect("a known context"))
    } else {
        let max = protocol.response_max_len::<E>(None);
        (1, max.expect("no context needed"))
    };
    decode_chunk(&chunk[head..], max).expect("an accepted chunk's payload decodes on its own")
}

/// Checks the invariants of one accepted response chunk against its wire bytes, read with the
/// fixture [`contexts`].
pub(crate) fn check_chunk(chunk: &[u8], protocol: Protocol, decoded: &ResponseChunk<E>) {
    check_chunk_in(contexts(), chunk, protocol, decoded);
}

/// [`check_chunk`] for a chunk read with `contexts`.
pub(crate) fn check_chunk_in(
    contexts: &ContextTable,
    chunk: &[u8],
    protocol: Protocol,
    decoded: &ResponseChunk<E>,
) {
    let ssz = payload(contexts, chunk, protocol);
    let reencoded = match decoded {
        ResponseChunk::Error { code, message } => {
            assert_ne!(*code, ResultCode::Success, "an error chunk with code 0");
            assert_eq!(code.as_byte(), chunk[0], "result code changed");
            message.as_ssz_bytes()
        }
        ResponseChunk::Success(response) => {
            assert_eq!(
                chunk[0],
                ResultCode::Success.as_byte(),
                "result code changed"
            );
            match (protocol, response) {
                (Protocol::StatusV2, Response::Status(status)) => status.as_ssz_bytes(),
                (Protocol::MetaDataV3, Response::MetaData(metadata)) => metadata.as_ssz_bytes(),
                (Protocol::PingV1, Response::Ping(ping)) => ping.as_ssz_bytes(),
                (Protocol::GoodbyeV1, Response::Goodbye(goodbye)) => goodbye.as_ssz_bytes(),
                (Protocol::BlocksByRangeV2, Response::Block(block)) => {
                    assert_eq!(
                        Some(block.fork_name()),
                        contexts.fork(&digest(chunk)),
                        "block decoded in another fork than its context names"
                    );
                    block.as_ssz_bytes()
                }
                (
                    Protocol::DataColumnsByRangeV1 | Protocol::DataColumnsByRootV1,
                    Response::DataColumn(sidecar),
                ) => {
                    assert_eq!(
                        Some(sidecar.fork_name()),
                        contexts.fork(&digest(chunk)),
                        "sidecar decoded in another fork than its context names"
                    );
                    sidecar.as_ssz_bytes()
                }
                (protocol, response) => panic!("a {protocol} chunk decoded to {response:?}"),
            }
        }
    };
    assert!(
        reencoded == ssz,
        "decoded value re-encodes to other SSZ bytes"
    );
}
