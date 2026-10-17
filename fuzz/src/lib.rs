//! The harness behind the req/resp decoder fuzz targets, shared with the corpus tests and the
//! seed generator.
//!
//! Each target feeds peer bytes to the exact decoder the `m2a-session` binary runs, with the
//! mainnet preset (the session's) and the fixture [`ContextTable`] (no network config runs on
//! peer bytes, so none runs here either). A decode error is the expected outcome for most
//! inputs; what must never happen is a panic, an allocation past the libFuzzer limits the gate
//! sets, or an accepted input that breaks one of these invariants:
//!
//! - an accepted chunk's payload decodes on its own through `decode_chunk` (with the bound of
//!   its result code and context), and the decoded value re-encodes to exactly those SSZ bytes;
//! - the scanner agrees with the decoder: an accepted chunk scans as complete at its full length;
//! - a success chunk decodes to the protocol's own response type, a block in the fork its
//!   context bytes name, and an error chunk carries the result byte it was sent with;
//! - a `BeaconBlocksByRange` response holds at most the request's chunk limit, an error chunk
//!   only last, and every input byte was consumed (nothing may follow an error chunk); every chunk
//!   the reader decoded meets the chunk invariants, also when it then refuses the stream.

pub mod seeds;

use cl_p2p::rpc::codec::{read_response_chunks, ReadError};
use consensus_types::Mainnet;
use futures::executor::block_on;
use futures::io::Cursor;
use p2p_wire::rpc::codec::{
    decode_chunk, decode_response_chunk, scan_response_chunk, ContextTable, Scan, CONTEXT_BYTES_LEN,
};
use p2p_wire::rpc::messages::{BlocksByRangeV2Request, ForkDigest, Goodbye};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
use ssz::{Decode, Encode};
use std::sync::OnceLock;

/// The preset the `m2a-session` binary decodes with.
pub type E = Mainnet;

/// The four targets, by name.
pub const TARGETS: [&str; 4] = [
    "status_v2",
    "metadata_v3",
    "ping_goodbye",
    "blocks_by_range_resp",
];

/// `ping_goodbye`: a first byte with this bit clear selects a `Ping` response chunk, set a
/// `Goodbye` payload.
pub const GOODBYE_BIT: u8 = 1;

/// The fixture context table: Fulu (two digests) and Gloas.
pub fn contexts() -> &'static ContextTable {
    static TABLE: OnceLock<ContextTable> = OnceLock::new();
    TABLE.get_or_init(p2p_wire::testkit::context_table)
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
        _ => return false,
    }
    true
}

/// `status_v2`: `data` is one `Status` v2 response chunk.
pub fn status_v2(data: &[u8]) {
    single_chunk(Protocol::StatusV2, data);
}

/// `metadata_v3`: `data` is one `MetaData` v3 response chunk.
pub fn metadata_v3(data: &[u8]) {
    single_chunk(Protocol::MetaDataV3, data);
}

/// `ping_goodbye`: the first byte selects ([`GOODBYE_BIT`]) a `Ping` response chunk or a
/// `Goodbye` payload (the request body a disconnecting peer sends) for the rest.
pub fn ping_goodbye(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if selector & GOODBYE_BIT == 0 {
        single_chunk(Protocol::PingV1, rest);
    } else {
        goodbye(rest);
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

fn single_chunk(protocol: Protocol, data: &[u8]) {
    if let Ok(chunk) = decode_response_chunk::<E>(data, protocol, contexts()) {
        assert_eq!(
            complete_len(data, protocol),
            data.len(),
            "scan and decode disagree"
        );
        check_chunk(data, protocol, &chunk);
    }
}

fn goodbye(payload: &[u8]) {
    let Ok(ssz) = decode_chunk(payload, <Goodbye as Decode>::ssz_fixed_len()) else {
        return;
    };
    if let Ok(reason) = Goodbye::from_ssz_bytes(&ssz) {
        assert_eq!(reason.as_ssz_bytes(), ssz, "Goodbye re-encodes differently");
    }
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

/// The SSZ payload of an accepted `chunk`, through the payload decoder alone.
fn payload(chunk: &[u8], protocol: Protocol) -> Vec<u8> {
    let (head, max) = if chunk[0] != ResultCode::Success.as_byte() {
        (1, protocol.error_max_len())
    } else if protocol.has_context_bytes() {
        let fork = contexts().fork(&digest(chunk));
        let max = protocol.response_max_len::<E>(fork);
        (1 + CONTEXT_BYTES_LEN, max.expect("a known context"))
    } else {
        let max = protocol.response_max_len::<E>(None);
        (1, max.expect("no context needed"))
    };
    decode_chunk(&chunk[head..], max).expect("an accepted chunk's payload decodes on its own")
}

/// Checks the invariants of one accepted response chunk against its wire bytes.
fn check_chunk(chunk: &[u8], protocol: Protocol, decoded: &ResponseChunk<E>) {
    let ssz = payload(chunk, protocol);
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
                (Protocol::BlocksByRangeV2, Response::Block(block)) => {
                    assert_eq!(
                        Some(block.fork_name()),
                        contexts().fork(&digest(chunk)),
                        "block decoded in another fork than its context names"
                    );
                    block.as_ssz_bytes()
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
