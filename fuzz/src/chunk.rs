//! `rpc_chunk`: one req/resp chunk of any protocol through `p2p-wire`'s stateless decoders, and
//! the incremental scanners a transport drives on the same bytes.
//!
//! The first byte selects the protocol (its low three bits, an index into [`Protocol::ALL`]
//! modulo its length) and, with [`REQUEST_SELECTOR`], a request payload instead of a response
//! chunk. The rest is the chunk:
//!
//! - a response chunk (result byte, context bytes where the protocol has them, length prefix,
//!   snappy frames) goes to `decode_response_chunk`, which bounds the payload by the result code
//!   (an `ErrorMessage` for codes 1-3) and the fork the context bytes name;
//! - a request payload (length prefix, snappy frames; nothing for `GetMetaData`) goes to
//!   `decode_request`, bounded by the request type.
//!
//! An accepted chunk meets the harness's chunk invariants (its payload decodes on its own through
//! `decode_chunk` at the bound of its result code and context, and re-encodes to those SSZ bytes),
//! and the scanners agree with the decoder and with each other: fed exactly the bytes they ask
//! for, as a transport feeds them, they never ask for a byte past the chunk or past their own
//! buffer bound, and they stop where a one-shot scan of the whole input does (the same length,
//! the same error, or the same missing end).

use crate::{check_chunk, contexts, E};
use p2p_wire::rpc::codec::{
    decode_chunk, decode_request, decode_response_chunk, scan_response_chunk, ChunkScanner,
    CodecError, ResponseChunkScanner, Scan,
};
use p2p_wire::rpc::protocols::Protocol;

/// The selector bit that makes the rest a request payload instead of a response chunk.
pub const REQUEST_SELECTOR: u8 = 0x08;

/// The protocol selector of the first byte.
const PROTOCOL_MASK: u8 = 0x07;

/// `rpc_chunk`: see the module docs.
pub fn rpc_chunk(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let protocol = Protocol::ALL[usize::from(selector & PROTOCOL_MASK) % Protocol::ALL.len()];
    if selector & REQUEST_SELECTOR != 0 {
        request_payload(protocol, rest);
    } else {
        response_chunk(protocol, rest);
    }
}

fn response_chunk(protocol: Protocol, wire: &[u8]) {
    let mut scanner = ResponseChunkScanner::<E>::new(protocol, contexts());
    let fed = feed(wire, |buf| scanner.scan(buf));
    let whole = scan_response_chunk::<E>(wire, protocol, contexts());
    agree(&fed, wire.len(), &whole);
    if let Ok(chunk) = decode_response_chunk::<E>(wire, protocol, contexts()) {
        assert_eq!(
            whole,
            Ok(Scan::Complete { len: wire.len() }),
            "an accepted chunk does not scan as complete at its length"
        );
        check_chunk(wire, protocol, &chunk);
    }
}

fn request_payload(protocol: Protocol, wire: &[u8]) {
    let decoded = decode_request(protocol, wire);
    let Some(bounds) = protocol.request_bounds() else {
        // `GetMetaData`: no payload at all.
        assert_eq!(
            decoded.is_ok(),
            wire.is_empty(),
            "an empty request: {decoded:?}"
        );
        return;
    };
    let mut scanner = ChunkScanner::with_bounds(bounds);
    let fed = feed(wire, |buf| scanner.scan(buf));
    let whole = ChunkScanner::with_bounds(bounds).scan(wire);
    agree(&fed, wire.len(), &whole);
    if let Ok(request) = decoded {
        assert_eq!(
            request.protocol(),
            protocol,
            "a request of another protocol"
        );
        assert_eq!(
            whole,
            Ok(Scan::Complete { len: wire.len() }),
            "an accepted request does not scan as complete at its length"
        );
        let ssz = decode_chunk(wire, bounds.max)
            .expect("an accepted request's payload decodes on its own");
        assert!(
            request.ssz_body() == Some(ssz),
            "the request re-encodes to other SSZ bytes"
        );
    }
}

/// How a scanner fed as a transport feeds it stopped.
#[derive(Debug)]
pub(crate) struct Fed {
    /// Its last answer.
    outcome: Result<Scan, CodecError>,
    /// The bytes it held then.
    held: usize,
}

/// Feeds `wire` to `scan` as a transport does: nothing first, then exactly the `need` more bytes
/// each incomplete scan asks for, until the scan completes, fails, or asks for more than `wire`
/// holds. Every request stays within the scanner's own buffer bound (`max_len`).
pub(crate) fn feed(wire: &[u8], mut scan: impl FnMut(&[u8]) -> Result<Scan, CodecError>) -> Fed {
    let mut held = 0;
    loop {
        let outcome = scan(&wire[..held]);
        let Ok(Scan::Incomplete { need, max_len }) = outcome else {
            return Fed { outcome, held };
        };
        assert!(need > 0, "an incomplete scan asks for no byte at {held}");
        let want = held.saturating_add(need);
        assert!(
            want <= max_len,
            "the scan asks for {want} bytes, past its {max_len}-byte buffer bound"
        );
        if want > wire.len() {
            return Fed { outcome, held };
        }
        held = want;
    }
}

/// The fed scanner and a one-shot scan of the whole input reach the same answer: the same
/// complete length (which is where the fed scanner stopped: it never asked for a byte past the
/// chunk), the same error, or the same end of a chunk still incomplete (the one-shot scan holds
/// the bytes the fed one did not ask for yet, so it needs that many fewer) under the same bound.
pub(crate) fn agree(fed: &Fed, wire_len: usize, whole: &Result<Scan, CodecError>) {
    match (&fed.outcome, whole) {
        (
            Ok(Scan::Incomplete { need, max_len }),
            Ok(Scan::Incomplete {
                need: rest,
                max_len: whole_max,
            }),
        ) => {
            assert_eq!(
                fed.held + need,
                wire_len + rest,
                "fed and one-shot scans need the chunk to end at different lengths"
            );
            assert_eq!(
                max_len, whole_max,
                "fed and one-shot scans bound the chunk differently"
            );
        }
        (Ok(Scan::Complete { len }), _) => {
            assert_eq!(*len, fed.held, "complete at a length it was not fed");
            assert_eq!(whole, &fed.outcome, "fed and one-shot scans disagree");
        }
        _ => assert_eq!(whole, &fed.outcome, "fed and one-shot scans disagree"),
    }
}
