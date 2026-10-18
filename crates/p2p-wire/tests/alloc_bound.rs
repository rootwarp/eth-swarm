//! "No allocation above the declared bound", measured: the chunk decoder runs under a counting
//! global allocator that records the peak live heap and the largest single allocation made on
//! the measuring thread.
//!
//! The decoder's only allocations are the `n`-byte output (after the prefix passed its bound
//! and every frame is present) and the snappy decoder's two fixed buffers.

use p2p_wire::rpc::codec::{decode_chunk, encode_chunk, encode_varint, CodecError};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const MAX_PAYLOAD_SIZE: usize = 10 * (1 << 20);
/// `snap::read::FrameDecoder`'s fixed buffers: one compressed block (76,490) and one
/// uncompressed block (65,536).
const SNAPPY_FIXED: usize = 76_490 + 65_536;
/// Headroom for small bookkeeping allocations (error strings, `Take`), never a payload.
const SLACK: usize = 1024;

struct Counting;

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

fn record_alloc(size: usize) {
    let _ = ON.try_with(|on| {
        if on.get() {
            LIVE.with(|l| {
                let live = l.get() + size;
                l.set(live);
                PEAK.with(|p| p.set(p.get().max(live)));
            });
            LARGEST.with(|m| m.set(m.get().max(size)));
        }
    });
}

fn record_free(size: usize) {
    let _ = ON.try_with(|on| {
        if on.get() {
            LIVE.with(|l| l.set(l.get().saturating_sub(size)));
        }
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_alloc(layout.size());
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_alloc(layout.size());
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record_free(layout.size());
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_free(layout.size());
        record_alloc(new_size);
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Peak live heap and largest single allocation while `f` runs.
struct Measured<T> {
    value: T,
    peak: usize,
    largest: usize,
}

fn measure<T>(f: impl FnOnce() -> T) -> Measured<T> {
    LIVE.with(|c| c.set(0));
    PEAK.with(|c| c.set(0));
    LARGEST.with(|c| c.set(0));
    ON.with(|on| on.set(true));
    let value = f();
    ON.with(|on| on.set(false));
    Measured {
        value,
        peak: PEAK.with(Cell::get),
        largest: LARGEST.with(Cell::get),
    }
}

fn prefixed(declared: usize, frames_of: &[u8]) -> Vec<u8> {
    let chunk = encode_chunk(frames_of).unwrap();
    let (_, hdr) = p2p_wire::rpc::codec::decode_varint(&chunk).unwrap();
    let mut out = Vec::new();
    encode_varint(declared as u64, &mut out);
    out.extend_from_slice(&chunk[hdr..]);
    out
}

#[test]
fn bomb_over_max_payload_size_allocates_nothing() {
    let bomb = prefixed(MAX_PAYLOAD_SIZE + 1, &[0u8; 16_384]);
    assert!(bomb.len() <= 1024);
    let m = measure(|| decode_chunk(&bomb, MAX_PAYLOAD_SIZE));
    assert!(matches!(m.value, Err(CodecError::PayloadTooLarge { .. })));
    assert_eq!(m.peak, 0, "refused at the prefix without allocating");
}

#[test]
fn frame_bomb_under_a_small_prefix_stops_at_the_prefix() {
    // 8 bytes declared; the frames hold 64 KiB of zeros (about 3 KiB compressed). Snappy stops
    // after 8 bytes and the overrun is refused; the output is never more than 8 bytes.
    let bomb = prefixed(8, &[0u8; 65_536]);
    let m = measure(|| decode_chunk(&bomb, MAX_PAYLOAD_SIZE));
    // The compressed frames run past max_compressed_len(8) = 41 bytes, refused by the scan.
    assert!(matches!(
        m.value,
        Err(CodecError::CompressedTooLarge { len: 8, max: 41 })
    ));
    assert_eq!(m.peak, 0, "refused by the scan before the decoder exists");

    // A frame small enough to pass the compressed bound but holding more than declared.
    let over = prefixed(8, &[0u8; 16]);
    let m = measure(|| decode_chunk(&over, MAX_PAYLOAD_SIZE));
    assert_eq!(m.value, Err(CodecError::PayloadOverrun { len: 8 }));
    assert!(m.largest <= 76_490, "largest allocation {}", m.largest);
    assert!(m.peak <= 8 + SNAPPY_FIXED + SLACK, "peak {}", m.peak);
}

#[test]
fn truncated_large_declaration_allocates_nothing() {
    let data = vec![7u8; 1 << 20];
    let chunk = encode_chunk(&data).unwrap();
    let half = &chunk[..chunk.len() / 2];
    let m = measure(|| decode_chunk(half, MAX_PAYLOAD_SIZE));
    assert_eq!(m.value, Err(CodecError::Truncated));
    assert_eq!(m.peak, 0, "the scan allocates nothing");
}

#[test]
fn valid_payload_allocates_its_length_and_the_fixed_buffers() {
    let data: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 253) as u8).collect();
    let chunk = encode_chunk(&data).unwrap();
    let m = measure(|| decode_chunk(&chunk, MAX_PAYLOAD_SIZE));
    assert_eq!(m.value.as_deref(), Ok(&data[..]));
    assert_eq!(m.largest, data.len());
    assert!(
        m.peak <= data.len() + SNAPPY_FIXED + SLACK,
        "peak {}",
        m.peak
    );
}

/// The req/resp bounds of `phase0/p2p-interface.md` "SSZ-snappy encoding strategy" (L1327–1394),
/// measured under the counting allocator.
mod rpc {
    use super::*;
    use consensus_types::Minimal;
    use p2p_wire::rpc::codec::{
        decode_request, decode_response_chunk, max_compressed_len, ChunkScanner, Scan,
    };
    use p2p_wire::rpc::protocols::Protocol;

    /// Only the varint of `declared`: no frame follows.
    fn prefix_only(declared: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint(declared, &mut out);
        out
    }

    #[test]
    fn prefix_over_bound_no_alloc() {
        // MAX_PAYLOAD_SIZE + 1 with no body at all: the scanner refuses at the prefix instead
        // of asking for frames, and neither it nor the decoder allocates.
        let over = prefix_only(MAX_PAYLOAD_SIZE as u64 + 1);
        let too_large = CodecError::PayloadTooLarge {
            len: MAX_PAYLOAD_SIZE as u64 + 1,
            max: MAX_PAYLOAD_SIZE,
        };
        let m = measure(|| {
            (
                ChunkScanner::new(usize::MAX).scan(&over),
                decode_chunk(&over, usize::MAX),
            )
        });
        assert_eq!(m.value, (Err(too_large.clone()), Err(too_large)));
        assert_eq!(m.peak, 0, "refused at the prefix without allocating");

        // Above the type bound: Status is 92 bytes. A 93-byte prefix followed by 1 MiB of
        // garbage is refused at the prefix (not as bad snappy), as a request and as a response
        // chunk, with nothing allocated.
        let status = Protocol::StatusV2.limits::<Minimal>();
        assert_eq!((status.ssz_min, status.ssz_max), (92, 92));
        let mut request = prefix_only(93);
        request.extend(vec![0xa5; 1 << 20]);
        let mut response = vec![0];
        response.extend_from_slice(&request);
        let contexts = p2p_wire::testkit::context_table();
        let m = measure(|| {
            (
                decode_request(Protocol::StatusV2, &request),
                decode_response_chunk::<Minimal>(&response, Protocol::StatusV2, &contexts),
            )
        });
        let over_type = CodecError::PayloadTooLarge { len: 93, max: 92 };
        assert_eq!(m.value.0, Err(over_type.clone()));
        assert_eq!(m.value.1.err(), Some(over_type));
        assert_eq!(m.peak, 0, "refused at the prefix without allocating");

        // Below it too: a fixed-size type has one valid length.
        let under = prefix_only(91);
        let m = measure(|| decode_request(Protocol::StatusV2, &under));
        assert_eq!(
            m.value,
            Err(CodecError::PayloadTooSmall { len: 91, min: 92 })
        );
        assert_eq!(m.peak, 0);
        let mut scanner = ChunkScanner::with_bounds(status.request.unwrap());
        assert_eq!(
            scanner.scan(&under),
            Err(CodecError::PayloadTooSmall { len: 91, min: 92 })
        );
        // The bound itself still asks for the frames.
        let mut scanner = ChunkScanner::with_bounds(status.request.unwrap());
        assert!(matches!(
            scanner.scan(&prefix_only(92)),
            Ok(Scan::Incomplete { .. })
        ));
    }

    #[test]
    fn snappy_bomb() {
        // 4 KiB declared; one snappy frame of 64 KiB of zeros, about 3 KiB compressed, so it
        // fits under max_compressed_len(4096) and only the output bound can stop it.
        let declared = 4096;
        let bomb = prefixed(declared, &[0u8; 65_536]);
        assert!(
            bomb.len() <= 2 + max_compressed_len(declared),
            "{}",
            bomb.len()
        );
        let m = measure(|| decode_chunk(&bomb, MAX_PAYLOAD_SIZE));
        assert_eq!(m.value, Err(CodecError::PayloadOverrun { len: declared }));
        // The output never grows past the prefix: n bytes plus snappy's fixed buffers.
        assert!(m.largest <= 76_490, "largest allocation {}", m.largest);
        assert!(m.peak <= declared + SNAPPY_FIXED + SLACK, "peak {}", m.peak);

        // Exactly the declared bytes decode; any byte after the last frame is refused, a whole
        // second payload's frames included.
        let data = vec![7u8; declared];
        let chunk = encode_chunk(&data).unwrap();
        assert_eq!(decode_chunk(&chunk, declared).as_deref(), Ok(&data[..]));
        let mut one_more = chunk.clone();
        one_more.push(0);
        assert_eq!(
            decode_chunk(&one_more, declared),
            Err(CodecError::TrailingBytes(1))
        );
        let (_, prefix) = p2p_wire::rpc::codec::decode_varint(&chunk).unwrap();
        let mut two = chunk.clone();
        two.extend_from_slice(&chunk[prefix..]);
        assert_eq!(
            decode_chunk(&two, declared),
            Err(CodecError::TrailingBytes(chunk.len() - prefix))
        );
        // An early EOF inside the frames is truncated, never a short payload.
        assert_eq!(
            decode_chunk(&chunk[..chunk.len() - 1], declared),
            Err(CodecError::Truncated)
        );
    }
}

/// The gossip transform refuses a snappy block declaring more than the topic cap from its
/// header: nothing is allocated, however much the header declares.
#[test]
fn gossip_bomb_over_the_topic_cap_allocates_nothing() {
    use consensus_types::caps::NetworkCaps;
    use p2p_wire::gossip::{SnappyTransform, TopicCaps, TransformError};
    let transform = SnappyTransform::new(TopicCaps::gloas::<consensus_types::Mainnet>(
        &NetworkCaps::from_blob_schedule(21, &[]),
    ));
    let topic = "/eth2/00000000/beacon_block/ssz_snappy";
    let mut bomb = Vec::new();
    encode_varint(u64::from(u32::MAX), &mut bomb);
    bomb.extend_from_slice(&[0u8; 1024]);
    let m = measure(|| transform.inbound(topic, &bomb));
    assert!(matches!(
        m.value,
        Err(TransformError::DeclaredTooLarge { .. })
    ));
    assert_eq!(m.peak, 0, "refused at the header without allocating");

    // A valid message allocates its decompressed length once.
    let data: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 253) as u8).collect();
    let compressed = snap::raw::Encoder::new().compress_vec(&data).unwrap();
    let m = measure(|| transform.inbound(topic, &compressed));
    assert_eq!(m.value.as_deref(), Ok(&data[..]));
    assert_eq!(m.largest, data.len());
    assert!(m.peak <= data.len() + SLACK, "peak {}", m.peak);
}
