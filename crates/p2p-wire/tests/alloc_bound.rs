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
