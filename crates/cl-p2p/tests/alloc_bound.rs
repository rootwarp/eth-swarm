//! The transport's receive buffer, measured: `read_response_chunks` runs under a counting
//! global allocator that records the peak live heap and the largest single allocation made on
//! the measuring thread.

use consensus_types::Minimal;
use futures::io::Cursor;
use p2p_wire::rpc::codec::{
    encode_success_chunk, encode_varint, max_compressed_len, CodecError, MAX_FRAME_BODY_LEN,
};
use p2p_wire::rpc::protocols::Protocol;
use p2p_wire::testkit;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

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

/// Reads `wire` as a one-chunk BlocksByRange response; the result, peak and largest allocation.
fn measure(wire: Vec<u8>) -> (Result<usize, cl_p2p::rpc::codec::ReadError>, usize, usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let contexts = testkit::context_table();
    let mut io = Cursor::new(wire);
    LIVE.with(|c| c.set(0));
    PEAK.with(|c| c.set(0));
    LARGEST.with(|c| c.set(0));
    ON.with(|on| on.set(true));
    let result = runtime.block_on(cl_p2p::rpc::codec::read_response_chunks::<Minimal, _>(
        &mut io,
        Protocol::BlocksByRangeV2,
        1,
        &contexts,
    ));
    let result = result.map(|chunks| chunks.len());
    ON.with(|on| on.set(false));
    (result, PEAK.with(Cell::get), LARGEST.with(Cell::get))
}

fn ten_mib_head() -> Vec<u8> {
    let mut wire = vec![0];
    wire.extend_from_slice(&testkit::FULU_DIGEST);
    encode_varint(10 << 20, &mut wire);
    wire.extend_from_slice(b"\xff\x06\x00\x00sNaPpY");
    wire
}

#[test]
fn oversized_frame_header_grows_no_buffer() {
    // About 20 bytes: a 10 MiB prefix and a frame header naming a 1 MB body.
    let mut wire = ten_mib_head();
    let len = 1_000_000usize;
    wire.extend_from_slice(&[0x00, len as u8, (len >> 8) as u8, (len >> 16) as u8]);
    assert!(wire.len() <= 24);
    let (result, peak, largest) = measure(wire);
    assert!(
        matches!(
            result,
            Err(cl_p2p::rpc::codec::ReadError::Codec(
                CodecError::FrameTooLarge { len: 1_000_000 }
            ))
        ),
        "{result:?}"
    );
    assert!(peak < 4096, "peak {peak}");
    assert!(largest < 1024, "largest {largest}");
}

#[test]
fn receive_buffer_never_passes_the_chunk_bound() {
    // A whole valid block: the buffer stays within the chunk's own bound (head, prefix and
    // max_compressed_len of the declared length), and no frame makes it grow by more than one
    // frame body at a time.
    let ssz = ssz::Encode::as_ssz_bytes(&testkit::fulu_block::<Minimal>(1));
    let wire = encode_success_chunk(Some(testkit::FULU_DIGEST), &ssz).unwrap();
    let bound = 1 + 4 + 10 + max_compressed_len(ssz.len());
    let (result, _, largest) = measure(wire);
    assert_eq!(result.unwrap(), 1);
    assert!(
        largest <= bound.max(MAX_FRAME_BODY_LEN),
        "largest {largest}, bound {bound}"
    );
}

/// The gossip transform decodes and caches only subscribed topics: a message on a supported
/// topic we do not subscribe is refused before its data is decompressed.
#[test]
fn gossip_transform_decodes_only_subscribed_topics() {
    use cl_p2p::gossip::GossipConfig;
    use consensus_types::caps::NetworkCaps;
    use libp2p::gossipsub::{DataTransform as _, RawMessage, TopicHash};
    use p2p_wire::gossip::{GossipKind, GossipTopic, SnappyTransform, TopicCaps};
    let caps =
        TopicCaps::gloas::<consensus_types::Mainnet>(&NetworkCaps::from_blob_schedule(21, &[]));
    let cfg = GossipConfig::new(
        vec![GossipTopic::new([0; 4], GossipKind::BeaconBlock)],
        caps,
        std::time::Duration::from_secs(60),
    );
    let transform = cfg.transform();
    let off_list = "/eth2/00000000/execution_payload/ssz_snappy";
    let ssz = vec![0u8; 4 << 20];
    let data = SnappyTransform::new(caps).outbound(off_list, &ssz).unwrap();
    let raw = RawMessage {
        source: None,
        data,
        sequence_number: None,
        topic: TopicHash::from_raw(off_list),
        signature: None,
        key: None,
        validated: false,
    };
    LIVE.with(|c| c.set(0));
    PEAK.with(|c| c.set(0));
    LARGEST.with(|c| c.set(0));
    ON.with(|on| on.set(true));
    let result = transform.inbound_transform(raw);
    ON.with(|on| on.set(false));
    assert!(result.is_err());
    let largest = LARGEST.with(Cell::get);
    assert!(
        largest <= 1024,
        "largest allocation {largest}: the data was decompressed"
    );
}
