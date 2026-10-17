//! The `blocks_by_range_resp` harness checks every chunk the reader decoded, including those
//! before a refusal (an extra chunk, a broken chunk, data after an error, the byte budget), not
//! only the chunks of an accepted response.

use ethswarm_fuzz::seeds::{self, Seed};
use ethswarm_fuzz::{blocks_by_range_resp, E};
use p2p_wire::rpc::codec::encode_success_chunk;
use p2p_wire::testkit;
use ssz::Encode;

fn seed(name: &str) -> Vec<u8> {
    seeds::all(&[])
        .into_iter()
        .find(|s: &Seed| s.target == "blocks_by_range_resp" && s.name == name)
        .unwrap_or_else(|| panic!("no seed {name}"))
        .bytes
}

fn block(digest: [u8; 4], slot: u64) -> Vec<u8> {
    let ssz = if digest == testkit::GLOAS_DIGEST {
        testkit::gloas_block::<E>(slot).as_ssz_bytes()
    } else {
        testkit::fulu_block::<E>(slot).as_ssz_bytes()
    };
    encode_success_chunk(Some(digest), &ssz).unwrap()
}

#[test]
fn accepted_responses_check_every_chunk() {
    assert_eq!(blocks_by_range_resp(&seed("fulu-bpo-gloas")), 3);
    assert_eq!(blocks_by_range_resp(&seed("block-then-error")), 2);
    assert_eq!(blocks_by_range_resp(&seed("empty-response")), 0);
}

#[test]
fn chunks_before_an_extra_chunk_are_checked() {
    // count = 1, two blocks: the reader refuses with TooManyChunks after decoding the first.
    assert_eq!(blocks_by_range_resp(&seed("too-many-chunks")), 1);
    assert_eq!(blocks_by_range_resp(&seed("trailing-byte")), 1);
    // A block and an error chunk, then data: both checked, then refused.
    assert_eq!(blocks_by_range_resp(&seed("data-after-error")), 2);
}

#[test]
fn chunks_within_the_byte_budget_are_checked() {
    // Three 2^20-transaction blocks fit the 256 MiB budget and the reader refuses the fourth;
    // the walk checks all four.
    assert_eq!(blocks_by_range_resp(&seed("response-over-byte-budget")), 4);
}

#[test]
fn chunks_before_a_broken_chunk_are_checked() {
    let second = block(testkit::GLOAS_DIGEST, 2);
    let wire = [
        &[3u8][..],
        &block(testkit::FULU_DIGEST, 1),
        &block(testkit::FULU_BPO_DIGEST, 3),
        &second[..second.len() - 1],
    ]
    .concat();
    assert_eq!(blocks_by_range_resp(&wire), 2);
    assert_eq!(blocks_by_range_resp(&seed("unknown-context-digest")), 0);
}
