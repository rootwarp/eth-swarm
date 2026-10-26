//! cl-chain's builder key feed, as `verify.v1` BuilderKeyFeed sees it: frames of at most 4,096
//! finalized builders, and no frame before cl-verify's first response.

#[path = "../src/verify/pubkey_feed/test_state.rs"]
mod test_state;

use cl_chain::verify::pubkey_feed::{
    BuilderFeed, BuilderFeedError, FeedEpochs, BUILDER_CHUNK_ENTRIES,
};
use consensus_types::Minimal;
use ethswarm_proto::verify::{BuilderKeyFeedResponseBody, KeyNamespace};
use test_state::state_with_builders;

/// cl-verify's first response on a fresh stream: an empty builder cache.
fn first_response() -> BuilderKeyFeedResponseBody {
    BuilderKeyFeedResponseBody {
        namespace: KeyNamespace::Builder as i32,
        high_water: 0,
        err: None,
    }
}

#[test]
fn chunking() {
    assert_eq!(BUILDER_CHUNK_ENTRIES, 4_096);
    let epochs = FeedEpochs {
        feed_finalized_epoch: 10,
        chain_finalized_epoch: 10,
    };
    for (builders, chunks) in [
        (4_096usize, vec![(0, 4_096)]),
        (4_097, vec![(0, 4_096), (4_096, 1)]),
    ] {
        let keys: Vec<u8> = (0..builders).map(|i| (i % 251) as u8).collect();
        let finalized = state_with_builders::<Minimal>(&keys);
        let mut feed = BuilderFeed::new();
        // A missing first response is a contract violation, and nothing is sent before one.
        assert!(matches!(
            feed.start(None),
            Err(BuilderFeedError::ContractViolation(_))
        ));
        assert_eq!(
            feed.frames(&finalized, epochs),
            Err(BuilderFeedError::NotStarted)
        );
        assert_eq!(feed.start(Some(&first_response())), Ok(0));
        let frames = feed.frames(&finalized, epochs).unwrap();
        assert_eq!(
            frames
                .iter()
                .map(|f| (f.start_index, f.entries.len() as u64))
                .collect::<Vec<_>>(),
            chunks,
            "{builders} finalized builders"
        );
        assert!(frames.iter().all(|f| f.count == f.entries.len() as u64));
        // Only the last frame completes the finalized registry of epoch 10.
        let reported: Vec<_> = frames
            .iter()
            .map(|f| (f.feed_finalized_epoch, f.chain_finalized_epoch))
            .collect();
        let mut expected = vec![(0, 10); chunks.len() - 1];
        expected.push((10, 10));
        assert_eq!(reported, expected);
    }
}
