//! The builder key namespace over real VerifyBls and BuilderKeyFeed streams: builder keys never
//! resolve as validator keys (or the other way round), only finalized builders are cached, a
//! builder above finality resolves only through its inline key on import, every cache hit needs
//! the full key of the state verified against, and the cache is memory only.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use cl_verify::bls::{BlsBackend, BlstBackend, PreparedSet};
use cl_verify::proto::common::ErrorCode;
use cl_verify::proto::verify::{BlsSet, KeyNamespace, VerifyOrigin, VerifyStatus};
use cl_verify_cache::{split_import_batch, MAX_INLINE_KEYS_PER_BATCH};
use common::*;

use VerifyOrigin::{Gossip, Import};

const VALID: Result<VerifyStatus, ErrorCode> = Ok(VerifyStatus::Valid);
const INVALID: Result<VerifyStatus, ErrorCode> = Ok(VerifyStatus::Invalid);
const UNKNOWN: Result<VerifyStatus, ErrorCode> = Ok(VerifyStatus::UnknownIndex);

/// Counts the batches that reach BLS.
#[derive(Clone, Default)]
struct Counting(Arc<AtomicUsize>);

impl BlsBackend for Counting {
    fn verify(&self, sets: &[PreparedSet]) -> Vec<bool> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BlstBackend.verify(sets)
    }
}

/// A set over `[root; 32]` signed by validator `i`'s key, naming `signer`.
fn validator_signed(signer: cl_verify::proto::verify::Signer, i: u64, root: u8) -> BlsSet {
    let mut set = signed_set(vec![cached(i)], &[i], root);
    set.signers = vec![signer];
    set
}

/// A builder signer for `index` at the version of the fed builder key `index`, but carrying
/// validator `i`'s key as the state key.
fn builder_with_validator_key(index: u64, i: u64) -> cl_verify::proto::verify::Signer {
    let mut s = builder_signer(index, index, false);
    s.builder.as_mut().unwrap().pubkey = pk_bytes(i);
    s
}

#[tokio::test]
async fn namespace_isolation() {
    let mut h = start().await;
    rebuild_over_feed(&mut h, 6, 6).await;
    let mut feed = feed_builders(&mut h, 6).await;
    assert_ne!(
        builder_pk_bytes(5),
        pk_bytes(5),
        "different keys at index 5"
    );

    let sets = vec![
        // Signed by builder 5.
        builder_set(builder_signer(5, 5, false), 5, 1),
        builder_set(cached(5), 5, 2),
        // Signed by validator 5.
        validator_signed(cached(5), 5, 3),
        validator_signed(builder_signer(5, 5, false), 5, 4),
        validator_signed(builder_with_validator_key(5, 5), 5, 5),
    ];
    for origin in [Gossip, Import] {
        assert_eq!(
            bls_outcomes(&mut h, sets.clone(), origin).await,
            [VALID, INVALID, VALID, INVALID, UNKNOWN],
            "each index resolves in its own namespace only"
        );
    }

    // A feed frame of another namespace is refused in-band and applies nothing.
    for (namespace, code) in [
        (
            KeyNamespace::Unspecified as i32,
            ErrorCode::ContractViolation,
        ),
        (KeyNamespace::Validator as i32, ErrorCode::ContractViolation),
        (99, ErrorCode::VersionMismatch),
    ] {
        let mut frame = builder_frame(0, [7]);
        frame.namespace = namespace;
        assert_eq!(builder_apply(&mut feed, frame).await, (6, Some(code)));
    }
    assert_eq!(
        bls_outcomes(
            &mut h,
            vec![builder_set(builder_signer(0, 0, false), 0, 6)],
            Gossip
        )
        .await,
        [VALID],
        "builder 0 is still the fed key"
    );

    // A zero signer namespace fails the VerifyBls stream.
    let mut zero = valid_set(1, 7);
    zero.signers[0].namespace = KeyNamespace::Unspecified as i32;
    let mut b = bls_open(&mut h).await;
    b.send(bls_body(bls_request(1, vec![zero]))).await;
    assert_eq!(
        b.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn unknown_ignored() {
    let counting = Counting::default();
    let mut h = start_with(Options {
        bls: Arc::new(counting.clone()),
        ..Options::default()
    })
    .await;
    let _feed = feed_builders(&mut h, 2).await;
    let mut wrong_version = builder_signer(1, 1, false);
    wrong_version.builder.as_mut().unwrap().key_version += 1;
    let mut other_key_same_version = builder_signer(1, 9, false);
    other_key_same_version.builder.as_mut().unwrap().key_version = builder_version(1);
    let sets = vec![
        // An index the feed never sent.
        builder_set(builder_signer(5, 5, false), 5, 1),
        // A fed index under another version.
        builder_set(wrong_version, 1, 2),
        // A fed index and version with another key.
        builder_set(other_key_same_version, 9, 3),
    ];
    for origin in [Gossip, Import] {
        assert_eq!(
            bls_outcomes(&mut h, sets.clone(), origin).await,
            [UNKNOWN; 3]
        );
    }
    assert_eq!(counting.0.load(Ordering::SeqCst), 0, "no BLS call");
}

#[tokio::test]
async fn inline_unfinalized() {
    let mut h = start().await;
    let mut feed = feed_builders(&mut h, 2).await;
    // 1,025 builders registered above finality, at indices 2.., signing as four aggregates of
    // 256 and one single set: 1,025 inline keys.
    let sizes = [256u64, 256, 256, 256, 1];
    let mut next = 2u64;
    let sets: Vec<BlsSet> = sizes
        .iter()
        .zip(10u8..)
        .map(|(&n, root)| {
            let keys: Vec<u64> = (next..next + n).collect();
            next += n;
            let msg = [root; 32];
            let sigs: Vec<_> = keys
                .iter()
                .map(|k| builder_sk(*k).sign(&msg, cl_verify::bls::DST, &[]))
                .collect();
            let refs: Vec<_> = sigs.iter().collect();
            let agg = blst::min_pk::AggregateSignature::aggregate(&refs, false).unwrap();
            BlsSet {
                signers: keys.iter().map(|k| builder_signer(*k, *k, true)).collect(),
                signing_root: msg.to_vec(),
                signature: agg.to_signature().compress().to_vec(),
            }
        })
        .collect();
    let batches = split_import_batch(sets.clone(), |s| s.signers.len());
    let inline: Vec<usize> = batches
        .iter()
        .map(|b| b.iter().map(|s| s.signers.len()).sum())
        .collect();
    assert_eq!(inline, [MAX_INLINE_KEYS_PER_BATCH, 1], "split 1,024 + 1");

    let mut b = bls_open(&mut h).await;
    for (id, batch) in (1u64..).zip(batches) {
        let n = batch.len();
        b.send(bls_body(bls_request(id, batch))).await;
        assert_eq!(outcomes(&bls_reply(&mut b).await), vec![VALID; n]);
    }
    // Without its inline key, a builder above finality is unknown.
    assert_eq!(
        bls_outcomes(
            &mut h,
            vec![builder_set(builder_signer(2, 2, false), 2, 1)],
            Import
        )
        .await,
        [UNKNOWN]
    );
    // The cache's high-water mark did not move.
    assert_eq!(
        builder_apply(&mut feed, builder_frame(2, [])).await,
        (2, None)
    );
    // All 1,025 inline keys in one request break the inline packing cap.
    let mut whole = bls_open(&mut h).await;
    whole.send(bls_body(bls_request(1, sets))).await;
    assert_eq!(
        whole.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
    // An inline builder key on gossip fails the stream.
    let mut gossip = bls_open(&mut h).await;
    let set = builder_set(builder_signer(2, 2, true), 2, 1);
    gossip
        .send(bls_body(bls_request_from(1, vec![set], Gossip)))
        .await;
    assert_eq!(
        gossip.expect_failure().await.code(),
        ErrorCode::ContractViolation
    );
}

#[tokio::test]
async fn reorg_discards_unfinalized() {
    const KEY_A: u64 = 100;
    const KEY_A0: u64 = 101;
    const KEY_B: u64 = 200;
    let mut h = start().await;
    // Finalized: builders 0 and 1.
    let mut feed = feed_builders(&mut h, 2).await;

    // Branch A: a deposit gives index 2 to key A, and finalized builder 0 (exited, swept)
    // gives its index to key A0. Both are above finality and resolve on import only inline.
    let a2 = |inline| builder_set(builder_signer(2, KEY_A, inline), KEY_A, 1);
    let a0 = |inline| builder_set(builder_signer(0, KEY_A0, inline), KEY_A0, 2);
    assert_eq!(
        bls_outcomes(&mut h, vec![a2(true), a0(true)], Import).await,
        [VALID, VALID]
    );
    assert_eq!(
        bls_outcomes(&mut h, vec![a2(false), a0(false)], Import).await,
        [UNKNOWN, UNKNOWN],
        "the finalized key of index 0 never stands in for branch A's"
    );

    // Reorg to branch B, where index 2 is key B, and B finalizes.
    assert_eq!(
        builder_apply(&mut feed, builder_frame(2, [])).await,
        (2, None)
    );
    assert_eq!(
        builder_apply(&mut feed, builder_frame(2, [KEY_B])).await,
        (3, None)
    );
    let b2 = builder_set(builder_signer(2, KEY_B, false), KEY_B, 3);
    // Key A under key B's version: a version match alone never selects the cached key.
    let mut collided = builder_signer(2, KEY_A, false);
    collided.builder.as_mut().unwrap().key_version = builder_version(KEY_B);
    let collided = builder_set(collided, KEY_A, 4);
    for origin in [Gossip, Import] {
        assert_eq!(
            bls_outcomes(
                &mut h,
                vec![a2(false), b2.clone(), collided.clone()],
                origin
            )
            .await,
            [UNKNOWN, VALID, UNKNOWN]
        );
    }
    // Builder 0 is still its finalized key.
    assert_eq!(
        bls_outcomes(
            &mut h,
            vec![builder_set(builder_signer(0, 0, false), 0, 5)],
            Gossip
        )
        .await,
        [VALID]
    );
}

#[tokio::test]
async fn startup_refill() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("pubkeys.bin");
    let one = |key: u64| vec![builder_set(builder_signer(key, key, false), key, 1)];

    let mut h = start_with(restarted(&snapshot)).await;
    rebuild_over_feed(&mut h, 3, 3).await;
    let feed = feed_builders(&mut h, 4).await;
    assert_eq!(bls_outcomes(&mut h, one(1), Gossip).await, [VALID]);
    drop(feed);
    h.shutdown().await;
    assert!(
        snapshot_holds(&snapshot, 3),
        "the snapshot holds the 3 validators and no builder entry"
    );

    let mut h = start_with(restarted(&snapshot)).await;
    rebuild_over_feed(&mut h, 3, 3).await;
    assert_eq!(
        bls_outcomes(&mut h, one(1), Gossip).await,
        [UNKNOWN],
        "nothing resolves before the builder feed"
    );
    let (mut feed, first) = builder_open(&mut h).await;
    assert_eq!(
        first, 0,
        "the first response reports an empty builder cache"
    );
    assert_eq!(
        builder_apply(&mut feed, builder_frame(0, 0..4)).await,
        (4, None)
    );
    let all: Vec<BlsSet> = (0..4).flat_map(one).collect();
    assert_eq!(bls_outcomes(&mut h, all, Gossip).await, [VALID; 4]);
}

#[tokio::test]
async fn builder_feed_lag_has_its_own_series() {
    use prometheus_client::encoding::text::encode;
    let mut h = start().await;
    let (mut feed, _) = builder_open(&mut h).await;
    let mut frame = builder_frame(0, [0]);
    (frame.feed_finalized_epoch, frame.chain_finalized_epoch) = (95, 100);
    assert_eq!(builder_apply(&mut feed, frame).await, (1, None));
    let mut text = String::new();
    encode(&mut text, h.server.metrics_registry()).unwrap();
    assert!(
        text.contains("\nverify_pubkey_feed_lag_alert{namespace=\"builder\"} 1\n"),
        "{text}"
    );
    assert!(
        text.contains("\nverify_pubkey_feed_lag_alert{namespace=\"validator\"} 0\n"),
        "{text}"
    );
    // Finality never moves back: refused in-band, nothing applied.
    let mut back = builder_frame(1, [1]);
    (back.feed_finalized_epoch, back.chain_finalized_epoch) = (95, 99);
    assert_eq!(
        builder_apply(&mut feed, back).await,
        (1, Some(ErrorCode::ContractViolation))
    );
    assert_eq!(h.server.contract_violations(), 1);
}

#[tokio::test]
async fn an_older_builder_feed_stream_never_overwrites_a_newer_one() {
    const NEWER: u64 = 50;
    let mut h = start().await;
    let at = |mut f: cl_verify::proto::verify::BuilderKeyFeedRequestBody, epoch| {
        (f.feed_finalized_epoch, f.chain_finalized_epoch) = (epoch, epoch);
        f
    };
    let (mut older, _) = builder_open(&mut h).await;
    assert_eq!(
        builder_apply(&mut older, at(builder_frame(0, 0..2), 3)).await,
        (2, None)
    );
    // A newer stream (a reconnect) feeds a newer finalized registry: index 0 was reused.
    let (mut newer, first) = builder_open(&mut h).await;
    assert_eq!(first, 2);
    assert_eq!(
        builder_apply(&mut newer, at(builder_frame(0, [NEWER]), 4)).await,
        (2, None)
    );
    // A late frame of the older stream, at the same finality, carries the old key of index 0.
    older.send(builder_body(at(builder_frame(0, [0]), 4))).await;
    assert_eq!(
        older.expect_failure().await.code(),
        ErrorCode::ResourceUnavailable,
        "the older stream is fenced"
    );
    let reused = |key| builder_set(builder_signer(0, key, false), key, 1);
    assert_eq!(
        bls_outcomes(&mut h, vec![reused(NEWER), reused(0)], Gossip).await,
        [VALID, UNKNOWN],
        "the newer key stays"
    );
    // The newer stream goes on.
    assert_eq!(
        builder_apply(&mut newer, at(builder_frame(2, [2]), 4)).await,
        (3, None)
    );
}

#[tokio::test]
async fn an_unknown_namespace_signer_is_ignored_per_set_on_either_origin() {
    let mut h = start().await;
    rebuild_over_feed(&mut h, 2, 2).await;
    let mut unknown = builder_set(builder_signer(1, 1, true), 1, 1);
    unknown.signers[0].namespace = 99;
    unknown.signers[0].inline_pubkey = pk_bytes(1);
    for origin in [Gossip, Import] {
        assert_eq!(
            bls_outcomes(&mut h, vec![unknown.clone(), valid_set(1, 2)], origin).await,
            [Err(ErrorCode::VersionMismatch), VALID]
        );
    }
}
