//! Signer eligibility: what `cl-verify` decides about a signer before any BLS work.

use cl_verify_cache::{
    split_import_batch, IgnoreReason, KeySource, Lookup, Origin, PubkeyCache, Resolution, Signer,
    Violation, MAX_INLINE_KEYS_PER_BATCH, MAX_SETS_PER_BATCH,
};
use proptest::prelude::*;

/// Finalized registry `0..n`, key of index `i` is `i * 10`.
fn finalized(n: u64) -> PubkeyCache<u64> {
    let mut c = PubkeyCache::new();
    c.append_range(0, (0..n).map(|i| i * 10).collect()).unwrap();
    c
}

/// Stand-in for a verify call: BLS runs only on a resolved key, and the counter records each run.
fn verify(
    cache: &PubkeyCache<u64>,
    signer: &Signer<u64>,
    origin: Origin,
    bls_runs: &mut u32,
) -> Result<u64, String> {
    match cache.resolve_signer(signer, origin) {
        Resolution::Resolved(key) => {
            *bls_runs += 1;
            Ok(*key.key())
        }
        Resolution::Ignore(reason) => Err(format!("ignore: {reason:?}")),
        Resolution::ContractViolation(v) => Err(format!("violation: {v}")),
    }
}

#[test]
fn gossip_signer_past_finalized_registry_is_ignored_before_bls() {
    let cache = finalized(3);
    let mut bls_runs = 0;
    for index in [3, 4, u64::MAX] {
        assert_eq!(
            cache.resolve_signer(&Signer::Validator(index), Origin::Gossip),
            Resolution::Ignore(IgnoreReason::UnknownIndex { index })
        );
        assert!(verify(
            &cache,
            &Signer::Validator(index),
            Origin::Gossip,
            &mut bls_runs
        )
        .is_err());
    }
    assert_eq!(bls_runs, 0, "no BLS work for an unknown index");
}

#[test]
fn active_validator_resolves_from_cache_on_gossip() {
    // phase0 `is_eligible_for_activation`: activation needs `activation_eligibility_epoch <=
    // finalized_checkpoint.epoch`, so every active validator's index is in the finalized prefix.
    let cache = finalized(3);
    let resolved = cache.resolve_signer(&Signer::Validator(2), Origin::Gossip);
    let Resolution::Resolved(key) = resolved else {
        panic!("expected a cached key, got {resolved:?}");
    };
    assert_eq!(*key.key(), 20);
    assert_eq!(key.source(), KeySource::Cache);
}

#[test]
fn validator_past_high_water_on_import_is_ignored() {
    let cache = finalized(3);
    assert_eq!(
        cache.resolve_signer(&Signer::Validator(3), Origin::Import),
        Resolution::Ignore(IgnoreReason::UnknownIndex { index: 3 })
    );
}

#[test]
fn inline_key_on_gossip_is_a_contract_violation() {
    let cache = finalized(3);
    for index in [1, 3, 9] {
        assert_eq!(
            cache.resolve_signer(&Signer::Inline { index, key: 7 }, Origin::Gossip),
            Resolution::ContractViolation(Violation::InlineOnGossip { index })
        );
    }
}

#[test]
fn inline_key_past_high_water_is_used_on_import_only() {
    let cache = finalized(3);
    let mut bls_runs = 0;
    for index in [3, 4, 1_000] {
        let signer = Signer::Inline { index, key: 777 };
        let resolved = cache.resolve_signer(&signer, Origin::Import);
        let Resolution::Resolved(key) = resolved else {
            panic!("expected the inline key, got {resolved:?}");
        };
        assert_eq!(*key.key(), 777);
        assert_eq!(key.source(), KeySource::Inline);
        assert_eq!(
            verify(&cache, &signer, Origin::Import, &mut bls_runs),
            Ok(777)
        );
        assert!(verify(&cache, &signer, Origin::Gossip, &mut bls_runs).is_err());
    }
    assert_eq!(bls_runs, 3, "BLS ran only for the import calls");
    assert_eq!(cache.high_water(), 3, "inline keys never enter the cache");
}

#[test]
fn inline_key_for_cached_index_is_a_contract_violation() {
    let cache = finalized(3);
    // Both a conflicting and an identical key: an inline key for a cached index is never valid.
    for (index, key) in [(0, 999), (2, 20)] {
        assert_eq!(
            cache.resolve_signer(&Signer::Inline { index, key }, Origin::Import),
            Resolution::ContractViolation(Violation::InlineForCachedIndex { index })
        );
    }
}

#[test]
fn empty_cache_resolves_nothing_from_cache() {
    let cache = finalized(0);
    assert_eq!(
        cache.resolve_signer(&Signer::Validator(0), Origin::Gossip),
        Resolution::Ignore(IgnoreReason::UnknownIndex { index: 0 })
    );
    assert!(matches!(
        cache.resolve_signer(&Signer::Inline { index: 0, key: 1 }, Origin::Import),
        Resolution::Resolved(_)
    ));
}

#[test]
fn violations_name_the_index() {
    assert_eq!(
        Violation::InlineOnGossip { index: 5 }.to_string(),
        "validator 5 carries an inline pubkey on gossip"
    );
    assert_eq!(
        Violation::InlineForCachedIndex { index: 2 }.to_string(),
        "validator 2 carries an inline pubkey but is already cached"
    );
}

#[test]
fn signer_reports_its_index_and_whether_it_is_inline() {
    assert_eq!(Signer::<u64>::Validator(4).index(), 4);
    assert!(!Signer::<u64>::Validator(4).is_inline());
    assert_eq!(
        Signer::Inline {
            index: 6,
            key: 1u64
        }
        .index(),
        6
    );
    assert!(Signer::Inline {
        index: 6,
        key: 1u64
    }
    .is_inline());
}

proptest! {
    /// Against a model of the rules: never a key for an unknown index without an inline key, never
    /// an inline key on gossip, and a cached key only ever equals the cached entry.
    #[test]
    fn resolution_matches_the_rules(
        n in 0u64..20,
        index in 0u64..40,
        inline in proptest::option::of(any::<u64>()),
        gossip in any::<bool>(),
    ) {
        let cache = finalized(n);
        let origin = if gossip { Origin::Gossip } else { Origin::Import };
        let signer = match inline {
            Some(key) => Signer::Inline { index, key },
            None => Signer::Validator(index),
        };
        let got = cache.resolve_signer(&signer, origin);
        match (inline, gossip, index < n) {
            (None, _, true) => match got {
                Resolution::Resolved(key) => {
                    prop_assert_eq!(cache.get(index), Lookup::Known(key.key()));
                    prop_assert_eq!(key.source(), KeySource::Cache);
                }
                other => prop_assert!(false, "expected cached key, got {:?}", other),
            },
            (None, _, false) => {
                prop_assert_eq!(got, Resolution::Ignore(IgnoreReason::UnknownIndex { index }));
            }
            (Some(_), true, _) => {
                prop_assert_eq!(got, Resolution::ContractViolation(Violation::InlineOnGossip { index }));
            }
            (Some(_), false, true) => prop_assert_eq!(
                got,
                Resolution::ContractViolation(Violation::InlineForCachedIndex { index })
            ),
            (Some(k), false, false) => match got {
                Resolution::Resolved(key) => {
                    prop_assert_eq!(*key.key(), k);
                    prop_assert_eq!(key.source(), KeySource::Inline);
                }
                other => prop_assert!(false, "expected inline key, got {:?}", other),
            },
        }
    }
}

// --- Import batch splitting ---

/// One signature set's signers, as an import item.
type Set = Vec<Signer<u64>>;

/// A set of `n` inline signers; `tag` keeps sets distinguishable for order checks.
fn inline_set(tag: u64, n: u64) -> Set {
    (0..n)
        .map(|i| Signer::Inline {
            index: 100 + tag * 10_000 + i,
            key: tag,
        })
        .collect()
}

/// A set of one cached signer: no inline keys.
fn cached_set(tag: u64) -> Set {
    vec![Signer::Validator(tag)]
}

fn inline_weight(set: &Set) -> usize {
    set.iter().filter(|s| s.is_inline()).count()
}

#[test]
fn empty_input_returns_no_batches() {
    let batches = split_import_batch(Vec::<Set>::new(), inline_weight);
    assert!(batches.is_empty());
}

#[test]
fn split_boundary() {
    assert_eq!(MAX_INLINE_KEYS_PER_BATCH, 1_024);

    // 4 sets of 256 inline signers: 1,024 inline keys, one batch.
    let at_cap: Vec<Set> = (0..4).map(|t| inline_set(t, 256)).collect();
    let batches = split_import_batch(at_cap.clone(), inline_weight);
    assert_eq!(batches, vec![at_cap.clone()]);

    // One more inline key: 1,025 give two batches, 1,024 + 1, in input order.
    let mut over = at_cap;
    over.push(inline_set(4, 1));
    let batches = split_import_batch(over.clone(), inline_weight);
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].iter().map(inline_weight).sum::<usize>(), 1_024);
    assert_eq!(batches[1].iter().map(inline_weight).sum::<usize>(), 1);
    assert_eq!(batches.concat(), over);
}

#[test]
fn split_caps_sets_at_256() {
    assert_eq!(MAX_SETS_PER_BATCH, 256);

    let at_cap: Vec<Set> = (0..256).map(cached_set).collect();
    assert_eq!(
        split_import_batch(at_cap.clone(), inline_weight),
        vec![at_cap]
    );

    let over: Vec<Set> = (0..257).map(cached_set).collect();
    let batches = split_import_batch(over.clone(), inline_weight);
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0][..], over[..256]);
    assert_eq!(batches[1][..], over[256..]);
}

#[test]
fn whichever_cap_is_hit_first_closes_the_batch() {
    // Inline cap first: 3 sets reach 1,024 inline keys long before 256 sets.
    let inline_first: Vec<Set> = vec![inline_set(0, 1_000), inline_set(1, 24), inline_set(2, 1)];
    let batches = split_import_batch(inline_first.clone(), inline_weight);
    assert_eq!(
        batches,
        vec![inline_first[..2].to_vec(), inline_first[2..].to_vec()]
    );

    // Set cap first: 256 sets with 10 inline keys in total, then one more.
    let mut sets_first: Vec<Set> = (0..246).map(cached_set).collect();
    sets_first.extend((0..10).map(|t| inline_set(t, 1)));
    sets_first.push(inline_set(99, 1));
    let batches = split_import_batch(sets_first.clone(), inline_weight);
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0][..], sets_first[..256]);
    assert_eq!(batches[1][..], sets_first[256..]);
}

#[test]
fn cached_signers_do_not_count_towards_the_inline_cap() {
    // One set of 5,000 cached signers plus 1,024 inline ones is still a single batch.
    let mut set: Set = (0..5_000).map(Signer::Validator).collect();
    set.extend(inline_set(1, 1_024));
    let input = vec![cached_set(0), set];
    let batches = split_import_batch(input.clone(), inline_weight);
    assert_eq!(batches, vec![input]);
}

#[test]
fn item_over_the_cap_travels_alone() {
    // An indivisible item (e.g. one aggregate set) heavier than the cap is never rejected: it is
    // the only item of its batch.
    let weights = [1usize, 2_000, 1];
    let batches = split_import_batch(weights, |w| *w);
    assert_eq!(batches, vec![vec![1], vec![2_000], vec![1]]);
}

proptest! {
    #[test]
    fn split_preserves_order_and_respects_both_caps(
        // Mostly cached sets (the set cap binds), or heavy inline sets (the inline cap binds).
        weights in prop_oneof![
            proptest::collection::vec(0usize..2, 0..700),
            proptest::collection::vec(0usize..1_200, 0..60),
        ],
    ) {
        let items: Vec<(usize, usize)> = weights.iter().copied().enumerate().collect();
        let batches = split_import_batch(items.clone(), |(_, w)| *w);

        let flat: Vec<_> = batches.iter().flatten().copied().collect();
        prop_assert_eq!(&flat, &items, "concatenated batches equal the input");
        prop_assert_eq!(batches.is_empty(), items.is_empty());

        let total = |b: &[(usize, usize)]| b.iter().map(|(_, w)| w).sum::<usize>();
        for (i, batch) in batches.iter().enumerate() {
            prop_assert!(!batch.is_empty());
            prop_assert!(batch.len() <= MAX_SETS_PER_BATCH, "batch {} has {} items", i, batch.len());
            prop_assert!(
                total(batch) <= MAX_INLINE_KEYS_PER_BATCH || batch.len() == 1,
                "batch {} over the inline cap with {} items", i, batch.len()
            );
            if let Some(next) = batches.get(i + 1) {
                prop_assert!(
                    batch.len() == MAX_SETS_PER_BATCH
                        || total(batch) + next[0].1 > MAX_INLINE_KEYS_PER_BATCH,
                    "batch {} could have taken the next item", i
                );
            }
        }
    }
}
