//! Tests of the state advance of block import through the chain core.
//!
//! A block more than `PRE_STATE_EPOCHS` epochs of slots after the state of its parent needs the
//! empty slots between them. The core walks them on a copy of the parent state, from the best
//! start: the parent state, or a checkpoint of an earlier walk from the same parent. The walk
//! is at most eight epochs of slots, and it stops one slot before the block.
//!
//! Before the walk, the core checks the proposer signature: the key of `proposer_index` in the
//! parent state, and the proposer domain of the fork that the network schedule gives for the
//! epoch of the block. After the walk, the core checks that `proposer_index` is the proposer of
//! the block slot. It sends the proposer set again only if the key or the domain of the advanced
//! state is different. Then it imports the block on the advanced state.
//!
//! The blocks come from the pinned minimal export. A test moves a block to a later slot: it sets
//! the slot of the block and of its bid, and the proposer of that slot, and it removes the
//! attestations and the payload attestations. A local transition gives the state root of the
//! moved block. The fake cl-verify gives each verdict, so no signature is checked.
//!
//! In some tests, the caller of an import stops waiting for the answer. A hook drops the
//! receiver of the answer at a known point of the import. The test then waits for the writer
//! thread to stop, and reads the core.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod support;

use cl_chain::core::advance::Advanced;
use cl_chain::core::snapshot::PRE_STATE_EPOCHS;
use cl_chain::core::{
    queue, ChainCore, Head, Outcome, Served, MAX_ADVANCED_STATES, MAX_ADVANCE_EPOCHS,
};
use cl_chain::import::block::PermitAll;
use cl_chain::verify::client::{BlsOutcome, BlsVerifier, UnixClock};
use consensus_types::common::PendingDeposit;
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{BLSPubkey, Bytes32, Epoch, Root};
use consensus_types::signing::{compute_domain, DOMAIN_BEACON_PROPOSER};
use consensus_types::{EthSpec, Minimal};
use crypto_bls::{eth_aggregate_pubkeys, PublicKey};
use ethswarm_proto::verify::BlsSet;
use network_config::ChainConfig;
use state_transition::caches::proposer::get_beacon_proposer_index;
use state_transition::per_slot::process_slots;
use state_transition::{
    state_root, state_transition, AggregationError, BackendError, BlsContext, PubkeyAggregator,
    SignatureBackend, SignatureSet, StfError,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::{
    assert_unchanged, clock_at, export_block, fixture, import_one, proposer_set, proposer_set_in,
    slot_start, Answer, FakeVerify, Fixture, QUEUE, VERIFY_TIMEOUT,
};
use testkit::anchor::fixtures::{pinned_export, AnchorFiles};
use testkit::anchor::load_anchor;
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tree_hash::TreeHash;

/// The block type of the fixture.
type Block = SignedBeaconBlock<Minimal>;
/// The state type of the fixture.
type State = BeaconState<Minimal>;

/// The slots per epoch of the fixture.
fn epoch_slots() -> u64 {
    Minimal::slots_per_epoch()
}

/// The pre-state window of the core in slots. A block nearer to its parent state needs no walk.
fn window() -> u64 {
    PRE_STATE_EPOCHS * epoch_slots()
}

/// The most slots between the start of a walk and the block.
fn cap() -> u64 {
    MAX_ADVANCE_EPOCHS * epoch_slots()
}

fn root(byte: u8) -> Root {
    Root::repeat_byte(byte)
}

#[test]
fn the_walk_bounds_are_eight_epochs_and_sixty_four_states() {
    assert_eq!(MAX_ADVANCE_EPOCHS, 8);
    assert_eq!(cap(), 64);
    assert_eq!(MAX_ADVANCED_STATES, 64);
}

#[test]
fn the_latest_kept_state_is_of_the_parent_and_not_past_the_epoch() {
    let mut kept = Advanced::new(8);
    kept.insert(root(1), 1, 11u64);
    kept.insert(root(1), 3, 13);
    kept.insert(root(1), 5, 15);
    kept.insert(root(2), 4, 24);
    assert_eq!(kept.latest(&root(1), 4), Some(&13));
    assert_eq!(kept.latest(&root(1), 9), Some(&15));
    assert_eq!(kept.latest(&root(1), 0), None);
    assert_eq!(kept.latest(&root(2), 9), Some(&24));
    assert_eq!(kept.latest(&root(3), 9), None);
    assert_eq!(kept.peek(&root(1), 3), Some(&13));
    assert_eq!(kept.peek(&root(1), 4), None);
}

#[test]
fn the_kept_states_are_bounded_and_the_least_recent_goes_first() {
    let mut kept = Advanced::new(3);
    kept.insert(root(1), 1, 11u64);
    kept.insert(root(1), 2, 12);
    kept.insert(root(2), 1, 21);
    // A start of a walk makes the state the most recent.
    assert_eq!(kept.latest(&root(1), 1), Some(&11));
    kept.insert(root(3), 1, 31);
    assert_eq!(kept.len(), 3, "the bound must hold");
    assert_eq!(
        kept.peek(&root(1), 2),
        None,
        "the least recent must go first"
    );
    assert_eq!(kept.peek(&root(1), 1), Some(&11));
    assert_eq!(kept.peek(&root(2), 1), Some(&21));
    // A peek does not change the order of use.
    assert_eq!(kept.peek(&root(2), 1), Some(&21));
    kept.insert(root(4), 1, 41);
    assert_eq!(kept.peek(&root(2), 1), None);
    // An insert of a kept key replaces it, and the bound holds.
    kept.insert(root(4), 1, 42);
    assert_eq!(kept.len(), 3);
    assert_eq!(kept.peek(&root(4), 1), Some(&42));
    for byte in 5..40 {
        kept.insert(root(byte), 1, u64::from(byte));
    }
    assert_eq!(kept.len(), 3);
    assert_eq!(kept.peek(&root(39), 1), Some(&39), "the newest must stay");
    assert!(!kept.is_empty());
    assert_eq!(Advanced::<u64>::new(0).len(), 0);
}

/// The wall clock of the fixture chain.
struct Wall {
    genesis_ms: u128,
    slot_ms: u128,
}

impl Wall {
    fn of(f: &Fixture) -> Self {
        let genesis_ms = slot_start(f, 0);
        Self {
            genesis_ms,
            slot_ms: slot_start(f, 1) - genesis_ms,
        }
    }

    /// A clock at the start of `slot`.
    fn at(&self, slot: u64) -> UnixClock {
        clock_at(self.genesis_ms + u128::from(slot) * self.slot_ms)
    }
}

/// A local transition has no deposit verdict. The fixture states have no pending deposit.
struct NoVerdicts;

impl SignatureBackend for NoVerdicts {
    fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
        Err(BackendError("a local transition has no verdict".into()))
    }
}

/// `eth_aggregate_pubkeys` for the next sync committee, as in the core.
struct Aggregate;

impl PubkeyAggregator for Aggregate {
    fn aggregate_pubkeys(&self, pubkeys: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError> {
        let keys = pubkeys
            .iter()
            .map(PublicKey::from_validated_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AggregationError(e.to_string()))?;
        let refs: Vec<&PublicKey> = keys.iter().collect();
        eth_aggregate_pubkeys(&refs)
            .map(|sum| sum.to_bytes())
            .map_err(|e| AggregationError(e.to_string()))
    }
}

/// Runs `f` with the BLS context of a local transition on the network of `config`.
fn local<R>(config: &ChainConfig, f: impl FnOnce(&BlsContext) -> R) -> R {
    let schedule = |epoch: Epoch| config.get_blob_parameters(epoch).max_blobs_per_block;
    let bls = BlsContext {
        backend: &NoVerdicts,
        aggregator: &Aggregate,
        genesis_fork_version: config.genesis_fork_version(),
        capella_fork_version: config.capella_fork_version().unwrap(),
        blob_schedule: &schedule,
    };
    f(&bls)
}

/// `parent`, the post-state of a block, after `process_slots` to `slot`.
fn advanced(parent: &State, slot: u64, config: &ChainConfig) -> State {
    let mut state = parent.clone();
    local(config, |bls| process_slots(&mut state, slot, bls)).unwrap();
    state
}

/// `template` moved to `slot` on `parent`, the post-state of the parent of `template`. The
/// block has the proposer of `slot` and the state root of its post-state. Also returns
/// `parent` advanced to the slot before `slot`: the state of the proposer check.
fn moved(template: &Block, parent: &State, slot: u64, config: &ChainConfig) -> (Block, State) {
    let mut block = template.clone();
    block.message.slot = slot;
    block.message.body.signed_execution_payload_bid.message.slot = slot;
    block.message.body.attestations = vec![].try_into().unwrap();
    block.message.body.payload_attestations = vec![].try_into().unwrap();
    let before = advanced(parent, slot - 1, config);
    let at = advanced(&before, slot, config);
    block.message.proposer_index = get_beacon_proposer_index(&at).unwrap();
    let mut post = parent.clone();
    local(config, |bls| {
        state_transition(&mut post, &block, false, bls)
    })
    .expect("the moved block must apply");
    block.message.state_root = state_root(&mut post).unwrap();
    (block, before)
}

/// The head of a committed `block`.
fn head_of(block: &Block) -> Head {
    Head {
        block_root: block.message.tree_hash_root(),
        slot: block.message.slot,
        state_root: block.message.state_root,
    }
}

/// The committed outcome of `block`.
fn committed(block: &Block) -> Outcome {
    Outcome::Committed {
        block_root: block.message.tree_hash_root(),
        state_root: block.message.state_root,
    }
}

/// The anchor state of the fixture.
fn anchor_state(f: &Fixture) -> State {
    f.core.state(&f.anchor.block_root).unwrap().clone()
}

/// The proposer set that the core sends before the walk: the key of `proposer_index` in
/// `parent`, and the proposer domain of the fork that the network schedule of `config` gives for
/// the epoch of the block, with the genesis validators root of `parent`.
fn early_set(parent: &State, block: &Block, config: &ChainConfig) -> BlsSet {
    let schedule = config.fork_schedule();
    let fork = schedule
        .fork_at(Minimal::epoch_at_slot(block.message.slot))
        .expect("the fixture network has a fork at each epoch");
    let domain = compute_domain(
        DOMAIN_BEACON_PROPOSER,
        schedule.fork_version(fork),
        parent.genesis_validators_root,
    );
    proposer_set_in(parent, block, domain)
}

#[tokio::test]
async fn a_valid_block_past_the_pre_state_window_commits() {
    for slot in [window() + 1, 40, cap()] {
        let f = fixture();
        let wall = Wall::of(&f);
        let (block, _) = moved(&f.block, &anchor_state(&f), slot, &f.config);
        let core = f.core.with_clock(wall.at(slot));
        let (outcome, core, verify) = import_one(core, block.clone(), Answer::Valid).await;
        assert_eq!(outcome, committed(&block), "slot {slot}");
        assert_eq!(
            verify.calls().len(),
            2,
            "slot {slot}: the proposer set must go to cl-verify first, then the block sets"
        );
        assert_eq!(core.head(), head_of(&block), "slot {slot}");
        assert_eq!(
            core.pre_states(),
            2,
            "slot {slot}: the anchor and the post-state"
        );
    }
}

#[tokio::test]
async fn a_child_of_a_committed_block_past_the_window_commits() {
    let f = fixture();
    let wall = Wall::of(&f);
    let first = f.block.clone();
    let first_root = first.message.tree_hash_root();
    let (outcome, core, _) = import_one(f.core.with_clock(wall.at(1)), first, Answer::Valid).await;
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
    let parent = core.state(&first_root).unwrap().clone();
    let slot = parent.slot + window() + 13;
    let (child, _) = moved(&export_block(2), &parent, slot, &f.config);
    assert_eq!(child.message.parent_root, first_root);
    let (outcome, core, verify) =
        import_one(core.with_clock(wall.at(slot)), child.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&child));
    assert_eq!(verify.calls().len(), 2);
    assert_eq!(core.head(), head_of(&child));
    assert_eq!(
        core.pre_states(),
        3,
        "the anchor, the slot 1 block and the child"
    );
}

#[tokio::test]
async fn the_walk_keeps_the_state_at_the_end_of_each_epoch_that_it_reaches() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let slot = 5 * epoch_slots() + 1;
    let (block, _) = moved(&f.block, &anchor, slot, &f.config);
    let (outcome, core, _) = import_one(
        f.core.with_clock(wall.at(slot)),
        block.clone(),
        Answer::Valid,
    )
    .await;
    assert_eq!(outcome, committed(&block));
    // The walk stops at slot 40, the slot before the block. It keeps the state at the last
    // slot of each epoch from 0 to 4, by the epoch after it.
    for epoch in 1..=5 {
        let last_slot = epoch * epoch_slots() - 1;
        let mut kept = core
            .advanced_state(&f.anchor.block_root, epoch)
            .unwrap_or_else(|| panic!("the walk must keep the state at slot {last_slot}"))
            .clone();
        assert_eq!(kept.slot, last_slot);
        let mut expected = advanced(&anchor, last_slot, &f.config);
        assert_eq!(
            state_root(&mut kept).unwrap(),
            state_root(&mut expected).unwrap(),
            "the state at slot {last_slot} must be the anchor state after process_slots"
        );
    }
    assert!(
        core.advanced_state(&f.anchor.block_root, 6).is_none(),
        "the walk must stop before the block"
    );
}

/// The first import is past the cap from the anchor, so the core does not walk. The second
/// import walks from the anchor and keeps a state near the end of its walk. From that state,
/// the first block is within the cap, so it now commits.
#[tokio::test]
async fn a_later_import_starts_from_a_kept_state_of_its_parent() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let late_slot = cap() + 2;
    let early_slot = cap() - 4;
    let (late, _) = moved(&f.block, &anchor, late_slot, &f.config);
    let (early, _) = moved(&f.block, &anchor, early_slot, &f.config);
    let late_root = late.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(late_slot));

    let (outcome, core, verify) = import_one(core, late.clone(), Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "a block past the cap from its parent state must be IGNORE: {outcome:?}"
    );
    assert!(
        verify.calls().is_empty(),
        "the block must not reach cl-verify"
    );
    assert!(
        !core.is_refused(&late_root),
        "the core must not keep the refusal of a block past the cap"
    );
    assert!(
        core.advanced_state(&f.anchor.block_root, 1).is_none(),
        "a block past the cap must not start a walk"
    );

    let (outcome, core, _) = import_one(core, early.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&early));
    let last_epoch = early_slot / epoch_slots();
    let kept = core
        .advanced_state(&f.anchor.block_root, last_epoch)
        .expect("the walk must keep the state at the end of its last full epoch");
    assert!(late_slot - kept.slot <= cap());

    let (outcome, core, verify) = import_one(core, late.clone(), Answer::Valid).await;
    assert_eq!(
        outcome,
        committed(&late),
        "the walk must start from the kept state"
    );
    assert_eq!(verify.calls().len(), 2);
    assert_eq!(core.head(), head_of(&late));
}

#[tokio::test]
async fn a_bad_proposer_signature_of_a_far_block_is_invalid_before_the_walk() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let slot = window() + 4;
    let (block, _) = moved(&f.block, &anchor, slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(slot));
    let verify = FakeVerify::new(Answer::Invalid);
    let watched = import_watched(
        core,
        block.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert_eq!(
        watched.outcome,
        Some(Outcome::Invalid(StfError::InvalidBlockSignature))
    );
    assert_eq!(
        verify.calls(),
        vec![vec![early_set(&anchor, &block, &f.config)]],
        "only the proposer set of the parent state must go to cl-verify"
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    let core = watched.core;
    assert!(
        core.advanced_state(&f.anchor.block_root, 1).is_none(),
        "the core must not keep a state of a walk"
    );
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        core.is_refused(&block_root),
        "the core must keep the refusal of the signature"
    );

    // The refusal holds for that signature only.
    let mut signed_again = block.clone();
    signed_again.signature[10] ^= 0x01;
    let (outcome, _, _) = import_one(core, signed_again, Answer::Valid).await;
    assert_eq!(outcome, committed(&block));
}

#[tokio::test]
async fn a_proposer_past_the_parent_registry_is_ignored_before_the_walk_and_not_kept() {
    let f = fixture();
    let validators = anchor_state(&f).validators.len();
    let first_out = u64::try_from(validators).unwrap();
    for proposer in [first_out, u64::MAX] {
        let f = fixture();
        let wall = Wall::of(&f);
        let slot = window() + 4;
        let mut block = f.block.clone();
        block.message.slot = slot;
        block.message.proposer_index = proposer;
        let block_root = block.message.tree_hash_root();
        let core = f.core.with_clock(wall.at(slot));
        let verify = FakeVerify::new(Answer::Valid);
        let watched = import_watched(
            core,
            block,
            Arc::clone(&verify),
            &verify,
            &Waiting::default(),
            None,
        )
        .await;
        assert!(
            matches!(watched.outcome, Some(Outcome::Ignored(_))),
            "{proposer}: a later parent state can have a longer registry: {:?}",
            watched.outcome
        );
        assert!(
            verify.calls().is_empty(),
            "{proposer}: the block must not reach cl-verify"
        );
        assert!(
            watched.walk.is_empty(),
            "{proposer}: the core must not start the walk"
        );
        let core = watched.core;
        assert!(core.advanced_state(&f.anchor.block_root, 1).is_none());
        assert_unchanged(&core, f.anchor, block_root);
        assert!(
            !core.is_refused(&block_root),
            "{proposer}: the core must not keep the refusal"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_missing_proposer_verdict_before_the_walk_is_ignored_and_not_kept() {
    for answer in [Answer::Never, Answer::Late, Answer::AtDeadline] {
        let f = fixture();
        let wall = Wall::of(&f);
        let anchor = anchor_state(&f);
        let slot = window() + 4;
        let (block, _) = moved(&f.block, &anchor, slot, &f.config);
        let block_root = block.message.tree_hash_root();
        let core = f.core.with_clock(wall.at(slot));
        let (outcome, core, verify) = import_one(core, block.clone(), answer).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "{answer:?}: {outcome:?}"
        );
        assert_eq!(
            verify.calls(),
            vec![vec![early_set(&anchor, &block, &f.config)]],
            "{answer:?}: only the proposer set must go to cl-verify"
        );
        assert!(
            core.advanced_state(&f.anchor.block_root, 1).is_none(),
            "{answer:?}: the core must not walk without a proposer verdict"
        );
        assert_unchanged(&core, f.anchor, block_root);
        assert!(!core.is_refused(&block_root), "{answer:?}");
        let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
        assert_eq!(
            outcome,
            committed(&block),
            "{answer:?}: the block must be able to come again"
        );
    }
}

/// The walk hook of an import from the anchor to the slot before a block at slot 20: before the
/// walk, at the end of epochs 0 and 1, and after the walk. Each entry also has the number of
/// cl-verify calls before that hook call. `calls` is that number for each entry.
fn walk_to_slot_19(calls: usize) -> Vec<(u64, usize)> {
    vec![
        (0, calls),
        (epoch_slots() - 1, calls),
        (2 * epoch_slots() - 1, calls),
        (window() + 3, calls),
    ]
}

#[tokio::test]
async fn a_valid_far_block_sends_its_proposer_set_once_before_the_walk() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let slot = window() + 4;
    let (block, before) = moved(&f.block, &anchor, slot, &f.config);
    let core = f.core.with_clock(wall.at(slot));
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        block.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert_eq!(watched.outcome, Some(committed(&block)));
    assert_eq!(
        watched.walk,
        walk_to_slot_19(1),
        "the proposer set must go to cl-verify before the walk, and no set during the walk"
    );
    let calls = verify.calls();
    assert_eq!(
        calls.len(),
        2,
        "the proposer set before the walk, then the block sets: no second proposer call"
    );
    assert_eq!(calls[0], vec![early_set(&anchor, &block, &f.config)]);
    assert_eq!(
        early_set(&anchor, &block, &f.config),
        proposer_set(&before, &block),
        "the key and the domain of the advanced state are the same"
    );
    assert!(
        calls[1].len() > 1,
        "the second call must hold the block sets"
    );
    assert_eq!(watched.core.head(), head_of(&block));
}

/// `block` with `proposer_index` set to another validator than the proposer of its slot. The
/// state root is not correct for it, but the core refuses the block before the transition.
fn other_proposer(block: &Block, validators: usize) -> Block {
    let mut other = block.clone();
    let count = u64::try_from(validators).unwrap();
    other.message.proposer_index = (block.message.proposer_index + 1) % count;
    other
}

#[tokio::test]
async fn a_signed_far_block_of_another_proposer_is_wrong_proposer_after_the_walk() {
    // Slot 20 is in the middle of epoch 2. Slot 24 opens epoch 3: the advanced state is at the
    // last slot of epoch 2, and its lookahead holds the proposers of epoch 3 after those of
    // epoch 2.
    for slot in [window() + 4, 3 * epoch_slots()] {
        let f = fixture();
        let wall = Wall::of(&f);
        let anchor = anchor_state(&f);
        let (valid, _) = moved(&f.block, &anchor, slot, &f.config);
        let expected = valid.message.proposer_index;
        let block = other_proposer(&valid, anchor.validators.len());
        let claimed = block.message.proposer_index;
        let block_root = block.message.tree_hash_root();
        let core = f.core.with_clock(wall.at(slot));
        let verify = FakeVerify::new(Answer::Valid);
        let watched = import_watched(
            core,
            block.clone(),
            Arc::clone(&verify),
            &verify,
            &Waiting::default(),
            None,
        )
        .await;
        assert_eq!(
            watched.outcome,
            Some(Outcome::Invalid(StfError::WrongProposer {
                block: claimed,
                expected,
            })),
            "slot {slot}"
        );
        assert_eq!(
            verify.calls(),
            vec![vec![early_set(&anchor, &block, &f.config)]],
            "slot {slot}: only the proposer set before the walk must go to cl-verify"
        );
        let last = watched.walk.last().copied();
        assert_eq!(
            watched.walk.first().copied(),
            Some((0, 1)),
            "slot {slot}: the walk must start after the proposer set"
        );
        assert_eq!(last, Some((slot - 1, 1)), "slot {slot}");
        let core = watched.core;
        assert_unchanged(&core, f.anchor, block_root);
        assert!(core.is_refused(&block_root), "slot {slot}");

        // The signature was valid, so the refusal holds for each signature.
        let mut signed_again = block.clone();
        signed_again.signature[10] ^= 0x01;
        let (outcome, _, verify) = import_one(core, signed_again, Answer::Valid).await;
        assert_eq!(
            outcome,
            Outcome::Invalid(StfError::WrongProposer {
                block: claimed,
                expected,
            }),
            "slot {slot}"
        );
        assert!(verify.calls().is_empty(), "slot {slot}");
    }
}

/// The fixture with another fork version in the anchor state. The network schedule does not
/// change, so the proposer domain of the advanced state is not the domain of the schedule.
fn other_fork_fixture() -> Fixture {
    anchor_with(|state| state.fork.current_version = [0x07, 0, 0, 0x42])
}

#[tokio::test]
async fn a_far_block_is_verified_again_when_the_advanced_domain_is_different() {
    let f = other_fork_fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let slot = window() + 4;
    let (block, before) = moved(&f.block, &anchor, slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let early = early_set(&anchor, &block, &f.config);
    let again = proposer_set(&before, &block);
    assert_ne!(early, again, "the two domains must be different");

    let core = f.core.with_clock(wall.at(slot));
    let verify = FakeVerify::answers(vec![Answer::Valid, Answer::Invalid]);
    let (outcome, core) = support::import_with(core, block.clone(), Arc::clone(&verify)).await;
    assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
    assert_eq!(
        verify.calls(),
        vec![vec![early.clone()], vec![again.clone()]],
        "the proposer set of the parent state, then of the advanced state"
    );
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        core.is_refused(&block_root),
        "the core must keep the refusal of the signature"
    );

    let mut signed_again = block.clone();
    signed_again.signature[10] ^= 0x01;
    let (outcome, _, verify) = import_one(core, signed_again, Answer::Valid).await;
    assert_eq!(outcome, committed(&block));
    let calls = verify.calls();
    assert_eq!(calls.len(), 3, "two proposer calls, then the block sets");
    assert_eq!(calls[1].len(), 1);
}

#[tokio::test]
async fn a_deadline_before_the_walk_is_ignored_and_not_kept() {
    let f = fixture();
    let wall = Wall::of(&f);
    let slot = window() + 4;
    let (block, _) = moved(&f.block, &anchor_state(&f), slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let core = f
        .core
        .with_clock(wall.at(slot))
        .with_verify_timeout(Duration::ZERO);
    let (outcome, core, verify) = import_one(core, block.clone(), Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "an import without time must be IGNORE: {outcome:?}"
    );
    assert!(verify.calls().is_empty());
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal of a walk out of time"
    );
    assert!(
        core.advanced_state(&f.anchor.block_root, 1).is_none(),
        "a walk out of time before it starts keeps no state"
    );

    let core = core.with_verify_timeout(VERIFY_TIMEOUT);
    let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
    assert_eq!(
        outcome,
        committed(&block),
        "the block must be able to come again"
    );
}

/// The fixture with an anchor state that `edit` changed. The anchor block gets the new state
/// root, and the slot 1 block has the new anchor as its parent.
fn anchor_with(edit: impl FnOnce(&mut State)) -> Fixture {
    let pinned = pinned_export().expect("the pinned export must open");
    let dir = tempfile::tempdir().unwrap();
    AnchorFiles::genesis(&pinned.export)
        .unwrap()
        .write(dir.path())
        .unwrap();
    let loaded = load_anchor::<Minimal>(dir.path()).expect("the anchor must load");
    let (mut state, mut block) = loaded.into_parts();
    edit(&mut state);
    block.message.state_root = state_root(&mut state).unwrap();
    let anchor = head_of(&block);
    let core = ChainCore::from_anchor(state, block, pinned.config.clone())
        .expect("the anchor must install")
        .with_verify_timeout(VERIFY_TIMEOUT)
        .with_payload_gate(PermitAll);
    let mut child = export_block(1);
    child.message.parent_root = anchor.block_root;
    child
        .message
        .body
        .signed_execution_payload_bid
        .message
        .parent_block_root = anchor.block_root;
    Fixture {
        core,
        anchor,
        block: child,
        config: pinned.config,
    }
}

/// The fixture with a pending deposit of a new key in the anchor state. The first epoch
/// boundary after the anchor applies it. verify.v1 has no signer for a key that is not in the
/// registry, so the core has no verdict for that deposit.
fn deposit_fixture() -> Fixture {
    anchor_with(|state| {
        assert!(state.pending_deposits.is_empty());
        let mut credentials = [0u8; 32];
        credentials[0] = 0x01;
        state
            .pending_deposits
            .push(PendingDeposit {
                pubkey: [0x42; 48],
                withdrawal_credentials: Bytes32::from(credentials),
                amount: 1_000_000_000,
                signature: [0x24; 96],
                slot: 0,
            })
            .unwrap();
    })
}

#[tokio::test]
async fn a_missing_deposit_verdict_in_the_walk_is_ignored_and_keeps_the_state_before_it() {
    let f = deposit_fixture();
    let wall = Wall::of(&f);
    let slot = window() + 4;
    let mut block = f.block.clone();
    block.message.slot = slot;
    let block_root = block.message.tree_hash_root();
    let expected = early_set(&anchor_state(&f), &block, &f.config);
    let core = f.core.with_clock(wall.at(slot));
    let (outcome, core, verify) = import_one(core, block, Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "a walk without a deposit verdict must be IGNORE: {outcome:?}"
    );
    assert_eq!(
        verify.calls(),
        vec![vec![expected]],
        "only the proposer set before the walk must go to cl-verify: no deposit set"
    );
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal of a walk without a verdict"
    );
    let kept = core
        .advanced_state(&f.anchor.block_root, 1)
        .expect("the walk must keep the state before the boundary of the deposit");
    assert_eq!(kept.slot, epoch_slots() - 1);
    assert!(
        core.advanced_state(&f.anchor.block_root, 2).is_none(),
        "the walk must not keep a state past the boundary of the deposit"
    );
}

/// The receiver of the answer to one import. A hook drops it: then the caller of the import
/// does not wait for the answer.
#[derive(Clone, Default)]
struct Waiting(Arc<Mutex<Option<oneshot::Receiver<Served>>>>);

impl Waiting {
    /// Drops the receiver, if it is still there.
    fn stop(&self) {
        drop(self.0.lock().unwrap().take());
    }
}

/// A fake cl-verify that gives the answers of `inner`. At the end of call `on_call` (1 is the
/// first call), the caller of the import stops waiting. The other calls do not drop the
/// receiver.
struct StopsWaiting {
    inner: Arc<FakeVerify>,
    waiting: Waiting,
    on_call: usize,
}

impl BlsVerifier for StopsWaiting {
    async fn verify_sets(&self, sets: Vec<BlsSet>, deadline: Instant) -> BlsOutcome {
        let outcome = self.inner.verify_sets(sets, deadline).await;
        // The core waits for each call, so the calls do not overlap.
        if self.inner.called().len() == self.on_call {
            self.waiting.stop();
        }
        outcome
    }
}

/// What a watched import did.
struct Watched {
    /// The answer of the core, or `None` if a hook dropped the receiver.
    outcome: Option<Outcome>,
    /// The core after its writer thread stops.
    core: ChainCore<Minimal>,
    /// Each call of the walk hook, in order: the slot of the walk state, and the number of
    /// cl-verify calls before it.
    walk: Vec<(u64, usize)>,
}

impl Watched {
    /// The slot of each call of the walk hook, in order.
    fn slots(&self) -> Vec<u64> {
        self.walk.iter().map(|(slot, _)| *slot).collect()
    }
}

/// Imports `block` on `core`, and sends its sets to `verifier`. `fake` is the fake cl-verify
/// that `verifier` uses. `waiting` holds the receiver of the answer. The walk hook of the core
/// records the slot of each call, and the number of calls of `fake` before it. At slot
/// `drop_at`, the hook drops the receiver. The test does not wait for the answer. It waits for
/// the writer thread to stop, and then reads the answer, if the receiver is still there.
async fn import_watched<V: BlsVerifier + 'static>(
    core: ChainCore<Minimal>,
    block: Block,
    verifier: Arc<V>,
    fake: &Arc<FakeVerify>,
    waiting: &Waiting,
    drop_at: Option<u64>,
) -> Watched {
    let walk: Arc<Mutex<Vec<(u64, usize)>>> = Arc::default();
    let hook = {
        let (walk, fake, waiting) = (Arc::clone(&walk), Arc::clone(fake), waiting.clone());
        move |slot| {
            walk.lock().unwrap().push((slot, fake.called().len()));
            if drop_at == Some(slot) {
                waiting.stop();
            }
        }
    };
    let (sender, queue) = queue::<Minimal>(QUEUE);
    // The item and its receiver are in place before the writer thread starts.
    let answer = sender
        .import(block)
        .expect("the import queue must have room");
    *waiting.0.lock().unwrap() = Some(answer);
    drop(sender);
    let writer = core
        .with_walk_hook(hook)
        .spawn(queue, verifier, Handle::current())
        .unwrap();
    // The writer thread can wait for a VerifyBls call on this runtime. The join must not block
    // the runtime.
    let core = tokio::task::spawn_blocking(move || writer.join())
        .await
        .unwrap()
        .expect("the writer thread must not panic");
    let outcome = (waiting.0.lock().unwrap().take())
        .map(|mut answer| answer.try_recv().expect("the core must answer").outcome);
    let walk = walk.lock().unwrap().clone();
    Watched {
        outcome,
        core,
        walk,
    }
}

#[tokio::test]
async fn an_import_whose_caller_stops_waiting_before_the_walk_is_ignored_and_not_kept() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let slot = window() + 4;
    let (block, _) = moved(&f.block, &anchor, slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(slot));
    let verify = FakeVerify::new(Answer::Valid);
    // The hook drops the receiver before the walk, at the slot of the anchor.
    let watched = import_watched(
        core,
        block.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        Some(f.anchor.slot),
    )
    .await;
    assert_eq!(watched.outcome, None, "the hook must drop the receiver");
    let core = watched.core;
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal of a stopped import"
    );
    assert_eq!(
        verify.calls(),
        vec![vec![early_set(&anchor, &block, &f.config)]],
        "only the proposer set before the walk must go to cl-verify"
    );
    assert!(
        core.advanced_state(&f.anchor.block_root, 1).is_none(),
        "the walk must stop before process_slots"
    );
    assert_eq!(
        watched.walk,
        vec![(f.anchor.slot, 1)],
        "the walk must stop at its first check"
    );

    let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
    assert_eq!(
        outcome,
        committed(&block),
        "the block must be able to come again"
    );
}

#[tokio::test]
async fn an_import_whose_caller_stops_waiting_at_an_epoch_boundary_keeps_the_states_before_it() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    // The walk goes from slot 0 to slot 19. It keeps the states at slots 7 and 15.
    let slot = window() + 4;
    let first_end = epoch_slots() - 1;
    let second_end = 2 * epoch_slots() - 1;
    let (block, _) = moved(&f.block, &anchor, slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(slot));
    let verify = FakeVerify::new(Answer::Valid);
    // The hook drops the receiver after the walk keeps the state at slot 7.
    let watched = import_watched(
        core,
        block.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        Some(first_end),
    )
    .await;
    assert_eq!(watched.outcome, None, "the hook must drop the receiver");
    let core = watched.core;
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal of a stopped import"
    );
    assert_eq!(
        verify.calls(),
        vec![vec![early_set(&anchor, &block, &f.config)]],
        "only the proposer set before the walk must go to cl-verify"
    );
    assert_eq!(
        watched.walk,
        vec![(0, 1), (first_end, 1)],
        "the walk must stop at the first epoch boundary"
    );
    let mut kept = core
        .advanced_state(&f.anchor.block_root, 1)
        .expect("the walk must keep the state at slot 7")
        .clone();
    assert_eq!(kept.slot, first_end);
    let mut expected = advanced(&anchor, first_end, &f.config);
    assert_eq!(
        state_root(&mut kept).unwrap(),
        state_root(&mut expected).unwrap(),
        "the kept state must be the anchor state after process_slots"
    );
    assert!(
        core.advanced_state(&f.anchor.block_root, 2).is_none(),
        "the walk must not keep a state after the stop"
    );

    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        block.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert_eq!(watched.outcome, Some(committed(&block)));
    assert_eq!(
        watched.slots(),
        vec![first_end, second_end, slot - 1],
        "the walk must start from the kept state at slot 7"
    );
    assert_eq!(verify.calls().len(), 2);
    assert_eq!(watched.core.head(), head_of(&block));
}

#[tokio::test]
async fn an_import_whose_caller_stops_waiting_after_the_walk_sends_no_block_sets() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let slot = window() + 4;
    let (block, _) = moved(&f.block, &anchor, slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(slot));
    let verify = FakeVerify::new(Answer::Valid);
    // The hook drops the receiver after the walk, at slot 19.
    let watched = import_watched(
        core,
        block.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        Some(slot - 1),
    )
    .await;
    assert_eq!(watched.outcome, None, "the hook must drop the receiver");
    let core = watched.core;
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal of a stopped import"
    );
    assert_eq!(
        verify.calls(),
        vec![vec![early_set(&anchor, &block, &f.config)]],
        "the proposer set goes before the walk, and the block sets must not go to cl-verify"
    );
    assert_eq!(watched.walk, walk_to_slot_19(1));
    assert!(
        core.advanced_state(&f.anchor.block_root, 2).is_some(),
        "the walk must keep the states that it reached"
    );

    let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
    assert_eq!(
        outcome,
        committed(&block),
        "the block must be able to come again"
    );
}

#[tokio::test]
async fn an_import_whose_caller_stops_waiting_during_the_proposer_check_does_not_commit() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let slot = window() + 4;
    let (block, _) = moved(&f.block, &anchor, slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let expected = early_set(&anchor, &block, &f.config);
    let core = f.core.with_clock(wall.at(slot));
    let verify = FakeVerify::new(Answer::Valid);
    let waiting = Waiting::default();
    // The fake cl-verify gives VALID to the proposer set, and then drops the receiver.
    let stops = Arc::new(StopsWaiting {
        inner: Arc::clone(&verify),
        waiting: waiting.clone(),
        on_call: 1,
    });
    let watched = import_watched(core, block.clone(), stops, &verify, &waiting, None).await;
    assert_eq!(
        watched.outcome, None,
        "the fake cl-verify must drop the receiver"
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    let core = watched.core;
    assert!(core.advanced_state(&f.anchor.block_root, 1).is_none());
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal of a stopped import"
    );
    assert_eq!(
        verify.calls(),
        vec![vec![expected]],
        "only the proposer set must go to cl-verify, and the block sets must not"
    );

    let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
    assert_eq!(
        outcome,
        committed(&block),
        "the block must be able to come again"
    );
}

#[tokio::test]
async fn an_import_whose_caller_stops_waiting_during_the_block_sets_does_not_commit() {
    let f = fixture();
    let wall = Wall::of(&f);
    let slot = window() + 4;
    let (block, _) = moved(&f.block, &anchor_state(&f), slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(slot));
    let verify = FakeVerify::new(Answer::Valid);
    let waiting = Waiting::default();
    // The fake cl-verify gives VALID to the proposer set and to the block sets. It drops the
    // receiver at the end of the second call, the call of the block sets.
    let stops = Arc::new(StopsWaiting {
        inner: Arc::clone(&verify),
        waiting: waiting.clone(),
        on_call: 2,
    });
    let watched = import_watched(core, block.clone(), stops, &verify, &waiting, None).await;
    assert_eq!(
        watched.outcome, None,
        "the fake cl-verify must drop the receiver"
    );
    assert_eq!(
        verify.calls().len(),
        2,
        "the proposer set and the block sets must go to cl-verify"
    );
    let core = watched.core;
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal of a stopped import"
    );

    // A committed root comes back as IGNORE before cl-verify. Two calls show a full import.
    let (outcome, core, verify) = import_one(core, block.clone(), Answer::Valid).await;
    assert_eq!(
        outcome,
        committed(&block),
        "the block must be able to come again"
    );
    assert_eq!(verify.calls().len(), 2);
    assert_eq!(core.head(), head_of(&block));
}

#[tokio::test]
async fn an_invalid_verdict_after_the_caller_stops_waiting_is_not_kept() {
    // INVALID for the proposer set before the walk (call 1), and INVALID for the block sets
    // (call 2).
    let cases = [
        (vec![Answer::Invalid], 1),
        (vec![Answer::Valid, Answer::Invalid], 2),
    ];
    for (answers, on_call) in cases {
        let f = fixture();
        let wall = Wall::of(&f);
        let slot = window() + 4;
        let (block, _) = moved(&f.block, &anchor_state(&f), slot, &f.config);
        let block_root = block.message.tree_hash_root();
        let core = f.core.with_clock(wall.at(slot));
        let verify = FakeVerify::answers(answers);
        let waiting = Waiting::default();
        // The fake cl-verify drops the receiver at the end of call `on_call`, and then gives
        // INVALID.
        let stops = Arc::new(StopsWaiting {
            inner: Arc::clone(&verify),
            waiting: waiting.clone(),
            on_call,
        });
        let watched = import_watched(core, block.clone(), stops, &verify, &waiting, None).await;
        assert_eq!(
            watched.outcome, None,
            "call {on_call}: the fake cl-verify must drop the receiver"
        );
        assert_eq!(verify.calls().len(), on_call, "call {on_call}");
        // The proposer set goes before the walk. A drop in that call stops the import before
        // the walk.
        let walk = if on_call == 1 {
            vec![]
        } else {
            walk_to_slot_19(1)
        };
        assert_eq!(watched.walk, walk, "call {on_call}");
        let core = watched.core;
        assert_unchanged(&core, f.anchor, block_root);
        assert!(
            !core.is_refused(&block_root),
            "call {on_call}: the core must not keep an INVALID verdict of a stopped import"
        );

        let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
        assert_eq!(
            outcome,
            committed(&block),
            "call {on_call}: the block must be able to come again"
        );
    }
}
