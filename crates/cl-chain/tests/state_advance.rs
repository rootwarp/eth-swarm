//! Tests of the state advance of block import through the chain core.
//!
//! A block more than `PRE_STATE_EPOCHS` epochs of slots after the state of its parent needs the
//! empty slots between them. The core walks them on a copy of the parent state, from the best
//! start: the parent state, or a checkpoint of an earlier walk from the same parent. The walk
//! is at most eight epochs of slots, and it stops one slot before the block.
//!
//! Before the walk, the core checks `proposer_index` in the parent state: it must be in the
//! registry, not slashed, and not exited or withdrawable by the block epoch. The fork of the
//! parent state at the block epoch must be the fork that the network schedule gives for that
//! epoch. Then the core checks the proposer signature: the key of `proposer_index` in the parent
//! state, and the proposer domain of the schedule fork. After that check, the core reads its
//! clock again, and the walk takes epochs from the admission budget of that clock slot: from the
//! budget of all proposers, and from the budget of its proposer. One proposer has one walk in
//! each slot of the clock.
//!
//! After the walk, the core checks that `proposer_index` is the proposer of the block slot. If
//! the fork of the advanced state at the block epoch is not the schedule fork, the block is
//! IGNORE, with no second proposer check. Then the core imports the block on the advanced state.
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

use cl_chain::core::advance::{AdvanceBudget, Advanced};
use cl_chain::core::snapshot::PRE_STATE_EPOCHS;
use cl_chain::core::{
    queue, ChainCore, Head, Outcome, Served, MAX_ADVANCED_STATES, MAX_ADVANCE_BUDGET_PROPOSERS,
    MAX_ADVANCE_EPOCHS, MAX_ADVANCE_EPOCHS_PER_PROPOSER_PER_SLOT, MAX_ADVANCE_EPOCHS_PER_SLOT,
};
use cl_chain::engine::fcu::PayloadStatus;
use cl_chain::import::block::PermitAll;
use cl_chain::verify::client::{BlsOutcome, BlsVerifier, UnixClock};
use consensus_types::common::{PendingDeposit, Validator};
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::{
    assert_unchanged, clock_at, export_block, fixture, import_one, proposer_set, proposer_set_in,
    slot_start, Answer, FakeVerify, Fixture, PayloadVerified, QUEUE, VERIFY_TIMEOUT,
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
    assert_eq!(MAX_ADVANCE_EPOCHS_PER_SLOT, 8);
    // A walk of the cap fits in the budget of one proposer.
    assert_eq!(MAX_ADVANCE_EPOCHS_PER_PROPOSER_PER_SLOT, MAX_ADVANCE_EPOCHS);
    assert_eq!(MAX_ADVANCE_BUDGET_PROPOSERS, 128);
}

#[test]
fn the_admission_budget_refills_with_the_clock_up_to_one_slot() {
    let mut budget = AdvanceBudget::new();
    // Each take is for another proposer, so the budget of all proposers is the bound.
    let mut proposers = 0..;
    let mut take = |now, epochs| budget.take(now, proposers.next().unwrap(), epochs);
    // The first take fills the bucket.
    assert!(take(10, 5));
    assert!(take(10, 3));
    assert!(!take(10, 1), "eight epochs in one slot");
    // A take over the budget takes nothing.
    assert!(take(11, 8));
    assert!(!take(11, 1));
    // Idle slots add no more than one slot of work.
    assert!(!take(20, 9));
    assert!(take(20, 8));
    // A clock that goes back adds nothing and empties nothing.
    assert!(!take(15, 1));
    assert!(take(21, 2));
    assert!(take(19, 6));
    assert!(!take(21, 1));
    assert!(take(22, 8));
    // A zero walk always fits.
    assert!(take(22, 0));
}

#[test]
fn one_proposer_has_one_walk_in_each_slot_of_the_clock() {
    let mut budget = AdvanceBudget::new();
    // A walk takes the full budget of its proposer, also a short walk.
    assert!(budget.take(10, 1, 3));
    assert!(
        !budget.take(10, 1, 1),
        "a second walk of proposer 1 in the slot"
    );
    // Another proposer can take the rest of the budget of all proposers.
    assert!(!budget.take(10, 2, 6));
    assert!(budget.take(10, 2, 5));
    assert!(!budget.take(10, 3, 1), "eight epochs in one slot");
    // The next slot fills both budgets again. A walk of no epoch takes nothing.
    assert!(budget.take(11, 1, 8));
    assert!(budget.take(11, 1, 0));
    assert!(!budget.take(11, 1, 1));
    // A clock that goes back adds nothing to the budget of a proposer.
    assert!(budget.take(13, 2, 1));
    assert!(!budget.take(12, 2, 1));
    assert!(
        budget.take(12, 3, 1),
        "a refused take keeps no budget of its proposer"
    );
}

#[test]
fn the_admission_budget_keeps_the_proposers_charged_last() {
    let mut budget = AdvanceBudget::new();
    let bound = u64::try_from(MAX_ADVANCE_BUDGET_PROPOSERS).unwrap();
    // One walk of each proposer, each in its own slot of the clock.
    for proposer in 0..=bound {
        assert!(budget.take(proposer, proposer, 1), "proposer {proposer}");
    }
    assert_eq!(
        budget.proposers(),
        MAX_ADVANCE_BUDGET_PROPOSERS,
        "the bound must hold"
    );
    // A clock that goes back adds nothing to the budget of a proposer that stays. Proposer 0,
    // charged first, went: a later walk of it starts from a full budget of its own.
    assert!(!budget.take(1, 1, 1), "proposer 1 stays");
    assert!(budget.take(0, 0, 1), "proposer 0 went");
    assert_eq!(budget.proposers(), MAX_ADVANCE_BUDGET_PROPOSERS);
    assert!(
        budget.take(1, 1, 1),
        "proposer 1 went after proposer 0 came back"
    );
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

#[test]
fn a_retain_keeps_the_states_of_the_parents_that_stay() {
    let mut kept = Advanced::new(8);
    kept.insert(root(1), 1, 11u64);
    kept.insert(root(2), 1, 21);
    kept.insert(root(1), 2, 12);
    kept.insert(root(3), 1, 31);
    kept.retain(|parent| *parent != root(1));
    assert_eq!(kept.len(), 2);
    assert_eq!(kept.peek(&root(1), 1), None);
    assert_eq!(kept.peek(&root(1), 2), None);
    assert_eq!(kept.peek(&root(2), 1), Some(&21));
    assert_eq!(kept.peek(&root(3), 1), Some(&31));
    // The order of use does not change: 2 is still the least recent, and goes at the next
    // insert past the bound.
    for byte in 4..11 {
        kept.insert(root(byte), 1, u64::from(byte));
    }
    assert_eq!(kept.peek(&root(2), 1), None);
    assert_eq!(kept.peek(&root(3), 1), Some(&31));
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

    /// The start of `slot`, in Unix milliseconds.
    fn ms(&self, slot: u64) -> u128 {
        self.genesis_ms + u128::from(slot) * self.slot_ms
    }

    /// A clock at the start of `slot`.
    fn at(&self, slot: u64) -> UnixClock {
        clock_at(self.ms(slot))
    }
}

/// `core` whose fork choice store took the tick of the start of `slot` (`on_tick`), as before a
/// wall clock that stepped back. A block one slot ahead of the wall clock is then not after the
/// current slot of fork choice, so it goes on to the checks after the wall-clock bound.
fn store_at(core: ChainCore<Minimal>, wall: &Wall, slot: u64) -> ChainCore<Minimal> {
    let ms = u64::try_from(wall.ms(slot)).unwrap();
    core.with_fork_choice(|store| fork_choice::on_tick(store, ms).unwrap())
}

/// A test clock that a fake cl-verify can move, in Unix milliseconds.
#[derive(Clone)]
struct Moving(Arc<AtomicU64>);

impl Moving {
    /// A clock at `ms`.
    fn at(ms: u128) -> Self {
        Self(Arc::new(AtomicU64::new(u64::try_from(ms).unwrap())))
    }

    /// The clock for the core.
    fn clock(&self) -> UnixClock {
        let ms = Arc::clone(&self.0);
        Arc::new(move || u128::from(ms.load(Ordering::SeqCst)))
    }

    /// Sets the clock to `ms`.
    fn set(&self, ms: u128) {
        self.0.store(u64::try_from(ms).unwrap(), Ordering::SeqCst);
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
        payload_status: PayloadStatus::Empty,
    }
}

/// The head of fork choice after the commits of `blocks`, each on the FULL node of the anchor
/// `anchor` or on the EMPTY node of one of `blocks`, with no votes and no proposer boost (no
/// block comes at the start of its own slot): at each node from the anchor, the child of the
/// highest root.
fn fork_choice_head(anchor: Root, blocks: &[&Block]) -> Head {
    let mut head = None;
    let mut at = anchor;
    while let Some(child) = blocks
        .iter()
        .filter(|block| block.message.parent_root == at)
        .max_by_key(|block| block.message.tree_hash_root())
    {
        at = child.message.tree_hash_root();
        head = Some(head_of(child));
    }
    head.expect("a block on the anchor")
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

    // The walk of the second import spends the admission budget of its slot. The third import
    // comes one slot later.
    let core = core.with_clock(wall.at(late_slot + 1));
    let (outcome, core, verify) = import_one(core, late.clone(), Answer::Valid).await;
    assert_eq!(
        outcome,
        committed(&late),
        "the walk must start from the kept state"
    );
    assert_eq!(verify.calls().len(), 2);
    // Two children of the anchor.
    assert_eq!(
        core.head(),
        fork_choice_head(f.anchor.block_root, &[&early, &late])
    );
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
        // The check of the registry gives this answer, and not a later check: cl-verify has no
        // signer for an index past the registry either.
        let parent = f.anchor.block_root;
        assert_eq!(
            watched.outcome,
            Some(Outcome::Ignored(format!(
                "proposer {proposer} is past the registry of the state of the parent {parent}"
            ))),
            "{proposer}: a later parent state can have a longer registry"
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

/// A change of a validator in the anchor state, with the block epoch.
type Edit = fn(&mut Validator, Epoch);

/// The proposer of slot `slot` after the anchor of the fixture.
fn anchor_proposer(slot: u64) -> u64 {
    let f = fixture();
    let (block, _) = moved(&f.block, &anchor_state(&f), slot, &f.config);
    block.message.proposer_index
}

/// The fixture with validator `index` of the anchor state changed by `edit`, for blocks at
/// `epoch`.
fn validator_fixture(index: u64, edit: Edit, epoch: Epoch) -> Fixture {
    let index = usize::try_from(index).unwrap();
    anchor_with(|state| edit(state.validators.get_mut(index).unwrap(), epoch))
}

/// The slot 1 block of `f` at `slot`, with `proposer` as its proposer. The core refuses it
/// before the transition, so its state root does not matter.
fn claimed_by(f: &Fixture, slot: u64, proposer: u64) -> Block {
    let mut block = f.block.clone();
    block.message.slot = slot;
    block.message.proposer_index = proposer;
    block
}

/// Slots without a block do not unslash a validator, or move a set exit epoch or withdrawable
/// epoch later. So a validator that the parent state shows slashed, or exited or withdrawable at
/// the block epoch, cannot propose the block.
#[tokio::test]
async fn a_far_block_of_a_slashed_exited_or_withdrawable_proposer_is_ignored_before_cl_verify() {
    let slot = window() + 4;
    let epoch = Minimal::epoch_at_slot(slot);
    let proposer = anchor_proposer(slot);
    let edits: [(&str, Edit); 3] = [
        ("slashed", |validator, _| validator.slashed = true),
        ("exited at the block epoch", |validator, epoch| {
            validator.exit_epoch = epoch;
        }),
        ("withdrawable at the block epoch", |validator, epoch| {
            validator.withdrawable_epoch = epoch;
        }),
    ];
    for (case, edit) in edits {
        let f = validator_fixture(proposer, edit, epoch);
        let wall = Wall::of(&f);
        let anchor = anchor_state(&f);
        let block = claimed_by(&f, slot, proposer);
        let block_root = block.message.tree_hash_root();
        // The clock is at the slot of a walk of eight epochs from the anchor.
        let core = f.core.with_clock(wall.at(cap()));
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
            "{case}: {:?}",
            watched.outcome
        );
        assert!(
            verify.calls().is_empty(),
            "{case}: the block must not reach cl-verify"
        );
        assert!(
            watched.walk.is_empty(),
            "{case}: the core must not start the walk"
        );
        let core = watched.core;
        assert!(core.advanced_state(&f.anchor.block_root, 1).is_none());
        assert_unchanged(&core, f.anchor, block_root);
        assert!(
            !core.is_refused(&block_root),
            "{case}: the core must not keep the refusal"
        );

        // The refusal took nothing from the budget of the clock slot: a walk of eight epochs
        // of another proposer fits in it.
        let (full, _) = moved(&f.block, &anchor, cap(), &f.config);
        assert_ne!(full.message.proposer_index, proposer, "{case}");
        let (outcome, _, _) = import_one(core, full.clone(), Answer::Valid).await;
        assert_eq!(outcome, committed(&full), "{case}");
    }
}

/// The walk can activate a validator whose activation epoch is set. A validator that exits, or
/// becomes withdrawable, after the block epoch can still propose the block.
#[tokio::test]
async fn a_far_block_of_a_proposer_that_can_propose_at_the_block_epoch_goes_to_the_signature_check()
{
    let slot = window() + 4;
    let epoch = Minimal::epoch_at_slot(slot);
    let proposer = anchor_proposer(slot);
    let edits: [(&str, Edit); 3] = [
        ("exited after the block epoch", |validator, epoch| {
            validator.exit_epoch = epoch + 1;
        }),
        ("withdrawable after the block epoch", |validator, epoch| {
            validator.withdrawable_epoch = epoch + 1;
        }),
        ("active from the block epoch", |validator, epoch| {
            validator.activation_epoch = epoch;
        }),
    ];
    for (case, edit) in edits {
        let f = validator_fixture(proposer, edit, epoch);
        let wall = Wall::of(&f);
        let anchor = anchor_state(&f);
        let block = claimed_by(&f, slot, proposer);
        let core = f.core.with_clock(wall.at(slot));
        let (outcome, _, verify) = import_one(core, block.clone(), Answer::Invalid).await;
        assert_eq!(
            outcome,
            Outcome::Invalid(StfError::InvalidBlockSignature),
            "{case}: the block must reach the proposer check"
        );
        assert_eq!(
            verify.calls(),
            vec![vec![early_set(&anchor, &block, &f.config)]],
            "{case}"
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

/// A fork version that the network schedule of the fixture does not have.
const OTHER_VERSION: [u8; 4] = [0x07, 0, 0, 0x42];

/// A change of the fork of the anchor state.
type ForkEdit = fn(&mut State);

#[tokio::test]
async fn a_far_block_whose_parent_fork_is_not_the_schedule_fork_is_ignored_before_cl_verify() {
    // `get_domain` on the parent state gives the previous version before the fork epoch of the
    // state, and the current version from it. Each case changes the version of the block
    // epoch. In the second case, the version from epoch 3 is still the schedule version.
    let cases: [(&str, ForkEdit, Option<u64>); 2] = [
        (
            "another current version",
            |state| state.fork.current_version = OTHER_VERSION,
            None,
        ),
        (
            "another previous version before epoch 3",
            |state| {
                state.fork.previous_version = OTHER_VERSION;
                state.fork.epoch = 3;
            },
            Some(cap()),
        ),
    ];
    for (case, edit, later) in cases {
        let f = anchor_with(edit);
        let wall = Wall::of(&f);
        let anchor = anchor_state(&f);
        let slot = window() + 4;
        let (block, _) = moved(&f.block, &anchor, slot, &f.config);
        let block_root = block.message.tree_hash_root();
        let core = f.core.with_clock(wall.at(cap()));
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
            "{case}: {:?}",
            watched.outcome
        );
        assert!(
            verify.calls().is_empty(),
            "{case}: the block must not reach cl-verify"
        );
        assert!(
            watched.walk.is_empty(),
            "{case}: the core must not start the walk"
        );
        let core = watched.core;
        assert_unchanged(&core, f.anchor, block_root);
        assert!(
            !core.is_refused(&block_root),
            "{case}: the core must not keep the refusal"
        );

        // A block at an epoch where the fork of the parent state is the schedule fork, in the
        // same clock slot: the refusal took nothing from the budget of that slot.
        if let Some(later) = later {
            let (full, _) = moved(&f.block, &anchor, later, &f.config);
            let (outcome, _, _) = import_one(core, full.clone(), Answer::Valid).await;
            assert_eq!(outcome, committed(&full), "{case}");
        }
    }
}

/// The walk has no fork upgrade yet, so it does not change the fork of a state. The test keeps
/// a walk state with another fork: the state that a walk with a fork upgrade would keep. The
/// fork of the parent state is the schedule fork, so the proposer signature goes to cl-verify
/// before the walk.
#[tokio::test]
async fn a_far_block_whose_advanced_fork_is_not_the_schedule_fork_is_ignored_after_the_walk() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let slot = window() + 4;
    let (block, _) = moved(&f.block, &anchor, slot, &f.config);
    let block_root = block.message.tree_hash_root();
    // The walk state at slot 15, the last slot of epoch 1, with another fork version.
    let kept_slot = 2 * epoch_slots() - 1;
    let mut kept = advanced(&anchor, kept_slot, &f.config);
    kept.fork.current_version = OTHER_VERSION;
    let core = f
        .core
        .with_clock(wall.at(slot))
        .with_advanced_state(f.anchor.block_root, 2, kept);
    // VALID for the proposer set before the walk, and INVALID for a second proposer set.
    let verify = FakeVerify::answers(vec![Answer::Valid, Answer::Invalid]);
    let watched = import_watched(
        core,
        block.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert!(
        matches!(watched.outcome, Some(Outcome::Ignored(_))),
        "the fork of the advanced state is no proof about the block: {:?}",
        watched.outcome
    );
    assert_eq!(
        verify.calls(),
        vec![vec![early_set(&anchor, &block, &f.config)]],
        "only the proposer set before the walk must go to cl-verify"
    );
    assert_eq!(
        watched.walk,
        vec![(kept_slot, 1), (slot - 1, 1)],
        "the walk must start from the kept state, after the proposer set"
    );
    let core = watched.core;
    assert_unchanged(&core, f.anchor, block_root);
    assert!(
        !core.is_refused(&block_root),
        "the core must not keep the refusal"
    );
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

#[tokio::test]
async fn one_slot_of_the_core_clock_admits_eight_epochs_of_walk() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    // A walk of eight epochs from the anchor. The next block then needs one more epoch from the
    // state that the walk keeps at slot 63.
    let first_slot = cap();
    let next_slot = cap() + 1;
    let (first, _) = moved(&f.block, &anchor, first_slot, &f.config);
    let (next, _) = moved(&f.block, &anchor, next_slot, &f.config);
    let next_root = next.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(first_slot));
    let (outcome, core, _) = import_one(core, first.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&first));
    // `next` is one slot ahead of the clock: only a store ahead of the clock takes it.
    let core = store_at(core, &wall, next_slot);

    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        next.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert!(
        matches!(watched.outcome, Some(Outcome::Ignored(_))),
        "the budget of the clock slot is spent: {:?}",
        watched.outcome
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    assert_eq!(
        verify.calls(),
        vec![vec![early_set(&anchor, &next, &f.config)]],
        "only the proposer set before the walk must go to cl-verify"
    );
    let core = watched.core;
    assert!(
        !core.is_refused(&next_root),
        "the core must not keep the refusal of a spent budget"
    );
    assert_eq!(core.head(), head_of(&first));

    // One slot later, the budget is full again.
    let core = core.with_clock(wall.at(next_slot));
    let (outcome, core, _) = import_one(core, next.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&next));
    assert_eq!(core.head(), head_of(&next));
}

#[tokio::test]
async fn two_walks_of_four_epochs_spend_the_admission_budget_of_one_slot() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let now = 4 * epoch_slots() + 1;
    let core = f.core.with_clock(wall.at(now));
    // An import in the pre-state window takes nothing from the budget.
    let first = f.block.clone();
    let first_root = first.message.tree_hash_root();
    let (outcome, core, _) = import_one(core, first.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&first));
    let parent = core.state(&first_root).unwrap().clone();
    // Four epochs from the anchor, and four epochs from the slot 1 block.
    let (from_anchor, _) = moved(&f.block, &anchor, 4 * epoch_slots(), &f.config);
    let (from_first, _) = moved(&export_block(2), &parent, now, &f.config);
    // One epoch from the state that the second walk keeps at slot 31.
    let (last, _) = moved(&export_block(2), &parent, now + 1, &f.config);
    let last_root = last.message.tree_hash_root();
    let (outcome, core, _) = import_one(core, from_anchor.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&from_anchor));
    let (outcome, core, _) = import_one(core, from_first.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&from_first));
    assert!(core.advanced_state(&first_root, 4).is_some());
    // `last` is one slot ahead of the clock: only a store ahead of the clock takes it.
    let core = store_at(core, &wall, now + 1);

    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        last.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert!(
        matches!(watched.outcome, Some(Outcome::Ignored(_))),
        "the budget of the clock slot is spent: {:?}",
        watched.outcome
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    assert_eq!(verify.calls().len(), 1, "only the proposer set");
    let core = watched.core;
    assert!(!core.is_refused(&last_root));
    assert_eq!(core.head(), head_of(&from_first));

    // One slot later, the budget is full again.
    let core = core.with_clock(wall.at(now + 1));
    let (outcome, _, _) = import_one(core, last.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&last));
}

#[tokio::test]
async fn a_block_past_the_cap_or_with_a_bad_signature_spends_no_admission_budget() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    // The store took the tick of the slot after the wall clock: a block of that slot is not
    // after the current slot of fork choice, and not more than `MAX_FUTURE_SLOTS` ahead of the
    // wall clock, so it reaches the walk cap.
    let mut core = store_at(f.core.with_clock(wall.at(cap())), &wall, cap() + 1);
    // Past the cap from the anchor: IGNORE before cl-verify, with no walk.
    let mut far = f.block.clone();
    far.message.slot = cap() + 1;
    let past_cap = format!(
        "more than {} slots after the state at slot {}",
        cap(),
        f.anchor.slot
    );
    for _ in 0..3 {
        let verify = FakeVerify::new(Answer::Valid);
        let watched = import_watched(
            core,
            far.clone(),
            Arc::clone(&verify),
            &verify,
            &Waiting::default(),
            None,
        )
        .await;
        match &watched.outcome {
            Some(Outcome::Ignored(why)) => assert!(why.contains(&past_cap), "{why}"),
            other => panic!("the walk cap must IGNORE the block: {other:?}"),
        }
        assert!(watched.walk.is_empty(), "the core must not start the walk");
        assert!(verify.calls().is_empty());
        core = watched.core;
    }
    // A bad signature: INVALID before the walk.
    let (block, _) = moved(&f.block, &anchor, cap(), &f.config);
    for byte in 1..4 {
        let mut bad = block.clone();
        bad.signature[10] ^= byte;
        let (outcome, next, _) = import_one(core, bad, Answer::Invalid).await;
        assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
        core = next;
    }
    // The full budget of the slot is still there: a walk of eight epochs.
    let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&block));
}

/// One proposer has one walk in each slot of the core clock. Another proposer can use the rest
/// of the budget of that slot. The fixture chains have proposer A at slot 32 after the anchor,
/// and proposer B at slots 29 and 65 after the slot 1 block.
#[tokio::test]
async fn one_proposer_has_one_walk_in_each_slot_of_the_core_clock() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let now = cap() + 1;
    let core = f.core.with_clock(wall.at(now));
    // An import in the pre-state window takes nothing from the budget.
    let first = f.block.clone();
    let first_root = first.message.tree_hash_root();
    let core = commit(core, &first).await;
    let parent = core.state(&first_root).unwrap().clone();
    // A: four epochs from the anchor, and a block at the same slot with another graffiti. The
    // second block needs one epoch from the state that the first walk keeps at slot 31.
    let a_slot = 4 * epoch_slots();
    let (a_first, _) = moved(&f.block, &anchor, a_slot, &f.config);
    let mut template = f.block.clone();
    template.message.body.graffiti = Bytes32::repeat_byte(0x11);
    let (a_again, _) = moved(&template, &anchor, a_slot, &f.config);
    let a_again_root = a_again.message.tree_hash_root();
    // B: eight epochs (64 slots) and four epochs (28 slots) from the slot 1 block.
    let (b_eight, _) = moved(&export_block(2), &parent, 1 + cap(), &f.config);
    let b_eight_root = b_eight.message.tree_hash_root();
    let (b_four, _) = moved(&export_block(2), &parent, 29, &f.config);
    let a = a_first.message.proposer_index;
    let b = b_eight.message.proposer_index;
    assert_eq!(a_again.message.proposer_index, a);
    assert_eq!(b_four.message.proposer_index, b);
    assert_ne!(a, b, "the test needs two proposers");

    let core = commit(core, &a_first).await;

    // A second walk of A in the same clock slot is IGNORE. Four epochs of the budget of the
    // slot are left, and one epoch is enough for the walk.
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        a_again.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert!(
        matches!(watched.outcome, Some(Outcome::Ignored(_))),
        "proposer {a} has no second walk in a clock slot: {:?}",
        watched.outcome
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    assert_eq!(
        verify.calls(),
        vec![vec![early_set(&anchor, &a_again, &f.config)]],
        "only the proposer set before the walk must go to cl-verify"
    );
    let core = watched.core;
    assert!(
        !core.is_refused(&a_again_root),
        "the core must not keep the refusal of a spent budget"
    );
    let anchor_root = f.anchor.block_root;
    assert_eq!(
        core.head(),
        fork_choice_head(anchor_root, &[&first, &a_first])
    );

    // B: eight epochs do not fit in the four that are left.
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        b_eight.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert!(
        matches!(watched.outcome, Some(Outcome::Ignored(_))),
        "the budget of the clock slot has four epochs left: {:?}",
        watched.outcome
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    let core = watched.core;
    assert!(!core.is_refused(&b_eight_root));

    // B: four epochs fit.
    let core = commit(core, &b_four).await;
    assert_eq!(
        core.head(),
        fork_choice_head(anchor_root, &[&first, &a_first, &b_four])
    );

    // One slot later, A can walk again.
    let core = commit(core.with_clock(wall.at(now + 1)), &a_again).await;
    assert_eq!(
        core.head(),
        fork_choice_head(anchor_root, &[&first, &a_first, &b_four, &a_again])
    );
}

/// A fake cl-verify that gives the answers of `inner`. At the end of call `on_call` (1 is the
/// first call), it sets `clock` to `then`.
struct MovesClock {
    inner: Arc<FakeVerify>,
    clock: Moving,
    then: u128,
    on_call: usize,
}

impl BlsVerifier for MovesClock {
    async fn verify_sets(&self, sets: Vec<BlsSet>, deadline: Instant) -> BlsOutcome {
        let outcome = self.inner.verify_sets(sets, deadline).await;
        // The core waits for each call, so the calls do not overlap.
        if self.inner.called().len() == self.on_call {
            self.clock.set(self.then);
        }
        outcome
    }
}

/// The clock of the core moves to the next slot during the VerifyBls call of the proposer set.
/// The walk takes its epochs from the budget of the slot after that call.
#[tokio::test]
async fn a_walk_takes_the_budget_of_the_clock_slot_after_the_proposer_check() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let now = cap() + 1;
    let clock = Moving::at(wall.ms(now));
    let core = f.core.with_clock(clock.clock());
    // An import in the pre-state window takes nothing from the budget.
    let first = f.block.clone();
    let first_root = first.message.tree_hash_root();
    let core = commit(core, &first).await;
    let parent = core.state(&first_root).unwrap().clone();
    // Eight epochs from the anchor, and eight epochs from the slot 1 block.
    let (full, _) = moved(&f.block, &anchor, cap(), &f.config);
    let (other, _) = moved(&export_block(2), &parent, 1 + cap(), &f.config);
    let other_root = other.message.tree_hash_root();
    assert_ne!(
        full.message.proposer_index, other.message.proposer_index,
        "the test needs two proposers"
    );

    let verify = FakeVerify::new(Answer::Valid);
    let moves = Arc::new(MovesClock {
        inner: Arc::clone(&verify),
        clock: clock.clone(),
        then: wall.ms(now + 1),
        on_call: 1,
    });
    let (outcome, core) = support::import_with(core, full.clone(), moves).await;
    assert_eq!(outcome, committed(&full));
    assert_eq!(verify.calls().len(), 2);

    // The first walk spent the budget of slot `now + 1`, not of slot `now`.
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        other.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert!(
        matches!(watched.outcome, Some(Outcome::Ignored(_))),
        "the budget of slot {} is spent: {:?}",
        now + 1,
        watched.outcome
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    let core = watched.core;
    assert!(!core.is_refused(&other_root));
    let anchor_root = f.anchor.block_root;
    assert_eq!(core.head(), fork_choice_head(anchor_root, &[&first, &full]));

    // One slot later, the budget is full again.
    clock.set(wall.ms(now + 2));
    let core = commit(core, &other).await;
    assert_eq!(
        core.head(),
        fork_choice_head(anchor_root, &[&first, &full, &other])
    );
}

/// The clock of the core goes back during the VerifyBls call of the proposer set: before
/// genesis, or to two slots before the block. The core checks the block slot against the clock
/// again after that call, and refuses the block before the walk.
#[tokio::test]
async fn a_far_block_out_of_the_wall_clock_after_the_proposer_check_is_ignored_before_the_walk() {
    let slot = cap();
    let backs: [fn(&Wall) -> u128; 2] = [|wall| wall.genesis_ms - 1, |wall| wall.ms(cap() - 2)];
    for back in backs {
        let f = fixture();
        let wall = Wall::of(&f);
        let anchor = anchor_state(&f);
        let then = back(&wall);
        let (block, _) = moved(&f.block, &anchor, slot, &f.config);
        let block_root = block.message.tree_hash_root();
        let clock = Moving::at(wall.ms(slot));
        let core = f.core.with_clock(clock.clock());
        let verify = FakeVerify::new(Answer::Valid);
        let moves = Arc::new(MovesClock {
            inner: Arc::clone(&verify),
            clock: clock.clone(),
            then,
            on_call: 1,
        });
        let watched = import_watched(
            core,
            block.clone(),
            moves,
            &verify,
            &Waiting::default(),
            None,
        )
        .await;
        assert!(
            matches!(watched.outcome, Some(Outcome::Ignored(_))),
            "clock {then} ms: {:?}",
            watched.outcome
        );
        assert_eq!(
            verify.calls(),
            vec![vec![early_set(&anchor, &block, &f.config)]],
            "clock {then} ms: only the proposer set must go to cl-verify"
        );
        assert!(
            watched.walk.is_empty(),
            "clock {then} ms: the core must not start the walk"
        );
        let core = watched.core;
        assert!(core.advanced_state(&f.anchor.block_root, 1).is_none());
        assert_unchanged(&core, f.anchor, block_root);
        assert!(
            !core.is_refused(&block_root),
            "clock {then} ms: the core must not keep the refusal"
        );

        // The refusal took nothing from the budget of the block slot: the walk of eight epochs
        // fits in it.
        clock.set(wall.ms(slot));
        let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
        assert_eq!(outcome, committed(&block), "clock {then} ms");
    }
}

/// The walk keeps a state at the end of each epoch that it reaches, also at epoch 8. A later
/// block of the same parent, more than eight epochs of slots after the parent state, starts its
/// walk from that state.
#[tokio::test]
async fn a_kept_state_of_epoch_eight_starts_a_later_walk() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let later_slot = cap() + epoch_slots();
    let (full, _) = moved(&f.block, &anchor, cap(), &f.config);
    let (later, _) = moved(&f.block, &anchor, later_slot, &f.config);
    let core = commit(f.core.with_clock(wall.at(later_slot)), &full).await;
    let kept = core
        .advanced_state(&f.anchor.block_root, MAX_ADVANCE_EPOCHS)
        .expect("the walk must keep the state at the end of epoch 7");
    assert_eq!(kept.slot, cap() - 1);
    assert!(
        later_slot - anchor.slot > cap(),
        "the anchor state is past the cap of the later block"
    );

    // The first walk spent the budget of its clock slot. The later block comes one slot later.
    let core = core.with_clock(wall.at(later_slot + 1));
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        later.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert_eq!(watched.outcome, Some(committed(&later)));
    assert_eq!(
        watched.slots(),
        vec![cap() - 1, later_slot - 1],
        "the walk must start from the state kept at epoch 8"
    );
}

/// The walk of a block starts from the latest kept state up to the block epoch, and the budget
/// takes the epochs from that state. A kept state after the block epoch is not the start.
#[tokio::test]
async fn a_kept_state_after_the_block_epoch_is_not_the_start_of_its_walk() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    // 64 slots after the state that the first walk keeps at slot 63: eight epochs.
    let last_slot = 2 * cap() - 1;
    let early_slot = window() + 4;
    let (full, _) = moved(&f.block, &anchor, cap(), &f.config);
    let (early, _) = moved(&f.block, &anchor, early_slot, &f.config);
    let (last, _) = moved(&f.block, &anchor, last_slot, &f.config);
    let last_root = last.message.tree_hash_root();
    assert_ne!(
        early.message.proposer_index, last.message.proposer_index,
        "the test needs two proposers"
    );
    // The anchor then has kept states at the ends of epochs 0 to 7.
    let core = commit(f.core.with_clock(wall.at(last_slot - 1)), &full).await;

    // The early block starts its walk from the state at slot 15, and takes one epoch.
    let core = core.with_clock(wall.at(last_slot));
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        early.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert_eq!(watched.outcome, Some(committed(&early)));
    assert_eq!(
        watched.slots(),
        vec![2 * epoch_slots() - 1, early_slot - 1],
        "the walk must start from the state kept at epoch 2"
    );

    // Seven epochs of the budget of the clock slot are left: a walk of eight epochs does not
    // fit.
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        watched.core,
        last.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert!(
        matches!(watched.outcome, Some(Outcome::Ignored(_))),
        "the early walk took one epoch from the budget: {:?}",
        watched.outcome
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    let core = watched.core;
    assert!(!core.is_refused(&last_root));

    // One slot later, it fits.
    let core = core.with_clock(wall.at(last_slot + 1));
    let (outcome, _, _) = import_one(core, last.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&last));
}

/// Commits `block` on `core` with a fake cl-verify that answers VALID.
async fn commit(core: ChainCore<Minimal>, block: &Block) -> ChainCore<Minimal> {
    let (outcome, core, _) = import_one(core, block.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(block));
    core
}

#[tokio::test]
async fn the_kept_states_of_a_parent_go_when_its_pre_state_goes() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    let now = window() + 6;
    let core = f.core.with_clock(wall.at(now));
    // A walk from the slot 1 block, and a walk from the anchor. Each keeps the states at the
    // ends of epochs 0 and 1.
    let first = f.block.clone();
    let first_root = first.message.tree_hash_root();
    let core = commit(core, &first).await;
    let parent = core.state(&first_root).unwrap().clone();
    let (child, _) = moved(&export_block(2), &parent, now, &f.config);
    let core = commit(core, &child).await;
    let (far, _) = moved(&f.block, &anchor, window() + 4, &f.config);
    let mut core = commit(core, &far).await;
    for epoch in 1..=2 {
        assert!(core.advanced_state(&first_root, epoch).is_some());
        assert!(core.advanced_state(&f.anchor.block_root, epoch).is_some());
    }

    // Children of the anchor in the pre-state window fill the pre-states. The pre-state of the
    // slot 1 block is the least recently used, so it goes first.
    let mut gone = false;
    for slot in 2..=window() {
        let (block, _) = moved(&f.block, &anchor, slot, &f.config);
        core = commit(core, &block).await;
        if core.state(&first_root).is_none() {
            gone = true;
            break;
        }
        for epoch in 1..=2 {
            assert!(
                core.advanced_state(&first_root, epoch).is_some(),
                "slot {slot}: the kept states of a parent with a pre-state must stay"
            );
        }
    }
    assert!(gone, "the pre-state of the slot 1 block must go");
    for epoch in 1..=2 {
        assert!(
            core.advanced_state(&first_root, epoch).is_none(),
            "epoch {epoch}: a kept state of a parent without a pre-state must go"
        );
        assert!(
            core.advanced_state(&f.anchor.block_root, epoch).is_some(),
            "epoch {epoch}: the kept states of the anchor must stay"
        );
    }
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
        .with_payload_gate(PermitAll)
        // The slot 1 block builds on the FULL payload of the anchor (see `support`).
        .with_payload_verified(anchor.block_root);
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

    // The walk took its epochs before its first check, and gives nothing back. The block can
    // come again in the next clock slot.
    let core = core.with_clock(wall.at(slot + 1));
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

    // The stopped walk keeps its charge, and its proposer has no second walk in the clock slot:
    // the same block in the same slot is IGNORE, with no walk.
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
    assert!(
        matches!(watched.outcome, Some(Outcome::Ignored(_))),
        "a stopped walk gives nothing back: {:?}",
        watched.outcome
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    let core = watched.core;
    assert!(!core.is_refused(&block_root));

    // In the next clock slot, the block comes again.
    let core = core.with_clock(wall.at(slot + 1));
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
async fn a_stopped_walk_gives_nothing_back_to_the_budget_of_all_proposers() {
    let f = fixture();
    let wall = Wall::of(&f);
    let anchor = anchor_state(&f);
    // A walk of six epochs from the anchor (slots 0 to 47) stops after the state at slot 7.
    // It keeps its charge, so the budget of all proposers keeps two epochs in this clock slot.
    let now = 6 * epoch_slots();
    let first_end = epoch_slots() - 1;
    let (first, _) = moved(&f.block, &anchor, now, &f.config);
    let core = f.core.with_clock(wall.at(now));
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        first.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        Some(first_end),
    )
    .await;
    assert_eq!(watched.outcome, None, "the hook must drop the receiver");
    assert_eq!(watched.walk, vec![(0, 1), (first_end, 1)]);
    let core = watched.core;

    // A block of another proposer needs three epochs from the state at slot 7 (slots 7 to 24
    // or more). Its own bucket is full, so only the budget of all proposers refuses it.
    let other = (3 * epoch_slots() + 1..4 * epoch_slots())
        .map(|slot| moved(&f.block, &anchor, slot, &f.config).0)
        .find(|block| block.message.proposer_index != first.message.proposer_index)
        .expect("a slot of epoch 3 with another proposer");
    let other_root = other.message.tree_hash_root();
    let verify = FakeVerify::new(Answer::Valid);
    let watched = import_watched(
        core,
        other.clone(),
        Arc::clone(&verify),
        &verify,
        &Waiting::default(),
        None,
    )
    .await;
    assert!(
        matches!(&watched.outcome, Some(Outcome::Ignored(why)) if why.contains("admission budget")),
        "a stopped walk gives nothing back to the budget of all proposers: {:?}",
        watched.outcome
    );
    assert!(watched.walk.is_empty(), "the core must not start the walk");
    let core = watched.core;
    assert!(!core.is_refused(&other_root));

    // In the next clock slot, the budget is full again.
    let core = core.with_clock(wall.at(now + 1));
    let (outcome, core, _) = import_one(core, other.clone(), Answer::Valid).await;
    assert_eq!(outcome, committed(&other));
    assert_eq!(core.head(), head_of(&other));
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

    // The walk is charged. The block can come again in the next clock slot.
    let core = core.with_clock(wall.at(slot + 1));
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
    // A walk of eight epochs: the full budget of a clock slot.
    let slot = cap();
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

    // The same block in the same clock slot. The stopped import took nothing from the budget of
    // the slot or of the proposer, so the walk of eight epochs fits.
    let (outcome, _, verify) = import_one(core, block.clone(), Answer::Valid).await;
    assert_eq!(
        outcome,
        committed(&block),
        "the block must be able to come again in the same clock slot"
    );
    assert_eq!(verify.calls().len(), 2);
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

    // The walk is charged. The block can come again in the next clock slot. A committed root
    // comes back as IGNORE before cl-verify, so two calls show a full import.
    let core = core.with_clock(wall.at(slot + 1));
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

        // A stop in the proposer check comes before the charge of the walk: the block can come
        // again in the same clock slot. After the walk, it can come again in the next one.
        let again = if on_call == 1 { slot } else { slot + 1 };
        let core = core.with_clock(wall.at(again));
        let (outcome, _, _) = import_one(core, block.clone(), Answer::Valid).await;
        assert_eq!(
            outcome,
            committed(&block),
            "call {on_call}: the block must be able to come again"
        );
    }
}
