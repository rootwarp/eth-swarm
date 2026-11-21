//! Tests of the state advance of block import through the chain core.
//!
//! A block more than `PRE_STATE_EPOCHS` epochs of slots after the state of its parent needs the
//! empty slots between them. The core walks them on a copy of the parent state, from the best
//! start: the parent state, or a checkpoint of an earlier walk from the same parent. The walk
//! is at most eight epochs of slots, and it stops one slot before the block. The core then
//! checks the proposer on the advanced state, and imports the block on it.
//!
//! The blocks come from the pinned minimal export. A test moves a block to a later slot: it sets
//! the slot of the block and of its bid, and the proposer of that slot, and it removes the
//! attestations and the payload attestations. A local transition gives the state root of the
//! moved block. The fake cl-verify gives each verdict, so no signature is checked.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod support;

use cl_chain::core::snapshot::PRE_STATE_EPOCHS;
use cl_chain::core::{ChainCore, Head, Outcome};
use cl_chain::import::block::PermitAll;
use cl_chain::verify::client::UnixClock;
use consensus_types::common::PendingDeposit;
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{BLSPubkey, Bytes32, Epoch};
use consensus_types::{EthSpec, Minimal};
use crypto_bls::{eth_aggregate_pubkeys, PublicKey};
use network_config::ChainConfig;
use state_transition::caches::proposer::get_beacon_proposer_index;
use state_transition::per_slot::process_slots;
use state_transition::{
    state_root, state_transition, AggregationError, BackendError, BlsContext, PubkeyAggregator,
    SignatureBackend, SignatureSet, StfError,
};
use std::time::Duration;
use support::{
    assert_unchanged, clock_at, export_block, fixture, import_one, proposer_set, slot_start,
    Answer, Fixture, VERIFY_TIMEOUT,
};
use testkit::anchor::fixtures::{pinned_export, AnchorFiles};
use testkit::anchor::load_anchor;
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

/// The most slots between the start of a walk and the block: eight epochs.
fn cap() -> u64 {
    8 * epoch_slots()
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
async fn a_bad_proposer_signature_after_the_walk_is_invalid_before_the_slot_loop() {
    let f = fixture();
    let wall = Wall::of(&f);
    let slot = window() + 4;
    let (block, before) = moved(&f.block, &anchor_state(&f), slot, &f.config);
    let block_root = block.message.tree_hash_root();
    let expected = proposer_set(&before, &block);
    let core = f.core.with_clock(wall.at(slot));
    let (outcome, core, verify) = import_one(core, block.clone(), Answer::Invalid).await;
    assert_eq!(outcome, Outcome::Invalid(StfError::InvalidBlockSignature));
    assert_eq!(
        verify.calls(),
        vec![vec![expected]],
        "only the proposer set of the advanced state must go to cl-verify, before the slot loop"
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
async fn an_out_of_range_proposer_after_the_walk_is_invalid_before_cl_verify() {
    let f = fixture();
    let wall = Wall::of(&f);
    let slot = window() + 4;
    let validators = anchor_state(&f).validators.len();
    let proposer = u64::try_from(validators).unwrap();
    let mut block = f.block.clone();
    block.message.slot = slot;
    block.message.proposer_index = proposer;
    let block_root = block.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(slot));
    let (outcome, core, verify) = import_one(core, block, Answer::Valid).await;
    assert_eq!(
        outcome,
        Outcome::Invalid(StfError::UnknownValidator(proposer))
    );
    assert!(verify.calls().is_empty());
    assert_unchanged(&core, f.anchor, block_root);
    assert!(core.is_refused(&block_root));
}

#[tokio::test(start_paused = true)]
async fn a_missing_proposer_verdict_after_the_walk_is_ignored_before_the_slot_loop() {
    for answer in [Answer::Never, Answer::Late, Answer::AtDeadline] {
        let f = fixture();
        let wall = Wall::of(&f);
        let slot = window() + 4;
        let (block, before) = moved(&f.block, &anchor_state(&f), slot, &f.config);
        let block_root = block.message.tree_hash_root();
        let expected = proposer_set(&before, &block);
        let core = f.core.with_clock(wall.at(slot));
        let (outcome, core, verify) = import_one(core, block.clone(), answer).await;
        assert!(
            matches!(outcome, Outcome::Ignored(_)),
            "{answer:?}: {outcome:?}"
        );
        assert_eq!(
            verify.calls(),
            vec![vec![expected]],
            "{answer:?}: only the proposer set must go to cl-verify, before the slot loop"
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

/// The fixture with a pending deposit of a new key in the anchor state. The first epoch
/// boundary after the anchor applies it. verify.v1 has no signer for a key that is not in the
/// registry, so the core has no verdict for that deposit. The slot 1 block has the new anchor as
/// its parent.
fn deposit_fixture() -> Fixture {
    let pinned = pinned_export().expect("the pinned export must open");
    let dir = tempfile::tempdir().unwrap();
    AnchorFiles::genesis(&pinned.export)
        .unwrap()
        .write(dir.path())
        .unwrap();
    let loaded = load_anchor::<Minimal>(dir.path()).expect("the anchor must load");
    let (mut state, mut block) = loaded.into_parts();
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

#[tokio::test]
async fn a_missing_deposit_verdict_in_the_walk_is_ignored_and_keeps_the_state_before_it() {
    let f = deposit_fixture();
    let wall = Wall::of(&f);
    let slot = window() + 4;
    let mut block = f.block.clone();
    block.message.slot = slot;
    let block_root = block.message.tree_hash_root();
    let core = f.core.with_clock(wall.at(slot));
    let (outcome, core, verify) = import_one(core, block, Answer::Valid).await;
    assert!(
        matches!(outcome, Outcome::Ignored(_)),
        "a walk without a deposit verdict must be IGNORE: {outcome:?}"
    );
    assert!(
        verify.calls().is_empty(),
        "the walk must stop before the proposer check"
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
