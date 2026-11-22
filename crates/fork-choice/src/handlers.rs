//! The handlers `on_tick` and `on_block`, their helpers, and `store_target_checkpoint_state`.
//! `on_attestation` and `on_attester_slashing` are in [`crate::attestations`].
//!
//! A handler that fails leaves the store as it was: "Invalid calls to handlers must not modify
//! `store`" (P0 L97-99). `on_block` computes every value that can fail before it changes the
//! store.

use crate::payload_attestation::ptc_votes;
use crate::store::{
    compute_slot_at_time_ms, compute_slots_since_epoch_start, compute_start_slot_at_epoch,
    compute_time_at_slot_ms, get_ancestor, get_checkpoint_block, get_current_slot,
    get_current_store_epoch, get_parent_payload_status, get_slot_component_duration_ms,
    get_time_into_slot_ms, is_payload_verified, key, prune, ptc_size, release_dropped,
    ForkChoiceNode, PayloadStatus, Store, ATTESTATION_TIMELINESS_INDEX, PTC_TIMELINESS_INDEX,
};
use crate::weights::get_head;
use crate::{Error, ATTESTATION_DUE_BPS_GLOAS, PAYLOAD_ATTESTATION_DUE_BPS};
use consensus_types::gloas::{BeaconState, Checkpoint, SignedBeaconBlock};
use consensus_types::primitives::{Root, Slot};
use state_transition::per_epoch::justification::process_justification_and_finalization;
use state_transition::{Preset, StfError};
use tree_hash::TreeHash;

/// The state transition that fork choice calls, with the signature checks of the caller.
/// Fork choice links no BLS library: a provider runs `state_transition` with its own
/// signature backend. A post-state must have passed `validate_result = true`.
pub trait StateProvider<E: Preset> {
    /// `state_transition(state, signed_block, validate_result=True)`. `state` is a copy of
    /// the parent's post-state; on `Err` the caller drops it.
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        signed_block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError>;

    /// `process_slots(state, slot)`, for [`store_target_checkpoint_state`].
    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError>;
}

/// `on_tick` (P0 L946-954): one `on_tick_per_slot` for each slot start up to `time_ms`, then
/// one at `time_ms`. A time before genesis fails and leaves the store as it was.
///
/// Then the store forgets the blocks that a prune dropped three or more epochs before the
/// current epoch (`store::release_dropped`). If the finalized checkpoint moved since the
/// last prune, it drops the blocks that do not descend from the finalized block
/// (`store::prune`), and keeps what `on_attestation` reads of them. This is not in the spec.
/// It does not change the result of `on_block` or of `get_head`, and `on_attestation` gives
/// the result of the spec until the store forgets the dropped blocks.
///
/// It is [`on_tick_unpruned`], then [`prune_after_tick`].
pub fn on_tick<E: Preset>(store: &mut Store<E>, time_ms: u64) -> Result<(), Error> {
    on_tick_unpruned(store, time_ms)?;
    prune_after_tick(store);
    Ok(())
}

/// The ticks of [`on_tick`] without its prune, for a caller that reads the blocks below the
/// checkpoints that the ticks moved before [`prune_after_tick`] can drop one of them
/// (`is_justified_on_invalid_payload`). Without [`prune_after_tick`] the store keeps each block,
/// as the spec's store does.
pub fn on_tick_unpruned<E: Preset>(store: &mut Store<E>, time_ms: u64) -> Result<(), Error> {
    let tick_slot = compute_slot_at_time_ms(store, time_ms)?;
    while get_current_slot(store) < tick_slot {
        let next_slot = get_current_slot(store) + 1;
        // At most `time_ms`, because `next_slot <= tick_slot`.
        let next_slot_time_ms =
            compute_time_at_slot_ms(store.genesis_time_ms, next_slot, store.slot_duration_ms)?;
        on_tick_per_slot(store, next_slot_time_ms);
    }
    on_tick_per_slot(store, time_ms);
    Ok(())
}

/// The end of [`on_tick`] after [`on_tick_unpruned`]: `store::release_dropped`, then
/// `store::prune`.
pub fn prune_after_tick<E: Preset>(store: &mut Store<E>) {
    release_dropped(store);
    prune(store);
}

/// `on_tick_per_slot` (P0 L792-808).
fn on_tick_per_slot<E: Preset>(store: &mut Store<E>, time_ms: u64) {
    let previous_slot = get_current_slot(store);
    store.time_ms = time_ms;
    let current_slot = get_current_slot(store);
    if current_slot > previous_slot {
        store.proposer_boost_root = Root::ZERO;
        if compute_slots_since_epoch_start::<E>(current_slot) == 0 {
            let justified = store.unrealized_justified_checkpoint.clone();
            let finalized = store.unrealized_finalized_checkpoint.clone();
            update_checkpoints(store, &justified, &finalized);
        }
    }
}

/// `update_checkpoints` (P0 L502-514).
fn update_checkpoints<E: Preset>(
    store: &mut Store<E>,
    justified_checkpoint: &Checkpoint,
    finalized_checkpoint: &Checkpoint,
) {
    if justified_checkpoint.epoch > store.justified_checkpoint.epoch {
        store.justified_checkpoint = justified_checkpoint.clone();
    }
    if finalized_checkpoint.epoch > store.finalized_checkpoint.epoch {
        store.finalized_checkpoint = finalized_checkpoint.clone();
    }
}

/// `update_unrealized_checkpoints` (P0 L520-534).
fn update_unrealized_checkpoints<E: Preset>(
    store: &mut Store<E>,
    unrealized_justified_checkpoint: &Checkpoint,
    unrealized_finalized_checkpoint: &Checkpoint,
) {
    if unrealized_justified_checkpoint.epoch > store.unrealized_justified_checkpoint.epoch {
        store.unrealized_justified_checkpoint = unrealized_justified_checkpoint.clone();
    }
    if unrealized_finalized_checkpoint.epoch > store.unrealized_finalized_checkpoint.epoch {
        store.unrealized_finalized_checkpoint = unrealized_finalized_checkpoint.clone();
    }
}

/// `on_block` (G L1044-1104).
///
/// A known block returns early and does not change the store. The spec's store keeps every
/// block, so a block that a prune dropped is a known block too, also after the store forgets
/// it ([`Store::is_known_block`]).
///
/// The spec order of the asserts is kept, the payload assert of G L1058-1061 included: a
/// block that builds on the FULL payload of its parent fails with
/// [`Error::ParentPayloadNotVerified`] until that payload is in `store.payloads`. Then the
/// provider runs the state transition, and the store takes the block only if every later
/// step can be computed.
pub fn on_block<E: Preset, P: StateProvider<E> + ?Sized>(
    store: &mut Store<E>,
    provider: &P,
    signed_block: &SignedBeaconBlock<E>,
) -> Result<(), Error> {
    let block = &signed_block.message;
    let block_root = block.tree_hash_root();
    if store.is_known_block(block_root) {
        return Ok(());
    }
    let parent_state = store
        .block_states
        .get(&block.parent_root)
        .ok_or(Error::UnknownParent(block.parent_root))?;
    // `is_parent_node_full` (G L378-379), kept for the index of children below.
    let parent_status = get_parent_payload_status(store, block)?;
    if parent_status == PayloadStatus::Full && !is_payload_verified(store, block.parent_root) {
        return Err(Error::ParentPayloadNotVerified(block.parent_root));
    }
    let current_slot = get_current_slot(store);
    if current_slot < block.slot {
        return Err(Error::FutureBlock {
            block: block.slot,
            current: current_slot,
        });
    }
    let finalized_slot = compute_start_slot_at_epoch::<E>(store.finalized_checkpoint.epoch)?;
    if block.slot <= finalized_slot {
        return Err(Error::NotAfterFinalized {
            block: block.slot,
            finalized: finalized_slot,
        });
    }
    let finalized_checkpoint_block =
        get_checkpoint_block(store, block.parent_root, store.finalized_checkpoint.epoch)?;
    if store.finalized_checkpoint.root != finalized_checkpoint_block {
        return Err(Error::NotFinalizedDescendant {
            finalized: store.finalized_checkpoint.root,
            checkpoint_block: finalized_checkpoint_block,
        });
    }
    let mut state = parent_state.clone();
    provider
        .state_transition(&mut state, signed_block)
        .map_err(Error::StateTransition)?;

    // Every value below that can fail is computed before the store changes.
    let head = get_head(store)?;
    let votes = ptc_votes(store, &state, &block.body.payload_attestations)?;
    let timeliness = block_timeliness(store, block.slot);
    let epoch = get_current_store_epoch(store);
    let head_dependent_root = get_shuffling_dependent_root(store, head.root, epoch)?;
    // `get_shuffling_dependent_root` of the new block, from its parent: the block itself
    // is not in the store yet.
    let dependent_slot = compute_shuffling_dependent_slot::<E>(epoch)?;
    let parent = ForkChoiceNode::new(block.parent_root, parent_status);
    let block_dependent_root = if block.slot > dependent_slot {
        get_ancestor(store, parent, dependent_slot)?.root
    } else {
        block_root
    };
    let realized = (
        state.current_justified_checkpoint.clone(),
        state.finalized_checkpoint.clone(),
    );
    // `compute_pulled_up_tip` (P0 L770-784): the post-state pulled up to the next epoch
    // boundary.
    let mut pulled_up = state.clone();
    process_justification_and_finalization(&mut pulled_up).map_err(Error::Stf)?;
    let unrealized = (
        pulled_up.current_justified_checkpoint,
        pulled_up.finalized_checkpoint,
    );

    store.blocks.insert(block_root, block.clone());
    store.block_states.insert(block_root, state);
    store.children.entry(parent).or_default().push(block_root);
    let no_votes = vec![None; ptc_size::<E>()];
    store
        .payload_timeliness_vote
        .insert(block_root, no_votes.clone());
    store
        .payload_data_availability_vote
        .insert(block_root, no_votes);
    // `notify_ptc_messages` (G L268-288).
    for vote in votes {
        vote.apply(store);
    }
    // `record_block_timeliness` (G L989-1000).
    store.block_timeliness.insert(block_root, timeliness);
    if timeliness[PTC_TIMELINESS_INDEX] {
        store
            .ptc_timely_proposals
            .entry((block.slot, block.proposer_index))
            .or_default()
            .push(block_root);
    }
    // `update_proposer_boost_root` (G L1019-1031).
    if timeliness[ATTESTATION_TIMELINESS_INDEX]
        && store.proposer_boost_root == Root::ZERO
        && head_dependent_root == block_dependent_root
    {
        store.proposer_boost_root = block_root;
    }
    update_checkpoints(store, &realized.0, &realized.1);
    // `compute_pulled_up_tip`.
    store
        .unrealized_justifications
        .insert(block_root, unrealized.0.clone());
    update_unrealized_checkpoints(store, &unrealized.0, &unrealized.1);
    if E::epoch_at_slot(block.slot) < epoch {
        update_checkpoints(store, &unrealized.0, &unrealized.1);
    }
    Ok(())
}

/// `compute_shuffling_dependent_slot` (P0 L902-912): the slot before the first slot of
/// `epoch - MIN_SEED_LOOKAHEAD`, both differences saturating at zero.
fn compute_shuffling_dependent_slot<E: Preset>(epoch: u64) -> Result<Slot, Error> {
    let lookahead_epoch = epoch.saturating_sub(state_transition::preset::MIN_SEED_LOOKAHEAD);
    Ok(compute_start_slot_at_epoch::<E>(lookahead_epoch)?.saturating_sub(1))
}

/// `get_shuffling_dependent_root` (G L1006-1013).
fn get_shuffling_dependent_root<E: Preset>(
    store: &Store<E>,
    root: Root,
    epoch: u64,
) -> Result<Root, Error> {
    let node = ForkChoiceNode::new(root, PayloadStatus::Pending);
    let dependent_slot = compute_shuffling_dependent_slot::<E>(epoch)?;
    Ok(get_ancestor(store, node, dependent_slot)?.root)
}

/// The value of `record_block_timeliness` (G L989-1000) for a block of `slot`: timely for the
/// attestation deadline and for the PTC deadline.
fn block_timeliness<E: Preset>(store: &Store<E>, slot: Slot) -> [bool; 2] {
    let is_current_slot = get_current_slot(store) == slot;
    let time_into_slot_ms = get_time_into_slot_ms(store);
    [ATTESTATION_DUE_BPS_GLOAS, PAYLOAD_ATTESTATION_DUE_BPS].map(|bps| {
        is_current_slot && time_into_slot_ms < get_slot_component_duration_ms(store, bps)
    })
}

/// `store_target_checkpoint_state` (P0 L860-866): the state of `target.root` advanced to the
/// first slot of `target.epoch`, kept in `store.checkpoint_states`. The target can be a block
/// that a prune dropped and the store keeps (`Store::dropped`).
pub fn store_target_checkpoint_state<E: Preset, P: StateProvider<E> + ?Sized>(
    store: &mut Store<E>,
    provider: &P,
    target: &Checkpoint,
) -> Result<(), Error> {
    if let Some(state) = target_checkpoint_state(store, provider, target)? {
        store.checkpoint_states.insert(key(target), state);
    }
    Ok(())
}

/// The state that `store_target_checkpoint_state` stores for `target`, or `None` if the store
/// has it. `on_attestation` stores it only once the attestation is valid.
pub(crate) fn target_checkpoint_state<E: Preset, P: StateProvider<E> + ?Sized>(
    store: &Store<E>,
    provider: &P,
    target: &Checkpoint,
) -> Result<Option<BeaconState<E>>, Error> {
    if store.checkpoint_states.contains_key(&key(target)) {
        return Ok(None);
    }
    let mut base_state = store.target_block_state(target.root)?.clone();
    let start_slot = compute_start_slot_at_epoch::<E>(target.epoch)?;
    if base_state.slot < start_slot {
        provider
            .process_slots(&mut base_state, start_slot)
            .map_err(Error::StateTransition)?;
    }
    Ok(Some(base_state))
}
