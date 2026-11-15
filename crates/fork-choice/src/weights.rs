//! Head selection: `get_head`, the filtered node tree, `get_weight` and the payload
//! tiebreaker, with the helpers that they call.
//!
//! The scores read `store.latest_messages` and `store.equivocating_indices`, which
//! `on_attestation` and `on_attester_slashing` fill. Those handlers are not here yet, so
//! outside the tests (the seams of `crate::testing`) both are empty: the attestation score of
//! each node is zero and only the proposer boost gives weight.

use crate::store::{
    get_checkpoint_block, get_current_slot, get_current_store_epoch, get_parent_payload_status,
    is_ancestor, is_parent_node_full, is_payload_verified, ptc_size, ForkChoiceNode, LatestMessage,
    PayloadStatus, Store, PTC_TIMELINESS_INDEX,
};
use crate::{Error, PROPOSER_SCORE_BOOST, REORG_HEAD_WEIGHT_THRESHOLD};
use consensus_types::gloas::{BeaconState, Checkpoint};
use consensus_types::primitives::{Gwei, Root, Slot};
use state_transition::accessors::{get_current_epoch, is_active_validator};
use state_transition::caches::CommitteeCache;
use state_transition::per_epoch::participation::get_total_balance;
use state_transition::Preset;
use std::collections::{BTreeSet, HashSet};

/// `GENESIS_EPOCH`.
const GENESIS_EPOCH: u64 = 0;

/// `get_head` (G L638-670).
pub fn get_head<E: Preset>(store: &Store<E>) -> Result<ForkChoiceNode, Error> {
    let nodes = get_filtered_node_tree(store)?;
    let justified_root = store.justified_checkpoint.root;
    if nodes.is_empty() {
        return Ok(ForkChoiceNode::new(justified_root, PayloadStatus::Empty));
    }
    let mut head = ForkChoiceNode::new(justified_root, PayloadStatus::Pending);
    loop {
        let mut best: Option<((Gwei, Root, u8), ForkChoiceNode)> = None;
        for child in get_node_children(store, &head)? {
            if !nodes.contains(&child) {
                continue;
            }
            let key = (
                get_weight(store, &child)?,
                child.root,
                get_payload_status_tiebreaker(store, &child)?,
            );
            if best.as_ref().is_none_or(|(best_key, _)| key > *best_key) {
                best = Some((key, child));
            }
        }
        match best {
            Some((_, child)) => head = child,
            None => return Ok(head),
        }
    }
}

/// `get_filtered_node_tree` (G L595-605): the viable nodes from the justified checkpoint.
/// The spec returns a sequence that callers use for membership only, so this is a set.
pub fn get_filtered_node_tree<E: Preset>(
    store: &Store<E>,
) -> Result<HashSet<ForkChoiceNode>, Error> {
    let base = ForkChoiceNode::new(store.justified_checkpoint.root, PayloadStatus::Pending);
    filter_node_tree(store, base)
}

/// `get_node_children` (G L614-628): the EMPTY node and, with a verified payload, the FULL
/// node of a PENDING node; else the PENDING nodes of the blocks that build on the payload
/// status of `node`.
pub fn get_node_children<E: Preset>(
    store: &Store<E>,
    node: &ForkChoiceNode,
) -> Result<Vec<ForkChoiceNode>, Error> {
    if node.payload_status == PayloadStatus::Pending {
        let mut children = vec![ForkChoiceNode::new(node.root, PayloadStatus::Empty)];
        if is_payload_verified(store, node.root) {
            children.push(ForkChoiceNode::new(node.root, PayloadStatus::Full));
        }
        return Ok(children);
    }
    let mut children = Vec::new();
    for (root, block) in &store.blocks {
        if block.parent_root == node.root
            && get_parent_payload_status(store, block)? == node.payload_status
        {
            children.push(ForkChoiceNode::new(*root, PayloadStatus::Pending));
        }
    }
    Ok(children)
}

/// `filter_node_tree` (P0 L427-467): a node is viable if a leaf below it is viable. An
/// explicit stack instead of the spec's recursion, so a long chain cannot overflow the
/// thread stack.
fn filter_node_tree<E: Preset>(
    store: &Store<E>,
    base: ForkChoiceNode,
) -> Result<HashSet<ForkChoiceNode>, Error> {
    struct Frame {
        node: ForkChoiceNode,
        children: Vec<ForkChoiceNode>,
        next: usize,
        any_viable: bool,
    }
    let frame = |node: ForkChoiceNode| -> Result<Frame, Error> {
        Ok(Frame {
            node,
            children: get_node_children(store, &node)?,
            next: 0,
            any_viable: false,
        })
    };
    let mut viable = HashSet::new();
    let mut stack = vec![frame(base)?];
    while let Some(top) = stack.last_mut() {
        if let Some(&child) = top.children.get(top.next) {
            top.next += 1;
            stack.push(frame(child)?);
            continue;
        }
        let node = top.node;
        let is_viable = if top.children.is_empty() {
            is_viable_leaf(store, &node)?
        } else {
            top.any_viable
        };
        stack.pop();
        if is_viable {
            viable.insert(node);
            if let Some(parent) = stack.last_mut() {
                parent.any_viable = true;
            }
        }
    }
    Ok(viable)
}

/// The leaf case of `filter_node_tree` (P0 L440-467): the voting source and the finalized
/// checkpoint block agree with the store.
fn is_viable_leaf<E: Preset>(store: &Store<E>, node: &ForkChoiceNode) -> Result<bool, Error> {
    let current_epoch = get_current_store_epoch(store);
    let voting_source = get_voting_source(store, node.root)?;
    let justified = &store.justified_checkpoint;
    let correct_justified = justified.epoch == GENESIS_EPOCH
        || voting_source.epoch == justified.epoch
        || voting_source.epoch.saturating_add(2) >= current_epoch;
    let finalized = &store.finalized_checkpoint;
    let correct_finalized = finalized.epoch == GENESIS_EPOCH
        || finalized.root == get_checkpoint_block(store, node.root, finalized.epoch)?;
    Ok(correct_justified && correct_finalized)
}

/// `get_voting_source` (P0 L397-410).
fn get_voting_source<E: Preset>(store: &Store<E>, block_root: Root) -> Result<Checkpoint, Error> {
    let block = store.get_block(block_root)?;
    if get_current_store_epoch(store) > E::epoch_at_slot(block.slot) {
        store
            .unrealized_justifications
            .get(&block_root)
            .cloned()
            .ok_or(Error::UnknownBlock(block_root))
    } else {
        Ok(store
            .get_block_state(block_root)?
            .current_justified_checkpoint
            .clone())
    }
}

/// `get_weight` (G L567-589).
pub fn get_weight<E: Preset>(store: &Store<E>, node: &ForkChoiceNode) -> Result<Gwei, Error> {
    if is_previous_slot_payload_decision(store, node)? {
        return Ok(0);
    }
    let state = store.justified_state()?;
    let attestation_score = get_attestation_score(store, node, state)?;
    if !should_apply_proposer_boost(store)? {
        return Ok(attestation_score);
    }
    let proposer_boost_node =
        ForkChoiceNode::new(store.proposer_boost_root, PayloadStatus::Pending);
    let proposer_score = if is_ancestor(store, proposer_boost_node, *node)? {
        calculate_committee_fraction(state, PROPOSER_SCORE_BOOST)?
    } else {
        0
    };
    attestation_score
        .checked_add(proposer_score)
        .ok_or(Error::Overflow)
}

/// `get_attestation_score` (P0 L338-356). It walks the latest messages instead of the
/// registry: the sum is the same, and the store has few messages or none.
fn get_attestation_score<E: Preset>(
    store: &Store<E>,
    node: &ForkChoiceNode,
    state: &BeaconState<E>,
) -> Result<Gwei, Error> {
    let epoch = get_current_epoch(state);
    let mut score: Gwei = 0;
    for (index, message) in &store.latest_messages {
        let Some(validator) = usize::try_from(*index)
            .ok()
            .and_then(|i| state.validators.get(i))
        else {
            continue;
        };
        if !is_active_validator(validator, epoch)
            || validator.slashed
            || store.equivocating_indices.contains(index)
        {
            continue;
        }
        if is_ancestor(store, get_supported_node(store, message)?, *node)? {
            score = score
                .checked_add(validator.effective_balance)
                .ok_or(Error::Overflow)?;
        }
    }
    Ok(score)
}

/// `get_supported_node` (G L436-451).
fn get_supported_node<E: Preset>(
    store: &Store<E>,
    message: &LatestMessage,
) -> Result<ForkChoiceNode, Error> {
    let block = store.get_block(message.root)?;
    let payload_status = if block.slot >= message.slot {
        PayloadStatus::Pending
    } else if message.payload_present {
        PayloadStatus::Full
    } else {
        PayloadStatus::Empty
    };
    Ok(ForkChoiceNode::new(message.root, payload_status))
}

/// `calculate_committee_fraction` (P0 L300-307). `compute_proposer_score` and
/// `get_proposer_score` (P0 L362-371) are this function with `PROPOSER_SCORE_BOOST` on the
/// justified state.
fn calculate_committee_fraction<E: Preset>(
    state: &BeaconState<E>,
    committee_percent: u64,
) -> Result<Gwei, Error> {
    let epoch = get_current_epoch(state);
    let indices: BTreeSet<u64> = state
        .validators
        .iter()
        .enumerate()
        .filter(|(_, v)| is_active_validator(v, epoch) && !v.slashed)
        .map(|(i, _)| i as u64)
        .collect();
    let total_balance = get_total_balance(state, &indices).map_err(Error::Stf)?;
    let committee_weight = total_balance / E::slots_per_epoch();
    committee_weight
        .checked_mul(committee_percent)
        .map(|w| w / 100)
        .ok_or(Error::Overflow)
}

/// `is_previous_slot_payload_decision` (G L461-464).
fn is_previous_slot_payload_decision<E: Preset>(
    store: &Store<E>,
    node: &ForkChoiceNode,
) -> Result<bool, Error> {
    let slot = store.get_block(node.root)?.slot;
    let is_previous_slot = slot.checked_add(1) == Some(get_current_slot(store));
    Ok(is_previous_slot && node.payload_status != PayloadStatus::Pending)
}

/// `payload_timeliness` (G L326-341) and `payload_data_availability` (G L347-362), which
/// differ only in the votes they count.
fn payload_vote<E: Preset>(
    store: &Store<E>,
    votes: &std::collections::HashMap<Root, Vec<Option<bool>>>,
    root: Root,
    value: bool,
) -> Result<bool, Error> {
    let votes = votes.get(&root).ok_or(Error::UnknownBlock(root))?;
    if !is_payload_verified(store, root) {
        return Ok(!value);
    }
    let count = votes.iter().filter(|v| **v == Some(value)).count();
    Ok(count > ptc_size::<E>() / 2)
}

/// `should_extend_payload` (G L497-509). Its spec assert (the block is of the previous
/// slot) holds at its one caller, [`get_payload_status_tiebreaker`].
fn should_extend_payload<E: Preset>(store: &Store<E>, root: Root) -> Result<bool, Error> {
    if !is_payload_verified(store, root) {
        return Ok(false);
    }
    let proposer_root = store.proposer_boost_root;
    let payload_is_timely = payload_vote(store, &store.payload_timeliness_vote, root, true)?;
    let payload_data_is_available =
        payload_vote(store, &store.payload_data_availability_vote, root, true)?;
    if (payload_is_timely && payload_data_is_available) || proposer_root == Root::ZERO {
        return Ok(true);
    }
    let proposer_block = store.get_block(proposer_root)?;
    Ok(proposer_block.parent_root != root || is_parent_node_full(store, proposer_block)?)
}

/// `get_payload_status_tiebreaker` (G L515-525).
fn get_payload_status_tiebreaker<E: Preset>(
    store: &Store<E>,
    node: &ForkChoiceNode,
) -> Result<u8, Error> {
    if !is_previous_slot_payload_decision(store, node)? {
        return Ok(node.payload_status as u8);
    }
    if node.payload_status == PayloadStatus::Empty {
        return Ok(1);
    }
    Ok(if should_extend_payload(store, node.root)? {
        2
    } else {
        0
    })
}

/// `should_apply_proposer_boost` (G L531-561).
fn should_apply_proposer_boost<E: Preset>(store: &Store<E>) -> Result<bool, Error> {
    if store.proposer_boost_root == Root::ZERO {
        return Ok(false);
    }
    let block = store.get_block(store.proposer_boost_root)?;
    let parent_root = block.parent_root;
    let parent = store.get_block(parent_root)?;
    let slot = block.slot;
    if parent.slot.saturating_add(1) < slot || !is_head_weak(store, parent_root)? {
        return Ok(true);
    }
    // A weak parent of the previous slot: boost only without an early equivocation.
    for (root, other) in &store.blocks {
        let timely = store
            .block_timeliness
            .get(root)
            .ok_or(Error::UnknownBlock(*root))?[PTC_TIMELINESS_INDEX];
        if timely
            && other.proposer_index == parent.proposer_index
            && other.slot.checked_add(1) == Some(slot)
            && *root != parent_root
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `is_head_weak` (G L810-832). The equivocation term needs the committees of the head slot
/// only when a validator equivocated; with none, the term is zero.
fn is_head_weak<E: Preset>(store: &Store<E>, head_root: Root) -> Result<bool, Error> {
    let justified_state = store.justified_state()?;
    let reorg_threshold =
        calculate_committee_fraction(justified_state, REORG_HEAD_WEIGHT_THRESHOLD)?;
    let head_block = store.get_block(head_root)?;
    let head_node = ForkChoiceNode::new(head_root, PayloadStatus::Pending);
    let mut head_weight = get_attestation_score(store, &head_node, justified_state)?;
    if !store.equivocating_indices.is_empty() {
        let head_state = store.get_block_state(head_root)?;
        let epoch = E::epoch_at_slot(head_block.slot);
        let committees = CommitteeCache::new(head_state, epoch).map_err(Error::Stf)?;
        for index in 0..committees.committees_per_slot() {
            let committee = committees
                .committee(head_block.slot, index)
                .map_err(Error::Stf)?;
            for validator_index in committee {
                if !store.equivocating_indices.contains(validator_index) {
                    continue;
                }
                let balance = usize::try_from(*validator_index)
                    .ok()
                    .and_then(|i| justified_state.validators.get(i))
                    .ok_or(Error::Stf(state_transition::StfError::UnknownValidator(
                        *validator_index,
                    )))?
                    .effective_balance;
                head_weight = head_weight.checked_add(balance).ok_or(Error::Overflow)?;
            }
        }
    }
    Ok(head_weight < reorg_threshold)
}

/// `is_valid_dependent_root` (G L732-744): `root` is, or can become, the latest block at or
/// before `dependent_slot` on some branch.
pub fn is_valid_dependent_root<E: Preset>(
    store: &Store<E>,
    root: Root,
    dependent_slot: Slot,
) -> Result<bool, Error> {
    if root == get_head(store)?.root {
        return Ok(true);
    }
    Ok(store
        .blocks
        .values()
        .any(|block| block.parent_root == root && block.slot > dependent_slot))
}
