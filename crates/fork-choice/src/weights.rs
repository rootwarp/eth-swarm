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
    PayloadStatus, Store,
};
use crate::{Error, PROPOSER_SCORE_BOOST, REORG_HEAD_WEIGHT_THRESHOLD};
use consensus_types::gloas::{BeaconBlock, BeaconState, Checkpoint};
use consensus_types::primitives::{Gwei, Root, Slot};
use state_transition::accessors::{get_current_epoch, is_active_validator};
use state_transition::caches::CommitteeCache;
use state_transition::per_epoch::participation::get_total_balance;
use state_transition::Preset;
use std::collections::{BTreeSet, HashMap, HashSet};

/// `GENESIS_EPOCH`.
const GENESIS_EPOCH: u64 = 0;

/// `get_head` (G L638-670). The parts of `get_weight` that are the same for each node are
/// computed once for the call (`Boost`), not once for each node.
pub fn get_head<E: Preset>(store: &Store<E>) -> Result<ForkChoiceNode, Error> {
    let nodes = get_filtered_node_tree(store)?;
    let justified_root = store.justified_checkpoint.root;
    if nodes.is_empty() {
        return Ok(ForkChoiceNode::new(justified_root, PayloadStatus::Empty));
    }
    let mut boost = None;
    let mut head = ForkChoiceNode::new(justified_root, PayloadStatus::Pending);
    loop {
        let mut best: Option<((Gwei, Root, u8), ForkChoiceNode)> = None;
        for child in get_node_children(store, &head)? {
            if !nodes.contains(&child) {
                continue;
            }
            let key = (
                weight(store, &child, &mut boost)?,
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
/// status of `node`, in the order of import. The blocks come from the index of children of
/// the store, which `on_block` fills with `get_parent_payload_status` of each block.
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
    let roots = store.children.get(node).map_or(&[][..], Vec::as_slice);
    Ok(roots
        .iter()
        .map(|root| ForkChoiceNode::new(*root, PayloadStatus::Pending))
        .collect())
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
    weight(store, node, &mut None)
}

/// `get_weight` with the [`Boost`] of the caller. `boost` is computed at the first node that
/// is not a payload decision of the previous slot (`is_previous_slot_payload_decision`). The
/// spec first reads the justified state and `should_apply_proposer_boost` at that node too, so
/// the call fails where the spec fails.
fn weight<E: Preset>(
    store: &Store<E>,
    node: &ForkChoiceNode,
    boost: &mut Option<Boost>,
) -> Result<Gwei, Error> {
    if is_previous_slot_payload_decision(store, node)? {
        return Ok(0);
    }
    let state = store.justified_state()?;
    let attestation_score = get_attestation_score(store, node, state)?;
    let boost = match boost {
        Some(boost) => boost,
        None => boost.insert(Boost::new(store, state)?),
    };
    let proposer_score = boost.proposer_score(node)?;
    attestation_score
        .checked_add(proposer_score)
        .ok_or(Error::Overflow)
}

/// The proposer boost part of `get_weight` (G L578-588), which does not depend on the node.
enum Boost {
    /// `should_apply_proposer_boost` is false.
    Off,
    On {
        /// The status of each block on the chain of the PENDING node of the boosted block
        /// down to the anchor: the root and the status of `get_ancestor(boost_node, slot)`
        /// for each slot. With it, `is_ancestor(boost_node, node)` is a lookup.
        chain: HashMap<Root, PayloadStatus>,
        /// `calculate_committee_fraction(justified_state, PROPOSER_SCORE_BOOST)`. The spec
        /// computes it only for an ancestor of the boosted block, so an error waits for one.
        score: Result<Gwei, Error>,
    },
}

impl Boost {
    fn new<E: Preset>(store: &Store<E>, state: &BeaconState<E>) -> Result<Self, Error> {
        let root = store.proposer_boost_root;
        if !should_apply_proposer_boost(store)? {
            return Ok(Self::Off);
        }
        let mut chain = HashMap::new();
        let mut node = ForkChoiceNode::new(root, PayloadStatus::Pending);
        loop {
            chain.insert(node.root, node.payload_status);
            let block = store.get_block(node.root)?;
            if node.root == store.anchor_root {
                break;
            }
            node = ForkChoiceNode::new(block.parent_root, get_parent_payload_status(store, block)?);
        }
        let score = calculate_committee_fraction(state, PROPOSER_SCORE_BOOST);
        Ok(Self::On { chain, score })
    }

    /// The proposer score of `node`: `is_ancestor(boost_node, node)` (G L406-415) gives the
    /// score, else zero. `node.root` is in the store.
    fn proposer_score(&self, node: &ForkChoiceNode) -> Result<Gwei, Error> {
        let Self::On { chain, score } = self else {
            return Ok(0);
        };
        let is_ancestor = chain.get(&node.root).is_some_and(|status| {
            node.payload_status == *status || node.payload_status == PayloadStatus::Pending
        });
        if is_ancestor {
            score.clone()
        } else {
            Ok(0)
        }
    }
}

/// `get_attestation_score` (P0 L338-356). It walks the latest messages instead of the
/// registry: the sum is the same, and the store has few messages or none.
///
/// A message for a block that the store does not have counts for no node. Only a prune
/// drops a block that a message names, and such a block is not a descendant of the
/// finalized block, so in the spec's store, which keeps it, the message supports no node
/// that the pruned store keeps.
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
        let Some(block) = store.blocks.get(&message.root) else {
            continue;
        };
        if is_ancestor(store, get_supported_node(block, message), *node)? {
            score = score
                .checked_add(validator.effective_balance)
                .ok_or(Error::Overflow)?;
        }
    }
    Ok(score)
}

/// `get_supported_node` (G L436-451). `block` is `store.blocks[message.root]`.
fn get_supported_node<E: Preset>(
    block: &BeaconBlock<E>,
    message: &LatestMessage,
) -> ForkChoiceNode {
    let payload_status = if block.slot >= message.slot {
        PayloadStatus::Pending
    } else if message.payload_present {
        PayloadStatus::Full
    } else {
        PayloadStatus::Empty
    };
    ForkChoiceNode::new(message.root, payload_status)
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
    votes: &HashMap<Root, Vec<Option<bool>>>,
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
    // A weak parent of the previous slot: boost only without an early equivocation, a block
    // of the parent's slot and proposer that was timely for the PTC deadline.
    let early_equivocation = slot.checked_sub(1).is_some_and(|previous_slot| {
        store
            .ptc_timely_proposals
            .get(&(previous_slot, parent.proposer_index))
            .is_some_and(|roots| roots.iter().any(|root| *root != parent_root))
    });
    Ok(!early_equivocation)
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
/// before `dependent_slot` on some branch. The spec scans `store.blocks` for a child of
/// `root`. The index of children has every block but the anchor, whose parent is not in the
/// store, so the edge from the anchor to its parent is checked first.
pub fn is_valid_dependent_root<E: Preset>(
    store: &Store<E>,
    root: Root,
    dependent_slot: Slot,
) -> Result<bool, Error> {
    if root == get_head(store)?.root {
        return Ok(true);
    }
    // A root only on a branch that a prune dropped for a conflict with finality is false
    // here and true in the spec's store. That branch cannot become canonical.
    let anchor = store.get_block(store.anchor_root)?;
    if anchor.parent_root == root && anchor.slot > dependent_slot {
        return Ok(true);
    }
    for payload_status in [PayloadStatus::Empty, PayloadStatus::Full] {
        let parent = ForkChoiceNode::new(root, payload_status);
        for child in get_node_children(store, &parent)? {
            if store.get_block(child.root)?.slot > dependent_slot {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
