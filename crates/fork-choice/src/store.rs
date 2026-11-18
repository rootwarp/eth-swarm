//! The Gloas `Store`, `get_forkchoice_store`, the time helpers and the ancestry helpers.
//!
//! Line references: G `specs/gloas/fork-choice.md`, P0 `specs/phase0/fork-choice.md`, P0b
//! `specs/phase0/beacon-chain.md`, all at v1.7.0-beta.4.

use crate::Error;
use consensus_types::gloas::{BeaconBlock, BeaconState, Checkpoint};
use consensus_types::primitives::{Epoch, Root, Slot, ValidatorIndex};
use ssz_types::typenum::Unsigned;
use state_transition::accessors::get_current_epoch;
use state_transition::{state_root, Preset};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::num::NonZeroU64;
use tree_hash::TreeHash;

/// `PayloadStatus` with the values of `PAYLOAD_STATUS_*` (G L79-83, L103-105).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadStatus {
    /// `PAYLOAD_STATUS_EMPTY`.
    Empty = 0,
    /// `PAYLOAD_STATUS_FULL`.
    Full = 1,
    /// `PAYLOAD_STATUS_PENDING`.
    Pending = 2,
}

/// `ForkChoiceNode` (G L154-157): a block root and the status of its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForkChoiceNode {
    /// The block root.
    pub root: Root,
    /// The payload status.
    pub payload_status: PayloadStatus,
}

impl ForkChoiceNode {
    pub(crate) fn new(root: Root, payload_status: PayloadStatus) -> Self {
        Self {
            root,
            payload_status,
        }
    }
}

/// `LatestMessage` (G L182-185): the latest attestation of a validator, which
/// `on_attestation` sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestMessage {
    /// The attestation slot.
    pub slot: Slot,
    /// The attested block root.
    pub root: Root,
    /// `attestation.data.index == 1`.
    pub payload_present: bool,
}

/// `ATTESTATION_TIMELINESS_INDEX` (G L106).
pub(crate) const ATTESTATION_TIMELINESS_INDEX: usize = 0;
/// `PTC_TIMELINESS_INDEX` (G L107).
pub(crate) const PTC_TIMELINESS_INDEX: usize = 1;

/// `Store` (G L192-213). The fields are private: only the handlers change them, which keeps
/// each per-block map keyed by the same roots as `blocks`.
///
/// `anchor_root` is not a spec field. It is the root of the anchor block, the one block of the
/// store whose parent is not in the store: the ancestor walk stops there ([`get_ancestor`]).
///
/// `children` and `ptc_timely_proposals` are not spec fields. They are indexes of `blocks`,
/// so that head selection reads the blocks that it needs and does not scan every block for
/// each node. `children` maps an EMPTY or a FULL node to the roots of the blocks that build
/// on it, in the order of import (the order of the spec's dict). It never has a PENDING key.
/// `ptc_timely_proposals` maps a slot and a proposer to the roots of the blocks of that slot
/// and proposer that were timely for the PTC deadline (`block_timeliness[root][1]`).
///
/// `slot_duration_ms` is the config value `SLOT_DURATION_MS`, the one config value of fork
/// choice that differs between the presets ([`crate::config_values`] lists the others).
/// `payloads` holds the roots only: fork choice reads only `root in store.payloads`.
/// `checkpoint_states` is keyed by `(epoch, root)`.
///
/// `PartialEq` compares every field, so a caller can check that a refused call left the store
/// as it was.
#[derive(Debug, Clone, PartialEq)]
pub struct Store<E: Preset> {
    pub(crate) slot_duration_ms: NonZeroU64,
    pub(crate) anchor_root: Root,
    pub(crate) time_ms: u64,
    pub(crate) genesis_time_ms: u64,
    pub(crate) justified_checkpoint: Checkpoint,
    pub(crate) finalized_checkpoint: Checkpoint,
    pub(crate) unrealized_justified_checkpoint: Checkpoint,
    pub(crate) unrealized_finalized_checkpoint: Checkpoint,
    pub(crate) proposer_boost_root: Root,
    pub(crate) equivocating_indices: BTreeSet<ValidatorIndex>,
    pub(crate) blocks: HashMap<Root, BeaconBlock<E>>,
    pub(crate) block_states: HashMap<Root, BeaconState<E>>,
    pub(crate) block_timeliness: HashMap<Root, [bool; 2]>,
    pub(crate) checkpoint_states: HashMap<(Epoch, Root), BeaconState<E>>,
    pub(crate) latest_messages: BTreeMap<ValidatorIndex, LatestMessage>,
    pub(crate) unrealized_justifications: HashMap<Root, Checkpoint>,
    pub(crate) payloads: HashSet<Root>,
    pub(crate) payload_timeliness_vote: HashMap<Root, Vec<Option<bool>>>,
    pub(crate) payload_data_availability_vote: HashMap<Root, Vec<Option<bool>>>,
    pub(crate) children: HashMap<ForkChoiceNode, Vec<Root>>,
    pub(crate) ptc_timely_proposals: BTreeMap<(Slot, ValidatorIndex), Vec<Root>>,
}

impl<E: Preset> Store<E> {
    /// `store.time_ms`.
    pub fn time_ms(&self) -> u64 {
        self.time_ms
    }

    /// `store.genesis_time_ms`.
    pub fn genesis_time_ms(&self) -> u64 {
        self.genesis_time_ms
    }

    /// `store.justified_checkpoint`.
    pub fn justified_checkpoint(&self) -> &Checkpoint {
        &self.justified_checkpoint
    }

    /// `store.finalized_checkpoint`.
    pub fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
    }

    /// `store.unrealized_justified_checkpoint`.
    pub fn unrealized_justified_checkpoint(&self) -> &Checkpoint {
        &self.unrealized_justified_checkpoint
    }

    /// `store.unrealized_finalized_checkpoint`.
    pub fn unrealized_finalized_checkpoint(&self) -> &Checkpoint {
        &self.unrealized_finalized_checkpoint
    }

    /// `store.proposer_boost_root`.
    pub fn proposer_boost_root(&self) -> Root {
        self.proposer_boost_root
    }

    /// `store.blocks[root]`.
    pub fn block(&self, root: Root) -> Option<&BeaconBlock<E>> {
        self.blocks.get(&root)
    }

    /// `store.block_states[root]`.
    pub fn block_state(&self, root: Root) -> Option<&BeaconState<E>> {
        self.block_states.get(&root)
    }

    /// `store.checkpoint_states[checkpoint]`.
    pub fn checkpoint_state(&self, checkpoint: &Checkpoint) -> Option<&BeaconState<E>> {
        self.checkpoint_states.get(&key(checkpoint))
    }

    /// `store.latest_messages[validator_index]`.
    pub fn latest_message(&self, validator_index: ValidatorIndex) -> Option<&LatestMessage> {
        self.latest_messages.get(&validator_index)
    }

    /// `store.equivocating_indices`.
    pub fn equivocating_indices(&self) -> &BTreeSet<ValidatorIndex> {
        &self.equivocating_indices
    }

    /// `store.block_timeliness[root]`: timely for the attestation deadline, then for the PTC
    /// deadline.
    pub fn block_timeliness(&self, root: Root) -> Option<[bool; 2]> {
        self.block_timeliness.get(&root).copied()
    }

    /// `store.payload_timeliness_vote[root]`, by PTC position.
    pub fn payload_timeliness_vote(&self, root: Root) -> Option<&[Option<bool>]> {
        self.payload_timeliness_vote.get(&root).map(Vec::as_slice)
    }

    /// `store.payload_data_availability_vote[root]`, by PTC position.
    pub fn payload_data_availability_vote(&self, root: Root) -> Option<&[Option<bool>]> {
        self.payload_data_availability_vote
            .get(&root)
            .map(Vec::as_slice)
    }

    pub(crate) fn get_block(&self, root: Root) -> Result<&BeaconBlock<E>, Error> {
        self.blocks.get(&root).ok_or(Error::UnknownBlock(root))
    }

    pub(crate) fn get_block_state(&self, root: Root) -> Result<&BeaconState<E>, Error> {
        self.block_states
            .get(&root)
            .ok_or(Error::UnknownBlock(root))
    }

    /// `store.checkpoint_states[store.justified_checkpoint]`.
    pub(crate) fn justified_state(&self) -> Result<&BeaconState<E>, Error> {
        let checkpoint = &self.justified_checkpoint;
        self.checkpoint_states
            .get(&key(checkpoint))
            .ok_or(Error::MissingCheckpointState {
                epoch: checkpoint.epoch,
                root: checkpoint.root,
            })
    }
}

/// The `checkpoint_states` key of a checkpoint.
pub(crate) fn key(checkpoint: &Checkpoint) -> (Epoch, Root) {
    (checkpoint.epoch, checkpoint.root)
}

/// `PTC_SIZE`.
pub(crate) fn ptc_size<E: Preset>() -> usize {
    E::PtcSize::to_usize()
}

/// `get_forkchoice_store` (G L219-248). `slot_duration_ms` is the config value
/// `SLOT_DURATION_MS`.
pub fn get_forkchoice_store<E: Preset>(
    mut anchor_state: BeaconState<E>,
    anchor_block: BeaconBlock<E>,
    slot_duration_ms: NonZeroU64,
) -> Result<Store<E>, Error> {
    let state_root = state_root(&mut anchor_state).map_err(Error::Stf)?;
    if anchor_block.state_root != state_root {
        return Err(Error::AnchorStateRoot {
            block: anchor_block.state_root,
            state: state_root,
        });
    }
    let anchor_root = anchor_block.tree_hash_root();
    let anchor_epoch = get_current_epoch(&anchor_state);
    let justified_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };
    let finalized_checkpoint = justified_checkpoint.clone();
    let genesis_time_ms = seconds_to_milliseconds(anchor_state.genesis_time);
    let time_ms = compute_time_at_slot_ms(genesis_time_ms, anchor_state.slot, slot_duration_ms)?;
    let votes = vec![None; ptc_size::<E>()];
    // The anchor is timely for both deadlines.
    let anchor_proposal = (anchor_block.slot, anchor_block.proposer_index);
    Ok(Store {
        slot_duration_ms,
        anchor_root,
        time_ms,
        genesis_time_ms,
        unrealized_justified_checkpoint: justified_checkpoint.clone(),
        unrealized_finalized_checkpoint: finalized_checkpoint.clone(),
        proposer_boost_root: Root::ZERO,
        equivocating_indices: BTreeSet::new(),
        blocks: HashMap::from([(anchor_root, anchor_block)]),
        block_states: HashMap::from([(anchor_root, anchor_state.clone())]),
        block_timeliness: HashMap::from([(anchor_root, [true, true])]),
        checkpoint_states: HashMap::from([(key(&justified_checkpoint), anchor_state)]),
        latest_messages: BTreeMap::new(),
        unrealized_justifications: HashMap::from([(anchor_root, justified_checkpoint.clone())]),
        payloads: HashSet::new(),
        payload_timeliness_vote: HashMap::from([(anchor_root, votes.clone())]),
        payload_data_availability_vote: HashMap::from([(anchor_root, votes)]),
        children: HashMap::new(),
        ptc_timely_proposals: BTreeMap::from([(anchor_proposal, vec![anchor_root])]),
        justified_checkpoint,
        finalized_checkpoint,
    })
}

/// `seconds_to_milliseconds` (P0 L550-557): `UINT64_MAX` on overflow.
pub fn seconds_to_milliseconds(seconds: u64) -> u64 {
    seconds.saturating_mul(1000)
}

/// `milliseconds_to_seconds` (P0 L563-567).
pub fn milliseconds_to_seconds(milliseconds: u64) -> u64 {
    milliseconds / 1000
}

/// `compute_time_at_slot_ms` (P0b L1316-1320).
pub(crate) fn compute_time_at_slot_ms(
    genesis_time_ms: u64,
    slot: Slot,
    slot_duration_ms: NonZeroU64,
) -> Result<u64, Error> {
    slot.checked_mul(slot_duration_ms.get())
        .and_then(|ms| ms.checked_add(genesis_time_ms))
        .ok_or(Error::Overflow)
}

/// `compute_slot_at_time_ms` (P0b L1326-1330). A time before genesis fails the `Uint64`
/// subtraction of the spec.
pub(crate) fn compute_slot_at_time_ms<E: Preset>(
    store: &Store<E>,
    time_ms: u64,
) -> Result<Slot, Error> {
    let since = time_ms
        .checked_sub(store.genesis_time_ms)
        .ok_or(Error::BeforeGenesis {
            time_ms,
            genesis_time_ms: store.genesis_time_ms,
        })?;
    Ok(since / store.slot_duration_ms.get())
}

/// `compute_start_slot_at_epoch` (P0b L1346-1350), with the `Uint64` overflow as an error.
pub(crate) fn compute_start_slot_at_epoch<E: Preset>(epoch: Epoch) -> Result<Slot, Error> {
    epoch
        .checked_mul(E::slots_per_epoch())
        .ok_or(Error::Overflow)
}

/// `get_slot_component_duration_ms` (P0 L573-577).
pub(crate) fn get_slot_component_duration_ms<E: Preset>(store: &Store<E>, bps: u64) -> u64 {
    // At most `slot_duration_ms` for `bps <= BASIS_POINTS`, so the product fits in u128 and
    // the quotient in u64.
    let ms = u128::from(bps) * u128::from(store.slot_duration_ms.get())
        / u128::from(crate::BASIS_POINTS);
    u64::try_from(ms).unwrap_or(u64::MAX)
}

/// `get_slots_since_genesis` (P0 L254-255). The store time is never before genesis: the
/// anchor time is not, and `on_tick` refuses a time before genesis.
pub fn get_slots_since_genesis<E: Preset>(store: &Store<E>) -> Slot {
    store.time_ms.saturating_sub(store.genesis_time_ms) / store.slot_duration_ms.get()
}

/// `get_current_slot` (P0 L261-262).
pub fn get_current_slot<E: Preset>(store: &Store<E>) -> Slot {
    get_slots_since_genesis(store)
}

/// `get_current_store_epoch` (P0 L268-269).
pub fn get_current_store_epoch<E: Preset>(store: &Store<E>) -> Epoch {
    E::epoch_at_slot(get_current_slot(store))
}

/// `get_time_into_slot_ms` (P0 L247-248).
pub fn get_time_into_slot_ms<E: Preset>(store: &Store<E>) -> u64 {
    // The start of the current slot is at or before `store.time_ms`.
    let slot_start = get_current_slot(store) * store.slot_duration_ms.get();
    store
        .time_ms
        .saturating_sub(store.genesis_time_ms)
        .saturating_sub(slot_start)
}

/// `compute_slots_since_epoch_start` (P0 L275-276).
pub fn compute_slots_since_epoch_start<E: Preset>(slot: Slot) -> Slot {
    slot % E::slots_per_epoch()
}

/// `is_payload_verified` (G L314-320).
pub fn is_payload_verified<E: Preset>(store: &Store<E>, root: Root) -> bool {
    store.payloads.contains(&root)
}

/// `get_parent_payload_status` (G L368-372): FULL when the bid of `block` builds on the block
/// hash of the bid of its parent.
pub fn get_parent_payload_status<E: Preset>(
    store: &Store<E>,
    block: &BeaconBlock<E>,
) -> Result<PayloadStatus, Error> {
    let parent = store.get_block(block.parent_root)?;
    let parent_block_hash = block
        .body
        .signed_execution_payload_bid
        .message
        .parent_block_hash;
    let message_block_hash = parent.body.signed_execution_payload_bid.message.block_hash;
    Ok(if parent_block_hash == message_block_hash {
        PayloadStatus::Full
    } else {
        PayloadStatus::Empty
    })
}

/// `is_parent_node_full` (G L378-379).
pub fn is_parent_node_full<E: Preset>(
    store: &Store<E>,
    block: &BeaconBlock<E>,
) -> Result<bool, Error> {
    Ok(get_parent_payload_status(store, block)? == PayloadStatus::Full)
}

/// `get_ancestor` (G L388-397): the node of the chain of `node` at `slot`, with the payload
/// status that its child builds on. A loop instead of the spec's recursion.
///
/// The walk stops at the anchor, also for a `slot` before it: the store has no block below
/// the anchor, and the spec's walk would fail on the parent of a non-genesis anchor (a
/// checkpoint sync) for each slot before it, for example the shuffling dependent slot of the
/// first two epochs after the anchor. Production clients also stop at their oldest block.
/// The node of the anchor keeps the payload status that its child builds on.
pub fn get_ancestor<E: Preset>(
    store: &Store<E>,
    mut node: ForkChoiceNode,
    slot: Slot,
) -> Result<ForkChoiceNode, Error> {
    loop {
        let block = store.get_block(node.root)?;
        if block.slot <= slot || node.root == store.anchor_root {
            return Ok(node);
        }
        node = ForkChoiceNode::new(block.parent_root, get_parent_payload_status(store, block)?);
    }
}

/// `is_ancestor` (G L406-415): a PENDING `ancestor` matches either payload status.
pub fn is_ancestor<E: Preset>(
    store: &Store<E>,
    node: ForkChoiceNode,
    ancestor: ForkChoiceNode,
) -> Result<bool, Error> {
    let slot = store.get_block(ancestor.root)?.slot;
    let node_ancestor = get_ancestor(store, node, slot)?;
    Ok(node_ancestor.root == ancestor.root
        && (node_ancestor.payload_status == ancestor.payload_status
            || ancestor.payload_status == PayloadStatus::Pending))
}

/// Not a spec function: drops what the store does not need once finality moves. `on_tick`
/// calls it, so the store prunes at the first tick after `on_block` or a tick moves the
/// finalized checkpoint.
///
/// It keeps the finalized checkpoint block and its descendants, and drops every other block
/// with the per-block entries of each, the index of children of each, and the checkpoint
/// states of earlier epochs or of dropped blocks. The finalized block becomes the anchor, so
/// the ancestor walk stops there ([`get_ancestor`]). Latest messages and equivocating
/// indices stay as the spec keeps them.
///
/// The spec's store keeps every block, and `get_head`, `get_weight` and the asserts of
/// `on_block` give the same result on the pruned store:
/// - The filtered tree starts at the justified block, a descendant of the finalized block,
///   and every walk up from a descendant stops at or above the finalized block.
/// - A message for a dropped block supports no node of the subtree ([`crate::get_weight`]).
/// - A block on a dropped block fails with [`crate::Error::UnknownParent`], where the spec's
///   store fails the finalized descendant assert.
/// - The PTC-timely proposals of the previous slot and later stay, also of dropped blocks,
///   for the early equivocation check of a later boost.
///
/// If the finalized block is not in the store, or the justified or the unrealized justified
/// block does not descend from it, nothing is dropped: the walks of the subtree of that
/// block need the blocks below the finalized block. Nothing is dropped either while the
/// proposer boost names a block that does not descend from it: `should_extend_payload` and
/// `should_apply_proposer_boost` read `store.blocks[store.proposer_boost_root]`. The boost
/// is of the current slot, so the first tick of the next slot clears it and then prunes.
pub(crate) fn prune<E: Preset>(store: &mut Store<E>) {
    let finalized = store.finalized_checkpoint.clone();
    if finalized.root == store.anchor_root || !store.blocks.contains_key(&finalized.root) {
        return;
    }
    let mut keep = HashSet::from([finalized.root]);
    let mut next = vec![finalized.root];
    while let Some(root) = next.pop() {
        for payload_status in [PayloadStatus::Empty, PayloadStatus::Full] {
            let node = ForkChoiceNode::new(root, payload_status);
            for child in store.children.get(&node).into_iter().flatten() {
                if keep.insert(*child) {
                    next.push(*child);
                }
            }
        }
    }
    let justified = [
        &store.justified_checkpoint,
        &store.unrealized_justified_checkpoint,
    ];
    let boost = store.proposer_boost_root;
    if justified.iter().any(|c| !keep.contains(&c.root))
        || (boost != Root::ZERO && !keep.contains(&boost))
    {
        return;
    }
    store.blocks.retain(|root, _| keep.contains(root));
    store.block_states.retain(|root, _| keep.contains(root));
    store.block_timeliness.retain(|root, _| keep.contains(root));
    store
        .unrealized_justifications
        .retain(|root, _| keep.contains(root));
    store.payloads.retain(|root| keep.contains(root));
    store
        .payload_timeliness_vote
        .retain(|root, _| keep.contains(root));
    store
        .payload_data_availability_vote
        .retain(|root, _| keep.contains(root));
    store.children.retain(|node, _| keep.contains(&node.root));
    store
        .checkpoint_states
        .retain(|(epoch, root), _| *epoch >= finalized.epoch && keep.contains(root));
    // A later boosted block is of the current slot or later, so the check reads the
    // previous slot or later.
    let first_slot = get_current_slot(store).saturating_sub(1);
    store.ptc_timely_proposals = store.ptc_timely_proposals.split_off(&(first_slot, 0));
    store.anchor_root = finalized.root;
}

/// `get_checkpoint_block` (G L421-428).
pub fn get_checkpoint_block<E: Preset>(
    store: &Store<E>,
    root: Root,
    epoch: Epoch,
) -> Result<Root, Error> {
    let epoch_first_slot = compute_start_slot_at_epoch::<E>(epoch)?;
    let node = ForkChoiceNode::new(root, PayloadStatus::Pending);
    Ok(get_ancestor(store, node, epoch_first_slot)?.root)
}
