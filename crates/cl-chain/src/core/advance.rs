//! The walk of the chain core over the empty slots between the pre-state of a parent and a
//! block far after it (`advance`), and the states that the walk keeps ([`Advanced`]).
//!
//! The core keeps the pre-states of [`PRE_STATE_EPOCHS`] epochs of slots, and the anchor for
//! good. A block more than [`PRE_STATE_EPOCHS`] epochs of slots after the pre-state of its
//! parent first needs `process_slots` over the empty slots between them. `advance` runs it on
//! a copy, from the best start: the latest state that [`Advanced`] keeps for that parent before
//! the block slot, else the pre-state of the parent. The walk stops at the slot before the
//! block, because `state_transition` runs `process_slots` again and that function needs a
//! state slot before the block slot.
//!
//! The walk has its own bounds. The wall-clock bound of the core does not stop a block at the
//! slot of the wall clock on an old pre-state, so:
//!
//! - a start more than [`MAX_ADVANCE_EPOCHS`] epochs of slots before the block is IGNORE at
//!   once, with no `process_slots`;
//! - before the walk, and before each epoch boundary, the walk checks the deadline of the
//!   import. The deposit verdicts of an epoch boundary go to cl-verify with that deadline.
//!
//! At the last slot of each epoch that it reaches, the walk keeps a copy of its state in
//! [`Advanced`], by the root of the parent and the epoch after that slot. A walk that stops
//! (the deadline, no deposit verdict, an error) keeps the states it reached. A later walk from
//! the same parent starts from the latest of them, so it does not walk those slots again.
//!
//! No refusal of the walk is a proof about the block: each is IGNORE, and the core does not
//! keep it. The block can import later from a nearer state, or with more time.
//!
//! [`PRE_STATE_EPOCHS`]: super::snapshot::PRE_STATE_EPOCHS

use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Epoch, Root, Slot};
use state_transition::Preset;

/// The most epochs of slots between the start of a walk and the block \[est\]: 64 slots on
/// the minimal preset, 256 on mainnet (about 51 minutes).
pub const MAX_ADVANCE_EPOCHS: u64 = 8;

/// The most states that the walks keep \[est\]. Past it, the least recently used goes first.
pub const MAX_ADVANCED_STATES: usize = 64;

/// `process_slots` on a state to a slot. `Err` (why, for the log) is IGNORE.
pub(crate) type Walk<'a, E> = dyn Fn(&mut BeaconState<E>, Slot) -> Result<(), String> + 'a;

/// The states that the walks keep, by the root of the parent and an epoch: the post-state of
/// the parent advanced to the last slot of the epoch before. At most `max`; past the bound,
/// the least recently used goes first. A state that left is computed again by a later walk.
#[derive(Debug)]
pub struct Advanced<S> {
    /// Least recently used first.
    entries: Vec<((Root, Epoch), S)>,
    /// At least 1.
    max: usize,
}

impl<S> Advanced<S> {
    /// Room for `max` states (at least 1).
    pub fn new(max: usize) -> Self {
        Self {
            entries: Vec::new(),
            max: max.max(1),
        }
    }

    /// The state of `parent` at the last slot of epoch `epoch - 1`. The order of use does not
    /// change.
    pub fn peek(&self, parent: &Root, epoch: Epoch) -> Option<&S> {
        self.entries
            .iter()
            .find(|(key, _)| *key == (*parent, epoch))
            .map(|(_, state)| state)
    }

    /// The state of `parent` with the latest epoch up to `epoch`, now the most recently used.
    pub fn latest(&mut self, parent: &Root, epoch: Epoch) -> Option<&S> {
        let at = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, ((root, kept), _))| root == parent && *kept <= epoch)
            .max_by_key(|(_, ((_, kept), _))| *kept)
            .map(|(at, _)| at)?;
        let entry = self.entries.remove(at);
        self.entries.push(entry);
        self.entries.last().map(|(_, state)| state)
    }

    /// Keeps `state` as the state of `parent` at the last slot of epoch `epoch - 1`, the most
    /// recently used. It replaces an earlier state with the same key. Past the bound, the least
    /// recently used goes.
    pub fn insert(&mut self, parent: Root, epoch: Epoch, state: S) {
        self.entries.retain(|(key, _)| *key != (parent, epoch));
        self.entries.push(((parent, epoch), state));
        if self.entries.len() > self.max {
            self.entries.remove(0);
        }
    }

    /// The number of states.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if there is no state.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Advances `pre`, the pre-state of block `parent`, toward a block at `slot` (see the module
/// docs), and returns the state at `slot - 1`. The caller calls it only for a block more than
/// [`PRE_STATE_EPOCHS`] epochs of slots after `pre`. `walk` runs `process_slots` on a state to
/// a slot. `out_of_time` gets the slot of the walk state, and is `true` once the deadline of
/// the import passed. `Err` (why, for the log) is IGNORE.
///
/// [`PRE_STATE_EPOCHS`]: super::snapshot::PRE_STATE_EPOCHS
pub(crate) fn advance<E: Preset>(
    advanced: &mut Advanced<BeaconState<E>>,
    parent: Root,
    pre: &BeaconState<E>,
    slot: Slot,
    out_of_time: &dyn Fn(Slot) -> bool,
    walk: &Walk<'_, E>,
) -> Result<BeaconState<E>, String> {
    let epoch_slots = E::slots_per_epoch();
    // The state kept at epoch `e` is at slot `e * epoch_slots - 1`: before `slot` for each `e`
    // up to `slot / epoch_slots`.
    let start = advanced.latest(&parent, slot / epoch_slots).unwrap_or(pre);
    let cap = MAX_ADVANCE_EPOCHS.saturating_mul(epoch_slots);
    if slot.saturating_sub(start.slot) > cap {
        return Err(format!(
            "block slot {slot} is more than {cap} slots after the state at slot {} of the \
             parent {parent}",
            start.slot
        ));
    }
    let target = slot.saturating_sub(1);
    let mut state = start.clone();
    while state.slot < target {
        if out_of_time(state.slot) {
            return Err(format!(
                "no time left to advance the state of the parent {parent} from slot {}",
                state.slot
            ));
        }
        // The next last slot of an epoch: one epoch boundary in each step at most.
        let epoch_end = ((state.slot + 1) / epoch_slots + 1)
            .saturating_mul(epoch_slots)
            .saturating_sub(1);
        let to = epoch_end.min(target);
        walk(&mut state, to)?;
        if to == epoch_end {
            advanced.insert(parent, (to + 1) / epoch_slots, state.clone());
        }
    }
    Ok(state)
}
