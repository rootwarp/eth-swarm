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
//!   once, with no `process_slots` (`walk_slots`, before the proposer signature of the block);
//! - the chain core checks the proposer signature before the walk, so a block that its
//!   proposer did not sign costs no `process_slots`;
//! - before the walk, and before each epoch boundary, the walk checks the deadline of the
//!   import, and that the caller of the import still waits for the answer. The deposit
//!   verdicts of an epoch boundary go to cl-verify with that deadline.
//!
//! At the last slot of each epoch that it reaches, the walk keeps a copy of its state in
//! [`Advanced`], by the root of the parent and the epoch after that slot. A walk that stops
//! (the deadline, a caller that stopped waiting, no deposit verdict, an error) keeps the states
//! it reached. A later walk from the same parent starts from the latest of them, so it does not
//! walk those slots again.
//!
//! An import reads a kept state only after it finds the pre-state of the parent. So after each
//! new pre-state, the chain core drops the kept states of each parent whose pre-state left the
//! LRU ([`Advanced::retain`]). A later prune of pre-states at finality must also drop the kept
//! states of the parents that it prunes.
//!
//! - after the proposer signature, the walk must fit in the admission budget of the core
//!   ([`AdvanceBudget`]): at most [`MAX_ADVANCE_EPOCHS_PER_SLOT`] epochs of walk for each slot
//!   of the clock of the core. Else it is IGNORE, with no `process_slots`.
//!
//! No refusal of the walk is a proof about the block: each is IGNORE, and the core does not
//! keep it. The block can import later from a nearer state, or with more time.
//!
//! After the walk, `block_proposer` gives the proposer of the block slot from the lookahead of
//! the advanced state.
//!
//! [`PRE_STATE_EPOCHS`]: super::snapshot::PRE_STATE_EPOCHS

use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Epoch, Root, Slot, ValidatorIndex};
use state_transition::Preset;

/// The most epochs of slots between the start of a walk and the block \[est\]: 64 slots on
/// the minimal preset, 256 on mainnet (about 51 minutes).
pub const MAX_ADVANCE_EPOCHS: u64 = 8;

/// The most states that the walks keep \[est\]. Past it, the least recently used goes first.
pub const MAX_ADVANCED_STATES: usize = 64;

/// The most epochs of walk that the core admits for each slot of its clock, and the most that
/// the admission budget holds \[est\]: one walk of [`MAX_ADVANCE_EPOCHS`] epochs, or several
/// shorter ones.
pub const MAX_ADVANCE_EPOCHS_PER_SLOT: u64 = 8;

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
        let at = self.latest_at(parent, epoch)?;
        let entry = self.entries.remove(at);
        self.entries.push(entry);
        self.entries.last().map(|(_, state)| state)
    }

    /// The place in `entries` of the state of `parent` with the latest epoch up to `epoch`.
    fn latest_at(&self, parent: &Root, epoch: Epoch) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, ((root, kept), _))| root == parent && *kept <= epoch)
            .max_by_key(|(_, ((_, kept), _))| *kept)
            .map(|(at, _)| at)
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

    /// Keeps only the states of the parents for which `keep` is `true`. The order of use of
    /// those states does not change.
    pub fn retain(&mut self, mut keep: impl FnMut(&Root) -> bool) {
        self.entries.retain(|((parent, _), _)| keep(parent));
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

/// The admission budget of the walks: a bucket of epochs of walk, on the slots of the clock of
/// the core. The core is the single writer, so the budget bounds the work of the walks in one
/// slot, not their concurrency.
///
/// The first [`Self::take`] fills the bucket to [`MAX_ADVANCE_EPOCHS_PER_SLOT`]. Each later
/// slot of the clock adds [`MAX_ADVANCE_EPOCHS_PER_SLOT`], up to that bound: idle slots keep no
/// more than one slot of work. A clock that goes back adds nothing and empties nothing.
#[derive(Clone, Debug, Default)]
pub struct AdvanceBudget {
    /// The epochs of walk left.
    epochs: u64,
    /// The latest slot of the clock that a take saw. `None` before the first take.
    slot: Option<Slot>,
}

impl AdvanceBudget {
    /// An empty budget. The first take fills it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes `epochs` of walk at slot `now` of the clock, and returns `true`, if the bucket
    /// holds them after the refill of `now`. Else it takes nothing, and returns `false`. A walk
    /// that stops early gives nothing back.
    pub fn take(&mut self, now: Slot, epochs: u64) -> bool {
        let added = self.slot.map_or(MAX_ADVANCE_EPOCHS_PER_SLOT, |last| {
            now.saturating_sub(last)
                .saturating_mul(MAX_ADVANCE_EPOCHS_PER_SLOT)
        });
        self.slot = Some(self.slot.map_or(now, |last| last.max(now)));
        self.epochs = self
            .epochs
            .saturating_add(added)
            .min(MAX_ADVANCE_EPOCHS_PER_SLOT);
        if epochs > self.epochs {
            return false;
        }
        self.epochs -= epochs;
        true
    }
}

/// The slots between the best start of a walk from `pre`, the pre-state of block `parent`, and
/// a block at `slot`: the latest state that `advanced` keeps for `parent` before the block,
/// else `pre`. The order of use does not change. `Err` (why, for the log) if that is more than
/// [`MAX_ADVANCE_EPOCHS`] epochs of slots: IGNORE, with no walk.
pub(crate) fn walk_slots<E: Preset>(
    advanced: &Advanced<BeaconState<E>>,
    parent: Root,
    pre: &BeaconState<E>,
    slot: Slot,
) -> Result<u64, String> {
    let epoch_slots = E::slots_per_epoch();
    let start = advanced
        .latest_at(&parent, slot / epoch_slots)
        .map_or(pre.slot, |at| advanced.entries[at].1.slot);
    let cap = MAX_ADVANCE_EPOCHS.saturating_mul(epoch_slots);
    let gap = slot.saturating_sub(start);
    if gap > cap {
        return Err(format!(
            "block slot {slot} is more than {cap} slots after the state at slot {start} of the \
             parent {parent}"
        ));
    }
    Ok(gap)
}

/// The proposer of the block at `slot` on `state`, a state of the walk before that slot in
/// the same epoch, or at the last slot of the epoch before. `get_beacon_proposer_index` on
/// `state` is the proposer of `state.slot`, not of `slot`. So the entry is `slot` minus the
/// first slot of the epoch of `state`, in `state.proposer_lookahead`. When the block opens an
/// epoch, that is the entry `SLOTS_PER_EPOCH`: the first proposer of the next epoch, which
/// `process_epoch` moves to entry 0. `Err` (why, for the log) if `slot` is not after the state,
/// or the lookahead has no such entry: a fault of the state, not of the block.
pub(crate) fn block_proposer<E: Preset>(
    state: &BeaconState<E>,
    slot: Slot,
) -> Result<ValidatorIndex, String> {
    let epoch_start = state.slot - state.slot % E::slots_per_epoch();
    slot.checked_sub(epoch_start)
        .filter(|_| slot > state.slot)
        .and_then(|at| usize::try_from(at).ok())
        .and_then(|at| state.proposer_lookahead.get(at).copied())
        .ok_or_else(|| {
            format!(
                "the proposer lookahead of the state at slot {} has no proposer of slot {slot}",
                state.slot
            )
        })
}

/// Advances `pre`, the pre-state of block `parent`, toward a block at `slot` (see the module
/// docs), and returns the state at `slot - 1`. The caller calls it only for a block more than
/// [`PRE_STATE_EPOCHS`] epochs of slots after `pre`. `walk` runs `process_slots` on a state to
/// a slot. `stop` gets the slot of the walk state, and gives why the walk must stop there (the
/// deadline of the import passed, or its caller stopped waiting), else `None`. `Err` (why, for
/// the log) is IGNORE.
///
/// [`PRE_STATE_EPOCHS`]: super::snapshot::PRE_STATE_EPOCHS
pub(crate) fn advance<E: Preset>(
    advanced: &mut Advanced<BeaconState<E>>,
    parent: Root,
    pre: &BeaconState<E>,
    slot: Slot,
    stop: &dyn Fn(Slot) -> Option<&'static str>,
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
        if let Some(why) = stop(state.slot) {
            return Err(format!(
                "{why}: the walk of the state of the parent {parent} stops at slot {}",
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
