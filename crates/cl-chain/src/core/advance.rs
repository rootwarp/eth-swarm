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
//! - after the proposer signature, the chain core reads its clock again, and the walk must fit
//!   in the admission budget of that slot of the clock ([`AdvanceBudget`]): at most
//!   [`MAX_ADVANCE_EPOCHS_PER_SLOT`] epochs of walk in each slot for all proposers, and one walk
//!   of at most [`MAX_ADVANCE_EPOCHS_PER_PROPOSER_PER_SLOT`] epochs in each slot for each
//!   proposer. Else it is IGNORE, with no `process_slots`.
//!
//! The fairness key of the budget is the claimed `proposer_index` of the block, not a peer: an
//! import carries no peer. A walk costs a valid signature of that proposer first, and one
//! proposer has one walk in each slot, so several short walks of one proposer cannot take the
//! budget of all proposers. One walk of the cap still takes it: the budget of all proposers
//! holds one such walk in each slot.
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

/// The most epochs of walk that the core admits for one proposer in each slot of its clock
/// \[est\]: one walk of [`MAX_ADVANCE_EPOCHS`] epochs. Each walk takes the full budget of its
/// proposer for the slot, so one proposer has one walk in each slot.
pub const MAX_ADVANCE_EPOCHS_PER_PROPOSER_PER_SLOT: u64 = 8;

/// The most proposers that the admission budget keeps a budget for \[est\]. Past it, the
/// proposer charged least recently goes first. A later walk of that proposer starts from a full
/// budget of its own, and the budget of all proposers still bounds it.
pub const MAX_ADVANCE_BUDGET_PROPOSERS: usize = 128;

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

/// A bucket of epochs of walk, on the slots of the clock of the core.
#[derive(Clone, Copy, Debug, Default)]
struct Bucket {
    /// The epochs of walk left.
    epochs: u64,
    /// The latest slot of the clock that a take saw. `None` before the first take.
    slot: Option<Slot>,
}

impl Bucket {
    /// The bucket after the refill of slot `now`, for a bucket of `size` epochs. The first take
    /// fills it. Each later slot adds `size`, up to `size`: idle slots keep no more than one
    /// slot of work. A clock that goes back adds nothing and empties nothing.
    fn refill(self, now: Slot, size: u64) -> Self {
        let added = self
            .slot
            .map_or(size, |last| now.saturating_sub(last).saturating_mul(size));
        Self {
            epochs: self.epochs.saturating_add(added).min(size),
            slot: Some(self.slot.map_or(now, |last| last.max(now))),
        }
    }
}

/// The admission budget of the walks, on the slots of the clock of the core. The core is the
/// single writer, so the budget bounds the work of the walks in one slot, not their concurrency.
///
/// It has a bucket of [`MAX_ADVANCE_EPOCHS_PER_SLOT`] epochs for all proposers, and a bucket of
/// [`MAX_ADVANCE_EPOCHS_PER_PROPOSER_PER_SLOT`] epochs for each proposer, with the same refill
/// on the same clock: the first take of a bucket fills it, and each later slot of the clock
/// fills it again. A clock that goes back adds nothing and empties nothing. The budget keeps the
/// buckets of at most [`MAX_ADVANCE_BUDGET_PROPOSERS`] proposers.
#[derive(Clone, Debug, Default)]
pub struct AdvanceBudget {
    /// The bucket of all proposers.
    all: Bucket,
    /// The bucket of each proposer, the least recently charged first.
    proposers: Vec<(ValidatorIndex, Bucket)>,
}

impl AdvanceBudget {
    /// An empty budget. The first take fills it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes a walk of `epochs` epochs for a block of `proposer` at slot `now` of the clock,
    /// and returns `true`, if both buckets hold it after the refill of `now`: `epochs` from the
    /// bucket of all proposers, and the full bucket of `proposer`. Else it takes nothing from
    /// either bucket, and returns `false`. A walk that stops early gives nothing back. A walk of
    /// no epoch takes nothing.
    pub fn take(&mut self, now: Slot, proposer: ValidatorIndex, epochs: u64) -> bool {
        if epochs == 0 {
            return true;
        }
        let at = self
            .proposers
            .iter()
            .position(|(index, _)| *index == proposer);
        let own = at
            .map_or_else(Bucket::default, |at| self.proposers[at].1)
            .refill(now, MAX_ADVANCE_EPOCHS_PER_PROPOSER_PER_SLOT);
        let all = self.all.refill(now, MAX_ADVANCE_EPOCHS_PER_SLOT);
        // The walk takes the full bucket of its proposer: one walk for each slot.
        let own_epochs = epochs.max(MAX_ADVANCE_EPOCHS_PER_PROPOSER_PER_SLOT);
        if epochs > all.epochs || own_epochs > own.epochs {
            return false;
        }
        self.all = Bucket {
            epochs: all.epochs - epochs,
            ..all
        };
        if let Some(at) = at {
            self.proposers.remove(at);
        }
        let own = Bucket {
            epochs: own.epochs - own_epochs,
            ..own
        };
        self.proposers.push((proposer, own));
        if self.proposers.len() > MAX_ADVANCE_BUDGET_PROPOSERS {
            self.proposers.remove(0);
        }
        true
    }

    /// The number of proposers that the budget keeps a bucket for.
    pub fn proposers(&self) -> usize {
        self.proposers.len()
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
        // The next last slot of an epoch: one epoch boundary in each step at most. The walk
        // keeps a state only at a last slot of an epoch, so `to + 1` starts an epoch.
        let epoch_end = next_epoch_end(state.slot, epoch_slots);
        let to = epoch_end.map_or(target, |end| end.min(target));
        walk(&mut state, to)?;
        if epoch_end == Some(to) {
            advanced.insert(parent, (to + 1) / epoch_slots, state.clone());
        }
    }
    Ok(state)
}

/// The first slot after `slot` that is the last slot of an epoch of `epoch_slots` slots, or
/// `None` if there is none up to [`Slot::MAX`].
fn next_epoch_end(slot: Slot, epoch_slots: u64) -> Option<Slot> {
    let last = epoch_slots.checked_sub(1)?;
    let next = slot.checked_add(1)?;
    (next / epoch_slots * epoch_slots).checked_add(last)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use consensus_types::{EthSpec, Minimal};
    use std::cell::RefCell;
    use testkit::anchor::fixtures::{pinned_export, AnchorFiles};
    use testkit::anchor::load_anchor;

    /// The anchor state of the pinned minimal export, at slot 0.
    fn anchor_state() -> BeaconState<Minimal> {
        let pinned = pinned_export().expect("the pinned export must open");
        let dir = tempfile::tempdir().unwrap();
        AnchorFiles::genesis(&pinned.export)
            .unwrap()
            .write(dir.path())
            .unwrap();
        let loaded = load_anchor::<Minimal>(dir.path()).expect("the anchor must load");
        loaded.into_parts().0
    }

    #[test]
    fn the_proposer_of_a_block_is_after_the_slot_of_the_state() {
        let mut state = anchor_state();
        let lookahead = |at: usize| state.proposer_lookahead.get(at).copied().unwrap();
        let (first, sixth, eighth) = (lookahead(1), lookahead(6), lookahead(8));
        assert!(
            block_proposer(&state, state.slot).is_err(),
            "the state slot has no block of the walk"
        );
        assert_eq!(block_proposer(&state, 1), Ok(first));
        state.slot = 5;
        assert!(block_proposer(&state, 5).is_err());
        assert!(block_proposer(&state, 4).is_err());
        assert_eq!(block_proposer(&state, 6), Ok(sixth));
        // At the last slot of an epoch, a block that opens the next epoch reads the entry
        // `SLOTS_PER_EPOCH` of the lookahead.
        state.slot = 7;
        assert!(block_proposer(&state, 7).is_err());
        assert_eq!(block_proposer(&state, 8), Ok(eighth));
        assert!(
            block_proposer(&state, 16).is_err(),
            "the lookahead has two epochs"
        );
    }

    #[test]
    fn the_next_epoch_end_is_exact_up_to_the_last_slot() {
        assert_eq!(next_epoch_end(0, 8), Some(7));
        assert_eq!(next_epoch_end(6, 8), Some(7));
        assert_eq!(next_epoch_end(7, 8), Some(15));
        // 2^64 is a multiple of 8 and of 32, so the last slot ends an epoch.
        for epoch_slots in [8, 32] {
            assert_eq!(next_epoch_end(Slot::MAX - 1, epoch_slots), Some(Slot::MAX));
            assert_eq!(
                next_epoch_end(Slot::MAX - epoch_slots, epoch_slots),
                Some(Slot::MAX)
            );
            assert_eq!(
                next_epoch_end(Slot::MAX - epoch_slots - 1, epoch_slots),
                Some(Slot::MAX - epoch_slots)
            );
        }
        assert_eq!(next_epoch_end(Slot::MAX, 8), None, "no slot is after it");
        // 2^64 is not a multiple of 6: the next last slot of an epoch is past the last slot.
        assert_eq!(next_epoch_end(Slot::MAX - 1, 6), None);
        assert_eq!(next_epoch_end(Slot::MAX - 4, 6), None);
        assert_eq!(next_epoch_end(Slot::MAX - 5, 6), Some(Slot::MAX - 4));
        assert_eq!(next_epoch_end(3, 0), None);
    }

    /// A walk to the slot before the last slot keeps a state only at a last slot of an epoch,
    /// by the epoch after it, and does not walk to the last slot.
    #[test]
    fn a_walk_near_the_last_slot_keeps_states_only_at_ends_of_epochs() {
        let epoch_slots = Minimal::slots_per_epoch();
        let parent = Root::repeat_byte(1);
        let mut pre = anchor_state();
        pre.slot = Slot::MAX - epoch_slots - 1;
        let tos = RefCell::new(Vec::new());
        let walk = |state: &mut BeaconState<Minimal>, to: Slot| {
            tos.borrow_mut().push(to);
            state.slot = to;
            Ok(())
        };
        let mut advanced = Advanced::new(8);
        let state = advance(&mut advanced, parent, &pre, Slot::MAX, &|_| None, &walk).unwrap();
        assert_eq!(state.slot, Slot::MAX - 1);
        assert_eq!(*tos.borrow(), vec![Slot::MAX - epoch_slots, Slot::MAX - 1]);
        assert_eq!(advanced.len(), 1, "one last slot of an epoch on the walk");
        let epoch = (Slot::MAX - epoch_slots + 1) / epoch_slots;
        let kept = advanced
            .peek(&parent, epoch)
            .expect("the state at an end of an epoch");
        assert_eq!(kept.slot, Slot::MAX - epoch_slots);
    }
}
