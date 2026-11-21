//! The pre-states of the chain core: a small LRU of post-states by block root.
//!
//! A block imports on the post-state of its parent, so the core keeps the post-state of each
//! block it commits as the pre-state of the children of that block. The anchor pre-state (the
//! installed anchor, later the finalized state) always stays. The other pre-states go least
//! recently used first, past [`max_pre_states`]: [`PRE_STATE_EPOCHS`] epochs of pre-states plus
//! the anchor.
//!
//! The bound is provisional. It holds until the state retention of the store binds the disk
//! budget of states (the last two per-epoch states plus the finalized one).
//!
//! [`Snapshots::insert`] is the only path that drops a pre-state. The chain core then drops the
//! states that its walks keep for that parent (see [`advance`](super::advance)). There is no
//! prune at finality yet; when one comes, it must also drop the kept walk states of the
//! parents that it prunes.

use consensus_types::primitives::Root;
use consensus_types::EthSpec;

/// The epochs of pre-states that the core keeps besides the anchor (provisional).
pub const PRE_STATE_EPOCHS: u64 = 2;

/// The most pre-states of the core on preset `E`: [`PRE_STATE_EPOCHS`] epochs of slots, plus
/// the anchor. 17 on the minimal preset, 65 on mainnet.
#[must_use]
pub fn max_pre_states<E: EthSpec>() -> usize {
    usize::try_from(PRE_STATE_EPOCHS * E::slots_per_epoch() + 1).unwrap_or(usize::MAX)
}

/// The anchor pre-state and the most recent others, by block root.
#[derive(Debug)]
pub struct Snapshots<S> {
    anchor: (Root, S),
    /// Least recently used first.
    recent: Vec<(Root, S)>,
    /// The most entries in `recent`, at least 1.
    recent_max: usize,
}

impl<S> Snapshots<S> {
    /// The anchor `state` of block `root`, and room for `max` pre-states with it. A `max` below
    /// 2 keeps the anchor and the newest pre-state.
    pub fn new(root: Root, state: S, max: usize) -> Self {
        Self {
            anchor: (root, state),
            recent: Vec::new(),
            recent_max: max.saturating_sub(1).max(1),
        }
    }

    /// The pre-state of block `root`, now the most recently used.
    pub fn get(&mut self, root: &Root) -> Option<&S> {
        self.promote(root);
        self.peek(root)
    }

    /// Makes the pre-state of block `root` the most recently used. A root without a pre-state,
    /// and the anchor, change nothing.
    pub fn promote(&mut self, root: &Root) {
        if let Some(at) = self.recent.iter().position(|(r, _)| r == root) {
            let entry = self.recent.remove(at);
            self.recent.push(entry);
        }
    }

    /// The pre-state of block `root`. The order of use does not change.
    pub fn peek(&self, root: &Root) -> Option<&S> {
        if self.anchor.0 == *root {
            return Some(&self.anchor.1);
        }
        self.recent
            .iter()
            .find(|(r, _)| r == root)
            .map(|(_, state)| state)
    }

    /// `true` if the core holds the pre-state of block `root`, the anchor included. The order
    /// of use does not change.
    pub fn contains(&self, root: &Root) -> bool {
        self.peek(root).is_some()
    }

    /// Keeps `state` as the pre-state of the children of block `root`, the most recently used.
    /// It replaces an earlier pre-state of `root`, never the anchor. Past the bound, the least
    /// recently used pre-state goes.
    pub fn insert(&mut self, root: Root, state: S) {
        if self.anchor.0 == root {
            return;
        }
        self.recent.retain(|(r, _)| *r != root);
        self.recent.push((root, state));
        if self.recent.len() > self.recent_max {
            self.recent.remove(0);
        }
    }

    /// The number of pre-states, the anchor included.
    pub fn len(&self) -> usize {
        1 + self.recent.len()
    }

    /// Always false: the anchor is always kept.
    pub fn is_empty(&self) -> bool {
        false
    }
}
