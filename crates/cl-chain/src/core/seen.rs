//! The blocks that the chain core refused for a reason that does not change ([`Refused`]).
//!
//! A refusal holds for the root of the block, `hash_tree_root(block.message)`. That root does
//! not commit to the signature of the proposer, so a refusal for that signature holds only for
//! the same signature: a copy of a valid block with a bad signature must not keep the valid
//! block out. Any other refusal is a property of the message and of the pre-state of its parent
//! (the post-state of `parent_root`), so it holds for each signature.

use consensus_types::primitives::{BLSSignature, Root};
use std::collections::{HashMap, VecDeque};

/// The refusals of at most `max` roots. Past the bound, the root refused first goes.
#[derive(Debug)]
pub(crate) struct Refused<V> {
    entries: HashMap<Root, Entry<V>>,
    /// The roots in `entries`, the first refused first.
    order: VecDeque<Root>,
    /// At least 1.
    max: usize,
}

#[derive(Debug)]
struct Entry<V> {
    /// `None`: each block with this message. `Some`: only the block with this signature.
    signature: Option<BLSSignature>,
    value: V,
}

impl<V: Clone> Refused<V> {
    /// Room for `max` roots (at least 1).
    pub(crate) fn new(max: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
        }
    }

    /// What the block of `root` with `signature` was refused with, if it was.
    pub(crate) fn get(&self, root: &Root, signature: &BLSSignature) -> Option<&V> {
        self.entries
            .get(root)
            .filter(|entry| entry.signature.is_none_or(|refused| refused == *signature))
            .map(|entry| &entry.value)
    }

    /// `true` if block `root` is refused, for one signature or for each.
    pub(crate) fn contains(&self, root: &Root) -> bool {
        self.entries.contains_key(root)
    }

    /// Keeps `value` as the refusal of block `root`: for each signature if `signature` is
    /// `None`, else for that signature only. Returns `value`. A refusal for each signature
    /// stays as it is. A root refused again keeps its place in the order.
    pub(crate) fn refuse(&mut self, root: Root, signature: Option<BLSSignature>, value: V) -> V {
        if let Some(entry) = self.entries.get_mut(&root) {
            if entry.signature.is_some() {
                *entry = Entry {
                    signature,
                    value: value.clone(),
                };
            }
            return value;
        }
        if self.order.len() >= self.max {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(root);
        self.entries.insert(
            root,
            Entry {
                signature,
                value: value.clone(),
            },
        );
        value
    }
}
