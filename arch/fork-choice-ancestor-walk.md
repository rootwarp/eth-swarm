# Fork choice: the ancestor walk stops at the anchor

`get_ancestor` (`specs/gloas/fork-choice.md` L388–397, consensus-specs v1.7.0-beta.4) gives the
node of the chain of a node at a slot. The spec recurses through
`store.blocks[root].parent_root` until the block slot is at or before that slot.

`get_ancestor` in `crates/fork-choice/src/store.rs` also stops at the anchor of the store. For
a slot before the anchor, it gives the anchor node with the payload status that its child
builds on.

**Why.** The store has no block below the anchor. After a checkpoint sync the anchor is not
genesis, and the spec's walk fails on the parent of the anchor for each slot before it, for
example the shuffling dependent slot of the first two epochs after the anchor. Production
clients also stop at their oldest block.

**Prune.** When finality moves, `on_tick` drops the blocks that do not descend from the
finalized block, and the finalized block becomes the anchor. The walk then stops there.
`get_head`, `get_weight` and the asserts of `on_block` give the result of the spec: each walk
that they need ends at or above the finalized block, or compares two walks that both pass
through it.

**What differs.** A direct call of `get_ancestor`, `get_checkpoint_block` or `is_ancestor` for
a slot or an epoch before the anchor gives the anchor, where the spec gives an older block or
fails.

**Attestation targets.** `on_attestation` refuses a target whose epoch starts before the
anchor block (`AttestationError::TargetBeforeAnchor`) before it calls `get_checkpoint_block`.
For such an epoch the spec's walk passes below the anchor: after a checkpoint sync it fails on
the missing parent, and after a prune it gives a block older than every block of the store,
which cannot be the target. So the spec refuses the attestation at the same assert. Such a
target is the epoch before a checkpoint-sync anchor state whose block is not at the first
slot of that epoch, or, in an attestation of a block, the previous epoch of a block of the
finalized epoch.
