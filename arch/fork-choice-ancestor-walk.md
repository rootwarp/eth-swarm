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

**Attestation targets.** The spec's store keeps every block, so after finality moves an
attestation can still name a block beside the finalized block, or have a target below the new
anchor, and pass every assert of `on_attestation`. Its attesters then move to that block,
and their older messages stop giving weight to the nodes that they support. So the prune
keeps what `on_attestation` reads of each dropped block in `Store::dropped`: its slot, its
parent root and its post-state, and the root of its verified payload stays in `payloads`.
`validate_on_attestation` looks up the target and the attested block in the store or in
`dropped`, and its `get_checkpoint_block` walk goes through both, past the anchor.
`store_target_checkpoint_state` reads the dropped state. `get_head` and `get_weight` read
only the blocks that the prune keeps, so a message for a dropped block supports no node, as
in the spec. The walk fails with `AttestationError::TargetBeforeAnchor` where it needs the
parent of a block and the store does not have that parent. After a checkpoint sync this is
the parent of the anchor, and the spec fails on it too.

The store forgets the dropped blocks, their states and their checkpoint states at the end of
the epoch after the prune (`store::release_dropped`). Until then a vote from the wire with a
target epoch of the prune or earlier can arrive, and `on_attestation` gives the result of the
spec for every vote that it gets. After that it refuses a vote that names a forgotten block
(`UnknownTarget`, `UnknownBeaconBlock`, or `TargetBeforeAnchor` for a walk below a kept
block), where the spec's store takes a valid one. A vote from the wire then has a target
epoch after the prune, so if it names a forgotten block it also attests to one, and in the
spec its message supports no node of the pruned store. A vote from a block has no such limit.
