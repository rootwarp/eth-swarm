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
spec for every vote that it gets. After that it refuses a vote that names a forgotten block,
where the spec's store takes a valid one. The refused vote, also a vote that a canonical block
includes, leaves the older latest message of each attester in place. The spec replaces that
message, so `get_head` can differ from the spec. The next section records this deviation.

## Deviation: the store keeps dropped blocks for a bounded time

**What.** The store keeps what `on_attestation` reads of a dropped block only until the end of
the epoch after the prune. A prune in epoch `p` keeps each dropped block with
`last_epoch = p + 1`, and the first tick of epoch `p + 2` forgets the block, its state, the
root of its verified payload and its checkpoint states (`store::release_dropped`). After
that, `on_attestation` refuses a vote that names a forgotten block: `UnknownTarget` for the
target, `UnknownBeaconBlock` for the attested block, or `TargetBeforeAnchor` for a
`get_checkpoint_block` walk that needs a parent that the store no longer has.

**Why.** If the store kept the dropped blocks, their states and their checkpoint states
forever, it would grow without bound: one full post-state for each orphaned block that it saw
before finality. Production clients also drop votes for blocks that conflict with finality.

**How a valid vote can still name a forgotten block.** The spec's store never forgets a
block. Let `X` be a forgotten block and `e >= p + 2` a later epoch. An attestation with
`beacon_block_root = X`, `target = (e, X)` and index 0 passes every assert of
`validate_on_attestation`: `X.slot <= compute_start_slot_at_epoch(e)`, so
`get_checkpoint_block(store, X, e) == X`. The Gloas gossip checks of
`beacon_attestation_{subnet_id}` and `beacon_aggregate_and_proof` ignore the vote, because
the finalized checkpoint is not an ancestor of `X`. `process_attestation` has no such check,
so a proposer can include the vote in a valid canonical block, and `on_attestation` gets it
with `is_from_block = true`. `process_attestation` reads the committees of the canonical
state, and `on_attestation` reads the committees of the checkpoint state of `X`, so the spec
takes the vote only if both give its bits the same attesters. The two branches have different
RANDAO mixes after they split, so their committees of `e` usually differ, but the spec does
not rule out a match.

**The head difference.** The spec moves the attesters of the vote to `X`, which is not in the
kept tree, so their new messages give no weight to a kept node, and their older messages on
the live branch stop giving weight. This store refuses the vote and keeps the older messages,
so their weight stays on the kept tree. `get_head` can then stay on a kept child that these
messages make heavier, where the spec moves to another node. The test
`after_the_window_a_refused_block_vote_for_a_forgotten_block_keeps_the_head_that_the_spec_moves`
in `crates/fork-choice/tests/prune.rs` pins this with two votes of this kind, one in the
window and one after it. Before each vote, two of its attesters have older messages for `d2`
and one other validator has an older message for `d`, two children of `c`. Inside the window
the store takes the vote and the head moves to `d`, as in the spec. After the window the store
refuses the vote, and the head stays on `d2`.
