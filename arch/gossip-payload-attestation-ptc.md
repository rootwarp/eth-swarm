# Gossip: a head state with no PTC of the message slot is IGNORE

`validate_payload_attestation_message_gossip` (`specs/gloas/p2p-interface.md` L891–954,
consensus-specs v1.7.0-beta.4) reads the PTC of the message slot from the head state,
`state = store.block_states[get_head(store).root]`:

```python
# [REJECT] The validator is a member of the payload timeliness committee
if validator_index not in get_ptc(state, data.slot):
    raise GossipReject("validator is not in the payload timeliness committee")
```

(L937–938). `get_ptc` (`specs/gloas/beacon-chain.md` L1392–1404) reads `state.ptc_window`,
which has the PTCs of the previous epoch, the current epoch and the next
`MIN_SEED_LOOKAHEAD` epochs of the state. With `epoch = compute_epoch_at_slot(data.slot)` and
`state_epoch = get_current_epoch(state)`, it asserts:

- `epoch >= GLOAS_FORK_EPOCH` (L1397);
- `epoch + 1 == state_epoch` if `epoch < state_epoch` (L1400), so `epoch + 1 >= state_epoch`;
- `epoch <= state_epoch + MIN_SEED_LOOKAHEAD` (L1402).

The docstring of the topic says that it raises `GossipIgnore` or `GossipReject`. A failed
assert raises neither, so the spec gives no verdict for it.

## Deviation: IGNORE, not REJECT

**What.** `validate_payload_attestation_message_gossip` in
`crates/gossip-validation/src/payload_attestation.rs` calls
`state_transition::caches::get_ptc(state, data.slot)` on the head state. If it returns `Err`
(`StfError::EpochOutOfWindow`), the verdict is
`Verdict::Ignore(IgnoreReason::NoPtc { slot: data.slot })`. The function does not check the
signature, and `Seen` does not get the key of the message.

**Why.** The checks before it already proved the message conditions that the asserts can
show:

- The fork check (L904–906) proved `epoch >= GLOAS_FORK_EPOCH`.
- `is_current_slot` (L913–915) proved that `data.slot` is the current slot, with
  `MAXIMUM_GOSSIP_CLOCK_DISPARITY` on both ends.

So a failed assert shows that the local head state is out of the window of the current slot,
not that the message is invalid:

- The head state is two or more epochs before the current epoch, so
  `epoch > state_epoch + MIN_SEED_LOOKAHEAD`. For example, the node syncs and its head is
  behind, or no block came in the whole previous epoch.
- The head state is two or more epochs after the current epoch, so
  `epoch + 1 < state_epoch`. The store refuses a block of a future slot, so this needs a local
  clock that moved back.

With a head state in the window, the same message can be valid. REJECT is only for a proven
spec violation, and it lowers the score of the peer that sent a message that the rest of the
network accepts. An assert that stops the node is not a possible answer for a message from a
peer. IGNORE drops the message and does not penalize the peer. `Seen` does not get the key,
so a later copy of the message can pass when the head is in the window again.

**What differs.** Where the spec's `get_ptc` fails an assert for this topic, this client gives
IGNORE. The spec gives no verdict there, so no valid message is dropped that the spec accepts,
and no message is accepted that the spec rejects.

**Fork choice.** `on_payload_attestation_message`
(`crates/fork-choice/src/payload_attestation.rs`) reads `get_ptc` on the post-state of the
attested block, and it returns early unless `data.slot` is the slot of that state. So its
`get_ptc` call is always in the window, and this deviation does not apply to it.

**Tests.** In `crates/gossip-validation/tests/payload_attestation.rs`:

- `a_head_state_two_epochs_before_the_slot_must_ignore`: a head state of epoch 0 and a
  current message of slot 17 (epoch 2) give `Ignore(NoPtc { slot: 17 })`. With the post-state
  of the block of slot 17 as the head state, the same message is pending.
- `a_head_state_with_no_ptc_of_the_slot_must_ignore`: a head state of slot 24 (epoch 3) and a
  message of slot 1 (epoch 0) give `Ignore(NoPtc { slot: 1 })`.

## Related: the `Seen` keys of a slot with head changes

The PTC check reads the head state at the time of each check, and the head can change in a
slot. Each head can have another PTC for the slot, so the spec's `Seen` can get the union of
the PTCs of the heads of a slot: more than `PTC_SIZE` keys. The spec does not prune `Seen`.
`crates/gossip-validation/src/seen.rs` bounds the payload attestation keys, and only a key of a
message with a valid signature changes them:

- A slot `s` stays until `end(s) + MAXIMUM_GOSSIP_CLOCK_DISPARITY`, where `end(s)` is the
  start of slot `s + 1`. After that time no message of `s` passes `is_current_slot` again, if
  the clock does not go back. `oldest_current_slot` gives the first slot that is still current,
  and `Seen::resolve` and `Seen::prune_payload_attestations` remove the slots before it. That
  slot is the floor, and it does not decrease. A key or a message of a slot before the floor is
  IGNORE, never ACCEPT: `Seen` keeps the validators of the last slot before the floor until the
  floor moves again, so a second copy of an accepted message is still a duplicate, and any
  other message before the floor is not current. A clock that goes back does not change this.
- At most `MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS` (8) slots. A new slot past the limit removes the
  oldest slot, and the floor moves past it as for a prune. Thus a message of the removed slot is
  IGNORE, never ACCEPT: a duplicate if the record of the last pruned slot has its key, else not
  current.
- At most `MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT` (4) times `PTC_SIZE` validators for each
  slot: 64 in the minimal preset and 2,048 in the mainnet preset. At that limit, a valid key of
  a new validator of the slot is IGNORE (`IgnoreReason::PayloadAttestationSlotFull { slot }`),
  and `Seen` does not change.

### Why a full slot ignores a new validator

There are three ways to bound the validators of a slot:

- **Remove the oldest validator of the slot (first in, first out).** A removed key is not a
  duplicate any more, so a valid copy of its message passes again and is ACCEPT a second time.
  Any peer can send such a copy again: it needs no key, only a message that it received. With
  five heads of disjoint PTCs in one slot, each validator of the first head can be ACCEPT again,
  and each of these copies removes the next oldest validator. Thus the copies can go on until
  the slot is past the clock disparity, and each ACCEPT forwards the message and gives it to
  fork choice again.
- **Keep a record of each removed validator.** A second copy is then IGNORE, but the record
  grows by one key for each new validator of the slot, so the slot has no bound again.
- **IGNORE a new validator of a full slot.** `Seen` stays at the limit, and each validator that
  it keeps stays a duplicate until the floor passes its slot. No copy of a message is ACCEPT
  twice. The cost is that a valid first message of a new validator of a full slot is IGNORE:
  this node does not forward it, and does not penalize its peer. A slot is full only after the
  head changed in the slot to at least four PTCs with different validators.

This client uses the third way. The check of the limit is in `Seen::resolve`, not in the
validation function. Thus a copy at a full slot gets each check of the topic: a validator
outside the PTC, or an invalid signature, is still REJECT, and a signature with no verdict is
still IGNORE with no change to `Seen`.

A first copy that is pending when its slot goes before the floor is IGNORE as not current. The
tests in `crates/gossip-validation/tests/payload_attestation.rs` pin each bound: the 500 ms
edge with an automatic and an explicit prune, pending copies across a prune, a clock that goes
back, the slot limit (`seen_keeps_at_most_the_slot_limit_and_removes_the_oldest_slot`,
`a_slot_that_the_slot_limit_removes_must_not_accept_again`), a head change that admits two PTCs
in one slot, the per-slot limit with five heads
(`an_accepted_validator_must_not_accept_again_when_a_fifth_head_fills_the_slot`,
`a_full_slot_keeps_each_validator_and_ignores_a_new_validator`), and invalid copies that change
nothing (`an_invalid_copy_at_the_validator_limit_removes_no_validator`,
`an_invalid_copy_does_not_prune_seen`).

The only public prune is `Seen::prune_payload_attestations(store, current_time_ms)`. It prunes
by the oldest current slot of the time, and an earlier time does nothing: the floor, the keys
and the record of the last pruned slot stay as they are. The prune by slot is private to
`seen.rs`, so no caller can give a floor that is not from the clock.
