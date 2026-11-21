# Gossip: a head state with no PTC of the message slot is IGNORE

This record also has the bounds of `Seen` in `crates/gossip-validation`: the payload
attestation keys of a slot with head changes, and the envelope keys and payloads (the last two
sections).

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

## Deviation: a bounded `Seen` for envelopes

`validate_execution_payload_envelope_gossip` (`specs/gloas/p2p-interface.md` L817-885) adds
each valid envelope to `seen.execution_payload_envelopes` and keeps its payload in
`seen.execution_payloads` (L881-883). The spec does not prune them, and the only slot check of
the topic is the finalized slot (L846-849). A prune by the finalized slot has no bound while the
chain does not finalize: each slot adds a key and a payload, and a proposer that equivocates
adds more.

**What.** `Seen` in `crates/gossip-validation/src/seen.rs` keeps the envelope keys and the
payloads by `payload.slot_number`: `execution_payload_envelopes: BTreeMap<Slot, SlotEnvelopes>`,
where `SlotEnvelopes` has the keys `(block_root, builder_index)` and the payloads by
`block_hash`. `Seen::has_execution_payload_envelope` and `Seen::execution_payload` read each
kept slot. The bounds are those of the payload attestation keys:

- **Floor.** The key of an envelope carries `oldest_current_slot(store, store.time_ms())`
  (`StoreView::time_ms` is `store.time_ms`, the time of the last tick). `Seen::resolve` removes
  each slot before it with its payloads, and `Seen::prune_execution_payload_envelopes(store,
  current_time_ms)` does the same with no envelope. The floor
  (`Seen::min_execution_payload_envelope_slot`) does not decrease: an earlier time changes
  nothing.
- **Below the floor.** `Seen` keeps the keys of the last slot before the floor, but not its
  payloads, until the floor moves again (`Seen::has_pruned_execution_payload_envelope`). An
  envelope or a key of a slot before the floor is IGNORE, never ACCEPT: `EnvelopeAlreadySeen`
  if that record has its key, else `NotCurrentSlot`. In the validation the record is part of
  the duplicate check, the first check, and the floor check comes after the finalized slot
  check and before the block slot check. Thus `UnknownBlock`, `BlockNotValid` and
  `BeforeFinalizedSlot` keep their spec order. `Seen::resolve` does the same checks, so two
  copies that were pending across a prune do not both accept. A clock of the store that goes
  back does not change this.
- **Slots.** At most `MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS` (8). A new slot past the limit
  removes the oldest slot and moves the floor past it, with the record, so the removed slot is
  never ACCEPT again.
- **Keys of a slot.** At most `MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT` (16). The bid of a
  block names one builder, so a slot has one key for each of its blocks, and more than one
  block only if its proposer equivocates. At the limit, a valid envelope of a new block is
  IGNORE (`ExecutionPayloadEnvelopeSlotFull { slot }`) and `Seen` does not change, for the
  reasons of a full payload attestation slot above.
- Only a valid signature (`Ok(true)` in `Seen::resolve`) changes `Seen`. An invalid signature,
  a signature with no verdict, and each IGNORE or REJECT before the signature leave the keys,
  the payloads, the floor and the record as they are.

**Why.** `Seen` must have a bound also while the chain does not finalize, and the finalized
slot gives none then. The clock gives one: on a healthy network the envelope of a slot comes in
that slot, and the payload attestation topic already ends a slot at
`end(s) + MAXIMUM_GOSSIP_CLOCK_DISPARITY`. The limits keep the bound for a clock that jumps and
for a proposer that equivocates.

**What differs.**

- The spec accepts a valid envelope that is not seen, of any slot from the finalized slot.
  Here an envelope of a slot before the floor is IGNORE. Such an envelope can still come by
  req/resp (`ExecutionPayloadEnvelopesByRange`, `ExecutionPayloadEnvelopesByRoot`), which does
  not read `Seen`.
- A valid envelope of a new block in a full slot is IGNORE.
- An envelope whose key the spec has seen, but `Seen` no longer keeps, and whose
  `payload.slot_number` is at or after the floor but not the slot of its block, is REJECT
  (`SlotMismatch`) where the spec gives IGNORE as a duplicate. The mismatch is a proven
  violation.
- The validation compares the slot with the floor of `Seen`, not with the clock. An envelope
  of a slot before the oldest current slot, but not before the floor, goes to the signature
  check, and `Seen::resolve` then gives IGNORE (`NotCurrentSlot`).
- `seen.execution_payloads` has only the payloads of the kept slots. The
  `execution_payload_bid` topic (L1029-1038) reads the payload of `bid.parent_block_hash`.
  That topic is not in this crate yet. When it comes, a bid whose parent payload is before the
  floor finds no payload here, where the spec's `Seen` has it: that change must read the
  parent payload from another source, for example the store, or IGNORE the bid.

No envelope is ACCEPT that the spec does not accept, and IGNORE does not penalize the peer.

**Tests.** In `crates/gossip-validation/tests/execution_payload.rs`:

- `an_envelope_slot_stays_through_the_clock_disparity_and_a_valid_envelope_then_removes_it`
  and `an_explicit_prune_removes_an_envelope_slot_only_after_the_clock_disparity`: at
  `end(1) + 500 ms` slot 1 and its payload stay, and at `end(1) + 501 ms` a valid envelope of
  slot 2 (at the time of `on_tick`) or an explicit prune removes both.
- `a_pending_duplicate_envelope_across_a_prune_must_ignore` and
  `pending_envelopes_that_resolve_only_after_a_prune_must_ignore`: with each kind of prune, the
  first copy accepts and the second is `EnvelopeAlreadySeen`, and copies that resolve only after
  the prune are `NotCurrentSlot`.
- `an_envelope_of_a_pruned_slot_must_ignore_also_at_an_earlier_time`: the validation and the
  commit IGNORE a slot before the floor while the clock of the store goes back, and a prune with
  an earlier time changes nothing.
- `seen_keeps_the_envelopes_of_the_last_pruned_slot_until_the_floor_moves_again`.
- `seen_keeps_at_most_the_envelope_slot_limit_and_a_removed_slot_must_not_accept_again` and
  `a_full_envelope_slot_keeps_each_envelope_and_ignores_a_new_block`: the two limits.
- `an_invalid_or_unverified_envelope_does_not_prune_seen`, and the invalid copies in the two
  limit tests: they change nothing.
