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
  start of slot `s + 1`. After that time no message of `s` passes `is_current_slot` again.
  `oldest_current_slot` gives the first slot that is still current, and `Seen::resolve` and
  `Seen::prune_payload_attestations` remove the slots before it.
- At most `MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS` (8) slots. A new slot past the limit removes the
  oldest slot.
- At most `MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT` (4) times `PTC_SIZE` validators for each
  slot: 64 in the minimal preset and 2,048 in the mainnet preset. A new validator past the
  limit removes the oldest validator of the slot.

A removed key lets a second copy of its message pass again, where the spec ignores it. That
copy is a duplicate of a valid message, not an invalid message, and the limits never make a
valid first copy IGNORE. The tests in `crates/gossip-validation/tests/payload_attestation.rs`
pin each bound: the 500 ms edge with an automatic and an explicit prune, the slot limit, a
head change that admits two PTCs in one slot, the per-slot limit with five heads, and invalid
copies that change nothing.
