//! The spec's `Seen` (`gloas/p2p-interface.md` L188-219), for the topics of this crate.
//!
//! A validation function only reads `Seen`. Its [`Verdict::Pending`] carries a [`SeenKey`], and
//! [`Seen::resolve`] adds that key only for a valid signature, the last check of a topic. Thus
//! `Seen` holds only fully valid messages: a copy with an invalid signature, or one that the
//! verifier gave no verdict on, leaves it unchanged, and a later valid copy can still pass.
//!
//! The spec does not prune `Seen`. Here the envelope keys grow by one entry for each accepted
//! envelope, which a block of the chain limits. The change that connects them to gossip must
//! bound them, for example by the finalized slot.
//!
//! The payload attestation keys have three bounds. Only a valid key changes them, so an invalid
//! copy removes nothing and uses no capacity.
//!
//! - **Clock disparity.** A message of slot `s` passes the current slot check
//!   ([`is_current_slot`]) until `end(s) + MAXIMUM_GOSSIP_CLOCK_DISPARITY`, where `end(s)` is
//!   the start of slot `s + 1`. After that time no message of `s` passes the check again, so its
//!   keys are not necessary. A key carries the oldest slot that is current at the time of its
//!   check ([`oldest_current_slot`]), and [`Seen::resolve`] removes each slot before it. That
//!   slot is the floor ([`Seen::min_payload_attestation_slot`]). A caller can also prune with
//!   no valid message: [`Seen::prune_payload_attestations`].
//! - **Below the floor.** A key of a slot before the floor is never ACCEPT, and does not add
//!   the slot again. Two copies of a message can both be pending while the slot is current, and
//!   the slot can go before the floor after the first copy accepts. Thus `Seen` keeps the
//!   validators of the last slot before the floor
//!   ([`Seen::has_pruned_payload_attestation`]) until the floor moves again. A key of that
//!   slot and validator is IGNORE as a duplicate. Any other key before the floor is IGNORE as
//!   not current. The validation of a message before the floor is IGNORE for the same reasons.
//! - **Monotonic clock.** The prune assumes that `current_time_ms` does not decrease from one
//!   call to the next. A prune with an earlier time does not lower the floor and changes
//!   nothing. If a caller gives an earlier time, [`is_current_slot`] can be true again for a
//!   slot before the floor, but the validation of a message of that slot is still IGNORE.
//! - **Slots.** `Seen` keeps at most [`MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS`] slots. A new slot
//!   past the limit removes the oldest slot and moves the floor past it, as a prune does. Thus
//!   a message of the removed slot is never ACCEPT again. A clock that moves normally keeps at
//!   most two slots current at a time. The limit is for a clock that jumps, or a slot duration
//!   that is very short.
//! - **Validators of a slot.** The PTC check reads `get_ptc(head_state, data.slot)` of the head
//!   at the time of the check, and the head can change in a slot. Each head can have another
//!   PTC for the slot, so a slot can admit the union of the PTCs of its heads: more than
//!   `PTC_SIZE` validators. `Seen` keeps at most [`MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT`]
//!   times `PTC_SIZE` validators for each slot. At that limit, a key of a new validator of the
//!   slot is IGNORE ([`IgnoreReason::PayloadAttestationSlotFull`]) and `Seen` does not change.
//!   Each validator that `Seen` keeps stays a duplicate until the floor passes its slot, so no
//!   copy of a message is ACCEPT twice. A valid first message of a new validator in a full slot
//!   is IGNORE: it is not propagated, and its peer is not penalized. To remove the oldest
//!   validator instead lets a copy of its message pass again, and a record of each removed
//!   validator has no bound.
//!
//! [`is_current_slot`]: crate::is_current_slot
//! [`oldest_current_slot`]: crate::oldest_current_slot

use crate::payload_attestation::oldest_current_slot;
use crate::verdict::{IgnoreReason, RejectReason, Verdict};
use crate::StoreView;
use consensus_types::primitives::{BuilderIndex, Hash32, Root, Slot, ValidatorIndex};
use state_transition::{BackendError, Preset};
use std::collections::{BTreeMap, HashMap, HashSet};

/// The most slots of payload attestation keys that [`Seen`] keeps. A new slot past the limit
/// removes the oldest slot, and the floor moves past that slot.
pub const MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS: usize = 8;

/// The most heads of a slot whose PTCs [`Seen`] keeps in full: a slot keeps at most this
/// number times `PTC_SIZE` validators (64 in the minimal preset, 2,048 in the mainnet preset).
/// A new validator past the limit is IGNORE ([`IgnoreReason::PayloadAttestationSlotFull`]), and
/// the slot keeps each validator that it has.
pub const MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT: usize = 4;

/// The keys of the fully valid gossip messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    /// `seen.execution_payload_envelopes`.
    execution_payload_envelopes: HashSet<(Root, BuilderIndex)>,
    /// `seen.execution_payloads`, with only what its readers need of each payload.
    execution_payloads: HashMap<Hash32, SeenPayload>,
    /// `seen.payload_attestation_validators`, by slot.
    payload_attestation_validators: BTreeMap<Slot, HashSet<ValidatorIndex>>,
    /// The oldest slot of the payload attestation keys: the floor. It only increases, and the
    /// slots before it are removed.
    min_payload_attestation_slot: Slot,
    /// The validators of the last slot before the floor, as the prune that moved the floor
    /// found them. The next move of the floor replaces them.
    pruned_payload_attestations: Option<(Slot, HashSet<ValidatorIndex>)>,
}

/// What `seen.execution_payloads[block_hash]` keeps of a payload. The spec keeps the whole
/// payload, and its reader (the `execution_payload_bid` topic) reads only `gas_limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenPayload {
    /// `payload.gas_limit`.
    pub gas_limit: u64,
}

/// The key of a pending message, which [`Seen::resolve`] adds once the message is fully valid.
/// Only the validation functions of this crate make one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenKey(Key);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    /// The key of an envelope, with the payload that `Seen` also keeps.
    ExecutionPayloadEnvelope {
        block_root: Root,
        builder_index: BuilderIndex,
        block_hash: Hash32,
        payload: SeenPayload,
    },
    /// The key of a payload attestation message, with the bounds that `Seen` applies when it
    /// adds the key.
    PayloadAttestation {
        slot: Slot,
        validator_index: ValidatorIndex,
        /// The oldest slot that is current at the time of the check: the slots before it are
        /// removed.
        prune_before: Slot,
        /// The most validators that a slot keeps.
        max_per_slot: usize,
    },
}

impl SeenKey {
    /// The key of an envelope for `block_root` from `builder_index`, whose payload has
    /// `block_hash` and `gas_limit`.
    pub(crate) fn execution_payload_envelope(
        block_root: Root,
        builder_index: BuilderIndex,
        block_hash: Hash32,
        gas_limit: u64,
    ) -> Self {
        Self(Key::ExecutionPayloadEnvelope {
            block_root,
            builder_index,
            block_hash,
            payload: SeenPayload { gas_limit },
        })
    }

    /// The key of a payload attestation message of `slot` from `validator_index`, checked when
    /// `prune_before` was the oldest current slot. A slot keeps at most `max_per_slot`
    /// validators.
    pub(crate) fn payload_attestation(
        slot: Slot,
        validator_index: ValidatorIndex,
        prune_before: Slot,
        max_per_slot: usize,
    ) -> Self {
        Self(Key::PayloadAttestation {
            slot,
            validator_index,
            prune_before,
            max_per_slot,
        })
    }
}

impl Seen {
    /// `(block_root, builder_index) in seen.execution_payload_envelopes`.
    pub fn has_execution_payload_envelope(
        &self,
        block_root: Root,
        builder_index: BuilderIndex,
    ) -> bool {
        self.execution_payload_envelopes
            .contains(&(block_root, builder_index))
    }

    /// `seen.execution_payloads[block_hash]`.
    pub fn execution_payload(&self, block_hash: Hash32) -> Option<&SeenPayload> {
        self.execution_payloads.get(&block_hash)
    }

    /// `(slot, validator_index) in seen.payload_attestation_validators`.
    pub fn has_payload_attestation(&self, slot: Slot, validator_index: ValidatorIndex) -> bool {
        self.payload_attestation_validators
            .get(&slot)
            .is_some_and(|validators| validators.contains(&validator_index))
    }

    /// The number of payload attestation keys, in all slots.
    pub fn payload_attestation_count(&self) -> usize {
        self.payload_attestation_validators
            .values()
            .map(HashSet::len)
            .sum()
    }

    /// The number of slots with a payload attestation key.
    pub fn payload_attestation_slot_count(&self) -> usize {
        self.payload_attestation_validators.len()
    }

    /// The floor of the payload attestation keys: the oldest slot that `Seen` can keep. Each
    /// slot before it is removed, and a key of such a slot is IGNORE. It does not decrease.
    pub fn min_payload_attestation_slot(&self) -> Slot {
        self.min_payload_attestation_slot
    }

    /// `(slot, validator_index)` was a key of the last slot before the floor when a prune
    /// removed that slot. [`Seen::has_payload_attestation`] is false for it. The next move of
    /// the floor removes this record.
    pub fn has_pruned_payload_attestation(
        &self,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> bool {
        self.pruned_payload_attestations
            .as_ref()
            .is_some_and(|(pruned, validators)| {
                *pruned == slot && validators.contains(&validator_index)
            })
    }

    /// Removes the payload attestation keys of each slot that is not current at
    /// `current_time_ms` and cannot be current again: each slot before
    /// [`oldest_current_slot`]. For a caller with no valid message to resolve, for example at
    /// the start of a slot.
    ///
    /// The caller must give a time that does not decrease from one call to the next. The floor
    /// does not decrease: a time whose oldest current slot is at or before the floor changes
    /// nothing, also the keys and the record of the last pruned slot.
    ///
    /// [`oldest_current_slot`]: crate::oldest_current_slot
    pub fn prune_payload_attestations<E, S>(&mut self, store: &S, current_time_ms: u64)
    where
        E: Preset,
        S: StoreView<E> + ?Sized,
    {
        self.prune_payload_attestations_before(oldest_current_slot(store, current_time_ms));
    }

    /// Removes the payload attestation keys of each slot before `min_slot`, and makes
    /// `min_slot` the floor. A later key of such a slot is IGNORE and does not add the slot
    /// again. The validators of slot `min_slot - 1` stay as a record of duplicates
    /// ([`Seen::has_pruned_payload_attestation`]), and replace the record of the earlier floor.
    ///
    /// The floor does not decrease: a `min_slot` at or before the floor changes nothing, also
    /// the record. Only this module gives a slot: an external caller prunes by time.
    fn prune_payload_attestations_before(&mut self, min_slot: Slot) {
        if min_slot <= self.min_payload_attestation_slot {
            return;
        }
        self.min_payload_attestation_slot = min_slot;
        self.pruned_payload_attestations =
            split_before(&mut self.payload_attestation_validators, min_slot);
    }

    /// The end of a [`Verdict::Pending`]: `signatures` is the BLS verdict of its sets, as
    /// `state_transition::SignatureBackend` gives it.
    ///
    /// - `Ok(true)`: the message is fully valid. `Seen` gets `seen_key`, and the verdict is
    ///   ACCEPT. If another copy got the key first, the verdict is IGNORE and `Seen` does not
    ///   change, so only one copy of a message is ACCEPT.
    /// - `Ok(false)`: REJECT, and `Seen` does not change.
    /// - `Err`: no verdict. IGNORE, and `Seen` does not change.
    ///
    /// The key of a payload attestation message also applies the bounds of `Seen` (see the
    /// module documentation), only for `Ok(true)`. A key of a slot before the floor is never
    /// ACCEPT: IGNORE as a duplicate if the record of the last pruned slot has it, else IGNORE
    /// as not current.
    pub fn resolve(
        &mut self,
        seen_key: SeenKey,
        signatures: Result<bool, BackendError>,
    ) -> Verdict {
        match signatures {
            Ok(true) => self.commit(seen_key), // stamped-commits: not an env txn (Seen)
            Ok(false) => Verdict::Reject(RejectReason::InvalidSignature),
            Err(_) => Verdict::Ignore(IgnoreReason::NoSignatureVerdict),
        }
    }

    /// Adds the key of a fully valid message ("Mark this envelope as seen and store its
    /// payload", L881-883; "Mark this payload_attestation as seen", L952-953). Only
    /// [`Seen::resolve`] calls it, after a valid signature.
    fn commit(&mut self, SeenKey(key): SeenKey) -> Verdict {
        match key {
            Key::ExecutionPayloadEnvelope {
                block_root,
                builder_index,
                block_hash,
                payload,
            } => {
                if !self
                    .execution_payload_envelopes
                    .insert((block_root, builder_index))
                {
                    return Verdict::Ignore(IgnoreReason::EnvelopeAlreadySeen {
                        block_root,
                        builder_index,
                    });
                }
                self.execution_payloads.insert(block_hash, payload);
                Verdict::Accept
            }
            Key::PayloadAttestation {
                slot,
                validator_index,
                prune_before,
                max_per_slot,
            } => {
                self.prune_payload_attestations_before(prune_before);
                // The slot stopped being current after the check, and `Seen` does not keep it.
                // Another copy of the message can have accepted before the prune. Thus this
                // copy is IGNORE, and does not add the slot again.
                if slot < self.min_payload_attestation_slot {
                    if self.has_pruned_payload_attestation(slot, validator_index) {
                        return Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
                            slot,
                            validator_index,
                        });
                    }
                    return Verdict::Ignore(IgnoreReason::NotCurrentSlot { slot });
                }
                let slots = &mut self.payload_attestation_validators;
                if let Some(validators) = slots.get(&slot) {
                    if validators.contains(&validator_index) {
                        return Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
                            slot,
                            validator_index,
                        });
                    }
                    // A full slot keeps each validator that it has, so each stays a duplicate.
                    if validators.len() >= max_per_slot.max(1) {
                        return Verdict::Ignore(IgnoreReason::PayloadAttestationSlotFull { slot });
                    }
                }
                slots.entry(slot).or_default().insert(validator_index);
                // A slot past the limit goes before the floor, so that no key of it is ACCEPT
                // again. A new slot that is older than each kept slot goes at once, and the
                // record of the last pruned slot keeps its key.
                while let Some(oldest) = oldest_past_the_limit(
                    &self.payload_attestation_validators,
                    MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS,
                ) {
                    self.prune_payload_attestations_before(oldest + 1);
                }
                Verdict::Accept
            }
        }
    }
}

/// The oldest slot of `slots`, if `slots` has more than `limit` slots. That slot is before
/// another slot, so the slot after it does not overflow.
fn oldest_past_the_limit<V>(slots: &BTreeMap<Slot, V>, limit: usize) -> Option<Slot> {
    if slots.len() > limit {
        slots.keys().next().copied()
    } else {
        None
    }
}

/// Removes each slot of `slots` before `min_slot`. Gives the removed keys of slot
/// `min_slot - 1`, if `slots` had that slot: the record of the last pruned slot.
fn split_before<V>(slots: &mut BTreeMap<Slot, V>, min_slot: Slot) -> Option<(Slot, V)> {
    let kept = slots.split_off(&min_slot);
    let mut removed = std::mem::replace(slots, kept);
    removed
        .pop_last()
        .filter(|(slot, _)| slot.checked_add(1) == Some(min_slot))
}
