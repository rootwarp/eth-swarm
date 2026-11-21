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
//!   check ([`oldest_current_slot`]), and [`Seen::resolve`] removes each slot before it. A key
//!   of a slot that is already removed accepts and does not add the slot again. A caller can
//!   also prune with no valid message: [`Seen::prune_payload_attestations`] and
//!   [`Seen::prune_payload_attestations_before`].
//! - **Slots.** `Seen` keeps at most [`MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS`] slots, and removes
//!   the oldest slot first. A clock that moves normally keeps at most two slots current at a
//!   time. The limit is for a clock that jumps, or a slot duration that is very short.
//! - **Validators of a slot.** The PTC check reads `get_ptc(head_state, data.slot)` of the head
//!   at the time of the check, and the head can change in a slot. Each head can have another
//!   PTC for the slot, so a slot can admit the union of the PTCs of its heads: more than
//!   `PTC_SIZE` validators. `Seen` keeps at most [`MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT`]
//!   times `PTC_SIZE` validators for each slot. At that limit, a new validator removes the
//!   oldest validator of the slot. A removed key lets a second copy of its message pass again
//!   (a duplicate, not an invalid message), and no valid message is ignored because of the
//!   limit.
//!
//! [`is_current_slot`]: crate::is_current_slot
//! [`oldest_current_slot`]: crate::oldest_current_slot

use crate::payload_attestation::oldest_current_slot;
use crate::verdict::{IgnoreReason, RejectReason, Verdict};
use crate::StoreView;
use consensus_types::primitives::{BuilderIndex, Hash32, Root, Slot, ValidatorIndex};
use state_transition::{BackendError, Preset};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// The most slots of payload attestation keys that [`Seen`] keeps. A new slot past the limit
/// removes the oldest slot.
pub const MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS: usize = 8;

/// The most heads of a slot whose PTCs [`Seen`] keeps in full: a slot keeps at most this
/// number times `PTC_SIZE` validators (64 in the minimal preset, 2,048 in the mainnet preset).
/// A new validator past the limit removes the oldest validator of the slot.
pub const MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT: usize = 4;

/// The keys of the fully valid gossip messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    /// `seen.execution_payload_envelopes`.
    execution_payload_envelopes: HashSet<(Root, BuilderIndex)>,
    /// `seen.execution_payloads`, with only what its readers need of each payload.
    execution_payloads: HashMap<Hash32, SeenPayload>,
    /// `seen.payload_attestation_validators`, by slot.
    payload_attestation_validators: BTreeMap<Slot, SlotValidators>,
    /// The oldest slot of the payload attestation keys. It only increases, and the slots
    /// before it are removed.
    min_payload_attestation_slot: Slot,
}

/// The validators of the payload attestation keys of one slot.
#[derive(Debug, Clone, Default)]
struct SlotValidators {
    /// The validators.
    set: HashSet<ValidatorIndex>,
    /// The same validators, oldest first: the order in which a full slot removes them.
    order: VecDeque<ValidatorIndex>,
}

/// Two slots are equal if they have the same validators, in any order.
impl PartialEq for SlotValidators {
    fn eq(&self, other: &Self) -> bool {
        self.set == other.set
    }
}

impl Eq for SlotValidators {}

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
            .is_some_and(|validators| validators.set.contains(&validator_index))
    }

    /// The number of payload attestation keys, in all slots.
    pub fn payload_attestation_count(&self) -> usize {
        self.payload_attestation_validators
            .values()
            .map(|validators| validators.set.len())
            .sum()
    }

    /// The number of slots with a payload attestation key.
    pub fn payload_attestation_slot_count(&self) -> usize {
        self.payload_attestation_validators.len()
    }

    /// Removes the payload attestation keys of each slot that is not current at
    /// `current_time_ms` and cannot be current again: each slot before
    /// [`oldest_current_slot`]. For a caller with no valid message to resolve, for example at
    /// the start of a slot.
    ///
    /// [`oldest_current_slot`]: crate::oldest_current_slot
    pub fn prune_payload_attestations<E, S>(&mut self, store: &S, current_time_ms: u64)
    where
        E: Preset,
        S: StoreView<E> + ?Sized,
    {
        self.prune_payload_attestations_before(oldest_current_slot(store, current_time_ms));
    }

    /// Removes the payload attestation keys of each slot before `min_slot`. A later key of such
    /// a slot does not add the slot again. A `min_slot` at or before an earlier one changes
    /// nothing.
    pub fn prune_payload_attestations_before(&mut self, min_slot: Slot) {
        if min_slot <= self.min_payload_attestation_slot {
            return;
        }
        self.min_payload_attestation_slot = min_slot;
        self.payload_attestation_validators =
            self.payload_attestation_validators.split_off(&min_slot);
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
    /// module documentation), only for `Ok(true)`.
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
                // The slot stopped being current after the check, so no message of it can
                // pass the check again.
                if slot < self.min_payload_attestation_slot {
                    return Verdict::Accept;
                }
                let slots = &mut self.payload_attestation_validators;
                let validators = slots.entry(slot).or_default();
                if validators.set.contains(&validator_index) {
                    return Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
                        slot,
                        validator_index,
                    });
                }
                while validators.order.len() >= max_per_slot.max(1) {
                    let Some(oldest) = validators.order.pop_front() else {
                        break;
                    };
                    validators.set.remove(&oldest);
                }
                validators.set.insert(validator_index);
                validators.order.push_back(validator_index);
                // A new slot that is older than each kept slot is removed again at once.
                while slots.len() > MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS {
                    slots.pop_first();
                }
                Verdict::Accept
            }
        }
    }
}
