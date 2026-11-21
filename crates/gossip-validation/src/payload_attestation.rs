//! The `payload_attestation_message` topic: `validate_payload_attestation_message_gossip`
//! (L891-954), with `is_current_slot` (`altair/p2p-interface.md` L95-107) and
//! `is_within_slot_range` (`phase0/p2p-interface.md` L395-411).
//!
//! # Deviation: a head state with no PTC of the slot is IGNORE
//!
//! The spec reads `get_ptc(state, data.slot)` on the head state (L937-938). `get_ptc`
//! (`gloas/beacon-chain.md` L1392-1404) asserts `epoch >= GLOAS_FORK_EPOCH`,
//! `epoch + 1 >= state_epoch` and `epoch <= state_epoch + MIN_SEED_LOOKAHEAD`, where `epoch` is
//! the epoch of `data.slot` and `state_epoch` is the epoch of the head state. The spec does not
//! say what a failed assert is in this function. Here it is IGNORE ([`IgnoreReason::NoPtc`]),
//! not REJECT. The earlier checks already proved the fork epoch and the current slot, so a
//! failed assert shows that the local head state is out of the window, for example a head that
//! is behind the current slot during a sync. It does not show that the message is invalid.
//! IGNORE does not penalize the peer, and `Seen` does not get the key, so a later copy can
//! pass when the head is in the window again. `arch/gossip-payload-attestation-ptc.md` records
//! this deviation and the tests that pin it.

use crate::seen::{Seen, SeenKey, MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT};
use crate::verdict::{IgnoreReason, RejectReason, Verdict};
use crate::StoreView;
use consensus_types::gloas::PayloadAttestationMessage;
use consensus_types::primitives::{Epoch, Slot};
use consensus_types::signing::{
    compute_signing_root, SignatureSet, SignerRef, DOMAIN_PTC_ATTESTER,
};
use ssz_types::typenum::Unsigned;
use state_transition::accessors::get_domain;
use state_transition::caches::get_ptc;
use state_transition::Preset;

/// `MAXIMUM_GOSSIP_CLOCK_DISPARITY` (`configs/{minimal,mainnet}.yaml`, 500 ms in both).
pub const MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS: u64 = 500;

/// `is_current_slot(store, slot, current_time_ms)`: `is_within_slot_range` with a slot range
/// of 0. The time is in `[start, end]` of `slot`, with `MAXIMUM_GOSSIP_CLOCK_DISPARITY` on both
/// ends, where `end` is the start of the next slot.
///
/// The times are `compute_time_at_slot_ms(store.genesis_time_ms, slot)`, in 128 bits: a slot
/// whose time does not fit in 64 bits is not current, where the spec's `Uint64` fails.
pub fn is_current_slot<E, S>(store: &S, slot: Slot, current_time_ms: u64) -> bool
where
    E: Preset,
    S: StoreView<E> + ?Sized,
{
    let time_at = |slot: u128| {
        u128::from(store.genesis_time_ms()) + slot * u128::from(store.slot_duration_ms().get())
    };
    let disparity = u128::from(MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS);
    let now = u128::from(current_time_ms);
    let start_time_ms = time_at(u128::from(slot));
    let end_time_ms = time_at(u128::from(slot) + 1);
    now + disparity >= start_time_ms && end_time_ms + disparity >= now
}

/// The oldest slot that is current at `current_time_ms` ([`is_current_slot`]). Not a spec
/// function: [`Seen`] removes the keys of the slots before it.
///
/// A slot `s` is not current once `end(s) + MAXIMUM_GOSSIP_CLOCK_DISPARITY < current_time_ms`,
/// where `end(s)` is the start of slot `s + 1`. It cannot be current again if the time does not
/// decrease: the prune of [`Seen`] assumes such a monotonic clock. The result is 0 up to
/// `genesis_time_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY`. The times are in 128 bits, so no value
/// can overflow.
pub fn oldest_current_slot<E, S>(store: &S, current_time_ms: u64) -> Slot
where
    E: Preset,
    S: StoreView<E> + ?Sized,
{
    let first_expiry =
        u128::from(store.genesis_time_ms()) + u128::from(MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS);
    let now = u128::from(current_time_ms);
    if now <= first_expiry {
        return 0;
    }
    // Slot `s` is past the disparity if `(s + 1) * slot_duration < over`.
    let over = now - first_expiry;
    let slot = (over - 1) / u128::from(store.slot_duration_ms().get());
    Slot::try_from(slot).unwrap_or(Slot::MAX)
}

/// `validate_payload_attestation_message_gossip` (L891-954) up to the signature check.
///
/// It runs the IGNORE and REJECT checks before the signature in spec order, and gives the
/// first that fails. If each passes, it gives [`Verdict::Pending`] with the set of
/// `bls.Verify` and the key of the message. The caller must verify the set and give the result
/// to [`Seen::resolve`], which adds the key to `Seen` only for a valid signature. The key also
/// has the oldest current slot at `current_time_ms` ([`oldest_current_slot`]) and the limit of
/// validators for each slot, `MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT * PTC_SIZE`, which
/// [`Seen::resolve`] applies.
///
/// `Seen` removes the keys of the slots before its floor
/// ([`Seen::min_payload_attestation_slot`]). A message of such a slot is IGNORE: as a duplicate
/// if the record of the last pruned slot has its key
/// ([`Seen::has_pruned_payload_attestation`]), else as not current. This is also true for a
/// `current_time_ms` before the time of the prune, where [`is_current_slot`] can be true again.
///
/// The checks of the validator read the head state, `store.block_states[get_head(store).root]`
/// ([`StoreView::head_state`]), not the post-state of the attested block: the index must be in
/// its registry and in its PTC of `data.slot`, and the signing root has its PTC domain at the
/// epoch of `data.slot`. A store with no head state, or a head state with no PTC of
/// `data.slot` (the deviation of the module documentation), is IGNORE: neither proves the
/// message invalid.
///
/// `gloas_fork_epoch` is the config value `GLOAS_FORK_EPOCH`. The signer is the validator by
/// index. Its key is the key of the head state: a PTC member is active, so the finalized
/// registry has its index.
pub fn validate_payload_attestation_message_gossip<E, S>(
    seen: &Seen,
    store: &S,
    payload_attestation_message: &PayloadAttestationMessage,
    current_time_ms: u64,
    gloas_fork_epoch: Epoch,
) -> Verdict
where
    E: Preset,
    S: StoreView<E> + ?Sized,
{
    let data = &payload_attestation_message.data;
    let validator_index = payload_attestation_message.validator_index;
    let block_root = data.beacon_block_root;
    let epoch = E::epoch_at_slot(data.slot);

    if epoch < gloas_fork_epoch {
        return Verdict::Reject(RejectReason::BeforeGloasFork {
            slot: data.slot,
            fork_epoch: gloas_fork_epoch,
        });
    }
    if seen.has_payload_attestation(data.slot, validator_index)
        || seen.has_pruned_payload_attestation(data.slot, validator_index)
    {
        return Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
            slot: data.slot,
            validator_index,
        });
    }
    // A slot before the floor of `Seen` is not current, also for a clock that went back.
    if data.slot < seen.min_payload_attestation_slot()
        || !is_current_slot(store, data.slot, current_time_ms)
    {
        return Verdict::Ignore(IgnoreReason::NotCurrentSlot { slot: data.slot });
    }
    let Some(block) = store.block(block_root) else {
        return Verdict::Ignore(IgnoreReason::UnknownBlock(block_root));
    };
    if store.block_state(block_root).is_none() {
        return Verdict::Reject(RejectReason::BlockNotValid(block_root));
    }
    if block.slot != data.slot {
        return Verdict::Ignore(IgnoreReason::BlockSlotMismatch {
            block: block.slot,
            message: data.slot,
        });
    }

    let Some(state) = store.head_state() else {
        return Verdict::Ignore(IgnoreReason::NoHeadState);
    };
    let in_registry = usize::try_from(validator_index).is_ok_and(|i| i < state.validators.len());
    if !in_registry {
        return Verdict::Reject(RejectReason::UnknownValidator(validator_index));
    }
    let Ok(ptc) = get_ptc(state, data.slot) else {
        return Verdict::Ignore(IgnoreReason::NoPtc { slot: data.slot });
    };
    if !ptc.contains(&validator_index) {
        return Verdict::Reject(RejectReason::NotInPtc {
            validator_index,
            slot: data.slot,
        });
    }
    let domain = get_domain(state, DOMAIN_PTC_ATTESTER, Some(epoch));
    let set = SignatureSet::single(
        SignerRef::Validator(validator_index),
        compute_signing_root(data, domain),
        payload_attestation_message.signature,
    );
    Verdict::Pending {
        bls_sets: vec![set],
        seen_key: SeenKey::payload_attestation(
            data.slot,
            validator_index,
            oldest_current_slot(store, current_time_ms),
            MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT * E::PtcSize::to_usize(),
        ),
    }
}
