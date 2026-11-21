//! The `payload_attestation_message` topic: `validate_payload_attestation_message_gossip`
//! (L891-954), with `is_current_slot` (`altair/p2p-interface.md` L95-107) and
//! `is_within_slot_range` (`phase0/p2p-interface.md` L395-411).

use crate::seen::{Seen, SeenKey};
use crate::verdict::{IgnoreReason, RejectReason, Verdict};
use crate::StoreView;
use consensus_types::gloas::PayloadAttestationMessage;
use consensus_types::primitives::{Epoch, Slot};
use consensus_types::signing::{
    compute_signing_root, SignatureSet, SignerRef, DOMAIN_PTC_ATTESTER,
};
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

/// `validate_payload_attestation_message_gossip` (L891-954) up to the signature check.
///
/// It runs the IGNORE and REJECT checks before the signature in spec order, and gives the
/// first that fails. If each passes, it gives [`Verdict::Pending`] with the set of
/// `bls.Verify` and the key of the message. The caller must verify the set and give the result
/// to [`Seen::resolve`], which adds the key to `Seen` only for a valid signature.
///
/// The checks of the validator read the head state, `store.block_states[get_head(store).root]`
/// ([`StoreView::head_state`]), not the post-state of the attested block: the index must be in
/// its registry and in its PTC of `data.slot`, and the signing root has its PTC domain at the
/// epoch of `data.slot`. A store with no head state, or a head state with no PTC of
/// `data.slot`, is IGNORE: neither proves the message invalid.
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
    if seen.has_payload_attestation(data.slot, validator_index) {
        return Verdict::Ignore(IgnoreReason::PayloadAttestationAlreadySeen {
            slot: data.slot,
            validator_index,
        });
    }
    if !is_current_slot(store, data.slot, current_time_ms) {
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
        seen_key: SeenKey::payload_attestation(data.slot, validator_index),
    }
}
