//! The handlers `on_attestation` (P0 L1013-1031) and `on_attester_slashing` (P0 L1040-1057),
//! which Gloas keeps, with the Gloas `validate_on_attestation` (G L914-955) and
//! `update_latest_messages` (G L965-983).
//!
//! A handler that fails leaves the store as it was (P0 L97-99). The spec's `on_attestation`
//! stores the state of the target before it checks the attesters, so its store can keep that
//! state after a refused attestation. Here the state goes into the store with the messages,
//! after every check. A later valid attestation of the same target stores the same state.

use crate::handlers::{target_checkpoint_state, StateProvider};
use crate::store::{
    compute_start_slot_at_epoch, get_checkpoint_block, get_current_slot, get_current_store_epoch,
    is_payload_verified, key, LatestMessage, Store,
};
use crate::{AttestationError, Error};
use consensus_types::gloas::{Attestation, AttesterSlashing, BeaconState, IndexedAttestation};
use consensus_types::primitives::{Epoch, ValidatorIndex};
use state_transition::caches::CommitteeCache;
use state_transition::per_block::attestation::get_indexed_attestation_with;
use state_transition::per_block::slashings::is_slashable_attestation_data;
use state_transition::{BackendError, Preset, SignatureBackend, SignatureSet};
use std::collections::BTreeSet;

/// The BLS checks of fork choice. Fork choice links no BLS library, so the caller verifies the
/// sets with its own backend.
///
/// Each signer of `sets` is a validator index of `state`, the state that the spec checks the
/// signature against. Before finality, two branches can give one index different keys, so
/// the keys must come from `state`.
pub trait SignatureVerifier<E: Preset> {
    /// `Ok(true)` if every set is valid and `Ok(false)` if one is not, as
    /// [`SignatureBackend::verify_signature_sets`] says. `Err` is no verdict, never a proof.
    fn verify_signature_sets(
        &self,
        state: &BeaconState<E>,
        sets: &[SignatureSet],
    ) -> Result<bool, BackendError>;
}

/// A [`SignatureVerifier`] with the keys of one state, as the transition helpers call it.
struct Keys<'a, E: Preset, V: ?Sized> {
    verifier: &'a V,
    state: &'a BeaconState<E>,
}

impl<E: Preset, V: SignatureVerifier<E> + ?Sized> SignatureBackend for Keys<'_, E, V> {
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        self.verifier.verify_signature_sets(self.state, sets)
    }
}

/// `is_valid_indexed_attestation` (G L1022-1041) on `state`, with the BLS verdict of
/// `verifier`.
fn is_valid_indexed_attestation<E: Preset, V: SignatureVerifier<E> + ?Sized>(
    verifier: &V,
    state: &BeaconState<E>,
    indexed_attestation: &IndexedAttestation<E>,
) -> Result<bool, Error> {
    let keys = Keys { verifier, state };
    state_transition::per_block::attestation::is_valid_indexed_attestation(
        state,
        indexed_attestation,
        &keys,
    )
    .map_err(Error::IndexedAttestation)
}

/// `on_attestation` (P0 L1013-1031) with the Gloas `validate_on_attestation` and
/// `update_latest_messages`. `is_from_block` is true for an attestation of a block that
/// `on_block` took, and false for one from the wire.
///
/// The provider advances the state of the target to its epoch
/// (`store_target_checkpoint_state`) and verifies the signature on that state.
pub fn on_attestation<E, P>(
    store: &mut Store<E>,
    provider: &P,
    attestation: &Attestation<E>,
    is_from_block: bool,
) -> Result<(), Error>
where
    E: Preset,
    P: StateProvider<E> + SignatureVerifier<E> + ?Sized,
{
    validate_on_attestation(store, attestation, is_from_block)?;
    let target = &attestation.data.target;
    let new_state = target_checkpoint_state(store, provider, target)?;
    let indexed_attestation = {
        let target_state =
            match &new_state {
                Some(state) => state,
                None => store.checkpoint_states.get(&key(target)).ok_or(
                    Error::MissingCheckpointState {
                        epoch: target.epoch,
                        root: target.root,
                    },
                )?,
            };
        // The target epoch is the epoch of the attestation slot (validated above).
        let committees =
            CommitteeCache::new(target_state, target.epoch).map_err(Error::IndexedAttestation)?;
        let indexed = get_indexed_attestation_with(target_state, &committees, attestation)
            .map_err(Error::IndexedAttestation)?;
        if !is_valid_indexed_attestation(provider, target_state, &indexed)? {
            return Err(AttestationError::InvalidIndexedAttestation.into());
        }
        indexed
    };
    if let Some(state) = new_state {
        store.checkpoint_states.insert(key(target), state);
    }
    update_latest_messages(store, &indexed_attestation.attesting_indices, attestation);
    Ok(())
}

/// `validate_target_epoch_against_current_time` (P0 L816-823).
fn validate_target_epoch_against_current_time<E: Preset>(
    store: &Store<E>,
    target_epoch: Epoch,
) -> Result<(), Error> {
    let current = get_current_store_epoch(store);
    let previous = current.saturating_sub(1);
    if target_epoch == current || target_epoch == previous {
        Ok(())
    } else {
        Err(AttestationError::TargetEpochNotCurrent {
            target: target_epoch,
            current,
        }
        .into())
    }
}

/// `validate_on_attestation` (G L914-955), with the asserts in spec order.
///
/// One check is not in the spec: the target epoch must not start before the anchor block
/// ([`AttestationError::TargetBeforeAnchor`]). For such an epoch the spec's
/// `get_checkpoint_block` walks below the anchor ([`crate::get_ancestor`] stops there). After
/// a checkpoint sync, the spec fails on the parent of the anchor, which no store has. After a
/// prune, the spec's walk gives a block older than every block of the store, and that block
/// is not the target, which is a block of the store. Thus the spec refuses the attestation
/// in both cases, at the same assert. An attestation of a block can have such a target: the
/// previous epoch of a block of the finalized epoch.
fn validate_on_attestation<E: Preset>(
    store: &Store<E>,
    attestation: &Attestation<E>,
    is_from_block: bool,
) -> Result<(), Error> {
    let data = &attestation.data;
    let target = &data.target;
    if !is_from_block {
        validate_target_epoch_against_current_time(store, target.epoch)?;
    }
    if target.epoch != E::epoch_at_slot(data.slot) {
        return Err(AttestationError::TargetEpochMismatch {
            target: target.epoch,
            slot: data.slot,
        }
        .into());
    }
    if !store.blocks.contains_key(&target.root) {
        return Err(AttestationError::UnknownTarget(target.root).into());
    }
    let root = data.beacon_block_root;
    let block_slot = store
        .blocks
        .get(&root)
        .ok_or(AttestationError::UnknownBeaconBlock(root))?
        .slot;
    if block_slot > data.slot {
        return Err(AttestationError::FutureBlock {
            block: block_slot,
            slot: data.slot,
        }
        .into());
    }
    if data.index > 1 {
        return Err(AttestationError::IndexOutOfRange(data.index).into());
    }
    if block_slot == data.slot && data.index != 0 {
        return Err(AttestationError::SameSlotFullVote(root).into());
    }
    if data.index == 1 && !is_payload_verified(store, root) {
        return Err(AttestationError::PayloadNotVerified(root).into());
    }
    // The target epoch is the epoch of `data.slot`, so its first slot does not overflow.
    let epoch_first_slot = compute_start_slot_at_epoch::<E>(target.epoch)?;
    let anchor_slot = store.get_block(store.anchor_root)?.slot;
    if epoch_first_slot < anchor_slot {
        return Err(AttestationError::TargetBeforeAnchor {
            epoch: target.epoch,
            anchor_slot,
        }
        .into());
    }
    let checkpoint_block = get_checkpoint_block(store, root, target.epoch)?;
    if target.root != checkpoint_block {
        return Err(AttestationError::TargetNotCheckpointBlock {
            target: target.root,
            checkpoint_block,
        }
        .into());
    }
    // `get_current_slot(store) >= data.slot + 1`. A slot with no next slot never passes.
    let current = get_current_slot(store);
    if data.slot.checked_add(1).is_none_or(|next| current < next) {
        return Err(AttestationError::SlotNotPast {
            slot: data.slot,
            current,
        }
        .into());
    }
    Ok(())
}

/// `update_latest_messages` (G L965-983): by the attestation slot, not the target epoch. A
/// message replaces only a message of an earlier slot, and an equivocating validator gets
/// none.
fn update_latest_messages<E: Preset>(
    store: &mut Store<E>,
    attesting_indices: &[ValidatorIndex],
    attestation: &Attestation<E>,
) {
    let data = &attestation.data;
    let message = LatestMessage {
        slot: data.slot,
        root: data.beacon_block_root,
        payload_present: data.index == 1,
    };
    for index in attesting_indices {
        if store.equivocating_indices.contains(index) {
            continue;
        }
        let is_later = store
            .latest_messages
            .get(index)
            .is_none_or(|latest| message.slot > latest.slot);
        if is_later {
            store.latest_messages.insert(*index, message);
        }
    }
}

/// `on_attester_slashing` (P0 L1040-1057): each validator of both attestations of a valid
/// slashing equivocates. The attestations are checked against the state of the justified
/// block.
pub fn on_attester_slashing<E: Preset, V: SignatureVerifier<E> + ?Sized>(
    store: &mut Store<E>,
    verifier: &V,
    attester_slashing: &AttesterSlashing<E>,
) -> Result<(), Error> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;
    if !is_slashable_attestation_data(&attestation_1.data, &attestation_2.data) {
        return Err(AttestationError::NotSlashable.into());
    }
    let state = store.get_block_state(store.justified_checkpoint.root)?;
    for attestation in [attestation_1, attestation_2] {
        if !is_valid_indexed_attestation(verifier, state, attestation)? {
            return Err(AttestationError::InvalidIndexedAttestation.into());
        }
    }
    let indices_2: BTreeSet<_> = attestation_2.attesting_indices.iter().collect();
    let both: Vec<ValidatorIndex> = attestation_1
        .attesting_indices
        .iter()
        .filter(|index| indices_2.contains(index))
        .copied()
        .collect();
    store.equivocating_indices.extend(both);
    Ok(())
}
