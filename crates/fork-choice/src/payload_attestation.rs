//! The handler `on_payload_attestation_message` (G L1139-1187), and the votes of the payload
//! attestations of a block (`notify_ptc_messages`, G L268-288), which go through the same
//! checks with `is_from_block = True`.
//!
//! The spec reads `store.block_states`, which keeps every block. Here the checks also read the
//! post-state of a block that a prune dropped and the store still keeps
//! ([`Store::block_state_or_dropped`]). The store keeps no votes of a dropped block, and a
//! dropped block supports no node of head selection, so a valid message for it writes no
//! vote. After the store forgets a dropped block, a message for it fails as unknown.
//!
//! A failed call leaves the store as it was: the handler writes the votes only after each check
//! passed.

use crate::attestations::{Keys, SignatureVerifier};
use crate::store::{get_current_slot, Store};
use crate::{Error, PayloadAttestationError};
use consensus_types::gloas::{
    BeaconState, IndexedPayloadAttestation, PayloadAttestation, PayloadAttestationData,
    PayloadAttestationMessage,
};
use consensus_types::primitives::{Root, ValidatorIndex};
use ssz_types::VariableList;
use state_transition::caches::get_ptc;
use state_transition::per_block::payload_attestation::{
    get_indexed_payload_attestation, is_valid_indexed_payload_attestation,
};
use state_transition::{Preset, StfError};

/// `on_payload_attestation_message` (G L1139-1187). `is_from_block` is true for a message of a
/// payload attestation of a block that `on_block` took, and false for one from the wire.
///
/// The checks run in spec order: the attested block must be known; a message of another slot
/// than its block returns early with no vote and no error; the validator must be in the PTC of
/// `data.slot` on the post-state of the attested block. A message from the wire must then be of
/// the current slot and pass `is_valid_indexed_payload_attestation` on that post-state, with the
/// BLS verdict of `verifier`. Then the message sets the votes of each PTC position of the
/// validator, and replaces an earlier vote at those positions.
///
/// A rejected signature is [`PayloadAttestationError::InvalidSignature`]. A verifier with no
/// verdict is [`Error::NoSignatureVerdict`], which is not a proof.
pub fn on_payload_attestation_message<E, V>(
    store: &mut Store<E>,
    verifier: &V,
    ptc_message: &PayloadAttestationMessage,
    is_from_block: bool,
) -> Result<(), Error>
where
    E: Preset,
    V: SignatureVerifier<E> + ?Sized,
{
    let data = &ptc_message.data;
    let Some(AttestedPtc { state, ptc }) = attested_ptc(store, data)? else {
        return Ok(());
    };
    let votes = member_votes(&ptc, ptc_message.validator_index, data)?;
    if !is_from_block {
        let current = get_current_slot(store);
        if data.slot != current {
            return Err(PayloadAttestationError::NotCurrentSlot {
                slot: data.slot,
                current,
            }
            .into());
        }
        let indexed = IndexedPayloadAttestation::<E> {
            // `PTC_SIZE` is at least 1, so the one index fits.
            attesting_indices: VariableList::new(vec![ptc_message.validator_index])
                .map_err(|e| Error::Stf(StfError::Tree(format!("PTC indices length: {e:?}"))))?,
            data: data.clone(),
            signature: ptc_message.signature,
        };
        let keys = Keys { verifier, state };
        match is_valid_indexed_payload_attestation(state, &indexed, &keys) {
            Ok(()) => {}
            Err(StfError::InvalidPayloadAttestationSignature) => {
                return Err(PayloadAttestationError::InvalidSignature.into())
            }
            Err(StfError::SignatureBackend(e)) => return Err(Error::NoSignatureVerdict(e)),
            // The validator is in the PTC of the state, so it is in its registry.
            Err(e) => return Err(Error::Stf(e)),
        }
    }
    for vote in votes {
        vote.apply(store);
    }
    Ok(())
}

/// One PTC vote of a payload attestation message.
pub(crate) struct PtcVote {
    root: Root,
    position: usize,
    payload_present: bool,
    blob_data_available: bool,
}

impl PtcVote {
    /// Sets `store.payload_timeliness_vote[root][position]` and
    /// `store.payload_data_availability_vote[root][position]`. The store has no votes of a
    /// dropped block, so a vote for one changes nothing.
    pub(crate) fn apply<E: Preset>(&self, store: &mut Store<E>) {
        let set = |votes: Option<&mut Vec<Option<bool>>>, value| {
            if let Some(vote) = votes.and_then(|v| v.get_mut(self.position)) {
                *vote = Some(value);
            }
        };
        set(
            store.payload_timeliness_vote.get_mut(&self.root),
            self.payload_present,
        );
        set(
            store.payload_data_availability_vote.get_mut(&self.root),
            self.blob_data_available,
        );
    }
}

/// The post-state of an attested block, and its PTC of the slot of the message.
struct AttestedPtc<'s, E: Preset> {
    state: &'s BeaconState<E>,
    ptc: Vec<ValidatorIndex>,
}

/// The first checks of `on_payload_attestation_message` (G L1148-1158): the post-state of the
/// attested block and its PTC of `data.slot`, or `None` if `data.slot` is not the slot of that
/// state (the spec returns early).
fn attested_ptc<'s, E: Preset>(
    store: &'s Store<E>,
    data: &PayloadAttestationData,
) -> Result<Option<AttestedPtc<'s, E>>, Error> {
    let root = data.beacon_block_root;
    let state = store
        .block_state_or_dropped(root)
        .ok_or(PayloadAttestationError::UnknownBeaconBlock(root))?;
    if data.slot != state.slot {
        return Ok(None);
    }
    let ptc = get_ptc(state, data.slot).map_err(Error::Stf)?;
    Ok(Some(AttestedPtc {
        state,
        ptc: ptc.to_vec(),
    }))
}

/// The PTC check of `on_payload_attestation_message` (G L1156-1164) and the votes that it
/// writes (G L1182-1187): one vote for each position of `validator_index` in `ptc`.
fn member_votes(
    ptc: &[ValidatorIndex],
    validator_index: ValidatorIndex,
    data: &PayloadAttestationData,
) -> Result<Vec<PtcVote>, Error> {
    let votes: Vec<PtcVote> = ptc
        .iter()
        .enumerate()
        .filter(|(_, member)| **member == validator_index)
        .map(|(position, _)| PtcVote {
            root: data.beacon_block_root,
            position,
            payload_present: data.payload_present,
            blob_data_available: data.blob_data_available,
        })
        .collect();
    if votes.is_empty() {
        return Err(PayloadAttestationError::NotInPtc {
            validator: validator_index,
            slot: data.slot,
        }
        .into());
    }
    Ok(votes)
}

/// The votes of `notify_ptc_messages` (G L268-288): each attester of each payload attestation
/// through the checks of `on_payload_attestation_message(..., is_from_block=True)`, which
/// checks no signature. `state` is the post-state of the block. The votes are in spec order, so
/// a later vote of a position replaces an earlier one. `on_block` computes them before it
/// changes the store.
pub(crate) fn ptc_votes<E: Preset>(
    store: &Store<E>,
    state: &BeaconState<E>,
    payload_attestations: &[PayloadAttestation<E>],
) -> Result<Vec<PtcVote>, Error> {
    let mut votes = Vec::new();
    if state.slot == 0 {
        return Ok(votes);
    }
    for payload_attestation in payload_attestations {
        let indexed =
            get_indexed_payload_attestation(state, payload_attestation).map_err(Error::Stf)?;
        let data = &indexed.data;
        let Some(AttestedPtc { ptc, .. }) = attested_ptc(store, data)? else {
            continue;
        };
        for validator_index in indexed.attesting_indices.iter() {
            votes.extend(member_votes(&ptc, *validator_index, data)?);
        }
    }
    Ok(votes)
}
