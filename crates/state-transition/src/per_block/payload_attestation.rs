//! `process_payload_attestation` (G L2488-2499, New in Gloas) and the indexed form of a
//! payload attestation (G L1094-1110, L1410-1427).
//!
//! The BLS check of the aggregate signature is not in [`process_payload_attestation`]. The
//! caller gives [`crate::signatures::payload_attestation_signature_set`] to the backend, in
//! the one batch of [`crate::signatures::block_signature_sets`], or calls
//! [`crate::signatures::verify_payload_attestation_signature`]. The checks that need no BLS
//! (the parent root, the slot and the structure of the indexed form) run in every mode.
//!
//! Fork choice uses [`get_indexed_payload_attestation`] and
//! [`is_valid_indexed_payload_attestation`] again for the payload attestations of a block and
//! of gossip.

use crate::caches::get_ptc;
use crate::signatures::indexed_payload_attestation_signature_set;
use crate::{Preset, SignatureBackend, StfError};
use consensus_types::gloas::{
    BeaconState, IndexedPayloadAttestation, PayloadAttestation, PayloadAttestationData,
};
use consensus_types::primitives::{Root, Slot};
use ssz_types::VariableList;

/// `process_payload_attestation` (G L2488-2499, New in Gloas) without the BLS check: the
/// asserts on the parent block root and the previous slot, then the structural checks of
/// `is_valid_indexed_payload_attestation` on the indexed form. The state does not change.
pub fn process_payload_attestation<E: Preset>(
    state: &BeaconState<E>,
    payload_attestation: &PayloadAttestation<E>,
) -> Result<(), StfError> {
    check_payload_attestation_target(
        &payload_attestation.data,
        state.latest_block_header.parent_root,
        state.slot,
    )?;
    let indexed = get_indexed_payload_attestation(state, payload_attestation)?;
    check_indexed_payload_attestation(state, &indexed)
}

/// The two asserts of `process_payload_attestation` (G L2494-2496), in the order of the
/// spec: `data.beacon_block_root == parent_root` and `data.slot + 1 == state_slot`.
///
/// `parent_root` is `state.latest_block_header.parent_root` after the header step, which is
/// `block.parent_root` (P0 L2350-2370).
pub(crate) fn check_payload_attestation_target(
    data: &PayloadAttestationData,
    parent_root: Root,
    state_slot: Slot,
) -> Result<(), StfError> {
    if data.beacon_block_root != parent_root {
        return Err(StfError::PayloadAttestationRootMismatch {
            attestation: data.beacon_block_root,
            expected: parent_root,
        });
    }
    // A `Uint64` overflow of `data.slot + 1` fails the assert too.
    if data.slot.checked_add(1) != Some(state_slot) {
        return Err(StfError::PayloadAttestationSlotMismatch {
            attestation: data.slot,
            state: state_slot,
        });
    }
    Ok(())
}

/// `get_indexed_payload_attestation` (G L1410-1427, New in Gloas): the PTC members of
/// `get_ptc(state, data.slot)` at the set positions of `aggregation_bits`, sorted. A member
/// at two positions stays two times.
pub fn get_indexed_payload_attestation<E: Preset>(
    state: &BeaconState<E>,
    payload_attestation: &PayloadAttestation<E>,
) -> Result<IndexedPayloadAttestation<E>, StfError> {
    let ptc = get_ptc(state, payload_attestation.data.slot)?;
    let mut attesting_indices: Vec<_> = ptc
        .iter()
        .zip(payload_attestation.aggregation_bits.iter())
        .filter(|(_, bit)| *bit)
        .map(|(&index, _)| index)
        .collect();
    attesting_indices.sort_unstable();
    // At most `PTC_SIZE` members, the limit of the list.
    let attesting_indices = VariableList::new(attesting_indices)
        .map_err(|e| StfError::Tree(format!("PTC indices length: {e:?}")))?;
    Ok(IndexedPayloadAttestation {
        attesting_indices,
        data: payload_attestation.data.clone(),
        signature: payload_attestation.signature,
    })
}

/// The checks of `is_valid_indexed_payload_attestation` (G L1094-1110) that need no BLS:
/// the indices are not empty, they are sorted (a duplicate is allowed), and each one is in
/// the registry (`state.validators[index]`).
///
/// The indices come from the PTC window of the state ([`get_indexed_payload_attestation`]),
/// not from the attestation. Thus an index past the registry is a fault of our own state:
/// [`StfError::ListIndexOutOfRange`], not a proof that the attestation is invalid.
pub fn check_indexed_payload_attestation<E: Preset>(
    state: &BeaconState<E>,
    indexed: &IndexedPayloadAttestation<E>,
) -> Result<(), StfError> {
    let indices = &indexed.attesting_indices;
    if indices.is_empty() {
        return Err(StfError::PayloadAttestationNoAttesters);
    }
    if indices.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(StfError::PayloadAttestationUnsorted);
    }
    let registry = state.validators.len() as u64;
    match indices.iter().find(|&&index| index >= registry) {
        Some(&index) => Err(StfError::ListIndexOutOfRange {
            list: "validators",
            index,
        }),
        None => Ok(()),
    }
}

/// `is_valid_indexed_payload_attestation` (G L1094-1110, New in Gloas): the structural
/// checks ([`check_indexed_payload_attestation`]), then the aggregate signature through
/// `backend`.
///
/// A structural failure is an error without a backend call. A rejected signature is
/// [`StfError::InvalidPayloadAttestationSignature`], and a backend without a verdict is
/// [`StfError::SignatureBackend`].
pub fn is_valid_indexed_payload_attestation<E: Preset>(
    state: &BeaconState<E>,
    indexed: &IndexedPayloadAttestation<E>,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let set = indexed_payload_attestation_signature_set(state, indexed)?;
    if backend.verify_signature_sets(std::slice::from_ref(&set))? {
        Ok(())
    } else {
        Err(StfError::InvalidPayloadAttestationSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::get_domain;
    use crate::caches::get_ptc;
    use crate::per_slot::process_slots;
    use crate::signatures::{
        block_signature_sets, indexed_payload_attestation_signature_set,
        payload_attestation_signature_set, randao_signature_set,
        verify_payload_attestation_signature,
    };
    use crate::testing::{block_at_state_slot, genesis_state, no_bls, ScriptedBackend};
    use crate::{BackendError, SignatureSet, SignerRef};
    use consensus_types::gloas::PayloadAttestationData;
    use consensus_types::signing::{compute_signing_root, DOMAIN_PTC_ATTESTER};
    use consensus_types::{EthSpec, Minimal};
    use ssz_types::VariableList;

    /// The root of the parent block in [`state_at_slot_9`].
    const PARENT: Root = Root::repeat_byte(0x7e);

    /// 64 validators at slot 9 (epoch 1), with `PARENT` as the parent root of the latest
    /// block header, as after the header step of a block at slot 9. Slot 8 is the first slot
    /// of the epoch, so its PTC is in the current-epoch third of the window.
    fn state_at_slot_9() -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        process_slots(&mut state, 7, &no_bls()).unwrap();
        // Skip the epoch transition (not ported yet): slots 8 and 9 by hand.
        state.slot = 9;
        state.latest_block_header.parent_root = PARENT;
        state
    }

    /// A payload attestation for `slot` and `root` with the PTC positions `bits` set and the
    /// signature `[0x33; 96]`.
    fn attestation(slot: Slot, root: Root, bits: &[usize]) -> PayloadAttestation<Minimal> {
        let mut attestation = PayloadAttestation {
            aggregation_bits: Default::default(),
            data: PayloadAttestationData {
                beacon_block_root: root,
                slot,
                payload_present: true,
                blob_data_available: false,
            },
            signature: [0x33; 96],
        };
        for &bit in bits {
            attestation.aggregation_bits.set(bit, true).unwrap();
        }
        attestation
    }

    fn indexed(indices: &[u64]) -> IndexedPayloadAttestation<Minimal> {
        IndexedPayloadAttestation {
            attesting_indices: VariableList::new(indices.to_vec()).unwrap(),
            data: attestation(8, PARENT, &[]).data,
            signature: [0x33; 96],
        }
    }

    #[test]
    fn ptc_slot_and_root() {
        let state = state_at_slot_9();
        // The previous slot and the parent root: valid.
        let valid = attestation(8, PARENT, &[0]);
        assert_eq!(process_payload_attestation(&state, &valid), Ok(()));
        assert!(payload_attestation_signature_set(&state, &valid, PARENT).is_ok());

        // Another slot than `state.slot - 1`: the slot of the block, an older slot and a
        // slot whose successor overflows.
        for slot in [9, 7, 0, u64::MAX] {
            let wrong = attestation(slot, PARENT, &[0]);
            let want = StfError::PayloadAttestationSlotMismatch {
                attestation: slot,
                state: 9,
            };
            assert_eq!(
                process_payload_attestation(&state, &wrong),
                Err(want.clone()),
                "{slot}"
            );
            // The set builder of the block makes the same check, before the PTC read.
            assert_eq!(
                payload_attestation_signature_set(&state, &wrong, PARENT),
                Err(want.clone())
            );
            assert!(want.proves_invalid());
        }

        // Another root than the parent block root: the root check comes first.
        let other = Root::repeat_byte(0x01);
        for slot in [8, 9] {
            let wrong = attestation(slot, other, &[0]);
            let want = StfError::PayloadAttestationRootMismatch {
                attestation: other,
                expected: PARENT,
            };
            assert_eq!(
                process_payload_attestation(&state, &wrong),
                Err(want.clone())
            );
            assert_eq!(
                payload_attestation_signature_set(&state, &wrong, PARENT),
                Err(want.clone())
            );
            assert!(want.proves_invalid());
        }
        // The block path compares with the parent root of the block, before its header step.
        assert_eq!(
            payload_attestation_signature_set(&state, &valid, other),
            Err(StfError::PayloadAttestationRootMismatch {
                attestation: PARENT,
                expected: other,
            })
        );
    }

    #[test]
    fn ptc_bits_mapping() {
        let state = state_at_slot_9();
        let ptc = get_ptc(&state, 8).unwrap();
        // Three positions, set out of order of their validator indices.
        let bits = [1, 5, 9];
        let payload_attestation = attestation(8, PARENT, &bits);
        let got = get_indexed_payload_attestation(&state, &payload_attestation).unwrap();
        let mut want: Vec<u64> = bits.iter().map(|&b| ptc[b]).collect();
        want.sort_unstable();
        assert_eq!(got.attesting_indices.to_vec(), want);
        assert_eq!(got.data, payload_attestation.data);
        assert_eq!(got.signature, payload_attestation.signature);

        // The set lists the pubkeys of those members by registry index, over the data with
        // the PTC domain of the slot's epoch.
        let domain = get_domain(&state, DOMAIN_PTC_ATTESTER, Some(1));
        let want_set = SignatureSet::aggregate(
            want.iter().map(|&i| SignerRef::Validator(i)).collect(),
            compute_signing_root(&payload_attestation.data, domain),
            [0x33; 96],
        )
        .unwrap();
        assert_eq!(
            payload_attestation_signature_set(&state, &payload_attestation, PARENT),
            Ok(want_set.clone())
        );

        // A member at two positions signs two times.
        let mut twice = state.clone();
        let mut committee = ptc.clone();
        committee[3] = 17;
        committee[4] = 17;
        let window_index = Minimal::slots_per_epoch() as usize; // slot 8: epoch 1, offset 0.
        *twice.ptc_window.get_mut(window_index).unwrap() = committee;
        let both = attestation(8, PARENT, &[4, 3]);
        let got = get_indexed_payload_attestation(&twice, &both).unwrap();
        assert_eq!(got.attesting_indices.to_vec(), vec![17, 17]);

        // In a block, the set comes after the RANDAO set, one set for each attestation.
        let mut block = block_at_state_slot(&state);
        block.message.parent_root = PARENT;
        block
            .message
            .body
            .payload_attestations
            .push(payload_attestation.clone())
            .unwrap();
        let sets = block_signature_sets(&state, &block, &no_bls()).unwrap();
        assert_eq!(sets.len(), 3);
        assert_eq!(
            sets[1],
            randao_signature_set(&state, &block.message.body).unwrap()
        );
        assert_eq!(sets[2], want_set);

        // The verdict of the backend for one attestation.
        let accepting = ScriptedBackend::new([Ok(true)]);
        assert_eq!(
            verify_payload_attestation_signature(&state, &payload_attestation, &accepting),
            Ok(())
        );
        assert_eq!(accepting.seen(), vec![want_set]);
        let rejecting = ScriptedBackend::new([Ok(false)]);
        let rejected =
            verify_payload_attestation_signature(&state, &payload_attestation, &rejecting);
        assert_eq!(rejected, Err(StfError::InvalidPayloadAttestationSignature));
        assert!(rejected.unwrap_err().proves_invalid());
        let unavailable = ScriptedBackend::new([Err(BackendError("timeout".into()))]);
        let got = verify_payload_attestation_signature(&state, &payload_attestation, &unavailable);
        assert_eq!(
            got,
            Err(StfError::SignatureBackend(BackendError("timeout".into())))
        );
        assert!(!got.unwrap_err().proves_invalid());
    }

    #[test]
    fn ptc_domain_of_the_attested_epoch() {
        // The fork boundary at epoch 1, with two versions, as in the vector
        // `process_payload_attestation_cross_epoch_wrong_domain`. The attestation is for the
        // last slot of epoch 0.
        let mut state = state_at_slot_9();
        state.slot = 8;
        state.fork.epoch = 1;
        state.fork.previous_version = [0, 0, 0, 1];
        state.fork.current_version = [0, 0, 0, 2];
        let mut indexed = indexed(&[3]);
        indexed.data.slot = 7;
        let set = indexed_payload_attestation_signature_set(&state, &indexed).unwrap();
        let attested = get_domain(&state, DOMAIN_PTC_ATTESTER, Some(0));
        let current = get_domain(&state, DOMAIN_PTC_ATTESTER, Some(1));
        assert_ne!(attested, current);
        assert_eq!(
            set.signing_root(),
            compute_signing_root(&indexed.data, attested)
        );
        // `get_ptc` reads the Gloas fork epoch from `state.fork.epoch`, so it has no PTC for
        // a slot before it.
        assert_eq!(
            get_indexed_payload_attestation(&state, &attestation(7, PARENT, &[3])),
            Err(StfError::EpochOutOfWindow {
                epoch: 0,
                state_epoch: 1
            })
        );
    }

    #[test]
    fn ptc_structural() {
        let state = state_at_slot_9();
        // No set bit: no attester, no set and no backend call.
        let empty = attestation(8, PARENT, &[]);
        let none = ScriptedBackend::new([]);
        assert_eq!(
            process_payload_attestation(&state, &empty),
            Err(StfError::PayloadAttestationNoAttesters)
        );
        assert_eq!(
            payload_attestation_signature_set(&state, &empty, PARENT),
            Err(StfError::PayloadAttestationNoAttesters)
        );
        assert_eq!(
            verify_payload_attestation_signature(&state, &empty, &none),
            Err(StfError::PayloadAttestationNoAttesters)
        );
        let mut block = block_at_state_slot(&state);
        block.message.parent_root = PARENT;
        block.message.body.payload_attestations.push(empty).unwrap();
        assert_eq!(
            block_signature_sets(&state, &block, &no_bls()),
            Err(StfError::PayloadAttestationNoAttesters)
        );

        // The indexed form: empty, not sorted, or a member past the registry. The last one
        // comes from the PTC window of our state, so it proves nothing about the attestation.
        for (indices, want, proves) in [
            (&[][..], StfError::PayloadAttestationNoAttesters, true),
            (&[5, 3][..], StfError::PayloadAttestationUnsorted, true),
            (
                &[3, 64][..],
                StfError::ListIndexOutOfRange {
                    list: "validators",
                    index: 64,
                },
                false,
            ),
        ] {
            let indexed = indexed(indices);
            assert_eq!(
                check_indexed_payload_attestation(&state, &indexed),
                Err(want.clone()),
                "{indices:?}"
            );
            assert_eq!(
                indexed_payload_attestation_signature_set(&state, &indexed),
                Err(want.clone())
            );
            assert_eq!(
                is_valid_indexed_payload_attestation(&state, &indexed, &none),
                Err(want.clone())
            );
            assert_eq!(want.proves_invalid(), proves, "{want}");
        }
        assert!(none.seen().is_empty());

        // A PTC window with a member past the registry gives the same error in the step.
        let mut broken = state.clone();
        let window_index = Minimal::slots_per_epoch() as usize; // slot 8: epoch 1, offset 0.
        broken.ptc_window.get_mut(window_index).unwrap()[0] = 64;
        assert_eq!(
            process_payload_attestation(&broken, &attestation(8, PARENT, &[0])),
            Err(StfError::ListIndexOutOfRange {
                list: "validators",
                index: 64,
            })
        );

        // Sorted with a duplicate is valid, and the backend decides.
        let duplicate = indexed(&[3, 3, 7]);
        assert_eq!(
            check_indexed_payload_attestation(&state, &duplicate),
            Ok(())
        );
        let rejecting = ScriptedBackend::new([Ok(false)]);
        assert_eq!(
            is_valid_indexed_payload_attestation(&state, &duplicate, &rejecting),
            Err(StfError::InvalidPayloadAttestationSignature)
        );
        assert_eq!(rejecting.seen()[0].signers().len(), 3);
        let accepting = ScriptedBackend::new([Ok(true)]);
        assert_eq!(
            is_valid_indexed_payload_attestation(&state, &duplicate, &accepting),
            Ok(())
        );
    }
}
