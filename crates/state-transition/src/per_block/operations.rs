//! The Gloas `process_operations` (G L2228-2263, Modified in Gloas).
//!
//! Each operation list goes to its handler in the order of the spec. The handlers that are
//! not ported yet are dispatch slots that return [`StfError::Unimplemented`] with the work
//! that ports them, so a block with an operation of such a kind fails and a block without
//! one passes. The Gloas text calls no builder deposit or exit request handler here (the
//! parent-payload step processes those), so no `4.6a` slot is in this function.
//!
//! The voluntary exits and the BLS-to-execution changes go to [`super::exits`].

use crate::accessors::TotalActiveBalanceCache;
use crate::per_block::exits::{process_bls_to_execution_change, process_voluntary_exit};
use crate::per_block::payload_attestation::process_payload_attestation;
use crate::{Preset, StfError};
use consensus_types::common::ProposerSlashing;
use consensus_types::gloas::{Attestation, AttesterSlashing, BeaconBlockBody, BeaconState};
use consensus_types::primitives::Slot;

/// `process_operations` (G L2228-2263, Modified in Gloas): `parent_slot` is the slot of the
/// latest block header before the block, which `process_attestation` reads.
///
/// The count asserts of L2239-2245 hold by construction: the list types of
/// [`BeaconBlockBody`] bound each count at decode to the same `MAX_*` preset values.
pub fn process_operations<E: Preset>(
    state: &mut BeaconState<E>,
    body: &BeaconBlockBody<E>,
    parent_slot: Slot,
) -> Result<(), StfError> {
    // One total active balance for the exit churn of the block: the operations do not
    // change the effective balances or the active set of the current epoch.
    let mut cache = TotalActiveBalanceCache::default();
    if !body.deposits.is_empty() {
        return Err(StfError::BlockDeposits(body.deposits.len()));
    }
    for operation in &body.proposer_slashings {
        process_proposer_slashing(state, operation)?;
    }
    for operation in &body.attester_slashings {
        process_attester_slashing(state, operation)?;
    }
    for operation in &body.attestations {
        process_attestation(state, operation, parent_slot)?;
    }
    for operation in &body.voluntary_exits {
        process_voluntary_exit(state, operation, &mut cache)?;
    }
    for operation in &body.bls_to_execution_changes {
        process_bls_to_execution_change(state, operation)?;
    }
    for operation in &body.payload_attestations {
        process_payload_attestation(state, operation)?;
    }
    Ok(())
}

/// Dispatch slot of `process_proposer_slashing` (P0 L2422). Not ported yet.
fn process_proposer_slashing<E: Preset>(
    _: &mut BeaconState<E>,
    _: &ProposerSlashing,
) -> Result<(), StfError> {
    Err(StfError::Unimplemented("4.3b"))
}

/// Dispatch slot of `process_attester_slashing` (P0 L2449). Not ported yet.
fn process_attester_slashing<E: Preset>(
    _: &mut BeaconState<E>,
    _: &AttesterSlashing<E>,
) -> Result<(), StfError> {
    Err(StfError::Unimplemented("4.3b"))
}

/// Dispatch slot of the Gloas `process_attestation(state, attestation, parent_slot)`
/// (G L2396-2480). Not ported yet.
fn process_attestation<E: Preset>(
    _: &mut BeaconState<E>,
    _: &Attestation<E>,
    _: Slot,
) -> Result<(), StfError> {
    Err(StfError::Unimplemented("4.3b"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::hash;
    use crate::testing::{genesis_state, signed_block};
    use consensus_types::common::{
        AttestationData, BLSToExecutionChange, BeaconBlockHeader, Checkpoint, Deposit, DepositData,
        SignedBLSToExecutionChange, SignedBeaconBlockHeader, SignedVoluntaryExit, VoluntaryExit,
    };
    use consensus_types::gloas::{IndexedAttestation, PayloadAttestation, PayloadAttestationData};
    use consensus_types::primitives::{Address, Root};
    use consensus_types::{EthSpec, Minimal};
    use ssz::{BitVector, ProgressiveBitList};

    fn header() -> SignedBeaconBlockHeader {
        SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: 0,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body_root: Root::ZERO,
            },
            signature: [0; 96],
        }
    }

    fn data() -> AttestationData {
        let checkpoint = Checkpoint {
            epoch: 0,
            root: Root::ZERO,
        };
        AttestationData {
            slot: 0,
            index: 0,
            beacon_block_root: Root::ZERO,
            source: checkpoint.clone(),
            target: checkpoint,
        }
    }

    fn indexed() -> IndexedAttestation<Minimal> {
        IndexedAttestation {
            attesting_indices: Default::default(),
            data: data(),
            signature: [0; 96],
        }
    }

    #[test]
    fn empty_operations_pass() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        let body = signed_block::<Minimal>(1, 0).message.body;
        assert_eq!(process_operations(&mut state, &body, 0), Ok(()));
    }

    #[test]
    fn deposits_are_refused() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        let mut body = signed_block::<Minimal>(1, 0).message.body;
        let deposit = Deposit {
            proof: Default::default(),
            data: DepositData {
                pubkey: [0; 48],
                withdrawal_credentials: Root::ZERO,
                amount: 0,
                signature: [0; 96],
            },
        };
        body.deposits.push(deposit).unwrap();
        assert_eq!(
            process_operations(&mut state, &body, 0),
            Err(StfError::BlockDeposits(1))
        );
    }

    /// Adds one operation to a block body.
    type AddOperation = dyn Fn(&mut BeaconBlockBody<Minimal>);

    #[test]
    fn each_operation_goes_to_its_dispatch_slot() {
        let state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        let empty = signed_block::<Minimal>(1, 0).message.body;
        let with = |f: &AddOperation| {
            let mut body = empty.clone();
            f(&mut body);
            process_operations(&mut state.clone(), &body, 0)
        };
        let cases: [(&str, &AddOperation); 3] = [
            ("4.3b", &|b| {
                b.proposer_slashings
                    .push(ProposerSlashing {
                        signed_header_1: header(),
                        signed_header_2: header(),
                    })
                    .unwrap()
            }),
            ("4.3b", &|b| {
                b.attester_slashings
                    .push(AttesterSlashing {
                        attestation_1: indexed(),
                        attestation_2: indexed(),
                    })
                    .unwrap()
            }),
            ("4.3b", &|b| {
                b.attestations
                    .push(Attestation {
                        aggregation_bits: ProgressiveBitList::with_capacity(1),
                        data: data(),
                        signature: [0; 96],
                        committee_bits: BitVector::new(),
                    })
                    .unwrap()
            }),
        ];
        for (id, add) in cases {
            assert_eq!(with(add), Err(StfError::Unimplemented(id)), "{id}");
        }
        // A payload attestation goes to `process_payload_attestation`, which refuses one
        // for the slot of the state.
        assert_eq!(
            with(&|b| {
                b.payload_attestations
                    .push(PayloadAttestation {
                        aggregation_bits: BitVector::new(),
                        data: PayloadAttestationData {
                            beacon_block_root: Root::ZERO,
                            slot: 0,
                            payload_present: false,
                            blob_data_available: false,
                        },
                        signature: [0; 96],
                    })
                    .unwrap()
            }),
            Err(StfError::PayloadAttestationSlotMismatch {
                attestation: 0,
                state: 0
            })
        );
    }

    #[test]
    fn exits_and_bls_changes_are_processed() {
        // 64 validators in epoch 64 of the minimal preset (SHARD_COMMITTEE_PERIOD), and
        // validator 5 with the BLS withdrawal credentials of the key `[0x77; 48]`.
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        state.slot = Minimal::start_slot_at_epoch(64);
        let credentials = &mut state.validators.get_mut(5).unwrap().withdrawal_credentials;
        *credentials = Root::from(hash(&[&[0x77; 48]]));
        credentials[0] = 0x00;
        let mut body = signed_block::<Minimal>(state.slot, 0).message.body;
        for validator_index in [3, 4] {
            body.voluntary_exits
                .push(SignedVoluntaryExit {
                    message: VoluntaryExit {
                        epoch: 64,
                        validator_index,
                    },
                    signature: [0; 96],
                })
                .unwrap();
        }
        let change = SignedBLSToExecutionChange {
            message: BLSToExecutionChange {
                validator_index: 5,
                from_bls_pubkey: [0x77; 48],
                to_execution_address: Address::repeat_byte(0xee),
            },
            signature: [0; 96],
        };
        body.bls_to_execution_changes.push(change.clone()).unwrap();

        let mut post = state.clone();
        assert_eq!(process_operations(&mut post, &body, 0), Ok(()));
        for index in [3, 4] {
            assert_ne!(post.validators.get(index).unwrap().exit_epoch, u64::MAX);
        }
        assert_eq!(post.validators.get(2).unwrap().exit_epoch, u64::MAX);
        let credentials = post.validators.get(5).unwrap().withdrawal_credentials;
        assert_eq!(
            (credentials[0], &credentials[12..]),
            (0x01, &[0xee; 20][..])
        );

        // The same change twice: the second one finds 0x01 credentials.
        body.bls_to_execution_changes.push(change).unwrap();
        assert_eq!(
            process_operations(&mut state.clone(), &body, 0),
            Err(StfError::NotBlsWithdrawalCredentials(5))
        );
        // An exit of a validator outside the registry.
        let mut body = signed_block::<Minimal>(state.slot, 0).message.body;
        body.voluntary_exits
            .push(SignedVoluntaryExit {
                message: VoluntaryExit {
                    epoch: 0,
                    validator_index: 64,
                },
                signature: [0; 96],
            })
            .unwrap();
        assert_eq!(
            process_operations(&mut state, &body, 0),
            Err(StfError::UnknownValidator(64))
        );
    }
}
