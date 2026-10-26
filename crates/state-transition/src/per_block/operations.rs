//! The Gloas `process_operations` (G L2228-2263, Modified in Gloas).
//!
//! Each operation list goes to its handler in the order of the spec. The Gloas text calls
//! no request handler here: the parent payload step
//! ([`super::parent_payload`]) processes the execution requests, the builder deposits and
//! the builder exits.
//!
//! The slashings go to [`super::slashings`], the attestations to [`super::attestation`], and
//! the voluntary exits and the BLS-to-execution changes to [`super::exits`].

use crate::per_block::attestation::process_attestation_with;
use crate::per_block::exits::{process_bls_to_execution_change, process_voluntary_exit};
use crate::per_block::payload_attestation::process_payload_attestation;
use crate::per_block::slashings::{process_attester_slashing_with, process_proposer_slashing_with};
use crate::per_block::BlockContext;
use crate::{Preset, StfError};
use consensus_types::gloas::{BeaconBlockBody, BeaconState};
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
    let mut ctx = BlockContext {
        parent_slot,
        ..BlockContext::default()
    };
    process_operations_with(state, body, &mut ctx)
}

/// [`process_operations`] with the [`BlockContext`] of the block: its `parent_slot`, the
/// committee caches that the attestation sets of the same block can compute first, and one
/// total active balance for the slashings and the exit churn of the block. The operations
/// do not change the effective balances or the active set of the current epoch.
pub fn process_operations_with<E: Preset>(
    state: &mut BeaconState<E>,
    body: &BeaconBlockBody<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    if !body.deposits.is_empty() {
        return Err(StfError::BlockDeposits(body.deposits.len()));
    }
    for operation in &body.proposer_slashings {
        process_proposer_slashing_with(state, operation, ctx)?;
    }
    for operation in &body.attester_slashings {
        process_attester_slashing_with(state, operation, ctx)?;
    }
    for operation in &body.attestations {
        process_attestation_with(state, operation, ctx.parent_slot(), ctx)?;
    }
    for operation in &body.voluntary_exits {
        process_voluntary_exit(state, operation, ctx.total_active_balance())?;
    }
    for operation in &body.bls_to_execution_changes {
        process_bls_to_execution_change(state, operation)?;
    }
    for operation in &body.payload_attestations {
        process_payload_attestation(state, operation)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::hash;
    use crate::testing::{genesis_state, signed_block};
    use consensus_types::common::ProposerSlashing;
    use consensus_types::common::{
        AttestationData, BLSToExecutionChange, BeaconBlockHeader, Checkpoint, Deposit, DepositData,
        SignedBLSToExecutionChange, SignedBeaconBlockHeader, SignedVoluntaryExit, VoluntaryExit,
    };
    use consensus_types::gloas::{
        Attestation, AttesterSlashing, IndexedAttestation, PayloadAttestation,
        PayloadAttestationData,
    };
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
    fn each_operation_goes_to_its_handler() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        state.slot = 1;
        let empty = signed_block::<Minimal>(1, 0).message.body;
        let with = |f: &AddOperation| {
            let mut body = empty.clone();
            f(&mut body);
            process_operations(&mut state.clone(), &body, 0)
        };
        let cases: [(StfError, &AddOperation); 3] = [
            (StfError::ProposerSlashingSameHeaders, &|b| {
                b.proposer_slashings
                    .push(ProposerSlashing {
                        signed_header_1: header(),
                        signed_header_2: header(),
                    })
                    .unwrap()
            }),
            (StfError::NotSlashableAttestationData, &|b| {
                b.attester_slashings
                    .push(AttesterSlashing {
                        attestation_1: indexed(),
                        attestation_2: indexed(),
                    })
                    .unwrap()
            }),
            (StfError::AttestationDataIndex(2), &|b| {
                let mut data = data();
                data.index = 2;
                b.attestations
                    .push(Attestation {
                        aggregation_bits: ProgressiveBitList::with_capacity(1),
                        data,
                        signature: [0; 96],
                        committee_bits: BitVector::new(),
                    })
                    .unwrap()
            }),
        ];
        for (want, add) in cases {
            assert_eq!(with(add), Err(want.clone()), "{want}");
        }
        // A payload attestation goes to `process_payload_attestation`, which refuses one
        // that is not for the slot before the state slot.
        assert_eq!(
            with(&|b| {
                b.payload_attestations
                    .push(PayloadAttestation {
                        aggregation_bits: BitVector::new(),
                        data: PayloadAttestationData {
                            beacon_block_root: Root::ZERO,
                            slot: 5,
                            payload_present: false,
                            blob_data_available: false,
                        },
                        signature: [0; 96],
                    })
                    .unwrap()
            }),
            Err(StfError::PayloadAttestationSlotMismatch {
                attestation: 5,
                state: 1
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
