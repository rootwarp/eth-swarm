//! The signature seam of the pure state transition.
//!
//! The transition only builds [`SignatureSet`]s; a [`SignatureBackend`] that the caller
//! supplies checks them. cl-chain uses cl-verify, and the spec-vector runner can use an
//! in-process BLS backend. A set names its signers by [`SignerRef`], never by key material,
//! for registry members.
//!
//! [`block_signature_sets`] gives every set of a block for one backend call. The block
//! processing steps check no signature themselves.

pub use consensus_types::signing::{SignatureSet, SignerRef};

use crate::accessors::{get_block_root_at_slot, get_current_epoch, get_domain};
use crate::per_block::state_proposer_index;
use crate::per_block::BlockContext;
use crate::preset::BUILDER_INDEX_SELF_BUILD;
use crate::{Preset, StfError};
use consensus_types::common::SyncAggregate;
use consensus_types::gloas::{BeaconBlockBody, BeaconState, SignedBeaconBlock};
use consensus_types::primitives::BLSSignature;
use consensus_types::signing::{
    compute_signing_root, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
};

/// `G2_POINT_AT_INFINITY` (`altair/bls.md` L25): the compressed G2 identity.
pub const G2_POINT_AT_INFINITY: BLSSignature = {
    let mut bytes = [0u8; 96];
    bytes[0] = 0xc0;
    bytes
};

/// The backend gave no verdict (a timeout, an overload, an unknown signer). This is never a
/// proof that a signature is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("signature backend gave no verdict: {0}")]
pub struct BackendError(pub String);

/// Checks signature sets for the state transition. Calls are synchronous.
pub trait SignatureBackend {
    /// `Ok(true)` if every set in `sets` is valid, `Ok(false)` if at least one is not.
    ///
    /// A key or a signature that does not decode, or a key that fails `KeyValidate`, makes
    /// its set invalid: `Ok(false)`, never `Err`. The spec needs this for the inline keys of
    /// deposits ([`SignerRef::Inline`]): `bls.Verify` returns `False` for such a key, and the
    /// deposit is ignored. `Err` is only for a backend that is not available or that fails
    /// (for example a timeout, an overload or a verdict that was not fetched).
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError>;
}

/// The proposer signature set of a block: `verify_block_signature` (P0 L1839-1844) without
/// the BLS call.
pub fn block_proposer_signature_set<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
) -> Result<SignatureSet, StfError> {
    let block = &signed_block.message;
    if block.proposer_index >= state.validators.len() as u64 {
        return Err(StfError::UnknownValidator(block.proposer_index));
    }
    let domain = get_domain(state, DOMAIN_BEACON_PROPOSER, None);
    Ok(SignatureSet::single(
        SignerRef::Validator(block.proposer_index),
        compute_signing_root(block, domain),
        signed_block.signature,
    ))
}

/// `verify_block_signature` (P0 L1839-1844) through `backend`.
pub fn verify_block_signature<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let set = block_proposer_signature_set(state, signed_block)?;
    if backend.verify_signature_sets(std::slice::from_ref(&set))? {
        Ok(())
    } else {
        Err(StfError::InvalidBlockSignature)
    }
}

/// The RANDAO reveal set of a block: the `bls.Verify` of `process_randao` (P0 L2376-2381),
/// by the proposer of the state's slot over the current epoch.
pub fn randao_signature_set<E: Preset>(
    state: &BeaconState<E>,
    body: &BeaconBlockBody<E>,
) -> Result<SignatureSet, StfError> {
    let epoch = get_current_epoch(state);
    let proposer = state_proposer_index(state)?;
    let signing_root = compute_signing_root(&epoch, get_domain(state, DOMAIN_RANDAO, None));
    Ok(SignatureSet::single(
        SignerRef::Validator(proposer),
        signing_root,
        body.randao_reveal,
    ))
}

/// The sync aggregate set of a block: the `eth_fast_aggregate_verify` of
/// `process_sync_aggregate` (A L637-664), over the block root of the previous slot.
///
/// The signers are the participants by validator index (duplicates stay, as each position
/// signs). The spec sums the same keys through `aggregate_pubkey` when more than half
/// participate; the sum is the same, because `aggregate_pubkey` is the sum of `pubkeys`.
///
/// With no participant there is no set (`Ok(None)`) if the signature is
/// [`G2_POINT_AT_INFINITY`], and [`StfError::InvalidSyncAggregateSignature`] if it is not.
pub fn sync_aggregate_signature_set<E: Preset>(
    state: &BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
) -> Result<Option<SignatureSet>, StfError> {
    sync_aggregate_signature_set_with(state, sync_aggregate, &mut BlockContext::default())
}

/// [`sync_aggregate_signature_set`] with the committee indices of `ctx`, which the rewards
/// of the same block read again. An empty aggregate needs no indices.
pub fn sync_aggregate_signature_set_with<E: Preset>(
    state: &BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
    ctx: &mut BlockContext,
) -> Result<Option<SignatureSet>, StfError> {
    let previous_slot = state.slot.saturating_sub(1);
    let domain = get_domain(
        state,
        DOMAIN_SYNC_COMMITTEE,
        Some(E::epoch_at_slot(previous_slot)),
    );
    let signing_root = compute_signing_root(&get_block_root_at_slot(state, previous_slot)?, domain);
    let signature = sync_aggregate.sync_committee_signature;
    let bits = &sync_aggregate.sync_committee_bits;
    if bits.is_zero() {
        return if signature == G2_POINT_AT_INFINITY {
            Ok(None)
        } else {
            Err(StfError::InvalidSyncAggregateSignature)
        };
    }
    let signers = ctx
        .sync_committee_indices(state)?
        .iter()
        .zip(bits.iter())
        .filter(|(_, bit)| *bit)
        .map(|(&index, _)| SignerRef::Validator(index))
        .collect();
    // At least one bit is set, so the signers are not empty.
    SignatureSet::aggregate(signers, signing_root, signature)
        .map(Some)
        .map_err(|_| StfError::InvalidSyncAggregateSignature)
}

/// The sync aggregate check of `process_sync_aggregate` through `backend`, for a caller that
/// processes a sync aggregate outside [`block_signature_sets`].
pub fn verify_sync_aggregate_signature<E: Preset>(
    state: &BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    verify_sync_aggregate_signature_with(
        state,
        sync_aggregate,
        backend,
        &mut BlockContext::default(),
    )
}

/// [`verify_sync_aggregate_signature`] with the committee indices of `ctx`, which
/// [`crate::per_block::sync_aggregate::process_sync_aggregate_with`] reads again.
pub fn verify_sync_aggregate_signature_with<E: Preset>(
    state: &BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
    backend: &dyn SignatureBackend,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    match sync_aggregate_signature_set_with(state, sync_aggregate, ctx)? {
        None => Ok(()),
        Some(set) if backend.verify_signature_sets(std::slice::from_ref(&set))? => Ok(()),
        Some(_) => Err(StfError::InvalidSyncAggregateSignature),
    }
}

/// Every signature set of a block, in the order of `process_block`: the proposer
/// signature, the RANDAO reveal and the sync aggregate (none for an empty aggregate with the
/// infinity signature).
///
/// The function fails closed for the signed parts of the body that have no set builder
/// yet: a builder bid (not a self-build), and each operation list that is not empty
/// (proposer slashings, attester slashings, attestations, voluntary exits, BLS-to-execution
/// changes, payload attestations) give [`StfError::Unimplemented`] with the work that ports
/// them. A port must add its set builder here and remove its `Unimplemented`, so that no
/// signature of the block is left out of the batch.
///
/// `state` is the state at the block's slot, after `process_slots` and before
/// `process_block`. The steps before each check do not change what the set reads (the
/// registry keys, the proposer lookahead, the fork and the block roots), so the sets are
/// the ones that the spec checks during `process_block`.
pub fn block_signature_sets<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
) -> Result<Vec<SignatureSet>, StfError> {
    block_signature_sets_with(state, signed_block, &mut BlockContext::default())
}

/// [`block_signature_sets`] with a [`BlockContext`] that
/// [`crate::per_block::process_block_with`] can use again for the same block.
pub fn block_signature_sets_with<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    ctx: &mut BlockContext,
) -> Result<Vec<SignatureSet>, StfError> {
    let body = &signed_block.message.body;
    let mut sets = vec![
        block_proposer_signature_set(state, signed_block)?,
        randao_signature_set(state, body)?,
    ];
    if body.signed_execution_payload_bid.message.builder_index != BUILDER_INDEX_SELF_BUILD {
        // `verify_execution_payload_bid_signature` (G L2149-2156).
        return Err(StfError::Unimplemented("4.5"));
    }
    let unported = [
        (body.proposer_slashings.is_empty(), "4.3b"),
        (body.attester_slashings.is_empty(), "4.3b"),
        (body.attestations.is_empty(), "4.3b"),
        (body.voluntary_exits.is_empty(), "4.4b"),
        (body.bls_to_execution_changes.is_empty(), "4.4b"),
        (body.payload_attestations.is_empty(), "4.11"),
    ];
    if let Some((_, id)) = unported.iter().find(|(empty, _)| !empty) {
        return Err(StfError::Unimplemented(id));
    }
    // Last, as it is the only set that can read the registry.
    sets.extend(sync_aggregate_signature_set_with(
        state,
        &body.sync_aggregate,
        ctx,
    )?);
    Ok(sets)
}

/// Checks [`block_signature_sets`] through `backend` in one call.
pub fn verify_block_signatures<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    verify_block_signatures_with(state, signed_block, backend, &mut BlockContext::default())
}

/// [`verify_block_signatures`] with a [`BlockContext`] for the same block.
pub fn verify_block_signatures_with<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    backend: &dyn SignatureBackend,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    let sets = block_signature_sets_with(state, signed_block, ctx)?;
    if backend.verify_signature_sets(&sets)? {
        Ok(())
    } else {
        Err(StfError::InvalidBlockSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per_slot::process_slots;
    use crate::testing::{block_at_state_slot, genesis_state};
    use consensus_types::primitives::Root;
    use consensus_types::Minimal;
    use std::cell::Cell;

    /// A backend with a fixed verdict that counts its calls.
    struct Counting {
        verdict: bool,
        calls: Cell<usize>,
    }

    impl SignatureBackend for Counting {
        fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.verdict)
        }
    }

    /// 64 validators at slot 9 (epoch 1), with a sync committee of validators `0..32` and a
    /// block of the slot that has `participants` set and the signature `[0x22; 96]`.
    fn state_and_block(
        participants: &[usize],
    ) -> (BeaconState<Minimal>, SignedBeaconBlock<Minimal>) {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        process_slots(&mut state, 7).unwrap();
        // Skip the epoch transition (not ported yet): slots 8 and 9 by hand.
        state.slot = 9;
        *state.block_roots.get_mut(8).unwrap() = Root::repeat_byte(8);
        for i in 0..32 {
            state.current_sync_committee.pubkeys[i] = state.validators.get(i).unwrap().pubkey;
        }
        let mut block = block_at_state_slot(&state);
        block.message.body.randao_reveal = [0x44; 96];
        let aggregate = &mut block.message.body.sync_aggregate;
        for &i in participants {
            aggregate.sync_committee_bits.set(i, true).unwrap();
        }
        aggregate.sync_committee_signature = [0x22; 96];
        (state, block)
    }

    #[test]
    fn block_sets() {
        // A full block: the proposer, RANDAO and sync aggregate sets, in that order.
        let (state, block) = state_and_block(&[1, 4, 4 + 16]);
        let sets = block_signature_sets(&state, &block).unwrap();
        let proposer = block.message.proposer_index;
        let randao_domain = get_domain(&state, DOMAIN_RANDAO, None);
        let sync_domain = get_domain(&state, DOMAIN_SYNC_COMMITTEE, Some(1));
        let want = vec![
            SignatureSet::single(
                SignerRef::Validator(proposer),
                compute_signing_root(
                    &block.message,
                    get_domain(&state, DOMAIN_BEACON_PROPOSER, None),
                ),
                [0x11; 96],
            ),
            SignatureSet::single(
                SignerRef::Validator(proposer),
                compute_signing_root(&1u64, randao_domain),
                [0x44; 96],
            ),
            SignatureSet::aggregate(
                vec![
                    SignerRef::Validator(1),
                    SignerRef::Validator(4),
                    SignerRef::Validator(20),
                ],
                compute_signing_root(&Root::repeat_byte(8), sync_domain),
                [0x22; 96],
            )
            .unwrap(),
        ];
        assert_eq!(sets, want);
        // One backend call for the whole block.
        let rejecting = Counting {
            verdict: false,
            calls: Cell::new(0),
        };
        assert_eq!(
            verify_block_signatures(&state, &block, &rejecting),
            Err(StfError::InvalidBlockSignature)
        );
        assert_eq!(rejecting.calls.get(), 1);
        let accepting = Counting {
            verdict: true,
            calls: Cell::new(0),
        };
        assert_eq!(verify_block_signatures(&state, &block, &accepting), Ok(()));

        // An empty sync aggregate: no sync set with the infinity signature, and an error
        // (with no backend call) without it.
        let (state, mut block) = state_and_block(&[]);
        assert_eq!(
            block_signature_sets(&state, &block),
            Err(StfError::InvalidSyncAggregateSignature)
        );
        let none = Counting {
            verdict: true,
            calls: Cell::new(0),
        };
        assert_eq!(
            verify_sync_aggregate_signature(&state, &block.message.body.sync_aggregate, &none),
            Err(StfError::InvalidSyncAggregateSignature)
        );
        assert_eq!(none.calls.get(), 0);
        block.message.body.sync_aggregate.sync_committee_signature = G2_POINT_AT_INFINITY;
        let sets = block_signature_sets(&state, &block).unwrap();
        let mut want = want;
        want[0] = block_proposer_signature_set(&state, &block).unwrap();
        assert_eq!(sets[..], want[..2]);
        assert_eq!(
            verify_sync_aggregate_signature(&state, &block.message.body.sync_aggregate, &none),
            Ok(())
        );
        assert_eq!(none.calls.get(), 0);
    }

    #[test]
    fn randao_signing_root_known_answer() {
        // Fork version 0x07000001, genesis validators root 0x42 * 32, epoch 1 (slot 9).
        let (state, block) = state_and_block(&[]);
        assert_eq!(state.fork.current_version, [0x07, 0, 0, 0x01]);
        assert_eq!(state.genesis_validators_root, Root::repeat_byte(0x42));
        let set = randao_signature_set(&state, &block.message.body).unwrap();

        // The spec formula, step by step with sha256:
        // fork_data_root = sha256(version + 28 zero bytes + genesis_validators_root)
        // domain = DOMAIN_RANDAO + fork_data_root[:28]
        // signing_root = sha256(uint64(epoch) as 32 bytes + domain)
        let mut fork_data = [0u8; 64];
        fork_data[..4].copy_from_slice(&[0x07, 0, 0, 0x01]);
        fork_data[32..].copy_from_slice(&[0x42; 32]);
        let fork_data_root = ethereum_hashing::hash_fixed(&fork_data);
        let mut signing_data = [0u8; 64];
        signing_data[0] = 1;
        signing_data[32..36].copy_from_slice(&DOMAIN_RANDAO);
        signing_data[36..].copy_from_slice(&fork_data_root[..28]);
        let want = ethereum_hashing::hash_fixed(&signing_data);
        assert_eq!(set.signing_root().as_slice(), &want);
        // The same 32 bytes from Python's hashlib.
        assert_eq!(
            format!("{:x}", set.signing_root()),
            "7debcaa30c867dcacb24ce02e86ae835ea813c12712d3072ec3917ac88de5284"
        );
        assert_eq!(
            set.signers(),
            &[SignerRef::Validator(block.message.proposer_index)]
        );
        assert_eq!(set.signature(), &[0x44; 96]);
    }

    #[test]
    fn operations_without_a_set_builder_fail_closed() {
        use consensus_types::common::{
            BLSToExecutionChange, BeaconBlockHeader, SignedBLSToExecutionChange,
            SignedBeaconBlockHeader, SignedVoluntaryExit, VoluntaryExit,
        };
        use consensus_types::gloas::{BeaconBlockBody, PayloadAttestation, PayloadAttestationData};
        use consensus_types::primitives::Address;

        let (state, block) = state_and_block(&[1]);
        let header = SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: 0,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body_root: Root::ZERO,
            },
            signature: [0; 96],
        };
        /// Adds one signed part to a block body.
        type AddPart = Box<dyn Fn(&mut BeaconBlockBody<Minimal>)>;
        let cases: [(&str, AddPart); 5] = [
            (
                "4.3b",
                Box::new(move |b| {
                    b.proposer_slashings
                        .push(consensus_types::common::ProposerSlashing {
                            signed_header_1: header.clone(),
                            signed_header_2: header.clone(),
                        })
                        .unwrap()
                }),
            ),
            (
                "4.4b",
                Box::new(|b| {
                    b.voluntary_exits
                        .push(SignedVoluntaryExit {
                            message: VoluntaryExit {
                                epoch: 0,
                                validator_index: 0,
                            },
                            signature: [0; 96],
                        })
                        .unwrap()
                }),
            ),
            (
                "4.4b",
                Box::new(|b| {
                    b.bls_to_execution_changes
                        .push(SignedBLSToExecutionChange {
                            message: BLSToExecutionChange {
                                validator_index: 0,
                                from_bls_pubkey: [0; 48],
                                to_execution_address: Address::ZERO,
                            },
                            signature: [0; 96],
                        })
                        .unwrap()
                }),
            ),
            (
                "4.11",
                Box::new(|b| {
                    b.payload_attestations
                        .push(PayloadAttestation {
                            aggregation_bits: Default::default(),
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
            ),
            (
                // A bid of a builder, not a self-build.
                "4.5",
                Box::new(|b| b.signed_execution_payload_bid.message.builder_index = 0),
            ),
        ];
        for (id, add) in cases {
            let mut with = block.clone();
            add(&mut with.message.body);
            assert_eq!(
                block_signature_sets(&state, &with),
                Err(StfError::Unimplemented(id)),
                "{id}"
            );
        }
        // A self-build bid with another signature than the infinity needs no BLS check, but
        // the bid step rejects it; the sets do not fail for it.
        let mut self_build = block.clone();
        self_build
            .message
            .body
            .signed_execution_payload_bid
            .signature = [0x55; 96];
        assert_eq!(
            block_signature_sets(&state, &self_build).map(|s| s.len()),
            Ok(3)
        );
    }

    #[test]
    fn one_index_computation_per_block() {
        use crate::per_block::sync_aggregate::process_sync_aggregate_with;
        use crate::per_block::BlockContext;

        // The set and the rewards share one computation of the committee indices.
        let (mut state, block) = state_and_block(&[1, 4]);
        let mut ctx = BlockContext::default();
        let sets = block_signature_sets_with(&state, &block, &mut ctx).unwrap();
        assert_eq!(sets.len(), 3);
        assert_eq!(ctx.sync_index_scans(), 1);
        let aggregate = &block.message.body.sync_aggregate;
        assert_eq!(
            process_sync_aggregate_with(&mut state, aggregate, &mut ctx),
            Ok(())
        );
        assert_eq!(ctx.sync_index_scans(), 1);

        // An empty aggregate needs no indices for its set, so only the rewards compute them.
        let (mut state, mut block) = state_and_block(&[]);
        block.message.body.sync_aggregate.sync_committee_signature = G2_POINT_AT_INFINITY;
        let mut ctx = BlockContext::default();
        assert_eq!(
            block_signature_sets_with(&state, &block, &mut ctx).map(|s| s.len()),
            Ok(2)
        );
        assert_eq!(ctx.sync_index_scans(), 0);
        let aggregate = &block.message.body.sync_aggregate;
        process_sync_aggregate_with(&mut state, aggregate, &mut ctx).unwrap();
        assert_eq!(ctx.sync_index_scans(), 1);
    }

    #[test]
    fn sync_set_errors() {
        let (mut state, block) = state_and_block(&[0]);
        let aggregate = &block.message.body.sync_aggregate;
        let rejecting = Counting {
            verdict: false,
            calls: Cell::new(0),
        };
        assert_eq!(
            verify_sync_aggregate_signature(&state, aggregate, &rejecting),
            Err(StfError::InvalidSyncAggregateSignature)
        );
        assert_eq!(rejecting.calls.get(), 1);
        // A committee key outside the registry.
        state.current_sync_committee.pubkeys[2] = [0xee; 48];
        assert_eq!(
            sync_aggregate_signature_set(&state, aggregate),
            Err(StfError::UnknownSyncCommitteeMember { position: 2 })
        );
        // The previous slot must be in the block-root history.
        let mut genesis = state.clone();
        genesis.slot = 0;
        assert_eq!(
            sync_aggregate_signature_set(&genesis, aggregate),
            Err(StfError::BlockRootOutOfRange {
                slot: 0,
                state_slot: 0
            })
        );
        // A proposer outside the registry has no RANDAO key.
        *state.proposer_lookahead.get_mut(9 % 8).unwrap() = 64;
        assert_eq!(
            randao_signature_set(&state, &block.message.body),
            Err(StfError::ListIndexOutOfRange {
                list: "validators",
                index: 64
            })
        );
    }
}
