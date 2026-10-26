//! `process_execution_payload_bid` (G L2162-2215, New in Gloas): the bid of the block and
//! the pending payment of its builder.
//!
//! The step makes no BLS check. The signature of a builder bid goes to the backend as a
//! set, in the one batch of [`crate::signatures::block_signature_sets`], before the steps
//! run. The set is by `state.builders[bid.builder_index].pubkey`
//! (`verify_execution_payload_bid_signature`, G L2149-2156), named by
//! `SignerRef::Builder { index, version }` with the
//! [`crate::accessors::builder_key_version`] of the state. A self-build bid has no set: it
//! must have the value 0 and the `G2_POINT_AT_INFINITY` signature (G L2170-2172).
//!
//! The blob limit is `get_blob_parameters(epoch).max_blobs_per_block` (Fu L293-300): a
//! value of the network config (`BLOB_SCHEDULE`, with BPO forks), never a preset
//! constant. The caller gives it through a [`BlobSchedule`].
//!
//! # The checks before the signature set
//!
//! The batch is built on the state before `process_block`, but the step runs after the
//! parent payload, the header and the withdrawals steps. Before the set of a builder bid is
//! built, `check_builder_bid_before_block` runs the asserts that need no BLS and that
//! those steps cannot change, so a bid that fails them costs no key lookup and no backend
//! call:
//!
//! - The builder is active and has `PAYLOAD_BUILDER_VERSION`. A builder that is active
//!   after the earlier steps was active before them with the same key: the parent payload
//!   can only exit a builder, and a builder that it adds at an index is not active, because
//!   its deposit epoch is not before the finalized epoch.
//! - The blob commitments, the slot, the block hash, the block root of the previous slot
//!   and the RANDAO mix of the current epoch. No earlier step changes the block roots or
//!   the RANDAO mixes (`process_randao` runs after the bid).
//!
//! Two asserts run in the step only. `can_builder_cover_bid` can become true in the parent
//! payload (a builder deposit request tops up the balance). `state.latest_block_hash` is set
//! by the parent payload (G L1830).

use crate::accessors::{
    can_builder_cover_bid, get_block_root_at_slot, get_current_epoch, get_randao_mix,
    is_active_builder,
};
use crate::caches::get_beacon_proposer_index;
use crate::preset::{BUILDER_INDEX_SELF_BUILD, GENESIS_SLOT, PAYLOAD_BUILDER_VERSION};
use crate::signatures::G2_POINT_AT_INFINITY;
use crate::{Preset, StfError};
use consensus_types::gloas::{
    BeaconState, BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid,
    SignedExecutionPayloadBid,
};
use consensus_types::primitives::{BuilderIndex, Epoch};

/// The blob schedule of the network: `get_blob_parameters(epoch).max_blobs_per_block`
/// (Fu L293-300), from `BLOB_SCHEDULE` and the Electra fallback of the network config.
///
/// cl-chain gives `network_config::ChainConfig::get_blob_parameters` as a closure:
/// `&|epoch| config.get_blob_parameters(epoch).max_blobs_per_block`.
pub trait BlobSchedule {
    /// The maximum number of blobs in a block of `epoch`.
    fn max_blobs_per_block(&self, epoch: Epoch) -> u64;
}

impl<F: Fn(Epoch) -> u64> BlobSchedule for F {
    fn max_blobs_per_block(&self, epoch: Epoch) -> u64 {
        self(epoch)
    }
}

/// `process_execution_payload_bid` (G L2162-2215, New in Gloas), without the BLS call of
/// `verify_execution_payload_bid_signature`.
///
/// `max_blobs_per_block` is `get_blob_parameters(get_current_epoch(state))
/// .max_blobs_per_block` of the network ([`BlobSchedule`]). The caller checks the signature
/// of a builder bid before the call: the batch of the block, or
/// [`crate::signatures::verify_execution_payload_bid_signature`] for a bid alone.
///
/// A bid with a value records a pending payment of the builder in the second half of
/// `state.builder_pending_payments`, at the slot of the bid. The bid becomes
/// `state.latest_execution_payload_bid`. On `Err`, `state` is not changed.
pub fn process_execution_payload_bid<E: Preset>(
    state: &mut BeaconState<E>,
    signed_bid: &SignedExecutionPayloadBid<E>,
    max_blobs_per_block: u64,
) -> Result<(), StfError> {
    let bid = &signed_bid.message;
    let builder_index = bid.builder_index;
    let amount = bid.value;

    if builder_index == BUILDER_INDEX_SELF_BUILD {
        check_self_build(signed_bid)?;
    } else {
        check_bid_builder(state, builder_index)?;
        // Verify that the builder has funds to cover the bid
        if !can_builder_cover_bid(state, builder_index, amount)? {
            return Err(StfError::BidNotCovered {
                index: builder_index,
                amount,
            });
        }
        // The signature: the caller checked the set before the call (see above).
    }
    check_bid_target(state, bid, max_blobs_per_block)?;
    // Verify that the bid is for the right parent block
    if bid.parent_block_hash != state.latest_block_hash {
        return Err(StfError::BidParentBlockHash {
            bid: bid.parent_block_hash,
            expected: state.latest_block_hash,
        });
    }
    check_bid_parent(state, bid)?;

    // Record the pending payment if there is some payment
    if amount > 0 {
        let pending_payment = BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: bid.fee_recipient,
                amount,
                builder_index,
            },
            proposer_index: get_beacon_proposer_index(state)?,
        };
        let slots_per_epoch = E::slots_per_epoch();
        let index = slots_per_epoch + bid.slot % slots_per_epoch;
        // `builder_pending_payments` has `2 * SLOTS_PER_EPOCH` entries, so the index is in
        // range. A shorter vector is a fault of our own state.
        *state
            .builder_pending_payments
            .get_mut(index as usize)
            .ok_or(StfError::ListIndexOutOfRange {
                list: "builder_pending_payments",
                index,
            })? = pending_payment;
    }

    // Cache the signed execution payload bid
    state.latest_execution_payload_bid = bid.clone();
    Ok(())
}

/// The asserts of `process_execution_payload_bid` on a builder bid that need no BLS and
/// that the steps of `process_block` before the bid cannot change (see the module
/// documentation), on the state before the block: an active builder with
/// `PAYLOAD_BUILDER_VERSION`, and the asserts on the blob commitments, the slot, the block
/// hash, the parent block root and the RANDAO mix. The signature set of the bid is built
/// only after they pass.
pub(crate) fn check_builder_bid_before_block<E: Preset>(
    state: &BeaconState<E>,
    bid: &ExecutionPayloadBid<E>,
    max_blobs_per_block: u64,
) -> Result<(), StfError> {
    check_bid_builder(state, bid.builder_index)?;
    check_bid_target(state, bid, max_blobs_per_block)?;
    check_bid_parent(state, bid)
}

/// G L2170-2172: a self-build bid has the value 0 and the `G2_POINT_AT_INFINITY` signature,
/// whatever the withdrawal credential prefix of the proposer.
fn check_self_build<E: Preset>(signed_bid: &SignedExecutionPayloadBid<E>) -> Result<(), StfError> {
    let amount = signed_bid.message.value;
    if amount != 0 {
        return Err(StfError::SelfBuildBidValue(amount));
    }
    if signed_bid.signature != G2_POINT_AT_INFINITY {
        return Err(StfError::SelfBuildBidSignature);
    }
    Ok(())
}

/// G L2174-2177: the builder is active and is a payload builder. A builder index past the
/// registry is [`StfError::UnknownBuilder`].
fn check_bid_builder<E: Preset>(
    state: &BeaconState<E>,
    builder_index: BuilderIndex,
) -> Result<(), StfError> {
    // Verify that the builder is active
    if !is_active_builder(state, builder_index)? {
        return Err(StfError::BidBuilderNotActive(builder_index));
    }
    // Verify that the builder is a payload builder
    let version = state
        .builders
        .get(builder_index as usize)
        .ok_or(StfError::UnknownBuilder(builder_index))?
        .version;
    if version != PAYLOAD_BUILDER_VERSION {
        return Err(StfError::BidBuilderVersion {
            index: builder_index,
            version,
        });
    }
    Ok(())
}

/// G L2183-2191: the blob commitments are under the limit of the epoch, and the bid is for
/// the slot of the state, which is after genesis.
fn check_bid_target<E: Preset>(
    state: &BeaconState<E>,
    bid: &ExecutionPayloadBid<E>,
    max_blobs_per_block: u64,
) -> Result<(), StfError> {
    // Verify commitments are under limit
    let count = bid.blob_kzg_commitments.len();
    if count as u64 > max_blobs_per_block {
        return Err(StfError::BidBlobCommitments {
            count,
            max: max_blobs_per_block,
        });
    }
    // Verify that the bid is for the current slot
    if bid.slot != state.slot {
        return Err(StfError::BidSlotMismatch {
            bid: bid.slot,
            state: state.slot,
        });
    }
    // `state.slot > GENESIS_SLOT`: a `Slot` is not less than `GENESIS_SLOT` (0).
    if state.slot == GENESIS_SLOT {
        return Err(StfError::BidAtGenesisSlot);
    }
    Ok(())
}

/// G L2194-2197: the block hash differs from the parent block hash, and the parent block
/// root and `prev_randao` are the ones of the state. Call it only for `state.slot` after
/// genesis ([`check_bid_target`]).
fn check_bid_parent<E: Preset>(
    state: &BeaconState<E>,
    bid: &ExecutionPayloadBid<E>,
) -> Result<(), StfError> {
    // Verify that the bid's block hash differs from its parent block hash
    if bid.block_hash == bid.parent_block_hash {
        return Err(StfError::BidBlockHashIsParent);
    }
    let expected = get_block_root_at_slot(state, state.slot - 1)?;
    if bid.parent_block_root != expected {
        return Err(StfError::BidParentBlockRoot {
            bid: bid.parent_block_root,
            expected,
        });
    }
    let expected = get_randao_mix(state, get_current_epoch(state));
    if bid.prev_randao != expected {
        return Err(StfError::BidPrevRandao {
            bid: bid.prev_randao,
            expected,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::{builder_key_version, get_domain};
    use crate::per_block::{block_steps, BlockContext, BlockStep};
    use crate::signatures::{
        block_bid_signature_set, block_signature_sets, execution_payload_bid_signature_set,
        verify_block_signatures, verify_execution_payload_bid_signature,
    };
    use crate::testing::{
        bid_for_state, block_at_state_slot, bls_context, builder, genesis_state,
        index_reuse_states, no_bls, ScriptedBackend, MINIMAL_MAX_BLOBS_PER_BLOCK,
    };
    use crate::{state_root, BackendError, SignatureSet, SignerRef};
    use consensus_types::primitives::{Gwei, Root, FAR_FUTURE_EPOCH};
    use consensus_types::signing::{compute_signing_root, DOMAIN_BEACON_BUILDER};
    use consensus_types::Minimal;

    const ETH: Gwei = 1_000_000_000;
    const LIMIT: u64 = MINIMAL_MAX_BLOBS_PER_BLOCK;

    /// 64 validators at slot 9 (epoch 1), finalized at epoch 1, with the latest block hash
    /// `[0x11; 32]`, the block root `[0x08; 32]` at slot 8, and the builders `[0xa1; 48]`
    /// (index 0) and `[0xa2; 48]` (index 1) with 5 ETH each, deposited in epoch 0.
    fn bid_state() -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        state.slot = 9;
        state.finalized_checkpoint.epoch = 1;
        state.latest_block_hash = Root::repeat_byte(0x11);
        *state.block_roots.get_mut(8).unwrap() = Root::repeat_byte(0x08);
        for key in [0xa1, 0xa2] {
            state.builders.push(builder(key, 5 * ETH, 0)).unwrap();
        }
        state
    }

    /// The bid step on a copy of `state`: its result, and the copy.
    fn step(
        state: &BeaconState<Minimal>,
        signed_bid: &SignedExecutionPayloadBid<Minimal>,
    ) -> (Result<(), StfError>, BeaconState<Minimal>) {
        let mut post = state.clone();
        let result = process_execution_payload_bid(&mut post, signed_bid, LIMIT);
        (result, post)
    }

    /// The bid step refuses `signed_bid` with `want` and leaves the state unchanged. The
    /// set builder of the block gives the same error for a builder bid, before any key
    /// lookup, so the scripted backend without a verdict gets no call.
    fn refused(
        state: &BeaconState<Minimal>,
        signed_bid: &SignedExecutionPayloadBid<Minimal>,
        want: StfError,
    ) {
        let (result, mut post) = step(state, signed_bid);
        assert_eq!(result, Err(want.clone()));
        assert!(want.proves_invalid(), "{want}");
        assert_eq!(state_root(&mut post), state_root(&mut state.clone()));
        if signed_bid.message.builder_index != BUILDER_INDEX_SELF_BUILD {
            let backend = ScriptedBackend::new([]);
            assert_eq!(
                verify_execution_payload_bid_signature(state, signed_bid, LIMIT, &backend),
                Err(want)
            );
            assert!(backend.seen().is_empty());
        }
    }

    #[test]
    fn self_build() {
        let state = bid_state();
        let valid = bid_for_state(&state, BUILDER_INDEX_SELF_BUILD, 0);
        // A valid self-build bid has no set, so it makes no backend call: the scripted
        // backend has no verdict, and a call panics.
        let backend = ScriptedBackend::new([]);
        assert_eq!(block_bid_signature_set(&state, &valid, LIMIT), Ok(None));
        assert_eq!(
            verify_execution_payload_bid_signature(&state, &valid, LIMIT, &backend),
            Ok(())
        );
        let (result, post) = step(&state, &valid);
        assert_eq!(result, Ok(()));
        assert!(backend.seen().is_empty());
        // The bid is cached, and a bid of 0 records no payment.
        assert_eq!(post.latest_execution_payload_bid, valid.message);
        assert_eq!(
            post.builder_pending_payments,
            state.builder_pending_payments
        );

        // In a block, the batch has no set of a builder.
        let mut block = block_at_state_slot(&state);
        block.message.body.signed_execution_payload_bid = valid.clone();
        let sets = block_signature_sets(&state, &block, &no_bls()).unwrap();
        assert!(sets
            .iter()
            .flat_map(|set| set.signers())
            .all(|signer| matches!(signer, SignerRef::Validator(_))));

        // A value of 1 Gwei, and a signature that is not the infinity point, are refused.
        let mut paid = valid.clone();
        paid.message.value = 1;
        refused(&state, &paid, StfError::SelfBuildBidValue(1));
        for signature in [[0; 96], [0x33; 96]] {
            let mut signed = valid.clone();
            signed.signature = signature;
            refused(&state, &signed, StfError::SelfBuildBidSignature);
        }
        // The self-build rules come first, before the other asserts.
        let mut both = paid.clone();
        both.message.slot = 10;
        refused(&state, &both, StfError::SelfBuildBidValue(1));
    }

    #[test]
    fn builder_cover() {
        let state = bid_state();
        // Builder 1 has 5 ETH: less MIN_DEPOSIT_AMOUNT (1 ETH), it covers 4 ETH.
        let covered = bid_for_state(&state, 1, 4 * ETH);
        let (result, post) = step(&state, &covered);
        assert_eq!(result, Ok(()));
        assert_eq!(post.latest_execution_payload_bid, covered.message);
        // The payment goes to SLOTS_PER_EPOCH + 9 % SLOTS_PER_EPOCH, with weight 0 and the
        // proposer of the slot.
        let want = BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: covered.message.fee_recipient,
                amount: 4 * ETH,
                builder_index: 1,
            },
            proposer_index: get_beacon_proposer_index(&state).unwrap(),
        };
        assert_eq!(post.builder_pending_payments.get(9), Some(&want));
        // The balance of the builder does not change.
        assert_eq!(post.builders, state.builders);

        // One Gwei more is refused by the step. The set builder does not check the funds: a
        // top-up in the parent payload can cover the bid.
        let over = bid_for_state(&state, 1, 4 * ETH + 1);
        let (result, _) = step(&state, &over);
        assert_eq!(
            result,
            Err(StfError::BidNotCovered {
                index: 1,
                amount: 4 * ETH + 1
            })
        );
        assert!(block_bid_signature_set(&state, &over, LIMIT)
            .unwrap()
            .is_some());
        // The pending payment of the covered bid counts against the next bid.
        let next = bid_for_state(&post, 1, 1);
        let (result, _) = step(&post, &next);
        assert_eq!(
            result,
            Err(StfError::BidNotCovered {
                index: 1,
                amount: 1
            })
        );

        // An inactive builder: the deposit is not finalized, or the builder exits.
        let mut recent = state.clone();
        recent.builders.get_mut(1).unwrap().deposit_epoch = 1;
        let bid = bid_for_state(&recent, 1, ETH);
        refused(&recent, &bid, StfError::BidBuilderNotActive(1));
        let mut exiting = state.clone();
        exiting.builders.get_mut(1).unwrap().withdrawable_epoch = 3;
        refused(&exiting, &bid, StfError::BidBuilderNotActive(1));
        assert_ne!(
            exiting.builders.get(1).unwrap().withdrawable_epoch,
            FAR_FUTURE_EPOCH
        );
        // A builder that is not a payload builder.
        let mut other = state.clone();
        other.builders.get_mut(1).unwrap().version = 1;
        refused(
            &other,
            &bid,
            StfError::BidBuilderVersion {
                index: 1,
                version: 1,
            },
        );
        // A builder past the registry.
        refused(
            &state,
            &bid_for_state(&state, 2, 0),
            StfError::UnknownBuilder(2),
        );
    }

    #[test]
    fn bid_set() {
        let state = bid_state();
        let signed_bid = bid_for_state(&state, 1, ETH);
        let version = builder_key_version(&state, 1).unwrap();
        let want = SignatureSet::single(
            SignerRef::Builder { index: 1, version },
            compute_signing_root(
                &signed_bid.message,
                get_domain(&state, DOMAIN_BEACON_BUILDER, None),
            ),
            [0x33; 96],
        );
        assert_eq!(
            execution_payload_bid_signature_set(&state, &signed_bid),
            Ok(want.clone())
        );
        assert_eq!(
            block_bid_signature_set(&state, &signed_bid, LIMIT),
            Ok(Some(want.clone()))
        );

        // In a block: exactly one set has a builder signer, the bid set, and it has no
        // validator signer. It comes after the proposer and RANDAO sets.
        let mut block = block_at_state_slot(&state);
        block.message.body.signed_execution_payload_bid = signed_bid.clone();
        let sets = block_signature_sets(&state, &block, &no_bls()).unwrap();
        let builder_sets: Vec<&SignatureSet> = sets
            .iter()
            .filter(|set| {
                set.signers()
                    .iter()
                    .any(|signer| matches!(signer, SignerRef::Builder { .. }))
            })
            .collect();
        assert_eq!(builder_sets, vec![&want]);
        assert_eq!(want.signers(), &[SignerRef::Builder { index: 1, version }]);
        assert_eq!(sets[2], want);

        // The backend verdicts: a refused set proves the bid invalid, and no verdict does not.
        let backend =
            ScriptedBackend::new([Ok(true), Ok(false), Err(BackendError("timeout".into()))]);
        let verify =
            || verify_execution_payload_bid_signature(&state, &signed_bid, LIMIT, &backend);
        assert_eq!(verify(), Ok(()));
        assert_eq!(verify(), Err(StfError::InvalidOperationSignature));
        let err = verify().unwrap_err();
        assert_eq!(
            err,
            StfError::SignatureBackend(BackendError("timeout".into()))
        );
        assert!(!err.proves_invalid());
        assert_eq!(backend.seen(), vec![want.clone(); 3]);
        // In the batch of the block, a refused set makes the block signature invalid.
        let rejecting = ScriptedBackend::new([Ok(false)]);
        assert_eq!(
            verify_block_signatures(&state, &block, &bls_context(&rejecting)),
            Err(StfError::InvalidBlockSignature)
        );
        assert!(rejecting.seen().contains(&want));

        // After an exit and an index reuse, index 0 has a new key and another version. The
        // version of each set is the version of its state.
        let (exited, reused) = index_reuse_states::<Minimal>();
        let set_of = |state: &BeaconState<Minimal>| {
            let mut bid = signed_bid.clone();
            bid.message.builder_index = 0;
            execution_payload_bid_signature_set(state, &bid).unwrap()
        };
        let versions: Vec<u64> = [&exited, &reused]
            .iter()
            .map(|state| match set_of(state).signers() {
                [SignerRef::Builder { index: 0, version }] => *version,
                other => panic!("not one builder signer: {other:?}"),
            })
            .collect();
        assert_eq!(
            versions,
            vec![
                builder_key_version(&exited, 0).unwrap(),
                builder_key_version(&reused, 0).unwrap()
            ]
        );
        assert_ne!(versions[0], versions[1]);
    }

    #[test]
    fn bid_field_asserts() {
        let state = bid_state();
        for builder_index in [BUILDER_INDEX_SELF_BUILD, 0] {
            let valid = bid_for_state(&state, builder_index, 0);
            let with = |change: &dyn Fn(&mut ExecutionPayloadBid<Minimal>)| {
                let mut signed = valid.clone();
                change(&mut signed.message);
                signed
            };
            // The blob limit of the epoch: at the limit is valid, one more is not.
            let commitments = |count: usize| {
                with(&|bid| bid.blob_kzg_commitments = vec![[0xc0; 48]; count].try_into().unwrap())
            };
            assert_eq!(step(&state, &commitments(9)).0, Ok(()));
            refused(
                &state,
                &commitments(10),
                StfError::BidBlobCommitments { count: 10, max: 9 },
            );
            refused(
                &state,
                &with(&|bid| bid.slot = 10),
                StfError::BidSlotMismatch { bid: 10, state: 9 },
            );
            let latest = state.latest_block_hash;
            let wrong_parent = with(&|bid| bid.parent_block_hash = Root::repeat_byte(0x12));
            let (result, _) = step(&state, &wrong_parent);
            assert_eq!(
                result,
                Err(StfError::BidParentBlockHash {
                    bid: Root::repeat_byte(0x12),
                    expected: latest
                })
            );
            refused(
                &state,
                &with(&|bid| bid.block_hash = latest),
                StfError::BidBlockHashIsParent,
            );
            refused(
                &state,
                &with(&|bid| bid.parent_block_root = Root::repeat_byte(0x07)),
                StfError::BidParentBlockRoot {
                    bid: Root::repeat_byte(0x07),
                    expected: Root::repeat_byte(0x08),
                },
            );
            let mix = get_randao_mix(&state, 1);
            refused(
                &state,
                &with(&|bid| bid.prev_randao = Root::repeat_byte(0x01)),
                StfError::BidPrevRandao {
                    bid: Root::repeat_byte(0x01),
                    expected: mix,
                },
            );
        }
        // The parent block hash is checked in the step only: the parent payload step sets
        // `state.latest_block_hash` before it.
        let mut builder_bid = bid_for_state(&state, 0, 0);
        builder_bid.message.parent_block_hash = Root::repeat_byte(0x12);
        assert!(block_bid_signature_set(&state, &builder_bid, LIMIT)
            .unwrap()
            .is_some());
        // No bid at the genesis slot.
        let mut genesis = state.clone();
        genesis.slot = 0;
        let mut at_genesis = bid_for_state(&state, BUILDER_INDEX_SELF_BUILD, 0);
        at_genesis.message.slot = 0;
        refused(&genesis, &at_genesis, StfError::BidAtGenesisSlot);
        // A limit from the BPO schedule of the network, not a constant.
        let mut many = bid_for_state(&state, 0, 0);
        many.message.blob_kzg_commitments = vec![[0xc0; 48]; 15].try_into().unwrap();
        let mut post = state.clone();
        assert_eq!(process_execution_payload_bid(&mut post, &many, 15), Ok(()));
        assert_eq!(
            process_execution_payload_bid(&mut state.clone(), &many, 14),
            Err(StfError::BidBlobCommitments { count: 15, max: 14 })
        );
    }

    #[test]
    fn bid_step_reads_the_blob_limit_of_the_context() {
        let state = bid_state();
        let mut block = block_at_state_slot(&state).message;
        block.body.signed_execution_payload_bid = bid_for_state(&state, 0, ETH);
        let steps = block_steps::<Minimal>();
        let (_, bid_step) = steps
            .iter()
            .find(|(s, _)| *s == BlockStep::ExecutionPayloadBid)
            .unwrap();
        // No limit, or a limit of another epoch: a caller error, not a proof.
        let mut ctx = BlockContext::default();
        let err = bid_step(&mut state.clone(), &block, &mut ctx).unwrap_err();
        assert_eq!(err, StfError::UnknownBlobLimit(1));
        assert!(!err.proves_invalid());
        ctx.set_max_blobs_per_block(2, LIMIT);
        assert_eq!(
            bid_step(&mut state.clone(), &block, &mut ctx),
            Err(StfError::UnknownBlobLimit(1))
        );
        // The limit of the epoch of the state.
        ctx.set_max_blobs_per_block(1, LIMIT);
        let mut post = state.clone();
        assert_eq!(bid_step(&mut post, &block, &mut ctx), Ok(()));
        assert_eq!(
            post.latest_execution_payload_bid,
            block.body.signed_execution_payload_bid.message
        );
        assert_eq!(
            post.builder_pending_payments
                .get(9)
                .unwrap()
                .withdrawal
                .amount,
            ETH
        );
        ctx.set_max_blobs_per_block(1, 0);
        block
            .body
            .signed_execution_payload_bid
            .message
            .blob_kzg_commitments = vec![[0xc0; 48]; 1].try_into().unwrap();
        assert_eq!(
            bid_step(&mut state.clone(), &block, &mut ctx),
            Err(StfError::BidBlobCommitments { count: 1, max: 0 })
        );
    }

    #[test]
    fn blob_schedule_of_a_closure() {
        // A BPO schedule: 9 blobs before epoch 10, 15 from it.
        let schedule = |epoch: Epoch| if epoch >= 10 { 15 } else { 9 };
        let schedule: &dyn BlobSchedule = &schedule;
        assert_eq!(schedule.max_blobs_per_block(9), 9);
        assert_eq!(schedule.max_blobs_per_block(10), 15);
    }
}
