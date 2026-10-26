//! The Gloas `process_attestation` (G L2396-2480, Modified in Gloas) and its helpers:
//! `get_attestation_participation_flag_indices` (G L1339-1386), `is_attestation_same_slot`
//! (G L1077-1088), `is_valid_indexed_attestation` (G L1022-1041), `get_indexed_attestation`
//! (P0 L1603-1613) and `add_flag` (A L279-284).
//!
//! As for the other operations, the BLS check of the attestation signature is not in
//! [`process_attestation`]: the caller gives
//! [`crate::signatures::attestation_signature_set`] to the backend, in the one batch of
//! [`crate::signatures::block_signature_sets`]. The checks of `is_valid_indexed_attestation`
//! that need no BLS ([`check_indexed_attestation`]) run in every mode.
//!
//! The committees come from the [`CommitteeCache`] of the [`BlockContext`], one shuffle for
//! each epoch and block, never one for each attestation.

use crate::accessors::{
    base_reward, base_reward_per_increment, get_attesting_indices_with, get_block_root,
    get_block_root_at_slot, get_committee_indices, get_current_epoch, get_previous_epoch, has_flag,
    integer_squareroot,
};
use crate::caches::CommitteeCache;
use crate::mutators::increase_balance;
use crate::per_block::{state_proposer_index, BlockContext};
use crate::preset::{
    PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX, WEIGHT_DENOMINATOR,
};
use crate::signatures::{indexed_attestation_signature_set, SignatureBackend};
use crate::{Preset, StfError};
use consensus_types::common::AttestationData;
use consensus_types::gloas::{Attestation, BeaconState, IndexedAttestation};
use consensus_types::primitives::{ParticipationFlags, Slot};
use ssz_types::typenum::Unsigned;
use ssz_types::ProgressiveVariableList;

/// `MIN_ATTESTATION_INCLUSION_DELAY` (`presets/{minimal,mainnet}/phase0.yaml`): 1 in both
/// presets.
pub const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;

/// `process_attestation` (G L2396-2480, Modified in Gloas): sets the participation flags of
/// the attesters, rewards the proposer, and adds the effective balance of each new same-slot
/// attester to the weight of the builder payment of the attested slot.
///
/// `parent_slot` is the slot of the parent block of the block that holds the attestation:
/// the slot of `state.latest_block_header` before the block (G L1756). The BLS check of the
/// signature is not here: see the module documentation. On `Err`, `state` is partly updated:
/// the caller drops it.
pub fn process_attestation<E: Preset>(
    state: &mut BeaconState<E>,
    attestation: &Attestation<E>,
    parent_slot: Slot,
) -> Result<(), StfError> {
    process_attestation_with(
        state,
        attestation,
        parent_slot,
        &mut BlockContext::default(),
    )
}

/// [`process_attestation`] with the committee caches and the total active balance of `ctx`,
/// which the other attestations and the signature sets of the same block read again.
pub fn process_attestation_with<E: Preset>(
    state: &mut BeaconState<E>,
    attestation: &Attestation<E>,
    parent_slot: Slot,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    let data = &attestation.data;
    let indexed = check_attestation(state, attestation, ctx)?;

    // Participation flag indices. `check_attestation` proves `data.slot < state.slot`.
    let inclusion_delay = state.slot - data.slot;
    let participation_flag_indices =
        get_attestation_participation_flag_indices(state, data, inclusion_delay, parent_slot)?;

    // Verify signature: the checks without BLS. The BLS check is in the batch.
    check_indexed_attestation(state, &indexed)?;

    let current_epoch_target = data.target.epoch == get_current_epoch(state);
    let slots_per_epoch = E::slots_per_epoch();
    let payment_index = if current_epoch_target {
        slots_per_epoch + data.slot % slots_per_epoch
    } else {
        data.slot % slots_per_epoch
    } as usize;
    let mut payment = state
        .builder_pending_payments
        .get(payment_index)
        .cloned()
        .ok_or_else(|| {
            StfError::Tree("builder_pending_payments is shorter than its length".into())
        })?;
    let same_slot = is_attestation_same_slot(state, data)?;
    let per_increment = base_reward_per_increment(ctx.total_active_balance().get(state)?);
    let overflow = || StfError::ArithmeticOverflow;

    let mut proposer_reward_numerator: u64 = 0;
    for &index in indexed.attesting_indices.iter() {
        // `check_indexed_attestation` proves that each index is in the registry.
        let effective_balance = state
            .validators
            .get(index as usize)
            .ok_or(StfError::UnknownValidator(index))?
            .effective_balance;
        let (epoch_participation, list) = if current_epoch_target {
            (
                &mut state.current_epoch_participation,
                "current_epoch_participation",
            )
        } else {
            (
                &mut state.previous_epoch_participation,
                "previous_epoch_participation",
            )
        };
        // The index is in the registry, so a shorter list is a fault of our own state.
        let flags = epoch_participation
            .get_mut(index as usize)
            .ok_or(StfError::ListIndexOutOfRange { list, index })?;
        let had_no_participation = *flags == 0b0000_0000;
        let mut will_set_new_flag = false;

        for (flag_index, weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
            if participation_flag_indices.contains(&flag_index) && !has_flag(*flags, flag_index)? {
                *flags = add_flag(*flags, flag_index)?;
                let reward = base_reward(effective_balance, per_increment)?
                    .checked_mul(*weight)
                    .ok_or_else(overflow)?;
                proposer_reward_numerator = proposer_reward_numerator
                    .checked_add(reward)
                    .ok_or_else(overflow)?;
                will_set_new_flag = true;
            }
        }

        if will_set_new_flag && had_no_participation && same_slot && payment.withdrawal.amount > 0 {
            payment.weight = payment
                .weight
                .checked_add(effective_balance)
                .ok_or_else(overflow)?;
        }
    }

    // Reward proposer
    let proposer_reward_denominator =
        (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
    let proposer_reward = proposer_reward_numerator / proposer_reward_denominator;
    increase_balance(state, state_proposer_index(state)?, proposer_reward)?;

    // Update builder payment weight
    *state
        .builder_pending_payments
        .get_mut(payment_index)
        .ok_or_else(|| {
            StfError::Tree("builder_pending_payments is shorter than its length".into())
        })? = payment;
    Ok(())
}

/// The asserts of `process_attestation` before its flag indices (G L2403-2423), and the
/// indexed attestation (P0 L1603-1613) of the attesters. The attestation signature set and
/// [`process_attestation_with`] share it, so that both read the same committees of `ctx`.
///
/// The epoch checks run before the committees are read, so `ctx` shuffles only the previous
/// or the current epoch.
pub(crate) fn check_attestation<E: Preset>(
    state: &BeaconState<E>,
    attestation: &Attestation<E>,
    ctx: &mut BlockContext,
) -> Result<IndexedAttestation<E>, StfError> {
    let data = &attestation.data;
    let state_epoch = get_current_epoch(state);
    let target = data.target.epoch;
    if target != get_previous_epoch(state) && target != state_epoch {
        return Err(StfError::AttestationTargetEpoch {
            target,
            state_epoch,
        });
    }
    if target != E::epoch_at_slot(data.slot) {
        return Err(StfError::AttestationTargetSlot {
            target,
            slot: data.slot,
        });
    }
    let earliest = data
        .slot
        .checked_add(MIN_ATTESTATION_INCLUSION_DELAY)
        .ok_or(StfError::ArithmeticOverflow)?;
    if earliest > state.slot {
        return Err(StfError::AttestationTooEarly {
            slot: data.slot,
            state_slot: state.slot,
        });
    }
    if data.index >= 2 {
        return Err(StfError::AttestationDataIndex(data.index));
    }

    let cache = ctx.committee_cache(state, target)?;
    cache.check_state(state, data.slot)?;
    let bits = &attestation.aggregation_bits;
    let mut committee_offset = 0usize;
    for committee_index in get_committee_indices(&attestation.committee_bits) {
        if committee_index >= cache.committees_per_slot() {
            return Err(StfError::UnknownCommittee {
                slot: data.slot,
                index: committee_index,
            });
        }
        let committee = cache.committee(data.slot, committee_index)?;
        // The spec reads every bit of the committee, so a short bitfield fails also after
        // an attester is found.
        let mut attesters = 0usize;
        for position in 0..committee.len() {
            let bit = committee_offset + position;
            let set = bits.get(bit).map_err(|_| StfError::BitOutOfRange {
                index: bit,
                len: bits.len(),
            })?;
            attesters += usize::from(set);
        }
        if attesters == 0 {
            return Err(StfError::EmptyCommitteeAttesters(committee_index));
        }
        committee_offset += committee.len();
    }

    // Bitfield length matches total number of participants
    if bits.len() != committee_offset {
        return Err(StfError::AggregationBitsLength {
            len: bits.len(),
            participants: committee_offset,
        });
    }
    get_indexed_attestation_with(state, cache, attestation)
}

/// `get_attestation_participation_flag_indices` (G L1339-1386, Modified in Gloas): the
/// flag indices that the attestation sets. The head flag needs the payload status of
/// `data.index` to match: always for a same-slot attestation (which must have index 0),
/// else the payload availability at `parent_slot`.
pub fn get_attestation_participation_flag_indices<E: Preset>(
    state: &BeaconState<E>,
    data: &AttestationData,
    inclusion_delay: u64,
    parent_slot: Slot,
) -> Result<Vec<usize>, StfError> {
    // Matching source
    let justified_checkpoint = if data.target.epoch == get_current_epoch(state) {
        &state.current_justified_checkpoint
    } else {
        &state.previous_justified_checkpoint
    };
    let is_matching_source = data.source == *justified_checkpoint;

    // Matching target
    let target_root = get_block_root(state, data.target.epoch)?;
    let target_root_matches = data.target.root == target_root;
    let is_matching_target = is_matching_source && target_root_matches;

    let payload_matches = if is_attestation_same_slot(state, data)? {
        if data.index != 0 {
            return Err(StfError::SameSlotAttestationIndex(data.index));
        }
        true
    } else {
        let slot_index = parent_slot % E::SlotsPerHistoricalRoot::to_u64();
        // The modulo keeps the index in the vector, so an error is a fault of our state.
        let payload_index = state
            .execution_payload_availability
            .get(slot_index as usize)
            .map_err(|_| StfError::ListIndexOutOfRange {
                list: "execution_payload_availability",
                index: slot_index,
            })?;
        data.index == u64::from(payload_index)
    };

    // Matching head
    let head_root = get_block_root_at_slot(state, data.slot)?;
    let head_root_matches = data.beacon_block_root == head_root;
    let is_matching_head = is_matching_target && head_root_matches && payload_matches;

    if !is_matching_source {
        return Err(StfError::AttestationSourceMismatch);
    }

    let mut participation_flag_indices = Vec::with_capacity(3);
    if is_matching_source && inclusion_delay <= integer_squareroot(E::slots_per_epoch()) {
        participation_flag_indices.push(TIMELY_SOURCE_FLAG_INDEX);
    }
    if is_matching_target {
        participation_flag_indices.push(TIMELY_TARGET_FLAG_INDEX);
    }
    if is_matching_head && inclusion_delay == MIN_ATTESTATION_INCLUSION_DELAY {
        participation_flag_indices.push(TIMELY_HEAD_FLAG_INDEX);
    }
    Ok(participation_flag_indices)
}

/// `add_flag` (A L279-284). A `flag_index` of 8 or more fails, as for
/// [`crate::accessors::has_flag`]: the flag index comes from the code, so that error is a
/// caller error.
pub fn add_flag(
    flags: ParticipationFlags,
    flag_index: usize,
) -> Result<ParticipationFlags, StfError> {
    let flag = u32::try_from(flag_index)
        .ok()
        .and_then(|i| 1u8.checked_shl(i))
        .ok_or(StfError::ListIndexOutOfRange {
            list: "ParticipationFlags",
            index: flag_index as u64,
        })?;
    Ok(flags | flag)
}

/// `is_attestation_same_slot` (G L1077-1088, New in Gloas): whether the attestation is for
/// the block of its own slot, that is, the slot has a block and the attestation votes for it.
pub fn is_attestation_same_slot<E: Preset>(
    state: &BeaconState<E>,
    data: &AttestationData,
) -> Result<bool, StfError> {
    if data.slot == 0 {
        return Ok(true);
    }
    let blockroot = data.beacon_block_root;
    let slot_blockroot = get_block_root_at_slot(state, data.slot)?;
    let prev_blockroot = get_block_root_at_slot(state, data.slot - 1)?;
    Ok(blockroot == slot_blockroot && blockroot != prev_blockroot)
}

/// `get_indexed_attestation` (P0 L1603-1613; Gloas keeps it) over the committees of `cache`
/// ([`get_attesting_indices_with`]).
///
/// The spec's `AttestingIndices` is a `ProgressiveList` without a limit, and
/// `is_valid_indexed_attestation` refuses more than `MAX_VALIDATORS_PER_COMMITTEE *
/// MAX_COMMITTEES_PER_SLOT` indices. The [`IndexedAttestation`] type holds no more than that,
/// so such a list gives the verdict of that check here: [`StfError::InvalidIndexedAttestation`].
pub fn get_indexed_attestation_with<E: Preset>(
    state: &BeaconState<E>,
    cache: &CommitteeCache,
    attestation: &Attestation<E>,
) -> Result<IndexedAttestation<E>, StfError> {
    let attesting_indices = get_attesting_indices_with(state, cache, attestation)?;
    Ok(IndexedAttestation {
        attesting_indices: ProgressiveVariableList::new(attesting_indices.into_iter().collect())
            .map_err(|_| StfError::InvalidIndexedAttestation)?,
        data: attestation.data.clone(),
        signature: attestation.signature,
    })
}

/// `get_indexed_attestation` (P0 L1603-1613). It shuffles the attestation's epoch on each
/// call; [`get_indexed_attestation_with`] reuses a cache.
pub fn get_indexed_attestation<E: Preset>(
    state: &BeaconState<E>,
    attestation: &Attestation<E>,
) -> Result<IndexedAttestation<E>, StfError> {
    let cache = CommitteeCache::new(state, E::epoch_at_slot(attestation.data.slot))?;
    get_indexed_attestation_with(state, &cache, attestation)
}

/// The checks of `is_valid_indexed_attestation` (G L1022-1041, Modified in Gloas) that need
/// no BLS: the indices are not empty, not more than `MAX_VALIDATORS_PER_COMMITTEE *
/// MAX_COMMITTEES_PER_SLOT`, sorted and unique ([`StfError::InvalidIndexedAttestation`]),
/// and each one is in the registry, as `state.validators[index]` raises for the others
/// ([`StfError::UnknownValidator`]).
pub fn check_indexed_attestation<E: Preset>(
    state: &BeaconState<E>,
    indexed_attestation: &IndexedAttestation<E>,
) -> Result<(), StfError> {
    let indices = &indexed_attestation.attesting_indices;
    if indices.is_empty()
        || indices.len() > E::MaxValidatorsPerSlot::to_usize()
        || !indices.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(StfError::InvalidIndexedAttestation);
    }
    // The indices are sorted, so the last one is the largest.
    match indices.last() {
        Some(&last) if last >= state.validators.len() as u64 => {
            Err(StfError::UnknownValidator(last))
        }
        _ => Ok(()),
    }
}

/// `is_valid_indexed_attestation` (G L1022-1041, Modified in Gloas) through `backend`:
/// [`check_indexed_attestation`], then the `bls.FastAggregateVerify` of
/// [`crate::signatures::indexed_attestation_signature_set`].
///
/// `Ok(false)` for indices that fail the checks or a signature that the backend refuses. An
/// index past the registry is [`StfError::UnknownValidator`], as the spec raises for it, and
/// a backend without a verdict is [`StfError::SignatureBackend`].
pub fn is_valid_indexed_attestation<E: Preset>(
    state: &BeaconState<E>,
    indexed_attestation: &IndexedAttestation<E>,
    backend: &dyn SignatureBackend,
) -> Result<bool, StfError> {
    match indexed_attestation_signature_set(state, indexed_attestation) {
        Ok(set) => Ok(backend.verify_signature_sets(std::slice::from_ref(&set))?),
        Err(StfError::InvalidIndexedAttestation) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::state_root;
    use crate::testing::genesis_state;
    use consensus_types::common::Checkpoint;
    use consensus_types::gloas::BuilderPendingWithdrawal;
    use consensus_types::primitives::{Address, Gwei, Root};
    use consensus_types::Minimal;
    use ssz::{BitVector, ProgressiveBitList};

    const ETH: Gwei = 1_000_000_000;
    /// The minimal `SLOTS_PER_EPOCH`.
    const SPE: u64 = 8;

    /// 64 validators of 32 ETH at `slot`, with the block root `[s + 1; 32]` at each slot `s`
    /// before it. Minimal has two committees of four for each slot.
    pub(crate) fn attestation_state(slot: Slot) -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        state.slot = slot;
        for s in 0..slot {
            *state.block_roots.get_mut(s as usize).unwrap() = Root::repeat_byte(s as u8 + 1);
        }
        state
    }

    /// An attestation of committee 0 at `slot` in epoch 0 with the bits at `positions` set,
    /// for the block of the slot (same-slot), with the matching source and target.
    pub(crate) fn attestation(
        state: &BeaconState<Minimal>,
        slot: Slot,
        positions: &[usize],
    ) -> Attestation<Minimal> {
        let cache = CommitteeCache::new(state, slot / SPE).unwrap();
        let size = cache.committee(slot, 0).unwrap().len();
        let mut aggregation_bits = ProgressiveBitList::with_capacity(size);
        for &p in positions {
            aggregation_bits.set(p, true).unwrap();
        }
        let mut committee_bits = BitVector::new();
        committee_bits.set(0, true).unwrap();
        Attestation {
            aggregation_bits,
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: Root::repeat_byte(slot as u8 + 1),
                source: state.current_justified_checkpoint.clone(),
                target: Checkpoint {
                    epoch: slot / SPE,
                    root: Root::repeat_byte((slot / SPE * SPE) as u8 + 1),
                },
            },
            signature: [0x33; 96],
            committee_bits,
        }
    }

    /// The validator at `position` of committee 0 at `slot`.
    fn attester(state: &BeaconState<Minimal>, slot: Slot, position: usize) -> u64 {
        CommitteeCache::new(state, slot / SPE)
            .unwrap()
            .committee(slot, 0)
            .unwrap()[position]
    }

    /// Puts a pending payment of `amount` with weight 0 at `index`.
    fn set_payment(state: &mut BeaconState<Minimal>, index: usize, amount: Gwei) {
        let payment = state.builder_pending_payments.get_mut(index).unwrap();
        payment.weight = 0;
        payment.withdrawal = BuilderPendingWithdrawal {
            fee_recipient: Address::repeat_byte(0xfe),
            amount,
            builder_index: 0,
        };
    }

    fn weight(state: &BeaconState<Minimal>, index: usize) -> Gwei {
        state.builder_pending_payments.get(index).unwrap().weight
    }

    #[test]
    fn payment_weight() {
        // A same-slot attestation at slot 3, included at slot 4: the payment of slot 3 of
        // the current epoch is at SLOTS_PER_EPOCH + 3.
        let mut state = attestation_state(4);
        let payment = (SPE + 3) as usize;
        set_payment(&mut state, payment, 5 * ETH);
        let first = attestation(&state, 3, &[0]);
        let a0 = attester(&state, 3, 0);
        assert_eq!(process_attestation(&mut state, &first, 3), Ok(()));
        // It sets the three flags of an attester with no participation: one effective
        // balance of weight.
        assert_eq!(
            *state.current_epoch_participation.get(a0 as usize).unwrap(),
            0b111
        );
        assert_eq!(weight(&state, payment), 32 * ETH);

        // The same attestation again sets no new flag and adds no weight.
        assert_eq!(process_attestation(&mut state, &first, 3), Ok(()));
        assert_eq!(weight(&state, payment), 32 * ETH);

        // An attester with participation before (a flag set) gets the new flags, but adds
        // no weight.
        let a1 = attester(&state, 3, 1);
        *state
            .current_epoch_participation
            .get_mut(a1 as usize)
            .unwrap() = 0b001;
        let second = attestation(&state, 3, &[0, 1]);
        assert_eq!(process_attestation(&mut state, &second, 3), Ok(()));
        assert_eq!(
            *state.current_epoch_participation.get(a1 as usize).unwrap(),
            0b111
        );
        assert_eq!(weight(&state, payment), 32 * ETH);

        // A new attester adds its own effective balance one time.
        state
            .validators
            .get_mut(attester(&state, 3, 2) as usize)
            .unwrap()
            .effective_balance = 31 * ETH;
        let third = attestation(&state, 3, &[2]);
        assert_eq!(process_attestation(&mut state, &third, 3), Ok(()));
        assert_eq!(weight(&state, payment), 63 * ETH);
        // The other payments did not change.
        for i in 0..2 * SPE as usize {
            if i != payment {
                assert_eq!(weight(&state, i), 0, "{i}");
            }
        }

        // A payment with no amount gets no weight.
        let mut state = attestation_state(4);
        set_payment(&mut state, payment, 0);
        assert_eq!(process_attestation(&mut state, &first, 3), Ok(()));
        assert_eq!(weight(&state, payment), 0);

        // An attestation of an earlier block (not same-slot) gets no weight.
        let mut state = attestation_state(4);
        set_payment(&mut state, payment, 5 * ETH);
        let mut late = attestation(&state, 3, &[0]);
        late.data.beacon_block_root = Root::repeat_byte(3);
        assert_eq!(process_attestation(&mut state, &late, 3), Ok(()));
        assert_ne!(
            *state.current_epoch_participation.get(a0 as usize).unwrap(),
            0
        );
        assert_eq!(weight(&state, payment), 0);
    }

    #[test]
    fn attestation_index_bound() {
        let mut state = attestation_state(4);
        let before = state_root(&mut state).unwrap();
        for index in [2, 3, u64::MAX] {
            let mut bad = attestation(&state, 3, &[0]);
            bad.data.index = index;
            assert_eq!(
                process_attestation(&mut state, &bad, 3),
                Err(StfError::AttestationDataIndex(index))
            );
        }
        assert_eq!(state_root(&mut state).unwrap(), before);
        // Index 1 is in the bound, but a same-slot attestation must have index 0.
        let mut one = attestation(&state, 3, &[0]);
        one.data.index = 1;
        assert_eq!(
            process_attestation(&mut state, &one, 3),
            Err(StfError::SameSlotAttestationIndex(1))
        );
        // For an earlier block, index 1 is the payload status.
        one.data.beacon_block_root = Root::repeat_byte(3);
        assert_eq!(process_attestation(&mut state, &one, 3), Ok(()));
    }

    #[test]
    fn attestation_asserts() {
        let state = attestation_state(4);
        let refused = |attestation: &Attestation<Minimal>| {
            let mut copy = state.clone();
            let before = state_root(&mut copy).unwrap();
            let result = process_attestation(&mut copy, attestation, 3);
            assert_eq!(state_root(&mut copy).unwrap(), before);
            result
        };
        let valid = attestation(&state, 3, &[0]);
        let with = |f: &dyn Fn(&mut Attestation<Minimal>)| {
            let mut a = valid.clone();
            f(&mut a);
            refused(&a)
        };
        assert_eq!(
            with(&|a| a.data.target.epoch = 1),
            Err(StfError::AttestationTargetEpoch {
                target: 1,
                state_epoch: 0
            })
        );
        assert_eq!(
            with(&|a| a.data.slot = 8),
            Err(StfError::AttestationTargetSlot { target: 0, slot: 8 })
        );
        assert_eq!(
            with(&|a| a.data.slot = 4),
            Err(StfError::AttestationTooEarly {
                slot: 4,
                state_slot: 4
            })
        );
        // Minimal with 64 validators has two committees for each slot.
        assert_eq!(
            with(&|a| a.committee_bits.set(2, true).unwrap()),
            Err(StfError::UnknownCommittee { slot: 3, index: 2 })
        );
        assert_eq!(
            with(&|a| a.aggregation_bits.set(0, false).unwrap()),
            Err(StfError::EmptyCommitteeAttesters(0))
        );
        // Two committees, and bits for the first one only.
        assert_eq!(
            with(&|a| a.committee_bits.set(1, true).unwrap()),
            Err(StfError::BitOutOfRange { index: 4, len: 4 })
        );
        assert_eq!(
            with(&|a| {
                let mut bits = ProgressiveBitList::with_capacity(5);
                bits.set(0, true).unwrap();
                a.aggregation_bits = bits;
            }),
            Err(StfError::AggregationBitsLength {
                len: 5,
                participants: 4
            })
        );
        assert_eq!(
            with(&|a| a.data.source.epoch = 1),
            Err(StfError::AttestationSourceMismatch)
        );
        // No committee: no attester, which `is_valid_indexed_attestation` refuses.
        assert_eq!(
            with(&|a| {
                a.committee_bits = BitVector::new();
                a.aggregation_bits = ProgressiveBitList::with_capacity(0);
            }),
            Err(StfError::InvalidIndexedAttestation)
        );
        // The proposer of the slot comes from our lookahead: an index past the registry is
        // a fault of our state.
        let mut corrupt = state.clone();
        *corrupt.proposer_lookahead.get_mut(4).unwrap() = 64;
        let fault = process_attestation(&mut corrupt, &valid, 3).unwrap_err();
        assert_eq!(
            fault,
            StfError::ListIndexOutOfRange {
                list: "validators",
                index: 64
            }
        );
        assert!(!fault.proves_invalid());
    }

    #[test]
    fn flags_and_rewards() {
        // Two committees: both attest, the reward of the proposer is the sum of the base
        // rewards of the three flags of each attester, divided by 448.
        let mut state = attestation_state(4);
        let mut both = attestation(&state, 3, &[0, 1]);
        both.committee_bits.set(1, true).unwrap();
        let mut bits = ProgressiveBitList::with_capacity(8);
        for p in [0, 1, 4] {
            bits.set(p, true).unwrap();
        }
        both.aggregation_bits = bits;
        let proposer = state_proposer_index(&state).unwrap();
        let before = *state.balances.get(proposer as usize).unwrap();
        assert_eq!(process_attestation(&mut state, &both, 3), Ok(()));
        let base = base_reward(32 * ETH, base_reward_per_increment(64 * 32 * ETH)).unwrap();
        assert_eq!(
            *state.balances.get(proposer as usize).unwrap(),
            before + 3 * base * 54 / 448
        );
        let set = state
            .current_epoch_participation
            .iter()
            .filter(|&&f| f == 0b111)
            .count();
        assert_eq!(set, 3);

        // The flags for each inclusion delay: the head flag needs a delay of 1, the source
        // flag a delay of at most isqrt(8) = 2.
        let state = attestation_state(8);
        let data = attestation(&state, 3, &[0]).data;
        let flags = |delay| get_attestation_participation_flag_indices(&state, &data, delay, 3);
        assert_eq!(flags(1), Ok(vec![0, 1, 2]));
        assert_eq!(flags(2), Ok(vec![0, 1]));
        assert_eq!(flags(3), Ok(vec![1]));
        // A wrong target root keeps the source flag only.
        let mut wrong_target = data.clone();
        wrong_target.target.root = Root::repeat_byte(0xee);
        assert_eq!(
            get_attestation_participation_flag_indices(&state, &wrong_target, 1, 3),
            Ok(vec![0])
        );

        // An attestation of an earlier block: the head flag needs the payload status of
        // `data.index` to be the availability bit at the parent slot.
        let mut earlier = data.clone();
        earlier.slot = 4;
        earlier.beacon_block_root = Root::repeat_byte(4);
        assert!(!is_attestation_same_slot(&state, &earlier).unwrap());
        let mut available = state.clone();
        available
            .execution_payload_availability
            .set(6, true)
            .unwrap();
        available
            .execution_payload_availability
            .set(5, false)
            .unwrap();
        // The head root of slot 4 is the root of slot 3.
        *available.block_roots.get_mut(4).unwrap() = Root::repeat_byte(4);
        for (index, parent_slot, head) in [(1, 6, true), (0, 6, false), (0, 5, true), (1, 5, false)]
        {
            earlier.index = index;
            let got =
                get_attestation_participation_flag_indices(&available, &earlier, 1, parent_slot)
                    .unwrap();
            assert_eq!(got.contains(&2), head, "{index} {parent_slot}");
        }
        // Slot 0 is always the same slot.
        let mut genesis = data.clone();
        genesis.slot = 0;
        assert_eq!(is_attestation_same_slot(&state, &genesis), Ok(true));

        assert_eq!(add_flag(0b001, 2), Ok(0b101));
        assert!(add_flag(0, 8).is_err());
    }

    #[test]
    fn previous_epoch_target() {
        // An attestation of slot 3 (epoch 0) included at slot 9 (epoch 1): the previous
        // participation and the payment of slot 3 of the previous epoch.
        let mut state = attestation_state(9);
        state.previous_justified_checkpoint = state.current_justified_checkpoint.clone();
        set_payment(&mut state, 3, 5 * ETH);
        set_payment(&mut state, (SPE + 3) as usize, 5 * ETH);
        let a = attestation(&state, 3, &[0]);
        let a0 = attester(&state, 3, 0);
        assert_eq!(process_attestation(&mut state, &a, 3), Ok(()));
        // Delay 6: only the target flag.
        assert_eq!(
            *state.previous_epoch_participation.get(a0 as usize).unwrap(),
            0b010
        );
        assert_eq!(
            *state.current_epoch_participation.get(a0 as usize).unwrap(),
            0
        );
        assert_eq!(weight(&state, 3), 32 * ETH);
        assert_eq!(weight(&state, (SPE + 3) as usize), 0);
    }

    #[test]
    fn indexed_attestations() {
        use crate::testing::ScriptedBackend;
        use crate::BackendError;
        let state = attestation_state(4);
        let a = attestation(&state, 3, &[0, 2]);
        let indexed = get_indexed_attestation(&state, &a).unwrap();
        let mut want = vec![attester(&state, 3, 0), attester(&state, 3, 2)];
        want.sort_unstable();
        assert_eq!(indexed.attesting_indices.to_vec(), want);
        assert_eq!(indexed.data, a.data);
        assert_eq!(check_indexed_attestation(&state, &indexed), Ok(()));

        // The backend gives the verdict of the signature.
        let backend = ScriptedBackend::new([Ok(true), Ok(false)]);
        assert_eq!(
            is_valid_indexed_attestation(&state, &indexed, &backend),
            Ok(true)
        );
        assert_eq!(
            is_valid_indexed_attestation(&state, &indexed, &backend),
            Ok(false)
        );
        assert_eq!(backend.seen().len(), 2);
        let unavailable = ScriptedBackend::new([Err(BackendError("timeout".into()))]);
        assert_eq!(
            is_valid_indexed_attestation(&state, &indexed, &unavailable),
            Err(StfError::SignatureBackend(BackendError("timeout".into())))
        );
        // Indices that are not valid give false without a backend call, and an index past
        // the registry raises, as `state.validators[index]` does.
        let none = ScriptedBackend::new([]);
        let mut empty = indexed.clone();
        empty.attesting_indices = Default::default();
        assert_eq!(
            is_valid_indexed_attestation(&state, &empty, &none),
            Ok(false)
        );
        let mut past = indexed.clone();
        past.attesting_indices = vec![1, 64].try_into().unwrap();
        assert_eq!(
            is_valid_indexed_attestation(&state, &past, &none),
            Err(StfError::UnknownValidator(64))
        );
    }
}
