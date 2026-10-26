//! Beacon-state accessors and the misc helpers they share.

use crate::caches::committee::{compute_shuffled_index, CommitteeCache};
use crate::preset::{
    BASE_REWARD_FACTOR, BUILDER_INDEX_FLAG, BUILDER_WITHDRAWAL_PREFIX,
    COMPOUNDING_WITHDRAWAL_PREFIX, EFFECTIVE_BALANCE_INCREMENT, ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    MAX_EFFECTIVE_BALANCE_ELECTRA, MAX_SEED_LOOKAHEAD, MIN_DEPOSIT_AMOUNT, MIN_SEED_LOOKAHEAD,
};
use crate::{Preset, StfError};
use consensus_types::common::Validator;
use consensus_types::gloas::{Attestation, BeaconState};
use consensus_types::primitives::{
    BuilderIndex, Bytes32, CommitteeIndex, Domain, DomainType, Epoch, Gwei, ParticipationFlags,
    Root, Slot, ValidatorIndex, FAR_FUTURE_EPOCH,
};
use consensus_types::signing::{compute_domain, DOMAIN_BEACON_ATTESTER, DOMAIN_SYNC_COMMITTEE};
use ethereum_hashing::{Context, Sha256Context};
use ssz::BitVector;
use ssz_types::typenum::Unsigned;
use std::collections::BTreeSet;

/// `hash` (P0 "Crypto"): SHA-256 of the concatenation of `parts`, without a copy.
pub(crate) fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut context = Context::new();
    for part in parts {
        context.update(part);
    }
    context.finalize()
}

/// `bytes_to_uint64` (P0 L1028-1032): little-endian.
pub(crate) fn bytes_to_uint64(bytes: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*bytes)
}

/// `get_current_epoch` (P0 L1418-1422).
pub fn get_current_epoch<E: Preset>(state: &BeaconState<E>) -> Epoch {
    E::epoch_at_slot(state.slot)
}

/// `is_active_validator` (P0 L1091-1095).
pub fn is_active_validator(validator: &Validator, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}

/// `get_active_validator_indices` (P0 L1469-1477).
pub fn get_active_validator_indices<E: Preset>(
    state: &BeaconState<E>,
    epoch: Epoch,
) -> Vec<ValidatorIndex> {
    state
        .validators
        .iter()
        .enumerate()
        .filter(|(_, v)| is_active_validator(v, epoch))
        .map(|(i, _)| i as ValidatorIndex)
        .collect()
}

/// `get_randao_mix` (P0 L1459-1463).
pub fn get_randao_mix<E: Preset>(state: &BeaconState<E>, epoch: Epoch) -> Bytes32 {
    let index = epoch % E::EpochsPerHistoricalVector::to_u64();
    // The vector has exactly EPOCHS_PER_HISTORICAL_VECTOR entries, so `index` is in range.
    state
        .randao_mixes
        .get(index as usize)
        .copied()
        .unwrap_or_default()
}

/// `get_seed` (P0 L1496-1503).
pub fn get_seed<E: Preset>(
    state: &BeaconState<E>,
    epoch: Epoch,
    domain_type: DomainType,
) -> Result<Bytes32, StfError> {
    // `epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1`, left to right as in the
    // spec, so an epoch near `u64::MAX` overflows instead of wrapping.
    let mix_epoch = epoch
        .checked_add(E::EpochsPerHistoricalVector::to_u64())
        .and_then(|e| e.checked_sub(MIN_SEED_LOOKAHEAD + 1))
        .ok_or(StfError::ArithmeticOverflow)?;
    let mix = get_randao_mix(state, mix_epoch);
    Ok(Bytes32::from(hash(&[
        &domain_type,
        &epoch.to_le_bytes(),
        mix.as_slice(),
    ])))
}

/// `get_committee_count_per_slot` (P0 L1509-1521) for `active_count` active validators.
pub fn committee_count_per_slot<E: Preset>(active_count: u64) -> u64 {
    (active_count / E::slots_per_epoch() / E::TARGET_COMMITTEE_SIZE)
        .clamp(1, E::MaxCommitteesPerSlot::to_u64())
}

/// `get_committee_count_per_slot` (P0 L1509-1521).
pub fn get_committee_count_per_slot<E: Preset>(state: &BeaconState<E>, epoch: Epoch) -> u64 {
    let active = state
        .validators
        .iter()
        .filter(|v| is_active_validator(v, epoch))
        .count();
    committee_count_per_slot::<E>(active as u64)
}

/// `get_domain` (P0 L1589-1597). `None` is the current epoch.
pub fn get_domain<E: Preset>(
    state: &BeaconState<E>,
    domain_type: DomainType,
    epoch: Option<Epoch>,
) -> Domain {
    let epoch = epoch.unwrap_or_else(|| get_current_epoch(state));
    let fork_version = if epoch < state.fork.epoch {
        state.fork.previous_version
    } else {
        state.fork.current_version
    };
    compute_domain(domain_type, fork_version, state.genesis_validators_root)
}

/// `get_committee_indices` (E L736-737).
pub fn get_committee_indices<N: Unsigned + Clone>(
    committee_bits: &BitVector<N>,
) -> Vec<CommitteeIndex> {
    committee_bits
        .iter()
        .enumerate()
        .filter(|(_, bit)| *bit)
        .map(|(i, _)| i as CommitteeIndex)
        .collect()
}

/// `get_attesting_indices` (E L801-819, Modified in Electra; Gloas keeps it). It shuffles
/// the attestation's epoch on each call, so only the tests have it.
/// [`get_attesting_indices_with`] reuses a cache.
#[cfg(test)]
pub fn get_attesting_indices<E: Preset>(
    state: &BeaconState<E>,
    attestation: &Attestation<E>,
) -> Result<BTreeSet<ValidatorIndex>, StfError> {
    let cache = CommitteeCache::new(state, E::epoch_at_slot(attestation.data.slot))?;
    get_attesting_indices_with(state, &cache, attestation)
}

/// `get_attesting_indices` over the committees of `cache`, which must be the cache of the
/// attestation slot's epoch (else `Err(CacheEpochMismatch)`) with the attester seed of
/// `state` for that epoch (else `Err(CacheSeedMismatch)`), shuffled from a registry of the
/// length of `state.validators` (else `Err(CacheRegistryMismatch)`).
pub fn get_attesting_indices_with<E: Preset>(
    state: &BeaconState<E>,
    cache: &CommitteeCache,
    attestation: &Attestation<E>,
) -> Result<BTreeSet<ValidatorIndex>, StfError> {
    let slot = attestation.data.slot;
    cache.check_state(state, slot)?;
    let bits = &attestation.aggregation_bits;
    let mut output = BTreeSet::new();
    let mut committee_offset = 0usize;
    for committee_index in get_committee_indices(&attestation.committee_bits) {
        let committee = cache.committee(slot, committee_index)?;
        for (index, attester_index) in committee.iter().enumerate() {
            let bit = committee_offset + index;
            let set = bits.get(bit).map_err(|_| StfError::BitOutOfRange {
                index: bit,
                len: bits.len(),
            })?;
            if set {
                output.insert(*attester_index);
            }
        }
        committee_offset += committee.len();
    }
    Ok(output)
}

/// `compute_balance_weighted_selection` (G L1198-1230, New in Gloas).
///
/// Returns `size` indices of `indices`, sampled by effective balance, with possible
/// duplicates. With `shuffle_indices` the candidates are drawn through
/// `compute_shuffled_index`, else `indices` is walked in order.
///
/// The spec gives it only active indices of `state` (the sync committee, the proposer
/// lookahead and the PTC). Thus an index past the registry is a fault of our own state
/// (`ListIndexOutOfRange`), not a proof.
pub fn compute_balance_weighted_selection<E: Preset>(
    state: &BeaconState<E>,
    indices: &[ValidatorIndex],
    seed: &Bytes32,
    size: u64,
    shuffle_indices: bool,
) -> Result<Vec<ValidatorIndex>, StfError> {
    const MAX_RANDOM_VALUE: u64 = (1 << 16) - 1;
    let total = indices.len() as u64;
    if total == 0 {
        return Err(StfError::NoCandidates);
    }
    let effective_balances = indices
        .iter()
        .map(|&index| {
            state
                .validators
                .get(index as usize)
                .map(|v| v.effective_balance)
                .ok_or(StfError::ListIndexOutOfRange {
                    list: "validators",
                    index,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let seed: &[u8; 32] = seed.as_ref();
    let mut selected = Vec::with_capacity(size as usize);
    let mut random_bytes = [0u8; 32];
    let mut i = 0u64;
    while (selected.len() as u64) < size {
        let offset = (i % 16 * 2) as usize;
        if offset == 0 {
            random_bytes = hash(&[seed, &(i / 16).to_le_bytes()]);
        }
        let mut next_index = i % total;
        if shuffle_indices {
            next_index = compute_shuffled_index(next_index, total, seed, E::SHUFFLE_ROUND_COUNT)?;
        }
        let weight = effective_balances[next_index as usize]
            .checked_mul(MAX_RANDOM_VALUE)
            .ok_or(StfError::ArithmeticOverflow)?;
        let random_value = u64::from(u16::from_le_bytes([
            random_bytes[offset],
            random_bytes[offset + 1],
        ]));
        // At most 2048 ETH * (2**16 - 1), far below u64::MAX.
        let threshold = MAX_EFFECTIVE_BALANCE_ELECTRA * random_value;
        if weight >= threshold {
            selected.push(indices[next_index as usize]);
        }
        i = i.checked_add(1).ok_or(StfError::ArithmeticOverflow)?;
    }
    Ok(selected)
}

/// `get_next_sync_committee_indices` (G L1315-1324, Modified in Gloas).
pub fn get_next_sync_committee_indices<E: Preset>(
    state: &BeaconState<E>,
) -> Result<Vec<ValidatorIndex>, StfError> {
    let epoch = get_current_epoch(state)
        .checked_add(1)
        .ok_or(StfError::ArithmeticOverflow)?;
    let seed = get_seed(state, epoch, DOMAIN_SYNC_COMMITTEE)?;
    let indices = get_active_validator_indices(state, epoch);
    compute_balance_weighted_selection(state, &indices, &seed, E::SyncCommitteeSize::to_u64(), true)
}

/// The attester seed of `epoch`: `get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)`.
pub(crate) fn attester_seed<E: Preset>(
    state: &BeaconState<E>,
    epoch: Epoch,
) -> Result<Bytes32, StfError> {
    get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)
}

/// `compute_activation_exit_epoch` (P0 L1356-1360): `epoch + 1 + MAX_SEED_LOOKAHEAD`.
pub fn compute_activation_exit_epoch(epoch: Epoch) -> Result<Epoch, StfError> {
    epoch
        .checked_add(1)
        .and_then(|e| e.checked_add(MAX_SEED_LOOKAHEAD))
        .ok_or(StfError::ArithmeticOverflow)
}

/// `get_total_active_balance` (P0 L1576-1583), with `get_total_balance` (P0 L1559-1570)
/// inlined: the sum of the effective balances of the validators that are active in the
/// current epoch, and at least `EFFECTIVE_BALANCE_INCREMENT`.
///
/// It reads the whole registry. Callers that read the total more than one time in an epoch
/// use a [`TotalActiveBalanceCache`].
pub fn get_total_active_balance<E: Preset>(state: &BeaconState<E>) -> Result<Gwei, StfError> {
    let epoch = get_current_epoch(state);
    let total = state
        .validators
        .iter()
        .filter(|v| is_active_validator(v, epoch))
        .try_fold(0u64, |sum, v| sum.checked_add(v.effective_balance))
        .ok_or(StfError::ArithmeticOverflow)?;
    Ok(total.max(EFFECTIVE_BALANCE_INCREMENT))
}

/// The root that fixes the effective balances and the active set of `epoch`: the block
/// root at the last slot of the previous epoch, `get_block_root_at_slot(state,
/// compute_start_slot_at_epoch(epoch) - 1)` (P0 L1448-1453), read from a state of `epoch`.
///
/// The spec has no block before slot 0. The validators of epoch 0 are the genesis registry,
/// so its root `genesis_validators_root` takes that place.
fn balance_decision_root<E: Preset>(
    state: &BeaconState<E>,
    epoch: Epoch,
) -> Result<Root, StfError> {
    let Some(decision_slot) = E::start_slot_at_epoch(epoch).checked_sub(1) else {
        return Ok(state.genesis_validators_root);
    };
    // `decision_slot < state.slot <= decision_slot + SLOTS_PER_EPOCH`, so the assert of
    // `get_block_root_at_slot` holds and the root is in the vector.
    let index = decision_slot % E::SlotsPerHistoricalRoot::to_u64();
    state
        .block_roots
        .get(index as usize)
        .copied()
        .ok_or_else(|| StfError::Tree("block_roots is shorter than its length".into()))
}

/// The total active balance of the current epoch, read one time per `(epoch, decision
/// root)`. The decision root is the block root at the last slot of the previous epoch (the
/// genesis validators root in epoch 0).
///
/// The effective balances and the active set of an epoch are fixed by the chain up to the
/// decision root:
///
/// - Only `process_epoch` changes the effective balances, and the epoch processing at the
///   end of the previous epoch runs on the state of the decision root.
/// - The registry updates set activation and exit epochs in the future, so the active set
///   of the current epoch stays the same.
/// - `process_effective_balance_updates` runs at the end of the epoch, and no later step of
///   the same `process_epoch` reads the total. Then the state goes to the next epoch, which
///   has a new key.
///
/// Thus two states with the same key have the same total, also on two branches, and one
/// cache can follow a state through its blocks and epochs. A key that is not the cached key
/// reads the registry again. After a direct edit of the registry (for example in a test),
/// use a new cache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TotalActiveBalanceCache {
    entry: Option<((Epoch, Root), Gwei)>,
}

impl TotalActiveBalanceCache {
    /// `get_total_active_balance(state)`. It reads the registry only when the key of `state`
    /// is not the key of the cached total.
    pub fn get<E: Preset>(&mut self, state: &BeaconState<E>) -> Result<Gwei, StfError> {
        let epoch = get_current_epoch(state);
        let key = (epoch, balance_decision_root(state, epoch)?);
        if let Some((cached, total)) = self.entry {
            if cached == key {
                return Ok(total);
            }
        }
        let total = get_total_active_balance(state)?;
        self.entry = Some((key, total));
        Ok(total)
    }

    /// The `(epoch, decision root)` of the cached total, `None` before the first read.
    pub fn key(&self) -> Option<(Epoch, Root)> {
        self.entry.map(|(key, _)| key)
    }
}

/// `churn - churn % EFFECTIVE_BALANCE_INCREMENT`.
fn round_to_increment(churn: Gwei) -> Gwei {
    churn - churn % EFFECTIVE_BALANCE_INCREMENT
}

/// `get_exit_churn_limit` (G L1461-1470, New in Gloas) for a total active balance of
/// `total_active_balance`.
pub fn exit_churn_limit<E: Preset>(total_active_balance: Gwei) -> Gwei {
    let churn = E::MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA
        .max(total_active_balance / E::CHURN_LIMIT_QUOTIENT_GLOAS);
    round_to_increment(churn)
}

/// `get_activation_churn_limit` (G L1445-1455, New in Gloas) for a total active balance of
/// `total_active_balance`: the exit churn, capped at
/// `MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS`.
pub fn activation_churn_limit<E: Preset>(total_active_balance: Gwei) -> Gwei {
    E::MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS.min(exit_churn_limit::<E>(total_active_balance))
}

/// `get_consolidation_churn_limit` (G L1479-1486, Modified in Gloas) for a total active
/// balance of `total_active_balance`.
pub fn consolidation_churn_limit<E: Preset>(total_active_balance: Gwei) -> Gwei {
    round_to_increment(total_active_balance / E::CONSOLIDATION_CHURN_LIMIT_QUOTIENT)
}

/// `get_activation_churn_limit` (G L1445-1455, New in Gloas), with the total from `cache`.
pub fn get_activation_churn_limit<E: Preset>(
    state: &BeaconState<E>,
    cache: &mut TotalActiveBalanceCache,
) -> Result<Gwei, StfError> {
    Ok(activation_churn_limit::<E>(cache.get(state)?))
}

/// `get_exit_churn_limit` (G L1461-1470, New in Gloas), with the total from `cache`.
pub fn get_exit_churn_limit<E: Preset>(
    state: &BeaconState<E>,
    cache: &mut TotalActiveBalanceCache,
) -> Result<Gwei, StfError> {
    Ok(exit_churn_limit::<E>(cache.get(state)?))
}

/// `get_consolidation_churn_limit` (G L1479-1486, Modified in Gloas), with the total from
/// `cache`.
pub fn get_consolidation_churn_limit<E: Preset>(
    state: &BeaconState<E>,
    cache: &mut TotalActiveBalanceCache,
) -> Result<Gwei, StfError> {
    Ok(consolidation_churn_limit::<E>(cache.get(state)?))
}

/// `integer_squareroot` (P0 L989-1000). `u64::isqrt(u64::MAX)` is `UINT64_MAX_SQRT`, as in
/// the spec.
pub fn integer_squareroot(n: u64) -> u64 {
    n.isqrt()
}

/// `has_flag` (A L290-295). A `flag_index` of 8 or more fails, as the spec raises on
/// `ParticipationFlags(2**flag_index)`. The flag index comes from the code, so that error
/// is a caller error.
pub fn has_flag(flags: ParticipationFlags, flag_index: usize) -> Result<bool, StfError> {
    let flag = u32::try_from(flag_index)
        .ok()
        .and_then(|i| 1u8.checked_shl(i))
        .ok_or(StfError::ListIndexOutOfRange {
            list: "ParticipationFlags",
            index: flag_index as u64,
        })?;
    Ok(flags & flag == flag)
}

/// `get_previous_epoch` (P0 L1428-1432).
pub fn get_previous_epoch<E: Preset>(state: &BeaconState<E>) -> Epoch {
    get_current_epoch(state).saturating_sub(1)
}

/// `get_block_root_at_slot` (P0 L1448-1453).
pub fn get_block_root_at_slot<E: Preset>(
    state: &BeaconState<E>,
    slot: Slot,
) -> Result<Root, StfError> {
    let history = E::SlotsPerHistoricalRoot::to_u64();
    let out_of_range = || StfError::BlockRootOutOfRange {
        slot,
        state_slot: state.slot,
    };
    // `assert slot < state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT`. Python evaluates the
    // sum only when `slot < state.slot`, and a `Uint64` sum past 2**64 - 1 raises.
    if slot >= state.slot {
        return Err(out_of_range());
    }
    let newest = slot
        .checked_add(history)
        .ok_or(StfError::ArithmeticOverflow)?;
    if state.slot > newest {
        return Err(out_of_range());
    }
    state
        .block_roots
        .get((slot % history) as usize)
        .copied()
        .ok_or_else(|| StfError::Tree("block_roots is shorter than its length".into()))
}

/// `get_block_root` (P0 L1438-1442).
pub fn get_block_root<E: Preset>(state: &BeaconState<E>, epoch: Epoch) -> Result<Root, StfError> {
    let slot = epoch
        .checked_mul(E::slots_per_epoch())
        .ok_or(StfError::ArithmeticOverflow)?;
    get_block_root_at_slot(state, slot)
}

/// `get_base_reward_per_increment` (A L369-374) for a total active balance.
pub fn base_reward_per_increment(total_active_balance: Gwei) -> Gwei {
    // EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR is 64 * 10**9, far below u64::MAX.
    // The square root is 0 only for a total of 0, which `get_total_active_balance` never
    // gives (its floor is one increment); `checked_div` keeps a 0 from a caller harmless.
    (EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR)
        .checked_div(integer_squareroot(total_active_balance))
        .unwrap_or(0)
}

/// `get_base_reward_per_increment` (A L369-374).
pub fn get_base_reward_per_increment<E: Preset>(state: &BeaconState<E>) -> Result<Gwei, StfError> {
    Ok(base_reward_per_increment(get_total_active_balance(state)?))
}

/// `get_base_reward` (A L386-391, Modified in Altair) for an effective balance and the base
/// reward per increment: `increments * base_reward_per_increment`.
pub fn base_reward(effective_balance: Gwei, per_increment: Gwei) -> Result<Gwei, StfError> {
    (effective_balance / EFFECTIVE_BALANCE_INCREMENT)
        .checked_mul(per_increment)
        .ok_or(StfError::ArithmeticOverflow)
}

/// `get_base_reward` (A L386-391, Modified in Altair). It reads the whole registry for the
/// total active balance; [`base_reward`] takes a total that the caller keeps.
pub fn get_base_reward<E: Preset>(
    state: &BeaconState<E>,
    index: ValidatorIndex,
) -> Result<Gwei, StfError> {
    let validator = state
        .validators
        .get(index as usize)
        .ok_or(StfError::UnknownValidator(index))?;
    base_reward(
        validator.effective_balance,
        get_base_reward_per_increment(state)?,
    )
}

/// `is_builder_index` (G L1047-1048, New in Gloas): whether `validator_index` carries
/// `BUILDER_INDEX_FLAG`, so that it names a builder.
pub fn is_builder_index(validator_index: ValidatorIndex) -> bool {
    validator_index & BUILDER_INDEX_FLAG != 0
}

/// `convert_builder_index_to_validator_index` (G L1141-1142, New in Gloas).
pub fn convert_builder_index_to_validator_index(builder_index: BuilderIndex) -> ValidatorIndex {
    builder_index | BUILDER_INDEX_FLAG
}

/// `convert_validator_index_to_builder_index` (G L1148-1149, New in Gloas).
pub fn convert_validator_index_to_builder_index(validator_index: ValidatorIndex) -> BuilderIndex {
    validator_index & !BUILDER_INDEX_FLAG
}

/// `is_builder_withdrawal_credential` (G L1070-1071, New in Gloas).
pub fn is_builder_withdrawal_credential(withdrawal_credentials: &Bytes32) -> bool {
    withdrawal_credentials[0] == BUILDER_WITHDRAWAL_PREFIX
}

/// `is_active_builder` (G L1054-1064, New in Gloas): the deposit epoch of the builder is
/// before the finalized epoch, and the builder did not initiate an exit.
pub fn is_active_builder<E: Preset>(
    state: &BeaconState<E>,
    builder_index: BuilderIndex,
) -> Result<bool, StfError> {
    let builder = state
        .builders
        .get(builder_index as usize)
        .ok_or(StfError::UnknownBuilder(builder_index))?;
    Ok(
        // Placement in builder list is finalized
        builder.deposit_epoch < state.finalized_checkpoint.epoch
            // Has not initiated exit
            && builder.withdrawable_epoch == FAR_FUTURE_EPOCH,
    )
}

/// `get_pending_balance_to_withdraw_for_builder` (G L1168-1178, New in Gloas): the sum of the
/// pending withdrawals and the pending payments of the builder. The sum is checked.
///
/// It reads both queues. `builder_pending_payments` has `2 * SLOTS_PER_EPOCH` entries, and
/// `builder_pending_withdrawals` holds only the withdrawals that the sweep did not pay yet.
pub fn get_pending_balance_to_withdraw_for_builder<E: Preset>(
    state: &BeaconState<E>,
    builder_index: BuilderIndex,
) -> Result<Gwei, StfError> {
    let withdrawals = state
        .builder_pending_withdrawals
        .iter()
        .filter(|withdrawal| withdrawal.builder_index == builder_index)
        .map(|withdrawal| withdrawal.amount);
    let payments = state
        .builder_pending_payments
        .iter()
        .filter(|payment| payment.withdrawal.builder_index == builder_index)
        .map(|payment| payment.withdrawal.amount);
    withdrawals
        .chain(payments)
        .try_fold(0u64, |balance, amount| balance.checked_add(amount))
        .ok_or(StfError::ArithmeticOverflow)
}

/// `can_builder_cover_bid` (G L1184-1192, New in Gloas): the balance of the builder, less
/// `MIN_DEPOSIT_AMOUNT` and its pending withdrawals and payments, is at least `bid_amount`.
pub fn can_builder_cover_bid<E: Preset>(
    state: &BeaconState<E>,
    builder_index: BuilderIndex,
    bid_amount: Gwei,
) -> Result<bool, StfError> {
    let builder_balance = state
        .builders
        .get(builder_index as usize)
        .ok_or(StfError::UnknownBuilder(builder_index))?
        .balance;
    let pending_withdrawals_amount =
        get_pending_balance_to_withdraw_for_builder(state, builder_index)?;
    let min_balance = MIN_DEPOSIT_AMOUNT
        .checked_add(pending_withdrawals_amount)
        .ok_or(StfError::ArithmeticOverflow)?;
    if builder_balance < min_balance {
        return Ok(false);
    }
    Ok(builder_balance - min_balance >= bid_amount)
}

/// The key version of the builder at `builder_index`: the `version` of its
/// [`SignerRef::Builder`](crate::SignerRef::Builder). It is the first 8 bytes of
/// `sha256(state.builders[builder_index].pubkey)`, little-endian. Not in the spec.
///
/// The value comes from `state` only, so the pure transition needs no other input. A
/// verifier that caches builder keys uses `(index, version)` as the cache key.
///
/// The beta.4 `Builder` container (G L660-666) has no field that tells two builders at a
/// reused index apart on every branch:
///
/// - `Builder.version` is `PAYLOAD_BUILDER_VERSION` for each builder that
///   `add_builder_to_registry` writes, so it does not change with an index reuse.
/// - `deposit_epoch` changes with an index reuse, but two branches before finality can each
///   reuse an index in the same epoch with different keys.
///
/// Thus the key version follows the key. It changes when a new key takes the index, on
/// any branch, and it stays the same while the key stays the same. The other fields of the
/// builder (balance, exit, `Builder.version`) do not change it. Two keys give the same
/// version only for a 64-bit collision of sha256. A verifier that must exclude that case
/// compares its cached key with `state.builders[index].pubkey`.
pub fn builder_key_version<E: Preset>(
    state: &BeaconState<E>,
    builder_index: BuilderIndex,
) -> Result<u64, StfError> {
    let builder = state
        .builders
        .get(builder_index as usize)
        .ok_or(StfError::UnknownBuilder(builder_index))?;
    let digest = hash(&[&builder.pubkey]);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    Ok(bytes_to_uint64(&prefix))
}

/// `has_eth1_withdrawal_credential` (C L313-317): the 0x01 prefix.
pub fn has_eth1_withdrawal_credential(validator: &Validator) -> bool {
    validator.withdrawal_credentials[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
}

/// `is_compounding_withdrawal_credential` (E L644-645, New in Electra): the 0x02 prefix.
pub fn is_compounding_withdrawal_credential(withdrawal_credentials: &Bytes32) -> bool {
    withdrawal_credentials[0] == COMPOUNDING_WITHDRAWAL_PREFIX
}

/// `has_compounding_withdrawal_credential` (E L651-655, New in Electra).
pub fn has_compounding_withdrawal_credential(validator: &Validator) -> bool {
    is_compounding_withdrawal_credential(&validator.withdrawal_credentials)
}

/// `has_execution_withdrawal_credential` (E L661-668, New in Electra): the 0x01 or the 0x02
/// prefix.
pub fn has_execution_withdrawal_credential(validator: &Validator) -> bool {
    has_eth1_withdrawal_credential(validator) || has_compounding_withdrawal_credential(validator)
}

/// `get_pending_balance_to_withdraw` (E L788-793, New in Electra): the sum of the pending
/// partial withdrawals of the validator. The sum is checked.
///
/// It reads the whole queue, which holds only the withdrawals that the sweep did not pay yet.
/// Each amount comes from our own state, and a state that the transition makes keeps the
/// sum in range. Thus an overflow is [`StfError::StateArithmetic`], not a proof.
pub fn get_pending_balance_to_withdraw<E: Preset>(
    state: &BeaconState<E>,
    validator_index: ValidatorIndex,
) -> Result<Gwei, StfError> {
    state
        .pending_partial_withdrawals
        .iter()
        .filter(|withdrawal| withdrawal.validator_index == validator_index)
        .try_fold(0u64, |balance, withdrawal| {
            balance.checked_add(withdrawal.amount)
        })
        .ok_or(StfError::StateArithmetic {
            what: "pending balance to withdraw",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{genesis_state, registry_state};
    use consensus_types::common::{AttestationData, Checkpoint, PendingPartialWithdrawal};
    use consensus_types::gloas::{Builder, BuilderPendingWithdrawal};
    use consensus_types::primitives::{Address, FAR_FUTURE_EPOCH};
    use consensus_types::signing::DOMAIN_BEACON_PROPOSER;
    use consensus_types::{EthSpec, Mainnet, Minimal};
    use proptest::prelude::*;
    use ssz::ProgressiveBitList;

    const ETH: u64 = 1_000_000_000;

    #[test]
    fn hash_of_parts_is_the_hash_of_their_concatenation() {
        let (a, b) = ([1u8; 40], [2u8; 70]);
        let joined = [&a[..], &b[..]].concat();
        assert_eq!(hash(&[&a, &b]), ethereum_hashing::hash_fixed(&joined));
        assert_eq!(hash(&[]), ethereum_hashing::hash_fixed(&[]));
    }

    #[test]
    fn seed_is_the_hash_of_domain_epoch_and_mix() {
        let state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        // sha256([1, 0, 0, 0] + uint_to_bytes(3) + [0x5a] * 32), from Python's hashlib.
        let want = "77d37fc269e9b71760b6c61449680b30e8de2a34dcc725b553fb05c5cfd00ed8";
        let got = get_seed(&state, 3, DOMAIN_BEACON_ATTESTER).unwrap();
        assert_eq!(format!("{got:x}"), want);
        assert_eq!(
            get_seed(&state, u64::MAX, DOMAIN_BEACON_ATTESTER),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn committee_count_is_clamped() {
        // Minimal: SLOTS_PER_EPOCH 8, TARGET_COMMITTEE_SIZE 4, MAX_COMMITTEES_PER_SLOT 4.
        assert_eq!(committee_count_per_slot::<Minimal>(0), 1);
        assert_eq!(committee_count_per_slot::<Minimal>(64), 2);
        assert_eq!(committee_count_per_slot::<Minimal>(10_000), 4);
        // Mainnet: 32 * 128 validators per committee, at most 64 committees.
        assert_eq!(committee_count_per_slot::<Mainnet>(32 * 128 * 3), 3);
        assert_eq!(committee_count_per_slot::<Mainnet>(1_664_885), 64);
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        assert_eq!(get_committee_count_per_slot(&state, 0), 2);
        state.validators.get_mut(0).unwrap().exit_epoch = 0;
        assert_eq!(get_committee_count_per_slot(&state, 0), 1);
        assert_eq!(get_active_validator_indices(&state, 0).len(), 63);
    }

    #[test]
    fn domain_takes_the_version_of_the_epoch() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        state.fork.previous_version = [1, 2, 3, 4];
        state.fork.epoch = 2;
        let gvr = state.genesis_validators_root;
        let prev = compute_domain(DOMAIN_BEACON_PROPOSER, [1, 2, 3, 4], gvr);
        let cur = compute_domain(DOMAIN_BEACON_PROPOSER, state.fork.current_version, gvr);
        assert_eq!(get_domain(&state, DOMAIN_BEACON_PROPOSER, Some(1)), prev);
        assert_eq!(get_domain(&state, DOMAIN_BEACON_PROPOSER, Some(2)), cur);
        // `None` is the current epoch, 0 here.
        assert_eq!(get_domain(&state, DOMAIN_BEACON_PROPOSER, None), prev);
    }

    #[test]
    fn weighted_selection_edges() {
        let state = genesis_state::<Minimal>(&[2048 * ETH; 8]);
        let seed = Bytes32::repeat_byte(7);
        assert_eq!(
            compute_balance_weighted_selection(&state, &[], &seed, 1, true),
            Err(StfError::NoCandidates)
        );
        // The candidates come from our own registry, so an index past it is not a proof.
        let err = compute_balance_weighted_selection(&state, &[0, 8], &seed, 1, false).unwrap_err();
        assert_eq!(
            err,
            StfError::ListIndexOutOfRange {
                list: "validators",
                index: 8
            }
        );
        assert!(!err.proves_invalid());
        // At the maximum effective balance every draw is taken, so the walk is in order.
        assert_eq!(
            compute_balance_weighted_selection(&state, &[2, 0, 1], &seed, 5, false),
            Ok(vec![2, 0, 1, 2, 0])
        );
        let mut huge = state.clone();
        huge.validators.get_mut(0).unwrap().effective_balance = u64::MAX;
        assert_eq!(
            compute_balance_weighted_selection(&huge, &[0], &seed, 1, false),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn next_sync_committee_has_sync_committee_size_active_members() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 40]);
        // Validator 5 exits before the next epoch.
        state.validators.get_mut(5).unwrap().exit_epoch = 1;
        let indices = get_next_sync_committee_indices(&state).unwrap();
        assert_eq!(
            indices.len() as u64,
            <Minimal as EthSpec>::SyncCommitteeSize::to_u64()
        );
        assert!(indices.iter().all(|&i| i < 40 && i != 5), "{indices:?}");
    }

    #[test]
    fn attesting_indices_follow_committee_bits_and_offsets() {
        // 64 validators: 2 committees per slot of 4 members each in the minimal preset.
        let state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        let cache = CommitteeCache::new(&state, 0).unwrap();
        let (c0, c1) = (
            cache.committee(3, 0).unwrap(),
            cache.committee(3, 1).unwrap(),
        );
        let mut committee_bits = BitVector::new();
        committee_bits.set(0, true).unwrap();
        committee_bits.set(1, true).unwrap();
        let mut bits = ProgressiveBitList::with_capacity(c0.len() + c1.len());
        bits.set(1, true).unwrap();
        bits.set(c0.len(), true).unwrap();
        let checkpoint = Checkpoint {
            epoch: 0,
            root: Root::ZERO,
        };
        let mut attestation = Attestation::<Minimal> {
            aggregation_bits: bits,
            data: AttestationData {
                slot: 3,
                index: 0,
                beacon_block_root: Root::ZERO,
                source: checkpoint.clone(),
                target: checkpoint,
            },
            signature: [0; 96],
            committee_bits,
        };
        assert_eq!(
            get_committee_indices(&attestation.committee_bits),
            vec![0, 1]
        );
        let got = get_attesting_indices(&state, &attestation).unwrap();
        assert_eq!(got, BTreeSet::from([c0[1], c1[0]]));
        // The cached variant gives the same set, and refuses a cache of another epoch.
        assert_eq!(
            get_attesting_indices_with(&state, &cache, &attestation),
            Ok(got)
        );
        let next = CommitteeCache::new(&state, 1).unwrap();
        assert_eq!(
            get_attesting_indices_with(&state, &next, &attestation),
            Err(StfError::CacheEpochMismatch {
                cache_epoch: 1,
                epoch: 0
            })
        );

        // A cache of the right epoch with another seed is a caller error, not a proof.
        let mut other = state.clone();
        other.randao_mixes = milhouse::Vector::from_elem(Root::repeat_byte(0xa5)).unwrap();
        let wrong = get_attesting_indices_with(&other, &cache, &attestation).unwrap_err();
        assert_eq!(
            wrong,
            StfError::CacheSeedMismatch {
                epoch: 0,
                cache_seed: cache.key().1,
                state_seed: attester_seed(&other, 0).unwrap(),
            }
        );
        assert!(!wrong.proves_invalid());

        // Bits shorter than the committees they cover are out of range.
        attestation.aggregation_bits = ProgressiveBitList::with_capacity(c0.len());
        assert!(matches!(
            get_attesting_indices(&state, &attestation),
            Err(StfError::BitOutOfRange { .. })
        ));
    }

    #[test]
    fn activation_exit_epoch_is_checked() {
        assert_eq!(compute_activation_exit_epoch(3), Ok(8));
        assert_eq!(compute_activation_exit_epoch(u64::MAX - 5), Ok(u64::MAX));
        assert_eq!(
            compute_activation_exit_epoch(u64::MAX - 4),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn total_active_balance_counts_active_validators_only() {
        let balances = [32 * ETH, 31 * ETH, 2048 * ETH, 1];
        let mut state = registry_state::<Minimal>(&balances, Bytes32::ZERO);
        assert_eq!(get_total_active_balance(&state), Ok(2111 * ETH + 1));
        // Exited and not yet active validators do not count. Slashed active validators count.
        state.validators.get_mut(2).unwrap().exit_epoch = 0;
        state.validators.get_mut(3).unwrap().activation_epoch = 1;
        state.validators.get_mut(1).unwrap().slashed = true;
        assert_eq!(get_total_active_balance(&state), Ok(63 * ETH));
        // The total is at least EFFECTIVE_BALANCE_INCREMENT.
        let empty = registry_state::<Minimal>(&[], Bytes32::ZERO);
        assert_eq!(get_total_active_balance(&empty), Ok(ETH));
        let mut huge = registry_state::<Minimal>(&[32 * ETH; 2], Bytes32::ZERO);
        huge.validators.get_mut(0).unwrap().effective_balance = u64::MAX;
        assert_eq!(
            get_total_active_balance(&huge),
            Err(StfError::ArithmeticOverflow)
        );
        assert_eq!(
            TotalActiveBalanceCache::default().get(&huge),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn total_active_balance_is_read_once_per_key() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        let mut cache = TotalActiveBalanceCache::default();
        assert_eq!(cache.key(), None);
        assert_eq!(cache.get(&state), Ok(256 * ETH));
        assert_eq!(cache.key(), Some((0, state.genesis_validators_root)));
        // A second read with the same key does not read the registry again.
        state.validators.get_mut(0).unwrap().effective_balance = 0;
        assert_eq!(cache.get(&state), Ok(256 * ETH));
        // A new epoch is a new key: the block root of slot 7.
        state.slot = Minimal::start_slot_at_epoch(1);
        *state.block_roots.get_mut(7).unwrap() = Root::repeat_byte(7);
        assert_eq!(cache.get(&state), Ok(224 * ETH));
        assert_eq!(cache.key(), Some((1, Root::repeat_byte(7))));
        // A new seed with the same decision root is the same key.
        state.randao_mixes = milhouse::Vector::from_elem(Bytes32::repeat_byte(9)).unwrap();
        assert_eq!(cache.get(&state), Ok(224 * ETH));
    }

    proptest! {
        #[test]
        fn builder_index_roundtrip(builder_index in 0..BUILDER_INDEX_FLAG, validator_index: u64) {
            // A builder index below the flag goes to a flagged validator index and back.
            let flagged = convert_builder_index_to_validator_index(builder_index);
            prop_assert!(is_builder_index(flagged));
            prop_assert_eq!(flagged, builder_index + BUILDER_INDEX_FLAG);
            prop_assert_eq!(convert_validator_index_to_builder_index(flagged), builder_index);
            // `is_builder_index` holds exactly for the indices that a conversion gives.
            let round = convert_builder_index_to_validator_index(
                convert_validator_index_to_builder_index(validator_index),
            );
            prop_assert_eq!(is_builder_index(validator_index), round == validator_index);
            prop_assert_eq!(
                is_builder_index(validator_index),
                validator_index & BUILDER_INDEX_FLAG != 0
            );
        }
    }

    #[test]
    fn builder_index_edges() {
        assert!(!is_builder_index(0));
        assert!(!is_builder_index(BUILDER_INDEX_FLAG - 1));
        assert!(is_builder_index(BUILDER_INDEX_FLAG));
        assert_eq!(
            convert_validator_index_to_builder_index(BUILDER_INDEX_FLAG),
            0
        );
        // The other bits stay: a validator index with the flag and higher bits keeps them.
        let high = (1 << 41) | BUILDER_INDEX_FLAG | 5;
        assert_eq!(
            convert_validator_index_to_builder_index(high),
            (1 << 41) | 5
        );
        // BUILDER_INDEX_SELF_BUILD (UINT64_MAX) has the flag bit, so it does not round-trip.
        assert_eq!(convert_builder_index_to_validator_index(u64::MAX), u64::MAX);
        assert_ne!(convert_validator_index_to_builder_index(u64::MAX), u64::MAX);
    }

    #[test]
    fn builder_withdrawal_credential_is_the_0xb0_prefix() {
        let mut credentials = Bytes32::repeat_byte(0x11);
        assert!(!is_builder_withdrawal_credential(&credentials));
        credentials.0[0] = 0xb0;
        assert!(is_builder_withdrawal_credential(&credentials));
        for prefix in [0x00, 0x01, 0x02, 0xb1, 0x0b] {
            credentials.0[0] = prefix;
            assert!(!is_builder_withdrawal_credential(&credentials), "{prefix}");
        }
    }

    fn builder_at(deposit_epoch: Epoch, withdrawable_epoch: Epoch) -> Builder {
        Builder {
            pubkey: [0xb0; 48],
            version: 0,
            execution_address: Address::repeat_byte(0xb1),
            balance: 5 * ETH,
            deposit_epoch,
            withdrawable_epoch,
        }
    }

    #[test]
    fn active_builder_needs_a_finalized_deposit_and_no_exit() {
        let mut state = registry_state::<Minimal>(&[32 * ETH; 4], Bytes32::ZERO);
        state.finalized_checkpoint.epoch = 3;
        for builder in [
            builder_at(2, FAR_FUTURE_EPOCH),
            builder_at(3, FAR_FUTURE_EPOCH),
            builder_at(0, 9),
        ] {
            state.builders.push(builder).unwrap();
        }
        assert_eq!(is_active_builder(&state, 0), Ok(true));
        // The deposit epoch must be before the finalized epoch.
        assert_eq!(is_active_builder(&state, 1), Ok(false));
        // An exit sets the withdrawable epoch.
        assert_eq!(is_active_builder(&state, 2), Ok(false));
        assert_eq!(
            is_active_builder(&state, 3),
            Err(StfError::UnknownBuilder(3))
        );
    }

    #[test]
    fn pending_balance_to_withdraw_for_builder_sums_both_queues() {
        let mut state = registry_state::<Minimal>(&[32 * ETH; 4], Bytes32::ZERO);
        let withdrawal = |amount, builder_index| BuilderPendingWithdrawal {
            fee_recipient: Address::repeat_byte(0xfe),
            amount,
            builder_index,
        };
        assert_eq!(
            get_pending_balance_to_withdraw_for_builder(&state, 1),
            Ok(0)
        );
        for w in [withdrawal(3, 1), withdrawal(4, 0), withdrawal(5, 1)] {
            state.builder_pending_withdrawals.push(w).unwrap();
        }
        state
            .builder_pending_payments
            .get_mut(2)
            .unwrap()
            .withdrawal = withdrawal(7, 1);
        state
            .builder_pending_payments
            .get_mut(5)
            .unwrap()
            .withdrawal = withdrawal(11, 0);
        assert_eq!(
            get_pending_balance_to_withdraw_for_builder(&state, 1),
            Ok(15)
        );
        // The empty payments name builder 0 with an amount of 0.
        assert_eq!(
            get_pending_balance_to_withdraw_for_builder(&state, 0),
            Ok(15)
        );
        assert_eq!(
            get_pending_balance_to_withdraw_for_builder(&state, 2),
            Ok(0)
        );
        // A sum past `u64::MAX` is a `Uint64` overflow.
        state
            .builder_pending_withdrawals
            .push(withdrawal(u64::MAX, 1))
            .unwrap();
        assert_eq!(
            get_pending_balance_to_withdraw_for_builder(&state, 1),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn builder_covers_a_bid_above_the_minimum_and_the_pending_amount() {
        let mut state = registry_state::<Minimal>(&[32 * ETH; 4], Bytes32::ZERO);
        state
            .builders
            .push(builder_at(0, FAR_FUTURE_EPOCH))
            .unwrap();
        // 5 ETH less MIN_DEPOSIT_AMOUNT (1 ETH) is 4 ETH free for a bid.
        assert_eq!(can_builder_cover_bid(&state, 0, 4 * ETH), Ok(true));
        assert_eq!(can_builder_cover_bid(&state, 0, 4 * ETH + 1), Ok(false));
        // A pending withdrawal or payment of the builder makes the free amount smaller.
        state
            .builder_pending_withdrawals
            .push(BuilderPendingWithdrawal {
                fee_recipient: Address::repeat_byte(0xfe),
                amount: ETH,
                builder_index: 0,
            })
            .unwrap();
        assert_eq!(can_builder_cover_bid(&state, 0, 3 * ETH), Ok(true));
        assert_eq!(can_builder_cover_bid(&state, 0, 3 * ETH + 1), Ok(false));
        // A balance under the minimum covers no bid, not even a bid of 0.
        state.builders.get_mut(0).unwrap().balance = 2 * ETH - 1;
        assert_eq!(can_builder_cover_bid(&state, 0, 0), Ok(false));
        state.builders.get_mut(0).unwrap().balance = 2 * ETH;
        assert_eq!(can_builder_cover_bid(&state, 0, 0), Ok(true));
        assert_eq!(
            can_builder_cover_bid(&state, 1, 0),
            Err(StfError::UnknownBuilder(1))
        );
        // A minimum past `u64::MAX` is a `Uint64` overflow.
        state.builder_pending_withdrawals.get_mut(0).unwrap().amount = u64::MAX;
        assert_eq!(
            can_builder_cover_bid(&state, 0, 0),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn builder_key_version_changes_with_the_key_only() {
        let mut state = registry_state::<Minimal>(&[32 * ETH; 4], Bytes32::ZERO);
        state
            .builders
            .push(builder_at(0, FAR_FUTURE_EPOCH))
            .unwrap();
        // The first 8 bytes of sha256([0xb0] * 48), little-endian, from Python's hashlib.
        // The digest starts with 1a163e8f938e9314.
        let version = builder_key_version(&state, 0).unwrap();
        assert_eq!(version, 0x1493_8e93_8f3e_161a);
        // The other fields of the builder do not change the version.
        let builder = state.builders.get_mut(0).unwrap();
        builder.balance = 0;
        builder.deposit_epoch = 7;
        builder.withdrawable_epoch = 9;
        builder.version = 1;
        assert_eq!(builder_key_version(&state, 0), Ok(version));
        // Another key at the same index gives another version.
        state.builders.get_mut(0).unwrap().pubkey = [0xb1; 48];
        assert_ne!(builder_key_version(&state, 0), Ok(version));
        assert_eq!(
            builder_key_version(&state, 1),
            Err(StfError::UnknownBuilder(1))
        );
    }

    #[test]
    fn total_active_balance_cache_tells_branches_apart() {
        // Two branches that fork in epoch 1: in epoch 2 they have the same epoch and the same
        // attester seed (from the mix of epoch 0), but the effective balances of the end of
        // epoch 1 differ, and so does the last block root of epoch 1.
        let mut a = genesis_state::<Minimal>(&[32 * ETH; 8]);
        a.slot = Minimal::start_slot_at_epoch(2) + 3;
        *a.block_roots.get_mut(15).unwrap() = Root::repeat_byte(0xa1);
        let mut b = a.clone();
        b.validators.get_mut(0).unwrap().effective_balance = 31 * ETH;
        *b.block_roots.get_mut(15).unwrap() = Root::repeat_byte(0xb1);
        assert_eq!(attester_seed(&a, 2), attester_seed(&b, 2));
        let mut cache = TotalActiveBalanceCache::default();
        assert_eq!(cache.get(&a), Ok(256 * ETH));
        assert_eq!(cache.key(), Some((2, Root::repeat_byte(0xa1))));
        assert_eq!(cache.get(&b), Ok(255 * ETH));
        assert_eq!(cache.key(), Some((2, Root::repeat_byte(0xb1))));
        assert_eq!(cache.get(&a), Ok(256 * ETH));

        // In epoch 0 the key is the genesis validators root, the root of the genesis
        // registry: two genesis registries are two keys.
        let x = genesis_state::<Minimal>(&[32 * ETH; 8]);
        let mut y = genesis_state::<Minimal>(&[31 * ETH; 8]);
        y.genesis_validators_root = Root::repeat_byte(0x43);
        assert_eq!(cache.get(&x), Ok(256 * ETH));
        assert_eq!(cache.key(), Some((0, x.genesis_validators_root)));
        assert_eq!(cache.get(&y), Ok(248 * ETH));
    }

    #[test]
    fn flags_and_square_roots() {
        use crate::preset::{PARTICIPATION_FLAG_WEIGHTS, TIMELY_TARGET_FLAG_INDEX};
        assert_eq!(has_flag(0b010, TIMELY_TARGET_FLAG_INDEX), Ok(true));
        assert_eq!(has_flag(0b101, TIMELY_TARGET_FLAG_INDEX), Ok(false));
        assert_eq!(has_flag(0x80, 7), Ok(true));
        // `ParticipationFlags(2**8)` raises in the spec.
        let past = has_flag(0xff, 8).unwrap_err();
        assert_eq!(
            past,
            StfError::ListIndexOutOfRange {
                list: "ParticipationFlags",
                index: 8
            }
        );
        assert!(!past.proves_invalid());
        assert_eq!(integer_squareroot(0), 0);
        assert_eq!(integer_squareroot(15), 3);
        assert_eq!(integer_squareroot(16), 4);
        assert_eq!(integer_squareroot(u64::MAX), (1 << 32) - 1);
        assert_eq!(PARTICIPATION_FLAG_WEIGHTS.iter().sum::<u64>(), 54);
    }

    #[test]
    fn block_roots_inside_the_history_only() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        state.slot = Minimal::start_slot_at_epoch(10) - 1;
        for i in 0..state.block_roots.len() {
            *state.block_roots.get_mut(i).unwrap() = Root::repeat_byte(i as u8);
        }
        // Slot 79 of the minimal preset; the history holds slots 15 to 78.
        assert_eq!(state.slot, 79);
        assert_eq!(get_previous_epoch(&state), 8);
        assert_eq!(
            get_block_root_at_slot(&state, 78),
            Ok(Root::repeat_byte(14))
        );
        assert_eq!(
            get_block_root_at_slot(&state, 15),
            Ok(Root::repeat_byte(15))
        );
        assert_eq!(get_block_root(&state, 9), Ok(Root::repeat_byte(72 % 64)));
        for slot in [14, 79, 80] {
            assert_eq!(
                get_block_root_at_slot(&state, slot),
                Err(StfError::BlockRootOutOfRange {
                    slot,
                    state_slot: 79
                })
            );
        }
        assert_eq!(
            get_block_root(&state, u64::MAX),
            Err(StfError::ArithmeticOverflow)
        );
        // The spec computes `slot + SLOTS_PER_HISTORICAL_ROOT` in uint64, which raises near
        // the top of the range, also where `state.slot - slot` is small.
        state.slot = u64::MAX;
        assert_eq!(
            get_block_root_at_slot(&state, u64::MAX - 1),
            Err(StfError::ArithmeticOverflow)
        );
        assert_eq!(
            get_block_root_at_slot(&state, u64::MAX - 64),
            Ok(Root::repeat_byte(((u64::MAX - 64) % 64) as u8))
        );
    }

    #[test]
    fn base_reward_of_the_total_active_balance() {
        let state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        // 64 * 10**9 // isqrt(256 * 10**9) = 64 * 10**9 // 505_964.
        assert_eq!(get_base_reward_per_increment(&state), Ok(126_491));
        assert_eq!(base_reward_per_increment(ETH), 64 * ETH / 31_622);
        assert_eq!(base_reward_per_increment(0), 0);
        assert_eq!(get_base_reward(&state, 3), Ok(32 * 126_491));
        assert_eq!(
            get_base_reward(&state, 8),
            Err(StfError::UnknownValidator(8))
        );
        assert_eq!(
            base_reward(2 * ETH, u64::MAX),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn withdrawal_credential_predicates() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        let with_prefix = |prefix: u8| {
            let mut validator = state.validators.get(0).unwrap().clone();
            validator.withdrawal_credentials[0] = prefix;
            validator
        };
        // (prefix, eth1, compounding, execution)
        for (prefix, eth1, compounding, execution) in [
            (0x00, false, false, false),
            (0x01, true, false, true),
            (0x02, false, true, true),
            (0x03, false, false, false),
            (0xb0, false, false, false),
        ] {
            let validator = with_prefix(prefix);
            assert_eq!(has_eth1_withdrawal_credential(&validator), eth1, "{prefix}");
            assert_eq!(
                has_compounding_withdrawal_credential(&validator),
                compounding,
                "{prefix}"
            );
            assert_eq!(
                has_execution_withdrawal_credential(&validator),
                execution,
                "{prefix}"
            );
        }

        // The pending partial withdrawals of validator 1 only, summed and checked.
        assert_eq!(get_pending_balance_to_withdraw(&state, 1), Ok(0));
        for (validator_index, amount) in [(1, 3), (2, 100), (1, 4)] {
            state
                .pending_partial_withdrawals
                .push(PendingPartialWithdrawal {
                    validator_index,
                    amount,
                    withdrawable_epoch: 0,
                })
                .unwrap();
        }
        assert_eq!(get_pending_balance_to_withdraw(&state, 1), Ok(7));
        assert_eq!(get_pending_balance_to_withdraw(&state, 3), Ok(0));
        state
            .pending_partial_withdrawals
            .push(PendingPartialWithdrawal {
                validator_index: 1,
                amount: u64::MAX,
                withdrawable_epoch: 0,
            })
            .unwrap();
        assert_eq!(
            get_pending_balance_to_withdraw(&state, 1),
            Err(StfError::StateArithmetic {
                what: "pending balance to withdraw"
            })
        );
    }
}
