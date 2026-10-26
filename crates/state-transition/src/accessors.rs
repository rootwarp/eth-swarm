//! Beacon-state accessors and the misc helpers they share.

use crate::caches::committee::{compute_shuffled_index, CommitteeCache};
use crate::preset::{MAX_EFFECTIVE_BALANCE_ELECTRA, MIN_SEED_LOOKAHEAD};
use crate::{Preset, StfError};
use consensus_types::common::Validator;
use consensus_types::gloas::{Attestation, BeaconState};
use consensus_types::primitives::{
    Bytes32, CommitteeIndex, Domain, DomainType, Epoch, ValidatorIndex,
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
/// the attestation's epoch on each call; [`get_attesting_indices_with`] reuses a cache.
pub fn get_attesting_indices<E: Preset>(
    state: &BeaconState<E>,
    attestation: &Attestation<E>,
) -> Result<BTreeSet<ValidatorIndex>, StfError> {
    let cache = CommitteeCache::new(state, E::epoch_at_slot(attestation.data.slot))?;
    get_attesting_indices_with(&cache, attestation)
}

/// [`get_attesting_indices`] over the committees of `cache`, which must be the cache of the
/// attestation slot's epoch (else `Err(CacheEpochMismatch)`).
pub fn get_attesting_indices_with<E: Preset>(
    cache: &CommitteeCache,
    attestation: &Attestation<E>,
) -> Result<BTreeSet<ValidatorIndex>, StfError> {
    let slot = attestation.data.slot;
    cache.check_slot(slot)?;
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
                .ok_or(StfError::UnknownValidator(index))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::genesis_state;
    use consensus_types::common::{AttestationData, Checkpoint};
    use consensus_types::primitives::Root;
    use consensus_types::signing::DOMAIN_BEACON_PROPOSER;
    use consensus_types::{EthSpec, Mainnet, Minimal};
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
        assert_eq!(
            compute_balance_weighted_selection(&state, &[0, 8], &seed, 1, false),
            Err(StfError::UnknownValidator(8))
        );
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
        assert_eq!(get_attesting_indices_with(&cache, &attestation), Ok(got));
        let next = CommitteeCache::new(&state, 1).unwrap();
        assert_eq!(
            get_attesting_indices_with(&next, &attestation),
            Err(StfError::CacheEpochMismatch {
                cache_epoch: 1,
                epoch: 0
            })
        );

        // Bits shorter than the committees they cover are out of range.
        attestation.aggregation_bits = ProgressiveBitList::with_capacity(c0.len());
        assert!(matches!(
            get_attesting_indices(&state, &attestation),
            Err(StfError::BitOutOfRange { .. })
        ));
    }
}
