//! Swap-or-not shuffling and the beacon committees.

use crate::accessors::{
    attester_seed, bytes_to_uint64, committee_count_per_slot, get_active_validator_indices, hash,
};
use crate::{Preset, StfError};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Bytes32, CommitteeIndex, Epoch, Slot, ValidatorIndex};

/// `compute_shuffled_index` (P0 L1240-1245), as the per-index swap-or-not loop. The spec
/// text at the pin defines it through `compute_shuffled_permutation`; both give the same
/// value, and this one is the reference oracle of [`compute_shuffled_permutation`].
pub fn compute_shuffled_index(
    index: u64,
    index_count: u64,
    seed: &[u8; 32],
    rounds: u8,
) -> Result<u64, StfError> {
    if index >= index_count {
        return Err(StfError::ShuffleIndexOutOfRange { index, index_count });
    }
    let mut index = index;
    for current_round in 0..rounds {
        let round = [current_round];
        let pivot = pivot(seed, &round, index_count);
        let flip = (pivot + index_count - index) % index_count;
        let position = index.max(flip);
        let source = hash(&[seed, &round, &((position / 256) as u32).to_le_bytes()]);
        if bit_at(&source, position) {
            index = flip;
        }
    }
    Ok(index)
}

/// `bytes_to_uint64(hash(seed + uint_to_bytes(uint8(round)))[0:8]) % index_count`.
fn pivot(seed: &[u8; 32], round: &[u8; 1], index_count: u64) -> u64 {
    let digest = hash(&[seed, round]);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    bytes_to_uint64(&first) % index_count
}

/// `(source[(position % 256) // 8] >> (position % 8)) % 2 == 1`.
fn bit_at(source: &[u8; 32], position: u64) -> bool {
    let byte = source[((position % 256) / 8) as usize];
    (byte >> (position % 8)) & 1 == 1
}

/// `compute_shuffled_permutation` (P0 L1211-1234), the whole list at once: `result[i] ==
/// compute_shuffled_index(i, index_count, seed)` for every `i`.
pub fn compute_shuffled_permutation(index_count: u64, seed: &[u8; 32], rounds: u8) -> Vec<u64> {
    // The spec's pivot is `% index_count`, which raises on zero; the shuffling vectors (and
    // `[compute_shuffled_index(i) for i in range(0)]`) give the empty list.
    if index_count == 0 {
        return Vec::new();
    }
    let mut indices: Vec<u64> = (0..index_count).collect();
    let buckets = index_count.div_ceil(256);
    for current_round in 0..rounds {
        let round = [current_round];
        let pivot = pivot(seed, &round, index_count);
        // Every bucket a position can fall in, hashed once per round (the spec memoizes the
        // same values in `source_by_bucket`).
        let sources: Vec<[u8; 32]> = (0..buckets)
            .map(|bucket| hash(&[seed, &round, &(bucket as u32).to_le_bytes()]))
            .collect();
        for index in &mut indices {
            let flip = (pivot + index_count - *index) % index_count;
            let position = (*index).max(flip);
            if bit_at(&sources[(position / 256) as usize], position) {
                *index = flip;
            }
        }
    }
    indices
}

/// The range `[start, end)` of committee `index` out of `count` over `len` validators
/// (`compute_committee`, P0 L1273-1284), or `None` if it holds an index past `len`, where the
/// spec's `compute_shuffled_index` assert fails. An empty range is never an error, as in the
/// spec, also when it starts past `len`: it is then `[len, len)`, so that it slices safely.
fn committee_range(len: u64, index: u64, count: u64) -> Option<(usize, usize)> {
    let (len, index, count) = (u128::from(len), u128::from(index), u128::from(count));
    let start = len * index / count;
    let end = len * (index + 1) / count;
    if start == end {
        let empty = start.min(len) as usize;
        return Some((empty, empty));
    }
    (end <= len).then_some((start as usize, end as usize))
}

/// `compute_committee` (P0 L1273-1284), per index through `compute_shuffled_index`: the
/// reference oracle of [`CommitteeCache::committee`].
pub fn compute_committee(
    indices: &[ValidatorIndex],
    seed: &[u8; 32],
    index: u64,
    count: u64,
    rounds: u8,
) -> Result<Vec<ValidatorIndex>, StfError> {
    let len = indices.len() as u64;
    let (start, end) =
        committee_range(len, index, count).ok_or(StfError::UnknownCommittee { slot: 0, index })?;
    (start as u64..end as u64)
        .map(|i| Ok(indices[compute_shuffled_index(i, len, seed, rounds)? as usize]))
        .collect()
}

/// The beacon committees of one epoch: the active validators shuffled once by the epoch's
/// attester seed, which fixes them for that `(epoch, seed)`.
///
/// Committee `k` of the epoch is the slice `[len * k / count, len * (k + 1) / count)` of the
/// shuffled list, so every committee is a slice instead of a new shuffle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeCache {
    epoch: Epoch,
    seed: Bytes32,
    slots_per_epoch: u64,
    committees_per_slot: u64,
    /// `indices[compute_shuffled_index(k)]` for each position `k` of the active set.
    shuffling: Vec<ValidatorIndex>,
}

impl CommitteeCache {
    /// Shuffles the active validators of `epoch` with
    /// `get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)`.
    pub fn new<E: Preset>(state: &BeaconState<E>, epoch: Epoch) -> Result<Self, StfError> {
        let indices = get_active_validator_indices(state, epoch);
        let seed = attester_seed(state, epoch)?;
        let len = indices.len() as u64;
        let shuffling = compute_shuffled_permutation(len, seed.as_ref(), E::SHUFFLE_ROUND_COUNT)
            .into_iter()
            .map(|k| indices[k as usize])
            .collect();
        Ok(Self {
            epoch,
            seed,
            slots_per_epoch: E::slots_per_epoch(),
            committees_per_slot: committee_count_per_slot::<E>(len),
            shuffling,
        })
    }

    /// The `(epoch, seed)` the committees belong to.
    pub fn key(&self) -> (Epoch, Bytes32) {
        (self.epoch, self.seed)
    }

    /// `Err(CacheEpochMismatch)` unless `slot` is in the epoch of the cache.
    pub fn check_slot(&self, slot: Slot) -> Result<(), StfError> {
        let epoch = slot / self.slots_per_epoch;
        if epoch == self.epoch {
            Ok(())
        } else {
            Err(StfError::CacheEpochMismatch {
                cache_epoch: self.epoch,
                epoch,
            })
        }
    }

    /// `get_committee_count_per_slot` of the epoch.
    pub fn committees_per_slot(&self) -> u64 {
        self.committees_per_slot
    }

    /// `get_beacon_committee(state, slot, index)` (P0 L1527-1540) for a slot of this epoch,
    /// without a new shuffle. The cache must come from the same state, or from one with the
    /// same active set and seed for this epoch.
    pub fn committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<&[ValidatorIndex], StfError> {
        self.check_slot(slot)?;
        let unknown = StfError::UnknownCommittee { slot, index };
        let count = self.committees_per_slot * self.slots_per_epoch;
        let position = (slot % self.slots_per_epoch)
            .checked_mul(self.committees_per_slot)
            .and_then(|p| p.checked_add(index))
            .ok_or(StfError::ArithmeticOverflow)?;
        let (start, end) =
            committee_range(self.shuffling.len() as u64, position, count).ok_or(unknown)?;
        Ok(&self.shuffling[start..end])
    }
}

/// `get_beacon_committee` (P0 L1527-1540). It shuffles the whole epoch on each call, so it
/// is for single reads only: to read several committees of one epoch, build one
/// [`CommitteeCache`] and call [`CommitteeCache::committee`], which this function delegates to.
pub fn get_beacon_committee<E: Preset>(
    state: &BeaconState<E>,
    slot: Slot,
    index: CommitteeIndex,
) -> Result<Vec<ValidatorIndex>, StfError> {
    let cache = CommitteeCache::new(state, E::epoch_at_slot(slot))?;
    Ok(cache.committee(slot, index)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [
        0x23, 0xbc, 0xd1, 0x16, 0x24, 0xa0, 0x74, 0x65, 0xb1, 0xc2, 0xfc, 0x1a, 0x0f, 0xe5, 0x29,
        0x96, 0xda, 0xae, 0x4b, 0xf8, 0x7b, 0x0f, 0xb6, 0xbe, 0xd4, 0x59, 0x26, 0x09, 0x6c, 0x64,
        0x48, 0x43,
    ];

    /// `minimal/phase0/shuffling/core/shuffle/shuffle_0x23bc…_10` (10 rounds).
    const MAPPING_10: [u64; 10] = [6, 9, 2, 7, 8, 3, 0, 1, 4, 5];

    #[test]
    fn index_matches_the_vector() {
        for (i, want) in MAPPING_10.iter().enumerate() {
            assert_eq!(compute_shuffled_index(i as u64, 10, &SEED, 10), Ok(*want));
        }
    }

    #[test]
    fn permutation_matches_the_vector_and_the_index_oracle() {
        assert_eq!(compute_shuffled_permutation(10, &SEED, 10), MAPPING_10);
        for count in [0u64, 1, 2, 3, 255, 256, 257, 1000] {
            let perm = compute_shuffled_permutation(count, &SEED, 10);
            let oracle: Vec<u64> = (0..count)
                .map(|i| compute_shuffled_index(i, count, &SEED, 10).unwrap())
                .collect();
            assert_eq!(perm, oracle, "count {count}");
        }
    }

    #[test]
    fn index_past_the_count_is_an_error() {
        assert!(compute_shuffled_index(10, 10, &SEED, 10).is_err());
        assert!(compute_shuffled_index(0, 0, &SEED, 10).is_err());
    }

    #[test]
    fn cache_committees_equal_the_per_index_oracle() {
        use crate::accessors::{attester_seed, get_active_validator_indices};
        use crate::testing::genesis_state;
        use consensus_types::{EthSpec, Minimal};

        // 70 active validators: 2 committees per slot of 4 or 5 members.
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 72]);
        state.validators.get_mut(10).unwrap().exit_epoch = 1;
        state.validators.get_mut(11).unwrap().activation_epoch = 2;
        for epoch in [0u64, 1, 2] {
            let cache = CommitteeCache::new(&state, epoch).unwrap();
            let indices = get_active_validator_indices(&state, epoch);
            let seed = attester_seed(&state, epoch).unwrap();
            assert_eq!(cache.key(), (epoch, seed));
            let cps = cache.committees_per_slot();
            assert_eq!(cps, 2);
            let count = cps * Minimal::slots_per_epoch();
            let mut seen = Vec::new();
            for slot in Minimal::start_slot_at_epoch(epoch)..Minimal::start_slot_at_epoch(epoch + 1)
            {
                for index in 0..cps {
                    let position = (slot % Minimal::slots_per_epoch()) * cps + index;
                    let want =
                        compute_committee(&indices, seed.as_ref(), position, count, 10).unwrap();
                    assert_eq!(cache.committee(slot, index).unwrap(), want.as_slice());
                    assert_eq!(get_beacon_committee(&state, slot, index).unwrap(), want);
                    seen.extend(want);
                }
            }
            // The committees of an epoch partition its active set.
            seen.sort_unstable();
            assert_eq!(seen, indices, "epoch {epoch}");
        }
        let cache = CommitteeCache::new(&state, 0).unwrap();
        // A position past the epoch's last committee does not exist.
        assert_eq!(
            cache.committee(7, 2),
            Err(StfError::UnknownCommittee { slot: 7, index: 2 })
        );
        // A slot of another epoch is a caller error, not an invalid input.
        let wrong = cache.committee(8, 0).unwrap_err();
        assert_eq!(
            wrong,
            StfError::CacheEpochMismatch {
                cache_epoch: 0,
                epoch: 1
            }
        );
        assert!(!wrong.proves_invalid());
        assert!(compute_committee(&[1, 2, 3], &SEED, 4, 2, 10).is_err());
        // An empty committee is not an error (the spec returns an empty list).
        assert_eq!(compute_committee(&[], &SEED, 0, 2, 10), Ok(vec![]));
    }

    #[test]
    fn an_empty_committee_past_the_registry_is_empty() {
        use crate::testing::registry_state;
        use consensus_types::primitives::Bytes32;
        use consensus_types::Minimal;

        // 4 active validators, 1 committee per slot: slot 7, index 3 is position 10 of 8,
        // whose range [5, 5) starts past the 4 shuffled validators. The spec returns [].
        let state = registry_state::<Minimal>(&[32_000_000_000; 4], Bytes32::repeat_byte(1));
        let cache = CommitteeCache::new(&state, 0).unwrap();
        assert_eq!(cache.committee(7, 3), Ok(&[][..]));
        assert_eq!(get_beacon_committee(&state, 7, 3), Ok(vec![]));
        let indices = [0, 1, 2, 3];
        assert_eq!(compute_committee(&indices, &SEED, 10, 8, 10), Ok(vec![]));
        // A range that holds an index past the registry is still an error.
        assert!(compute_committee(&indices, &SEED, 9, 8, 10).is_err());
        assert_eq!(
            cache.committee(7, 4),
            Err(StfError::UnknownCommittee { slot: 7, index: 4 })
        );
    }

    /// Every range `committee_range` gives slices a list of `len` safely. Mainnet has 32
    /// committee positions per slot for 1 to 31 active validators, with up to 64 indices.
    #[test]
    fn committee_ranges_always_slice_safely() {
        for len in 0..=40u64 {
            for count in [1u64, 8, 32, 2048] {
                for index in 0..count + 64 {
                    if let Some((start, end)) = committee_range(len, index, count) {
                        assert!(start <= end && end as u64 <= len, "{len} {index} {count}");
                    }
                }
            }
        }
    }
}
