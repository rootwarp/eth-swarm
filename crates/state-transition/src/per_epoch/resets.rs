//! The end-of-epoch updates after the effective balances: the eth1 votes (P0 L2268-2272),
//! the slashings slot (P0 L2297-2300), the RANDAO mix (P0 L2306-2312), the historical
//! summaries (C L379-387), the participation flags (A L826-830) and the sync committees
//! (A L838-842, with `get_next_sync_committee`, A L356-363).

use super::state_validator;
use crate::accessors::{get_current_epoch, get_next_sync_committee_indices, get_randao_mix};
use crate::preset::epochs_per_eth1_voting_period;
use crate::{Preset, PubkeyAggregator, StfError};
use consensus_types::common::{HistoricalSummary, SyncCommittee};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{BLSPubkey, Epoch};
use milhouse::{List, ProgressiveList};
use ssz_types::typenum::Unsigned;
use ssz_types::FixedVector;
use tree_hash::TreeHash;

/// `get_current_epoch(state) + 1`.
fn next_epoch<E: Preset>(state: &BeaconState<E>) -> Result<Epoch, StfError> {
    get_current_epoch(state)
        .checked_add(1)
        .ok_or(StfError::ArithmeticOverflow)
}

/// `process_eth1_data_reset` (P0 L2268-2272; Gloas keeps it).
pub fn process_eth1_data_reset<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    let next_epoch = next_epoch(state)?;
    // Reset eth1 data votes
    if next_epoch.is_multiple_of(epochs_per_eth1_voting_period::<E>()) {
        state.eth1_data_votes = List::default();
    }
    Ok(())
}

/// `process_slashings_reset` (P0 L2297-2300; Gloas keeps it).
pub fn process_slashings_reset<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    let next_epoch = next_epoch(state)?;
    let index = next_epoch % E::EpochsPerSlashingsVector::to_u64();
    // Reset slashings
    *state
        .slashings
        .get_mut(index as usize)
        .ok_or_else(|| StfError::Tree("slashings is shorter than its length".into()))? = 0;
    Ok(())
}

/// `process_randao_mixes_reset` (P0 L2306-2312; Gloas keeps it).
pub fn process_randao_mixes_reset<E: Preset>(state: &mut BeaconState<E>) -> Result<(), StfError> {
    let current_epoch = get_current_epoch(state);
    let next_epoch = next_epoch(state)?;
    let index = next_epoch % E::EpochsPerHistoricalVector::to_u64();
    // Set randao mix
    let mix = get_randao_mix(state, current_epoch);
    *state
        .randao_mixes
        .get_mut(index as usize)
        .ok_or_else(|| StfError::Tree("randao_mixes is shorter than its length".into()))? = mix;
    Ok(())
}

/// `process_historical_summaries_update` (C L379-387, New in Capella; Gloas keeps it).
pub fn process_historical_summaries_update<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    // Set historical block root accumulator.
    let next_epoch = next_epoch(state)?;
    let period = E::SlotsPerHistoricalRoot::to_u64() / E::slots_per_epoch();
    if next_epoch.is_multiple_of(period) {
        // milhouse trees panic in `tree_hash_root` while they hold pending updates.
        state.block_roots.apply_updates()?;
        state.state_roots.apply_updates()?;
        let historical_summary = HistoricalSummary {
            block_summary_root: state.block_roots.tree_hash_root(),
            state_summary_root: state.state_roots.tree_hash_root(),
        };
        // `HISTORICAL_ROOTS_LIMIT` summaries take 2**24 periods, about 16 million years on
        // mainnet. A full list is `StfError::Tree`, which is not a proof.
        state.historical_summaries.push(historical_summary)?;
    }
    Ok(())
}

/// `process_participation_flag_updates` (A L826-830, New in Altair; Gloas keeps it).
pub fn process_participation_flag_updates<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    state.previous_epoch_participation = state.current_epoch_participation.clone();
    state.current_epoch_participation =
        ProgressiveList::try_from_iter(std::iter::repeat_n(0, state.validators.len()))?;
    Ok(())
}

/// `get_next_sync_committee` (A L356-363, New in Altair; Gloas keeps it), with
/// `eth_aggregate_pubkeys` through `aggregator`. The committee can hold a key more than one
/// time.
///
/// The spec calls it only at a sync committee period boundary and at the fork upgrade.
pub fn get_next_sync_committee<E: Preset>(
    state: &BeaconState<E>,
    aggregator: &dyn PubkeyAggregator,
) -> Result<SyncCommittee<E>, StfError> {
    let indices = get_next_sync_committee_indices(state)?;
    // The indices come from the registry, so an index past it is a fault of our own state.
    let pubkeys = indices
        .iter()
        .map(|&index| state_validator(state, index).map(|validator| validator.pubkey))
        .collect::<Result<Vec<BLSPubkey>, _>>()?;
    let aggregate_pubkey = aggregator.aggregate_pubkeys(&pubkeys)?;
    // `compute_balance_weighted_selection` gives exactly `SYNC_COMMITTEE_SIZE` indices.
    let pubkeys = FixedVector::new(pubkeys)
        .map_err(|e| StfError::Tree(format!("sync committee length: {e:?}")))?;
    Ok(SyncCommittee {
        pubkeys,
        aggregate_pubkey,
    })
}

/// `process_sync_committee_updates` (A L838-842, New in Altair; Gloas keeps it).
pub fn process_sync_committee_updates<E: Preset>(
    state: &mut BeaconState<E>,
    aggregator: &dyn PubkeyAggregator,
) -> Result<(), StfError> {
    let next_epoch = next_epoch(state)?;
    if next_epoch.is_multiple_of(E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD) {
        let next_sync_committee = get_next_sync_committee(state, aggregator)?;
        state.current_sync_committee =
            std::mem::replace(&mut state.next_sync_committee, next_sync_committee);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::get_next_sync_committee_indices;
    use crate::testing::{genesis_state, XorAggregator};
    use crate::{AggregationError, PubkeyAggregator, StfError};
    use consensus_types::gloas::{BeaconState, Eth1Data};
    use consensus_types::primitives::{BLSPubkey, Bytes32, Root};
    use consensus_types::{EthSpec, Minimal};
    use ssz_types::typenum::Unsigned;
    use tree_hash::TreeHash;

    /// A minimal state of 64 validators at the last slot of `epoch`.
    fn state_at(epoch: u64) -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        state.slot = Minimal::start_slot_at_epoch(epoch + 1) - 1;
        state
    }

    fn vote() -> Eth1Data {
        Eth1Data {
            deposit_root: Root::repeat_byte(1),
            deposit_count: 2,
            block_hash: Root::repeat_byte(3),
        }
    }

    #[test]
    fn eth1_votes_reset_at_the_voting_period() {
        // EPOCHS_PER_ETH1_VOTING_PERIOD is 4 in the minimal preset.
        for (epoch, cleared) in [(2, false), (3, true), (7, true), (8, false)] {
            let mut state = state_at(epoch);
            state.eth1_data_votes.push(vote()).unwrap();
            process_eth1_data_reset(&mut state).unwrap();
            assert_eq!(state.eth1_data_votes.is_empty(), cleared, "epoch {epoch}");
        }
    }

    #[test]
    fn slashings_and_randao_slots_of_the_next_epoch() {
        let n = <Minimal as EthSpec>::EpochsPerSlashingsVector::to_u64();
        let mut state = state_at(n - 1);
        *state.slashings.get_mut(0).unwrap() = 5;
        *state.slashings.get_mut(1).unwrap() = 6;
        *state.randao_mixes.get_mut(((n - 1) % 64) as usize).unwrap() = Bytes32::repeat_byte(9);
        process_slashings_reset(&mut state).unwrap();
        // The next epoch `n` wraps to slot 0.
        assert_eq!(state.slashings.get(0), Some(&0));
        assert_eq!(state.slashings.get(1), Some(&6));
        process_randao_mixes_reset(&mut state).unwrap();
        // EPOCHS_PER_HISTORICAL_VECTOR is 64, and so is `n`.
        assert_eq!(state.randao_mixes.get(0), Some(&Bytes32::repeat_byte(9)));
    }

    #[test]
    fn historical_summaries_at_the_period() {
        // SLOTS_PER_HISTORICAL_ROOT // SLOTS_PER_EPOCH is 8 in the minimal preset.
        let mut state = state_at(6);
        process_historical_summaries_update(&mut state).unwrap();
        assert!(state.historical_summaries.is_empty());
        let mut state = state_at(7);
        *state.block_roots.get_mut(3).unwrap() = Root::repeat_byte(4);
        *state.state_roots.get_mut(5).unwrap() = Root::repeat_byte(6);
        process_historical_summaries_update(&mut state).unwrap();
        let summary = state.historical_summaries.get(0).unwrap();
        assert_eq!(
            summary.block_summary_root,
            state.block_roots.tree_hash_root()
        );
        assert_eq!(
            summary.state_summary_root,
            state.state_roots.tree_hash_root()
        );
        assert_ne!(summary.block_summary_root, summary.state_summary_root);
    }

    #[test]
    fn participation_moves_to_the_previous_epoch() {
        let mut state = state_at(3);
        for i in 0..64 {
            *state.current_epoch_participation.get_mut(i).unwrap() = (i % 8) as u8;
            *state.previous_epoch_participation.get_mut(i).unwrap() = 7;
        }
        let current = state.current_epoch_participation.to_vec();
        process_participation_flag_updates(&mut state).unwrap();
        assert_eq!(state.previous_epoch_participation.to_vec(), current);
        assert_eq!(state.current_epoch_participation.to_vec(), vec![0; 64]);
    }

    /// An aggregator that always fails.
    struct Failing;

    impl PubkeyAggregator for Failing {
        fn aggregate_pubkeys(&self, _: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError> {
            Err(AggregationError("bad key".into()))
        }
    }

    #[test]
    fn sync_committees_rotate_at_the_period() {
        // EPOCHS_PER_SYNC_COMMITTEE_PERIOD is 8 in the minimal preset.
        let mut state = state_at(6);
        let pre = state.clone();
        process_sync_committee_updates(&mut state, &Failing).unwrap();
        assert_eq!(state, pre);

        let mut state = state_at(7);
        let next = state.next_sync_committee.clone();
        let indices = get_next_sync_committee_indices(&state).unwrap();
        let want_keys: Vec<BLSPubkey> = indices
            .iter()
            .map(|&i| state.validators.get(i as usize).unwrap().pubkey)
            .collect();
        let committee = get_next_sync_committee(&state, &XorAggregator).unwrap();
        assert_eq!(committee.pubkeys.to_vec(), want_keys);
        assert_eq!(
            committee.aggregate_pubkey,
            XorAggregator.aggregate_pubkeys(&want_keys).unwrap()
        );
        process_sync_committee_updates(&mut state, &XorAggregator).unwrap();
        assert_eq!(state.current_sync_committee, next);
        assert_eq!(state.next_sync_committee, committee);

        let mut state = state_at(7);
        assert_eq!(
            process_sync_committee_updates(&mut state, &Failing),
            Err(StfError::PubkeyAggregation(AggregationError(
                "bad key".into()
            )))
        );
    }
}
