//! Shuffling and the selections built on it: beacon committees ([`committee`]), proposers
//! ([`proposer`]) and the payload timeliness committee ([`ptc`]).
//!
//! [`committee::CommitteeCache`] shuffles the whole active set once per `(epoch, seed)`; the
//! per-index [`committee::compute_shuffled_index`] stays the reference oracle.

pub mod committee;
pub mod proposer;
pub mod ptc;

pub use committee::{
    compute_committee, compute_shuffled_index, compute_shuffled_permutation, get_beacon_committee,
    CommitteeCache,
};
pub use proposer::{
    compute_proposer_indices, get_beacon_proposer_index, get_beacon_proposer_indices,
    initialize_proposer_lookahead,
};
pub use ptc::{compute_ptc, compute_ptc_with, get_ptc, initialize_ptc_window};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::{get_active_validator_indices, get_committee_count_per_slot, get_seed};
    use crate::testing::{genesis_state_with_mix, refresh_lookahead};
    use consensus_types::gloas::BeaconState;
    use consensus_types::primitives::{Bytes32, Gwei};
    use consensus_types::signing::DOMAIN_BEACON_PROPOSER;
    use consensus_types::{EthSpec, Minimal};
    use proptest::prelude::*;
    use ssz_types::typenum::Unsigned;
    use std::collections::BTreeSet;

    const ETH: Gwei = 1_000_000_000;

    /// A minimal genesis registry: balances of 1 to 2048 ETH, some validators slashed (never
    /// all), a random RANDAO mix and a start epoch.
    fn registry() -> impl Strategy<Value = (Vec<(Gwei, bool)>, [u8; 32], u64)> {
        (
            prop::collection::vec((1..=2048u64, prop::bool::weighted(0.2)), 16..=160),
            any::<[u8; 32]>(),
            0..4u64,
        )
            .prop_map(|(mut validators, mix, epoch)| {
                validators[0].1 = false;
                let validators = validators.into_iter().map(|(b, s)| (b * ETH, s)).collect();
                (validators, mix, epoch)
            })
    }

    fn state_at(validators: &[(Gwei, bool)], mix: [u8; 32], epoch: u64) -> BeaconState<Minimal> {
        let balances: Vec<Gwei> = validators.iter().map(|(b, _)| *b).collect();
        let mut state = genesis_state_with_mix::<Minimal>(&balances, Bytes32::from(mix));
        for (i, (_, slashed)) in validators.iter().enumerate() {
            state.validators.get_mut(i).unwrap().slashed = *slashed;
        }
        state.slot = Minimal::start_slot_at_epoch(epoch);
        refresh_lookahead(&mut state);
        state
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn ptc_and_proposers((validators, mix, start_epoch) in registry()) {
            let spe = Minimal::slots_per_epoch();
            let mut state = state_at(&validators, mix, start_epoch);

            // The PTC of every slot in the window: PTC_SIZE members, each in a beacon
            // committee of that slot, equal to a fresh `compute_ptc`.
            for epoch in start_epoch..=start_epoch + 1 {
                let committees = get_committee_count_per_slot(&state, epoch);
                for slot in Minimal::start_slot_at_epoch(epoch)..Minimal::start_slot_at_epoch(epoch + 1) {
                    let ptc = get_ptc(&state, slot).unwrap();
                    prop_assert_eq!(ptc.len(), <Minimal as EthSpec>::PtcSize::to_usize());
                    let members: BTreeSet<u64> = (0..committees)
                        .flat_map(|c| get_beacon_committee(&state, slot, c).unwrap())
                        .collect();
                    for member in ptc.iter() {
                        prop_assert!(members.contains(member), "slot {} member {}", slot, member);
                    }
                    prop_assert_eq!(ptc.to_vec(), compute_ptc(&state, slot).unwrap());
                }
            }

            // Over 3 epochs, the lookahead read gives what `compute_proposer_indices` draws for
            // the slot, and the next-epoch half of one lookahead is the next epoch's first half.
            let mut previous: Option<Vec<u64>> = None;
            for epoch in start_epoch..start_epoch + 3 {
                state.slot = Minimal::start_slot_at_epoch(epoch);
                refresh_lookahead(&mut state);
                let lookahead = state.proposer_lookahead.to_vec();
                if let Some(previous) = previous {
                    prop_assert_eq!(&previous[spe as usize..], &lookahead[..spe as usize]);
                }
                let candidates: Vec<u64> = get_active_validator_indices(&state, epoch)
                    .into_iter()
                    .filter(|&i| !validators[i as usize].1)
                    .collect();
                let seed = get_seed(&state, epoch, DOMAIN_BEACON_PROPOSER).unwrap();
                let drawn = compute_proposer_indices(&state, epoch, &seed, &candidates).unwrap();
                prop_assert_eq!(drawn.len() as u64, spe);
                for (i, want) in drawn.iter().enumerate() {
                    state.slot = Minimal::start_slot_at_epoch(epoch) + i as u64;
                    prop_assert_eq!(get_beacon_proposer_index(&state).unwrap(), *want);
                    prop_assert!(!validators[*want as usize].1, "slashed proposer {}", want);
                }
                previous = Some(lookahead);
            }
        }
    }
}
