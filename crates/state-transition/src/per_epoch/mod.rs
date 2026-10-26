//! Epoch processing (`process_epoch`, G L1633-1653).
//!
//! - [`justification`] holds `process_justification_and_finalization`.
//! - [`inactivity`] holds `process_inactivity_updates`.
//! - [`rewards`] holds `process_rewards_and_penalties` and its delta functions.
//! - [`participation`] holds the accessors and the one-pass participation cache they share.
//! - [`registry`] holds `process_registry_updates`, `process_slashings` and
//!   `process_effective_balance_updates`.
//! - [`pending`] holds `process_pending_deposits` and `process_pending_consolidations`.
//! - [`resets`] holds the eth1, slashings, RANDAO, historical summary, participation flag and
//!   sync committee updates.
//! - [`gloas`] holds `process_proposer_lookahead` and `process_ptc_window`.
//!
//! `process_builder_pending_payments` is not ported yet: [`process_epoch`] stops there with
//! [`StfError::Unimplemented`].

pub mod gloas;
pub mod inactivity;
pub mod justification;
#[cfg(test)]
mod literal;
pub mod participation;
pub mod pending;
pub mod registry;
pub mod resets;
pub mod rewards;

pub use inactivity::process_inactivity_updates;
pub use justification::{
    process_justification_and_finalization, weigh_justification_and_finalization,
};
pub use participation::get_unslashed_participating_indices;
pub use pending::pending_deposit_signature_sets;
pub use rewards::{
    get_flag_index_deltas, get_inactivity_penalty_deltas, process_rewards_and_penalties,
};

use crate::accessors::TotalActiveBalanceCache;
use crate::{BlsContext, Preset, StfError};
use consensus_types::common::Validator;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::ValidatorIndex;
use participation::ParticipationCache;

/// `state.validators[index]` for an index that a step read from the state, not from an
/// object. A state that the spec makes holds each such index in its registry, so an index
/// past it is a fault of our own state: `ListIndexOutOfRange`, not a proof.
pub(crate) fn state_validator<E: Preset>(
    state: &BeaconState<E>,
    index: ValidatorIndex,
) -> Result<&Validator, StfError> {
    state
        .validators
        .get(index as usize)
        .ok_or(StfError::ListIndexOutOfRange {
            list: "validators",
            index,
        })
}

/// One step of `process_epoch` (G L1633-1653).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EpochStep {
    /// `process_justification_and_finalization`.
    JustificationAndFinalization,
    /// `process_inactivity_updates`.
    InactivityUpdates,
    /// `process_rewards_and_penalties`.
    RewardsAndPenalties,
    /// `process_registry_updates`.
    RegistryUpdates,
    /// `process_slashings`.
    Slashings,
    /// `process_eth1_data_reset`.
    Eth1DataReset,
    /// `process_pending_deposits`.
    PendingDeposits,
    /// `process_pending_consolidations`.
    PendingConsolidations,
    /// `process_builder_pending_payments` (not ported yet).
    BuilderPendingPayments,
    /// `process_effective_balance_updates`.
    EffectiveBalanceUpdates,
    /// `process_slashings_reset`.
    SlashingsReset,
    /// `process_randao_mixes_reset`.
    RandaoMixesReset,
    /// `process_historical_summaries_update`.
    HistoricalSummariesUpdate,
    /// `process_participation_flag_updates`.
    ParticipationFlagUpdates,
    /// `process_sync_committee_updates`.
    SyncCommitteeUpdates,
    /// `process_proposer_lookahead`.
    ProposerLookahead,
    /// `process_ptc_window`.
    PtcWindow,
}

impl EpochStep {
    /// The name of the step function in the spec.
    pub fn name(self) -> &'static str {
        match self {
            Self::JustificationAndFinalization => "process_justification_and_finalization",
            Self::InactivityUpdates => "process_inactivity_updates",
            Self::RewardsAndPenalties => "process_rewards_and_penalties",
            Self::RegistryUpdates => "process_registry_updates",
            Self::Slashings => "process_slashings",
            Self::Eth1DataReset => "process_eth1_data_reset",
            Self::PendingDeposits => "process_pending_deposits",
            Self::PendingConsolidations => "process_pending_consolidations",
            Self::BuilderPendingPayments => "process_builder_pending_payments",
            Self::EffectiveBalanceUpdates => "process_effective_balance_updates",
            Self::SlashingsReset => "process_slashings_reset",
            Self::RandaoMixesReset => "process_randao_mixes_reset",
            Self::HistoricalSummariesUpdate => "process_historical_summaries_update",
            Self::ParticipationFlagUpdates => "process_participation_flag_updates",
            Self::SyncCommitteeUpdates => "process_sync_committee_updates",
            Self::ProposerLookahead => "process_proposer_lookahead",
            Self::PtcWindow => "process_ptc_window",
        }
    }
}

/// The steps of the Gloas `process_epoch` (G L1633-1653), in the spec order.
pub const EPOCH_STEPS: [EpochStep; 17] = [
    EpochStep::JustificationAndFinalization,
    EpochStep::InactivityUpdates,
    EpochStep::RewardsAndPenalties,
    EpochStep::RegistryUpdates,
    EpochStep::Slashings,
    EpochStep::Eth1DataReset,
    EpochStep::PendingDeposits,
    EpochStep::PendingConsolidations,
    EpochStep::BuilderPendingPayments,
    EpochStep::EffectiveBalanceUpdates,
    EpochStep::SlashingsReset,
    EpochStep::RandaoMixesReset,
    EpochStep::HistoricalSummariesUpdate,
    EpochStep::ParticipationFlagUpdates,
    EpochStep::SyncCommitteeUpdates,
    EpochStep::ProposerLookahead,
    EpochStep::PtcWindow,
];

/// One `process_epoch` call: the state, the BLS context, and the caches that the steps
/// share.
///
/// The participation cache is valid for the first three steps (see [`ParticipationCache`]).
/// The total-balance cache is valid up to `process_effective_balance_updates`, and no later
/// step reads the total (see the limits in the rustdoc of `TotalActiveBalanceCache`).
struct EpochRun<'s, 'b, E: Preset> {
    state: &'s mut BeaconState<E>,
    bls: &'s BlsContext<'b>,
    totals: TotalActiveBalanceCache,
    participation: ParticipationCache,
}

impl<'s, 'b, E: Preset> EpochRun<'s, 'b, E> {
    /// Reads the participation of `state` one time, before the first step.
    fn new(state: &'s mut BeaconState<E>, bls: &'s BlsContext<'b>) -> Self {
        let mut totals = TotalActiveBalanceCache::default();
        let participation = ParticipationCache::new(state, &mut totals);
        Self {
            state,
            bls,
            totals,
            participation,
        }
    }

    /// Runs `step` on the state.
    fn run(&mut self, step: EpochStep) -> Result<(), StfError> {
        let state = &mut *self.state;
        let bls = self.bls;
        match step {
            EpochStep::JustificationAndFinalization => {
                justification::process_justification_and_finalization_with(
                    state,
                    &self.participation,
                )
            }
            EpochStep::InactivityUpdates => {
                inactivity::process_inactivity_updates_with(state, &self.participation)
            }
            EpochStep::RewardsAndPenalties => {
                rewards::process_rewards_and_penalties_with(state, &self.participation)
            }
            EpochStep::RegistryUpdates => {
                registry::process_registry_updates_with(state, &mut self.totals)
            }
            EpochStep::Slashings => registry::process_slashings_with(state, &mut self.totals),
            EpochStep::Eth1DataReset => resets::process_eth1_data_reset(state),
            EpochStep::PendingDeposits => pending::process_pending_deposits_with(
                state,
                bls.genesis_fork_version,
                bls.backend,
                &mut self.totals,
            ),
            EpochStep::PendingConsolidations => pending::process_pending_consolidations(state),
            EpochStep::BuilderPendingPayments => Err(StfError::Unimplemented(
                "process_builder_pending_payments (4.6b)",
            )),
            EpochStep::EffectiveBalanceUpdates => {
                registry::process_effective_balance_updates(state)
            }
            EpochStep::SlashingsReset => resets::process_slashings_reset(state),
            EpochStep::RandaoMixesReset => resets::process_randao_mixes_reset(state),
            EpochStep::HistoricalSummariesUpdate => {
                resets::process_historical_summaries_update(state)
            }
            EpochStep::ParticipationFlagUpdates => {
                resets::process_participation_flag_updates(state)
            }
            EpochStep::SyncCommitteeUpdates => {
                resets::process_sync_committee_updates(state, bls.aggregator)
            }
            EpochStep::ProposerLookahead => gloas::process_proposer_lookahead(state),
            EpochStep::PtcWindow => gloas::process_ptc_window(state),
        }
    }
}

/// `process_epoch` (G L1633-1653, Modified in Gloas): the [`EPOCH_STEPS`] in the spec order,
/// with one participation cache and one total-balance cache for the steps that read them.
///
/// `bls` gives the verdicts of the pending deposits, the aggregation of the next sync
/// committee and the deposit domain. [`pending_deposit_signature_sets`] lists the deposit
/// verdicts to prefetch. The call returns [`StfError::Unimplemented`] at
/// `process_builder_pending_payments`, which is not ported yet. On `Err`, `state` is partly
/// updated: the caller drops it.
pub fn process_epoch<E: Preset>(
    state: &mut BeaconState<E>,
    bls: &BlsContext,
) -> Result<(), StfError> {
    process_epoch_with(state, bls, |step, epoch| epoch.run(step))
}

/// [`process_epoch`] with each step through `run_step`, so that a test can trace the steps.
fn process_epoch_with<E, F>(
    state: &mut BeaconState<E>,
    bls: &BlsContext,
    mut run_step: F,
) -> Result<(), StfError>
where
    E: Preset,
    F: FnMut(EpochStep, &mut EpochRun<'_, '_, E>) -> Result<(), StfError>,
{
    let mut epoch = EpochRun::new(state, bls);
    for step in EPOCH_STEPS {
        run_step(step, &mut epoch)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per_slot::{process_slot, process_slots};
    use crate::signatures::deposit_signature_set;
    use crate::testing::{
        bls_context, genesis_state, PrefetchedBackend, ScriptedBackend, GENESIS_FORK_VERSION,
    };
    use crate::{BackendError, BlsContext, SignatureSet};
    use consensus_types::common::{PendingConsolidation, PendingDeposit};
    use consensus_types::gloas::Eth1Data;
    use consensus_types::primitives::{BLSPubkey, Bytes32, Gwei, Root, Slot};
    use consensus_types::{EthSpec, Minimal};
    use ssz_types::typenum::Unsigned;

    const ETH: Gwei = 1_000_000_000;

    /// The step functions of `process_epoch` (G L1633-1653), in the spec order.
    const SPEC_ORDER: [&str; 17] = [
        "process_justification_and_finalization",
        "process_inactivity_updates",
        "process_rewards_and_penalties",
        "process_registry_updates",
        "process_slashings",
        "process_eth1_data_reset",
        "process_pending_deposits",
        "process_pending_consolidations",
        "process_builder_pending_payments",
        "process_effective_balance_updates",
        "process_slashings_reset",
        "process_randao_mixes_reset",
        "process_historical_summaries_update",
        "process_participation_flag_updates",
        "process_sync_committee_updates",
        "process_proposer_lookahead",
        "process_ptc_window",
    ];

    /// A deposit of 32 ETH for the new key `[0xd1; 48]` at slot 0.
    fn new_deposit() -> PendingDeposit {
        PendingDeposit {
            pubkey: [0xd1; 48],
            withdrawal_credentials: Bytes32::ZERO,
            amount: 32 * ETH,
            signature: [0x44; 96],
            slot: 0,
        }
    }

    /// A minimal state of 64 validators at the last slot of epoch 7, in which each step
    /// changes something: the next epoch 8 starts an eth1 voting period, a sync committee
    /// period and a historical summary period. It has participation, a slashed validator at
    /// the half of the slashings vector, a validator to eject, a new deposit for the key
    /// `[0xd1; 48]` and a consolidation.
    fn busy_state() -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        for i in 0..64 {
            *state.randao_mixes.get_mut(i).unwrap() = Bytes32::repeat_byte(i as u8);
        }
        state.slot = Minimal::start_slot_at_epoch(8) - 1;
        crate::testing::refresh_lookahead(&mut state);
        state.finalized_checkpoint.epoch = 5;
        state.current_justified_checkpoint.epoch = 5;
        state.previous_justified_checkpoint.epoch = 5;
        for i in 0..64 {
            *state.previous_epoch_participation.get_mut(i).unwrap() = 0b111;
            *state.current_epoch_participation.get_mut(i).unwrap() =
                if i % 3 == 0 { 0 } else { 0b011 };
        }
        let half = <Minimal as EthSpec>::EpochsPerSlashingsVector::to_u64() / 2;
        let slashed = state.validators.get_mut(5).unwrap();
        slashed.slashed = true;
        slashed.withdrawable_epoch = 7 + half;
        *state.slashings.get_mut(7).unwrap() = 32 * ETH;
        *state.slashings.get_mut(8).unwrap() = 32 * ETH;
        state.validators.get_mut(6).unwrap().effective_balance = 16 * ETH;
        *state.balances.get_mut(6).unwrap() = 16 * ETH;
        state.validators.get_mut(7).unwrap().withdrawable_epoch = 8;
        state
            .pending_consolidations
            .push(PendingConsolidation {
                source_index: 7,
                target_index: 8,
            })
            .unwrap();
        state.pending_deposits.push(new_deposit()).unwrap();
        state
            .eth1_data_votes
            .push(Eth1Data {
                deposit_root: Root::repeat_byte(1),
                deposit_count: 1,
                block_hash: Root::repeat_byte(2),
            })
            .unwrap();
        state
    }

    /// The steps of [`SPEC_ORDER`] one by one through their public functions, each with its
    /// own caches. `process_builder_pending_payments` is not ported, so it is left out.
    fn stepwise(state: &mut BeaconState<Minimal>, bls: &BlsContext) -> Result<(), StfError> {
        process_justification_and_finalization(state)?;
        process_inactivity_updates(state)?;
        process_rewards_and_penalties(state)?;
        registry::process_registry_updates(state)?;
        registry::process_slashings(state)?;
        resets::process_eth1_data_reset(state)?;
        pending::process_pending_deposits(state, bls.genesis_fork_version, bls.backend)?;
        pending::process_pending_consolidations(state)?;
        registry::process_effective_balance_updates(state)?;
        resets::process_slashings_reset(state)?;
        resets::process_randao_mixes_reset(state)?;
        resets::process_historical_summaries_update(state)?;
        resets::process_participation_flag_updates(state)?;
        resets::process_sync_committee_updates(state, bls.aggregator)?;
        gloas::process_proposer_lookahead(state)?;
        gloas::process_ptc_window(state)
    }

    /// `process_epoch` with a step trace, and with the builder payments step left out.
    fn traced(
        state: &mut BeaconState<Minimal>,
        bls: &BlsContext,
    ) -> (Vec<EpochStep>, Result<(), StfError>) {
        let mut trace = Vec::new();
        let result = process_epoch_with(state, bls, |step, epoch| {
            trace.push(step);
            if step == EpochStep::BuilderPendingPayments {
                Ok(())
            } else {
                epoch.run(step)
            }
        });
        (trace, result)
    }

    #[test]
    fn gloas_order() {
        assert_eq!(EPOCH_STEPS.map(EpochStep::name), SPEC_ORDER);
        let backend = ScriptedBackend::new([Ok(true)]);
        let mut state = busy_state();
        let (trace, result) = traced(&mut state, &bls_context(&backend));
        assert_eq!(result, Ok(()));
        assert_eq!(trace, EPOCH_STEPS);

        // The run equals the public steps in the spec order.
        let mut want = busy_state();
        let backend = ScriptedBackend::new([Ok(true)]);
        stepwise(&mut want, &bls_context(&backend)).unwrap();
        assert_eq!(state, want);
        // Each step changed the state that it owns.
        let pre = busy_state();
        assert_ne!(
            state.current_justified_checkpoint,
            pre.current_justified_checkpoint
        );
        assert_ne!(state.inactivity_scores, pre.inactivity_scores);
        assert_eq!(state.validators.len(), 65);
        assert!(state.pending_deposits.is_empty() && state.pending_consolidations.is_empty());
        assert_ne!(state.validators.get(6), pre.validators.get(6));
        assert!(state.eth1_data_votes.is_empty());
        assert_eq!(state.slashings.get(8), Some(&0));
        assert_eq!(state.historical_summaries.len(), 1);
        assert_ne!(state.next_sync_committee, pre.next_sync_committee);
        assert_ne!(state.proposer_lookahead, pre.proposer_lookahead);
        assert_ne!(state.ptc_window, pre.ptc_window);
    }

    #[test]
    fn process_epoch_stops_at_the_builder_payments() {
        let backend = ScriptedBackend::new([Ok(true)]);
        let mut state = busy_state();
        let err = process_epoch(&mut state, &bls_context(&backend)).unwrap_err();
        assert_eq!(
            err,
            StfError::Unimplemented("process_builder_pending_payments (4.6b)")
        );
        assert!(!err.proves_invalid());
        // The steps before it ran in the spec order.
        let mut want = busy_state();
        let backend = ScriptedBackend::new([Ok(true)]);
        let bls = bls_context(&backend);
        process_justification_and_finalization(&mut want).unwrap();
        process_inactivity_updates(&mut want).unwrap();
        process_rewards_and_penalties(&mut want).unwrap();
        registry::process_registry_updates(&mut want).unwrap();
        registry::process_slashings(&mut want).unwrap();
        resets::process_eth1_data_reset(&mut want).unwrap();
        pending::process_pending_deposits(&mut want, bls.genesis_fork_version, bls.backend)
            .unwrap();
        pending::process_pending_consolidations(&mut want).unwrap();
        assert_eq!(state, want);
    }

    #[test]
    fn deposit_verdicts() {
        // An invalid signature skips the deposit, and the rest of the epoch runs.
        let backend = ScriptedBackend::new([Ok(false)]);
        let mut state = busy_state();
        let (trace, result) = traced(&mut state, &bls_context(&backend));
        assert_eq!((trace, result), (EPOCH_STEPS.to_vec(), Ok(())));
        assert_eq!(backend.seen().len(), 1);
        assert_eq!(state.validators.len(), 64);
        assert!(state.validators.iter().all(|v| v.pubkey != [0xd1; 48]));
        assert!(state.pending_deposits.is_empty());
        let mut want = busy_state();
        let backend = ScriptedBackend::new([Ok(false)]);
        stepwise(&mut want, &bls_context(&backend)).unwrap();
        assert_eq!(state, want);

        // A missing verdict stops the epoch at the deposits step.
        let backend = ScriptedBackend::new([Err(BackendError("not prefetched".into()))]);
        let mut state = busy_state();
        let (trace, result) = traced(&mut state, &bls_context(&backend));
        assert_eq!(
            result,
            Err(StfError::MissingVerdict(BackendError(
                "not prefetched".into()
            )))
        );
        assert_eq!(trace.last(), Some(&EpochStep::PendingDeposits));
        let backend = ScriptedBackend::new([Err(BackendError("not prefetched".into()))]);
        assert_eq!(
            process_epoch(&mut busy_state(), &bls_context(&backend)),
            Err(StfError::MissingVerdict(BackendError(
                "not prefetched".into()
            )))
        );
    }

    /// A deposit of `amount` for `pubkey` at `slot`, with 0x01 credentials.
    fn deposit(pubkey: BLSPubkey, amount: Gwei, slot: Slot) -> PendingDeposit {
        let mut withdrawal_credentials = Bytes32::ZERO;
        withdrawal_credentials[0] = 0x01;
        PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount,
            signature: [0x44; 96],
            slot,
        }
    }

    fn set_of(deposit: &PendingDeposit) -> SignatureSet {
        deposit_signature_set(
            deposit.pubkey,
            deposit.withdrawal_credentials,
            deposit.amount,
            deposit.signature,
            GENESIS_FORK_VERSION,
        )
    }

    /// The deposits of [`finalizing_state`]: the new key `[0xa1; 48]` at slot 44, which
    /// only the justification of epoch 7 finalizes, at the front, and the new keys
    /// `[0xb1; 48]` and `[0xc1; 48]` after the reach of the first boundary.
    struct Queue {
        first: PendingDeposit,
        second: PendingDeposit,
        again: PendingDeposit,
        invalid: PendingDeposit,
    }

    /// A minimal state of 64 validators at the last slot of epoch 7, with full
    /// participation in epochs 6 and 7. It is finalized at epoch 5 (slot 40), and epochs 5
    /// and 6 are justified. Thus its justification finalizes epoch 6 (slot 48).
    ///
    /// Its queue holds [`Queue::first`], 15 top-ups for validator 1, and then
    /// [`Queue::second`], [`Queue::again`] (a top-up for `[0xa1; 48]`) and
    /// [`Queue::invalid`] (the key `[0xc1; 48]`, with an invalid signature in the tests).
    fn finalizing_state() -> (BeaconState<Minimal>, Queue) {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        state.slot = Minimal::start_slot_at_epoch(8) - 1;
        crate::testing::refresh_lookahead(&mut state);
        state.finalized_checkpoint.epoch = 5;
        state.previous_justified_checkpoint.epoch = 5;
        state.current_justified_checkpoint.epoch = 6;
        state.justification_bits.set(0, true).unwrap();
        state.justification_bits.set(1, true).unwrap();
        for i in 0..64 {
            *state.previous_epoch_participation.get_mut(i).unwrap() = 0b111;
            *state.current_epoch_participation.get_mut(i).unwrap() = 0b111;
        }
        let queue = Queue {
            first: deposit([0xa1; 48], 32 * ETH, 44),
            second: deposit([0xb1; 48], 32 * ETH, 45),
            again: deposit([0xa1; 48], ETH, 46),
            invalid: deposit([0xc1; 48], ETH, 47),
        };
        let mut validator_1 = [0u8; 48];
        validator_1[0] = 1;
        let mut deposits = vec![queue.first.clone()];
        deposits.extend(std::iter::repeat_n(deposit(validator_1, ETH, 0), 15));
        deposits.extend([
            queue.second.clone(),
            queue.again.clone(),
            queue.invalid.clone(),
        ]);
        for d in deposits {
            state.pending_deposits.push(d).unwrap();
        }
        (state, queue)
    }

    /// The verdicts of `sets`, with an invalid signature for `invalid` only.
    fn verdicts(sets: &[SignatureSet], invalid: &PendingDeposit) -> PrefetchedBackend {
        let invalid = set_of(invalid);
        PrefetchedBackend::new(sets.iter().map(|set| (set.clone(), *set != invalid)))
    }

    /// `process_slots` with the builder payments step left out, as in [`traced`], so that
    /// the loop can cross more than one epoch boundary.
    // TODO(#72): when `process_builder_pending_payments` is ported, remove this copy of
    // the slot loop and call `process_slots` in the two-boundary test.
    fn slots_without_builder_payments(
        state: &mut BeaconState<Minimal>,
        slot: Slot,
        bls: &BlsContext,
    ) -> Result<(), StfError> {
        while state.slot < slot {
            process_slot(state)?;
            let next_slot = state.slot + 1;
            if next_slot.is_multiple_of(Minimal::slots_per_epoch()) {
                traced(state, bls).1?;
            }
            state.slot = next_slot;
        }
        Ok(())
    }

    #[test]
    fn prefetch_covers_a_deposit_that_the_same_epoch_finalizes() {
        let (pre, queue) = finalizing_state();
        let sets = pending_deposit_signature_sets(&pre, 64, GENESIS_FORK_VERSION);
        assert_eq!(sets, vec![set_of(&queue.first)]);
        let backend = verdicts(&sets, &queue.invalid);
        let mut state = pre.clone();
        // The real slot loop gets to the builder payments step, after the deposits.
        assert_eq!(
            process_slots(&mut state, 64, &bls_context(&backend)),
            Err(StfError::Unimplemented(
                "process_builder_pending_payments (4.6b)"
            ))
        );
        assert_eq!(state.finalized_checkpoint.epoch, 6);
        assert_eq!(backend.seen(), sets);
        assert_eq!(state.validators.get(64).unwrap().pubkey, [0xa1; 48]);
        assert_eq!(state.pending_deposits.len(), 3);

        // A prefetch with the finality of the pre-state (slot 40) has no verdict for it.
        let filtered = verdicts(&[], &queue.invalid);
        assert_eq!(
            process_slots(&mut pre.clone(), 64, &bls_context(&filtered)),
            Err(StfError::MissingVerdict(BackendError(
                "not prefetched".into()
            )))
        );
    }

    #[test]
    fn prefetch_covers_each_boundary_of_the_slot_loop() {
        let (pre, queue) = finalizing_state();
        let sets = pending_deposit_signature_sets(&pre, 72, GENESIS_FORK_VERSION);
        assert_eq!(
            sets,
            [&queue.first, &queue.second, &queue.again, &queue.invalid].map(set_of)
        );
        let backend = verdicts(&sets, &queue.invalid);
        let mut state = pre.clone();
        assert_eq!(
            slots_without_builder_payments(&mut state, 72, &bls_context(&backend)),
            Ok(())
        );
        // The second deposit for `[0xa1; 48]` is a top-up, so the loop asked for the
        // other three sets only.
        assert_eq!(
            backend.seen(),
            [&queue.first, &queue.second, &queue.invalid].map(set_of)
        );
        assert!(state.pending_deposits.is_empty());
        let keys: Vec<BLSPubkey> = state.validators.iter().skip(64).map(|v| v.pubkey).collect();
        assert_eq!(keys, [[0xa1; 48], [0xb1; 48]]);

        // The sets of the first boundary only do not cover the second one.
        let first = pending_deposit_signature_sets(&pre, 64, GENESIS_FORK_VERSION);
        let backend = verdicts(&first, &queue.invalid);
        assert_eq!(
            slots_without_builder_payments(&mut pre.clone(), 72, &bls_context(&backend)),
            Err(StfError::MissingVerdict(BackendError(
                "not prefetched".into()
            )))
        );
    }

    #[test]
    fn indices_from_the_state_are_not_a_proof() {
        let state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        assert_eq!(state_validator(&state, 7).map(|v| v.pubkey[0]), Ok(7));
        let err = state_validator(&state, 8).unwrap_err();
        assert_eq!(
            err,
            StfError::ListIndexOutOfRange {
                list: "validators",
                index: 8
            }
        );
        assert!(!err.proves_invalid());
    }
}
