//! Rewards and penalties (A L780-793): the flag deltas (A L459-485) and the inactivity
//! penalties (Bx L292-310). The base reward (A L386-391) is in [`crate::accessors`].
//!
//! Each delta function reads a `ParticipationCache`: one pass over the registry, in place
//! of a set of participants for each flag. The spec-literal loops are the test oracles in
//! `per_epoch::literal`.

use super::participation::{is_in_inactivity_leak, ParticipationCache};
use crate::accessors::{base_reward, base_reward_per_increment, get_current_epoch, has_flag};
use crate::preset::{
    EFFECTIVE_BALANCE_INCREMENT, GENESIS_EPOCH, INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
    INACTIVITY_SCORE_BIAS, PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX,
    TIMELY_TARGET_FLAG_INDEX, WEIGHT_DENOMINATOR,
};
use crate::{Preset, StfError};
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::Gwei;

/// The rewards and the penalties of one delta function, one entry for each validator.
pub type Deltas = (Vec<Gwei>, Vec<Gwei>);

/// `get_flag_index_deltas` (A L459-485).
pub fn get_flag_index_deltas<E: Preset>(
    state: &BeaconState<E>,
    flag_index: usize,
) -> Result<Deltas, StfError> {
    flag_index_deltas(state, &ParticipationCache::of(state), flag_index)
}

/// `get_inactivity_penalty_deltas` (Bx L292-310, Modified in Bellatrix).
pub fn get_inactivity_penalty_deltas<E: Preset>(
    state: &BeaconState<E>,
) -> Result<Deltas, StfError> {
    inactivity_penalty_deltas(state, &ParticipationCache::of(state))
}

/// `get_flag_index_deltas` over `participation`.
pub(crate) fn flag_index_deltas<E: Preset>(
    state: &BeaconState<E>,
    participation: &ParticipationCache,
    flag_index: usize,
) -> Result<Deltas, StfError> {
    let n = participation.validators.len();
    let mut rewards = vec![0; n];
    let mut penalties = vec![0; n];
    let unslashed_participating_balance = participation.previous_flag_balance(flag_index)?;
    // `previous_flag_balance` refuses an index past PARTICIPATION_FLAG_WEIGHTS.
    let weight = PARTICIPATION_FLAG_WEIGHTS[flag_index];
    let unslashed_participating_increments =
        unslashed_participating_balance / EFFECTIVE_BALANCE_INCREMENT;
    let total_active_balance = participation.total_active_balance()?;
    let active_increments = total_active_balance / EFFECTIVE_BALANCE_INCREMENT;
    let per_increment = base_reward_per_increment(total_active_balance);
    // The spec asks `is_in_inactivity_leak` only for a participant, so its error counts only
    // there.
    let leaking = is_in_inactivity_leak(state);
    for (index, v) in participation.validators.iter().enumerate() {
        if !v.eligible {
            continue;
        }
        let base_reward = base_reward(v.effective_balance, per_increment)?;
        if has_flag(v.previous_flags, flag_index)? {
            if !leaking.clone()? {
                let reward_numerator = base_reward
                    .checked_mul(weight)
                    .and_then(|r| r.checked_mul(unslashed_participating_increments))
                    .ok_or(StfError::ArithmeticOverflow)?;
                // `active_increments` is at least 1, and at most u64::MAX / 10**9.
                rewards[index] = reward_numerator / (active_increments * WEIGHT_DENOMINATOR);
            }
        } else if flag_index != TIMELY_HEAD_FLAG_INDEX {
            penalties[index] = base_reward
                .checked_mul(weight)
                .ok_or(StfError::ArithmeticOverflow)?
                / WEIGHT_DENOMINATOR;
        }
    }
    Ok((rewards, penalties))
}

/// `get_inactivity_penalty_deltas` over `participation`.
pub(crate) fn inactivity_penalty_deltas<E: Preset>(
    state: &BeaconState<E>,
    participation: &ParticipationCache,
) -> Result<Deltas, StfError> {
    let n = participation.validators.len();
    let rewards = vec![0; n];
    let mut penalties = vec![0; n];
    participation.previous_participation()?;
    for (index, v) in participation.validators.iter().enumerate() {
        if !v.eligible || has_flag(v.previous_flags, TIMELY_TARGET_FLAG_INDEX)? {
            continue;
        }
        let score = state
            .inactivity_scores
            .get(index)
            .ok_or(StfError::ListIndexOutOfRange {
                list: "inactivity_scores",
                index: index as u64,
            })?;
        let penalty_numerator = v
            .effective_balance
            .checked_mul(*score)
            .ok_or(StfError::ArithmeticOverflow)?;
        // [Modified in Bellatrix]
        let penalty_denominator = INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_BELLATRIX;
        penalties[index] = penalty_numerator / penalty_denominator;
    }
    Ok((rewards, penalties))
}

/// `process_rewards_and_penalties` (A L780-793, Modified in Altair; Gloas keeps it).
pub fn process_rewards_and_penalties<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    if get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(());
    }
    let participation = ParticipationCache::of(state);
    process_rewards_and_penalties_with(state, &participation)
}

/// [`process_rewards_and_penalties`] over `participation`, which must be the cache of
/// `state` at this epoch boundary.
pub(crate) fn process_rewards_and_penalties_with<E: Preset>(
    state: &mut BeaconState<E>,
    participation: &ParticipationCache,
) -> Result<(), StfError> {
    // No rewards are applied at the end of `GENESIS_EPOCH` because rewards are for work done
    // in the previous epoch
    if get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(());
    }
    let mut deltas = Vec::with_capacity(PARTICIPATION_FLAG_WEIGHTS.len() + 1);
    for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
        deltas.push(flag_index_deltas(state, participation, flag_index)?);
    }
    deltas.push(inactivity_penalty_deltas(state, participation)?);
    apply_deltas(state, &deltas)
}

/// The loop of `process_rewards_and_penalties`: for each delta pair in order, and for each
/// validator, `increase_balance` and then `decrease_balance` (P0 L1653-1667).
fn apply_deltas<E: Preset>(state: &mut BeaconState<E>, deltas: &[Deltas]) -> Result<(), StfError> {
    let n = state.validators.len();
    let mut balances: Vec<Gwei> = state.balances.iter().copied().collect();
    if n > balances.len() {
        return Err(StfError::ListIndexOutOfRange {
            list: "balances",
            index: balances.len() as u64,
        });
    }
    let before = balances.clone();
    for (rewards, penalties) in deltas {
        for (index, balance) in balances.iter_mut().enumerate().take(n) {
            *balance = balance
                .checked_add(rewards[index])
                .ok_or(StfError::ArithmeticOverflow)?;
            *balance = balance.saturating_sub(penalties[index]);
        }
    }
    for (index, (new, old)) in balances.iter().zip(&before).enumerate() {
        if new != old {
            *state
                .balances
                .get_mut(index)
                .ok_or_else(|| StfError::Tree("balance index out of range".into()))? = *new;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::get_base_reward;
    use crate::per_epoch::inactivity::process_inactivity_updates_with;
    use crate::per_epoch::justification::process_justification_and_finalization_with;
    use crate::per_epoch::literal;
    use crate::state_root;
    use crate::testing::{genesis_state, registry_state};
    use consensus_types::common::Checkpoint;
    use consensus_types::primitives::{Epoch, Root, FAR_FUTURE_EPOCH};
    use consensus_types::{EthSpec, Minimal};
    use proptest::prelude::*;

    const ETH: Gwei = 1_000_000_000;

    #[test]
    fn deltas_shape() {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 16]);
        // A genesis registry at the last slot of epoch 1, so every validator is eligible.
        state.slot = Minimal::start_slot_at_epoch(2) - 1;
        let n = state.validators.len();
        for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
            let (rewards, penalties) = get_flag_index_deltas(&state, flag_index).unwrap();
            assert_eq!(
                (rewards.len(), penalties.len()),
                (n, n),
                "flag {flag_index}"
            );
        }
        let (rewards, penalties) = get_inactivity_penalty_deltas(&state).unwrap();
        assert_eq!((rewards.len(), penalties.len()), (n, n));
        // The genesis state itself (epoch 0) gives the same shape.
        let genesis = genesis_state::<Minimal>(&[32 * ETH; 16]);
        let (rewards, penalties) = get_flag_index_deltas(&genesis, 0).unwrap();
        assert_eq!((rewards.len(), penalties.len()), (n, n));
    }

    #[test]
    fn base_reward_and_flag_index_bounds() {
        let state = genesis_state::<Minimal>(&[32 * ETH; 16]);
        // 64 * 10**9 // isqrt(512 * 10**9) = 89_442 per increment.
        assert_eq!(get_base_reward(&state, 3), Ok(32 * 89_442));
        assert_eq!(
            get_base_reward(&state, 16),
            Err(StfError::UnknownValidator(16))
        );
        assert!(matches!(
            get_flag_index_deltas(&state, 3),
            Err(StfError::ListIndexOutOfRange { index: 3, .. })
        ));
        assert_eq!(
            base_reward(2 * ETH, u64::MAX),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn rewards_need_a_balance_for_each_validator() {
        let mut state = registry_state::<Minimal>(&[32 * ETH; 4], Root::ZERO);
        state.slot = Minimal::start_slot_at_epoch(2) - 1;
        state.balances = milhouse::ProgressiveList::try_from_iter([32 * ETH; 3]).unwrap();
        assert_eq!(
            process_rewards_and_penalties(&mut state),
            Err(StfError::ListIndexOutOfRange {
                list: "balances",
                index: 3
            })
        );
        // At the end of the genesis epoch nothing is read.
        state.slot = 7;
        assert_eq!(process_rewards_and_penalties(&mut state), Ok(()));
    }

    #[test]
    fn overflows_raise() {
        let mut state = registry_state::<Minimal>(&[32 * ETH; 4], Root::ZERO);
        state.slot = Minimal::start_slot_at_epoch(2) - 1;
        *state.balances.get_mut(0).unwrap() = u64::MAX;
        *state.previous_epoch_participation.get_mut(0).unwrap() = 0b111;
        assert_eq!(
            process_rewards_and_penalties(&mut state.clone()),
            Err(StfError::ArithmeticOverflow)
        );
        // An inactivity score that overflows the penalty numerator.
        *state.inactivity_scores.get_mut(1).unwrap() = u64::MAX;
        assert_eq!(
            get_inactivity_penalty_deltas(&state),
            Err(StfError::ArithmeticOverflow)
        );
        state.inactivity_scores = milhouse::ProgressiveList::default();
        assert!(matches!(
            get_inactivity_penalty_deltas(&state),
            Err(StfError::ListIndexOutOfRange {
                list: "inactivity_scores",
                ..
            })
        ));
    }

    /// One validator of a random state: effective balance in ETH, balance in Gwei, slashed,
    /// activation, exit and withdrawable epochs relative to the state epoch, the previous
    /// and current participation flags, and the inactivity score.
    type ValidatorSpec = (u64, u64, bool, (u64, i64, i64), (u8, u8), u64);

    fn validator_spec() -> impl Strategy<Value = ValidatorSpec> {
        (
            prop_oneof![4 => 0..=64u64, 1 => Just(2048u64)],
            0..=70 * ETH,
            prop::bool::weighted(0.15),
            (0..=3u64, -3..=3i64, -3..=6i64),
            (any::<u8>(), any::<u8>()),
            prop_oneof![1 => Just(0u64), 3 => 0..=400u64],
        )
    }

    /// A random minimal state at the last slot of `epoch`: the registry, the checkpoints and
    /// the justification bits. `finality_delay` puts the finalized epoch that many epochs
    /// before the previous epoch (saturating at 0), so a delay above 4 leaks.
    fn random_state(
        validators: &[ValidatorSpec],
        epoch: Epoch,
        finality_delay: u64,
        justified: (u64, u64),
        bits: [bool; 4],
    ) -> BeaconState<Minimal> {
        let balances: Vec<Gwei> = validators.iter().map(|v| v.0 * ETH).collect();
        // No proposer lookahead: a weighted draw over tiny balances takes very long.
        let mut state = registry_state::<Minimal>(&balances, Root::repeat_byte(0x5a));
        state.slot = Minimal::start_slot_at_epoch(epoch + 1) - 1;
        let relative = |offset: i64| epoch.saturating_add_signed(offset);
        for (i, &(_, balance, slashed, (activation, exit, withdrawable), flags, score)) in
            validators.iter().enumerate()
        {
            let v = state.validators.get_mut(i).unwrap();
            v.slashed = slashed;
            v.activation_epoch = epoch.saturating_sub(activation);
            v.exit_epoch = if exit == 3 {
                FAR_FUTURE_EPOCH
            } else {
                relative(exit)
            };
            v.withdrawable_epoch = relative(withdrawable);
            *state.balances.get_mut(i).unwrap() = balance;
            *state.previous_epoch_participation.get_mut(i).unwrap() = flags.0;
            *state.current_epoch_participation.get_mut(i).unwrap() = flags.1;
            *state.inactivity_scores.get_mut(i).unwrap() = score;
        }
        for i in 0..state.block_roots.len() {
            *state.block_roots.get_mut(i).unwrap() = Root::repeat_byte(i as u8 ^ 0xa5);
        }
        let previous = epoch.saturating_sub(1);
        state.finalized_checkpoint = Checkpoint {
            epoch: previous.saturating_sub(finality_delay),
            root: Root::repeat_byte(1),
        };
        let checkpoint = |back: u64| Checkpoint {
            epoch: epoch.saturating_sub(back),
            root: Root::repeat_byte(back as u8),
        };
        state.previous_justified_checkpoint = checkpoint(justified.0);
        state.current_justified_checkpoint = checkpoint(justified.1);
        for (i, bit) in bits.into_iter().enumerate() {
            state.justification_bits.set(i, bit).unwrap();
        }
        state
    }

    /// The three steps as `process_epoch` runs them: one cache for all of them.
    fn cached(state: &mut BeaconState<Minimal>) -> Result<(), StfError> {
        let participation = ParticipationCache::of(state);
        process_justification_and_finalization_with(state, &participation)?;
        process_inactivity_updates_with(state, &participation)?;
        process_rewards_and_penalties_with(state, &participation)
    }

    /// The three steps of the spec text.
    fn spec_literal(state: &mut BeaconState<Minimal>) -> Result<(), StfError> {
        literal::process_justification_and_finalization(state)?;
        literal::process_inactivity_updates(state)?;
        literal::process_rewards_and_penalties(state)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn cached_vs_literal(
            validators in prop::collection::vec(validator_spec(), 1..=48),
            epoch in prop_oneof![1 => 0..=1u64, 6 => 2..=20u64],
            finality_delay in prop_oneof![1 => 0..=4u64, 2 => 5..=12u64],
            justified in (0..=4u64, 0..=3u64),
            bits in any::<[bool; 4]>(),
        ) {
            let pre = random_state(&validators, epoch, finality_delay, justified, bits);

            // Each delta function on the pre-state.
            for flag_index in 0..PARTICIPATION_FLAG_WEIGHTS.len() {
                prop_assert_eq!(
                    get_flag_index_deltas(&pre, flag_index),
                    literal::get_flag_index_deltas(&pre, flag_index)
                );
            }
            prop_assert_eq!(
                get_inactivity_penalty_deltas(&pre),
                literal::get_inactivity_penalty_deltas(&pre)
            );

            // The three steps in a row, with the cache built once before the first.
            let (mut got, mut want) = (pre.clone(), pre.clone());
            let (got_result, want_result) = (cached(&mut got), spec_literal(&mut want));
            prop_assert_eq!(&got_result, &want_result);
            if got_result.is_ok() {
                prop_assert_eq!(state_root(&mut got).unwrap(), state_root(&mut want).unwrap());
            }
            // The public steps, each with its own cache, give the same post-state.
            let mut public = pre;
            let public_result = public_steps(&mut public);
            prop_assert_eq!(&public_result, &want_result);
            if public_result.is_ok() {
                prop_assert_eq!(state_root(&mut public).unwrap(), state_root(&mut want).unwrap());
            }
        }
    }

    /// The three public steps, each with its own cache.
    fn public_steps(state: &mut BeaconState<Minimal>) -> Result<(), StfError> {
        crate::per_epoch::process_justification_and_finalization(state)?;
        crate::per_epoch::process_inactivity_updates(state)?;
        process_rewards_and_penalties(state)
    }

    /// The random states of [`cached_vs_literal`] cover the leak: a fixed one with a finality
    /// delay of 5 leaks, and the cached and the literal rewards agree on it.
    #[test]
    fn a_leaking_state_agrees() {
        let validators: Vec<ValidatorSpec> = (0..32)
            .map(|i| (32, 32 * ETH, i % 7 == 0, (1, 3, 3), (i as u8, 0b011), i))
            .collect();
        let pre = random_state(&validators, 9, 5, (2, 1), [true, false, true, true]);
        assert_eq!(is_in_inactivity_leak(&pre), Ok(true));
        // In a leak, no flag reward is paid, but the penalties are.
        let (rewards, penalties) = get_flag_index_deltas(&pre, TIMELY_TARGET_FLAG_INDEX).unwrap();
        assert!(rewards.iter().all(|r| *r == 0));
        assert!(penalties.iter().any(|p| *p > 0));
        let (mut got, mut want) = (pre.clone(), pre);
        assert_eq!(cached(&mut got), spec_literal(&mut want));
        assert_eq!(state_root(&mut got), state_root(&mut want));
    }
}
