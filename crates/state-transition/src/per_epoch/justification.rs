//! Justification and finalization (A L730-746, P0 L1963-2002).

use super::participation::ParticipationCache;
use crate::accessors::{get_block_root, get_current_epoch, get_previous_epoch};
use crate::preset::{GENESIS_EPOCH, TIMELY_TARGET_FLAG_INDEX};
use crate::{Preset, StfError};
use consensus_types::common::Checkpoint;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{Epoch, Gwei};

/// The `what` of `target_balance * 3`. The target balance is a sum of our own state, so a
/// failed product is `StateArithmetic`, not a proof.
pub(crate) const JUSTIFICATION_TARGET_BALANCE: &str = "justification target balance";
/// The `what` of `total_active_balance * 2`, also a value of our own state.
pub(crate) const JUSTIFICATION_TOTAL_BALANCE: &str = "justification total balance";

/// `process_justification_and_finalization` (A L730-746, Modified in Altair; Gloas keeps
/// it).
pub fn process_justification_and_finalization<E: Preset>(
    state: &mut BeaconState<E>,
) -> Result<(), StfError> {
    if skips_ffg(state) {
        return Ok(());
    }
    let participation = ParticipationCache::of(state);
    process_justification_and_finalization_with(state, &participation)
}

/// [`process_justification_and_finalization`] with the balances of `participation`, which
/// must be the cache of `state` at this epoch boundary.
pub(crate) fn process_justification_and_finalization_with<E: Preset>(
    state: &mut BeaconState<E>,
    participation: &ParticipationCache,
) -> Result<(), StfError> {
    // Initial FFG checkpoint values have a `0x00` stub for `root`.
    // Skip FFG updates in the first two epochs to avoid corner cases that might result in
    // modifying this stub.
    if skips_ffg(state) {
        return Ok(());
    }
    // The spec reads both participation lists, then the total active balance, then the two
    // target sums. A short list is not a proof, so it must fail before a sum that overflows.
    participation.previous_participation()?;
    participation.current_participation()?;
    let total_active_balance = participation.total_active_balance()?;
    let previous_target_balance = participation.previous_flag_balance(TIMELY_TARGET_FLAG_INDEX)?;
    let current_target_balance = participation.current_target_balance()?;
    weigh_justification_and_finalization(
        state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}

/// `get_current_epoch(state) <= GENESIS_EPOCH + 1`.
pub(crate) fn skips_ffg<E: Preset>(state: &BeaconState<E>) -> bool {
    get_current_epoch(state) <= GENESIS_EPOCH + 1
}

/// `weigh_justification_and_finalization` (P0 L1963-2002).
pub fn weigh_justification_and_finalization<E: Preset>(
    state: &mut BeaconState<E>,
    total_active_balance: Gwei,
    previous_epoch_target_balance: Gwei,
    current_epoch_target_balance: Gwei,
) -> Result<(), StfError> {
    let previous_epoch = get_previous_epoch(state);
    let current_epoch = get_current_epoch(state);
    let old_previous_justified_checkpoint = state.previous_justified_checkpoint.clone();
    let old_current_justified_checkpoint = state.current_justified_checkpoint.clone();

    // Process justifications
    state.previous_justified_checkpoint = state.current_justified_checkpoint.clone();
    let mut bits = [false; 4];
    for (i, bit) in bits.iter_mut().enumerate().skip(1) {
        *bit = justification_bit(state, i - 1)?;
    }
    let two_thirds = |balance: Gwei| -> Result<bool, StfError> {
        let lhs = balance.checked_mul(3).ok_or(StfError::StateArithmetic {
            what: JUSTIFICATION_TARGET_BALANCE,
        })?;
        let rhs = total_active_balance
            .checked_mul(2)
            .ok_or(StfError::StateArithmetic {
                what: JUSTIFICATION_TOTAL_BALANCE,
            })?;
        Ok(lhs >= rhs)
    };
    if two_thirds(previous_epoch_target_balance)? {
        state.current_justified_checkpoint = Checkpoint {
            epoch: previous_epoch,
            root: get_block_root(state, previous_epoch)?,
        };
        bits[1] = true;
    }
    if two_thirds(current_epoch_target_balance)? {
        state.current_justified_checkpoint = Checkpoint {
            epoch: current_epoch,
            root: get_block_root(state, current_epoch)?,
        };
        bits[0] = true;
    }
    for (i, bit) in bits.iter().enumerate() {
        state
            .justification_bits
            .set(i, *bit)
            .map_err(|_| StfError::BitOutOfRange { index: i, len: 4 })?;
    }

    // Process finalizations
    // The spec evaluates `checkpoint.epoch + k` only when the bits hold, and a `Uint64`
    // overflow raises.
    // Kept a proof: the epoch_processing runner accepts this crafted pre-state only as a proof.
    let source_is = |checkpoint: &Checkpoint, k: Epoch| -> Result<bool, StfError> {
        Ok(checkpoint
            .epoch
            .checked_add(k)
            .ok_or(StfError::ArithmeticOverflow)?
            == current_epoch)
    };
    // The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if bits[1..4].iter().all(|b| *b) && source_is(&old_previous_justified_checkpoint, 3)? {
        state.finalized_checkpoint = old_previous_justified_checkpoint.clone();
    }
    // The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if bits[1..3].iter().all(|b| *b) && source_is(&old_previous_justified_checkpoint, 2)? {
        state.finalized_checkpoint = old_previous_justified_checkpoint;
    }
    // The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if bits[0..3].iter().all(|b| *b) && source_is(&old_current_justified_checkpoint, 2)? {
        state.finalized_checkpoint = old_current_justified_checkpoint.clone();
    }
    // The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if bits[0..2].iter().all(|b| *b) && source_is(&old_current_justified_checkpoint, 1)? {
        state.finalized_checkpoint = old_current_justified_checkpoint;
    }
    Ok(())
}

/// `state.justification_bits[index]`.
fn justification_bit<E: Preset>(state: &BeaconState<E>, index: usize) -> Result<bool, StfError> {
    state
        .justification_bits
        .get(index)
        .map_err(|_| StfError::BitOutOfRange { index, len: 4 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::genesis_state;
    use consensus_types::primitives::Root;
    use consensus_types::{EthSpec, Minimal};

    const ETH: Gwei = 1_000_000_000;

    /// A minimal state at the last slot of epoch 6, with block root `i` at slot `i`.
    fn state_at_epoch_6() -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
        state.slot = Minimal::start_slot_at_epoch(7) - 1;
        for i in 0..state.block_roots.len() {
            *state.block_roots.get_mut(i).unwrap() = Root::repeat_byte(i as u8);
        }
        state
    }

    fn set_bits(state: &mut BeaconState<Minimal>, bits: [bool; 4]) {
        for (i, bit) in bits.into_iter().enumerate() {
            state.justification_bits.set(i, bit).unwrap();
        }
    }

    fn bits(state: &BeaconState<Minimal>) -> [bool; 4] {
        std::array::from_fn(|i| state.justification_bits.get(i).unwrap())
    }

    fn checkpoint(epoch: Epoch) -> Checkpoint {
        Checkpoint {
            epoch,
            root: Root::repeat_byte(epoch as u8),
        }
    }

    #[test]
    fn justifies_the_epochs_with_two_thirds_of_the_balance() {
        let mut state = state_at_epoch_6();
        set_bits(&mut state, [true, false, true, false]);
        // 2/3 exactly justifies; one Gwei less does not.
        weigh_justification_and_finalization(&mut state, 3 * ETH, 2 * ETH, 2 * ETH - 1).unwrap();
        assert_eq!(bits(&state), [false, true, false, true]);
        assert_eq!(state.current_justified_checkpoint.epoch, 5);
        // Epoch 5 starts at slot 40.
        assert_eq!(
            state.current_justified_checkpoint.root,
            Root::repeat_byte(40)
        );
        assert_eq!(state.previous_justified_checkpoint.epoch, 0);

        weigh_justification_and_finalization(&mut state, 3 * ETH, 0, 2 * ETH).unwrap();
        assert_eq!(bits(&state), [true, false, true, false]);
        assert_eq!(state.current_justified_checkpoint.epoch, 6);
        assert_eq!(
            state.current_justified_checkpoint.root,
            Root::repeat_byte(48)
        );
        assert_eq!(state.previous_justified_checkpoint.epoch, 5);
    }

    #[test]
    fn the_four_finalization_rules() {
        // (bits before, previous justified, current justified, finalized after), at epoch 6
        // with both epochs justified. The bits shift by one before the rules look at them.
        for (before, previous, current, finalized) in [
            // 2nd/3rd/4th justified, the 2nd using the 4th as source: epoch 3.
            ([false, true, true, false], 3, 0, 3),
            // 2nd/3rd justified, the 2nd using the 3rd as source: epoch 4.
            ([false, true, false, false], 4, 0, 4),
            // 1st/2nd/3rd justified, the 1st using the 3rd as source: epoch 4.
            ([false, true, false, false], 0, 4, 4),
            // 1st/2nd justified, the 1st using the 2nd as source: epoch 5.
            ([false, false, false, false], 0, 5, 5),
            // A source epoch that does not match finalizes nothing.
            ([true, true, true, true], 1, 1, 0),
        ] {
            let mut state = state_at_epoch_6();
            set_bits(&mut state, before);
            state.previous_justified_checkpoint = checkpoint(previous);
            state.current_justified_checkpoint = checkpoint(current);
            weigh_justification_and_finalization(&mut state, 3 * ETH, 3 * ETH, 3 * ETH).unwrap();
            assert_eq!(
                state.finalized_checkpoint.epoch, finalized,
                "{before:?} {previous} {current}"
            );
        }
    }

    #[test]
    fn overflows_raise() {
        let mut state = state_at_epoch_6();
        // The balances come from our own state, so their products are not a proof.
        let err =
            weigh_justification_and_finalization(&mut state.clone(), u64::MAX, 0, 0).unwrap_err();
        assert_eq!(
            err,
            StfError::StateArithmetic {
                what: JUSTIFICATION_TOTAL_BALANCE
            }
        );
        assert!(!err.proves_invalid());
        let err =
            weigh_justification_and_finalization(&mut state.clone(), ETH, u64::MAX, 0).unwrap_err();
        assert_eq!(
            err,
            StfError::StateArithmetic {
                what: JUSTIFICATION_TARGET_BALANCE
            }
        );
        assert!(!err.proves_invalid());
        let err =
            weigh_justification_and_finalization(&mut state.clone(), ETH, 0, u64::MAX).unwrap_err();
        assert_eq!(
            err,
            StfError::StateArithmetic {
                what: JUSTIFICATION_TARGET_BALANCE
            }
        );
        assert_eq!(
            err.to_string(),
            "state arithmetic failed: justification target balance"
        );
        // `epoch + 3` is evaluated once the bits hold.
        set_bits(&mut state, [true, true, true, false]);
        state.previous_justified_checkpoint = checkpoint(u64::MAX);
        assert_eq!(
            weigh_justification_and_finalization(&mut state, 3 * ETH, 0, 0),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn reads_both_participation_lists_before_the_sums() {
        // The previous target sum overflows, and `current_epoch_participation` is shorter
        // than the registry. The spec reads both lists before it adds a balance, so the
        // short list fails first, and that error is not a proof.
        let mut state = state_at_epoch_6();
        for i in 0..8 {
            state.validators.get_mut(i).unwrap().effective_balance = u64::MAX;
            *state.previous_epoch_participation.get_mut(i).unwrap() = 0b111;
        }
        state.current_epoch_participation = milhouse::ProgressiveList::default();
        let want = Err(StfError::ListIndexOutOfRange {
            list: "current_epoch_participation",
            index: 0,
        });
        assert_eq!(
            super::super::literal::process_justification_and_finalization(&mut state.clone()),
            want
        );
        assert_eq!(process_justification_and_finalization(&mut state), want);
    }

    #[test]
    fn the_first_two_epochs_are_skipped() {
        for epoch in [0, 1] {
            let mut state = genesis_state::<Minimal>(&[32 * ETH; 8]);
            state.slot = Minimal::start_slot_at_epoch(epoch + 1) - 1;
            // Full participation would justify, but the step does not run.
            for i in 0..8 {
                *state.current_epoch_participation.get_mut(i).unwrap() = 0b111;
            }
            let before = state.clone();
            process_justification_and_finalization(&mut state).unwrap();
            assert_eq!(state, before);
        }
        let mut state = state_at_epoch_6();
        for i in 0..8 {
            *state.current_epoch_participation.get_mut(i).unwrap() = 0b111;
        }
        process_justification_and_finalization(&mut state).unwrap();
        assert_eq!(bits(&state), [true, false, false, false]);
        assert_eq!(state.current_justified_checkpoint.epoch, 6);
    }
}
