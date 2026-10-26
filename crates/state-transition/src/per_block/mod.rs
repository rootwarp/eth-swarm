//! Block processing: `process_block` (G L1754-1771, Modified in Gloas) and its steps.
//!
//! [`process_block`] runs the eight steps of [`block_steps`] in the order of the spec. The
//! steps that are not ported yet return [`StfError::Unimplemented`] with the work that ports
//! them: the parent payload (`4.6a`), the withdrawals (`4.4a`) and the bid (`4.5`).
//!
//! The steps make no BLS check. The RANDAO reveal, the payload attestation signatures and
//! the sync aggregate signature (and later the other operation signatures) go to the
//! backend as sets, in the one batch of [`crate::signatures::block_signature_sets`], before
//! the steps run. The checks that need no BLS stay in the steps, for example the infinity
//! signature of an empty sync aggregate and the structure of a payload attestation.
//!
//! - [`builder`] has the builder deposit and exit requests.
//! - [`exits`] has `process_voluntary_exit` and `process_bls_to_execution_change`.
//! - [`header`] has `process_block_header`, `process_randao` and `process_eth1_data`.
//! - [`operations`] has the Gloas `process_operations`.
//! - [`payload_attestation`] has `process_payload_attestation` and the indexed form of a
//!   payload attestation.
//! - [`requests`] has `process_consolidation_request` and its helpers.
//! - [`sync_aggregate`] has `process_sync_aggregate`.

pub mod builder;
pub mod exits;
pub mod header;
pub mod operations;
pub mod payload_attestation;
pub mod requests;
pub mod sync_aggregate;

pub use header::{check_block_header, process_block_header, process_eth1_data, process_randao};
pub use operations::process_operations;
pub use payload_attestation::process_payload_attestation;
pub use sync_aggregate::process_sync_aggregate;

use crate::caches::get_beacon_proposer_index;
use crate::{Preset, StfError};
use consensus_types::gloas::{BeaconBlock, BeaconState};
use consensus_types::primitives::{BLSPubkey, Slot, ValidatorIndex};

/// A step of `process_block`, in the order of G L1754-1771.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockStep {
    /// `process_parent_execution_payload` (G L1841, New in Gloas).
    ParentExecutionPayload,
    /// `process_block_header` (P0 L2350-2370).
    BlockHeader,
    /// `process_withdrawals(state)` (Modified in Gloas).
    Withdrawals,
    /// `process_execution_payload_bid` (G L2162-2215, New in Gloas).
    ExecutionPayloadBid,
    /// `process_randao` (P0 L2376-2384).
    Randao,
    /// `process_eth1_data` (P0 L2390-2396).
    Eth1Data,
    /// `process_operations` (G L2228-2263, Modified in Gloas).
    Operations,
    /// `process_sync_aggregate` (A L635-695).
    SyncAggregate,
}

/// What the steps of one block share.
///
/// - `parent_slot`: the slot of `state.latest_block_header` before the block (G L1756),
///   which the operations read. [`process_block_with`] sets it before the first step.
/// - The indices of the current sync committee members (A L684-686), computed at most one
///   time for each block. The signature set and the rewards of the sync aggregate both read
///   them. No step of a Gloas block changes the registry keys or the sync committee, so the
///   indices of the pre-state are the indices that `process_sync_aggregate` computes.
///   The context keeps the indices with the `state.slot` and the
///   `current_sync_committee.aggregate_pubkey` that they are for. It computes them again
///   for a state with another slot or another committee, for example a state on another
///   fork after a sync committee period boundary.
///
/// Use one context for one block on one state, and a new context for the next block.
#[derive(Debug, Default)]
pub struct BlockContext {
    parent_slot: Slot,
    sync_committee_indices: Option<SyncCommitteeIndices>,
    sync_index_scans: usize,
}

/// The sync committee indices of a state, with the key of the state that they are for.
#[derive(Debug)]
struct SyncCommitteeIndices {
    slot: Slot,
    aggregate_pubkey: BLSPubkey,
    indices: Vec<ValidatorIndex>,
}

impl SyncCommitteeIndices {
    /// Whether the indices are for the slot and the current sync committee of `state`.
    fn is_for<E: Preset>(&self, state: &BeaconState<E>) -> bool {
        self.slot == state.slot
            && self.aggregate_pubkey == state.current_sync_committee.aggregate_pubkey
    }
}

impl BlockContext {
    /// The slot of the latest block header before the block.
    pub fn parent_slot(&self) -> Slot {
        self.parent_slot
    }

    /// The validator index of each member of `state.current_sync_committee`
    /// ([`sync_aggregate::sync_committee_indices`]). The first call for a `state.slot` and a
    /// `current_sync_committee.aggregate_pubkey` reads the registry. The later calls for the
    /// same slot and the same committee give the same indices.
    pub fn sync_committee_indices<E: Preset>(
        &mut self,
        state: &BeaconState<E>,
    ) -> Result<&[ValidatorIndex], StfError> {
        let fresh = self
            .sync_committee_indices
            .as_ref()
            .is_some_and(|cached| cached.is_for(state));
        if !fresh {
            self.sync_committee_indices = None;
            self.sync_index_scans += 1;
            let indices = sync_aggregate::sync_committee_indices(state)?;
            self.sync_committee_indices = Some(SyncCommitteeIndices {
                slot: state.slot,
                aggregate_pubkey: state.current_sync_committee.aggregate_pubkey,
                indices,
            });
        }
        Ok(self
            .sync_committee_indices
            .as_ref()
            .map(|cached| cached.indices.as_slice())
            .unwrap_or_default())
    }

    /// The number of registry reads for the sync committee indices.
    #[cfg(test)]
    pub(crate) fn sync_index_scans(&self) -> usize {
        self.sync_index_scans
    }
}

/// One step of [`process_block`].
pub type StepFn<E> =
    fn(&mut BeaconState<E>, &BeaconBlock<E>, &mut BlockContext) -> Result<(), StfError>;

/// The steps of `process_block` (G L1754-1771) in the order that [`process_block`] runs
/// them. A Rust `const` cannot be generic over the preset, so the table is a `const fn`.
pub const fn block_steps<E: Preset>() -> [(BlockStep, StepFn<E>); 8] {
    [
        (
            BlockStep::ParentExecutionPayload,
            parent_execution_payload_step::<E> as StepFn<E>,
        ),
        (BlockStep::BlockHeader, block_header_step::<E> as StepFn<E>),
        (BlockStep::Withdrawals, withdrawals_step::<E> as StepFn<E>),
        (
            BlockStep::ExecutionPayloadBid,
            execution_payload_bid_step::<E> as StepFn<E>,
        ),
        (BlockStep::Randao, randao_step::<E> as StepFn<E>),
        (BlockStep::Eth1Data, eth1_data_step::<E> as StepFn<E>),
        (BlockStep::Operations, operations_step::<E> as StepFn<E>),
        (
            BlockStep::SyncAggregate,
            sync_aggregate_step::<E> as StepFn<E>,
        ),
    ]
}

/// `process_block` (G L1754-1771, Modified in Gloas): runs [`block_steps`] in order and
/// stops at the first error. On `Err`, `state` is partly updated: the caller drops it.
///
/// No BLS check is made here: see the module documentation.
///
/// # Warning
///
/// Do not use this function on real blocks yet. The parent-payload step, the first step,
/// is not ported, so every call returns [`StfError::Unimplemented`], which is not a proof
/// that the block is invalid.
pub fn process_block<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
) -> Result<(), StfError> {
    process_block_with(state, block, &mut BlockContext::default())
}

/// [`process_block`] with a [`BlockContext`] that the caller can share with
/// [`crate::signatures::block_signature_sets_with`] for the same block, so that the sync
/// committee indices are computed one time.
pub fn process_block_with<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    run_steps(state, block, ctx, |_, step, state, block, ctx| {
        step(state, block, ctx)
    })
}

/// Sets `ctx.parent_slot` (G L1756), then calls `call` for each entry of [`block_steps`] in
/// order, until the first error.
fn run_steps<E, F>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    ctx: &mut BlockContext,
    mut call: F,
) -> Result<(), StfError>
where
    E: Preset,
    F: FnMut(
        BlockStep,
        StepFn<E>,
        &mut BeaconState<E>,
        &BeaconBlock<E>,
        &mut BlockContext,
    ) -> Result<(), StfError>,
{
    ctx.parent_slot = state.latest_block_header.slot;
    for (step, step_fn) in block_steps::<E>() {
        call(step, step_fn, state, block, ctx)?;
    }
    Ok(())
}

/// [`process_block`] with each [`StepFn`] replaced by a recorder: the steps in the order that
/// `process_block` runs them, each with the `parent_slot` that it gets. The state does not
/// change.
#[cfg(test)]
pub(crate) fn process_block_traced<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
) -> (Result<(), StfError>, Vec<(BlockStep, Slot)>) {
    let mut trace = Vec::new();
    let mut ctx = BlockContext::default();
    let result = run_steps(state, block, &mut ctx, |step, _, _, _, ctx| {
        trace.push((step, ctx.parent_slot()));
        Ok(())
    });
    (result, trace)
}

/// `get_beacon_proposer_index(state)`, checked against the registry. The index comes from
/// `state.proposer_lookahead`, not from the block, so an index outside the registry is a
/// fault of our own state: `ListIndexOutOfRange`, not a proof that the block is invalid.
pub(crate) fn state_proposer_index<E: Preset>(
    state: &BeaconState<E>,
) -> Result<ValidatorIndex, StfError> {
    let index = get_beacon_proposer_index(state)?;
    if index >= state.validators.len() as u64 {
        return Err(StfError::ListIndexOutOfRange {
            list: "validators",
            index,
        });
    }
    Ok(index)
}

/// `process_parent_execution_payload` (G L1841, New in Gloas). Not ported yet.
fn parent_execution_payload_step<E: Preset>(
    _: &mut BeaconState<E>,
    _: &BeaconBlock<E>,
    _: &mut BlockContext,
) -> Result<(), StfError> {
    Err(StfError::Unimplemented("4.6a"))
}

fn block_header_step<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    _: &mut BlockContext,
) -> Result<(), StfError> {
    process_block_header(state, block)
}

/// `process_withdrawals(state)` (Modified in Gloas: it takes the state only). Not ported yet.
fn withdrawals_step<E: Preset>(
    _: &mut BeaconState<E>,
    _: &BeaconBlock<E>,
    _: &mut BlockContext,
) -> Result<(), StfError> {
    Err(StfError::Unimplemented("4.4a"))
}

/// `process_execution_payload_bid(state, block.body.signed_execution_payload_bid)`
/// (G L2162-2215, New in Gloas). Not ported yet.
fn execution_payload_bid_step<E: Preset>(
    _: &mut BeaconState<E>,
    _: &BeaconBlock<E>,
    _: &mut BlockContext,
) -> Result<(), StfError> {
    Err(StfError::Unimplemented("4.5"))
}

fn randao_step<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    _: &mut BlockContext,
) -> Result<(), StfError> {
    process_randao(state, &block.body)
}

fn eth1_data_step<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    _: &mut BlockContext,
) -> Result<(), StfError> {
    process_eth1_data(state, &block.body)
}

fn operations_step<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    process_operations(state, &block.body, ctx.parent_slot())
}

fn sync_aggregate_step<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    sync_aggregate::process_sync_aggregate_with(state, &block.body.sync_aggregate, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{block_at_state_slot, genesis_state};
    use crate::{per_slot, state_root};
    use consensus_types::Minimal;

    /// The call sequence of G L1754-1771.
    const GLOAS_ORDER: [BlockStep; 8] = [
        BlockStep::ParentExecutionPayload,
        BlockStep::BlockHeader,
        BlockStep::Withdrawals,
        BlockStep::ExecutionPayloadBid,
        BlockStep::Randao,
        BlockStep::Eth1Data,
        BlockStep::Operations,
        BlockStep::SyncAggregate,
    ];

    #[test]
    fn gloas_order() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        per_slot::process_slots(&mut state, 3, &crate::testing::no_bls()).unwrap();
        state.latest_block_header.slot = 2;
        let block = block_at_state_slot(&state).message;
        let before = state_root(&mut state).unwrap();

        // The trace has all 8 steps in the spec order, stubs included. Each step gets the
        // header slot of the pre-state as `parent_slot`.
        let (result, trace) = process_block_traced(&mut state, &block);
        assert_eq!(result, Ok(()));
        let want: Vec<(BlockStep, Slot)> = GLOAS_ORDER.iter().map(|&s| (s, 2)).collect();
        assert_eq!(trace, want);
        assert_eq!(state_root(&mut state).unwrap(), before);

        // The table is the order that `process_block` runs.
        let table: Vec<BlockStep> = block_steps::<Minimal>().iter().map(|(s, _)| *s).collect();
        assert_eq!(table, GLOAS_ORDER);

        // The real run stops at the first stub, before any change to the state.
        assert_eq!(
            process_block(&mut state, &block),
            Err(StfError::Unimplemented("4.6a"))
        );
        assert_eq!(state_root(&mut state).unwrap(), before);
    }

    #[test]
    fn context_computes_the_indices_again_for_another_slot() {
        // Two states at different slots, with other sync committees. One context for both
        // must not give the indices of the first state for the second.
        let mut first = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        per_slot::process_slots(&mut first, 1, &crate::testing::no_bls()).unwrap();
        let mut second = first.clone();
        second.slot = 2;
        second.current_sync_committee.pubkeys[0] = second.validators.get(63).unwrap().pubkey;
        let want_first = sync_aggregate::sync_committee_indices(&first).unwrap();
        let want_second = sync_aggregate::sync_committee_indices(&second).unwrap();
        assert_ne!(want_first, want_second);

        let mut ctx = BlockContext::default();
        assert_eq!(ctx.sync_committee_indices(&first).unwrap(), &want_first[..]);
        assert_eq!(ctx.sync_committee_indices(&first).unwrap(), &want_first[..]);
        assert_eq!(ctx.sync_index_scans(), 1);
        assert_eq!(
            ctx.sync_committee_indices(&second).unwrap(),
            &want_second[..]
        );
        assert_eq!(ctx.sync_index_scans(), 2);
    }

    #[test]
    fn context_computes_the_indices_again_for_another_committee() {
        // Two fork states at the same slot after a sync committee period boundary: each has
        // its own committee, with its own aggregate key. One context for both must not give
        // the indices of the first state for the second.
        let mut first = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        per_slot::process_slots(&mut first, 1, &crate::testing::no_bls()).unwrap();
        let mut second = first.clone();
        second.current_sync_committee.pubkeys[0] = second.validators.get(63).unwrap().pubkey;
        second.current_sync_committee.aggregate_pubkey = [0x77; 48];
        assert_ne!(
            first.current_sync_committee.aggregate_pubkey,
            second.current_sync_committee.aggregate_pubkey
        );
        let want_first = sync_aggregate::sync_committee_indices(&first).unwrap();
        let want_second = sync_aggregate::sync_committee_indices(&second).unwrap();
        assert_ne!(want_first, want_second);

        let mut ctx = BlockContext::default();
        assert_eq!(ctx.sync_committee_indices(&first).unwrap(), &want_first[..]);
        assert_eq!(
            ctx.sync_committee_indices(&second).unwrap(),
            &want_second[..]
        );
        assert_eq!(ctx.sync_index_scans(), 2);
        // The same committee at the same slot needs no new registry read.
        assert_eq!(
            ctx.sync_committee_indices(&second).unwrap(),
            &want_second[..]
        );
        assert_eq!(ctx.sync_index_scans(), 2);
    }

    #[test]
    fn steps_call_their_spec_function() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        per_slot::process_slots(&mut state, 1, &crate::testing::no_bls()).unwrap();
        let block = block_at_state_slot(&state).message;
        let steps = block_steps::<Minimal>();
        let step = |s: BlockStep| steps.iter().find(|(k, _)| *k == s).unwrap().1;
        for (s, id) in [
            (BlockStep::ParentExecutionPayload, "4.6a"),
            (BlockStep::Withdrawals, "4.4a"),
            (BlockStep::ExecutionPayloadBid, "4.5"),
        ] {
            assert_eq!(
                step(s)(&mut state.clone(), &block, &mut BlockContext::default()),
                Err(StfError::Unimplemented(id))
            );
        }
        // The ported steps, in the spec order, apply the block to the state.
        let mut post = state.clone();
        let mut ctx = BlockContext::default();
        for s in [
            BlockStep::BlockHeader,
            BlockStep::Randao,
            BlockStep::Eth1Data,
            BlockStep::Operations,
            BlockStep::SyncAggregate,
        ] {
            assert_eq!(step(s)(&mut post, &block, &mut ctx), Ok(()), "{s:?}");
        }
        assert_eq!(post.latest_block_header.slot, 1);
        assert_eq!(post.eth1_data_votes.len(), 1);
        assert_ne!(post.randao_mixes.get(0), state.randao_mixes.get(0));
        // A second header for the same slot is refused.
        assert_eq!(
            step(BlockStep::BlockHeader)(&mut post, &block, &mut ctx),
            Err(StfError::BlockNotNewer {
                block: 1,
                latest: 1
            })
        );
    }
}
