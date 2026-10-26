//! Block processing: `process_block` (G L1754-1771, Modified in Gloas) and its steps.
//!
//! [`process_block`] runs the eight steps of [`block_steps`] in the order of the spec.
//!
//! The steps make no BLS check. The RANDAO reveal, the bid signature of a builder, the
//! operation signatures, the payload attestation signatures and the sync aggregate signature
//! go to the backend as sets, in the one batch of
//! [`crate::signatures::block_signature_sets`], before the steps run. The checks that need
//! no BLS stay in the steps, for example the infinity signature of an empty sync aggregate,
//! the self-build rules of a bid and the structure of a payload attestation.
//!
//! - [`attestation`] has the Gloas `process_attestation` and its helpers.
//! - [`bid`] has `process_execution_payload_bid` and the [`bid::BlobSchedule`] seam.
//! - [`builder`] has the builder deposit and exit requests.
//! - [`exits`] has `process_voluntary_exit` and `process_bls_to_execution_change`.
//! - [`header`] has `process_block_header`, `process_randao` and `process_eth1_data`.
//! - [`operations`] has the Gloas `process_operations`.
//! - [`parent_payload`] has `process_parent_execution_payload` and
//!   `apply_parent_execution_payload`: the builder payment and the execution requests of
//!   the parent payload.
//! - [`payload_attestation`] has `process_payload_attestation` and the indexed form of a
//!   payload attestation.
//! - [`requests`] has `process_deposit_request`, `process_withdrawal_request` and
//!   `process_consolidation_request`, with their helpers.
//! - [`slashings`] has `process_proposer_slashing` and `process_attester_slashing`.
//! - [`sync_aggregate`] has `process_sync_aggregate`.
//! - [`withdrawals`] has the Gloas `process_withdrawals(state)` and the withdrawals sweep.

pub mod attestation;
pub mod bid;
pub mod builder;
pub mod exits;
pub mod header;
pub mod operations;
pub mod parent_payload;
pub mod payload_attestation;
pub mod requests;
pub mod slashings;
pub mod sync_aggregate;
pub mod withdrawals;

pub use attestation::process_attestation_with;
pub use bid::process_execution_payload_bid;
pub use header::{check_block_header, process_block_header, process_eth1_data, process_randao};
pub use operations::process_operations;
pub use parent_payload::process_parent_execution_payload;
pub use payload_attestation::process_payload_attestation;
pub use slashings::{process_attester_slashing, process_proposer_slashing};
pub use sync_aggregate::process_sync_aggregate;
pub use withdrawals::process_withdrawals;

use crate::accessors::{get_current_epoch, TotalActiveBalanceCache};
use crate::caches::get_beacon_proposer_index;
use crate::caches::CommitteeCache;
use crate::{Preset, SignatureBackend, StfError};
use consensus_types::gloas::{BeaconBlock, BeaconState};
use consensus_types::primitives::{BLSPubkey, Epoch, Slot, ValidatorIndex, Version};
use std::fmt;

/// A step of `process_block`, in the order of G L1754-1771.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockStep {
    /// `process_parent_execution_payload` (G L1841, New in Gloas).
    ParentExecutionPayload,
    /// `process_block_header` (P0 L2350-2370).
    BlockHeader,
    /// `process_withdrawals(state)` (G L2067-2092, Modified in Gloas).
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
/// - The beacon committees of each attestation epoch, shuffled at most one time for each
///   block: the attestation sets and `process_attestation` read them. The attestations of a
///   block are of the previous or the current epoch, so the context keeps at most two.
/// - The total active balance, which the attestation rewards and `slash_validator` read.
/// - The blob limit of the network for the epoch of the block, which the bid step reads
///   ([`BlockContext::set_max_blobs_per_block`]). [`crate::state_transition`] sets it from
///   [`crate::BlsContext::blob_schedule`]. A context without it fails the bid step with
///   [`StfError::UnknownBlobLimit`], which is not a proof that the block is invalid.
/// - The verdicts of the builder deposit signatures of the parent payload, which the parent
///   payload step reads ([`BlockContext::set_deposit_verdicts`]). [`crate::state_transition`]
///   sets them from [`crate::BlsContext::backend`] and
///   [`crate::BlsContext::genesis_fork_version`]. With a context without them, a builder
///   deposit that needs a verdict gives [`StfError::MissingVerdict`], which is not a proof.
///
/// Use one context for one block on one state, and a new context for the next block. A
/// committee cache of another state with another seed is not used:
/// [`crate::accessors::get_attesting_indices_with`] gives `CacheSeedMismatch` for it. A state
/// with the same seed and another registry length gets its own shuffle.
#[derive(Debug, Default)]
pub struct BlockContext<'a> {
    parent_slot: Slot,
    sync_committee_indices: Option<SyncCommitteeIndices>,
    sync_index_scans: usize,
    committee_caches: Vec<CommitteeCache>,
    total_active_balance: TotalActiveBalanceCache,
    max_blobs_per_block: Option<(Epoch, u64)>,
    deposit_verdicts: Option<DepositVerdicts<'a>>,
}

/// The source of the verdicts of the builder deposit signatures: the backend, and the
/// `GENESIS_FORK_VERSION` of the network for the deposit domain.
#[derive(Clone, Copy)]
pub(crate) struct DepositVerdicts<'a> {
    pub(crate) backend: &'a dyn SignatureBackend,
    pub(crate) genesis_fork_version: Version,
}

impl fmt::Debug for DepositVerdicts<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DepositVerdicts")
            .field("genesis_fork_version", &self.genesis_fork_version)
            .finish_non_exhaustive()
    }
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

impl<'a> BlockContext<'a> {
    /// Sets the source of the verdicts of the builder deposit signatures of the parent
    /// payload: `backend`, and `genesis_fork_version`, the `GENESIS_FORK_VERSION` of the
    /// network (see [`builder::builder_deposit_signature_set`]).
    pub fn set_deposit_verdicts(
        &mut self,
        backend: &'a dyn SignatureBackend,
        genesis_fork_version: Version,
    ) {
        self.deposit_verdicts = Some(DepositVerdicts {
            backend,
            genesis_fork_version,
        });
    }

    /// The source that [`Self::set_deposit_verdicts`] set, if any.
    pub(crate) fn deposit_verdicts(&self) -> Option<DepositVerdicts<'a>> {
        self.deposit_verdicts
    }
}

impl BlockContext<'_> {
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

    /// The beacon committees of `epoch` on `state`. The first call for an epoch and a
    /// registry length shuffles the epoch, and the later calls give the same cache.
    ///
    /// The key holds the registry length, because the attester seed alone does not identify
    /// the active set. A state with the same seed and another registry gets a new shuffle.
    /// Thus the committees of a longer registry never give an index past the registry of
    /// `state`, which would be [`StfError::UnknownValidator`], a proof, for a fault of our
    /// own state. [`CommitteeCache::check_state`] refuses a cache with another seed or
    /// another registry length.
    ///
    /// Call it only for the previous or the current epoch of `state`: the cache of another
    /// epoch costs a shuffle, and the spec reads no committee of it.
    pub fn committee_cache<E: Preset>(
        &mut self,
        state: &BeaconState<E>,
        epoch: Epoch,
    ) -> Result<&CommitteeCache, StfError> {
        let registry_len = state.validators.len() as u64;
        let position = match self
            .committee_caches
            .iter()
            .position(|cache| cache.key().0 == epoch && cache.registry_len() == registry_len)
        {
            Some(position) => position,
            None => {
                self.committee_caches
                    .push(CommitteeCache::new(state, epoch)?);
                self.committee_caches.len() - 1
            }
        };
        Ok(&self.committee_caches[position])
    }

    /// The number of shuffles for the committee caches.
    #[cfg(test)]
    pub(crate) fn committee_shuffles(&self) -> usize {
        self.committee_caches.len()
    }

    /// The total active balance cache of the block.
    pub fn total_active_balance(&mut self) -> &mut TotalActiveBalanceCache {
        &mut self.total_active_balance
    }

    /// Sets the blob limit of the network for `epoch`:
    /// `get_blob_parameters(epoch).max_blobs_per_block` (Fu L293-300).
    pub fn set_max_blobs_per_block(&mut self, epoch: Epoch, max_blobs_per_block: u64) {
        self.max_blobs_per_block = Some((epoch, max_blobs_per_block));
    }

    /// The blob limit that [`Self::set_max_blobs_per_block`] set for `epoch`.
    /// [`StfError::UnknownBlobLimit`] if it set none, or set it for another epoch.
    pub fn max_blobs_per_block(&self, epoch: Epoch) -> Result<u64, StfError> {
        match self.max_blobs_per_block {
            Some((limit_epoch, max)) if limit_epoch == epoch => Ok(max),
            _ => Err(StfError::UnknownBlobLimit(epoch)),
        }
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
/// The context of this function has no blob limit and no deposit verdicts, so the bid step
/// gives [`StfError::UnknownBlobLimit`], and a builder deposit of a new key gives
/// [`StfError::MissingVerdict`]. Use [`process_block_with`] with a context that has them.
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

/// `process_parent_execution_payload(state, block)` (G L1841-1853, New in Gloas), with the
/// total active balance and the deposit verdicts of `ctx`.
fn parent_execution_payload_step<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    parent_payload::process_parent_execution_payload_with(state, block, ctx)
}

fn block_header_step<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    _: &mut BlockContext,
) -> Result<(), StfError> {
    process_block_header(state, block)
}

/// `process_withdrawals(state)` (G L2067-2092, Modified in Gloas: it takes the state only).
fn withdrawals_step<E: Preset>(
    state: &mut BeaconState<E>,
    _: &BeaconBlock<E>,
    _: &mut BlockContext,
) -> Result<(), StfError> {
    process_withdrawals(state)
}

/// `process_execution_payload_bid(state, block.body.signed_execution_payload_bid)`
/// (G L2162-2215, New in Gloas), with the blob limit of `ctx` for the current epoch. The
/// batch of the block checked the signature of a builder bid before the steps.
fn execution_payload_bid_step<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    let max_blobs_per_block = ctx.max_blobs_per_block(get_current_epoch(state))?;
    bid::process_execution_payload_bid(
        state,
        &block.body.signed_execution_payload_bid,
        max_blobs_per_block,
    )
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
    operations::process_operations_with(state, &block.body, ctx)
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
    use crate::testing::{bid_for_state, block_at_state_slot, genesis_state};
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

        // The trace has all 8 steps in the spec order. Each step gets the
        // header slot of the pre-state as `parent_slot`.
        let (result, trace) = process_block_traced(&mut state, &block);
        assert_eq!(result, Ok(()));
        let want: Vec<(BlockStep, Slot)> = GLOAS_ORDER.iter().map(|&s| (s, 2)).collect();
        assert_eq!(trace, want);
        assert_eq!(state_root(&mut state).unwrap(), before);

        // The table is the order that `process_block` runs.
        let table: Vec<BlockStep> = block_steps::<Minimal>().iter().map(|(s, _)| *s).collect();
        assert_eq!(table, GLOAS_ORDER);

        // The real run has no stub. A context without the blob limit of the network stops
        // it at the bid step, after the parent payload and the header.
        assert_eq!(
            process_block(&mut state, &block),
            Err(StfError::UnknownBlobLimit(0))
        );
        assert_eq!(state.latest_block_header.slot, 3);
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
    fn context_shuffles_again_for_a_shorter_registry() {
        use crate::per_block::attestation::tests::{attestation, attestation_state};
        use crate::signatures::attestation_signature_set_with;

        // Two states with the same attester seed of epoch 0: 64 validators, and the first
        // 32 of them. The committees of the first state hold indices past the second
        // registry. One context for both must not give them for the second state.
        let long = attestation_state(4);
        let mut short = genesis_state::<Minimal>(&[32_000_000_000; 32]);
        short.slot = long.slot;
        short.block_roots = long.block_roots.clone();
        let seed = |state: &BeaconState<Minimal>| CommitteeCache::new(state, 0).unwrap().key();
        assert_eq!(seed(&long), seed(&short));

        let mut ctx = BlockContext::default();
        let on_long = attestation(&long, 3, &[0, 1, 2, 3]);
        assert!(attestation_signature_set_with(&long, &on_long, &mut ctx).is_ok());
        let on_short = attestation(&short, 3, &[0, 1, 2, 3]);
        let want = attestation_signature_set_with(&short, &on_short, &mut BlockContext::default());
        assert!(want.is_ok());
        assert_eq!(
            attestation_signature_set_with(&short, &on_short, &mut ctx),
            want
        );
        assert_eq!(
            ctx.committee_cache(&short, 0).unwrap(),
            &CommitteeCache::new(&short, 0).unwrap()
        );
        assert_eq!(ctx.committee_shuffles(), 2);
        // The first state still reads its own committees, with no new shuffle.
        assert_eq!(
            ctx.committee_cache(&long, 0).unwrap(),
            &CommitteeCache::new(&long, 0).unwrap()
        );
        assert_eq!(ctx.committee_shuffles(), 2);
    }

    #[test]
    fn steps_call_their_spec_function() {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        per_slot::process_slots(&mut state, 1, &crate::testing::no_bls()).unwrap();
        let mut block = block_at_state_slot(&state).message;
        block.body.signed_execution_payload_bid =
            bid_for_state(&state, crate::preset::BUILDER_INDEX_SELF_BUILD, 0);
        let steps = block_steps::<Minimal>();
        let step = |s: BlockStep| steps.iter().find(|(k, _)| *k == s).unwrap().1;
        // The steps, in the spec order, apply the block to the state.
        let mut post = state.clone();
        let mut ctx = BlockContext::default();
        ctx.set_max_blobs_per_block(0, crate::testing::MINIMAL_MAX_BLOBS_PER_BLOCK);
        for s in [
            BlockStep::ParentExecutionPayload,
            BlockStep::BlockHeader,
            BlockStep::Withdrawals,
            BlockStep::ExecutionPayloadBid,
            BlockStep::Randao,
            BlockStep::Eth1Data,
            BlockStep::Operations,
            BlockStep::SyncAggregate,
        ] {
            assert_eq!(step(s)(&mut post, &block, &mut ctx), Ok(()), "{s:?}");
        }
        assert_eq!(post.latest_block_header.slot, 1);
        // The parent (the genesis block) is FULL with no requests: its payload is available.
        assert!(post.execution_payload_availability.get(0).unwrap());
        assert_eq!(
            post.latest_execution_payload_bid,
            block.body.signed_execution_payload_bid.message
        );
        assert_eq!(post.eth1_data_votes.len(), 1);
        assert_ne!(post.randao_mixes.get(0), state.randao_mixes.get(0));
        // The parent is FULL, and no validator can withdraw (0x00 credentials): the sweep
        // moves its cursor by `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` (16 of 64).
        assert_eq!(post.next_withdrawal_validator_index, 16);
        // A second header for the same slot is refused.
        assert_eq!(
            step(BlockStep::BlockHeader)(&mut post, &block, &mut ctx),
            Err(StfError::BlockNotNewer {
                block: 1,
                latest: 1
            })
        );
    }

    #[test]
    fn builder_requests_wired() {
        use crate::per_block::builder::{
            process_builder_deposit_request, process_builder_exit_request,
        };
        use crate::testing::{
            builder, builder_deposit_request, builder_exit_request, empty_requests,
            ScriptedBackend, GENESIS_FORK_VERSION, MINIMAL_MAX_BLOBS_PER_BLOCK,
        };
        use crate::Preset;
        use tree_hash::TreeHash;

        // Slot 1 of a state finalized at epoch 1, with the builders `[0xa1; 48]` and
        // `[0xa2; 48]`, both active. The genesis parent is FULL, and its bid committed one
        // builder deposit of a new key and one builder exit of builder 0.
        let mut pre = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        per_slot::process_slots(&mut pre, 1, &crate::testing::no_bls()).unwrap();
        pre.finalized_checkpoint.epoch = 1;
        for key in [0xa1, 0xa2] {
            pre.builders.push(builder(key, 5_000_000_000, 0)).unwrap();
        }
        let deposit = builder_deposit_request(0xc1, 2_000_000_000);
        let exit = builder_exit_request(0xa1);
        let mut requests = empty_requests::<Minimal>();
        requests.builder_deposits.push(deposit.clone()).unwrap();
        requests.builder_exits.push(exit.clone()).unwrap();
        pre.latest_execution_payload_bid.execution_requests_root = requests.tree_hash_root();
        let mut block = block_at_state_slot(&pre).message;
        block.body.signed_execution_payload_bid =
            bid_for_state(&pre, crate::preset::BUILDER_INDEX_SELF_BUILD, 0);
        block.body.parent_execution_requests = requests;

        // The whole block, with the verdict of the new builder from the context.
        let mut post = pre.clone();
        let backend = ScriptedBackend::new([Ok(true)]);
        let mut ctx = BlockContext::default();
        ctx.set_max_blobs_per_block(0, MINIMAL_MAX_BLOBS_PER_BLOCK);
        ctx.set_deposit_verdicts(&backend, GENESIS_FORK_VERSION);
        assert_eq!(process_block_with(&mut post, &block, &mut ctx), Ok(()));

        // The builder functions called directly on the pre-state, in the spec order.
        let mut direct = pre.clone();
        let direct_backend = ScriptedBackend::new([Ok(true)]);
        process_builder_deposit_request(
            &mut direct,
            &deposit,
            GENESIS_FORK_VERSION,
            &direct_backend,
        )
        .unwrap();
        process_builder_exit_request(&mut direct, &exit).unwrap();

        let builders =
            |state: &BeaconState<Minimal>| state.builders.iter().cloned().collect::<Vec<_>>();
        assert_eq!(builders(&post), builders(&direct));
        assert_eq!(backend.seen(), direct_backend.seen());
        // Both requests changed the registry: a new builder at index 2, and the exit of
        // builder 0.
        assert_eq!(post.builders.len(), 3);
        assert_eq!(post.builders.get(2).unwrap().pubkey, [0xc1; 48]);
        assert_eq!(
            post.builders.get(0).unwrap().withdrawable_epoch,
            Minimal::MIN_BUILDER_WITHDRAWABILITY_DELAY
        );
    }
}
