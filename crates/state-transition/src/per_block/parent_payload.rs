//! The deferred payload of the parent block: `process_parent_execution_payload` (G
//! L1841-1853, New in Gloas) and `apply_parent_execution_payload` (G L1784-1830, New in
//! Gloas).
//!
//! Gloas processes the execution payload of a block in the next block. The child block
//! carries the execution requests of its parent's payload (`parent_execution_requests`). If
//! the bid of the child builds on the block hash of the parent bid, the parent is FULL: the
//! requests must hash to the `execution_requests_root` that the parent bid committed to.
//! Then the parent's builder payment is settled, the requests are applied at the slot of the
//! child, and the parent payload becomes available. If the parent is EMPTY, the block must
//! carry no request, and the step changes nothing.
//!
//! The step reads the child block only. The envelope, the execution engine and the data
//! availability checks of the parent payload are outside the pure transition.
//!
//! # Builder deposit verdicts
//!
//! A builder deposit request for a key that no builder has registers a builder only with a
//! valid proof of possession ([`super::builder::process_builder_deposit_request`]). The
//! verdict comes from the backend of the [`BlockContext`]
//! ([`BlockContext::set_deposit_verdicts`]). Before the transition of a block, prefetch a
//! verdict for [`super::builder::builder_deposit_signature_set`] of each request in
//! `block.body.parent_execution_requests.builder_deposits` whose withdrawal credentials have
//! the `BUILDER_WITHDRAWAL_PREFIX`. Do not use the pre-state to select fewer requests: an
//! earlier request of the same payload can change the registry. A missing verdict gives
//! [`StfError::MissingVerdict`], which is not a proof that the block is invalid.

use crate::accessors::{get_current_epoch, get_previous_epoch};
use crate::mutators::settle_builder_payment;
use crate::per_block::builder::{process_builder_deposit_request, process_builder_exit_request};
use crate::per_block::requests::{
    process_consolidation_request, process_deposit_request, process_withdrawal_request,
};
use crate::per_block::BlockContext;
use crate::{BackendError, Preset, SignatureBackend, SignatureSet, StfError};
use consensus_types::gloas::{
    BeaconBlock, BeaconState, BuilderPendingWithdrawal, ExecutionRequests,
};
use consensus_types::primitives::Version;
use ssz_types::typenum::Unsigned;
use tree_hash::TreeHash;

/// Records `step` in the test-only trace of the steps of `apply_parent_execution_payload`.
/// It does nothing outside the tests.
fn trace(_step: &'static str) {
    #[cfg(test)]
    tests::TRACE.with(|trace| trace.borrow_mut().push(_step));
}

/// The backend of a [`BlockContext`] without a source of deposit verdicts: each call gives
/// `Err`, which the builder deposit maps to [`StfError::MissingVerdict`].
struct NoDepositVerdicts;

impl SignatureBackend for NoDepositVerdicts {
    fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
        Err(BackendError(
            "the block context has no source of deposit verdicts".into(),
        ))
    }
}

/// `process_parent_execution_payload` (G L1841-1853, New in Gloas), with the verdicts of
/// the builder deposits from `backend` and the deposit domain of `genesis_fork_version`
/// (the `GENESIS_FORK_VERSION` of the network). See the module documentation for the
/// verdicts to prefetch.
///
/// Call it before `process_execution_payload_bid`, which overwrites
/// `state.latest_execution_payload_bid`. On `Err`, `state` is partly updated: the caller
/// drops it.
pub fn process_parent_execution_payload<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let mut ctx = BlockContext::default();
    ctx.set_deposit_verdicts(backend, genesis_fork_version);
    process_parent_execution_payload_with(state, block, &mut ctx)
}

/// [`process_parent_execution_payload`] with the [`BlockContext`] of the block: its total
/// active balance cache and its source of deposit verdicts.
///
/// - EMPTY parent (`bid.parent_block_hash != parent_bid.block_hash`): the block must carry
///   no request ([`StfError::ParentRequestsNotEmpty`]), and the state does not change.
/// - FULL parent: the requests must hash to `parent_bid.execution_requests_root`
///   ([`StfError::ParentRequestsRootMismatch`]) before anything is applied. Then
///   [`apply_parent_execution_payload`] runs.
pub fn process_parent_execution_payload_with<E: Preset>(
    state: &mut BeaconState<E>,
    block: &BeaconBlock<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    let bid = &block.body.signed_execution_payload_bid.message;
    let parent_bid = &state.latest_execution_payload_bid;
    let requests = &block.body.parent_execution_requests;

    if bid.parent_block_hash != parent_bid.block_hash {
        // Parent was EMPTY -- no execution requests expected
        if !is_empty(requests) {
            return Err(StfError::ParentRequestsNotEmpty);
        }
        return Ok(());
    }

    // Parent was FULL -- verify the bid commitment and apply the payload
    let requests_root = requests.tree_hash_root();
    if requests_root != parent_bid.execution_requests_root {
        return Err(StfError::ParentRequestsRootMismatch {
            block: requests_root,
            expected: parent_bid.execution_requests_root,
        });
    }
    apply_parent_execution_payload(state, requests, ctx)
}

/// `requests == ExecutionRequests.empty()`: no request of any kind.
fn is_empty<E: Preset>(requests: &ExecutionRequests<E>) -> bool {
    requests.deposits.is_empty()
        && requests.withdrawals.is_empty()
        && requests.consolidations.is_empty()
        && requests.builder_deposits.is_empty()
        && requests.builder_exits.is_empty()
}

/// `apply_parent_execution_payload` (G L1784-1830, New in Gloas): settles the builder
/// payment of the parent, applies the requests of the parent payload at the slot of the
/// state, marks the parent payload available, and makes its block hash the latest one.
///
/// The settlement comes before the first request (G L1797-1804, consensus-specs PR 5695),
/// so that a builder exit request is ignored while the payment of the builder is pending.
/// A parent older than the previous epoch has no payment entry any more: its bid value goes
/// to `state.builder_pending_withdrawals` directly.
///
/// The count asserts of G L1792-1795 hold by construction: the list types of
/// [`ExecutionRequests`] bound each count at decode to the same `MAX_*_REQUESTS_PER_PAYLOAD`
/// preset values ([`StfError::ParentRequestsPastLimit`]).
///
/// `ctx` gives the total active balance of the churn, and the verdicts of the builder
/// deposits (see the module documentation). On `Err`, `state` is partly updated: the caller
/// drops it.
pub fn apply_parent_execution_payload<E: Preset>(
    state: &mut BeaconState<E>,
    requests: &ExecutionRequests<E>,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    let parent_bid = state.latest_execution_payload_bid.clone();
    let parent_slot = state.latest_block_header.slot;
    let parent_epoch = E::epoch_at_slot(parent_slot);
    let slots_per_epoch = E::slots_per_epoch();

    // Settle the builder payment before the requests so that a builder exit
    // request is rejected while the payment is pending
    // Each payment index is in `0..2 * SLOTS_PER_EPOCH`, the length of
    // `builder_pending_payments`. Thus `PaymentIndexOutOfRange` can come only from a defect
    // of this function, never from the block.
    if parent_epoch == get_current_epoch(state) {
        trace("settle_builder_payment");
        let payment_index = slots_per_epoch + parent_slot % slots_per_epoch;
        debug_assert!(payment_index < 2 * slots_per_epoch);
        settle_builder_payment(state, payment_index)?;
    } else if parent_epoch == get_previous_epoch(state) {
        trace("settle_builder_payment");
        let payment_index = parent_slot % slots_per_epoch;
        debug_assert!(payment_index < 2 * slots_per_epoch);
        settle_builder_payment(state, payment_index)?;
    } else if parent_bid.value > 0 {
        // Parent is older than the previous epoch, its payment entry has been
        // evicted from builder_pending_payments. Append the withdrawal directly.
        trace("append_builder_withdrawal");
        // `BuilderPendingWithdrawals` is a `ProgressiveList` without a limit. milhouse fails
        // only at a length of `usize::MAX`: `StfError::Tree`, which is not a proof.
        state
            .builder_pending_withdrawals
            .push(BuilderPendingWithdrawal {
                fee_recipient: parent_bid.fee_recipient,
                amount: parent_bid.value,
                builder_index: parent_bid.builder_index,
            })?;
    }

    // Process execution requests from parent's payload. The execution
    // requests are processed at state.slot (child's slot), not the parent's slot.
    for request in requests.deposits.iter() {
        trace("process_deposit_request");
        process_deposit_request(state, request)?;
    }
    for request in requests.withdrawals.iter() {
        trace("process_withdrawal_request");
        process_withdrawal_request(state, request, ctx.total_active_balance())?;
    }
    for request in requests.consolidations.iter() {
        trace("process_consolidation_request");
        process_consolidation_request(state, request, ctx.total_active_balance())?;
    }
    let verdicts = ctx.deposit_verdicts();
    let (backend, genesis_fork_version): (&dyn SignatureBackend, Version) = match &verdicts {
        Some(verdicts) => (verdicts.backend, verdicts.genesis_fork_version),
        None => (&NoDepositVerdicts, Version::default()),
    };
    for request in requests.builder_deposits.iter() {
        trace("process_builder_deposit_request");
        process_builder_deposit_request(state, request, genesis_fork_version, backend)?;
    }
    for request in requests.builder_exits.iter() {
        trace("process_builder_exit_request");
        process_builder_exit_request(state, request)?;
    }

    // Update parent payload availability and latest block hash
    let index = parent_slot % E::SlotsPerHistoricalRoot::to_u64();
    state
        .execution_payload_availability
        .set(index as usize, true)
        .map_err(|_| StfError::ListIndexOutOfRange {
            list: "execution_payload_availability",
            index,
        })?;
    state.latest_block_hash = parent_bid.block_hash;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per_block::{block_steps, process_block, BlockStep};
    use crate::testing::{
        builder, builder_deposit_request, builder_exit_request, empty_requests, genesis_state,
        signed_block, ScriptedBackend, GENESIS_FORK_VERSION,
    };
    use crate::{state_root, BackendError, StfError};
    use consensus_types::common::{ConsolidationRequest, DepositRequest, WithdrawalRequest};
    use consensus_types::gloas::{
        BeaconBlock, BeaconState, BuilderPendingPayment, BuilderPendingWithdrawal,
        ExecutionRequests,
    };
    use consensus_types::primitives::{Address, Bytes32, Root, Slot, FAR_FUTURE_EPOCH};
    use consensus_types::Minimal;
    use std::cell::RefCell;
    use tree_hash::TreeHash;

    thread_local! {
        /// The steps of `apply_parent_execution_payload` on this thread, in sequence.
        pub(super) static TRACE: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }

    /// Empties the trace of this thread and gives its steps.
    fn take_trace() -> Vec<&'static str> {
        TRACE.with(|trace| trace.take())
    }

    const ETH: u64 = 1_000_000_000;

    /// The state slot of the tests: slot 2 of epoch 4 in the minimal preset.
    const SLOT: Slot = 34;

    /// The block hash of the parent bid.
    fn parent_hash() -> Root {
        Root::repeat_byte(0xaa)
    }

    /// The payment of `value` to builder 0 for a block of proposer 5, with the fee
    /// recipient `[0xfe; 20]`.
    fn payment(value: u64) -> BuilderPendingPayment {
        BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: Address::repeat_byte(0xfe),
                amount: value,
                builder_index: 0,
            },
            proposer_index: 5,
        }
    }

    /// 64 validators at [`SLOT`] (finalized at epoch 3), with the builders `[0xa1; 48]`
    /// (index 0) and `[0xa2; 48]` (index 1) of 5 ETH each, deposited in epoch 0. The parent
    /// block is at `parent_slot`. Its bid by builder 0 has the block hash [`parent_hash`],
    /// the value `value` and the fee recipient `[0xfe; 20]`, and commits to `requests`.
    /// No payment is pending.
    fn state_with_parent(
        parent_slot: Slot,
        value: u64,
        requests: &ExecutionRequests<Minimal>,
    ) -> BeaconState<Minimal> {
        let mut state = genesis_state::<Minimal>(&[32 * ETH; 64]);
        state.slot = SLOT;
        state.finalized_checkpoint.epoch = 3;
        state.latest_block_header.slot = parent_slot;
        state.latest_block_hash = Root::repeat_byte(0x99);
        for key in [0xa1, 0xa2] {
            state.builders.push(builder(key, 5 * ETH, 0)).unwrap();
        }
        let bid = &mut state.latest_execution_payload_bid;
        bid.slot = parent_slot;
        bid.block_hash = parent_hash();
        bid.builder_index = 0;
        bid.value = value;
        bid.fee_recipient = Address::repeat_byte(0xfe);
        bid.execution_requests_root = requests.tree_hash_root();
        state
    }

    /// A block at [`SLOT`] whose bid builds on `parent_block_hash`, with `requests`.
    fn block_on(
        parent_block_hash: Root,
        requests: ExecutionRequests<Minimal>,
    ) -> BeaconBlock<Minimal> {
        let mut block = signed_block::<Minimal>(SLOT, 0).message;
        block
            .body
            .signed_execution_payload_bid
            .message
            .parent_block_hash = parent_block_hash;
        block.body.parent_execution_requests = requests;
        block
    }

    fn deposit(key: u8) -> DepositRequest {
        DepositRequest {
            pubkey: [key; 48],
            withdrawal_credentials: Bytes32::repeat_byte(key),
            amount: 2 * ETH,
            signature: [0x22; 96],
            index: 0,
        }
    }

    /// One request of each kind. The withdrawal and the consolidation are for keys that no
    /// validator has, so they do nothing. The builder deposit tops up builder 1, and the
    /// builder exit is for builder 0.
    fn one_of_each() -> ExecutionRequests<Minimal> {
        let mut requests = empty_requests::<Minimal>();
        requests.deposits.push(deposit(0xd1)).unwrap();
        requests
            .withdrawals
            .push(WithdrawalRequest {
                source_address: Address::repeat_byte(0x11),
                validator_pubkey: [0xff; 48],
                amount: 0,
            })
            .unwrap();
        requests
            .consolidations
            .push(ConsolidationRequest {
                source_address: Address::repeat_byte(0x11),
                source_pubkey: [0xff; 48],
                target_pubkey: [0xfe; 48],
            })
            .unwrap();
        requests
            .builder_deposits
            .push(builder_deposit_request(0xa2, ETH))
            .unwrap();
        requests
            .builder_exits
            .push(builder_exit_request(0xa1))
            .unwrap();
        requests
    }

    /// [`process_parent_execution_payload`] with a backend that has no verdict: a call to it
    /// panics.
    fn process(
        state: &mut BeaconState<Minimal>,
        block: &BeaconBlock<Minimal>,
    ) -> Result<(), StfError> {
        let backend = ScriptedBackend::new([]);
        process_parent_execution_payload(state, block, GENESIS_FORK_VERSION, &backend)
    }

    #[test]
    fn empty_parent() {
        // The parent bid committed requests and has a pending payment of 3 ETH in the
        // current epoch (parent slot 33, index 8 + 1). The block builds on another block
        // hash: the parent payload did not arrive.
        let requests = one_of_each();
        let mut state = state_with_parent(33, 3 * ETH, &requests);
        *state.builder_pending_payments.get_mut(9).unwrap() = payment(3 * ETH);
        let empty = block_on(Root::repeat_byte(0x99), empty_requests());
        let before = state_root(&mut state).unwrap();
        assert_eq!(process(&mut state, &empty), Ok(()));
        // No request applied, no payment settled, and no availability or block hash change.
        assert_eq!(state_root(&mut state).unwrap(), before);
        assert_eq!(
            state.builder_pending_payments.get(9),
            Some(&payment(3 * ETH))
        );
        assert_eq!(state.builder_pending_withdrawals.len(), 0);
        assert!(!state.execution_payload_availability.get(33).unwrap());
        assert_eq!(state.latest_block_hash, Root::repeat_byte(0x99));

        // An EMPTY parent with a request of any kind makes the block invalid.
        let mut kinds = Vec::new();
        for kind in 0..5 {
            let mut one = empty_requests::<Minimal>();
            let all = one_of_each();
            match kind {
                0 => one.deposits = all.deposits,
                1 => one.withdrawals = all.withdrawals,
                2 => one.consolidations = all.consolidations,
                3 => one.builder_deposits = all.builder_deposits,
                _ => one.builder_exits = all.builder_exits,
            }
            kinds.push(one);
        }
        kinds.push(requests);
        for requests in kinds {
            let block = block_on(Root::repeat_byte(0x99), requests);
            let mut state = state.clone();
            let err = process(&mut state, &block).unwrap_err();
            assert_eq!(err, StfError::ParentRequestsNotEmpty);
            assert!(err.proves_invalid());
            assert_eq!(state_root(&mut state).unwrap(), before);
        }
    }

    #[test]
    fn requests_root_mismatch() {
        let committed = one_of_each();
        let mut state = state_with_parent(33, 3 * ETH, &committed);
        *state.builder_pending_payments.get_mut(9).unwrap() = payment(3 * ETH);
        let before = state_root(&mut state).unwrap();
        // The block carries one more deposit than the parent bid committed to, and no
        // request at all.
        let mut more = committed.clone();
        more.deposits.push(deposit(0xd2)).unwrap();
        for requests in [more, empty_requests()] {
            let block = block_on(parent_hash(), requests.clone());
            let want = StfError::ParentRequestsRootMismatch {
                block: requests.tree_hash_root(),
                expected: committed.tree_hash_root(),
            };
            let mut post = state.clone();
            let err = process(&mut post, &block).unwrap_err();
            assert_eq!(err, want);
            assert!(err.proves_invalid());
            // The check runs before the settlement and the requests.
            assert_eq!(state_root(&mut post).unwrap(), before);

            // The block is invalid: `process_block` stops at its first step.
            let mut post = state.clone();
            assert_eq!(process_block(&mut post, &block), Err(want.clone()));
            let steps = block_steps::<Minimal>();
            let (step, parent_step) = steps[0];
            assert_eq!(step, BlockStep::ParentExecutionPayload);
            assert_eq!(
                parent_step(&mut state.clone(), &block, &mut BlockContext::default()),
                Err(want)
            );
        }
    }

    #[test]
    fn settle_before_requests() {
        // A parent in the current epoch: its payment to builder 0 is settled first, so the
        // exit request of builder 0 sees a pending withdrawal and is ignored (#5695).
        let requests = one_of_each();
        let mut state = state_with_parent(33, 3 * ETH, &requests);
        *state.builder_pending_payments.get_mut(9).unwrap() = payment(3 * ETH);
        let block = block_on(parent_hash(), requests);
        take_trace();
        assert_eq!(process(&mut state, &block), Ok(()));
        assert_eq!(
            take_trace(),
            vec![
                "settle_builder_payment",
                "process_deposit_request",
                "process_withdrawal_request",
                "process_consolidation_request",
                "process_builder_deposit_request",
                "process_builder_exit_request",
            ]
        );
        assert_eq!(
            state.builder_pending_withdrawals.iter().collect::<Vec<_>>(),
            vec![&payment(3 * ETH).withdrawal]
        );
        assert_eq!(
            state.builders.get(0).unwrap().withdrawable_epoch,
            FAR_FUTURE_EPOCH
        );

        // A parent older than the previous epoch has no payment entry. Its withdrawal is
        // appended before the requests, so the exit request of builder 0 is ignored too.
        let mut requests = empty_requests::<Minimal>();
        requests
            .builder_exits
            .push(builder_exit_request(0xa1))
            .unwrap();
        let mut state = state_with_parent(20, 3 * ETH, &requests);
        let block = block_on(parent_hash(), requests);
        assert_eq!(process(&mut state, &block), Ok(()));
        assert_eq!(
            take_trace(),
            vec!["append_builder_withdrawal", "process_builder_exit_request"]
        );
        assert_eq!(
            state.builder_pending_withdrawals.iter().collect::<Vec<_>>(),
            vec![&payment(3 * ETH).withdrawal]
        );
        assert_eq!(
            state.builders.get(0).unwrap().withdrawable_epoch,
            FAR_FUTURE_EPOCH
        );

        // Without a pending amount, the same exit request is processed.
        let mut state = state_with_parent(20, 0, &block.body.parent_execution_requests);
        assert_eq!(process(&mut state, &block), Ok(()));
        assert_eq!(take_trace(), vec!["process_builder_exit_request"]);
        assert_eq!(
            state.builders.get(0).unwrap().withdrawable_epoch,
            4 + <Minimal as crate::Preset>::MIN_BUILDER_WITHDRAWABILITY_DELAY
        );
    }

    #[test]
    fn full_parent_settles_the_payment_of_its_slot() {
        // The parent slot 33 is in the current epoch (index 8 + 1), and the parent slot 30 in
        // the previous epoch (index 30 % 8). Each settlement moves only its own payment.
        for (parent_slot, index) in [(33, 9), (30, 6)] {
            let requests = empty_requests::<Minimal>();
            let mut state = state_with_parent(parent_slot, 3 * ETH, &requests);
            for i in [6, 9] {
                *state.builder_pending_payments.get_mut(i).unwrap() = payment(ETH * i as u64);
            }
            let block = block_on(parent_hash(), requests);
            assert_eq!(process(&mut state, &block), Ok(()));
            assert_eq!(
                state.builder_pending_withdrawals.iter().collect::<Vec<_>>(),
                vec![&payment(ETH * index as u64).withdrawal]
            );
            let other = 15 - index;
            assert_eq!(
                state.builder_pending_payments.get(index),
                Some(&crate::mutators::empty_payment())
            );
            assert_eq!(
                state.builder_pending_payments.get(other),
                Some(&payment(ETH * other as u64))
            );
            // The parent payload is available, and its block hash is the latest one.
            let availability = &state.execution_payload_availability;
            assert!(availability.get(parent_slot as usize).unwrap());
            assert_eq!(availability.num_set_bits(), 1);
            assert_eq!(state.latest_block_hash, parent_hash());
        }

        // A zero payment in the current epoch, and an old parent with a zero value, append
        // no withdrawal.
        for parent_slot in [33, 20] {
            let requests = empty_requests::<Minimal>();
            let mut state = state_with_parent(parent_slot, 0, &requests);
            let block = block_on(parent_hash(), requests);
            assert_eq!(process(&mut state, &block), Ok(()));
            assert_eq!(state.builder_pending_withdrawals.len(), 0);
            assert_eq!(state.latest_block_hash, parent_hash());
        }
    }

    #[test]
    fn requests_apply_at_the_child_slot() {
        let requests = one_of_each();
        let mut state = state_with_parent(20, 0, &requests);
        let block = block_on(parent_hash(), requests);
        assert_eq!(process(&mut state, &block), Ok(()));
        // The deposit is queued with the slot of the child block, not of the parent.
        let queued = state.pending_deposits.get(0).unwrap();
        assert_eq!((queued.pubkey, queued.slot), ([0xd1; 48], SLOT));
        // The top-up of builder 1 needs no verdict, and builder 0 exits in epoch 4.
        assert_eq!(state.builders.get(1).unwrap().balance, 6 * ETH);
        assert_eq!(state.builders.get(0).unwrap().withdrawable_epoch, 4 + 2);
    }

    #[test]
    fn builder_deposit_needs_a_verdict() {
        let mut requests = empty_requests::<Minimal>();
        let request = builder_deposit_request(0xc1, 2 * ETH);
        requests.builder_deposits.push(request.clone()).unwrap();
        let pre = state_with_parent(33, 0, &requests);
        let block = block_on(parent_hash(), requests);
        let set = crate::per_block::builder::builder_deposit_signature_set(
            &request,
            GENESIS_FORK_VERSION,
        );

        // A valid proof of possession registers the builder at index 2.
        let mut state = pre.clone();
        let backend = ScriptedBackend::new([Ok(true)]);
        assert_eq!(
            process_parent_execution_payload(&mut state, &block, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        assert_eq!(backend.seen(), vec![set.clone()]);
        assert_eq!(state.builders.get(2).unwrap().pubkey, [0xc1; 48]);

        // An invalid one ignores the request.
        let mut state = pre.clone();
        let backend = ScriptedBackend::new([Ok(false)]);
        assert_eq!(
            process_parent_execution_payload(&mut state, &block, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        assert_eq!(state.builders.len(), 2);

        // A backend without the verdict, and a context without a source of verdicts: the
        // transition cannot continue, and the block is not proven invalid.
        let missing = BackendError("not prefetched".into());
        let backend = ScriptedBackend::new([Err(missing.clone())]);
        let err = process_parent_execution_payload(
            &mut pre.clone(),
            &block,
            GENESIS_FORK_VERSION,
            &backend,
        )
        .unwrap_err();
        assert_eq!(err, StfError::MissingVerdict(missing));
        assert!(!err.proves_invalid());
        let err = process_parent_execution_payload_with(
            &mut pre.clone(),
            &block,
            &mut BlockContext::default(),
        )
        .unwrap_err();
        assert!(matches!(err, StfError::MissingVerdict(_)), "{err:?}");
        assert!(!err.proves_invalid());
    }
}
