//! The `execution_payload` topic: `validate_execution_payload_envelope_gossip` (L811-885) and
//! `verify_execution_requests_limits` (L504-529).
//!
//! The SSZ types of `consensus_types::gloas` bound the request lists and the withdrawals of a
//! payload with the same preset values, so a decoded envelope cannot exceed a limit. An
//! envelope past a limit thus fails at deserialization, which the spec allows for the requests
//! ("These checks MAY be performed when deserializing"). The checks also run here, in spec
//! order, so that a looser type bound cannot let such an envelope through.
//!
//! # Deviation: a bounded `Seen`, and IGNORE before its floor
//!
//! The spec's `Seen` keeps each envelope key and each payload (`seen.execution_payload_envelopes`
//! and `seen.execution_payloads`) for good, and the only slot check of this topic is the
//! finalized slot (L846-849). The finalized slot does not move while the chain does not
//! finalize, so a prune by that slot has no bound then. Here [`Seen`] keeps the keys and the
//! payloads by `payload.slot_number`, with the bounds of [`crate::seen`]: the floor is the
//! oldest slot that is current at the time of the store ([`crate::oldest_current_slot`] of
//! [`StoreView::time_ms`]), and `Seen` keeps at most
//! [`MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS`](crate::MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS)
//! slots and [`MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT`] keys for each slot. These bounds do not
//! depend on finality.
//!
//! What differs from the spec:
//!
//! - An envelope of a slot before the floor is IGNORE ([`IgnoreReason::NotCurrentSlot`]):
//!   `Seen` does not keep that slot, so it cannot tell a duplicate. The check comes after the
//!   finalized slot check and before the block slot check, and the duplicate check also reads
//!   the record of the last pruned slot. The spec accepts such an envelope if it is valid and
//!   not seen. On a healthy network an envelope arrives in its slot, and a late envelope can
//!   still come by req/resp (`ExecutionPayloadEnvelopesByRange`,
//!   `ExecutionPayloadEnvelopesByRoot`).
//! - A valid envelope of a new block in a full slot is IGNORE
//!   ([`IgnoreReason::ExecutionPayloadEnvelopeSlotFull`]). A slot has more than one block only
//!   if its proposer equivocates.
//! - An envelope whose key the spec has seen, but `Seen` no longer keeps, and whose
//!   `payload.slot_number` is not the slot of its block can be REJECT for the slot mismatch,
//!   where the spec gives IGNORE as a duplicate. The mismatch is a proven violation.
//! - `seen.execution_payloads` has only the payloads of the kept slots. The
//!   `execution_payload_bid` topic, which is not in this crate yet, reads the payload of
//!   `bid.parent_block_hash`, and the payload of a parent before the floor is not there.
//!
//! IGNORE does not penalize the peer, and no envelope is ACCEPT that the spec does not accept.

use crate::payload_attestation::oldest_current_slot;
use crate::seen::{Seen, SeenKey, MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT};
use crate::verdict::{IgnoreReason, RejectReason, RequestKind, Verdict};
use crate::StoreView;
use consensus_types::gloas::{ExecutionRequests, SignedExecutionPayloadEnvelope};
use consensus_types::EthSpec;
use fork_choice::execution_payload_envelope_signature_set;
use ssz_types::typenum::Unsigned;
use state_transition::Preset;
use tree_hash::TreeHash;

/// The lengths of the request lists that `verify_execution_requests_limits` bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestCounts {
    /// `len(execution_requests.withdrawals)`.
    pub withdrawals: usize,
    /// `len(execution_requests.consolidations)`.
    pub consolidations: usize,
    /// `len(execution_requests.builder_deposits)`.
    pub builder_deposits: usize,
    /// `len(execution_requests.builder_exits)`.
    pub builder_exits: usize,
}

impl RequestCounts {
    /// The counts of `requests`.
    pub fn of<E: EthSpec>(requests: &ExecutionRequests<E>) -> Self {
        Self {
            withdrawals: requests.withdrawals.len(),
            consolidations: requests.consolidations.len(),
            builder_deposits: requests.builder_deposits.len(),
            builder_exits: requests.builder_exits.len(),
        }
    }
}

/// `verify_execution_requests_limits` (L509-528) on the counts of the requests, in spec
/// order. Deposit requests have no limit.
pub fn verify_execution_requests_limits<E: EthSpec>(
    counts: &RequestCounts,
) -> Result<(), RejectReason> {
    let limits = [
        (
            RequestKind::Withdrawal,
            counts.withdrawals,
            E::MaxWithdrawalRequestsPerPayload::to_usize(),
        ),
        (
            RequestKind::Consolidation,
            counts.consolidations,
            E::MaxConsolidationRequestsPerPayload::to_usize(),
        ),
        (
            RequestKind::BuilderDeposit,
            counts.builder_deposits,
            E::MaxBuilderDepositRequestsPerPayload::to_usize(),
        ),
        (
            RequestKind::BuilderExit,
            counts.builder_exits,
            E::MaxBuilderExitRequestsPerPayload::to_usize(),
        ),
    ];
    for (kind, count, limit) in limits {
        if count > limit {
            return Err(RejectReason::TooManyRequests { kind, count, limit });
        }
    }
    Ok(())
}

/// The withdrawal check of `validate_execution_payload_envelope_gossip` (L873-875):
/// `len(payload.withdrawals) <= MAX_WITHDRAWALS_PER_PAYLOAD`.
pub fn verify_withdrawals_limit<E: EthSpec>(count: usize) -> Result<(), RejectReason> {
    let limit = E::MaxWithdrawalsPerPayload::to_usize();
    if count > limit {
        return Err(RejectReason::TooManyWithdrawals { count, limit });
    }
    Ok(())
}

/// `validate_execution_payload_envelope_gossip` (L811-885) up to the signature check.
///
/// It runs the three IGNORE checks and the REJECT checks before the signature in spec order,
/// and gives the first that fails. If each passes, it gives [`Verdict::Pending`] with the set of
/// `verify_execution_payload_envelope_signature` on the post-state of the block (the builder
/// key, or the proposer key for a self-build envelope) and the key of the envelope. The
/// caller must verify the set and give the result to [`Seen::resolve`], which adds the key to
/// `Seen` only for a valid signature.
///
/// `Seen` has bounds by slot (the deviation of the module documentation). The duplicate check
/// also reads the record of the last pruned slot ([`Seen::has_pruned_execution_payload_envelope`]).
/// After the finalized slot check, an envelope of a slot before the floor of `Seen`
/// ([`Seen::min_execution_payload_envelope_slot`]) is IGNORE as not current, also for a clock
/// of the store that went back. The key has the oldest current slot at the time of the store
/// ([`StoreView::time_ms`]) and the limit of envelopes for each slot,
/// [`MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT`], which [`Seen::resolve`] applies.
///
/// The pinned function reads no clock, only the finalized slot of the store. This function
/// reads the clock of the store only for the key, so no check before the signature depends on
/// it. A key whose slot is before the oldest current slot is IGNORE in [`Seen::resolve`].
pub fn validate_execution_payload_envelope_gossip<E, S>(
    seen: &Seen,
    store: &S,
    signed_envelope: &SignedExecutionPayloadEnvelope<E>,
) -> Verdict
where
    E: Preset,
    S: StoreView<E> + ?Sized,
{
    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;
    let block_root = envelope.beacon_block_root;
    let builder_index = envelope.builder_index;

    if seen.has_execution_payload_envelope(block_root, builder_index)
        || seen.has_pruned_execution_payload_envelope(
            payload.slot_number,
            block_root,
            builder_index,
        )
    {
        return Verdict::Ignore(IgnoreReason::EnvelopeAlreadySeen {
            block_root,
            builder_index,
        });
    }
    let Some(block) = store.block(block_root) else {
        return Verdict::Ignore(IgnoreReason::UnknownBlock(block_root));
    };
    let Some(state) = store.block_state(block_root) else {
        return Verdict::Reject(RejectReason::BlockNotValid(block_root));
    };
    // `compute_start_slot_at_epoch`, saturating: an epoch past the last slot ignores each
    // envelope, never accepts one.
    let finalized_slot = E::start_slot_at_epoch(store.finalized_checkpoint().epoch);
    if payload.slot_number < finalized_slot {
        return Verdict::Ignore(IgnoreReason::BeforeFinalizedSlot {
            slot: payload.slot_number,
            finalized_slot,
        });
    }
    // Not a spec check: `Seen` keeps no slot before its floor, so it cannot tell a duplicate
    // there.
    if payload.slot_number < seen.min_execution_payload_envelope_slot() {
        return Verdict::Ignore(IgnoreReason::NotCurrentSlot {
            slot: payload.slot_number,
        });
    }

    let bid = &block.body.signed_execution_payload_bid.message;
    if block.slot != payload.slot_number {
        return Verdict::Reject(RejectReason::SlotMismatch {
            block: block.slot,
            payload: payload.slot_number,
        });
    }
    if builder_index != bid.builder_index {
        return Verdict::Reject(RejectReason::BuilderIndexMismatch {
            envelope: builder_index,
            bid: bid.builder_index,
        });
    }
    if payload.block_hash != bid.block_hash {
        return Verdict::Reject(RejectReason::BlockHashMismatch {
            payload: payload.block_hash,
            bid: bid.block_hash,
        });
    }
    let requests_root = envelope.execution_requests.tree_hash_root();
    if requests_root != bid.execution_requests_root {
        return Verdict::Reject(RejectReason::ExecutionRequestsRootMismatch {
            envelope: requests_root,
            bid: bid.execution_requests_root,
        });
    }
    let counts = RequestCounts::of(&envelope.execution_requests);
    if let Err(reason) = verify_execution_requests_limits::<E>(&counts)
        .and_then(|()| verify_withdrawals_limit::<E>(payload.withdrawals.len()))
    {
        return Verdict::Reject(reason);
    }

    // The bid of a validated block names a builder of its post-state, and the envelope has
    // that builder: a builder past the registry is a fault of the store.
    let Ok(set) = execution_payload_envelope_signature_set(state, signed_envelope) else {
        return Verdict::Ignore(IgnoreReason::UnknownBuilder(builder_index));
    };
    Verdict::Pending {
        bls_sets: vec![set],
        seen_key: SeenKey::execution_payload_envelope(
            payload.slot_number,
            block_root,
            builder_index,
            payload.block_hash,
            payload.gas_limit,
            oldest_current_slot(store, store.time_ms()),
            MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT,
        ),
    }
}
