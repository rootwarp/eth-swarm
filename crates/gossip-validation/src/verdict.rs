//! The verdict of a gossip message: ACCEPT, IGNORE or REJECT (`phase0/p2p-interface.md`), or
//! pending its signature check.

use crate::seen::SeenKey;
use consensus_types::primitives::{BuilderIndex, Epoch, Hash32, Root, Slot, ValidatorIndex};
use consensus_types::signing::SignatureSet;

/// The verdict of a gossip message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// ACCEPT: the message is fully valid, and `Seen` has its key. Only
    /// [`crate::Seen::resolve`] gives this verdict.
    Accept,
    /// IGNORE: drop the message, and do not penalize the peer.
    Ignore(IgnoreReason),
    /// REJECT: the message breaks the spec. Drop it, and penalize the peer.
    Reject(RejectReason),
    /// Each check that needs no BLS passed. The caller must verify `bls_sets` and give the
    /// verdict with `seen_key` to [`crate::Seen::resolve`]. Until then `Seen` does not change.
    /// Only a validation function gives this verdict.
    Pending {
        /// The signature sets of the message, for the BLS backend of the caller.
        bls_sets: Vec<SignatureSet>,
        /// The key that `Seen` gets if each set is valid.
        seen_key: SeenKey,
    },
}

/// Why a message is IGNORE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoreReason {
    /// A valid envelope for this block root from this builder is already seen.
    EnvelopeAlreadySeen {
        /// `envelope.beacon_block_root`.
        block_root: Root,
        /// `envelope.builder_index`.
        builder_index: BuilderIndex,
    },
    /// The block of the message is not seen. The message MAY wait until the block arrives.
    UnknownBlock(Root),
    /// The payload is from a slot before the first slot of the finalized epoch.
    BeforeFinalizedSlot {
        /// `payload.slot_number`.
        slot: Slot,
        /// `compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)`.
        finalized_slot: Slot,
    },
    /// The builder of a validated block is not in its post-state: a fault of the store, not a
    /// proof against the message.
    UnknownBuilder(BuilderIndex),
    /// The signature verifier gave no verdict.
    NoSignatureVerdict,
    /// A valid payload attestation message of this slot from this validator is already seen.
    PayloadAttestationAlreadySeen {
        /// `data.slot`.
        slot: Slot,
        /// `validator_index`.
        validator_index: ValidatorIndex,
    },
    /// The slot of the message is not the current slot, with `MAXIMUM_GOSSIP_CLOCK_DISPARITY`
    /// on both ends.
    NotCurrentSlot {
        /// `data.slot`.
        slot: Slot,
    },
    /// The block of the message is not of the slot of the message.
    BlockSlotMismatch {
        /// `block.slot`.
        block: Slot,
        /// `data.slot`.
        message: Slot,
    },
    /// The store gives no post-state of its head: a fault of the store, not a proof against
    /// the message.
    NoHeadState,
    /// The head state has no PTC of the slot of the message (`get_ptc` fails, for example for
    /// a slot more than one epoch after the head state): not a proof against the message.
    NoPtc {
        /// `data.slot`.
        slot: Slot,
    },
}

/// A kind of execution request that `verify_execution_requests_limits` bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD`.
    Withdrawal,
    /// `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD`.
    Consolidation,
    /// `MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD`.
    BuilderDeposit,
    /// `MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD`.
    BuilderExit,
}

/// Why a message is REJECT: a proven spec violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// The block of the message is seen but did not pass validation.
    BlockNotValid(Root),
    /// The slot of the payload is not the slot of the block.
    SlotMismatch {
        /// `block.slot`.
        block: Slot,
        /// `payload.slot_number`.
        payload: Slot,
    },
    /// The envelope is not from the builder of the bid.
    BuilderIndexMismatch {
        /// `envelope.builder_index`.
        envelope: BuilderIndex,
        /// `bid.builder_index`.
        bid: BuilderIndex,
    },
    /// The block hash of the payload is not the block hash of the bid.
    BlockHashMismatch {
        /// `payload.block_hash`.
        payload: Hash32,
        /// `bid.block_hash`.
        bid: Hash32,
    },
    /// The root of the execution requests is not the root of the bid.
    ExecutionRequestsRootMismatch {
        /// `hash_tree_root(envelope.execution_requests)`.
        envelope: Root,
        /// `bid.execution_requests_root`.
        bid: Root,
    },
    /// A count of execution requests is past its limit.
    TooManyRequests {
        /// The kind of request.
        kind: RequestKind,
        /// The number of requests of that kind.
        count: usize,
        /// The limit of that kind.
        limit: usize,
    },
    /// The payload has more withdrawals than `MAX_WITHDRAWALS_PER_PAYLOAD`.
    TooManyWithdrawals {
        /// `len(payload.withdrawals)`.
        count: usize,
        /// `MAX_WITHDRAWALS_PER_PAYLOAD`.
        limit: usize,
    },
    /// A signature of the message is not valid.
    InvalidSignature,
    /// The slot of the message is before the Gloas fork.
    BeforeGloasFork {
        /// `data.slot`.
        slot: Slot,
        /// `GLOAS_FORK_EPOCH`.
        fork_epoch: Epoch,
    },
    /// The validator index is past the registry of the head state.
    UnknownValidator(ValidatorIndex),
    /// The validator is not in the PTC of the slot of the message on the head state.
    NotInPtc {
        /// `validator_index`.
        validator_index: ValidatorIndex,
        /// `data.slot`.
        slot: Slot,
    },
}
