//! The verdict of a gossip message: ACCEPT, IGNORE or REJECT (`phase0/p2p-interface.md`), or
//! pending its signature check.

use crate::seen::SeenKey;
use consensus_types::primitives::{BuilderIndex, Hash32, Root, Slot};
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
    /// The block of the envelope is seen but did not pass validation.
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
}
