//! The Gloas fork choice (`specs/gloas/fork-choice.md` at consensus-specs v1.7.0-beta.4, and the
//! phase0 helpers that Gloas keeps), ported function by function.
//!
//! - [`store`]: [`Store`], [`get_forkchoice_store`], the time helpers and the ancestry
//!   helpers with their payload status.
//! - [`handlers`]: [`on_tick`], [`on_block`] and [`store_target_checkpoint_state`].
//! - [`attestations`]: [`on_attestation`] and [`on_attester_slashing`].
//! - [`weights`]: [`get_head`], the filtered node tree, [`get_weight`] and the payload
//!   tiebreaker.
//! - [`envelope`]: [`on_execution_payload_envelope`] and
//!   [`verify_execution_payload_envelope`].
//! - [`payload_attestation`]: [`on_payload_attestation_message`], which also gives `on_block`
//!   the votes of the payload attestations of a block.
//!
//! The crate does no I/O and links no BLS library. The state transition of a block comes
//! from the caller through a [`StateProvider`], and the BLS verdicts of an attestation, an
//! envelope or a payload attestation message through a [`SignatureVerifier`]. Data availability and the answer of the execution
//! engine for an envelope come through a [`DataAvailabilityCheck`] and an [`ExecutionEngine`].
//! [`on_execution_payload_envelope`] fills `store.payloads`. The test seam
//! `testing::mark_payload_verified` (tests only) also does, without the checks of the
//! handler.
//!
//! The spec's store keeps every block. Here [`on_tick`] still drops the blocks that do not
//! descend from the finalized checkpoint block once finality moves, from the kept set that
//! [`on_block`], [`get_head`] and [`get_weight`] read. After a prune in epoch `p`, the store
//! keeps what [`on_attestation`] reads of the dropped blocks through the end of epoch `p + 2`.
//! That window has every target epoch up to `p + 1`, for a vote from the wire and for a vote
//! from a block, and for a vote that arrives in it [`on_attestation`] and then [`get_head`]
//! give the result of the spec. After that window [`on_attestation`] refuses a vote that names
//! a forgotten block, where the spec would still accept a valid one. A refused vote leaves the
//! older latest messages of its attesters in place, where the spec replaces them, so
//! [`get_head`] can differ from the spec.
//!
//! The spec signals an invalid call with a failed `assert` or a missing key. Here each public
//! handler returns an [`Error`] instead, and a failed handler leaves the store as it was.
//! Each ported function cites its spec lines: G `gloas/fork-choice.md`, P0
//! `phase0/fork-choice.md`, P0b `phase0/beacon-chain.md`.

pub mod attestations;
pub mod envelope;
pub mod handlers;
pub mod payload_attestation;
pub mod store;
pub mod weights;

pub use attestations::{on_attestation, on_attester_slashing, SignatureVerifier};
pub use envelope::{
    execution_payload_envelope_signature_set, on_execution_payload_envelope,
    verify_execution_payload_envelope, DataAvailability, DataAvailabilityCheck, ExecutionEngine,
    NewPayloadRequestRef, PayloadImport,
};
pub use handlers::{on_block, on_tick, store_target_checkpoint_state, StateProvider};
pub use payload_attestation::on_payload_attestation_message;
pub use store::{
    compute_slots_since_epoch_start, get_ancestor, get_checkpoint_block, get_current_slot,
    get_current_store_epoch, get_forkchoice_store, get_parent_payload_status,
    get_slots_since_genesis, get_time_into_slot_ms, is_ancestor, is_parent_node_full,
    is_payload_verified, milliseconds_to_seconds, seconds_to_milliseconds, ForkChoiceNode,
    LatestMessage, PayloadStatus, Store,
};
pub use weights::{
    get_filtered_node_tree, get_head, get_node_children, get_weight, is_valid_dependent_root,
};

use consensus_types::primitives::{
    BuilderIndex, Bytes32, CommitteeIndex, Epoch, Hash32, Root, Slot, ValidatorIndex,
};
use state_transition::{BackendError, StfError};

/// `BASIS_POINTS` (P0 L126).
pub const BASIS_POINTS: u64 = 10_000;
/// `ATTESTATION_DUE_BPS_GLOAS` (`configs/{minimal,mainnet}.yaml`, 2500 in both).
pub const ATTESTATION_DUE_BPS_GLOAS: u64 = 2_500;
/// `PAYLOAD_ATTESTATION_DUE_BPS` (`configs/{minimal,mainnet}.yaml`, 7500 in both).
pub const PAYLOAD_ATTESTATION_DUE_BPS: u64 = 7_500;
/// `PROPOSER_SCORE_BOOST` (P0 L132, `configs/{minimal,mainnet}.yaml`, 40 in both).
pub const PROPOSER_SCORE_BOOST: u64 = 40;
/// `REORG_HEAD_WEIGHT_THRESHOLD` (P0 L133, `configs/{minimal,mainnet}.yaml`, 20 in both).
pub const REORG_HEAD_WEIGHT_THRESHOLD: u64 = 20;

/// The config values that fork choice compiles in, by config key. They are equal in the
/// minimal and the mainnet configs. A caller compares them with its network config at
/// startup, as it does with `state_transition::preset::config_values`. `SLOT_DURATION_MS`
/// differs between networks, so it is an argument of [`get_forkchoice_store`].
pub fn config_values() -> [(&'static str, u64); 4] {
    [
        ("ATTESTATION_DUE_BPS_GLOAS", ATTESTATION_DUE_BPS_GLOAS),
        ("PAYLOAD_ATTESTATION_DUE_BPS", PAYLOAD_ATTESTATION_DUE_BPS),
        ("PROPOSER_SCORE_BOOST", PROPOSER_SCORE_BOOST),
        ("REORG_HEAD_WEIGHT_THRESHOLD", REORG_HEAD_WEIGHT_THRESHOLD),
    ]
}

/// Why a fork-choice call failed: a spec `assert` or a missing key of the spec's `Store`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `get_forkchoice_store` asserts `anchor_block.state_root == hash_tree_root(anchor_state)`.
    #[error("anchor block state root {block} is not the anchor state root {state}")]
    AnchorStateRoot {
        /// `anchor_block.state_root`.
        block: Root,
        /// `hash_tree_root(anchor_state)`.
        state: Root,
    },
    /// `on_block` asserts `block.parent_root in store.block_states`.
    #[error("parent block {0} is not in the store")]
    UnknownParent(Root),
    /// `on_block` asserts `is_payload_verified(store, block.parent_root)` for a block that
    /// builds on the FULL payload of its parent (G L1058-1061).
    #[error("the block builds on the FULL payload of {0}, which is not verified")]
    ParentPayloadNotVerified(Root),
    /// `on_block` asserts `get_current_slot(store) >= block.slot`.
    #[error("block slot {block} is after the current slot {current}")]
    FutureBlock {
        /// `block.slot`.
        block: Slot,
        /// `get_current_slot(store)`.
        current: Slot,
    },
    /// `on_block` asserts that the block is after the first slot of the finalized epoch.
    #[error("block slot {block} is not after the finalized slot {finalized}")]
    NotAfterFinalized {
        /// `block.slot`.
        block: Slot,
        /// `compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)`.
        finalized: Slot,
    },
    /// `on_block` asserts that the block descends from the finalized checkpoint block.
    #[error("the checkpoint block {checkpoint_block} is not the finalized block {finalized}")]
    NotFinalizedDescendant {
        /// `store.finalized_checkpoint.root`.
        finalized: Root,
        /// The checkpoint block of the parent at the finalized epoch.
        checkpoint_block: Root,
    },
    /// The [`StateProvider`] failed. [`StfError::proves_invalid`] tells whether the block (or
    /// the slots) are invalid by the spec.
    #[error("state transition: {0}")]
    StateTransition(StfError),
    /// A state helper failed on a state of the store: a fault of the store, not of the input.
    #[error("state helper: {0}")]
    Stf(StfError),
    /// A spec lookup of a block, a block state or a per-block entry of the store that the
    /// store does not have, for example an ancestor below the anchor.
    #[error("block {0} is not in the store")]
    UnknownBlock(Root),
    /// `store.checkpoint_states[store.justified_checkpoint]` is missing. On the spec path,
    /// `on_attestation` stores the state of each attestation target first.
    #[error("no checkpoint state of epoch {epoch} root {root}")]
    MissingCheckpointState {
        /// The checkpoint epoch.
        epoch: Epoch,
        /// The checkpoint root.
        root: Root,
    },
    /// A time before genesis: the `Uint64` subtraction of `compute_slot_at_time_ms` fails.
    #[error("time {time_ms} ms is before the genesis time {genesis_time_ms} ms")]
    BeforeGenesis {
        /// The time of the tick.
        time_ms: u64,
        /// `store.genesis_time_ms`.
        genesis_time_ms: u64,
    },
    /// A `Uint64` operation of the spec overflowed.
    #[error("arithmetic overflow")]
    Overflow,
    /// `on_attestation` or `on_attester_slashing` failed a spec `assert` on its input. An
    /// attestation can pass later, when its blocks or its slot arrive.
    #[error("invalid attestation: {0}")]
    InvalidAttestation(AttestationError),
    /// `get_indexed_attestation` or `is_valid_indexed_attestation` failed with an error, not a
    /// verdict. [`StfError::proves_invalid`] tells whether the spec fails on the input too (a
    /// bit or a committee that the slot does not have, an index past the registry), or the
    /// state or the signature backend failed (no verdict, never a proof).
    #[error("indexed attestation: {0}")]
    IndexedAttestation(StfError),
    /// `on_execution_payload_envelope` or `verify_execution_payload_envelope` failed a spec
    /// `assert` on the envelope.
    #[error("invalid execution payload envelope: {0}")]
    InvalidEnvelope(EnvelopeError),
    /// `is_data_available` is false for the block of an envelope. The envelope can pass later,
    /// when the data is available: this is not a proof.
    #[error("the data of block {0} is not available")]
    DataUnavailable(Root),
    /// The answer of the execution engine does not permit the import of the payload of the
    /// block: INVALID, INVALID_BLOCK_HASH, no answer, or a gate of the caller. This is not a
    /// proof that the envelope is invalid.
    #[error("the execution engine refused the payload of block {0}")]
    PayloadRefused(Root),
    /// `on_payload_attestation_message` failed a spec `assert` on the message, from the wire
    /// or from a block.
    #[error("invalid payload attestation message: {0}")]
    InvalidPayloadAttestation(PayloadAttestationError),
    /// The signature verifier gave no verdict on an envelope or a payload attestation message:
    /// never a proof.
    #[error("no signature verdict: {0}")]
    NoSignatureVerdict(BackendError),
}

/// The spec `assert` that a payload attestation message failed, in the order of
/// `on_payload_attestation_message` (G L1139-1187).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadAttestationError {
    /// The attested block must be in `store.block_states`. The message can pass later, when
    /// the block arrives.
    #[error("attested block {0} is not in the store")]
    UnknownBeaconBlock(Root),
    /// The validator must be in the PTC of `data.slot` on the post-state of the attested block.
    #[error("validator {validator} is not in the PTC of slot {slot}")]
    NotInPtc {
        /// `ptc_message.validator_index`.
        validator: ValidatorIndex,
        /// `data.slot`.
        slot: Slot,
    },
    /// A message from the wire must be of the current slot.
    #[error("payload attestation slot {slot} is not the current slot {current}")]
    NotCurrentSlot {
        /// `data.slot`.
        slot: Slot,
        /// `get_current_slot(store)`.
        current: Slot,
    },
    /// `is_valid_indexed_payload_attestation` is false for a message from the wire: the
    /// verifier rejected the signature.
    #[error("the payload attestation signature is not valid")]
    InvalidSignature,
}

impl From<PayloadAttestationError> for Error {
    fn from(e: PayloadAttestationError) -> Self {
        Self::InvalidPayloadAttestation(e)
    }
}

/// The spec `assert` that an execution payload envelope failed, in the order of
/// `on_execution_payload_envelope` (G L1113-1135) and `verify_execution_payload_envelope`
/// (G L683-728).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// The block of the envelope must be in `store.block_states`.
    #[error("beacon block {0} is not in the store")]
    UnknownBeaconBlock(Root),
    /// `state.builders[builder_index]` must exist for a builder envelope.
    #[error("builder {0} is not in the registry")]
    UnknownBuilder(BuilderIndex),
    /// `verify_execution_payload_envelope_signature` is false.
    #[error("the envelope signature is not valid")]
    InvalidSignature,
    /// `beacon_block_root` must be the root of the latest block header of the state.
    #[error("beacon block root {envelope} is not the block root {block} of the state")]
    BeaconBlockRoot {
        /// `envelope.beacon_block_root`.
        envelope: Root,
        /// The root of the latest block header, with the state root.
        block: Root,
    },
    /// `parent_beacon_block_root` must be the parent root of the latest block header.
    #[error("parent beacon block root {envelope} is not {state}")]
    ParentBeaconBlockRoot {
        /// `envelope.parent_beacon_block_root`.
        envelope: Root,
        /// `state.latest_block_header.parent_root`.
        state: Root,
    },
    /// `builder_index` must be the builder of the committed bid.
    #[error("builder index {envelope} is not the bid builder {bid}")]
    BuilderIndex {
        /// `envelope.builder_index`.
        envelope: BuilderIndex,
        /// `bid.builder_index`.
        bid: BuilderIndex,
    },
    /// `payload.prev_randao` must be the one of the bid.
    #[error("prev_randao {payload} is not the bid prev_randao {bid}")]
    PrevRandao {
        /// `payload.prev_randao`.
        payload: Bytes32,
        /// `bid.prev_randao`.
        bid: Bytes32,
    },
    /// `payload.gas_limit` must be the one of the bid.
    #[error("gas limit {payload} is not the bid gas limit {bid}")]
    GasLimit {
        /// `payload.gas_limit`.
        payload: u64,
        /// `bid.gas_limit`.
        bid: u64,
    },
    /// `payload.block_hash` must be the one of the bid.
    #[error("block hash {payload} is not the bid block hash {bid}")]
    BlockHash {
        /// `payload.block_hash`.
        payload: Hash32,
        /// `bid.block_hash`.
        bid: Hash32,
    },
    /// The root of the execution requests must be the one of the bid.
    #[error("execution requests root {envelope} is not the bid root {bid}")]
    ExecutionRequestsRoot {
        /// `hash_tree_root(envelope.execution_requests)`.
        envelope: Root,
        /// `bid.execution_requests_root`.
        bid: Root,
    },
    /// `payload.slot_number` must be the slot of the state.
    #[error("payload slot {payload} is not the state slot {state}")]
    Slot {
        /// `payload.slot_number`.
        payload: Slot,
        /// `state.slot`.
        state: Slot,
    },
    /// `payload.parent_hash` must be the latest block hash of the state.
    #[error("parent hash {payload} is not the latest block hash {state}")]
    ParentHash {
        /// `payload.parent_hash`.
        payload: Hash32,
        /// `state.latest_block_hash`.
        state: Hash32,
    },
    /// `payload.timestamp` must be the time of the slot of the state.
    #[error("timestamp {payload} is not the slot time {expected}")]
    Timestamp {
        /// `payload.timestamp`.
        payload: u64,
        /// `compute_time_at_slot(state.genesis_time, state.slot)`.
        expected: u64,
    },
    /// The withdrawals of the payload must be the expected withdrawals of the state.
    #[error("withdrawals root {payload} is not the expected root {expected}")]
    WithdrawalsRoot {
        /// `hash_tree_root(payload.withdrawals)`.
        payload: Root,
        /// `hash_tree_root(state.payload_expected_withdrawals)`.
        expected: Root,
    },
}

impl From<EnvelopeError> for Error {
    fn from(e: EnvelopeError) -> Self {
        Self::InvalidEnvelope(e)
    }
}

/// The spec `assert` that an attestation or an attester slashing failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    /// `validate_target_epoch_against_current_time` (P0 L816-823): an attestation from the
    /// wire must have the target epoch of the current or the previous epoch of the store.
    #[error("target epoch {target} is not the current epoch {current} or the one before")]
    TargetEpochNotCurrent {
        /// `data.target.epoch`.
        target: Epoch,
        /// `get_current_store_epoch(store)`.
        current: Epoch,
    },
    /// The target epoch must be the epoch of the attestation slot.
    #[error("target epoch {target} is not the epoch of slot {slot}")]
    TargetEpochMismatch {
        /// `data.target.epoch`.
        target: Epoch,
        /// `data.slot`.
        slot: Slot,
    },
    /// The target block must be in the store.
    #[error("target block {0} is not in the store")]
    UnknownTarget(Root),
    /// The attested block must be in the store.
    #[error("attested block {0} is not in the store")]
    UnknownBeaconBlock(Root),
    /// The attested block must not be after the attestation slot.
    #[error("attested block of slot {block} is after the attestation slot {slot}")]
    FutureBlock {
        /// The slot of the attested block.
        block: Slot,
        /// `data.slot`.
        slot: Slot,
    },
    /// `data.index` must be 0 (an EMPTY vote) or 1 (a FULL vote) (G L937).
    #[error("attestation index {0} is not 0 or 1")]
    IndexOutOfRange(CommitteeIndex),
    /// A vote of the slot of its block must have index 0: the payload of that block is not
    /// known at the attestation deadline (G L938-939).
    #[error("a vote of the slot of block {0} is for its FULL node")]
    SameSlotFullVote(Root),
    /// A FULL vote needs the verified payload of its block (G L942-943).
    #[error("a FULL vote for block {0}, whose payload is not verified")]
    PayloadNotVerified(Root),
    /// The target epoch starts before the oldest block that the store has on the chain of the
    /// attested block, an anchor of the store. The spec's `get_checkpoint_block` walks to the
    /// parent of that block, which the store does not have: see
    /// `attestations::validate_on_attestation`.
    #[error("target epoch {epoch} starts before the anchor block of slot {anchor_slot}")]
    TargetBeforeAnchor {
        /// `data.target.epoch`.
        epoch: Epoch,
        /// The slot of that block.
        anchor_slot: Slot,
    },
    /// The target must be the checkpoint block of the attested block (the LMD vote must agree
    /// with the FFG vote).
    #[error("target {target} is not the checkpoint block {checkpoint_block}")]
    TargetNotCheckpointBlock {
        /// `data.target.root`.
        target: Root,
        /// `get_checkpoint_block(store, data.beacon_block_root, data.target.epoch)`.
        checkpoint_block: Root,
    },
    /// An attestation counts only from the slot after its own.
    #[error("attestation slot {slot} is not before the current slot {current}")]
    SlotNotPast {
        /// `data.slot`.
        slot: Slot,
        /// `get_current_slot(store)`.
        current: Slot,
    },
    /// `is_valid_indexed_attestation` is false: the indices are empty, not sorted or not
    /// unique, or the signature is invalid.
    #[error("the indexed attestation is not valid")]
    InvalidIndexedAttestation,
    /// `is_slashable_attestation_data` is false: not a double vote and not a surround vote.
    #[error("the two attestations are not slashable")]
    NotSlashable,
}

impl From<AttestationError> for Error {
    fn from(e: AttestationError) -> Self {
        Self::InvalidAttestation(e)
    }
}

/// Test seams. Only tests may enable them: the feature `testing` is for dev-dependencies.
/// They change the store without the checks of the handlers that they stand for:
/// `mark_payload_verified` stands for `on_execution_payload_envelope`, so that a test needs
/// no envelope, and the others let a test set a weight without the committees of an
/// attestation.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use crate::{LatestMessage, Store};
    use consensus_types::primitives::{Root, ValidatorIndex};
    use state_transition::Preset;

    /// Puts `root` in `store.payloads`, as `on_execution_payload_envelope` does after it
    /// verifies the envelope of the block.
    pub fn mark_payload_verified<E: Preset>(store: &mut Store<E>, root: Root) {
        store.payloads.insert(root);
    }

    /// Sets `store.latest_messages[validator_index]` to `message`, as `update_latest_messages`
    /// does for an attestation that `on_attestation` accepts. It replaces an earlier message
    /// of any slot, and it also sets a message of an equivocating validator: the test chooses.
    pub fn set_latest_message<E: Preset>(
        store: &mut Store<E>,
        validator_index: ValidatorIndex,
        message: LatestMessage,
    ) {
        store.latest_messages.insert(validator_index, message);
    }

    /// Puts `validator_index` in `store.equivocating_indices`, as `on_attester_slashing` does
    /// for each validator of both attestations of a slashing.
    pub fn add_equivocating_index<E: Preset>(
        store: &mut Store<E>,
        validator_index: ValidatorIndex,
    ) {
        store.equivocating_indices.insert(validator_index);
    }
}
