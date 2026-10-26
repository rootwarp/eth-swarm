//! The pure Gloas state transition (`specs/gloas/beacon-chain.md` at consensus-specs
//! v1.7.0-beta.4, and the earlier forks it inherits from).
//!
//! The crate does no I/O and links no BLS library: signature checks go through a
//! [`SignatureBackend`] that the caller supplies, and pubkey aggregation goes through a
//! [`PubkeyAggregator`].
//!
//! - [`state_transition`]: the slot loop, the block signature, the block and the state root.
//! - [`per_slot`]: `process_slots` and `process_slot`.
//! - [`per_epoch`]: the epoch processing (every step but the builder payments).
//! - [`per_block`]: the block processing: the step order, the header, the bid, RANDAO, eth1
//!   data, the voluntary exits, the BLS-to-execution changes, the payload attestations and
//!   the sync aggregate. The other steps and operations are stubs for now. It also has the
//!   builder requests and the consolidation requests of the parent payload.
//! - [`accessors`]: the beacon-state accessors and the misc helpers.
//! - [`caches`]: shuffling, beacon committees, proposer and PTC selection.
//! - [`mutators`]: the balance helpers, the exit and consolidation churn, validator and
//!   builder exits, builder-payment settlement and `slash_validator`.
//! - [`signatures`]: the [`SignatureBackend`] and [`PubkeyAggregator`] seams in a
//!   [`BlsContext`], the signature sets of a block and the deposit signature set.
//!
//! Each ported function cites its spec file and line range at the pin. File prefixes: P0
//! `phase0/beacon-chain.md`, A `altair/beacon-chain.md`, Bx `bellatrix/beacon-chain.md`, C
//! `capella/beacon-chain.md`, E `electra/beacon-chain.md`, Fu `fulu/beacon-chain.md`, G
//! `gloas/beacon-chain.md`.
//!
//! milhouse trees panic in `tree_hash_root` while they hold pending updates, so every root
//! of a state goes through [`state_root`], which flushes them first.

pub mod accessors;
pub mod caches;
pub mod mutators;
pub mod per_block;
pub mod per_epoch;
pub mod per_slot;
pub mod preset;
pub mod signatures;

#[cfg(test)]
mod testing;

pub use per_block::bid::BlobSchedule;
pub use preset::Preset;
pub use signatures::{
    AggregationError, BackendError, BlsContext, PubkeyAggregator, SignatureBackend, SignatureSet,
    SignerRef,
};

use consensus_types::gloas::{BeaconBlock, BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{
    BuilderIndex, Bytes32, CommitteeIndex, Epoch, Gwei, Hash32, Root, Slot, ValidatorIndex,
};
use tree_hash::TreeHash;

/// Why a state transition step failed. Most variants mean that the input is invalid by the
/// spec (a failed `assert`, an out-of-range access or a `Uint64` overflow). Some variants
/// are not a proof of an invalid input: [`StfError::proves_invalid`] gives the class of
/// each variant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StfError {
    /// The step is not ported yet; the text names the work that ports it.
    #[error("not implemented yet ({0})")]
    Unimplemented(&'static str),
    /// `process_slots` asserts `state.slot < slot`.
    #[error("target slot {slot} is not after the state slot {state_slot}")]
    SlotNotLater {
        /// `state.slot`.
        state_slot: Slot,
        /// The requested slot.
        slot: Slot,
    },
    /// The backend rejected a signature set of the block: the proposer signature, or a set
    /// of the same batch ([`signatures::block_signature_sets`]).
    #[error("invalid block signature")]
    InvalidBlockSignature,
    /// `block.state_root != hash_tree_root(state)` after the block.
    #[error("state root mismatch: block has {block}, the post-state is {computed}")]
    StateRootMismatch {
        /// `block.state_root`.
        block: Root,
        /// `hash_tree_root(state)`.
        computed: Root,
    },
    /// The signature backend gave no verdict. This is never a proof that the block is
    /// invalid: callers IGNORE, never REJECT, on it.
    #[error(transparent)]
    SignatureBackend(#[from] BackendError),
    /// A `Uint64` operation overflowed, underflowed or divided by zero.
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    /// `state.validators[index]` is out of range. A proof only on the object's own
    /// pre-state: see [`StfError::proves_invalid`].
    #[error("validator index {0} is out of range")]
    UnknownValidator(ValidatorIndex),
    /// An index past the end of a state list or a spec table, for example `balances`,
    /// `inactivity_scores`, the participation flags or `PARTICIPATION_FLAG_WEIGHTS`. It is
    /// also a `state.proposer_lookahead` entry past the end of `validators`.
    ///
    /// A state that the transition makes keeps these lists as long as the registry, keeps
    /// each lookahead entry in the registry, and the flag index comes from the code. Thus
    /// this error shows a bug in our state or in the caller, never a proof that the input
    /// object is invalid.
    #[error("index {index} is out of range of {list}")]
    ListIndexOutOfRange {
        /// The name of the list.
        list: &'static str,
        /// The index.
        index: u64,
    },
    /// `get_block_root_at_slot` asserts `slot < state.slot <= slot + SLOTS_PER_HISTORICAL_ROOT`.
    ///
    /// As [`StfError::EpochOutOfWindow`], this proves that the input is invalid only when
    /// the state is the object's own pre-state, advanced to the object's slot.
    #[error("block root of slot {slot} is out of the history of state slot {state_slot}")]
    BlockRootOutOfRange {
        /// The requested slot.
        slot: Slot,
        /// `state.slot`.
        state_slot: Slot,
    },
    /// `get_unslashed_participating_indices` asserts that `epoch` is the previous or the
    /// current epoch of the state. The spec calls it only with those two epochs, so this is
    /// a caller error, never a proof that the input is invalid.
    #[error("participation of epoch {epoch} is not kept by a state of epoch {state_epoch}")]
    ParticipationEpochOutOfRange {
        /// The requested epoch.
        epoch: Epoch,
        /// `get_current_epoch(state)`.
        state_epoch: Epoch,
    },
    /// `compute_shuffled_index` asserts `index < index_count`.
    #[error("shuffle index {index} is out of range of {index_count}")]
    ShuffleIndexOutOfRange {
        /// The index.
        index: u64,
        /// The number of indices.
        index_count: u64,
    },
    /// A selection had no candidates (`assert total > 0`).
    #[error("no candidate validators to select from")]
    NoCandidates,
    /// A beacon committee that does not exist at `slot`.
    #[error("committee {index} does not exist at slot {slot}")]
    UnknownCommittee {
        /// The slot.
        slot: Slot,
        /// The committee index.
        index: CommitteeIndex,
    },
    /// A bitfield is shorter than the committees it covers.
    #[error("bit {index} is out of range of a bitfield of length {len}")]
    BitOutOfRange {
        /// The bit index.
        index: usize,
        /// The length of the bitfield.
        len: usize,
    },
    /// An epoch that the state's PTC window or proposer lookahead does not cover.
    ///
    /// This proves that the input is invalid only when the state is the object's own
    /// pre-state, advanced to the object's slot. A caller that uses another state (for
    /// example a head state behind the slot of a gossip message) must map it to IGNORE.
    #[error("epoch {epoch} is out of the window of state epoch {state_epoch}")]
    EpochOutOfWindow {
        /// The requested epoch.
        epoch: Epoch,
        /// `get_current_epoch(state)`.
        state_epoch: Epoch,
    },
    /// A [`caches::CommitteeCache`] of another epoch than the slot's. This is a caller
    /// error, never a proof that the input is invalid.
    #[error("committee cache of epoch {cache_epoch} used for epoch {epoch}")]
    CacheEpochMismatch {
        /// The epoch of the cache.
        cache_epoch: Epoch,
        /// The epoch of the slot.
        epoch: Epoch,
    },
    /// A milhouse tree failed an update or a flush.
    #[error("state tree: {0}")]
    Tree(String),
    /// A [`caches::CommitteeCache`] of the slot's epoch, but with another attester seed than
    /// the state (for example a cache from another branch). This is a caller error, never a
    /// proof that the input is invalid.
    #[error("committee cache seed {cache_seed} differs from the state seed {state_seed} of epoch {epoch}")]
    CacheSeedMismatch {
        /// The epoch of the slot.
        epoch: Epoch,
        /// The seed of the cache.
        cache_seed: Bytes32,
        /// `get_seed(state, epoch, DOMAIN_BEACON_ATTESTER)`.
        state_seed: Bytes32,
    },
    /// `state.builders[index]` is out of range.
    #[error("builder index {0} is out of range")]
    UnknownBuilder(BuilderIndex),
    /// `settle_builder_payment` asserts `payment_index < len(state.builder_pending_payments)`.
    #[error("builder payment index {index} is out of range of {len}")]
    PaymentIndexOutOfRange {
        /// The payment index.
        index: u64,
        /// `len(state.builder_pending_payments)`.
        len: u64,
    },
    /// The backend has no verdict for the signature of a deposit with an inline key (for
    /// example a builder deposit, or a pending deposit of a new key at an epoch boundary).
    /// The caller fetches these verdicts before the transition (ADR-011), so this error
    /// means that the fetch did not give one. This is never a proof that the input is
    /// invalid: callers IGNORE, never REJECT, on it.
    #[error("no prefetched deposit signature verdict: {0}")]
    MissingVerdict(BackendError),
    /// `process_block_header` asserts `block.slot == state.slot`.
    #[error("block slot {block} is not the state slot {state}")]
    BlockSlotMismatch {
        /// `block.slot`.
        block: Slot,
        /// `state.slot`.
        state: Slot,
    },
    /// `process_block_header` asserts `block.slot > state.latest_block_header.slot`.
    #[error("block slot {block} is not after the latest block header slot {latest}")]
    BlockNotNewer {
        /// `block.slot`.
        block: Slot,
        /// `state.latest_block_header.slot`.
        latest: Slot,
    },
    /// `process_block_header` asserts `block.proposer_index == get_beacon_proposer_index(state)`.
    #[error("block proposer {block} is not the proposer {expected} of the slot")]
    WrongProposer {
        /// `block.proposer_index`.
        block: ValidatorIndex,
        /// `get_beacon_proposer_index(state)`.
        expected: ValidatorIndex,
    },
    /// `process_block_header` asserts that `block.parent_root` is the root of the latest
    /// block header.
    #[error("block parent root {block} is not the latest block header root {expected}")]
    ParentRootMismatch {
        /// `block.parent_root`.
        block: Root,
        /// `hash_tree_root(state.latest_block_header)`.
        expected: Root,
    },
    /// `process_block_header` asserts that the proposer is not slashed.
    #[error("proposer {0} is slashed")]
    ProposerSlashed(ValidatorIndex),
    /// The Gloas `process_operations` asserts `len(body.deposits) == 0`.
    #[error("block has {0} deposits, Gloas allows none")]
    BlockDeposits(usize),
    /// A sync committee pubkey that no validator has (`all_pubkeys.index` raises in
    /// `process_sync_aggregate`). The keys come from the state, and a state that the spec
    /// makes has each of them in its registry, so this error shows a fault of our own state,
    /// never a proof that the block is invalid.
    #[error("sync committee member {position} is not in the validator registry")]
    UnknownSyncCommitteeMember {
        /// The position in `state.current_sync_committee.pubkeys`.
        position: usize,
    },
    /// The sync aggregate signature is invalid: an empty aggregate whose signature is not
    /// `G2_POINT_AT_INFINITY` (`eth_fast_aggregate_verify`), or a backend rejection in
    /// [`signatures::verify_sync_aggregate_signature`].
    #[error("invalid sync aggregate signature")]
    InvalidSyncAggregateSignature,
    /// The [`PubkeyAggregator`] failed on the keys of the next sync committee. The keys come
    /// from the registry, so this is a failure of the aggregator or of our state, never a
    /// proof that the input is invalid.
    #[error(transparent)]
    PubkeyAggregation(#[from] AggregationError),
    /// `process_payload_attestation` asserts
    /// `data.beacon_block_root == state.latest_block_header.parent_root`.
    #[error("payload attestation root {attestation} is not the parent block root {expected}")]
    PayloadAttestationRootMismatch {
        /// `data.beacon_block_root`.
        attestation: Root,
        /// `state.latest_block_header.parent_root`.
        expected: Root,
    },
    /// `process_payload_attestation` asserts `data.slot + 1 == state.slot`.
    #[error("payload attestation slot {attestation} is not the slot before {state}")]
    PayloadAttestationSlotMismatch {
        /// `data.slot`.
        attestation: Slot,
        /// `state.slot`.
        state: Slot,
    },
    /// `is_valid_indexed_payload_attestation` is false: the attestation has no attesting
    /// index (no aggregation bit is set).
    #[error("payload attestation has no attester")]
    PayloadAttestationNoAttesters,
    /// `is_valid_indexed_payload_attestation` is false: the attesting indices are not
    /// sorted.
    #[error("payload attestation indices are not sorted")]
    PayloadAttestationUnsorted,
    /// `is_valid_indexed_payload_attestation` is false: the backend rejected the aggregate
    /// signature ([`signatures::verify_payload_attestation_signature`] or
    /// [`per_block::payload_attestation::is_valid_indexed_payload_attestation`]).
    #[error("invalid payload attestation signature")]
    InvalidPayloadAttestationSignature,
    /// `process_voluntary_exit` asserts that the validator is active in the current epoch.
    #[error("validator {0} is not active, so it cannot exit")]
    ExitNotActive(ValidatorIndex),
    /// `process_voluntary_exit` asserts `validator.exit_epoch == FAR_FUTURE_EPOCH`.
    #[error("validator {0} already initiated its exit")]
    ExitAlreadyInitiated(ValidatorIndex),
    /// `process_voluntary_exit` asserts `get_current_epoch(state) >= voluntary_exit.epoch`.
    #[error("exit epoch {exit_epoch} is after the current epoch {current_epoch}")]
    ExitEpochInFuture {
        /// `voluntary_exit.epoch`.
        exit_epoch: Epoch,
        /// `get_current_epoch(state)`.
        current_epoch: Epoch,
    },
    /// `process_voluntary_exit` asserts
    /// `get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD`.
    #[error(
        "validator {index} can exit from epoch {earliest_epoch}, not in epoch {current_epoch}"
    )]
    ExitTooEarly {
        /// `voluntary_exit.validator_index`.
        index: ValidatorIndex,
        /// `validator.activation_epoch + SHARD_COMMITTEE_PERIOD`.
        earliest_epoch: Epoch,
        /// `get_current_epoch(state)`.
        current_epoch: Epoch,
    },
    /// `process_voluntary_exit` asserts
    /// `get_pending_balance_to_withdraw(state, voluntary_exit.validator_index) == 0`.
    #[error("validator {index} has {pending} Gwei of pending withdrawals, so it cannot exit")]
    ExitPendingWithdrawals {
        /// `voluntary_exit.validator_index`.
        index: ValidatorIndex,
        /// `get_pending_balance_to_withdraw(state, index)`.
        pending: Gwei,
    },
    /// The backend rejected the signature of a voluntary exit in
    /// [`signatures::verify_voluntary_exit_signature`] (the `bls.Verify` of
    /// `process_voluntary_exit`).
    #[error("invalid voluntary exit signature")]
    InvalidVoluntaryExitSignature,
    /// `process_bls_to_execution_change` asserts
    /// `validator.withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX`.
    #[error("validator {0} does not have BLS withdrawal credentials")]
    NotBlsWithdrawalCredentials(ValidatorIndex),
    /// `process_bls_to_execution_change` asserts
    /// `validator.withdrawal_credentials[1:] == sha256(address_change.from_bls_pubkey)[1:]`.
    #[error("from_bls_pubkey is not the key of the withdrawal credentials of validator {0}")]
    BlsChangeKeyMismatch(ValidatorIndex),
    /// The backend rejected the signature of a BLS-to-execution change in
    /// [`signatures::verify_bls_to_execution_change_signature`] (the `bls.Verify` of
    /// `process_bls_to_execution_change`).
    #[error("invalid BLS-to-execution change signature")]
    InvalidBlsToExecutionChangeSignature,
    /// `process_attestation` asserts that `data.target.epoch` is the previous or the current
    /// epoch of the state.
    #[error("attestation target epoch {target} is not the previous or the current epoch of state epoch {state_epoch}")]
    AttestationTargetEpoch {
        /// `data.target.epoch`.
        target: Epoch,
        /// `get_current_epoch(state)`.
        state_epoch: Epoch,
    },
    /// `process_attestation` asserts `data.target.epoch == compute_epoch_at_slot(data.slot)`.
    #[error("attestation target epoch {target} is not the epoch of its slot {slot}")]
    AttestationTargetSlot {
        /// `data.target.epoch`.
        target: Epoch,
        /// `data.slot`.
        slot: Slot,
    },
    /// `process_attestation` asserts `data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot`.
    #[error("attestation of slot {slot} is too early for state slot {state_slot}")]
    AttestationTooEarly {
        /// `data.slot`.
        slot: Slot,
        /// `state.slot`.
        state_slot: Slot,
    },
    /// The Gloas `process_attestation` asserts `data.index < 2`: the index tells the payload
    /// status, not a committee.
    #[error("attestation data index {0} is not 0 or 1")]
    AttestationDataIndex(u64),
    /// The Gloas `get_attestation_participation_flag_indices` asserts `data.index == 0` for an
    /// attestation of the block of its own slot (`is_attestation_same_slot`).
    #[error("same-slot attestation has data index {0}, not 0")]
    SameSlotAttestationIndex(u64),
    /// `process_attestation` asserts that each committee of `committee_bits` has an attester.
    #[error("committee {0} of the attestation has no attester")]
    EmptyCommitteeAttesters(CommitteeIndex),
    /// `process_attestation` asserts that `aggregation_bits` is as long as its committees.
    #[error("aggregation bits have length {len}, the committees have {participants} members")]
    AggregationBitsLength {
        /// `len(attestation.aggregation_bits)`.
        len: usize,
        /// The sum of the committee sizes (`committee_offset`).
        participants: usize,
    },
    /// `get_attestation_participation_flag_indices` asserts `is_matching_source`: the source
    /// is not the justified checkpoint of the target epoch.
    #[error("attestation source is not the justified checkpoint")]
    AttestationSourceMismatch,
    /// `is_valid_indexed_attestation` is false before its BLS check: the attesting indices are
    /// empty, more than `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`, or not
    /// sorted and unique.
    #[error("attesting indices are empty, too many, or not sorted and unique")]
    InvalidIndexedAttestation,
    /// `process_attester_slashing` asserts `is_slashable_attestation_data`: the two data are
    /// not a double vote and not a surround vote.
    #[error("attester slashing data are not slashable")]
    NotSlashableAttestationData,
    /// `process_attester_slashing` asserts `slashed_any`: no validator in both attestations
    /// is slashable.
    #[error("attester slashing slashes no validator")]
    NoValidatorSlashed,
    /// `process_proposer_slashing` asserts `header_1.slot == header_2.slot`.
    #[error("proposer slashing headers have slots {slot_1} and {slot_2}")]
    ProposerSlashingSlots {
        /// `header_1.slot`.
        slot_1: Slot,
        /// `header_2.slot`.
        slot_2: Slot,
    },
    /// `process_proposer_slashing` asserts `header_1.proposer_index == header_2.proposer_index`.
    #[error("proposer slashing headers have proposers {proposer_1} and {proposer_2}")]
    ProposerSlashingProposers {
        /// `header_1.proposer_index`.
        proposer_1: ValidatorIndex,
        /// `header_2.proposer_index`.
        proposer_2: ValidatorIndex,
    },
    /// `process_proposer_slashing` asserts `header_1 != header_2`.
    #[error("proposer slashing headers are the same")]
    ProposerSlashingSameHeaders,
    /// `process_proposer_slashing` asserts `is_slashable_validator` for the proposer.
    #[error("validator {0} is not slashable")]
    ValidatorNotSlashable(ValidatorIndex),
    /// The backend rejected a signature set of one operation (an attestation, an attester
    /// slashing or a proposer slashing) that the caller checks alone, through
    /// [`signatures::verify_operation_signatures`], not in the batch of the block.
    #[error("invalid operation signature")]
    InvalidOperationSignature,
    /// A part of the withdrawals sweep got more prior withdrawals than its limit (the
    /// `assert len(prior_withdrawals) <= withdrawals_limit` of G L1867 and L1920, E L1366, and
    /// the `<` of E L1412). The prior withdrawals come from `get_expected_withdrawals`, which
    /// keeps each part inside its limit, so this error shows a bug in our code or in the
    /// caller, never a proof that the input is invalid.
    #[error("{prior} prior withdrawals are past the limit {limit}")]
    PriorWithdrawalsPastLimit {
        /// `len(prior_withdrawals)`.
        prior: u64,
        /// The largest number of prior withdrawals that the part accepts.
        limit: u64,
    },
    /// A `Uint64` operation of the withdrawals sweep overflowed, underflowed or divided by
    /// zero. Each operand comes from the state only: the withdrawal index, the balances, the
    /// sweep cursors and the length of the registry. A state that the transition makes keeps
    /// them in range, so this error shows a fault of our own state, never a proof that a block
    /// is invalid.
    #[error("withdrawals sweep arithmetic failed on the state: {what}")]
    StateArithmetic {
        /// The value that failed, for example `"withdrawal index"`.
        what: &'static str,
    },
    /// `process_execution_payload_bid` asserts `amount == 0` for a self-build bid
    /// (`BUILDER_INDEX_SELF_BUILD`).
    #[error("self-build bid has the value {0}, not 0")]
    SelfBuildBidValue(Gwei),
    /// `process_execution_payload_bid` asserts that the signature of a self-build bid is
    /// `G2_POINT_AT_INFINITY`.
    #[error("self-build bid signature is not the infinity point")]
    SelfBuildBidSignature,
    /// `process_execution_payload_bid` asserts `is_active_builder` for the builder of the bid.
    #[error("builder {0} is not active, so it cannot bid")]
    BidBuilderNotActive(BuilderIndex),
    /// `process_execution_payload_bid` asserts that the builder of the bid has
    /// `PAYLOAD_BUILDER_VERSION`.
    #[error("builder {index} has version {version}, not the payload builder version")]
    BidBuilderVersion {
        /// `bid.builder_index`.
        index: BuilderIndex,
        /// `state.builders[index].version`.
        version: u8,
    },
    /// `process_execution_payload_bid` asserts `can_builder_cover_bid`.
    #[error("builder {index} cannot cover a bid of {amount} Gwei")]
    BidNotCovered {
        /// `bid.builder_index`.
        index: BuilderIndex,
        /// `bid.value`.
        amount: Gwei,
    },
    /// `process_execution_payload_bid` asserts that the bid has at most
    /// `get_blob_parameters(get_current_epoch(state)).max_blobs_per_block` blob commitments.
    #[error("bid has {count} blob commitments, the limit is {max}")]
    BidBlobCommitments {
        /// `len(bid.blob_kzg_commitments)`.
        count: usize,
        /// The limit of the network for the epoch.
        max: u64,
    },
    /// `process_execution_payload_bid` asserts `bid.slot == state.slot`.
    #[error("bid slot {bid} is not the state slot {state}")]
    BidSlotMismatch {
        /// `bid.slot`.
        bid: Slot,
        /// `state.slot`.
        state: Slot,
    },
    /// `process_execution_payload_bid` asserts `state.slot > GENESIS_SLOT`.
    #[error("a bid cannot be at the genesis slot")]
    BidAtGenesisSlot,
    /// `process_execution_payload_bid` asserts
    /// `bid.parent_block_hash == state.latest_block_hash`.
    #[error("bid parent block hash {bid} is not the latest block hash {expected}")]
    BidParentBlockHash {
        /// `bid.parent_block_hash`.
        bid: Hash32,
        /// `state.latest_block_hash`.
        expected: Hash32,
    },
    /// `process_execution_payload_bid` asserts `bid.block_hash != bid.parent_block_hash`.
    #[error("bid block hash is the same as its parent block hash")]
    BidBlockHashIsParent,
    /// `process_execution_payload_bid` asserts
    /// `bid.parent_block_root == get_block_root_at_slot(state, state.slot - 1)`.
    #[error("bid parent block root {bid} is not the block root {expected} of the previous slot")]
    BidParentBlockRoot {
        /// `bid.parent_block_root`.
        bid: Root,
        /// `get_block_root_at_slot(state, state.slot - 1)`.
        expected: Root,
    },
    /// `process_execution_payload_bid` asserts
    /// `bid.prev_randao == get_randao_mix(state, get_current_epoch(state))`.
    #[error("bid prev_randao {bid} is not the RANDAO mix {expected} of the current epoch")]
    BidPrevRandao {
        /// `bid.prev_randao`.
        bid: Bytes32,
        /// `get_randao_mix(state, get_current_epoch(state))`.
        expected: Bytes32,
    },
    /// The [`per_block::BlockContext`] has no blob limit of the network for the epoch of the
    /// state. The caller did not give it ([`per_block::BlockContext::set_max_blobs_per_block`]).
    /// This is a caller error, never a proof that the input is invalid.
    #[error("no blob limit of the network for epoch {0}")]
    UnknownBlobLimit(Epoch),
}

impl StfError {
    /// Whether the error proves that the input is invalid by the spec (REJECT). It does not
    /// for a step that is not ported yet, a backend without a verdict, a missing deposit
    /// verdict, a failed pubkey aggregation, a committee cache of another epoch or seed, a
    /// failure of the state trees, a state list shorter than the registry, a
    /// `proposer_lookahead` entry past the registry or a code index past a spec table
    /// (`ListIndexOutOfRange`), a participation epoch other than the previous and the
    /// current one (`ParticipationEpochOutOfRange`), prior withdrawals past the limit of a
    /// sweep part (`PriorWithdrawalsPastLimit`), or a failed `Uint64` operation of the
    /// withdrawals sweep on values of our own state (`StateArithmetic`): callers IGNORE
    /// those, never REJECT.
    ///
    /// These variants are a proof only when the state is the object's own pre-state,
    /// advanced to the object's slot: [`StfError::EpochOutOfWindow`],
    /// [`StfError::BlockRootOutOfRange`], [`StfError::BlockSlotMismatch`],
    /// [`StfError::BlockNotNewer`], [`StfError::WrongProposer`],
    /// [`StfError::ParentRootMismatch`], [`StfError::ProposerSlashed`],
    /// [`StfError::InvalidSyncAggregateSignature`],
    /// [`StfError::PayloadAttestationRootMismatch`],
    /// [`StfError::PayloadAttestationSlotMismatch`] and
    /// [`StfError::InvalidPayloadAttestationSignature`]. A caller that uses another state (for
    /// example a head state behind the slot of a gossip message) must map them to IGNORE.
    ///
    /// The asserts of a voluntary exit and of a BLS-to-execution change read the validator
    /// in the state, and they have the same rule: [`StfError::ExitNotActive`],
    /// [`StfError::ExitAlreadyInitiated`], [`StfError::ExitEpochInFuture`],
    /// [`StfError::ExitTooEarly`], [`StfError::ExitPendingWithdrawals`],
    /// [`StfError::InvalidVoluntaryExitSignature`], [`StfError::NotBlsWithdrawalCredentials`]
    /// and [`StfError::BlsChangeKeyMismatch`].
    ///
    /// [`StfError::UnknownValidator`] has the same rule. The result depends on the registry
    /// of the state that the caller uses. A head state older than the object can have a
    /// shorter registry, so the index of a valid object can be past it. Thus a caller that
    /// uses another state than the object's own pre-state must map it to IGNORE.
    ///
    /// The attestation and slashing variants that read the state have the same rule:
    /// [`StfError::AttestationTargetEpoch`], [`StfError::AttestationTooEarly`],
    /// [`StfError::SameSlotAttestationIndex`], [`StfError::EmptyCommitteeAttesters`],
    /// [`StfError::AggregationBitsLength`], [`StfError::AttestationSourceMismatch`],
    /// [`StfError::NoValidatorSlashed`], [`StfError::ValidatorNotSlashable`] and
    /// [`StfError::InvalidOperationSignature`].
    ///
    /// The bid variants that read the state have the same rule:
    /// [`StfError::BidBuilderNotActive`], [`StfError::BidBuilderVersion`],
    /// [`StfError::BidNotCovered`], [`StfError::BidSlotMismatch`],
    /// [`StfError::BidAtGenesisSlot`], [`StfError::BidParentBlockHash`],
    /// [`StfError::BidParentBlockRoot`] and [`StfError::BidPrevRandao`].
    /// [`StfError::BidBlobCommitments`] is a proof only with the blob schedule of the
    /// network of the bid. [`StfError::UnknownBlobLimit`] is a caller error: IGNORE.
    ///
    /// The match has no `_` arm, so each new variant must select its class here.
    pub fn proves_invalid(&self) -> bool {
        match self {
            Self::Unimplemented(_)
            | Self::SignatureBackend(_)
            | Self::CacheEpochMismatch { .. }
            | Self::CacheSeedMismatch { .. }
            | Self::Tree(_)
            // A state list shorter than the registry, a lookahead entry past the registry,
            // or a flag index past the table: our own state or code is wrong, and the
            // object did not cause it.
            | Self::ListIndexOutOfRange { .. }
            // The spec reads participation only for the previous and the current epoch,
            // so another epoch is a caller error.
            | Self::ParticipationEpochOutOfRange { .. }
            // The verdict was not fetched, which says nothing about the deposit.
            | Self::MissingVerdict(_)
            // The committee keys come from the state, not from the block, and a state that
            // the spec makes has each of them in its registry. So, as for
            // `ListIndexOutOfRange`, our own state is wrong, and the block did not cause it.
            | Self::UnknownSyncCommitteeMember { .. }
            // Registry keys passed a proof of possession, so the aggregator or our state
            // failed, not the object.
            | Self::PubkeyAggregation(_)
            // The prior withdrawals come from our own `get_expected_withdrawals`, not from
            // the object, so an excess is a fault of our code.
            | Self::PriorWithdrawalsPastLimit { .. }
            // The operands come from our own state, not from the block, so a failure is a
            // fault of our state.
            | Self::StateArithmetic { .. }
            // The caller did not give the blob limit of the network, which says nothing
            // about the bid.
            | Self::UnknownBlobLimit(_) => false,
            Self::SlotNotLater { .. }
            | Self::InvalidBlockSignature
            | Self::StateRootMismatch { .. }
            | Self::ArithmeticOverflow
            // A proof only on the object's own pre-state, as for `EpochOutOfWindow`.
            | Self::UnknownValidator(_)
            | Self::ShuffleIndexOutOfRange { .. }
            | Self::NoCandidates
            | Self::UnknownCommittee { .. }
            | Self::BitOutOfRange { .. }
            | Self::EpochOutOfWindow { .. }
            // The `assert` of `get_block_root_at_slot`: a spec error on the object's own
            // pre-state, as for `EpochOutOfWindow`.
            | Self::BlockRootOutOfRange { .. }
            // An out-of-range access of `state.builders`, a spec error.
            | Self::UnknownBuilder(_)
            // The `assert` of `settle_builder_payment` on the length of
            // `state.builder_pending_payments`, a spec error.
            | Self::PaymentIndexOutOfRange { .. }
            // The asserts of `process_block_header` on the block's own pre-state at its
            // slot: the slot, a newer slot than the parent header, the proposer of the
            // slot, the parent root, and a proposer that is not slashed.
            | Self::BlockSlotMismatch { .. }
            | Self::BlockNotNewer { .. }
            | Self::WrongProposer { .. }
            | Self::ParentRootMismatch { .. }
            | Self::ProposerSlashed(_)
            // `assert len(body.deposits) == 0` of the Gloas `process_operations`: a
            // property of the block alone.
            | Self::BlockDeposits(_)
            // `eth_fast_aggregate_verify` is false: an empty aggregate without the infinity
            // signature, or a verdict of the backend (as for `InvalidBlockSignature`).
            | Self::InvalidSyncAggregateSignature
            // The asserts of `process_payload_attestation` on the block's own pre-state at
            // its slot: the parent block root and the previous slot.
            | Self::PayloadAttestationRootMismatch { .. }
            | Self::PayloadAttestationSlotMismatch { .. }
            // The structural checks of `is_valid_indexed_payload_attestation`: properties of
            // the attestation alone. No set bit gives no index, on any state.
            | Self::PayloadAttestationNoAttesters
            | Self::PayloadAttestationUnsorted
            // `bls.FastAggregateVerify` is false: a verdict of the backend on the
            // attestation's own pre-state, as for `InvalidSyncAggregateSignature`.
            | Self::InvalidPayloadAttestationSignature
            // The asserts of `process_voluntary_exit` on the exit and on the validator in the
            // exit's own pre-state at its slot: active, no exit yet, an epoch that is not in
            // the future, active for `SHARD_COMMITTEE_PERIOD`, and no pending withdrawal.
            | Self::ExitNotActive(_)
            | Self::ExitAlreadyInitiated(_)
            | Self::ExitEpochInFuture { .. }
            | Self::ExitTooEarly { .. }
            | Self::ExitPendingWithdrawals { .. }
            // `bls.Verify` is false for the key of the validator in the registry, a verdict
            // of the backend (as for `InvalidBlockSignature`).
            | Self::InvalidVoluntaryExitSignature
            // The asserts of `process_bls_to_execution_change` on the change and on the
            // withdrawal credentials of the validator in the change's own pre-state.
            | Self::NotBlsWithdrawalCredentials(_)
            | Self::BlsChangeKeyMismatch(_)
            // `bls.Verify` is false for the inline key of the change, a verdict of the
            // backend (as for `InvalidBlockSignature`).
            | Self::InvalidBlsToExecutionChangeSignature
            // The asserts of `process_attestation` and of its flag indices on the state at
            // the attestation's block slot: the target epoch, the inclusion delay, the index
            // of a same-slot attestation, the attesters of each committee, the length of
            // the bits and the source. A proof only on the object's own pre-state.
            | Self::AttestationTargetEpoch { .. }
            | Self::AttestationTooEarly { .. }
            | Self::SameSlotAttestationIndex(_)
            | Self::EmptyCommitteeAttesters(_)
            | Self::AggregationBitsLength { .. }
            | Self::AttestationSourceMismatch
            // Properties of the attestation alone: the target epoch of its slot, and an
            // index that is not a payload status.
            | Self::AttestationTargetSlot { .. }
            | Self::AttestationDataIndex(_)
            // `is_valid_indexed_attestation` is false for the indices alone.
            | Self::InvalidIndexedAttestation
            // The asserts of `process_attester_slashing` and `process_proposer_slashing`
            // on the slashing alone: two data that are not slashable, and two headers of
            // other slots, of other proposers, or that are the same.
            | Self::NotSlashableAttestationData
            | Self::ProposerSlashingSlots { .. }
            | Self::ProposerSlashingProposers { .. }
            | Self::ProposerSlashingSameHeaders
            // The slashable checks read the registry of the state: a proof only on the
            // object's own pre-state.
            | Self::NoValidatorSlashed
            | Self::ValidatorNotSlashable(_)
            // A verdict of the backend on the keys of the state, as for
            // `InvalidBlockSignature`.
            | Self::InvalidOperationSignature
            // The asserts of a self-build bid and the block hash of a bid: properties of the
            // bid alone.
            | Self::SelfBuildBidValue(_)
            | Self::SelfBuildBidSignature
            | Self::BidBlockHashIsParent
            // The asserts of `process_execution_payload_bid` that read the state: the
            // builder, its funds, the slot, the latest block hash, the block root of the
            // previous slot and the RANDAO mix. A proof only on the bid's own pre-state.
            | Self::BidBuilderNotActive(_)
            | Self::BidBuilderVersion { .. }
            | Self::BidNotCovered { .. }
            | Self::BidSlotMismatch { .. }
            | Self::BidAtGenesisSlot
            | Self::BidParentBlockHash { .. }
            | Self::BidParentBlockRoot { .. }
            | Self::BidPrevRandao { .. }
            // The limit of the blob schedule of the network at the bid's epoch: a proof
            // with the network config of the bid's chain.
            | Self::BidBlobCommitments { .. } => true,
        }
    }
}

impl From<milhouse::Error> for StfError {
    fn from(e: milhouse::Error) -> Self {
        Self::Tree(e.to_string())
    }
}

/// `hash_tree_root(state)`, after the pending updates of every milhouse tree are flushed.
pub fn state_root<E: Preset>(state: &mut BeaconState<E>) -> Result<Root, StfError> {
    state.apply_updates()?;
    Ok(state.tree_hash_root())
}

/// `state_transition` (P0 L1822-1835).
///
/// Processes the slots up to `block.slot`, applies the block, and checks
/// `block.state_root`. With `validate_result` true it first runs the cheap header checks
/// ([`per_block::check_block_header`]) and then checks every signature set of the block
/// ([`signatures::block_signature_sets`]) through `bls.backend` in one call. A block that
/// fails the header checks costs no registry read and no backend call. On `Err`, `state` is
/// partly updated: the caller drops it.
///
/// `validate_result` controls only the signature sets of the block. With `validate_result`
/// false, the call does not check the proposer signature, the RANDAO reveal, the sync
/// aggregate signature and the payload attestation signatures. The spec skips only the
/// proposer signature there. Use `validate_result` false only to compute the state root of
/// a block that we produce ourselves, whose signatures we made. The checks that need no BLS
/// (for example the infinity signature of an empty sync aggregate) run in both modes.
///
/// The slot loop always needs `bls`, in both modes. At each epoch boundary it asks
/// `bls.backend` for the verdicts of the pending deposits of new keys, and it aggregates the
/// keys of the next sync committee through `bls.aggregator` (see
/// [`per_slot::process_slots`]). Prefetch the deposit verdicts with
/// [`per_epoch::pending_deposit_signature_sets`] on the pre-state and `block.slot`.
///
/// # Warning
///
/// Do not use this function on real blocks yet. Block processing is ported only in part:
/// [`per_block::process_block`] returns [`StfError::Unimplemented`] at its first step (the
/// parent payload), so every block fails with an error that is not a proof of an invalid
/// block.
///
/// Bound `block.slot` against the wall clock before the call. As in the spec, the slots
/// are processed before the signature check, and `process_slots` has no upper bound: a
/// block with a far-future slot costs one `process_slot` for each slot.
pub fn state_transition<E: Preset>(
    state: &mut BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    validate_result: bool,
    bls: &BlsContext,
) -> Result<(), StfError> {
    apply_block(
        state,
        signed_block,
        validate_result,
        bls,
        per_block::process_block_with,
    )
}

/// The body of [`state_transition`] with the block processing as a parameter, so that tests
/// can run the slot loop, the signature check and the root check with any `block_fn`.
pub(crate) fn apply_block<E, F>(
    state: &mut BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    validate_result: bool,
    bls: &BlsContext,
    block_fn: F,
) -> Result<(), StfError>
where
    E: Preset,
    F: FnOnce(
        &mut BeaconState<E>,
        &BeaconBlock<E>,
        &mut per_block::BlockContext,
    ) -> Result<(), StfError>,
{
    let block = &signed_block.message;
    per_slot::process_slots(state, block.slot, bls)?;
    // One context for the block: the signature sets and the steps share the sync committee
    // indices. The bid step reads the blob limit of the network for the epoch of the block.
    let mut ctx = per_block::BlockContext::default();
    let epoch = accessors::get_current_epoch(state);
    ctx.set_max_blobs_per_block(epoch, bls.blob_schedule.max_blobs_per_block(epoch));
    if validate_result {
        per_block::check_block_header(state, block)?;
        signatures::verify_block_signatures_with(state, signed_block, bls, &mut ctx)?;
    }
    block_fn(state, block, &mut ctx)?;
    if validate_result {
        let computed = state_root(state)?;
        if computed != block.state_root {
            return Err(StfError::StateRootMismatch {
                block: block.state_root,
                computed,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::get_domain;
    use crate::testing::{block_at_state_slot, bls_context, genesis_state, no_bls};
    use consensus_types::signing::{compute_signing_root, DOMAIN_BEACON_PROPOSER};
    use consensus_types::Minimal;
    use std::cell::RefCell;

    /// A backend with a fixed verdict that records every set it is asked about.
    struct FixedBackend {
        verdict: Result<bool, BackendError>,
        seen: RefCell<Vec<SignatureSet>>,
    }

    impl FixedBackend {
        fn new(verdict: Result<bool, BackendError>) -> Self {
            Self {
                verdict,
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl SignatureBackend for FixedBackend {
        fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
            self.seen.borrow_mut().extend_from_slice(sets);
            self.verdict.clone()
        }
    }

    fn no_op(
        _: &mut BeaconState<Minimal>,
        _: &BeaconBlock<Minimal>,
        _: &mut per_block::BlockContext,
    ) -> Result<(), StfError> {
        Ok(())
    }

    /// The pre-state, and a block at slot 1 by the proposer of the slot, on the latest block
    /// header, whose `state_root` is the post-state root of the slot loop.
    fn state_and_block() -> (BeaconState<Minimal>, SignedBeaconBlock<Minimal>) {
        let state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        let mut post = state.clone();
        per_slot::process_slots(&mut post, 1, &no_bls()).unwrap();
        let mut block = block_at_state_slot(&post);
        block.message.state_root = state_root(&mut post).unwrap();
        (state, block)
    }

    #[test]
    fn block_context_has_the_blob_limit_of_the_network() {
        // The context has the limit of the schedule for the epoch of the block (0), and no
        // limit for another epoch.
        let (mut state, block) = state_and_block();
        let schedule = |epoch: Epoch| if epoch == 0 { 6 } else { 9 };
        let bls = BlsContext {
            blob_schedule: &schedule,
            ..no_bls()
        };
        let mut seen = Vec::new();
        let read = |_: &mut BeaconState<Minimal>,
                    _: &BeaconBlock<Minimal>,
                    ctx: &mut per_block::BlockContext| {
            seen = vec![ctx.max_blobs_per_block(0), ctx.max_blobs_per_block(1)];
            Ok(())
        };
        assert_eq!(apply_block(&mut state, &block, false, &bls, read), Ok(()));
        assert_eq!(seen, vec![Ok(6), Err(StfError::UnknownBlobLimit(1))]);
    }

    #[test]
    fn bad_block_signature() {
        let (state, block) = state_and_block();
        let rejecting = FixedBackend::new(Ok(false));
        assert_eq!(
            apply_block(
                &mut state.clone(),
                &block,
                true,
                &bls_context(&rejecting),
                no_op
            ),
            Err(StfError::InvalidBlockSignature)
        );
        // The backend saw the proposer set of the block first, in one batch with the
        // RANDAO set (the sync aggregate is empty, with the infinity signature).
        let mut at_slot = state.clone();
        per_slot::process_slots(&mut at_slot, 1, &no_bls()).unwrap();
        let domain = get_domain(&at_slot, DOMAIN_BEACON_PROPOSER, None);
        let want = SignatureSet::single(
            SignerRef::Validator(block.message.proposer_index),
            compute_signing_root(&block.message, domain),
            [0x11; 96],
        );
        let randao = signatures::randao_signature_set(&at_slot, &block.message.body).unwrap();
        assert_eq!(*rejecting.seen.borrow(), vec![want, randao]);

        // No verdict is not a proof of a bad signature.
        let unavailable = FixedBackend::new(Err(BackendError("timeout".into())));
        assert_eq!(
            apply_block(
                &mut state.clone(),
                &block,
                true,
                &bls_context(&unavailable),
                no_op
            ),
            Err(StfError::SignatureBackend(BackendError("timeout".into())))
        );
        // Without `validate_result` the backend is not asked.
        let skipped = FixedBackend::new(Ok(false));
        assert_eq!(
            apply_block(
                &mut state.clone(),
                &block,
                false,
                &bls_context(&skipped),
                no_op
            ),
            Ok(())
        );
        assert!(skipped.seen.borrow().is_empty());
        // A proposer outside the registry is not the proposer of the slot, and its set has
        // no key to check.
        let mut stranger = block.clone();
        stranger.message.proposer_index = 8;
        assert_eq!(
            apply_block(
                &mut state.clone(),
                &stranger,
                true,
                &bls_context(&FixedBackend::new(Ok(true))),
                no_op
            ),
            Err(StfError::WrongProposer {
                block: 8,
                expected: block.message.proposer_index
            })
        );
        assert_eq!(
            signatures::block_proposer_signature_set(&at_slot, &stranger),
            Err(StfError::UnknownValidator(8))
        );
    }

    #[test]
    fn header_checks_run_before_the_registry_scan() {
        // 64 validators at slot 1, and a sync committee with a key outside the registry: a
        // registry scan for the committee indices fails with `UnknownSyncCommitteeMember`.
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        state.current_sync_committee.pubkeys[0] = [0xee; 48];
        let mut at_slot = state.clone();
        per_slot::process_slots(&mut at_slot, 1, &no_bls()).unwrap();
        let mut block = block_at_state_slot(&at_slot);
        let aggregate = &mut block.message.body.sync_aggregate;
        aggregate.sync_committee_bits.set(0, true).unwrap();
        aggregate.sync_committee_signature = [0x22; 96];

        // A block with a wrong parent fails at the header checks: no scan, no backend call.
        let mut orphan = block.clone();
        orphan.message.parent_root = Root::repeat_byte(9);
        let backend = FixedBackend::new(Ok(true));
        assert!(matches!(
            apply_block(
                &mut state.clone(),
                &orphan,
                true,
                &bls_context(&backend),
                no_op
            ),
            Err(StfError::ParentRootMismatch { .. })
        ));
        // A block with a wrong slot for its proposer fails the same way.
        let mut stranger = block.clone();
        stranger.message.proposer_index = (block.message.proposer_index + 1) % 64;
        assert!(matches!(
            apply_block(
                &mut state.clone(),
                &stranger,
                true,
                &bls_context(&backend),
                no_op
            ),
            Err(StfError::WrongProposer { .. })
        ));
        assert!(backend.seen.borrow().is_empty());

        // A block that passes the header checks reaches the scan before the backend.
        assert_eq!(
            apply_block(
                &mut state.clone(),
                &block,
                true,
                &bls_context(&backend),
                no_op
            ),
            Err(StfError::UnknownSyncCommitteeMember { position: 0 })
        );
        assert!(backend.seen.borrow().is_empty());
    }

    #[test]
    fn lookahead_outside_the_registry_is_not_a_proof() {
        // 64 validators, and a lookahead entry of 64 for slot 1: the index comes from our
        // own state, so a block that carries it gets an error that is not a proof.
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        *state.proposer_lookahead.get_mut(1).unwrap() = 64;
        let mut at_slot = state.clone();
        per_slot::process_slots(&mut at_slot, 1, &no_bls()).unwrap();
        let block = block_at_state_slot(&at_slot);
        assert_eq!(block.message.proposer_index, 64);
        let backend = FixedBackend::new(Ok(true));
        let err = apply_block(
            &mut state.clone(),
            &block,
            true,
            &bls_context(&backend),
            no_op,
        )
        .unwrap_err();
        assert_eq!(
            err,
            StfError::ListIndexOutOfRange {
                list: "validators",
                index: 64
            }
        );
        assert!(!err.proves_invalid());
        assert!(backend.seen.borrow().is_empty());

        // A block with another proposer index (0, in the registry) gets the same error,
        // not `WrongProposer`: the lookahead entry is the fault.
        let mut other = block.clone();
        other.message.proposer_index = 0;
        let err = apply_block(
            &mut state.clone(),
            &other,
            true,
            &bls_context(&backend),
            no_op,
        )
        .unwrap_err();
        assert_eq!(
            err,
            StfError::ListIndexOutOfRange {
                list: "validators",
                index: 64
            }
        );
        assert!(!err.proves_invalid());
        assert!(backend.seen.borrow().is_empty());
    }

    #[test]
    fn state_root_mismatch() {
        let (state, block) = state_and_block();
        let accepting = FixedBackend::new(Ok(true));
        let mut wrong = block.clone();
        wrong.message.state_root = Root::repeat_byte(0xee);
        assert_eq!(
            apply_block(
                &mut state.clone(),
                &wrong,
                true,
                &bls_context(&accepting),
                no_op
            ),
            Err(StfError::StateRootMismatch {
                block: Root::repeat_byte(0xee),
                computed: block.message.state_root,
            })
        );
        // Without `validate_result` the root is not checked.
        assert_eq!(
            apply_block(
                &mut state.clone(),
                &wrong,
                false,
                &bls_context(&accepting),
                no_op
            ),
            Ok(())
        );
        let mut post = state.clone();
        assert_eq!(
            apply_block(&mut post, &block, true, &bls_context(&accepting), no_op),
            Ok(())
        );
        assert_eq!(post.slot, 1);
        // The public entry point runs the same steps, then `process_block`, which stops at
        // the parent-payload step until it is ported.
        let mut post = state;
        assert_eq!(
            state_transition(&mut post, &block, true, &bls_context(&accepting)),
            Err(StfError::Unimplemented("4.6a"))
        );
    }

    /// The number of [`StfError`] variants: one more than the largest [`variant_id`].
    /// Increase `VARIANTS` when you add an id.
    const VARIANTS: usize = 75;

    /// A distinct id for each variant. The match has no `_` arm, so a new variant does not
    /// compile until it gets an id here, and then the table test fails until it has an entry.
    fn variant_id(e: &StfError) -> usize {
        match e {
            StfError::Unimplemented(_) => 0,
            StfError::SlotNotLater { .. } => 1,
            StfError::InvalidBlockSignature => 2,
            StfError::StateRootMismatch { .. } => 3,
            StfError::SignatureBackend(_) => 4,
            StfError::ArithmeticOverflow => 5,
            StfError::UnknownValidator(_) => 6,
            StfError::ShuffleIndexOutOfRange { .. } => 7,
            StfError::NoCandidates => 8,
            StfError::UnknownCommittee { .. } => 9,
            StfError::BitOutOfRange { .. } => 10,
            StfError::EpochOutOfWindow { .. } => 11,
            StfError::CacheEpochMismatch { .. } => 12,
            StfError::Tree(_) => 13,
            StfError::CacheSeedMismatch { .. } => 14,
            StfError::UnknownBuilder(_) => 15,
            StfError::PaymentIndexOutOfRange { .. } => 16,
            StfError::ListIndexOutOfRange { .. } => 17,
            StfError::BlockRootOutOfRange { .. } => 18,
            StfError::ParticipationEpochOutOfRange { .. } => 19,
            StfError::MissingVerdict(_) => 20,
            StfError::BlockSlotMismatch { .. } => 21,
            StfError::BlockNotNewer { .. } => 22,
            StfError::WrongProposer { .. } => 23,
            StfError::ParentRootMismatch { .. } => 24,
            StfError::ProposerSlashed(_) => 25,
            StfError::BlockDeposits(_) => 26,
            StfError::UnknownSyncCommitteeMember { .. } => 27,
            StfError::InvalidSyncAggregateSignature => 28,
            StfError::PubkeyAggregation(_) => 29,
            StfError::PayloadAttestationRootMismatch { .. } => 30,
            StfError::PayloadAttestationSlotMismatch { .. } => 31,
            StfError::PayloadAttestationNoAttesters => 32,
            StfError::PayloadAttestationUnsorted => 33,
            StfError::InvalidPayloadAttestationSignature => 34,
            StfError::ExitNotActive(_) => 35,
            StfError::ExitAlreadyInitiated(_) => 36,
            StfError::ExitEpochInFuture { .. } => 37,
            StfError::ExitTooEarly { .. } => 38,
            StfError::ExitPendingWithdrawals { .. } => 39,
            StfError::InvalidVoluntaryExitSignature => 40,
            StfError::NotBlsWithdrawalCredentials(_) => 41,
            StfError::BlsChangeKeyMismatch(_) => 42,
            StfError::InvalidBlsToExecutionChangeSignature => 43,
            StfError::AttestationTargetEpoch { .. } => 44,
            StfError::AttestationTargetSlot { .. } => 45,
            StfError::AttestationTooEarly { .. } => 46,
            StfError::AttestationDataIndex(_) => 47,
            StfError::SameSlotAttestationIndex(_) => 48,
            StfError::EmptyCommitteeAttesters(_) => 49,
            StfError::AggregationBitsLength { .. } => 50,
            StfError::AttestationSourceMismatch => 51,
            StfError::InvalidIndexedAttestation => 52,
            StfError::NotSlashableAttestationData => 53,
            StfError::NoValidatorSlashed => 54,
            StfError::ProposerSlashingSlots { .. } => 55,
            StfError::ProposerSlashingProposers { .. } => 56,
            StfError::ProposerSlashingSameHeaders => 57,
            StfError::ValidatorNotSlashable(_) => 58,
            StfError::InvalidOperationSignature => 59,
            StfError::PriorWithdrawalsPastLimit { .. } => 60,
            StfError::StateArithmetic { .. } => 61,
            StfError::SelfBuildBidValue(_) => 62,
            StfError::SelfBuildBidSignature => 63,
            StfError::BidBuilderNotActive(_) => 64,
            StfError::BidBuilderVersion { .. } => 65,
            StfError::BidNotCovered { .. } => 66,
            StfError::BidBlobCommitments { .. } => 67,
            StfError::BidSlotMismatch { .. } => 68,
            StfError::BidAtGenesisSlot => 69,
            StfError::BidParentBlockHash { .. } => 70,
            StfError::BidBlockHashIsParent => 71,
            StfError::BidParentBlockRoot { .. } => 72,
            StfError::BidPrevRandao { .. } => 73,
            StfError::UnknownBlobLimit(_) => 74,
        }
    }

    #[test]
    fn only_spec_failures_prove_invalid() {
        // One entry for each variant, checked against `variant_id` below.
        let cases = [
            (StfError::Unimplemented("x"), false),
            (
                StfError::SlotNotLater {
                    state_slot: 1,
                    slot: 1,
                },
                true,
            ),
            (StfError::InvalidBlockSignature, true),
            (
                StfError::StateRootMismatch {
                    block: Root::repeat_byte(1),
                    computed: Root::repeat_byte(2),
                },
                true,
            ),
            (
                StfError::SignatureBackend(BackendError("timeout".into())),
                false,
            ),
            (StfError::ArithmeticOverflow, true),
            (StfError::UnknownValidator(1), true),
            (
                StfError::ShuffleIndexOutOfRange {
                    index: 1,
                    index_count: 1,
                },
                true,
            ),
            (StfError::NoCandidates, true),
            (StfError::UnknownCommittee { slot: 1, index: 2 }, true),
            (StfError::BitOutOfRange { index: 3, len: 3 }, true),
            (
                StfError::EpochOutOfWindow {
                    epoch: 5,
                    state_epoch: 1,
                },
                true,
            ),
            (
                StfError::CacheEpochMismatch {
                    cache_epoch: 0,
                    epoch: 1,
                },
                false,
            ),
            (StfError::Tree("flush".into()), false),
            (
                StfError::CacheSeedMismatch {
                    epoch: 0,
                    cache_seed: Bytes32::repeat_byte(1),
                    state_seed: Bytes32::repeat_byte(2),
                },
                false,
            ),
            (StfError::UnknownBuilder(2), true),
            (
                StfError::PaymentIndexOutOfRange { index: 16, len: 16 },
                true,
            ),
            (
                StfError::ListIndexOutOfRange {
                    list: "balances",
                    index: 3,
                },
                false,
            ),
            (
                StfError::BlockRootOutOfRange {
                    slot: 9,
                    state_slot: 9,
                },
                true,
            ),
            (
                StfError::ParticipationEpochOutOfRange {
                    epoch: 1,
                    state_epoch: 3,
                },
                false,
            ),
            (
                StfError::MissingVerdict(BackendError("not prefetched".into())),
                false,
            ),
            (StfError::BlockSlotMismatch { block: 1, state: 2 }, true),
            (
                StfError::BlockNotNewer {
                    block: 1,
                    latest: 1,
                },
                true,
            ),
            (
                StfError::WrongProposer {
                    block: 1,
                    expected: 2,
                },
                true,
            ),
            (
                StfError::ParentRootMismatch {
                    block: Root::repeat_byte(1),
                    expected: Root::repeat_byte(2),
                },
                true,
            ),
            (StfError::ProposerSlashed(1), true),
            (StfError::BlockDeposits(1), true),
            (StfError::UnknownSyncCommitteeMember { position: 1 }, false),
            (StfError::InvalidSyncAggregateSignature, true),
            (
                StfError::PubkeyAggregation(AggregationError("bad key".into())),
                false,
            ),
            (
                StfError::PayloadAttestationRootMismatch {
                    attestation: Root::repeat_byte(1),
                    expected: Root::repeat_byte(2),
                },
                true,
            ),
            (
                StfError::PayloadAttestationSlotMismatch {
                    attestation: 1,
                    state: 1,
                },
                true,
            ),
            (StfError::PayloadAttestationNoAttesters, true),
            (StfError::PayloadAttestationUnsorted, true),
            (StfError::InvalidPayloadAttestationSignature, true),
            (StfError::ExitNotActive(1), true),
            (StfError::ExitAlreadyInitiated(1), true),
            (
                StfError::ExitEpochInFuture {
                    exit_epoch: 2,
                    current_epoch: 1,
                },
                true,
            ),
            (
                StfError::ExitTooEarly {
                    index: 1,
                    earliest_epoch: 64,
                    current_epoch: 1,
                },
                true,
            ),
            (
                StfError::ExitPendingWithdrawals {
                    index: 1,
                    pending: 1,
                },
                true,
            ),
            (StfError::InvalidVoluntaryExitSignature, true),
            (StfError::NotBlsWithdrawalCredentials(1), true),
            (StfError::BlsChangeKeyMismatch(1), true),
            (StfError::InvalidBlsToExecutionChangeSignature, true),
            (
                StfError::AttestationTargetEpoch {
                    target: 5,
                    state_epoch: 2,
                },
                true,
            ),
            (StfError::AttestationTargetSlot { target: 1, slot: 0 }, true),
            (
                StfError::AttestationTooEarly {
                    slot: 3,
                    state_slot: 3,
                },
                true,
            ),
            (StfError::AttestationDataIndex(2), true),
            (StfError::SameSlotAttestationIndex(1), true),
            (StfError::EmptyCommitteeAttesters(0), true),
            (
                StfError::AggregationBitsLength {
                    len: 5,
                    participants: 4,
                },
                true,
            ),
            (StfError::AttestationSourceMismatch, true),
            (StfError::InvalidIndexedAttestation, true),
            (StfError::NotSlashableAttestationData, true),
            (StfError::NoValidatorSlashed, true),
            (
                StfError::ProposerSlashingSlots {
                    slot_1: 1,
                    slot_2: 2,
                },
                true,
            ),
            (
                StfError::ProposerSlashingProposers {
                    proposer_1: 1,
                    proposer_2: 2,
                },
                true,
            ),
            (StfError::ProposerSlashingSameHeaders, true),
            (StfError::ValidatorNotSlashable(1), true),
            (StfError::InvalidOperationSignature, true),
            (
                StfError::PriorWithdrawalsPastLimit { prior: 4, limit: 3 },
                false,
            ),
            (
                StfError::StateArithmetic {
                    what: "withdrawal index",
                },
                false,
            ),
            (StfError::SelfBuildBidValue(1), true),
            (StfError::SelfBuildBidSignature, true),
            (StfError::BidBuilderNotActive(1), true),
            (
                StfError::BidBuilderVersion {
                    index: 1,
                    version: 1,
                },
                true,
            ),
            (
                StfError::BidNotCovered {
                    index: 1,
                    amount: 2,
                },
                true,
            ),
            (StfError::BidBlobCommitments { count: 10, max: 9 }, true),
            (StfError::BidSlotMismatch { bid: 1, state: 2 }, true),
            (StfError::BidAtGenesisSlot, true),
            (
                StfError::BidParentBlockHash {
                    bid: Root::repeat_byte(1),
                    expected: Root::repeat_byte(2),
                },
                true,
            ),
            (StfError::BidBlockHashIsParent, true),
            (
                StfError::BidParentBlockRoot {
                    bid: Root::repeat_byte(1),
                    expected: Root::repeat_byte(2),
                },
                true,
            ),
            (
                StfError::BidPrevRandao {
                    bid: Bytes32::repeat_byte(1),
                    expected: Bytes32::repeat_byte(2),
                },
                true,
            ),
            (StfError::UnknownBlobLimit(1), false),
        ];
        let mut ids: Vec<usize> = cases.iter().map(|(e, _)| variant_id(e)).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            (0..VARIANTS).collect::<Vec<_>>(),
            "one entry per variant"
        );
        for (e, proves) in cases {
            assert_eq!(e.proves_invalid(), proves, "{e}");
        }
    }
}
