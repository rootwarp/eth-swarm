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
//! - [`per_block`]: the block processing: the step order, the header, RANDAO, eth1 data,
//!   the sync aggregate and the payload attestations (the other steps and operations are
//!   stubs for now).
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

pub use preset::Preset;
pub use signatures::{
    AggregationError, BackendError, BlsContext, PubkeyAggregator, SignatureBackend, SignatureSet,
    SignerRef,
};

use consensus_types::gloas::{BeaconBlock, BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{
    BuilderIndex, Bytes32, CommitteeIndex, Epoch, Root, Slot, ValidatorIndex,
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
    /// `inactivity_scores`, the participation flags or `PARTICIPATION_FLAG_WEIGHTS`.
    ///
    /// A state that the transition makes keeps these lists as long as the registry, and the
    /// flag index comes from the code. Thus this error shows a bug in our state or in the
    /// caller, never a proof that the input object is invalid.
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
    /// example a builder deposit). The caller fetches these verdicts before the transition
    /// (ADR-011), so this error means that the fetch did not give one. This is never a
    /// proof that the input is invalid: callers IGNORE, never REJECT, on it.
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
}

impl StfError {
    /// Whether the error proves that the input is invalid by the spec (REJECT). It does not
    /// for a step that is not ported yet, a backend without a verdict, a missing deposit
    /// verdict, a failed pubkey aggregation, a committee cache of another epoch or seed, a failure of the state trees, a
    /// state list shorter than the registry or a code index past a spec table
    /// (`ListIndexOutOfRange`), or a participation epoch other than the previous and the
    /// current one (`ParticipationEpochOutOfRange`):
    /// callers IGNORE those, never REJECT.
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
    /// [`StfError::UnknownValidator`] has the same rule. The result depends on the registry
    /// of the state that the caller uses. A head state older than the object can have a
    /// shorter registry, so the index of a valid object can be past it. Thus a caller that
    /// uses another state than the object's own pre-state must map it to IGNORE.
    ///
    /// The match has no `_` arm, so each new variant must select its class here.
    pub fn proves_invalid(&self) -> bool {
        match self {
            Self::Unimplemented(_)
            | Self::SignatureBackend(_)
            | Self::CacheEpochMismatch { .. }
            | Self::CacheSeedMismatch { .. }
            | Self::Tree(_)
            // A state list shorter than the registry, or a flag index past the table: our
            // own state or code is wrong, and the object did not cause it.
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
            | Self::PubkeyAggregation(_) => false,
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
            | Self::InvalidPayloadAttestationSignature => true,
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
/// partly updated: the caller drops it. The epoch processing of the slots also reads `bls`
/// (see [`per_epoch::process_epoch`]).
///
/// `validate_result` false skips every BLS check: the proposer signature, the RANDAO reveal
/// and the sync aggregate signature. The spec skips only the proposer signature there.
/// Use `validate_result` false only to compute the state root of a block that we produce
/// ourselves, whose signatures we made. The checks that need no BLS (for example the
/// infinity signature of an empty sync aggregate) run in both modes.
///
/// # Warning
///
/// Do not use this function on real blocks yet. Block processing is ported only in part:
/// [`per_block::process_block`] returns [`StfError::Unimplemented`] at its first step (the
/// parent payload), so every block fails with an error that is not a proof of an invalid
/// block. For the same reason, a block with an operation other than a payload attestation,
/// or with a builder bid, fails the signature sets with `Unimplemented`.
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
    // indices.
    let mut ctx = per_block::BlockContext::default();
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
    const VARIANTS: usize = 35;

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
