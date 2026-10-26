//! The pure Gloas state transition (`specs/gloas/beacon-chain.md` at consensus-specs
//! v1.7.0-beta.4, and the earlier forks it inherits from).
//!
//! The crate does no I/O and links no BLS library: signature checks go through a
//! [`SignatureBackend`] that the caller supplies.
//!
//! - [`state_transition`]: the slot loop, the block signature, the block and the state root.
//! - [`per_slot`]: `process_slots` and `process_slot`.
//! - [`per_epoch`] and [`per_block`]: the epoch and block processing (stubs for now).
//! - [`accessors`]: the beacon-state accessors and the misc helpers.
//! - [`caches`]: shuffling, beacon committees, proposer and PTC selection.
//! - [`signatures`]: the [`SignatureBackend`] seam and the block signature set.
//!
//! Each ported function cites its spec file and line range at the pin. File prefixes: P0
//! `phase0/beacon-chain.md`, A `altair/beacon-chain.md`, E `electra/beacon-chain.md`, Fu
//! `fulu/beacon-chain.md`, G `gloas/beacon-chain.md`.
//!
//! milhouse trees panic in `tree_hash_root` while they hold pending updates, so every root
//! of a state goes through [`state_root`], which flushes them first.

pub mod accessors;
pub mod caches;
pub mod per_block;
pub mod per_epoch;
pub mod per_slot;
pub mod preset;
pub mod signatures;

#[cfg(test)]
mod testing;

pub use preset::Preset;
pub use signatures::{BackendError, SignatureBackend, SignatureSet, SignerRef};

use consensus_types::gloas::{BeaconBlock, BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{CommitteeIndex, Epoch, Root, Slot, ValidatorIndex};
use tree_hash::TreeHash;

/// Why a state transition step failed. Every variant except
/// [`StfError::SignatureBackend`] and [`StfError::Unimplemented`] means that the input is
/// invalid by the spec (a failed `assert`, an out-of-range access or a `Uint64` overflow).
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
    /// The backend rejected the proposer signature of the block.
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
    /// A `Uint64` operation overflowed or underflowed.
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    /// `state.validators[index]` is out of range.
    #[error("validator index {0} is out of range")]
    UnknownValidator(ValidatorIndex),
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
}

impl StfError {
    /// Whether the error proves that the input is invalid by the spec (REJECT). It does not
    /// for a step that is not ported yet, a backend without a verdict, or a failure of the
    /// state trees: callers IGNORE those, never REJECT.
    pub fn proves_invalid(&self) -> bool {
        !matches!(
            self,
            Self::Unimplemented(_)
                | Self::SignatureBackend(_)
                | Self::CacheEpochMismatch { .. }
                | Self::Tree(_)
        )
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
/// Processes the slots up to `block.slot`, checks the proposer signature through `backend`
/// (when `validate_result`), applies the block, and checks `block.state_root` (when
/// `validate_result`). On `Err`, `state` is partly updated: the caller drops it.
///
/// # Warning
///
/// Do not use this function on real blocks yet. Block processing is not ported:
/// [`per_block::process_block`] applies nothing. With `validate_result` false, the
/// post-state is wrong. With `validate_result` true, a valid block fails with
/// [`StfError::StateRootMismatch`], which looks like a proof of an invalid block.
///
/// Bound `block.slot` against the wall clock before the call. As in the spec, the slots
/// are processed before the signature check, and `process_slots` has no upper bound: a
/// block with a far-future slot costs one `process_slot` for each slot.
pub fn state_transition<E: Preset>(
    state: &mut BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    validate_result: bool,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    apply_block(
        state,
        signed_block,
        validate_result,
        backend,
        per_block::process_block,
    )
}

/// The body of [`state_transition`] with the block processing as a parameter, so that tests
/// can run the slot loop, the signature check and the root check with any `block_fn`.
pub(crate) fn apply_block<E, F>(
    state: &mut BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    validate_result: bool,
    backend: &dyn SignatureBackend,
    block_fn: F,
) -> Result<(), StfError>
where
    E: Preset,
    F: FnOnce(&mut BeaconState<E>, &BeaconBlock<E>) -> Result<(), StfError>,
{
    let block = &signed_block.message;
    per_slot::process_slots(state, block.slot)?;
    if validate_result {
        signatures::verify_block_signature(state, signed_block, backend)?;
    }
    block_fn(state, block)?;
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
    use crate::testing::{genesis_state, signed_block};
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

    fn no_op(_: &mut BeaconState<Minimal>, _: &BeaconBlock<Minimal>) -> Result<(), StfError> {
        Ok(())
    }

    /// The pre-state, and a block at slot 1 whose `state_root` is the post-state root.
    fn state_and_block() -> (BeaconState<Minimal>, SignedBeaconBlock<Minimal>) {
        let state = genesis_state::<Minimal>(&[32_000_000_000; 8]);
        let mut block = signed_block::<Minimal>(1, 3);
        let mut post = state.clone();
        per_slot::process_slots(&mut post, 1).unwrap();
        block.message.state_root = state_root(&mut post).unwrap();
        (state, block)
    }

    #[test]
    fn bad_block_signature() {
        let (state, block) = state_and_block();
        let rejecting = FixedBackend::new(Ok(false));
        assert_eq!(
            apply_block(&mut state.clone(), &block, true, &rejecting, no_op),
            Err(StfError::InvalidBlockSignature)
        );
        // The backend saw exactly the proposer set of the block.
        let mut at_slot = state.clone();
        per_slot::process_slots(&mut at_slot, 1).unwrap();
        let domain = get_domain(&at_slot, DOMAIN_BEACON_PROPOSER, None);
        let want = SignatureSet::single(
            SignerRef::Validator(3),
            compute_signing_root(&block.message, domain),
            [0x11; 96],
        );
        assert_eq!(*rejecting.seen.borrow(), vec![want]);

        // No verdict is not a proof of a bad signature.
        let unavailable = FixedBackend::new(Err(BackendError("timeout".into())));
        assert_eq!(
            apply_block(&mut state.clone(), &block, true, &unavailable, no_op),
            Err(StfError::SignatureBackend(BackendError("timeout".into())))
        );
        // Without `validate_result` the backend is not asked.
        let skipped = FixedBackend::new(Ok(false));
        assert_eq!(
            apply_block(&mut state.clone(), &block, false, &skipped, no_op),
            Ok(())
        );
        assert!(skipped.seen.borrow().is_empty());
        // A proposer outside the registry has no key to check.
        let mut stranger = block.clone();
        stranger.message.proposer_index = 8;
        assert_eq!(
            apply_block(
                &mut state.clone(),
                &stranger,
                true,
                &FixedBackend::new(Ok(true)),
                no_op
            ),
            Err(StfError::UnknownValidator(8))
        );
    }

    #[test]
    fn state_root_mismatch() {
        let (state, block) = state_and_block();
        let accepting = FixedBackend::new(Ok(true));
        let mut wrong = block.clone();
        wrong.message.state_root = Root::repeat_byte(0xee);
        assert_eq!(
            apply_block(&mut state.clone(), &wrong, true, &accepting, no_op),
            Err(StfError::StateRootMismatch {
                block: Root::repeat_byte(0xee),
                computed: block.message.state_root,
            })
        );
        // Without `validate_result` the root is not checked.
        assert_eq!(
            apply_block(&mut state.clone(), &wrong, false, &accepting, no_op),
            Ok(())
        );
        let mut post = state.clone();
        assert_eq!(
            apply_block(&mut post, &block, true, &accepting, no_op),
            Ok(())
        );
        assert_eq!(post.slot, 1);
        // The public entry point runs the same steps.
        let mut post = state;
        assert_eq!(
            state_transition(&mut post, &block, true, &accepting),
            Ok(())
        );
    }

    #[test]
    fn only_spec_failures_prove_invalid() {
        for e in [
            StfError::SlotNotLater {
                state_slot: 1,
                slot: 1,
            },
            StfError::InvalidBlockSignature,
            StfError::ArithmeticOverflow,
            StfError::UnknownValidator(1),
            StfError::NoCandidates,
        ] {
            assert!(e.proves_invalid(), "{e}");
        }
        for e in [
            StfError::Unimplemented("x"),
            StfError::SignatureBackend(BackendError("timeout".into())),
            StfError::Tree("flush".into()),
            StfError::CacheEpochMismatch {
                cache_epoch: 0,
                epoch: 1,
            },
        ] {
            assert!(!e.proves_invalid(), "{e}");
        }
    }
}
