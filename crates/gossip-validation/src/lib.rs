//! Gloas gossip validation (`specs/gloas/p2p-interface.md` at consensus-specs v1.7.0-beta.4)
//! as pure functions of a [`Seen`] set and the fork-choice store.
//!
//! - [`execution_payload`]: the `execution_payload` topic,
//!   [`validate_execution_payload_envelope_gossip`] (L811-885).
//! - [`seen`]: the spec's `Seen` (L188-219), for the topics of this crate.
//! - [`verdict`]: the [`Verdict`] of a message, and why it is IGNORE or REJECT.
//!
//! The crate does no I/O and links no BLS library. A validation function runs each check that
//! needs no BLS, in spec order, and then gives [`Verdict::Pending`] with the signature sets and
//! the [`SeenKey`] of the message. The caller verifies the sets with its own backend and gives
//! the BLS verdict to [`Seen::resolve`]. Only a valid signature puts the key into `Seen`, so an
//! invalid copy of a message does not stop a later valid copy.
//!
//! A verifier that gives no verdict (timeout, overload, a service that is not available) makes
//! the message IGNORE, never ACCEPT. REJECT is only for a proven spec violation.
//!
//! No gossip dispatch calls this crate yet.

pub mod execution_payload;
pub mod seen;
pub mod verdict;

pub use execution_payload::{
    validate_execution_payload_envelope_gossip, verify_execution_requests_limits,
    verify_withdrawals_limit, RequestCounts,
};
pub use seen::{Seen, SeenKey, SeenPayload};
pub use verdict::{IgnoreReason, RejectReason, RequestKind, Verdict};

use consensus_types::gloas::{BeaconBlock, BeaconState, Checkpoint};
use consensus_types::primitives::Root;
use fork_choice::Store;
use state_transition::Preset;

/// What the gossip checks read of the fork-choice store.
///
/// The spec reads `store.blocks` for a block that the node has seen from any source, and
/// `store.block_states` for a block that passed validation. The fork-choice [`Store`] adds a
/// block and its post-state together, so for it the two sets are equal. A caller that also
/// keeps the blocks that failed validation can give a view in which they are seen but have no
/// post-state.
pub trait StoreView<E: Preset> {
    /// `store.blocks[root]`.
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>>;

    /// `store.block_states[root]`.
    fn block_state(&self, root: Root) -> Option<&BeaconState<E>>;

    /// `store.finalized_checkpoint`.
    fn finalized_checkpoint(&self) -> &Checkpoint;
}

impl<E: Preset> StoreView<E> for Store<E> {
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>> {
        Store::block(self, root)
    }

    fn block_state(&self, root: Root) -> Option<&BeaconState<E>> {
        Store::block_state(self, root)
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        Store::finalized_checkpoint(self)
    }
}
